// C++/WinRT v1.0.190111.3

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#pragma once

#include "winrt/base.h"

#include "winrt/Windows.Foundation.h"
#include "winrt/Windows.Foundation.Collections.h"
#include "winrt/impl/Windows.UI.2.h"
#include "winrt/impl/Windows.UI.Xaml.Automation.2.h"
#include "winrt/impl/Windows.UI.Xaml.Automation.Peers.2.h"
#include "winrt/impl/Windows.UI.Xaml.Automation.Text.2.h"
#include "winrt/impl/Windows.UI.Xaml.2.h"
#include "winrt/impl/Windows.UI.Xaml.Automation.Provider.2.h"
#include "winrt/Windows.UI.Xaml.Automation.h"

namespace winrt::impl {

template <typename D> int32_t consume_Windows_UI_Xaml_Automation_Provider_IAnnotationProvider<D>::AnnotationTypeId() const
{
    int32_t value{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Automation::Provider::IAnnotationProvider)->get_AnnotationTypeId(&value));
    return value;
}

template <typename D> hstring consume_Windows_UI_Xaml_Automation_Provider_IAnnotationProvider<D>::AnnotationTypeName() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Automation::Provider::IAnnotationProvider)->get_AnnotationTypeName(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_UI_Xaml_Automation_Provider_IAnnotationProvider<D>::Author() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Automation::Provider::IAnnotationProvider)->get_Author(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_UI_Xaml_Automation_Provider_IAnnotationProvider<D>::DateTime() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Automation::Provider::IAnnotationProvider)->get_DateTime(put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Xaml::Automation::Provider::IRawElementProviderSimple consume_Windows_UI_Xaml_Automation_Provider_IAnnotationProvider<D>::Target() const
{
    Windows::UI::Xaml::Automation::Provider::IRawElementProviderSimple value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Automation::Provider::IAnnotationProvider)->get_Target(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::IInspectable consume_Windows_UI_Xaml_Automation_Provider_ICustomNavigationProvider<D>::NavigateCustom(Windows::UI::Xaml::Automation::Peers::AutomationNavigationDirection const& direction) const
{
    Windows::Foundation::IInspectable result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Automation::Provider::ICustomNavigationProvider)->NavigateCustom(get_abi(direction), put_abi(result)));
    return result;
}

template <typename D> Windows::UI::Xaml::Automation::DockPosition consume_Windows_UI_Xaml_Automation_Provider_IDockProvider<D>::DockPosition() const
{
    Windows::UI::Xaml::Automation::DockPosition value{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Automation::Provider::IDockProvider)->get_DockPosition(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_UI_Xaml_Automation_Provider_IDockProvider<D>::SetDockPosition(Windows::UI::Xaml::Automation::DockPosition const& dockPosition) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Automation::Provider::IDockProvider)->SetDockPosition(get_abi(dockPosition)));
}

template <typename D> bool consume_Windows_UI_Xaml_Automation_Provider_IDragProvider<D>::IsGrabbed() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Automation::Provider::IDragProvider)->get_IsGrabbed(&value));
    return value;
}

template <typename D> hstring consume_Windows_UI_Xaml_Automation_Provider_IDragProvider<D>::DropEffect() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Automation::Provider::IDragProvider)->get_DropEffect(put_abi(value)));
    return value;
}

template <typename D> com_array<hstring> consume_Windows_UI_Xaml_Automation_Provider_IDragProvider<D>::DropEffects() const
{
    com_array<hstring> value;
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Automation::Provider::IDragProvider)->get_DropEffects(impl::put_size_abi(value), put_abi(value)));
    return value;
}

template <typename D> com_array<Windows::UI::Xaml::Automation::Provider::IRawElementProviderSimple> consume_Windows_UI_Xaml_Automation_Provider_IDragProvider<D>::GetGrabbedItems() const
{
    com_array<Windows::UI::Xaml::Automation::Provider::IRawElementProviderSimple> result;
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Automation::Provider::IDragProvider)->GetGrabbedItems(impl::put_size_abi(result), put_abi(result)));
    return result;
}

template <typename D> hstring consume_Windows_UI_Xaml_Automation_Provider_IDropTargetProvider<D>::DropEffect() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Automation::Provider::IDropTargetProvider)->get_DropEffect(put_abi(value)));
    return value;
}

template <typename D> com_array<hstring> consume_Windows_UI_Xaml_Automation_Provider_IDropTargetProvider<D>::DropEffects() const
{
    com_array<hstring> value;
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Automation::Provider::IDropTargetProvider)->get_DropEffects(impl::put_size_abi(value), put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Xaml::Automation::ExpandCollapseState consume_Windows_UI_Xaml_Automation_Provider_IExpandCollapseProvider<D>::ExpandCollapseState() const
{
    Windows::UI::Xaml::Automation::ExpandCollapseState value{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Automation::Provider::IExpandCollapseProvider)->get_ExpandCollapseState(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_UI_Xaml_Automation_Provider_IExpandCollapseProvider<D>::Collapse() const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Automation::Provider::IExpandCollapseProvider)->Collapse());
}

template <typename D> void consume_Windows_UI_Xaml_Automation_Provider_IExpandCollapseProvider<D>::Expand() const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Automation::Provider::IExpandCollapseProvider)->Expand());
}

template <typename D> int32_t consume_Windows_UI_Xaml_Automation_Provider_IGridItemProvider<D>::Column() const
{
    int32_t value{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Automation::Provider::IGridItemProvider)->get_Column(&value));
    return value;
}

template <typename D> int32_t consume_Windows_UI_Xaml_Automation_Provider_IGridItemProvider<D>::ColumnSpan() const
{
    int32_t value{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Automation::Provider::IGridItemProvider)->get_ColumnSpan(&value));
    return value;
}

template <typename D> Windows::UI::Xaml::Automation::Provider::IRawElementProviderSimple consume_Windows_UI_Xaml_Automation_Provider_IGridItemProvider<D>::ContainingGrid() const
{
    Windows::UI::Xaml::Automation::Provider::IRawElementProviderSimple value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Automation::Provider::IGridItemProvider)->get_ContainingGrid(put_abi(value)));
    return value;
}

template <typename D> int32_t consume_Windows_UI_Xaml_Automation_Provider_IGridItemProvider<D>::Row() const
{
    int32_t value{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Automation::Provider::IGridItemProvider)->get_Row(&value));
    return value;
}

template <typename D> int32_t consume_Windows_UI_Xaml_Automation_Provider_IGridItemProvider<D>::RowSpan() const
{
    int32_t value{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Automation::Provider::IGridItemProvider)->get_RowSpan(&value));
    return value;
}

template <typename D> int32_t consume_Windows_UI_Xaml_Automation_Provider_IGridProvider<D>::ColumnCount() const
{
    int32_t value{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Automation::Provider::IGridProvider)->get_ColumnCount(&value));
    return value;
}

template <typename D> int32_t consume_Windows_UI_Xaml_Automation_Provider_IGridProvider<D>::RowCount() const
{
    int32_t value{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Automation::Provider::IGridProvider)->get_RowCount(&value));
    return value;
}

template <typename D> Windows::UI::Xaml::Automation::Provider::IRawElementProviderSimple consume_Windows_UI_Xaml_Automation_Provider_IGridProvider<D>::GetItem(int32_t row, int32_t column) const
{
    Windows::UI::Xaml::Automation::Provider::IRawElementProviderSimple result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Automation::Provider::IGridProvider)->GetItem(row, column, put_abi(result)));
    return result;
}

template <typename D> void consume_Windows_UI_Xaml_Automation_Provider_IInvokeProvider<D>::Invoke() const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Automation::Provider::IInvokeProvider)->Invoke());
}

template <typename D> Windows::UI::Xaml::Automation::Provider::IRawElementProviderSimple consume_Windows_UI_Xaml_Automation_Provider_IItemContainerProvider<D>::FindItemByProperty(Windows::UI::Xaml::Automation::Provider::IRawElementProviderSimple const& startAfter, Windows::UI::Xaml::Automation::AutomationProperty const& automationProperty, Windows::Foundation::IInspectable const& value) const
{
    Windows::UI::Xaml::Automation::Provider::IRawElementProviderSimple result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Automation::Provider::IItemContainerProvider)->FindItemByProperty(get_abi(startAfter), get_abi(automationProperty), get_abi(value), put_abi(result)));
    return result;
}

template <typename D> int32_t consume_Windows_UI_Xaml_Automation_Provider_IMultipleViewProvider<D>::CurrentView() const
{
    int32_t value{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Automation::Provider::IMultipleViewProvider)->get_CurrentView(&value));
    return value;
}

template <typename D> com_array<int32_t> consume_Windows_UI_Xaml_Automation_Provider_IMultipleViewProvider<D>::GetSupportedViews() const
{
    com_array<int32_t> result;
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Automation::Provider::IMultipleViewProvider)->GetSupportedViews(impl::put_size_abi(result), put_abi(result)));
    return result;
}

template <typename D> hstring consume_Windows_UI_Xaml_Automation_Provider_IMultipleViewProvider<D>::GetViewName(int32_t viewId) const
{
    hstring result{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Automation::Provider::IMultipleViewProvider)->GetViewName(viewId, put_abi(result)));
    return result;
}

template <typename D> void consume_Windows_UI_Xaml_Automation_Provider_IMultipleViewProvider<D>::SetCurrentView(int32_t viewId) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Automation::Provider::IMultipleViewProvider)->SetCurrentView(viewId));
}

template <typename D> Windows::Foundation::IInspectable consume_Windows_UI_Xaml_Automation_Provider_IObjectModelProvider<D>::GetUnderlyingObjectModel() const
{
    Windows::Foundation::IInspectable result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Automation::Provider::IObjectModelProvider)->GetUnderlyingObjectModel(put_abi(result)));
    return result;
}

template <typename D> bool consume_Windows_UI_Xaml_Automation_Provider_IRangeValueProvider<D>::IsReadOnly() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Automation::Provider::IRangeValueProvider)->get_IsReadOnly(&value));
    return value;
}

template <typename D> double consume_Windows_UI_Xaml_Automation_Provider_IRangeValueProvider<D>::LargeChange() const
{
    double value{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Automation::Provider::IRangeValueProvider)->get_LargeChange(&value));
    return value;
}

template <typename D> double consume_Windows_UI_Xaml_Automation_Provider_IRangeValueProvider<D>::Maximum() const
{
    double value{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Automation::Provider::IRangeValueProvider)->get_Maximum(&value));
    return value;
}

template <typename D> double consume_Windows_UI_Xaml_Automation_Provider_IRangeValueProvider<D>::Minimum() const
{
    double value{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Automation::Provider::IRangeValueProvider)->get_Minimum(&value));
    return value;
}

template <typename D> double consume_Windows_UI_Xaml_Automation_Provider_IRangeValueProvider<D>::SmallChange() const
{
    double value{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Automation::Provider::IRangeValueProvider)->get_SmallChange(&value));
    return value;
}

template <typename D> double consume_Windows_UI_Xaml_Automation_Provider_IRangeValueProvider<D>::Value() const
{
    double value{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Automation::Provider::IRangeValueProvider)->get_Value(&value));
    return value;
}

template <typename D> void consume_Windows_UI_Xaml_Automation_Provider_IRangeValueProvider<D>::SetValue(double value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Automation::Provider::IRangeValueProvider)->SetValue(value));
}

template <typename D> void consume_Windows_UI_Xaml_Automation_Provider_IScrollItemProvider<D>::ScrollIntoView() const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Automation::Provider::IScrollItemProvider)->ScrollIntoView());
}

template <typename D> bool consume_Windows_UI_Xaml_Automation_Provider_IScrollProvider<D>::HorizontallyScrollable() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Automation::Provider::IScrollProvider)->get_HorizontallyScrollable(&value));
    return value;
}

template <typename D> double consume_Windows_UI_Xaml_Automation_Provider_IScrollProvider<D>::HorizontalScrollPercent() const
{
    double value{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Automation::Provider::IScrollProvider)->get_HorizontalScrollPercent(&value));
    return value;
}

template <typename D> double consume_Windows_UI_Xaml_Automation_Provider_IScrollProvider<D>::HorizontalViewSize() const
{
    double value{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Automation::Provider::IScrollProvider)->get_HorizontalViewSize(&value));
    return value;
}

template <typename D> bool consume_Windows_UI_Xaml_Automation_Provider_IScrollProvider<D>::VerticallyScrollable() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Automation::Provider::IScrollProvider)->get_VerticallyScrollable(&value));
    return value;
}

template <typename D> double consume_Windows_UI_Xaml_Automation_Provider_IScrollProvider<D>::VerticalScrollPercent() const
{
    double value{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Automation::Provider::IScrollProvider)->get_VerticalScrollPercent(&value));
    return value;
}

template <typename D> double consume_Windows_UI_Xaml_Automation_Provider_IScrollProvider<D>::VerticalViewSize() const
{
    double value{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Automation::Provider::IScrollProvider)->get_VerticalViewSize(&value));
    return value;
}

template <typename D> void consume_Windows_UI_Xaml_Automation_Provider_IScrollProvider<D>::Scroll(Windows::UI::Xaml::Automation::ScrollAmount const& horizontalAmount, Windows::UI::Xaml::Automation::ScrollAmount const& verticalAmount) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Automation::Provider::IScrollProvider)->Scroll(get_abi(horizontalAmount), get_abi(verticalAmount)));
}

template <typename D> void consume_Windows_UI_Xaml_Automation_Provider_IScrollProvider<D>::SetScrollPercent(double horizontalPercent, double verticalPercent) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Automation::Provider::IScrollProvider)->SetScrollPercent(horizontalPercent, verticalPercent));
}

template <typename D> bool consume_Windows_UI_Xaml_Automation_Provider_ISelectionItemProvider<D>::IsSelected() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Automation::Provider::ISelectionItemProvider)->get_IsSelected(&value));
    return value;
}

template <typename D> Windows::UI::Xaml::Automation::Provider::IRawElementProviderSimple consume_Windows_UI_Xaml_Automation_Provider_ISelectionItemProvider<D>::SelectionContainer() const
{
    Windows::UI::Xaml::Automation::Provider::IRawElementProviderSimple value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Automation::Provider::ISelectionItemProvider)->get_SelectionContainer(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_UI_Xaml_Automation_Provider_ISelectionItemProvider<D>::AddToSelection() const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Automation::Provider::ISelectionItemProvider)->AddToSelection());
}

template <typename D> void consume_Windows_UI_Xaml_Automation_Provider_ISelectionItemProvider<D>::RemoveFromSelection() const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Automation::Provider::ISelectionItemProvider)->RemoveFromSelection());
}

template <typename D> void consume_Windows_UI_Xaml_Automation_Provider_ISelectionItemProvider<D>::Select() const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Automation::Provider::ISelectionItemProvider)->Select());
}

template <typename D> bool consume_Windows_UI_Xaml_Automation_Provider_ISelectionProvider<D>::CanSelectMultiple() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Automation::Provider::ISelectionProvider)->get_CanSelectMultiple(&value));
    return value;
}

template <typename D> bool consume_Windows_UI_Xaml_Automation_Provider_ISelectionProvider<D>::IsSelectionRequired() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Automation::Provider::ISelectionProvider)->get_IsSelectionRequired(&value));
    return value;
}

template <typename D> com_array<Windows::UI::Xaml::Automation::Provider::IRawElementProviderSimple> consume_Windows_UI_Xaml_Automation_Provider_ISelectionProvider<D>::GetSelection() const
{
    com_array<Windows::UI::Xaml::Automation::Provider::IRawElementProviderSimple> result;
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Automation::Provider::ISelectionProvider)->GetSelection(impl::put_size_abi(result), put_abi(result)));
    return result;
}

template <typename D> hstring consume_Windows_UI_Xaml_Automation_Provider_ISpreadsheetItemProvider<D>::Formula() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Automation::Provider::ISpreadsheetItemProvider)->get_Formula(put_abi(value)));
    return value;
}

template <typename D> com_array<Windows::UI::Xaml::Automation::Provider::IRawElementProviderSimple> consume_Windows_UI_Xaml_Automation_Provider_ISpreadsheetItemProvider<D>::GetAnnotationObjects() const
{
    com_array<Windows::UI::Xaml::Automation::Provider::IRawElementProviderSimple> result;
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Automation::Provider::ISpreadsheetItemProvider)->GetAnnotationObjects(impl::put_size_abi(result), put_abi(result)));
    return result;
}

template <typename D> com_array<Windows::UI::Xaml::Automation::AnnotationType> consume_Windows_UI_Xaml_Automation_Provider_ISpreadsheetItemProvider<D>::GetAnnotationTypes() const
{
    com_array<Windows::UI::Xaml::Automation::AnnotationType> result;
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Automation::Provider::ISpreadsheetItemProvider)->GetAnnotationTypes(impl::put_size_abi(result), put_abi(result)));
    return result;
}

template <typename D> Windows::UI::Xaml::Automation::Provider::IRawElementProviderSimple consume_Windows_UI_Xaml_Automation_Provider_ISpreadsheetProvider<D>::GetItemByName(param::hstring const& name) const
{
    Windows::UI::Xaml::Automation::Provider::IRawElementProviderSimple result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Automation::Provider::ISpreadsheetProvider)->GetItemByName(get_abi(name), put_abi(result)));
    return result;
}

template <typename D> hstring consume_Windows_UI_Xaml_Automation_Provider_IStylesProvider<D>::ExtendedProperties() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Automation::Provider::IStylesProvider)->get_ExtendedProperties(put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Color consume_Windows_UI_Xaml_Automation_Provider_IStylesProvider<D>::FillColor() const
{
    Windows::UI::Color value{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Automation::Provider::IStylesProvider)->get_FillColor(put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Color consume_Windows_UI_Xaml_Automation_Provider_IStylesProvider<D>::FillPatternColor() const
{
    Windows::UI::Color value{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Automation::Provider::IStylesProvider)->get_FillPatternColor(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_UI_Xaml_Automation_Provider_IStylesProvider<D>::FillPatternStyle() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Automation::Provider::IStylesProvider)->get_FillPatternStyle(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_UI_Xaml_Automation_Provider_IStylesProvider<D>::Shape() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Automation::Provider::IStylesProvider)->get_Shape(put_abi(value)));
    return value;
}

template <typename D> int32_t consume_Windows_UI_Xaml_Automation_Provider_IStylesProvider<D>::StyleId() const
{
    int32_t value{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Automation::Provider::IStylesProvider)->get_StyleId(&value));
    return value;
}

template <typename D> hstring consume_Windows_UI_Xaml_Automation_Provider_IStylesProvider<D>::StyleName() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Automation::Provider::IStylesProvider)->get_StyleName(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_UI_Xaml_Automation_Provider_ISynchronizedInputProvider<D>::Cancel() const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Automation::Provider::ISynchronizedInputProvider)->Cancel());
}

template <typename D> void consume_Windows_UI_Xaml_Automation_Provider_ISynchronizedInputProvider<D>::StartListening(Windows::UI::Xaml::Automation::SynchronizedInputType const& inputType) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Automation::Provider::ISynchronizedInputProvider)->StartListening(get_abi(inputType)));
}

template <typename D> com_array<Windows::UI::Xaml::Automation::Provider::IRawElementProviderSimple> consume_Windows_UI_Xaml_Automation_Provider_ITableItemProvider<D>::GetColumnHeaderItems() const
{
    com_array<Windows::UI::Xaml::Automation::Provider::IRawElementProviderSimple> result;
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Automation::Provider::ITableItemProvider)->GetColumnHeaderItems(impl::put_size_abi(result), put_abi(result)));
    return result;
}

template <typename D> com_array<Windows::UI::Xaml::Automation::Provider::IRawElementProviderSimple> consume_Windows_UI_Xaml_Automation_Provider_ITableItemProvider<D>::GetRowHeaderItems() const
{
    com_array<Windows::UI::Xaml::Automation::Provider::IRawElementProviderSimple> result;
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Automation::Provider::ITableItemProvider)->GetRowHeaderItems(impl::put_size_abi(result), put_abi(result)));
    return result;
}

template <typename D> Windows::UI::Xaml::Automation::RowOrColumnMajor consume_Windows_UI_Xaml_Automation_Provider_ITableProvider<D>::RowOrColumnMajor() const
{
    Windows::UI::Xaml::Automation::RowOrColumnMajor value{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Automation::Provider::ITableProvider)->get_RowOrColumnMajor(put_abi(value)));
    return value;
}

template <typename D> com_array<Windows::UI::Xaml::Automation::Provider::IRawElementProviderSimple> consume_Windows_UI_Xaml_Automation_Provider_ITableProvider<D>::GetColumnHeaders() const
{
    com_array<Windows::UI::Xaml::Automation::Provider::IRawElementProviderSimple> result;
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Automation::Provider::ITableProvider)->GetColumnHeaders(impl::put_size_abi(result), put_abi(result)));
    return result;
}

template <typename D> com_array<Windows::UI::Xaml::Automation::Provider::IRawElementProviderSimple> consume_Windows_UI_Xaml_Automation_Provider_ITableProvider<D>::GetRowHeaders() const
{
    com_array<Windows::UI::Xaml::Automation::Provider::IRawElementProviderSimple> result;
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Automation::Provider::ITableProvider)->GetRowHeaders(impl::put_size_abi(result), put_abi(result)));
    return result;
}

template <typename D> Windows::UI::Xaml::Automation::Provider::IRawElementProviderSimple consume_Windows_UI_Xaml_Automation_Provider_ITextChildProvider<D>::TextContainer() const
{
    Windows::UI::Xaml::Automation::Provider::IRawElementProviderSimple value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Automation::Provider::ITextChildProvider)->get_TextContainer(put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Xaml::Automation::Provider::ITextRangeProvider consume_Windows_UI_Xaml_Automation_Provider_ITextChildProvider<D>::TextRange() const
{
    Windows::UI::Xaml::Automation::Provider::ITextRangeProvider value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Automation::Provider::ITextChildProvider)->get_TextRange(put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Xaml::Automation::Provider::ITextRangeProvider consume_Windows_UI_Xaml_Automation_Provider_ITextEditProvider<D>::GetActiveComposition() const
{
    Windows::UI::Xaml::Automation::Provider::ITextRangeProvider result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Automation::Provider::ITextEditProvider)->GetActiveComposition(put_abi(result)));
    return result;
}

template <typename D> Windows::UI::Xaml::Automation::Provider::ITextRangeProvider consume_Windows_UI_Xaml_Automation_Provider_ITextEditProvider<D>::GetConversionTarget() const
{
    Windows::UI::Xaml::Automation::Provider::ITextRangeProvider result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Automation::Provider::ITextEditProvider)->GetConversionTarget(put_abi(result)));
    return result;
}

template <typename D> Windows::UI::Xaml::Automation::Provider::ITextRangeProvider consume_Windows_UI_Xaml_Automation_Provider_ITextProvider<D>::DocumentRange() const
{
    Windows::UI::Xaml::Automation::Provider::ITextRangeProvider value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Automation::Provider::ITextProvider)->get_DocumentRange(put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Xaml::Automation::SupportedTextSelection consume_Windows_UI_Xaml_Automation_Provider_ITextProvider<D>::SupportedTextSelection() const
{
    Windows::UI::Xaml::Automation::SupportedTextSelection value{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Automation::Provider::ITextProvider)->get_SupportedTextSelection(put_abi(value)));
    return value;
}

template <typename D> com_array<Windows::UI::Xaml::Automation::Provider::ITextRangeProvider> consume_Windows_UI_Xaml_Automation_Provider_ITextProvider<D>::GetSelection() const
{
    com_array<Windows::UI::Xaml::Automation::Provider::ITextRangeProvider> result;
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Automation::Provider::ITextProvider)->GetSelection(impl::put_size_abi(result), put_abi(result)));
    return result;
}

template <typename D> com_array<Windows::UI::Xaml::Automation::Provider::ITextRangeProvider> consume_Windows_UI_Xaml_Automation_Provider_ITextProvider<D>::GetVisibleRanges() const
{
    com_array<Windows::UI::Xaml::Automation::Provider::ITextRangeProvider> result;
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Automation::Provider::ITextProvider)->GetVisibleRanges(impl::put_size_abi(result), put_abi(result)));
    return result;
}

template <typename D> Windows::UI::Xaml::Automation::Provider::ITextRangeProvider consume_Windows_UI_Xaml_Automation_Provider_ITextProvider<D>::RangeFromChild(Windows::UI::Xaml::Automation::Provider::IRawElementProviderSimple const& childElement) const
{
    Windows::UI::Xaml::Automation::Provider::ITextRangeProvider result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Automation::Provider::ITextProvider)->RangeFromChild(get_abi(childElement), put_abi(result)));
    return result;
}

template <typename D> Windows::UI::Xaml::Automation::Provider::ITextRangeProvider consume_Windows_UI_Xaml_Automation_Provider_ITextProvider<D>::RangeFromPoint(Windows::Foundation::Point const& screenLocation) const
{
    Windows::UI::Xaml::Automation::Provider::ITextRangeProvider result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Automation::Provider::ITextProvider)->RangeFromPoint(get_abi(screenLocation), put_abi(result)));
    return result;
}

template <typename D> Windows::UI::Xaml::Automation::Provider::ITextRangeProvider consume_Windows_UI_Xaml_Automation_Provider_ITextProvider2<D>::RangeFromAnnotation(Windows::UI::Xaml::Automation::Provider::IRawElementProviderSimple const& annotationElement) const
{
    Windows::UI::Xaml::Automation::Provider::ITextRangeProvider result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Automation::Provider::ITextProvider2)->RangeFromAnnotation(get_abi(annotationElement), put_abi(result)));
    return result;
}

template <typename D> Windows::UI::Xaml::Automation::Provider::ITextRangeProvider consume_Windows_UI_Xaml_Automation_Provider_ITextProvider2<D>::GetCaretRange(bool& isActive) const
{
    Windows::UI::Xaml::Automation::Provider::ITextRangeProvider returnValue{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Automation::Provider::ITextProvider2)->GetCaretRange(&isActive, put_abi(returnValue)));
    return returnValue;
}

template <typename D> Windows::UI::Xaml::Automation::Provider::ITextRangeProvider consume_Windows_UI_Xaml_Automation_Provider_ITextRangeProvider<D>::Clone() const
{
    Windows::UI::Xaml::Automation::Provider::ITextRangeProvider result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Automation::Provider::ITextRangeProvider)->Clone(put_abi(result)));
    return result;
}

template <typename D> bool consume_Windows_UI_Xaml_Automation_Provider_ITextRangeProvider<D>::Compare(Windows::UI::Xaml::Automation::Provider::ITextRangeProvider const& textRangeProvider) const
{
    bool result{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Automation::Provider::ITextRangeProvider)->Compare(get_abi(textRangeProvider), &result));
    return result;
}

template <typename D> int32_t consume_Windows_UI_Xaml_Automation_Provider_ITextRangeProvider<D>::CompareEndpoints(Windows::UI::Xaml::Automation::Text::TextPatternRangeEndpoint const& endpoint, Windows::UI::Xaml::Automation::Provider::ITextRangeProvider const& textRangeProvider, Windows::UI::Xaml::Automation::Text::TextPatternRangeEndpoint const& targetEndpoint) const
{
    int32_t result{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Automation::Provider::ITextRangeProvider)->CompareEndpoints(get_abi(endpoint), get_abi(textRangeProvider), get_abi(targetEndpoint), &result));
    return result;
}

template <typename D> void consume_Windows_UI_Xaml_Automation_Provider_ITextRangeProvider<D>::ExpandToEnclosingUnit(Windows::UI::Xaml::Automation::Text::TextUnit const& unit) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Automation::Provider::ITextRangeProvider)->ExpandToEnclosingUnit(get_abi(unit)));
}

template <typename D> Windows::UI::Xaml::Automation::Provider::ITextRangeProvider consume_Windows_UI_Xaml_Automation_Provider_ITextRangeProvider<D>::FindAttribute(int32_t attributeId, Windows::Foundation::IInspectable const& value, bool backward) const
{
    Windows::UI::Xaml::Automation::Provider::ITextRangeProvider result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Automation::Provider::ITextRangeProvider)->FindAttribute(attributeId, get_abi(value), backward, put_abi(result)));
    return result;
}

template <typename D> Windows::UI::Xaml::Automation::Provider::ITextRangeProvider consume_Windows_UI_Xaml_Automation_Provider_ITextRangeProvider<D>::FindText(param::hstring const& text, bool backward, bool ignoreCase) const
{
    Windows::UI::Xaml::Automation::Provider::ITextRangeProvider result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Automation::Provider::ITextRangeProvider)->FindText(get_abi(text), backward, ignoreCase, put_abi(result)));
    return result;
}

template <typename D> Windows::Foundation::IInspectable consume_Windows_UI_Xaml_Automation_Provider_ITextRangeProvider<D>::GetAttributeValue(int32_t attributeId) const
{
    Windows::Foundation::IInspectable result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Automation::Provider::ITextRangeProvider)->GetAttributeValue(attributeId, put_abi(result)));
    return result;
}

template <typename D> void consume_Windows_UI_Xaml_Automation_Provider_ITextRangeProvider<D>::GetBoundingRectangles(com_array<double>& returnValue) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Automation::Provider::ITextRangeProvider)->GetBoundingRectangles(impl::put_size_abi(returnValue), put_abi(returnValue)));
}

template <typename D> Windows::UI::Xaml::Automation::Provider::IRawElementProviderSimple consume_Windows_UI_Xaml_Automation_Provider_ITextRangeProvider<D>::GetEnclosingElement() const
{
    Windows::UI::Xaml::Automation::Provider::IRawElementProviderSimple result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Automation::Provider::ITextRangeProvider)->GetEnclosingElement(put_abi(result)));
    return result;
}

template <typename D> hstring consume_Windows_UI_Xaml_Automation_Provider_ITextRangeProvider<D>::GetText(int32_t maxLength) const
{
    hstring result{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Automation::Provider::ITextRangeProvider)->GetText(maxLength, put_abi(result)));
    return result;
}

template <typename D> int32_t consume_Windows_UI_Xaml_Automation_Provider_ITextRangeProvider<D>::Move(Windows::UI::Xaml::Automation::Text::TextUnit const& unit, int32_t count) const
{
    int32_t result{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Automation::Provider::ITextRangeProvider)->Move(get_abi(unit), count, &result));
    return result;
}

template <typename D> int32_t consume_Windows_UI_Xaml_Automation_Provider_ITextRangeProvider<D>::MoveEndpointByUnit(Windows::UI::Xaml::Automation::Text::TextPatternRangeEndpoint const& endpoint, Windows::UI::Xaml::Automation::Text::TextUnit const& unit, int32_t count) const
{
    int32_t result{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Automation::Provider::ITextRangeProvider)->MoveEndpointByUnit(get_abi(endpoint), get_abi(unit), count, &result));
    return result;
}

template <typename D> void consume_Windows_UI_Xaml_Automation_Provider_ITextRangeProvider<D>::MoveEndpointByRange(Windows::UI::Xaml::Automation::Text::TextPatternRangeEndpoint const& endpoint, Windows::UI::Xaml::Automation::Provider::ITextRangeProvider const& textRangeProvider, Windows::UI::Xaml::Automation::Text::TextPatternRangeEndpoint const& targetEndpoint) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Automation::Provider::ITextRangeProvider)->MoveEndpointByRange(get_abi(endpoint), get_abi(textRangeProvider), get_abi(targetEndpoint)));
}

template <typename D> void consume_Windows_UI_Xaml_Automation_Provider_ITextRangeProvider<D>::Select() const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Automation::Provider::ITextRangeProvider)->Select());
}

template <typename D> void consume_Windows_UI_Xaml_Automation_Provider_ITextRangeProvider<D>::AddToSelection() const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Automation::Provider::ITextRangeProvider)->AddToSelection());
}

template <typename D> void consume_Windows_UI_Xaml_Automation_Provider_ITextRangeProvider<D>::RemoveFromSelection() const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Automation::Provider::ITextRangeProvider)->RemoveFromSelection());
}

template <typename D> void consume_Windows_UI_Xaml_Automation_Provider_ITextRangeProvider<D>::ScrollIntoView(bool alignToTop) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Automation::Provider::ITextRangeProvider)->ScrollIntoView(alignToTop));
}

template <typename D> com_array<Windows::UI::Xaml::Automation::Provider::IRawElementProviderSimple> consume_Windows_UI_Xaml_Automation_Provider_ITextRangeProvider<D>::GetChildren() const
{
    com_array<Windows::UI::Xaml::Automation::Provider::IRawElementProviderSimple> result;
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Automation::Provider::ITextRangeProvider)->GetChildren(impl::put_size_abi(result), put_abi(result)));
    return result;
}

template <typename D> void consume_Windows_UI_Xaml_Automation_Provider_ITextRangeProvider2<D>::ShowContextMenu() const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Automation::Provider::ITextRangeProvider2)->ShowContextMenu());
}

template <typename D> Windows::UI::Xaml::Automation::ToggleState consume_Windows_UI_Xaml_Automation_Provider_IToggleProvider<D>::ToggleState() const
{
    Windows::UI::Xaml::Automation::ToggleState value{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Automation::Provider::IToggleProvider)->get_ToggleState(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_UI_Xaml_Automation_Provider_IToggleProvider<D>::Toggle() const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Automation::Provider::IToggleProvider)->Toggle());
}

template <typename D> bool consume_Windows_UI_Xaml_Automation_Provider_ITransformProvider<D>::CanMove() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Automation::Provider::ITransformProvider)->get_CanMove(&value));
    return value;
}

template <typename D> bool consume_Windows_UI_Xaml_Automation_Provider_ITransformProvider<D>::CanResize() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Automation::Provider::ITransformProvider)->get_CanResize(&value));
    return value;
}

template <typename D> bool consume_Windows_UI_Xaml_Automation_Provider_ITransformProvider<D>::CanRotate() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Automation::Provider::ITransformProvider)->get_CanRotate(&value));
    return value;
}

template <typename D> void consume_Windows_UI_Xaml_Automation_Provider_ITransformProvider<D>::Move(double x, double y) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Automation::Provider::ITransformProvider)->Move(x, y));
}

template <typename D> void consume_Windows_UI_Xaml_Automation_Provider_ITransformProvider<D>::Resize(double width, double height) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Automation::Provider::ITransformProvider)->Resize(width, height));
}

template <typename D> void consume_Windows_UI_Xaml_Automation_Provider_ITransformProvider<D>::Rotate(double degrees) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Automation::Provider::ITransformProvider)->Rotate(degrees));
}

template <typename D> bool consume_Windows_UI_Xaml_Automation_Provider_ITransformProvider2<D>::CanZoom() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Automation::Provider::ITransformProvider2)->get_CanZoom(&value));
    return value;
}

template <typename D> double consume_Windows_UI_Xaml_Automation_Provider_ITransformProvider2<D>::ZoomLevel() const
{
    double value{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Automation::Provider::ITransformProvider2)->get_ZoomLevel(&value));
    return value;
}

template <typename D> double consume_Windows_UI_Xaml_Automation_Provider_ITransformProvider2<D>::MaxZoom() const
{
    double value{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Automation::Provider::ITransformProvider2)->get_MaxZoom(&value));
    return value;
}

template <typename D> double consume_Windows_UI_Xaml_Automation_Provider_ITransformProvider2<D>::MinZoom() const
{
    double value{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Automation::Provider::ITransformProvider2)->get_MinZoom(&value));
    return value;
}

template <typename D> void consume_Windows_UI_Xaml_Automation_Provider_ITransformProvider2<D>::Zoom(double zoom) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Automation::Provider::ITransformProvider2)->Zoom(zoom));
}

template <typename D> void consume_Windows_UI_Xaml_Automation_Provider_ITransformProvider2<D>::ZoomByUnit(Windows::UI::Xaml::Automation::ZoomUnit const& zoomUnit) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Automation::Provider::ITransformProvider2)->ZoomByUnit(get_abi(zoomUnit)));
}

template <typename D> bool consume_Windows_UI_Xaml_Automation_Provider_IValueProvider<D>::IsReadOnly() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Automation::Provider::IValueProvider)->get_IsReadOnly(&value));
    return value;
}

template <typename D> hstring consume_Windows_UI_Xaml_Automation_Provider_IValueProvider<D>::Value() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Automation::Provider::IValueProvider)->get_Value(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_UI_Xaml_Automation_Provider_IValueProvider<D>::SetValue(param::hstring const& value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Automation::Provider::IValueProvider)->SetValue(get_abi(value)));
}

template <typename D> void consume_Windows_UI_Xaml_Automation_Provider_IVirtualizedItemProvider<D>::Realize() const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Automation::Provider::IVirtualizedItemProvider)->Realize());
}

template <typename D> bool consume_Windows_UI_Xaml_Automation_Provider_IWindowProvider<D>::IsModal() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Automation::Provider::IWindowProvider)->get_IsModal(&value));
    return value;
}

template <typename D> bool consume_Windows_UI_Xaml_Automation_Provider_IWindowProvider<D>::IsTopmost() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Automation::Provider::IWindowProvider)->get_IsTopmost(&value));
    return value;
}

template <typename D> bool consume_Windows_UI_Xaml_Automation_Provider_IWindowProvider<D>::Maximizable() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Automation::Provider::IWindowProvider)->get_Maximizable(&value));
    return value;
}

template <typename D> bool consume_Windows_UI_Xaml_Automation_Provider_IWindowProvider<D>::Minimizable() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Automation::Provider::IWindowProvider)->get_Minimizable(&value));
    return value;
}

template <typename D> Windows::UI::Xaml::Automation::WindowInteractionState consume_Windows_UI_Xaml_Automation_Provider_IWindowProvider<D>::InteractionState() const
{
    Windows::UI::Xaml::Automation::WindowInteractionState value{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Automation::Provider::IWindowProvider)->get_InteractionState(put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Xaml::Automation::WindowVisualState consume_Windows_UI_Xaml_Automation_Provider_IWindowProvider<D>::VisualState() const
{
    Windows::UI::Xaml::Automation::WindowVisualState value{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Automation::Provider::IWindowProvider)->get_VisualState(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_UI_Xaml_Automation_Provider_IWindowProvider<D>::Close() const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Automation::Provider::IWindowProvider)->Close());
}

template <typename D> void consume_Windows_UI_Xaml_Automation_Provider_IWindowProvider<D>::SetVisualState(Windows::UI::Xaml::Automation::WindowVisualState const& state) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Automation::Provider::IWindowProvider)->SetVisualState(get_abi(state)));
}

template <typename D> bool consume_Windows_UI_Xaml_Automation_Provider_IWindowProvider<D>::WaitForInputIdle(int32_t milliseconds) const
{
    bool result{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Automation::Provider::IWindowProvider)->WaitForInputIdle(milliseconds, &result));
    return result;
}

template <typename D>
struct produce<D, Windows::UI::Xaml::Automation::Provider::IAnnotationProvider> : produce_base<D, Windows::UI::Xaml::Automation::Provider::IAnnotationProvider>
{
    int32_t WINRT_CALL get_AnnotationTypeId(int32_t* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(AnnotationTypeId, WINRT_WRAP(int32_t));
            *value = detach_from<int32_t>(this->shim().AnnotationTypeId());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_AnnotationTypeName(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(AnnotationTypeName, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().AnnotationTypeName());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Author(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Author, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().Author());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_DateTime(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(DateTime, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().DateTime());
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
            WINRT_ASSERT_DECLARATION(Target, WINRT_WRAP(Windows::UI::Xaml::Automation::Provider::IRawElementProviderSimple));
            *value = detach_from<Windows::UI::Xaml::Automation::Provider::IRawElementProviderSimple>(this->shim().Target());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Xaml::Automation::Provider::ICustomNavigationProvider> : produce_base<D, Windows::UI::Xaml::Automation::Provider::ICustomNavigationProvider>
{
    int32_t WINRT_CALL NavigateCustom(Windows::UI::Xaml::Automation::Peers::AutomationNavigationDirection direction, void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(NavigateCustom, WINRT_WRAP(Windows::Foundation::IInspectable), Windows::UI::Xaml::Automation::Peers::AutomationNavigationDirection const&);
            *result = detach_from<Windows::Foundation::IInspectable>(this->shim().NavigateCustom(*reinterpret_cast<Windows::UI::Xaml::Automation::Peers::AutomationNavigationDirection const*>(&direction)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Xaml::Automation::Provider::IDockProvider> : produce_base<D, Windows::UI::Xaml::Automation::Provider::IDockProvider>
{
    int32_t WINRT_CALL get_DockPosition(Windows::UI::Xaml::Automation::DockPosition* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(DockPosition, WINRT_WRAP(Windows::UI::Xaml::Automation::DockPosition));
            *value = detach_from<Windows::UI::Xaml::Automation::DockPosition>(this->shim().DockPosition());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL SetDockPosition(Windows::UI::Xaml::Automation::DockPosition dockPosition) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SetDockPosition, WINRT_WRAP(void), Windows::UI::Xaml::Automation::DockPosition const&);
            this->shim().SetDockPosition(*reinterpret_cast<Windows::UI::Xaml::Automation::DockPosition const*>(&dockPosition));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Xaml::Automation::Provider::IDragProvider> : produce_base<D, Windows::UI::Xaml::Automation::Provider::IDragProvider>
{
    int32_t WINRT_CALL get_IsGrabbed(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IsGrabbed, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().IsGrabbed());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_DropEffect(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(DropEffect, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().DropEffect());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_DropEffects(uint32_t* __valueSize, void*** value) noexcept final
    {
        try
        {
            *__valueSize = 0;
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(DropEffects, WINRT_WRAP(com_array<hstring>));
            std::tie(*__valueSize, *value) = detach_abi(this->shim().DropEffects());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL GetGrabbedItems(uint32_t* __resultSize, void*** result) noexcept final
    {
        try
        {
            *__resultSize = 0;
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetGrabbedItems, WINRT_WRAP(com_array<Windows::UI::Xaml::Automation::Provider::IRawElementProviderSimple>));
            std::tie(*__resultSize, *result) = detach_abi(this->shim().GetGrabbedItems());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Xaml::Automation::Provider::IDropTargetProvider> : produce_base<D, Windows::UI::Xaml::Automation::Provider::IDropTargetProvider>
{
    int32_t WINRT_CALL get_DropEffect(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(DropEffect, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().DropEffect());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_DropEffects(uint32_t* __valueSize, void*** value) noexcept final
    {
        try
        {
            *__valueSize = 0;
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(DropEffects, WINRT_WRAP(com_array<hstring>));
            std::tie(*__valueSize, *value) = detach_abi(this->shim().DropEffects());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Xaml::Automation::Provider::IExpandCollapseProvider> : produce_base<D, Windows::UI::Xaml::Automation::Provider::IExpandCollapseProvider>
{
    int32_t WINRT_CALL get_ExpandCollapseState(Windows::UI::Xaml::Automation::ExpandCollapseState* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ExpandCollapseState, WINRT_WRAP(Windows::UI::Xaml::Automation::ExpandCollapseState));
            *value = detach_from<Windows::UI::Xaml::Automation::ExpandCollapseState>(this->shim().ExpandCollapseState());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL Collapse() noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Collapse, WINRT_WRAP(void));
            this->shim().Collapse();
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL Expand() noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Expand, WINRT_WRAP(void));
            this->shim().Expand();
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Xaml::Automation::Provider::IGridItemProvider> : produce_base<D, Windows::UI::Xaml::Automation::Provider::IGridItemProvider>
{
    int32_t WINRT_CALL get_Column(int32_t* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Column, WINRT_WRAP(int32_t));
            *value = detach_from<int32_t>(this->shim().Column());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_ColumnSpan(int32_t* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ColumnSpan, WINRT_WRAP(int32_t));
            *value = detach_from<int32_t>(this->shim().ColumnSpan());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_ContainingGrid(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ContainingGrid, WINRT_WRAP(Windows::UI::Xaml::Automation::Provider::IRawElementProviderSimple));
            *value = detach_from<Windows::UI::Xaml::Automation::Provider::IRawElementProviderSimple>(this->shim().ContainingGrid());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Row(int32_t* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Row, WINRT_WRAP(int32_t));
            *value = detach_from<int32_t>(this->shim().Row());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_RowSpan(int32_t* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(RowSpan, WINRT_WRAP(int32_t));
            *value = detach_from<int32_t>(this->shim().RowSpan());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Xaml::Automation::Provider::IGridProvider> : produce_base<D, Windows::UI::Xaml::Automation::Provider::IGridProvider>
{
    int32_t WINRT_CALL get_ColumnCount(int32_t* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ColumnCount, WINRT_WRAP(int32_t));
            *value = detach_from<int32_t>(this->shim().ColumnCount());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_RowCount(int32_t* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(RowCount, WINRT_WRAP(int32_t));
            *value = detach_from<int32_t>(this->shim().RowCount());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL GetItem(int32_t row, int32_t column, void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetItem, WINRT_WRAP(Windows::UI::Xaml::Automation::Provider::IRawElementProviderSimple), int32_t, int32_t);
            *result = detach_from<Windows::UI::Xaml::Automation::Provider::IRawElementProviderSimple>(this->shim().GetItem(row, column));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Xaml::Automation::Provider::IIRawElementProviderSimple> : produce_base<D, Windows::UI::Xaml::Automation::Provider::IIRawElementProviderSimple>
{};

template <typename D>
struct produce<D, Windows::UI::Xaml::Automation::Provider::IInvokeProvider> : produce_base<D, Windows::UI::Xaml::Automation::Provider::IInvokeProvider>
{
    int32_t WINRT_CALL Invoke() noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Invoke, WINRT_WRAP(void));
            this->shim().Invoke();
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Xaml::Automation::Provider::IItemContainerProvider> : produce_base<D, Windows::UI::Xaml::Automation::Provider::IItemContainerProvider>
{
    int32_t WINRT_CALL FindItemByProperty(void* startAfter, void* automationProperty, void* value, void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(FindItemByProperty, WINRT_WRAP(Windows::UI::Xaml::Automation::Provider::IRawElementProviderSimple), Windows::UI::Xaml::Automation::Provider::IRawElementProviderSimple const&, Windows::UI::Xaml::Automation::AutomationProperty const&, Windows::Foundation::IInspectable const&);
            *result = detach_from<Windows::UI::Xaml::Automation::Provider::IRawElementProviderSimple>(this->shim().FindItemByProperty(*reinterpret_cast<Windows::UI::Xaml::Automation::Provider::IRawElementProviderSimple const*>(&startAfter), *reinterpret_cast<Windows::UI::Xaml::Automation::AutomationProperty const*>(&automationProperty), *reinterpret_cast<Windows::Foundation::IInspectable const*>(&value)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Xaml::Automation::Provider::IMultipleViewProvider> : produce_base<D, Windows::UI::Xaml::Automation::Provider::IMultipleViewProvider>
{
    int32_t WINRT_CALL get_CurrentView(int32_t* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CurrentView, WINRT_WRAP(int32_t));
            *value = detach_from<int32_t>(this->shim().CurrentView());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL GetSupportedViews(uint32_t* __resultSize, int32_t** result) noexcept final
    {
        try
        {
            *__resultSize = 0;
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetSupportedViews, WINRT_WRAP(com_array<int32_t>));
            std::tie(*__resultSize, *result) = detach_abi(this->shim().GetSupportedViews());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL GetViewName(int32_t viewId, void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetViewName, WINRT_WRAP(hstring), int32_t);
            *result = detach_from<hstring>(this->shim().GetViewName(viewId));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL SetCurrentView(int32_t viewId) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SetCurrentView, WINRT_WRAP(void), int32_t);
            this->shim().SetCurrentView(viewId);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Xaml::Automation::Provider::IObjectModelProvider> : produce_base<D, Windows::UI::Xaml::Automation::Provider::IObjectModelProvider>
{
    int32_t WINRT_CALL GetUnderlyingObjectModel(void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetUnderlyingObjectModel, WINRT_WRAP(Windows::Foundation::IInspectable));
            *result = detach_from<Windows::Foundation::IInspectable>(this->shim().GetUnderlyingObjectModel());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Xaml::Automation::Provider::IRangeValueProvider> : produce_base<D, Windows::UI::Xaml::Automation::Provider::IRangeValueProvider>
{
    int32_t WINRT_CALL get_IsReadOnly(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IsReadOnly, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().IsReadOnly());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_LargeChange(double* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(LargeChange, WINRT_WRAP(double));
            *value = detach_from<double>(this->shim().LargeChange());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Maximum(double* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Maximum, WINRT_WRAP(double));
            *value = detach_from<double>(this->shim().Maximum());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Minimum(double* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Minimum, WINRT_WRAP(double));
            *value = detach_from<double>(this->shim().Minimum());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_SmallChange(double* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SmallChange, WINRT_WRAP(double));
            *value = detach_from<double>(this->shim().SmallChange());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Value(double* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Value, WINRT_WRAP(double));
            *value = detach_from<double>(this->shim().Value());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL SetValue(double value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SetValue, WINRT_WRAP(void), double);
            this->shim().SetValue(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Xaml::Automation::Provider::IScrollItemProvider> : produce_base<D, Windows::UI::Xaml::Automation::Provider::IScrollItemProvider>
{
    int32_t WINRT_CALL ScrollIntoView() noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ScrollIntoView, WINRT_WRAP(void));
            this->shim().ScrollIntoView();
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Xaml::Automation::Provider::IScrollProvider> : produce_base<D, Windows::UI::Xaml::Automation::Provider::IScrollProvider>
{
    int32_t WINRT_CALL get_HorizontallyScrollable(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(HorizontallyScrollable, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().HorizontallyScrollable());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_HorizontalScrollPercent(double* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(HorizontalScrollPercent, WINRT_WRAP(double));
            *value = detach_from<double>(this->shim().HorizontalScrollPercent());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_HorizontalViewSize(double* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(HorizontalViewSize, WINRT_WRAP(double));
            *value = detach_from<double>(this->shim().HorizontalViewSize());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_VerticallyScrollable(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(VerticallyScrollable, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().VerticallyScrollable());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_VerticalScrollPercent(double* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(VerticalScrollPercent, WINRT_WRAP(double));
            *value = detach_from<double>(this->shim().VerticalScrollPercent());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_VerticalViewSize(double* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(VerticalViewSize, WINRT_WRAP(double));
            *value = detach_from<double>(this->shim().VerticalViewSize());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL Scroll(Windows::UI::Xaml::Automation::ScrollAmount horizontalAmount, Windows::UI::Xaml::Automation::ScrollAmount verticalAmount) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Scroll, WINRT_WRAP(void), Windows::UI::Xaml::Automation::ScrollAmount const&, Windows::UI::Xaml::Automation::ScrollAmount const&);
            this->shim().Scroll(*reinterpret_cast<Windows::UI::Xaml::Automation::ScrollAmount const*>(&horizontalAmount), *reinterpret_cast<Windows::UI::Xaml::Automation::ScrollAmount const*>(&verticalAmount));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL SetScrollPercent(double horizontalPercent, double verticalPercent) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SetScrollPercent, WINRT_WRAP(void), double, double);
            this->shim().SetScrollPercent(horizontalPercent, verticalPercent);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Xaml::Automation::Provider::ISelectionItemProvider> : produce_base<D, Windows::UI::Xaml::Automation::Provider::ISelectionItemProvider>
{
    int32_t WINRT_CALL get_IsSelected(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IsSelected, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().IsSelected());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_SelectionContainer(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SelectionContainer, WINRT_WRAP(Windows::UI::Xaml::Automation::Provider::IRawElementProviderSimple));
            *value = detach_from<Windows::UI::Xaml::Automation::Provider::IRawElementProviderSimple>(this->shim().SelectionContainer());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL AddToSelection() noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(AddToSelection, WINRT_WRAP(void));
            this->shim().AddToSelection();
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL RemoveFromSelection() noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(RemoveFromSelection, WINRT_WRAP(void));
            this->shim().RemoveFromSelection();
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL Select() noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Select, WINRT_WRAP(void));
            this->shim().Select();
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Xaml::Automation::Provider::ISelectionProvider> : produce_base<D, Windows::UI::Xaml::Automation::Provider::ISelectionProvider>
{
    int32_t WINRT_CALL get_CanSelectMultiple(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CanSelectMultiple, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().CanSelectMultiple());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_IsSelectionRequired(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IsSelectionRequired, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().IsSelectionRequired());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL GetSelection(uint32_t* __resultSize, void*** result) noexcept final
    {
        try
        {
            *__resultSize = 0;
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetSelection, WINRT_WRAP(com_array<Windows::UI::Xaml::Automation::Provider::IRawElementProviderSimple>));
            std::tie(*__resultSize, *result) = detach_abi(this->shim().GetSelection());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Xaml::Automation::Provider::ISpreadsheetItemProvider> : produce_base<D, Windows::UI::Xaml::Automation::Provider::ISpreadsheetItemProvider>
{
    int32_t WINRT_CALL get_Formula(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Formula, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().Formula());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL GetAnnotationObjects(uint32_t* __resultSize, void*** result) noexcept final
    {
        try
        {
            *__resultSize = 0;
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetAnnotationObjects, WINRT_WRAP(com_array<Windows::UI::Xaml::Automation::Provider::IRawElementProviderSimple>));
            std::tie(*__resultSize, *result) = detach_abi(this->shim().GetAnnotationObjects());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL GetAnnotationTypes(uint32_t* __resultSize, Windows::UI::Xaml::Automation::AnnotationType** result) noexcept final
    {
        try
        {
            *__resultSize = 0;
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetAnnotationTypes, WINRT_WRAP(com_array<Windows::UI::Xaml::Automation::AnnotationType>));
            std::tie(*__resultSize, *result) = detach_abi(this->shim().GetAnnotationTypes());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Xaml::Automation::Provider::ISpreadsheetProvider> : produce_base<D, Windows::UI::Xaml::Automation::Provider::ISpreadsheetProvider>
{
    int32_t WINRT_CALL GetItemByName(void* name, void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetItemByName, WINRT_WRAP(Windows::UI::Xaml::Automation::Provider::IRawElementProviderSimple), hstring const&);
            *result = detach_from<Windows::UI::Xaml::Automation::Provider::IRawElementProviderSimple>(this->shim().GetItemByName(*reinterpret_cast<hstring const*>(&name)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Xaml::Automation::Provider::IStylesProvider> : produce_base<D, Windows::UI::Xaml::Automation::Provider::IStylesProvider>
{
    int32_t WINRT_CALL get_ExtendedProperties(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ExtendedProperties, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().ExtendedProperties());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_FillColor(struct struct_Windows_UI_Color* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(FillColor, WINRT_WRAP(Windows::UI::Color));
            *value = detach_from<Windows::UI::Color>(this->shim().FillColor());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_FillPatternColor(struct struct_Windows_UI_Color* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(FillPatternColor, WINRT_WRAP(Windows::UI::Color));
            *value = detach_from<Windows::UI::Color>(this->shim().FillPatternColor());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_FillPatternStyle(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(FillPatternStyle, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().FillPatternStyle());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Shape(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Shape, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().Shape());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_StyleId(int32_t* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(StyleId, WINRT_WRAP(int32_t));
            *value = detach_from<int32_t>(this->shim().StyleId());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_StyleName(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(StyleName, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().StyleName());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Xaml::Automation::Provider::ISynchronizedInputProvider> : produce_base<D, Windows::UI::Xaml::Automation::Provider::ISynchronizedInputProvider>
{
    int32_t WINRT_CALL Cancel() noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Cancel, WINRT_WRAP(void));
            this->shim().Cancel();
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL StartListening(Windows::UI::Xaml::Automation::SynchronizedInputType inputType) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(StartListening, WINRT_WRAP(void), Windows::UI::Xaml::Automation::SynchronizedInputType const&);
            this->shim().StartListening(*reinterpret_cast<Windows::UI::Xaml::Automation::SynchronizedInputType const*>(&inputType));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Xaml::Automation::Provider::ITableItemProvider> : produce_base<D, Windows::UI::Xaml::Automation::Provider::ITableItemProvider>
{
    int32_t WINRT_CALL GetColumnHeaderItems(uint32_t* __resultSize, void*** result) noexcept final
    {
        try
        {
            *__resultSize = 0;
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetColumnHeaderItems, WINRT_WRAP(com_array<Windows::UI::Xaml::Automation::Provider::IRawElementProviderSimple>));
            std::tie(*__resultSize, *result) = detach_abi(this->shim().GetColumnHeaderItems());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL GetRowHeaderItems(uint32_t* __resultSize, void*** result) noexcept final
    {
        try
        {
            *__resultSize = 0;
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetRowHeaderItems, WINRT_WRAP(com_array<Windows::UI::Xaml::Automation::Provider::IRawElementProviderSimple>));
            std::tie(*__resultSize, *result) = detach_abi(this->shim().GetRowHeaderItems());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Xaml::Automation::Provider::ITableProvider> : produce_base<D, Windows::UI::Xaml::Automation::Provider::ITableProvider>
{
    int32_t WINRT_CALL get_RowOrColumnMajor(Windows::UI::Xaml::Automation::RowOrColumnMajor* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(RowOrColumnMajor, WINRT_WRAP(Windows::UI::Xaml::Automation::RowOrColumnMajor));
            *value = detach_from<Windows::UI::Xaml::Automation::RowOrColumnMajor>(this->shim().RowOrColumnMajor());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL GetColumnHeaders(uint32_t* __resultSize, void*** result) noexcept final
    {
        try
        {
            *__resultSize = 0;
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetColumnHeaders, WINRT_WRAP(com_array<Windows::UI::Xaml::Automation::Provider::IRawElementProviderSimple>));
            std::tie(*__resultSize, *result) = detach_abi(this->shim().GetColumnHeaders());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL GetRowHeaders(uint32_t* __resultSize, void*** result) noexcept final
    {
        try
        {
            *__resultSize = 0;
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetRowHeaders, WINRT_WRAP(com_array<Windows::UI::Xaml::Automation::Provider::IRawElementProviderSimple>));
            std::tie(*__resultSize, *result) = detach_abi(this->shim().GetRowHeaders());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Xaml::Automation::Provider::ITextChildProvider> : produce_base<D, Windows::UI::Xaml::Automation::Provider::ITextChildProvider>
{
    int32_t WINRT_CALL get_TextContainer(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(TextContainer, WINRT_WRAP(Windows::UI::Xaml::Automation::Provider::IRawElementProviderSimple));
            *value = detach_from<Windows::UI::Xaml::Automation::Provider::IRawElementProviderSimple>(this->shim().TextContainer());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_TextRange(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(TextRange, WINRT_WRAP(Windows::UI::Xaml::Automation::Provider::ITextRangeProvider));
            *value = detach_from<Windows::UI::Xaml::Automation::Provider::ITextRangeProvider>(this->shim().TextRange());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Xaml::Automation::Provider::ITextEditProvider> : produce_base<D, Windows::UI::Xaml::Automation::Provider::ITextEditProvider>
{
    int32_t WINRT_CALL GetActiveComposition(void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetActiveComposition, WINRT_WRAP(Windows::UI::Xaml::Automation::Provider::ITextRangeProvider));
            *result = detach_from<Windows::UI::Xaml::Automation::Provider::ITextRangeProvider>(this->shim().GetActiveComposition());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL GetConversionTarget(void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetConversionTarget, WINRT_WRAP(Windows::UI::Xaml::Automation::Provider::ITextRangeProvider));
            *result = detach_from<Windows::UI::Xaml::Automation::Provider::ITextRangeProvider>(this->shim().GetConversionTarget());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Xaml::Automation::Provider::ITextProvider> : produce_base<D, Windows::UI::Xaml::Automation::Provider::ITextProvider>
{
    int32_t WINRT_CALL get_DocumentRange(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(DocumentRange, WINRT_WRAP(Windows::UI::Xaml::Automation::Provider::ITextRangeProvider));
            *value = detach_from<Windows::UI::Xaml::Automation::Provider::ITextRangeProvider>(this->shim().DocumentRange());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_SupportedTextSelection(Windows::UI::Xaml::Automation::SupportedTextSelection* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SupportedTextSelection, WINRT_WRAP(Windows::UI::Xaml::Automation::SupportedTextSelection));
            *value = detach_from<Windows::UI::Xaml::Automation::SupportedTextSelection>(this->shim().SupportedTextSelection());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL GetSelection(uint32_t* __resultSize, void*** result) noexcept final
    {
        try
        {
            *__resultSize = 0;
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetSelection, WINRT_WRAP(com_array<Windows::UI::Xaml::Automation::Provider::ITextRangeProvider>));
            std::tie(*__resultSize, *result) = detach_abi(this->shim().GetSelection());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL GetVisibleRanges(uint32_t* __resultSize, void*** result) noexcept final
    {
        try
        {
            *__resultSize = 0;
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetVisibleRanges, WINRT_WRAP(com_array<Windows::UI::Xaml::Automation::Provider::ITextRangeProvider>));
            std::tie(*__resultSize, *result) = detach_abi(this->shim().GetVisibleRanges());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL RangeFromChild(void* childElement, void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(RangeFromChild, WINRT_WRAP(Windows::UI::Xaml::Automation::Provider::ITextRangeProvider), Windows::UI::Xaml::Automation::Provider::IRawElementProviderSimple const&);
            *result = detach_from<Windows::UI::Xaml::Automation::Provider::ITextRangeProvider>(this->shim().RangeFromChild(*reinterpret_cast<Windows::UI::Xaml::Automation::Provider::IRawElementProviderSimple const*>(&childElement)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL RangeFromPoint(Windows::Foundation::Point screenLocation, void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(RangeFromPoint, WINRT_WRAP(Windows::UI::Xaml::Automation::Provider::ITextRangeProvider), Windows::Foundation::Point const&);
            *result = detach_from<Windows::UI::Xaml::Automation::Provider::ITextRangeProvider>(this->shim().RangeFromPoint(*reinterpret_cast<Windows::Foundation::Point const*>(&screenLocation)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Xaml::Automation::Provider::ITextProvider2> : produce_base<D, Windows::UI::Xaml::Automation::Provider::ITextProvider2>
{
    int32_t WINRT_CALL RangeFromAnnotation(void* annotationElement, void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(RangeFromAnnotation, WINRT_WRAP(Windows::UI::Xaml::Automation::Provider::ITextRangeProvider), Windows::UI::Xaml::Automation::Provider::IRawElementProviderSimple const&);
            *result = detach_from<Windows::UI::Xaml::Automation::Provider::ITextRangeProvider>(this->shim().RangeFromAnnotation(*reinterpret_cast<Windows::UI::Xaml::Automation::Provider::IRawElementProviderSimple const*>(&annotationElement)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL GetCaretRange(bool* isActive, void** returnValue) noexcept final
    {
        try
        {
            *returnValue = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetCaretRange, WINRT_WRAP(Windows::UI::Xaml::Automation::Provider::ITextRangeProvider), bool&);
            *returnValue = detach_from<Windows::UI::Xaml::Automation::Provider::ITextRangeProvider>(this->shim().GetCaretRange(*isActive));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Xaml::Automation::Provider::ITextRangeProvider> : produce_base<D, Windows::UI::Xaml::Automation::Provider::ITextRangeProvider>
{
    int32_t WINRT_CALL Clone(void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Clone, WINRT_WRAP(Windows::UI::Xaml::Automation::Provider::ITextRangeProvider));
            *result = detach_from<Windows::UI::Xaml::Automation::Provider::ITextRangeProvider>(this->shim().Clone());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL Compare(void* textRangeProvider, bool* result) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Compare, WINRT_WRAP(bool), Windows::UI::Xaml::Automation::Provider::ITextRangeProvider const&);
            *result = detach_from<bool>(this->shim().Compare(*reinterpret_cast<Windows::UI::Xaml::Automation::Provider::ITextRangeProvider const*>(&textRangeProvider)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL CompareEndpoints(Windows::UI::Xaml::Automation::Text::TextPatternRangeEndpoint endpoint, void* textRangeProvider, Windows::UI::Xaml::Automation::Text::TextPatternRangeEndpoint targetEndpoint, int32_t* result) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CompareEndpoints, WINRT_WRAP(int32_t), Windows::UI::Xaml::Automation::Text::TextPatternRangeEndpoint const&, Windows::UI::Xaml::Automation::Provider::ITextRangeProvider const&, Windows::UI::Xaml::Automation::Text::TextPatternRangeEndpoint const&);
            *result = detach_from<int32_t>(this->shim().CompareEndpoints(*reinterpret_cast<Windows::UI::Xaml::Automation::Text::TextPatternRangeEndpoint const*>(&endpoint), *reinterpret_cast<Windows::UI::Xaml::Automation::Provider::ITextRangeProvider const*>(&textRangeProvider), *reinterpret_cast<Windows::UI::Xaml::Automation::Text::TextPatternRangeEndpoint const*>(&targetEndpoint)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL ExpandToEnclosingUnit(Windows::UI::Xaml::Automation::Text::TextUnit unit) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ExpandToEnclosingUnit, WINRT_WRAP(void), Windows::UI::Xaml::Automation::Text::TextUnit const&);
            this->shim().ExpandToEnclosingUnit(*reinterpret_cast<Windows::UI::Xaml::Automation::Text::TextUnit const*>(&unit));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL FindAttribute(int32_t attributeId, void* value, bool backward, void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(FindAttribute, WINRT_WRAP(Windows::UI::Xaml::Automation::Provider::ITextRangeProvider), int32_t, Windows::Foundation::IInspectable const&, bool);
            *result = detach_from<Windows::UI::Xaml::Automation::Provider::ITextRangeProvider>(this->shim().FindAttribute(attributeId, *reinterpret_cast<Windows::Foundation::IInspectable const*>(&value), backward));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL FindText(void* text, bool backward, bool ignoreCase, void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(FindText, WINRT_WRAP(Windows::UI::Xaml::Automation::Provider::ITextRangeProvider), hstring const&, bool, bool);
            *result = detach_from<Windows::UI::Xaml::Automation::Provider::ITextRangeProvider>(this->shim().FindText(*reinterpret_cast<hstring const*>(&text), backward, ignoreCase));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL GetAttributeValue(int32_t attributeId, void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetAttributeValue, WINRT_WRAP(Windows::Foundation::IInspectable), int32_t);
            *result = detach_from<Windows::Foundation::IInspectable>(this->shim().GetAttributeValue(attributeId));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL GetBoundingRectangles(uint32_t* __returnValueSize, double** returnValue) noexcept final
    {
        try
        {
            *__returnValueSize = 0;
            *returnValue = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetBoundingRectangles, WINRT_WRAP(void), com_array<double>&);
            this->shim().GetBoundingRectangles(detach_abi<double>(__returnValueSize, returnValue));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL GetEnclosingElement(void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetEnclosingElement, WINRT_WRAP(Windows::UI::Xaml::Automation::Provider::IRawElementProviderSimple));
            *result = detach_from<Windows::UI::Xaml::Automation::Provider::IRawElementProviderSimple>(this->shim().GetEnclosingElement());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL GetText(int32_t maxLength, void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetText, WINRT_WRAP(hstring), int32_t);
            *result = detach_from<hstring>(this->shim().GetText(maxLength));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL Move(Windows::UI::Xaml::Automation::Text::TextUnit unit, int32_t count, int32_t* result) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Move, WINRT_WRAP(int32_t), Windows::UI::Xaml::Automation::Text::TextUnit const&, int32_t);
            *result = detach_from<int32_t>(this->shim().Move(*reinterpret_cast<Windows::UI::Xaml::Automation::Text::TextUnit const*>(&unit), count));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL MoveEndpointByUnit(Windows::UI::Xaml::Automation::Text::TextPatternRangeEndpoint endpoint, Windows::UI::Xaml::Automation::Text::TextUnit unit, int32_t count, int32_t* result) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(MoveEndpointByUnit, WINRT_WRAP(int32_t), Windows::UI::Xaml::Automation::Text::TextPatternRangeEndpoint const&, Windows::UI::Xaml::Automation::Text::TextUnit const&, int32_t);
            *result = detach_from<int32_t>(this->shim().MoveEndpointByUnit(*reinterpret_cast<Windows::UI::Xaml::Automation::Text::TextPatternRangeEndpoint const*>(&endpoint), *reinterpret_cast<Windows::UI::Xaml::Automation::Text::TextUnit const*>(&unit), count));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL MoveEndpointByRange(Windows::UI::Xaml::Automation::Text::TextPatternRangeEndpoint endpoint, void* textRangeProvider, Windows::UI::Xaml::Automation::Text::TextPatternRangeEndpoint targetEndpoint) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(MoveEndpointByRange, WINRT_WRAP(void), Windows::UI::Xaml::Automation::Text::TextPatternRangeEndpoint const&, Windows::UI::Xaml::Automation::Provider::ITextRangeProvider const&, Windows::UI::Xaml::Automation::Text::TextPatternRangeEndpoint const&);
            this->shim().MoveEndpointByRange(*reinterpret_cast<Windows::UI::Xaml::Automation::Text::TextPatternRangeEndpoint const*>(&endpoint), *reinterpret_cast<Windows::UI::Xaml::Automation::Provider::ITextRangeProvider const*>(&textRangeProvider), *reinterpret_cast<Windows::UI::Xaml::Automation::Text::TextPatternRangeEndpoint const*>(&targetEndpoint));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL Select() noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Select, WINRT_WRAP(void));
            this->shim().Select();
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL AddToSelection() noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(AddToSelection, WINRT_WRAP(void));
            this->shim().AddToSelection();
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL RemoveFromSelection() noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(RemoveFromSelection, WINRT_WRAP(void));
            this->shim().RemoveFromSelection();
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL ScrollIntoView(bool alignToTop) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ScrollIntoView, WINRT_WRAP(void), bool);
            this->shim().ScrollIntoView(alignToTop);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL GetChildren(uint32_t* __resultSize, void*** result) noexcept final
    {
        try
        {
            *__resultSize = 0;
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetChildren, WINRT_WRAP(com_array<Windows::UI::Xaml::Automation::Provider::IRawElementProviderSimple>));
            std::tie(*__resultSize, *result) = detach_abi(this->shim().GetChildren());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Xaml::Automation::Provider::ITextRangeProvider2> : produce_base<D, Windows::UI::Xaml::Automation::Provider::ITextRangeProvider2>
{
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
};

template <typename D>
struct produce<D, Windows::UI::Xaml::Automation::Provider::IToggleProvider> : produce_base<D, Windows::UI::Xaml::Automation::Provider::IToggleProvider>
{
    int32_t WINRT_CALL get_ToggleState(Windows::UI::Xaml::Automation::ToggleState* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ToggleState, WINRT_WRAP(Windows::UI::Xaml::Automation::ToggleState));
            *value = detach_from<Windows::UI::Xaml::Automation::ToggleState>(this->shim().ToggleState());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL Toggle() noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Toggle, WINRT_WRAP(void));
            this->shim().Toggle();
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Xaml::Automation::Provider::ITransformProvider> : produce_base<D, Windows::UI::Xaml::Automation::Provider::ITransformProvider>
{
    int32_t WINRT_CALL get_CanMove(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CanMove, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().CanMove());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_CanResize(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CanResize, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().CanResize());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_CanRotate(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CanRotate, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().CanRotate());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL Move(double x, double y) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Move, WINRT_WRAP(void), double, double);
            this->shim().Move(x, y);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL Resize(double width, double height) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Resize, WINRT_WRAP(void), double, double);
            this->shim().Resize(width, height);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL Rotate(double degrees) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Rotate, WINRT_WRAP(void), double);
            this->shim().Rotate(degrees);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Xaml::Automation::Provider::ITransformProvider2> : produce_base<D, Windows::UI::Xaml::Automation::Provider::ITransformProvider2>
{
    int32_t WINRT_CALL get_CanZoom(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CanZoom, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().CanZoom());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_ZoomLevel(double* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ZoomLevel, WINRT_WRAP(double));
            *value = detach_from<double>(this->shim().ZoomLevel());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_MaxZoom(double* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(MaxZoom, WINRT_WRAP(double));
            *value = detach_from<double>(this->shim().MaxZoom());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_MinZoom(double* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(MinZoom, WINRT_WRAP(double));
            *value = detach_from<double>(this->shim().MinZoom());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL Zoom(double zoom) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Zoom, WINRT_WRAP(void), double);
            this->shim().Zoom(zoom);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL ZoomByUnit(Windows::UI::Xaml::Automation::ZoomUnit zoomUnit) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ZoomByUnit, WINRT_WRAP(void), Windows::UI::Xaml::Automation::ZoomUnit const&);
            this->shim().ZoomByUnit(*reinterpret_cast<Windows::UI::Xaml::Automation::ZoomUnit const*>(&zoomUnit));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Xaml::Automation::Provider::IValueProvider> : produce_base<D, Windows::UI::Xaml::Automation::Provider::IValueProvider>
{
    int32_t WINRT_CALL get_IsReadOnly(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IsReadOnly, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().IsReadOnly());
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

    int32_t WINRT_CALL SetValue(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SetValue, WINRT_WRAP(void), hstring const&);
            this->shim().SetValue(*reinterpret_cast<hstring const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Xaml::Automation::Provider::IVirtualizedItemProvider> : produce_base<D, Windows::UI::Xaml::Automation::Provider::IVirtualizedItemProvider>
{
    int32_t WINRT_CALL Realize() noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Realize, WINRT_WRAP(void));
            this->shim().Realize();
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Xaml::Automation::Provider::IWindowProvider> : produce_base<D, Windows::UI::Xaml::Automation::Provider::IWindowProvider>
{
    int32_t WINRT_CALL get_IsModal(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IsModal, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().IsModal());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_IsTopmost(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IsTopmost, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().IsTopmost());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Maximizable(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Maximizable, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().Maximizable());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Minimizable(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Minimizable, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().Minimizable());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_InteractionState(Windows::UI::Xaml::Automation::WindowInteractionState* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(InteractionState, WINRT_WRAP(Windows::UI::Xaml::Automation::WindowInteractionState));
            *value = detach_from<Windows::UI::Xaml::Automation::WindowInteractionState>(this->shim().InteractionState());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_VisualState(Windows::UI::Xaml::Automation::WindowVisualState* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(VisualState, WINRT_WRAP(Windows::UI::Xaml::Automation::WindowVisualState));
            *value = detach_from<Windows::UI::Xaml::Automation::WindowVisualState>(this->shim().VisualState());
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

    int32_t WINRT_CALL SetVisualState(Windows::UI::Xaml::Automation::WindowVisualState state) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SetVisualState, WINRT_WRAP(void), Windows::UI::Xaml::Automation::WindowVisualState const&);
            this->shim().SetVisualState(*reinterpret_cast<Windows::UI::Xaml::Automation::WindowVisualState const*>(&state));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL WaitForInputIdle(int32_t milliseconds, bool* result) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(WaitForInputIdle, WINRT_WRAP(bool), int32_t);
            *result = detach_from<bool>(this->shim().WaitForInputIdle(milliseconds));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

}

WINRT_EXPORT namespace winrt::Windows::UI::Xaml::Automation::Provider {

}

WINRT_EXPORT namespace std {

template<> struct hash<winrt::Windows::UI::Xaml::Automation::Provider::IAnnotationProvider> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Automation::Provider::IAnnotationProvider> {};
template<> struct hash<winrt::Windows::UI::Xaml::Automation::Provider::ICustomNavigationProvider> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Automation::Provider::ICustomNavigationProvider> {};
template<> struct hash<winrt::Windows::UI::Xaml::Automation::Provider::IDockProvider> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Automation::Provider::IDockProvider> {};
template<> struct hash<winrt::Windows::UI::Xaml::Automation::Provider::IDragProvider> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Automation::Provider::IDragProvider> {};
template<> struct hash<winrt::Windows::UI::Xaml::Automation::Provider::IDropTargetProvider> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Automation::Provider::IDropTargetProvider> {};
template<> struct hash<winrt::Windows::UI::Xaml::Automation::Provider::IExpandCollapseProvider> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Automation::Provider::IExpandCollapseProvider> {};
template<> struct hash<winrt::Windows::UI::Xaml::Automation::Provider::IGridItemProvider> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Automation::Provider::IGridItemProvider> {};
template<> struct hash<winrt::Windows::UI::Xaml::Automation::Provider::IGridProvider> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Automation::Provider::IGridProvider> {};
template<> struct hash<winrt::Windows::UI::Xaml::Automation::Provider::IIRawElementProviderSimple> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Automation::Provider::IIRawElementProviderSimple> {};
template<> struct hash<winrt::Windows::UI::Xaml::Automation::Provider::IInvokeProvider> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Automation::Provider::IInvokeProvider> {};
template<> struct hash<winrt::Windows::UI::Xaml::Automation::Provider::IItemContainerProvider> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Automation::Provider::IItemContainerProvider> {};
template<> struct hash<winrt::Windows::UI::Xaml::Automation::Provider::IMultipleViewProvider> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Automation::Provider::IMultipleViewProvider> {};
template<> struct hash<winrt::Windows::UI::Xaml::Automation::Provider::IObjectModelProvider> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Automation::Provider::IObjectModelProvider> {};
template<> struct hash<winrt::Windows::UI::Xaml::Automation::Provider::IRangeValueProvider> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Automation::Provider::IRangeValueProvider> {};
template<> struct hash<winrt::Windows::UI::Xaml::Automation::Provider::IScrollItemProvider> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Automation::Provider::IScrollItemProvider> {};
template<> struct hash<winrt::Windows::UI::Xaml::Automation::Provider::IScrollProvider> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Automation::Provider::IScrollProvider> {};
template<> struct hash<winrt::Windows::UI::Xaml::Automation::Provider::ISelectionItemProvider> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Automation::Provider::ISelectionItemProvider> {};
template<> struct hash<winrt::Windows::UI::Xaml::Automation::Provider::ISelectionProvider> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Automation::Provider::ISelectionProvider> {};
template<> struct hash<winrt::Windows::UI::Xaml::Automation::Provider::ISpreadsheetItemProvider> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Automation::Provider::ISpreadsheetItemProvider> {};
template<> struct hash<winrt::Windows::UI::Xaml::Automation::Provider::ISpreadsheetProvider> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Automation::Provider::ISpreadsheetProvider> {};
template<> struct hash<winrt::Windows::UI::Xaml::Automation::Provider::IStylesProvider> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Automation::Provider::IStylesProvider> {};
template<> struct hash<winrt::Windows::UI::Xaml::Automation::Provider::ISynchronizedInputProvider> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Automation::Provider::ISynchronizedInputProvider> {};
template<> struct hash<winrt::Windows::UI::Xaml::Automation::Provider::ITableItemProvider> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Automation::Provider::ITableItemProvider> {};
template<> struct hash<winrt::Windows::UI::Xaml::Automation::Provider::ITableProvider> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Automation::Provider::ITableProvider> {};
template<> struct hash<winrt::Windows::UI::Xaml::Automation::Provider::ITextChildProvider> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Automation::Provider::ITextChildProvider> {};
template<> struct hash<winrt::Windows::UI::Xaml::Automation::Provider::ITextEditProvider> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Automation::Provider::ITextEditProvider> {};
template<> struct hash<winrt::Windows::UI::Xaml::Automation::Provider::ITextProvider> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Automation::Provider::ITextProvider> {};
template<> struct hash<winrt::Windows::UI::Xaml::Automation::Provider::ITextProvider2> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Automation::Provider::ITextProvider2> {};
template<> struct hash<winrt::Windows::UI::Xaml::Automation::Provider::ITextRangeProvider> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Automation::Provider::ITextRangeProvider> {};
template<> struct hash<winrt::Windows::UI::Xaml::Automation::Provider::ITextRangeProvider2> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Automation::Provider::ITextRangeProvider2> {};
template<> struct hash<winrt::Windows::UI::Xaml::Automation::Provider::IToggleProvider> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Automation::Provider::IToggleProvider> {};
template<> struct hash<winrt::Windows::UI::Xaml::Automation::Provider::ITransformProvider> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Automation::Provider::ITransformProvider> {};
template<> struct hash<winrt::Windows::UI::Xaml::Automation::Provider::ITransformProvider2> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Automation::Provider::ITransformProvider2> {};
template<> struct hash<winrt::Windows::UI::Xaml::Automation::Provider::IValueProvider> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Automation::Provider::IValueProvider> {};
template<> struct hash<winrt::Windows::UI::Xaml::Automation::Provider::IVirtualizedItemProvider> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Automation::Provider::IVirtualizedItemProvider> {};
template<> struct hash<winrt::Windows::UI::Xaml::Automation::Provider::IWindowProvider> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Automation::Provider::IWindowProvider> {};
template<> struct hash<winrt::Windows::UI::Xaml::Automation::Provider::IRawElementProviderSimple> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Automation::Provider::IRawElementProviderSimple> {};

}
