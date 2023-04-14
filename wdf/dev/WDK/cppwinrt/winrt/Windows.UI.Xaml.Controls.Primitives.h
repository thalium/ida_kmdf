// C++/WinRT v1.0.190111.3

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#pragma once

#include "winrt/base.h"

#include "winrt/Windows.Foundation.h"
#include "winrt/Windows.Foundation.Collections.h"
#include "winrt/impl/Windows.UI.2.h"
#include "winrt/impl/Windows.UI.Xaml.2.h"
#include "winrt/impl/Windows.UI.Xaml.Controls.2.h"
#include "winrt/impl/Windows.UI.Xaml.Input.2.h"
#include "winrt/impl/Windows.UI.Xaml.Interop.2.h"
#include "winrt/impl/Windows.UI.Xaml.Media.2.h"
#include "winrt/impl/Windows.UI.Xaml.Media.Animation.2.h"
#include "winrt/impl/Windows.UI.Composition.2.h"
#include "winrt/impl/Windows.UI.Xaml.Data.2.h"
#include "winrt/impl/Windows.UI.Xaml.Controls.Primitives.2.h"
#include "winrt/Windows.UI.Xaml.Controls.h"

namespace winrt::impl {

template <typename D> double consume_Windows_UI_Xaml_Controls_Primitives_IAppBarButtonTemplateSettings<D>::KeyboardAcceleratorTextMinWidth() const
{
    double value{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Primitives::IAppBarButtonTemplateSettings)->get_KeyboardAcceleratorTextMinWidth(&value));
    return value;
}

template <typename D> Windows::Foundation::Rect consume_Windows_UI_Xaml_Controls_Primitives_IAppBarTemplateSettings<D>::ClipRect() const
{
    Windows::Foundation::Rect value{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Primitives::IAppBarTemplateSettings)->get_ClipRect(put_abi(value)));
    return value;
}

template <typename D> double consume_Windows_UI_Xaml_Controls_Primitives_IAppBarTemplateSettings<D>::CompactVerticalDelta() const
{
    double value{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Primitives::IAppBarTemplateSettings)->get_CompactVerticalDelta(&value));
    return value;
}

template <typename D> Windows::UI::Xaml::Thickness consume_Windows_UI_Xaml_Controls_Primitives_IAppBarTemplateSettings<D>::CompactRootMargin() const
{
    Windows::UI::Xaml::Thickness value{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Primitives::IAppBarTemplateSettings)->get_CompactRootMargin(put_abi(value)));
    return value;
}

template <typename D> double consume_Windows_UI_Xaml_Controls_Primitives_IAppBarTemplateSettings<D>::MinimalVerticalDelta() const
{
    double value{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Primitives::IAppBarTemplateSettings)->get_MinimalVerticalDelta(&value));
    return value;
}

template <typename D> Windows::UI::Xaml::Thickness consume_Windows_UI_Xaml_Controls_Primitives_IAppBarTemplateSettings<D>::MinimalRootMargin() const
{
    Windows::UI::Xaml::Thickness value{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Primitives::IAppBarTemplateSettings)->get_MinimalRootMargin(put_abi(value)));
    return value;
}

template <typename D> double consume_Windows_UI_Xaml_Controls_Primitives_IAppBarTemplateSettings<D>::HiddenVerticalDelta() const
{
    double value{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Primitives::IAppBarTemplateSettings)->get_HiddenVerticalDelta(&value));
    return value;
}

template <typename D> Windows::UI::Xaml::Thickness consume_Windows_UI_Xaml_Controls_Primitives_IAppBarTemplateSettings<D>::HiddenRootMargin() const
{
    Windows::UI::Xaml::Thickness value{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Primitives::IAppBarTemplateSettings)->get_HiddenRootMargin(put_abi(value)));
    return value;
}

template <typename D> double consume_Windows_UI_Xaml_Controls_Primitives_IAppBarTemplateSettings2<D>::NegativeCompactVerticalDelta() const
{
    double value{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Primitives::IAppBarTemplateSettings2)->get_NegativeCompactVerticalDelta(&value));
    return value;
}

template <typename D> double consume_Windows_UI_Xaml_Controls_Primitives_IAppBarTemplateSettings2<D>::NegativeMinimalVerticalDelta() const
{
    double value{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Primitives::IAppBarTemplateSettings2)->get_NegativeMinimalVerticalDelta(&value));
    return value;
}

template <typename D> double consume_Windows_UI_Xaml_Controls_Primitives_IAppBarTemplateSettings2<D>::NegativeHiddenVerticalDelta() const
{
    double value{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Primitives::IAppBarTemplateSettings2)->get_NegativeHiddenVerticalDelta(&value));
    return value;
}

template <typename D> double consume_Windows_UI_Xaml_Controls_Primitives_IAppBarToggleButtonTemplateSettings<D>::KeyboardAcceleratorTextMinWidth() const
{
    double value{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Primitives::IAppBarToggleButtonTemplateSettings)->get_KeyboardAcceleratorTextMinWidth(&value));
    return value;
}

template <typename D> Windows::UI::Xaml::Controls::ClickMode consume_Windows_UI_Xaml_Controls_Primitives_IButtonBase<D>::ClickMode() const
{
    Windows::UI::Xaml::Controls::ClickMode value{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Primitives::IButtonBase)->get_ClickMode(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_UI_Xaml_Controls_Primitives_IButtonBase<D>::ClickMode(Windows::UI::Xaml::Controls::ClickMode const& value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Primitives::IButtonBase)->put_ClickMode(get_abi(value)));
}

template <typename D> bool consume_Windows_UI_Xaml_Controls_Primitives_IButtonBase<D>::IsPointerOver() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Primitives::IButtonBase)->get_IsPointerOver(&value));
    return value;
}

template <typename D> bool consume_Windows_UI_Xaml_Controls_Primitives_IButtonBase<D>::IsPressed() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Primitives::IButtonBase)->get_IsPressed(&value));
    return value;
}

template <typename D> Windows::UI::Xaml::Input::ICommand consume_Windows_UI_Xaml_Controls_Primitives_IButtonBase<D>::Command() const
{
    Windows::UI::Xaml::Input::ICommand value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Primitives::IButtonBase)->get_Command(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_UI_Xaml_Controls_Primitives_IButtonBase<D>::Command(Windows::UI::Xaml::Input::ICommand const& value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Primitives::IButtonBase)->put_Command(get_abi(value)));
}

template <typename D> Windows::Foundation::IInspectable consume_Windows_UI_Xaml_Controls_Primitives_IButtonBase<D>::CommandParameter() const
{
    Windows::Foundation::IInspectable value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Primitives::IButtonBase)->get_CommandParameter(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_UI_Xaml_Controls_Primitives_IButtonBase<D>::CommandParameter(Windows::Foundation::IInspectable const& value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Primitives::IButtonBase)->put_CommandParameter(get_abi(value)));
}

template <typename D> winrt::event_token consume_Windows_UI_Xaml_Controls_Primitives_IButtonBase<D>::Click(Windows::UI::Xaml::RoutedEventHandler const& handler) const
{
    winrt::event_token token{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Primitives::IButtonBase)->add_Click(get_abi(handler), put_abi(token)));
    return token;
}

template <typename D> typename consume_Windows_UI_Xaml_Controls_Primitives_IButtonBase<D>::Click_revoker consume_Windows_UI_Xaml_Controls_Primitives_IButtonBase<D>::Click(auto_revoke_t, Windows::UI::Xaml::RoutedEventHandler const& handler) const
{
    return impl::make_event_revoker<D, Click_revoker>(this, Click(handler));
}

template <typename D> void consume_Windows_UI_Xaml_Controls_Primitives_IButtonBase<D>::Click(winrt::event_token const& token) const noexcept
{
    WINRT_VERIFY_(0, WINRT_SHIM(Windows::UI::Xaml::Controls::Primitives::IButtonBase)->remove_Click(get_abi(token)));
}

template <typename D> Windows::UI::Xaml::Controls::Primitives::ButtonBase consume_Windows_UI_Xaml_Controls_Primitives_IButtonBaseFactory<D>::CreateInstance(Windows::Foundation::IInspectable const& baseInterface, Windows::Foundation::IInspectable& innerInterface) const
{
    Windows::UI::Xaml::Controls::Primitives::ButtonBase value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Primitives::IButtonBaseFactory)->CreateInstance(get_abi(baseInterface), put_abi(innerInterface), put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Xaml::DependencyProperty consume_Windows_UI_Xaml_Controls_Primitives_IButtonBaseStatics<D>::ClickModeProperty() const
{
    Windows::UI::Xaml::DependencyProperty value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Primitives::IButtonBaseStatics)->get_ClickModeProperty(put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Xaml::DependencyProperty consume_Windows_UI_Xaml_Controls_Primitives_IButtonBaseStatics<D>::IsPointerOverProperty() const
{
    Windows::UI::Xaml::DependencyProperty value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Primitives::IButtonBaseStatics)->get_IsPointerOverProperty(put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Xaml::DependencyProperty consume_Windows_UI_Xaml_Controls_Primitives_IButtonBaseStatics<D>::IsPressedProperty() const
{
    Windows::UI::Xaml::DependencyProperty value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Primitives::IButtonBaseStatics)->get_IsPressedProperty(put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Xaml::DependencyProperty consume_Windows_UI_Xaml_Controls_Primitives_IButtonBaseStatics<D>::CommandProperty() const
{
    Windows::UI::Xaml::DependencyProperty value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Primitives::IButtonBaseStatics)->get_CommandProperty(put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Xaml::DependencyProperty consume_Windows_UI_Xaml_Controls_Primitives_IButtonBaseStatics<D>::CommandParameterProperty() const
{
    Windows::UI::Xaml::DependencyProperty value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Primitives::IButtonBaseStatics)->get_CommandParameterProperty(put_abi(value)));
    return value;
}

template <typename D> double consume_Windows_UI_Xaml_Controls_Primitives_ICalendarViewTemplateSettings<D>::MinViewWidth() const
{
    double value{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Primitives::ICalendarViewTemplateSettings)->get_MinViewWidth(&value));
    return value;
}

template <typename D> hstring consume_Windows_UI_Xaml_Controls_Primitives_ICalendarViewTemplateSettings<D>::HeaderText() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Primitives::ICalendarViewTemplateSettings)->get_HeaderText(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_UI_Xaml_Controls_Primitives_ICalendarViewTemplateSettings<D>::WeekDay1() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Primitives::ICalendarViewTemplateSettings)->get_WeekDay1(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_UI_Xaml_Controls_Primitives_ICalendarViewTemplateSettings<D>::WeekDay2() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Primitives::ICalendarViewTemplateSettings)->get_WeekDay2(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_UI_Xaml_Controls_Primitives_ICalendarViewTemplateSettings<D>::WeekDay3() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Primitives::ICalendarViewTemplateSettings)->get_WeekDay3(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_UI_Xaml_Controls_Primitives_ICalendarViewTemplateSettings<D>::WeekDay4() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Primitives::ICalendarViewTemplateSettings)->get_WeekDay4(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_UI_Xaml_Controls_Primitives_ICalendarViewTemplateSettings<D>::WeekDay5() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Primitives::ICalendarViewTemplateSettings)->get_WeekDay5(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_UI_Xaml_Controls_Primitives_ICalendarViewTemplateSettings<D>::WeekDay6() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Primitives::ICalendarViewTemplateSettings)->get_WeekDay6(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_UI_Xaml_Controls_Primitives_ICalendarViewTemplateSettings<D>::WeekDay7() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Primitives::ICalendarViewTemplateSettings)->get_WeekDay7(put_abi(value)));
    return value;
}

template <typename D> bool consume_Windows_UI_Xaml_Controls_Primitives_ICalendarViewTemplateSettings<D>::HasMoreContentAfter() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Primitives::ICalendarViewTemplateSettings)->get_HasMoreContentAfter(&value));
    return value;
}

template <typename D> bool consume_Windows_UI_Xaml_Controls_Primitives_ICalendarViewTemplateSettings<D>::HasMoreContentBefore() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Primitives::ICalendarViewTemplateSettings)->get_HasMoreContentBefore(&value));
    return value;
}

template <typename D> bool consume_Windows_UI_Xaml_Controls_Primitives_ICalendarViewTemplateSettings<D>::HasMoreViews() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Primitives::ICalendarViewTemplateSettings)->get_HasMoreViews(&value));
    return value;
}

template <typename D> Windows::Foundation::Rect consume_Windows_UI_Xaml_Controls_Primitives_ICalendarViewTemplateSettings<D>::ClipRect() const
{
    Windows::Foundation::Rect value{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Primitives::ICalendarViewTemplateSettings)->get_ClipRect(put_abi(value)));
    return value;
}

template <typename D> double consume_Windows_UI_Xaml_Controls_Primitives_ICalendarViewTemplateSettings<D>::CenterX() const
{
    double value{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Primitives::ICalendarViewTemplateSettings)->get_CenterX(&value));
    return value;
}

template <typename D> double consume_Windows_UI_Xaml_Controls_Primitives_ICalendarViewTemplateSettings<D>::CenterY() const
{
    double value{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Primitives::ICalendarViewTemplateSettings)->get_CenterY(&value));
    return value;
}

template <typename D> bool consume_Windows_UI_Xaml_Controls_Primitives_ICarouselPanel<D>::CanVerticallyScroll() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Primitives::ICarouselPanel)->get_CanVerticallyScroll(&value));
    return value;
}

template <typename D> void consume_Windows_UI_Xaml_Controls_Primitives_ICarouselPanel<D>::CanVerticallyScroll(bool value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Primitives::ICarouselPanel)->put_CanVerticallyScroll(value));
}

template <typename D> bool consume_Windows_UI_Xaml_Controls_Primitives_ICarouselPanel<D>::CanHorizontallyScroll() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Primitives::ICarouselPanel)->get_CanHorizontallyScroll(&value));
    return value;
}

template <typename D> void consume_Windows_UI_Xaml_Controls_Primitives_ICarouselPanel<D>::CanHorizontallyScroll(bool value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Primitives::ICarouselPanel)->put_CanHorizontallyScroll(value));
}

template <typename D> double consume_Windows_UI_Xaml_Controls_Primitives_ICarouselPanel<D>::ExtentWidth() const
{
    double value{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Primitives::ICarouselPanel)->get_ExtentWidth(&value));
    return value;
}

template <typename D> double consume_Windows_UI_Xaml_Controls_Primitives_ICarouselPanel<D>::ExtentHeight() const
{
    double value{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Primitives::ICarouselPanel)->get_ExtentHeight(&value));
    return value;
}

template <typename D> double consume_Windows_UI_Xaml_Controls_Primitives_ICarouselPanel<D>::ViewportWidth() const
{
    double value{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Primitives::ICarouselPanel)->get_ViewportWidth(&value));
    return value;
}

template <typename D> double consume_Windows_UI_Xaml_Controls_Primitives_ICarouselPanel<D>::ViewportHeight() const
{
    double value{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Primitives::ICarouselPanel)->get_ViewportHeight(&value));
    return value;
}

template <typename D> double consume_Windows_UI_Xaml_Controls_Primitives_ICarouselPanel<D>::HorizontalOffset() const
{
    double value{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Primitives::ICarouselPanel)->get_HorizontalOffset(&value));
    return value;
}

template <typename D> double consume_Windows_UI_Xaml_Controls_Primitives_ICarouselPanel<D>::VerticalOffset() const
{
    double value{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Primitives::ICarouselPanel)->get_VerticalOffset(&value));
    return value;
}

template <typename D> Windows::Foundation::IInspectable consume_Windows_UI_Xaml_Controls_Primitives_ICarouselPanel<D>::ScrollOwner() const
{
    Windows::Foundation::IInspectable value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Primitives::ICarouselPanel)->get_ScrollOwner(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_UI_Xaml_Controls_Primitives_ICarouselPanel<D>::ScrollOwner(Windows::Foundation::IInspectable const& value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Primitives::ICarouselPanel)->put_ScrollOwner(get_abi(value)));
}

template <typename D> void consume_Windows_UI_Xaml_Controls_Primitives_ICarouselPanel<D>::LineUp() const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Primitives::ICarouselPanel)->LineUp());
}

template <typename D> void consume_Windows_UI_Xaml_Controls_Primitives_ICarouselPanel<D>::LineDown() const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Primitives::ICarouselPanel)->LineDown());
}

template <typename D> void consume_Windows_UI_Xaml_Controls_Primitives_ICarouselPanel<D>::LineLeft() const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Primitives::ICarouselPanel)->LineLeft());
}

template <typename D> void consume_Windows_UI_Xaml_Controls_Primitives_ICarouselPanel<D>::LineRight() const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Primitives::ICarouselPanel)->LineRight());
}

template <typename D> void consume_Windows_UI_Xaml_Controls_Primitives_ICarouselPanel<D>::PageUp() const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Primitives::ICarouselPanel)->PageUp());
}

template <typename D> void consume_Windows_UI_Xaml_Controls_Primitives_ICarouselPanel<D>::PageDown() const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Primitives::ICarouselPanel)->PageDown());
}

template <typename D> void consume_Windows_UI_Xaml_Controls_Primitives_ICarouselPanel<D>::PageLeft() const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Primitives::ICarouselPanel)->PageLeft());
}

template <typename D> void consume_Windows_UI_Xaml_Controls_Primitives_ICarouselPanel<D>::PageRight() const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Primitives::ICarouselPanel)->PageRight());
}

template <typename D> void consume_Windows_UI_Xaml_Controls_Primitives_ICarouselPanel<D>::MouseWheelUp() const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Primitives::ICarouselPanel)->MouseWheelUp());
}

template <typename D> void consume_Windows_UI_Xaml_Controls_Primitives_ICarouselPanel<D>::MouseWheelDown() const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Primitives::ICarouselPanel)->MouseWheelDown());
}

template <typename D> void consume_Windows_UI_Xaml_Controls_Primitives_ICarouselPanel<D>::MouseWheelLeft() const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Primitives::ICarouselPanel)->MouseWheelLeft());
}

template <typename D> void consume_Windows_UI_Xaml_Controls_Primitives_ICarouselPanel<D>::MouseWheelRight() const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Primitives::ICarouselPanel)->MouseWheelRight());
}

template <typename D> void consume_Windows_UI_Xaml_Controls_Primitives_ICarouselPanel<D>::SetHorizontalOffset(double offset) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Primitives::ICarouselPanel)->SetHorizontalOffset(offset));
}

template <typename D> void consume_Windows_UI_Xaml_Controls_Primitives_ICarouselPanel<D>::SetVerticalOffset(double offset) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Primitives::ICarouselPanel)->SetVerticalOffset(offset));
}

template <typename D> Windows::Foundation::Rect consume_Windows_UI_Xaml_Controls_Primitives_ICarouselPanel<D>::MakeVisible(Windows::UI::Xaml::UIElement const& visual, Windows::Foundation::Rect const& rectangle) const
{
    Windows::Foundation::Rect result{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Primitives::ICarouselPanel)->MakeVisible(get_abi(visual), get_abi(rectangle), put_abi(result)));
    return result;
}

template <typename D> Windows::UI::Xaml::Controls::Primitives::CarouselPanel consume_Windows_UI_Xaml_Controls_Primitives_ICarouselPanelFactory<D>::CreateInstance(Windows::Foundation::IInspectable const& baseInterface, Windows::Foundation::IInspectable& innerInterface) const
{
    Windows::UI::Xaml::Controls::Primitives::CarouselPanel value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Primitives::ICarouselPanelFactory)->CreateInstance(get_abi(baseInterface), put_abi(innerInterface), put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Xaml::Controls::ColorPickerHsvChannel consume_Windows_UI_Xaml_Controls_Primitives_IColorPickerSlider<D>::ColorChannel() const
{
    Windows::UI::Xaml::Controls::ColorPickerHsvChannel value{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Primitives::IColorPickerSlider)->get_ColorChannel(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_UI_Xaml_Controls_Primitives_IColorPickerSlider<D>::ColorChannel(Windows::UI::Xaml::Controls::ColorPickerHsvChannel const& value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Primitives::IColorPickerSlider)->put_ColorChannel(get_abi(value)));
}

template <typename D> Windows::UI::Xaml::Controls::Primitives::ColorPickerSlider consume_Windows_UI_Xaml_Controls_Primitives_IColorPickerSliderFactory<D>::CreateInstance(Windows::Foundation::IInspectable const& baseInterface, Windows::Foundation::IInspectable& innerInterface) const
{
    Windows::UI::Xaml::Controls::Primitives::ColorPickerSlider value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Primitives::IColorPickerSliderFactory)->CreateInstance(get_abi(baseInterface), put_abi(innerInterface), put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Xaml::DependencyProperty consume_Windows_UI_Xaml_Controls_Primitives_IColorPickerSliderStatics<D>::ColorChannelProperty() const
{
    Windows::UI::Xaml::DependencyProperty value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Primitives::IColorPickerSliderStatics)->get_ColorChannelProperty(put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Color consume_Windows_UI_Xaml_Controls_Primitives_IColorSpectrum<D>::Color() const
{
    Windows::UI::Color value{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Primitives::IColorSpectrum)->get_Color(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_UI_Xaml_Controls_Primitives_IColorSpectrum<D>::Color(Windows::UI::Color const& value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Primitives::IColorSpectrum)->put_Color(get_abi(value)));
}

template <typename D> Windows::Foundation::Numerics::float4 consume_Windows_UI_Xaml_Controls_Primitives_IColorSpectrum<D>::HsvColor() const
{
    Windows::Foundation::Numerics::float4 value{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Primitives::IColorSpectrum)->get_HsvColor(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_UI_Xaml_Controls_Primitives_IColorSpectrum<D>::HsvColor(Windows::Foundation::Numerics::float4 const& value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Primitives::IColorSpectrum)->put_HsvColor(get_abi(value)));
}

template <typename D> int32_t consume_Windows_UI_Xaml_Controls_Primitives_IColorSpectrum<D>::MinHue() const
{
    int32_t value{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Primitives::IColorSpectrum)->get_MinHue(&value));
    return value;
}

template <typename D> void consume_Windows_UI_Xaml_Controls_Primitives_IColorSpectrum<D>::MinHue(int32_t value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Primitives::IColorSpectrum)->put_MinHue(value));
}

template <typename D> int32_t consume_Windows_UI_Xaml_Controls_Primitives_IColorSpectrum<D>::MaxHue() const
{
    int32_t value{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Primitives::IColorSpectrum)->get_MaxHue(&value));
    return value;
}

template <typename D> void consume_Windows_UI_Xaml_Controls_Primitives_IColorSpectrum<D>::MaxHue(int32_t value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Primitives::IColorSpectrum)->put_MaxHue(value));
}

template <typename D> int32_t consume_Windows_UI_Xaml_Controls_Primitives_IColorSpectrum<D>::MinSaturation() const
{
    int32_t value{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Primitives::IColorSpectrum)->get_MinSaturation(&value));
    return value;
}

template <typename D> void consume_Windows_UI_Xaml_Controls_Primitives_IColorSpectrum<D>::MinSaturation(int32_t value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Primitives::IColorSpectrum)->put_MinSaturation(value));
}

template <typename D> int32_t consume_Windows_UI_Xaml_Controls_Primitives_IColorSpectrum<D>::MaxSaturation() const
{
    int32_t value{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Primitives::IColorSpectrum)->get_MaxSaturation(&value));
    return value;
}

template <typename D> void consume_Windows_UI_Xaml_Controls_Primitives_IColorSpectrum<D>::MaxSaturation(int32_t value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Primitives::IColorSpectrum)->put_MaxSaturation(value));
}

template <typename D> int32_t consume_Windows_UI_Xaml_Controls_Primitives_IColorSpectrum<D>::MinValue() const
{
    int32_t value{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Primitives::IColorSpectrum)->get_MinValue(&value));
    return value;
}

template <typename D> void consume_Windows_UI_Xaml_Controls_Primitives_IColorSpectrum<D>::MinValue(int32_t value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Primitives::IColorSpectrum)->put_MinValue(value));
}

template <typename D> int32_t consume_Windows_UI_Xaml_Controls_Primitives_IColorSpectrum<D>::MaxValue() const
{
    int32_t value{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Primitives::IColorSpectrum)->get_MaxValue(&value));
    return value;
}

template <typename D> void consume_Windows_UI_Xaml_Controls_Primitives_IColorSpectrum<D>::MaxValue(int32_t value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Primitives::IColorSpectrum)->put_MaxValue(value));
}

template <typename D> Windows::UI::Xaml::Controls::ColorSpectrumShape consume_Windows_UI_Xaml_Controls_Primitives_IColorSpectrum<D>::Shape() const
{
    Windows::UI::Xaml::Controls::ColorSpectrumShape value{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Primitives::IColorSpectrum)->get_Shape(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_UI_Xaml_Controls_Primitives_IColorSpectrum<D>::Shape(Windows::UI::Xaml::Controls::ColorSpectrumShape const& value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Primitives::IColorSpectrum)->put_Shape(get_abi(value)));
}

template <typename D> Windows::UI::Xaml::Controls::ColorSpectrumComponents consume_Windows_UI_Xaml_Controls_Primitives_IColorSpectrum<D>::Components() const
{
    Windows::UI::Xaml::Controls::ColorSpectrumComponents value{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Primitives::IColorSpectrum)->get_Components(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_UI_Xaml_Controls_Primitives_IColorSpectrum<D>::Components(Windows::UI::Xaml::Controls::ColorSpectrumComponents const& value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Primitives::IColorSpectrum)->put_Components(get_abi(value)));
}

template <typename D> winrt::event_token consume_Windows_UI_Xaml_Controls_Primitives_IColorSpectrum<D>::ColorChanged(Windows::Foundation::TypedEventHandler<Windows::UI::Xaml::Controls::Primitives::ColorSpectrum, Windows::UI::Xaml::Controls::ColorChangedEventArgs> const& handler) const
{
    winrt::event_token token{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Primitives::IColorSpectrum)->add_ColorChanged(get_abi(handler), put_abi(token)));
    return token;
}

template <typename D> typename consume_Windows_UI_Xaml_Controls_Primitives_IColorSpectrum<D>::ColorChanged_revoker consume_Windows_UI_Xaml_Controls_Primitives_IColorSpectrum<D>::ColorChanged(auto_revoke_t, Windows::Foundation::TypedEventHandler<Windows::UI::Xaml::Controls::Primitives::ColorSpectrum, Windows::UI::Xaml::Controls::ColorChangedEventArgs> const& handler) const
{
    return impl::make_event_revoker<D, ColorChanged_revoker>(this, ColorChanged(handler));
}

template <typename D> void consume_Windows_UI_Xaml_Controls_Primitives_IColorSpectrum<D>::ColorChanged(winrt::event_token const& token) const noexcept
{
    WINRT_VERIFY_(0, WINRT_SHIM(Windows::UI::Xaml::Controls::Primitives::IColorSpectrum)->remove_ColorChanged(get_abi(token)));
}

template <typename D> Windows::UI::Xaml::Controls::Primitives::ColorSpectrum consume_Windows_UI_Xaml_Controls_Primitives_IColorSpectrumFactory<D>::CreateInstance(Windows::Foundation::IInspectable const& baseInterface, Windows::Foundation::IInspectable& innerInterface) const
{
    Windows::UI::Xaml::Controls::Primitives::ColorSpectrum value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Primitives::IColorSpectrumFactory)->CreateInstance(get_abi(baseInterface), put_abi(innerInterface), put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Xaml::DependencyProperty consume_Windows_UI_Xaml_Controls_Primitives_IColorSpectrumStatics<D>::ColorProperty() const
{
    Windows::UI::Xaml::DependencyProperty value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Primitives::IColorSpectrumStatics)->get_ColorProperty(put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Xaml::DependencyProperty consume_Windows_UI_Xaml_Controls_Primitives_IColorSpectrumStatics<D>::HsvColorProperty() const
{
    Windows::UI::Xaml::DependencyProperty value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Primitives::IColorSpectrumStatics)->get_HsvColorProperty(put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Xaml::DependencyProperty consume_Windows_UI_Xaml_Controls_Primitives_IColorSpectrumStatics<D>::MinHueProperty() const
{
    Windows::UI::Xaml::DependencyProperty value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Primitives::IColorSpectrumStatics)->get_MinHueProperty(put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Xaml::DependencyProperty consume_Windows_UI_Xaml_Controls_Primitives_IColorSpectrumStatics<D>::MaxHueProperty() const
{
    Windows::UI::Xaml::DependencyProperty value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Primitives::IColorSpectrumStatics)->get_MaxHueProperty(put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Xaml::DependencyProperty consume_Windows_UI_Xaml_Controls_Primitives_IColorSpectrumStatics<D>::MinSaturationProperty() const
{
    Windows::UI::Xaml::DependencyProperty value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Primitives::IColorSpectrumStatics)->get_MinSaturationProperty(put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Xaml::DependencyProperty consume_Windows_UI_Xaml_Controls_Primitives_IColorSpectrumStatics<D>::MaxSaturationProperty() const
{
    Windows::UI::Xaml::DependencyProperty value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Primitives::IColorSpectrumStatics)->get_MaxSaturationProperty(put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Xaml::DependencyProperty consume_Windows_UI_Xaml_Controls_Primitives_IColorSpectrumStatics<D>::MinValueProperty() const
{
    Windows::UI::Xaml::DependencyProperty value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Primitives::IColorSpectrumStatics)->get_MinValueProperty(put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Xaml::DependencyProperty consume_Windows_UI_Xaml_Controls_Primitives_IColorSpectrumStatics<D>::MaxValueProperty() const
{
    Windows::UI::Xaml::DependencyProperty value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Primitives::IColorSpectrumStatics)->get_MaxValueProperty(put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Xaml::DependencyProperty consume_Windows_UI_Xaml_Controls_Primitives_IColorSpectrumStatics<D>::ShapeProperty() const
{
    Windows::UI::Xaml::DependencyProperty value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Primitives::IColorSpectrumStatics)->get_ShapeProperty(put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Xaml::DependencyProperty consume_Windows_UI_Xaml_Controls_Primitives_IColorSpectrumStatics<D>::ComponentsProperty() const
{
    Windows::UI::Xaml::DependencyProperty value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Primitives::IColorSpectrumStatics)->get_ComponentsProperty(put_abi(value)));
    return value;
}

template <typename D> double consume_Windows_UI_Xaml_Controls_Primitives_IComboBoxTemplateSettings<D>::DropDownOpenedHeight() const
{
    double value{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Primitives::IComboBoxTemplateSettings)->get_DropDownOpenedHeight(&value));
    return value;
}

template <typename D> double consume_Windows_UI_Xaml_Controls_Primitives_IComboBoxTemplateSettings<D>::DropDownClosedHeight() const
{
    double value{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Primitives::IComboBoxTemplateSettings)->get_DropDownClosedHeight(&value));
    return value;
}

template <typename D> double consume_Windows_UI_Xaml_Controls_Primitives_IComboBoxTemplateSettings<D>::DropDownOffset() const
{
    double value{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Primitives::IComboBoxTemplateSettings)->get_DropDownOffset(&value));
    return value;
}

template <typename D> Windows::UI::Xaml::Controls::Primitives::AnimationDirection consume_Windows_UI_Xaml_Controls_Primitives_IComboBoxTemplateSettings<D>::SelectedItemDirection() const
{
    Windows::UI::Xaml::Controls::Primitives::AnimationDirection value{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Primitives::IComboBoxTemplateSettings)->get_SelectedItemDirection(put_abi(value)));
    return value;
}

template <typename D> double consume_Windows_UI_Xaml_Controls_Primitives_IComboBoxTemplateSettings2<D>::DropDownContentMinWidth() const
{
    double value{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Primitives::IComboBoxTemplateSettings2)->get_DropDownContentMinWidth(&value));
    return value;
}

template <typename D> Windows::UI::Xaml::Controls::Primitives::CommandBarFlyoutCommandBarTemplateSettings consume_Windows_UI_Xaml_Controls_Primitives_ICommandBarFlyoutCommandBar<D>::FlyoutTemplateSettings() const
{
    Windows::UI::Xaml::Controls::Primitives::CommandBarFlyoutCommandBarTemplateSettings value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Primitives::ICommandBarFlyoutCommandBar)->get_FlyoutTemplateSettings(put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Xaml::Controls::Primitives::CommandBarFlyoutCommandBar consume_Windows_UI_Xaml_Controls_Primitives_ICommandBarFlyoutCommandBarFactory<D>::CreateInstance(Windows::Foundation::IInspectable const& baseInterface, Windows::Foundation::IInspectable& innerInterface) const
{
    Windows::UI::Xaml::Controls::Primitives::CommandBarFlyoutCommandBar value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Primitives::ICommandBarFlyoutCommandBarFactory)->CreateInstance(get_abi(baseInterface), put_abi(innerInterface), put_abi(value)));
    return value;
}

template <typename D> double consume_Windows_UI_Xaml_Controls_Primitives_ICommandBarFlyoutCommandBarTemplateSettings<D>::OpenAnimationStartPosition() const
{
    double value{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Primitives::ICommandBarFlyoutCommandBarTemplateSettings)->get_OpenAnimationStartPosition(&value));
    return value;
}

template <typename D> double consume_Windows_UI_Xaml_Controls_Primitives_ICommandBarFlyoutCommandBarTemplateSettings<D>::OpenAnimationEndPosition() const
{
    double value{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Primitives::ICommandBarFlyoutCommandBarTemplateSettings)->get_OpenAnimationEndPosition(&value));
    return value;
}

template <typename D> double consume_Windows_UI_Xaml_Controls_Primitives_ICommandBarFlyoutCommandBarTemplateSettings<D>::CloseAnimationEndPosition() const
{
    double value{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Primitives::ICommandBarFlyoutCommandBarTemplateSettings)->get_CloseAnimationEndPosition(&value));
    return value;
}

template <typename D> double consume_Windows_UI_Xaml_Controls_Primitives_ICommandBarFlyoutCommandBarTemplateSettings<D>::CurrentWidth() const
{
    double value{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Primitives::ICommandBarFlyoutCommandBarTemplateSettings)->get_CurrentWidth(&value));
    return value;
}

template <typename D> double consume_Windows_UI_Xaml_Controls_Primitives_ICommandBarFlyoutCommandBarTemplateSettings<D>::ExpandedWidth() const
{
    double value{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Primitives::ICommandBarFlyoutCommandBarTemplateSettings)->get_ExpandedWidth(&value));
    return value;
}

template <typename D> double consume_Windows_UI_Xaml_Controls_Primitives_ICommandBarFlyoutCommandBarTemplateSettings<D>::WidthExpansionDelta() const
{
    double value{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Primitives::ICommandBarFlyoutCommandBarTemplateSettings)->get_WidthExpansionDelta(&value));
    return value;
}

template <typename D> double consume_Windows_UI_Xaml_Controls_Primitives_ICommandBarFlyoutCommandBarTemplateSettings<D>::WidthExpansionAnimationStartPosition() const
{
    double value{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Primitives::ICommandBarFlyoutCommandBarTemplateSettings)->get_WidthExpansionAnimationStartPosition(&value));
    return value;
}

template <typename D> double consume_Windows_UI_Xaml_Controls_Primitives_ICommandBarFlyoutCommandBarTemplateSettings<D>::WidthExpansionAnimationEndPosition() const
{
    double value{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Primitives::ICommandBarFlyoutCommandBarTemplateSettings)->get_WidthExpansionAnimationEndPosition(&value));
    return value;
}

template <typename D> double consume_Windows_UI_Xaml_Controls_Primitives_ICommandBarFlyoutCommandBarTemplateSettings<D>::WidthExpansionMoreButtonAnimationStartPosition() const
{
    double value{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Primitives::ICommandBarFlyoutCommandBarTemplateSettings)->get_WidthExpansionMoreButtonAnimationStartPosition(&value));
    return value;
}

template <typename D> double consume_Windows_UI_Xaml_Controls_Primitives_ICommandBarFlyoutCommandBarTemplateSettings<D>::WidthExpansionMoreButtonAnimationEndPosition() const
{
    double value{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Primitives::ICommandBarFlyoutCommandBarTemplateSettings)->get_WidthExpansionMoreButtonAnimationEndPosition(&value));
    return value;
}

template <typename D> double consume_Windows_UI_Xaml_Controls_Primitives_ICommandBarFlyoutCommandBarTemplateSettings<D>::ExpandUpOverflowVerticalPosition() const
{
    double value{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Primitives::ICommandBarFlyoutCommandBarTemplateSettings)->get_ExpandUpOverflowVerticalPosition(&value));
    return value;
}

template <typename D> double consume_Windows_UI_Xaml_Controls_Primitives_ICommandBarFlyoutCommandBarTemplateSettings<D>::ExpandDownOverflowVerticalPosition() const
{
    double value{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Primitives::ICommandBarFlyoutCommandBarTemplateSettings)->get_ExpandDownOverflowVerticalPosition(&value));
    return value;
}

template <typename D> double consume_Windows_UI_Xaml_Controls_Primitives_ICommandBarFlyoutCommandBarTemplateSettings<D>::ExpandUpAnimationStartPosition() const
{
    double value{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Primitives::ICommandBarFlyoutCommandBarTemplateSettings)->get_ExpandUpAnimationStartPosition(&value));
    return value;
}

template <typename D> double consume_Windows_UI_Xaml_Controls_Primitives_ICommandBarFlyoutCommandBarTemplateSettings<D>::ExpandUpAnimationEndPosition() const
{
    double value{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Primitives::ICommandBarFlyoutCommandBarTemplateSettings)->get_ExpandUpAnimationEndPosition(&value));
    return value;
}

template <typename D> double consume_Windows_UI_Xaml_Controls_Primitives_ICommandBarFlyoutCommandBarTemplateSettings<D>::ExpandUpAnimationHoldPosition() const
{
    double value{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Primitives::ICommandBarFlyoutCommandBarTemplateSettings)->get_ExpandUpAnimationHoldPosition(&value));
    return value;
}

template <typename D> double consume_Windows_UI_Xaml_Controls_Primitives_ICommandBarFlyoutCommandBarTemplateSettings<D>::ExpandDownAnimationStartPosition() const
{
    double value{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Primitives::ICommandBarFlyoutCommandBarTemplateSettings)->get_ExpandDownAnimationStartPosition(&value));
    return value;
}

template <typename D> double consume_Windows_UI_Xaml_Controls_Primitives_ICommandBarFlyoutCommandBarTemplateSettings<D>::ExpandDownAnimationEndPosition() const
{
    double value{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Primitives::ICommandBarFlyoutCommandBarTemplateSettings)->get_ExpandDownAnimationEndPosition(&value));
    return value;
}

template <typename D> double consume_Windows_UI_Xaml_Controls_Primitives_ICommandBarFlyoutCommandBarTemplateSettings<D>::ExpandDownAnimationHoldPosition() const
{
    double value{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Primitives::ICommandBarFlyoutCommandBarTemplateSettings)->get_ExpandDownAnimationHoldPosition(&value));
    return value;
}

template <typename D> Windows::Foundation::Rect consume_Windows_UI_Xaml_Controls_Primitives_ICommandBarFlyoutCommandBarTemplateSettings<D>::ContentClipRect() const
{
    Windows::Foundation::Rect value{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Primitives::ICommandBarFlyoutCommandBarTemplateSettings)->get_ContentClipRect(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::Rect consume_Windows_UI_Xaml_Controls_Primitives_ICommandBarFlyoutCommandBarTemplateSettings<D>::OverflowContentClipRect() const
{
    Windows::Foundation::Rect value{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Primitives::ICommandBarFlyoutCommandBarTemplateSettings)->get_OverflowContentClipRect(put_abi(value)));
    return value;
}

template <typename D> double consume_Windows_UI_Xaml_Controls_Primitives_ICommandBarTemplateSettings<D>::ContentHeight() const
{
    double value{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Primitives::ICommandBarTemplateSettings)->get_ContentHeight(&value));
    return value;
}

template <typename D> Windows::Foundation::Rect consume_Windows_UI_Xaml_Controls_Primitives_ICommandBarTemplateSettings<D>::OverflowContentClipRect() const
{
    Windows::Foundation::Rect value{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Primitives::ICommandBarTemplateSettings)->get_OverflowContentClipRect(put_abi(value)));
    return value;
}

template <typename D> double consume_Windows_UI_Xaml_Controls_Primitives_ICommandBarTemplateSettings<D>::OverflowContentMinWidth() const
{
    double value{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Primitives::ICommandBarTemplateSettings)->get_OverflowContentMinWidth(&value));
    return value;
}

template <typename D> double consume_Windows_UI_Xaml_Controls_Primitives_ICommandBarTemplateSettings<D>::OverflowContentMaxHeight() const
{
    double value{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Primitives::ICommandBarTemplateSettings)->get_OverflowContentMaxHeight(&value));
    return value;
}

template <typename D> double consume_Windows_UI_Xaml_Controls_Primitives_ICommandBarTemplateSettings<D>::OverflowContentHorizontalOffset() const
{
    double value{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Primitives::ICommandBarTemplateSettings)->get_OverflowContentHorizontalOffset(&value));
    return value;
}

template <typename D> double consume_Windows_UI_Xaml_Controls_Primitives_ICommandBarTemplateSettings<D>::OverflowContentHeight() const
{
    double value{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Primitives::ICommandBarTemplateSettings)->get_OverflowContentHeight(&value));
    return value;
}

template <typename D> double consume_Windows_UI_Xaml_Controls_Primitives_ICommandBarTemplateSettings<D>::NegativeOverflowContentHeight() const
{
    double value{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Primitives::ICommandBarTemplateSettings)->get_NegativeOverflowContentHeight(&value));
    return value;
}

template <typename D> double consume_Windows_UI_Xaml_Controls_Primitives_ICommandBarTemplateSettings2<D>::OverflowContentMaxWidth() const
{
    double value{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Primitives::ICommandBarTemplateSettings2)->get_OverflowContentMaxWidth(&value));
    return value;
}

template <typename D> Windows::UI::Xaml::Visibility consume_Windows_UI_Xaml_Controls_Primitives_ICommandBarTemplateSettings3<D>::EffectiveOverflowButtonVisibility() const
{
    Windows::UI::Xaml::Visibility value{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Primitives::ICommandBarTemplateSettings3)->get_EffectiveOverflowButtonVisibility(put_abi(value)));
    return value;
}

template <typename D> double consume_Windows_UI_Xaml_Controls_Primitives_ICommandBarTemplateSettings4<D>::OverflowContentCompactYTranslation() const
{
    double value{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Primitives::ICommandBarTemplateSettings4)->get_OverflowContentCompactYTranslation(&value));
    return value;
}

template <typename D> double consume_Windows_UI_Xaml_Controls_Primitives_ICommandBarTemplateSettings4<D>::OverflowContentMinimalYTranslation() const
{
    double value{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Primitives::ICommandBarTemplateSettings4)->get_OverflowContentMinimalYTranslation(&value));
    return value;
}

template <typename D> double consume_Windows_UI_Xaml_Controls_Primitives_ICommandBarTemplateSettings4<D>::OverflowContentHiddenYTranslation() const
{
    double value{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Primitives::ICommandBarTemplateSettings4)->get_OverflowContentHiddenYTranslation(&value));
    return value;
}

template <typename D> double consume_Windows_UI_Xaml_Controls_Primitives_IDragCompletedEventArgs<D>::HorizontalChange() const
{
    double value{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Primitives::IDragCompletedEventArgs)->get_HorizontalChange(&value));
    return value;
}

template <typename D> double consume_Windows_UI_Xaml_Controls_Primitives_IDragCompletedEventArgs<D>::VerticalChange() const
{
    double value{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Primitives::IDragCompletedEventArgs)->get_VerticalChange(&value));
    return value;
}

template <typename D> bool consume_Windows_UI_Xaml_Controls_Primitives_IDragCompletedEventArgs<D>::Canceled() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Primitives::IDragCompletedEventArgs)->get_Canceled(&value));
    return value;
}

template <typename D> Windows::UI::Xaml::Controls::Primitives::DragCompletedEventArgs consume_Windows_UI_Xaml_Controls_Primitives_IDragCompletedEventArgsFactory<D>::CreateInstanceWithHorizontalChangeVerticalChangeAndCanceled(double horizontalChange, double verticalChange, bool canceled, Windows::Foundation::IInspectable const& baseInterface, Windows::Foundation::IInspectable& innerInterface) const
{
    Windows::UI::Xaml::Controls::Primitives::DragCompletedEventArgs value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Primitives::IDragCompletedEventArgsFactory)->CreateInstanceWithHorizontalChangeVerticalChangeAndCanceled(horizontalChange, verticalChange, canceled, get_abi(baseInterface), put_abi(innerInterface), put_abi(value)));
    return value;
}

template <typename D> double consume_Windows_UI_Xaml_Controls_Primitives_IDragDeltaEventArgs<D>::HorizontalChange() const
{
    double value{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Primitives::IDragDeltaEventArgs)->get_HorizontalChange(&value));
    return value;
}

template <typename D> double consume_Windows_UI_Xaml_Controls_Primitives_IDragDeltaEventArgs<D>::VerticalChange() const
{
    double value{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Primitives::IDragDeltaEventArgs)->get_VerticalChange(&value));
    return value;
}

template <typename D> Windows::UI::Xaml::Controls::Primitives::DragDeltaEventArgs consume_Windows_UI_Xaml_Controls_Primitives_IDragDeltaEventArgsFactory<D>::CreateInstanceWithHorizontalChangeAndVerticalChange(double horizontalChange, double verticalChange, Windows::Foundation::IInspectable const& baseInterface, Windows::Foundation::IInspectable& innerInterface) const
{
    Windows::UI::Xaml::Controls::Primitives::DragDeltaEventArgs value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Primitives::IDragDeltaEventArgsFactory)->CreateInstanceWithHorizontalChangeAndVerticalChange(horizontalChange, verticalChange, get_abi(baseInterface), put_abi(innerInterface), put_abi(value)));
    return value;
}

template <typename D> double consume_Windows_UI_Xaml_Controls_Primitives_IDragStartedEventArgs<D>::HorizontalOffset() const
{
    double value{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Primitives::IDragStartedEventArgs)->get_HorizontalOffset(&value));
    return value;
}

template <typename D> double consume_Windows_UI_Xaml_Controls_Primitives_IDragStartedEventArgs<D>::VerticalOffset() const
{
    double value{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Primitives::IDragStartedEventArgs)->get_VerticalOffset(&value));
    return value;
}

template <typename D> Windows::UI::Xaml::Controls::Primitives::DragStartedEventArgs consume_Windows_UI_Xaml_Controls_Primitives_IDragStartedEventArgsFactory<D>::CreateInstanceWithHorizontalOffsetAndVerticalOffset(double horizontalOffset, double verticalOffset, Windows::Foundation::IInspectable const& baseInterface, Windows::Foundation::IInspectable& innerInterface) const
{
    Windows::UI::Xaml::Controls::Primitives::DragStartedEventArgs value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Primitives::IDragStartedEventArgsFactory)->CreateInstanceWithHorizontalOffsetAndVerticalOffset(horizontalOffset, verticalOffset, get_abi(baseInterface), put_abi(innerInterface), put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Xaml::Controls::Primitives::FlyoutPlacementMode consume_Windows_UI_Xaml_Controls_Primitives_IFlyoutBase<D>::Placement() const
{
    Windows::UI::Xaml::Controls::Primitives::FlyoutPlacementMode value{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Primitives::IFlyoutBase)->get_Placement(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_UI_Xaml_Controls_Primitives_IFlyoutBase<D>::Placement(Windows::UI::Xaml::Controls::Primitives::FlyoutPlacementMode const& value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Primitives::IFlyoutBase)->put_Placement(get_abi(value)));
}

template <typename D> winrt::event_token consume_Windows_UI_Xaml_Controls_Primitives_IFlyoutBase<D>::Opened(Windows::Foundation::EventHandler<Windows::Foundation::IInspectable> const& handler) const
{
    winrt::event_token token{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Primitives::IFlyoutBase)->add_Opened(get_abi(handler), put_abi(token)));
    return token;
}

template <typename D> typename consume_Windows_UI_Xaml_Controls_Primitives_IFlyoutBase<D>::Opened_revoker consume_Windows_UI_Xaml_Controls_Primitives_IFlyoutBase<D>::Opened(auto_revoke_t, Windows::Foundation::EventHandler<Windows::Foundation::IInspectable> const& handler) const
{
    return impl::make_event_revoker<D, Opened_revoker>(this, Opened(handler));
}

template <typename D> void consume_Windows_UI_Xaml_Controls_Primitives_IFlyoutBase<D>::Opened(winrt::event_token const& token) const noexcept
{
    WINRT_VERIFY_(0, WINRT_SHIM(Windows::UI::Xaml::Controls::Primitives::IFlyoutBase)->remove_Opened(get_abi(token)));
}

template <typename D> winrt::event_token consume_Windows_UI_Xaml_Controls_Primitives_IFlyoutBase<D>::Closed(Windows::Foundation::EventHandler<Windows::Foundation::IInspectable> const& handler) const
{
    winrt::event_token token{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Primitives::IFlyoutBase)->add_Closed(get_abi(handler), put_abi(token)));
    return token;
}

template <typename D> typename consume_Windows_UI_Xaml_Controls_Primitives_IFlyoutBase<D>::Closed_revoker consume_Windows_UI_Xaml_Controls_Primitives_IFlyoutBase<D>::Closed(auto_revoke_t, Windows::Foundation::EventHandler<Windows::Foundation::IInspectable> const& handler) const
{
    return impl::make_event_revoker<D, Closed_revoker>(this, Closed(handler));
}

template <typename D> void consume_Windows_UI_Xaml_Controls_Primitives_IFlyoutBase<D>::Closed(winrt::event_token const& token) const noexcept
{
    WINRT_VERIFY_(0, WINRT_SHIM(Windows::UI::Xaml::Controls::Primitives::IFlyoutBase)->remove_Closed(get_abi(token)));
}

template <typename D> winrt::event_token consume_Windows_UI_Xaml_Controls_Primitives_IFlyoutBase<D>::Opening(Windows::Foundation::EventHandler<Windows::Foundation::IInspectable> const& handler) const
{
    winrt::event_token token{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Primitives::IFlyoutBase)->add_Opening(get_abi(handler), put_abi(token)));
    return token;
}

template <typename D> typename consume_Windows_UI_Xaml_Controls_Primitives_IFlyoutBase<D>::Opening_revoker consume_Windows_UI_Xaml_Controls_Primitives_IFlyoutBase<D>::Opening(auto_revoke_t, Windows::Foundation::EventHandler<Windows::Foundation::IInspectable> const& handler) const
{
    return impl::make_event_revoker<D, Opening_revoker>(this, Opening(handler));
}

template <typename D> void consume_Windows_UI_Xaml_Controls_Primitives_IFlyoutBase<D>::Opening(winrt::event_token const& token) const noexcept
{
    WINRT_VERIFY_(0, WINRT_SHIM(Windows::UI::Xaml::Controls::Primitives::IFlyoutBase)->remove_Opening(get_abi(token)));
}

template <typename D> void consume_Windows_UI_Xaml_Controls_Primitives_IFlyoutBase<D>::ShowAt(Windows::UI::Xaml::FrameworkElement const& placementTarget) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Primitives::IFlyoutBase)->ShowAt(get_abi(placementTarget)));
}

template <typename D> void consume_Windows_UI_Xaml_Controls_Primitives_IFlyoutBase<D>::Hide() const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Primitives::IFlyoutBase)->Hide());
}

template <typename D> Windows::UI::Xaml::FrameworkElement consume_Windows_UI_Xaml_Controls_Primitives_IFlyoutBase2<D>::Target() const
{
    Windows::UI::Xaml::FrameworkElement value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Primitives::IFlyoutBase2)->get_Target(put_abi(value)));
    return value;
}

template <typename D> bool consume_Windows_UI_Xaml_Controls_Primitives_IFlyoutBase2<D>::AllowFocusOnInteraction() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Primitives::IFlyoutBase2)->get_AllowFocusOnInteraction(&value));
    return value;
}

template <typename D> void consume_Windows_UI_Xaml_Controls_Primitives_IFlyoutBase2<D>::AllowFocusOnInteraction(bool value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Primitives::IFlyoutBase2)->put_AllowFocusOnInteraction(value));
}

template <typename D> Windows::UI::Xaml::Controls::LightDismissOverlayMode consume_Windows_UI_Xaml_Controls_Primitives_IFlyoutBase2<D>::LightDismissOverlayMode() const
{
    Windows::UI::Xaml::Controls::LightDismissOverlayMode value{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Primitives::IFlyoutBase2)->get_LightDismissOverlayMode(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_UI_Xaml_Controls_Primitives_IFlyoutBase2<D>::LightDismissOverlayMode(Windows::UI::Xaml::Controls::LightDismissOverlayMode const& value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Primitives::IFlyoutBase2)->put_LightDismissOverlayMode(get_abi(value)));
}

template <typename D> bool consume_Windows_UI_Xaml_Controls_Primitives_IFlyoutBase2<D>::AllowFocusWhenDisabled() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Primitives::IFlyoutBase2)->get_AllowFocusWhenDisabled(&value));
    return value;
}

template <typename D> void consume_Windows_UI_Xaml_Controls_Primitives_IFlyoutBase2<D>::AllowFocusWhenDisabled(bool value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Primitives::IFlyoutBase2)->put_AllowFocusWhenDisabled(value));
}

template <typename D> Windows::UI::Xaml::ElementSoundMode consume_Windows_UI_Xaml_Controls_Primitives_IFlyoutBase2<D>::ElementSoundMode() const
{
    Windows::UI::Xaml::ElementSoundMode value{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Primitives::IFlyoutBase2)->get_ElementSoundMode(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_UI_Xaml_Controls_Primitives_IFlyoutBase2<D>::ElementSoundMode(Windows::UI::Xaml::ElementSoundMode const& value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Primitives::IFlyoutBase2)->put_ElementSoundMode(get_abi(value)));
}

template <typename D> winrt::event_token consume_Windows_UI_Xaml_Controls_Primitives_IFlyoutBase2<D>::Closing(Windows::Foundation::TypedEventHandler<Windows::UI::Xaml::Controls::Primitives::FlyoutBase, Windows::UI::Xaml::Controls::Primitives::FlyoutBaseClosingEventArgs> const& handler) const
{
    winrt::event_token token{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Primitives::IFlyoutBase2)->add_Closing(get_abi(handler), put_abi(token)));
    return token;
}

template <typename D> typename consume_Windows_UI_Xaml_Controls_Primitives_IFlyoutBase2<D>::Closing_revoker consume_Windows_UI_Xaml_Controls_Primitives_IFlyoutBase2<D>::Closing(auto_revoke_t, Windows::Foundation::TypedEventHandler<Windows::UI::Xaml::Controls::Primitives::FlyoutBase, Windows::UI::Xaml::Controls::Primitives::FlyoutBaseClosingEventArgs> const& handler) const
{
    return impl::make_event_revoker<D, Closing_revoker>(this, Closing(handler));
}

template <typename D> void consume_Windows_UI_Xaml_Controls_Primitives_IFlyoutBase2<D>::Closing(winrt::event_token const& token) const noexcept
{
    WINRT_VERIFY_(0, WINRT_SHIM(Windows::UI::Xaml::Controls::Primitives::IFlyoutBase2)->remove_Closing(get_abi(token)));
}

template <typename D> Windows::UI::Xaml::DependencyObject consume_Windows_UI_Xaml_Controls_Primitives_IFlyoutBase3<D>::OverlayInputPassThroughElement() const
{
    Windows::UI::Xaml::DependencyObject value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Primitives::IFlyoutBase3)->get_OverlayInputPassThroughElement(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_UI_Xaml_Controls_Primitives_IFlyoutBase3<D>::OverlayInputPassThroughElement(Windows::UI::Xaml::DependencyObject const& value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Primitives::IFlyoutBase3)->put_OverlayInputPassThroughElement(get_abi(value)));
}

template <typename D> void consume_Windows_UI_Xaml_Controls_Primitives_IFlyoutBase4<D>::TryInvokeKeyboardAccelerator(Windows::UI::Xaml::Input::ProcessKeyboardAcceleratorEventArgs const& args) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Primitives::IFlyoutBase4)->TryInvokeKeyboardAccelerator(get_abi(args)));
}

template <typename D> Windows::UI::Xaml::Controls::Primitives::FlyoutShowMode consume_Windows_UI_Xaml_Controls_Primitives_IFlyoutBase5<D>::ShowMode() const
{
    Windows::UI::Xaml::Controls::Primitives::FlyoutShowMode value{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Primitives::IFlyoutBase5)->get_ShowMode(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_UI_Xaml_Controls_Primitives_IFlyoutBase5<D>::ShowMode(Windows::UI::Xaml::Controls::Primitives::FlyoutShowMode const& value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Primitives::IFlyoutBase5)->put_ShowMode(get_abi(value)));
}

template <typename D> bool consume_Windows_UI_Xaml_Controls_Primitives_IFlyoutBase5<D>::InputDevicePrefersPrimaryCommands() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Primitives::IFlyoutBase5)->get_InputDevicePrefersPrimaryCommands(&value));
    return value;
}

template <typename D> bool consume_Windows_UI_Xaml_Controls_Primitives_IFlyoutBase5<D>::AreOpenCloseAnimationsEnabled() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Primitives::IFlyoutBase5)->get_AreOpenCloseAnimationsEnabled(&value));
    return value;
}

template <typename D> void consume_Windows_UI_Xaml_Controls_Primitives_IFlyoutBase5<D>::AreOpenCloseAnimationsEnabled(bool value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Primitives::IFlyoutBase5)->put_AreOpenCloseAnimationsEnabled(value));
}

template <typename D> bool consume_Windows_UI_Xaml_Controls_Primitives_IFlyoutBase5<D>::IsOpen() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Primitives::IFlyoutBase5)->get_IsOpen(&value));
    return value;
}

template <typename D> void consume_Windows_UI_Xaml_Controls_Primitives_IFlyoutBase5<D>::ShowAt(Windows::UI::Xaml::DependencyObject const& placementTarget, Windows::UI::Xaml::Controls::Primitives::FlyoutShowOptions const& showOptions) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Primitives::IFlyoutBase5)->ShowAt(get_abi(placementTarget), get_abi(showOptions)));
}

template <typename D> bool consume_Windows_UI_Xaml_Controls_Primitives_IFlyoutBase6<D>::ShouldConstrainToRootBounds() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Primitives::IFlyoutBase6)->get_ShouldConstrainToRootBounds(&value));
    return value;
}

template <typename D> void consume_Windows_UI_Xaml_Controls_Primitives_IFlyoutBase6<D>::ShouldConstrainToRootBounds(bool value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Primitives::IFlyoutBase6)->put_ShouldConstrainToRootBounds(value));
}

template <typename D> bool consume_Windows_UI_Xaml_Controls_Primitives_IFlyoutBase6<D>::IsConstrainedToRootBounds() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Primitives::IFlyoutBase6)->get_IsConstrainedToRootBounds(&value));
    return value;
}

template <typename D> Windows::UI::Xaml::XamlRoot consume_Windows_UI_Xaml_Controls_Primitives_IFlyoutBase6<D>::XamlRoot() const
{
    Windows::UI::Xaml::XamlRoot value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Primitives::IFlyoutBase6)->get_XamlRoot(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_UI_Xaml_Controls_Primitives_IFlyoutBase6<D>::XamlRoot(Windows::UI::Xaml::XamlRoot const& value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Primitives::IFlyoutBase6)->put_XamlRoot(get_abi(value)));
}

template <typename D> bool consume_Windows_UI_Xaml_Controls_Primitives_IFlyoutBaseClosingEventArgs<D>::Cancel() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Primitives::IFlyoutBaseClosingEventArgs)->get_Cancel(&value));
    return value;
}

template <typename D> void consume_Windows_UI_Xaml_Controls_Primitives_IFlyoutBaseClosingEventArgs<D>::Cancel(bool value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Primitives::IFlyoutBaseClosingEventArgs)->put_Cancel(value));
}

template <typename D> Windows::UI::Xaml::Controls::Primitives::FlyoutBase consume_Windows_UI_Xaml_Controls_Primitives_IFlyoutBaseFactory<D>::CreateInstance(Windows::Foundation::IInspectable const& baseInterface, Windows::Foundation::IInspectable& innerInterface) const
{
    Windows::UI::Xaml::Controls::Primitives::FlyoutBase value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Primitives::IFlyoutBaseFactory)->CreateInstance(get_abi(baseInterface), put_abi(innerInterface), put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Xaml::Controls::Control consume_Windows_UI_Xaml_Controls_Primitives_IFlyoutBaseOverrides<D>::CreatePresenter() const
{
    Windows::UI::Xaml::Controls::Control result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Primitives::IFlyoutBaseOverrides)->CreatePresenter(put_abi(result)));
    return result;
}

template <typename D> void consume_Windows_UI_Xaml_Controls_Primitives_IFlyoutBaseOverrides4<D>::OnProcessKeyboardAccelerators(Windows::UI::Xaml::Input::ProcessKeyboardAcceleratorEventArgs const& args) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Primitives::IFlyoutBaseOverrides4)->OnProcessKeyboardAccelerators(get_abi(args)));
}

template <typename D> Windows::UI::Xaml::DependencyProperty consume_Windows_UI_Xaml_Controls_Primitives_IFlyoutBaseStatics<D>::PlacementProperty() const
{
    Windows::UI::Xaml::DependencyProperty value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Primitives::IFlyoutBaseStatics)->get_PlacementProperty(put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Xaml::DependencyProperty consume_Windows_UI_Xaml_Controls_Primitives_IFlyoutBaseStatics<D>::AttachedFlyoutProperty() const
{
    Windows::UI::Xaml::DependencyProperty value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Primitives::IFlyoutBaseStatics)->get_AttachedFlyoutProperty(put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Xaml::Controls::Primitives::FlyoutBase consume_Windows_UI_Xaml_Controls_Primitives_IFlyoutBaseStatics<D>::GetAttachedFlyout(Windows::UI::Xaml::FrameworkElement const& element) const
{
    Windows::UI::Xaml::Controls::Primitives::FlyoutBase result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Primitives::IFlyoutBaseStatics)->GetAttachedFlyout(get_abi(element), put_abi(result)));
    return result;
}

template <typename D> void consume_Windows_UI_Xaml_Controls_Primitives_IFlyoutBaseStatics<D>::SetAttachedFlyout(Windows::UI::Xaml::FrameworkElement const& element, Windows::UI::Xaml::Controls::Primitives::FlyoutBase const& value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Primitives::IFlyoutBaseStatics)->SetAttachedFlyout(get_abi(element), get_abi(value)));
}

template <typename D> void consume_Windows_UI_Xaml_Controls_Primitives_IFlyoutBaseStatics<D>::ShowAttachedFlyout(Windows::UI::Xaml::FrameworkElement const& flyoutOwner) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Primitives::IFlyoutBaseStatics)->ShowAttachedFlyout(get_abi(flyoutOwner)));
}

template <typename D> Windows::UI::Xaml::DependencyProperty consume_Windows_UI_Xaml_Controls_Primitives_IFlyoutBaseStatics2<D>::AllowFocusOnInteractionProperty() const
{
    Windows::UI::Xaml::DependencyProperty value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Primitives::IFlyoutBaseStatics2)->get_AllowFocusOnInteractionProperty(put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Xaml::DependencyProperty consume_Windows_UI_Xaml_Controls_Primitives_IFlyoutBaseStatics2<D>::LightDismissOverlayModeProperty() const
{
    Windows::UI::Xaml::DependencyProperty value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Primitives::IFlyoutBaseStatics2)->get_LightDismissOverlayModeProperty(put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Xaml::DependencyProperty consume_Windows_UI_Xaml_Controls_Primitives_IFlyoutBaseStatics2<D>::AllowFocusWhenDisabledProperty() const
{
    Windows::UI::Xaml::DependencyProperty value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Primitives::IFlyoutBaseStatics2)->get_AllowFocusWhenDisabledProperty(put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Xaml::DependencyProperty consume_Windows_UI_Xaml_Controls_Primitives_IFlyoutBaseStatics2<D>::ElementSoundModeProperty() const
{
    Windows::UI::Xaml::DependencyProperty value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Primitives::IFlyoutBaseStatics2)->get_ElementSoundModeProperty(put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Xaml::DependencyProperty consume_Windows_UI_Xaml_Controls_Primitives_IFlyoutBaseStatics3<D>::OverlayInputPassThroughElementProperty() const
{
    Windows::UI::Xaml::DependencyProperty value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Primitives::IFlyoutBaseStatics3)->get_OverlayInputPassThroughElementProperty(put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Xaml::DependencyProperty consume_Windows_UI_Xaml_Controls_Primitives_IFlyoutBaseStatics5<D>::TargetProperty() const
{
    Windows::UI::Xaml::DependencyProperty value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Primitives::IFlyoutBaseStatics5)->get_TargetProperty(put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Xaml::DependencyProperty consume_Windows_UI_Xaml_Controls_Primitives_IFlyoutBaseStatics5<D>::ShowModeProperty() const
{
    Windows::UI::Xaml::DependencyProperty value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Primitives::IFlyoutBaseStatics5)->get_ShowModeProperty(put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Xaml::DependencyProperty consume_Windows_UI_Xaml_Controls_Primitives_IFlyoutBaseStatics5<D>::InputDevicePrefersPrimaryCommandsProperty() const
{
    Windows::UI::Xaml::DependencyProperty value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Primitives::IFlyoutBaseStatics5)->get_InputDevicePrefersPrimaryCommandsProperty(put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Xaml::DependencyProperty consume_Windows_UI_Xaml_Controls_Primitives_IFlyoutBaseStatics5<D>::AreOpenCloseAnimationsEnabledProperty() const
{
    Windows::UI::Xaml::DependencyProperty value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Primitives::IFlyoutBaseStatics5)->get_AreOpenCloseAnimationsEnabledProperty(put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Xaml::DependencyProperty consume_Windows_UI_Xaml_Controls_Primitives_IFlyoutBaseStatics5<D>::IsOpenProperty() const
{
    Windows::UI::Xaml::DependencyProperty value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Primitives::IFlyoutBaseStatics5)->get_IsOpenProperty(put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Xaml::DependencyProperty consume_Windows_UI_Xaml_Controls_Primitives_IFlyoutBaseStatics6<D>::ShouldConstrainToRootBoundsProperty() const
{
    Windows::UI::Xaml::DependencyProperty value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Primitives::IFlyoutBaseStatics6)->get_ShouldConstrainToRootBoundsProperty(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::IReference<Windows::Foundation::Point> consume_Windows_UI_Xaml_Controls_Primitives_IFlyoutShowOptions<D>::Position() const
{
    Windows::Foundation::IReference<Windows::Foundation::Point> value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Primitives::IFlyoutShowOptions)->get_Position(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_UI_Xaml_Controls_Primitives_IFlyoutShowOptions<D>::Position(optional<Windows::Foundation::Point> const& value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Primitives::IFlyoutShowOptions)->put_Position(get_abi(value)));
}

template <typename D> Windows::Foundation::IReference<Windows::Foundation::Rect> consume_Windows_UI_Xaml_Controls_Primitives_IFlyoutShowOptions<D>::ExclusionRect() const
{
    Windows::Foundation::IReference<Windows::Foundation::Rect> value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Primitives::IFlyoutShowOptions)->get_ExclusionRect(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_UI_Xaml_Controls_Primitives_IFlyoutShowOptions<D>::ExclusionRect(optional<Windows::Foundation::Rect> const& value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Primitives::IFlyoutShowOptions)->put_ExclusionRect(get_abi(value)));
}

template <typename D> Windows::UI::Xaml::Controls::Primitives::FlyoutShowMode consume_Windows_UI_Xaml_Controls_Primitives_IFlyoutShowOptions<D>::ShowMode() const
{
    Windows::UI::Xaml::Controls::Primitives::FlyoutShowMode value{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Primitives::IFlyoutShowOptions)->get_ShowMode(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_UI_Xaml_Controls_Primitives_IFlyoutShowOptions<D>::ShowMode(Windows::UI::Xaml::Controls::Primitives::FlyoutShowMode const& value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Primitives::IFlyoutShowOptions)->put_ShowMode(get_abi(value)));
}

template <typename D> Windows::UI::Xaml::Controls::Primitives::FlyoutPlacementMode consume_Windows_UI_Xaml_Controls_Primitives_IFlyoutShowOptions<D>::Placement() const
{
    Windows::UI::Xaml::Controls::Primitives::FlyoutPlacementMode value{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Primitives::IFlyoutShowOptions)->get_Placement(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_UI_Xaml_Controls_Primitives_IFlyoutShowOptions<D>::Placement(Windows::UI::Xaml::Controls::Primitives::FlyoutPlacementMode const& value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Primitives::IFlyoutShowOptions)->put_Placement(get_abi(value)));
}

template <typename D> Windows::UI::Xaml::Controls::Primitives::FlyoutShowOptions consume_Windows_UI_Xaml_Controls_Primitives_IFlyoutShowOptionsFactory<D>::CreateInstance(Windows::Foundation::IInspectable const& baseInterface, Windows::Foundation::IInspectable& innerInterface) const
{
    Windows::UI::Xaml::Controls::Primitives::FlyoutShowOptions value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Primitives::IFlyoutShowOptionsFactory)->CreateInstance(get_abi(baseInterface), put_abi(innerInterface), put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Xaml::Controls::Primitives::GeneratorPosition consume_Windows_UI_Xaml_Controls_Primitives_IGeneratorPositionHelperStatics<D>::FromIndexAndOffset(int32_t index, int32_t offset) const
{
    Windows::UI::Xaml::Controls::Primitives::GeneratorPosition result{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Primitives::IGeneratorPositionHelperStatics)->FromIndexAndOffset(index, offset, put_abi(result)));
    return result;
}

template <typename D> bool consume_Windows_UI_Xaml_Controls_Primitives_IGridViewItemPresenter<D>::SelectionCheckMarkVisualEnabled() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Primitives::IGridViewItemPresenter)->get_SelectionCheckMarkVisualEnabled(&value));
    return value;
}

template <typename D> void consume_Windows_UI_Xaml_Controls_Primitives_IGridViewItemPresenter<D>::SelectionCheckMarkVisualEnabled(bool value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Primitives::IGridViewItemPresenter)->put_SelectionCheckMarkVisualEnabled(value));
}

template <typename D> Windows::UI::Xaml::Media::Brush consume_Windows_UI_Xaml_Controls_Primitives_IGridViewItemPresenter<D>::CheckHintBrush() const
{
    Windows::UI::Xaml::Media::Brush value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Primitives::IGridViewItemPresenter)->get_CheckHintBrush(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_UI_Xaml_Controls_Primitives_IGridViewItemPresenter<D>::CheckHintBrush(Windows::UI::Xaml::Media::Brush const& value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Primitives::IGridViewItemPresenter)->put_CheckHintBrush(get_abi(value)));
}

template <typename D> Windows::UI::Xaml::Media::Brush consume_Windows_UI_Xaml_Controls_Primitives_IGridViewItemPresenter<D>::CheckSelectingBrush() const
{
    Windows::UI::Xaml::Media::Brush value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Primitives::IGridViewItemPresenter)->get_CheckSelectingBrush(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_UI_Xaml_Controls_Primitives_IGridViewItemPresenter<D>::CheckSelectingBrush(Windows::UI::Xaml::Media::Brush const& value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Primitives::IGridViewItemPresenter)->put_CheckSelectingBrush(get_abi(value)));
}

template <typename D> Windows::UI::Xaml::Media::Brush consume_Windows_UI_Xaml_Controls_Primitives_IGridViewItemPresenter<D>::CheckBrush() const
{
    Windows::UI::Xaml::Media::Brush value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Primitives::IGridViewItemPresenter)->get_CheckBrush(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_UI_Xaml_Controls_Primitives_IGridViewItemPresenter<D>::CheckBrush(Windows::UI::Xaml::Media::Brush const& value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Primitives::IGridViewItemPresenter)->put_CheckBrush(get_abi(value)));
}

template <typename D> Windows::UI::Xaml::Media::Brush consume_Windows_UI_Xaml_Controls_Primitives_IGridViewItemPresenter<D>::DragBackground() const
{
    Windows::UI::Xaml::Media::Brush value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Primitives::IGridViewItemPresenter)->get_DragBackground(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_UI_Xaml_Controls_Primitives_IGridViewItemPresenter<D>::DragBackground(Windows::UI::Xaml::Media::Brush const& value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Primitives::IGridViewItemPresenter)->put_DragBackground(get_abi(value)));
}

template <typename D> Windows::UI::Xaml::Media::Brush consume_Windows_UI_Xaml_Controls_Primitives_IGridViewItemPresenter<D>::DragForeground() const
{
    Windows::UI::Xaml::Media::Brush value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Primitives::IGridViewItemPresenter)->get_DragForeground(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_UI_Xaml_Controls_Primitives_IGridViewItemPresenter<D>::DragForeground(Windows::UI::Xaml::Media::Brush const& value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Primitives::IGridViewItemPresenter)->put_DragForeground(get_abi(value)));
}

template <typename D> Windows::UI::Xaml::Media::Brush consume_Windows_UI_Xaml_Controls_Primitives_IGridViewItemPresenter<D>::FocusBorderBrush() const
{
    Windows::UI::Xaml::Media::Brush value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Primitives::IGridViewItemPresenter)->get_FocusBorderBrush(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_UI_Xaml_Controls_Primitives_IGridViewItemPresenter<D>::FocusBorderBrush(Windows::UI::Xaml::Media::Brush const& value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Primitives::IGridViewItemPresenter)->put_FocusBorderBrush(get_abi(value)));
}

template <typename D> Windows::UI::Xaml::Media::Brush consume_Windows_UI_Xaml_Controls_Primitives_IGridViewItemPresenter<D>::PlaceholderBackground() const
{
    Windows::UI::Xaml::Media::Brush value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Primitives::IGridViewItemPresenter)->get_PlaceholderBackground(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_UI_Xaml_Controls_Primitives_IGridViewItemPresenter<D>::PlaceholderBackground(Windows::UI::Xaml::Media::Brush const& value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Primitives::IGridViewItemPresenter)->put_PlaceholderBackground(get_abi(value)));
}

template <typename D> Windows::UI::Xaml::Media::Brush consume_Windows_UI_Xaml_Controls_Primitives_IGridViewItemPresenter<D>::PointerOverBackground() const
{
    Windows::UI::Xaml::Media::Brush value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Primitives::IGridViewItemPresenter)->get_PointerOverBackground(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_UI_Xaml_Controls_Primitives_IGridViewItemPresenter<D>::PointerOverBackground(Windows::UI::Xaml::Media::Brush const& value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Primitives::IGridViewItemPresenter)->put_PointerOverBackground(get_abi(value)));
}

template <typename D> Windows::UI::Xaml::Media::Brush consume_Windows_UI_Xaml_Controls_Primitives_IGridViewItemPresenter<D>::SelectedBackground() const
{
    Windows::UI::Xaml::Media::Brush value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Primitives::IGridViewItemPresenter)->get_SelectedBackground(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_UI_Xaml_Controls_Primitives_IGridViewItemPresenter<D>::SelectedBackground(Windows::UI::Xaml::Media::Brush const& value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Primitives::IGridViewItemPresenter)->put_SelectedBackground(get_abi(value)));
}

template <typename D> Windows::UI::Xaml::Media::Brush consume_Windows_UI_Xaml_Controls_Primitives_IGridViewItemPresenter<D>::SelectedForeground() const
{
    Windows::UI::Xaml::Media::Brush value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Primitives::IGridViewItemPresenter)->get_SelectedForeground(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_UI_Xaml_Controls_Primitives_IGridViewItemPresenter<D>::SelectedForeground(Windows::UI::Xaml::Media::Brush const& value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Primitives::IGridViewItemPresenter)->put_SelectedForeground(get_abi(value)));
}

template <typename D> Windows::UI::Xaml::Media::Brush consume_Windows_UI_Xaml_Controls_Primitives_IGridViewItemPresenter<D>::SelectedPointerOverBackground() const
{
    Windows::UI::Xaml::Media::Brush value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Primitives::IGridViewItemPresenter)->get_SelectedPointerOverBackground(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_UI_Xaml_Controls_Primitives_IGridViewItemPresenter<D>::SelectedPointerOverBackground(Windows::UI::Xaml::Media::Brush const& value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Primitives::IGridViewItemPresenter)->put_SelectedPointerOverBackground(get_abi(value)));
}

template <typename D> Windows::UI::Xaml::Media::Brush consume_Windows_UI_Xaml_Controls_Primitives_IGridViewItemPresenter<D>::SelectedPointerOverBorderBrush() const
{
    Windows::UI::Xaml::Media::Brush value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Primitives::IGridViewItemPresenter)->get_SelectedPointerOverBorderBrush(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_UI_Xaml_Controls_Primitives_IGridViewItemPresenter<D>::SelectedPointerOverBorderBrush(Windows::UI::Xaml::Media::Brush const& value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Primitives::IGridViewItemPresenter)->put_SelectedPointerOverBorderBrush(get_abi(value)));
}

template <typename D> Windows::UI::Xaml::Thickness consume_Windows_UI_Xaml_Controls_Primitives_IGridViewItemPresenter<D>::SelectedBorderThickness() const
{
    Windows::UI::Xaml::Thickness value{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Primitives::IGridViewItemPresenter)->get_SelectedBorderThickness(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_UI_Xaml_Controls_Primitives_IGridViewItemPresenter<D>::SelectedBorderThickness(Windows::UI::Xaml::Thickness const& value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Primitives::IGridViewItemPresenter)->put_SelectedBorderThickness(get_abi(value)));
}

template <typename D> double consume_Windows_UI_Xaml_Controls_Primitives_IGridViewItemPresenter<D>::DisabledOpacity() const
{
    double value{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Primitives::IGridViewItemPresenter)->get_DisabledOpacity(&value));
    return value;
}

template <typename D> void consume_Windows_UI_Xaml_Controls_Primitives_IGridViewItemPresenter<D>::DisabledOpacity(double value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Primitives::IGridViewItemPresenter)->put_DisabledOpacity(value));
}

template <typename D> double consume_Windows_UI_Xaml_Controls_Primitives_IGridViewItemPresenter<D>::DragOpacity() const
{
    double value{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Primitives::IGridViewItemPresenter)->get_DragOpacity(&value));
    return value;
}

template <typename D> void consume_Windows_UI_Xaml_Controls_Primitives_IGridViewItemPresenter<D>::DragOpacity(double value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Primitives::IGridViewItemPresenter)->put_DragOpacity(value));
}

template <typename D> double consume_Windows_UI_Xaml_Controls_Primitives_IGridViewItemPresenter<D>::ReorderHintOffset() const
{
    double value{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Primitives::IGridViewItemPresenter)->get_ReorderHintOffset(&value));
    return value;
}

template <typename D> void consume_Windows_UI_Xaml_Controls_Primitives_IGridViewItemPresenter<D>::ReorderHintOffset(double value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Primitives::IGridViewItemPresenter)->put_ReorderHintOffset(value));
}

template <typename D> Windows::UI::Xaml::HorizontalAlignment consume_Windows_UI_Xaml_Controls_Primitives_IGridViewItemPresenter<D>::GridViewItemPresenterHorizontalContentAlignment() const
{
    Windows::UI::Xaml::HorizontalAlignment value{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Primitives::IGridViewItemPresenter)->get_GridViewItemPresenterHorizontalContentAlignment(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_UI_Xaml_Controls_Primitives_IGridViewItemPresenter<D>::GridViewItemPresenterHorizontalContentAlignment(Windows::UI::Xaml::HorizontalAlignment const& value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Primitives::IGridViewItemPresenter)->put_GridViewItemPresenterHorizontalContentAlignment(get_abi(value)));
}

template <typename D> Windows::UI::Xaml::VerticalAlignment consume_Windows_UI_Xaml_Controls_Primitives_IGridViewItemPresenter<D>::GridViewItemPresenterVerticalContentAlignment() const
{
    Windows::UI::Xaml::VerticalAlignment value{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Primitives::IGridViewItemPresenter)->get_GridViewItemPresenterVerticalContentAlignment(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_UI_Xaml_Controls_Primitives_IGridViewItemPresenter<D>::GridViewItemPresenterVerticalContentAlignment(Windows::UI::Xaml::VerticalAlignment const& value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Primitives::IGridViewItemPresenter)->put_GridViewItemPresenterVerticalContentAlignment(get_abi(value)));
}

template <typename D> Windows::UI::Xaml::Thickness consume_Windows_UI_Xaml_Controls_Primitives_IGridViewItemPresenter<D>::GridViewItemPresenterPadding() const
{
    Windows::UI::Xaml::Thickness value{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Primitives::IGridViewItemPresenter)->get_GridViewItemPresenterPadding(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_UI_Xaml_Controls_Primitives_IGridViewItemPresenter<D>::GridViewItemPresenterPadding(Windows::UI::Xaml::Thickness const& value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Primitives::IGridViewItemPresenter)->put_GridViewItemPresenterPadding(get_abi(value)));
}

template <typename D> Windows::UI::Xaml::Thickness consume_Windows_UI_Xaml_Controls_Primitives_IGridViewItemPresenter<D>::PointerOverBackgroundMargin() const
{
    Windows::UI::Xaml::Thickness value{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Primitives::IGridViewItemPresenter)->get_PointerOverBackgroundMargin(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_UI_Xaml_Controls_Primitives_IGridViewItemPresenter<D>::PointerOverBackgroundMargin(Windows::UI::Xaml::Thickness const& value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Primitives::IGridViewItemPresenter)->put_PointerOverBackgroundMargin(get_abi(value)));
}

template <typename D> Windows::UI::Xaml::Thickness consume_Windows_UI_Xaml_Controls_Primitives_IGridViewItemPresenter<D>::ContentMargin() const
{
    Windows::UI::Xaml::Thickness value{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Primitives::IGridViewItemPresenter)->get_ContentMargin(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_UI_Xaml_Controls_Primitives_IGridViewItemPresenter<D>::ContentMargin(Windows::UI::Xaml::Thickness const& value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Primitives::IGridViewItemPresenter)->put_ContentMargin(get_abi(value)));
}

template <typename D> Windows::UI::Xaml::Controls::Primitives::GridViewItemPresenter consume_Windows_UI_Xaml_Controls_Primitives_IGridViewItemPresenterFactory<D>::CreateInstance(Windows::Foundation::IInspectable const& baseInterface, Windows::Foundation::IInspectable& innerInterface) const
{
    Windows::UI::Xaml::Controls::Primitives::GridViewItemPresenter value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Primitives::IGridViewItemPresenterFactory)->CreateInstance(get_abi(baseInterface), put_abi(innerInterface), put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Xaml::DependencyProperty consume_Windows_UI_Xaml_Controls_Primitives_IGridViewItemPresenterStatics<D>::SelectionCheckMarkVisualEnabledProperty() const
{
    Windows::UI::Xaml::DependencyProperty value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Primitives::IGridViewItemPresenterStatics)->get_SelectionCheckMarkVisualEnabledProperty(put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Xaml::DependencyProperty consume_Windows_UI_Xaml_Controls_Primitives_IGridViewItemPresenterStatics<D>::CheckHintBrushProperty() const
{
    Windows::UI::Xaml::DependencyProperty value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Primitives::IGridViewItemPresenterStatics)->get_CheckHintBrushProperty(put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Xaml::DependencyProperty consume_Windows_UI_Xaml_Controls_Primitives_IGridViewItemPresenterStatics<D>::CheckSelectingBrushProperty() const
{
    Windows::UI::Xaml::DependencyProperty value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Primitives::IGridViewItemPresenterStatics)->get_CheckSelectingBrushProperty(put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Xaml::DependencyProperty consume_Windows_UI_Xaml_Controls_Primitives_IGridViewItemPresenterStatics<D>::CheckBrushProperty() const
{
    Windows::UI::Xaml::DependencyProperty value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Primitives::IGridViewItemPresenterStatics)->get_CheckBrushProperty(put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Xaml::DependencyProperty consume_Windows_UI_Xaml_Controls_Primitives_IGridViewItemPresenterStatics<D>::DragBackgroundProperty() const
{
    Windows::UI::Xaml::DependencyProperty value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Primitives::IGridViewItemPresenterStatics)->get_DragBackgroundProperty(put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Xaml::DependencyProperty consume_Windows_UI_Xaml_Controls_Primitives_IGridViewItemPresenterStatics<D>::DragForegroundProperty() const
{
    Windows::UI::Xaml::DependencyProperty value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Primitives::IGridViewItemPresenterStatics)->get_DragForegroundProperty(put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Xaml::DependencyProperty consume_Windows_UI_Xaml_Controls_Primitives_IGridViewItemPresenterStatics<D>::FocusBorderBrushProperty() const
{
    Windows::UI::Xaml::DependencyProperty value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Primitives::IGridViewItemPresenterStatics)->get_FocusBorderBrushProperty(put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Xaml::DependencyProperty consume_Windows_UI_Xaml_Controls_Primitives_IGridViewItemPresenterStatics<D>::PlaceholderBackgroundProperty() const
{
    Windows::UI::Xaml::DependencyProperty value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Primitives::IGridViewItemPresenterStatics)->get_PlaceholderBackgroundProperty(put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Xaml::DependencyProperty consume_Windows_UI_Xaml_Controls_Primitives_IGridViewItemPresenterStatics<D>::PointerOverBackgroundProperty() const
{
    Windows::UI::Xaml::DependencyProperty value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Primitives::IGridViewItemPresenterStatics)->get_PointerOverBackgroundProperty(put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Xaml::DependencyProperty consume_Windows_UI_Xaml_Controls_Primitives_IGridViewItemPresenterStatics<D>::SelectedBackgroundProperty() const
{
    Windows::UI::Xaml::DependencyProperty value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Primitives::IGridViewItemPresenterStatics)->get_SelectedBackgroundProperty(put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Xaml::DependencyProperty consume_Windows_UI_Xaml_Controls_Primitives_IGridViewItemPresenterStatics<D>::SelectedForegroundProperty() const
{
    Windows::UI::Xaml::DependencyProperty value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Primitives::IGridViewItemPresenterStatics)->get_SelectedForegroundProperty(put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Xaml::DependencyProperty consume_Windows_UI_Xaml_Controls_Primitives_IGridViewItemPresenterStatics<D>::SelectedPointerOverBackgroundProperty() const
{
    Windows::UI::Xaml::DependencyProperty value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Primitives::IGridViewItemPresenterStatics)->get_SelectedPointerOverBackgroundProperty(put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Xaml::DependencyProperty consume_Windows_UI_Xaml_Controls_Primitives_IGridViewItemPresenterStatics<D>::SelectedPointerOverBorderBrushProperty() const
{
    Windows::UI::Xaml::DependencyProperty value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Primitives::IGridViewItemPresenterStatics)->get_SelectedPointerOverBorderBrushProperty(put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Xaml::DependencyProperty consume_Windows_UI_Xaml_Controls_Primitives_IGridViewItemPresenterStatics<D>::SelectedBorderThicknessProperty() const
{
    Windows::UI::Xaml::DependencyProperty value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Primitives::IGridViewItemPresenterStatics)->get_SelectedBorderThicknessProperty(put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Xaml::DependencyProperty consume_Windows_UI_Xaml_Controls_Primitives_IGridViewItemPresenterStatics<D>::DisabledOpacityProperty() const
{
    Windows::UI::Xaml::DependencyProperty value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Primitives::IGridViewItemPresenterStatics)->get_DisabledOpacityProperty(put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Xaml::DependencyProperty consume_Windows_UI_Xaml_Controls_Primitives_IGridViewItemPresenterStatics<D>::DragOpacityProperty() const
{
    Windows::UI::Xaml::DependencyProperty value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Primitives::IGridViewItemPresenterStatics)->get_DragOpacityProperty(put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Xaml::DependencyProperty consume_Windows_UI_Xaml_Controls_Primitives_IGridViewItemPresenterStatics<D>::ReorderHintOffsetProperty() const
{
    Windows::UI::Xaml::DependencyProperty value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Primitives::IGridViewItemPresenterStatics)->get_ReorderHintOffsetProperty(put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Xaml::DependencyProperty consume_Windows_UI_Xaml_Controls_Primitives_IGridViewItemPresenterStatics<D>::GridViewItemPresenterHorizontalContentAlignmentProperty() const
{
    Windows::UI::Xaml::DependencyProperty value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Primitives::IGridViewItemPresenterStatics)->get_GridViewItemPresenterHorizontalContentAlignmentProperty(put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Xaml::DependencyProperty consume_Windows_UI_Xaml_Controls_Primitives_IGridViewItemPresenterStatics<D>::GridViewItemPresenterVerticalContentAlignmentProperty() const
{
    Windows::UI::Xaml::DependencyProperty value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Primitives::IGridViewItemPresenterStatics)->get_GridViewItemPresenterVerticalContentAlignmentProperty(put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Xaml::DependencyProperty consume_Windows_UI_Xaml_Controls_Primitives_IGridViewItemPresenterStatics<D>::GridViewItemPresenterPaddingProperty() const
{
    Windows::UI::Xaml::DependencyProperty value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Primitives::IGridViewItemPresenterStatics)->get_GridViewItemPresenterPaddingProperty(put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Xaml::DependencyProperty consume_Windows_UI_Xaml_Controls_Primitives_IGridViewItemPresenterStatics<D>::PointerOverBackgroundMarginProperty() const
{
    Windows::UI::Xaml::DependencyProperty value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Primitives::IGridViewItemPresenterStatics)->get_PointerOverBackgroundMarginProperty(put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Xaml::DependencyProperty consume_Windows_UI_Xaml_Controls_Primitives_IGridViewItemPresenterStatics<D>::ContentMarginProperty() const
{
    Windows::UI::Xaml::DependencyProperty value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Primitives::IGridViewItemPresenterStatics)->get_ContentMarginProperty(put_abi(value)));
    return value;
}

template <typename D> int32_t consume_Windows_UI_Xaml_Controls_Primitives_IGridViewItemTemplateSettings<D>::DragItemsCount() const
{
    int32_t value{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Primitives::IGridViewItemTemplateSettings)->get_DragItemsCount(&value));
    return value;
}

template <typename D> int32_t consume_Windows_UI_Xaml_Controls_Primitives_IItemsChangedEventArgs<D>::Action() const
{
    int32_t value{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Primitives::IItemsChangedEventArgs)->get_Action(&value));
    return value;
}

template <typename D> Windows::UI::Xaml::Controls::Primitives::GeneratorPosition consume_Windows_UI_Xaml_Controls_Primitives_IItemsChangedEventArgs<D>::Position() const
{
    Windows::UI::Xaml::Controls::Primitives::GeneratorPosition value{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Primitives::IItemsChangedEventArgs)->get_Position(put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Xaml::Controls::Primitives::GeneratorPosition consume_Windows_UI_Xaml_Controls_Primitives_IItemsChangedEventArgs<D>::OldPosition() const
{
    Windows::UI::Xaml::Controls::Primitives::GeneratorPosition value{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Primitives::IItemsChangedEventArgs)->get_OldPosition(put_abi(value)));
    return value;
}

template <typename D> int32_t consume_Windows_UI_Xaml_Controls_Primitives_IItemsChangedEventArgs<D>::ItemCount() const
{
    int32_t value{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Primitives::IItemsChangedEventArgs)->get_ItemCount(&value));
    return value;
}

template <typename D> int32_t consume_Windows_UI_Xaml_Controls_Primitives_IItemsChangedEventArgs<D>::ItemUICount() const
{
    int32_t value{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Primitives::IItemsChangedEventArgs)->get_ItemUICount(&value));
    return value;
}

template <typename D> Windows::UI::Xaml::Media::Brush consume_Windows_UI_Xaml_Controls_Primitives_IJumpListItemBackgroundConverter<D>::Enabled() const
{
    Windows::UI::Xaml::Media::Brush value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Primitives::IJumpListItemBackgroundConverter)->get_Enabled(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_UI_Xaml_Controls_Primitives_IJumpListItemBackgroundConverter<D>::Enabled(Windows::UI::Xaml::Media::Brush const& value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Primitives::IJumpListItemBackgroundConverter)->put_Enabled(get_abi(value)));
}

template <typename D> Windows::UI::Xaml::Media::Brush consume_Windows_UI_Xaml_Controls_Primitives_IJumpListItemBackgroundConverter<D>::Disabled() const
{
    Windows::UI::Xaml::Media::Brush value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Primitives::IJumpListItemBackgroundConverter)->get_Disabled(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_UI_Xaml_Controls_Primitives_IJumpListItemBackgroundConverter<D>::Disabled(Windows::UI::Xaml::Media::Brush const& value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Primitives::IJumpListItemBackgroundConverter)->put_Disabled(get_abi(value)));
}

template <typename D> Windows::UI::Xaml::DependencyProperty consume_Windows_UI_Xaml_Controls_Primitives_IJumpListItemBackgroundConverterStatics<D>::EnabledProperty() const
{
    Windows::UI::Xaml::DependencyProperty value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Primitives::IJumpListItemBackgroundConverterStatics)->get_EnabledProperty(put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Xaml::DependencyProperty consume_Windows_UI_Xaml_Controls_Primitives_IJumpListItemBackgroundConverterStatics<D>::DisabledProperty() const
{
    Windows::UI::Xaml::DependencyProperty value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Primitives::IJumpListItemBackgroundConverterStatics)->get_DisabledProperty(put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Xaml::Media::Brush consume_Windows_UI_Xaml_Controls_Primitives_IJumpListItemForegroundConverter<D>::Enabled() const
{
    Windows::UI::Xaml::Media::Brush value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Primitives::IJumpListItemForegroundConverter)->get_Enabled(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_UI_Xaml_Controls_Primitives_IJumpListItemForegroundConverter<D>::Enabled(Windows::UI::Xaml::Media::Brush const& value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Primitives::IJumpListItemForegroundConverter)->put_Enabled(get_abi(value)));
}

template <typename D> Windows::UI::Xaml::Media::Brush consume_Windows_UI_Xaml_Controls_Primitives_IJumpListItemForegroundConverter<D>::Disabled() const
{
    Windows::UI::Xaml::Media::Brush value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Primitives::IJumpListItemForegroundConverter)->get_Disabled(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_UI_Xaml_Controls_Primitives_IJumpListItemForegroundConverter<D>::Disabled(Windows::UI::Xaml::Media::Brush const& value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Primitives::IJumpListItemForegroundConverter)->put_Disabled(get_abi(value)));
}

template <typename D> Windows::UI::Xaml::DependencyProperty consume_Windows_UI_Xaml_Controls_Primitives_IJumpListItemForegroundConverterStatics<D>::EnabledProperty() const
{
    Windows::UI::Xaml::DependencyProperty value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Primitives::IJumpListItemForegroundConverterStatics)->get_EnabledProperty(put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Xaml::DependencyProperty consume_Windows_UI_Xaml_Controls_Primitives_IJumpListItemForegroundConverterStatics<D>::DisabledProperty() const
{
    Windows::UI::Xaml::DependencyProperty value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Primitives::IJumpListItemForegroundConverterStatics)->get_DisabledProperty(put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Xaml::UIElement consume_Windows_UI_Xaml_Controls_Primitives_ILayoutInformationStatics<D>::GetLayoutExceptionElement(Windows::Foundation::IInspectable const& dispatcher) const
{
    Windows::UI::Xaml::UIElement result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Primitives::ILayoutInformationStatics)->GetLayoutExceptionElement(get_abi(dispatcher), put_abi(result)));
    return result;
}

template <typename D> Windows::Foundation::Rect consume_Windows_UI_Xaml_Controls_Primitives_ILayoutInformationStatics<D>::GetLayoutSlot(Windows::UI::Xaml::FrameworkElement const& element) const
{
    Windows::Foundation::Rect result{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Primitives::ILayoutInformationStatics)->GetLayoutSlot(get_abi(element), put_abi(result)));
    return result;
}

template <typename D> Windows::Foundation::Size consume_Windows_UI_Xaml_Controls_Primitives_ILayoutInformationStatics2<D>::GetAvailableSize(Windows::UI::Xaml::UIElement const& element) const
{
    Windows::Foundation::Size result{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Primitives::ILayoutInformationStatics2)->GetAvailableSize(get_abi(element), put_abi(result)));
    return result;
}

template <typename D> bool consume_Windows_UI_Xaml_Controls_Primitives_IListViewItemPresenter<D>::SelectionCheckMarkVisualEnabled() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Primitives::IListViewItemPresenter)->get_SelectionCheckMarkVisualEnabled(&value));
    return value;
}

template <typename D> void consume_Windows_UI_Xaml_Controls_Primitives_IListViewItemPresenter<D>::SelectionCheckMarkVisualEnabled(bool value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Primitives::IListViewItemPresenter)->put_SelectionCheckMarkVisualEnabled(value));
}

template <typename D> Windows::UI::Xaml::Media::Brush consume_Windows_UI_Xaml_Controls_Primitives_IListViewItemPresenter<D>::CheckHintBrush() const
{
    Windows::UI::Xaml::Media::Brush value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Primitives::IListViewItemPresenter)->get_CheckHintBrush(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_UI_Xaml_Controls_Primitives_IListViewItemPresenter<D>::CheckHintBrush(Windows::UI::Xaml::Media::Brush const& value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Primitives::IListViewItemPresenter)->put_CheckHintBrush(get_abi(value)));
}

template <typename D> Windows::UI::Xaml::Media::Brush consume_Windows_UI_Xaml_Controls_Primitives_IListViewItemPresenter<D>::CheckSelectingBrush() const
{
    Windows::UI::Xaml::Media::Brush value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Primitives::IListViewItemPresenter)->get_CheckSelectingBrush(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_UI_Xaml_Controls_Primitives_IListViewItemPresenter<D>::CheckSelectingBrush(Windows::UI::Xaml::Media::Brush const& value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Primitives::IListViewItemPresenter)->put_CheckSelectingBrush(get_abi(value)));
}

template <typename D> Windows::UI::Xaml::Media::Brush consume_Windows_UI_Xaml_Controls_Primitives_IListViewItemPresenter<D>::CheckBrush() const
{
    Windows::UI::Xaml::Media::Brush value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Primitives::IListViewItemPresenter)->get_CheckBrush(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_UI_Xaml_Controls_Primitives_IListViewItemPresenter<D>::CheckBrush(Windows::UI::Xaml::Media::Brush const& value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Primitives::IListViewItemPresenter)->put_CheckBrush(get_abi(value)));
}

template <typename D> Windows::UI::Xaml::Media::Brush consume_Windows_UI_Xaml_Controls_Primitives_IListViewItemPresenter<D>::DragBackground() const
{
    Windows::UI::Xaml::Media::Brush value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Primitives::IListViewItemPresenter)->get_DragBackground(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_UI_Xaml_Controls_Primitives_IListViewItemPresenter<D>::DragBackground(Windows::UI::Xaml::Media::Brush const& value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Primitives::IListViewItemPresenter)->put_DragBackground(get_abi(value)));
}

template <typename D> Windows::UI::Xaml::Media::Brush consume_Windows_UI_Xaml_Controls_Primitives_IListViewItemPresenter<D>::DragForeground() const
{
    Windows::UI::Xaml::Media::Brush value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Primitives::IListViewItemPresenter)->get_DragForeground(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_UI_Xaml_Controls_Primitives_IListViewItemPresenter<D>::DragForeground(Windows::UI::Xaml::Media::Brush const& value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Primitives::IListViewItemPresenter)->put_DragForeground(get_abi(value)));
}

template <typename D> Windows::UI::Xaml::Media::Brush consume_Windows_UI_Xaml_Controls_Primitives_IListViewItemPresenter<D>::FocusBorderBrush() const
{
    Windows::UI::Xaml::Media::Brush value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Primitives::IListViewItemPresenter)->get_FocusBorderBrush(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_UI_Xaml_Controls_Primitives_IListViewItemPresenter<D>::FocusBorderBrush(Windows::UI::Xaml::Media::Brush const& value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Primitives::IListViewItemPresenter)->put_FocusBorderBrush(get_abi(value)));
}

template <typename D> Windows::UI::Xaml::Media::Brush consume_Windows_UI_Xaml_Controls_Primitives_IListViewItemPresenter<D>::PlaceholderBackground() const
{
    Windows::UI::Xaml::Media::Brush value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Primitives::IListViewItemPresenter)->get_PlaceholderBackground(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_UI_Xaml_Controls_Primitives_IListViewItemPresenter<D>::PlaceholderBackground(Windows::UI::Xaml::Media::Brush const& value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Primitives::IListViewItemPresenter)->put_PlaceholderBackground(get_abi(value)));
}

template <typename D> Windows::UI::Xaml::Media::Brush consume_Windows_UI_Xaml_Controls_Primitives_IListViewItemPresenter<D>::PointerOverBackground() const
{
    Windows::UI::Xaml::Media::Brush value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Primitives::IListViewItemPresenter)->get_PointerOverBackground(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_UI_Xaml_Controls_Primitives_IListViewItemPresenter<D>::PointerOverBackground(Windows::UI::Xaml::Media::Brush const& value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Primitives::IListViewItemPresenter)->put_PointerOverBackground(get_abi(value)));
}

template <typename D> Windows::UI::Xaml::Media::Brush consume_Windows_UI_Xaml_Controls_Primitives_IListViewItemPresenter<D>::SelectedBackground() const
{
    Windows::UI::Xaml::Media::Brush value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Primitives::IListViewItemPresenter)->get_SelectedBackground(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_UI_Xaml_Controls_Primitives_IListViewItemPresenter<D>::SelectedBackground(Windows::UI::Xaml::Media::Brush const& value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Primitives::IListViewItemPresenter)->put_SelectedBackground(get_abi(value)));
}

template <typename D> Windows::UI::Xaml::Media::Brush consume_Windows_UI_Xaml_Controls_Primitives_IListViewItemPresenter<D>::SelectedForeground() const
{
    Windows::UI::Xaml::Media::Brush value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Primitives::IListViewItemPresenter)->get_SelectedForeground(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_UI_Xaml_Controls_Primitives_IListViewItemPresenter<D>::SelectedForeground(Windows::UI::Xaml::Media::Brush const& value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Primitives::IListViewItemPresenter)->put_SelectedForeground(get_abi(value)));
}

template <typename D> Windows::UI::Xaml::Media::Brush consume_Windows_UI_Xaml_Controls_Primitives_IListViewItemPresenter<D>::SelectedPointerOverBackground() const
{
    Windows::UI::Xaml::Media::Brush value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Primitives::IListViewItemPresenter)->get_SelectedPointerOverBackground(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_UI_Xaml_Controls_Primitives_IListViewItemPresenter<D>::SelectedPointerOverBackground(Windows::UI::Xaml::Media::Brush const& value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Primitives::IListViewItemPresenter)->put_SelectedPointerOverBackground(get_abi(value)));
}

template <typename D> Windows::UI::Xaml::Media::Brush consume_Windows_UI_Xaml_Controls_Primitives_IListViewItemPresenter<D>::SelectedPointerOverBorderBrush() const
{
    Windows::UI::Xaml::Media::Brush value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Primitives::IListViewItemPresenter)->get_SelectedPointerOverBorderBrush(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_UI_Xaml_Controls_Primitives_IListViewItemPresenter<D>::SelectedPointerOverBorderBrush(Windows::UI::Xaml::Media::Brush const& value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Primitives::IListViewItemPresenter)->put_SelectedPointerOverBorderBrush(get_abi(value)));
}

template <typename D> Windows::UI::Xaml::Thickness consume_Windows_UI_Xaml_Controls_Primitives_IListViewItemPresenter<D>::SelectedBorderThickness() const
{
    Windows::UI::Xaml::Thickness value{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Primitives::IListViewItemPresenter)->get_SelectedBorderThickness(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_UI_Xaml_Controls_Primitives_IListViewItemPresenter<D>::SelectedBorderThickness(Windows::UI::Xaml::Thickness const& value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Primitives::IListViewItemPresenter)->put_SelectedBorderThickness(get_abi(value)));
}

template <typename D> double consume_Windows_UI_Xaml_Controls_Primitives_IListViewItemPresenter<D>::DisabledOpacity() const
{
    double value{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Primitives::IListViewItemPresenter)->get_DisabledOpacity(&value));
    return value;
}

template <typename D> void consume_Windows_UI_Xaml_Controls_Primitives_IListViewItemPresenter<D>::DisabledOpacity(double value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Primitives::IListViewItemPresenter)->put_DisabledOpacity(value));
}

template <typename D> double consume_Windows_UI_Xaml_Controls_Primitives_IListViewItemPresenter<D>::DragOpacity() const
{
    double value{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Primitives::IListViewItemPresenter)->get_DragOpacity(&value));
    return value;
}

template <typename D> void consume_Windows_UI_Xaml_Controls_Primitives_IListViewItemPresenter<D>::DragOpacity(double value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Primitives::IListViewItemPresenter)->put_DragOpacity(value));
}

template <typename D> double consume_Windows_UI_Xaml_Controls_Primitives_IListViewItemPresenter<D>::ReorderHintOffset() const
{
    double value{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Primitives::IListViewItemPresenter)->get_ReorderHintOffset(&value));
    return value;
}

template <typename D> void consume_Windows_UI_Xaml_Controls_Primitives_IListViewItemPresenter<D>::ReorderHintOffset(double value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Primitives::IListViewItemPresenter)->put_ReorderHintOffset(value));
}

template <typename D> Windows::UI::Xaml::HorizontalAlignment consume_Windows_UI_Xaml_Controls_Primitives_IListViewItemPresenter<D>::ListViewItemPresenterHorizontalContentAlignment() const
{
    Windows::UI::Xaml::HorizontalAlignment value{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Primitives::IListViewItemPresenter)->get_ListViewItemPresenterHorizontalContentAlignment(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_UI_Xaml_Controls_Primitives_IListViewItemPresenter<D>::ListViewItemPresenterHorizontalContentAlignment(Windows::UI::Xaml::HorizontalAlignment const& value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Primitives::IListViewItemPresenter)->put_ListViewItemPresenterHorizontalContentAlignment(get_abi(value)));
}

template <typename D> Windows::UI::Xaml::VerticalAlignment consume_Windows_UI_Xaml_Controls_Primitives_IListViewItemPresenter<D>::ListViewItemPresenterVerticalContentAlignment() const
{
    Windows::UI::Xaml::VerticalAlignment value{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Primitives::IListViewItemPresenter)->get_ListViewItemPresenterVerticalContentAlignment(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_UI_Xaml_Controls_Primitives_IListViewItemPresenter<D>::ListViewItemPresenterVerticalContentAlignment(Windows::UI::Xaml::VerticalAlignment const& value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Primitives::IListViewItemPresenter)->put_ListViewItemPresenterVerticalContentAlignment(get_abi(value)));
}

template <typename D> Windows::UI::Xaml::Thickness consume_Windows_UI_Xaml_Controls_Primitives_IListViewItemPresenter<D>::ListViewItemPresenterPadding() const
{
    Windows::UI::Xaml::Thickness value{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Primitives::IListViewItemPresenter)->get_ListViewItemPresenterPadding(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_UI_Xaml_Controls_Primitives_IListViewItemPresenter<D>::ListViewItemPresenterPadding(Windows::UI::Xaml::Thickness const& value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Primitives::IListViewItemPresenter)->put_ListViewItemPresenterPadding(get_abi(value)));
}

template <typename D> Windows::UI::Xaml::Thickness consume_Windows_UI_Xaml_Controls_Primitives_IListViewItemPresenter<D>::PointerOverBackgroundMargin() const
{
    Windows::UI::Xaml::Thickness value{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Primitives::IListViewItemPresenter)->get_PointerOverBackgroundMargin(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_UI_Xaml_Controls_Primitives_IListViewItemPresenter<D>::PointerOverBackgroundMargin(Windows::UI::Xaml::Thickness const& value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Primitives::IListViewItemPresenter)->put_PointerOverBackgroundMargin(get_abi(value)));
}

template <typename D> Windows::UI::Xaml::Thickness consume_Windows_UI_Xaml_Controls_Primitives_IListViewItemPresenter<D>::ContentMargin() const
{
    Windows::UI::Xaml::Thickness value{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Primitives::IListViewItemPresenter)->get_ContentMargin(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_UI_Xaml_Controls_Primitives_IListViewItemPresenter<D>::ContentMargin(Windows::UI::Xaml::Thickness const& value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Primitives::IListViewItemPresenter)->put_ContentMargin(get_abi(value)));
}

template <typename D> Windows::UI::Xaml::Media::Brush consume_Windows_UI_Xaml_Controls_Primitives_IListViewItemPresenter2<D>::SelectedPressedBackground() const
{
    Windows::UI::Xaml::Media::Brush value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Primitives::IListViewItemPresenter2)->get_SelectedPressedBackground(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_UI_Xaml_Controls_Primitives_IListViewItemPresenter2<D>::SelectedPressedBackground(Windows::UI::Xaml::Media::Brush const& value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Primitives::IListViewItemPresenter2)->put_SelectedPressedBackground(get_abi(value)));
}

template <typename D> Windows::UI::Xaml::Media::Brush consume_Windows_UI_Xaml_Controls_Primitives_IListViewItemPresenter2<D>::PressedBackground() const
{
    Windows::UI::Xaml::Media::Brush value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Primitives::IListViewItemPresenter2)->get_PressedBackground(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_UI_Xaml_Controls_Primitives_IListViewItemPresenter2<D>::PressedBackground(Windows::UI::Xaml::Media::Brush const& value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Primitives::IListViewItemPresenter2)->put_PressedBackground(get_abi(value)));
}

template <typename D> Windows::UI::Xaml::Media::Brush consume_Windows_UI_Xaml_Controls_Primitives_IListViewItemPresenter2<D>::CheckBoxBrush() const
{
    Windows::UI::Xaml::Media::Brush value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Primitives::IListViewItemPresenter2)->get_CheckBoxBrush(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_UI_Xaml_Controls_Primitives_IListViewItemPresenter2<D>::CheckBoxBrush(Windows::UI::Xaml::Media::Brush const& value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Primitives::IListViewItemPresenter2)->put_CheckBoxBrush(get_abi(value)));
}

template <typename D> Windows::UI::Xaml::Media::Brush consume_Windows_UI_Xaml_Controls_Primitives_IListViewItemPresenter2<D>::FocusSecondaryBorderBrush() const
{
    Windows::UI::Xaml::Media::Brush value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Primitives::IListViewItemPresenter2)->get_FocusSecondaryBorderBrush(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_UI_Xaml_Controls_Primitives_IListViewItemPresenter2<D>::FocusSecondaryBorderBrush(Windows::UI::Xaml::Media::Brush const& value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Primitives::IListViewItemPresenter2)->put_FocusSecondaryBorderBrush(get_abi(value)));
}

template <typename D> Windows::UI::Xaml::Controls::Primitives::ListViewItemPresenterCheckMode consume_Windows_UI_Xaml_Controls_Primitives_IListViewItemPresenter2<D>::CheckMode() const
{
    Windows::UI::Xaml::Controls::Primitives::ListViewItemPresenterCheckMode value{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Primitives::IListViewItemPresenter2)->get_CheckMode(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_UI_Xaml_Controls_Primitives_IListViewItemPresenter2<D>::CheckMode(Windows::UI::Xaml::Controls::Primitives::ListViewItemPresenterCheckMode const& value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Primitives::IListViewItemPresenter2)->put_CheckMode(get_abi(value)));
}

template <typename D> Windows::UI::Xaml::Media::Brush consume_Windows_UI_Xaml_Controls_Primitives_IListViewItemPresenter2<D>::PointerOverForeground() const
{
    Windows::UI::Xaml::Media::Brush value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Primitives::IListViewItemPresenter2)->get_PointerOverForeground(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_UI_Xaml_Controls_Primitives_IListViewItemPresenter2<D>::PointerOverForeground(Windows::UI::Xaml::Media::Brush const& value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Primitives::IListViewItemPresenter2)->put_PointerOverForeground(get_abi(value)));
}

template <typename D> Windows::UI::Xaml::Media::Brush consume_Windows_UI_Xaml_Controls_Primitives_IListViewItemPresenter3<D>::RevealBackground() const
{
    Windows::UI::Xaml::Media::Brush value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Primitives::IListViewItemPresenter3)->get_RevealBackground(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_UI_Xaml_Controls_Primitives_IListViewItemPresenter3<D>::RevealBackground(Windows::UI::Xaml::Media::Brush const& value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Primitives::IListViewItemPresenter3)->put_RevealBackground(get_abi(value)));
}

template <typename D> Windows::UI::Xaml::Media::Brush consume_Windows_UI_Xaml_Controls_Primitives_IListViewItemPresenter3<D>::RevealBorderBrush() const
{
    Windows::UI::Xaml::Media::Brush value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Primitives::IListViewItemPresenter3)->get_RevealBorderBrush(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_UI_Xaml_Controls_Primitives_IListViewItemPresenter3<D>::RevealBorderBrush(Windows::UI::Xaml::Media::Brush const& value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Primitives::IListViewItemPresenter3)->put_RevealBorderBrush(get_abi(value)));
}

template <typename D> Windows::UI::Xaml::Thickness consume_Windows_UI_Xaml_Controls_Primitives_IListViewItemPresenter3<D>::RevealBorderThickness() const
{
    Windows::UI::Xaml::Thickness value{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Primitives::IListViewItemPresenter3)->get_RevealBorderThickness(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_UI_Xaml_Controls_Primitives_IListViewItemPresenter3<D>::RevealBorderThickness(Windows::UI::Xaml::Thickness const& value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Primitives::IListViewItemPresenter3)->put_RevealBorderThickness(get_abi(value)));
}

template <typename D> bool consume_Windows_UI_Xaml_Controls_Primitives_IListViewItemPresenter3<D>::RevealBackgroundShowsAboveContent() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Primitives::IListViewItemPresenter3)->get_RevealBackgroundShowsAboveContent(&value));
    return value;
}

template <typename D> void consume_Windows_UI_Xaml_Controls_Primitives_IListViewItemPresenter3<D>::RevealBackgroundShowsAboveContent(bool value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Primitives::IListViewItemPresenter3)->put_RevealBackgroundShowsAboveContent(value));
}

template <typename D> Windows::UI::Xaml::Controls::Primitives::ListViewItemPresenter consume_Windows_UI_Xaml_Controls_Primitives_IListViewItemPresenterFactory<D>::CreateInstance(Windows::Foundation::IInspectable const& baseInterface, Windows::Foundation::IInspectable& innerInterface) const
{
    Windows::UI::Xaml::Controls::Primitives::ListViewItemPresenter value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Primitives::IListViewItemPresenterFactory)->CreateInstance(get_abi(baseInterface), put_abi(innerInterface), put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Xaml::DependencyProperty consume_Windows_UI_Xaml_Controls_Primitives_IListViewItemPresenterStatics<D>::SelectionCheckMarkVisualEnabledProperty() const
{
    Windows::UI::Xaml::DependencyProperty value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Primitives::IListViewItemPresenterStatics)->get_SelectionCheckMarkVisualEnabledProperty(put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Xaml::DependencyProperty consume_Windows_UI_Xaml_Controls_Primitives_IListViewItemPresenterStatics<D>::CheckHintBrushProperty() const
{
    Windows::UI::Xaml::DependencyProperty value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Primitives::IListViewItemPresenterStatics)->get_CheckHintBrushProperty(put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Xaml::DependencyProperty consume_Windows_UI_Xaml_Controls_Primitives_IListViewItemPresenterStatics<D>::CheckSelectingBrushProperty() const
{
    Windows::UI::Xaml::DependencyProperty value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Primitives::IListViewItemPresenterStatics)->get_CheckSelectingBrushProperty(put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Xaml::DependencyProperty consume_Windows_UI_Xaml_Controls_Primitives_IListViewItemPresenterStatics<D>::CheckBrushProperty() const
{
    Windows::UI::Xaml::DependencyProperty value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Primitives::IListViewItemPresenterStatics)->get_CheckBrushProperty(put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Xaml::DependencyProperty consume_Windows_UI_Xaml_Controls_Primitives_IListViewItemPresenterStatics<D>::DragBackgroundProperty() const
{
    Windows::UI::Xaml::DependencyProperty value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Primitives::IListViewItemPresenterStatics)->get_DragBackgroundProperty(put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Xaml::DependencyProperty consume_Windows_UI_Xaml_Controls_Primitives_IListViewItemPresenterStatics<D>::DragForegroundProperty() const
{
    Windows::UI::Xaml::DependencyProperty value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Primitives::IListViewItemPresenterStatics)->get_DragForegroundProperty(put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Xaml::DependencyProperty consume_Windows_UI_Xaml_Controls_Primitives_IListViewItemPresenterStatics<D>::FocusBorderBrushProperty() const
{
    Windows::UI::Xaml::DependencyProperty value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Primitives::IListViewItemPresenterStatics)->get_FocusBorderBrushProperty(put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Xaml::DependencyProperty consume_Windows_UI_Xaml_Controls_Primitives_IListViewItemPresenterStatics<D>::PlaceholderBackgroundProperty() const
{
    Windows::UI::Xaml::DependencyProperty value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Primitives::IListViewItemPresenterStatics)->get_PlaceholderBackgroundProperty(put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Xaml::DependencyProperty consume_Windows_UI_Xaml_Controls_Primitives_IListViewItemPresenterStatics<D>::PointerOverBackgroundProperty() const
{
    Windows::UI::Xaml::DependencyProperty value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Primitives::IListViewItemPresenterStatics)->get_PointerOverBackgroundProperty(put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Xaml::DependencyProperty consume_Windows_UI_Xaml_Controls_Primitives_IListViewItemPresenterStatics<D>::SelectedBackgroundProperty() const
{
    Windows::UI::Xaml::DependencyProperty value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Primitives::IListViewItemPresenterStatics)->get_SelectedBackgroundProperty(put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Xaml::DependencyProperty consume_Windows_UI_Xaml_Controls_Primitives_IListViewItemPresenterStatics<D>::SelectedForegroundProperty() const
{
    Windows::UI::Xaml::DependencyProperty value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Primitives::IListViewItemPresenterStatics)->get_SelectedForegroundProperty(put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Xaml::DependencyProperty consume_Windows_UI_Xaml_Controls_Primitives_IListViewItemPresenterStatics<D>::SelectedPointerOverBackgroundProperty() const
{
    Windows::UI::Xaml::DependencyProperty value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Primitives::IListViewItemPresenterStatics)->get_SelectedPointerOverBackgroundProperty(put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Xaml::DependencyProperty consume_Windows_UI_Xaml_Controls_Primitives_IListViewItemPresenterStatics<D>::SelectedPointerOverBorderBrushProperty() const
{
    Windows::UI::Xaml::DependencyProperty value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Primitives::IListViewItemPresenterStatics)->get_SelectedPointerOverBorderBrushProperty(put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Xaml::DependencyProperty consume_Windows_UI_Xaml_Controls_Primitives_IListViewItemPresenterStatics<D>::SelectedBorderThicknessProperty() const
{
    Windows::UI::Xaml::DependencyProperty value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Primitives::IListViewItemPresenterStatics)->get_SelectedBorderThicknessProperty(put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Xaml::DependencyProperty consume_Windows_UI_Xaml_Controls_Primitives_IListViewItemPresenterStatics<D>::DisabledOpacityProperty() const
{
    Windows::UI::Xaml::DependencyProperty value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Primitives::IListViewItemPresenterStatics)->get_DisabledOpacityProperty(put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Xaml::DependencyProperty consume_Windows_UI_Xaml_Controls_Primitives_IListViewItemPresenterStatics<D>::DragOpacityProperty() const
{
    Windows::UI::Xaml::DependencyProperty value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Primitives::IListViewItemPresenterStatics)->get_DragOpacityProperty(put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Xaml::DependencyProperty consume_Windows_UI_Xaml_Controls_Primitives_IListViewItemPresenterStatics<D>::ReorderHintOffsetProperty() const
{
    Windows::UI::Xaml::DependencyProperty value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Primitives::IListViewItemPresenterStatics)->get_ReorderHintOffsetProperty(put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Xaml::DependencyProperty consume_Windows_UI_Xaml_Controls_Primitives_IListViewItemPresenterStatics<D>::ListViewItemPresenterHorizontalContentAlignmentProperty() const
{
    Windows::UI::Xaml::DependencyProperty value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Primitives::IListViewItemPresenterStatics)->get_ListViewItemPresenterHorizontalContentAlignmentProperty(put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Xaml::DependencyProperty consume_Windows_UI_Xaml_Controls_Primitives_IListViewItemPresenterStatics<D>::ListViewItemPresenterVerticalContentAlignmentProperty() const
{
    Windows::UI::Xaml::DependencyProperty value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Primitives::IListViewItemPresenterStatics)->get_ListViewItemPresenterVerticalContentAlignmentProperty(put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Xaml::DependencyProperty consume_Windows_UI_Xaml_Controls_Primitives_IListViewItemPresenterStatics<D>::ListViewItemPresenterPaddingProperty() const
{
    Windows::UI::Xaml::DependencyProperty value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Primitives::IListViewItemPresenterStatics)->get_ListViewItemPresenterPaddingProperty(put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Xaml::DependencyProperty consume_Windows_UI_Xaml_Controls_Primitives_IListViewItemPresenterStatics<D>::PointerOverBackgroundMarginProperty() const
{
    Windows::UI::Xaml::DependencyProperty value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Primitives::IListViewItemPresenterStatics)->get_PointerOverBackgroundMarginProperty(put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Xaml::DependencyProperty consume_Windows_UI_Xaml_Controls_Primitives_IListViewItemPresenterStatics<D>::ContentMarginProperty() const
{
    Windows::UI::Xaml::DependencyProperty value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Primitives::IListViewItemPresenterStatics)->get_ContentMarginProperty(put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Xaml::DependencyProperty consume_Windows_UI_Xaml_Controls_Primitives_IListViewItemPresenterStatics2<D>::SelectedPressedBackgroundProperty() const
{
    Windows::UI::Xaml::DependencyProperty value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Primitives::IListViewItemPresenterStatics2)->get_SelectedPressedBackgroundProperty(put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Xaml::DependencyProperty consume_Windows_UI_Xaml_Controls_Primitives_IListViewItemPresenterStatics2<D>::PressedBackgroundProperty() const
{
    Windows::UI::Xaml::DependencyProperty value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Primitives::IListViewItemPresenterStatics2)->get_PressedBackgroundProperty(put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Xaml::DependencyProperty consume_Windows_UI_Xaml_Controls_Primitives_IListViewItemPresenterStatics2<D>::CheckBoxBrushProperty() const
{
    Windows::UI::Xaml::DependencyProperty value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Primitives::IListViewItemPresenterStatics2)->get_CheckBoxBrushProperty(put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Xaml::DependencyProperty consume_Windows_UI_Xaml_Controls_Primitives_IListViewItemPresenterStatics2<D>::FocusSecondaryBorderBrushProperty() const
{
    Windows::UI::Xaml::DependencyProperty value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Primitives::IListViewItemPresenterStatics2)->get_FocusSecondaryBorderBrushProperty(put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Xaml::DependencyProperty consume_Windows_UI_Xaml_Controls_Primitives_IListViewItemPresenterStatics2<D>::CheckModeProperty() const
{
    Windows::UI::Xaml::DependencyProperty value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Primitives::IListViewItemPresenterStatics2)->get_CheckModeProperty(put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Xaml::DependencyProperty consume_Windows_UI_Xaml_Controls_Primitives_IListViewItemPresenterStatics2<D>::PointerOverForegroundProperty() const
{
    Windows::UI::Xaml::DependencyProperty value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Primitives::IListViewItemPresenterStatics2)->get_PointerOverForegroundProperty(put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Xaml::DependencyProperty consume_Windows_UI_Xaml_Controls_Primitives_IListViewItemPresenterStatics3<D>::RevealBackgroundProperty() const
{
    Windows::UI::Xaml::DependencyProperty value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Primitives::IListViewItemPresenterStatics3)->get_RevealBackgroundProperty(put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Xaml::DependencyProperty consume_Windows_UI_Xaml_Controls_Primitives_IListViewItemPresenterStatics3<D>::RevealBorderBrushProperty() const
{
    Windows::UI::Xaml::DependencyProperty value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Primitives::IListViewItemPresenterStatics3)->get_RevealBorderBrushProperty(put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Xaml::DependencyProperty consume_Windows_UI_Xaml_Controls_Primitives_IListViewItemPresenterStatics3<D>::RevealBorderThicknessProperty() const
{
    Windows::UI::Xaml::DependencyProperty value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Primitives::IListViewItemPresenterStatics3)->get_RevealBorderThicknessProperty(put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Xaml::DependencyProperty consume_Windows_UI_Xaml_Controls_Primitives_IListViewItemPresenterStatics3<D>::RevealBackgroundShowsAboveContentProperty() const
{
    Windows::UI::Xaml::DependencyProperty value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Primitives::IListViewItemPresenterStatics3)->get_RevealBackgroundShowsAboveContentProperty(put_abi(value)));
    return value;
}

template <typename D> int32_t consume_Windows_UI_Xaml_Controls_Primitives_IListViewItemTemplateSettings<D>::DragItemsCount() const
{
    int32_t value{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Primitives::IListViewItemTemplateSettings)->get_DragItemsCount(&value));
    return value;
}

template <typename D> bool consume_Windows_UI_Xaml_Controls_Primitives_ILoopingSelector<D>::ShouldLoop() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Primitives::ILoopingSelector)->get_ShouldLoop(&value));
    return value;
}

template <typename D> void consume_Windows_UI_Xaml_Controls_Primitives_ILoopingSelector<D>::ShouldLoop(bool value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Primitives::ILoopingSelector)->put_ShouldLoop(value));
}

template <typename D> Windows::Foundation::Collections::IVector<Windows::Foundation::IInspectable> consume_Windows_UI_Xaml_Controls_Primitives_ILoopingSelector<D>::Items() const
{
    Windows::Foundation::Collections::IVector<Windows::Foundation::IInspectable> value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Primitives::ILoopingSelector)->get_Items(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_UI_Xaml_Controls_Primitives_ILoopingSelector<D>::Items(param::vector<Windows::Foundation::IInspectable> const& value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Primitives::ILoopingSelector)->put_Items(get_abi(value)));
}

template <typename D> int32_t consume_Windows_UI_Xaml_Controls_Primitives_ILoopingSelector<D>::SelectedIndex() const
{
    int32_t value{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Primitives::ILoopingSelector)->get_SelectedIndex(&value));
    return value;
}

template <typename D> void consume_Windows_UI_Xaml_Controls_Primitives_ILoopingSelector<D>::SelectedIndex(int32_t value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Primitives::ILoopingSelector)->put_SelectedIndex(value));
}

template <typename D> Windows::Foundation::IInspectable consume_Windows_UI_Xaml_Controls_Primitives_ILoopingSelector<D>::SelectedItem() const
{
    Windows::Foundation::IInspectable value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Primitives::ILoopingSelector)->get_SelectedItem(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_UI_Xaml_Controls_Primitives_ILoopingSelector<D>::SelectedItem(Windows::Foundation::IInspectable const& value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Primitives::ILoopingSelector)->put_SelectedItem(get_abi(value)));
}

template <typename D> int32_t consume_Windows_UI_Xaml_Controls_Primitives_ILoopingSelector<D>::ItemWidth() const
{
    int32_t value{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Primitives::ILoopingSelector)->get_ItemWidth(&value));
    return value;
}

template <typename D> void consume_Windows_UI_Xaml_Controls_Primitives_ILoopingSelector<D>::ItemWidth(int32_t value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Primitives::ILoopingSelector)->put_ItemWidth(value));
}

template <typename D> int32_t consume_Windows_UI_Xaml_Controls_Primitives_ILoopingSelector<D>::ItemHeight() const
{
    int32_t value{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Primitives::ILoopingSelector)->get_ItemHeight(&value));
    return value;
}

template <typename D> void consume_Windows_UI_Xaml_Controls_Primitives_ILoopingSelector<D>::ItemHeight(int32_t value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Primitives::ILoopingSelector)->put_ItemHeight(value));
}

template <typename D> Windows::UI::Xaml::DataTemplate consume_Windows_UI_Xaml_Controls_Primitives_ILoopingSelector<D>::ItemTemplate() const
{
    Windows::UI::Xaml::DataTemplate value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Primitives::ILoopingSelector)->get_ItemTemplate(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_UI_Xaml_Controls_Primitives_ILoopingSelector<D>::ItemTemplate(Windows::UI::Xaml::DataTemplate const& value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Primitives::ILoopingSelector)->put_ItemTemplate(get_abi(value)));
}

template <typename D> winrt::event_token consume_Windows_UI_Xaml_Controls_Primitives_ILoopingSelector<D>::SelectionChanged(Windows::UI::Xaml::Controls::SelectionChangedEventHandler const& handler) const
{
    winrt::event_token token{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Primitives::ILoopingSelector)->add_SelectionChanged(get_abi(handler), put_abi(token)));
    return token;
}

template <typename D> typename consume_Windows_UI_Xaml_Controls_Primitives_ILoopingSelector<D>::SelectionChanged_revoker consume_Windows_UI_Xaml_Controls_Primitives_ILoopingSelector<D>::SelectionChanged(auto_revoke_t, Windows::UI::Xaml::Controls::SelectionChangedEventHandler const& handler) const
{
    return impl::make_event_revoker<D, SelectionChanged_revoker>(this, SelectionChanged(handler));
}

template <typename D> void consume_Windows_UI_Xaml_Controls_Primitives_ILoopingSelector<D>::SelectionChanged(winrt::event_token const& token) const noexcept
{
    WINRT_VERIFY_(0, WINRT_SHIM(Windows::UI::Xaml::Controls::Primitives::ILoopingSelector)->remove_SelectionChanged(get_abi(token)));
}

template <typename D> Windows::UI::Xaml::DependencyProperty consume_Windows_UI_Xaml_Controls_Primitives_ILoopingSelectorStatics<D>::ShouldLoopProperty() const
{
    Windows::UI::Xaml::DependencyProperty value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Primitives::ILoopingSelectorStatics)->get_ShouldLoopProperty(put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Xaml::DependencyProperty consume_Windows_UI_Xaml_Controls_Primitives_ILoopingSelectorStatics<D>::ItemsProperty() const
{
    Windows::UI::Xaml::DependencyProperty value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Primitives::ILoopingSelectorStatics)->get_ItemsProperty(put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Xaml::DependencyProperty consume_Windows_UI_Xaml_Controls_Primitives_ILoopingSelectorStatics<D>::SelectedIndexProperty() const
{
    Windows::UI::Xaml::DependencyProperty value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Primitives::ILoopingSelectorStatics)->get_SelectedIndexProperty(put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Xaml::DependencyProperty consume_Windows_UI_Xaml_Controls_Primitives_ILoopingSelectorStatics<D>::SelectedItemProperty() const
{
    Windows::UI::Xaml::DependencyProperty value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Primitives::ILoopingSelectorStatics)->get_SelectedItemProperty(put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Xaml::DependencyProperty consume_Windows_UI_Xaml_Controls_Primitives_ILoopingSelectorStatics<D>::ItemWidthProperty() const
{
    Windows::UI::Xaml::DependencyProperty value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Primitives::ILoopingSelectorStatics)->get_ItemWidthProperty(put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Xaml::DependencyProperty consume_Windows_UI_Xaml_Controls_Primitives_ILoopingSelectorStatics<D>::ItemHeightProperty() const
{
    Windows::UI::Xaml::DependencyProperty value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Primitives::ILoopingSelectorStatics)->get_ItemHeightProperty(put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Xaml::DependencyProperty consume_Windows_UI_Xaml_Controls_Primitives_ILoopingSelectorStatics<D>::ItemTemplateProperty() const
{
    Windows::UI::Xaml::DependencyProperty value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Primitives::ILoopingSelectorStatics)->get_ItemTemplateProperty(put_abi(value)));
    return value;
}

template <typename D> double consume_Windows_UI_Xaml_Controls_Primitives_IMenuFlyoutItemTemplateSettings<D>::KeyboardAcceleratorTextMinWidth() const
{
    double value{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Primitives::IMenuFlyoutItemTemplateSettings)->get_KeyboardAcceleratorTextMinWidth(&value));
    return value;
}

template <typename D> double consume_Windows_UI_Xaml_Controls_Primitives_IMenuFlyoutPresenterTemplateSettings<D>::FlyoutContentMinWidth() const
{
    double value{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Primitives::IMenuFlyoutPresenterTemplateSettings)->get_FlyoutContentMinWidth(&value));
    return value;
}

template <typename D> Windows::UI::Xaml::Controls::IconElement consume_Windows_UI_Xaml_Controls_Primitives_INavigationViewItemPresenter<D>::Icon() const
{
    Windows::UI::Xaml::Controls::IconElement value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Primitives::INavigationViewItemPresenter)->get_Icon(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_UI_Xaml_Controls_Primitives_INavigationViewItemPresenter<D>::Icon(Windows::UI::Xaml::Controls::IconElement const& value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Primitives::INavigationViewItemPresenter)->put_Icon(get_abi(value)));
}

template <typename D> Windows::UI::Xaml::Controls::Primitives::NavigationViewItemPresenter consume_Windows_UI_Xaml_Controls_Primitives_INavigationViewItemPresenterFactory<D>::CreateInstance(Windows::Foundation::IInspectable const& baseInterface, Windows::Foundation::IInspectable& innerInterface) const
{
    Windows::UI::Xaml::Controls::Primitives::NavigationViewItemPresenter value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Primitives::INavigationViewItemPresenterFactory)->CreateInstance(get_abi(baseInterface), put_abi(innerInterface), put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Xaml::DependencyProperty consume_Windows_UI_Xaml_Controls_Primitives_INavigationViewItemPresenterStatics<D>::IconProperty() const
{
    Windows::UI::Xaml::DependencyProperty value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Primitives::INavigationViewItemPresenterStatics)->get_IconProperty(put_abi(value)));
    return value;
}

template <typename D> bool consume_Windows_UI_Xaml_Controls_Primitives_IOrientedVirtualizingPanel<D>::CanVerticallyScroll() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Primitives::IOrientedVirtualizingPanel)->get_CanVerticallyScroll(&value));
    return value;
}

template <typename D> void consume_Windows_UI_Xaml_Controls_Primitives_IOrientedVirtualizingPanel<D>::CanVerticallyScroll(bool value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Primitives::IOrientedVirtualizingPanel)->put_CanVerticallyScroll(value));
}

template <typename D> bool consume_Windows_UI_Xaml_Controls_Primitives_IOrientedVirtualizingPanel<D>::CanHorizontallyScroll() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Primitives::IOrientedVirtualizingPanel)->get_CanHorizontallyScroll(&value));
    return value;
}

template <typename D> void consume_Windows_UI_Xaml_Controls_Primitives_IOrientedVirtualizingPanel<D>::CanHorizontallyScroll(bool value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Primitives::IOrientedVirtualizingPanel)->put_CanHorizontallyScroll(value));
}

template <typename D> double consume_Windows_UI_Xaml_Controls_Primitives_IOrientedVirtualizingPanel<D>::ExtentWidth() const
{
    double value{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Primitives::IOrientedVirtualizingPanel)->get_ExtentWidth(&value));
    return value;
}

template <typename D> double consume_Windows_UI_Xaml_Controls_Primitives_IOrientedVirtualizingPanel<D>::ExtentHeight() const
{
    double value{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Primitives::IOrientedVirtualizingPanel)->get_ExtentHeight(&value));
    return value;
}

template <typename D> double consume_Windows_UI_Xaml_Controls_Primitives_IOrientedVirtualizingPanel<D>::ViewportWidth() const
{
    double value{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Primitives::IOrientedVirtualizingPanel)->get_ViewportWidth(&value));
    return value;
}

template <typename D> double consume_Windows_UI_Xaml_Controls_Primitives_IOrientedVirtualizingPanel<D>::ViewportHeight() const
{
    double value{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Primitives::IOrientedVirtualizingPanel)->get_ViewportHeight(&value));
    return value;
}

template <typename D> double consume_Windows_UI_Xaml_Controls_Primitives_IOrientedVirtualizingPanel<D>::HorizontalOffset() const
{
    double value{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Primitives::IOrientedVirtualizingPanel)->get_HorizontalOffset(&value));
    return value;
}

template <typename D> double consume_Windows_UI_Xaml_Controls_Primitives_IOrientedVirtualizingPanel<D>::VerticalOffset() const
{
    double value{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Primitives::IOrientedVirtualizingPanel)->get_VerticalOffset(&value));
    return value;
}

template <typename D> Windows::Foundation::IInspectable consume_Windows_UI_Xaml_Controls_Primitives_IOrientedVirtualizingPanel<D>::ScrollOwner() const
{
    Windows::Foundation::IInspectable value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Primitives::IOrientedVirtualizingPanel)->get_ScrollOwner(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_UI_Xaml_Controls_Primitives_IOrientedVirtualizingPanel<D>::ScrollOwner(Windows::Foundation::IInspectable const& value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Primitives::IOrientedVirtualizingPanel)->put_ScrollOwner(get_abi(value)));
}

template <typename D> void consume_Windows_UI_Xaml_Controls_Primitives_IOrientedVirtualizingPanel<D>::LineUp() const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Primitives::IOrientedVirtualizingPanel)->LineUp());
}

template <typename D> void consume_Windows_UI_Xaml_Controls_Primitives_IOrientedVirtualizingPanel<D>::LineDown() const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Primitives::IOrientedVirtualizingPanel)->LineDown());
}

template <typename D> void consume_Windows_UI_Xaml_Controls_Primitives_IOrientedVirtualizingPanel<D>::LineLeft() const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Primitives::IOrientedVirtualizingPanel)->LineLeft());
}

template <typename D> void consume_Windows_UI_Xaml_Controls_Primitives_IOrientedVirtualizingPanel<D>::LineRight() const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Primitives::IOrientedVirtualizingPanel)->LineRight());
}

template <typename D> void consume_Windows_UI_Xaml_Controls_Primitives_IOrientedVirtualizingPanel<D>::PageUp() const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Primitives::IOrientedVirtualizingPanel)->PageUp());
}

template <typename D> void consume_Windows_UI_Xaml_Controls_Primitives_IOrientedVirtualizingPanel<D>::PageDown() const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Primitives::IOrientedVirtualizingPanel)->PageDown());
}

template <typename D> void consume_Windows_UI_Xaml_Controls_Primitives_IOrientedVirtualizingPanel<D>::PageLeft() const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Primitives::IOrientedVirtualizingPanel)->PageLeft());
}

template <typename D> void consume_Windows_UI_Xaml_Controls_Primitives_IOrientedVirtualizingPanel<D>::PageRight() const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Primitives::IOrientedVirtualizingPanel)->PageRight());
}

template <typename D> void consume_Windows_UI_Xaml_Controls_Primitives_IOrientedVirtualizingPanel<D>::MouseWheelUp() const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Primitives::IOrientedVirtualizingPanel)->MouseWheelUp());
}

template <typename D> void consume_Windows_UI_Xaml_Controls_Primitives_IOrientedVirtualizingPanel<D>::MouseWheelDown() const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Primitives::IOrientedVirtualizingPanel)->MouseWheelDown());
}

template <typename D> void consume_Windows_UI_Xaml_Controls_Primitives_IOrientedVirtualizingPanel<D>::MouseWheelLeft() const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Primitives::IOrientedVirtualizingPanel)->MouseWheelLeft());
}

template <typename D> void consume_Windows_UI_Xaml_Controls_Primitives_IOrientedVirtualizingPanel<D>::MouseWheelRight() const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Primitives::IOrientedVirtualizingPanel)->MouseWheelRight());
}

template <typename D> void consume_Windows_UI_Xaml_Controls_Primitives_IOrientedVirtualizingPanel<D>::SetHorizontalOffset(double offset) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Primitives::IOrientedVirtualizingPanel)->SetHorizontalOffset(offset));
}

template <typename D> void consume_Windows_UI_Xaml_Controls_Primitives_IOrientedVirtualizingPanel<D>::SetVerticalOffset(double offset) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Primitives::IOrientedVirtualizingPanel)->SetVerticalOffset(offset));
}

template <typename D> Windows::Foundation::Rect consume_Windows_UI_Xaml_Controls_Primitives_IOrientedVirtualizingPanel<D>::MakeVisible(Windows::UI::Xaml::UIElement const& visual, Windows::Foundation::Rect const& rectangle) const
{
    Windows::Foundation::Rect result{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Primitives::IOrientedVirtualizingPanel)->MakeVisible(get_abi(visual), get_abi(rectangle), put_abi(result)));
    return result;
}

template <typename D> Windows::UI::Xaml::Controls::Primitives::PickerFlyoutBase consume_Windows_UI_Xaml_Controls_Primitives_IPickerFlyoutBaseFactory<D>::CreateInstance(Windows::Foundation::IInspectable const& baseInterface, Windows::Foundation::IInspectable& innerInterface) const
{
    Windows::UI::Xaml::Controls::Primitives::PickerFlyoutBase value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Primitives::IPickerFlyoutBaseFactory)->CreateInstance(get_abi(baseInterface), put_abi(innerInterface), put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_UI_Xaml_Controls_Primitives_IPickerFlyoutBaseOverrides<D>::OnConfirmed() const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Primitives::IPickerFlyoutBaseOverrides)->OnConfirmed());
}

template <typename D> bool consume_Windows_UI_Xaml_Controls_Primitives_IPickerFlyoutBaseOverrides<D>::ShouldShowConfirmationButtons() const
{
    bool result{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Primitives::IPickerFlyoutBaseOverrides)->ShouldShowConfirmationButtons(&result));
    return result;
}

template <typename D> Windows::UI::Xaml::DependencyProperty consume_Windows_UI_Xaml_Controls_Primitives_IPickerFlyoutBaseStatics<D>::TitleProperty() const
{
    Windows::UI::Xaml::DependencyProperty value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Primitives::IPickerFlyoutBaseStatics)->get_TitleProperty(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_UI_Xaml_Controls_Primitives_IPickerFlyoutBaseStatics<D>::GetTitle(Windows::UI::Xaml::DependencyObject const& element) const
{
    hstring result{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Primitives::IPickerFlyoutBaseStatics)->GetTitle(get_abi(element), put_abi(result)));
    return result;
}

template <typename D> void consume_Windows_UI_Xaml_Controls_Primitives_IPickerFlyoutBaseStatics<D>::SetTitle(Windows::UI::Xaml::DependencyObject const& element, param::hstring const& value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Primitives::IPickerFlyoutBaseStatics)->SetTitle(get_abi(element), get_abi(value)));
}

template <typename D> Windows::UI::Xaml::Controls::Primitives::PivotHeaderItem consume_Windows_UI_Xaml_Controls_Primitives_IPivotHeaderItemFactory<D>::CreateInstance(Windows::Foundation::IInspectable const& baseInterface, Windows::Foundation::IInspectable& innerInterface) const
{
    Windows::UI::Xaml::Controls::Primitives::PivotHeaderItem value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Primitives::IPivotHeaderItemFactory)->CreateInstance(get_abi(baseInterface), put_abi(innerInterface), put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Xaml::UIElement consume_Windows_UI_Xaml_Controls_Primitives_IPopup<D>::Child() const
{
    Windows::UI::Xaml::UIElement value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Primitives::IPopup)->get_Child(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_UI_Xaml_Controls_Primitives_IPopup<D>::Child(Windows::UI::Xaml::UIElement const& value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Primitives::IPopup)->put_Child(get_abi(value)));
}

template <typename D> bool consume_Windows_UI_Xaml_Controls_Primitives_IPopup<D>::IsOpen() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Primitives::IPopup)->get_IsOpen(&value));
    return value;
}

template <typename D> void consume_Windows_UI_Xaml_Controls_Primitives_IPopup<D>::IsOpen(bool value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Primitives::IPopup)->put_IsOpen(value));
}

template <typename D> double consume_Windows_UI_Xaml_Controls_Primitives_IPopup<D>::HorizontalOffset() const
{
    double value{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Primitives::IPopup)->get_HorizontalOffset(&value));
    return value;
}

template <typename D> void consume_Windows_UI_Xaml_Controls_Primitives_IPopup<D>::HorizontalOffset(double value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Primitives::IPopup)->put_HorizontalOffset(value));
}

template <typename D> double consume_Windows_UI_Xaml_Controls_Primitives_IPopup<D>::VerticalOffset() const
{
    double value{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Primitives::IPopup)->get_VerticalOffset(&value));
    return value;
}

template <typename D> void consume_Windows_UI_Xaml_Controls_Primitives_IPopup<D>::VerticalOffset(double value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Primitives::IPopup)->put_VerticalOffset(value));
}

template <typename D> Windows::UI::Xaml::Media::Animation::TransitionCollection consume_Windows_UI_Xaml_Controls_Primitives_IPopup<D>::ChildTransitions() const
{
    Windows::UI::Xaml::Media::Animation::TransitionCollection value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Primitives::IPopup)->get_ChildTransitions(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_UI_Xaml_Controls_Primitives_IPopup<D>::ChildTransitions(Windows::UI::Xaml::Media::Animation::TransitionCollection const& value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Primitives::IPopup)->put_ChildTransitions(get_abi(value)));
}

template <typename D> bool consume_Windows_UI_Xaml_Controls_Primitives_IPopup<D>::IsLightDismissEnabled() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Primitives::IPopup)->get_IsLightDismissEnabled(&value));
    return value;
}

template <typename D> void consume_Windows_UI_Xaml_Controls_Primitives_IPopup<D>::IsLightDismissEnabled(bool value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Primitives::IPopup)->put_IsLightDismissEnabled(value));
}

template <typename D> winrt::event_token consume_Windows_UI_Xaml_Controls_Primitives_IPopup<D>::Opened(Windows::Foundation::EventHandler<Windows::Foundation::IInspectable> const& handler) const
{
    winrt::event_token token{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Primitives::IPopup)->add_Opened(get_abi(handler), put_abi(token)));
    return token;
}

template <typename D> typename consume_Windows_UI_Xaml_Controls_Primitives_IPopup<D>::Opened_revoker consume_Windows_UI_Xaml_Controls_Primitives_IPopup<D>::Opened(auto_revoke_t, Windows::Foundation::EventHandler<Windows::Foundation::IInspectable> const& handler) const
{
    return impl::make_event_revoker<D, Opened_revoker>(this, Opened(handler));
}

template <typename D> void consume_Windows_UI_Xaml_Controls_Primitives_IPopup<D>::Opened(winrt::event_token const& token) const noexcept
{
    WINRT_VERIFY_(0, WINRT_SHIM(Windows::UI::Xaml::Controls::Primitives::IPopup)->remove_Opened(get_abi(token)));
}

template <typename D> winrt::event_token consume_Windows_UI_Xaml_Controls_Primitives_IPopup<D>::Closed(Windows::Foundation::EventHandler<Windows::Foundation::IInspectable> const& handler) const
{
    winrt::event_token token{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Primitives::IPopup)->add_Closed(get_abi(handler), put_abi(token)));
    return token;
}

template <typename D> typename consume_Windows_UI_Xaml_Controls_Primitives_IPopup<D>::Closed_revoker consume_Windows_UI_Xaml_Controls_Primitives_IPopup<D>::Closed(auto_revoke_t, Windows::Foundation::EventHandler<Windows::Foundation::IInspectable> const& handler) const
{
    return impl::make_event_revoker<D, Closed_revoker>(this, Closed(handler));
}

template <typename D> void consume_Windows_UI_Xaml_Controls_Primitives_IPopup<D>::Closed(winrt::event_token const& token) const noexcept
{
    WINRT_VERIFY_(0, WINRT_SHIM(Windows::UI::Xaml::Controls::Primitives::IPopup)->remove_Closed(get_abi(token)));
}

template <typename D> Windows::UI::Xaml::Controls::LightDismissOverlayMode consume_Windows_UI_Xaml_Controls_Primitives_IPopup2<D>::LightDismissOverlayMode() const
{
    Windows::UI::Xaml::Controls::LightDismissOverlayMode value{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Primitives::IPopup2)->get_LightDismissOverlayMode(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_UI_Xaml_Controls_Primitives_IPopup2<D>::LightDismissOverlayMode(Windows::UI::Xaml::Controls::LightDismissOverlayMode const& value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Primitives::IPopup2)->put_LightDismissOverlayMode(get_abi(value)));
}

template <typename D> bool consume_Windows_UI_Xaml_Controls_Primitives_IPopup3<D>::ShouldConstrainToRootBounds() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Primitives::IPopup3)->get_ShouldConstrainToRootBounds(&value));
    return value;
}

template <typename D> void consume_Windows_UI_Xaml_Controls_Primitives_IPopup3<D>::ShouldConstrainToRootBounds(bool value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Primitives::IPopup3)->put_ShouldConstrainToRootBounds(value));
}

template <typename D> bool consume_Windows_UI_Xaml_Controls_Primitives_IPopup3<D>::IsConstrainedToRootBounds() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Primitives::IPopup3)->get_IsConstrainedToRootBounds(&value));
    return value;
}

template <typename D> Windows::UI::Xaml::DependencyProperty consume_Windows_UI_Xaml_Controls_Primitives_IPopupStatics<D>::ChildProperty() const
{
    Windows::UI::Xaml::DependencyProperty value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Primitives::IPopupStatics)->get_ChildProperty(put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Xaml::DependencyProperty consume_Windows_UI_Xaml_Controls_Primitives_IPopupStatics<D>::IsOpenProperty() const
{
    Windows::UI::Xaml::DependencyProperty value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Primitives::IPopupStatics)->get_IsOpenProperty(put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Xaml::DependencyProperty consume_Windows_UI_Xaml_Controls_Primitives_IPopupStatics<D>::HorizontalOffsetProperty() const
{
    Windows::UI::Xaml::DependencyProperty value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Primitives::IPopupStatics)->get_HorizontalOffsetProperty(put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Xaml::DependencyProperty consume_Windows_UI_Xaml_Controls_Primitives_IPopupStatics<D>::VerticalOffsetProperty() const
{
    Windows::UI::Xaml::DependencyProperty value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Primitives::IPopupStatics)->get_VerticalOffsetProperty(put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Xaml::DependencyProperty consume_Windows_UI_Xaml_Controls_Primitives_IPopupStatics<D>::ChildTransitionsProperty() const
{
    Windows::UI::Xaml::DependencyProperty value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Primitives::IPopupStatics)->get_ChildTransitionsProperty(put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Xaml::DependencyProperty consume_Windows_UI_Xaml_Controls_Primitives_IPopupStatics<D>::IsLightDismissEnabledProperty() const
{
    Windows::UI::Xaml::DependencyProperty value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Primitives::IPopupStatics)->get_IsLightDismissEnabledProperty(put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Xaml::DependencyProperty consume_Windows_UI_Xaml_Controls_Primitives_IPopupStatics2<D>::LightDismissOverlayModeProperty() const
{
    Windows::UI::Xaml::DependencyProperty value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Primitives::IPopupStatics2)->get_LightDismissOverlayModeProperty(put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Xaml::DependencyProperty consume_Windows_UI_Xaml_Controls_Primitives_IPopupStatics3<D>::ShouldConstrainToRootBoundsProperty() const
{
    Windows::UI::Xaml::DependencyProperty value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Primitives::IPopupStatics3)->get_ShouldConstrainToRootBoundsProperty(put_abi(value)));
    return value;
}

template <typename D> double consume_Windows_UI_Xaml_Controls_Primitives_IProgressBarTemplateSettings<D>::EllipseDiameter() const
{
    double value{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Primitives::IProgressBarTemplateSettings)->get_EllipseDiameter(&value));
    return value;
}

template <typename D> double consume_Windows_UI_Xaml_Controls_Primitives_IProgressBarTemplateSettings<D>::EllipseOffset() const
{
    double value{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Primitives::IProgressBarTemplateSettings)->get_EllipseOffset(&value));
    return value;
}

template <typename D> double consume_Windows_UI_Xaml_Controls_Primitives_IProgressBarTemplateSettings<D>::EllipseAnimationWellPosition() const
{
    double value{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Primitives::IProgressBarTemplateSettings)->get_EllipseAnimationWellPosition(&value));
    return value;
}

template <typename D> double consume_Windows_UI_Xaml_Controls_Primitives_IProgressBarTemplateSettings<D>::EllipseAnimationEndPosition() const
{
    double value{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Primitives::IProgressBarTemplateSettings)->get_EllipseAnimationEndPosition(&value));
    return value;
}

template <typename D> double consume_Windows_UI_Xaml_Controls_Primitives_IProgressBarTemplateSettings<D>::ContainerAnimationStartPosition() const
{
    double value{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Primitives::IProgressBarTemplateSettings)->get_ContainerAnimationStartPosition(&value));
    return value;
}

template <typename D> double consume_Windows_UI_Xaml_Controls_Primitives_IProgressBarTemplateSettings<D>::ContainerAnimationEndPosition() const
{
    double value{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Primitives::IProgressBarTemplateSettings)->get_ContainerAnimationEndPosition(&value));
    return value;
}

template <typename D> double consume_Windows_UI_Xaml_Controls_Primitives_IProgressBarTemplateSettings<D>::IndicatorLengthDelta() const
{
    double value{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Primitives::IProgressBarTemplateSettings)->get_IndicatorLengthDelta(&value));
    return value;
}

template <typename D> double consume_Windows_UI_Xaml_Controls_Primitives_IProgressRingTemplateSettings<D>::EllipseDiameter() const
{
    double value{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Primitives::IProgressRingTemplateSettings)->get_EllipseDiameter(&value));
    return value;
}

template <typename D> Windows::UI::Xaml::Thickness consume_Windows_UI_Xaml_Controls_Primitives_IProgressRingTemplateSettings<D>::EllipseOffset() const
{
    Windows::UI::Xaml::Thickness value{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Primitives::IProgressRingTemplateSettings)->get_EllipseOffset(put_abi(value)));
    return value;
}

template <typename D> double consume_Windows_UI_Xaml_Controls_Primitives_IProgressRingTemplateSettings<D>::MaxSideLength() const
{
    double value{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Primitives::IProgressRingTemplateSettings)->get_MaxSideLength(&value));
    return value;
}

template <typename D> double consume_Windows_UI_Xaml_Controls_Primitives_IRangeBase<D>::Minimum() const
{
    double value{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Primitives::IRangeBase)->get_Minimum(&value));
    return value;
}

template <typename D> void consume_Windows_UI_Xaml_Controls_Primitives_IRangeBase<D>::Minimum(double value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Primitives::IRangeBase)->put_Minimum(value));
}

template <typename D> double consume_Windows_UI_Xaml_Controls_Primitives_IRangeBase<D>::Maximum() const
{
    double value{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Primitives::IRangeBase)->get_Maximum(&value));
    return value;
}

template <typename D> void consume_Windows_UI_Xaml_Controls_Primitives_IRangeBase<D>::Maximum(double value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Primitives::IRangeBase)->put_Maximum(value));
}

template <typename D> double consume_Windows_UI_Xaml_Controls_Primitives_IRangeBase<D>::SmallChange() const
{
    double value{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Primitives::IRangeBase)->get_SmallChange(&value));
    return value;
}

template <typename D> void consume_Windows_UI_Xaml_Controls_Primitives_IRangeBase<D>::SmallChange(double value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Primitives::IRangeBase)->put_SmallChange(value));
}

template <typename D> double consume_Windows_UI_Xaml_Controls_Primitives_IRangeBase<D>::LargeChange() const
{
    double value{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Primitives::IRangeBase)->get_LargeChange(&value));
    return value;
}

template <typename D> void consume_Windows_UI_Xaml_Controls_Primitives_IRangeBase<D>::LargeChange(double value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Primitives::IRangeBase)->put_LargeChange(value));
}

template <typename D> double consume_Windows_UI_Xaml_Controls_Primitives_IRangeBase<D>::Value() const
{
    double value{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Primitives::IRangeBase)->get_Value(&value));
    return value;
}

template <typename D> void consume_Windows_UI_Xaml_Controls_Primitives_IRangeBase<D>::Value(double value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Primitives::IRangeBase)->put_Value(value));
}

template <typename D> winrt::event_token consume_Windows_UI_Xaml_Controls_Primitives_IRangeBase<D>::ValueChanged(Windows::UI::Xaml::Controls::Primitives::RangeBaseValueChangedEventHandler const& handler) const
{
    winrt::event_token token{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Primitives::IRangeBase)->add_ValueChanged(get_abi(handler), put_abi(token)));
    return token;
}

template <typename D> typename consume_Windows_UI_Xaml_Controls_Primitives_IRangeBase<D>::ValueChanged_revoker consume_Windows_UI_Xaml_Controls_Primitives_IRangeBase<D>::ValueChanged(auto_revoke_t, Windows::UI::Xaml::Controls::Primitives::RangeBaseValueChangedEventHandler const& handler) const
{
    return impl::make_event_revoker<D, ValueChanged_revoker>(this, ValueChanged(handler));
}

template <typename D> void consume_Windows_UI_Xaml_Controls_Primitives_IRangeBase<D>::ValueChanged(winrt::event_token const& token) const noexcept
{
    WINRT_VERIFY_(0, WINRT_SHIM(Windows::UI::Xaml::Controls::Primitives::IRangeBase)->remove_ValueChanged(get_abi(token)));
}

template <typename D> Windows::UI::Xaml::Controls::Primitives::RangeBase consume_Windows_UI_Xaml_Controls_Primitives_IRangeBaseFactory<D>::CreateInstance(Windows::Foundation::IInspectable const& baseInterface, Windows::Foundation::IInspectable& innerInterface) const
{
    Windows::UI::Xaml::Controls::Primitives::RangeBase value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Primitives::IRangeBaseFactory)->CreateInstance(get_abi(baseInterface), put_abi(innerInterface), put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_UI_Xaml_Controls_Primitives_IRangeBaseOverrides<D>::OnMinimumChanged(double oldMinimum, double newMinimum) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Primitives::IRangeBaseOverrides)->OnMinimumChanged(oldMinimum, newMinimum));
}

template <typename D> void consume_Windows_UI_Xaml_Controls_Primitives_IRangeBaseOverrides<D>::OnMaximumChanged(double oldMaximum, double newMaximum) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Primitives::IRangeBaseOverrides)->OnMaximumChanged(oldMaximum, newMaximum));
}

template <typename D> void consume_Windows_UI_Xaml_Controls_Primitives_IRangeBaseOverrides<D>::OnValueChanged(double oldValue, double newValue) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Primitives::IRangeBaseOverrides)->OnValueChanged(oldValue, newValue));
}

template <typename D> Windows::UI::Xaml::DependencyProperty consume_Windows_UI_Xaml_Controls_Primitives_IRangeBaseStatics<D>::MinimumProperty() const
{
    Windows::UI::Xaml::DependencyProperty value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Primitives::IRangeBaseStatics)->get_MinimumProperty(put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Xaml::DependencyProperty consume_Windows_UI_Xaml_Controls_Primitives_IRangeBaseStatics<D>::MaximumProperty() const
{
    Windows::UI::Xaml::DependencyProperty value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Primitives::IRangeBaseStatics)->get_MaximumProperty(put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Xaml::DependencyProperty consume_Windows_UI_Xaml_Controls_Primitives_IRangeBaseStatics<D>::SmallChangeProperty() const
{
    Windows::UI::Xaml::DependencyProperty value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Primitives::IRangeBaseStatics)->get_SmallChangeProperty(put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Xaml::DependencyProperty consume_Windows_UI_Xaml_Controls_Primitives_IRangeBaseStatics<D>::LargeChangeProperty() const
{
    Windows::UI::Xaml::DependencyProperty value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Primitives::IRangeBaseStatics)->get_LargeChangeProperty(put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Xaml::DependencyProperty consume_Windows_UI_Xaml_Controls_Primitives_IRangeBaseStatics<D>::ValueProperty() const
{
    Windows::UI::Xaml::DependencyProperty value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Primitives::IRangeBaseStatics)->get_ValueProperty(put_abi(value)));
    return value;
}

template <typename D> double consume_Windows_UI_Xaml_Controls_Primitives_IRangeBaseValueChangedEventArgs<D>::OldValue() const
{
    double value{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Primitives::IRangeBaseValueChangedEventArgs)->get_OldValue(&value));
    return value;
}

template <typename D> double consume_Windows_UI_Xaml_Controls_Primitives_IRangeBaseValueChangedEventArgs<D>::NewValue() const
{
    double value{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Primitives::IRangeBaseValueChangedEventArgs)->get_NewValue(&value));
    return value;
}

template <typename D> int32_t consume_Windows_UI_Xaml_Controls_Primitives_IRepeatButton<D>::Delay() const
{
    int32_t value{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Primitives::IRepeatButton)->get_Delay(&value));
    return value;
}

template <typename D> void consume_Windows_UI_Xaml_Controls_Primitives_IRepeatButton<D>::Delay(int32_t value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Primitives::IRepeatButton)->put_Delay(value));
}

template <typename D> int32_t consume_Windows_UI_Xaml_Controls_Primitives_IRepeatButton<D>::Interval() const
{
    int32_t value{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Primitives::IRepeatButton)->get_Interval(&value));
    return value;
}

template <typename D> void consume_Windows_UI_Xaml_Controls_Primitives_IRepeatButton<D>::Interval(int32_t value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Primitives::IRepeatButton)->put_Interval(value));
}

template <typename D> Windows::UI::Xaml::DependencyProperty consume_Windows_UI_Xaml_Controls_Primitives_IRepeatButtonStatics<D>::DelayProperty() const
{
    Windows::UI::Xaml::DependencyProperty value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Primitives::IRepeatButtonStatics)->get_DelayProperty(put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Xaml::DependencyProperty consume_Windows_UI_Xaml_Controls_Primitives_IRepeatButtonStatics<D>::IntervalProperty() const
{
    Windows::UI::Xaml::DependencyProperty value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Primitives::IRepeatButtonStatics)->get_IntervalProperty(put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Xaml::Controls::Orientation consume_Windows_UI_Xaml_Controls_Primitives_IScrollBar<D>::Orientation() const
{
    Windows::UI::Xaml::Controls::Orientation value{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Primitives::IScrollBar)->get_Orientation(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_UI_Xaml_Controls_Primitives_IScrollBar<D>::Orientation(Windows::UI::Xaml::Controls::Orientation const& value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Primitives::IScrollBar)->put_Orientation(get_abi(value)));
}

template <typename D> double consume_Windows_UI_Xaml_Controls_Primitives_IScrollBar<D>::ViewportSize() const
{
    double value{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Primitives::IScrollBar)->get_ViewportSize(&value));
    return value;
}

template <typename D> void consume_Windows_UI_Xaml_Controls_Primitives_IScrollBar<D>::ViewportSize(double value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Primitives::IScrollBar)->put_ViewportSize(value));
}

template <typename D> Windows::UI::Xaml::Controls::Primitives::ScrollingIndicatorMode consume_Windows_UI_Xaml_Controls_Primitives_IScrollBar<D>::IndicatorMode() const
{
    Windows::UI::Xaml::Controls::Primitives::ScrollingIndicatorMode value{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Primitives::IScrollBar)->get_IndicatorMode(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_UI_Xaml_Controls_Primitives_IScrollBar<D>::IndicatorMode(Windows::UI::Xaml::Controls::Primitives::ScrollingIndicatorMode const& value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Primitives::IScrollBar)->put_IndicatorMode(get_abi(value)));
}

template <typename D> winrt::event_token consume_Windows_UI_Xaml_Controls_Primitives_IScrollBar<D>::Scroll(Windows::UI::Xaml::Controls::Primitives::ScrollEventHandler const& handler) const
{
    winrt::event_token token{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Primitives::IScrollBar)->add_Scroll(get_abi(handler), put_abi(token)));
    return token;
}

template <typename D> typename consume_Windows_UI_Xaml_Controls_Primitives_IScrollBar<D>::Scroll_revoker consume_Windows_UI_Xaml_Controls_Primitives_IScrollBar<D>::Scroll(auto_revoke_t, Windows::UI::Xaml::Controls::Primitives::ScrollEventHandler const& handler) const
{
    return impl::make_event_revoker<D, Scroll_revoker>(this, Scroll(handler));
}

template <typename D> void consume_Windows_UI_Xaml_Controls_Primitives_IScrollBar<D>::Scroll(winrt::event_token const& token) const noexcept
{
    WINRT_VERIFY_(0, WINRT_SHIM(Windows::UI::Xaml::Controls::Primitives::IScrollBar)->remove_Scroll(get_abi(token)));
}

template <typename D> Windows::UI::Xaml::DependencyProperty consume_Windows_UI_Xaml_Controls_Primitives_IScrollBarStatics<D>::OrientationProperty() const
{
    Windows::UI::Xaml::DependencyProperty value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Primitives::IScrollBarStatics)->get_OrientationProperty(put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Xaml::DependencyProperty consume_Windows_UI_Xaml_Controls_Primitives_IScrollBarStatics<D>::ViewportSizeProperty() const
{
    Windows::UI::Xaml::DependencyProperty value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Primitives::IScrollBarStatics)->get_ViewportSizeProperty(put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Xaml::DependencyProperty consume_Windows_UI_Xaml_Controls_Primitives_IScrollBarStatics<D>::IndicatorModeProperty() const
{
    Windows::UI::Xaml::DependencyProperty value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Primitives::IScrollBarStatics)->get_IndicatorModeProperty(put_abi(value)));
    return value;
}

template <typename D> double consume_Windows_UI_Xaml_Controls_Primitives_IScrollEventArgs<D>::NewValue() const
{
    double value{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Primitives::IScrollEventArgs)->get_NewValue(&value));
    return value;
}

template <typename D> Windows::UI::Xaml::Controls::Primitives::ScrollEventType consume_Windows_UI_Xaml_Controls_Primitives_IScrollEventArgs<D>::ScrollEventType() const
{
    Windows::UI::Xaml::Controls::Primitives::ScrollEventType value{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Primitives::IScrollEventArgs)->get_ScrollEventType(put_abi(value)));
    return value;
}

template <typename D> bool consume_Windows_UI_Xaml_Controls_Primitives_IScrollSnapPointsInfo<D>::AreHorizontalSnapPointsRegular() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Primitives::IScrollSnapPointsInfo)->get_AreHorizontalSnapPointsRegular(&value));
    return value;
}

template <typename D> bool consume_Windows_UI_Xaml_Controls_Primitives_IScrollSnapPointsInfo<D>::AreVerticalSnapPointsRegular() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Primitives::IScrollSnapPointsInfo)->get_AreVerticalSnapPointsRegular(&value));
    return value;
}

template <typename D> winrt::event_token consume_Windows_UI_Xaml_Controls_Primitives_IScrollSnapPointsInfo<D>::HorizontalSnapPointsChanged(Windows::Foundation::EventHandler<Windows::Foundation::IInspectable> const& handler) const
{
    winrt::event_token token{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Primitives::IScrollSnapPointsInfo)->add_HorizontalSnapPointsChanged(get_abi(handler), put_abi(token)));
    return token;
}

template <typename D> typename consume_Windows_UI_Xaml_Controls_Primitives_IScrollSnapPointsInfo<D>::HorizontalSnapPointsChanged_revoker consume_Windows_UI_Xaml_Controls_Primitives_IScrollSnapPointsInfo<D>::HorizontalSnapPointsChanged(auto_revoke_t, Windows::Foundation::EventHandler<Windows::Foundation::IInspectable> const& handler) const
{
    return impl::make_event_revoker<D, HorizontalSnapPointsChanged_revoker>(this, HorizontalSnapPointsChanged(handler));
}

template <typename D> void consume_Windows_UI_Xaml_Controls_Primitives_IScrollSnapPointsInfo<D>::HorizontalSnapPointsChanged(winrt::event_token const& token) const noexcept
{
    WINRT_VERIFY_(0, WINRT_SHIM(Windows::UI::Xaml::Controls::Primitives::IScrollSnapPointsInfo)->remove_HorizontalSnapPointsChanged(get_abi(token)));
}

template <typename D> winrt::event_token consume_Windows_UI_Xaml_Controls_Primitives_IScrollSnapPointsInfo<D>::VerticalSnapPointsChanged(Windows::Foundation::EventHandler<Windows::Foundation::IInspectable> const& handler) const
{
    winrt::event_token token{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Primitives::IScrollSnapPointsInfo)->add_VerticalSnapPointsChanged(get_abi(handler), put_abi(token)));
    return token;
}

template <typename D> typename consume_Windows_UI_Xaml_Controls_Primitives_IScrollSnapPointsInfo<D>::VerticalSnapPointsChanged_revoker consume_Windows_UI_Xaml_Controls_Primitives_IScrollSnapPointsInfo<D>::VerticalSnapPointsChanged(auto_revoke_t, Windows::Foundation::EventHandler<Windows::Foundation::IInspectable> const& handler) const
{
    return impl::make_event_revoker<D, VerticalSnapPointsChanged_revoker>(this, VerticalSnapPointsChanged(handler));
}

template <typename D> void consume_Windows_UI_Xaml_Controls_Primitives_IScrollSnapPointsInfo<D>::VerticalSnapPointsChanged(winrt::event_token const& token) const noexcept
{
    WINRT_VERIFY_(0, WINRT_SHIM(Windows::UI::Xaml::Controls::Primitives::IScrollSnapPointsInfo)->remove_VerticalSnapPointsChanged(get_abi(token)));
}

template <typename D> Windows::Foundation::Collections::IVectorView<float> consume_Windows_UI_Xaml_Controls_Primitives_IScrollSnapPointsInfo<D>::GetIrregularSnapPoints(Windows::UI::Xaml::Controls::Orientation const& orientation, Windows::UI::Xaml::Controls::Primitives::SnapPointsAlignment const& alignment) const
{
    Windows::Foundation::Collections::IVectorView<float> result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Primitives::IScrollSnapPointsInfo)->GetIrregularSnapPoints(get_abi(orientation), get_abi(alignment), put_abi(result)));
    return result;
}

template <typename D> float consume_Windows_UI_Xaml_Controls_Primitives_IScrollSnapPointsInfo<D>::GetRegularSnapPoints(Windows::UI::Xaml::Controls::Orientation const& orientation, Windows::UI::Xaml::Controls::Primitives::SnapPointsAlignment const& alignment, float& offset) const
{
    float returnValue{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Primitives::IScrollSnapPointsInfo)->GetRegularSnapPoints(get_abi(orientation), get_abi(alignment), &offset, &returnValue));
    return returnValue;
}

template <typename D> int32_t consume_Windows_UI_Xaml_Controls_Primitives_ISelector<D>::SelectedIndex() const
{
    int32_t value{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Primitives::ISelector)->get_SelectedIndex(&value));
    return value;
}

template <typename D> void consume_Windows_UI_Xaml_Controls_Primitives_ISelector<D>::SelectedIndex(int32_t value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Primitives::ISelector)->put_SelectedIndex(value));
}

template <typename D> Windows::Foundation::IInspectable consume_Windows_UI_Xaml_Controls_Primitives_ISelector<D>::SelectedItem() const
{
    Windows::Foundation::IInspectable value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Primitives::ISelector)->get_SelectedItem(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_UI_Xaml_Controls_Primitives_ISelector<D>::SelectedItem(Windows::Foundation::IInspectable const& value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Primitives::ISelector)->put_SelectedItem(get_abi(value)));
}

template <typename D> Windows::Foundation::IInspectable consume_Windows_UI_Xaml_Controls_Primitives_ISelector<D>::SelectedValue() const
{
    Windows::Foundation::IInspectable value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Primitives::ISelector)->get_SelectedValue(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_UI_Xaml_Controls_Primitives_ISelector<D>::SelectedValue(Windows::Foundation::IInspectable const& value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Primitives::ISelector)->put_SelectedValue(get_abi(value)));
}

template <typename D> hstring consume_Windows_UI_Xaml_Controls_Primitives_ISelector<D>::SelectedValuePath() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Primitives::ISelector)->get_SelectedValuePath(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_UI_Xaml_Controls_Primitives_ISelector<D>::SelectedValuePath(param::hstring const& value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Primitives::ISelector)->put_SelectedValuePath(get_abi(value)));
}

template <typename D> Windows::Foundation::IReference<bool> consume_Windows_UI_Xaml_Controls_Primitives_ISelector<D>::IsSynchronizedWithCurrentItem() const
{
    Windows::Foundation::IReference<bool> value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Primitives::ISelector)->get_IsSynchronizedWithCurrentItem(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_UI_Xaml_Controls_Primitives_ISelector<D>::IsSynchronizedWithCurrentItem(optional<bool> const& value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Primitives::ISelector)->put_IsSynchronizedWithCurrentItem(get_abi(value)));
}

template <typename D> winrt::event_token consume_Windows_UI_Xaml_Controls_Primitives_ISelector<D>::SelectionChanged(Windows::UI::Xaml::Controls::SelectionChangedEventHandler const& handler) const
{
    winrt::event_token token{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Primitives::ISelector)->add_SelectionChanged(get_abi(handler), put_abi(token)));
    return token;
}

template <typename D> typename consume_Windows_UI_Xaml_Controls_Primitives_ISelector<D>::SelectionChanged_revoker consume_Windows_UI_Xaml_Controls_Primitives_ISelector<D>::SelectionChanged(auto_revoke_t, Windows::UI::Xaml::Controls::SelectionChangedEventHandler const& handler) const
{
    return impl::make_event_revoker<D, SelectionChanged_revoker>(this, SelectionChanged(handler));
}

template <typename D> void consume_Windows_UI_Xaml_Controls_Primitives_ISelector<D>::SelectionChanged(winrt::event_token const& token) const noexcept
{
    WINRT_VERIFY_(0, WINRT_SHIM(Windows::UI::Xaml::Controls::Primitives::ISelector)->remove_SelectionChanged(get_abi(token)));
}

template <typename D> bool consume_Windows_UI_Xaml_Controls_Primitives_ISelectorItem<D>::IsSelected() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Primitives::ISelectorItem)->get_IsSelected(&value));
    return value;
}

template <typename D> void consume_Windows_UI_Xaml_Controls_Primitives_ISelectorItem<D>::IsSelected(bool value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Primitives::ISelectorItem)->put_IsSelected(value));
}

template <typename D> Windows::UI::Xaml::Controls::Primitives::SelectorItem consume_Windows_UI_Xaml_Controls_Primitives_ISelectorItemFactory<D>::CreateInstance(Windows::Foundation::IInspectable const& baseInterface, Windows::Foundation::IInspectable& innerInterface) const
{
    Windows::UI::Xaml::Controls::Primitives::SelectorItem value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Primitives::ISelectorItemFactory)->CreateInstance(get_abi(baseInterface), put_abi(innerInterface), put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Xaml::DependencyProperty consume_Windows_UI_Xaml_Controls_Primitives_ISelectorItemStatics<D>::IsSelectedProperty() const
{
    Windows::UI::Xaml::DependencyProperty value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Primitives::ISelectorItemStatics)->get_IsSelectedProperty(put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Xaml::DependencyProperty consume_Windows_UI_Xaml_Controls_Primitives_ISelectorStatics<D>::SelectedIndexProperty() const
{
    Windows::UI::Xaml::DependencyProperty value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Primitives::ISelectorStatics)->get_SelectedIndexProperty(put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Xaml::DependencyProperty consume_Windows_UI_Xaml_Controls_Primitives_ISelectorStatics<D>::SelectedItemProperty() const
{
    Windows::UI::Xaml::DependencyProperty value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Primitives::ISelectorStatics)->get_SelectedItemProperty(put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Xaml::DependencyProperty consume_Windows_UI_Xaml_Controls_Primitives_ISelectorStatics<D>::SelectedValueProperty() const
{
    Windows::UI::Xaml::DependencyProperty value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Primitives::ISelectorStatics)->get_SelectedValueProperty(put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Xaml::DependencyProperty consume_Windows_UI_Xaml_Controls_Primitives_ISelectorStatics<D>::SelectedValuePathProperty() const
{
    Windows::UI::Xaml::DependencyProperty value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Primitives::ISelectorStatics)->get_SelectedValuePathProperty(put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Xaml::DependencyProperty consume_Windows_UI_Xaml_Controls_Primitives_ISelectorStatics<D>::IsSynchronizedWithCurrentItemProperty() const
{
    Windows::UI::Xaml::DependencyProperty value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Primitives::ISelectorStatics)->get_IsSynchronizedWithCurrentItemProperty(put_abi(value)));
    return value;
}

template <typename D> bool consume_Windows_UI_Xaml_Controls_Primitives_ISelectorStatics<D>::GetIsSelectionActive(Windows::UI::Xaml::DependencyObject const& element) const
{
    bool result{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Primitives::ISelectorStatics)->GetIsSelectionActive(get_abi(element), &result));
    return result;
}

template <typename D> Windows::UI::Xaml::Media::Brush consume_Windows_UI_Xaml_Controls_Primitives_ISettingsFlyoutTemplateSettings<D>::HeaderBackground() const
{
    Windows::UI::Xaml::Media::Brush value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Primitives::ISettingsFlyoutTemplateSettings)->get_HeaderBackground(put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Xaml::Media::Brush consume_Windows_UI_Xaml_Controls_Primitives_ISettingsFlyoutTemplateSettings<D>::HeaderForeground() const
{
    Windows::UI::Xaml::Media::Brush value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Primitives::ISettingsFlyoutTemplateSettings)->get_HeaderForeground(put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Xaml::Media::Brush consume_Windows_UI_Xaml_Controls_Primitives_ISettingsFlyoutTemplateSettings<D>::BorderBrush() const
{
    Windows::UI::Xaml::Media::Brush value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Primitives::ISettingsFlyoutTemplateSettings)->get_BorderBrush(put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Xaml::Thickness consume_Windows_UI_Xaml_Controls_Primitives_ISettingsFlyoutTemplateSettings<D>::BorderThickness() const
{
    Windows::UI::Xaml::Thickness value{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Primitives::ISettingsFlyoutTemplateSettings)->get_BorderThickness(put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Xaml::Media::ImageSource consume_Windows_UI_Xaml_Controls_Primitives_ISettingsFlyoutTemplateSettings<D>::IconSource() const
{
    Windows::UI::Xaml::Media::ImageSource value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Primitives::ISettingsFlyoutTemplateSettings)->get_IconSource(put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Xaml::Media::Animation::TransitionCollection consume_Windows_UI_Xaml_Controls_Primitives_ISettingsFlyoutTemplateSettings<D>::ContentTransitions() const
{
    Windows::UI::Xaml::Media::Animation::TransitionCollection value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Primitives::ISettingsFlyoutTemplateSettings)->get_ContentTransitions(put_abi(value)));
    return value;
}

template <typename D> double consume_Windows_UI_Xaml_Controls_Primitives_ISplitViewTemplateSettings<D>::OpenPaneLength() const
{
    double value{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Primitives::ISplitViewTemplateSettings)->get_OpenPaneLength(&value));
    return value;
}

template <typename D> double consume_Windows_UI_Xaml_Controls_Primitives_ISplitViewTemplateSettings<D>::NegativeOpenPaneLength() const
{
    double value{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Primitives::ISplitViewTemplateSettings)->get_NegativeOpenPaneLength(&value));
    return value;
}

template <typename D> double consume_Windows_UI_Xaml_Controls_Primitives_ISplitViewTemplateSettings<D>::OpenPaneLengthMinusCompactLength() const
{
    double value{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Primitives::ISplitViewTemplateSettings)->get_OpenPaneLengthMinusCompactLength(&value));
    return value;
}

template <typename D> double consume_Windows_UI_Xaml_Controls_Primitives_ISplitViewTemplateSettings<D>::NegativeOpenPaneLengthMinusCompactLength() const
{
    double value{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Primitives::ISplitViewTemplateSettings)->get_NegativeOpenPaneLengthMinusCompactLength(&value));
    return value;
}

template <typename D> Windows::UI::Xaml::GridLength consume_Windows_UI_Xaml_Controls_Primitives_ISplitViewTemplateSettings<D>::OpenPaneGridLength() const
{
    Windows::UI::Xaml::GridLength value{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Primitives::ISplitViewTemplateSettings)->get_OpenPaneGridLength(put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Xaml::GridLength consume_Windows_UI_Xaml_Controls_Primitives_ISplitViewTemplateSettings<D>::CompactPaneGridLength() const
{
    Windows::UI::Xaml::GridLength value{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Primitives::ISplitViewTemplateSettings)->get_CompactPaneGridLength(put_abi(value)));
    return value;
}

template <typename D> bool consume_Windows_UI_Xaml_Controls_Primitives_IThumb<D>::IsDragging() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Primitives::IThumb)->get_IsDragging(&value));
    return value;
}

template <typename D> winrt::event_token consume_Windows_UI_Xaml_Controls_Primitives_IThumb<D>::DragStarted(Windows::UI::Xaml::Controls::Primitives::DragStartedEventHandler const& handler) const
{
    winrt::event_token token{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Primitives::IThumb)->add_DragStarted(get_abi(handler), put_abi(token)));
    return token;
}

template <typename D> typename consume_Windows_UI_Xaml_Controls_Primitives_IThumb<D>::DragStarted_revoker consume_Windows_UI_Xaml_Controls_Primitives_IThumb<D>::DragStarted(auto_revoke_t, Windows::UI::Xaml::Controls::Primitives::DragStartedEventHandler const& handler) const
{
    return impl::make_event_revoker<D, DragStarted_revoker>(this, DragStarted(handler));
}

template <typename D> void consume_Windows_UI_Xaml_Controls_Primitives_IThumb<D>::DragStarted(winrt::event_token const& token) const noexcept
{
    WINRT_VERIFY_(0, WINRT_SHIM(Windows::UI::Xaml::Controls::Primitives::IThumb)->remove_DragStarted(get_abi(token)));
}

template <typename D> winrt::event_token consume_Windows_UI_Xaml_Controls_Primitives_IThumb<D>::DragDelta(Windows::UI::Xaml::Controls::Primitives::DragDeltaEventHandler const& handler) const
{
    winrt::event_token token{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Primitives::IThumb)->add_DragDelta(get_abi(handler), put_abi(token)));
    return token;
}

template <typename D> typename consume_Windows_UI_Xaml_Controls_Primitives_IThumb<D>::DragDelta_revoker consume_Windows_UI_Xaml_Controls_Primitives_IThumb<D>::DragDelta(auto_revoke_t, Windows::UI::Xaml::Controls::Primitives::DragDeltaEventHandler const& handler) const
{
    return impl::make_event_revoker<D, DragDelta_revoker>(this, DragDelta(handler));
}

template <typename D> void consume_Windows_UI_Xaml_Controls_Primitives_IThumb<D>::DragDelta(winrt::event_token const& token) const noexcept
{
    WINRT_VERIFY_(0, WINRT_SHIM(Windows::UI::Xaml::Controls::Primitives::IThumb)->remove_DragDelta(get_abi(token)));
}

template <typename D> winrt::event_token consume_Windows_UI_Xaml_Controls_Primitives_IThumb<D>::DragCompleted(Windows::UI::Xaml::Controls::Primitives::DragCompletedEventHandler const& handler) const
{
    winrt::event_token token{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Primitives::IThumb)->add_DragCompleted(get_abi(handler), put_abi(token)));
    return token;
}

template <typename D> typename consume_Windows_UI_Xaml_Controls_Primitives_IThumb<D>::DragCompleted_revoker consume_Windows_UI_Xaml_Controls_Primitives_IThumb<D>::DragCompleted(auto_revoke_t, Windows::UI::Xaml::Controls::Primitives::DragCompletedEventHandler const& handler) const
{
    return impl::make_event_revoker<D, DragCompleted_revoker>(this, DragCompleted(handler));
}

template <typename D> void consume_Windows_UI_Xaml_Controls_Primitives_IThumb<D>::DragCompleted(winrt::event_token const& token) const noexcept
{
    WINRT_VERIFY_(0, WINRT_SHIM(Windows::UI::Xaml::Controls::Primitives::IThumb)->remove_DragCompleted(get_abi(token)));
}

template <typename D> void consume_Windows_UI_Xaml_Controls_Primitives_IThumb<D>::CancelDrag() const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Primitives::IThumb)->CancelDrag());
}

template <typename D> Windows::UI::Xaml::DependencyProperty consume_Windows_UI_Xaml_Controls_Primitives_IThumbStatics<D>::IsDraggingProperty() const
{
    Windows::UI::Xaml::DependencyProperty value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Primitives::IThumbStatics)->get_IsDraggingProperty(put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Xaml::Media::Brush consume_Windows_UI_Xaml_Controls_Primitives_ITickBar<D>::Fill() const
{
    Windows::UI::Xaml::Media::Brush value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Primitives::ITickBar)->get_Fill(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_UI_Xaml_Controls_Primitives_ITickBar<D>::Fill(Windows::UI::Xaml::Media::Brush const& value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Primitives::ITickBar)->put_Fill(get_abi(value)));
}

template <typename D> Windows::UI::Xaml::DependencyProperty consume_Windows_UI_Xaml_Controls_Primitives_ITickBarStatics<D>::FillProperty() const
{
    Windows::UI::Xaml::DependencyProperty value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Primitives::ITickBarStatics)->get_FillProperty(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::IReference<bool> consume_Windows_UI_Xaml_Controls_Primitives_IToggleButton<D>::IsChecked() const
{
    Windows::Foundation::IReference<bool> value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Primitives::IToggleButton)->get_IsChecked(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_UI_Xaml_Controls_Primitives_IToggleButton<D>::IsChecked(optional<bool> const& value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Primitives::IToggleButton)->put_IsChecked(get_abi(value)));
}

template <typename D> bool consume_Windows_UI_Xaml_Controls_Primitives_IToggleButton<D>::IsThreeState() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Primitives::IToggleButton)->get_IsThreeState(&value));
    return value;
}

template <typename D> void consume_Windows_UI_Xaml_Controls_Primitives_IToggleButton<D>::IsThreeState(bool value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Primitives::IToggleButton)->put_IsThreeState(value));
}

template <typename D> winrt::event_token consume_Windows_UI_Xaml_Controls_Primitives_IToggleButton<D>::Checked(Windows::UI::Xaml::RoutedEventHandler const& handler) const
{
    winrt::event_token token{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Primitives::IToggleButton)->add_Checked(get_abi(handler), put_abi(token)));
    return token;
}

template <typename D> typename consume_Windows_UI_Xaml_Controls_Primitives_IToggleButton<D>::Checked_revoker consume_Windows_UI_Xaml_Controls_Primitives_IToggleButton<D>::Checked(auto_revoke_t, Windows::UI::Xaml::RoutedEventHandler const& handler) const
{
    return impl::make_event_revoker<D, Checked_revoker>(this, Checked(handler));
}

template <typename D> void consume_Windows_UI_Xaml_Controls_Primitives_IToggleButton<D>::Checked(winrt::event_token const& token) const noexcept
{
    WINRT_VERIFY_(0, WINRT_SHIM(Windows::UI::Xaml::Controls::Primitives::IToggleButton)->remove_Checked(get_abi(token)));
}

template <typename D> winrt::event_token consume_Windows_UI_Xaml_Controls_Primitives_IToggleButton<D>::Unchecked(Windows::UI::Xaml::RoutedEventHandler const& handler) const
{
    winrt::event_token token{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Primitives::IToggleButton)->add_Unchecked(get_abi(handler), put_abi(token)));
    return token;
}

template <typename D> typename consume_Windows_UI_Xaml_Controls_Primitives_IToggleButton<D>::Unchecked_revoker consume_Windows_UI_Xaml_Controls_Primitives_IToggleButton<D>::Unchecked(auto_revoke_t, Windows::UI::Xaml::RoutedEventHandler const& handler) const
{
    return impl::make_event_revoker<D, Unchecked_revoker>(this, Unchecked(handler));
}

template <typename D> void consume_Windows_UI_Xaml_Controls_Primitives_IToggleButton<D>::Unchecked(winrt::event_token const& token) const noexcept
{
    WINRT_VERIFY_(0, WINRT_SHIM(Windows::UI::Xaml::Controls::Primitives::IToggleButton)->remove_Unchecked(get_abi(token)));
}

template <typename D> winrt::event_token consume_Windows_UI_Xaml_Controls_Primitives_IToggleButton<D>::Indeterminate(Windows::UI::Xaml::RoutedEventHandler const& handler) const
{
    winrt::event_token token{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Primitives::IToggleButton)->add_Indeterminate(get_abi(handler), put_abi(token)));
    return token;
}

template <typename D> typename consume_Windows_UI_Xaml_Controls_Primitives_IToggleButton<D>::Indeterminate_revoker consume_Windows_UI_Xaml_Controls_Primitives_IToggleButton<D>::Indeterminate(auto_revoke_t, Windows::UI::Xaml::RoutedEventHandler const& handler) const
{
    return impl::make_event_revoker<D, Indeterminate_revoker>(this, Indeterminate(handler));
}

template <typename D> void consume_Windows_UI_Xaml_Controls_Primitives_IToggleButton<D>::Indeterminate(winrt::event_token const& token) const noexcept
{
    WINRT_VERIFY_(0, WINRT_SHIM(Windows::UI::Xaml::Controls::Primitives::IToggleButton)->remove_Indeterminate(get_abi(token)));
}

template <typename D> Windows::UI::Xaml::Controls::Primitives::ToggleButton consume_Windows_UI_Xaml_Controls_Primitives_IToggleButtonFactory<D>::CreateInstance(Windows::Foundation::IInspectable const& baseInterface, Windows::Foundation::IInspectable& innerInterface) const
{
    Windows::UI::Xaml::Controls::Primitives::ToggleButton value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Primitives::IToggleButtonFactory)->CreateInstance(get_abi(baseInterface), put_abi(innerInterface), put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_UI_Xaml_Controls_Primitives_IToggleButtonOverrides<D>::OnToggle() const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Primitives::IToggleButtonOverrides)->OnToggle());
}

template <typename D> Windows::UI::Xaml::DependencyProperty consume_Windows_UI_Xaml_Controls_Primitives_IToggleButtonStatics<D>::IsCheckedProperty() const
{
    Windows::UI::Xaml::DependencyProperty value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Primitives::IToggleButtonStatics)->get_IsCheckedProperty(put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Xaml::DependencyProperty consume_Windows_UI_Xaml_Controls_Primitives_IToggleButtonStatics<D>::IsThreeStateProperty() const
{
    Windows::UI::Xaml::DependencyProperty value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Primitives::IToggleButtonStatics)->get_IsThreeStateProperty(put_abi(value)));
    return value;
}

template <typename D> double consume_Windows_UI_Xaml_Controls_Primitives_IToggleSwitchTemplateSettings<D>::KnobCurrentToOnOffset() const
{
    double value{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Primitives::IToggleSwitchTemplateSettings)->get_KnobCurrentToOnOffset(&value));
    return value;
}

template <typename D> double consume_Windows_UI_Xaml_Controls_Primitives_IToggleSwitchTemplateSettings<D>::KnobCurrentToOffOffset() const
{
    double value{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Primitives::IToggleSwitchTemplateSettings)->get_KnobCurrentToOffOffset(&value));
    return value;
}

template <typename D> double consume_Windows_UI_Xaml_Controls_Primitives_IToggleSwitchTemplateSettings<D>::KnobOnToOffOffset() const
{
    double value{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Primitives::IToggleSwitchTemplateSettings)->get_KnobOnToOffOffset(&value));
    return value;
}

template <typename D> double consume_Windows_UI_Xaml_Controls_Primitives_IToggleSwitchTemplateSettings<D>::KnobOffToOnOffset() const
{
    double value{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Primitives::IToggleSwitchTemplateSettings)->get_KnobOffToOnOffset(&value));
    return value;
}

template <typename D> double consume_Windows_UI_Xaml_Controls_Primitives_IToggleSwitchTemplateSettings<D>::CurtainCurrentToOnOffset() const
{
    double value{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Primitives::IToggleSwitchTemplateSettings)->get_CurtainCurrentToOnOffset(&value));
    return value;
}

template <typename D> double consume_Windows_UI_Xaml_Controls_Primitives_IToggleSwitchTemplateSettings<D>::CurtainCurrentToOffOffset() const
{
    double value{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Primitives::IToggleSwitchTemplateSettings)->get_CurtainCurrentToOffOffset(&value));
    return value;
}

template <typename D> double consume_Windows_UI_Xaml_Controls_Primitives_IToggleSwitchTemplateSettings<D>::CurtainOnToOffOffset() const
{
    double value{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Primitives::IToggleSwitchTemplateSettings)->get_CurtainOnToOffOffset(&value));
    return value;
}

template <typename D> double consume_Windows_UI_Xaml_Controls_Primitives_IToggleSwitchTemplateSettings<D>::CurtainOffToOnOffset() const
{
    double value{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Primitives::IToggleSwitchTemplateSettings)->get_CurtainOffToOnOffset(&value));
    return value;
}

template <typename D> double consume_Windows_UI_Xaml_Controls_Primitives_IToolTipTemplateSettings<D>::FromHorizontalOffset() const
{
    double value{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Primitives::IToolTipTemplateSettings)->get_FromHorizontalOffset(&value));
    return value;
}

template <typename D> double consume_Windows_UI_Xaml_Controls_Primitives_IToolTipTemplateSettings<D>::FromVerticalOffset() const
{
    double value{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Primitives::IToolTipTemplateSettings)->get_FromVerticalOffset(&value));
    return value;
}

template <> struct delegate<Windows::UI::Xaml::Controls::Primitives::DragCompletedEventHandler>
{
    template <typename H>
    struct type : implements_delegate<Windows::UI::Xaml::Controls::Primitives::DragCompletedEventHandler, H>
    {
        type(H&& handler) : implements_delegate<Windows::UI::Xaml::Controls::Primitives::DragCompletedEventHandler, H>(std::forward<H>(handler)) {}

        int32_t WINRT_CALL Invoke(void* sender, void* e) noexcept final
        {
            try
            {
                (*this)(*reinterpret_cast<Windows::Foundation::IInspectable const*>(&sender), *reinterpret_cast<Windows::UI::Xaml::Controls::Primitives::DragCompletedEventArgs const*>(&e));
                return 0;
            }
            catch (...)
            {
                return to_hresult();
            }
        }
    };
};

template <> struct delegate<Windows::UI::Xaml::Controls::Primitives::DragDeltaEventHandler>
{
    template <typename H>
    struct type : implements_delegate<Windows::UI::Xaml::Controls::Primitives::DragDeltaEventHandler, H>
    {
        type(H&& handler) : implements_delegate<Windows::UI::Xaml::Controls::Primitives::DragDeltaEventHandler, H>(std::forward<H>(handler)) {}

        int32_t WINRT_CALL Invoke(void* sender, void* e) noexcept final
        {
            try
            {
                (*this)(*reinterpret_cast<Windows::Foundation::IInspectable const*>(&sender), *reinterpret_cast<Windows::UI::Xaml::Controls::Primitives::DragDeltaEventArgs const*>(&e));
                return 0;
            }
            catch (...)
            {
                return to_hresult();
            }
        }
    };
};

template <> struct delegate<Windows::UI::Xaml::Controls::Primitives::DragStartedEventHandler>
{
    template <typename H>
    struct type : implements_delegate<Windows::UI::Xaml::Controls::Primitives::DragStartedEventHandler, H>
    {
        type(H&& handler) : implements_delegate<Windows::UI::Xaml::Controls::Primitives::DragStartedEventHandler, H>(std::forward<H>(handler)) {}

        int32_t WINRT_CALL Invoke(void* sender, void* e) noexcept final
        {
            try
            {
                (*this)(*reinterpret_cast<Windows::Foundation::IInspectable const*>(&sender), *reinterpret_cast<Windows::UI::Xaml::Controls::Primitives::DragStartedEventArgs const*>(&e));
                return 0;
            }
            catch (...)
            {
                return to_hresult();
            }
        }
    };
};

template <> struct delegate<Windows::UI::Xaml::Controls::Primitives::ItemsChangedEventHandler>
{
    template <typename H>
    struct type : implements_delegate<Windows::UI::Xaml::Controls::Primitives::ItemsChangedEventHandler, H>
    {
        type(H&& handler) : implements_delegate<Windows::UI::Xaml::Controls::Primitives::ItemsChangedEventHandler, H>(std::forward<H>(handler)) {}

        int32_t WINRT_CALL Invoke(void* sender, void* e) noexcept final
        {
            try
            {
                (*this)(*reinterpret_cast<Windows::Foundation::IInspectable const*>(&sender), *reinterpret_cast<Windows::UI::Xaml::Controls::Primitives::ItemsChangedEventArgs const*>(&e));
                return 0;
            }
            catch (...)
            {
                return to_hresult();
            }
        }
    };
};

template <> struct delegate<Windows::UI::Xaml::Controls::Primitives::RangeBaseValueChangedEventHandler>
{
    template <typename H>
    struct type : implements_delegate<Windows::UI::Xaml::Controls::Primitives::RangeBaseValueChangedEventHandler, H>
    {
        type(H&& handler) : implements_delegate<Windows::UI::Xaml::Controls::Primitives::RangeBaseValueChangedEventHandler, H>(std::forward<H>(handler)) {}

        int32_t WINRT_CALL Invoke(void* sender, void* e) noexcept final
        {
            try
            {
                (*this)(*reinterpret_cast<Windows::Foundation::IInspectable const*>(&sender), *reinterpret_cast<Windows::UI::Xaml::Controls::Primitives::RangeBaseValueChangedEventArgs const*>(&e));
                return 0;
            }
            catch (...)
            {
                return to_hresult();
            }
        }
    };
};

template <> struct delegate<Windows::UI::Xaml::Controls::Primitives::ScrollEventHandler>
{
    template <typename H>
    struct type : implements_delegate<Windows::UI::Xaml::Controls::Primitives::ScrollEventHandler, H>
    {
        type(H&& handler) : implements_delegate<Windows::UI::Xaml::Controls::Primitives::ScrollEventHandler, H>(std::forward<H>(handler)) {}

        int32_t WINRT_CALL Invoke(void* sender, void* e) noexcept final
        {
            try
            {
                (*this)(*reinterpret_cast<Windows::Foundation::IInspectable const*>(&sender), *reinterpret_cast<Windows::UI::Xaml::Controls::Primitives::ScrollEventArgs const*>(&e));
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
struct produce<D, Windows::UI::Xaml::Controls::Primitives::IAppBarButtonTemplateSettings> : produce_base<D, Windows::UI::Xaml::Controls::Primitives::IAppBarButtonTemplateSettings>
{
    int32_t WINRT_CALL get_KeyboardAcceleratorTextMinWidth(double* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(KeyboardAcceleratorTextMinWidth, WINRT_WRAP(double));
            *value = detach_from<double>(this->shim().KeyboardAcceleratorTextMinWidth());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Xaml::Controls::Primitives::IAppBarTemplateSettings> : produce_base<D, Windows::UI::Xaml::Controls::Primitives::IAppBarTemplateSettings>
{
    int32_t WINRT_CALL get_ClipRect(Windows::Foundation::Rect* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ClipRect, WINRT_WRAP(Windows::Foundation::Rect));
            *value = detach_from<Windows::Foundation::Rect>(this->shim().ClipRect());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_CompactVerticalDelta(double* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CompactVerticalDelta, WINRT_WRAP(double));
            *value = detach_from<double>(this->shim().CompactVerticalDelta());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_CompactRootMargin(struct struct_Windows_UI_Xaml_Thickness* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CompactRootMargin, WINRT_WRAP(Windows::UI::Xaml::Thickness));
            *value = detach_from<Windows::UI::Xaml::Thickness>(this->shim().CompactRootMargin());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_MinimalVerticalDelta(double* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(MinimalVerticalDelta, WINRT_WRAP(double));
            *value = detach_from<double>(this->shim().MinimalVerticalDelta());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_MinimalRootMargin(struct struct_Windows_UI_Xaml_Thickness* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(MinimalRootMargin, WINRT_WRAP(Windows::UI::Xaml::Thickness));
            *value = detach_from<Windows::UI::Xaml::Thickness>(this->shim().MinimalRootMargin());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_HiddenVerticalDelta(double* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(HiddenVerticalDelta, WINRT_WRAP(double));
            *value = detach_from<double>(this->shim().HiddenVerticalDelta());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_HiddenRootMargin(struct struct_Windows_UI_Xaml_Thickness* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(HiddenRootMargin, WINRT_WRAP(Windows::UI::Xaml::Thickness));
            *value = detach_from<Windows::UI::Xaml::Thickness>(this->shim().HiddenRootMargin());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Xaml::Controls::Primitives::IAppBarTemplateSettings2> : produce_base<D, Windows::UI::Xaml::Controls::Primitives::IAppBarTemplateSettings2>
{
    int32_t WINRT_CALL get_NegativeCompactVerticalDelta(double* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(NegativeCompactVerticalDelta, WINRT_WRAP(double));
            *value = detach_from<double>(this->shim().NegativeCompactVerticalDelta());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_NegativeMinimalVerticalDelta(double* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(NegativeMinimalVerticalDelta, WINRT_WRAP(double));
            *value = detach_from<double>(this->shim().NegativeMinimalVerticalDelta());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_NegativeHiddenVerticalDelta(double* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(NegativeHiddenVerticalDelta, WINRT_WRAP(double));
            *value = detach_from<double>(this->shim().NegativeHiddenVerticalDelta());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Xaml::Controls::Primitives::IAppBarToggleButtonTemplateSettings> : produce_base<D, Windows::UI::Xaml::Controls::Primitives::IAppBarToggleButtonTemplateSettings>
{
    int32_t WINRT_CALL get_KeyboardAcceleratorTextMinWidth(double* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(KeyboardAcceleratorTextMinWidth, WINRT_WRAP(double));
            *value = detach_from<double>(this->shim().KeyboardAcceleratorTextMinWidth());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Xaml::Controls::Primitives::IButtonBase> : produce_base<D, Windows::UI::Xaml::Controls::Primitives::IButtonBase>
{
    int32_t WINRT_CALL get_ClickMode(Windows::UI::Xaml::Controls::ClickMode* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ClickMode, WINRT_WRAP(Windows::UI::Xaml::Controls::ClickMode));
            *value = detach_from<Windows::UI::Xaml::Controls::ClickMode>(this->shim().ClickMode());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_ClickMode(Windows::UI::Xaml::Controls::ClickMode value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ClickMode, WINRT_WRAP(void), Windows::UI::Xaml::Controls::ClickMode const&);
            this->shim().ClickMode(*reinterpret_cast<Windows::UI::Xaml::Controls::ClickMode const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_IsPointerOver(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IsPointerOver, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().IsPointerOver());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_IsPressed(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IsPressed, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().IsPressed());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Command(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Command, WINRT_WRAP(Windows::UI::Xaml::Input::ICommand));
            *value = detach_from<Windows::UI::Xaml::Input::ICommand>(this->shim().Command());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_Command(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Command, WINRT_WRAP(void), Windows::UI::Xaml::Input::ICommand const&);
            this->shim().Command(*reinterpret_cast<Windows::UI::Xaml::Input::ICommand const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_CommandParameter(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CommandParameter, WINRT_WRAP(Windows::Foundation::IInspectable));
            *value = detach_from<Windows::Foundation::IInspectable>(this->shim().CommandParameter());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_CommandParameter(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CommandParameter, WINRT_WRAP(void), Windows::Foundation::IInspectable const&);
            this->shim().CommandParameter(*reinterpret_cast<Windows::Foundation::IInspectable const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL add_Click(void* handler, winrt::event_token* token) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Click, WINRT_WRAP(winrt::event_token), Windows::UI::Xaml::RoutedEventHandler const&);
            *token = detach_from<winrt::event_token>(this->shim().Click(*reinterpret_cast<Windows::UI::Xaml::RoutedEventHandler const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL remove_Click(winrt::event_token token) noexcept final
    {
        typename D::abi_guard guard(this->shim());
        WINRT_ASSERT_DECLARATION(Click, WINRT_WRAP(void), winrt::event_token const&);
        this->shim().Click(*reinterpret_cast<winrt::event_token const*>(&token));
        return 0;
    }
};

template <typename D>
struct produce<D, Windows::UI::Xaml::Controls::Primitives::IButtonBaseFactory> : produce_base<D, Windows::UI::Xaml::Controls::Primitives::IButtonBaseFactory>
{
    int32_t WINRT_CALL CreateInstance(void* baseInterface, void** innerInterface, void** value) noexcept final
    {
        try
        {
            if (innerInterface) *innerInterface = nullptr;
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            Windows::Foundation::IInspectable __local_innerInterface;
            WINRT_ASSERT_DECLARATION(CreateInstance, WINRT_WRAP(Windows::UI::Xaml::Controls::Primitives::ButtonBase), Windows::Foundation::IInspectable const&, Windows::Foundation::IInspectable&);
            *value = detach_from<Windows::UI::Xaml::Controls::Primitives::ButtonBase>(this->shim().CreateInstance(*reinterpret_cast<Windows::Foundation::IInspectable const*>(&baseInterface), __local_innerInterface));
            if (innerInterface) *innerInterface = detach_abi(__local_innerInterface);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Xaml::Controls::Primitives::IButtonBaseStatics> : produce_base<D, Windows::UI::Xaml::Controls::Primitives::IButtonBaseStatics>
{
    int32_t WINRT_CALL get_ClickModeProperty(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ClickModeProperty, WINRT_WRAP(Windows::UI::Xaml::DependencyProperty));
            *value = detach_from<Windows::UI::Xaml::DependencyProperty>(this->shim().ClickModeProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_IsPointerOverProperty(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IsPointerOverProperty, WINRT_WRAP(Windows::UI::Xaml::DependencyProperty));
            *value = detach_from<Windows::UI::Xaml::DependencyProperty>(this->shim().IsPointerOverProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_IsPressedProperty(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IsPressedProperty, WINRT_WRAP(Windows::UI::Xaml::DependencyProperty));
            *value = detach_from<Windows::UI::Xaml::DependencyProperty>(this->shim().IsPressedProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_CommandProperty(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CommandProperty, WINRT_WRAP(Windows::UI::Xaml::DependencyProperty));
            *value = detach_from<Windows::UI::Xaml::DependencyProperty>(this->shim().CommandProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_CommandParameterProperty(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CommandParameterProperty, WINRT_WRAP(Windows::UI::Xaml::DependencyProperty));
            *value = detach_from<Windows::UI::Xaml::DependencyProperty>(this->shim().CommandParameterProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Xaml::Controls::Primitives::ICalendarPanel> : produce_base<D, Windows::UI::Xaml::Controls::Primitives::ICalendarPanel>
{};

template <typename D>
struct produce<D, Windows::UI::Xaml::Controls::Primitives::ICalendarViewTemplateSettings> : produce_base<D, Windows::UI::Xaml::Controls::Primitives::ICalendarViewTemplateSettings>
{
    int32_t WINRT_CALL get_MinViewWidth(double* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(MinViewWidth, WINRT_WRAP(double));
            *value = detach_from<double>(this->shim().MinViewWidth());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_HeaderText(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(HeaderText, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().HeaderText());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_WeekDay1(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(WeekDay1, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().WeekDay1());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_WeekDay2(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(WeekDay2, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().WeekDay2());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_WeekDay3(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(WeekDay3, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().WeekDay3());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_WeekDay4(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(WeekDay4, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().WeekDay4());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_WeekDay5(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(WeekDay5, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().WeekDay5());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_WeekDay6(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(WeekDay6, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().WeekDay6());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_WeekDay7(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(WeekDay7, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().WeekDay7());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_HasMoreContentAfter(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(HasMoreContentAfter, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().HasMoreContentAfter());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_HasMoreContentBefore(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(HasMoreContentBefore, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().HasMoreContentBefore());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_HasMoreViews(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(HasMoreViews, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().HasMoreViews());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_ClipRect(Windows::Foundation::Rect* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ClipRect, WINRT_WRAP(Windows::Foundation::Rect));
            *value = detach_from<Windows::Foundation::Rect>(this->shim().ClipRect());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_CenterX(double* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CenterX, WINRT_WRAP(double));
            *value = detach_from<double>(this->shim().CenterX());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_CenterY(double* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CenterY, WINRT_WRAP(double));
            *value = detach_from<double>(this->shim().CenterY());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Xaml::Controls::Primitives::ICarouselPanel> : produce_base<D, Windows::UI::Xaml::Controls::Primitives::ICarouselPanel>
{
    int32_t WINRT_CALL get_CanVerticallyScroll(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CanVerticallyScroll, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().CanVerticallyScroll());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_CanVerticallyScroll(bool value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CanVerticallyScroll, WINRT_WRAP(void), bool);
            this->shim().CanVerticallyScroll(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_CanHorizontallyScroll(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CanHorizontallyScroll, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().CanHorizontallyScroll());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_CanHorizontallyScroll(bool value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CanHorizontallyScroll, WINRT_WRAP(void), bool);
            this->shim().CanHorizontallyScroll(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_ExtentWidth(double* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ExtentWidth, WINRT_WRAP(double));
            *value = detach_from<double>(this->shim().ExtentWidth());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_ExtentHeight(double* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ExtentHeight, WINRT_WRAP(double));
            *value = detach_from<double>(this->shim().ExtentHeight());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_ViewportWidth(double* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ViewportWidth, WINRT_WRAP(double));
            *value = detach_from<double>(this->shim().ViewportWidth());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_ViewportHeight(double* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ViewportHeight, WINRT_WRAP(double));
            *value = detach_from<double>(this->shim().ViewportHeight());
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

    int32_t WINRT_CALL get_ScrollOwner(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ScrollOwner, WINRT_WRAP(Windows::Foundation::IInspectable));
            *value = detach_from<Windows::Foundation::IInspectable>(this->shim().ScrollOwner());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_ScrollOwner(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ScrollOwner, WINRT_WRAP(void), Windows::Foundation::IInspectable const&);
            this->shim().ScrollOwner(*reinterpret_cast<Windows::Foundation::IInspectable const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL LineUp() noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(LineUp, WINRT_WRAP(void));
            this->shim().LineUp();
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL LineDown() noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(LineDown, WINRT_WRAP(void));
            this->shim().LineDown();
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL LineLeft() noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(LineLeft, WINRT_WRAP(void));
            this->shim().LineLeft();
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL LineRight() noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(LineRight, WINRT_WRAP(void));
            this->shim().LineRight();
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL PageUp() noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(PageUp, WINRT_WRAP(void));
            this->shim().PageUp();
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL PageDown() noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(PageDown, WINRT_WRAP(void));
            this->shim().PageDown();
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL PageLeft() noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(PageLeft, WINRT_WRAP(void));
            this->shim().PageLeft();
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL PageRight() noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(PageRight, WINRT_WRAP(void));
            this->shim().PageRight();
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL MouseWheelUp() noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(MouseWheelUp, WINRT_WRAP(void));
            this->shim().MouseWheelUp();
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL MouseWheelDown() noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(MouseWheelDown, WINRT_WRAP(void));
            this->shim().MouseWheelDown();
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL MouseWheelLeft() noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(MouseWheelLeft, WINRT_WRAP(void));
            this->shim().MouseWheelLeft();
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL MouseWheelRight() noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(MouseWheelRight, WINRT_WRAP(void));
            this->shim().MouseWheelRight();
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL SetHorizontalOffset(double offset) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SetHorizontalOffset, WINRT_WRAP(void), double);
            this->shim().SetHorizontalOffset(offset);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL SetVerticalOffset(double offset) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SetVerticalOffset, WINRT_WRAP(void), double);
            this->shim().SetVerticalOffset(offset);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL MakeVisible(void* visual, Windows::Foundation::Rect rectangle, Windows::Foundation::Rect* result) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(MakeVisible, WINRT_WRAP(Windows::Foundation::Rect), Windows::UI::Xaml::UIElement const&, Windows::Foundation::Rect const&);
            *result = detach_from<Windows::Foundation::Rect>(this->shim().MakeVisible(*reinterpret_cast<Windows::UI::Xaml::UIElement const*>(&visual), *reinterpret_cast<Windows::Foundation::Rect const*>(&rectangle)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Xaml::Controls::Primitives::ICarouselPanelFactory> : produce_base<D, Windows::UI::Xaml::Controls::Primitives::ICarouselPanelFactory>
{
    int32_t WINRT_CALL CreateInstance(void* baseInterface, void** innerInterface, void** value) noexcept final
    {
        try
        {
            if (innerInterface) *innerInterface = nullptr;
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            Windows::Foundation::IInspectable __local_innerInterface;
            WINRT_ASSERT_DECLARATION(CreateInstance, WINRT_WRAP(Windows::UI::Xaml::Controls::Primitives::CarouselPanel), Windows::Foundation::IInspectable const&, Windows::Foundation::IInspectable&);
            *value = detach_from<Windows::UI::Xaml::Controls::Primitives::CarouselPanel>(this->shim().CreateInstance(*reinterpret_cast<Windows::Foundation::IInspectable const*>(&baseInterface), __local_innerInterface));
            if (innerInterface) *innerInterface = detach_abi(__local_innerInterface);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Xaml::Controls::Primitives::IColorPickerSlider> : produce_base<D, Windows::UI::Xaml::Controls::Primitives::IColorPickerSlider>
{
    int32_t WINRT_CALL get_ColorChannel(Windows::UI::Xaml::Controls::ColorPickerHsvChannel* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ColorChannel, WINRT_WRAP(Windows::UI::Xaml::Controls::ColorPickerHsvChannel));
            *value = detach_from<Windows::UI::Xaml::Controls::ColorPickerHsvChannel>(this->shim().ColorChannel());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_ColorChannel(Windows::UI::Xaml::Controls::ColorPickerHsvChannel value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ColorChannel, WINRT_WRAP(void), Windows::UI::Xaml::Controls::ColorPickerHsvChannel const&);
            this->shim().ColorChannel(*reinterpret_cast<Windows::UI::Xaml::Controls::ColorPickerHsvChannel const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Xaml::Controls::Primitives::IColorPickerSliderFactory> : produce_base<D, Windows::UI::Xaml::Controls::Primitives::IColorPickerSliderFactory>
{
    int32_t WINRT_CALL CreateInstance(void* baseInterface, void** innerInterface, void** value) noexcept final
    {
        try
        {
            if (innerInterface) *innerInterface = nullptr;
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            Windows::Foundation::IInspectable __local_innerInterface;
            WINRT_ASSERT_DECLARATION(CreateInstance, WINRT_WRAP(Windows::UI::Xaml::Controls::Primitives::ColorPickerSlider), Windows::Foundation::IInspectable const&, Windows::Foundation::IInspectable&);
            *value = detach_from<Windows::UI::Xaml::Controls::Primitives::ColorPickerSlider>(this->shim().CreateInstance(*reinterpret_cast<Windows::Foundation::IInspectable const*>(&baseInterface), __local_innerInterface));
            if (innerInterface) *innerInterface = detach_abi(__local_innerInterface);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Xaml::Controls::Primitives::IColorPickerSliderStatics> : produce_base<D, Windows::UI::Xaml::Controls::Primitives::IColorPickerSliderStatics>
{
    int32_t WINRT_CALL get_ColorChannelProperty(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ColorChannelProperty, WINRT_WRAP(Windows::UI::Xaml::DependencyProperty));
            *value = detach_from<Windows::UI::Xaml::DependencyProperty>(this->shim().ColorChannelProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Xaml::Controls::Primitives::IColorSpectrum> : produce_base<D, Windows::UI::Xaml::Controls::Primitives::IColorSpectrum>
{
    int32_t WINRT_CALL get_Color(struct struct_Windows_UI_Color* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Color, WINRT_WRAP(Windows::UI::Color));
            *value = detach_from<Windows::UI::Color>(this->shim().Color());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_Color(struct struct_Windows_UI_Color value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Color, WINRT_WRAP(void), Windows::UI::Color const&);
            this->shim().Color(*reinterpret_cast<Windows::UI::Color const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_HsvColor(Windows::Foundation::Numerics::float4* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(HsvColor, WINRT_WRAP(Windows::Foundation::Numerics::float4));
            *value = detach_from<Windows::Foundation::Numerics::float4>(this->shim().HsvColor());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_HsvColor(Windows::Foundation::Numerics::float4 value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(HsvColor, WINRT_WRAP(void), Windows::Foundation::Numerics::float4 const&);
            this->shim().HsvColor(*reinterpret_cast<Windows::Foundation::Numerics::float4 const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_MinHue(int32_t* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(MinHue, WINRT_WRAP(int32_t));
            *value = detach_from<int32_t>(this->shim().MinHue());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_MinHue(int32_t value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(MinHue, WINRT_WRAP(void), int32_t);
            this->shim().MinHue(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_MaxHue(int32_t* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(MaxHue, WINRT_WRAP(int32_t));
            *value = detach_from<int32_t>(this->shim().MaxHue());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_MaxHue(int32_t value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(MaxHue, WINRT_WRAP(void), int32_t);
            this->shim().MaxHue(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_MinSaturation(int32_t* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(MinSaturation, WINRT_WRAP(int32_t));
            *value = detach_from<int32_t>(this->shim().MinSaturation());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_MinSaturation(int32_t value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(MinSaturation, WINRT_WRAP(void), int32_t);
            this->shim().MinSaturation(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_MaxSaturation(int32_t* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(MaxSaturation, WINRT_WRAP(int32_t));
            *value = detach_from<int32_t>(this->shim().MaxSaturation());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_MaxSaturation(int32_t value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(MaxSaturation, WINRT_WRAP(void), int32_t);
            this->shim().MaxSaturation(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_MinValue(int32_t* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(MinValue, WINRT_WRAP(int32_t));
            *value = detach_from<int32_t>(this->shim().MinValue());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_MinValue(int32_t value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(MinValue, WINRT_WRAP(void), int32_t);
            this->shim().MinValue(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_MaxValue(int32_t* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(MaxValue, WINRT_WRAP(int32_t));
            *value = detach_from<int32_t>(this->shim().MaxValue());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_MaxValue(int32_t value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(MaxValue, WINRT_WRAP(void), int32_t);
            this->shim().MaxValue(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Shape(Windows::UI::Xaml::Controls::ColorSpectrumShape* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Shape, WINRT_WRAP(Windows::UI::Xaml::Controls::ColorSpectrumShape));
            *value = detach_from<Windows::UI::Xaml::Controls::ColorSpectrumShape>(this->shim().Shape());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_Shape(Windows::UI::Xaml::Controls::ColorSpectrumShape value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Shape, WINRT_WRAP(void), Windows::UI::Xaml::Controls::ColorSpectrumShape const&);
            this->shim().Shape(*reinterpret_cast<Windows::UI::Xaml::Controls::ColorSpectrumShape const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Components(Windows::UI::Xaml::Controls::ColorSpectrumComponents* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Components, WINRT_WRAP(Windows::UI::Xaml::Controls::ColorSpectrumComponents));
            *value = detach_from<Windows::UI::Xaml::Controls::ColorSpectrumComponents>(this->shim().Components());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_Components(Windows::UI::Xaml::Controls::ColorSpectrumComponents value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Components, WINRT_WRAP(void), Windows::UI::Xaml::Controls::ColorSpectrumComponents const&);
            this->shim().Components(*reinterpret_cast<Windows::UI::Xaml::Controls::ColorSpectrumComponents const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL add_ColorChanged(void* handler, winrt::event_token* token) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ColorChanged, WINRT_WRAP(winrt::event_token), Windows::Foundation::TypedEventHandler<Windows::UI::Xaml::Controls::Primitives::ColorSpectrum, Windows::UI::Xaml::Controls::ColorChangedEventArgs> const&);
            *token = detach_from<winrt::event_token>(this->shim().ColorChanged(*reinterpret_cast<Windows::Foundation::TypedEventHandler<Windows::UI::Xaml::Controls::Primitives::ColorSpectrum, Windows::UI::Xaml::Controls::ColorChangedEventArgs> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL remove_ColorChanged(winrt::event_token token) noexcept final
    {
        typename D::abi_guard guard(this->shim());
        WINRT_ASSERT_DECLARATION(ColorChanged, WINRT_WRAP(void), winrt::event_token const&);
        this->shim().ColorChanged(*reinterpret_cast<winrt::event_token const*>(&token));
        return 0;
    }
};

template <typename D>
struct produce<D, Windows::UI::Xaml::Controls::Primitives::IColorSpectrumFactory> : produce_base<D, Windows::UI::Xaml::Controls::Primitives::IColorSpectrumFactory>
{
    int32_t WINRT_CALL CreateInstance(void* baseInterface, void** innerInterface, void** value) noexcept final
    {
        try
        {
            if (innerInterface) *innerInterface = nullptr;
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            Windows::Foundation::IInspectable __local_innerInterface;
            WINRT_ASSERT_DECLARATION(CreateInstance, WINRT_WRAP(Windows::UI::Xaml::Controls::Primitives::ColorSpectrum), Windows::Foundation::IInspectable const&, Windows::Foundation::IInspectable&);
            *value = detach_from<Windows::UI::Xaml::Controls::Primitives::ColorSpectrum>(this->shim().CreateInstance(*reinterpret_cast<Windows::Foundation::IInspectable const*>(&baseInterface), __local_innerInterface));
            if (innerInterface) *innerInterface = detach_abi(__local_innerInterface);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Xaml::Controls::Primitives::IColorSpectrumStatics> : produce_base<D, Windows::UI::Xaml::Controls::Primitives::IColorSpectrumStatics>
{
    int32_t WINRT_CALL get_ColorProperty(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ColorProperty, WINRT_WRAP(Windows::UI::Xaml::DependencyProperty));
            *value = detach_from<Windows::UI::Xaml::DependencyProperty>(this->shim().ColorProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_HsvColorProperty(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(HsvColorProperty, WINRT_WRAP(Windows::UI::Xaml::DependencyProperty));
            *value = detach_from<Windows::UI::Xaml::DependencyProperty>(this->shim().HsvColorProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_MinHueProperty(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(MinHueProperty, WINRT_WRAP(Windows::UI::Xaml::DependencyProperty));
            *value = detach_from<Windows::UI::Xaml::DependencyProperty>(this->shim().MinHueProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_MaxHueProperty(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(MaxHueProperty, WINRT_WRAP(Windows::UI::Xaml::DependencyProperty));
            *value = detach_from<Windows::UI::Xaml::DependencyProperty>(this->shim().MaxHueProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_MinSaturationProperty(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(MinSaturationProperty, WINRT_WRAP(Windows::UI::Xaml::DependencyProperty));
            *value = detach_from<Windows::UI::Xaml::DependencyProperty>(this->shim().MinSaturationProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_MaxSaturationProperty(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(MaxSaturationProperty, WINRT_WRAP(Windows::UI::Xaml::DependencyProperty));
            *value = detach_from<Windows::UI::Xaml::DependencyProperty>(this->shim().MaxSaturationProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_MinValueProperty(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(MinValueProperty, WINRT_WRAP(Windows::UI::Xaml::DependencyProperty));
            *value = detach_from<Windows::UI::Xaml::DependencyProperty>(this->shim().MinValueProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_MaxValueProperty(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(MaxValueProperty, WINRT_WRAP(Windows::UI::Xaml::DependencyProperty));
            *value = detach_from<Windows::UI::Xaml::DependencyProperty>(this->shim().MaxValueProperty());
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
            WINRT_ASSERT_DECLARATION(ShapeProperty, WINRT_WRAP(Windows::UI::Xaml::DependencyProperty));
            *value = detach_from<Windows::UI::Xaml::DependencyProperty>(this->shim().ShapeProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_ComponentsProperty(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ComponentsProperty, WINRT_WRAP(Windows::UI::Xaml::DependencyProperty));
            *value = detach_from<Windows::UI::Xaml::DependencyProperty>(this->shim().ComponentsProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Xaml::Controls::Primitives::IComboBoxTemplateSettings> : produce_base<D, Windows::UI::Xaml::Controls::Primitives::IComboBoxTemplateSettings>
{
    int32_t WINRT_CALL get_DropDownOpenedHeight(double* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(DropDownOpenedHeight, WINRT_WRAP(double));
            *value = detach_from<double>(this->shim().DropDownOpenedHeight());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_DropDownClosedHeight(double* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(DropDownClosedHeight, WINRT_WRAP(double));
            *value = detach_from<double>(this->shim().DropDownClosedHeight());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_DropDownOffset(double* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(DropDownOffset, WINRT_WRAP(double));
            *value = detach_from<double>(this->shim().DropDownOffset());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_SelectedItemDirection(Windows::UI::Xaml::Controls::Primitives::AnimationDirection* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SelectedItemDirection, WINRT_WRAP(Windows::UI::Xaml::Controls::Primitives::AnimationDirection));
            *value = detach_from<Windows::UI::Xaml::Controls::Primitives::AnimationDirection>(this->shim().SelectedItemDirection());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Xaml::Controls::Primitives::IComboBoxTemplateSettings2> : produce_base<D, Windows::UI::Xaml::Controls::Primitives::IComboBoxTemplateSettings2>
{
    int32_t WINRT_CALL get_DropDownContentMinWidth(double* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(DropDownContentMinWidth, WINRT_WRAP(double));
            *value = detach_from<double>(this->shim().DropDownContentMinWidth());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Xaml::Controls::Primitives::ICommandBarFlyoutCommandBar> : produce_base<D, Windows::UI::Xaml::Controls::Primitives::ICommandBarFlyoutCommandBar>
{
    int32_t WINRT_CALL get_FlyoutTemplateSettings(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(FlyoutTemplateSettings, WINRT_WRAP(Windows::UI::Xaml::Controls::Primitives::CommandBarFlyoutCommandBarTemplateSettings));
            *value = detach_from<Windows::UI::Xaml::Controls::Primitives::CommandBarFlyoutCommandBarTemplateSettings>(this->shim().FlyoutTemplateSettings());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Xaml::Controls::Primitives::ICommandBarFlyoutCommandBarFactory> : produce_base<D, Windows::UI::Xaml::Controls::Primitives::ICommandBarFlyoutCommandBarFactory>
{
    int32_t WINRT_CALL CreateInstance(void* baseInterface, void** innerInterface, void** value) noexcept final
    {
        try
        {
            if (innerInterface) *innerInterface = nullptr;
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            Windows::Foundation::IInspectable __local_innerInterface;
            WINRT_ASSERT_DECLARATION(CreateInstance, WINRT_WRAP(Windows::UI::Xaml::Controls::Primitives::CommandBarFlyoutCommandBar), Windows::Foundation::IInspectable const&, Windows::Foundation::IInspectable&);
            *value = detach_from<Windows::UI::Xaml::Controls::Primitives::CommandBarFlyoutCommandBar>(this->shim().CreateInstance(*reinterpret_cast<Windows::Foundation::IInspectable const*>(&baseInterface), __local_innerInterface));
            if (innerInterface) *innerInterface = detach_abi(__local_innerInterface);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Xaml::Controls::Primitives::ICommandBarFlyoutCommandBarTemplateSettings> : produce_base<D, Windows::UI::Xaml::Controls::Primitives::ICommandBarFlyoutCommandBarTemplateSettings>
{
    int32_t WINRT_CALL get_OpenAnimationStartPosition(double* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(OpenAnimationStartPosition, WINRT_WRAP(double));
            *value = detach_from<double>(this->shim().OpenAnimationStartPosition());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_OpenAnimationEndPosition(double* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(OpenAnimationEndPosition, WINRT_WRAP(double));
            *value = detach_from<double>(this->shim().OpenAnimationEndPosition());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_CloseAnimationEndPosition(double* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CloseAnimationEndPosition, WINRT_WRAP(double));
            *value = detach_from<double>(this->shim().CloseAnimationEndPosition());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_CurrentWidth(double* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CurrentWidth, WINRT_WRAP(double));
            *value = detach_from<double>(this->shim().CurrentWidth());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_ExpandedWidth(double* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ExpandedWidth, WINRT_WRAP(double));
            *value = detach_from<double>(this->shim().ExpandedWidth());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_WidthExpansionDelta(double* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(WidthExpansionDelta, WINRT_WRAP(double));
            *value = detach_from<double>(this->shim().WidthExpansionDelta());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_WidthExpansionAnimationStartPosition(double* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(WidthExpansionAnimationStartPosition, WINRT_WRAP(double));
            *value = detach_from<double>(this->shim().WidthExpansionAnimationStartPosition());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_WidthExpansionAnimationEndPosition(double* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(WidthExpansionAnimationEndPosition, WINRT_WRAP(double));
            *value = detach_from<double>(this->shim().WidthExpansionAnimationEndPosition());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_WidthExpansionMoreButtonAnimationStartPosition(double* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(WidthExpansionMoreButtonAnimationStartPosition, WINRT_WRAP(double));
            *value = detach_from<double>(this->shim().WidthExpansionMoreButtonAnimationStartPosition());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_WidthExpansionMoreButtonAnimationEndPosition(double* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(WidthExpansionMoreButtonAnimationEndPosition, WINRT_WRAP(double));
            *value = detach_from<double>(this->shim().WidthExpansionMoreButtonAnimationEndPosition());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_ExpandUpOverflowVerticalPosition(double* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ExpandUpOverflowVerticalPosition, WINRT_WRAP(double));
            *value = detach_from<double>(this->shim().ExpandUpOverflowVerticalPosition());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_ExpandDownOverflowVerticalPosition(double* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ExpandDownOverflowVerticalPosition, WINRT_WRAP(double));
            *value = detach_from<double>(this->shim().ExpandDownOverflowVerticalPosition());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_ExpandUpAnimationStartPosition(double* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ExpandUpAnimationStartPosition, WINRT_WRAP(double));
            *value = detach_from<double>(this->shim().ExpandUpAnimationStartPosition());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_ExpandUpAnimationEndPosition(double* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ExpandUpAnimationEndPosition, WINRT_WRAP(double));
            *value = detach_from<double>(this->shim().ExpandUpAnimationEndPosition());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_ExpandUpAnimationHoldPosition(double* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ExpandUpAnimationHoldPosition, WINRT_WRAP(double));
            *value = detach_from<double>(this->shim().ExpandUpAnimationHoldPosition());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_ExpandDownAnimationStartPosition(double* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ExpandDownAnimationStartPosition, WINRT_WRAP(double));
            *value = detach_from<double>(this->shim().ExpandDownAnimationStartPosition());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_ExpandDownAnimationEndPosition(double* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ExpandDownAnimationEndPosition, WINRT_WRAP(double));
            *value = detach_from<double>(this->shim().ExpandDownAnimationEndPosition());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_ExpandDownAnimationHoldPosition(double* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ExpandDownAnimationHoldPosition, WINRT_WRAP(double));
            *value = detach_from<double>(this->shim().ExpandDownAnimationHoldPosition());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_ContentClipRect(Windows::Foundation::Rect* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ContentClipRect, WINRT_WRAP(Windows::Foundation::Rect));
            *value = detach_from<Windows::Foundation::Rect>(this->shim().ContentClipRect());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_OverflowContentClipRect(Windows::Foundation::Rect* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(OverflowContentClipRect, WINRT_WRAP(Windows::Foundation::Rect));
            *value = detach_from<Windows::Foundation::Rect>(this->shim().OverflowContentClipRect());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Xaml::Controls::Primitives::ICommandBarTemplateSettings> : produce_base<D, Windows::UI::Xaml::Controls::Primitives::ICommandBarTemplateSettings>
{
    int32_t WINRT_CALL get_ContentHeight(double* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ContentHeight, WINRT_WRAP(double));
            *value = detach_from<double>(this->shim().ContentHeight());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_OverflowContentClipRect(Windows::Foundation::Rect* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(OverflowContentClipRect, WINRT_WRAP(Windows::Foundation::Rect));
            *value = detach_from<Windows::Foundation::Rect>(this->shim().OverflowContentClipRect());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_OverflowContentMinWidth(double* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(OverflowContentMinWidth, WINRT_WRAP(double));
            *value = detach_from<double>(this->shim().OverflowContentMinWidth());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_OverflowContentMaxHeight(double* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(OverflowContentMaxHeight, WINRT_WRAP(double));
            *value = detach_from<double>(this->shim().OverflowContentMaxHeight());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_OverflowContentHorizontalOffset(double* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(OverflowContentHorizontalOffset, WINRT_WRAP(double));
            *value = detach_from<double>(this->shim().OverflowContentHorizontalOffset());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_OverflowContentHeight(double* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(OverflowContentHeight, WINRT_WRAP(double));
            *value = detach_from<double>(this->shim().OverflowContentHeight());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_NegativeOverflowContentHeight(double* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(NegativeOverflowContentHeight, WINRT_WRAP(double));
            *value = detach_from<double>(this->shim().NegativeOverflowContentHeight());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Xaml::Controls::Primitives::ICommandBarTemplateSettings2> : produce_base<D, Windows::UI::Xaml::Controls::Primitives::ICommandBarTemplateSettings2>
{
    int32_t WINRT_CALL get_OverflowContentMaxWidth(double* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(OverflowContentMaxWidth, WINRT_WRAP(double));
            *value = detach_from<double>(this->shim().OverflowContentMaxWidth());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Xaml::Controls::Primitives::ICommandBarTemplateSettings3> : produce_base<D, Windows::UI::Xaml::Controls::Primitives::ICommandBarTemplateSettings3>
{
    int32_t WINRT_CALL get_EffectiveOverflowButtonVisibility(Windows::UI::Xaml::Visibility* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(EffectiveOverflowButtonVisibility, WINRT_WRAP(Windows::UI::Xaml::Visibility));
            *value = detach_from<Windows::UI::Xaml::Visibility>(this->shim().EffectiveOverflowButtonVisibility());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Xaml::Controls::Primitives::ICommandBarTemplateSettings4> : produce_base<D, Windows::UI::Xaml::Controls::Primitives::ICommandBarTemplateSettings4>
{
    int32_t WINRT_CALL get_OverflowContentCompactYTranslation(double* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(OverflowContentCompactYTranslation, WINRT_WRAP(double));
            *value = detach_from<double>(this->shim().OverflowContentCompactYTranslation());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_OverflowContentMinimalYTranslation(double* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(OverflowContentMinimalYTranslation, WINRT_WRAP(double));
            *value = detach_from<double>(this->shim().OverflowContentMinimalYTranslation());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_OverflowContentHiddenYTranslation(double* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(OverflowContentHiddenYTranslation, WINRT_WRAP(double));
            *value = detach_from<double>(this->shim().OverflowContentHiddenYTranslation());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Xaml::Controls::Primitives::IDragCompletedEventArgs> : produce_base<D, Windows::UI::Xaml::Controls::Primitives::IDragCompletedEventArgs>
{
    int32_t WINRT_CALL get_HorizontalChange(double* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(HorizontalChange, WINRT_WRAP(double));
            *value = detach_from<double>(this->shim().HorizontalChange());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_VerticalChange(double* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(VerticalChange, WINRT_WRAP(double));
            *value = detach_from<double>(this->shim().VerticalChange());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Canceled(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Canceled, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().Canceled());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Xaml::Controls::Primitives::IDragCompletedEventArgsFactory> : produce_base<D, Windows::UI::Xaml::Controls::Primitives::IDragCompletedEventArgsFactory>
{
    int32_t WINRT_CALL CreateInstanceWithHorizontalChangeVerticalChangeAndCanceled(double horizontalChange, double verticalChange, bool canceled, void* baseInterface, void** innerInterface, void** value) noexcept final
    {
        try
        {
            if (innerInterface) *innerInterface = nullptr;
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            Windows::Foundation::IInspectable __local_innerInterface;
            WINRT_ASSERT_DECLARATION(CreateInstanceWithHorizontalChangeVerticalChangeAndCanceled, WINRT_WRAP(Windows::UI::Xaml::Controls::Primitives::DragCompletedEventArgs), double, double, bool, Windows::Foundation::IInspectable const&, Windows::Foundation::IInspectable&);
            *value = detach_from<Windows::UI::Xaml::Controls::Primitives::DragCompletedEventArgs>(this->shim().CreateInstanceWithHorizontalChangeVerticalChangeAndCanceled(horizontalChange, verticalChange, canceled, *reinterpret_cast<Windows::Foundation::IInspectable const*>(&baseInterface), __local_innerInterface));
            if (innerInterface) *innerInterface = detach_abi(__local_innerInterface);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Xaml::Controls::Primitives::IDragDeltaEventArgs> : produce_base<D, Windows::UI::Xaml::Controls::Primitives::IDragDeltaEventArgs>
{
    int32_t WINRT_CALL get_HorizontalChange(double* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(HorizontalChange, WINRT_WRAP(double));
            *value = detach_from<double>(this->shim().HorizontalChange());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_VerticalChange(double* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(VerticalChange, WINRT_WRAP(double));
            *value = detach_from<double>(this->shim().VerticalChange());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Xaml::Controls::Primitives::IDragDeltaEventArgsFactory> : produce_base<D, Windows::UI::Xaml::Controls::Primitives::IDragDeltaEventArgsFactory>
{
    int32_t WINRT_CALL CreateInstanceWithHorizontalChangeAndVerticalChange(double horizontalChange, double verticalChange, void* baseInterface, void** innerInterface, void** value) noexcept final
    {
        try
        {
            if (innerInterface) *innerInterface = nullptr;
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            Windows::Foundation::IInspectable __local_innerInterface;
            WINRT_ASSERT_DECLARATION(CreateInstanceWithHorizontalChangeAndVerticalChange, WINRT_WRAP(Windows::UI::Xaml::Controls::Primitives::DragDeltaEventArgs), double, double, Windows::Foundation::IInspectable const&, Windows::Foundation::IInspectable&);
            *value = detach_from<Windows::UI::Xaml::Controls::Primitives::DragDeltaEventArgs>(this->shim().CreateInstanceWithHorizontalChangeAndVerticalChange(horizontalChange, verticalChange, *reinterpret_cast<Windows::Foundation::IInspectable const*>(&baseInterface), __local_innerInterface));
            if (innerInterface) *innerInterface = detach_abi(__local_innerInterface);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Xaml::Controls::Primitives::IDragStartedEventArgs> : produce_base<D, Windows::UI::Xaml::Controls::Primitives::IDragStartedEventArgs>
{
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
};

template <typename D>
struct produce<D, Windows::UI::Xaml::Controls::Primitives::IDragStartedEventArgsFactory> : produce_base<D, Windows::UI::Xaml::Controls::Primitives::IDragStartedEventArgsFactory>
{
    int32_t WINRT_CALL CreateInstanceWithHorizontalOffsetAndVerticalOffset(double horizontalOffset, double verticalOffset, void* baseInterface, void** innerInterface, void** value) noexcept final
    {
        try
        {
            if (innerInterface) *innerInterface = nullptr;
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            Windows::Foundation::IInspectable __local_innerInterface;
            WINRT_ASSERT_DECLARATION(CreateInstanceWithHorizontalOffsetAndVerticalOffset, WINRT_WRAP(Windows::UI::Xaml::Controls::Primitives::DragStartedEventArgs), double, double, Windows::Foundation::IInspectable const&, Windows::Foundation::IInspectable&);
            *value = detach_from<Windows::UI::Xaml::Controls::Primitives::DragStartedEventArgs>(this->shim().CreateInstanceWithHorizontalOffsetAndVerticalOffset(horizontalOffset, verticalOffset, *reinterpret_cast<Windows::Foundation::IInspectable const*>(&baseInterface), __local_innerInterface));
            if (innerInterface) *innerInterface = detach_abi(__local_innerInterface);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Xaml::Controls::Primitives::IFlyoutBase> : produce_base<D, Windows::UI::Xaml::Controls::Primitives::IFlyoutBase>
{
    int32_t WINRT_CALL get_Placement(Windows::UI::Xaml::Controls::Primitives::FlyoutPlacementMode* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Placement, WINRT_WRAP(Windows::UI::Xaml::Controls::Primitives::FlyoutPlacementMode));
            *value = detach_from<Windows::UI::Xaml::Controls::Primitives::FlyoutPlacementMode>(this->shim().Placement());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_Placement(Windows::UI::Xaml::Controls::Primitives::FlyoutPlacementMode value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Placement, WINRT_WRAP(void), Windows::UI::Xaml::Controls::Primitives::FlyoutPlacementMode const&);
            this->shim().Placement(*reinterpret_cast<Windows::UI::Xaml::Controls::Primitives::FlyoutPlacementMode const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL add_Opened(void* handler, winrt::event_token* token) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Opened, WINRT_WRAP(winrt::event_token), Windows::Foundation::EventHandler<Windows::Foundation::IInspectable> const&);
            *token = detach_from<winrt::event_token>(this->shim().Opened(*reinterpret_cast<Windows::Foundation::EventHandler<Windows::Foundation::IInspectable> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL remove_Opened(winrt::event_token token) noexcept final
    {
        typename D::abi_guard guard(this->shim());
        WINRT_ASSERT_DECLARATION(Opened, WINRT_WRAP(void), winrt::event_token const&);
        this->shim().Opened(*reinterpret_cast<winrt::event_token const*>(&token));
        return 0;
    }

    int32_t WINRT_CALL add_Closed(void* handler, winrt::event_token* token) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Closed, WINRT_WRAP(winrt::event_token), Windows::Foundation::EventHandler<Windows::Foundation::IInspectable> const&);
            *token = detach_from<winrt::event_token>(this->shim().Closed(*reinterpret_cast<Windows::Foundation::EventHandler<Windows::Foundation::IInspectable> const*>(&handler)));
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

    int32_t WINRT_CALL add_Opening(void* handler, winrt::event_token* token) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Opening, WINRT_WRAP(winrt::event_token), Windows::Foundation::EventHandler<Windows::Foundation::IInspectable> const&);
            *token = detach_from<winrt::event_token>(this->shim().Opening(*reinterpret_cast<Windows::Foundation::EventHandler<Windows::Foundation::IInspectable> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL remove_Opening(winrt::event_token token) noexcept final
    {
        typename D::abi_guard guard(this->shim());
        WINRT_ASSERT_DECLARATION(Opening, WINRT_WRAP(void), winrt::event_token const&);
        this->shim().Opening(*reinterpret_cast<winrt::event_token const*>(&token));
        return 0;
    }

    int32_t WINRT_CALL ShowAt(void* placementTarget) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ShowAt, WINRT_WRAP(void), Windows::UI::Xaml::FrameworkElement const&);
            this->shim().ShowAt(*reinterpret_cast<Windows::UI::Xaml::FrameworkElement const*>(&placementTarget));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL Hide() noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Hide, WINRT_WRAP(void));
            this->shim().Hide();
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Xaml::Controls::Primitives::IFlyoutBase2> : produce_base<D, Windows::UI::Xaml::Controls::Primitives::IFlyoutBase2>
{
    int32_t WINRT_CALL get_Target(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Target, WINRT_WRAP(Windows::UI::Xaml::FrameworkElement));
            *value = detach_from<Windows::UI::Xaml::FrameworkElement>(this->shim().Target());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

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

    int32_t WINRT_CALL get_LightDismissOverlayMode(Windows::UI::Xaml::Controls::LightDismissOverlayMode* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(LightDismissOverlayMode, WINRT_WRAP(Windows::UI::Xaml::Controls::LightDismissOverlayMode));
            *value = detach_from<Windows::UI::Xaml::Controls::LightDismissOverlayMode>(this->shim().LightDismissOverlayMode());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_LightDismissOverlayMode(Windows::UI::Xaml::Controls::LightDismissOverlayMode value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(LightDismissOverlayMode, WINRT_WRAP(void), Windows::UI::Xaml::Controls::LightDismissOverlayMode const&);
            this->shim().LightDismissOverlayMode(*reinterpret_cast<Windows::UI::Xaml::Controls::LightDismissOverlayMode const*>(&value));
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

    int32_t WINRT_CALL get_ElementSoundMode(Windows::UI::Xaml::ElementSoundMode* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ElementSoundMode, WINRT_WRAP(Windows::UI::Xaml::ElementSoundMode));
            *value = detach_from<Windows::UI::Xaml::ElementSoundMode>(this->shim().ElementSoundMode());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_ElementSoundMode(Windows::UI::Xaml::ElementSoundMode value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ElementSoundMode, WINRT_WRAP(void), Windows::UI::Xaml::ElementSoundMode const&);
            this->shim().ElementSoundMode(*reinterpret_cast<Windows::UI::Xaml::ElementSoundMode const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL add_Closing(void* handler, winrt::event_token* token) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Closing, WINRT_WRAP(winrt::event_token), Windows::Foundation::TypedEventHandler<Windows::UI::Xaml::Controls::Primitives::FlyoutBase, Windows::UI::Xaml::Controls::Primitives::FlyoutBaseClosingEventArgs> const&);
            *token = detach_from<winrt::event_token>(this->shim().Closing(*reinterpret_cast<Windows::Foundation::TypedEventHandler<Windows::UI::Xaml::Controls::Primitives::FlyoutBase, Windows::UI::Xaml::Controls::Primitives::FlyoutBaseClosingEventArgs> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL remove_Closing(winrt::event_token token) noexcept final
    {
        typename D::abi_guard guard(this->shim());
        WINRT_ASSERT_DECLARATION(Closing, WINRT_WRAP(void), winrt::event_token const&);
        this->shim().Closing(*reinterpret_cast<winrt::event_token const*>(&token));
        return 0;
    }
};

template <typename D>
struct produce<D, Windows::UI::Xaml::Controls::Primitives::IFlyoutBase3> : produce_base<D, Windows::UI::Xaml::Controls::Primitives::IFlyoutBase3>
{
    int32_t WINRT_CALL get_OverlayInputPassThroughElement(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(OverlayInputPassThroughElement, WINRT_WRAP(Windows::UI::Xaml::DependencyObject));
            *value = detach_from<Windows::UI::Xaml::DependencyObject>(this->shim().OverlayInputPassThroughElement());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_OverlayInputPassThroughElement(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(OverlayInputPassThroughElement, WINRT_WRAP(void), Windows::UI::Xaml::DependencyObject const&);
            this->shim().OverlayInputPassThroughElement(*reinterpret_cast<Windows::UI::Xaml::DependencyObject const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Xaml::Controls::Primitives::IFlyoutBase4> : produce_base<D, Windows::UI::Xaml::Controls::Primitives::IFlyoutBase4>
{
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
struct produce<D, Windows::UI::Xaml::Controls::Primitives::IFlyoutBase5> : produce_base<D, Windows::UI::Xaml::Controls::Primitives::IFlyoutBase5>
{
    int32_t WINRT_CALL get_ShowMode(Windows::UI::Xaml::Controls::Primitives::FlyoutShowMode* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ShowMode, WINRT_WRAP(Windows::UI::Xaml::Controls::Primitives::FlyoutShowMode));
            *value = detach_from<Windows::UI::Xaml::Controls::Primitives::FlyoutShowMode>(this->shim().ShowMode());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_ShowMode(Windows::UI::Xaml::Controls::Primitives::FlyoutShowMode value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ShowMode, WINRT_WRAP(void), Windows::UI::Xaml::Controls::Primitives::FlyoutShowMode const&);
            this->shim().ShowMode(*reinterpret_cast<Windows::UI::Xaml::Controls::Primitives::FlyoutShowMode const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_InputDevicePrefersPrimaryCommands(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(InputDevicePrefersPrimaryCommands, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().InputDevicePrefersPrimaryCommands());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_AreOpenCloseAnimationsEnabled(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(AreOpenCloseAnimationsEnabled, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().AreOpenCloseAnimationsEnabled());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_AreOpenCloseAnimationsEnabled(bool value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(AreOpenCloseAnimationsEnabled, WINRT_WRAP(void), bool);
            this->shim().AreOpenCloseAnimationsEnabled(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_IsOpen(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IsOpen, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().IsOpen());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL ShowAt(void* placementTarget, void* showOptions) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ShowAt, WINRT_WRAP(void), Windows::UI::Xaml::DependencyObject const&, Windows::UI::Xaml::Controls::Primitives::FlyoutShowOptions const&);
            this->shim().ShowAt(*reinterpret_cast<Windows::UI::Xaml::DependencyObject const*>(&placementTarget), *reinterpret_cast<Windows::UI::Xaml::Controls::Primitives::FlyoutShowOptions const*>(&showOptions));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Xaml::Controls::Primitives::IFlyoutBase6> : produce_base<D, Windows::UI::Xaml::Controls::Primitives::IFlyoutBase6>
{
    int32_t WINRT_CALL get_ShouldConstrainToRootBounds(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ShouldConstrainToRootBounds, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().ShouldConstrainToRootBounds());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_ShouldConstrainToRootBounds(bool value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ShouldConstrainToRootBounds, WINRT_WRAP(void), bool);
            this->shim().ShouldConstrainToRootBounds(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_IsConstrainedToRootBounds(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IsConstrainedToRootBounds, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().IsConstrainedToRootBounds());
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
};

template <typename D>
struct produce<D, Windows::UI::Xaml::Controls::Primitives::IFlyoutBaseClosingEventArgs> : produce_base<D, Windows::UI::Xaml::Controls::Primitives::IFlyoutBaseClosingEventArgs>
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
};

template <typename D>
struct produce<D, Windows::UI::Xaml::Controls::Primitives::IFlyoutBaseFactory> : produce_base<D, Windows::UI::Xaml::Controls::Primitives::IFlyoutBaseFactory>
{
    int32_t WINRT_CALL CreateInstance(void* baseInterface, void** innerInterface, void** value) noexcept final
    {
        try
        {
            if (innerInterface) *innerInterface = nullptr;
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            Windows::Foundation::IInspectable __local_innerInterface;
            WINRT_ASSERT_DECLARATION(CreateInstance, WINRT_WRAP(Windows::UI::Xaml::Controls::Primitives::FlyoutBase), Windows::Foundation::IInspectable const&, Windows::Foundation::IInspectable&);
            *value = detach_from<Windows::UI::Xaml::Controls::Primitives::FlyoutBase>(this->shim().CreateInstance(*reinterpret_cast<Windows::Foundation::IInspectable const*>(&baseInterface), __local_innerInterface));
            if (innerInterface) *innerInterface = detach_abi(__local_innerInterface);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Xaml::Controls::Primitives::IFlyoutBaseOverrides> : produce_base<D, Windows::UI::Xaml::Controls::Primitives::IFlyoutBaseOverrides>
{
    int32_t WINRT_CALL CreatePresenter(void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CreatePresenter, WINRT_WRAP(Windows::UI::Xaml::Controls::Control));
            *result = detach_from<Windows::UI::Xaml::Controls::Control>(this->shim().CreatePresenter());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Xaml::Controls::Primitives::IFlyoutBaseOverrides4> : produce_base<D, Windows::UI::Xaml::Controls::Primitives::IFlyoutBaseOverrides4>
{
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
struct produce<D, Windows::UI::Xaml::Controls::Primitives::IFlyoutBaseStatics> : produce_base<D, Windows::UI::Xaml::Controls::Primitives::IFlyoutBaseStatics>
{
    int32_t WINRT_CALL get_PlacementProperty(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(PlacementProperty, WINRT_WRAP(Windows::UI::Xaml::DependencyProperty));
            *value = detach_from<Windows::UI::Xaml::DependencyProperty>(this->shim().PlacementProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_AttachedFlyoutProperty(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(AttachedFlyoutProperty, WINRT_WRAP(Windows::UI::Xaml::DependencyProperty));
            *value = detach_from<Windows::UI::Xaml::DependencyProperty>(this->shim().AttachedFlyoutProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL GetAttachedFlyout(void* element, void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetAttachedFlyout, WINRT_WRAP(Windows::UI::Xaml::Controls::Primitives::FlyoutBase), Windows::UI::Xaml::FrameworkElement const&);
            *result = detach_from<Windows::UI::Xaml::Controls::Primitives::FlyoutBase>(this->shim().GetAttachedFlyout(*reinterpret_cast<Windows::UI::Xaml::FrameworkElement const*>(&element)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL SetAttachedFlyout(void* element, void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SetAttachedFlyout, WINRT_WRAP(void), Windows::UI::Xaml::FrameworkElement const&, Windows::UI::Xaml::Controls::Primitives::FlyoutBase const&);
            this->shim().SetAttachedFlyout(*reinterpret_cast<Windows::UI::Xaml::FrameworkElement const*>(&element), *reinterpret_cast<Windows::UI::Xaml::Controls::Primitives::FlyoutBase const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL ShowAttachedFlyout(void* flyoutOwner) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ShowAttachedFlyout, WINRT_WRAP(void), Windows::UI::Xaml::FrameworkElement const&);
            this->shim().ShowAttachedFlyout(*reinterpret_cast<Windows::UI::Xaml::FrameworkElement const*>(&flyoutOwner));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Xaml::Controls::Primitives::IFlyoutBaseStatics2> : produce_base<D, Windows::UI::Xaml::Controls::Primitives::IFlyoutBaseStatics2>
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

    int32_t WINRT_CALL get_LightDismissOverlayModeProperty(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(LightDismissOverlayModeProperty, WINRT_WRAP(Windows::UI::Xaml::DependencyProperty));
            *value = detach_from<Windows::UI::Xaml::DependencyProperty>(this->shim().LightDismissOverlayModeProperty());
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

    int32_t WINRT_CALL get_ElementSoundModeProperty(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ElementSoundModeProperty, WINRT_WRAP(Windows::UI::Xaml::DependencyProperty));
            *value = detach_from<Windows::UI::Xaml::DependencyProperty>(this->shim().ElementSoundModeProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Xaml::Controls::Primitives::IFlyoutBaseStatics3> : produce_base<D, Windows::UI::Xaml::Controls::Primitives::IFlyoutBaseStatics3>
{
    int32_t WINRT_CALL get_OverlayInputPassThroughElementProperty(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(OverlayInputPassThroughElementProperty, WINRT_WRAP(Windows::UI::Xaml::DependencyProperty));
            *value = detach_from<Windows::UI::Xaml::DependencyProperty>(this->shim().OverlayInputPassThroughElementProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Xaml::Controls::Primitives::IFlyoutBaseStatics5> : produce_base<D, Windows::UI::Xaml::Controls::Primitives::IFlyoutBaseStatics5>
{
    int32_t WINRT_CALL get_TargetProperty(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(TargetProperty, WINRT_WRAP(Windows::UI::Xaml::DependencyProperty));
            *value = detach_from<Windows::UI::Xaml::DependencyProperty>(this->shim().TargetProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_ShowModeProperty(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ShowModeProperty, WINRT_WRAP(Windows::UI::Xaml::DependencyProperty));
            *value = detach_from<Windows::UI::Xaml::DependencyProperty>(this->shim().ShowModeProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_InputDevicePrefersPrimaryCommandsProperty(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(InputDevicePrefersPrimaryCommandsProperty, WINRT_WRAP(Windows::UI::Xaml::DependencyProperty));
            *value = detach_from<Windows::UI::Xaml::DependencyProperty>(this->shim().InputDevicePrefersPrimaryCommandsProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_AreOpenCloseAnimationsEnabledProperty(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(AreOpenCloseAnimationsEnabledProperty, WINRT_WRAP(Windows::UI::Xaml::DependencyProperty));
            *value = detach_from<Windows::UI::Xaml::DependencyProperty>(this->shim().AreOpenCloseAnimationsEnabledProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_IsOpenProperty(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IsOpenProperty, WINRT_WRAP(Windows::UI::Xaml::DependencyProperty));
            *value = detach_from<Windows::UI::Xaml::DependencyProperty>(this->shim().IsOpenProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Xaml::Controls::Primitives::IFlyoutBaseStatics6> : produce_base<D, Windows::UI::Xaml::Controls::Primitives::IFlyoutBaseStatics6>
{
    int32_t WINRT_CALL get_ShouldConstrainToRootBoundsProperty(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ShouldConstrainToRootBoundsProperty, WINRT_WRAP(Windows::UI::Xaml::DependencyProperty));
            *value = detach_from<Windows::UI::Xaml::DependencyProperty>(this->shim().ShouldConstrainToRootBoundsProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Xaml::Controls::Primitives::IFlyoutShowOptions> : produce_base<D, Windows::UI::Xaml::Controls::Primitives::IFlyoutShowOptions>
{
    int32_t WINRT_CALL get_Position(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Position, WINRT_WRAP(Windows::Foundation::IReference<Windows::Foundation::Point>));
            *value = detach_from<Windows::Foundation::IReference<Windows::Foundation::Point>>(this->shim().Position());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_Position(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Position, WINRT_WRAP(void), Windows::Foundation::IReference<Windows::Foundation::Point> const&);
            this->shim().Position(*reinterpret_cast<Windows::Foundation::IReference<Windows::Foundation::Point> const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_ExclusionRect(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ExclusionRect, WINRT_WRAP(Windows::Foundation::IReference<Windows::Foundation::Rect>));
            *value = detach_from<Windows::Foundation::IReference<Windows::Foundation::Rect>>(this->shim().ExclusionRect());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_ExclusionRect(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ExclusionRect, WINRT_WRAP(void), Windows::Foundation::IReference<Windows::Foundation::Rect> const&);
            this->shim().ExclusionRect(*reinterpret_cast<Windows::Foundation::IReference<Windows::Foundation::Rect> const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_ShowMode(Windows::UI::Xaml::Controls::Primitives::FlyoutShowMode* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ShowMode, WINRT_WRAP(Windows::UI::Xaml::Controls::Primitives::FlyoutShowMode));
            *value = detach_from<Windows::UI::Xaml::Controls::Primitives::FlyoutShowMode>(this->shim().ShowMode());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_ShowMode(Windows::UI::Xaml::Controls::Primitives::FlyoutShowMode value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ShowMode, WINRT_WRAP(void), Windows::UI::Xaml::Controls::Primitives::FlyoutShowMode const&);
            this->shim().ShowMode(*reinterpret_cast<Windows::UI::Xaml::Controls::Primitives::FlyoutShowMode const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Placement(Windows::UI::Xaml::Controls::Primitives::FlyoutPlacementMode* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Placement, WINRT_WRAP(Windows::UI::Xaml::Controls::Primitives::FlyoutPlacementMode));
            *value = detach_from<Windows::UI::Xaml::Controls::Primitives::FlyoutPlacementMode>(this->shim().Placement());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_Placement(Windows::UI::Xaml::Controls::Primitives::FlyoutPlacementMode value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Placement, WINRT_WRAP(void), Windows::UI::Xaml::Controls::Primitives::FlyoutPlacementMode const&);
            this->shim().Placement(*reinterpret_cast<Windows::UI::Xaml::Controls::Primitives::FlyoutPlacementMode const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Xaml::Controls::Primitives::IFlyoutShowOptionsFactory> : produce_base<D, Windows::UI::Xaml::Controls::Primitives::IFlyoutShowOptionsFactory>
{
    int32_t WINRT_CALL CreateInstance(void* baseInterface, void** innerInterface, void** value) noexcept final
    {
        try
        {
            if (innerInterface) *innerInterface = nullptr;
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            Windows::Foundation::IInspectable __local_innerInterface;
            WINRT_ASSERT_DECLARATION(CreateInstance, WINRT_WRAP(Windows::UI::Xaml::Controls::Primitives::FlyoutShowOptions), Windows::Foundation::IInspectable const&, Windows::Foundation::IInspectable&);
            *value = detach_from<Windows::UI::Xaml::Controls::Primitives::FlyoutShowOptions>(this->shim().CreateInstance(*reinterpret_cast<Windows::Foundation::IInspectable const*>(&baseInterface), __local_innerInterface));
            if (innerInterface) *innerInterface = detach_abi(__local_innerInterface);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Xaml::Controls::Primitives::IGeneratorPositionHelper> : produce_base<D, Windows::UI::Xaml::Controls::Primitives::IGeneratorPositionHelper>
{};

template <typename D>
struct produce<D, Windows::UI::Xaml::Controls::Primitives::IGeneratorPositionHelperStatics> : produce_base<D, Windows::UI::Xaml::Controls::Primitives::IGeneratorPositionHelperStatics>
{
    int32_t WINRT_CALL FromIndexAndOffset(int32_t index, int32_t offset, struct struct_Windows_UI_Xaml_Controls_Primitives_GeneratorPosition* result) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(FromIndexAndOffset, WINRT_WRAP(Windows::UI::Xaml::Controls::Primitives::GeneratorPosition), int32_t, int32_t);
            *result = detach_from<Windows::UI::Xaml::Controls::Primitives::GeneratorPosition>(this->shim().FromIndexAndOffset(index, offset));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Xaml::Controls::Primitives::IGridViewItemPresenter> : produce_base<D, Windows::UI::Xaml::Controls::Primitives::IGridViewItemPresenter>
{
    int32_t WINRT_CALL get_SelectionCheckMarkVisualEnabled(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SelectionCheckMarkVisualEnabled, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().SelectionCheckMarkVisualEnabled());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_SelectionCheckMarkVisualEnabled(bool value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SelectionCheckMarkVisualEnabled, WINRT_WRAP(void), bool);
            this->shim().SelectionCheckMarkVisualEnabled(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_CheckHintBrush(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CheckHintBrush, WINRT_WRAP(Windows::UI::Xaml::Media::Brush));
            *value = detach_from<Windows::UI::Xaml::Media::Brush>(this->shim().CheckHintBrush());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_CheckHintBrush(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CheckHintBrush, WINRT_WRAP(void), Windows::UI::Xaml::Media::Brush const&);
            this->shim().CheckHintBrush(*reinterpret_cast<Windows::UI::Xaml::Media::Brush const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_CheckSelectingBrush(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CheckSelectingBrush, WINRT_WRAP(Windows::UI::Xaml::Media::Brush));
            *value = detach_from<Windows::UI::Xaml::Media::Brush>(this->shim().CheckSelectingBrush());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_CheckSelectingBrush(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CheckSelectingBrush, WINRT_WRAP(void), Windows::UI::Xaml::Media::Brush const&);
            this->shim().CheckSelectingBrush(*reinterpret_cast<Windows::UI::Xaml::Media::Brush const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_CheckBrush(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CheckBrush, WINRT_WRAP(Windows::UI::Xaml::Media::Brush));
            *value = detach_from<Windows::UI::Xaml::Media::Brush>(this->shim().CheckBrush());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_CheckBrush(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CheckBrush, WINRT_WRAP(void), Windows::UI::Xaml::Media::Brush const&);
            this->shim().CheckBrush(*reinterpret_cast<Windows::UI::Xaml::Media::Brush const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_DragBackground(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(DragBackground, WINRT_WRAP(Windows::UI::Xaml::Media::Brush));
            *value = detach_from<Windows::UI::Xaml::Media::Brush>(this->shim().DragBackground());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_DragBackground(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(DragBackground, WINRT_WRAP(void), Windows::UI::Xaml::Media::Brush const&);
            this->shim().DragBackground(*reinterpret_cast<Windows::UI::Xaml::Media::Brush const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_DragForeground(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(DragForeground, WINRT_WRAP(Windows::UI::Xaml::Media::Brush));
            *value = detach_from<Windows::UI::Xaml::Media::Brush>(this->shim().DragForeground());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_DragForeground(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(DragForeground, WINRT_WRAP(void), Windows::UI::Xaml::Media::Brush const&);
            this->shim().DragForeground(*reinterpret_cast<Windows::UI::Xaml::Media::Brush const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_FocusBorderBrush(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(FocusBorderBrush, WINRT_WRAP(Windows::UI::Xaml::Media::Brush));
            *value = detach_from<Windows::UI::Xaml::Media::Brush>(this->shim().FocusBorderBrush());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_FocusBorderBrush(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(FocusBorderBrush, WINRT_WRAP(void), Windows::UI::Xaml::Media::Brush const&);
            this->shim().FocusBorderBrush(*reinterpret_cast<Windows::UI::Xaml::Media::Brush const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_PlaceholderBackground(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(PlaceholderBackground, WINRT_WRAP(Windows::UI::Xaml::Media::Brush));
            *value = detach_from<Windows::UI::Xaml::Media::Brush>(this->shim().PlaceholderBackground());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_PlaceholderBackground(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(PlaceholderBackground, WINRT_WRAP(void), Windows::UI::Xaml::Media::Brush const&);
            this->shim().PlaceholderBackground(*reinterpret_cast<Windows::UI::Xaml::Media::Brush const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_PointerOverBackground(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(PointerOverBackground, WINRT_WRAP(Windows::UI::Xaml::Media::Brush));
            *value = detach_from<Windows::UI::Xaml::Media::Brush>(this->shim().PointerOverBackground());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_PointerOverBackground(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(PointerOverBackground, WINRT_WRAP(void), Windows::UI::Xaml::Media::Brush const&);
            this->shim().PointerOverBackground(*reinterpret_cast<Windows::UI::Xaml::Media::Brush const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_SelectedBackground(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SelectedBackground, WINRT_WRAP(Windows::UI::Xaml::Media::Brush));
            *value = detach_from<Windows::UI::Xaml::Media::Brush>(this->shim().SelectedBackground());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_SelectedBackground(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SelectedBackground, WINRT_WRAP(void), Windows::UI::Xaml::Media::Brush const&);
            this->shim().SelectedBackground(*reinterpret_cast<Windows::UI::Xaml::Media::Brush const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_SelectedForeground(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SelectedForeground, WINRT_WRAP(Windows::UI::Xaml::Media::Brush));
            *value = detach_from<Windows::UI::Xaml::Media::Brush>(this->shim().SelectedForeground());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_SelectedForeground(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SelectedForeground, WINRT_WRAP(void), Windows::UI::Xaml::Media::Brush const&);
            this->shim().SelectedForeground(*reinterpret_cast<Windows::UI::Xaml::Media::Brush const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_SelectedPointerOverBackground(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SelectedPointerOverBackground, WINRT_WRAP(Windows::UI::Xaml::Media::Brush));
            *value = detach_from<Windows::UI::Xaml::Media::Brush>(this->shim().SelectedPointerOverBackground());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_SelectedPointerOverBackground(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SelectedPointerOverBackground, WINRT_WRAP(void), Windows::UI::Xaml::Media::Brush const&);
            this->shim().SelectedPointerOverBackground(*reinterpret_cast<Windows::UI::Xaml::Media::Brush const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_SelectedPointerOverBorderBrush(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SelectedPointerOverBorderBrush, WINRT_WRAP(Windows::UI::Xaml::Media::Brush));
            *value = detach_from<Windows::UI::Xaml::Media::Brush>(this->shim().SelectedPointerOverBorderBrush());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_SelectedPointerOverBorderBrush(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SelectedPointerOverBorderBrush, WINRT_WRAP(void), Windows::UI::Xaml::Media::Brush const&);
            this->shim().SelectedPointerOverBorderBrush(*reinterpret_cast<Windows::UI::Xaml::Media::Brush const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_SelectedBorderThickness(struct struct_Windows_UI_Xaml_Thickness* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SelectedBorderThickness, WINRT_WRAP(Windows::UI::Xaml::Thickness));
            *value = detach_from<Windows::UI::Xaml::Thickness>(this->shim().SelectedBorderThickness());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_SelectedBorderThickness(struct struct_Windows_UI_Xaml_Thickness value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SelectedBorderThickness, WINRT_WRAP(void), Windows::UI::Xaml::Thickness const&);
            this->shim().SelectedBorderThickness(*reinterpret_cast<Windows::UI::Xaml::Thickness const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_DisabledOpacity(double* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(DisabledOpacity, WINRT_WRAP(double));
            *value = detach_from<double>(this->shim().DisabledOpacity());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_DisabledOpacity(double value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(DisabledOpacity, WINRT_WRAP(void), double);
            this->shim().DisabledOpacity(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_DragOpacity(double* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(DragOpacity, WINRT_WRAP(double));
            *value = detach_from<double>(this->shim().DragOpacity());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_DragOpacity(double value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(DragOpacity, WINRT_WRAP(void), double);
            this->shim().DragOpacity(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_ReorderHintOffset(double* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ReorderHintOffset, WINRT_WRAP(double));
            *value = detach_from<double>(this->shim().ReorderHintOffset());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_ReorderHintOffset(double value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ReorderHintOffset, WINRT_WRAP(void), double);
            this->shim().ReorderHintOffset(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_GridViewItemPresenterHorizontalContentAlignment(Windows::UI::Xaml::HorizontalAlignment* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GridViewItemPresenterHorizontalContentAlignment, WINRT_WRAP(Windows::UI::Xaml::HorizontalAlignment));
            *value = detach_from<Windows::UI::Xaml::HorizontalAlignment>(this->shim().GridViewItemPresenterHorizontalContentAlignment());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_GridViewItemPresenterHorizontalContentAlignment(Windows::UI::Xaml::HorizontalAlignment value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GridViewItemPresenterHorizontalContentAlignment, WINRT_WRAP(void), Windows::UI::Xaml::HorizontalAlignment const&);
            this->shim().GridViewItemPresenterHorizontalContentAlignment(*reinterpret_cast<Windows::UI::Xaml::HorizontalAlignment const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_GridViewItemPresenterVerticalContentAlignment(Windows::UI::Xaml::VerticalAlignment* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GridViewItemPresenterVerticalContentAlignment, WINRT_WRAP(Windows::UI::Xaml::VerticalAlignment));
            *value = detach_from<Windows::UI::Xaml::VerticalAlignment>(this->shim().GridViewItemPresenterVerticalContentAlignment());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_GridViewItemPresenterVerticalContentAlignment(Windows::UI::Xaml::VerticalAlignment value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GridViewItemPresenterVerticalContentAlignment, WINRT_WRAP(void), Windows::UI::Xaml::VerticalAlignment const&);
            this->shim().GridViewItemPresenterVerticalContentAlignment(*reinterpret_cast<Windows::UI::Xaml::VerticalAlignment const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_GridViewItemPresenterPadding(struct struct_Windows_UI_Xaml_Thickness* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GridViewItemPresenterPadding, WINRT_WRAP(Windows::UI::Xaml::Thickness));
            *value = detach_from<Windows::UI::Xaml::Thickness>(this->shim().GridViewItemPresenterPadding());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_GridViewItemPresenterPadding(struct struct_Windows_UI_Xaml_Thickness value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GridViewItemPresenterPadding, WINRT_WRAP(void), Windows::UI::Xaml::Thickness const&);
            this->shim().GridViewItemPresenterPadding(*reinterpret_cast<Windows::UI::Xaml::Thickness const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_PointerOverBackgroundMargin(struct struct_Windows_UI_Xaml_Thickness* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(PointerOverBackgroundMargin, WINRT_WRAP(Windows::UI::Xaml::Thickness));
            *value = detach_from<Windows::UI::Xaml::Thickness>(this->shim().PointerOverBackgroundMargin());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_PointerOverBackgroundMargin(struct struct_Windows_UI_Xaml_Thickness value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(PointerOverBackgroundMargin, WINRT_WRAP(void), Windows::UI::Xaml::Thickness const&);
            this->shim().PointerOverBackgroundMargin(*reinterpret_cast<Windows::UI::Xaml::Thickness const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_ContentMargin(struct struct_Windows_UI_Xaml_Thickness* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ContentMargin, WINRT_WRAP(Windows::UI::Xaml::Thickness));
            *value = detach_from<Windows::UI::Xaml::Thickness>(this->shim().ContentMargin());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_ContentMargin(struct struct_Windows_UI_Xaml_Thickness value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ContentMargin, WINRT_WRAP(void), Windows::UI::Xaml::Thickness const&);
            this->shim().ContentMargin(*reinterpret_cast<Windows::UI::Xaml::Thickness const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Xaml::Controls::Primitives::IGridViewItemPresenterFactory> : produce_base<D, Windows::UI::Xaml::Controls::Primitives::IGridViewItemPresenterFactory>
{
    int32_t WINRT_CALL CreateInstance(void* baseInterface, void** innerInterface, void** value) noexcept final
    {
        try
        {
            if (innerInterface) *innerInterface = nullptr;
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            Windows::Foundation::IInspectable __local_innerInterface;
            WINRT_ASSERT_DECLARATION(CreateInstance, WINRT_WRAP(Windows::UI::Xaml::Controls::Primitives::GridViewItemPresenter), Windows::Foundation::IInspectable const&, Windows::Foundation::IInspectable&);
            *value = detach_from<Windows::UI::Xaml::Controls::Primitives::GridViewItemPresenter>(this->shim().CreateInstance(*reinterpret_cast<Windows::Foundation::IInspectable const*>(&baseInterface), __local_innerInterface));
            if (innerInterface) *innerInterface = detach_abi(__local_innerInterface);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Xaml::Controls::Primitives::IGridViewItemPresenterStatics> : produce_base<D, Windows::UI::Xaml::Controls::Primitives::IGridViewItemPresenterStatics>
{
    int32_t WINRT_CALL get_SelectionCheckMarkVisualEnabledProperty(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SelectionCheckMarkVisualEnabledProperty, WINRT_WRAP(Windows::UI::Xaml::DependencyProperty));
            *value = detach_from<Windows::UI::Xaml::DependencyProperty>(this->shim().SelectionCheckMarkVisualEnabledProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_CheckHintBrushProperty(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CheckHintBrushProperty, WINRT_WRAP(Windows::UI::Xaml::DependencyProperty));
            *value = detach_from<Windows::UI::Xaml::DependencyProperty>(this->shim().CheckHintBrushProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_CheckSelectingBrushProperty(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CheckSelectingBrushProperty, WINRT_WRAP(Windows::UI::Xaml::DependencyProperty));
            *value = detach_from<Windows::UI::Xaml::DependencyProperty>(this->shim().CheckSelectingBrushProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_CheckBrushProperty(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CheckBrushProperty, WINRT_WRAP(Windows::UI::Xaml::DependencyProperty));
            *value = detach_from<Windows::UI::Xaml::DependencyProperty>(this->shim().CheckBrushProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_DragBackgroundProperty(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(DragBackgroundProperty, WINRT_WRAP(Windows::UI::Xaml::DependencyProperty));
            *value = detach_from<Windows::UI::Xaml::DependencyProperty>(this->shim().DragBackgroundProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_DragForegroundProperty(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(DragForegroundProperty, WINRT_WRAP(Windows::UI::Xaml::DependencyProperty));
            *value = detach_from<Windows::UI::Xaml::DependencyProperty>(this->shim().DragForegroundProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_FocusBorderBrushProperty(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(FocusBorderBrushProperty, WINRT_WRAP(Windows::UI::Xaml::DependencyProperty));
            *value = detach_from<Windows::UI::Xaml::DependencyProperty>(this->shim().FocusBorderBrushProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_PlaceholderBackgroundProperty(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(PlaceholderBackgroundProperty, WINRT_WRAP(Windows::UI::Xaml::DependencyProperty));
            *value = detach_from<Windows::UI::Xaml::DependencyProperty>(this->shim().PlaceholderBackgroundProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_PointerOverBackgroundProperty(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(PointerOverBackgroundProperty, WINRT_WRAP(Windows::UI::Xaml::DependencyProperty));
            *value = detach_from<Windows::UI::Xaml::DependencyProperty>(this->shim().PointerOverBackgroundProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_SelectedBackgroundProperty(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SelectedBackgroundProperty, WINRT_WRAP(Windows::UI::Xaml::DependencyProperty));
            *value = detach_from<Windows::UI::Xaml::DependencyProperty>(this->shim().SelectedBackgroundProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_SelectedForegroundProperty(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SelectedForegroundProperty, WINRT_WRAP(Windows::UI::Xaml::DependencyProperty));
            *value = detach_from<Windows::UI::Xaml::DependencyProperty>(this->shim().SelectedForegroundProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_SelectedPointerOverBackgroundProperty(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SelectedPointerOverBackgroundProperty, WINRT_WRAP(Windows::UI::Xaml::DependencyProperty));
            *value = detach_from<Windows::UI::Xaml::DependencyProperty>(this->shim().SelectedPointerOverBackgroundProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_SelectedPointerOverBorderBrushProperty(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SelectedPointerOverBorderBrushProperty, WINRT_WRAP(Windows::UI::Xaml::DependencyProperty));
            *value = detach_from<Windows::UI::Xaml::DependencyProperty>(this->shim().SelectedPointerOverBorderBrushProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_SelectedBorderThicknessProperty(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SelectedBorderThicknessProperty, WINRT_WRAP(Windows::UI::Xaml::DependencyProperty));
            *value = detach_from<Windows::UI::Xaml::DependencyProperty>(this->shim().SelectedBorderThicknessProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_DisabledOpacityProperty(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(DisabledOpacityProperty, WINRT_WRAP(Windows::UI::Xaml::DependencyProperty));
            *value = detach_from<Windows::UI::Xaml::DependencyProperty>(this->shim().DisabledOpacityProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_DragOpacityProperty(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(DragOpacityProperty, WINRT_WRAP(Windows::UI::Xaml::DependencyProperty));
            *value = detach_from<Windows::UI::Xaml::DependencyProperty>(this->shim().DragOpacityProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_ReorderHintOffsetProperty(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ReorderHintOffsetProperty, WINRT_WRAP(Windows::UI::Xaml::DependencyProperty));
            *value = detach_from<Windows::UI::Xaml::DependencyProperty>(this->shim().ReorderHintOffsetProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_GridViewItemPresenterHorizontalContentAlignmentProperty(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GridViewItemPresenterHorizontalContentAlignmentProperty, WINRT_WRAP(Windows::UI::Xaml::DependencyProperty));
            *value = detach_from<Windows::UI::Xaml::DependencyProperty>(this->shim().GridViewItemPresenterHorizontalContentAlignmentProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_GridViewItemPresenterVerticalContentAlignmentProperty(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GridViewItemPresenterVerticalContentAlignmentProperty, WINRT_WRAP(Windows::UI::Xaml::DependencyProperty));
            *value = detach_from<Windows::UI::Xaml::DependencyProperty>(this->shim().GridViewItemPresenterVerticalContentAlignmentProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_GridViewItemPresenterPaddingProperty(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GridViewItemPresenterPaddingProperty, WINRT_WRAP(Windows::UI::Xaml::DependencyProperty));
            *value = detach_from<Windows::UI::Xaml::DependencyProperty>(this->shim().GridViewItemPresenterPaddingProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_PointerOverBackgroundMarginProperty(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(PointerOverBackgroundMarginProperty, WINRT_WRAP(Windows::UI::Xaml::DependencyProperty));
            *value = detach_from<Windows::UI::Xaml::DependencyProperty>(this->shim().PointerOverBackgroundMarginProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_ContentMarginProperty(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ContentMarginProperty, WINRT_WRAP(Windows::UI::Xaml::DependencyProperty));
            *value = detach_from<Windows::UI::Xaml::DependencyProperty>(this->shim().ContentMarginProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Xaml::Controls::Primitives::IGridViewItemTemplateSettings> : produce_base<D, Windows::UI::Xaml::Controls::Primitives::IGridViewItemTemplateSettings>
{
    int32_t WINRT_CALL get_DragItemsCount(int32_t* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(DragItemsCount, WINRT_WRAP(int32_t));
            *value = detach_from<int32_t>(this->shim().DragItemsCount());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Xaml::Controls::Primitives::IItemsChangedEventArgs> : produce_base<D, Windows::UI::Xaml::Controls::Primitives::IItemsChangedEventArgs>
{
    int32_t WINRT_CALL get_Action(int32_t* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Action, WINRT_WRAP(int32_t));
            *value = detach_from<int32_t>(this->shim().Action());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Position(struct struct_Windows_UI_Xaml_Controls_Primitives_GeneratorPosition* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Position, WINRT_WRAP(Windows::UI::Xaml::Controls::Primitives::GeneratorPosition));
            *value = detach_from<Windows::UI::Xaml::Controls::Primitives::GeneratorPosition>(this->shim().Position());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_OldPosition(struct struct_Windows_UI_Xaml_Controls_Primitives_GeneratorPosition* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(OldPosition, WINRT_WRAP(Windows::UI::Xaml::Controls::Primitives::GeneratorPosition));
            *value = detach_from<Windows::UI::Xaml::Controls::Primitives::GeneratorPosition>(this->shim().OldPosition());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_ItemCount(int32_t* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ItemCount, WINRT_WRAP(int32_t));
            *value = detach_from<int32_t>(this->shim().ItemCount());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_ItemUICount(int32_t* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ItemUICount, WINRT_WRAP(int32_t));
            *value = detach_from<int32_t>(this->shim().ItemUICount());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Xaml::Controls::Primitives::IJumpListItemBackgroundConverter> : produce_base<D, Windows::UI::Xaml::Controls::Primitives::IJumpListItemBackgroundConverter>
{
    int32_t WINRT_CALL get_Enabled(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Enabled, WINRT_WRAP(Windows::UI::Xaml::Media::Brush));
            *value = detach_from<Windows::UI::Xaml::Media::Brush>(this->shim().Enabled());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_Enabled(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Enabled, WINRT_WRAP(void), Windows::UI::Xaml::Media::Brush const&);
            this->shim().Enabled(*reinterpret_cast<Windows::UI::Xaml::Media::Brush const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Disabled(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Disabled, WINRT_WRAP(Windows::UI::Xaml::Media::Brush));
            *value = detach_from<Windows::UI::Xaml::Media::Brush>(this->shim().Disabled());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_Disabled(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Disabled, WINRT_WRAP(void), Windows::UI::Xaml::Media::Brush const&);
            this->shim().Disabled(*reinterpret_cast<Windows::UI::Xaml::Media::Brush const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Xaml::Controls::Primitives::IJumpListItemBackgroundConverterStatics> : produce_base<D, Windows::UI::Xaml::Controls::Primitives::IJumpListItemBackgroundConverterStatics>
{
    int32_t WINRT_CALL get_EnabledProperty(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(EnabledProperty, WINRT_WRAP(Windows::UI::Xaml::DependencyProperty));
            *value = detach_from<Windows::UI::Xaml::DependencyProperty>(this->shim().EnabledProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_DisabledProperty(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(DisabledProperty, WINRT_WRAP(Windows::UI::Xaml::DependencyProperty));
            *value = detach_from<Windows::UI::Xaml::DependencyProperty>(this->shim().DisabledProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Xaml::Controls::Primitives::IJumpListItemForegroundConverter> : produce_base<D, Windows::UI::Xaml::Controls::Primitives::IJumpListItemForegroundConverter>
{
    int32_t WINRT_CALL get_Enabled(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Enabled, WINRT_WRAP(Windows::UI::Xaml::Media::Brush));
            *value = detach_from<Windows::UI::Xaml::Media::Brush>(this->shim().Enabled());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_Enabled(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Enabled, WINRT_WRAP(void), Windows::UI::Xaml::Media::Brush const&);
            this->shim().Enabled(*reinterpret_cast<Windows::UI::Xaml::Media::Brush const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Disabled(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Disabled, WINRT_WRAP(Windows::UI::Xaml::Media::Brush));
            *value = detach_from<Windows::UI::Xaml::Media::Brush>(this->shim().Disabled());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_Disabled(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Disabled, WINRT_WRAP(void), Windows::UI::Xaml::Media::Brush const&);
            this->shim().Disabled(*reinterpret_cast<Windows::UI::Xaml::Media::Brush const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Xaml::Controls::Primitives::IJumpListItemForegroundConverterStatics> : produce_base<D, Windows::UI::Xaml::Controls::Primitives::IJumpListItemForegroundConverterStatics>
{
    int32_t WINRT_CALL get_EnabledProperty(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(EnabledProperty, WINRT_WRAP(Windows::UI::Xaml::DependencyProperty));
            *value = detach_from<Windows::UI::Xaml::DependencyProperty>(this->shim().EnabledProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_DisabledProperty(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(DisabledProperty, WINRT_WRAP(Windows::UI::Xaml::DependencyProperty));
            *value = detach_from<Windows::UI::Xaml::DependencyProperty>(this->shim().DisabledProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Xaml::Controls::Primitives::ILayoutInformation> : produce_base<D, Windows::UI::Xaml::Controls::Primitives::ILayoutInformation>
{};

template <typename D>
struct produce<D, Windows::UI::Xaml::Controls::Primitives::ILayoutInformationStatics> : produce_base<D, Windows::UI::Xaml::Controls::Primitives::ILayoutInformationStatics>
{
    int32_t WINRT_CALL GetLayoutExceptionElement(void* dispatcher, void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetLayoutExceptionElement, WINRT_WRAP(Windows::UI::Xaml::UIElement), Windows::Foundation::IInspectable const&);
            *result = detach_from<Windows::UI::Xaml::UIElement>(this->shim().GetLayoutExceptionElement(*reinterpret_cast<Windows::Foundation::IInspectable const*>(&dispatcher)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL GetLayoutSlot(void* element, Windows::Foundation::Rect* result) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetLayoutSlot, WINRT_WRAP(Windows::Foundation::Rect), Windows::UI::Xaml::FrameworkElement const&);
            *result = detach_from<Windows::Foundation::Rect>(this->shim().GetLayoutSlot(*reinterpret_cast<Windows::UI::Xaml::FrameworkElement const*>(&element)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Xaml::Controls::Primitives::ILayoutInformationStatics2> : produce_base<D, Windows::UI::Xaml::Controls::Primitives::ILayoutInformationStatics2>
{
    int32_t WINRT_CALL GetAvailableSize(void* element, Windows::Foundation::Size* result) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetAvailableSize, WINRT_WRAP(Windows::Foundation::Size), Windows::UI::Xaml::UIElement const&);
            *result = detach_from<Windows::Foundation::Size>(this->shim().GetAvailableSize(*reinterpret_cast<Windows::UI::Xaml::UIElement const*>(&element)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Xaml::Controls::Primitives::IListViewItemPresenter> : produce_base<D, Windows::UI::Xaml::Controls::Primitives::IListViewItemPresenter>
{
    int32_t WINRT_CALL get_SelectionCheckMarkVisualEnabled(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SelectionCheckMarkVisualEnabled, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().SelectionCheckMarkVisualEnabled());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_SelectionCheckMarkVisualEnabled(bool value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SelectionCheckMarkVisualEnabled, WINRT_WRAP(void), bool);
            this->shim().SelectionCheckMarkVisualEnabled(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_CheckHintBrush(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CheckHintBrush, WINRT_WRAP(Windows::UI::Xaml::Media::Brush));
            *value = detach_from<Windows::UI::Xaml::Media::Brush>(this->shim().CheckHintBrush());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_CheckHintBrush(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CheckHintBrush, WINRT_WRAP(void), Windows::UI::Xaml::Media::Brush const&);
            this->shim().CheckHintBrush(*reinterpret_cast<Windows::UI::Xaml::Media::Brush const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_CheckSelectingBrush(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CheckSelectingBrush, WINRT_WRAP(Windows::UI::Xaml::Media::Brush));
            *value = detach_from<Windows::UI::Xaml::Media::Brush>(this->shim().CheckSelectingBrush());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_CheckSelectingBrush(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CheckSelectingBrush, WINRT_WRAP(void), Windows::UI::Xaml::Media::Brush const&);
            this->shim().CheckSelectingBrush(*reinterpret_cast<Windows::UI::Xaml::Media::Brush const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_CheckBrush(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CheckBrush, WINRT_WRAP(Windows::UI::Xaml::Media::Brush));
            *value = detach_from<Windows::UI::Xaml::Media::Brush>(this->shim().CheckBrush());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_CheckBrush(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CheckBrush, WINRT_WRAP(void), Windows::UI::Xaml::Media::Brush const&);
            this->shim().CheckBrush(*reinterpret_cast<Windows::UI::Xaml::Media::Brush const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_DragBackground(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(DragBackground, WINRT_WRAP(Windows::UI::Xaml::Media::Brush));
            *value = detach_from<Windows::UI::Xaml::Media::Brush>(this->shim().DragBackground());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_DragBackground(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(DragBackground, WINRT_WRAP(void), Windows::UI::Xaml::Media::Brush const&);
            this->shim().DragBackground(*reinterpret_cast<Windows::UI::Xaml::Media::Brush const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_DragForeground(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(DragForeground, WINRT_WRAP(Windows::UI::Xaml::Media::Brush));
            *value = detach_from<Windows::UI::Xaml::Media::Brush>(this->shim().DragForeground());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_DragForeground(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(DragForeground, WINRT_WRAP(void), Windows::UI::Xaml::Media::Brush const&);
            this->shim().DragForeground(*reinterpret_cast<Windows::UI::Xaml::Media::Brush const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_FocusBorderBrush(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(FocusBorderBrush, WINRT_WRAP(Windows::UI::Xaml::Media::Brush));
            *value = detach_from<Windows::UI::Xaml::Media::Brush>(this->shim().FocusBorderBrush());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_FocusBorderBrush(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(FocusBorderBrush, WINRT_WRAP(void), Windows::UI::Xaml::Media::Brush const&);
            this->shim().FocusBorderBrush(*reinterpret_cast<Windows::UI::Xaml::Media::Brush const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_PlaceholderBackground(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(PlaceholderBackground, WINRT_WRAP(Windows::UI::Xaml::Media::Brush));
            *value = detach_from<Windows::UI::Xaml::Media::Brush>(this->shim().PlaceholderBackground());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_PlaceholderBackground(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(PlaceholderBackground, WINRT_WRAP(void), Windows::UI::Xaml::Media::Brush const&);
            this->shim().PlaceholderBackground(*reinterpret_cast<Windows::UI::Xaml::Media::Brush const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_PointerOverBackground(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(PointerOverBackground, WINRT_WRAP(Windows::UI::Xaml::Media::Brush));
            *value = detach_from<Windows::UI::Xaml::Media::Brush>(this->shim().PointerOverBackground());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_PointerOverBackground(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(PointerOverBackground, WINRT_WRAP(void), Windows::UI::Xaml::Media::Brush const&);
            this->shim().PointerOverBackground(*reinterpret_cast<Windows::UI::Xaml::Media::Brush const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_SelectedBackground(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SelectedBackground, WINRT_WRAP(Windows::UI::Xaml::Media::Brush));
            *value = detach_from<Windows::UI::Xaml::Media::Brush>(this->shim().SelectedBackground());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_SelectedBackground(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SelectedBackground, WINRT_WRAP(void), Windows::UI::Xaml::Media::Brush const&);
            this->shim().SelectedBackground(*reinterpret_cast<Windows::UI::Xaml::Media::Brush const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_SelectedForeground(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SelectedForeground, WINRT_WRAP(Windows::UI::Xaml::Media::Brush));
            *value = detach_from<Windows::UI::Xaml::Media::Brush>(this->shim().SelectedForeground());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_SelectedForeground(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SelectedForeground, WINRT_WRAP(void), Windows::UI::Xaml::Media::Brush const&);
            this->shim().SelectedForeground(*reinterpret_cast<Windows::UI::Xaml::Media::Brush const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_SelectedPointerOverBackground(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SelectedPointerOverBackground, WINRT_WRAP(Windows::UI::Xaml::Media::Brush));
            *value = detach_from<Windows::UI::Xaml::Media::Brush>(this->shim().SelectedPointerOverBackground());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_SelectedPointerOverBackground(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SelectedPointerOverBackground, WINRT_WRAP(void), Windows::UI::Xaml::Media::Brush const&);
            this->shim().SelectedPointerOverBackground(*reinterpret_cast<Windows::UI::Xaml::Media::Brush const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_SelectedPointerOverBorderBrush(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SelectedPointerOverBorderBrush, WINRT_WRAP(Windows::UI::Xaml::Media::Brush));
            *value = detach_from<Windows::UI::Xaml::Media::Brush>(this->shim().SelectedPointerOverBorderBrush());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_SelectedPointerOverBorderBrush(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SelectedPointerOverBorderBrush, WINRT_WRAP(void), Windows::UI::Xaml::Media::Brush const&);
            this->shim().SelectedPointerOverBorderBrush(*reinterpret_cast<Windows::UI::Xaml::Media::Brush const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_SelectedBorderThickness(struct struct_Windows_UI_Xaml_Thickness* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SelectedBorderThickness, WINRT_WRAP(Windows::UI::Xaml::Thickness));
            *value = detach_from<Windows::UI::Xaml::Thickness>(this->shim().SelectedBorderThickness());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_SelectedBorderThickness(struct struct_Windows_UI_Xaml_Thickness value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SelectedBorderThickness, WINRT_WRAP(void), Windows::UI::Xaml::Thickness const&);
            this->shim().SelectedBorderThickness(*reinterpret_cast<Windows::UI::Xaml::Thickness const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_DisabledOpacity(double* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(DisabledOpacity, WINRT_WRAP(double));
            *value = detach_from<double>(this->shim().DisabledOpacity());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_DisabledOpacity(double value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(DisabledOpacity, WINRT_WRAP(void), double);
            this->shim().DisabledOpacity(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_DragOpacity(double* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(DragOpacity, WINRT_WRAP(double));
            *value = detach_from<double>(this->shim().DragOpacity());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_DragOpacity(double value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(DragOpacity, WINRT_WRAP(void), double);
            this->shim().DragOpacity(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_ReorderHintOffset(double* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ReorderHintOffset, WINRT_WRAP(double));
            *value = detach_from<double>(this->shim().ReorderHintOffset());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_ReorderHintOffset(double value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ReorderHintOffset, WINRT_WRAP(void), double);
            this->shim().ReorderHintOffset(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_ListViewItemPresenterHorizontalContentAlignment(Windows::UI::Xaml::HorizontalAlignment* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ListViewItemPresenterHorizontalContentAlignment, WINRT_WRAP(Windows::UI::Xaml::HorizontalAlignment));
            *value = detach_from<Windows::UI::Xaml::HorizontalAlignment>(this->shim().ListViewItemPresenterHorizontalContentAlignment());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_ListViewItemPresenterHorizontalContentAlignment(Windows::UI::Xaml::HorizontalAlignment value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ListViewItemPresenterHorizontalContentAlignment, WINRT_WRAP(void), Windows::UI::Xaml::HorizontalAlignment const&);
            this->shim().ListViewItemPresenterHorizontalContentAlignment(*reinterpret_cast<Windows::UI::Xaml::HorizontalAlignment const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_ListViewItemPresenterVerticalContentAlignment(Windows::UI::Xaml::VerticalAlignment* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ListViewItemPresenterVerticalContentAlignment, WINRT_WRAP(Windows::UI::Xaml::VerticalAlignment));
            *value = detach_from<Windows::UI::Xaml::VerticalAlignment>(this->shim().ListViewItemPresenterVerticalContentAlignment());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_ListViewItemPresenterVerticalContentAlignment(Windows::UI::Xaml::VerticalAlignment value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ListViewItemPresenterVerticalContentAlignment, WINRT_WRAP(void), Windows::UI::Xaml::VerticalAlignment const&);
            this->shim().ListViewItemPresenterVerticalContentAlignment(*reinterpret_cast<Windows::UI::Xaml::VerticalAlignment const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_ListViewItemPresenterPadding(struct struct_Windows_UI_Xaml_Thickness* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ListViewItemPresenterPadding, WINRT_WRAP(Windows::UI::Xaml::Thickness));
            *value = detach_from<Windows::UI::Xaml::Thickness>(this->shim().ListViewItemPresenterPadding());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_ListViewItemPresenterPadding(struct struct_Windows_UI_Xaml_Thickness value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ListViewItemPresenterPadding, WINRT_WRAP(void), Windows::UI::Xaml::Thickness const&);
            this->shim().ListViewItemPresenterPadding(*reinterpret_cast<Windows::UI::Xaml::Thickness const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_PointerOverBackgroundMargin(struct struct_Windows_UI_Xaml_Thickness* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(PointerOverBackgroundMargin, WINRT_WRAP(Windows::UI::Xaml::Thickness));
            *value = detach_from<Windows::UI::Xaml::Thickness>(this->shim().PointerOverBackgroundMargin());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_PointerOverBackgroundMargin(struct struct_Windows_UI_Xaml_Thickness value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(PointerOverBackgroundMargin, WINRT_WRAP(void), Windows::UI::Xaml::Thickness const&);
            this->shim().PointerOverBackgroundMargin(*reinterpret_cast<Windows::UI::Xaml::Thickness const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_ContentMargin(struct struct_Windows_UI_Xaml_Thickness* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ContentMargin, WINRT_WRAP(Windows::UI::Xaml::Thickness));
            *value = detach_from<Windows::UI::Xaml::Thickness>(this->shim().ContentMargin());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_ContentMargin(struct struct_Windows_UI_Xaml_Thickness value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ContentMargin, WINRT_WRAP(void), Windows::UI::Xaml::Thickness const&);
            this->shim().ContentMargin(*reinterpret_cast<Windows::UI::Xaml::Thickness const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Xaml::Controls::Primitives::IListViewItemPresenter2> : produce_base<D, Windows::UI::Xaml::Controls::Primitives::IListViewItemPresenter2>
{
    int32_t WINRT_CALL get_SelectedPressedBackground(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SelectedPressedBackground, WINRT_WRAP(Windows::UI::Xaml::Media::Brush));
            *value = detach_from<Windows::UI::Xaml::Media::Brush>(this->shim().SelectedPressedBackground());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_SelectedPressedBackground(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SelectedPressedBackground, WINRT_WRAP(void), Windows::UI::Xaml::Media::Brush const&);
            this->shim().SelectedPressedBackground(*reinterpret_cast<Windows::UI::Xaml::Media::Brush const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_PressedBackground(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(PressedBackground, WINRT_WRAP(Windows::UI::Xaml::Media::Brush));
            *value = detach_from<Windows::UI::Xaml::Media::Brush>(this->shim().PressedBackground());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_PressedBackground(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(PressedBackground, WINRT_WRAP(void), Windows::UI::Xaml::Media::Brush const&);
            this->shim().PressedBackground(*reinterpret_cast<Windows::UI::Xaml::Media::Brush const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_CheckBoxBrush(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CheckBoxBrush, WINRT_WRAP(Windows::UI::Xaml::Media::Brush));
            *value = detach_from<Windows::UI::Xaml::Media::Brush>(this->shim().CheckBoxBrush());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_CheckBoxBrush(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CheckBoxBrush, WINRT_WRAP(void), Windows::UI::Xaml::Media::Brush const&);
            this->shim().CheckBoxBrush(*reinterpret_cast<Windows::UI::Xaml::Media::Brush const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_FocusSecondaryBorderBrush(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(FocusSecondaryBorderBrush, WINRT_WRAP(Windows::UI::Xaml::Media::Brush));
            *value = detach_from<Windows::UI::Xaml::Media::Brush>(this->shim().FocusSecondaryBorderBrush());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_FocusSecondaryBorderBrush(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(FocusSecondaryBorderBrush, WINRT_WRAP(void), Windows::UI::Xaml::Media::Brush const&);
            this->shim().FocusSecondaryBorderBrush(*reinterpret_cast<Windows::UI::Xaml::Media::Brush const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_CheckMode(Windows::UI::Xaml::Controls::Primitives::ListViewItemPresenterCheckMode* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CheckMode, WINRT_WRAP(Windows::UI::Xaml::Controls::Primitives::ListViewItemPresenterCheckMode));
            *value = detach_from<Windows::UI::Xaml::Controls::Primitives::ListViewItemPresenterCheckMode>(this->shim().CheckMode());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_CheckMode(Windows::UI::Xaml::Controls::Primitives::ListViewItemPresenterCheckMode value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CheckMode, WINRT_WRAP(void), Windows::UI::Xaml::Controls::Primitives::ListViewItemPresenterCheckMode const&);
            this->shim().CheckMode(*reinterpret_cast<Windows::UI::Xaml::Controls::Primitives::ListViewItemPresenterCheckMode const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_PointerOverForeground(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(PointerOverForeground, WINRT_WRAP(Windows::UI::Xaml::Media::Brush));
            *value = detach_from<Windows::UI::Xaml::Media::Brush>(this->shim().PointerOverForeground());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_PointerOverForeground(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(PointerOverForeground, WINRT_WRAP(void), Windows::UI::Xaml::Media::Brush const&);
            this->shim().PointerOverForeground(*reinterpret_cast<Windows::UI::Xaml::Media::Brush const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Xaml::Controls::Primitives::IListViewItemPresenter3> : produce_base<D, Windows::UI::Xaml::Controls::Primitives::IListViewItemPresenter3>
{
    int32_t WINRT_CALL get_RevealBackground(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(RevealBackground, WINRT_WRAP(Windows::UI::Xaml::Media::Brush));
            *value = detach_from<Windows::UI::Xaml::Media::Brush>(this->shim().RevealBackground());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_RevealBackground(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(RevealBackground, WINRT_WRAP(void), Windows::UI::Xaml::Media::Brush const&);
            this->shim().RevealBackground(*reinterpret_cast<Windows::UI::Xaml::Media::Brush const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_RevealBorderBrush(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(RevealBorderBrush, WINRT_WRAP(Windows::UI::Xaml::Media::Brush));
            *value = detach_from<Windows::UI::Xaml::Media::Brush>(this->shim().RevealBorderBrush());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_RevealBorderBrush(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(RevealBorderBrush, WINRT_WRAP(void), Windows::UI::Xaml::Media::Brush const&);
            this->shim().RevealBorderBrush(*reinterpret_cast<Windows::UI::Xaml::Media::Brush const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_RevealBorderThickness(struct struct_Windows_UI_Xaml_Thickness* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(RevealBorderThickness, WINRT_WRAP(Windows::UI::Xaml::Thickness));
            *value = detach_from<Windows::UI::Xaml::Thickness>(this->shim().RevealBorderThickness());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_RevealBorderThickness(struct struct_Windows_UI_Xaml_Thickness value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(RevealBorderThickness, WINRT_WRAP(void), Windows::UI::Xaml::Thickness const&);
            this->shim().RevealBorderThickness(*reinterpret_cast<Windows::UI::Xaml::Thickness const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_RevealBackgroundShowsAboveContent(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(RevealBackgroundShowsAboveContent, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().RevealBackgroundShowsAboveContent());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_RevealBackgroundShowsAboveContent(bool value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(RevealBackgroundShowsAboveContent, WINRT_WRAP(void), bool);
            this->shim().RevealBackgroundShowsAboveContent(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Xaml::Controls::Primitives::IListViewItemPresenterFactory> : produce_base<D, Windows::UI::Xaml::Controls::Primitives::IListViewItemPresenterFactory>
{
    int32_t WINRT_CALL CreateInstance(void* baseInterface, void** innerInterface, void** value) noexcept final
    {
        try
        {
            if (innerInterface) *innerInterface = nullptr;
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            Windows::Foundation::IInspectable __local_innerInterface;
            WINRT_ASSERT_DECLARATION(CreateInstance, WINRT_WRAP(Windows::UI::Xaml::Controls::Primitives::ListViewItemPresenter), Windows::Foundation::IInspectable const&, Windows::Foundation::IInspectable&);
            *value = detach_from<Windows::UI::Xaml::Controls::Primitives::ListViewItemPresenter>(this->shim().CreateInstance(*reinterpret_cast<Windows::Foundation::IInspectable const*>(&baseInterface), __local_innerInterface));
            if (innerInterface) *innerInterface = detach_abi(__local_innerInterface);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Xaml::Controls::Primitives::IListViewItemPresenterStatics> : produce_base<D, Windows::UI::Xaml::Controls::Primitives::IListViewItemPresenterStatics>
{
    int32_t WINRT_CALL get_SelectionCheckMarkVisualEnabledProperty(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SelectionCheckMarkVisualEnabledProperty, WINRT_WRAP(Windows::UI::Xaml::DependencyProperty));
            *value = detach_from<Windows::UI::Xaml::DependencyProperty>(this->shim().SelectionCheckMarkVisualEnabledProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_CheckHintBrushProperty(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CheckHintBrushProperty, WINRT_WRAP(Windows::UI::Xaml::DependencyProperty));
            *value = detach_from<Windows::UI::Xaml::DependencyProperty>(this->shim().CheckHintBrushProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_CheckSelectingBrushProperty(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CheckSelectingBrushProperty, WINRT_WRAP(Windows::UI::Xaml::DependencyProperty));
            *value = detach_from<Windows::UI::Xaml::DependencyProperty>(this->shim().CheckSelectingBrushProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_CheckBrushProperty(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CheckBrushProperty, WINRT_WRAP(Windows::UI::Xaml::DependencyProperty));
            *value = detach_from<Windows::UI::Xaml::DependencyProperty>(this->shim().CheckBrushProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_DragBackgroundProperty(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(DragBackgroundProperty, WINRT_WRAP(Windows::UI::Xaml::DependencyProperty));
            *value = detach_from<Windows::UI::Xaml::DependencyProperty>(this->shim().DragBackgroundProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_DragForegroundProperty(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(DragForegroundProperty, WINRT_WRAP(Windows::UI::Xaml::DependencyProperty));
            *value = detach_from<Windows::UI::Xaml::DependencyProperty>(this->shim().DragForegroundProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_FocusBorderBrushProperty(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(FocusBorderBrushProperty, WINRT_WRAP(Windows::UI::Xaml::DependencyProperty));
            *value = detach_from<Windows::UI::Xaml::DependencyProperty>(this->shim().FocusBorderBrushProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_PlaceholderBackgroundProperty(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(PlaceholderBackgroundProperty, WINRT_WRAP(Windows::UI::Xaml::DependencyProperty));
            *value = detach_from<Windows::UI::Xaml::DependencyProperty>(this->shim().PlaceholderBackgroundProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_PointerOverBackgroundProperty(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(PointerOverBackgroundProperty, WINRT_WRAP(Windows::UI::Xaml::DependencyProperty));
            *value = detach_from<Windows::UI::Xaml::DependencyProperty>(this->shim().PointerOverBackgroundProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_SelectedBackgroundProperty(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SelectedBackgroundProperty, WINRT_WRAP(Windows::UI::Xaml::DependencyProperty));
            *value = detach_from<Windows::UI::Xaml::DependencyProperty>(this->shim().SelectedBackgroundProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_SelectedForegroundProperty(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SelectedForegroundProperty, WINRT_WRAP(Windows::UI::Xaml::DependencyProperty));
            *value = detach_from<Windows::UI::Xaml::DependencyProperty>(this->shim().SelectedForegroundProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_SelectedPointerOverBackgroundProperty(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SelectedPointerOverBackgroundProperty, WINRT_WRAP(Windows::UI::Xaml::DependencyProperty));
            *value = detach_from<Windows::UI::Xaml::DependencyProperty>(this->shim().SelectedPointerOverBackgroundProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_SelectedPointerOverBorderBrushProperty(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SelectedPointerOverBorderBrushProperty, WINRT_WRAP(Windows::UI::Xaml::DependencyProperty));
            *value = detach_from<Windows::UI::Xaml::DependencyProperty>(this->shim().SelectedPointerOverBorderBrushProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_SelectedBorderThicknessProperty(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SelectedBorderThicknessProperty, WINRT_WRAP(Windows::UI::Xaml::DependencyProperty));
            *value = detach_from<Windows::UI::Xaml::DependencyProperty>(this->shim().SelectedBorderThicknessProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_DisabledOpacityProperty(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(DisabledOpacityProperty, WINRT_WRAP(Windows::UI::Xaml::DependencyProperty));
            *value = detach_from<Windows::UI::Xaml::DependencyProperty>(this->shim().DisabledOpacityProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_DragOpacityProperty(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(DragOpacityProperty, WINRT_WRAP(Windows::UI::Xaml::DependencyProperty));
            *value = detach_from<Windows::UI::Xaml::DependencyProperty>(this->shim().DragOpacityProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_ReorderHintOffsetProperty(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ReorderHintOffsetProperty, WINRT_WRAP(Windows::UI::Xaml::DependencyProperty));
            *value = detach_from<Windows::UI::Xaml::DependencyProperty>(this->shim().ReorderHintOffsetProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_ListViewItemPresenterHorizontalContentAlignmentProperty(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ListViewItemPresenterHorizontalContentAlignmentProperty, WINRT_WRAP(Windows::UI::Xaml::DependencyProperty));
            *value = detach_from<Windows::UI::Xaml::DependencyProperty>(this->shim().ListViewItemPresenterHorizontalContentAlignmentProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_ListViewItemPresenterVerticalContentAlignmentProperty(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ListViewItemPresenterVerticalContentAlignmentProperty, WINRT_WRAP(Windows::UI::Xaml::DependencyProperty));
            *value = detach_from<Windows::UI::Xaml::DependencyProperty>(this->shim().ListViewItemPresenterVerticalContentAlignmentProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_ListViewItemPresenterPaddingProperty(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ListViewItemPresenterPaddingProperty, WINRT_WRAP(Windows::UI::Xaml::DependencyProperty));
            *value = detach_from<Windows::UI::Xaml::DependencyProperty>(this->shim().ListViewItemPresenterPaddingProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_PointerOverBackgroundMarginProperty(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(PointerOverBackgroundMarginProperty, WINRT_WRAP(Windows::UI::Xaml::DependencyProperty));
            *value = detach_from<Windows::UI::Xaml::DependencyProperty>(this->shim().PointerOverBackgroundMarginProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_ContentMarginProperty(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ContentMarginProperty, WINRT_WRAP(Windows::UI::Xaml::DependencyProperty));
            *value = detach_from<Windows::UI::Xaml::DependencyProperty>(this->shim().ContentMarginProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Xaml::Controls::Primitives::IListViewItemPresenterStatics2> : produce_base<D, Windows::UI::Xaml::Controls::Primitives::IListViewItemPresenterStatics2>
{
    int32_t WINRT_CALL get_SelectedPressedBackgroundProperty(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SelectedPressedBackgroundProperty, WINRT_WRAP(Windows::UI::Xaml::DependencyProperty));
            *value = detach_from<Windows::UI::Xaml::DependencyProperty>(this->shim().SelectedPressedBackgroundProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_PressedBackgroundProperty(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(PressedBackgroundProperty, WINRT_WRAP(Windows::UI::Xaml::DependencyProperty));
            *value = detach_from<Windows::UI::Xaml::DependencyProperty>(this->shim().PressedBackgroundProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_CheckBoxBrushProperty(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CheckBoxBrushProperty, WINRT_WRAP(Windows::UI::Xaml::DependencyProperty));
            *value = detach_from<Windows::UI::Xaml::DependencyProperty>(this->shim().CheckBoxBrushProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_FocusSecondaryBorderBrushProperty(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(FocusSecondaryBorderBrushProperty, WINRT_WRAP(Windows::UI::Xaml::DependencyProperty));
            *value = detach_from<Windows::UI::Xaml::DependencyProperty>(this->shim().FocusSecondaryBorderBrushProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_CheckModeProperty(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CheckModeProperty, WINRT_WRAP(Windows::UI::Xaml::DependencyProperty));
            *value = detach_from<Windows::UI::Xaml::DependencyProperty>(this->shim().CheckModeProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_PointerOverForegroundProperty(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(PointerOverForegroundProperty, WINRT_WRAP(Windows::UI::Xaml::DependencyProperty));
            *value = detach_from<Windows::UI::Xaml::DependencyProperty>(this->shim().PointerOverForegroundProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Xaml::Controls::Primitives::IListViewItemPresenterStatics3> : produce_base<D, Windows::UI::Xaml::Controls::Primitives::IListViewItemPresenterStatics3>
{
    int32_t WINRT_CALL get_RevealBackgroundProperty(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(RevealBackgroundProperty, WINRT_WRAP(Windows::UI::Xaml::DependencyProperty));
            *value = detach_from<Windows::UI::Xaml::DependencyProperty>(this->shim().RevealBackgroundProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_RevealBorderBrushProperty(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(RevealBorderBrushProperty, WINRT_WRAP(Windows::UI::Xaml::DependencyProperty));
            *value = detach_from<Windows::UI::Xaml::DependencyProperty>(this->shim().RevealBorderBrushProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_RevealBorderThicknessProperty(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(RevealBorderThicknessProperty, WINRT_WRAP(Windows::UI::Xaml::DependencyProperty));
            *value = detach_from<Windows::UI::Xaml::DependencyProperty>(this->shim().RevealBorderThicknessProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_RevealBackgroundShowsAboveContentProperty(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(RevealBackgroundShowsAboveContentProperty, WINRT_WRAP(Windows::UI::Xaml::DependencyProperty));
            *value = detach_from<Windows::UI::Xaml::DependencyProperty>(this->shim().RevealBackgroundShowsAboveContentProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Xaml::Controls::Primitives::IListViewItemTemplateSettings> : produce_base<D, Windows::UI::Xaml::Controls::Primitives::IListViewItemTemplateSettings>
{
    int32_t WINRT_CALL get_DragItemsCount(int32_t* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(DragItemsCount, WINRT_WRAP(int32_t));
            *value = detach_from<int32_t>(this->shim().DragItemsCount());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Xaml::Controls::Primitives::ILoopingSelector> : produce_base<D, Windows::UI::Xaml::Controls::Primitives::ILoopingSelector>
{
    int32_t WINRT_CALL get_ShouldLoop(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ShouldLoop, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().ShouldLoop());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_ShouldLoop(bool value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ShouldLoop, WINRT_WRAP(void), bool);
            this->shim().ShouldLoop(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Items(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Items, WINRT_WRAP(Windows::Foundation::Collections::IVector<Windows::Foundation::IInspectable>));
            *value = detach_from<Windows::Foundation::Collections::IVector<Windows::Foundation::IInspectable>>(this->shim().Items());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_Items(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Items, WINRT_WRAP(void), Windows::Foundation::Collections::IVector<Windows::Foundation::IInspectable> const&);
            this->shim().Items(*reinterpret_cast<Windows::Foundation::Collections::IVector<Windows::Foundation::IInspectable> const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_SelectedIndex(int32_t* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SelectedIndex, WINRT_WRAP(int32_t));
            *value = detach_from<int32_t>(this->shim().SelectedIndex());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_SelectedIndex(int32_t value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SelectedIndex, WINRT_WRAP(void), int32_t);
            this->shim().SelectedIndex(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_SelectedItem(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SelectedItem, WINRT_WRAP(Windows::Foundation::IInspectable));
            *value = detach_from<Windows::Foundation::IInspectable>(this->shim().SelectedItem());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_SelectedItem(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SelectedItem, WINRT_WRAP(void), Windows::Foundation::IInspectable const&);
            this->shim().SelectedItem(*reinterpret_cast<Windows::Foundation::IInspectable const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_ItemWidth(int32_t* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ItemWidth, WINRT_WRAP(int32_t));
            *value = detach_from<int32_t>(this->shim().ItemWidth());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_ItemWidth(int32_t value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ItemWidth, WINRT_WRAP(void), int32_t);
            this->shim().ItemWidth(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_ItemHeight(int32_t* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ItemHeight, WINRT_WRAP(int32_t));
            *value = detach_from<int32_t>(this->shim().ItemHeight());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_ItemHeight(int32_t value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ItemHeight, WINRT_WRAP(void), int32_t);
            this->shim().ItemHeight(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_ItemTemplate(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ItemTemplate, WINRT_WRAP(Windows::UI::Xaml::DataTemplate));
            *value = detach_from<Windows::UI::Xaml::DataTemplate>(this->shim().ItemTemplate());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_ItemTemplate(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ItemTemplate, WINRT_WRAP(void), Windows::UI::Xaml::DataTemplate const&);
            this->shim().ItemTemplate(*reinterpret_cast<Windows::UI::Xaml::DataTemplate const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL add_SelectionChanged(void* handler, winrt::event_token* token) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SelectionChanged, WINRT_WRAP(winrt::event_token), Windows::UI::Xaml::Controls::SelectionChangedEventHandler const&);
            *token = detach_from<winrt::event_token>(this->shim().SelectionChanged(*reinterpret_cast<Windows::UI::Xaml::Controls::SelectionChangedEventHandler const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL remove_SelectionChanged(winrt::event_token token) noexcept final
    {
        typename D::abi_guard guard(this->shim());
        WINRT_ASSERT_DECLARATION(SelectionChanged, WINRT_WRAP(void), winrt::event_token const&);
        this->shim().SelectionChanged(*reinterpret_cast<winrt::event_token const*>(&token));
        return 0;
    }
};

template <typename D>
struct produce<D, Windows::UI::Xaml::Controls::Primitives::ILoopingSelectorItem> : produce_base<D, Windows::UI::Xaml::Controls::Primitives::ILoopingSelectorItem>
{};

template <typename D>
struct produce<D, Windows::UI::Xaml::Controls::Primitives::ILoopingSelectorPanel> : produce_base<D, Windows::UI::Xaml::Controls::Primitives::ILoopingSelectorPanel>
{};

template <typename D>
struct produce<D, Windows::UI::Xaml::Controls::Primitives::ILoopingSelectorStatics> : produce_base<D, Windows::UI::Xaml::Controls::Primitives::ILoopingSelectorStatics>
{
    int32_t WINRT_CALL get_ShouldLoopProperty(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ShouldLoopProperty, WINRT_WRAP(Windows::UI::Xaml::DependencyProperty));
            *value = detach_from<Windows::UI::Xaml::DependencyProperty>(this->shim().ShouldLoopProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_ItemsProperty(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ItemsProperty, WINRT_WRAP(Windows::UI::Xaml::DependencyProperty));
            *value = detach_from<Windows::UI::Xaml::DependencyProperty>(this->shim().ItemsProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_SelectedIndexProperty(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SelectedIndexProperty, WINRT_WRAP(Windows::UI::Xaml::DependencyProperty));
            *value = detach_from<Windows::UI::Xaml::DependencyProperty>(this->shim().SelectedIndexProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_SelectedItemProperty(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SelectedItemProperty, WINRT_WRAP(Windows::UI::Xaml::DependencyProperty));
            *value = detach_from<Windows::UI::Xaml::DependencyProperty>(this->shim().SelectedItemProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_ItemWidthProperty(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ItemWidthProperty, WINRT_WRAP(Windows::UI::Xaml::DependencyProperty));
            *value = detach_from<Windows::UI::Xaml::DependencyProperty>(this->shim().ItemWidthProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_ItemHeightProperty(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ItemHeightProperty, WINRT_WRAP(Windows::UI::Xaml::DependencyProperty));
            *value = detach_from<Windows::UI::Xaml::DependencyProperty>(this->shim().ItemHeightProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_ItemTemplateProperty(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ItemTemplateProperty, WINRT_WRAP(Windows::UI::Xaml::DependencyProperty));
            *value = detach_from<Windows::UI::Xaml::DependencyProperty>(this->shim().ItemTemplateProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Xaml::Controls::Primitives::IMenuFlyoutItemTemplateSettings> : produce_base<D, Windows::UI::Xaml::Controls::Primitives::IMenuFlyoutItemTemplateSettings>
{
    int32_t WINRT_CALL get_KeyboardAcceleratorTextMinWidth(double* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(KeyboardAcceleratorTextMinWidth, WINRT_WRAP(double));
            *value = detach_from<double>(this->shim().KeyboardAcceleratorTextMinWidth());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Xaml::Controls::Primitives::IMenuFlyoutPresenterTemplateSettings> : produce_base<D, Windows::UI::Xaml::Controls::Primitives::IMenuFlyoutPresenterTemplateSettings>
{
    int32_t WINRT_CALL get_FlyoutContentMinWidth(double* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(FlyoutContentMinWidth, WINRT_WRAP(double));
            *value = detach_from<double>(this->shim().FlyoutContentMinWidth());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Xaml::Controls::Primitives::INavigationViewItemPresenter> : produce_base<D, Windows::UI::Xaml::Controls::Primitives::INavigationViewItemPresenter>
{
    int32_t WINRT_CALL get_Icon(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Icon, WINRT_WRAP(Windows::UI::Xaml::Controls::IconElement));
            *value = detach_from<Windows::UI::Xaml::Controls::IconElement>(this->shim().Icon());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_Icon(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Icon, WINRT_WRAP(void), Windows::UI::Xaml::Controls::IconElement const&);
            this->shim().Icon(*reinterpret_cast<Windows::UI::Xaml::Controls::IconElement const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Xaml::Controls::Primitives::INavigationViewItemPresenterFactory> : produce_base<D, Windows::UI::Xaml::Controls::Primitives::INavigationViewItemPresenterFactory>
{
    int32_t WINRT_CALL CreateInstance(void* baseInterface, void** innerInterface, void** value) noexcept final
    {
        try
        {
            if (innerInterface) *innerInterface = nullptr;
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            Windows::Foundation::IInspectable __local_innerInterface;
            WINRT_ASSERT_DECLARATION(CreateInstance, WINRT_WRAP(Windows::UI::Xaml::Controls::Primitives::NavigationViewItemPresenter), Windows::Foundation::IInspectable const&, Windows::Foundation::IInspectable&);
            *value = detach_from<Windows::UI::Xaml::Controls::Primitives::NavigationViewItemPresenter>(this->shim().CreateInstance(*reinterpret_cast<Windows::Foundation::IInspectable const*>(&baseInterface), __local_innerInterface));
            if (innerInterface) *innerInterface = detach_abi(__local_innerInterface);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Xaml::Controls::Primitives::INavigationViewItemPresenterStatics> : produce_base<D, Windows::UI::Xaml::Controls::Primitives::INavigationViewItemPresenterStatics>
{
    int32_t WINRT_CALL get_IconProperty(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IconProperty, WINRT_WRAP(Windows::UI::Xaml::DependencyProperty));
            *value = detach_from<Windows::UI::Xaml::DependencyProperty>(this->shim().IconProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Xaml::Controls::Primitives::IOrientedVirtualizingPanel> : produce_base<D, Windows::UI::Xaml::Controls::Primitives::IOrientedVirtualizingPanel>
{
    int32_t WINRT_CALL get_CanVerticallyScroll(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CanVerticallyScroll, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().CanVerticallyScroll());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_CanVerticallyScroll(bool value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CanVerticallyScroll, WINRT_WRAP(void), bool);
            this->shim().CanVerticallyScroll(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_CanHorizontallyScroll(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CanHorizontallyScroll, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().CanHorizontallyScroll());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_CanHorizontallyScroll(bool value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CanHorizontallyScroll, WINRT_WRAP(void), bool);
            this->shim().CanHorizontallyScroll(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_ExtentWidth(double* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ExtentWidth, WINRT_WRAP(double));
            *value = detach_from<double>(this->shim().ExtentWidth());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_ExtentHeight(double* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ExtentHeight, WINRT_WRAP(double));
            *value = detach_from<double>(this->shim().ExtentHeight());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_ViewportWidth(double* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ViewportWidth, WINRT_WRAP(double));
            *value = detach_from<double>(this->shim().ViewportWidth());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_ViewportHeight(double* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ViewportHeight, WINRT_WRAP(double));
            *value = detach_from<double>(this->shim().ViewportHeight());
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

    int32_t WINRT_CALL get_ScrollOwner(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ScrollOwner, WINRT_WRAP(Windows::Foundation::IInspectable));
            *value = detach_from<Windows::Foundation::IInspectable>(this->shim().ScrollOwner());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_ScrollOwner(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ScrollOwner, WINRT_WRAP(void), Windows::Foundation::IInspectable const&);
            this->shim().ScrollOwner(*reinterpret_cast<Windows::Foundation::IInspectable const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL LineUp() noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(LineUp, WINRT_WRAP(void));
            this->shim().LineUp();
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL LineDown() noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(LineDown, WINRT_WRAP(void));
            this->shim().LineDown();
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL LineLeft() noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(LineLeft, WINRT_WRAP(void));
            this->shim().LineLeft();
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL LineRight() noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(LineRight, WINRT_WRAP(void));
            this->shim().LineRight();
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL PageUp() noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(PageUp, WINRT_WRAP(void));
            this->shim().PageUp();
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL PageDown() noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(PageDown, WINRT_WRAP(void));
            this->shim().PageDown();
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL PageLeft() noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(PageLeft, WINRT_WRAP(void));
            this->shim().PageLeft();
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL PageRight() noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(PageRight, WINRT_WRAP(void));
            this->shim().PageRight();
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL MouseWheelUp() noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(MouseWheelUp, WINRT_WRAP(void));
            this->shim().MouseWheelUp();
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL MouseWheelDown() noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(MouseWheelDown, WINRT_WRAP(void));
            this->shim().MouseWheelDown();
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL MouseWheelLeft() noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(MouseWheelLeft, WINRT_WRAP(void));
            this->shim().MouseWheelLeft();
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL MouseWheelRight() noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(MouseWheelRight, WINRT_WRAP(void));
            this->shim().MouseWheelRight();
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL SetHorizontalOffset(double offset) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SetHorizontalOffset, WINRT_WRAP(void), double);
            this->shim().SetHorizontalOffset(offset);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL SetVerticalOffset(double offset) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SetVerticalOffset, WINRT_WRAP(void), double);
            this->shim().SetVerticalOffset(offset);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL MakeVisible(void* visual, Windows::Foundation::Rect rectangle, Windows::Foundation::Rect* result) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(MakeVisible, WINRT_WRAP(Windows::Foundation::Rect), Windows::UI::Xaml::UIElement const&, Windows::Foundation::Rect const&);
            *result = detach_from<Windows::Foundation::Rect>(this->shim().MakeVisible(*reinterpret_cast<Windows::UI::Xaml::UIElement const*>(&visual), *reinterpret_cast<Windows::Foundation::Rect const*>(&rectangle)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Xaml::Controls::Primitives::IOrientedVirtualizingPanelFactory> : produce_base<D, Windows::UI::Xaml::Controls::Primitives::IOrientedVirtualizingPanelFactory>
{};

template <typename D>
struct produce<D, Windows::UI::Xaml::Controls::Primitives::IPickerFlyoutBase> : produce_base<D, Windows::UI::Xaml::Controls::Primitives::IPickerFlyoutBase>
{};

template <typename D>
struct produce<D, Windows::UI::Xaml::Controls::Primitives::IPickerFlyoutBaseFactory> : produce_base<D, Windows::UI::Xaml::Controls::Primitives::IPickerFlyoutBaseFactory>
{
    int32_t WINRT_CALL CreateInstance(void* baseInterface, void** innerInterface, void** value) noexcept final
    {
        try
        {
            if (innerInterface) *innerInterface = nullptr;
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            Windows::Foundation::IInspectable __local_innerInterface;
            WINRT_ASSERT_DECLARATION(CreateInstance, WINRT_WRAP(Windows::UI::Xaml::Controls::Primitives::PickerFlyoutBase), Windows::Foundation::IInspectable const&, Windows::Foundation::IInspectable&);
            *value = detach_from<Windows::UI::Xaml::Controls::Primitives::PickerFlyoutBase>(this->shim().CreateInstance(*reinterpret_cast<Windows::Foundation::IInspectable const*>(&baseInterface), __local_innerInterface));
            if (innerInterface) *innerInterface = detach_abi(__local_innerInterface);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Xaml::Controls::Primitives::IPickerFlyoutBaseOverrides> : produce_base<D, Windows::UI::Xaml::Controls::Primitives::IPickerFlyoutBaseOverrides>
{
    int32_t WINRT_CALL OnConfirmed() noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(OnConfirmed, WINRT_WRAP(void));
            this->shim().OnConfirmed();
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL ShouldShowConfirmationButtons(bool* result) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ShouldShowConfirmationButtons, WINRT_WRAP(bool));
            *result = detach_from<bool>(this->shim().ShouldShowConfirmationButtons());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Xaml::Controls::Primitives::IPickerFlyoutBaseStatics> : produce_base<D, Windows::UI::Xaml::Controls::Primitives::IPickerFlyoutBaseStatics>
{
    int32_t WINRT_CALL get_TitleProperty(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(TitleProperty, WINRT_WRAP(Windows::UI::Xaml::DependencyProperty));
            *value = detach_from<Windows::UI::Xaml::DependencyProperty>(this->shim().TitleProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL GetTitle(void* element, void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetTitle, WINRT_WRAP(hstring), Windows::UI::Xaml::DependencyObject const&);
            *result = detach_from<hstring>(this->shim().GetTitle(*reinterpret_cast<Windows::UI::Xaml::DependencyObject const*>(&element)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL SetTitle(void* element, void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SetTitle, WINRT_WRAP(void), Windows::UI::Xaml::DependencyObject const&, hstring const&);
            this->shim().SetTitle(*reinterpret_cast<Windows::UI::Xaml::DependencyObject const*>(&element), *reinterpret_cast<hstring const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Xaml::Controls::Primitives::IPivotHeaderItem> : produce_base<D, Windows::UI::Xaml::Controls::Primitives::IPivotHeaderItem>
{};

template <typename D>
struct produce<D, Windows::UI::Xaml::Controls::Primitives::IPivotHeaderItemFactory> : produce_base<D, Windows::UI::Xaml::Controls::Primitives::IPivotHeaderItemFactory>
{
    int32_t WINRT_CALL CreateInstance(void* baseInterface, void** innerInterface, void** value) noexcept final
    {
        try
        {
            if (innerInterface) *innerInterface = nullptr;
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            Windows::Foundation::IInspectable __local_innerInterface;
            WINRT_ASSERT_DECLARATION(CreateInstance, WINRT_WRAP(Windows::UI::Xaml::Controls::Primitives::PivotHeaderItem), Windows::Foundation::IInspectable const&, Windows::Foundation::IInspectable&);
            *value = detach_from<Windows::UI::Xaml::Controls::Primitives::PivotHeaderItem>(this->shim().CreateInstance(*reinterpret_cast<Windows::Foundation::IInspectable const*>(&baseInterface), __local_innerInterface));
            if (innerInterface) *innerInterface = detach_abi(__local_innerInterface);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Xaml::Controls::Primitives::IPivotHeaderPanel> : produce_base<D, Windows::UI::Xaml::Controls::Primitives::IPivotHeaderPanel>
{};

template <typename D>
struct produce<D, Windows::UI::Xaml::Controls::Primitives::IPivotPanel> : produce_base<D, Windows::UI::Xaml::Controls::Primitives::IPivotPanel>
{};

template <typename D>
struct produce<D, Windows::UI::Xaml::Controls::Primitives::IPopup> : produce_base<D, Windows::UI::Xaml::Controls::Primitives::IPopup>
{
    int32_t WINRT_CALL get_Child(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Child, WINRT_WRAP(Windows::UI::Xaml::UIElement));
            *value = detach_from<Windows::UI::Xaml::UIElement>(this->shim().Child());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_Child(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Child, WINRT_WRAP(void), Windows::UI::Xaml::UIElement const&);
            this->shim().Child(*reinterpret_cast<Windows::UI::Xaml::UIElement const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_IsOpen(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IsOpen, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().IsOpen());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_IsOpen(bool value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IsOpen, WINRT_WRAP(void), bool);
            this->shim().IsOpen(value);
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

    int32_t WINRT_CALL get_ChildTransitions(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ChildTransitions, WINRT_WRAP(Windows::UI::Xaml::Media::Animation::TransitionCollection));
            *value = detach_from<Windows::UI::Xaml::Media::Animation::TransitionCollection>(this->shim().ChildTransitions());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_ChildTransitions(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ChildTransitions, WINRT_WRAP(void), Windows::UI::Xaml::Media::Animation::TransitionCollection const&);
            this->shim().ChildTransitions(*reinterpret_cast<Windows::UI::Xaml::Media::Animation::TransitionCollection const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_IsLightDismissEnabled(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IsLightDismissEnabled, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().IsLightDismissEnabled());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_IsLightDismissEnabled(bool value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IsLightDismissEnabled, WINRT_WRAP(void), bool);
            this->shim().IsLightDismissEnabled(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL add_Opened(void* handler, winrt::event_token* token) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Opened, WINRT_WRAP(winrt::event_token), Windows::Foundation::EventHandler<Windows::Foundation::IInspectable> const&);
            *token = detach_from<winrt::event_token>(this->shim().Opened(*reinterpret_cast<Windows::Foundation::EventHandler<Windows::Foundation::IInspectable> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL remove_Opened(winrt::event_token token) noexcept final
    {
        typename D::abi_guard guard(this->shim());
        WINRT_ASSERT_DECLARATION(Opened, WINRT_WRAP(void), winrt::event_token const&);
        this->shim().Opened(*reinterpret_cast<winrt::event_token const*>(&token));
        return 0;
    }

    int32_t WINRT_CALL add_Closed(void* handler, winrt::event_token* token) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Closed, WINRT_WRAP(winrt::event_token), Windows::Foundation::EventHandler<Windows::Foundation::IInspectable> const&);
            *token = detach_from<winrt::event_token>(this->shim().Closed(*reinterpret_cast<Windows::Foundation::EventHandler<Windows::Foundation::IInspectable> const*>(&handler)));
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
};

template <typename D>
struct produce<D, Windows::UI::Xaml::Controls::Primitives::IPopup2> : produce_base<D, Windows::UI::Xaml::Controls::Primitives::IPopup2>
{
    int32_t WINRT_CALL get_LightDismissOverlayMode(Windows::UI::Xaml::Controls::LightDismissOverlayMode* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(LightDismissOverlayMode, WINRT_WRAP(Windows::UI::Xaml::Controls::LightDismissOverlayMode));
            *value = detach_from<Windows::UI::Xaml::Controls::LightDismissOverlayMode>(this->shim().LightDismissOverlayMode());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_LightDismissOverlayMode(Windows::UI::Xaml::Controls::LightDismissOverlayMode value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(LightDismissOverlayMode, WINRT_WRAP(void), Windows::UI::Xaml::Controls::LightDismissOverlayMode const&);
            this->shim().LightDismissOverlayMode(*reinterpret_cast<Windows::UI::Xaml::Controls::LightDismissOverlayMode const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Xaml::Controls::Primitives::IPopup3> : produce_base<D, Windows::UI::Xaml::Controls::Primitives::IPopup3>
{
    int32_t WINRT_CALL get_ShouldConstrainToRootBounds(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ShouldConstrainToRootBounds, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().ShouldConstrainToRootBounds());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_ShouldConstrainToRootBounds(bool value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ShouldConstrainToRootBounds, WINRT_WRAP(void), bool);
            this->shim().ShouldConstrainToRootBounds(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_IsConstrainedToRootBounds(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IsConstrainedToRootBounds, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().IsConstrainedToRootBounds());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Xaml::Controls::Primitives::IPopupStatics> : produce_base<D, Windows::UI::Xaml::Controls::Primitives::IPopupStatics>
{
    int32_t WINRT_CALL get_ChildProperty(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ChildProperty, WINRT_WRAP(Windows::UI::Xaml::DependencyProperty));
            *value = detach_from<Windows::UI::Xaml::DependencyProperty>(this->shim().ChildProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_IsOpenProperty(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IsOpenProperty, WINRT_WRAP(Windows::UI::Xaml::DependencyProperty));
            *value = detach_from<Windows::UI::Xaml::DependencyProperty>(this->shim().IsOpenProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_HorizontalOffsetProperty(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(HorizontalOffsetProperty, WINRT_WRAP(Windows::UI::Xaml::DependencyProperty));
            *value = detach_from<Windows::UI::Xaml::DependencyProperty>(this->shim().HorizontalOffsetProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_VerticalOffsetProperty(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(VerticalOffsetProperty, WINRT_WRAP(Windows::UI::Xaml::DependencyProperty));
            *value = detach_from<Windows::UI::Xaml::DependencyProperty>(this->shim().VerticalOffsetProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_ChildTransitionsProperty(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ChildTransitionsProperty, WINRT_WRAP(Windows::UI::Xaml::DependencyProperty));
            *value = detach_from<Windows::UI::Xaml::DependencyProperty>(this->shim().ChildTransitionsProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_IsLightDismissEnabledProperty(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IsLightDismissEnabledProperty, WINRT_WRAP(Windows::UI::Xaml::DependencyProperty));
            *value = detach_from<Windows::UI::Xaml::DependencyProperty>(this->shim().IsLightDismissEnabledProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Xaml::Controls::Primitives::IPopupStatics2> : produce_base<D, Windows::UI::Xaml::Controls::Primitives::IPopupStatics2>
{
    int32_t WINRT_CALL get_LightDismissOverlayModeProperty(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(LightDismissOverlayModeProperty, WINRT_WRAP(Windows::UI::Xaml::DependencyProperty));
            *value = detach_from<Windows::UI::Xaml::DependencyProperty>(this->shim().LightDismissOverlayModeProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Xaml::Controls::Primitives::IPopupStatics3> : produce_base<D, Windows::UI::Xaml::Controls::Primitives::IPopupStatics3>
{
    int32_t WINRT_CALL get_ShouldConstrainToRootBoundsProperty(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ShouldConstrainToRootBoundsProperty, WINRT_WRAP(Windows::UI::Xaml::DependencyProperty));
            *value = detach_from<Windows::UI::Xaml::DependencyProperty>(this->shim().ShouldConstrainToRootBoundsProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Xaml::Controls::Primitives::IProgressBarTemplateSettings> : produce_base<D, Windows::UI::Xaml::Controls::Primitives::IProgressBarTemplateSettings>
{
    int32_t WINRT_CALL get_EllipseDiameter(double* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(EllipseDiameter, WINRT_WRAP(double));
            *value = detach_from<double>(this->shim().EllipseDiameter());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_EllipseOffset(double* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(EllipseOffset, WINRT_WRAP(double));
            *value = detach_from<double>(this->shim().EllipseOffset());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_EllipseAnimationWellPosition(double* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(EllipseAnimationWellPosition, WINRT_WRAP(double));
            *value = detach_from<double>(this->shim().EllipseAnimationWellPosition());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_EllipseAnimationEndPosition(double* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(EllipseAnimationEndPosition, WINRT_WRAP(double));
            *value = detach_from<double>(this->shim().EllipseAnimationEndPosition());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_ContainerAnimationStartPosition(double* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ContainerAnimationStartPosition, WINRT_WRAP(double));
            *value = detach_from<double>(this->shim().ContainerAnimationStartPosition());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_ContainerAnimationEndPosition(double* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ContainerAnimationEndPosition, WINRT_WRAP(double));
            *value = detach_from<double>(this->shim().ContainerAnimationEndPosition());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_IndicatorLengthDelta(double* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IndicatorLengthDelta, WINRT_WRAP(double));
            *value = detach_from<double>(this->shim().IndicatorLengthDelta());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Xaml::Controls::Primitives::IProgressRingTemplateSettings> : produce_base<D, Windows::UI::Xaml::Controls::Primitives::IProgressRingTemplateSettings>
{
    int32_t WINRT_CALL get_EllipseDiameter(double* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(EllipseDiameter, WINRT_WRAP(double));
            *value = detach_from<double>(this->shim().EllipseDiameter());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_EllipseOffset(struct struct_Windows_UI_Xaml_Thickness* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(EllipseOffset, WINRT_WRAP(Windows::UI::Xaml::Thickness));
            *value = detach_from<Windows::UI::Xaml::Thickness>(this->shim().EllipseOffset());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_MaxSideLength(double* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(MaxSideLength, WINRT_WRAP(double));
            *value = detach_from<double>(this->shim().MaxSideLength());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Xaml::Controls::Primitives::IRangeBase> : produce_base<D, Windows::UI::Xaml::Controls::Primitives::IRangeBase>
{
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

    int32_t WINRT_CALL put_Minimum(double value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Minimum, WINRT_WRAP(void), double);
            this->shim().Minimum(value);
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

    int32_t WINRT_CALL put_Maximum(double value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Maximum, WINRT_WRAP(void), double);
            this->shim().Maximum(value);
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

    int32_t WINRT_CALL put_SmallChange(double value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SmallChange, WINRT_WRAP(void), double);
            this->shim().SmallChange(value);
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

    int32_t WINRT_CALL put_LargeChange(double value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(LargeChange, WINRT_WRAP(void), double);
            this->shim().LargeChange(value);
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

    int32_t WINRT_CALL put_Value(double value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Value, WINRT_WRAP(void), double);
            this->shim().Value(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL add_ValueChanged(void* handler, winrt::event_token* token) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ValueChanged, WINRT_WRAP(winrt::event_token), Windows::UI::Xaml::Controls::Primitives::RangeBaseValueChangedEventHandler const&);
            *token = detach_from<winrt::event_token>(this->shim().ValueChanged(*reinterpret_cast<Windows::UI::Xaml::Controls::Primitives::RangeBaseValueChangedEventHandler const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL remove_ValueChanged(winrt::event_token token) noexcept final
    {
        typename D::abi_guard guard(this->shim());
        WINRT_ASSERT_DECLARATION(ValueChanged, WINRT_WRAP(void), winrt::event_token const&);
        this->shim().ValueChanged(*reinterpret_cast<winrt::event_token const*>(&token));
        return 0;
    }
};

template <typename D>
struct produce<D, Windows::UI::Xaml::Controls::Primitives::IRangeBaseFactory> : produce_base<D, Windows::UI::Xaml::Controls::Primitives::IRangeBaseFactory>
{
    int32_t WINRT_CALL CreateInstance(void* baseInterface, void** innerInterface, void** value) noexcept final
    {
        try
        {
            if (innerInterface) *innerInterface = nullptr;
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            Windows::Foundation::IInspectable __local_innerInterface;
            WINRT_ASSERT_DECLARATION(CreateInstance, WINRT_WRAP(Windows::UI::Xaml::Controls::Primitives::RangeBase), Windows::Foundation::IInspectable const&, Windows::Foundation::IInspectable&);
            *value = detach_from<Windows::UI::Xaml::Controls::Primitives::RangeBase>(this->shim().CreateInstance(*reinterpret_cast<Windows::Foundation::IInspectable const*>(&baseInterface), __local_innerInterface));
            if (innerInterface) *innerInterface = detach_abi(__local_innerInterface);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Xaml::Controls::Primitives::IRangeBaseOverrides> : produce_base<D, Windows::UI::Xaml::Controls::Primitives::IRangeBaseOverrides>
{
    int32_t WINRT_CALL OnMinimumChanged(double oldMinimum, double newMinimum) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(OnMinimumChanged, WINRT_WRAP(void), double, double);
            this->shim().OnMinimumChanged(oldMinimum, newMinimum);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL OnMaximumChanged(double oldMaximum, double newMaximum) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(OnMaximumChanged, WINRT_WRAP(void), double, double);
            this->shim().OnMaximumChanged(oldMaximum, newMaximum);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL OnValueChanged(double oldValue, double newValue) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(OnValueChanged, WINRT_WRAP(void), double, double);
            this->shim().OnValueChanged(oldValue, newValue);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Xaml::Controls::Primitives::IRangeBaseStatics> : produce_base<D, Windows::UI::Xaml::Controls::Primitives::IRangeBaseStatics>
{
    int32_t WINRT_CALL get_MinimumProperty(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(MinimumProperty, WINRT_WRAP(Windows::UI::Xaml::DependencyProperty));
            *value = detach_from<Windows::UI::Xaml::DependencyProperty>(this->shim().MinimumProperty());
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
            WINRT_ASSERT_DECLARATION(MaximumProperty, WINRT_WRAP(Windows::UI::Xaml::DependencyProperty));
            *value = detach_from<Windows::UI::Xaml::DependencyProperty>(this->shim().MaximumProperty());
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
            WINRT_ASSERT_DECLARATION(SmallChangeProperty, WINRT_WRAP(Windows::UI::Xaml::DependencyProperty));
            *value = detach_from<Windows::UI::Xaml::DependencyProperty>(this->shim().SmallChangeProperty());
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
            WINRT_ASSERT_DECLARATION(LargeChangeProperty, WINRT_WRAP(Windows::UI::Xaml::DependencyProperty));
            *value = detach_from<Windows::UI::Xaml::DependencyProperty>(this->shim().LargeChangeProperty());
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
            WINRT_ASSERT_DECLARATION(ValueProperty, WINRT_WRAP(Windows::UI::Xaml::DependencyProperty));
            *value = detach_from<Windows::UI::Xaml::DependencyProperty>(this->shim().ValueProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Xaml::Controls::Primitives::IRangeBaseValueChangedEventArgs> : produce_base<D, Windows::UI::Xaml::Controls::Primitives::IRangeBaseValueChangedEventArgs>
{
    int32_t WINRT_CALL get_OldValue(double* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(OldValue, WINRT_WRAP(double));
            *value = detach_from<double>(this->shim().OldValue());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_NewValue(double* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(NewValue, WINRT_WRAP(double));
            *value = detach_from<double>(this->shim().NewValue());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Xaml::Controls::Primitives::IRepeatButton> : produce_base<D, Windows::UI::Xaml::Controls::Primitives::IRepeatButton>
{
    int32_t WINRT_CALL get_Delay(int32_t* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Delay, WINRT_WRAP(int32_t));
            *value = detach_from<int32_t>(this->shim().Delay());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_Delay(int32_t value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Delay, WINRT_WRAP(void), int32_t);
            this->shim().Delay(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Interval(int32_t* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Interval, WINRT_WRAP(int32_t));
            *value = detach_from<int32_t>(this->shim().Interval());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_Interval(int32_t value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Interval, WINRT_WRAP(void), int32_t);
            this->shim().Interval(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Xaml::Controls::Primitives::IRepeatButtonStatics> : produce_base<D, Windows::UI::Xaml::Controls::Primitives::IRepeatButtonStatics>
{
    int32_t WINRT_CALL get_DelayProperty(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(DelayProperty, WINRT_WRAP(Windows::UI::Xaml::DependencyProperty));
            *value = detach_from<Windows::UI::Xaml::DependencyProperty>(this->shim().DelayProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_IntervalProperty(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IntervalProperty, WINRT_WRAP(Windows::UI::Xaml::DependencyProperty));
            *value = detach_from<Windows::UI::Xaml::DependencyProperty>(this->shim().IntervalProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Xaml::Controls::Primitives::IScrollBar> : produce_base<D, Windows::UI::Xaml::Controls::Primitives::IScrollBar>
{
    int32_t WINRT_CALL get_Orientation(Windows::UI::Xaml::Controls::Orientation* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Orientation, WINRT_WRAP(Windows::UI::Xaml::Controls::Orientation));
            *value = detach_from<Windows::UI::Xaml::Controls::Orientation>(this->shim().Orientation());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_Orientation(Windows::UI::Xaml::Controls::Orientation value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Orientation, WINRT_WRAP(void), Windows::UI::Xaml::Controls::Orientation const&);
            this->shim().Orientation(*reinterpret_cast<Windows::UI::Xaml::Controls::Orientation const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_ViewportSize(double* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ViewportSize, WINRT_WRAP(double));
            *value = detach_from<double>(this->shim().ViewportSize());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_ViewportSize(double value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ViewportSize, WINRT_WRAP(void), double);
            this->shim().ViewportSize(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_IndicatorMode(Windows::UI::Xaml::Controls::Primitives::ScrollingIndicatorMode* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IndicatorMode, WINRT_WRAP(Windows::UI::Xaml::Controls::Primitives::ScrollingIndicatorMode));
            *value = detach_from<Windows::UI::Xaml::Controls::Primitives::ScrollingIndicatorMode>(this->shim().IndicatorMode());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_IndicatorMode(Windows::UI::Xaml::Controls::Primitives::ScrollingIndicatorMode value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IndicatorMode, WINRT_WRAP(void), Windows::UI::Xaml::Controls::Primitives::ScrollingIndicatorMode const&);
            this->shim().IndicatorMode(*reinterpret_cast<Windows::UI::Xaml::Controls::Primitives::ScrollingIndicatorMode const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL add_Scroll(void* handler, winrt::event_token* token) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Scroll, WINRT_WRAP(winrt::event_token), Windows::UI::Xaml::Controls::Primitives::ScrollEventHandler const&);
            *token = detach_from<winrt::event_token>(this->shim().Scroll(*reinterpret_cast<Windows::UI::Xaml::Controls::Primitives::ScrollEventHandler const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL remove_Scroll(winrt::event_token token) noexcept final
    {
        typename D::abi_guard guard(this->shim());
        WINRT_ASSERT_DECLARATION(Scroll, WINRT_WRAP(void), winrt::event_token const&);
        this->shim().Scroll(*reinterpret_cast<winrt::event_token const*>(&token));
        return 0;
    }
};

template <typename D>
struct produce<D, Windows::UI::Xaml::Controls::Primitives::IScrollBarStatics> : produce_base<D, Windows::UI::Xaml::Controls::Primitives::IScrollBarStatics>
{
    int32_t WINRT_CALL get_OrientationProperty(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(OrientationProperty, WINRT_WRAP(Windows::UI::Xaml::DependencyProperty));
            *value = detach_from<Windows::UI::Xaml::DependencyProperty>(this->shim().OrientationProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_ViewportSizeProperty(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ViewportSizeProperty, WINRT_WRAP(Windows::UI::Xaml::DependencyProperty));
            *value = detach_from<Windows::UI::Xaml::DependencyProperty>(this->shim().ViewportSizeProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_IndicatorModeProperty(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IndicatorModeProperty, WINRT_WRAP(Windows::UI::Xaml::DependencyProperty));
            *value = detach_from<Windows::UI::Xaml::DependencyProperty>(this->shim().IndicatorModeProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Xaml::Controls::Primitives::IScrollEventArgs> : produce_base<D, Windows::UI::Xaml::Controls::Primitives::IScrollEventArgs>
{
    int32_t WINRT_CALL get_NewValue(double* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(NewValue, WINRT_WRAP(double));
            *value = detach_from<double>(this->shim().NewValue());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_ScrollEventType(Windows::UI::Xaml::Controls::Primitives::ScrollEventType* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ScrollEventType, WINRT_WRAP(Windows::UI::Xaml::Controls::Primitives::ScrollEventType));
            *value = detach_from<Windows::UI::Xaml::Controls::Primitives::ScrollEventType>(this->shim().ScrollEventType());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Xaml::Controls::Primitives::IScrollSnapPointsInfo> : produce_base<D, Windows::UI::Xaml::Controls::Primitives::IScrollSnapPointsInfo>
{
    int32_t WINRT_CALL get_AreHorizontalSnapPointsRegular(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(AreHorizontalSnapPointsRegular, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().AreHorizontalSnapPointsRegular());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_AreVerticalSnapPointsRegular(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(AreVerticalSnapPointsRegular, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().AreVerticalSnapPointsRegular());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL add_HorizontalSnapPointsChanged(void* handler, winrt::event_token* token) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(HorizontalSnapPointsChanged, WINRT_WRAP(winrt::event_token), Windows::Foundation::EventHandler<Windows::Foundation::IInspectable> const&);
            *token = detach_from<winrt::event_token>(this->shim().HorizontalSnapPointsChanged(*reinterpret_cast<Windows::Foundation::EventHandler<Windows::Foundation::IInspectable> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL remove_HorizontalSnapPointsChanged(winrt::event_token token) noexcept final
    {
        typename D::abi_guard guard(this->shim());
        WINRT_ASSERT_DECLARATION(HorizontalSnapPointsChanged, WINRT_WRAP(void), winrt::event_token const&);
        this->shim().HorizontalSnapPointsChanged(*reinterpret_cast<winrt::event_token const*>(&token));
        return 0;
    }

    int32_t WINRT_CALL add_VerticalSnapPointsChanged(void* handler, winrt::event_token* token) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(VerticalSnapPointsChanged, WINRT_WRAP(winrt::event_token), Windows::Foundation::EventHandler<Windows::Foundation::IInspectable> const&);
            *token = detach_from<winrt::event_token>(this->shim().VerticalSnapPointsChanged(*reinterpret_cast<Windows::Foundation::EventHandler<Windows::Foundation::IInspectable> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL remove_VerticalSnapPointsChanged(winrt::event_token token) noexcept final
    {
        typename D::abi_guard guard(this->shim());
        WINRT_ASSERT_DECLARATION(VerticalSnapPointsChanged, WINRT_WRAP(void), winrt::event_token const&);
        this->shim().VerticalSnapPointsChanged(*reinterpret_cast<winrt::event_token const*>(&token));
        return 0;
    }

    int32_t WINRT_CALL GetIrregularSnapPoints(Windows::UI::Xaml::Controls::Orientation orientation, Windows::UI::Xaml::Controls::Primitives::SnapPointsAlignment alignment, void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetIrregularSnapPoints, WINRT_WRAP(Windows::Foundation::Collections::IVectorView<float>), Windows::UI::Xaml::Controls::Orientation const&, Windows::UI::Xaml::Controls::Primitives::SnapPointsAlignment const&);
            *result = detach_from<Windows::Foundation::Collections::IVectorView<float>>(this->shim().GetIrregularSnapPoints(*reinterpret_cast<Windows::UI::Xaml::Controls::Orientation const*>(&orientation), *reinterpret_cast<Windows::UI::Xaml::Controls::Primitives::SnapPointsAlignment const*>(&alignment)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL GetRegularSnapPoints(Windows::UI::Xaml::Controls::Orientation orientation, Windows::UI::Xaml::Controls::Primitives::SnapPointsAlignment alignment, float* offset, float* returnValue) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetRegularSnapPoints, WINRT_WRAP(float), Windows::UI::Xaml::Controls::Orientation const&, Windows::UI::Xaml::Controls::Primitives::SnapPointsAlignment const&, float&);
            *returnValue = detach_from<float>(this->shim().GetRegularSnapPoints(*reinterpret_cast<Windows::UI::Xaml::Controls::Orientation const*>(&orientation), *reinterpret_cast<Windows::UI::Xaml::Controls::Primitives::SnapPointsAlignment const*>(&alignment), *offset));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Xaml::Controls::Primitives::ISelector> : produce_base<D, Windows::UI::Xaml::Controls::Primitives::ISelector>
{
    int32_t WINRT_CALL get_SelectedIndex(int32_t* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SelectedIndex, WINRT_WRAP(int32_t));
            *value = detach_from<int32_t>(this->shim().SelectedIndex());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_SelectedIndex(int32_t value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SelectedIndex, WINRT_WRAP(void), int32_t);
            this->shim().SelectedIndex(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_SelectedItem(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SelectedItem, WINRT_WRAP(Windows::Foundation::IInspectable));
            *value = detach_from<Windows::Foundation::IInspectable>(this->shim().SelectedItem());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_SelectedItem(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SelectedItem, WINRT_WRAP(void), Windows::Foundation::IInspectable const&);
            this->shim().SelectedItem(*reinterpret_cast<Windows::Foundation::IInspectable const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_SelectedValue(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SelectedValue, WINRT_WRAP(Windows::Foundation::IInspectable));
            *value = detach_from<Windows::Foundation::IInspectable>(this->shim().SelectedValue());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_SelectedValue(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SelectedValue, WINRT_WRAP(void), Windows::Foundation::IInspectable const&);
            this->shim().SelectedValue(*reinterpret_cast<Windows::Foundation::IInspectable const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_SelectedValuePath(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SelectedValuePath, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().SelectedValuePath());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_SelectedValuePath(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SelectedValuePath, WINRT_WRAP(void), hstring const&);
            this->shim().SelectedValuePath(*reinterpret_cast<hstring const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_IsSynchronizedWithCurrentItem(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IsSynchronizedWithCurrentItem, WINRT_WRAP(Windows::Foundation::IReference<bool>));
            *value = detach_from<Windows::Foundation::IReference<bool>>(this->shim().IsSynchronizedWithCurrentItem());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_IsSynchronizedWithCurrentItem(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IsSynchronizedWithCurrentItem, WINRT_WRAP(void), Windows::Foundation::IReference<bool> const&);
            this->shim().IsSynchronizedWithCurrentItem(*reinterpret_cast<Windows::Foundation::IReference<bool> const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL add_SelectionChanged(void* handler, winrt::event_token* token) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SelectionChanged, WINRT_WRAP(winrt::event_token), Windows::UI::Xaml::Controls::SelectionChangedEventHandler const&);
            *token = detach_from<winrt::event_token>(this->shim().SelectionChanged(*reinterpret_cast<Windows::UI::Xaml::Controls::SelectionChangedEventHandler const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL remove_SelectionChanged(winrt::event_token token) noexcept final
    {
        typename D::abi_guard guard(this->shim());
        WINRT_ASSERT_DECLARATION(SelectionChanged, WINRT_WRAP(void), winrt::event_token const&);
        this->shim().SelectionChanged(*reinterpret_cast<winrt::event_token const*>(&token));
        return 0;
    }
};

template <typename D>
struct produce<D, Windows::UI::Xaml::Controls::Primitives::ISelectorFactory> : produce_base<D, Windows::UI::Xaml::Controls::Primitives::ISelectorFactory>
{};

template <typename D>
struct produce<D, Windows::UI::Xaml::Controls::Primitives::ISelectorItem> : produce_base<D, Windows::UI::Xaml::Controls::Primitives::ISelectorItem>
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

    int32_t WINRT_CALL put_IsSelected(bool value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IsSelected, WINRT_WRAP(void), bool);
            this->shim().IsSelected(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Xaml::Controls::Primitives::ISelectorItemFactory> : produce_base<D, Windows::UI::Xaml::Controls::Primitives::ISelectorItemFactory>
{
    int32_t WINRT_CALL CreateInstance(void* baseInterface, void** innerInterface, void** value) noexcept final
    {
        try
        {
            if (innerInterface) *innerInterface = nullptr;
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            Windows::Foundation::IInspectable __local_innerInterface;
            WINRT_ASSERT_DECLARATION(CreateInstance, WINRT_WRAP(Windows::UI::Xaml::Controls::Primitives::SelectorItem), Windows::Foundation::IInspectable const&, Windows::Foundation::IInspectable&);
            *value = detach_from<Windows::UI::Xaml::Controls::Primitives::SelectorItem>(this->shim().CreateInstance(*reinterpret_cast<Windows::Foundation::IInspectable const*>(&baseInterface), __local_innerInterface));
            if (innerInterface) *innerInterface = detach_abi(__local_innerInterface);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Xaml::Controls::Primitives::ISelectorItemStatics> : produce_base<D, Windows::UI::Xaml::Controls::Primitives::ISelectorItemStatics>
{
    int32_t WINRT_CALL get_IsSelectedProperty(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IsSelectedProperty, WINRT_WRAP(Windows::UI::Xaml::DependencyProperty));
            *value = detach_from<Windows::UI::Xaml::DependencyProperty>(this->shim().IsSelectedProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Xaml::Controls::Primitives::ISelectorStatics> : produce_base<D, Windows::UI::Xaml::Controls::Primitives::ISelectorStatics>
{
    int32_t WINRT_CALL get_SelectedIndexProperty(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SelectedIndexProperty, WINRT_WRAP(Windows::UI::Xaml::DependencyProperty));
            *value = detach_from<Windows::UI::Xaml::DependencyProperty>(this->shim().SelectedIndexProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_SelectedItemProperty(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SelectedItemProperty, WINRT_WRAP(Windows::UI::Xaml::DependencyProperty));
            *value = detach_from<Windows::UI::Xaml::DependencyProperty>(this->shim().SelectedItemProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_SelectedValueProperty(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SelectedValueProperty, WINRT_WRAP(Windows::UI::Xaml::DependencyProperty));
            *value = detach_from<Windows::UI::Xaml::DependencyProperty>(this->shim().SelectedValueProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_SelectedValuePathProperty(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SelectedValuePathProperty, WINRT_WRAP(Windows::UI::Xaml::DependencyProperty));
            *value = detach_from<Windows::UI::Xaml::DependencyProperty>(this->shim().SelectedValuePathProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_IsSynchronizedWithCurrentItemProperty(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IsSynchronizedWithCurrentItemProperty, WINRT_WRAP(Windows::UI::Xaml::DependencyProperty));
            *value = detach_from<Windows::UI::Xaml::DependencyProperty>(this->shim().IsSynchronizedWithCurrentItemProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL GetIsSelectionActive(void* element, bool* result) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetIsSelectionActive, WINRT_WRAP(bool), Windows::UI::Xaml::DependencyObject const&);
            *result = detach_from<bool>(this->shim().GetIsSelectionActive(*reinterpret_cast<Windows::UI::Xaml::DependencyObject const*>(&element)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Xaml::Controls::Primitives::ISettingsFlyoutTemplateSettings> : produce_base<D, Windows::UI::Xaml::Controls::Primitives::ISettingsFlyoutTemplateSettings>
{
    int32_t WINRT_CALL get_HeaderBackground(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(HeaderBackground, WINRT_WRAP(Windows::UI::Xaml::Media::Brush));
            *value = detach_from<Windows::UI::Xaml::Media::Brush>(this->shim().HeaderBackground());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_HeaderForeground(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(HeaderForeground, WINRT_WRAP(Windows::UI::Xaml::Media::Brush));
            *value = detach_from<Windows::UI::Xaml::Media::Brush>(this->shim().HeaderForeground());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_BorderBrush(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(BorderBrush, WINRT_WRAP(Windows::UI::Xaml::Media::Brush));
            *value = detach_from<Windows::UI::Xaml::Media::Brush>(this->shim().BorderBrush());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_BorderThickness(struct struct_Windows_UI_Xaml_Thickness* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(BorderThickness, WINRT_WRAP(Windows::UI::Xaml::Thickness));
            *value = detach_from<Windows::UI::Xaml::Thickness>(this->shim().BorderThickness());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_IconSource(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IconSource, WINRT_WRAP(Windows::UI::Xaml::Media::ImageSource));
            *value = detach_from<Windows::UI::Xaml::Media::ImageSource>(this->shim().IconSource());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_ContentTransitions(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ContentTransitions, WINRT_WRAP(Windows::UI::Xaml::Media::Animation::TransitionCollection));
            *value = detach_from<Windows::UI::Xaml::Media::Animation::TransitionCollection>(this->shim().ContentTransitions());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Xaml::Controls::Primitives::ISplitViewTemplateSettings> : produce_base<D, Windows::UI::Xaml::Controls::Primitives::ISplitViewTemplateSettings>
{
    int32_t WINRT_CALL get_OpenPaneLength(double* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(OpenPaneLength, WINRT_WRAP(double));
            *value = detach_from<double>(this->shim().OpenPaneLength());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_NegativeOpenPaneLength(double* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(NegativeOpenPaneLength, WINRT_WRAP(double));
            *value = detach_from<double>(this->shim().NegativeOpenPaneLength());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_OpenPaneLengthMinusCompactLength(double* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(OpenPaneLengthMinusCompactLength, WINRT_WRAP(double));
            *value = detach_from<double>(this->shim().OpenPaneLengthMinusCompactLength());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_NegativeOpenPaneLengthMinusCompactLength(double* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(NegativeOpenPaneLengthMinusCompactLength, WINRT_WRAP(double));
            *value = detach_from<double>(this->shim().NegativeOpenPaneLengthMinusCompactLength());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_OpenPaneGridLength(struct struct_Windows_UI_Xaml_GridLength* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(OpenPaneGridLength, WINRT_WRAP(Windows::UI::Xaml::GridLength));
            *value = detach_from<Windows::UI::Xaml::GridLength>(this->shim().OpenPaneGridLength());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_CompactPaneGridLength(struct struct_Windows_UI_Xaml_GridLength* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CompactPaneGridLength, WINRT_WRAP(Windows::UI::Xaml::GridLength));
            *value = detach_from<Windows::UI::Xaml::GridLength>(this->shim().CompactPaneGridLength());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Xaml::Controls::Primitives::IThumb> : produce_base<D, Windows::UI::Xaml::Controls::Primitives::IThumb>
{
    int32_t WINRT_CALL get_IsDragging(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IsDragging, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().IsDragging());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL add_DragStarted(void* handler, winrt::event_token* token) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(DragStarted, WINRT_WRAP(winrt::event_token), Windows::UI::Xaml::Controls::Primitives::DragStartedEventHandler const&);
            *token = detach_from<winrt::event_token>(this->shim().DragStarted(*reinterpret_cast<Windows::UI::Xaml::Controls::Primitives::DragStartedEventHandler const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL remove_DragStarted(winrt::event_token token) noexcept final
    {
        typename D::abi_guard guard(this->shim());
        WINRT_ASSERT_DECLARATION(DragStarted, WINRT_WRAP(void), winrt::event_token const&);
        this->shim().DragStarted(*reinterpret_cast<winrt::event_token const*>(&token));
        return 0;
    }

    int32_t WINRT_CALL add_DragDelta(void* handler, winrt::event_token* token) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(DragDelta, WINRT_WRAP(winrt::event_token), Windows::UI::Xaml::Controls::Primitives::DragDeltaEventHandler const&);
            *token = detach_from<winrt::event_token>(this->shim().DragDelta(*reinterpret_cast<Windows::UI::Xaml::Controls::Primitives::DragDeltaEventHandler const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL remove_DragDelta(winrt::event_token token) noexcept final
    {
        typename D::abi_guard guard(this->shim());
        WINRT_ASSERT_DECLARATION(DragDelta, WINRT_WRAP(void), winrt::event_token const&);
        this->shim().DragDelta(*reinterpret_cast<winrt::event_token const*>(&token));
        return 0;
    }

    int32_t WINRT_CALL add_DragCompleted(void* handler, winrt::event_token* token) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(DragCompleted, WINRT_WRAP(winrt::event_token), Windows::UI::Xaml::Controls::Primitives::DragCompletedEventHandler const&);
            *token = detach_from<winrt::event_token>(this->shim().DragCompleted(*reinterpret_cast<Windows::UI::Xaml::Controls::Primitives::DragCompletedEventHandler const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL remove_DragCompleted(winrt::event_token token) noexcept final
    {
        typename D::abi_guard guard(this->shim());
        WINRT_ASSERT_DECLARATION(DragCompleted, WINRT_WRAP(void), winrt::event_token const&);
        this->shim().DragCompleted(*reinterpret_cast<winrt::event_token const*>(&token));
        return 0;
    }

    int32_t WINRT_CALL CancelDrag() noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CancelDrag, WINRT_WRAP(void));
            this->shim().CancelDrag();
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Xaml::Controls::Primitives::IThumbStatics> : produce_base<D, Windows::UI::Xaml::Controls::Primitives::IThumbStatics>
{
    int32_t WINRT_CALL get_IsDraggingProperty(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IsDraggingProperty, WINRT_WRAP(Windows::UI::Xaml::DependencyProperty));
            *value = detach_from<Windows::UI::Xaml::DependencyProperty>(this->shim().IsDraggingProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Xaml::Controls::Primitives::ITickBar> : produce_base<D, Windows::UI::Xaml::Controls::Primitives::ITickBar>
{
    int32_t WINRT_CALL get_Fill(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Fill, WINRT_WRAP(Windows::UI::Xaml::Media::Brush));
            *value = detach_from<Windows::UI::Xaml::Media::Brush>(this->shim().Fill());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_Fill(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Fill, WINRT_WRAP(void), Windows::UI::Xaml::Media::Brush const&);
            this->shim().Fill(*reinterpret_cast<Windows::UI::Xaml::Media::Brush const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Xaml::Controls::Primitives::ITickBarStatics> : produce_base<D, Windows::UI::Xaml::Controls::Primitives::ITickBarStatics>
{
    int32_t WINRT_CALL get_FillProperty(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(FillProperty, WINRT_WRAP(Windows::UI::Xaml::DependencyProperty));
            *value = detach_from<Windows::UI::Xaml::DependencyProperty>(this->shim().FillProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Xaml::Controls::Primitives::IToggleButton> : produce_base<D, Windows::UI::Xaml::Controls::Primitives::IToggleButton>
{
    int32_t WINRT_CALL get_IsChecked(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IsChecked, WINRT_WRAP(Windows::Foundation::IReference<bool>));
            *value = detach_from<Windows::Foundation::IReference<bool>>(this->shim().IsChecked());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_IsChecked(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IsChecked, WINRT_WRAP(void), Windows::Foundation::IReference<bool> const&);
            this->shim().IsChecked(*reinterpret_cast<Windows::Foundation::IReference<bool> const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_IsThreeState(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IsThreeState, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().IsThreeState());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_IsThreeState(bool value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IsThreeState, WINRT_WRAP(void), bool);
            this->shim().IsThreeState(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL add_Checked(void* handler, winrt::event_token* token) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Checked, WINRT_WRAP(winrt::event_token), Windows::UI::Xaml::RoutedEventHandler const&);
            *token = detach_from<winrt::event_token>(this->shim().Checked(*reinterpret_cast<Windows::UI::Xaml::RoutedEventHandler const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL remove_Checked(winrt::event_token token) noexcept final
    {
        typename D::abi_guard guard(this->shim());
        WINRT_ASSERT_DECLARATION(Checked, WINRT_WRAP(void), winrt::event_token const&);
        this->shim().Checked(*reinterpret_cast<winrt::event_token const*>(&token));
        return 0;
    }

    int32_t WINRT_CALL add_Unchecked(void* handler, winrt::event_token* token) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Unchecked, WINRT_WRAP(winrt::event_token), Windows::UI::Xaml::RoutedEventHandler const&);
            *token = detach_from<winrt::event_token>(this->shim().Unchecked(*reinterpret_cast<Windows::UI::Xaml::RoutedEventHandler const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL remove_Unchecked(winrt::event_token token) noexcept final
    {
        typename D::abi_guard guard(this->shim());
        WINRT_ASSERT_DECLARATION(Unchecked, WINRT_WRAP(void), winrt::event_token const&);
        this->shim().Unchecked(*reinterpret_cast<winrt::event_token const*>(&token));
        return 0;
    }

    int32_t WINRT_CALL add_Indeterminate(void* handler, winrt::event_token* token) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Indeterminate, WINRT_WRAP(winrt::event_token), Windows::UI::Xaml::RoutedEventHandler const&);
            *token = detach_from<winrt::event_token>(this->shim().Indeterminate(*reinterpret_cast<Windows::UI::Xaml::RoutedEventHandler const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL remove_Indeterminate(winrt::event_token token) noexcept final
    {
        typename D::abi_guard guard(this->shim());
        WINRT_ASSERT_DECLARATION(Indeterminate, WINRT_WRAP(void), winrt::event_token const&);
        this->shim().Indeterminate(*reinterpret_cast<winrt::event_token const*>(&token));
        return 0;
    }
};

template <typename D>
struct produce<D, Windows::UI::Xaml::Controls::Primitives::IToggleButtonFactory> : produce_base<D, Windows::UI::Xaml::Controls::Primitives::IToggleButtonFactory>
{
    int32_t WINRT_CALL CreateInstance(void* baseInterface, void** innerInterface, void** value) noexcept final
    {
        try
        {
            if (innerInterface) *innerInterface = nullptr;
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            Windows::Foundation::IInspectable __local_innerInterface;
            WINRT_ASSERT_DECLARATION(CreateInstance, WINRT_WRAP(Windows::UI::Xaml::Controls::Primitives::ToggleButton), Windows::Foundation::IInspectable const&, Windows::Foundation::IInspectable&);
            *value = detach_from<Windows::UI::Xaml::Controls::Primitives::ToggleButton>(this->shim().CreateInstance(*reinterpret_cast<Windows::Foundation::IInspectable const*>(&baseInterface), __local_innerInterface));
            if (innerInterface) *innerInterface = detach_abi(__local_innerInterface);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Xaml::Controls::Primitives::IToggleButtonOverrides> : produce_base<D, Windows::UI::Xaml::Controls::Primitives::IToggleButtonOverrides>
{
    int32_t WINRT_CALL OnToggle() noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(OnToggle, WINRT_WRAP(void));
            this->shim().OnToggle();
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Xaml::Controls::Primitives::IToggleButtonStatics> : produce_base<D, Windows::UI::Xaml::Controls::Primitives::IToggleButtonStatics>
{
    int32_t WINRT_CALL get_IsCheckedProperty(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IsCheckedProperty, WINRT_WRAP(Windows::UI::Xaml::DependencyProperty));
            *value = detach_from<Windows::UI::Xaml::DependencyProperty>(this->shim().IsCheckedProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_IsThreeStateProperty(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IsThreeStateProperty, WINRT_WRAP(Windows::UI::Xaml::DependencyProperty));
            *value = detach_from<Windows::UI::Xaml::DependencyProperty>(this->shim().IsThreeStateProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Xaml::Controls::Primitives::IToggleSwitchTemplateSettings> : produce_base<D, Windows::UI::Xaml::Controls::Primitives::IToggleSwitchTemplateSettings>
{
    int32_t WINRT_CALL get_KnobCurrentToOnOffset(double* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(KnobCurrentToOnOffset, WINRT_WRAP(double));
            *value = detach_from<double>(this->shim().KnobCurrentToOnOffset());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_KnobCurrentToOffOffset(double* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(KnobCurrentToOffOffset, WINRT_WRAP(double));
            *value = detach_from<double>(this->shim().KnobCurrentToOffOffset());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_KnobOnToOffOffset(double* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(KnobOnToOffOffset, WINRT_WRAP(double));
            *value = detach_from<double>(this->shim().KnobOnToOffOffset());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_KnobOffToOnOffset(double* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(KnobOffToOnOffset, WINRT_WRAP(double));
            *value = detach_from<double>(this->shim().KnobOffToOnOffset());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_CurtainCurrentToOnOffset(double* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CurtainCurrentToOnOffset, WINRT_WRAP(double));
            *value = detach_from<double>(this->shim().CurtainCurrentToOnOffset());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_CurtainCurrentToOffOffset(double* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CurtainCurrentToOffOffset, WINRT_WRAP(double));
            *value = detach_from<double>(this->shim().CurtainCurrentToOffOffset());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_CurtainOnToOffOffset(double* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CurtainOnToOffOffset, WINRT_WRAP(double));
            *value = detach_from<double>(this->shim().CurtainOnToOffOffset());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_CurtainOffToOnOffset(double* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CurtainOffToOnOffset, WINRT_WRAP(double));
            *value = detach_from<double>(this->shim().CurtainOffToOnOffset());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Xaml::Controls::Primitives::IToolTipTemplateSettings> : produce_base<D, Windows::UI::Xaml::Controls::Primitives::IToolTipTemplateSettings>
{
    int32_t WINRT_CALL get_FromHorizontalOffset(double* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(FromHorizontalOffset, WINRT_WRAP(double));
            *value = detach_from<double>(this->shim().FromHorizontalOffset());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_FromVerticalOffset(double* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(FromVerticalOffset, WINRT_WRAP(double));
            *value = detach_from<double>(this->shim().FromVerticalOffset());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename T, typename D>
struct WINRT_EBO produce_dispatch_to_overridable<T, D, Windows::UI::Xaml::Controls::Primitives::IFlyoutBaseOverrides>
    : produce_dispatch_to_overridable_base<T, D, Windows::UI::Xaml::Controls::Primitives::IFlyoutBaseOverrides>
{
    Windows::UI::Xaml::Controls::Control CreatePresenter()
    {
        Windows::UI::Xaml::Controls::Primitives::IFlyoutBaseOverrides overridable = this->shim_overridable();
        if (overridable)
        {
            return overridable.CreatePresenter();
        }
        return this->shim().CreatePresenter();
    }
};
template <typename T, typename D>
struct WINRT_EBO produce_dispatch_to_overridable<T, D, Windows::UI::Xaml::Controls::Primitives::IFlyoutBaseOverrides4>
    : produce_dispatch_to_overridable_base<T, D, Windows::UI::Xaml::Controls::Primitives::IFlyoutBaseOverrides4>
{
    void OnProcessKeyboardAccelerators(Windows::UI::Xaml::Input::ProcessKeyboardAcceleratorEventArgs const& args)
    {
        Windows::UI::Xaml::Controls::Primitives::IFlyoutBaseOverrides4 overridable = this->shim_overridable();
        if (overridable)
        {
            return overridable.OnProcessKeyboardAccelerators(args);
        }
        return this->shim().OnProcessKeyboardAccelerators(args);
    }
};
template <typename T, typename D>
struct WINRT_EBO produce_dispatch_to_overridable<T, D, Windows::UI::Xaml::Controls::Primitives::IPickerFlyoutBaseOverrides>
    : produce_dispatch_to_overridable_base<T, D, Windows::UI::Xaml::Controls::Primitives::IPickerFlyoutBaseOverrides>
{
    void OnConfirmed()
    {
        Windows::UI::Xaml::Controls::Primitives::IPickerFlyoutBaseOverrides overridable = this->shim_overridable();
        if (overridable)
        {
            return overridable.OnConfirmed();
        }
        return this->shim().OnConfirmed();
    }
    bool ShouldShowConfirmationButtons()
    {
        Windows::UI::Xaml::Controls::Primitives::IPickerFlyoutBaseOverrides overridable = this->shim_overridable();
        if (overridable)
        {
            return overridable.ShouldShowConfirmationButtons();
        }
        return this->shim().ShouldShowConfirmationButtons();
    }
};
template <typename T, typename D>
struct WINRT_EBO produce_dispatch_to_overridable<T, D, Windows::UI::Xaml::Controls::Primitives::IRangeBaseOverrides>
    : produce_dispatch_to_overridable_base<T, D, Windows::UI::Xaml::Controls::Primitives::IRangeBaseOverrides>
{
    void OnMinimumChanged(double oldMinimum, double newMinimum)
    {
        Windows::UI::Xaml::Controls::Primitives::IRangeBaseOverrides overridable = this->shim_overridable();
        if (overridable)
        {
            return overridable.OnMinimumChanged(oldMinimum, newMinimum);
        }
        return this->shim().OnMinimumChanged(oldMinimum, newMinimum);
    }
    void OnMaximumChanged(double oldMaximum, double newMaximum)
    {
        Windows::UI::Xaml::Controls::Primitives::IRangeBaseOverrides overridable = this->shim_overridable();
        if (overridable)
        {
            return overridable.OnMaximumChanged(oldMaximum, newMaximum);
        }
        return this->shim().OnMaximumChanged(oldMaximum, newMaximum);
    }
    void OnValueChanged(double oldValue, double newValue)
    {
        Windows::UI::Xaml::Controls::Primitives::IRangeBaseOverrides overridable = this->shim_overridable();
        if (overridable)
        {
            return overridable.OnValueChanged(oldValue, newValue);
        }
        return this->shim().OnValueChanged(oldValue, newValue);
    }
};
template <typename T, typename D>
struct WINRT_EBO produce_dispatch_to_overridable<T, D, Windows::UI::Xaml::Controls::Primitives::IToggleButtonOverrides>
    : produce_dispatch_to_overridable_base<T, D, Windows::UI::Xaml::Controls::Primitives::IToggleButtonOverrides>
{
    void OnToggle()
    {
        Windows::UI::Xaml::Controls::Primitives::IToggleButtonOverrides overridable = this->shim_overridable();
        if (overridable)
        {
            return overridable.OnToggle();
        }
        return this->shim().OnToggle();
    }
};
}

WINRT_EXPORT namespace winrt::Windows::UI::Xaml::Controls::Primitives {

inline Windows::UI::Xaml::DependencyProperty ButtonBase::ClickModeProperty()
{
    return impl::call_factory<ButtonBase, Windows::UI::Xaml::Controls::Primitives::IButtonBaseStatics>([&](auto&& f) { return f.ClickModeProperty(); });
}

inline Windows::UI::Xaml::DependencyProperty ButtonBase::IsPointerOverProperty()
{
    return impl::call_factory<ButtonBase, Windows::UI::Xaml::Controls::Primitives::IButtonBaseStatics>([&](auto&& f) { return f.IsPointerOverProperty(); });
}

inline Windows::UI::Xaml::DependencyProperty ButtonBase::IsPressedProperty()
{
    return impl::call_factory<ButtonBase, Windows::UI::Xaml::Controls::Primitives::IButtonBaseStatics>([&](auto&& f) { return f.IsPressedProperty(); });
}

inline Windows::UI::Xaml::DependencyProperty ButtonBase::CommandProperty()
{
    return impl::call_factory<ButtonBase, Windows::UI::Xaml::Controls::Primitives::IButtonBaseStatics>([&](auto&& f) { return f.CommandProperty(); });
}

inline Windows::UI::Xaml::DependencyProperty ButtonBase::CommandParameterProperty()
{
    return impl::call_factory<ButtonBase, Windows::UI::Xaml::Controls::Primitives::IButtonBaseStatics>([&](auto&& f) { return f.CommandParameterProperty(); });
}

inline CalendarPanel::CalendarPanel() :
    CalendarPanel(impl::call_factory<CalendarPanel>([](auto&& f) { return f.template ActivateInstance<CalendarPanel>(); }))
{}

inline CarouselPanel::CarouselPanel()
{
    Windows::Foundation::IInspectable baseInterface, innerInterface;
    *this = impl::call_factory<CarouselPanel, Windows::UI::Xaml::Controls::Primitives::ICarouselPanelFactory>([&](auto&& f) { return f.CreateInstance(baseInterface, innerInterface); });
}

inline ColorPickerSlider::ColorPickerSlider()
{
    Windows::Foundation::IInspectable baseInterface, innerInterface;
    *this = impl::call_factory<ColorPickerSlider, Windows::UI::Xaml::Controls::Primitives::IColorPickerSliderFactory>([&](auto&& f) { return f.CreateInstance(baseInterface, innerInterface); });
}

inline Windows::UI::Xaml::DependencyProperty ColorPickerSlider::ColorChannelProperty()
{
    return impl::call_factory<ColorPickerSlider, Windows::UI::Xaml::Controls::Primitives::IColorPickerSliderStatics>([&](auto&& f) { return f.ColorChannelProperty(); });
}

inline ColorSpectrum::ColorSpectrum()
{
    Windows::Foundation::IInspectable baseInterface, innerInterface;
    *this = impl::call_factory<ColorSpectrum, Windows::UI::Xaml::Controls::Primitives::IColorSpectrumFactory>([&](auto&& f) { return f.CreateInstance(baseInterface, innerInterface); });
}

inline Windows::UI::Xaml::DependencyProperty ColorSpectrum::ColorProperty()
{
    return impl::call_factory<ColorSpectrum, Windows::UI::Xaml::Controls::Primitives::IColorSpectrumStatics>([&](auto&& f) { return f.ColorProperty(); });
}

inline Windows::UI::Xaml::DependencyProperty ColorSpectrum::HsvColorProperty()
{
    return impl::call_factory<ColorSpectrum, Windows::UI::Xaml::Controls::Primitives::IColorSpectrumStatics>([&](auto&& f) { return f.HsvColorProperty(); });
}

inline Windows::UI::Xaml::DependencyProperty ColorSpectrum::MinHueProperty()
{
    return impl::call_factory<ColorSpectrum, Windows::UI::Xaml::Controls::Primitives::IColorSpectrumStatics>([&](auto&& f) { return f.MinHueProperty(); });
}

inline Windows::UI::Xaml::DependencyProperty ColorSpectrum::MaxHueProperty()
{
    return impl::call_factory<ColorSpectrum, Windows::UI::Xaml::Controls::Primitives::IColorSpectrumStatics>([&](auto&& f) { return f.MaxHueProperty(); });
}

inline Windows::UI::Xaml::DependencyProperty ColorSpectrum::MinSaturationProperty()
{
    return impl::call_factory<ColorSpectrum, Windows::UI::Xaml::Controls::Primitives::IColorSpectrumStatics>([&](auto&& f) { return f.MinSaturationProperty(); });
}

inline Windows::UI::Xaml::DependencyProperty ColorSpectrum::MaxSaturationProperty()
{
    return impl::call_factory<ColorSpectrum, Windows::UI::Xaml::Controls::Primitives::IColorSpectrumStatics>([&](auto&& f) { return f.MaxSaturationProperty(); });
}

inline Windows::UI::Xaml::DependencyProperty ColorSpectrum::MinValueProperty()
{
    return impl::call_factory<ColorSpectrum, Windows::UI::Xaml::Controls::Primitives::IColorSpectrumStatics>([&](auto&& f) { return f.MinValueProperty(); });
}

inline Windows::UI::Xaml::DependencyProperty ColorSpectrum::MaxValueProperty()
{
    return impl::call_factory<ColorSpectrum, Windows::UI::Xaml::Controls::Primitives::IColorSpectrumStatics>([&](auto&& f) { return f.MaxValueProperty(); });
}

inline Windows::UI::Xaml::DependencyProperty ColorSpectrum::ShapeProperty()
{
    return impl::call_factory<ColorSpectrum, Windows::UI::Xaml::Controls::Primitives::IColorSpectrumStatics>([&](auto&& f) { return f.ShapeProperty(); });
}

inline Windows::UI::Xaml::DependencyProperty ColorSpectrum::ComponentsProperty()
{
    return impl::call_factory<ColorSpectrum, Windows::UI::Xaml::Controls::Primitives::IColorSpectrumStatics>([&](auto&& f) { return f.ComponentsProperty(); });
}

inline CommandBarFlyoutCommandBar::CommandBarFlyoutCommandBar()
{
    Windows::Foundation::IInspectable baseInterface, innerInterface;
    *this = impl::call_factory<CommandBarFlyoutCommandBar, Windows::UI::Xaml::Controls::Primitives::ICommandBarFlyoutCommandBarFactory>([&](auto&& f) { return f.CreateInstance(baseInterface, innerInterface); });
}

inline DragCompletedEventArgs::DragCompletedEventArgs(double horizontalChange, double verticalChange, bool canceled)
{
    Windows::Foundation::IInspectable baseInterface, innerInterface;
    *this = impl::call_factory<DragCompletedEventArgs, Windows::UI::Xaml::Controls::Primitives::IDragCompletedEventArgsFactory>([&](auto&& f) { return f.CreateInstanceWithHorizontalChangeVerticalChangeAndCanceled(horizontalChange, verticalChange, canceled, baseInterface, innerInterface); });
}

inline DragDeltaEventArgs::DragDeltaEventArgs(double horizontalChange, double verticalChange)
{
    Windows::Foundation::IInspectable baseInterface, innerInterface;
    *this = impl::call_factory<DragDeltaEventArgs, Windows::UI::Xaml::Controls::Primitives::IDragDeltaEventArgsFactory>([&](auto&& f) { return f.CreateInstanceWithHorizontalChangeAndVerticalChange(horizontalChange, verticalChange, baseInterface, innerInterface); });
}

inline DragStartedEventArgs::DragStartedEventArgs(double horizontalOffset, double verticalOffset)
{
    Windows::Foundation::IInspectable baseInterface, innerInterface;
    *this = impl::call_factory<DragStartedEventArgs, Windows::UI::Xaml::Controls::Primitives::IDragStartedEventArgsFactory>([&](auto&& f) { return f.CreateInstanceWithHorizontalOffsetAndVerticalOffset(horizontalOffset, verticalOffset, baseInterface, innerInterface); });
}

inline Windows::UI::Xaml::DependencyProperty FlyoutBase::PlacementProperty()
{
    return impl::call_factory<FlyoutBase, Windows::UI::Xaml::Controls::Primitives::IFlyoutBaseStatics>([&](auto&& f) { return f.PlacementProperty(); });
}

inline Windows::UI::Xaml::DependencyProperty FlyoutBase::AttachedFlyoutProperty()
{
    return impl::call_factory<FlyoutBase, Windows::UI::Xaml::Controls::Primitives::IFlyoutBaseStatics>([&](auto&& f) { return f.AttachedFlyoutProperty(); });
}

inline Windows::UI::Xaml::Controls::Primitives::FlyoutBase FlyoutBase::GetAttachedFlyout(Windows::UI::Xaml::FrameworkElement const& element)
{
    return impl::call_factory<FlyoutBase, Windows::UI::Xaml::Controls::Primitives::IFlyoutBaseStatics>([&](auto&& f) { return f.GetAttachedFlyout(element); });
}

inline void FlyoutBase::SetAttachedFlyout(Windows::UI::Xaml::FrameworkElement const& element, Windows::UI::Xaml::Controls::Primitives::FlyoutBase const& value)
{
    impl::call_factory<FlyoutBase, Windows::UI::Xaml::Controls::Primitives::IFlyoutBaseStatics>([&](auto&& f) { return f.SetAttachedFlyout(element, value); });
}

inline void FlyoutBase::ShowAttachedFlyout(Windows::UI::Xaml::FrameworkElement const& flyoutOwner)
{
    impl::call_factory<FlyoutBase, Windows::UI::Xaml::Controls::Primitives::IFlyoutBaseStatics>([&](auto&& f) { return f.ShowAttachedFlyout(flyoutOwner); });
}

inline Windows::UI::Xaml::DependencyProperty FlyoutBase::AllowFocusOnInteractionProperty()
{
    return impl::call_factory<FlyoutBase, Windows::UI::Xaml::Controls::Primitives::IFlyoutBaseStatics2>([&](auto&& f) { return f.AllowFocusOnInteractionProperty(); });
}

inline Windows::UI::Xaml::DependencyProperty FlyoutBase::LightDismissOverlayModeProperty()
{
    return impl::call_factory<FlyoutBase, Windows::UI::Xaml::Controls::Primitives::IFlyoutBaseStatics2>([&](auto&& f) { return f.LightDismissOverlayModeProperty(); });
}

inline Windows::UI::Xaml::DependencyProperty FlyoutBase::AllowFocusWhenDisabledProperty()
{
    return impl::call_factory<FlyoutBase, Windows::UI::Xaml::Controls::Primitives::IFlyoutBaseStatics2>([&](auto&& f) { return f.AllowFocusWhenDisabledProperty(); });
}

inline Windows::UI::Xaml::DependencyProperty FlyoutBase::ElementSoundModeProperty()
{
    return impl::call_factory<FlyoutBase, Windows::UI::Xaml::Controls::Primitives::IFlyoutBaseStatics2>([&](auto&& f) { return f.ElementSoundModeProperty(); });
}

inline Windows::UI::Xaml::DependencyProperty FlyoutBase::OverlayInputPassThroughElementProperty()
{
    return impl::call_factory<FlyoutBase, Windows::UI::Xaml::Controls::Primitives::IFlyoutBaseStatics3>([&](auto&& f) { return f.OverlayInputPassThroughElementProperty(); });
}

inline Windows::UI::Xaml::DependencyProperty FlyoutBase::TargetProperty()
{
    return impl::call_factory<FlyoutBase, Windows::UI::Xaml::Controls::Primitives::IFlyoutBaseStatics5>([&](auto&& f) { return f.TargetProperty(); });
}

inline Windows::UI::Xaml::DependencyProperty FlyoutBase::ShowModeProperty()
{
    return impl::call_factory<FlyoutBase, Windows::UI::Xaml::Controls::Primitives::IFlyoutBaseStatics5>([&](auto&& f) { return f.ShowModeProperty(); });
}

inline Windows::UI::Xaml::DependencyProperty FlyoutBase::InputDevicePrefersPrimaryCommandsProperty()
{
    return impl::call_factory<FlyoutBase, Windows::UI::Xaml::Controls::Primitives::IFlyoutBaseStatics5>([&](auto&& f) { return f.InputDevicePrefersPrimaryCommandsProperty(); });
}

inline Windows::UI::Xaml::DependencyProperty FlyoutBase::AreOpenCloseAnimationsEnabledProperty()
{
    return impl::call_factory<FlyoutBase, Windows::UI::Xaml::Controls::Primitives::IFlyoutBaseStatics5>([&](auto&& f) { return f.AreOpenCloseAnimationsEnabledProperty(); });
}

inline Windows::UI::Xaml::DependencyProperty FlyoutBase::IsOpenProperty()
{
    return impl::call_factory<FlyoutBase, Windows::UI::Xaml::Controls::Primitives::IFlyoutBaseStatics5>([&](auto&& f) { return f.IsOpenProperty(); });
}

inline Windows::UI::Xaml::DependencyProperty FlyoutBase::ShouldConstrainToRootBoundsProperty()
{
    return impl::call_factory<FlyoutBase, Windows::UI::Xaml::Controls::Primitives::IFlyoutBaseStatics6>([&](auto&& f) { return f.ShouldConstrainToRootBoundsProperty(); });
}

inline FlyoutShowOptions::FlyoutShowOptions()
{
    Windows::Foundation::IInspectable baseInterface, innerInterface;
    *this = impl::call_factory<FlyoutShowOptions, Windows::UI::Xaml::Controls::Primitives::IFlyoutShowOptionsFactory>([&](auto&& f) { return f.CreateInstance(baseInterface, innerInterface); });
}

inline Windows::UI::Xaml::Controls::Primitives::GeneratorPosition GeneratorPositionHelper::FromIndexAndOffset(int32_t index, int32_t offset)
{
    return impl::call_factory<GeneratorPositionHelper, Windows::UI::Xaml::Controls::Primitives::IGeneratorPositionHelperStatics>([&](auto&& f) { return f.FromIndexAndOffset(index, offset); });
}

inline GridViewItemPresenter::GridViewItemPresenter()
{
    Windows::Foundation::IInspectable baseInterface, innerInterface;
    *this = impl::call_factory<GridViewItemPresenter, Windows::UI::Xaml::Controls::Primitives::IGridViewItemPresenterFactory>([&](auto&& f) { return f.CreateInstance(baseInterface, innerInterface); });
}

inline Windows::UI::Xaml::DependencyProperty GridViewItemPresenter::SelectionCheckMarkVisualEnabledProperty()
{
    return impl::call_factory<GridViewItemPresenter, Windows::UI::Xaml::Controls::Primitives::IGridViewItemPresenterStatics>([&](auto&& f) { return f.SelectionCheckMarkVisualEnabledProperty(); });
}

inline Windows::UI::Xaml::DependencyProperty GridViewItemPresenter::CheckHintBrushProperty()
{
    return impl::call_factory<GridViewItemPresenter, Windows::UI::Xaml::Controls::Primitives::IGridViewItemPresenterStatics>([&](auto&& f) { return f.CheckHintBrushProperty(); });
}

inline Windows::UI::Xaml::DependencyProperty GridViewItemPresenter::CheckSelectingBrushProperty()
{
    return impl::call_factory<GridViewItemPresenter, Windows::UI::Xaml::Controls::Primitives::IGridViewItemPresenterStatics>([&](auto&& f) { return f.CheckSelectingBrushProperty(); });
}

inline Windows::UI::Xaml::DependencyProperty GridViewItemPresenter::CheckBrushProperty()
{
    return impl::call_factory<GridViewItemPresenter, Windows::UI::Xaml::Controls::Primitives::IGridViewItemPresenterStatics>([&](auto&& f) { return f.CheckBrushProperty(); });
}

inline Windows::UI::Xaml::DependencyProperty GridViewItemPresenter::DragBackgroundProperty()
{
    return impl::call_factory<GridViewItemPresenter, Windows::UI::Xaml::Controls::Primitives::IGridViewItemPresenterStatics>([&](auto&& f) { return f.DragBackgroundProperty(); });
}

inline Windows::UI::Xaml::DependencyProperty GridViewItemPresenter::DragForegroundProperty()
{
    return impl::call_factory<GridViewItemPresenter, Windows::UI::Xaml::Controls::Primitives::IGridViewItemPresenterStatics>([&](auto&& f) { return f.DragForegroundProperty(); });
}

inline Windows::UI::Xaml::DependencyProperty GridViewItemPresenter::FocusBorderBrushProperty()
{
    return impl::call_factory<GridViewItemPresenter, Windows::UI::Xaml::Controls::Primitives::IGridViewItemPresenterStatics>([&](auto&& f) { return f.FocusBorderBrushProperty(); });
}

inline Windows::UI::Xaml::DependencyProperty GridViewItemPresenter::PlaceholderBackgroundProperty()
{
    return impl::call_factory<GridViewItemPresenter, Windows::UI::Xaml::Controls::Primitives::IGridViewItemPresenterStatics>([&](auto&& f) { return f.PlaceholderBackgroundProperty(); });
}

inline Windows::UI::Xaml::DependencyProperty GridViewItemPresenter::PointerOverBackgroundProperty()
{
    return impl::call_factory<GridViewItemPresenter, Windows::UI::Xaml::Controls::Primitives::IGridViewItemPresenterStatics>([&](auto&& f) { return f.PointerOverBackgroundProperty(); });
}

inline Windows::UI::Xaml::DependencyProperty GridViewItemPresenter::SelectedBackgroundProperty()
{
    return impl::call_factory<GridViewItemPresenter, Windows::UI::Xaml::Controls::Primitives::IGridViewItemPresenterStatics>([&](auto&& f) { return f.SelectedBackgroundProperty(); });
}

inline Windows::UI::Xaml::DependencyProperty GridViewItemPresenter::SelectedForegroundProperty()
{
    return impl::call_factory<GridViewItemPresenter, Windows::UI::Xaml::Controls::Primitives::IGridViewItemPresenterStatics>([&](auto&& f) { return f.SelectedForegroundProperty(); });
}

inline Windows::UI::Xaml::DependencyProperty GridViewItemPresenter::SelectedPointerOverBackgroundProperty()
{
    return impl::call_factory<GridViewItemPresenter, Windows::UI::Xaml::Controls::Primitives::IGridViewItemPresenterStatics>([&](auto&& f) { return f.SelectedPointerOverBackgroundProperty(); });
}

inline Windows::UI::Xaml::DependencyProperty GridViewItemPresenter::SelectedPointerOverBorderBrushProperty()
{
    return impl::call_factory<GridViewItemPresenter, Windows::UI::Xaml::Controls::Primitives::IGridViewItemPresenterStatics>([&](auto&& f) { return f.SelectedPointerOverBorderBrushProperty(); });
}

inline Windows::UI::Xaml::DependencyProperty GridViewItemPresenter::SelectedBorderThicknessProperty()
{
    return impl::call_factory<GridViewItemPresenter, Windows::UI::Xaml::Controls::Primitives::IGridViewItemPresenterStatics>([&](auto&& f) { return f.SelectedBorderThicknessProperty(); });
}

inline Windows::UI::Xaml::DependencyProperty GridViewItemPresenter::DisabledOpacityProperty()
{
    return impl::call_factory<GridViewItemPresenter, Windows::UI::Xaml::Controls::Primitives::IGridViewItemPresenterStatics>([&](auto&& f) { return f.DisabledOpacityProperty(); });
}

inline Windows::UI::Xaml::DependencyProperty GridViewItemPresenter::DragOpacityProperty()
{
    return impl::call_factory<GridViewItemPresenter, Windows::UI::Xaml::Controls::Primitives::IGridViewItemPresenterStatics>([&](auto&& f) { return f.DragOpacityProperty(); });
}

inline Windows::UI::Xaml::DependencyProperty GridViewItemPresenter::ReorderHintOffsetProperty()
{
    return impl::call_factory<GridViewItemPresenter, Windows::UI::Xaml::Controls::Primitives::IGridViewItemPresenterStatics>([&](auto&& f) { return f.ReorderHintOffsetProperty(); });
}

inline Windows::UI::Xaml::DependencyProperty GridViewItemPresenter::GridViewItemPresenterHorizontalContentAlignmentProperty()
{
    return impl::call_factory<GridViewItemPresenter, Windows::UI::Xaml::Controls::Primitives::IGridViewItemPresenterStatics>([&](auto&& f) { return f.GridViewItemPresenterHorizontalContentAlignmentProperty(); });
}

inline Windows::UI::Xaml::DependencyProperty GridViewItemPresenter::GridViewItemPresenterVerticalContentAlignmentProperty()
{
    return impl::call_factory<GridViewItemPresenter, Windows::UI::Xaml::Controls::Primitives::IGridViewItemPresenterStatics>([&](auto&& f) { return f.GridViewItemPresenterVerticalContentAlignmentProperty(); });
}

inline Windows::UI::Xaml::DependencyProperty GridViewItemPresenter::GridViewItemPresenterPaddingProperty()
{
    return impl::call_factory<GridViewItemPresenter, Windows::UI::Xaml::Controls::Primitives::IGridViewItemPresenterStatics>([&](auto&& f) { return f.GridViewItemPresenterPaddingProperty(); });
}

inline Windows::UI::Xaml::DependencyProperty GridViewItemPresenter::PointerOverBackgroundMarginProperty()
{
    return impl::call_factory<GridViewItemPresenter, Windows::UI::Xaml::Controls::Primitives::IGridViewItemPresenterStatics>([&](auto&& f) { return f.PointerOverBackgroundMarginProperty(); });
}

inline Windows::UI::Xaml::DependencyProperty GridViewItemPresenter::ContentMarginProperty()
{
    return impl::call_factory<GridViewItemPresenter, Windows::UI::Xaml::Controls::Primitives::IGridViewItemPresenterStatics>([&](auto&& f) { return f.ContentMarginProperty(); });
}

inline JumpListItemBackgroundConverter::JumpListItemBackgroundConverter() :
    JumpListItemBackgroundConverter(impl::call_factory<JumpListItemBackgroundConverter>([](auto&& f) { return f.template ActivateInstance<JumpListItemBackgroundConverter>(); }))
{}

inline Windows::UI::Xaml::DependencyProperty JumpListItemBackgroundConverter::EnabledProperty()
{
    return impl::call_factory<JumpListItemBackgroundConverter, Windows::UI::Xaml::Controls::Primitives::IJumpListItemBackgroundConverterStatics>([&](auto&& f) { return f.EnabledProperty(); });
}

inline Windows::UI::Xaml::DependencyProperty JumpListItemBackgroundConverter::DisabledProperty()
{
    return impl::call_factory<JumpListItemBackgroundConverter, Windows::UI::Xaml::Controls::Primitives::IJumpListItemBackgroundConverterStatics>([&](auto&& f) { return f.DisabledProperty(); });
}

inline JumpListItemForegroundConverter::JumpListItemForegroundConverter() :
    JumpListItemForegroundConverter(impl::call_factory<JumpListItemForegroundConverter>([](auto&& f) { return f.template ActivateInstance<JumpListItemForegroundConverter>(); }))
{}

inline Windows::UI::Xaml::DependencyProperty JumpListItemForegroundConverter::EnabledProperty()
{
    return impl::call_factory<JumpListItemForegroundConverter, Windows::UI::Xaml::Controls::Primitives::IJumpListItemForegroundConverterStatics>([&](auto&& f) { return f.EnabledProperty(); });
}

inline Windows::UI::Xaml::DependencyProperty JumpListItemForegroundConverter::DisabledProperty()
{
    return impl::call_factory<JumpListItemForegroundConverter, Windows::UI::Xaml::Controls::Primitives::IJumpListItemForegroundConverterStatics>([&](auto&& f) { return f.DisabledProperty(); });
}

inline Windows::UI::Xaml::UIElement LayoutInformation::GetLayoutExceptionElement(Windows::Foundation::IInspectable const& dispatcher)
{
    return impl::call_factory<LayoutInformation, Windows::UI::Xaml::Controls::Primitives::ILayoutInformationStatics>([&](auto&& f) { return f.GetLayoutExceptionElement(dispatcher); });
}

inline Windows::Foundation::Rect LayoutInformation::GetLayoutSlot(Windows::UI::Xaml::FrameworkElement const& element)
{
    return impl::call_factory<LayoutInformation, Windows::UI::Xaml::Controls::Primitives::ILayoutInformationStatics>([&](auto&& f) { return f.GetLayoutSlot(element); });
}

inline Windows::Foundation::Size LayoutInformation::GetAvailableSize(Windows::UI::Xaml::UIElement const& element)
{
    return impl::call_factory<LayoutInformation, Windows::UI::Xaml::Controls::Primitives::ILayoutInformationStatics2>([&](auto&& f) { return f.GetAvailableSize(element); });
}

inline ListViewItemPresenter::ListViewItemPresenter()
{
    Windows::Foundation::IInspectable baseInterface, innerInterface;
    *this = impl::call_factory<ListViewItemPresenter, Windows::UI::Xaml::Controls::Primitives::IListViewItemPresenterFactory>([&](auto&& f) { return f.CreateInstance(baseInterface, innerInterface); });
}

inline Windows::UI::Xaml::DependencyProperty ListViewItemPresenter::SelectionCheckMarkVisualEnabledProperty()
{
    return impl::call_factory<ListViewItemPresenter, Windows::UI::Xaml::Controls::Primitives::IListViewItemPresenterStatics>([&](auto&& f) { return f.SelectionCheckMarkVisualEnabledProperty(); });
}

inline Windows::UI::Xaml::DependencyProperty ListViewItemPresenter::CheckHintBrushProperty()
{
    return impl::call_factory<ListViewItemPresenter, Windows::UI::Xaml::Controls::Primitives::IListViewItemPresenterStatics>([&](auto&& f) { return f.CheckHintBrushProperty(); });
}

inline Windows::UI::Xaml::DependencyProperty ListViewItemPresenter::CheckSelectingBrushProperty()
{
    return impl::call_factory<ListViewItemPresenter, Windows::UI::Xaml::Controls::Primitives::IListViewItemPresenterStatics>([&](auto&& f) { return f.CheckSelectingBrushProperty(); });
}

inline Windows::UI::Xaml::DependencyProperty ListViewItemPresenter::CheckBrushProperty()
{
    return impl::call_factory<ListViewItemPresenter, Windows::UI::Xaml::Controls::Primitives::IListViewItemPresenterStatics>([&](auto&& f) { return f.CheckBrushProperty(); });
}

inline Windows::UI::Xaml::DependencyProperty ListViewItemPresenter::DragBackgroundProperty()
{
    return impl::call_factory<ListViewItemPresenter, Windows::UI::Xaml::Controls::Primitives::IListViewItemPresenterStatics>([&](auto&& f) { return f.DragBackgroundProperty(); });
}

inline Windows::UI::Xaml::DependencyProperty ListViewItemPresenter::DragForegroundProperty()
{
    return impl::call_factory<ListViewItemPresenter, Windows::UI::Xaml::Controls::Primitives::IListViewItemPresenterStatics>([&](auto&& f) { return f.DragForegroundProperty(); });
}

inline Windows::UI::Xaml::DependencyProperty ListViewItemPresenter::FocusBorderBrushProperty()
{
    return impl::call_factory<ListViewItemPresenter, Windows::UI::Xaml::Controls::Primitives::IListViewItemPresenterStatics>([&](auto&& f) { return f.FocusBorderBrushProperty(); });
}

inline Windows::UI::Xaml::DependencyProperty ListViewItemPresenter::PlaceholderBackgroundProperty()
{
    return impl::call_factory<ListViewItemPresenter, Windows::UI::Xaml::Controls::Primitives::IListViewItemPresenterStatics>([&](auto&& f) { return f.PlaceholderBackgroundProperty(); });
}

inline Windows::UI::Xaml::DependencyProperty ListViewItemPresenter::PointerOverBackgroundProperty()
{
    return impl::call_factory<ListViewItemPresenter, Windows::UI::Xaml::Controls::Primitives::IListViewItemPresenterStatics>([&](auto&& f) { return f.PointerOverBackgroundProperty(); });
}

inline Windows::UI::Xaml::DependencyProperty ListViewItemPresenter::SelectedBackgroundProperty()
{
    return impl::call_factory<ListViewItemPresenter, Windows::UI::Xaml::Controls::Primitives::IListViewItemPresenterStatics>([&](auto&& f) { return f.SelectedBackgroundProperty(); });
}

inline Windows::UI::Xaml::DependencyProperty ListViewItemPresenter::SelectedForegroundProperty()
{
    return impl::call_factory<ListViewItemPresenter, Windows::UI::Xaml::Controls::Primitives::IListViewItemPresenterStatics>([&](auto&& f) { return f.SelectedForegroundProperty(); });
}

inline Windows::UI::Xaml::DependencyProperty ListViewItemPresenter::SelectedPointerOverBackgroundProperty()
{
    return impl::call_factory<ListViewItemPresenter, Windows::UI::Xaml::Controls::Primitives::IListViewItemPresenterStatics>([&](auto&& f) { return f.SelectedPointerOverBackgroundProperty(); });
}

inline Windows::UI::Xaml::DependencyProperty ListViewItemPresenter::SelectedPointerOverBorderBrushProperty()
{
    return impl::call_factory<ListViewItemPresenter, Windows::UI::Xaml::Controls::Primitives::IListViewItemPresenterStatics>([&](auto&& f) { return f.SelectedPointerOverBorderBrushProperty(); });
}

inline Windows::UI::Xaml::DependencyProperty ListViewItemPresenter::SelectedBorderThicknessProperty()
{
    return impl::call_factory<ListViewItemPresenter, Windows::UI::Xaml::Controls::Primitives::IListViewItemPresenterStatics>([&](auto&& f) { return f.SelectedBorderThicknessProperty(); });
}

inline Windows::UI::Xaml::DependencyProperty ListViewItemPresenter::DisabledOpacityProperty()
{
    return impl::call_factory<ListViewItemPresenter, Windows::UI::Xaml::Controls::Primitives::IListViewItemPresenterStatics>([&](auto&& f) { return f.DisabledOpacityProperty(); });
}

inline Windows::UI::Xaml::DependencyProperty ListViewItemPresenter::DragOpacityProperty()
{
    return impl::call_factory<ListViewItemPresenter, Windows::UI::Xaml::Controls::Primitives::IListViewItemPresenterStatics>([&](auto&& f) { return f.DragOpacityProperty(); });
}

inline Windows::UI::Xaml::DependencyProperty ListViewItemPresenter::ReorderHintOffsetProperty()
{
    return impl::call_factory<ListViewItemPresenter, Windows::UI::Xaml::Controls::Primitives::IListViewItemPresenterStatics>([&](auto&& f) { return f.ReorderHintOffsetProperty(); });
}

inline Windows::UI::Xaml::DependencyProperty ListViewItemPresenter::ListViewItemPresenterHorizontalContentAlignmentProperty()
{
    return impl::call_factory<ListViewItemPresenter, Windows::UI::Xaml::Controls::Primitives::IListViewItemPresenterStatics>([&](auto&& f) { return f.ListViewItemPresenterHorizontalContentAlignmentProperty(); });
}

inline Windows::UI::Xaml::DependencyProperty ListViewItemPresenter::ListViewItemPresenterVerticalContentAlignmentProperty()
{
    return impl::call_factory<ListViewItemPresenter, Windows::UI::Xaml::Controls::Primitives::IListViewItemPresenterStatics>([&](auto&& f) { return f.ListViewItemPresenterVerticalContentAlignmentProperty(); });
}

inline Windows::UI::Xaml::DependencyProperty ListViewItemPresenter::ListViewItemPresenterPaddingProperty()
{
    return impl::call_factory<ListViewItemPresenter, Windows::UI::Xaml::Controls::Primitives::IListViewItemPresenterStatics>([&](auto&& f) { return f.ListViewItemPresenterPaddingProperty(); });
}

inline Windows::UI::Xaml::DependencyProperty ListViewItemPresenter::PointerOverBackgroundMarginProperty()
{
    return impl::call_factory<ListViewItemPresenter, Windows::UI::Xaml::Controls::Primitives::IListViewItemPresenterStatics>([&](auto&& f) { return f.PointerOverBackgroundMarginProperty(); });
}

inline Windows::UI::Xaml::DependencyProperty ListViewItemPresenter::ContentMarginProperty()
{
    return impl::call_factory<ListViewItemPresenter, Windows::UI::Xaml::Controls::Primitives::IListViewItemPresenterStatics>([&](auto&& f) { return f.ContentMarginProperty(); });
}

inline Windows::UI::Xaml::DependencyProperty ListViewItemPresenter::SelectedPressedBackgroundProperty()
{
    return impl::call_factory<ListViewItemPresenter, Windows::UI::Xaml::Controls::Primitives::IListViewItemPresenterStatics2>([&](auto&& f) { return f.SelectedPressedBackgroundProperty(); });
}

inline Windows::UI::Xaml::DependencyProperty ListViewItemPresenter::PressedBackgroundProperty()
{
    return impl::call_factory<ListViewItemPresenter, Windows::UI::Xaml::Controls::Primitives::IListViewItemPresenterStatics2>([&](auto&& f) { return f.PressedBackgroundProperty(); });
}

inline Windows::UI::Xaml::DependencyProperty ListViewItemPresenter::CheckBoxBrushProperty()
{
    return impl::call_factory<ListViewItemPresenter, Windows::UI::Xaml::Controls::Primitives::IListViewItemPresenterStatics2>([&](auto&& f) { return f.CheckBoxBrushProperty(); });
}

inline Windows::UI::Xaml::DependencyProperty ListViewItemPresenter::FocusSecondaryBorderBrushProperty()
{
    return impl::call_factory<ListViewItemPresenter, Windows::UI::Xaml::Controls::Primitives::IListViewItemPresenterStatics2>([&](auto&& f) { return f.FocusSecondaryBorderBrushProperty(); });
}

inline Windows::UI::Xaml::DependencyProperty ListViewItemPresenter::CheckModeProperty()
{
    return impl::call_factory<ListViewItemPresenter, Windows::UI::Xaml::Controls::Primitives::IListViewItemPresenterStatics2>([&](auto&& f) { return f.CheckModeProperty(); });
}

inline Windows::UI::Xaml::DependencyProperty ListViewItemPresenter::PointerOverForegroundProperty()
{
    return impl::call_factory<ListViewItemPresenter, Windows::UI::Xaml::Controls::Primitives::IListViewItemPresenterStatics2>([&](auto&& f) { return f.PointerOverForegroundProperty(); });
}

inline Windows::UI::Xaml::DependencyProperty ListViewItemPresenter::RevealBackgroundProperty()
{
    return impl::call_factory<ListViewItemPresenter, Windows::UI::Xaml::Controls::Primitives::IListViewItemPresenterStatics3>([&](auto&& f) { return f.RevealBackgroundProperty(); });
}

inline Windows::UI::Xaml::DependencyProperty ListViewItemPresenter::RevealBorderBrushProperty()
{
    return impl::call_factory<ListViewItemPresenter, Windows::UI::Xaml::Controls::Primitives::IListViewItemPresenterStatics3>([&](auto&& f) { return f.RevealBorderBrushProperty(); });
}

inline Windows::UI::Xaml::DependencyProperty ListViewItemPresenter::RevealBorderThicknessProperty()
{
    return impl::call_factory<ListViewItemPresenter, Windows::UI::Xaml::Controls::Primitives::IListViewItemPresenterStatics3>([&](auto&& f) { return f.RevealBorderThicknessProperty(); });
}

inline Windows::UI::Xaml::DependencyProperty ListViewItemPresenter::RevealBackgroundShowsAboveContentProperty()
{
    return impl::call_factory<ListViewItemPresenter, Windows::UI::Xaml::Controls::Primitives::IListViewItemPresenterStatics3>([&](auto&& f) { return f.RevealBackgroundShowsAboveContentProperty(); });
}

inline Windows::UI::Xaml::DependencyProperty LoopingSelector::ShouldLoopProperty()
{
    return impl::call_factory<LoopingSelector, Windows::UI::Xaml::Controls::Primitives::ILoopingSelectorStatics>([&](auto&& f) { return f.ShouldLoopProperty(); });
}

inline Windows::UI::Xaml::DependencyProperty LoopingSelector::ItemsProperty()
{
    return impl::call_factory<LoopingSelector, Windows::UI::Xaml::Controls::Primitives::ILoopingSelectorStatics>([&](auto&& f) { return f.ItemsProperty(); });
}

inline Windows::UI::Xaml::DependencyProperty LoopingSelector::SelectedIndexProperty()
{
    return impl::call_factory<LoopingSelector, Windows::UI::Xaml::Controls::Primitives::ILoopingSelectorStatics>([&](auto&& f) { return f.SelectedIndexProperty(); });
}

inline Windows::UI::Xaml::DependencyProperty LoopingSelector::SelectedItemProperty()
{
    return impl::call_factory<LoopingSelector, Windows::UI::Xaml::Controls::Primitives::ILoopingSelectorStatics>([&](auto&& f) { return f.SelectedItemProperty(); });
}

inline Windows::UI::Xaml::DependencyProperty LoopingSelector::ItemWidthProperty()
{
    return impl::call_factory<LoopingSelector, Windows::UI::Xaml::Controls::Primitives::ILoopingSelectorStatics>([&](auto&& f) { return f.ItemWidthProperty(); });
}

inline Windows::UI::Xaml::DependencyProperty LoopingSelector::ItemHeightProperty()
{
    return impl::call_factory<LoopingSelector, Windows::UI::Xaml::Controls::Primitives::ILoopingSelectorStatics>([&](auto&& f) { return f.ItemHeightProperty(); });
}

inline Windows::UI::Xaml::DependencyProperty LoopingSelector::ItemTemplateProperty()
{
    return impl::call_factory<LoopingSelector, Windows::UI::Xaml::Controls::Primitives::ILoopingSelectorStatics>([&](auto&& f) { return f.ItemTemplateProperty(); });
}

inline NavigationViewItemPresenter::NavigationViewItemPresenter()
{
    Windows::Foundation::IInspectable baseInterface, innerInterface;
    *this = impl::call_factory<NavigationViewItemPresenter, Windows::UI::Xaml::Controls::Primitives::INavigationViewItemPresenterFactory>([&](auto&& f) { return f.CreateInstance(baseInterface, innerInterface); });
}

inline Windows::UI::Xaml::DependencyProperty NavigationViewItemPresenter::IconProperty()
{
    return impl::call_factory<NavigationViewItemPresenter, Windows::UI::Xaml::Controls::Primitives::INavigationViewItemPresenterStatics>([&](auto&& f) { return f.IconProperty(); });
}

inline Windows::UI::Xaml::DependencyProperty PickerFlyoutBase::TitleProperty()
{
    return impl::call_factory<PickerFlyoutBase, Windows::UI::Xaml::Controls::Primitives::IPickerFlyoutBaseStatics>([&](auto&& f) { return f.TitleProperty(); });
}

inline hstring PickerFlyoutBase::GetTitle(Windows::UI::Xaml::DependencyObject const& element)
{
    return impl::call_factory<PickerFlyoutBase, Windows::UI::Xaml::Controls::Primitives::IPickerFlyoutBaseStatics>([&](auto&& f) { return f.GetTitle(element); });
}

inline void PickerFlyoutBase::SetTitle(Windows::UI::Xaml::DependencyObject const& element, param::hstring const& value)
{
    impl::call_factory<PickerFlyoutBase, Windows::UI::Xaml::Controls::Primitives::IPickerFlyoutBaseStatics>([&](auto&& f) { return f.SetTitle(element, value); });
}

inline PivotHeaderItem::PivotHeaderItem()
{
    Windows::Foundation::IInspectable baseInterface, innerInterface;
    *this = impl::call_factory<PivotHeaderItem, Windows::UI::Xaml::Controls::Primitives::IPivotHeaderItemFactory>([&](auto&& f) { return f.CreateInstance(baseInterface, innerInterface); });
}

inline PivotHeaderPanel::PivotHeaderPanel() :
    PivotHeaderPanel(impl::call_factory<PivotHeaderPanel>([](auto&& f) { return f.template ActivateInstance<PivotHeaderPanel>(); }))
{}

inline PivotPanel::PivotPanel() :
    PivotPanel(impl::call_factory<PivotPanel>([](auto&& f) { return f.template ActivateInstance<PivotPanel>(); }))
{}

inline Popup::Popup() :
    Popup(impl::call_factory<Popup>([](auto&& f) { return f.template ActivateInstance<Popup>(); }))
{}

inline Windows::UI::Xaml::DependencyProperty Popup::ChildProperty()
{
    return impl::call_factory<Popup, Windows::UI::Xaml::Controls::Primitives::IPopupStatics>([&](auto&& f) { return f.ChildProperty(); });
}

inline Windows::UI::Xaml::DependencyProperty Popup::IsOpenProperty()
{
    return impl::call_factory<Popup, Windows::UI::Xaml::Controls::Primitives::IPopupStatics>([&](auto&& f) { return f.IsOpenProperty(); });
}

inline Windows::UI::Xaml::DependencyProperty Popup::HorizontalOffsetProperty()
{
    return impl::call_factory<Popup, Windows::UI::Xaml::Controls::Primitives::IPopupStatics>([&](auto&& f) { return f.HorizontalOffsetProperty(); });
}

inline Windows::UI::Xaml::DependencyProperty Popup::VerticalOffsetProperty()
{
    return impl::call_factory<Popup, Windows::UI::Xaml::Controls::Primitives::IPopupStatics>([&](auto&& f) { return f.VerticalOffsetProperty(); });
}

inline Windows::UI::Xaml::DependencyProperty Popup::ChildTransitionsProperty()
{
    return impl::call_factory<Popup, Windows::UI::Xaml::Controls::Primitives::IPopupStatics>([&](auto&& f) { return f.ChildTransitionsProperty(); });
}

inline Windows::UI::Xaml::DependencyProperty Popup::IsLightDismissEnabledProperty()
{
    return impl::call_factory<Popup, Windows::UI::Xaml::Controls::Primitives::IPopupStatics>([&](auto&& f) { return f.IsLightDismissEnabledProperty(); });
}

inline Windows::UI::Xaml::DependencyProperty Popup::LightDismissOverlayModeProperty()
{
    return impl::call_factory<Popup, Windows::UI::Xaml::Controls::Primitives::IPopupStatics2>([&](auto&& f) { return f.LightDismissOverlayModeProperty(); });
}

inline Windows::UI::Xaml::DependencyProperty Popup::ShouldConstrainToRootBoundsProperty()
{
    return impl::call_factory<Popup, Windows::UI::Xaml::Controls::Primitives::IPopupStatics3>([&](auto&& f) { return f.ShouldConstrainToRootBoundsProperty(); });
}

inline Windows::UI::Xaml::DependencyProperty RangeBase::MinimumProperty()
{
    return impl::call_factory<RangeBase, Windows::UI::Xaml::Controls::Primitives::IRangeBaseStatics>([&](auto&& f) { return f.MinimumProperty(); });
}

inline Windows::UI::Xaml::DependencyProperty RangeBase::MaximumProperty()
{
    return impl::call_factory<RangeBase, Windows::UI::Xaml::Controls::Primitives::IRangeBaseStatics>([&](auto&& f) { return f.MaximumProperty(); });
}

inline Windows::UI::Xaml::DependencyProperty RangeBase::SmallChangeProperty()
{
    return impl::call_factory<RangeBase, Windows::UI::Xaml::Controls::Primitives::IRangeBaseStatics>([&](auto&& f) { return f.SmallChangeProperty(); });
}

inline Windows::UI::Xaml::DependencyProperty RangeBase::LargeChangeProperty()
{
    return impl::call_factory<RangeBase, Windows::UI::Xaml::Controls::Primitives::IRangeBaseStatics>([&](auto&& f) { return f.LargeChangeProperty(); });
}

inline Windows::UI::Xaml::DependencyProperty RangeBase::ValueProperty()
{
    return impl::call_factory<RangeBase, Windows::UI::Xaml::Controls::Primitives::IRangeBaseStatics>([&](auto&& f) { return f.ValueProperty(); });
}

inline RepeatButton::RepeatButton() :
    RepeatButton(impl::call_factory<RepeatButton>([](auto&& f) { return f.template ActivateInstance<RepeatButton>(); }))
{}

inline Windows::UI::Xaml::DependencyProperty RepeatButton::DelayProperty()
{
    return impl::call_factory<RepeatButton, Windows::UI::Xaml::Controls::Primitives::IRepeatButtonStatics>([&](auto&& f) { return f.DelayProperty(); });
}

inline Windows::UI::Xaml::DependencyProperty RepeatButton::IntervalProperty()
{
    return impl::call_factory<RepeatButton, Windows::UI::Xaml::Controls::Primitives::IRepeatButtonStatics>([&](auto&& f) { return f.IntervalProperty(); });
}

inline ScrollBar::ScrollBar() :
    ScrollBar(impl::call_factory<ScrollBar>([](auto&& f) { return f.template ActivateInstance<ScrollBar>(); }))
{}

inline Windows::UI::Xaml::DependencyProperty ScrollBar::OrientationProperty()
{
    return impl::call_factory<ScrollBar, Windows::UI::Xaml::Controls::Primitives::IScrollBarStatics>([&](auto&& f) { return f.OrientationProperty(); });
}

inline Windows::UI::Xaml::DependencyProperty ScrollBar::ViewportSizeProperty()
{
    return impl::call_factory<ScrollBar, Windows::UI::Xaml::Controls::Primitives::IScrollBarStatics>([&](auto&& f) { return f.ViewportSizeProperty(); });
}

inline Windows::UI::Xaml::DependencyProperty ScrollBar::IndicatorModeProperty()
{
    return impl::call_factory<ScrollBar, Windows::UI::Xaml::Controls::Primitives::IScrollBarStatics>([&](auto&& f) { return f.IndicatorModeProperty(); });
}

inline ScrollEventArgs::ScrollEventArgs() :
    ScrollEventArgs(impl::call_factory<ScrollEventArgs>([](auto&& f) { return f.template ActivateInstance<ScrollEventArgs>(); }))
{}

inline Windows::UI::Xaml::DependencyProperty Selector::SelectedIndexProperty()
{
    return impl::call_factory<Selector, Windows::UI::Xaml::Controls::Primitives::ISelectorStatics>([&](auto&& f) { return f.SelectedIndexProperty(); });
}

inline Windows::UI::Xaml::DependencyProperty Selector::SelectedItemProperty()
{
    return impl::call_factory<Selector, Windows::UI::Xaml::Controls::Primitives::ISelectorStatics>([&](auto&& f) { return f.SelectedItemProperty(); });
}

inline Windows::UI::Xaml::DependencyProperty Selector::SelectedValueProperty()
{
    return impl::call_factory<Selector, Windows::UI::Xaml::Controls::Primitives::ISelectorStatics>([&](auto&& f) { return f.SelectedValueProperty(); });
}

inline Windows::UI::Xaml::DependencyProperty Selector::SelectedValuePathProperty()
{
    return impl::call_factory<Selector, Windows::UI::Xaml::Controls::Primitives::ISelectorStatics>([&](auto&& f) { return f.SelectedValuePathProperty(); });
}

inline Windows::UI::Xaml::DependencyProperty Selector::IsSynchronizedWithCurrentItemProperty()
{
    return impl::call_factory<Selector, Windows::UI::Xaml::Controls::Primitives::ISelectorStatics>([&](auto&& f) { return f.IsSynchronizedWithCurrentItemProperty(); });
}

inline bool Selector::GetIsSelectionActive(Windows::UI::Xaml::DependencyObject const& element)
{
    return impl::call_factory<Selector, Windows::UI::Xaml::Controls::Primitives::ISelectorStatics>([&](auto&& f) { return f.GetIsSelectionActive(element); });
}

inline Windows::UI::Xaml::DependencyProperty SelectorItem::IsSelectedProperty()
{
    return impl::call_factory<SelectorItem, Windows::UI::Xaml::Controls::Primitives::ISelectorItemStatics>([&](auto&& f) { return f.IsSelectedProperty(); });
}

inline Thumb::Thumb() :
    Thumb(impl::call_factory<Thumb>([](auto&& f) { return f.template ActivateInstance<Thumb>(); }))
{}

inline Windows::UI::Xaml::DependencyProperty Thumb::IsDraggingProperty()
{
    return impl::call_factory<Thumb, Windows::UI::Xaml::Controls::Primitives::IThumbStatics>([&](auto&& f) { return f.IsDraggingProperty(); });
}

inline TickBar::TickBar() :
    TickBar(impl::call_factory<TickBar>([](auto&& f) { return f.template ActivateInstance<TickBar>(); }))
{}

inline Windows::UI::Xaml::DependencyProperty TickBar::FillProperty()
{
    return impl::call_factory<TickBar, Windows::UI::Xaml::Controls::Primitives::ITickBarStatics>([&](auto&& f) { return f.FillProperty(); });
}

inline ToggleButton::ToggleButton()
{
    Windows::Foundation::IInspectable baseInterface, innerInterface;
    *this = impl::call_factory<ToggleButton, Windows::UI::Xaml::Controls::Primitives::IToggleButtonFactory>([&](auto&& f) { return f.CreateInstance(baseInterface, innerInterface); });
}

inline Windows::UI::Xaml::DependencyProperty ToggleButton::IsCheckedProperty()
{
    return impl::call_factory<ToggleButton, Windows::UI::Xaml::Controls::Primitives::IToggleButtonStatics>([&](auto&& f) { return f.IsCheckedProperty(); });
}

inline Windows::UI::Xaml::DependencyProperty ToggleButton::IsThreeStateProperty()
{
    return impl::call_factory<ToggleButton, Windows::UI::Xaml::Controls::Primitives::IToggleButtonStatics>([&](auto&& f) { return f.IsThreeStateProperty(); });
}

template <typename L> DragCompletedEventHandler::DragCompletedEventHandler(L handler) :
    DragCompletedEventHandler(impl::make_delegate<DragCompletedEventHandler>(std::forward<L>(handler)))
{}

template <typename F> DragCompletedEventHandler::DragCompletedEventHandler(F* handler) :
    DragCompletedEventHandler([=](auto&&... args) { return handler(args...); })
{}

template <typename O, typename M> DragCompletedEventHandler::DragCompletedEventHandler(O* object, M method) :
    DragCompletedEventHandler([=](auto&&... args) { return ((*object).*(method))(args...); })
{}

template <typename O, typename M> DragCompletedEventHandler::DragCompletedEventHandler(com_ptr<O>&& object, M method) :
    DragCompletedEventHandler([o = std::move(object), method](auto&&... args) { return ((*o).*(method))(args...); })
{}

template <typename O, typename M> DragCompletedEventHandler::DragCompletedEventHandler(weak_ref<O>&& object, M method) :
    DragCompletedEventHandler([o = std::move(object), method](auto&&... args) { if (auto s = o.get()) { ((*s).*(method))(args...); } })
{}

inline void DragCompletedEventHandler::operator()(Windows::Foundation::IInspectable const& sender, Windows::UI::Xaml::Controls::Primitives::DragCompletedEventArgs const& e) const
{
    check_hresult((*(impl::abi_t<DragCompletedEventHandler>**)this)->Invoke(get_abi(sender), get_abi(e)));
}

template <typename L> DragDeltaEventHandler::DragDeltaEventHandler(L handler) :
    DragDeltaEventHandler(impl::make_delegate<DragDeltaEventHandler>(std::forward<L>(handler)))
{}

template <typename F> DragDeltaEventHandler::DragDeltaEventHandler(F* handler) :
    DragDeltaEventHandler([=](auto&&... args) { return handler(args...); })
{}

template <typename O, typename M> DragDeltaEventHandler::DragDeltaEventHandler(O* object, M method) :
    DragDeltaEventHandler([=](auto&&... args) { return ((*object).*(method))(args...); })
{}

template <typename O, typename M> DragDeltaEventHandler::DragDeltaEventHandler(com_ptr<O>&& object, M method) :
    DragDeltaEventHandler([o = std::move(object), method](auto&&... args) { return ((*o).*(method))(args...); })
{}

template <typename O, typename M> DragDeltaEventHandler::DragDeltaEventHandler(weak_ref<O>&& object, M method) :
    DragDeltaEventHandler([o = std::move(object), method](auto&&... args) { if (auto s = o.get()) { ((*s).*(method))(args...); } })
{}

inline void DragDeltaEventHandler::operator()(Windows::Foundation::IInspectable const& sender, Windows::UI::Xaml::Controls::Primitives::DragDeltaEventArgs const& e) const
{
    check_hresult((*(impl::abi_t<DragDeltaEventHandler>**)this)->Invoke(get_abi(sender), get_abi(e)));
}

template <typename L> DragStartedEventHandler::DragStartedEventHandler(L handler) :
    DragStartedEventHandler(impl::make_delegate<DragStartedEventHandler>(std::forward<L>(handler)))
{}

template <typename F> DragStartedEventHandler::DragStartedEventHandler(F* handler) :
    DragStartedEventHandler([=](auto&&... args) { return handler(args...); })
{}

template <typename O, typename M> DragStartedEventHandler::DragStartedEventHandler(O* object, M method) :
    DragStartedEventHandler([=](auto&&... args) { return ((*object).*(method))(args...); })
{}

template <typename O, typename M> DragStartedEventHandler::DragStartedEventHandler(com_ptr<O>&& object, M method) :
    DragStartedEventHandler([o = std::move(object), method](auto&&... args) { return ((*o).*(method))(args...); })
{}

template <typename O, typename M> DragStartedEventHandler::DragStartedEventHandler(weak_ref<O>&& object, M method) :
    DragStartedEventHandler([o = std::move(object), method](auto&&... args) { if (auto s = o.get()) { ((*s).*(method))(args...); } })
{}

inline void DragStartedEventHandler::operator()(Windows::Foundation::IInspectable const& sender, Windows::UI::Xaml::Controls::Primitives::DragStartedEventArgs const& e) const
{
    check_hresult((*(impl::abi_t<DragStartedEventHandler>**)this)->Invoke(get_abi(sender), get_abi(e)));
}

template <typename L> ItemsChangedEventHandler::ItemsChangedEventHandler(L handler) :
    ItemsChangedEventHandler(impl::make_delegate<ItemsChangedEventHandler>(std::forward<L>(handler)))
{}

template <typename F> ItemsChangedEventHandler::ItemsChangedEventHandler(F* handler) :
    ItemsChangedEventHandler([=](auto&&... args) { return handler(args...); })
{}

template <typename O, typename M> ItemsChangedEventHandler::ItemsChangedEventHandler(O* object, M method) :
    ItemsChangedEventHandler([=](auto&&... args) { return ((*object).*(method))(args...); })
{}

template <typename O, typename M> ItemsChangedEventHandler::ItemsChangedEventHandler(com_ptr<O>&& object, M method) :
    ItemsChangedEventHandler([o = std::move(object), method](auto&&... args) { return ((*o).*(method))(args...); })
{}

template <typename O, typename M> ItemsChangedEventHandler::ItemsChangedEventHandler(weak_ref<O>&& object, M method) :
    ItemsChangedEventHandler([o = std::move(object), method](auto&&... args) { if (auto s = o.get()) { ((*s).*(method))(args...); } })
{}

inline void ItemsChangedEventHandler::operator()(Windows::Foundation::IInspectable const& sender, Windows::UI::Xaml::Controls::Primitives::ItemsChangedEventArgs const& e) const
{
    check_hresult((*(impl::abi_t<ItemsChangedEventHandler>**)this)->Invoke(get_abi(sender), get_abi(e)));
}

template <typename L> RangeBaseValueChangedEventHandler::RangeBaseValueChangedEventHandler(L handler) :
    RangeBaseValueChangedEventHandler(impl::make_delegate<RangeBaseValueChangedEventHandler>(std::forward<L>(handler)))
{}

template <typename F> RangeBaseValueChangedEventHandler::RangeBaseValueChangedEventHandler(F* handler) :
    RangeBaseValueChangedEventHandler([=](auto&&... args) { return handler(args...); })
{}

template <typename O, typename M> RangeBaseValueChangedEventHandler::RangeBaseValueChangedEventHandler(O* object, M method) :
    RangeBaseValueChangedEventHandler([=](auto&&... args) { return ((*object).*(method))(args...); })
{}

template <typename O, typename M> RangeBaseValueChangedEventHandler::RangeBaseValueChangedEventHandler(com_ptr<O>&& object, M method) :
    RangeBaseValueChangedEventHandler([o = std::move(object), method](auto&&... args) { return ((*o).*(method))(args...); })
{}

template <typename O, typename M> RangeBaseValueChangedEventHandler::RangeBaseValueChangedEventHandler(weak_ref<O>&& object, M method) :
    RangeBaseValueChangedEventHandler([o = std::move(object), method](auto&&... args) { if (auto s = o.get()) { ((*s).*(method))(args...); } })
{}

inline void RangeBaseValueChangedEventHandler::operator()(Windows::Foundation::IInspectable const& sender, Windows::UI::Xaml::Controls::Primitives::RangeBaseValueChangedEventArgs const& e) const
{
    check_hresult((*(impl::abi_t<RangeBaseValueChangedEventHandler>**)this)->Invoke(get_abi(sender), get_abi(e)));
}

template <typename L> ScrollEventHandler::ScrollEventHandler(L handler) :
    ScrollEventHandler(impl::make_delegate<ScrollEventHandler>(std::forward<L>(handler)))
{}

template <typename F> ScrollEventHandler::ScrollEventHandler(F* handler) :
    ScrollEventHandler([=](auto&&... args) { return handler(args...); })
{}

template <typename O, typename M> ScrollEventHandler::ScrollEventHandler(O* object, M method) :
    ScrollEventHandler([=](auto&&... args) { return ((*object).*(method))(args...); })
{}

template <typename O, typename M> ScrollEventHandler::ScrollEventHandler(com_ptr<O>&& object, M method) :
    ScrollEventHandler([o = std::move(object), method](auto&&... args) { return ((*o).*(method))(args...); })
{}

template <typename O, typename M> ScrollEventHandler::ScrollEventHandler(weak_ref<O>&& object, M method) :
    ScrollEventHandler([o = std::move(object), method](auto&&... args) { if (auto s = o.get()) { ((*s).*(method))(args...); } })
{}

inline void ScrollEventHandler::operator()(Windows::Foundation::IInspectable const& sender, Windows::UI::Xaml::Controls::Primitives::ScrollEventArgs const& e) const
{
    check_hresult((*(impl::abi_t<ScrollEventHandler>**)this)->Invoke(get_abi(sender), get_abi(e)));
}

template <typename D> Windows::UI::Xaml::Controls::Control IFlyoutBaseOverridesT<D>::CreatePresenter() const
{
    return shim().template try_as<IFlyoutBaseOverrides>().CreatePresenter();
}

template <typename D> void IFlyoutBaseOverrides4T<D>::OnProcessKeyboardAccelerators(Windows::UI::Xaml::Input::ProcessKeyboardAcceleratorEventArgs const& args) const
{
    return shim().template try_as<IFlyoutBaseOverrides4>().OnProcessKeyboardAccelerators(args);
}

template <typename D> void IPickerFlyoutBaseOverridesT<D>::OnConfirmed() const
{
    return shim().template try_as<IPickerFlyoutBaseOverrides>().OnConfirmed();
}

template <typename D> bool IPickerFlyoutBaseOverridesT<D>::ShouldShowConfirmationButtons() const
{
    return shim().template try_as<IPickerFlyoutBaseOverrides>().ShouldShowConfirmationButtons();
}

template <typename D> void IRangeBaseOverridesT<D>::OnMinimumChanged(double oldMinimum, double newMinimum) const
{
    return shim().template try_as<IRangeBaseOverrides>().OnMinimumChanged(oldMinimum, newMinimum);
}

template <typename D> void IRangeBaseOverridesT<D>::OnMaximumChanged(double oldMaximum, double newMaximum) const
{
    return shim().template try_as<IRangeBaseOverrides>().OnMaximumChanged(oldMaximum, newMaximum);
}

template <typename D> void IRangeBaseOverridesT<D>::OnValueChanged(double oldValue, double newValue) const
{
    return shim().template try_as<IRangeBaseOverrides>().OnValueChanged(oldValue, newValue);
}

template <typename D> void IToggleButtonOverridesT<D>::OnToggle() const
{
    return shim().template try_as<IToggleButtonOverrides>().OnToggle();
}

template <typename D, typename... Interfaces>
struct ButtonBaseT :
    implements<D, Windows::UI::Xaml::Controls::IContentControlOverrides, Windows::UI::Xaml::Controls::IControlOverrides, Windows::UI::Xaml::Controls::IControlOverrides6, Windows::UI::Xaml::IFrameworkElementOverrides, Windows::UI::Xaml::IFrameworkElementOverrides2, Windows::UI::Xaml::IUIElementOverrides, Windows::UI::Xaml::IUIElementOverrides7, Windows::UI::Xaml::IUIElementOverrides8, Windows::UI::Xaml::IUIElementOverrides9, composing, Interfaces...>,
    impl::require<D, Windows::UI::Xaml::Controls::Primitives::IButtonBase, Windows::UI::Composition::IAnimationObject, Windows::UI::Composition::IVisualElement, Windows::UI::Xaml::Controls::IContentControl, Windows::UI::Xaml::Controls::IContentControl2, Windows::UI::Xaml::Controls::IControl, Windows::UI::Xaml::Controls::IControl2, Windows::UI::Xaml::Controls::IControl3, Windows::UI::Xaml::Controls::IControl4, Windows::UI::Xaml::Controls::IControl5, Windows::UI::Xaml::Controls::IControl7, Windows::UI::Xaml::Controls::IControlProtected, Windows::UI::Xaml::IDependencyObject, Windows::UI::Xaml::IDependencyObject2, Windows::UI::Xaml::IFrameworkElement, Windows::UI::Xaml::IFrameworkElement2, Windows::UI::Xaml::IFrameworkElement3, Windows::UI::Xaml::IFrameworkElement4, Windows::UI::Xaml::IFrameworkElement6, Windows::UI::Xaml::IFrameworkElement7, Windows::UI::Xaml::IFrameworkElementProtected7, Windows::UI::Xaml::IUIElement, Windows::UI::Xaml::IUIElement10, Windows::UI::Xaml::IUIElement2, Windows::UI::Xaml::IUIElement3, Windows::UI::Xaml::IUIElement4, Windows::UI::Xaml::IUIElement5, Windows::UI::Xaml::IUIElement7, Windows::UI::Xaml::IUIElement8, Windows::UI::Xaml::IUIElement9>,
    impl::base<D, Windows::UI::Xaml::Controls::Primitives::ButtonBase, Windows::UI::Xaml::Controls::ContentControl, Windows::UI::Xaml::Controls::Control, Windows::UI::Xaml::FrameworkElement, Windows::UI::Xaml::UIElement, Windows::UI::Xaml::DependencyObject>,
    Windows::UI::Xaml::Controls::IContentControlOverridesT<D>, Windows::UI::Xaml::Controls::IControlOverridesT<D>, Windows::UI::Xaml::Controls::IControlOverrides6T<D>, Windows::UI::Xaml::IFrameworkElementOverridesT<D>, Windows::UI::Xaml::IFrameworkElementOverrides2T<D>, Windows::UI::Xaml::IUIElementOverridesT<D>, Windows::UI::Xaml::IUIElementOverrides7T<D>, Windows::UI::Xaml::IUIElementOverrides8T<D>, Windows::UI::Xaml::IUIElementOverrides9T<D>
{
    using composable = ButtonBase;

protected:
    ButtonBaseT()
    {
        impl::call_factory<Windows::UI::Xaml::Controls::Primitives::ButtonBase, Windows::UI::Xaml::Controls::Primitives::IButtonBaseFactory>([&](auto&& f) { f.CreateInstance(*this, this->m_inner); });
    }
};

template <typename D, typename... Interfaces>
struct CarouselPanelT :
    implements<D, Windows::UI::Xaml::Controls::IVirtualizingPanelOverrides, Windows::UI::Xaml::IFrameworkElementOverrides, Windows::UI::Xaml::IFrameworkElementOverrides2, Windows::UI::Xaml::IUIElementOverrides, Windows::UI::Xaml::IUIElementOverrides7, Windows::UI::Xaml::IUIElementOverrides8, Windows::UI::Xaml::IUIElementOverrides9, composing, Interfaces...>,
    impl::require<D, Windows::UI::Xaml::Controls::Primitives::ICarouselPanel, Windows::UI::Composition::IAnimationObject, Windows::UI::Composition::IVisualElement, Windows::UI::Xaml::Controls::IPanel, Windows::UI::Xaml::Controls::IPanel2, Windows::UI::Xaml::Controls::IVirtualizingPanel, Windows::UI::Xaml::Controls::IVirtualizingPanelProtected, Windows::UI::Xaml::Controls::Primitives::IScrollSnapPointsInfo, Windows::UI::Xaml::IDependencyObject, Windows::UI::Xaml::IDependencyObject2, Windows::UI::Xaml::IFrameworkElement, Windows::UI::Xaml::IFrameworkElement2, Windows::UI::Xaml::IFrameworkElement3, Windows::UI::Xaml::IFrameworkElement4, Windows::UI::Xaml::IFrameworkElement6, Windows::UI::Xaml::IFrameworkElement7, Windows::UI::Xaml::IFrameworkElementProtected7, Windows::UI::Xaml::IUIElement, Windows::UI::Xaml::IUIElement10, Windows::UI::Xaml::IUIElement2, Windows::UI::Xaml::IUIElement3, Windows::UI::Xaml::IUIElement4, Windows::UI::Xaml::IUIElement5, Windows::UI::Xaml::IUIElement7, Windows::UI::Xaml::IUIElement8, Windows::UI::Xaml::IUIElement9>,
    impl::base<D, Windows::UI::Xaml::Controls::Primitives::CarouselPanel, Windows::UI::Xaml::Controls::VirtualizingPanel, Windows::UI::Xaml::Controls::Panel, Windows::UI::Xaml::FrameworkElement, Windows::UI::Xaml::UIElement, Windows::UI::Xaml::DependencyObject>,
    Windows::UI::Xaml::Controls::IVirtualizingPanelOverridesT<D>, Windows::UI::Xaml::IFrameworkElementOverridesT<D>, Windows::UI::Xaml::IFrameworkElementOverrides2T<D>, Windows::UI::Xaml::IUIElementOverridesT<D>, Windows::UI::Xaml::IUIElementOverrides7T<D>, Windows::UI::Xaml::IUIElementOverrides8T<D>, Windows::UI::Xaml::IUIElementOverrides9T<D>
{
    using composable = CarouselPanel;

protected:
    CarouselPanelT()
    {
        impl::call_factory<Windows::UI::Xaml::Controls::Primitives::CarouselPanel, Windows::UI::Xaml::Controls::Primitives::ICarouselPanelFactory>([&](auto&& f) { f.CreateInstance(*this, this->m_inner); });
    }
};

template <typename D, typename... Interfaces>
struct ColorPickerSliderT :
    implements<D, Windows::UI::Xaml::Controls::IControlOverrides, Windows::UI::Xaml::Controls::IControlOverrides6, Windows::UI::Xaml::Controls::Primitives::IRangeBaseOverrides, Windows::UI::Xaml::IFrameworkElementOverrides, Windows::UI::Xaml::IFrameworkElementOverrides2, Windows::UI::Xaml::IUIElementOverrides, Windows::UI::Xaml::IUIElementOverrides7, Windows::UI::Xaml::IUIElementOverrides8, Windows::UI::Xaml::IUIElementOverrides9, composing, Interfaces...>,
    impl::require<D, Windows::UI::Xaml::Controls::Primitives::IColorPickerSlider, Windows::UI::Composition::IAnimationObject, Windows::UI::Composition::IVisualElement, Windows::UI::Xaml::Controls::IControl, Windows::UI::Xaml::Controls::IControl2, Windows::UI::Xaml::Controls::IControl3, Windows::UI::Xaml::Controls::IControl4, Windows::UI::Xaml::Controls::IControl5, Windows::UI::Xaml::Controls::IControl7, Windows::UI::Xaml::Controls::IControlProtected, Windows::UI::Xaml::Controls::ISlider, Windows::UI::Xaml::Controls::ISlider2, Windows::UI::Xaml::Controls::Primitives::IRangeBase, Windows::UI::Xaml::IDependencyObject, Windows::UI::Xaml::IDependencyObject2, Windows::UI::Xaml::IFrameworkElement, Windows::UI::Xaml::IFrameworkElement2, Windows::UI::Xaml::IFrameworkElement3, Windows::UI::Xaml::IFrameworkElement4, Windows::UI::Xaml::IFrameworkElement6, Windows::UI::Xaml::IFrameworkElement7, Windows::UI::Xaml::IFrameworkElementProtected7, Windows::UI::Xaml::IUIElement, Windows::UI::Xaml::IUIElement10, Windows::UI::Xaml::IUIElement2, Windows::UI::Xaml::IUIElement3, Windows::UI::Xaml::IUIElement4, Windows::UI::Xaml::IUIElement5, Windows::UI::Xaml::IUIElement7, Windows::UI::Xaml::IUIElement8, Windows::UI::Xaml::IUIElement9>,
    impl::base<D, Windows::UI::Xaml::Controls::Primitives::ColorPickerSlider, Windows::UI::Xaml::Controls::Slider, Windows::UI::Xaml::Controls::Primitives::RangeBase, Windows::UI::Xaml::Controls::Control, Windows::UI::Xaml::FrameworkElement, Windows::UI::Xaml::UIElement, Windows::UI::Xaml::DependencyObject>,
    Windows::UI::Xaml::Controls::IControlOverridesT<D>, Windows::UI::Xaml::Controls::IControlOverrides6T<D>, Windows::UI::Xaml::Controls::Primitives::IRangeBaseOverridesT<D>, Windows::UI::Xaml::IFrameworkElementOverridesT<D>, Windows::UI::Xaml::IFrameworkElementOverrides2T<D>, Windows::UI::Xaml::IUIElementOverridesT<D>, Windows::UI::Xaml::IUIElementOverrides7T<D>, Windows::UI::Xaml::IUIElementOverrides8T<D>, Windows::UI::Xaml::IUIElementOverrides9T<D>
{
    using composable = ColorPickerSlider;

protected:
    ColorPickerSliderT()
    {
        impl::call_factory<Windows::UI::Xaml::Controls::Primitives::ColorPickerSlider, Windows::UI::Xaml::Controls::Primitives::IColorPickerSliderFactory>([&](auto&& f) { f.CreateInstance(*this, this->m_inner); });
    }
};

template <typename D, typename... Interfaces>
struct ColorSpectrumT :
    implements<D, Windows::UI::Xaml::Controls::IControlOverrides, Windows::UI::Xaml::Controls::IControlOverrides6, Windows::UI::Xaml::IFrameworkElementOverrides, Windows::UI::Xaml::IFrameworkElementOverrides2, Windows::UI::Xaml::IUIElementOverrides, Windows::UI::Xaml::IUIElementOverrides7, Windows::UI::Xaml::IUIElementOverrides8, Windows::UI::Xaml::IUIElementOverrides9, composing, Interfaces...>,
    impl::require<D, Windows::UI::Xaml::Controls::Primitives::IColorSpectrum, Windows::UI::Composition::IAnimationObject, Windows::UI::Composition::IVisualElement, Windows::UI::Xaml::Controls::IControl, Windows::UI::Xaml::Controls::IControl2, Windows::UI::Xaml::Controls::IControl3, Windows::UI::Xaml::Controls::IControl4, Windows::UI::Xaml::Controls::IControl5, Windows::UI::Xaml::Controls::IControl7, Windows::UI::Xaml::Controls::IControlProtected, Windows::UI::Xaml::IDependencyObject, Windows::UI::Xaml::IDependencyObject2, Windows::UI::Xaml::IFrameworkElement, Windows::UI::Xaml::IFrameworkElement2, Windows::UI::Xaml::IFrameworkElement3, Windows::UI::Xaml::IFrameworkElement4, Windows::UI::Xaml::IFrameworkElement6, Windows::UI::Xaml::IFrameworkElement7, Windows::UI::Xaml::IFrameworkElementProtected7, Windows::UI::Xaml::IUIElement, Windows::UI::Xaml::IUIElement10, Windows::UI::Xaml::IUIElement2, Windows::UI::Xaml::IUIElement3, Windows::UI::Xaml::IUIElement4, Windows::UI::Xaml::IUIElement5, Windows::UI::Xaml::IUIElement7, Windows::UI::Xaml::IUIElement8, Windows::UI::Xaml::IUIElement9>,
    impl::base<D, Windows::UI::Xaml::Controls::Primitives::ColorSpectrum, Windows::UI::Xaml::Controls::Control, Windows::UI::Xaml::FrameworkElement, Windows::UI::Xaml::UIElement, Windows::UI::Xaml::DependencyObject>,
    Windows::UI::Xaml::Controls::IControlOverridesT<D>, Windows::UI::Xaml::Controls::IControlOverrides6T<D>, Windows::UI::Xaml::IFrameworkElementOverridesT<D>, Windows::UI::Xaml::IFrameworkElementOverrides2T<D>, Windows::UI::Xaml::IUIElementOverridesT<D>, Windows::UI::Xaml::IUIElementOverrides7T<D>, Windows::UI::Xaml::IUIElementOverrides8T<D>, Windows::UI::Xaml::IUIElementOverrides9T<D>
{
    using composable = ColorSpectrum;

protected:
    ColorSpectrumT()
    {
        impl::call_factory<Windows::UI::Xaml::Controls::Primitives::ColorSpectrum, Windows::UI::Xaml::Controls::Primitives::IColorSpectrumFactory>([&](auto&& f) { f.CreateInstance(*this, this->m_inner); });
    }
};

template <typename D, typename... Interfaces>
struct CommandBarFlyoutCommandBarT :
    implements<D, Windows::UI::Xaml::Controls::IAppBarOverrides, Windows::UI::Xaml::Controls::IAppBarOverrides3, Windows::UI::Xaml::Controls::IContentControlOverrides, Windows::UI::Xaml::Controls::IControlOverrides, Windows::UI::Xaml::Controls::IControlOverrides6, Windows::UI::Xaml::IFrameworkElementOverrides, Windows::UI::Xaml::IFrameworkElementOverrides2, Windows::UI::Xaml::IUIElementOverrides, Windows::UI::Xaml::IUIElementOverrides7, Windows::UI::Xaml::IUIElementOverrides8, Windows::UI::Xaml::IUIElementOverrides9, composing, Interfaces...>,
    impl::require<D, Windows::UI::Xaml::Controls::Primitives::ICommandBarFlyoutCommandBar, Windows::UI::Composition::IAnimationObject, Windows::UI::Composition::IVisualElement, Windows::UI::Xaml::Controls::IAppBar, Windows::UI::Xaml::Controls::IAppBar2, Windows::UI::Xaml::Controls::IAppBar3, Windows::UI::Xaml::Controls::IAppBar4, Windows::UI::Xaml::Controls::ICommandBar, Windows::UI::Xaml::Controls::ICommandBar2, Windows::UI::Xaml::Controls::ICommandBar3, Windows::UI::Xaml::Controls::IContentControl, Windows::UI::Xaml::Controls::IContentControl2, Windows::UI::Xaml::Controls::IControl, Windows::UI::Xaml::Controls::IControl2, Windows::UI::Xaml::Controls::IControl3, Windows::UI::Xaml::Controls::IControl4, Windows::UI::Xaml::Controls::IControl5, Windows::UI::Xaml::Controls::IControl7, Windows::UI::Xaml::Controls::IControlProtected, Windows::UI::Xaml::IDependencyObject, Windows::UI::Xaml::IDependencyObject2, Windows::UI::Xaml::IFrameworkElement, Windows::UI::Xaml::IFrameworkElement2, Windows::UI::Xaml::IFrameworkElement3, Windows::UI::Xaml::IFrameworkElement4, Windows::UI::Xaml::IFrameworkElement6, Windows::UI::Xaml::IFrameworkElement7, Windows::UI::Xaml::IFrameworkElementProtected7, Windows::UI::Xaml::IUIElement, Windows::UI::Xaml::IUIElement10, Windows::UI::Xaml::IUIElement2, Windows::UI::Xaml::IUIElement3, Windows::UI::Xaml::IUIElement4, Windows::UI::Xaml::IUIElement5, Windows::UI::Xaml::IUIElement7, Windows::UI::Xaml::IUIElement8, Windows::UI::Xaml::IUIElement9>,
    impl::base<D, Windows::UI::Xaml::Controls::Primitives::CommandBarFlyoutCommandBar, Windows::UI::Xaml::Controls::CommandBar, Windows::UI::Xaml::Controls::AppBar, Windows::UI::Xaml::Controls::ContentControl, Windows::UI::Xaml::Controls::Control, Windows::UI::Xaml::FrameworkElement, Windows::UI::Xaml::UIElement, Windows::UI::Xaml::DependencyObject>,
    Windows::UI::Xaml::Controls::IAppBarOverridesT<D>, Windows::UI::Xaml::Controls::IAppBarOverrides3T<D>, Windows::UI::Xaml::Controls::IContentControlOverridesT<D>, Windows::UI::Xaml::Controls::IControlOverridesT<D>, Windows::UI::Xaml::Controls::IControlOverrides6T<D>, Windows::UI::Xaml::IFrameworkElementOverridesT<D>, Windows::UI::Xaml::IFrameworkElementOverrides2T<D>, Windows::UI::Xaml::IUIElementOverridesT<D>, Windows::UI::Xaml::IUIElementOverrides7T<D>, Windows::UI::Xaml::IUIElementOverrides8T<D>, Windows::UI::Xaml::IUIElementOverrides9T<D>
{
    using composable = CommandBarFlyoutCommandBar;

protected:
    CommandBarFlyoutCommandBarT()
    {
        impl::call_factory<Windows::UI::Xaml::Controls::Primitives::CommandBarFlyoutCommandBar, Windows::UI::Xaml::Controls::Primitives::ICommandBarFlyoutCommandBarFactory>([&](auto&& f) { f.CreateInstance(*this, this->m_inner); });
    }
};

template <typename D, typename... Interfaces>
struct DragCompletedEventArgsT :
    implements<D, Windows::Foundation::IInspectable, composing, Interfaces...>,
    impl::require<D, Windows::UI::Xaml::Controls::Primitives::IDragCompletedEventArgs, Windows::UI::Xaml::IRoutedEventArgs>,
    impl::base<D, Windows::UI::Xaml::Controls::Primitives::DragCompletedEventArgs, Windows::UI::Xaml::RoutedEventArgs>
{
    using composable = DragCompletedEventArgs;

protected:
    DragCompletedEventArgsT(double horizontalChange, double verticalChange, bool canceled)
    {
        impl::call_factory<Windows::UI::Xaml::Controls::Primitives::DragCompletedEventArgs, Windows::UI::Xaml::Controls::Primitives::IDragCompletedEventArgsFactory>([&](auto&& f) { f.CreateInstanceWithHorizontalChangeVerticalChangeAndCanceled(horizontalChange, verticalChange, canceled, *this, this->m_inner); });
    }
};

template <typename D, typename... Interfaces>
struct DragDeltaEventArgsT :
    implements<D, Windows::Foundation::IInspectable, composing, Interfaces...>,
    impl::require<D, Windows::UI::Xaml::Controls::Primitives::IDragDeltaEventArgs, Windows::UI::Xaml::IRoutedEventArgs>,
    impl::base<D, Windows::UI::Xaml::Controls::Primitives::DragDeltaEventArgs, Windows::UI::Xaml::RoutedEventArgs>
{
    using composable = DragDeltaEventArgs;

protected:
    DragDeltaEventArgsT(double horizontalChange, double verticalChange)
    {
        impl::call_factory<Windows::UI::Xaml::Controls::Primitives::DragDeltaEventArgs, Windows::UI::Xaml::Controls::Primitives::IDragDeltaEventArgsFactory>([&](auto&& f) { f.CreateInstanceWithHorizontalChangeAndVerticalChange(horizontalChange, verticalChange, *this, this->m_inner); });
    }
};

template <typename D, typename... Interfaces>
struct DragStartedEventArgsT :
    implements<D, Windows::Foundation::IInspectable, composing, Interfaces...>,
    impl::require<D, Windows::UI::Xaml::Controls::Primitives::IDragStartedEventArgs, Windows::UI::Xaml::IRoutedEventArgs>,
    impl::base<D, Windows::UI::Xaml::Controls::Primitives::DragStartedEventArgs, Windows::UI::Xaml::RoutedEventArgs>
{
    using composable = DragStartedEventArgs;

protected:
    DragStartedEventArgsT(double horizontalOffset, double verticalOffset)
    {
        impl::call_factory<Windows::UI::Xaml::Controls::Primitives::DragStartedEventArgs, Windows::UI::Xaml::Controls::Primitives::IDragStartedEventArgsFactory>([&](auto&& f) { f.CreateInstanceWithHorizontalOffsetAndVerticalOffset(horizontalOffset, verticalOffset, *this, this->m_inner); });
    }
};

template <typename D, typename... Interfaces>
struct FlyoutBaseT :
    implements<D, Windows::UI::Xaml::Controls::Primitives::IFlyoutBaseOverrides, Windows::UI::Xaml::Controls::Primitives::IFlyoutBaseOverrides4, composing, Interfaces...>,
    impl::require<D, Windows::UI::Xaml::Controls::Primitives::IFlyoutBase, Windows::UI::Xaml::Controls::Primitives::IFlyoutBase2, Windows::UI::Xaml::Controls::Primitives::IFlyoutBase3, Windows::UI::Xaml::Controls::Primitives::IFlyoutBase4, Windows::UI::Xaml::Controls::Primitives::IFlyoutBase5, Windows::UI::Xaml::Controls::Primitives::IFlyoutBase6, Windows::UI::Xaml::IDependencyObject, Windows::UI::Xaml::IDependencyObject2>,
    impl::base<D, Windows::UI::Xaml::Controls::Primitives::FlyoutBase, Windows::UI::Xaml::DependencyObject>,
    Windows::UI::Xaml::Controls::Primitives::IFlyoutBaseOverridesT<D>, Windows::UI::Xaml::Controls::Primitives::IFlyoutBaseOverrides4T<D>
{
    using composable = FlyoutBase;

protected:
    FlyoutBaseT()
    {
        impl::call_factory<Windows::UI::Xaml::Controls::Primitives::FlyoutBase, Windows::UI::Xaml::Controls::Primitives::IFlyoutBaseFactory>([&](auto&& f) { f.CreateInstance(*this, this->m_inner); });
    }
};

template <typename D, typename... Interfaces>
struct FlyoutShowOptionsT :
    implements<D, Windows::Foundation::IInspectable, composing, Interfaces...>,
    impl::require<D, Windows::UI::Xaml::Controls::Primitives::IFlyoutShowOptions>,
    impl::base<D, Windows::UI::Xaml::Controls::Primitives::FlyoutShowOptions>
{
    using composable = FlyoutShowOptions;

protected:
    FlyoutShowOptionsT()
    {
        impl::call_factory<Windows::UI::Xaml::Controls::Primitives::FlyoutShowOptions, Windows::UI::Xaml::Controls::Primitives::IFlyoutShowOptionsFactory>([&](auto&& f) { f.CreateInstance(*this, this->m_inner); });
    }
};

template <typename D, typename... Interfaces>
struct GridViewItemPresenterT :
    implements<D, Windows::UI::Xaml::Controls::IContentPresenterOverrides, Windows::UI::Xaml::IFrameworkElementOverrides, Windows::UI::Xaml::IFrameworkElementOverrides2, Windows::UI::Xaml::IUIElementOverrides, Windows::UI::Xaml::IUIElementOverrides7, Windows::UI::Xaml::IUIElementOverrides8, Windows::UI::Xaml::IUIElementOverrides9, composing, Interfaces...>,
    impl::require<D, Windows::UI::Xaml::Controls::Primitives::IGridViewItemPresenter, Windows::UI::Composition::IAnimationObject, Windows::UI::Composition::IVisualElement, Windows::UI::Xaml::Controls::IContentPresenter, Windows::UI::Xaml::Controls::IContentPresenter2, Windows::UI::Xaml::Controls::IContentPresenter3, Windows::UI::Xaml::Controls::IContentPresenter4, Windows::UI::Xaml::Controls::IContentPresenter5, Windows::UI::Xaml::IDependencyObject, Windows::UI::Xaml::IDependencyObject2, Windows::UI::Xaml::IFrameworkElement, Windows::UI::Xaml::IFrameworkElement2, Windows::UI::Xaml::IFrameworkElement3, Windows::UI::Xaml::IFrameworkElement4, Windows::UI::Xaml::IFrameworkElement6, Windows::UI::Xaml::IFrameworkElement7, Windows::UI::Xaml::IFrameworkElementProtected7, Windows::UI::Xaml::IUIElement, Windows::UI::Xaml::IUIElement10, Windows::UI::Xaml::IUIElement2, Windows::UI::Xaml::IUIElement3, Windows::UI::Xaml::IUIElement4, Windows::UI::Xaml::IUIElement5, Windows::UI::Xaml::IUIElement7, Windows::UI::Xaml::IUIElement8, Windows::UI::Xaml::IUIElement9>,
    impl::base<D, Windows::UI::Xaml::Controls::Primitives::GridViewItemPresenter, Windows::UI::Xaml::Controls::ContentPresenter, Windows::UI::Xaml::FrameworkElement, Windows::UI::Xaml::UIElement, Windows::UI::Xaml::DependencyObject>,
    Windows::UI::Xaml::Controls::IContentPresenterOverridesT<D>, Windows::UI::Xaml::IFrameworkElementOverridesT<D>, Windows::UI::Xaml::IFrameworkElementOverrides2T<D>, Windows::UI::Xaml::IUIElementOverridesT<D>, Windows::UI::Xaml::IUIElementOverrides7T<D>, Windows::UI::Xaml::IUIElementOverrides8T<D>, Windows::UI::Xaml::IUIElementOverrides9T<D>
{
    using composable = GridViewItemPresenter;

protected:
    GridViewItemPresenterT()
    {
        impl::call_factory<Windows::UI::Xaml::Controls::Primitives::GridViewItemPresenter, Windows::UI::Xaml::Controls::Primitives::IGridViewItemPresenterFactory>([&](auto&& f) { f.CreateInstance(*this, this->m_inner); });
    }
};

template <typename D, typename... Interfaces>
struct ListViewItemPresenterT :
    implements<D, Windows::UI::Xaml::Controls::IContentPresenterOverrides, Windows::UI::Xaml::IFrameworkElementOverrides, Windows::UI::Xaml::IFrameworkElementOverrides2, Windows::UI::Xaml::IUIElementOverrides, Windows::UI::Xaml::IUIElementOverrides7, Windows::UI::Xaml::IUIElementOverrides8, Windows::UI::Xaml::IUIElementOverrides9, composing, Interfaces...>,
    impl::require<D, Windows::UI::Xaml::Controls::Primitives::IListViewItemPresenter, Windows::UI::Composition::IAnimationObject, Windows::UI::Composition::IVisualElement, Windows::UI::Xaml::Controls::IContentPresenter, Windows::UI::Xaml::Controls::IContentPresenter2, Windows::UI::Xaml::Controls::IContentPresenter3, Windows::UI::Xaml::Controls::IContentPresenter4, Windows::UI::Xaml::Controls::IContentPresenter5, Windows::UI::Xaml::Controls::Primitives::IListViewItemPresenter2, Windows::UI::Xaml::Controls::Primitives::IListViewItemPresenter3, Windows::UI::Xaml::IDependencyObject, Windows::UI::Xaml::IDependencyObject2, Windows::UI::Xaml::IFrameworkElement, Windows::UI::Xaml::IFrameworkElement2, Windows::UI::Xaml::IFrameworkElement3, Windows::UI::Xaml::IFrameworkElement4, Windows::UI::Xaml::IFrameworkElement6, Windows::UI::Xaml::IFrameworkElement7, Windows::UI::Xaml::IFrameworkElementProtected7, Windows::UI::Xaml::IUIElement, Windows::UI::Xaml::IUIElement10, Windows::UI::Xaml::IUIElement2, Windows::UI::Xaml::IUIElement3, Windows::UI::Xaml::IUIElement4, Windows::UI::Xaml::IUIElement5, Windows::UI::Xaml::IUIElement7, Windows::UI::Xaml::IUIElement8, Windows::UI::Xaml::IUIElement9>,
    impl::base<D, Windows::UI::Xaml::Controls::Primitives::ListViewItemPresenter, Windows::UI::Xaml::Controls::ContentPresenter, Windows::UI::Xaml::FrameworkElement, Windows::UI::Xaml::UIElement, Windows::UI::Xaml::DependencyObject>,
    Windows::UI::Xaml::Controls::IContentPresenterOverridesT<D>, Windows::UI::Xaml::IFrameworkElementOverridesT<D>, Windows::UI::Xaml::IFrameworkElementOverrides2T<D>, Windows::UI::Xaml::IUIElementOverridesT<D>, Windows::UI::Xaml::IUIElementOverrides7T<D>, Windows::UI::Xaml::IUIElementOverrides8T<D>, Windows::UI::Xaml::IUIElementOverrides9T<D>
{
    using composable = ListViewItemPresenter;

protected:
    ListViewItemPresenterT()
    {
        impl::call_factory<Windows::UI::Xaml::Controls::Primitives::ListViewItemPresenter, Windows::UI::Xaml::Controls::Primitives::IListViewItemPresenterFactory>([&](auto&& f) { f.CreateInstance(*this, this->m_inner); });
    }
};

template <typename D, typename... Interfaces>
struct NavigationViewItemPresenterT :
    implements<D, Windows::UI::Xaml::Controls::IContentControlOverrides, Windows::UI::Xaml::Controls::IControlOverrides, Windows::UI::Xaml::Controls::IControlOverrides6, Windows::UI::Xaml::IFrameworkElementOverrides, Windows::UI::Xaml::IFrameworkElementOverrides2, Windows::UI::Xaml::IUIElementOverrides, Windows::UI::Xaml::IUIElementOverrides7, Windows::UI::Xaml::IUIElementOverrides8, Windows::UI::Xaml::IUIElementOverrides9, composing, Interfaces...>,
    impl::require<D, Windows::UI::Xaml::Controls::Primitives::INavigationViewItemPresenter, Windows::UI::Composition::IAnimationObject, Windows::UI::Composition::IVisualElement, Windows::UI::Xaml::Controls::IContentControl, Windows::UI::Xaml::Controls::IContentControl2, Windows::UI::Xaml::Controls::IControl, Windows::UI::Xaml::Controls::IControl2, Windows::UI::Xaml::Controls::IControl3, Windows::UI::Xaml::Controls::IControl4, Windows::UI::Xaml::Controls::IControl5, Windows::UI::Xaml::Controls::IControl7, Windows::UI::Xaml::Controls::IControlProtected, Windows::UI::Xaml::IDependencyObject, Windows::UI::Xaml::IDependencyObject2, Windows::UI::Xaml::IFrameworkElement, Windows::UI::Xaml::IFrameworkElement2, Windows::UI::Xaml::IFrameworkElement3, Windows::UI::Xaml::IFrameworkElement4, Windows::UI::Xaml::IFrameworkElement6, Windows::UI::Xaml::IFrameworkElement7, Windows::UI::Xaml::IFrameworkElementProtected7, Windows::UI::Xaml::IUIElement, Windows::UI::Xaml::IUIElement10, Windows::UI::Xaml::IUIElement2, Windows::UI::Xaml::IUIElement3, Windows::UI::Xaml::IUIElement4, Windows::UI::Xaml::IUIElement5, Windows::UI::Xaml::IUIElement7, Windows::UI::Xaml::IUIElement8, Windows::UI::Xaml::IUIElement9>,
    impl::base<D, Windows::UI::Xaml::Controls::Primitives::NavigationViewItemPresenter, Windows::UI::Xaml::Controls::ContentControl, Windows::UI::Xaml::Controls::Control, Windows::UI::Xaml::FrameworkElement, Windows::UI::Xaml::UIElement, Windows::UI::Xaml::DependencyObject>,
    Windows::UI::Xaml::Controls::IContentControlOverridesT<D>, Windows::UI::Xaml::Controls::IControlOverridesT<D>, Windows::UI::Xaml::Controls::IControlOverrides6T<D>, Windows::UI::Xaml::IFrameworkElementOverridesT<D>, Windows::UI::Xaml::IFrameworkElementOverrides2T<D>, Windows::UI::Xaml::IUIElementOverridesT<D>, Windows::UI::Xaml::IUIElementOverrides7T<D>, Windows::UI::Xaml::IUIElementOverrides8T<D>, Windows::UI::Xaml::IUIElementOverrides9T<D>
{
    using composable = NavigationViewItemPresenter;

protected:
    NavigationViewItemPresenterT()
    {
        impl::call_factory<Windows::UI::Xaml::Controls::Primitives::NavigationViewItemPresenter, Windows::UI::Xaml::Controls::Primitives::INavigationViewItemPresenterFactory>([&](auto&& f) { f.CreateInstance(*this, this->m_inner); });
    }
};

template <typename D, typename... Interfaces>
struct PickerFlyoutBaseT :
    implements<D, Windows::UI::Xaml::Controls::Primitives::IFlyoutBaseOverrides, Windows::UI::Xaml::Controls::Primitives::IFlyoutBaseOverrides4, Windows::UI::Xaml::Controls::Primitives::IPickerFlyoutBaseOverrides, composing, Interfaces...>,
    impl::require<D, Windows::UI::Xaml::Controls::Primitives::IPickerFlyoutBase, Windows::UI::Xaml::Controls::Primitives::IFlyoutBase, Windows::UI::Xaml::Controls::Primitives::IFlyoutBase2, Windows::UI::Xaml::Controls::Primitives::IFlyoutBase3, Windows::UI::Xaml::Controls::Primitives::IFlyoutBase4, Windows::UI::Xaml::Controls::Primitives::IFlyoutBase5, Windows::UI::Xaml::Controls::Primitives::IFlyoutBase6, Windows::UI::Xaml::IDependencyObject, Windows::UI::Xaml::IDependencyObject2>,
    impl::base<D, Windows::UI::Xaml::Controls::Primitives::PickerFlyoutBase, Windows::UI::Xaml::Controls::Primitives::FlyoutBase, Windows::UI::Xaml::DependencyObject>,
    Windows::UI::Xaml::Controls::Primitives::IFlyoutBaseOverridesT<D>, Windows::UI::Xaml::Controls::Primitives::IFlyoutBaseOverrides4T<D>, Windows::UI::Xaml::Controls::Primitives::IPickerFlyoutBaseOverridesT<D>
{
    using composable = PickerFlyoutBase;

protected:
    PickerFlyoutBaseT()
    {
        impl::call_factory<Windows::UI::Xaml::Controls::Primitives::PickerFlyoutBase, Windows::UI::Xaml::Controls::Primitives::IPickerFlyoutBaseFactory>([&](auto&& f) { f.CreateInstance(*this, this->m_inner); });
    }
};

template <typename D, typename... Interfaces>
struct PivotHeaderItemT :
    implements<D, Windows::UI::Xaml::Controls::IContentControlOverrides, Windows::UI::Xaml::Controls::IControlOverrides, Windows::UI::Xaml::Controls::IControlOverrides6, Windows::UI::Xaml::IFrameworkElementOverrides, Windows::UI::Xaml::IFrameworkElementOverrides2, Windows::UI::Xaml::IUIElementOverrides, Windows::UI::Xaml::IUIElementOverrides7, Windows::UI::Xaml::IUIElementOverrides8, Windows::UI::Xaml::IUIElementOverrides9, composing, Interfaces...>,
    impl::require<D, Windows::UI::Xaml::Controls::Primitives::IPivotHeaderItem, Windows::UI::Composition::IAnimationObject, Windows::UI::Composition::IVisualElement, Windows::UI::Xaml::Controls::IContentControl, Windows::UI::Xaml::Controls::IContentControl2, Windows::UI::Xaml::Controls::IControl, Windows::UI::Xaml::Controls::IControl2, Windows::UI::Xaml::Controls::IControl3, Windows::UI::Xaml::Controls::IControl4, Windows::UI::Xaml::Controls::IControl5, Windows::UI::Xaml::Controls::IControl7, Windows::UI::Xaml::Controls::IControlProtected, Windows::UI::Xaml::IDependencyObject, Windows::UI::Xaml::IDependencyObject2, Windows::UI::Xaml::IFrameworkElement, Windows::UI::Xaml::IFrameworkElement2, Windows::UI::Xaml::IFrameworkElement3, Windows::UI::Xaml::IFrameworkElement4, Windows::UI::Xaml::IFrameworkElement6, Windows::UI::Xaml::IFrameworkElement7, Windows::UI::Xaml::IFrameworkElementProtected7, Windows::UI::Xaml::IUIElement, Windows::UI::Xaml::IUIElement10, Windows::UI::Xaml::IUIElement2, Windows::UI::Xaml::IUIElement3, Windows::UI::Xaml::IUIElement4, Windows::UI::Xaml::IUIElement5, Windows::UI::Xaml::IUIElement7, Windows::UI::Xaml::IUIElement8, Windows::UI::Xaml::IUIElement9>,
    impl::base<D, Windows::UI::Xaml::Controls::Primitives::PivotHeaderItem, Windows::UI::Xaml::Controls::ContentControl, Windows::UI::Xaml::Controls::Control, Windows::UI::Xaml::FrameworkElement, Windows::UI::Xaml::UIElement, Windows::UI::Xaml::DependencyObject>,
    Windows::UI::Xaml::Controls::IContentControlOverridesT<D>, Windows::UI::Xaml::Controls::IControlOverridesT<D>, Windows::UI::Xaml::Controls::IControlOverrides6T<D>, Windows::UI::Xaml::IFrameworkElementOverridesT<D>, Windows::UI::Xaml::IFrameworkElementOverrides2T<D>, Windows::UI::Xaml::IUIElementOverridesT<D>, Windows::UI::Xaml::IUIElementOverrides7T<D>, Windows::UI::Xaml::IUIElementOverrides8T<D>, Windows::UI::Xaml::IUIElementOverrides9T<D>
{
    using composable = PivotHeaderItem;

protected:
    PivotHeaderItemT()
    {
        impl::call_factory<Windows::UI::Xaml::Controls::Primitives::PivotHeaderItem, Windows::UI::Xaml::Controls::Primitives::IPivotHeaderItemFactory>([&](auto&& f) { f.CreateInstance(*this, this->m_inner); });
    }
};

template <typename D, typename... Interfaces>
struct RangeBaseT :
    implements<D, Windows::UI::Xaml::Controls::IControlOverrides, Windows::UI::Xaml::Controls::IControlOverrides6, Windows::UI::Xaml::Controls::Primitives::IRangeBaseOverrides, Windows::UI::Xaml::IFrameworkElementOverrides, Windows::UI::Xaml::IFrameworkElementOverrides2, Windows::UI::Xaml::IUIElementOverrides, Windows::UI::Xaml::IUIElementOverrides7, Windows::UI::Xaml::IUIElementOverrides8, Windows::UI::Xaml::IUIElementOverrides9, composing, Interfaces...>,
    impl::require<D, Windows::UI::Xaml::Controls::Primitives::IRangeBase, Windows::UI::Composition::IAnimationObject, Windows::UI::Composition::IVisualElement, Windows::UI::Xaml::Controls::IControl, Windows::UI::Xaml::Controls::IControl2, Windows::UI::Xaml::Controls::IControl3, Windows::UI::Xaml::Controls::IControl4, Windows::UI::Xaml::Controls::IControl5, Windows::UI::Xaml::Controls::IControl7, Windows::UI::Xaml::Controls::IControlProtected, Windows::UI::Xaml::IDependencyObject, Windows::UI::Xaml::IDependencyObject2, Windows::UI::Xaml::IFrameworkElement, Windows::UI::Xaml::IFrameworkElement2, Windows::UI::Xaml::IFrameworkElement3, Windows::UI::Xaml::IFrameworkElement4, Windows::UI::Xaml::IFrameworkElement6, Windows::UI::Xaml::IFrameworkElement7, Windows::UI::Xaml::IFrameworkElementProtected7, Windows::UI::Xaml::IUIElement, Windows::UI::Xaml::IUIElement10, Windows::UI::Xaml::IUIElement2, Windows::UI::Xaml::IUIElement3, Windows::UI::Xaml::IUIElement4, Windows::UI::Xaml::IUIElement5, Windows::UI::Xaml::IUIElement7, Windows::UI::Xaml::IUIElement8, Windows::UI::Xaml::IUIElement9>,
    impl::base<D, Windows::UI::Xaml::Controls::Primitives::RangeBase, Windows::UI::Xaml::Controls::Control, Windows::UI::Xaml::FrameworkElement, Windows::UI::Xaml::UIElement, Windows::UI::Xaml::DependencyObject>,
    Windows::UI::Xaml::Controls::IControlOverridesT<D>, Windows::UI::Xaml::Controls::IControlOverrides6T<D>, Windows::UI::Xaml::Controls::Primitives::IRangeBaseOverridesT<D>, Windows::UI::Xaml::IFrameworkElementOverridesT<D>, Windows::UI::Xaml::IFrameworkElementOverrides2T<D>, Windows::UI::Xaml::IUIElementOverridesT<D>, Windows::UI::Xaml::IUIElementOverrides7T<D>, Windows::UI::Xaml::IUIElementOverrides8T<D>, Windows::UI::Xaml::IUIElementOverrides9T<D>
{
    using composable = RangeBase;

protected:
    RangeBaseT()
    {
        impl::call_factory<Windows::UI::Xaml::Controls::Primitives::RangeBase, Windows::UI::Xaml::Controls::Primitives::IRangeBaseFactory>([&](auto&& f) { f.CreateInstance(*this, this->m_inner); });
    }
};

template <typename D, typename... Interfaces>
struct SelectorItemT :
    implements<D, Windows::UI::Xaml::Controls::IContentControlOverrides, Windows::UI::Xaml::Controls::IControlOverrides, Windows::UI::Xaml::Controls::IControlOverrides6, Windows::UI::Xaml::IFrameworkElementOverrides, Windows::UI::Xaml::IFrameworkElementOverrides2, Windows::UI::Xaml::IUIElementOverrides, Windows::UI::Xaml::IUIElementOverrides7, Windows::UI::Xaml::IUIElementOverrides8, Windows::UI::Xaml::IUIElementOverrides9, composing, Interfaces...>,
    impl::require<D, Windows::UI::Xaml::Controls::Primitives::ISelectorItem, Windows::UI::Composition::IAnimationObject, Windows::UI::Composition::IVisualElement, Windows::UI::Xaml::Controls::IContentControl, Windows::UI::Xaml::Controls::IContentControl2, Windows::UI::Xaml::Controls::IControl, Windows::UI::Xaml::Controls::IControl2, Windows::UI::Xaml::Controls::IControl3, Windows::UI::Xaml::Controls::IControl4, Windows::UI::Xaml::Controls::IControl5, Windows::UI::Xaml::Controls::IControl7, Windows::UI::Xaml::Controls::IControlProtected, Windows::UI::Xaml::IDependencyObject, Windows::UI::Xaml::IDependencyObject2, Windows::UI::Xaml::IFrameworkElement, Windows::UI::Xaml::IFrameworkElement2, Windows::UI::Xaml::IFrameworkElement3, Windows::UI::Xaml::IFrameworkElement4, Windows::UI::Xaml::IFrameworkElement6, Windows::UI::Xaml::IFrameworkElement7, Windows::UI::Xaml::IFrameworkElementProtected7, Windows::UI::Xaml::IUIElement, Windows::UI::Xaml::IUIElement10, Windows::UI::Xaml::IUIElement2, Windows::UI::Xaml::IUIElement3, Windows::UI::Xaml::IUIElement4, Windows::UI::Xaml::IUIElement5, Windows::UI::Xaml::IUIElement7, Windows::UI::Xaml::IUIElement8, Windows::UI::Xaml::IUIElement9>,
    impl::base<D, Windows::UI::Xaml::Controls::Primitives::SelectorItem, Windows::UI::Xaml::Controls::ContentControl, Windows::UI::Xaml::Controls::Control, Windows::UI::Xaml::FrameworkElement, Windows::UI::Xaml::UIElement, Windows::UI::Xaml::DependencyObject>,
    Windows::UI::Xaml::Controls::IContentControlOverridesT<D>, Windows::UI::Xaml::Controls::IControlOverridesT<D>, Windows::UI::Xaml::Controls::IControlOverrides6T<D>, Windows::UI::Xaml::IFrameworkElementOverridesT<D>, Windows::UI::Xaml::IFrameworkElementOverrides2T<D>, Windows::UI::Xaml::IUIElementOverridesT<D>, Windows::UI::Xaml::IUIElementOverrides7T<D>, Windows::UI::Xaml::IUIElementOverrides8T<D>, Windows::UI::Xaml::IUIElementOverrides9T<D>
{
    using composable = SelectorItem;

protected:
    SelectorItemT()
    {
        impl::call_factory<Windows::UI::Xaml::Controls::Primitives::SelectorItem, Windows::UI::Xaml::Controls::Primitives::ISelectorItemFactory>([&](auto&& f) { f.CreateInstance(*this, this->m_inner); });
    }
};

template <typename D, typename... Interfaces>
struct ToggleButtonT :
    implements<D, Windows::UI::Xaml::Controls::IContentControlOverrides, Windows::UI::Xaml::Controls::IControlOverrides, Windows::UI::Xaml::Controls::IControlOverrides6, Windows::UI::Xaml::Controls::Primitives::IToggleButtonOverrides, Windows::UI::Xaml::IFrameworkElementOverrides, Windows::UI::Xaml::IFrameworkElementOverrides2, Windows::UI::Xaml::IUIElementOverrides, Windows::UI::Xaml::IUIElementOverrides7, Windows::UI::Xaml::IUIElementOverrides8, Windows::UI::Xaml::IUIElementOverrides9, composing, Interfaces...>,
    impl::require<D, Windows::UI::Xaml::Controls::Primitives::IToggleButton, Windows::UI::Composition::IAnimationObject, Windows::UI::Composition::IVisualElement, Windows::UI::Xaml::Controls::IContentControl, Windows::UI::Xaml::Controls::IContentControl2, Windows::UI::Xaml::Controls::IControl, Windows::UI::Xaml::Controls::IControl2, Windows::UI::Xaml::Controls::IControl3, Windows::UI::Xaml::Controls::IControl4, Windows::UI::Xaml::Controls::IControl5, Windows::UI::Xaml::Controls::IControl7, Windows::UI::Xaml::Controls::IControlProtected, Windows::UI::Xaml::Controls::Primitives::IButtonBase, Windows::UI::Xaml::IDependencyObject, Windows::UI::Xaml::IDependencyObject2, Windows::UI::Xaml::IFrameworkElement, Windows::UI::Xaml::IFrameworkElement2, Windows::UI::Xaml::IFrameworkElement3, Windows::UI::Xaml::IFrameworkElement4, Windows::UI::Xaml::IFrameworkElement6, Windows::UI::Xaml::IFrameworkElement7, Windows::UI::Xaml::IFrameworkElementProtected7, Windows::UI::Xaml::IUIElement, Windows::UI::Xaml::IUIElement10, Windows::UI::Xaml::IUIElement2, Windows::UI::Xaml::IUIElement3, Windows::UI::Xaml::IUIElement4, Windows::UI::Xaml::IUIElement5, Windows::UI::Xaml::IUIElement7, Windows::UI::Xaml::IUIElement8, Windows::UI::Xaml::IUIElement9>,
    impl::base<D, Windows::UI::Xaml::Controls::Primitives::ToggleButton, Windows::UI::Xaml::Controls::Primitives::ButtonBase, Windows::UI::Xaml::Controls::ContentControl, Windows::UI::Xaml::Controls::Control, Windows::UI::Xaml::FrameworkElement, Windows::UI::Xaml::UIElement, Windows::UI::Xaml::DependencyObject>,
    Windows::UI::Xaml::Controls::IContentControlOverridesT<D>, Windows::UI::Xaml::Controls::IControlOverridesT<D>, Windows::UI::Xaml::Controls::IControlOverrides6T<D>, Windows::UI::Xaml::Controls::Primitives::IToggleButtonOverridesT<D>, Windows::UI::Xaml::IFrameworkElementOverridesT<D>, Windows::UI::Xaml::IFrameworkElementOverrides2T<D>, Windows::UI::Xaml::IUIElementOverridesT<D>, Windows::UI::Xaml::IUIElementOverrides7T<D>, Windows::UI::Xaml::IUIElementOverrides8T<D>, Windows::UI::Xaml::IUIElementOverrides9T<D>
{
    using composable = ToggleButton;

protected:
    ToggleButtonT()
    {
        impl::call_factory<Windows::UI::Xaml::Controls::Primitives::ToggleButton, Windows::UI::Xaml::Controls::Primitives::IToggleButtonFactory>([&](auto&& f) { f.CreateInstance(*this, this->m_inner); });
    }
};

}

WINRT_EXPORT namespace std {

template<> struct hash<winrt::Windows::UI::Xaml::Controls::Primitives::IAppBarButtonTemplateSettings> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Controls::Primitives::IAppBarButtonTemplateSettings> {};
template<> struct hash<winrt::Windows::UI::Xaml::Controls::Primitives::IAppBarTemplateSettings> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Controls::Primitives::IAppBarTemplateSettings> {};
template<> struct hash<winrt::Windows::UI::Xaml::Controls::Primitives::IAppBarTemplateSettings2> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Controls::Primitives::IAppBarTemplateSettings2> {};
template<> struct hash<winrt::Windows::UI::Xaml::Controls::Primitives::IAppBarToggleButtonTemplateSettings> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Controls::Primitives::IAppBarToggleButtonTemplateSettings> {};
template<> struct hash<winrt::Windows::UI::Xaml::Controls::Primitives::IButtonBase> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Controls::Primitives::IButtonBase> {};
template<> struct hash<winrt::Windows::UI::Xaml::Controls::Primitives::IButtonBaseFactory> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Controls::Primitives::IButtonBaseFactory> {};
template<> struct hash<winrt::Windows::UI::Xaml::Controls::Primitives::IButtonBaseStatics> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Controls::Primitives::IButtonBaseStatics> {};
template<> struct hash<winrt::Windows::UI::Xaml::Controls::Primitives::ICalendarPanel> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Controls::Primitives::ICalendarPanel> {};
template<> struct hash<winrt::Windows::UI::Xaml::Controls::Primitives::ICalendarViewTemplateSettings> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Controls::Primitives::ICalendarViewTemplateSettings> {};
template<> struct hash<winrt::Windows::UI::Xaml::Controls::Primitives::ICarouselPanel> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Controls::Primitives::ICarouselPanel> {};
template<> struct hash<winrt::Windows::UI::Xaml::Controls::Primitives::ICarouselPanelFactory> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Controls::Primitives::ICarouselPanelFactory> {};
template<> struct hash<winrt::Windows::UI::Xaml::Controls::Primitives::IColorPickerSlider> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Controls::Primitives::IColorPickerSlider> {};
template<> struct hash<winrt::Windows::UI::Xaml::Controls::Primitives::IColorPickerSliderFactory> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Controls::Primitives::IColorPickerSliderFactory> {};
template<> struct hash<winrt::Windows::UI::Xaml::Controls::Primitives::IColorPickerSliderStatics> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Controls::Primitives::IColorPickerSliderStatics> {};
template<> struct hash<winrt::Windows::UI::Xaml::Controls::Primitives::IColorSpectrum> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Controls::Primitives::IColorSpectrum> {};
template<> struct hash<winrt::Windows::UI::Xaml::Controls::Primitives::IColorSpectrumFactory> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Controls::Primitives::IColorSpectrumFactory> {};
template<> struct hash<winrt::Windows::UI::Xaml::Controls::Primitives::IColorSpectrumStatics> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Controls::Primitives::IColorSpectrumStatics> {};
template<> struct hash<winrt::Windows::UI::Xaml::Controls::Primitives::IComboBoxTemplateSettings> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Controls::Primitives::IComboBoxTemplateSettings> {};
template<> struct hash<winrt::Windows::UI::Xaml::Controls::Primitives::IComboBoxTemplateSettings2> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Controls::Primitives::IComboBoxTemplateSettings2> {};
template<> struct hash<winrt::Windows::UI::Xaml::Controls::Primitives::ICommandBarFlyoutCommandBar> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Controls::Primitives::ICommandBarFlyoutCommandBar> {};
template<> struct hash<winrt::Windows::UI::Xaml::Controls::Primitives::ICommandBarFlyoutCommandBarFactory> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Controls::Primitives::ICommandBarFlyoutCommandBarFactory> {};
template<> struct hash<winrt::Windows::UI::Xaml::Controls::Primitives::ICommandBarFlyoutCommandBarTemplateSettings> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Controls::Primitives::ICommandBarFlyoutCommandBarTemplateSettings> {};
template<> struct hash<winrt::Windows::UI::Xaml::Controls::Primitives::ICommandBarTemplateSettings> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Controls::Primitives::ICommandBarTemplateSettings> {};
template<> struct hash<winrt::Windows::UI::Xaml::Controls::Primitives::ICommandBarTemplateSettings2> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Controls::Primitives::ICommandBarTemplateSettings2> {};
template<> struct hash<winrt::Windows::UI::Xaml::Controls::Primitives::ICommandBarTemplateSettings3> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Controls::Primitives::ICommandBarTemplateSettings3> {};
template<> struct hash<winrt::Windows::UI::Xaml::Controls::Primitives::ICommandBarTemplateSettings4> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Controls::Primitives::ICommandBarTemplateSettings4> {};
template<> struct hash<winrt::Windows::UI::Xaml::Controls::Primitives::IDragCompletedEventArgs> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Controls::Primitives::IDragCompletedEventArgs> {};
template<> struct hash<winrt::Windows::UI::Xaml::Controls::Primitives::IDragCompletedEventArgsFactory> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Controls::Primitives::IDragCompletedEventArgsFactory> {};
template<> struct hash<winrt::Windows::UI::Xaml::Controls::Primitives::IDragDeltaEventArgs> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Controls::Primitives::IDragDeltaEventArgs> {};
template<> struct hash<winrt::Windows::UI::Xaml::Controls::Primitives::IDragDeltaEventArgsFactory> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Controls::Primitives::IDragDeltaEventArgsFactory> {};
template<> struct hash<winrt::Windows::UI::Xaml::Controls::Primitives::IDragStartedEventArgs> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Controls::Primitives::IDragStartedEventArgs> {};
template<> struct hash<winrt::Windows::UI::Xaml::Controls::Primitives::IDragStartedEventArgsFactory> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Controls::Primitives::IDragStartedEventArgsFactory> {};
template<> struct hash<winrt::Windows::UI::Xaml::Controls::Primitives::IFlyoutBase> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Controls::Primitives::IFlyoutBase> {};
template<> struct hash<winrt::Windows::UI::Xaml::Controls::Primitives::IFlyoutBase2> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Controls::Primitives::IFlyoutBase2> {};
template<> struct hash<winrt::Windows::UI::Xaml::Controls::Primitives::IFlyoutBase3> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Controls::Primitives::IFlyoutBase3> {};
template<> struct hash<winrt::Windows::UI::Xaml::Controls::Primitives::IFlyoutBase4> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Controls::Primitives::IFlyoutBase4> {};
template<> struct hash<winrt::Windows::UI::Xaml::Controls::Primitives::IFlyoutBase5> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Controls::Primitives::IFlyoutBase5> {};
template<> struct hash<winrt::Windows::UI::Xaml::Controls::Primitives::IFlyoutBase6> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Controls::Primitives::IFlyoutBase6> {};
template<> struct hash<winrt::Windows::UI::Xaml::Controls::Primitives::IFlyoutBaseClosingEventArgs> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Controls::Primitives::IFlyoutBaseClosingEventArgs> {};
template<> struct hash<winrt::Windows::UI::Xaml::Controls::Primitives::IFlyoutBaseFactory> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Controls::Primitives::IFlyoutBaseFactory> {};
template<> struct hash<winrt::Windows::UI::Xaml::Controls::Primitives::IFlyoutBaseOverrides> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Controls::Primitives::IFlyoutBaseOverrides> {};
template<> struct hash<winrt::Windows::UI::Xaml::Controls::Primitives::IFlyoutBaseOverrides4> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Controls::Primitives::IFlyoutBaseOverrides4> {};
template<> struct hash<winrt::Windows::UI::Xaml::Controls::Primitives::IFlyoutBaseStatics> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Controls::Primitives::IFlyoutBaseStatics> {};
template<> struct hash<winrt::Windows::UI::Xaml::Controls::Primitives::IFlyoutBaseStatics2> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Controls::Primitives::IFlyoutBaseStatics2> {};
template<> struct hash<winrt::Windows::UI::Xaml::Controls::Primitives::IFlyoutBaseStatics3> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Controls::Primitives::IFlyoutBaseStatics3> {};
template<> struct hash<winrt::Windows::UI::Xaml::Controls::Primitives::IFlyoutBaseStatics5> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Controls::Primitives::IFlyoutBaseStatics5> {};
template<> struct hash<winrt::Windows::UI::Xaml::Controls::Primitives::IFlyoutBaseStatics6> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Controls::Primitives::IFlyoutBaseStatics6> {};
template<> struct hash<winrt::Windows::UI::Xaml::Controls::Primitives::IFlyoutShowOptions> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Controls::Primitives::IFlyoutShowOptions> {};
template<> struct hash<winrt::Windows::UI::Xaml::Controls::Primitives::IFlyoutShowOptionsFactory> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Controls::Primitives::IFlyoutShowOptionsFactory> {};
template<> struct hash<winrt::Windows::UI::Xaml::Controls::Primitives::IGeneratorPositionHelper> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Controls::Primitives::IGeneratorPositionHelper> {};
template<> struct hash<winrt::Windows::UI::Xaml::Controls::Primitives::IGeneratorPositionHelperStatics> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Controls::Primitives::IGeneratorPositionHelperStatics> {};
template<> struct hash<winrt::Windows::UI::Xaml::Controls::Primitives::IGridViewItemPresenter> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Controls::Primitives::IGridViewItemPresenter> {};
template<> struct hash<winrt::Windows::UI::Xaml::Controls::Primitives::IGridViewItemPresenterFactory> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Controls::Primitives::IGridViewItemPresenterFactory> {};
template<> struct hash<winrt::Windows::UI::Xaml::Controls::Primitives::IGridViewItemPresenterStatics> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Controls::Primitives::IGridViewItemPresenterStatics> {};
template<> struct hash<winrt::Windows::UI::Xaml::Controls::Primitives::IGridViewItemTemplateSettings> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Controls::Primitives::IGridViewItemTemplateSettings> {};
template<> struct hash<winrt::Windows::UI::Xaml::Controls::Primitives::IItemsChangedEventArgs> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Controls::Primitives::IItemsChangedEventArgs> {};
template<> struct hash<winrt::Windows::UI::Xaml::Controls::Primitives::IJumpListItemBackgroundConverter> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Controls::Primitives::IJumpListItemBackgroundConverter> {};
template<> struct hash<winrt::Windows::UI::Xaml::Controls::Primitives::IJumpListItemBackgroundConverterStatics> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Controls::Primitives::IJumpListItemBackgroundConverterStatics> {};
template<> struct hash<winrt::Windows::UI::Xaml::Controls::Primitives::IJumpListItemForegroundConverter> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Controls::Primitives::IJumpListItemForegroundConverter> {};
template<> struct hash<winrt::Windows::UI::Xaml::Controls::Primitives::IJumpListItemForegroundConverterStatics> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Controls::Primitives::IJumpListItemForegroundConverterStatics> {};
template<> struct hash<winrt::Windows::UI::Xaml::Controls::Primitives::ILayoutInformation> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Controls::Primitives::ILayoutInformation> {};
template<> struct hash<winrt::Windows::UI::Xaml::Controls::Primitives::ILayoutInformationStatics> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Controls::Primitives::ILayoutInformationStatics> {};
template<> struct hash<winrt::Windows::UI::Xaml::Controls::Primitives::ILayoutInformationStatics2> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Controls::Primitives::ILayoutInformationStatics2> {};
template<> struct hash<winrt::Windows::UI::Xaml::Controls::Primitives::IListViewItemPresenter> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Controls::Primitives::IListViewItemPresenter> {};
template<> struct hash<winrt::Windows::UI::Xaml::Controls::Primitives::IListViewItemPresenter2> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Controls::Primitives::IListViewItemPresenter2> {};
template<> struct hash<winrt::Windows::UI::Xaml::Controls::Primitives::IListViewItemPresenter3> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Controls::Primitives::IListViewItemPresenter3> {};
template<> struct hash<winrt::Windows::UI::Xaml::Controls::Primitives::IListViewItemPresenterFactory> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Controls::Primitives::IListViewItemPresenterFactory> {};
template<> struct hash<winrt::Windows::UI::Xaml::Controls::Primitives::IListViewItemPresenterStatics> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Controls::Primitives::IListViewItemPresenterStatics> {};
template<> struct hash<winrt::Windows::UI::Xaml::Controls::Primitives::IListViewItemPresenterStatics2> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Controls::Primitives::IListViewItemPresenterStatics2> {};
template<> struct hash<winrt::Windows::UI::Xaml::Controls::Primitives::IListViewItemPresenterStatics3> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Controls::Primitives::IListViewItemPresenterStatics3> {};
template<> struct hash<winrt::Windows::UI::Xaml::Controls::Primitives::IListViewItemTemplateSettings> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Controls::Primitives::IListViewItemTemplateSettings> {};
template<> struct hash<winrt::Windows::UI::Xaml::Controls::Primitives::ILoopingSelector> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Controls::Primitives::ILoopingSelector> {};
template<> struct hash<winrt::Windows::UI::Xaml::Controls::Primitives::ILoopingSelectorItem> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Controls::Primitives::ILoopingSelectorItem> {};
template<> struct hash<winrt::Windows::UI::Xaml::Controls::Primitives::ILoopingSelectorPanel> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Controls::Primitives::ILoopingSelectorPanel> {};
template<> struct hash<winrt::Windows::UI::Xaml::Controls::Primitives::ILoopingSelectorStatics> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Controls::Primitives::ILoopingSelectorStatics> {};
template<> struct hash<winrt::Windows::UI::Xaml::Controls::Primitives::IMenuFlyoutItemTemplateSettings> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Controls::Primitives::IMenuFlyoutItemTemplateSettings> {};
template<> struct hash<winrt::Windows::UI::Xaml::Controls::Primitives::IMenuFlyoutPresenterTemplateSettings> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Controls::Primitives::IMenuFlyoutPresenterTemplateSettings> {};
template<> struct hash<winrt::Windows::UI::Xaml::Controls::Primitives::INavigationViewItemPresenter> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Controls::Primitives::INavigationViewItemPresenter> {};
template<> struct hash<winrt::Windows::UI::Xaml::Controls::Primitives::INavigationViewItemPresenterFactory> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Controls::Primitives::INavigationViewItemPresenterFactory> {};
template<> struct hash<winrt::Windows::UI::Xaml::Controls::Primitives::INavigationViewItemPresenterStatics> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Controls::Primitives::INavigationViewItemPresenterStatics> {};
template<> struct hash<winrt::Windows::UI::Xaml::Controls::Primitives::IOrientedVirtualizingPanel> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Controls::Primitives::IOrientedVirtualizingPanel> {};
template<> struct hash<winrt::Windows::UI::Xaml::Controls::Primitives::IOrientedVirtualizingPanelFactory> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Controls::Primitives::IOrientedVirtualizingPanelFactory> {};
template<> struct hash<winrt::Windows::UI::Xaml::Controls::Primitives::IPickerFlyoutBase> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Controls::Primitives::IPickerFlyoutBase> {};
template<> struct hash<winrt::Windows::UI::Xaml::Controls::Primitives::IPickerFlyoutBaseFactory> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Controls::Primitives::IPickerFlyoutBaseFactory> {};
template<> struct hash<winrt::Windows::UI::Xaml::Controls::Primitives::IPickerFlyoutBaseOverrides> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Controls::Primitives::IPickerFlyoutBaseOverrides> {};
template<> struct hash<winrt::Windows::UI::Xaml::Controls::Primitives::IPickerFlyoutBaseStatics> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Controls::Primitives::IPickerFlyoutBaseStatics> {};
template<> struct hash<winrt::Windows::UI::Xaml::Controls::Primitives::IPivotHeaderItem> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Controls::Primitives::IPivotHeaderItem> {};
template<> struct hash<winrt::Windows::UI::Xaml::Controls::Primitives::IPivotHeaderItemFactory> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Controls::Primitives::IPivotHeaderItemFactory> {};
template<> struct hash<winrt::Windows::UI::Xaml::Controls::Primitives::IPivotHeaderPanel> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Controls::Primitives::IPivotHeaderPanel> {};
template<> struct hash<winrt::Windows::UI::Xaml::Controls::Primitives::IPivotPanel> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Controls::Primitives::IPivotPanel> {};
template<> struct hash<winrt::Windows::UI::Xaml::Controls::Primitives::IPopup> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Controls::Primitives::IPopup> {};
template<> struct hash<winrt::Windows::UI::Xaml::Controls::Primitives::IPopup2> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Controls::Primitives::IPopup2> {};
template<> struct hash<winrt::Windows::UI::Xaml::Controls::Primitives::IPopup3> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Controls::Primitives::IPopup3> {};
template<> struct hash<winrt::Windows::UI::Xaml::Controls::Primitives::IPopupStatics> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Controls::Primitives::IPopupStatics> {};
template<> struct hash<winrt::Windows::UI::Xaml::Controls::Primitives::IPopupStatics2> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Controls::Primitives::IPopupStatics2> {};
template<> struct hash<winrt::Windows::UI::Xaml::Controls::Primitives::IPopupStatics3> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Controls::Primitives::IPopupStatics3> {};
template<> struct hash<winrt::Windows::UI::Xaml::Controls::Primitives::IProgressBarTemplateSettings> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Controls::Primitives::IProgressBarTemplateSettings> {};
template<> struct hash<winrt::Windows::UI::Xaml::Controls::Primitives::IProgressRingTemplateSettings> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Controls::Primitives::IProgressRingTemplateSettings> {};
template<> struct hash<winrt::Windows::UI::Xaml::Controls::Primitives::IRangeBase> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Controls::Primitives::IRangeBase> {};
template<> struct hash<winrt::Windows::UI::Xaml::Controls::Primitives::IRangeBaseFactory> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Controls::Primitives::IRangeBaseFactory> {};
template<> struct hash<winrt::Windows::UI::Xaml::Controls::Primitives::IRangeBaseOverrides> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Controls::Primitives::IRangeBaseOverrides> {};
template<> struct hash<winrt::Windows::UI::Xaml::Controls::Primitives::IRangeBaseStatics> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Controls::Primitives::IRangeBaseStatics> {};
template<> struct hash<winrt::Windows::UI::Xaml::Controls::Primitives::IRangeBaseValueChangedEventArgs> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Controls::Primitives::IRangeBaseValueChangedEventArgs> {};
template<> struct hash<winrt::Windows::UI::Xaml::Controls::Primitives::IRepeatButton> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Controls::Primitives::IRepeatButton> {};
template<> struct hash<winrt::Windows::UI::Xaml::Controls::Primitives::IRepeatButtonStatics> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Controls::Primitives::IRepeatButtonStatics> {};
template<> struct hash<winrt::Windows::UI::Xaml::Controls::Primitives::IScrollBar> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Controls::Primitives::IScrollBar> {};
template<> struct hash<winrt::Windows::UI::Xaml::Controls::Primitives::IScrollBarStatics> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Controls::Primitives::IScrollBarStatics> {};
template<> struct hash<winrt::Windows::UI::Xaml::Controls::Primitives::IScrollEventArgs> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Controls::Primitives::IScrollEventArgs> {};
template<> struct hash<winrt::Windows::UI::Xaml::Controls::Primitives::IScrollSnapPointsInfo> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Controls::Primitives::IScrollSnapPointsInfo> {};
template<> struct hash<winrt::Windows::UI::Xaml::Controls::Primitives::ISelector> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Controls::Primitives::ISelector> {};
template<> struct hash<winrt::Windows::UI::Xaml::Controls::Primitives::ISelectorFactory> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Controls::Primitives::ISelectorFactory> {};
template<> struct hash<winrt::Windows::UI::Xaml::Controls::Primitives::ISelectorItem> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Controls::Primitives::ISelectorItem> {};
template<> struct hash<winrt::Windows::UI::Xaml::Controls::Primitives::ISelectorItemFactory> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Controls::Primitives::ISelectorItemFactory> {};
template<> struct hash<winrt::Windows::UI::Xaml::Controls::Primitives::ISelectorItemStatics> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Controls::Primitives::ISelectorItemStatics> {};
template<> struct hash<winrt::Windows::UI::Xaml::Controls::Primitives::ISelectorStatics> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Controls::Primitives::ISelectorStatics> {};
template<> struct hash<winrt::Windows::UI::Xaml::Controls::Primitives::ISettingsFlyoutTemplateSettings> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Controls::Primitives::ISettingsFlyoutTemplateSettings> {};
template<> struct hash<winrt::Windows::UI::Xaml::Controls::Primitives::ISplitViewTemplateSettings> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Controls::Primitives::ISplitViewTemplateSettings> {};
template<> struct hash<winrt::Windows::UI::Xaml::Controls::Primitives::IThumb> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Controls::Primitives::IThumb> {};
template<> struct hash<winrt::Windows::UI::Xaml::Controls::Primitives::IThumbStatics> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Controls::Primitives::IThumbStatics> {};
template<> struct hash<winrt::Windows::UI::Xaml::Controls::Primitives::ITickBar> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Controls::Primitives::ITickBar> {};
template<> struct hash<winrt::Windows::UI::Xaml::Controls::Primitives::ITickBarStatics> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Controls::Primitives::ITickBarStatics> {};
template<> struct hash<winrt::Windows::UI::Xaml::Controls::Primitives::IToggleButton> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Controls::Primitives::IToggleButton> {};
template<> struct hash<winrt::Windows::UI::Xaml::Controls::Primitives::IToggleButtonFactory> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Controls::Primitives::IToggleButtonFactory> {};
template<> struct hash<winrt::Windows::UI::Xaml::Controls::Primitives::IToggleButtonOverrides> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Controls::Primitives::IToggleButtonOverrides> {};
template<> struct hash<winrt::Windows::UI::Xaml::Controls::Primitives::IToggleButtonStatics> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Controls::Primitives::IToggleButtonStatics> {};
template<> struct hash<winrt::Windows::UI::Xaml::Controls::Primitives::IToggleSwitchTemplateSettings> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Controls::Primitives::IToggleSwitchTemplateSettings> {};
template<> struct hash<winrt::Windows::UI::Xaml::Controls::Primitives::IToolTipTemplateSettings> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Controls::Primitives::IToolTipTemplateSettings> {};
template<> struct hash<winrt::Windows::UI::Xaml::Controls::Primitives::AppBarButtonTemplateSettings> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Controls::Primitives::AppBarButtonTemplateSettings> {};
template<> struct hash<winrt::Windows::UI::Xaml::Controls::Primitives::AppBarTemplateSettings> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Controls::Primitives::AppBarTemplateSettings> {};
template<> struct hash<winrt::Windows::UI::Xaml::Controls::Primitives::AppBarToggleButtonTemplateSettings> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Controls::Primitives::AppBarToggleButtonTemplateSettings> {};
template<> struct hash<winrt::Windows::UI::Xaml::Controls::Primitives::ButtonBase> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Controls::Primitives::ButtonBase> {};
template<> struct hash<winrt::Windows::UI::Xaml::Controls::Primitives::CalendarPanel> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Controls::Primitives::CalendarPanel> {};
template<> struct hash<winrt::Windows::UI::Xaml::Controls::Primitives::CalendarViewTemplateSettings> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Controls::Primitives::CalendarViewTemplateSettings> {};
template<> struct hash<winrt::Windows::UI::Xaml::Controls::Primitives::CarouselPanel> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Controls::Primitives::CarouselPanel> {};
template<> struct hash<winrt::Windows::UI::Xaml::Controls::Primitives::ColorPickerSlider> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Controls::Primitives::ColorPickerSlider> {};
template<> struct hash<winrt::Windows::UI::Xaml::Controls::Primitives::ColorSpectrum> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Controls::Primitives::ColorSpectrum> {};
template<> struct hash<winrt::Windows::UI::Xaml::Controls::Primitives::ComboBoxTemplateSettings> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Controls::Primitives::ComboBoxTemplateSettings> {};
template<> struct hash<winrt::Windows::UI::Xaml::Controls::Primitives::CommandBarFlyoutCommandBar> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Controls::Primitives::CommandBarFlyoutCommandBar> {};
template<> struct hash<winrt::Windows::UI::Xaml::Controls::Primitives::CommandBarFlyoutCommandBarTemplateSettings> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Controls::Primitives::CommandBarFlyoutCommandBarTemplateSettings> {};
template<> struct hash<winrt::Windows::UI::Xaml::Controls::Primitives::CommandBarTemplateSettings> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Controls::Primitives::CommandBarTemplateSettings> {};
template<> struct hash<winrt::Windows::UI::Xaml::Controls::Primitives::DragCompletedEventArgs> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Controls::Primitives::DragCompletedEventArgs> {};
template<> struct hash<winrt::Windows::UI::Xaml::Controls::Primitives::DragDeltaEventArgs> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Controls::Primitives::DragDeltaEventArgs> {};
template<> struct hash<winrt::Windows::UI::Xaml::Controls::Primitives::DragStartedEventArgs> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Controls::Primitives::DragStartedEventArgs> {};
template<> struct hash<winrt::Windows::UI::Xaml::Controls::Primitives::FlyoutBase> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Controls::Primitives::FlyoutBase> {};
template<> struct hash<winrt::Windows::UI::Xaml::Controls::Primitives::FlyoutBaseClosingEventArgs> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Controls::Primitives::FlyoutBaseClosingEventArgs> {};
template<> struct hash<winrt::Windows::UI::Xaml::Controls::Primitives::FlyoutShowOptions> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Controls::Primitives::FlyoutShowOptions> {};
template<> struct hash<winrt::Windows::UI::Xaml::Controls::Primitives::GeneratorPositionHelper> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Controls::Primitives::GeneratorPositionHelper> {};
template<> struct hash<winrt::Windows::UI::Xaml::Controls::Primitives::GridViewItemPresenter> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Controls::Primitives::GridViewItemPresenter> {};
template<> struct hash<winrt::Windows::UI::Xaml::Controls::Primitives::GridViewItemTemplateSettings> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Controls::Primitives::GridViewItemTemplateSettings> {};
template<> struct hash<winrt::Windows::UI::Xaml::Controls::Primitives::ItemsChangedEventArgs> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Controls::Primitives::ItemsChangedEventArgs> {};
template<> struct hash<winrt::Windows::UI::Xaml::Controls::Primitives::JumpListItemBackgroundConverter> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Controls::Primitives::JumpListItemBackgroundConverter> {};
template<> struct hash<winrt::Windows::UI::Xaml::Controls::Primitives::JumpListItemForegroundConverter> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Controls::Primitives::JumpListItemForegroundConverter> {};
template<> struct hash<winrt::Windows::UI::Xaml::Controls::Primitives::LayoutInformation> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Controls::Primitives::LayoutInformation> {};
template<> struct hash<winrt::Windows::UI::Xaml::Controls::Primitives::ListViewItemPresenter> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Controls::Primitives::ListViewItemPresenter> {};
template<> struct hash<winrt::Windows::UI::Xaml::Controls::Primitives::ListViewItemTemplateSettings> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Controls::Primitives::ListViewItemTemplateSettings> {};
template<> struct hash<winrt::Windows::UI::Xaml::Controls::Primitives::LoopingSelector> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Controls::Primitives::LoopingSelector> {};
template<> struct hash<winrt::Windows::UI::Xaml::Controls::Primitives::LoopingSelectorItem> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Controls::Primitives::LoopingSelectorItem> {};
template<> struct hash<winrt::Windows::UI::Xaml::Controls::Primitives::LoopingSelectorPanel> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Controls::Primitives::LoopingSelectorPanel> {};
template<> struct hash<winrt::Windows::UI::Xaml::Controls::Primitives::MenuFlyoutItemTemplateSettings> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Controls::Primitives::MenuFlyoutItemTemplateSettings> {};
template<> struct hash<winrt::Windows::UI::Xaml::Controls::Primitives::MenuFlyoutPresenterTemplateSettings> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Controls::Primitives::MenuFlyoutPresenterTemplateSettings> {};
template<> struct hash<winrt::Windows::UI::Xaml::Controls::Primitives::NavigationViewItemPresenter> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Controls::Primitives::NavigationViewItemPresenter> {};
template<> struct hash<winrt::Windows::UI::Xaml::Controls::Primitives::OrientedVirtualizingPanel> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Controls::Primitives::OrientedVirtualizingPanel> {};
template<> struct hash<winrt::Windows::UI::Xaml::Controls::Primitives::PickerFlyoutBase> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Controls::Primitives::PickerFlyoutBase> {};
template<> struct hash<winrt::Windows::UI::Xaml::Controls::Primitives::PivotHeaderItem> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Controls::Primitives::PivotHeaderItem> {};
template<> struct hash<winrt::Windows::UI::Xaml::Controls::Primitives::PivotHeaderPanel> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Controls::Primitives::PivotHeaderPanel> {};
template<> struct hash<winrt::Windows::UI::Xaml::Controls::Primitives::PivotPanel> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Controls::Primitives::PivotPanel> {};
template<> struct hash<winrt::Windows::UI::Xaml::Controls::Primitives::Popup> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Controls::Primitives::Popup> {};
template<> struct hash<winrt::Windows::UI::Xaml::Controls::Primitives::ProgressBarTemplateSettings> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Controls::Primitives::ProgressBarTemplateSettings> {};
template<> struct hash<winrt::Windows::UI::Xaml::Controls::Primitives::ProgressRingTemplateSettings> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Controls::Primitives::ProgressRingTemplateSettings> {};
template<> struct hash<winrt::Windows::UI::Xaml::Controls::Primitives::RangeBase> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Controls::Primitives::RangeBase> {};
template<> struct hash<winrt::Windows::UI::Xaml::Controls::Primitives::RangeBaseValueChangedEventArgs> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Controls::Primitives::RangeBaseValueChangedEventArgs> {};
template<> struct hash<winrt::Windows::UI::Xaml::Controls::Primitives::RepeatButton> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Controls::Primitives::RepeatButton> {};
template<> struct hash<winrt::Windows::UI::Xaml::Controls::Primitives::ScrollBar> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Controls::Primitives::ScrollBar> {};
template<> struct hash<winrt::Windows::UI::Xaml::Controls::Primitives::ScrollEventArgs> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Controls::Primitives::ScrollEventArgs> {};
template<> struct hash<winrt::Windows::UI::Xaml::Controls::Primitives::Selector> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Controls::Primitives::Selector> {};
template<> struct hash<winrt::Windows::UI::Xaml::Controls::Primitives::SelectorItem> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Controls::Primitives::SelectorItem> {};
template<> struct hash<winrt::Windows::UI::Xaml::Controls::Primitives::SettingsFlyoutTemplateSettings> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Controls::Primitives::SettingsFlyoutTemplateSettings> {};
template<> struct hash<winrt::Windows::UI::Xaml::Controls::Primitives::SplitViewTemplateSettings> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Controls::Primitives::SplitViewTemplateSettings> {};
template<> struct hash<winrt::Windows::UI::Xaml::Controls::Primitives::Thumb> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Controls::Primitives::Thumb> {};
template<> struct hash<winrt::Windows::UI::Xaml::Controls::Primitives::TickBar> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Controls::Primitives::TickBar> {};
template<> struct hash<winrt::Windows::UI::Xaml::Controls::Primitives::ToggleButton> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Controls::Primitives::ToggleButton> {};
template<> struct hash<winrt::Windows::UI::Xaml::Controls::Primitives::ToggleSwitchTemplateSettings> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Controls::Primitives::ToggleSwitchTemplateSettings> {};
template<> struct hash<winrt::Windows::UI::Xaml::Controls::Primitives::ToolTipTemplateSettings> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Controls::Primitives::ToolTipTemplateSettings> {};

}
