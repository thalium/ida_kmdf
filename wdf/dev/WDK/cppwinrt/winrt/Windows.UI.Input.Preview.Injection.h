// C++/WinRT v1.0.190111.3

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#pragma once

#include "winrt/base.h"

#include "winrt/Windows.Foundation.h"
#include "winrt/Windows.Foundation.Collections.h"
#include "winrt/impl/Windows.Gaming.Input.2.h"
#include "winrt/impl/Windows.UI.Input.Preview.Injection.2.h"
#include "winrt/Windows.UI.Input.Preview.h"

namespace winrt::impl {

template <typename D> Windows::Gaming::Input::GamepadButtons consume_Windows_UI_Input_Preview_Injection_IInjectedInputGamepadInfo<D>::Buttons() const
{
    Windows::Gaming::Input::GamepadButtons value{};
    check_hresult(WINRT_SHIM(Windows::UI::Input::Preview::Injection::IInjectedInputGamepadInfo)->get_Buttons(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_UI_Input_Preview_Injection_IInjectedInputGamepadInfo<D>::Buttons(Windows::Gaming::Input::GamepadButtons const& value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Input::Preview::Injection::IInjectedInputGamepadInfo)->put_Buttons(get_abi(value)));
}

template <typename D> double consume_Windows_UI_Input_Preview_Injection_IInjectedInputGamepadInfo<D>::LeftThumbstickX() const
{
    double value{};
    check_hresult(WINRT_SHIM(Windows::UI::Input::Preview::Injection::IInjectedInputGamepadInfo)->get_LeftThumbstickX(&value));
    return value;
}

template <typename D> void consume_Windows_UI_Input_Preview_Injection_IInjectedInputGamepadInfo<D>::LeftThumbstickX(double value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Input::Preview::Injection::IInjectedInputGamepadInfo)->put_LeftThumbstickX(value));
}

template <typename D> double consume_Windows_UI_Input_Preview_Injection_IInjectedInputGamepadInfo<D>::LeftThumbstickY() const
{
    double value{};
    check_hresult(WINRT_SHIM(Windows::UI::Input::Preview::Injection::IInjectedInputGamepadInfo)->get_LeftThumbstickY(&value));
    return value;
}

template <typename D> void consume_Windows_UI_Input_Preview_Injection_IInjectedInputGamepadInfo<D>::LeftThumbstickY(double value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Input::Preview::Injection::IInjectedInputGamepadInfo)->put_LeftThumbstickY(value));
}

template <typename D> double consume_Windows_UI_Input_Preview_Injection_IInjectedInputGamepadInfo<D>::LeftTrigger() const
{
    double value{};
    check_hresult(WINRT_SHIM(Windows::UI::Input::Preview::Injection::IInjectedInputGamepadInfo)->get_LeftTrigger(&value));
    return value;
}

template <typename D> void consume_Windows_UI_Input_Preview_Injection_IInjectedInputGamepadInfo<D>::LeftTrigger(double value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Input::Preview::Injection::IInjectedInputGamepadInfo)->put_LeftTrigger(value));
}

template <typename D> double consume_Windows_UI_Input_Preview_Injection_IInjectedInputGamepadInfo<D>::RightThumbstickX() const
{
    double value{};
    check_hresult(WINRT_SHIM(Windows::UI::Input::Preview::Injection::IInjectedInputGamepadInfo)->get_RightThumbstickX(&value));
    return value;
}

template <typename D> void consume_Windows_UI_Input_Preview_Injection_IInjectedInputGamepadInfo<D>::RightThumbstickX(double value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Input::Preview::Injection::IInjectedInputGamepadInfo)->put_RightThumbstickX(value));
}

template <typename D> double consume_Windows_UI_Input_Preview_Injection_IInjectedInputGamepadInfo<D>::RightThumbstickY() const
{
    double value{};
    check_hresult(WINRT_SHIM(Windows::UI::Input::Preview::Injection::IInjectedInputGamepadInfo)->get_RightThumbstickY(&value));
    return value;
}

template <typename D> void consume_Windows_UI_Input_Preview_Injection_IInjectedInputGamepadInfo<D>::RightThumbstickY(double value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Input::Preview::Injection::IInjectedInputGamepadInfo)->put_RightThumbstickY(value));
}

template <typename D> double consume_Windows_UI_Input_Preview_Injection_IInjectedInputGamepadInfo<D>::RightTrigger() const
{
    double value{};
    check_hresult(WINRT_SHIM(Windows::UI::Input::Preview::Injection::IInjectedInputGamepadInfo)->get_RightTrigger(&value));
    return value;
}

template <typename D> void consume_Windows_UI_Input_Preview_Injection_IInjectedInputGamepadInfo<D>::RightTrigger(double value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Input::Preview::Injection::IInjectedInputGamepadInfo)->put_RightTrigger(value));
}

template <typename D> Windows::UI::Input::Preview::Injection::InjectedInputGamepadInfo consume_Windows_UI_Input_Preview_Injection_IInjectedInputGamepadInfoFactory<D>::CreateInstance(Windows::Gaming::Input::GamepadReading const& reading) const
{
    Windows::UI::Input::Preview::Injection::InjectedInputGamepadInfo value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Input::Preview::Injection::IInjectedInputGamepadInfoFactory)->CreateInstanceFromGamepadReading(get_abi(reading), put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Input::Preview::Injection::InjectedInputKeyOptions consume_Windows_UI_Input_Preview_Injection_IInjectedInputKeyboardInfo<D>::KeyOptions() const
{
    Windows::UI::Input::Preview::Injection::InjectedInputKeyOptions value{};
    check_hresult(WINRT_SHIM(Windows::UI::Input::Preview::Injection::IInjectedInputKeyboardInfo)->get_KeyOptions(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_UI_Input_Preview_Injection_IInjectedInputKeyboardInfo<D>::KeyOptions(Windows::UI::Input::Preview::Injection::InjectedInputKeyOptions const& value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Input::Preview::Injection::IInjectedInputKeyboardInfo)->put_KeyOptions(get_abi(value)));
}

template <typename D> uint16_t consume_Windows_UI_Input_Preview_Injection_IInjectedInputKeyboardInfo<D>::ScanCode() const
{
    uint16_t value{};
    check_hresult(WINRT_SHIM(Windows::UI::Input::Preview::Injection::IInjectedInputKeyboardInfo)->get_ScanCode(&value));
    return value;
}

template <typename D> void consume_Windows_UI_Input_Preview_Injection_IInjectedInputKeyboardInfo<D>::ScanCode(uint16_t value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Input::Preview::Injection::IInjectedInputKeyboardInfo)->put_ScanCode(value));
}

template <typename D> uint16_t consume_Windows_UI_Input_Preview_Injection_IInjectedInputKeyboardInfo<D>::VirtualKey() const
{
    uint16_t value{};
    check_hresult(WINRT_SHIM(Windows::UI::Input::Preview::Injection::IInjectedInputKeyboardInfo)->get_VirtualKey(&value));
    return value;
}

template <typename D> void consume_Windows_UI_Input_Preview_Injection_IInjectedInputKeyboardInfo<D>::VirtualKey(uint16_t value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Input::Preview::Injection::IInjectedInputKeyboardInfo)->put_VirtualKey(value));
}

template <typename D> Windows::UI::Input::Preview::Injection::InjectedInputMouseOptions consume_Windows_UI_Input_Preview_Injection_IInjectedInputMouseInfo<D>::MouseOptions() const
{
    Windows::UI::Input::Preview::Injection::InjectedInputMouseOptions value{};
    check_hresult(WINRT_SHIM(Windows::UI::Input::Preview::Injection::IInjectedInputMouseInfo)->get_MouseOptions(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_UI_Input_Preview_Injection_IInjectedInputMouseInfo<D>::MouseOptions(Windows::UI::Input::Preview::Injection::InjectedInputMouseOptions const& value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Input::Preview::Injection::IInjectedInputMouseInfo)->put_MouseOptions(get_abi(value)));
}

template <typename D> uint32_t consume_Windows_UI_Input_Preview_Injection_IInjectedInputMouseInfo<D>::MouseData() const
{
    uint32_t value{};
    check_hresult(WINRT_SHIM(Windows::UI::Input::Preview::Injection::IInjectedInputMouseInfo)->get_MouseData(&value));
    return value;
}

template <typename D> void consume_Windows_UI_Input_Preview_Injection_IInjectedInputMouseInfo<D>::MouseData(uint32_t value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Input::Preview::Injection::IInjectedInputMouseInfo)->put_MouseData(value));
}

template <typename D> int32_t consume_Windows_UI_Input_Preview_Injection_IInjectedInputMouseInfo<D>::DeltaY() const
{
    int32_t value{};
    check_hresult(WINRT_SHIM(Windows::UI::Input::Preview::Injection::IInjectedInputMouseInfo)->get_DeltaY(&value));
    return value;
}

template <typename D> void consume_Windows_UI_Input_Preview_Injection_IInjectedInputMouseInfo<D>::DeltaY(int32_t value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Input::Preview::Injection::IInjectedInputMouseInfo)->put_DeltaY(value));
}

template <typename D> int32_t consume_Windows_UI_Input_Preview_Injection_IInjectedInputMouseInfo<D>::DeltaX() const
{
    int32_t value{};
    check_hresult(WINRT_SHIM(Windows::UI::Input::Preview::Injection::IInjectedInputMouseInfo)->get_DeltaX(&value));
    return value;
}

template <typename D> void consume_Windows_UI_Input_Preview_Injection_IInjectedInputMouseInfo<D>::DeltaX(int32_t value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Input::Preview::Injection::IInjectedInputMouseInfo)->put_DeltaX(value));
}

template <typename D> uint32_t consume_Windows_UI_Input_Preview_Injection_IInjectedInputMouseInfo<D>::TimeOffsetInMilliseconds() const
{
    uint32_t value{};
    check_hresult(WINRT_SHIM(Windows::UI::Input::Preview::Injection::IInjectedInputMouseInfo)->get_TimeOffsetInMilliseconds(&value));
    return value;
}

template <typename D> void consume_Windows_UI_Input_Preview_Injection_IInjectedInputMouseInfo<D>::TimeOffsetInMilliseconds(uint32_t value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Input::Preview::Injection::IInjectedInputMouseInfo)->put_TimeOffsetInMilliseconds(value));
}

template <typename D> Windows::UI::Input::Preview::Injection::InjectedInputPointerInfo consume_Windows_UI_Input_Preview_Injection_IInjectedInputPenInfo<D>::PointerInfo() const
{
    Windows::UI::Input::Preview::Injection::InjectedInputPointerInfo value{};
    check_hresult(WINRT_SHIM(Windows::UI::Input::Preview::Injection::IInjectedInputPenInfo)->get_PointerInfo(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_UI_Input_Preview_Injection_IInjectedInputPenInfo<D>::PointerInfo(Windows::UI::Input::Preview::Injection::InjectedInputPointerInfo const& value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Input::Preview::Injection::IInjectedInputPenInfo)->put_PointerInfo(get_abi(value)));
}

template <typename D> Windows::UI::Input::Preview::Injection::InjectedInputPenButtons consume_Windows_UI_Input_Preview_Injection_IInjectedInputPenInfo<D>::PenButtons() const
{
    Windows::UI::Input::Preview::Injection::InjectedInputPenButtons value{};
    check_hresult(WINRT_SHIM(Windows::UI::Input::Preview::Injection::IInjectedInputPenInfo)->get_PenButtons(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_UI_Input_Preview_Injection_IInjectedInputPenInfo<D>::PenButtons(Windows::UI::Input::Preview::Injection::InjectedInputPenButtons const& value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Input::Preview::Injection::IInjectedInputPenInfo)->put_PenButtons(get_abi(value)));
}

template <typename D> Windows::UI::Input::Preview::Injection::InjectedInputPenParameters consume_Windows_UI_Input_Preview_Injection_IInjectedInputPenInfo<D>::PenParameters() const
{
    Windows::UI::Input::Preview::Injection::InjectedInputPenParameters value{};
    check_hresult(WINRT_SHIM(Windows::UI::Input::Preview::Injection::IInjectedInputPenInfo)->get_PenParameters(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_UI_Input_Preview_Injection_IInjectedInputPenInfo<D>::PenParameters(Windows::UI::Input::Preview::Injection::InjectedInputPenParameters const& value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Input::Preview::Injection::IInjectedInputPenInfo)->put_PenParameters(get_abi(value)));
}

template <typename D> double consume_Windows_UI_Input_Preview_Injection_IInjectedInputPenInfo<D>::Pressure() const
{
    double value{};
    check_hresult(WINRT_SHIM(Windows::UI::Input::Preview::Injection::IInjectedInputPenInfo)->get_Pressure(&value));
    return value;
}

template <typename D> void consume_Windows_UI_Input_Preview_Injection_IInjectedInputPenInfo<D>::Pressure(double value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Input::Preview::Injection::IInjectedInputPenInfo)->put_Pressure(value));
}

template <typename D> double consume_Windows_UI_Input_Preview_Injection_IInjectedInputPenInfo<D>::Rotation() const
{
    double value{};
    check_hresult(WINRT_SHIM(Windows::UI::Input::Preview::Injection::IInjectedInputPenInfo)->get_Rotation(&value));
    return value;
}

template <typename D> void consume_Windows_UI_Input_Preview_Injection_IInjectedInputPenInfo<D>::Rotation(double value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Input::Preview::Injection::IInjectedInputPenInfo)->put_Rotation(value));
}

template <typename D> int32_t consume_Windows_UI_Input_Preview_Injection_IInjectedInputPenInfo<D>::TiltX() const
{
    int32_t value{};
    check_hresult(WINRT_SHIM(Windows::UI::Input::Preview::Injection::IInjectedInputPenInfo)->get_TiltX(&value));
    return value;
}

template <typename D> void consume_Windows_UI_Input_Preview_Injection_IInjectedInputPenInfo<D>::TiltX(int32_t value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Input::Preview::Injection::IInjectedInputPenInfo)->put_TiltX(value));
}

template <typename D> int32_t consume_Windows_UI_Input_Preview_Injection_IInjectedInputPenInfo<D>::TiltY() const
{
    int32_t value{};
    check_hresult(WINRT_SHIM(Windows::UI::Input::Preview::Injection::IInjectedInputPenInfo)->get_TiltY(&value));
    return value;
}

template <typename D> void consume_Windows_UI_Input_Preview_Injection_IInjectedInputPenInfo<D>::TiltY(int32_t value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Input::Preview::Injection::IInjectedInputPenInfo)->put_TiltY(value));
}

template <typename D> Windows::UI::Input::Preview::Injection::InjectedInputRectangle consume_Windows_UI_Input_Preview_Injection_IInjectedInputTouchInfo<D>::Contact() const
{
    Windows::UI::Input::Preview::Injection::InjectedInputRectangle value{};
    check_hresult(WINRT_SHIM(Windows::UI::Input::Preview::Injection::IInjectedInputTouchInfo)->get_Contact(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_UI_Input_Preview_Injection_IInjectedInputTouchInfo<D>::Contact(Windows::UI::Input::Preview::Injection::InjectedInputRectangle const& value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Input::Preview::Injection::IInjectedInputTouchInfo)->put_Contact(get_abi(value)));
}

template <typename D> int32_t consume_Windows_UI_Input_Preview_Injection_IInjectedInputTouchInfo<D>::Orientation() const
{
    int32_t value{};
    check_hresult(WINRT_SHIM(Windows::UI::Input::Preview::Injection::IInjectedInputTouchInfo)->get_Orientation(&value));
    return value;
}

template <typename D> void consume_Windows_UI_Input_Preview_Injection_IInjectedInputTouchInfo<D>::Orientation(int32_t value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Input::Preview::Injection::IInjectedInputTouchInfo)->put_Orientation(value));
}

template <typename D> Windows::UI::Input::Preview::Injection::InjectedInputPointerInfo consume_Windows_UI_Input_Preview_Injection_IInjectedInputTouchInfo<D>::PointerInfo() const
{
    Windows::UI::Input::Preview::Injection::InjectedInputPointerInfo value{};
    check_hresult(WINRT_SHIM(Windows::UI::Input::Preview::Injection::IInjectedInputTouchInfo)->get_PointerInfo(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_UI_Input_Preview_Injection_IInjectedInputTouchInfo<D>::PointerInfo(Windows::UI::Input::Preview::Injection::InjectedInputPointerInfo const& value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Input::Preview::Injection::IInjectedInputTouchInfo)->put_PointerInfo(get_abi(value)));
}

template <typename D> double consume_Windows_UI_Input_Preview_Injection_IInjectedInputTouchInfo<D>::Pressure() const
{
    double value{};
    check_hresult(WINRT_SHIM(Windows::UI::Input::Preview::Injection::IInjectedInputTouchInfo)->get_Pressure(&value));
    return value;
}

template <typename D> void consume_Windows_UI_Input_Preview_Injection_IInjectedInputTouchInfo<D>::Pressure(double value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Input::Preview::Injection::IInjectedInputTouchInfo)->put_Pressure(value));
}

template <typename D> Windows::UI::Input::Preview::Injection::InjectedInputTouchParameters consume_Windows_UI_Input_Preview_Injection_IInjectedInputTouchInfo<D>::TouchParameters() const
{
    Windows::UI::Input::Preview::Injection::InjectedInputTouchParameters value{};
    check_hresult(WINRT_SHIM(Windows::UI::Input::Preview::Injection::IInjectedInputTouchInfo)->get_TouchParameters(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_UI_Input_Preview_Injection_IInjectedInputTouchInfo<D>::TouchParameters(Windows::UI::Input::Preview::Injection::InjectedInputTouchParameters const& value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Input::Preview::Injection::IInjectedInputTouchInfo)->put_TouchParameters(get_abi(value)));
}

template <typename D> void consume_Windows_UI_Input_Preview_Injection_IInputInjector<D>::InjectKeyboardInput(param::iterable<Windows::UI::Input::Preview::Injection::InjectedInputKeyboardInfo> const& input) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Input::Preview::Injection::IInputInjector)->InjectKeyboardInput(get_abi(input)));
}

template <typename D> void consume_Windows_UI_Input_Preview_Injection_IInputInjector<D>::InjectMouseInput(param::iterable<Windows::UI::Input::Preview::Injection::InjectedInputMouseInfo> const& input) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Input::Preview::Injection::IInputInjector)->InjectMouseInput(get_abi(input)));
}

template <typename D> void consume_Windows_UI_Input_Preview_Injection_IInputInjector<D>::InitializeTouchInjection(Windows::UI::Input::Preview::Injection::InjectedInputVisualizationMode const& visualMode) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Input::Preview::Injection::IInputInjector)->InitializeTouchInjection(get_abi(visualMode)));
}

template <typename D> void consume_Windows_UI_Input_Preview_Injection_IInputInjector<D>::InjectTouchInput(param::iterable<Windows::UI::Input::Preview::Injection::InjectedInputTouchInfo> const& input) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Input::Preview::Injection::IInputInjector)->InjectTouchInput(get_abi(input)));
}

template <typename D> void consume_Windows_UI_Input_Preview_Injection_IInputInjector<D>::UninitializeTouchInjection() const
{
    check_hresult(WINRT_SHIM(Windows::UI::Input::Preview::Injection::IInputInjector)->UninitializeTouchInjection());
}

template <typename D> void consume_Windows_UI_Input_Preview_Injection_IInputInjector<D>::InitializePenInjection(Windows::UI::Input::Preview::Injection::InjectedInputVisualizationMode const& visualMode) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Input::Preview::Injection::IInputInjector)->InitializePenInjection(get_abi(visualMode)));
}

template <typename D> void consume_Windows_UI_Input_Preview_Injection_IInputInjector<D>::InjectPenInput(Windows::UI::Input::Preview::Injection::InjectedInputPenInfo const& input) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Input::Preview::Injection::IInputInjector)->InjectPenInput(get_abi(input)));
}

template <typename D> void consume_Windows_UI_Input_Preview_Injection_IInputInjector<D>::UninitializePenInjection() const
{
    check_hresult(WINRT_SHIM(Windows::UI::Input::Preview::Injection::IInputInjector)->UninitializePenInjection());
}

template <typename D> void consume_Windows_UI_Input_Preview_Injection_IInputInjector<D>::InjectShortcut(Windows::UI::Input::Preview::Injection::InjectedInputShortcut const& shortcut) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Input::Preview::Injection::IInputInjector)->InjectShortcut(get_abi(shortcut)));
}

template <typename D> void consume_Windows_UI_Input_Preview_Injection_IInputInjector2<D>::InitializeGamepadInjection() const
{
    check_hresult(WINRT_SHIM(Windows::UI::Input::Preview::Injection::IInputInjector2)->InitializeGamepadInjection());
}

template <typename D> void consume_Windows_UI_Input_Preview_Injection_IInputInjector2<D>::InjectGamepadInput(Windows::UI::Input::Preview::Injection::InjectedInputGamepadInfo const& input) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Input::Preview::Injection::IInputInjector2)->InjectGamepadInput(get_abi(input)));
}

template <typename D> void consume_Windows_UI_Input_Preview_Injection_IInputInjector2<D>::UninitializeGamepadInjection() const
{
    check_hresult(WINRT_SHIM(Windows::UI::Input::Preview::Injection::IInputInjector2)->UninitializeGamepadInjection());
}

template <typename D> Windows::UI::Input::Preview::Injection::InputInjector consume_Windows_UI_Input_Preview_Injection_IInputInjectorStatics<D>::TryCreate() const
{
    Windows::UI::Input::Preview::Injection::InputInjector instance{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Input::Preview::Injection::IInputInjectorStatics)->TryCreate(put_abi(instance)));
    return instance;
}

template <typename D> Windows::UI::Input::Preview::Injection::InputInjector consume_Windows_UI_Input_Preview_Injection_IInputInjectorStatics2<D>::TryCreateForAppBroadcastOnly() const
{
    Windows::UI::Input::Preview::Injection::InputInjector instance{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Input::Preview::Injection::IInputInjectorStatics2)->TryCreateForAppBroadcastOnly(put_abi(instance)));
    return instance;
}

template <typename D>
struct produce<D, Windows::UI::Input::Preview::Injection::IInjectedInputGamepadInfo> : produce_base<D, Windows::UI::Input::Preview::Injection::IInjectedInputGamepadInfo>
{
    int32_t WINRT_CALL get_Buttons(Windows::Gaming::Input::GamepadButtons* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Buttons, WINRT_WRAP(Windows::Gaming::Input::GamepadButtons));
            *value = detach_from<Windows::Gaming::Input::GamepadButtons>(this->shim().Buttons());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_Buttons(Windows::Gaming::Input::GamepadButtons value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Buttons, WINRT_WRAP(void), Windows::Gaming::Input::GamepadButtons const&);
            this->shim().Buttons(*reinterpret_cast<Windows::Gaming::Input::GamepadButtons const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_LeftThumbstickX(double* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(LeftThumbstickX, WINRT_WRAP(double));
            *value = detach_from<double>(this->shim().LeftThumbstickX());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_LeftThumbstickX(double value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(LeftThumbstickX, WINRT_WRAP(void), double);
            this->shim().LeftThumbstickX(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_LeftThumbstickY(double* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(LeftThumbstickY, WINRT_WRAP(double));
            *value = detach_from<double>(this->shim().LeftThumbstickY());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_LeftThumbstickY(double value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(LeftThumbstickY, WINRT_WRAP(void), double);
            this->shim().LeftThumbstickY(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_LeftTrigger(double* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(LeftTrigger, WINRT_WRAP(double));
            *value = detach_from<double>(this->shim().LeftTrigger());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_LeftTrigger(double value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(LeftTrigger, WINRT_WRAP(void), double);
            this->shim().LeftTrigger(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_RightThumbstickX(double* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(RightThumbstickX, WINRT_WRAP(double));
            *value = detach_from<double>(this->shim().RightThumbstickX());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_RightThumbstickX(double value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(RightThumbstickX, WINRT_WRAP(void), double);
            this->shim().RightThumbstickX(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_RightThumbstickY(double* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(RightThumbstickY, WINRT_WRAP(double));
            *value = detach_from<double>(this->shim().RightThumbstickY());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_RightThumbstickY(double value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(RightThumbstickY, WINRT_WRAP(void), double);
            this->shim().RightThumbstickY(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_RightTrigger(double* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(RightTrigger, WINRT_WRAP(double));
            *value = detach_from<double>(this->shim().RightTrigger());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_RightTrigger(double value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(RightTrigger, WINRT_WRAP(void), double);
            this->shim().RightTrigger(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Input::Preview::Injection::IInjectedInputGamepadInfoFactory> : produce_base<D, Windows::UI::Input::Preview::Injection::IInjectedInputGamepadInfoFactory>
{
    int32_t WINRT_CALL CreateInstanceFromGamepadReading(struct struct_Windows_Gaming_Input_GamepadReading reading, void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CreateInstance, WINRT_WRAP(Windows::UI::Input::Preview::Injection::InjectedInputGamepadInfo), Windows::Gaming::Input::GamepadReading const&);
            *value = detach_from<Windows::UI::Input::Preview::Injection::InjectedInputGamepadInfo>(this->shim().CreateInstance(*reinterpret_cast<Windows::Gaming::Input::GamepadReading const*>(&reading)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Input::Preview::Injection::IInjectedInputKeyboardInfo> : produce_base<D, Windows::UI::Input::Preview::Injection::IInjectedInputKeyboardInfo>
{
    int32_t WINRT_CALL get_KeyOptions(Windows::UI::Input::Preview::Injection::InjectedInputKeyOptions* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(KeyOptions, WINRT_WRAP(Windows::UI::Input::Preview::Injection::InjectedInputKeyOptions));
            *value = detach_from<Windows::UI::Input::Preview::Injection::InjectedInputKeyOptions>(this->shim().KeyOptions());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_KeyOptions(Windows::UI::Input::Preview::Injection::InjectedInputKeyOptions value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(KeyOptions, WINRT_WRAP(void), Windows::UI::Input::Preview::Injection::InjectedInputKeyOptions const&);
            this->shim().KeyOptions(*reinterpret_cast<Windows::UI::Input::Preview::Injection::InjectedInputKeyOptions const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_ScanCode(uint16_t* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ScanCode, WINRT_WRAP(uint16_t));
            *value = detach_from<uint16_t>(this->shim().ScanCode());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_ScanCode(uint16_t value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ScanCode, WINRT_WRAP(void), uint16_t);
            this->shim().ScanCode(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_VirtualKey(uint16_t* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(VirtualKey, WINRT_WRAP(uint16_t));
            *value = detach_from<uint16_t>(this->shim().VirtualKey());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_VirtualKey(uint16_t value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(VirtualKey, WINRT_WRAP(void), uint16_t);
            this->shim().VirtualKey(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Input::Preview::Injection::IInjectedInputMouseInfo> : produce_base<D, Windows::UI::Input::Preview::Injection::IInjectedInputMouseInfo>
{
    int32_t WINRT_CALL get_MouseOptions(Windows::UI::Input::Preview::Injection::InjectedInputMouseOptions* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(MouseOptions, WINRT_WRAP(Windows::UI::Input::Preview::Injection::InjectedInputMouseOptions));
            *value = detach_from<Windows::UI::Input::Preview::Injection::InjectedInputMouseOptions>(this->shim().MouseOptions());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_MouseOptions(Windows::UI::Input::Preview::Injection::InjectedInputMouseOptions value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(MouseOptions, WINRT_WRAP(void), Windows::UI::Input::Preview::Injection::InjectedInputMouseOptions const&);
            this->shim().MouseOptions(*reinterpret_cast<Windows::UI::Input::Preview::Injection::InjectedInputMouseOptions const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_MouseData(uint32_t* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(MouseData, WINRT_WRAP(uint32_t));
            *value = detach_from<uint32_t>(this->shim().MouseData());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_MouseData(uint32_t value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(MouseData, WINRT_WRAP(void), uint32_t);
            this->shim().MouseData(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_DeltaY(int32_t* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(DeltaY, WINRT_WRAP(int32_t));
            *value = detach_from<int32_t>(this->shim().DeltaY());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_DeltaY(int32_t value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(DeltaY, WINRT_WRAP(void), int32_t);
            this->shim().DeltaY(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_DeltaX(int32_t* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(DeltaX, WINRT_WRAP(int32_t));
            *value = detach_from<int32_t>(this->shim().DeltaX());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_DeltaX(int32_t value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(DeltaX, WINRT_WRAP(void), int32_t);
            this->shim().DeltaX(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_TimeOffsetInMilliseconds(uint32_t* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(TimeOffsetInMilliseconds, WINRT_WRAP(uint32_t));
            *value = detach_from<uint32_t>(this->shim().TimeOffsetInMilliseconds());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_TimeOffsetInMilliseconds(uint32_t value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(TimeOffsetInMilliseconds, WINRT_WRAP(void), uint32_t);
            this->shim().TimeOffsetInMilliseconds(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Input::Preview::Injection::IInjectedInputPenInfo> : produce_base<D, Windows::UI::Input::Preview::Injection::IInjectedInputPenInfo>
{
    int32_t WINRT_CALL get_PointerInfo(struct struct_Windows_UI_Input_Preview_Injection_InjectedInputPointerInfo* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(PointerInfo, WINRT_WRAP(Windows::UI::Input::Preview::Injection::InjectedInputPointerInfo));
            *value = detach_from<Windows::UI::Input::Preview::Injection::InjectedInputPointerInfo>(this->shim().PointerInfo());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_PointerInfo(struct struct_Windows_UI_Input_Preview_Injection_InjectedInputPointerInfo value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(PointerInfo, WINRT_WRAP(void), Windows::UI::Input::Preview::Injection::InjectedInputPointerInfo const&);
            this->shim().PointerInfo(*reinterpret_cast<Windows::UI::Input::Preview::Injection::InjectedInputPointerInfo const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_PenButtons(Windows::UI::Input::Preview::Injection::InjectedInputPenButtons* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(PenButtons, WINRT_WRAP(Windows::UI::Input::Preview::Injection::InjectedInputPenButtons));
            *value = detach_from<Windows::UI::Input::Preview::Injection::InjectedInputPenButtons>(this->shim().PenButtons());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_PenButtons(Windows::UI::Input::Preview::Injection::InjectedInputPenButtons value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(PenButtons, WINRT_WRAP(void), Windows::UI::Input::Preview::Injection::InjectedInputPenButtons const&);
            this->shim().PenButtons(*reinterpret_cast<Windows::UI::Input::Preview::Injection::InjectedInputPenButtons const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_PenParameters(Windows::UI::Input::Preview::Injection::InjectedInputPenParameters* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(PenParameters, WINRT_WRAP(Windows::UI::Input::Preview::Injection::InjectedInputPenParameters));
            *value = detach_from<Windows::UI::Input::Preview::Injection::InjectedInputPenParameters>(this->shim().PenParameters());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_PenParameters(Windows::UI::Input::Preview::Injection::InjectedInputPenParameters value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(PenParameters, WINRT_WRAP(void), Windows::UI::Input::Preview::Injection::InjectedInputPenParameters const&);
            this->shim().PenParameters(*reinterpret_cast<Windows::UI::Input::Preview::Injection::InjectedInputPenParameters const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Pressure(double* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Pressure, WINRT_WRAP(double));
            *value = detach_from<double>(this->shim().Pressure());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_Pressure(double value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Pressure, WINRT_WRAP(void), double);
            this->shim().Pressure(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Rotation(double* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Rotation, WINRT_WRAP(double));
            *value = detach_from<double>(this->shim().Rotation());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_Rotation(double value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Rotation, WINRT_WRAP(void), double);
            this->shim().Rotation(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_TiltX(int32_t* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(TiltX, WINRT_WRAP(int32_t));
            *value = detach_from<int32_t>(this->shim().TiltX());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_TiltX(int32_t value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(TiltX, WINRT_WRAP(void), int32_t);
            this->shim().TiltX(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_TiltY(int32_t* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(TiltY, WINRT_WRAP(int32_t));
            *value = detach_from<int32_t>(this->shim().TiltY());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_TiltY(int32_t value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(TiltY, WINRT_WRAP(void), int32_t);
            this->shim().TiltY(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Input::Preview::Injection::IInjectedInputTouchInfo> : produce_base<D, Windows::UI::Input::Preview::Injection::IInjectedInputTouchInfo>
{
    int32_t WINRT_CALL get_Contact(struct struct_Windows_UI_Input_Preview_Injection_InjectedInputRectangle* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Contact, WINRT_WRAP(Windows::UI::Input::Preview::Injection::InjectedInputRectangle));
            *value = detach_from<Windows::UI::Input::Preview::Injection::InjectedInputRectangle>(this->shim().Contact());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_Contact(struct struct_Windows_UI_Input_Preview_Injection_InjectedInputRectangle value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Contact, WINRT_WRAP(void), Windows::UI::Input::Preview::Injection::InjectedInputRectangle const&);
            this->shim().Contact(*reinterpret_cast<Windows::UI::Input::Preview::Injection::InjectedInputRectangle const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Orientation(int32_t* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Orientation, WINRT_WRAP(int32_t));
            *value = detach_from<int32_t>(this->shim().Orientation());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_Orientation(int32_t value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Orientation, WINRT_WRAP(void), int32_t);
            this->shim().Orientation(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_PointerInfo(struct struct_Windows_UI_Input_Preview_Injection_InjectedInputPointerInfo* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(PointerInfo, WINRT_WRAP(Windows::UI::Input::Preview::Injection::InjectedInputPointerInfo));
            *value = detach_from<Windows::UI::Input::Preview::Injection::InjectedInputPointerInfo>(this->shim().PointerInfo());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_PointerInfo(struct struct_Windows_UI_Input_Preview_Injection_InjectedInputPointerInfo value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(PointerInfo, WINRT_WRAP(void), Windows::UI::Input::Preview::Injection::InjectedInputPointerInfo const&);
            this->shim().PointerInfo(*reinterpret_cast<Windows::UI::Input::Preview::Injection::InjectedInputPointerInfo const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Pressure(double* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Pressure, WINRT_WRAP(double));
            *value = detach_from<double>(this->shim().Pressure());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_Pressure(double value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Pressure, WINRT_WRAP(void), double);
            this->shim().Pressure(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_TouchParameters(Windows::UI::Input::Preview::Injection::InjectedInputTouchParameters* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(TouchParameters, WINRT_WRAP(Windows::UI::Input::Preview::Injection::InjectedInputTouchParameters));
            *value = detach_from<Windows::UI::Input::Preview::Injection::InjectedInputTouchParameters>(this->shim().TouchParameters());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_TouchParameters(Windows::UI::Input::Preview::Injection::InjectedInputTouchParameters value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(TouchParameters, WINRT_WRAP(void), Windows::UI::Input::Preview::Injection::InjectedInputTouchParameters const&);
            this->shim().TouchParameters(*reinterpret_cast<Windows::UI::Input::Preview::Injection::InjectedInputTouchParameters const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Input::Preview::Injection::IInputInjector> : produce_base<D, Windows::UI::Input::Preview::Injection::IInputInjector>
{
    int32_t WINRT_CALL InjectKeyboardInput(void* input) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(InjectKeyboardInput, WINRT_WRAP(void), Windows::Foundation::Collections::IIterable<Windows::UI::Input::Preview::Injection::InjectedInputKeyboardInfo> const&);
            this->shim().InjectKeyboardInput(*reinterpret_cast<Windows::Foundation::Collections::IIterable<Windows::UI::Input::Preview::Injection::InjectedInputKeyboardInfo> const*>(&input));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL InjectMouseInput(void* input) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(InjectMouseInput, WINRT_WRAP(void), Windows::Foundation::Collections::IIterable<Windows::UI::Input::Preview::Injection::InjectedInputMouseInfo> const&);
            this->shim().InjectMouseInput(*reinterpret_cast<Windows::Foundation::Collections::IIterable<Windows::UI::Input::Preview::Injection::InjectedInputMouseInfo> const*>(&input));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL InitializeTouchInjection(Windows::UI::Input::Preview::Injection::InjectedInputVisualizationMode visualMode) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(InitializeTouchInjection, WINRT_WRAP(void), Windows::UI::Input::Preview::Injection::InjectedInputVisualizationMode const&);
            this->shim().InitializeTouchInjection(*reinterpret_cast<Windows::UI::Input::Preview::Injection::InjectedInputVisualizationMode const*>(&visualMode));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL InjectTouchInput(void* input) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(InjectTouchInput, WINRT_WRAP(void), Windows::Foundation::Collections::IIterable<Windows::UI::Input::Preview::Injection::InjectedInputTouchInfo> const&);
            this->shim().InjectTouchInput(*reinterpret_cast<Windows::Foundation::Collections::IIterable<Windows::UI::Input::Preview::Injection::InjectedInputTouchInfo> const*>(&input));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL UninitializeTouchInjection() noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(UninitializeTouchInjection, WINRT_WRAP(void));
            this->shim().UninitializeTouchInjection();
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL InitializePenInjection(Windows::UI::Input::Preview::Injection::InjectedInputVisualizationMode visualMode) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(InitializePenInjection, WINRT_WRAP(void), Windows::UI::Input::Preview::Injection::InjectedInputVisualizationMode const&);
            this->shim().InitializePenInjection(*reinterpret_cast<Windows::UI::Input::Preview::Injection::InjectedInputVisualizationMode const*>(&visualMode));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL InjectPenInput(void* input) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(InjectPenInput, WINRT_WRAP(void), Windows::UI::Input::Preview::Injection::InjectedInputPenInfo const&);
            this->shim().InjectPenInput(*reinterpret_cast<Windows::UI::Input::Preview::Injection::InjectedInputPenInfo const*>(&input));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL UninitializePenInjection() noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(UninitializePenInjection, WINRT_WRAP(void));
            this->shim().UninitializePenInjection();
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL InjectShortcut(Windows::UI::Input::Preview::Injection::InjectedInputShortcut shortcut) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(InjectShortcut, WINRT_WRAP(void), Windows::UI::Input::Preview::Injection::InjectedInputShortcut const&);
            this->shim().InjectShortcut(*reinterpret_cast<Windows::UI::Input::Preview::Injection::InjectedInputShortcut const*>(&shortcut));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Input::Preview::Injection::IInputInjector2> : produce_base<D, Windows::UI::Input::Preview::Injection::IInputInjector2>
{
    int32_t WINRT_CALL InitializeGamepadInjection() noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(InitializeGamepadInjection, WINRT_WRAP(void));
            this->shim().InitializeGamepadInjection();
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL InjectGamepadInput(void* input) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(InjectGamepadInput, WINRT_WRAP(void), Windows::UI::Input::Preview::Injection::InjectedInputGamepadInfo const&);
            this->shim().InjectGamepadInput(*reinterpret_cast<Windows::UI::Input::Preview::Injection::InjectedInputGamepadInfo const*>(&input));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL UninitializeGamepadInjection() noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(UninitializeGamepadInjection, WINRT_WRAP(void));
            this->shim().UninitializeGamepadInjection();
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Input::Preview::Injection::IInputInjectorStatics> : produce_base<D, Windows::UI::Input::Preview::Injection::IInputInjectorStatics>
{
    int32_t WINRT_CALL TryCreate(void** instance) noexcept final
    {
        try
        {
            *instance = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(TryCreate, WINRT_WRAP(Windows::UI::Input::Preview::Injection::InputInjector));
            *instance = detach_from<Windows::UI::Input::Preview::Injection::InputInjector>(this->shim().TryCreate());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Input::Preview::Injection::IInputInjectorStatics2> : produce_base<D, Windows::UI::Input::Preview::Injection::IInputInjectorStatics2>
{
    int32_t WINRT_CALL TryCreateForAppBroadcastOnly(void** instance) noexcept final
    {
        try
        {
            *instance = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(TryCreateForAppBroadcastOnly, WINRT_WRAP(Windows::UI::Input::Preview::Injection::InputInjector));
            *instance = detach_from<Windows::UI::Input::Preview::Injection::InputInjector>(this->shim().TryCreateForAppBroadcastOnly());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

}

WINRT_EXPORT namespace winrt::Windows::UI::Input::Preview::Injection {

inline InjectedInputGamepadInfo::InjectedInputGamepadInfo() :
    InjectedInputGamepadInfo(impl::call_factory<InjectedInputGamepadInfo>([](auto&& f) { return f.template ActivateInstance<InjectedInputGamepadInfo>(); }))
{}

inline InjectedInputGamepadInfo::InjectedInputGamepadInfo(Windows::Gaming::Input::GamepadReading const& reading) :
    InjectedInputGamepadInfo(impl::call_factory<InjectedInputGamepadInfo, Windows::UI::Input::Preview::Injection::IInjectedInputGamepadInfoFactory>([&](auto&& f) { return f.CreateInstance(reading); }))
{}

inline InjectedInputKeyboardInfo::InjectedInputKeyboardInfo() :
    InjectedInputKeyboardInfo(impl::call_factory<InjectedInputKeyboardInfo>([](auto&& f) { return f.template ActivateInstance<InjectedInputKeyboardInfo>(); }))
{}

inline InjectedInputMouseInfo::InjectedInputMouseInfo() :
    InjectedInputMouseInfo(impl::call_factory<InjectedInputMouseInfo>([](auto&& f) { return f.template ActivateInstance<InjectedInputMouseInfo>(); }))
{}

inline InjectedInputPenInfo::InjectedInputPenInfo() :
    InjectedInputPenInfo(impl::call_factory<InjectedInputPenInfo>([](auto&& f) { return f.template ActivateInstance<InjectedInputPenInfo>(); }))
{}

inline InjectedInputTouchInfo::InjectedInputTouchInfo() :
    InjectedInputTouchInfo(impl::call_factory<InjectedInputTouchInfo>([](auto&& f) { return f.template ActivateInstance<InjectedInputTouchInfo>(); }))
{}

inline Windows::UI::Input::Preview::Injection::InputInjector InputInjector::TryCreate()
{
    return impl::call_factory<InputInjector, Windows::UI::Input::Preview::Injection::IInputInjectorStatics>([&](auto&& f) { return f.TryCreate(); });
}

inline Windows::UI::Input::Preview::Injection::InputInjector InputInjector::TryCreateForAppBroadcastOnly()
{
    return impl::call_factory<InputInjector, Windows::UI::Input::Preview::Injection::IInputInjectorStatics2>([&](auto&& f) { return f.TryCreateForAppBroadcastOnly(); });
}

}

WINRT_EXPORT namespace std {

template<> struct hash<winrt::Windows::UI::Input::Preview::Injection::IInjectedInputGamepadInfo> : winrt::impl::hash_base<winrt::Windows::UI::Input::Preview::Injection::IInjectedInputGamepadInfo> {};
template<> struct hash<winrt::Windows::UI::Input::Preview::Injection::IInjectedInputGamepadInfoFactory> : winrt::impl::hash_base<winrt::Windows::UI::Input::Preview::Injection::IInjectedInputGamepadInfoFactory> {};
template<> struct hash<winrt::Windows::UI::Input::Preview::Injection::IInjectedInputKeyboardInfo> : winrt::impl::hash_base<winrt::Windows::UI::Input::Preview::Injection::IInjectedInputKeyboardInfo> {};
template<> struct hash<winrt::Windows::UI::Input::Preview::Injection::IInjectedInputMouseInfo> : winrt::impl::hash_base<winrt::Windows::UI::Input::Preview::Injection::IInjectedInputMouseInfo> {};
template<> struct hash<winrt::Windows::UI::Input::Preview::Injection::IInjectedInputPenInfo> : winrt::impl::hash_base<winrt::Windows::UI::Input::Preview::Injection::IInjectedInputPenInfo> {};
template<> struct hash<winrt::Windows::UI::Input::Preview::Injection::IInjectedInputTouchInfo> : winrt::impl::hash_base<winrt::Windows::UI::Input::Preview::Injection::IInjectedInputTouchInfo> {};
template<> struct hash<winrt::Windows::UI::Input::Preview::Injection::IInputInjector> : winrt::impl::hash_base<winrt::Windows::UI::Input::Preview::Injection::IInputInjector> {};
template<> struct hash<winrt::Windows::UI::Input::Preview::Injection::IInputInjector2> : winrt::impl::hash_base<winrt::Windows::UI::Input::Preview::Injection::IInputInjector2> {};
template<> struct hash<winrt::Windows::UI::Input::Preview::Injection::IInputInjectorStatics> : winrt::impl::hash_base<winrt::Windows::UI::Input::Preview::Injection::IInputInjectorStatics> {};
template<> struct hash<winrt::Windows::UI::Input::Preview::Injection::IInputInjectorStatics2> : winrt::impl::hash_base<winrt::Windows::UI::Input::Preview::Injection::IInputInjectorStatics2> {};
template<> struct hash<winrt::Windows::UI::Input::Preview::Injection::InjectedInputGamepadInfo> : winrt::impl::hash_base<winrt::Windows::UI::Input::Preview::Injection::InjectedInputGamepadInfo> {};
template<> struct hash<winrt::Windows::UI::Input::Preview::Injection::InjectedInputKeyboardInfo> : winrt::impl::hash_base<winrt::Windows::UI::Input::Preview::Injection::InjectedInputKeyboardInfo> {};
template<> struct hash<winrt::Windows::UI::Input::Preview::Injection::InjectedInputMouseInfo> : winrt::impl::hash_base<winrt::Windows::UI::Input::Preview::Injection::InjectedInputMouseInfo> {};
template<> struct hash<winrt::Windows::UI::Input::Preview::Injection::InjectedInputPenInfo> : winrt::impl::hash_base<winrt::Windows::UI::Input::Preview::Injection::InjectedInputPenInfo> {};
template<> struct hash<winrt::Windows::UI::Input::Preview::Injection::InjectedInputTouchInfo> : winrt::impl::hash_base<winrt::Windows::UI::Input::Preview::Injection::InjectedInputTouchInfo> {};
template<> struct hash<winrt::Windows::UI::Input::Preview::Injection::InputInjector> : winrt::impl::hash_base<winrt::Windows::UI::Input::Preview::Injection::InputInjector> {};

}
