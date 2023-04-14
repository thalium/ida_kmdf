// C++/WinRT v1.0.190111.3

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#pragma once

#include "winrt/base.h"

#include "winrt/Windows.Foundation.h"
#include "winrt/Windows.Foundation.Collections.h"
#include "winrt/impl/Windows.Devices.Haptics.2.h"
#include "winrt/impl/Windows.Devices.Power.2.h"
#include "winrt/impl/Windows.Gaming.Input.ForceFeedback.2.h"
#include "winrt/impl/Windows.System.2.h"
#include "winrt/impl/Windows.Gaming.Input.2.h"

namespace winrt::impl {

template <typename D> Windows::Gaming::Input::GameControllerButtonLabel consume_Windows_Gaming_Input_IArcadeStick<D>::GetButtonLabel(Windows::Gaming::Input::ArcadeStickButtons const& button) const
{
    Windows::Gaming::Input::GameControllerButtonLabel value{};
    check_hresult(WINRT_SHIM(Windows::Gaming::Input::IArcadeStick)->GetButtonLabel(get_abi(button), put_abi(value)));
    return value;
}

template <typename D> Windows::Gaming::Input::ArcadeStickReading consume_Windows_Gaming_Input_IArcadeStick<D>::GetCurrentReading() const
{
    Windows::Gaming::Input::ArcadeStickReading value{};
    check_hresult(WINRT_SHIM(Windows::Gaming::Input::IArcadeStick)->GetCurrentReading(put_abi(value)));
    return value;
}

template <typename D> winrt::event_token consume_Windows_Gaming_Input_IArcadeStickStatics<D>::ArcadeStickAdded(Windows::Foundation::EventHandler<Windows::Gaming::Input::ArcadeStick> const& value) const
{
    winrt::event_token token{};
    check_hresult(WINRT_SHIM(Windows::Gaming::Input::IArcadeStickStatics)->add_ArcadeStickAdded(get_abi(value), put_abi(token)));
    return token;
}

template <typename D> typename consume_Windows_Gaming_Input_IArcadeStickStatics<D>::ArcadeStickAdded_revoker consume_Windows_Gaming_Input_IArcadeStickStatics<D>::ArcadeStickAdded(auto_revoke_t, Windows::Foundation::EventHandler<Windows::Gaming::Input::ArcadeStick> const& value) const
{
    return impl::make_event_revoker<D, ArcadeStickAdded_revoker>(this, ArcadeStickAdded(value));
}

template <typename D> void consume_Windows_Gaming_Input_IArcadeStickStatics<D>::ArcadeStickAdded(winrt::event_token const& token) const noexcept
{
    WINRT_VERIFY_(0, WINRT_SHIM(Windows::Gaming::Input::IArcadeStickStatics)->remove_ArcadeStickAdded(get_abi(token)));
}

template <typename D> winrt::event_token consume_Windows_Gaming_Input_IArcadeStickStatics<D>::ArcadeStickRemoved(Windows::Foundation::EventHandler<Windows::Gaming::Input::ArcadeStick> const& value) const
{
    winrt::event_token token{};
    check_hresult(WINRT_SHIM(Windows::Gaming::Input::IArcadeStickStatics)->add_ArcadeStickRemoved(get_abi(value), put_abi(token)));
    return token;
}

template <typename D> typename consume_Windows_Gaming_Input_IArcadeStickStatics<D>::ArcadeStickRemoved_revoker consume_Windows_Gaming_Input_IArcadeStickStatics<D>::ArcadeStickRemoved(auto_revoke_t, Windows::Foundation::EventHandler<Windows::Gaming::Input::ArcadeStick> const& value) const
{
    return impl::make_event_revoker<D, ArcadeStickRemoved_revoker>(this, ArcadeStickRemoved(value));
}

template <typename D> void consume_Windows_Gaming_Input_IArcadeStickStatics<D>::ArcadeStickRemoved(winrt::event_token const& token) const noexcept
{
    WINRT_VERIFY_(0, WINRT_SHIM(Windows::Gaming::Input::IArcadeStickStatics)->remove_ArcadeStickRemoved(get_abi(token)));
}

template <typename D> Windows::Foundation::Collections::IVectorView<Windows::Gaming::Input::ArcadeStick> consume_Windows_Gaming_Input_IArcadeStickStatics<D>::ArcadeSticks() const
{
    Windows::Foundation::Collections::IVectorView<Windows::Gaming::Input::ArcadeStick> value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Gaming::Input::IArcadeStickStatics)->get_ArcadeSticks(put_abi(value)));
    return value;
}

template <typename D> Windows::Gaming::Input::ArcadeStick consume_Windows_Gaming_Input_IArcadeStickStatics2<D>::FromGameController(Windows::Gaming::Input::IGameController const& gameController) const
{
    Windows::Gaming::Input::ArcadeStick value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Gaming::Input::IArcadeStickStatics2)->FromGameController(get_abi(gameController), put_abi(value)));
    return value;
}

template <typename D> Windows::Gaming::Input::GameControllerSwitchKind consume_Windows_Gaming_Input_IFlightStick<D>::HatSwitchKind() const
{
    Windows::Gaming::Input::GameControllerSwitchKind value{};
    check_hresult(WINRT_SHIM(Windows::Gaming::Input::IFlightStick)->get_HatSwitchKind(put_abi(value)));
    return value;
}

template <typename D> Windows::Gaming::Input::GameControllerButtonLabel consume_Windows_Gaming_Input_IFlightStick<D>::GetButtonLabel(Windows::Gaming::Input::FlightStickButtons const& button) const
{
    Windows::Gaming::Input::GameControllerButtonLabel value{};
    check_hresult(WINRT_SHIM(Windows::Gaming::Input::IFlightStick)->GetButtonLabel(get_abi(button), put_abi(value)));
    return value;
}

template <typename D> Windows::Gaming::Input::FlightStickReading consume_Windows_Gaming_Input_IFlightStick<D>::GetCurrentReading() const
{
    Windows::Gaming::Input::FlightStickReading value{};
    check_hresult(WINRT_SHIM(Windows::Gaming::Input::IFlightStick)->GetCurrentReading(put_abi(value)));
    return value;
}

template <typename D> winrt::event_token consume_Windows_Gaming_Input_IFlightStickStatics<D>::FlightStickAdded(Windows::Foundation::EventHandler<Windows::Gaming::Input::FlightStick> const& value) const
{
    winrt::event_token token{};
    check_hresult(WINRT_SHIM(Windows::Gaming::Input::IFlightStickStatics)->add_FlightStickAdded(get_abi(value), put_abi(token)));
    return token;
}

template <typename D> typename consume_Windows_Gaming_Input_IFlightStickStatics<D>::FlightStickAdded_revoker consume_Windows_Gaming_Input_IFlightStickStatics<D>::FlightStickAdded(auto_revoke_t, Windows::Foundation::EventHandler<Windows::Gaming::Input::FlightStick> const& value) const
{
    return impl::make_event_revoker<D, FlightStickAdded_revoker>(this, FlightStickAdded(value));
}

template <typename D> void consume_Windows_Gaming_Input_IFlightStickStatics<D>::FlightStickAdded(winrt::event_token const& token) const noexcept
{
    WINRT_VERIFY_(0, WINRT_SHIM(Windows::Gaming::Input::IFlightStickStatics)->remove_FlightStickAdded(get_abi(token)));
}

template <typename D> winrt::event_token consume_Windows_Gaming_Input_IFlightStickStatics<D>::FlightStickRemoved(Windows::Foundation::EventHandler<Windows::Gaming::Input::FlightStick> const& value) const
{
    winrt::event_token token{};
    check_hresult(WINRT_SHIM(Windows::Gaming::Input::IFlightStickStatics)->add_FlightStickRemoved(get_abi(value), put_abi(token)));
    return token;
}

template <typename D> typename consume_Windows_Gaming_Input_IFlightStickStatics<D>::FlightStickRemoved_revoker consume_Windows_Gaming_Input_IFlightStickStatics<D>::FlightStickRemoved(auto_revoke_t, Windows::Foundation::EventHandler<Windows::Gaming::Input::FlightStick> const& value) const
{
    return impl::make_event_revoker<D, FlightStickRemoved_revoker>(this, FlightStickRemoved(value));
}

template <typename D> void consume_Windows_Gaming_Input_IFlightStickStatics<D>::FlightStickRemoved(winrt::event_token const& token) const noexcept
{
    WINRT_VERIFY_(0, WINRT_SHIM(Windows::Gaming::Input::IFlightStickStatics)->remove_FlightStickRemoved(get_abi(token)));
}

template <typename D> Windows::Foundation::Collections::IVectorView<Windows::Gaming::Input::FlightStick> consume_Windows_Gaming_Input_IFlightStickStatics<D>::FlightSticks() const
{
    Windows::Foundation::Collections::IVectorView<Windows::Gaming::Input::FlightStick> value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Gaming::Input::IFlightStickStatics)->get_FlightSticks(put_abi(value)));
    return value;
}

template <typename D> Windows::Gaming::Input::FlightStick consume_Windows_Gaming_Input_IFlightStickStatics<D>::FromGameController(Windows::Gaming::Input::IGameController const& gameController) const
{
    Windows::Gaming::Input::FlightStick value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Gaming::Input::IFlightStickStatics)->FromGameController(get_abi(gameController), put_abi(value)));
    return value;
}

template <typename D> winrt::event_token consume_Windows_Gaming_Input_IGameController<D>::HeadsetConnected(Windows::Foundation::TypedEventHandler<Windows::Gaming::Input::IGameController, Windows::Gaming::Input::Headset> const& value) const
{
    winrt::event_token token{};
    check_hresult(WINRT_SHIM(Windows::Gaming::Input::IGameController)->add_HeadsetConnected(get_abi(value), put_abi(token)));
    return token;
}

template <typename D> typename consume_Windows_Gaming_Input_IGameController<D>::HeadsetConnected_revoker consume_Windows_Gaming_Input_IGameController<D>::HeadsetConnected(auto_revoke_t, Windows::Foundation::TypedEventHandler<Windows::Gaming::Input::IGameController, Windows::Gaming::Input::Headset> const& value) const
{
    return impl::make_event_revoker<D, HeadsetConnected_revoker>(this, HeadsetConnected(value));
}

template <typename D> void consume_Windows_Gaming_Input_IGameController<D>::HeadsetConnected(winrt::event_token const& token) const noexcept
{
    WINRT_VERIFY_(0, WINRT_SHIM(Windows::Gaming::Input::IGameController)->remove_HeadsetConnected(get_abi(token)));
}

template <typename D> winrt::event_token consume_Windows_Gaming_Input_IGameController<D>::HeadsetDisconnected(Windows::Foundation::TypedEventHandler<Windows::Gaming::Input::IGameController, Windows::Gaming::Input::Headset> const& value) const
{
    winrt::event_token token{};
    check_hresult(WINRT_SHIM(Windows::Gaming::Input::IGameController)->add_HeadsetDisconnected(get_abi(value), put_abi(token)));
    return token;
}

template <typename D> typename consume_Windows_Gaming_Input_IGameController<D>::HeadsetDisconnected_revoker consume_Windows_Gaming_Input_IGameController<D>::HeadsetDisconnected(auto_revoke_t, Windows::Foundation::TypedEventHandler<Windows::Gaming::Input::IGameController, Windows::Gaming::Input::Headset> const& value) const
{
    return impl::make_event_revoker<D, HeadsetDisconnected_revoker>(this, HeadsetDisconnected(value));
}

template <typename D> void consume_Windows_Gaming_Input_IGameController<D>::HeadsetDisconnected(winrt::event_token const& token) const noexcept
{
    WINRT_VERIFY_(0, WINRT_SHIM(Windows::Gaming::Input::IGameController)->remove_HeadsetDisconnected(get_abi(token)));
}

template <typename D> winrt::event_token consume_Windows_Gaming_Input_IGameController<D>::UserChanged(Windows::Foundation::TypedEventHandler<Windows::Gaming::Input::IGameController, Windows::System::UserChangedEventArgs> const& value) const
{
    winrt::event_token token{};
    check_hresult(WINRT_SHIM(Windows::Gaming::Input::IGameController)->add_UserChanged(get_abi(value), put_abi(token)));
    return token;
}

template <typename D> typename consume_Windows_Gaming_Input_IGameController<D>::UserChanged_revoker consume_Windows_Gaming_Input_IGameController<D>::UserChanged(auto_revoke_t, Windows::Foundation::TypedEventHandler<Windows::Gaming::Input::IGameController, Windows::System::UserChangedEventArgs> const& value) const
{
    return impl::make_event_revoker<D, UserChanged_revoker>(this, UserChanged(value));
}

template <typename D> void consume_Windows_Gaming_Input_IGameController<D>::UserChanged(winrt::event_token const& token) const noexcept
{
    WINRT_VERIFY_(0, WINRT_SHIM(Windows::Gaming::Input::IGameController)->remove_UserChanged(get_abi(token)));
}

template <typename D> Windows::Gaming::Input::Headset consume_Windows_Gaming_Input_IGameController<D>::Headset() const
{
    Windows::Gaming::Input::Headset value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Gaming::Input::IGameController)->get_Headset(put_abi(value)));
    return value;
}

template <typename D> bool consume_Windows_Gaming_Input_IGameController<D>::IsWireless() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::Gaming::Input::IGameController)->get_IsWireless(&value));
    return value;
}

template <typename D> Windows::System::User consume_Windows_Gaming_Input_IGameController<D>::User() const
{
    Windows::System::User value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Gaming::Input::IGameController)->get_User(put_abi(value)));
    return value;
}

template <typename D> Windows::Devices::Power::BatteryReport consume_Windows_Gaming_Input_IGameControllerBatteryInfo<D>::TryGetBatteryReport() const
{
    Windows::Devices::Power::BatteryReport value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Gaming::Input::IGameControllerBatteryInfo)->TryGetBatteryReport(put_abi(value)));
    return value;
}

template <typename D> Windows::Gaming::Input::GamepadVibration consume_Windows_Gaming_Input_IGamepad<D>::Vibration() const
{
    Windows::Gaming::Input::GamepadVibration value{};
    check_hresult(WINRT_SHIM(Windows::Gaming::Input::IGamepad)->get_Vibration(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_Gaming_Input_IGamepad<D>::Vibration(Windows::Gaming::Input::GamepadVibration const& value) const
{
    check_hresult(WINRT_SHIM(Windows::Gaming::Input::IGamepad)->put_Vibration(get_abi(value)));
}

template <typename D> Windows::Gaming::Input::GamepadReading consume_Windows_Gaming_Input_IGamepad<D>::GetCurrentReading() const
{
    Windows::Gaming::Input::GamepadReading value{};
    check_hresult(WINRT_SHIM(Windows::Gaming::Input::IGamepad)->GetCurrentReading(put_abi(value)));
    return value;
}

template <typename D> Windows::Gaming::Input::GameControllerButtonLabel consume_Windows_Gaming_Input_IGamepad2<D>::GetButtonLabel(Windows::Gaming::Input::GamepadButtons const& button) const
{
    Windows::Gaming::Input::GameControllerButtonLabel value{};
    check_hresult(WINRT_SHIM(Windows::Gaming::Input::IGamepad2)->GetButtonLabel(get_abi(button), put_abi(value)));
    return value;
}

template <typename D> winrt::event_token consume_Windows_Gaming_Input_IGamepadStatics<D>::GamepadAdded(Windows::Foundation::EventHandler<Windows::Gaming::Input::Gamepad> const& value) const
{
    winrt::event_token token{};
    check_hresult(WINRT_SHIM(Windows::Gaming::Input::IGamepadStatics)->add_GamepadAdded(get_abi(value), put_abi(token)));
    return token;
}

template <typename D> typename consume_Windows_Gaming_Input_IGamepadStatics<D>::GamepadAdded_revoker consume_Windows_Gaming_Input_IGamepadStatics<D>::GamepadAdded(auto_revoke_t, Windows::Foundation::EventHandler<Windows::Gaming::Input::Gamepad> const& value) const
{
    return impl::make_event_revoker<D, GamepadAdded_revoker>(this, GamepadAdded(value));
}

template <typename D> void consume_Windows_Gaming_Input_IGamepadStatics<D>::GamepadAdded(winrt::event_token const& token) const noexcept
{
    WINRT_VERIFY_(0, WINRT_SHIM(Windows::Gaming::Input::IGamepadStatics)->remove_GamepadAdded(get_abi(token)));
}

template <typename D> winrt::event_token consume_Windows_Gaming_Input_IGamepadStatics<D>::GamepadRemoved(Windows::Foundation::EventHandler<Windows::Gaming::Input::Gamepad> const& value) const
{
    winrt::event_token token{};
    check_hresult(WINRT_SHIM(Windows::Gaming::Input::IGamepadStatics)->add_GamepadRemoved(get_abi(value), put_abi(token)));
    return token;
}

template <typename D> typename consume_Windows_Gaming_Input_IGamepadStatics<D>::GamepadRemoved_revoker consume_Windows_Gaming_Input_IGamepadStatics<D>::GamepadRemoved(auto_revoke_t, Windows::Foundation::EventHandler<Windows::Gaming::Input::Gamepad> const& value) const
{
    return impl::make_event_revoker<D, GamepadRemoved_revoker>(this, GamepadRemoved(value));
}

template <typename D> void consume_Windows_Gaming_Input_IGamepadStatics<D>::GamepadRemoved(winrt::event_token const& token) const noexcept
{
    WINRT_VERIFY_(0, WINRT_SHIM(Windows::Gaming::Input::IGamepadStatics)->remove_GamepadRemoved(get_abi(token)));
}

template <typename D> Windows::Foundation::Collections::IVectorView<Windows::Gaming::Input::Gamepad> consume_Windows_Gaming_Input_IGamepadStatics<D>::Gamepads() const
{
    Windows::Foundation::Collections::IVectorView<Windows::Gaming::Input::Gamepad> value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Gaming::Input::IGamepadStatics)->get_Gamepads(put_abi(value)));
    return value;
}

template <typename D> Windows::Gaming::Input::Gamepad consume_Windows_Gaming_Input_IGamepadStatics2<D>::FromGameController(Windows::Gaming::Input::IGameController const& gameController) const
{
    Windows::Gaming::Input::Gamepad value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Gaming::Input::IGamepadStatics2)->FromGameController(get_abi(gameController), put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_Gaming_Input_IHeadset<D>::CaptureDeviceId() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Gaming::Input::IHeadset)->get_CaptureDeviceId(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_Gaming_Input_IHeadset<D>::RenderDeviceId() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Gaming::Input::IHeadset)->get_RenderDeviceId(put_abi(value)));
    return value;
}

template <typename D> bool consume_Windows_Gaming_Input_IRacingWheel<D>::HasClutch() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::Gaming::Input::IRacingWheel)->get_HasClutch(&value));
    return value;
}

template <typename D> bool consume_Windows_Gaming_Input_IRacingWheel<D>::HasHandbrake() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::Gaming::Input::IRacingWheel)->get_HasHandbrake(&value));
    return value;
}

template <typename D> bool consume_Windows_Gaming_Input_IRacingWheel<D>::HasPatternShifter() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::Gaming::Input::IRacingWheel)->get_HasPatternShifter(&value));
    return value;
}

template <typename D> int32_t consume_Windows_Gaming_Input_IRacingWheel<D>::MaxPatternShifterGear() const
{
    int32_t value{};
    check_hresult(WINRT_SHIM(Windows::Gaming::Input::IRacingWheel)->get_MaxPatternShifterGear(&value));
    return value;
}

template <typename D> double consume_Windows_Gaming_Input_IRacingWheel<D>::MaxWheelAngle() const
{
    double value{};
    check_hresult(WINRT_SHIM(Windows::Gaming::Input::IRacingWheel)->get_MaxWheelAngle(&value));
    return value;
}

template <typename D> Windows::Gaming::Input::ForceFeedback::ForceFeedbackMotor consume_Windows_Gaming_Input_IRacingWheel<D>::WheelMotor() const
{
    Windows::Gaming::Input::ForceFeedback::ForceFeedbackMotor value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Gaming::Input::IRacingWheel)->get_WheelMotor(put_abi(value)));
    return value;
}

template <typename D> Windows::Gaming::Input::GameControllerButtonLabel consume_Windows_Gaming_Input_IRacingWheel<D>::GetButtonLabel(Windows::Gaming::Input::RacingWheelButtons const& button) const
{
    Windows::Gaming::Input::GameControllerButtonLabel value{};
    check_hresult(WINRT_SHIM(Windows::Gaming::Input::IRacingWheel)->GetButtonLabel(get_abi(button), put_abi(value)));
    return value;
}

template <typename D> Windows::Gaming::Input::RacingWheelReading consume_Windows_Gaming_Input_IRacingWheel<D>::GetCurrentReading() const
{
    Windows::Gaming::Input::RacingWheelReading value{};
    check_hresult(WINRT_SHIM(Windows::Gaming::Input::IRacingWheel)->GetCurrentReading(put_abi(value)));
    return value;
}

template <typename D> winrt::event_token consume_Windows_Gaming_Input_IRacingWheelStatics<D>::RacingWheelAdded(Windows::Foundation::EventHandler<Windows::Gaming::Input::RacingWheel> const& value) const
{
    winrt::event_token token{};
    check_hresult(WINRT_SHIM(Windows::Gaming::Input::IRacingWheelStatics)->add_RacingWheelAdded(get_abi(value), put_abi(token)));
    return token;
}

template <typename D> typename consume_Windows_Gaming_Input_IRacingWheelStatics<D>::RacingWheelAdded_revoker consume_Windows_Gaming_Input_IRacingWheelStatics<D>::RacingWheelAdded(auto_revoke_t, Windows::Foundation::EventHandler<Windows::Gaming::Input::RacingWheel> const& value) const
{
    return impl::make_event_revoker<D, RacingWheelAdded_revoker>(this, RacingWheelAdded(value));
}

template <typename D> void consume_Windows_Gaming_Input_IRacingWheelStatics<D>::RacingWheelAdded(winrt::event_token const& token) const noexcept
{
    WINRT_VERIFY_(0, WINRT_SHIM(Windows::Gaming::Input::IRacingWheelStatics)->remove_RacingWheelAdded(get_abi(token)));
}

template <typename D> winrt::event_token consume_Windows_Gaming_Input_IRacingWheelStatics<D>::RacingWheelRemoved(Windows::Foundation::EventHandler<Windows::Gaming::Input::RacingWheel> const& value) const
{
    winrt::event_token token{};
    check_hresult(WINRT_SHIM(Windows::Gaming::Input::IRacingWheelStatics)->add_RacingWheelRemoved(get_abi(value), put_abi(token)));
    return token;
}

template <typename D> typename consume_Windows_Gaming_Input_IRacingWheelStatics<D>::RacingWheelRemoved_revoker consume_Windows_Gaming_Input_IRacingWheelStatics<D>::RacingWheelRemoved(auto_revoke_t, Windows::Foundation::EventHandler<Windows::Gaming::Input::RacingWheel> const& value) const
{
    return impl::make_event_revoker<D, RacingWheelRemoved_revoker>(this, RacingWheelRemoved(value));
}

template <typename D> void consume_Windows_Gaming_Input_IRacingWheelStatics<D>::RacingWheelRemoved(winrt::event_token const& token) const noexcept
{
    WINRT_VERIFY_(0, WINRT_SHIM(Windows::Gaming::Input::IRacingWheelStatics)->remove_RacingWheelRemoved(get_abi(token)));
}

template <typename D> Windows::Foundation::Collections::IVectorView<Windows::Gaming::Input::RacingWheel> consume_Windows_Gaming_Input_IRacingWheelStatics<D>::RacingWheels() const
{
    Windows::Foundation::Collections::IVectorView<Windows::Gaming::Input::RacingWheel> value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Gaming::Input::IRacingWheelStatics)->get_RacingWheels(put_abi(value)));
    return value;
}

template <typename D> Windows::Gaming::Input::RacingWheel consume_Windows_Gaming_Input_IRacingWheelStatics2<D>::FromGameController(Windows::Gaming::Input::IGameController const& gameController) const
{
    Windows::Gaming::Input::RacingWheel value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Gaming::Input::IRacingWheelStatics2)->FromGameController(get_abi(gameController), put_abi(value)));
    return value;
}

template <typename D> int32_t consume_Windows_Gaming_Input_IRawGameController<D>::AxisCount() const
{
    int32_t value{};
    check_hresult(WINRT_SHIM(Windows::Gaming::Input::IRawGameController)->get_AxisCount(&value));
    return value;
}

template <typename D> int32_t consume_Windows_Gaming_Input_IRawGameController<D>::ButtonCount() const
{
    int32_t value{};
    check_hresult(WINRT_SHIM(Windows::Gaming::Input::IRawGameController)->get_ButtonCount(&value));
    return value;
}

template <typename D> Windows::Foundation::Collections::IVectorView<Windows::Gaming::Input::ForceFeedback::ForceFeedbackMotor> consume_Windows_Gaming_Input_IRawGameController<D>::ForceFeedbackMotors() const
{
    Windows::Foundation::Collections::IVectorView<Windows::Gaming::Input::ForceFeedback::ForceFeedbackMotor> value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Gaming::Input::IRawGameController)->get_ForceFeedbackMotors(put_abi(value)));
    return value;
}

template <typename D> uint16_t consume_Windows_Gaming_Input_IRawGameController<D>::HardwareProductId() const
{
    uint16_t value{};
    check_hresult(WINRT_SHIM(Windows::Gaming::Input::IRawGameController)->get_HardwareProductId(&value));
    return value;
}

template <typename D> uint16_t consume_Windows_Gaming_Input_IRawGameController<D>::HardwareVendorId() const
{
    uint16_t value{};
    check_hresult(WINRT_SHIM(Windows::Gaming::Input::IRawGameController)->get_HardwareVendorId(&value));
    return value;
}

template <typename D> int32_t consume_Windows_Gaming_Input_IRawGameController<D>::SwitchCount() const
{
    int32_t value{};
    check_hresult(WINRT_SHIM(Windows::Gaming::Input::IRawGameController)->get_SwitchCount(&value));
    return value;
}

template <typename D> Windows::Gaming::Input::GameControllerButtonLabel consume_Windows_Gaming_Input_IRawGameController<D>::GetButtonLabel(int32_t buttonIndex) const
{
    Windows::Gaming::Input::GameControllerButtonLabel value{};
    check_hresult(WINRT_SHIM(Windows::Gaming::Input::IRawGameController)->GetButtonLabel(buttonIndex, put_abi(value)));
    return value;
}

template <typename D> uint64_t consume_Windows_Gaming_Input_IRawGameController<D>::GetCurrentReading(array_view<bool> buttonArray, array_view<Windows::Gaming::Input::GameControllerSwitchPosition> switchArray, array_view<double> axisArray) const
{
    uint64_t timestamp{};
    check_hresult(WINRT_SHIM(Windows::Gaming::Input::IRawGameController)->GetCurrentReading(buttonArray.size(), get_abi(buttonArray), switchArray.size(), get_abi(switchArray), axisArray.size(), get_abi(axisArray), &timestamp));
    return timestamp;
}

template <typename D> Windows::Gaming::Input::GameControllerSwitchKind consume_Windows_Gaming_Input_IRawGameController<D>::GetSwitchKind(int32_t switchIndex) const
{
    Windows::Gaming::Input::GameControllerSwitchKind value{};
    check_hresult(WINRT_SHIM(Windows::Gaming::Input::IRawGameController)->GetSwitchKind(switchIndex, put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::Collections::IVectorView<Windows::Devices::Haptics::SimpleHapticsController> consume_Windows_Gaming_Input_IRawGameController2<D>::SimpleHapticsControllers() const
{
    Windows::Foundation::Collections::IVectorView<Windows::Devices::Haptics::SimpleHapticsController> value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Gaming::Input::IRawGameController2)->get_SimpleHapticsControllers(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_Gaming_Input_IRawGameController2<D>::NonRoamableId() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Gaming::Input::IRawGameController2)->get_NonRoamableId(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_Gaming_Input_IRawGameController2<D>::DisplayName() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Gaming::Input::IRawGameController2)->get_DisplayName(put_abi(value)));
    return value;
}

template <typename D> winrt::event_token consume_Windows_Gaming_Input_IRawGameControllerStatics<D>::RawGameControllerAdded(Windows::Foundation::EventHandler<Windows::Gaming::Input::RawGameController> const& value) const
{
    winrt::event_token token{};
    check_hresult(WINRT_SHIM(Windows::Gaming::Input::IRawGameControllerStatics)->add_RawGameControllerAdded(get_abi(value), put_abi(token)));
    return token;
}

template <typename D> typename consume_Windows_Gaming_Input_IRawGameControllerStatics<D>::RawGameControllerAdded_revoker consume_Windows_Gaming_Input_IRawGameControllerStatics<D>::RawGameControllerAdded(auto_revoke_t, Windows::Foundation::EventHandler<Windows::Gaming::Input::RawGameController> const& value) const
{
    return impl::make_event_revoker<D, RawGameControllerAdded_revoker>(this, RawGameControllerAdded(value));
}

template <typename D> void consume_Windows_Gaming_Input_IRawGameControllerStatics<D>::RawGameControllerAdded(winrt::event_token const& token) const noexcept
{
    WINRT_VERIFY_(0, WINRT_SHIM(Windows::Gaming::Input::IRawGameControllerStatics)->remove_RawGameControllerAdded(get_abi(token)));
}

template <typename D> winrt::event_token consume_Windows_Gaming_Input_IRawGameControllerStatics<D>::RawGameControllerRemoved(Windows::Foundation::EventHandler<Windows::Gaming::Input::RawGameController> const& value) const
{
    winrt::event_token token{};
    check_hresult(WINRT_SHIM(Windows::Gaming::Input::IRawGameControllerStatics)->add_RawGameControllerRemoved(get_abi(value), put_abi(token)));
    return token;
}

template <typename D> typename consume_Windows_Gaming_Input_IRawGameControllerStatics<D>::RawGameControllerRemoved_revoker consume_Windows_Gaming_Input_IRawGameControllerStatics<D>::RawGameControllerRemoved(auto_revoke_t, Windows::Foundation::EventHandler<Windows::Gaming::Input::RawGameController> const& value) const
{
    return impl::make_event_revoker<D, RawGameControllerRemoved_revoker>(this, RawGameControllerRemoved(value));
}

template <typename D> void consume_Windows_Gaming_Input_IRawGameControllerStatics<D>::RawGameControllerRemoved(winrt::event_token const& token) const noexcept
{
    WINRT_VERIFY_(0, WINRT_SHIM(Windows::Gaming::Input::IRawGameControllerStatics)->remove_RawGameControllerRemoved(get_abi(token)));
}

template <typename D> Windows::Foundation::Collections::IVectorView<Windows::Gaming::Input::RawGameController> consume_Windows_Gaming_Input_IRawGameControllerStatics<D>::RawGameControllers() const
{
    Windows::Foundation::Collections::IVectorView<Windows::Gaming::Input::RawGameController> value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Gaming::Input::IRawGameControllerStatics)->get_RawGameControllers(put_abi(value)));
    return value;
}

template <typename D> Windows::Gaming::Input::RawGameController consume_Windows_Gaming_Input_IRawGameControllerStatics<D>::FromGameController(Windows::Gaming::Input::IGameController const& gameController) const
{
    Windows::Gaming::Input::RawGameController value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Gaming::Input::IRawGameControllerStatics)->FromGameController(get_abi(gameController), put_abi(value)));
    return value;
}

template <typename D> Windows::Gaming::Input::UINavigationReading consume_Windows_Gaming_Input_IUINavigationController<D>::GetCurrentReading() const
{
    Windows::Gaming::Input::UINavigationReading value{};
    check_hresult(WINRT_SHIM(Windows::Gaming::Input::IUINavigationController)->GetCurrentReading(put_abi(value)));
    return value;
}

template <typename D> Windows::Gaming::Input::GameControllerButtonLabel consume_Windows_Gaming_Input_IUINavigationController<D>::GetOptionalButtonLabel(Windows::Gaming::Input::OptionalUINavigationButtons const& button) const
{
    Windows::Gaming::Input::GameControllerButtonLabel value{};
    check_hresult(WINRT_SHIM(Windows::Gaming::Input::IUINavigationController)->GetOptionalButtonLabel(get_abi(button), put_abi(value)));
    return value;
}

template <typename D> Windows::Gaming::Input::GameControllerButtonLabel consume_Windows_Gaming_Input_IUINavigationController<D>::GetRequiredButtonLabel(Windows::Gaming::Input::RequiredUINavigationButtons const& button) const
{
    Windows::Gaming::Input::GameControllerButtonLabel value{};
    check_hresult(WINRT_SHIM(Windows::Gaming::Input::IUINavigationController)->GetRequiredButtonLabel(get_abi(button), put_abi(value)));
    return value;
}

template <typename D> winrt::event_token consume_Windows_Gaming_Input_IUINavigationControllerStatics<D>::UINavigationControllerAdded(Windows::Foundation::EventHandler<Windows::Gaming::Input::UINavigationController> const& value) const
{
    winrt::event_token token{};
    check_hresult(WINRT_SHIM(Windows::Gaming::Input::IUINavigationControllerStatics)->add_UINavigationControllerAdded(get_abi(value), put_abi(token)));
    return token;
}

template <typename D> typename consume_Windows_Gaming_Input_IUINavigationControllerStatics<D>::UINavigationControllerAdded_revoker consume_Windows_Gaming_Input_IUINavigationControllerStatics<D>::UINavigationControllerAdded(auto_revoke_t, Windows::Foundation::EventHandler<Windows::Gaming::Input::UINavigationController> const& value) const
{
    return impl::make_event_revoker<D, UINavigationControllerAdded_revoker>(this, UINavigationControllerAdded(value));
}

template <typename D> void consume_Windows_Gaming_Input_IUINavigationControllerStatics<D>::UINavigationControllerAdded(winrt::event_token const& token) const noexcept
{
    WINRT_VERIFY_(0, WINRT_SHIM(Windows::Gaming::Input::IUINavigationControllerStatics)->remove_UINavigationControllerAdded(get_abi(token)));
}

template <typename D> winrt::event_token consume_Windows_Gaming_Input_IUINavigationControllerStatics<D>::UINavigationControllerRemoved(Windows::Foundation::EventHandler<Windows::Gaming::Input::UINavigationController> const& value) const
{
    winrt::event_token token{};
    check_hresult(WINRT_SHIM(Windows::Gaming::Input::IUINavigationControllerStatics)->add_UINavigationControllerRemoved(get_abi(value), put_abi(token)));
    return token;
}

template <typename D> typename consume_Windows_Gaming_Input_IUINavigationControllerStatics<D>::UINavigationControllerRemoved_revoker consume_Windows_Gaming_Input_IUINavigationControllerStatics<D>::UINavigationControllerRemoved(auto_revoke_t, Windows::Foundation::EventHandler<Windows::Gaming::Input::UINavigationController> const& value) const
{
    return impl::make_event_revoker<D, UINavigationControllerRemoved_revoker>(this, UINavigationControllerRemoved(value));
}

template <typename D> void consume_Windows_Gaming_Input_IUINavigationControllerStatics<D>::UINavigationControllerRemoved(winrt::event_token const& token) const noexcept
{
    WINRT_VERIFY_(0, WINRT_SHIM(Windows::Gaming::Input::IUINavigationControllerStatics)->remove_UINavigationControllerRemoved(get_abi(token)));
}

template <typename D> Windows::Foundation::Collections::IVectorView<Windows::Gaming::Input::UINavigationController> consume_Windows_Gaming_Input_IUINavigationControllerStatics<D>::UINavigationControllers() const
{
    Windows::Foundation::Collections::IVectorView<Windows::Gaming::Input::UINavigationController> value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Gaming::Input::IUINavigationControllerStatics)->get_UINavigationControllers(put_abi(value)));
    return value;
}

template <typename D> Windows::Gaming::Input::UINavigationController consume_Windows_Gaming_Input_IUINavigationControllerStatics2<D>::FromGameController(Windows::Gaming::Input::IGameController const& gameController) const
{
    Windows::Gaming::Input::UINavigationController value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Gaming::Input::IUINavigationControllerStatics2)->FromGameController(get_abi(gameController), put_abi(value)));
    return value;
}

template <typename D>
struct produce<D, Windows::Gaming::Input::IArcadeStick> : produce_base<D, Windows::Gaming::Input::IArcadeStick>
{
    int32_t WINRT_CALL GetButtonLabel(Windows::Gaming::Input::ArcadeStickButtons button, Windows::Gaming::Input::GameControllerButtonLabel* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetButtonLabel, WINRT_WRAP(Windows::Gaming::Input::GameControllerButtonLabel), Windows::Gaming::Input::ArcadeStickButtons const&);
            *value = detach_from<Windows::Gaming::Input::GameControllerButtonLabel>(this->shim().GetButtonLabel(*reinterpret_cast<Windows::Gaming::Input::ArcadeStickButtons const*>(&button)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL GetCurrentReading(struct struct_Windows_Gaming_Input_ArcadeStickReading* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetCurrentReading, WINRT_WRAP(Windows::Gaming::Input::ArcadeStickReading));
            *value = detach_from<Windows::Gaming::Input::ArcadeStickReading>(this->shim().GetCurrentReading());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Gaming::Input::IArcadeStickStatics> : produce_base<D, Windows::Gaming::Input::IArcadeStickStatics>
{
    int32_t WINRT_CALL add_ArcadeStickAdded(void* value, winrt::event_token* token) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ArcadeStickAdded, WINRT_WRAP(winrt::event_token), Windows::Foundation::EventHandler<Windows::Gaming::Input::ArcadeStick> const&);
            *token = detach_from<winrt::event_token>(this->shim().ArcadeStickAdded(*reinterpret_cast<Windows::Foundation::EventHandler<Windows::Gaming::Input::ArcadeStick> const*>(&value)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL remove_ArcadeStickAdded(winrt::event_token token) noexcept final
    {
        typename D::abi_guard guard(this->shim());
        WINRT_ASSERT_DECLARATION(ArcadeStickAdded, WINRT_WRAP(void), winrt::event_token const&);
        this->shim().ArcadeStickAdded(*reinterpret_cast<winrt::event_token const*>(&token));
        return 0;
    }

    int32_t WINRT_CALL add_ArcadeStickRemoved(void* value, winrt::event_token* token) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ArcadeStickRemoved, WINRT_WRAP(winrt::event_token), Windows::Foundation::EventHandler<Windows::Gaming::Input::ArcadeStick> const&);
            *token = detach_from<winrt::event_token>(this->shim().ArcadeStickRemoved(*reinterpret_cast<Windows::Foundation::EventHandler<Windows::Gaming::Input::ArcadeStick> const*>(&value)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL remove_ArcadeStickRemoved(winrt::event_token token) noexcept final
    {
        typename D::abi_guard guard(this->shim());
        WINRT_ASSERT_DECLARATION(ArcadeStickRemoved, WINRT_WRAP(void), winrt::event_token const&);
        this->shim().ArcadeStickRemoved(*reinterpret_cast<winrt::event_token const*>(&token));
        return 0;
    }

    int32_t WINRT_CALL get_ArcadeSticks(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ArcadeSticks, WINRT_WRAP(Windows::Foundation::Collections::IVectorView<Windows::Gaming::Input::ArcadeStick>));
            *value = detach_from<Windows::Foundation::Collections::IVectorView<Windows::Gaming::Input::ArcadeStick>>(this->shim().ArcadeSticks());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Gaming::Input::IArcadeStickStatics2> : produce_base<D, Windows::Gaming::Input::IArcadeStickStatics2>
{
    int32_t WINRT_CALL FromGameController(void* gameController, void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(FromGameController, WINRT_WRAP(Windows::Gaming::Input::ArcadeStick), Windows::Gaming::Input::IGameController const&);
            *value = detach_from<Windows::Gaming::Input::ArcadeStick>(this->shim().FromGameController(*reinterpret_cast<Windows::Gaming::Input::IGameController const*>(&gameController)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Gaming::Input::IFlightStick> : produce_base<D, Windows::Gaming::Input::IFlightStick>
{
    int32_t WINRT_CALL get_HatSwitchKind(Windows::Gaming::Input::GameControllerSwitchKind* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(HatSwitchKind, WINRT_WRAP(Windows::Gaming::Input::GameControllerSwitchKind));
            *value = detach_from<Windows::Gaming::Input::GameControllerSwitchKind>(this->shim().HatSwitchKind());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL GetButtonLabel(Windows::Gaming::Input::FlightStickButtons button, Windows::Gaming::Input::GameControllerButtonLabel* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetButtonLabel, WINRT_WRAP(Windows::Gaming::Input::GameControllerButtonLabel), Windows::Gaming::Input::FlightStickButtons const&);
            *value = detach_from<Windows::Gaming::Input::GameControllerButtonLabel>(this->shim().GetButtonLabel(*reinterpret_cast<Windows::Gaming::Input::FlightStickButtons const*>(&button)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL GetCurrentReading(struct struct_Windows_Gaming_Input_FlightStickReading* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetCurrentReading, WINRT_WRAP(Windows::Gaming::Input::FlightStickReading));
            *value = detach_from<Windows::Gaming::Input::FlightStickReading>(this->shim().GetCurrentReading());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Gaming::Input::IFlightStickStatics> : produce_base<D, Windows::Gaming::Input::IFlightStickStatics>
{
    int32_t WINRT_CALL add_FlightStickAdded(void* value, winrt::event_token* token) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(FlightStickAdded, WINRT_WRAP(winrt::event_token), Windows::Foundation::EventHandler<Windows::Gaming::Input::FlightStick> const&);
            *token = detach_from<winrt::event_token>(this->shim().FlightStickAdded(*reinterpret_cast<Windows::Foundation::EventHandler<Windows::Gaming::Input::FlightStick> const*>(&value)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL remove_FlightStickAdded(winrt::event_token token) noexcept final
    {
        typename D::abi_guard guard(this->shim());
        WINRT_ASSERT_DECLARATION(FlightStickAdded, WINRT_WRAP(void), winrt::event_token const&);
        this->shim().FlightStickAdded(*reinterpret_cast<winrt::event_token const*>(&token));
        return 0;
    }

    int32_t WINRT_CALL add_FlightStickRemoved(void* value, winrt::event_token* token) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(FlightStickRemoved, WINRT_WRAP(winrt::event_token), Windows::Foundation::EventHandler<Windows::Gaming::Input::FlightStick> const&);
            *token = detach_from<winrt::event_token>(this->shim().FlightStickRemoved(*reinterpret_cast<Windows::Foundation::EventHandler<Windows::Gaming::Input::FlightStick> const*>(&value)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL remove_FlightStickRemoved(winrt::event_token token) noexcept final
    {
        typename D::abi_guard guard(this->shim());
        WINRT_ASSERT_DECLARATION(FlightStickRemoved, WINRT_WRAP(void), winrt::event_token const&);
        this->shim().FlightStickRemoved(*reinterpret_cast<winrt::event_token const*>(&token));
        return 0;
    }

    int32_t WINRT_CALL get_FlightSticks(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(FlightSticks, WINRT_WRAP(Windows::Foundation::Collections::IVectorView<Windows::Gaming::Input::FlightStick>));
            *value = detach_from<Windows::Foundation::Collections::IVectorView<Windows::Gaming::Input::FlightStick>>(this->shim().FlightSticks());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL FromGameController(void* gameController, void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(FromGameController, WINRT_WRAP(Windows::Gaming::Input::FlightStick), Windows::Gaming::Input::IGameController const&);
            *value = detach_from<Windows::Gaming::Input::FlightStick>(this->shim().FromGameController(*reinterpret_cast<Windows::Gaming::Input::IGameController const*>(&gameController)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Gaming::Input::IGameController> : produce_base<D, Windows::Gaming::Input::IGameController>
{
    int32_t WINRT_CALL add_HeadsetConnected(void* value, winrt::event_token* token) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(HeadsetConnected, WINRT_WRAP(winrt::event_token), Windows::Foundation::TypedEventHandler<Windows::Gaming::Input::IGameController, Windows::Gaming::Input::Headset> const&);
            *token = detach_from<winrt::event_token>(this->shim().HeadsetConnected(*reinterpret_cast<Windows::Foundation::TypedEventHandler<Windows::Gaming::Input::IGameController, Windows::Gaming::Input::Headset> const*>(&value)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL remove_HeadsetConnected(winrt::event_token token) noexcept final
    {
        typename D::abi_guard guard(this->shim());
        WINRT_ASSERT_DECLARATION(HeadsetConnected, WINRT_WRAP(void), winrt::event_token const&);
        this->shim().HeadsetConnected(*reinterpret_cast<winrt::event_token const*>(&token));
        return 0;
    }

    int32_t WINRT_CALL add_HeadsetDisconnected(void* value, winrt::event_token* token) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(HeadsetDisconnected, WINRT_WRAP(winrt::event_token), Windows::Foundation::TypedEventHandler<Windows::Gaming::Input::IGameController, Windows::Gaming::Input::Headset> const&);
            *token = detach_from<winrt::event_token>(this->shim().HeadsetDisconnected(*reinterpret_cast<Windows::Foundation::TypedEventHandler<Windows::Gaming::Input::IGameController, Windows::Gaming::Input::Headset> const*>(&value)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL remove_HeadsetDisconnected(winrt::event_token token) noexcept final
    {
        typename D::abi_guard guard(this->shim());
        WINRT_ASSERT_DECLARATION(HeadsetDisconnected, WINRT_WRAP(void), winrt::event_token const&);
        this->shim().HeadsetDisconnected(*reinterpret_cast<winrt::event_token const*>(&token));
        return 0;
    }

    int32_t WINRT_CALL add_UserChanged(void* value, winrt::event_token* token) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(UserChanged, WINRT_WRAP(winrt::event_token), Windows::Foundation::TypedEventHandler<Windows::Gaming::Input::IGameController, Windows::System::UserChangedEventArgs> const&);
            *token = detach_from<winrt::event_token>(this->shim().UserChanged(*reinterpret_cast<Windows::Foundation::TypedEventHandler<Windows::Gaming::Input::IGameController, Windows::System::UserChangedEventArgs> const*>(&value)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL remove_UserChanged(winrt::event_token token) noexcept final
    {
        typename D::abi_guard guard(this->shim());
        WINRT_ASSERT_DECLARATION(UserChanged, WINRT_WRAP(void), winrt::event_token const&);
        this->shim().UserChanged(*reinterpret_cast<winrt::event_token const*>(&token));
        return 0;
    }

    int32_t WINRT_CALL get_Headset(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Headset, WINRT_WRAP(Windows::Gaming::Input::Headset));
            *value = detach_from<Windows::Gaming::Input::Headset>(this->shim().Headset());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_IsWireless(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IsWireless, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().IsWireless());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_User(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(User, WINRT_WRAP(Windows::System::User));
            *value = detach_from<Windows::System::User>(this->shim().User());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Gaming::Input::IGameControllerBatteryInfo> : produce_base<D, Windows::Gaming::Input::IGameControllerBatteryInfo>
{
    int32_t WINRT_CALL TryGetBatteryReport(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(TryGetBatteryReport, WINRT_WRAP(Windows::Devices::Power::BatteryReport));
            *value = detach_from<Windows::Devices::Power::BatteryReport>(this->shim().TryGetBatteryReport());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Gaming::Input::IGamepad> : produce_base<D, Windows::Gaming::Input::IGamepad>
{
    int32_t WINRT_CALL get_Vibration(struct struct_Windows_Gaming_Input_GamepadVibration* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Vibration, WINRT_WRAP(Windows::Gaming::Input::GamepadVibration));
            *value = detach_from<Windows::Gaming::Input::GamepadVibration>(this->shim().Vibration());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_Vibration(struct struct_Windows_Gaming_Input_GamepadVibration value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Vibration, WINRT_WRAP(void), Windows::Gaming::Input::GamepadVibration const&);
            this->shim().Vibration(*reinterpret_cast<Windows::Gaming::Input::GamepadVibration const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL GetCurrentReading(struct struct_Windows_Gaming_Input_GamepadReading* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetCurrentReading, WINRT_WRAP(Windows::Gaming::Input::GamepadReading));
            *value = detach_from<Windows::Gaming::Input::GamepadReading>(this->shim().GetCurrentReading());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Gaming::Input::IGamepad2> : produce_base<D, Windows::Gaming::Input::IGamepad2>
{
    int32_t WINRT_CALL GetButtonLabel(Windows::Gaming::Input::GamepadButtons button, Windows::Gaming::Input::GameControllerButtonLabel* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetButtonLabel, WINRT_WRAP(Windows::Gaming::Input::GameControllerButtonLabel), Windows::Gaming::Input::GamepadButtons const&);
            *value = detach_from<Windows::Gaming::Input::GameControllerButtonLabel>(this->shim().GetButtonLabel(*reinterpret_cast<Windows::Gaming::Input::GamepadButtons const*>(&button)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Gaming::Input::IGamepadStatics> : produce_base<D, Windows::Gaming::Input::IGamepadStatics>
{
    int32_t WINRT_CALL add_GamepadAdded(void* value, winrt::event_token* token) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GamepadAdded, WINRT_WRAP(winrt::event_token), Windows::Foundation::EventHandler<Windows::Gaming::Input::Gamepad> const&);
            *token = detach_from<winrt::event_token>(this->shim().GamepadAdded(*reinterpret_cast<Windows::Foundation::EventHandler<Windows::Gaming::Input::Gamepad> const*>(&value)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL remove_GamepadAdded(winrt::event_token token) noexcept final
    {
        typename D::abi_guard guard(this->shim());
        WINRT_ASSERT_DECLARATION(GamepadAdded, WINRT_WRAP(void), winrt::event_token const&);
        this->shim().GamepadAdded(*reinterpret_cast<winrt::event_token const*>(&token));
        return 0;
    }

    int32_t WINRT_CALL add_GamepadRemoved(void* value, winrt::event_token* token) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GamepadRemoved, WINRT_WRAP(winrt::event_token), Windows::Foundation::EventHandler<Windows::Gaming::Input::Gamepad> const&);
            *token = detach_from<winrt::event_token>(this->shim().GamepadRemoved(*reinterpret_cast<Windows::Foundation::EventHandler<Windows::Gaming::Input::Gamepad> const*>(&value)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL remove_GamepadRemoved(winrt::event_token token) noexcept final
    {
        typename D::abi_guard guard(this->shim());
        WINRT_ASSERT_DECLARATION(GamepadRemoved, WINRT_WRAP(void), winrt::event_token const&);
        this->shim().GamepadRemoved(*reinterpret_cast<winrt::event_token const*>(&token));
        return 0;
    }

    int32_t WINRT_CALL get_Gamepads(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Gamepads, WINRT_WRAP(Windows::Foundation::Collections::IVectorView<Windows::Gaming::Input::Gamepad>));
            *value = detach_from<Windows::Foundation::Collections::IVectorView<Windows::Gaming::Input::Gamepad>>(this->shim().Gamepads());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Gaming::Input::IGamepadStatics2> : produce_base<D, Windows::Gaming::Input::IGamepadStatics2>
{
    int32_t WINRT_CALL FromGameController(void* gameController, void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(FromGameController, WINRT_WRAP(Windows::Gaming::Input::Gamepad), Windows::Gaming::Input::IGameController const&);
            *value = detach_from<Windows::Gaming::Input::Gamepad>(this->shim().FromGameController(*reinterpret_cast<Windows::Gaming::Input::IGameController const*>(&gameController)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Gaming::Input::IHeadset> : produce_base<D, Windows::Gaming::Input::IHeadset>
{
    int32_t WINRT_CALL get_CaptureDeviceId(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CaptureDeviceId, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().CaptureDeviceId());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_RenderDeviceId(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(RenderDeviceId, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().RenderDeviceId());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Gaming::Input::IRacingWheel> : produce_base<D, Windows::Gaming::Input::IRacingWheel>
{
    int32_t WINRT_CALL get_HasClutch(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(HasClutch, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().HasClutch());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_HasHandbrake(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(HasHandbrake, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().HasHandbrake());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_HasPatternShifter(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(HasPatternShifter, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().HasPatternShifter());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_MaxPatternShifterGear(int32_t* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(MaxPatternShifterGear, WINRT_WRAP(int32_t));
            *value = detach_from<int32_t>(this->shim().MaxPatternShifterGear());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_MaxWheelAngle(double* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(MaxWheelAngle, WINRT_WRAP(double));
            *value = detach_from<double>(this->shim().MaxWheelAngle());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_WheelMotor(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(WheelMotor, WINRT_WRAP(Windows::Gaming::Input::ForceFeedback::ForceFeedbackMotor));
            *value = detach_from<Windows::Gaming::Input::ForceFeedback::ForceFeedbackMotor>(this->shim().WheelMotor());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL GetButtonLabel(Windows::Gaming::Input::RacingWheelButtons button, Windows::Gaming::Input::GameControllerButtonLabel* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetButtonLabel, WINRT_WRAP(Windows::Gaming::Input::GameControllerButtonLabel), Windows::Gaming::Input::RacingWheelButtons const&);
            *value = detach_from<Windows::Gaming::Input::GameControllerButtonLabel>(this->shim().GetButtonLabel(*reinterpret_cast<Windows::Gaming::Input::RacingWheelButtons const*>(&button)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL GetCurrentReading(struct struct_Windows_Gaming_Input_RacingWheelReading* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetCurrentReading, WINRT_WRAP(Windows::Gaming::Input::RacingWheelReading));
            *value = detach_from<Windows::Gaming::Input::RacingWheelReading>(this->shim().GetCurrentReading());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Gaming::Input::IRacingWheelStatics> : produce_base<D, Windows::Gaming::Input::IRacingWheelStatics>
{
    int32_t WINRT_CALL add_RacingWheelAdded(void* value, winrt::event_token* token) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(RacingWheelAdded, WINRT_WRAP(winrt::event_token), Windows::Foundation::EventHandler<Windows::Gaming::Input::RacingWheel> const&);
            *token = detach_from<winrt::event_token>(this->shim().RacingWheelAdded(*reinterpret_cast<Windows::Foundation::EventHandler<Windows::Gaming::Input::RacingWheel> const*>(&value)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL remove_RacingWheelAdded(winrt::event_token token) noexcept final
    {
        typename D::abi_guard guard(this->shim());
        WINRT_ASSERT_DECLARATION(RacingWheelAdded, WINRT_WRAP(void), winrt::event_token const&);
        this->shim().RacingWheelAdded(*reinterpret_cast<winrt::event_token const*>(&token));
        return 0;
    }

    int32_t WINRT_CALL add_RacingWheelRemoved(void* value, winrt::event_token* token) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(RacingWheelRemoved, WINRT_WRAP(winrt::event_token), Windows::Foundation::EventHandler<Windows::Gaming::Input::RacingWheel> const&);
            *token = detach_from<winrt::event_token>(this->shim().RacingWheelRemoved(*reinterpret_cast<Windows::Foundation::EventHandler<Windows::Gaming::Input::RacingWheel> const*>(&value)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL remove_RacingWheelRemoved(winrt::event_token token) noexcept final
    {
        typename D::abi_guard guard(this->shim());
        WINRT_ASSERT_DECLARATION(RacingWheelRemoved, WINRT_WRAP(void), winrt::event_token const&);
        this->shim().RacingWheelRemoved(*reinterpret_cast<winrt::event_token const*>(&token));
        return 0;
    }

    int32_t WINRT_CALL get_RacingWheels(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(RacingWheels, WINRT_WRAP(Windows::Foundation::Collections::IVectorView<Windows::Gaming::Input::RacingWheel>));
            *value = detach_from<Windows::Foundation::Collections::IVectorView<Windows::Gaming::Input::RacingWheel>>(this->shim().RacingWheels());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Gaming::Input::IRacingWheelStatics2> : produce_base<D, Windows::Gaming::Input::IRacingWheelStatics2>
{
    int32_t WINRT_CALL FromGameController(void* gameController, void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(FromGameController, WINRT_WRAP(Windows::Gaming::Input::RacingWheel), Windows::Gaming::Input::IGameController const&);
            *value = detach_from<Windows::Gaming::Input::RacingWheel>(this->shim().FromGameController(*reinterpret_cast<Windows::Gaming::Input::IGameController const*>(&gameController)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Gaming::Input::IRawGameController> : produce_base<D, Windows::Gaming::Input::IRawGameController>
{
    int32_t WINRT_CALL get_AxisCount(int32_t* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(AxisCount, WINRT_WRAP(int32_t));
            *value = detach_from<int32_t>(this->shim().AxisCount());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_ButtonCount(int32_t* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ButtonCount, WINRT_WRAP(int32_t));
            *value = detach_from<int32_t>(this->shim().ButtonCount());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_ForceFeedbackMotors(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ForceFeedbackMotors, WINRT_WRAP(Windows::Foundation::Collections::IVectorView<Windows::Gaming::Input::ForceFeedback::ForceFeedbackMotor>));
            *value = detach_from<Windows::Foundation::Collections::IVectorView<Windows::Gaming::Input::ForceFeedback::ForceFeedbackMotor>>(this->shim().ForceFeedbackMotors());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_HardwareProductId(uint16_t* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(HardwareProductId, WINRT_WRAP(uint16_t));
            *value = detach_from<uint16_t>(this->shim().HardwareProductId());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_HardwareVendorId(uint16_t* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(HardwareVendorId, WINRT_WRAP(uint16_t));
            *value = detach_from<uint16_t>(this->shim().HardwareVendorId());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_SwitchCount(int32_t* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SwitchCount, WINRT_WRAP(int32_t));
            *value = detach_from<int32_t>(this->shim().SwitchCount());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL GetButtonLabel(int32_t buttonIndex, Windows::Gaming::Input::GameControllerButtonLabel* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetButtonLabel, WINRT_WRAP(Windows::Gaming::Input::GameControllerButtonLabel), int32_t);
            *value = detach_from<Windows::Gaming::Input::GameControllerButtonLabel>(this->shim().GetButtonLabel(buttonIndex));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL GetCurrentReading(uint32_t __buttonArraySize, bool* buttonArray, uint32_t __switchArraySize, Windows::Gaming::Input::GameControllerSwitchPosition* switchArray, uint32_t __axisArraySize, double* axisArray, uint64_t* timestamp) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetCurrentReading, WINRT_WRAP(uint64_t), array_view<bool>, array_view<Windows::Gaming::Input::GameControllerSwitchPosition>, array_view<double>);
            *timestamp = detach_from<uint64_t>(this->shim().GetCurrentReading(array_view<bool>(reinterpret_cast<bool*>(buttonArray), reinterpret_cast<bool*>(buttonArray) + __buttonArraySize), array_view<Windows::Gaming::Input::GameControllerSwitchPosition>(reinterpret_cast<Windows::Gaming::Input::GameControllerSwitchPosition*>(switchArray), reinterpret_cast<Windows::Gaming::Input::GameControllerSwitchPosition*>(switchArray) + __switchArraySize), array_view<double>(reinterpret_cast<double*>(axisArray), reinterpret_cast<double*>(axisArray) + __axisArraySize)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL GetSwitchKind(int32_t switchIndex, Windows::Gaming::Input::GameControllerSwitchKind* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetSwitchKind, WINRT_WRAP(Windows::Gaming::Input::GameControllerSwitchKind), int32_t);
            *value = detach_from<Windows::Gaming::Input::GameControllerSwitchKind>(this->shim().GetSwitchKind(switchIndex));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Gaming::Input::IRawGameController2> : produce_base<D, Windows::Gaming::Input::IRawGameController2>
{
    int32_t WINRT_CALL get_SimpleHapticsControllers(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SimpleHapticsControllers, WINRT_WRAP(Windows::Foundation::Collections::IVectorView<Windows::Devices::Haptics::SimpleHapticsController>));
            *value = detach_from<Windows::Foundation::Collections::IVectorView<Windows::Devices::Haptics::SimpleHapticsController>>(this->shim().SimpleHapticsControllers());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_NonRoamableId(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(NonRoamableId, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().NonRoamableId());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_DisplayName(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(DisplayName, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().DisplayName());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Gaming::Input::IRawGameControllerStatics> : produce_base<D, Windows::Gaming::Input::IRawGameControllerStatics>
{
    int32_t WINRT_CALL add_RawGameControllerAdded(void* value, winrt::event_token* token) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(RawGameControllerAdded, WINRT_WRAP(winrt::event_token), Windows::Foundation::EventHandler<Windows::Gaming::Input::RawGameController> const&);
            *token = detach_from<winrt::event_token>(this->shim().RawGameControllerAdded(*reinterpret_cast<Windows::Foundation::EventHandler<Windows::Gaming::Input::RawGameController> const*>(&value)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL remove_RawGameControllerAdded(winrt::event_token token) noexcept final
    {
        typename D::abi_guard guard(this->shim());
        WINRT_ASSERT_DECLARATION(RawGameControllerAdded, WINRT_WRAP(void), winrt::event_token const&);
        this->shim().RawGameControllerAdded(*reinterpret_cast<winrt::event_token const*>(&token));
        return 0;
    }

    int32_t WINRT_CALL add_RawGameControllerRemoved(void* value, winrt::event_token* token) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(RawGameControllerRemoved, WINRT_WRAP(winrt::event_token), Windows::Foundation::EventHandler<Windows::Gaming::Input::RawGameController> const&);
            *token = detach_from<winrt::event_token>(this->shim().RawGameControllerRemoved(*reinterpret_cast<Windows::Foundation::EventHandler<Windows::Gaming::Input::RawGameController> const*>(&value)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL remove_RawGameControllerRemoved(winrt::event_token token) noexcept final
    {
        typename D::abi_guard guard(this->shim());
        WINRT_ASSERT_DECLARATION(RawGameControllerRemoved, WINRT_WRAP(void), winrt::event_token const&);
        this->shim().RawGameControllerRemoved(*reinterpret_cast<winrt::event_token const*>(&token));
        return 0;
    }

    int32_t WINRT_CALL get_RawGameControllers(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(RawGameControllers, WINRT_WRAP(Windows::Foundation::Collections::IVectorView<Windows::Gaming::Input::RawGameController>));
            *value = detach_from<Windows::Foundation::Collections::IVectorView<Windows::Gaming::Input::RawGameController>>(this->shim().RawGameControllers());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL FromGameController(void* gameController, void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(FromGameController, WINRT_WRAP(Windows::Gaming::Input::RawGameController), Windows::Gaming::Input::IGameController const&);
            *value = detach_from<Windows::Gaming::Input::RawGameController>(this->shim().FromGameController(*reinterpret_cast<Windows::Gaming::Input::IGameController const*>(&gameController)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Gaming::Input::IUINavigationController> : produce_base<D, Windows::Gaming::Input::IUINavigationController>
{
    int32_t WINRT_CALL GetCurrentReading(struct struct_Windows_Gaming_Input_UINavigationReading* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetCurrentReading, WINRT_WRAP(Windows::Gaming::Input::UINavigationReading));
            *value = detach_from<Windows::Gaming::Input::UINavigationReading>(this->shim().GetCurrentReading());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL GetOptionalButtonLabel(Windows::Gaming::Input::OptionalUINavigationButtons button, Windows::Gaming::Input::GameControllerButtonLabel* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetOptionalButtonLabel, WINRT_WRAP(Windows::Gaming::Input::GameControllerButtonLabel), Windows::Gaming::Input::OptionalUINavigationButtons const&);
            *value = detach_from<Windows::Gaming::Input::GameControllerButtonLabel>(this->shim().GetOptionalButtonLabel(*reinterpret_cast<Windows::Gaming::Input::OptionalUINavigationButtons const*>(&button)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL GetRequiredButtonLabel(Windows::Gaming::Input::RequiredUINavigationButtons button, Windows::Gaming::Input::GameControllerButtonLabel* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetRequiredButtonLabel, WINRT_WRAP(Windows::Gaming::Input::GameControllerButtonLabel), Windows::Gaming::Input::RequiredUINavigationButtons const&);
            *value = detach_from<Windows::Gaming::Input::GameControllerButtonLabel>(this->shim().GetRequiredButtonLabel(*reinterpret_cast<Windows::Gaming::Input::RequiredUINavigationButtons const*>(&button)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Gaming::Input::IUINavigationControllerStatics> : produce_base<D, Windows::Gaming::Input::IUINavigationControllerStatics>
{
    int32_t WINRT_CALL add_UINavigationControllerAdded(void* value, winrt::event_token* token) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(UINavigationControllerAdded, WINRT_WRAP(winrt::event_token), Windows::Foundation::EventHandler<Windows::Gaming::Input::UINavigationController> const&);
            *token = detach_from<winrt::event_token>(this->shim().UINavigationControllerAdded(*reinterpret_cast<Windows::Foundation::EventHandler<Windows::Gaming::Input::UINavigationController> const*>(&value)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL remove_UINavigationControllerAdded(winrt::event_token token) noexcept final
    {
        typename D::abi_guard guard(this->shim());
        WINRT_ASSERT_DECLARATION(UINavigationControllerAdded, WINRT_WRAP(void), winrt::event_token const&);
        this->shim().UINavigationControllerAdded(*reinterpret_cast<winrt::event_token const*>(&token));
        return 0;
    }

    int32_t WINRT_CALL add_UINavigationControllerRemoved(void* value, winrt::event_token* token) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(UINavigationControllerRemoved, WINRT_WRAP(winrt::event_token), Windows::Foundation::EventHandler<Windows::Gaming::Input::UINavigationController> const&);
            *token = detach_from<winrt::event_token>(this->shim().UINavigationControllerRemoved(*reinterpret_cast<Windows::Foundation::EventHandler<Windows::Gaming::Input::UINavigationController> const*>(&value)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL remove_UINavigationControllerRemoved(winrt::event_token token) noexcept final
    {
        typename D::abi_guard guard(this->shim());
        WINRT_ASSERT_DECLARATION(UINavigationControllerRemoved, WINRT_WRAP(void), winrt::event_token const&);
        this->shim().UINavigationControllerRemoved(*reinterpret_cast<winrt::event_token const*>(&token));
        return 0;
    }

    int32_t WINRT_CALL get_UINavigationControllers(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(UINavigationControllers, WINRT_WRAP(Windows::Foundation::Collections::IVectorView<Windows::Gaming::Input::UINavigationController>));
            *value = detach_from<Windows::Foundation::Collections::IVectorView<Windows::Gaming::Input::UINavigationController>>(this->shim().UINavigationControllers());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Gaming::Input::IUINavigationControllerStatics2> : produce_base<D, Windows::Gaming::Input::IUINavigationControllerStatics2>
{
    int32_t WINRT_CALL FromGameController(void* gameController, void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(FromGameController, WINRT_WRAP(Windows::Gaming::Input::UINavigationController), Windows::Gaming::Input::IGameController const&);
            *value = detach_from<Windows::Gaming::Input::UINavigationController>(this->shim().FromGameController(*reinterpret_cast<Windows::Gaming::Input::IGameController const*>(&gameController)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

}

WINRT_EXPORT namespace winrt::Windows::Gaming::Input {

inline winrt::event_token ArcadeStick::ArcadeStickAdded(Windows::Foundation::EventHandler<Windows::Gaming::Input::ArcadeStick> const& value)
{
    return impl::call_factory<ArcadeStick, Windows::Gaming::Input::IArcadeStickStatics>([&](auto&& f) { return f.ArcadeStickAdded(value); });
}

inline ArcadeStick::ArcadeStickAdded_revoker ArcadeStick::ArcadeStickAdded(auto_revoke_t, Windows::Foundation::EventHandler<Windows::Gaming::Input::ArcadeStick> const& value)
{
    auto f = get_activation_factory<ArcadeStick, Windows::Gaming::Input::IArcadeStickStatics>();
    return { f, f.ArcadeStickAdded(value) };
}

inline void ArcadeStick::ArcadeStickAdded(winrt::event_token const& token)
{
    impl::call_factory<ArcadeStick, Windows::Gaming::Input::IArcadeStickStatics>([&](auto&& f) { return f.ArcadeStickAdded(token); });
}

inline winrt::event_token ArcadeStick::ArcadeStickRemoved(Windows::Foundation::EventHandler<Windows::Gaming::Input::ArcadeStick> const& value)
{
    return impl::call_factory<ArcadeStick, Windows::Gaming::Input::IArcadeStickStatics>([&](auto&& f) { return f.ArcadeStickRemoved(value); });
}

inline ArcadeStick::ArcadeStickRemoved_revoker ArcadeStick::ArcadeStickRemoved(auto_revoke_t, Windows::Foundation::EventHandler<Windows::Gaming::Input::ArcadeStick> const& value)
{
    auto f = get_activation_factory<ArcadeStick, Windows::Gaming::Input::IArcadeStickStatics>();
    return { f, f.ArcadeStickRemoved(value) };
}

inline void ArcadeStick::ArcadeStickRemoved(winrt::event_token const& token)
{
    impl::call_factory<ArcadeStick, Windows::Gaming::Input::IArcadeStickStatics>([&](auto&& f) { return f.ArcadeStickRemoved(token); });
}

inline Windows::Foundation::Collections::IVectorView<Windows::Gaming::Input::ArcadeStick> ArcadeStick::ArcadeSticks()
{
    return impl::call_factory<ArcadeStick, Windows::Gaming::Input::IArcadeStickStatics>([&](auto&& f) { return f.ArcadeSticks(); });
}

inline Windows::Gaming::Input::ArcadeStick ArcadeStick::FromGameController(Windows::Gaming::Input::IGameController const& gameController)
{
    return impl::call_factory<ArcadeStick, Windows::Gaming::Input::IArcadeStickStatics2>([&](auto&& f) { return f.FromGameController(gameController); });
}

inline winrt::event_token FlightStick::FlightStickAdded(Windows::Foundation::EventHandler<Windows::Gaming::Input::FlightStick> const& value)
{
    return impl::call_factory<FlightStick, Windows::Gaming::Input::IFlightStickStatics>([&](auto&& f) { return f.FlightStickAdded(value); });
}

inline FlightStick::FlightStickAdded_revoker FlightStick::FlightStickAdded(auto_revoke_t, Windows::Foundation::EventHandler<Windows::Gaming::Input::FlightStick> const& value)
{
    auto f = get_activation_factory<FlightStick, Windows::Gaming::Input::IFlightStickStatics>();
    return { f, f.FlightStickAdded(value) };
}

inline void FlightStick::FlightStickAdded(winrt::event_token const& token)
{
    impl::call_factory<FlightStick, Windows::Gaming::Input::IFlightStickStatics>([&](auto&& f) { return f.FlightStickAdded(token); });
}

inline winrt::event_token FlightStick::FlightStickRemoved(Windows::Foundation::EventHandler<Windows::Gaming::Input::FlightStick> const& value)
{
    return impl::call_factory<FlightStick, Windows::Gaming::Input::IFlightStickStatics>([&](auto&& f) { return f.FlightStickRemoved(value); });
}

inline FlightStick::FlightStickRemoved_revoker FlightStick::FlightStickRemoved(auto_revoke_t, Windows::Foundation::EventHandler<Windows::Gaming::Input::FlightStick> const& value)
{
    auto f = get_activation_factory<FlightStick, Windows::Gaming::Input::IFlightStickStatics>();
    return { f, f.FlightStickRemoved(value) };
}

inline void FlightStick::FlightStickRemoved(winrt::event_token const& token)
{
    impl::call_factory<FlightStick, Windows::Gaming::Input::IFlightStickStatics>([&](auto&& f) { return f.FlightStickRemoved(token); });
}

inline Windows::Foundation::Collections::IVectorView<Windows::Gaming::Input::FlightStick> FlightStick::FlightSticks()
{
    return impl::call_factory<FlightStick, Windows::Gaming::Input::IFlightStickStatics>([&](auto&& f) { return f.FlightSticks(); });
}

inline Windows::Gaming::Input::FlightStick FlightStick::FromGameController(Windows::Gaming::Input::IGameController const& gameController)
{
    return impl::call_factory<FlightStick, Windows::Gaming::Input::IFlightStickStatics>([&](auto&& f) { return f.FromGameController(gameController); });
}

inline winrt::event_token Gamepad::GamepadAdded(Windows::Foundation::EventHandler<Windows::Gaming::Input::Gamepad> const& value)
{
    return impl::call_factory<Gamepad, Windows::Gaming::Input::IGamepadStatics>([&](auto&& f) { return f.GamepadAdded(value); });
}

inline Gamepad::GamepadAdded_revoker Gamepad::GamepadAdded(auto_revoke_t, Windows::Foundation::EventHandler<Windows::Gaming::Input::Gamepad> const& value)
{
    auto f = get_activation_factory<Gamepad, Windows::Gaming::Input::IGamepadStatics>();
    return { f, f.GamepadAdded(value) };
}

inline void Gamepad::GamepadAdded(winrt::event_token const& token)
{
    impl::call_factory<Gamepad, Windows::Gaming::Input::IGamepadStatics>([&](auto&& f) { return f.GamepadAdded(token); });
}

inline winrt::event_token Gamepad::GamepadRemoved(Windows::Foundation::EventHandler<Windows::Gaming::Input::Gamepad> const& value)
{
    return impl::call_factory<Gamepad, Windows::Gaming::Input::IGamepadStatics>([&](auto&& f) { return f.GamepadRemoved(value); });
}

inline Gamepad::GamepadRemoved_revoker Gamepad::GamepadRemoved(auto_revoke_t, Windows::Foundation::EventHandler<Windows::Gaming::Input::Gamepad> const& value)
{
    auto f = get_activation_factory<Gamepad, Windows::Gaming::Input::IGamepadStatics>();
    return { f, f.GamepadRemoved(value) };
}

inline void Gamepad::GamepadRemoved(winrt::event_token const& token)
{
    impl::call_factory<Gamepad, Windows::Gaming::Input::IGamepadStatics>([&](auto&& f) { return f.GamepadRemoved(token); });
}

inline Windows::Foundation::Collections::IVectorView<Windows::Gaming::Input::Gamepad> Gamepad::Gamepads()
{
    return impl::call_factory<Gamepad, Windows::Gaming::Input::IGamepadStatics>([&](auto&& f) { return f.Gamepads(); });
}

inline Windows::Gaming::Input::Gamepad Gamepad::FromGameController(Windows::Gaming::Input::IGameController const& gameController)
{
    return impl::call_factory<Gamepad, Windows::Gaming::Input::IGamepadStatics2>([&](auto&& f) { return f.FromGameController(gameController); });
}

inline winrt::event_token RacingWheel::RacingWheelAdded(Windows::Foundation::EventHandler<Windows::Gaming::Input::RacingWheel> const& value)
{
    return impl::call_factory<RacingWheel, Windows::Gaming::Input::IRacingWheelStatics>([&](auto&& f) { return f.RacingWheelAdded(value); });
}

inline RacingWheel::RacingWheelAdded_revoker RacingWheel::RacingWheelAdded(auto_revoke_t, Windows::Foundation::EventHandler<Windows::Gaming::Input::RacingWheel> const& value)
{
    auto f = get_activation_factory<RacingWheel, Windows::Gaming::Input::IRacingWheelStatics>();
    return { f, f.RacingWheelAdded(value) };
}

inline void RacingWheel::RacingWheelAdded(winrt::event_token const& token)
{
    impl::call_factory<RacingWheel, Windows::Gaming::Input::IRacingWheelStatics>([&](auto&& f) { return f.RacingWheelAdded(token); });
}

inline winrt::event_token RacingWheel::RacingWheelRemoved(Windows::Foundation::EventHandler<Windows::Gaming::Input::RacingWheel> const& value)
{
    return impl::call_factory<RacingWheel, Windows::Gaming::Input::IRacingWheelStatics>([&](auto&& f) { return f.RacingWheelRemoved(value); });
}

inline RacingWheel::RacingWheelRemoved_revoker RacingWheel::RacingWheelRemoved(auto_revoke_t, Windows::Foundation::EventHandler<Windows::Gaming::Input::RacingWheel> const& value)
{
    auto f = get_activation_factory<RacingWheel, Windows::Gaming::Input::IRacingWheelStatics>();
    return { f, f.RacingWheelRemoved(value) };
}

inline void RacingWheel::RacingWheelRemoved(winrt::event_token const& token)
{
    impl::call_factory<RacingWheel, Windows::Gaming::Input::IRacingWheelStatics>([&](auto&& f) { return f.RacingWheelRemoved(token); });
}

inline Windows::Foundation::Collections::IVectorView<Windows::Gaming::Input::RacingWheel> RacingWheel::RacingWheels()
{
    return impl::call_factory<RacingWheel, Windows::Gaming::Input::IRacingWheelStatics>([&](auto&& f) { return f.RacingWheels(); });
}

inline Windows::Gaming::Input::RacingWheel RacingWheel::FromGameController(Windows::Gaming::Input::IGameController const& gameController)
{
    return impl::call_factory<RacingWheel, Windows::Gaming::Input::IRacingWheelStatics2>([&](auto&& f) { return f.FromGameController(gameController); });
}

inline winrt::event_token RawGameController::RawGameControllerAdded(Windows::Foundation::EventHandler<Windows::Gaming::Input::RawGameController> const& value)
{
    return impl::call_factory<RawGameController, Windows::Gaming::Input::IRawGameControllerStatics>([&](auto&& f) { return f.RawGameControllerAdded(value); });
}

inline RawGameController::RawGameControllerAdded_revoker RawGameController::RawGameControllerAdded(auto_revoke_t, Windows::Foundation::EventHandler<Windows::Gaming::Input::RawGameController> const& value)
{
    auto f = get_activation_factory<RawGameController, Windows::Gaming::Input::IRawGameControllerStatics>();
    return { f, f.RawGameControllerAdded(value) };
}

inline void RawGameController::RawGameControllerAdded(winrt::event_token const& token)
{
    impl::call_factory<RawGameController, Windows::Gaming::Input::IRawGameControllerStatics>([&](auto&& f) { return f.RawGameControllerAdded(token); });
}

inline winrt::event_token RawGameController::RawGameControllerRemoved(Windows::Foundation::EventHandler<Windows::Gaming::Input::RawGameController> const& value)
{
    return impl::call_factory<RawGameController, Windows::Gaming::Input::IRawGameControllerStatics>([&](auto&& f) { return f.RawGameControllerRemoved(value); });
}

inline RawGameController::RawGameControllerRemoved_revoker RawGameController::RawGameControllerRemoved(auto_revoke_t, Windows::Foundation::EventHandler<Windows::Gaming::Input::RawGameController> const& value)
{
    auto f = get_activation_factory<RawGameController, Windows::Gaming::Input::IRawGameControllerStatics>();
    return { f, f.RawGameControllerRemoved(value) };
}

inline void RawGameController::RawGameControllerRemoved(winrt::event_token const& token)
{
    impl::call_factory<RawGameController, Windows::Gaming::Input::IRawGameControllerStatics>([&](auto&& f) { return f.RawGameControllerRemoved(token); });
}

inline Windows::Foundation::Collections::IVectorView<Windows::Gaming::Input::RawGameController> RawGameController::RawGameControllers()
{
    return impl::call_factory<RawGameController, Windows::Gaming::Input::IRawGameControllerStatics>([&](auto&& f) { return f.RawGameControllers(); });
}

inline Windows::Gaming::Input::RawGameController RawGameController::FromGameController(Windows::Gaming::Input::IGameController const& gameController)
{
    return impl::call_factory<RawGameController, Windows::Gaming::Input::IRawGameControllerStatics>([&](auto&& f) { return f.FromGameController(gameController); });
}

inline winrt::event_token UINavigationController::UINavigationControllerAdded(Windows::Foundation::EventHandler<Windows::Gaming::Input::UINavigationController> const& value)
{
    return impl::call_factory<UINavigationController, Windows::Gaming::Input::IUINavigationControllerStatics>([&](auto&& f) { return f.UINavigationControllerAdded(value); });
}

inline UINavigationController::UINavigationControllerAdded_revoker UINavigationController::UINavigationControllerAdded(auto_revoke_t, Windows::Foundation::EventHandler<Windows::Gaming::Input::UINavigationController> const& value)
{
    auto f = get_activation_factory<UINavigationController, Windows::Gaming::Input::IUINavigationControllerStatics>();
    return { f, f.UINavigationControllerAdded(value) };
}

inline void UINavigationController::UINavigationControllerAdded(winrt::event_token const& token)
{
    impl::call_factory<UINavigationController, Windows::Gaming::Input::IUINavigationControllerStatics>([&](auto&& f) { return f.UINavigationControllerAdded(token); });
}

inline winrt::event_token UINavigationController::UINavigationControllerRemoved(Windows::Foundation::EventHandler<Windows::Gaming::Input::UINavigationController> const& value)
{
    return impl::call_factory<UINavigationController, Windows::Gaming::Input::IUINavigationControllerStatics>([&](auto&& f) { return f.UINavigationControllerRemoved(value); });
}

inline UINavigationController::UINavigationControllerRemoved_revoker UINavigationController::UINavigationControllerRemoved(auto_revoke_t, Windows::Foundation::EventHandler<Windows::Gaming::Input::UINavigationController> const& value)
{
    auto f = get_activation_factory<UINavigationController, Windows::Gaming::Input::IUINavigationControllerStatics>();
    return { f, f.UINavigationControllerRemoved(value) };
}

inline void UINavigationController::UINavigationControllerRemoved(winrt::event_token const& token)
{
    impl::call_factory<UINavigationController, Windows::Gaming::Input::IUINavigationControllerStatics>([&](auto&& f) { return f.UINavigationControllerRemoved(token); });
}

inline Windows::Foundation::Collections::IVectorView<Windows::Gaming::Input::UINavigationController> UINavigationController::UINavigationControllers()
{
    return impl::call_factory<UINavigationController, Windows::Gaming::Input::IUINavigationControllerStatics>([&](auto&& f) { return f.UINavigationControllers(); });
}

inline Windows::Gaming::Input::UINavigationController UINavigationController::FromGameController(Windows::Gaming::Input::IGameController const& gameController)
{
    return impl::call_factory<UINavigationController, Windows::Gaming::Input::IUINavigationControllerStatics2>([&](auto&& f) { return f.FromGameController(gameController); });
}

}

WINRT_EXPORT namespace std {

template<> struct hash<winrt::Windows::Gaming::Input::IArcadeStick> : winrt::impl::hash_base<winrt::Windows::Gaming::Input::IArcadeStick> {};
template<> struct hash<winrt::Windows::Gaming::Input::IArcadeStickStatics> : winrt::impl::hash_base<winrt::Windows::Gaming::Input::IArcadeStickStatics> {};
template<> struct hash<winrt::Windows::Gaming::Input::IArcadeStickStatics2> : winrt::impl::hash_base<winrt::Windows::Gaming::Input::IArcadeStickStatics2> {};
template<> struct hash<winrt::Windows::Gaming::Input::IFlightStick> : winrt::impl::hash_base<winrt::Windows::Gaming::Input::IFlightStick> {};
template<> struct hash<winrt::Windows::Gaming::Input::IFlightStickStatics> : winrt::impl::hash_base<winrt::Windows::Gaming::Input::IFlightStickStatics> {};
template<> struct hash<winrt::Windows::Gaming::Input::IGameController> : winrt::impl::hash_base<winrt::Windows::Gaming::Input::IGameController> {};
template<> struct hash<winrt::Windows::Gaming::Input::IGameControllerBatteryInfo> : winrt::impl::hash_base<winrt::Windows::Gaming::Input::IGameControllerBatteryInfo> {};
template<> struct hash<winrt::Windows::Gaming::Input::IGamepad> : winrt::impl::hash_base<winrt::Windows::Gaming::Input::IGamepad> {};
template<> struct hash<winrt::Windows::Gaming::Input::IGamepad2> : winrt::impl::hash_base<winrt::Windows::Gaming::Input::IGamepad2> {};
template<> struct hash<winrt::Windows::Gaming::Input::IGamepadStatics> : winrt::impl::hash_base<winrt::Windows::Gaming::Input::IGamepadStatics> {};
template<> struct hash<winrt::Windows::Gaming::Input::IGamepadStatics2> : winrt::impl::hash_base<winrt::Windows::Gaming::Input::IGamepadStatics2> {};
template<> struct hash<winrt::Windows::Gaming::Input::IHeadset> : winrt::impl::hash_base<winrt::Windows::Gaming::Input::IHeadset> {};
template<> struct hash<winrt::Windows::Gaming::Input::IRacingWheel> : winrt::impl::hash_base<winrt::Windows::Gaming::Input::IRacingWheel> {};
template<> struct hash<winrt::Windows::Gaming::Input::IRacingWheelStatics> : winrt::impl::hash_base<winrt::Windows::Gaming::Input::IRacingWheelStatics> {};
template<> struct hash<winrt::Windows::Gaming::Input::IRacingWheelStatics2> : winrt::impl::hash_base<winrt::Windows::Gaming::Input::IRacingWheelStatics2> {};
template<> struct hash<winrt::Windows::Gaming::Input::IRawGameController> : winrt::impl::hash_base<winrt::Windows::Gaming::Input::IRawGameController> {};
template<> struct hash<winrt::Windows::Gaming::Input::IRawGameController2> : winrt::impl::hash_base<winrt::Windows::Gaming::Input::IRawGameController2> {};
template<> struct hash<winrt::Windows::Gaming::Input::IRawGameControllerStatics> : winrt::impl::hash_base<winrt::Windows::Gaming::Input::IRawGameControllerStatics> {};
template<> struct hash<winrt::Windows::Gaming::Input::IUINavigationController> : winrt::impl::hash_base<winrt::Windows::Gaming::Input::IUINavigationController> {};
template<> struct hash<winrt::Windows::Gaming::Input::IUINavigationControllerStatics> : winrt::impl::hash_base<winrt::Windows::Gaming::Input::IUINavigationControllerStatics> {};
template<> struct hash<winrt::Windows::Gaming::Input::IUINavigationControllerStatics2> : winrt::impl::hash_base<winrt::Windows::Gaming::Input::IUINavigationControllerStatics2> {};
template<> struct hash<winrt::Windows::Gaming::Input::ArcadeStick> : winrt::impl::hash_base<winrt::Windows::Gaming::Input::ArcadeStick> {};
template<> struct hash<winrt::Windows::Gaming::Input::FlightStick> : winrt::impl::hash_base<winrt::Windows::Gaming::Input::FlightStick> {};
template<> struct hash<winrt::Windows::Gaming::Input::Gamepad> : winrt::impl::hash_base<winrt::Windows::Gaming::Input::Gamepad> {};
template<> struct hash<winrt::Windows::Gaming::Input::Headset> : winrt::impl::hash_base<winrt::Windows::Gaming::Input::Headset> {};
template<> struct hash<winrt::Windows::Gaming::Input::RacingWheel> : winrt::impl::hash_base<winrt::Windows::Gaming::Input::RacingWheel> {};
template<> struct hash<winrt::Windows::Gaming::Input::RawGameController> : winrt::impl::hash_base<winrt::Windows::Gaming::Input::RawGameController> {};
template<> struct hash<winrt::Windows::Gaming::Input::UINavigationController> : winrt::impl::hash_base<winrt::Windows::Gaming::Input::UINavigationController> {};

}
