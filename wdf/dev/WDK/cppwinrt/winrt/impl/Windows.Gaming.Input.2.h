// C++/WinRT v1.0.190111.3

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#pragma once
#include "winrt/impl/Windows.Devices.Haptics.1.h"
#include "winrt/impl/Windows.Devices.Power.1.h"
#include "winrt/impl/Windows.Gaming.Input.ForceFeedback.1.h"
#include "winrt/impl/Windows.System.1.h"
#include "winrt/impl/Windows.Gaming.Input.1.h"

WINRT_EXPORT namespace winrt::Windows::Gaming::Input {

struct ArcadeStickReading
{
    uint64_t Timestamp;
    Windows::Gaming::Input::ArcadeStickButtons Buttons;
};

inline bool operator==(ArcadeStickReading const& left, ArcadeStickReading const& right) noexcept
{
    return left.Timestamp == right.Timestamp && left.Buttons == right.Buttons;
}

inline bool operator!=(ArcadeStickReading const& left, ArcadeStickReading const& right) noexcept
{
    return !(left == right);
}

struct FlightStickReading
{
    uint64_t Timestamp;
    Windows::Gaming::Input::FlightStickButtons Buttons;
    Windows::Gaming::Input::GameControllerSwitchPosition HatSwitch;
    double Roll;
    double Pitch;
    double Yaw;
    double Throttle;
};

inline bool operator==(FlightStickReading const& left, FlightStickReading const& right) noexcept
{
    return left.Timestamp == right.Timestamp && left.Buttons == right.Buttons && left.HatSwitch == right.HatSwitch && left.Roll == right.Roll && left.Pitch == right.Pitch && left.Yaw == right.Yaw && left.Throttle == right.Throttle;
}

inline bool operator!=(FlightStickReading const& left, FlightStickReading const& right) noexcept
{
    return !(left == right);
}

struct GamepadReading
{
    uint64_t Timestamp;
    Windows::Gaming::Input::GamepadButtons Buttons;
    double LeftTrigger;
    double RightTrigger;
    double LeftThumbstickX;
    double LeftThumbstickY;
    double RightThumbstickX;
    double RightThumbstickY;
};

inline bool operator==(GamepadReading const& left, GamepadReading const& right) noexcept
{
    return left.Timestamp == right.Timestamp && left.Buttons == right.Buttons && left.LeftTrigger == right.LeftTrigger && left.RightTrigger == right.RightTrigger && left.LeftThumbstickX == right.LeftThumbstickX && left.LeftThumbstickY == right.LeftThumbstickY && left.RightThumbstickX == right.RightThumbstickX && left.RightThumbstickY == right.RightThumbstickY;
}

inline bool operator!=(GamepadReading const& left, GamepadReading const& right) noexcept
{
    return !(left == right);
}

struct GamepadVibration
{
    double LeftMotor;
    double RightMotor;
    double LeftTrigger;
    double RightTrigger;
};

inline bool operator==(GamepadVibration const& left, GamepadVibration const& right) noexcept
{
    return left.LeftMotor == right.LeftMotor && left.RightMotor == right.RightMotor && left.LeftTrigger == right.LeftTrigger && left.RightTrigger == right.RightTrigger;
}

inline bool operator!=(GamepadVibration const& left, GamepadVibration const& right) noexcept
{
    return !(left == right);
}

struct RacingWheelReading
{
    uint64_t Timestamp;
    Windows::Gaming::Input::RacingWheelButtons Buttons;
    int32_t PatternShifterGear;
    double Wheel;
    double Throttle;
    double Brake;
    double Clutch;
    double Handbrake;
};

inline bool operator==(RacingWheelReading const& left, RacingWheelReading const& right) noexcept
{
    return left.Timestamp == right.Timestamp && left.Buttons == right.Buttons && left.PatternShifterGear == right.PatternShifterGear && left.Wheel == right.Wheel && left.Throttle == right.Throttle && left.Brake == right.Brake && left.Clutch == right.Clutch && left.Handbrake == right.Handbrake;
}

inline bool operator!=(RacingWheelReading const& left, RacingWheelReading const& right) noexcept
{
    return !(left == right);
}

struct UINavigationReading
{
    uint64_t Timestamp;
    Windows::Gaming::Input::RequiredUINavigationButtons RequiredButtons;
    Windows::Gaming::Input::OptionalUINavigationButtons OptionalButtons;
};

inline bool operator==(UINavigationReading const& left, UINavigationReading const& right) noexcept
{
    return left.Timestamp == right.Timestamp && left.RequiredButtons == right.RequiredButtons && left.OptionalButtons == right.OptionalButtons;
}

inline bool operator!=(UINavigationReading const& left, UINavigationReading const& right) noexcept
{
    return !(left == right);
}

}

namespace winrt::impl {

}

WINRT_EXPORT namespace winrt::Windows::Gaming::Input {

struct WINRT_EBO ArcadeStick :
    Windows::Gaming::Input::IArcadeStick,
    impl::require<ArcadeStick, Windows::Gaming::Input::IGameControllerBatteryInfo>
{
    ArcadeStick(std::nullptr_t) noexcept {}
    static winrt::event_token ArcadeStickAdded(Windows::Foundation::EventHandler<Windows::Gaming::Input::ArcadeStick> const& value);
    using ArcadeStickAdded_revoker = impl::factory_event_revoker<Windows::Gaming::Input::IArcadeStickStatics, &impl::abi_t<Windows::Gaming::Input::IArcadeStickStatics>::remove_ArcadeStickAdded>;
    static ArcadeStickAdded_revoker ArcadeStickAdded(auto_revoke_t, Windows::Foundation::EventHandler<Windows::Gaming::Input::ArcadeStick> const& value);
    static void ArcadeStickAdded(winrt::event_token const& token);
    static winrt::event_token ArcadeStickRemoved(Windows::Foundation::EventHandler<Windows::Gaming::Input::ArcadeStick> const& value);
    using ArcadeStickRemoved_revoker = impl::factory_event_revoker<Windows::Gaming::Input::IArcadeStickStatics, &impl::abi_t<Windows::Gaming::Input::IArcadeStickStatics>::remove_ArcadeStickRemoved>;
    static ArcadeStickRemoved_revoker ArcadeStickRemoved(auto_revoke_t, Windows::Foundation::EventHandler<Windows::Gaming::Input::ArcadeStick> const& value);
    static void ArcadeStickRemoved(winrt::event_token const& token);
    static Windows::Foundation::Collections::IVectorView<Windows::Gaming::Input::ArcadeStick> ArcadeSticks();
    static Windows::Gaming::Input::ArcadeStick FromGameController(Windows::Gaming::Input::IGameController const& gameController);
};

struct WINRT_EBO FlightStick :
    Windows::Gaming::Input::IFlightStick,
    impl::require<FlightStick, Windows::Gaming::Input::IGameControllerBatteryInfo>
{
    FlightStick(std::nullptr_t) noexcept {}
    static winrt::event_token FlightStickAdded(Windows::Foundation::EventHandler<Windows::Gaming::Input::FlightStick> const& value);
    using FlightStickAdded_revoker = impl::factory_event_revoker<Windows::Gaming::Input::IFlightStickStatics, &impl::abi_t<Windows::Gaming::Input::IFlightStickStatics>::remove_FlightStickAdded>;
    static FlightStickAdded_revoker FlightStickAdded(auto_revoke_t, Windows::Foundation::EventHandler<Windows::Gaming::Input::FlightStick> const& value);
    static void FlightStickAdded(winrt::event_token const& token);
    static winrt::event_token FlightStickRemoved(Windows::Foundation::EventHandler<Windows::Gaming::Input::FlightStick> const& value);
    using FlightStickRemoved_revoker = impl::factory_event_revoker<Windows::Gaming::Input::IFlightStickStatics, &impl::abi_t<Windows::Gaming::Input::IFlightStickStatics>::remove_FlightStickRemoved>;
    static FlightStickRemoved_revoker FlightStickRemoved(auto_revoke_t, Windows::Foundation::EventHandler<Windows::Gaming::Input::FlightStick> const& value);
    static void FlightStickRemoved(winrt::event_token const& token);
    static Windows::Foundation::Collections::IVectorView<Windows::Gaming::Input::FlightStick> FlightSticks();
    static Windows::Gaming::Input::FlightStick FromGameController(Windows::Gaming::Input::IGameController const& gameController);
};

struct WINRT_EBO Gamepad :
    Windows::Gaming::Input::IGamepad,
    impl::require<Gamepad, Windows::Gaming::Input::IGameControllerBatteryInfo, Windows::Gaming::Input::IGamepad2>
{
    Gamepad(std::nullptr_t) noexcept {}
    static winrt::event_token GamepadAdded(Windows::Foundation::EventHandler<Windows::Gaming::Input::Gamepad> const& value);
    using GamepadAdded_revoker = impl::factory_event_revoker<Windows::Gaming::Input::IGamepadStatics, &impl::abi_t<Windows::Gaming::Input::IGamepadStatics>::remove_GamepadAdded>;
    static GamepadAdded_revoker GamepadAdded(auto_revoke_t, Windows::Foundation::EventHandler<Windows::Gaming::Input::Gamepad> const& value);
    static void GamepadAdded(winrt::event_token const& token);
    static winrt::event_token GamepadRemoved(Windows::Foundation::EventHandler<Windows::Gaming::Input::Gamepad> const& value);
    using GamepadRemoved_revoker = impl::factory_event_revoker<Windows::Gaming::Input::IGamepadStatics, &impl::abi_t<Windows::Gaming::Input::IGamepadStatics>::remove_GamepadRemoved>;
    static GamepadRemoved_revoker GamepadRemoved(auto_revoke_t, Windows::Foundation::EventHandler<Windows::Gaming::Input::Gamepad> const& value);
    static void GamepadRemoved(winrt::event_token const& token);
    static Windows::Foundation::Collections::IVectorView<Windows::Gaming::Input::Gamepad> Gamepads();
    static Windows::Gaming::Input::Gamepad FromGameController(Windows::Gaming::Input::IGameController const& gameController);
};

struct WINRT_EBO Headset :
    Windows::Gaming::Input::IHeadset,
    impl::require<Headset, Windows::Gaming::Input::IGameControllerBatteryInfo>
{
    Headset(std::nullptr_t) noexcept {}
};

struct WINRT_EBO RacingWheel :
    Windows::Gaming::Input::IRacingWheel,
    impl::require<RacingWheel, Windows::Gaming::Input::IGameControllerBatteryInfo>
{
    RacingWheel(std::nullptr_t) noexcept {}
    static winrt::event_token RacingWheelAdded(Windows::Foundation::EventHandler<Windows::Gaming::Input::RacingWheel> const& value);
    using RacingWheelAdded_revoker = impl::factory_event_revoker<Windows::Gaming::Input::IRacingWheelStatics, &impl::abi_t<Windows::Gaming::Input::IRacingWheelStatics>::remove_RacingWheelAdded>;
    static RacingWheelAdded_revoker RacingWheelAdded(auto_revoke_t, Windows::Foundation::EventHandler<Windows::Gaming::Input::RacingWheel> const& value);
    static void RacingWheelAdded(winrt::event_token const& token);
    static winrt::event_token RacingWheelRemoved(Windows::Foundation::EventHandler<Windows::Gaming::Input::RacingWheel> const& value);
    using RacingWheelRemoved_revoker = impl::factory_event_revoker<Windows::Gaming::Input::IRacingWheelStatics, &impl::abi_t<Windows::Gaming::Input::IRacingWheelStatics>::remove_RacingWheelRemoved>;
    static RacingWheelRemoved_revoker RacingWheelRemoved(auto_revoke_t, Windows::Foundation::EventHandler<Windows::Gaming::Input::RacingWheel> const& value);
    static void RacingWheelRemoved(winrt::event_token const& token);
    static Windows::Foundation::Collections::IVectorView<Windows::Gaming::Input::RacingWheel> RacingWheels();
    static Windows::Gaming::Input::RacingWheel FromGameController(Windows::Gaming::Input::IGameController const& gameController);
};

struct WINRT_EBO RawGameController :
    Windows::Gaming::Input::IRawGameController,
    impl::require<RawGameController, Windows::Gaming::Input::IGameControllerBatteryInfo, Windows::Gaming::Input::IRawGameController2>
{
    RawGameController(std::nullptr_t) noexcept {}
    static winrt::event_token RawGameControllerAdded(Windows::Foundation::EventHandler<Windows::Gaming::Input::RawGameController> const& value);
    using RawGameControllerAdded_revoker = impl::factory_event_revoker<Windows::Gaming::Input::IRawGameControllerStatics, &impl::abi_t<Windows::Gaming::Input::IRawGameControllerStatics>::remove_RawGameControllerAdded>;
    static RawGameControllerAdded_revoker RawGameControllerAdded(auto_revoke_t, Windows::Foundation::EventHandler<Windows::Gaming::Input::RawGameController> const& value);
    static void RawGameControllerAdded(winrt::event_token const& token);
    static winrt::event_token RawGameControllerRemoved(Windows::Foundation::EventHandler<Windows::Gaming::Input::RawGameController> const& value);
    using RawGameControllerRemoved_revoker = impl::factory_event_revoker<Windows::Gaming::Input::IRawGameControllerStatics, &impl::abi_t<Windows::Gaming::Input::IRawGameControllerStatics>::remove_RawGameControllerRemoved>;
    static RawGameControllerRemoved_revoker RawGameControllerRemoved(auto_revoke_t, Windows::Foundation::EventHandler<Windows::Gaming::Input::RawGameController> const& value);
    static void RawGameControllerRemoved(winrt::event_token const& token);
    static Windows::Foundation::Collections::IVectorView<Windows::Gaming::Input::RawGameController> RawGameControllers();
    static Windows::Gaming::Input::RawGameController FromGameController(Windows::Gaming::Input::IGameController const& gameController);
};

struct WINRT_EBO UINavigationController :
    Windows::Gaming::Input::IUINavigationController,
    impl::require<UINavigationController, Windows::Gaming::Input::IGameControllerBatteryInfo>
{
    UINavigationController(std::nullptr_t) noexcept {}
    static winrt::event_token UINavigationControllerAdded(Windows::Foundation::EventHandler<Windows::Gaming::Input::UINavigationController> const& value);
    using UINavigationControllerAdded_revoker = impl::factory_event_revoker<Windows::Gaming::Input::IUINavigationControllerStatics, &impl::abi_t<Windows::Gaming::Input::IUINavigationControllerStatics>::remove_UINavigationControllerAdded>;
    static UINavigationControllerAdded_revoker UINavigationControllerAdded(auto_revoke_t, Windows::Foundation::EventHandler<Windows::Gaming::Input::UINavigationController> const& value);
    static void UINavigationControllerAdded(winrt::event_token const& token);
    static winrt::event_token UINavigationControllerRemoved(Windows::Foundation::EventHandler<Windows::Gaming::Input::UINavigationController> const& value);
    using UINavigationControllerRemoved_revoker = impl::factory_event_revoker<Windows::Gaming::Input::IUINavigationControllerStatics, &impl::abi_t<Windows::Gaming::Input::IUINavigationControllerStatics>::remove_UINavigationControllerRemoved>;
    static UINavigationControllerRemoved_revoker UINavigationControllerRemoved(auto_revoke_t, Windows::Foundation::EventHandler<Windows::Gaming::Input::UINavigationController> const& value);
    static void UINavigationControllerRemoved(winrt::event_token const& token);
    static Windows::Foundation::Collections::IVectorView<Windows::Gaming::Input::UINavigationController> UINavigationControllers();
    static Windows::Gaming::Input::UINavigationController FromGameController(Windows::Gaming::Input::IGameController const& gameController);
};

}
