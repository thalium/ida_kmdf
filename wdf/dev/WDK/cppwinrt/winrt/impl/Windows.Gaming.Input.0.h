// C++/WinRT v1.0.190111.3

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#pragma once

WINRT_EXPORT namespace winrt::Windows::Devices::Haptics {

struct SimpleHapticsController;

}

WINRT_EXPORT namespace winrt::Windows::Devices::Power {

struct BatteryReport;

}

WINRT_EXPORT namespace winrt::Windows::Gaming::Input::ForceFeedback {

struct ForceFeedbackMotor;

}

WINRT_EXPORT namespace winrt::Windows::System {

struct User;
struct UserChangedEventArgs;

}

WINRT_EXPORT namespace winrt::Windows::Gaming::Input {

enum class ArcadeStickButtons : uint32_t
{
    None = 0x0,
    StickUp = 0x1,
    StickDown = 0x2,
    StickLeft = 0x4,
    StickRight = 0x8,
    Action1 = 0x10,
    Action2 = 0x20,
    Action3 = 0x40,
    Action4 = 0x80,
    Action5 = 0x100,
    Action6 = 0x200,
    Special1 = 0x400,
    Special2 = 0x800,
};

enum class FlightStickButtons : uint32_t
{
    None = 0x0,
    FirePrimary = 0x1,
    FireSecondary = 0x2,
};

enum class GameControllerButtonLabel : int32_t
{
    None = 0,
    XboxBack = 1,
    XboxStart = 2,
    XboxMenu = 3,
    XboxView = 4,
    XboxUp = 5,
    XboxDown = 6,
    XboxLeft = 7,
    XboxRight = 8,
    XboxA = 9,
    XboxB = 10,
    XboxX = 11,
    XboxY = 12,
    XboxLeftBumper = 13,
    XboxLeftTrigger = 14,
    XboxLeftStickButton = 15,
    XboxRightBumper = 16,
    XboxRightTrigger = 17,
    XboxRightStickButton = 18,
    XboxPaddle1 = 19,
    XboxPaddle2 = 20,
    XboxPaddle3 = 21,
    XboxPaddle4 = 22,
    Mode = 23,
    Select = 24,
    Menu = 25,
    View = 26,
    Back = 27,
    Start = 28,
    Options = 29,
    Share = 30,
    Up = 31,
    Down = 32,
    Left = 33,
    Right = 34,
    LetterA = 35,
    LetterB = 36,
    LetterC = 37,
    LetterL = 38,
    LetterR = 39,
    LetterX = 40,
    LetterY = 41,
    LetterZ = 42,
    Cross = 43,
    Circle = 44,
    Square = 45,
    Triangle = 46,
    LeftBumper = 47,
    LeftTrigger = 48,
    LeftStickButton = 49,
    Left1 = 50,
    Left2 = 51,
    Left3 = 52,
    RightBumper = 53,
    RightTrigger = 54,
    RightStickButton = 55,
    Right1 = 56,
    Right2 = 57,
    Right3 = 58,
    Paddle1 = 59,
    Paddle2 = 60,
    Paddle3 = 61,
    Paddle4 = 62,
    Plus = 63,
    Minus = 64,
    DownLeftArrow = 65,
    DialLeft = 66,
    DialRight = 67,
    Suspension = 68,
};

enum class GameControllerSwitchKind : int32_t
{
    TwoWay = 0,
    FourWay = 1,
    EightWay = 2,
};

enum class GameControllerSwitchPosition : int32_t
{
    Center = 0,
    Up = 1,
    UpRight = 2,
    Right = 3,
    DownRight = 4,
    Down = 5,
    DownLeft = 6,
    Left = 7,
    UpLeft = 8,
};

enum class GamepadButtons : uint32_t
{
    None = 0x0,
    Menu = 0x1,
    View = 0x2,
    A = 0x4,
    B = 0x8,
    X = 0x10,
    Y = 0x20,
    DPadUp = 0x40,
    DPadDown = 0x80,
    DPadLeft = 0x100,
    DPadRight = 0x200,
    LeftShoulder = 0x400,
    RightShoulder = 0x800,
    LeftThumbstick = 0x1000,
    RightThumbstick = 0x2000,
    Paddle1 = 0x4000,
    Paddle2 = 0x8000,
    Paddle3 = 0x10000,
    Paddle4 = 0x20000,
};

enum class OptionalUINavigationButtons : uint32_t
{
    None = 0x0,
    Context1 = 0x1,
    Context2 = 0x2,
    Context3 = 0x4,
    Context4 = 0x8,
    PageUp = 0x10,
    PageDown = 0x20,
    PageLeft = 0x40,
    PageRight = 0x80,
    ScrollUp = 0x100,
    ScrollDown = 0x200,
    ScrollLeft = 0x400,
    ScrollRight = 0x800,
};

enum class RacingWheelButtons : uint32_t
{
    None = 0x0,
    PreviousGear = 0x1,
    NextGear = 0x2,
    DPadUp = 0x4,
    DPadDown = 0x8,
    DPadLeft = 0x10,
    DPadRight = 0x20,
    Button1 = 0x40,
    Button2 = 0x80,
    Button3 = 0x100,
    Button4 = 0x200,
    Button5 = 0x400,
    Button6 = 0x800,
    Button7 = 0x1000,
    Button8 = 0x2000,
    Button9 = 0x4000,
    Button10 = 0x8000,
    Button11 = 0x10000,
    Button12 = 0x20000,
    Button13 = 0x40000,
    Button14 = 0x80000,
    Button15 = 0x100000,
    Button16 = 0x200000,
};

enum class RequiredUINavigationButtons : uint32_t
{
    None = 0x0,
    Menu = 0x1,
    View = 0x2,
    Accept = 0x4,
    Cancel = 0x8,
    Up = 0x10,
    Down = 0x20,
    Left = 0x40,
    Right = 0x80,
};

struct IArcadeStick;
struct IArcadeStickStatics;
struct IArcadeStickStatics2;
struct IFlightStick;
struct IFlightStickStatics;
struct IGameController;
struct IGameControllerBatteryInfo;
struct IGamepad;
struct IGamepad2;
struct IGamepadStatics;
struct IGamepadStatics2;
struct IHeadset;
struct IRacingWheel;
struct IRacingWheelStatics;
struct IRacingWheelStatics2;
struct IRawGameController;
struct IRawGameController2;
struct IRawGameControllerStatics;
struct IUINavigationController;
struct IUINavigationControllerStatics;
struct IUINavigationControllerStatics2;
struct ArcadeStick;
struct FlightStick;
struct Gamepad;
struct Headset;
struct RacingWheel;
struct RawGameController;
struct UINavigationController;
struct ArcadeStickReading;
struct FlightStickReading;
struct GamepadReading;
struct GamepadVibration;
struct RacingWheelReading;
struct UINavigationReading;

}

namespace winrt::impl {

template<> struct is_enum_flag<Windows::Gaming::Input::ArcadeStickButtons> : std::true_type {};
template<> struct is_enum_flag<Windows::Gaming::Input::FlightStickButtons> : std::true_type {};
template<> struct is_enum_flag<Windows::Gaming::Input::GamepadButtons> : std::true_type {};
template<> struct is_enum_flag<Windows::Gaming::Input::OptionalUINavigationButtons> : std::true_type {};
template<> struct is_enum_flag<Windows::Gaming::Input::RacingWheelButtons> : std::true_type {};
template<> struct is_enum_flag<Windows::Gaming::Input::RequiredUINavigationButtons> : std::true_type {};
template <> struct category<Windows::Gaming::Input::IArcadeStick>{ using type = interface_category; };
template <> struct category<Windows::Gaming::Input::IArcadeStickStatics>{ using type = interface_category; };
template <> struct category<Windows::Gaming::Input::IArcadeStickStatics2>{ using type = interface_category; };
template <> struct category<Windows::Gaming::Input::IFlightStick>{ using type = interface_category; };
template <> struct category<Windows::Gaming::Input::IFlightStickStatics>{ using type = interface_category; };
template <> struct category<Windows::Gaming::Input::IGameController>{ using type = interface_category; };
template <> struct category<Windows::Gaming::Input::IGameControllerBatteryInfo>{ using type = interface_category; };
template <> struct category<Windows::Gaming::Input::IGamepad>{ using type = interface_category; };
template <> struct category<Windows::Gaming::Input::IGamepad2>{ using type = interface_category; };
template <> struct category<Windows::Gaming::Input::IGamepadStatics>{ using type = interface_category; };
template <> struct category<Windows::Gaming::Input::IGamepadStatics2>{ using type = interface_category; };
template <> struct category<Windows::Gaming::Input::IHeadset>{ using type = interface_category; };
template <> struct category<Windows::Gaming::Input::IRacingWheel>{ using type = interface_category; };
template <> struct category<Windows::Gaming::Input::IRacingWheelStatics>{ using type = interface_category; };
template <> struct category<Windows::Gaming::Input::IRacingWheelStatics2>{ using type = interface_category; };
template <> struct category<Windows::Gaming::Input::IRawGameController>{ using type = interface_category; };
template <> struct category<Windows::Gaming::Input::IRawGameController2>{ using type = interface_category; };
template <> struct category<Windows::Gaming::Input::IRawGameControllerStatics>{ using type = interface_category; };
template <> struct category<Windows::Gaming::Input::IUINavigationController>{ using type = interface_category; };
template <> struct category<Windows::Gaming::Input::IUINavigationControllerStatics>{ using type = interface_category; };
template <> struct category<Windows::Gaming::Input::IUINavigationControllerStatics2>{ using type = interface_category; };
template <> struct category<Windows::Gaming::Input::ArcadeStick>{ using type = class_category; };
template <> struct category<Windows::Gaming::Input::FlightStick>{ using type = class_category; };
template <> struct category<Windows::Gaming::Input::Gamepad>{ using type = class_category; };
template <> struct category<Windows::Gaming::Input::Headset>{ using type = class_category; };
template <> struct category<Windows::Gaming::Input::RacingWheel>{ using type = class_category; };
template <> struct category<Windows::Gaming::Input::RawGameController>{ using type = class_category; };
template <> struct category<Windows::Gaming::Input::UINavigationController>{ using type = class_category; };
template <> struct category<Windows::Gaming::Input::ArcadeStickButtons>{ using type = enum_category; };
template <> struct category<Windows::Gaming::Input::FlightStickButtons>{ using type = enum_category; };
template <> struct category<Windows::Gaming::Input::GameControllerButtonLabel>{ using type = enum_category; };
template <> struct category<Windows::Gaming::Input::GameControllerSwitchKind>{ using type = enum_category; };
template <> struct category<Windows::Gaming::Input::GameControllerSwitchPosition>{ using type = enum_category; };
template <> struct category<Windows::Gaming::Input::GamepadButtons>{ using type = enum_category; };
template <> struct category<Windows::Gaming::Input::OptionalUINavigationButtons>{ using type = enum_category; };
template <> struct category<Windows::Gaming::Input::RacingWheelButtons>{ using type = enum_category; };
template <> struct category<Windows::Gaming::Input::RequiredUINavigationButtons>{ using type = enum_category; };
template <> struct category<Windows::Gaming::Input::ArcadeStickReading>{ using type = struct_category<uint64_t,Windows::Gaming::Input::ArcadeStickButtons>; };
template <> struct category<Windows::Gaming::Input::FlightStickReading>{ using type = struct_category<uint64_t,Windows::Gaming::Input::FlightStickButtons,Windows::Gaming::Input::GameControllerSwitchPosition,double,double,double,double>; };
template <> struct category<Windows::Gaming::Input::GamepadReading>{ using type = struct_category<uint64_t,Windows::Gaming::Input::GamepadButtons,double,double,double,double,double,double>; };
template <> struct category<Windows::Gaming::Input::GamepadVibration>{ using type = struct_category<double,double,double,double>; };
template <> struct category<Windows::Gaming::Input::RacingWheelReading>{ using type = struct_category<uint64_t,Windows::Gaming::Input::RacingWheelButtons,int32_t,double,double,double,double,double>; };
template <> struct category<Windows::Gaming::Input::UINavigationReading>{ using type = struct_category<uint64_t,Windows::Gaming::Input::RequiredUINavigationButtons,Windows::Gaming::Input::OptionalUINavigationButtons>; };
template <> struct name<Windows::Gaming::Input::IArcadeStick>{ static constexpr auto & value{ L"Windows.Gaming.Input.IArcadeStick" }; };
template <> struct name<Windows::Gaming::Input::IArcadeStickStatics>{ static constexpr auto & value{ L"Windows.Gaming.Input.IArcadeStickStatics" }; };
template <> struct name<Windows::Gaming::Input::IArcadeStickStatics2>{ static constexpr auto & value{ L"Windows.Gaming.Input.IArcadeStickStatics2" }; };
template <> struct name<Windows::Gaming::Input::IFlightStick>{ static constexpr auto & value{ L"Windows.Gaming.Input.IFlightStick" }; };
template <> struct name<Windows::Gaming::Input::IFlightStickStatics>{ static constexpr auto & value{ L"Windows.Gaming.Input.IFlightStickStatics" }; };
template <> struct name<Windows::Gaming::Input::IGameController>{ static constexpr auto & value{ L"Windows.Gaming.Input.IGameController" }; };
template <> struct name<Windows::Gaming::Input::IGameControllerBatteryInfo>{ static constexpr auto & value{ L"Windows.Gaming.Input.IGameControllerBatteryInfo" }; };
template <> struct name<Windows::Gaming::Input::IGamepad>{ static constexpr auto & value{ L"Windows.Gaming.Input.IGamepad" }; };
template <> struct name<Windows::Gaming::Input::IGamepad2>{ static constexpr auto & value{ L"Windows.Gaming.Input.IGamepad2" }; };
template <> struct name<Windows::Gaming::Input::IGamepadStatics>{ static constexpr auto & value{ L"Windows.Gaming.Input.IGamepadStatics" }; };
template <> struct name<Windows::Gaming::Input::IGamepadStatics2>{ static constexpr auto & value{ L"Windows.Gaming.Input.IGamepadStatics2" }; };
template <> struct name<Windows::Gaming::Input::IHeadset>{ static constexpr auto & value{ L"Windows.Gaming.Input.IHeadset" }; };
template <> struct name<Windows::Gaming::Input::IRacingWheel>{ static constexpr auto & value{ L"Windows.Gaming.Input.IRacingWheel" }; };
template <> struct name<Windows::Gaming::Input::IRacingWheelStatics>{ static constexpr auto & value{ L"Windows.Gaming.Input.IRacingWheelStatics" }; };
template <> struct name<Windows::Gaming::Input::IRacingWheelStatics2>{ static constexpr auto & value{ L"Windows.Gaming.Input.IRacingWheelStatics2" }; };
template <> struct name<Windows::Gaming::Input::IRawGameController>{ static constexpr auto & value{ L"Windows.Gaming.Input.IRawGameController" }; };
template <> struct name<Windows::Gaming::Input::IRawGameController2>{ static constexpr auto & value{ L"Windows.Gaming.Input.IRawGameController2" }; };
template <> struct name<Windows::Gaming::Input::IRawGameControllerStatics>{ static constexpr auto & value{ L"Windows.Gaming.Input.IRawGameControllerStatics" }; };
template <> struct name<Windows::Gaming::Input::IUINavigationController>{ static constexpr auto & value{ L"Windows.Gaming.Input.IUINavigationController" }; };
template <> struct name<Windows::Gaming::Input::IUINavigationControllerStatics>{ static constexpr auto & value{ L"Windows.Gaming.Input.IUINavigationControllerStatics" }; };
template <> struct name<Windows::Gaming::Input::IUINavigationControllerStatics2>{ static constexpr auto & value{ L"Windows.Gaming.Input.IUINavigationControllerStatics2" }; };
template <> struct name<Windows::Gaming::Input::ArcadeStick>{ static constexpr auto & value{ L"Windows.Gaming.Input.ArcadeStick" }; };
template <> struct name<Windows::Gaming::Input::FlightStick>{ static constexpr auto & value{ L"Windows.Gaming.Input.FlightStick" }; };
template <> struct name<Windows::Gaming::Input::Gamepad>{ static constexpr auto & value{ L"Windows.Gaming.Input.Gamepad" }; };
template <> struct name<Windows::Gaming::Input::Headset>{ static constexpr auto & value{ L"Windows.Gaming.Input.Headset" }; };
template <> struct name<Windows::Gaming::Input::RacingWheel>{ static constexpr auto & value{ L"Windows.Gaming.Input.RacingWheel" }; };
template <> struct name<Windows::Gaming::Input::RawGameController>{ static constexpr auto & value{ L"Windows.Gaming.Input.RawGameController" }; };
template <> struct name<Windows::Gaming::Input::UINavigationController>{ static constexpr auto & value{ L"Windows.Gaming.Input.UINavigationController" }; };
template <> struct name<Windows::Gaming::Input::ArcadeStickButtons>{ static constexpr auto & value{ L"Windows.Gaming.Input.ArcadeStickButtons" }; };
template <> struct name<Windows::Gaming::Input::FlightStickButtons>{ static constexpr auto & value{ L"Windows.Gaming.Input.FlightStickButtons" }; };
template <> struct name<Windows::Gaming::Input::GameControllerButtonLabel>{ static constexpr auto & value{ L"Windows.Gaming.Input.GameControllerButtonLabel" }; };
template <> struct name<Windows::Gaming::Input::GameControllerSwitchKind>{ static constexpr auto & value{ L"Windows.Gaming.Input.GameControllerSwitchKind" }; };
template <> struct name<Windows::Gaming::Input::GameControllerSwitchPosition>{ static constexpr auto & value{ L"Windows.Gaming.Input.GameControllerSwitchPosition" }; };
template <> struct name<Windows::Gaming::Input::GamepadButtons>{ static constexpr auto & value{ L"Windows.Gaming.Input.GamepadButtons" }; };
template <> struct name<Windows::Gaming::Input::OptionalUINavigationButtons>{ static constexpr auto & value{ L"Windows.Gaming.Input.OptionalUINavigationButtons" }; };
template <> struct name<Windows::Gaming::Input::RacingWheelButtons>{ static constexpr auto & value{ L"Windows.Gaming.Input.RacingWheelButtons" }; };
template <> struct name<Windows::Gaming::Input::RequiredUINavigationButtons>{ static constexpr auto & value{ L"Windows.Gaming.Input.RequiredUINavigationButtons" }; };
template <> struct name<Windows::Gaming::Input::ArcadeStickReading>{ static constexpr auto & value{ L"Windows.Gaming.Input.ArcadeStickReading" }; };
template <> struct name<Windows::Gaming::Input::FlightStickReading>{ static constexpr auto & value{ L"Windows.Gaming.Input.FlightStickReading" }; };
template <> struct name<Windows::Gaming::Input::GamepadReading>{ static constexpr auto & value{ L"Windows.Gaming.Input.GamepadReading" }; };
template <> struct name<Windows::Gaming::Input::GamepadVibration>{ static constexpr auto & value{ L"Windows.Gaming.Input.GamepadVibration" }; };
template <> struct name<Windows::Gaming::Input::RacingWheelReading>{ static constexpr auto & value{ L"Windows.Gaming.Input.RacingWheelReading" }; };
template <> struct name<Windows::Gaming::Input::UINavigationReading>{ static constexpr auto & value{ L"Windows.Gaming.Input.UINavigationReading" }; };
template <> struct guid_storage<Windows::Gaming::Input::IArcadeStick>{ static constexpr guid value{ 0xB14A539D,0xBEFB,0x4C81,{ 0x80,0x51,0x15,0xEC,0xF3,0xB1,0x30,0x36 } }; };
template <> struct guid_storage<Windows::Gaming::Input::IArcadeStickStatics>{ static constexpr guid value{ 0x5C37B8C8,0x37B1,0x4AD8,{ 0x94,0x58,0x20,0x0F,0x1A,0x30,0x01,0x8E } }; };
template <> struct guid_storage<Windows::Gaming::Input::IArcadeStickStatics2>{ static constexpr guid value{ 0x52B5D744,0xBB86,0x445A,{ 0xB5,0x9C,0x59,0x6F,0x0E,0x2A,0x49,0xDF } }; };
template <> struct guid_storage<Windows::Gaming::Input::IFlightStick>{ static constexpr guid value{ 0xB4A2C01C,0xB83B,0x4459,{ 0xA1,0xA9,0x97,0xB0,0x3C,0x33,0xDA,0x7C } }; };
template <> struct guid_storage<Windows::Gaming::Input::IFlightStickStatics>{ static constexpr guid value{ 0x5514924A,0xFECC,0x435E,{ 0x83,0xDC,0x5C,0xEC,0x8A,0x18,0xA5,0x20 } }; };
template <> struct guid_storage<Windows::Gaming::Input::IGameController>{ static constexpr guid value{ 0x1BAF6522,0x5F64,0x42C5,{ 0x82,0x67,0xB9,0xFE,0x22,0x15,0xBF,0xBD } }; };
template <> struct guid_storage<Windows::Gaming::Input::IGameControllerBatteryInfo>{ static constexpr guid value{ 0xDCECC681,0x3963,0x4DA6,{ 0x95,0x5D,0x55,0x3F,0x3B,0x6F,0x61,0x61 } }; };
template <> struct guid_storage<Windows::Gaming::Input::IGamepad>{ static constexpr guid value{ 0xBC7BB43C,0x0A69,0x3903,{ 0x9E,0x9D,0xA5,0x0F,0x86,0xA4,0x5D,0xE5 } }; };
template <> struct guid_storage<Windows::Gaming::Input::IGamepad2>{ static constexpr guid value{ 0x3C1689BD,0x5915,0x4245,{ 0xB0,0xC0,0xC8,0x9F,0xAE,0x03,0x08,0xFF } }; };
template <> struct guid_storage<Windows::Gaming::Input::IGamepadStatics>{ static constexpr guid value{ 0x8BBCE529,0xD49C,0x39E9,{ 0x95,0x60,0xE4,0x7D,0xDE,0x96,0xB7,0xC8 } }; };
template <> struct guid_storage<Windows::Gaming::Input::IGamepadStatics2>{ static constexpr guid value{ 0x42676DC5,0x0856,0x47C4,{ 0x92,0x13,0xB3,0x95,0x50,0x4C,0x3A,0x3C } }; };
template <> struct guid_storage<Windows::Gaming::Input::IHeadset>{ static constexpr guid value{ 0x3FD156EF,0x6925,0x3FA8,{ 0x91,0x81,0x02,0x9C,0x52,0x23,0xAE,0x3B } }; };
template <> struct guid_storage<Windows::Gaming::Input::IRacingWheel>{ static constexpr guid value{ 0xF546656F,0xE106,0x4C82,{ 0xA9,0x0F,0x55,0x40,0x12,0x90,0x4B,0x85 } }; };
template <> struct guid_storage<Windows::Gaming::Input::IRacingWheelStatics>{ static constexpr guid value{ 0x3AC12CD5,0x581B,0x4936,{ 0x9F,0x94,0x69,0xF1,0xE6,0x51,0x4C,0x7D } }; };
template <> struct guid_storage<Windows::Gaming::Input::IRacingWheelStatics2>{ static constexpr guid value{ 0xE666BCAA,0xEDFD,0x4323,{ 0xA9,0xF6,0x3C,0x38,0x40,0x48,0xD1,0xED } }; };
template <> struct guid_storage<Windows::Gaming::Input::IRawGameController>{ static constexpr guid value{ 0x7CAD6D91,0xA7E1,0x4F71,{ 0x9A,0x78,0x33,0xE9,0xC5,0xDF,0xEA,0x62 } }; };
template <> struct guid_storage<Windows::Gaming::Input::IRawGameController2>{ static constexpr guid value{ 0x43C0C035,0xBB73,0x4756,{ 0xA7,0x87,0x3E,0xD6,0xBE,0xA6,0x17,0xBD } }; };
template <> struct guid_storage<Windows::Gaming::Input::IRawGameControllerStatics>{ static constexpr guid value{ 0xEB8D0792,0xE95A,0x4B19,{ 0xAF,0xC7,0x0A,0x59,0xF8,0xBF,0x75,0x9E } }; };
template <> struct guid_storage<Windows::Gaming::Input::IUINavigationController>{ static constexpr guid value{ 0xE5AEEFDD,0xF50E,0x4A55,{ 0x8C,0xDC,0xD3,0x32,0x29,0x54,0x81,0x75 } }; };
template <> struct guid_storage<Windows::Gaming::Input::IUINavigationControllerStatics>{ static constexpr guid value{ 0x2F14930A,0xF6F8,0x4A48,{ 0x8D,0x89,0x94,0x78,0x6C,0xCA,0x0C,0x2E } }; };
template <> struct guid_storage<Windows::Gaming::Input::IUINavigationControllerStatics2>{ static constexpr guid value{ 0xE0CB28E3,0xB20B,0x4B0B,{ 0x9E,0xD4,0xF3,0xD5,0x3C,0xEC,0x0D,0xE4 } }; };
template <> struct default_interface<Windows::Gaming::Input::ArcadeStick>{ using type = Windows::Gaming::Input::IArcadeStick; };
template <> struct default_interface<Windows::Gaming::Input::FlightStick>{ using type = Windows::Gaming::Input::IFlightStick; };
template <> struct default_interface<Windows::Gaming::Input::Gamepad>{ using type = Windows::Gaming::Input::IGamepad; };
template <> struct default_interface<Windows::Gaming::Input::Headset>{ using type = Windows::Gaming::Input::IHeadset; };
template <> struct default_interface<Windows::Gaming::Input::RacingWheel>{ using type = Windows::Gaming::Input::IRacingWheel; };
template <> struct default_interface<Windows::Gaming::Input::RawGameController>{ using type = Windows::Gaming::Input::IRawGameController; };
template <> struct default_interface<Windows::Gaming::Input::UINavigationController>{ using type = Windows::Gaming::Input::IUINavigationController; };

template <> struct abi<Windows::Gaming::Input::IArcadeStick>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL GetButtonLabel(Windows::Gaming::Input::ArcadeStickButtons button, Windows::Gaming::Input::GameControllerButtonLabel* value) noexcept = 0;
    virtual int32_t WINRT_CALL GetCurrentReading(struct struct_Windows_Gaming_Input_ArcadeStickReading* value) noexcept = 0;
};};

template <> struct abi<Windows::Gaming::Input::IArcadeStickStatics>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL add_ArcadeStickAdded(void* value, winrt::event_token* token) noexcept = 0;
    virtual int32_t WINRT_CALL remove_ArcadeStickAdded(winrt::event_token token) noexcept = 0;
    virtual int32_t WINRT_CALL add_ArcadeStickRemoved(void* value, winrt::event_token* token) noexcept = 0;
    virtual int32_t WINRT_CALL remove_ArcadeStickRemoved(winrt::event_token token) noexcept = 0;
    virtual int32_t WINRT_CALL get_ArcadeSticks(void** value) noexcept = 0;
};};

template <> struct abi<Windows::Gaming::Input::IArcadeStickStatics2>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL FromGameController(void* gameController, void** value) noexcept = 0;
};};

template <> struct abi<Windows::Gaming::Input::IFlightStick>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL get_HatSwitchKind(Windows::Gaming::Input::GameControllerSwitchKind* value) noexcept = 0;
    virtual int32_t WINRT_CALL GetButtonLabel(Windows::Gaming::Input::FlightStickButtons button, Windows::Gaming::Input::GameControllerButtonLabel* value) noexcept = 0;
    virtual int32_t WINRT_CALL GetCurrentReading(struct struct_Windows_Gaming_Input_FlightStickReading* value) noexcept = 0;
};};

template <> struct abi<Windows::Gaming::Input::IFlightStickStatics>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL add_FlightStickAdded(void* value, winrt::event_token* token) noexcept = 0;
    virtual int32_t WINRT_CALL remove_FlightStickAdded(winrt::event_token token) noexcept = 0;
    virtual int32_t WINRT_CALL add_FlightStickRemoved(void* value, winrt::event_token* token) noexcept = 0;
    virtual int32_t WINRT_CALL remove_FlightStickRemoved(winrt::event_token token) noexcept = 0;
    virtual int32_t WINRT_CALL get_FlightSticks(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL FromGameController(void* gameController, void** value) noexcept = 0;
};};

template <> struct abi<Windows::Gaming::Input::IGameController>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL add_HeadsetConnected(void* value, winrt::event_token* token) noexcept = 0;
    virtual int32_t WINRT_CALL remove_HeadsetConnected(winrt::event_token token) noexcept = 0;
    virtual int32_t WINRT_CALL add_HeadsetDisconnected(void* value, winrt::event_token* token) noexcept = 0;
    virtual int32_t WINRT_CALL remove_HeadsetDisconnected(winrt::event_token token) noexcept = 0;
    virtual int32_t WINRT_CALL add_UserChanged(void* value, winrt::event_token* token) noexcept = 0;
    virtual int32_t WINRT_CALL remove_UserChanged(winrt::event_token token) noexcept = 0;
    virtual int32_t WINRT_CALL get_Headset(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_IsWireless(bool* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_User(void** value) noexcept = 0;
};};

template <> struct abi<Windows::Gaming::Input::IGameControllerBatteryInfo>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL TryGetBatteryReport(void** value) noexcept = 0;
};};

template <> struct abi<Windows::Gaming::Input::IGamepad>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL get_Vibration(struct struct_Windows_Gaming_Input_GamepadVibration* value) noexcept = 0;
    virtual int32_t WINRT_CALL put_Vibration(struct struct_Windows_Gaming_Input_GamepadVibration value) noexcept = 0;
    virtual int32_t WINRT_CALL GetCurrentReading(struct struct_Windows_Gaming_Input_GamepadReading* value) noexcept = 0;
};};

template <> struct abi<Windows::Gaming::Input::IGamepad2>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL GetButtonLabel(Windows::Gaming::Input::GamepadButtons button, Windows::Gaming::Input::GameControllerButtonLabel* value) noexcept = 0;
};};

template <> struct abi<Windows::Gaming::Input::IGamepadStatics>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL add_GamepadAdded(void* value, winrt::event_token* token) noexcept = 0;
    virtual int32_t WINRT_CALL remove_GamepadAdded(winrt::event_token token) noexcept = 0;
    virtual int32_t WINRT_CALL add_GamepadRemoved(void* value, winrt::event_token* token) noexcept = 0;
    virtual int32_t WINRT_CALL remove_GamepadRemoved(winrt::event_token token) noexcept = 0;
    virtual int32_t WINRT_CALL get_Gamepads(void** value) noexcept = 0;
};};

template <> struct abi<Windows::Gaming::Input::IGamepadStatics2>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL FromGameController(void* gameController, void** value) noexcept = 0;
};};

template <> struct abi<Windows::Gaming::Input::IHeadset>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL get_CaptureDeviceId(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_RenderDeviceId(void** value) noexcept = 0;
};};

template <> struct abi<Windows::Gaming::Input::IRacingWheel>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL get_HasClutch(bool* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_HasHandbrake(bool* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_HasPatternShifter(bool* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_MaxPatternShifterGear(int32_t* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_MaxWheelAngle(double* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_WheelMotor(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL GetButtonLabel(Windows::Gaming::Input::RacingWheelButtons button, Windows::Gaming::Input::GameControllerButtonLabel* value) noexcept = 0;
    virtual int32_t WINRT_CALL GetCurrentReading(struct struct_Windows_Gaming_Input_RacingWheelReading* value) noexcept = 0;
};};

template <> struct abi<Windows::Gaming::Input::IRacingWheelStatics>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL add_RacingWheelAdded(void* value, winrt::event_token* token) noexcept = 0;
    virtual int32_t WINRT_CALL remove_RacingWheelAdded(winrt::event_token token) noexcept = 0;
    virtual int32_t WINRT_CALL add_RacingWheelRemoved(void* value, winrt::event_token* token) noexcept = 0;
    virtual int32_t WINRT_CALL remove_RacingWheelRemoved(winrt::event_token token) noexcept = 0;
    virtual int32_t WINRT_CALL get_RacingWheels(void** value) noexcept = 0;
};};

template <> struct abi<Windows::Gaming::Input::IRacingWheelStatics2>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL FromGameController(void* gameController, void** value) noexcept = 0;
};};

template <> struct abi<Windows::Gaming::Input::IRawGameController>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL get_AxisCount(int32_t* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_ButtonCount(int32_t* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_ForceFeedbackMotors(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_HardwareProductId(uint16_t* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_HardwareVendorId(uint16_t* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_SwitchCount(int32_t* value) noexcept = 0;
    virtual int32_t WINRT_CALL GetButtonLabel(int32_t buttonIndex, Windows::Gaming::Input::GameControllerButtonLabel* value) noexcept = 0;
    virtual int32_t WINRT_CALL GetCurrentReading(uint32_t __buttonArraySize, bool* buttonArray, uint32_t __switchArraySize, Windows::Gaming::Input::GameControllerSwitchPosition* switchArray, uint32_t __axisArraySize, double* axisArray, uint64_t* timestamp) noexcept = 0;
    virtual int32_t WINRT_CALL GetSwitchKind(int32_t switchIndex, Windows::Gaming::Input::GameControllerSwitchKind* value) noexcept = 0;
};};

template <> struct abi<Windows::Gaming::Input::IRawGameController2>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL get_SimpleHapticsControllers(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_NonRoamableId(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_DisplayName(void** value) noexcept = 0;
};};

template <> struct abi<Windows::Gaming::Input::IRawGameControllerStatics>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL add_RawGameControllerAdded(void* value, winrt::event_token* token) noexcept = 0;
    virtual int32_t WINRT_CALL remove_RawGameControllerAdded(winrt::event_token token) noexcept = 0;
    virtual int32_t WINRT_CALL add_RawGameControllerRemoved(void* value, winrt::event_token* token) noexcept = 0;
    virtual int32_t WINRT_CALL remove_RawGameControllerRemoved(winrt::event_token token) noexcept = 0;
    virtual int32_t WINRT_CALL get_RawGameControllers(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL FromGameController(void* gameController, void** value) noexcept = 0;
};};

template <> struct abi<Windows::Gaming::Input::IUINavigationController>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL GetCurrentReading(struct struct_Windows_Gaming_Input_UINavigationReading* value) noexcept = 0;
    virtual int32_t WINRT_CALL GetOptionalButtonLabel(Windows::Gaming::Input::OptionalUINavigationButtons button, Windows::Gaming::Input::GameControllerButtonLabel* value) noexcept = 0;
    virtual int32_t WINRT_CALL GetRequiredButtonLabel(Windows::Gaming::Input::RequiredUINavigationButtons button, Windows::Gaming::Input::GameControllerButtonLabel* value) noexcept = 0;
};};

template <> struct abi<Windows::Gaming::Input::IUINavigationControllerStatics>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL add_UINavigationControllerAdded(void* value, winrt::event_token* token) noexcept = 0;
    virtual int32_t WINRT_CALL remove_UINavigationControllerAdded(winrt::event_token token) noexcept = 0;
    virtual int32_t WINRT_CALL add_UINavigationControllerRemoved(void* value, winrt::event_token* token) noexcept = 0;
    virtual int32_t WINRT_CALL remove_UINavigationControllerRemoved(winrt::event_token token) noexcept = 0;
    virtual int32_t WINRT_CALL get_UINavigationControllers(void** value) noexcept = 0;
};};

template <> struct abi<Windows::Gaming::Input::IUINavigationControllerStatics2>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL FromGameController(void* gameController, void** value) noexcept = 0;
};};

template <typename D>
struct consume_Windows_Gaming_Input_IArcadeStick
{
    Windows::Gaming::Input::GameControllerButtonLabel GetButtonLabel(Windows::Gaming::Input::ArcadeStickButtons const& button) const;
    Windows::Gaming::Input::ArcadeStickReading GetCurrentReading() const;
};
template <> struct consume<Windows::Gaming::Input::IArcadeStick> { template <typename D> using type = consume_Windows_Gaming_Input_IArcadeStick<D>; };

template <typename D>
struct consume_Windows_Gaming_Input_IArcadeStickStatics
{
    winrt::event_token ArcadeStickAdded(Windows::Foundation::EventHandler<Windows::Gaming::Input::ArcadeStick> const& value) const;
    using ArcadeStickAdded_revoker = impl::event_revoker<Windows::Gaming::Input::IArcadeStickStatics, &impl::abi_t<Windows::Gaming::Input::IArcadeStickStatics>::remove_ArcadeStickAdded>;
    ArcadeStickAdded_revoker ArcadeStickAdded(auto_revoke_t, Windows::Foundation::EventHandler<Windows::Gaming::Input::ArcadeStick> const& value) const;
    void ArcadeStickAdded(winrt::event_token const& token) const noexcept;
    winrt::event_token ArcadeStickRemoved(Windows::Foundation::EventHandler<Windows::Gaming::Input::ArcadeStick> const& value) const;
    using ArcadeStickRemoved_revoker = impl::event_revoker<Windows::Gaming::Input::IArcadeStickStatics, &impl::abi_t<Windows::Gaming::Input::IArcadeStickStatics>::remove_ArcadeStickRemoved>;
    ArcadeStickRemoved_revoker ArcadeStickRemoved(auto_revoke_t, Windows::Foundation::EventHandler<Windows::Gaming::Input::ArcadeStick> const& value) const;
    void ArcadeStickRemoved(winrt::event_token const& token) const noexcept;
    Windows::Foundation::Collections::IVectorView<Windows::Gaming::Input::ArcadeStick> ArcadeSticks() const;
};
template <> struct consume<Windows::Gaming::Input::IArcadeStickStatics> { template <typename D> using type = consume_Windows_Gaming_Input_IArcadeStickStatics<D>; };

template <typename D>
struct consume_Windows_Gaming_Input_IArcadeStickStatics2
{
    Windows::Gaming::Input::ArcadeStick FromGameController(Windows::Gaming::Input::IGameController const& gameController) const;
};
template <> struct consume<Windows::Gaming::Input::IArcadeStickStatics2> { template <typename D> using type = consume_Windows_Gaming_Input_IArcadeStickStatics2<D>; };

template <typename D>
struct consume_Windows_Gaming_Input_IFlightStick
{
    Windows::Gaming::Input::GameControllerSwitchKind HatSwitchKind() const;
    Windows::Gaming::Input::GameControllerButtonLabel GetButtonLabel(Windows::Gaming::Input::FlightStickButtons const& button) const;
    Windows::Gaming::Input::FlightStickReading GetCurrentReading() const;
};
template <> struct consume<Windows::Gaming::Input::IFlightStick> { template <typename D> using type = consume_Windows_Gaming_Input_IFlightStick<D>; };

template <typename D>
struct consume_Windows_Gaming_Input_IFlightStickStatics
{
    winrt::event_token FlightStickAdded(Windows::Foundation::EventHandler<Windows::Gaming::Input::FlightStick> const& value) const;
    using FlightStickAdded_revoker = impl::event_revoker<Windows::Gaming::Input::IFlightStickStatics, &impl::abi_t<Windows::Gaming::Input::IFlightStickStatics>::remove_FlightStickAdded>;
    FlightStickAdded_revoker FlightStickAdded(auto_revoke_t, Windows::Foundation::EventHandler<Windows::Gaming::Input::FlightStick> const& value) const;
    void FlightStickAdded(winrt::event_token const& token) const noexcept;
    winrt::event_token FlightStickRemoved(Windows::Foundation::EventHandler<Windows::Gaming::Input::FlightStick> const& value) const;
    using FlightStickRemoved_revoker = impl::event_revoker<Windows::Gaming::Input::IFlightStickStatics, &impl::abi_t<Windows::Gaming::Input::IFlightStickStatics>::remove_FlightStickRemoved>;
    FlightStickRemoved_revoker FlightStickRemoved(auto_revoke_t, Windows::Foundation::EventHandler<Windows::Gaming::Input::FlightStick> const& value) const;
    void FlightStickRemoved(winrt::event_token const& token) const noexcept;
    Windows::Foundation::Collections::IVectorView<Windows::Gaming::Input::FlightStick> FlightSticks() const;
    Windows::Gaming::Input::FlightStick FromGameController(Windows::Gaming::Input::IGameController const& gameController) const;
};
template <> struct consume<Windows::Gaming::Input::IFlightStickStatics> { template <typename D> using type = consume_Windows_Gaming_Input_IFlightStickStatics<D>; };

template <typename D>
struct consume_Windows_Gaming_Input_IGameController
{
    winrt::event_token HeadsetConnected(Windows::Foundation::TypedEventHandler<Windows::Gaming::Input::IGameController, Windows::Gaming::Input::Headset> const& value) const;
    using HeadsetConnected_revoker = impl::event_revoker<Windows::Gaming::Input::IGameController, &impl::abi_t<Windows::Gaming::Input::IGameController>::remove_HeadsetConnected>;
    HeadsetConnected_revoker HeadsetConnected(auto_revoke_t, Windows::Foundation::TypedEventHandler<Windows::Gaming::Input::IGameController, Windows::Gaming::Input::Headset> const& value) const;
    void HeadsetConnected(winrt::event_token const& token) const noexcept;
    winrt::event_token HeadsetDisconnected(Windows::Foundation::TypedEventHandler<Windows::Gaming::Input::IGameController, Windows::Gaming::Input::Headset> const& value) const;
    using HeadsetDisconnected_revoker = impl::event_revoker<Windows::Gaming::Input::IGameController, &impl::abi_t<Windows::Gaming::Input::IGameController>::remove_HeadsetDisconnected>;
    HeadsetDisconnected_revoker HeadsetDisconnected(auto_revoke_t, Windows::Foundation::TypedEventHandler<Windows::Gaming::Input::IGameController, Windows::Gaming::Input::Headset> const& value) const;
    void HeadsetDisconnected(winrt::event_token const& token) const noexcept;
    winrt::event_token UserChanged(Windows::Foundation::TypedEventHandler<Windows::Gaming::Input::IGameController, Windows::System::UserChangedEventArgs> const& value) const;
    using UserChanged_revoker = impl::event_revoker<Windows::Gaming::Input::IGameController, &impl::abi_t<Windows::Gaming::Input::IGameController>::remove_UserChanged>;
    UserChanged_revoker UserChanged(auto_revoke_t, Windows::Foundation::TypedEventHandler<Windows::Gaming::Input::IGameController, Windows::System::UserChangedEventArgs> const& value) const;
    void UserChanged(winrt::event_token const& token) const noexcept;
    Windows::Gaming::Input::Headset Headset() const;
    bool IsWireless() const;
    Windows::System::User User() const;
};
template <> struct consume<Windows::Gaming::Input::IGameController> { template <typename D> using type = consume_Windows_Gaming_Input_IGameController<D>; };

template <typename D>
struct consume_Windows_Gaming_Input_IGameControllerBatteryInfo
{
    Windows::Devices::Power::BatteryReport TryGetBatteryReport() const;
};
template <> struct consume<Windows::Gaming::Input::IGameControllerBatteryInfo> { template <typename D> using type = consume_Windows_Gaming_Input_IGameControllerBatteryInfo<D>; };

template <typename D>
struct consume_Windows_Gaming_Input_IGamepad
{
    Windows::Gaming::Input::GamepadVibration Vibration() const;
    void Vibration(Windows::Gaming::Input::GamepadVibration const& value) const;
    Windows::Gaming::Input::GamepadReading GetCurrentReading() const;
};
template <> struct consume<Windows::Gaming::Input::IGamepad> { template <typename D> using type = consume_Windows_Gaming_Input_IGamepad<D>; };

template <typename D>
struct consume_Windows_Gaming_Input_IGamepad2
{
    Windows::Gaming::Input::GameControllerButtonLabel GetButtonLabel(Windows::Gaming::Input::GamepadButtons const& button) const;
};
template <> struct consume<Windows::Gaming::Input::IGamepad2> { template <typename D> using type = consume_Windows_Gaming_Input_IGamepad2<D>; };

template <typename D>
struct consume_Windows_Gaming_Input_IGamepadStatics
{
    winrt::event_token GamepadAdded(Windows::Foundation::EventHandler<Windows::Gaming::Input::Gamepad> const& value) const;
    using GamepadAdded_revoker = impl::event_revoker<Windows::Gaming::Input::IGamepadStatics, &impl::abi_t<Windows::Gaming::Input::IGamepadStatics>::remove_GamepadAdded>;
    GamepadAdded_revoker GamepadAdded(auto_revoke_t, Windows::Foundation::EventHandler<Windows::Gaming::Input::Gamepad> const& value) const;
    void GamepadAdded(winrt::event_token const& token) const noexcept;
    winrt::event_token GamepadRemoved(Windows::Foundation::EventHandler<Windows::Gaming::Input::Gamepad> const& value) const;
    using GamepadRemoved_revoker = impl::event_revoker<Windows::Gaming::Input::IGamepadStatics, &impl::abi_t<Windows::Gaming::Input::IGamepadStatics>::remove_GamepadRemoved>;
    GamepadRemoved_revoker GamepadRemoved(auto_revoke_t, Windows::Foundation::EventHandler<Windows::Gaming::Input::Gamepad> const& value) const;
    void GamepadRemoved(winrt::event_token const& token) const noexcept;
    Windows::Foundation::Collections::IVectorView<Windows::Gaming::Input::Gamepad> Gamepads() const;
};
template <> struct consume<Windows::Gaming::Input::IGamepadStatics> { template <typename D> using type = consume_Windows_Gaming_Input_IGamepadStatics<D>; };

template <typename D>
struct consume_Windows_Gaming_Input_IGamepadStatics2
{
    Windows::Gaming::Input::Gamepad FromGameController(Windows::Gaming::Input::IGameController const& gameController) const;
};
template <> struct consume<Windows::Gaming::Input::IGamepadStatics2> { template <typename D> using type = consume_Windows_Gaming_Input_IGamepadStatics2<D>; };

template <typename D>
struct consume_Windows_Gaming_Input_IHeadset
{
    hstring CaptureDeviceId() const;
    hstring RenderDeviceId() const;
};
template <> struct consume<Windows::Gaming::Input::IHeadset> { template <typename D> using type = consume_Windows_Gaming_Input_IHeadset<D>; };

template <typename D>
struct consume_Windows_Gaming_Input_IRacingWheel
{
    bool HasClutch() const;
    bool HasHandbrake() const;
    bool HasPatternShifter() const;
    int32_t MaxPatternShifterGear() const;
    double MaxWheelAngle() const;
    Windows::Gaming::Input::ForceFeedback::ForceFeedbackMotor WheelMotor() const;
    Windows::Gaming::Input::GameControllerButtonLabel GetButtonLabel(Windows::Gaming::Input::RacingWheelButtons const& button) const;
    Windows::Gaming::Input::RacingWheelReading GetCurrentReading() const;
};
template <> struct consume<Windows::Gaming::Input::IRacingWheel> { template <typename D> using type = consume_Windows_Gaming_Input_IRacingWheel<D>; };

template <typename D>
struct consume_Windows_Gaming_Input_IRacingWheelStatics
{
    winrt::event_token RacingWheelAdded(Windows::Foundation::EventHandler<Windows::Gaming::Input::RacingWheel> const& value) const;
    using RacingWheelAdded_revoker = impl::event_revoker<Windows::Gaming::Input::IRacingWheelStatics, &impl::abi_t<Windows::Gaming::Input::IRacingWheelStatics>::remove_RacingWheelAdded>;
    RacingWheelAdded_revoker RacingWheelAdded(auto_revoke_t, Windows::Foundation::EventHandler<Windows::Gaming::Input::RacingWheel> const& value) const;
    void RacingWheelAdded(winrt::event_token const& token) const noexcept;
    winrt::event_token RacingWheelRemoved(Windows::Foundation::EventHandler<Windows::Gaming::Input::RacingWheel> const& value) const;
    using RacingWheelRemoved_revoker = impl::event_revoker<Windows::Gaming::Input::IRacingWheelStatics, &impl::abi_t<Windows::Gaming::Input::IRacingWheelStatics>::remove_RacingWheelRemoved>;
    RacingWheelRemoved_revoker RacingWheelRemoved(auto_revoke_t, Windows::Foundation::EventHandler<Windows::Gaming::Input::RacingWheel> const& value) const;
    void RacingWheelRemoved(winrt::event_token const& token) const noexcept;
    Windows::Foundation::Collections::IVectorView<Windows::Gaming::Input::RacingWheel> RacingWheels() const;
};
template <> struct consume<Windows::Gaming::Input::IRacingWheelStatics> { template <typename D> using type = consume_Windows_Gaming_Input_IRacingWheelStatics<D>; };

template <typename D>
struct consume_Windows_Gaming_Input_IRacingWheelStatics2
{
    Windows::Gaming::Input::RacingWheel FromGameController(Windows::Gaming::Input::IGameController const& gameController) const;
};
template <> struct consume<Windows::Gaming::Input::IRacingWheelStatics2> { template <typename D> using type = consume_Windows_Gaming_Input_IRacingWheelStatics2<D>; };

template <typename D>
struct consume_Windows_Gaming_Input_IRawGameController
{
    int32_t AxisCount() const;
    int32_t ButtonCount() const;
    Windows::Foundation::Collections::IVectorView<Windows::Gaming::Input::ForceFeedback::ForceFeedbackMotor> ForceFeedbackMotors() const;
    uint16_t HardwareProductId() const;
    uint16_t HardwareVendorId() const;
    int32_t SwitchCount() const;
    Windows::Gaming::Input::GameControllerButtonLabel GetButtonLabel(int32_t buttonIndex) const;
    uint64_t GetCurrentReading(array_view<bool> buttonArray, array_view<Windows::Gaming::Input::GameControllerSwitchPosition> switchArray, array_view<double> axisArray) const;
    Windows::Gaming::Input::GameControllerSwitchKind GetSwitchKind(int32_t switchIndex) const;
};
template <> struct consume<Windows::Gaming::Input::IRawGameController> { template <typename D> using type = consume_Windows_Gaming_Input_IRawGameController<D>; };

template <typename D>
struct consume_Windows_Gaming_Input_IRawGameController2
{
    Windows::Foundation::Collections::IVectorView<Windows::Devices::Haptics::SimpleHapticsController> SimpleHapticsControllers() const;
    hstring NonRoamableId() const;
    hstring DisplayName() const;
};
template <> struct consume<Windows::Gaming::Input::IRawGameController2> { template <typename D> using type = consume_Windows_Gaming_Input_IRawGameController2<D>; };

template <typename D>
struct consume_Windows_Gaming_Input_IRawGameControllerStatics
{
    winrt::event_token RawGameControllerAdded(Windows::Foundation::EventHandler<Windows::Gaming::Input::RawGameController> const& value) const;
    using RawGameControllerAdded_revoker = impl::event_revoker<Windows::Gaming::Input::IRawGameControllerStatics, &impl::abi_t<Windows::Gaming::Input::IRawGameControllerStatics>::remove_RawGameControllerAdded>;
    RawGameControllerAdded_revoker RawGameControllerAdded(auto_revoke_t, Windows::Foundation::EventHandler<Windows::Gaming::Input::RawGameController> const& value) const;
    void RawGameControllerAdded(winrt::event_token const& token) const noexcept;
    winrt::event_token RawGameControllerRemoved(Windows::Foundation::EventHandler<Windows::Gaming::Input::RawGameController> const& value) const;
    using RawGameControllerRemoved_revoker = impl::event_revoker<Windows::Gaming::Input::IRawGameControllerStatics, &impl::abi_t<Windows::Gaming::Input::IRawGameControllerStatics>::remove_RawGameControllerRemoved>;
    RawGameControllerRemoved_revoker RawGameControllerRemoved(auto_revoke_t, Windows::Foundation::EventHandler<Windows::Gaming::Input::RawGameController> const& value) const;
    void RawGameControllerRemoved(winrt::event_token const& token) const noexcept;
    Windows::Foundation::Collections::IVectorView<Windows::Gaming::Input::RawGameController> RawGameControllers() const;
    Windows::Gaming::Input::RawGameController FromGameController(Windows::Gaming::Input::IGameController const& gameController) const;
};
template <> struct consume<Windows::Gaming::Input::IRawGameControllerStatics> { template <typename D> using type = consume_Windows_Gaming_Input_IRawGameControllerStatics<D>; };

template <typename D>
struct consume_Windows_Gaming_Input_IUINavigationController
{
    Windows::Gaming::Input::UINavigationReading GetCurrentReading() const;
    Windows::Gaming::Input::GameControllerButtonLabel GetOptionalButtonLabel(Windows::Gaming::Input::OptionalUINavigationButtons const& button) const;
    Windows::Gaming::Input::GameControllerButtonLabel GetRequiredButtonLabel(Windows::Gaming::Input::RequiredUINavigationButtons const& button) const;
};
template <> struct consume<Windows::Gaming::Input::IUINavigationController> { template <typename D> using type = consume_Windows_Gaming_Input_IUINavigationController<D>; };

template <typename D>
struct consume_Windows_Gaming_Input_IUINavigationControllerStatics
{
    winrt::event_token UINavigationControllerAdded(Windows::Foundation::EventHandler<Windows::Gaming::Input::UINavigationController> const& value) const;
    using UINavigationControllerAdded_revoker = impl::event_revoker<Windows::Gaming::Input::IUINavigationControllerStatics, &impl::abi_t<Windows::Gaming::Input::IUINavigationControllerStatics>::remove_UINavigationControllerAdded>;
    UINavigationControllerAdded_revoker UINavigationControllerAdded(auto_revoke_t, Windows::Foundation::EventHandler<Windows::Gaming::Input::UINavigationController> const& value) const;
    void UINavigationControllerAdded(winrt::event_token const& token) const noexcept;
    winrt::event_token UINavigationControllerRemoved(Windows::Foundation::EventHandler<Windows::Gaming::Input::UINavigationController> const& value) const;
    using UINavigationControllerRemoved_revoker = impl::event_revoker<Windows::Gaming::Input::IUINavigationControllerStatics, &impl::abi_t<Windows::Gaming::Input::IUINavigationControllerStatics>::remove_UINavigationControllerRemoved>;
    UINavigationControllerRemoved_revoker UINavigationControllerRemoved(auto_revoke_t, Windows::Foundation::EventHandler<Windows::Gaming::Input::UINavigationController> const& value) const;
    void UINavigationControllerRemoved(winrt::event_token const& token) const noexcept;
    Windows::Foundation::Collections::IVectorView<Windows::Gaming::Input::UINavigationController> UINavigationControllers() const;
};
template <> struct consume<Windows::Gaming::Input::IUINavigationControllerStatics> { template <typename D> using type = consume_Windows_Gaming_Input_IUINavigationControllerStatics<D>; };

template <typename D>
struct consume_Windows_Gaming_Input_IUINavigationControllerStatics2
{
    Windows::Gaming::Input::UINavigationController FromGameController(Windows::Gaming::Input::IGameController const& gameController) const;
};
template <> struct consume<Windows::Gaming::Input::IUINavigationControllerStatics2> { template <typename D> using type = consume_Windows_Gaming_Input_IUINavigationControllerStatics2<D>; };

struct struct_Windows_Gaming_Input_ArcadeStickReading
{
    uint64_t Timestamp;
    Windows::Gaming::Input::ArcadeStickButtons Buttons;
};
template <> struct abi<Windows::Gaming::Input::ArcadeStickReading>{ using type = struct_Windows_Gaming_Input_ArcadeStickReading; };


struct struct_Windows_Gaming_Input_FlightStickReading
{
    uint64_t Timestamp;
    Windows::Gaming::Input::FlightStickButtons Buttons;
    Windows::Gaming::Input::GameControllerSwitchPosition HatSwitch;
    double Roll;
    double Pitch;
    double Yaw;
    double Throttle;
};
template <> struct abi<Windows::Gaming::Input::FlightStickReading>{ using type = struct_Windows_Gaming_Input_FlightStickReading; };


struct struct_Windows_Gaming_Input_GamepadReading
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
template <> struct abi<Windows::Gaming::Input::GamepadReading>{ using type = struct_Windows_Gaming_Input_GamepadReading; };


struct struct_Windows_Gaming_Input_GamepadVibration
{
    double LeftMotor;
    double RightMotor;
    double LeftTrigger;
    double RightTrigger;
};
template <> struct abi<Windows::Gaming::Input::GamepadVibration>{ using type = struct_Windows_Gaming_Input_GamepadVibration; };


struct struct_Windows_Gaming_Input_RacingWheelReading
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
template <> struct abi<Windows::Gaming::Input::RacingWheelReading>{ using type = struct_Windows_Gaming_Input_RacingWheelReading; };


struct struct_Windows_Gaming_Input_UINavigationReading
{
    uint64_t Timestamp;
    Windows::Gaming::Input::RequiredUINavigationButtons RequiredButtons;
    Windows::Gaming::Input::OptionalUINavigationButtons OptionalButtons;
};
template <> struct abi<Windows::Gaming::Input::UINavigationReading>{ using type = struct_Windows_Gaming_Input_UINavigationReading; };


}
