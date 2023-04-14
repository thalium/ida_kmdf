// C++/WinRT v1.0.190111.3

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#pragma once
#include "winrt/impl/Windows.Gaming.Input.1.h"
#include "winrt/impl/Windows.UI.Input.Preview.Injection.1.h"
#include "winrt/impl/Windows.UI.Input.Preview.Injection.2.h"

WINRT_EXPORT namespace winrt::Windows::UI::Input::Preview::Injection {

struct InjectedInputPoint
{
    int32_t PositionX;
    int32_t PositionY;
};

inline bool operator==(InjectedInputPoint const& left, InjectedInputPoint const& right) noexcept
{
    return left.PositionX == right.PositionX && left.PositionY == right.PositionY;
}

inline bool operator!=(InjectedInputPoint const& left, InjectedInputPoint const& right) noexcept
{
    return !(left == right);
}

struct InjectedInputPointerInfo
{
    uint32_t PointerId;
    Windows::UI::Input::Preview::Injection::InjectedInputPointerOptions PointerOptions;
    Windows::UI::Input::Preview::Injection::InjectedInputPoint PixelLocation;
    uint32_t TimeOffsetInMilliseconds;
    uint64_t PerformanceCount;
};

inline bool operator==(InjectedInputPointerInfo const& left, InjectedInputPointerInfo const& right) noexcept
{
    return left.PointerId == right.PointerId && left.PointerOptions == right.PointerOptions && left.PixelLocation == right.PixelLocation && left.TimeOffsetInMilliseconds == right.TimeOffsetInMilliseconds && left.PerformanceCount == right.PerformanceCount;
}

inline bool operator!=(InjectedInputPointerInfo const& left, InjectedInputPointerInfo const& right) noexcept
{
    return !(left == right);
}

struct InjectedInputRectangle
{
    int32_t Left;
    int32_t Top;
    int32_t Bottom;
    int32_t Right;
};

inline bool operator==(InjectedInputRectangle const& left, InjectedInputRectangle const& right) noexcept
{
    return left.Left == right.Left && left.Top == right.Top && left.Bottom == right.Bottom && left.Right == right.Right;
}

inline bool operator!=(InjectedInputRectangle const& left, InjectedInputRectangle const& right) noexcept
{
    return !(left == right);
}

}

namespace winrt::impl {

}

WINRT_EXPORT namespace winrt::Windows::UI::Input::Preview::Injection {

struct WINRT_EBO InjectedInputGamepadInfo :
    Windows::UI::Input::Preview::Injection::IInjectedInputGamepadInfo
{
    InjectedInputGamepadInfo(std::nullptr_t) noexcept {}
    InjectedInputGamepadInfo();
    InjectedInputGamepadInfo(Windows::Gaming::Input::GamepadReading const& reading);
};

struct WINRT_EBO InjectedInputKeyboardInfo :
    Windows::UI::Input::Preview::Injection::IInjectedInputKeyboardInfo
{
    InjectedInputKeyboardInfo(std::nullptr_t) noexcept {}
    InjectedInputKeyboardInfo();
};

struct WINRT_EBO InjectedInputMouseInfo :
    Windows::UI::Input::Preview::Injection::IInjectedInputMouseInfo
{
    InjectedInputMouseInfo(std::nullptr_t) noexcept {}
    InjectedInputMouseInfo();
};

struct WINRT_EBO InjectedInputPenInfo :
    Windows::UI::Input::Preview::Injection::IInjectedInputPenInfo
{
    InjectedInputPenInfo(std::nullptr_t) noexcept {}
    InjectedInputPenInfo();
};

struct WINRT_EBO InjectedInputTouchInfo :
    Windows::UI::Input::Preview::Injection::IInjectedInputTouchInfo
{
    InjectedInputTouchInfo(std::nullptr_t) noexcept {}
    InjectedInputTouchInfo();
};

struct WINRT_EBO InputInjector :
    Windows::UI::Input::Preview::Injection::IInputInjector,
    impl::require<InputInjector, Windows::UI::Input::Preview::Injection::IInputInjector2>
{
    InputInjector(std::nullptr_t) noexcept {}
    static Windows::UI::Input::Preview::Injection::InputInjector TryCreate();
    static Windows::UI::Input::Preview::Injection::InputInjector TryCreateForAppBroadcastOnly();
};

}
