// C++/WinRT v1.0.190111.3

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#pragma once
#include "winrt/impl/Windows.Devices.Input.1.h"

WINRT_EXPORT namespace winrt::Windows::Devices::Input {

struct MouseDelta
{
    int32_t X;
    int32_t Y;
};

inline bool operator==(MouseDelta const& left, MouseDelta const& right) noexcept
{
    return left.X == right.X && left.Y == right.Y;
}

inline bool operator!=(MouseDelta const& left, MouseDelta const& right) noexcept
{
    return !(left == right);
}

struct PointerDeviceUsage
{
    uint32_t UsagePage;
    uint32_t Usage;
    int32_t MinLogical;
    int32_t MaxLogical;
    int32_t MinPhysical;
    int32_t MaxPhysical;
    uint32_t Unit;
    float PhysicalMultiplier;
};

inline bool operator==(PointerDeviceUsage const& left, PointerDeviceUsage const& right) noexcept
{
    return left.UsagePage == right.UsagePage && left.Usage == right.Usage && left.MinLogical == right.MinLogical && left.MaxLogical == right.MaxLogical && left.MinPhysical == right.MinPhysical && left.MaxPhysical == right.MaxPhysical && left.Unit == right.Unit && left.PhysicalMultiplier == right.PhysicalMultiplier;
}

inline bool operator!=(PointerDeviceUsage const& left, PointerDeviceUsage const& right) noexcept
{
    return !(left == right);
}

}

namespace winrt::impl {

}

WINRT_EXPORT namespace winrt::Windows::Devices::Input {

struct WINRT_EBO KeyboardCapabilities :
    Windows::Devices::Input::IKeyboardCapabilities
{
    KeyboardCapabilities(std::nullptr_t) noexcept {}
    KeyboardCapabilities();
};

struct WINRT_EBO MouseCapabilities :
    Windows::Devices::Input::IMouseCapabilities
{
    MouseCapabilities(std::nullptr_t) noexcept {}
    MouseCapabilities();
};

struct WINRT_EBO MouseDevice :
    Windows::Devices::Input::IMouseDevice
{
    MouseDevice(std::nullptr_t) noexcept {}
    static Windows::Devices::Input::MouseDevice GetForCurrentView();
};

struct WINRT_EBO MouseEventArgs :
    Windows::Devices::Input::IMouseEventArgs
{
    MouseEventArgs(std::nullptr_t) noexcept {}
};

struct WINRT_EBO PenDevice :
    Windows::Devices::Input::IPenDevice
{
    PenDevice(std::nullptr_t) noexcept {}
    static Windows::Devices::Input::PenDevice GetFromPointerId(uint32_t pointerId);
};

struct WINRT_EBO PointerDevice :
    Windows::Devices::Input::IPointerDevice,
    impl::require<PointerDevice, Windows::Devices::Input::IPointerDevice2>
{
    PointerDevice(std::nullptr_t) noexcept {}
    static Windows::Devices::Input::PointerDevice GetPointerDevice(uint32_t pointerId);
    static Windows::Foundation::Collections::IVectorView<Windows::Devices::Input::PointerDevice> GetPointerDevices();
};

struct WINRT_EBO TouchCapabilities :
    Windows::Devices::Input::ITouchCapabilities
{
    TouchCapabilities(std::nullptr_t) noexcept {}
    TouchCapabilities();
};

}
