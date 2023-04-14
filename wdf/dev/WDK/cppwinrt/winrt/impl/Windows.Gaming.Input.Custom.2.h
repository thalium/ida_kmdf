// C++/WinRT v1.0.190111.3

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#pragma once
#include "winrt/impl/Windows.Gaming.Input.1.h"
#include "winrt/impl/Windows.Storage.Streams.1.h"
#include "winrt/impl/Windows.Gaming.Input.Custom.1.h"

WINRT_EXPORT namespace winrt::Windows::Gaming::Input::Custom {

struct GameControllerVersionInfo
{
    uint16_t Major;
    uint16_t Minor;
    uint16_t Build;
    uint16_t Revision;
};

inline bool operator==(GameControllerVersionInfo const& left, GameControllerVersionInfo const& right) noexcept
{
    return left.Major == right.Major && left.Minor == right.Minor && left.Build == right.Build && left.Revision == right.Revision;
}

inline bool operator!=(GameControllerVersionInfo const& left, GameControllerVersionInfo const& right) noexcept
{
    return !(left == right);
}

struct GipFirmwareUpdateProgress
{
    double PercentCompleted;
    uint32_t CurrentComponentId;
};

inline bool operator==(GipFirmwareUpdateProgress const& left, GipFirmwareUpdateProgress const& right) noexcept
{
    return left.PercentCompleted == right.PercentCompleted && left.CurrentComponentId == right.CurrentComponentId;
}

inline bool operator!=(GipFirmwareUpdateProgress const& left, GipFirmwareUpdateProgress const& right) noexcept
{
    return !(left == right);
}

}

namespace winrt::impl {

}

WINRT_EXPORT namespace winrt::Windows::Gaming::Input::Custom {

struct GameControllerFactoryManager
{
    GameControllerFactoryManager() = delete;
    static void RegisterCustomFactoryForGipInterface(Windows::Gaming::Input::Custom::ICustomGameControllerFactory const& factory, winrt::guid const& interfaceId);
    static void RegisterCustomFactoryForHardwareId(Windows::Gaming::Input::Custom::ICustomGameControllerFactory const& factory, uint16_t hardwareVendorId, uint16_t hardwareProductId);
    static void RegisterCustomFactoryForXusbType(Windows::Gaming::Input::Custom::ICustomGameControllerFactory const& factory, Windows::Gaming::Input::Custom::XusbDeviceType const& xusbType, Windows::Gaming::Input::Custom::XusbDeviceSubtype const& xusbSubtype);
    static Windows::Gaming::Input::IGameController TryGetFactoryControllerFromGameController(Windows::Gaming::Input::Custom::ICustomGameControllerFactory const& factory, Windows::Gaming::Input::IGameController const& gameController);
};

struct WINRT_EBO GipFirmwareUpdateResult :
    Windows::Gaming::Input::Custom::IGipFirmwareUpdateResult
{
    GipFirmwareUpdateResult(std::nullptr_t) noexcept {}
};

struct WINRT_EBO GipGameControllerProvider :
    Windows::Gaming::Input::Custom::IGipGameControllerProvider
{
    GipGameControllerProvider(std::nullptr_t) noexcept {}
};

struct WINRT_EBO HidGameControllerProvider :
    Windows::Gaming::Input::Custom::IHidGameControllerProvider
{
    HidGameControllerProvider(std::nullptr_t) noexcept {}
};

struct WINRT_EBO XusbGameControllerProvider :
    Windows::Gaming::Input::Custom::IXusbGameControllerProvider
{
    XusbGameControllerProvider(std::nullptr_t) noexcept {}
};

}
