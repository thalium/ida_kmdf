// C++/WinRT v1.0.190111.3

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#pragma once
#include "winrt/impl/Windows.Storage.Streams.1.h"
#include "winrt/impl/Windows.ApplicationModel.LockScreen.1.h"

WINRT_EXPORT namespace winrt::Windows::ApplicationModel::LockScreen {

}

namespace winrt::impl {

}

WINRT_EXPORT namespace winrt::Windows::ApplicationModel::LockScreen {

struct WINRT_EBO LockApplicationHost :
    Windows::ApplicationModel::LockScreen::ILockApplicationHost
{
    LockApplicationHost(std::nullptr_t) noexcept {}
    static Windows::ApplicationModel::LockScreen::LockApplicationHost GetForCurrentView();
};

struct WINRT_EBO LockScreenBadge :
    Windows::ApplicationModel::LockScreen::ILockScreenBadge
{
    LockScreenBadge(std::nullptr_t) noexcept {}
};

struct WINRT_EBO LockScreenInfo :
    Windows::ApplicationModel::LockScreen::ILockScreenInfo
{
    LockScreenInfo(std::nullptr_t) noexcept {}
};

struct WINRT_EBO LockScreenUnlockingDeferral :
    Windows::ApplicationModel::LockScreen::ILockScreenUnlockingDeferral
{
    LockScreenUnlockingDeferral(std::nullptr_t) noexcept {}
};

struct WINRT_EBO LockScreenUnlockingEventArgs :
    Windows::ApplicationModel::LockScreen::ILockScreenUnlockingEventArgs
{
    LockScreenUnlockingEventArgs(std::nullptr_t) noexcept {}
};

}
