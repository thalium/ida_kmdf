// C++/WinRT v1.0.190111.3

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#pragma once
#include "winrt/impl/Windows.UI.Notifications.1.h"
#include "winrt/impl/Windows.UI.Notifications.Management.1.h"

WINRT_EXPORT namespace winrt::Windows::UI::Notifications::Management {

}

namespace winrt::impl {

}

WINRT_EXPORT namespace winrt::Windows::UI::Notifications::Management {

struct WINRT_EBO UserNotificationListener :
    Windows::UI::Notifications::Management::IUserNotificationListener
{
    UserNotificationListener(std::nullptr_t) noexcept {}
    static Windows::UI::Notifications::Management::UserNotificationListener Current();
};

}
