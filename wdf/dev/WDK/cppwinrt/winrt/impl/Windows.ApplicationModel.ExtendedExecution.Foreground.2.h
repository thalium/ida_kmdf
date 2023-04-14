// C++/WinRT v1.0.190111.3

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#pragma once
#include "winrt/impl/Windows.Foundation.1.h"
#include "winrt/impl/Windows.ApplicationModel.ExtendedExecution.Foreground.1.h"

WINRT_EXPORT namespace winrt::Windows::ApplicationModel::ExtendedExecution::Foreground {

}

namespace winrt::impl {

}

WINRT_EXPORT namespace winrt::Windows::ApplicationModel::ExtendedExecution::Foreground {

struct WINRT_EBO ExtendedExecutionForegroundRevokedEventArgs :
    Windows::ApplicationModel::ExtendedExecution::Foreground::IExtendedExecutionForegroundRevokedEventArgs
{
    ExtendedExecutionForegroundRevokedEventArgs(std::nullptr_t) noexcept {}
};

struct WINRT_EBO ExtendedExecutionForegroundSession :
    Windows::ApplicationModel::ExtendedExecution::Foreground::IExtendedExecutionForegroundSession
{
    ExtendedExecutionForegroundSession(std::nullptr_t) noexcept {}
    ExtendedExecutionForegroundSession();
};

}
