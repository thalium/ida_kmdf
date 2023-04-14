// C++/WinRT v1.0.190111.3

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#pragma once
#include "winrt/impl/Windows.Foundation.1.h"
#include "winrt/impl/Windows.ApplicationModel.ExtendedExecution.1.h"

WINRT_EXPORT namespace winrt::Windows::ApplicationModel::ExtendedExecution {

}

namespace winrt::impl {

}

WINRT_EXPORT namespace winrt::Windows::ApplicationModel::ExtendedExecution {

struct WINRT_EBO ExtendedExecutionRevokedEventArgs :
    Windows::ApplicationModel::ExtendedExecution::IExtendedExecutionRevokedEventArgs
{
    ExtendedExecutionRevokedEventArgs(std::nullptr_t) noexcept {}
};

struct WINRT_EBO ExtendedExecutionSession :
    Windows::ApplicationModel::ExtendedExecution::IExtendedExecutionSession
{
    ExtendedExecutionSession(std::nullptr_t) noexcept {}
    ExtendedExecutionSession();
};

}
