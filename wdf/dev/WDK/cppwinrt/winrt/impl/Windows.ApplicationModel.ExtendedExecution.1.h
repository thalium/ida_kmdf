// C++/WinRT v1.0.190111.3

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#pragma once
#include "winrt/impl/Windows.Foundation.0.h"
#include "winrt/impl/Windows.ApplicationModel.ExtendedExecution.0.h"

WINRT_EXPORT namespace winrt::Windows::ApplicationModel::ExtendedExecution {

struct WINRT_EBO IExtendedExecutionRevokedEventArgs :
    Windows::Foundation::IInspectable,
    impl::consume_t<IExtendedExecutionRevokedEventArgs>
{
    IExtendedExecutionRevokedEventArgs(std::nullptr_t = nullptr) noexcept {}
};

struct WINRT_EBO IExtendedExecutionSession :
    Windows::Foundation::IInspectable,
    impl::consume_t<IExtendedExecutionSession>,
    impl::require<IExtendedExecutionSession, Windows::Foundation::IClosable>
{
    IExtendedExecutionSession(std::nullptr_t = nullptr) noexcept {}
};

}
