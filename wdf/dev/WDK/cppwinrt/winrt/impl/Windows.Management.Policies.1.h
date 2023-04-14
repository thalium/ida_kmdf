// C++/WinRT v1.0.190111.3

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#pragma once
#include "winrt/impl/Windows.Storage.Streams.0.h"
#include "winrt/impl/Windows.System.0.h"
#include "winrt/impl/Windows.Management.Policies.0.h"

WINRT_EXPORT namespace winrt::Windows::Management::Policies {

struct WINRT_EBO INamedPolicyData :
    Windows::Foundation::IInspectable,
    impl::consume_t<INamedPolicyData>
{
    INamedPolicyData(std::nullptr_t = nullptr) noexcept {}
};

struct WINRT_EBO INamedPolicyStatics :
    Windows::Foundation::IInspectable,
    impl::consume_t<INamedPolicyStatics>
{
    INamedPolicyStatics(std::nullptr_t = nullptr) noexcept {}
};

}
