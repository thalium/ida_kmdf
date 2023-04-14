// C++/WinRT v1.0.190111.3

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#pragma once
#include "winrt/impl/Windows.Storage.0.h"
#include "winrt/impl/Windows.Management.Core.0.h"

WINRT_EXPORT namespace winrt::Windows::Management::Core {

struct WINRT_EBO IApplicationDataManager :
    Windows::Foundation::IInspectable,
    impl::consume_t<IApplicationDataManager>
{
    IApplicationDataManager(std::nullptr_t = nullptr) noexcept {}
};

struct WINRT_EBO IApplicationDataManagerStatics :
    Windows::Foundation::IInspectable,
    impl::consume_t<IApplicationDataManagerStatics>
{
    IApplicationDataManagerStatics(std::nullptr_t = nullptr) noexcept {}
};

}
