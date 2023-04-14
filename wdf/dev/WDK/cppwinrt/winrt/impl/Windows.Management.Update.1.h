// C++/WinRT v1.0.190111.3

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#pragma once
#include "winrt/impl/Windows.Foundation.Collections.0.h"
#include "winrt/impl/Windows.Management.Update.0.h"

WINRT_EXPORT namespace winrt::Windows::Management::Update {

struct WINRT_EBO IPreviewBuildsManager :
    Windows::Foundation::IInspectable,
    impl::consume_t<IPreviewBuildsManager>
{
    IPreviewBuildsManager(std::nullptr_t = nullptr) noexcept {}
};

struct WINRT_EBO IPreviewBuildsManagerStatics :
    Windows::Foundation::IInspectable,
    impl::consume_t<IPreviewBuildsManagerStatics>
{
    IPreviewBuildsManagerStatics(std::nullptr_t = nullptr) noexcept {}
};

struct WINRT_EBO IPreviewBuildsState :
    Windows::Foundation::IInspectable,
    impl::consume_t<IPreviewBuildsState>
{
    IPreviewBuildsState(std::nullptr_t = nullptr) noexcept {}
};

}
