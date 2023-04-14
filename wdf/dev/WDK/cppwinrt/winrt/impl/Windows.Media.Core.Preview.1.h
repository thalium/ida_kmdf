// C++/WinRT v1.0.190111.3

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#pragma once
#include "winrt/impl/Windows.Media.0.h"
#include "winrt/impl/Windows.Media.Core.Preview.0.h"

WINRT_EXPORT namespace winrt::Windows::Media::Core::Preview {

struct WINRT_EBO ISoundLevelBrokerStatics :
    Windows::Foundation::IInspectable,
    impl::consume_t<ISoundLevelBrokerStatics>
{
    ISoundLevelBrokerStatics(std::nullptr_t = nullptr) noexcept {}
};

}
