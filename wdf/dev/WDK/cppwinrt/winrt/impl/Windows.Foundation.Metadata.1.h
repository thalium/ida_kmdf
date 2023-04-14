// C++/WinRT v1.0.190111.3

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#pragma once
#include "winrt/impl/Windows.Foundation.Metadata.0.h"

WINRT_EXPORT namespace winrt::Windows::Foundation::Metadata {

struct WINRT_EBO IApiInformationStatics :
    Windows::Foundation::IInspectable,
    impl::consume_t<IApiInformationStatics>
{
    IApiInformationStatics(std::nullptr_t = nullptr) noexcept {}
};

}
