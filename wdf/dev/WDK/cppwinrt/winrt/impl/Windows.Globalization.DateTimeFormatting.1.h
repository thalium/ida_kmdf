// C++/WinRT v1.0.190111.3

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#pragma once
#include "winrt/impl/Windows.Globalization.DateTimeFormatting.0.h"

WINRT_EXPORT namespace winrt::Windows::Globalization::DateTimeFormatting {

struct WINRT_EBO IDateTimeFormatter :
    Windows::Foundation::IInspectable,
    impl::consume_t<IDateTimeFormatter>
{
    IDateTimeFormatter(std::nullptr_t = nullptr) noexcept {}
};

struct WINRT_EBO IDateTimeFormatter2 :
    Windows::Foundation::IInspectable,
    impl::consume_t<IDateTimeFormatter2>
{
    IDateTimeFormatter2(std::nullptr_t = nullptr) noexcept {}
};

struct WINRT_EBO IDateTimeFormatterFactory :
    Windows::Foundation::IInspectable,
    impl::consume_t<IDateTimeFormatterFactory>
{
    IDateTimeFormatterFactory(std::nullptr_t = nullptr) noexcept {}
};

struct WINRT_EBO IDateTimeFormatterStatics :
    Windows::Foundation::IInspectable,
    impl::consume_t<IDateTimeFormatterStatics>
{
    IDateTimeFormatterStatics(std::nullptr_t = nullptr) noexcept {}
};

}
