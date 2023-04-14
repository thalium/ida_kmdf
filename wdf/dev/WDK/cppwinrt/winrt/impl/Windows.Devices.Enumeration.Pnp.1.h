// C++/WinRT v1.0.190111.3

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#pragma once
#include "winrt/impl/Windows.Devices.Enumeration.0.h"
#include "winrt/impl/Windows.Devices.Enumeration.Pnp.0.h"

WINRT_EXPORT namespace winrt::Windows::Devices::Enumeration::Pnp {

struct WINRT_EBO IPnpObject :
    Windows::Foundation::IInspectable,
    impl::consume_t<IPnpObject>
{
    IPnpObject(std::nullptr_t = nullptr) noexcept {}
};

struct WINRT_EBO IPnpObjectStatics :
    Windows::Foundation::IInspectable,
    impl::consume_t<IPnpObjectStatics>
{
    IPnpObjectStatics(std::nullptr_t = nullptr) noexcept {}
};

struct WINRT_EBO IPnpObjectUpdate :
    Windows::Foundation::IInspectable,
    impl::consume_t<IPnpObjectUpdate>
{
    IPnpObjectUpdate(std::nullptr_t = nullptr) noexcept {}
};

struct WINRT_EBO IPnpObjectWatcher :
    Windows::Foundation::IInspectable,
    impl::consume_t<IPnpObjectWatcher>
{
    IPnpObjectWatcher(std::nullptr_t = nullptr) noexcept {}
};

}
