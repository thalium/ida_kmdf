// C++/WinRT v1.0.190111.3

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#pragma once
#include "winrt/impl/Windows.System.Threading.0.h"
#include "winrt/impl/Windows.System.Threading.Core.0.h"

WINRT_EXPORT namespace winrt::Windows::System::Threading::Core {

struct WINRT_EBO IPreallocatedWorkItem :
    Windows::Foundation::IInspectable,
    impl::consume_t<IPreallocatedWorkItem>
{
    IPreallocatedWorkItem(std::nullptr_t = nullptr) noexcept {}
};

struct WINRT_EBO IPreallocatedWorkItemFactory :
    Windows::Foundation::IInspectable,
    impl::consume_t<IPreallocatedWorkItemFactory>
{
    IPreallocatedWorkItemFactory(std::nullptr_t = nullptr) noexcept {}
};

struct WINRT_EBO ISignalNotifier :
    Windows::Foundation::IInspectable,
    impl::consume_t<ISignalNotifier>
{
    ISignalNotifier(std::nullptr_t = nullptr) noexcept {}
};

struct WINRT_EBO ISignalNotifierStatics :
    Windows::Foundation::IInspectable,
    impl::consume_t<ISignalNotifierStatics>
{
    ISignalNotifierStatics(std::nullptr_t = nullptr) noexcept {}
};

}
