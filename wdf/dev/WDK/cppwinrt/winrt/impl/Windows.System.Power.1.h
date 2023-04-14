// C++/WinRT v1.0.190111.3

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#pragma once
#include "winrt/impl/Windows.System.Power.0.h"

WINRT_EXPORT namespace winrt::Windows::System::Power {

struct WINRT_EBO IBackgroundEnergyManagerStatics :
    Windows::Foundation::IInspectable,
    impl::consume_t<IBackgroundEnergyManagerStatics>
{
    IBackgroundEnergyManagerStatics(std::nullptr_t = nullptr) noexcept {}
};

struct WINRT_EBO IForegroundEnergyManagerStatics :
    Windows::Foundation::IInspectable,
    impl::consume_t<IForegroundEnergyManagerStatics>
{
    IForegroundEnergyManagerStatics(std::nullptr_t = nullptr) noexcept {}
};

struct WINRT_EBO IPowerManagerStatics :
    Windows::Foundation::IInspectable,
    impl::consume_t<IPowerManagerStatics>
{
    IPowerManagerStatics(std::nullptr_t = nullptr) noexcept {}
};

}
