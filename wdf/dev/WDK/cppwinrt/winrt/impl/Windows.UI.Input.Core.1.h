// C++/WinRT v1.0.190111.3

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#pragma once
#include "winrt/impl/Windows.ApplicationModel.Core.0.h"
#include "winrt/impl/Windows.System.0.h"
#include "winrt/impl/Windows.UI.Core.0.h"
#include "winrt/impl/Windows.UI.Input.0.h"
#include "winrt/impl/Windows.UI.Input.Core.0.h"

WINRT_EXPORT namespace winrt::Windows::UI::Input::Core {

struct WINRT_EBO IRadialControllerIndependentInputSource :
    Windows::Foundation::IInspectable,
    impl::consume_t<IRadialControllerIndependentInputSource>
{
    IRadialControllerIndependentInputSource(std::nullptr_t = nullptr) noexcept {}
};

struct WINRT_EBO IRadialControllerIndependentInputSource2 :
    Windows::Foundation::IInspectable,
    impl::consume_t<IRadialControllerIndependentInputSource2>
{
    IRadialControllerIndependentInputSource2(std::nullptr_t = nullptr) noexcept {}
};

struct WINRT_EBO IRadialControllerIndependentInputSourceStatics :
    Windows::Foundation::IInspectable,
    impl::consume_t<IRadialControllerIndependentInputSourceStatics>
{
    IRadialControllerIndependentInputSourceStatics(std::nullptr_t = nullptr) noexcept {}
};

}
