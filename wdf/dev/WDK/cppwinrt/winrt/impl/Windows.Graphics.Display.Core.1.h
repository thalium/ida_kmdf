// C++/WinRT v1.0.190111.3

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#pragma once
#include "winrt/impl/Windows.Graphics.Display.Core.0.h"

WINRT_EXPORT namespace winrt::Windows::Graphics::Display::Core {

struct WINRT_EBO IHdmiDisplayInformation :
    Windows::Foundation::IInspectable,
    impl::consume_t<IHdmiDisplayInformation>
{
    IHdmiDisplayInformation(std::nullptr_t = nullptr) noexcept {}
};

struct WINRT_EBO IHdmiDisplayInformationStatics :
    Windows::Foundation::IInspectable,
    impl::consume_t<IHdmiDisplayInformationStatics>
{
    IHdmiDisplayInformationStatics(std::nullptr_t = nullptr) noexcept {}
};

struct WINRT_EBO IHdmiDisplayMode :
    Windows::Foundation::IInspectable,
    impl::consume_t<IHdmiDisplayMode>
{
    IHdmiDisplayMode(std::nullptr_t = nullptr) noexcept {}
};

struct WINRT_EBO IHdmiDisplayMode2 :
    Windows::Foundation::IInspectable,
    impl::consume_t<IHdmiDisplayMode2>
{
    IHdmiDisplayMode2(std::nullptr_t = nullptr) noexcept {}
};

}
