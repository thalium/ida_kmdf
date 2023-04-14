// C++/WinRT v1.0.190111.3

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#pragma once
#include "winrt/impl/Windows.Devices.Input.0.h"

WINRT_EXPORT namespace winrt::Windows::Devices::Input {

struct WINRT_EBO IKeyboardCapabilities :
    Windows::Foundation::IInspectable,
    impl::consume_t<IKeyboardCapabilities>
{
    IKeyboardCapabilities(std::nullptr_t = nullptr) noexcept {}
};

struct WINRT_EBO IMouseCapabilities :
    Windows::Foundation::IInspectable,
    impl::consume_t<IMouseCapabilities>
{
    IMouseCapabilities(std::nullptr_t = nullptr) noexcept {}
};

struct WINRT_EBO IMouseDevice :
    Windows::Foundation::IInspectable,
    impl::consume_t<IMouseDevice>
{
    IMouseDevice(std::nullptr_t = nullptr) noexcept {}
};

struct WINRT_EBO IMouseDeviceStatics :
    Windows::Foundation::IInspectable,
    impl::consume_t<IMouseDeviceStatics>
{
    IMouseDeviceStatics(std::nullptr_t = nullptr) noexcept {}
};

struct WINRT_EBO IMouseEventArgs :
    Windows::Foundation::IInspectable,
    impl::consume_t<IMouseEventArgs>
{
    IMouseEventArgs(std::nullptr_t = nullptr) noexcept {}
};

struct WINRT_EBO IPenDevice :
    Windows::Foundation::IInspectable,
    impl::consume_t<IPenDevice>
{
    IPenDevice(std::nullptr_t = nullptr) noexcept {}
};

struct WINRT_EBO IPenDeviceStatics :
    Windows::Foundation::IInspectable,
    impl::consume_t<IPenDeviceStatics>
{
    IPenDeviceStatics(std::nullptr_t = nullptr) noexcept {}
};

struct WINRT_EBO IPointerDevice :
    Windows::Foundation::IInspectable,
    impl::consume_t<IPointerDevice>
{
    IPointerDevice(std::nullptr_t = nullptr) noexcept {}
};

struct WINRT_EBO IPointerDevice2 :
    Windows::Foundation::IInspectable,
    impl::consume_t<IPointerDevice2>
{
    IPointerDevice2(std::nullptr_t = nullptr) noexcept {}
};

struct WINRT_EBO IPointerDeviceStatics :
    Windows::Foundation::IInspectable,
    impl::consume_t<IPointerDeviceStatics>
{
    IPointerDeviceStatics(std::nullptr_t = nullptr) noexcept {}
};

struct WINRT_EBO ITouchCapabilities :
    Windows::Foundation::IInspectable,
    impl::consume_t<ITouchCapabilities>
{
    ITouchCapabilities(std::nullptr_t = nullptr) noexcept {}
};

}
