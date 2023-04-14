// C++/WinRT v1.0.190111.3

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#pragma once

WINRT_EXPORT namespace winrt::Windows::ApplicationModel::Core {

struct CoreApplicationView;

}

WINRT_EXPORT namespace winrt::Windows::System {

struct DispatcherQueue;

}

WINRT_EXPORT namespace winrt::Windows::UI::Core {

struct CoreDispatcher;

}

WINRT_EXPORT namespace winrt::Windows::UI::Input {

struct RadialController;

}

WINRT_EXPORT namespace winrt::Windows::UI::Input::Core {

struct IRadialControllerIndependentInputSource;
struct IRadialControllerIndependentInputSource2;
struct IRadialControllerIndependentInputSourceStatics;
struct RadialControllerIndependentInputSource;

}

namespace winrt::impl {

template <> struct category<Windows::UI::Input::Core::IRadialControllerIndependentInputSource>{ using type = interface_category; };
template <> struct category<Windows::UI::Input::Core::IRadialControllerIndependentInputSource2>{ using type = interface_category; };
template <> struct category<Windows::UI::Input::Core::IRadialControllerIndependentInputSourceStatics>{ using type = interface_category; };
template <> struct category<Windows::UI::Input::Core::RadialControllerIndependentInputSource>{ using type = class_category; };
template <> struct name<Windows::UI::Input::Core::IRadialControllerIndependentInputSource>{ static constexpr auto & value{ L"Windows.UI.Input.Core.IRadialControllerIndependentInputSource" }; };
template <> struct name<Windows::UI::Input::Core::IRadialControllerIndependentInputSource2>{ static constexpr auto & value{ L"Windows.UI.Input.Core.IRadialControllerIndependentInputSource2" }; };
template <> struct name<Windows::UI::Input::Core::IRadialControllerIndependentInputSourceStatics>{ static constexpr auto & value{ L"Windows.UI.Input.Core.IRadialControllerIndependentInputSourceStatics" }; };
template <> struct name<Windows::UI::Input::Core::RadialControllerIndependentInputSource>{ static constexpr auto & value{ L"Windows.UI.Input.Core.RadialControllerIndependentInputSource" }; };
template <> struct guid_storage<Windows::UI::Input::Core::IRadialControllerIndependentInputSource>{ static constexpr guid value{ 0x3D577EF6,0x4CEE,0x11E6,{ 0xB5,0x35,0x00,0x1B,0xDC,0x06,0xAB,0x3B } }; };
template <> struct guid_storage<Windows::UI::Input::Core::IRadialControllerIndependentInputSource2>{ static constexpr guid value{ 0x7073AAD8,0x35F3,0x4EEB,{ 0x87,0x51,0xBE,0x4D,0x0A,0x66,0xFA,0xF4 } }; };
template <> struct guid_storage<Windows::UI::Input::Core::IRadialControllerIndependentInputSourceStatics>{ static constexpr guid value{ 0x3D577EF5,0x4CEE,0x11E6,{ 0xB5,0x35,0x00,0x1B,0xDC,0x06,0xAB,0x3B } }; };
template <> struct default_interface<Windows::UI::Input::Core::RadialControllerIndependentInputSource>{ using type = Windows::UI::Input::Core::IRadialControllerIndependentInputSource; };

template <> struct abi<Windows::UI::Input::Core::IRadialControllerIndependentInputSource>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL get_Controller(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_Dispatcher(void** value) noexcept = 0;
};};

template <> struct abi<Windows::UI::Input::Core::IRadialControllerIndependentInputSource2>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL get_DispatcherQueue(void** value) noexcept = 0;
};};

template <> struct abi<Windows::UI::Input::Core::IRadialControllerIndependentInputSourceStatics>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL CreateForView(void* view, void** result) noexcept = 0;
};};

template <typename D>
struct consume_Windows_UI_Input_Core_IRadialControllerIndependentInputSource
{
    Windows::UI::Input::RadialController Controller() const;
    Windows::UI::Core::CoreDispatcher Dispatcher() const;
};
template <> struct consume<Windows::UI::Input::Core::IRadialControllerIndependentInputSource> { template <typename D> using type = consume_Windows_UI_Input_Core_IRadialControllerIndependentInputSource<D>; };

template <typename D>
struct consume_Windows_UI_Input_Core_IRadialControllerIndependentInputSource2
{
    Windows::System::DispatcherQueue DispatcherQueue() const;
};
template <> struct consume<Windows::UI::Input::Core::IRadialControllerIndependentInputSource2> { template <typename D> using type = consume_Windows_UI_Input_Core_IRadialControllerIndependentInputSource2<D>; };

template <typename D>
struct consume_Windows_UI_Input_Core_IRadialControllerIndependentInputSourceStatics
{
    Windows::UI::Input::Core::RadialControllerIndependentInputSource CreateForView(Windows::ApplicationModel::Core::CoreApplicationView const& view) const;
};
template <> struct consume<Windows::UI::Input::Core::IRadialControllerIndependentInputSourceStatics> { template <typename D> using type = consume_Windows_UI_Input_Core_IRadialControllerIndependentInputSourceStatics<D>; };

}
