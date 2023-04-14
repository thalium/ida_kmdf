// C++/WinRT v1.0.190111.3

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#pragma once

WINRT_EXPORT namespace winrt::Windows::UI::Composition::Desktop {

struct IDesktopWindowTarget;
struct DesktopWindowTarget;

}

namespace winrt::impl {

template <> struct category<Windows::UI::Composition::Desktop::IDesktopWindowTarget>{ using type = interface_category; };
template <> struct category<Windows::UI::Composition::Desktop::DesktopWindowTarget>{ using type = class_category; };
template <> struct name<Windows::UI::Composition::Desktop::IDesktopWindowTarget>{ static constexpr auto & value{ L"Windows.UI.Composition.Desktop.IDesktopWindowTarget" }; };
template <> struct name<Windows::UI::Composition::Desktop::DesktopWindowTarget>{ static constexpr auto & value{ L"Windows.UI.Composition.Desktop.DesktopWindowTarget" }; };
template <> struct guid_storage<Windows::UI::Composition::Desktop::IDesktopWindowTarget>{ static constexpr guid value{ 0x6329D6CA,0x3366,0x490E,{ 0x9D,0xB3,0x25,0x31,0x29,0x29,0xAC,0x51 } }; };
template <> struct default_interface<Windows::UI::Composition::Desktop::DesktopWindowTarget>{ using type = Windows::UI::Composition::Desktop::IDesktopWindowTarget; };

template <> struct abi<Windows::UI::Composition::Desktop::IDesktopWindowTarget>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL get_IsTopmost(bool* value) noexcept = 0;
};};

template <typename D>
struct consume_Windows_UI_Composition_Desktop_IDesktopWindowTarget
{
    bool IsTopmost() const;
};
template <> struct consume<Windows::UI::Composition::Desktop::IDesktopWindowTarget> { template <typename D> using type = consume_Windows_UI_Composition_Desktop_IDesktopWindowTarget<D>; };

}
