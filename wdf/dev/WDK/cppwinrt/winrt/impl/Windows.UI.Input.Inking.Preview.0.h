// C++/WinRT v1.0.190111.3

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#pragma once

WINRT_EXPORT namespace winrt::Windows::UI::Composition {

struct Visual;

}

WINRT_EXPORT namespace winrt::Windows::UI::Input::Inking::Preview {

struct IPalmRejectionDelayZonePreview;
struct IPalmRejectionDelayZonePreviewStatics;
struct PalmRejectionDelayZonePreview;

}

namespace winrt::impl {

template <> struct category<Windows::UI::Input::Inking::Preview::IPalmRejectionDelayZonePreview>{ using type = interface_category; };
template <> struct category<Windows::UI::Input::Inking::Preview::IPalmRejectionDelayZonePreviewStatics>{ using type = interface_category; };
template <> struct category<Windows::UI::Input::Inking::Preview::PalmRejectionDelayZonePreview>{ using type = class_category; };
template <> struct name<Windows::UI::Input::Inking::Preview::IPalmRejectionDelayZonePreview>{ static constexpr auto & value{ L"Windows.UI.Input.Inking.Preview.IPalmRejectionDelayZonePreview" }; };
template <> struct name<Windows::UI::Input::Inking::Preview::IPalmRejectionDelayZonePreviewStatics>{ static constexpr auto & value{ L"Windows.UI.Input.Inking.Preview.IPalmRejectionDelayZonePreviewStatics" }; };
template <> struct name<Windows::UI::Input::Inking::Preview::PalmRejectionDelayZonePreview>{ static constexpr auto & value{ L"Windows.UI.Input.Inking.Preview.PalmRejectionDelayZonePreview" }; };
template <> struct guid_storage<Windows::UI::Input::Inking::Preview::IPalmRejectionDelayZonePreview>{ static constexpr guid value{ 0x62B496CB,0x539D,0x5343,{ 0xA6,0x5F,0x41,0xF5,0x30,0x0E,0xC7,0x0C } }; };
template <> struct guid_storage<Windows::UI::Input::Inking::Preview::IPalmRejectionDelayZonePreviewStatics>{ static constexpr guid value{ 0xCDEF5EE0,0x93D0,0x53A9,{ 0x8F,0x0E,0x9A,0x37,0x9F,0x8F,0x75,0x30 } }; };
template <> struct default_interface<Windows::UI::Input::Inking::Preview::PalmRejectionDelayZonePreview>{ using type = Windows::UI::Input::Inking::Preview::IPalmRejectionDelayZonePreview; };

template <> struct abi<Windows::UI::Input::Inking::Preview::IPalmRejectionDelayZonePreview>{ struct type : IInspectable
{
};};

template <> struct abi<Windows::UI::Input::Inking::Preview::IPalmRejectionDelayZonePreviewStatics>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL CreateForVisual(void* inputPanelVisual, Windows::Foundation::Rect inputPanelRect, void** result) noexcept = 0;
    virtual int32_t WINRT_CALL CreateForVisualWithViewportClip(void* inputPanelVisual, Windows::Foundation::Rect inputPanelRect, void* viewportVisual, Windows::Foundation::Rect viewportRect, void** result) noexcept = 0;
};};

template <typename D>
struct consume_Windows_UI_Input_Inking_Preview_IPalmRejectionDelayZonePreview
{
};
template <> struct consume<Windows::UI::Input::Inking::Preview::IPalmRejectionDelayZonePreview> { template <typename D> using type = consume_Windows_UI_Input_Inking_Preview_IPalmRejectionDelayZonePreview<D>; };

template <typename D>
struct consume_Windows_UI_Input_Inking_Preview_IPalmRejectionDelayZonePreviewStatics
{
    Windows::UI::Input::Inking::Preview::PalmRejectionDelayZonePreview CreateForVisual(Windows::UI::Composition::Visual const& inputPanelVisual, Windows::Foundation::Rect const& inputPanelRect) const;
    Windows::UI::Input::Inking::Preview::PalmRejectionDelayZonePreview CreateForVisual(Windows::UI::Composition::Visual const& inputPanelVisual, Windows::Foundation::Rect const& inputPanelRect, Windows::UI::Composition::Visual const& viewportVisual, Windows::Foundation::Rect const& viewportRect) const;
};
template <> struct consume<Windows::UI::Input::Inking::Preview::IPalmRejectionDelayZonePreviewStatics> { template <typename D> using type = consume_Windows_UI_Input_Inking_Preview_IPalmRejectionDelayZonePreviewStatics<D>; };

}
