// C++/WinRT v1.0.190111.3

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#pragma once

WINRT_EXPORT namespace winrt::Windows::UI::WindowManagement {

struct AppWindow;

}

WINRT_EXPORT namespace winrt::Windows::UI::WindowManagement::Preview {

struct IWindowManagementPreview;
struct IWindowManagementPreviewStatics;
struct WindowManagementPreview;

}

namespace winrt::impl {

template <> struct category<Windows::UI::WindowManagement::Preview::IWindowManagementPreview>{ using type = interface_category; };
template <> struct category<Windows::UI::WindowManagement::Preview::IWindowManagementPreviewStatics>{ using type = interface_category; };
template <> struct category<Windows::UI::WindowManagement::Preview::WindowManagementPreview>{ using type = class_category; };
template <> struct name<Windows::UI::WindowManagement::Preview::IWindowManagementPreview>{ static constexpr auto & value{ L"Windows.UI.WindowManagement.Preview.IWindowManagementPreview" }; };
template <> struct name<Windows::UI::WindowManagement::Preview::IWindowManagementPreviewStatics>{ static constexpr auto & value{ L"Windows.UI.WindowManagement.Preview.IWindowManagementPreviewStatics" }; };
template <> struct name<Windows::UI::WindowManagement::Preview::WindowManagementPreview>{ static constexpr auto & value{ L"Windows.UI.WindowManagement.Preview.WindowManagementPreview" }; };
template <> struct guid_storage<Windows::UI::WindowManagement::Preview::IWindowManagementPreview>{ static constexpr guid value{ 0x4EF55B0D,0x561D,0x513C,{ 0xA6,0x7C,0x2C,0x02,0xB6,0x9C,0xEF,0x41 } }; };
template <> struct guid_storage<Windows::UI::WindowManagement::Preview::IWindowManagementPreviewStatics>{ static constexpr guid value{ 0x0F9725C6,0xC004,0x5A23,{ 0x8F,0xD2,0x8D,0x09,0x2C,0xE2,0x70,0x4A } }; };
template <> struct default_interface<Windows::UI::WindowManagement::Preview::WindowManagementPreview>{ using type = Windows::UI::WindowManagement::Preview::IWindowManagementPreview; };

template <> struct abi<Windows::UI::WindowManagement::Preview::IWindowManagementPreview>{ struct type : IInspectable
{
};};

template <> struct abi<Windows::UI::WindowManagement::Preview::IWindowManagementPreviewStatics>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL SetPreferredMinSize(void* window, Windows::Foundation::Size preferredFrameMinSize) noexcept = 0;
};};

template <typename D>
struct consume_Windows_UI_WindowManagement_Preview_IWindowManagementPreview
{
};
template <> struct consume<Windows::UI::WindowManagement::Preview::IWindowManagementPreview> { template <typename D> using type = consume_Windows_UI_WindowManagement_Preview_IWindowManagementPreview<D>; };

template <typename D>
struct consume_Windows_UI_WindowManagement_Preview_IWindowManagementPreviewStatics
{
    void SetPreferredMinSize(Windows::UI::WindowManagement::AppWindow const& window, Windows::Foundation::Size const& preferredFrameMinSize) const;
};
template <> struct consume<Windows::UI::WindowManagement::Preview::IWindowManagementPreviewStatics> { template <typename D> using type = consume_Windows_UI_WindowManagement_Preview_IWindowManagementPreviewStatics<D>; };

}
