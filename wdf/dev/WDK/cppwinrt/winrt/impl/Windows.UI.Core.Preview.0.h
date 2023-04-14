// C++/WinRT v1.0.190111.3

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#pragma once

WINRT_EXPORT namespace winrt::Windows::Foundation {

struct Deferral;

}

WINRT_EXPORT namespace winrt::Windows::UI::WindowManagement {

struct AppWindow;

}

WINRT_EXPORT namespace winrt::Windows::UI::Core::Preview {

struct ICoreAppWindowPreview;
struct ICoreAppWindowPreviewStatics;
struct ISystemNavigationCloseRequestedPreviewEventArgs;
struct ISystemNavigationManagerPreview;
struct ISystemNavigationManagerPreviewStatics;
struct CoreAppWindowPreview;
struct SystemNavigationCloseRequestedPreviewEventArgs;
struct SystemNavigationManagerPreview;

}

namespace winrt::impl {

template <> struct category<Windows::UI::Core::Preview::ICoreAppWindowPreview>{ using type = interface_category; };
template <> struct category<Windows::UI::Core::Preview::ICoreAppWindowPreviewStatics>{ using type = interface_category; };
template <> struct category<Windows::UI::Core::Preview::ISystemNavigationCloseRequestedPreviewEventArgs>{ using type = interface_category; };
template <> struct category<Windows::UI::Core::Preview::ISystemNavigationManagerPreview>{ using type = interface_category; };
template <> struct category<Windows::UI::Core::Preview::ISystemNavigationManagerPreviewStatics>{ using type = interface_category; };
template <> struct category<Windows::UI::Core::Preview::CoreAppWindowPreview>{ using type = class_category; };
template <> struct category<Windows::UI::Core::Preview::SystemNavigationCloseRequestedPreviewEventArgs>{ using type = class_category; };
template <> struct category<Windows::UI::Core::Preview::SystemNavigationManagerPreview>{ using type = class_category; };
template <> struct name<Windows::UI::Core::Preview::ICoreAppWindowPreview>{ static constexpr auto & value{ L"Windows.UI.Core.Preview.ICoreAppWindowPreview" }; };
template <> struct name<Windows::UI::Core::Preview::ICoreAppWindowPreviewStatics>{ static constexpr auto & value{ L"Windows.UI.Core.Preview.ICoreAppWindowPreviewStatics" }; };
template <> struct name<Windows::UI::Core::Preview::ISystemNavigationCloseRequestedPreviewEventArgs>{ static constexpr auto & value{ L"Windows.UI.Core.Preview.ISystemNavigationCloseRequestedPreviewEventArgs" }; };
template <> struct name<Windows::UI::Core::Preview::ISystemNavigationManagerPreview>{ static constexpr auto & value{ L"Windows.UI.Core.Preview.ISystemNavigationManagerPreview" }; };
template <> struct name<Windows::UI::Core::Preview::ISystemNavigationManagerPreviewStatics>{ static constexpr auto & value{ L"Windows.UI.Core.Preview.ISystemNavigationManagerPreviewStatics" }; };
template <> struct name<Windows::UI::Core::Preview::CoreAppWindowPreview>{ static constexpr auto & value{ L"Windows.UI.Core.Preview.CoreAppWindowPreview" }; };
template <> struct name<Windows::UI::Core::Preview::SystemNavigationCloseRequestedPreviewEventArgs>{ static constexpr auto & value{ L"Windows.UI.Core.Preview.SystemNavigationCloseRequestedPreviewEventArgs" }; };
template <> struct name<Windows::UI::Core::Preview::SystemNavigationManagerPreview>{ static constexpr auto & value{ L"Windows.UI.Core.Preview.SystemNavigationManagerPreview" }; };
template <> struct guid_storage<Windows::UI::Core::Preview::ICoreAppWindowPreview>{ static constexpr guid value{ 0xA4F6E665,0x365E,0x5FDE,{ 0x87,0xA5,0x95,0x43,0xC3,0xA1,0x5A,0xA8 } }; };
template <> struct guid_storage<Windows::UI::Core::Preview::ICoreAppWindowPreviewStatics>{ static constexpr guid value{ 0x33AC21BE,0x423B,0x5DB6,{ 0x8A,0x8E,0x4D,0xC8,0x73,0x53,0xB7,0x5B } }; };
template <> struct guid_storage<Windows::UI::Core::Preview::ISystemNavigationCloseRequestedPreviewEventArgs>{ static constexpr guid value{ 0x83D00DE1,0xCBE5,0x4F31,{ 0x84,0x14,0x36,0x1D,0xA0,0x46,0x51,0x8F } }; };
template <> struct guid_storage<Windows::UI::Core::Preview::ISystemNavigationManagerPreview>{ static constexpr guid value{ 0xEC5F0488,0x6425,0x4777,{ 0xA5,0x36,0xCB,0x56,0x34,0x42,0x7F,0x0D } }; };
template <> struct guid_storage<Windows::UI::Core::Preview::ISystemNavigationManagerPreviewStatics>{ static constexpr guid value{ 0x0E971360,0xDF74,0x4BCE,{ 0x84,0xCB,0xBD,0x11,0x81,0xAC,0x0A,0x71 } }; };
template <> struct default_interface<Windows::UI::Core::Preview::CoreAppWindowPreview>{ using type = Windows::UI::Core::Preview::ICoreAppWindowPreview; };
template <> struct default_interface<Windows::UI::Core::Preview::SystemNavigationCloseRequestedPreviewEventArgs>{ using type = Windows::UI::Core::Preview::ISystemNavigationCloseRequestedPreviewEventArgs; };
template <> struct default_interface<Windows::UI::Core::Preview::SystemNavigationManagerPreview>{ using type = Windows::UI::Core::Preview::ISystemNavigationManagerPreview; };

template <> struct abi<Windows::UI::Core::Preview::ICoreAppWindowPreview>{ struct type : IInspectable
{
};};

template <> struct abi<Windows::UI::Core::Preview::ICoreAppWindowPreviewStatics>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL GetIdFromWindow(void* window, int32_t* result) noexcept = 0;
};};

template <> struct abi<Windows::UI::Core::Preview::ISystemNavigationCloseRequestedPreviewEventArgs>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL get_Handled(bool* value) noexcept = 0;
    virtual int32_t WINRT_CALL put_Handled(bool value) noexcept = 0;
    virtual int32_t WINRT_CALL GetDeferral(void** result) noexcept = 0;
};};

template <> struct abi<Windows::UI::Core::Preview::ISystemNavigationManagerPreview>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL add_CloseRequested(void* handler, winrt::event_token* token) noexcept = 0;
    virtual int32_t WINRT_CALL remove_CloseRequested(winrt::event_token token) noexcept = 0;
};};

template <> struct abi<Windows::UI::Core::Preview::ISystemNavigationManagerPreviewStatics>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL GetForCurrentView(void** loader) noexcept = 0;
};};

template <typename D>
struct consume_Windows_UI_Core_Preview_ICoreAppWindowPreview
{
};
template <> struct consume<Windows::UI::Core::Preview::ICoreAppWindowPreview> { template <typename D> using type = consume_Windows_UI_Core_Preview_ICoreAppWindowPreview<D>; };

template <typename D>
struct consume_Windows_UI_Core_Preview_ICoreAppWindowPreviewStatics
{
    int32_t GetIdFromWindow(Windows::UI::WindowManagement::AppWindow const& window) const;
};
template <> struct consume<Windows::UI::Core::Preview::ICoreAppWindowPreviewStatics> { template <typename D> using type = consume_Windows_UI_Core_Preview_ICoreAppWindowPreviewStatics<D>; };

template <typename D>
struct consume_Windows_UI_Core_Preview_ISystemNavigationCloseRequestedPreviewEventArgs
{
    bool Handled() const;
    void Handled(bool value) const;
    Windows::Foundation::Deferral GetDeferral() const;
};
template <> struct consume<Windows::UI::Core::Preview::ISystemNavigationCloseRequestedPreviewEventArgs> { template <typename D> using type = consume_Windows_UI_Core_Preview_ISystemNavigationCloseRequestedPreviewEventArgs<D>; };

template <typename D>
struct consume_Windows_UI_Core_Preview_ISystemNavigationManagerPreview
{
    winrt::event_token CloseRequested(Windows::Foundation::EventHandler<Windows::UI::Core::Preview::SystemNavigationCloseRequestedPreviewEventArgs> const& handler) const;
    using CloseRequested_revoker = impl::event_revoker<Windows::UI::Core::Preview::ISystemNavigationManagerPreview, &impl::abi_t<Windows::UI::Core::Preview::ISystemNavigationManagerPreview>::remove_CloseRequested>;
    CloseRequested_revoker CloseRequested(auto_revoke_t, Windows::Foundation::EventHandler<Windows::UI::Core::Preview::SystemNavigationCloseRequestedPreviewEventArgs> const& handler) const;
    void CloseRequested(winrt::event_token const& token) const noexcept;
};
template <> struct consume<Windows::UI::Core::Preview::ISystemNavigationManagerPreview> { template <typename D> using type = consume_Windows_UI_Core_Preview_ISystemNavigationManagerPreview<D>; };

template <typename D>
struct consume_Windows_UI_Core_Preview_ISystemNavigationManagerPreviewStatics
{
    Windows::UI::Core::Preview::SystemNavigationManagerPreview GetForCurrentView() const;
};
template <> struct consume<Windows::UI::Core::Preview::ISystemNavigationManagerPreviewStatics> { template <typename D> using type = consume_Windows_UI_Core_Preview_ISystemNavigationManagerPreviewStatics<D>; };

}
