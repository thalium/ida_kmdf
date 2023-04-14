// C++/WinRT v1.0.190111.3

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#pragma once

WINRT_EXPORT namespace winrt::Windows::UI {

struct UIContext;

}

WINRT_EXPORT namespace winrt::Windows::UI::ViewManagement::Core {

enum class CoreInputViewKind : int32_t
{
    Default = 0,
    Keyboard = 1,
    Handwriting = 2,
    Emoji = 3,
};

enum class CoreInputViewOcclusionKind : int32_t
{
    Docked = 0,
    Floating = 1,
    Overlay = 2,
};

enum class CoreInputViewXYFocusTransferDirection : int32_t
{
    Up = 0,
    Right = 1,
    Down = 2,
    Left = 3,
};

struct ICoreInputView;
struct ICoreInputView2;
struct ICoreInputView3;
struct ICoreInputViewOcclusion;
struct ICoreInputViewOcclusionsChangedEventArgs;
struct ICoreInputViewStatics;
struct ICoreInputViewStatics2;
struct ICoreInputViewTransferringXYFocusEventArgs;
struct CoreInputView;
struct CoreInputViewOcclusion;
struct CoreInputViewOcclusionsChangedEventArgs;
struct CoreInputViewTransferringXYFocusEventArgs;

}

namespace winrt::impl {

template <> struct category<Windows::UI::ViewManagement::Core::ICoreInputView>{ using type = interface_category; };
template <> struct category<Windows::UI::ViewManagement::Core::ICoreInputView2>{ using type = interface_category; };
template <> struct category<Windows::UI::ViewManagement::Core::ICoreInputView3>{ using type = interface_category; };
template <> struct category<Windows::UI::ViewManagement::Core::ICoreInputViewOcclusion>{ using type = interface_category; };
template <> struct category<Windows::UI::ViewManagement::Core::ICoreInputViewOcclusionsChangedEventArgs>{ using type = interface_category; };
template <> struct category<Windows::UI::ViewManagement::Core::ICoreInputViewStatics>{ using type = interface_category; };
template <> struct category<Windows::UI::ViewManagement::Core::ICoreInputViewStatics2>{ using type = interface_category; };
template <> struct category<Windows::UI::ViewManagement::Core::ICoreInputViewTransferringXYFocusEventArgs>{ using type = interface_category; };
template <> struct category<Windows::UI::ViewManagement::Core::CoreInputView>{ using type = class_category; };
template <> struct category<Windows::UI::ViewManagement::Core::CoreInputViewOcclusion>{ using type = class_category; };
template <> struct category<Windows::UI::ViewManagement::Core::CoreInputViewOcclusionsChangedEventArgs>{ using type = class_category; };
template <> struct category<Windows::UI::ViewManagement::Core::CoreInputViewTransferringXYFocusEventArgs>{ using type = class_category; };
template <> struct category<Windows::UI::ViewManagement::Core::CoreInputViewKind>{ using type = enum_category; };
template <> struct category<Windows::UI::ViewManagement::Core::CoreInputViewOcclusionKind>{ using type = enum_category; };
template <> struct category<Windows::UI::ViewManagement::Core::CoreInputViewXYFocusTransferDirection>{ using type = enum_category; };
template <> struct name<Windows::UI::ViewManagement::Core::ICoreInputView>{ static constexpr auto & value{ L"Windows.UI.ViewManagement.Core.ICoreInputView" }; };
template <> struct name<Windows::UI::ViewManagement::Core::ICoreInputView2>{ static constexpr auto & value{ L"Windows.UI.ViewManagement.Core.ICoreInputView2" }; };
template <> struct name<Windows::UI::ViewManagement::Core::ICoreInputView3>{ static constexpr auto & value{ L"Windows.UI.ViewManagement.Core.ICoreInputView3" }; };
template <> struct name<Windows::UI::ViewManagement::Core::ICoreInputViewOcclusion>{ static constexpr auto & value{ L"Windows.UI.ViewManagement.Core.ICoreInputViewOcclusion" }; };
template <> struct name<Windows::UI::ViewManagement::Core::ICoreInputViewOcclusionsChangedEventArgs>{ static constexpr auto & value{ L"Windows.UI.ViewManagement.Core.ICoreInputViewOcclusionsChangedEventArgs" }; };
template <> struct name<Windows::UI::ViewManagement::Core::ICoreInputViewStatics>{ static constexpr auto & value{ L"Windows.UI.ViewManagement.Core.ICoreInputViewStatics" }; };
template <> struct name<Windows::UI::ViewManagement::Core::ICoreInputViewStatics2>{ static constexpr auto & value{ L"Windows.UI.ViewManagement.Core.ICoreInputViewStatics2" }; };
template <> struct name<Windows::UI::ViewManagement::Core::ICoreInputViewTransferringXYFocusEventArgs>{ static constexpr auto & value{ L"Windows.UI.ViewManagement.Core.ICoreInputViewTransferringXYFocusEventArgs" }; };
template <> struct name<Windows::UI::ViewManagement::Core::CoreInputView>{ static constexpr auto & value{ L"Windows.UI.ViewManagement.Core.CoreInputView" }; };
template <> struct name<Windows::UI::ViewManagement::Core::CoreInputViewOcclusion>{ static constexpr auto & value{ L"Windows.UI.ViewManagement.Core.CoreInputViewOcclusion" }; };
template <> struct name<Windows::UI::ViewManagement::Core::CoreInputViewOcclusionsChangedEventArgs>{ static constexpr auto & value{ L"Windows.UI.ViewManagement.Core.CoreInputViewOcclusionsChangedEventArgs" }; };
template <> struct name<Windows::UI::ViewManagement::Core::CoreInputViewTransferringXYFocusEventArgs>{ static constexpr auto & value{ L"Windows.UI.ViewManagement.Core.CoreInputViewTransferringXYFocusEventArgs" }; };
template <> struct name<Windows::UI::ViewManagement::Core::CoreInputViewKind>{ static constexpr auto & value{ L"Windows.UI.ViewManagement.Core.CoreInputViewKind" }; };
template <> struct name<Windows::UI::ViewManagement::Core::CoreInputViewOcclusionKind>{ static constexpr auto & value{ L"Windows.UI.ViewManagement.Core.CoreInputViewOcclusionKind" }; };
template <> struct name<Windows::UI::ViewManagement::Core::CoreInputViewXYFocusTransferDirection>{ static constexpr auto & value{ L"Windows.UI.ViewManagement.Core.CoreInputViewXYFocusTransferDirection" }; };
template <> struct guid_storage<Windows::UI::ViewManagement::Core::ICoreInputView>{ static constexpr guid value{ 0xC770CD7A,0x7001,0x4C32,{ 0xBF,0x94,0x25,0xC1,0xF5,0x54,0xCB,0xF1 } }; };
template <> struct guid_storage<Windows::UI::ViewManagement::Core::ICoreInputView2>{ static constexpr guid value{ 0x0ED726C1,0xE09A,0x4AE8,{ 0xAE,0xDF,0xDF,0xA4,0x85,0x7D,0x1A,0x01 } }; };
template <> struct guid_storage<Windows::UI::ViewManagement::Core::ICoreInputView3>{ static constexpr guid value{ 0xBC941653,0x3AB9,0x4849,{ 0x8F,0x58,0x46,0xE7,0xF0,0x35,0x3C,0xFC } }; };
template <> struct guid_storage<Windows::UI::ViewManagement::Core::ICoreInputViewOcclusion>{ static constexpr guid value{ 0xCC36CE06,0x3865,0x4177,{ 0xB5,0xF5,0x8B,0x65,0xE0,0xB9,0xCE,0x84 } }; };
template <> struct guid_storage<Windows::UI::ViewManagement::Core::ICoreInputViewOcclusionsChangedEventArgs>{ static constexpr guid value{ 0xBE1027E8,0xB3EE,0x4DF7,{ 0x95,0x54,0x89,0xCD,0xC6,0x60,0x82,0xC2 } }; };
template <> struct guid_storage<Windows::UI::ViewManagement::Core::ICoreInputViewStatics>{ static constexpr guid value{ 0x7D9B97CD,0xEDBE,0x49CF,{ 0xA5,0x4F,0x33,0x7D,0xE0,0x52,0x90,0x7F } }; };
template <> struct guid_storage<Windows::UI::ViewManagement::Core::ICoreInputViewStatics2>{ static constexpr guid value{ 0x7EBC0862,0xD049,0x4E52,{ 0x87,0xB0,0x1E,0x90,0xE9,0x8C,0x49,0xED } }; };
template <> struct guid_storage<Windows::UI::ViewManagement::Core::ICoreInputViewTransferringXYFocusEventArgs>{ static constexpr guid value{ 0x04DE169F,0xBA02,0x4850,{ 0x8B,0x55,0xD8,0x2D,0x03,0xBA,0x6D,0x7F } }; };
template <> struct default_interface<Windows::UI::ViewManagement::Core::CoreInputView>{ using type = Windows::UI::ViewManagement::Core::ICoreInputView; };
template <> struct default_interface<Windows::UI::ViewManagement::Core::CoreInputViewOcclusion>{ using type = Windows::UI::ViewManagement::Core::ICoreInputViewOcclusion; };
template <> struct default_interface<Windows::UI::ViewManagement::Core::CoreInputViewOcclusionsChangedEventArgs>{ using type = Windows::UI::ViewManagement::Core::ICoreInputViewOcclusionsChangedEventArgs; };
template <> struct default_interface<Windows::UI::ViewManagement::Core::CoreInputViewTransferringXYFocusEventArgs>{ using type = Windows::UI::ViewManagement::Core::ICoreInputViewTransferringXYFocusEventArgs; };

template <> struct abi<Windows::UI::ViewManagement::Core::ICoreInputView>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL add_OcclusionsChanged(void* handler, winrt::event_token* token) noexcept = 0;
    virtual int32_t WINRT_CALL remove_OcclusionsChanged(winrt::event_token token) noexcept = 0;
    virtual int32_t WINRT_CALL GetCoreInputViewOcclusions(void** result) noexcept = 0;
    virtual int32_t WINRT_CALL TryShowPrimaryView(bool* result) noexcept = 0;
    virtual int32_t WINRT_CALL TryHidePrimaryView(bool* result) noexcept = 0;
};};

template <> struct abi<Windows::UI::ViewManagement::Core::ICoreInputView2>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL add_XYFocusTransferringFromPrimaryView(void* handler, winrt::event_token* token) noexcept = 0;
    virtual int32_t WINRT_CALL remove_XYFocusTransferringFromPrimaryView(winrt::event_token token) noexcept = 0;
    virtual int32_t WINRT_CALL add_XYFocusTransferredToPrimaryView(void* handler, winrt::event_token* token) noexcept = 0;
    virtual int32_t WINRT_CALL remove_XYFocusTransferredToPrimaryView(winrt::event_token token) noexcept = 0;
    virtual int32_t WINRT_CALL TryTransferXYFocusToPrimaryView(Windows::Foundation::Rect origin, Windows::UI::ViewManagement::Core::CoreInputViewXYFocusTransferDirection direction, bool* result) noexcept = 0;
};};

template <> struct abi<Windows::UI::ViewManagement::Core::ICoreInputView3>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL TryShow(bool* result) noexcept = 0;
    virtual int32_t WINRT_CALL TryShowWithKind(Windows::UI::ViewManagement::Core::CoreInputViewKind type, bool* result) noexcept = 0;
    virtual int32_t WINRT_CALL TryHide(bool* result) noexcept = 0;
};};

template <> struct abi<Windows::UI::ViewManagement::Core::ICoreInputViewOcclusion>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL get_OccludingRect(Windows::Foundation::Rect* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_OcclusionKind(Windows::UI::ViewManagement::Core::CoreInputViewOcclusionKind* value) noexcept = 0;
};};

template <> struct abi<Windows::UI::ViewManagement::Core::ICoreInputViewOcclusionsChangedEventArgs>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL get_Occlusions(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_Handled(bool* value) noexcept = 0;
    virtual int32_t WINRT_CALL put_Handled(bool value) noexcept = 0;
};};

template <> struct abi<Windows::UI::ViewManagement::Core::ICoreInputViewStatics>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL GetForCurrentView(void** result) noexcept = 0;
};};

template <> struct abi<Windows::UI::ViewManagement::Core::ICoreInputViewStatics2>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL GetForUIContext(void* context, void** result) noexcept = 0;
};};

template <> struct abi<Windows::UI::ViewManagement::Core::ICoreInputViewTransferringXYFocusEventArgs>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL get_Origin(Windows::Foundation::Rect* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_Direction(Windows::UI::ViewManagement::Core::CoreInputViewXYFocusTransferDirection* value) noexcept = 0;
    virtual int32_t WINRT_CALL put_TransferHandled(bool value) noexcept = 0;
    virtual int32_t WINRT_CALL get_TransferHandled(bool* value) noexcept = 0;
    virtual int32_t WINRT_CALL put_KeepPrimaryViewVisible(bool value) noexcept = 0;
    virtual int32_t WINRT_CALL get_KeepPrimaryViewVisible(bool* value) noexcept = 0;
};};

template <typename D>
struct consume_Windows_UI_ViewManagement_Core_ICoreInputView
{
    winrt::event_token OcclusionsChanged(Windows::Foundation::TypedEventHandler<Windows::UI::ViewManagement::Core::CoreInputView, Windows::UI::ViewManagement::Core::CoreInputViewOcclusionsChangedEventArgs> const& handler) const;
    using OcclusionsChanged_revoker = impl::event_revoker<Windows::UI::ViewManagement::Core::ICoreInputView, &impl::abi_t<Windows::UI::ViewManagement::Core::ICoreInputView>::remove_OcclusionsChanged>;
    OcclusionsChanged_revoker OcclusionsChanged(auto_revoke_t, Windows::Foundation::TypedEventHandler<Windows::UI::ViewManagement::Core::CoreInputView, Windows::UI::ViewManagement::Core::CoreInputViewOcclusionsChangedEventArgs> const& handler) const;
    void OcclusionsChanged(winrt::event_token const& token) const noexcept;
    Windows::Foundation::Collections::IVectorView<Windows::UI::ViewManagement::Core::CoreInputViewOcclusion> GetCoreInputViewOcclusions() const;
    bool TryShowPrimaryView() const;
    bool TryHidePrimaryView() const;
};
template <> struct consume<Windows::UI::ViewManagement::Core::ICoreInputView> { template <typename D> using type = consume_Windows_UI_ViewManagement_Core_ICoreInputView<D>; };

template <typename D>
struct consume_Windows_UI_ViewManagement_Core_ICoreInputView2
{
    winrt::event_token XYFocusTransferringFromPrimaryView(Windows::Foundation::TypedEventHandler<Windows::UI::ViewManagement::Core::CoreInputView, Windows::UI::ViewManagement::Core::CoreInputViewTransferringXYFocusEventArgs> const& handler) const;
    using XYFocusTransferringFromPrimaryView_revoker = impl::event_revoker<Windows::UI::ViewManagement::Core::ICoreInputView2, &impl::abi_t<Windows::UI::ViewManagement::Core::ICoreInputView2>::remove_XYFocusTransferringFromPrimaryView>;
    XYFocusTransferringFromPrimaryView_revoker XYFocusTransferringFromPrimaryView(auto_revoke_t, Windows::Foundation::TypedEventHandler<Windows::UI::ViewManagement::Core::CoreInputView, Windows::UI::ViewManagement::Core::CoreInputViewTransferringXYFocusEventArgs> const& handler) const;
    void XYFocusTransferringFromPrimaryView(winrt::event_token const& token) const noexcept;
    winrt::event_token XYFocusTransferredToPrimaryView(Windows::Foundation::TypedEventHandler<Windows::UI::ViewManagement::Core::CoreInputView, Windows::Foundation::IInspectable> const& handler) const;
    using XYFocusTransferredToPrimaryView_revoker = impl::event_revoker<Windows::UI::ViewManagement::Core::ICoreInputView2, &impl::abi_t<Windows::UI::ViewManagement::Core::ICoreInputView2>::remove_XYFocusTransferredToPrimaryView>;
    XYFocusTransferredToPrimaryView_revoker XYFocusTransferredToPrimaryView(auto_revoke_t, Windows::Foundation::TypedEventHandler<Windows::UI::ViewManagement::Core::CoreInputView, Windows::Foundation::IInspectable> const& handler) const;
    void XYFocusTransferredToPrimaryView(winrt::event_token const& token) const noexcept;
    bool TryTransferXYFocusToPrimaryView(Windows::Foundation::Rect const& origin, Windows::UI::ViewManagement::Core::CoreInputViewXYFocusTransferDirection const& direction) const;
};
template <> struct consume<Windows::UI::ViewManagement::Core::ICoreInputView2> { template <typename D> using type = consume_Windows_UI_ViewManagement_Core_ICoreInputView2<D>; };

template <typename D>
struct consume_Windows_UI_ViewManagement_Core_ICoreInputView3
{
    bool TryShow() const;
    bool TryShow(Windows::UI::ViewManagement::Core::CoreInputViewKind const& type) const;
    bool TryHide() const;
};
template <> struct consume<Windows::UI::ViewManagement::Core::ICoreInputView3> { template <typename D> using type = consume_Windows_UI_ViewManagement_Core_ICoreInputView3<D>; };

template <typename D>
struct consume_Windows_UI_ViewManagement_Core_ICoreInputViewOcclusion
{
    Windows::Foundation::Rect OccludingRect() const;
    Windows::UI::ViewManagement::Core::CoreInputViewOcclusionKind OcclusionKind() const;
};
template <> struct consume<Windows::UI::ViewManagement::Core::ICoreInputViewOcclusion> { template <typename D> using type = consume_Windows_UI_ViewManagement_Core_ICoreInputViewOcclusion<D>; };

template <typename D>
struct consume_Windows_UI_ViewManagement_Core_ICoreInputViewOcclusionsChangedEventArgs
{
    Windows::Foundation::Collections::IVectorView<Windows::UI::ViewManagement::Core::CoreInputViewOcclusion> Occlusions() const;
    bool Handled() const;
    void Handled(bool value) const;
};
template <> struct consume<Windows::UI::ViewManagement::Core::ICoreInputViewOcclusionsChangedEventArgs> { template <typename D> using type = consume_Windows_UI_ViewManagement_Core_ICoreInputViewOcclusionsChangedEventArgs<D>; };

template <typename D>
struct consume_Windows_UI_ViewManagement_Core_ICoreInputViewStatics
{
    Windows::UI::ViewManagement::Core::CoreInputView GetForCurrentView() const;
};
template <> struct consume<Windows::UI::ViewManagement::Core::ICoreInputViewStatics> { template <typename D> using type = consume_Windows_UI_ViewManagement_Core_ICoreInputViewStatics<D>; };

template <typename D>
struct consume_Windows_UI_ViewManagement_Core_ICoreInputViewStatics2
{
    Windows::UI::ViewManagement::Core::CoreInputView GetForUIContext(Windows::UI::UIContext const& context) const;
};
template <> struct consume<Windows::UI::ViewManagement::Core::ICoreInputViewStatics2> { template <typename D> using type = consume_Windows_UI_ViewManagement_Core_ICoreInputViewStatics2<D>; };

template <typename D>
struct consume_Windows_UI_ViewManagement_Core_ICoreInputViewTransferringXYFocusEventArgs
{
    Windows::Foundation::Rect Origin() const;
    Windows::UI::ViewManagement::Core::CoreInputViewXYFocusTransferDirection Direction() const;
    void TransferHandled(bool value) const;
    bool TransferHandled() const;
    void KeepPrimaryViewVisible(bool value) const;
    bool KeepPrimaryViewVisible() const;
};
template <> struct consume<Windows::UI::ViewManagement::Core::ICoreInputViewTransferringXYFocusEventArgs> { template <typename D> using type = consume_Windows_UI_ViewManagement_Core_ICoreInputViewTransferringXYFocusEventArgs<D>; };

}
