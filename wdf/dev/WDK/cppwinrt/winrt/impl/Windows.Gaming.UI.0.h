﻿// C++/WinRT v1.0.190111.3

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#pragma once

WINRT_EXPORT namespace winrt::Windows::ApplicationModel::Activation {

enum class ActivationKind;
enum class ApplicationExecutionState;
struct SplashScreen;

}

WINRT_EXPORT namespace winrt::Windows::Foundation::Collections {

struct ValueSet;

}

WINRT_EXPORT namespace winrt::Windows::Gaming::UI {

enum class GameChatMessageOrigin : int32_t
{
    Voice = 0,
    Text = 1,
};

enum class GameChatOverlayPosition : int32_t
{
    BottomCenter = 0,
    BottomLeft = 1,
    BottomRight = 2,
    MiddleRight = 3,
    MiddleLeft = 4,
    TopCenter = 5,
    TopLeft = 6,
    TopRight = 7,
};

struct IGameBarStatics;
struct IGameChatMessageReceivedEventArgs;
struct IGameChatOverlay;
struct IGameChatOverlayMessageSource;
struct IGameChatOverlayStatics;
struct IGameUIProviderActivatedEventArgs;
struct GameBar;
struct GameChatMessageReceivedEventArgs;
struct GameChatOverlay;
struct GameChatOverlayMessageSource;
struct GameUIProviderActivatedEventArgs;

}

namespace winrt::impl {

template <> struct category<Windows::Gaming::UI::IGameBarStatics>{ using type = interface_category; };
template <> struct category<Windows::Gaming::UI::IGameChatMessageReceivedEventArgs>{ using type = interface_category; };
template <> struct category<Windows::Gaming::UI::IGameChatOverlay>{ using type = interface_category; };
template <> struct category<Windows::Gaming::UI::IGameChatOverlayMessageSource>{ using type = interface_category; };
template <> struct category<Windows::Gaming::UI::IGameChatOverlayStatics>{ using type = interface_category; };
template <> struct category<Windows::Gaming::UI::IGameUIProviderActivatedEventArgs>{ using type = interface_category; };
template <> struct category<Windows::Gaming::UI::GameBar>{ using type = class_category; };
template <> struct category<Windows::Gaming::UI::GameChatMessageReceivedEventArgs>{ using type = class_category; };
template <> struct category<Windows::Gaming::UI::GameChatOverlay>{ using type = class_category; };
template <> struct category<Windows::Gaming::UI::GameChatOverlayMessageSource>{ using type = class_category; };
template <> struct category<Windows::Gaming::UI::GameUIProviderActivatedEventArgs>{ using type = class_category; };
template <> struct category<Windows::Gaming::UI::GameChatMessageOrigin>{ using type = enum_category; };
template <> struct category<Windows::Gaming::UI::GameChatOverlayPosition>{ using type = enum_category; };
template <> struct name<Windows::Gaming::UI::IGameBarStatics>{ static constexpr auto & value{ L"Windows.Gaming.UI.IGameBarStatics" }; };
template <> struct name<Windows::Gaming::UI::IGameChatMessageReceivedEventArgs>{ static constexpr auto & value{ L"Windows.Gaming.UI.IGameChatMessageReceivedEventArgs" }; };
template <> struct name<Windows::Gaming::UI::IGameChatOverlay>{ static constexpr auto & value{ L"Windows.Gaming.UI.IGameChatOverlay" }; };
template <> struct name<Windows::Gaming::UI::IGameChatOverlayMessageSource>{ static constexpr auto & value{ L"Windows.Gaming.UI.IGameChatOverlayMessageSource" }; };
template <> struct name<Windows::Gaming::UI::IGameChatOverlayStatics>{ static constexpr auto & value{ L"Windows.Gaming.UI.IGameChatOverlayStatics" }; };
template <> struct name<Windows::Gaming::UI::IGameUIProviderActivatedEventArgs>{ static constexpr auto & value{ L"Windows.Gaming.UI.IGameUIProviderActivatedEventArgs" }; };
template <> struct name<Windows::Gaming::UI::GameBar>{ static constexpr auto & value{ L"Windows.Gaming.UI.GameBar" }; };
template <> struct name<Windows::Gaming::UI::GameChatMessageReceivedEventArgs>{ static constexpr auto & value{ L"Windows.Gaming.UI.GameChatMessageReceivedEventArgs" }; };
template <> struct name<Windows::Gaming::UI::GameChatOverlay>{ static constexpr auto & value{ L"Windows.Gaming.UI.GameChatOverlay" }; };
template <> struct name<Windows::Gaming::UI::GameChatOverlayMessageSource>{ static constexpr auto & value{ L"Windows.Gaming.UI.GameChatOverlayMessageSource" }; };
template <> struct name<Windows::Gaming::UI::GameUIProviderActivatedEventArgs>{ static constexpr auto & value{ L"Windows.Gaming.UI.GameUIProviderActivatedEventArgs" }; };
template <> struct name<Windows::Gaming::UI::GameChatMessageOrigin>{ static constexpr auto & value{ L"Windows.Gaming.UI.GameChatMessageOrigin" }; };
template <> struct name<Windows::Gaming::UI::GameChatOverlayPosition>{ static constexpr auto & value{ L"Windows.Gaming.UI.GameChatOverlayPosition" }; };
template <> struct guid_storage<Windows::Gaming::UI::IGameBarStatics>{ static constexpr guid value{ 0x1DB9A292,0xCC78,0x4173,{ 0xBE,0x45,0xB6,0x1E,0x67,0x28,0x3E,0xA7 } }; };
template <> struct guid_storage<Windows::Gaming::UI::IGameChatMessageReceivedEventArgs>{ static constexpr guid value{ 0xA28201F1,0x3FB9,0x4E42,{ 0xA4,0x03,0x7A,0xFC,0xE2,0x02,0x3B,0x1E } }; };
template <> struct guid_storage<Windows::Gaming::UI::IGameChatOverlay>{ static constexpr guid value{ 0xFBC64865,0xF6FC,0x4A48,{ 0xAE,0x07,0x03,0xAC,0x6E,0xD4,0x37,0x04 } }; };
template <> struct guid_storage<Windows::Gaming::UI::IGameChatOverlayMessageSource>{ static constexpr guid value{ 0x1E177397,0x59FB,0x4F4F,{ 0x8E,0x9A,0x80,0xAC,0xF8,0x17,0x74,0x3C } }; };
template <> struct guid_storage<Windows::Gaming::UI::IGameChatOverlayStatics>{ static constexpr guid value{ 0x89ACF614,0x7867,0x49F7,{ 0x96,0x87,0x25,0xD9,0xDB,0xF4,0x44,0xD1 } }; };
template <> struct guid_storage<Windows::Gaming::UI::IGameUIProviderActivatedEventArgs>{ static constexpr guid value{ 0xA7B3203E,0xCAF7,0x4DED,{ 0xBB,0xD2,0x47,0xDE,0x43,0xBB,0x6D,0xD5 } }; };
template <> struct default_interface<Windows::Gaming::UI::GameChatMessageReceivedEventArgs>{ using type = Windows::Gaming::UI::IGameChatMessageReceivedEventArgs; };
template <> struct default_interface<Windows::Gaming::UI::GameChatOverlay>{ using type = Windows::Gaming::UI::IGameChatOverlay; };
template <> struct default_interface<Windows::Gaming::UI::GameChatOverlayMessageSource>{ using type = Windows::Gaming::UI::IGameChatOverlayMessageSource; };
template <> struct default_interface<Windows::Gaming::UI::GameUIProviderActivatedEventArgs>{ using type = Windows::Gaming::UI::IGameUIProviderActivatedEventArgs; };

template <> struct abi<Windows::Gaming::UI::IGameBarStatics>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL add_VisibilityChanged(void* handler, winrt::event_token* token) noexcept = 0;
    virtual int32_t WINRT_CALL remove_VisibilityChanged(winrt::event_token token) noexcept = 0;
    virtual int32_t WINRT_CALL add_IsInputRedirectedChanged(void* handler, winrt::event_token* token) noexcept = 0;
    virtual int32_t WINRT_CALL remove_IsInputRedirectedChanged(winrt::event_token token) noexcept = 0;
    virtual int32_t WINRT_CALL get_Visible(bool* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_IsInputRedirected(bool* value) noexcept = 0;
};};

template <> struct abi<Windows::Gaming::UI::IGameChatMessageReceivedEventArgs>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL get_AppId(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_AppDisplayName(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_SenderName(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_Message(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_Origin(Windows::Gaming::UI::GameChatMessageOrigin* value) noexcept = 0;
};};

template <> struct abi<Windows::Gaming::UI::IGameChatOverlay>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL get_DesiredPosition(Windows::Gaming::UI::GameChatOverlayPosition* value) noexcept = 0;
    virtual int32_t WINRT_CALL put_DesiredPosition(Windows::Gaming::UI::GameChatOverlayPosition value) noexcept = 0;
    virtual int32_t WINRT_CALL AddMessage(void* sender, void* message, Windows::Gaming::UI::GameChatMessageOrigin origin) noexcept = 0;
};};

template <> struct abi<Windows::Gaming::UI::IGameChatOverlayMessageSource>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL add_MessageReceived(void* handler, winrt::event_token* token) noexcept = 0;
    virtual int32_t WINRT_CALL remove_MessageReceived(winrt::event_token token) noexcept = 0;
    virtual int32_t WINRT_CALL SetDelayBeforeClosingAfterMessageReceived(Windows::Foundation::TimeSpan value) noexcept = 0;
};};

template <> struct abi<Windows::Gaming::UI::IGameChatOverlayStatics>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL GetDefault(void** value) noexcept = 0;
};};

template <> struct abi<Windows::Gaming::UI::IGameUIProviderActivatedEventArgs>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL get_GameUIArgs(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL ReportCompleted(void* results) noexcept = 0;
};};

template <typename D>
struct consume_Windows_Gaming_UI_IGameBarStatics
{
    winrt::event_token VisibilityChanged(Windows::Foundation::EventHandler<Windows::Foundation::IInspectable> const& handler) const;
    using VisibilityChanged_revoker = impl::event_revoker<Windows::Gaming::UI::IGameBarStatics, &impl::abi_t<Windows::Gaming::UI::IGameBarStatics>::remove_VisibilityChanged>;
    VisibilityChanged_revoker VisibilityChanged(auto_revoke_t, Windows::Foundation::EventHandler<Windows::Foundation::IInspectable> const& handler) const;
    void VisibilityChanged(winrt::event_token const& token) const noexcept;
    winrt::event_token IsInputRedirectedChanged(Windows::Foundation::EventHandler<Windows::Foundation::IInspectable> const& handler) const;
    using IsInputRedirectedChanged_revoker = impl::event_revoker<Windows::Gaming::UI::IGameBarStatics, &impl::abi_t<Windows::Gaming::UI::IGameBarStatics>::remove_IsInputRedirectedChanged>;
    IsInputRedirectedChanged_revoker IsInputRedirectedChanged(auto_revoke_t, Windows::Foundation::EventHandler<Windows::Foundation::IInspectable> const& handler) const;
    void IsInputRedirectedChanged(winrt::event_token const& token) const noexcept;
    bool Visible() const;
    bool IsInputRedirected() const;
};
template <> struct consume<Windows::Gaming::UI::IGameBarStatics> { template <typename D> using type = consume_Windows_Gaming_UI_IGameBarStatics<D>; };

template <typename D>
struct consume_Windows_Gaming_UI_IGameChatMessageReceivedEventArgs
{
    hstring AppId() const;
    hstring AppDisplayName() const;
    hstring SenderName() const;
    hstring Message() const;
    Windows::Gaming::UI::GameChatMessageOrigin Origin() const;
};
template <> struct consume<Windows::Gaming::UI::IGameChatMessageReceivedEventArgs> { template <typename D> using type = consume_Windows_Gaming_UI_IGameChatMessageReceivedEventArgs<D>; };

template <typename D>
struct consume_Windows_Gaming_UI_IGameChatOverlay
{
    Windows::Gaming::UI::GameChatOverlayPosition DesiredPosition() const;
    void DesiredPosition(Windows::Gaming::UI::GameChatOverlayPosition const& value) const;
    void AddMessage(param::hstring const& sender, param::hstring const& message, Windows::Gaming::UI::GameChatMessageOrigin const& origin) const;
};
template <> struct consume<Windows::Gaming::UI::IGameChatOverlay> { template <typename D> using type = consume_Windows_Gaming_UI_IGameChatOverlay<D>; };

template <typename D>
struct consume_Windows_Gaming_UI_IGameChatOverlayMessageSource
{
    winrt::event_token MessageReceived(Windows::Foundation::TypedEventHandler<Windows::Gaming::UI::GameChatOverlayMessageSource, Windows::Gaming::UI::GameChatMessageReceivedEventArgs> const& handler) const;
    using MessageReceived_revoker = impl::event_revoker<Windows::Gaming::UI::IGameChatOverlayMessageSource, &impl::abi_t<Windows::Gaming::UI::IGameChatOverlayMessageSource>::remove_MessageReceived>;
    MessageReceived_revoker MessageReceived(auto_revoke_t, Windows::Foundation::TypedEventHandler<Windows::Gaming::UI::GameChatOverlayMessageSource, Windows::Gaming::UI::GameChatMessageReceivedEventArgs> const& handler) const;
    void MessageReceived(winrt::event_token const& token) const noexcept;
    void SetDelayBeforeClosingAfterMessageReceived(Windows::Foundation::TimeSpan const& value) const;
};
template <> struct consume<Windows::Gaming::UI::IGameChatOverlayMessageSource> { template <typename D> using type = consume_Windows_Gaming_UI_IGameChatOverlayMessageSource<D>; };

template <typename D>
struct consume_Windows_Gaming_UI_IGameChatOverlayStatics
{
    Windows::Gaming::UI::GameChatOverlay GetDefault() const;
};
template <> struct consume<Windows::Gaming::UI::IGameChatOverlayStatics> { template <typename D> using type = consume_Windows_Gaming_UI_IGameChatOverlayStatics<D>; };

template <typename D>
struct consume_Windows_Gaming_UI_IGameUIProviderActivatedEventArgs
{
    Windows::Foundation::Collections::ValueSet GameUIArgs() const;
    void ReportCompleted(Windows::Foundation::Collections::ValueSet const& results) const;
};
template <> struct consume<Windows::Gaming::UI::IGameUIProviderActivatedEventArgs> { template <typename D> using type = consume_Windows_Gaming_UI_IGameUIProviderActivatedEventArgs<D>; };

}
