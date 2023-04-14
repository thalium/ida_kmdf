// C++/WinRT v1.0.190111.3

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#pragma once

WINRT_EXPORT namespace winrt::Windows::ApplicationModel::Core {

struct AppListEntry;

}

WINRT_EXPORT namespace winrt::Windows::Foundation {

struct Uri;

}

WINRT_EXPORT namespace winrt::Windows::UI::StartScreen {

struct SecondaryTile;

}

WINRT_EXPORT namespace winrt::Windows::UI::Shell {

enum class SecurityAppKind : int32_t
{
    WebProtection = 0,
};

enum class SecurityAppState : int32_t
{
    Disabled = 0,
    Enabled = 1,
};

enum class SecurityAppSubstatus : int32_t
{
    Undetermined = 0,
    NoActionNeeded = 1,
    ActionRecommended = 2,
    ActionNeeded = 3,
};

struct IAdaptiveCard;
struct IAdaptiveCardBuilderStatics;
struct ISecurityAppManager;
struct ITaskbarManager;
struct ITaskbarManager2;
struct ITaskbarManagerStatics;
struct AdaptiveCardBuilder;
struct SecurityAppManager;
struct TaskbarManager;

}

namespace winrt::impl {

template <> struct category<Windows::UI::Shell::IAdaptiveCard>{ using type = interface_category; };
template <> struct category<Windows::UI::Shell::IAdaptiveCardBuilderStatics>{ using type = interface_category; };
template <> struct category<Windows::UI::Shell::ISecurityAppManager>{ using type = interface_category; };
template <> struct category<Windows::UI::Shell::ITaskbarManager>{ using type = interface_category; };
template <> struct category<Windows::UI::Shell::ITaskbarManager2>{ using type = interface_category; };
template <> struct category<Windows::UI::Shell::ITaskbarManagerStatics>{ using type = interface_category; };
template <> struct category<Windows::UI::Shell::AdaptiveCardBuilder>{ using type = class_category; };
template <> struct category<Windows::UI::Shell::SecurityAppManager>{ using type = class_category; };
template <> struct category<Windows::UI::Shell::TaskbarManager>{ using type = class_category; };
template <> struct category<Windows::UI::Shell::SecurityAppKind>{ using type = enum_category; };
template <> struct category<Windows::UI::Shell::SecurityAppState>{ using type = enum_category; };
template <> struct category<Windows::UI::Shell::SecurityAppSubstatus>{ using type = enum_category; };
template <> struct name<Windows::UI::Shell::IAdaptiveCard>{ static constexpr auto & value{ L"Windows.UI.Shell.IAdaptiveCard" }; };
template <> struct name<Windows::UI::Shell::IAdaptiveCardBuilderStatics>{ static constexpr auto & value{ L"Windows.UI.Shell.IAdaptiveCardBuilderStatics" }; };
template <> struct name<Windows::UI::Shell::ISecurityAppManager>{ static constexpr auto & value{ L"Windows.UI.Shell.ISecurityAppManager" }; };
template <> struct name<Windows::UI::Shell::ITaskbarManager>{ static constexpr auto & value{ L"Windows.UI.Shell.ITaskbarManager" }; };
template <> struct name<Windows::UI::Shell::ITaskbarManager2>{ static constexpr auto & value{ L"Windows.UI.Shell.ITaskbarManager2" }; };
template <> struct name<Windows::UI::Shell::ITaskbarManagerStatics>{ static constexpr auto & value{ L"Windows.UI.Shell.ITaskbarManagerStatics" }; };
template <> struct name<Windows::UI::Shell::AdaptiveCardBuilder>{ static constexpr auto & value{ L"Windows.UI.Shell.AdaptiveCardBuilder" }; };
template <> struct name<Windows::UI::Shell::SecurityAppManager>{ static constexpr auto & value{ L"Windows.UI.Shell.SecurityAppManager" }; };
template <> struct name<Windows::UI::Shell::TaskbarManager>{ static constexpr auto & value{ L"Windows.UI.Shell.TaskbarManager" }; };
template <> struct name<Windows::UI::Shell::SecurityAppKind>{ static constexpr auto & value{ L"Windows.UI.Shell.SecurityAppKind" }; };
template <> struct name<Windows::UI::Shell::SecurityAppState>{ static constexpr auto & value{ L"Windows.UI.Shell.SecurityAppState" }; };
template <> struct name<Windows::UI::Shell::SecurityAppSubstatus>{ static constexpr auto & value{ L"Windows.UI.Shell.SecurityAppSubstatus" }; };
template <> struct guid_storage<Windows::UI::Shell::IAdaptiveCard>{ static constexpr guid value{ 0x72D0568C,0xA274,0x41CD,{ 0x82,0xA8,0x98,0x9D,0x40,0xB9,0xB0,0x5E } }; };
template <> struct guid_storage<Windows::UI::Shell::IAdaptiveCardBuilderStatics>{ static constexpr guid value{ 0x766D8F08,0xD3FE,0x4347,{ 0xA0,0xBC,0xB9,0xEA,0x9A,0x6D,0xC2,0x8E } }; };
template <> struct guid_storage<Windows::UI::Shell::ISecurityAppManager>{ static constexpr guid value{ 0x96AC500C,0xAED4,0x561D,{ 0xBD,0xE8,0x95,0x35,0x20,0x34,0x3A,0x2D } }; };
template <> struct guid_storage<Windows::UI::Shell::ITaskbarManager>{ static constexpr guid value{ 0x87490A19,0x1AD9,0x49F4,{ 0xB2,0xE8,0x86,0x73,0x8D,0xC5,0xAC,0x40 } }; };
template <> struct guid_storage<Windows::UI::Shell::ITaskbarManager2>{ static constexpr guid value{ 0x79F0A06E,0x7B02,0x4911,{ 0x91,0x8C,0xDE,0xE0,0xBB,0xD2,0x0B,0xA4 } }; };
template <> struct guid_storage<Windows::UI::Shell::ITaskbarManagerStatics>{ static constexpr guid value{ 0xDB32AB74,0xDE52,0x4FE6,{ 0xB7,0xB6,0x95,0xFF,0x9F,0x83,0x95,0xDF } }; };
template <> struct default_interface<Windows::UI::Shell::SecurityAppManager>{ using type = Windows::UI::Shell::ISecurityAppManager; };
template <> struct default_interface<Windows::UI::Shell::TaskbarManager>{ using type = Windows::UI::Shell::ITaskbarManager; };

template <> struct abi<Windows::UI::Shell::IAdaptiveCard>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL ToJson(void** result) noexcept = 0;
};};

template <> struct abi<Windows::UI::Shell::IAdaptiveCardBuilderStatics>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL CreateAdaptiveCardFromJson(void* value, void** result) noexcept = 0;
};};

template <> struct abi<Windows::UI::Shell::ISecurityAppManager>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL Register(Windows::UI::Shell::SecurityAppKind kind, void* displayName, void* detailsUri, bool registerPerUser, winrt::guid* result) noexcept = 0;
    virtual int32_t WINRT_CALL Unregister(Windows::UI::Shell::SecurityAppKind kind, winrt::guid guidRegistration) noexcept = 0;
    virtual int32_t WINRT_CALL UpdateState(Windows::UI::Shell::SecurityAppKind kind, winrt::guid guidRegistration, Windows::UI::Shell::SecurityAppState state, Windows::UI::Shell::SecurityAppSubstatus substatus, void* detailsUri) noexcept = 0;
};};

template <> struct abi<Windows::UI::Shell::ITaskbarManager>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL get_IsSupported(bool* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_IsPinningAllowed(bool* value) noexcept = 0;
    virtual int32_t WINRT_CALL IsCurrentAppPinnedAsync(void** operation) noexcept = 0;
    virtual int32_t WINRT_CALL IsAppListEntryPinnedAsync(void* appListEntry, void** operation) noexcept = 0;
    virtual int32_t WINRT_CALL RequestPinCurrentAppAsync(void** operation) noexcept = 0;
    virtual int32_t WINRT_CALL RequestPinAppListEntryAsync(void* appListEntry, void** operation) noexcept = 0;
};};

template <> struct abi<Windows::UI::Shell::ITaskbarManager2>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL IsSecondaryTilePinnedAsync(void* tileId, void** operation) noexcept = 0;
    virtual int32_t WINRT_CALL RequestPinSecondaryTileAsync(void* secondaryTile, void** operation) noexcept = 0;
    virtual int32_t WINRT_CALL TryUnpinSecondaryTileAsync(void* tileId, void** operation) noexcept = 0;
};};

template <> struct abi<Windows::UI::Shell::ITaskbarManagerStatics>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL GetDefault(void** result) noexcept = 0;
};};

template <typename D>
struct consume_Windows_UI_Shell_IAdaptiveCard
{
    hstring ToJson() const;
};
template <> struct consume<Windows::UI::Shell::IAdaptiveCard> { template <typename D> using type = consume_Windows_UI_Shell_IAdaptiveCard<D>; };

template <typename D>
struct consume_Windows_UI_Shell_IAdaptiveCardBuilderStatics
{
    Windows::UI::Shell::IAdaptiveCard CreateAdaptiveCardFromJson(param::hstring const& value) const;
};
template <> struct consume<Windows::UI::Shell::IAdaptiveCardBuilderStatics> { template <typename D> using type = consume_Windows_UI_Shell_IAdaptiveCardBuilderStatics<D>; };

template <typename D>
struct consume_Windows_UI_Shell_ISecurityAppManager
{
    winrt::guid Register(Windows::UI::Shell::SecurityAppKind const& kind, param::hstring const& displayName, Windows::Foundation::Uri const& detailsUri, bool registerPerUser) const;
    void Unregister(Windows::UI::Shell::SecurityAppKind const& kind, winrt::guid const& guidRegistration) const;
    void UpdateState(Windows::UI::Shell::SecurityAppKind const& kind, winrt::guid const& guidRegistration, Windows::UI::Shell::SecurityAppState const& state, Windows::UI::Shell::SecurityAppSubstatus const& substatus, Windows::Foundation::Uri const& detailsUri) const;
};
template <> struct consume<Windows::UI::Shell::ISecurityAppManager> { template <typename D> using type = consume_Windows_UI_Shell_ISecurityAppManager<D>; };

template <typename D>
struct consume_Windows_UI_Shell_ITaskbarManager
{
    bool IsSupported() const;
    bool IsPinningAllowed() const;
    Windows::Foundation::IAsyncOperation<bool> IsCurrentAppPinnedAsync() const;
    Windows::Foundation::IAsyncOperation<bool> IsAppListEntryPinnedAsync(Windows::ApplicationModel::Core::AppListEntry const& appListEntry) const;
    Windows::Foundation::IAsyncOperation<bool> RequestPinCurrentAppAsync() const;
    Windows::Foundation::IAsyncOperation<bool> RequestPinAppListEntryAsync(Windows::ApplicationModel::Core::AppListEntry const& appListEntry) const;
};
template <> struct consume<Windows::UI::Shell::ITaskbarManager> { template <typename D> using type = consume_Windows_UI_Shell_ITaskbarManager<D>; };

template <typename D>
struct consume_Windows_UI_Shell_ITaskbarManager2
{
    Windows::Foundation::IAsyncOperation<bool> IsSecondaryTilePinnedAsync(param::hstring const& tileId) const;
    Windows::Foundation::IAsyncOperation<bool> RequestPinSecondaryTileAsync(Windows::UI::StartScreen::SecondaryTile const& secondaryTile) const;
    Windows::Foundation::IAsyncOperation<bool> TryUnpinSecondaryTileAsync(param::hstring const& tileId) const;
};
template <> struct consume<Windows::UI::Shell::ITaskbarManager2> { template <typename D> using type = consume_Windows_UI_Shell_ITaskbarManager2<D>; };

template <typename D>
struct consume_Windows_UI_Shell_ITaskbarManagerStatics
{
    Windows::UI::Shell::TaskbarManager GetDefault() const;
};
template <> struct consume<Windows::UI::Shell::ITaskbarManagerStatics> { template <typename D> using type = consume_Windows_UI_Shell_ITaskbarManagerStatics<D>; };

}
