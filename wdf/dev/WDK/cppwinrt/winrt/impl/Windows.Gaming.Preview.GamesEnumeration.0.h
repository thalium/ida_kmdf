// C++/WinRT v1.0.190111.3

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#pragma once

WINRT_EXPORT namespace winrt::Windows::ApplicationModel {

struct AppDisplayInfo;

}

WINRT_EXPORT namespace winrt::Windows::Storage {

struct IStorageFile;

}

WINRT_EXPORT namespace winrt::Windows::Gaming::Preview::GamesEnumeration {

enum class GameListCategory : int32_t
{
    Candidate = 0,
    ConfirmedBySystem = 1,
    ConfirmedByUser = 2,
};

enum class GameListEntryLaunchableState : int32_t
{
    NotLaunchable = 0,
    ByLastRunningFullPath = 1,
    ByUserProvidedPath = 2,
    ByTile = 3,
};

struct IGameListEntry;
struct IGameListEntry2;
struct IGameListStatics;
struct IGameListStatics2;
struct IGameModeConfiguration;
struct IGameModeUserConfiguration;
struct IGameModeUserConfigurationStatics;
struct GameList;
struct GameListEntry;
struct GameModeConfiguration;
struct GameModeUserConfiguration;
struct GameListChangedEventHandler;
struct GameListRemovedEventHandler;

}

namespace winrt::impl {

template <> struct category<Windows::Gaming::Preview::GamesEnumeration::IGameListEntry>{ using type = interface_category; };
template <> struct category<Windows::Gaming::Preview::GamesEnumeration::IGameListEntry2>{ using type = interface_category; };
template <> struct category<Windows::Gaming::Preview::GamesEnumeration::IGameListStatics>{ using type = interface_category; };
template <> struct category<Windows::Gaming::Preview::GamesEnumeration::IGameListStatics2>{ using type = interface_category; };
template <> struct category<Windows::Gaming::Preview::GamesEnumeration::IGameModeConfiguration>{ using type = interface_category; };
template <> struct category<Windows::Gaming::Preview::GamesEnumeration::IGameModeUserConfiguration>{ using type = interface_category; };
template <> struct category<Windows::Gaming::Preview::GamesEnumeration::IGameModeUserConfigurationStatics>{ using type = interface_category; };
template <> struct category<Windows::Gaming::Preview::GamesEnumeration::GameList>{ using type = class_category; };
template <> struct category<Windows::Gaming::Preview::GamesEnumeration::GameListEntry>{ using type = class_category; };
template <> struct category<Windows::Gaming::Preview::GamesEnumeration::GameModeConfiguration>{ using type = class_category; };
template <> struct category<Windows::Gaming::Preview::GamesEnumeration::GameModeUserConfiguration>{ using type = class_category; };
template <> struct category<Windows::Gaming::Preview::GamesEnumeration::GameListCategory>{ using type = enum_category; };
template <> struct category<Windows::Gaming::Preview::GamesEnumeration::GameListEntryLaunchableState>{ using type = enum_category; };
template <> struct category<Windows::Gaming::Preview::GamesEnumeration::GameListChangedEventHandler>{ using type = delegate_category; };
template <> struct category<Windows::Gaming::Preview::GamesEnumeration::GameListRemovedEventHandler>{ using type = delegate_category; };
template <> struct name<Windows::Gaming::Preview::GamesEnumeration::IGameListEntry>{ static constexpr auto & value{ L"Windows.Gaming.Preview.GamesEnumeration.IGameListEntry" }; };
template <> struct name<Windows::Gaming::Preview::GamesEnumeration::IGameListEntry2>{ static constexpr auto & value{ L"Windows.Gaming.Preview.GamesEnumeration.IGameListEntry2" }; };
template <> struct name<Windows::Gaming::Preview::GamesEnumeration::IGameListStatics>{ static constexpr auto & value{ L"Windows.Gaming.Preview.GamesEnumeration.IGameListStatics" }; };
template <> struct name<Windows::Gaming::Preview::GamesEnumeration::IGameListStatics2>{ static constexpr auto & value{ L"Windows.Gaming.Preview.GamesEnumeration.IGameListStatics2" }; };
template <> struct name<Windows::Gaming::Preview::GamesEnumeration::IGameModeConfiguration>{ static constexpr auto & value{ L"Windows.Gaming.Preview.GamesEnumeration.IGameModeConfiguration" }; };
template <> struct name<Windows::Gaming::Preview::GamesEnumeration::IGameModeUserConfiguration>{ static constexpr auto & value{ L"Windows.Gaming.Preview.GamesEnumeration.IGameModeUserConfiguration" }; };
template <> struct name<Windows::Gaming::Preview::GamesEnumeration::IGameModeUserConfigurationStatics>{ static constexpr auto & value{ L"Windows.Gaming.Preview.GamesEnumeration.IGameModeUserConfigurationStatics" }; };
template <> struct name<Windows::Gaming::Preview::GamesEnumeration::GameList>{ static constexpr auto & value{ L"Windows.Gaming.Preview.GamesEnumeration.GameList" }; };
template <> struct name<Windows::Gaming::Preview::GamesEnumeration::GameListEntry>{ static constexpr auto & value{ L"Windows.Gaming.Preview.GamesEnumeration.GameListEntry" }; };
template <> struct name<Windows::Gaming::Preview::GamesEnumeration::GameModeConfiguration>{ static constexpr auto & value{ L"Windows.Gaming.Preview.GamesEnumeration.GameModeConfiguration" }; };
template <> struct name<Windows::Gaming::Preview::GamesEnumeration::GameModeUserConfiguration>{ static constexpr auto & value{ L"Windows.Gaming.Preview.GamesEnumeration.GameModeUserConfiguration" }; };
template <> struct name<Windows::Gaming::Preview::GamesEnumeration::GameListCategory>{ static constexpr auto & value{ L"Windows.Gaming.Preview.GamesEnumeration.GameListCategory" }; };
template <> struct name<Windows::Gaming::Preview::GamesEnumeration::GameListEntryLaunchableState>{ static constexpr auto & value{ L"Windows.Gaming.Preview.GamesEnumeration.GameListEntryLaunchableState" }; };
template <> struct name<Windows::Gaming::Preview::GamesEnumeration::GameListChangedEventHandler>{ static constexpr auto & value{ L"Windows.Gaming.Preview.GamesEnumeration.GameListChangedEventHandler" }; };
template <> struct name<Windows::Gaming::Preview::GamesEnumeration::GameListRemovedEventHandler>{ static constexpr auto & value{ L"Windows.Gaming.Preview.GamesEnumeration.GameListRemovedEventHandler" }; };
template <> struct guid_storage<Windows::Gaming::Preview::GamesEnumeration::IGameListEntry>{ static constexpr guid value{ 0x735924D3,0x811F,0x4494,{ 0xB6,0x9C,0xC6,0x41,0xA0,0xC6,0x15,0x43 } }; };
template <> struct guid_storage<Windows::Gaming::Preview::GamesEnumeration::IGameListEntry2>{ static constexpr guid value{ 0xD84A8F8B,0x8749,0x4A25,{ 0x90,0xD3,0xF6,0xC5,0xA4,0x27,0x88,0x6D } }; };
template <> struct guid_storage<Windows::Gaming::Preview::GamesEnumeration::IGameListStatics>{ static constexpr guid value{ 0x2DDD0F6F,0x9C66,0x4B05,{ 0x94,0x5C,0xD6,0xED,0x78,0x49,0x1B,0x8C } }; };
template <> struct guid_storage<Windows::Gaming::Preview::GamesEnumeration::IGameListStatics2>{ static constexpr guid value{ 0x395F2098,0xEA1A,0x45AA,{ 0x92,0x68,0xA8,0x39,0x05,0x68,0x6F,0x27 } }; };
template <> struct guid_storage<Windows::Gaming::Preview::GamesEnumeration::IGameModeConfiguration>{ static constexpr guid value{ 0x78E591AF,0xB142,0x4EF0,{ 0x88,0x30,0x55,0xBC,0x2B,0xE4,0xF5,0xEA } }; };
template <> struct guid_storage<Windows::Gaming::Preview::GamesEnumeration::IGameModeUserConfiguration>{ static constexpr guid value{ 0x72D34AF4,0x756B,0x470F,{ 0xA0,0xC2,0xBA,0x62,0xA9,0x07,0x95,0xDB } }; };
template <> struct guid_storage<Windows::Gaming::Preview::GamesEnumeration::IGameModeUserConfigurationStatics>{ static constexpr guid value{ 0x6E50D97C,0x66EA,0x478E,{ 0xA4,0xA1,0xF5,0x7C,0x0E,0x8D,0x00,0xE7 } }; };
template <> struct guid_storage<Windows::Gaming::Preview::GamesEnumeration::GameListChangedEventHandler>{ static constexpr guid value{ 0x25F6A421,0xD8F5,0x4D91,{ 0xB4,0x0E,0x53,0xD5,0xE8,0x6F,0xDE,0x64 } }; };
template <> struct guid_storage<Windows::Gaming::Preview::GamesEnumeration::GameListRemovedEventHandler>{ static constexpr guid value{ 0x10C5648F,0x6C8F,0x4712,{ 0x9B,0x38,0x47,0x4B,0xC2,0x2E,0x76,0xD8 } }; };
template <> struct default_interface<Windows::Gaming::Preview::GamesEnumeration::GameListEntry>{ using type = Windows::Gaming::Preview::GamesEnumeration::IGameListEntry; };
template <> struct default_interface<Windows::Gaming::Preview::GamesEnumeration::GameModeConfiguration>{ using type = Windows::Gaming::Preview::GamesEnumeration::IGameModeConfiguration; };
template <> struct default_interface<Windows::Gaming::Preview::GamesEnumeration::GameModeUserConfiguration>{ using type = Windows::Gaming::Preview::GamesEnumeration::IGameModeUserConfiguration; };

template <> struct abi<Windows::Gaming::Preview::GamesEnumeration::IGameListEntry>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL get_DisplayInfo(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL LaunchAsync(void** operation) noexcept = 0;
    virtual int32_t WINRT_CALL get_Category(Windows::Gaming::Preview::GamesEnumeration::GameListCategory* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_Properties(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL SetCategoryAsync(Windows::Gaming::Preview::GamesEnumeration::GameListCategory value, void** action) noexcept = 0;
};};

template <> struct abi<Windows::Gaming::Preview::GamesEnumeration::IGameListEntry2>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL get_LaunchableState(Windows::Gaming::Preview::GamesEnumeration::GameListEntryLaunchableState* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_LauncherExecutable(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_LaunchParameters(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL SetLauncherExecutableFileAsync(void* executableFile, void** operation) noexcept = 0;
    virtual int32_t WINRT_CALL SetLauncherExecutableFileWithParamsAsync(void* executableFile, void* launchParams, void** operation) noexcept = 0;
    virtual int32_t WINRT_CALL get_TitleId(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL SetTitleIdAsync(void* id, void** operation) noexcept = 0;
    virtual int32_t WINRT_CALL get_GameModeConfiguration(void** value) noexcept = 0;
};};

template <> struct abi<Windows::Gaming::Preview::GamesEnumeration::IGameListStatics>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL FindAllAsync(void** operation) noexcept = 0;
    virtual int32_t WINRT_CALL FindAllAsyncPackageFamilyName(void* packageFamilyName, void** operation) noexcept = 0;
    virtual int32_t WINRT_CALL add_GameAdded(void* handler, winrt::event_token* token) noexcept = 0;
    virtual int32_t WINRT_CALL remove_GameAdded(winrt::event_token token) noexcept = 0;
    virtual int32_t WINRT_CALL add_GameRemoved(void* handler, winrt::event_token* token) noexcept = 0;
    virtual int32_t WINRT_CALL remove_GameRemoved(winrt::event_token token) noexcept = 0;
    virtual int32_t WINRT_CALL add_GameUpdated(void* handler, winrt::event_token* token) noexcept = 0;
    virtual int32_t WINRT_CALL remove_GameUpdated(winrt::event_token token) noexcept = 0;
};};

template <> struct abi<Windows::Gaming::Preview::GamesEnumeration::IGameListStatics2>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL MergeEntriesAsync(void* left, void* right, void** operation) noexcept = 0;
    virtual int32_t WINRT_CALL UnmergeEntryAsync(void* mergedEntry, void** operation) noexcept = 0;
};};

template <> struct abi<Windows::Gaming::Preview::GamesEnumeration::IGameModeConfiguration>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL get_IsEnabled(bool* value) noexcept = 0;
    virtual int32_t WINRT_CALL put_IsEnabled(bool value) noexcept = 0;
    virtual int32_t WINRT_CALL get_RelatedProcessNames(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_PercentGpuTimeAllocatedToGame(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL put_PercentGpuTimeAllocatedToGame(void* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_PercentGpuMemoryAllocatedToGame(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL put_PercentGpuMemoryAllocatedToGame(void* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_PercentGpuMemoryAllocatedToSystemCompositor(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL put_PercentGpuMemoryAllocatedToSystemCompositor(void* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_MaxCpuCount(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL put_MaxCpuCount(void* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_CpuExclusivityMaskLow(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL put_CpuExclusivityMaskLow(void* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_CpuExclusivityMaskHigh(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL put_CpuExclusivityMaskHigh(void* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_AffinitizeToExclusiveCpus(bool* value) noexcept = 0;
    virtual int32_t WINRT_CALL put_AffinitizeToExclusiveCpus(bool value) noexcept = 0;
    virtual int32_t WINRT_CALL SaveAsync(void** operation) noexcept = 0;
};};

template <> struct abi<Windows::Gaming::Preview::GamesEnumeration::IGameModeUserConfiguration>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL get_GamingRelatedProcessNames(void** processNames) noexcept = 0;
    virtual int32_t WINRT_CALL SaveAsync(void** operation) noexcept = 0;
};};

template <> struct abi<Windows::Gaming::Preview::GamesEnumeration::IGameModeUserConfigurationStatics>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL GetDefault(void** userConfiguration) noexcept = 0;
};};

template <> struct abi<Windows::Gaming::Preview::GamesEnumeration::GameListChangedEventHandler>{ struct type : IUnknown
{
    virtual int32_t WINRT_CALL Invoke(void* game) noexcept = 0;
};};

template <> struct abi<Windows::Gaming::Preview::GamesEnumeration::GameListRemovedEventHandler>{ struct type : IUnknown
{
    virtual int32_t WINRT_CALL Invoke(void* identifier) noexcept = 0;
};};

template <typename D>
struct consume_Windows_Gaming_Preview_GamesEnumeration_IGameListEntry
{
    Windows::ApplicationModel::AppDisplayInfo DisplayInfo() const;
    Windows::Foundation::IAsyncOperation<bool> LaunchAsync() const;
    Windows::Gaming::Preview::GamesEnumeration::GameListCategory Category() const;
    Windows::Foundation::Collections::IMapView<hstring, Windows::Foundation::IInspectable> Properties() const;
    Windows::Foundation::IAsyncAction SetCategoryAsync(Windows::Gaming::Preview::GamesEnumeration::GameListCategory const& value) const;
};
template <> struct consume<Windows::Gaming::Preview::GamesEnumeration::IGameListEntry> { template <typename D> using type = consume_Windows_Gaming_Preview_GamesEnumeration_IGameListEntry<D>; };

template <typename D>
struct consume_Windows_Gaming_Preview_GamesEnumeration_IGameListEntry2
{
    Windows::Gaming::Preview::GamesEnumeration::GameListEntryLaunchableState LaunchableState() const;
    Windows::Storage::IStorageFile LauncherExecutable() const;
    hstring LaunchParameters() const;
    Windows::Foundation::IAsyncAction SetLauncherExecutableFileAsync(Windows::Storage::IStorageFile const& executableFile) const;
    Windows::Foundation::IAsyncAction SetLauncherExecutableFileAsync(Windows::Storage::IStorageFile const& executableFile, param::hstring const& launchParams) const;
    hstring TitleId() const;
    Windows::Foundation::IAsyncAction SetTitleIdAsync(param::hstring const& id) const;
    Windows::Gaming::Preview::GamesEnumeration::GameModeConfiguration GameModeConfiguration() const;
};
template <> struct consume<Windows::Gaming::Preview::GamesEnumeration::IGameListEntry2> { template <typename D> using type = consume_Windows_Gaming_Preview_GamesEnumeration_IGameListEntry2<D>; };

template <typename D>
struct consume_Windows_Gaming_Preview_GamesEnumeration_IGameListStatics
{
    Windows::Foundation::IAsyncOperation<Windows::Foundation::Collections::IVectorView<Windows::Gaming::Preview::GamesEnumeration::GameListEntry>> FindAllAsync() const;
    Windows::Foundation::IAsyncOperation<Windows::Foundation::Collections::IVectorView<Windows::Gaming::Preview::GamesEnumeration::GameListEntry>> FindAllAsync(param::hstring const& packageFamilyName) const;
    winrt::event_token GameAdded(Windows::Gaming::Preview::GamesEnumeration::GameListChangedEventHandler const& handler) const;
    using GameAdded_revoker = impl::event_revoker<Windows::Gaming::Preview::GamesEnumeration::IGameListStatics, &impl::abi_t<Windows::Gaming::Preview::GamesEnumeration::IGameListStatics>::remove_GameAdded>;
    GameAdded_revoker GameAdded(auto_revoke_t, Windows::Gaming::Preview::GamesEnumeration::GameListChangedEventHandler const& handler) const;
    void GameAdded(winrt::event_token const& token) const noexcept;
    winrt::event_token GameRemoved(Windows::Gaming::Preview::GamesEnumeration::GameListRemovedEventHandler const& handler) const;
    using GameRemoved_revoker = impl::event_revoker<Windows::Gaming::Preview::GamesEnumeration::IGameListStatics, &impl::abi_t<Windows::Gaming::Preview::GamesEnumeration::IGameListStatics>::remove_GameRemoved>;
    GameRemoved_revoker GameRemoved(auto_revoke_t, Windows::Gaming::Preview::GamesEnumeration::GameListRemovedEventHandler const& handler) const;
    void GameRemoved(winrt::event_token const& token) const noexcept;
    winrt::event_token GameUpdated(Windows::Gaming::Preview::GamesEnumeration::GameListChangedEventHandler const& handler) const;
    using GameUpdated_revoker = impl::event_revoker<Windows::Gaming::Preview::GamesEnumeration::IGameListStatics, &impl::abi_t<Windows::Gaming::Preview::GamesEnumeration::IGameListStatics>::remove_GameUpdated>;
    GameUpdated_revoker GameUpdated(auto_revoke_t, Windows::Gaming::Preview::GamesEnumeration::GameListChangedEventHandler const& handler) const;
    void GameUpdated(winrt::event_token const& token) const noexcept;
};
template <> struct consume<Windows::Gaming::Preview::GamesEnumeration::IGameListStatics> { template <typename D> using type = consume_Windows_Gaming_Preview_GamesEnumeration_IGameListStatics<D>; };

template <typename D>
struct consume_Windows_Gaming_Preview_GamesEnumeration_IGameListStatics2
{
    Windows::Foundation::IAsyncOperation<Windows::Gaming::Preview::GamesEnumeration::GameListEntry> MergeEntriesAsync(Windows::Gaming::Preview::GamesEnumeration::GameListEntry const& left, Windows::Gaming::Preview::GamesEnumeration::GameListEntry const& right) const;
    Windows::Foundation::IAsyncOperation<Windows::Foundation::Collections::IVectorView<Windows::Gaming::Preview::GamesEnumeration::GameListEntry>> UnmergeEntryAsync(Windows::Gaming::Preview::GamesEnumeration::GameListEntry const& mergedEntry) const;
};
template <> struct consume<Windows::Gaming::Preview::GamesEnumeration::IGameListStatics2> { template <typename D> using type = consume_Windows_Gaming_Preview_GamesEnumeration_IGameListStatics2<D>; };

template <typename D>
struct consume_Windows_Gaming_Preview_GamesEnumeration_IGameModeConfiguration
{
    bool IsEnabled() const;
    void IsEnabled(bool value) const;
    Windows::Foundation::Collections::IVector<hstring> RelatedProcessNames() const;
    Windows::Foundation::IReference<int32_t> PercentGpuTimeAllocatedToGame() const;
    void PercentGpuTimeAllocatedToGame(optional<int32_t> const& value) const;
    Windows::Foundation::IReference<int32_t> PercentGpuMemoryAllocatedToGame() const;
    void PercentGpuMemoryAllocatedToGame(optional<int32_t> const& value) const;
    Windows::Foundation::IReference<int32_t> PercentGpuMemoryAllocatedToSystemCompositor() const;
    void PercentGpuMemoryAllocatedToSystemCompositor(optional<int32_t> const& value) const;
    Windows::Foundation::IReference<int32_t> MaxCpuCount() const;
    void MaxCpuCount(optional<int32_t> const& value) const;
    Windows::Foundation::IReference<int32_t> CpuExclusivityMaskLow() const;
    void CpuExclusivityMaskLow(optional<int32_t> const& value) const;
    Windows::Foundation::IReference<int32_t> CpuExclusivityMaskHigh() const;
    void CpuExclusivityMaskHigh(optional<int32_t> const& value) const;
    bool AffinitizeToExclusiveCpus() const;
    void AffinitizeToExclusiveCpus(bool value) const;
    Windows::Foundation::IAsyncAction SaveAsync() const;
};
template <> struct consume<Windows::Gaming::Preview::GamesEnumeration::IGameModeConfiguration> { template <typename D> using type = consume_Windows_Gaming_Preview_GamesEnumeration_IGameModeConfiguration<D>; };

template <typename D>
struct consume_Windows_Gaming_Preview_GamesEnumeration_IGameModeUserConfiguration
{
    Windows::Foundation::Collections::IVector<hstring> GamingRelatedProcessNames() const;
    Windows::Foundation::IAsyncAction SaveAsync() const;
};
template <> struct consume<Windows::Gaming::Preview::GamesEnumeration::IGameModeUserConfiguration> { template <typename D> using type = consume_Windows_Gaming_Preview_GamesEnumeration_IGameModeUserConfiguration<D>; };

template <typename D>
struct consume_Windows_Gaming_Preview_GamesEnumeration_IGameModeUserConfigurationStatics
{
    Windows::Gaming::Preview::GamesEnumeration::GameModeUserConfiguration GetDefault() const;
};
template <> struct consume<Windows::Gaming::Preview::GamesEnumeration::IGameModeUserConfigurationStatics> { template <typename D> using type = consume_Windows_Gaming_Preview_GamesEnumeration_IGameModeUserConfigurationStatics<D>; };

}
