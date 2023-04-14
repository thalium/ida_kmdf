// C++/WinRT v1.0.190111.3

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#pragma once

#include "winrt/base.h"

#include "winrt/Windows.Foundation.h"
#include "winrt/Windows.Foundation.Collections.h"
#include "winrt/impl/Windows.ApplicationModel.2.h"
#include "winrt/impl/Windows.Storage.2.h"
#include "winrt/impl/Windows.Gaming.Preview.GamesEnumeration.2.h"

namespace winrt::impl {

template <typename D> Windows::ApplicationModel::AppDisplayInfo consume_Windows_Gaming_Preview_GamesEnumeration_IGameListEntry<D>::DisplayInfo() const
{
    Windows::ApplicationModel::AppDisplayInfo value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Gaming::Preview::GamesEnumeration::IGameListEntry)->get_DisplayInfo(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::IAsyncOperation<bool> consume_Windows_Gaming_Preview_GamesEnumeration_IGameListEntry<D>::LaunchAsync() const
{
    Windows::Foundation::IAsyncOperation<bool> operation{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Gaming::Preview::GamesEnumeration::IGameListEntry)->LaunchAsync(put_abi(operation)));
    return operation;
}

template <typename D> Windows::Gaming::Preview::GamesEnumeration::GameListCategory consume_Windows_Gaming_Preview_GamesEnumeration_IGameListEntry<D>::Category() const
{
    Windows::Gaming::Preview::GamesEnumeration::GameListCategory value{};
    check_hresult(WINRT_SHIM(Windows::Gaming::Preview::GamesEnumeration::IGameListEntry)->get_Category(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::Collections::IMapView<hstring, Windows::Foundation::IInspectable> consume_Windows_Gaming_Preview_GamesEnumeration_IGameListEntry<D>::Properties() const
{
    Windows::Foundation::Collections::IMapView<hstring, Windows::Foundation::IInspectable> value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Gaming::Preview::GamesEnumeration::IGameListEntry)->get_Properties(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::IAsyncAction consume_Windows_Gaming_Preview_GamesEnumeration_IGameListEntry<D>::SetCategoryAsync(Windows::Gaming::Preview::GamesEnumeration::GameListCategory const& value) const
{
    Windows::Foundation::IAsyncAction action{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Gaming::Preview::GamesEnumeration::IGameListEntry)->SetCategoryAsync(get_abi(value), put_abi(action)));
    return action;
}

template <typename D> Windows::Gaming::Preview::GamesEnumeration::GameListEntryLaunchableState consume_Windows_Gaming_Preview_GamesEnumeration_IGameListEntry2<D>::LaunchableState() const
{
    Windows::Gaming::Preview::GamesEnumeration::GameListEntryLaunchableState value{};
    check_hresult(WINRT_SHIM(Windows::Gaming::Preview::GamesEnumeration::IGameListEntry2)->get_LaunchableState(put_abi(value)));
    return value;
}

template <typename D> Windows::Storage::IStorageFile consume_Windows_Gaming_Preview_GamesEnumeration_IGameListEntry2<D>::LauncherExecutable() const
{
    Windows::Storage::IStorageFile value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Gaming::Preview::GamesEnumeration::IGameListEntry2)->get_LauncherExecutable(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_Gaming_Preview_GamesEnumeration_IGameListEntry2<D>::LaunchParameters() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Gaming::Preview::GamesEnumeration::IGameListEntry2)->get_LaunchParameters(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::IAsyncAction consume_Windows_Gaming_Preview_GamesEnumeration_IGameListEntry2<D>::SetLauncherExecutableFileAsync(Windows::Storage::IStorageFile const& executableFile) const
{
    Windows::Foundation::IAsyncAction operation{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Gaming::Preview::GamesEnumeration::IGameListEntry2)->SetLauncherExecutableFileAsync(get_abi(executableFile), put_abi(operation)));
    return operation;
}

template <typename D> Windows::Foundation::IAsyncAction consume_Windows_Gaming_Preview_GamesEnumeration_IGameListEntry2<D>::SetLauncherExecutableFileAsync(Windows::Storage::IStorageFile const& executableFile, param::hstring const& launchParams) const
{
    Windows::Foundation::IAsyncAction operation{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Gaming::Preview::GamesEnumeration::IGameListEntry2)->SetLauncherExecutableFileWithParamsAsync(get_abi(executableFile), get_abi(launchParams), put_abi(operation)));
    return operation;
}

template <typename D> hstring consume_Windows_Gaming_Preview_GamesEnumeration_IGameListEntry2<D>::TitleId() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Gaming::Preview::GamesEnumeration::IGameListEntry2)->get_TitleId(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::IAsyncAction consume_Windows_Gaming_Preview_GamesEnumeration_IGameListEntry2<D>::SetTitleIdAsync(param::hstring const& id) const
{
    Windows::Foundation::IAsyncAction operation{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Gaming::Preview::GamesEnumeration::IGameListEntry2)->SetTitleIdAsync(get_abi(id), put_abi(operation)));
    return operation;
}

template <typename D> Windows::Gaming::Preview::GamesEnumeration::GameModeConfiguration consume_Windows_Gaming_Preview_GamesEnumeration_IGameListEntry2<D>::GameModeConfiguration() const
{
    Windows::Gaming::Preview::GamesEnumeration::GameModeConfiguration value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Gaming::Preview::GamesEnumeration::IGameListEntry2)->get_GameModeConfiguration(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::IAsyncOperation<Windows::Foundation::Collections::IVectorView<Windows::Gaming::Preview::GamesEnumeration::GameListEntry>> consume_Windows_Gaming_Preview_GamesEnumeration_IGameListStatics<D>::FindAllAsync() const
{
    Windows::Foundation::IAsyncOperation<Windows::Foundation::Collections::IVectorView<Windows::Gaming::Preview::GamesEnumeration::GameListEntry>> operation{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Gaming::Preview::GamesEnumeration::IGameListStatics)->FindAllAsync(put_abi(operation)));
    return operation;
}

template <typename D> Windows::Foundation::IAsyncOperation<Windows::Foundation::Collections::IVectorView<Windows::Gaming::Preview::GamesEnumeration::GameListEntry>> consume_Windows_Gaming_Preview_GamesEnumeration_IGameListStatics<D>::FindAllAsync(param::hstring const& packageFamilyName) const
{
    Windows::Foundation::IAsyncOperation<Windows::Foundation::Collections::IVectorView<Windows::Gaming::Preview::GamesEnumeration::GameListEntry>> operation{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Gaming::Preview::GamesEnumeration::IGameListStatics)->FindAllAsyncPackageFamilyName(get_abi(packageFamilyName), put_abi(operation)));
    return operation;
}

template <typename D> winrt::event_token consume_Windows_Gaming_Preview_GamesEnumeration_IGameListStatics<D>::GameAdded(Windows::Gaming::Preview::GamesEnumeration::GameListChangedEventHandler const& handler) const
{
    winrt::event_token token{};
    check_hresult(WINRT_SHIM(Windows::Gaming::Preview::GamesEnumeration::IGameListStatics)->add_GameAdded(get_abi(handler), put_abi(token)));
    return token;
}

template <typename D> typename consume_Windows_Gaming_Preview_GamesEnumeration_IGameListStatics<D>::GameAdded_revoker consume_Windows_Gaming_Preview_GamesEnumeration_IGameListStatics<D>::GameAdded(auto_revoke_t, Windows::Gaming::Preview::GamesEnumeration::GameListChangedEventHandler const& handler) const
{
    return impl::make_event_revoker<D, GameAdded_revoker>(this, GameAdded(handler));
}

template <typename D> void consume_Windows_Gaming_Preview_GamesEnumeration_IGameListStatics<D>::GameAdded(winrt::event_token const& token) const noexcept
{
    WINRT_VERIFY_(0, WINRT_SHIM(Windows::Gaming::Preview::GamesEnumeration::IGameListStatics)->remove_GameAdded(get_abi(token)));
}

template <typename D> winrt::event_token consume_Windows_Gaming_Preview_GamesEnumeration_IGameListStatics<D>::GameRemoved(Windows::Gaming::Preview::GamesEnumeration::GameListRemovedEventHandler const& handler) const
{
    winrt::event_token token{};
    check_hresult(WINRT_SHIM(Windows::Gaming::Preview::GamesEnumeration::IGameListStatics)->add_GameRemoved(get_abi(handler), put_abi(token)));
    return token;
}

template <typename D> typename consume_Windows_Gaming_Preview_GamesEnumeration_IGameListStatics<D>::GameRemoved_revoker consume_Windows_Gaming_Preview_GamesEnumeration_IGameListStatics<D>::GameRemoved(auto_revoke_t, Windows::Gaming::Preview::GamesEnumeration::GameListRemovedEventHandler const& handler) const
{
    return impl::make_event_revoker<D, GameRemoved_revoker>(this, GameRemoved(handler));
}

template <typename D> void consume_Windows_Gaming_Preview_GamesEnumeration_IGameListStatics<D>::GameRemoved(winrt::event_token const& token) const noexcept
{
    WINRT_VERIFY_(0, WINRT_SHIM(Windows::Gaming::Preview::GamesEnumeration::IGameListStatics)->remove_GameRemoved(get_abi(token)));
}

template <typename D> winrt::event_token consume_Windows_Gaming_Preview_GamesEnumeration_IGameListStatics<D>::GameUpdated(Windows::Gaming::Preview::GamesEnumeration::GameListChangedEventHandler const& handler) const
{
    winrt::event_token token{};
    check_hresult(WINRT_SHIM(Windows::Gaming::Preview::GamesEnumeration::IGameListStatics)->add_GameUpdated(get_abi(handler), put_abi(token)));
    return token;
}

template <typename D> typename consume_Windows_Gaming_Preview_GamesEnumeration_IGameListStatics<D>::GameUpdated_revoker consume_Windows_Gaming_Preview_GamesEnumeration_IGameListStatics<D>::GameUpdated(auto_revoke_t, Windows::Gaming::Preview::GamesEnumeration::GameListChangedEventHandler const& handler) const
{
    return impl::make_event_revoker<D, GameUpdated_revoker>(this, GameUpdated(handler));
}

template <typename D> void consume_Windows_Gaming_Preview_GamesEnumeration_IGameListStatics<D>::GameUpdated(winrt::event_token const& token) const noexcept
{
    WINRT_VERIFY_(0, WINRT_SHIM(Windows::Gaming::Preview::GamesEnumeration::IGameListStatics)->remove_GameUpdated(get_abi(token)));
}

template <typename D> Windows::Foundation::IAsyncOperation<Windows::Gaming::Preview::GamesEnumeration::GameListEntry> consume_Windows_Gaming_Preview_GamesEnumeration_IGameListStatics2<D>::MergeEntriesAsync(Windows::Gaming::Preview::GamesEnumeration::GameListEntry const& left, Windows::Gaming::Preview::GamesEnumeration::GameListEntry const& right) const
{
    Windows::Foundation::IAsyncOperation<Windows::Gaming::Preview::GamesEnumeration::GameListEntry> operation{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Gaming::Preview::GamesEnumeration::IGameListStatics2)->MergeEntriesAsync(get_abi(left), get_abi(right), put_abi(operation)));
    return operation;
}

template <typename D> Windows::Foundation::IAsyncOperation<Windows::Foundation::Collections::IVectorView<Windows::Gaming::Preview::GamesEnumeration::GameListEntry>> consume_Windows_Gaming_Preview_GamesEnumeration_IGameListStatics2<D>::UnmergeEntryAsync(Windows::Gaming::Preview::GamesEnumeration::GameListEntry const& mergedEntry) const
{
    Windows::Foundation::IAsyncOperation<Windows::Foundation::Collections::IVectorView<Windows::Gaming::Preview::GamesEnumeration::GameListEntry>> operation{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Gaming::Preview::GamesEnumeration::IGameListStatics2)->UnmergeEntryAsync(get_abi(mergedEntry), put_abi(operation)));
    return operation;
}

template <typename D> bool consume_Windows_Gaming_Preview_GamesEnumeration_IGameModeConfiguration<D>::IsEnabled() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::Gaming::Preview::GamesEnumeration::IGameModeConfiguration)->get_IsEnabled(&value));
    return value;
}

template <typename D> void consume_Windows_Gaming_Preview_GamesEnumeration_IGameModeConfiguration<D>::IsEnabled(bool value) const
{
    check_hresult(WINRT_SHIM(Windows::Gaming::Preview::GamesEnumeration::IGameModeConfiguration)->put_IsEnabled(value));
}

template <typename D> Windows::Foundation::Collections::IVector<hstring> consume_Windows_Gaming_Preview_GamesEnumeration_IGameModeConfiguration<D>::RelatedProcessNames() const
{
    Windows::Foundation::Collections::IVector<hstring> value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Gaming::Preview::GamesEnumeration::IGameModeConfiguration)->get_RelatedProcessNames(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::IReference<int32_t> consume_Windows_Gaming_Preview_GamesEnumeration_IGameModeConfiguration<D>::PercentGpuTimeAllocatedToGame() const
{
    Windows::Foundation::IReference<int32_t> value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Gaming::Preview::GamesEnumeration::IGameModeConfiguration)->get_PercentGpuTimeAllocatedToGame(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_Gaming_Preview_GamesEnumeration_IGameModeConfiguration<D>::PercentGpuTimeAllocatedToGame(optional<int32_t> const& value) const
{
    check_hresult(WINRT_SHIM(Windows::Gaming::Preview::GamesEnumeration::IGameModeConfiguration)->put_PercentGpuTimeAllocatedToGame(get_abi(value)));
}

template <typename D> Windows::Foundation::IReference<int32_t> consume_Windows_Gaming_Preview_GamesEnumeration_IGameModeConfiguration<D>::PercentGpuMemoryAllocatedToGame() const
{
    Windows::Foundation::IReference<int32_t> value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Gaming::Preview::GamesEnumeration::IGameModeConfiguration)->get_PercentGpuMemoryAllocatedToGame(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_Gaming_Preview_GamesEnumeration_IGameModeConfiguration<D>::PercentGpuMemoryAllocatedToGame(optional<int32_t> const& value) const
{
    check_hresult(WINRT_SHIM(Windows::Gaming::Preview::GamesEnumeration::IGameModeConfiguration)->put_PercentGpuMemoryAllocatedToGame(get_abi(value)));
}

template <typename D> Windows::Foundation::IReference<int32_t> consume_Windows_Gaming_Preview_GamesEnumeration_IGameModeConfiguration<D>::PercentGpuMemoryAllocatedToSystemCompositor() const
{
    Windows::Foundation::IReference<int32_t> value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Gaming::Preview::GamesEnumeration::IGameModeConfiguration)->get_PercentGpuMemoryAllocatedToSystemCompositor(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_Gaming_Preview_GamesEnumeration_IGameModeConfiguration<D>::PercentGpuMemoryAllocatedToSystemCompositor(optional<int32_t> const& value) const
{
    check_hresult(WINRT_SHIM(Windows::Gaming::Preview::GamesEnumeration::IGameModeConfiguration)->put_PercentGpuMemoryAllocatedToSystemCompositor(get_abi(value)));
}

template <typename D> Windows::Foundation::IReference<int32_t> consume_Windows_Gaming_Preview_GamesEnumeration_IGameModeConfiguration<D>::MaxCpuCount() const
{
    Windows::Foundation::IReference<int32_t> value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Gaming::Preview::GamesEnumeration::IGameModeConfiguration)->get_MaxCpuCount(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_Gaming_Preview_GamesEnumeration_IGameModeConfiguration<D>::MaxCpuCount(optional<int32_t> const& value) const
{
    check_hresult(WINRT_SHIM(Windows::Gaming::Preview::GamesEnumeration::IGameModeConfiguration)->put_MaxCpuCount(get_abi(value)));
}

template <typename D> Windows::Foundation::IReference<int32_t> consume_Windows_Gaming_Preview_GamesEnumeration_IGameModeConfiguration<D>::CpuExclusivityMaskLow() const
{
    Windows::Foundation::IReference<int32_t> value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Gaming::Preview::GamesEnumeration::IGameModeConfiguration)->get_CpuExclusivityMaskLow(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_Gaming_Preview_GamesEnumeration_IGameModeConfiguration<D>::CpuExclusivityMaskLow(optional<int32_t> const& value) const
{
    check_hresult(WINRT_SHIM(Windows::Gaming::Preview::GamesEnumeration::IGameModeConfiguration)->put_CpuExclusivityMaskLow(get_abi(value)));
}

template <typename D> Windows::Foundation::IReference<int32_t> consume_Windows_Gaming_Preview_GamesEnumeration_IGameModeConfiguration<D>::CpuExclusivityMaskHigh() const
{
    Windows::Foundation::IReference<int32_t> value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Gaming::Preview::GamesEnumeration::IGameModeConfiguration)->get_CpuExclusivityMaskHigh(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_Gaming_Preview_GamesEnumeration_IGameModeConfiguration<D>::CpuExclusivityMaskHigh(optional<int32_t> const& value) const
{
    check_hresult(WINRT_SHIM(Windows::Gaming::Preview::GamesEnumeration::IGameModeConfiguration)->put_CpuExclusivityMaskHigh(get_abi(value)));
}

template <typename D> bool consume_Windows_Gaming_Preview_GamesEnumeration_IGameModeConfiguration<D>::AffinitizeToExclusiveCpus() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::Gaming::Preview::GamesEnumeration::IGameModeConfiguration)->get_AffinitizeToExclusiveCpus(&value));
    return value;
}

template <typename D> void consume_Windows_Gaming_Preview_GamesEnumeration_IGameModeConfiguration<D>::AffinitizeToExclusiveCpus(bool value) const
{
    check_hresult(WINRT_SHIM(Windows::Gaming::Preview::GamesEnumeration::IGameModeConfiguration)->put_AffinitizeToExclusiveCpus(value));
}

template <typename D> Windows::Foundation::IAsyncAction consume_Windows_Gaming_Preview_GamesEnumeration_IGameModeConfiguration<D>::SaveAsync() const
{
    Windows::Foundation::IAsyncAction operation{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Gaming::Preview::GamesEnumeration::IGameModeConfiguration)->SaveAsync(put_abi(operation)));
    return operation;
}

template <typename D> Windows::Foundation::Collections::IVector<hstring> consume_Windows_Gaming_Preview_GamesEnumeration_IGameModeUserConfiguration<D>::GamingRelatedProcessNames() const
{
    Windows::Foundation::Collections::IVector<hstring> processNames{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Gaming::Preview::GamesEnumeration::IGameModeUserConfiguration)->get_GamingRelatedProcessNames(put_abi(processNames)));
    return processNames;
}

template <typename D> Windows::Foundation::IAsyncAction consume_Windows_Gaming_Preview_GamesEnumeration_IGameModeUserConfiguration<D>::SaveAsync() const
{
    Windows::Foundation::IAsyncAction operation{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Gaming::Preview::GamesEnumeration::IGameModeUserConfiguration)->SaveAsync(put_abi(operation)));
    return operation;
}

template <typename D> Windows::Gaming::Preview::GamesEnumeration::GameModeUserConfiguration consume_Windows_Gaming_Preview_GamesEnumeration_IGameModeUserConfigurationStatics<D>::GetDefault() const
{
    Windows::Gaming::Preview::GamesEnumeration::GameModeUserConfiguration userConfiguration{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Gaming::Preview::GamesEnumeration::IGameModeUserConfigurationStatics)->GetDefault(put_abi(userConfiguration)));
    return userConfiguration;
}

template <> struct delegate<Windows::Gaming::Preview::GamesEnumeration::GameListChangedEventHandler>
{
    template <typename H>
    struct type : implements_delegate<Windows::Gaming::Preview::GamesEnumeration::GameListChangedEventHandler, H>
    {
        type(H&& handler) : implements_delegate<Windows::Gaming::Preview::GamesEnumeration::GameListChangedEventHandler, H>(std::forward<H>(handler)) {}

        int32_t WINRT_CALL Invoke(void* game) noexcept final
        {
            try
            {
                (*this)(*reinterpret_cast<Windows::Gaming::Preview::GamesEnumeration::GameListEntry const*>(&game));
                return 0;
            }
            catch (...)
            {
                return to_hresult();
            }
        }
    };
};

template <> struct delegate<Windows::Gaming::Preview::GamesEnumeration::GameListRemovedEventHandler>
{
    template <typename H>
    struct type : implements_delegate<Windows::Gaming::Preview::GamesEnumeration::GameListRemovedEventHandler, H>
    {
        type(H&& handler) : implements_delegate<Windows::Gaming::Preview::GamesEnumeration::GameListRemovedEventHandler, H>(std::forward<H>(handler)) {}

        int32_t WINRT_CALL Invoke(void* identifier) noexcept final
        {
            try
            {
                (*this)(*reinterpret_cast<hstring const*>(&identifier));
                return 0;
            }
            catch (...)
            {
                return to_hresult();
            }
        }
    };
};

template <typename D>
struct produce<D, Windows::Gaming::Preview::GamesEnumeration::IGameListEntry> : produce_base<D, Windows::Gaming::Preview::GamesEnumeration::IGameListEntry>
{
    int32_t WINRT_CALL get_DisplayInfo(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(DisplayInfo, WINRT_WRAP(Windows::ApplicationModel::AppDisplayInfo));
            *value = detach_from<Windows::ApplicationModel::AppDisplayInfo>(this->shim().DisplayInfo());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL LaunchAsync(void** operation) noexcept final
    {
        try
        {
            *operation = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(LaunchAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<bool>));
            *operation = detach_from<Windows::Foundation::IAsyncOperation<bool>>(this->shim().LaunchAsync());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Category(Windows::Gaming::Preview::GamesEnumeration::GameListCategory* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Category, WINRT_WRAP(Windows::Gaming::Preview::GamesEnumeration::GameListCategory));
            *value = detach_from<Windows::Gaming::Preview::GamesEnumeration::GameListCategory>(this->shim().Category());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Properties(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Properties, WINRT_WRAP(Windows::Foundation::Collections::IMapView<hstring, Windows::Foundation::IInspectable>));
            *value = detach_from<Windows::Foundation::Collections::IMapView<hstring, Windows::Foundation::IInspectable>>(this->shim().Properties());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL SetCategoryAsync(Windows::Gaming::Preview::GamesEnumeration::GameListCategory value, void** action) noexcept final
    {
        try
        {
            *action = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SetCategoryAsync, WINRT_WRAP(Windows::Foundation::IAsyncAction), Windows::Gaming::Preview::GamesEnumeration::GameListCategory const);
            *action = detach_from<Windows::Foundation::IAsyncAction>(this->shim().SetCategoryAsync(*reinterpret_cast<Windows::Gaming::Preview::GamesEnumeration::GameListCategory const*>(&value)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Gaming::Preview::GamesEnumeration::IGameListEntry2> : produce_base<D, Windows::Gaming::Preview::GamesEnumeration::IGameListEntry2>
{
    int32_t WINRT_CALL get_LaunchableState(Windows::Gaming::Preview::GamesEnumeration::GameListEntryLaunchableState* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(LaunchableState, WINRT_WRAP(Windows::Gaming::Preview::GamesEnumeration::GameListEntryLaunchableState));
            *value = detach_from<Windows::Gaming::Preview::GamesEnumeration::GameListEntryLaunchableState>(this->shim().LaunchableState());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_LauncherExecutable(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(LauncherExecutable, WINRT_WRAP(Windows::Storage::IStorageFile));
            *value = detach_from<Windows::Storage::IStorageFile>(this->shim().LauncherExecutable());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_LaunchParameters(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(LaunchParameters, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().LaunchParameters());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL SetLauncherExecutableFileAsync(void* executableFile, void** operation) noexcept final
    {
        try
        {
            *operation = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SetLauncherExecutableFileAsync, WINRT_WRAP(Windows::Foundation::IAsyncAction), Windows::Storage::IStorageFile const);
            *operation = detach_from<Windows::Foundation::IAsyncAction>(this->shim().SetLauncherExecutableFileAsync(*reinterpret_cast<Windows::Storage::IStorageFile const*>(&executableFile)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL SetLauncherExecutableFileWithParamsAsync(void* executableFile, void* launchParams, void** operation) noexcept final
    {
        try
        {
            *operation = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SetLauncherExecutableFileAsync, WINRT_WRAP(Windows::Foundation::IAsyncAction), Windows::Storage::IStorageFile const, hstring const);
            *operation = detach_from<Windows::Foundation::IAsyncAction>(this->shim().SetLauncherExecutableFileAsync(*reinterpret_cast<Windows::Storage::IStorageFile const*>(&executableFile), *reinterpret_cast<hstring const*>(&launchParams)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_TitleId(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(TitleId, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().TitleId());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL SetTitleIdAsync(void* id, void** operation) noexcept final
    {
        try
        {
            *operation = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SetTitleIdAsync, WINRT_WRAP(Windows::Foundation::IAsyncAction), hstring const);
            *operation = detach_from<Windows::Foundation::IAsyncAction>(this->shim().SetTitleIdAsync(*reinterpret_cast<hstring const*>(&id)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_GameModeConfiguration(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GameModeConfiguration, WINRT_WRAP(Windows::Gaming::Preview::GamesEnumeration::GameModeConfiguration));
            *value = detach_from<Windows::Gaming::Preview::GamesEnumeration::GameModeConfiguration>(this->shim().GameModeConfiguration());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Gaming::Preview::GamesEnumeration::IGameListStatics> : produce_base<D, Windows::Gaming::Preview::GamesEnumeration::IGameListStatics>
{
    int32_t WINRT_CALL FindAllAsync(void** operation) noexcept final
    {
        try
        {
            *operation = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(FindAllAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<Windows::Foundation::Collections::IVectorView<Windows::Gaming::Preview::GamesEnumeration::GameListEntry>>));
            *operation = detach_from<Windows::Foundation::IAsyncOperation<Windows::Foundation::Collections::IVectorView<Windows::Gaming::Preview::GamesEnumeration::GameListEntry>>>(this->shim().FindAllAsync());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL FindAllAsyncPackageFamilyName(void* packageFamilyName, void** operation) noexcept final
    {
        try
        {
            *operation = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(FindAllAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<Windows::Foundation::Collections::IVectorView<Windows::Gaming::Preview::GamesEnumeration::GameListEntry>>), hstring const);
            *operation = detach_from<Windows::Foundation::IAsyncOperation<Windows::Foundation::Collections::IVectorView<Windows::Gaming::Preview::GamesEnumeration::GameListEntry>>>(this->shim().FindAllAsync(*reinterpret_cast<hstring const*>(&packageFamilyName)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL add_GameAdded(void* handler, winrt::event_token* token) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GameAdded, WINRT_WRAP(winrt::event_token), Windows::Gaming::Preview::GamesEnumeration::GameListChangedEventHandler const&);
            *token = detach_from<winrt::event_token>(this->shim().GameAdded(*reinterpret_cast<Windows::Gaming::Preview::GamesEnumeration::GameListChangedEventHandler const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL remove_GameAdded(winrt::event_token token) noexcept final
    {
        typename D::abi_guard guard(this->shim());
        WINRT_ASSERT_DECLARATION(GameAdded, WINRT_WRAP(void), winrt::event_token const&);
        this->shim().GameAdded(*reinterpret_cast<winrt::event_token const*>(&token));
        return 0;
    }

    int32_t WINRT_CALL add_GameRemoved(void* handler, winrt::event_token* token) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GameRemoved, WINRT_WRAP(winrt::event_token), Windows::Gaming::Preview::GamesEnumeration::GameListRemovedEventHandler const&);
            *token = detach_from<winrt::event_token>(this->shim().GameRemoved(*reinterpret_cast<Windows::Gaming::Preview::GamesEnumeration::GameListRemovedEventHandler const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL remove_GameRemoved(winrt::event_token token) noexcept final
    {
        typename D::abi_guard guard(this->shim());
        WINRT_ASSERT_DECLARATION(GameRemoved, WINRT_WRAP(void), winrt::event_token const&);
        this->shim().GameRemoved(*reinterpret_cast<winrt::event_token const*>(&token));
        return 0;
    }

    int32_t WINRT_CALL add_GameUpdated(void* handler, winrt::event_token* token) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GameUpdated, WINRT_WRAP(winrt::event_token), Windows::Gaming::Preview::GamesEnumeration::GameListChangedEventHandler const&);
            *token = detach_from<winrt::event_token>(this->shim().GameUpdated(*reinterpret_cast<Windows::Gaming::Preview::GamesEnumeration::GameListChangedEventHandler const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL remove_GameUpdated(winrt::event_token token) noexcept final
    {
        typename D::abi_guard guard(this->shim());
        WINRT_ASSERT_DECLARATION(GameUpdated, WINRT_WRAP(void), winrt::event_token const&);
        this->shim().GameUpdated(*reinterpret_cast<winrt::event_token const*>(&token));
        return 0;
    }
};

template <typename D>
struct produce<D, Windows::Gaming::Preview::GamesEnumeration::IGameListStatics2> : produce_base<D, Windows::Gaming::Preview::GamesEnumeration::IGameListStatics2>
{
    int32_t WINRT_CALL MergeEntriesAsync(void* left, void* right, void** operation) noexcept final
    {
        try
        {
            *operation = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(MergeEntriesAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<Windows::Gaming::Preview::GamesEnumeration::GameListEntry>), Windows::Gaming::Preview::GamesEnumeration::GameListEntry const, Windows::Gaming::Preview::GamesEnumeration::GameListEntry const);
            *operation = detach_from<Windows::Foundation::IAsyncOperation<Windows::Gaming::Preview::GamesEnumeration::GameListEntry>>(this->shim().MergeEntriesAsync(*reinterpret_cast<Windows::Gaming::Preview::GamesEnumeration::GameListEntry const*>(&left), *reinterpret_cast<Windows::Gaming::Preview::GamesEnumeration::GameListEntry const*>(&right)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL UnmergeEntryAsync(void* mergedEntry, void** operation) noexcept final
    {
        try
        {
            *operation = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(UnmergeEntryAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<Windows::Foundation::Collections::IVectorView<Windows::Gaming::Preview::GamesEnumeration::GameListEntry>>), Windows::Gaming::Preview::GamesEnumeration::GameListEntry const);
            *operation = detach_from<Windows::Foundation::IAsyncOperation<Windows::Foundation::Collections::IVectorView<Windows::Gaming::Preview::GamesEnumeration::GameListEntry>>>(this->shim().UnmergeEntryAsync(*reinterpret_cast<Windows::Gaming::Preview::GamesEnumeration::GameListEntry const*>(&mergedEntry)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Gaming::Preview::GamesEnumeration::IGameModeConfiguration> : produce_base<D, Windows::Gaming::Preview::GamesEnumeration::IGameModeConfiguration>
{
    int32_t WINRT_CALL get_IsEnabled(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IsEnabled, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().IsEnabled());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_IsEnabled(bool value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IsEnabled, WINRT_WRAP(void), bool);
            this->shim().IsEnabled(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_RelatedProcessNames(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(RelatedProcessNames, WINRT_WRAP(Windows::Foundation::Collections::IVector<hstring>));
            *value = detach_from<Windows::Foundation::Collections::IVector<hstring>>(this->shim().RelatedProcessNames());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_PercentGpuTimeAllocatedToGame(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(PercentGpuTimeAllocatedToGame, WINRT_WRAP(Windows::Foundation::IReference<int32_t>));
            *value = detach_from<Windows::Foundation::IReference<int32_t>>(this->shim().PercentGpuTimeAllocatedToGame());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_PercentGpuTimeAllocatedToGame(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(PercentGpuTimeAllocatedToGame, WINRT_WRAP(void), Windows::Foundation::IReference<int32_t> const&);
            this->shim().PercentGpuTimeAllocatedToGame(*reinterpret_cast<Windows::Foundation::IReference<int32_t> const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_PercentGpuMemoryAllocatedToGame(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(PercentGpuMemoryAllocatedToGame, WINRT_WRAP(Windows::Foundation::IReference<int32_t>));
            *value = detach_from<Windows::Foundation::IReference<int32_t>>(this->shim().PercentGpuMemoryAllocatedToGame());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_PercentGpuMemoryAllocatedToGame(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(PercentGpuMemoryAllocatedToGame, WINRT_WRAP(void), Windows::Foundation::IReference<int32_t> const&);
            this->shim().PercentGpuMemoryAllocatedToGame(*reinterpret_cast<Windows::Foundation::IReference<int32_t> const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_PercentGpuMemoryAllocatedToSystemCompositor(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(PercentGpuMemoryAllocatedToSystemCompositor, WINRT_WRAP(Windows::Foundation::IReference<int32_t>));
            *value = detach_from<Windows::Foundation::IReference<int32_t>>(this->shim().PercentGpuMemoryAllocatedToSystemCompositor());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_PercentGpuMemoryAllocatedToSystemCompositor(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(PercentGpuMemoryAllocatedToSystemCompositor, WINRT_WRAP(void), Windows::Foundation::IReference<int32_t> const&);
            this->shim().PercentGpuMemoryAllocatedToSystemCompositor(*reinterpret_cast<Windows::Foundation::IReference<int32_t> const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_MaxCpuCount(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(MaxCpuCount, WINRT_WRAP(Windows::Foundation::IReference<int32_t>));
            *value = detach_from<Windows::Foundation::IReference<int32_t>>(this->shim().MaxCpuCount());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_MaxCpuCount(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(MaxCpuCount, WINRT_WRAP(void), Windows::Foundation::IReference<int32_t> const&);
            this->shim().MaxCpuCount(*reinterpret_cast<Windows::Foundation::IReference<int32_t> const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_CpuExclusivityMaskLow(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CpuExclusivityMaskLow, WINRT_WRAP(Windows::Foundation::IReference<int32_t>));
            *value = detach_from<Windows::Foundation::IReference<int32_t>>(this->shim().CpuExclusivityMaskLow());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_CpuExclusivityMaskLow(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CpuExclusivityMaskLow, WINRT_WRAP(void), Windows::Foundation::IReference<int32_t> const&);
            this->shim().CpuExclusivityMaskLow(*reinterpret_cast<Windows::Foundation::IReference<int32_t> const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_CpuExclusivityMaskHigh(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CpuExclusivityMaskHigh, WINRT_WRAP(Windows::Foundation::IReference<int32_t>));
            *value = detach_from<Windows::Foundation::IReference<int32_t>>(this->shim().CpuExclusivityMaskHigh());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_CpuExclusivityMaskHigh(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CpuExclusivityMaskHigh, WINRT_WRAP(void), Windows::Foundation::IReference<int32_t> const&);
            this->shim().CpuExclusivityMaskHigh(*reinterpret_cast<Windows::Foundation::IReference<int32_t> const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_AffinitizeToExclusiveCpus(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(AffinitizeToExclusiveCpus, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().AffinitizeToExclusiveCpus());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_AffinitizeToExclusiveCpus(bool value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(AffinitizeToExclusiveCpus, WINRT_WRAP(void), bool);
            this->shim().AffinitizeToExclusiveCpus(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL SaveAsync(void** operation) noexcept final
    {
        try
        {
            *operation = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SaveAsync, WINRT_WRAP(Windows::Foundation::IAsyncAction));
            *operation = detach_from<Windows::Foundation::IAsyncAction>(this->shim().SaveAsync());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Gaming::Preview::GamesEnumeration::IGameModeUserConfiguration> : produce_base<D, Windows::Gaming::Preview::GamesEnumeration::IGameModeUserConfiguration>
{
    int32_t WINRT_CALL get_GamingRelatedProcessNames(void** processNames) noexcept final
    {
        try
        {
            *processNames = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GamingRelatedProcessNames, WINRT_WRAP(Windows::Foundation::Collections::IVector<hstring>));
            *processNames = detach_from<Windows::Foundation::Collections::IVector<hstring>>(this->shim().GamingRelatedProcessNames());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL SaveAsync(void** operation) noexcept final
    {
        try
        {
            *operation = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SaveAsync, WINRT_WRAP(Windows::Foundation::IAsyncAction));
            *operation = detach_from<Windows::Foundation::IAsyncAction>(this->shim().SaveAsync());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Gaming::Preview::GamesEnumeration::IGameModeUserConfigurationStatics> : produce_base<D, Windows::Gaming::Preview::GamesEnumeration::IGameModeUserConfigurationStatics>
{
    int32_t WINRT_CALL GetDefault(void** userConfiguration) noexcept final
    {
        try
        {
            *userConfiguration = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetDefault, WINRT_WRAP(Windows::Gaming::Preview::GamesEnumeration::GameModeUserConfiguration));
            *userConfiguration = detach_from<Windows::Gaming::Preview::GamesEnumeration::GameModeUserConfiguration>(this->shim().GetDefault());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

}

WINRT_EXPORT namespace winrt::Windows::Gaming::Preview::GamesEnumeration {

inline Windows::Foundation::IAsyncOperation<Windows::Foundation::Collections::IVectorView<Windows::Gaming::Preview::GamesEnumeration::GameListEntry>> GameList::FindAllAsync()
{
    return impl::call_factory<GameList, Windows::Gaming::Preview::GamesEnumeration::IGameListStatics>([&](auto&& f) { return f.FindAllAsync(); });
}

inline Windows::Foundation::IAsyncOperation<Windows::Foundation::Collections::IVectorView<Windows::Gaming::Preview::GamesEnumeration::GameListEntry>> GameList::FindAllAsync(param::hstring const& packageFamilyName)
{
    return impl::call_factory<GameList, Windows::Gaming::Preview::GamesEnumeration::IGameListStatics>([&](auto&& f) { return f.FindAllAsync(packageFamilyName); });
}

inline winrt::event_token GameList::GameAdded(Windows::Gaming::Preview::GamesEnumeration::GameListChangedEventHandler const& handler)
{
    return impl::call_factory<GameList, Windows::Gaming::Preview::GamesEnumeration::IGameListStatics>([&](auto&& f) { return f.GameAdded(handler); });
}

inline GameList::GameAdded_revoker GameList::GameAdded(auto_revoke_t, Windows::Gaming::Preview::GamesEnumeration::GameListChangedEventHandler const& handler)
{
    auto f = get_activation_factory<GameList, Windows::Gaming::Preview::GamesEnumeration::IGameListStatics>();
    return { f, f.GameAdded(handler) };
}

inline void GameList::GameAdded(winrt::event_token const& token)
{
    impl::call_factory<GameList, Windows::Gaming::Preview::GamesEnumeration::IGameListStatics>([&](auto&& f) { return f.GameAdded(token); });
}

inline winrt::event_token GameList::GameRemoved(Windows::Gaming::Preview::GamesEnumeration::GameListRemovedEventHandler const& handler)
{
    return impl::call_factory<GameList, Windows::Gaming::Preview::GamesEnumeration::IGameListStatics>([&](auto&& f) { return f.GameRemoved(handler); });
}

inline GameList::GameRemoved_revoker GameList::GameRemoved(auto_revoke_t, Windows::Gaming::Preview::GamesEnumeration::GameListRemovedEventHandler const& handler)
{
    auto f = get_activation_factory<GameList, Windows::Gaming::Preview::GamesEnumeration::IGameListStatics>();
    return { f, f.GameRemoved(handler) };
}

inline void GameList::GameRemoved(winrt::event_token const& token)
{
    impl::call_factory<GameList, Windows::Gaming::Preview::GamesEnumeration::IGameListStatics>([&](auto&& f) { return f.GameRemoved(token); });
}

inline winrt::event_token GameList::GameUpdated(Windows::Gaming::Preview::GamesEnumeration::GameListChangedEventHandler const& handler)
{
    return impl::call_factory<GameList, Windows::Gaming::Preview::GamesEnumeration::IGameListStatics>([&](auto&& f) { return f.GameUpdated(handler); });
}

inline GameList::GameUpdated_revoker GameList::GameUpdated(auto_revoke_t, Windows::Gaming::Preview::GamesEnumeration::GameListChangedEventHandler const& handler)
{
    auto f = get_activation_factory<GameList, Windows::Gaming::Preview::GamesEnumeration::IGameListStatics>();
    return { f, f.GameUpdated(handler) };
}

inline void GameList::GameUpdated(winrt::event_token const& token)
{
    impl::call_factory<GameList, Windows::Gaming::Preview::GamesEnumeration::IGameListStatics>([&](auto&& f) { return f.GameUpdated(token); });
}

inline Windows::Foundation::IAsyncOperation<Windows::Gaming::Preview::GamesEnumeration::GameListEntry> GameList::MergeEntriesAsync(Windows::Gaming::Preview::GamesEnumeration::GameListEntry const& left, Windows::Gaming::Preview::GamesEnumeration::GameListEntry const& right)
{
    return impl::call_factory<GameList, Windows::Gaming::Preview::GamesEnumeration::IGameListStatics2>([&](auto&& f) { return f.MergeEntriesAsync(left, right); });
}

inline Windows::Foundation::IAsyncOperation<Windows::Foundation::Collections::IVectorView<Windows::Gaming::Preview::GamesEnumeration::GameListEntry>> GameList::UnmergeEntryAsync(Windows::Gaming::Preview::GamesEnumeration::GameListEntry const& mergedEntry)
{
    return impl::call_factory<GameList, Windows::Gaming::Preview::GamesEnumeration::IGameListStatics2>([&](auto&& f) { return f.UnmergeEntryAsync(mergedEntry); });
}

inline Windows::Gaming::Preview::GamesEnumeration::GameModeUserConfiguration GameModeUserConfiguration::GetDefault()
{
    return impl::call_factory<GameModeUserConfiguration, Windows::Gaming::Preview::GamesEnumeration::IGameModeUserConfigurationStatics>([&](auto&& f) { return f.GetDefault(); });
}

template <typename L> GameListChangedEventHandler::GameListChangedEventHandler(L handler) :
    GameListChangedEventHandler(impl::make_delegate<GameListChangedEventHandler>(std::forward<L>(handler)))
{}

template <typename F> GameListChangedEventHandler::GameListChangedEventHandler(F* handler) :
    GameListChangedEventHandler([=](auto&&... args) { return handler(args...); })
{}

template <typename O, typename M> GameListChangedEventHandler::GameListChangedEventHandler(O* object, M method) :
    GameListChangedEventHandler([=](auto&&... args) { return ((*object).*(method))(args...); })
{}

template <typename O, typename M> GameListChangedEventHandler::GameListChangedEventHandler(com_ptr<O>&& object, M method) :
    GameListChangedEventHandler([o = std::move(object), method](auto&&... args) { return ((*o).*(method))(args...); })
{}

template <typename O, typename M> GameListChangedEventHandler::GameListChangedEventHandler(weak_ref<O>&& object, M method) :
    GameListChangedEventHandler([o = std::move(object), method](auto&&... args) { if (auto s = o.get()) { ((*s).*(method))(args...); } })
{}

inline void GameListChangedEventHandler::operator()(Windows::Gaming::Preview::GamesEnumeration::GameListEntry const& game) const
{
    check_hresult((*(impl::abi_t<GameListChangedEventHandler>**)this)->Invoke(get_abi(game)));
}

template <typename L> GameListRemovedEventHandler::GameListRemovedEventHandler(L handler) :
    GameListRemovedEventHandler(impl::make_delegate<GameListRemovedEventHandler>(std::forward<L>(handler)))
{}

template <typename F> GameListRemovedEventHandler::GameListRemovedEventHandler(F* handler) :
    GameListRemovedEventHandler([=](auto&&... args) { return handler(args...); })
{}

template <typename O, typename M> GameListRemovedEventHandler::GameListRemovedEventHandler(O* object, M method) :
    GameListRemovedEventHandler([=](auto&&... args) { return ((*object).*(method))(args...); })
{}

template <typename O, typename M> GameListRemovedEventHandler::GameListRemovedEventHandler(com_ptr<O>&& object, M method) :
    GameListRemovedEventHandler([o = std::move(object), method](auto&&... args) { return ((*o).*(method))(args...); })
{}

template <typename O, typename M> GameListRemovedEventHandler::GameListRemovedEventHandler(weak_ref<O>&& object, M method) :
    GameListRemovedEventHandler([o = std::move(object), method](auto&&... args) { if (auto s = o.get()) { ((*s).*(method))(args...); } })
{}

inline void GameListRemovedEventHandler::operator()(param::hstring const& identifier) const
{
    check_hresult((*(impl::abi_t<GameListRemovedEventHandler>**)this)->Invoke(get_abi(identifier)));
}

}

WINRT_EXPORT namespace std {

template<> struct hash<winrt::Windows::Gaming::Preview::GamesEnumeration::IGameListEntry> : winrt::impl::hash_base<winrt::Windows::Gaming::Preview::GamesEnumeration::IGameListEntry> {};
template<> struct hash<winrt::Windows::Gaming::Preview::GamesEnumeration::IGameListEntry2> : winrt::impl::hash_base<winrt::Windows::Gaming::Preview::GamesEnumeration::IGameListEntry2> {};
template<> struct hash<winrt::Windows::Gaming::Preview::GamesEnumeration::IGameListStatics> : winrt::impl::hash_base<winrt::Windows::Gaming::Preview::GamesEnumeration::IGameListStatics> {};
template<> struct hash<winrt::Windows::Gaming::Preview::GamesEnumeration::IGameListStatics2> : winrt::impl::hash_base<winrt::Windows::Gaming::Preview::GamesEnumeration::IGameListStatics2> {};
template<> struct hash<winrt::Windows::Gaming::Preview::GamesEnumeration::IGameModeConfiguration> : winrt::impl::hash_base<winrt::Windows::Gaming::Preview::GamesEnumeration::IGameModeConfiguration> {};
template<> struct hash<winrt::Windows::Gaming::Preview::GamesEnumeration::IGameModeUserConfiguration> : winrt::impl::hash_base<winrt::Windows::Gaming::Preview::GamesEnumeration::IGameModeUserConfiguration> {};
template<> struct hash<winrt::Windows::Gaming::Preview::GamesEnumeration::IGameModeUserConfigurationStatics> : winrt::impl::hash_base<winrt::Windows::Gaming::Preview::GamesEnumeration::IGameModeUserConfigurationStatics> {};
template<> struct hash<winrt::Windows::Gaming::Preview::GamesEnumeration::GameList> : winrt::impl::hash_base<winrt::Windows::Gaming::Preview::GamesEnumeration::GameList> {};
template<> struct hash<winrt::Windows::Gaming::Preview::GamesEnumeration::GameListEntry> : winrt::impl::hash_base<winrt::Windows::Gaming::Preview::GamesEnumeration::GameListEntry> {};
template<> struct hash<winrt::Windows::Gaming::Preview::GamesEnumeration::GameModeConfiguration> : winrt::impl::hash_base<winrt::Windows::Gaming::Preview::GamesEnumeration::GameModeConfiguration> {};
template<> struct hash<winrt::Windows::Gaming::Preview::GamesEnumeration::GameModeUserConfiguration> : winrt::impl::hash_base<winrt::Windows::Gaming::Preview::GamesEnumeration::GameModeUserConfiguration> {};

}
