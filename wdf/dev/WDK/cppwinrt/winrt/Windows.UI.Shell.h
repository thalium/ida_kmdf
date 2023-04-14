// C++/WinRT v1.0.190111.3

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#pragma once

#include "winrt/base.h"

#include "winrt/Windows.Foundation.h"
#include "winrt/Windows.Foundation.Collections.h"
#include "winrt/impl/Windows.ApplicationModel.Core.2.h"
#include "winrt/impl/Windows.Foundation.2.h"
#include "winrt/impl/Windows.UI.StartScreen.2.h"
#include "winrt/impl/Windows.UI.Shell.2.h"
#include "winrt/Windows.UI.h"

namespace winrt::impl {

template <typename D> hstring consume_Windows_UI_Shell_IAdaptiveCard<D>::ToJson() const
{
    hstring result{};
    check_hresult(WINRT_SHIM(Windows::UI::Shell::IAdaptiveCard)->ToJson(put_abi(result)));
    return result;
}

template <typename D> Windows::UI::Shell::IAdaptiveCard consume_Windows_UI_Shell_IAdaptiveCardBuilderStatics<D>::CreateAdaptiveCardFromJson(param::hstring const& value) const
{
    Windows::UI::Shell::IAdaptiveCard result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Shell::IAdaptiveCardBuilderStatics)->CreateAdaptiveCardFromJson(get_abi(value), put_abi(result)));
    return result;
}

template <typename D> winrt::guid consume_Windows_UI_Shell_ISecurityAppManager<D>::Register(Windows::UI::Shell::SecurityAppKind const& kind, param::hstring const& displayName, Windows::Foundation::Uri const& detailsUri, bool registerPerUser) const
{
    winrt::guid result{};
    check_hresult(WINRT_SHIM(Windows::UI::Shell::ISecurityAppManager)->Register(get_abi(kind), get_abi(displayName), get_abi(detailsUri), registerPerUser, put_abi(result)));
    return result;
}

template <typename D> void consume_Windows_UI_Shell_ISecurityAppManager<D>::Unregister(Windows::UI::Shell::SecurityAppKind const& kind, winrt::guid const& guidRegistration) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Shell::ISecurityAppManager)->Unregister(get_abi(kind), get_abi(guidRegistration)));
}

template <typename D> void consume_Windows_UI_Shell_ISecurityAppManager<D>::UpdateState(Windows::UI::Shell::SecurityAppKind const& kind, winrt::guid const& guidRegistration, Windows::UI::Shell::SecurityAppState const& state, Windows::UI::Shell::SecurityAppSubstatus const& substatus, Windows::Foundation::Uri const& detailsUri) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Shell::ISecurityAppManager)->UpdateState(get_abi(kind), get_abi(guidRegistration), get_abi(state), get_abi(substatus), get_abi(detailsUri)));
}

template <typename D> bool consume_Windows_UI_Shell_ITaskbarManager<D>::IsSupported() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::UI::Shell::ITaskbarManager)->get_IsSupported(&value));
    return value;
}

template <typename D> bool consume_Windows_UI_Shell_ITaskbarManager<D>::IsPinningAllowed() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::UI::Shell::ITaskbarManager)->get_IsPinningAllowed(&value));
    return value;
}

template <typename D> Windows::Foundation::IAsyncOperation<bool> consume_Windows_UI_Shell_ITaskbarManager<D>::IsCurrentAppPinnedAsync() const
{
    Windows::Foundation::IAsyncOperation<bool> operation{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Shell::ITaskbarManager)->IsCurrentAppPinnedAsync(put_abi(operation)));
    return operation;
}

template <typename D> Windows::Foundation::IAsyncOperation<bool> consume_Windows_UI_Shell_ITaskbarManager<D>::IsAppListEntryPinnedAsync(Windows::ApplicationModel::Core::AppListEntry const& appListEntry) const
{
    Windows::Foundation::IAsyncOperation<bool> operation{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Shell::ITaskbarManager)->IsAppListEntryPinnedAsync(get_abi(appListEntry), put_abi(operation)));
    return operation;
}

template <typename D> Windows::Foundation::IAsyncOperation<bool> consume_Windows_UI_Shell_ITaskbarManager<D>::RequestPinCurrentAppAsync() const
{
    Windows::Foundation::IAsyncOperation<bool> operation{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Shell::ITaskbarManager)->RequestPinCurrentAppAsync(put_abi(operation)));
    return operation;
}

template <typename D> Windows::Foundation::IAsyncOperation<bool> consume_Windows_UI_Shell_ITaskbarManager<D>::RequestPinAppListEntryAsync(Windows::ApplicationModel::Core::AppListEntry const& appListEntry) const
{
    Windows::Foundation::IAsyncOperation<bool> operation{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Shell::ITaskbarManager)->RequestPinAppListEntryAsync(get_abi(appListEntry), put_abi(operation)));
    return operation;
}

template <typename D> Windows::Foundation::IAsyncOperation<bool> consume_Windows_UI_Shell_ITaskbarManager2<D>::IsSecondaryTilePinnedAsync(param::hstring const& tileId) const
{
    Windows::Foundation::IAsyncOperation<bool> operation{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Shell::ITaskbarManager2)->IsSecondaryTilePinnedAsync(get_abi(tileId), put_abi(operation)));
    return operation;
}

template <typename D> Windows::Foundation::IAsyncOperation<bool> consume_Windows_UI_Shell_ITaskbarManager2<D>::RequestPinSecondaryTileAsync(Windows::UI::StartScreen::SecondaryTile const& secondaryTile) const
{
    Windows::Foundation::IAsyncOperation<bool> operation{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Shell::ITaskbarManager2)->RequestPinSecondaryTileAsync(get_abi(secondaryTile), put_abi(operation)));
    return operation;
}

template <typename D> Windows::Foundation::IAsyncOperation<bool> consume_Windows_UI_Shell_ITaskbarManager2<D>::TryUnpinSecondaryTileAsync(param::hstring const& tileId) const
{
    Windows::Foundation::IAsyncOperation<bool> operation{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Shell::ITaskbarManager2)->TryUnpinSecondaryTileAsync(get_abi(tileId), put_abi(operation)));
    return operation;
}

template <typename D> Windows::UI::Shell::TaskbarManager consume_Windows_UI_Shell_ITaskbarManagerStatics<D>::GetDefault() const
{
    Windows::UI::Shell::TaskbarManager result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Shell::ITaskbarManagerStatics)->GetDefault(put_abi(result)));
    return result;
}

template <typename D>
struct produce<D, Windows::UI::Shell::IAdaptiveCard> : produce_base<D, Windows::UI::Shell::IAdaptiveCard>
{
    int32_t WINRT_CALL ToJson(void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ToJson, WINRT_WRAP(hstring));
            *result = detach_from<hstring>(this->shim().ToJson());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Shell::IAdaptiveCardBuilderStatics> : produce_base<D, Windows::UI::Shell::IAdaptiveCardBuilderStatics>
{
    int32_t WINRT_CALL CreateAdaptiveCardFromJson(void* value, void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CreateAdaptiveCardFromJson, WINRT_WRAP(Windows::UI::Shell::IAdaptiveCard), hstring const&);
            *result = detach_from<Windows::UI::Shell::IAdaptiveCard>(this->shim().CreateAdaptiveCardFromJson(*reinterpret_cast<hstring const*>(&value)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Shell::ISecurityAppManager> : produce_base<D, Windows::UI::Shell::ISecurityAppManager>
{
    int32_t WINRT_CALL Register(Windows::UI::Shell::SecurityAppKind kind, void* displayName, void* detailsUri, bool registerPerUser, winrt::guid* result) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Register, WINRT_WRAP(winrt::guid), Windows::UI::Shell::SecurityAppKind const&, hstring const&, Windows::Foundation::Uri const&, bool);
            *result = detach_from<winrt::guid>(this->shim().Register(*reinterpret_cast<Windows::UI::Shell::SecurityAppKind const*>(&kind), *reinterpret_cast<hstring const*>(&displayName), *reinterpret_cast<Windows::Foundation::Uri const*>(&detailsUri), registerPerUser));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL Unregister(Windows::UI::Shell::SecurityAppKind kind, winrt::guid guidRegistration) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Unregister, WINRT_WRAP(void), Windows::UI::Shell::SecurityAppKind const&, winrt::guid const&);
            this->shim().Unregister(*reinterpret_cast<Windows::UI::Shell::SecurityAppKind const*>(&kind), *reinterpret_cast<winrt::guid const*>(&guidRegistration));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL UpdateState(Windows::UI::Shell::SecurityAppKind kind, winrt::guid guidRegistration, Windows::UI::Shell::SecurityAppState state, Windows::UI::Shell::SecurityAppSubstatus substatus, void* detailsUri) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(UpdateState, WINRT_WRAP(void), Windows::UI::Shell::SecurityAppKind const&, winrt::guid const&, Windows::UI::Shell::SecurityAppState const&, Windows::UI::Shell::SecurityAppSubstatus const&, Windows::Foundation::Uri const&);
            this->shim().UpdateState(*reinterpret_cast<Windows::UI::Shell::SecurityAppKind const*>(&kind), *reinterpret_cast<winrt::guid const*>(&guidRegistration), *reinterpret_cast<Windows::UI::Shell::SecurityAppState const*>(&state), *reinterpret_cast<Windows::UI::Shell::SecurityAppSubstatus const*>(&substatus), *reinterpret_cast<Windows::Foundation::Uri const*>(&detailsUri));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Shell::ITaskbarManager> : produce_base<D, Windows::UI::Shell::ITaskbarManager>
{
    int32_t WINRT_CALL get_IsSupported(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IsSupported, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().IsSupported());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_IsPinningAllowed(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IsPinningAllowed, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().IsPinningAllowed());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL IsCurrentAppPinnedAsync(void** operation) noexcept final
    {
        try
        {
            *operation = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IsCurrentAppPinnedAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<bool>));
            *operation = detach_from<Windows::Foundation::IAsyncOperation<bool>>(this->shim().IsCurrentAppPinnedAsync());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL IsAppListEntryPinnedAsync(void* appListEntry, void** operation) noexcept final
    {
        try
        {
            *operation = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IsAppListEntryPinnedAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<bool>), Windows::ApplicationModel::Core::AppListEntry const);
            *operation = detach_from<Windows::Foundation::IAsyncOperation<bool>>(this->shim().IsAppListEntryPinnedAsync(*reinterpret_cast<Windows::ApplicationModel::Core::AppListEntry const*>(&appListEntry)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL RequestPinCurrentAppAsync(void** operation) noexcept final
    {
        try
        {
            *operation = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(RequestPinCurrentAppAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<bool>));
            *operation = detach_from<Windows::Foundation::IAsyncOperation<bool>>(this->shim().RequestPinCurrentAppAsync());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL RequestPinAppListEntryAsync(void* appListEntry, void** operation) noexcept final
    {
        try
        {
            *operation = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(RequestPinAppListEntryAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<bool>), Windows::ApplicationModel::Core::AppListEntry const);
            *operation = detach_from<Windows::Foundation::IAsyncOperation<bool>>(this->shim().RequestPinAppListEntryAsync(*reinterpret_cast<Windows::ApplicationModel::Core::AppListEntry const*>(&appListEntry)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Shell::ITaskbarManager2> : produce_base<D, Windows::UI::Shell::ITaskbarManager2>
{
    int32_t WINRT_CALL IsSecondaryTilePinnedAsync(void* tileId, void** operation) noexcept final
    {
        try
        {
            *operation = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IsSecondaryTilePinnedAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<bool>), hstring const);
            *operation = detach_from<Windows::Foundation::IAsyncOperation<bool>>(this->shim().IsSecondaryTilePinnedAsync(*reinterpret_cast<hstring const*>(&tileId)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL RequestPinSecondaryTileAsync(void* secondaryTile, void** operation) noexcept final
    {
        try
        {
            *operation = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(RequestPinSecondaryTileAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<bool>), Windows::UI::StartScreen::SecondaryTile const);
            *operation = detach_from<Windows::Foundation::IAsyncOperation<bool>>(this->shim().RequestPinSecondaryTileAsync(*reinterpret_cast<Windows::UI::StartScreen::SecondaryTile const*>(&secondaryTile)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL TryUnpinSecondaryTileAsync(void* tileId, void** operation) noexcept final
    {
        try
        {
            *operation = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(TryUnpinSecondaryTileAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<bool>), hstring const);
            *operation = detach_from<Windows::Foundation::IAsyncOperation<bool>>(this->shim().TryUnpinSecondaryTileAsync(*reinterpret_cast<hstring const*>(&tileId)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Shell::ITaskbarManagerStatics> : produce_base<D, Windows::UI::Shell::ITaskbarManagerStatics>
{
    int32_t WINRT_CALL GetDefault(void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetDefault, WINRT_WRAP(Windows::UI::Shell::TaskbarManager));
            *result = detach_from<Windows::UI::Shell::TaskbarManager>(this->shim().GetDefault());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

}

WINRT_EXPORT namespace winrt::Windows::UI::Shell {

inline Windows::UI::Shell::IAdaptiveCard AdaptiveCardBuilder::CreateAdaptiveCardFromJson(param::hstring const& value)
{
    return impl::call_factory<AdaptiveCardBuilder, Windows::UI::Shell::IAdaptiveCardBuilderStatics>([&](auto&& f) { return f.CreateAdaptiveCardFromJson(value); });
}

inline SecurityAppManager::SecurityAppManager() :
    SecurityAppManager(impl::call_factory<SecurityAppManager>([](auto&& f) { return f.template ActivateInstance<SecurityAppManager>(); }))
{}

inline Windows::UI::Shell::TaskbarManager TaskbarManager::GetDefault()
{
    return impl::call_factory<TaskbarManager, Windows::UI::Shell::ITaskbarManagerStatics>([&](auto&& f) { return f.GetDefault(); });
}

}

WINRT_EXPORT namespace std {

template<> struct hash<winrt::Windows::UI::Shell::IAdaptiveCard> : winrt::impl::hash_base<winrt::Windows::UI::Shell::IAdaptiveCard> {};
template<> struct hash<winrt::Windows::UI::Shell::IAdaptiveCardBuilderStatics> : winrt::impl::hash_base<winrt::Windows::UI::Shell::IAdaptiveCardBuilderStatics> {};
template<> struct hash<winrt::Windows::UI::Shell::ISecurityAppManager> : winrt::impl::hash_base<winrt::Windows::UI::Shell::ISecurityAppManager> {};
template<> struct hash<winrt::Windows::UI::Shell::ITaskbarManager> : winrt::impl::hash_base<winrt::Windows::UI::Shell::ITaskbarManager> {};
template<> struct hash<winrt::Windows::UI::Shell::ITaskbarManager2> : winrt::impl::hash_base<winrt::Windows::UI::Shell::ITaskbarManager2> {};
template<> struct hash<winrt::Windows::UI::Shell::ITaskbarManagerStatics> : winrt::impl::hash_base<winrt::Windows::UI::Shell::ITaskbarManagerStatics> {};
template<> struct hash<winrt::Windows::UI::Shell::AdaptiveCardBuilder> : winrt::impl::hash_base<winrt::Windows::UI::Shell::AdaptiveCardBuilder> {};
template<> struct hash<winrt::Windows::UI::Shell::SecurityAppManager> : winrt::impl::hash_base<winrt::Windows::UI::Shell::SecurityAppManager> {};
template<> struct hash<winrt::Windows::UI::Shell::TaskbarManager> : winrt::impl::hash_base<winrt::Windows::UI::Shell::TaskbarManager> {};

}
