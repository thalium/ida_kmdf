// C++/WinRT v1.0.190111.3

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#pragma once

#include "winrt/base.h"

#include "winrt/Windows.Foundation.h"
#include "winrt/Windows.Foundation.Collections.h"
#include "winrt/impl/Windows.UI.Notifications.2.h"
#include "winrt/impl/Windows.Phone.StartScreen.2.h"

namespace winrt::impl {

template <typename D> void consume_Windows_Phone_StartScreen_IDualSimTile<D>::DisplayName(param::hstring const& value) const
{
    check_hresult(WINRT_SHIM(Windows::Phone::StartScreen::IDualSimTile)->put_DisplayName(get_abi(value)));
}

template <typename D> hstring consume_Windows_Phone_StartScreen_IDualSimTile<D>::DisplayName() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Phone::StartScreen::IDualSimTile)->get_DisplayName(put_abi(value)));
    return value;
}

template <typename D> bool consume_Windows_Phone_StartScreen_IDualSimTile<D>::IsPinnedToStart() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::Phone::StartScreen::IDualSimTile)->get_IsPinnedToStart(&value));
    return value;
}

template <typename D> Windows::Foundation::IAsyncOperation<bool> consume_Windows_Phone_StartScreen_IDualSimTile<D>::CreateAsync() const
{
    Windows::Foundation::IAsyncOperation<bool> operation{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Phone::StartScreen::IDualSimTile)->CreateAsync(put_abi(operation)));
    return operation;
}

template <typename D> Windows::Foundation::IAsyncOperation<bool> consume_Windows_Phone_StartScreen_IDualSimTile<D>::UpdateAsync() const
{
    Windows::Foundation::IAsyncOperation<bool> operation{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Phone::StartScreen::IDualSimTile)->UpdateAsync(put_abi(operation)));
    return operation;
}

template <typename D> Windows::Foundation::IAsyncOperation<bool> consume_Windows_Phone_StartScreen_IDualSimTile<D>::DeleteAsync() const
{
    Windows::Foundation::IAsyncOperation<bool> operation{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Phone::StartScreen::IDualSimTile)->DeleteAsync(put_abi(operation)));
    return operation;
}

template <typename D> Windows::Phone::StartScreen::DualSimTile consume_Windows_Phone_StartScreen_IDualSimTileStatics<D>::GetTileForSim2() const
{
    Windows::Phone::StartScreen::DualSimTile result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Phone::StartScreen::IDualSimTileStatics)->GetTileForSim2(put_abi(result)));
    return result;
}

template <typename D> Windows::Foundation::IAsyncOperation<bool> consume_Windows_Phone_StartScreen_IDualSimTileStatics<D>::UpdateDisplayNameForSim1Async(param::hstring const& name) const
{
    Windows::Foundation::IAsyncOperation<bool> operation{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Phone::StartScreen::IDualSimTileStatics)->UpdateDisplayNameForSim1Async(get_abi(name), put_abi(operation)));
    return operation;
}

template <typename D> Windows::UI::Notifications::TileUpdater consume_Windows_Phone_StartScreen_IDualSimTileStatics<D>::CreateTileUpdaterForSim1() const
{
    Windows::UI::Notifications::TileUpdater updater{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Phone::StartScreen::IDualSimTileStatics)->CreateTileUpdaterForSim1(put_abi(updater)));
    return updater;
}

template <typename D> Windows::UI::Notifications::TileUpdater consume_Windows_Phone_StartScreen_IDualSimTileStatics<D>::CreateTileUpdaterForSim2() const
{
    Windows::UI::Notifications::TileUpdater updater{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Phone::StartScreen::IDualSimTileStatics)->CreateTileUpdaterForSim2(put_abi(updater)));
    return updater;
}

template <typename D> Windows::UI::Notifications::BadgeUpdater consume_Windows_Phone_StartScreen_IDualSimTileStatics<D>::CreateBadgeUpdaterForSim1() const
{
    Windows::UI::Notifications::BadgeUpdater updater{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Phone::StartScreen::IDualSimTileStatics)->CreateBadgeUpdaterForSim1(put_abi(updater)));
    return updater;
}

template <typename D> Windows::UI::Notifications::BadgeUpdater consume_Windows_Phone_StartScreen_IDualSimTileStatics<D>::CreateBadgeUpdaterForSim2() const
{
    Windows::UI::Notifications::BadgeUpdater updater{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Phone::StartScreen::IDualSimTileStatics)->CreateBadgeUpdaterForSim2(put_abi(updater)));
    return updater;
}

template <typename D> Windows::UI::Notifications::ToastNotifier consume_Windows_Phone_StartScreen_IDualSimTileStatics<D>::CreateToastNotifierForSim1() const
{
    Windows::UI::Notifications::ToastNotifier notifier{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Phone::StartScreen::IDualSimTileStatics)->CreateToastNotifierForSim1(put_abi(notifier)));
    return notifier;
}

template <typename D> Windows::UI::Notifications::ToastNotifier consume_Windows_Phone_StartScreen_IDualSimTileStatics<D>::CreateToastNotifierForSim2() const
{
    Windows::UI::Notifications::ToastNotifier notifier{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Phone::StartScreen::IDualSimTileStatics)->CreateToastNotifierForSim2(put_abi(notifier)));
    return notifier;
}

template <typename D> Windows::UI::Notifications::ToastNotifier consume_Windows_Phone_StartScreen_IToastNotificationManagerStatics3<D>::CreateToastNotifierForSecondaryTile(param::hstring const& tileId) const
{
    Windows::UI::Notifications::ToastNotifier notifier{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Phone::StartScreen::IToastNotificationManagerStatics3)->CreateToastNotifierForSecondaryTile(get_abi(tileId), put_abi(notifier)));
    return notifier;
}

template <typename D>
struct produce<D, Windows::Phone::StartScreen::IDualSimTile> : produce_base<D, Windows::Phone::StartScreen::IDualSimTile>
{
    int32_t WINRT_CALL put_DisplayName(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(DisplayName, WINRT_WRAP(void), hstring const&);
            this->shim().DisplayName(*reinterpret_cast<hstring const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_DisplayName(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(DisplayName, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().DisplayName());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_IsPinnedToStart(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IsPinnedToStart, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().IsPinnedToStart());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL CreateAsync(void** operation) noexcept final
    {
        try
        {
            *operation = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CreateAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<bool>));
            *operation = detach_from<Windows::Foundation::IAsyncOperation<bool>>(this->shim().CreateAsync());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL UpdateAsync(void** operation) noexcept final
    {
        try
        {
            *operation = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(UpdateAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<bool>));
            *operation = detach_from<Windows::Foundation::IAsyncOperation<bool>>(this->shim().UpdateAsync());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL DeleteAsync(void** operation) noexcept final
    {
        try
        {
            *operation = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(DeleteAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<bool>));
            *operation = detach_from<Windows::Foundation::IAsyncOperation<bool>>(this->shim().DeleteAsync());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Phone::StartScreen::IDualSimTileStatics> : produce_base<D, Windows::Phone::StartScreen::IDualSimTileStatics>
{
    int32_t WINRT_CALL GetTileForSim2(void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetTileForSim2, WINRT_WRAP(Windows::Phone::StartScreen::DualSimTile));
            *result = detach_from<Windows::Phone::StartScreen::DualSimTile>(this->shim().GetTileForSim2());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL UpdateDisplayNameForSim1Async(void* name, void** operation) noexcept final
    {
        try
        {
            *operation = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(UpdateDisplayNameForSim1Async, WINRT_WRAP(Windows::Foundation::IAsyncOperation<bool>), hstring const);
            *operation = detach_from<Windows::Foundation::IAsyncOperation<bool>>(this->shim().UpdateDisplayNameForSim1Async(*reinterpret_cast<hstring const*>(&name)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL CreateTileUpdaterForSim1(void** updater) noexcept final
    {
        try
        {
            *updater = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CreateTileUpdaterForSim1, WINRT_WRAP(Windows::UI::Notifications::TileUpdater));
            *updater = detach_from<Windows::UI::Notifications::TileUpdater>(this->shim().CreateTileUpdaterForSim1());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL CreateTileUpdaterForSim2(void** updater) noexcept final
    {
        try
        {
            *updater = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CreateTileUpdaterForSim2, WINRT_WRAP(Windows::UI::Notifications::TileUpdater));
            *updater = detach_from<Windows::UI::Notifications::TileUpdater>(this->shim().CreateTileUpdaterForSim2());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL CreateBadgeUpdaterForSim1(void** updater) noexcept final
    {
        try
        {
            *updater = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CreateBadgeUpdaterForSim1, WINRT_WRAP(Windows::UI::Notifications::BadgeUpdater));
            *updater = detach_from<Windows::UI::Notifications::BadgeUpdater>(this->shim().CreateBadgeUpdaterForSim1());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL CreateBadgeUpdaterForSim2(void** updater) noexcept final
    {
        try
        {
            *updater = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CreateBadgeUpdaterForSim2, WINRT_WRAP(Windows::UI::Notifications::BadgeUpdater));
            *updater = detach_from<Windows::UI::Notifications::BadgeUpdater>(this->shim().CreateBadgeUpdaterForSim2());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL CreateToastNotifierForSim1(void** notifier) noexcept final
    {
        try
        {
            *notifier = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CreateToastNotifierForSim1, WINRT_WRAP(Windows::UI::Notifications::ToastNotifier));
            *notifier = detach_from<Windows::UI::Notifications::ToastNotifier>(this->shim().CreateToastNotifierForSim1());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL CreateToastNotifierForSim2(void** notifier) noexcept final
    {
        try
        {
            *notifier = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CreateToastNotifierForSim2, WINRT_WRAP(Windows::UI::Notifications::ToastNotifier));
            *notifier = detach_from<Windows::UI::Notifications::ToastNotifier>(this->shim().CreateToastNotifierForSim2());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Phone::StartScreen::IToastNotificationManagerStatics3> : produce_base<D, Windows::Phone::StartScreen::IToastNotificationManagerStatics3>
{
    int32_t WINRT_CALL CreateToastNotifierForSecondaryTile(void* tileId, void** notifier) noexcept final
    {
        try
        {
            *notifier = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CreateToastNotifierForSecondaryTile, WINRT_WRAP(Windows::UI::Notifications::ToastNotifier), hstring const&);
            *notifier = detach_from<Windows::UI::Notifications::ToastNotifier>(this->shim().CreateToastNotifierForSecondaryTile(*reinterpret_cast<hstring const*>(&tileId)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

}

WINRT_EXPORT namespace winrt::Windows::Phone::StartScreen {

inline DualSimTile::DualSimTile() :
    DualSimTile(impl::call_factory<DualSimTile>([](auto&& f) { return f.template ActivateInstance<DualSimTile>(); }))
{}

inline Windows::Phone::StartScreen::DualSimTile DualSimTile::GetTileForSim2()
{
    return impl::call_factory<DualSimTile, Windows::Phone::StartScreen::IDualSimTileStatics>([&](auto&& f) { return f.GetTileForSim2(); });
}

inline Windows::Foundation::IAsyncOperation<bool> DualSimTile::UpdateDisplayNameForSim1Async(param::hstring const& name)
{
    return impl::call_factory<DualSimTile, Windows::Phone::StartScreen::IDualSimTileStatics>([&](auto&& f) { return f.UpdateDisplayNameForSim1Async(name); });
}

inline Windows::UI::Notifications::TileUpdater DualSimTile::CreateTileUpdaterForSim1()
{
    return impl::call_factory<DualSimTile, Windows::Phone::StartScreen::IDualSimTileStatics>([&](auto&& f) { return f.CreateTileUpdaterForSim1(); });
}

inline Windows::UI::Notifications::TileUpdater DualSimTile::CreateTileUpdaterForSim2()
{
    return impl::call_factory<DualSimTile, Windows::Phone::StartScreen::IDualSimTileStatics>([&](auto&& f) { return f.CreateTileUpdaterForSim2(); });
}

inline Windows::UI::Notifications::BadgeUpdater DualSimTile::CreateBadgeUpdaterForSim1()
{
    return impl::call_factory<DualSimTile, Windows::Phone::StartScreen::IDualSimTileStatics>([&](auto&& f) { return f.CreateBadgeUpdaterForSim1(); });
}

inline Windows::UI::Notifications::BadgeUpdater DualSimTile::CreateBadgeUpdaterForSim2()
{
    return impl::call_factory<DualSimTile, Windows::Phone::StartScreen::IDualSimTileStatics>([&](auto&& f) { return f.CreateBadgeUpdaterForSim2(); });
}

inline Windows::UI::Notifications::ToastNotifier DualSimTile::CreateToastNotifierForSim1()
{
    return impl::call_factory<DualSimTile, Windows::Phone::StartScreen::IDualSimTileStatics>([&](auto&& f) { return f.CreateToastNotifierForSim1(); });
}

inline Windows::UI::Notifications::ToastNotifier DualSimTile::CreateToastNotifierForSim2()
{
    return impl::call_factory<DualSimTile, Windows::Phone::StartScreen::IDualSimTileStatics>([&](auto&& f) { return f.CreateToastNotifierForSim2(); });
}

}

WINRT_EXPORT namespace std {

template<> struct hash<winrt::Windows::Phone::StartScreen::IDualSimTile> : winrt::impl::hash_base<winrt::Windows::Phone::StartScreen::IDualSimTile> {};
template<> struct hash<winrt::Windows::Phone::StartScreen::IDualSimTileStatics> : winrt::impl::hash_base<winrt::Windows::Phone::StartScreen::IDualSimTileStatics> {};
template<> struct hash<winrt::Windows::Phone::StartScreen::IToastNotificationManagerStatics3> : winrt::impl::hash_base<winrt::Windows::Phone::StartScreen::IToastNotificationManagerStatics3> {};
template<> struct hash<winrt::Windows::Phone::StartScreen::DualSimTile> : winrt::impl::hash_base<winrt::Windows::Phone::StartScreen::DualSimTile> {};

}
