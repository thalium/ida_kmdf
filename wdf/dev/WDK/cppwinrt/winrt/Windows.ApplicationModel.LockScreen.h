// C++/WinRT v1.0.190111.3

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#pragma once

#include "winrt/base.h"

#include "winrt/Windows.Foundation.h"
#include "winrt/Windows.Foundation.Collections.h"
#include "winrt/impl/Windows.Storage.Streams.2.h"
#include "winrt/impl/Windows.ApplicationModel.LockScreen.2.h"
#include "winrt/Windows.ApplicationModel.h"

namespace winrt::impl {

template <typename D> void consume_Windows_ApplicationModel_LockScreen_ILockApplicationHost<D>::RequestUnlock() const
{
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::LockScreen::ILockApplicationHost)->RequestUnlock());
}

template <typename D> winrt::event_token consume_Windows_ApplicationModel_LockScreen_ILockApplicationHost<D>::Unlocking(Windows::Foundation::TypedEventHandler<Windows::ApplicationModel::LockScreen::LockApplicationHost, Windows::ApplicationModel::LockScreen::LockScreenUnlockingEventArgs> const& handler) const
{
    winrt::event_token token{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::LockScreen::ILockApplicationHost)->add_Unlocking(get_abi(handler), put_abi(token)));
    return token;
}

template <typename D> typename consume_Windows_ApplicationModel_LockScreen_ILockApplicationHost<D>::Unlocking_revoker consume_Windows_ApplicationModel_LockScreen_ILockApplicationHost<D>::Unlocking(auto_revoke_t, Windows::Foundation::TypedEventHandler<Windows::ApplicationModel::LockScreen::LockApplicationHost, Windows::ApplicationModel::LockScreen::LockScreenUnlockingEventArgs> const& handler) const
{
    return impl::make_event_revoker<D, Unlocking_revoker>(this, Unlocking(handler));
}

template <typename D> void consume_Windows_ApplicationModel_LockScreen_ILockApplicationHost<D>::Unlocking(winrt::event_token const& token) const noexcept
{
    WINRT_VERIFY_(0, WINRT_SHIM(Windows::ApplicationModel::LockScreen::ILockApplicationHost)->remove_Unlocking(get_abi(token)));
}

template <typename D> Windows::ApplicationModel::LockScreen::LockApplicationHost consume_Windows_ApplicationModel_LockScreen_ILockApplicationHostStatics<D>::GetForCurrentView() const
{
    Windows::ApplicationModel::LockScreen::LockApplicationHost result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::LockScreen::ILockApplicationHostStatics)->GetForCurrentView(put_abi(result)));
    return result;
}

template <typename D> Windows::Storage::Streams::IRandomAccessStream consume_Windows_ApplicationModel_LockScreen_ILockScreenBadge<D>::Logo() const
{
    Windows::Storage::Streams::IRandomAccessStream value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::LockScreen::ILockScreenBadge)->get_Logo(put_abi(value)));
    return value;
}

template <typename D> Windows::Storage::Streams::IRandomAccessStream consume_Windows_ApplicationModel_LockScreen_ILockScreenBadge<D>::Glyph() const
{
    Windows::Storage::Streams::IRandomAccessStream value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::LockScreen::ILockScreenBadge)->get_Glyph(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::IReference<uint32_t> consume_Windows_ApplicationModel_LockScreen_ILockScreenBadge<D>::Number() const
{
    Windows::Foundation::IReference<uint32_t> value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::LockScreen::ILockScreenBadge)->get_Number(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_ApplicationModel_LockScreen_ILockScreenBadge<D>::AutomationName() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::LockScreen::ILockScreenBadge)->get_AutomationName(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_ApplicationModel_LockScreen_ILockScreenBadge<D>::LaunchApp() const
{
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::LockScreen::ILockScreenBadge)->LaunchApp());
}

template <typename D> winrt::event_token consume_Windows_ApplicationModel_LockScreen_ILockScreenInfo<D>::LockScreenImageChanged(Windows::Foundation::TypedEventHandler<Windows::ApplicationModel::LockScreen::LockScreenInfo, Windows::Foundation::IInspectable> const& handler) const
{
    winrt::event_token token{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::LockScreen::ILockScreenInfo)->add_LockScreenImageChanged(get_abi(handler), put_abi(token)));
    return token;
}

template <typename D> typename consume_Windows_ApplicationModel_LockScreen_ILockScreenInfo<D>::LockScreenImageChanged_revoker consume_Windows_ApplicationModel_LockScreen_ILockScreenInfo<D>::LockScreenImageChanged(auto_revoke_t, Windows::Foundation::TypedEventHandler<Windows::ApplicationModel::LockScreen::LockScreenInfo, Windows::Foundation::IInspectable> const& handler) const
{
    return impl::make_event_revoker<D, LockScreenImageChanged_revoker>(this, LockScreenImageChanged(handler));
}

template <typename D> void consume_Windows_ApplicationModel_LockScreen_ILockScreenInfo<D>::LockScreenImageChanged(winrt::event_token const& token) const noexcept
{
    WINRT_VERIFY_(0, WINRT_SHIM(Windows::ApplicationModel::LockScreen::ILockScreenInfo)->remove_LockScreenImageChanged(get_abi(token)));
}

template <typename D> Windows::Storage::Streams::IRandomAccessStream consume_Windows_ApplicationModel_LockScreen_ILockScreenInfo<D>::LockScreenImage() const
{
    Windows::Storage::Streams::IRandomAccessStream value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::LockScreen::ILockScreenInfo)->get_LockScreenImage(put_abi(value)));
    return value;
}

template <typename D> winrt::event_token consume_Windows_ApplicationModel_LockScreen_ILockScreenInfo<D>::BadgesChanged(Windows::Foundation::TypedEventHandler<Windows::ApplicationModel::LockScreen::LockScreenInfo, Windows::Foundation::IInspectable> const& handler) const
{
    winrt::event_token token{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::LockScreen::ILockScreenInfo)->add_BadgesChanged(get_abi(handler), put_abi(token)));
    return token;
}

template <typename D> typename consume_Windows_ApplicationModel_LockScreen_ILockScreenInfo<D>::BadgesChanged_revoker consume_Windows_ApplicationModel_LockScreen_ILockScreenInfo<D>::BadgesChanged(auto_revoke_t, Windows::Foundation::TypedEventHandler<Windows::ApplicationModel::LockScreen::LockScreenInfo, Windows::Foundation::IInspectable> const& handler) const
{
    return impl::make_event_revoker<D, BadgesChanged_revoker>(this, BadgesChanged(handler));
}

template <typename D> void consume_Windows_ApplicationModel_LockScreen_ILockScreenInfo<D>::BadgesChanged(winrt::event_token const& token) const noexcept
{
    WINRT_VERIFY_(0, WINRT_SHIM(Windows::ApplicationModel::LockScreen::ILockScreenInfo)->remove_BadgesChanged(get_abi(token)));
}

template <typename D> Windows::Foundation::Collections::IVectorView<Windows::ApplicationModel::LockScreen::LockScreenBadge> consume_Windows_ApplicationModel_LockScreen_ILockScreenInfo<D>::Badges() const
{
    Windows::Foundation::Collections::IVectorView<Windows::ApplicationModel::LockScreen::LockScreenBadge> value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::LockScreen::ILockScreenInfo)->get_Badges(put_abi(value)));
    return value;
}

template <typename D> winrt::event_token consume_Windows_ApplicationModel_LockScreen_ILockScreenInfo<D>::DetailTextChanged(Windows::Foundation::TypedEventHandler<Windows::ApplicationModel::LockScreen::LockScreenInfo, Windows::Foundation::IInspectable> const& handler) const
{
    winrt::event_token token{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::LockScreen::ILockScreenInfo)->add_DetailTextChanged(get_abi(handler), put_abi(token)));
    return token;
}

template <typename D> typename consume_Windows_ApplicationModel_LockScreen_ILockScreenInfo<D>::DetailTextChanged_revoker consume_Windows_ApplicationModel_LockScreen_ILockScreenInfo<D>::DetailTextChanged(auto_revoke_t, Windows::Foundation::TypedEventHandler<Windows::ApplicationModel::LockScreen::LockScreenInfo, Windows::Foundation::IInspectable> const& handler) const
{
    return impl::make_event_revoker<D, DetailTextChanged_revoker>(this, DetailTextChanged(handler));
}

template <typename D> void consume_Windows_ApplicationModel_LockScreen_ILockScreenInfo<D>::DetailTextChanged(winrt::event_token const& token) const noexcept
{
    WINRT_VERIFY_(0, WINRT_SHIM(Windows::ApplicationModel::LockScreen::ILockScreenInfo)->remove_DetailTextChanged(get_abi(token)));
}

template <typename D> Windows::Foundation::Collections::IVectorView<hstring> consume_Windows_ApplicationModel_LockScreen_ILockScreenInfo<D>::DetailText() const
{
    Windows::Foundation::Collections::IVectorView<hstring> value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::LockScreen::ILockScreenInfo)->get_DetailText(put_abi(value)));
    return value;
}

template <typename D> winrt::event_token consume_Windows_ApplicationModel_LockScreen_ILockScreenInfo<D>::AlarmIconChanged(Windows::Foundation::TypedEventHandler<Windows::ApplicationModel::LockScreen::LockScreenInfo, Windows::Foundation::IInspectable> const& handler) const
{
    winrt::event_token token{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::LockScreen::ILockScreenInfo)->add_AlarmIconChanged(get_abi(handler), put_abi(token)));
    return token;
}

template <typename D> typename consume_Windows_ApplicationModel_LockScreen_ILockScreenInfo<D>::AlarmIconChanged_revoker consume_Windows_ApplicationModel_LockScreen_ILockScreenInfo<D>::AlarmIconChanged(auto_revoke_t, Windows::Foundation::TypedEventHandler<Windows::ApplicationModel::LockScreen::LockScreenInfo, Windows::Foundation::IInspectable> const& handler) const
{
    return impl::make_event_revoker<D, AlarmIconChanged_revoker>(this, AlarmIconChanged(handler));
}

template <typename D> void consume_Windows_ApplicationModel_LockScreen_ILockScreenInfo<D>::AlarmIconChanged(winrt::event_token const& token) const noexcept
{
    WINRT_VERIFY_(0, WINRT_SHIM(Windows::ApplicationModel::LockScreen::ILockScreenInfo)->remove_AlarmIconChanged(get_abi(token)));
}

template <typename D> Windows::Storage::Streams::IRandomAccessStream consume_Windows_ApplicationModel_LockScreen_ILockScreenInfo<D>::AlarmIcon() const
{
    Windows::Storage::Streams::IRandomAccessStream value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::LockScreen::ILockScreenInfo)->get_AlarmIcon(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_ApplicationModel_LockScreen_ILockScreenUnlockingDeferral<D>::Complete() const
{
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::LockScreen::ILockScreenUnlockingDeferral)->Complete());
}

template <typename D> Windows::ApplicationModel::LockScreen::LockScreenUnlockingDeferral consume_Windows_ApplicationModel_LockScreen_ILockScreenUnlockingEventArgs<D>::GetDeferral() const
{
    Windows::ApplicationModel::LockScreen::LockScreenUnlockingDeferral deferral{ nullptr };
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::LockScreen::ILockScreenUnlockingEventArgs)->GetDeferral(put_abi(deferral)));
    return deferral;
}

template <typename D> Windows::Foundation::DateTime consume_Windows_ApplicationModel_LockScreen_ILockScreenUnlockingEventArgs<D>::Deadline() const
{
    Windows::Foundation::DateTime value{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::LockScreen::ILockScreenUnlockingEventArgs)->get_Deadline(put_abi(value)));
    return value;
}

template <typename D>
struct produce<D, Windows::ApplicationModel::LockScreen::ILockApplicationHost> : produce_base<D, Windows::ApplicationModel::LockScreen::ILockApplicationHost>
{
    int32_t WINRT_CALL RequestUnlock() noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(RequestUnlock, WINRT_WRAP(void));
            this->shim().RequestUnlock();
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL add_Unlocking(void* handler, winrt::event_token* token) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Unlocking, WINRT_WRAP(winrt::event_token), Windows::Foundation::TypedEventHandler<Windows::ApplicationModel::LockScreen::LockApplicationHost, Windows::ApplicationModel::LockScreen::LockScreenUnlockingEventArgs> const&);
            *token = detach_from<winrt::event_token>(this->shim().Unlocking(*reinterpret_cast<Windows::Foundation::TypedEventHandler<Windows::ApplicationModel::LockScreen::LockApplicationHost, Windows::ApplicationModel::LockScreen::LockScreenUnlockingEventArgs> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL remove_Unlocking(winrt::event_token token) noexcept final
    {
        typename D::abi_guard guard(this->shim());
        WINRT_ASSERT_DECLARATION(Unlocking, WINRT_WRAP(void), winrt::event_token const&);
        this->shim().Unlocking(*reinterpret_cast<winrt::event_token const*>(&token));
        return 0;
    }
};

template <typename D>
struct produce<D, Windows::ApplicationModel::LockScreen::ILockApplicationHostStatics> : produce_base<D, Windows::ApplicationModel::LockScreen::ILockApplicationHostStatics>
{
    int32_t WINRT_CALL GetForCurrentView(void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetForCurrentView, WINRT_WRAP(Windows::ApplicationModel::LockScreen::LockApplicationHost));
            *result = detach_from<Windows::ApplicationModel::LockScreen::LockApplicationHost>(this->shim().GetForCurrentView());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::ApplicationModel::LockScreen::ILockScreenBadge> : produce_base<D, Windows::ApplicationModel::LockScreen::ILockScreenBadge>
{
    int32_t WINRT_CALL get_Logo(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Logo, WINRT_WRAP(Windows::Storage::Streams::IRandomAccessStream));
            *value = detach_from<Windows::Storage::Streams::IRandomAccessStream>(this->shim().Logo());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Glyph(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Glyph, WINRT_WRAP(Windows::Storage::Streams::IRandomAccessStream));
            *value = detach_from<Windows::Storage::Streams::IRandomAccessStream>(this->shim().Glyph());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Number(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Number, WINRT_WRAP(Windows::Foundation::IReference<uint32_t>));
            *value = detach_from<Windows::Foundation::IReference<uint32_t>>(this->shim().Number());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_AutomationName(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(AutomationName, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().AutomationName());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL LaunchApp() noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(LaunchApp, WINRT_WRAP(void));
            this->shim().LaunchApp();
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::ApplicationModel::LockScreen::ILockScreenInfo> : produce_base<D, Windows::ApplicationModel::LockScreen::ILockScreenInfo>
{
    int32_t WINRT_CALL add_LockScreenImageChanged(void* handler, winrt::event_token* token) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(LockScreenImageChanged, WINRT_WRAP(winrt::event_token), Windows::Foundation::TypedEventHandler<Windows::ApplicationModel::LockScreen::LockScreenInfo, Windows::Foundation::IInspectable> const&);
            *token = detach_from<winrt::event_token>(this->shim().LockScreenImageChanged(*reinterpret_cast<Windows::Foundation::TypedEventHandler<Windows::ApplicationModel::LockScreen::LockScreenInfo, Windows::Foundation::IInspectable> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL remove_LockScreenImageChanged(winrt::event_token token) noexcept final
    {
        typename D::abi_guard guard(this->shim());
        WINRT_ASSERT_DECLARATION(LockScreenImageChanged, WINRT_WRAP(void), winrt::event_token const&);
        this->shim().LockScreenImageChanged(*reinterpret_cast<winrt::event_token const*>(&token));
        return 0;
    }

    int32_t WINRT_CALL get_LockScreenImage(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(LockScreenImage, WINRT_WRAP(Windows::Storage::Streams::IRandomAccessStream));
            *value = detach_from<Windows::Storage::Streams::IRandomAccessStream>(this->shim().LockScreenImage());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL add_BadgesChanged(void* handler, winrt::event_token* token) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(BadgesChanged, WINRT_WRAP(winrt::event_token), Windows::Foundation::TypedEventHandler<Windows::ApplicationModel::LockScreen::LockScreenInfo, Windows::Foundation::IInspectable> const&);
            *token = detach_from<winrt::event_token>(this->shim().BadgesChanged(*reinterpret_cast<Windows::Foundation::TypedEventHandler<Windows::ApplicationModel::LockScreen::LockScreenInfo, Windows::Foundation::IInspectable> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL remove_BadgesChanged(winrt::event_token token) noexcept final
    {
        typename D::abi_guard guard(this->shim());
        WINRT_ASSERT_DECLARATION(BadgesChanged, WINRT_WRAP(void), winrt::event_token const&);
        this->shim().BadgesChanged(*reinterpret_cast<winrt::event_token const*>(&token));
        return 0;
    }

    int32_t WINRT_CALL get_Badges(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Badges, WINRT_WRAP(Windows::Foundation::Collections::IVectorView<Windows::ApplicationModel::LockScreen::LockScreenBadge>));
            *value = detach_from<Windows::Foundation::Collections::IVectorView<Windows::ApplicationModel::LockScreen::LockScreenBadge>>(this->shim().Badges());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL add_DetailTextChanged(void* handler, winrt::event_token* token) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(DetailTextChanged, WINRT_WRAP(winrt::event_token), Windows::Foundation::TypedEventHandler<Windows::ApplicationModel::LockScreen::LockScreenInfo, Windows::Foundation::IInspectable> const&);
            *token = detach_from<winrt::event_token>(this->shim().DetailTextChanged(*reinterpret_cast<Windows::Foundation::TypedEventHandler<Windows::ApplicationModel::LockScreen::LockScreenInfo, Windows::Foundation::IInspectable> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL remove_DetailTextChanged(winrt::event_token token) noexcept final
    {
        typename D::abi_guard guard(this->shim());
        WINRT_ASSERT_DECLARATION(DetailTextChanged, WINRT_WRAP(void), winrt::event_token const&);
        this->shim().DetailTextChanged(*reinterpret_cast<winrt::event_token const*>(&token));
        return 0;
    }

    int32_t WINRT_CALL get_DetailText(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(DetailText, WINRT_WRAP(Windows::Foundation::Collections::IVectorView<hstring>));
            *value = detach_from<Windows::Foundation::Collections::IVectorView<hstring>>(this->shim().DetailText());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL add_AlarmIconChanged(void* handler, winrt::event_token* token) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(AlarmIconChanged, WINRT_WRAP(winrt::event_token), Windows::Foundation::TypedEventHandler<Windows::ApplicationModel::LockScreen::LockScreenInfo, Windows::Foundation::IInspectable> const&);
            *token = detach_from<winrt::event_token>(this->shim().AlarmIconChanged(*reinterpret_cast<Windows::Foundation::TypedEventHandler<Windows::ApplicationModel::LockScreen::LockScreenInfo, Windows::Foundation::IInspectable> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL remove_AlarmIconChanged(winrt::event_token token) noexcept final
    {
        typename D::abi_guard guard(this->shim());
        WINRT_ASSERT_DECLARATION(AlarmIconChanged, WINRT_WRAP(void), winrt::event_token const&);
        this->shim().AlarmIconChanged(*reinterpret_cast<winrt::event_token const*>(&token));
        return 0;
    }

    int32_t WINRT_CALL get_AlarmIcon(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(AlarmIcon, WINRT_WRAP(Windows::Storage::Streams::IRandomAccessStream));
            *value = detach_from<Windows::Storage::Streams::IRandomAccessStream>(this->shim().AlarmIcon());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::ApplicationModel::LockScreen::ILockScreenUnlockingDeferral> : produce_base<D, Windows::ApplicationModel::LockScreen::ILockScreenUnlockingDeferral>
{
    int32_t WINRT_CALL Complete() noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Complete, WINRT_WRAP(void));
            this->shim().Complete();
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::ApplicationModel::LockScreen::ILockScreenUnlockingEventArgs> : produce_base<D, Windows::ApplicationModel::LockScreen::ILockScreenUnlockingEventArgs>
{
    int32_t WINRT_CALL GetDeferral(void** deferral) noexcept final
    {
        try
        {
            *deferral = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetDeferral, WINRT_WRAP(Windows::ApplicationModel::LockScreen::LockScreenUnlockingDeferral));
            *deferral = detach_from<Windows::ApplicationModel::LockScreen::LockScreenUnlockingDeferral>(this->shim().GetDeferral());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Deadline(Windows::Foundation::DateTime* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Deadline, WINRT_WRAP(Windows::Foundation::DateTime));
            *value = detach_from<Windows::Foundation::DateTime>(this->shim().Deadline());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

}

WINRT_EXPORT namespace winrt::Windows::ApplicationModel::LockScreen {

inline Windows::ApplicationModel::LockScreen::LockApplicationHost LockApplicationHost::GetForCurrentView()
{
    return impl::call_factory<LockApplicationHost, Windows::ApplicationModel::LockScreen::ILockApplicationHostStatics>([&](auto&& f) { return f.GetForCurrentView(); });
}

}

WINRT_EXPORT namespace std {

template<> struct hash<winrt::Windows::ApplicationModel::LockScreen::ILockApplicationHost> : winrt::impl::hash_base<winrt::Windows::ApplicationModel::LockScreen::ILockApplicationHost> {};
template<> struct hash<winrt::Windows::ApplicationModel::LockScreen::ILockApplicationHostStatics> : winrt::impl::hash_base<winrt::Windows::ApplicationModel::LockScreen::ILockApplicationHostStatics> {};
template<> struct hash<winrt::Windows::ApplicationModel::LockScreen::ILockScreenBadge> : winrt::impl::hash_base<winrt::Windows::ApplicationModel::LockScreen::ILockScreenBadge> {};
template<> struct hash<winrt::Windows::ApplicationModel::LockScreen::ILockScreenInfo> : winrt::impl::hash_base<winrt::Windows::ApplicationModel::LockScreen::ILockScreenInfo> {};
template<> struct hash<winrt::Windows::ApplicationModel::LockScreen::ILockScreenUnlockingDeferral> : winrt::impl::hash_base<winrt::Windows::ApplicationModel::LockScreen::ILockScreenUnlockingDeferral> {};
template<> struct hash<winrt::Windows::ApplicationModel::LockScreen::ILockScreenUnlockingEventArgs> : winrt::impl::hash_base<winrt::Windows::ApplicationModel::LockScreen::ILockScreenUnlockingEventArgs> {};
template<> struct hash<winrt::Windows::ApplicationModel::LockScreen::LockApplicationHost> : winrt::impl::hash_base<winrt::Windows::ApplicationModel::LockScreen::LockApplicationHost> {};
template<> struct hash<winrt::Windows::ApplicationModel::LockScreen::LockScreenBadge> : winrt::impl::hash_base<winrt::Windows::ApplicationModel::LockScreen::LockScreenBadge> {};
template<> struct hash<winrt::Windows::ApplicationModel::LockScreen::LockScreenInfo> : winrt::impl::hash_base<winrt::Windows::ApplicationModel::LockScreen::LockScreenInfo> {};
template<> struct hash<winrt::Windows::ApplicationModel::LockScreen::LockScreenUnlockingDeferral> : winrt::impl::hash_base<winrt::Windows::ApplicationModel::LockScreen::LockScreenUnlockingDeferral> {};
template<> struct hash<winrt::Windows::ApplicationModel::LockScreen::LockScreenUnlockingEventArgs> : winrt::impl::hash_base<winrt::Windows::ApplicationModel::LockScreen::LockScreenUnlockingEventArgs> {};

}
