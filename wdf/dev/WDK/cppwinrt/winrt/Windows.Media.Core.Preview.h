// C++/WinRT v1.0.190111.3

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#pragma once

#include "winrt/base.h"

#include "winrt/Windows.Foundation.h"
#include "winrt/Windows.Foundation.Collections.h"
#include "winrt/impl/Windows.Media.2.h"
#include "winrt/impl/Windows.Media.Core.Preview.2.h"
#include "winrt/Windows.Media.Core.h"

namespace winrt::impl {

template <typename D> Windows::Media::SoundLevel consume_Windows_Media_Core_Preview_ISoundLevelBrokerStatics<D>::SoundLevel() const
{
    Windows::Media::SoundLevel value{};
    check_hresult(WINRT_SHIM(Windows::Media::Core::Preview::ISoundLevelBrokerStatics)->get_SoundLevel(put_abi(value)));
    return value;
}

template <typename D> winrt::event_token consume_Windows_Media_Core_Preview_ISoundLevelBrokerStatics<D>::SoundLevelChanged(Windows::Foundation::EventHandler<Windows::Foundation::IInspectable> const& handler) const
{
    winrt::event_token token{};
    check_hresult(WINRT_SHIM(Windows::Media::Core::Preview::ISoundLevelBrokerStatics)->add_SoundLevelChanged(get_abi(handler), put_abi(token)));
    return token;
}

template <typename D> typename consume_Windows_Media_Core_Preview_ISoundLevelBrokerStatics<D>::SoundLevelChanged_revoker consume_Windows_Media_Core_Preview_ISoundLevelBrokerStatics<D>::SoundLevelChanged(auto_revoke_t, Windows::Foundation::EventHandler<Windows::Foundation::IInspectable> const& handler) const
{
    return impl::make_event_revoker<D, SoundLevelChanged_revoker>(this, SoundLevelChanged(handler));
}

template <typename D> void consume_Windows_Media_Core_Preview_ISoundLevelBrokerStatics<D>::SoundLevelChanged(winrt::event_token const& token) const noexcept
{
    WINRT_VERIFY_(0, WINRT_SHIM(Windows::Media::Core::Preview::ISoundLevelBrokerStatics)->remove_SoundLevelChanged(get_abi(token)));
}

template <typename D>
struct produce<D, Windows::Media::Core::Preview::ISoundLevelBrokerStatics> : produce_base<D, Windows::Media::Core::Preview::ISoundLevelBrokerStatics>
{
    int32_t WINRT_CALL get_SoundLevel(Windows::Media::SoundLevel* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SoundLevel, WINRT_WRAP(Windows::Media::SoundLevel));
            *value = detach_from<Windows::Media::SoundLevel>(this->shim().SoundLevel());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL add_SoundLevelChanged(void* handler, winrt::event_token* token) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SoundLevelChanged, WINRT_WRAP(winrt::event_token), Windows::Foundation::EventHandler<Windows::Foundation::IInspectable> const&);
            *token = detach_from<winrt::event_token>(this->shim().SoundLevelChanged(*reinterpret_cast<Windows::Foundation::EventHandler<Windows::Foundation::IInspectable> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL remove_SoundLevelChanged(winrt::event_token token) noexcept final
    {
        typename D::abi_guard guard(this->shim());
        WINRT_ASSERT_DECLARATION(SoundLevelChanged, WINRT_WRAP(void), winrt::event_token const&);
        this->shim().SoundLevelChanged(*reinterpret_cast<winrt::event_token const*>(&token));
        return 0;
    }
};

}

WINRT_EXPORT namespace winrt::Windows::Media::Core::Preview {

inline Windows::Media::SoundLevel SoundLevelBroker::SoundLevel()
{
    return impl::call_factory<SoundLevelBroker, Windows::Media::Core::Preview::ISoundLevelBrokerStatics>([&](auto&& f) { return f.SoundLevel(); });
}

inline winrt::event_token SoundLevelBroker::SoundLevelChanged(Windows::Foundation::EventHandler<Windows::Foundation::IInspectable> const& handler)
{
    return impl::call_factory<SoundLevelBroker, Windows::Media::Core::Preview::ISoundLevelBrokerStatics>([&](auto&& f) { return f.SoundLevelChanged(handler); });
}

inline SoundLevelBroker::SoundLevelChanged_revoker SoundLevelBroker::SoundLevelChanged(auto_revoke_t, Windows::Foundation::EventHandler<Windows::Foundation::IInspectable> const& handler)
{
    auto f = get_activation_factory<SoundLevelBroker, Windows::Media::Core::Preview::ISoundLevelBrokerStatics>();
    return { f, f.SoundLevelChanged(handler) };
}

inline void SoundLevelBroker::SoundLevelChanged(winrt::event_token const& token)
{
    impl::call_factory<SoundLevelBroker, Windows::Media::Core::Preview::ISoundLevelBrokerStatics>([&](auto&& f) { return f.SoundLevelChanged(token); });
}

}

WINRT_EXPORT namespace std {

template<> struct hash<winrt::Windows::Media::Core::Preview::ISoundLevelBrokerStatics> : winrt::impl::hash_base<winrt::Windows::Media::Core::Preview::ISoundLevelBrokerStatics> {};
template<> struct hash<winrt::Windows::Media::Core::Preview::SoundLevelBroker> : winrt::impl::hash_base<winrt::Windows::Media::Core::Preview::SoundLevelBroker> {};

}
