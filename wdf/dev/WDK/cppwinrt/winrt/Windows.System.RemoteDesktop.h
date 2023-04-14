// C++/WinRT v1.0.190111.3

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#pragma once

#include "winrt/base.h"

#include "winrt/Windows.Foundation.h"
#include "winrt/Windows.Foundation.Collections.h"
#include "winrt/impl/Windows.System.RemoteDesktop.2.h"
#include "winrt/Windows.System.h"

namespace winrt::impl {

template <typename D> bool consume_Windows_System_RemoteDesktop_IInteractiveSessionStatics<D>::IsRemote() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::System::RemoteDesktop::IInteractiveSessionStatics)->get_IsRemote(&value));
    return value;
}

template <typename D>
struct produce<D, Windows::System::RemoteDesktop::IInteractiveSessionStatics> : produce_base<D, Windows::System::RemoteDesktop::IInteractiveSessionStatics>
{
    int32_t WINRT_CALL get_IsRemote(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IsRemote, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().IsRemote());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

}

WINRT_EXPORT namespace winrt::Windows::System::RemoteDesktop {

inline bool InteractiveSession::IsRemote()
{
    return impl::call_factory<InteractiveSession, Windows::System::RemoteDesktop::IInteractiveSessionStatics>([&](auto&& f) { return f.IsRemote(); });
}

}

WINRT_EXPORT namespace std {

template<> struct hash<winrt::Windows::System::RemoteDesktop::IInteractiveSessionStatics> : winrt::impl::hash_base<winrt::Windows::System::RemoteDesktop::IInteractiveSessionStatics> {};
template<> struct hash<winrt::Windows::System::RemoteDesktop::InteractiveSession> : winrt::impl::hash_base<winrt::Windows::System::RemoteDesktop::InteractiveSession> {};

}
