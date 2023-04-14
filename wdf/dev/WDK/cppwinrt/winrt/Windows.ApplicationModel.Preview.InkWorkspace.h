// C++/WinRT v1.0.190111.3

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#pragma once

#include "winrt/base.h"

#include "winrt/Windows.Foundation.h"
#include "winrt/Windows.Foundation.Collections.h"
#include "winrt/impl/Windows.Graphics.Imaging.2.h"
#include "winrt/impl/Windows.ApplicationModel.Preview.InkWorkspace.2.h"

namespace winrt::impl {

template <typename D> Windows::Foundation::IAsyncAction consume_Windows_ApplicationModel_Preview_InkWorkspace_IInkWorkspaceHostedAppManager<D>::SetThumbnailAsync(Windows::Graphics::Imaging::SoftwareBitmap const& bitmap) const
{
    Windows::Foundation::IAsyncAction action{ nullptr };
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Preview::InkWorkspace::IInkWorkspaceHostedAppManager)->SetThumbnailAsync(get_abi(bitmap), put_abi(action)));
    return action;
}

template <typename D> Windows::ApplicationModel::Preview::InkWorkspace::InkWorkspaceHostedAppManager consume_Windows_ApplicationModel_Preview_InkWorkspace_IInkWorkspaceHostedAppManagerStatics<D>::GetForCurrentApp() const
{
    Windows::ApplicationModel::Preview::InkWorkspace::InkWorkspaceHostedAppManager current{ nullptr };
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Preview::InkWorkspace::IInkWorkspaceHostedAppManagerStatics)->GetForCurrentApp(put_abi(current)));
    return current;
}

template <typename D>
struct produce<D, Windows::ApplicationModel::Preview::InkWorkspace::IInkWorkspaceHostedAppManager> : produce_base<D, Windows::ApplicationModel::Preview::InkWorkspace::IInkWorkspaceHostedAppManager>
{
    int32_t WINRT_CALL SetThumbnailAsync(void* bitmap, void** action) noexcept final
    {
        try
        {
            *action = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SetThumbnailAsync, WINRT_WRAP(Windows::Foundation::IAsyncAction), Windows::Graphics::Imaging::SoftwareBitmap const);
            *action = detach_from<Windows::Foundation::IAsyncAction>(this->shim().SetThumbnailAsync(*reinterpret_cast<Windows::Graphics::Imaging::SoftwareBitmap const*>(&bitmap)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::ApplicationModel::Preview::InkWorkspace::IInkWorkspaceHostedAppManagerStatics> : produce_base<D, Windows::ApplicationModel::Preview::InkWorkspace::IInkWorkspaceHostedAppManagerStatics>
{
    int32_t WINRT_CALL GetForCurrentApp(void** current) noexcept final
    {
        try
        {
            *current = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetForCurrentApp, WINRT_WRAP(Windows::ApplicationModel::Preview::InkWorkspace::InkWorkspaceHostedAppManager));
            *current = detach_from<Windows::ApplicationModel::Preview::InkWorkspace::InkWorkspaceHostedAppManager>(this->shim().GetForCurrentApp());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

}

WINRT_EXPORT namespace winrt::Windows::ApplicationModel::Preview::InkWorkspace {

inline Windows::ApplicationModel::Preview::InkWorkspace::InkWorkspaceHostedAppManager InkWorkspaceHostedAppManager::GetForCurrentApp()
{
    return impl::call_factory<InkWorkspaceHostedAppManager, Windows::ApplicationModel::Preview::InkWorkspace::IInkWorkspaceHostedAppManagerStatics>([&](auto&& f) { return f.GetForCurrentApp(); });
}

}

WINRT_EXPORT namespace std {

template<> struct hash<winrt::Windows::ApplicationModel::Preview::InkWorkspace::IInkWorkspaceHostedAppManager> : winrt::impl::hash_base<winrt::Windows::ApplicationModel::Preview::InkWorkspace::IInkWorkspaceHostedAppManager> {};
template<> struct hash<winrt::Windows::ApplicationModel::Preview::InkWorkspace::IInkWorkspaceHostedAppManagerStatics> : winrt::impl::hash_base<winrt::Windows::ApplicationModel::Preview::InkWorkspace::IInkWorkspaceHostedAppManagerStatics> {};
template<> struct hash<winrt::Windows::ApplicationModel::Preview::InkWorkspace::InkWorkspaceHostedAppManager> : winrt::impl::hash_base<winrt::Windows::ApplicationModel::Preview::InkWorkspace::InkWorkspaceHostedAppManager> {};

}
