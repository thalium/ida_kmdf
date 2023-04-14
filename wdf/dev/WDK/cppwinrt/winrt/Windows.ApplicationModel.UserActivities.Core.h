// C++/WinRT v1.0.190111.3

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#pragma once

#include "winrt/base.h"

#include "winrt/Windows.Foundation.h"
#include "winrt/Windows.Foundation.Collections.h"
#include "winrt/impl/Windows.ApplicationModel.UserActivities.2.h"
#include "winrt/impl/Windows.ApplicationModel.UserActivities.Core.2.h"
#include "winrt/Windows.ApplicationModel.UserActivities.h"

namespace winrt::impl {

template <typename D> Windows::ApplicationModel::UserActivities::UserActivitySession consume_Windows_ApplicationModel_UserActivities_Core_ICoreUserActivityManagerStatics<D>::CreateUserActivitySessionInBackground(Windows::ApplicationModel::UserActivities::UserActivity const& activity) const
{
    Windows::ApplicationModel::UserActivities::UserActivitySession result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::UserActivities::Core::ICoreUserActivityManagerStatics)->CreateUserActivitySessionInBackground(get_abi(activity), put_abi(result)));
    return result;
}

template <typename D> Windows::Foundation::IAsyncAction consume_Windows_ApplicationModel_UserActivities_Core_ICoreUserActivityManagerStatics<D>::DeleteUserActivitySessionsInTimeRangeAsync(Windows::ApplicationModel::UserActivities::UserActivityChannel const& channel, Windows::Foundation::DateTime const& startTime, Windows::Foundation::DateTime const& endTime) const
{
    Windows::Foundation::IAsyncAction operation{ nullptr };
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::UserActivities::Core::ICoreUserActivityManagerStatics)->DeleteUserActivitySessionsInTimeRangeAsync(get_abi(channel), get_abi(startTime), get_abi(endTime), put_abi(operation)));
    return operation;
}

template <typename D>
struct produce<D, Windows::ApplicationModel::UserActivities::Core::ICoreUserActivityManagerStatics> : produce_base<D, Windows::ApplicationModel::UserActivities::Core::ICoreUserActivityManagerStatics>
{
    int32_t WINRT_CALL CreateUserActivitySessionInBackground(void* activity, void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CreateUserActivitySessionInBackground, WINRT_WRAP(Windows::ApplicationModel::UserActivities::UserActivitySession), Windows::ApplicationModel::UserActivities::UserActivity const&);
            *result = detach_from<Windows::ApplicationModel::UserActivities::UserActivitySession>(this->shim().CreateUserActivitySessionInBackground(*reinterpret_cast<Windows::ApplicationModel::UserActivities::UserActivity const*>(&activity)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL DeleteUserActivitySessionsInTimeRangeAsync(void* channel, Windows::Foundation::DateTime startTime, Windows::Foundation::DateTime endTime, void** operation) noexcept final
    {
        try
        {
            *operation = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(DeleteUserActivitySessionsInTimeRangeAsync, WINRT_WRAP(Windows::Foundation::IAsyncAction), Windows::ApplicationModel::UserActivities::UserActivityChannel const, Windows::Foundation::DateTime const, Windows::Foundation::DateTime const);
            *operation = detach_from<Windows::Foundation::IAsyncAction>(this->shim().DeleteUserActivitySessionsInTimeRangeAsync(*reinterpret_cast<Windows::ApplicationModel::UserActivities::UserActivityChannel const*>(&channel), *reinterpret_cast<Windows::Foundation::DateTime const*>(&startTime), *reinterpret_cast<Windows::Foundation::DateTime const*>(&endTime)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

}

WINRT_EXPORT namespace winrt::Windows::ApplicationModel::UserActivities::Core {

inline Windows::ApplicationModel::UserActivities::UserActivitySession CoreUserActivityManager::CreateUserActivitySessionInBackground(Windows::ApplicationModel::UserActivities::UserActivity const& activity)
{
    return impl::call_factory<CoreUserActivityManager, Windows::ApplicationModel::UserActivities::Core::ICoreUserActivityManagerStatics>([&](auto&& f) { return f.CreateUserActivitySessionInBackground(activity); });
}

inline Windows::Foundation::IAsyncAction CoreUserActivityManager::DeleteUserActivitySessionsInTimeRangeAsync(Windows::ApplicationModel::UserActivities::UserActivityChannel const& channel, Windows::Foundation::DateTime const& startTime, Windows::Foundation::DateTime const& endTime)
{
    return impl::call_factory<CoreUserActivityManager, Windows::ApplicationModel::UserActivities::Core::ICoreUserActivityManagerStatics>([&](auto&& f) { return f.DeleteUserActivitySessionsInTimeRangeAsync(channel, startTime, endTime); });
}

}

WINRT_EXPORT namespace std {

template<> struct hash<winrt::Windows::ApplicationModel::UserActivities::Core::ICoreUserActivityManagerStatics> : winrt::impl::hash_base<winrt::Windows::ApplicationModel::UserActivities::Core::ICoreUserActivityManagerStatics> {};
template<> struct hash<winrt::Windows::ApplicationModel::UserActivities::Core::CoreUserActivityManager> : winrt::impl::hash_base<winrt::Windows::ApplicationModel::UserActivities::Core::CoreUserActivityManager> {};

}
