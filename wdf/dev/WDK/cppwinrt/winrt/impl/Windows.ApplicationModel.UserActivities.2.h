// C++/WinRT v1.0.190111.3

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#pragma once
#include "winrt/impl/Windows.Foundation.1.h"
#include "winrt/impl/Windows.Security.Credentials.1.h"
#include "winrt/impl/Windows.System.1.h"
#include "winrt/impl/Windows.UI.1.h"
#include "winrt/impl/Windows.UI.Shell.1.h"
#include "winrt/impl/Windows.ApplicationModel.UserActivities.1.h"

WINRT_EXPORT namespace winrt::Windows::ApplicationModel::UserActivities {

}

namespace winrt::impl {

}

WINRT_EXPORT namespace winrt::Windows::ApplicationModel::UserActivities {

struct WINRT_EBO UserActivity :
    Windows::ApplicationModel::UserActivities::IUserActivity,
    impl::require<UserActivity, Windows::ApplicationModel::UserActivities::IUserActivity2, Windows::ApplicationModel::UserActivities::IUserActivity3>
{
    UserActivity(std::nullptr_t) noexcept {}
    UserActivity(param::hstring const& activityId);
    static Windows::ApplicationModel::UserActivities::UserActivity TryParseFromJson(param::hstring const& json);
    static Windows::Foundation::Collections::IVector<Windows::ApplicationModel::UserActivities::UserActivity> TryParseFromJsonArray(param::hstring const& json);
    static hstring ToJsonArray(param::iterable<Windows::ApplicationModel::UserActivities::UserActivity> const& activities);
};

struct WINRT_EBO UserActivityAttribution :
    Windows::ApplicationModel::UserActivities::IUserActivityAttribution
{
    UserActivityAttribution(std::nullptr_t) noexcept {}
    UserActivityAttribution();
    UserActivityAttribution(Windows::Foundation::Uri const& iconUri);
};

struct WINRT_EBO UserActivityChannel :
    Windows::ApplicationModel::UserActivities::IUserActivityChannel,
    impl::require<UserActivityChannel, Windows::ApplicationModel::UserActivities::IUserActivityChannel2>
{
    UserActivityChannel(std::nullptr_t) noexcept {}
    static Windows::ApplicationModel::UserActivities::UserActivityChannel GetDefault();
    static void DisableAutoSessionCreation();
    static Windows::ApplicationModel::UserActivities::UserActivityChannel TryGetForWebAccount(Windows::Security::Credentials::WebAccount const& account);
    static Windows::ApplicationModel::UserActivities::UserActivityChannel GetForUser(Windows::System::User const& user);
};

struct WINRT_EBO UserActivityContentInfo :
    Windows::ApplicationModel::UserActivities::IUserActivityContentInfo
{
    UserActivityContentInfo(std::nullptr_t) noexcept {}
    static Windows::ApplicationModel::UserActivities::UserActivityContentInfo FromJson(param::hstring const& value);
};

struct WINRT_EBO UserActivityRequest :
    Windows::ApplicationModel::UserActivities::IUserActivityRequest
{
    UserActivityRequest(std::nullptr_t) noexcept {}
};

struct WINRT_EBO UserActivityRequestManager :
    Windows::ApplicationModel::UserActivities::IUserActivityRequestManager
{
    UserActivityRequestManager(std::nullptr_t) noexcept {}
    static Windows::ApplicationModel::UserActivities::UserActivityRequestManager GetForCurrentView();
};

struct WINRT_EBO UserActivityRequestedEventArgs :
    Windows::ApplicationModel::UserActivities::IUserActivityRequestedEventArgs
{
    UserActivityRequestedEventArgs(std::nullptr_t) noexcept {}
};

struct WINRT_EBO UserActivitySession :
    Windows::ApplicationModel::UserActivities::IUserActivitySession,
    impl::require<UserActivitySession, Windows::Foundation::IClosable>
{
    UserActivitySession(std::nullptr_t) noexcept {}
};

struct WINRT_EBO UserActivitySessionHistoryItem :
    Windows::ApplicationModel::UserActivities::IUserActivitySessionHistoryItem
{
    UserActivitySessionHistoryItem(std::nullptr_t) noexcept {}
};

struct WINRT_EBO UserActivityVisualElements :
    Windows::ApplicationModel::UserActivities::IUserActivityVisualElements,
    impl::require<UserActivityVisualElements, Windows::ApplicationModel::UserActivities::IUserActivityVisualElements2>
{
    UserActivityVisualElements(std::nullptr_t) noexcept {}
};

}
