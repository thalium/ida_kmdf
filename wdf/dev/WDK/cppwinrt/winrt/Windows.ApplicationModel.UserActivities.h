// C++/WinRT v1.0.190111.3

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#pragma once

#include "winrt/base.h"

#include "winrt/Windows.Foundation.h"
#include "winrt/Windows.Foundation.Collections.h"
#include "winrt/impl/Windows.Foundation.2.h"
#include "winrt/impl/Windows.Security.Credentials.2.h"
#include "winrt/impl/Windows.System.2.h"
#include "winrt/impl/Windows.UI.2.h"
#include "winrt/impl/Windows.UI.Shell.2.h"
#include "winrt/impl/Windows.ApplicationModel.UserActivities.2.h"
#include "winrt/Windows.ApplicationModel.h"

namespace winrt::impl {

template <typename D> Windows::ApplicationModel::UserActivities::UserActivityState consume_Windows_ApplicationModel_UserActivities_IUserActivity<D>::State() const
{
    Windows::ApplicationModel::UserActivities::UserActivityState value{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::UserActivities::IUserActivity)->get_State(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_ApplicationModel_UserActivities_IUserActivity<D>::ActivityId() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::UserActivities::IUserActivity)->get_ActivityId(put_abi(value)));
    return value;
}

template <typename D> Windows::ApplicationModel::UserActivities::UserActivityVisualElements consume_Windows_ApplicationModel_UserActivities_IUserActivity<D>::VisualElements() const
{
    Windows::ApplicationModel::UserActivities::UserActivityVisualElements value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::UserActivities::IUserActivity)->get_VisualElements(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::Uri consume_Windows_ApplicationModel_UserActivities_IUserActivity<D>::ContentUri() const
{
    Windows::Foundation::Uri value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::UserActivities::IUserActivity)->get_ContentUri(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_ApplicationModel_UserActivities_IUserActivity<D>::ContentUri(Windows::Foundation::Uri const& value) const
{
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::UserActivities::IUserActivity)->put_ContentUri(get_abi(value)));
}

template <typename D> hstring consume_Windows_ApplicationModel_UserActivities_IUserActivity<D>::ContentType() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::UserActivities::IUserActivity)->get_ContentType(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_ApplicationModel_UserActivities_IUserActivity<D>::ContentType(param::hstring const& value) const
{
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::UserActivities::IUserActivity)->put_ContentType(get_abi(value)));
}

template <typename D> Windows::Foundation::Uri consume_Windows_ApplicationModel_UserActivities_IUserActivity<D>::FallbackUri() const
{
    Windows::Foundation::Uri value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::UserActivities::IUserActivity)->get_FallbackUri(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_ApplicationModel_UserActivities_IUserActivity<D>::FallbackUri(Windows::Foundation::Uri const& value) const
{
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::UserActivities::IUserActivity)->put_FallbackUri(get_abi(value)));
}

template <typename D> Windows::Foundation::Uri consume_Windows_ApplicationModel_UserActivities_IUserActivity<D>::ActivationUri() const
{
    Windows::Foundation::Uri value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::UserActivities::IUserActivity)->get_ActivationUri(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_ApplicationModel_UserActivities_IUserActivity<D>::ActivationUri(Windows::Foundation::Uri const& value) const
{
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::UserActivities::IUserActivity)->put_ActivationUri(get_abi(value)));
}

template <typename D> Windows::ApplicationModel::UserActivities::IUserActivityContentInfo consume_Windows_ApplicationModel_UserActivities_IUserActivity<D>::ContentInfo() const
{
    Windows::ApplicationModel::UserActivities::IUserActivityContentInfo value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::UserActivities::IUserActivity)->get_ContentInfo(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_ApplicationModel_UserActivities_IUserActivity<D>::ContentInfo(Windows::ApplicationModel::UserActivities::IUserActivityContentInfo const& value) const
{
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::UserActivities::IUserActivity)->put_ContentInfo(get_abi(value)));
}

template <typename D> Windows::Foundation::IAsyncAction consume_Windows_ApplicationModel_UserActivities_IUserActivity<D>::SaveAsync() const
{
    Windows::Foundation::IAsyncAction operation{ nullptr };
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::UserActivities::IUserActivity)->SaveAsync(put_abi(operation)));
    return operation;
}

template <typename D> Windows::ApplicationModel::UserActivities::UserActivitySession consume_Windows_ApplicationModel_UserActivities_IUserActivity<D>::CreateSession() const
{
    Windows::ApplicationModel::UserActivities::UserActivitySession result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::UserActivities::IUserActivity)->CreateSession(put_abi(result)));
    return result;
}

template <typename D> hstring consume_Windows_ApplicationModel_UserActivities_IUserActivity2<D>::ToJson() const
{
    hstring result{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::UserActivities::IUserActivity2)->ToJson(put_abi(result)));
    return result;
}

template <typename D> bool consume_Windows_ApplicationModel_UserActivities_IUserActivity3<D>::IsRoamable() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::UserActivities::IUserActivity3)->get_IsRoamable(&value));
    return value;
}

template <typename D> void consume_Windows_ApplicationModel_UserActivities_IUserActivity3<D>::IsRoamable(bool value) const
{
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::UserActivities::IUserActivity3)->put_IsRoamable(value));
}

template <typename D> Windows::Foundation::Uri consume_Windows_ApplicationModel_UserActivities_IUserActivityAttribution<D>::IconUri() const
{
    Windows::Foundation::Uri value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::UserActivities::IUserActivityAttribution)->get_IconUri(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_ApplicationModel_UserActivities_IUserActivityAttribution<D>::IconUri(Windows::Foundation::Uri const& value) const
{
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::UserActivities::IUserActivityAttribution)->put_IconUri(get_abi(value)));
}

template <typename D> hstring consume_Windows_ApplicationModel_UserActivities_IUserActivityAttribution<D>::AlternateText() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::UserActivities::IUserActivityAttribution)->get_AlternateText(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_ApplicationModel_UserActivities_IUserActivityAttribution<D>::AlternateText(param::hstring const& value) const
{
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::UserActivities::IUserActivityAttribution)->put_AlternateText(get_abi(value)));
}

template <typename D> bool consume_Windows_ApplicationModel_UserActivities_IUserActivityAttribution<D>::AddImageQuery() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::UserActivities::IUserActivityAttribution)->get_AddImageQuery(&value));
    return value;
}

template <typename D> void consume_Windows_ApplicationModel_UserActivities_IUserActivityAttribution<D>::AddImageQuery(bool value) const
{
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::UserActivities::IUserActivityAttribution)->put_AddImageQuery(value));
}

template <typename D> Windows::ApplicationModel::UserActivities::UserActivityAttribution consume_Windows_ApplicationModel_UserActivities_IUserActivityAttributionFactory<D>::CreateWithUri(Windows::Foundation::Uri const& iconUri) const
{
    Windows::ApplicationModel::UserActivities::UserActivityAttribution value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::UserActivities::IUserActivityAttributionFactory)->CreateWithUri(get_abi(iconUri), put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::IAsyncOperation<Windows::ApplicationModel::UserActivities::UserActivity> consume_Windows_ApplicationModel_UserActivities_IUserActivityChannel<D>::GetOrCreateUserActivityAsync(param::hstring const& activityId) const
{
    Windows::Foundation::IAsyncOperation<Windows::ApplicationModel::UserActivities::UserActivity> operation{ nullptr };
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::UserActivities::IUserActivityChannel)->GetOrCreateUserActivityAsync(get_abi(activityId), put_abi(operation)));
    return operation;
}

template <typename D> Windows::Foundation::IAsyncAction consume_Windows_ApplicationModel_UserActivities_IUserActivityChannel<D>::DeleteActivityAsync(param::hstring const& activityId) const
{
    Windows::Foundation::IAsyncAction operation{ nullptr };
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::UserActivities::IUserActivityChannel)->DeleteActivityAsync(get_abi(activityId), put_abi(operation)));
    return operation;
}

template <typename D> Windows::Foundation::IAsyncAction consume_Windows_ApplicationModel_UserActivities_IUserActivityChannel<D>::DeleteAllActivitiesAsync() const
{
    Windows::Foundation::IAsyncAction operation{ nullptr };
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::UserActivities::IUserActivityChannel)->DeleteAllActivitiesAsync(put_abi(operation)));
    return operation;
}

template <typename D> Windows::Foundation::IAsyncOperation<Windows::Foundation::Collections::IVector<Windows::ApplicationModel::UserActivities::UserActivitySessionHistoryItem>> consume_Windows_ApplicationModel_UserActivities_IUserActivityChannel2<D>::GetRecentUserActivitiesAsync(int32_t maxUniqueActivities) const
{
    Windows::Foundation::IAsyncOperation<Windows::Foundation::Collections::IVector<Windows::ApplicationModel::UserActivities::UserActivitySessionHistoryItem>> operation{ nullptr };
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::UserActivities::IUserActivityChannel2)->GetRecentUserActivitiesAsync(maxUniqueActivities, put_abi(operation)));
    return operation;
}

template <typename D> Windows::Foundation::IAsyncOperation<Windows::Foundation::Collections::IVector<Windows::ApplicationModel::UserActivities::UserActivitySessionHistoryItem>> consume_Windows_ApplicationModel_UserActivities_IUserActivityChannel2<D>::GetSessionHistoryItemsForUserActivityAsync(param::hstring const& activityId, Windows::Foundation::DateTime const& startTime) const
{
    Windows::Foundation::IAsyncOperation<Windows::Foundation::Collections::IVector<Windows::ApplicationModel::UserActivities::UserActivitySessionHistoryItem>> operation{ nullptr };
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::UserActivities::IUserActivityChannel2)->GetSessionHistoryItemsForUserActivityAsync(get_abi(activityId), get_abi(startTime), put_abi(operation)));
    return operation;
}

template <typename D> Windows::ApplicationModel::UserActivities::UserActivityChannel consume_Windows_ApplicationModel_UserActivities_IUserActivityChannelStatics<D>::GetDefault() const
{
    Windows::ApplicationModel::UserActivities::UserActivityChannel result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::UserActivities::IUserActivityChannelStatics)->GetDefault(put_abi(result)));
    return result;
}

template <typename D> void consume_Windows_ApplicationModel_UserActivities_IUserActivityChannelStatics2<D>::DisableAutoSessionCreation() const
{
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::UserActivities::IUserActivityChannelStatics2)->DisableAutoSessionCreation());
}

template <typename D> Windows::ApplicationModel::UserActivities::UserActivityChannel consume_Windows_ApplicationModel_UserActivities_IUserActivityChannelStatics2<D>::TryGetForWebAccount(Windows::Security::Credentials::WebAccount const& account) const
{
    Windows::ApplicationModel::UserActivities::UserActivityChannel result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::UserActivities::IUserActivityChannelStatics2)->TryGetForWebAccount(get_abi(account), put_abi(result)));
    return result;
}

template <typename D> Windows::ApplicationModel::UserActivities::UserActivityChannel consume_Windows_ApplicationModel_UserActivities_IUserActivityChannelStatics3<D>::GetForUser(Windows::System::User const& user) const
{
    Windows::ApplicationModel::UserActivities::UserActivityChannel result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::UserActivities::IUserActivityChannelStatics3)->GetForUser(get_abi(user), put_abi(result)));
    return result;
}

template <typename D> hstring consume_Windows_ApplicationModel_UserActivities_IUserActivityContentInfo<D>::ToJson() const
{
    hstring result{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::UserActivities::IUserActivityContentInfo)->ToJson(put_abi(result)));
    return result;
}

template <typename D> Windows::ApplicationModel::UserActivities::UserActivityContentInfo consume_Windows_ApplicationModel_UserActivities_IUserActivityContentInfoStatics<D>::FromJson(param::hstring const& value) const
{
    Windows::ApplicationModel::UserActivities::UserActivityContentInfo result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::UserActivities::IUserActivityContentInfoStatics)->FromJson(get_abi(value), put_abi(result)));
    return result;
}

template <typename D> Windows::ApplicationModel::UserActivities::UserActivity consume_Windows_ApplicationModel_UserActivities_IUserActivityFactory<D>::CreateWithActivityId(param::hstring const& activityId) const
{
    Windows::ApplicationModel::UserActivities::UserActivity value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::UserActivities::IUserActivityFactory)->CreateWithActivityId(get_abi(activityId), put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_ApplicationModel_UserActivities_IUserActivityRequest<D>::SetUserActivity(Windows::ApplicationModel::UserActivities::UserActivity const& activity) const
{
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::UserActivities::IUserActivityRequest)->SetUserActivity(get_abi(activity)));
}

template <typename D> winrt::event_token consume_Windows_ApplicationModel_UserActivities_IUserActivityRequestManager<D>::UserActivityRequested(Windows::Foundation::TypedEventHandler<Windows::ApplicationModel::UserActivities::UserActivityRequestManager, Windows::ApplicationModel::UserActivities::UserActivityRequestedEventArgs> const& handler) const
{
    winrt::event_token token{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::UserActivities::IUserActivityRequestManager)->add_UserActivityRequested(get_abi(handler), put_abi(token)));
    return token;
}

template <typename D> typename consume_Windows_ApplicationModel_UserActivities_IUserActivityRequestManager<D>::UserActivityRequested_revoker consume_Windows_ApplicationModel_UserActivities_IUserActivityRequestManager<D>::UserActivityRequested(auto_revoke_t, Windows::Foundation::TypedEventHandler<Windows::ApplicationModel::UserActivities::UserActivityRequestManager, Windows::ApplicationModel::UserActivities::UserActivityRequestedEventArgs> const& handler) const
{
    return impl::make_event_revoker<D, UserActivityRequested_revoker>(this, UserActivityRequested(handler));
}

template <typename D> void consume_Windows_ApplicationModel_UserActivities_IUserActivityRequestManager<D>::UserActivityRequested(winrt::event_token const& token) const noexcept
{
    WINRT_VERIFY_(0, WINRT_SHIM(Windows::ApplicationModel::UserActivities::IUserActivityRequestManager)->remove_UserActivityRequested(get_abi(token)));
}

template <typename D> Windows::ApplicationModel::UserActivities::UserActivityRequestManager consume_Windows_ApplicationModel_UserActivities_IUserActivityRequestManagerStatics<D>::GetForCurrentView() const
{
    Windows::ApplicationModel::UserActivities::UserActivityRequestManager result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::UserActivities::IUserActivityRequestManagerStatics)->GetForCurrentView(put_abi(result)));
    return result;
}

template <typename D> Windows::ApplicationModel::UserActivities::UserActivityRequest consume_Windows_ApplicationModel_UserActivities_IUserActivityRequestedEventArgs<D>::Request() const
{
    Windows::ApplicationModel::UserActivities::UserActivityRequest value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::UserActivities::IUserActivityRequestedEventArgs)->get_Request(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::Deferral consume_Windows_ApplicationModel_UserActivities_IUserActivityRequestedEventArgs<D>::GetDeferral() const
{
    Windows::Foundation::Deferral value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::UserActivities::IUserActivityRequestedEventArgs)->GetDeferral(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_ApplicationModel_UserActivities_IUserActivitySession<D>::ActivityId() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::UserActivities::IUserActivitySession)->get_ActivityId(put_abi(value)));
    return value;
}

template <typename D> Windows::ApplicationModel::UserActivities::UserActivity consume_Windows_ApplicationModel_UserActivities_IUserActivitySessionHistoryItem<D>::UserActivity() const
{
    Windows::ApplicationModel::UserActivities::UserActivity value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::UserActivities::IUserActivitySessionHistoryItem)->get_UserActivity(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::DateTime consume_Windows_ApplicationModel_UserActivities_IUserActivitySessionHistoryItem<D>::StartTime() const
{
    Windows::Foundation::DateTime value{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::UserActivities::IUserActivitySessionHistoryItem)->get_StartTime(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::IReference<Windows::Foundation::DateTime> consume_Windows_ApplicationModel_UserActivities_IUserActivitySessionHistoryItem<D>::EndTime() const
{
    Windows::Foundation::IReference<Windows::Foundation::DateTime> value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::UserActivities::IUserActivitySessionHistoryItem)->get_EndTime(put_abi(value)));
    return value;
}

template <typename D> Windows::ApplicationModel::UserActivities::UserActivity consume_Windows_ApplicationModel_UserActivities_IUserActivityStatics<D>::TryParseFromJson(param::hstring const& json) const
{
    Windows::ApplicationModel::UserActivities::UserActivity result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::UserActivities::IUserActivityStatics)->TryParseFromJson(get_abi(json), put_abi(result)));
    return result;
}

template <typename D> Windows::Foundation::Collections::IVector<Windows::ApplicationModel::UserActivities::UserActivity> consume_Windows_ApplicationModel_UserActivities_IUserActivityStatics<D>::TryParseFromJsonArray(param::hstring const& json) const
{
    Windows::Foundation::Collections::IVector<Windows::ApplicationModel::UserActivities::UserActivity> result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::UserActivities::IUserActivityStatics)->TryParseFromJsonArray(get_abi(json), put_abi(result)));
    return result;
}

template <typename D> hstring consume_Windows_ApplicationModel_UserActivities_IUserActivityStatics<D>::ToJsonArray(param::iterable<Windows::ApplicationModel::UserActivities::UserActivity> const& activities) const
{
    hstring result{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::UserActivities::IUserActivityStatics)->ToJsonArray(get_abi(activities), put_abi(result)));
    return result;
}

template <typename D> hstring consume_Windows_ApplicationModel_UserActivities_IUserActivityVisualElements<D>::DisplayText() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::UserActivities::IUserActivityVisualElements)->get_DisplayText(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_ApplicationModel_UserActivities_IUserActivityVisualElements<D>::DisplayText(param::hstring const& value) const
{
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::UserActivities::IUserActivityVisualElements)->put_DisplayText(get_abi(value)));
}

template <typename D> hstring consume_Windows_ApplicationModel_UserActivities_IUserActivityVisualElements<D>::Description() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::UserActivities::IUserActivityVisualElements)->get_Description(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_ApplicationModel_UserActivities_IUserActivityVisualElements<D>::Description(param::hstring const& value) const
{
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::UserActivities::IUserActivityVisualElements)->put_Description(get_abi(value)));
}

template <typename D> Windows::UI::Color consume_Windows_ApplicationModel_UserActivities_IUserActivityVisualElements<D>::BackgroundColor() const
{
    Windows::UI::Color value{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::UserActivities::IUserActivityVisualElements)->get_BackgroundColor(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_ApplicationModel_UserActivities_IUserActivityVisualElements<D>::BackgroundColor(Windows::UI::Color const& value) const
{
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::UserActivities::IUserActivityVisualElements)->put_BackgroundColor(get_abi(value)));
}

template <typename D> Windows::ApplicationModel::UserActivities::UserActivityAttribution consume_Windows_ApplicationModel_UserActivities_IUserActivityVisualElements<D>::Attribution() const
{
    Windows::ApplicationModel::UserActivities::UserActivityAttribution value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::UserActivities::IUserActivityVisualElements)->get_Attribution(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_ApplicationModel_UserActivities_IUserActivityVisualElements<D>::Attribution(Windows::ApplicationModel::UserActivities::UserActivityAttribution const& value) const
{
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::UserActivities::IUserActivityVisualElements)->put_Attribution(get_abi(value)));
}

template <typename D> void consume_Windows_ApplicationModel_UserActivities_IUserActivityVisualElements<D>::Content(Windows::UI::Shell::IAdaptiveCard const& value) const
{
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::UserActivities::IUserActivityVisualElements)->put_Content(get_abi(value)));
}

template <typename D> Windows::UI::Shell::IAdaptiveCard consume_Windows_ApplicationModel_UserActivities_IUserActivityVisualElements<D>::Content() const
{
    Windows::UI::Shell::IAdaptiveCard value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::UserActivities::IUserActivityVisualElements)->get_Content(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_ApplicationModel_UserActivities_IUserActivityVisualElements2<D>::AttributionDisplayText() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::UserActivities::IUserActivityVisualElements2)->get_AttributionDisplayText(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_ApplicationModel_UserActivities_IUserActivityVisualElements2<D>::AttributionDisplayText(param::hstring const& value) const
{
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::UserActivities::IUserActivityVisualElements2)->put_AttributionDisplayText(get_abi(value)));
}

template <typename D>
struct produce<D, Windows::ApplicationModel::UserActivities::IUserActivity> : produce_base<D, Windows::ApplicationModel::UserActivities::IUserActivity>
{
    int32_t WINRT_CALL get_State(Windows::ApplicationModel::UserActivities::UserActivityState* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(State, WINRT_WRAP(Windows::ApplicationModel::UserActivities::UserActivityState));
            *value = detach_from<Windows::ApplicationModel::UserActivities::UserActivityState>(this->shim().State());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_ActivityId(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ActivityId, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().ActivityId());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_VisualElements(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(VisualElements, WINRT_WRAP(Windows::ApplicationModel::UserActivities::UserActivityVisualElements));
            *value = detach_from<Windows::ApplicationModel::UserActivities::UserActivityVisualElements>(this->shim().VisualElements());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_ContentUri(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ContentUri, WINRT_WRAP(Windows::Foundation::Uri));
            *value = detach_from<Windows::Foundation::Uri>(this->shim().ContentUri());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_ContentUri(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ContentUri, WINRT_WRAP(void), Windows::Foundation::Uri const&);
            this->shim().ContentUri(*reinterpret_cast<Windows::Foundation::Uri const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_ContentType(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ContentType, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().ContentType());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_ContentType(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ContentType, WINRT_WRAP(void), hstring const&);
            this->shim().ContentType(*reinterpret_cast<hstring const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_FallbackUri(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(FallbackUri, WINRT_WRAP(Windows::Foundation::Uri));
            *value = detach_from<Windows::Foundation::Uri>(this->shim().FallbackUri());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_FallbackUri(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(FallbackUri, WINRT_WRAP(void), Windows::Foundation::Uri const&);
            this->shim().FallbackUri(*reinterpret_cast<Windows::Foundation::Uri const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_ActivationUri(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ActivationUri, WINRT_WRAP(Windows::Foundation::Uri));
            *value = detach_from<Windows::Foundation::Uri>(this->shim().ActivationUri());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_ActivationUri(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ActivationUri, WINRT_WRAP(void), Windows::Foundation::Uri const&);
            this->shim().ActivationUri(*reinterpret_cast<Windows::Foundation::Uri const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_ContentInfo(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ContentInfo, WINRT_WRAP(Windows::ApplicationModel::UserActivities::IUserActivityContentInfo));
            *value = detach_from<Windows::ApplicationModel::UserActivities::IUserActivityContentInfo>(this->shim().ContentInfo());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_ContentInfo(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ContentInfo, WINRT_WRAP(void), Windows::ApplicationModel::UserActivities::IUserActivityContentInfo const&);
            this->shim().ContentInfo(*reinterpret_cast<Windows::ApplicationModel::UserActivities::IUserActivityContentInfo const*>(&value));
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

    int32_t WINRT_CALL CreateSession(void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CreateSession, WINRT_WRAP(Windows::ApplicationModel::UserActivities::UserActivitySession));
            *result = detach_from<Windows::ApplicationModel::UserActivities::UserActivitySession>(this->shim().CreateSession());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::ApplicationModel::UserActivities::IUserActivity2> : produce_base<D, Windows::ApplicationModel::UserActivities::IUserActivity2>
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
struct produce<D, Windows::ApplicationModel::UserActivities::IUserActivity3> : produce_base<D, Windows::ApplicationModel::UserActivities::IUserActivity3>
{
    int32_t WINRT_CALL get_IsRoamable(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IsRoamable, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().IsRoamable());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_IsRoamable(bool value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IsRoamable, WINRT_WRAP(void), bool);
            this->shim().IsRoamable(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::ApplicationModel::UserActivities::IUserActivityAttribution> : produce_base<D, Windows::ApplicationModel::UserActivities::IUserActivityAttribution>
{
    int32_t WINRT_CALL get_IconUri(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IconUri, WINRT_WRAP(Windows::Foundation::Uri));
            *value = detach_from<Windows::Foundation::Uri>(this->shim().IconUri());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_IconUri(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IconUri, WINRT_WRAP(void), Windows::Foundation::Uri const&);
            this->shim().IconUri(*reinterpret_cast<Windows::Foundation::Uri const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_AlternateText(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(AlternateText, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().AlternateText());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_AlternateText(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(AlternateText, WINRT_WRAP(void), hstring const&);
            this->shim().AlternateText(*reinterpret_cast<hstring const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_AddImageQuery(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(AddImageQuery, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().AddImageQuery());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_AddImageQuery(bool value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(AddImageQuery, WINRT_WRAP(void), bool);
            this->shim().AddImageQuery(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::ApplicationModel::UserActivities::IUserActivityAttributionFactory> : produce_base<D, Windows::ApplicationModel::UserActivities::IUserActivityAttributionFactory>
{
    int32_t WINRT_CALL CreateWithUri(void* iconUri, void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CreateWithUri, WINRT_WRAP(Windows::ApplicationModel::UserActivities::UserActivityAttribution), Windows::Foundation::Uri const&);
            *value = detach_from<Windows::ApplicationModel::UserActivities::UserActivityAttribution>(this->shim().CreateWithUri(*reinterpret_cast<Windows::Foundation::Uri const*>(&iconUri)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::ApplicationModel::UserActivities::IUserActivityChannel> : produce_base<D, Windows::ApplicationModel::UserActivities::IUserActivityChannel>
{
    int32_t WINRT_CALL GetOrCreateUserActivityAsync(void* activityId, void** operation) noexcept final
    {
        try
        {
            *operation = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetOrCreateUserActivityAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<Windows::ApplicationModel::UserActivities::UserActivity>), hstring const);
            *operation = detach_from<Windows::Foundation::IAsyncOperation<Windows::ApplicationModel::UserActivities::UserActivity>>(this->shim().GetOrCreateUserActivityAsync(*reinterpret_cast<hstring const*>(&activityId)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL DeleteActivityAsync(void* activityId, void** operation) noexcept final
    {
        try
        {
            *operation = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(DeleteActivityAsync, WINRT_WRAP(Windows::Foundation::IAsyncAction), hstring const);
            *operation = detach_from<Windows::Foundation::IAsyncAction>(this->shim().DeleteActivityAsync(*reinterpret_cast<hstring const*>(&activityId)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL DeleteAllActivitiesAsync(void** operation) noexcept final
    {
        try
        {
            *operation = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(DeleteAllActivitiesAsync, WINRT_WRAP(Windows::Foundation::IAsyncAction));
            *operation = detach_from<Windows::Foundation::IAsyncAction>(this->shim().DeleteAllActivitiesAsync());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::ApplicationModel::UserActivities::IUserActivityChannel2> : produce_base<D, Windows::ApplicationModel::UserActivities::IUserActivityChannel2>
{
    int32_t WINRT_CALL GetRecentUserActivitiesAsync(int32_t maxUniqueActivities, void** operation) noexcept final
    {
        try
        {
            *operation = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetRecentUserActivitiesAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<Windows::Foundation::Collections::IVector<Windows::ApplicationModel::UserActivities::UserActivitySessionHistoryItem>>), int32_t);
            *operation = detach_from<Windows::Foundation::IAsyncOperation<Windows::Foundation::Collections::IVector<Windows::ApplicationModel::UserActivities::UserActivitySessionHistoryItem>>>(this->shim().GetRecentUserActivitiesAsync(maxUniqueActivities));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL GetSessionHistoryItemsForUserActivityAsync(void* activityId, Windows::Foundation::DateTime startTime, void** operation) noexcept final
    {
        try
        {
            *operation = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetSessionHistoryItemsForUserActivityAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<Windows::Foundation::Collections::IVector<Windows::ApplicationModel::UserActivities::UserActivitySessionHistoryItem>>), hstring const, Windows::Foundation::DateTime const);
            *operation = detach_from<Windows::Foundation::IAsyncOperation<Windows::Foundation::Collections::IVector<Windows::ApplicationModel::UserActivities::UserActivitySessionHistoryItem>>>(this->shim().GetSessionHistoryItemsForUserActivityAsync(*reinterpret_cast<hstring const*>(&activityId), *reinterpret_cast<Windows::Foundation::DateTime const*>(&startTime)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::ApplicationModel::UserActivities::IUserActivityChannelStatics> : produce_base<D, Windows::ApplicationModel::UserActivities::IUserActivityChannelStatics>
{
    int32_t WINRT_CALL GetDefault(void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetDefault, WINRT_WRAP(Windows::ApplicationModel::UserActivities::UserActivityChannel));
            *result = detach_from<Windows::ApplicationModel::UserActivities::UserActivityChannel>(this->shim().GetDefault());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::ApplicationModel::UserActivities::IUserActivityChannelStatics2> : produce_base<D, Windows::ApplicationModel::UserActivities::IUserActivityChannelStatics2>
{
    int32_t WINRT_CALL DisableAutoSessionCreation() noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(DisableAutoSessionCreation, WINRT_WRAP(void));
            this->shim().DisableAutoSessionCreation();
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL TryGetForWebAccount(void* account, void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(TryGetForWebAccount, WINRT_WRAP(Windows::ApplicationModel::UserActivities::UserActivityChannel), Windows::Security::Credentials::WebAccount const&);
            *result = detach_from<Windows::ApplicationModel::UserActivities::UserActivityChannel>(this->shim().TryGetForWebAccount(*reinterpret_cast<Windows::Security::Credentials::WebAccount const*>(&account)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::ApplicationModel::UserActivities::IUserActivityChannelStatics3> : produce_base<D, Windows::ApplicationModel::UserActivities::IUserActivityChannelStatics3>
{
    int32_t WINRT_CALL GetForUser(void* user, void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetForUser, WINRT_WRAP(Windows::ApplicationModel::UserActivities::UserActivityChannel), Windows::System::User const&);
            *result = detach_from<Windows::ApplicationModel::UserActivities::UserActivityChannel>(this->shim().GetForUser(*reinterpret_cast<Windows::System::User const*>(&user)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::ApplicationModel::UserActivities::IUserActivityContentInfo> : produce_base<D, Windows::ApplicationModel::UserActivities::IUserActivityContentInfo>
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
struct produce<D, Windows::ApplicationModel::UserActivities::IUserActivityContentInfoStatics> : produce_base<D, Windows::ApplicationModel::UserActivities::IUserActivityContentInfoStatics>
{
    int32_t WINRT_CALL FromJson(void* value, void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(FromJson, WINRT_WRAP(Windows::ApplicationModel::UserActivities::UserActivityContentInfo), hstring const&);
            *result = detach_from<Windows::ApplicationModel::UserActivities::UserActivityContentInfo>(this->shim().FromJson(*reinterpret_cast<hstring const*>(&value)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::ApplicationModel::UserActivities::IUserActivityFactory> : produce_base<D, Windows::ApplicationModel::UserActivities::IUserActivityFactory>
{
    int32_t WINRT_CALL CreateWithActivityId(void* activityId, void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CreateWithActivityId, WINRT_WRAP(Windows::ApplicationModel::UserActivities::UserActivity), hstring const&);
            *value = detach_from<Windows::ApplicationModel::UserActivities::UserActivity>(this->shim().CreateWithActivityId(*reinterpret_cast<hstring const*>(&activityId)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::ApplicationModel::UserActivities::IUserActivityRequest> : produce_base<D, Windows::ApplicationModel::UserActivities::IUserActivityRequest>
{
    int32_t WINRT_CALL SetUserActivity(void* activity) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SetUserActivity, WINRT_WRAP(void), Windows::ApplicationModel::UserActivities::UserActivity const&);
            this->shim().SetUserActivity(*reinterpret_cast<Windows::ApplicationModel::UserActivities::UserActivity const*>(&activity));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::ApplicationModel::UserActivities::IUserActivityRequestManager> : produce_base<D, Windows::ApplicationModel::UserActivities::IUserActivityRequestManager>
{
    int32_t WINRT_CALL add_UserActivityRequested(void* handler, winrt::event_token* token) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(UserActivityRequested, WINRT_WRAP(winrt::event_token), Windows::Foundation::TypedEventHandler<Windows::ApplicationModel::UserActivities::UserActivityRequestManager, Windows::ApplicationModel::UserActivities::UserActivityRequestedEventArgs> const&);
            *token = detach_from<winrt::event_token>(this->shim().UserActivityRequested(*reinterpret_cast<Windows::Foundation::TypedEventHandler<Windows::ApplicationModel::UserActivities::UserActivityRequestManager, Windows::ApplicationModel::UserActivities::UserActivityRequestedEventArgs> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL remove_UserActivityRequested(winrt::event_token token) noexcept final
    {
        typename D::abi_guard guard(this->shim());
        WINRT_ASSERT_DECLARATION(UserActivityRequested, WINRT_WRAP(void), winrt::event_token const&);
        this->shim().UserActivityRequested(*reinterpret_cast<winrt::event_token const*>(&token));
        return 0;
    }
};

template <typename D>
struct produce<D, Windows::ApplicationModel::UserActivities::IUserActivityRequestManagerStatics> : produce_base<D, Windows::ApplicationModel::UserActivities::IUserActivityRequestManagerStatics>
{
    int32_t WINRT_CALL GetForCurrentView(void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetForCurrentView, WINRT_WRAP(Windows::ApplicationModel::UserActivities::UserActivityRequestManager));
            *result = detach_from<Windows::ApplicationModel::UserActivities::UserActivityRequestManager>(this->shim().GetForCurrentView());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::ApplicationModel::UserActivities::IUserActivityRequestedEventArgs> : produce_base<D, Windows::ApplicationModel::UserActivities::IUserActivityRequestedEventArgs>
{
    int32_t WINRT_CALL get_Request(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Request, WINRT_WRAP(Windows::ApplicationModel::UserActivities::UserActivityRequest));
            *value = detach_from<Windows::ApplicationModel::UserActivities::UserActivityRequest>(this->shim().Request());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL GetDeferral(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetDeferral, WINRT_WRAP(Windows::Foundation::Deferral));
            *value = detach_from<Windows::Foundation::Deferral>(this->shim().GetDeferral());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::ApplicationModel::UserActivities::IUserActivitySession> : produce_base<D, Windows::ApplicationModel::UserActivities::IUserActivitySession>
{
    int32_t WINRT_CALL get_ActivityId(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ActivityId, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().ActivityId());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::ApplicationModel::UserActivities::IUserActivitySessionHistoryItem> : produce_base<D, Windows::ApplicationModel::UserActivities::IUserActivitySessionHistoryItem>
{
    int32_t WINRT_CALL get_UserActivity(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(UserActivity, WINRT_WRAP(Windows::ApplicationModel::UserActivities::UserActivity));
            *value = detach_from<Windows::ApplicationModel::UserActivities::UserActivity>(this->shim().UserActivity());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_StartTime(Windows::Foundation::DateTime* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(StartTime, WINRT_WRAP(Windows::Foundation::DateTime));
            *value = detach_from<Windows::Foundation::DateTime>(this->shim().StartTime());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_EndTime(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(EndTime, WINRT_WRAP(Windows::Foundation::IReference<Windows::Foundation::DateTime>));
            *value = detach_from<Windows::Foundation::IReference<Windows::Foundation::DateTime>>(this->shim().EndTime());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::ApplicationModel::UserActivities::IUserActivityStatics> : produce_base<D, Windows::ApplicationModel::UserActivities::IUserActivityStatics>
{
    int32_t WINRT_CALL TryParseFromJson(void* json, void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(TryParseFromJson, WINRT_WRAP(Windows::ApplicationModel::UserActivities::UserActivity), hstring const&);
            *result = detach_from<Windows::ApplicationModel::UserActivities::UserActivity>(this->shim().TryParseFromJson(*reinterpret_cast<hstring const*>(&json)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL TryParseFromJsonArray(void* json, void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(TryParseFromJsonArray, WINRT_WRAP(Windows::Foundation::Collections::IVector<Windows::ApplicationModel::UserActivities::UserActivity>), hstring const&);
            *result = detach_from<Windows::Foundation::Collections::IVector<Windows::ApplicationModel::UserActivities::UserActivity>>(this->shim().TryParseFromJsonArray(*reinterpret_cast<hstring const*>(&json)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL ToJsonArray(void* activities, void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ToJsonArray, WINRT_WRAP(hstring), Windows::Foundation::Collections::IIterable<Windows::ApplicationModel::UserActivities::UserActivity> const&);
            *result = detach_from<hstring>(this->shim().ToJsonArray(*reinterpret_cast<Windows::Foundation::Collections::IIterable<Windows::ApplicationModel::UserActivities::UserActivity> const*>(&activities)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::ApplicationModel::UserActivities::IUserActivityVisualElements> : produce_base<D, Windows::ApplicationModel::UserActivities::IUserActivityVisualElements>
{
    int32_t WINRT_CALL get_DisplayText(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(DisplayText, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().DisplayText());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_DisplayText(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(DisplayText, WINRT_WRAP(void), hstring const&);
            this->shim().DisplayText(*reinterpret_cast<hstring const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Description(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Description, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().Description());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_Description(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Description, WINRT_WRAP(void), hstring const&);
            this->shim().Description(*reinterpret_cast<hstring const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_BackgroundColor(struct struct_Windows_UI_Color* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(BackgroundColor, WINRT_WRAP(Windows::UI::Color));
            *value = detach_from<Windows::UI::Color>(this->shim().BackgroundColor());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_BackgroundColor(struct struct_Windows_UI_Color value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(BackgroundColor, WINRT_WRAP(void), Windows::UI::Color const&);
            this->shim().BackgroundColor(*reinterpret_cast<Windows::UI::Color const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Attribution(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Attribution, WINRT_WRAP(Windows::ApplicationModel::UserActivities::UserActivityAttribution));
            *value = detach_from<Windows::ApplicationModel::UserActivities::UserActivityAttribution>(this->shim().Attribution());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_Attribution(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Attribution, WINRT_WRAP(void), Windows::ApplicationModel::UserActivities::UserActivityAttribution const&);
            this->shim().Attribution(*reinterpret_cast<Windows::ApplicationModel::UserActivities::UserActivityAttribution const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_Content(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Content, WINRT_WRAP(void), Windows::UI::Shell::IAdaptiveCard const&);
            this->shim().Content(*reinterpret_cast<Windows::UI::Shell::IAdaptiveCard const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Content(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Content, WINRT_WRAP(Windows::UI::Shell::IAdaptiveCard));
            *value = detach_from<Windows::UI::Shell::IAdaptiveCard>(this->shim().Content());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::ApplicationModel::UserActivities::IUserActivityVisualElements2> : produce_base<D, Windows::ApplicationModel::UserActivities::IUserActivityVisualElements2>
{
    int32_t WINRT_CALL get_AttributionDisplayText(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(AttributionDisplayText, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().AttributionDisplayText());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_AttributionDisplayText(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(AttributionDisplayText, WINRT_WRAP(void), hstring const&);
            this->shim().AttributionDisplayText(*reinterpret_cast<hstring const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

}

WINRT_EXPORT namespace winrt::Windows::ApplicationModel::UserActivities {

inline UserActivity::UserActivity(param::hstring const& activityId) :
    UserActivity(impl::call_factory<UserActivity, Windows::ApplicationModel::UserActivities::IUserActivityFactory>([&](auto&& f) { return f.CreateWithActivityId(activityId); }))
{}

inline Windows::ApplicationModel::UserActivities::UserActivity UserActivity::TryParseFromJson(param::hstring const& json)
{
    return impl::call_factory<UserActivity, Windows::ApplicationModel::UserActivities::IUserActivityStatics>([&](auto&& f) { return f.TryParseFromJson(json); });
}

inline Windows::Foundation::Collections::IVector<Windows::ApplicationModel::UserActivities::UserActivity> UserActivity::TryParseFromJsonArray(param::hstring const& json)
{
    return impl::call_factory<UserActivity, Windows::ApplicationModel::UserActivities::IUserActivityStatics>([&](auto&& f) { return f.TryParseFromJsonArray(json); });
}

inline hstring UserActivity::ToJsonArray(param::iterable<Windows::ApplicationModel::UserActivities::UserActivity> const& activities)
{
    return impl::call_factory<UserActivity, Windows::ApplicationModel::UserActivities::IUserActivityStatics>([&](auto&& f) { return f.ToJsonArray(activities); });
}

inline UserActivityAttribution::UserActivityAttribution() :
    UserActivityAttribution(impl::call_factory<UserActivityAttribution>([](auto&& f) { return f.template ActivateInstance<UserActivityAttribution>(); }))
{}

inline UserActivityAttribution::UserActivityAttribution(Windows::Foundation::Uri const& iconUri) :
    UserActivityAttribution(impl::call_factory<UserActivityAttribution, Windows::ApplicationModel::UserActivities::IUserActivityAttributionFactory>([&](auto&& f) { return f.CreateWithUri(iconUri); }))
{}

inline Windows::ApplicationModel::UserActivities::UserActivityChannel UserActivityChannel::GetDefault()
{
    return impl::call_factory<UserActivityChannel, Windows::ApplicationModel::UserActivities::IUserActivityChannelStatics>([&](auto&& f) { return f.GetDefault(); });
}

inline void UserActivityChannel::DisableAutoSessionCreation()
{
    impl::call_factory<UserActivityChannel, Windows::ApplicationModel::UserActivities::IUserActivityChannelStatics2>([&](auto&& f) { return f.DisableAutoSessionCreation(); });
}

inline Windows::ApplicationModel::UserActivities::UserActivityChannel UserActivityChannel::TryGetForWebAccount(Windows::Security::Credentials::WebAccount const& account)
{
    return impl::call_factory<UserActivityChannel, Windows::ApplicationModel::UserActivities::IUserActivityChannelStatics2>([&](auto&& f) { return f.TryGetForWebAccount(account); });
}

inline Windows::ApplicationModel::UserActivities::UserActivityChannel UserActivityChannel::GetForUser(Windows::System::User const& user)
{
    return impl::call_factory<UserActivityChannel, Windows::ApplicationModel::UserActivities::IUserActivityChannelStatics3>([&](auto&& f) { return f.GetForUser(user); });
}

inline Windows::ApplicationModel::UserActivities::UserActivityContentInfo UserActivityContentInfo::FromJson(param::hstring const& value)
{
    return impl::call_factory<UserActivityContentInfo, Windows::ApplicationModel::UserActivities::IUserActivityContentInfoStatics>([&](auto&& f) { return f.FromJson(value); });
}

inline Windows::ApplicationModel::UserActivities::UserActivityRequestManager UserActivityRequestManager::GetForCurrentView()
{
    return impl::call_factory<UserActivityRequestManager, Windows::ApplicationModel::UserActivities::IUserActivityRequestManagerStatics>([&](auto&& f) { return f.GetForCurrentView(); });
}

}

WINRT_EXPORT namespace std {

template<> struct hash<winrt::Windows::ApplicationModel::UserActivities::IUserActivity> : winrt::impl::hash_base<winrt::Windows::ApplicationModel::UserActivities::IUserActivity> {};
template<> struct hash<winrt::Windows::ApplicationModel::UserActivities::IUserActivity2> : winrt::impl::hash_base<winrt::Windows::ApplicationModel::UserActivities::IUserActivity2> {};
template<> struct hash<winrt::Windows::ApplicationModel::UserActivities::IUserActivity3> : winrt::impl::hash_base<winrt::Windows::ApplicationModel::UserActivities::IUserActivity3> {};
template<> struct hash<winrt::Windows::ApplicationModel::UserActivities::IUserActivityAttribution> : winrt::impl::hash_base<winrt::Windows::ApplicationModel::UserActivities::IUserActivityAttribution> {};
template<> struct hash<winrt::Windows::ApplicationModel::UserActivities::IUserActivityAttributionFactory> : winrt::impl::hash_base<winrt::Windows::ApplicationModel::UserActivities::IUserActivityAttributionFactory> {};
template<> struct hash<winrt::Windows::ApplicationModel::UserActivities::IUserActivityChannel> : winrt::impl::hash_base<winrt::Windows::ApplicationModel::UserActivities::IUserActivityChannel> {};
template<> struct hash<winrt::Windows::ApplicationModel::UserActivities::IUserActivityChannel2> : winrt::impl::hash_base<winrt::Windows::ApplicationModel::UserActivities::IUserActivityChannel2> {};
template<> struct hash<winrt::Windows::ApplicationModel::UserActivities::IUserActivityChannelStatics> : winrt::impl::hash_base<winrt::Windows::ApplicationModel::UserActivities::IUserActivityChannelStatics> {};
template<> struct hash<winrt::Windows::ApplicationModel::UserActivities::IUserActivityChannelStatics2> : winrt::impl::hash_base<winrt::Windows::ApplicationModel::UserActivities::IUserActivityChannelStatics2> {};
template<> struct hash<winrt::Windows::ApplicationModel::UserActivities::IUserActivityChannelStatics3> : winrt::impl::hash_base<winrt::Windows::ApplicationModel::UserActivities::IUserActivityChannelStatics3> {};
template<> struct hash<winrt::Windows::ApplicationModel::UserActivities::IUserActivityContentInfo> : winrt::impl::hash_base<winrt::Windows::ApplicationModel::UserActivities::IUserActivityContentInfo> {};
template<> struct hash<winrt::Windows::ApplicationModel::UserActivities::IUserActivityContentInfoStatics> : winrt::impl::hash_base<winrt::Windows::ApplicationModel::UserActivities::IUserActivityContentInfoStatics> {};
template<> struct hash<winrt::Windows::ApplicationModel::UserActivities::IUserActivityFactory> : winrt::impl::hash_base<winrt::Windows::ApplicationModel::UserActivities::IUserActivityFactory> {};
template<> struct hash<winrt::Windows::ApplicationModel::UserActivities::IUserActivityRequest> : winrt::impl::hash_base<winrt::Windows::ApplicationModel::UserActivities::IUserActivityRequest> {};
template<> struct hash<winrt::Windows::ApplicationModel::UserActivities::IUserActivityRequestManager> : winrt::impl::hash_base<winrt::Windows::ApplicationModel::UserActivities::IUserActivityRequestManager> {};
template<> struct hash<winrt::Windows::ApplicationModel::UserActivities::IUserActivityRequestManagerStatics> : winrt::impl::hash_base<winrt::Windows::ApplicationModel::UserActivities::IUserActivityRequestManagerStatics> {};
template<> struct hash<winrt::Windows::ApplicationModel::UserActivities::IUserActivityRequestedEventArgs> : winrt::impl::hash_base<winrt::Windows::ApplicationModel::UserActivities::IUserActivityRequestedEventArgs> {};
template<> struct hash<winrt::Windows::ApplicationModel::UserActivities::IUserActivitySession> : winrt::impl::hash_base<winrt::Windows::ApplicationModel::UserActivities::IUserActivitySession> {};
template<> struct hash<winrt::Windows::ApplicationModel::UserActivities::IUserActivitySessionHistoryItem> : winrt::impl::hash_base<winrt::Windows::ApplicationModel::UserActivities::IUserActivitySessionHistoryItem> {};
template<> struct hash<winrt::Windows::ApplicationModel::UserActivities::IUserActivityStatics> : winrt::impl::hash_base<winrt::Windows::ApplicationModel::UserActivities::IUserActivityStatics> {};
template<> struct hash<winrt::Windows::ApplicationModel::UserActivities::IUserActivityVisualElements> : winrt::impl::hash_base<winrt::Windows::ApplicationModel::UserActivities::IUserActivityVisualElements> {};
template<> struct hash<winrt::Windows::ApplicationModel::UserActivities::IUserActivityVisualElements2> : winrt::impl::hash_base<winrt::Windows::ApplicationModel::UserActivities::IUserActivityVisualElements2> {};
template<> struct hash<winrt::Windows::ApplicationModel::UserActivities::UserActivity> : winrt::impl::hash_base<winrt::Windows::ApplicationModel::UserActivities::UserActivity> {};
template<> struct hash<winrt::Windows::ApplicationModel::UserActivities::UserActivityAttribution> : winrt::impl::hash_base<winrt::Windows::ApplicationModel::UserActivities::UserActivityAttribution> {};
template<> struct hash<winrt::Windows::ApplicationModel::UserActivities::UserActivityChannel> : winrt::impl::hash_base<winrt::Windows::ApplicationModel::UserActivities::UserActivityChannel> {};
template<> struct hash<winrt::Windows::ApplicationModel::UserActivities::UserActivityContentInfo> : winrt::impl::hash_base<winrt::Windows::ApplicationModel::UserActivities::UserActivityContentInfo> {};
template<> struct hash<winrt::Windows::ApplicationModel::UserActivities::UserActivityRequest> : winrt::impl::hash_base<winrt::Windows::ApplicationModel::UserActivities::UserActivityRequest> {};
template<> struct hash<winrt::Windows::ApplicationModel::UserActivities::UserActivityRequestManager> : winrt::impl::hash_base<winrt::Windows::ApplicationModel::UserActivities::UserActivityRequestManager> {};
template<> struct hash<winrt::Windows::ApplicationModel::UserActivities::UserActivityRequestedEventArgs> : winrt::impl::hash_base<winrt::Windows::ApplicationModel::UserActivities::UserActivityRequestedEventArgs> {};
template<> struct hash<winrt::Windows::ApplicationModel::UserActivities::UserActivitySession> : winrt::impl::hash_base<winrt::Windows::ApplicationModel::UserActivities::UserActivitySession> {};
template<> struct hash<winrt::Windows::ApplicationModel::UserActivities::UserActivitySessionHistoryItem> : winrt::impl::hash_base<winrt::Windows::ApplicationModel::UserActivities::UserActivitySessionHistoryItem> {};
template<> struct hash<winrt::Windows::ApplicationModel::UserActivities::UserActivityVisualElements> : winrt::impl::hash_base<winrt::Windows::ApplicationModel::UserActivities::UserActivityVisualElements> {};

}
