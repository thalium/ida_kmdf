// C++/WinRT v1.0.190111.3

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#pragma once

WINRT_EXPORT namespace winrt::Windows::Foundation {

struct Deferral;
struct Uri;

}

WINRT_EXPORT namespace winrt::Windows::Security::Credentials {

struct WebAccount;

}

WINRT_EXPORT namespace winrt::Windows::System {

struct User;

}

WINRT_EXPORT namespace winrt::Windows::UI {

struct Color;

}

WINRT_EXPORT namespace winrt::Windows::UI::Shell {

struct IAdaptiveCard;

}

WINRT_EXPORT namespace winrt::Windows::ApplicationModel::UserActivities {

enum class UserActivityState : int32_t
{
    New = 0,
    Published = 1,
};

struct IUserActivity;
struct IUserActivity2;
struct IUserActivity3;
struct IUserActivityAttribution;
struct IUserActivityAttributionFactory;
struct IUserActivityChannel;
struct IUserActivityChannel2;
struct IUserActivityChannelStatics;
struct IUserActivityChannelStatics2;
struct IUserActivityChannelStatics3;
struct IUserActivityContentInfo;
struct IUserActivityContentInfoStatics;
struct IUserActivityFactory;
struct IUserActivityRequest;
struct IUserActivityRequestManager;
struct IUserActivityRequestManagerStatics;
struct IUserActivityRequestedEventArgs;
struct IUserActivitySession;
struct IUserActivitySessionHistoryItem;
struct IUserActivityStatics;
struct IUserActivityVisualElements;
struct IUserActivityVisualElements2;
struct UserActivity;
struct UserActivityAttribution;
struct UserActivityChannel;
struct UserActivityContentInfo;
struct UserActivityRequest;
struct UserActivityRequestManager;
struct UserActivityRequestedEventArgs;
struct UserActivitySession;
struct UserActivitySessionHistoryItem;
struct UserActivityVisualElements;

}

namespace winrt::impl {

template <> struct category<Windows::ApplicationModel::UserActivities::IUserActivity>{ using type = interface_category; };
template <> struct category<Windows::ApplicationModel::UserActivities::IUserActivity2>{ using type = interface_category; };
template <> struct category<Windows::ApplicationModel::UserActivities::IUserActivity3>{ using type = interface_category; };
template <> struct category<Windows::ApplicationModel::UserActivities::IUserActivityAttribution>{ using type = interface_category; };
template <> struct category<Windows::ApplicationModel::UserActivities::IUserActivityAttributionFactory>{ using type = interface_category; };
template <> struct category<Windows::ApplicationModel::UserActivities::IUserActivityChannel>{ using type = interface_category; };
template <> struct category<Windows::ApplicationModel::UserActivities::IUserActivityChannel2>{ using type = interface_category; };
template <> struct category<Windows::ApplicationModel::UserActivities::IUserActivityChannelStatics>{ using type = interface_category; };
template <> struct category<Windows::ApplicationModel::UserActivities::IUserActivityChannelStatics2>{ using type = interface_category; };
template <> struct category<Windows::ApplicationModel::UserActivities::IUserActivityChannelStatics3>{ using type = interface_category; };
template <> struct category<Windows::ApplicationModel::UserActivities::IUserActivityContentInfo>{ using type = interface_category; };
template <> struct category<Windows::ApplicationModel::UserActivities::IUserActivityContentInfoStatics>{ using type = interface_category; };
template <> struct category<Windows::ApplicationModel::UserActivities::IUserActivityFactory>{ using type = interface_category; };
template <> struct category<Windows::ApplicationModel::UserActivities::IUserActivityRequest>{ using type = interface_category; };
template <> struct category<Windows::ApplicationModel::UserActivities::IUserActivityRequestManager>{ using type = interface_category; };
template <> struct category<Windows::ApplicationModel::UserActivities::IUserActivityRequestManagerStatics>{ using type = interface_category; };
template <> struct category<Windows::ApplicationModel::UserActivities::IUserActivityRequestedEventArgs>{ using type = interface_category; };
template <> struct category<Windows::ApplicationModel::UserActivities::IUserActivitySession>{ using type = interface_category; };
template <> struct category<Windows::ApplicationModel::UserActivities::IUserActivitySessionHistoryItem>{ using type = interface_category; };
template <> struct category<Windows::ApplicationModel::UserActivities::IUserActivityStatics>{ using type = interface_category; };
template <> struct category<Windows::ApplicationModel::UserActivities::IUserActivityVisualElements>{ using type = interface_category; };
template <> struct category<Windows::ApplicationModel::UserActivities::IUserActivityVisualElements2>{ using type = interface_category; };
template <> struct category<Windows::ApplicationModel::UserActivities::UserActivity>{ using type = class_category; };
template <> struct category<Windows::ApplicationModel::UserActivities::UserActivityAttribution>{ using type = class_category; };
template <> struct category<Windows::ApplicationModel::UserActivities::UserActivityChannel>{ using type = class_category; };
template <> struct category<Windows::ApplicationModel::UserActivities::UserActivityContentInfo>{ using type = class_category; };
template <> struct category<Windows::ApplicationModel::UserActivities::UserActivityRequest>{ using type = class_category; };
template <> struct category<Windows::ApplicationModel::UserActivities::UserActivityRequestManager>{ using type = class_category; };
template <> struct category<Windows::ApplicationModel::UserActivities::UserActivityRequestedEventArgs>{ using type = class_category; };
template <> struct category<Windows::ApplicationModel::UserActivities::UserActivitySession>{ using type = class_category; };
template <> struct category<Windows::ApplicationModel::UserActivities::UserActivitySessionHistoryItem>{ using type = class_category; };
template <> struct category<Windows::ApplicationModel::UserActivities::UserActivityVisualElements>{ using type = class_category; };
template <> struct category<Windows::ApplicationModel::UserActivities::UserActivityState>{ using type = enum_category; };
template <> struct name<Windows::ApplicationModel::UserActivities::IUserActivity>{ static constexpr auto & value{ L"Windows.ApplicationModel.UserActivities.IUserActivity" }; };
template <> struct name<Windows::ApplicationModel::UserActivities::IUserActivity2>{ static constexpr auto & value{ L"Windows.ApplicationModel.UserActivities.IUserActivity2" }; };
template <> struct name<Windows::ApplicationModel::UserActivities::IUserActivity3>{ static constexpr auto & value{ L"Windows.ApplicationModel.UserActivities.IUserActivity3" }; };
template <> struct name<Windows::ApplicationModel::UserActivities::IUserActivityAttribution>{ static constexpr auto & value{ L"Windows.ApplicationModel.UserActivities.IUserActivityAttribution" }; };
template <> struct name<Windows::ApplicationModel::UserActivities::IUserActivityAttributionFactory>{ static constexpr auto & value{ L"Windows.ApplicationModel.UserActivities.IUserActivityAttributionFactory" }; };
template <> struct name<Windows::ApplicationModel::UserActivities::IUserActivityChannel>{ static constexpr auto & value{ L"Windows.ApplicationModel.UserActivities.IUserActivityChannel" }; };
template <> struct name<Windows::ApplicationModel::UserActivities::IUserActivityChannel2>{ static constexpr auto & value{ L"Windows.ApplicationModel.UserActivities.IUserActivityChannel2" }; };
template <> struct name<Windows::ApplicationModel::UserActivities::IUserActivityChannelStatics>{ static constexpr auto & value{ L"Windows.ApplicationModel.UserActivities.IUserActivityChannelStatics" }; };
template <> struct name<Windows::ApplicationModel::UserActivities::IUserActivityChannelStatics2>{ static constexpr auto & value{ L"Windows.ApplicationModel.UserActivities.IUserActivityChannelStatics2" }; };
template <> struct name<Windows::ApplicationModel::UserActivities::IUserActivityChannelStatics3>{ static constexpr auto & value{ L"Windows.ApplicationModel.UserActivities.IUserActivityChannelStatics3" }; };
template <> struct name<Windows::ApplicationModel::UserActivities::IUserActivityContentInfo>{ static constexpr auto & value{ L"Windows.ApplicationModel.UserActivities.IUserActivityContentInfo" }; };
template <> struct name<Windows::ApplicationModel::UserActivities::IUserActivityContentInfoStatics>{ static constexpr auto & value{ L"Windows.ApplicationModel.UserActivities.IUserActivityContentInfoStatics" }; };
template <> struct name<Windows::ApplicationModel::UserActivities::IUserActivityFactory>{ static constexpr auto & value{ L"Windows.ApplicationModel.UserActivities.IUserActivityFactory" }; };
template <> struct name<Windows::ApplicationModel::UserActivities::IUserActivityRequest>{ static constexpr auto & value{ L"Windows.ApplicationModel.UserActivities.IUserActivityRequest" }; };
template <> struct name<Windows::ApplicationModel::UserActivities::IUserActivityRequestManager>{ static constexpr auto & value{ L"Windows.ApplicationModel.UserActivities.IUserActivityRequestManager" }; };
template <> struct name<Windows::ApplicationModel::UserActivities::IUserActivityRequestManagerStatics>{ static constexpr auto & value{ L"Windows.ApplicationModel.UserActivities.IUserActivityRequestManagerStatics" }; };
template <> struct name<Windows::ApplicationModel::UserActivities::IUserActivityRequestedEventArgs>{ static constexpr auto & value{ L"Windows.ApplicationModel.UserActivities.IUserActivityRequestedEventArgs" }; };
template <> struct name<Windows::ApplicationModel::UserActivities::IUserActivitySession>{ static constexpr auto & value{ L"Windows.ApplicationModel.UserActivities.IUserActivitySession" }; };
template <> struct name<Windows::ApplicationModel::UserActivities::IUserActivitySessionHistoryItem>{ static constexpr auto & value{ L"Windows.ApplicationModel.UserActivities.IUserActivitySessionHistoryItem" }; };
template <> struct name<Windows::ApplicationModel::UserActivities::IUserActivityStatics>{ static constexpr auto & value{ L"Windows.ApplicationModel.UserActivities.IUserActivityStatics" }; };
template <> struct name<Windows::ApplicationModel::UserActivities::IUserActivityVisualElements>{ static constexpr auto & value{ L"Windows.ApplicationModel.UserActivities.IUserActivityVisualElements" }; };
template <> struct name<Windows::ApplicationModel::UserActivities::IUserActivityVisualElements2>{ static constexpr auto & value{ L"Windows.ApplicationModel.UserActivities.IUserActivityVisualElements2" }; };
template <> struct name<Windows::ApplicationModel::UserActivities::UserActivity>{ static constexpr auto & value{ L"Windows.ApplicationModel.UserActivities.UserActivity" }; };
template <> struct name<Windows::ApplicationModel::UserActivities::UserActivityAttribution>{ static constexpr auto & value{ L"Windows.ApplicationModel.UserActivities.UserActivityAttribution" }; };
template <> struct name<Windows::ApplicationModel::UserActivities::UserActivityChannel>{ static constexpr auto & value{ L"Windows.ApplicationModel.UserActivities.UserActivityChannel" }; };
template <> struct name<Windows::ApplicationModel::UserActivities::UserActivityContentInfo>{ static constexpr auto & value{ L"Windows.ApplicationModel.UserActivities.UserActivityContentInfo" }; };
template <> struct name<Windows::ApplicationModel::UserActivities::UserActivityRequest>{ static constexpr auto & value{ L"Windows.ApplicationModel.UserActivities.UserActivityRequest" }; };
template <> struct name<Windows::ApplicationModel::UserActivities::UserActivityRequestManager>{ static constexpr auto & value{ L"Windows.ApplicationModel.UserActivities.UserActivityRequestManager" }; };
template <> struct name<Windows::ApplicationModel::UserActivities::UserActivityRequestedEventArgs>{ static constexpr auto & value{ L"Windows.ApplicationModel.UserActivities.UserActivityRequestedEventArgs" }; };
template <> struct name<Windows::ApplicationModel::UserActivities::UserActivitySession>{ static constexpr auto & value{ L"Windows.ApplicationModel.UserActivities.UserActivitySession" }; };
template <> struct name<Windows::ApplicationModel::UserActivities::UserActivitySessionHistoryItem>{ static constexpr auto & value{ L"Windows.ApplicationModel.UserActivities.UserActivitySessionHistoryItem" }; };
template <> struct name<Windows::ApplicationModel::UserActivities::UserActivityVisualElements>{ static constexpr auto & value{ L"Windows.ApplicationModel.UserActivities.UserActivityVisualElements" }; };
template <> struct name<Windows::ApplicationModel::UserActivities::UserActivityState>{ static constexpr auto & value{ L"Windows.ApplicationModel.UserActivities.UserActivityState" }; };
template <> struct guid_storage<Windows::ApplicationModel::UserActivities::IUserActivity>{ static constexpr guid value{ 0xFC103E9E,0x2CAB,0x4D36,{ 0xAE,0xA2,0xB4,0xBB,0x55,0x6C,0xEF,0x0F } }; };
template <> struct guid_storage<Windows::ApplicationModel::UserActivities::IUserActivity2>{ static constexpr guid value{ 0x9DC40C62,0x08C4,0x47AC,{ 0xAA,0x9C,0x2B,0xB2,0x22,0x1C,0x55,0xFD } }; };
template <> struct guid_storage<Windows::ApplicationModel::UserActivities::IUserActivity3>{ static constexpr guid value{ 0xE7697744,0xE1A2,0x5147,{ 0x8E,0x06,0x55,0xF1,0xEE,0xEF,0x27,0x1C } }; };
template <> struct guid_storage<Windows::ApplicationModel::UserActivities::IUserActivityAttribution>{ static constexpr guid value{ 0x34A5C8B5,0x86DD,0x4AEC,{ 0xA4,0x91,0x6A,0x4F,0xAE,0xA5,0xD2,0x2E } }; };
template <> struct guid_storage<Windows::ApplicationModel::UserActivities::IUserActivityAttributionFactory>{ static constexpr guid value{ 0xE62BD252,0xC566,0x4F42,{ 0x99,0x74,0x91,0x6C,0x4D,0x76,0x37,0x7E } }; };
template <> struct guid_storage<Windows::ApplicationModel::UserActivities::IUserActivityChannel>{ static constexpr guid value{ 0xBAC0F8B8,0xA0E4,0x483B,{ 0xB9,0x48,0x9C,0xBA,0xBD,0x06,0x07,0x0C } }; };
template <> struct guid_storage<Windows::ApplicationModel::UserActivities::IUserActivityChannel2>{ static constexpr guid value{ 0x1698E35B,0xEB7E,0x4EA0,{ 0xBF,0x17,0xA4,0x59,0xE8,0xBE,0x70,0x6C } }; };
template <> struct guid_storage<Windows::ApplicationModel::UserActivities::IUserActivityChannelStatics>{ static constexpr guid value{ 0xC8C005AB,0x198D,0x4D80,{ 0xAB,0xB2,0xC9,0x77,0x5E,0xC4,0xA7,0x29 } }; };
template <> struct guid_storage<Windows::ApplicationModel::UserActivities::IUserActivityChannelStatics2>{ static constexpr guid value{ 0x8E87DE30,0xAA4F,0x4624,{ 0x9A,0xD0,0xD4,0x0F,0x3B,0xA0,0x31,0x7C } }; };
template <> struct guid_storage<Windows::ApplicationModel::UserActivities::IUserActivityChannelStatics3>{ static constexpr guid value{ 0x53BC4DDB,0xBBDF,0x5984,{ 0x80,0x2A,0x53,0x05,0x87,0x4E,0x20,0x5C } }; };
template <> struct guid_storage<Windows::ApplicationModel::UserActivities::IUserActivityContentInfo>{ static constexpr guid value{ 0xB399E5AD,0x137F,0x409D,{ 0x82,0x2D,0xE1,0xAF,0x27,0xCE,0x08,0xDC } }; };
template <> struct guid_storage<Windows::ApplicationModel::UserActivities::IUserActivityContentInfoStatics>{ static constexpr guid value{ 0x9988C34B,0x0386,0x4BC9,{ 0x96,0x8A,0x82,0x00,0xB0,0x04,0x14,0x4F } }; };
template <> struct guid_storage<Windows::ApplicationModel::UserActivities::IUserActivityFactory>{ static constexpr guid value{ 0x7C385758,0x361D,0x4A67,{ 0x8A,0x3B,0x34,0xCA,0x29,0x78,0xF9,0xA3 } }; };
template <> struct guid_storage<Windows::ApplicationModel::UserActivities::IUserActivityRequest>{ static constexpr guid value{ 0xA0EF6355,0xCF35,0x4FF0,{ 0x88,0x33,0x50,0xCB,0x4B,0x72,0xE0,0x6D } }; };
template <> struct guid_storage<Windows::ApplicationModel::UserActivities::IUserActivityRequestManager>{ static constexpr guid value{ 0x0C30BE4E,0x903D,0x48D6,{ 0x82,0xD4,0x40,0x43,0xED,0x57,0x79,0x1B } }; };
template <> struct guid_storage<Windows::ApplicationModel::UserActivities::IUserActivityRequestManagerStatics>{ static constexpr guid value{ 0xC0392DF1,0x224A,0x432C,{ 0x81,0xE5,0x0C,0x76,0xB4,0xC4,0xCE,0xFA } }; };
template <> struct guid_storage<Windows::ApplicationModel::UserActivities::IUserActivityRequestedEventArgs>{ static constexpr guid value{ 0xA4CC7A4C,0x8229,0x4CFD,{ 0xA3,0xBC,0xC6,0x1D,0x31,0x85,0x75,0xA4 } }; };
template <> struct guid_storage<Windows::ApplicationModel::UserActivities::IUserActivitySession>{ static constexpr guid value{ 0xAE434D78,0x24FA,0x44A3,{ 0xAD,0x48,0x6E,0xDA,0x61,0xAA,0x19,0x24 } }; };
template <> struct guid_storage<Windows::ApplicationModel::UserActivities::IUserActivitySessionHistoryItem>{ static constexpr guid value{ 0xE8D59BD3,0x3E5D,0x49FD,{ 0x98,0xD7,0x6D,0xA9,0x75,0x21,0xE2,0x55 } }; };
template <> struct guid_storage<Windows::ApplicationModel::UserActivities::IUserActivityStatics>{ static constexpr guid value{ 0x8C8FD333,0x0E09,0x47F6,{ 0x9A,0xC7,0x95,0xCF,0x5C,0x39,0x36,0x7B } }; };
template <> struct guid_storage<Windows::ApplicationModel::UserActivities::IUserActivityVisualElements>{ static constexpr guid value{ 0x94757513,0x262F,0x49EF,{ 0xBB,0xBF,0x9B,0x75,0xD2,0xE8,0x52,0x50 } }; };
template <> struct guid_storage<Windows::ApplicationModel::UserActivities::IUserActivityVisualElements2>{ static constexpr guid value{ 0xCAAE7FC7,0x3EEF,0x4359,{ 0x82,0x5C,0x9D,0x51,0xB9,0x22,0x0D,0xE3 } }; };
template <> struct default_interface<Windows::ApplicationModel::UserActivities::UserActivity>{ using type = Windows::ApplicationModel::UserActivities::IUserActivity; };
template <> struct default_interface<Windows::ApplicationModel::UserActivities::UserActivityAttribution>{ using type = Windows::ApplicationModel::UserActivities::IUserActivityAttribution; };
template <> struct default_interface<Windows::ApplicationModel::UserActivities::UserActivityChannel>{ using type = Windows::ApplicationModel::UserActivities::IUserActivityChannel; };
template <> struct default_interface<Windows::ApplicationModel::UserActivities::UserActivityContentInfo>{ using type = Windows::ApplicationModel::UserActivities::IUserActivityContentInfo; };
template <> struct default_interface<Windows::ApplicationModel::UserActivities::UserActivityRequest>{ using type = Windows::ApplicationModel::UserActivities::IUserActivityRequest; };
template <> struct default_interface<Windows::ApplicationModel::UserActivities::UserActivityRequestManager>{ using type = Windows::ApplicationModel::UserActivities::IUserActivityRequestManager; };
template <> struct default_interface<Windows::ApplicationModel::UserActivities::UserActivityRequestedEventArgs>{ using type = Windows::ApplicationModel::UserActivities::IUserActivityRequestedEventArgs; };
template <> struct default_interface<Windows::ApplicationModel::UserActivities::UserActivitySession>{ using type = Windows::ApplicationModel::UserActivities::IUserActivitySession; };
template <> struct default_interface<Windows::ApplicationModel::UserActivities::UserActivitySessionHistoryItem>{ using type = Windows::ApplicationModel::UserActivities::IUserActivitySessionHistoryItem; };
template <> struct default_interface<Windows::ApplicationModel::UserActivities::UserActivityVisualElements>{ using type = Windows::ApplicationModel::UserActivities::IUserActivityVisualElements; };

template <> struct abi<Windows::ApplicationModel::UserActivities::IUserActivity>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL get_State(Windows::ApplicationModel::UserActivities::UserActivityState* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_ActivityId(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_VisualElements(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_ContentUri(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL put_ContentUri(void* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_ContentType(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL put_ContentType(void* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_FallbackUri(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL put_FallbackUri(void* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_ActivationUri(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL put_ActivationUri(void* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_ContentInfo(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL put_ContentInfo(void* value) noexcept = 0;
    virtual int32_t WINRT_CALL SaveAsync(void** operation) noexcept = 0;
    virtual int32_t WINRT_CALL CreateSession(void** result) noexcept = 0;
};};

template <> struct abi<Windows::ApplicationModel::UserActivities::IUserActivity2>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL ToJson(void** result) noexcept = 0;
};};

template <> struct abi<Windows::ApplicationModel::UserActivities::IUserActivity3>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL get_IsRoamable(bool* value) noexcept = 0;
    virtual int32_t WINRT_CALL put_IsRoamable(bool value) noexcept = 0;
};};

template <> struct abi<Windows::ApplicationModel::UserActivities::IUserActivityAttribution>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL get_IconUri(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL put_IconUri(void* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_AlternateText(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL put_AlternateText(void* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_AddImageQuery(bool* value) noexcept = 0;
    virtual int32_t WINRT_CALL put_AddImageQuery(bool value) noexcept = 0;
};};

template <> struct abi<Windows::ApplicationModel::UserActivities::IUserActivityAttributionFactory>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL CreateWithUri(void* iconUri, void** value) noexcept = 0;
};};

template <> struct abi<Windows::ApplicationModel::UserActivities::IUserActivityChannel>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL GetOrCreateUserActivityAsync(void* activityId, void** operation) noexcept = 0;
    virtual int32_t WINRT_CALL DeleteActivityAsync(void* activityId, void** operation) noexcept = 0;
    virtual int32_t WINRT_CALL DeleteAllActivitiesAsync(void** operation) noexcept = 0;
};};

template <> struct abi<Windows::ApplicationModel::UserActivities::IUserActivityChannel2>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL GetRecentUserActivitiesAsync(int32_t maxUniqueActivities, void** operation) noexcept = 0;
    virtual int32_t WINRT_CALL GetSessionHistoryItemsForUserActivityAsync(void* activityId, Windows::Foundation::DateTime startTime, void** operation) noexcept = 0;
};};

template <> struct abi<Windows::ApplicationModel::UserActivities::IUserActivityChannelStatics>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL GetDefault(void** result) noexcept = 0;
};};

template <> struct abi<Windows::ApplicationModel::UserActivities::IUserActivityChannelStatics2>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL DisableAutoSessionCreation() noexcept = 0;
    virtual int32_t WINRT_CALL TryGetForWebAccount(void* account, void** result) noexcept = 0;
};};

template <> struct abi<Windows::ApplicationModel::UserActivities::IUserActivityChannelStatics3>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL GetForUser(void* user, void** result) noexcept = 0;
};};

template <> struct abi<Windows::ApplicationModel::UserActivities::IUserActivityContentInfo>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL ToJson(void** result) noexcept = 0;
};};

template <> struct abi<Windows::ApplicationModel::UserActivities::IUserActivityContentInfoStatics>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL FromJson(void* value, void** result) noexcept = 0;
};};

template <> struct abi<Windows::ApplicationModel::UserActivities::IUserActivityFactory>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL CreateWithActivityId(void* activityId, void** value) noexcept = 0;
};};

template <> struct abi<Windows::ApplicationModel::UserActivities::IUserActivityRequest>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL SetUserActivity(void* activity) noexcept = 0;
};};

template <> struct abi<Windows::ApplicationModel::UserActivities::IUserActivityRequestManager>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL add_UserActivityRequested(void* handler, winrt::event_token* token) noexcept = 0;
    virtual int32_t WINRT_CALL remove_UserActivityRequested(winrt::event_token token) noexcept = 0;
};};

template <> struct abi<Windows::ApplicationModel::UserActivities::IUserActivityRequestManagerStatics>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL GetForCurrentView(void** result) noexcept = 0;
};};

template <> struct abi<Windows::ApplicationModel::UserActivities::IUserActivityRequestedEventArgs>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL get_Request(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL GetDeferral(void** value) noexcept = 0;
};};

template <> struct abi<Windows::ApplicationModel::UserActivities::IUserActivitySession>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL get_ActivityId(void** value) noexcept = 0;
};};

template <> struct abi<Windows::ApplicationModel::UserActivities::IUserActivitySessionHistoryItem>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL get_UserActivity(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_StartTime(Windows::Foundation::DateTime* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_EndTime(void** value) noexcept = 0;
};};

template <> struct abi<Windows::ApplicationModel::UserActivities::IUserActivityStatics>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL TryParseFromJson(void* json, void** result) noexcept = 0;
    virtual int32_t WINRT_CALL TryParseFromJsonArray(void* json, void** result) noexcept = 0;
    virtual int32_t WINRT_CALL ToJsonArray(void* activities, void** result) noexcept = 0;
};};

template <> struct abi<Windows::ApplicationModel::UserActivities::IUserActivityVisualElements>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL get_DisplayText(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL put_DisplayText(void* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_Description(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL put_Description(void* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_BackgroundColor(struct struct_Windows_UI_Color* value) noexcept = 0;
    virtual int32_t WINRT_CALL put_BackgroundColor(struct struct_Windows_UI_Color value) noexcept = 0;
    virtual int32_t WINRT_CALL get_Attribution(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL put_Attribution(void* value) noexcept = 0;
    virtual int32_t WINRT_CALL put_Content(void* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_Content(void** value) noexcept = 0;
};};

template <> struct abi<Windows::ApplicationModel::UserActivities::IUserActivityVisualElements2>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL get_AttributionDisplayText(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL put_AttributionDisplayText(void* value) noexcept = 0;
};};

template <typename D>
struct consume_Windows_ApplicationModel_UserActivities_IUserActivity
{
    Windows::ApplicationModel::UserActivities::UserActivityState State() const;
    hstring ActivityId() const;
    Windows::ApplicationModel::UserActivities::UserActivityVisualElements VisualElements() const;
    Windows::Foundation::Uri ContentUri() const;
    void ContentUri(Windows::Foundation::Uri const& value) const;
    hstring ContentType() const;
    void ContentType(param::hstring const& value) const;
    Windows::Foundation::Uri FallbackUri() const;
    void FallbackUri(Windows::Foundation::Uri const& value) const;
    Windows::Foundation::Uri ActivationUri() const;
    void ActivationUri(Windows::Foundation::Uri const& value) const;
    Windows::ApplicationModel::UserActivities::IUserActivityContentInfo ContentInfo() const;
    void ContentInfo(Windows::ApplicationModel::UserActivities::IUserActivityContentInfo const& value) const;
    Windows::Foundation::IAsyncAction SaveAsync() const;
    Windows::ApplicationModel::UserActivities::UserActivitySession CreateSession() const;
};
template <> struct consume<Windows::ApplicationModel::UserActivities::IUserActivity> { template <typename D> using type = consume_Windows_ApplicationModel_UserActivities_IUserActivity<D>; };

template <typename D>
struct consume_Windows_ApplicationModel_UserActivities_IUserActivity2
{
    hstring ToJson() const;
};
template <> struct consume<Windows::ApplicationModel::UserActivities::IUserActivity2> { template <typename D> using type = consume_Windows_ApplicationModel_UserActivities_IUserActivity2<D>; };

template <typename D>
struct consume_Windows_ApplicationModel_UserActivities_IUserActivity3
{
    bool IsRoamable() const;
    void IsRoamable(bool value) const;
};
template <> struct consume<Windows::ApplicationModel::UserActivities::IUserActivity3> { template <typename D> using type = consume_Windows_ApplicationModel_UserActivities_IUserActivity3<D>; };

template <typename D>
struct consume_Windows_ApplicationModel_UserActivities_IUserActivityAttribution
{
    Windows::Foundation::Uri IconUri() const;
    void IconUri(Windows::Foundation::Uri const& value) const;
    hstring AlternateText() const;
    void AlternateText(param::hstring const& value) const;
    bool AddImageQuery() const;
    void AddImageQuery(bool value) const;
};
template <> struct consume<Windows::ApplicationModel::UserActivities::IUserActivityAttribution> { template <typename D> using type = consume_Windows_ApplicationModel_UserActivities_IUserActivityAttribution<D>; };

template <typename D>
struct consume_Windows_ApplicationModel_UserActivities_IUserActivityAttributionFactory
{
    Windows::ApplicationModel::UserActivities::UserActivityAttribution CreateWithUri(Windows::Foundation::Uri const& iconUri) const;
};
template <> struct consume<Windows::ApplicationModel::UserActivities::IUserActivityAttributionFactory> { template <typename D> using type = consume_Windows_ApplicationModel_UserActivities_IUserActivityAttributionFactory<D>; };

template <typename D>
struct consume_Windows_ApplicationModel_UserActivities_IUserActivityChannel
{
    Windows::Foundation::IAsyncOperation<Windows::ApplicationModel::UserActivities::UserActivity> GetOrCreateUserActivityAsync(param::hstring const& activityId) const;
    Windows::Foundation::IAsyncAction DeleteActivityAsync(param::hstring const& activityId) const;
    Windows::Foundation::IAsyncAction DeleteAllActivitiesAsync() const;
};
template <> struct consume<Windows::ApplicationModel::UserActivities::IUserActivityChannel> { template <typename D> using type = consume_Windows_ApplicationModel_UserActivities_IUserActivityChannel<D>; };

template <typename D>
struct consume_Windows_ApplicationModel_UserActivities_IUserActivityChannel2
{
    Windows::Foundation::IAsyncOperation<Windows::Foundation::Collections::IVector<Windows::ApplicationModel::UserActivities::UserActivitySessionHistoryItem>> GetRecentUserActivitiesAsync(int32_t maxUniqueActivities) const;
    Windows::Foundation::IAsyncOperation<Windows::Foundation::Collections::IVector<Windows::ApplicationModel::UserActivities::UserActivitySessionHistoryItem>> GetSessionHistoryItemsForUserActivityAsync(param::hstring const& activityId, Windows::Foundation::DateTime const& startTime) const;
};
template <> struct consume<Windows::ApplicationModel::UserActivities::IUserActivityChannel2> { template <typename D> using type = consume_Windows_ApplicationModel_UserActivities_IUserActivityChannel2<D>; };

template <typename D>
struct consume_Windows_ApplicationModel_UserActivities_IUserActivityChannelStatics
{
    Windows::ApplicationModel::UserActivities::UserActivityChannel GetDefault() const;
};
template <> struct consume<Windows::ApplicationModel::UserActivities::IUserActivityChannelStatics> { template <typename D> using type = consume_Windows_ApplicationModel_UserActivities_IUserActivityChannelStatics<D>; };

template <typename D>
struct consume_Windows_ApplicationModel_UserActivities_IUserActivityChannelStatics2
{
    void DisableAutoSessionCreation() const;
    Windows::ApplicationModel::UserActivities::UserActivityChannel TryGetForWebAccount(Windows::Security::Credentials::WebAccount const& account) const;
};
template <> struct consume<Windows::ApplicationModel::UserActivities::IUserActivityChannelStatics2> { template <typename D> using type = consume_Windows_ApplicationModel_UserActivities_IUserActivityChannelStatics2<D>; };

template <typename D>
struct consume_Windows_ApplicationModel_UserActivities_IUserActivityChannelStatics3
{
    Windows::ApplicationModel::UserActivities::UserActivityChannel GetForUser(Windows::System::User const& user) const;
};
template <> struct consume<Windows::ApplicationModel::UserActivities::IUserActivityChannelStatics3> { template <typename D> using type = consume_Windows_ApplicationModel_UserActivities_IUserActivityChannelStatics3<D>; };

template <typename D>
struct consume_Windows_ApplicationModel_UserActivities_IUserActivityContentInfo
{
    hstring ToJson() const;
};
template <> struct consume<Windows::ApplicationModel::UserActivities::IUserActivityContentInfo> { template <typename D> using type = consume_Windows_ApplicationModel_UserActivities_IUserActivityContentInfo<D>; };

template <typename D>
struct consume_Windows_ApplicationModel_UserActivities_IUserActivityContentInfoStatics
{
    Windows::ApplicationModel::UserActivities::UserActivityContentInfo FromJson(param::hstring const& value) const;
};
template <> struct consume<Windows::ApplicationModel::UserActivities::IUserActivityContentInfoStatics> { template <typename D> using type = consume_Windows_ApplicationModel_UserActivities_IUserActivityContentInfoStatics<D>; };

template <typename D>
struct consume_Windows_ApplicationModel_UserActivities_IUserActivityFactory
{
    Windows::ApplicationModel::UserActivities::UserActivity CreateWithActivityId(param::hstring const& activityId) const;
};
template <> struct consume<Windows::ApplicationModel::UserActivities::IUserActivityFactory> { template <typename D> using type = consume_Windows_ApplicationModel_UserActivities_IUserActivityFactory<D>; };

template <typename D>
struct consume_Windows_ApplicationModel_UserActivities_IUserActivityRequest
{
    void SetUserActivity(Windows::ApplicationModel::UserActivities::UserActivity const& activity) const;
};
template <> struct consume<Windows::ApplicationModel::UserActivities::IUserActivityRequest> { template <typename D> using type = consume_Windows_ApplicationModel_UserActivities_IUserActivityRequest<D>; };

template <typename D>
struct consume_Windows_ApplicationModel_UserActivities_IUserActivityRequestManager
{
    winrt::event_token UserActivityRequested(Windows::Foundation::TypedEventHandler<Windows::ApplicationModel::UserActivities::UserActivityRequestManager, Windows::ApplicationModel::UserActivities::UserActivityRequestedEventArgs> const& handler) const;
    using UserActivityRequested_revoker = impl::event_revoker<Windows::ApplicationModel::UserActivities::IUserActivityRequestManager, &impl::abi_t<Windows::ApplicationModel::UserActivities::IUserActivityRequestManager>::remove_UserActivityRequested>;
    UserActivityRequested_revoker UserActivityRequested(auto_revoke_t, Windows::Foundation::TypedEventHandler<Windows::ApplicationModel::UserActivities::UserActivityRequestManager, Windows::ApplicationModel::UserActivities::UserActivityRequestedEventArgs> const& handler) const;
    void UserActivityRequested(winrt::event_token const& token) const noexcept;
};
template <> struct consume<Windows::ApplicationModel::UserActivities::IUserActivityRequestManager> { template <typename D> using type = consume_Windows_ApplicationModel_UserActivities_IUserActivityRequestManager<D>; };

template <typename D>
struct consume_Windows_ApplicationModel_UserActivities_IUserActivityRequestManagerStatics
{
    Windows::ApplicationModel::UserActivities::UserActivityRequestManager GetForCurrentView() const;
};
template <> struct consume<Windows::ApplicationModel::UserActivities::IUserActivityRequestManagerStatics> { template <typename D> using type = consume_Windows_ApplicationModel_UserActivities_IUserActivityRequestManagerStatics<D>; };

template <typename D>
struct consume_Windows_ApplicationModel_UserActivities_IUserActivityRequestedEventArgs
{
    Windows::ApplicationModel::UserActivities::UserActivityRequest Request() const;
    Windows::Foundation::Deferral GetDeferral() const;
};
template <> struct consume<Windows::ApplicationModel::UserActivities::IUserActivityRequestedEventArgs> { template <typename D> using type = consume_Windows_ApplicationModel_UserActivities_IUserActivityRequestedEventArgs<D>; };

template <typename D>
struct consume_Windows_ApplicationModel_UserActivities_IUserActivitySession
{
    hstring ActivityId() const;
};
template <> struct consume<Windows::ApplicationModel::UserActivities::IUserActivitySession> { template <typename D> using type = consume_Windows_ApplicationModel_UserActivities_IUserActivitySession<D>; };

template <typename D>
struct consume_Windows_ApplicationModel_UserActivities_IUserActivitySessionHistoryItem
{
    Windows::ApplicationModel::UserActivities::UserActivity UserActivity() const;
    Windows::Foundation::DateTime StartTime() const;
    Windows::Foundation::IReference<Windows::Foundation::DateTime> EndTime() const;
};
template <> struct consume<Windows::ApplicationModel::UserActivities::IUserActivitySessionHistoryItem> { template <typename D> using type = consume_Windows_ApplicationModel_UserActivities_IUserActivitySessionHistoryItem<D>; };

template <typename D>
struct consume_Windows_ApplicationModel_UserActivities_IUserActivityStatics
{
    Windows::ApplicationModel::UserActivities::UserActivity TryParseFromJson(param::hstring const& json) const;
    Windows::Foundation::Collections::IVector<Windows::ApplicationModel::UserActivities::UserActivity> TryParseFromJsonArray(param::hstring const& json) const;
    hstring ToJsonArray(param::iterable<Windows::ApplicationModel::UserActivities::UserActivity> const& activities) const;
};
template <> struct consume<Windows::ApplicationModel::UserActivities::IUserActivityStatics> { template <typename D> using type = consume_Windows_ApplicationModel_UserActivities_IUserActivityStatics<D>; };

template <typename D>
struct consume_Windows_ApplicationModel_UserActivities_IUserActivityVisualElements
{
    hstring DisplayText() const;
    void DisplayText(param::hstring const& value) const;
    hstring Description() const;
    void Description(param::hstring const& value) const;
    Windows::UI::Color BackgroundColor() const;
    void BackgroundColor(Windows::UI::Color const& value) const;
    Windows::ApplicationModel::UserActivities::UserActivityAttribution Attribution() const;
    void Attribution(Windows::ApplicationModel::UserActivities::UserActivityAttribution const& value) const;
    void Content(Windows::UI::Shell::IAdaptiveCard const& value) const;
    Windows::UI::Shell::IAdaptiveCard Content() const;
};
template <> struct consume<Windows::ApplicationModel::UserActivities::IUserActivityVisualElements> { template <typename D> using type = consume_Windows_ApplicationModel_UserActivities_IUserActivityVisualElements<D>; };

template <typename D>
struct consume_Windows_ApplicationModel_UserActivities_IUserActivityVisualElements2
{
    hstring AttributionDisplayText() const;
    void AttributionDisplayText(param::hstring const& value) const;
};
template <> struct consume<Windows::ApplicationModel::UserActivities::IUserActivityVisualElements2> { template <typename D> using type = consume_Windows_ApplicationModel_UserActivities_IUserActivityVisualElements2<D>; };

}
