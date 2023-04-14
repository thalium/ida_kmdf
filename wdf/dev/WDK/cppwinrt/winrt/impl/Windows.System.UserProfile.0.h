// C++/WinRT v1.0.190111.3

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#pragma once

WINRT_EXPORT namespace winrt::Windows::Foundation {

struct Uri;

}

WINRT_EXPORT namespace winrt::Windows::Globalization {

enum class DayOfWeek;

}

WINRT_EXPORT namespace winrt::Windows::Storage {

struct IStorageFile;
struct StorageFile;

}

WINRT_EXPORT namespace winrt::Windows::Storage::Streams {

struct IRandomAccessStream;

}

WINRT_EXPORT namespace winrt::Windows::System {

struct User;

}

WINRT_EXPORT namespace winrt::Windows::System::UserProfile {

enum class AccountPictureKind : int32_t
{
    SmallImage = 0,
    LargeImage = 1,
    Video = 2,
};

enum class SetAccountPictureResult : int32_t
{
    Success = 0,
    ChangeDisabled = 1,
    LargeOrDynamicError = 2,
    VideoFrameSizeError = 3,
    FileSizeError = 4,
    Failure = 5,
};

enum class SetImageFeedResult : int32_t
{
    Success = 0,
    ChangeDisabled = 1,
    UserCanceled = 2,
};

struct IAdvertisingManagerForUser;
struct IAdvertisingManagerStatics;
struct IAdvertisingManagerStatics2;
struct IAssignedAccessSettings;
struct IAssignedAccessSettingsStatics;
struct IDiagnosticsSettings;
struct IDiagnosticsSettingsStatics;
struct IFirstSignInSettings;
struct IFirstSignInSettingsStatics;
struct IGlobalizationPreferencesForUser;
struct IGlobalizationPreferencesStatics;
struct IGlobalizationPreferencesStatics2;
struct IGlobalizationPreferencesStatics3;
struct ILockScreenImageFeedStatics;
struct ILockScreenStatics;
struct IUserInformationStatics;
struct IUserProfilePersonalizationSettings;
struct IUserProfilePersonalizationSettingsStatics;
struct AdvertisingManager;
struct AdvertisingManagerForUser;
struct AssignedAccessSettings;
struct DiagnosticsSettings;
struct FirstSignInSettings;
struct GlobalizationPreferences;
struct GlobalizationPreferencesForUser;
struct LockScreen;
struct UserInformation;
struct UserProfilePersonalizationSettings;

}

namespace winrt::impl {

template <> struct category<Windows::System::UserProfile::IAdvertisingManagerForUser>{ using type = interface_category; };
template <> struct category<Windows::System::UserProfile::IAdvertisingManagerStatics>{ using type = interface_category; };
template <> struct category<Windows::System::UserProfile::IAdvertisingManagerStatics2>{ using type = interface_category; };
template <> struct category<Windows::System::UserProfile::IAssignedAccessSettings>{ using type = interface_category; };
template <> struct category<Windows::System::UserProfile::IAssignedAccessSettingsStatics>{ using type = interface_category; };
template <> struct category<Windows::System::UserProfile::IDiagnosticsSettings>{ using type = interface_category; };
template <> struct category<Windows::System::UserProfile::IDiagnosticsSettingsStatics>{ using type = interface_category; };
template <> struct category<Windows::System::UserProfile::IFirstSignInSettings>{ using type = interface_category; };
template <> struct category<Windows::System::UserProfile::IFirstSignInSettingsStatics>{ using type = interface_category; };
template <> struct category<Windows::System::UserProfile::IGlobalizationPreferencesForUser>{ using type = interface_category; };
template <> struct category<Windows::System::UserProfile::IGlobalizationPreferencesStatics>{ using type = interface_category; };
template <> struct category<Windows::System::UserProfile::IGlobalizationPreferencesStatics2>{ using type = interface_category; };
template <> struct category<Windows::System::UserProfile::IGlobalizationPreferencesStatics3>{ using type = interface_category; };
template <> struct category<Windows::System::UserProfile::ILockScreenImageFeedStatics>{ using type = interface_category; };
template <> struct category<Windows::System::UserProfile::ILockScreenStatics>{ using type = interface_category; };
template <> struct category<Windows::System::UserProfile::IUserInformationStatics>{ using type = interface_category; };
template <> struct category<Windows::System::UserProfile::IUserProfilePersonalizationSettings>{ using type = interface_category; };
template <> struct category<Windows::System::UserProfile::IUserProfilePersonalizationSettingsStatics>{ using type = interface_category; };
template <> struct category<Windows::System::UserProfile::AdvertisingManager>{ using type = class_category; };
template <> struct category<Windows::System::UserProfile::AdvertisingManagerForUser>{ using type = class_category; };
template <> struct category<Windows::System::UserProfile::AssignedAccessSettings>{ using type = class_category; };
template <> struct category<Windows::System::UserProfile::DiagnosticsSettings>{ using type = class_category; };
template <> struct category<Windows::System::UserProfile::FirstSignInSettings>{ using type = class_category; };
template <> struct category<Windows::System::UserProfile::GlobalizationPreferences>{ using type = class_category; };
template <> struct category<Windows::System::UserProfile::GlobalizationPreferencesForUser>{ using type = class_category; };
template <> struct category<Windows::System::UserProfile::LockScreen>{ using type = class_category; };
template <> struct category<Windows::System::UserProfile::UserInformation>{ using type = class_category; };
template <> struct category<Windows::System::UserProfile::UserProfilePersonalizationSettings>{ using type = class_category; };
template <> struct category<Windows::System::UserProfile::AccountPictureKind>{ using type = enum_category; };
template <> struct category<Windows::System::UserProfile::SetAccountPictureResult>{ using type = enum_category; };
template <> struct category<Windows::System::UserProfile::SetImageFeedResult>{ using type = enum_category; };
template <> struct name<Windows::System::UserProfile::IAdvertisingManagerForUser>{ static constexpr auto & value{ L"Windows.System.UserProfile.IAdvertisingManagerForUser" }; };
template <> struct name<Windows::System::UserProfile::IAdvertisingManagerStatics>{ static constexpr auto & value{ L"Windows.System.UserProfile.IAdvertisingManagerStatics" }; };
template <> struct name<Windows::System::UserProfile::IAdvertisingManagerStatics2>{ static constexpr auto & value{ L"Windows.System.UserProfile.IAdvertisingManagerStatics2" }; };
template <> struct name<Windows::System::UserProfile::IAssignedAccessSettings>{ static constexpr auto & value{ L"Windows.System.UserProfile.IAssignedAccessSettings" }; };
template <> struct name<Windows::System::UserProfile::IAssignedAccessSettingsStatics>{ static constexpr auto & value{ L"Windows.System.UserProfile.IAssignedAccessSettingsStatics" }; };
template <> struct name<Windows::System::UserProfile::IDiagnosticsSettings>{ static constexpr auto & value{ L"Windows.System.UserProfile.IDiagnosticsSettings" }; };
template <> struct name<Windows::System::UserProfile::IDiagnosticsSettingsStatics>{ static constexpr auto & value{ L"Windows.System.UserProfile.IDiagnosticsSettingsStatics" }; };
template <> struct name<Windows::System::UserProfile::IFirstSignInSettings>{ static constexpr auto & value{ L"Windows.System.UserProfile.IFirstSignInSettings" }; };
template <> struct name<Windows::System::UserProfile::IFirstSignInSettingsStatics>{ static constexpr auto & value{ L"Windows.System.UserProfile.IFirstSignInSettingsStatics" }; };
template <> struct name<Windows::System::UserProfile::IGlobalizationPreferencesForUser>{ static constexpr auto & value{ L"Windows.System.UserProfile.IGlobalizationPreferencesForUser" }; };
template <> struct name<Windows::System::UserProfile::IGlobalizationPreferencesStatics>{ static constexpr auto & value{ L"Windows.System.UserProfile.IGlobalizationPreferencesStatics" }; };
template <> struct name<Windows::System::UserProfile::IGlobalizationPreferencesStatics2>{ static constexpr auto & value{ L"Windows.System.UserProfile.IGlobalizationPreferencesStatics2" }; };
template <> struct name<Windows::System::UserProfile::IGlobalizationPreferencesStatics3>{ static constexpr auto & value{ L"Windows.System.UserProfile.IGlobalizationPreferencesStatics3" }; };
template <> struct name<Windows::System::UserProfile::ILockScreenImageFeedStatics>{ static constexpr auto & value{ L"Windows.System.UserProfile.ILockScreenImageFeedStatics" }; };
template <> struct name<Windows::System::UserProfile::ILockScreenStatics>{ static constexpr auto & value{ L"Windows.System.UserProfile.ILockScreenStatics" }; };
template <> struct name<Windows::System::UserProfile::IUserInformationStatics>{ static constexpr auto & value{ L"Windows.System.UserProfile.IUserInformationStatics" }; };
template <> struct name<Windows::System::UserProfile::IUserProfilePersonalizationSettings>{ static constexpr auto & value{ L"Windows.System.UserProfile.IUserProfilePersonalizationSettings" }; };
template <> struct name<Windows::System::UserProfile::IUserProfilePersonalizationSettingsStatics>{ static constexpr auto & value{ L"Windows.System.UserProfile.IUserProfilePersonalizationSettingsStatics" }; };
template <> struct name<Windows::System::UserProfile::AdvertisingManager>{ static constexpr auto & value{ L"Windows.System.UserProfile.AdvertisingManager" }; };
template <> struct name<Windows::System::UserProfile::AdvertisingManagerForUser>{ static constexpr auto & value{ L"Windows.System.UserProfile.AdvertisingManagerForUser" }; };
template <> struct name<Windows::System::UserProfile::AssignedAccessSettings>{ static constexpr auto & value{ L"Windows.System.UserProfile.AssignedAccessSettings" }; };
template <> struct name<Windows::System::UserProfile::DiagnosticsSettings>{ static constexpr auto & value{ L"Windows.System.UserProfile.DiagnosticsSettings" }; };
template <> struct name<Windows::System::UserProfile::FirstSignInSettings>{ static constexpr auto & value{ L"Windows.System.UserProfile.FirstSignInSettings" }; };
template <> struct name<Windows::System::UserProfile::GlobalizationPreferences>{ static constexpr auto & value{ L"Windows.System.UserProfile.GlobalizationPreferences" }; };
template <> struct name<Windows::System::UserProfile::GlobalizationPreferencesForUser>{ static constexpr auto & value{ L"Windows.System.UserProfile.GlobalizationPreferencesForUser" }; };
template <> struct name<Windows::System::UserProfile::LockScreen>{ static constexpr auto & value{ L"Windows.System.UserProfile.LockScreen" }; };
template <> struct name<Windows::System::UserProfile::UserInformation>{ static constexpr auto & value{ L"Windows.System.UserProfile.UserInformation" }; };
template <> struct name<Windows::System::UserProfile::UserProfilePersonalizationSettings>{ static constexpr auto & value{ L"Windows.System.UserProfile.UserProfilePersonalizationSettings" }; };
template <> struct name<Windows::System::UserProfile::AccountPictureKind>{ static constexpr auto & value{ L"Windows.System.UserProfile.AccountPictureKind" }; };
template <> struct name<Windows::System::UserProfile::SetAccountPictureResult>{ static constexpr auto & value{ L"Windows.System.UserProfile.SetAccountPictureResult" }; };
template <> struct name<Windows::System::UserProfile::SetImageFeedResult>{ static constexpr auto & value{ L"Windows.System.UserProfile.SetImageFeedResult" }; };
template <> struct guid_storage<Windows::System::UserProfile::IAdvertisingManagerForUser>{ static constexpr guid value{ 0x928BF3D0,0xCF7C,0x4AB0,{ 0xA7,0xDC,0x6D,0xC5,0xBC,0xD4,0x42,0x52 } }; };
template <> struct guid_storage<Windows::System::UserProfile::IAdvertisingManagerStatics>{ static constexpr guid value{ 0xADD3468C,0xA273,0x48CB,{ 0xB3,0x46,0x35,0x44,0x52,0x2D,0x55,0x81 } }; };
template <> struct guid_storage<Windows::System::UserProfile::IAdvertisingManagerStatics2>{ static constexpr guid value{ 0xDD0947AF,0x1A6D,0x46B0,{ 0x95,0xBC,0xF3,0xF9,0xD6,0xBE,0xB9,0xFB } }; };
template <> struct guid_storage<Windows::System::UserProfile::IAssignedAccessSettings>{ static constexpr guid value{ 0x1BC57F1C,0xE971,0x5757,{ 0xB8,0xE0,0x51,0x2F,0x8B,0x8C,0x46,0xD2 } }; };
template <> struct guid_storage<Windows::System::UserProfile::IAssignedAccessSettingsStatics>{ static constexpr guid value{ 0x34A81D0D,0x8A29,0x5EF3,{ 0xA7,0xBE,0x61,0x8E,0x6A,0xC3,0xBD,0x01 } }; };
template <> struct guid_storage<Windows::System::UserProfile::IDiagnosticsSettings>{ static constexpr guid value{ 0xE5E9ECCD,0x2711,0x44E0,{ 0x97,0x3C,0x49,0x1D,0x78,0x04,0x8D,0x24 } }; };
template <> struct guid_storage<Windows::System::UserProfile::IDiagnosticsSettingsStatics>{ static constexpr guid value{ 0x72D2E80F,0x5390,0x4793,{ 0x99,0x0B,0x3C,0xCC,0x7D,0x6A,0xC9,0xC8 } }; };
template <> struct guid_storage<Windows::System::UserProfile::IFirstSignInSettings>{ static constexpr guid value{ 0x3E945153,0x3A5E,0x452E,{ 0xA6,0x01,0xF5,0xBA,0xAD,0x2A,0x48,0x70 } }; };
template <> struct guid_storage<Windows::System::UserProfile::IFirstSignInSettingsStatics>{ static constexpr guid value{ 0x1CE18F0F,0x1C41,0x4EA0,{ 0xB7,0xA2,0x6F,0x0C,0x1C,0x7E,0x84,0x38 } }; };
template <> struct guid_storage<Windows::System::UserProfile::IGlobalizationPreferencesForUser>{ static constexpr guid value{ 0x150F0795,0x4F6E,0x40BA,{ 0xA0,0x10,0xE2,0x7D,0x81,0xBD,0xA7,0xF5 } }; };
template <> struct guid_storage<Windows::System::UserProfile::IGlobalizationPreferencesStatics>{ static constexpr guid value{ 0x01BF4326,0xED37,0x4E96,{ 0xB0,0xE9,0xC1,0x34,0x0D,0x1E,0xA1,0x58 } }; };
template <> struct guid_storage<Windows::System::UserProfile::IGlobalizationPreferencesStatics2>{ static constexpr guid value{ 0xFCCE85F1,0x4300,0x4CD0,{ 0x9C,0xAC,0x1A,0x8E,0x7B,0x7E,0x18,0xF4 } }; };
template <> struct guid_storage<Windows::System::UserProfile::IGlobalizationPreferencesStatics3>{ static constexpr guid value{ 0x1E059733,0x35F5,0x40D8,{ 0xB9,0xE8,0xAE,0xF3,0xEF,0x85,0x6F,0xCE } }; };
template <> struct guid_storage<Windows::System::UserProfile::ILockScreenImageFeedStatics>{ static constexpr guid value{ 0x2C0D73F6,0x03A9,0x41A6,{ 0x9B,0x01,0x49,0x52,0x51,0xFF,0x51,0xD5 } }; };
template <> struct guid_storage<Windows::System::UserProfile::ILockScreenStatics>{ static constexpr guid value{ 0x3EE9D3AD,0xB607,0x40AE,{ 0xB4,0x26,0x76,0x31,0xD9,0x82,0x12,0x69 } }; };
template <> struct guid_storage<Windows::System::UserProfile::IUserInformationStatics>{ static constexpr guid value{ 0x77F3A910,0x48FA,0x489C,{ 0x93,0x4E,0x2A,0xE8,0x5B,0xA8,0xF7,0x72 } }; };
template <> struct guid_storage<Windows::System::UserProfile::IUserProfilePersonalizationSettings>{ static constexpr guid value{ 0x8CEDDAB4,0x7998,0x46D5,{ 0x8D,0xD3,0x18,0x4F,0x1C,0x5F,0x9A,0xB9 } }; };
template <> struct guid_storage<Windows::System::UserProfile::IUserProfilePersonalizationSettingsStatics>{ static constexpr guid value{ 0x91ACB841,0x5037,0x454B,{ 0x98,0x83,0xBB,0x77,0x2D,0x08,0xDD,0x16 } }; };
template <> struct default_interface<Windows::System::UserProfile::AdvertisingManagerForUser>{ using type = Windows::System::UserProfile::IAdvertisingManagerForUser; };
template <> struct default_interface<Windows::System::UserProfile::AssignedAccessSettings>{ using type = Windows::System::UserProfile::IAssignedAccessSettings; };
template <> struct default_interface<Windows::System::UserProfile::DiagnosticsSettings>{ using type = Windows::System::UserProfile::IDiagnosticsSettings; };
template <> struct default_interface<Windows::System::UserProfile::FirstSignInSettings>{ using type = Windows::System::UserProfile::IFirstSignInSettings; };
template <> struct default_interface<Windows::System::UserProfile::GlobalizationPreferencesForUser>{ using type = Windows::System::UserProfile::IGlobalizationPreferencesForUser; };
template <> struct default_interface<Windows::System::UserProfile::UserProfilePersonalizationSettings>{ using type = Windows::System::UserProfile::IUserProfilePersonalizationSettings; };

template <> struct abi<Windows::System::UserProfile::IAdvertisingManagerForUser>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL get_AdvertisingId(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_User(void** value) noexcept = 0;
};};

template <> struct abi<Windows::System::UserProfile::IAdvertisingManagerStatics>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL get_AdvertisingId(void** value) noexcept = 0;
};};

template <> struct abi<Windows::System::UserProfile::IAdvertisingManagerStatics2>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL GetForUser(void* user, void** value) noexcept = 0;
};};

template <> struct abi<Windows::System::UserProfile::IAssignedAccessSettings>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL get_IsEnabled(bool* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_IsSingleAppKioskMode(bool* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_User(void** value) noexcept = 0;
};};

template <> struct abi<Windows::System::UserProfile::IAssignedAccessSettingsStatics>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL GetDefault(void** result) noexcept = 0;
    virtual int32_t WINRT_CALL GetForUser(void* user, void** result) noexcept = 0;
};};

template <> struct abi<Windows::System::UserProfile::IDiagnosticsSettings>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL get_CanUseDiagnosticsToTailorExperiences(bool* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_User(void** value) noexcept = 0;
};};

template <> struct abi<Windows::System::UserProfile::IDiagnosticsSettingsStatics>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL GetDefault(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL GetForUser(void* user, void** value) noexcept = 0;
};};

template <> struct abi<Windows::System::UserProfile::IFirstSignInSettings>{ struct type : IInspectable
{
};};

template <> struct abi<Windows::System::UserProfile::IFirstSignInSettingsStatics>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL GetDefault(void** result) noexcept = 0;
};};

template <> struct abi<Windows::System::UserProfile::IGlobalizationPreferencesForUser>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL get_User(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_Calendars(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_Clocks(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_Currencies(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_Languages(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_HomeGeographicRegion(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_WeekStartsOn(Windows::Globalization::DayOfWeek* value) noexcept = 0;
};};

template <> struct abi<Windows::System::UserProfile::IGlobalizationPreferencesStatics>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL get_Calendars(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_Clocks(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_Currencies(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_Languages(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_HomeGeographicRegion(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_WeekStartsOn(Windows::Globalization::DayOfWeek* value) noexcept = 0;
};};

template <> struct abi<Windows::System::UserProfile::IGlobalizationPreferencesStatics2>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL TrySetHomeGeographicRegion(void* region, bool* result) noexcept = 0;
    virtual int32_t WINRT_CALL TrySetLanguages(void* languageTags, bool* result) noexcept = 0;
};};

template <> struct abi<Windows::System::UserProfile::IGlobalizationPreferencesStatics3>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL GetForUser(void* user, void** value) noexcept = 0;
};};

template <> struct abi<Windows::System::UserProfile::ILockScreenImageFeedStatics>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL RequestSetImageFeedAsync(void* syndicationFeedUri, void** value) noexcept = 0;
    virtual int32_t WINRT_CALL TryRemoveImageFeed(bool* result) noexcept = 0;
};};

template <> struct abi<Windows::System::UserProfile::ILockScreenStatics>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL get_OriginalImageFile(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL GetImageStream(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL SetImageFileAsync(void* value, void** Operation) noexcept = 0;
    virtual int32_t WINRT_CALL SetImageStreamAsync(void* value, void** Operation) noexcept = 0;
};};

template <> struct abi<Windows::System::UserProfile::IUserInformationStatics>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL get_AccountPictureChangeEnabled(bool* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_NameAccessAllowed(bool* value) noexcept = 0;
    virtual int32_t WINRT_CALL GetAccountPicture(Windows::System::UserProfile::AccountPictureKind kind, void** storageFile) noexcept = 0;
    virtual int32_t WINRT_CALL SetAccountPictureAsync(void* image, void** operation) noexcept = 0;
    virtual int32_t WINRT_CALL SetAccountPicturesAsync(void* smallImage, void* largeImage, void* video, void** operation) noexcept = 0;
    virtual int32_t WINRT_CALL SetAccountPictureFromStreamAsync(void* image, void** operation) noexcept = 0;
    virtual int32_t WINRT_CALL SetAccountPicturesFromStreamsAsync(void* smallImage, void* largeImage, void* video, void** operation) noexcept = 0;
    virtual int32_t WINRT_CALL add_AccountPictureChanged(void* changeHandler, winrt::event_token* token) noexcept = 0;
    virtual int32_t WINRT_CALL remove_AccountPictureChanged(winrt::event_token token) noexcept = 0;
    virtual int32_t WINRT_CALL GetDisplayNameAsync(void** operation) noexcept = 0;
    virtual int32_t WINRT_CALL GetFirstNameAsync(void** operation) noexcept = 0;
    virtual int32_t WINRT_CALL GetLastNameAsync(void** operation) noexcept = 0;
    virtual int32_t WINRT_CALL GetPrincipalNameAsync(void** operation) noexcept = 0;
    virtual int32_t WINRT_CALL GetSessionInitiationProtocolUriAsync(void** operation) noexcept = 0;
    virtual int32_t WINRT_CALL GetDomainNameAsync(void** operation) noexcept = 0;
};};

template <> struct abi<Windows::System::UserProfile::IUserProfilePersonalizationSettings>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL TrySetLockScreenImageAsync(void* imageFile, void** operation) noexcept = 0;
    virtual int32_t WINRT_CALL TrySetWallpaperImageAsync(void* imageFile, void** operation) noexcept = 0;
};};

template <> struct abi<Windows::System::UserProfile::IUserProfilePersonalizationSettingsStatics>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL get_Current(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL IsSupported(bool* result) noexcept = 0;
};};

template <typename D>
struct consume_Windows_System_UserProfile_IAdvertisingManagerForUser
{
    hstring AdvertisingId() const;
    Windows::System::User User() const;
};
template <> struct consume<Windows::System::UserProfile::IAdvertisingManagerForUser> { template <typename D> using type = consume_Windows_System_UserProfile_IAdvertisingManagerForUser<D>; };

template <typename D>
struct consume_Windows_System_UserProfile_IAdvertisingManagerStatics
{
    hstring AdvertisingId() const;
};
template <> struct consume<Windows::System::UserProfile::IAdvertisingManagerStatics> { template <typename D> using type = consume_Windows_System_UserProfile_IAdvertisingManagerStatics<D>; };

template <typename D>
struct consume_Windows_System_UserProfile_IAdvertisingManagerStatics2
{
    Windows::System::UserProfile::AdvertisingManagerForUser GetForUser(Windows::System::User const& user) const;
};
template <> struct consume<Windows::System::UserProfile::IAdvertisingManagerStatics2> { template <typename D> using type = consume_Windows_System_UserProfile_IAdvertisingManagerStatics2<D>; };

template <typename D>
struct consume_Windows_System_UserProfile_IAssignedAccessSettings
{
    bool IsEnabled() const;
    bool IsSingleAppKioskMode() const;
    Windows::System::User User() const;
};
template <> struct consume<Windows::System::UserProfile::IAssignedAccessSettings> { template <typename D> using type = consume_Windows_System_UserProfile_IAssignedAccessSettings<D>; };

template <typename D>
struct consume_Windows_System_UserProfile_IAssignedAccessSettingsStatics
{
    Windows::System::UserProfile::AssignedAccessSettings GetDefault() const;
    Windows::System::UserProfile::AssignedAccessSettings GetForUser(Windows::System::User const& user) const;
};
template <> struct consume<Windows::System::UserProfile::IAssignedAccessSettingsStatics> { template <typename D> using type = consume_Windows_System_UserProfile_IAssignedAccessSettingsStatics<D>; };

template <typename D>
struct consume_Windows_System_UserProfile_IDiagnosticsSettings
{
    bool CanUseDiagnosticsToTailorExperiences() const;
    Windows::System::User User() const;
};
template <> struct consume<Windows::System::UserProfile::IDiagnosticsSettings> { template <typename D> using type = consume_Windows_System_UserProfile_IDiagnosticsSettings<D>; };

template <typename D>
struct consume_Windows_System_UserProfile_IDiagnosticsSettingsStatics
{
    Windows::System::UserProfile::DiagnosticsSettings GetDefault() const;
    Windows::System::UserProfile::DiagnosticsSettings GetForUser(Windows::System::User const& user) const;
};
template <> struct consume<Windows::System::UserProfile::IDiagnosticsSettingsStatics> { template <typename D> using type = consume_Windows_System_UserProfile_IDiagnosticsSettingsStatics<D>; };

template <typename D>
struct consume_Windows_System_UserProfile_IFirstSignInSettings
{
};
template <> struct consume<Windows::System::UserProfile::IFirstSignInSettings> { template <typename D> using type = consume_Windows_System_UserProfile_IFirstSignInSettings<D>; };

template <typename D>
struct consume_Windows_System_UserProfile_IFirstSignInSettingsStatics
{
    Windows::System::UserProfile::FirstSignInSettings GetDefault() const;
};
template <> struct consume<Windows::System::UserProfile::IFirstSignInSettingsStatics> { template <typename D> using type = consume_Windows_System_UserProfile_IFirstSignInSettingsStatics<D>; };

template <typename D>
struct consume_Windows_System_UserProfile_IGlobalizationPreferencesForUser
{
    Windows::System::User User() const;
    Windows::Foundation::Collections::IVectorView<hstring> Calendars() const;
    Windows::Foundation::Collections::IVectorView<hstring> Clocks() const;
    Windows::Foundation::Collections::IVectorView<hstring> Currencies() const;
    Windows::Foundation::Collections::IVectorView<hstring> Languages() const;
    hstring HomeGeographicRegion() const;
    Windows::Globalization::DayOfWeek WeekStartsOn() const;
};
template <> struct consume<Windows::System::UserProfile::IGlobalizationPreferencesForUser> { template <typename D> using type = consume_Windows_System_UserProfile_IGlobalizationPreferencesForUser<D>; };

template <typename D>
struct consume_Windows_System_UserProfile_IGlobalizationPreferencesStatics
{
    Windows::Foundation::Collections::IVectorView<hstring> Calendars() const;
    Windows::Foundation::Collections::IVectorView<hstring> Clocks() const;
    Windows::Foundation::Collections::IVectorView<hstring> Currencies() const;
    Windows::Foundation::Collections::IVectorView<hstring> Languages() const;
    hstring HomeGeographicRegion() const;
    Windows::Globalization::DayOfWeek WeekStartsOn() const;
};
template <> struct consume<Windows::System::UserProfile::IGlobalizationPreferencesStatics> { template <typename D> using type = consume_Windows_System_UserProfile_IGlobalizationPreferencesStatics<D>; };

template <typename D>
struct consume_Windows_System_UserProfile_IGlobalizationPreferencesStatics2
{
    bool TrySetHomeGeographicRegion(param::hstring const& region) const;
    bool TrySetLanguages(param::iterable<hstring> const& languageTags) const;
};
template <> struct consume<Windows::System::UserProfile::IGlobalizationPreferencesStatics2> { template <typename D> using type = consume_Windows_System_UserProfile_IGlobalizationPreferencesStatics2<D>; };

template <typename D>
struct consume_Windows_System_UserProfile_IGlobalizationPreferencesStatics3
{
    Windows::System::UserProfile::GlobalizationPreferencesForUser GetForUser(Windows::System::User const& user) const;
};
template <> struct consume<Windows::System::UserProfile::IGlobalizationPreferencesStatics3> { template <typename D> using type = consume_Windows_System_UserProfile_IGlobalizationPreferencesStatics3<D>; };

template <typename D>
struct consume_Windows_System_UserProfile_ILockScreenImageFeedStatics
{
    Windows::Foundation::IAsyncOperation<Windows::System::UserProfile::SetImageFeedResult> RequestSetImageFeedAsync(Windows::Foundation::Uri const& syndicationFeedUri) const;
    bool TryRemoveImageFeed() const;
};
template <> struct consume<Windows::System::UserProfile::ILockScreenImageFeedStatics> { template <typename D> using type = consume_Windows_System_UserProfile_ILockScreenImageFeedStatics<D>; };

template <typename D>
struct consume_Windows_System_UserProfile_ILockScreenStatics
{
    Windows::Foundation::Uri OriginalImageFile() const;
    Windows::Storage::Streams::IRandomAccessStream GetImageStream() const;
    Windows::Foundation::IAsyncAction SetImageFileAsync(Windows::Storage::IStorageFile const& value) const;
    Windows::Foundation::IAsyncAction SetImageStreamAsync(Windows::Storage::Streams::IRandomAccessStream const& value) const;
};
template <> struct consume<Windows::System::UserProfile::ILockScreenStatics> { template <typename D> using type = consume_Windows_System_UserProfile_ILockScreenStatics<D>; };

template <typename D>
struct consume_Windows_System_UserProfile_IUserInformationStatics
{
    bool AccountPictureChangeEnabled() const;
    bool NameAccessAllowed() const;
    Windows::Storage::IStorageFile GetAccountPicture(Windows::System::UserProfile::AccountPictureKind const& kind) const;
    Windows::Foundation::IAsyncOperation<Windows::System::UserProfile::SetAccountPictureResult> SetAccountPictureAsync(Windows::Storage::IStorageFile const& image) const;
    Windows::Foundation::IAsyncOperation<Windows::System::UserProfile::SetAccountPictureResult> SetAccountPicturesAsync(Windows::Storage::IStorageFile const& smallImage, Windows::Storage::IStorageFile const& largeImage, Windows::Storage::IStorageFile const& video) const;
    Windows::Foundation::IAsyncOperation<Windows::System::UserProfile::SetAccountPictureResult> SetAccountPictureFromStreamAsync(Windows::Storage::Streams::IRandomAccessStream const& image) const;
    Windows::Foundation::IAsyncOperation<Windows::System::UserProfile::SetAccountPictureResult> SetAccountPicturesFromStreamsAsync(Windows::Storage::Streams::IRandomAccessStream const& smallImage, Windows::Storage::Streams::IRandomAccessStream const& largeImage, Windows::Storage::Streams::IRandomAccessStream const& video) const;
    winrt::event_token AccountPictureChanged(Windows::Foundation::EventHandler<Windows::Foundation::IInspectable> const& changeHandler) const;
    using AccountPictureChanged_revoker = impl::event_revoker<Windows::System::UserProfile::IUserInformationStatics, &impl::abi_t<Windows::System::UserProfile::IUserInformationStatics>::remove_AccountPictureChanged>;
    AccountPictureChanged_revoker AccountPictureChanged(auto_revoke_t, Windows::Foundation::EventHandler<Windows::Foundation::IInspectable> const& changeHandler) const;
    void AccountPictureChanged(winrt::event_token const& token) const noexcept;
    Windows::Foundation::IAsyncOperation<hstring> GetDisplayNameAsync() const;
    Windows::Foundation::IAsyncOperation<hstring> GetFirstNameAsync() const;
    Windows::Foundation::IAsyncOperation<hstring> GetLastNameAsync() const;
    Windows::Foundation::IAsyncOperation<hstring> GetPrincipalNameAsync() const;
    Windows::Foundation::IAsyncOperation<Windows::Foundation::Uri> GetSessionInitiationProtocolUriAsync() const;
    Windows::Foundation::IAsyncOperation<hstring> GetDomainNameAsync() const;
};
template <> struct consume<Windows::System::UserProfile::IUserInformationStatics> { template <typename D> using type = consume_Windows_System_UserProfile_IUserInformationStatics<D>; };

template <typename D>
struct consume_Windows_System_UserProfile_IUserProfilePersonalizationSettings
{
    Windows::Foundation::IAsyncOperation<bool> TrySetLockScreenImageAsync(Windows::Storage::StorageFile const& imageFile) const;
    Windows::Foundation::IAsyncOperation<bool> TrySetWallpaperImageAsync(Windows::Storage::StorageFile const& imageFile) const;
};
template <> struct consume<Windows::System::UserProfile::IUserProfilePersonalizationSettings> { template <typename D> using type = consume_Windows_System_UserProfile_IUserProfilePersonalizationSettings<D>; };

template <typename D>
struct consume_Windows_System_UserProfile_IUserProfilePersonalizationSettingsStatics
{
    Windows::System::UserProfile::UserProfilePersonalizationSettings Current() const;
    bool IsSupported() const;
};
template <> struct consume<Windows::System::UserProfile::IUserProfilePersonalizationSettingsStatics> { template <typename D> using type = consume_Windows_System_UserProfile_IUserProfilePersonalizationSettingsStatics<D>; };

}
