// C++/WinRT v1.0.190111.3

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#pragma once

#include "winrt/base.h"

#include "winrt/Windows.Foundation.h"
#include "winrt/Windows.Foundation.Collections.h"
#include "winrt/impl/Windows.Foundation.2.h"
#include "winrt/impl/Windows.Globalization.2.h"
#include "winrt/impl/Windows.Storage.2.h"
#include "winrt/impl/Windows.Storage.Streams.2.h"
#include "winrt/impl/Windows.System.2.h"
#include "winrt/impl/Windows.Foundation.Collections.2.h"
#include "winrt/impl/Windows.System.UserProfile.2.h"
#include "winrt/Windows.System.h"

namespace winrt::impl {

template <typename D> hstring consume_Windows_System_UserProfile_IAdvertisingManagerForUser<D>::AdvertisingId() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::System::UserProfile::IAdvertisingManagerForUser)->get_AdvertisingId(put_abi(value)));
    return value;
}

template <typename D> Windows::System::User consume_Windows_System_UserProfile_IAdvertisingManagerForUser<D>::User() const
{
    Windows::System::User value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::System::UserProfile::IAdvertisingManagerForUser)->get_User(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_System_UserProfile_IAdvertisingManagerStatics<D>::AdvertisingId() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::System::UserProfile::IAdvertisingManagerStatics)->get_AdvertisingId(put_abi(value)));
    return value;
}

template <typename D> Windows::System::UserProfile::AdvertisingManagerForUser consume_Windows_System_UserProfile_IAdvertisingManagerStatics2<D>::GetForUser(Windows::System::User const& user) const
{
    Windows::System::UserProfile::AdvertisingManagerForUser value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::System::UserProfile::IAdvertisingManagerStatics2)->GetForUser(get_abi(user), put_abi(value)));
    return value;
}

template <typename D> bool consume_Windows_System_UserProfile_IAssignedAccessSettings<D>::IsEnabled() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::System::UserProfile::IAssignedAccessSettings)->get_IsEnabled(&value));
    return value;
}

template <typename D> bool consume_Windows_System_UserProfile_IAssignedAccessSettings<D>::IsSingleAppKioskMode() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::System::UserProfile::IAssignedAccessSettings)->get_IsSingleAppKioskMode(&value));
    return value;
}

template <typename D> Windows::System::User consume_Windows_System_UserProfile_IAssignedAccessSettings<D>::User() const
{
    Windows::System::User value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::System::UserProfile::IAssignedAccessSettings)->get_User(put_abi(value)));
    return value;
}

template <typename D> Windows::System::UserProfile::AssignedAccessSettings consume_Windows_System_UserProfile_IAssignedAccessSettingsStatics<D>::GetDefault() const
{
    Windows::System::UserProfile::AssignedAccessSettings result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::System::UserProfile::IAssignedAccessSettingsStatics)->GetDefault(put_abi(result)));
    return result;
}

template <typename D> Windows::System::UserProfile::AssignedAccessSettings consume_Windows_System_UserProfile_IAssignedAccessSettingsStatics<D>::GetForUser(Windows::System::User const& user) const
{
    Windows::System::UserProfile::AssignedAccessSettings result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::System::UserProfile::IAssignedAccessSettingsStatics)->GetForUser(get_abi(user), put_abi(result)));
    return result;
}

template <typename D> bool consume_Windows_System_UserProfile_IDiagnosticsSettings<D>::CanUseDiagnosticsToTailorExperiences() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::System::UserProfile::IDiagnosticsSettings)->get_CanUseDiagnosticsToTailorExperiences(&value));
    return value;
}

template <typename D> Windows::System::User consume_Windows_System_UserProfile_IDiagnosticsSettings<D>::User() const
{
    Windows::System::User value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::System::UserProfile::IDiagnosticsSettings)->get_User(put_abi(value)));
    return value;
}

template <typename D> Windows::System::UserProfile::DiagnosticsSettings consume_Windows_System_UserProfile_IDiagnosticsSettingsStatics<D>::GetDefault() const
{
    Windows::System::UserProfile::DiagnosticsSettings value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::System::UserProfile::IDiagnosticsSettingsStatics)->GetDefault(put_abi(value)));
    return value;
}

template <typename D> Windows::System::UserProfile::DiagnosticsSettings consume_Windows_System_UserProfile_IDiagnosticsSettingsStatics<D>::GetForUser(Windows::System::User const& user) const
{
    Windows::System::UserProfile::DiagnosticsSettings value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::System::UserProfile::IDiagnosticsSettingsStatics)->GetForUser(get_abi(user), put_abi(value)));
    return value;
}

template <typename D> Windows::System::UserProfile::FirstSignInSettings consume_Windows_System_UserProfile_IFirstSignInSettingsStatics<D>::GetDefault() const
{
    Windows::System::UserProfile::FirstSignInSettings result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::System::UserProfile::IFirstSignInSettingsStatics)->GetDefault(put_abi(result)));
    return result;
}

template <typename D> Windows::System::User consume_Windows_System_UserProfile_IGlobalizationPreferencesForUser<D>::User() const
{
    Windows::System::User value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::System::UserProfile::IGlobalizationPreferencesForUser)->get_User(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::Collections::IVectorView<hstring> consume_Windows_System_UserProfile_IGlobalizationPreferencesForUser<D>::Calendars() const
{
    Windows::Foundation::Collections::IVectorView<hstring> value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::System::UserProfile::IGlobalizationPreferencesForUser)->get_Calendars(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::Collections::IVectorView<hstring> consume_Windows_System_UserProfile_IGlobalizationPreferencesForUser<D>::Clocks() const
{
    Windows::Foundation::Collections::IVectorView<hstring> value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::System::UserProfile::IGlobalizationPreferencesForUser)->get_Clocks(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::Collections::IVectorView<hstring> consume_Windows_System_UserProfile_IGlobalizationPreferencesForUser<D>::Currencies() const
{
    Windows::Foundation::Collections::IVectorView<hstring> value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::System::UserProfile::IGlobalizationPreferencesForUser)->get_Currencies(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::Collections::IVectorView<hstring> consume_Windows_System_UserProfile_IGlobalizationPreferencesForUser<D>::Languages() const
{
    Windows::Foundation::Collections::IVectorView<hstring> value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::System::UserProfile::IGlobalizationPreferencesForUser)->get_Languages(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_System_UserProfile_IGlobalizationPreferencesForUser<D>::HomeGeographicRegion() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::System::UserProfile::IGlobalizationPreferencesForUser)->get_HomeGeographicRegion(put_abi(value)));
    return value;
}

template <typename D> Windows::Globalization::DayOfWeek consume_Windows_System_UserProfile_IGlobalizationPreferencesForUser<D>::WeekStartsOn() const
{
    Windows::Globalization::DayOfWeek value{};
    check_hresult(WINRT_SHIM(Windows::System::UserProfile::IGlobalizationPreferencesForUser)->get_WeekStartsOn(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::Collections::IVectorView<hstring> consume_Windows_System_UserProfile_IGlobalizationPreferencesStatics<D>::Calendars() const
{
    Windows::Foundation::Collections::IVectorView<hstring> value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::System::UserProfile::IGlobalizationPreferencesStatics)->get_Calendars(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::Collections::IVectorView<hstring> consume_Windows_System_UserProfile_IGlobalizationPreferencesStatics<D>::Clocks() const
{
    Windows::Foundation::Collections::IVectorView<hstring> value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::System::UserProfile::IGlobalizationPreferencesStatics)->get_Clocks(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::Collections::IVectorView<hstring> consume_Windows_System_UserProfile_IGlobalizationPreferencesStatics<D>::Currencies() const
{
    Windows::Foundation::Collections::IVectorView<hstring> value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::System::UserProfile::IGlobalizationPreferencesStatics)->get_Currencies(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::Collections::IVectorView<hstring> consume_Windows_System_UserProfile_IGlobalizationPreferencesStatics<D>::Languages() const
{
    Windows::Foundation::Collections::IVectorView<hstring> value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::System::UserProfile::IGlobalizationPreferencesStatics)->get_Languages(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_System_UserProfile_IGlobalizationPreferencesStatics<D>::HomeGeographicRegion() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::System::UserProfile::IGlobalizationPreferencesStatics)->get_HomeGeographicRegion(put_abi(value)));
    return value;
}

template <typename D> Windows::Globalization::DayOfWeek consume_Windows_System_UserProfile_IGlobalizationPreferencesStatics<D>::WeekStartsOn() const
{
    Windows::Globalization::DayOfWeek value{};
    check_hresult(WINRT_SHIM(Windows::System::UserProfile::IGlobalizationPreferencesStatics)->get_WeekStartsOn(put_abi(value)));
    return value;
}

template <typename D> bool consume_Windows_System_UserProfile_IGlobalizationPreferencesStatics2<D>::TrySetHomeGeographicRegion(param::hstring const& region) const
{
    bool result{};
    check_hresult(WINRT_SHIM(Windows::System::UserProfile::IGlobalizationPreferencesStatics2)->TrySetHomeGeographicRegion(get_abi(region), &result));
    return result;
}

template <typename D> bool consume_Windows_System_UserProfile_IGlobalizationPreferencesStatics2<D>::TrySetLanguages(param::iterable<hstring> const& languageTags) const
{
    bool result{};
    check_hresult(WINRT_SHIM(Windows::System::UserProfile::IGlobalizationPreferencesStatics2)->TrySetLanguages(get_abi(languageTags), &result));
    return result;
}

template <typename D> Windows::System::UserProfile::GlobalizationPreferencesForUser consume_Windows_System_UserProfile_IGlobalizationPreferencesStatics3<D>::GetForUser(Windows::System::User const& user) const
{
    Windows::System::UserProfile::GlobalizationPreferencesForUser value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::System::UserProfile::IGlobalizationPreferencesStatics3)->GetForUser(get_abi(user), put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::IAsyncOperation<Windows::System::UserProfile::SetImageFeedResult> consume_Windows_System_UserProfile_ILockScreenImageFeedStatics<D>::RequestSetImageFeedAsync(Windows::Foundation::Uri const& syndicationFeedUri) const
{
    Windows::Foundation::IAsyncOperation<Windows::System::UserProfile::SetImageFeedResult> value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::System::UserProfile::ILockScreenImageFeedStatics)->RequestSetImageFeedAsync(get_abi(syndicationFeedUri), put_abi(value)));
    return value;
}

template <typename D> bool consume_Windows_System_UserProfile_ILockScreenImageFeedStatics<D>::TryRemoveImageFeed() const
{
    bool result{};
    check_hresult(WINRT_SHIM(Windows::System::UserProfile::ILockScreenImageFeedStatics)->TryRemoveImageFeed(&result));
    return result;
}

template <typename D> Windows::Foundation::Uri consume_Windows_System_UserProfile_ILockScreenStatics<D>::OriginalImageFile() const
{
    Windows::Foundation::Uri value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::System::UserProfile::ILockScreenStatics)->get_OriginalImageFile(put_abi(value)));
    return value;
}

template <typename D> Windows::Storage::Streams::IRandomAccessStream consume_Windows_System_UserProfile_ILockScreenStatics<D>::GetImageStream() const
{
    Windows::Storage::Streams::IRandomAccessStream value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::System::UserProfile::ILockScreenStatics)->GetImageStream(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::IAsyncAction consume_Windows_System_UserProfile_ILockScreenStatics<D>::SetImageFileAsync(Windows::Storage::IStorageFile const& value) const
{
    Windows::Foundation::IAsyncAction Operation{ nullptr };
    check_hresult(WINRT_SHIM(Windows::System::UserProfile::ILockScreenStatics)->SetImageFileAsync(get_abi(value), put_abi(Operation)));
    return Operation;
}

template <typename D> Windows::Foundation::IAsyncAction consume_Windows_System_UserProfile_ILockScreenStatics<D>::SetImageStreamAsync(Windows::Storage::Streams::IRandomAccessStream const& value) const
{
    Windows::Foundation::IAsyncAction Operation{ nullptr };
    check_hresult(WINRT_SHIM(Windows::System::UserProfile::ILockScreenStatics)->SetImageStreamAsync(get_abi(value), put_abi(Operation)));
    return Operation;
}

template <typename D> bool consume_Windows_System_UserProfile_IUserInformationStatics<D>::AccountPictureChangeEnabled() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::System::UserProfile::IUserInformationStatics)->get_AccountPictureChangeEnabled(&value));
    return value;
}

template <typename D> bool consume_Windows_System_UserProfile_IUserInformationStatics<D>::NameAccessAllowed() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::System::UserProfile::IUserInformationStatics)->get_NameAccessAllowed(&value));
    return value;
}

template <typename D> Windows::Storage::IStorageFile consume_Windows_System_UserProfile_IUserInformationStatics<D>::GetAccountPicture(Windows::System::UserProfile::AccountPictureKind const& kind) const
{
    Windows::Storage::IStorageFile storageFile{ nullptr };
    check_hresult(WINRT_SHIM(Windows::System::UserProfile::IUserInformationStatics)->GetAccountPicture(get_abi(kind), put_abi(storageFile)));
    return storageFile;
}

template <typename D> Windows::Foundation::IAsyncOperation<Windows::System::UserProfile::SetAccountPictureResult> consume_Windows_System_UserProfile_IUserInformationStatics<D>::SetAccountPictureAsync(Windows::Storage::IStorageFile const& image) const
{
    Windows::Foundation::IAsyncOperation<Windows::System::UserProfile::SetAccountPictureResult> operation{ nullptr };
    check_hresult(WINRT_SHIM(Windows::System::UserProfile::IUserInformationStatics)->SetAccountPictureAsync(get_abi(image), put_abi(operation)));
    return operation;
}

template <typename D> Windows::Foundation::IAsyncOperation<Windows::System::UserProfile::SetAccountPictureResult> consume_Windows_System_UserProfile_IUserInformationStatics<D>::SetAccountPicturesAsync(Windows::Storage::IStorageFile const& smallImage, Windows::Storage::IStorageFile const& largeImage, Windows::Storage::IStorageFile const& video) const
{
    Windows::Foundation::IAsyncOperation<Windows::System::UserProfile::SetAccountPictureResult> operation{ nullptr };
    check_hresult(WINRT_SHIM(Windows::System::UserProfile::IUserInformationStatics)->SetAccountPicturesAsync(get_abi(smallImage), get_abi(largeImage), get_abi(video), put_abi(operation)));
    return operation;
}

template <typename D> Windows::Foundation::IAsyncOperation<Windows::System::UserProfile::SetAccountPictureResult> consume_Windows_System_UserProfile_IUserInformationStatics<D>::SetAccountPictureFromStreamAsync(Windows::Storage::Streams::IRandomAccessStream const& image) const
{
    Windows::Foundation::IAsyncOperation<Windows::System::UserProfile::SetAccountPictureResult> operation{ nullptr };
    check_hresult(WINRT_SHIM(Windows::System::UserProfile::IUserInformationStatics)->SetAccountPictureFromStreamAsync(get_abi(image), put_abi(operation)));
    return operation;
}

template <typename D> Windows::Foundation::IAsyncOperation<Windows::System::UserProfile::SetAccountPictureResult> consume_Windows_System_UserProfile_IUserInformationStatics<D>::SetAccountPicturesFromStreamsAsync(Windows::Storage::Streams::IRandomAccessStream const& smallImage, Windows::Storage::Streams::IRandomAccessStream const& largeImage, Windows::Storage::Streams::IRandomAccessStream const& video) const
{
    Windows::Foundation::IAsyncOperation<Windows::System::UserProfile::SetAccountPictureResult> operation{ nullptr };
    check_hresult(WINRT_SHIM(Windows::System::UserProfile::IUserInformationStatics)->SetAccountPicturesFromStreamsAsync(get_abi(smallImage), get_abi(largeImage), get_abi(video), put_abi(operation)));
    return operation;
}

template <typename D> winrt::event_token consume_Windows_System_UserProfile_IUserInformationStatics<D>::AccountPictureChanged(Windows::Foundation::EventHandler<Windows::Foundation::IInspectable> const& changeHandler) const
{
    winrt::event_token token{};
    check_hresult(WINRT_SHIM(Windows::System::UserProfile::IUserInformationStatics)->add_AccountPictureChanged(get_abi(changeHandler), put_abi(token)));
    return token;
}

template <typename D> typename consume_Windows_System_UserProfile_IUserInformationStatics<D>::AccountPictureChanged_revoker consume_Windows_System_UserProfile_IUserInformationStatics<D>::AccountPictureChanged(auto_revoke_t, Windows::Foundation::EventHandler<Windows::Foundation::IInspectable> const& changeHandler) const
{
    return impl::make_event_revoker<D, AccountPictureChanged_revoker>(this, AccountPictureChanged(changeHandler));
}

template <typename D> void consume_Windows_System_UserProfile_IUserInformationStatics<D>::AccountPictureChanged(winrt::event_token const& token) const noexcept
{
    WINRT_VERIFY_(0, WINRT_SHIM(Windows::System::UserProfile::IUserInformationStatics)->remove_AccountPictureChanged(get_abi(token)));
}

template <typename D> Windows::Foundation::IAsyncOperation<hstring> consume_Windows_System_UserProfile_IUserInformationStatics<D>::GetDisplayNameAsync() const
{
    Windows::Foundation::IAsyncOperation<hstring> operation{ nullptr };
    check_hresult(WINRT_SHIM(Windows::System::UserProfile::IUserInformationStatics)->GetDisplayNameAsync(put_abi(operation)));
    return operation;
}

template <typename D> Windows::Foundation::IAsyncOperation<hstring> consume_Windows_System_UserProfile_IUserInformationStatics<D>::GetFirstNameAsync() const
{
    Windows::Foundation::IAsyncOperation<hstring> operation{ nullptr };
    check_hresult(WINRT_SHIM(Windows::System::UserProfile::IUserInformationStatics)->GetFirstNameAsync(put_abi(operation)));
    return operation;
}

template <typename D> Windows::Foundation::IAsyncOperation<hstring> consume_Windows_System_UserProfile_IUserInformationStatics<D>::GetLastNameAsync() const
{
    Windows::Foundation::IAsyncOperation<hstring> operation{ nullptr };
    check_hresult(WINRT_SHIM(Windows::System::UserProfile::IUserInformationStatics)->GetLastNameAsync(put_abi(operation)));
    return operation;
}

template <typename D> Windows::Foundation::IAsyncOperation<hstring> consume_Windows_System_UserProfile_IUserInformationStatics<D>::GetPrincipalNameAsync() const
{
    Windows::Foundation::IAsyncOperation<hstring> operation{ nullptr };
    check_hresult(WINRT_SHIM(Windows::System::UserProfile::IUserInformationStatics)->GetPrincipalNameAsync(put_abi(operation)));
    return operation;
}

template <typename D> Windows::Foundation::IAsyncOperation<Windows::Foundation::Uri> consume_Windows_System_UserProfile_IUserInformationStatics<D>::GetSessionInitiationProtocolUriAsync() const
{
    Windows::Foundation::IAsyncOperation<Windows::Foundation::Uri> operation{ nullptr };
    check_hresult(WINRT_SHIM(Windows::System::UserProfile::IUserInformationStatics)->GetSessionInitiationProtocolUriAsync(put_abi(operation)));
    return operation;
}

template <typename D> Windows::Foundation::IAsyncOperation<hstring> consume_Windows_System_UserProfile_IUserInformationStatics<D>::GetDomainNameAsync() const
{
    Windows::Foundation::IAsyncOperation<hstring> operation{ nullptr };
    check_hresult(WINRT_SHIM(Windows::System::UserProfile::IUserInformationStatics)->GetDomainNameAsync(put_abi(operation)));
    return operation;
}

template <typename D> Windows::Foundation::IAsyncOperation<bool> consume_Windows_System_UserProfile_IUserProfilePersonalizationSettings<D>::TrySetLockScreenImageAsync(Windows::Storage::StorageFile const& imageFile) const
{
    Windows::Foundation::IAsyncOperation<bool> operation{ nullptr };
    check_hresult(WINRT_SHIM(Windows::System::UserProfile::IUserProfilePersonalizationSettings)->TrySetLockScreenImageAsync(get_abi(imageFile), put_abi(operation)));
    return operation;
}

template <typename D> Windows::Foundation::IAsyncOperation<bool> consume_Windows_System_UserProfile_IUserProfilePersonalizationSettings<D>::TrySetWallpaperImageAsync(Windows::Storage::StorageFile const& imageFile) const
{
    Windows::Foundation::IAsyncOperation<bool> operation{ nullptr };
    check_hresult(WINRT_SHIM(Windows::System::UserProfile::IUserProfilePersonalizationSettings)->TrySetWallpaperImageAsync(get_abi(imageFile), put_abi(operation)));
    return operation;
}

template <typename D> Windows::System::UserProfile::UserProfilePersonalizationSettings consume_Windows_System_UserProfile_IUserProfilePersonalizationSettingsStatics<D>::Current() const
{
    Windows::System::UserProfile::UserProfilePersonalizationSettings value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::System::UserProfile::IUserProfilePersonalizationSettingsStatics)->get_Current(put_abi(value)));
    return value;
}

template <typename D> bool consume_Windows_System_UserProfile_IUserProfilePersonalizationSettingsStatics<D>::IsSupported() const
{
    bool result{};
    check_hresult(WINRT_SHIM(Windows::System::UserProfile::IUserProfilePersonalizationSettingsStatics)->IsSupported(&result));
    return result;
}

template <typename D>
struct produce<D, Windows::System::UserProfile::IAdvertisingManagerForUser> : produce_base<D, Windows::System::UserProfile::IAdvertisingManagerForUser>
{
    int32_t WINRT_CALL get_AdvertisingId(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(AdvertisingId, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().AdvertisingId());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_User(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(User, WINRT_WRAP(Windows::System::User));
            *value = detach_from<Windows::System::User>(this->shim().User());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::System::UserProfile::IAdvertisingManagerStatics> : produce_base<D, Windows::System::UserProfile::IAdvertisingManagerStatics>
{
    int32_t WINRT_CALL get_AdvertisingId(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(AdvertisingId, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().AdvertisingId());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::System::UserProfile::IAdvertisingManagerStatics2> : produce_base<D, Windows::System::UserProfile::IAdvertisingManagerStatics2>
{
    int32_t WINRT_CALL GetForUser(void* user, void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetForUser, WINRT_WRAP(Windows::System::UserProfile::AdvertisingManagerForUser), Windows::System::User const&);
            *value = detach_from<Windows::System::UserProfile::AdvertisingManagerForUser>(this->shim().GetForUser(*reinterpret_cast<Windows::System::User const*>(&user)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::System::UserProfile::IAssignedAccessSettings> : produce_base<D, Windows::System::UserProfile::IAssignedAccessSettings>
{
    int32_t WINRT_CALL get_IsEnabled(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IsEnabled, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().IsEnabled());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_IsSingleAppKioskMode(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IsSingleAppKioskMode, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().IsSingleAppKioskMode());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_User(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(User, WINRT_WRAP(Windows::System::User));
            *value = detach_from<Windows::System::User>(this->shim().User());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::System::UserProfile::IAssignedAccessSettingsStatics> : produce_base<D, Windows::System::UserProfile::IAssignedAccessSettingsStatics>
{
    int32_t WINRT_CALL GetDefault(void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetDefault, WINRT_WRAP(Windows::System::UserProfile::AssignedAccessSettings));
            *result = detach_from<Windows::System::UserProfile::AssignedAccessSettings>(this->shim().GetDefault());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL GetForUser(void* user, void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetForUser, WINRT_WRAP(Windows::System::UserProfile::AssignedAccessSettings), Windows::System::User const&);
            *result = detach_from<Windows::System::UserProfile::AssignedAccessSettings>(this->shim().GetForUser(*reinterpret_cast<Windows::System::User const*>(&user)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::System::UserProfile::IDiagnosticsSettings> : produce_base<D, Windows::System::UserProfile::IDiagnosticsSettings>
{
    int32_t WINRT_CALL get_CanUseDiagnosticsToTailorExperiences(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CanUseDiagnosticsToTailorExperiences, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().CanUseDiagnosticsToTailorExperiences());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_User(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(User, WINRT_WRAP(Windows::System::User));
            *value = detach_from<Windows::System::User>(this->shim().User());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::System::UserProfile::IDiagnosticsSettingsStatics> : produce_base<D, Windows::System::UserProfile::IDiagnosticsSettingsStatics>
{
    int32_t WINRT_CALL GetDefault(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetDefault, WINRT_WRAP(Windows::System::UserProfile::DiagnosticsSettings));
            *value = detach_from<Windows::System::UserProfile::DiagnosticsSettings>(this->shim().GetDefault());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL GetForUser(void* user, void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetForUser, WINRT_WRAP(Windows::System::UserProfile::DiagnosticsSettings), Windows::System::User const&);
            *value = detach_from<Windows::System::UserProfile::DiagnosticsSettings>(this->shim().GetForUser(*reinterpret_cast<Windows::System::User const*>(&user)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::System::UserProfile::IFirstSignInSettings> : produce_base<D, Windows::System::UserProfile::IFirstSignInSettings>
{};

template <typename D>
struct produce<D, Windows::System::UserProfile::IFirstSignInSettingsStatics> : produce_base<D, Windows::System::UserProfile::IFirstSignInSettingsStatics>
{
    int32_t WINRT_CALL GetDefault(void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetDefault, WINRT_WRAP(Windows::System::UserProfile::FirstSignInSettings));
            *result = detach_from<Windows::System::UserProfile::FirstSignInSettings>(this->shim().GetDefault());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::System::UserProfile::IGlobalizationPreferencesForUser> : produce_base<D, Windows::System::UserProfile::IGlobalizationPreferencesForUser>
{
    int32_t WINRT_CALL get_User(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(User, WINRT_WRAP(Windows::System::User));
            *value = detach_from<Windows::System::User>(this->shim().User());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Calendars(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Calendars, WINRT_WRAP(Windows::Foundation::Collections::IVectorView<hstring>));
            *value = detach_from<Windows::Foundation::Collections::IVectorView<hstring>>(this->shim().Calendars());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Clocks(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Clocks, WINRT_WRAP(Windows::Foundation::Collections::IVectorView<hstring>));
            *value = detach_from<Windows::Foundation::Collections::IVectorView<hstring>>(this->shim().Clocks());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Currencies(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Currencies, WINRT_WRAP(Windows::Foundation::Collections::IVectorView<hstring>));
            *value = detach_from<Windows::Foundation::Collections::IVectorView<hstring>>(this->shim().Currencies());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Languages(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Languages, WINRT_WRAP(Windows::Foundation::Collections::IVectorView<hstring>));
            *value = detach_from<Windows::Foundation::Collections::IVectorView<hstring>>(this->shim().Languages());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_HomeGeographicRegion(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(HomeGeographicRegion, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().HomeGeographicRegion());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_WeekStartsOn(Windows::Globalization::DayOfWeek* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(WeekStartsOn, WINRT_WRAP(Windows::Globalization::DayOfWeek));
            *value = detach_from<Windows::Globalization::DayOfWeek>(this->shim().WeekStartsOn());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::System::UserProfile::IGlobalizationPreferencesStatics> : produce_base<D, Windows::System::UserProfile::IGlobalizationPreferencesStatics>
{
    int32_t WINRT_CALL get_Calendars(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Calendars, WINRT_WRAP(Windows::Foundation::Collections::IVectorView<hstring>));
            *value = detach_from<Windows::Foundation::Collections::IVectorView<hstring>>(this->shim().Calendars());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Clocks(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Clocks, WINRT_WRAP(Windows::Foundation::Collections::IVectorView<hstring>));
            *value = detach_from<Windows::Foundation::Collections::IVectorView<hstring>>(this->shim().Clocks());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Currencies(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Currencies, WINRT_WRAP(Windows::Foundation::Collections::IVectorView<hstring>));
            *value = detach_from<Windows::Foundation::Collections::IVectorView<hstring>>(this->shim().Currencies());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Languages(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Languages, WINRT_WRAP(Windows::Foundation::Collections::IVectorView<hstring>));
            *value = detach_from<Windows::Foundation::Collections::IVectorView<hstring>>(this->shim().Languages());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_HomeGeographicRegion(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(HomeGeographicRegion, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().HomeGeographicRegion());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_WeekStartsOn(Windows::Globalization::DayOfWeek* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(WeekStartsOn, WINRT_WRAP(Windows::Globalization::DayOfWeek));
            *value = detach_from<Windows::Globalization::DayOfWeek>(this->shim().WeekStartsOn());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::System::UserProfile::IGlobalizationPreferencesStatics2> : produce_base<D, Windows::System::UserProfile::IGlobalizationPreferencesStatics2>
{
    int32_t WINRT_CALL TrySetHomeGeographicRegion(void* region, bool* result) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(TrySetHomeGeographicRegion, WINRT_WRAP(bool), hstring const&);
            *result = detach_from<bool>(this->shim().TrySetHomeGeographicRegion(*reinterpret_cast<hstring const*>(&region)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL TrySetLanguages(void* languageTags, bool* result) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(TrySetLanguages, WINRT_WRAP(bool), Windows::Foundation::Collections::IIterable<hstring> const&);
            *result = detach_from<bool>(this->shim().TrySetLanguages(*reinterpret_cast<Windows::Foundation::Collections::IIterable<hstring> const*>(&languageTags)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::System::UserProfile::IGlobalizationPreferencesStatics3> : produce_base<D, Windows::System::UserProfile::IGlobalizationPreferencesStatics3>
{
    int32_t WINRT_CALL GetForUser(void* user, void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetForUser, WINRT_WRAP(Windows::System::UserProfile::GlobalizationPreferencesForUser), Windows::System::User const&);
            *value = detach_from<Windows::System::UserProfile::GlobalizationPreferencesForUser>(this->shim().GetForUser(*reinterpret_cast<Windows::System::User const*>(&user)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::System::UserProfile::ILockScreenImageFeedStatics> : produce_base<D, Windows::System::UserProfile::ILockScreenImageFeedStatics>
{
    int32_t WINRT_CALL RequestSetImageFeedAsync(void* syndicationFeedUri, void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(RequestSetImageFeedAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<Windows::System::UserProfile::SetImageFeedResult>), Windows::Foundation::Uri const);
            *value = detach_from<Windows::Foundation::IAsyncOperation<Windows::System::UserProfile::SetImageFeedResult>>(this->shim().RequestSetImageFeedAsync(*reinterpret_cast<Windows::Foundation::Uri const*>(&syndicationFeedUri)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL TryRemoveImageFeed(bool* result) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(TryRemoveImageFeed, WINRT_WRAP(bool));
            *result = detach_from<bool>(this->shim().TryRemoveImageFeed());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::System::UserProfile::ILockScreenStatics> : produce_base<D, Windows::System::UserProfile::ILockScreenStatics>
{
    int32_t WINRT_CALL get_OriginalImageFile(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(OriginalImageFile, WINRT_WRAP(Windows::Foundation::Uri));
            *value = detach_from<Windows::Foundation::Uri>(this->shim().OriginalImageFile());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL GetImageStream(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetImageStream, WINRT_WRAP(Windows::Storage::Streams::IRandomAccessStream));
            *value = detach_from<Windows::Storage::Streams::IRandomAccessStream>(this->shim().GetImageStream());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL SetImageFileAsync(void* value, void** Operation) noexcept final
    {
        try
        {
            *Operation = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SetImageFileAsync, WINRT_WRAP(Windows::Foundation::IAsyncAction), Windows::Storage::IStorageFile const);
            *Operation = detach_from<Windows::Foundation::IAsyncAction>(this->shim().SetImageFileAsync(*reinterpret_cast<Windows::Storage::IStorageFile const*>(&value)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL SetImageStreamAsync(void* value, void** Operation) noexcept final
    {
        try
        {
            *Operation = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SetImageStreamAsync, WINRT_WRAP(Windows::Foundation::IAsyncAction), Windows::Storage::Streams::IRandomAccessStream const);
            *Operation = detach_from<Windows::Foundation::IAsyncAction>(this->shim().SetImageStreamAsync(*reinterpret_cast<Windows::Storage::Streams::IRandomAccessStream const*>(&value)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::System::UserProfile::IUserInformationStatics> : produce_base<D, Windows::System::UserProfile::IUserInformationStatics>
{
    int32_t WINRT_CALL get_AccountPictureChangeEnabled(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(AccountPictureChangeEnabled, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().AccountPictureChangeEnabled());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_NameAccessAllowed(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(NameAccessAllowed, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().NameAccessAllowed());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL GetAccountPicture(Windows::System::UserProfile::AccountPictureKind kind, void** storageFile) noexcept final
    {
        try
        {
            *storageFile = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetAccountPicture, WINRT_WRAP(Windows::Storage::IStorageFile), Windows::System::UserProfile::AccountPictureKind const&);
            *storageFile = detach_from<Windows::Storage::IStorageFile>(this->shim().GetAccountPicture(*reinterpret_cast<Windows::System::UserProfile::AccountPictureKind const*>(&kind)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL SetAccountPictureAsync(void* image, void** operation) noexcept final
    {
        try
        {
            *operation = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SetAccountPictureAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<Windows::System::UserProfile::SetAccountPictureResult>), Windows::Storage::IStorageFile const);
            *operation = detach_from<Windows::Foundation::IAsyncOperation<Windows::System::UserProfile::SetAccountPictureResult>>(this->shim().SetAccountPictureAsync(*reinterpret_cast<Windows::Storage::IStorageFile const*>(&image)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL SetAccountPicturesAsync(void* smallImage, void* largeImage, void* video, void** operation) noexcept final
    {
        try
        {
            *operation = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SetAccountPicturesAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<Windows::System::UserProfile::SetAccountPictureResult>), Windows::Storage::IStorageFile const, Windows::Storage::IStorageFile const, Windows::Storage::IStorageFile const);
            *operation = detach_from<Windows::Foundation::IAsyncOperation<Windows::System::UserProfile::SetAccountPictureResult>>(this->shim().SetAccountPicturesAsync(*reinterpret_cast<Windows::Storage::IStorageFile const*>(&smallImage), *reinterpret_cast<Windows::Storage::IStorageFile const*>(&largeImage), *reinterpret_cast<Windows::Storage::IStorageFile const*>(&video)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL SetAccountPictureFromStreamAsync(void* image, void** operation) noexcept final
    {
        try
        {
            *operation = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SetAccountPictureFromStreamAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<Windows::System::UserProfile::SetAccountPictureResult>), Windows::Storage::Streams::IRandomAccessStream const);
            *operation = detach_from<Windows::Foundation::IAsyncOperation<Windows::System::UserProfile::SetAccountPictureResult>>(this->shim().SetAccountPictureFromStreamAsync(*reinterpret_cast<Windows::Storage::Streams::IRandomAccessStream const*>(&image)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL SetAccountPicturesFromStreamsAsync(void* smallImage, void* largeImage, void* video, void** operation) noexcept final
    {
        try
        {
            *operation = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SetAccountPicturesFromStreamsAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<Windows::System::UserProfile::SetAccountPictureResult>), Windows::Storage::Streams::IRandomAccessStream const, Windows::Storage::Streams::IRandomAccessStream const, Windows::Storage::Streams::IRandomAccessStream const);
            *operation = detach_from<Windows::Foundation::IAsyncOperation<Windows::System::UserProfile::SetAccountPictureResult>>(this->shim().SetAccountPicturesFromStreamsAsync(*reinterpret_cast<Windows::Storage::Streams::IRandomAccessStream const*>(&smallImage), *reinterpret_cast<Windows::Storage::Streams::IRandomAccessStream const*>(&largeImage), *reinterpret_cast<Windows::Storage::Streams::IRandomAccessStream const*>(&video)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL add_AccountPictureChanged(void* changeHandler, winrt::event_token* token) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(AccountPictureChanged, WINRT_WRAP(winrt::event_token), Windows::Foundation::EventHandler<Windows::Foundation::IInspectable> const&);
            *token = detach_from<winrt::event_token>(this->shim().AccountPictureChanged(*reinterpret_cast<Windows::Foundation::EventHandler<Windows::Foundation::IInspectable> const*>(&changeHandler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL remove_AccountPictureChanged(winrt::event_token token) noexcept final
    {
        typename D::abi_guard guard(this->shim());
        WINRT_ASSERT_DECLARATION(AccountPictureChanged, WINRT_WRAP(void), winrt::event_token const&);
        this->shim().AccountPictureChanged(*reinterpret_cast<winrt::event_token const*>(&token));
        return 0;
    }

    int32_t WINRT_CALL GetDisplayNameAsync(void** operation) noexcept final
    {
        try
        {
            *operation = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetDisplayNameAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<hstring>));
            *operation = detach_from<Windows::Foundation::IAsyncOperation<hstring>>(this->shim().GetDisplayNameAsync());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL GetFirstNameAsync(void** operation) noexcept final
    {
        try
        {
            *operation = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetFirstNameAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<hstring>));
            *operation = detach_from<Windows::Foundation::IAsyncOperation<hstring>>(this->shim().GetFirstNameAsync());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL GetLastNameAsync(void** operation) noexcept final
    {
        try
        {
            *operation = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetLastNameAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<hstring>));
            *operation = detach_from<Windows::Foundation::IAsyncOperation<hstring>>(this->shim().GetLastNameAsync());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL GetPrincipalNameAsync(void** operation) noexcept final
    {
        try
        {
            *operation = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetPrincipalNameAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<hstring>));
            *operation = detach_from<Windows::Foundation::IAsyncOperation<hstring>>(this->shim().GetPrincipalNameAsync());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL GetSessionInitiationProtocolUriAsync(void** operation) noexcept final
    {
        try
        {
            *operation = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetSessionInitiationProtocolUriAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<Windows::Foundation::Uri>));
            *operation = detach_from<Windows::Foundation::IAsyncOperation<Windows::Foundation::Uri>>(this->shim().GetSessionInitiationProtocolUriAsync());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL GetDomainNameAsync(void** operation) noexcept final
    {
        try
        {
            *operation = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetDomainNameAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<hstring>));
            *operation = detach_from<Windows::Foundation::IAsyncOperation<hstring>>(this->shim().GetDomainNameAsync());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::System::UserProfile::IUserProfilePersonalizationSettings> : produce_base<D, Windows::System::UserProfile::IUserProfilePersonalizationSettings>
{
    int32_t WINRT_CALL TrySetLockScreenImageAsync(void* imageFile, void** operation) noexcept final
    {
        try
        {
            *operation = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(TrySetLockScreenImageAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<bool>), Windows::Storage::StorageFile const);
            *operation = detach_from<Windows::Foundation::IAsyncOperation<bool>>(this->shim().TrySetLockScreenImageAsync(*reinterpret_cast<Windows::Storage::StorageFile const*>(&imageFile)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL TrySetWallpaperImageAsync(void* imageFile, void** operation) noexcept final
    {
        try
        {
            *operation = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(TrySetWallpaperImageAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<bool>), Windows::Storage::StorageFile const);
            *operation = detach_from<Windows::Foundation::IAsyncOperation<bool>>(this->shim().TrySetWallpaperImageAsync(*reinterpret_cast<Windows::Storage::StorageFile const*>(&imageFile)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::System::UserProfile::IUserProfilePersonalizationSettingsStatics> : produce_base<D, Windows::System::UserProfile::IUserProfilePersonalizationSettingsStatics>
{
    int32_t WINRT_CALL get_Current(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Current, WINRT_WRAP(Windows::System::UserProfile::UserProfilePersonalizationSettings));
            *value = detach_from<Windows::System::UserProfile::UserProfilePersonalizationSettings>(this->shim().Current());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL IsSupported(bool* result) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IsSupported, WINRT_WRAP(bool));
            *result = detach_from<bool>(this->shim().IsSupported());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

}

WINRT_EXPORT namespace winrt::Windows::System::UserProfile {

inline hstring AdvertisingManager::AdvertisingId()
{
    return impl::call_factory<AdvertisingManager, Windows::System::UserProfile::IAdvertisingManagerStatics>([&](auto&& f) { return f.AdvertisingId(); });
}

inline Windows::System::UserProfile::AdvertisingManagerForUser AdvertisingManager::GetForUser(Windows::System::User const& user)
{
    return impl::call_factory<AdvertisingManager, Windows::System::UserProfile::IAdvertisingManagerStatics2>([&](auto&& f) { return f.GetForUser(user); });
}

inline Windows::System::UserProfile::AssignedAccessSettings AssignedAccessSettings::GetDefault()
{
    return impl::call_factory<AssignedAccessSettings, Windows::System::UserProfile::IAssignedAccessSettingsStatics>([&](auto&& f) { return f.GetDefault(); });
}

inline Windows::System::UserProfile::AssignedAccessSettings AssignedAccessSettings::GetForUser(Windows::System::User const& user)
{
    return impl::call_factory<AssignedAccessSettings, Windows::System::UserProfile::IAssignedAccessSettingsStatics>([&](auto&& f) { return f.GetForUser(user); });
}

inline Windows::System::UserProfile::DiagnosticsSettings DiagnosticsSettings::GetDefault()
{
    return impl::call_factory<DiagnosticsSettings, Windows::System::UserProfile::IDiagnosticsSettingsStatics>([&](auto&& f) { return f.GetDefault(); });
}

inline Windows::System::UserProfile::DiagnosticsSettings DiagnosticsSettings::GetForUser(Windows::System::User const& user)
{
    return impl::call_factory<DiagnosticsSettings, Windows::System::UserProfile::IDiagnosticsSettingsStatics>([&](auto&& f) { return f.GetForUser(user); });
}

inline Windows::System::UserProfile::FirstSignInSettings FirstSignInSettings::GetDefault()
{
    return impl::call_factory<FirstSignInSettings, Windows::System::UserProfile::IFirstSignInSettingsStatics>([&](auto&& f) { return f.GetDefault(); });
}

inline Windows::Foundation::Collections::IVectorView<hstring> GlobalizationPreferences::Calendars()
{
    return impl::call_factory<GlobalizationPreferences, Windows::System::UserProfile::IGlobalizationPreferencesStatics>([&](auto&& f) { return f.Calendars(); });
}

inline Windows::Foundation::Collections::IVectorView<hstring> GlobalizationPreferences::Clocks()
{
    return impl::call_factory<GlobalizationPreferences, Windows::System::UserProfile::IGlobalizationPreferencesStatics>([&](auto&& f) { return f.Clocks(); });
}

inline Windows::Foundation::Collections::IVectorView<hstring> GlobalizationPreferences::Currencies()
{
    return impl::call_factory<GlobalizationPreferences, Windows::System::UserProfile::IGlobalizationPreferencesStatics>([&](auto&& f) { return f.Currencies(); });
}

inline Windows::Foundation::Collections::IVectorView<hstring> GlobalizationPreferences::Languages()
{
    return impl::call_factory<GlobalizationPreferences, Windows::System::UserProfile::IGlobalizationPreferencesStatics>([&](auto&& f) { return f.Languages(); });
}

inline hstring GlobalizationPreferences::HomeGeographicRegion()
{
    return impl::call_factory<GlobalizationPreferences, Windows::System::UserProfile::IGlobalizationPreferencesStatics>([&](auto&& f) { return f.HomeGeographicRegion(); });
}

inline Windows::Globalization::DayOfWeek GlobalizationPreferences::WeekStartsOn()
{
    return impl::call_factory<GlobalizationPreferences, Windows::System::UserProfile::IGlobalizationPreferencesStatics>([&](auto&& f) { return f.WeekStartsOn(); });
}

inline bool GlobalizationPreferences::TrySetHomeGeographicRegion(param::hstring const& region)
{
    return impl::call_factory<GlobalizationPreferences, Windows::System::UserProfile::IGlobalizationPreferencesStatics2>([&](auto&& f) { return f.TrySetHomeGeographicRegion(region); });
}

inline bool GlobalizationPreferences::TrySetLanguages(param::iterable<hstring> const& languageTags)
{
    return impl::call_factory<GlobalizationPreferences, Windows::System::UserProfile::IGlobalizationPreferencesStatics2>([&](auto&& f) { return f.TrySetLanguages(languageTags); });
}

inline Windows::System::UserProfile::GlobalizationPreferencesForUser GlobalizationPreferences::GetForUser(Windows::System::User const& user)
{
    return impl::call_factory<GlobalizationPreferences, Windows::System::UserProfile::IGlobalizationPreferencesStatics3>([&](auto&& f) { return f.GetForUser(user); });
}

inline Windows::Foundation::IAsyncOperation<Windows::System::UserProfile::SetImageFeedResult> LockScreen::RequestSetImageFeedAsync(Windows::Foundation::Uri const& syndicationFeedUri)
{
    return impl::call_factory<LockScreen, Windows::System::UserProfile::ILockScreenImageFeedStatics>([&](auto&& f) { return f.RequestSetImageFeedAsync(syndicationFeedUri); });
}

inline bool LockScreen::TryRemoveImageFeed()
{
    return impl::call_factory<LockScreen, Windows::System::UserProfile::ILockScreenImageFeedStatics>([&](auto&& f) { return f.TryRemoveImageFeed(); });
}

inline Windows::Foundation::Uri LockScreen::OriginalImageFile()
{
    return impl::call_factory<LockScreen, Windows::System::UserProfile::ILockScreenStatics>([&](auto&& f) { return f.OriginalImageFile(); });
}

inline Windows::Storage::Streams::IRandomAccessStream LockScreen::GetImageStream()
{
    return impl::call_factory<LockScreen, Windows::System::UserProfile::ILockScreenStatics>([&](auto&& f) { return f.GetImageStream(); });
}

inline Windows::Foundation::IAsyncAction LockScreen::SetImageFileAsync(Windows::Storage::IStorageFile const& value)
{
    return impl::call_factory<LockScreen, Windows::System::UserProfile::ILockScreenStatics>([&](auto&& f) { return f.SetImageFileAsync(value); });
}

inline Windows::Foundation::IAsyncAction LockScreen::SetImageStreamAsync(Windows::Storage::Streams::IRandomAccessStream const& value)
{
    return impl::call_factory<LockScreen, Windows::System::UserProfile::ILockScreenStatics>([&](auto&& f) { return f.SetImageStreamAsync(value); });
}

inline bool UserInformation::AccountPictureChangeEnabled()
{
    return impl::call_factory<UserInformation, Windows::System::UserProfile::IUserInformationStatics>([&](auto&& f) { return f.AccountPictureChangeEnabled(); });
}

inline bool UserInformation::NameAccessAllowed()
{
    return impl::call_factory<UserInformation, Windows::System::UserProfile::IUserInformationStatics>([&](auto&& f) { return f.NameAccessAllowed(); });
}

inline Windows::Storage::IStorageFile UserInformation::GetAccountPicture(Windows::System::UserProfile::AccountPictureKind const& kind)
{
    return impl::call_factory<UserInformation, Windows::System::UserProfile::IUserInformationStatics>([&](auto&& f) { return f.GetAccountPicture(kind); });
}

inline Windows::Foundation::IAsyncOperation<Windows::System::UserProfile::SetAccountPictureResult> UserInformation::SetAccountPictureAsync(Windows::Storage::IStorageFile const& image)
{
    return impl::call_factory<UserInformation, Windows::System::UserProfile::IUserInformationStatics>([&](auto&& f) { return f.SetAccountPictureAsync(image); });
}

inline Windows::Foundation::IAsyncOperation<Windows::System::UserProfile::SetAccountPictureResult> UserInformation::SetAccountPicturesAsync(Windows::Storage::IStorageFile const& smallImage, Windows::Storage::IStorageFile const& largeImage, Windows::Storage::IStorageFile const& video)
{
    return impl::call_factory<UserInformation, Windows::System::UserProfile::IUserInformationStatics>([&](auto&& f) { return f.SetAccountPicturesAsync(smallImage, largeImage, video); });
}

inline Windows::Foundation::IAsyncOperation<Windows::System::UserProfile::SetAccountPictureResult> UserInformation::SetAccountPictureFromStreamAsync(Windows::Storage::Streams::IRandomAccessStream const& image)
{
    return impl::call_factory<UserInformation, Windows::System::UserProfile::IUserInformationStatics>([&](auto&& f) { return f.SetAccountPictureFromStreamAsync(image); });
}

inline Windows::Foundation::IAsyncOperation<Windows::System::UserProfile::SetAccountPictureResult> UserInformation::SetAccountPicturesFromStreamsAsync(Windows::Storage::Streams::IRandomAccessStream const& smallImage, Windows::Storage::Streams::IRandomAccessStream const& largeImage, Windows::Storage::Streams::IRandomAccessStream const& video)
{
    return impl::call_factory<UserInformation, Windows::System::UserProfile::IUserInformationStatics>([&](auto&& f) { return f.SetAccountPicturesFromStreamsAsync(smallImage, largeImage, video); });
}

inline winrt::event_token UserInformation::AccountPictureChanged(Windows::Foundation::EventHandler<Windows::Foundation::IInspectable> const& changeHandler)
{
    return impl::call_factory<UserInformation, Windows::System::UserProfile::IUserInformationStatics>([&](auto&& f) { return f.AccountPictureChanged(changeHandler); });
}

inline UserInformation::AccountPictureChanged_revoker UserInformation::AccountPictureChanged(auto_revoke_t, Windows::Foundation::EventHandler<Windows::Foundation::IInspectable> const& changeHandler)
{
    auto f = get_activation_factory<UserInformation, Windows::System::UserProfile::IUserInformationStatics>();
    return { f, f.AccountPictureChanged(changeHandler) };
}

inline void UserInformation::AccountPictureChanged(winrt::event_token const& token)
{
    impl::call_factory<UserInformation, Windows::System::UserProfile::IUserInformationStatics>([&](auto&& f) { return f.AccountPictureChanged(token); });
}

inline Windows::Foundation::IAsyncOperation<hstring> UserInformation::GetDisplayNameAsync()
{
    return impl::call_factory<UserInformation, Windows::System::UserProfile::IUserInformationStatics>([&](auto&& f) { return f.GetDisplayNameAsync(); });
}

inline Windows::Foundation::IAsyncOperation<hstring> UserInformation::GetFirstNameAsync()
{
    return impl::call_factory<UserInformation, Windows::System::UserProfile::IUserInformationStatics>([&](auto&& f) { return f.GetFirstNameAsync(); });
}

inline Windows::Foundation::IAsyncOperation<hstring> UserInformation::GetLastNameAsync()
{
    return impl::call_factory<UserInformation, Windows::System::UserProfile::IUserInformationStatics>([&](auto&& f) { return f.GetLastNameAsync(); });
}

inline Windows::Foundation::IAsyncOperation<hstring> UserInformation::GetPrincipalNameAsync()
{
    return impl::call_factory<UserInformation, Windows::System::UserProfile::IUserInformationStatics>([&](auto&& f) { return f.GetPrincipalNameAsync(); });
}

inline Windows::Foundation::IAsyncOperation<Windows::Foundation::Uri> UserInformation::GetSessionInitiationProtocolUriAsync()
{
    return impl::call_factory<UserInformation, Windows::System::UserProfile::IUserInformationStatics>([&](auto&& f) { return f.GetSessionInitiationProtocolUriAsync(); });
}

inline Windows::Foundation::IAsyncOperation<hstring> UserInformation::GetDomainNameAsync()
{
    return impl::call_factory<UserInformation, Windows::System::UserProfile::IUserInformationStatics>([&](auto&& f) { return f.GetDomainNameAsync(); });
}

inline Windows::System::UserProfile::UserProfilePersonalizationSettings UserProfilePersonalizationSettings::Current()
{
    return impl::call_factory<UserProfilePersonalizationSettings, Windows::System::UserProfile::IUserProfilePersonalizationSettingsStatics>([&](auto&& f) { return f.Current(); });
}

inline bool UserProfilePersonalizationSettings::IsSupported()
{
    return impl::call_factory<UserProfilePersonalizationSettings, Windows::System::UserProfile::IUserProfilePersonalizationSettingsStatics>([&](auto&& f) { return f.IsSupported(); });
}

}

WINRT_EXPORT namespace std {

template<> struct hash<winrt::Windows::System::UserProfile::IAdvertisingManagerForUser> : winrt::impl::hash_base<winrt::Windows::System::UserProfile::IAdvertisingManagerForUser> {};
template<> struct hash<winrt::Windows::System::UserProfile::IAdvertisingManagerStatics> : winrt::impl::hash_base<winrt::Windows::System::UserProfile::IAdvertisingManagerStatics> {};
template<> struct hash<winrt::Windows::System::UserProfile::IAdvertisingManagerStatics2> : winrt::impl::hash_base<winrt::Windows::System::UserProfile::IAdvertisingManagerStatics2> {};
template<> struct hash<winrt::Windows::System::UserProfile::IAssignedAccessSettings> : winrt::impl::hash_base<winrt::Windows::System::UserProfile::IAssignedAccessSettings> {};
template<> struct hash<winrt::Windows::System::UserProfile::IAssignedAccessSettingsStatics> : winrt::impl::hash_base<winrt::Windows::System::UserProfile::IAssignedAccessSettingsStatics> {};
template<> struct hash<winrt::Windows::System::UserProfile::IDiagnosticsSettings> : winrt::impl::hash_base<winrt::Windows::System::UserProfile::IDiagnosticsSettings> {};
template<> struct hash<winrt::Windows::System::UserProfile::IDiagnosticsSettingsStatics> : winrt::impl::hash_base<winrt::Windows::System::UserProfile::IDiagnosticsSettingsStatics> {};
template<> struct hash<winrt::Windows::System::UserProfile::IFirstSignInSettings> : winrt::impl::hash_base<winrt::Windows::System::UserProfile::IFirstSignInSettings> {};
template<> struct hash<winrt::Windows::System::UserProfile::IFirstSignInSettingsStatics> : winrt::impl::hash_base<winrt::Windows::System::UserProfile::IFirstSignInSettingsStatics> {};
template<> struct hash<winrt::Windows::System::UserProfile::IGlobalizationPreferencesForUser> : winrt::impl::hash_base<winrt::Windows::System::UserProfile::IGlobalizationPreferencesForUser> {};
template<> struct hash<winrt::Windows::System::UserProfile::IGlobalizationPreferencesStatics> : winrt::impl::hash_base<winrt::Windows::System::UserProfile::IGlobalizationPreferencesStatics> {};
template<> struct hash<winrt::Windows::System::UserProfile::IGlobalizationPreferencesStatics2> : winrt::impl::hash_base<winrt::Windows::System::UserProfile::IGlobalizationPreferencesStatics2> {};
template<> struct hash<winrt::Windows::System::UserProfile::IGlobalizationPreferencesStatics3> : winrt::impl::hash_base<winrt::Windows::System::UserProfile::IGlobalizationPreferencesStatics3> {};
template<> struct hash<winrt::Windows::System::UserProfile::ILockScreenImageFeedStatics> : winrt::impl::hash_base<winrt::Windows::System::UserProfile::ILockScreenImageFeedStatics> {};
template<> struct hash<winrt::Windows::System::UserProfile::ILockScreenStatics> : winrt::impl::hash_base<winrt::Windows::System::UserProfile::ILockScreenStatics> {};
template<> struct hash<winrt::Windows::System::UserProfile::IUserInformationStatics> : winrt::impl::hash_base<winrt::Windows::System::UserProfile::IUserInformationStatics> {};
template<> struct hash<winrt::Windows::System::UserProfile::IUserProfilePersonalizationSettings> : winrt::impl::hash_base<winrt::Windows::System::UserProfile::IUserProfilePersonalizationSettings> {};
template<> struct hash<winrt::Windows::System::UserProfile::IUserProfilePersonalizationSettingsStatics> : winrt::impl::hash_base<winrt::Windows::System::UserProfile::IUserProfilePersonalizationSettingsStatics> {};
template<> struct hash<winrt::Windows::System::UserProfile::AdvertisingManager> : winrt::impl::hash_base<winrt::Windows::System::UserProfile::AdvertisingManager> {};
template<> struct hash<winrt::Windows::System::UserProfile::AdvertisingManagerForUser> : winrt::impl::hash_base<winrt::Windows::System::UserProfile::AdvertisingManagerForUser> {};
template<> struct hash<winrt::Windows::System::UserProfile::AssignedAccessSettings> : winrt::impl::hash_base<winrt::Windows::System::UserProfile::AssignedAccessSettings> {};
template<> struct hash<winrt::Windows::System::UserProfile::DiagnosticsSettings> : winrt::impl::hash_base<winrt::Windows::System::UserProfile::DiagnosticsSettings> {};
template<> struct hash<winrt::Windows::System::UserProfile::FirstSignInSettings> : winrt::impl::hash_base<winrt::Windows::System::UserProfile::FirstSignInSettings> {};
template<> struct hash<winrt::Windows::System::UserProfile::GlobalizationPreferences> : winrt::impl::hash_base<winrt::Windows::System::UserProfile::GlobalizationPreferences> {};
template<> struct hash<winrt::Windows::System::UserProfile::GlobalizationPreferencesForUser> : winrt::impl::hash_base<winrt::Windows::System::UserProfile::GlobalizationPreferencesForUser> {};
template<> struct hash<winrt::Windows::System::UserProfile::LockScreen> : winrt::impl::hash_base<winrt::Windows::System::UserProfile::LockScreen> {};
template<> struct hash<winrt::Windows::System::UserProfile::UserInformation> : winrt::impl::hash_base<winrt::Windows::System::UserProfile::UserInformation> {};
template<> struct hash<winrt::Windows::System::UserProfile::UserProfilePersonalizationSettings> : winrt::impl::hash_base<winrt::Windows::System::UserProfile::UserProfilePersonalizationSettings> {};

}
