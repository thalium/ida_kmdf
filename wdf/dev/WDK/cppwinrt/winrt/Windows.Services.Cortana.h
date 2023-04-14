// C++/WinRT v1.0.190111.3

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#pragma once

#include "winrt/base.h"

#include "winrt/Windows.Foundation.h"
#include "winrt/Windows.Foundation.Collections.h"
#include "winrt/impl/Windows.ApplicationModel.DataTransfer.2.h"
#include "winrt/impl/Windows.Foundation.2.h"
#include "winrt/impl/Windows.Storage.Streams.2.h"
#include "winrt/impl/Windows.System.2.h"
#include "winrt/impl/Windows.Services.Cortana.2.h"

namespace winrt::impl {

template <typename D> Windows::System::User consume_Windows_Services_Cortana_ICortanaActionableInsights<D>::User() const
{
    Windows::System::User value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Services::Cortana::ICortanaActionableInsights)->get_User(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::IAsyncOperation<bool> consume_Windows_Services_Cortana_ICortanaActionableInsights<D>::IsAvailableAsync() const
{
    Windows::Foundation::IAsyncOperation<bool> operation{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Services::Cortana::ICortanaActionableInsights)->IsAvailableAsync(put_abi(operation)));
    return operation;
}

template <typename D> Windows::Foundation::IAsyncAction consume_Windows_Services_Cortana_ICortanaActionableInsights<D>::ShowInsightsForImageAsync(Windows::Storage::Streams::IRandomAccessStreamReference const& imageStream) const
{
    Windows::Foundation::IAsyncAction operation{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Services::Cortana::ICortanaActionableInsights)->ShowInsightsForImageAsync(get_abi(imageStream), put_abi(operation)));
    return operation;
}

template <typename D> Windows::Foundation::IAsyncAction consume_Windows_Services_Cortana_ICortanaActionableInsights<D>::ShowInsightsForImageAsync(Windows::Storage::Streams::IRandomAccessStreamReference const& imageStream, Windows::Services::Cortana::CortanaActionableInsightsOptions const& options) const
{
    Windows::Foundation::IAsyncAction operation{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Services::Cortana::ICortanaActionableInsights)->ShowInsightsForImageWithOptionsAsync(get_abi(imageStream), get_abi(options), put_abi(operation)));
    return operation;
}

template <typename D> Windows::Foundation::IAsyncAction consume_Windows_Services_Cortana_ICortanaActionableInsights<D>::ShowInsightsForTextAsync(param::hstring const& text) const
{
    Windows::Foundation::IAsyncAction operation{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Services::Cortana::ICortanaActionableInsights)->ShowInsightsForTextAsync(get_abi(text), put_abi(operation)));
    return operation;
}

template <typename D> Windows::Foundation::IAsyncAction consume_Windows_Services_Cortana_ICortanaActionableInsights<D>::ShowInsightsForTextAsync(param::hstring const& text, Windows::Services::Cortana::CortanaActionableInsightsOptions const& options) const
{
    Windows::Foundation::IAsyncAction operation{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Services::Cortana::ICortanaActionableInsights)->ShowInsightsForTextWithOptionsAsync(get_abi(text), get_abi(options), put_abi(operation)));
    return operation;
}

template <typename D> Windows::Foundation::IAsyncAction consume_Windows_Services_Cortana_ICortanaActionableInsights<D>::ShowInsightsAsync(Windows::ApplicationModel::DataTransfer::DataPackage const& datapackage) const
{
    Windows::Foundation::IAsyncAction operation{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Services::Cortana::ICortanaActionableInsights)->ShowInsightsAsync(get_abi(datapackage), put_abi(operation)));
    return operation;
}

template <typename D> Windows::Foundation::IAsyncAction consume_Windows_Services_Cortana_ICortanaActionableInsights<D>::ShowInsightsAsync(Windows::ApplicationModel::DataTransfer::DataPackage const& datapackage, Windows::Services::Cortana::CortanaActionableInsightsOptions const& options) const
{
    Windows::Foundation::IAsyncAction operation{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Services::Cortana::ICortanaActionableInsights)->ShowInsightsWithOptionsAsync(get_abi(datapackage), get_abi(options), put_abi(operation)));
    return operation;
}

template <typename D> Windows::Foundation::Uri consume_Windows_Services_Cortana_ICortanaActionableInsightsOptions<D>::ContentSourceWebLink() const
{
    Windows::Foundation::Uri value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Services::Cortana::ICortanaActionableInsightsOptions)->get_ContentSourceWebLink(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_Services_Cortana_ICortanaActionableInsightsOptions<D>::ContentSourceWebLink(Windows::Foundation::Uri const& value) const
{
    check_hresult(WINRT_SHIM(Windows::Services::Cortana::ICortanaActionableInsightsOptions)->put_ContentSourceWebLink(get_abi(value)));
}

template <typename D> hstring consume_Windows_Services_Cortana_ICortanaActionableInsightsOptions<D>::SurroundingText() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Services::Cortana::ICortanaActionableInsightsOptions)->get_SurroundingText(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_Services_Cortana_ICortanaActionableInsightsOptions<D>::SurroundingText(param::hstring const& value) const
{
    check_hresult(WINRT_SHIM(Windows::Services::Cortana::ICortanaActionableInsightsOptions)->put_SurroundingText(get_abi(value)));
}

template <typename D> Windows::Services::Cortana::CortanaActionableInsights consume_Windows_Services_Cortana_ICortanaActionableInsightsStatics<D>::GetDefault() const
{
    Windows::Services::Cortana::CortanaActionableInsights result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Services::Cortana::ICortanaActionableInsightsStatics)->GetDefault(put_abi(result)));
    return result;
}

template <typename D> Windows::Services::Cortana::CortanaActionableInsights consume_Windows_Services_Cortana_ICortanaActionableInsightsStatics<D>::GetForUser(Windows::System::User const& user) const
{
    Windows::Services::Cortana::CortanaActionableInsights result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Services::Cortana::ICortanaActionableInsightsStatics)->GetForUser(get_abi(user), put_abi(result)));
    return result;
}

template <typename D> bool consume_Windows_Services_Cortana_ICortanaPermissionsManager<D>::IsSupported() const
{
    bool result{};
    check_hresult(WINRT_SHIM(Windows::Services::Cortana::ICortanaPermissionsManager)->IsSupported(&result));
    return result;
}

template <typename D> Windows::Foundation::IAsyncOperation<bool> consume_Windows_Services_Cortana_ICortanaPermissionsManager<D>::ArePermissionsGrantedAsync(param::async_iterable<Windows::Services::Cortana::CortanaPermission> const& permissions) const
{
    Windows::Foundation::IAsyncOperation<bool> getGrantedPermissionsOperation{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Services::Cortana::ICortanaPermissionsManager)->ArePermissionsGrantedAsync(get_abi(permissions), put_abi(getGrantedPermissionsOperation)));
    return getGrantedPermissionsOperation;
}

template <typename D> Windows::Foundation::IAsyncOperation<Windows::Services::Cortana::CortanaPermissionsChangeResult> consume_Windows_Services_Cortana_ICortanaPermissionsManager<D>::GrantPermissionsAsync(param::async_iterable<Windows::Services::Cortana::CortanaPermission> const& permissions) const
{
    Windows::Foundation::IAsyncOperation<Windows::Services::Cortana::CortanaPermissionsChangeResult> grantOperation{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Services::Cortana::ICortanaPermissionsManager)->GrantPermissionsAsync(get_abi(permissions), put_abi(grantOperation)));
    return grantOperation;
}

template <typename D> Windows::Foundation::IAsyncOperation<Windows::Services::Cortana::CortanaPermissionsChangeResult> consume_Windows_Services_Cortana_ICortanaPermissionsManager<D>::RevokePermissionsAsync(param::async_iterable<Windows::Services::Cortana::CortanaPermission> const& permissions) const
{
    Windows::Foundation::IAsyncOperation<Windows::Services::Cortana::CortanaPermissionsChangeResult> revokeOperation{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Services::Cortana::ICortanaPermissionsManager)->RevokePermissionsAsync(get_abi(permissions), put_abi(revokeOperation)));
    return revokeOperation;
}

template <typename D> Windows::Services::Cortana::CortanaPermissionsManager consume_Windows_Services_Cortana_ICortanaPermissionsManagerStatics<D>::GetDefault() const
{
    Windows::Services::Cortana::CortanaPermissionsManager result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Services::Cortana::ICortanaPermissionsManagerStatics)->GetDefault(put_abi(result)));
    return result;
}

template <typename D> bool consume_Windows_Services_Cortana_ICortanaSettings<D>::HasUserConsentToVoiceActivation() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::Services::Cortana::ICortanaSettings)->get_HasUserConsentToVoiceActivation(&value));
    return value;
}

template <typename D> bool consume_Windows_Services_Cortana_ICortanaSettings<D>::IsVoiceActivationEnabled() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::Services::Cortana::ICortanaSettings)->get_IsVoiceActivationEnabled(&value));
    return value;
}

template <typename D> void consume_Windows_Services_Cortana_ICortanaSettings<D>::IsVoiceActivationEnabled(bool value) const
{
    check_hresult(WINRT_SHIM(Windows::Services::Cortana::ICortanaSettings)->put_IsVoiceActivationEnabled(value));
}

template <typename D> bool consume_Windows_Services_Cortana_ICortanaSettingsStatics<D>::IsSupported() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::Services::Cortana::ICortanaSettingsStatics)->IsSupported(&value));
    return value;
}

template <typename D> Windows::Services::Cortana::CortanaSettings consume_Windows_Services_Cortana_ICortanaSettingsStatics<D>::GetDefault() const
{
    Windows::Services::Cortana::CortanaSettings result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Services::Cortana::ICortanaSettingsStatics)->GetDefault(put_abi(result)));
    return result;
}

template <typename D>
struct produce<D, Windows::Services::Cortana::ICortanaActionableInsights> : produce_base<D, Windows::Services::Cortana::ICortanaActionableInsights>
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

    int32_t WINRT_CALL IsAvailableAsync(void** operation) noexcept final
    {
        try
        {
            *operation = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IsAvailableAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<bool>));
            *operation = detach_from<Windows::Foundation::IAsyncOperation<bool>>(this->shim().IsAvailableAsync());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL ShowInsightsForImageAsync(void* imageStream, void** operation) noexcept final
    {
        try
        {
            *operation = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ShowInsightsForImageAsync, WINRT_WRAP(Windows::Foundation::IAsyncAction), Windows::Storage::Streams::IRandomAccessStreamReference const);
            *operation = detach_from<Windows::Foundation::IAsyncAction>(this->shim().ShowInsightsForImageAsync(*reinterpret_cast<Windows::Storage::Streams::IRandomAccessStreamReference const*>(&imageStream)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL ShowInsightsForImageWithOptionsAsync(void* imageStream, void* options, void** operation) noexcept final
    {
        try
        {
            *operation = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ShowInsightsForImageAsync, WINRT_WRAP(Windows::Foundation::IAsyncAction), Windows::Storage::Streams::IRandomAccessStreamReference const, Windows::Services::Cortana::CortanaActionableInsightsOptions const);
            *operation = detach_from<Windows::Foundation::IAsyncAction>(this->shim().ShowInsightsForImageAsync(*reinterpret_cast<Windows::Storage::Streams::IRandomAccessStreamReference const*>(&imageStream), *reinterpret_cast<Windows::Services::Cortana::CortanaActionableInsightsOptions const*>(&options)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL ShowInsightsForTextAsync(void* text, void** operation) noexcept final
    {
        try
        {
            *operation = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ShowInsightsForTextAsync, WINRT_WRAP(Windows::Foundation::IAsyncAction), hstring const);
            *operation = detach_from<Windows::Foundation::IAsyncAction>(this->shim().ShowInsightsForTextAsync(*reinterpret_cast<hstring const*>(&text)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL ShowInsightsForTextWithOptionsAsync(void* text, void* options, void** operation) noexcept final
    {
        try
        {
            *operation = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ShowInsightsForTextAsync, WINRT_WRAP(Windows::Foundation::IAsyncAction), hstring const, Windows::Services::Cortana::CortanaActionableInsightsOptions const);
            *operation = detach_from<Windows::Foundation::IAsyncAction>(this->shim().ShowInsightsForTextAsync(*reinterpret_cast<hstring const*>(&text), *reinterpret_cast<Windows::Services::Cortana::CortanaActionableInsightsOptions const*>(&options)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL ShowInsightsAsync(void* datapackage, void** operation) noexcept final
    {
        try
        {
            *operation = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ShowInsightsAsync, WINRT_WRAP(Windows::Foundation::IAsyncAction), Windows::ApplicationModel::DataTransfer::DataPackage const);
            *operation = detach_from<Windows::Foundation::IAsyncAction>(this->shim().ShowInsightsAsync(*reinterpret_cast<Windows::ApplicationModel::DataTransfer::DataPackage const*>(&datapackage)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL ShowInsightsWithOptionsAsync(void* datapackage, void* options, void** operation) noexcept final
    {
        try
        {
            *operation = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ShowInsightsAsync, WINRT_WRAP(Windows::Foundation::IAsyncAction), Windows::ApplicationModel::DataTransfer::DataPackage const, Windows::Services::Cortana::CortanaActionableInsightsOptions const);
            *operation = detach_from<Windows::Foundation::IAsyncAction>(this->shim().ShowInsightsAsync(*reinterpret_cast<Windows::ApplicationModel::DataTransfer::DataPackage const*>(&datapackage), *reinterpret_cast<Windows::Services::Cortana::CortanaActionableInsightsOptions const*>(&options)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Services::Cortana::ICortanaActionableInsightsOptions> : produce_base<D, Windows::Services::Cortana::ICortanaActionableInsightsOptions>
{
    int32_t WINRT_CALL get_ContentSourceWebLink(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ContentSourceWebLink, WINRT_WRAP(Windows::Foundation::Uri));
            *value = detach_from<Windows::Foundation::Uri>(this->shim().ContentSourceWebLink());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_ContentSourceWebLink(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ContentSourceWebLink, WINRT_WRAP(void), Windows::Foundation::Uri const&);
            this->shim().ContentSourceWebLink(*reinterpret_cast<Windows::Foundation::Uri const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_SurroundingText(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SurroundingText, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().SurroundingText());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_SurroundingText(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SurroundingText, WINRT_WRAP(void), hstring const&);
            this->shim().SurroundingText(*reinterpret_cast<hstring const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Services::Cortana::ICortanaActionableInsightsStatics> : produce_base<D, Windows::Services::Cortana::ICortanaActionableInsightsStatics>
{
    int32_t WINRT_CALL GetDefault(void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetDefault, WINRT_WRAP(Windows::Services::Cortana::CortanaActionableInsights));
            *result = detach_from<Windows::Services::Cortana::CortanaActionableInsights>(this->shim().GetDefault());
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
            WINRT_ASSERT_DECLARATION(GetForUser, WINRT_WRAP(Windows::Services::Cortana::CortanaActionableInsights), Windows::System::User const&);
            *result = detach_from<Windows::Services::Cortana::CortanaActionableInsights>(this->shim().GetForUser(*reinterpret_cast<Windows::System::User const*>(&user)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Services::Cortana::ICortanaPermissionsManager> : produce_base<D, Windows::Services::Cortana::ICortanaPermissionsManager>
{
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

    int32_t WINRT_CALL ArePermissionsGrantedAsync(void* permissions, void** getGrantedPermissionsOperation) noexcept final
    {
        try
        {
            *getGrantedPermissionsOperation = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ArePermissionsGrantedAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<bool>), Windows::Foundation::Collections::IIterable<Windows::Services::Cortana::CortanaPermission> const);
            *getGrantedPermissionsOperation = detach_from<Windows::Foundation::IAsyncOperation<bool>>(this->shim().ArePermissionsGrantedAsync(*reinterpret_cast<Windows::Foundation::Collections::IIterable<Windows::Services::Cortana::CortanaPermission> const*>(&permissions)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL GrantPermissionsAsync(void* permissions, void** grantOperation) noexcept final
    {
        try
        {
            *grantOperation = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GrantPermissionsAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<Windows::Services::Cortana::CortanaPermissionsChangeResult>), Windows::Foundation::Collections::IIterable<Windows::Services::Cortana::CortanaPermission> const);
            *grantOperation = detach_from<Windows::Foundation::IAsyncOperation<Windows::Services::Cortana::CortanaPermissionsChangeResult>>(this->shim().GrantPermissionsAsync(*reinterpret_cast<Windows::Foundation::Collections::IIterable<Windows::Services::Cortana::CortanaPermission> const*>(&permissions)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL RevokePermissionsAsync(void* permissions, void** revokeOperation) noexcept final
    {
        try
        {
            *revokeOperation = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(RevokePermissionsAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<Windows::Services::Cortana::CortanaPermissionsChangeResult>), Windows::Foundation::Collections::IIterable<Windows::Services::Cortana::CortanaPermission> const);
            *revokeOperation = detach_from<Windows::Foundation::IAsyncOperation<Windows::Services::Cortana::CortanaPermissionsChangeResult>>(this->shim().RevokePermissionsAsync(*reinterpret_cast<Windows::Foundation::Collections::IIterable<Windows::Services::Cortana::CortanaPermission> const*>(&permissions)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Services::Cortana::ICortanaPermissionsManagerStatics> : produce_base<D, Windows::Services::Cortana::ICortanaPermissionsManagerStatics>
{
    int32_t WINRT_CALL GetDefault(void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetDefault, WINRT_WRAP(Windows::Services::Cortana::CortanaPermissionsManager));
            *result = detach_from<Windows::Services::Cortana::CortanaPermissionsManager>(this->shim().GetDefault());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Services::Cortana::ICortanaSettings> : produce_base<D, Windows::Services::Cortana::ICortanaSettings>
{
    int32_t WINRT_CALL get_HasUserConsentToVoiceActivation(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(HasUserConsentToVoiceActivation, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().HasUserConsentToVoiceActivation());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_IsVoiceActivationEnabled(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IsVoiceActivationEnabled, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().IsVoiceActivationEnabled());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_IsVoiceActivationEnabled(bool value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IsVoiceActivationEnabled, WINRT_WRAP(void), bool);
            this->shim().IsVoiceActivationEnabled(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Services::Cortana::ICortanaSettingsStatics> : produce_base<D, Windows::Services::Cortana::ICortanaSettingsStatics>
{
    int32_t WINRT_CALL IsSupported(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IsSupported, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().IsSupported());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL GetDefault(void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetDefault, WINRT_WRAP(Windows::Services::Cortana::CortanaSettings));
            *result = detach_from<Windows::Services::Cortana::CortanaSettings>(this->shim().GetDefault());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

}

WINRT_EXPORT namespace winrt::Windows::Services::Cortana {

inline Windows::Services::Cortana::CortanaActionableInsights CortanaActionableInsights::GetDefault()
{
    return impl::call_factory<CortanaActionableInsights, Windows::Services::Cortana::ICortanaActionableInsightsStatics>([&](auto&& f) { return f.GetDefault(); });
}

inline Windows::Services::Cortana::CortanaActionableInsights CortanaActionableInsights::GetForUser(Windows::System::User const& user)
{
    return impl::call_factory<CortanaActionableInsights, Windows::Services::Cortana::ICortanaActionableInsightsStatics>([&](auto&& f) { return f.GetForUser(user); });
}

inline CortanaActionableInsightsOptions::CortanaActionableInsightsOptions() :
    CortanaActionableInsightsOptions(impl::call_factory<CortanaActionableInsightsOptions>([](auto&& f) { return f.template ActivateInstance<CortanaActionableInsightsOptions>(); }))
{}

inline Windows::Services::Cortana::CortanaPermissionsManager CortanaPermissionsManager::GetDefault()
{
    return impl::call_factory<CortanaPermissionsManager, Windows::Services::Cortana::ICortanaPermissionsManagerStatics>([&](auto&& f) { return f.GetDefault(); });
}

inline bool CortanaSettings::IsSupported()
{
    return impl::call_factory<CortanaSettings, Windows::Services::Cortana::ICortanaSettingsStatics>([&](auto&& f) { return f.IsSupported(); });
}

inline Windows::Services::Cortana::CortanaSettings CortanaSettings::GetDefault()
{
    return impl::call_factory<CortanaSettings, Windows::Services::Cortana::ICortanaSettingsStatics>([&](auto&& f) { return f.GetDefault(); });
}

}

WINRT_EXPORT namespace std {

template<> struct hash<winrt::Windows::Services::Cortana::ICortanaActionableInsights> : winrt::impl::hash_base<winrt::Windows::Services::Cortana::ICortanaActionableInsights> {};
template<> struct hash<winrt::Windows::Services::Cortana::ICortanaActionableInsightsOptions> : winrt::impl::hash_base<winrt::Windows::Services::Cortana::ICortanaActionableInsightsOptions> {};
template<> struct hash<winrt::Windows::Services::Cortana::ICortanaActionableInsightsStatics> : winrt::impl::hash_base<winrt::Windows::Services::Cortana::ICortanaActionableInsightsStatics> {};
template<> struct hash<winrt::Windows::Services::Cortana::ICortanaPermissionsManager> : winrt::impl::hash_base<winrt::Windows::Services::Cortana::ICortanaPermissionsManager> {};
template<> struct hash<winrt::Windows::Services::Cortana::ICortanaPermissionsManagerStatics> : winrt::impl::hash_base<winrt::Windows::Services::Cortana::ICortanaPermissionsManagerStatics> {};
template<> struct hash<winrt::Windows::Services::Cortana::ICortanaSettings> : winrt::impl::hash_base<winrt::Windows::Services::Cortana::ICortanaSettings> {};
template<> struct hash<winrt::Windows::Services::Cortana::ICortanaSettingsStatics> : winrt::impl::hash_base<winrt::Windows::Services::Cortana::ICortanaSettingsStatics> {};
template<> struct hash<winrt::Windows::Services::Cortana::CortanaActionableInsights> : winrt::impl::hash_base<winrt::Windows::Services::Cortana::CortanaActionableInsights> {};
template<> struct hash<winrt::Windows::Services::Cortana::CortanaActionableInsightsOptions> : winrt::impl::hash_base<winrt::Windows::Services::Cortana::CortanaActionableInsightsOptions> {};
template<> struct hash<winrt::Windows::Services::Cortana::CortanaPermissionsManager> : winrt::impl::hash_base<winrt::Windows::Services::Cortana::CortanaPermissionsManager> {};
template<> struct hash<winrt::Windows::Services::Cortana::CortanaSettings> : winrt::impl::hash_base<winrt::Windows::Services::Cortana::CortanaSettings> {};

}
