// C++/WinRT v1.0.190111.3

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#pragma once

#include "winrt/base.h"

#include "winrt/Windows.Foundation.h"
#include "winrt/Windows.Foundation.Collections.h"
#include "winrt/impl/Windows.Security.Authentication.Web.Core.2.h"
#include "winrt/impl/Windows.Security.Credentials.2.h"
#include "winrt/impl/Windows.Storage.Streams.2.h"
#include "winrt/impl/Windows.System.2.h"
#include "winrt/impl/Windows.UI.Xaml.2.h"
#include "winrt/impl/Windows.ApplicationModel.Store.Preview.2.h"
#include "winrt/Windows.ApplicationModel.Store.h"

namespace winrt::impl {

template <typename D> Windows::ApplicationModel::Store::Preview::DeliveryOptimizationDownloadMode consume_Windows_ApplicationModel_Store_Preview_IDeliveryOptimizationSettings<D>::DownloadMode() const
{
    Windows::ApplicationModel::Store::Preview::DeliveryOptimizationDownloadMode value{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Store::Preview::IDeliveryOptimizationSettings)->get_DownloadMode(put_abi(value)));
    return value;
}

template <typename D> Windows::ApplicationModel::Store::Preview::DeliveryOptimizationDownloadModeSource consume_Windows_ApplicationModel_Store_Preview_IDeliveryOptimizationSettings<D>::DownloadModeSource() const
{
    Windows::ApplicationModel::Store::Preview::DeliveryOptimizationDownloadModeSource value{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Store::Preview::IDeliveryOptimizationSettings)->get_DownloadModeSource(put_abi(value)));
    return value;
}

template <typename D> Windows::ApplicationModel::Store::Preview::DeliveryOptimizationSettings consume_Windows_ApplicationModel_Store_Preview_IDeliveryOptimizationSettingsStatics<D>::GetCurrentSettings() const
{
    Windows::ApplicationModel::Store::Preview::DeliveryOptimizationSettings result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Store::Preview::IDeliveryOptimizationSettingsStatics)->GetCurrentSettings(put_abi(result)));
    return result;
}

template <typename D> void consume_Windows_ApplicationModel_Store_Preview_IStoreConfigurationStatics<D>::SetSystemConfiguration(param::hstring const& catalogHardwareManufacturerId, param::hstring const& catalogStoreContentModifierId, Windows::Foundation::DateTime const& systemConfigurationExpiration, param::hstring const& catalogHardwareDescriptor) const
{
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Store::Preview::IStoreConfigurationStatics)->SetSystemConfiguration(get_abi(catalogHardwareManufacturerId), get_abi(catalogStoreContentModifierId), get_abi(systemConfigurationExpiration), get_abi(catalogHardwareDescriptor)));
}

template <typename D> void consume_Windows_ApplicationModel_Store_Preview_IStoreConfigurationStatics<D>::SetMobileOperatorConfiguration(param::hstring const& mobileOperatorId, uint32_t appDownloadLimitInMegabytes, uint32_t updateDownloadLimitInMegabytes) const
{
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Store::Preview::IStoreConfigurationStatics)->SetMobileOperatorConfiguration(get_abi(mobileOperatorId), appDownloadLimitInMegabytes, updateDownloadLimitInMegabytes));
}

template <typename D> void consume_Windows_ApplicationModel_Store_Preview_IStoreConfigurationStatics<D>::SetStoreWebAccountId(param::hstring const& webAccountId) const
{
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Store::Preview::IStoreConfigurationStatics)->SetStoreWebAccountId(get_abi(webAccountId)));
}

template <typename D> bool consume_Windows_ApplicationModel_Store_Preview_IStoreConfigurationStatics<D>::IsStoreWebAccountId(param::hstring const& webAccountId) const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Store::Preview::IStoreConfigurationStatics)->IsStoreWebAccountId(get_abi(webAccountId), &value));
    return value;
}

template <typename D> Windows::ApplicationModel::Store::Preview::StoreHardwareManufacturerInfo consume_Windows_ApplicationModel_Store_Preview_IStoreConfigurationStatics<D>::HardwareManufacturerInfo() const
{
    Windows::ApplicationModel::Store::Preview::StoreHardwareManufacturerInfo value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Store::Preview::IStoreConfigurationStatics)->get_HardwareManufacturerInfo(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::IAsyncOperation<Windows::Foundation::Collections::IVectorView<Windows::ApplicationModel::Store::Preview::StoreSystemFeature>> consume_Windows_ApplicationModel_Store_Preview_IStoreConfigurationStatics<D>::FilterUnsupportedSystemFeaturesAsync(param::async_iterable<Windows::ApplicationModel::Store::Preview::StoreSystemFeature> const& systemFeatures) const
{
    Windows::Foundation::IAsyncOperation<Windows::Foundation::Collections::IVectorView<Windows::ApplicationModel::Store::Preview::StoreSystemFeature>> operation{ nullptr };
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Store::Preview::IStoreConfigurationStatics)->FilterUnsupportedSystemFeaturesAsync(get_abi(systemFeatures), put_abi(operation)));
    return operation;
}

template <typename D> Windows::Foundation::IReference<uint32_t> consume_Windows_ApplicationModel_Store_Preview_IStoreConfigurationStatics2<D>::PurchasePromptingPolicy() const
{
    Windows::Foundation::IReference<uint32_t> value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Store::Preview::IStoreConfigurationStatics2)->get_PurchasePromptingPolicy(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_ApplicationModel_Store_Preview_IStoreConfigurationStatics2<D>::PurchasePromptingPolicy(optional<uint32_t> const& value) const
{
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Store::Preview::IStoreConfigurationStatics2)->put_PurchasePromptingPolicy(get_abi(value)));
}

template <typename D> bool consume_Windows_ApplicationModel_Store_Preview_IStoreConfigurationStatics3<D>::HasStoreWebAccount() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Store::Preview::IStoreConfigurationStatics3)->HasStoreWebAccount(&value));
    return value;
}

template <typename D> bool consume_Windows_ApplicationModel_Store_Preview_IStoreConfigurationStatics3<D>::HasStoreWebAccountForUser(Windows::System::User const& user) const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Store::Preview::IStoreConfigurationStatics3)->HasStoreWebAccountForUser(get_abi(user), &value));
    return value;
}

template <typename D> Windows::Foundation::IAsyncOperation<Windows::Storage::Streams::IRandomAccessStreamReference> consume_Windows_ApplicationModel_Store_Preview_IStoreConfigurationStatics3<D>::GetStoreLogDataAsync(Windows::ApplicationModel::Store::Preview::StoreLogOptions const& options) const
{
    Windows::Foundation::IAsyncOperation<Windows::Storage::Streams::IRandomAccessStreamReference> operation{ nullptr };
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Store::Preview::IStoreConfigurationStatics3)->GetStoreLogDataAsync(get_abi(options), put_abi(operation)));
    return operation;
}

template <typename D> void consume_Windows_ApplicationModel_Store_Preview_IStoreConfigurationStatics3<D>::SetStoreWebAccountIdForUser(Windows::System::User const& user, param::hstring const& webAccountId) const
{
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Store::Preview::IStoreConfigurationStatics3)->SetStoreWebAccountIdForUser(get_abi(user), get_abi(webAccountId)));
}

template <typename D> bool consume_Windows_ApplicationModel_Store_Preview_IStoreConfigurationStatics3<D>::IsStoreWebAccountIdForUser(Windows::System::User const& user, param::hstring const& webAccountId) const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Store::Preview::IStoreConfigurationStatics3)->IsStoreWebAccountIdForUser(get_abi(user), get_abi(webAccountId), &value));
    return value;
}

template <typename D> Windows::Foundation::IReference<uint32_t> consume_Windows_ApplicationModel_Store_Preview_IStoreConfigurationStatics3<D>::GetPurchasePromptingPolicyForUser(Windows::System::User const& user) const
{
    Windows::Foundation::IReference<uint32_t> value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Store::Preview::IStoreConfigurationStatics3)->GetPurchasePromptingPolicyForUser(get_abi(user), put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_ApplicationModel_Store_Preview_IStoreConfigurationStatics3<D>::SetPurchasePromptingPolicyForUser(Windows::System::User const& user, optional<uint32_t> const& value) const
{
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Store::Preview::IStoreConfigurationStatics3)->SetPurchasePromptingPolicyForUser(get_abi(user), get_abi(value)));
}

template <typename D> hstring consume_Windows_ApplicationModel_Store_Preview_IStoreConfigurationStatics4<D>::GetStoreWebAccountId() const
{
    hstring result{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Store::Preview::IStoreConfigurationStatics4)->GetStoreWebAccountId(put_abi(result)));
    return result;
}

template <typename D> hstring consume_Windows_ApplicationModel_Store_Preview_IStoreConfigurationStatics4<D>::GetStoreWebAccountIdForUser(Windows::System::User const& user) const
{
    hstring result{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Store::Preview::IStoreConfigurationStatics4)->GetStoreWebAccountIdForUser(get_abi(user), put_abi(result)));
    return result;
}

template <typename D> void consume_Windows_ApplicationModel_Store_Preview_IStoreConfigurationStatics4<D>::SetEnterpriseStoreWebAccountId(param::hstring const& webAccountId) const
{
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Store::Preview::IStoreConfigurationStatics4)->SetEnterpriseStoreWebAccountId(get_abi(webAccountId)));
}

template <typename D> void consume_Windows_ApplicationModel_Store_Preview_IStoreConfigurationStatics4<D>::SetEnterpriseStoreWebAccountIdForUser(Windows::System::User const& user, param::hstring const& webAccountId) const
{
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Store::Preview::IStoreConfigurationStatics4)->SetEnterpriseStoreWebAccountIdForUser(get_abi(user), get_abi(webAccountId)));
}

template <typename D> hstring consume_Windows_ApplicationModel_Store_Preview_IStoreConfigurationStatics4<D>::GetEnterpriseStoreWebAccountId() const
{
    hstring result{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Store::Preview::IStoreConfigurationStatics4)->GetEnterpriseStoreWebAccountId(put_abi(result)));
    return result;
}

template <typename D> hstring consume_Windows_ApplicationModel_Store_Preview_IStoreConfigurationStatics4<D>::GetEnterpriseStoreWebAccountIdForUser(Windows::System::User const& user) const
{
    hstring result{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Store::Preview::IStoreConfigurationStatics4)->GetEnterpriseStoreWebAccountIdForUser(get_abi(user), put_abi(result)));
    return result;
}

template <typename D> bool consume_Windows_ApplicationModel_Store_Preview_IStoreConfigurationStatics4<D>::ShouldRestrictToEnterpriseStoreOnly() const
{
    bool result{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Store::Preview::IStoreConfigurationStatics4)->ShouldRestrictToEnterpriseStoreOnly(&result));
    return result;
}

template <typename D> bool consume_Windows_ApplicationModel_Store_Preview_IStoreConfigurationStatics4<D>::ShouldRestrictToEnterpriseStoreOnlyForUser(Windows::System::User const& user) const
{
    bool result{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Store::Preview::IStoreConfigurationStatics4)->ShouldRestrictToEnterpriseStoreOnlyForUser(get_abi(user), &result));
    return result;
}

template <typename D> bool consume_Windows_ApplicationModel_Store_Preview_IStoreConfigurationStatics5<D>::IsPinToDesktopSupported() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Store::Preview::IStoreConfigurationStatics5)->IsPinToDesktopSupported(&value));
    return value;
}

template <typename D> bool consume_Windows_ApplicationModel_Store_Preview_IStoreConfigurationStatics5<D>::IsPinToTaskbarSupported() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Store::Preview::IStoreConfigurationStatics5)->IsPinToTaskbarSupported(&value));
    return value;
}

template <typename D> bool consume_Windows_ApplicationModel_Store_Preview_IStoreConfigurationStatics5<D>::IsPinToStartSupported() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Store::Preview::IStoreConfigurationStatics5)->IsPinToStartSupported(&value));
    return value;
}

template <typename D> void consume_Windows_ApplicationModel_Store_Preview_IStoreConfigurationStatics5<D>::PinToDesktop(param::hstring const& appPackageFamilyName) const
{
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Store::Preview::IStoreConfigurationStatics5)->PinToDesktop(get_abi(appPackageFamilyName)));
}

template <typename D> void consume_Windows_ApplicationModel_Store_Preview_IStoreConfigurationStatics5<D>::PinToDesktopForUser(Windows::System::User const& user, param::hstring const& appPackageFamilyName) const
{
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Store::Preview::IStoreConfigurationStatics5)->PinToDesktopForUser(get_abi(user), get_abi(appPackageFamilyName)));
}

template <typename D> hstring consume_Windows_ApplicationModel_Store_Preview_IStoreHardwareManufacturerInfo<D>::HardwareManufacturerId() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Store::Preview::IStoreHardwareManufacturerInfo)->get_HardwareManufacturerId(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_ApplicationModel_Store_Preview_IStoreHardwareManufacturerInfo<D>::StoreContentModifierId() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Store::Preview::IStoreHardwareManufacturerInfo)->get_StoreContentModifierId(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_ApplicationModel_Store_Preview_IStoreHardwareManufacturerInfo<D>::ModelName() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Store::Preview::IStoreHardwareManufacturerInfo)->get_ModelName(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_ApplicationModel_Store_Preview_IStoreHardwareManufacturerInfo<D>::ManufacturerName() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Store::Preview::IStoreHardwareManufacturerInfo)->get_ManufacturerName(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::IAsyncOperation<Windows::ApplicationModel::Store::Preview::StorePreviewPurchaseResults> consume_Windows_ApplicationModel_Store_Preview_IStorePreview<D>::RequestProductPurchaseByProductIdAndSkuIdAsync(param::hstring const& productId, param::hstring const& skuId) const
{
    Windows::Foundation::IAsyncOperation<Windows::ApplicationModel::Store::Preview::StorePreviewPurchaseResults> requestPurchaseBySkuIdOperation{ nullptr };
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Store::Preview::IStorePreview)->RequestProductPurchaseByProductIdAndSkuIdAsync(get_abi(productId), get_abi(skuId), put_abi(requestPurchaseBySkuIdOperation)));
    return requestPurchaseBySkuIdOperation;
}

template <typename D> Windows::Foundation::IAsyncOperation<Windows::Foundation::Collections::IVectorView<Windows::ApplicationModel::Store::Preview::StorePreviewProductInfo>> consume_Windows_ApplicationModel_Store_Preview_IStorePreview<D>::LoadAddOnProductInfosAsync() const
{
    Windows::Foundation::IAsyncOperation<Windows::Foundation::Collections::IVectorView<Windows::ApplicationModel::Store::Preview::StorePreviewProductInfo>> loadAddOnProductInfosOperation{ nullptr };
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Store::Preview::IStorePreview)->LoadAddOnProductInfosAsync(put_abi(loadAddOnProductInfosOperation)));
    return loadAddOnProductInfosOperation;
}

template <typename D> hstring consume_Windows_ApplicationModel_Store_Preview_IStorePreviewProductInfo<D>::ProductId() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Store::Preview::IStorePreviewProductInfo)->get_ProductId(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_ApplicationModel_Store_Preview_IStorePreviewProductInfo<D>::ProductType() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Store::Preview::IStorePreviewProductInfo)->get_ProductType(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_ApplicationModel_Store_Preview_IStorePreviewProductInfo<D>::Title() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Store::Preview::IStorePreviewProductInfo)->get_Title(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_ApplicationModel_Store_Preview_IStorePreviewProductInfo<D>::Description() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Store::Preview::IStorePreviewProductInfo)->get_Description(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::Collections::IVectorView<Windows::ApplicationModel::Store::Preview::StorePreviewSkuInfo> consume_Windows_ApplicationModel_Store_Preview_IStorePreviewProductInfo<D>::SkuInfoList() const
{
    Windows::Foundation::Collections::IVectorView<Windows::ApplicationModel::Store::Preview::StorePreviewSkuInfo> value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Store::Preview::IStorePreviewProductInfo)->get_SkuInfoList(put_abi(value)));
    return value;
}

template <typename D> Windows::ApplicationModel::Store::Preview::StorePreviewProductPurchaseStatus consume_Windows_ApplicationModel_Store_Preview_IStorePreviewPurchaseResults<D>::ProductPurchaseStatus() const
{
    Windows::ApplicationModel::Store::Preview::StorePreviewProductPurchaseStatus value{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Store::Preview::IStorePreviewPurchaseResults)->get_ProductPurchaseStatus(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_ApplicationModel_Store_Preview_IStorePreviewSkuInfo<D>::ProductId() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Store::Preview::IStorePreviewSkuInfo)->get_ProductId(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_ApplicationModel_Store_Preview_IStorePreviewSkuInfo<D>::SkuId() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Store::Preview::IStorePreviewSkuInfo)->get_SkuId(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_ApplicationModel_Store_Preview_IStorePreviewSkuInfo<D>::SkuType() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Store::Preview::IStorePreviewSkuInfo)->get_SkuType(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_ApplicationModel_Store_Preview_IStorePreviewSkuInfo<D>::Title() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Store::Preview::IStorePreviewSkuInfo)->get_Title(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_ApplicationModel_Store_Preview_IStorePreviewSkuInfo<D>::Description() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Store::Preview::IStorePreviewSkuInfo)->get_Description(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_ApplicationModel_Store_Preview_IStorePreviewSkuInfo<D>::CustomDeveloperData() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Store::Preview::IStorePreviewSkuInfo)->get_CustomDeveloperData(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_ApplicationModel_Store_Preview_IStorePreviewSkuInfo<D>::CurrencyCode() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Store::Preview::IStorePreviewSkuInfo)->get_CurrencyCode(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_ApplicationModel_Store_Preview_IStorePreviewSkuInfo<D>::FormattedListPrice() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Store::Preview::IStorePreviewSkuInfo)->get_FormattedListPrice(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_ApplicationModel_Store_Preview_IStorePreviewSkuInfo<D>::ExtendedData() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Store::Preview::IStorePreviewSkuInfo)->get_ExtendedData(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::IAsyncOperation<Windows::Security::Authentication::Web::Core::WebTokenRequestResult> consume_Windows_ApplicationModel_Store_Preview_IWebAuthenticationCoreManagerHelper<D>::RequestTokenWithUIElementHostingAsync(Windows::Security::Authentication::Web::Core::WebTokenRequest const& request, Windows::UI::Xaml::UIElement const& uiElement) const
{
    Windows::Foundation::IAsyncOperation<Windows::Security::Authentication::Web::Core::WebTokenRequestResult> asyncInfo{ nullptr };
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Store::Preview::IWebAuthenticationCoreManagerHelper)->RequestTokenWithUIElementHostingAsync(get_abi(request), get_abi(uiElement), put_abi(asyncInfo)));
    return asyncInfo;
}

template <typename D> Windows::Foundation::IAsyncOperation<Windows::Security::Authentication::Web::Core::WebTokenRequestResult> consume_Windows_ApplicationModel_Store_Preview_IWebAuthenticationCoreManagerHelper<D>::RequestTokenWithUIElementHostingAsync(Windows::Security::Authentication::Web::Core::WebTokenRequest const& request, Windows::Security::Credentials::WebAccount const& webAccount, Windows::UI::Xaml::UIElement const& uiElement) const
{
    Windows::Foundation::IAsyncOperation<Windows::Security::Authentication::Web::Core::WebTokenRequestResult> asyncInfo{ nullptr };
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Store::Preview::IWebAuthenticationCoreManagerHelper)->RequestTokenWithUIElementHostingAndWebAccountAsync(get_abi(request), get_abi(webAccount), get_abi(uiElement), put_abi(asyncInfo)));
    return asyncInfo;
}

template <typename D>
struct produce<D, Windows::ApplicationModel::Store::Preview::IDeliveryOptimizationSettings> : produce_base<D, Windows::ApplicationModel::Store::Preview::IDeliveryOptimizationSettings>
{
    int32_t WINRT_CALL get_DownloadMode(Windows::ApplicationModel::Store::Preview::DeliveryOptimizationDownloadMode* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(DownloadMode, WINRT_WRAP(Windows::ApplicationModel::Store::Preview::DeliveryOptimizationDownloadMode));
            *value = detach_from<Windows::ApplicationModel::Store::Preview::DeliveryOptimizationDownloadMode>(this->shim().DownloadMode());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_DownloadModeSource(Windows::ApplicationModel::Store::Preview::DeliveryOptimizationDownloadModeSource* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(DownloadModeSource, WINRT_WRAP(Windows::ApplicationModel::Store::Preview::DeliveryOptimizationDownloadModeSource));
            *value = detach_from<Windows::ApplicationModel::Store::Preview::DeliveryOptimizationDownloadModeSource>(this->shim().DownloadModeSource());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::ApplicationModel::Store::Preview::IDeliveryOptimizationSettingsStatics> : produce_base<D, Windows::ApplicationModel::Store::Preview::IDeliveryOptimizationSettingsStatics>
{
    int32_t WINRT_CALL GetCurrentSettings(void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetCurrentSettings, WINRT_WRAP(Windows::ApplicationModel::Store::Preview::DeliveryOptimizationSettings));
            *result = detach_from<Windows::ApplicationModel::Store::Preview::DeliveryOptimizationSettings>(this->shim().GetCurrentSettings());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::ApplicationModel::Store::Preview::IStoreConfigurationStatics> : produce_base<D, Windows::ApplicationModel::Store::Preview::IStoreConfigurationStatics>
{
    int32_t WINRT_CALL SetSystemConfiguration(void* catalogHardwareManufacturerId, void* catalogStoreContentModifierId, Windows::Foundation::DateTime systemConfigurationExpiration, void* catalogHardwareDescriptor) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SetSystemConfiguration, WINRT_WRAP(void), hstring const&, hstring const&, Windows::Foundation::DateTime const&, hstring const&);
            this->shim().SetSystemConfiguration(*reinterpret_cast<hstring const*>(&catalogHardwareManufacturerId), *reinterpret_cast<hstring const*>(&catalogStoreContentModifierId), *reinterpret_cast<Windows::Foundation::DateTime const*>(&systemConfigurationExpiration), *reinterpret_cast<hstring const*>(&catalogHardwareDescriptor));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL SetMobileOperatorConfiguration(void* mobileOperatorId, uint32_t appDownloadLimitInMegabytes, uint32_t updateDownloadLimitInMegabytes) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SetMobileOperatorConfiguration, WINRT_WRAP(void), hstring const&, uint32_t, uint32_t);
            this->shim().SetMobileOperatorConfiguration(*reinterpret_cast<hstring const*>(&mobileOperatorId), appDownloadLimitInMegabytes, updateDownloadLimitInMegabytes);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL SetStoreWebAccountId(void* webAccountId) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SetStoreWebAccountId, WINRT_WRAP(void), hstring const&);
            this->shim().SetStoreWebAccountId(*reinterpret_cast<hstring const*>(&webAccountId));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL IsStoreWebAccountId(void* webAccountId, bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IsStoreWebAccountId, WINRT_WRAP(bool), hstring const&);
            *value = detach_from<bool>(this->shim().IsStoreWebAccountId(*reinterpret_cast<hstring const*>(&webAccountId)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_HardwareManufacturerInfo(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(HardwareManufacturerInfo, WINRT_WRAP(Windows::ApplicationModel::Store::Preview::StoreHardwareManufacturerInfo));
            *value = detach_from<Windows::ApplicationModel::Store::Preview::StoreHardwareManufacturerInfo>(this->shim().HardwareManufacturerInfo());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL FilterUnsupportedSystemFeaturesAsync(void* systemFeatures, void** operation) noexcept final
    {
        try
        {
            *operation = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(FilterUnsupportedSystemFeaturesAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<Windows::Foundation::Collections::IVectorView<Windows::ApplicationModel::Store::Preview::StoreSystemFeature>>), Windows::Foundation::Collections::IIterable<Windows::ApplicationModel::Store::Preview::StoreSystemFeature> const);
            *operation = detach_from<Windows::Foundation::IAsyncOperation<Windows::Foundation::Collections::IVectorView<Windows::ApplicationModel::Store::Preview::StoreSystemFeature>>>(this->shim().FilterUnsupportedSystemFeaturesAsync(*reinterpret_cast<Windows::Foundation::Collections::IIterable<Windows::ApplicationModel::Store::Preview::StoreSystemFeature> const*>(&systemFeatures)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::ApplicationModel::Store::Preview::IStoreConfigurationStatics2> : produce_base<D, Windows::ApplicationModel::Store::Preview::IStoreConfigurationStatics2>
{
    int32_t WINRT_CALL get_PurchasePromptingPolicy(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(PurchasePromptingPolicy, WINRT_WRAP(Windows::Foundation::IReference<uint32_t>));
            *value = detach_from<Windows::Foundation::IReference<uint32_t>>(this->shim().PurchasePromptingPolicy());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_PurchasePromptingPolicy(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(PurchasePromptingPolicy, WINRT_WRAP(void), Windows::Foundation::IReference<uint32_t> const&);
            this->shim().PurchasePromptingPolicy(*reinterpret_cast<Windows::Foundation::IReference<uint32_t> const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::ApplicationModel::Store::Preview::IStoreConfigurationStatics3> : produce_base<D, Windows::ApplicationModel::Store::Preview::IStoreConfigurationStatics3>
{
    int32_t WINRT_CALL HasStoreWebAccount(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(HasStoreWebAccount, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().HasStoreWebAccount());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL HasStoreWebAccountForUser(void* user, bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(HasStoreWebAccountForUser, WINRT_WRAP(bool), Windows::System::User const&);
            *value = detach_from<bool>(this->shim().HasStoreWebAccountForUser(*reinterpret_cast<Windows::System::User const*>(&user)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL GetStoreLogDataAsync(Windows::ApplicationModel::Store::Preview::StoreLogOptions options, void** operation) noexcept final
    {
        try
        {
            *operation = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetStoreLogDataAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<Windows::Storage::Streams::IRandomAccessStreamReference>), Windows::ApplicationModel::Store::Preview::StoreLogOptions const);
            *operation = detach_from<Windows::Foundation::IAsyncOperation<Windows::Storage::Streams::IRandomAccessStreamReference>>(this->shim().GetStoreLogDataAsync(*reinterpret_cast<Windows::ApplicationModel::Store::Preview::StoreLogOptions const*>(&options)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL SetStoreWebAccountIdForUser(void* user, void* webAccountId) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SetStoreWebAccountIdForUser, WINRT_WRAP(void), Windows::System::User const&, hstring const&);
            this->shim().SetStoreWebAccountIdForUser(*reinterpret_cast<Windows::System::User const*>(&user), *reinterpret_cast<hstring const*>(&webAccountId));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL IsStoreWebAccountIdForUser(void* user, void* webAccountId, bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IsStoreWebAccountIdForUser, WINRT_WRAP(bool), Windows::System::User const&, hstring const&);
            *value = detach_from<bool>(this->shim().IsStoreWebAccountIdForUser(*reinterpret_cast<Windows::System::User const*>(&user), *reinterpret_cast<hstring const*>(&webAccountId)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL GetPurchasePromptingPolicyForUser(void* user, void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetPurchasePromptingPolicyForUser, WINRT_WRAP(Windows::Foundation::IReference<uint32_t>), Windows::System::User const&);
            *value = detach_from<Windows::Foundation::IReference<uint32_t>>(this->shim().GetPurchasePromptingPolicyForUser(*reinterpret_cast<Windows::System::User const*>(&user)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL SetPurchasePromptingPolicyForUser(void* user, void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SetPurchasePromptingPolicyForUser, WINRT_WRAP(void), Windows::System::User const&, Windows::Foundation::IReference<uint32_t> const&);
            this->shim().SetPurchasePromptingPolicyForUser(*reinterpret_cast<Windows::System::User const*>(&user), *reinterpret_cast<Windows::Foundation::IReference<uint32_t> const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::ApplicationModel::Store::Preview::IStoreConfigurationStatics4> : produce_base<D, Windows::ApplicationModel::Store::Preview::IStoreConfigurationStatics4>
{
    int32_t WINRT_CALL GetStoreWebAccountId(void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetStoreWebAccountId, WINRT_WRAP(hstring));
            *result = detach_from<hstring>(this->shim().GetStoreWebAccountId());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL GetStoreWebAccountIdForUser(void* user, void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetStoreWebAccountIdForUser, WINRT_WRAP(hstring), Windows::System::User const&);
            *result = detach_from<hstring>(this->shim().GetStoreWebAccountIdForUser(*reinterpret_cast<Windows::System::User const*>(&user)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL SetEnterpriseStoreWebAccountId(void* webAccountId) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SetEnterpriseStoreWebAccountId, WINRT_WRAP(void), hstring const&);
            this->shim().SetEnterpriseStoreWebAccountId(*reinterpret_cast<hstring const*>(&webAccountId));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL SetEnterpriseStoreWebAccountIdForUser(void* user, void* webAccountId) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SetEnterpriseStoreWebAccountIdForUser, WINRT_WRAP(void), Windows::System::User const&, hstring const&);
            this->shim().SetEnterpriseStoreWebAccountIdForUser(*reinterpret_cast<Windows::System::User const*>(&user), *reinterpret_cast<hstring const*>(&webAccountId));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL GetEnterpriseStoreWebAccountId(void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetEnterpriseStoreWebAccountId, WINRT_WRAP(hstring));
            *result = detach_from<hstring>(this->shim().GetEnterpriseStoreWebAccountId());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL GetEnterpriseStoreWebAccountIdForUser(void* user, void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetEnterpriseStoreWebAccountIdForUser, WINRT_WRAP(hstring), Windows::System::User const&);
            *result = detach_from<hstring>(this->shim().GetEnterpriseStoreWebAccountIdForUser(*reinterpret_cast<Windows::System::User const*>(&user)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL ShouldRestrictToEnterpriseStoreOnly(bool* result) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ShouldRestrictToEnterpriseStoreOnly, WINRT_WRAP(bool));
            *result = detach_from<bool>(this->shim().ShouldRestrictToEnterpriseStoreOnly());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL ShouldRestrictToEnterpriseStoreOnlyForUser(void* user, bool* result) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ShouldRestrictToEnterpriseStoreOnlyForUser, WINRT_WRAP(bool), Windows::System::User const&);
            *result = detach_from<bool>(this->shim().ShouldRestrictToEnterpriseStoreOnlyForUser(*reinterpret_cast<Windows::System::User const*>(&user)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::ApplicationModel::Store::Preview::IStoreConfigurationStatics5> : produce_base<D, Windows::ApplicationModel::Store::Preview::IStoreConfigurationStatics5>
{
    int32_t WINRT_CALL IsPinToDesktopSupported(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IsPinToDesktopSupported, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().IsPinToDesktopSupported());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL IsPinToTaskbarSupported(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IsPinToTaskbarSupported, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().IsPinToTaskbarSupported());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL IsPinToStartSupported(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IsPinToStartSupported, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().IsPinToStartSupported());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL PinToDesktop(void* appPackageFamilyName) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(PinToDesktop, WINRT_WRAP(void), hstring const&);
            this->shim().PinToDesktop(*reinterpret_cast<hstring const*>(&appPackageFamilyName));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL PinToDesktopForUser(void* user, void* appPackageFamilyName) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(PinToDesktopForUser, WINRT_WRAP(void), Windows::System::User const&, hstring const&);
            this->shim().PinToDesktopForUser(*reinterpret_cast<Windows::System::User const*>(&user), *reinterpret_cast<hstring const*>(&appPackageFamilyName));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::ApplicationModel::Store::Preview::IStoreHardwareManufacturerInfo> : produce_base<D, Windows::ApplicationModel::Store::Preview::IStoreHardwareManufacturerInfo>
{
    int32_t WINRT_CALL get_HardwareManufacturerId(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(HardwareManufacturerId, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().HardwareManufacturerId());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_StoreContentModifierId(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(StoreContentModifierId, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().StoreContentModifierId());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_ModelName(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ModelName, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().ModelName());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_ManufacturerName(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ManufacturerName, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().ManufacturerName());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::ApplicationModel::Store::Preview::IStorePreview> : produce_base<D, Windows::ApplicationModel::Store::Preview::IStorePreview>
{
    int32_t WINRT_CALL RequestProductPurchaseByProductIdAndSkuIdAsync(void* productId, void* skuId, void** requestPurchaseBySkuIdOperation) noexcept final
    {
        try
        {
            *requestPurchaseBySkuIdOperation = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(RequestProductPurchaseByProductIdAndSkuIdAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<Windows::ApplicationModel::Store::Preview::StorePreviewPurchaseResults>), hstring const, hstring const);
            *requestPurchaseBySkuIdOperation = detach_from<Windows::Foundation::IAsyncOperation<Windows::ApplicationModel::Store::Preview::StorePreviewPurchaseResults>>(this->shim().RequestProductPurchaseByProductIdAndSkuIdAsync(*reinterpret_cast<hstring const*>(&productId), *reinterpret_cast<hstring const*>(&skuId)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL LoadAddOnProductInfosAsync(void** loadAddOnProductInfosOperation) noexcept final
    {
        try
        {
            *loadAddOnProductInfosOperation = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(LoadAddOnProductInfosAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<Windows::Foundation::Collections::IVectorView<Windows::ApplicationModel::Store::Preview::StorePreviewProductInfo>>));
            *loadAddOnProductInfosOperation = detach_from<Windows::Foundation::IAsyncOperation<Windows::Foundation::Collections::IVectorView<Windows::ApplicationModel::Store::Preview::StorePreviewProductInfo>>>(this->shim().LoadAddOnProductInfosAsync());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::ApplicationModel::Store::Preview::IStorePreviewProductInfo> : produce_base<D, Windows::ApplicationModel::Store::Preview::IStorePreviewProductInfo>
{
    int32_t WINRT_CALL get_ProductId(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ProductId, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().ProductId());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_ProductType(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ProductType, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().ProductType());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Title(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Title, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().Title());
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

    int32_t WINRT_CALL get_SkuInfoList(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SkuInfoList, WINRT_WRAP(Windows::Foundation::Collections::IVectorView<Windows::ApplicationModel::Store::Preview::StorePreviewSkuInfo>));
            *value = detach_from<Windows::Foundation::Collections::IVectorView<Windows::ApplicationModel::Store::Preview::StorePreviewSkuInfo>>(this->shim().SkuInfoList());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::ApplicationModel::Store::Preview::IStorePreviewPurchaseResults> : produce_base<D, Windows::ApplicationModel::Store::Preview::IStorePreviewPurchaseResults>
{
    int32_t WINRT_CALL get_ProductPurchaseStatus(Windows::ApplicationModel::Store::Preview::StorePreviewProductPurchaseStatus* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ProductPurchaseStatus, WINRT_WRAP(Windows::ApplicationModel::Store::Preview::StorePreviewProductPurchaseStatus));
            *value = detach_from<Windows::ApplicationModel::Store::Preview::StorePreviewProductPurchaseStatus>(this->shim().ProductPurchaseStatus());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::ApplicationModel::Store::Preview::IStorePreviewSkuInfo> : produce_base<D, Windows::ApplicationModel::Store::Preview::IStorePreviewSkuInfo>
{
    int32_t WINRT_CALL get_ProductId(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ProductId, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().ProductId());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_SkuId(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SkuId, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().SkuId());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_SkuType(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SkuType, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().SkuType());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Title(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Title, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().Title());
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

    int32_t WINRT_CALL get_CustomDeveloperData(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CustomDeveloperData, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().CustomDeveloperData());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_CurrencyCode(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CurrencyCode, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().CurrencyCode());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_FormattedListPrice(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(FormattedListPrice, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().FormattedListPrice());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_ExtendedData(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ExtendedData, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().ExtendedData());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::ApplicationModel::Store::Preview::IWebAuthenticationCoreManagerHelper> : produce_base<D, Windows::ApplicationModel::Store::Preview::IWebAuthenticationCoreManagerHelper>
{
    int32_t WINRT_CALL RequestTokenWithUIElementHostingAsync(void* request, void* uiElement, void** asyncInfo) noexcept final
    {
        try
        {
            *asyncInfo = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(RequestTokenWithUIElementHostingAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<Windows::Security::Authentication::Web::Core::WebTokenRequestResult>), Windows::Security::Authentication::Web::Core::WebTokenRequest const, Windows::UI::Xaml::UIElement const);
            *asyncInfo = detach_from<Windows::Foundation::IAsyncOperation<Windows::Security::Authentication::Web::Core::WebTokenRequestResult>>(this->shim().RequestTokenWithUIElementHostingAsync(*reinterpret_cast<Windows::Security::Authentication::Web::Core::WebTokenRequest const*>(&request), *reinterpret_cast<Windows::UI::Xaml::UIElement const*>(&uiElement)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL RequestTokenWithUIElementHostingAndWebAccountAsync(void* request, void* webAccount, void* uiElement, void** asyncInfo) noexcept final
    {
        try
        {
            *asyncInfo = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(RequestTokenWithUIElementHostingAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<Windows::Security::Authentication::Web::Core::WebTokenRequestResult>), Windows::Security::Authentication::Web::Core::WebTokenRequest const, Windows::Security::Credentials::WebAccount const, Windows::UI::Xaml::UIElement const);
            *asyncInfo = detach_from<Windows::Foundation::IAsyncOperation<Windows::Security::Authentication::Web::Core::WebTokenRequestResult>>(this->shim().RequestTokenWithUIElementHostingAsync(*reinterpret_cast<Windows::Security::Authentication::Web::Core::WebTokenRequest const*>(&request), *reinterpret_cast<Windows::Security::Credentials::WebAccount const*>(&webAccount), *reinterpret_cast<Windows::UI::Xaml::UIElement const*>(&uiElement)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

}

WINRT_EXPORT namespace winrt::Windows::ApplicationModel::Store::Preview {

inline Windows::ApplicationModel::Store::Preview::DeliveryOptimizationSettings DeliveryOptimizationSettings::GetCurrentSettings()
{
    return impl::call_factory<DeliveryOptimizationSettings, Windows::ApplicationModel::Store::Preview::IDeliveryOptimizationSettingsStatics>([&](auto&& f) { return f.GetCurrentSettings(); });
}

inline void StoreConfiguration::SetSystemConfiguration(param::hstring const& catalogHardwareManufacturerId, param::hstring const& catalogStoreContentModifierId, Windows::Foundation::DateTime const& systemConfigurationExpiration, param::hstring const& catalogHardwareDescriptor)
{
    impl::call_factory<StoreConfiguration, Windows::ApplicationModel::Store::Preview::IStoreConfigurationStatics>([&](auto&& f) { return f.SetSystemConfiguration(catalogHardwareManufacturerId, catalogStoreContentModifierId, systemConfigurationExpiration, catalogHardwareDescriptor); });
}

inline void StoreConfiguration::SetMobileOperatorConfiguration(param::hstring const& mobileOperatorId, uint32_t appDownloadLimitInMegabytes, uint32_t updateDownloadLimitInMegabytes)
{
    impl::call_factory<StoreConfiguration, Windows::ApplicationModel::Store::Preview::IStoreConfigurationStatics>([&](auto&& f) { return f.SetMobileOperatorConfiguration(mobileOperatorId, appDownloadLimitInMegabytes, updateDownloadLimitInMegabytes); });
}

inline void StoreConfiguration::SetStoreWebAccountId(param::hstring const& webAccountId)
{
    impl::call_factory<StoreConfiguration, Windows::ApplicationModel::Store::Preview::IStoreConfigurationStatics>([&](auto&& f) { return f.SetStoreWebAccountId(webAccountId); });
}

inline bool StoreConfiguration::IsStoreWebAccountId(param::hstring const& webAccountId)
{
    return impl::call_factory<StoreConfiguration, Windows::ApplicationModel::Store::Preview::IStoreConfigurationStatics>([&](auto&& f) { return f.IsStoreWebAccountId(webAccountId); });
}

inline Windows::ApplicationModel::Store::Preview::StoreHardwareManufacturerInfo StoreConfiguration::HardwareManufacturerInfo()
{
    return impl::call_factory<StoreConfiguration, Windows::ApplicationModel::Store::Preview::IStoreConfigurationStatics>([&](auto&& f) { return f.HardwareManufacturerInfo(); });
}

inline Windows::Foundation::IAsyncOperation<Windows::Foundation::Collections::IVectorView<Windows::ApplicationModel::Store::Preview::StoreSystemFeature>> StoreConfiguration::FilterUnsupportedSystemFeaturesAsync(param::async_iterable<Windows::ApplicationModel::Store::Preview::StoreSystemFeature> const& systemFeatures)
{
    return impl::call_factory<StoreConfiguration, Windows::ApplicationModel::Store::Preview::IStoreConfigurationStatics>([&](auto&& f) { return f.FilterUnsupportedSystemFeaturesAsync(systemFeatures); });
}

inline Windows::Foundation::IReference<uint32_t> StoreConfiguration::PurchasePromptingPolicy()
{
    return impl::call_factory<StoreConfiguration, Windows::ApplicationModel::Store::Preview::IStoreConfigurationStatics2>([&](auto&& f) { return f.PurchasePromptingPolicy(); });
}

inline void StoreConfiguration::PurchasePromptingPolicy(optional<uint32_t> const& value)
{
    impl::call_factory<StoreConfiguration, Windows::ApplicationModel::Store::Preview::IStoreConfigurationStatics2>([&](auto&& f) { return f.PurchasePromptingPolicy(value); });
}

inline bool StoreConfiguration::HasStoreWebAccount()
{
    return impl::call_factory<StoreConfiguration, Windows::ApplicationModel::Store::Preview::IStoreConfigurationStatics3>([&](auto&& f) { return f.HasStoreWebAccount(); });
}

inline bool StoreConfiguration::HasStoreWebAccountForUser(Windows::System::User const& user)
{
    return impl::call_factory<StoreConfiguration, Windows::ApplicationModel::Store::Preview::IStoreConfigurationStatics3>([&](auto&& f) { return f.HasStoreWebAccountForUser(user); });
}

inline Windows::Foundation::IAsyncOperation<Windows::Storage::Streams::IRandomAccessStreamReference> StoreConfiguration::GetStoreLogDataAsync(Windows::ApplicationModel::Store::Preview::StoreLogOptions const& options)
{
    return impl::call_factory<StoreConfiguration, Windows::ApplicationModel::Store::Preview::IStoreConfigurationStatics3>([&](auto&& f) { return f.GetStoreLogDataAsync(options); });
}

inline void StoreConfiguration::SetStoreWebAccountIdForUser(Windows::System::User const& user, param::hstring const& webAccountId)
{
    impl::call_factory<StoreConfiguration, Windows::ApplicationModel::Store::Preview::IStoreConfigurationStatics3>([&](auto&& f) { return f.SetStoreWebAccountIdForUser(user, webAccountId); });
}

inline bool StoreConfiguration::IsStoreWebAccountIdForUser(Windows::System::User const& user, param::hstring const& webAccountId)
{
    return impl::call_factory<StoreConfiguration, Windows::ApplicationModel::Store::Preview::IStoreConfigurationStatics3>([&](auto&& f) { return f.IsStoreWebAccountIdForUser(user, webAccountId); });
}

inline Windows::Foundation::IReference<uint32_t> StoreConfiguration::GetPurchasePromptingPolicyForUser(Windows::System::User const& user)
{
    return impl::call_factory<StoreConfiguration, Windows::ApplicationModel::Store::Preview::IStoreConfigurationStatics3>([&](auto&& f) { return f.GetPurchasePromptingPolicyForUser(user); });
}

inline void StoreConfiguration::SetPurchasePromptingPolicyForUser(Windows::System::User const& user, optional<uint32_t> const& value)
{
    impl::call_factory<StoreConfiguration, Windows::ApplicationModel::Store::Preview::IStoreConfigurationStatics3>([&](auto&& f) { return f.SetPurchasePromptingPolicyForUser(user, value); });
}

inline hstring StoreConfiguration::GetStoreWebAccountId()
{
    return impl::call_factory<StoreConfiguration, Windows::ApplicationModel::Store::Preview::IStoreConfigurationStatics4>([&](auto&& f) { return f.GetStoreWebAccountId(); });
}

inline hstring StoreConfiguration::GetStoreWebAccountIdForUser(Windows::System::User const& user)
{
    return impl::call_factory<StoreConfiguration, Windows::ApplicationModel::Store::Preview::IStoreConfigurationStatics4>([&](auto&& f) { return f.GetStoreWebAccountIdForUser(user); });
}

inline void StoreConfiguration::SetEnterpriseStoreWebAccountId(param::hstring const& webAccountId)
{
    impl::call_factory<StoreConfiguration, Windows::ApplicationModel::Store::Preview::IStoreConfigurationStatics4>([&](auto&& f) { return f.SetEnterpriseStoreWebAccountId(webAccountId); });
}

inline void StoreConfiguration::SetEnterpriseStoreWebAccountIdForUser(Windows::System::User const& user, param::hstring const& webAccountId)
{
    impl::call_factory<StoreConfiguration, Windows::ApplicationModel::Store::Preview::IStoreConfigurationStatics4>([&](auto&& f) { return f.SetEnterpriseStoreWebAccountIdForUser(user, webAccountId); });
}

inline hstring StoreConfiguration::GetEnterpriseStoreWebAccountId()
{
    return impl::call_factory<StoreConfiguration, Windows::ApplicationModel::Store::Preview::IStoreConfigurationStatics4>([&](auto&& f) { return f.GetEnterpriseStoreWebAccountId(); });
}

inline hstring StoreConfiguration::GetEnterpriseStoreWebAccountIdForUser(Windows::System::User const& user)
{
    return impl::call_factory<StoreConfiguration, Windows::ApplicationModel::Store::Preview::IStoreConfigurationStatics4>([&](auto&& f) { return f.GetEnterpriseStoreWebAccountIdForUser(user); });
}

inline bool StoreConfiguration::ShouldRestrictToEnterpriseStoreOnly()
{
    return impl::call_factory<StoreConfiguration, Windows::ApplicationModel::Store::Preview::IStoreConfigurationStatics4>([&](auto&& f) { return f.ShouldRestrictToEnterpriseStoreOnly(); });
}

inline bool StoreConfiguration::ShouldRestrictToEnterpriseStoreOnlyForUser(Windows::System::User const& user)
{
    return impl::call_factory<StoreConfiguration, Windows::ApplicationModel::Store::Preview::IStoreConfigurationStatics4>([&](auto&& f) { return f.ShouldRestrictToEnterpriseStoreOnlyForUser(user); });
}

inline bool StoreConfiguration::IsPinToDesktopSupported()
{
    return impl::call_factory<StoreConfiguration, Windows::ApplicationModel::Store::Preview::IStoreConfigurationStatics5>([&](auto&& f) { return f.IsPinToDesktopSupported(); });
}

inline bool StoreConfiguration::IsPinToTaskbarSupported()
{
    return impl::call_factory<StoreConfiguration, Windows::ApplicationModel::Store::Preview::IStoreConfigurationStatics5>([&](auto&& f) { return f.IsPinToTaskbarSupported(); });
}

inline bool StoreConfiguration::IsPinToStartSupported()
{
    return impl::call_factory<StoreConfiguration, Windows::ApplicationModel::Store::Preview::IStoreConfigurationStatics5>([&](auto&& f) { return f.IsPinToStartSupported(); });
}

inline void StoreConfiguration::PinToDesktop(param::hstring const& appPackageFamilyName)
{
    impl::call_factory<StoreConfiguration, Windows::ApplicationModel::Store::Preview::IStoreConfigurationStatics5>([&](auto&& f) { return f.PinToDesktop(appPackageFamilyName); });
}

inline void StoreConfiguration::PinToDesktopForUser(Windows::System::User const& user, param::hstring const& appPackageFamilyName)
{
    impl::call_factory<StoreConfiguration, Windows::ApplicationModel::Store::Preview::IStoreConfigurationStatics5>([&](auto&& f) { return f.PinToDesktopForUser(user, appPackageFamilyName); });
}

inline Windows::Foundation::IAsyncOperation<Windows::ApplicationModel::Store::Preview::StorePreviewPurchaseResults> StorePreview::RequestProductPurchaseByProductIdAndSkuIdAsync(param::hstring const& productId, param::hstring const& skuId)
{
    return impl::call_factory<StorePreview, Windows::ApplicationModel::Store::Preview::IStorePreview>([&](auto&& f) { return f.RequestProductPurchaseByProductIdAndSkuIdAsync(productId, skuId); });
}

inline Windows::Foundation::IAsyncOperation<Windows::Foundation::Collections::IVectorView<Windows::ApplicationModel::Store::Preview::StorePreviewProductInfo>> StorePreview::LoadAddOnProductInfosAsync()
{
    return impl::call_factory<StorePreview, Windows::ApplicationModel::Store::Preview::IStorePreview>([&](auto&& f) { return f.LoadAddOnProductInfosAsync(); });
}

inline Windows::Foundation::IAsyncOperation<Windows::Security::Authentication::Web::Core::WebTokenRequestResult> WebAuthenticationCoreManagerHelper::RequestTokenWithUIElementHostingAsync(Windows::Security::Authentication::Web::Core::WebTokenRequest const& request, Windows::UI::Xaml::UIElement const& uiElement)
{
    return impl::call_factory<WebAuthenticationCoreManagerHelper, Windows::ApplicationModel::Store::Preview::IWebAuthenticationCoreManagerHelper>([&](auto&& f) { return f.RequestTokenWithUIElementHostingAsync(request, uiElement); });
}

inline Windows::Foundation::IAsyncOperation<Windows::Security::Authentication::Web::Core::WebTokenRequestResult> WebAuthenticationCoreManagerHelper::RequestTokenWithUIElementHostingAsync(Windows::Security::Authentication::Web::Core::WebTokenRequest const& request, Windows::Security::Credentials::WebAccount const& webAccount, Windows::UI::Xaml::UIElement const& uiElement)
{
    return impl::call_factory<WebAuthenticationCoreManagerHelper, Windows::ApplicationModel::Store::Preview::IWebAuthenticationCoreManagerHelper>([&](auto&& f) { return f.RequestTokenWithUIElementHostingAsync(request, webAccount, uiElement); });
}

}

WINRT_EXPORT namespace std {

template<> struct hash<winrt::Windows::ApplicationModel::Store::Preview::IDeliveryOptimizationSettings> : winrt::impl::hash_base<winrt::Windows::ApplicationModel::Store::Preview::IDeliveryOptimizationSettings> {};
template<> struct hash<winrt::Windows::ApplicationModel::Store::Preview::IDeliveryOptimizationSettingsStatics> : winrt::impl::hash_base<winrt::Windows::ApplicationModel::Store::Preview::IDeliveryOptimizationSettingsStatics> {};
template<> struct hash<winrt::Windows::ApplicationModel::Store::Preview::IStoreConfigurationStatics> : winrt::impl::hash_base<winrt::Windows::ApplicationModel::Store::Preview::IStoreConfigurationStatics> {};
template<> struct hash<winrt::Windows::ApplicationModel::Store::Preview::IStoreConfigurationStatics2> : winrt::impl::hash_base<winrt::Windows::ApplicationModel::Store::Preview::IStoreConfigurationStatics2> {};
template<> struct hash<winrt::Windows::ApplicationModel::Store::Preview::IStoreConfigurationStatics3> : winrt::impl::hash_base<winrt::Windows::ApplicationModel::Store::Preview::IStoreConfigurationStatics3> {};
template<> struct hash<winrt::Windows::ApplicationModel::Store::Preview::IStoreConfigurationStatics4> : winrt::impl::hash_base<winrt::Windows::ApplicationModel::Store::Preview::IStoreConfigurationStatics4> {};
template<> struct hash<winrt::Windows::ApplicationModel::Store::Preview::IStoreConfigurationStatics5> : winrt::impl::hash_base<winrt::Windows::ApplicationModel::Store::Preview::IStoreConfigurationStatics5> {};
template<> struct hash<winrt::Windows::ApplicationModel::Store::Preview::IStoreHardwareManufacturerInfo> : winrt::impl::hash_base<winrt::Windows::ApplicationModel::Store::Preview::IStoreHardwareManufacturerInfo> {};
template<> struct hash<winrt::Windows::ApplicationModel::Store::Preview::IStorePreview> : winrt::impl::hash_base<winrt::Windows::ApplicationModel::Store::Preview::IStorePreview> {};
template<> struct hash<winrt::Windows::ApplicationModel::Store::Preview::IStorePreviewProductInfo> : winrt::impl::hash_base<winrt::Windows::ApplicationModel::Store::Preview::IStorePreviewProductInfo> {};
template<> struct hash<winrt::Windows::ApplicationModel::Store::Preview::IStorePreviewPurchaseResults> : winrt::impl::hash_base<winrt::Windows::ApplicationModel::Store::Preview::IStorePreviewPurchaseResults> {};
template<> struct hash<winrt::Windows::ApplicationModel::Store::Preview::IStorePreviewSkuInfo> : winrt::impl::hash_base<winrt::Windows::ApplicationModel::Store::Preview::IStorePreviewSkuInfo> {};
template<> struct hash<winrt::Windows::ApplicationModel::Store::Preview::IWebAuthenticationCoreManagerHelper> : winrt::impl::hash_base<winrt::Windows::ApplicationModel::Store::Preview::IWebAuthenticationCoreManagerHelper> {};
template<> struct hash<winrt::Windows::ApplicationModel::Store::Preview::DeliveryOptimizationSettings> : winrt::impl::hash_base<winrt::Windows::ApplicationModel::Store::Preview::DeliveryOptimizationSettings> {};
template<> struct hash<winrt::Windows::ApplicationModel::Store::Preview::StoreConfiguration> : winrt::impl::hash_base<winrt::Windows::ApplicationModel::Store::Preview::StoreConfiguration> {};
template<> struct hash<winrt::Windows::ApplicationModel::Store::Preview::StoreHardwareManufacturerInfo> : winrt::impl::hash_base<winrt::Windows::ApplicationModel::Store::Preview::StoreHardwareManufacturerInfo> {};
template<> struct hash<winrt::Windows::ApplicationModel::Store::Preview::StorePreview> : winrt::impl::hash_base<winrt::Windows::ApplicationModel::Store::Preview::StorePreview> {};
template<> struct hash<winrt::Windows::ApplicationModel::Store::Preview::StorePreviewProductInfo> : winrt::impl::hash_base<winrt::Windows::ApplicationModel::Store::Preview::StorePreviewProductInfo> {};
template<> struct hash<winrt::Windows::ApplicationModel::Store::Preview::StorePreviewPurchaseResults> : winrt::impl::hash_base<winrt::Windows::ApplicationModel::Store::Preview::StorePreviewPurchaseResults> {};
template<> struct hash<winrt::Windows::ApplicationModel::Store::Preview::StorePreviewSkuInfo> : winrt::impl::hash_base<winrt::Windows::ApplicationModel::Store::Preview::StorePreviewSkuInfo> {};
template<> struct hash<winrt::Windows::ApplicationModel::Store::Preview::WebAuthenticationCoreManagerHelper> : winrt::impl::hash_base<winrt::Windows::ApplicationModel::Store::Preview::WebAuthenticationCoreManagerHelper> {};

}
