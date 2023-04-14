// C++/WinRT v1.0.190111.3

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#pragma once

#include "winrt/base.h"

#include "winrt/Windows.Foundation.h"
#include "winrt/Windows.Foundation.Collections.h"
#include "winrt/impl/Windows.Foundation.2.h"
#include "winrt/impl/Windows.Storage.2.h"
#include "winrt/impl/Windows.ApplicationModel.Store.2.h"
#include "winrt/Windows.ApplicationModel.h"

namespace winrt::impl {

template <typename D> Windows::ApplicationModel::Store::LicenseInformation consume_Windows_ApplicationModel_Store_ICurrentApp<D>::LicenseInformation() const
{
    Windows::ApplicationModel::Store::LicenseInformation value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Store::ICurrentApp)->get_LicenseInformation(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::Uri consume_Windows_ApplicationModel_Store_ICurrentApp<D>::LinkUri() const
{
    Windows::Foundation::Uri value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Store::ICurrentApp)->get_LinkUri(put_abi(value)));
    return value;
}

template <typename D> winrt::guid consume_Windows_ApplicationModel_Store_ICurrentApp<D>::AppId() const
{
    winrt::guid value{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Store::ICurrentApp)->get_AppId(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::IAsyncOperation<hstring> consume_Windows_ApplicationModel_Store_ICurrentApp<D>::RequestAppPurchaseAsync(bool includeReceipt) const
{
    Windows::Foundation::IAsyncOperation<hstring> requestAppPurchaseOperation{ nullptr };
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Store::ICurrentApp)->RequestAppPurchaseAsync(includeReceipt, put_abi(requestAppPurchaseOperation)));
    return requestAppPurchaseOperation;
}

template <typename D> Windows::Foundation::IAsyncOperation<hstring> consume_Windows_ApplicationModel_Store_ICurrentApp<D>::RequestProductPurchaseAsync(param::hstring const& productId, bool includeReceipt) const
{
    Windows::Foundation::IAsyncOperation<hstring> requestProductPurchaseOperation{ nullptr };
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Store::ICurrentApp)->RequestProductPurchaseAsync(get_abi(productId), includeReceipt, put_abi(requestProductPurchaseOperation)));
    return requestProductPurchaseOperation;
}

template <typename D> Windows::Foundation::IAsyncOperation<Windows::ApplicationModel::Store::ListingInformation> consume_Windows_ApplicationModel_Store_ICurrentApp<D>::LoadListingInformationAsync() const
{
    Windows::Foundation::IAsyncOperation<Windows::ApplicationModel::Store::ListingInformation> loadListingOperation{ nullptr };
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Store::ICurrentApp)->LoadListingInformationAsync(put_abi(loadListingOperation)));
    return loadListingOperation;
}

template <typename D> Windows::Foundation::IAsyncOperation<hstring> consume_Windows_ApplicationModel_Store_ICurrentApp<D>::GetAppReceiptAsync() const
{
    Windows::Foundation::IAsyncOperation<hstring> appReceiptOperation{ nullptr };
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Store::ICurrentApp)->GetAppReceiptAsync(put_abi(appReceiptOperation)));
    return appReceiptOperation;
}

template <typename D> Windows::Foundation::IAsyncOperation<hstring> consume_Windows_ApplicationModel_Store_ICurrentApp<D>::GetProductReceiptAsync(param::hstring const& productId) const
{
    Windows::Foundation::IAsyncOperation<hstring> getProductReceiptOperation{ nullptr };
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Store::ICurrentApp)->GetProductReceiptAsync(get_abi(productId), put_abi(getProductReceiptOperation)));
    return getProductReceiptOperation;
}

template <typename D> Windows::Foundation::IAsyncOperation<hstring> consume_Windows_ApplicationModel_Store_ICurrentApp2Statics<D>::GetCustomerPurchaseIdAsync(param::hstring const& serviceTicket, param::hstring const& publisherUserId) const
{
    Windows::Foundation::IAsyncOperation<hstring> operation{ nullptr };
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Store::ICurrentApp2Statics)->GetCustomerPurchaseIdAsync(get_abi(serviceTicket), get_abi(publisherUserId), put_abi(operation)));
    return operation;
}

template <typename D> Windows::Foundation::IAsyncOperation<hstring> consume_Windows_ApplicationModel_Store_ICurrentApp2Statics<D>::GetCustomerCollectionsIdAsync(param::hstring const& serviceTicket, param::hstring const& publisherUserId) const
{
    Windows::Foundation::IAsyncOperation<hstring> operation{ nullptr };
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Store::ICurrentApp2Statics)->GetCustomerCollectionsIdAsync(get_abi(serviceTicket), get_abi(publisherUserId), put_abi(operation)));
    return operation;
}

template <typename D> Windows::ApplicationModel::Store::LicenseInformation consume_Windows_ApplicationModel_Store_ICurrentAppSimulator<D>::LicenseInformation() const
{
    Windows::ApplicationModel::Store::LicenseInformation value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Store::ICurrentAppSimulator)->get_LicenseInformation(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::Uri consume_Windows_ApplicationModel_Store_ICurrentAppSimulator<D>::LinkUri() const
{
    Windows::Foundation::Uri value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Store::ICurrentAppSimulator)->get_LinkUri(put_abi(value)));
    return value;
}

template <typename D> winrt::guid consume_Windows_ApplicationModel_Store_ICurrentAppSimulator<D>::AppId() const
{
    winrt::guid value{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Store::ICurrentAppSimulator)->get_AppId(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::IAsyncOperation<hstring> consume_Windows_ApplicationModel_Store_ICurrentAppSimulator<D>::RequestAppPurchaseAsync(bool includeReceipt) const
{
    Windows::Foundation::IAsyncOperation<hstring> requestAppPurchaseOperation{ nullptr };
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Store::ICurrentAppSimulator)->RequestAppPurchaseAsync(includeReceipt, put_abi(requestAppPurchaseOperation)));
    return requestAppPurchaseOperation;
}

template <typename D> Windows::Foundation::IAsyncOperation<hstring> consume_Windows_ApplicationModel_Store_ICurrentAppSimulator<D>::RequestProductPurchaseAsync(param::hstring const& productId, bool includeReceipt) const
{
    Windows::Foundation::IAsyncOperation<hstring> requestProductPurchaseOperation{ nullptr };
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Store::ICurrentAppSimulator)->RequestProductPurchaseAsync(get_abi(productId), includeReceipt, put_abi(requestProductPurchaseOperation)));
    return requestProductPurchaseOperation;
}

template <typename D> Windows::Foundation::IAsyncOperation<Windows::ApplicationModel::Store::ListingInformation> consume_Windows_ApplicationModel_Store_ICurrentAppSimulator<D>::LoadListingInformationAsync() const
{
    Windows::Foundation::IAsyncOperation<Windows::ApplicationModel::Store::ListingInformation> loadListingOperation{ nullptr };
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Store::ICurrentAppSimulator)->LoadListingInformationAsync(put_abi(loadListingOperation)));
    return loadListingOperation;
}

template <typename D> Windows::Foundation::IAsyncOperation<hstring> consume_Windows_ApplicationModel_Store_ICurrentAppSimulator<D>::GetAppReceiptAsync() const
{
    Windows::Foundation::IAsyncOperation<hstring> appReceiptOperation{ nullptr };
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Store::ICurrentAppSimulator)->GetAppReceiptAsync(put_abi(appReceiptOperation)));
    return appReceiptOperation;
}

template <typename D> Windows::Foundation::IAsyncOperation<hstring> consume_Windows_ApplicationModel_Store_ICurrentAppSimulator<D>::GetProductReceiptAsync(param::hstring const& productId) const
{
    Windows::Foundation::IAsyncOperation<hstring> getProductReceiptOperation{ nullptr };
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Store::ICurrentAppSimulator)->GetProductReceiptAsync(get_abi(productId), put_abi(getProductReceiptOperation)));
    return getProductReceiptOperation;
}

template <typename D> Windows::Foundation::IAsyncAction consume_Windows_ApplicationModel_Store_ICurrentAppSimulator<D>::ReloadSimulatorAsync(Windows::Storage::StorageFile const& simulatorSettingsFile) const
{
    Windows::Foundation::IAsyncAction reloadSimulatorOperation{ nullptr };
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Store::ICurrentAppSimulator)->ReloadSimulatorAsync(get_abi(simulatorSettingsFile), put_abi(reloadSimulatorOperation)));
    return reloadSimulatorOperation;
}

template <typename D> Windows::Foundation::IAsyncOperation<Windows::ApplicationModel::Store::ListingInformation> consume_Windows_ApplicationModel_Store_ICurrentAppSimulatorStaticsWithFiltering<D>::LoadListingInformationByProductIdsAsync(param::async_iterable<hstring> const& productIds) const
{
    Windows::Foundation::IAsyncOperation<Windows::ApplicationModel::Store::ListingInformation> loadListingOperation{ nullptr };
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Store::ICurrentAppSimulatorStaticsWithFiltering)->LoadListingInformationByProductIdsAsync(get_abi(productIds), put_abi(loadListingOperation)));
    return loadListingOperation;
}

template <typename D> Windows::Foundation::IAsyncOperation<Windows::ApplicationModel::Store::ListingInformation> consume_Windows_ApplicationModel_Store_ICurrentAppSimulatorStaticsWithFiltering<D>::LoadListingInformationByKeywordsAsync(param::async_iterable<hstring> const& keywords) const
{
    Windows::Foundation::IAsyncOperation<Windows::ApplicationModel::Store::ListingInformation> loadListingOperation{ nullptr };
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Store::ICurrentAppSimulatorStaticsWithFiltering)->LoadListingInformationByKeywordsAsync(get_abi(keywords), put_abi(loadListingOperation)));
    return loadListingOperation;
}

template <typename D> Windows::Foundation::IAsyncOperation<hstring> consume_Windows_ApplicationModel_Store_ICurrentAppSimulatorWithCampaignId<D>::GetAppPurchaseCampaignIdAsync() const
{
    Windows::Foundation::IAsyncOperation<hstring> operation{ nullptr };
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Store::ICurrentAppSimulatorWithCampaignId)->GetAppPurchaseCampaignIdAsync(put_abi(operation)));
    return operation;
}

template <typename D> Windows::Foundation::IAsyncOperation<Windows::ApplicationModel::Store::FulfillmentResult> consume_Windows_ApplicationModel_Store_ICurrentAppSimulatorWithConsumables<D>::ReportConsumableFulfillmentAsync(param::hstring const& productId, winrt::guid const& transactionId) const
{
    Windows::Foundation::IAsyncOperation<Windows::ApplicationModel::Store::FulfillmentResult> reportConsumableFulfillmentOperation{ nullptr };
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Store::ICurrentAppSimulatorWithConsumables)->ReportConsumableFulfillmentAsync(get_abi(productId), get_abi(transactionId), put_abi(reportConsumableFulfillmentOperation)));
    return reportConsumableFulfillmentOperation;
}

template <typename D> Windows::Foundation::IAsyncOperation<Windows::ApplicationModel::Store::PurchaseResults> consume_Windows_ApplicationModel_Store_ICurrentAppSimulatorWithConsumables<D>::RequestProductPurchaseAsync(param::hstring const& productId) const
{
    Windows::Foundation::IAsyncOperation<Windows::ApplicationModel::Store::PurchaseResults> requestProductPurchaseWithResultsOperation{ nullptr };
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Store::ICurrentAppSimulatorWithConsumables)->RequestProductPurchaseWithResultsAsync(get_abi(productId), put_abi(requestProductPurchaseWithResultsOperation)));
    return requestProductPurchaseWithResultsOperation;
}

template <typename D> Windows::Foundation::IAsyncOperation<Windows::ApplicationModel::Store::PurchaseResults> consume_Windows_ApplicationModel_Store_ICurrentAppSimulatorWithConsumables<D>::RequestProductPurchaseAsync(param::hstring const& productId, param::hstring const& offerId, Windows::ApplicationModel::Store::ProductPurchaseDisplayProperties const& displayProperties) const
{
    Windows::Foundation::IAsyncOperation<Windows::ApplicationModel::Store::PurchaseResults> requestProductPurchaseWithDisplayPropertiesOperation{ nullptr };
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Store::ICurrentAppSimulatorWithConsumables)->RequestProductPurchaseWithDisplayPropertiesAsync(get_abi(productId), get_abi(offerId), get_abi(displayProperties), put_abi(requestProductPurchaseWithDisplayPropertiesOperation)));
    return requestProductPurchaseWithDisplayPropertiesOperation;
}

template <typename D> Windows::Foundation::IAsyncOperation<Windows::Foundation::Collections::IVectorView<Windows::ApplicationModel::Store::UnfulfilledConsumable>> consume_Windows_ApplicationModel_Store_ICurrentAppSimulatorWithConsumables<D>::GetUnfulfilledConsumablesAsync() const
{
    Windows::Foundation::IAsyncOperation<Windows::Foundation::Collections::IVectorView<Windows::ApplicationModel::Store::UnfulfilledConsumable>> getUnfulfilledConsumablesOperation{ nullptr };
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Store::ICurrentAppSimulatorWithConsumables)->GetUnfulfilledConsumablesAsync(put_abi(getUnfulfilledConsumablesOperation)));
    return getUnfulfilledConsumablesOperation;
}

template <typename D> Windows::Foundation::IAsyncOperation<Windows::ApplicationModel::Store::ListingInformation> consume_Windows_ApplicationModel_Store_ICurrentAppStaticsWithFiltering<D>::LoadListingInformationByProductIdsAsync(param::async_iterable<hstring> const& productIds) const
{
    Windows::Foundation::IAsyncOperation<Windows::ApplicationModel::Store::ListingInformation> loadListingOperation{ nullptr };
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Store::ICurrentAppStaticsWithFiltering)->LoadListingInformationByProductIdsAsync(get_abi(productIds), put_abi(loadListingOperation)));
    return loadListingOperation;
}

template <typename D> Windows::Foundation::IAsyncOperation<Windows::ApplicationModel::Store::ListingInformation> consume_Windows_ApplicationModel_Store_ICurrentAppStaticsWithFiltering<D>::LoadListingInformationByKeywordsAsync(param::async_iterable<hstring> const& keywords) const
{
    Windows::Foundation::IAsyncOperation<Windows::ApplicationModel::Store::ListingInformation> loadListingOperation{ nullptr };
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Store::ICurrentAppStaticsWithFiltering)->LoadListingInformationByKeywordsAsync(get_abi(keywords), put_abi(loadListingOperation)));
    return loadListingOperation;
}

template <typename D> void consume_Windows_ApplicationModel_Store_ICurrentAppStaticsWithFiltering<D>::ReportProductFulfillment(param::hstring const& productId) const
{
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Store::ICurrentAppStaticsWithFiltering)->ReportProductFulfillment(get_abi(productId)));
}

template <typename D> Windows::Foundation::IAsyncOperation<hstring> consume_Windows_ApplicationModel_Store_ICurrentAppWithCampaignId<D>::GetAppPurchaseCampaignIdAsync() const
{
    Windows::Foundation::IAsyncOperation<hstring> operation{ nullptr };
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Store::ICurrentAppWithCampaignId)->GetAppPurchaseCampaignIdAsync(put_abi(operation)));
    return operation;
}

template <typename D> Windows::Foundation::IAsyncOperation<Windows::ApplicationModel::Store::FulfillmentResult> consume_Windows_ApplicationModel_Store_ICurrentAppWithConsumables<D>::ReportConsumableFulfillmentAsync(param::hstring const& productId, winrt::guid const& transactionId) const
{
    Windows::Foundation::IAsyncOperation<Windows::ApplicationModel::Store::FulfillmentResult> reportConsumableFulfillmentOperation{ nullptr };
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Store::ICurrentAppWithConsumables)->ReportConsumableFulfillmentAsync(get_abi(productId), get_abi(transactionId), put_abi(reportConsumableFulfillmentOperation)));
    return reportConsumableFulfillmentOperation;
}

template <typename D> Windows::Foundation::IAsyncOperation<Windows::ApplicationModel::Store::PurchaseResults> consume_Windows_ApplicationModel_Store_ICurrentAppWithConsumables<D>::RequestProductPurchaseAsync(param::hstring const& productId) const
{
    Windows::Foundation::IAsyncOperation<Windows::ApplicationModel::Store::PurchaseResults> requestProductPurchaseWithResultsOperation{ nullptr };
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Store::ICurrentAppWithConsumables)->RequestProductPurchaseWithResultsAsync(get_abi(productId), put_abi(requestProductPurchaseWithResultsOperation)));
    return requestProductPurchaseWithResultsOperation;
}

template <typename D> Windows::Foundation::IAsyncOperation<Windows::ApplicationModel::Store::PurchaseResults> consume_Windows_ApplicationModel_Store_ICurrentAppWithConsumables<D>::RequestProductPurchaseAsync(param::hstring const& productId, param::hstring const& offerId, Windows::ApplicationModel::Store::ProductPurchaseDisplayProperties const& displayProperties) const
{
    Windows::Foundation::IAsyncOperation<Windows::ApplicationModel::Store::PurchaseResults> requestProductPurchaseWithDisplayPropertiesOperation{ nullptr };
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Store::ICurrentAppWithConsumables)->RequestProductPurchaseWithDisplayPropertiesAsync(get_abi(productId), get_abi(offerId), get_abi(displayProperties), put_abi(requestProductPurchaseWithDisplayPropertiesOperation)));
    return requestProductPurchaseWithDisplayPropertiesOperation;
}

template <typename D> Windows::Foundation::IAsyncOperation<Windows::Foundation::Collections::IVectorView<Windows::ApplicationModel::Store::UnfulfilledConsumable>> consume_Windows_ApplicationModel_Store_ICurrentAppWithConsumables<D>::GetUnfulfilledConsumablesAsync() const
{
    Windows::Foundation::IAsyncOperation<Windows::Foundation::Collections::IVectorView<Windows::ApplicationModel::Store::UnfulfilledConsumable>> getUnfulfilledConsumablesOperation{ nullptr };
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Store::ICurrentAppWithConsumables)->GetUnfulfilledConsumablesAsync(put_abi(getUnfulfilledConsumablesOperation)));
    return getUnfulfilledConsumablesOperation;
}

template <typename D> Windows::Foundation::Collections::IMapView<hstring, Windows::ApplicationModel::Store::ProductLicense> consume_Windows_ApplicationModel_Store_ILicenseInformation<D>::ProductLicenses() const
{
    Windows::Foundation::Collections::IMapView<hstring, Windows::ApplicationModel::Store::ProductLicense> value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Store::ILicenseInformation)->get_ProductLicenses(put_abi(value)));
    return value;
}

template <typename D> bool consume_Windows_ApplicationModel_Store_ILicenseInformation<D>::IsActive() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Store::ILicenseInformation)->get_IsActive(&value));
    return value;
}

template <typename D> bool consume_Windows_ApplicationModel_Store_ILicenseInformation<D>::IsTrial() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Store::ILicenseInformation)->get_IsTrial(&value));
    return value;
}

template <typename D> Windows::Foundation::DateTime consume_Windows_ApplicationModel_Store_ILicenseInformation<D>::ExpirationDate() const
{
    Windows::Foundation::DateTime value{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Store::ILicenseInformation)->get_ExpirationDate(put_abi(value)));
    return value;
}

template <typename D> winrt::event_token consume_Windows_ApplicationModel_Store_ILicenseInformation<D>::LicenseChanged(Windows::ApplicationModel::Store::LicenseChangedEventHandler const& handler) const
{
    winrt::event_token cookie{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Store::ILicenseInformation)->add_LicenseChanged(get_abi(handler), put_abi(cookie)));
    return cookie;
}

template <typename D> typename consume_Windows_ApplicationModel_Store_ILicenseInformation<D>::LicenseChanged_revoker consume_Windows_ApplicationModel_Store_ILicenseInformation<D>::LicenseChanged(auto_revoke_t, Windows::ApplicationModel::Store::LicenseChangedEventHandler const& handler) const
{
    return impl::make_event_revoker<D, LicenseChanged_revoker>(this, LicenseChanged(handler));
}

template <typename D> void consume_Windows_ApplicationModel_Store_ILicenseInformation<D>::LicenseChanged(winrt::event_token const& cookie) const noexcept
{
    WINRT_VERIFY_(0, WINRT_SHIM(Windows::ApplicationModel::Store::ILicenseInformation)->remove_LicenseChanged(get_abi(cookie)));
}

template <typename D> hstring consume_Windows_ApplicationModel_Store_IListingInformation<D>::CurrentMarket() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Store::IListingInformation)->get_CurrentMarket(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_ApplicationModel_Store_IListingInformation<D>::Description() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Store::IListingInformation)->get_Description(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::Collections::IMapView<hstring, Windows::ApplicationModel::Store::ProductListing> consume_Windows_ApplicationModel_Store_IListingInformation<D>::ProductListings() const
{
    Windows::Foundation::Collections::IMapView<hstring, Windows::ApplicationModel::Store::ProductListing> value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Store::IListingInformation)->get_ProductListings(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_ApplicationModel_Store_IListingInformation<D>::FormattedPrice() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Store::IListingInformation)->get_FormattedPrice(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_ApplicationModel_Store_IListingInformation<D>::Name() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Store::IListingInformation)->get_Name(put_abi(value)));
    return value;
}

template <typename D> uint32_t consume_Windows_ApplicationModel_Store_IListingInformation<D>::AgeRating() const
{
    uint32_t value{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Store::IListingInformation)->get_AgeRating(&value));
    return value;
}

template <typename D> hstring consume_Windows_ApplicationModel_Store_IListingInformation2<D>::FormattedBasePrice() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Store::IListingInformation2)->get_FormattedBasePrice(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::DateTime consume_Windows_ApplicationModel_Store_IListingInformation2<D>::SaleEndDate() const
{
    Windows::Foundation::DateTime value{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Store::IListingInformation2)->get_SaleEndDate(put_abi(value)));
    return value;
}

template <typename D> bool consume_Windows_ApplicationModel_Store_IListingInformation2<D>::IsOnSale() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Store::IListingInformation2)->get_IsOnSale(&value));
    return value;
}

template <typename D> hstring consume_Windows_ApplicationModel_Store_IListingInformation2<D>::CurrencyCode() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Store::IListingInformation2)->get_CurrencyCode(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_ApplicationModel_Store_IProductLicense<D>::ProductId() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Store::IProductLicense)->get_ProductId(put_abi(value)));
    return value;
}

template <typename D> bool consume_Windows_ApplicationModel_Store_IProductLicense<D>::IsActive() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Store::IProductLicense)->get_IsActive(&value));
    return value;
}

template <typename D> Windows::Foundation::DateTime consume_Windows_ApplicationModel_Store_IProductLicense<D>::ExpirationDate() const
{
    Windows::Foundation::DateTime value{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Store::IProductLicense)->get_ExpirationDate(put_abi(value)));
    return value;
}

template <typename D> bool consume_Windows_ApplicationModel_Store_IProductLicenseWithFulfillment<D>::IsConsumable() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Store::IProductLicenseWithFulfillment)->get_IsConsumable(&value));
    return value;
}

template <typename D> hstring consume_Windows_ApplicationModel_Store_IProductListing<D>::ProductId() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Store::IProductListing)->get_ProductId(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_ApplicationModel_Store_IProductListing<D>::FormattedPrice() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Store::IProductListing)->get_FormattedPrice(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_ApplicationModel_Store_IProductListing<D>::Name() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Store::IProductListing)->get_Name(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_ApplicationModel_Store_IProductListing2<D>::FormattedBasePrice() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Store::IProductListing2)->get_FormattedBasePrice(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::DateTime consume_Windows_ApplicationModel_Store_IProductListing2<D>::SaleEndDate() const
{
    Windows::Foundation::DateTime value{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Store::IProductListing2)->get_SaleEndDate(put_abi(value)));
    return value;
}

template <typename D> bool consume_Windows_ApplicationModel_Store_IProductListing2<D>::IsOnSale() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Store::IProductListing2)->get_IsOnSale(&value));
    return value;
}

template <typename D> hstring consume_Windows_ApplicationModel_Store_IProductListing2<D>::CurrencyCode() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Store::IProductListing2)->get_CurrencyCode(put_abi(value)));
    return value;
}

template <typename D> Windows::ApplicationModel::Store::ProductType consume_Windows_ApplicationModel_Store_IProductListingWithConsumables<D>::ProductType() const
{
    Windows::ApplicationModel::Store::ProductType value{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Store::IProductListingWithConsumables)->get_ProductType(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_ApplicationModel_Store_IProductListingWithMetadata<D>::Description() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Store::IProductListingWithMetadata)->get_Description(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::Collections::IIterable<hstring> consume_Windows_ApplicationModel_Store_IProductListingWithMetadata<D>::Keywords() const
{
    Windows::Foundation::Collections::IIterable<hstring> value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Store::IProductListingWithMetadata)->get_Keywords(put_abi(value)));
    return value;
}

template <typename D> Windows::ApplicationModel::Store::ProductType consume_Windows_ApplicationModel_Store_IProductListingWithMetadata<D>::ProductType() const
{
    Windows::ApplicationModel::Store::ProductType value{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Store::IProductListingWithMetadata)->get_ProductType(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_ApplicationModel_Store_IProductListingWithMetadata<D>::Tag() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Store::IProductListingWithMetadata)->get_Tag(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::Uri consume_Windows_ApplicationModel_Store_IProductListingWithMetadata<D>::ImageUri() const
{
    Windows::Foundation::Uri value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Store::IProductListingWithMetadata)->get_ImageUri(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_ApplicationModel_Store_IProductPurchaseDisplayProperties<D>::Name() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Store::IProductPurchaseDisplayProperties)->get_Name(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_ApplicationModel_Store_IProductPurchaseDisplayProperties<D>::Name(param::hstring const& value) const
{
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Store::IProductPurchaseDisplayProperties)->put_Name(get_abi(value)));
}

template <typename D> hstring consume_Windows_ApplicationModel_Store_IProductPurchaseDisplayProperties<D>::Description() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Store::IProductPurchaseDisplayProperties)->get_Description(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_ApplicationModel_Store_IProductPurchaseDisplayProperties<D>::Description(param::hstring const& value) const
{
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Store::IProductPurchaseDisplayProperties)->put_Description(get_abi(value)));
}

template <typename D> Windows::Foundation::Uri consume_Windows_ApplicationModel_Store_IProductPurchaseDisplayProperties<D>::Image() const
{
    Windows::Foundation::Uri value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Store::IProductPurchaseDisplayProperties)->get_Image(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_ApplicationModel_Store_IProductPurchaseDisplayProperties<D>::Image(Windows::Foundation::Uri const& value) const
{
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Store::IProductPurchaseDisplayProperties)->put_Image(get_abi(value)));
}

template <typename D> Windows::ApplicationModel::Store::ProductPurchaseDisplayProperties consume_Windows_ApplicationModel_Store_IProductPurchaseDisplayPropertiesFactory<D>::CreateProductPurchaseDisplayProperties(param::hstring const& name) const
{
    Windows::ApplicationModel::Store::ProductPurchaseDisplayProperties displayProperties{ nullptr };
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Store::IProductPurchaseDisplayPropertiesFactory)->CreateProductPurchaseDisplayProperties(get_abi(name), put_abi(displayProperties)));
    return displayProperties;
}

template <typename D> Windows::ApplicationModel::Store::ProductPurchaseStatus consume_Windows_ApplicationModel_Store_IPurchaseResults<D>::Status() const
{
    Windows::ApplicationModel::Store::ProductPurchaseStatus value{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Store::IPurchaseResults)->get_Status(put_abi(value)));
    return value;
}

template <typename D> winrt::guid consume_Windows_ApplicationModel_Store_IPurchaseResults<D>::TransactionId() const
{
    winrt::guid value{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Store::IPurchaseResults)->get_TransactionId(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_ApplicationModel_Store_IPurchaseResults<D>::ReceiptXml() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Store::IPurchaseResults)->get_ReceiptXml(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_ApplicationModel_Store_IPurchaseResults<D>::OfferId() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Store::IPurchaseResults)->get_OfferId(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_ApplicationModel_Store_IUnfulfilledConsumable<D>::ProductId() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Store::IUnfulfilledConsumable)->get_ProductId(put_abi(value)));
    return value;
}

template <typename D> winrt::guid consume_Windows_ApplicationModel_Store_IUnfulfilledConsumable<D>::TransactionId() const
{
    winrt::guid value{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Store::IUnfulfilledConsumable)->get_TransactionId(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_ApplicationModel_Store_IUnfulfilledConsumable<D>::OfferId() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Store::IUnfulfilledConsumable)->get_OfferId(put_abi(value)));
    return value;
}

template <> struct delegate<Windows::ApplicationModel::Store::LicenseChangedEventHandler>
{
    template <typename H>
    struct type : implements_delegate<Windows::ApplicationModel::Store::LicenseChangedEventHandler, H>
    {
        type(H&& handler) : implements_delegate<Windows::ApplicationModel::Store::LicenseChangedEventHandler, H>(std::forward<H>(handler)) {}

        int32_t WINRT_CALL Invoke() noexcept final
        {
            try
            {
                (*this)();
                return 0;
            }
            catch (...)
            {
                return to_hresult();
            }
        }
    };
};

template <typename D>
struct produce<D, Windows::ApplicationModel::Store::ICurrentApp> : produce_base<D, Windows::ApplicationModel::Store::ICurrentApp>
{
    int32_t WINRT_CALL get_LicenseInformation(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(LicenseInformation, WINRT_WRAP(Windows::ApplicationModel::Store::LicenseInformation));
            *value = detach_from<Windows::ApplicationModel::Store::LicenseInformation>(this->shim().LicenseInformation());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_LinkUri(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(LinkUri, WINRT_WRAP(Windows::Foundation::Uri));
            *value = detach_from<Windows::Foundation::Uri>(this->shim().LinkUri());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_AppId(winrt::guid* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(AppId, WINRT_WRAP(winrt::guid));
            *value = detach_from<winrt::guid>(this->shim().AppId());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL RequestAppPurchaseAsync(bool includeReceipt, void** requestAppPurchaseOperation) noexcept final
    {
        try
        {
            *requestAppPurchaseOperation = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(RequestAppPurchaseAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<hstring>), bool);
            *requestAppPurchaseOperation = detach_from<Windows::Foundation::IAsyncOperation<hstring>>(this->shim().RequestAppPurchaseAsync(includeReceipt));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL RequestProductPurchaseAsync(void* productId, bool includeReceipt, void** requestProductPurchaseOperation) noexcept final
    {
        try
        {
            *requestProductPurchaseOperation = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(RequestProductPurchaseAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<hstring>), hstring const, bool);
            *requestProductPurchaseOperation = detach_from<Windows::Foundation::IAsyncOperation<hstring>>(this->shim().RequestProductPurchaseAsync(*reinterpret_cast<hstring const*>(&productId), includeReceipt));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL LoadListingInformationAsync(void** loadListingOperation) noexcept final
    {
        try
        {
            *loadListingOperation = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(LoadListingInformationAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<Windows::ApplicationModel::Store::ListingInformation>));
            *loadListingOperation = detach_from<Windows::Foundation::IAsyncOperation<Windows::ApplicationModel::Store::ListingInformation>>(this->shim().LoadListingInformationAsync());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL GetAppReceiptAsync(void** appReceiptOperation) noexcept final
    {
        try
        {
            *appReceiptOperation = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetAppReceiptAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<hstring>));
            *appReceiptOperation = detach_from<Windows::Foundation::IAsyncOperation<hstring>>(this->shim().GetAppReceiptAsync());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL GetProductReceiptAsync(void* productId, void** getProductReceiptOperation) noexcept final
    {
        try
        {
            *getProductReceiptOperation = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetProductReceiptAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<hstring>), hstring const);
            *getProductReceiptOperation = detach_from<Windows::Foundation::IAsyncOperation<hstring>>(this->shim().GetProductReceiptAsync(*reinterpret_cast<hstring const*>(&productId)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::ApplicationModel::Store::ICurrentApp2Statics> : produce_base<D, Windows::ApplicationModel::Store::ICurrentApp2Statics>
{
    int32_t WINRT_CALL GetCustomerPurchaseIdAsync(void* serviceTicket, void* publisherUserId, void** operation) noexcept final
    {
        try
        {
            *operation = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetCustomerPurchaseIdAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<hstring>), hstring const, hstring const);
            *operation = detach_from<Windows::Foundation::IAsyncOperation<hstring>>(this->shim().GetCustomerPurchaseIdAsync(*reinterpret_cast<hstring const*>(&serviceTicket), *reinterpret_cast<hstring const*>(&publisherUserId)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL GetCustomerCollectionsIdAsync(void* serviceTicket, void* publisherUserId, void** operation) noexcept final
    {
        try
        {
            *operation = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetCustomerCollectionsIdAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<hstring>), hstring const, hstring const);
            *operation = detach_from<Windows::Foundation::IAsyncOperation<hstring>>(this->shim().GetCustomerCollectionsIdAsync(*reinterpret_cast<hstring const*>(&serviceTicket), *reinterpret_cast<hstring const*>(&publisherUserId)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::ApplicationModel::Store::ICurrentAppSimulator> : produce_base<D, Windows::ApplicationModel::Store::ICurrentAppSimulator>
{
    int32_t WINRT_CALL get_LicenseInformation(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(LicenseInformation, WINRT_WRAP(Windows::ApplicationModel::Store::LicenseInformation));
            *value = detach_from<Windows::ApplicationModel::Store::LicenseInformation>(this->shim().LicenseInformation());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_LinkUri(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(LinkUri, WINRT_WRAP(Windows::Foundation::Uri));
            *value = detach_from<Windows::Foundation::Uri>(this->shim().LinkUri());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_AppId(winrt::guid* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(AppId, WINRT_WRAP(winrt::guid));
            *value = detach_from<winrt::guid>(this->shim().AppId());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL RequestAppPurchaseAsync(bool includeReceipt, void** requestAppPurchaseOperation) noexcept final
    {
        try
        {
            *requestAppPurchaseOperation = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(RequestAppPurchaseAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<hstring>), bool);
            *requestAppPurchaseOperation = detach_from<Windows::Foundation::IAsyncOperation<hstring>>(this->shim().RequestAppPurchaseAsync(includeReceipt));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL RequestProductPurchaseAsync(void* productId, bool includeReceipt, void** requestProductPurchaseOperation) noexcept final
    {
        try
        {
            *requestProductPurchaseOperation = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(RequestProductPurchaseAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<hstring>), hstring const, bool);
            *requestProductPurchaseOperation = detach_from<Windows::Foundation::IAsyncOperation<hstring>>(this->shim().RequestProductPurchaseAsync(*reinterpret_cast<hstring const*>(&productId), includeReceipt));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL LoadListingInformationAsync(void** loadListingOperation) noexcept final
    {
        try
        {
            *loadListingOperation = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(LoadListingInformationAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<Windows::ApplicationModel::Store::ListingInformation>));
            *loadListingOperation = detach_from<Windows::Foundation::IAsyncOperation<Windows::ApplicationModel::Store::ListingInformation>>(this->shim().LoadListingInformationAsync());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL GetAppReceiptAsync(void** appReceiptOperation) noexcept final
    {
        try
        {
            *appReceiptOperation = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetAppReceiptAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<hstring>));
            *appReceiptOperation = detach_from<Windows::Foundation::IAsyncOperation<hstring>>(this->shim().GetAppReceiptAsync());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL GetProductReceiptAsync(void* productId, void** getProductReceiptOperation) noexcept final
    {
        try
        {
            *getProductReceiptOperation = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetProductReceiptAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<hstring>), hstring const);
            *getProductReceiptOperation = detach_from<Windows::Foundation::IAsyncOperation<hstring>>(this->shim().GetProductReceiptAsync(*reinterpret_cast<hstring const*>(&productId)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL ReloadSimulatorAsync(void* simulatorSettingsFile, void** reloadSimulatorOperation) noexcept final
    {
        try
        {
            *reloadSimulatorOperation = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ReloadSimulatorAsync, WINRT_WRAP(Windows::Foundation::IAsyncAction), Windows::Storage::StorageFile const);
            *reloadSimulatorOperation = detach_from<Windows::Foundation::IAsyncAction>(this->shim().ReloadSimulatorAsync(*reinterpret_cast<Windows::Storage::StorageFile const*>(&simulatorSettingsFile)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::ApplicationModel::Store::ICurrentAppSimulatorStaticsWithFiltering> : produce_base<D, Windows::ApplicationModel::Store::ICurrentAppSimulatorStaticsWithFiltering>
{
    int32_t WINRT_CALL LoadListingInformationByProductIdsAsync(void* productIds, void** loadListingOperation) noexcept final
    {
        try
        {
            *loadListingOperation = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(LoadListingInformationByProductIdsAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<Windows::ApplicationModel::Store::ListingInformation>), Windows::Foundation::Collections::IIterable<hstring> const);
            *loadListingOperation = detach_from<Windows::Foundation::IAsyncOperation<Windows::ApplicationModel::Store::ListingInformation>>(this->shim().LoadListingInformationByProductIdsAsync(*reinterpret_cast<Windows::Foundation::Collections::IIterable<hstring> const*>(&productIds)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL LoadListingInformationByKeywordsAsync(void* keywords, void** loadListingOperation) noexcept final
    {
        try
        {
            *loadListingOperation = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(LoadListingInformationByKeywordsAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<Windows::ApplicationModel::Store::ListingInformation>), Windows::Foundation::Collections::IIterable<hstring> const);
            *loadListingOperation = detach_from<Windows::Foundation::IAsyncOperation<Windows::ApplicationModel::Store::ListingInformation>>(this->shim().LoadListingInformationByKeywordsAsync(*reinterpret_cast<Windows::Foundation::Collections::IIterable<hstring> const*>(&keywords)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::ApplicationModel::Store::ICurrentAppSimulatorWithCampaignId> : produce_base<D, Windows::ApplicationModel::Store::ICurrentAppSimulatorWithCampaignId>
{
    int32_t WINRT_CALL GetAppPurchaseCampaignIdAsync(void** operation) noexcept final
    {
        try
        {
            *operation = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetAppPurchaseCampaignIdAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<hstring>));
            *operation = detach_from<Windows::Foundation::IAsyncOperation<hstring>>(this->shim().GetAppPurchaseCampaignIdAsync());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::ApplicationModel::Store::ICurrentAppSimulatorWithConsumables> : produce_base<D, Windows::ApplicationModel::Store::ICurrentAppSimulatorWithConsumables>
{
    int32_t WINRT_CALL ReportConsumableFulfillmentAsync(void* productId, winrt::guid transactionId, void** reportConsumableFulfillmentOperation) noexcept final
    {
        try
        {
            *reportConsumableFulfillmentOperation = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ReportConsumableFulfillmentAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<Windows::ApplicationModel::Store::FulfillmentResult>), hstring const, winrt::guid const);
            *reportConsumableFulfillmentOperation = detach_from<Windows::Foundation::IAsyncOperation<Windows::ApplicationModel::Store::FulfillmentResult>>(this->shim().ReportConsumableFulfillmentAsync(*reinterpret_cast<hstring const*>(&productId), *reinterpret_cast<winrt::guid const*>(&transactionId)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL RequestProductPurchaseWithResultsAsync(void* productId, void** requestProductPurchaseWithResultsOperation) noexcept final
    {
        try
        {
            *requestProductPurchaseWithResultsOperation = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(RequestProductPurchaseAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<Windows::ApplicationModel::Store::PurchaseResults>), hstring const);
            *requestProductPurchaseWithResultsOperation = detach_from<Windows::Foundation::IAsyncOperation<Windows::ApplicationModel::Store::PurchaseResults>>(this->shim().RequestProductPurchaseAsync(*reinterpret_cast<hstring const*>(&productId)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL RequestProductPurchaseWithDisplayPropertiesAsync(void* productId, void* offerId, void* displayProperties, void** requestProductPurchaseWithDisplayPropertiesOperation) noexcept final
    {
        try
        {
            *requestProductPurchaseWithDisplayPropertiesOperation = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(RequestProductPurchaseAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<Windows::ApplicationModel::Store::PurchaseResults>), hstring const, hstring const, Windows::ApplicationModel::Store::ProductPurchaseDisplayProperties const);
            *requestProductPurchaseWithDisplayPropertiesOperation = detach_from<Windows::Foundation::IAsyncOperation<Windows::ApplicationModel::Store::PurchaseResults>>(this->shim().RequestProductPurchaseAsync(*reinterpret_cast<hstring const*>(&productId), *reinterpret_cast<hstring const*>(&offerId), *reinterpret_cast<Windows::ApplicationModel::Store::ProductPurchaseDisplayProperties const*>(&displayProperties)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL GetUnfulfilledConsumablesAsync(void** getUnfulfilledConsumablesOperation) noexcept final
    {
        try
        {
            *getUnfulfilledConsumablesOperation = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetUnfulfilledConsumablesAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<Windows::Foundation::Collections::IVectorView<Windows::ApplicationModel::Store::UnfulfilledConsumable>>));
            *getUnfulfilledConsumablesOperation = detach_from<Windows::Foundation::IAsyncOperation<Windows::Foundation::Collections::IVectorView<Windows::ApplicationModel::Store::UnfulfilledConsumable>>>(this->shim().GetUnfulfilledConsumablesAsync());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::ApplicationModel::Store::ICurrentAppStaticsWithFiltering> : produce_base<D, Windows::ApplicationModel::Store::ICurrentAppStaticsWithFiltering>
{
    int32_t WINRT_CALL LoadListingInformationByProductIdsAsync(void* productIds, void** loadListingOperation) noexcept final
    {
        try
        {
            *loadListingOperation = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(LoadListingInformationByProductIdsAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<Windows::ApplicationModel::Store::ListingInformation>), Windows::Foundation::Collections::IIterable<hstring> const);
            *loadListingOperation = detach_from<Windows::Foundation::IAsyncOperation<Windows::ApplicationModel::Store::ListingInformation>>(this->shim().LoadListingInformationByProductIdsAsync(*reinterpret_cast<Windows::Foundation::Collections::IIterable<hstring> const*>(&productIds)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL LoadListingInformationByKeywordsAsync(void* keywords, void** loadListingOperation) noexcept final
    {
        try
        {
            *loadListingOperation = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(LoadListingInformationByKeywordsAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<Windows::ApplicationModel::Store::ListingInformation>), Windows::Foundation::Collections::IIterable<hstring> const);
            *loadListingOperation = detach_from<Windows::Foundation::IAsyncOperation<Windows::ApplicationModel::Store::ListingInformation>>(this->shim().LoadListingInformationByKeywordsAsync(*reinterpret_cast<Windows::Foundation::Collections::IIterable<hstring> const*>(&keywords)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL ReportProductFulfillment(void* productId) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ReportProductFulfillment, WINRT_WRAP(void), hstring const&);
            this->shim().ReportProductFulfillment(*reinterpret_cast<hstring const*>(&productId));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::ApplicationModel::Store::ICurrentAppWithCampaignId> : produce_base<D, Windows::ApplicationModel::Store::ICurrentAppWithCampaignId>
{
    int32_t WINRT_CALL GetAppPurchaseCampaignIdAsync(void** operation) noexcept final
    {
        try
        {
            *operation = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetAppPurchaseCampaignIdAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<hstring>));
            *operation = detach_from<Windows::Foundation::IAsyncOperation<hstring>>(this->shim().GetAppPurchaseCampaignIdAsync());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::ApplicationModel::Store::ICurrentAppWithConsumables> : produce_base<D, Windows::ApplicationModel::Store::ICurrentAppWithConsumables>
{
    int32_t WINRT_CALL ReportConsumableFulfillmentAsync(void* productId, winrt::guid transactionId, void** reportConsumableFulfillmentOperation) noexcept final
    {
        try
        {
            *reportConsumableFulfillmentOperation = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ReportConsumableFulfillmentAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<Windows::ApplicationModel::Store::FulfillmentResult>), hstring const, winrt::guid const);
            *reportConsumableFulfillmentOperation = detach_from<Windows::Foundation::IAsyncOperation<Windows::ApplicationModel::Store::FulfillmentResult>>(this->shim().ReportConsumableFulfillmentAsync(*reinterpret_cast<hstring const*>(&productId), *reinterpret_cast<winrt::guid const*>(&transactionId)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL RequestProductPurchaseWithResultsAsync(void* productId, void** requestProductPurchaseWithResultsOperation) noexcept final
    {
        try
        {
            *requestProductPurchaseWithResultsOperation = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(RequestProductPurchaseAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<Windows::ApplicationModel::Store::PurchaseResults>), hstring const);
            *requestProductPurchaseWithResultsOperation = detach_from<Windows::Foundation::IAsyncOperation<Windows::ApplicationModel::Store::PurchaseResults>>(this->shim().RequestProductPurchaseAsync(*reinterpret_cast<hstring const*>(&productId)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL RequestProductPurchaseWithDisplayPropertiesAsync(void* productId, void* offerId, void* displayProperties, void** requestProductPurchaseWithDisplayPropertiesOperation) noexcept final
    {
        try
        {
            *requestProductPurchaseWithDisplayPropertiesOperation = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(RequestProductPurchaseAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<Windows::ApplicationModel::Store::PurchaseResults>), hstring const, hstring const, Windows::ApplicationModel::Store::ProductPurchaseDisplayProperties const);
            *requestProductPurchaseWithDisplayPropertiesOperation = detach_from<Windows::Foundation::IAsyncOperation<Windows::ApplicationModel::Store::PurchaseResults>>(this->shim().RequestProductPurchaseAsync(*reinterpret_cast<hstring const*>(&productId), *reinterpret_cast<hstring const*>(&offerId), *reinterpret_cast<Windows::ApplicationModel::Store::ProductPurchaseDisplayProperties const*>(&displayProperties)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL GetUnfulfilledConsumablesAsync(void** getUnfulfilledConsumablesOperation) noexcept final
    {
        try
        {
            *getUnfulfilledConsumablesOperation = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetUnfulfilledConsumablesAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<Windows::Foundation::Collections::IVectorView<Windows::ApplicationModel::Store::UnfulfilledConsumable>>));
            *getUnfulfilledConsumablesOperation = detach_from<Windows::Foundation::IAsyncOperation<Windows::Foundation::Collections::IVectorView<Windows::ApplicationModel::Store::UnfulfilledConsumable>>>(this->shim().GetUnfulfilledConsumablesAsync());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::ApplicationModel::Store::ILicenseInformation> : produce_base<D, Windows::ApplicationModel::Store::ILicenseInformation>
{
    int32_t WINRT_CALL get_ProductLicenses(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ProductLicenses, WINRT_WRAP(Windows::Foundation::Collections::IMapView<hstring, Windows::ApplicationModel::Store::ProductLicense>));
            *value = detach_from<Windows::Foundation::Collections::IMapView<hstring, Windows::ApplicationModel::Store::ProductLicense>>(this->shim().ProductLicenses());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_IsActive(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IsActive, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().IsActive());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_IsTrial(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IsTrial, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().IsTrial());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_ExpirationDate(Windows::Foundation::DateTime* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ExpirationDate, WINRT_WRAP(Windows::Foundation::DateTime));
            *value = detach_from<Windows::Foundation::DateTime>(this->shim().ExpirationDate());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL add_LicenseChanged(void* handler, winrt::event_token* cookie) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(LicenseChanged, WINRT_WRAP(winrt::event_token), Windows::ApplicationModel::Store::LicenseChangedEventHandler const&);
            *cookie = detach_from<winrt::event_token>(this->shim().LicenseChanged(*reinterpret_cast<Windows::ApplicationModel::Store::LicenseChangedEventHandler const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL remove_LicenseChanged(winrt::event_token cookie) noexcept final
    {
        typename D::abi_guard guard(this->shim());
        WINRT_ASSERT_DECLARATION(LicenseChanged, WINRT_WRAP(void), winrt::event_token const&);
        this->shim().LicenseChanged(*reinterpret_cast<winrt::event_token const*>(&cookie));
        return 0;
    }
};

template <typename D>
struct produce<D, Windows::ApplicationModel::Store::IListingInformation> : produce_base<D, Windows::ApplicationModel::Store::IListingInformation>
{
    int32_t WINRT_CALL get_CurrentMarket(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CurrentMarket, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().CurrentMarket());
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

    int32_t WINRT_CALL get_ProductListings(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ProductListings, WINRT_WRAP(Windows::Foundation::Collections::IMapView<hstring, Windows::ApplicationModel::Store::ProductListing>));
            *value = detach_from<Windows::Foundation::Collections::IMapView<hstring, Windows::ApplicationModel::Store::ProductListing>>(this->shim().ProductListings());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_FormattedPrice(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(FormattedPrice, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().FormattedPrice());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Name(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Name, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().Name());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_AgeRating(uint32_t* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(AgeRating, WINRT_WRAP(uint32_t));
            *value = detach_from<uint32_t>(this->shim().AgeRating());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::ApplicationModel::Store::IListingInformation2> : produce_base<D, Windows::ApplicationModel::Store::IListingInformation2>
{
    int32_t WINRT_CALL get_FormattedBasePrice(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(FormattedBasePrice, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().FormattedBasePrice());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_SaleEndDate(Windows::Foundation::DateTime* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SaleEndDate, WINRT_WRAP(Windows::Foundation::DateTime));
            *value = detach_from<Windows::Foundation::DateTime>(this->shim().SaleEndDate());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_IsOnSale(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IsOnSale, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().IsOnSale());
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
};

template <typename D>
struct produce<D, Windows::ApplicationModel::Store::IProductLicense> : produce_base<D, Windows::ApplicationModel::Store::IProductLicense>
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

    int32_t WINRT_CALL get_IsActive(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IsActive, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().IsActive());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_ExpirationDate(Windows::Foundation::DateTime* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ExpirationDate, WINRT_WRAP(Windows::Foundation::DateTime));
            *value = detach_from<Windows::Foundation::DateTime>(this->shim().ExpirationDate());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::ApplicationModel::Store::IProductLicenseWithFulfillment> : produce_base<D, Windows::ApplicationModel::Store::IProductLicenseWithFulfillment>
{
    int32_t WINRT_CALL get_IsConsumable(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IsConsumable, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().IsConsumable());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::ApplicationModel::Store::IProductListing> : produce_base<D, Windows::ApplicationModel::Store::IProductListing>
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

    int32_t WINRT_CALL get_FormattedPrice(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(FormattedPrice, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().FormattedPrice());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Name(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Name, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().Name());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::ApplicationModel::Store::IProductListing2> : produce_base<D, Windows::ApplicationModel::Store::IProductListing2>
{
    int32_t WINRT_CALL get_FormattedBasePrice(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(FormattedBasePrice, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().FormattedBasePrice());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_SaleEndDate(Windows::Foundation::DateTime* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SaleEndDate, WINRT_WRAP(Windows::Foundation::DateTime));
            *value = detach_from<Windows::Foundation::DateTime>(this->shim().SaleEndDate());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_IsOnSale(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IsOnSale, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().IsOnSale());
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
};

template <typename D>
struct produce<D, Windows::ApplicationModel::Store::IProductListingWithConsumables> : produce_base<D, Windows::ApplicationModel::Store::IProductListingWithConsumables>
{
    int32_t WINRT_CALL get_ProductType(Windows::ApplicationModel::Store::ProductType* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ProductType, WINRT_WRAP(Windows::ApplicationModel::Store::ProductType));
            *value = detach_from<Windows::ApplicationModel::Store::ProductType>(this->shim().ProductType());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::ApplicationModel::Store::IProductListingWithMetadata> : produce_base<D, Windows::ApplicationModel::Store::IProductListingWithMetadata>
{
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

    int32_t WINRT_CALL get_Keywords(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Keywords, WINRT_WRAP(Windows::Foundation::Collections::IIterable<hstring>));
            *value = detach_from<Windows::Foundation::Collections::IIterable<hstring>>(this->shim().Keywords());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_ProductType(Windows::ApplicationModel::Store::ProductType* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ProductType, WINRT_WRAP(Windows::ApplicationModel::Store::ProductType));
            *value = detach_from<Windows::ApplicationModel::Store::ProductType>(this->shim().ProductType());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Tag(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Tag, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().Tag());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_ImageUri(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ImageUri, WINRT_WRAP(Windows::Foundation::Uri));
            *value = detach_from<Windows::Foundation::Uri>(this->shim().ImageUri());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::ApplicationModel::Store::IProductPurchaseDisplayProperties> : produce_base<D, Windows::ApplicationModel::Store::IProductPurchaseDisplayProperties>
{
    int32_t WINRT_CALL get_Name(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Name, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().Name());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_Name(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Name, WINRT_WRAP(void), hstring const&);
            this->shim().Name(*reinterpret_cast<hstring const*>(&value));
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

    int32_t WINRT_CALL get_Image(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Image, WINRT_WRAP(Windows::Foundation::Uri));
            *value = detach_from<Windows::Foundation::Uri>(this->shim().Image());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_Image(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Image, WINRT_WRAP(void), Windows::Foundation::Uri const&);
            this->shim().Image(*reinterpret_cast<Windows::Foundation::Uri const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::ApplicationModel::Store::IProductPurchaseDisplayPropertiesFactory> : produce_base<D, Windows::ApplicationModel::Store::IProductPurchaseDisplayPropertiesFactory>
{
    int32_t WINRT_CALL CreateProductPurchaseDisplayProperties(void* name, void** displayProperties) noexcept final
    {
        try
        {
            *displayProperties = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CreateProductPurchaseDisplayProperties, WINRT_WRAP(Windows::ApplicationModel::Store::ProductPurchaseDisplayProperties), hstring const&);
            *displayProperties = detach_from<Windows::ApplicationModel::Store::ProductPurchaseDisplayProperties>(this->shim().CreateProductPurchaseDisplayProperties(*reinterpret_cast<hstring const*>(&name)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::ApplicationModel::Store::IPurchaseResults> : produce_base<D, Windows::ApplicationModel::Store::IPurchaseResults>
{
    int32_t WINRT_CALL get_Status(Windows::ApplicationModel::Store::ProductPurchaseStatus* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Status, WINRT_WRAP(Windows::ApplicationModel::Store::ProductPurchaseStatus));
            *value = detach_from<Windows::ApplicationModel::Store::ProductPurchaseStatus>(this->shim().Status());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_TransactionId(winrt::guid* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(TransactionId, WINRT_WRAP(winrt::guid));
            *value = detach_from<winrt::guid>(this->shim().TransactionId());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_ReceiptXml(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ReceiptXml, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().ReceiptXml());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_OfferId(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(OfferId, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().OfferId());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::ApplicationModel::Store::IUnfulfilledConsumable> : produce_base<D, Windows::ApplicationModel::Store::IUnfulfilledConsumable>
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

    int32_t WINRT_CALL get_TransactionId(winrt::guid* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(TransactionId, WINRT_WRAP(winrt::guid));
            *value = detach_from<winrt::guid>(this->shim().TransactionId());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_OfferId(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(OfferId, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().OfferId());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

}

WINRT_EXPORT namespace winrt::Windows::ApplicationModel::Store {

inline Windows::ApplicationModel::Store::LicenseInformation CurrentApp::LicenseInformation()
{
    return impl::call_factory<CurrentApp, Windows::ApplicationModel::Store::ICurrentApp>([&](auto&& f) { return f.LicenseInformation(); });
}

inline Windows::Foundation::Uri CurrentApp::LinkUri()
{
    return impl::call_factory<CurrentApp, Windows::ApplicationModel::Store::ICurrentApp>([&](auto&& f) { return f.LinkUri(); });
}

inline winrt::guid CurrentApp::AppId()
{
    return impl::call_factory<CurrentApp, Windows::ApplicationModel::Store::ICurrentApp>([&](auto&& f) { return f.AppId(); });
}

inline Windows::Foundation::IAsyncOperation<hstring> CurrentApp::RequestAppPurchaseAsync(bool includeReceipt)
{
    return impl::call_factory<CurrentApp, Windows::ApplicationModel::Store::ICurrentApp>([&](auto&& f) { return f.RequestAppPurchaseAsync(includeReceipt); });
}

inline Windows::Foundation::IAsyncOperation<hstring> CurrentApp::RequestProductPurchaseAsync(param::hstring const& productId, bool includeReceipt)
{
    return impl::call_factory<CurrentApp, Windows::ApplicationModel::Store::ICurrentApp>([&](auto&& f) { return f.RequestProductPurchaseAsync(productId, includeReceipt); });
}

inline Windows::Foundation::IAsyncOperation<Windows::ApplicationModel::Store::ListingInformation> CurrentApp::LoadListingInformationAsync()
{
    return impl::call_factory<CurrentApp, Windows::ApplicationModel::Store::ICurrentApp>([&](auto&& f) { return f.LoadListingInformationAsync(); });
}

inline Windows::Foundation::IAsyncOperation<hstring> CurrentApp::GetAppReceiptAsync()
{
    return impl::call_factory<CurrentApp, Windows::ApplicationModel::Store::ICurrentApp>([&](auto&& f) { return f.GetAppReceiptAsync(); });
}

inline Windows::Foundation::IAsyncOperation<hstring> CurrentApp::GetProductReceiptAsync(param::hstring const& productId)
{
    return impl::call_factory<CurrentApp, Windows::ApplicationModel::Store::ICurrentApp>([&](auto&& f) { return f.GetProductReceiptAsync(productId); });
}

inline Windows::Foundation::IAsyncOperation<hstring> CurrentApp::GetCustomerPurchaseIdAsync(param::hstring const& serviceTicket, param::hstring const& publisherUserId)
{
    return impl::call_factory<CurrentApp, Windows::ApplicationModel::Store::ICurrentApp2Statics>([&](auto&& f) { return f.GetCustomerPurchaseIdAsync(serviceTicket, publisherUserId); });
}

inline Windows::Foundation::IAsyncOperation<hstring> CurrentApp::GetCustomerCollectionsIdAsync(param::hstring const& serviceTicket, param::hstring const& publisherUserId)
{
    return impl::call_factory<CurrentApp, Windows::ApplicationModel::Store::ICurrentApp2Statics>([&](auto&& f) { return f.GetCustomerCollectionsIdAsync(serviceTicket, publisherUserId); });
}

inline Windows::Foundation::IAsyncOperation<Windows::ApplicationModel::Store::ListingInformation> CurrentApp::LoadListingInformationByProductIdsAsync(param::async_iterable<hstring> const& productIds)
{
    return impl::call_factory<CurrentApp, Windows::ApplicationModel::Store::ICurrentAppStaticsWithFiltering>([&](auto&& f) { return f.LoadListingInformationByProductIdsAsync(productIds); });
}

inline Windows::Foundation::IAsyncOperation<Windows::ApplicationModel::Store::ListingInformation> CurrentApp::LoadListingInformationByKeywordsAsync(param::async_iterable<hstring> const& keywords)
{
    return impl::call_factory<CurrentApp, Windows::ApplicationModel::Store::ICurrentAppStaticsWithFiltering>([&](auto&& f) { return f.LoadListingInformationByKeywordsAsync(keywords); });
}

inline void CurrentApp::ReportProductFulfillment(param::hstring const& productId)
{
    impl::call_factory<CurrentApp, Windows::ApplicationModel::Store::ICurrentAppStaticsWithFiltering>([&](auto&& f) { return f.ReportProductFulfillment(productId); });
}

inline Windows::Foundation::IAsyncOperation<hstring> CurrentApp::GetAppPurchaseCampaignIdAsync()
{
    return impl::call_factory<CurrentApp, Windows::ApplicationModel::Store::ICurrentAppWithCampaignId>([&](auto&& f) { return f.GetAppPurchaseCampaignIdAsync(); });
}

inline Windows::Foundation::IAsyncOperation<Windows::ApplicationModel::Store::FulfillmentResult> CurrentApp::ReportConsumableFulfillmentAsync(param::hstring const& productId, winrt::guid const& transactionId)
{
    return impl::call_factory<CurrentApp, Windows::ApplicationModel::Store::ICurrentAppWithConsumables>([&](auto&& f) { return f.ReportConsumableFulfillmentAsync(productId, transactionId); });
}

inline Windows::Foundation::IAsyncOperation<Windows::ApplicationModel::Store::PurchaseResults> CurrentApp::RequestProductPurchaseAsync(param::hstring const& productId)
{
    return impl::call_factory<CurrentApp, Windows::ApplicationModel::Store::ICurrentAppWithConsumables>([&](auto&& f) { return f.RequestProductPurchaseAsync(productId); });
}

inline Windows::Foundation::IAsyncOperation<Windows::ApplicationModel::Store::PurchaseResults> CurrentApp::RequestProductPurchaseAsync(param::hstring const& productId, param::hstring const& offerId, Windows::ApplicationModel::Store::ProductPurchaseDisplayProperties const& displayProperties)
{
    return impl::call_factory<CurrentApp, Windows::ApplicationModel::Store::ICurrentAppWithConsumables>([&](auto&& f) { return f.RequestProductPurchaseAsync(productId, offerId, displayProperties); });
}

inline Windows::Foundation::IAsyncOperation<Windows::Foundation::Collections::IVectorView<Windows::ApplicationModel::Store::UnfulfilledConsumable>> CurrentApp::GetUnfulfilledConsumablesAsync()
{
    return impl::call_factory<CurrentApp, Windows::ApplicationModel::Store::ICurrentAppWithConsumables>([&](auto&& f) { return f.GetUnfulfilledConsumablesAsync(); });
}

inline Windows::ApplicationModel::Store::LicenseInformation CurrentAppSimulator::LicenseInformation()
{
    return impl::call_factory<CurrentAppSimulator, Windows::ApplicationModel::Store::ICurrentAppSimulator>([&](auto&& f) { return f.LicenseInformation(); });
}

inline Windows::Foundation::Uri CurrentAppSimulator::LinkUri()
{
    return impl::call_factory<CurrentAppSimulator, Windows::ApplicationModel::Store::ICurrentAppSimulator>([&](auto&& f) { return f.LinkUri(); });
}

inline winrt::guid CurrentAppSimulator::AppId()
{
    return impl::call_factory<CurrentAppSimulator, Windows::ApplicationModel::Store::ICurrentAppSimulator>([&](auto&& f) { return f.AppId(); });
}

inline Windows::Foundation::IAsyncOperation<hstring> CurrentAppSimulator::RequestAppPurchaseAsync(bool includeReceipt)
{
    return impl::call_factory<CurrentAppSimulator, Windows::ApplicationModel::Store::ICurrentAppSimulator>([&](auto&& f) { return f.RequestAppPurchaseAsync(includeReceipt); });
}

inline Windows::Foundation::IAsyncOperation<hstring> CurrentAppSimulator::RequestProductPurchaseAsync(param::hstring const& productId, bool includeReceipt)
{
    return impl::call_factory<CurrentAppSimulator, Windows::ApplicationModel::Store::ICurrentAppSimulator>([&](auto&& f) { return f.RequestProductPurchaseAsync(productId, includeReceipt); });
}

inline Windows::Foundation::IAsyncOperation<Windows::ApplicationModel::Store::ListingInformation> CurrentAppSimulator::LoadListingInformationAsync()
{
    return impl::call_factory<CurrentAppSimulator, Windows::ApplicationModel::Store::ICurrentAppSimulator>([&](auto&& f) { return f.LoadListingInformationAsync(); });
}

inline Windows::Foundation::IAsyncOperation<hstring> CurrentAppSimulator::GetAppReceiptAsync()
{
    return impl::call_factory<CurrentAppSimulator, Windows::ApplicationModel::Store::ICurrentAppSimulator>([&](auto&& f) { return f.GetAppReceiptAsync(); });
}

inline Windows::Foundation::IAsyncOperation<hstring> CurrentAppSimulator::GetProductReceiptAsync(param::hstring const& productId)
{
    return impl::call_factory<CurrentAppSimulator, Windows::ApplicationModel::Store::ICurrentAppSimulator>([&](auto&& f) { return f.GetProductReceiptAsync(productId); });
}

inline Windows::Foundation::IAsyncAction CurrentAppSimulator::ReloadSimulatorAsync(Windows::Storage::StorageFile const& simulatorSettingsFile)
{
    return impl::call_factory<CurrentAppSimulator, Windows::ApplicationModel::Store::ICurrentAppSimulator>([&](auto&& f) { return f.ReloadSimulatorAsync(simulatorSettingsFile); });
}

inline Windows::Foundation::IAsyncOperation<Windows::ApplicationModel::Store::ListingInformation> CurrentAppSimulator::LoadListingInformationByProductIdsAsync(param::async_iterable<hstring> const& productIds)
{
    return impl::call_factory<CurrentAppSimulator, Windows::ApplicationModel::Store::ICurrentAppSimulatorStaticsWithFiltering>([&](auto&& f) { return f.LoadListingInformationByProductIdsAsync(productIds); });
}

inline Windows::Foundation::IAsyncOperation<Windows::ApplicationModel::Store::ListingInformation> CurrentAppSimulator::LoadListingInformationByKeywordsAsync(param::async_iterable<hstring> const& keywords)
{
    return impl::call_factory<CurrentAppSimulator, Windows::ApplicationModel::Store::ICurrentAppSimulatorStaticsWithFiltering>([&](auto&& f) { return f.LoadListingInformationByKeywordsAsync(keywords); });
}

inline Windows::Foundation::IAsyncOperation<hstring> CurrentAppSimulator::GetAppPurchaseCampaignIdAsync()
{
    return impl::call_factory<CurrentAppSimulator, Windows::ApplicationModel::Store::ICurrentAppSimulatorWithCampaignId>([&](auto&& f) { return f.GetAppPurchaseCampaignIdAsync(); });
}

inline Windows::Foundation::IAsyncOperation<Windows::ApplicationModel::Store::FulfillmentResult> CurrentAppSimulator::ReportConsumableFulfillmentAsync(param::hstring const& productId, winrt::guid const& transactionId)
{
    return impl::call_factory<CurrentAppSimulator, Windows::ApplicationModel::Store::ICurrentAppSimulatorWithConsumables>([&](auto&& f) { return f.ReportConsumableFulfillmentAsync(productId, transactionId); });
}

inline Windows::Foundation::IAsyncOperation<Windows::ApplicationModel::Store::PurchaseResults> CurrentAppSimulator::RequestProductPurchaseAsync(param::hstring const& productId)
{
    return impl::call_factory<CurrentAppSimulator, Windows::ApplicationModel::Store::ICurrentAppSimulatorWithConsumables>([&](auto&& f) { return f.RequestProductPurchaseAsync(productId); });
}

inline Windows::Foundation::IAsyncOperation<Windows::ApplicationModel::Store::PurchaseResults> CurrentAppSimulator::RequestProductPurchaseAsync(param::hstring const& productId, param::hstring const& offerId, Windows::ApplicationModel::Store::ProductPurchaseDisplayProperties const& displayProperties)
{
    return impl::call_factory<CurrentAppSimulator, Windows::ApplicationModel::Store::ICurrentAppSimulatorWithConsumables>([&](auto&& f) { return f.RequestProductPurchaseAsync(productId, offerId, displayProperties); });
}

inline Windows::Foundation::IAsyncOperation<Windows::Foundation::Collections::IVectorView<Windows::ApplicationModel::Store::UnfulfilledConsumable>> CurrentAppSimulator::GetUnfulfilledConsumablesAsync()
{
    return impl::call_factory<CurrentAppSimulator, Windows::ApplicationModel::Store::ICurrentAppSimulatorWithConsumables>([&](auto&& f) { return f.GetUnfulfilledConsumablesAsync(); });
}

inline ProductPurchaseDisplayProperties::ProductPurchaseDisplayProperties() :
    ProductPurchaseDisplayProperties(impl::call_factory<ProductPurchaseDisplayProperties>([](auto&& f) { return f.template ActivateInstance<ProductPurchaseDisplayProperties>(); }))
{}

inline ProductPurchaseDisplayProperties::ProductPurchaseDisplayProperties(param::hstring const& name) :
    ProductPurchaseDisplayProperties(impl::call_factory<ProductPurchaseDisplayProperties, Windows::ApplicationModel::Store::IProductPurchaseDisplayPropertiesFactory>([&](auto&& f) { return f.CreateProductPurchaseDisplayProperties(name); }))
{}

template <typename L> LicenseChangedEventHandler::LicenseChangedEventHandler(L handler) :
    LicenseChangedEventHandler(impl::make_delegate<LicenseChangedEventHandler>(std::forward<L>(handler)))
{}

template <typename F> LicenseChangedEventHandler::LicenseChangedEventHandler(F* handler) :
    LicenseChangedEventHandler([=](auto&&... args) { return handler(args...); })
{}

template <typename O, typename M> LicenseChangedEventHandler::LicenseChangedEventHandler(O* object, M method) :
    LicenseChangedEventHandler([=](auto&&... args) { return ((*object).*(method))(args...); })
{}

template <typename O, typename M> LicenseChangedEventHandler::LicenseChangedEventHandler(com_ptr<O>&& object, M method) :
    LicenseChangedEventHandler([o = std::move(object), method](auto&&... args) { return ((*o).*(method))(args...); })
{}

template <typename O, typename M> LicenseChangedEventHandler::LicenseChangedEventHandler(weak_ref<O>&& object, M method) :
    LicenseChangedEventHandler([o = std::move(object), method](auto&&... args) { if (auto s = o.get()) { ((*s).*(method))(args...); } })
{}

inline void LicenseChangedEventHandler::operator()() const
{
    check_hresult((*(impl::abi_t<LicenseChangedEventHandler>**)this)->Invoke());
}

}

WINRT_EXPORT namespace std {

template<> struct hash<winrt::Windows::ApplicationModel::Store::ICurrentApp> : winrt::impl::hash_base<winrt::Windows::ApplicationModel::Store::ICurrentApp> {};
template<> struct hash<winrt::Windows::ApplicationModel::Store::ICurrentApp2Statics> : winrt::impl::hash_base<winrt::Windows::ApplicationModel::Store::ICurrentApp2Statics> {};
template<> struct hash<winrt::Windows::ApplicationModel::Store::ICurrentAppSimulator> : winrt::impl::hash_base<winrt::Windows::ApplicationModel::Store::ICurrentAppSimulator> {};
template<> struct hash<winrt::Windows::ApplicationModel::Store::ICurrentAppSimulatorStaticsWithFiltering> : winrt::impl::hash_base<winrt::Windows::ApplicationModel::Store::ICurrentAppSimulatorStaticsWithFiltering> {};
template<> struct hash<winrt::Windows::ApplicationModel::Store::ICurrentAppSimulatorWithCampaignId> : winrt::impl::hash_base<winrt::Windows::ApplicationModel::Store::ICurrentAppSimulatorWithCampaignId> {};
template<> struct hash<winrt::Windows::ApplicationModel::Store::ICurrentAppSimulatorWithConsumables> : winrt::impl::hash_base<winrt::Windows::ApplicationModel::Store::ICurrentAppSimulatorWithConsumables> {};
template<> struct hash<winrt::Windows::ApplicationModel::Store::ICurrentAppStaticsWithFiltering> : winrt::impl::hash_base<winrt::Windows::ApplicationModel::Store::ICurrentAppStaticsWithFiltering> {};
template<> struct hash<winrt::Windows::ApplicationModel::Store::ICurrentAppWithCampaignId> : winrt::impl::hash_base<winrt::Windows::ApplicationModel::Store::ICurrentAppWithCampaignId> {};
template<> struct hash<winrt::Windows::ApplicationModel::Store::ICurrentAppWithConsumables> : winrt::impl::hash_base<winrt::Windows::ApplicationModel::Store::ICurrentAppWithConsumables> {};
template<> struct hash<winrt::Windows::ApplicationModel::Store::ILicenseInformation> : winrt::impl::hash_base<winrt::Windows::ApplicationModel::Store::ILicenseInformation> {};
template<> struct hash<winrt::Windows::ApplicationModel::Store::IListingInformation> : winrt::impl::hash_base<winrt::Windows::ApplicationModel::Store::IListingInformation> {};
template<> struct hash<winrt::Windows::ApplicationModel::Store::IListingInformation2> : winrt::impl::hash_base<winrt::Windows::ApplicationModel::Store::IListingInformation2> {};
template<> struct hash<winrt::Windows::ApplicationModel::Store::IProductLicense> : winrt::impl::hash_base<winrt::Windows::ApplicationModel::Store::IProductLicense> {};
template<> struct hash<winrt::Windows::ApplicationModel::Store::IProductLicenseWithFulfillment> : winrt::impl::hash_base<winrt::Windows::ApplicationModel::Store::IProductLicenseWithFulfillment> {};
template<> struct hash<winrt::Windows::ApplicationModel::Store::IProductListing> : winrt::impl::hash_base<winrt::Windows::ApplicationModel::Store::IProductListing> {};
template<> struct hash<winrt::Windows::ApplicationModel::Store::IProductListing2> : winrt::impl::hash_base<winrt::Windows::ApplicationModel::Store::IProductListing2> {};
template<> struct hash<winrt::Windows::ApplicationModel::Store::IProductListingWithConsumables> : winrt::impl::hash_base<winrt::Windows::ApplicationModel::Store::IProductListingWithConsumables> {};
template<> struct hash<winrt::Windows::ApplicationModel::Store::IProductListingWithMetadata> : winrt::impl::hash_base<winrt::Windows::ApplicationModel::Store::IProductListingWithMetadata> {};
template<> struct hash<winrt::Windows::ApplicationModel::Store::IProductPurchaseDisplayProperties> : winrt::impl::hash_base<winrt::Windows::ApplicationModel::Store::IProductPurchaseDisplayProperties> {};
template<> struct hash<winrt::Windows::ApplicationModel::Store::IProductPurchaseDisplayPropertiesFactory> : winrt::impl::hash_base<winrt::Windows::ApplicationModel::Store::IProductPurchaseDisplayPropertiesFactory> {};
template<> struct hash<winrt::Windows::ApplicationModel::Store::IPurchaseResults> : winrt::impl::hash_base<winrt::Windows::ApplicationModel::Store::IPurchaseResults> {};
template<> struct hash<winrt::Windows::ApplicationModel::Store::IUnfulfilledConsumable> : winrt::impl::hash_base<winrt::Windows::ApplicationModel::Store::IUnfulfilledConsumable> {};
template<> struct hash<winrt::Windows::ApplicationModel::Store::CurrentApp> : winrt::impl::hash_base<winrt::Windows::ApplicationModel::Store::CurrentApp> {};
template<> struct hash<winrt::Windows::ApplicationModel::Store::CurrentAppSimulator> : winrt::impl::hash_base<winrt::Windows::ApplicationModel::Store::CurrentAppSimulator> {};
template<> struct hash<winrt::Windows::ApplicationModel::Store::LicenseInformation> : winrt::impl::hash_base<winrt::Windows::ApplicationModel::Store::LicenseInformation> {};
template<> struct hash<winrt::Windows::ApplicationModel::Store::ListingInformation> : winrt::impl::hash_base<winrt::Windows::ApplicationModel::Store::ListingInformation> {};
template<> struct hash<winrt::Windows::ApplicationModel::Store::ProductLicense> : winrt::impl::hash_base<winrt::Windows::ApplicationModel::Store::ProductLicense> {};
template<> struct hash<winrt::Windows::ApplicationModel::Store::ProductListing> : winrt::impl::hash_base<winrt::Windows::ApplicationModel::Store::ProductListing> {};
template<> struct hash<winrt::Windows::ApplicationModel::Store::ProductPurchaseDisplayProperties> : winrt::impl::hash_base<winrt::Windows::ApplicationModel::Store::ProductPurchaseDisplayProperties> {};
template<> struct hash<winrt::Windows::ApplicationModel::Store::PurchaseResults> : winrt::impl::hash_base<winrt::Windows::ApplicationModel::Store::PurchaseResults> {};
template<> struct hash<winrt::Windows::ApplicationModel::Store::UnfulfilledConsumable> : winrt::impl::hash_base<winrt::Windows::ApplicationModel::Store::UnfulfilledConsumable> {};

}
