// C++/WinRT v1.0.190111.3

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#pragma once

#include "winrt/base.h"

#include "winrt/Windows.Foundation.h"
#include "winrt/Windows.Foundation.Collections.h"
#include "winrt/impl/Windows.Devices.Geolocation.2.h"
#include "winrt/impl/Windows.Storage.Streams.2.h"
#include "winrt/impl/Windows.UI.2.h"
#include "winrt/impl/Windows.ApplicationModel.Wallet.2.h"
#include "winrt/Windows.ApplicationModel.h"

namespace winrt::impl {

template <typename D> Windows::ApplicationModel::Wallet::WalletBarcodeSymbology consume_Windows_ApplicationModel_Wallet_IWalletBarcode<D>::Symbology() const
{
    Windows::ApplicationModel::Wallet::WalletBarcodeSymbology value{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Wallet::IWalletBarcode)->get_Symbology(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_ApplicationModel_Wallet_IWalletBarcode<D>::Value() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Wallet::IWalletBarcode)->get_Value(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::IAsyncOperation<Windows::Storage::Streams::IRandomAccessStreamReference> consume_Windows_ApplicationModel_Wallet_IWalletBarcode<D>::GetImageAsync() const
{
    Windows::Foundation::IAsyncOperation<Windows::Storage::Streams::IRandomAccessStreamReference> operation{ nullptr };
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Wallet::IWalletBarcode)->GetImageAsync(put_abi(operation)));
    return operation;
}

template <typename D> Windows::ApplicationModel::Wallet::WalletBarcode consume_Windows_ApplicationModel_Wallet_IWalletBarcodeFactory<D>::CreateWalletBarcode(Windows::ApplicationModel::Wallet::WalletBarcodeSymbology const& symbology, param::hstring const& value) const
{
    Windows::ApplicationModel::Wallet::WalletBarcode barcode{ nullptr };
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Wallet::IWalletBarcodeFactory)->CreateWalletBarcode(get_abi(symbology), get_abi(value), put_abi(barcode)));
    return barcode;
}

template <typename D> Windows::ApplicationModel::Wallet::WalletBarcode consume_Windows_ApplicationModel_Wallet_IWalletBarcodeFactory<D>::CreateCustomWalletBarcode(Windows::Storage::Streams::IRandomAccessStreamReference const& streamToBarcodeImage) const
{
    Windows::ApplicationModel::Wallet::WalletBarcode barcode{ nullptr };
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Wallet::IWalletBarcodeFactory)->CreateCustomWalletBarcode(get_abi(streamToBarcodeImage), put_abi(barcode)));
    return barcode;
}

template <typename D> hstring consume_Windows_ApplicationModel_Wallet_IWalletItem<D>::DisplayName() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Wallet::IWalletItem)->get_DisplayName(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_ApplicationModel_Wallet_IWalletItem<D>::DisplayName(param::hstring const& value) const
{
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Wallet::IWalletItem)->put_DisplayName(get_abi(value)));
}

template <typename D> hstring consume_Windows_ApplicationModel_Wallet_IWalletItem<D>::Id() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Wallet::IWalletItem)->get_Id(put_abi(value)));
    return value;
}

template <typename D> bool consume_Windows_ApplicationModel_Wallet_IWalletItem<D>::IsAcknowledged() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Wallet::IWalletItem)->get_IsAcknowledged(&value));
    return value;
}

template <typename D> void consume_Windows_ApplicationModel_Wallet_IWalletItem<D>::IsAcknowledged(bool value) const
{
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Wallet::IWalletItem)->put_IsAcknowledged(value));
}

template <typename D> hstring consume_Windows_ApplicationModel_Wallet_IWalletItem<D>::IssuerDisplayName() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Wallet::IWalletItem)->get_IssuerDisplayName(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_ApplicationModel_Wallet_IWalletItem<D>::IssuerDisplayName(param::hstring const& value) const
{
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Wallet::IWalletItem)->put_IssuerDisplayName(get_abi(value)));
}

template <typename D> Windows::Foundation::IReference<Windows::Foundation::DateTime> consume_Windows_ApplicationModel_Wallet_IWalletItem<D>::LastUpdated() const
{
    Windows::Foundation::IReference<Windows::Foundation::DateTime> value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Wallet::IWalletItem)->get_LastUpdated(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_ApplicationModel_Wallet_IWalletItem<D>::LastUpdated(optional<Windows::Foundation::DateTime> const& value) const
{
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Wallet::IWalletItem)->put_LastUpdated(get_abi(value)));
}

template <typename D> Windows::ApplicationModel::Wallet::WalletItemKind consume_Windows_ApplicationModel_Wallet_IWalletItem<D>::Kind() const
{
    Windows::ApplicationModel::Wallet::WalletItemKind value{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Wallet::IWalletItem)->get_Kind(put_abi(value)));
    return value;
}

template <typename D> Windows::ApplicationModel::Wallet::WalletBarcode consume_Windows_ApplicationModel_Wallet_IWalletItem<D>::Barcode() const
{
    Windows::ApplicationModel::Wallet::WalletBarcode value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Wallet::IWalletItem)->get_Barcode(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_ApplicationModel_Wallet_IWalletItem<D>::Barcode(Windows::ApplicationModel::Wallet::WalletBarcode const& value) const
{
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Wallet::IWalletItem)->put_Barcode(get_abi(value)));
}

template <typename D> Windows::Foundation::IReference<Windows::Foundation::DateTime> consume_Windows_ApplicationModel_Wallet_IWalletItem<D>::ExpirationDate() const
{
    Windows::Foundation::IReference<Windows::Foundation::DateTime> value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Wallet::IWalletItem)->get_ExpirationDate(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_ApplicationModel_Wallet_IWalletItem<D>::ExpirationDate(optional<Windows::Foundation::DateTime> const& value) const
{
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Wallet::IWalletItem)->put_ExpirationDate(get_abi(value)));
}

template <typename D> Windows::Storage::Streams::IRandomAccessStreamReference consume_Windows_ApplicationModel_Wallet_IWalletItem<D>::Logo159x159() const
{
    Windows::Storage::Streams::IRandomAccessStreamReference value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Wallet::IWalletItem)->get_Logo159x159(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_ApplicationModel_Wallet_IWalletItem<D>::Logo159x159(Windows::Storage::Streams::IRandomAccessStreamReference const& value) const
{
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Wallet::IWalletItem)->put_Logo159x159(get_abi(value)));
}

template <typename D> Windows::Storage::Streams::IRandomAccessStreamReference consume_Windows_ApplicationModel_Wallet_IWalletItem<D>::Logo336x336() const
{
    Windows::Storage::Streams::IRandomAccessStreamReference value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Wallet::IWalletItem)->get_Logo336x336(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_ApplicationModel_Wallet_IWalletItem<D>::Logo336x336(Windows::Storage::Streams::IRandomAccessStreamReference const& value) const
{
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Wallet::IWalletItem)->put_Logo336x336(get_abi(value)));
}

template <typename D> Windows::Storage::Streams::IRandomAccessStreamReference consume_Windows_ApplicationModel_Wallet_IWalletItem<D>::Logo99x99() const
{
    Windows::Storage::Streams::IRandomAccessStreamReference value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Wallet::IWalletItem)->get_Logo99x99(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_ApplicationModel_Wallet_IWalletItem<D>::Logo99x99(Windows::Storage::Streams::IRandomAccessStreamReference const& value) const
{
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Wallet::IWalletItem)->put_Logo99x99(get_abi(value)));
}

template <typename D> hstring consume_Windows_ApplicationModel_Wallet_IWalletItem<D>::DisplayMessage() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Wallet::IWalletItem)->get_DisplayMessage(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_ApplicationModel_Wallet_IWalletItem<D>::DisplayMessage(param::hstring const& value) const
{
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Wallet::IWalletItem)->put_DisplayMessage(get_abi(value)));
}

template <typename D> bool consume_Windows_ApplicationModel_Wallet_IWalletItem<D>::IsDisplayMessageLaunchable() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Wallet::IWalletItem)->get_IsDisplayMessageLaunchable(&value));
    return value;
}

template <typename D> void consume_Windows_ApplicationModel_Wallet_IWalletItem<D>::IsDisplayMessageLaunchable(bool value) const
{
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Wallet::IWalletItem)->put_IsDisplayMessageLaunchable(value));
}

template <typename D> hstring consume_Windows_ApplicationModel_Wallet_IWalletItem<D>::LogoText() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Wallet::IWalletItem)->get_LogoText(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_ApplicationModel_Wallet_IWalletItem<D>::LogoText(param::hstring const& value) const
{
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Wallet::IWalletItem)->put_LogoText(get_abi(value)));
}

template <typename D> Windows::UI::Color consume_Windows_ApplicationModel_Wallet_IWalletItem<D>::HeaderColor() const
{
    Windows::UI::Color value{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Wallet::IWalletItem)->get_HeaderColor(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_ApplicationModel_Wallet_IWalletItem<D>::HeaderColor(Windows::UI::Color const& value) const
{
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Wallet::IWalletItem)->put_HeaderColor(get_abi(value)));
}

template <typename D> Windows::UI::Color consume_Windows_ApplicationModel_Wallet_IWalletItem<D>::BodyColor() const
{
    Windows::UI::Color value{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Wallet::IWalletItem)->get_BodyColor(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_ApplicationModel_Wallet_IWalletItem<D>::BodyColor(Windows::UI::Color const& value) const
{
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Wallet::IWalletItem)->put_BodyColor(get_abi(value)));
}

template <typename D> Windows::UI::Color consume_Windows_ApplicationModel_Wallet_IWalletItem<D>::HeaderFontColor() const
{
    Windows::UI::Color value{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Wallet::IWalletItem)->get_HeaderFontColor(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_ApplicationModel_Wallet_IWalletItem<D>::HeaderFontColor(Windows::UI::Color const& value) const
{
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Wallet::IWalletItem)->put_HeaderFontColor(get_abi(value)));
}

template <typename D> Windows::UI::Color consume_Windows_ApplicationModel_Wallet_IWalletItem<D>::BodyFontColor() const
{
    Windows::UI::Color value{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Wallet::IWalletItem)->get_BodyFontColor(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_ApplicationModel_Wallet_IWalletItem<D>::BodyFontColor(Windows::UI::Color const& value) const
{
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Wallet::IWalletItem)->put_BodyFontColor(get_abi(value)));
}

template <typename D> Windows::Storage::Streams::IRandomAccessStreamReference consume_Windows_ApplicationModel_Wallet_IWalletItem<D>::HeaderBackgroundImage() const
{
    Windows::Storage::Streams::IRandomAccessStreamReference value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Wallet::IWalletItem)->get_HeaderBackgroundImage(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_ApplicationModel_Wallet_IWalletItem<D>::HeaderBackgroundImage(Windows::Storage::Streams::IRandomAccessStreamReference const& value) const
{
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Wallet::IWalletItem)->put_HeaderBackgroundImage(get_abi(value)));
}

template <typename D> Windows::Storage::Streams::IRandomAccessStreamReference consume_Windows_ApplicationModel_Wallet_IWalletItem<D>::BodyBackgroundImage() const
{
    Windows::Storage::Streams::IRandomAccessStreamReference value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Wallet::IWalletItem)->get_BodyBackgroundImage(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_ApplicationModel_Wallet_IWalletItem<D>::BodyBackgroundImage(Windows::Storage::Streams::IRandomAccessStreamReference const& value) const
{
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Wallet::IWalletItem)->put_BodyBackgroundImage(get_abi(value)));
}

template <typename D> Windows::Storage::Streams::IRandomAccessStreamReference consume_Windows_ApplicationModel_Wallet_IWalletItem<D>::LogoImage() const
{
    Windows::Storage::Streams::IRandomAccessStreamReference value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Wallet::IWalletItem)->get_LogoImage(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_ApplicationModel_Wallet_IWalletItem<D>::LogoImage(Windows::Storage::Streams::IRandomAccessStreamReference const& value) const
{
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Wallet::IWalletItem)->put_LogoImage(get_abi(value)));
}

template <typename D> Windows::Storage::Streams::IRandomAccessStreamReference consume_Windows_ApplicationModel_Wallet_IWalletItem<D>::PromotionalImage() const
{
    Windows::Storage::Streams::IRandomAccessStreamReference value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Wallet::IWalletItem)->get_PromotionalImage(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_ApplicationModel_Wallet_IWalletItem<D>::PromotionalImage(Windows::Storage::Streams::IRandomAccessStreamReference const& value) const
{
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Wallet::IWalletItem)->put_PromotionalImage(get_abi(value)));
}

template <typename D> Windows::Foundation::IReference<Windows::Foundation::DateTime> consume_Windows_ApplicationModel_Wallet_IWalletItem<D>::RelevantDate() const
{
    Windows::Foundation::IReference<Windows::Foundation::DateTime> value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Wallet::IWalletItem)->get_RelevantDate(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_ApplicationModel_Wallet_IWalletItem<D>::RelevantDate(optional<Windows::Foundation::DateTime> const& value) const
{
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Wallet::IWalletItem)->put_RelevantDate(get_abi(value)));
}

template <typename D> hstring consume_Windows_ApplicationModel_Wallet_IWalletItem<D>::RelevantDateDisplayMessage() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Wallet::IWalletItem)->get_RelevantDateDisplayMessage(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_ApplicationModel_Wallet_IWalletItem<D>::RelevantDateDisplayMessage(param::hstring const& value) const
{
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Wallet::IWalletItem)->put_RelevantDateDisplayMessage(get_abi(value)));
}

template <typename D> Windows::Foundation::Collections::IMap<hstring, Windows::ApplicationModel::Wallet::WalletTransaction> consume_Windows_ApplicationModel_Wallet_IWalletItem<D>::TransactionHistory() const
{
    Windows::Foundation::Collections::IMap<hstring, Windows::ApplicationModel::Wallet::WalletTransaction> value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Wallet::IWalletItem)->get_TransactionHistory(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::Collections::IMap<hstring, Windows::ApplicationModel::Wallet::WalletRelevantLocation> consume_Windows_ApplicationModel_Wallet_IWalletItem<D>::RelevantLocations() const
{
    Windows::Foundation::Collections::IMap<hstring, Windows::ApplicationModel::Wallet::WalletRelevantLocation> value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Wallet::IWalletItem)->get_RelevantLocations(put_abi(value)));
    return value;
}

template <typename D> bool consume_Windows_ApplicationModel_Wallet_IWalletItem<D>::IsMoreTransactionHistoryLaunchable() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Wallet::IWalletItem)->get_IsMoreTransactionHistoryLaunchable(&value));
    return value;
}

template <typename D> void consume_Windows_ApplicationModel_Wallet_IWalletItem<D>::IsMoreTransactionHistoryLaunchable(bool value) const
{
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Wallet::IWalletItem)->put_IsMoreTransactionHistoryLaunchable(value));
}

template <typename D> Windows::Foundation::Collections::IMap<hstring, Windows::ApplicationModel::Wallet::WalletItemCustomProperty> consume_Windows_ApplicationModel_Wallet_IWalletItem<D>::DisplayProperties() const
{
    Windows::Foundation::Collections::IMap<hstring, Windows::ApplicationModel::Wallet::WalletItemCustomProperty> value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Wallet::IWalletItem)->get_DisplayProperties(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::Collections::IMap<hstring, Windows::ApplicationModel::Wallet::WalletVerb> consume_Windows_ApplicationModel_Wallet_IWalletItem<D>::Verbs() const
{
    Windows::Foundation::Collections::IMap<hstring, Windows::ApplicationModel::Wallet::WalletVerb> value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Wallet::IWalletItem)->get_Verbs(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_ApplicationModel_Wallet_IWalletItemCustomProperty<D>::Name() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Wallet::IWalletItemCustomProperty)->get_Name(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_ApplicationModel_Wallet_IWalletItemCustomProperty<D>::Name(param::hstring const& value) const
{
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Wallet::IWalletItemCustomProperty)->put_Name(get_abi(value)));
}

template <typename D> hstring consume_Windows_ApplicationModel_Wallet_IWalletItemCustomProperty<D>::Value() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Wallet::IWalletItemCustomProperty)->get_Value(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_ApplicationModel_Wallet_IWalletItemCustomProperty<D>::Value(param::hstring const& value) const
{
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Wallet::IWalletItemCustomProperty)->put_Value(get_abi(value)));
}

template <typename D> bool consume_Windows_ApplicationModel_Wallet_IWalletItemCustomProperty<D>::AutoDetectLinks() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Wallet::IWalletItemCustomProperty)->get_AutoDetectLinks(&value));
    return value;
}

template <typename D> void consume_Windows_ApplicationModel_Wallet_IWalletItemCustomProperty<D>::AutoDetectLinks(bool value) const
{
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Wallet::IWalletItemCustomProperty)->put_AutoDetectLinks(value));
}

template <typename D> Windows::ApplicationModel::Wallet::WalletDetailViewPosition consume_Windows_ApplicationModel_Wallet_IWalletItemCustomProperty<D>::DetailViewPosition() const
{
    Windows::ApplicationModel::Wallet::WalletDetailViewPosition value{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Wallet::IWalletItemCustomProperty)->get_DetailViewPosition(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_ApplicationModel_Wallet_IWalletItemCustomProperty<D>::DetailViewPosition(Windows::ApplicationModel::Wallet::WalletDetailViewPosition const& value) const
{
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Wallet::IWalletItemCustomProperty)->put_DetailViewPosition(get_abi(value)));
}

template <typename D> Windows::ApplicationModel::Wallet::WalletSummaryViewPosition consume_Windows_ApplicationModel_Wallet_IWalletItemCustomProperty<D>::SummaryViewPosition() const
{
    Windows::ApplicationModel::Wallet::WalletSummaryViewPosition value{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Wallet::IWalletItemCustomProperty)->get_SummaryViewPosition(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_ApplicationModel_Wallet_IWalletItemCustomProperty<D>::SummaryViewPosition(Windows::ApplicationModel::Wallet::WalletSummaryViewPosition const& value) const
{
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Wallet::IWalletItemCustomProperty)->put_SummaryViewPosition(get_abi(value)));
}

template <typename D> Windows::ApplicationModel::Wallet::WalletItemCustomProperty consume_Windows_ApplicationModel_Wallet_IWalletItemCustomPropertyFactory<D>::CreateWalletItemCustomProperty(param::hstring const& name, param::hstring const& value) const
{
    Windows::ApplicationModel::Wallet::WalletItemCustomProperty walletItemCustomProperty{ nullptr };
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Wallet::IWalletItemCustomPropertyFactory)->CreateWalletItemCustomProperty(get_abi(name), get_abi(value), put_abi(walletItemCustomProperty)));
    return walletItemCustomProperty;
}

template <typename D> Windows::ApplicationModel::Wallet::WalletItem consume_Windows_ApplicationModel_Wallet_IWalletItemFactory<D>::CreateWalletItem(Windows::ApplicationModel::Wallet::WalletItemKind const& kind, param::hstring const& displayName) const
{
    Windows::ApplicationModel::Wallet::WalletItem walletItem{ nullptr };
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Wallet::IWalletItemFactory)->CreateWalletItem(get_abi(kind), get_abi(displayName), put_abi(walletItem)));
    return walletItem;
}

template <typename D> Windows::Foundation::IAsyncAction consume_Windows_ApplicationModel_Wallet_IWalletItemStore<D>::AddAsync(param::hstring const& id, Windows::ApplicationModel::Wallet::WalletItem const& item) const
{
    Windows::Foundation::IAsyncAction operation{ nullptr };
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Wallet::IWalletItemStore)->AddAsync(get_abi(id), get_abi(item), put_abi(operation)));
    return operation;
}

template <typename D> Windows::Foundation::IAsyncAction consume_Windows_ApplicationModel_Wallet_IWalletItemStore<D>::ClearAsync() const
{
    Windows::Foundation::IAsyncAction operation{ nullptr };
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Wallet::IWalletItemStore)->ClearAsync(put_abi(operation)));
    return operation;
}

template <typename D> Windows::Foundation::IAsyncOperation<Windows::ApplicationModel::Wallet::WalletItem> consume_Windows_ApplicationModel_Wallet_IWalletItemStore<D>::GetWalletItemAsync(param::hstring const& id) const
{
    Windows::Foundation::IAsyncOperation<Windows::ApplicationModel::Wallet::WalletItem> operation{ nullptr };
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Wallet::IWalletItemStore)->GetWalletItemAsync(get_abi(id), put_abi(operation)));
    return operation;
}

template <typename D> Windows::Foundation::IAsyncOperation<Windows::Foundation::Collections::IVectorView<Windows::ApplicationModel::Wallet::WalletItem>> consume_Windows_ApplicationModel_Wallet_IWalletItemStore<D>::GetItemsAsync() const
{
    Windows::Foundation::IAsyncOperation<Windows::Foundation::Collections::IVectorView<Windows::ApplicationModel::Wallet::WalletItem>> operation{ nullptr };
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Wallet::IWalletItemStore)->GetItemsAsync(put_abi(operation)));
    return operation;
}

template <typename D> Windows::Foundation::IAsyncOperation<Windows::Foundation::Collections::IVectorView<Windows::ApplicationModel::Wallet::WalletItem>> consume_Windows_ApplicationModel_Wallet_IWalletItemStore<D>::GetItemsAsync(Windows::ApplicationModel::Wallet::WalletItemKind const& kind) const
{
    Windows::Foundation::IAsyncOperation<Windows::Foundation::Collections::IVectorView<Windows::ApplicationModel::Wallet::WalletItem>> operation{ nullptr };
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Wallet::IWalletItemStore)->GetItemsWithKindAsync(get_abi(kind), put_abi(operation)));
    return operation;
}

template <typename D> Windows::Foundation::IAsyncOperation<Windows::ApplicationModel::Wallet::WalletItem> consume_Windows_ApplicationModel_Wallet_IWalletItemStore<D>::ImportItemAsync(Windows::Storage::Streams::IRandomAccessStreamReference const& stream) const
{
    Windows::Foundation::IAsyncOperation<Windows::ApplicationModel::Wallet::WalletItem> operation{ nullptr };
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Wallet::IWalletItemStore)->ImportItemAsync(get_abi(stream), put_abi(operation)));
    return operation;
}

template <typename D> Windows::Foundation::IAsyncAction consume_Windows_ApplicationModel_Wallet_IWalletItemStore<D>::DeleteAsync(param::hstring const& id) const
{
    Windows::Foundation::IAsyncAction operation{ nullptr };
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Wallet::IWalletItemStore)->DeleteAsync(get_abi(id), put_abi(operation)));
    return operation;
}

template <typename D> Windows::Foundation::IAsyncAction consume_Windows_ApplicationModel_Wallet_IWalletItemStore<D>::ShowAsync() const
{
    Windows::Foundation::IAsyncAction operation{ nullptr };
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Wallet::IWalletItemStore)->ShowAsync(put_abi(operation)));
    return operation;
}

template <typename D> Windows::Foundation::IAsyncAction consume_Windows_ApplicationModel_Wallet_IWalletItemStore<D>::ShowAsync(param::hstring const& id) const
{
    Windows::Foundation::IAsyncAction operation{ nullptr };
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Wallet::IWalletItemStore)->ShowItemAsync(get_abi(id), put_abi(operation)));
    return operation;
}

template <typename D> Windows::Foundation::IAsyncAction consume_Windows_ApplicationModel_Wallet_IWalletItemStore<D>::UpdateAsync(Windows::ApplicationModel::Wallet::WalletItem const& item) const
{
    Windows::Foundation::IAsyncAction operation{ nullptr };
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Wallet::IWalletItemStore)->UpdateAsync(get_abi(item), put_abi(operation)));
    return operation;
}

template <typename D> winrt::event_token consume_Windows_ApplicationModel_Wallet_IWalletItemStore2<D>::ItemsChanged(Windows::Foundation::TypedEventHandler<Windows::ApplicationModel::Wallet::WalletItemStore, Windows::Foundation::IInspectable> const& handler) const
{
    winrt::event_token cookie{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Wallet::IWalletItemStore2)->add_ItemsChanged(get_abi(handler), put_abi(cookie)));
    return cookie;
}

template <typename D> typename consume_Windows_ApplicationModel_Wallet_IWalletItemStore2<D>::ItemsChanged_revoker consume_Windows_ApplicationModel_Wallet_IWalletItemStore2<D>::ItemsChanged(auto_revoke_t, Windows::Foundation::TypedEventHandler<Windows::ApplicationModel::Wallet::WalletItemStore, Windows::Foundation::IInspectable> const& handler) const
{
    return impl::make_event_revoker<D, ItemsChanged_revoker>(this, ItemsChanged(handler));
}

template <typename D> void consume_Windows_ApplicationModel_Wallet_IWalletItemStore2<D>::ItemsChanged(winrt::event_token const& cookie) const noexcept
{
    WINRT_VERIFY_(0, WINRT_SHIM(Windows::ApplicationModel::Wallet::IWalletItemStore2)->remove_ItemsChanged(get_abi(cookie)));
}

template <typename D> Windows::Foundation::IAsyncOperation<Windows::ApplicationModel::Wallet::WalletItemStore> consume_Windows_ApplicationModel_Wallet_IWalletManagerStatics<D>::RequestStoreAsync() const
{
    Windows::Foundation::IAsyncOperation<Windows::ApplicationModel::Wallet::WalletItemStore> operation{ nullptr };
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Wallet::IWalletManagerStatics)->RequestStoreAsync(put_abi(operation)));
    return operation;
}

template <typename D> Windows::Devices::Geolocation::BasicGeoposition consume_Windows_ApplicationModel_Wallet_IWalletRelevantLocation<D>::Position() const
{
    Windows::Devices::Geolocation::BasicGeoposition value{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Wallet::IWalletRelevantLocation)->get_Position(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_ApplicationModel_Wallet_IWalletRelevantLocation<D>::Position(Windows::Devices::Geolocation::BasicGeoposition const& value) const
{
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Wallet::IWalletRelevantLocation)->put_Position(get_abi(value)));
}

template <typename D> hstring consume_Windows_ApplicationModel_Wallet_IWalletRelevantLocation<D>::DisplayMessage() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Wallet::IWalletRelevantLocation)->get_DisplayMessage(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_ApplicationModel_Wallet_IWalletRelevantLocation<D>::DisplayMessage(param::hstring const& value) const
{
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Wallet::IWalletRelevantLocation)->put_DisplayMessage(get_abi(value)));
}

template <typename D> hstring consume_Windows_ApplicationModel_Wallet_IWalletTransaction<D>::Description() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Wallet::IWalletTransaction)->get_Description(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_ApplicationModel_Wallet_IWalletTransaction<D>::Description(param::hstring const& value) const
{
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Wallet::IWalletTransaction)->put_Description(get_abi(value)));
}

template <typename D> hstring consume_Windows_ApplicationModel_Wallet_IWalletTransaction<D>::DisplayAmount() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Wallet::IWalletTransaction)->get_DisplayAmount(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_ApplicationModel_Wallet_IWalletTransaction<D>::DisplayAmount(param::hstring const& value) const
{
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Wallet::IWalletTransaction)->put_DisplayAmount(get_abi(value)));
}

template <typename D> bool consume_Windows_ApplicationModel_Wallet_IWalletTransaction<D>::IgnoreTimeOfDay() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Wallet::IWalletTransaction)->get_IgnoreTimeOfDay(&value));
    return value;
}

template <typename D> void consume_Windows_ApplicationModel_Wallet_IWalletTransaction<D>::IgnoreTimeOfDay(bool value) const
{
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Wallet::IWalletTransaction)->put_IgnoreTimeOfDay(value));
}

template <typename D> hstring consume_Windows_ApplicationModel_Wallet_IWalletTransaction<D>::DisplayLocation() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Wallet::IWalletTransaction)->get_DisplayLocation(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_ApplicationModel_Wallet_IWalletTransaction<D>::DisplayLocation(param::hstring const& value) const
{
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Wallet::IWalletTransaction)->put_DisplayLocation(get_abi(value)));
}

template <typename D> Windows::Foundation::IReference<Windows::Foundation::DateTime> consume_Windows_ApplicationModel_Wallet_IWalletTransaction<D>::TransactionDate() const
{
    Windows::Foundation::IReference<Windows::Foundation::DateTime> value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Wallet::IWalletTransaction)->get_TransactionDate(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_ApplicationModel_Wallet_IWalletTransaction<D>::TransactionDate(optional<Windows::Foundation::DateTime> const& value) const
{
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Wallet::IWalletTransaction)->put_TransactionDate(get_abi(value)));
}

template <typename D> bool consume_Windows_ApplicationModel_Wallet_IWalletTransaction<D>::IsLaunchable() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Wallet::IWalletTransaction)->get_IsLaunchable(&value));
    return value;
}

template <typename D> void consume_Windows_ApplicationModel_Wallet_IWalletTransaction<D>::IsLaunchable(bool value) const
{
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Wallet::IWalletTransaction)->put_IsLaunchable(value));
}

template <typename D> hstring consume_Windows_ApplicationModel_Wallet_IWalletVerb<D>::Name() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Wallet::IWalletVerb)->get_Name(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_ApplicationModel_Wallet_IWalletVerb<D>::Name(param::hstring const& value) const
{
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Wallet::IWalletVerb)->put_Name(get_abi(value)));
}

template <typename D> Windows::ApplicationModel::Wallet::WalletVerb consume_Windows_ApplicationModel_Wallet_IWalletVerbFactory<D>::CreateWalletVerb(param::hstring const& name) const
{
    Windows::ApplicationModel::Wallet::WalletVerb WalletVerb{ nullptr };
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Wallet::IWalletVerbFactory)->CreateWalletVerb(get_abi(name), put_abi(WalletVerb)));
    return WalletVerb;
}

template <typename D>
struct produce<D, Windows::ApplicationModel::Wallet::IWalletBarcode> : produce_base<D, Windows::ApplicationModel::Wallet::IWalletBarcode>
{
    int32_t WINRT_CALL get_Symbology(Windows::ApplicationModel::Wallet::WalletBarcodeSymbology* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Symbology, WINRT_WRAP(Windows::ApplicationModel::Wallet::WalletBarcodeSymbology));
            *value = detach_from<Windows::ApplicationModel::Wallet::WalletBarcodeSymbology>(this->shim().Symbology());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Value(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Value, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().Value());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL GetImageAsync(void** operation) noexcept final
    {
        try
        {
            *operation = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetImageAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<Windows::Storage::Streams::IRandomAccessStreamReference>));
            *operation = detach_from<Windows::Foundation::IAsyncOperation<Windows::Storage::Streams::IRandomAccessStreamReference>>(this->shim().GetImageAsync());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::ApplicationModel::Wallet::IWalletBarcodeFactory> : produce_base<D, Windows::ApplicationModel::Wallet::IWalletBarcodeFactory>
{
    int32_t WINRT_CALL CreateWalletBarcode(Windows::ApplicationModel::Wallet::WalletBarcodeSymbology symbology, void* value, void** barcode) noexcept final
    {
        try
        {
            *barcode = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CreateWalletBarcode, WINRT_WRAP(Windows::ApplicationModel::Wallet::WalletBarcode), Windows::ApplicationModel::Wallet::WalletBarcodeSymbology const&, hstring const&);
            *barcode = detach_from<Windows::ApplicationModel::Wallet::WalletBarcode>(this->shim().CreateWalletBarcode(*reinterpret_cast<Windows::ApplicationModel::Wallet::WalletBarcodeSymbology const*>(&symbology), *reinterpret_cast<hstring const*>(&value)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL CreateCustomWalletBarcode(void* streamToBarcodeImage, void** barcode) noexcept final
    {
        try
        {
            *barcode = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CreateCustomWalletBarcode, WINRT_WRAP(Windows::ApplicationModel::Wallet::WalletBarcode), Windows::Storage::Streams::IRandomAccessStreamReference const&);
            *barcode = detach_from<Windows::ApplicationModel::Wallet::WalletBarcode>(this->shim().CreateCustomWalletBarcode(*reinterpret_cast<Windows::Storage::Streams::IRandomAccessStreamReference const*>(&streamToBarcodeImage)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::ApplicationModel::Wallet::IWalletItem> : produce_base<D, Windows::ApplicationModel::Wallet::IWalletItem>
{
    int32_t WINRT_CALL get_DisplayName(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(DisplayName, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().DisplayName());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_DisplayName(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(DisplayName, WINRT_WRAP(void), hstring const&);
            this->shim().DisplayName(*reinterpret_cast<hstring const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Id(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Id, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().Id());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_IsAcknowledged(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IsAcknowledged, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().IsAcknowledged());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_IsAcknowledged(bool value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IsAcknowledged, WINRT_WRAP(void), bool);
            this->shim().IsAcknowledged(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_IssuerDisplayName(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IssuerDisplayName, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().IssuerDisplayName());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_IssuerDisplayName(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IssuerDisplayName, WINRT_WRAP(void), hstring const&);
            this->shim().IssuerDisplayName(*reinterpret_cast<hstring const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_LastUpdated(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(LastUpdated, WINRT_WRAP(Windows::Foundation::IReference<Windows::Foundation::DateTime>));
            *value = detach_from<Windows::Foundation::IReference<Windows::Foundation::DateTime>>(this->shim().LastUpdated());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_LastUpdated(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(LastUpdated, WINRT_WRAP(void), Windows::Foundation::IReference<Windows::Foundation::DateTime> const&);
            this->shim().LastUpdated(*reinterpret_cast<Windows::Foundation::IReference<Windows::Foundation::DateTime> const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Kind(Windows::ApplicationModel::Wallet::WalletItemKind* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Kind, WINRT_WRAP(Windows::ApplicationModel::Wallet::WalletItemKind));
            *value = detach_from<Windows::ApplicationModel::Wallet::WalletItemKind>(this->shim().Kind());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Barcode(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Barcode, WINRT_WRAP(Windows::ApplicationModel::Wallet::WalletBarcode));
            *value = detach_from<Windows::ApplicationModel::Wallet::WalletBarcode>(this->shim().Barcode());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_Barcode(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Barcode, WINRT_WRAP(void), Windows::ApplicationModel::Wallet::WalletBarcode const&);
            this->shim().Barcode(*reinterpret_cast<Windows::ApplicationModel::Wallet::WalletBarcode const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_ExpirationDate(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ExpirationDate, WINRT_WRAP(Windows::Foundation::IReference<Windows::Foundation::DateTime>));
            *value = detach_from<Windows::Foundation::IReference<Windows::Foundation::DateTime>>(this->shim().ExpirationDate());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_ExpirationDate(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ExpirationDate, WINRT_WRAP(void), Windows::Foundation::IReference<Windows::Foundation::DateTime> const&);
            this->shim().ExpirationDate(*reinterpret_cast<Windows::Foundation::IReference<Windows::Foundation::DateTime> const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Logo159x159(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Logo159x159, WINRT_WRAP(Windows::Storage::Streams::IRandomAccessStreamReference));
            *value = detach_from<Windows::Storage::Streams::IRandomAccessStreamReference>(this->shim().Logo159x159());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_Logo159x159(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Logo159x159, WINRT_WRAP(void), Windows::Storage::Streams::IRandomAccessStreamReference const&);
            this->shim().Logo159x159(*reinterpret_cast<Windows::Storage::Streams::IRandomAccessStreamReference const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Logo336x336(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Logo336x336, WINRT_WRAP(Windows::Storage::Streams::IRandomAccessStreamReference));
            *value = detach_from<Windows::Storage::Streams::IRandomAccessStreamReference>(this->shim().Logo336x336());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_Logo336x336(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Logo336x336, WINRT_WRAP(void), Windows::Storage::Streams::IRandomAccessStreamReference const&);
            this->shim().Logo336x336(*reinterpret_cast<Windows::Storage::Streams::IRandomAccessStreamReference const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Logo99x99(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Logo99x99, WINRT_WRAP(Windows::Storage::Streams::IRandomAccessStreamReference));
            *value = detach_from<Windows::Storage::Streams::IRandomAccessStreamReference>(this->shim().Logo99x99());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_Logo99x99(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Logo99x99, WINRT_WRAP(void), Windows::Storage::Streams::IRandomAccessStreamReference const&);
            this->shim().Logo99x99(*reinterpret_cast<Windows::Storage::Streams::IRandomAccessStreamReference const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_DisplayMessage(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(DisplayMessage, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().DisplayMessage());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_DisplayMessage(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(DisplayMessage, WINRT_WRAP(void), hstring const&);
            this->shim().DisplayMessage(*reinterpret_cast<hstring const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_IsDisplayMessageLaunchable(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IsDisplayMessageLaunchable, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().IsDisplayMessageLaunchable());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_IsDisplayMessageLaunchable(bool value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IsDisplayMessageLaunchable, WINRT_WRAP(void), bool);
            this->shim().IsDisplayMessageLaunchable(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_LogoText(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(LogoText, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().LogoText());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_LogoText(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(LogoText, WINRT_WRAP(void), hstring const&);
            this->shim().LogoText(*reinterpret_cast<hstring const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_HeaderColor(struct struct_Windows_UI_Color* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(HeaderColor, WINRT_WRAP(Windows::UI::Color));
            *value = detach_from<Windows::UI::Color>(this->shim().HeaderColor());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_HeaderColor(struct struct_Windows_UI_Color value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(HeaderColor, WINRT_WRAP(void), Windows::UI::Color const&);
            this->shim().HeaderColor(*reinterpret_cast<Windows::UI::Color const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_BodyColor(struct struct_Windows_UI_Color* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(BodyColor, WINRT_WRAP(Windows::UI::Color));
            *value = detach_from<Windows::UI::Color>(this->shim().BodyColor());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_BodyColor(struct struct_Windows_UI_Color value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(BodyColor, WINRT_WRAP(void), Windows::UI::Color const&);
            this->shim().BodyColor(*reinterpret_cast<Windows::UI::Color const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_HeaderFontColor(struct struct_Windows_UI_Color* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(HeaderFontColor, WINRT_WRAP(Windows::UI::Color));
            *value = detach_from<Windows::UI::Color>(this->shim().HeaderFontColor());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_HeaderFontColor(struct struct_Windows_UI_Color value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(HeaderFontColor, WINRT_WRAP(void), Windows::UI::Color const&);
            this->shim().HeaderFontColor(*reinterpret_cast<Windows::UI::Color const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_BodyFontColor(struct struct_Windows_UI_Color* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(BodyFontColor, WINRT_WRAP(Windows::UI::Color));
            *value = detach_from<Windows::UI::Color>(this->shim().BodyFontColor());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_BodyFontColor(struct struct_Windows_UI_Color value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(BodyFontColor, WINRT_WRAP(void), Windows::UI::Color const&);
            this->shim().BodyFontColor(*reinterpret_cast<Windows::UI::Color const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_HeaderBackgroundImage(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(HeaderBackgroundImage, WINRT_WRAP(Windows::Storage::Streams::IRandomAccessStreamReference));
            *value = detach_from<Windows::Storage::Streams::IRandomAccessStreamReference>(this->shim().HeaderBackgroundImage());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_HeaderBackgroundImage(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(HeaderBackgroundImage, WINRT_WRAP(void), Windows::Storage::Streams::IRandomAccessStreamReference const&);
            this->shim().HeaderBackgroundImage(*reinterpret_cast<Windows::Storage::Streams::IRandomAccessStreamReference const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_BodyBackgroundImage(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(BodyBackgroundImage, WINRT_WRAP(Windows::Storage::Streams::IRandomAccessStreamReference));
            *value = detach_from<Windows::Storage::Streams::IRandomAccessStreamReference>(this->shim().BodyBackgroundImage());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_BodyBackgroundImage(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(BodyBackgroundImage, WINRT_WRAP(void), Windows::Storage::Streams::IRandomAccessStreamReference const&);
            this->shim().BodyBackgroundImage(*reinterpret_cast<Windows::Storage::Streams::IRandomAccessStreamReference const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_LogoImage(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(LogoImage, WINRT_WRAP(Windows::Storage::Streams::IRandomAccessStreamReference));
            *value = detach_from<Windows::Storage::Streams::IRandomAccessStreamReference>(this->shim().LogoImage());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_LogoImage(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(LogoImage, WINRT_WRAP(void), Windows::Storage::Streams::IRandomAccessStreamReference const&);
            this->shim().LogoImage(*reinterpret_cast<Windows::Storage::Streams::IRandomAccessStreamReference const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_PromotionalImage(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(PromotionalImage, WINRT_WRAP(Windows::Storage::Streams::IRandomAccessStreamReference));
            *value = detach_from<Windows::Storage::Streams::IRandomAccessStreamReference>(this->shim().PromotionalImage());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_PromotionalImage(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(PromotionalImage, WINRT_WRAP(void), Windows::Storage::Streams::IRandomAccessStreamReference const&);
            this->shim().PromotionalImage(*reinterpret_cast<Windows::Storage::Streams::IRandomAccessStreamReference const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_RelevantDate(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(RelevantDate, WINRT_WRAP(Windows::Foundation::IReference<Windows::Foundation::DateTime>));
            *value = detach_from<Windows::Foundation::IReference<Windows::Foundation::DateTime>>(this->shim().RelevantDate());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_RelevantDate(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(RelevantDate, WINRT_WRAP(void), Windows::Foundation::IReference<Windows::Foundation::DateTime> const&);
            this->shim().RelevantDate(*reinterpret_cast<Windows::Foundation::IReference<Windows::Foundation::DateTime> const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_RelevantDateDisplayMessage(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(RelevantDateDisplayMessage, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().RelevantDateDisplayMessage());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_RelevantDateDisplayMessage(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(RelevantDateDisplayMessage, WINRT_WRAP(void), hstring const&);
            this->shim().RelevantDateDisplayMessage(*reinterpret_cast<hstring const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_TransactionHistory(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(TransactionHistory, WINRT_WRAP(Windows::Foundation::Collections::IMap<hstring, Windows::ApplicationModel::Wallet::WalletTransaction>));
            *value = detach_from<Windows::Foundation::Collections::IMap<hstring, Windows::ApplicationModel::Wallet::WalletTransaction>>(this->shim().TransactionHistory());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_RelevantLocations(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(RelevantLocations, WINRT_WRAP(Windows::Foundation::Collections::IMap<hstring, Windows::ApplicationModel::Wallet::WalletRelevantLocation>));
            *value = detach_from<Windows::Foundation::Collections::IMap<hstring, Windows::ApplicationModel::Wallet::WalletRelevantLocation>>(this->shim().RelevantLocations());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_IsMoreTransactionHistoryLaunchable(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IsMoreTransactionHistoryLaunchable, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().IsMoreTransactionHistoryLaunchable());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_IsMoreTransactionHistoryLaunchable(bool value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IsMoreTransactionHistoryLaunchable, WINRT_WRAP(void), bool);
            this->shim().IsMoreTransactionHistoryLaunchable(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_DisplayProperties(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(DisplayProperties, WINRT_WRAP(Windows::Foundation::Collections::IMap<hstring, Windows::ApplicationModel::Wallet::WalletItemCustomProperty>));
            *value = detach_from<Windows::Foundation::Collections::IMap<hstring, Windows::ApplicationModel::Wallet::WalletItemCustomProperty>>(this->shim().DisplayProperties());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Verbs(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Verbs, WINRT_WRAP(Windows::Foundation::Collections::IMap<hstring, Windows::ApplicationModel::Wallet::WalletVerb>));
            *value = detach_from<Windows::Foundation::Collections::IMap<hstring, Windows::ApplicationModel::Wallet::WalletVerb>>(this->shim().Verbs());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::ApplicationModel::Wallet::IWalletItemCustomProperty> : produce_base<D, Windows::ApplicationModel::Wallet::IWalletItemCustomProperty>
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

    int32_t WINRT_CALL get_Value(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Value, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().Value());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_Value(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Value, WINRT_WRAP(void), hstring const&);
            this->shim().Value(*reinterpret_cast<hstring const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_AutoDetectLinks(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(AutoDetectLinks, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().AutoDetectLinks());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_AutoDetectLinks(bool value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(AutoDetectLinks, WINRT_WRAP(void), bool);
            this->shim().AutoDetectLinks(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_DetailViewPosition(Windows::ApplicationModel::Wallet::WalletDetailViewPosition* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(DetailViewPosition, WINRT_WRAP(Windows::ApplicationModel::Wallet::WalletDetailViewPosition));
            *value = detach_from<Windows::ApplicationModel::Wallet::WalletDetailViewPosition>(this->shim().DetailViewPosition());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_DetailViewPosition(Windows::ApplicationModel::Wallet::WalletDetailViewPosition value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(DetailViewPosition, WINRT_WRAP(void), Windows::ApplicationModel::Wallet::WalletDetailViewPosition const&);
            this->shim().DetailViewPosition(*reinterpret_cast<Windows::ApplicationModel::Wallet::WalletDetailViewPosition const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_SummaryViewPosition(Windows::ApplicationModel::Wallet::WalletSummaryViewPosition* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SummaryViewPosition, WINRT_WRAP(Windows::ApplicationModel::Wallet::WalletSummaryViewPosition));
            *value = detach_from<Windows::ApplicationModel::Wallet::WalletSummaryViewPosition>(this->shim().SummaryViewPosition());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_SummaryViewPosition(Windows::ApplicationModel::Wallet::WalletSummaryViewPosition value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SummaryViewPosition, WINRT_WRAP(void), Windows::ApplicationModel::Wallet::WalletSummaryViewPosition const&);
            this->shim().SummaryViewPosition(*reinterpret_cast<Windows::ApplicationModel::Wallet::WalletSummaryViewPosition const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::ApplicationModel::Wallet::IWalletItemCustomPropertyFactory> : produce_base<D, Windows::ApplicationModel::Wallet::IWalletItemCustomPropertyFactory>
{
    int32_t WINRT_CALL CreateWalletItemCustomProperty(void* name, void* value, void** walletItemCustomProperty) noexcept final
    {
        try
        {
            *walletItemCustomProperty = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CreateWalletItemCustomProperty, WINRT_WRAP(Windows::ApplicationModel::Wallet::WalletItemCustomProperty), hstring const&, hstring const&);
            *walletItemCustomProperty = detach_from<Windows::ApplicationModel::Wallet::WalletItemCustomProperty>(this->shim().CreateWalletItemCustomProperty(*reinterpret_cast<hstring const*>(&name), *reinterpret_cast<hstring const*>(&value)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::ApplicationModel::Wallet::IWalletItemFactory> : produce_base<D, Windows::ApplicationModel::Wallet::IWalletItemFactory>
{
    int32_t WINRT_CALL CreateWalletItem(Windows::ApplicationModel::Wallet::WalletItemKind kind, void* displayName, void** walletItem) noexcept final
    {
        try
        {
            *walletItem = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CreateWalletItem, WINRT_WRAP(Windows::ApplicationModel::Wallet::WalletItem), Windows::ApplicationModel::Wallet::WalletItemKind const&, hstring const&);
            *walletItem = detach_from<Windows::ApplicationModel::Wallet::WalletItem>(this->shim().CreateWalletItem(*reinterpret_cast<Windows::ApplicationModel::Wallet::WalletItemKind const*>(&kind), *reinterpret_cast<hstring const*>(&displayName)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::ApplicationModel::Wallet::IWalletItemStore> : produce_base<D, Windows::ApplicationModel::Wallet::IWalletItemStore>
{
    int32_t WINRT_CALL AddAsync(void* id, void* item, void** operation) noexcept final
    {
        try
        {
            *operation = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(AddAsync, WINRT_WRAP(Windows::Foundation::IAsyncAction), hstring const, Windows::ApplicationModel::Wallet::WalletItem const);
            *operation = detach_from<Windows::Foundation::IAsyncAction>(this->shim().AddAsync(*reinterpret_cast<hstring const*>(&id), *reinterpret_cast<Windows::ApplicationModel::Wallet::WalletItem const*>(&item)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL ClearAsync(void** operation) noexcept final
    {
        try
        {
            *operation = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ClearAsync, WINRT_WRAP(Windows::Foundation::IAsyncAction));
            *operation = detach_from<Windows::Foundation::IAsyncAction>(this->shim().ClearAsync());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL GetWalletItemAsync(void* id, void** operation) noexcept final
    {
        try
        {
            *operation = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetWalletItemAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<Windows::ApplicationModel::Wallet::WalletItem>), hstring const);
            *operation = detach_from<Windows::Foundation::IAsyncOperation<Windows::ApplicationModel::Wallet::WalletItem>>(this->shim().GetWalletItemAsync(*reinterpret_cast<hstring const*>(&id)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL GetItemsAsync(void** operation) noexcept final
    {
        try
        {
            *operation = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetItemsAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<Windows::Foundation::Collections::IVectorView<Windows::ApplicationModel::Wallet::WalletItem>>));
            *operation = detach_from<Windows::Foundation::IAsyncOperation<Windows::Foundation::Collections::IVectorView<Windows::ApplicationModel::Wallet::WalletItem>>>(this->shim().GetItemsAsync());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL GetItemsWithKindAsync(Windows::ApplicationModel::Wallet::WalletItemKind kind, void** operation) noexcept final
    {
        try
        {
            *operation = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetItemsAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<Windows::Foundation::Collections::IVectorView<Windows::ApplicationModel::Wallet::WalletItem>>), Windows::ApplicationModel::Wallet::WalletItemKind const);
            *operation = detach_from<Windows::Foundation::IAsyncOperation<Windows::Foundation::Collections::IVectorView<Windows::ApplicationModel::Wallet::WalletItem>>>(this->shim().GetItemsAsync(*reinterpret_cast<Windows::ApplicationModel::Wallet::WalletItemKind const*>(&kind)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL ImportItemAsync(void* stream, void** operation) noexcept final
    {
        try
        {
            *operation = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ImportItemAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<Windows::ApplicationModel::Wallet::WalletItem>), Windows::Storage::Streams::IRandomAccessStreamReference const);
            *operation = detach_from<Windows::Foundation::IAsyncOperation<Windows::ApplicationModel::Wallet::WalletItem>>(this->shim().ImportItemAsync(*reinterpret_cast<Windows::Storage::Streams::IRandomAccessStreamReference const*>(&stream)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL DeleteAsync(void* id, void** operation) noexcept final
    {
        try
        {
            *operation = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(DeleteAsync, WINRT_WRAP(Windows::Foundation::IAsyncAction), hstring const);
            *operation = detach_from<Windows::Foundation::IAsyncAction>(this->shim().DeleteAsync(*reinterpret_cast<hstring const*>(&id)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL ShowAsync(void** operation) noexcept final
    {
        try
        {
            *operation = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ShowAsync, WINRT_WRAP(Windows::Foundation::IAsyncAction));
            *operation = detach_from<Windows::Foundation::IAsyncAction>(this->shim().ShowAsync());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL ShowItemAsync(void* id, void** operation) noexcept final
    {
        try
        {
            *operation = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ShowAsync, WINRT_WRAP(Windows::Foundation::IAsyncAction), hstring const);
            *operation = detach_from<Windows::Foundation::IAsyncAction>(this->shim().ShowAsync(*reinterpret_cast<hstring const*>(&id)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL UpdateAsync(void* item, void** operation) noexcept final
    {
        try
        {
            *operation = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(UpdateAsync, WINRT_WRAP(Windows::Foundation::IAsyncAction), Windows::ApplicationModel::Wallet::WalletItem const);
            *operation = detach_from<Windows::Foundation::IAsyncAction>(this->shim().UpdateAsync(*reinterpret_cast<Windows::ApplicationModel::Wallet::WalletItem const*>(&item)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::ApplicationModel::Wallet::IWalletItemStore2> : produce_base<D, Windows::ApplicationModel::Wallet::IWalletItemStore2>
{
    int32_t WINRT_CALL add_ItemsChanged(void* handler, winrt::event_token* cookie) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ItemsChanged, WINRT_WRAP(winrt::event_token), Windows::Foundation::TypedEventHandler<Windows::ApplicationModel::Wallet::WalletItemStore, Windows::Foundation::IInspectable> const&);
            *cookie = detach_from<winrt::event_token>(this->shim().ItemsChanged(*reinterpret_cast<Windows::Foundation::TypedEventHandler<Windows::ApplicationModel::Wallet::WalletItemStore, Windows::Foundation::IInspectable> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL remove_ItemsChanged(winrt::event_token cookie) noexcept final
    {
        typename D::abi_guard guard(this->shim());
        WINRT_ASSERT_DECLARATION(ItemsChanged, WINRT_WRAP(void), winrt::event_token const&);
        this->shim().ItemsChanged(*reinterpret_cast<winrt::event_token const*>(&cookie));
        return 0;
    }
};

template <typename D>
struct produce<D, Windows::ApplicationModel::Wallet::IWalletManagerStatics> : produce_base<D, Windows::ApplicationModel::Wallet::IWalletManagerStatics>
{
    int32_t WINRT_CALL RequestStoreAsync(void** operation) noexcept final
    {
        try
        {
            *operation = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(RequestStoreAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<Windows::ApplicationModel::Wallet::WalletItemStore>));
            *operation = detach_from<Windows::Foundation::IAsyncOperation<Windows::ApplicationModel::Wallet::WalletItemStore>>(this->shim().RequestStoreAsync());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::ApplicationModel::Wallet::IWalletRelevantLocation> : produce_base<D, Windows::ApplicationModel::Wallet::IWalletRelevantLocation>
{
    int32_t WINRT_CALL get_Position(struct struct_Windows_Devices_Geolocation_BasicGeoposition* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Position, WINRT_WRAP(Windows::Devices::Geolocation::BasicGeoposition));
            *value = detach_from<Windows::Devices::Geolocation::BasicGeoposition>(this->shim().Position());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_Position(struct struct_Windows_Devices_Geolocation_BasicGeoposition value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Position, WINRT_WRAP(void), Windows::Devices::Geolocation::BasicGeoposition const&);
            this->shim().Position(*reinterpret_cast<Windows::Devices::Geolocation::BasicGeoposition const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_DisplayMessage(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(DisplayMessage, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().DisplayMessage());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_DisplayMessage(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(DisplayMessage, WINRT_WRAP(void), hstring const&);
            this->shim().DisplayMessage(*reinterpret_cast<hstring const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::ApplicationModel::Wallet::IWalletTransaction> : produce_base<D, Windows::ApplicationModel::Wallet::IWalletTransaction>
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

    int32_t WINRT_CALL get_DisplayAmount(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(DisplayAmount, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().DisplayAmount());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_DisplayAmount(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(DisplayAmount, WINRT_WRAP(void), hstring const&);
            this->shim().DisplayAmount(*reinterpret_cast<hstring const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_IgnoreTimeOfDay(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IgnoreTimeOfDay, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().IgnoreTimeOfDay());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_IgnoreTimeOfDay(bool value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IgnoreTimeOfDay, WINRT_WRAP(void), bool);
            this->shim().IgnoreTimeOfDay(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_DisplayLocation(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(DisplayLocation, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().DisplayLocation());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_DisplayLocation(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(DisplayLocation, WINRT_WRAP(void), hstring const&);
            this->shim().DisplayLocation(*reinterpret_cast<hstring const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_TransactionDate(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(TransactionDate, WINRT_WRAP(Windows::Foundation::IReference<Windows::Foundation::DateTime>));
            *value = detach_from<Windows::Foundation::IReference<Windows::Foundation::DateTime>>(this->shim().TransactionDate());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_TransactionDate(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(TransactionDate, WINRT_WRAP(void), Windows::Foundation::IReference<Windows::Foundation::DateTime> const&);
            this->shim().TransactionDate(*reinterpret_cast<Windows::Foundation::IReference<Windows::Foundation::DateTime> const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_IsLaunchable(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IsLaunchable, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().IsLaunchable());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_IsLaunchable(bool value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IsLaunchable, WINRT_WRAP(void), bool);
            this->shim().IsLaunchable(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::ApplicationModel::Wallet::IWalletVerb> : produce_base<D, Windows::ApplicationModel::Wallet::IWalletVerb>
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
};

template <typename D>
struct produce<D, Windows::ApplicationModel::Wallet::IWalletVerbFactory> : produce_base<D, Windows::ApplicationModel::Wallet::IWalletVerbFactory>
{
    int32_t WINRT_CALL CreateWalletVerb(void* name, void** WalletVerb) noexcept final
    {
        try
        {
            *WalletVerb = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CreateWalletVerb, WINRT_WRAP(Windows::ApplicationModel::Wallet::WalletVerb), hstring const&);
            *WalletVerb = detach_from<Windows::ApplicationModel::Wallet::WalletVerb>(this->shim().CreateWalletVerb(*reinterpret_cast<hstring const*>(&name)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

}

WINRT_EXPORT namespace winrt::Windows::ApplicationModel::Wallet {

inline WalletBarcode::WalletBarcode(Windows::ApplicationModel::Wallet::WalletBarcodeSymbology const& symbology, param::hstring const& value) :
    WalletBarcode(impl::call_factory<WalletBarcode, Windows::ApplicationModel::Wallet::IWalletBarcodeFactory>([&](auto&& f) { return f.CreateWalletBarcode(symbology, value); }))
{}

inline WalletBarcode::WalletBarcode(Windows::Storage::Streams::IRandomAccessStreamReference const& streamToBarcodeImage) :
    WalletBarcode(impl::call_factory<WalletBarcode, Windows::ApplicationModel::Wallet::IWalletBarcodeFactory>([&](auto&& f) { return f.CreateCustomWalletBarcode(streamToBarcodeImage); }))
{}

inline WalletItem::WalletItem(Windows::ApplicationModel::Wallet::WalletItemKind const& kind, param::hstring const& displayName) :
    WalletItem(impl::call_factory<WalletItem, Windows::ApplicationModel::Wallet::IWalletItemFactory>([&](auto&& f) { return f.CreateWalletItem(kind, displayName); }))
{}

inline WalletItemCustomProperty::WalletItemCustomProperty(param::hstring const& name, param::hstring const& value) :
    WalletItemCustomProperty(impl::call_factory<WalletItemCustomProperty, Windows::ApplicationModel::Wallet::IWalletItemCustomPropertyFactory>([&](auto&& f) { return f.CreateWalletItemCustomProperty(name, value); }))
{}

inline Windows::Foundation::IAsyncOperation<Windows::ApplicationModel::Wallet::WalletItemStore> WalletManager::RequestStoreAsync()
{
    return impl::call_factory<WalletManager, Windows::ApplicationModel::Wallet::IWalletManagerStatics>([&](auto&& f) { return f.RequestStoreAsync(); });
}

inline WalletRelevantLocation::WalletRelevantLocation() :
    WalletRelevantLocation(impl::call_factory<WalletRelevantLocation>([](auto&& f) { return f.template ActivateInstance<WalletRelevantLocation>(); }))
{}

inline WalletTransaction::WalletTransaction() :
    WalletTransaction(impl::call_factory<WalletTransaction>([](auto&& f) { return f.template ActivateInstance<WalletTransaction>(); }))
{}

inline WalletVerb::WalletVerb(param::hstring const& name) :
    WalletVerb(impl::call_factory<WalletVerb, Windows::ApplicationModel::Wallet::IWalletVerbFactory>([&](auto&& f) { return f.CreateWalletVerb(name); }))
{}

}

WINRT_EXPORT namespace std {

template<> struct hash<winrt::Windows::ApplicationModel::Wallet::IWalletBarcode> : winrt::impl::hash_base<winrt::Windows::ApplicationModel::Wallet::IWalletBarcode> {};
template<> struct hash<winrt::Windows::ApplicationModel::Wallet::IWalletBarcodeFactory> : winrt::impl::hash_base<winrt::Windows::ApplicationModel::Wallet::IWalletBarcodeFactory> {};
template<> struct hash<winrt::Windows::ApplicationModel::Wallet::IWalletItem> : winrt::impl::hash_base<winrt::Windows::ApplicationModel::Wallet::IWalletItem> {};
template<> struct hash<winrt::Windows::ApplicationModel::Wallet::IWalletItemCustomProperty> : winrt::impl::hash_base<winrt::Windows::ApplicationModel::Wallet::IWalletItemCustomProperty> {};
template<> struct hash<winrt::Windows::ApplicationModel::Wallet::IWalletItemCustomPropertyFactory> : winrt::impl::hash_base<winrt::Windows::ApplicationModel::Wallet::IWalletItemCustomPropertyFactory> {};
template<> struct hash<winrt::Windows::ApplicationModel::Wallet::IWalletItemFactory> : winrt::impl::hash_base<winrt::Windows::ApplicationModel::Wallet::IWalletItemFactory> {};
template<> struct hash<winrt::Windows::ApplicationModel::Wallet::IWalletItemStore> : winrt::impl::hash_base<winrt::Windows::ApplicationModel::Wallet::IWalletItemStore> {};
template<> struct hash<winrt::Windows::ApplicationModel::Wallet::IWalletItemStore2> : winrt::impl::hash_base<winrt::Windows::ApplicationModel::Wallet::IWalletItemStore2> {};
template<> struct hash<winrt::Windows::ApplicationModel::Wallet::IWalletManagerStatics> : winrt::impl::hash_base<winrt::Windows::ApplicationModel::Wallet::IWalletManagerStatics> {};
template<> struct hash<winrt::Windows::ApplicationModel::Wallet::IWalletRelevantLocation> : winrt::impl::hash_base<winrt::Windows::ApplicationModel::Wallet::IWalletRelevantLocation> {};
template<> struct hash<winrt::Windows::ApplicationModel::Wallet::IWalletTransaction> : winrt::impl::hash_base<winrt::Windows::ApplicationModel::Wallet::IWalletTransaction> {};
template<> struct hash<winrt::Windows::ApplicationModel::Wallet::IWalletVerb> : winrt::impl::hash_base<winrt::Windows::ApplicationModel::Wallet::IWalletVerb> {};
template<> struct hash<winrt::Windows::ApplicationModel::Wallet::IWalletVerbFactory> : winrt::impl::hash_base<winrt::Windows::ApplicationModel::Wallet::IWalletVerbFactory> {};
template<> struct hash<winrt::Windows::ApplicationModel::Wallet::WalletBarcode> : winrt::impl::hash_base<winrt::Windows::ApplicationModel::Wallet::WalletBarcode> {};
template<> struct hash<winrt::Windows::ApplicationModel::Wallet::WalletItem> : winrt::impl::hash_base<winrt::Windows::ApplicationModel::Wallet::WalletItem> {};
template<> struct hash<winrt::Windows::ApplicationModel::Wallet::WalletItemCustomProperty> : winrt::impl::hash_base<winrt::Windows::ApplicationModel::Wallet::WalletItemCustomProperty> {};
template<> struct hash<winrt::Windows::ApplicationModel::Wallet::WalletItemStore> : winrt::impl::hash_base<winrt::Windows::ApplicationModel::Wallet::WalletItemStore> {};
template<> struct hash<winrt::Windows::ApplicationModel::Wallet::WalletManager> : winrt::impl::hash_base<winrt::Windows::ApplicationModel::Wallet::WalletManager> {};
template<> struct hash<winrt::Windows::ApplicationModel::Wallet::WalletRelevantLocation> : winrt::impl::hash_base<winrt::Windows::ApplicationModel::Wallet::WalletRelevantLocation> {};
template<> struct hash<winrt::Windows::ApplicationModel::Wallet::WalletTransaction> : winrt::impl::hash_base<winrt::Windows::ApplicationModel::Wallet::WalletTransaction> {};
template<> struct hash<winrt::Windows::ApplicationModel::Wallet::WalletVerb> : winrt::impl::hash_base<winrt::Windows::ApplicationModel::Wallet::WalletVerb> {};

}
