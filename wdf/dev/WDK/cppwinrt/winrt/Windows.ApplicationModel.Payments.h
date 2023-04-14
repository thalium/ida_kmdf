// C++/WinRT v1.0.190111.3

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#pragma once

#include "winrt/base.h"

#include "winrt/Windows.Foundation.h"
#include "winrt/Windows.Foundation.Collections.h"
#include "winrt/impl/Windows.Foundation.2.h"
#include "winrt/impl/Windows.Foundation.Collections.2.h"
#include "winrt/impl/Windows.ApplicationModel.Payments.2.h"
#include "winrt/Windows.ApplicationModel.h"

namespace winrt::impl {

template <typename D> hstring consume_Windows_ApplicationModel_Payments_IPaymentAddress<D>::Country() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Payments::IPaymentAddress)->get_Country(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_ApplicationModel_Payments_IPaymentAddress<D>::Country(param::hstring const& value) const
{
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Payments::IPaymentAddress)->put_Country(get_abi(value)));
}

template <typename D> Windows::Foundation::Collections::IVectorView<hstring> consume_Windows_ApplicationModel_Payments_IPaymentAddress<D>::AddressLines() const
{
    Windows::Foundation::Collections::IVectorView<hstring> value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Payments::IPaymentAddress)->get_AddressLines(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_ApplicationModel_Payments_IPaymentAddress<D>::AddressLines(param::async_vector_view<hstring> const& value) const
{
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Payments::IPaymentAddress)->put_AddressLines(get_abi(value)));
}

template <typename D> hstring consume_Windows_ApplicationModel_Payments_IPaymentAddress<D>::Region() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Payments::IPaymentAddress)->get_Region(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_ApplicationModel_Payments_IPaymentAddress<D>::Region(param::hstring const& value) const
{
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Payments::IPaymentAddress)->put_Region(get_abi(value)));
}

template <typename D> hstring consume_Windows_ApplicationModel_Payments_IPaymentAddress<D>::City() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Payments::IPaymentAddress)->get_City(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_ApplicationModel_Payments_IPaymentAddress<D>::City(param::hstring const& value) const
{
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Payments::IPaymentAddress)->put_City(get_abi(value)));
}

template <typename D> hstring consume_Windows_ApplicationModel_Payments_IPaymentAddress<D>::DependentLocality() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Payments::IPaymentAddress)->get_DependentLocality(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_ApplicationModel_Payments_IPaymentAddress<D>::DependentLocality(param::hstring const& value) const
{
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Payments::IPaymentAddress)->put_DependentLocality(get_abi(value)));
}

template <typename D> hstring consume_Windows_ApplicationModel_Payments_IPaymentAddress<D>::PostalCode() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Payments::IPaymentAddress)->get_PostalCode(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_ApplicationModel_Payments_IPaymentAddress<D>::PostalCode(param::hstring const& value) const
{
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Payments::IPaymentAddress)->put_PostalCode(get_abi(value)));
}

template <typename D> hstring consume_Windows_ApplicationModel_Payments_IPaymentAddress<D>::SortingCode() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Payments::IPaymentAddress)->get_SortingCode(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_ApplicationModel_Payments_IPaymentAddress<D>::SortingCode(param::hstring const& value) const
{
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Payments::IPaymentAddress)->put_SortingCode(get_abi(value)));
}

template <typename D> hstring consume_Windows_ApplicationModel_Payments_IPaymentAddress<D>::LanguageCode() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Payments::IPaymentAddress)->get_LanguageCode(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_ApplicationModel_Payments_IPaymentAddress<D>::LanguageCode(param::hstring const& value) const
{
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Payments::IPaymentAddress)->put_LanguageCode(get_abi(value)));
}

template <typename D> hstring consume_Windows_ApplicationModel_Payments_IPaymentAddress<D>::Organization() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Payments::IPaymentAddress)->get_Organization(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_ApplicationModel_Payments_IPaymentAddress<D>::Organization(param::hstring const& value) const
{
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Payments::IPaymentAddress)->put_Organization(get_abi(value)));
}

template <typename D> hstring consume_Windows_ApplicationModel_Payments_IPaymentAddress<D>::Recipient() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Payments::IPaymentAddress)->get_Recipient(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_ApplicationModel_Payments_IPaymentAddress<D>::Recipient(param::hstring const& value) const
{
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Payments::IPaymentAddress)->put_Recipient(get_abi(value)));
}

template <typename D> hstring consume_Windows_ApplicationModel_Payments_IPaymentAddress<D>::PhoneNumber() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Payments::IPaymentAddress)->get_PhoneNumber(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_ApplicationModel_Payments_IPaymentAddress<D>::PhoneNumber(param::hstring const& value) const
{
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Payments::IPaymentAddress)->put_PhoneNumber(get_abi(value)));
}

template <typename D> Windows::Foundation::Collections::ValueSet consume_Windows_ApplicationModel_Payments_IPaymentAddress<D>::Properties() const
{
    Windows::Foundation::Collections::ValueSet value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Payments::IPaymentAddress)->get_Properties(put_abi(value)));
    return value;
}

template <typename D> Windows::ApplicationModel::Payments::PaymentCanMakePaymentResultStatus consume_Windows_ApplicationModel_Payments_IPaymentCanMakePaymentResult<D>::Status() const
{
    Windows::ApplicationModel::Payments::PaymentCanMakePaymentResultStatus value{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Payments::IPaymentCanMakePaymentResult)->get_Status(put_abi(value)));
    return value;
}

template <typename D> Windows::ApplicationModel::Payments::PaymentCanMakePaymentResult consume_Windows_ApplicationModel_Payments_IPaymentCanMakePaymentResultFactory<D>::Create(Windows::ApplicationModel::Payments::PaymentCanMakePaymentResultStatus const& value) const
{
    Windows::ApplicationModel::Payments::PaymentCanMakePaymentResult result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Payments::IPaymentCanMakePaymentResultFactory)->Create(get_abi(value), put_abi(result)));
    return result;
}

template <typename D> hstring consume_Windows_ApplicationModel_Payments_IPaymentCurrencyAmount<D>::Currency() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Payments::IPaymentCurrencyAmount)->get_Currency(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_ApplicationModel_Payments_IPaymentCurrencyAmount<D>::Currency(param::hstring const& value) const
{
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Payments::IPaymentCurrencyAmount)->put_Currency(get_abi(value)));
}

template <typename D> hstring consume_Windows_ApplicationModel_Payments_IPaymentCurrencyAmount<D>::CurrencySystem() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Payments::IPaymentCurrencyAmount)->get_CurrencySystem(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_ApplicationModel_Payments_IPaymentCurrencyAmount<D>::CurrencySystem(param::hstring const& value) const
{
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Payments::IPaymentCurrencyAmount)->put_CurrencySystem(get_abi(value)));
}

template <typename D> hstring consume_Windows_ApplicationModel_Payments_IPaymentCurrencyAmount<D>::Value() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Payments::IPaymentCurrencyAmount)->get_Value(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_ApplicationModel_Payments_IPaymentCurrencyAmount<D>::Value(param::hstring const& value) const
{
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Payments::IPaymentCurrencyAmount)->put_Value(get_abi(value)));
}

template <typename D> Windows::ApplicationModel::Payments::PaymentCurrencyAmount consume_Windows_ApplicationModel_Payments_IPaymentCurrencyAmountFactory<D>::Create(param::hstring const& value, param::hstring const& currency) const
{
    Windows::ApplicationModel::Payments::PaymentCurrencyAmount result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Payments::IPaymentCurrencyAmountFactory)->Create(get_abi(value), get_abi(currency), put_abi(result)));
    return result;
}

template <typename D> Windows::ApplicationModel::Payments::PaymentCurrencyAmount consume_Windows_ApplicationModel_Payments_IPaymentCurrencyAmountFactory<D>::CreateWithCurrencySystem(param::hstring const& value, param::hstring const& currency, param::hstring const& currencySystem) const
{
    Windows::ApplicationModel::Payments::PaymentCurrencyAmount result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Payments::IPaymentCurrencyAmountFactory)->CreateWithCurrencySystem(get_abi(value), get_abi(currency), get_abi(currencySystem), put_abi(result)));
    return result;
}

template <typename D> Windows::ApplicationModel::Payments::PaymentItem consume_Windows_ApplicationModel_Payments_IPaymentDetails<D>::Total() const
{
    Windows::ApplicationModel::Payments::PaymentItem value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Payments::IPaymentDetails)->get_Total(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_ApplicationModel_Payments_IPaymentDetails<D>::Total(Windows::ApplicationModel::Payments::PaymentItem const& value) const
{
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Payments::IPaymentDetails)->put_Total(get_abi(value)));
}

template <typename D> Windows::Foundation::Collections::IVectorView<Windows::ApplicationModel::Payments::PaymentItem> consume_Windows_ApplicationModel_Payments_IPaymentDetails<D>::DisplayItems() const
{
    Windows::Foundation::Collections::IVectorView<Windows::ApplicationModel::Payments::PaymentItem> value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Payments::IPaymentDetails)->get_DisplayItems(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_ApplicationModel_Payments_IPaymentDetails<D>::DisplayItems(param::async_vector_view<Windows::ApplicationModel::Payments::PaymentItem> const& value) const
{
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Payments::IPaymentDetails)->put_DisplayItems(get_abi(value)));
}

template <typename D> Windows::Foundation::Collections::IVectorView<Windows::ApplicationModel::Payments::PaymentShippingOption> consume_Windows_ApplicationModel_Payments_IPaymentDetails<D>::ShippingOptions() const
{
    Windows::Foundation::Collections::IVectorView<Windows::ApplicationModel::Payments::PaymentShippingOption> value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Payments::IPaymentDetails)->get_ShippingOptions(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_ApplicationModel_Payments_IPaymentDetails<D>::ShippingOptions(param::async_vector_view<Windows::ApplicationModel::Payments::PaymentShippingOption> const& value) const
{
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Payments::IPaymentDetails)->put_ShippingOptions(get_abi(value)));
}

template <typename D> Windows::Foundation::Collections::IVectorView<Windows::ApplicationModel::Payments::PaymentDetailsModifier> consume_Windows_ApplicationModel_Payments_IPaymentDetails<D>::Modifiers() const
{
    Windows::Foundation::Collections::IVectorView<Windows::ApplicationModel::Payments::PaymentDetailsModifier> value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Payments::IPaymentDetails)->get_Modifiers(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_ApplicationModel_Payments_IPaymentDetails<D>::Modifiers(param::async_vector_view<Windows::ApplicationModel::Payments::PaymentDetailsModifier> const& value) const
{
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Payments::IPaymentDetails)->put_Modifiers(get_abi(value)));
}

template <typename D> Windows::ApplicationModel::Payments::PaymentDetails consume_Windows_ApplicationModel_Payments_IPaymentDetailsFactory<D>::Create(Windows::ApplicationModel::Payments::PaymentItem const& total) const
{
    Windows::ApplicationModel::Payments::PaymentDetails result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Payments::IPaymentDetailsFactory)->Create(get_abi(total), put_abi(result)));
    return result;
}

template <typename D> Windows::ApplicationModel::Payments::PaymentDetails consume_Windows_ApplicationModel_Payments_IPaymentDetailsFactory<D>::CreateWithDisplayItems(Windows::ApplicationModel::Payments::PaymentItem const& total, param::iterable<Windows::ApplicationModel::Payments::PaymentItem> const& displayItems) const
{
    Windows::ApplicationModel::Payments::PaymentDetails result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Payments::IPaymentDetailsFactory)->CreateWithDisplayItems(get_abi(total), get_abi(displayItems), put_abi(result)));
    return result;
}

template <typename D> hstring consume_Windows_ApplicationModel_Payments_IPaymentDetailsModifier<D>::JsonData() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Payments::IPaymentDetailsModifier)->get_JsonData(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::Collections::IVectorView<hstring> consume_Windows_ApplicationModel_Payments_IPaymentDetailsModifier<D>::SupportedMethodIds() const
{
    Windows::Foundation::Collections::IVectorView<hstring> value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Payments::IPaymentDetailsModifier)->get_SupportedMethodIds(put_abi(value)));
    return value;
}

template <typename D> Windows::ApplicationModel::Payments::PaymentItem consume_Windows_ApplicationModel_Payments_IPaymentDetailsModifier<D>::Total() const
{
    Windows::ApplicationModel::Payments::PaymentItem value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Payments::IPaymentDetailsModifier)->get_Total(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::Collections::IVectorView<Windows::ApplicationModel::Payments::PaymentItem> consume_Windows_ApplicationModel_Payments_IPaymentDetailsModifier<D>::AdditionalDisplayItems() const
{
    Windows::Foundation::Collections::IVectorView<Windows::ApplicationModel::Payments::PaymentItem> value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Payments::IPaymentDetailsModifier)->get_AdditionalDisplayItems(put_abi(value)));
    return value;
}

template <typename D> Windows::ApplicationModel::Payments::PaymentDetailsModifier consume_Windows_ApplicationModel_Payments_IPaymentDetailsModifierFactory<D>::Create(param::iterable<hstring> const& supportedMethodIds, Windows::ApplicationModel::Payments::PaymentItem const& total) const
{
    Windows::ApplicationModel::Payments::PaymentDetailsModifier result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Payments::IPaymentDetailsModifierFactory)->Create(get_abi(supportedMethodIds), get_abi(total), put_abi(result)));
    return result;
}

template <typename D> Windows::ApplicationModel::Payments::PaymentDetailsModifier consume_Windows_ApplicationModel_Payments_IPaymentDetailsModifierFactory<D>::CreateWithAdditionalDisplayItems(param::iterable<hstring> const& supportedMethodIds, Windows::ApplicationModel::Payments::PaymentItem const& total, param::iterable<Windows::ApplicationModel::Payments::PaymentItem> const& additionalDisplayItems) const
{
    Windows::ApplicationModel::Payments::PaymentDetailsModifier result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Payments::IPaymentDetailsModifierFactory)->CreateWithAdditionalDisplayItems(get_abi(supportedMethodIds), get_abi(total), get_abi(additionalDisplayItems), put_abi(result)));
    return result;
}

template <typename D> Windows::ApplicationModel::Payments::PaymentDetailsModifier consume_Windows_ApplicationModel_Payments_IPaymentDetailsModifierFactory<D>::CreateWithAdditionalDisplayItemsAndJsonData(param::iterable<hstring> const& supportedMethodIds, Windows::ApplicationModel::Payments::PaymentItem const& total, param::iterable<Windows::ApplicationModel::Payments::PaymentItem> const& additionalDisplayItems, param::hstring const& jsonData) const
{
    Windows::ApplicationModel::Payments::PaymentDetailsModifier result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Payments::IPaymentDetailsModifierFactory)->CreateWithAdditionalDisplayItemsAndJsonData(get_abi(supportedMethodIds), get_abi(total), get_abi(additionalDisplayItems), get_abi(jsonData), put_abi(result)));
    return result;
}

template <typename D> hstring consume_Windows_ApplicationModel_Payments_IPaymentItem<D>::Label() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Payments::IPaymentItem)->get_Label(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_ApplicationModel_Payments_IPaymentItem<D>::Label(param::hstring const& value) const
{
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Payments::IPaymentItem)->put_Label(get_abi(value)));
}

template <typename D> Windows::ApplicationModel::Payments::PaymentCurrencyAmount consume_Windows_ApplicationModel_Payments_IPaymentItem<D>::Amount() const
{
    Windows::ApplicationModel::Payments::PaymentCurrencyAmount value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Payments::IPaymentItem)->get_Amount(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_ApplicationModel_Payments_IPaymentItem<D>::Amount(Windows::ApplicationModel::Payments::PaymentCurrencyAmount const& value) const
{
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Payments::IPaymentItem)->put_Amount(get_abi(value)));
}

template <typename D> bool consume_Windows_ApplicationModel_Payments_IPaymentItem<D>::Pending() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Payments::IPaymentItem)->get_Pending(&value));
    return value;
}

template <typename D> void consume_Windows_ApplicationModel_Payments_IPaymentItem<D>::Pending(bool value) const
{
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Payments::IPaymentItem)->put_Pending(value));
}

template <typename D> Windows::ApplicationModel::Payments::PaymentItem consume_Windows_ApplicationModel_Payments_IPaymentItemFactory<D>::Create(param::hstring const& label, Windows::ApplicationModel::Payments::PaymentCurrencyAmount const& amount) const
{
    Windows::ApplicationModel::Payments::PaymentItem result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Payments::IPaymentItemFactory)->Create(get_abi(label), get_abi(amount), put_abi(result)));
    return result;
}

template <typename D> Windows::Foundation::IAsyncOperation<Windows::Foundation::Collections::IVectorView<hstring>> consume_Windows_ApplicationModel_Payments_IPaymentMediator<D>::GetSupportedMethodIdsAsync() const
{
    Windows::Foundation::IAsyncOperation<Windows::Foundation::Collections::IVectorView<hstring>> result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Payments::IPaymentMediator)->GetSupportedMethodIdsAsync(put_abi(result)));
    return result;
}

template <typename D> Windows::Foundation::IAsyncOperation<Windows::ApplicationModel::Payments::PaymentRequestSubmitResult> consume_Windows_ApplicationModel_Payments_IPaymentMediator<D>::SubmitPaymentRequestAsync(Windows::ApplicationModel::Payments::PaymentRequest const& paymentRequest) const
{
    Windows::Foundation::IAsyncOperation<Windows::ApplicationModel::Payments::PaymentRequestSubmitResult> result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Payments::IPaymentMediator)->SubmitPaymentRequestAsync(get_abi(paymentRequest), put_abi(result)));
    return result;
}

template <typename D> Windows::Foundation::IAsyncOperation<Windows::ApplicationModel::Payments::PaymentRequestSubmitResult> consume_Windows_ApplicationModel_Payments_IPaymentMediator<D>::SubmitPaymentRequestAsync(Windows::ApplicationModel::Payments::PaymentRequest const& paymentRequest, Windows::ApplicationModel::Payments::PaymentRequestChangedHandler const& changeHandler) const
{
    Windows::Foundation::IAsyncOperation<Windows::ApplicationModel::Payments::PaymentRequestSubmitResult> result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Payments::IPaymentMediator)->SubmitPaymentRequestWithChangeHandlerAsync(get_abi(paymentRequest), get_abi(changeHandler), put_abi(result)));
    return result;
}

template <typename D> Windows::Foundation::IAsyncOperation<Windows::ApplicationModel::Payments::PaymentCanMakePaymentResult> consume_Windows_ApplicationModel_Payments_IPaymentMediator2<D>::CanMakePaymentAsync(Windows::ApplicationModel::Payments::PaymentRequest const& paymentRequest) const
{
    Windows::Foundation::IAsyncOperation<Windows::ApplicationModel::Payments::PaymentCanMakePaymentResult> result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Payments::IPaymentMediator2)->CanMakePaymentAsync(get_abi(paymentRequest), put_abi(result)));
    return result;
}

template <typename D> hstring consume_Windows_ApplicationModel_Payments_IPaymentMerchantInfo<D>::PackageFullName() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Payments::IPaymentMerchantInfo)->get_PackageFullName(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::Uri consume_Windows_ApplicationModel_Payments_IPaymentMerchantInfo<D>::Uri() const
{
    Windows::Foundation::Uri value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Payments::IPaymentMerchantInfo)->get_Uri(put_abi(value)));
    return value;
}

template <typename D> Windows::ApplicationModel::Payments::PaymentMerchantInfo consume_Windows_ApplicationModel_Payments_IPaymentMerchantInfoFactory<D>::Create(Windows::Foundation::Uri const& uri) const
{
    Windows::ApplicationModel::Payments::PaymentMerchantInfo result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Payments::IPaymentMerchantInfoFactory)->Create(get_abi(uri), put_abi(result)));
    return result;
}

template <typename D> Windows::Foundation::Collections::IVectorView<hstring> consume_Windows_ApplicationModel_Payments_IPaymentMethodData<D>::SupportedMethodIds() const
{
    Windows::Foundation::Collections::IVectorView<hstring> value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Payments::IPaymentMethodData)->get_SupportedMethodIds(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_ApplicationModel_Payments_IPaymentMethodData<D>::JsonData() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Payments::IPaymentMethodData)->get_JsonData(put_abi(value)));
    return value;
}

template <typename D> Windows::ApplicationModel::Payments::PaymentMethodData consume_Windows_ApplicationModel_Payments_IPaymentMethodDataFactory<D>::Create(param::iterable<hstring> const& supportedMethodIds) const
{
    Windows::ApplicationModel::Payments::PaymentMethodData result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Payments::IPaymentMethodDataFactory)->Create(get_abi(supportedMethodIds), put_abi(result)));
    return result;
}

template <typename D> Windows::ApplicationModel::Payments::PaymentMethodData consume_Windows_ApplicationModel_Payments_IPaymentMethodDataFactory<D>::CreateWithJsonData(param::iterable<hstring> const& supportedMethodIds, param::hstring const& jsonData) const
{
    Windows::ApplicationModel::Payments::PaymentMethodData result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Payments::IPaymentMethodDataFactory)->CreateWithJsonData(get_abi(supportedMethodIds), get_abi(jsonData), put_abi(result)));
    return result;
}

template <typename D> Windows::ApplicationModel::Payments::PaymentOptionPresence consume_Windows_ApplicationModel_Payments_IPaymentOptions<D>::RequestPayerEmail() const
{
    Windows::ApplicationModel::Payments::PaymentOptionPresence value{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Payments::IPaymentOptions)->get_RequestPayerEmail(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_ApplicationModel_Payments_IPaymentOptions<D>::RequestPayerEmail(Windows::ApplicationModel::Payments::PaymentOptionPresence const& value) const
{
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Payments::IPaymentOptions)->put_RequestPayerEmail(get_abi(value)));
}

template <typename D> Windows::ApplicationModel::Payments::PaymentOptionPresence consume_Windows_ApplicationModel_Payments_IPaymentOptions<D>::RequestPayerName() const
{
    Windows::ApplicationModel::Payments::PaymentOptionPresence value{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Payments::IPaymentOptions)->get_RequestPayerName(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_ApplicationModel_Payments_IPaymentOptions<D>::RequestPayerName(Windows::ApplicationModel::Payments::PaymentOptionPresence const& value) const
{
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Payments::IPaymentOptions)->put_RequestPayerName(get_abi(value)));
}

template <typename D> Windows::ApplicationModel::Payments::PaymentOptionPresence consume_Windows_ApplicationModel_Payments_IPaymentOptions<D>::RequestPayerPhoneNumber() const
{
    Windows::ApplicationModel::Payments::PaymentOptionPresence value{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Payments::IPaymentOptions)->get_RequestPayerPhoneNumber(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_ApplicationModel_Payments_IPaymentOptions<D>::RequestPayerPhoneNumber(Windows::ApplicationModel::Payments::PaymentOptionPresence const& value) const
{
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Payments::IPaymentOptions)->put_RequestPayerPhoneNumber(get_abi(value)));
}

template <typename D> bool consume_Windows_ApplicationModel_Payments_IPaymentOptions<D>::RequestShipping() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Payments::IPaymentOptions)->get_RequestShipping(&value));
    return value;
}

template <typename D> void consume_Windows_ApplicationModel_Payments_IPaymentOptions<D>::RequestShipping(bool value) const
{
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Payments::IPaymentOptions)->put_RequestShipping(value));
}

template <typename D> Windows::ApplicationModel::Payments::PaymentShippingType consume_Windows_ApplicationModel_Payments_IPaymentOptions<D>::ShippingType() const
{
    Windows::ApplicationModel::Payments::PaymentShippingType value{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Payments::IPaymentOptions)->get_ShippingType(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_ApplicationModel_Payments_IPaymentOptions<D>::ShippingType(Windows::ApplicationModel::Payments::PaymentShippingType const& value) const
{
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Payments::IPaymentOptions)->put_ShippingType(get_abi(value)));
}

template <typename D> Windows::ApplicationModel::Payments::PaymentMerchantInfo consume_Windows_ApplicationModel_Payments_IPaymentRequest<D>::MerchantInfo() const
{
    Windows::ApplicationModel::Payments::PaymentMerchantInfo value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Payments::IPaymentRequest)->get_MerchantInfo(put_abi(value)));
    return value;
}

template <typename D> Windows::ApplicationModel::Payments::PaymentDetails consume_Windows_ApplicationModel_Payments_IPaymentRequest<D>::Details() const
{
    Windows::ApplicationModel::Payments::PaymentDetails value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Payments::IPaymentRequest)->get_Details(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::Collections::IVectorView<Windows::ApplicationModel::Payments::PaymentMethodData> consume_Windows_ApplicationModel_Payments_IPaymentRequest<D>::MethodData() const
{
    Windows::Foundation::Collections::IVectorView<Windows::ApplicationModel::Payments::PaymentMethodData> value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Payments::IPaymentRequest)->get_MethodData(put_abi(value)));
    return value;
}

template <typename D> Windows::ApplicationModel::Payments::PaymentOptions consume_Windows_ApplicationModel_Payments_IPaymentRequest<D>::Options() const
{
    Windows::ApplicationModel::Payments::PaymentOptions value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Payments::IPaymentRequest)->get_Options(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_ApplicationModel_Payments_IPaymentRequest2<D>::Id() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Payments::IPaymentRequest2)->get_Id(put_abi(value)));
    return value;
}

template <typename D> Windows::ApplicationModel::Payments::PaymentRequestChangeKind consume_Windows_ApplicationModel_Payments_IPaymentRequestChangedArgs<D>::ChangeKind() const
{
    Windows::ApplicationModel::Payments::PaymentRequestChangeKind value{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Payments::IPaymentRequestChangedArgs)->get_ChangeKind(put_abi(value)));
    return value;
}

template <typename D> Windows::ApplicationModel::Payments::PaymentAddress consume_Windows_ApplicationModel_Payments_IPaymentRequestChangedArgs<D>::ShippingAddress() const
{
    Windows::ApplicationModel::Payments::PaymentAddress value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Payments::IPaymentRequestChangedArgs)->get_ShippingAddress(put_abi(value)));
    return value;
}

template <typename D> Windows::ApplicationModel::Payments::PaymentShippingOption consume_Windows_ApplicationModel_Payments_IPaymentRequestChangedArgs<D>::SelectedShippingOption() const
{
    Windows::ApplicationModel::Payments::PaymentShippingOption value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Payments::IPaymentRequestChangedArgs)->get_SelectedShippingOption(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_ApplicationModel_Payments_IPaymentRequestChangedArgs<D>::Acknowledge(Windows::ApplicationModel::Payments::PaymentRequestChangedResult const& changeResult) const
{
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Payments::IPaymentRequestChangedArgs)->Acknowledge(get_abi(changeResult)));
}

template <typename D> bool consume_Windows_ApplicationModel_Payments_IPaymentRequestChangedResult<D>::ChangeAcceptedByMerchant() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Payments::IPaymentRequestChangedResult)->get_ChangeAcceptedByMerchant(&value));
    return value;
}

template <typename D> void consume_Windows_ApplicationModel_Payments_IPaymentRequestChangedResult<D>::ChangeAcceptedByMerchant(bool value) const
{
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Payments::IPaymentRequestChangedResult)->put_ChangeAcceptedByMerchant(value));
}

template <typename D> hstring consume_Windows_ApplicationModel_Payments_IPaymentRequestChangedResult<D>::Message() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Payments::IPaymentRequestChangedResult)->get_Message(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_ApplicationModel_Payments_IPaymentRequestChangedResult<D>::Message(param::hstring const& value) const
{
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Payments::IPaymentRequestChangedResult)->put_Message(get_abi(value)));
}

template <typename D> Windows::ApplicationModel::Payments::PaymentDetails consume_Windows_ApplicationModel_Payments_IPaymentRequestChangedResult<D>::UpdatedPaymentDetails() const
{
    Windows::ApplicationModel::Payments::PaymentDetails value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Payments::IPaymentRequestChangedResult)->get_UpdatedPaymentDetails(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_ApplicationModel_Payments_IPaymentRequestChangedResult<D>::UpdatedPaymentDetails(Windows::ApplicationModel::Payments::PaymentDetails const& value) const
{
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Payments::IPaymentRequestChangedResult)->put_UpdatedPaymentDetails(get_abi(value)));
}

template <typename D> Windows::ApplicationModel::Payments::PaymentRequestChangedResult consume_Windows_ApplicationModel_Payments_IPaymentRequestChangedResultFactory<D>::Create(bool changeAcceptedByMerchant) const
{
    Windows::ApplicationModel::Payments::PaymentRequestChangedResult result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Payments::IPaymentRequestChangedResultFactory)->Create(changeAcceptedByMerchant, put_abi(result)));
    return result;
}

template <typename D> Windows::ApplicationModel::Payments::PaymentRequestChangedResult consume_Windows_ApplicationModel_Payments_IPaymentRequestChangedResultFactory<D>::CreateWithPaymentDetails(bool changeAcceptedByMerchant, Windows::ApplicationModel::Payments::PaymentDetails const& updatedPaymentDetails) const
{
    Windows::ApplicationModel::Payments::PaymentRequestChangedResult result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Payments::IPaymentRequestChangedResultFactory)->CreateWithPaymentDetails(changeAcceptedByMerchant, get_abi(updatedPaymentDetails), put_abi(result)));
    return result;
}

template <typename D> Windows::ApplicationModel::Payments::PaymentRequest consume_Windows_ApplicationModel_Payments_IPaymentRequestFactory<D>::Create(Windows::ApplicationModel::Payments::PaymentDetails const& details, param::iterable<Windows::ApplicationModel::Payments::PaymentMethodData> const& methodData) const
{
    Windows::ApplicationModel::Payments::PaymentRequest result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Payments::IPaymentRequestFactory)->Create(get_abi(details), get_abi(methodData), put_abi(result)));
    return result;
}

template <typename D> Windows::ApplicationModel::Payments::PaymentRequest consume_Windows_ApplicationModel_Payments_IPaymentRequestFactory<D>::CreateWithMerchantInfo(Windows::ApplicationModel::Payments::PaymentDetails const& details, param::iterable<Windows::ApplicationModel::Payments::PaymentMethodData> const& methodData, Windows::ApplicationModel::Payments::PaymentMerchantInfo const& merchantInfo) const
{
    Windows::ApplicationModel::Payments::PaymentRequest result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Payments::IPaymentRequestFactory)->CreateWithMerchantInfo(get_abi(details), get_abi(methodData), get_abi(merchantInfo), put_abi(result)));
    return result;
}

template <typename D> Windows::ApplicationModel::Payments::PaymentRequest consume_Windows_ApplicationModel_Payments_IPaymentRequestFactory<D>::CreateWithMerchantInfoAndOptions(Windows::ApplicationModel::Payments::PaymentDetails const& details, param::iterable<Windows::ApplicationModel::Payments::PaymentMethodData> const& methodData, Windows::ApplicationModel::Payments::PaymentMerchantInfo const& merchantInfo, Windows::ApplicationModel::Payments::PaymentOptions const& options) const
{
    Windows::ApplicationModel::Payments::PaymentRequest result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Payments::IPaymentRequestFactory)->CreateWithMerchantInfoAndOptions(get_abi(details), get_abi(methodData), get_abi(merchantInfo), get_abi(options), put_abi(result)));
    return result;
}

template <typename D> Windows::ApplicationModel::Payments::PaymentRequest consume_Windows_ApplicationModel_Payments_IPaymentRequestFactory2<D>::CreateWithMerchantInfoOptionsAndId(Windows::ApplicationModel::Payments::PaymentDetails const& details, param::iterable<Windows::ApplicationModel::Payments::PaymentMethodData> const& methodData, Windows::ApplicationModel::Payments::PaymentMerchantInfo const& merchantInfo, Windows::ApplicationModel::Payments::PaymentOptions const& options, param::hstring const& id) const
{
    Windows::ApplicationModel::Payments::PaymentRequest result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Payments::IPaymentRequestFactory2)->CreateWithMerchantInfoOptionsAndId(get_abi(details), get_abi(methodData), get_abi(merchantInfo), get_abi(options), get_abi(id), put_abi(result)));
    return result;
}

template <typename D> Windows::ApplicationModel::Payments::PaymentRequestStatus consume_Windows_ApplicationModel_Payments_IPaymentRequestSubmitResult<D>::Status() const
{
    Windows::ApplicationModel::Payments::PaymentRequestStatus value{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Payments::IPaymentRequestSubmitResult)->get_Status(put_abi(value)));
    return value;
}

template <typename D> Windows::ApplicationModel::Payments::PaymentResponse consume_Windows_ApplicationModel_Payments_IPaymentRequestSubmitResult<D>::Response() const
{
    Windows::ApplicationModel::Payments::PaymentResponse value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Payments::IPaymentRequestSubmitResult)->get_Response(put_abi(value)));
    return value;
}

template <typename D> Windows::ApplicationModel::Payments::PaymentToken consume_Windows_ApplicationModel_Payments_IPaymentResponse<D>::PaymentToken() const
{
    Windows::ApplicationModel::Payments::PaymentToken value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Payments::IPaymentResponse)->get_PaymentToken(put_abi(value)));
    return value;
}

template <typename D> Windows::ApplicationModel::Payments::PaymentShippingOption consume_Windows_ApplicationModel_Payments_IPaymentResponse<D>::ShippingOption() const
{
    Windows::ApplicationModel::Payments::PaymentShippingOption value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Payments::IPaymentResponse)->get_ShippingOption(put_abi(value)));
    return value;
}

template <typename D> Windows::ApplicationModel::Payments::PaymentAddress consume_Windows_ApplicationModel_Payments_IPaymentResponse<D>::ShippingAddress() const
{
    Windows::ApplicationModel::Payments::PaymentAddress value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Payments::IPaymentResponse)->get_ShippingAddress(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_ApplicationModel_Payments_IPaymentResponse<D>::PayerEmail() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Payments::IPaymentResponse)->get_PayerEmail(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_ApplicationModel_Payments_IPaymentResponse<D>::PayerName() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Payments::IPaymentResponse)->get_PayerName(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_ApplicationModel_Payments_IPaymentResponse<D>::PayerPhoneNumber() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Payments::IPaymentResponse)->get_PayerPhoneNumber(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::IAsyncAction consume_Windows_ApplicationModel_Payments_IPaymentResponse<D>::CompleteAsync(Windows::ApplicationModel::Payments::PaymentRequestCompletionStatus const& status) const
{
    Windows::Foundation::IAsyncAction result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Payments::IPaymentResponse)->CompleteAsync(get_abi(status), put_abi(result)));
    return result;
}

template <typename D> hstring consume_Windows_ApplicationModel_Payments_IPaymentShippingOption<D>::Label() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Payments::IPaymentShippingOption)->get_Label(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_ApplicationModel_Payments_IPaymentShippingOption<D>::Label(param::hstring const& value) const
{
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Payments::IPaymentShippingOption)->put_Label(get_abi(value)));
}

template <typename D> Windows::ApplicationModel::Payments::PaymentCurrencyAmount consume_Windows_ApplicationModel_Payments_IPaymentShippingOption<D>::Amount() const
{
    Windows::ApplicationModel::Payments::PaymentCurrencyAmount value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Payments::IPaymentShippingOption)->get_Amount(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_ApplicationModel_Payments_IPaymentShippingOption<D>::Amount(Windows::ApplicationModel::Payments::PaymentCurrencyAmount const& value) const
{
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Payments::IPaymentShippingOption)->put_Amount(get_abi(value)));
}

template <typename D> hstring consume_Windows_ApplicationModel_Payments_IPaymentShippingOption<D>::Tag() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Payments::IPaymentShippingOption)->get_Tag(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_ApplicationModel_Payments_IPaymentShippingOption<D>::Tag(param::hstring const& value) const
{
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Payments::IPaymentShippingOption)->put_Tag(get_abi(value)));
}

template <typename D> bool consume_Windows_ApplicationModel_Payments_IPaymentShippingOption<D>::IsSelected() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Payments::IPaymentShippingOption)->get_IsSelected(&value));
    return value;
}

template <typename D> void consume_Windows_ApplicationModel_Payments_IPaymentShippingOption<D>::IsSelected(bool value) const
{
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Payments::IPaymentShippingOption)->put_IsSelected(value));
}

template <typename D> Windows::ApplicationModel::Payments::PaymentShippingOption consume_Windows_ApplicationModel_Payments_IPaymentShippingOptionFactory<D>::Create(param::hstring const& label, Windows::ApplicationModel::Payments::PaymentCurrencyAmount const& amount) const
{
    Windows::ApplicationModel::Payments::PaymentShippingOption result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Payments::IPaymentShippingOptionFactory)->Create(get_abi(label), get_abi(amount), put_abi(result)));
    return result;
}

template <typename D> Windows::ApplicationModel::Payments::PaymentShippingOption consume_Windows_ApplicationModel_Payments_IPaymentShippingOptionFactory<D>::CreateWithSelected(param::hstring const& label, Windows::ApplicationModel::Payments::PaymentCurrencyAmount const& amount, bool selected) const
{
    Windows::ApplicationModel::Payments::PaymentShippingOption result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Payments::IPaymentShippingOptionFactory)->CreateWithSelected(get_abi(label), get_abi(amount), selected, put_abi(result)));
    return result;
}

template <typename D> Windows::ApplicationModel::Payments::PaymentShippingOption consume_Windows_ApplicationModel_Payments_IPaymentShippingOptionFactory<D>::CreateWithSelectedAndTag(param::hstring const& label, Windows::ApplicationModel::Payments::PaymentCurrencyAmount const& amount, bool selected, param::hstring const& tag) const
{
    Windows::ApplicationModel::Payments::PaymentShippingOption result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Payments::IPaymentShippingOptionFactory)->CreateWithSelectedAndTag(get_abi(label), get_abi(amount), selected, get_abi(tag), put_abi(result)));
    return result;
}

template <typename D> hstring consume_Windows_ApplicationModel_Payments_IPaymentToken<D>::PaymentMethodId() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Payments::IPaymentToken)->get_PaymentMethodId(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_ApplicationModel_Payments_IPaymentToken<D>::JsonDetails() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Payments::IPaymentToken)->get_JsonDetails(put_abi(value)));
    return value;
}

template <typename D> Windows::ApplicationModel::Payments::PaymentToken consume_Windows_ApplicationModel_Payments_IPaymentTokenFactory<D>::Create(param::hstring const& paymentMethodId) const
{
    Windows::ApplicationModel::Payments::PaymentToken result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Payments::IPaymentTokenFactory)->Create(get_abi(paymentMethodId), put_abi(result)));
    return result;
}

template <typename D> Windows::ApplicationModel::Payments::PaymentToken consume_Windows_ApplicationModel_Payments_IPaymentTokenFactory<D>::CreateWithJsonDetails(param::hstring const& paymentMethodId, param::hstring const& jsonDetails) const
{
    Windows::ApplicationModel::Payments::PaymentToken result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Payments::IPaymentTokenFactory)->CreateWithJsonDetails(get_abi(paymentMethodId), get_abi(jsonDetails), put_abi(result)));
    return result;
}

template <> struct delegate<Windows::ApplicationModel::Payments::PaymentRequestChangedHandler>
{
    template <typename H>
    struct type : implements_delegate<Windows::ApplicationModel::Payments::PaymentRequestChangedHandler, H>
    {
        type(H&& handler) : implements_delegate<Windows::ApplicationModel::Payments::PaymentRequestChangedHandler, H>(std::forward<H>(handler)) {}

        int32_t WINRT_CALL Invoke(void* paymentRequest, void* args) noexcept final
        {
            try
            {
                (*this)(*reinterpret_cast<Windows::ApplicationModel::Payments::PaymentRequest const*>(&paymentRequest), *reinterpret_cast<Windows::ApplicationModel::Payments::PaymentRequestChangedArgs const*>(&args));
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
struct produce<D, Windows::ApplicationModel::Payments::IPaymentAddress> : produce_base<D, Windows::ApplicationModel::Payments::IPaymentAddress>
{
    int32_t WINRT_CALL get_Country(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Country, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().Country());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_Country(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Country, WINRT_WRAP(void), hstring const&);
            this->shim().Country(*reinterpret_cast<hstring const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_AddressLines(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(AddressLines, WINRT_WRAP(Windows::Foundation::Collections::IVectorView<hstring>));
            *value = detach_from<Windows::Foundation::Collections::IVectorView<hstring>>(this->shim().AddressLines());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_AddressLines(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(AddressLines, WINRT_WRAP(void), Windows::Foundation::Collections::IVectorView<hstring> const&);
            this->shim().AddressLines(*reinterpret_cast<Windows::Foundation::Collections::IVectorView<hstring> const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Region(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Region, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().Region());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_Region(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Region, WINRT_WRAP(void), hstring const&);
            this->shim().Region(*reinterpret_cast<hstring const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_City(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(City, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().City());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_City(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(City, WINRT_WRAP(void), hstring const&);
            this->shim().City(*reinterpret_cast<hstring const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_DependentLocality(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(DependentLocality, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().DependentLocality());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_DependentLocality(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(DependentLocality, WINRT_WRAP(void), hstring const&);
            this->shim().DependentLocality(*reinterpret_cast<hstring const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_PostalCode(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(PostalCode, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().PostalCode());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_PostalCode(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(PostalCode, WINRT_WRAP(void), hstring const&);
            this->shim().PostalCode(*reinterpret_cast<hstring const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_SortingCode(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SortingCode, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().SortingCode());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_SortingCode(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SortingCode, WINRT_WRAP(void), hstring const&);
            this->shim().SortingCode(*reinterpret_cast<hstring const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_LanguageCode(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(LanguageCode, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().LanguageCode());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_LanguageCode(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(LanguageCode, WINRT_WRAP(void), hstring const&);
            this->shim().LanguageCode(*reinterpret_cast<hstring const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Organization(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Organization, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().Organization());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_Organization(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Organization, WINRT_WRAP(void), hstring const&);
            this->shim().Organization(*reinterpret_cast<hstring const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Recipient(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Recipient, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().Recipient());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_Recipient(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Recipient, WINRT_WRAP(void), hstring const&);
            this->shim().Recipient(*reinterpret_cast<hstring const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_PhoneNumber(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(PhoneNumber, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().PhoneNumber());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_PhoneNumber(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(PhoneNumber, WINRT_WRAP(void), hstring const&);
            this->shim().PhoneNumber(*reinterpret_cast<hstring const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Properties(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Properties, WINRT_WRAP(Windows::Foundation::Collections::ValueSet));
            *value = detach_from<Windows::Foundation::Collections::ValueSet>(this->shim().Properties());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::ApplicationModel::Payments::IPaymentCanMakePaymentResult> : produce_base<D, Windows::ApplicationModel::Payments::IPaymentCanMakePaymentResult>
{
    int32_t WINRT_CALL get_Status(Windows::ApplicationModel::Payments::PaymentCanMakePaymentResultStatus* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Status, WINRT_WRAP(Windows::ApplicationModel::Payments::PaymentCanMakePaymentResultStatus));
            *value = detach_from<Windows::ApplicationModel::Payments::PaymentCanMakePaymentResultStatus>(this->shim().Status());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::ApplicationModel::Payments::IPaymentCanMakePaymentResultFactory> : produce_base<D, Windows::ApplicationModel::Payments::IPaymentCanMakePaymentResultFactory>
{
    int32_t WINRT_CALL Create(Windows::ApplicationModel::Payments::PaymentCanMakePaymentResultStatus value, void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Create, WINRT_WRAP(Windows::ApplicationModel::Payments::PaymentCanMakePaymentResult), Windows::ApplicationModel::Payments::PaymentCanMakePaymentResultStatus const&);
            *result = detach_from<Windows::ApplicationModel::Payments::PaymentCanMakePaymentResult>(this->shim().Create(*reinterpret_cast<Windows::ApplicationModel::Payments::PaymentCanMakePaymentResultStatus const*>(&value)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::ApplicationModel::Payments::IPaymentCurrencyAmount> : produce_base<D, Windows::ApplicationModel::Payments::IPaymentCurrencyAmount>
{
    int32_t WINRT_CALL get_Currency(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Currency, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().Currency());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_Currency(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Currency, WINRT_WRAP(void), hstring const&);
            this->shim().Currency(*reinterpret_cast<hstring const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_CurrencySystem(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CurrencySystem, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().CurrencySystem());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_CurrencySystem(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CurrencySystem, WINRT_WRAP(void), hstring const&);
            this->shim().CurrencySystem(*reinterpret_cast<hstring const*>(&value));
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
};

template <typename D>
struct produce<D, Windows::ApplicationModel::Payments::IPaymentCurrencyAmountFactory> : produce_base<D, Windows::ApplicationModel::Payments::IPaymentCurrencyAmountFactory>
{
    int32_t WINRT_CALL Create(void* value, void* currency, void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Create, WINRT_WRAP(Windows::ApplicationModel::Payments::PaymentCurrencyAmount), hstring const&, hstring const&);
            *result = detach_from<Windows::ApplicationModel::Payments::PaymentCurrencyAmount>(this->shim().Create(*reinterpret_cast<hstring const*>(&value), *reinterpret_cast<hstring const*>(&currency)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL CreateWithCurrencySystem(void* value, void* currency, void* currencySystem, void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CreateWithCurrencySystem, WINRT_WRAP(Windows::ApplicationModel::Payments::PaymentCurrencyAmount), hstring const&, hstring const&, hstring const&);
            *result = detach_from<Windows::ApplicationModel::Payments::PaymentCurrencyAmount>(this->shim().CreateWithCurrencySystem(*reinterpret_cast<hstring const*>(&value), *reinterpret_cast<hstring const*>(&currency), *reinterpret_cast<hstring const*>(&currencySystem)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::ApplicationModel::Payments::IPaymentDetails> : produce_base<D, Windows::ApplicationModel::Payments::IPaymentDetails>
{
    int32_t WINRT_CALL get_Total(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Total, WINRT_WRAP(Windows::ApplicationModel::Payments::PaymentItem));
            *value = detach_from<Windows::ApplicationModel::Payments::PaymentItem>(this->shim().Total());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_Total(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Total, WINRT_WRAP(void), Windows::ApplicationModel::Payments::PaymentItem const&);
            this->shim().Total(*reinterpret_cast<Windows::ApplicationModel::Payments::PaymentItem const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_DisplayItems(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(DisplayItems, WINRT_WRAP(Windows::Foundation::Collections::IVectorView<Windows::ApplicationModel::Payments::PaymentItem>));
            *value = detach_from<Windows::Foundation::Collections::IVectorView<Windows::ApplicationModel::Payments::PaymentItem>>(this->shim().DisplayItems());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_DisplayItems(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(DisplayItems, WINRT_WRAP(void), Windows::Foundation::Collections::IVectorView<Windows::ApplicationModel::Payments::PaymentItem> const&);
            this->shim().DisplayItems(*reinterpret_cast<Windows::Foundation::Collections::IVectorView<Windows::ApplicationModel::Payments::PaymentItem> const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_ShippingOptions(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ShippingOptions, WINRT_WRAP(Windows::Foundation::Collections::IVectorView<Windows::ApplicationModel::Payments::PaymentShippingOption>));
            *value = detach_from<Windows::Foundation::Collections::IVectorView<Windows::ApplicationModel::Payments::PaymentShippingOption>>(this->shim().ShippingOptions());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_ShippingOptions(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ShippingOptions, WINRT_WRAP(void), Windows::Foundation::Collections::IVectorView<Windows::ApplicationModel::Payments::PaymentShippingOption> const&);
            this->shim().ShippingOptions(*reinterpret_cast<Windows::Foundation::Collections::IVectorView<Windows::ApplicationModel::Payments::PaymentShippingOption> const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Modifiers(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Modifiers, WINRT_WRAP(Windows::Foundation::Collections::IVectorView<Windows::ApplicationModel::Payments::PaymentDetailsModifier>));
            *value = detach_from<Windows::Foundation::Collections::IVectorView<Windows::ApplicationModel::Payments::PaymentDetailsModifier>>(this->shim().Modifiers());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_Modifiers(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Modifiers, WINRT_WRAP(void), Windows::Foundation::Collections::IVectorView<Windows::ApplicationModel::Payments::PaymentDetailsModifier> const&);
            this->shim().Modifiers(*reinterpret_cast<Windows::Foundation::Collections::IVectorView<Windows::ApplicationModel::Payments::PaymentDetailsModifier> const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::ApplicationModel::Payments::IPaymentDetailsFactory> : produce_base<D, Windows::ApplicationModel::Payments::IPaymentDetailsFactory>
{
    int32_t WINRT_CALL Create(void* total, void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Create, WINRT_WRAP(Windows::ApplicationModel::Payments::PaymentDetails), Windows::ApplicationModel::Payments::PaymentItem const&);
            *result = detach_from<Windows::ApplicationModel::Payments::PaymentDetails>(this->shim().Create(*reinterpret_cast<Windows::ApplicationModel::Payments::PaymentItem const*>(&total)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL CreateWithDisplayItems(void* total, void* displayItems, void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CreateWithDisplayItems, WINRT_WRAP(Windows::ApplicationModel::Payments::PaymentDetails), Windows::ApplicationModel::Payments::PaymentItem const&, Windows::Foundation::Collections::IIterable<Windows::ApplicationModel::Payments::PaymentItem> const&);
            *result = detach_from<Windows::ApplicationModel::Payments::PaymentDetails>(this->shim().CreateWithDisplayItems(*reinterpret_cast<Windows::ApplicationModel::Payments::PaymentItem const*>(&total), *reinterpret_cast<Windows::Foundation::Collections::IIterable<Windows::ApplicationModel::Payments::PaymentItem> const*>(&displayItems)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::ApplicationModel::Payments::IPaymentDetailsModifier> : produce_base<D, Windows::ApplicationModel::Payments::IPaymentDetailsModifier>
{
    int32_t WINRT_CALL get_JsonData(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(JsonData, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().JsonData());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_SupportedMethodIds(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SupportedMethodIds, WINRT_WRAP(Windows::Foundation::Collections::IVectorView<hstring>));
            *value = detach_from<Windows::Foundation::Collections::IVectorView<hstring>>(this->shim().SupportedMethodIds());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Total(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Total, WINRT_WRAP(Windows::ApplicationModel::Payments::PaymentItem));
            *value = detach_from<Windows::ApplicationModel::Payments::PaymentItem>(this->shim().Total());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_AdditionalDisplayItems(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(AdditionalDisplayItems, WINRT_WRAP(Windows::Foundation::Collections::IVectorView<Windows::ApplicationModel::Payments::PaymentItem>));
            *value = detach_from<Windows::Foundation::Collections::IVectorView<Windows::ApplicationModel::Payments::PaymentItem>>(this->shim().AdditionalDisplayItems());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::ApplicationModel::Payments::IPaymentDetailsModifierFactory> : produce_base<D, Windows::ApplicationModel::Payments::IPaymentDetailsModifierFactory>
{
    int32_t WINRT_CALL Create(void* supportedMethodIds, void* total, void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Create, WINRT_WRAP(Windows::ApplicationModel::Payments::PaymentDetailsModifier), Windows::Foundation::Collections::IIterable<hstring> const&, Windows::ApplicationModel::Payments::PaymentItem const&);
            *result = detach_from<Windows::ApplicationModel::Payments::PaymentDetailsModifier>(this->shim().Create(*reinterpret_cast<Windows::Foundation::Collections::IIterable<hstring> const*>(&supportedMethodIds), *reinterpret_cast<Windows::ApplicationModel::Payments::PaymentItem const*>(&total)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL CreateWithAdditionalDisplayItems(void* supportedMethodIds, void* total, void* additionalDisplayItems, void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CreateWithAdditionalDisplayItems, WINRT_WRAP(Windows::ApplicationModel::Payments::PaymentDetailsModifier), Windows::Foundation::Collections::IIterable<hstring> const&, Windows::ApplicationModel::Payments::PaymentItem const&, Windows::Foundation::Collections::IIterable<Windows::ApplicationModel::Payments::PaymentItem> const&);
            *result = detach_from<Windows::ApplicationModel::Payments::PaymentDetailsModifier>(this->shim().CreateWithAdditionalDisplayItems(*reinterpret_cast<Windows::Foundation::Collections::IIterable<hstring> const*>(&supportedMethodIds), *reinterpret_cast<Windows::ApplicationModel::Payments::PaymentItem const*>(&total), *reinterpret_cast<Windows::Foundation::Collections::IIterable<Windows::ApplicationModel::Payments::PaymentItem> const*>(&additionalDisplayItems)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL CreateWithAdditionalDisplayItemsAndJsonData(void* supportedMethodIds, void* total, void* additionalDisplayItems, void* jsonData, void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CreateWithAdditionalDisplayItemsAndJsonData, WINRT_WRAP(Windows::ApplicationModel::Payments::PaymentDetailsModifier), Windows::Foundation::Collections::IIterable<hstring> const&, Windows::ApplicationModel::Payments::PaymentItem const&, Windows::Foundation::Collections::IIterable<Windows::ApplicationModel::Payments::PaymentItem> const&, hstring const&);
            *result = detach_from<Windows::ApplicationModel::Payments::PaymentDetailsModifier>(this->shim().CreateWithAdditionalDisplayItemsAndJsonData(*reinterpret_cast<Windows::Foundation::Collections::IIterable<hstring> const*>(&supportedMethodIds), *reinterpret_cast<Windows::ApplicationModel::Payments::PaymentItem const*>(&total), *reinterpret_cast<Windows::Foundation::Collections::IIterable<Windows::ApplicationModel::Payments::PaymentItem> const*>(&additionalDisplayItems), *reinterpret_cast<hstring const*>(&jsonData)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::ApplicationModel::Payments::IPaymentItem> : produce_base<D, Windows::ApplicationModel::Payments::IPaymentItem>
{
    int32_t WINRT_CALL get_Label(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Label, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().Label());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_Label(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Label, WINRT_WRAP(void), hstring const&);
            this->shim().Label(*reinterpret_cast<hstring const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Amount(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Amount, WINRT_WRAP(Windows::ApplicationModel::Payments::PaymentCurrencyAmount));
            *value = detach_from<Windows::ApplicationModel::Payments::PaymentCurrencyAmount>(this->shim().Amount());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_Amount(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Amount, WINRT_WRAP(void), Windows::ApplicationModel::Payments::PaymentCurrencyAmount const&);
            this->shim().Amount(*reinterpret_cast<Windows::ApplicationModel::Payments::PaymentCurrencyAmount const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Pending(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Pending, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().Pending());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_Pending(bool value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Pending, WINRT_WRAP(void), bool);
            this->shim().Pending(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::ApplicationModel::Payments::IPaymentItemFactory> : produce_base<D, Windows::ApplicationModel::Payments::IPaymentItemFactory>
{
    int32_t WINRT_CALL Create(void* label, void* amount, void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Create, WINRT_WRAP(Windows::ApplicationModel::Payments::PaymentItem), hstring const&, Windows::ApplicationModel::Payments::PaymentCurrencyAmount const&);
            *result = detach_from<Windows::ApplicationModel::Payments::PaymentItem>(this->shim().Create(*reinterpret_cast<hstring const*>(&label), *reinterpret_cast<Windows::ApplicationModel::Payments::PaymentCurrencyAmount const*>(&amount)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::ApplicationModel::Payments::IPaymentMediator> : produce_base<D, Windows::ApplicationModel::Payments::IPaymentMediator>
{
    int32_t WINRT_CALL GetSupportedMethodIdsAsync(void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetSupportedMethodIdsAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<Windows::Foundation::Collections::IVectorView<hstring>>));
            *result = detach_from<Windows::Foundation::IAsyncOperation<Windows::Foundation::Collections::IVectorView<hstring>>>(this->shim().GetSupportedMethodIdsAsync());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL SubmitPaymentRequestAsync(void* paymentRequest, void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SubmitPaymentRequestAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<Windows::ApplicationModel::Payments::PaymentRequestSubmitResult>), Windows::ApplicationModel::Payments::PaymentRequest const);
            *result = detach_from<Windows::Foundation::IAsyncOperation<Windows::ApplicationModel::Payments::PaymentRequestSubmitResult>>(this->shim().SubmitPaymentRequestAsync(*reinterpret_cast<Windows::ApplicationModel::Payments::PaymentRequest const*>(&paymentRequest)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL SubmitPaymentRequestWithChangeHandlerAsync(void* paymentRequest, void* changeHandler, void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SubmitPaymentRequestAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<Windows::ApplicationModel::Payments::PaymentRequestSubmitResult>), Windows::ApplicationModel::Payments::PaymentRequest const, Windows::ApplicationModel::Payments::PaymentRequestChangedHandler const);
            *result = detach_from<Windows::Foundation::IAsyncOperation<Windows::ApplicationModel::Payments::PaymentRequestSubmitResult>>(this->shim().SubmitPaymentRequestAsync(*reinterpret_cast<Windows::ApplicationModel::Payments::PaymentRequest const*>(&paymentRequest), *reinterpret_cast<Windows::ApplicationModel::Payments::PaymentRequestChangedHandler const*>(&changeHandler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::ApplicationModel::Payments::IPaymentMediator2> : produce_base<D, Windows::ApplicationModel::Payments::IPaymentMediator2>
{
    int32_t WINRT_CALL CanMakePaymentAsync(void* paymentRequest, void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CanMakePaymentAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<Windows::ApplicationModel::Payments::PaymentCanMakePaymentResult>), Windows::ApplicationModel::Payments::PaymentRequest const);
            *result = detach_from<Windows::Foundation::IAsyncOperation<Windows::ApplicationModel::Payments::PaymentCanMakePaymentResult>>(this->shim().CanMakePaymentAsync(*reinterpret_cast<Windows::ApplicationModel::Payments::PaymentRequest const*>(&paymentRequest)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::ApplicationModel::Payments::IPaymentMerchantInfo> : produce_base<D, Windows::ApplicationModel::Payments::IPaymentMerchantInfo>
{
    int32_t WINRT_CALL get_PackageFullName(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(PackageFullName, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().PackageFullName());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Uri(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Uri, WINRT_WRAP(Windows::Foundation::Uri));
            *value = detach_from<Windows::Foundation::Uri>(this->shim().Uri());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::ApplicationModel::Payments::IPaymentMerchantInfoFactory> : produce_base<D, Windows::ApplicationModel::Payments::IPaymentMerchantInfoFactory>
{
    int32_t WINRT_CALL Create(void* uri, void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Create, WINRT_WRAP(Windows::ApplicationModel::Payments::PaymentMerchantInfo), Windows::Foundation::Uri const&);
            *result = detach_from<Windows::ApplicationModel::Payments::PaymentMerchantInfo>(this->shim().Create(*reinterpret_cast<Windows::Foundation::Uri const*>(&uri)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::ApplicationModel::Payments::IPaymentMethodData> : produce_base<D, Windows::ApplicationModel::Payments::IPaymentMethodData>
{
    int32_t WINRT_CALL get_SupportedMethodIds(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SupportedMethodIds, WINRT_WRAP(Windows::Foundation::Collections::IVectorView<hstring>));
            *value = detach_from<Windows::Foundation::Collections::IVectorView<hstring>>(this->shim().SupportedMethodIds());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_JsonData(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(JsonData, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().JsonData());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::ApplicationModel::Payments::IPaymentMethodDataFactory> : produce_base<D, Windows::ApplicationModel::Payments::IPaymentMethodDataFactory>
{
    int32_t WINRT_CALL Create(void* supportedMethodIds, void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Create, WINRT_WRAP(Windows::ApplicationModel::Payments::PaymentMethodData), Windows::Foundation::Collections::IIterable<hstring> const&);
            *result = detach_from<Windows::ApplicationModel::Payments::PaymentMethodData>(this->shim().Create(*reinterpret_cast<Windows::Foundation::Collections::IIterable<hstring> const*>(&supportedMethodIds)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL CreateWithJsonData(void* supportedMethodIds, void* jsonData, void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CreateWithJsonData, WINRT_WRAP(Windows::ApplicationModel::Payments::PaymentMethodData), Windows::Foundation::Collections::IIterable<hstring> const&, hstring const&);
            *result = detach_from<Windows::ApplicationModel::Payments::PaymentMethodData>(this->shim().CreateWithJsonData(*reinterpret_cast<Windows::Foundation::Collections::IIterable<hstring> const*>(&supportedMethodIds), *reinterpret_cast<hstring const*>(&jsonData)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::ApplicationModel::Payments::IPaymentOptions> : produce_base<D, Windows::ApplicationModel::Payments::IPaymentOptions>
{
    int32_t WINRT_CALL get_RequestPayerEmail(Windows::ApplicationModel::Payments::PaymentOptionPresence* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(RequestPayerEmail, WINRT_WRAP(Windows::ApplicationModel::Payments::PaymentOptionPresence));
            *value = detach_from<Windows::ApplicationModel::Payments::PaymentOptionPresence>(this->shim().RequestPayerEmail());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_RequestPayerEmail(Windows::ApplicationModel::Payments::PaymentOptionPresence value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(RequestPayerEmail, WINRT_WRAP(void), Windows::ApplicationModel::Payments::PaymentOptionPresence const&);
            this->shim().RequestPayerEmail(*reinterpret_cast<Windows::ApplicationModel::Payments::PaymentOptionPresence const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_RequestPayerName(Windows::ApplicationModel::Payments::PaymentOptionPresence* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(RequestPayerName, WINRT_WRAP(Windows::ApplicationModel::Payments::PaymentOptionPresence));
            *value = detach_from<Windows::ApplicationModel::Payments::PaymentOptionPresence>(this->shim().RequestPayerName());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_RequestPayerName(Windows::ApplicationModel::Payments::PaymentOptionPresence value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(RequestPayerName, WINRT_WRAP(void), Windows::ApplicationModel::Payments::PaymentOptionPresence const&);
            this->shim().RequestPayerName(*reinterpret_cast<Windows::ApplicationModel::Payments::PaymentOptionPresence const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_RequestPayerPhoneNumber(Windows::ApplicationModel::Payments::PaymentOptionPresence* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(RequestPayerPhoneNumber, WINRT_WRAP(Windows::ApplicationModel::Payments::PaymentOptionPresence));
            *value = detach_from<Windows::ApplicationModel::Payments::PaymentOptionPresence>(this->shim().RequestPayerPhoneNumber());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_RequestPayerPhoneNumber(Windows::ApplicationModel::Payments::PaymentOptionPresence value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(RequestPayerPhoneNumber, WINRT_WRAP(void), Windows::ApplicationModel::Payments::PaymentOptionPresence const&);
            this->shim().RequestPayerPhoneNumber(*reinterpret_cast<Windows::ApplicationModel::Payments::PaymentOptionPresence const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_RequestShipping(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(RequestShipping, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().RequestShipping());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_RequestShipping(bool value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(RequestShipping, WINRT_WRAP(void), bool);
            this->shim().RequestShipping(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_ShippingType(Windows::ApplicationModel::Payments::PaymentShippingType* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ShippingType, WINRT_WRAP(Windows::ApplicationModel::Payments::PaymentShippingType));
            *value = detach_from<Windows::ApplicationModel::Payments::PaymentShippingType>(this->shim().ShippingType());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_ShippingType(Windows::ApplicationModel::Payments::PaymentShippingType value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ShippingType, WINRT_WRAP(void), Windows::ApplicationModel::Payments::PaymentShippingType const&);
            this->shim().ShippingType(*reinterpret_cast<Windows::ApplicationModel::Payments::PaymentShippingType const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::ApplicationModel::Payments::IPaymentRequest> : produce_base<D, Windows::ApplicationModel::Payments::IPaymentRequest>
{
    int32_t WINRT_CALL get_MerchantInfo(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(MerchantInfo, WINRT_WRAP(Windows::ApplicationModel::Payments::PaymentMerchantInfo));
            *value = detach_from<Windows::ApplicationModel::Payments::PaymentMerchantInfo>(this->shim().MerchantInfo());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Details(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Details, WINRT_WRAP(Windows::ApplicationModel::Payments::PaymentDetails));
            *value = detach_from<Windows::ApplicationModel::Payments::PaymentDetails>(this->shim().Details());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_MethodData(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(MethodData, WINRT_WRAP(Windows::Foundation::Collections::IVectorView<Windows::ApplicationModel::Payments::PaymentMethodData>));
            *value = detach_from<Windows::Foundation::Collections::IVectorView<Windows::ApplicationModel::Payments::PaymentMethodData>>(this->shim().MethodData());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Options(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Options, WINRT_WRAP(Windows::ApplicationModel::Payments::PaymentOptions));
            *value = detach_from<Windows::ApplicationModel::Payments::PaymentOptions>(this->shim().Options());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::ApplicationModel::Payments::IPaymentRequest2> : produce_base<D, Windows::ApplicationModel::Payments::IPaymentRequest2>
{
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
};

template <typename D>
struct produce<D, Windows::ApplicationModel::Payments::IPaymentRequestChangedArgs> : produce_base<D, Windows::ApplicationModel::Payments::IPaymentRequestChangedArgs>
{
    int32_t WINRT_CALL get_ChangeKind(Windows::ApplicationModel::Payments::PaymentRequestChangeKind* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ChangeKind, WINRT_WRAP(Windows::ApplicationModel::Payments::PaymentRequestChangeKind));
            *value = detach_from<Windows::ApplicationModel::Payments::PaymentRequestChangeKind>(this->shim().ChangeKind());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_ShippingAddress(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ShippingAddress, WINRT_WRAP(Windows::ApplicationModel::Payments::PaymentAddress));
            *value = detach_from<Windows::ApplicationModel::Payments::PaymentAddress>(this->shim().ShippingAddress());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_SelectedShippingOption(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SelectedShippingOption, WINRT_WRAP(Windows::ApplicationModel::Payments::PaymentShippingOption));
            *value = detach_from<Windows::ApplicationModel::Payments::PaymentShippingOption>(this->shim().SelectedShippingOption());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL Acknowledge(void* changeResult) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Acknowledge, WINRT_WRAP(void), Windows::ApplicationModel::Payments::PaymentRequestChangedResult const&);
            this->shim().Acknowledge(*reinterpret_cast<Windows::ApplicationModel::Payments::PaymentRequestChangedResult const*>(&changeResult));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::ApplicationModel::Payments::IPaymentRequestChangedResult> : produce_base<D, Windows::ApplicationModel::Payments::IPaymentRequestChangedResult>
{
    int32_t WINRT_CALL get_ChangeAcceptedByMerchant(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ChangeAcceptedByMerchant, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().ChangeAcceptedByMerchant());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_ChangeAcceptedByMerchant(bool value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ChangeAcceptedByMerchant, WINRT_WRAP(void), bool);
            this->shim().ChangeAcceptedByMerchant(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Message(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Message, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().Message());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_Message(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Message, WINRT_WRAP(void), hstring const&);
            this->shim().Message(*reinterpret_cast<hstring const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_UpdatedPaymentDetails(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(UpdatedPaymentDetails, WINRT_WRAP(Windows::ApplicationModel::Payments::PaymentDetails));
            *value = detach_from<Windows::ApplicationModel::Payments::PaymentDetails>(this->shim().UpdatedPaymentDetails());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_UpdatedPaymentDetails(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(UpdatedPaymentDetails, WINRT_WRAP(void), Windows::ApplicationModel::Payments::PaymentDetails const&);
            this->shim().UpdatedPaymentDetails(*reinterpret_cast<Windows::ApplicationModel::Payments::PaymentDetails const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::ApplicationModel::Payments::IPaymentRequestChangedResultFactory> : produce_base<D, Windows::ApplicationModel::Payments::IPaymentRequestChangedResultFactory>
{
    int32_t WINRT_CALL Create(bool changeAcceptedByMerchant, void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Create, WINRT_WRAP(Windows::ApplicationModel::Payments::PaymentRequestChangedResult), bool);
            *result = detach_from<Windows::ApplicationModel::Payments::PaymentRequestChangedResult>(this->shim().Create(changeAcceptedByMerchant));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL CreateWithPaymentDetails(bool changeAcceptedByMerchant, void* updatedPaymentDetails, void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CreateWithPaymentDetails, WINRT_WRAP(Windows::ApplicationModel::Payments::PaymentRequestChangedResult), bool, Windows::ApplicationModel::Payments::PaymentDetails const&);
            *result = detach_from<Windows::ApplicationModel::Payments::PaymentRequestChangedResult>(this->shim().CreateWithPaymentDetails(changeAcceptedByMerchant, *reinterpret_cast<Windows::ApplicationModel::Payments::PaymentDetails const*>(&updatedPaymentDetails)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::ApplicationModel::Payments::IPaymentRequestFactory> : produce_base<D, Windows::ApplicationModel::Payments::IPaymentRequestFactory>
{
    int32_t WINRT_CALL Create(void* details, void* methodData, void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Create, WINRT_WRAP(Windows::ApplicationModel::Payments::PaymentRequest), Windows::ApplicationModel::Payments::PaymentDetails const&, Windows::Foundation::Collections::IIterable<Windows::ApplicationModel::Payments::PaymentMethodData> const&);
            *result = detach_from<Windows::ApplicationModel::Payments::PaymentRequest>(this->shim().Create(*reinterpret_cast<Windows::ApplicationModel::Payments::PaymentDetails const*>(&details), *reinterpret_cast<Windows::Foundation::Collections::IIterable<Windows::ApplicationModel::Payments::PaymentMethodData> const*>(&methodData)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL CreateWithMerchantInfo(void* details, void* methodData, void* merchantInfo, void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CreateWithMerchantInfo, WINRT_WRAP(Windows::ApplicationModel::Payments::PaymentRequest), Windows::ApplicationModel::Payments::PaymentDetails const&, Windows::Foundation::Collections::IIterable<Windows::ApplicationModel::Payments::PaymentMethodData> const&, Windows::ApplicationModel::Payments::PaymentMerchantInfo const&);
            *result = detach_from<Windows::ApplicationModel::Payments::PaymentRequest>(this->shim().CreateWithMerchantInfo(*reinterpret_cast<Windows::ApplicationModel::Payments::PaymentDetails const*>(&details), *reinterpret_cast<Windows::Foundation::Collections::IIterable<Windows::ApplicationModel::Payments::PaymentMethodData> const*>(&methodData), *reinterpret_cast<Windows::ApplicationModel::Payments::PaymentMerchantInfo const*>(&merchantInfo)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL CreateWithMerchantInfoAndOptions(void* details, void* methodData, void* merchantInfo, void* options, void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CreateWithMerchantInfoAndOptions, WINRT_WRAP(Windows::ApplicationModel::Payments::PaymentRequest), Windows::ApplicationModel::Payments::PaymentDetails const&, Windows::Foundation::Collections::IIterable<Windows::ApplicationModel::Payments::PaymentMethodData> const&, Windows::ApplicationModel::Payments::PaymentMerchantInfo const&, Windows::ApplicationModel::Payments::PaymentOptions const&);
            *result = detach_from<Windows::ApplicationModel::Payments::PaymentRequest>(this->shim().CreateWithMerchantInfoAndOptions(*reinterpret_cast<Windows::ApplicationModel::Payments::PaymentDetails const*>(&details), *reinterpret_cast<Windows::Foundation::Collections::IIterable<Windows::ApplicationModel::Payments::PaymentMethodData> const*>(&methodData), *reinterpret_cast<Windows::ApplicationModel::Payments::PaymentMerchantInfo const*>(&merchantInfo), *reinterpret_cast<Windows::ApplicationModel::Payments::PaymentOptions const*>(&options)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::ApplicationModel::Payments::IPaymentRequestFactory2> : produce_base<D, Windows::ApplicationModel::Payments::IPaymentRequestFactory2>
{
    int32_t WINRT_CALL CreateWithMerchantInfoOptionsAndId(void* details, void* methodData, void* merchantInfo, void* options, void* id, void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CreateWithMerchantInfoOptionsAndId, WINRT_WRAP(Windows::ApplicationModel::Payments::PaymentRequest), Windows::ApplicationModel::Payments::PaymentDetails const&, Windows::Foundation::Collections::IIterable<Windows::ApplicationModel::Payments::PaymentMethodData> const&, Windows::ApplicationModel::Payments::PaymentMerchantInfo const&, Windows::ApplicationModel::Payments::PaymentOptions const&, hstring const&);
            *result = detach_from<Windows::ApplicationModel::Payments::PaymentRequest>(this->shim().CreateWithMerchantInfoOptionsAndId(*reinterpret_cast<Windows::ApplicationModel::Payments::PaymentDetails const*>(&details), *reinterpret_cast<Windows::Foundation::Collections::IIterable<Windows::ApplicationModel::Payments::PaymentMethodData> const*>(&methodData), *reinterpret_cast<Windows::ApplicationModel::Payments::PaymentMerchantInfo const*>(&merchantInfo), *reinterpret_cast<Windows::ApplicationModel::Payments::PaymentOptions const*>(&options), *reinterpret_cast<hstring const*>(&id)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::ApplicationModel::Payments::IPaymentRequestSubmitResult> : produce_base<D, Windows::ApplicationModel::Payments::IPaymentRequestSubmitResult>
{
    int32_t WINRT_CALL get_Status(Windows::ApplicationModel::Payments::PaymentRequestStatus* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Status, WINRT_WRAP(Windows::ApplicationModel::Payments::PaymentRequestStatus));
            *value = detach_from<Windows::ApplicationModel::Payments::PaymentRequestStatus>(this->shim().Status());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Response(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Response, WINRT_WRAP(Windows::ApplicationModel::Payments::PaymentResponse));
            *value = detach_from<Windows::ApplicationModel::Payments::PaymentResponse>(this->shim().Response());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::ApplicationModel::Payments::IPaymentResponse> : produce_base<D, Windows::ApplicationModel::Payments::IPaymentResponse>
{
    int32_t WINRT_CALL get_PaymentToken(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(PaymentToken, WINRT_WRAP(Windows::ApplicationModel::Payments::PaymentToken));
            *value = detach_from<Windows::ApplicationModel::Payments::PaymentToken>(this->shim().PaymentToken());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_ShippingOption(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ShippingOption, WINRT_WRAP(Windows::ApplicationModel::Payments::PaymentShippingOption));
            *value = detach_from<Windows::ApplicationModel::Payments::PaymentShippingOption>(this->shim().ShippingOption());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_ShippingAddress(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ShippingAddress, WINRT_WRAP(Windows::ApplicationModel::Payments::PaymentAddress));
            *value = detach_from<Windows::ApplicationModel::Payments::PaymentAddress>(this->shim().ShippingAddress());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_PayerEmail(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(PayerEmail, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().PayerEmail());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_PayerName(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(PayerName, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().PayerName());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_PayerPhoneNumber(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(PayerPhoneNumber, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().PayerPhoneNumber());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL CompleteAsync(Windows::ApplicationModel::Payments::PaymentRequestCompletionStatus status, void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CompleteAsync, WINRT_WRAP(Windows::Foundation::IAsyncAction), Windows::ApplicationModel::Payments::PaymentRequestCompletionStatus const);
            *result = detach_from<Windows::Foundation::IAsyncAction>(this->shim().CompleteAsync(*reinterpret_cast<Windows::ApplicationModel::Payments::PaymentRequestCompletionStatus const*>(&status)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::ApplicationModel::Payments::IPaymentShippingOption> : produce_base<D, Windows::ApplicationModel::Payments::IPaymentShippingOption>
{
    int32_t WINRT_CALL get_Label(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Label, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().Label());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_Label(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Label, WINRT_WRAP(void), hstring const&);
            this->shim().Label(*reinterpret_cast<hstring const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Amount(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Amount, WINRT_WRAP(Windows::ApplicationModel::Payments::PaymentCurrencyAmount));
            *value = detach_from<Windows::ApplicationModel::Payments::PaymentCurrencyAmount>(this->shim().Amount());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_Amount(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Amount, WINRT_WRAP(void), Windows::ApplicationModel::Payments::PaymentCurrencyAmount const&);
            this->shim().Amount(*reinterpret_cast<Windows::ApplicationModel::Payments::PaymentCurrencyAmount const*>(&value));
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

    int32_t WINRT_CALL put_Tag(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Tag, WINRT_WRAP(void), hstring const&);
            this->shim().Tag(*reinterpret_cast<hstring const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_IsSelected(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IsSelected, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().IsSelected());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_IsSelected(bool value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IsSelected, WINRT_WRAP(void), bool);
            this->shim().IsSelected(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::ApplicationModel::Payments::IPaymentShippingOptionFactory> : produce_base<D, Windows::ApplicationModel::Payments::IPaymentShippingOptionFactory>
{
    int32_t WINRT_CALL Create(void* label, void* amount, void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Create, WINRT_WRAP(Windows::ApplicationModel::Payments::PaymentShippingOption), hstring const&, Windows::ApplicationModel::Payments::PaymentCurrencyAmount const&);
            *result = detach_from<Windows::ApplicationModel::Payments::PaymentShippingOption>(this->shim().Create(*reinterpret_cast<hstring const*>(&label), *reinterpret_cast<Windows::ApplicationModel::Payments::PaymentCurrencyAmount const*>(&amount)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL CreateWithSelected(void* label, void* amount, bool selected, void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CreateWithSelected, WINRT_WRAP(Windows::ApplicationModel::Payments::PaymentShippingOption), hstring const&, Windows::ApplicationModel::Payments::PaymentCurrencyAmount const&, bool);
            *result = detach_from<Windows::ApplicationModel::Payments::PaymentShippingOption>(this->shim().CreateWithSelected(*reinterpret_cast<hstring const*>(&label), *reinterpret_cast<Windows::ApplicationModel::Payments::PaymentCurrencyAmount const*>(&amount), selected));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL CreateWithSelectedAndTag(void* label, void* amount, bool selected, void* tag, void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CreateWithSelectedAndTag, WINRT_WRAP(Windows::ApplicationModel::Payments::PaymentShippingOption), hstring const&, Windows::ApplicationModel::Payments::PaymentCurrencyAmount const&, bool, hstring const&);
            *result = detach_from<Windows::ApplicationModel::Payments::PaymentShippingOption>(this->shim().CreateWithSelectedAndTag(*reinterpret_cast<hstring const*>(&label), *reinterpret_cast<Windows::ApplicationModel::Payments::PaymentCurrencyAmount const*>(&amount), selected, *reinterpret_cast<hstring const*>(&tag)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::ApplicationModel::Payments::IPaymentToken> : produce_base<D, Windows::ApplicationModel::Payments::IPaymentToken>
{
    int32_t WINRT_CALL get_PaymentMethodId(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(PaymentMethodId, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().PaymentMethodId());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_JsonDetails(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(JsonDetails, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().JsonDetails());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::ApplicationModel::Payments::IPaymentTokenFactory> : produce_base<D, Windows::ApplicationModel::Payments::IPaymentTokenFactory>
{
    int32_t WINRT_CALL Create(void* paymentMethodId, void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Create, WINRT_WRAP(Windows::ApplicationModel::Payments::PaymentToken), hstring const&);
            *result = detach_from<Windows::ApplicationModel::Payments::PaymentToken>(this->shim().Create(*reinterpret_cast<hstring const*>(&paymentMethodId)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL CreateWithJsonDetails(void* paymentMethodId, void* jsonDetails, void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CreateWithJsonDetails, WINRT_WRAP(Windows::ApplicationModel::Payments::PaymentToken), hstring const&, hstring const&);
            *result = detach_from<Windows::ApplicationModel::Payments::PaymentToken>(this->shim().CreateWithJsonDetails(*reinterpret_cast<hstring const*>(&paymentMethodId), *reinterpret_cast<hstring const*>(&jsonDetails)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

}

WINRT_EXPORT namespace winrt::Windows::ApplicationModel::Payments {

inline PaymentAddress::PaymentAddress() :
    PaymentAddress(impl::call_factory<PaymentAddress>([](auto&& f) { return f.template ActivateInstance<PaymentAddress>(); }))
{}

inline PaymentCanMakePaymentResult::PaymentCanMakePaymentResult(Windows::ApplicationModel::Payments::PaymentCanMakePaymentResultStatus const& value) :
    PaymentCanMakePaymentResult(impl::call_factory<PaymentCanMakePaymentResult, Windows::ApplicationModel::Payments::IPaymentCanMakePaymentResultFactory>([&](auto&& f) { return f.Create(value); }))
{}

inline PaymentCurrencyAmount::PaymentCurrencyAmount(param::hstring const& value, param::hstring const& currency) :
    PaymentCurrencyAmount(impl::call_factory<PaymentCurrencyAmount, Windows::ApplicationModel::Payments::IPaymentCurrencyAmountFactory>([&](auto&& f) { return f.Create(value, currency); }))
{}

inline PaymentCurrencyAmount::PaymentCurrencyAmount(param::hstring const& value, param::hstring const& currency, param::hstring const& currencySystem) :
    PaymentCurrencyAmount(impl::call_factory<PaymentCurrencyAmount, Windows::ApplicationModel::Payments::IPaymentCurrencyAmountFactory>([&](auto&& f) { return f.CreateWithCurrencySystem(value, currency, currencySystem); }))
{}

inline PaymentDetails::PaymentDetails() :
    PaymentDetails(impl::call_factory<PaymentDetails>([](auto&& f) { return f.template ActivateInstance<PaymentDetails>(); }))
{}

inline PaymentDetails::PaymentDetails(Windows::ApplicationModel::Payments::PaymentItem const& total) :
    PaymentDetails(impl::call_factory<PaymentDetails, Windows::ApplicationModel::Payments::IPaymentDetailsFactory>([&](auto&& f) { return f.Create(total); }))
{}

inline PaymentDetails::PaymentDetails(Windows::ApplicationModel::Payments::PaymentItem const& total, param::iterable<Windows::ApplicationModel::Payments::PaymentItem> const& displayItems) :
    PaymentDetails(impl::call_factory<PaymentDetails, Windows::ApplicationModel::Payments::IPaymentDetailsFactory>([&](auto&& f) { return f.CreateWithDisplayItems(total, displayItems); }))
{}

inline PaymentDetailsModifier::PaymentDetailsModifier(param::iterable<hstring> const& supportedMethodIds, Windows::ApplicationModel::Payments::PaymentItem const& total) :
    PaymentDetailsModifier(impl::call_factory<PaymentDetailsModifier, Windows::ApplicationModel::Payments::IPaymentDetailsModifierFactory>([&](auto&& f) { return f.Create(supportedMethodIds, total); }))
{}

inline PaymentDetailsModifier::PaymentDetailsModifier(param::iterable<hstring> const& supportedMethodIds, Windows::ApplicationModel::Payments::PaymentItem const& total, param::iterable<Windows::ApplicationModel::Payments::PaymentItem> const& additionalDisplayItems) :
    PaymentDetailsModifier(impl::call_factory<PaymentDetailsModifier, Windows::ApplicationModel::Payments::IPaymentDetailsModifierFactory>([&](auto&& f) { return f.CreateWithAdditionalDisplayItems(supportedMethodIds, total, additionalDisplayItems); }))
{}

inline PaymentDetailsModifier::PaymentDetailsModifier(param::iterable<hstring> const& supportedMethodIds, Windows::ApplicationModel::Payments::PaymentItem const& total, param::iterable<Windows::ApplicationModel::Payments::PaymentItem> const& additionalDisplayItems, param::hstring const& jsonData) :
    PaymentDetailsModifier(impl::call_factory<PaymentDetailsModifier, Windows::ApplicationModel::Payments::IPaymentDetailsModifierFactory>([&](auto&& f) { return f.CreateWithAdditionalDisplayItemsAndJsonData(supportedMethodIds, total, additionalDisplayItems, jsonData); }))
{}

inline PaymentItem::PaymentItem(param::hstring const& label, Windows::ApplicationModel::Payments::PaymentCurrencyAmount const& amount) :
    PaymentItem(impl::call_factory<PaymentItem, Windows::ApplicationModel::Payments::IPaymentItemFactory>([&](auto&& f) { return f.Create(label, amount); }))
{}

inline PaymentMediator::PaymentMediator() :
    PaymentMediator(impl::call_factory<PaymentMediator>([](auto&& f) { return f.template ActivateInstance<PaymentMediator>(); }))
{}

inline PaymentMerchantInfo::PaymentMerchantInfo() :
    PaymentMerchantInfo(impl::call_factory<PaymentMerchantInfo>([](auto&& f) { return f.template ActivateInstance<PaymentMerchantInfo>(); }))
{}

inline PaymentMerchantInfo::PaymentMerchantInfo(Windows::Foundation::Uri const& uri) :
    PaymentMerchantInfo(impl::call_factory<PaymentMerchantInfo, Windows::ApplicationModel::Payments::IPaymentMerchantInfoFactory>([&](auto&& f) { return f.Create(uri); }))
{}

inline PaymentMethodData::PaymentMethodData(param::iterable<hstring> const& supportedMethodIds) :
    PaymentMethodData(impl::call_factory<PaymentMethodData, Windows::ApplicationModel::Payments::IPaymentMethodDataFactory>([&](auto&& f) { return f.Create(supportedMethodIds); }))
{}

inline PaymentMethodData::PaymentMethodData(param::iterable<hstring> const& supportedMethodIds, param::hstring const& jsonData) :
    PaymentMethodData(impl::call_factory<PaymentMethodData, Windows::ApplicationModel::Payments::IPaymentMethodDataFactory>([&](auto&& f) { return f.CreateWithJsonData(supportedMethodIds, jsonData); }))
{}

inline PaymentOptions::PaymentOptions() :
    PaymentOptions(impl::call_factory<PaymentOptions>([](auto&& f) { return f.template ActivateInstance<PaymentOptions>(); }))
{}

inline PaymentRequest::PaymentRequest(Windows::ApplicationModel::Payments::PaymentDetails const& details, param::iterable<Windows::ApplicationModel::Payments::PaymentMethodData> const& methodData) :
    PaymentRequest(impl::call_factory<PaymentRequest, Windows::ApplicationModel::Payments::IPaymentRequestFactory>([&](auto&& f) { return f.Create(details, methodData); }))
{}

inline PaymentRequest::PaymentRequest(Windows::ApplicationModel::Payments::PaymentDetails const& details, param::iterable<Windows::ApplicationModel::Payments::PaymentMethodData> const& methodData, Windows::ApplicationModel::Payments::PaymentMerchantInfo const& merchantInfo) :
    PaymentRequest(impl::call_factory<PaymentRequest, Windows::ApplicationModel::Payments::IPaymentRequestFactory>([&](auto&& f) { return f.CreateWithMerchantInfo(details, methodData, merchantInfo); }))
{}

inline PaymentRequest::PaymentRequest(Windows::ApplicationModel::Payments::PaymentDetails const& details, param::iterable<Windows::ApplicationModel::Payments::PaymentMethodData> const& methodData, Windows::ApplicationModel::Payments::PaymentMerchantInfo const& merchantInfo, Windows::ApplicationModel::Payments::PaymentOptions const& options) :
    PaymentRequest(impl::call_factory<PaymentRequest, Windows::ApplicationModel::Payments::IPaymentRequestFactory>([&](auto&& f) { return f.CreateWithMerchantInfoAndOptions(details, methodData, merchantInfo, options); }))
{}

inline PaymentRequest::PaymentRequest(Windows::ApplicationModel::Payments::PaymentDetails const& details, param::iterable<Windows::ApplicationModel::Payments::PaymentMethodData> const& methodData, Windows::ApplicationModel::Payments::PaymentMerchantInfo const& merchantInfo, Windows::ApplicationModel::Payments::PaymentOptions const& options, param::hstring const& id) :
    PaymentRequest(impl::call_factory<PaymentRequest, Windows::ApplicationModel::Payments::IPaymentRequestFactory2>([&](auto&& f) { return f.CreateWithMerchantInfoOptionsAndId(details, methodData, merchantInfo, options, id); }))
{}

inline PaymentRequestChangedResult::PaymentRequestChangedResult(bool changeAcceptedByMerchant) :
    PaymentRequestChangedResult(impl::call_factory<PaymentRequestChangedResult, Windows::ApplicationModel::Payments::IPaymentRequestChangedResultFactory>([&](auto&& f) { return f.Create(changeAcceptedByMerchant); }))
{}

inline PaymentRequestChangedResult::PaymentRequestChangedResult(bool changeAcceptedByMerchant, Windows::ApplicationModel::Payments::PaymentDetails const& updatedPaymentDetails) :
    PaymentRequestChangedResult(impl::call_factory<PaymentRequestChangedResult, Windows::ApplicationModel::Payments::IPaymentRequestChangedResultFactory>([&](auto&& f) { return f.CreateWithPaymentDetails(changeAcceptedByMerchant, updatedPaymentDetails); }))
{}

inline PaymentShippingOption::PaymentShippingOption(param::hstring const& label, Windows::ApplicationModel::Payments::PaymentCurrencyAmount const& amount) :
    PaymentShippingOption(impl::call_factory<PaymentShippingOption, Windows::ApplicationModel::Payments::IPaymentShippingOptionFactory>([&](auto&& f) { return f.Create(label, amount); }))
{}

inline PaymentShippingOption::PaymentShippingOption(param::hstring const& label, Windows::ApplicationModel::Payments::PaymentCurrencyAmount const& amount, bool selected) :
    PaymentShippingOption(impl::call_factory<PaymentShippingOption, Windows::ApplicationModel::Payments::IPaymentShippingOptionFactory>([&](auto&& f) { return f.CreateWithSelected(label, amount, selected); }))
{}

inline PaymentShippingOption::PaymentShippingOption(param::hstring const& label, Windows::ApplicationModel::Payments::PaymentCurrencyAmount const& amount, bool selected, param::hstring const& tag) :
    PaymentShippingOption(impl::call_factory<PaymentShippingOption, Windows::ApplicationModel::Payments::IPaymentShippingOptionFactory>([&](auto&& f) { return f.CreateWithSelectedAndTag(label, amount, selected, tag); }))
{}

inline PaymentToken::PaymentToken(param::hstring const& paymentMethodId) :
    PaymentToken(impl::call_factory<PaymentToken, Windows::ApplicationModel::Payments::IPaymentTokenFactory>([&](auto&& f) { return f.Create(paymentMethodId); }))
{}

inline PaymentToken::PaymentToken(param::hstring const& paymentMethodId, param::hstring const& jsonDetails) :
    PaymentToken(impl::call_factory<PaymentToken, Windows::ApplicationModel::Payments::IPaymentTokenFactory>([&](auto&& f) { return f.CreateWithJsonDetails(paymentMethodId, jsonDetails); }))
{}

template <typename L> PaymentRequestChangedHandler::PaymentRequestChangedHandler(L handler) :
    PaymentRequestChangedHandler(impl::make_delegate<PaymentRequestChangedHandler>(std::forward<L>(handler)))
{}

template <typename F> PaymentRequestChangedHandler::PaymentRequestChangedHandler(F* handler) :
    PaymentRequestChangedHandler([=](auto&&... args) { return handler(args...); })
{}

template <typename O, typename M> PaymentRequestChangedHandler::PaymentRequestChangedHandler(O* object, M method) :
    PaymentRequestChangedHandler([=](auto&&... args) { return ((*object).*(method))(args...); })
{}

template <typename O, typename M> PaymentRequestChangedHandler::PaymentRequestChangedHandler(com_ptr<O>&& object, M method) :
    PaymentRequestChangedHandler([o = std::move(object), method](auto&&... args) { return ((*o).*(method))(args...); })
{}

template <typename O, typename M> PaymentRequestChangedHandler::PaymentRequestChangedHandler(weak_ref<O>&& object, M method) :
    PaymentRequestChangedHandler([o = std::move(object), method](auto&&... args) { if (auto s = o.get()) { ((*s).*(method))(args...); } })
{}

inline void PaymentRequestChangedHandler::operator()(Windows::ApplicationModel::Payments::PaymentRequest const& paymentRequest, Windows::ApplicationModel::Payments::PaymentRequestChangedArgs const& args) const
{
    check_hresult((*(impl::abi_t<PaymentRequestChangedHandler>**)this)->Invoke(get_abi(paymentRequest), get_abi(args)));
}

}

WINRT_EXPORT namespace std {

template<> struct hash<winrt::Windows::ApplicationModel::Payments::IPaymentAddress> : winrt::impl::hash_base<winrt::Windows::ApplicationModel::Payments::IPaymentAddress> {};
template<> struct hash<winrt::Windows::ApplicationModel::Payments::IPaymentCanMakePaymentResult> : winrt::impl::hash_base<winrt::Windows::ApplicationModel::Payments::IPaymentCanMakePaymentResult> {};
template<> struct hash<winrt::Windows::ApplicationModel::Payments::IPaymentCanMakePaymentResultFactory> : winrt::impl::hash_base<winrt::Windows::ApplicationModel::Payments::IPaymentCanMakePaymentResultFactory> {};
template<> struct hash<winrt::Windows::ApplicationModel::Payments::IPaymentCurrencyAmount> : winrt::impl::hash_base<winrt::Windows::ApplicationModel::Payments::IPaymentCurrencyAmount> {};
template<> struct hash<winrt::Windows::ApplicationModel::Payments::IPaymentCurrencyAmountFactory> : winrt::impl::hash_base<winrt::Windows::ApplicationModel::Payments::IPaymentCurrencyAmountFactory> {};
template<> struct hash<winrt::Windows::ApplicationModel::Payments::IPaymentDetails> : winrt::impl::hash_base<winrt::Windows::ApplicationModel::Payments::IPaymentDetails> {};
template<> struct hash<winrt::Windows::ApplicationModel::Payments::IPaymentDetailsFactory> : winrt::impl::hash_base<winrt::Windows::ApplicationModel::Payments::IPaymentDetailsFactory> {};
template<> struct hash<winrt::Windows::ApplicationModel::Payments::IPaymentDetailsModifier> : winrt::impl::hash_base<winrt::Windows::ApplicationModel::Payments::IPaymentDetailsModifier> {};
template<> struct hash<winrt::Windows::ApplicationModel::Payments::IPaymentDetailsModifierFactory> : winrt::impl::hash_base<winrt::Windows::ApplicationModel::Payments::IPaymentDetailsModifierFactory> {};
template<> struct hash<winrt::Windows::ApplicationModel::Payments::IPaymentItem> : winrt::impl::hash_base<winrt::Windows::ApplicationModel::Payments::IPaymentItem> {};
template<> struct hash<winrt::Windows::ApplicationModel::Payments::IPaymentItemFactory> : winrt::impl::hash_base<winrt::Windows::ApplicationModel::Payments::IPaymentItemFactory> {};
template<> struct hash<winrt::Windows::ApplicationModel::Payments::IPaymentMediator> : winrt::impl::hash_base<winrt::Windows::ApplicationModel::Payments::IPaymentMediator> {};
template<> struct hash<winrt::Windows::ApplicationModel::Payments::IPaymentMediator2> : winrt::impl::hash_base<winrt::Windows::ApplicationModel::Payments::IPaymentMediator2> {};
template<> struct hash<winrt::Windows::ApplicationModel::Payments::IPaymentMerchantInfo> : winrt::impl::hash_base<winrt::Windows::ApplicationModel::Payments::IPaymentMerchantInfo> {};
template<> struct hash<winrt::Windows::ApplicationModel::Payments::IPaymentMerchantInfoFactory> : winrt::impl::hash_base<winrt::Windows::ApplicationModel::Payments::IPaymentMerchantInfoFactory> {};
template<> struct hash<winrt::Windows::ApplicationModel::Payments::IPaymentMethodData> : winrt::impl::hash_base<winrt::Windows::ApplicationModel::Payments::IPaymentMethodData> {};
template<> struct hash<winrt::Windows::ApplicationModel::Payments::IPaymentMethodDataFactory> : winrt::impl::hash_base<winrt::Windows::ApplicationModel::Payments::IPaymentMethodDataFactory> {};
template<> struct hash<winrt::Windows::ApplicationModel::Payments::IPaymentOptions> : winrt::impl::hash_base<winrt::Windows::ApplicationModel::Payments::IPaymentOptions> {};
template<> struct hash<winrt::Windows::ApplicationModel::Payments::IPaymentRequest> : winrt::impl::hash_base<winrt::Windows::ApplicationModel::Payments::IPaymentRequest> {};
template<> struct hash<winrt::Windows::ApplicationModel::Payments::IPaymentRequest2> : winrt::impl::hash_base<winrt::Windows::ApplicationModel::Payments::IPaymentRequest2> {};
template<> struct hash<winrt::Windows::ApplicationModel::Payments::IPaymentRequestChangedArgs> : winrt::impl::hash_base<winrt::Windows::ApplicationModel::Payments::IPaymentRequestChangedArgs> {};
template<> struct hash<winrt::Windows::ApplicationModel::Payments::IPaymentRequestChangedResult> : winrt::impl::hash_base<winrt::Windows::ApplicationModel::Payments::IPaymentRequestChangedResult> {};
template<> struct hash<winrt::Windows::ApplicationModel::Payments::IPaymentRequestChangedResultFactory> : winrt::impl::hash_base<winrt::Windows::ApplicationModel::Payments::IPaymentRequestChangedResultFactory> {};
template<> struct hash<winrt::Windows::ApplicationModel::Payments::IPaymentRequestFactory> : winrt::impl::hash_base<winrt::Windows::ApplicationModel::Payments::IPaymentRequestFactory> {};
template<> struct hash<winrt::Windows::ApplicationModel::Payments::IPaymentRequestFactory2> : winrt::impl::hash_base<winrt::Windows::ApplicationModel::Payments::IPaymentRequestFactory2> {};
template<> struct hash<winrt::Windows::ApplicationModel::Payments::IPaymentRequestSubmitResult> : winrt::impl::hash_base<winrt::Windows::ApplicationModel::Payments::IPaymentRequestSubmitResult> {};
template<> struct hash<winrt::Windows::ApplicationModel::Payments::IPaymentResponse> : winrt::impl::hash_base<winrt::Windows::ApplicationModel::Payments::IPaymentResponse> {};
template<> struct hash<winrt::Windows::ApplicationModel::Payments::IPaymentShippingOption> : winrt::impl::hash_base<winrt::Windows::ApplicationModel::Payments::IPaymentShippingOption> {};
template<> struct hash<winrt::Windows::ApplicationModel::Payments::IPaymentShippingOptionFactory> : winrt::impl::hash_base<winrt::Windows::ApplicationModel::Payments::IPaymentShippingOptionFactory> {};
template<> struct hash<winrt::Windows::ApplicationModel::Payments::IPaymentToken> : winrt::impl::hash_base<winrt::Windows::ApplicationModel::Payments::IPaymentToken> {};
template<> struct hash<winrt::Windows::ApplicationModel::Payments::IPaymentTokenFactory> : winrt::impl::hash_base<winrt::Windows::ApplicationModel::Payments::IPaymentTokenFactory> {};
template<> struct hash<winrt::Windows::ApplicationModel::Payments::PaymentAddress> : winrt::impl::hash_base<winrt::Windows::ApplicationModel::Payments::PaymentAddress> {};
template<> struct hash<winrt::Windows::ApplicationModel::Payments::PaymentCanMakePaymentResult> : winrt::impl::hash_base<winrt::Windows::ApplicationModel::Payments::PaymentCanMakePaymentResult> {};
template<> struct hash<winrt::Windows::ApplicationModel::Payments::PaymentCurrencyAmount> : winrt::impl::hash_base<winrt::Windows::ApplicationModel::Payments::PaymentCurrencyAmount> {};
template<> struct hash<winrt::Windows::ApplicationModel::Payments::PaymentDetails> : winrt::impl::hash_base<winrt::Windows::ApplicationModel::Payments::PaymentDetails> {};
template<> struct hash<winrt::Windows::ApplicationModel::Payments::PaymentDetailsModifier> : winrt::impl::hash_base<winrt::Windows::ApplicationModel::Payments::PaymentDetailsModifier> {};
template<> struct hash<winrt::Windows::ApplicationModel::Payments::PaymentItem> : winrt::impl::hash_base<winrt::Windows::ApplicationModel::Payments::PaymentItem> {};
template<> struct hash<winrt::Windows::ApplicationModel::Payments::PaymentMediator> : winrt::impl::hash_base<winrt::Windows::ApplicationModel::Payments::PaymentMediator> {};
template<> struct hash<winrt::Windows::ApplicationModel::Payments::PaymentMerchantInfo> : winrt::impl::hash_base<winrt::Windows::ApplicationModel::Payments::PaymentMerchantInfo> {};
template<> struct hash<winrt::Windows::ApplicationModel::Payments::PaymentMethodData> : winrt::impl::hash_base<winrt::Windows::ApplicationModel::Payments::PaymentMethodData> {};
template<> struct hash<winrt::Windows::ApplicationModel::Payments::PaymentOptions> : winrt::impl::hash_base<winrt::Windows::ApplicationModel::Payments::PaymentOptions> {};
template<> struct hash<winrt::Windows::ApplicationModel::Payments::PaymentRequest> : winrt::impl::hash_base<winrt::Windows::ApplicationModel::Payments::PaymentRequest> {};
template<> struct hash<winrt::Windows::ApplicationModel::Payments::PaymentRequestChangedArgs> : winrt::impl::hash_base<winrt::Windows::ApplicationModel::Payments::PaymentRequestChangedArgs> {};
template<> struct hash<winrt::Windows::ApplicationModel::Payments::PaymentRequestChangedResult> : winrt::impl::hash_base<winrt::Windows::ApplicationModel::Payments::PaymentRequestChangedResult> {};
template<> struct hash<winrt::Windows::ApplicationModel::Payments::PaymentRequestSubmitResult> : winrt::impl::hash_base<winrt::Windows::ApplicationModel::Payments::PaymentRequestSubmitResult> {};
template<> struct hash<winrt::Windows::ApplicationModel::Payments::PaymentResponse> : winrt::impl::hash_base<winrt::Windows::ApplicationModel::Payments::PaymentResponse> {};
template<> struct hash<winrt::Windows::ApplicationModel::Payments::PaymentShippingOption> : winrt::impl::hash_base<winrt::Windows::ApplicationModel::Payments::PaymentShippingOption> {};
template<> struct hash<winrt::Windows::ApplicationModel::Payments::PaymentToken> : winrt::impl::hash_base<winrt::Windows::ApplicationModel::Payments::PaymentToken> {};

}
