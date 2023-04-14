// C++/WinRT v1.0.190111.3

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#pragma once

#include "winrt/base.h"

#include "winrt/Windows.Foundation.h"
#include "winrt/Windows.Foundation.Collections.h"
#include "winrt/impl/Windows.Foundation.Collections.2.h"
#include "winrt/impl/Windows.Security.Cryptography.Core.2.h"
#include "winrt/impl/Windows.Storage.Streams.2.h"
#include "winrt/impl/Windows.Foundation.2.h"
#include "winrt/impl/Windows.Devices.SmartCards.2.h"
#include "winrt/Windows.Devices.h"

namespace winrt::impl {

template <typename D> Windows::Devices::SmartCards::SmartCard consume_Windows_Devices_SmartCards_ICardAddedEventArgs<D>::SmartCard() const
{
    Windows::Devices::SmartCards::SmartCard value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Devices::SmartCards::ICardAddedEventArgs)->get_SmartCard(put_abi(value)));
    return value;
}

template <typename D> Windows::Devices::SmartCards::SmartCard consume_Windows_Devices_SmartCards_ICardRemovedEventArgs<D>::SmartCard() const
{
    Windows::Devices::SmartCards::SmartCard value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Devices::SmartCards::ICardRemovedEventArgs)->get_SmartCard(put_abi(value)));
    return value;
}

template <typename D> Windows::Storage::Streams::IBuffer consume_Windows_Devices_SmartCards_IKnownSmartCardAppletIds<D>::PaymentSystemEnvironment() const
{
    Windows::Storage::Streams::IBuffer value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Devices::SmartCards::IKnownSmartCardAppletIds)->get_PaymentSystemEnvironment(put_abi(value)));
    return value;
}

template <typename D> Windows::Storage::Streams::IBuffer consume_Windows_Devices_SmartCards_IKnownSmartCardAppletIds<D>::ProximityPaymentSystemEnvironment() const
{
    Windows::Storage::Streams::IBuffer value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Devices::SmartCards::IKnownSmartCardAppletIds)->get_ProximityPaymentSystemEnvironment(put_abi(value)));
    return value;
}

template <typename D> Windows::Devices::SmartCards::SmartCardReader consume_Windows_Devices_SmartCards_ISmartCard<D>::Reader() const
{
    Windows::Devices::SmartCards::SmartCardReader value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Devices::SmartCards::ISmartCard)->get_Reader(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::IAsyncOperation<Windows::Devices::SmartCards::SmartCardStatus> consume_Windows_Devices_SmartCards_ISmartCard<D>::GetStatusAsync() const
{
    Windows::Foundation::IAsyncOperation<Windows::Devices::SmartCards::SmartCardStatus> result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Devices::SmartCards::ISmartCard)->GetStatusAsync(put_abi(result)));
    return result;
}

template <typename D> Windows::Foundation::IAsyncOperation<Windows::Storage::Streams::IBuffer> consume_Windows_Devices_SmartCards_ISmartCard<D>::GetAnswerToResetAsync() const
{
    Windows::Foundation::IAsyncOperation<Windows::Storage::Streams::IBuffer> result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Devices::SmartCards::ISmartCard)->GetAnswerToResetAsync(put_abi(result)));
    return result;
}

template <typename D> hstring consume_Windows_Devices_SmartCards_ISmartCardAppletIdGroup<D>::DisplayName() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Devices::SmartCards::ISmartCardAppletIdGroup)->get_DisplayName(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_Devices_SmartCards_ISmartCardAppletIdGroup<D>::DisplayName(param::hstring const& value) const
{
    check_hresult(WINRT_SHIM(Windows::Devices::SmartCards::ISmartCardAppletIdGroup)->put_DisplayName(get_abi(value)));
}

template <typename D> Windows::Foundation::Collections::IVector<Windows::Storage::Streams::IBuffer> consume_Windows_Devices_SmartCards_ISmartCardAppletIdGroup<D>::AppletIds() const
{
    Windows::Foundation::Collections::IVector<Windows::Storage::Streams::IBuffer> value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Devices::SmartCards::ISmartCardAppletIdGroup)->get_AppletIds(put_abi(value)));
    return value;
}

template <typename D> Windows::Devices::SmartCards::SmartCardEmulationCategory consume_Windows_Devices_SmartCards_ISmartCardAppletIdGroup<D>::SmartCardEmulationCategory() const
{
    Windows::Devices::SmartCards::SmartCardEmulationCategory value{};
    check_hresult(WINRT_SHIM(Windows::Devices::SmartCards::ISmartCardAppletIdGroup)->get_SmartCardEmulationCategory(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_Devices_SmartCards_ISmartCardAppletIdGroup<D>::SmartCardEmulationCategory(Windows::Devices::SmartCards::SmartCardEmulationCategory const& value) const
{
    check_hresult(WINRT_SHIM(Windows::Devices::SmartCards::ISmartCardAppletIdGroup)->put_SmartCardEmulationCategory(get_abi(value)));
}

template <typename D> Windows::Devices::SmartCards::SmartCardEmulationType consume_Windows_Devices_SmartCards_ISmartCardAppletIdGroup<D>::SmartCardEmulationType() const
{
    Windows::Devices::SmartCards::SmartCardEmulationType value{};
    check_hresult(WINRT_SHIM(Windows::Devices::SmartCards::ISmartCardAppletIdGroup)->get_SmartCardEmulationType(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_Devices_SmartCards_ISmartCardAppletIdGroup<D>::SmartCardEmulationType(Windows::Devices::SmartCards::SmartCardEmulationType const& value) const
{
    check_hresult(WINRT_SHIM(Windows::Devices::SmartCards::ISmartCardAppletIdGroup)->put_SmartCardEmulationType(get_abi(value)));
}

template <typename D> bool consume_Windows_Devices_SmartCards_ISmartCardAppletIdGroup<D>::AutomaticEnablement() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::Devices::SmartCards::ISmartCardAppletIdGroup)->get_AutomaticEnablement(&value));
    return value;
}

template <typename D> void consume_Windows_Devices_SmartCards_ISmartCardAppletIdGroup<D>::AutomaticEnablement(bool value) const
{
    check_hresult(WINRT_SHIM(Windows::Devices::SmartCards::ISmartCardAppletIdGroup)->put_AutomaticEnablement(value));
}

template <typename D> Windows::Storage::Streams::IRandomAccessStreamReference consume_Windows_Devices_SmartCards_ISmartCardAppletIdGroup2<D>::Logo() const
{
    Windows::Storage::Streams::IRandomAccessStreamReference value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Devices::SmartCards::ISmartCardAppletIdGroup2)->get_Logo(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_Devices_SmartCards_ISmartCardAppletIdGroup2<D>::Logo(Windows::Storage::Streams::IRandomAccessStreamReference const& value) const
{
    check_hresult(WINRT_SHIM(Windows::Devices::SmartCards::ISmartCardAppletIdGroup2)->put_Logo(get_abi(value)));
}

template <typename D> hstring consume_Windows_Devices_SmartCards_ISmartCardAppletIdGroup2<D>::Description() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Devices::SmartCards::ISmartCardAppletIdGroup2)->get_Description(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_Devices_SmartCards_ISmartCardAppletIdGroup2<D>::Description(param::hstring const& value) const
{
    check_hresult(WINRT_SHIM(Windows::Devices::SmartCards::ISmartCardAppletIdGroup2)->put_Description(get_abi(value)));
}

template <typename D> Windows::Foundation::Collections::ValueSet consume_Windows_Devices_SmartCards_ISmartCardAppletIdGroup2<D>::Properties() const
{
    Windows::Foundation::Collections::ValueSet value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Devices::SmartCards::ISmartCardAppletIdGroup2)->get_Properties(put_abi(value)));
    return value;
}

template <typename D> bool consume_Windows_Devices_SmartCards_ISmartCardAppletIdGroup2<D>::SecureUserAuthenticationRequired() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::Devices::SmartCards::ISmartCardAppletIdGroup2)->get_SecureUserAuthenticationRequired(&value));
    return value;
}

template <typename D> void consume_Windows_Devices_SmartCards_ISmartCardAppletIdGroup2<D>::SecureUserAuthenticationRequired(bool value) const
{
    check_hresult(WINRT_SHIM(Windows::Devices::SmartCards::ISmartCardAppletIdGroup2)->put_SecureUserAuthenticationRequired(value));
}

template <typename D> Windows::Devices::SmartCards::SmartCardAppletIdGroup consume_Windows_Devices_SmartCards_ISmartCardAppletIdGroupFactory<D>::Create(param::hstring const& displayName, param::vector<Windows::Storage::Streams::IBuffer> const& appletIds, Windows::Devices::SmartCards::SmartCardEmulationCategory const& emulationCategory, Windows::Devices::SmartCards::SmartCardEmulationType const& emulationType) const
{
    Windows::Devices::SmartCards::SmartCardAppletIdGroup result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Devices::SmartCards::ISmartCardAppletIdGroupFactory)->Create(get_abi(displayName), get_abi(appletIds), get_abi(emulationCategory), get_abi(emulationType), put_abi(result)));
    return result;
}

template <typename D> Windows::Devices::SmartCards::SmartCardAppletIdGroupActivationPolicy consume_Windows_Devices_SmartCards_ISmartCardAppletIdGroupRegistration<D>::ActivationPolicy() const
{
    Windows::Devices::SmartCards::SmartCardAppletIdGroupActivationPolicy value{};
    check_hresult(WINRT_SHIM(Windows::Devices::SmartCards::ISmartCardAppletIdGroupRegistration)->get_ActivationPolicy(put_abi(value)));
    return value;
}

template <typename D> Windows::Devices::SmartCards::SmartCardAppletIdGroup consume_Windows_Devices_SmartCards_ISmartCardAppletIdGroupRegistration<D>::AppletIdGroup() const
{
    Windows::Devices::SmartCards::SmartCardAppletIdGroup value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Devices::SmartCards::ISmartCardAppletIdGroupRegistration)->get_AppletIdGroup(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::IAsyncOperation<Windows::Devices::SmartCards::SmartCardActivationPolicyChangeResult> consume_Windows_Devices_SmartCards_ISmartCardAppletIdGroupRegistration<D>::RequestActivationPolicyChangeAsync(Windows::Devices::SmartCards::SmartCardAppletIdGroupActivationPolicy const& policy) const
{
    Windows::Foundation::IAsyncOperation<Windows::Devices::SmartCards::SmartCardActivationPolicyChangeResult> result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Devices::SmartCards::ISmartCardAppletIdGroupRegistration)->RequestActivationPolicyChangeAsync(get_abi(policy), put_abi(result)));
    return result;
}

template <typename D> winrt::guid consume_Windows_Devices_SmartCards_ISmartCardAppletIdGroupRegistration<D>::Id() const
{
    winrt::guid value{};
    check_hresult(WINRT_SHIM(Windows::Devices::SmartCards::ISmartCardAppletIdGroupRegistration)->get_Id(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::IAsyncAction consume_Windows_Devices_SmartCards_ISmartCardAppletIdGroupRegistration<D>::SetAutomaticResponseApdusAsync(param::async_iterable<Windows::Devices::SmartCards::SmartCardAutomaticResponseApdu> const& apdus) const
{
    Windows::Foundation::IAsyncAction result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Devices::SmartCards::ISmartCardAppletIdGroupRegistration)->SetAutomaticResponseApdusAsync(get_abi(apdus), put_abi(result)));
    return result;
}

template <typename D> hstring consume_Windows_Devices_SmartCards_ISmartCardAppletIdGroupRegistration2<D>::SmartCardReaderId() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Devices::SmartCards::ISmartCardAppletIdGroupRegistration2)->get_SmartCardReaderId(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::IAsyncAction consume_Windows_Devices_SmartCards_ISmartCardAppletIdGroupRegistration2<D>::SetPropertiesAsync(Windows::Foundation::Collections::ValueSet const& props) const
{
    Windows::Foundation::IAsyncAction operation{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Devices::SmartCards::ISmartCardAppletIdGroupRegistration2)->SetPropertiesAsync(get_abi(props), put_abi(operation)));
    return operation;
}

template <typename D> uint16_t consume_Windows_Devices_SmartCards_ISmartCardAppletIdGroupStatics<D>::MaxAppletIds() const
{
    uint16_t value{};
    check_hresult(WINRT_SHIM(Windows::Devices::SmartCards::ISmartCardAppletIdGroupStatics)->get_MaxAppletIds(&value));
    return value;
}

template <typename D> Windows::Storage::Streams::IBuffer consume_Windows_Devices_SmartCards_ISmartCardAutomaticResponseApdu<D>::CommandApdu() const
{
    Windows::Storage::Streams::IBuffer value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Devices::SmartCards::ISmartCardAutomaticResponseApdu)->get_CommandApdu(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_Devices_SmartCards_ISmartCardAutomaticResponseApdu<D>::CommandApdu(Windows::Storage::Streams::IBuffer const& value) const
{
    check_hresult(WINRT_SHIM(Windows::Devices::SmartCards::ISmartCardAutomaticResponseApdu)->put_CommandApdu(get_abi(value)));
}

template <typename D> Windows::Storage::Streams::IBuffer consume_Windows_Devices_SmartCards_ISmartCardAutomaticResponseApdu<D>::CommandApduBitMask() const
{
    Windows::Storage::Streams::IBuffer value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Devices::SmartCards::ISmartCardAutomaticResponseApdu)->get_CommandApduBitMask(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_Devices_SmartCards_ISmartCardAutomaticResponseApdu<D>::CommandApduBitMask(Windows::Storage::Streams::IBuffer const& value) const
{
    check_hresult(WINRT_SHIM(Windows::Devices::SmartCards::ISmartCardAutomaticResponseApdu)->put_CommandApduBitMask(get_abi(value)));
}

template <typename D> bool consume_Windows_Devices_SmartCards_ISmartCardAutomaticResponseApdu<D>::ShouldMatchLength() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::Devices::SmartCards::ISmartCardAutomaticResponseApdu)->get_ShouldMatchLength(&value));
    return value;
}

template <typename D> void consume_Windows_Devices_SmartCards_ISmartCardAutomaticResponseApdu<D>::ShouldMatchLength(bool value) const
{
    check_hresult(WINRT_SHIM(Windows::Devices::SmartCards::ISmartCardAutomaticResponseApdu)->put_ShouldMatchLength(value));
}

template <typename D> Windows::Storage::Streams::IBuffer consume_Windows_Devices_SmartCards_ISmartCardAutomaticResponseApdu<D>::AppletId() const
{
    Windows::Storage::Streams::IBuffer value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Devices::SmartCards::ISmartCardAutomaticResponseApdu)->get_AppletId(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_Devices_SmartCards_ISmartCardAutomaticResponseApdu<D>::AppletId(Windows::Storage::Streams::IBuffer const& value) const
{
    check_hresult(WINRT_SHIM(Windows::Devices::SmartCards::ISmartCardAutomaticResponseApdu)->put_AppletId(get_abi(value)));
}

template <typename D> Windows::Storage::Streams::IBuffer consume_Windows_Devices_SmartCards_ISmartCardAutomaticResponseApdu<D>::ResponseApdu() const
{
    Windows::Storage::Streams::IBuffer value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Devices::SmartCards::ISmartCardAutomaticResponseApdu)->get_ResponseApdu(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_Devices_SmartCards_ISmartCardAutomaticResponseApdu<D>::ResponseApdu(Windows::Storage::Streams::IBuffer const& value) const
{
    check_hresult(WINRT_SHIM(Windows::Devices::SmartCards::ISmartCardAutomaticResponseApdu)->put_ResponseApdu(get_abi(value)));
}

template <typename D> Windows::Foundation::IReference<uint32_t> consume_Windows_Devices_SmartCards_ISmartCardAutomaticResponseApdu2<D>::InputState() const
{
    Windows::Foundation::IReference<uint32_t> value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Devices::SmartCards::ISmartCardAutomaticResponseApdu2)->get_InputState(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_Devices_SmartCards_ISmartCardAutomaticResponseApdu2<D>::InputState(optional<uint32_t> const& value) const
{
    check_hresult(WINRT_SHIM(Windows::Devices::SmartCards::ISmartCardAutomaticResponseApdu2)->put_InputState(get_abi(value)));
}

template <typename D> Windows::Foundation::IReference<uint32_t> consume_Windows_Devices_SmartCards_ISmartCardAutomaticResponseApdu2<D>::OutputState() const
{
    Windows::Foundation::IReference<uint32_t> value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Devices::SmartCards::ISmartCardAutomaticResponseApdu2)->get_OutputState(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_Devices_SmartCards_ISmartCardAutomaticResponseApdu2<D>::OutputState(optional<uint32_t> const& value) const
{
    check_hresult(WINRT_SHIM(Windows::Devices::SmartCards::ISmartCardAutomaticResponseApdu2)->put_OutputState(get_abi(value)));
}

template <typename D> bool consume_Windows_Devices_SmartCards_ISmartCardAutomaticResponseApdu3<D>::AllowWhenCryptogramGeneratorNotPrepared() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::Devices::SmartCards::ISmartCardAutomaticResponseApdu3)->get_AllowWhenCryptogramGeneratorNotPrepared(&value));
    return value;
}

template <typename D> void consume_Windows_Devices_SmartCards_ISmartCardAutomaticResponseApdu3<D>::AllowWhenCryptogramGeneratorNotPrepared(bool value) const
{
    check_hresult(WINRT_SHIM(Windows::Devices::SmartCards::ISmartCardAutomaticResponseApdu3)->put_AllowWhenCryptogramGeneratorNotPrepared(value));
}

template <typename D> Windows::Devices::SmartCards::SmartCardAutomaticResponseApdu consume_Windows_Devices_SmartCards_ISmartCardAutomaticResponseApduFactory<D>::Create(Windows::Storage::Streams::IBuffer const& commandApdu, Windows::Storage::Streams::IBuffer const& responseApdu) const
{
    Windows::Devices::SmartCards::SmartCardAutomaticResponseApdu result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Devices::SmartCards::ISmartCardAutomaticResponseApduFactory)->Create(get_abi(commandApdu), get_abi(responseApdu), put_abi(result)));
    return result;
}

template <typename D> Windows::Storage::Streams::IBuffer consume_Windows_Devices_SmartCards_ISmartCardChallengeContext<D>::Challenge() const
{
    Windows::Storage::Streams::IBuffer value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Devices::SmartCards::ISmartCardChallengeContext)->get_Challenge(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::IAsyncOperation<bool> consume_Windows_Devices_SmartCards_ISmartCardChallengeContext<D>::VerifyResponseAsync(Windows::Storage::Streams::IBuffer const& response) const
{
    Windows::Foundation::IAsyncOperation<bool> result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Devices::SmartCards::ISmartCardChallengeContext)->VerifyResponseAsync(get_abi(response), put_abi(result)));
    return result;
}

template <typename D> Windows::Foundation::IAsyncAction consume_Windows_Devices_SmartCards_ISmartCardChallengeContext<D>::ProvisionAsync(Windows::Storage::Streams::IBuffer const& response, bool formatCard) const
{
    Windows::Foundation::IAsyncAction result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Devices::SmartCards::ISmartCardChallengeContext)->ProvisionAsync(get_abi(response), formatCard, put_abi(result)));
    return result;
}

template <typename D> Windows::Foundation::IAsyncAction consume_Windows_Devices_SmartCards_ISmartCardChallengeContext<D>::ProvisionAsync(Windows::Storage::Streams::IBuffer const& response, bool formatCard, winrt::guid const& newCardId) const
{
    Windows::Foundation::IAsyncAction result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Devices::SmartCards::ISmartCardChallengeContext)->ProvisionAsyncWithNewCardId(get_abi(response), formatCard, get_abi(newCardId), put_abi(result)));
    return result;
}

template <typename D> Windows::Foundation::IAsyncAction consume_Windows_Devices_SmartCards_ISmartCardChallengeContext<D>::ChangeAdministrativeKeyAsync(Windows::Storage::Streams::IBuffer const& response, Windows::Storage::Streams::IBuffer const& newAdministrativeKey) const
{
    Windows::Foundation::IAsyncAction result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Devices::SmartCards::ISmartCardChallengeContext)->ChangeAdministrativeKeyAsync(get_abi(response), get_abi(newAdministrativeKey), put_abi(result)));
    return result;
}

template <typename D> Windows::Foundation::IAsyncOperation<Windows::Devices::SmartCards::SmartCardConnection> consume_Windows_Devices_SmartCards_ISmartCardConnect<D>::ConnectAsync() const
{
    Windows::Foundation::IAsyncOperation<Windows::Devices::SmartCards::SmartCardConnection> result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Devices::SmartCards::ISmartCardConnect)->ConnectAsync(put_abi(result)));
    return result;
}

template <typename D> Windows::Foundation::IAsyncOperation<Windows::Storage::Streams::IBuffer> consume_Windows_Devices_SmartCards_ISmartCardConnection<D>::TransmitAsync(Windows::Storage::Streams::IBuffer const& command) const
{
    Windows::Foundation::IAsyncOperation<Windows::Storage::Streams::IBuffer> result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Devices::SmartCards::ISmartCardConnection)->TransmitAsync(get_abi(command), put_abi(result)));
    return result;
}

template <typename D> Windows::Foundation::Collections::IVectorView<Windows::Devices::SmartCards::SmartCardCryptogramMaterialType> consume_Windows_Devices_SmartCards_ISmartCardCryptogramGenerator<D>::SupportedCryptogramMaterialTypes() const
{
    Windows::Foundation::Collections::IVectorView<Windows::Devices::SmartCards::SmartCardCryptogramMaterialType> result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Devices::SmartCards::ISmartCardCryptogramGenerator)->get_SupportedCryptogramMaterialTypes(put_abi(result)));
    return result;
}

template <typename D> Windows::Foundation::Collections::IVectorView<Windows::Devices::SmartCards::SmartCardCryptogramAlgorithm> consume_Windows_Devices_SmartCards_ISmartCardCryptogramGenerator<D>::SupportedCryptogramAlgorithms() const
{
    Windows::Foundation::Collections::IVectorView<Windows::Devices::SmartCards::SmartCardCryptogramAlgorithm> result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Devices::SmartCards::ISmartCardCryptogramGenerator)->get_SupportedCryptogramAlgorithms(put_abi(result)));
    return result;
}

template <typename D> Windows::Foundation::Collections::IVectorView<Windows::Devices::SmartCards::SmartCardCryptogramMaterialPackageFormat> consume_Windows_Devices_SmartCards_ISmartCardCryptogramGenerator<D>::SupportedCryptogramMaterialPackageFormats() const
{
    Windows::Foundation::Collections::IVectorView<Windows::Devices::SmartCards::SmartCardCryptogramMaterialPackageFormat> result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Devices::SmartCards::ISmartCardCryptogramGenerator)->get_SupportedCryptogramMaterialPackageFormats(put_abi(result)));
    return result;
}

template <typename D> Windows::Foundation::Collections::IVectorView<Windows::Devices::SmartCards::SmartCardCryptogramMaterialPackageConfirmationResponseFormat> consume_Windows_Devices_SmartCards_ISmartCardCryptogramGenerator<D>::SupportedCryptogramMaterialPackageConfirmationResponseFormats() const
{
    Windows::Foundation::Collections::IVectorView<Windows::Devices::SmartCards::SmartCardCryptogramMaterialPackageConfirmationResponseFormat> result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Devices::SmartCards::ISmartCardCryptogramGenerator)->get_SupportedCryptogramMaterialPackageConfirmationResponseFormats(put_abi(result)));
    return result;
}

template <typename D> Windows::Foundation::Collections::IVectorView<Windows::Devices::SmartCards::SmartCardCryptogramStorageKeyCapabilities> consume_Windows_Devices_SmartCards_ISmartCardCryptogramGenerator<D>::SupportedSmartCardCryptogramStorageKeyCapabilities() const
{
    Windows::Foundation::Collections::IVectorView<Windows::Devices::SmartCards::SmartCardCryptogramStorageKeyCapabilities> result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Devices::SmartCards::ISmartCardCryptogramGenerator)->get_SupportedSmartCardCryptogramStorageKeyCapabilities(put_abi(result)));
    return result;
}

template <typename D> Windows::Foundation::IAsyncOperation<Windows::Devices::SmartCards::SmartCardCryptogramGeneratorOperationStatus> consume_Windows_Devices_SmartCards_ISmartCardCryptogramGenerator<D>::DeleteCryptogramMaterialStorageKeyAsync(param::hstring const& storageKeyName) const
{
    Windows::Foundation::IAsyncOperation<Windows::Devices::SmartCards::SmartCardCryptogramGeneratorOperationStatus> result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Devices::SmartCards::ISmartCardCryptogramGenerator)->DeleteCryptogramMaterialStorageKeyAsync(get_abi(storageKeyName), put_abi(result)));
    return result;
}

template <typename D> Windows::Foundation::IAsyncOperation<Windows::Devices::SmartCards::SmartCardCryptogramGeneratorOperationStatus> consume_Windows_Devices_SmartCards_ISmartCardCryptogramGenerator<D>::CreateCryptogramMaterialStorageKeyAsync(Windows::Devices::SmartCards::SmartCardUnlockPromptingBehavior const& promptingBehavior, param::hstring const& storageKeyName, Windows::Devices::SmartCards::SmartCardCryptogramStorageKeyAlgorithm const& algorithm, Windows::Devices::SmartCards::SmartCardCryptogramStorageKeyCapabilities const& capabilities) const
{
    Windows::Foundation::IAsyncOperation<Windows::Devices::SmartCards::SmartCardCryptogramGeneratorOperationStatus> result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Devices::SmartCards::ISmartCardCryptogramGenerator)->CreateCryptogramMaterialStorageKeyAsync(get_abi(promptingBehavior), get_abi(storageKeyName), get_abi(algorithm), get_abi(capabilities), put_abi(result)));
    return result;
}

template <typename D> Windows::Foundation::IAsyncOperation<Windows::Devices::SmartCards::SmartCardCryptogramStorageKeyInfo> consume_Windows_Devices_SmartCards_ISmartCardCryptogramGenerator<D>::RequestCryptogramMaterialStorageKeyInfoAsync(Windows::Devices::SmartCards::SmartCardUnlockPromptingBehavior const& promptingBehavior, param::hstring const& storageKeyName, Windows::Security::Cryptography::Core::CryptographicPublicKeyBlobType const& format) const
{
    Windows::Foundation::IAsyncOperation<Windows::Devices::SmartCards::SmartCardCryptogramStorageKeyInfo> result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Devices::SmartCards::ISmartCardCryptogramGenerator)->RequestCryptogramMaterialStorageKeyInfoAsync(get_abi(promptingBehavior), get_abi(storageKeyName), get_abi(format), put_abi(result)));
    return result;
}

template <typename D> Windows::Foundation::IAsyncOperation<Windows::Devices::SmartCards::SmartCardCryptogramGeneratorOperationStatus> consume_Windows_Devices_SmartCards_ISmartCardCryptogramGenerator<D>::ImportCryptogramMaterialPackageAsync(Windows::Devices::SmartCards::SmartCardCryptogramMaterialPackageFormat const& format, param::hstring const& storageKeyName, param::hstring const& materialPackageName, Windows::Storage::Streams::IBuffer const& cryptogramMaterialPackage) const
{
    Windows::Foundation::IAsyncOperation<Windows::Devices::SmartCards::SmartCardCryptogramGeneratorOperationStatus> result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Devices::SmartCards::ISmartCardCryptogramGenerator)->ImportCryptogramMaterialPackageAsync(get_abi(format), get_abi(storageKeyName), get_abi(materialPackageName), get_abi(cryptogramMaterialPackage), put_abi(result)));
    return result;
}

template <typename D> Windows::Foundation::IAsyncOperation<Windows::Devices::SmartCards::SmartCardCryptogramMaterialPossessionProof> consume_Windows_Devices_SmartCards_ISmartCardCryptogramGenerator<D>::TryProvePossessionOfCryptogramMaterialPackageAsync(Windows::Devices::SmartCards::SmartCardUnlockPromptingBehavior const& promptingBehavior, Windows::Devices::SmartCards::SmartCardCryptogramMaterialPackageConfirmationResponseFormat const& responseFormat, param::hstring const& materialPackageName, param::hstring const& materialName, Windows::Storage::Streams::IBuffer const& challenge) const
{
    Windows::Foundation::IAsyncOperation<Windows::Devices::SmartCards::SmartCardCryptogramMaterialPossessionProof> result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Devices::SmartCards::ISmartCardCryptogramGenerator)->TryProvePossessionOfCryptogramMaterialPackageAsync(get_abi(promptingBehavior), get_abi(responseFormat), get_abi(materialPackageName), get_abi(materialName), get_abi(challenge), put_abi(result)));
    return result;
}

template <typename D> Windows::Foundation::IAsyncOperation<Windows::Devices::SmartCards::SmartCardCryptogramGeneratorOperationStatus> consume_Windows_Devices_SmartCards_ISmartCardCryptogramGenerator<D>::RequestUnlockCryptogramMaterialForUseAsync(Windows::Devices::SmartCards::SmartCardUnlockPromptingBehavior const& promptingBehavior) const
{
    Windows::Foundation::IAsyncOperation<Windows::Devices::SmartCards::SmartCardCryptogramGeneratorOperationStatus> result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Devices::SmartCards::ISmartCardCryptogramGenerator)->RequestUnlockCryptogramMaterialForUseAsync(get_abi(promptingBehavior), put_abi(result)));
    return result;
}

template <typename D> Windows::Foundation::IAsyncOperation<Windows::Devices::SmartCards::SmartCardCryptogramGeneratorOperationStatus> consume_Windows_Devices_SmartCards_ISmartCardCryptogramGenerator<D>::DeleteCryptogramMaterialPackageAsync(param::hstring const& materialPackageName) const
{
    Windows::Foundation::IAsyncOperation<Windows::Devices::SmartCards::SmartCardCryptogramGeneratorOperationStatus> result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Devices::SmartCards::ISmartCardCryptogramGenerator)->DeleteCryptogramMaterialPackageAsync(get_abi(materialPackageName), put_abi(result)));
    return result;
}

template <typename D> Windows::Foundation::IAsyncOperation<Windows::Devices::SmartCards::SmartCardCryptogramGeneratorOperationStatus> consume_Windows_Devices_SmartCards_ISmartCardCryptogramGenerator2<D>::ValidateRequestApduAsync(Windows::Devices::SmartCards::SmartCardUnlockPromptingBehavior const& promptingBehavior, Windows::Storage::Streams::IBuffer const& apduToValidate, param::async_iterable<Windows::Devices::SmartCards::SmartCardCryptogramPlacementStep> const& cryptogramPlacementSteps) const
{
    Windows::Foundation::IAsyncOperation<Windows::Devices::SmartCards::SmartCardCryptogramGeneratorOperationStatus> result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Devices::SmartCards::ISmartCardCryptogramGenerator2)->ValidateRequestApduAsync(get_abi(promptingBehavior), get_abi(apduToValidate), get_abi(cryptogramPlacementSteps), put_abi(result)));
    return result;
}

template <typename D> Windows::Foundation::IAsyncOperation<Windows::Devices::SmartCards::SmartCardCryptogramGetAllCryptogramStorageKeyCharacteristicsResult> consume_Windows_Devices_SmartCards_ISmartCardCryptogramGenerator2<D>::GetAllCryptogramStorageKeyCharacteristicsAsync() const
{
    Windows::Foundation::IAsyncOperation<Windows::Devices::SmartCards::SmartCardCryptogramGetAllCryptogramStorageKeyCharacteristicsResult> result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Devices::SmartCards::ISmartCardCryptogramGenerator2)->GetAllCryptogramStorageKeyCharacteristicsAsync(put_abi(result)));
    return result;
}

template <typename D> Windows::Foundation::IAsyncOperation<Windows::Devices::SmartCards::SmartCardCryptogramGetAllCryptogramMaterialPackageCharacteristicsResult> consume_Windows_Devices_SmartCards_ISmartCardCryptogramGenerator2<D>::GetAllCryptogramMaterialPackageCharacteristicsAsync() const
{
    Windows::Foundation::IAsyncOperation<Windows::Devices::SmartCards::SmartCardCryptogramGetAllCryptogramMaterialPackageCharacteristicsResult> result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Devices::SmartCards::ISmartCardCryptogramGenerator2)->GetAllCryptogramMaterialPackageCharacteristicsAsync(put_abi(result)));
    return result;
}

template <typename D> Windows::Foundation::IAsyncOperation<Windows::Devices::SmartCards::SmartCardCryptogramGetAllCryptogramMaterialPackageCharacteristicsResult> consume_Windows_Devices_SmartCards_ISmartCardCryptogramGenerator2<D>::GetAllCryptogramMaterialPackageCharacteristicsAsync(param::hstring const& storageKeyName) const
{
    Windows::Foundation::IAsyncOperation<Windows::Devices::SmartCards::SmartCardCryptogramGetAllCryptogramMaterialPackageCharacteristicsResult> result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Devices::SmartCards::ISmartCardCryptogramGenerator2)->GetAllCryptogramMaterialPackageCharacteristicsWithStorageKeyAsync(get_abi(storageKeyName), put_abi(result)));
    return result;
}

template <typename D> Windows::Foundation::IAsyncOperation<Windows::Devices::SmartCards::SmartCardCryptogramGetAllCryptogramMaterialCharacteristicsResult> consume_Windows_Devices_SmartCards_ISmartCardCryptogramGenerator2<D>::GetAllCryptogramMaterialCharacteristicsAsync(Windows::Devices::SmartCards::SmartCardUnlockPromptingBehavior const& promptingBehavior, param::hstring const& materialPackageName) const
{
    Windows::Foundation::IAsyncOperation<Windows::Devices::SmartCards::SmartCardCryptogramGetAllCryptogramMaterialCharacteristicsResult> result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Devices::SmartCards::ISmartCardCryptogramGenerator2)->GetAllCryptogramMaterialCharacteristicsAsync(get_abi(promptingBehavior), get_abi(materialPackageName), put_abi(result)));
    return result;
}

template <typename D> Windows::Foundation::IAsyncOperation<Windows::Devices::SmartCards::SmartCardCryptogramGenerator> consume_Windows_Devices_SmartCards_ISmartCardCryptogramGeneratorStatics<D>::GetSmartCardCryptogramGeneratorAsync() const
{
    Windows::Foundation::IAsyncOperation<Windows::Devices::SmartCards::SmartCardCryptogramGenerator> result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Devices::SmartCards::ISmartCardCryptogramGeneratorStatics)->GetSmartCardCryptogramGeneratorAsync(put_abi(result)));
    return result;
}

template <typename D> bool consume_Windows_Devices_SmartCards_ISmartCardCryptogramGeneratorStatics2<D>::IsSupported() const
{
    bool result{};
    check_hresult(WINRT_SHIM(Windows::Devices::SmartCards::ISmartCardCryptogramGeneratorStatics2)->IsSupported(&result));
    return result;
}

template <typename D> Windows::Devices::SmartCards::SmartCardCryptogramGeneratorOperationStatus consume_Windows_Devices_SmartCards_ISmartCardCryptogramGetAllCryptogramMaterialCharacteristicsResult<D>::OperationStatus() const
{
    Windows::Devices::SmartCards::SmartCardCryptogramGeneratorOperationStatus value{};
    check_hresult(WINRT_SHIM(Windows::Devices::SmartCards::ISmartCardCryptogramGetAllCryptogramMaterialCharacteristicsResult)->get_OperationStatus(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::Collections::IVectorView<Windows::Devices::SmartCards::SmartCardCryptogramMaterialCharacteristics> consume_Windows_Devices_SmartCards_ISmartCardCryptogramGetAllCryptogramMaterialCharacteristicsResult<D>::Characteristics() const
{
    Windows::Foundation::Collections::IVectorView<Windows::Devices::SmartCards::SmartCardCryptogramMaterialCharacteristics> value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Devices::SmartCards::ISmartCardCryptogramGetAllCryptogramMaterialCharacteristicsResult)->get_Characteristics(put_abi(value)));
    return value;
}

template <typename D> Windows::Devices::SmartCards::SmartCardCryptogramGeneratorOperationStatus consume_Windows_Devices_SmartCards_ISmartCardCryptogramGetAllCryptogramMaterialPackageCharacteristicsResult<D>::OperationStatus() const
{
    Windows::Devices::SmartCards::SmartCardCryptogramGeneratorOperationStatus value{};
    check_hresult(WINRT_SHIM(Windows::Devices::SmartCards::ISmartCardCryptogramGetAllCryptogramMaterialPackageCharacteristicsResult)->get_OperationStatus(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::Collections::IVectorView<Windows::Devices::SmartCards::SmartCardCryptogramMaterialPackageCharacteristics> consume_Windows_Devices_SmartCards_ISmartCardCryptogramGetAllCryptogramMaterialPackageCharacteristicsResult<D>::Characteristics() const
{
    Windows::Foundation::Collections::IVectorView<Windows::Devices::SmartCards::SmartCardCryptogramMaterialPackageCharacteristics> value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Devices::SmartCards::ISmartCardCryptogramGetAllCryptogramMaterialPackageCharacteristicsResult)->get_Characteristics(put_abi(value)));
    return value;
}

template <typename D> Windows::Devices::SmartCards::SmartCardCryptogramGeneratorOperationStatus consume_Windows_Devices_SmartCards_ISmartCardCryptogramGetAllCryptogramStorageKeyCharacteristicsResult<D>::OperationStatus() const
{
    Windows::Devices::SmartCards::SmartCardCryptogramGeneratorOperationStatus value{};
    check_hresult(WINRT_SHIM(Windows::Devices::SmartCards::ISmartCardCryptogramGetAllCryptogramStorageKeyCharacteristicsResult)->get_OperationStatus(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::Collections::IVectorView<Windows::Devices::SmartCards::SmartCardCryptogramStorageKeyCharacteristics> consume_Windows_Devices_SmartCards_ISmartCardCryptogramGetAllCryptogramStorageKeyCharacteristicsResult<D>::Characteristics() const
{
    Windows::Foundation::Collections::IVectorView<Windows::Devices::SmartCards::SmartCardCryptogramStorageKeyCharacteristics> value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Devices::SmartCards::ISmartCardCryptogramGetAllCryptogramStorageKeyCharacteristicsResult)->get_Characteristics(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_Devices_SmartCards_ISmartCardCryptogramMaterialCharacteristics<D>::MaterialName() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Devices::SmartCards::ISmartCardCryptogramMaterialCharacteristics)->get_MaterialName(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::Collections::IVectorView<Windows::Devices::SmartCards::SmartCardCryptogramAlgorithm> consume_Windows_Devices_SmartCards_ISmartCardCryptogramMaterialCharacteristics<D>::AllowedAlgorithms() const
{
    Windows::Foundation::Collections::IVectorView<Windows::Devices::SmartCards::SmartCardCryptogramAlgorithm> value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Devices::SmartCards::ISmartCardCryptogramMaterialCharacteristics)->get_AllowedAlgorithms(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::Collections::IVectorView<Windows::Devices::SmartCards::SmartCardCryptogramMaterialPackageConfirmationResponseFormat> consume_Windows_Devices_SmartCards_ISmartCardCryptogramMaterialCharacteristics<D>::AllowedProofOfPossessionAlgorithms() const
{
    Windows::Foundation::Collections::IVectorView<Windows::Devices::SmartCards::SmartCardCryptogramMaterialPackageConfirmationResponseFormat> value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Devices::SmartCards::ISmartCardCryptogramMaterialCharacteristics)->get_AllowedProofOfPossessionAlgorithms(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::Collections::IVectorView<Windows::Devices::SmartCards::SmartCardCryptogramAlgorithm> consume_Windows_Devices_SmartCards_ISmartCardCryptogramMaterialCharacteristics<D>::AllowedValidations() const
{
    Windows::Foundation::Collections::IVectorView<Windows::Devices::SmartCards::SmartCardCryptogramAlgorithm> value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Devices::SmartCards::ISmartCardCryptogramMaterialCharacteristics)->get_AllowedValidations(put_abi(value)));
    return value;
}

template <typename D> Windows::Devices::SmartCards::SmartCardCryptogramMaterialType consume_Windows_Devices_SmartCards_ISmartCardCryptogramMaterialCharacteristics<D>::MaterialType() const
{
    Windows::Devices::SmartCards::SmartCardCryptogramMaterialType value{};
    check_hresult(WINRT_SHIM(Windows::Devices::SmartCards::ISmartCardCryptogramMaterialCharacteristics)->get_MaterialType(put_abi(value)));
    return value;
}

template <typename D> Windows::Devices::SmartCards::SmartCardCryptogramMaterialProtectionMethod consume_Windows_Devices_SmartCards_ISmartCardCryptogramMaterialCharacteristics<D>::ProtectionMethod() const
{
    Windows::Devices::SmartCards::SmartCardCryptogramMaterialProtectionMethod value{};
    check_hresult(WINRT_SHIM(Windows::Devices::SmartCards::ISmartCardCryptogramMaterialCharacteristics)->get_ProtectionMethod(put_abi(value)));
    return value;
}

template <typename D> int32_t consume_Windows_Devices_SmartCards_ISmartCardCryptogramMaterialCharacteristics<D>::ProtectionVersion() const
{
    int32_t value{};
    check_hresult(WINRT_SHIM(Windows::Devices::SmartCards::ISmartCardCryptogramMaterialCharacteristics)->get_ProtectionVersion(&value));
    return value;
}

template <typename D> int32_t consume_Windows_Devices_SmartCards_ISmartCardCryptogramMaterialCharacteristics<D>::MaterialLength() const
{
    int32_t value{};
    check_hresult(WINRT_SHIM(Windows::Devices::SmartCards::ISmartCardCryptogramMaterialCharacteristics)->get_MaterialLength(&value));
    return value;
}

template <typename D> hstring consume_Windows_Devices_SmartCards_ISmartCardCryptogramMaterialPackageCharacteristics<D>::PackageName() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Devices::SmartCards::ISmartCardCryptogramMaterialPackageCharacteristics)->get_PackageName(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_Devices_SmartCards_ISmartCardCryptogramMaterialPackageCharacteristics<D>::StorageKeyName() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Devices::SmartCards::ISmartCardCryptogramMaterialPackageCharacteristics)->get_StorageKeyName(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::DateTime consume_Windows_Devices_SmartCards_ISmartCardCryptogramMaterialPackageCharacteristics<D>::DateImported() const
{
    Windows::Foundation::DateTime value{};
    check_hresult(WINRT_SHIM(Windows::Devices::SmartCards::ISmartCardCryptogramMaterialPackageCharacteristics)->get_DateImported(put_abi(value)));
    return value;
}

template <typename D> Windows::Devices::SmartCards::SmartCardCryptogramMaterialPackageFormat consume_Windows_Devices_SmartCards_ISmartCardCryptogramMaterialPackageCharacteristics<D>::PackageFormat() const
{
    Windows::Devices::SmartCards::SmartCardCryptogramMaterialPackageFormat value{};
    check_hresult(WINRT_SHIM(Windows::Devices::SmartCards::ISmartCardCryptogramMaterialPackageCharacteristics)->get_PackageFormat(put_abi(value)));
    return value;
}

template <typename D> Windows::Devices::SmartCards::SmartCardCryptogramGeneratorOperationStatus consume_Windows_Devices_SmartCards_ISmartCardCryptogramMaterialPossessionProof<D>::OperationStatus() const
{
    Windows::Devices::SmartCards::SmartCardCryptogramGeneratorOperationStatus value{};
    check_hresult(WINRT_SHIM(Windows::Devices::SmartCards::ISmartCardCryptogramMaterialPossessionProof)->get_OperationStatus(put_abi(value)));
    return value;
}

template <typename D> Windows::Storage::Streams::IBuffer consume_Windows_Devices_SmartCards_ISmartCardCryptogramMaterialPossessionProof<D>::Proof() const
{
    Windows::Storage::Streams::IBuffer value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Devices::SmartCards::ISmartCardCryptogramMaterialPossessionProof)->get_Proof(put_abi(value)));
    return value;
}

template <typename D> Windows::Devices::SmartCards::SmartCardCryptogramAlgorithm consume_Windows_Devices_SmartCards_ISmartCardCryptogramPlacementStep<D>::Algorithm() const
{
    Windows::Devices::SmartCards::SmartCardCryptogramAlgorithm value{};
    check_hresult(WINRT_SHIM(Windows::Devices::SmartCards::ISmartCardCryptogramPlacementStep)->get_Algorithm(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_Devices_SmartCards_ISmartCardCryptogramPlacementStep<D>::Algorithm(Windows::Devices::SmartCards::SmartCardCryptogramAlgorithm const& value) const
{
    check_hresult(WINRT_SHIM(Windows::Devices::SmartCards::ISmartCardCryptogramPlacementStep)->put_Algorithm(get_abi(value)));
}

template <typename D> Windows::Storage::Streams::IBuffer consume_Windows_Devices_SmartCards_ISmartCardCryptogramPlacementStep<D>::SourceData() const
{
    Windows::Storage::Streams::IBuffer value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Devices::SmartCards::ISmartCardCryptogramPlacementStep)->get_SourceData(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_Devices_SmartCards_ISmartCardCryptogramPlacementStep<D>::SourceData(Windows::Storage::Streams::IBuffer const& value) const
{
    check_hresult(WINRT_SHIM(Windows::Devices::SmartCards::ISmartCardCryptogramPlacementStep)->put_SourceData(get_abi(value)));
}

template <typename D> hstring consume_Windows_Devices_SmartCards_ISmartCardCryptogramPlacementStep<D>::CryptogramMaterialPackageName() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Devices::SmartCards::ISmartCardCryptogramPlacementStep)->get_CryptogramMaterialPackageName(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_Devices_SmartCards_ISmartCardCryptogramPlacementStep<D>::CryptogramMaterialPackageName(param::hstring const& value) const
{
    check_hresult(WINRT_SHIM(Windows::Devices::SmartCards::ISmartCardCryptogramPlacementStep)->put_CryptogramMaterialPackageName(get_abi(value)));
}

template <typename D> hstring consume_Windows_Devices_SmartCards_ISmartCardCryptogramPlacementStep<D>::CryptogramMaterialName() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Devices::SmartCards::ISmartCardCryptogramPlacementStep)->get_CryptogramMaterialName(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_Devices_SmartCards_ISmartCardCryptogramPlacementStep<D>::CryptogramMaterialName(param::hstring const& value) const
{
    check_hresult(WINRT_SHIM(Windows::Devices::SmartCards::ISmartCardCryptogramPlacementStep)->put_CryptogramMaterialName(get_abi(value)));
}

template <typename D> int32_t consume_Windows_Devices_SmartCards_ISmartCardCryptogramPlacementStep<D>::TemplateOffset() const
{
    int32_t value{};
    check_hresult(WINRT_SHIM(Windows::Devices::SmartCards::ISmartCardCryptogramPlacementStep)->get_TemplateOffset(&value));
    return value;
}

template <typename D> void consume_Windows_Devices_SmartCards_ISmartCardCryptogramPlacementStep<D>::TemplateOffset(int32_t value) const
{
    check_hresult(WINRT_SHIM(Windows::Devices::SmartCards::ISmartCardCryptogramPlacementStep)->put_TemplateOffset(value));
}

template <typename D> int32_t consume_Windows_Devices_SmartCards_ISmartCardCryptogramPlacementStep<D>::CryptogramOffset() const
{
    int32_t value{};
    check_hresult(WINRT_SHIM(Windows::Devices::SmartCards::ISmartCardCryptogramPlacementStep)->get_CryptogramOffset(&value));
    return value;
}

template <typename D> void consume_Windows_Devices_SmartCards_ISmartCardCryptogramPlacementStep<D>::CryptogramOffset(int32_t value) const
{
    check_hresult(WINRT_SHIM(Windows::Devices::SmartCards::ISmartCardCryptogramPlacementStep)->put_CryptogramOffset(value));
}

template <typename D> int32_t consume_Windows_Devices_SmartCards_ISmartCardCryptogramPlacementStep<D>::CryptogramLength() const
{
    int32_t value{};
    check_hresult(WINRT_SHIM(Windows::Devices::SmartCards::ISmartCardCryptogramPlacementStep)->get_CryptogramLength(&value));
    return value;
}

template <typename D> void consume_Windows_Devices_SmartCards_ISmartCardCryptogramPlacementStep<D>::CryptogramLength(int32_t value) const
{
    check_hresult(WINRT_SHIM(Windows::Devices::SmartCards::ISmartCardCryptogramPlacementStep)->put_CryptogramLength(value));
}

template <typename D> Windows::Devices::SmartCards::SmartCardCryptogramPlacementOptions consume_Windows_Devices_SmartCards_ISmartCardCryptogramPlacementStep<D>::CryptogramPlacementOptions() const
{
    Windows::Devices::SmartCards::SmartCardCryptogramPlacementOptions value{};
    check_hresult(WINRT_SHIM(Windows::Devices::SmartCards::ISmartCardCryptogramPlacementStep)->get_CryptogramPlacementOptions(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_Devices_SmartCards_ISmartCardCryptogramPlacementStep<D>::CryptogramPlacementOptions(Windows::Devices::SmartCards::SmartCardCryptogramPlacementOptions const& value) const
{
    check_hresult(WINRT_SHIM(Windows::Devices::SmartCards::ISmartCardCryptogramPlacementStep)->put_CryptogramPlacementOptions(get_abi(value)));
}

template <typename D> Windows::Devices::SmartCards::SmartCardCryptogramPlacementStep consume_Windows_Devices_SmartCards_ISmartCardCryptogramPlacementStep<D>::ChainedOutputStep() const
{
    Windows::Devices::SmartCards::SmartCardCryptogramPlacementStep value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Devices::SmartCards::ISmartCardCryptogramPlacementStep)->get_ChainedOutputStep(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_Devices_SmartCards_ISmartCardCryptogramPlacementStep<D>::ChainedOutputStep(Windows::Devices::SmartCards::SmartCardCryptogramPlacementStep const& value) const
{
    check_hresult(WINRT_SHIM(Windows::Devices::SmartCards::ISmartCardCryptogramPlacementStep)->put_ChainedOutputStep(get_abi(value)));
}

template <typename D> hstring consume_Windows_Devices_SmartCards_ISmartCardCryptogramStorageKeyCharacteristics<D>::StorageKeyName() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Devices::SmartCards::ISmartCardCryptogramStorageKeyCharacteristics)->get_StorageKeyName(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::DateTime consume_Windows_Devices_SmartCards_ISmartCardCryptogramStorageKeyCharacteristics<D>::DateCreated() const
{
    Windows::Foundation::DateTime value{};
    check_hresult(WINRT_SHIM(Windows::Devices::SmartCards::ISmartCardCryptogramStorageKeyCharacteristics)->get_DateCreated(put_abi(value)));
    return value;
}

template <typename D> Windows::Devices::SmartCards::SmartCardCryptogramStorageKeyAlgorithm consume_Windows_Devices_SmartCards_ISmartCardCryptogramStorageKeyCharacteristics<D>::Algorithm() const
{
    Windows::Devices::SmartCards::SmartCardCryptogramStorageKeyAlgorithm value{};
    check_hresult(WINRT_SHIM(Windows::Devices::SmartCards::ISmartCardCryptogramStorageKeyCharacteristics)->get_Algorithm(put_abi(value)));
    return value;
}

template <typename D> Windows::Devices::SmartCards::SmartCardCryptogramStorageKeyCapabilities consume_Windows_Devices_SmartCards_ISmartCardCryptogramStorageKeyCharacteristics<D>::Capabilities() const
{
    Windows::Devices::SmartCards::SmartCardCryptogramStorageKeyCapabilities value{};
    check_hresult(WINRT_SHIM(Windows::Devices::SmartCards::ISmartCardCryptogramStorageKeyCharacteristics)->get_Capabilities(put_abi(value)));
    return value;
}

template <typename D> Windows::Devices::SmartCards::SmartCardCryptogramGeneratorOperationStatus consume_Windows_Devices_SmartCards_ISmartCardCryptogramStorageKeyInfo<D>::OperationStatus() const
{
    Windows::Devices::SmartCards::SmartCardCryptogramGeneratorOperationStatus value{};
    check_hresult(WINRT_SHIM(Windows::Devices::SmartCards::ISmartCardCryptogramStorageKeyInfo)->get_OperationStatus(put_abi(value)));
    return value;
}

template <typename D> Windows::Security::Cryptography::Core::CryptographicPublicKeyBlobType consume_Windows_Devices_SmartCards_ISmartCardCryptogramStorageKeyInfo<D>::PublicKeyBlobType() const
{
    Windows::Security::Cryptography::Core::CryptographicPublicKeyBlobType value{};
    check_hresult(WINRT_SHIM(Windows::Devices::SmartCards::ISmartCardCryptogramStorageKeyInfo)->get_PublicKeyBlobType(put_abi(value)));
    return value;
}

template <typename D> Windows::Storage::Streams::IBuffer consume_Windows_Devices_SmartCards_ISmartCardCryptogramStorageKeyInfo<D>::PublicKey() const
{
    Windows::Storage::Streams::IBuffer value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Devices::SmartCards::ISmartCardCryptogramStorageKeyInfo)->get_PublicKey(put_abi(value)));
    return value;
}

template <typename D> Windows::Devices::SmartCards::SmartCardCryptographicKeyAttestationStatus consume_Windows_Devices_SmartCards_ISmartCardCryptogramStorageKeyInfo<D>::AttestationStatus() const
{
    Windows::Devices::SmartCards::SmartCardCryptographicKeyAttestationStatus value{};
    check_hresult(WINRT_SHIM(Windows::Devices::SmartCards::ISmartCardCryptogramStorageKeyInfo)->get_AttestationStatus(put_abi(value)));
    return value;
}

template <typename D> Windows::Storage::Streams::IBuffer consume_Windows_Devices_SmartCards_ISmartCardCryptogramStorageKeyInfo<D>::Attestation() const
{
    Windows::Storage::Streams::IBuffer value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Devices::SmartCards::ISmartCardCryptogramStorageKeyInfo)->get_Attestation(put_abi(value)));
    return value;
}

template <typename D> Windows::Storage::Streams::IBuffer consume_Windows_Devices_SmartCards_ISmartCardCryptogramStorageKeyInfo<D>::AttestationCertificateChain() const
{
    Windows::Storage::Streams::IBuffer value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Devices::SmartCards::ISmartCardCryptogramStorageKeyInfo)->get_AttestationCertificateChain(put_abi(value)));
    return value;
}

template <typename D> Windows::Devices::SmartCards::SmartCardCryptogramStorageKeyCapabilities consume_Windows_Devices_SmartCards_ISmartCardCryptogramStorageKeyInfo<D>::Capabilities() const
{
    Windows::Devices::SmartCards::SmartCardCryptogramStorageKeyCapabilities value{};
    check_hresult(WINRT_SHIM(Windows::Devices::SmartCards::ISmartCardCryptogramStorageKeyInfo)->get_Capabilities(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_Devices_SmartCards_ISmartCardCryptogramStorageKeyInfo2<D>::OperationalRequirements() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Devices::SmartCards::ISmartCardCryptogramStorageKeyInfo2)->get_OperationalRequirements(put_abi(value)));
    return value;
}

template <typename D> Windows::Devices::SmartCards::SmartCardEmulatorEnablementPolicy consume_Windows_Devices_SmartCards_ISmartCardEmulator<D>::EnablementPolicy() const
{
    Windows::Devices::SmartCards::SmartCardEmulatorEnablementPolicy value{};
    check_hresult(WINRT_SHIM(Windows::Devices::SmartCards::ISmartCardEmulator)->get_EnablementPolicy(put_abi(value)));
    return value;
}

template <typename D> winrt::event_token consume_Windows_Devices_SmartCards_ISmartCardEmulator2<D>::ApduReceived(Windows::Foundation::TypedEventHandler<Windows::Devices::SmartCards::SmartCardEmulator, Windows::Devices::SmartCards::SmartCardEmulatorApduReceivedEventArgs> const& value) const
{
    winrt::event_token token{};
    check_hresult(WINRT_SHIM(Windows::Devices::SmartCards::ISmartCardEmulator2)->add_ApduReceived(get_abi(value), put_abi(token)));
    return token;
}

template <typename D> typename consume_Windows_Devices_SmartCards_ISmartCardEmulator2<D>::ApduReceived_revoker consume_Windows_Devices_SmartCards_ISmartCardEmulator2<D>::ApduReceived(auto_revoke_t, Windows::Foundation::TypedEventHandler<Windows::Devices::SmartCards::SmartCardEmulator, Windows::Devices::SmartCards::SmartCardEmulatorApduReceivedEventArgs> const& value) const
{
    return impl::make_event_revoker<D, ApduReceived_revoker>(this, ApduReceived(value));
}

template <typename D> void consume_Windows_Devices_SmartCards_ISmartCardEmulator2<D>::ApduReceived(winrt::event_token const& value) const noexcept
{
    WINRT_VERIFY_(0, WINRT_SHIM(Windows::Devices::SmartCards::ISmartCardEmulator2)->remove_ApduReceived(get_abi(value)));
}

template <typename D> winrt::event_token consume_Windows_Devices_SmartCards_ISmartCardEmulator2<D>::ConnectionDeactivated(Windows::Foundation::TypedEventHandler<Windows::Devices::SmartCards::SmartCardEmulator, Windows::Devices::SmartCards::SmartCardEmulatorConnectionDeactivatedEventArgs> const& value) const
{
    winrt::event_token token{};
    check_hresult(WINRT_SHIM(Windows::Devices::SmartCards::ISmartCardEmulator2)->add_ConnectionDeactivated(get_abi(value), put_abi(token)));
    return token;
}

template <typename D> typename consume_Windows_Devices_SmartCards_ISmartCardEmulator2<D>::ConnectionDeactivated_revoker consume_Windows_Devices_SmartCards_ISmartCardEmulator2<D>::ConnectionDeactivated(auto_revoke_t, Windows::Foundation::TypedEventHandler<Windows::Devices::SmartCards::SmartCardEmulator, Windows::Devices::SmartCards::SmartCardEmulatorConnectionDeactivatedEventArgs> const& value) const
{
    return impl::make_event_revoker<D, ConnectionDeactivated_revoker>(this, ConnectionDeactivated(value));
}

template <typename D> void consume_Windows_Devices_SmartCards_ISmartCardEmulator2<D>::ConnectionDeactivated(winrt::event_token const& value) const noexcept
{
    WINRT_VERIFY_(0, WINRT_SHIM(Windows::Devices::SmartCards::ISmartCardEmulator2)->remove_ConnectionDeactivated(get_abi(value)));
}

template <typename D> void consume_Windows_Devices_SmartCards_ISmartCardEmulator2<D>::Start() const
{
    check_hresult(WINRT_SHIM(Windows::Devices::SmartCards::ISmartCardEmulator2)->Start());
}

template <typename D> bool consume_Windows_Devices_SmartCards_ISmartCardEmulator2<D>::IsHostCardEmulationSupported() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::Devices::SmartCards::ISmartCardEmulator2)->IsHostCardEmulationSupported(&value));
    return value;
}

template <typename D> Windows::Storage::Streams::IBuffer consume_Windows_Devices_SmartCards_ISmartCardEmulatorApduReceivedEventArgs<D>::CommandApdu() const
{
    Windows::Storage::Streams::IBuffer value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Devices::SmartCards::ISmartCardEmulatorApduReceivedEventArgs)->get_CommandApdu(put_abi(value)));
    return value;
}

template <typename D> Windows::Devices::SmartCards::SmartCardEmulatorConnectionProperties consume_Windows_Devices_SmartCards_ISmartCardEmulatorApduReceivedEventArgs<D>::ConnectionProperties() const
{
    Windows::Devices::SmartCards::SmartCardEmulatorConnectionProperties value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Devices::SmartCards::ISmartCardEmulatorApduReceivedEventArgs)->get_ConnectionProperties(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::IAsyncOperation<bool> consume_Windows_Devices_SmartCards_ISmartCardEmulatorApduReceivedEventArgs<D>::TryRespondAsync(Windows::Storage::Streams::IBuffer const& responseApdu) const
{
    Windows::Foundation::IAsyncOperation<bool> result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Devices::SmartCards::ISmartCardEmulatorApduReceivedEventArgs)->TryRespondAsync(get_abi(responseApdu), put_abi(result)));
    return result;
}

template <typename D> Windows::Devices::SmartCards::SmartCardAutomaticResponseStatus consume_Windows_Devices_SmartCards_ISmartCardEmulatorApduReceivedEventArgs<D>::AutomaticResponseStatus() const
{
    Windows::Devices::SmartCards::SmartCardAutomaticResponseStatus value{};
    check_hresult(WINRT_SHIM(Windows::Devices::SmartCards::ISmartCardEmulatorApduReceivedEventArgs)->get_AutomaticResponseStatus(put_abi(value)));
    return value;
}

template <typename D> uint32_t consume_Windows_Devices_SmartCards_ISmartCardEmulatorApduReceivedEventArgs2<D>::State() const
{
    uint32_t value{};
    check_hresult(WINRT_SHIM(Windows::Devices::SmartCards::ISmartCardEmulatorApduReceivedEventArgs2)->get_State(&value));
    return value;
}

template <typename D> Windows::Foundation::IAsyncOperation<bool> consume_Windows_Devices_SmartCards_ISmartCardEmulatorApduReceivedEventArgs2<D>::TryRespondAsync(Windows::Storage::Streams::IBuffer const& responseApdu, optional<uint32_t> const& nextState) const
{
    Windows::Foundation::IAsyncOperation<bool> result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Devices::SmartCards::ISmartCardEmulatorApduReceivedEventArgs2)->TryRespondWithStateAsync(get_abi(responseApdu), get_abi(nextState), put_abi(result)));
    return result;
}

template <typename D> Windows::Foundation::IAsyncOperation<Windows::Devices::SmartCards::SmartCardCryptogramGeneratorOperationStatus> consume_Windows_Devices_SmartCards_ISmartCardEmulatorApduReceivedEventArgsWithCryptograms<D>::TryRespondWithCryptogramsAsync(Windows::Storage::Streams::IBuffer const& responseTemplate, param::async_iterable<Windows::Devices::SmartCards::SmartCardCryptogramPlacementStep> const& cryptogramPlacementSteps) const
{
    Windows::Foundation::IAsyncOperation<Windows::Devices::SmartCards::SmartCardCryptogramGeneratorOperationStatus> result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Devices::SmartCards::ISmartCardEmulatorApduReceivedEventArgsWithCryptograms)->TryRespondWithCryptogramsAsync(get_abi(responseTemplate), get_abi(cryptogramPlacementSteps), put_abi(result)));
    return result;
}

template <typename D> Windows::Foundation::IAsyncOperation<Windows::Devices::SmartCards::SmartCardCryptogramGeneratorOperationStatus> consume_Windows_Devices_SmartCards_ISmartCardEmulatorApduReceivedEventArgsWithCryptograms<D>::TryRespondWithCryptogramsAsync(Windows::Storage::Streams::IBuffer const& responseTemplate, param::async_iterable<Windows::Devices::SmartCards::SmartCardCryptogramPlacementStep> const& cryptogramPlacementSteps, optional<uint32_t> const& nextState) const
{
    Windows::Foundation::IAsyncOperation<Windows::Devices::SmartCards::SmartCardCryptogramGeneratorOperationStatus> result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Devices::SmartCards::ISmartCardEmulatorApduReceivedEventArgsWithCryptograms)->TryRespondWithCryptogramsAndStateAsync(get_abi(responseTemplate), get_abi(cryptogramPlacementSteps), get_abi(nextState), put_abi(result)));
    return result;
}

template <typename D> Windows::Devices::SmartCards::SmartCardEmulatorConnectionProperties consume_Windows_Devices_SmartCards_ISmartCardEmulatorConnectionDeactivatedEventArgs<D>::ConnectionProperties() const
{
    Windows::Devices::SmartCards::SmartCardEmulatorConnectionProperties value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Devices::SmartCards::ISmartCardEmulatorConnectionDeactivatedEventArgs)->get_ConnectionProperties(put_abi(value)));
    return value;
}

template <typename D> Windows::Devices::SmartCards::SmartCardEmulatorConnectionDeactivatedReason consume_Windows_Devices_SmartCards_ISmartCardEmulatorConnectionDeactivatedEventArgs<D>::Reason() const
{
    Windows::Devices::SmartCards::SmartCardEmulatorConnectionDeactivatedReason value{};
    check_hresult(WINRT_SHIM(Windows::Devices::SmartCards::ISmartCardEmulatorConnectionDeactivatedEventArgs)->get_Reason(put_abi(value)));
    return value;
}

template <typename D> winrt::guid consume_Windows_Devices_SmartCards_ISmartCardEmulatorConnectionProperties<D>::Id() const
{
    winrt::guid value{};
    check_hresult(WINRT_SHIM(Windows::Devices::SmartCards::ISmartCardEmulatorConnectionProperties)->get_Id(put_abi(value)));
    return value;
}

template <typename D> Windows::Devices::SmartCards::SmartCardEmulatorConnectionSource consume_Windows_Devices_SmartCards_ISmartCardEmulatorConnectionProperties<D>::Source() const
{
    Windows::Devices::SmartCards::SmartCardEmulatorConnectionSource value{};
    check_hresult(WINRT_SHIM(Windows::Devices::SmartCards::ISmartCardEmulatorConnectionProperties)->get_Source(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::IAsyncOperation<Windows::Devices::SmartCards::SmartCardEmulator> consume_Windows_Devices_SmartCards_ISmartCardEmulatorStatics<D>::GetDefaultAsync() const
{
    Windows::Foundation::IAsyncOperation<Windows::Devices::SmartCards::SmartCardEmulator> result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Devices::SmartCards::ISmartCardEmulatorStatics)->GetDefaultAsync(put_abi(result)));
    return result;
}

template <typename D> Windows::Foundation::IAsyncOperation<Windows::Foundation::Collections::IVectorView<Windows::Devices::SmartCards::SmartCardAppletIdGroupRegistration>> consume_Windows_Devices_SmartCards_ISmartCardEmulatorStatics2<D>::GetAppletIdGroupRegistrationsAsync() const
{
    Windows::Foundation::IAsyncOperation<Windows::Foundation::Collections::IVectorView<Windows::Devices::SmartCards::SmartCardAppletIdGroupRegistration>> result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Devices::SmartCards::ISmartCardEmulatorStatics2)->GetAppletIdGroupRegistrationsAsync(put_abi(result)));
    return result;
}

template <typename D> Windows::Foundation::IAsyncOperation<Windows::Devices::SmartCards::SmartCardAppletIdGroupRegistration> consume_Windows_Devices_SmartCards_ISmartCardEmulatorStatics2<D>::RegisterAppletIdGroupAsync(Windows::Devices::SmartCards::SmartCardAppletIdGroup const& appletIdGroup) const
{
    Windows::Foundation::IAsyncOperation<Windows::Devices::SmartCards::SmartCardAppletIdGroupRegistration> result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Devices::SmartCards::ISmartCardEmulatorStatics2)->RegisterAppletIdGroupAsync(get_abi(appletIdGroup), put_abi(result)));
    return result;
}

template <typename D> Windows::Foundation::IAsyncAction consume_Windows_Devices_SmartCards_ISmartCardEmulatorStatics2<D>::UnregisterAppletIdGroupAsync(Windows::Devices::SmartCards::SmartCardAppletIdGroupRegistration const& registration) const
{
    Windows::Foundation::IAsyncAction result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Devices::SmartCards::ISmartCardEmulatorStatics2)->UnregisterAppletIdGroupAsync(get_abi(registration), put_abi(result)));
    return result;
}

template <typename D> uint16_t consume_Windows_Devices_SmartCards_ISmartCardEmulatorStatics2<D>::MaxAppletIdGroupRegistrations() const
{
    uint16_t value{};
    check_hresult(WINRT_SHIM(Windows::Devices::SmartCards::ISmartCardEmulatorStatics2)->get_MaxAppletIdGroupRegistrations(&value));
    return value;
}

template <typename D> bool consume_Windows_Devices_SmartCards_ISmartCardEmulatorStatics3<D>::IsSupported() const
{
    bool result{};
    check_hresult(WINRT_SHIM(Windows::Devices::SmartCards::ISmartCardEmulatorStatics3)->IsSupported(&result));
    return result;
}

template <typename D> uint32_t consume_Windows_Devices_SmartCards_ISmartCardPinPolicy<D>::MinLength() const
{
    uint32_t value{};
    check_hresult(WINRT_SHIM(Windows::Devices::SmartCards::ISmartCardPinPolicy)->get_MinLength(&value));
    return value;
}

template <typename D> void consume_Windows_Devices_SmartCards_ISmartCardPinPolicy<D>::MinLength(uint32_t value) const
{
    check_hresult(WINRT_SHIM(Windows::Devices::SmartCards::ISmartCardPinPolicy)->put_MinLength(value));
}

template <typename D> uint32_t consume_Windows_Devices_SmartCards_ISmartCardPinPolicy<D>::MaxLength() const
{
    uint32_t value{};
    check_hresult(WINRT_SHIM(Windows::Devices::SmartCards::ISmartCardPinPolicy)->get_MaxLength(&value));
    return value;
}

template <typename D> void consume_Windows_Devices_SmartCards_ISmartCardPinPolicy<D>::MaxLength(uint32_t value) const
{
    check_hresult(WINRT_SHIM(Windows::Devices::SmartCards::ISmartCardPinPolicy)->put_MaxLength(value));
}

template <typename D> Windows::Devices::SmartCards::SmartCardPinCharacterPolicyOption consume_Windows_Devices_SmartCards_ISmartCardPinPolicy<D>::UppercaseLetters() const
{
    Windows::Devices::SmartCards::SmartCardPinCharacterPolicyOption value{};
    check_hresult(WINRT_SHIM(Windows::Devices::SmartCards::ISmartCardPinPolicy)->get_UppercaseLetters(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_Devices_SmartCards_ISmartCardPinPolicy<D>::UppercaseLetters(Windows::Devices::SmartCards::SmartCardPinCharacterPolicyOption const& value) const
{
    check_hresult(WINRT_SHIM(Windows::Devices::SmartCards::ISmartCardPinPolicy)->put_UppercaseLetters(get_abi(value)));
}

template <typename D> Windows::Devices::SmartCards::SmartCardPinCharacterPolicyOption consume_Windows_Devices_SmartCards_ISmartCardPinPolicy<D>::LowercaseLetters() const
{
    Windows::Devices::SmartCards::SmartCardPinCharacterPolicyOption value{};
    check_hresult(WINRT_SHIM(Windows::Devices::SmartCards::ISmartCardPinPolicy)->get_LowercaseLetters(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_Devices_SmartCards_ISmartCardPinPolicy<D>::LowercaseLetters(Windows::Devices::SmartCards::SmartCardPinCharacterPolicyOption const& value) const
{
    check_hresult(WINRT_SHIM(Windows::Devices::SmartCards::ISmartCardPinPolicy)->put_LowercaseLetters(get_abi(value)));
}

template <typename D> Windows::Devices::SmartCards::SmartCardPinCharacterPolicyOption consume_Windows_Devices_SmartCards_ISmartCardPinPolicy<D>::Digits() const
{
    Windows::Devices::SmartCards::SmartCardPinCharacterPolicyOption value{};
    check_hresult(WINRT_SHIM(Windows::Devices::SmartCards::ISmartCardPinPolicy)->get_Digits(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_Devices_SmartCards_ISmartCardPinPolicy<D>::Digits(Windows::Devices::SmartCards::SmartCardPinCharacterPolicyOption const& value) const
{
    check_hresult(WINRT_SHIM(Windows::Devices::SmartCards::ISmartCardPinPolicy)->put_Digits(get_abi(value)));
}

template <typename D> Windows::Devices::SmartCards::SmartCardPinCharacterPolicyOption consume_Windows_Devices_SmartCards_ISmartCardPinPolicy<D>::SpecialCharacters() const
{
    Windows::Devices::SmartCards::SmartCardPinCharacterPolicyOption value{};
    check_hresult(WINRT_SHIM(Windows::Devices::SmartCards::ISmartCardPinPolicy)->get_SpecialCharacters(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_Devices_SmartCards_ISmartCardPinPolicy<D>::SpecialCharacters(Windows::Devices::SmartCards::SmartCardPinCharacterPolicyOption const& value) const
{
    check_hresult(WINRT_SHIM(Windows::Devices::SmartCards::ISmartCardPinPolicy)->put_SpecialCharacters(get_abi(value)));
}

template <typename D> void consume_Windows_Devices_SmartCards_ISmartCardPinResetDeferral<D>::Complete() const
{
    check_hresult(WINRT_SHIM(Windows::Devices::SmartCards::ISmartCardPinResetDeferral)->Complete());
}

template <typename D> Windows::Storage::Streams::IBuffer consume_Windows_Devices_SmartCards_ISmartCardPinResetRequest<D>::Challenge() const
{
    Windows::Storage::Streams::IBuffer value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Devices::SmartCards::ISmartCardPinResetRequest)->get_Challenge(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::DateTime consume_Windows_Devices_SmartCards_ISmartCardPinResetRequest<D>::Deadline() const
{
    Windows::Foundation::DateTime value{};
    check_hresult(WINRT_SHIM(Windows::Devices::SmartCards::ISmartCardPinResetRequest)->get_Deadline(put_abi(value)));
    return value;
}

template <typename D> Windows::Devices::SmartCards::SmartCardPinResetDeferral consume_Windows_Devices_SmartCards_ISmartCardPinResetRequest<D>::GetDeferral() const
{
    Windows::Devices::SmartCards::SmartCardPinResetDeferral result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Devices::SmartCards::ISmartCardPinResetRequest)->GetDeferral(put_abi(result)));
    return result;
}

template <typename D> void consume_Windows_Devices_SmartCards_ISmartCardPinResetRequest<D>::SetResponse(Windows::Storage::Streams::IBuffer const& response) const
{
    check_hresult(WINRT_SHIM(Windows::Devices::SmartCards::ISmartCardPinResetRequest)->SetResponse(get_abi(response)));
}

template <typename D> Windows::Devices::SmartCards::SmartCard consume_Windows_Devices_SmartCards_ISmartCardProvisioning<D>::SmartCard() const
{
    Windows::Devices::SmartCards::SmartCard value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Devices::SmartCards::ISmartCardProvisioning)->get_SmartCard(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::IAsyncOperation<winrt::guid> consume_Windows_Devices_SmartCards_ISmartCardProvisioning<D>::GetIdAsync() const
{
    Windows::Foundation::IAsyncOperation<winrt::guid> result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Devices::SmartCards::ISmartCardProvisioning)->GetIdAsync(put_abi(result)));
    return result;
}

template <typename D> Windows::Foundation::IAsyncOperation<hstring> consume_Windows_Devices_SmartCards_ISmartCardProvisioning<D>::GetNameAsync() const
{
    Windows::Foundation::IAsyncOperation<hstring> result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Devices::SmartCards::ISmartCardProvisioning)->GetNameAsync(put_abi(result)));
    return result;
}

template <typename D> Windows::Foundation::IAsyncOperation<Windows::Devices::SmartCards::SmartCardChallengeContext> consume_Windows_Devices_SmartCards_ISmartCardProvisioning<D>::GetChallengeContextAsync() const
{
    Windows::Foundation::IAsyncOperation<Windows::Devices::SmartCards::SmartCardChallengeContext> result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Devices::SmartCards::ISmartCardProvisioning)->GetChallengeContextAsync(put_abi(result)));
    return result;
}

template <typename D> Windows::Foundation::IAsyncOperation<bool> consume_Windows_Devices_SmartCards_ISmartCardProvisioning<D>::RequestPinChangeAsync() const
{
    Windows::Foundation::IAsyncOperation<bool> result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Devices::SmartCards::ISmartCardProvisioning)->RequestPinChangeAsync(put_abi(result)));
    return result;
}

template <typename D> Windows::Foundation::IAsyncOperation<bool> consume_Windows_Devices_SmartCards_ISmartCardProvisioning<D>::RequestPinResetAsync(Windows::Devices::SmartCards::SmartCardPinResetHandler const& handler) const
{
    Windows::Foundation::IAsyncOperation<bool> result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Devices::SmartCards::ISmartCardProvisioning)->RequestPinResetAsync(get_abi(handler), put_abi(result)));
    return result;
}

template <typename D> Windows::Foundation::IAsyncOperation<hstring> consume_Windows_Devices_SmartCards_ISmartCardProvisioning2<D>::GetAuthorityKeyContainerNameAsync() const
{
    Windows::Foundation::IAsyncOperation<hstring> result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Devices::SmartCards::ISmartCardProvisioning2)->GetAuthorityKeyContainerNameAsync(put_abi(result)));
    return result;
}

template <typename D> Windows::Foundation::IAsyncOperation<Windows::Devices::SmartCards::SmartCardProvisioning> consume_Windows_Devices_SmartCards_ISmartCardProvisioningStatics<D>::FromSmartCardAsync(Windows::Devices::SmartCards::SmartCard const& card) const
{
    Windows::Foundation::IAsyncOperation<Windows::Devices::SmartCards::SmartCardProvisioning> result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Devices::SmartCards::ISmartCardProvisioningStatics)->FromSmartCardAsync(get_abi(card), put_abi(result)));
    return result;
}

template <typename D> Windows::Foundation::IAsyncOperation<Windows::Devices::SmartCards::SmartCardProvisioning> consume_Windows_Devices_SmartCards_ISmartCardProvisioningStatics<D>::RequestVirtualSmartCardCreationAsync(param::hstring const& friendlyName, Windows::Storage::Streams::IBuffer const& administrativeKey, Windows::Devices::SmartCards::SmartCardPinPolicy const& pinPolicy) const
{
    Windows::Foundation::IAsyncOperation<Windows::Devices::SmartCards::SmartCardProvisioning> result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Devices::SmartCards::ISmartCardProvisioningStatics)->RequestVirtualSmartCardCreationAsync(get_abi(friendlyName), get_abi(administrativeKey), get_abi(pinPolicy), put_abi(result)));
    return result;
}

template <typename D> Windows::Foundation::IAsyncOperation<Windows::Devices::SmartCards::SmartCardProvisioning> consume_Windows_Devices_SmartCards_ISmartCardProvisioningStatics<D>::RequestVirtualSmartCardCreationAsync(param::hstring const& friendlyName, Windows::Storage::Streams::IBuffer const& administrativeKey, Windows::Devices::SmartCards::SmartCardPinPolicy const& pinPolicy, winrt::guid const& cardId) const
{
    Windows::Foundation::IAsyncOperation<Windows::Devices::SmartCards::SmartCardProvisioning> result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Devices::SmartCards::ISmartCardProvisioningStatics)->RequestVirtualSmartCardCreationAsyncWithCardId(get_abi(friendlyName), get_abi(administrativeKey), get_abi(pinPolicy), get_abi(cardId), put_abi(result)));
    return result;
}

template <typename D> Windows::Foundation::IAsyncOperation<bool> consume_Windows_Devices_SmartCards_ISmartCardProvisioningStatics<D>::RequestVirtualSmartCardDeletionAsync(Windows::Devices::SmartCards::SmartCard const& card) const
{
    Windows::Foundation::IAsyncOperation<bool> result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Devices::SmartCards::ISmartCardProvisioningStatics)->RequestVirtualSmartCardDeletionAsync(get_abi(card), put_abi(result)));
    return result;
}

template <typename D> Windows::Foundation::IAsyncOperation<Windows::Devices::SmartCards::SmartCardProvisioning> consume_Windows_Devices_SmartCards_ISmartCardProvisioningStatics2<D>::RequestAttestedVirtualSmartCardCreationAsync(param::hstring const& friendlyName, Windows::Storage::Streams::IBuffer const& administrativeKey, Windows::Devices::SmartCards::SmartCardPinPolicy const& pinPolicy) const
{
    Windows::Foundation::IAsyncOperation<Windows::Devices::SmartCards::SmartCardProvisioning> result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Devices::SmartCards::ISmartCardProvisioningStatics2)->RequestAttestedVirtualSmartCardCreationAsync(get_abi(friendlyName), get_abi(administrativeKey), get_abi(pinPolicy), put_abi(result)));
    return result;
}

template <typename D> Windows::Foundation::IAsyncOperation<Windows::Devices::SmartCards::SmartCardProvisioning> consume_Windows_Devices_SmartCards_ISmartCardProvisioningStatics2<D>::RequestAttestedVirtualSmartCardCreationAsync(param::hstring const& friendlyName, Windows::Storage::Streams::IBuffer const& administrativeKey, Windows::Devices::SmartCards::SmartCardPinPolicy const& pinPolicy, winrt::guid const& cardId) const
{
    Windows::Foundation::IAsyncOperation<Windows::Devices::SmartCards::SmartCardProvisioning> result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Devices::SmartCards::ISmartCardProvisioningStatics2)->RequestAttestedVirtualSmartCardCreationAsyncWithCardId(get_abi(friendlyName), get_abi(administrativeKey), get_abi(pinPolicy), get_abi(cardId), put_abi(result)));
    return result;
}

template <typename D> hstring consume_Windows_Devices_SmartCards_ISmartCardReader<D>::DeviceId() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Devices::SmartCards::ISmartCardReader)->get_DeviceId(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_Devices_SmartCards_ISmartCardReader<D>::Name() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Devices::SmartCards::ISmartCardReader)->get_Name(put_abi(value)));
    return value;
}

template <typename D> Windows::Devices::SmartCards::SmartCardReaderKind consume_Windows_Devices_SmartCards_ISmartCardReader<D>::Kind() const
{
    Windows::Devices::SmartCards::SmartCardReaderKind value{};
    check_hresult(WINRT_SHIM(Windows::Devices::SmartCards::ISmartCardReader)->get_Kind(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::IAsyncOperation<Windows::Devices::SmartCards::SmartCardReaderStatus> consume_Windows_Devices_SmartCards_ISmartCardReader<D>::GetStatusAsync() const
{
    Windows::Foundation::IAsyncOperation<Windows::Devices::SmartCards::SmartCardReaderStatus> result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Devices::SmartCards::ISmartCardReader)->GetStatusAsync(put_abi(result)));
    return result;
}

template <typename D> Windows::Foundation::IAsyncOperation<Windows::Foundation::Collections::IVectorView<Windows::Devices::SmartCards::SmartCard>> consume_Windows_Devices_SmartCards_ISmartCardReader<D>::FindAllCardsAsync() const
{
    Windows::Foundation::IAsyncOperation<Windows::Foundation::Collections::IVectorView<Windows::Devices::SmartCards::SmartCard>> result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Devices::SmartCards::ISmartCardReader)->FindAllCardsAsync(put_abi(result)));
    return result;
}

template <typename D> winrt::event_token consume_Windows_Devices_SmartCards_ISmartCardReader<D>::CardAdded(Windows::Foundation::TypedEventHandler<Windows::Devices::SmartCards::SmartCardReader, Windows::Devices::SmartCards::CardAddedEventArgs> const& handler) const
{
    winrt::event_token token{};
    check_hresult(WINRT_SHIM(Windows::Devices::SmartCards::ISmartCardReader)->add_CardAdded(get_abi(handler), put_abi(token)));
    return token;
}

template <typename D> typename consume_Windows_Devices_SmartCards_ISmartCardReader<D>::CardAdded_revoker consume_Windows_Devices_SmartCards_ISmartCardReader<D>::CardAdded(auto_revoke_t, Windows::Foundation::TypedEventHandler<Windows::Devices::SmartCards::SmartCardReader, Windows::Devices::SmartCards::CardAddedEventArgs> const& handler) const
{
    return impl::make_event_revoker<D, CardAdded_revoker>(this, CardAdded(handler));
}

template <typename D> void consume_Windows_Devices_SmartCards_ISmartCardReader<D>::CardAdded(winrt::event_token const& token) const noexcept
{
    WINRT_VERIFY_(0, WINRT_SHIM(Windows::Devices::SmartCards::ISmartCardReader)->remove_CardAdded(get_abi(token)));
}

template <typename D> winrt::event_token consume_Windows_Devices_SmartCards_ISmartCardReader<D>::CardRemoved(Windows::Foundation::TypedEventHandler<Windows::Devices::SmartCards::SmartCardReader, Windows::Devices::SmartCards::CardRemovedEventArgs> const& handler) const
{
    winrt::event_token token{};
    check_hresult(WINRT_SHIM(Windows::Devices::SmartCards::ISmartCardReader)->add_CardRemoved(get_abi(handler), put_abi(token)));
    return token;
}

template <typename D> typename consume_Windows_Devices_SmartCards_ISmartCardReader<D>::CardRemoved_revoker consume_Windows_Devices_SmartCards_ISmartCardReader<D>::CardRemoved(auto_revoke_t, Windows::Foundation::TypedEventHandler<Windows::Devices::SmartCards::SmartCardReader, Windows::Devices::SmartCards::CardRemovedEventArgs> const& handler) const
{
    return impl::make_event_revoker<D, CardRemoved_revoker>(this, CardRemoved(handler));
}

template <typename D> void consume_Windows_Devices_SmartCards_ISmartCardReader<D>::CardRemoved(winrt::event_token const& token) const noexcept
{
    WINRT_VERIFY_(0, WINRT_SHIM(Windows::Devices::SmartCards::ISmartCardReader)->remove_CardRemoved(get_abi(token)));
}

template <typename D> hstring consume_Windows_Devices_SmartCards_ISmartCardReaderStatics<D>::GetDeviceSelector() const
{
    hstring selector{};
    check_hresult(WINRT_SHIM(Windows::Devices::SmartCards::ISmartCardReaderStatics)->GetDeviceSelector(put_abi(selector)));
    return selector;
}

template <typename D> hstring consume_Windows_Devices_SmartCards_ISmartCardReaderStatics<D>::GetDeviceSelector(Windows::Devices::SmartCards::SmartCardReaderKind const& kind) const
{
    hstring selector{};
    check_hresult(WINRT_SHIM(Windows::Devices::SmartCards::ISmartCardReaderStatics)->GetDeviceSelectorWithKind(get_abi(kind), put_abi(selector)));
    return selector;
}

template <typename D> Windows::Foundation::IAsyncOperation<Windows::Devices::SmartCards::SmartCardReader> consume_Windows_Devices_SmartCards_ISmartCardReaderStatics<D>::FromIdAsync(param::hstring const& deviceId) const
{
    Windows::Foundation::IAsyncOperation<Windows::Devices::SmartCards::SmartCardReader> result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Devices::SmartCards::ISmartCardReaderStatics)->FromIdAsync(get_abi(deviceId), put_abi(result)));
    return result;
}

template <typename D> Windows::Devices::SmartCards::SmartCardTriggerType consume_Windows_Devices_SmartCards_ISmartCardTriggerDetails<D>::TriggerType() const
{
    Windows::Devices::SmartCards::SmartCardTriggerType value{};
    check_hresult(WINRT_SHIM(Windows::Devices::SmartCards::ISmartCardTriggerDetails)->get_TriggerType(put_abi(value)));
    return value;
}

template <typename D> Windows::Storage::Streams::IBuffer consume_Windows_Devices_SmartCards_ISmartCardTriggerDetails<D>::SourceAppletId() const
{
    Windows::Storage::Streams::IBuffer value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Devices::SmartCards::ISmartCardTriggerDetails)->get_SourceAppletId(put_abi(value)));
    return value;
}

template <typename D> Windows::Storage::Streams::IBuffer consume_Windows_Devices_SmartCards_ISmartCardTriggerDetails<D>::TriggerData() const
{
    Windows::Storage::Streams::IBuffer value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Devices::SmartCards::ISmartCardTriggerDetails)->get_TriggerData(put_abi(value)));
    return value;
}

template <typename D> Windows::Devices::SmartCards::SmartCardEmulator consume_Windows_Devices_SmartCards_ISmartCardTriggerDetails2<D>::Emulator() const
{
    Windows::Devices::SmartCards::SmartCardEmulator value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Devices::SmartCards::ISmartCardTriggerDetails2)->get_Emulator(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::IAsyncOperation<bool> consume_Windows_Devices_SmartCards_ISmartCardTriggerDetails2<D>::TryLaunchCurrentAppAsync(param::hstring const& arguments) const
{
    Windows::Foundation::IAsyncOperation<bool> result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Devices::SmartCards::ISmartCardTriggerDetails2)->TryLaunchCurrentAppAsync(get_abi(arguments), put_abi(result)));
    return result;
}

template <typename D> Windows::Foundation::IAsyncOperation<bool> consume_Windows_Devices_SmartCards_ISmartCardTriggerDetails2<D>::TryLaunchCurrentAppAsync(param::hstring const& arguments, Windows::Devices::SmartCards::SmartCardLaunchBehavior const& behavior) const
{
    Windows::Foundation::IAsyncOperation<bool> result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Devices::SmartCards::ISmartCardTriggerDetails2)->TryLaunchCurrentAppWithBehaviorAsync(get_abi(arguments), get_abi(behavior), put_abi(result)));
    return result;
}

template <typename D> Windows::Devices::SmartCards::SmartCard consume_Windows_Devices_SmartCards_ISmartCardTriggerDetails3<D>::SmartCard() const
{
    Windows::Devices::SmartCards::SmartCard value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Devices::SmartCards::ISmartCardTriggerDetails3)->get_SmartCard(put_abi(value)));
    return value;
}

template <> struct delegate<Windows::Devices::SmartCards::SmartCardPinResetHandler>
{
    template <typename H>
    struct type : implements_delegate<Windows::Devices::SmartCards::SmartCardPinResetHandler, H>
    {
        type(H&& handler) : implements_delegate<Windows::Devices::SmartCards::SmartCardPinResetHandler, H>(std::forward<H>(handler)) {}

        int32_t WINRT_CALL Invoke(void* sender, void* request) noexcept final
        {
            try
            {
                (*this)(*reinterpret_cast<Windows::Devices::SmartCards::SmartCardProvisioning const*>(&sender), *reinterpret_cast<Windows::Devices::SmartCards::SmartCardPinResetRequest const*>(&request));
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
struct produce<D, Windows::Devices::SmartCards::ICardAddedEventArgs> : produce_base<D, Windows::Devices::SmartCards::ICardAddedEventArgs>
{
    int32_t WINRT_CALL get_SmartCard(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SmartCard, WINRT_WRAP(Windows::Devices::SmartCards::SmartCard));
            *value = detach_from<Windows::Devices::SmartCards::SmartCard>(this->shim().SmartCard());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Devices::SmartCards::ICardRemovedEventArgs> : produce_base<D, Windows::Devices::SmartCards::ICardRemovedEventArgs>
{
    int32_t WINRT_CALL get_SmartCard(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SmartCard, WINRT_WRAP(Windows::Devices::SmartCards::SmartCard));
            *value = detach_from<Windows::Devices::SmartCards::SmartCard>(this->shim().SmartCard());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Devices::SmartCards::IKnownSmartCardAppletIds> : produce_base<D, Windows::Devices::SmartCards::IKnownSmartCardAppletIds>
{
    int32_t WINRT_CALL get_PaymentSystemEnvironment(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(PaymentSystemEnvironment, WINRT_WRAP(Windows::Storage::Streams::IBuffer));
            *value = detach_from<Windows::Storage::Streams::IBuffer>(this->shim().PaymentSystemEnvironment());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_ProximityPaymentSystemEnvironment(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ProximityPaymentSystemEnvironment, WINRT_WRAP(Windows::Storage::Streams::IBuffer));
            *value = detach_from<Windows::Storage::Streams::IBuffer>(this->shim().ProximityPaymentSystemEnvironment());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Devices::SmartCards::ISmartCard> : produce_base<D, Windows::Devices::SmartCards::ISmartCard>
{
    int32_t WINRT_CALL get_Reader(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Reader, WINRT_WRAP(Windows::Devices::SmartCards::SmartCardReader));
            *value = detach_from<Windows::Devices::SmartCards::SmartCardReader>(this->shim().Reader());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL GetStatusAsync(void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetStatusAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<Windows::Devices::SmartCards::SmartCardStatus>));
            *result = detach_from<Windows::Foundation::IAsyncOperation<Windows::Devices::SmartCards::SmartCardStatus>>(this->shim().GetStatusAsync());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL GetAnswerToResetAsync(void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetAnswerToResetAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<Windows::Storage::Streams::IBuffer>));
            *result = detach_from<Windows::Foundation::IAsyncOperation<Windows::Storage::Streams::IBuffer>>(this->shim().GetAnswerToResetAsync());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Devices::SmartCards::ISmartCardAppletIdGroup> : produce_base<D, Windows::Devices::SmartCards::ISmartCardAppletIdGroup>
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

    int32_t WINRT_CALL get_AppletIds(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(AppletIds, WINRT_WRAP(Windows::Foundation::Collections::IVector<Windows::Storage::Streams::IBuffer>));
            *value = detach_from<Windows::Foundation::Collections::IVector<Windows::Storage::Streams::IBuffer>>(this->shim().AppletIds());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_SmartCardEmulationCategory(Windows::Devices::SmartCards::SmartCardEmulationCategory* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SmartCardEmulationCategory, WINRT_WRAP(Windows::Devices::SmartCards::SmartCardEmulationCategory));
            *value = detach_from<Windows::Devices::SmartCards::SmartCardEmulationCategory>(this->shim().SmartCardEmulationCategory());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_SmartCardEmulationCategory(Windows::Devices::SmartCards::SmartCardEmulationCategory value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SmartCardEmulationCategory, WINRT_WRAP(void), Windows::Devices::SmartCards::SmartCardEmulationCategory const&);
            this->shim().SmartCardEmulationCategory(*reinterpret_cast<Windows::Devices::SmartCards::SmartCardEmulationCategory const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_SmartCardEmulationType(Windows::Devices::SmartCards::SmartCardEmulationType* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SmartCardEmulationType, WINRT_WRAP(Windows::Devices::SmartCards::SmartCardEmulationType));
            *value = detach_from<Windows::Devices::SmartCards::SmartCardEmulationType>(this->shim().SmartCardEmulationType());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_SmartCardEmulationType(Windows::Devices::SmartCards::SmartCardEmulationType value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SmartCardEmulationType, WINRT_WRAP(void), Windows::Devices::SmartCards::SmartCardEmulationType const&);
            this->shim().SmartCardEmulationType(*reinterpret_cast<Windows::Devices::SmartCards::SmartCardEmulationType const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_AutomaticEnablement(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(AutomaticEnablement, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().AutomaticEnablement());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_AutomaticEnablement(bool value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(AutomaticEnablement, WINRT_WRAP(void), bool);
            this->shim().AutomaticEnablement(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Devices::SmartCards::ISmartCardAppletIdGroup2> : produce_base<D, Windows::Devices::SmartCards::ISmartCardAppletIdGroup2>
{
    int32_t WINRT_CALL get_Logo(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Logo, WINRT_WRAP(Windows::Storage::Streams::IRandomAccessStreamReference));
            *value = detach_from<Windows::Storage::Streams::IRandomAccessStreamReference>(this->shim().Logo());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_Logo(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Logo, WINRT_WRAP(void), Windows::Storage::Streams::IRandomAccessStreamReference const&);
            this->shim().Logo(*reinterpret_cast<Windows::Storage::Streams::IRandomAccessStreamReference const*>(&value));
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

    int32_t WINRT_CALL get_SecureUserAuthenticationRequired(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SecureUserAuthenticationRequired, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().SecureUserAuthenticationRequired());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_SecureUserAuthenticationRequired(bool value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SecureUserAuthenticationRequired, WINRT_WRAP(void), bool);
            this->shim().SecureUserAuthenticationRequired(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Devices::SmartCards::ISmartCardAppletIdGroupFactory> : produce_base<D, Windows::Devices::SmartCards::ISmartCardAppletIdGroupFactory>
{
    int32_t WINRT_CALL Create(void* displayName, void* appletIds, Windows::Devices::SmartCards::SmartCardEmulationCategory emulationCategory, Windows::Devices::SmartCards::SmartCardEmulationType emulationType, void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Create, WINRT_WRAP(Windows::Devices::SmartCards::SmartCardAppletIdGroup), hstring const&, Windows::Foundation::Collections::IVector<Windows::Storage::Streams::IBuffer> const&, Windows::Devices::SmartCards::SmartCardEmulationCategory const&, Windows::Devices::SmartCards::SmartCardEmulationType const&);
            *result = detach_from<Windows::Devices::SmartCards::SmartCardAppletIdGroup>(this->shim().Create(*reinterpret_cast<hstring const*>(&displayName), *reinterpret_cast<Windows::Foundation::Collections::IVector<Windows::Storage::Streams::IBuffer> const*>(&appletIds), *reinterpret_cast<Windows::Devices::SmartCards::SmartCardEmulationCategory const*>(&emulationCategory), *reinterpret_cast<Windows::Devices::SmartCards::SmartCardEmulationType const*>(&emulationType)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Devices::SmartCards::ISmartCardAppletIdGroupRegistration> : produce_base<D, Windows::Devices::SmartCards::ISmartCardAppletIdGroupRegistration>
{
    int32_t WINRT_CALL get_ActivationPolicy(Windows::Devices::SmartCards::SmartCardAppletIdGroupActivationPolicy* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ActivationPolicy, WINRT_WRAP(Windows::Devices::SmartCards::SmartCardAppletIdGroupActivationPolicy));
            *value = detach_from<Windows::Devices::SmartCards::SmartCardAppletIdGroupActivationPolicy>(this->shim().ActivationPolicy());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_AppletIdGroup(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(AppletIdGroup, WINRT_WRAP(Windows::Devices::SmartCards::SmartCardAppletIdGroup));
            *value = detach_from<Windows::Devices::SmartCards::SmartCardAppletIdGroup>(this->shim().AppletIdGroup());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL RequestActivationPolicyChangeAsync(Windows::Devices::SmartCards::SmartCardAppletIdGroupActivationPolicy policy, void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(RequestActivationPolicyChangeAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<Windows::Devices::SmartCards::SmartCardActivationPolicyChangeResult>), Windows::Devices::SmartCards::SmartCardAppletIdGroupActivationPolicy const);
            *result = detach_from<Windows::Foundation::IAsyncOperation<Windows::Devices::SmartCards::SmartCardActivationPolicyChangeResult>>(this->shim().RequestActivationPolicyChangeAsync(*reinterpret_cast<Windows::Devices::SmartCards::SmartCardAppletIdGroupActivationPolicy const*>(&policy)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Id(winrt::guid* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Id, WINRT_WRAP(winrt::guid));
            *value = detach_from<winrt::guid>(this->shim().Id());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL SetAutomaticResponseApdusAsync(void* apdus, void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SetAutomaticResponseApdusAsync, WINRT_WRAP(Windows::Foundation::IAsyncAction), Windows::Foundation::Collections::IIterable<Windows::Devices::SmartCards::SmartCardAutomaticResponseApdu> const);
            *result = detach_from<Windows::Foundation::IAsyncAction>(this->shim().SetAutomaticResponseApdusAsync(*reinterpret_cast<Windows::Foundation::Collections::IIterable<Windows::Devices::SmartCards::SmartCardAutomaticResponseApdu> const*>(&apdus)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Devices::SmartCards::ISmartCardAppletIdGroupRegistration2> : produce_base<D, Windows::Devices::SmartCards::ISmartCardAppletIdGroupRegistration2>
{
    int32_t WINRT_CALL get_SmartCardReaderId(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SmartCardReaderId, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().SmartCardReaderId());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL SetPropertiesAsync(void* props, void** operation) noexcept final
    {
        try
        {
            *operation = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SetPropertiesAsync, WINRT_WRAP(Windows::Foundation::IAsyncAction), Windows::Foundation::Collections::ValueSet const);
            *operation = detach_from<Windows::Foundation::IAsyncAction>(this->shim().SetPropertiesAsync(*reinterpret_cast<Windows::Foundation::Collections::ValueSet const*>(&props)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Devices::SmartCards::ISmartCardAppletIdGroupStatics> : produce_base<D, Windows::Devices::SmartCards::ISmartCardAppletIdGroupStatics>
{
    int32_t WINRT_CALL get_MaxAppletIds(uint16_t* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(MaxAppletIds, WINRT_WRAP(uint16_t));
            *value = detach_from<uint16_t>(this->shim().MaxAppletIds());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Devices::SmartCards::ISmartCardAutomaticResponseApdu> : produce_base<D, Windows::Devices::SmartCards::ISmartCardAutomaticResponseApdu>
{
    int32_t WINRT_CALL get_CommandApdu(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CommandApdu, WINRT_WRAP(Windows::Storage::Streams::IBuffer));
            *value = detach_from<Windows::Storage::Streams::IBuffer>(this->shim().CommandApdu());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_CommandApdu(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CommandApdu, WINRT_WRAP(void), Windows::Storage::Streams::IBuffer const&);
            this->shim().CommandApdu(*reinterpret_cast<Windows::Storage::Streams::IBuffer const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_CommandApduBitMask(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CommandApduBitMask, WINRT_WRAP(Windows::Storage::Streams::IBuffer));
            *value = detach_from<Windows::Storage::Streams::IBuffer>(this->shim().CommandApduBitMask());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_CommandApduBitMask(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CommandApduBitMask, WINRT_WRAP(void), Windows::Storage::Streams::IBuffer const&);
            this->shim().CommandApduBitMask(*reinterpret_cast<Windows::Storage::Streams::IBuffer const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_ShouldMatchLength(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ShouldMatchLength, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().ShouldMatchLength());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_ShouldMatchLength(bool value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ShouldMatchLength, WINRT_WRAP(void), bool);
            this->shim().ShouldMatchLength(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_AppletId(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(AppletId, WINRT_WRAP(Windows::Storage::Streams::IBuffer));
            *value = detach_from<Windows::Storage::Streams::IBuffer>(this->shim().AppletId());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_AppletId(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(AppletId, WINRT_WRAP(void), Windows::Storage::Streams::IBuffer const&);
            this->shim().AppletId(*reinterpret_cast<Windows::Storage::Streams::IBuffer const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_ResponseApdu(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ResponseApdu, WINRT_WRAP(Windows::Storage::Streams::IBuffer));
            *value = detach_from<Windows::Storage::Streams::IBuffer>(this->shim().ResponseApdu());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_ResponseApdu(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ResponseApdu, WINRT_WRAP(void), Windows::Storage::Streams::IBuffer const&);
            this->shim().ResponseApdu(*reinterpret_cast<Windows::Storage::Streams::IBuffer const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Devices::SmartCards::ISmartCardAutomaticResponseApdu2> : produce_base<D, Windows::Devices::SmartCards::ISmartCardAutomaticResponseApdu2>
{
    int32_t WINRT_CALL get_InputState(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(InputState, WINRT_WRAP(Windows::Foundation::IReference<uint32_t>));
            *value = detach_from<Windows::Foundation::IReference<uint32_t>>(this->shim().InputState());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_InputState(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(InputState, WINRT_WRAP(void), Windows::Foundation::IReference<uint32_t> const&);
            this->shim().InputState(*reinterpret_cast<Windows::Foundation::IReference<uint32_t> const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_OutputState(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(OutputState, WINRT_WRAP(Windows::Foundation::IReference<uint32_t>));
            *value = detach_from<Windows::Foundation::IReference<uint32_t>>(this->shim().OutputState());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_OutputState(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(OutputState, WINRT_WRAP(void), Windows::Foundation::IReference<uint32_t> const&);
            this->shim().OutputState(*reinterpret_cast<Windows::Foundation::IReference<uint32_t> const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Devices::SmartCards::ISmartCardAutomaticResponseApdu3> : produce_base<D, Windows::Devices::SmartCards::ISmartCardAutomaticResponseApdu3>
{
    int32_t WINRT_CALL get_AllowWhenCryptogramGeneratorNotPrepared(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(AllowWhenCryptogramGeneratorNotPrepared, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().AllowWhenCryptogramGeneratorNotPrepared());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_AllowWhenCryptogramGeneratorNotPrepared(bool value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(AllowWhenCryptogramGeneratorNotPrepared, WINRT_WRAP(void), bool);
            this->shim().AllowWhenCryptogramGeneratorNotPrepared(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Devices::SmartCards::ISmartCardAutomaticResponseApduFactory> : produce_base<D, Windows::Devices::SmartCards::ISmartCardAutomaticResponseApduFactory>
{
    int32_t WINRT_CALL Create(void* commandApdu, void* responseApdu, void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Create, WINRT_WRAP(Windows::Devices::SmartCards::SmartCardAutomaticResponseApdu), Windows::Storage::Streams::IBuffer const&, Windows::Storage::Streams::IBuffer const&);
            *result = detach_from<Windows::Devices::SmartCards::SmartCardAutomaticResponseApdu>(this->shim().Create(*reinterpret_cast<Windows::Storage::Streams::IBuffer const*>(&commandApdu), *reinterpret_cast<Windows::Storage::Streams::IBuffer const*>(&responseApdu)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Devices::SmartCards::ISmartCardChallengeContext> : produce_base<D, Windows::Devices::SmartCards::ISmartCardChallengeContext>
{
    int32_t WINRT_CALL get_Challenge(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Challenge, WINRT_WRAP(Windows::Storage::Streams::IBuffer));
            *value = detach_from<Windows::Storage::Streams::IBuffer>(this->shim().Challenge());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL VerifyResponseAsync(void* response, void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(VerifyResponseAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<bool>), Windows::Storage::Streams::IBuffer const);
            *result = detach_from<Windows::Foundation::IAsyncOperation<bool>>(this->shim().VerifyResponseAsync(*reinterpret_cast<Windows::Storage::Streams::IBuffer const*>(&response)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL ProvisionAsync(void* response, bool formatCard, void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ProvisionAsync, WINRT_WRAP(Windows::Foundation::IAsyncAction), Windows::Storage::Streams::IBuffer const, bool);
            *result = detach_from<Windows::Foundation::IAsyncAction>(this->shim().ProvisionAsync(*reinterpret_cast<Windows::Storage::Streams::IBuffer const*>(&response), formatCard));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL ProvisionAsyncWithNewCardId(void* response, bool formatCard, winrt::guid newCardId, void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ProvisionAsync, WINRT_WRAP(Windows::Foundation::IAsyncAction), Windows::Storage::Streams::IBuffer const, bool, winrt::guid const);
            *result = detach_from<Windows::Foundation::IAsyncAction>(this->shim().ProvisionAsync(*reinterpret_cast<Windows::Storage::Streams::IBuffer const*>(&response), formatCard, *reinterpret_cast<winrt::guid const*>(&newCardId)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL ChangeAdministrativeKeyAsync(void* response, void* newAdministrativeKey, void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ChangeAdministrativeKeyAsync, WINRT_WRAP(Windows::Foundation::IAsyncAction), Windows::Storage::Streams::IBuffer const, Windows::Storage::Streams::IBuffer const);
            *result = detach_from<Windows::Foundation::IAsyncAction>(this->shim().ChangeAdministrativeKeyAsync(*reinterpret_cast<Windows::Storage::Streams::IBuffer const*>(&response), *reinterpret_cast<Windows::Storage::Streams::IBuffer const*>(&newAdministrativeKey)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Devices::SmartCards::ISmartCardConnect> : produce_base<D, Windows::Devices::SmartCards::ISmartCardConnect>
{
    int32_t WINRT_CALL ConnectAsync(void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ConnectAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<Windows::Devices::SmartCards::SmartCardConnection>));
            *result = detach_from<Windows::Foundation::IAsyncOperation<Windows::Devices::SmartCards::SmartCardConnection>>(this->shim().ConnectAsync());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Devices::SmartCards::ISmartCardConnection> : produce_base<D, Windows::Devices::SmartCards::ISmartCardConnection>
{
    int32_t WINRT_CALL TransmitAsync(void* command, void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(TransmitAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<Windows::Storage::Streams::IBuffer>), Windows::Storage::Streams::IBuffer const);
            *result = detach_from<Windows::Foundation::IAsyncOperation<Windows::Storage::Streams::IBuffer>>(this->shim().TransmitAsync(*reinterpret_cast<Windows::Storage::Streams::IBuffer const*>(&command)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Devices::SmartCards::ISmartCardCryptogramGenerator> : produce_base<D, Windows::Devices::SmartCards::ISmartCardCryptogramGenerator>
{
    int32_t WINRT_CALL get_SupportedCryptogramMaterialTypes(void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SupportedCryptogramMaterialTypes, WINRT_WRAP(Windows::Foundation::Collections::IVectorView<Windows::Devices::SmartCards::SmartCardCryptogramMaterialType>));
            *result = detach_from<Windows::Foundation::Collections::IVectorView<Windows::Devices::SmartCards::SmartCardCryptogramMaterialType>>(this->shim().SupportedCryptogramMaterialTypes());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_SupportedCryptogramAlgorithms(void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SupportedCryptogramAlgorithms, WINRT_WRAP(Windows::Foundation::Collections::IVectorView<Windows::Devices::SmartCards::SmartCardCryptogramAlgorithm>));
            *result = detach_from<Windows::Foundation::Collections::IVectorView<Windows::Devices::SmartCards::SmartCardCryptogramAlgorithm>>(this->shim().SupportedCryptogramAlgorithms());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_SupportedCryptogramMaterialPackageFormats(void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SupportedCryptogramMaterialPackageFormats, WINRT_WRAP(Windows::Foundation::Collections::IVectorView<Windows::Devices::SmartCards::SmartCardCryptogramMaterialPackageFormat>));
            *result = detach_from<Windows::Foundation::Collections::IVectorView<Windows::Devices::SmartCards::SmartCardCryptogramMaterialPackageFormat>>(this->shim().SupportedCryptogramMaterialPackageFormats());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_SupportedCryptogramMaterialPackageConfirmationResponseFormats(void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SupportedCryptogramMaterialPackageConfirmationResponseFormats, WINRT_WRAP(Windows::Foundation::Collections::IVectorView<Windows::Devices::SmartCards::SmartCardCryptogramMaterialPackageConfirmationResponseFormat>));
            *result = detach_from<Windows::Foundation::Collections::IVectorView<Windows::Devices::SmartCards::SmartCardCryptogramMaterialPackageConfirmationResponseFormat>>(this->shim().SupportedCryptogramMaterialPackageConfirmationResponseFormats());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_SupportedSmartCardCryptogramStorageKeyCapabilities(void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SupportedSmartCardCryptogramStorageKeyCapabilities, WINRT_WRAP(Windows::Foundation::Collections::IVectorView<Windows::Devices::SmartCards::SmartCardCryptogramStorageKeyCapabilities>));
            *result = detach_from<Windows::Foundation::Collections::IVectorView<Windows::Devices::SmartCards::SmartCardCryptogramStorageKeyCapabilities>>(this->shim().SupportedSmartCardCryptogramStorageKeyCapabilities());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL DeleteCryptogramMaterialStorageKeyAsync(void* storageKeyName, void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(DeleteCryptogramMaterialStorageKeyAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<Windows::Devices::SmartCards::SmartCardCryptogramGeneratorOperationStatus>), hstring const);
            *result = detach_from<Windows::Foundation::IAsyncOperation<Windows::Devices::SmartCards::SmartCardCryptogramGeneratorOperationStatus>>(this->shim().DeleteCryptogramMaterialStorageKeyAsync(*reinterpret_cast<hstring const*>(&storageKeyName)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL CreateCryptogramMaterialStorageKeyAsync(Windows::Devices::SmartCards::SmartCardUnlockPromptingBehavior promptingBehavior, void* storageKeyName, Windows::Devices::SmartCards::SmartCardCryptogramStorageKeyAlgorithm algorithm, Windows::Devices::SmartCards::SmartCardCryptogramStorageKeyCapabilities capabilities, void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CreateCryptogramMaterialStorageKeyAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<Windows::Devices::SmartCards::SmartCardCryptogramGeneratorOperationStatus>), Windows::Devices::SmartCards::SmartCardUnlockPromptingBehavior const, hstring const, Windows::Devices::SmartCards::SmartCardCryptogramStorageKeyAlgorithm const, Windows::Devices::SmartCards::SmartCardCryptogramStorageKeyCapabilities const);
            *result = detach_from<Windows::Foundation::IAsyncOperation<Windows::Devices::SmartCards::SmartCardCryptogramGeneratorOperationStatus>>(this->shim().CreateCryptogramMaterialStorageKeyAsync(*reinterpret_cast<Windows::Devices::SmartCards::SmartCardUnlockPromptingBehavior const*>(&promptingBehavior), *reinterpret_cast<hstring const*>(&storageKeyName), *reinterpret_cast<Windows::Devices::SmartCards::SmartCardCryptogramStorageKeyAlgorithm const*>(&algorithm), *reinterpret_cast<Windows::Devices::SmartCards::SmartCardCryptogramStorageKeyCapabilities const*>(&capabilities)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL RequestCryptogramMaterialStorageKeyInfoAsync(Windows::Devices::SmartCards::SmartCardUnlockPromptingBehavior promptingBehavior, void* storageKeyName, Windows::Security::Cryptography::Core::CryptographicPublicKeyBlobType format, void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(RequestCryptogramMaterialStorageKeyInfoAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<Windows::Devices::SmartCards::SmartCardCryptogramStorageKeyInfo>), Windows::Devices::SmartCards::SmartCardUnlockPromptingBehavior const, hstring const, Windows::Security::Cryptography::Core::CryptographicPublicKeyBlobType const);
            *result = detach_from<Windows::Foundation::IAsyncOperation<Windows::Devices::SmartCards::SmartCardCryptogramStorageKeyInfo>>(this->shim().RequestCryptogramMaterialStorageKeyInfoAsync(*reinterpret_cast<Windows::Devices::SmartCards::SmartCardUnlockPromptingBehavior const*>(&promptingBehavior), *reinterpret_cast<hstring const*>(&storageKeyName), *reinterpret_cast<Windows::Security::Cryptography::Core::CryptographicPublicKeyBlobType const*>(&format)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL ImportCryptogramMaterialPackageAsync(Windows::Devices::SmartCards::SmartCardCryptogramMaterialPackageFormat format, void* storageKeyName, void* materialPackageName, void* cryptogramMaterialPackage, void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ImportCryptogramMaterialPackageAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<Windows::Devices::SmartCards::SmartCardCryptogramGeneratorOperationStatus>), Windows::Devices::SmartCards::SmartCardCryptogramMaterialPackageFormat const, hstring const, hstring const, Windows::Storage::Streams::IBuffer const);
            *result = detach_from<Windows::Foundation::IAsyncOperation<Windows::Devices::SmartCards::SmartCardCryptogramGeneratorOperationStatus>>(this->shim().ImportCryptogramMaterialPackageAsync(*reinterpret_cast<Windows::Devices::SmartCards::SmartCardCryptogramMaterialPackageFormat const*>(&format), *reinterpret_cast<hstring const*>(&storageKeyName), *reinterpret_cast<hstring const*>(&materialPackageName), *reinterpret_cast<Windows::Storage::Streams::IBuffer const*>(&cryptogramMaterialPackage)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL TryProvePossessionOfCryptogramMaterialPackageAsync(Windows::Devices::SmartCards::SmartCardUnlockPromptingBehavior promptingBehavior, Windows::Devices::SmartCards::SmartCardCryptogramMaterialPackageConfirmationResponseFormat responseFormat, void* materialPackageName, void* materialName, void* challenge, void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(TryProvePossessionOfCryptogramMaterialPackageAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<Windows::Devices::SmartCards::SmartCardCryptogramMaterialPossessionProof>), Windows::Devices::SmartCards::SmartCardUnlockPromptingBehavior const, Windows::Devices::SmartCards::SmartCardCryptogramMaterialPackageConfirmationResponseFormat const, hstring const, hstring const, Windows::Storage::Streams::IBuffer const);
            *result = detach_from<Windows::Foundation::IAsyncOperation<Windows::Devices::SmartCards::SmartCardCryptogramMaterialPossessionProof>>(this->shim().TryProvePossessionOfCryptogramMaterialPackageAsync(*reinterpret_cast<Windows::Devices::SmartCards::SmartCardUnlockPromptingBehavior const*>(&promptingBehavior), *reinterpret_cast<Windows::Devices::SmartCards::SmartCardCryptogramMaterialPackageConfirmationResponseFormat const*>(&responseFormat), *reinterpret_cast<hstring const*>(&materialPackageName), *reinterpret_cast<hstring const*>(&materialName), *reinterpret_cast<Windows::Storage::Streams::IBuffer const*>(&challenge)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL RequestUnlockCryptogramMaterialForUseAsync(Windows::Devices::SmartCards::SmartCardUnlockPromptingBehavior promptingBehavior, void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(RequestUnlockCryptogramMaterialForUseAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<Windows::Devices::SmartCards::SmartCardCryptogramGeneratorOperationStatus>), Windows::Devices::SmartCards::SmartCardUnlockPromptingBehavior const);
            *result = detach_from<Windows::Foundation::IAsyncOperation<Windows::Devices::SmartCards::SmartCardCryptogramGeneratorOperationStatus>>(this->shim().RequestUnlockCryptogramMaterialForUseAsync(*reinterpret_cast<Windows::Devices::SmartCards::SmartCardUnlockPromptingBehavior const*>(&promptingBehavior)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL DeleteCryptogramMaterialPackageAsync(void* materialPackageName, void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(DeleteCryptogramMaterialPackageAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<Windows::Devices::SmartCards::SmartCardCryptogramGeneratorOperationStatus>), hstring const);
            *result = detach_from<Windows::Foundation::IAsyncOperation<Windows::Devices::SmartCards::SmartCardCryptogramGeneratorOperationStatus>>(this->shim().DeleteCryptogramMaterialPackageAsync(*reinterpret_cast<hstring const*>(&materialPackageName)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Devices::SmartCards::ISmartCardCryptogramGenerator2> : produce_base<D, Windows::Devices::SmartCards::ISmartCardCryptogramGenerator2>
{
    int32_t WINRT_CALL ValidateRequestApduAsync(Windows::Devices::SmartCards::SmartCardUnlockPromptingBehavior promptingBehavior, void* apduToValidate, void* cryptogramPlacementSteps, void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ValidateRequestApduAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<Windows::Devices::SmartCards::SmartCardCryptogramGeneratorOperationStatus>), Windows::Devices::SmartCards::SmartCardUnlockPromptingBehavior const, Windows::Storage::Streams::IBuffer const, Windows::Foundation::Collections::IIterable<Windows::Devices::SmartCards::SmartCardCryptogramPlacementStep> const);
            *result = detach_from<Windows::Foundation::IAsyncOperation<Windows::Devices::SmartCards::SmartCardCryptogramGeneratorOperationStatus>>(this->shim().ValidateRequestApduAsync(*reinterpret_cast<Windows::Devices::SmartCards::SmartCardUnlockPromptingBehavior const*>(&promptingBehavior), *reinterpret_cast<Windows::Storage::Streams::IBuffer const*>(&apduToValidate), *reinterpret_cast<Windows::Foundation::Collections::IIterable<Windows::Devices::SmartCards::SmartCardCryptogramPlacementStep> const*>(&cryptogramPlacementSteps)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL GetAllCryptogramStorageKeyCharacteristicsAsync(void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetAllCryptogramStorageKeyCharacteristicsAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<Windows::Devices::SmartCards::SmartCardCryptogramGetAllCryptogramStorageKeyCharacteristicsResult>));
            *result = detach_from<Windows::Foundation::IAsyncOperation<Windows::Devices::SmartCards::SmartCardCryptogramGetAllCryptogramStorageKeyCharacteristicsResult>>(this->shim().GetAllCryptogramStorageKeyCharacteristicsAsync());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL GetAllCryptogramMaterialPackageCharacteristicsAsync(void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetAllCryptogramMaterialPackageCharacteristicsAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<Windows::Devices::SmartCards::SmartCardCryptogramGetAllCryptogramMaterialPackageCharacteristicsResult>));
            *result = detach_from<Windows::Foundation::IAsyncOperation<Windows::Devices::SmartCards::SmartCardCryptogramGetAllCryptogramMaterialPackageCharacteristicsResult>>(this->shim().GetAllCryptogramMaterialPackageCharacteristicsAsync());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL GetAllCryptogramMaterialPackageCharacteristicsWithStorageKeyAsync(void* storageKeyName, void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetAllCryptogramMaterialPackageCharacteristicsAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<Windows::Devices::SmartCards::SmartCardCryptogramGetAllCryptogramMaterialPackageCharacteristicsResult>), hstring const);
            *result = detach_from<Windows::Foundation::IAsyncOperation<Windows::Devices::SmartCards::SmartCardCryptogramGetAllCryptogramMaterialPackageCharacteristicsResult>>(this->shim().GetAllCryptogramMaterialPackageCharacteristicsAsync(*reinterpret_cast<hstring const*>(&storageKeyName)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL GetAllCryptogramMaterialCharacteristicsAsync(Windows::Devices::SmartCards::SmartCardUnlockPromptingBehavior promptingBehavior, void* materialPackageName, void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetAllCryptogramMaterialCharacteristicsAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<Windows::Devices::SmartCards::SmartCardCryptogramGetAllCryptogramMaterialCharacteristicsResult>), Windows::Devices::SmartCards::SmartCardUnlockPromptingBehavior const, hstring const);
            *result = detach_from<Windows::Foundation::IAsyncOperation<Windows::Devices::SmartCards::SmartCardCryptogramGetAllCryptogramMaterialCharacteristicsResult>>(this->shim().GetAllCryptogramMaterialCharacteristicsAsync(*reinterpret_cast<Windows::Devices::SmartCards::SmartCardUnlockPromptingBehavior const*>(&promptingBehavior), *reinterpret_cast<hstring const*>(&materialPackageName)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Devices::SmartCards::ISmartCardCryptogramGeneratorStatics> : produce_base<D, Windows::Devices::SmartCards::ISmartCardCryptogramGeneratorStatics>
{
    int32_t WINRT_CALL GetSmartCardCryptogramGeneratorAsync(void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetSmartCardCryptogramGeneratorAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<Windows::Devices::SmartCards::SmartCardCryptogramGenerator>));
            *result = detach_from<Windows::Foundation::IAsyncOperation<Windows::Devices::SmartCards::SmartCardCryptogramGenerator>>(this->shim().GetSmartCardCryptogramGeneratorAsync());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Devices::SmartCards::ISmartCardCryptogramGeneratorStatics2> : produce_base<D, Windows::Devices::SmartCards::ISmartCardCryptogramGeneratorStatics2>
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
};

template <typename D>
struct produce<D, Windows::Devices::SmartCards::ISmartCardCryptogramGetAllCryptogramMaterialCharacteristicsResult> : produce_base<D, Windows::Devices::SmartCards::ISmartCardCryptogramGetAllCryptogramMaterialCharacteristicsResult>
{
    int32_t WINRT_CALL get_OperationStatus(Windows::Devices::SmartCards::SmartCardCryptogramGeneratorOperationStatus* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(OperationStatus, WINRT_WRAP(Windows::Devices::SmartCards::SmartCardCryptogramGeneratorOperationStatus));
            *value = detach_from<Windows::Devices::SmartCards::SmartCardCryptogramGeneratorOperationStatus>(this->shim().OperationStatus());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Characteristics(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Characteristics, WINRT_WRAP(Windows::Foundation::Collections::IVectorView<Windows::Devices::SmartCards::SmartCardCryptogramMaterialCharacteristics>));
            *value = detach_from<Windows::Foundation::Collections::IVectorView<Windows::Devices::SmartCards::SmartCardCryptogramMaterialCharacteristics>>(this->shim().Characteristics());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Devices::SmartCards::ISmartCardCryptogramGetAllCryptogramMaterialPackageCharacteristicsResult> : produce_base<D, Windows::Devices::SmartCards::ISmartCardCryptogramGetAllCryptogramMaterialPackageCharacteristicsResult>
{
    int32_t WINRT_CALL get_OperationStatus(Windows::Devices::SmartCards::SmartCardCryptogramGeneratorOperationStatus* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(OperationStatus, WINRT_WRAP(Windows::Devices::SmartCards::SmartCardCryptogramGeneratorOperationStatus));
            *value = detach_from<Windows::Devices::SmartCards::SmartCardCryptogramGeneratorOperationStatus>(this->shim().OperationStatus());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Characteristics(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Characteristics, WINRT_WRAP(Windows::Foundation::Collections::IVectorView<Windows::Devices::SmartCards::SmartCardCryptogramMaterialPackageCharacteristics>));
            *value = detach_from<Windows::Foundation::Collections::IVectorView<Windows::Devices::SmartCards::SmartCardCryptogramMaterialPackageCharacteristics>>(this->shim().Characteristics());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Devices::SmartCards::ISmartCardCryptogramGetAllCryptogramStorageKeyCharacteristicsResult> : produce_base<D, Windows::Devices::SmartCards::ISmartCardCryptogramGetAllCryptogramStorageKeyCharacteristicsResult>
{
    int32_t WINRT_CALL get_OperationStatus(Windows::Devices::SmartCards::SmartCardCryptogramGeneratorOperationStatus* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(OperationStatus, WINRT_WRAP(Windows::Devices::SmartCards::SmartCardCryptogramGeneratorOperationStatus));
            *value = detach_from<Windows::Devices::SmartCards::SmartCardCryptogramGeneratorOperationStatus>(this->shim().OperationStatus());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Characteristics(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Characteristics, WINRT_WRAP(Windows::Foundation::Collections::IVectorView<Windows::Devices::SmartCards::SmartCardCryptogramStorageKeyCharacteristics>));
            *value = detach_from<Windows::Foundation::Collections::IVectorView<Windows::Devices::SmartCards::SmartCardCryptogramStorageKeyCharacteristics>>(this->shim().Characteristics());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Devices::SmartCards::ISmartCardCryptogramMaterialCharacteristics> : produce_base<D, Windows::Devices::SmartCards::ISmartCardCryptogramMaterialCharacteristics>
{
    int32_t WINRT_CALL get_MaterialName(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(MaterialName, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().MaterialName());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_AllowedAlgorithms(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(AllowedAlgorithms, WINRT_WRAP(Windows::Foundation::Collections::IVectorView<Windows::Devices::SmartCards::SmartCardCryptogramAlgorithm>));
            *value = detach_from<Windows::Foundation::Collections::IVectorView<Windows::Devices::SmartCards::SmartCardCryptogramAlgorithm>>(this->shim().AllowedAlgorithms());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_AllowedProofOfPossessionAlgorithms(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(AllowedProofOfPossessionAlgorithms, WINRT_WRAP(Windows::Foundation::Collections::IVectorView<Windows::Devices::SmartCards::SmartCardCryptogramMaterialPackageConfirmationResponseFormat>));
            *value = detach_from<Windows::Foundation::Collections::IVectorView<Windows::Devices::SmartCards::SmartCardCryptogramMaterialPackageConfirmationResponseFormat>>(this->shim().AllowedProofOfPossessionAlgorithms());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_AllowedValidations(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(AllowedValidations, WINRT_WRAP(Windows::Foundation::Collections::IVectorView<Windows::Devices::SmartCards::SmartCardCryptogramAlgorithm>));
            *value = detach_from<Windows::Foundation::Collections::IVectorView<Windows::Devices::SmartCards::SmartCardCryptogramAlgorithm>>(this->shim().AllowedValidations());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_MaterialType(Windows::Devices::SmartCards::SmartCardCryptogramMaterialType* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(MaterialType, WINRT_WRAP(Windows::Devices::SmartCards::SmartCardCryptogramMaterialType));
            *value = detach_from<Windows::Devices::SmartCards::SmartCardCryptogramMaterialType>(this->shim().MaterialType());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_ProtectionMethod(Windows::Devices::SmartCards::SmartCardCryptogramMaterialProtectionMethod* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ProtectionMethod, WINRT_WRAP(Windows::Devices::SmartCards::SmartCardCryptogramMaterialProtectionMethod));
            *value = detach_from<Windows::Devices::SmartCards::SmartCardCryptogramMaterialProtectionMethod>(this->shim().ProtectionMethod());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_ProtectionVersion(int32_t* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ProtectionVersion, WINRT_WRAP(int32_t));
            *value = detach_from<int32_t>(this->shim().ProtectionVersion());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_MaterialLength(int32_t* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(MaterialLength, WINRT_WRAP(int32_t));
            *value = detach_from<int32_t>(this->shim().MaterialLength());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Devices::SmartCards::ISmartCardCryptogramMaterialPackageCharacteristics> : produce_base<D, Windows::Devices::SmartCards::ISmartCardCryptogramMaterialPackageCharacteristics>
{
    int32_t WINRT_CALL get_PackageName(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(PackageName, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().PackageName());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_StorageKeyName(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(StorageKeyName, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().StorageKeyName());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_DateImported(Windows::Foundation::DateTime* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(DateImported, WINRT_WRAP(Windows::Foundation::DateTime));
            *value = detach_from<Windows::Foundation::DateTime>(this->shim().DateImported());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_PackageFormat(Windows::Devices::SmartCards::SmartCardCryptogramMaterialPackageFormat* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(PackageFormat, WINRT_WRAP(Windows::Devices::SmartCards::SmartCardCryptogramMaterialPackageFormat));
            *value = detach_from<Windows::Devices::SmartCards::SmartCardCryptogramMaterialPackageFormat>(this->shim().PackageFormat());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Devices::SmartCards::ISmartCardCryptogramMaterialPossessionProof> : produce_base<D, Windows::Devices::SmartCards::ISmartCardCryptogramMaterialPossessionProof>
{
    int32_t WINRT_CALL get_OperationStatus(Windows::Devices::SmartCards::SmartCardCryptogramGeneratorOperationStatus* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(OperationStatus, WINRT_WRAP(Windows::Devices::SmartCards::SmartCardCryptogramGeneratorOperationStatus));
            *value = detach_from<Windows::Devices::SmartCards::SmartCardCryptogramGeneratorOperationStatus>(this->shim().OperationStatus());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Proof(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Proof, WINRT_WRAP(Windows::Storage::Streams::IBuffer));
            *value = detach_from<Windows::Storage::Streams::IBuffer>(this->shim().Proof());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Devices::SmartCards::ISmartCardCryptogramPlacementStep> : produce_base<D, Windows::Devices::SmartCards::ISmartCardCryptogramPlacementStep>
{
    int32_t WINRT_CALL get_Algorithm(Windows::Devices::SmartCards::SmartCardCryptogramAlgorithm* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Algorithm, WINRT_WRAP(Windows::Devices::SmartCards::SmartCardCryptogramAlgorithm));
            *value = detach_from<Windows::Devices::SmartCards::SmartCardCryptogramAlgorithm>(this->shim().Algorithm());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_Algorithm(Windows::Devices::SmartCards::SmartCardCryptogramAlgorithm value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Algorithm, WINRT_WRAP(void), Windows::Devices::SmartCards::SmartCardCryptogramAlgorithm const&);
            this->shim().Algorithm(*reinterpret_cast<Windows::Devices::SmartCards::SmartCardCryptogramAlgorithm const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_SourceData(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SourceData, WINRT_WRAP(Windows::Storage::Streams::IBuffer));
            *value = detach_from<Windows::Storage::Streams::IBuffer>(this->shim().SourceData());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_SourceData(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SourceData, WINRT_WRAP(void), Windows::Storage::Streams::IBuffer const&);
            this->shim().SourceData(*reinterpret_cast<Windows::Storage::Streams::IBuffer const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_CryptogramMaterialPackageName(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CryptogramMaterialPackageName, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().CryptogramMaterialPackageName());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_CryptogramMaterialPackageName(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CryptogramMaterialPackageName, WINRT_WRAP(void), hstring const&);
            this->shim().CryptogramMaterialPackageName(*reinterpret_cast<hstring const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_CryptogramMaterialName(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CryptogramMaterialName, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().CryptogramMaterialName());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_CryptogramMaterialName(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CryptogramMaterialName, WINRT_WRAP(void), hstring const&);
            this->shim().CryptogramMaterialName(*reinterpret_cast<hstring const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_TemplateOffset(int32_t* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(TemplateOffset, WINRT_WRAP(int32_t));
            *value = detach_from<int32_t>(this->shim().TemplateOffset());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_TemplateOffset(int32_t value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(TemplateOffset, WINRT_WRAP(void), int32_t);
            this->shim().TemplateOffset(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_CryptogramOffset(int32_t* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CryptogramOffset, WINRT_WRAP(int32_t));
            *value = detach_from<int32_t>(this->shim().CryptogramOffset());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_CryptogramOffset(int32_t value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CryptogramOffset, WINRT_WRAP(void), int32_t);
            this->shim().CryptogramOffset(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_CryptogramLength(int32_t* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CryptogramLength, WINRT_WRAP(int32_t));
            *value = detach_from<int32_t>(this->shim().CryptogramLength());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_CryptogramLength(int32_t value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CryptogramLength, WINRT_WRAP(void), int32_t);
            this->shim().CryptogramLength(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_CryptogramPlacementOptions(Windows::Devices::SmartCards::SmartCardCryptogramPlacementOptions* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CryptogramPlacementOptions, WINRT_WRAP(Windows::Devices::SmartCards::SmartCardCryptogramPlacementOptions));
            *value = detach_from<Windows::Devices::SmartCards::SmartCardCryptogramPlacementOptions>(this->shim().CryptogramPlacementOptions());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_CryptogramPlacementOptions(Windows::Devices::SmartCards::SmartCardCryptogramPlacementOptions value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CryptogramPlacementOptions, WINRT_WRAP(void), Windows::Devices::SmartCards::SmartCardCryptogramPlacementOptions const&);
            this->shim().CryptogramPlacementOptions(*reinterpret_cast<Windows::Devices::SmartCards::SmartCardCryptogramPlacementOptions const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_ChainedOutputStep(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ChainedOutputStep, WINRT_WRAP(Windows::Devices::SmartCards::SmartCardCryptogramPlacementStep));
            *value = detach_from<Windows::Devices::SmartCards::SmartCardCryptogramPlacementStep>(this->shim().ChainedOutputStep());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_ChainedOutputStep(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ChainedOutputStep, WINRT_WRAP(void), Windows::Devices::SmartCards::SmartCardCryptogramPlacementStep const&);
            this->shim().ChainedOutputStep(*reinterpret_cast<Windows::Devices::SmartCards::SmartCardCryptogramPlacementStep const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Devices::SmartCards::ISmartCardCryptogramStorageKeyCharacteristics> : produce_base<D, Windows::Devices::SmartCards::ISmartCardCryptogramStorageKeyCharacteristics>
{
    int32_t WINRT_CALL get_StorageKeyName(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(StorageKeyName, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().StorageKeyName());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_DateCreated(Windows::Foundation::DateTime* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(DateCreated, WINRT_WRAP(Windows::Foundation::DateTime));
            *value = detach_from<Windows::Foundation::DateTime>(this->shim().DateCreated());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Algorithm(Windows::Devices::SmartCards::SmartCardCryptogramStorageKeyAlgorithm* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Algorithm, WINRT_WRAP(Windows::Devices::SmartCards::SmartCardCryptogramStorageKeyAlgorithm));
            *value = detach_from<Windows::Devices::SmartCards::SmartCardCryptogramStorageKeyAlgorithm>(this->shim().Algorithm());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Capabilities(Windows::Devices::SmartCards::SmartCardCryptogramStorageKeyCapabilities* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Capabilities, WINRT_WRAP(Windows::Devices::SmartCards::SmartCardCryptogramStorageKeyCapabilities));
            *value = detach_from<Windows::Devices::SmartCards::SmartCardCryptogramStorageKeyCapabilities>(this->shim().Capabilities());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Devices::SmartCards::ISmartCardCryptogramStorageKeyInfo> : produce_base<D, Windows::Devices::SmartCards::ISmartCardCryptogramStorageKeyInfo>
{
    int32_t WINRT_CALL get_OperationStatus(Windows::Devices::SmartCards::SmartCardCryptogramGeneratorOperationStatus* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(OperationStatus, WINRT_WRAP(Windows::Devices::SmartCards::SmartCardCryptogramGeneratorOperationStatus));
            *value = detach_from<Windows::Devices::SmartCards::SmartCardCryptogramGeneratorOperationStatus>(this->shim().OperationStatus());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_PublicKeyBlobType(Windows::Security::Cryptography::Core::CryptographicPublicKeyBlobType* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(PublicKeyBlobType, WINRT_WRAP(Windows::Security::Cryptography::Core::CryptographicPublicKeyBlobType));
            *value = detach_from<Windows::Security::Cryptography::Core::CryptographicPublicKeyBlobType>(this->shim().PublicKeyBlobType());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_PublicKey(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(PublicKey, WINRT_WRAP(Windows::Storage::Streams::IBuffer));
            *value = detach_from<Windows::Storage::Streams::IBuffer>(this->shim().PublicKey());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_AttestationStatus(Windows::Devices::SmartCards::SmartCardCryptographicKeyAttestationStatus* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(AttestationStatus, WINRT_WRAP(Windows::Devices::SmartCards::SmartCardCryptographicKeyAttestationStatus));
            *value = detach_from<Windows::Devices::SmartCards::SmartCardCryptographicKeyAttestationStatus>(this->shim().AttestationStatus());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Attestation(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Attestation, WINRT_WRAP(Windows::Storage::Streams::IBuffer));
            *value = detach_from<Windows::Storage::Streams::IBuffer>(this->shim().Attestation());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_AttestationCertificateChain(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(AttestationCertificateChain, WINRT_WRAP(Windows::Storage::Streams::IBuffer));
            *value = detach_from<Windows::Storage::Streams::IBuffer>(this->shim().AttestationCertificateChain());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Capabilities(Windows::Devices::SmartCards::SmartCardCryptogramStorageKeyCapabilities* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Capabilities, WINRT_WRAP(Windows::Devices::SmartCards::SmartCardCryptogramStorageKeyCapabilities));
            *value = detach_from<Windows::Devices::SmartCards::SmartCardCryptogramStorageKeyCapabilities>(this->shim().Capabilities());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Devices::SmartCards::ISmartCardCryptogramStorageKeyInfo2> : produce_base<D, Windows::Devices::SmartCards::ISmartCardCryptogramStorageKeyInfo2>
{
    int32_t WINRT_CALL get_OperationalRequirements(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(OperationalRequirements, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().OperationalRequirements());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Devices::SmartCards::ISmartCardEmulator> : produce_base<D, Windows::Devices::SmartCards::ISmartCardEmulator>
{
    int32_t WINRT_CALL get_EnablementPolicy(Windows::Devices::SmartCards::SmartCardEmulatorEnablementPolicy* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(EnablementPolicy, WINRT_WRAP(Windows::Devices::SmartCards::SmartCardEmulatorEnablementPolicy));
            *value = detach_from<Windows::Devices::SmartCards::SmartCardEmulatorEnablementPolicy>(this->shim().EnablementPolicy());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Devices::SmartCards::ISmartCardEmulator2> : produce_base<D, Windows::Devices::SmartCards::ISmartCardEmulator2>
{
    int32_t WINRT_CALL add_ApduReceived(void* value, winrt::event_token* token) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ApduReceived, WINRT_WRAP(winrt::event_token), Windows::Foundation::TypedEventHandler<Windows::Devices::SmartCards::SmartCardEmulator, Windows::Devices::SmartCards::SmartCardEmulatorApduReceivedEventArgs> const&);
            *token = detach_from<winrt::event_token>(this->shim().ApduReceived(*reinterpret_cast<Windows::Foundation::TypedEventHandler<Windows::Devices::SmartCards::SmartCardEmulator, Windows::Devices::SmartCards::SmartCardEmulatorApduReceivedEventArgs> const*>(&value)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL remove_ApduReceived(winrt::event_token value) noexcept final
    {
        typename D::abi_guard guard(this->shim());
        WINRT_ASSERT_DECLARATION(ApduReceived, WINRT_WRAP(void), winrt::event_token const&);
        this->shim().ApduReceived(*reinterpret_cast<winrt::event_token const*>(&value));
        return 0;
    }

    int32_t WINRT_CALL add_ConnectionDeactivated(void* value, winrt::event_token* token) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ConnectionDeactivated, WINRT_WRAP(winrt::event_token), Windows::Foundation::TypedEventHandler<Windows::Devices::SmartCards::SmartCardEmulator, Windows::Devices::SmartCards::SmartCardEmulatorConnectionDeactivatedEventArgs> const&);
            *token = detach_from<winrt::event_token>(this->shim().ConnectionDeactivated(*reinterpret_cast<Windows::Foundation::TypedEventHandler<Windows::Devices::SmartCards::SmartCardEmulator, Windows::Devices::SmartCards::SmartCardEmulatorConnectionDeactivatedEventArgs> const*>(&value)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL remove_ConnectionDeactivated(winrt::event_token value) noexcept final
    {
        typename D::abi_guard guard(this->shim());
        WINRT_ASSERT_DECLARATION(ConnectionDeactivated, WINRT_WRAP(void), winrt::event_token const&);
        this->shim().ConnectionDeactivated(*reinterpret_cast<winrt::event_token const*>(&value));
        return 0;
    }

    int32_t WINRT_CALL Start() noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Start, WINRT_WRAP(void));
            this->shim().Start();
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL IsHostCardEmulationSupported(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IsHostCardEmulationSupported, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().IsHostCardEmulationSupported());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Devices::SmartCards::ISmartCardEmulatorApduReceivedEventArgs> : produce_base<D, Windows::Devices::SmartCards::ISmartCardEmulatorApduReceivedEventArgs>
{
    int32_t WINRT_CALL get_CommandApdu(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CommandApdu, WINRT_WRAP(Windows::Storage::Streams::IBuffer));
            *value = detach_from<Windows::Storage::Streams::IBuffer>(this->shim().CommandApdu());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_ConnectionProperties(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ConnectionProperties, WINRT_WRAP(Windows::Devices::SmartCards::SmartCardEmulatorConnectionProperties));
            *value = detach_from<Windows::Devices::SmartCards::SmartCardEmulatorConnectionProperties>(this->shim().ConnectionProperties());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL TryRespondAsync(void* responseApdu, void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(TryRespondAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<bool>), Windows::Storage::Streams::IBuffer const);
            *result = detach_from<Windows::Foundation::IAsyncOperation<bool>>(this->shim().TryRespondAsync(*reinterpret_cast<Windows::Storage::Streams::IBuffer const*>(&responseApdu)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_AutomaticResponseStatus(Windows::Devices::SmartCards::SmartCardAutomaticResponseStatus* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(AutomaticResponseStatus, WINRT_WRAP(Windows::Devices::SmartCards::SmartCardAutomaticResponseStatus));
            *value = detach_from<Windows::Devices::SmartCards::SmartCardAutomaticResponseStatus>(this->shim().AutomaticResponseStatus());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Devices::SmartCards::ISmartCardEmulatorApduReceivedEventArgs2> : produce_base<D, Windows::Devices::SmartCards::ISmartCardEmulatorApduReceivedEventArgs2>
{
    int32_t WINRT_CALL get_State(uint32_t* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(State, WINRT_WRAP(uint32_t));
            *value = detach_from<uint32_t>(this->shim().State());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL TryRespondWithStateAsync(void* responseApdu, void* nextState, void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(TryRespondAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<bool>), Windows::Storage::Streams::IBuffer const, Windows::Foundation::IReference<uint32_t> const);
            *result = detach_from<Windows::Foundation::IAsyncOperation<bool>>(this->shim().TryRespondAsync(*reinterpret_cast<Windows::Storage::Streams::IBuffer const*>(&responseApdu), *reinterpret_cast<Windows::Foundation::IReference<uint32_t> const*>(&nextState)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Devices::SmartCards::ISmartCardEmulatorApduReceivedEventArgsWithCryptograms> : produce_base<D, Windows::Devices::SmartCards::ISmartCardEmulatorApduReceivedEventArgsWithCryptograms>
{
    int32_t WINRT_CALL TryRespondWithCryptogramsAsync(void* responseTemplate, void* cryptogramPlacementSteps, void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(TryRespondWithCryptogramsAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<Windows::Devices::SmartCards::SmartCardCryptogramGeneratorOperationStatus>), Windows::Storage::Streams::IBuffer const, Windows::Foundation::Collections::IIterable<Windows::Devices::SmartCards::SmartCardCryptogramPlacementStep> const);
            *result = detach_from<Windows::Foundation::IAsyncOperation<Windows::Devices::SmartCards::SmartCardCryptogramGeneratorOperationStatus>>(this->shim().TryRespondWithCryptogramsAsync(*reinterpret_cast<Windows::Storage::Streams::IBuffer const*>(&responseTemplate), *reinterpret_cast<Windows::Foundation::Collections::IIterable<Windows::Devices::SmartCards::SmartCardCryptogramPlacementStep> const*>(&cryptogramPlacementSteps)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL TryRespondWithCryptogramsAndStateAsync(void* responseTemplate, void* cryptogramPlacementSteps, void* nextState, void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(TryRespondWithCryptogramsAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<Windows::Devices::SmartCards::SmartCardCryptogramGeneratorOperationStatus>), Windows::Storage::Streams::IBuffer const, Windows::Foundation::Collections::IIterable<Windows::Devices::SmartCards::SmartCardCryptogramPlacementStep> const, Windows::Foundation::IReference<uint32_t> const);
            *result = detach_from<Windows::Foundation::IAsyncOperation<Windows::Devices::SmartCards::SmartCardCryptogramGeneratorOperationStatus>>(this->shim().TryRespondWithCryptogramsAsync(*reinterpret_cast<Windows::Storage::Streams::IBuffer const*>(&responseTemplate), *reinterpret_cast<Windows::Foundation::Collections::IIterable<Windows::Devices::SmartCards::SmartCardCryptogramPlacementStep> const*>(&cryptogramPlacementSteps), *reinterpret_cast<Windows::Foundation::IReference<uint32_t> const*>(&nextState)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Devices::SmartCards::ISmartCardEmulatorConnectionDeactivatedEventArgs> : produce_base<D, Windows::Devices::SmartCards::ISmartCardEmulatorConnectionDeactivatedEventArgs>
{
    int32_t WINRT_CALL get_ConnectionProperties(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ConnectionProperties, WINRT_WRAP(Windows::Devices::SmartCards::SmartCardEmulatorConnectionProperties));
            *value = detach_from<Windows::Devices::SmartCards::SmartCardEmulatorConnectionProperties>(this->shim().ConnectionProperties());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Reason(Windows::Devices::SmartCards::SmartCardEmulatorConnectionDeactivatedReason* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Reason, WINRT_WRAP(Windows::Devices::SmartCards::SmartCardEmulatorConnectionDeactivatedReason));
            *value = detach_from<Windows::Devices::SmartCards::SmartCardEmulatorConnectionDeactivatedReason>(this->shim().Reason());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Devices::SmartCards::ISmartCardEmulatorConnectionProperties> : produce_base<D, Windows::Devices::SmartCards::ISmartCardEmulatorConnectionProperties>
{
    int32_t WINRT_CALL get_Id(winrt::guid* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Id, WINRT_WRAP(winrt::guid));
            *value = detach_from<winrt::guid>(this->shim().Id());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Source(Windows::Devices::SmartCards::SmartCardEmulatorConnectionSource* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Source, WINRT_WRAP(Windows::Devices::SmartCards::SmartCardEmulatorConnectionSource));
            *value = detach_from<Windows::Devices::SmartCards::SmartCardEmulatorConnectionSource>(this->shim().Source());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Devices::SmartCards::ISmartCardEmulatorStatics> : produce_base<D, Windows::Devices::SmartCards::ISmartCardEmulatorStatics>
{
    int32_t WINRT_CALL GetDefaultAsync(void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetDefaultAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<Windows::Devices::SmartCards::SmartCardEmulator>));
            *result = detach_from<Windows::Foundation::IAsyncOperation<Windows::Devices::SmartCards::SmartCardEmulator>>(this->shim().GetDefaultAsync());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Devices::SmartCards::ISmartCardEmulatorStatics2> : produce_base<D, Windows::Devices::SmartCards::ISmartCardEmulatorStatics2>
{
    int32_t WINRT_CALL GetAppletIdGroupRegistrationsAsync(void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetAppletIdGroupRegistrationsAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<Windows::Foundation::Collections::IVectorView<Windows::Devices::SmartCards::SmartCardAppletIdGroupRegistration>>));
            *result = detach_from<Windows::Foundation::IAsyncOperation<Windows::Foundation::Collections::IVectorView<Windows::Devices::SmartCards::SmartCardAppletIdGroupRegistration>>>(this->shim().GetAppletIdGroupRegistrationsAsync());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL RegisterAppletIdGroupAsync(void* appletIdGroup, void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(RegisterAppletIdGroupAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<Windows::Devices::SmartCards::SmartCardAppletIdGroupRegistration>), Windows::Devices::SmartCards::SmartCardAppletIdGroup const);
            *result = detach_from<Windows::Foundation::IAsyncOperation<Windows::Devices::SmartCards::SmartCardAppletIdGroupRegistration>>(this->shim().RegisterAppletIdGroupAsync(*reinterpret_cast<Windows::Devices::SmartCards::SmartCardAppletIdGroup const*>(&appletIdGroup)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL UnregisterAppletIdGroupAsync(void* registration, void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(UnregisterAppletIdGroupAsync, WINRT_WRAP(Windows::Foundation::IAsyncAction), Windows::Devices::SmartCards::SmartCardAppletIdGroupRegistration const);
            *result = detach_from<Windows::Foundation::IAsyncAction>(this->shim().UnregisterAppletIdGroupAsync(*reinterpret_cast<Windows::Devices::SmartCards::SmartCardAppletIdGroupRegistration const*>(&registration)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_MaxAppletIdGroupRegistrations(uint16_t* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(MaxAppletIdGroupRegistrations, WINRT_WRAP(uint16_t));
            *value = detach_from<uint16_t>(this->shim().MaxAppletIdGroupRegistrations());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Devices::SmartCards::ISmartCardEmulatorStatics3> : produce_base<D, Windows::Devices::SmartCards::ISmartCardEmulatorStatics3>
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
};

template <typename D>
struct produce<D, Windows::Devices::SmartCards::ISmartCardPinPolicy> : produce_base<D, Windows::Devices::SmartCards::ISmartCardPinPolicy>
{
    int32_t WINRT_CALL get_MinLength(uint32_t* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(MinLength, WINRT_WRAP(uint32_t));
            *value = detach_from<uint32_t>(this->shim().MinLength());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_MinLength(uint32_t value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(MinLength, WINRT_WRAP(void), uint32_t);
            this->shim().MinLength(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_MaxLength(uint32_t* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(MaxLength, WINRT_WRAP(uint32_t));
            *value = detach_from<uint32_t>(this->shim().MaxLength());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_MaxLength(uint32_t value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(MaxLength, WINRT_WRAP(void), uint32_t);
            this->shim().MaxLength(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_UppercaseLetters(Windows::Devices::SmartCards::SmartCardPinCharacterPolicyOption* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(UppercaseLetters, WINRT_WRAP(Windows::Devices::SmartCards::SmartCardPinCharacterPolicyOption));
            *value = detach_from<Windows::Devices::SmartCards::SmartCardPinCharacterPolicyOption>(this->shim().UppercaseLetters());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_UppercaseLetters(Windows::Devices::SmartCards::SmartCardPinCharacterPolicyOption value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(UppercaseLetters, WINRT_WRAP(void), Windows::Devices::SmartCards::SmartCardPinCharacterPolicyOption const&);
            this->shim().UppercaseLetters(*reinterpret_cast<Windows::Devices::SmartCards::SmartCardPinCharacterPolicyOption const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_LowercaseLetters(Windows::Devices::SmartCards::SmartCardPinCharacterPolicyOption* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(LowercaseLetters, WINRT_WRAP(Windows::Devices::SmartCards::SmartCardPinCharacterPolicyOption));
            *value = detach_from<Windows::Devices::SmartCards::SmartCardPinCharacterPolicyOption>(this->shim().LowercaseLetters());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_LowercaseLetters(Windows::Devices::SmartCards::SmartCardPinCharacterPolicyOption value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(LowercaseLetters, WINRT_WRAP(void), Windows::Devices::SmartCards::SmartCardPinCharacterPolicyOption const&);
            this->shim().LowercaseLetters(*reinterpret_cast<Windows::Devices::SmartCards::SmartCardPinCharacterPolicyOption const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Digits(Windows::Devices::SmartCards::SmartCardPinCharacterPolicyOption* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Digits, WINRT_WRAP(Windows::Devices::SmartCards::SmartCardPinCharacterPolicyOption));
            *value = detach_from<Windows::Devices::SmartCards::SmartCardPinCharacterPolicyOption>(this->shim().Digits());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_Digits(Windows::Devices::SmartCards::SmartCardPinCharacterPolicyOption value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Digits, WINRT_WRAP(void), Windows::Devices::SmartCards::SmartCardPinCharacterPolicyOption const&);
            this->shim().Digits(*reinterpret_cast<Windows::Devices::SmartCards::SmartCardPinCharacterPolicyOption const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_SpecialCharacters(Windows::Devices::SmartCards::SmartCardPinCharacterPolicyOption* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SpecialCharacters, WINRT_WRAP(Windows::Devices::SmartCards::SmartCardPinCharacterPolicyOption));
            *value = detach_from<Windows::Devices::SmartCards::SmartCardPinCharacterPolicyOption>(this->shim().SpecialCharacters());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_SpecialCharacters(Windows::Devices::SmartCards::SmartCardPinCharacterPolicyOption value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SpecialCharacters, WINRT_WRAP(void), Windows::Devices::SmartCards::SmartCardPinCharacterPolicyOption const&);
            this->shim().SpecialCharacters(*reinterpret_cast<Windows::Devices::SmartCards::SmartCardPinCharacterPolicyOption const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Devices::SmartCards::ISmartCardPinResetDeferral> : produce_base<D, Windows::Devices::SmartCards::ISmartCardPinResetDeferral>
{
    int32_t WINRT_CALL Complete() noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Complete, WINRT_WRAP(void));
            this->shim().Complete();
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Devices::SmartCards::ISmartCardPinResetRequest> : produce_base<D, Windows::Devices::SmartCards::ISmartCardPinResetRequest>
{
    int32_t WINRT_CALL get_Challenge(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Challenge, WINRT_WRAP(Windows::Storage::Streams::IBuffer));
            *value = detach_from<Windows::Storage::Streams::IBuffer>(this->shim().Challenge());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Deadline(Windows::Foundation::DateTime* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Deadline, WINRT_WRAP(Windows::Foundation::DateTime));
            *value = detach_from<Windows::Foundation::DateTime>(this->shim().Deadline());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL GetDeferral(void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetDeferral, WINRT_WRAP(Windows::Devices::SmartCards::SmartCardPinResetDeferral));
            *result = detach_from<Windows::Devices::SmartCards::SmartCardPinResetDeferral>(this->shim().GetDeferral());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL SetResponse(void* response) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SetResponse, WINRT_WRAP(void), Windows::Storage::Streams::IBuffer const&);
            this->shim().SetResponse(*reinterpret_cast<Windows::Storage::Streams::IBuffer const*>(&response));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Devices::SmartCards::ISmartCardProvisioning> : produce_base<D, Windows::Devices::SmartCards::ISmartCardProvisioning>
{
    int32_t WINRT_CALL get_SmartCard(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SmartCard, WINRT_WRAP(Windows::Devices::SmartCards::SmartCard));
            *value = detach_from<Windows::Devices::SmartCards::SmartCard>(this->shim().SmartCard());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL GetIdAsync(void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetIdAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<winrt::guid>));
            *result = detach_from<Windows::Foundation::IAsyncOperation<winrt::guid>>(this->shim().GetIdAsync());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL GetNameAsync(void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetNameAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<hstring>));
            *result = detach_from<Windows::Foundation::IAsyncOperation<hstring>>(this->shim().GetNameAsync());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL GetChallengeContextAsync(void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetChallengeContextAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<Windows::Devices::SmartCards::SmartCardChallengeContext>));
            *result = detach_from<Windows::Foundation::IAsyncOperation<Windows::Devices::SmartCards::SmartCardChallengeContext>>(this->shim().GetChallengeContextAsync());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL RequestPinChangeAsync(void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(RequestPinChangeAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<bool>));
            *result = detach_from<Windows::Foundation::IAsyncOperation<bool>>(this->shim().RequestPinChangeAsync());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL RequestPinResetAsync(void* handler, void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(RequestPinResetAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<bool>), Windows::Devices::SmartCards::SmartCardPinResetHandler const);
            *result = detach_from<Windows::Foundation::IAsyncOperation<bool>>(this->shim().RequestPinResetAsync(*reinterpret_cast<Windows::Devices::SmartCards::SmartCardPinResetHandler const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Devices::SmartCards::ISmartCardProvisioning2> : produce_base<D, Windows::Devices::SmartCards::ISmartCardProvisioning2>
{
    int32_t WINRT_CALL GetAuthorityKeyContainerNameAsync(void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetAuthorityKeyContainerNameAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<hstring>));
            *result = detach_from<Windows::Foundation::IAsyncOperation<hstring>>(this->shim().GetAuthorityKeyContainerNameAsync());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Devices::SmartCards::ISmartCardProvisioningStatics> : produce_base<D, Windows::Devices::SmartCards::ISmartCardProvisioningStatics>
{
    int32_t WINRT_CALL FromSmartCardAsync(void* card, void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(FromSmartCardAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<Windows::Devices::SmartCards::SmartCardProvisioning>), Windows::Devices::SmartCards::SmartCard const);
            *result = detach_from<Windows::Foundation::IAsyncOperation<Windows::Devices::SmartCards::SmartCardProvisioning>>(this->shim().FromSmartCardAsync(*reinterpret_cast<Windows::Devices::SmartCards::SmartCard const*>(&card)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL RequestVirtualSmartCardCreationAsync(void* friendlyName, void* administrativeKey, void* pinPolicy, void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(RequestVirtualSmartCardCreationAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<Windows::Devices::SmartCards::SmartCardProvisioning>), hstring const, Windows::Storage::Streams::IBuffer const, Windows::Devices::SmartCards::SmartCardPinPolicy const);
            *result = detach_from<Windows::Foundation::IAsyncOperation<Windows::Devices::SmartCards::SmartCardProvisioning>>(this->shim().RequestVirtualSmartCardCreationAsync(*reinterpret_cast<hstring const*>(&friendlyName), *reinterpret_cast<Windows::Storage::Streams::IBuffer const*>(&administrativeKey), *reinterpret_cast<Windows::Devices::SmartCards::SmartCardPinPolicy const*>(&pinPolicy)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL RequestVirtualSmartCardCreationAsyncWithCardId(void* friendlyName, void* administrativeKey, void* pinPolicy, winrt::guid cardId, void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(RequestVirtualSmartCardCreationAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<Windows::Devices::SmartCards::SmartCardProvisioning>), hstring const, Windows::Storage::Streams::IBuffer const, Windows::Devices::SmartCards::SmartCardPinPolicy const, winrt::guid const);
            *result = detach_from<Windows::Foundation::IAsyncOperation<Windows::Devices::SmartCards::SmartCardProvisioning>>(this->shim().RequestVirtualSmartCardCreationAsync(*reinterpret_cast<hstring const*>(&friendlyName), *reinterpret_cast<Windows::Storage::Streams::IBuffer const*>(&administrativeKey), *reinterpret_cast<Windows::Devices::SmartCards::SmartCardPinPolicy const*>(&pinPolicy), *reinterpret_cast<winrt::guid const*>(&cardId)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL RequestVirtualSmartCardDeletionAsync(void* card, void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(RequestVirtualSmartCardDeletionAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<bool>), Windows::Devices::SmartCards::SmartCard const);
            *result = detach_from<Windows::Foundation::IAsyncOperation<bool>>(this->shim().RequestVirtualSmartCardDeletionAsync(*reinterpret_cast<Windows::Devices::SmartCards::SmartCard const*>(&card)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Devices::SmartCards::ISmartCardProvisioningStatics2> : produce_base<D, Windows::Devices::SmartCards::ISmartCardProvisioningStatics2>
{
    int32_t WINRT_CALL RequestAttestedVirtualSmartCardCreationAsync(void* friendlyName, void* administrativeKey, void* pinPolicy, void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(RequestAttestedVirtualSmartCardCreationAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<Windows::Devices::SmartCards::SmartCardProvisioning>), hstring const, Windows::Storage::Streams::IBuffer const, Windows::Devices::SmartCards::SmartCardPinPolicy const);
            *result = detach_from<Windows::Foundation::IAsyncOperation<Windows::Devices::SmartCards::SmartCardProvisioning>>(this->shim().RequestAttestedVirtualSmartCardCreationAsync(*reinterpret_cast<hstring const*>(&friendlyName), *reinterpret_cast<Windows::Storage::Streams::IBuffer const*>(&administrativeKey), *reinterpret_cast<Windows::Devices::SmartCards::SmartCardPinPolicy const*>(&pinPolicy)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL RequestAttestedVirtualSmartCardCreationAsyncWithCardId(void* friendlyName, void* administrativeKey, void* pinPolicy, winrt::guid cardId, void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(RequestAttestedVirtualSmartCardCreationAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<Windows::Devices::SmartCards::SmartCardProvisioning>), hstring const, Windows::Storage::Streams::IBuffer const, Windows::Devices::SmartCards::SmartCardPinPolicy const, winrt::guid const);
            *result = detach_from<Windows::Foundation::IAsyncOperation<Windows::Devices::SmartCards::SmartCardProvisioning>>(this->shim().RequestAttestedVirtualSmartCardCreationAsync(*reinterpret_cast<hstring const*>(&friendlyName), *reinterpret_cast<Windows::Storage::Streams::IBuffer const*>(&administrativeKey), *reinterpret_cast<Windows::Devices::SmartCards::SmartCardPinPolicy const*>(&pinPolicy), *reinterpret_cast<winrt::guid const*>(&cardId)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Devices::SmartCards::ISmartCardReader> : produce_base<D, Windows::Devices::SmartCards::ISmartCardReader>
{
    int32_t WINRT_CALL get_DeviceId(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(DeviceId, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().DeviceId());
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

    int32_t WINRT_CALL get_Kind(Windows::Devices::SmartCards::SmartCardReaderKind* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Kind, WINRT_WRAP(Windows::Devices::SmartCards::SmartCardReaderKind));
            *value = detach_from<Windows::Devices::SmartCards::SmartCardReaderKind>(this->shim().Kind());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL GetStatusAsync(void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetStatusAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<Windows::Devices::SmartCards::SmartCardReaderStatus>));
            *result = detach_from<Windows::Foundation::IAsyncOperation<Windows::Devices::SmartCards::SmartCardReaderStatus>>(this->shim().GetStatusAsync());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL FindAllCardsAsync(void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(FindAllCardsAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<Windows::Foundation::Collections::IVectorView<Windows::Devices::SmartCards::SmartCard>>));
            *result = detach_from<Windows::Foundation::IAsyncOperation<Windows::Foundation::Collections::IVectorView<Windows::Devices::SmartCards::SmartCard>>>(this->shim().FindAllCardsAsync());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL add_CardAdded(void* handler, winrt::event_token* token) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CardAdded, WINRT_WRAP(winrt::event_token), Windows::Foundation::TypedEventHandler<Windows::Devices::SmartCards::SmartCardReader, Windows::Devices::SmartCards::CardAddedEventArgs> const&);
            *token = detach_from<winrt::event_token>(this->shim().CardAdded(*reinterpret_cast<Windows::Foundation::TypedEventHandler<Windows::Devices::SmartCards::SmartCardReader, Windows::Devices::SmartCards::CardAddedEventArgs> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL remove_CardAdded(winrt::event_token token) noexcept final
    {
        typename D::abi_guard guard(this->shim());
        WINRT_ASSERT_DECLARATION(CardAdded, WINRT_WRAP(void), winrt::event_token const&);
        this->shim().CardAdded(*reinterpret_cast<winrt::event_token const*>(&token));
        return 0;
    }

    int32_t WINRT_CALL add_CardRemoved(void* handler, winrt::event_token* token) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CardRemoved, WINRT_WRAP(winrt::event_token), Windows::Foundation::TypedEventHandler<Windows::Devices::SmartCards::SmartCardReader, Windows::Devices::SmartCards::CardRemovedEventArgs> const&);
            *token = detach_from<winrt::event_token>(this->shim().CardRemoved(*reinterpret_cast<Windows::Foundation::TypedEventHandler<Windows::Devices::SmartCards::SmartCardReader, Windows::Devices::SmartCards::CardRemovedEventArgs> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL remove_CardRemoved(winrt::event_token token) noexcept final
    {
        typename D::abi_guard guard(this->shim());
        WINRT_ASSERT_DECLARATION(CardRemoved, WINRT_WRAP(void), winrt::event_token const&);
        this->shim().CardRemoved(*reinterpret_cast<winrt::event_token const*>(&token));
        return 0;
    }
};

template <typename D>
struct produce<D, Windows::Devices::SmartCards::ISmartCardReaderStatics> : produce_base<D, Windows::Devices::SmartCards::ISmartCardReaderStatics>
{
    int32_t WINRT_CALL GetDeviceSelector(void** selector) noexcept final
    {
        try
        {
            *selector = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetDeviceSelector, WINRT_WRAP(hstring));
            *selector = detach_from<hstring>(this->shim().GetDeviceSelector());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL GetDeviceSelectorWithKind(Windows::Devices::SmartCards::SmartCardReaderKind kind, void** selector) noexcept final
    {
        try
        {
            *selector = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetDeviceSelector, WINRT_WRAP(hstring), Windows::Devices::SmartCards::SmartCardReaderKind const&);
            *selector = detach_from<hstring>(this->shim().GetDeviceSelector(*reinterpret_cast<Windows::Devices::SmartCards::SmartCardReaderKind const*>(&kind)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL FromIdAsync(void* deviceId, void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(FromIdAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<Windows::Devices::SmartCards::SmartCardReader>), hstring const);
            *result = detach_from<Windows::Foundation::IAsyncOperation<Windows::Devices::SmartCards::SmartCardReader>>(this->shim().FromIdAsync(*reinterpret_cast<hstring const*>(&deviceId)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Devices::SmartCards::ISmartCardTriggerDetails> : produce_base<D, Windows::Devices::SmartCards::ISmartCardTriggerDetails>
{
    int32_t WINRT_CALL get_TriggerType(Windows::Devices::SmartCards::SmartCardTriggerType* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(TriggerType, WINRT_WRAP(Windows::Devices::SmartCards::SmartCardTriggerType));
            *value = detach_from<Windows::Devices::SmartCards::SmartCardTriggerType>(this->shim().TriggerType());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_SourceAppletId(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SourceAppletId, WINRT_WRAP(Windows::Storage::Streams::IBuffer));
            *value = detach_from<Windows::Storage::Streams::IBuffer>(this->shim().SourceAppletId());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_TriggerData(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(TriggerData, WINRT_WRAP(Windows::Storage::Streams::IBuffer));
            *value = detach_from<Windows::Storage::Streams::IBuffer>(this->shim().TriggerData());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Devices::SmartCards::ISmartCardTriggerDetails2> : produce_base<D, Windows::Devices::SmartCards::ISmartCardTriggerDetails2>
{
    int32_t WINRT_CALL get_Emulator(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Emulator, WINRT_WRAP(Windows::Devices::SmartCards::SmartCardEmulator));
            *value = detach_from<Windows::Devices::SmartCards::SmartCardEmulator>(this->shim().Emulator());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL TryLaunchCurrentAppAsync(void* arguments, void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(TryLaunchCurrentAppAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<bool>), hstring const);
            *result = detach_from<Windows::Foundation::IAsyncOperation<bool>>(this->shim().TryLaunchCurrentAppAsync(*reinterpret_cast<hstring const*>(&arguments)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL TryLaunchCurrentAppWithBehaviorAsync(void* arguments, Windows::Devices::SmartCards::SmartCardLaunchBehavior behavior, void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(TryLaunchCurrentAppAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<bool>), hstring const, Windows::Devices::SmartCards::SmartCardLaunchBehavior const);
            *result = detach_from<Windows::Foundation::IAsyncOperation<bool>>(this->shim().TryLaunchCurrentAppAsync(*reinterpret_cast<hstring const*>(&arguments), *reinterpret_cast<Windows::Devices::SmartCards::SmartCardLaunchBehavior const*>(&behavior)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Devices::SmartCards::ISmartCardTriggerDetails3> : produce_base<D, Windows::Devices::SmartCards::ISmartCardTriggerDetails3>
{
    int32_t WINRT_CALL get_SmartCard(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SmartCard, WINRT_WRAP(Windows::Devices::SmartCards::SmartCard));
            *value = detach_from<Windows::Devices::SmartCards::SmartCard>(this->shim().SmartCard());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

}

WINRT_EXPORT namespace winrt::Windows::Devices::SmartCards {

inline Windows::Storage::Streams::IBuffer KnownSmartCardAppletIds::PaymentSystemEnvironment()
{
    return impl::call_factory<KnownSmartCardAppletIds, Windows::Devices::SmartCards::IKnownSmartCardAppletIds>([&](auto&& f) { return f.PaymentSystemEnvironment(); });
}

inline Windows::Storage::Streams::IBuffer KnownSmartCardAppletIds::ProximityPaymentSystemEnvironment()
{
    return impl::call_factory<KnownSmartCardAppletIds, Windows::Devices::SmartCards::IKnownSmartCardAppletIds>([&](auto&& f) { return f.ProximityPaymentSystemEnvironment(); });
}

inline SmartCardAppletIdGroup::SmartCardAppletIdGroup() :
    SmartCardAppletIdGroup(impl::call_factory<SmartCardAppletIdGroup>([](auto&& f) { return f.template ActivateInstance<SmartCardAppletIdGroup>(); }))
{}

inline SmartCardAppletIdGroup::SmartCardAppletIdGroup(param::hstring const& displayName, param::vector<Windows::Storage::Streams::IBuffer> const& appletIds, Windows::Devices::SmartCards::SmartCardEmulationCategory const& emulationCategory, Windows::Devices::SmartCards::SmartCardEmulationType const& emulationType) :
    SmartCardAppletIdGroup(impl::call_factory<SmartCardAppletIdGroup, Windows::Devices::SmartCards::ISmartCardAppletIdGroupFactory>([&](auto&& f) { return f.Create(displayName, appletIds, emulationCategory, emulationType); }))
{}

inline uint16_t SmartCardAppletIdGroup::MaxAppletIds()
{
    return impl::call_factory<SmartCardAppletIdGroup, Windows::Devices::SmartCards::ISmartCardAppletIdGroupStatics>([&](auto&& f) { return f.MaxAppletIds(); });
}

inline SmartCardAutomaticResponseApdu::SmartCardAutomaticResponseApdu(Windows::Storage::Streams::IBuffer const& commandApdu, Windows::Storage::Streams::IBuffer const& responseApdu) :
    SmartCardAutomaticResponseApdu(impl::call_factory<SmartCardAutomaticResponseApdu, Windows::Devices::SmartCards::ISmartCardAutomaticResponseApduFactory>([&](auto&& f) { return f.Create(commandApdu, responseApdu); }))
{}

inline Windows::Foundation::IAsyncOperation<Windows::Devices::SmartCards::SmartCardCryptogramGenerator> SmartCardCryptogramGenerator::GetSmartCardCryptogramGeneratorAsync()
{
    return impl::call_factory<SmartCardCryptogramGenerator, Windows::Devices::SmartCards::ISmartCardCryptogramGeneratorStatics>([&](auto&& f) { return f.GetSmartCardCryptogramGeneratorAsync(); });
}

inline bool SmartCardCryptogramGenerator::IsSupported()
{
    return impl::call_factory<SmartCardCryptogramGenerator, Windows::Devices::SmartCards::ISmartCardCryptogramGeneratorStatics2>([&](auto&& f) { return f.IsSupported(); });
}

inline SmartCardCryptogramGetAllCryptogramMaterialCharacteristicsResult::SmartCardCryptogramGetAllCryptogramMaterialCharacteristicsResult() :
    SmartCardCryptogramGetAllCryptogramMaterialCharacteristicsResult(impl::call_factory<SmartCardCryptogramGetAllCryptogramMaterialCharacteristicsResult>([](auto&& f) { return f.template ActivateInstance<SmartCardCryptogramGetAllCryptogramMaterialCharacteristicsResult>(); }))
{}

inline SmartCardCryptogramGetAllCryptogramMaterialPackageCharacteristicsResult::SmartCardCryptogramGetAllCryptogramMaterialPackageCharacteristicsResult() :
    SmartCardCryptogramGetAllCryptogramMaterialPackageCharacteristicsResult(impl::call_factory<SmartCardCryptogramGetAllCryptogramMaterialPackageCharacteristicsResult>([](auto&& f) { return f.template ActivateInstance<SmartCardCryptogramGetAllCryptogramMaterialPackageCharacteristicsResult>(); }))
{}

inline SmartCardCryptogramGetAllCryptogramStorageKeyCharacteristicsResult::SmartCardCryptogramGetAllCryptogramStorageKeyCharacteristicsResult() :
    SmartCardCryptogramGetAllCryptogramStorageKeyCharacteristicsResult(impl::call_factory<SmartCardCryptogramGetAllCryptogramStorageKeyCharacteristicsResult>([](auto&& f) { return f.template ActivateInstance<SmartCardCryptogramGetAllCryptogramStorageKeyCharacteristicsResult>(); }))
{}

inline SmartCardCryptogramMaterialCharacteristics::SmartCardCryptogramMaterialCharacteristics() :
    SmartCardCryptogramMaterialCharacteristics(impl::call_factory<SmartCardCryptogramMaterialCharacteristics>([](auto&& f) { return f.template ActivateInstance<SmartCardCryptogramMaterialCharacteristics>(); }))
{}

inline SmartCardCryptogramMaterialPackageCharacteristics::SmartCardCryptogramMaterialPackageCharacteristics() :
    SmartCardCryptogramMaterialPackageCharacteristics(impl::call_factory<SmartCardCryptogramMaterialPackageCharacteristics>([](auto&& f) { return f.template ActivateInstance<SmartCardCryptogramMaterialPackageCharacteristics>(); }))
{}

inline SmartCardCryptogramPlacementStep::SmartCardCryptogramPlacementStep() :
    SmartCardCryptogramPlacementStep(impl::call_factory<SmartCardCryptogramPlacementStep>([](auto&& f) { return f.template ActivateInstance<SmartCardCryptogramPlacementStep>(); }))
{}

inline SmartCardCryptogramStorageKeyCharacteristics::SmartCardCryptogramStorageKeyCharacteristics() :
    SmartCardCryptogramStorageKeyCharacteristics(impl::call_factory<SmartCardCryptogramStorageKeyCharacteristics>([](auto&& f) { return f.template ActivateInstance<SmartCardCryptogramStorageKeyCharacteristics>(); }))
{}

inline Windows::Foundation::IAsyncOperation<Windows::Devices::SmartCards::SmartCardEmulator> SmartCardEmulator::GetDefaultAsync()
{
    return impl::call_factory<SmartCardEmulator, Windows::Devices::SmartCards::ISmartCardEmulatorStatics>([&](auto&& f) { return f.GetDefaultAsync(); });
}

inline Windows::Foundation::IAsyncOperation<Windows::Foundation::Collections::IVectorView<Windows::Devices::SmartCards::SmartCardAppletIdGroupRegistration>> SmartCardEmulator::GetAppletIdGroupRegistrationsAsync()
{
    return impl::call_factory<SmartCardEmulator, Windows::Devices::SmartCards::ISmartCardEmulatorStatics2>([&](auto&& f) { return f.GetAppletIdGroupRegistrationsAsync(); });
}

inline Windows::Foundation::IAsyncOperation<Windows::Devices::SmartCards::SmartCardAppletIdGroupRegistration> SmartCardEmulator::RegisterAppletIdGroupAsync(Windows::Devices::SmartCards::SmartCardAppletIdGroup const& appletIdGroup)
{
    return impl::call_factory<SmartCardEmulator, Windows::Devices::SmartCards::ISmartCardEmulatorStatics2>([&](auto&& f) { return f.RegisterAppletIdGroupAsync(appletIdGroup); });
}

inline Windows::Foundation::IAsyncAction SmartCardEmulator::UnregisterAppletIdGroupAsync(Windows::Devices::SmartCards::SmartCardAppletIdGroupRegistration const& registration)
{
    return impl::call_factory<SmartCardEmulator, Windows::Devices::SmartCards::ISmartCardEmulatorStatics2>([&](auto&& f) { return f.UnregisterAppletIdGroupAsync(registration); });
}

inline uint16_t SmartCardEmulator::MaxAppletIdGroupRegistrations()
{
    return impl::call_factory<SmartCardEmulator, Windows::Devices::SmartCards::ISmartCardEmulatorStatics2>([&](auto&& f) { return f.MaxAppletIdGroupRegistrations(); });
}

inline bool SmartCardEmulator::IsSupported()
{
    return impl::call_factory<SmartCardEmulator, Windows::Devices::SmartCards::ISmartCardEmulatorStatics3>([&](auto&& f) { return f.IsSupported(); });
}

inline SmartCardPinPolicy::SmartCardPinPolicy() :
    SmartCardPinPolicy(impl::call_factory<SmartCardPinPolicy>([](auto&& f) { return f.template ActivateInstance<SmartCardPinPolicy>(); }))
{}

inline Windows::Foundation::IAsyncOperation<Windows::Devices::SmartCards::SmartCardProvisioning> SmartCardProvisioning::FromSmartCardAsync(Windows::Devices::SmartCards::SmartCard const& card)
{
    return impl::call_factory<SmartCardProvisioning, Windows::Devices::SmartCards::ISmartCardProvisioningStatics>([&](auto&& f) { return f.FromSmartCardAsync(card); });
}

inline Windows::Foundation::IAsyncOperation<Windows::Devices::SmartCards::SmartCardProvisioning> SmartCardProvisioning::RequestVirtualSmartCardCreationAsync(param::hstring const& friendlyName, Windows::Storage::Streams::IBuffer const& administrativeKey, Windows::Devices::SmartCards::SmartCardPinPolicy const& pinPolicy)
{
    return impl::call_factory<SmartCardProvisioning, Windows::Devices::SmartCards::ISmartCardProvisioningStatics>([&](auto&& f) { return f.RequestVirtualSmartCardCreationAsync(friendlyName, administrativeKey, pinPolicy); });
}

inline Windows::Foundation::IAsyncOperation<Windows::Devices::SmartCards::SmartCardProvisioning> SmartCardProvisioning::RequestVirtualSmartCardCreationAsync(param::hstring const& friendlyName, Windows::Storage::Streams::IBuffer const& administrativeKey, Windows::Devices::SmartCards::SmartCardPinPolicy const& pinPolicy, winrt::guid const& cardId)
{
    return impl::call_factory<SmartCardProvisioning, Windows::Devices::SmartCards::ISmartCardProvisioningStatics>([&](auto&& f) { return f.RequestVirtualSmartCardCreationAsync(friendlyName, administrativeKey, pinPolicy, cardId); });
}

inline Windows::Foundation::IAsyncOperation<bool> SmartCardProvisioning::RequestVirtualSmartCardDeletionAsync(Windows::Devices::SmartCards::SmartCard const& card)
{
    return impl::call_factory<SmartCardProvisioning, Windows::Devices::SmartCards::ISmartCardProvisioningStatics>([&](auto&& f) { return f.RequestVirtualSmartCardDeletionAsync(card); });
}

inline Windows::Foundation::IAsyncOperation<Windows::Devices::SmartCards::SmartCardProvisioning> SmartCardProvisioning::RequestAttestedVirtualSmartCardCreationAsync(param::hstring const& friendlyName, Windows::Storage::Streams::IBuffer const& administrativeKey, Windows::Devices::SmartCards::SmartCardPinPolicy const& pinPolicy)
{
    return impl::call_factory<SmartCardProvisioning, Windows::Devices::SmartCards::ISmartCardProvisioningStatics2>([&](auto&& f) { return f.RequestAttestedVirtualSmartCardCreationAsync(friendlyName, administrativeKey, pinPolicy); });
}

inline Windows::Foundation::IAsyncOperation<Windows::Devices::SmartCards::SmartCardProvisioning> SmartCardProvisioning::RequestAttestedVirtualSmartCardCreationAsync(param::hstring const& friendlyName, Windows::Storage::Streams::IBuffer const& administrativeKey, Windows::Devices::SmartCards::SmartCardPinPolicy const& pinPolicy, winrt::guid const& cardId)
{
    return impl::call_factory<SmartCardProvisioning, Windows::Devices::SmartCards::ISmartCardProvisioningStatics2>([&](auto&& f) { return f.RequestAttestedVirtualSmartCardCreationAsync(friendlyName, administrativeKey, pinPolicy, cardId); });
}

inline hstring SmartCardReader::GetDeviceSelector()
{
    return impl::call_factory<SmartCardReader, Windows::Devices::SmartCards::ISmartCardReaderStatics>([&](auto&& f) { return f.GetDeviceSelector(); });
}

inline hstring SmartCardReader::GetDeviceSelector(Windows::Devices::SmartCards::SmartCardReaderKind const& kind)
{
    return impl::call_factory<SmartCardReader, Windows::Devices::SmartCards::ISmartCardReaderStatics>([&](auto&& f) { return f.GetDeviceSelector(kind); });
}

inline Windows::Foundation::IAsyncOperation<Windows::Devices::SmartCards::SmartCardReader> SmartCardReader::FromIdAsync(param::hstring const& deviceId)
{
    return impl::call_factory<SmartCardReader, Windows::Devices::SmartCards::ISmartCardReaderStatics>([&](auto&& f) { return f.FromIdAsync(deviceId); });
}

template <typename L> SmartCardPinResetHandler::SmartCardPinResetHandler(L handler) :
    SmartCardPinResetHandler(impl::make_delegate<SmartCardPinResetHandler>(std::forward<L>(handler)))
{}

template <typename F> SmartCardPinResetHandler::SmartCardPinResetHandler(F* handler) :
    SmartCardPinResetHandler([=](auto&&... args) { return handler(args...); })
{}

template <typename O, typename M> SmartCardPinResetHandler::SmartCardPinResetHandler(O* object, M method) :
    SmartCardPinResetHandler([=](auto&&... args) { return ((*object).*(method))(args...); })
{}

template <typename O, typename M> SmartCardPinResetHandler::SmartCardPinResetHandler(com_ptr<O>&& object, M method) :
    SmartCardPinResetHandler([o = std::move(object), method](auto&&... args) { return ((*o).*(method))(args...); })
{}

template <typename O, typename M> SmartCardPinResetHandler::SmartCardPinResetHandler(weak_ref<O>&& object, M method) :
    SmartCardPinResetHandler([o = std::move(object), method](auto&&... args) { if (auto s = o.get()) { ((*s).*(method))(args...); } })
{}

inline void SmartCardPinResetHandler::operator()(Windows::Devices::SmartCards::SmartCardProvisioning const& sender, Windows::Devices::SmartCards::SmartCardPinResetRequest const& request) const
{
    check_hresult((*(impl::abi_t<SmartCardPinResetHandler>**)this)->Invoke(get_abi(sender), get_abi(request)));
}

}

WINRT_EXPORT namespace std {

template<> struct hash<winrt::Windows::Devices::SmartCards::ICardAddedEventArgs> : winrt::impl::hash_base<winrt::Windows::Devices::SmartCards::ICardAddedEventArgs> {};
template<> struct hash<winrt::Windows::Devices::SmartCards::ICardRemovedEventArgs> : winrt::impl::hash_base<winrt::Windows::Devices::SmartCards::ICardRemovedEventArgs> {};
template<> struct hash<winrt::Windows::Devices::SmartCards::IKnownSmartCardAppletIds> : winrt::impl::hash_base<winrt::Windows::Devices::SmartCards::IKnownSmartCardAppletIds> {};
template<> struct hash<winrt::Windows::Devices::SmartCards::ISmartCard> : winrt::impl::hash_base<winrt::Windows::Devices::SmartCards::ISmartCard> {};
template<> struct hash<winrt::Windows::Devices::SmartCards::ISmartCardAppletIdGroup> : winrt::impl::hash_base<winrt::Windows::Devices::SmartCards::ISmartCardAppletIdGroup> {};
template<> struct hash<winrt::Windows::Devices::SmartCards::ISmartCardAppletIdGroup2> : winrt::impl::hash_base<winrt::Windows::Devices::SmartCards::ISmartCardAppletIdGroup2> {};
template<> struct hash<winrt::Windows::Devices::SmartCards::ISmartCardAppletIdGroupFactory> : winrt::impl::hash_base<winrt::Windows::Devices::SmartCards::ISmartCardAppletIdGroupFactory> {};
template<> struct hash<winrt::Windows::Devices::SmartCards::ISmartCardAppletIdGroupRegistration> : winrt::impl::hash_base<winrt::Windows::Devices::SmartCards::ISmartCardAppletIdGroupRegistration> {};
template<> struct hash<winrt::Windows::Devices::SmartCards::ISmartCardAppletIdGroupRegistration2> : winrt::impl::hash_base<winrt::Windows::Devices::SmartCards::ISmartCardAppletIdGroupRegistration2> {};
template<> struct hash<winrt::Windows::Devices::SmartCards::ISmartCardAppletIdGroupStatics> : winrt::impl::hash_base<winrt::Windows::Devices::SmartCards::ISmartCardAppletIdGroupStatics> {};
template<> struct hash<winrt::Windows::Devices::SmartCards::ISmartCardAutomaticResponseApdu> : winrt::impl::hash_base<winrt::Windows::Devices::SmartCards::ISmartCardAutomaticResponseApdu> {};
template<> struct hash<winrt::Windows::Devices::SmartCards::ISmartCardAutomaticResponseApdu2> : winrt::impl::hash_base<winrt::Windows::Devices::SmartCards::ISmartCardAutomaticResponseApdu2> {};
template<> struct hash<winrt::Windows::Devices::SmartCards::ISmartCardAutomaticResponseApdu3> : winrt::impl::hash_base<winrt::Windows::Devices::SmartCards::ISmartCardAutomaticResponseApdu3> {};
template<> struct hash<winrt::Windows::Devices::SmartCards::ISmartCardAutomaticResponseApduFactory> : winrt::impl::hash_base<winrt::Windows::Devices::SmartCards::ISmartCardAutomaticResponseApduFactory> {};
template<> struct hash<winrt::Windows::Devices::SmartCards::ISmartCardChallengeContext> : winrt::impl::hash_base<winrt::Windows::Devices::SmartCards::ISmartCardChallengeContext> {};
template<> struct hash<winrt::Windows::Devices::SmartCards::ISmartCardConnect> : winrt::impl::hash_base<winrt::Windows::Devices::SmartCards::ISmartCardConnect> {};
template<> struct hash<winrt::Windows::Devices::SmartCards::ISmartCardConnection> : winrt::impl::hash_base<winrt::Windows::Devices::SmartCards::ISmartCardConnection> {};
template<> struct hash<winrt::Windows::Devices::SmartCards::ISmartCardCryptogramGenerator> : winrt::impl::hash_base<winrt::Windows::Devices::SmartCards::ISmartCardCryptogramGenerator> {};
template<> struct hash<winrt::Windows::Devices::SmartCards::ISmartCardCryptogramGenerator2> : winrt::impl::hash_base<winrt::Windows::Devices::SmartCards::ISmartCardCryptogramGenerator2> {};
template<> struct hash<winrt::Windows::Devices::SmartCards::ISmartCardCryptogramGeneratorStatics> : winrt::impl::hash_base<winrt::Windows::Devices::SmartCards::ISmartCardCryptogramGeneratorStatics> {};
template<> struct hash<winrt::Windows::Devices::SmartCards::ISmartCardCryptogramGeneratorStatics2> : winrt::impl::hash_base<winrt::Windows::Devices::SmartCards::ISmartCardCryptogramGeneratorStatics2> {};
template<> struct hash<winrt::Windows::Devices::SmartCards::ISmartCardCryptogramGetAllCryptogramMaterialCharacteristicsResult> : winrt::impl::hash_base<winrt::Windows::Devices::SmartCards::ISmartCardCryptogramGetAllCryptogramMaterialCharacteristicsResult> {};
template<> struct hash<winrt::Windows::Devices::SmartCards::ISmartCardCryptogramGetAllCryptogramMaterialPackageCharacteristicsResult> : winrt::impl::hash_base<winrt::Windows::Devices::SmartCards::ISmartCardCryptogramGetAllCryptogramMaterialPackageCharacteristicsResult> {};
template<> struct hash<winrt::Windows::Devices::SmartCards::ISmartCardCryptogramGetAllCryptogramStorageKeyCharacteristicsResult> : winrt::impl::hash_base<winrt::Windows::Devices::SmartCards::ISmartCardCryptogramGetAllCryptogramStorageKeyCharacteristicsResult> {};
template<> struct hash<winrt::Windows::Devices::SmartCards::ISmartCardCryptogramMaterialCharacteristics> : winrt::impl::hash_base<winrt::Windows::Devices::SmartCards::ISmartCardCryptogramMaterialCharacteristics> {};
template<> struct hash<winrt::Windows::Devices::SmartCards::ISmartCardCryptogramMaterialPackageCharacteristics> : winrt::impl::hash_base<winrt::Windows::Devices::SmartCards::ISmartCardCryptogramMaterialPackageCharacteristics> {};
template<> struct hash<winrt::Windows::Devices::SmartCards::ISmartCardCryptogramMaterialPossessionProof> : winrt::impl::hash_base<winrt::Windows::Devices::SmartCards::ISmartCardCryptogramMaterialPossessionProof> {};
template<> struct hash<winrt::Windows::Devices::SmartCards::ISmartCardCryptogramPlacementStep> : winrt::impl::hash_base<winrt::Windows::Devices::SmartCards::ISmartCardCryptogramPlacementStep> {};
template<> struct hash<winrt::Windows::Devices::SmartCards::ISmartCardCryptogramStorageKeyCharacteristics> : winrt::impl::hash_base<winrt::Windows::Devices::SmartCards::ISmartCardCryptogramStorageKeyCharacteristics> {};
template<> struct hash<winrt::Windows::Devices::SmartCards::ISmartCardCryptogramStorageKeyInfo> : winrt::impl::hash_base<winrt::Windows::Devices::SmartCards::ISmartCardCryptogramStorageKeyInfo> {};
template<> struct hash<winrt::Windows::Devices::SmartCards::ISmartCardCryptogramStorageKeyInfo2> : winrt::impl::hash_base<winrt::Windows::Devices::SmartCards::ISmartCardCryptogramStorageKeyInfo2> {};
template<> struct hash<winrt::Windows::Devices::SmartCards::ISmartCardEmulator> : winrt::impl::hash_base<winrt::Windows::Devices::SmartCards::ISmartCardEmulator> {};
template<> struct hash<winrt::Windows::Devices::SmartCards::ISmartCardEmulator2> : winrt::impl::hash_base<winrt::Windows::Devices::SmartCards::ISmartCardEmulator2> {};
template<> struct hash<winrt::Windows::Devices::SmartCards::ISmartCardEmulatorApduReceivedEventArgs> : winrt::impl::hash_base<winrt::Windows::Devices::SmartCards::ISmartCardEmulatorApduReceivedEventArgs> {};
template<> struct hash<winrt::Windows::Devices::SmartCards::ISmartCardEmulatorApduReceivedEventArgs2> : winrt::impl::hash_base<winrt::Windows::Devices::SmartCards::ISmartCardEmulatorApduReceivedEventArgs2> {};
template<> struct hash<winrt::Windows::Devices::SmartCards::ISmartCardEmulatorApduReceivedEventArgsWithCryptograms> : winrt::impl::hash_base<winrt::Windows::Devices::SmartCards::ISmartCardEmulatorApduReceivedEventArgsWithCryptograms> {};
template<> struct hash<winrt::Windows::Devices::SmartCards::ISmartCardEmulatorConnectionDeactivatedEventArgs> : winrt::impl::hash_base<winrt::Windows::Devices::SmartCards::ISmartCardEmulatorConnectionDeactivatedEventArgs> {};
template<> struct hash<winrt::Windows::Devices::SmartCards::ISmartCardEmulatorConnectionProperties> : winrt::impl::hash_base<winrt::Windows::Devices::SmartCards::ISmartCardEmulatorConnectionProperties> {};
template<> struct hash<winrt::Windows::Devices::SmartCards::ISmartCardEmulatorStatics> : winrt::impl::hash_base<winrt::Windows::Devices::SmartCards::ISmartCardEmulatorStatics> {};
template<> struct hash<winrt::Windows::Devices::SmartCards::ISmartCardEmulatorStatics2> : winrt::impl::hash_base<winrt::Windows::Devices::SmartCards::ISmartCardEmulatorStatics2> {};
template<> struct hash<winrt::Windows::Devices::SmartCards::ISmartCardEmulatorStatics3> : winrt::impl::hash_base<winrt::Windows::Devices::SmartCards::ISmartCardEmulatorStatics3> {};
template<> struct hash<winrt::Windows::Devices::SmartCards::ISmartCardPinPolicy> : winrt::impl::hash_base<winrt::Windows::Devices::SmartCards::ISmartCardPinPolicy> {};
template<> struct hash<winrt::Windows::Devices::SmartCards::ISmartCardPinResetDeferral> : winrt::impl::hash_base<winrt::Windows::Devices::SmartCards::ISmartCardPinResetDeferral> {};
template<> struct hash<winrt::Windows::Devices::SmartCards::ISmartCardPinResetRequest> : winrt::impl::hash_base<winrt::Windows::Devices::SmartCards::ISmartCardPinResetRequest> {};
template<> struct hash<winrt::Windows::Devices::SmartCards::ISmartCardProvisioning> : winrt::impl::hash_base<winrt::Windows::Devices::SmartCards::ISmartCardProvisioning> {};
template<> struct hash<winrt::Windows::Devices::SmartCards::ISmartCardProvisioning2> : winrt::impl::hash_base<winrt::Windows::Devices::SmartCards::ISmartCardProvisioning2> {};
template<> struct hash<winrt::Windows::Devices::SmartCards::ISmartCardProvisioningStatics> : winrt::impl::hash_base<winrt::Windows::Devices::SmartCards::ISmartCardProvisioningStatics> {};
template<> struct hash<winrt::Windows::Devices::SmartCards::ISmartCardProvisioningStatics2> : winrt::impl::hash_base<winrt::Windows::Devices::SmartCards::ISmartCardProvisioningStatics2> {};
template<> struct hash<winrt::Windows::Devices::SmartCards::ISmartCardReader> : winrt::impl::hash_base<winrt::Windows::Devices::SmartCards::ISmartCardReader> {};
template<> struct hash<winrt::Windows::Devices::SmartCards::ISmartCardReaderStatics> : winrt::impl::hash_base<winrt::Windows::Devices::SmartCards::ISmartCardReaderStatics> {};
template<> struct hash<winrt::Windows::Devices::SmartCards::ISmartCardTriggerDetails> : winrt::impl::hash_base<winrt::Windows::Devices::SmartCards::ISmartCardTriggerDetails> {};
template<> struct hash<winrt::Windows::Devices::SmartCards::ISmartCardTriggerDetails2> : winrt::impl::hash_base<winrt::Windows::Devices::SmartCards::ISmartCardTriggerDetails2> {};
template<> struct hash<winrt::Windows::Devices::SmartCards::ISmartCardTriggerDetails3> : winrt::impl::hash_base<winrt::Windows::Devices::SmartCards::ISmartCardTriggerDetails3> {};
template<> struct hash<winrt::Windows::Devices::SmartCards::CardAddedEventArgs> : winrt::impl::hash_base<winrt::Windows::Devices::SmartCards::CardAddedEventArgs> {};
template<> struct hash<winrt::Windows::Devices::SmartCards::CardRemovedEventArgs> : winrt::impl::hash_base<winrt::Windows::Devices::SmartCards::CardRemovedEventArgs> {};
template<> struct hash<winrt::Windows::Devices::SmartCards::KnownSmartCardAppletIds> : winrt::impl::hash_base<winrt::Windows::Devices::SmartCards::KnownSmartCardAppletIds> {};
template<> struct hash<winrt::Windows::Devices::SmartCards::SmartCard> : winrt::impl::hash_base<winrt::Windows::Devices::SmartCards::SmartCard> {};
template<> struct hash<winrt::Windows::Devices::SmartCards::SmartCardAppletIdGroup> : winrt::impl::hash_base<winrt::Windows::Devices::SmartCards::SmartCardAppletIdGroup> {};
template<> struct hash<winrt::Windows::Devices::SmartCards::SmartCardAppletIdGroupRegistration> : winrt::impl::hash_base<winrt::Windows::Devices::SmartCards::SmartCardAppletIdGroupRegistration> {};
template<> struct hash<winrt::Windows::Devices::SmartCards::SmartCardAutomaticResponseApdu> : winrt::impl::hash_base<winrt::Windows::Devices::SmartCards::SmartCardAutomaticResponseApdu> {};
template<> struct hash<winrt::Windows::Devices::SmartCards::SmartCardChallengeContext> : winrt::impl::hash_base<winrt::Windows::Devices::SmartCards::SmartCardChallengeContext> {};
template<> struct hash<winrt::Windows::Devices::SmartCards::SmartCardConnection> : winrt::impl::hash_base<winrt::Windows::Devices::SmartCards::SmartCardConnection> {};
template<> struct hash<winrt::Windows::Devices::SmartCards::SmartCardCryptogramGenerator> : winrt::impl::hash_base<winrt::Windows::Devices::SmartCards::SmartCardCryptogramGenerator> {};
template<> struct hash<winrt::Windows::Devices::SmartCards::SmartCardCryptogramGetAllCryptogramMaterialCharacteristicsResult> : winrt::impl::hash_base<winrt::Windows::Devices::SmartCards::SmartCardCryptogramGetAllCryptogramMaterialCharacteristicsResult> {};
template<> struct hash<winrt::Windows::Devices::SmartCards::SmartCardCryptogramGetAllCryptogramMaterialPackageCharacteristicsResult> : winrt::impl::hash_base<winrt::Windows::Devices::SmartCards::SmartCardCryptogramGetAllCryptogramMaterialPackageCharacteristicsResult> {};
template<> struct hash<winrt::Windows::Devices::SmartCards::SmartCardCryptogramGetAllCryptogramStorageKeyCharacteristicsResult> : winrt::impl::hash_base<winrt::Windows::Devices::SmartCards::SmartCardCryptogramGetAllCryptogramStorageKeyCharacteristicsResult> {};
template<> struct hash<winrt::Windows::Devices::SmartCards::SmartCardCryptogramMaterialCharacteristics> : winrt::impl::hash_base<winrt::Windows::Devices::SmartCards::SmartCardCryptogramMaterialCharacteristics> {};
template<> struct hash<winrt::Windows::Devices::SmartCards::SmartCardCryptogramMaterialPackageCharacteristics> : winrt::impl::hash_base<winrt::Windows::Devices::SmartCards::SmartCardCryptogramMaterialPackageCharacteristics> {};
template<> struct hash<winrt::Windows::Devices::SmartCards::SmartCardCryptogramMaterialPossessionProof> : winrt::impl::hash_base<winrt::Windows::Devices::SmartCards::SmartCardCryptogramMaterialPossessionProof> {};
template<> struct hash<winrt::Windows::Devices::SmartCards::SmartCardCryptogramPlacementStep> : winrt::impl::hash_base<winrt::Windows::Devices::SmartCards::SmartCardCryptogramPlacementStep> {};
template<> struct hash<winrt::Windows::Devices::SmartCards::SmartCardCryptogramStorageKeyCharacteristics> : winrt::impl::hash_base<winrt::Windows::Devices::SmartCards::SmartCardCryptogramStorageKeyCharacteristics> {};
template<> struct hash<winrt::Windows::Devices::SmartCards::SmartCardCryptogramStorageKeyInfo> : winrt::impl::hash_base<winrt::Windows::Devices::SmartCards::SmartCardCryptogramStorageKeyInfo> {};
template<> struct hash<winrt::Windows::Devices::SmartCards::SmartCardEmulator> : winrt::impl::hash_base<winrt::Windows::Devices::SmartCards::SmartCardEmulator> {};
template<> struct hash<winrt::Windows::Devices::SmartCards::SmartCardEmulatorApduReceivedEventArgs> : winrt::impl::hash_base<winrt::Windows::Devices::SmartCards::SmartCardEmulatorApduReceivedEventArgs> {};
template<> struct hash<winrt::Windows::Devices::SmartCards::SmartCardEmulatorConnectionDeactivatedEventArgs> : winrt::impl::hash_base<winrt::Windows::Devices::SmartCards::SmartCardEmulatorConnectionDeactivatedEventArgs> {};
template<> struct hash<winrt::Windows::Devices::SmartCards::SmartCardEmulatorConnectionProperties> : winrt::impl::hash_base<winrt::Windows::Devices::SmartCards::SmartCardEmulatorConnectionProperties> {};
template<> struct hash<winrt::Windows::Devices::SmartCards::SmartCardPinPolicy> : winrt::impl::hash_base<winrt::Windows::Devices::SmartCards::SmartCardPinPolicy> {};
template<> struct hash<winrt::Windows::Devices::SmartCards::SmartCardPinResetDeferral> : winrt::impl::hash_base<winrt::Windows::Devices::SmartCards::SmartCardPinResetDeferral> {};
template<> struct hash<winrt::Windows::Devices::SmartCards::SmartCardPinResetRequest> : winrt::impl::hash_base<winrt::Windows::Devices::SmartCards::SmartCardPinResetRequest> {};
template<> struct hash<winrt::Windows::Devices::SmartCards::SmartCardProvisioning> : winrt::impl::hash_base<winrt::Windows::Devices::SmartCards::SmartCardProvisioning> {};
template<> struct hash<winrt::Windows::Devices::SmartCards::SmartCardReader> : winrt::impl::hash_base<winrt::Windows::Devices::SmartCards::SmartCardReader> {};
template<> struct hash<winrt::Windows::Devices::SmartCards::SmartCardTriggerDetails> : winrt::impl::hash_base<winrt::Windows::Devices::SmartCards::SmartCardTriggerDetails> {};

}
