// C++/WinRT v1.0.190111.3

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#pragma once

#include "winrt/base.h"

#include "winrt/Windows.Foundation.h"
#include "winrt/Windows.Foundation.Collections.h"
#include "winrt/impl/Windows.Foundation.2.h"
#include "winrt/impl/Windows.Foundation.Collections.2.h"
#include "winrt/impl/Windows.Media.Core.2.h"
#include "winrt/impl/Windows.Media.Protection.2.h"
#include "winrt/impl/Windows.Storage.2.h"
#include "winrt/impl/Windows.Media.Protection.PlayReady.2.h"
#include "winrt/Windows.Media.Protection.h"

namespace winrt::impl {

template <typename D> winrt::event_token consume_Windows_Media_Protection_PlayReady_INDClient<D>::RegistrationCompleted(Windows::Foundation::TypedEventHandler<Windows::Media::Protection::PlayReady::NDClient, Windows::Media::Protection::PlayReady::INDRegistrationCompletedEventArgs> const& handler) const
{
    winrt::event_token token{};
    check_hresult(WINRT_SHIM(Windows::Media::Protection::PlayReady::INDClient)->add_RegistrationCompleted(get_abi(handler), put_abi(token)));
    return token;
}

template <typename D> typename consume_Windows_Media_Protection_PlayReady_INDClient<D>::RegistrationCompleted_revoker consume_Windows_Media_Protection_PlayReady_INDClient<D>::RegistrationCompleted(auto_revoke_t, Windows::Foundation::TypedEventHandler<Windows::Media::Protection::PlayReady::NDClient, Windows::Media::Protection::PlayReady::INDRegistrationCompletedEventArgs> const& handler) const
{
    return impl::make_event_revoker<D, RegistrationCompleted_revoker>(this, RegistrationCompleted(handler));
}

template <typename D> void consume_Windows_Media_Protection_PlayReady_INDClient<D>::RegistrationCompleted(winrt::event_token const& token) const noexcept
{
    WINRT_VERIFY_(0, WINRT_SHIM(Windows::Media::Protection::PlayReady::INDClient)->remove_RegistrationCompleted(get_abi(token)));
}

template <typename D> winrt::event_token consume_Windows_Media_Protection_PlayReady_INDClient<D>::ProximityDetectionCompleted(Windows::Foundation::TypedEventHandler<Windows::Media::Protection::PlayReady::NDClient, Windows::Media::Protection::PlayReady::INDProximityDetectionCompletedEventArgs> const& handler) const
{
    winrt::event_token token{};
    check_hresult(WINRT_SHIM(Windows::Media::Protection::PlayReady::INDClient)->add_ProximityDetectionCompleted(get_abi(handler), put_abi(token)));
    return token;
}

template <typename D> typename consume_Windows_Media_Protection_PlayReady_INDClient<D>::ProximityDetectionCompleted_revoker consume_Windows_Media_Protection_PlayReady_INDClient<D>::ProximityDetectionCompleted(auto_revoke_t, Windows::Foundation::TypedEventHandler<Windows::Media::Protection::PlayReady::NDClient, Windows::Media::Protection::PlayReady::INDProximityDetectionCompletedEventArgs> const& handler) const
{
    return impl::make_event_revoker<D, ProximityDetectionCompleted_revoker>(this, ProximityDetectionCompleted(handler));
}

template <typename D> void consume_Windows_Media_Protection_PlayReady_INDClient<D>::ProximityDetectionCompleted(winrt::event_token const& token) const noexcept
{
    WINRT_VERIFY_(0, WINRT_SHIM(Windows::Media::Protection::PlayReady::INDClient)->remove_ProximityDetectionCompleted(get_abi(token)));
}

template <typename D> winrt::event_token consume_Windows_Media_Protection_PlayReady_INDClient<D>::LicenseFetchCompleted(Windows::Foundation::TypedEventHandler<Windows::Media::Protection::PlayReady::NDClient, Windows::Media::Protection::PlayReady::INDLicenseFetchCompletedEventArgs> const& handler) const
{
    winrt::event_token token{};
    check_hresult(WINRT_SHIM(Windows::Media::Protection::PlayReady::INDClient)->add_LicenseFetchCompleted(get_abi(handler), put_abi(token)));
    return token;
}

template <typename D> typename consume_Windows_Media_Protection_PlayReady_INDClient<D>::LicenseFetchCompleted_revoker consume_Windows_Media_Protection_PlayReady_INDClient<D>::LicenseFetchCompleted(auto_revoke_t, Windows::Foundation::TypedEventHandler<Windows::Media::Protection::PlayReady::NDClient, Windows::Media::Protection::PlayReady::INDLicenseFetchCompletedEventArgs> const& handler) const
{
    return impl::make_event_revoker<D, LicenseFetchCompleted_revoker>(this, LicenseFetchCompleted(handler));
}

template <typename D> void consume_Windows_Media_Protection_PlayReady_INDClient<D>::LicenseFetchCompleted(winrt::event_token const& token) const noexcept
{
    WINRT_VERIFY_(0, WINRT_SHIM(Windows::Media::Protection::PlayReady::INDClient)->remove_LicenseFetchCompleted(get_abi(token)));
}

template <typename D> winrt::event_token consume_Windows_Media_Protection_PlayReady_INDClient<D>::ReRegistrationNeeded(Windows::Foundation::TypedEventHandler<Windows::Media::Protection::PlayReady::NDClient, Windows::Foundation::IInspectable> const& handler) const
{
    winrt::event_token token{};
    check_hresult(WINRT_SHIM(Windows::Media::Protection::PlayReady::INDClient)->add_ReRegistrationNeeded(get_abi(handler), put_abi(token)));
    return token;
}

template <typename D> typename consume_Windows_Media_Protection_PlayReady_INDClient<D>::ReRegistrationNeeded_revoker consume_Windows_Media_Protection_PlayReady_INDClient<D>::ReRegistrationNeeded(auto_revoke_t, Windows::Foundation::TypedEventHandler<Windows::Media::Protection::PlayReady::NDClient, Windows::Foundation::IInspectable> const& handler) const
{
    return impl::make_event_revoker<D, ReRegistrationNeeded_revoker>(this, ReRegistrationNeeded(handler));
}

template <typename D> void consume_Windows_Media_Protection_PlayReady_INDClient<D>::ReRegistrationNeeded(winrt::event_token const& token) const noexcept
{
    WINRT_VERIFY_(0, WINRT_SHIM(Windows::Media::Protection::PlayReady::INDClient)->remove_ReRegistrationNeeded(get_abi(token)));
}

template <typename D> winrt::event_token consume_Windows_Media_Protection_PlayReady_INDClient<D>::ClosedCaptionDataReceived(Windows::Foundation::TypedEventHandler<Windows::Media::Protection::PlayReady::NDClient, Windows::Media::Protection::PlayReady::INDClosedCaptionDataReceivedEventArgs> const& handler) const
{
    winrt::event_token token{};
    check_hresult(WINRT_SHIM(Windows::Media::Protection::PlayReady::INDClient)->add_ClosedCaptionDataReceived(get_abi(handler), put_abi(token)));
    return token;
}

template <typename D> typename consume_Windows_Media_Protection_PlayReady_INDClient<D>::ClosedCaptionDataReceived_revoker consume_Windows_Media_Protection_PlayReady_INDClient<D>::ClosedCaptionDataReceived(auto_revoke_t, Windows::Foundation::TypedEventHandler<Windows::Media::Protection::PlayReady::NDClient, Windows::Media::Protection::PlayReady::INDClosedCaptionDataReceivedEventArgs> const& handler) const
{
    return impl::make_event_revoker<D, ClosedCaptionDataReceived_revoker>(this, ClosedCaptionDataReceived(handler));
}

template <typename D> void consume_Windows_Media_Protection_PlayReady_INDClient<D>::ClosedCaptionDataReceived(winrt::event_token const& token) const noexcept
{
    WINRT_VERIFY_(0, WINRT_SHIM(Windows::Media::Protection::PlayReady::INDClient)->remove_ClosedCaptionDataReceived(get_abi(token)));
}

template <typename D> Windows::Foundation::IAsyncOperation<Windows::Media::Protection::PlayReady::INDStartResult> consume_Windows_Media_Protection_PlayReady_INDClient<D>::StartAsync(Windows::Foundation::Uri const& contentUrl, uint32_t startAsyncOptions, Windows::Media::Protection::PlayReady::INDCustomData const& registrationCustomData, Windows::Media::Protection::PlayReady::INDLicenseFetchDescriptor const& licenseFetchDescriptor) const
{
    Windows::Foundation::IAsyncOperation<Windows::Media::Protection::PlayReady::INDStartResult> result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Media::Protection::PlayReady::INDClient)->StartAsync(get_abi(contentUrl), startAsyncOptions, get_abi(registrationCustomData), get_abi(licenseFetchDescriptor), put_abi(result)));
    return result;
}

template <typename D> Windows::Foundation::IAsyncOperation<Windows::Media::Protection::PlayReady::INDLicenseFetchResult> consume_Windows_Media_Protection_PlayReady_INDClient<D>::LicenseFetchAsync(Windows::Media::Protection::PlayReady::INDLicenseFetchDescriptor const& licenseFetchDescriptor) const
{
    Windows::Foundation::IAsyncOperation<Windows::Media::Protection::PlayReady::INDLicenseFetchResult> result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Media::Protection::PlayReady::INDClient)->LicenseFetchAsync(get_abi(licenseFetchDescriptor), put_abi(result)));
    return result;
}

template <typename D> Windows::Foundation::IAsyncAction consume_Windows_Media_Protection_PlayReady_INDClient<D>::ReRegistrationAsync(Windows::Media::Protection::PlayReady::INDCustomData const& registrationCustomData) const
{
    Windows::Foundation::IAsyncAction result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Media::Protection::PlayReady::INDClient)->ReRegistrationAsync(get_abi(registrationCustomData), put_abi(result)));
    return result;
}

template <typename D> void consume_Windows_Media_Protection_PlayReady_INDClient<D>::Close() const
{
    check_hresult(WINRT_SHIM(Windows::Media::Protection::PlayReady::INDClient)->Close());
}

template <typename D> Windows::Media::Protection::PlayReady::NDClient consume_Windows_Media_Protection_PlayReady_INDClientFactory<D>::CreateInstance(Windows::Media::Protection::PlayReady::INDDownloadEngine const& downloadEngine, Windows::Media::Protection::PlayReady::INDStreamParser const& streamParser, Windows::Media::Protection::PlayReady::INDMessenger const& pMessenger) const
{
    Windows::Media::Protection::PlayReady::NDClient instance{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Media::Protection::PlayReady::INDClientFactory)->CreateInstance(get_abi(downloadEngine), get_abi(streamParser), get_abi(pMessenger), put_abi(instance)));
    return instance;
}

template <typename D> Windows::Media::Protection::PlayReady::NDClosedCaptionFormat consume_Windows_Media_Protection_PlayReady_INDClosedCaptionDataReceivedEventArgs<D>::ClosedCaptionDataFormat() const
{
    Windows::Media::Protection::PlayReady::NDClosedCaptionFormat ccForamt{};
    check_hresult(WINRT_SHIM(Windows::Media::Protection::PlayReady::INDClosedCaptionDataReceivedEventArgs)->get_ClosedCaptionDataFormat(put_abi(ccForamt)));
    return ccForamt;
}

template <typename D> int64_t consume_Windows_Media_Protection_PlayReady_INDClosedCaptionDataReceivedEventArgs<D>::PresentationTimestamp() const
{
    int64_t presentationTimestamp{};
    check_hresult(WINRT_SHIM(Windows::Media::Protection::PlayReady::INDClosedCaptionDataReceivedEventArgs)->get_PresentationTimestamp(&presentationTimestamp));
    return presentationTimestamp;
}

template <typename D> com_array<uint8_t> consume_Windows_Media_Protection_PlayReady_INDClosedCaptionDataReceivedEventArgs<D>::ClosedCaptionData() const
{
    com_array<uint8_t> ccDataBytes;
    check_hresult(WINRT_SHIM(Windows::Media::Protection::PlayReady::INDClosedCaptionDataReceivedEventArgs)->get_ClosedCaptionData(impl::put_size_abi(ccDataBytes), put_abi(ccDataBytes)));
    return ccDataBytes;
}

template <typename D> com_array<uint8_t> consume_Windows_Media_Protection_PlayReady_INDCustomData<D>::CustomDataTypeID() const
{
    com_array<uint8_t> customDataTypeIDBytes;
    check_hresult(WINRT_SHIM(Windows::Media::Protection::PlayReady::INDCustomData)->get_CustomDataTypeID(impl::put_size_abi(customDataTypeIDBytes), put_abi(customDataTypeIDBytes)));
    return customDataTypeIDBytes;
}

template <typename D> com_array<uint8_t> consume_Windows_Media_Protection_PlayReady_INDCustomData<D>::CustomData() const
{
    com_array<uint8_t> customDataBytes;
    check_hresult(WINRT_SHIM(Windows::Media::Protection::PlayReady::INDCustomData)->get_CustomData(impl::put_size_abi(customDataBytes), put_abi(customDataBytes)));
    return customDataBytes;
}

template <typename D> Windows::Media::Protection::PlayReady::NDCustomData consume_Windows_Media_Protection_PlayReady_INDCustomDataFactory<D>::CreateInstance(array_view<uint8_t const> customDataTypeIDBytes, array_view<uint8_t const> customDataBytes) const
{
    Windows::Media::Protection::PlayReady::NDCustomData instance{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Media::Protection::PlayReady::INDCustomDataFactory)->CreateInstance(customDataTypeIDBytes.size(), get_abi(customDataTypeIDBytes), customDataBytes.size(), get_abi(customDataBytes), put_abi(instance)));
    return instance;
}

template <typename D> void consume_Windows_Media_Protection_PlayReady_INDDownloadEngine<D>::Open(Windows::Foundation::Uri const& uri, array_view<uint8_t const> sessionIDBytes) const
{
    check_hresult(WINRT_SHIM(Windows::Media::Protection::PlayReady::INDDownloadEngine)->Open(get_abi(uri), sessionIDBytes.size(), get_abi(sessionIDBytes)));
}

template <typename D> void consume_Windows_Media_Protection_PlayReady_INDDownloadEngine<D>::Pause() const
{
    check_hresult(WINRT_SHIM(Windows::Media::Protection::PlayReady::INDDownloadEngine)->Pause());
}

template <typename D> void consume_Windows_Media_Protection_PlayReady_INDDownloadEngine<D>::Resume() const
{
    check_hresult(WINRT_SHIM(Windows::Media::Protection::PlayReady::INDDownloadEngine)->Resume());
}

template <typename D> void consume_Windows_Media_Protection_PlayReady_INDDownloadEngine<D>::Close() const
{
    check_hresult(WINRT_SHIM(Windows::Media::Protection::PlayReady::INDDownloadEngine)->Close());
}

template <typename D> void consume_Windows_Media_Protection_PlayReady_INDDownloadEngine<D>::Seek(Windows::Foundation::TimeSpan const& startPosition) const
{
    check_hresult(WINRT_SHIM(Windows::Media::Protection::PlayReady::INDDownloadEngine)->Seek(get_abi(startPosition)));
}

template <typename D> bool consume_Windows_Media_Protection_PlayReady_INDDownloadEngine<D>::CanSeek() const
{
    bool canSeek{};
    check_hresult(WINRT_SHIM(Windows::Media::Protection::PlayReady::INDDownloadEngine)->get_CanSeek(&canSeek));
    return canSeek;
}

template <typename D> uint32_t consume_Windows_Media_Protection_PlayReady_INDDownloadEngine<D>::BufferFullMinThresholdInSamples() const
{
    uint32_t bufferFullMinThreshold{};
    check_hresult(WINRT_SHIM(Windows::Media::Protection::PlayReady::INDDownloadEngine)->get_BufferFullMinThresholdInSamples(&bufferFullMinThreshold));
    return bufferFullMinThreshold;
}

template <typename D> uint32_t consume_Windows_Media_Protection_PlayReady_INDDownloadEngine<D>::BufferFullMaxThresholdInSamples() const
{
    uint32_t bufferFullMaxThreshold{};
    check_hresult(WINRT_SHIM(Windows::Media::Protection::PlayReady::INDDownloadEngine)->get_BufferFullMaxThresholdInSamples(&bufferFullMaxThreshold));
    return bufferFullMaxThreshold;
}

template <typename D> Windows::Media::Protection::PlayReady::NDDownloadEngineNotifier consume_Windows_Media_Protection_PlayReady_INDDownloadEngine<D>::Notifier() const
{
    Windows::Media::Protection::PlayReady::NDDownloadEngineNotifier instance{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Media::Protection::PlayReady::INDDownloadEngine)->get_Notifier(put_abi(instance)));
    return instance;
}

template <typename D> void consume_Windows_Media_Protection_PlayReady_INDDownloadEngineNotifier<D>::OnStreamOpened() const
{
    check_hresult(WINRT_SHIM(Windows::Media::Protection::PlayReady::INDDownloadEngineNotifier)->OnStreamOpened());
}

template <typename D> void consume_Windows_Media_Protection_PlayReady_INDDownloadEngineNotifier<D>::OnPlayReadyObjectReceived(array_view<uint8_t const> dataBytes) const
{
    check_hresult(WINRT_SHIM(Windows::Media::Protection::PlayReady::INDDownloadEngineNotifier)->OnPlayReadyObjectReceived(dataBytes.size(), get_abi(dataBytes)));
}

template <typename D> void consume_Windows_Media_Protection_PlayReady_INDDownloadEngineNotifier<D>::OnContentIDReceived(Windows::Media::Protection::PlayReady::INDLicenseFetchDescriptor const& licenseFetchDescriptor) const
{
    check_hresult(WINRT_SHIM(Windows::Media::Protection::PlayReady::INDDownloadEngineNotifier)->OnContentIDReceived(get_abi(licenseFetchDescriptor)));
}

template <typename D> void consume_Windows_Media_Protection_PlayReady_INDDownloadEngineNotifier<D>::OnDataReceived(array_view<uint8_t const> dataBytes, uint32_t bytesReceived) const
{
    check_hresult(WINRT_SHIM(Windows::Media::Protection::PlayReady::INDDownloadEngineNotifier)->OnDataReceived(dataBytes.size(), get_abi(dataBytes), bytesReceived));
}

template <typename D> void consume_Windows_Media_Protection_PlayReady_INDDownloadEngineNotifier<D>::OnEndOfStream() const
{
    check_hresult(WINRT_SHIM(Windows::Media::Protection::PlayReady::INDDownloadEngineNotifier)->OnEndOfStream());
}

template <typename D> void consume_Windows_Media_Protection_PlayReady_INDDownloadEngineNotifier<D>::OnNetworkError() const
{
    check_hresult(WINRT_SHIM(Windows::Media::Protection::PlayReady::INDDownloadEngineNotifier)->OnNetworkError());
}

template <typename D> Windows::Media::Protection::PlayReady::INDCustomData consume_Windows_Media_Protection_PlayReady_INDLicenseFetchCompletedEventArgs<D>::ResponseCustomData() const
{
    Windows::Media::Protection::PlayReady::INDCustomData customData{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Media::Protection::PlayReady::INDLicenseFetchCompletedEventArgs)->get_ResponseCustomData(put_abi(customData)));
    return customData;
}

template <typename D> Windows::Media::Protection::PlayReady::NDContentIDType consume_Windows_Media_Protection_PlayReady_INDLicenseFetchDescriptor<D>::ContentIDType() const
{
    Windows::Media::Protection::PlayReady::NDContentIDType contentIDType{};
    check_hresult(WINRT_SHIM(Windows::Media::Protection::PlayReady::INDLicenseFetchDescriptor)->get_ContentIDType(put_abi(contentIDType)));
    return contentIDType;
}

template <typename D> com_array<uint8_t> consume_Windows_Media_Protection_PlayReady_INDLicenseFetchDescriptor<D>::ContentID() const
{
    com_array<uint8_t> contentIDBytes;
    check_hresult(WINRT_SHIM(Windows::Media::Protection::PlayReady::INDLicenseFetchDescriptor)->get_ContentID(impl::put_size_abi(contentIDBytes), put_abi(contentIDBytes)));
    return contentIDBytes;
}

template <typename D> Windows::Media::Protection::PlayReady::INDCustomData consume_Windows_Media_Protection_PlayReady_INDLicenseFetchDescriptor<D>::LicenseFetchChallengeCustomData() const
{
    Windows::Media::Protection::PlayReady::INDCustomData licenseFetchChallengeCustomData{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Media::Protection::PlayReady::INDLicenseFetchDescriptor)->get_LicenseFetchChallengeCustomData(put_abi(licenseFetchChallengeCustomData)));
    return licenseFetchChallengeCustomData;
}

template <typename D> void consume_Windows_Media_Protection_PlayReady_INDLicenseFetchDescriptor<D>::LicenseFetchChallengeCustomData(Windows::Media::Protection::PlayReady::INDCustomData const& licenseFetchChallengeCustomData) const
{
    check_hresult(WINRT_SHIM(Windows::Media::Protection::PlayReady::INDLicenseFetchDescriptor)->put_LicenseFetchChallengeCustomData(get_abi(licenseFetchChallengeCustomData)));
}

template <typename D> Windows::Media::Protection::PlayReady::NDLicenseFetchDescriptor consume_Windows_Media_Protection_PlayReady_INDLicenseFetchDescriptorFactory<D>::CreateInstance(Windows::Media::Protection::PlayReady::NDContentIDType const& contentIDType, array_view<uint8_t const> contentIDBytes, Windows::Media::Protection::PlayReady::INDCustomData const& licenseFetchChallengeCustomData) const
{
    Windows::Media::Protection::PlayReady::NDLicenseFetchDescriptor instance{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Media::Protection::PlayReady::INDLicenseFetchDescriptorFactory)->CreateInstance(get_abi(contentIDType), contentIDBytes.size(), get_abi(contentIDBytes), get_abi(licenseFetchChallengeCustomData), put_abi(instance)));
    return instance;
}

template <typename D> Windows::Media::Protection::PlayReady::INDCustomData consume_Windows_Media_Protection_PlayReady_INDLicenseFetchResult<D>::ResponseCustomData() const
{
    Windows::Media::Protection::PlayReady::INDCustomData customData{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Media::Protection::PlayReady::INDLicenseFetchResult)->get_ResponseCustomData(put_abi(customData)));
    return customData;
}

template <typename D> Windows::Foundation::IAsyncOperation<Windows::Media::Protection::PlayReady::INDSendResult> consume_Windows_Media_Protection_PlayReady_INDMessenger<D>::SendRegistrationRequestAsync(array_view<uint8_t const> sessionIDBytes, array_view<uint8_t const> challengeDataBytes) const
{
    Windows::Foundation::IAsyncOperation<Windows::Media::Protection::PlayReady::INDSendResult> result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Media::Protection::PlayReady::INDMessenger)->SendRegistrationRequestAsync(sessionIDBytes.size(), get_abi(sessionIDBytes), challengeDataBytes.size(), get_abi(challengeDataBytes), put_abi(result)));
    return result;
}

template <typename D> Windows::Foundation::IAsyncOperation<Windows::Media::Protection::PlayReady::INDSendResult> consume_Windows_Media_Protection_PlayReady_INDMessenger<D>::SendProximityDetectionStartAsync(Windows::Media::Protection::PlayReady::NDProximityDetectionType const& pdType, array_view<uint8_t const> transmitterChannelBytes, array_view<uint8_t const> sessionIDBytes, array_view<uint8_t const> challengeDataBytes) const
{
    Windows::Foundation::IAsyncOperation<Windows::Media::Protection::PlayReady::INDSendResult> result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Media::Protection::PlayReady::INDMessenger)->SendProximityDetectionStartAsync(get_abi(pdType), transmitterChannelBytes.size(), get_abi(transmitterChannelBytes), sessionIDBytes.size(), get_abi(sessionIDBytes), challengeDataBytes.size(), get_abi(challengeDataBytes), put_abi(result)));
    return result;
}

template <typename D> Windows::Foundation::IAsyncOperation<Windows::Media::Protection::PlayReady::INDSendResult> consume_Windows_Media_Protection_PlayReady_INDMessenger<D>::SendProximityDetectionResponseAsync(Windows::Media::Protection::PlayReady::NDProximityDetectionType const& pdType, array_view<uint8_t const> transmitterChannelBytes, array_view<uint8_t const> sessionIDBytes, array_view<uint8_t const> responseDataBytes) const
{
    Windows::Foundation::IAsyncOperation<Windows::Media::Protection::PlayReady::INDSendResult> result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Media::Protection::PlayReady::INDMessenger)->SendProximityDetectionResponseAsync(get_abi(pdType), transmitterChannelBytes.size(), get_abi(transmitterChannelBytes), sessionIDBytes.size(), get_abi(sessionIDBytes), responseDataBytes.size(), get_abi(responseDataBytes), put_abi(result)));
    return result;
}

template <typename D> Windows::Foundation::IAsyncOperation<Windows::Media::Protection::PlayReady::INDSendResult> consume_Windows_Media_Protection_PlayReady_INDMessenger<D>::SendLicenseFetchRequestAsync(array_view<uint8_t const> sessionIDBytes, array_view<uint8_t const> challengeDataBytes) const
{
    Windows::Foundation::IAsyncOperation<Windows::Media::Protection::PlayReady::INDSendResult> result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Media::Protection::PlayReady::INDMessenger)->SendLicenseFetchRequestAsync(sessionIDBytes.size(), get_abi(sessionIDBytes), challengeDataBytes.size(), get_abi(challengeDataBytes), put_abi(result)));
    return result;
}

template <typename D> uint32_t consume_Windows_Media_Protection_PlayReady_INDProximityDetectionCompletedEventArgs<D>::ProximityDetectionRetryCount() const
{
    uint32_t retryCount{};
    check_hresult(WINRT_SHIM(Windows::Media::Protection::PlayReady::INDProximityDetectionCompletedEventArgs)->get_ProximityDetectionRetryCount(&retryCount));
    return retryCount;
}

template <typename D> Windows::Media::Protection::PlayReady::INDCustomData consume_Windows_Media_Protection_PlayReady_INDRegistrationCompletedEventArgs<D>::ResponseCustomData() const
{
    Windows::Media::Protection::PlayReady::INDCustomData customData{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Media::Protection::PlayReady::INDRegistrationCompletedEventArgs)->get_ResponseCustomData(put_abi(customData)));
    return customData;
}

template <typename D> Windows::Media::Protection::PlayReady::INDTransmitterProperties consume_Windows_Media_Protection_PlayReady_INDRegistrationCompletedEventArgs<D>::TransmitterProperties() const
{
    Windows::Media::Protection::PlayReady::INDTransmitterProperties transmitterProperties{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Media::Protection::PlayReady::INDRegistrationCompletedEventArgs)->get_TransmitterProperties(put_abi(transmitterProperties)));
    return transmitterProperties;
}

template <typename D> bool consume_Windows_Media_Protection_PlayReady_INDRegistrationCompletedEventArgs<D>::TransmitterCertificateAccepted() const
{
    bool acceptpt{};
    check_hresult(WINRT_SHIM(Windows::Media::Protection::PlayReady::INDRegistrationCompletedEventArgs)->get_TransmitterCertificateAccepted(&acceptpt));
    return acceptpt;
}

template <typename D> void consume_Windows_Media_Protection_PlayReady_INDRegistrationCompletedEventArgs<D>::TransmitterCertificateAccepted(bool accept) const
{
    check_hresult(WINRT_SHIM(Windows::Media::Protection::PlayReady::INDRegistrationCompletedEventArgs)->put_TransmitterCertificateAccepted(accept));
}

template <typename D> com_array<uint8_t> consume_Windows_Media_Protection_PlayReady_INDSendResult<D>::Response() const
{
    com_array<uint8_t> responseDataBytes;
    check_hresult(WINRT_SHIM(Windows::Media::Protection::PlayReady::INDSendResult)->get_Response(impl::put_size_abi(responseDataBytes), put_abi(responseDataBytes)));
    return responseDataBytes;
}

template <typename D> Windows::Media::Core::MediaStreamSource consume_Windows_Media_Protection_PlayReady_INDStartResult<D>::MediaStreamSource() const
{
    Windows::Media::Core::MediaStreamSource mediaStreamSource{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Media::Protection::PlayReady::INDStartResult)->get_MediaStreamSource(put_abi(mediaStreamSource)));
    return mediaStreamSource;
}

template <typename D> Windows::Foundation::Collections::IVector<hstring> consume_Windows_Media_Protection_PlayReady_INDStorageFileHelper<D>::GetFileURLs(Windows::Storage::IStorageFile const& file) const
{
    Windows::Foundation::Collections::IVector<hstring> fileURLs{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Media::Protection::PlayReady::INDStorageFileHelper)->GetFileURLs(get_abi(file), put_abi(fileURLs)));
    return fileURLs;
}

template <typename D> void consume_Windows_Media_Protection_PlayReady_INDStreamParser<D>::ParseData(array_view<uint8_t const> dataBytes) const
{
    check_hresult(WINRT_SHIM(Windows::Media::Protection::PlayReady::INDStreamParser)->ParseData(dataBytes.size(), get_abi(dataBytes)));
}

template <typename D> uint32_t consume_Windows_Media_Protection_PlayReady_INDStreamParser<D>::GetStreamInformation(Windows::Media::Core::IMediaStreamDescriptor const& descriptor, Windows::Media::Protection::PlayReady::NDMediaStreamType& streamType) const
{
    uint32_t streamID{};
    check_hresult(WINRT_SHIM(Windows::Media::Protection::PlayReady::INDStreamParser)->GetStreamInformation(get_abi(descriptor), put_abi(streamType), &streamID));
    return streamID;
}

template <typename D> void consume_Windows_Media_Protection_PlayReady_INDStreamParser<D>::BeginOfStream() const
{
    check_hresult(WINRT_SHIM(Windows::Media::Protection::PlayReady::INDStreamParser)->BeginOfStream());
}

template <typename D> void consume_Windows_Media_Protection_PlayReady_INDStreamParser<D>::EndOfStream() const
{
    check_hresult(WINRT_SHIM(Windows::Media::Protection::PlayReady::INDStreamParser)->EndOfStream());
}

template <typename D> Windows::Media::Protection::PlayReady::NDStreamParserNotifier consume_Windows_Media_Protection_PlayReady_INDStreamParser<D>::Notifier() const
{
    Windows::Media::Protection::PlayReady::NDStreamParserNotifier instance{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Media::Protection::PlayReady::INDStreamParser)->get_Notifier(put_abi(instance)));
    return instance;
}

template <typename D> void consume_Windows_Media_Protection_PlayReady_INDStreamParserNotifier<D>::OnContentIDReceived(Windows::Media::Protection::PlayReady::INDLicenseFetchDescriptor const& licenseFetchDescriptor) const
{
    check_hresult(WINRT_SHIM(Windows::Media::Protection::PlayReady::INDStreamParserNotifier)->OnContentIDReceived(get_abi(licenseFetchDescriptor)));
}

template <typename D> void consume_Windows_Media_Protection_PlayReady_INDStreamParserNotifier<D>::OnMediaStreamDescriptorCreated(param::vector<Windows::Media::Core::AudioStreamDescriptor> const& audioStreamDescriptors, param::vector<Windows::Media::Core::VideoStreamDescriptor> const& videoStreamDescriptors) const
{
    check_hresult(WINRT_SHIM(Windows::Media::Protection::PlayReady::INDStreamParserNotifier)->OnMediaStreamDescriptorCreated(get_abi(audioStreamDescriptors), get_abi(videoStreamDescriptors)));
}

template <typename D> void consume_Windows_Media_Protection_PlayReady_INDStreamParserNotifier<D>::OnSampleParsed(uint32_t streamID, Windows::Media::Protection::PlayReady::NDMediaStreamType const& streamType, Windows::Media::Core::MediaStreamSample const& streamSample, int64_t pts, Windows::Media::Protection::PlayReady::NDClosedCaptionFormat const& ccFormat, array_view<uint8_t const> ccDataBytes) const
{
    check_hresult(WINRT_SHIM(Windows::Media::Protection::PlayReady::INDStreamParserNotifier)->OnSampleParsed(streamID, get_abi(streamType), get_abi(streamSample), pts, get_abi(ccFormat), ccDataBytes.size(), get_abi(ccDataBytes)));
}

template <typename D> void consume_Windows_Media_Protection_PlayReady_INDStreamParserNotifier<D>::OnBeginSetupDecryptor(Windows::Media::Core::IMediaStreamDescriptor const& descriptor, winrt::guid const& keyID, array_view<uint8_t const> proBytes) const
{
    check_hresult(WINRT_SHIM(Windows::Media::Protection::PlayReady::INDStreamParserNotifier)->OnBeginSetupDecryptor(get_abi(descriptor), get_abi(keyID), proBytes.size(), get_abi(proBytes)));
}

template <typename D> Windows::Media::Protection::PlayReady::NDTCPMessenger consume_Windows_Media_Protection_PlayReady_INDTCPMessengerFactory<D>::CreateInstance(param::hstring const& remoteHostName, uint32_t remoteHostPort) const
{
    Windows::Media::Protection::PlayReady::NDTCPMessenger instance{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Media::Protection::PlayReady::INDTCPMessengerFactory)->CreateInstance(get_abi(remoteHostName), remoteHostPort, put_abi(instance)));
    return instance;
}

template <typename D> Windows::Media::Protection::PlayReady::NDCertificateType consume_Windows_Media_Protection_PlayReady_INDTransmitterProperties<D>::CertificateType() const
{
    Windows::Media::Protection::PlayReady::NDCertificateType type{};
    check_hresult(WINRT_SHIM(Windows::Media::Protection::PlayReady::INDTransmitterProperties)->get_CertificateType(put_abi(type)));
    return type;
}

template <typename D> Windows::Media::Protection::PlayReady::NDCertificatePlatformID consume_Windows_Media_Protection_PlayReady_INDTransmitterProperties<D>::PlatformIdentifier() const
{
    Windows::Media::Protection::PlayReady::NDCertificatePlatformID identifier{};
    check_hresult(WINRT_SHIM(Windows::Media::Protection::PlayReady::INDTransmitterProperties)->get_PlatformIdentifier(put_abi(identifier)));
    return identifier;
}

template <typename D> com_array<Windows::Media::Protection::PlayReady::NDCertificateFeature> consume_Windows_Media_Protection_PlayReady_INDTransmitterProperties<D>::SupportedFeatures() const
{
    com_array<Windows::Media::Protection::PlayReady::NDCertificateFeature> featureSets;
    check_hresult(WINRT_SHIM(Windows::Media::Protection::PlayReady::INDTransmitterProperties)->get_SupportedFeatures(impl::put_size_abi(featureSets), put_abi(featureSets)));
    return featureSets;
}

template <typename D> uint32_t consume_Windows_Media_Protection_PlayReady_INDTransmitterProperties<D>::SecurityLevel() const
{
    uint32_t level{};
    check_hresult(WINRT_SHIM(Windows::Media::Protection::PlayReady::INDTransmitterProperties)->get_SecurityLevel(&level));
    return level;
}

template <typename D> uint32_t consume_Windows_Media_Protection_PlayReady_INDTransmitterProperties<D>::SecurityVersion() const
{
    uint32_t securityVersion{};
    check_hresult(WINRT_SHIM(Windows::Media::Protection::PlayReady::INDTransmitterProperties)->get_SecurityVersion(&securityVersion));
    return securityVersion;
}

template <typename D> Windows::Foundation::DateTime consume_Windows_Media_Protection_PlayReady_INDTransmitterProperties<D>::ExpirationDate() const
{
    Windows::Foundation::DateTime expirationDate{};
    check_hresult(WINRT_SHIM(Windows::Media::Protection::PlayReady::INDTransmitterProperties)->get_ExpirationDate(put_abi(expirationDate)));
    return expirationDate;
}

template <typename D> com_array<uint8_t> consume_Windows_Media_Protection_PlayReady_INDTransmitterProperties<D>::ClientID() const
{
    com_array<uint8_t> clientIDBytes;
    check_hresult(WINRT_SHIM(Windows::Media::Protection::PlayReady::INDTransmitterProperties)->get_ClientID(impl::put_size_abi(clientIDBytes), put_abi(clientIDBytes)));
    return clientIDBytes;
}

template <typename D> com_array<uint8_t> consume_Windows_Media_Protection_PlayReady_INDTransmitterProperties<D>::ModelDigest() const
{
    com_array<uint8_t> modelDigestBytes;
    check_hresult(WINRT_SHIM(Windows::Media::Protection::PlayReady::INDTransmitterProperties)->get_ModelDigest(impl::put_size_abi(modelDigestBytes), put_abi(modelDigestBytes)));
    return modelDigestBytes;
}

template <typename D> hstring consume_Windows_Media_Protection_PlayReady_INDTransmitterProperties<D>::ModelManufacturerName() const
{
    hstring modelManufacturerName{};
    check_hresult(WINRT_SHIM(Windows::Media::Protection::PlayReady::INDTransmitterProperties)->get_ModelManufacturerName(put_abi(modelManufacturerName)));
    return modelManufacturerName;
}

template <typename D> hstring consume_Windows_Media_Protection_PlayReady_INDTransmitterProperties<D>::ModelName() const
{
    hstring modelName{};
    check_hresult(WINRT_SHIM(Windows::Media::Protection::PlayReady::INDTransmitterProperties)->get_ModelName(put_abi(modelName)));
    return modelName;
}

template <typename D> hstring consume_Windows_Media_Protection_PlayReady_INDTransmitterProperties<D>::ModelNumber() const
{
    hstring modelNumber{};
    check_hresult(WINRT_SHIM(Windows::Media::Protection::PlayReady::INDTransmitterProperties)->get_ModelNumber(put_abi(modelNumber)));
    return modelNumber;
}

template <typename D> winrt::guid consume_Windows_Media_Protection_PlayReady_IPlayReadyContentHeader<D>::KeyId() const
{
    winrt::guid value{};
    check_hresult(WINRT_SHIM(Windows::Media::Protection::PlayReady::IPlayReadyContentHeader)->get_KeyId(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_Media_Protection_PlayReady_IPlayReadyContentHeader<D>::KeyIdString() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Media::Protection::PlayReady::IPlayReadyContentHeader)->get_KeyIdString(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::Uri consume_Windows_Media_Protection_PlayReady_IPlayReadyContentHeader<D>::LicenseAcquisitionUrl() const
{
    Windows::Foundation::Uri value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Media::Protection::PlayReady::IPlayReadyContentHeader)->get_LicenseAcquisitionUrl(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::Uri consume_Windows_Media_Protection_PlayReady_IPlayReadyContentHeader<D>::LicenseAcquisitionUserInterfaceUrl() const
{
    Windows::Foundation::Uri value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Media::Protection::PlayReady::IPlayReadyContentHeader)->get_LicenseAcquisitionUserInterfaceUrl(put_abi(value)));
    return value;
}

template <typename D> winrt::guid consume_Windows_Media_Protection_PlayReady_IPlayReadyContentHeader<D>::DomainServiceId() const
{
    winrt::guid value{};
    check_hresult(WINRT_SHIM(Windows::Media::Protection::PlayReady::IPlayReadyContentHeader)->get_DomainServiceId(put_abi(value)));
    return value;
}

template <typename D> Windows::Media::Protection::PlayReady::PlayReadyEncryptionAlgorithm consume_Windows_Media_Protection_PlayReady_IPlayReadyContentHeader<D>::EncryptionType() const
{
    Windows::Media::Protection::PlayReady::PlayReadyEncryptionAlgorithm value{};
    check_hresult(WINRT_SHIM(Windows::Media::Protection::PlayReady::IPlayReadyContentHeader)->get_EncryptionType(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_Media_Protection_PlayReady_IPlayReadyContentHeader<D>::CustomAttributes() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Media::Protection::PlayReady::IPlayReadyContentHeader)->get_CustomAttributes(put_abi(value)));
    return value;
}

template <typename D> Windows::Media::Protection::PlayReady::PlayReadyDecryptorSetup consume_Windows_Media_Protection_PlayReady_IPlayReadyContentHeader<D>::DecryptorSetup() const
{
    Windows::Media::Protection::PlayReady::PlayReadyDecryptorSetup value{};
    check_hresult(WINRT_SHIM(Windows::Media::Protection::PlayReady::IPlayReadyContentHeader)->get_DecryptorSetup(put_abi(value)));
    return value;
}

template <typename D> com_array<uint8_t> consume_Windows_Media_Protection_PlayReady_IPlayReadyContentHeader<D>::GetSerializedHeader() const
{
    com_array<uint8_t> headerBytes;
    check_hresult(WINRT_SHIM(Windows::Media::Protection::PlayReady::IPlayReadyContentHeader)->GetSerializedHeader(impl::put_size_abi(headerBytes), put_abi(headerBytes)));
    return headerBytes;
}

template <typename D> Windows::Media::Protection::PlayReady::PlayReadyContentHeader consume_Windows_Media_Protection_PlayReady_IPlayReadyContentHeader<D>::HeaderWithEmbeddedUpdates() const
{
    Windows::Media::Protection::PlayReady::PlayReadyContentHeader value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Media::Protection::PlayReady::IPlayReadyContentHeader)->get_HeaderWithEmbeddedUpdates(put_abi(value)));
    return value;
}

template <typename D> com_array<winrt::guid> consume_Windows_Media_Protection_PlayReady_IPlayReadyContentHeader2<D>::KeyIds() const
{
    com_array<winrt::guid> contentKeyIds;
    check_hresult(WINRT_SHIM(Windows::Media::Protection::PlayReady::IPlayReadyContentHeader2)->get_KeyIds(impl::put_size_abi(contentKeyIds), put_abi(contentKeyIds)));
    return contentKeyIds;
}

template <typename D> com_array<hstring> consume_Windows_Media_Protection_PlayReady_IPlayReadyContentHeader2<D>::KeyIdStrings() const
{
    com_array<hstring> contentKeyIdStrings;
    check_hresult(WINRT_SHIM(Windows::Media::Protection::PlayReady::IPlayReadyContentHeader2)->get_KeyIdStrings(impl::put_size_abi(contentKeyIdStrings), put_abi(contentKeyIdStrings)));
    return contentKeyIdStrings;
}

template <typename D> Windows::Media::Protection::PlayReady::PlayReadyContentHeader consume_Windows_Media_Protection_PlayReady_IPlayReadyContentHeaderFactory<D>::CreateInstanceFromWindowsMediaDrmHeader(array_view<uint8_t const> headerBytes, Windows::Foundation::Uri const& licenseAcquisitionUrl, Windows::Foundation::Uri const& licenseAcquisitionUserInterfaceUrl, param::hstring const& customAttributes, winrt::guid const& domainServiceId) const
{
    Windows::Media::Protection::PlayReady::PlayReadyContentHeader instance{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Media::Protection::PlayReady::IPlayReadyContentHeaderFactory)->CreateInstanceFromWindowsMediaDrmHeader(headerBytes.size(), get_abi(headerBytes), get_abi(licenseAcquisitionUrl), get_abi(licenseAcquisitionUserInterfaceUrl), get_abi(customAttributes), get_abi(domainServiceId), put_abi(instance)));
    return instance;
}

template <typename D> Windows::Media::Protection::PlayReady::PlayReadyContentHeader consume_Windows_Media_Protection_PlayReady_IPlayReadyContentHeaderFactory<D>::CreateInstanceFromComponents(winrt::guid const& contentKeyId, param::hstring const& contentKeyIdString, Windows::Media::Protection::PlayReady::PlayReadyEncryptionAlgorithm const& contentEncryptionAlgorithm, Windows::Foundation::Uri const& licenseAcquisitionUrl, Windows::Foundation::Uri const& licenseAcquisitionUserInterfaceUrl, param::hstring const& customAttributes, winrt::guid const& domainServiceId) const
{
    Windows::Media::Protection::PlayReady::PlayReadyContentHeader instance{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Media::Protection::PlayReady::IPlayReadyContentHeaderFactory)->CreateInstanceFromComponents(get_abi(contentKeyId), get_abi(contentKeyIdString), get_abi(contentEncryptionAlgorithm), get_abi(licenseAcquisitionUrl), get_abi(licenseAcquisitionUserInterfaceUrl), get_abi(customAttributes), get_abi(domainServiceId), put_abi(instance)));
    return instance;
}

template <typename D> Windows::Media::Protection::PlayReady::PlayReadyContentHeader consume_Windows_Media_Protection_PlayReady_IPlayReadyContentHeaderFactory<D>::CreateInstanceFromPlayReadyHeader(array_view<uint8_t const> headerBytes) const
{
    Windows::Media::Protection::PlayReady::PlayReadyContentHeader instance{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Media::Protection::PlayReady::IPlayReadyContentHeaderFactory)->CreateInstanceFromPlayReadyHeader(headerBytes.size(), get_abi(headerBytes), put_abi(instance)));
    return instance;
}

template <typename D> Windows::Media::Protection::PlayReady::PlayReadyContentHeader consume_Windows_Media_Protection_PlayReady_IPlayReadyContentHeaderFactory2<D>::CreateInstanceFromComponents2(uint32_t dwFlags, array_view<winrt::guid const> contentKeyIds, array_view<hstring const> contentKeyIdStrings, Windows::Media::Protection::PlayReady::PlayReadyEncryptionAlgorithm const& contentEncryptionAlgorithm, Windows::Foundation::Uri const& licenseAcquisitionUrl, Windows::Foundation::Uri const& licenseAcquisitionUserInterfaceUrl, param::hstring const& customAttributes, winrt::guid const& domainServiceId) const
{
    Windows::Media::Protection::PlayReady::PlayReadyContentHeader instance{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Media::Protection::PlayReady::IPlayReadyContentHeaderFactory2)->CreateInstanceFromComponents2(dwFlags, contentKeyIds.size(), get_abi(contentKeyIds), contentKeyIdStrings.size(), get_abi(contentKeyIdStrings), get_abi(contentEncryptionAlgorithm), get_abi(licenseAcquisitionUrl), get_abi(licenseAcquisitionUserInterfaceUrl), get_abi(customAttributes), get_abi(domainServiceId), put_abi(instance)));
    return instance;
}

template <typename D> Windows::Media::Protection::PlayReady::IPlayReadyServiceRequest consume_Windows_Media_Protection_PlayReady_IPlayReadyContentResolver<D>::ServiceRequest(Windows::Media::Protection::PlayReady::PlayReadyContentHeader const& contentHeader) const
{
    Windows::Media::Protection::PlayReady::IPlayReadyServiceRequest serviceRequest{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Media::Protection::PlayReady::IPlayReadyContentResolver)->ServiceRequest(get_abi(contentHeader), put_abi(serviceRequest)));
    return serviceRequest;
}

template <typename D> winrt::guid consume_Windows_Media_Protection_PlayReady_IPlayReadyDomain<D>::AccountId() const
{
    winrt::guid value{};
    check_hresult(WINRT_SHIM(Windows::Media::Protection::PlayReady::IPlayReadyDomain)->get_AccountId(put_abi(value)));
    return value;
}

template <typename D> winrt::guid consume_Windows_Media_Protection_PlayReady_IPlayReadyDomain<D>::ServiceId() const
{
    winrt::guid value{};
    check_hresult(WINRT_SHIM(Windows::Media::Protection::PlayReady::IPlayReadyDomain)->get_ServiceId(put_abi(value)));
    return value;
}

template <typename D> uint32_t consume_Windows_Media_Protection_PlayReady_IPlayReadyDomain<D>::Revision() const
{
    uint32_t value{};
    check_hresult(WINRT_SHIM(Windows::Media::Protection::PlayReady::IPlayReadyDomain)->get_Revision(&value));
    return value;
}

template <typename D> hstring consume_Windows_Media_Protection_PlayReady_IPlayReadyDomain<D>::FriendlyName() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Media::Protection::PlayReady::IPlayReadyDomain)->get_FriendlyName(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::Uri consume_Windows_Media_Protection_PlayReady_IPlayReadyDomain<D>::DomainJoinUrl() const
{
    Windows::Foundation::Uri value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Media::Protection::PlayReady::IPlayReadyDomain)->get_DomainJoinUrl(put_abi(value)));
    return value;
}

template <typename D> Windows::Media::Protection::PlayReady::PlayReadyDomainIterable consume_Windows_Media_Protection_PlayReady_IPlayReadyDomainIterableFactory<D>::CreateInstance(winrt::guid const& domainAccountId) const
{
    Windows::Media::Protection::PlayReady::PlayReadyDomainIterable domainIterable{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Media::Protection::PlayReady::IPlayReadyDomainIterableFactory)->CreateInstance(get_abi(domainAccountId), put_abi(domainIterable)));
    return domainIterable;
}

template <typename D> winrt::guid consume_Windows_Media_Protection_PlayReady_IPlayReadyDomainJoinServiceRequest<D>::DomainAccountId() const
{
    winrt::guid value{};
    check_hresult(WINRT_SHIM(Windows::Media::Protection::PlayReady::IPlayReadyDomainJoinServiceRequest)->get_DomainAccountId(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_Media_Protection_PlayReady_IPlayReadyDomainJoinServiceRequest<D>::DomainAccountId(winrt::guid const& value) const
{
    check_hresult(WINRT_SHIM(Windows::Media::Protection::PlayReady::IPlayReadyDomainJoinServiceRequest)->put_DomainAccountId(get_abi(value)));
}

template <typename D> hstring consume_Windows_Media_Protection_PlayReady_IPlayReadyDomainJoinServiceRequest<D>::DomainFriendlyName() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Media::Protection::PlayReady::IPlayReadyDomainJoinServiceRequest)->get_DomainFriendlyName(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_Media_Protection_PlayReady_IPlayReadyDomainJoinServiceRequest<D>::DomainFriendlyName(param::hstring const& value) const
{
    check_hresult(WINRT_SHIM(Windows::Media::Protection::PlayReady::IPlayReadyDomainJoinServiceRequest)->put_DomainFriendlyName(get_abi(value)));
}

template <typename D> winrt::guid consume_Windows_Media_Protection_PlayReady_IPlayReadyDomainJoinServiceRequest<D>::DomainServiceId() const
{
    winrt::guid value{};
    check_hresult(WINRT_SHIM(Windows::Media::Protection::PlayReady::IPlayReadyDomainJoinServiceRequest)->get_DomainServiceId(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_Media_Protection_PlayReady_IPlayReadyDomainJoinServiceRequest<D>::DomainServiceId(winrt::guid const& value) const
{
    check_hresult(WINRT_SHIM(Windows::Media::Protection::PlayReady::IPlayReadyDomainJoinServiceRequest)->put_DomainServiceId(get_abi(value)));
}

template <typename D> winrt::guid consume_Windows_Media_Protection_PlayReady_IPlayReadyDomainLeaveServiceRequest<D>::DomainAccountId() const
{
    winrt::guid value{};
    check_hresult(WINRT_SHIM(Windows::Media::Protection::PlayReady::IPlayReadyDomainLeaveServiceRequest)->get_DomainAccountId(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_Media_Protection_PlayReady_IPlayReadyDomainLeaveServiceRequest<D>::DomainAccountId(winrt::guid const& value) const
{
    check_hresult(WINRT_SHIM(Windows::Media::Protection::PlayReady::IPlayReadyDomainLeaveServiceRequest)->put_DomainAccountId(get_abi(value)));
}

template <typename D> winrt::guid consume_Windows_Media_Protection_PlayReady_IPlayReadyDomainLeaveServiceRequest<D>::DomainServiceId() const
{
    winrt::guid value{};
    check_hresult(WINRT_SHIM(Windows::Media::Protection::PlayReady::IPlayReadyDomainLeaveServiceRequest)->get_DomainServiceId(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_Media_Protection_PlayReady_IPlayReadyDomainLeaveServiceRequest<D>::DomainServiceId(winrt::guid const& value) const
{
    check_hresult(WINRT_SHIM(Windows::Media::Protection::PlayReady::IPlayReadyDomainLeaveServiceRequest)->put_DomainServiceId(get_abi(value)));
}

template <typename D> com_array<uint8_t> consume_Windows_Media_Protection_PlayReady_IPlayReadyITADataGenerator<D>::GenerateData(winrt::guid const& guidCPSystemId, uint32_t countOfStreams, Windows::Foundation::Collections::IPropertySet const& configuration, Windows::Media::Protection::PlayReady::PlayReadyITADataFormat const& format) const
{
    com_array<uint8_t> dataBytes;
    check_hresult(WINRT_SHIM(Windows::Media::Protection::PlayReady::IPlayReadyITADataGenerator)->GenerateData(get_abi(guidCPSystemId), countOfStreams, get_abi(configuration), get_abi(format), impl::put_size_abi(dataBytes), put_abi(dataBytes)));
    return dataBytes;
}

template <typename D> bool consume_Windows_Media_Protection_PlayReady_IPlayReadyLicense<D>::FullyEvaluated() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::Media::Protection::PlayReady::IPlayReadyLicense)->get_FullyEvaluated(&value));
    return value;
}

template <typename D> bool consume_Windows_Media_Protection_PlayReady_IPlayReadyLicense<D>::UsableForPlay() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::Media::Protection::PlayReady::IPlayReadyLicense)->get_UsableForPlay(&value));
    return value;
}

template <typename D> Windows::Foundation::IReference<Windows::Foundation::DateTime> consume_Windows_Media_Protection_PlayReady_IPlayReadyLicense<D>::ExpirationDate() const
{
    Windows::Foundation::IReference<Windows::Foundation::DateTime> value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Media::Protection::PlayReady::IPlayReadyLicense)->get_ExpirationDate(put_abi(value)));
    return value;
}

template <typename D> uint32_t consume_Windows_Media_Protection_PlayReady_IPlayReadyLicense<D>::ExpireAfterFirstPlay() const
{
    uint32_t value{};
    check_hresult(WINRT_SHIM(Windows::Media::Protection::PlayReady::IPlayReadyLicense)->get_ExpireAfterFirstPlay(&value));
    return value;
}

template <typename D> winrt::guid consume_Windows_Media_Protection_PlayReady_IPlayReadyLicense<D>::DomainAccountID() const
{
    winrt::guid value{};
    check_hresult(WINRT_SHIM(Windows::Media::Protection::PlayReady::IPlayReadyLicense)->get_DomainAccountID(put_abi(value)));
    return value;
}

template <typename D> uint32_t consume_Windows_Media_Protection_PlayReady_IPlayReadyLicense<D>::ChainDepth() const
{
    uint32_t value{};
    check_hresult(WINRT_SHIM(Windows::Media::Protection::PlayReady::IPlayReadyLicense)->get_ChainDepth(&value));
    return value;
}

template <typename D> winrt::guid consume_Windows_Media_Protection_PlayReady_IPlayReadyLicense<D>::GetKIDAtChainDepth(uint32_t chainDepth) const
{
    winrt::guid kid{};
    check_hresult(WINRT_SHIM(Windows::Media::Protection::PlayReady::IPlayReadyLicense)->GetKIDAtChainDepth(chainDepth, put_abi(kid)));
    return kid;
}

template <typename D> winrt::guid consume_Windows_Media_Protection_PlayReady_IPlayReadyLicense2<D>::SecureStopId() const
{
    winrt::guid value{};
    check_hresult(WINRT_SHIM(Windows::Media::Protection::PlayReady::IPlayReadyLicense2)->get_SecureStopId(put_abi(value)));
    return value;
}

template <typename D> uint32_t consume_Windows_Media_Protection_PlayReady_IPlayReadyLicense2<D>::SecurityLevel() const
{
    uint32_t value{};
    check_hresult(WINRT_SHIM(Windows::Media::Protection::PlayReady::IPlayReadyLicense2)->get_SecurityLevel(&value));
    return value;
}

template <typename D> bool consume_Windows_Media_Protection_PlayReady_IPlayReadyLicense2<D>::InMemoryOnly() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::Media::Protection::PlayReady::IPlayReadyLicense2)->get_InMemoryOnly(&value));
    return value;
}

template <typename D> bool consume_Windows_Media_Protection_PlayReady_IPlayReadyLicense2<D>::ExpiresInRealTime() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::Media::Protection::PlayReady::IPlayReadyLicense2)->get_ExpiresInRealTime(&value));
    return value;
}

template <typename D> Windows::Media::Protection::PlayReady::PlayReadyContentHeader consume_Windows_Media_Protection_PlayReady_IPlayReadyLicenseAcquisitionServiceRequest<D>::ContentHeader() const
{
    Windows::Media::Protection::PlayReady::PlayReadyContentHeader value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Media::Protection::PlayReady::IPlayReadyLicenseAcquisitionServiceRequest)->get_ContentHeader(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_Media_Protection_PlayReady_IPlayReadyLicenseAcquisitionServiceRequest<D>::ContentHeader(Windows::Media::Protection::PlayReady::PlayReadyContentHeader const& value) const
{
    check_hresult(WINRT_SHIM(Windows::Media::Protection::PlayReady::IPlayReadyLicenseAcquisitionServiceRequest)->put_ContentHeader(get_abi(value)));
}

template <typename D> winrt::guid consume_Windows_Media_Protection_PlayReady_IPlayReadyLicenseAcquisitionServiceRequest<D>::DomainServiceId() const
{
    winrt::guid value{};
    check_hresult(WINRT_SHIM(Windows::Media::Protection::PlayReady::IPlayReadyLicenseAcquisitionServiceRequest)->get_DomainServiceId(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_Media_Protection_PlayReady_IPlayReadyLicenseAcquisitionServiceRequest<D>::DomainServiceId(winrt::guid const& value) const
{
    check_hresult(WINRT_SHIM(Windows::Media::Protection::PlayReady::IPlayReadyLicenseAcquisitionServiceRequest)->put_DomainServiceId(get_abi(value)));
}

template <typename D> winrt::guid consume_Windows_Media_Protection_PlayReady_IPlayReadyLicenseAcquisitionServiceRequest2<D>::SessionId() const
{
    winrt::guid value{};
    check_hresult(WINRT_SHIM(Windows::Media::Protection::PlayReady::IPlayReadyLicenseAcquisitionServiceRequest2)->get_SessionId(put_abi(value)));
    return value;
}

template <typename D> Windows::Media::Protection::PlayReady::PlayReadyLicenseIterable consume_Windows_Media_Protection_PlayReady_IPlayReadyLicenseAcquisitionServiceRequest3<D>::CreateLicenseIterable(Windows::Media::Protection::PlayReady::PlayReadyContentHeader const& contentHeader, bool fullyEvaluated) const
{
    Windows::Media::Protection::PlayReady::PlayReadyLicenseIterable result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Media::Protection::PlayReady::IPlayReadyLicenseAcquisitionServiceRequest3)->CreateLicenseIterable(get_abi(contentHeader), fullyEvaluated, put_abi(result)));
    return result;
}

template <typename D> Windows::Media::Protection::PlayReady::PlayReadyLicenseIterable consume_Windows_Media_Protection_PlayReady_IPlayReadyLicenseIterableFactory<D>::CreateInstance(Windows::Media::Protection::PlayReady::PlayReadyContentHeader const& contentHeader, bool fullyEvaluated) const
{
    Windows::Media::Protection::PlayReady::PlayReadyLicenseIterable instance{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Media::Protection::PlayReady::IPlayReadyLicenseIterableFactory)->CreateInstance(get_abi(contentHeader), fullyEvaluated, put_abi(instance)));
    return instance;
}

template <typename D> Windows::Foundation::IAsyncAction consume_Windows_Media_Protection_PlayReady_IPlayReadyLicenseManagement<D>::DeleteLicenses(Windows::Media::Protection::PlayReady::PlayReadyContentHeader const& contentHeader) const
{
    Windows::Foundation::IAsyncAction operation{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Media::Protection::PlayReady::IPlayReadyLicenseManagement)->DeleteLicenses(get_abi(contentHeader), put_abi(operation)));
    return operation;
}

template <typename D> Windows::Media::Protection::PlayReady::IPlayReadyLicenseAcquisitionServiceRequest consume_Windows_Media_Protection_PlayReady_IPlayReadyLicenseSession<D>::CreateLAServiceRequest() const
{
    Windows::Media::Protection::PlayReady::IPlayReadyLicenseAcquisitionServiceRequest serviceRequest{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Media::Protection::PlayReady::IPlayReadyLicenseSession)->CreateLAServiceRequest(put_abi(serviceRequest)));
    return serviceRequest;
}

template <typename D> void consume_Windows_Media_Protection_PlayReady_IPlayReadyLicenseSession<D>::ConfigureMediaProtectionManager(Windows::Media::Protection::MediaProtectionManager const& mpm) const
{
    check_hresult(WINRT_SHIM(Windows::Media::Protection::PlayReady::IPlayReadyLicenseSession)->ConfigureMediaProtectionManager(get_abi(mpm)));
}

template <typename D> Windows::Media::Protection::PlayReady::PlayReadyLicenseIterable consume_Windows_Media_Protection_PlayReady_IPlayReadyLicenseSession2<D>::CreateLicenseIterable(Windows::Media::Protection::PlayReady::PlayReadyContentHeader const& contentHeader, bool fullyEvaluated) const
{
    Windows::Media::Protection::PlayReady::PlayReadyLicenseIterable licenseIterable{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Media::Protection::PlayReady::IPlayReadyLicenseSession2)->CreateLicenseIterable(get_abi(contentHeader), fullyEvaluated, put_abi(licenseIterable)));
    return licenseIterable;
}

template <typename D> Windows::Media::Protection::PlayReady::PlayReadyLicenseSession consume_Windows_Media_Protection_PlayReady_IPlayReadyLicenseSessionFactory<D>::CreateInstance(Windows::Foundation::Collections::IPropertySet const& configuration) const
{
    Windows::Media::Protection::PlayReady::PlayReadyLicenseSession instance{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Media::Protection::PlayReady::IPlayReadyLicenseSessionFactory)->CreateInstance(get_abi(configuration), put_abi(instance)));
    return instance;
}

template <typename D> com_array<uint8_t> consume_Windows_Media_Protection_PlayReady_IPlayReadyMeteringReportServiceRequest<D>::MeteringCertificate() const
{
    com_array<uint8_t> meteringCertBytes;
    check_hresult(WINRT_SHIM(Windows::Media::Protection::PlayReady::IPlayReadyMeteringReportServiceRequest)->get_MeteringCertificate(impl::put_size_abi(meteringCertBytes), put_abi(meteringCertBytes)));
    return meteringCertBytes;
}

template <typename D> void consume_Windows_Media_Protection_PlayReady_IPlayReadyMeteringReportServiceRequest<D>::MeteringCertificate(array_view<uint8_t const> meteringCertBytes) const
{
    check_hresult(WINRT_SHIM(Windows::Media::Protection::PlayReady::IPlayReadyMeteringReportServiceRequest)->put_MeteringCertificate(meteringCertBytes.size(), get_abi(meteringCertBytes)));
}

template <typename D> Windows::Media::Protection::PlayReady::PlayReadySecureStopIterable consume_Windows_Media_Protection_PlayReady_IPlayReadySecureStopIterableFactory<D>::CreateInstance(array_view<uint8_t const> publisherCertBytes) const
{
    Windows::Media::Protection::PlayReady::PlayReadySecureStopIterable instance{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Media::Protection::PlayReady::IPlayReadySecureStopIterableFactory)->CreateInstance(publisherCertBytes.size(), get_abi(publisherCertBytes), put_abi(instance)));
    return instance;
}

template <typename D> winrt::guid consume_Windows_Media_Protection_PlayReady_IPlayReadySecureStopServiceRequest<D>::SessionID() const
{
    winrt::guid value{};
    check_hresult(WINRT_SHIM(Windows::Media::Protection::PlayReady::IPlayReadySecureStopServiceRequest)->get_SessionID(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::DateTime consume_Windows_Media_Protection_PlayReady_IPlayReadySecureStopServiceRequest<D>::StartTime() const
{
    Windows::Foundation::DateTime value{};
    check_hresult(WINRT_SHIM(Windows::Media::Protection::PlayReady::IPlayReadySecureStopServiceRequest)->get_StartTime(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::DateTime consume_Windows_Media_Protection_PlayReady_IPlayReadySecureStopServiceRequest<D>::UpdateTime() const
{
    Windows::Foundation::DateTime value{};
    check_hresult(WINRT_SHIM(Windows::Media::Protection::PlayReady::IPlayReadySecureStopServiceRequest)->get_UpdateTime(put_abi(value)));
    return value;
}

template <typename D> bool consume_Windows_Media_Protection_PlayReady_IPlayReadySecureStopServiceRequest<D>::Stopped() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::Media::Protection::PlayReady::IPlayReadySecureStopServiceRequest)->get_Stopped(&value));
    return value;
}

template <typename D> com_array<uint8_t> consume_Windows_Media_Protection_PlayReady_IPlayReadySecureStopServiceRequest<D>::PublisherCertificate() const
{
    com_array<uint8_t> publisherCertBytes;
    check_hresult(WINRT_SHIM(Windows::Media::Protection::PlayReady::IPlayReadySecureStopServiceRequest)->get_PublisherCertificate(impl::put_size_abi(publisherCertBytes), put_abi(publisherCertBytes)));
    return publisherCertBytes;
}

template <typename D> Windows::Media::Protection::PlayReady::PlayReadySecureStopServiceRequest consume_Windows_Media_Protection_PlayReady_IPlayReadySecureStopServiceRequestFactory<D>::CreateInstance(array_view<uint8_t const> publisherCertBytes) const
{
    Windows::Media::Protection::PlayReady::PlayReadySecureStopServiceRequest instance{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Media::Protection::PlayReady::IPlayReadySecureStopServiceRequestFactory)->CreateInstance(publisherCertBytes.size(), get_abi(publisherCertBytes), put_abi(instance)));
    return instance;
}

template <typename D> Windows::Media::Protection::PlayReady::PlayReadySecureStopServiceRequest consume_Windows_Media_Protection_PlayReady_IPlayReadySecureStopServiceRequestFactory<D>::CreateInstanceFromSessionID(winrt::guid const& sessionID, array_view<uint8_t const> publisherCertBytes) const
{
    Windows::Media::Protection::PlayReady::PlayReadySecureStopServiceRequest instance{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Media::Protection::PlayReady::IPlayReadySecureStopServiceRequestFactory)->CreateInstanceFromSessionID(get_abi(sessionID), publisherCertBytes.size(), get_abi(publisherCertBytes), put_abi(instance)));
    return instance;
}

template <typename D> Windows::Foundation::Uri consume_Windows_Media_Protection_PlayReady_IPlayReadyServiceRequest<D>::Uri() const
{
    Windows::Foundation::Uri value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Media::Protection::PlayReady::IPlayReadyServiceRequest)->get_Uri(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_Media_Protection_PlayReady_IPlayReadyServiceRequest<D>::Uri(Windows::Foundation::Uri const& value) const
{
    check_hresult(WINRT_SHIM(Windows::Media::Protection::PlayReady::IPlayReadyServiceRequest)->put_Uri(get_abi(value)));
}

template <typename D> hstring consume_Windows_Media_Protection_PlayReady_IPlayReadyServiceRequest<D>::ResponseCustomData() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Media::Protection::PlayReady::IPlayReadyServiceRequest)->get_ResponseCustomData(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_Media_Protection_PlayReady_IPlayReadyServiceRequest<D>::ChallengeCustomData() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Media::Protection::PlayReady::IPlayReadyServiceRequest)->get_ChallengeCustomData(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_Media_Protection_PlayReady_IPlayReadyServiceRequest<D>::ChallengeCustomData(param::hstring const& value) const
{
    check_hresult(WINRT_SHIM(Windows::Media::Protection::PlayReady::IPlayReadyServiceRequest)->put_ChallengeCustomData(get_abi(value)));
}

template <typename D> Windows::Foundation::IAsyncAction consume_Windows_Media_Protection_PlayReady_IPlayReadyServiceRequest<D>::BeginServiceRequest() const
{
    Windows::Foundation::IAsyncAction action{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Media::Protection::PlayReady::IPlayReadyServiceRequest)->BeginServiceRequest(put_abi(action)));
    return action;
}

template <typename D> Windows::Media::Protection::PlayReady::IPlayReadyServiceRequest consume_Windows_Media_Protection_PlayReady_IPlayReadyServiceRequest<D>::NextServiceRequest() const
{
    Windows::Media::Protection::PlayReady::IPlayReadyServiceRequest serviceRequest{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Media::Protection::PlayReady::IPlayReadyServiceRequest)->NextServiceRequest(put_abi(serviceRequest)));
    return serviceRequest;
}

template <typename D> Windows::Media::Protection::PlayReady::PlayReadySoapMessage consume_Windows_Media_Protection_PlayReady_IPlayReadyServiceRequest<D>::GenerateManualEnablingChallenge() const
{
    Windows::Media::Protection::PlayReady::PlayReadySoapMessage challengeMessage{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Media::Protection::PlayReady::IPlayReadyServiceRequest)->GenerateManualEnablingChallenge(put_abi(challengeMessage)));
    return challengeMessage;
}

template <typename D> winrt::hresult consume_Windows_Media_Protection_PlayReady_IPlayReadyServiceRequest<D>::ProcessManualEnablingResponse(array_view<uint8_t const> responseBytes) const
{
    winrt::hresult result{};
    check_hresult(WINRT_SHIM(Windows::Media::Protection::PlayReady::IPlayReadyServiceRequest)->ProcessManualEnablingResponse(responseBytes.size(), get_abi(responseBytes), put_abi(result)));
    return result;
}

template <typename D> com_array<uint8_t> consume_Windows_Media_Protection_PlayReady_IPlayReadySoapMessage<D>::GetMessageBody() const
{
    com_array<uint8_t> messageBodyBytes;
    check_hresult(WINRT_SHIM(Windows::Media::Protection::PlayReady::IPlayReadySoapMessage)->GetMessageBody(impl::put_size_abi(messageBodyBytes), put_abi(messageBodyBytes)));
    return messageBodyBytes;
}

template <typename D> Windows::Foundation::Collections::IPropertySet consume_Windows_Media_Protection_PlayReady_IPlayReadySoapMessage<D>::MessageHeaders() const
{
    Windows::Foundation::Collections::IPropertySet value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Media::Protection::PlayReady::IPlayReadySoapMessage)->get_MessageHeaders(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::Uri consume_Windows_Media_Protection_PlayReady_IPlayReadySoapMessage<D>::Uri() const
{
    Windows::Foundation::Uri messageUri{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Media::Protection::PlayReady::IPlayReadySoapMessage)->get_Uri(put_abi(messageUri)));
    return messageUri;
}

template <typename D> winrt::guid consume_Windows_Media_Protection_PlayReady_IPlayReadyStatics<D>::DomainJoinServiceRequestType() const
{
    winrt::guid value{};
    check_hresult(WINRT_SHIM(Windows::Media::Protection::PlayReady::IPlayReadyStatics)->get_DomainJoinServiceRequestType(put_abi(value)));
    return value;
}

template <typename D> winrt::guid consume_Windows_Media_Protection_PlayReady_IPlayReadyStatics<D>::DomainLeaveServiceRequestType() const
{
    winrt::guid value{};
    check_hresult(WINRT_SHIM(Windows::Media::Protection::PlayReady::IPlayReadyStatics)->get_DomainLeaveServiceRequestType(put_abi(value)));
    return value;
}

template <typename D> winrt::guid consume_Windows_Media_Protection_PlayReady_IPlayReadyStatics<D>::IndividualizationServiceRequestType() const
{
    winrt::guid value{};
    check_hresult(WINRT_SHIM(Windows::Media::Protection::PlayReady::IPlayReadyStatics)->get_IndividualizationServiceRequestType(put_abi(value)));
    return value;
}

template <typename D> winrt::guid consume_Windows_Media_Protection_PlayReady_IPlayReadyStatics<D>::LicenseAcquirerServiceRequestType() const
{
    winrt::guid value{};
    check_hresult(WINRT_SHIM(Windows::Media::Protection::PlayReady::IPlayReadyStatics)->get_LicenseAcquirerServiceRequestType(put_abi(value)));
    return value;
}

template <typename D> winrt::guid consume_Windows_Media_Protection_PlayReady_IPlayReadyStatics<D>::MeteringReportServiceRequestType() const
{
    winrt::guid value{};
    check_hresult(WINRT_SHIM(Windows::Media::Protection::PlayReady::IPlayReadyStatics)->get_MeteringReportServiceRequestType(put_abi(value)));
    return value;
}

template <typename D> winrt::guid consume_Windows_Media_Protection_PlayReady_IPlayReadyStatics<D>::RevocationServiceRequestType() const
{
    winrt::guid value{};
    check_hresult(WINRT_SHIM(Windows::Media::Protection::PlayReady::IPlayReadyStatics)->get_RevocationServiceRequestType(put_abi(value)));
    return value;
}

template <typename D> winrt::guid consume_Windows_Media_Protection_PlayReady_IPlayReadyStatics<D>::MediaProtectionSystemId() const
{
    winrt::guid value{};
    check_hresult(WINRT_SHIM(Windows::Media::Protection::PlayReady::IPlayReadyStatics)->get_MediaProtectionSystemId(put_abi(value)));
    return value;
}

template <typename D> uint32_t consume_Windows_Media_Protection_PlayReady_IPlayReadyStatics<D>::PlayReadySecurityVersion() const
{
    uint32_t value{};
    check_hresult(WINRT_SHIM(Windows::Media::Protection::PlayReady::IPlayReadyStatics)->get_PlayReadySecurityVersion(&value));
    return value;
}

template <typename D> uint32_t consume_Windows_Media_Protection_PlayReady_IPlayReadyStatics2<D>::PlayReadyCertificateSecurityLevel() const
{
    uint32_t value{};
    check_hresult(WINRT_SHIM(Windows::Media::Protection::PlayReady::IPlayReadyStatics2)->get_PlayReadyCertificateSecurityLevel(&value));
    return value;
}

template <typename D> winrt::guid consume_Windows_Media_Protection_PlayReady_IPlayReadyStatics3<D>::SecureStopServiceRequestType() const
{
    winrt::guid value{};
    check_hresult(WINRT_SHIM(Windows::Media::Protection::PlayReady::IPlayReadyStatics3)->get_SecureStopServiceRequestType(put_abi(value)));
    return value;
}

template <typename D> bool consume_Windows_Media_Protection_PlayReady_IPlayReadyStatics3<D>::CheckSupportedHardware(Windows::Media::Protection::PlayReady::PlayReadyHardwareDRMFeatures const& hwdrmFeature) const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::Media::Protection::PlayReady::IPlayReadyStatics3)->CheckSupportedHardware(get_abi(hwdrmFeature), &value));
    return value;
}

template <typename D> hstring consume_Windows_Media_Protection_PlayReady_IPlayReadyStatics4<D>::InputTrustAuthorityToCreate() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Media::Protection::PlayReady::IPlayReadyStatics4)->get_InputTrustAuthorityToCreate(put_abi(value)));
    return value;
}

template <typename D> winrt::guid consume_Windows_Media_Protection_PlayReady_IPlayReadyStatics4<D>::ProtectionSystemId() const
{
    winrt::guid value{};
    check_hresult(WINRT_SHIM(Windows::Media::Protection::PlayReady::IPlayReadyStatics4)->get_ProtectionSystemId(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::IReference<Windows::Foundation::DateTime> consume_Windows_Media_Protection_PlayReady_IPlayReadyStatics5<D>::HardwareDRMDisabledAtTime() const
{
    Windows::Foundation::IReference<Windows::Foundation::DateTime> value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Media::Protection::PlayReady::IPlayReadyStatics5)->get_HardwareDRMDisabledAtTime(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::IReference<Windows::Foundation::DateTime> consume_Windows_Media_Protection_PlayReady_IPlayReadyStatics5<D>::HardwareDRMDisabledUntilTime() const
{
    Windows::Foundation::IReference<Windows::Foundation::DateTime> value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Media::Protection::PlayReady::IPlayReadyStatics5)->get_HardwareDRMDisabledUntilTime(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_Media_Protection_PlayReady_IPlayReadyStatics5<D>::ResetHardwareDRMDisabled() const
{
    check_hresult(WINRT_SHIM(Windows::Media::Protection::PlayReady::IPlayReadyStatics5)->ResetHardwareDRMDisabled());
}

template <typename D>
struct produce<D, Windows::Media::Protection::PlayReady::INDClient> : produce_base<D, Windows::Media::Protection::PlayReady::INDClient>
{
    int32_t WINRT_CALL add_RegistrationCompleted(void* handler, winrt::event_token* token) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(RegistrationCompleted, WINRT_WRAP(winrt::event_token), Windows::Foundation::TypedEventHandler<Windows::Media::Protection::PlayReady::NDClient, Windows::Media::Protection::PlayReady::INDRegistrationCompletedEventArgs> const&);
            *token = detach_from<winrt::event_token>(this->shim().RegistrationCompleted(*reinterpret_cast<Windows::Foundation::TypedEventHandler<Windows::Media::Protection::PlayReady::NDClient, Windows::Media::Protection::PlayReady::INDRegistrationCompletedEventArgs> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL remove_RegistrationCompleted(winrt::event_token token) noexcept final
    {
        typename D::abi_guard guard(this->shim());
        WINRT_ASSERT_DECLARATION(RegistrationCompleted, WINRT_WRAP(void), winrt::event_token const&);
        this->shim().RegistrationCompleted(*reinterpret_cast<winrt::event_token const*>(&token));
        return 0;
    }

    int32_t WINRT_CALL add_ProximityDetectionCompleted(void* handler, winrt::event_token* token) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ProximityDetectionCompleted, WINRT_WRAP(winrt::event_token), Windows::Foundation::TypedEventHandler<Windows::Media::Protection::PlayReady::NDClient, Windows::Media::Protection::PlayReady::INDProximityDetectionCompletedEventArgs> const&);
            *token = detach_from<winrt::event_token>(this->shim().ProximityDetectionCompleted(*reinterpret_cast<Windows::Foundation::TypedEventHandler<Windows::Media::Protection::PlayReady::NDClient, Windows::Media::Protection::PlayReady::INDProximityDetectionCompletedEventArgs> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL remove_ProximityDetectionCompleted(winrt::event_token token) noexcept final
    {
        typename D::abi_guard guard(this->shim());
        WINRT_ASSERT_DECLARATION(ProximityDetectionCompleted, WINRT_WRAP(void), winrt::event_token const&);
        this->shim().ProximityDetectionCompleted(*reinterpret_cast<winrt::event_token const*>(&token));
        return 0;
    }

    int32_t WINRT_CALL add_LicenseFetchCompleted(void* handler, winrt::event_token* token) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(LicenseFetchCompleted, WINRT_WRAP(winrt::event_token), Windows::Foundation::TypedEventHandler<Windows::Media::Protection::PlayReady::NDClient, Windows::Media::Protection::PlayReady::INDLicenseFetchCompletedEventArgs> const&);
            *token = detach_from<winrt::event_token>(this->shim().LicenseFetchCompleted(*reinterpret_cast<Windows::Foundation::TypedEventHandler<Windows::Media::Protection::PlayReady::NDClient, Windows::Media::Protection::PlayReady::INDLicenseFetchCompletedEventArgs> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL remove_LicenseFetchCompleted(winrt::event_token token) noexcept final
    {
        typename D::abi_guard guard(this->shim());
        WINRT_ASSERT_DECLARATION(LicenseFetchCompleted, WINRT_WRAP(void), winrt::event_token const&);
        this->shim().LicenseFetchCompleted(*reinterpret_cast<winrt::event_token const*>(&token));
        return 0;
    }

    int32_t WINRT_CALL add_ReRegistrationNeeded(void* handler, winrt::event_token* token) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ReRegistrationNeeded, WINRT_WRAP(winrt::event_token), Windows::Foundation::TypedEventHandler<Windows::Media::Protection::PlayReady::NDClient, Windows::Foundation::IInspectable> const&);
            *token = detach_from<winrt::event_token>(this->shim().ReRegistrationNeeded(*reinterpret_cast<Windows::Foundation::TypedEventHandler<Windows::Media::Protection::PlayReady::NDClient, Windows::Foundation::IInspectable> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL remove_ReRegistrationNeeded(winrt::event_token token) noexcept final
    {
        typename D::abi_guard guard(this->shim());
        WINRT_ASSERT_DECLARATION(ReRegistrationNeeded, WINRT_WRAP(void), winrt::event_token const&);
        this->shim().ReRegistrationNeeded(*reinterpret_cast<winrt::event_token const*>(&token));
        return 0;
    }

    int32_t WINRT_CALL add_ClosedCaptionDataReceived(void* handler, winrt::event_token* token) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ClosedCaptionDataReceived, WINRT_WRAP(winrt::event_token), Windows::Foundation::TypedEventHandler<Windows::Media::Protection::PlayReady::NDClient, Windows::Media::Protection::PlayReady::INDClosedCaptionDataReceivedEventArgs> const&);
            *token = detach_from<winrt::event_token>(this->shim().ClosedCaptionDataReceived(*reinterpret_cast<Windows::Foundation::TypedEventHandler<Windows::Media::Protection::PlayReady::NDClient, Windows::Media::Protection::PlayReady::INDClosedCaptionDataReceivedEventArgs> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL remove_ClosedCaptionDataReceived(winrt::event_token token) noexcept final
    {
        typename D::abi_guard guard(this->shim());
        WINRT_ASSERT_DECLARATION(ClosedCaptionDataReceived, WINRT_WRAP(void), winrt::event_token const&);
        this->shim().ClosedCaptionDataReceived(*reinterpret_cast<winrt::event_token const*>(&token));
        return 0;
    }

    int32_t WINRT_CALL StartAsync(void* contentUrl, uint32_t startAsyncOptions, void* registrationCustomData, void* licenseFetchDescriptor, void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(StartAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<Windows::Media::Protection::PlayReady::INDStartResult>), Windows::Foundation::Uri const, uint32_t, Windows::Media::Protection::PlayReady::INDCustomData const, Windows::Media::Protection::PlayReady::INDLicenseFetchDescriptor const);
            *result = detach_from<Windows::Foundation::IAsyncOperation<Windows::Media::Protection::PlayReady::INDStartResult>>(this->shim().StartAsync(*reinterpret_cast<Windows::Foundation::Uri const*>(&contentUrl), startAsyncOptions, *reinterpret_cast<Windows::Media::Protection::PlayReady::INDCustomData const*>(&registrationCustomData), *reinterpret_cast<Windows::Media::Protection::PlayReady::INDLicenseFetchDescriptor const*>(&licenseFetchDescriptor)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL LicenseFetchAsync(void* licenseFetchDescriptor, void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(LicenseFetchAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<Windows::Media::Protection::PlayReady::INDLicenseFetchResult>), Windows::Media::Protection::PlayReady::INDLicenseFetchDescriptor const);
            *result = detach_from<Windows::Foundation::IAsyncOperation<Windows::Media::Protection::PlayReady::INDLicenseFetchResult>>(this->shim().LicenseFetchAsync(*reinterpret_cast<Windows::Media::Protection::PlayReady::INDLicenseFetchDescriptor const*>(&licenseFetchDescriptor)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL ReRegistrationAsync(void* registrationCustomData, void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ReRegistrationAsync, WINRT_WRAP(Windows::Foundation::IAsyncAction), Windows::Media::Protection::PlayReady::INDCustomData const);
            *result = detach_from<Windows::Foundation::IAsyncAction>(this->shim().ReRegistrationAsync(*reinterpret_cast<Windows::Media::Protection::PlayReady::INDCustomData const*>(&registrationCustomData)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL Close() noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Close, WINRT_WRAP(void));
            this->shim().Close();
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Media::Protection::PlayReady::INDClientFactory> : produce_base<D, Windows::Media::Protection::PlayReady::INDClientFactory>
{
    int32_t WINRT_CALL CreateInstance(void* downloadEngine, void* streamParser, void* pMessenger, void** instance) noexcept final
    {
        try
        {
            *instance = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CreateInstance, WINRT_WRAP(Windows::Media::Protection::PlayReady::NDClient), Windows::Media::Protection::PlayReady::INDDownloadEngine const&, Windows::Media::Protection::PlayReady::INDStreamParser const&, Windows::Media::Protection::PlayReady::INDMessenger const&);
            *instance = detach_from<Windows::Media::Protection::PlayReady::NDClient>(this->shim().CreateInstance(*reinterpret_cast<Windows::Media::Protection::PlayReady::INDDownloadEngine const*>(&downloadEngine), *reinterpret_cast<Windows::Media::Protection::PlayReady::INDStreamParser const*>(&streamParser), *reinterpret_cast<Windows::Media::Protection::PlayReady::INDMessenger const*>(&pMessenger)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Media::Protection::PlayReady::INDClosedCaptionDataReceivedEventArgs> : produce_base<D, Windows::Media::Protection::PlayReady::INDClosedCaptionDataReceivedEventArgs>
{
    int32_t WINRT_CALL get_ClosedCaptionDataFormat(Windows::Media::Protection::PlayReady::NDClosedCaptionFormat* ccForamt) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ClosedCaptionDataFormat, WINRT_WRAP(Windows::Media::Protection::PlayReady::NDClosedCaptionFormat));
            *ccForamt = detach_from<Windows::Media::Protection::PlayReady::NDClosedCaptionFormat>(this->shim().ClosedCaptionDataFormat());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_PresentationTimestamp(int64_t* presentationTimestamp) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(PresentationTimestamp, WINRT_WRAP(int64_t));
            *presentationTimestamp = detach_from<int64_t>(this->shim().PresentationTimestamp());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_ClosedCaptionData(uint32_t* __ccDataBytesSize, uint8_t** ccDataBytes) noexcept final
    {
        try
        {
            *__ccDataBytesSize = 0;
            *ccDataBytes = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ClosedCaptionData, WINRT_WRAP(com_array<uint8_t>));
            std::tie(*__ccDataBytesSize, *ccDataBytes) = detach_abi(this->shim().ClosedCaptionData());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Media::Protection::PlayReady::INDCustomData> : produce_base<D, Windows::Media::Protection::PlayReady::INDCustomData>
{
    int32_t WINRT_CALL get_CustomDataTypeID(uint32_t* __customDataTypeIDBytesSize, uint8_t** customDataTypeIDBytes) noexcept final
    {
        try
        {
            *__customDataTypeIDBytesSize = 0;
            *customDataTypeIDBytes = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CustomDataTypeID, WINRT_WRAP(com_array<uint8_t>));
            std::tie(*__customDataTypeIDBytesSize, *customDataTypeIDBytes) = detach_abi(this->shim().CustomDataTypeID());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_CustomData(uint32_t* __customDataBytesSize, uint8_t** customDataBytes) noexcept final
    {
        try
        {
            *__customDataBytesSize = 0;
            *customDataBytes = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CustomData, WINRT_WRAP(com_array<uint8_t>));
            std::tie(*__customDataBytesSize, *customDataBytes) = detach_abi(this->shim().CustomData());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Media::Protection::PlayReady::INDCustomDataFactory> : produce_base<D, Windows::Media::Protection::PlayReady::INDCustomDataFactory>
{
    int32_t WINRT_CALL CreateInstance(uint32_t __customDataTypeIDBytesSize, uint8_t* customDataTypeIDBytes, uint32_t __customDataBytesSize, uint8_t* customDataBytes, void** instance) noexcept final
    {
        try
        {
            *instance = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CreateInstance, WINRT_WRAP(Windows::Media::Protection::PlayReady::NDCustomData), array_view<uint8_t const>, array_view<uint8_t const>);
            *instance = detach_from<Windows::Media::Protection::PlayReady::NDCustomData>(this->shim().CreateInstance(array_view<uint8_t const>(reinterpret_cast<uint8_t const *>(customDataTypeIDBytes), reinterpret_cast<uint8_t const *>(customDataTypeIDBytes) + __customDataTypeIDBytesSize), array_view<uint8_t const>(reinterpret_cast<uint8_t const *>(customDataBytes), reinterpret_cast<uint8_t const *>(customDataBytes) + __customDataBytesSize)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Media::Protection::PlayReady::INDDownloadEngine> : produce_base<D, Windows::Media::Protection::PlayReady::INDDownloadEngine>
{
    int32_t WINRT_CALL Open(void* uri, uint32_t __sessionIDBytesSize, uint8_t* sessionIDBytes) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Open, WINRT_WRAP(void), Windows::Foundation::Uri const&, array_view<uint8_t const>);
            this->shim().Open(*reinterpret_cast<Windows::Foundation::Uri const*>(&uri), array_view<uint8_t const>(reinterpret_cast<uint8_t const *>(sessionIDBytes), reinterpret_cast<uint8_t const *>(sessionIDBytes) + __sessionIDBytesSize));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL Pause() noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Pause, WINRT_WRAP(void));
            this->shim().Pause();
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL Resume() noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Resume, WINRT_WRAP(void));
            this->shim().Resume();
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL Close() noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Close, WINRT_WRAP(void));
            this->shim().Close();
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL Seek(Windows::Foundation::TimeSpan startPosition) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Seek, WINRT_WRAP(void), Windows::Foundation::TimeSpan const&);
            this->shim().Seek(*reinterpret_cast<Windows::Foundation::TimeSpan const*>(&startPosition));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_CanSeek(bool* canSeek) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CanSeek, WINRT_WRAP(bool));
            *canSeek = detach_from<bool>(this->shim().CanSeek());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_BufferFullMinThresholdInSamples(uint32_t* bufferFullMinThreshold) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(BufferFullMinThresholdInSamples, WINRT_WRAP(uint32_t));
            *bufferFullMinThreshold = detach_from<uint32_t>(this->shim().BufferFullMinThresholdInSamples());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_BufferFullMaxThresholdInSamples(uint32_t* bufferFullMaxThreshold) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(BufferFullMaxThresholdInSamples, WINRT_WRAP(uint32_t));
            *bufferFullMaxThreshold = detach_from<uint32_t>(this->shim().BufferFullMaxThresholdInSamples());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Notifier(void** instance) noexcept final
    {
        try
        {
            *instance = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Notifier, WINRT_WRAP(Windows::Media::Protection::PlayReady::NDDownloadEngineNotifier));
            *instance = detach_from<Windows::Media::Protection::PlayReady::NDDownloadEngineNotifier>(this->shim().Notifier());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Media::Protection::PlayReady::INDDownloadEngineNotifier> : produce_base<D, Windows::Media::Protection::PlayReady::INDDownloadEngineNotifier>
{
    int32_t WINRT_CALL OnStreamOpened() noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(OnStreamOpened, WINRT_WRAP(void));
            this->shim().OnStreamOpened();
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL OnPlayReadyObjectReceived(uint32_t __dataBytesSize, uint8_t* dataBytes) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(OnPlayReadyObjectReceived, WINRT_WRAP(void), array_view<uint8_t const>);
            this->shim().OnPlayReadyObjectReceived(array_view<uint8_t const>(reinterpret_cast<uint8_t const *>(dataBytes), reinterpret_cast<uint8_t const *>(dataBytes) + __dataBytesSize));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL OnContentIDReceived(void* licenseFetchDescriptor) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(OnContentIDReceived, WINRT_WRAP(void), Windows::Media::Protection::PlayReady::INDLicenseFetchDescriptor const&);
            this->shim().OnContentIDReceived(*reinterpret_cast<Windows::Media::Protection::PlayReady::INDLicenseFetchDescriptor const*>(&licenseFetchDescriptor));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL OnDataReceived(uint32_t __dataBytesSize, uint8_t* dataBytes, uint32_t bytesReceived) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(OnDataReceived, WINRT_WRAP(void), array_view<uint8_t const>, uint32_t);
            this->shim().OnDataReceived(array_view<uint8_t const>(reinterpret_cast<uint8_t const *>(dataBytes), reinterpret_cast<uint8_t const *>(dataBytes) + __dataBytesSize), bytesReceived);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL OnEndOfStream() noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(OnEndOfStream, WINRT_WRAP(void));
            this->shim().OnEndOfStream();
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL OnNetworkError() noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(OnNetworkError, WINRT_WRAP(void));
            this->shim().OnNetworkError();
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Media::Protection::PlayReady::INDLicenseFetchCompletedEventArgs> : produce_base<D, Windows::Media::Protection::PlayReady::INDLicenseFetchCompletedEventArgs>
{
    int32_t WINRT_CALL get_ResponseCustomData(void** customData) noexcept final
    {
        try
        {
            *customData = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ResponseCustomData, WINRT_WRAP(Windows::Media::Protection::PlayReady::INDCustomData));
            *customData = detach_from<Windows::Media::Protection::PlayReady::INDCustomData>(this->shim().ResponseCustomData());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Media::Protection::PlayReady::INDLicenseFetchDescriptor> : produce_base<D, Windows::Media::Protection::PlayReady::INDLicenseFetchDescriptor>
{
    int32_t WINRT_CALL get_ContentIDType(Windows::Media::Protection::PlayReady::NDContentIDType* contentIDType) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ContentIDType, WINRT_WRAP(Windows::Media::Protection::PlayReady::NDContentIDType));
            *contentIDType = detach_from<Windows::Media::Protection::PlayReady::NDContentIDType>(this->shim().ContentIDType());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_ContentID(uint32_t* __contentIDBytesSize, uint8_t** contentIDBytes) noexcept final
    {
        try
        {
            *__contentIDBytesSize = 0;
            *contentIDBytes = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ContentID, WINRT_WRAP(com_array<uint8_t>));
            std::tie(*__contentIDBytesSize, *contentIDBytes) = detach_abi(this->shim().ContentID());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_LicenseFetchChallengeCustomData(void** licenseFetchChallengeCustomData) noexcept final
    {
        try
        {
            *licenseFetchChallengeCustomData = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(LicenseFetchChallengeCustomData, WINRT_WRAP(Windows::Media::Protection::PlayReady::INDCustomData));
            *licenseFetchChallengeCustomData = detach_from<Windows::Media::Protection::PlayReady::INDCustomData>(this->shim().LicenseFetchChallengeCustomData());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_LicenseFetchChallengeCustomData(void* licenseFetchChallengeCustomData) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(LicenseFetchChallengeCustomData, WINRT_WRAP(void), Windows::Media::Protection::PlayReady::INDCustomData const&);
            this->shim().LicenseFetchChallengeCustomData(*reinterpret_cast<Windows::Media::Protection::PlayReady::INDCustomData const*>(&licenseFetchChallengeCustomData));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Media::Protection::PlayReady::INDLicenseFetchDescriptorFactory> : produce_base<D, Windows::Media::Protection::PlayReady::INDLicenseFetchDescriptorFactory>
{
    int32_t WINRT_CALL CreateInstance(Windows::Media::Protection::PlayReady::NDContentIDType contentIDType, uint32_t __contentIDBytesSize, uint8_t* contentIDBytes, void* licenseFetchChallengeCustomData, void** instance) noexcept final
    {
        try
        {
            *instance = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CreateInstance, WINRT_WRAP(Windows::Media::Protection::PlayReady::NDLicenseFetchDescriptor), Windows::Media::Protection::PlayReady::NDContentIDType const&, array_view<uint8_t const>, Windows::Media::Protection::PlayReady::INDCustomData const&);
            *instance = detach_from<Windows::Media::Protection::PlayReady::NDLicenseFetchDescriptor>(this->shim().CreateInstance(*reinterpret_cast<Windows::Media::Protection::PlayReady::NDContentIDType const*>(&contentIDType), array_view<uint8_t const>(reinterpret_cast<uint8_t const *>(contentIDBytes), reinterpret_cast<uint8_t const *>(contentIDBytes) + __contentIDBytesSize), *reinterpret_cast<Windows::Media::Protection::PlayReady::INDCustomData const*>(&licenseFetchChallengeCustomData)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Media::Protection::PlayReady::INDLicenseFetchResult> : produce_base<D, Windows::Media::Protection::PlayReady::INDLicenseFetchResult>
{
    int32_t WINRT_CALL get_ResponseCustomData(void** customData) noexcept final
    {
        try
        {
            *customData = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ResponseCustomData, WINRT_WRAP(Windows::Media::Protection::PlayReady::INDCustomData));
            *customData = detach_from<Windows::Media::Protection::PlayReady::INDCustomData>(this->shim().ResponseCustomData());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Media::Protection::PlayReady::INDMessenger> : produce_base<D, Windows::Media::Protection::PlayReady::INDMessenger>
{
    int32_t WINRT_CALL SendRegistrationRequestAsync(uint32_t __sessionIDBytesSize, uint8_t* sessionIDBytes, uint32_t __challengeDataBytesSize, uint8_t* challengeDataBytes, void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SendRegistrationRequestAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<Windows::Media::Protection::PlayReady::INDSendResult>), array_view<uint8_t const>, array_view<uint8_t const>);
            *result = detach_from<Windows::Foundation::IAsyncOperation<Windows::Media::Protection::PlayReady::INDSendResult>>(this->shim().SendRegistrationRequestAsync(array_view<uint8_t const>(reinterpret_cast<uint8_t const *>(sessionIDBytes), reinterpret_cast<uint8_t const *>(sessionIDBytes) + __sessionIDBytesSize), array_view<uint8_t const>(reinterpret_cast<uint8_t const *>(challengeDataBytes), reinterpret_cast<uint8_t const *>(challengeDataBytes) + __challengeDataBytesSize)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL SendProximityDetectionStartAsync(Windows::Media::Protection::PlayReady::NDProximityDetectionType pdType, uint32_t __transmitterChannelBytesSize, uint8_t* transmitterChannelBytes, uint32_t __sessionIDBytesSize, uint8_t* sessionIDBytes, uint32_t __challengeDataBytesSize, uint8_t* challengeDataBytes, void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SendProximityDetectionStartAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<Windows::Media::Protection::PlayReady::INDSendResult>), Windows::Media::Protection::PlayReady::NDProximityDetectionType const, array_view<uint8_t const>, array_view<uint8_t const>, array_view<uint8_t const>);
            *result = detach_from<Windows::Foundation::IAsyncOperation<Windows::Media::Protection::PlayReady::INDSendResult>>(this->shim().SendProximityDetectionStartAsync(*reinterpret_cast<Windows::Media::Protection::PlayReady::NDProximityDetectionType const*>(&pdType), array_view<uint8_t const>(reinterpret_cast<uint8_t const *>(transmitterChannelBytes), reinterpret_cast<uint8_t const *>(transmitterChannelBytes) + __transmitterChannelBytesSize), array_view<uint8_t const>(reinterpret_cast<uint8_t const *>(sessionIDBytes), reinterpret_cast<uint8_t const *>(sessionIDBytes) + __sessionIDBytesSize), array_view<uint8_t const>(reinterpret_cast<uint8_t const *>(challengeDataBytes), reinterpret_cast<uint8_t const *>(challengeDataBytes) + __challengeDataBytesSize)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL SendProximityDetectionResponseAsync(Windows::Media::Protection::PlayReady::NDProximityDetectionType pdType, uint32_t __transmitterChannelBytesSize, uint8_t* transmitterChannelBytes, uint32_t __sessionIDBytesSize, uint8_t* sessionIDBytes, uint32_t __responseDataBytesSize, uint8_t* responseDataBytes, void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SendProximityDetectionResponseAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<Windows::Media::Protection::PlayReady::INDSendResult>), Windows::Media::Protection::PlayReady::NDProximityDetectionType const, array_view<uint8_t const>, array_view<uint8_t const>, array_view<uint8_t const>);
            *result = detach_from<Windows::Foundation::IAsyncOperation<Windows::Media::Protection::PlayReady::INDSendResult>>(this->shim().SendProximityDetectionResponseAsync(*reinterpret_cast<Windows::Media::Protection::PlayReady::NDProximityDetectionType const*>(&pdType), array_view<uint8_t const>(reinterpret_cast<uint8_t const *>(transmitterChannelBytes), reinterpret_cast<uint8_t const *>(transmitterChannelBytes) + __transmitterChannelBytesSize), array_view<uint8_t const>(reinterpret_cast<uint8_t const *>(sessionIDBytes), reinterpret_cast<uint8_t const *>(sessionIDBytes) + __sessionIDBytesSize), array_view<uint8_t const>(reinterpret_cast<uint8_t const *>(responseDataBytes), reinterpret_cast<uint8_t const *>(responseDataBytes) + __responseDataBytesSize)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL SendLicenseFetchRequestAsync(uint32_t __sessionIDBytesSize, uint8_t* sessionIDBytes, uint32_t __challengeDataBytesSize, uint8_t* challengeDataBytes, void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SendLicenseFetchRequestAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<Windows::Media::Protection::PlayReady::INDSendResult>), array_view<uint8_t const>, array_view<uint8_t const>);
            *result = detach_from<Windows::Foundation::IAsyncOperation<Windows::Media::Protection::PlayReady::INDSendResult>>(this->shim().SendLicenseFetchRequestAsync(array_view<uint8_t const>(reinterpret_cast<uint8_t const *>(sessionIDBytes), reinterpret_cast<uint8_t const *>(sessionIDBytes) + __sessionIDBytesSize), array_view<uint8_t const>(reinterpret_cast<uint8_t const *>(challengeDataBytes), reinterpret_cast<uint8_t const *>(challengeDataBytes) + __challengeDataBytesSize)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Media::Protection::PlayReady::INDProximityDetectionCompletedEventArgs> : produce_base<D, Windows::Media::Protection::PlayReady::INDProximityDetectionCompletedEventArgs>
{
    int32_t WINRT_CALL get_ProximityDetectionRetryCount(uint32_t* retryCount) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ProximityDetectionRetryCount, WINRT_WRAP(uint32_t));
            *retryCount = detach_from<uint32_t>(this->shim().ProximityDetectionRetryCount());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Media::Protection::PlayReady::INDRegistrationCompletedEventArgs> : produce_base<D, Windows::Media::Protection::PlayReady::INDRegistrationCompletedEventArgs>
{
    int32_t WINRT_CALL get_ResponseCustomData(void** customData) noexcept final
    {
        try
        {
            *customData = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ResponseCustomData, WINRT_WRAP(Windows::Media::Protection::PlayReady::INDCustomData));
            *customData = detach_from<Windows::Media::Protection::PlayReady::INDCustomData>(this->shim().ResponseCustomData());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_TransmitterProperties(void** transmitterProperties) noexcept final
    {
        try
        {
            *transmitterProperties = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(TransmitterProperties, WINRT_WRAP(Windows::Media::Protection::PlayReady::INDTransmitterProperties));
            *transmitterProperties = detach_from<Windows::Media::Protection::PlayReady::INDTransmitterProperties>(this->shim().TransmitterProperties());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_TransmitterCertificateAccepted(bool* acceptpt) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(TransmitterCertificateAccepted, WINRT_WRAP(bool));
            *acceptpt = detach_from<bool>(this->shim().TransmitterCertificateAccepted());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_TransmitterCertificateAccepted(bool accept) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(TransmitterCertificateAccepted, WINRT_WRAP(void), bool);
            this->shim().TransmitterCertificateAccepted(accept);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Media::Protection::PlayReady::INDSendResult> : produce_base<D, Windows::Media::Protection::PlayReady::INDSendResult>
{
    int32_t WINRT_CALL get_Response(uint32_t* __responseDataBytesSize, uint8_t** responseDataBytes) noexcept final
    {
        try
        {
            *__responseDataBytesSize = 0;
            *responseDataBytes = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Response, WINRT_WRAP(com_array<uint8_t>));
            std::tie(*__responseDataBytesSize, *responseDataBytes) = detach_abi(this->shim().Response());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Media::Protection::PlayReady::INDStartResult> : produce_base<D, Windows::Media::Protection::PlayReady::INDStartResult>
{
    int32_t WINRT_CALL get_MediaStreamSource(void** mediaStreamSource) noexcept final
    {
        try
        {
            *mediaStreamSource = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(MediaStreamSource, WINRT_WRAP(Windows::Media::Core::MediaStreamSource));
            *mediaStreamSource = detach_from<Windows::Media::Core::MediaStreamSource>(this->shim().MediaStreamSource());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Media::Protection::PlayReady::INDStorageFileHelper> : produce_base<D, Windows::Media::Protection::PlayReady::INDStorageFileHelper>
{
    int32_t WINRT_CALL GetFileURLs(void* file, void** fileURLs) noexcept final
    {
        try
        {
            *fileURLs = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetFileURLs, WINRT_WRAP(Windows::Foundation::Collections::IVector<hstring>), Windows::Storage::IStorageFile const&);
            *fileURLs = detach_from<Windows::Foundation::Collections::IVector<hstring>>(this->shim().GetFileURLs(*reinterpret_cast<Windows::Storage::IStorageFile const*>(&file)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Media::Protection::PlayReady::INDStreamParser> : produce_base<D, Windows::Media::Protection::PlayReady::INDStreamParser>
{
    int32_t WINRT_CALL ParseData(uint32_t __dataBytesSize, uint8_t* dataBytes) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ParseData, WINRT_WRAP(void), array_view<uint8_t const>);
            this->shim().ParseData(array_view<uint8_t const>(reinterpret_cast<uint8_t const *>(dataBytes), reinterpret_cast<uint8_t const *>(dataBytes) + __dataBytesSize));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL GetStreamInformation(void* descriptor, Windows::Media::Protection::PlayReady::NDMediaStreamType* streamType, uint32_t* streamID) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetStreamInformation, WINRT_WRAP(uint32_t), Windows::Media::Core::IMediaStreamDescriptor const&, Windows::Media::Protection::PlayReady::NDMediaStreamType&);
            *streamID = detach_from<uint32_t>(this->shim().GetStreamInformation(*reinterpret_cast<Windows::Media::Core::IMediaStreamDescriptor const*>(&descriptor), *reinterpret_cast<Windows::Media::Protection::PlayReady::NDMediaStreamType*>(streamType)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL BeginOfStream() noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(BeginOfStream, WINRT_WRAP(void));
            this->shim().BeginOfStream();
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL EndOfStream() noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(EndOfStream, WINRT_WRAP(void));
            this->shim().EndOfStream();
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Notifier(void** instance) noexcept final
    {
        try
        {
            *instance = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Notifier, WINRT_WRAP(Windows::Media::Protection::PlayReady::NDStreamParserNotifier));
            *instance = detach_from<Windows::Media::Protection::PlayReady::NDStreamParserNotifier>(this->shim().Notifier());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Media::Protection::PlayReady::INDStreamParserNotifier> : produce_base<D, Windows::Media::Protection::PlayReady::INDStreamParserNotifier>
{
    int32_t WINRT_CALL OnContentIDReceived(void* licenseFetchDescriptor) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(OnContentIDReceived, WINRT_WRAP(void), Windows::Media::Protection::PlayReady::INDLicenseFetchDescriptor const&);
            this->shim().OnContentIDReceived(*reinterpret_cast<Windows::Media::Protection::PlayReady::INDLicenseFetchDescriptor const*>(&licenseFetchDescriptor));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL OnMediaStreamDescriptorCreated(void* audioStreamDescriptors, void* videoStreamDescriptors) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(OnMediaStreamDescriptorCreated, WINRT_WRAP(void), Windows::Foundation::Collections::IVector<Windows::Media::Core::AudioStreamDescriptor> const&, Windows::Foundation::Collections::IVector<Windows::Media::Core::VideoStreamDescriptor> const&);
            this->shim().OnMediaStreamDescriptorCreated(*reinterpret_cast<Windows::Foundation::Collections::IVector<Windows::Media::Core::AudioStreamDescriptor> const*>(&audioStreamDescriptors), *reinterpret_cast<Windows::Foundation::Collections::IVector<Windows::Media::Core::VideoStreamDescriptor> const*>(&videoStreamDescriptors));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL OnSampleParsed(uint32_t streamID, Windows::Media::Protection::PlayReady::NDMediaStreamType streamType, void* streamSample, int64_t pts, Windows::Media::Protection::PlayReady::NDClosedCaptionFormat ccFormat, uint32_t __ccDataBytesSize, uint8_t* ccDataBytes) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(OnSampleParsed, WINRT_WRAP(void), uint32_t, Windows::Media::Protection::PlayReady::NDMediaStreamType const&, Windows::Media::Core::MediaStreamSample const&, int64_t, Windows::Media::Protection::PlayReady::NDClosedCaptionFormat const&, array_view<uint8_t const>);
            this->shim().OnSampleParsed(streamID, *reinterpret_cast<Windows::Media::Protection::PlayReady::NDMediaStreamType const*>(&streamType), *reinterpret_cast<Windows::Media::Core::MediaStreamSample const*>(&streamSample), pts, *reinterpret_cast<Windows::Media::Protection::PlayReady::NDClosedCaptionFormat const*>(&ccFormat), array_view<uint8_t const>(reinterpret_cast<uint8_t const *>(ccDataBytes), reinterpret_cast<uint8_t const *>(ccDataBytes) + __ccDataBytesSize));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL OnBeginSetupDecryptor(void* descriptor, winrt::guid keyID, uint32_t __proBytesSize, uint8_t* proBytes) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(OnBeginSetupDecryptor, WINRT_WRAP(void), Windows::Media::Core::IMediaStreamDescriptor const&, winrt::guid const&, array_view<uint8_t const>);
            this->shim().OnBeginSetupDecryptor(*reinterpret_cast<Windows::Media::Core::IMediaStreamDescriptor const*>(&descriptor), *reinterpret_cast<winrt::guid const*>(&keyID), array_view<uint8_t const>(reinterpret_cast<uint8_t const *>(proBytes), reinterpret_cast<uint8_t const *>(proBytes) + __proBytesSize));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Media::Protection::PlayReady::INDTCPMessengerFactory> : produce_base<D, Windows::Media::Protection::PlayReady::INDTCPMessengerFactory>
{
    int32_t WINRT_CALL CreateInstance(void* remoteHostName, uint32_t remoteHostPort, void** instance) noexcept final
    {
        try
        {
            *instance = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CreateInstance, WINRT_WRAP(Windows::Media::Protection::PlayReady::NDTCPMessenger), hstring const&, uint32_t);
            *instance = detach_from<Windows::Media::Protection::PlayReady::NDTCPMessenger>(this->shim().CreateInstance(*reinterpret_cast<hstring const*>(&remoteHostName), remoteHostPort));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Media::Protection::PlayReady::INDTransmitterProperties> : produce_base<D, Windows::Media::Protection::PlayReady::INDTransmitterProperties>
{
    int32_t WINRT_CALL get_CertificateType(Windows::Media::Protection::PlayReady::NDCertificateType* type) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CertificateType, WINRT_WRAP(Windows::Media::Protection::PlayReady::NDCertificateType));
            *type = detach_from<Windows::Media::Protection::PlayReady::NDCertificateType>(this->shim().CertificateType());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_PlatformIdentifier(Windows::Media::Protection::PlayReady::NDCertificatePlatformID* identifier) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(PlatformIdentifier, WINRT_WRAP(Windows::Media::Protection::PlayReady::NDCertificatePlatformID));
            *identifier = detach_from<Windows::Media::Protection::PlayReady::NDCertificatePlatformID>(this->shim().PlatformIdentifier());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_SupportedFeatures(uint32_t* __featureSetsSize, Windows::Media::Protection::PlayReady::NDCertificateFeature** featureSets) noexcept final
    {
        try
        {
            *__featureSetsSize = 0;
            *featureSets = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SupportedFeatures, WINRT_WRAP(com_array<Windows::Media::Protection::PlayReady::NDCertificateFeature>));
            std::tie(*__featureSetsSize, *featureSets) = detach_abi(this->shim().SupportedFeatures());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_SecurityLevel(uint32_t* level) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SecurityLevel, WINRT_WRAP(uint32_t));
            *level = detach_from<uint32_t>(this->shim().SecurityLevel());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_SecurityVersion(uint32_t* securityVersion) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SecurityVersion, WINRT_WRAP(uint32_t));
            *securityVersion = detach_from<uint32_t>(this->shim().SecurityVersion());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_ExpirationDate(Windows::Foundation::DateTime* expirationDate) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ExpirationDate, WINRT_WRAP(Windows::Foundation::DateTime));
            *expirationDate = detach_from<Windows::Foundation::DateTime>(this->shim().ExpirationDate());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_ClientID(uint32_t* __clientIDBytesSize, uint8_t** clientIDBytes) noexcept final
    {
        try
        {
            *__clientIDBytesSize = 0;
            *clientIDBytes = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ClientID, WINRT_WRAP(com_array<uint8_t>));
            std::tie(*__clientIDBytesSize, *clientIDBytes) = detach_abi(this->shim().ClientID());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_ModelDigest(uint32_t* __modelDigestBytesSize, uint8_t** modelDigestBytes) noexcept final
    {
        try
        {
            *__modelDigestBytesSize = 0;
            *modelDigestBytes = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ModelDigest, WINRT_WRAP(com_array<uint8_t>));
            std::tie(*__modelDigestBytesSize, *modelDigestBytes) = detach_abi(this->shim().ModelDigest());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_ModelManufacturerName(void** modelManufacturerName) noexcept final
    {
        try
        {
            *modelManufacturerName = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ModelManufacturerName, WINRT_WRAP(hstring));
            *modelManufacturerName = detach_from<hstring>(this->shim().ModelManufacturerName());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_ModelName(void** modelName) noexcept final
    {
        try
        {
            *modelName = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ModelName, WINRT_WRAP(hstring));
            *modelName = detach_from<hstring>(this->shim().ModelName());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_ModelNumber(void** modelNumber) noexcept final
    {
        try
        {
            *modelNumber = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ModelNumber, WINRT_WRAP(hstring));
            *modelNumber = detach_from<hstring>(this->shim().ModelNumber());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Media::Protection::PlayReady::IPlayReadyContentHeader> : produce_base<D, Windows::Media::Protection::PlayReady::IPlayReadyContentHeader>
{
    int32_t WINRT_CALL get_KeyId(winrt::guid* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(KeyId, WINRT_WRAP(winrt::guid));
            *value = detach_from<winrt::guid>(this->shim().KeyId());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_KeyIdString(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(KeyIdString, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().KeyIdString());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_LicenseAcquisitionUrl(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(LicenseAcquisitionUrl, WINRT_WRAP(Windows::Foundation::Uri));
            *value = detach_from<Windows::Foundation::Uri>(this->shim().LicenseAcquisitionUrl());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_LicenseAcquisitionUserInterfaceUrl(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(LicenseAcquisitionUserInterfaceUrl, WINRT_WRAP(Windows::Foundation::Uri));
            *value = detach_from<Windows::Foundation::Uri>(this->shim().LicenseAcquisitionUserInterfaceUrl());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_DomainServiceId(winrt::guid* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(DomainServiceId, WINRT_WRAP(winrt::guid));
            *value = detach_from<winrt::guid>(this->shim().DomainServiceId());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_EncryptionType(Windows::Media::Protection::PlayReady::PlayReadyEncryptionAlgorithm* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(EncryptionType, WINRT_WRAP(Windows::Media::Protection::PlayReady::PlayReadyEncryptionAlgorithm));
            *value = detach_from<Windows::Media::Protection::PlayReady::PlayReadyEncryptionAlgorithm>(this->shim().EncryptionType());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_CustomAttributes(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CustomAttributes, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().CustomAttributes());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_DecryptorSetup(Windows::Media::Protection::PlayReady::PlayReadyDecryptorSetup* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(DecryptorSetup, WINRT_WRAP(Windows::Media::Protection::PlayReady::PlayReadyDecryptorSetup));
            *value = detach_from<Windows::Media::Protection::PlayReady::PlayReadyDecryptorSetup>(this->shim().DecryptorSetup());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL GetSerializedHeader(uint32_t* __headerBytesSize, uint8_t** headerBytes) noexcept final
    {
        try
        {
            *__headerBytesSize = 0;
            *headerBytes = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetSerializedHeader, WINRT_WRAP(com_array<uint8_t>));
            std::tie(*__headerBytesSize, *headerBytes) = detach_abi(this->shim().GetSerializedHeader());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_HeaderWithEmbeddedUpdates(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(HeaderWithEmbeddedUpdates, WINRT_WRAP(Windows::Media::Protection::PlayReady::PlayReadyContentHeader));
            *value = detach_from<Windows::Media::Protection::PlayReady::PlayReadyContentHeader>(this->shim().HeaderWithEmbeddedUpdates());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Media::Protection::PlayReady::IPlayReadyContentHeader2> : produce_base<D, Windows::Media::Protection::PlayReady::IPlayReadyContentHeader2>
{
    int32_t WINRT_CALL get_KeyIds(uint32_t* __contentKeyIdsSize, winrt::guid** contentKeyIds) noexcept final
    {
        try
        {
            *__contentKeyIdsSize = 0;
            *contentKeyIds = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(KeyIds, WINRT_WRAP(com_array<winrt::guid>));
            std::tie(*__contentKeyIdsSize, *contentKeyIds) = detach_abi(this->shim().KeyIds());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_KeyIdStrings(uint32_t* __contentKeyIdStringsSize, void*** contentKeyIdStrings) noexcept final
    {
        try
        {
            *__contentKeyIdStringsSize = 0;
            *contentKeyIdStrings = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(KeyIdStrings, WINRT_WRAP(com_array<hstring>));
            std::tie(*__contentKeyIdStringsSize, *contentKeyIdStrings) = detach_abi(this->shim().KeyIdStrings());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Media::Protection::PlayReady::IPlayReadyContentHeaderFactory> : produce_base<D, Windows::Media::Protection::PlayReady::IPlayReadyContentHeaderFactory>
{
    int32_t WINRT_CALL CreateInstanceFromWindowsMediaDrmHeader(uint32_t __headerBytesSize, uint8_t* headerBytes, void* licenseAcquisitionUrl, void* licenseAcquisitionUserInterfaceUrl, void* customAttributes, winrt::guid domainServiceId, void** instance) noexcept final
    {
        try
        {
            *instance = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CreateInstanceFromWindowsMediaDrmHeader, WINRT_WRAP(Windows::Media::Protection::PlayReady::PlayReadyContentHeader), array_view<uint8_t const>, Windows::Foundation::Uri const&, Windows::Foundation::Uri const&, hstring const&, winrt::guid const&);
            *instance = detach_from<Windows::Media::Protection::PlayReady::PlayReadyContentHeader>(this->shim().CreateInstanceFromWindowsMediaDrmHeader(array_view<uint8_t const>(reinterpret_cast<uint8_t const *>(headerBytes), reinterpret_cast<uint8_t const *>(headerBytes) + __headerBytesSize), *reinterpret_cast<Windows::Foundation::Uri const*>(&licenseAcquisitionUrl), *reinterpret_cast<Windows::Foundation::Uri const*>(&licenseAcquisitionUserInterfaceUrl), *reinterpret_cast<hstring const*>(&customAttributes), *reinterpret_cast<winrt::guid const*>(&domainServiceId)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL CreateInstanceFromComponents(winrt::guid contentKeyId, void* contentKeyIdString, Windows::Media::Protection::PlayReady::PlayReadyEncryptionAlgorithm contentEncryptionAlgorithm, void* licenseAcquisitionUrl, void* licenseAcquisitionUserInterfaceUrl, void* customAttributes, winrt::guid domainServiceId, void** instance) noexcept final
    {
        try
        {
            *instance = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CreateInstanceFromComponents, WINRT_WRAP(Windows::Media::Protection::PlayReady::PlayReadyContentHeader), winrt::guid const&, hstring const&, Windows::Media::Protection::PlayReady::PlayReadyEncryptionAlgorithm const&, Windows::Foundation::Uri const&, Windows::Foundation::Uri const&, hstring const&, winrt::guid const&);
            *instance = detach_from<Windows::Media::Protection::PlayReady::PlayReadyContentHeader>(this->shim().CreateInstanceFromComponents(*reinterpret_cast<winrt::guid const*>(&contentKeyId), *reinterpret_cast<hstring const*>(&contentKeyIdString), *reinterpret_cast<Windows::Media::Protection::PlayReady::PlayReadyEncryptionAlgorithm const*>(&contentEncryptionAlgorithm), *reinterpret_cast<Windows::Foundation::Uri const*>(&licenseAcquisitionUrl), *reinterpret_cast<Windows::Foundation::Uri const*>(&licenseAcquisitionUserInterfaceUrl), *reinterpret_cast<hstring const*>(&customAttributes), *reinterpret_cast<winrt::guid const*>(&domainServiceId)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL CreateInstanceFromPlayReadyHeader(uint32_t __headerBytesSize, uint8_t* headerBytes, void** instance) noexcept final
    {
        try
        {
            *instance = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CreateInstanceFromPlayReadyHeader, WINRT_WRAP(Windows::Media::Protection::PlayReady::PlayReadyContentHeader), array_view<uint8_t const>);
            *instance = detach_from<Windows::Media::Protection::PlayReady::PlayReadyContentHeader>(this->shim().CreateInstanceFromPlayReadyHeader(array_view<uint8_t const>(reinterpret_cast<uint8_t const *>(headerBytes), reinterpret_cast<uint8_t const *>(headerBytes) + __headerBytesSize)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Media::Protection::PlayReady::IPlayReadyContentHeaderFactory2> : produce_base<D, Windows::Media::Protection::PlayReady::IPlayReadyContentHeaderFactory2>
{
    int32_t WINRT_CALL CreateInstanceFromComponents2(uint32_t dwFlags, uint32_t __contentKeyIdsSize, winrt::guid* contentKeyIds, uint32_t __contentKeyIdStringsSize, void** contentKeyIdStrings, Windows::Media::Protection::PlayReady::PlayReadyEncryptionAlgorithm contentEncryptionAlgorithm, void* licenseAcquisitionUrl, void* licenseAcquisitionUserInterfaceUrl, void* customAttributes, winrt::guid domainServiceId, void** instance) noexcept final
    {
        try
        {
            *instance = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CreateInstanceFromComponents2, WINRT_WRAP(Windows::Media::Protection::PlayReady::PlayReadyContentHeader), uint32_t, array_view<winrt::guid const>, array_view<hstring const>, Windows::Media::Protection::PlayReady::PlayReadyEncryptionAlgorithm const&, Windows::Foundation::Uri const&, Windows::Foundation::Uri const&, hstring const&, winrt::guid const&);
            *instance = detach_from<Windows::Media::Protection::PlayReady::PlayReadyContentHeader>(this->shim().CreateInstanceFromComponents2(dwFlags, array_view<winrt::guid const>(reinterpret_cast<winrt::guid const *>(contentKeyIds), reinterpret_cast<winrt::guid const *>(contentKeyIds) + __contentKeyIdsSize), array_view<hstring const>(reinterpret_cast<hstring const *>(contentKeyIdStrings), reinterpret_cast<hstring const *>(contentKeyIdStrings) + __contentKeyIdStringsSize), *reinterpret_cast<Windows::Media::Protection::PlayReady::PlayReadyEncryptionAlgorithm const*>(&contentEncryptionAlgorithm), *reinterpret_cast<Windows::Foundation::Uri const*>(&licenseAcquisitionUrl), *reinterpret_cast<Windows::Foundation::Uri const*>(&licenseAcquisitionUserInterfaceUrl), *reinterpret_cast<hstring const*>(&customAttributes), *reinterpret_cast<winrt::guid const*>(&domainServiceId)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Media::Protection::PlayReady::IPlayReadyContentResolver> : produce_base<D, Windows::Media::Protection::PlayReady::IPlayReadyContentResolver>
{
    int32_t WINRT_CALL ServiceRequest(void* contentHeader, void** serviceRequest) noexcept final
    {
        try
        {
            *serviceRequest = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ServiceRequest, WINRT_WRAP(Windows::Media::Protection::PlayReady::IPlayReadyServiceRequest), Windows::Media::Protection::PlayReady::PlayReadyContentHeader const&);
            *serviceRequest = detach_from<Windows::Media::Protection::PlayReady::IPlayReadyServiceRequest>(this->shim().ServiceRequest(*reinterpret_cast<Windows::Media::Protection::PlayReady::PlayReadyContentHeader const*>(&contentHeader)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Media::Protection::PlayReady::IPlayReadyDomain> : produce_base<D, Windows::Media::Protection::PlayReady::IPlayReadyDomain>
{
    int32_t WINRT_CALL get_AccountId(winrt::guid* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(AccountId, WINRT_WRAP(winrt::guid));
            *value = detach_from<winrt::guid>(this->shim().AccountId());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_ServiceId(winrt::guid* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ServiceId, WINRT_WRAP(winrt::guid));
            *value = detach_from<winrt::guid>(this->shim().ServiceId());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Revision(uint32_t* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Revision, WINRT_WRAP(uint32_t));
            *value = detach_from<uint32_t>(this->shim().Revision());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_FriendlyName(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(FriendlyName, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().FriendlyName());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_DomainJoinUrl(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(DomainJoinUrl, WINRT_WRAP(Windows::Foundation::Uri));
            *value = detach_from<Windows::Foundation::Uri>(this->shim().DomainJoinUrl());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Media::Protection::PlayReady::IPlayReadyDomainIterableFactory> : produce_base<D, Windows::Media::Protection::PlayReady::IPlayReadyDomainIterableFactory>
{
    int32_t WINRT_CALL CreateInstance(winrt::guid domainAccountId, void** domainIterable) noexcept final
    {
        try
        {
            *domainIterable = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CreateInstance, WINRT_WRAP(Windows::Media::Protection::PlayReady::PlayReadyDomainIterable), winrt::guid const&);
            *domainIterable = detach_from<Windows::Media::Protection::PlayReady::PlayReadyDomainIterable>(this->shim().CreateInstance(*reinterpret_cast<winrt::guid const*>(&domainAccountId)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Media::Protection::PlayReady::IPlayReadyDomainJoinServiceRequest> : produce_base<D, Windows::Media::Protection::PlayReady::IPlayReadyDomainJoinServiceRequest>
{
    int32_t WINRT_CALL get_DomainAccountId(winrt::guid* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(DomainAccountId, WINRT_WRAP(winrt::guid));
            *value = detach_from<winrt::guid>(this->shim().DomainAccountId());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_DomainAccountId(winrt::guid value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(DomainAccountId, WINRT_WRAP(void), winrt::guid const&);
            this->shim().DomainAccountId(*reinterpret_cast<winrt::guid const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_DomainFriendlyName(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(DomainFriendlyName, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().DomainFriendlyName());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_DomainFriendlyName(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(DomainFriendlyName, WINRT_WRAP(void), hstring const&);
            this->shim().DomainFriendlyName(*reinterpret_cast<hstring const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_DomainServiceId(winrt::guid* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(DomainServiceId, WINRT_WRAP(winrt::guid));
            *value = detach_from<winrt::guid>(this->shim().DomainServiceId());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_DomainServiceId(winrt::guid value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(DomainServiceId, WINRT_WRAP(void), winrt::guid const&);
            this->shim().DomainServiceId(*reinterpret_cast<winrt::guid const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Media::Protection::PlayReady::IPlayReadyDomainLeaveServiceRequest> : produce_base<D, Windows::Media::Protection::PlayReady::IPlayReadyDomainLeaveServiceRequest>
{
    int32_t WINRT_CALL get_DomainAccountId(winrt::guid* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(DomainAccountId, WINRT_WRAP(winrt::guid));
            *value = detach_from<winrt::guid>(this->shim().DomainAccountId());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_DomainAccountId(winrt::guid value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(DomainAccountId, WINRT_WRAP(void), winrt::guid const&);
            this->shim().DomainAccountId(*reinterpret_cast<winrt::guid const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_DomainServiceId(winrt::guid* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(DomainServiceId, WINRT_WRAP(winrt::guid));
            *value = detach_from<winrt::guid>(this->shim().DomainServiceId());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_DomainServiceId(winrt::guid value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(DomainServiceId, WINRT_WRAP(void), winrt::guid const&);
            this->shim().DomainServiceId(*reinterpret_cast<winrt::guid const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Media::Protection::PlayReady::IPlayReadyITADataGenerator> : produce_base<D, Windows::Media::Protection::PlayReady::IPlayReadyITADataGenerator>
{
    int32_t WINRT_CALL GenerateData(winrt::guid guidCPSystemId, uint32_t countOfStreams, void* configuration, Windows::Media::Protection::PlayReady::PlayReadyITADataFormat format, uint32_t* __dataBytesSize, uint8_t** dataBytes) noexcept final
    {
        try
        {
            *__dataBytesSize = 0;
            *dataBytes = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GenerateData, WINRT_WRAP(com_array<uint8_t>), winrt::guid const&, uint32_t, Windows::Foundation::Collections::IPropertySet const&, Windows::Media::Protection::PlayReady::PlayReadyITADataFormat const&);
            std::tie(*__dataBytesSize, *dataBytes) = detach_abi(this->shim().GenerateData(*reinterpret_cast<winrt::guid const*>(&guidCPSystemId), countOfStreams, *reinterpret_cast<Windows::Foundation::Collections::IPropertySet const*>(&configuration), *reinterpret_cast<Windows::Media::Protection::PlayReady::PlayReadyITADataFormat const*>(&format)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Media::Protection::PlayReady::IPlayReadyIndividualizationServiceRequest> : produce_base<D, Windows::Media::Protection::PlayReady::IPlayReadyIndividualizationServiceRequest>
{};

template <typename D>
struct produce<D, Windows::Media::Protection::PlayReady::IPlayReadyLicense> : produce_base<D, Windows::Media::Protection::PlayReady::IPlayReadyLicense>
{
    int32_t WINRT_CALL get_FullyEvaluated(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(FullyEvaluated, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().FullyEvaluated());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_UsableForPlay(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(UsableForPlay, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().UsableForPlay());
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

    int32_t WINRT_CALL get_ExpireAfterFirstPlay(uint32_t* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ExpireAfterFirstPlay, WINRT_WRAP(uint32_t));
            *value = detach_from<uint32_t>(this->shim().ExpireAfterFirstPlay());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_DomainAccountID(winrt::guid* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(DomainAccountID, WINRT_WRAP(winrt::guid));
            *value = detach_from<winrt::guid>(this->shim().DomainAccountID());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_ChainDepth(uint32_t* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ChainDepth, WINRT_WRAP(uint32_t));
            *value = detach_from<uint32_t>(this->shim().ChainDepth());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL GetKIDAtChainDepth(uint32_t chainDepth, winrt::guid* kid) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetKIDAtChainDepth, WINRT_WRAP(winrt::guid), uint32_t);
            *kid = detach_from<winrt::guid>(this->shim().GetKIDAtChainDepth(chainDepth));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Media::Protection::PlayReady::IPlayReadyLicense2> : produce_base<D, Windows::Media::Protection::PlayReady::IPlayReadyLicense2>
{
    int32_t WINRT_CALL get_SecureStopId(winrt::guid* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SecureStopId, WINRT_WRAP(winrt::guid));
            *value = detach_from<winrt::guid>(this->shim().SecureStopId());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_SecurityLevel(uint32_t* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SecurityLevel, WINRT_WRAP(uint32_t));
            *value = detach_from<uint32_t>(this->shim().SecurityLevel());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_InMemoryOnly(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(InMemoryOnly, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().InMemoryOnly());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_ExpiresInRealTime(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ExpiresInRealTime, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().ExpiresInRealTime());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Media::Protection::PlayReady::IPlayReadyLicenseAcquisitionServiceRequest> : produce_base<D, Windows::Media::Protection::PlayReady::IPlayReadyLicenseAcquisitionServiceRequest>
{
    int32_t WINRT_CALL get_ContentHeader(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ContentHeader, WINRT_WRAP(Windows::Media::Protection::PlayReady::PlayReadyContentHeader));
            *value = detach_from<Windows::Media::Protection::PlayReady::PlayReadyContentHeader>(this->shim().ContentHeader());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_ContentHeader(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ContentHeader, WINRT_WRAP(void), Windows::Media::Protection::PlayReady::PlayReadyContentHeader const&);
            this->shim().ContentHeader(*reinterpret_cast<Windows::Media::Protection::PlayReady::PlayReadyContentHeader const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_DomainServiceId(winrt::guid* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(DomainServiceId, WINRT_WRAP(winrt::guid));
            *value = detach_from<winrt::guid>(this->shim().DomainServiceId());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_DomainServiceId(winrt::guid value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(DomainServiceId, WINRT_WRAP(void), winrt::guid const&);
            this->shim().DomainServiceId(*reinterpret_cast<winrt::guid const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Media::Protection::PlayReady::IPlayReadyLicenseAcquisitionServiceRequest2> : produce_base<D, Windows::Media::Protection::PlayReady::IPlayReadyLicenseAcquisitionServiceRequest2>
{
    int32_t WINRT_CALL get_SessionId(winrt::guid* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SessionId, WINRT_WRAP(winrt::guid));
            *value = detach_from<winrt::guid>(this->shim().SessionId());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Media::Protection::PlayReady::IPlayReadyLicenseAcquisitionServiceRequest3> : produce_base<D, Windows::Media::Protection::PlayReady::IPlayReadyLicenseAcquisitionServiceRequest3>
{
    int32_t WINRT_CALL CreateLicenseIterable(void* contentHeader, bool fullyEvaluated, void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CreateLicenseIterable, WINRT_WRAP(Windows::Media::Protection::PlayReady::PlayReadyLicenseIterable), Windows::Media::Protection::PlayReady::PlayReadyContentHeader const&, bool);
            *result = detach_from<Windows::Media::Protection::PlayReady::PlayReadyLicenseIterable>(this->shim().CreateLicenseIterable(*reinterpret_cast<Windows::Media::Protection::PlayReady::PlayReadyContentHeader const*>(&contentHeader), fullyEvaluated));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Media::Protection::PlayReady::IPlayReadyLicenseIterableFactory> : produce_base<D, Windows::Media::Protection::PlayReady::IPlayReadyLicenseIterableFactory>
{
    int32_t WINRT_CALL CreateInstance(void* contentHeader, bool fullyEvaluated, void** instance) noexcept final
    {
        try
        {
            *instance = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CreateInstance, WINRT_WRAP(Windows::Media::Protection::PlayReady::PlayReadyLicenseIterable), Windows::Media::Protection::PlayReady::PlayReadyContentHeader const&, bool);
            *instance = detach_from<Windows::Media::Protection::PlayReady::PlayReadyLicenseIterable>(this->shim().CreateInstance(*reinterpret_cast<Windows::Media::Protection::PlayReady::PlayReadyContentHeader const*>(&contentHeader), fullyEvaluated));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Media::Protection::PlayReady::IPlayReadyLicenseManagement> : produce_base<D, Windows::Media::Protection::PlayReady::IPlayReadyLicenseManagement>
{
    int32_t WINRT_CALL DeleteLicenses(void* contentHeader, void** operation) noexcept final
    {
        try
        {
            *operation = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(DeleteLicenses, WINRT_WRAP(Windows::Foundation::IAsyncAction), Windows::Media::Protection::PlayReady::PlayReadyContentHeader const&);
            *operation = detach_from<Windows::Foundation::IAsyncAction>(this->shim().DeleteLicenses(*reinterpret_cast<Windows::Media::Protection::PlayReady::PlayReadyContentHeader const*>(&contentHeader)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Media::Protection::PlayReady::IPlayReadyLicenseSession> : produce_base<D, Windows::Media::Protection::PlayReady::IPlayReadyLicenseSession>
{
    int32_t WINRT_CALL CreateLAServiceRequest(void** serviceRequest) noexcept final
    {
        try
        {
            *serviceRequest = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CreateLAServiceRequest, WINRT_WRAP(Windows::Media::Protection::PlayReady::IPlayReadyLicenseAcquisitionServiceRequest));
            *serviceRequest = detach_from<Windows::Media::Protection::PlayReady::IPlayReadyLicenseAcquisitionServiceRequest>(this->shim().CreateLAServiceRequest());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL ConfigureMediaProtectionManager(void* mpm) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ConfigureMediaProtectionManager, WINRT_WRAP(void), Windows::Media::Protection::MediaProtectionManager const&);
            this->shim().ConfigureMediaProtectionManager(*reinterpret_cast<Windows::Media::Protection::MediaProtectionManager const*>(&mpm));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Media::Protection::PlayReady::IPlayReadyLicenseSession2> : produce_base<D, Windows::Media::Protection::PlayReady::IPlayReadyLicenseSession2>
{
    int32_t WINRT_CALL CreateLicenseIterable(void* contentHeader, bool fullyEvaluated, void** licenseIterable) noexcept final
    {
        try
        {
            *licenseIterable = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CreateLicenseIterable, WINRT_WRAP(Windows::Media::Protection::PlayReady::PlayReadyLicenseIterable), Windows::Media::Protection::PlayReady::PlayReadyContentHeader const&, bool);
            *licenseIterable = detach_from<Windows::Media::Protection::PlayReady::PlayReadyLicenseIterable>(this->shim().CreateLicenseIterable(*reinterpret_cast<Windows::Media::Protection::PlayReady::PlayReadyContentHeader const*>(&contentHeader), fullyEvaluated));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Media::Protection::PlayReady::IPlayReadyLicenseSessionFactory> : produce_base<D, Windows::Media::Protection::PlayReady::IPlayReadyLicenseSessionFactory>
{
    int32_t WINRT_CALL CreateInstance(void* configuration, void** instance) noexcept final
    {
        try
        {
            *instance = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CreateInstance, WINRT_WRAP(Windows::Media::Protection::PlayReady::PlayReadyLicenseSession), Windows::Foundation::Collections::IPropertySet const&);
            *instance = detach_from<Windows::Media::Protection::PlayReady::PlayReadyLicenseSession>(this->shim().CreateInstance(*reinterpret_cast<Windows::Foundation::Collections::IPropertySet const*>(&configuration)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Media::Protection::PlayReady::IPlayReadyMeteringReportServiceRequest> : produce_base<D, Windows::Media::Protection::PlayReady::IPlayReadyMeteringReportServiceRequest>
{
    int32_t WINRT_CALL get_MeteringCertificate(uint32_t* __meteringCertBytesSize, uint8_t** meteringCertBytes) noexcept final
    {
        try
        {
            *__meteringCertBytesSize = 0;
            *meteringCertBytes = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(MeteringCertificate, WINRT_WRAP(com_array<uint8_t>));
            std::tie(*__meteringCertBytesSize, *meteringCertBytes) = detach_abi(this->shim().MeteringCertificate());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_MeteringCertificate(uint32_t __meteringCertBytesSize, uint8_t* meteringCertBytes) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(MeteringCertificate, WINRT_WRAP(void), array_view<uint8_t const>);
            this->shim().MeteringCertificate(array_view<uint8_t const>(reinterpret_cast<uint8_t const *>(meteringCertBytes), reinterpret_cast<uint8_t const *>(meteringCertBytes) + __meteringCertBytesSize));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Media::Protection::PlayReady::IPlayReadyRevocationServiceRequest> : produce_base<D, Windows::Media::Protection::PlayReady::IPlayReadyRevocationServiceRequest>
{};

template <typename D>
struct produce<D, Windows::Media::Protection::PlayReady::IPlayReadySecureStopIterableFactory> : produce_base<D, Windows::Media::Protection::PlayReady::IPlayReadySecureStopIterableFactory>
{
    int32_t WINRT_CALL CreateInstance(uint32_t __publisherCertBytesSize, uint8_t* publisherCertBytes, void** instance) noexcept final
    {
        try
        {
            *instance = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CreateInstance, WINRT_WRAP(Windows::Media::Protection::PlayReady::PlayReadySecureStopIterable), array_view<uint8_t const>);
            *instance = detach_from<Windows::Media::Protection::PlayReady::PlayReadySecureStopIterable>(this->shim().CreateInstance(array_view<uint8_t const>(reinterpret_cast<uint8_t const *>(publisherCertBytes), reinterpret_cast<uint8_t const *>(publisherCertBytes) + __publisherCertBytesSize)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Media::Protection::PlayReady::IPlayReadySecureStopServiceRequest> : produce_base<D, Windows::Media::Protection::PlayReady::IPlayReadySecureStopServiceRequest>
{
    int32_t WINRT_CALL get_SessionID(winrt::guid* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SessionID, WINRT_WRAP(winrt::guid));
            *value = detach_from<winrt::guid>(this->shim().SessionID());
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

    int32_t WINRT_CALL get_UpdateTime(Windows::Foundation::DateTime* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(UpdateTime, WINRT_WRAP(Windows::Foundation::DateTime));
            *value = detach_from<Windows::Foundation::DateTime>(this->shim().UpdateTime());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Stopped(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Stopped, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().Stopped());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_PublisherCertificate(uint32_t* __publisherCertBytesSize, uint8_t** publisherCertBytes) noexcept final
    {
        try
        {
            *__publisherCertBytesSize = 0;
            *publisherCertBytes = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(PublisherCertificate, WINRT_WRAP(com_array<uint8_t>));
            std::tie(*__publisherCertBytesSize, *publisherCertBytes) = detach_abi(this->shim().PublisherCertificate());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Media::Protection::PlayReady::IPlayReadySecureStopServiceRequestFactory> : produce_base<D, Windows::Media::Protection::PlayReady::IPlayReadySecureStopServiceRequestFactory>
{
    int32_t WINRT_CALL CreateInstance(uint32_t __publisherCertBytesSize, uint8_t* publisherCertBytes, void** instance) noexcept final
    {
        try
        {
            *instance = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CreateInstance, WINRT_WRAP(Windows::Media::Protection::PlayReady::PlayReadySecureStopServiceRequest), array_view<uint8_t const>);
            *instance = detach_from<Windows::Media::Protection::PlayReady::PlayReadySecureStopServiceRequest>(this->shim().CreateInstance(array_view<uint8_t const>(reinterpret_cast<uint8_t const *>(publisherCertBytes), reinterpret_cast<uint8_t const *>(publisherCertBytes) + __publisherCertBytesSize)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL CreateInstanceFromSessionID(winrt::guid sessionID, uint32_t __publisherCertBytesSize, uint8_t* publisherCertBytes, void** instance) noexcept final
    {
        try
        {
            *instance = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CreateInstanceFromSessionID, WINRT_WRAP(Windows::Media::Protection::PlayReady::PlayReadySecureStopServiceRequest), winrt::guid const&, array_view<uint8_t const>);
            *instance = detach_from<Windows::Media::Protection::PlayReady::PlayReadySecureStopServiceRequest>(this->shim().CreateInstanceFromSessionID(*reinterpret_cast<winrt::guid const*>(&sessionID), array_view<uint8_t const>(reinterpret_cast<uint8_t const *>(publisherCertBytes), reinterpret_cast<uint8_t const *>(publisherCertBytes) + __publisherCertBytesSize)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Media::Protection::PlayReady::IPlayReadyServiceRequest> : produce_base<D, Windows::Media::Protection::PlayReady::IPlayReadyServiceRequest>
{
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

    int32_t WINRT_CALL put_Uri(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Uri, WINRT_WRAP(void), Windows::Foundation::Uri const&);
            this->shim().Uri(*reinterpret_cast<Windows::Foundation::Uri const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_ResponseCustomData(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ResponseCustomData, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().ResponseCustomData());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_ChallengeCustomData(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ChallengeCustomData, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().ChallengeCustomData());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_ChallengeCustomData(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ChallengeCustomData, WINRT_WRAP(void), hstring const&);
            this->shim().ChallengeCustomData(*reinterpret_cast<hstring const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL BeginServiceRequest(void** action) noexcept final
    {
        try
        {
            *action = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(BeginServiceRequest, WINRT_WRAP(Windows::Foundation::IAsyncAction));
            *action = detach_from<Windows::Foundation::IAsyncAction>(this->shim().BeginServiceRequest());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL NextServiceRequest(void** serviceRequest) noexcept final
    {
        try
        {
            *serviceRequest = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(NextServiceRequest, WINRT_WRAP(Windows::Media::Protection::PlayReady::IPlayReadyServiceRequest));
            *serviceRequest = detach_from<Windows::Media::Protection::PlayReady::IPlayReadyServiceRequest>(this->shim().NextServiceRequest());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL GenerateManualEnablingChallenge(void** challengeMessage) noexcept final
    {
        try
        {
            *challengeMessage = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GenerateManualEnablingChallenge, WINRT_WRAP(Windows::Media::Protection::PlayReady::PlayReadySoapMessage));
            *challengeMessage = detach_from<Windows::Media::Protection::PlayReady::PlayReadySoapMessage>(this->shim().GenerateManualEnablingChallenge());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL ProcessManualEnablingResponse(uint32_t __responseBytesSize, uint8_t* responseBytes, winrt::hresult* result) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ProcessManualEnablingResponse, WINRT_WRAP(winrt::hresult), array_view<uint8_t const>);
            *result = detach_from<winrt::hresult>(this->shim().ProcessManualEnablingResponse(array_view<uint8_t const>(reinterpret_cast<uint8_t const *>(responseBytes), reinterpret_cast<uint8_t const *>(responseBytes) + __responseBytesSize)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Media::Protection::PlayReady::IPlayReadySoapMessage> : produce_base<D, Windows::Media::Protection::PlayReady::IPlayReadySoapMessage>
{
    int32_t WINRT_CALL GetMessageBody(uint32_t* __messageBodyBytesSize, uint8_t** messageBodyBytes) noexcept final
    {
        try
        {
            *__messageBodyBytesSize = 0;
            *messageBodyBytes = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetMessageBody, WINRT_WRAP(com_array<uint8_t>));
            std::tie(*__messageBodyBytesSize, *messageBodyBytes) = detach_abi(this->shim().GetMessageBody());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_MessageHeaders(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(MessageHeaders, WINRT_WRAP(Windows::Foundation::Collections::IPropertySet));
            *value = detach_from<Windows::Foundation::Collections::IPropertySet>(this->shim().MessageHeaders());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Uri(void** messageUri) noexcept final
    {
        try
        {
            *messageUri = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Uri, WINRT_WRAP(Windows::Foundation::Uri));
            *messageUri = detach_from<Windows::Foundation::Uri>(this->shim().Uri());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Media::Protection::PlayReady::IPlayReadyStatics> : produce_base<D, Windows::Media::Protection::PlayReady::IPlayReadyStatics>
{
    int32_t WINRT_CALL get_DomainJoinServiceRequestType(winrt::guid* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(DomainJoinServiceRequestType, WINRT_WRAP(winrt::guid));
            *value = detach_from<winrt::guid>(this->shim().DomainJoinServiceRequestType());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_DomainLeaveServiceRequestType(winrt::guid* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(DomainLeaveServiceRequestType, WINRT_WRAP(winrt::guid));
            *value = detach_from<winrt::guid>(this->shim().DomainLeaveServiceRequestType());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_IndividualizationServiceRequestType(winrt::guid* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IndividualizationServiceRequestType, WINRT_WRAP(winrt::guid));
            *value = detach_from<winrt::guid>(this->shim().IndividualizationServiceRequestType());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_LicenseAcquirerServiceRequestType(winrt::guid* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(LicenseAcquirerServiceRequestType, WINRT_WRAP(winrt::guid));
            *value = detach_from<winrt::guid>(this->shim().LicenseAcquirerServiceRequestType());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_MeteringReportServiceRequestType(winrt::guid* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(MeteringReportServiceRequestType, WINRT_WRAP(winrt::guid));
            *value = detach_from<winrt::guid>(this->shim().MeteringReportServiceRequestType());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_RevocationServiceRequestType(winrt::guid* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(RevocationServiceRequestType, WINRT_WRAP(winrt::guid));
            *value = detach_from<winrt::guid>(this->shim().RevocationServiceRequestType());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_MediaProtectionSystemId(winrt::guid* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(MediaProtectionSystemId, WINRT_WRAP(winrt::guid));
            *value = detach_from<winrt::guid>(this->shim().MediaProtectionSystemId());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_PlayReadySecurityVersion(uint32_t* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(PlayReadySecurityVersion, WINRT_WRAP(uint32_t));
            *value = detach_from<uint32_t>(this->shim().PlayReadySecurityVersion());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Media::Protection::PlayReady::IPlayReadyStatics2> : produce_base<D, Windows::Media::Protection::PlayReady::IPlayReadyStatics2>
{
    int32_t WINRT_CALL get_PlayReadyCertificateSecurityLevel(uint32_t* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(PlayReadyCertificateSecurityLevel, WINRT_WRAP(uint32_t));
            *value = detach_from<uint32_t>(this->shim().PlayReadyCertificateSecurityLevel());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Media::Protection::PlayReady::IPlayReadyStatics3> : produce_base<D, Windows::Media::Protection::PlayReady::IPlayReadyStatics3>
{
    int32_t WINRT_CALL get_SecureStopServiceRequestType(winrt::guid* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SecureStopServiceRequestType, WINRT_WRAP(winrt::guid));
            *value = detach_from<winrt::guid>(this->shim().SecureStopServiceRequestType());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL CheckSupportedHardware(Windows::Media::Protection::PlayReady::PlayReadyHardwareDRMFeatures hwdrmFeature, bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CheckSupportedHardware, WINRT_WRAP(bool), Windows::Media::Protection::PlayReady::PlayReadyHardwareDRMFeatures const&);
            *value = detach_from<bool>(this->shim().CheckSupportedHardware(*reinterpret_cast<Windows::Media::Protection::PlayReady::PlayReadyHardwareDRMFeatures const*>(&hwdrmFeature)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Media::Protection::PlayReady::IPlayReadyStatics4> : produce_base<D, Windows::Media::Protection::PlayReady::IPlayReadyStatics4>
{
    int32_t WINRT_CALL get_InputTrustAuthorityToCreate(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(InputTrustAuthorityToCreate, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().InputTrustAuthorityToCreate());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_ProtectionSystemId(winrt::guid* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ProtectionSystemId, WINRT_WRAP(winrt::guid));
            *value = detach_from<winrt::guid>(this->shim().ProtectionSystemId());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Media::Protection::PlayReady::IPlayReadyStatics5> : produce_base<D, Windows::Media::Protection::PlayReady::IPlayReadyStatics5>
{
    int32_t WINRT_CALL get_HardwareDRMDisabledAtTime(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(HardwareDRMDisabledAtTime, WINRT_WRAP(Windows::Foundation::IReference<Windows::Foundation::DateTime>));
            *value = detach_from<Windows::Foundation::IReference<Windows::Foundation::DateTime>>(this->shim().HardwareDRMDisabledAtTime());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_HardwareDRMDisabledUntilTime(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(HardwareDRMDisabledUntilTime, WINRT_WRAP(Windows::Foundation::IReference<Windows::Foundation::DateTime>));
            *value = detach_from<Windows::Foundation::IReference<Windows::Foundation::DateTime>>(this->shim().HardwareDRMDisabledUntilTime());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL ResetHardwareDRMDisabled() noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ResetHardwareDRMDisabled, WINRT_WRAP(void));
            this->shim().ResetHardwareDRMDisabled();
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

}

WINRT_EXPORT namespace winrt::Windows::Media::Protection::PlayReady {

inline NDClient::NDClient(Windows::Media::Protection::PlayReady::INDDownloadEngine const& downloadEngine, Windows::Media::Protection::PlayReady::INDStreamParser const& streamParser, Windows::Media::Protection::PlayReady::INDMessenger const& pMessenger) :
    NDClient(impl::call_factory<NDClient, Windows::Media::Protection::PlayReady::INDClientFactory>([&](auto&& f) { return f.CreateInstance(downloadEngine, streamParser, pMessenger); }))
{}

inline NDCustomData::NDCustomData(array_view<uint8_t const> customDataTypeIDBytes, array_view<uint8_t const> customDataBytes) :
    NDCustomData(impl::call_factory<NDCustomData, Windows::Media::Protection::PlayReady::INDCustomDataFactory>([&](auto&& f) { return f.CreateInstance(customDataTypeIDBytes, customDataBytes); }))
{}

inline NDDownloadEngineNotifier::NDDownloadEngineNotifier() :
    NDDownloadEngineNotifier(impl::call_factory<NDDownloadEngineNotifier>([](auto&& f) { return f.template ActivateInstance<NDDownloadEngineNotifier>(); }))
{}

inline NDLicenseFetchDescriptor::NDLicenseFetchDescriptor(Windows::Media::Protection::PlayReady::NDContentIDType const& contentIDType, array_view<uint8_t const> contentIDBytes, Windows::Media::Protection::PlayReady::INDCustomData const& licenseFetchChallengeCustomData) :
    NDLicenseFetchDescriptor(impl::call_factory<NDLicenseFetchDescriptor, Windows::Media::Protection::PlayReady::INDLicenseFetchDescriptorFactory>([&](auto&& f) { return f.CreateInstance(contentIDType, contentIDBytes, licenseFetchChallengeCustomData); }))
{}

inline NDStorageFileHelper::NDStorageFileHelper() :
    NDStorageFileHelper(impl::call_factory<NDStorageFileHelper>([](auto&& f) { return f.template ActivateInstance<NDStorageFileHelper>(); }))
{}

inline NDStreamParserNotifier::NDStreamParserNotifier() :
    NDStreamParserNotifier(impl::call_factory<NDStreamParserNotifier>([](auto&& f) { return f.template ActivateInstance<NDStreamParserNotifier>(); }))
{}

inline NDTCPMessenger::NDTCPMessenger(param::hstring const& remoteHostName, uint32_t remoteHostPort) :
    NDTCPMessenger(impl::call_factory<NDTCPMessenger, Windows::Media::Protection::PlayReady::INDTCPMessengerFactory>([&](auto&& f) { return f.CreateInstance(remoteHostName, remoteHostPort); }))
{}

inline PlayReadyContentHeader::PlayReadyContentHeader(array_view<uint8_t const> headerBytes, Windows::Foundation::Uri const& licenseAcquisitionUrl, Windows::Foundation::Uri const& licenseAcquisitionUserInterfaceUrl, param::hstring const& customAttributes, winrt::guid const& domainServiceId) :
    PlayReadyContentHeader(impl::call_factory<PlayReadyContentHeader, Windows::Media::Protection::PlayReady::IPlayReadyContentHeaderFactory>([&](auto&& f) { return f.CreateInstanceFromWindowsMediaDrmHeader(headerBytes, licenseAcquisitionUrl, licenseAcquisitionUserInterfaceUrl, customAttributes, domainServiceId); }))
{}

inline PlayReadyContentHeader::PlayReadyContentHeader(winrt::guid const& contentKeyId, param::hstring const& contentKeyIdString, Windows::Media::Protection::PlayReady::PlayReadyEncryptionAlgorithm const& contentEncryptionAlgorithm, Windows::Foundation::Uri const& licenseAcquisitionUrl, Windows::Foundation::Uri const& licenseAcquisitionUserInterfaceUrl, param::hstring const& customAttributes, winrt::guid const& domainServiceId) :
    PlayReadyContentHeader(impl::call_factory<PlayReadyContentHeader, Windows::Media::Protection::PlayReady::IPlayReadyContentHeaderFactory>([&](auto&& f) { return f.CreateInstanceFromComponents(contentKeyId, contentKeyIdString, contentEncryptionAlgorithm, licenseAcquisitionUrl, licenseAcquisitionUserInterfaceUrl, customAttributes, domainServiceId); }))
{}

inline PlayReadyContentHeader::PlayReadyContentHeader(array_view<uint8_t const> headerBytes) :
    PlayReadyContentHeader(impl::call_factory<PlayReadyContentHeader, Windows::Media::Protection::PlayReady::IPlayReadyContentHeaderFactory>([&](auto&& f) { return f.CreateInstanceFromPlayReadyHeader(headerBytes); }))
{}

inline PlayReadyContentHeader::PlayReadyContentHeader(uint32_t dwFlags, array_view<winrt::guid const> contentKeyIds, array_view<hstring const> contentKeyIdStrings, Windows::Media::Protection::PlayReady::PlayReadyEncryptionAlgorithm const& contentEncryptionAlgorithm, Windows::Foundation::Uri const& licenseAcquisitionUrl, Windows::Foundation::Uri const& licenseAcquisitionUserInterfaceUrl, param::hstring const& customAttributes, winrt::guid const& domainServiceId) :
    PlayReadyContentHeader(impl::call_factory<PlayReadyContentHeader, Windows::Media::Protection::PlayReady::IPlayReadyContentHeaderFactory2>([&](auto&& f) { return f.CreateInstanceFromComponents2(dwFlags, contentKeyIds, contentKeyIdStrings, contentEncryptionAlgorithm, licenseAcquisitionUrl, licenseAcquisitionUserInterfaceUrl, customAttributes, domainServiceId); }))
{}

inline Windows::Media::Protection::PlayReady::IPlayReadyServiceRequest PlayReadyContentResolver::ServiceRequest(Windows::Media::Protection::PlayReady::PlayReadyContentHeader const& contentHeader)
{
    return impl::call_factory<PlayReadyContentResolver, Windows::Media::Protection::PlayReady::IPlayReadyContentResolver>([&](auto&& f) { return f.ServiceRequest(contentHeader); });
}

inline PlayReadyDomainIterable::PlayReadyDomainIterable(winrt::guid const& domainAccountId) :
    PlayReadyDomainIterable(impl::call_factory<PlayReadyDomainIterable, Windows::Media::Protection::PlayReady::IPlayReadyDomainIterableFactory>([&](auto&& f) { return f.CreateInstance(domainAccountId); }))
{}

inline PlayReadyDomainJoinServiceRequest::PlayReadyDomainJoinServiceRequest() :
    PlayReadyDomainJoinServiceRequest(impl::call_factory<PlayReadyDomainJoinServiceRequest>([](auto&& f) { return f.template ActivateInstance<PlayReadyDomainJoinServiceRequest>(); }))
{}

inline PlayReadyDomainLeaveServiceRequest::PlayReadyDomainLeaveServiceRequest() :
    PlayReadyDomainLeaveServiceRequest(impl::call_factory<PlayReadyDomainLeaveServiceRequest>([](auto&& f) { return f.template ActivateInstance<PlayReadyDomainLeaveServiceRequest>(); }))
{}

inline PlayReadyITADataGenerator::PlayReadyITADataGenerator() :
    PlayReadyITADataGenerator(impl::call_factory<PlayReadyITADataGenerator>([](auto&& f) { return f.template ActivateInstance<PlayReadyITADataGenerator>(); }))
{}

inline PlayReadyIndividualizationServiceRequest::PlayReadyIndividualizationServiceRequest() :
    PlayReadyIndividualizationServiceRequest(impl::call_factory<PlayReadyIndividualizationServiceRequest>([](auto&& f) { return f.template ActivateInstance<PlayReadyIndividualizationServiceRequest>(); }))
{}

inline PlayReadyLicenseAcquisitionServiceRequest::PlayReadyLicenseAcquisitionServiceRequest() :
    PlayReadyLicenseAcquisitionServiceRequest(impl::call_factory<PlayReadyLicenseAcquisitionServiceRequest>([](auto&& f) { return f.template ActivateInstance<PlayReadyLicenseAcquisitionServiceRequest>(); }))
{}

inline PlayReadyLicenseIterable::PlayReadyLicenseIterable() :
    PlayReadyLicenseIterable(impl::call_factory<PlayReadyLicenseIterable>([](auto&& f) { return f.template ActivateInstance<PlayReadyLicenseIterable>(); }))
{}

inline PlayReadyLicenseIterable::PlayReadyLicenseIterable(Windows::Media::Protection::PlayReady::PlayReadyContentHeader const& contentHeader, bool fullyEvaluated) :
    PlayReadyLicenseIterable(impl::call_factory<PlayReadyLicenseIterable, Windows::Media::Protection::PlayReady::IPlayReadyLicenseIterableFactory>([&](auto&& f) { return f.CreateInstance(contentHeader, fullyEvaluated); }))
{}

inline Windows::Foundation::IAsyncAction PlayReadyLicenseManagement::DeleteLicenses(Windows::Media::Protection::PlayReady::PlayReadyContentHeader const& contentHeader)
{
    return impl::call_factory<PlayReadyLicenseManagement, Windows::Media::Protection::PlayReady::IPlayReadyLicenseManagement>([&](auto&& f) { return f.DeleteLicenses(contentHeader); });
}

inline PlayReadyLicenseSession::PlayReadyLicenseSession(Windows::Foundation::Collections::IPropertySet const& configuration) :
    PlayReadyLicenseSession(impl::call_factory<PlayReadyLicenseSession, Windows::Media::Protection::PlayReady::IPlayReadyLicenseSessionFactory>([&](auto&& f) { return f.CreateInstance(configuration); }))
{}

inline PlayReadyMeteringReportServiceRequest::PlayReadyMeteringReportServiceRequest() :
    PlayReadyMeteringReportServiceRequest(impl::call_factory<PlayReadyMeteringReportServiceRequest>([](auto&& f) { return f.template ActivateInstance<PlayReadyMeteringReportServiceRequest>(); }))
{}

inline PlayReadyRevocationServiceRequest::PlayReadyRevocationServiceRequest() :
    PlayReadyRevocationServiceRequest(impl::call_factory<PlayReadyRevocationServiceRequest>([](auto&& f) { return f.template ActivateInstance<PlayReadyRevocationServiceRequest>(); }))
{}

inline PlayReadySecureStopIterable::PlayReadySecureStopIterable(array_view<uint8_t const> publisherCertBytes) :
    PlayReadySecureStopIterable(impl::call_factory<PlayReadySecureStopIterable, Windows::Media::Protection::PlayReady::IPlayReadySecureStopIterableFactory>([&](auto&& f) { return f.CreateInstance(publisherCertBytes); }))
{}

inline PlayReadySecureStopServiceRequest::PlayReadySecureStopServiceRequest(array_view<uint8_t const> publisherCertBytes) :
    PlayReadySecureStopServiceRequest(impl::call_factory<PlayReadySecureStopServiceRequest, Windows::Media::Protection::PlayReady::IPlayReadySecureStopServiceRequestFactory>([&](auto&& f) { return f.CreateInstance(publisherCertBytes); }))
{}

inline PlayReadySecureStopServiceRequest::PlayReadySecureStopServiceRequest(winrt::guid const& sessionID, array_view<uint8_t const> publisherCertBytes) :
    PlayReadySecureStopServiceRequest(impl::call_factory<PlayReadySecureStopServiceRequest, Windows::Media::Protection::PlayReady::IPlayReadySecureStopServiceRequestFactory>([&](auto&& f) { return f.CreateInstanceFromSessionID(sessionID, publisherCertBytes); }))
{}

inline winrt::guid PlayReadyStatics::DomainJoinServiceRequestType()
{
    return impl::call_factory<PlayReadyStatics, Windows::Media::Protection::PlayReady::IPlayReadyStatics>([&](auto&& f) { return f.DomainJoinServiceRequestType(); });
}

inline winrt::guid PlayReadyStatics::DomainLeaveServiceRequestType()
{
    return impl::call_factory<PlayReadyStatics, Windows::Media::Protection::PlayReady::IPlayReadyStatics>([&](auto&& f) { return f.DomainLeaveServiceRequestType(); });
}

inline winrt::guid PlayReadyStatics::IndividualizationServiceRequestType()
{
    return impl::call_factory<PlayReadyStatics, Windows::Media::Protection::PlayReady::IPlayReadyStatics>([&](auto&& f) { return f.IndividualizationServiceRequestType(); });
}

inline winrt::guid PlayReadyStatics::LicenseAcquirerServiceRequestType()
{
    return impl::call_factory<PlayReadyStatics, Windows::Media::Protection::PlayReady::IPlayReadyStatics>([&](auto&& f) { return f.LicenseAcquirerServiceRequestType(); });
}

inline winrt::guid PlayReadyStatics::MeteringReportServiceRequestType()
{
    return impl::call_factory<PlayReadyStatics, Windows::Media::Protection::PlayReady::IPlayReadyStatics>([&](auto&& f) { return f.MeteringReportServiceRequestType(); });
}

inline winrt::guid PlayReadyStatics::RevocationServiceRequestType()
{
    return impl::call_factory<PlayReadyStatics, Windows::Media::Protection::PlayReady::IPlayReadyStatics>([&](auto&& f) { return f.RevocationServiceRequestType(); });
}

inline winrt::guid PlayReadyStatics::MediaProtectionSystemId()
{
    return impl::call_factory<PlayReadyStatics, Windows::Media::Protection::PlayReady::IPlayReadyStatics>([&](auto&& f) { return f.MediaProtectionSystemId(); });
}

inline uint32_t PlayReadyStatics::PlayReadySecurityVersion()
{
    return impl::call_factory<PlayReadyStatics, Windows::Media::Protection::PlayReady::IPlayReadyStatics>([&](auto&& f) { return f.PlayReadySecurityVersion(); });
}

inline uint32_t PlayReadyStatics::PlayReadyCertificateSecurityLevel()
{
    return impl::call_factory<PlayReadyStatics, Windows::Media::Protection::PlayReady::IPlayReadyStatics2>([&](auto&& f) { return f.PlayReadyCertificateSecurityLevel(); });
}

inline winrt::guid PlayReadyStatics::SecureStopServiceRequestType()
{
    return impl::call_factory<PlayReadyStatics, Windows::Media::Protection::PlayReady::IPlayReadyStatics3>([&](auto&& f) { return f.SecureStopServiceRequestType(); });
}

inline bool PlayReadyStatics::CheckSupportedHardware(Windows::Media::Protection::PlayReady::PlayReadyHardwareDRMFeatures const& hwdrmFeature)
{
    return impl::call_factory<PlayReadyStatics, Windows::Media::Protection::PlayReady::IPlayReadyStatics3>([&](auto&& f) { return f.CheckSupportedHardware(hwdrmFeature); });
}

inline hstring PlayReadyStatics::InputTrustAuthorityToCreate()
{
    return impl::call_factory<PlayReadyStatics, Windows::Media::Protection::PlayReady::IPlayReadyStatics4>([&](auto&& f) { return f.InputTrustAuthorityToCreate(); });
}

inline winrt::guid PlayReadyStatics::ProtectionSystemId()
{
    return impl::call_factory<PlayReadyStatics, Windows::Media::Protection::PlayReady::IPlayReadyStatics4>([&](auto&& f) { return f.ProtectionSystemId(); });
}

inline Windows::Foundation::IReference<Windows::Foundation::DateTime> PlayReadyStatics::HardwareDRMDisabledAtTime()
{
    return impl::call_factory<PlayReadyStatics, Windows::Media::Protection::PlayReady::IPlayReadyStatics5>([&](auto&& f) { return f.HardwareDRMDisabledAtTime(); });
}

inline Windows::Foundation::IReference<Windows::Foundation::DateTime> PlayReadyStatics::HardwareDRMDisabledUntilTime()
{
    return impl::call_factory<PlayReadyStatics, Windows::Media::Protection::PlayReady::IPlayReadyStatics5>([&](auto&& f) { return f.HardwareDRMDisabledUntilTime(); });
}

inline void PlayReadyStatics::ResetHardwareDRMDisabled()
{
    impl::call_factory<PlayReadyStatics, Windows::Media::Protection::PlayReady::IPlayReadyStatics5>([&](auto&& f) { return f.ResetHardwareDRMDisabled(); });
}

}

WINRT_EXPORT namespace std {

template<> struct hash<winrt::Windows::Media::Protection::PlayReady::INDClient> : winrt::impl::hash_base<winrt::Windows::Media::Protection::PlayReady::INDClient> {};
template<> struct hash<winrt::Windows::Media::Protection::PlayReady::INDClientFactory> : winrt::impl::hash_base<winrt::Windows::Media::Protection::PlayReady::INDClientFactory> {};
template<> struct hash<winrt::Windows::Media::Protection::PlayReady::INDClosedCaptionDataReceivedEventArgs> : winrt::impl::hash_base<winrt::Windows::Media::Protection::PlayReady::INDClosedCaptionDataReceivedEventArgs> {};
template<> struct hash<winrt::Windows::Media::Protection::PlayReady::INDCustomData> : winrt::impl::hash_base<winrt::Windows::Media::Protection::PlayReady::INDCustomData> {};
template<> struct hash<winrt::Windows::Media::Protection::PlayReady::INDCustomDataFactory> : winrt::impl::hash_base<winrt::Windows::Media::Protection::PlayReady::INDCustomDataFactory> {};
template<> struct hash<winrt::Windows::Media::Protection::PlayReady::INDDownloadEngine> : winrt::impl::hash_base<winrt::Windows::Media::Protection::PlayReady::INDDownloadEngine> {};
template<> struct hash<winrt::Windows::Media::Protection::PlayReady::INDDownloadEngineNotifier> : winrt::impl::hash_base<winrt::Windows::Media::Protection::PlayReady::INDDownloadEngineNotifier> {};
template<> struct hash<winrt::Windows::Media::Protection::PlayReady::INDLicenseFetchCompletedEventArgs> : winrt::impl::hash_base<winrt::Windows::Media::Protection::PlayReady::INDLicenseFetchCompletedEventArgs> {};
template<> struct hash<winrt::Windows::Media::Protection::PlayReady::INDLicenseFetchDescriptor> : winrt::impl::hash_base<winrt::Windows::Media::Protection::PlayReady::INDLicenseFetchDescriptor> {};
template<> struct hash<winrt::Windows::Media::Protection::PlayReady::INDLicenseFetchDescriptorFactory> : winrt::impl::hash_base<winrt::Windows::Media::Protection::PlayReady::INDLicenseFetchDescriptorFactory> {};
template<> struct hash<winrt::Windows::Media::Protection::PlayReady::INDLicenseFetchResult> : winrt::impl::hash_base<winrt::Windows::Media::Protection::PlayReady::INDLicenseFetchResult> {};
template<> struct hash<winrt::Windows::Media::Protection::PlayReady::INDMessenger> : winrt::impl::hash_base<winrt::Windows::Media::Protection::PlayReady::INDMessenger> {};
template<> struct hash<winrt::Windows::Media::Protection::PlayReady::INDProximityDetectionCompletedEventArgs> : winrt::impl::hash_base<winrt::Windows::Media::Protection::PlayReady::INDProximityDetectionCompletedEventArgs> {};
template<> struct hash<winrt::Windows::Media::Protection::PlayReady::INDRegistrationCompletedEventArgs> : winrt::impl::hash_base<winrt::Windows::Media::Protection::PlayReady::INDRegistrationCompletedEventArgs> {};
template<> struct hash<winrt::Windows::Media::Protection::PlayReady::INDSendResult> : winrt::impl::hash_base<winrt::Windows::Media::Protection::PlayReady::INDSendResult> {};
template<> struct hash<winrt::Windows::Media::Protection::PlayReady::INDStartResult> : winrt::impl::hash_base<winrt::Windows::Media::Protection::PlayReady::INDStartResult> {};
template<> struct hash<winrt::Windows::Media::Protection::PlayReady::INDStorageFileHelper> : winrt::impl::hash_base<winrt::Windows::Media::Protection::PlayReady::INDStorageFileHelper> {};
template<> struct hash<winrt::Windows::Media::Protection::PlayReady::INDStreamParser> : winrt::impl::hash_base<winrt::Windows::Media::Protection::PlayReady::INDStreamParser> {};
template<> struct hash<winrt::Windows::Media::Protection::PlayReady::INDStreamParserNotifier> : winrt::impl::hash_base<winrt::Windows::Media::Protection::PlayReady::INDStreamParserNotifier> {};
template<> struct hash<winrt::Windows::Media::Protection::PlayReady::INDTCPMessengerFactory> : winrt::impl::hash_base<winrt::Windows::Media::Protection::PlayReady::INDTCPMessengerFactory> {};
template<> struct hash<winrt::Windows::Media::Protection::PlayReady::INDTransmitterProperties> : winrt::impl::hash_base<winrt::Windows::Media::Protection::PlayReady::INDTransmitterProperties> {};
template<> struct hash<winrt::Windows::Media::Protection::PlayReady::IPlayReadyContentHeader> : winrt::impl::hash_base<winrt::Windows::Media::Protection::PlayReady::IPlayReadyContentHeader> {};
template<> struct hash<winrt::Windows::Media::Protection::PlayReady::IPlayReadyContentHeader2> : winrt::impl::hash_base<winrt::Windows::Media::Protection::PlayReady::IPlayReadyContentHeader2> {};
template<> struct hash<winrt::Windows::Media::Protection::PlayReady::IPlayReadyContentHeaderFactory> : winrt::impl::hash_base<winrt::Windows::Media::Protection::PlayReady::IPlayReadyContentHeaderFactory> {};
template<> struct hash<winrt::Windows::Media::Protection::PlayReady::IPlayReadyContentHeaderFactory2> : winrt::impl::hash_base<winrt::Windows::Media::Protection::PlayReady::IPlayReadyContentHeaderFactory2> {};
template<> struct hash<winrt::Windows::Media::Protection::PlayReady::IPlayReadyContentResolver> : winrt::impl::hash_base<winrt::Windows::Media::Protection::PlayReady::IPlayReadyContentResolver> {};
template<> struct hash<winrt::Windows::Media::Protection::PlayReady::IPlayReadyDomain> : winrt::impl::hash_base<winrt::Windows::Media::Protection::PlayReady::IPlayReadyDomain> {};
template<> struct hash<winrt::Windows::Media::Protection::PlayReady::IPlayReadyDomainIterableFactory> : winrt::impl::hash_base<winrt::Windows::Media::Protection::PlayReady::IPlayReadyDomainIterableFactory> {};
template<> struct hash<winrt::Windows::Media::Protection::PlayReady::IPlayReadyDomainJoinServiceRequest> : winrt::impl::hash_base<winrt::Windows::Media::Protection::PlayReady::IPlayReadyDomainJoinServiceRequest> {};
template<> struct hash<winrt::Windows::Media::Protection::PlayReady::IPlayReadyDomainLeaveServiceRequest> : winrt::impl::hash_base<winrt::Windows::Media::Protection::PlayReady::IPlayReadyDomainLeaveServiceRequest> {};
template<> struct hash<winrt::Windows::Media::Protection::PlayReady::IPlayReadyITADataGenerator> : winrt::impl::hash_base<winrt::Windows::Media::Protection::PlayReady::IPlayReadyITADataGenerator> {};
template<> struct hash<winrt::Windows::Media::Protection::PlayReady::IPlayReadyIndividualizationServiceRequest> : winrt::impl::hash_base<winrt::Windows::Media::Protection::PlayReady::IPlayReadyIndividualizationServiceRequest> {};
template<> struct hash<winrt::Windows::Media::Protection::PlayReady::IPlayReadyLicense> : winrt::impl::hash_base<winrt::Windows::Media::Protection::PlayReady::IPlayReadyLicense> {};
template<> struct hash<winrt::Windows::Media::Protection::PlayReady::IPlayReadyLicense2> : winrt::impl::hash_base<winrt::Windows::Media::Protection::PlayReady::IPlayReadyLicense2> {};
template<> struct hash<winrt::Windows::Media::Protection::PlayReady::IPlayReadyLicenseAcquisitionServiceRequest> : winrt::impl::hash_base<winrt::Windows::Media::Protection::PlayReady::IPlayReadyLicenseAcquisitionServiceRequest> {};
template<> struct hash<winrt::Windows::Media::Protection::PlayReady::IPlayReadyLicenseAcquisitionServiceRequest2> : winrt::impl::hash_base<winrt::Windows::Media::Protection::PlayReady::IPlayReadyLicenseAcquisitionServiceRequest2> {};
template<> struct hash<winrt::Windows::Media::Protection::PlayReady::IPlayReadyLicenseAcquisitionServiceRequest3> : winrt::impl::hash_base<winrt::Windows::Media::Protection::PlayReady::IPlayReadyLicenseAcquisitionServiceRequest3> {};
template<> struct hash<winrt::Windows::Media::Protection::PlayReady::IPlayReadyLicenseIterableFactory> : winrt::impl::hash_base<winrt::Windows::Media::Protection::PlayReady::IPlayReadyLicenseIterableFactory> {};
template<> struct hash<winrt::Windows::Media::Protection::PlayReady::IPlayReadyLicenseManagement> : winrt::impl::hash_base<winrt::Windows::Media::Protection::PlayReady::IPlayReadyLicenseManagement> {};
template<> struct hash<winrt::Windows::Media::Protection::PlayReady::IPlayReadyLicenseSession> : winrt::impl::hash_base<winrt::Windows::Media::Protection::PlayReady::IPlayReadyLicenseSession> {};
template<> struct hash<winrt::Windows::Media::Protection::PlayReady::IPlayReadyLicenseSession2> : winrt::impl::hash_base<winrt::Windows::Media::Protection::PlayReady::IPlayReadyLicenseSession2> {};
template<> struct hash<winrt::Windows::Media::Protection::PlayReady::IPlayReadyLicenseSessionFactory> : winrt::impl::hash_base<winrt::Windows::Media::Protection::PlayReady::IPlayReadyLicenseSessionFactory> {};
template<> struct hash<winrt::Windows::Media::Protection::PlayReady::IPlayReadyMeteringReportServiceRequest> : winrt::impl::hash_base<winrt::Windows::Media::Protection::PlayReady::IPlayReadyMeteringReportServiceRequest> {};
template<> struct hash<winrt::Windows::Media::Protection::PlayReady::IPlayReadyRevocationServiceRequest> : winrt::impl::hash_base<winrt::Windows::Media::Protection::PlayReady::IPlayReadyRevocationServiceRequest> {};
template<> struct hash<winrt::Windows::Media::Protection::PlayReady::IPlayReadySecureStopIterableFactory> : winrt::impl::hash_base<winrt::Windows::Media::Protection::PlayReady::IPlayReadySecureStopIterableFactory> {};
template<> struct hash<winrt::Windows::Media::Protection::PlayReady::IPlayReadySecureStopServiceRequest> : winrt::impl::hash_base<winrt::Windows::Media::Protection::PlayReady::IPlayReadySecureStopServiceRequest> {};
template<> struct hash<winrt::Windows::Media::Protection::PlayReady::IPlayReadySecureStopServiceRequestFactory> : winrt::impl::hash_base<winrt::Windows::Media::Protection::PlayReady::IPlayReadySecureStopServiceRequestFactory> {};
template<> struct hash<winrt::Windows::Media::Protection::PlayReady::IPlayReadyServiceRequest> : winrt::impl::hash_base<winrt::Windows::Media::Protection::PlayReady::IPlayReadyServiceRequest> {};
template<> struct hash<winrt::Windows::Media::Protection::PlayReady::IPlayReadySoapMessage> : winrt::impl::hash_base<winrt::Windows::Media::Protection::PlayReady::IPlayReadySoapMessage> {};
template<> struct hash<winrt::Windows::Media::Protection::PlayReady::IPlayReadyStatics> : winrt::impl::hash_base<winrt::Windows::Media::Protection::PlayReady::IPlayReadyStatics> {};
template<> struct hash<winrt::Windows::Media::Protection::PlayReady::IPlayReadyStatics2> : winrt::impl::hash_base<winrt::Windows::Media::Protection::PlayReady::IPlayReadyStatics2> {};
template<> struct hash<winrt::Windows::Media::Protection::PlayReady::IPlayReadyStatics3> : winrt::impl::hash_base<winrt::Windows::Media::Protection::PlayReady::IPlayReadyStatics3> {};
template<> struct hash<winrt::Windows::Media::Protection::PlayReady::IPlayReadyStatics4> : winrt::impl::hash_base<winrt::Windows::Media::Protection::PlayReady::IPlayReadyStatics4> {};
template<> struct hash<winrt::Windows::Media::Protection::PlayReady::IPlayReadyStatics5> : winrt::impl::hash_base<winrt::Windows::Media::Protection::PlayReady::IPlayReadyStatics5> {};
template<> struct hash<winrt::Windows::Media::Protection::PlayReady::NDClient> : winrt::impl::hash_base<winrt::Windows::Media::Protection::PlayReady::NDClient> {};
template<> struct hash<winrt::Windows::Media::Protection::PlayReady::NDCustomData> : winrt::impl::hash_base<winrt::Windows::Media::Protection::PlayReady::NDCustomData> {};
template<> struct hash<winrt::Windows::Media::Protection::PlayReady::NDDownloadEngineNotifier> : winrt::impl::hash_base<winrt::Windows::Media::Protection::PlayReady::NDDownloadEngineNotifier> {};
template<> struct hash<winrt::Windows::Media::Protection::PlayReady::NDLicenseFetchDescriptor> : winrt::impl::hash_base<winrt::Windows::Media::Protection::PlayReady::NDLicenseFetchDescriptor> {};
template<> struct hash<winrt::Windows::Media::Protection::PlayReady::NDStorageFileHelper> : winrt::impl::hash_base<winrt::Windows::Media::Protection::PlayReady::NDStorageFileHelper> {};
template<> struct hash<winrt::Windows::Media::Protection::PlayReady::NDStreamParserNotifier> : winrt::impl::hash_base<winrt::Windows::Media::Protection::PlayReady::NDStreamParserNotifier> {};
template<> struct hash<winrt::Windows::Media::Protection::PlayReady::NDTCPMessenger> : winrt::impl::hash_base<winrt::Windows::Media::Protection::PlayReady::NDTCPMessenger> {};
template<> struct hash<winrt::Windows::Media::Protection::PlayReady::PlayReadyContentHeader> : winrt::impl::hash_base<winrt::Windows::Media::Protection::PlayReady::PlayReadyContentHeader> {};
template<> struct hash<winrt::Windows::Media::Protection::PlayReady::PlayReadyContentResolver> : winrt::impl::hash_base<winrt::Windows::Media::Protection::PlayReady::PlayReadyContentResolver> {};
template<> struct hash<winrt::Windows::Media::Protection::PlayReady::PlayReadyDomain> : winrt::impl::hash_base<winrt::Windows::Media::Protection::PlayReady::PlayReadyDomain> {};
template<> struct hash<winrt::Windows::Media::Protection::PlayReady::PlayReadyDomainIterable> : winrt::impl::hash_base<winrt::Windows::Media::Protection::PlayReady::PlayReadyDomainIterable> {};
template<> struct hash<winrt::Windows::Media::Protection::PlayReady::PlayReadyDomainIterator> : winrt::impl::hash_base<winrt::Windows::Media::Protection::PlayReady::PlayReadyDomainIterator> {};
template<> struct hash<winrt::Windows::Media::Protection::PlayReady::PlayReadyDomainJoinServiceRequest> : winrt::impl::hash_base<winrt::Windows::Media::Protection::PlayReady::PlayReadyDomainJoinServiceRequest> {};
template<> struct hash<winrt::Windows::Media::Protection::PlayReady::PlayReadyDomainLeaveServiceRequest> : winrt::impl::hash_base<winrt::Windows::Media::Protection::PlayReady::PlayReadyDomainLeaveServiceRequest> {};
template<> struct hash<winrt::Windows::Media::Protection::PlayReady::PlayReadyITADataGenerator> : winrt::impl::hash_base<winrt::Windows::Media::Protection::PlayReady::PlayReadyITADataGenerator> {};
template<> struct hash<winrt::Windows::Media::Protection::PlayReady::PlayReadyIndividualizationServiceRequest> : winrt::impl::hash_base<winrt::Windows::Media::Protection::PlayReady::PlayReadyIndividualizationServiceRequest> {};
template<> struct hash<winrt::Windows::Media::Protection::PlayReady::PlayReadyLicense> : winrt::impl::hash_base<winrt::Windows::Media::Protection::PlayReady::PlayReadyLicense> {};
template<> struct hash<winrt::Windows::Media::Protection::PlayReady::PlayReadyLicenseAcquisitionServiceRequest> : winrt::impl::hash_base<winrt::Windows::Media::Protection::PlayReady::PlayReadyLicenseAcquisitionServiceRequest> {};
template<> struct hash<winrt::Windows::Media::Protection::PlayReady::PlayReadyLicenseIterable> : winrt::impl::hash_base<winrt::Windows::Media::Protection::PlayReady::PlayReadyLicenseIterable> {};
template<> struct hash<winrt::Windows::Media::Protection::PlayReady::PlayReadyLicenseIterator> : winrt::impl::hash_base<winrt::Windows::Media::Protection::PlayReady::PlayReadyLicenseIterator> {};
template<> struct hash<winrt::Windows::Media::Protection::PlayReady::PlayReadyLicenseManagement> : winrt::impl::hash_base<winrt::Windows::Media::Protection::PlayReady::PlayReadyLicenseManagement> {};
template<> struct hash<winrt::Windows::Media::Protection::PlayReady::PlayReadyLicenseSession> : winrt::impl::hash_base<winrt::Windows::Media::Protection::PlayReady::PlayReadyLicenseSession> {};
template<> struct hash<winrt::Windows::Media::Protection::PlayReady::PlayReadyMeteringReportServiceRequest> : winrt::impl::hash_base<winrt::Windows::Media::Protection::PlayReady::PlayReadyMeteringReportServiceRequest> {};
template<> struct hash<winrt::Windows::Media::Protection::PlayReady::PlayReadyRevocationServiceRequest> : winrt::impl::hash_base<winrt::Windows::Media::Protection::PlayReady::PlayReadyRevocationServiceRequest> {};
template<> struct hash<winrt::Windows::Media::Protection::PlayReady::PlayReadySecureStopIterable> : winrt::impl::hash_base<winrt::Windows::Media::Protection::PlayReady::PlayReadySecureStopIterable> {};
template<> struct hash<winrt::Windows::Media::Protection::PlayReady::PlayReadySecureStopIterator> : winrt::impl::hash_base<winrt::Windows::Media::Protection::PlayReady::PlayReadySecureStopIterator> {};
template<> struct hash<winrt::Windows::Media::Protection::PlayReady::PlayReadySecureStopServiceRequest> : winrt::impl::hash_base<winrt::Windows::Media::Protection::PlayReady::PlayReadySecureStopServiceRequest> {};
template<> struct hash<winrt::Windows::Media::Protection::PlayReady::PlayReadySoapMessage> : winrt::impl::hash_base<winrt::Windows::Media::Protection::PlayReady::PlayReadySoapMessage> {};
template<> struct hash<winrt::Windows::Media::Protection::PlayReady::PlayReadyStatics> : winrt::impl::hash_base<winrt::Windows::Media::Protection::PlayReady::PlayReadyStatics> {};

}
