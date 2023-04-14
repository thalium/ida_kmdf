// C++/WinRT v1.0.190111.3

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#pragma once
#include "winrt/impl/Windows.Foundation.0.h"
#include "winrt/impl/Windows.Foundation.Collections.0.h"
#include "winrt/impl/Windows.Media.Core.0.h"
#include "winrt/impl/Windows.Media.Protection.0.h"
#include "winrt/impl/Windows.Storage.0.h"
#include "winrt/impl/Windows.Media.Protection.PlayReady.0.h"

WINRT_EXPORT namespace winrt::Windows::Media::Protection::PlayReady {

struct WINRT_EBO INDClient :
    Windows::Foundation::IInspectable,
    impl::consume_t<INDClient>
{
    INDClient(std::nullptr_t = nullptr) noexcept {}
};

struct WINRT_EBO INDClientFactory :
    Windows::Foundation::IInspectable,
    impl::consume_t<INDClientFactory>
{
    INDClientFactory(std::nullptr_t = nullptr) noexcept {}
};

struct WINRT_EBO INDClosedCaptionDataReceivedEventArgs :
    Windows::Foundation::IInspectable,
    impl::consume_t<INDClosedCaptionDataReceivedEventArgs>
{
    INDClosedCaptionDataReceivedEventArgs(std::nullptr_t = nullptr) noexcept {}
};

struct WINRT_EBO INDCustomData :
    Windows::Foundation::IInspectable,
    impl::consume_t<INDCustomData>
{
    INDCustomData(std::nullptr_t = nullptr) noexcept {}
};

struct WINRT_EBO INDCustomDataFactory :
    Windows::Foundation::IInspectable,
    impl::consume_t<INDCustomDataFactory>
{
    INDCustomDataFactory(std::nullptr_t = nullptr) noexcept {}
};

struct WINRT_EBO INDDownloadEngine :
    Windows::Foundation::IInspectable,
    impl::consume_t<INDDownloadEngine>
{
    INDDownloadEngine(std::nullptr_t = nullptr) noexcept {}
};

struct WINRT_EBO INDDownloadEngineNotifier :
    Windows::Foundation::IInspectable,
    impl::consume_t<INDDownloadEngineNotifier>
{
    INDDownloadEngineNotifier(std::nullptr_t = nullptr) noexcept {}
};

struct WINRT_EBO INDLicenseFetchCompletedEventArgs :
    Windows::Foundation::IInspectable,
    impl::consume_t<INDLicenseFetchCompletedEventArgs>
{
    INDLicenseFetchCompletedEventArgs(std::nullptr_t = nullptr) noexcept {}
};

struct WINRT_EBO INDLicenseFetchDescriptor :
    Windows::Foundation::IInspectable,
    impl::consume_t<INDLicenseFetchDescriptor>
{
    INDLicenseFetchDescriptor(std::nullptr_t = nullptr) noexcept {}
};

struct WINRT_EBO INDLicenseFetchDescriptorFactory :
    Windows::Foundation::IInspectable,
    impl::consume_t<INDLicenseFetchDescriptorFactory>
{
    INDLicenseFetchDescriptorFactory(std::nullptr_t = nullptr) noexcept {}
};

struct WINRT_EBO INDLicenseFetchResult :
    Windows::Foundation::IInspectable,
    impl::consume_t<INDLicenseFetchResult>
{
    INDLicenseFetchResult(std::nullptr_t = nullptr) noexcept {}
};

struct WINRT_EBO INDMessenger :
    Windows::Foundation::IInspectable,
    impl::consume_t<INDMessenger>
{
    INDMessenger(std::nullptr_t = nullptr) noexcept {}
};

struct WINRT_EBO INDProximityDetectionCompletedEventArgs :
    Windows::Foundation::IInspectable,
    impl::consume_t<INDProximityDetectionCompletedEventArgs>
{
    INDProximityDetectionCompletedEventArgs(std::nullptr_t = nullptr) noexcept {}
};

struct WINRT_EBO INDRegistrationCompletedEventArgs :
    Windows::Foundation::IInspectable,
    impl::consume_t<INDRegistrationCompletedEventArgs>
{
    INDRegistrationCompletedEventArgs(std::nullptr_t = nullptr) noexcept {}
};

struct WINRT_EBO INDSendResult :
    Windows::Foundation::IInspectable,
    impl::consume_t<INDSendResult>
{
    INDSendResult(std::nullptr_t = nullptr) noexcept {}
};

struct WINRT_EBO INDStartResult :
    Windows::Foundation::IInspectable,
    impl::consume_t<INDStartResult>
{
    INDStartResult(std::nullptr_t = nullptr) noexcept {}
};

struct WINRT_EBO INDStorageFileHelper :
    Windows::Foundation::IInspectable,
    impl::consume_t<INDStorageFileHelper>
{
    INDStorageFileHelper(std::nullptr_t = nullptr) noexcept {}
};

struct WINRT_EBO INDStreamParser :
    Windows::Foundation::IInspectable,
    impl::consume_t<INDStreamParser>
{
    INDStreamParser(std::nullptr_t = nullptr) noexcept {}
};

struct WINRT_EBO INDStreamParserNotifier :
    Windows::Foundation::IInspectable,
    impl::consume_t<INDStreamParserNotifier>
{
    INDStreamParserNotifier(std::nullptr_t = nullptr) noexcept {}
};

struct WINRT_EBO INDTCPMessengerFactory :
    Windows::Foundation::IInspectable,
    impl::consume_t<INDTCPMessengerFactory>
{
    INDTCPMessengerFactory(std::nullptr_t = nullptr) noexcept {}
};

struct WINRT_EBO INDTransmitterProperties :
    Windows::Foundation::IInspectable,
    impl::consume_t<INDTransmitterProperties>
{
    INDTransmitterProperties(std::nullptr_t = nullptr) noexcept {}
};

struct WINRT_EBO IPlayReadyContentHeader :
    Windows::Foundation::IInspectable,
    impl::consume_t<IPlayReadyContentHeader>
{
    IPlayReadyContentHeader(std::nullptr_t = nullptr) noexcept {}
};

struct WINRT_EBO IPlayReadyContentHeader2 :
    Windows::Foundation::IInspectable,
    impl::consume_t<IPlayReadyContentHeader2>,
    impl::require<IPlayReadyContentHeader2, Windows::Media::Protection::PlayReady::IPlayReadyContentHeader>
{
    IPlayReadyContentHeader2(std::nullptr_t = nullptr) noexcept {}
};

struct WINRT_EBO IPlayReadyContentHeaderFactory :
    Windows::Foundation::IInspectable,
    impl::consume_t<IPlayReadyContentHeaderFactory>
{
    IPlayReadyContentHeaderFactory(std::nullptr_t = nullptr) noexcept {}
};

struct WINRT_EBO IPlayReadyContentHeaderFactory2 :
    Windows::Foundation::IInspectable,
    impl::consume_t<IPlayReadyContentHeaderFactory2>
{
    IPlayReadyContentHeaderFactory2(std::nullptr_t = nullptr) noexcept {}
};

struct WINRT_EBO IPlayReadyContentResolver :
    Windows::Foundation::IInspectable,
    impl::consume_t<IPlayReadyContentResolver>
{
    IPlayReadyContentResolver(std::nullptr_t = nullptr) noexcept {}
};

struct WINRT_EBO IPlayReadyDomain :
    Windows::Foundation::IInspectable,
    impl::consume_t<IPlayReadyDomain>
{
    IPlayReadyDomain(std::nullptr_t = nullptr) noexcept {}
};

struct WINRT_EBO IPlayReadyDomainIterableFactory :
    Windows::Foundation::IInspectable,
    impl::consume_t<IPlayReadyDomainIterableFactory>
{
    IPlayReadyDomainIterableFactory(std::nullptr_t = nullptr) noexcept {}
};

struct WINRT_EBO IPlayReadyDomainJoinServiceRequest :
    Windows::Foundation::IInspectable,
    impl::consume_t<IPlayReadyDomainJoinServiceRequest>,
    impl::require<IPlayReadyDomainJoinServiceRequest, Windows::Media::Protection::IMediaProtectionServiceRequest, Windows::Media::Protection::PlayReady::IPlayReadyServiceRequest>
{
    IPlayReadyDomainJoinServiceRequest(std::nullptr_t = nullptr) noexcept {}
};

struct WINRT_EBO IPlayReadyDomainLeaveServiceRequest :
    Windows::Foundation::IInspectable,
    impl::consume_t<IPlayReadyDomainLeaveServiceRequest>,
    impl::require<IPlayReadyDomainLeaveServiceRequest, Windows::Media::Protection::IMediaProtectionServiceRequest, Windows::Media::Protection::PlayReady::IPlayReadyServiceRequest>
{
    IPlayReadyDomainLeaveServiceRequest(std::nullptr_t = nullptr) noexcept {}
};

struct WINRT_EBO IPlayReadyITADataGenerator :
    Windows::Foundation::IInspectable,
    impl::consume_t<IPlayReadyITADataGenerator>
{
    IPlayReadyITADataGenerator(std::nullptr_t = nullptr) noexcept {}
};

struct WINRT_EBO IPlayReadyIndividualizationServiceRequest :
    Windows::Foundation::IInspectable,
    impl::consume_t<IPlayReadyIndividualizationServiceRequest>,
    impl::require<IPlayReadyIndividualizationServiceRequest, Windows::Media::Protection::IMediaProtectionServiceRequest, Windows::Media::Protection::PlayReady::IPlayReadyServiceRequest>
{
    IPlayReadyIndividualizationServiceRequest(std::nullptr_t = nullptr) noexcept {}
};

struct WINRT_EBO IPlayReadyLicense :
    Windows::Foundation::IInspectable,
    impl::consume_t<IPlayReadyLicense>
{
    IPlayReadyLicense(std::nullptr_t = nullptr) noexcept {}
};

struct WINRT_EBO IPlayReadyLicense2 :
    Windows::Foundation::IInspectable,
    impl::consume_t<IPlayReadyLicense2>,
    impl::require<IPlayReadyLicense2, Windows::Media::Protection::PlayReady::IPlayReadyLicense>
{
    IPlayReadyLicense2(std::nullptr_t = nullptr) noexcept {}
};

struct WINRT_EBO IPlayReadyLicenseAcquisitionServiceRequest :
    Windows::Foundation::IInspectable,
    impl::consume_t<IPlayReadyLicenseAcquisitionServiceRequest>,
    impl::require<IPlayReadyLicenseAcquisitionServiceRequest, Windows::Media::Protection::IMediaProtectionServiceRequest, Windows::Media::Protection::PlayReady::IPlayReadyServiceRequest>
{
    IPlayReadyLicenseAcquisitionServiceRequest(std::nullptr_t = nullptr) noexcept {}
};

struct WINRT_EBO IPlayReadyLicenseAcquisitionServiceRequest2 :
    Windows::Foundation::IInspectable,
    impl::consume_t<IPlayReadyLicenseAcquisitionServiceRequest2>,
    impl::require<IPlayReadyLicenseAcquisitionServiceRequest2, Windows::Media::Protection::IMediaProtectionServiceRequest, Windows::Media::Protection::PlayReady::IPlayReadyLicenseAcquisitionServiceRequest, Windows::Media::Protection::PlayReady::IPlayReadyServiceRequest>
{
    IPlayReadyLicenseAcquisitionServiceRequest2(std::nullptr_t = nullptr) noexcept {}
};

struct WINRT_EBO IPlayReadyLicenseAcquisitionServiceRequest3 :
    Windows::Foundation::IInspectable,
    impl::consume_t<IPlayReadyLicenseAcquisitionServiceRequest3>,
    impl::require<IPlayReadyLicenseAcquisitionServiceRequest3, Windows::Media::Protection::IMediaProtectionServiceRequest, Windows::Media::Protection::PlayReady::IPlayReadyLicenseAcquisitionServiceRequest, Windows::Media::Protection::PlayReady::IPlayReadyLicenseAcquisitionServiceRequest2, Windows::Media::Protection::PlayReady::IPlayReadyServiceRequest>
{
    IPlayReadyLicenseAcquisitionServiceRequest3(std::nullptr_t = nullptr) noexcept {}
};

struct WINRT_EBO IPlayReadyLicenseIterableFactory :
    Windows::Foundation::IInspectable,
    impl::consume_t<IPlayReadyLicenseIterableFactory>
{
    IPlayReadyLicenseIterableFactory(std::nullptr_t = nullptr) noexcept {}
};

struct WINRT_EBO IPlayReadyLicenseManagement :
    Windows::Foundation::IInspectable,
    impl::consume_t<IPlayReadyLicenseManagement>
{
    IPlayReadyLicenseManagement(std::nullptr_t = nullptr) noexcept {}
};

struct WINRT_EBO IPlayReadyLicenseSession :
    Windows::Foundation::IInspectable,
    impl::consume_t<IPlayReadyLicenseSession>
{
    IPlayReadyLicenseSession(std::nullptr_t = nullptr) noexcept {}
};

struct WINRT_EBO IPlayReadyLicenseSession2 :
    Windows::Foundation::IInspectable,
    impl::consume_t<IPlayReadyLicenseSession2>,
    impl::require<IPlayReadyLicenseSession2, Windows::Media::Protection::PlayReady::IPlayReadyLicenseSession>
{
    IPlayReadyLicenseSession2(std::nullptr_t = nullptr) noexcept {}
};

struct WINRT_EBO IPlayReadyLicenseSessionFactory :
    Windows::Foundation::IInspectable,
    impl::consume_t<IPlayReadyLicenseSessionFactory>
{
    IPlayReadyLicenseSessionFactory(std::nullptr_t = nullptr) noexcept {}
};

struct WINRT_EBO IPlayReadyMeteringReportServiceRequest :
    Windows::Foundation::IInspectable,
    impl::consume_t<IPlayReadyMeteringReportServiceRequest>,
    impl::require<IPlayReadyMeteringReportServiceRequest, Windows::Media::Protection::IMediaProtectionServiceRequest, Windows::Media::Protection::PlayReady::IPlayReadyServiceRequest>
{
    IPlayReadyMeteringReportServiceRequest(std::nullptr_t = nullptr) noexcept {}
};

struct WINRT_EBO IPlayReadyRevocationServiceRequest :
    Windows::Foundation::IInspectable,
    impl::consume_t<IPlayReadyRevocationServiceRequest>,
    impl::require<IPlayReadyRevocationServiceRequest, Windows::Media::Protection::IMediaProtectionServiceRequest, Windows::Media::Protection::PlayReady::IPlayReadyServiceRequest>
{
    IPlayReadyRevocationServiceRequest(std::nullptr_t = nullptr) noexcept {}
};

struct WINRT_EBO IPlayReadySecureStopIterableFactory :
    Windows::Foundation::IInspectable,
    impl::consume_t<IPlayReadySecureStopIterableFactory>
{
    IPlayReadySecureStopIterableFactory(std::nullptr_t = nullptr) noexcept {}
};

struct WINRT_EBO IPlayReadySecureStopServiceRequest :
    Windows::Foundation::IInspectable,
    impl::consume_t<IPlayReadySecureStopServiceRequest>,
    impl::require<IPlayReadySecureStopServiceRequest, Windows::Media::Protection::IMediaProtectionServiceRequest, Windows::Media::Protection::PlayReady::IPlayReadyServiceRequest>
{
    IPlayReadySecureStopServiceRequest(std::nullptr_t = nullptr) noexcept {}
};

struct WINRT_EBO IPlayReadySecureStopServiceRequestFactory :
    Windows::Foundation::IInspectable,
    impl::consume_t<IPlayReadySecureStopServiceRequestFactory>
{
    IPlayReadySecureStopServiceRequestFactory(std::nullptr_t = nullptr) noexcept {}
};

struct WINRT_EBO IPlayReadyServiceRequest :
    Windows::Foundation::IInspectable,
    impl::consume_t<IPlayReadyServiceRequest>,
    impl::require<IPlayReadyServiceRequest, Windows::Media::Protection::IMediaProtectionServiceRequest>
{
    IPlayReadyServiceRequest(std::nullptr_t = nullptr) noexcept {}
};

struct WINRT_EBO IPlayReadySoapMessage :
    Windows::Foundation::IInspectable,
    impl::consume_t<IPlayReadySoapMessage>
{
    IPlayReadySoapMessage(std::nullptr_t = nullptr) noexcept {}
};

struct WINRT_EBO IPlayReadyStatics :
    Windows::Foundation::IInspectable,
    impl::consume_t<IPlayReadyStatics>
{
    IPlayReadyStatics(std::nullptr_t = nullptr) noexcept {}
};

struct WINRT_EBO IPlayReadyStatics2 :
    Windows::Foundation::IInspectable,
    impl::consume_t<IPlayReadyStatics2>,
    impl::require<IPlayReadyStatics2, Windows::Media::Protection::PlayReady::IPlayReadyStatics>
{
    IPlayReadyStatics2(std::nullptr_t = nullptr) noexcept {}
};

struct WINRT_EBO IPlayReadyStatics3 :
    Windows::Foundation::IInspectable,
    impl::consume_t<IPlayReadyStatics3>,
    impl::require<IPlayReadyStatics3, Windows::Media::Protection::PlayReady::IPlayReadyStatics, Windows::Media::Protection::PlayReady::IPlayReadyStatics2>
{
    IPlayReadyStatics3(std::nullptr_t = nullptr) noexcept {}
};

struct WINRT_EBO IPlayReadyStatics4 :
    Windows::Foundation::IInspectable,
    impl::consume_t<IPlayReadyStatics4>,
    impl::require<IPlayReadyStatics4, Windows::Media::Protection::PlayReady::IPlayReadyStatics, Windows::Media::Protection::PlayReady::IPlayReadyStatics2, Windows::Media::Protection::PlayReady::IPlayReadyStatics3>
{
    IPlayReadyStatics4(std::nullptr_t = nullptr) noexcept {}
};

struct WINRT_EBO IPlayReadyStatics5 :
    Windows::Foundation::IInspectable,
    impl::consume_t<IPlayReadyStatics5>,
    impl::require<IPlayReadyStatics5, Windows::Media::Protection::PlayReady::IPlayReadyStatics, Windows::Media::Protection::PlayReady::IPlayReadyStatics2, Windows::Media::Protection::PlayReady::IPlayReadyStatics3, Windows::Media::Protection::PlayReady::IPlayReadyStatics4>
{
    IPlayReadyStatics5(std::nullptr_t = nullptr) noexcept {}
};

}
