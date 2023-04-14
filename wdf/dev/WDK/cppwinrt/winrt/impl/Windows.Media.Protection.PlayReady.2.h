// C++/WinRT v1.0.190111.3

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#pragma once
#include "winrt/impl/Windows.Foundation.1.h"
#include "winrt/impl/Windows.Foundation.Collections.1.h"
#include "winrt/impl/Windows.Media.Core.1.h"
#include "winrt/impl/Windows.Media.Protection.1.h"
#include "winrt/impl/Windows.Storage.1.h"
#include "winrt/impl/Windows.Media.Protection.PlayReady.1.h"

WINRT_EXPORT namespace winrt::Windows::Media::Protection::PlayReady {

}

namespace winrt::impl {

}

WINRT_EXPORT namespace winrt::Windows::Media::Protection::PlayReady {

struct WINRT_EBO NDClient :
    Windows::Media::Protection::PlayReady::INDClient
{
    NDClient(std::nullptr_t) noexcept {}
    NDClient(Windows::Media::Protection::PlayReady::INDDownloadEngine const& downloadEngine, Windows::Media::Protection::PlayReady::INDStreamParser const& streamParser, Windows::Media::Protection::PlayReady::INDMessenger const& pMessenger);
};

struct WINRT_EBO NDCustomData :
    Windows::Media::Protection::PlayReady::INDCustomData
{
    NDCustomData(std::nullptr_t) noexcept {}
    NDCustomData(array_view<uint8_t const> customDataTypeIDBytes, array_view<uint8_t const> customDataBytes);
};

struct WINRT_EBO NDDownloadEngineNotifier :
    Windows::Media::Protection::PlayReady::INDDownloadEngineNotifier
{
    NDDownloadEngineNotifier(std::nullptr_t) noexcept {}
    NDDownloadEngineNotifier();
};

struct WINRT_EBO NDLicenseFetchDescriptor :
    Windows::Media::Protection::PlayReady::INDLicenseFetchDescriptor
{
    NDLicenseFetchDescriptor(std::nullptr_t) noexcept {}
    NDLicenseFetchDescriptor(Windows::Media::Protection::PlayReady::NDContentIDType const& contentIDType, array_view<uint8_t const> contentIDBytes, Windows::Media::Protection::PlayReady::INDCustomData const& licenseFetchChallengeCustomData);
};

struct WINRT_EBO NDStorageFileHelper :
    Windows::Media::Protection::PlayReady::INDStorageFileHelper
{
    NDStorageFileHelper(std::nullptr_t) noexcept {}
    NDStorageFileHelper();
};

struct WINRT_EBO NDStreamParserNotifier :
    Windows::Media::Protection::PlayReady::INDStreamParserNotifier
{
    NDStreamParserNotifier(std::nullptr_t) noexcept {}
    NDStreamParserNotifier();
};

struct WINRT_EBO NDTCPMessenger :
    Windows::Media::Protection::PlayReady::INDMessenger
{
    NDTCPMessenger(std::nullptr_t) noexcept {}
    NDTCPMessenger(param::hstring const& remoteHostName, uint32_t remoteHostPort);
};

struct WINRT_EBO PlayReadyContentHeader :
    Windows::Media::Protection::PlayReady::IPlayReadyContentHeader,
    impl::require<PlayReadyContentHeader, Windows::Media::Protection::PlayReady::IPlayReadyContentHeader2>
{
    PlayReadyContentHeader(std::nullptr_t) noexcept {}
    PlayReadyContentHeader(array_view<uint8_t const> headerBytes, Windows::Foundation::Uri const& licenseAcquisitionUrl, Windows::Foundation::Uri const& licenseAcquisitionUserInterfaceUrl, param::hstring const& customAttributes, winrt::guid const& domainServiceId);
    PlayReadyContentHeader(winrt::guid const& contentKeyId, param::hstring const& contentKeyIdString, Windows::Media::Protection::PlayReady::PlayReadyEncryptionAlgorithm const& contentEncryptionAlgorithm, Windows::Foundation::Uri const& licenseAcquisitionUrl, Windows::Foundation::Uri const& licenseAcquisitionUserInterfaceUrl, param::hstring const& customAttributes, winrt::guid const& domainServiceId);
    PlayReadyContentHeader(array_view<uint8_t const> headerBytes);
    PlayReadyContentHeader(uint32_t dwFlags, array_view<winrt::guid const> contentKeyIds, array_view<hstring const> contentKeyIdStrings, Windows::Media::Protection::PlayReady::PlayReadyEncryptionAlgorithm const& contentEncryptionAlgorithm, Windows::Foundation::Uri const& licenseAcquisitionUrl, Windows::Foundation::Uri const& licenseAcquisitionUserInterfaceUrl, param::hstring const& customAttributes, winrt::guid const& domainServiceId);
};

struct PlayReadyContentResolver
{
    PlayReadyContentResolver() = delete;
    static Windows::Media::Protection::PlayReady::IPlayReadyServiceRequest ServiceRequest(Windows::Media::Protection::PlayReady::PlayReadyContentHeader const& contentHeader);
};

struct WINRT_EBO PlayReadyDomain :
    Windows::Media::Protection::PlayReady::IPlayReadyDomain
{
    PlayReadyDomain(std::nullptr_t) noexcept {}
};

struct WINRT_EBO PlayReadyDomainIterable :
    Windows::Foundation::Collections::IIterable<Windows::Media::Protection::PlayReady::IPlayReadyDomain>
{
    PlayReadyDomainIterable(std::nullptr_t) noexcept {}
    PlayReadyDomainIterable(winrt::guid const& domainAccountId);
};

struct WINRT_EBO PlayReadyDomainIterator :
    Windows::Foundation::Collections::IIterator<Windows::Media::Protection::PlayReady::IPlayReadyDomain>
{
    PlayReadyDomainIterator(std::nullptr_t) noexcept {}
};

struct WINRT_EBO PlayReadyDomainJoinServiceRequest :
    Windows::Media::Protection::PlayReady::IPlayReadyDomainJoinServiceRequest
{
    PlayReadyDomainJoinServiceRequest(std::nullptr_t) noexcept {}
    PlayReadyDomainJoinServiceRequest();
};

struct WINRT_EBO PlayReadyDomainLeaveServiceRequest :
    Windows::Media::Protection::PlayReady::IPlayReadyDomainLeaveServiceRequest
{
    PlayReadyDomainLeaveServiceRequest(std::nullptr_t) noexcept {}
    PlayReadyDomainLeaveServiceRequest();
};

struct WINRT_EBO PlayReadyITADataGenerator :
    Windows::Media::Protection::PlayReady::IPlayReadyITADataGenerator
{
    PlayReadyITADataGenerator(std::nullptr_t) noexcept {}
    PlayReadyITADataGenerator();
};

struct WINRT_EBO PlayReadyIndividualizationServiceRequest :
    Windows::Media::Protection::PlayReady::IPlayReadyIndividualizationServiceRequest
{
    PlayReadyIndividualizationServiceRequest(std::nullptr_t) noexcept {}
    PlayReadyIndividualizationServiceRequest();
};

struct WINRT_EBO PlayReadyLicense :
    Windows::Media::Protection::PlayReady::IPlayReadyLicense,
    impl::require<PlayReadyLicense, Windows::Media::Protection::PlayReady::IPlayReadyLicense2>
{
    PlayReadyLicense(std::nullptr_t) noexcept {}
};

struct WINRT_EBO PlayReadyLicenseAcquisitionServiceRequest :
    Windows::Media::Protection::PlayReady::IPlayReadyLicenseAcquisitionServiceRequest,
    impl::require<PlayReadyLicenseAcquisitionServiceRequest, Windows::Media::Protection::PlayReady::IPlayReadyLicenseAcquisitionServiceRequest2, Windows::Media::Protection::PlayReady::IPlayReadyLicenseAcquisitionServiceRequest3>
{
    PlayReadyLicenseAcquisitionServiceRequest(std::nullptr_t) noexcept {}
    PlayReadyLicenseAcquisitionServiceRequest();
};

struct WINRT_EBO PlayReadyLicenseIterable :
    Windows::Foundation::Collections::IIterable<Windows::Media::Protection::PlayReady::IPlayReadyLicense>
{
    PlayReadyLicenseIterable(std::nullptr_t) noexcept {}
    PlayReadyLicenseIterable();
    PlayReadyLicenseIterable(Windows::Media::Protection::PlayReady::PlayReadyContentHeader const& contentHeader, bool fullyEvaluated);
};

struct WINRT_EBO PlayReadyLicenseIterator :
    Windows::Foundation::Collections::IIterator<Windows::Media::Protection::PlayReady::IPlayReadyLicense>
{
    PlayReadyLicenseIterator(std::nullptr_t) noexcept {}
};

struct PlayReadyLicenseManagement
{
    PlayReadyLicenseManagement() = delete;
    static Windows::Foundation::IAsyncAction DeleteLicenses(Windows::Media::Protection::PlayReady::PlayReadyContentHeader const& contentHeader);
};

struct WINRT_EBO PlayReadyLicenseSession :
    Windows::Media::Protection::PlayReady::IPlayReadyLicenseSession,
    impl::require<PlayReadyLicenseSession, Windows::Media::Protection::PlayReady::IPlayReadyLicenseSession2>
{
    PlayReadyLicenseSession(std::nullptr_t) noexcept {}
    PlayReadyLicenseSession(Windows::Foundation::Collections::IPropertySet const& configuration);
};

struct WINRT_EBO PlayReadyMeteringReportServiceRequest :
    Windows::Media::Protection::PlayReady::IPlayReadyMeteringReportServiceRequest
{
    PlayReadyMeteringReportServiceRequest(std::nullptr_t) noexcept {}
    PlayReadyMeteringReportServiceRequest();
};

struct WINRT_EBO PlayReadyRevocationServiceRequest :
    Windows::Media::Protection::PlayReady::IPlayReadyRevocationServiceRequest
{
    PlayReadyRevocationServiceRequest(std::nullptr_t) noexcept {}
    PlayReadyRevocationServiceRequest();
};

struct WINRT_EBO PlayReadySecureStopIterable :
    Windows::Foundation::Collections::IIterable<Windows::Media::Protection::PlayReady::IPlayReadySecureStopServiceRequest>
{
    PlayReadySecureStopIterable(std::nullptr_t) noexcept {}
    PlayReadySecureStopIterable(array_view<uint8_t const> publisherCertBytes);
};

struct WINRT_EBO PlayReadySecureStopIterator :
    Windows::Foundation::Collections::IIterator<Windows::Media::Protection::PlayReady::IPlayReadySecureStopServiceRequest>
{
    PlayReadySecureStopIterator(std::nullptr_t) noexcept {}
};

struct WINRT_EBO PlayReadySecureStopServiceRequest :
    Windows::Media::Protection::PlayReady::IPlayReadySecureStopServiceRequest
{
    PlayReadySecureStopServiceRequest(std::nullptr_t) noexcept {}
    PlayReadySecureStopServiceRequest(array_view<uint8_t const> publisherCertBytes);
    PlayReadySecureStopServiceRequest(winrt::guid const& sessionID, array_view<uint8_t const> publisherCertBytes);
};

struct WINRT_EBO PlayReadySoapMessage :
    Windows::Media::Protection::PlayReady::IPlayReadySoapMessage
{
    PlayReadySoapMessage(std::nullptr_t) noexcept {}
};

struct PlayReadyStatics
{
    PlayReadyStatics() = delete;
    static winrt::guid DomainJoinServiceRequestType();
    static winrt::guid DomainLeaveServiceRequestType();
    static winrt::guid IndividualizationServiceRequestType();
    static winrt::guid LicenseAcquirerServiceRequestType();
    static winrt::guid MeteringReportServiceRequestType();
    static winrt::guid RevocationServiceRequestType();
    static winrt::guid MediaProtectionSystemId();
    static uint32_t PlayReadySecurityVersion();
    static uint32_t PlayReadyCertificateSecurityLevel();
    static winrt::guid SecureStopServiceRequestType();
    static bool CheckSupportedHardware(Windows::Media::Protection::PlayReady::PlayReadyHardwareDRMFeatures const& hwdrmFeature);
    static hstring InputTrustAuthorityToCreate();
    static winrt::guid ProtectionSystemId();
    static Windows::Foundation::IReference<Windows::Foundation::DateTime> HardwareDRMDisabledAtTime();
    static Windows::Foundation::IReference<Windows::Foundation::DateTime> HardwareDRMDisabledUntilTime();
    static void ResetHardwareDRMDisabled();
};

}
