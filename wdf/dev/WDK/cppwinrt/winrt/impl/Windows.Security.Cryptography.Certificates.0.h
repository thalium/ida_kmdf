// C++/WinRT v1.0.190111.3

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#pragma once

WINRT_EXPORT namespace winrt::Windows::Networking {

struct HostName;

}

WINRT_EXPORT namespace winrt::Windows::Storage::Streams {

struct IBuffer;
struct IInputStream;

}

WINRT_EXPORT namespace winrt::Windows::Security::Cryptography::Certificates {

enum class CertificateChainPolicy : int32_t
{
    Base = 0,
    Ssl = 1,
    NTAuthentication = 2,
    MicrosoftRoot = 3,
};

enum class ChainValidationResult : int32_t
{
    Success = 0,
    Untrusted = 1,
    Revoked = 2,
    Expired = 3,
    IncompleteChain = 4,
    InvalidSignature = 5,
    WrongUsage = 6,
    InvalidName = 7,
    InvalidCertificateAuthorityPolicy = 8,
    BasicConstraintsError = 9,
    UnknownCriticalExtension = 10,
    RevocationInformationMissing = 11,
    RevocationFailure = 12,
    OtherErrors = 13,
};

enum class EnrollKeyUsages : uint32_t
{
    None = 0x0,
    Decryption = 0x1,
    Signing = 0x2,
    KeyAgreement = 0x4,
    All = 0xFFFFFF,
};

enum class ExportOption : int32_t
{
    NotExportable = 0,
    Exportable = 1,
};

enum class InstallOptions : uint32_t
{
    None = 0x0,
    DeleteExpired = 0x1,
};

enum class KeyProtectionLevel : int32_t
{
    NoConsent = 0,
    ConsentOnly = 1,
    ConsentWithPassword = 2,
    ConsentWithFingerprint = 3,
};

enum class KeySize : int32_t
{
    Invalid = 0,
    Rsa2048 = 2048,
    Rsa4096 = 4096,
};

enum class SignatureValidationResult : int32_t
{
    Success = 0,
    InvalidParameter = 1,
    BadMessage = 2,
    InvalidSignature = 3,
    OtherErrors = 4,
};

struct ICertificate;
struct ICertificate2;
struct ICertificate3;
struct ICertificateChain;
struct ICertificateEnrollmentManagerStatics;
struct ICertificateEnrollmentManagerStatics2;
struct ICertificateEnrollmentManagerStatics3;
struct ICertificateExtension;
struct ICertificateFactory;
struct ICertificateKeyUsages;
struct ICertificateQuery;
struct ICertificateQuery2;
struct ICertificateRequestProperties;
struct ICertificateRequestProperties2;
struct ICertificateRequestProperties3;
struct ICertificateRequestProperties4;
struct ICertificateStore;
struct ICertificateStore2;
struct ICertificateStoresStatics;
struct ICertificateStoresStatics2;
struct IChainBuildingParameters;
struct IChainValidationParameters;
struct ICmsAttachedSignature;
struct ICmsAttachedSignatureFactory;
struct ICmsAttachedSignatureStatics;
struct ICmsDetachedSignature;
struct ICmsDetachedSignatureFactory;
struct ICmsDetachedSignatureStatics;
struct ICmsSignerInfo;
struct ICmsTimestampInfo;
struct IKeyAlgorithmNamesStatics;
struct IKeyAlgorithmNamesStatics2;
struct IKeyAttestationHelperStatics;
struct IKeyAttestationHelperStatics2;
struct IKeyStorageProviderNamesStatics;
struct IKeyStorageProviderNamesStatics2;
struct IPfxImportParameters;
struct IStandardCertificateStoreNamesStatics;
struct ISubjectAlternativeNameInfo;
struct ISubjectAlternativeNameInfo2;
struct IUserCertificateEnrollmentManager;
struct IUserCertificateEnrollmentManager2;
struct IUserCertificateStore;
struct Certificate;
struct CertificateChain;
struct CertificateEnrollmentManager;
struct CertificateExtension;
struct CertificateKeyUsages;
struct CertificateQuery;
struct CertificateRequestProperties;
struct CertificateStore;
struct CertificateStores;
struct ChainBuildingParameters;
struct ChainValidationParameters;
struct CmsAttachedSignature;
struct CmsDetachedSignature;
struct CmsSignerInfo;
struct CmsTimestampInfo;
struct KeyAlgorithmNames;
struct KeyAttestationHelper;
struct KeyStorageProviderNames;
struct PfxImportParameters;
struct StandardCertificateStoreNames;
struct SubjectAlternativeNameInfo;
struct UserCertificateEnrollmentManager;
struct UserCertificateStore;

}

namespace winrt::impl {

template<> struct is_enum_flag<Windows::Security::Cryptography::Certificates::EnrollKeyUsages> : std::true_type {};
template<> struct is_enum_flag<Windows::Security::Cryptography::Certificates::InstallOptions> : std::true_type {};
template <> struct category<Windows::Security::Cryptography::Certificates::ICertificate>{ using type = interface_category; };
template <> struct category<Windows::Security::Cryptography::Certificates::ICertificate2>{ using type = interface_category; };
template <> struct category<Windows::Security::Cryptography::Certificates::ICertificate3>{ using type = interface_category; };
template <> struct category<Windows::Security::Cryptography::Certificates::ICertificateChain>{ using type = interface_category; };
template <> struct category<Windows::Security::Cryptography::Certificates::ICertificateEnrollmentManagerStatics>{ using type = interface_category; };
template <> struct category<Windows::Security::Cryptography::Certificates::ICertificateEnrollmentManagerStatics2>{ using type = interface_category; };
template <> struct category<Windows::Security::Cryptography::Certificates::ICertificateEnrollmentManagerStatics3>{ using type = interface_category; };
template <> struct category<Windows::Security::Cryptography::Certificates::ICertificateExtension>{ using type = interface_category; };
template <> struct category<Windows::Security::Cryptography::Certificates::ICertificateFactory>{ using type = interface_category; };
template <> struct category<Windows::Security::Cryptography::Certificates::ICertificateKeyUsages>{ using type = interface_category; };
template <> struct category<Windows::Security::Cryptography::Certificates::ICertificateQuery>{ using type = interface_category; };
template <> struct category<Windows::Security::Cryptography::Certificates::ICertificateQuery2>{ using type = interface_category; };
template <> struct category<Windows::Security::Cryptography::Certificates::ICertificateRequestProperties>{ using type = interface_category; };
template <> struct category<Windows::Security::Cryptography::Certificates::ICertificateRequestProperties2>{ using type = interface_category; };
template <> struct category<Windows::Security::Cryptography::Certificates::ICertificateRequestProperties3>{ using type = interface_category; };
template <> struct category<Windows::Security::Cryptography::Certificates::ICertificateRequestProperties4>{ using type = interface_category; };
template <> struct category<Windows::Security::Cryptography::Certificates::ICertificateStore>{ using type = interface_category; };
template <> struct category<Windows::Security::Cryptography::Certificates::ICertificateStore2>{ using type = interface_category; };
template <> struct category<Windows::Security::Cryptography::Certificates::ICertificateStoresStatics>{ using type = interface_category; };
template <> struct category<Windows::Security::Cryptography::Certificates::ICertificateStoresStatics2>{ using type = interface_category; };
template <> struct category<Windows::Security::Cryptography::Certificates::IChainBuildingParameters>{ using type = interface_category; };
template <> struct category<Windows::Security::Cryptography::Certificates::IChainValidationParameters>{ using type = interface_category; };
template <> struct category<Windows::Security::Cryptography::Certificates::ICmsAttachedSignature>{ using type = interface_category; };
template <> struct category<Windows::Security::Cryptography::Certificates::ICmsAttachedSignatureFactory>{ using type = interface_category; };
template <> struct category<Windows::Security::Cryptography::Certificates::ICmsAttachedSignatureStatics>{ using type = interface_category; };
template <> struct category<Windows::Security::Cryptography::Certificates::ICmsDetachedSignature>{ using type = interface_category; };
template <> struct category<Windows::Security::Cryptography::Certificates::ICmsDetachedSignatureFactory>{ using type = interface_category; };
template <> struct category<Windows::Security::Cryptography::Certificates::ICmsDetachedSignatureStatics>{ using type = interface_category; };
template <> struct category<Windows::Security::Cryptography::Certificates::ICmsSignerInfo>{ using type = interface_category; };
template <> struct category<Windows::Security::Cryptography::Certificates::ICmsTimestampInfo>{ using type = interface_category; };
template <> struct category<Windows::Security::Cryptography::Certificates::IKeyAlgorithmNamesStatics>{ using type = interface_category; };
template <> struct category<Windows::Security::Cryptography::Certificates::IKeyAlgorithmNamesStatics2>{ using type = interface_category; };
template <> struct category<Windows::Security::Cryptography::Certificates::IKeyAttestationHelperStatics>{ using type = interface_category; };
template <> struct category<Windows::Security::Cryptography::Certificates::IKeyAttestationHelperStatics2>{ using type = interface_category; };
template <> struct category<Windows::Security::Cryptography::Certificates::IKeyStorageProviderNamesStatics>{ using type = interface_category; };
template <> struct category<Windows::Security::Cryptography::Certificates::IKeyStorageProviderNamesStatics2>{ using type = interface_category; };
template <> struct category<Windows::Security::Cryptography::Certificates::IPfxImportParameters>{ using type = interface_category; };
template <> struct category<Windows::Security::Cryptography::Certificates::IStandardCertificateStoreNamesStatics>{ using type = interface_category; };
template <> struct category<Windows::Security::Cryptography::Certificates::ISubjectAlternativeNameInfo>{ using type = interface_category; };
template <> struct category<Windows::Security::Cryptography::Certificates::ISubjectAlternativeNameInfo2>{ using type = interface_category; };
template <> struct category<Windows::Security::Cryptography::Certificates::IUserCertificateEnrollmentManager>{ using type = interface_category; };
template <> struct category<Windows::Security::Cryptography::Certificates::IUserCertificateEnrollmentManager2>{ using type = interface_category; };
template <> struct category<Windows::Security::Cryptography::Certificates::IUserCertificateStore>{ using type = interface_category; };
template <> struct category<Windows::Security::Cryptography::Certificates::Certificate>{ using type = class_category; };
template <> struct category<Windows::Security::Cryptography::Certificates::CertificateChain>{ using type = class_category; };
template <> struct category<Windows::Security::Cryptography::Certificates::CertificateEnrollmentManager>{ using type = class_category; };
template <> struct category<Windows::Security::Cryptography::Certificates::CertificateExtension>{ using type = class_category; };
template <> struct category<Windows::Security::Cryptography::Certificates::CertificateKeyUsages>{ using type = class_category; };
template <> struct category<Windows::Security::Cryptography::Certificates::CertificateQuery>{ using type = class_category; };
template <> struct category<Windows::Security::Cryptography::Certificates::CertificateRequestProperties>{ using type = class_category; };
template <> struct category<Windows::Security::Cryptography::Certificates::CertificateStore>{ using type = class_category; };
template <> struct category<Windows::Security::Cryptography::Certificates::CertificateStores>{ using type = class_category; };
template <> struct category<Windows::Security::Cryptography::Certificates::ChainBuildingParameters>{ using type = class_category; };
template <> struct category<Windows::Security::Cryptography::Certificates::ChainValidationParameters>{ using type = class_category; };
template <> struct category<Windows::Security::Cryptography::Certificates::CmsAttachedSignature>{ using type = class_category; };
template <> struct category<Windows::Security::Cryptography::Certificates::CmsDetachedSignature>{ using type = class_category; };
template <> struct category<Windows::Security::Cryptography::Certificates::CmsSignerInfo>{ using type = class_category; };
template <> struct category<Windows::Security::Cryptography::Certificates::CmsTimestampInfo>{ using type = class_category; };
template <> struct category<Windows::Security::Cryptography::Certificates::KeyAlgorithmNames>{ using type = class_category; };
template <> struct category<Windows::Security::Cryptography::Certificates::KeyAttestationHelper>{ using type = class_category; };
template <> struct category<Windows::Security::Cryptography::Certificates::KeyStorageProviderNames>{ using type = class_category; };
template <> struct category<Windows::Security::Cryptography::Certificates::PfxImportParameters>{ using type = class_category; };
template <> struct category<Windows::Security::Cryptography::Certificates::StandardCertificateStoreNames>{ using type = class_category; };
template <> struct category<Windows::Security::Cryptography::Certificates::SubjectAlternativeNameInfo>{ using type = class_category; };
template <> struct category<Windows::Security::Cryptography::Certificates::UserCertificateEnrollmentManager>{ using type = class_category; };
template <> struct category<Windows::Security::Cryptography::Certificates::UserCertificateStore>{ using type = class_category; };
template <> struct category<Windows::Security::Cryptography::Certificates::CertificateChainPolicy>{ using type = enum_category; };
template <> struct category<Windows::Security::Cryptography::Certificates::ChainValidationResult>{ using type = enum_category; };
template <> struct category<Windows::Security::Cryptography::Certificates::EnrollKeyUsages>{ using type = enum_category; };
template <> struct category<Windows::Security::Cryptography::Certificates::ExportOption>{ using type = enum_category; };
template <> struct category<Windows::Security::Cryptography::Certificates::InstallOptions>{ using type = enum_category; };
template <> struct category<Windows::Security::Cryptography::Certificates::KeyProtectionLevel>{ using type = enum_category; };
template <> struct category<Windows::Security::Cryptography::Certificates::KeySize>{ using type = enum_category; };
template <> struct category<Windows::Security::Cryptography::Certificates::SignatureValidationResult>{ using type = enum_category; };
template <> struct name<Windows::Security::Cryptography::Certificates::ICertificate>{ static constexpr auto & value{ L"Windows.Security.Cryptography.Certificates.ICertificate" }; };
template <> struct name<Windows::Security::Cryptography::Certificates::ICertificate2>{ static constexpr auto & value{ L"Windows.Security.Cryptography.Certificates.ICertificate2" }; };
template <> struct name<Windows::Security::Cryptography::Certificates::ICertificate3>{ static constexpr auto & value{ L"Windows.Security.Cryptography.Certificates.ICertificate3" }; };
template <> struct name<Windows::Security::Cryptography::Certificates::ICertificateChain>{ static constexpr auto & value{ L"Windows.Security.Cryptography.Certificates.ICertificateChain" }; };
template <> struct name<Windows::Security::Cryptography::Certificates::ICertificateEnrollmentManagerStatics>{ static constexpr auto & value{ L"Windows.Security.Cryptography.Certificates.ICertificateEnrollmentManagerStatics" }; };
template <> struct name<Windows::Security::Cryptography::Certificates::ICertificateEnrollmentManagerStatics2>{ static constexpr auto & value{ L"Windows.Security.Cryptography.Certificates.ICertificateEnrollmentManagerStatics2" }; };
template <> struct name<Windows::Security::Cryptography::Certificates::ICertificateEnrollmentManagerStatics3>{ static constexpr auto & value{ L"Windows.Security.Cryptography.Certificates.ICertificateEnrollmentManagerStatics3" }; };
template <> struct name<Windows::Security::Cryptography::Certificates::ICertificateExtension>{ static constexpr auto & value{ L"Windows.Security.Cryptography.Certificates.ICertificateExtension" }; };
template <> struct name<Windows::Security::Cryptography::Certificates::ICertificateFactory>{ static constexpr auto & value{ L"Windows.Security.Cryptography.Certificates.ICertificateFactory" }; };
template <> struct name<Windows::Security::Cryptography::Certificates::ICertificateKeyUsages>{ static constexpr auto & value{ L"Windows.Security.Cryptography.Certificates.ICertificateKeyUsages" }; };
template <> struct name<Windows::Security::Cryptography::Certificates::ICertificateQuery>{ static constexpr auto & value{ L"Windows.Security.Cryptography.Certificates.ICertificateQuery" }; };
template <> struct name<Windows::Security::Cryptography::Certificates::ICertificateQuery2>{ static constexpr auto & value{ L"Windows.Security.Cryptography.Certificates.ICertificateQuery2" }; };
template <> struct name<Windows::Security::Cryptography::Certificates::ICertificateRequestProperties>{ static constexpr auto & value{ L"Windows.Security.Cryptography.Certificates.ICertificateRequestProperties" }; };
template <> struct name<Windows::Security::Cryptography::Certificates::ICertificateRequestProperties2>{ static constexpr auto & value{ L"Windows.Security.Cryptography.Certificates.ICertificateRequestProperties2" }; };
template <> struct name<Windows::Security::Cryptography::Certificates::ICertificateRequestProperties3>{ static constexpr auto & value{ L"Windows.Security.Cryptography.Certificates.ICertificateRequestProperties3" }; };
template <> struct name<Windows::Security::Cryptography::Certificates::ICertificateRequestProperties4>{ static constexpr auto & value{ L"Windows.Security.Cryptography.Certificates.ICertificateRequestProperties4" }; };
template <> struct name<Windows::Security::Cryptography::Certificates::ICertificateStore>{ static constexpr auto & value{ L"Windows.Security.Cryptography.Certificates.ICertificateStore" }; };
template <> struct name<Windows::Security::Cryptography::Certificates::ICertificateStore2>{ static constexpr auto & value{ L"Windows.Security.Cryptography.Certificates.ICertificateStore2" }; };
template <> struct name<Windows::Security::Cryptography::Certificates::ICertificateStoresStatics>{ static constexpr auto & value{ L"Windows.Security.Cryptography.Certificates.ICertificateStoresStatics" }; };
template <> struct name<Windows::Security::Cryptography::Certificates::ICertificateStoresStatics2>{ static constexpr auto & value{ L"Windows.Security.Cryptography.Certificates.ICertificateStoresStatics2" }; };
template <> struct name<Windows::Security::Cryptography::Certificates::IChainBuildingParameters>{ static constexpr auto & value{ L"Windows.Security.Cryptography.Certificates.IChainBuildingParameters" }; };
template <> struct name<Windows::Security::Cryptography::Certificates::IChainValidationParameters>{ static constexpr auto & value{ L"Windows.Security.Cryptography.Certificates.IChainValidationParameters" }; };
template <> struct name<Windows::Security::Cryptography::Certificates::ICmsAttachedSignature>{ static constexpr auto & value{ L"Windows.Security.Cryptography.Certificates.ICmsAttachedSignature" }; };
template <> struct name<Windows::Security::Cryptography::Certificates::ICmsAttachedSignatureFactory>{ static constexpr auto & value{ L"Windows.Security.Cryptography.Certificates.ICmsAttachedSignatureFactory" }; };
template <> struct name<Windows::Security::Cryptography::Certificates::ICmsAttachedSignatureStatics>{ static constexpr auto & value{ L"Windows.Security.Cryptography.Certificates.ICmsAttachedSignatureStatics" }; };
template <> struct name<Windows::Security::Cryptography::Certificates::ICmsDetachedSignature>{ static constexpr auto & value{ L"Windows.Security.Cryptography.Certificates.ICmsDetachedSignature" }; };
template <> struct name<Windows::Security::Cryptography::Certificates::ICmsDetachedSignatureFactory>{ static constexpr auto & value{ L"Windows.Security.Cryptography.Certificates.ICmsDetachedSignatureFactory" }; };
template <> struct name<Windows::Security::Cryptography::Certificates::ICmsDetachedSignatureStatics>{ static constexpr auto & value{ L"Windows.Security.Cryptography.Certificates.ICmsDetachedSignatureStatics" }; };
template <> struct name<Windows::Security::Cryptography::Certificates::ICmsSignerInfo>{ static constexpr auto & value{ L"Windows.Security.Cryptography.Certificates.ICmsSignerInfo" }; };
template <> struct name<Windows::Security::Cryptography::Certificates::ICmsTimestampInfo>{ static constexpr auto & value{ L"Windows.Security.Cryptography.Certificates.ICmsTimestampInfo" }; };
template <> struct name<Windows::Security::Cryptography::Certificates::IKeyAlgorithmNamesStatics>{ static constexpr auto & value{ L"Windows.Security.Cryptography.Certificates.IKeyAlgorithmNamesStatics" }; };
template <> struct name<Windows::Security::Cryptography::Certificates::IKeyAlgorithmNamesStatics2>{ static constexpr auto & value{ L"Windows.Security.Cryptography.Certificates.IKeyAlgorithmNamesStatics2" }; };
template <> struct name<Windows::Security::Cryptography::Certificates::IKeyAttestationHelperStatics>{ static constexpr auto & value{ L"Windows.Security.Cryptography.Certificates.IKeyAttestationHelperStatics" }; };
template <> struct name<Windows::Security::Cryptography::Certificates::IKeyAttestationHelperStatics2>{ static constexpr auto & value{ L"Windows.Security.Cryptography.Certificates.IKeyAttestationHelperStatics2" }; };
template <> struct name<Windows::Security::Cryptography::Certificates::IKeyStorageProviderNamesStatics>{ static constexpr auto & value{ L"Windows.Security.Cryptography.Certificates.IKeyStorageProviderNamesStatics" }; };
template <> struct name<Windows::Security::Cryptography::Certificates::IKeyStorageProviderNamesStatics2>{ static constexpr auto & value{ L"Windows.Security.Cryptography.Certificates.IKeyStorageProviderNamesStatics2" }; };
template <> struct name<Windows::Security::Cryptography::Certificates::IPfxImportParameters>{ static constexpr auto & value{ L"Windows.Security.Cryptography.Certificates.IPfxImportParameters" }; };
template <> struct name<Windows::Security::Cryptography::Certificates::IStandardCertificateStoreNamesStatics>{ static constexpr auto & value{ L"Windows.Security.Cryptography.Certificates.IStandardCertificateStoreNamesStatics" }; };
template <> struct name<Windows::Security::Cryptography::Certificates::ISubjectAlternativeNameInfo>{ static constexpr auto & value{ L"Windows.Security.Cryptography.Certificates.ISubjectAlternativeNameInfo" }; };
template <> struct name<Windows::Security::Cryptography::Certificates::ISubjectAlternativeNameInfo2>{ static constexpr auto & value{ L"Windows.Security.Cryptography.Certificates.ISubjectAlternativeNameInfo2" }; };
template <> struct name<Windows::Security::Cryptography::Certificates::IUserCertificateEnrollmentManager>{ static constexpr auto & value{ L"Windows.Security.Cryptography.Certificates.IUserCertificateEnrollmentManager" }; };
template <> struct name<Windows::Security::Cryptography::Certificates::IUserCertificateEnrollmentManager2>{ static constexpr auto & value{ L"Windows.Security.Cryptography.Certificates.IUserCertificateEnrollmentManager2" }; };
template <> struct name<Windows::Security::Cryptography::Certificates::IUserCertificateStore>{ static constexpr auto & value{ L"Windows.Security.Cryptography.Certificates.IUserCertificateStore" }; };
template <> struct name<Windows::Security::Cryptography::Certificates::Certificate>{ static constexpr auto & value{ L"Windows.Security.Cryptography.Certificates.Certificate" }; };
template <> struct name<Windows::Security::Cryptography::Certificates::CertificateChain>{ static constexpr auto & value{ L"Windows.Security.Cryptography.Certificates.CertificateChain" }; };
template <> struct name<Windows::Security::Cryptography::Certificates::CertificateEnrollmentManager>{ static constexpr auto & value{ L"Windows.Security.Cryptography.Certificates.CertificateEnrollmentManager" }; };
template <> struct name<Windows::Security::Cryptography::Certificates::CertificateExtension>{ static constexpr auto & value{ L"Windows.Security.Cryptography.Certificates.CertificateExtension" }; };
template <> struct name<Windows::Security::Cryptography::Certificates::CertificateKeyUsages>{ static constexpr auto & value{ L"Windows.Security.Cryptography.Certificates.CertificateKeyUsages" }; };
template <> struct name<Windows::Security::Cryptography::Certificates::CertificateQuery>{ static constexpr auto & value{ L"Windows.Security.Cryptography.Certificates.CertificateQuery" }; };
template <> struct name<Windows::Security::Cryptography::Certificates::CertificateRequestProperties>{ static constexpr auto & value{ L"Windows.Security.Cryptography.Certificates.CertificateRequestProperties" }; };
template <> struct name<Windows::Security::Cryptography::Certificates::CertificateStore>{ static constexpr auto & value{ L"Windows.Security.Cryptography.Certificates.CertificateStore" }; };
template <> struct name<Windows::Security::Cryptography::Certificates::CertificateStores>{ static constexpr auto & value{ L"Windows.Security.Cryptography.Certificates.CertificateStores" }; };
template <> struct name<Windows::Security::Cryptography::Certificates::ChainBuildingParameters>{ static constexpr auto & value{ L"Windows.Security.Cryptography.Certificates.ChainBuildingParameters" }; };
template <> struct name<Windows::Security::Cryptography::Certificates::ChainValidationParameters>{ static constexpr auto & value{ L"Windows.Security.Cryptography.Certificates.ChainValidationParameters" }; };
template <> struct name<Windows::Security::Cryptography::Certificates::CmsAttachedSignature>{ static constexpr auto & value{ L"Windows.Security.Cryptography.Certificates.CmsAttachedSignature" }; };
template <> struct name<Windows::Security::Cryptography::Certificates::CmsDetachedSignature>{ static constexpr auto & value{ L"Windows.Security.Cryptography.Certificates.CmsDetachedSignature" }; };
template <> struct name<Windows::Security::Cryptography::Certificates::CmsSignerInfo>{ static constexpr auto & value{ L"Windows.Security.Cryptography.Certificates.CmsSignerInfo" }; };
template <> struct name<Windows::Security::Cryptography::Certificates::CmsTimestampInfo>{ static constexpr auto & value{ L"Windows.Security.Cryptography.Certificates.CmsTimestampInfo" }; };
template <> struct name<Windows::Security::Cryptography::Certificates::KeyAlgorithmNames>{ static constexpr auto & value{ L"Windows.Security.Cryptography.Certificates.KeyAlgorithmNames" }; };
template <> struct name<Windows::Security::Cryptography::Certificates::KeyAttestationHelper>{ static constexpr auto & value{ L"Windows.Security.Cryptography.Certificates.KeyAttestationHelper" }; };
template <> struct name<Windows::Security::Cryptography::Certificates::KeyStorageProviderNames>{ static constexpr auto & value{ L"Windows.Security.Cryptography.Certificates.KeyStorageProviderNames" }; };
template <> struct name<Windows::Security::Cryptography::Certificates::PfxImportParameters>{ static constexpr auto & value{ L"Windows.Security.Cryptography.Certificates.PfxImportParameters" }; };
template <> struct name<Windows::Security::Cryptography::Certificates::StandardCertificateStoreNames>{ static constexpr auto & value{ L"Windows.Security.Cryptography.Certificates.StandardCertificateStoreNames" }; };
template <> struct name<Windows::Security::Cryptography::Certificates::SubjectAlternativeNameInfo>{ static constexpr auto & value{ L"Windows.Security.Cryptography.Certificates.SubjectAlternativeNameInfo" }; };
template <> struct name<Windows::Security::Cryptography::Certificates::UserCertificateEnrollmentManager>{ static constexpr auto & value{ L"Windows.Security.Cryptography.Certificates.UserCertificateEnrollmentManager" }; };
template <> struct name<Windows::Security::Cryptography::Certificates::UserCertificateStore>{ static constexpr auto & value{ L"Windows.Security.Cryptography.Certificates.UserCertificateStore" }; };
template <> struct name<Windows::Security::Cryptography::Certificates::CertificateChainPolicy>{ static constexpr auto & value{ L"Windows.Security.Cryptography.Certificates.CertificateChainPolicy" }; };
template <> struct name<Windows::Security::Cryptography::Certificates::ChainValidationResult>{ static constexpr auto & value{ L"Windows.Security.Cryptography.Certificates.ChainValidationResult" }; };
template <> struct name<Windows::Security::Cryptography::Certificates::EnrollKeyUsages>{ static constexpr auto & value{ L"Windows.Security.Cryptography.Certificates.EnrollKeyUsages" }; };
template <> struct name<Windows::Security::Cryptography::Certificates::ExportOption>{ static constexpr auto & value{ L"Windows.Security.Cryptography.Certificates.ExportOption" }; };
template <> struct name<Windows::Security::Cryptography::Certificates::InstallOptions>{ static constexpr auto & value{ L"Windows.Security.Cryptography.Certificates.InstallOptions" }; };
template <> struct name<Windows::Security::Cryptography::Certificates::KeyProtectionLevel>{ static constexpr auto & value{ L"Windows.Security.Cryptography.Certificates.KeyProtectionLevel" }; };
template <> struct name<Windows::Security::Cryptography::Certificates::KeySize>{ static constexpr auto & value{ L"Windows.Security.Cryptography.Certificates.KeySize" }; };
template <> struct name<Windows::Security::Cryptography::Certificates::SignatureValidationResult>{ static constexpr auto & value{ L"Windows.Security.Cryptography.Certificates.SignatureValidationResult" }; };
template <> struct guid_storage<Windows::Security::Cryptography::Certificates::ICertificate>{ static constexpr guid value{ 0x333F740C,0x04D8,0x43B3,{ 0xB2,0x78,0x8C,0x5F,0xCC,0x9B,0xE5,0xA0 } }; };
template <> struct guid_storage<Windows::Security::Cryptography::Certificates::ICertificate2>{ static constexpr guid value{ 0x17B8374C,0x8A25,0x4D96,{ 0xA4,0x92,0x8F,0xC2,0x9A,0xC4,0xFD,0xA6 } }; };
template <> struct guid_storage<Windows::Security::Cryptography::Certificates::ICertificate3>{ static constexpr guid value{ 0xBE51A966,0xAE5F,0x4652,{ 0xAC,0xE7,0xC6,0xD7,0xE7,0x72,0x4C,0xF3 } }; };
template <> struct guid_storage<Windows::Security::Cryptography::Certificates::ICertificateChain>{ static constexpr guid value{ 0x20BF5385,0x3691,0x4501,{ 0xA6,0x2C,0xFD,0x97,0x27,0x8B,0x31,0xEE } }; };
template <> struct guid_storage<Windows::Security::Cryptography::Certificates::ICertificateEnrollmentManagerStatics>{ static constexpr guid value{ 0x8846EF3F,0xA986,0x48FB,{ 0x9F,0xD7,0x9A,0xEC,0x06,0x93,0x5B,0xF1 } }; };
template <> struct guid_storage<Windows::Security::Cryptography::Certificates::ICertificateEnrollmentManagerStatics2>{ static constexpr guid value{ 0xDC5B1C33,0x6429,0x4014,{ 0x99,0x9C,0x5D,0x97,0x35,0x80,0x2D,0x1D } }; };
template <> struct guid_storage<Windows::Security::Cryptography::Certificates::ICertificateEnrollmentManagerStatics3>{ static constexpr guid value{ 0xFDEC82BE,0x617C,0x425A,{ 0xB7,0x2D,0x39,0x8B,0x26,0xAC,0x72,0x64 } }; };
template <> struct guid_storage<Windows::Security::Cryptography::Certificates::ICertificateExtension>{ static constexpr guid value{ 0x84CF0656,0xA9E6,0x454D,{ 0x8E,0x45,0x2E,0xA7,0xC4,0xBC,0xD5,0x3B } }; };
template <> struct guid_storage<Windows::Security::Cryptography::Certificates::ICertificateFactory>{ static constexpr guid value{ 0x17B4221C,0x4BAF,0x44A2,{ 0x96,0x08,0x04,0xFB,0x62,0xB1,0x69,0x42 } }; };
template <> struct guid_storage<Windows::Security::Cryptography::Certificates::ICertificateKeyUsages>{ static constexpr guid value{ 0x6AC6206F,0xE1CF,0x486A,{ 0xB4,0x85,0xA6,0x9C,0x83,0xE4,0x6F,0xD1 } }; };
template <> struct guid_storage<Windows::Security::Cryptography::Certificates::ICertificateQuery>{ static constexpr guid value{ 0x5B082A31,0xA728,0x4916,{ 0xB5,0xEE,0xFF,0xCB,0x8A,0xCF,0x24,0x17 } }; };
template <> struct guid_storage<Windows::Security::Cryptography::Certificates::ICertificateQuery2>{ static constexpr guid value{ 0x935A0AF7,0x0BD9,0x4F75,{ 0xB8,0xC2,0xE2,0x7A,0x7F,0x74,0xEE,0xCD } }; };
template <> struct guid_storage<Windows::Security::Cryptography::Certificates::ICertificateRequestProperties>{ static constexpr guid value{ 0x487E84F6,0x94E2,0x4DCE,{ 0x88,0x33,0x1A,0x70,0x0A,0x37,0xA2,0x9A } }; };
template <> struct guid_storage<Windows::Security::Cryptography::Certificates::ICertificateRequestProperties2>{ static constexpr guid value{ 0x3DA0C954,0xD73F,0x4FF3,{ 0xA0,0xA6,0x06,0x77,0xC0,0xAD,0xA0,0x5B } }; };
template <> struct guid_storage<Windows::Security::Cryptography::Certificates::ICertificateRequestProperties3>{ static constexpr guid value{ 0xE687F616,0x734D,0x46B1,{ 0x9D,0x4C,0x6E,0xDF,0xDB,0xFC,0x84,0x5B } }; };
template <> struct guid_storage<Windows::Security::Cryptography::Certificates::ICertificateRequestProperties4>{ static constexpr guid value{ 0x4E429AD2,0x1C61,0x4FEA,{ 0xB8,0xFE,0x13,0x5F,0xB1,0x9C,0xDC,0xE4 } }; };
template <> struct guid_storage<Windows::Security::Cryptography::Certificates::ICertificateStore>{ static constexpr guid value{ 0xB0BFF720,0x344E,0x4331,{ 0xAF,0x14,0xA7,0xF7,0xA7,0xEB,0xC9,0x3A } }; };
template <> struct guid_storage<Windows::Security::Cryptography::Certificates::ICertificateStore2>{ static constexpr guid value{ 0xC7E68E4A,0x417D,0x4D1A,{ 0xBA,0xBD,0x15,0x68,0x7E,0x54,0x99,0x74 } }; };
template <> struct guid_storage<Windows::Security::Cryptography::Certificates::ICertificateStoresStatics>{ static constexpr guid value{ 0xFBECC739,0xC6FE,0x4DE7,{ 0x99,0xCF,0x74,0xC3,0xE5,0x96,0xE0,0x32 } }; };
template <> struct guid_storage<Windows::Security::Cryptography::Certificates::ICertificateStoresStatics2>{ static constexpr guid value{ 0xFA900B79,0xA0D4,0x4B8C,{ 0xBC,0x55,0xC0,0xA3,0x7E,0xB1,0x41,0xED } }; };
template <> struct guid_storage<Windows::Security::Cryptography::Certificates::IChainBuildingParameters>{ static constexpr guid value{ 0x422BA922,0x7C8D,0x47B7,{ 0xB5,0x9B,0xB1,0x27,0x03,0x73,0x3A,0xC3 } }; };
template <> struct guid_storage<Windows::Security::Cryptography::Certificates::IChainValidationParameters>{ static constexpr guid value{ 0xC4743B4A,0x7EB0,0x4B56,{ 0xA0,0x40,0xB9,0xC8,0xE6,0x55,0xDD,0xF3 } }; };
template <> struct guid_storage<Windows::Security::Cryptography::Certificates::ICmsAttachedSignature>{ static constexpr guid value{ 0x61899D9D,0x3757,0x4ECB,{ 0xBD,0xDC,0x0C,0xA3,0x57,0xD7,0xA9,0x36 } }; };
template <> struct guid_storage<Windows::Security::Cryptography::Certificates::ICmsAttachedSignatureFactory>{ static constexpr guid value{ 0xD0C8FC15,0xF757,0x4C64,{ 0xA3,0x62,0x52,0xCC,0x1C,0x77,0xCF,0xFB } }; };
template <> struct guid_storage<Windows::Security::Cryptography::Certificates::ICmsAttachedSignatureStatics>{ static constexpr guid value{ 0x87989C8E,0xB0AD,0x498D,{ 0xA7,0xF5,0x78,0xB5,0x9B,0xCE,0x4B,0x36 } }; };
template <> struct guid_storage<Windows::Security::Cryptography::Certificates::ICmsDetachedSignature>{ static constexpr guid value{ 0x0F1EF154,0xF65E,0x4536,{ 0x83,0x39,0x59,0x44,0x08,0x1D,0xB2,0xCA } }; };
template <> struct guid_storage<Windows::Security::Cryptography::Certificates::ICmsDetachedSignatureFactory>{ static constexpr guid value{ 0xC4AB3503,0xAE7F,0x4387,{ 0xAD,0x19,0x00,0xF1,0x50,0xE4,0x8E,0xBB } }; };
template <> struct guid_storage<Windows::Security::Cryptography::Certificates::ICmsDetachedSignatureStatics>{ static constexpr guid value{ 0x3D114CFD,0xBF9B,0x4682,{ 0x9B,0xE6,0x91,0xF5,0x7C,0x05,0x38,0x08 } }; };
template <> struct guid_storage<Windows::Security::Cryptography::Certificates::ICmsSignerInfo>{ static constexpr guid value{ 0x50D020DB,0x1D2F,0x4C1A,{ 0xB5,0xC5,0xD0,0x18,0x8F,0xF9,0x1F,0x47 } }; };
template <> struct guid_storage<Windows::Security::Cryptography::Certificates::ICmsTimestampInfo>{ static constexpr guid value{ 0x2F5F00F2,0x2C18,0x4F88,{ 0x84,0x35,0xC5,0x34,0x08,0x60,0x76,0xF5 } }; };
template <> struct guid_storage<Windows::Security::Cryptography::Certificates::IKeyAlgorithmNamesStatics>{ static constexpr guid value{ 0x479065D7,0x7AC7,0x4581,{ 0x8C,0x3B,0xD0,0x70,0x27,0x14,0x04,0x48 } }; };
template <> struct guid_storage<Windows::Security::Cryptography::Certificates::IKeyAlgorithmNamesStatics2>{ static constexpr guid value{ 0xC99B5686,0xE1FD,0x4A4A,{ 0x89,0x3D,0xA2,0x6F,0x33,0xDD,0x8B,0xB4 } }; };
template <> struct guid_storage<Windows::Security::Cryptography::Certificates::IKeyAttestationHelperStatics>{ static constexpr guid value{ 0x1648E246,0xF644,0x4326,{ 0x88,0xBE,0x3A,0xF1,0x02,0xD3,0x0E,0x0C } }; };
template <> struct guid_storage<Windows::Security::Cryptography::Certificates::IKeyAttestationHelperStatics2>{ static constexpr guid value{ 0x9C590B2C,0xA6C6,0x4A5E,{ 0x9E,0x64,0xE8,0x5D,0x52,0x79,0xDF,0x97 } }; };
template <> struct guid_storage<Windows::Security::Cryptography::Certificates::IKeyStorageProviderNamesStatics>{ static constexpr guid value{ 0xAF186AE0,0x5529,0x4602,{ 0xBD,0x94,0x0A,0xAB,0x91,0x95,0x7B,0x5C } }; };
template <> struct guid_storage<Windows::Security::Cryptography::Certificates::IKeyStorageProviderNamesStatics2>{ static constexpr guid value{ 0x262D743D,0x9C2E,0x41CC,{ 0x88,0x12,0xC4,0xD9,0x71,0xDD,0x7C,0x60 } }; };
template <> struct guid_storage<Windows::Security::Cryptography::Certificates::IPfxImportParameters>{ static constexpr guid value{ 0x680D3511,0x9A08,0x47C8,{ 0x86,0x4A,0x2E,0xDD,0x4D,0x8E,0xB4,0x6C } }; };
template <> struct guid_storage<Windows::Security::Cryptography::Certificates::IStandardCertificateStoreNamesStatics>{ static constexpr guid value{ 0x0C154ADB,0xA496,0x41F8,{ 0x8F,0xE5,0x9E,0x96,0xF3,0x6E,0xFB,0xF8 } }; };
template <> struct guid_storage<Windows::Security::Cryptography::Certificates::ISubjectAlternativeNameInfo>{ static constexpr guid value{ 0x582859F1,0x569D,0x4C20,{ 0xBE,0x7B,0x4E,0x1C,0x9A,0x0B,0xC5,0x2B } }; };
template <> struct guid_storage<Windows::Security::Cryptography::Certificates::ISubjectAlternativeNameInfo2>{ static constexpr guid value{ 0x437A78C6,0x1C51,0x41EA,{ 0xB3,0x4A,0x3D,0x65,0x43,0x98,0xA3,0x70 } }; };
template <> struct guid_storage<Windows::Security::Cryptography::Certificates::IUserCertificateEnrollmentManager>{ static constexpr guid value{ 0x96313718,0x22E1,0x4819,{ 0xB2,0x0B,0xAB,0x46,0xA6,0xEC,0xA0,0x6E } }; };
template <> struct guid_storage<Windows::Security::Cryptography::Certificates::IUserCertificateEnrollmentManager2>{ static constexpr guid value{ 0x0DAD9CB1,0x65DE,0x492A,{ 0xB8,0x6D,0xFC,0x5C,0x48,0x2C,0x37,0x47 } }; };
template <> struct guid_storage<Windows::Security::Cryptography::Certificates::IUserCertificateStore>{ static constexpr guid value{ 0xC9FB1D83,0x789F,0x4B4E,{ 0x91,0x80,0x04,0x5A,0x75,0x7A,0xAC,0x6D } }; };
template <> struct default_interface<Windows::Security::Cryptography::Certificates::Certificate>{ using type = Windows::Security::Cryptography::Certificates::ICertificate; };
template <> struct default_interface<Windows::Security::Cryptography::Certificates::CertificateChain>{ using type = Windows::Security::Cryptography::Certificates::ICertificateChain; };
template <> struct default_interface<Windows::Security::Cryptography::Certificates::CertificateExtension>{ using type = Windows::Security::Cryptography::Certificates::ICertificateExtension; };
template <> struct default_interface<Windows::Security::Cryptography::Certificates::CertificateKeyUsages>{ using type = Windows::Security::Cryptography::Certificates::ICertificateKeyUsages; };
template <> struct default_interface<Windows::Security::Cryptography::Certificates::CertificateQuery>{ using type = Windows::Security::Cryptography::Certificates::ICertificateQuery; };
template <> struct default_interface<Windows::Security::Cryptography::Certificates::CertificateRequestProperties>{ using type = Windows::Security::Cryptography::Certificates::ICertificateRequestProperties; };
template <> struct default_interface<Windows::Security::Cryptography::Certificates::CertificateStore>{ using type = Windows::Security::Cryptography::Certificates::ICertificateStore; };
template <> struct default_interface<Windows::Security::Cryptography::Certificates::ChainBuildingParameters>{ using type = Windows::Security::Cryptography::Certificates::IChainBuildingParameters; };
template <> struct default_interface<Windows::Security::Cryptography::Certificates::ChainValidationParameters>{ using type = Windows::Security::Cryptography::Certificates::IChainValidationParameters; };
template <> struct default_interface<Windows::Security::Cryptography::Certificates::CmsAttachedSignature>{ using type = Windows::Security::Cryptography::Certificates::ICmsAttachedSignature; };
template <> struct default_interface<Windows::Security::Cryptography::Certificates::CmsDetachedSignature>{ using type = Windows::Security::Cryptography::Certificates::ICmsDetachedSignature; };
template <> struct default_interface<Windows::Security::Cryptography::Certificates::CmsSignerInfo>{ using type = Windows::Security::Cryptography::Certificates::ICmsSignerInfo; };
template <> struct default_interface<Windows::Security::Cryptography::Certificates::CmsTimestampInfo>{ using type = Windows::Security::Cryptography::Certificates::ICmsTimestampInfo; };
template <> struct default_interface<Windows::Security::Cryptography::Certificates::PfxImportParameters>{ using type = Windows::Security::Cryptography::Certificates::IPfxImportParameters; };
template <> struct default_interface<Windows::Security::Cryptography::Certificates::SubjectAlternativeNameInfo>{ using type = Windows::Security::Cryptography::Certificates::ISubjectAlternativeNameInfo; };
template <> struct default_interface<Windows::Security::Cryptography::Certificates::UserCertificateEnrollmentManager>{ using type = Windows::Security::Cryptography::Certificates::IUserCertificateEnrollmentManager; };
template <> struct default_interface<Windows::Security::Cryptography::Certificates::UserCertificateStore>{ using type = Windows::Security::Cryptography::Certificates::IUserCertificateStore; };

template <> struct abi<Windows::Security::Cryptography::Certificates::ICertificate>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL BuildChainAsync(void* certificates, void** value) noexcept = 0;
    virtual int32_t WINRT_CALL BuildChainWithParametersAsync(void* certificates, void* parameters, void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_SerialNumber(uint32_t* __valueSize, uint8_t** value) noexcept = 0;
    virtual int32_t WINRT_CALL GetHashValue(uint32_t* __valueSize, uint8_t** value) noexcept = 0;
    virtual int32_t WINRT_CALL GetHashValueWithAlgorithm(void* hashAlgorithmName, uint32_t* __valueSize, uint8_t** value) noexcept = 0;
    virtual int32_t WINRT_CALL GetCertificateBlob(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_Subject(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_Issuer(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_HasPrivateKey(bool* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_IsStronglyProtected(bool* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_ValidFrom(Windows::Foundation::DateTime* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_ValidTo(Windows::Foundation::DateTime* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_EnhancedKeyUsages(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL put_FriendlyName(void* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_FriendlyName(void** value) noexcept = 0;
};};

template <> struct abi<Windows::Security::Cryptography::Certificates::ICertificate2>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL get_IsSecurityDeviceBound(bool* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_KeyUsages(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_KeyAlgorithmName(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_SignatureAlgorithmName(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_SignatureHashAlgorithmName(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_SubjectAlternativeName(void** value) noexcept = 0;
};};

template <> struct abi<Windows::Security::Cryptography::Certificates::ICertificate3>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL get_IsPerUser(bool* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_StoreName(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_KeyStorageProviderName(void** value) noexcept = 0;
};};

template <> struct abi<Windows::Security::Cryptography::Certificates::ICertificateChain>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL Validate(Windows::Security::Cryptography::Certificates::ChainValidationResult* status) noexcept = 0;
    virtual int32_t WINRT_CALL ValidateWithParameters(void* parameter, Windows::Security::Cryptography::Certificates::ChainValidationResult* status) noexcept = 0;
    virtual int32_t WINRT_CALL GetCertificates(bool includeRoot, void** certificates) noexcept = 0;
};};

template <> struct abi<Windows::Security::Cryptography::Certificates::ICertificateEnrollmentManagerStatics>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL CreateRequestAsync(void* request, void** value) noexcept = 0;
    virtual int32_t WINRT_CALL InstallCertificateAsync(void* certificate, Windows::Security::Cryptography::Certificates::InstallOptions installOption, void** value) noexcept = 0;
    virtual int32_t WINRT_CALL ImportPfxDataAsync(void* pfxData, void* password, Windows::Security::Cryptography::Certificates::ExportOption exportable, Windows::Security::Cryptography::Certificates::KeyProtectionLevel keyProtectionLevel, Windows::Security::Cryptography::Certificates::InstallOptions installOption, void* friendlyName, void** value) noexcept = 0;
};};

template <> struct abi<Windows::Security::Cryptography::Certificates::ICertificateEnrollmentManagerStatics2>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL get_UserCertificateEnrollmentManager(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL ImportPfxDataToKspAsync(void* pfxData, void* password, Windows::Security::Cryptography::Certificates::ExportOption exportable, Windows::Security::Cryptography::Certificates::KeyProtectionLevel keyProtectionLevel, Windows::Security::Cryptography::Certificates::InstallOptions installOption, void* friendlyName, void* keyStorageProvider, void** value) noexcept = 0;
};};

template <> struct abi<Windows::Security::Cryptography::Certificates::ICertificateEnrollmentManagerStatics3>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL ImportPfxDataToKspWithParametersAsync(void* pfxData, void* password, void* pfxImportParameters, void** value) noexcept = 0;
};};

template <> struct abi<Windows::Security::Cryptography::Certificates::ICertificateExtension>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL get_ObjectId(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL put_ObjectId(void* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_IsCritical(bool* value) noexcept = 0;
    virtual int32_t WINRT_CALL put_IsCritical(bool value) noexcept = 0;
    virtual int32_t WINRT_CALL EncodeValue(void* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_Value(uint32_t* __valueSize, uint8_t** value) noexcept = 0;
    virtual int32_t WINRT_CALL put_Value(uint32_t __valueSize, uint8_t* value) noexcept = 0;
};};

template <> struct abi<Windows::Security::Cryptography::Certificates::ICertificateFactory>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL CreateCertificate(void* certBlob, void** certificate) noexcept = 0;
};};

template <> struct abi<Windows::Security::Cryptography::Certificates::ICertificateKeyUsages>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL get_EncipherOnly(bool* value) noexcept = 0;
    virtual int32_t WINRT_CALL put_EncipherOnly(bool value) noexcept = 0;
    virtual int32_t WINRT_CALL get_CrlSign(bool* value) noexcept = 0;
    virtual int32_t WINRT_CALL put_CrlSign(bool value) noexcept = 0;
    virtual int32_t WINRT_CALL get_KeyCertificateSign(bool* value) noexcept = 0;
    virtual int32_t WINRT_CALL put_KeyCertificateSign(bool value) noexcept = 0;
    virtual int32_t WINRT_CALL get_KeyAgreement(bool* value) noexcept = 0;
    virtual int32_t WINRT_CALL put_KeyAgreement(bool value) noexcept = 0;
    virtual int32_t WINRT_CALL get_DataEncipherment(bool* value) noexcept = 0;
    virtual int32_t WINRT_CALL put_DataEncipherment(bool value) noexcept = 0;
    virtual int32_t WINRT_CALL get_KeyEncipherment(bool* value) noexcept = 0;
    virtual int32_t WINRT_CALL put_KeyEncipherment(bool value) noexcept = 0;
    virtual int32_t WINRT_CALL get_NonRepudiation(bool* value) noexcept = 0;
    virtual int32_t WINRT_CALL put_NonRepudiation(bool value) noexcept = 0;
    virtual int32_t WINRT_CALL get_DigitalSignature(bool* value) noexcept = 0;
    virtual int32_t WINRT_CALL put_DigitalSignature(bool value) noexcept = 0;
};};

template <> struct abi<Windows::Security::Cryptography::Certificates::ICertificateQuery>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL get_EnhancedKeyUsages(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_IssuerName(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL put_IssuerName(void* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_FriendlyName(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL put_FriendlyName(void* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_Thumbprint(uint32_t* __valueSize, uint8_t** value) noexcept = 0;
    virtual int32_t WINRT_CALL put_Thumbprint(uint32_t __valueSize, uint8_t* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_HardwareOnly(bool* value) noexcept = 0;
    virtual int32_t WINRT_CALL put_HardwareOnly(bool value) noexcept = 0;
};};

template <> struct abi<Windows::Security::Cryptography::Certificates::ICertificateQuery2>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL get_IncludeDuplicates(bool* value) noexcept = 0;
    virtual int32_t WINRT_CALL put_IncludeDuplicates(bool value) noexcept = 0;
    virtual int32_t WINRT_CALL get_IncludeExpiredCertificates(bool* value) noexcept = 0;
    virtual int32_t WINRT_CALL put_IncludeExpiredCertificates(bool value) noexcept = 0;
    virtual int32_t WINRT_CALL get_StoreName(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL put_StoreName(void* value) noexcept = 0;
};};

template <> struct abi<Windows::Security::Cryptography::Certificates::ICertificateRequestProperties>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL get_Subject(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL put_Subject(void* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_KeyAlgorithmName(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL put_KeyAlgorithmName(void* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_KeySize(uint32_t* value) noexcept = 0;
    virtual int32_t WINRT_CALL put_KeySize(uint32_t value) noexcept = 0;
    virtual int32_t WINRT_CALL get_FriendlyName(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL put_FriendlyName(void* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_HashAlgorithmName(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL put_HashAlgorithmName(void* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_Exportable(Windows::Security::Cryptography::Certificates::ExportOption* value) noexcept = 0;
    virtual int32_t WINRT_CALL put_Exportable(Windows::Security::Cryptography::Certificates::ExportOption value) noexcept = 0;
    virtual int32_t WINRT_CALL get_KeyUsages(Windows::Security::Cryptography::Certificates::EnrollKeyUsages* value) noexcept = 0;
    virtual int32_t WINRT_CALL put_KeyUsages(Windows::Security::Cryptography::Certificates::EnrollKeyUsages value) noexcept = 0;
    virtual int32_t WINRT_CALL get_KeyProtectionLevel(Windows::Security::Cryptography::Certificates::KeyProtectionLevel* value) noexcept = 0;
    virtual int32_t WINRT_CALL put_KeyProtectionLevel(Windows::Security::Cryptography::Certificates::KeyProtectionLevel value) noexcept = 0;
    virtual int32_t WINRT_CALL get_KeyStorageProviderName(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL put_KeyStorageProviderName(void* value) noexcept = 0;
};};

template <> struct abi<Windows::Security::Cryptography::Certificates::ICertificateRequestProperties2>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL get_SmartcardReaderName(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL put_SmartcardReaderName(void* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_SigningCertificate(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL put_SigningCertificate(void* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_AttestationCredentialCertificate(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL put_AttestationCredentialCertificate(void* value) noexcept = 0;
};};

template <> struct abi<Windows::Security::Cryptography::Certificates::ICertificateRequestProperties3>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL get_CurveName(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL put_CurveName(void* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_CurveParameters(uint32_t* __valueSize, uint8_t** value) noexcept = 0;
    virtual int32_t WINRT_CALL put_CurveParameters(uint32_t __valueSize, uint8_t* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_ContainerNamePrefix(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL put_ContainerNamePrefix(void* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_ContainerName(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL put_ContainerName(void* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_UseExistingKey(bool* value) noexcept = 0;
    virtual int32_t WINRT_CALL put_UseExistingKey(bool value) noexcept = 0;
};};

template <> struct abi<Windows::Security::Cryptography::Certificates::ICertificateRequestProperties4>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL get_SuppressedDefaults(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_SubjectAlternativeName(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_Extensions(void** value) noexcept = 0;
};};

template <> struct abi<Windows::Security::Cryptography::Certificates::ICertificateStore>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL Add(void* certificate) noexcept = 0;
    virtual int32_t WINRT_CALL Delete(void* certificate) noexcept = 0;
};};

template <> struct abi<Windows::Security::Cryptography::Certificates::ICertificateStore2>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL get_Name(void** value) noexcept = 0;
};};

template <> struct abi<Windows::Security::Cryptography::Certificates::ICertificateStoresStatics>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL FindAllAsync(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL FindAllWithQueryAsync(void* query, void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_TrustedRootCertificationAuthorities(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_IntermediateCertificationAuthorities(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL GetStoreByName(void* storeName, void** value) noexcept = 0;
};};

template <> struct abi<Windows::Security::Cryptography::Certificates::ICertificateStoresStatics2>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL GetUserStoreByName(void* storeName, void** result) noexcept = 0;
};};

template <> struct abi<Windows::Security::Cryptography::Certificates::IChainBuildingParameters>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL get_EnhancedKeyUsages(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_ValidationTimestamp(Windows::Foundation::DateTime* value) noexcept = 0;
    virtual int32_t WINRT_CALL put_ValidationTimestamp(Windows::Foundation::DateTime value) noexcept = 0;
    virtual int32_t WINRT_CALL get_RevocationCheckEnabled(bool* value) noexcept = 0;
    virtual int32_t WINRT_CALL put_RevocationCheckEnabled(bool value) noexcept = 0;
    virtual int32_t WINRT_CALL get_NetworkRetrievalEnabled(bool* value) noexcept = 0;
    virtual int32_t WINRT_CALL put_NetworkRetrievalEnabled(bool value) noexcept = 0;
    virtual int32_t WINRT_CALL get_AuthorityInformationAccessEnabled(bool* value) noexcept = 0;
    virtual int32_t WINRT_CALL put_AuthorityInformationAccessEnabled(bool value) noexcept = 0;
    virtual int32_t WINRT_CALL get_CurrentTimeValidationEnabled(bool* value) noexcept = 0;
    virtual int32_t WINRT_CALL put_CurrentTimeValidationEnabled(bool value) noexcept = 0;
    virtual int32_t WINRT_CALL get_ExclusiveTrustRoots(void** certificates) noexcept = 0;
};};

template <> struct abi<Windows::Security::Cryptography::Certificates::IChainValidationParameters>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL get_CertificateChainPolicy(Windows::Security::Cryptography::Certificates::CertificateChainPolicy* value) noexcept = 0;
    virtual int32_t WINRT_CALL put_CertificateChainPolicy(Windows::Security::Cryptography::Certificates::CertificateChainPolicy value) noexcept = 0;
    virtual int32_t WINRT_CALL get_ServerDnsName(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL put_ServerDnsName(void* value) noexcept = 0;
};};

template <> struct abi<Windows::Security::Cryptography::Certificates::ICmsAttachedSignature>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL get_Certificates(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_Content(uint32_t* __valueSize, uint8_t** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_Signers(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL VerifySignature(Windows::Security::Cryptography::Certificates::SignatureValidationResult* value) noexcept = 0;
};};

template <> struct abi<Windows::Security::Cryptography::Certificates::ICmsAttachedSignatureFactory>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL CreateCmsAttachedSignature(void* inputBlob, void** cmsSignedData) noexcept = 0;
};};

template <> struct abi<Windows::Security::Cryptography::Certificates::ICmsAttachedSignatureStatics>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL GenerateSignatureAsync(void* data, void* signers, void* certificates, void** outputBlob) noexcept = 0;
};};

template <> struct abi<Windows::Security::Cryptography::Certificates::ICmsDetachedSignature>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL get_Certificates(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_Signers(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL VerifySignatureAsync(void* data, void** value) noexcept = 0;
};};

template <> struct abi<Windows::Security::Cryptography::Certificates::ICmsDetachedSignatureFactory>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL CreateCmsDetachedSignature(void* inputBlob, void** cmsSignedData) noexcept = 0;
};};

template <> struct abi<Windows::Security::Cryptography::Certificates::ICmsDetachedSignatureStatics>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL GenerateSignatureAsync(void* data, void* signers, void* certificates, void** outputBlob) noexcept = 0;
};};

template <> struct abi<Windows::Security::Cryptography::Certificates::ICmsSignerInfo>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL get_Certificate(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL put_Certificate(void* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_HashAlgorithmName(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL put_HashAlgorithmName(void* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_TimestampInfo(void** value) noexcept = 0;
};};

template <> struct abi<Windows::Security::Cryptography::Certificates::ICmsTimestampInfo>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL get_SigningCertificate(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_Certificates(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_Timestamp(Windows::Foundation::DateTime* value) noexcept = 0;
};};

template <> struct abi<Windows::Security::Cryptography::Certificates::IKeyAlgorithmNamesStatics>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL get_Rsa(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_Dsa(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_Ecdh256(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_Ecdh384(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_Ecdh521(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_Ecdsa256(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_Ecdsa384(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_Ecdsa521(void** value) noexcept = 0;
};};

template <> struct abi<Windows::Security::Cryptography::Certificates::IKeyAlgorithmNamesStatics2>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL get_Ecdsa(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_Ecdh(void** value) noexcept = 0;
};};

template <> struct abi<Windows::Security::Cryptography::Certificates::IKeyAttestationHelperStatics>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL DecryptTpmAttestationCredentialAsync(void* credential, void** value) noexcept = 0;
    virtual int32_t WINRT_CALL GetTpmAttestationCredentialId(void* credential, void** value) noexcept = 0;
};};

template <> struct abi<Windows::Security::Cryptography::Certificates::IKeyAttestationHelperStatics2>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL DecryptTpmAttestationCredentialWithContainerNameAsync(void* credential, void* containerName, void** value) noexcept = 0;
};};

template <> struct abi<Windows::Security::Cryptography::Certificates::IKeyStorageProviderNamesStatics>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL get_SoftwareKeyStorageProvider(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_SmartcardKeyStorageProvider(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_PlatformKeyStorageProvider(void** value) noexcept = 0;
};};

template <> struct abi<Windows::Security::Cryptography::Certificates::IKeyStorageProviderNamesStatics2>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL get_PassportKeyStorageProvider(void** value) noexcept = 0;
};};

template <> struct abi<Windows::Security::Cryptography::Certificates::IPfxImportParameters>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL get_Exportable(Windows::Security::Cryptography::Certificates::ExportOption* value) noexcept = 0;
    virtual int32_t WINRT_CALL put_Exportable(Windows::Security::Cryptography::Certificates::ExportOption value) noexcept = 0;
    virtual int32_t WINRT_CALL get_KeyProtectionLevel(Windows::Security::Cryptography::Certificates::KeyProtectionLevel* value) noexcept = 0;
    virtual int32_t WINRT_CALL put_KeyProtectionLevel(Windows::Security::Cryptography::Certificates::KeyProtectionLevel value) noexcept = 0;
    virtual int32_t WINRT_CALL get_InstallOptions(Windows::Security::Cryptography::Certificates::InstallOptions* value) noexcept = 0;
    virtual int32_t WINRT_CALL put_InstallOptions(Windows::Security::Cryptography::Certificates::InstallOptions value) noexcept = 0;
    virtual int32_t WINRT_CALL get_FriendlyName(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL put_FriendlyName(void* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_KeyStorageProviderName(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL put_KeyStorageProviderName(void* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_ContainerNamePrefix(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL put_ContainerNamePrefix(void* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_ReaderName(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL put_ReaderName(void* value) noexcept = 0;
};};

template <> struct abi<Windows::Security::Cryptography::Certificates::IStandardCertificateStoreNamesStatics>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL get_Personal(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_TrustedRootCertificationAuthorities(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_IntermediateCertificationAuthorities(void** value) noexcept = 0;
};};

template <> struct abi<Windows::Security::Cryptography::Certificates::ISubjectAlternativeNameInfo>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL get_EmailName(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_IPAddress(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_Url(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_DnsName(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_DistinguishedName(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_PrincipalName(void** value) noexcept = 0;
};};

template <> struct abi<Windows::Security::Cryptography::Certificates::ISubjectAlternativeNameInfo2>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL get_EmailNames(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_IPAddresses(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_Urls(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_DnsNames(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_DistinguishedNames(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_PrincipalNames(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_Extension(void** value) noexcept = 0;
};};

template <> struct abi<Windows::Security::Cryptography::Certificates::IUserCertificateEnrollmentManager>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL CreateRequestAsync(void* request, void** value) noexcept = 0;
    virtual int32_t WINRT_CALL InstallCertificateAsync(void* certificate, Windows::Security::Cryptography::Certificates::InstallOptions installOption, void** value) noexcept = 0;
    virtual int32_t WINRT_CALL ImportPfxDataAsync(void* pfxData, void* password, Windows::Security::Cryptography::Certificates::ExportOption exportable, Windows::Security::Cryptography::Certificates::KeyProtectionLevel keyProtectionLevel, Windows::Security::Cryptography::Certificates::InstallOptions installOption, void* friendlyName, void** value) noexcept = 0;
    virtual int32_t WINRT_CALL ImportPfxDataToKspAsync(void* pfxData, void* password, Windows::Security::Cryptography::Certificates::ExportOption exportable, Windows::Security::Cryptography::Certificates::KeyProtectionLevel keyProtectionLevel, Windows::Security::Cryptography::Certificates::InstallOptions installOption, void* friendlyName, void* keyStorageProvider, void** value) noexcept = 0;
};};

template <> struct abi<Windows::Security::Cryptography::Certificates::IUserCertificateEnrollmentManager2>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL ImportPfxDataToKspWithParametersAsync(void* pfxData, void* password, void* pfxImportParameters, void** value) noexcept = 0;
};};

template <> struct abi<Windows::Security::Cryptography::Certificates::IUserCertificateStore>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL RequestAddAsync(void* certificate, void** result) noexcept = 0;
    virtual int32_t WINRT_CALL RequestDeleteAsync(void* certificate, void** result) noexcept = 0;
    virtual int32_t WINRT_CALL get_Name(void** value) noexcept = 0;
};};

template <typename D>
struct consume_Windows_Security_Cryptography_Certificates_ICertificate
{
    Windows::Foundation::IAsyncOperation<Windows::Security::Cryptography::Certificates::CertificateChain> BuildChainAsync(param::async_iterable<Windows::Security::Cryptography::Certificates::Certificate> const& certificates) const;
    Windows::Foundation::IAsyncOperation<Windows::Security::Cryptography::Certificates::CertificateChain> BuildChainAsync(param::async_iterable<Windows::Security::Cryptography::Certificates::Certificate> const& certificates, Windows::Security::Cryptography::Certificates::ChainBuildingParameters const& parameters) const;
    com_array<uint8_t> SerialNumber() const;
    com_array<uint8_t> GetHashValue() const;
    com_array<uint8_t> GetHashValue(param::hstring const& hashAlgorithmName) const;
    Windows::Storage::Streams::IBuffer GetCertificateBlob() const;
    hstring Subject() const;
    hstring Issuer() const;
    bool HasPrivateKey() const;
    bool IsStronglyProtected() const;
    Windows::Foundation::DateTime ValidFrom() const;
    Windows::Foundation::DateTime ValidTo() const;
    Windows::Foundation::Collections::IVectorView<hstring> EnhancedKeyUsages() const;
    void FriendlyName(param::hstring const& value) const;
    hstring FriendlyName() const;
};
template <> struct consume<Windows::Security::Cryptography::Certificates::ICertificate> { template <typename D> using type = consume_Windows_Security_Cryptography_Certificates_ICertificate<D>; };

template <typename D>
struct consume_Windows_Security_Cryptography_Certificates_ICertificate2
{
    bool IsSecurityDeviceBound() const;
    Windows::Security::Cryptography::Certificates::CertificateKeyUsages KeyUsages() const;
    hstring KeyAlgorithmName() const;
    hstring SignatureAlgorithmName() const;
    hstring SignatureHashAlgorithmName() const;
    Windows::Security::Cryptography::Certificates::SubjectAlternativeNameInfo SubjectAlternativeName() const;
};
template <> struct consume<Windows::Security::Cryptography::Certificates::ICertificate2> { template <typename D> using type = consume_Windows_Security_Cryptography_Certificates_ICertificate2<D>; };

template <typename D>
struct consume_Windows_Security_Cryptography_Certificates_ICertificate3
{
    bool IsPerUser() const;
    hstring StoreName() const;
    hstring KeyStorageProviderName() const;
};
template <> struct consume<Windows::Security::Cryptography::Certificates::ICertificate3> { template <typename D> using type = consume_Windows_Security_Cryptography_Certificates_ICertificate3<D>; };

template <typename D>
struct consume_Windows_Security_Cryptography_Certificates_ICertificateChain
{
    Windows::Security::Cryptography::Certificates::ChainValidationResult Validate() const;
    Windows::Security::Cryptography::Certificates::ChainValidationResult Validate(Windows::Security::Cryptography::Certificates::ChainValidationParameters const& parameter) const;
    Windows::Foundation::Collections::IVectorView<Windows::Security::Cryptography::Certificates::Certificate> GetCertificates(bool includeRoot) const;
};
template <> struct consume<Windows::Security::Cryptography::Certificates::ICertificateChain> { template <typename D> using type = consume_Windows_Security_Cryptography_Certificates_ICertificateChain<D>; };

template <typename D>
struct consume_Windows_Security_Cryptography_Certificates_ICertificateEnrollmentManagerStatics
{
    Windows::Foundation::IAsyncOperation<hstring> CreateRequestAsync(Windows::Security::Cryptography::Certificates::CertificateRequestProperties const& request) const;
    Windows::Foundation::IAsyncAction InstallCertificateAsync(param::hstring const& certificate, Windows::Security::Cryptography::Certificates::InstallOptions const& installOption) const;
    Windows::Foundation::IAsyncAction ImportPfxDataAsync(param::hstring const& pfxData, param::hstring const& password, Windows::Security::Cryptography::Certificates::ExportOption const& exportable, Windows::Security::Cryptography::Certificates::KeyProtectionLevel const& keyProtectionLevel, Windows::Security::Cryptography::Certificates::InstallOptions const& installOption, param::hstring const& friendlyName) const;
};
template <> struct consume<Windows::Security::Cryptography::Certificates::ICertificateEnrollmentManagerStatics> { template <typename D> using type = consume_Windows_Security_Cryptography_Certificates_ICertificateEnrollmentManagerStatics<D>; };

template <typename D>
struct consume_Windows_Security_Cryptography_Certificates_ICertificateEnrollmentManagerStatics2
{
    Windows::Security::Cryptography::Certificates::UserCertificateEnrollmentManager UserCertificateEnrollmentManager() const;
    Windows::Foundation::IAsyncAction ImportPfxDataAsync(param::hstring const& pfxData, param::hstring const& password, Windows::Security::Cryptography::Certificates::ExportOption const& exportable, Windows::Security::Cryptography::Certificates::KeyProtectionLevel const& keyProtectionLevel, Windows::Security::Cryptography::Certificates::InstallOptions const& installOption, param::hstring const& friendlyName, param::hstring const& keyStorageProvider) const;
};
template <> struct consume<Windows::Security::Cryptography::Certificates::ICertificateEnrollmentManagerStatics2> { template <typename D> using type = consume_Windows_Security_Cryptography_Certificates_ICertificateEnrollmentManagerStatics2<D>; };

template <typename D>
struct consume_Windows_Security_Cryptography_Certificates_ICertificateEnrollmentManagerStatics3
{
    Windows::Foundation::IAsyncAction ImportPfxDataAsync(param::hstring const& pfxData, param::hstring const& password, Windows::Security::Cryptography::Certificates::PfxImportParameters const& pfxImportParameters) const;
};
template <> struct consume<Windows::Security::Cryptography::Certificates::ICertificateEnrollmentManagerStatics3> { template <typename D> using type = consume_Windows_Security_Cryptography_Certificates_ICertificateEnrollmentManagerStatics3<D>; };

template <typename D>
struct consume_Windows_Security_Cryptography_Certificates_ICertificateExtension
{
    hstring ObjectId() const;
    void ObjectId(param::hstring const& value) const;
    bool IsCritical() const;
    void IsCritical(bool value) const;
    void EncodeValue(param::hstring const& value) const;
    com_array<uint8_t> Value() const;
    void Value(array_view<uint8_t const> value) const;
};
template <> struct consume<Windows::Security::Cryptography::Certificates::ICertificateExtension> { template <typename D> using type = consume_Windows_Security_Cryptography_Certificates_ICertificateExtension<D>; };

template <typename D>
struct consume_Windows_Security_Cryptography_Certificates_ICertificateFactory
{
    Windows::Security::Cryptography::Certificates::Certificate CreateCertificate(Windows::Storage::Streams::IBuffer const& certBlob) const;
};
template <> struct consume<Windows::Security::Cryptography::Certificates::ICertificateFactory> { template <typename D> using type = consume_Windows_Security_Cryptography_Certificates_ICertificateFactory<D>; };

template <typename D>
struct consume_Windows_Security_Cryptography_Certificates_ICertificateKeyUsages
{
    bool EncipherOnly() const;
    void EncipherOnly(bool value) const;
    bool CrlSign() const;
    void CrlSign(bool value) const;
    bool KeyCertificateSign() const;
    void KeyCertificateSign(bool value) const;
    bool KeyAgreement() const;
    void KeyAgreement(bool value) const;
    bool DataEncipherment() const;
    void DataEncipherment(bool value) const;
    bool KeyEncipherment() const;
    void KeyEncipherment(bool value) const;
    bool NonRepudiation() const;
    void NonRepudiation(bool value) const;
    bool DigitalSignature() const;
    void DigitalSignature(bool value) const;
};
template <> struct consume<Windows::Security::Cryptography::Certificates::ICertificateKeyUsages> { template <typename D> using type = consume_Windows_Security_Cryptography_Certificates_ICertificateKeyUsages<D>; };

template <typename D>
struct consume_Windows_Security_Cryptography_Certificates_ICertificateQuery
{
    Windows::Foundation::Collections::IVector<hstring> EnhancedKeyUsages() const;
    hstring IssuerName() const;
    void IssuerName(param::hstring const& value) const;
    hstring FriendlyName() const;
    void FriendlyName(param::hstring const& value) const;
    com_array<uint8_t> Thumbprint() const;
    void Thumbprint(array_view<uint8_t const> value) const;
    bool HardwareOnly() const;
    void HardwareOnly(bool value) const;
};
template <> struct consume<Windows::Security::Cryptography::Certificates::ICertificateQuery> { template <typename D> using type = consume_Windows_Security_Cryptography_Certificates_ICertificateQuery<D>; };

template <typename D>
struct consume_Windows_Security_Cryptography_Certificates_ICertificateQuery2
{
    bool IncludeDuplicates() const;
    void IncludeDuplicates(bool value) const;
    bool IncludeExpiredCertificates() const;
    void IncludeExpiredCertificates(bool value) const;
    hstring StoreName() const;
    void StoreName(param::hstring const& value) const;
};
template <> struct consume<Windows::Security::Cryptography::Certificates::ICertificateQuery2> { template <typename D> using type = consume_Windows_Security_Cryptography_Certificates_ICertificateQuery2<D>; };

template <typename D>
struct consume_Windows_Security_Cryptography_Certificates_ICertificateRequestProperties
{
    hstring Subject() const;
    void Subject(param::hstring const& value) const;
    hstring KeyAlgorithmName() const;
    void KeyAlgorithmName(param::hstring const& value) const;
    uint32_t KeySize() const;
    void KeySize(uint32_t value) const;
    hstring FriendlyName() const;
    void FriendlyName(param::hstring const& value) const;
    hstring HashAlgorithmName() const;
    void HashAlgorithmName(param::hstring const& value) const;
    Windows::Security::Cryptography::Certificates::ExportOption Exportable() const;
    void Exportable(Windows::Security::Cryptography::Certificates::ExportOption const& value) const;
    Windows::Security::Cryptography::Certificates::EnrollKeyUsages KeyUsages() const;
    void KeyUsages(Windows::Security::Cryptography::Certificates::EnrollKeyUsages const& value) const;
    Windows::Security::Cryptography::Certificates::KeyProtectionLevel KeyProtectionLevel() const;
    void KeyProtectionLevel(Windows::Security::Cryptography::Certificates::KeyProtectionLevel const& value) const;
    hstring KeyStorageProviderName() const;
    void KeyStorageProviderName(param::hstring const& value) const;
};
template <> struct consume<Windows::Security::Cryptography::Certificates::ICertificateRequestProperties> { template <typename D> using type = consume_Windows_Security_Cryptography_Certificates_ICertificateRequestProperties<D>; };

template <typename D>
struct consume_Windows_Security_Cryptography_Certificates_ICertificateRequestProperties2
{
    hstring SmartcardReaderName() const;
    void SmartcardReaderName(param::hstring const& value) const;
    Windows::Security::Cryptography::Certificates::Certificate SigningCertificate() const;
    void SigningCertificate(Windows::Security::Cryptography::Certificates::Certificate const& value) const;
    Windows::Security::Cryptography::Certificates::Certificate AttestationCredentialCertificate() const;
    void AttestationCredentialCertificate(Windows::Security::Cryptography::Certificates::Certificate const& value) const;
};
template <> struct consume<Windows::Security::Cryptography::Certificates::ICertificateRequestProperties2> { template <typename D> using type = consume_Windows_Security_Cryptography_Certificates_ICertificateRequestProperties2<D>; };

template <typename D>
struct consume_Windows_Security_Cryptography_Certificates_ICertificateRequestProperties3
{
    hstring CurveName() const;
    void CurveName(param::hstring const& value) const;
    com_array<uint8_t> CurveParameters() const;
    void CurveParameters(array_view<uint8_t const> value) const;
    hstring ContainerNamePrefix() const;
    void ContainerNamePrefix(param::hstring const& value) const;
    hstring ContainerName() const;
    void ContainerName(param::hstring const& value) const;
    bool UseExistingKey() const;
    void UseExistingKey(bool value) const;
};
template <> struct consume<Windows::Security::Cryptography::Certificates::ICertificateRequestProperties3> { template <typename D> using type = consume_Windows_Security_Cryptography_Certificates_ICertificateRequestProperties3<D>; };

template <typename D>
struct consume_Windows_Security_Cryptography_Certificates_ICertificateRequestProperties4
{
    Windows::Foundation::Collections::IVector<hstring> SuppressedDefaults() const;
    Windows::Security::Cryptography::Certificates::SubjectAlternativeNameInfo SubjectAlternativeName() const;
    Windows::Foundation::Collections::IVector<Windows::Security::Cryptography::Certificates::CertificateExtension> Extensions() const;
};
template <> struct consume<Windows::Security::Cryptography::Certificates::ICertificateRequestProperties4> { template <typename D> using type = consume_Windows_Security_Cryptography_Certificates_ICertificateRequestProperties4<D>; };

template <typename D>
struct consume_Windows_Security_Cryptography_Certificates_ICertificateStore
{
    void Add(Windows::Security::Cryptography::Certificates::Certificate const& certificate) const;
    void Delete(Windows::Security::Cryptography::Certificates::Certificate const& certificate) const;
};
template <> struct consume<Windows::Security::Cryptography::Certificates::ICertificateStore> { template <typename D> using type = consume_Windows_Security_Cryptography_Certificates_ICertificateStore<D>; };

template <typename D>
struct consume_Windows_Security_Cryptography_Certificates_ICertificateStore2
{
    hstring Name() const;
};
template <> struct consume<Windows::Security::Cryptography::Certificates::ICertificateStore2> { template <typename D> using type = consume_Windows_Security_Cryptography_Certificates_ICertificateStore2<D>; };

template <typename D>
struct consume_Windows_Security_Cryptography_Certificates_ICertificateStoresStatics
{
    Windows::Foundation::IAsyncOperation<Windows::Foundation::Collections::IVectorView<Windows::Security::Cryptography::Certificates::Certificate>> FindAllAsync() const;
    Windows::Foundation::IAsyncOperation<Windows::Foundation::Collections::IVectorView<Windows::Security::Cryptography::Certificates::Certificate>> FindAllAsync(Windows::Security::Cryptography::Certificates::CertificateQuery const& query) const;
    Windows::Security::Cryptography::Certificates::CertificateStore TrustedRootCertificationAuthorities() const;
    Windows::Security::Cryptography::Certificates::CertificateStore IntermediateCertificationAuthorities() const;
    Windows::Security::Cryptography::Certificates::CertificateStore GetStoreByName(param::hstring const& storeName) const;
};
template <> struct consume<Windows::Security::Cryptography::Certificates::ICertificateStoresStatics> { template <typename D> using type = consume_Windows_Security_Cryptography_Certificates_ICertificateStoresStatics<D>; };

template <typename D>
struct consume_Windows_Security_Cryptography_Certificates_ICertificateStoresStatics2
{
    Windows::Security::Cryptography::Certificates::UserCertificateStore GetUserStoreByName(param::hstring const& storeName) const;
};
template <> struct consume<Windows::Security::Cryptography::Certificates::ICertificateStoresStatics2> { template <typename D> using type = consume_Windows_Security_Cryptography_Certificates_ICertificateStoresStatics2<D>; };

template <typename D>
struct consume_Windows_Security_Cryptography_Certificates_IChainBuildingParameters
{
    Windows::Foundation::Collections::IVector<hstring> EnhancedKeyUsages() const;
    Windows::Foundation::DateTime ValidationTimestamp() const;
    void ValidationTimestamp(Windows::Foundation::DateTime const& value) const;
    bool RevocationCheckEnabled() const;
    void RevocationCheckEnabled(bool value) const;
    bool NetworkRetrievalEnabled() const;
    void NetworkRetrievalEnabled(bool value) const;
    bool AuthorityInformationAccessEnabled() const;
    void AuthorityInformationAccessEnabled(bool value) const;
    bool CurrentTimeValidationEnabled() const;
    void CurrentTimeValidationEnabled(bool value) const;
    Windows::Foundation::Collections::IVector<Windows::Security::Cryptography::Certificates::Certificate> ExclusiveTrustRoots() const;
};
template <> struct consume<Windows::Security::Cryptography::Certificates::IChainBuildingParameters> { template <typename D> using type = consume_Windows_Security_Cryptography_Certificates_IChainBuildingParameters<D>; };

template <typename D>
struct consume_Windows_Security_Cryptography_Certificates_IChainValidationParameters
{
    Windows::Security::Cryptography::Certificates::CertificateChainPolicy CertificateChainPolicy() const;
    void CertificateChainPolicy(Windows::Security::Cryptography::Certificates::CertificateChainPolicy const& value) const;
    Windows::Networking::HostName ServerDnsName() const;
    void ServerDnsName(Windows::Networking::HostName const& value) const;
};
template <> struct consume<Windows::Security::Cryptography::Certificates::IChainValidationParameters> { template <typename D> using type = consume_Windows_Security_Cryptography_Certificates_IChainValidationParameters<D>; };

template <typename D>
struct consume_Windows_Security_Cryptography_Certificates_ICmsAttachedSignature
{
    Windows::Foundation::Collections::IVectorView<Windows::Security::Cryptography::Certificates::Certificate> Certificates() const;
    com_array<uint8_t> Content() const;
    Windows::Foundation::Collections::IVectorView<Windows::Security::Cryptography::Certificates::CmsSignerInfo> Signers() const;
    Windows::Security::Cryptography::Certificates::SignatureValidationResult VerifySignature() const;
};
template <> struct consume<Windows::Security::Cryptography::Certificates::ICmsAttachedSignature> { template <typename D> using type = consume_Windows_Security_Cryptography_Certificates_ICmsAttachedSignature<D>; };

template <typename D>
struct consume_Windows_Security_Cryptography_Certificates_ICmsAttachedSignatureFactory
{
    Windows::Security::Cryptography::Certificates::CmsAttachedSignature CreateCmsAttachedSignature(Windows::Storage::Streams::IBuffer const& inputBlob) const;
};
template <> struct consume<Windows::Security::Cryptography::Certificates::ICmsAttachedSignatureFactory> { template <typename D> using type = consume_Windows_Security_Cryptography_Certificates_ICmsAttachedSignatureFactory<D>; };

template <typename D>
struct consume_Windows_Security_Cryptography_Certificates_ICmsAttachedSignatureStatics
{
    Windows::Foundation::IAsyncOperation<Windows::Storage::Streams::IBuffer> GenerateSignatureAsync(Windows::Storage::Streams::IBuffer const& data, param::async_iterable<Windows::Security::Cryptography::Certificates::CmsSignerInfo> const& signers, param::async_iterable<Windows::Security::Cryptography::Certificates::Certificate> const& certificates) const;
};
template <> struct consume<Windows::Security::Cryptography::Certificates::ICmsAttachedSignatureStatics> { template <typename D> using type = consume_Windows_Security_Cryptography_Certificates_ICmsAttachedSignatureStatics<D>; };

template <typename D>
struct consume_Windows_Security_Cryptography_Certificates_ICmsDetachedSignature
{
    Windows::Foundation::Collections::IVectorView<Windows::Security::Cryptography::Certificates::Certificate> Certificates() const;
    Windows::Foundation::Collections::IVectorView<Windows::Security::Cryptography::Certificates::CmsSignerInfo> Signers() const;
    Windows::Foundation::IAsyncOperation<Windows::Security::Cryptography::Certificates::SignatureValidationResult> VerifySignatureAsync(Windows::Storage::Streams::IInputStream const& data) const;
};
template <> struct consume<Windows::Security::Cryptography::Certificates::ICmsDetachedSignature> { template <typename D> using type = consume_Windows_Security_Cryptography_Certificates_ICmsDetachedSignature<D>; };

template <typename D>
struct consume_Windows_Security_Cryptography_Certificates_ICmsDetachedSignatureFactory
{
    Windows::Security::Cryptography::Certificates::CmsDetachedSignature CreateCmsDetachedSignature(Windows::Storage::Streams::IBuffer const& inputBlob) const;
};
template <> struct consume<Windows::Security::Cryptography::Certificates::ICmsDetachedSignatureFactory> { template <typename D> using type = consume_Windows_Security_Cryptography_Certificates_ICmsDetachedSignatureFactory<D>; };

template <typename D>
struct consume_Windows_Security_Cryptography_Certificates_ICmsDetachedSignatureStatics
{
    Windows::Foundation::IAsyncOperation<Windows::Storage::Streams::IBuffer> GenerateSignatureAsync(Windows::Storage::Streams::IInputStream const& data, param::async_iterable<Windows::Security::Cryptography::Certificates::CmsSignerInfo> const& signers, param::async_iterable<Windows::Security::Cryptography::Certificates::Certificate> const& certificates) const;
};
template <> struct consume<Windows::Security::Cryptography::Certificates::ICmsDetachedSignatureStatics> { template <typename D> using type = consume_Windows_Security_Cryptography_Certificates_ICmsDetachedSignatureStatics<D>; };

template <typename D>
struct consume_Windows_Security_Cryptography_Certificates_ICmsSignerInfo
{
    Windows::Security::Cryptography::Certificates::Certificate Certificate() const;
    void Certificate(Windows::Security::Cryptography::Certificates::Certificate const& value) const;
    hstring HashAlgorithmName() const;
    void HashAlgorithmName(param::hstring const& value) const;
    Windows::Security::Cryptography::Certificates::CmsTimestampInfo TimestampInfo() const;
};
template <> struct consume<Windows::Security::Cryptography::Certificates::ICmsSignerInfo> { template <typename D> using type = consume_Windows_Security_Cryptography_Certificates_ICmsSignerInfo<D>; };

template <typename D>
struct consume_Windows_Security_Cryptography_Certificates_ICmsTimestampInfo
{
    Windows::Security::Cryptography::Certificates::Certificate SigningCertificate() const;
    Windows::Foundation::Collections::IVectorView<Windows::Security::Cryptography::Certificates::Certificate> Certificates() const;
    Windows::Foundation::DateTime Timestamp() const;
};
template <> struct consume<Windows::Security::Cryptography::Certificates::ICmsTimestampInfo> { template <typename D> using type = consume_Windows_Security_Cryptography_Certificates_ICmsTimestampInfo<D>; };

template <typename D>
struct consume_Windows_Security_Cryptography_Certificates_IKeyAlgorithmNamesStatics
{
    hstring Rsa() const;
    hstring Dsa() const;
    hstring Ecdh256() const;
    hstring Ecdh384() const;
    hstring Ecdh521() const;
    hstring Ecdsa256() const;
    hstring Ecdsa384() const;
    hstring Ecdsa521() const;
};
template <> struct consume<Windows::Security::Cryptography::Certificates::IKeyAlgorithmNamesStatics> { template <typename D> using type = consume_Windows_Security_Cryptography_Certificates_IKeyAlgorithmNamesStatics<D>; };

template <typename D>
struct consume_Windows_Security_Cryptography_Certificates_IKeyAlgorithmNamesStatics2
{
    hstring Ecdsa() const;
    hstring Ecdh() const;
};
template <> struct consume<Windows::Security::Cryptography::Certificates::IKeyAlgorithmNamesStatics2> { template <typename D> using type = consume_Windows_Security_Cryptography_Certificates_IKeyAlgorithmNamesStatics2<D>; };

template <typename D>
struct consume_Windows_Security_Cryptography_Certificates_IKeyAttestationHelperStatics
{
    Windows::Foundation::IAsyncOperation<hstring> DecryptTpmAttestationCredentialAsync(param::hstring const& credential) const;
    hstring GetTpmAttestationCredentialId(param::hstring const& credential) const;
};
template <> struct consume<Windows::Security::Cryptography::Certificates::IKeyAttestationHelperStatics> { template <typename D> using type = consume_Windows_Security_Cryptography_Certificates_IKeyAttestationHelperStatics<D>; };

template <typename D>
struct consume_Windows_Security_Cryptography_Certificates_IKeyAttestationHelperStatics2
{
    Windows::Foundation::IAsyncOperation<hstring> DecryptTpmAttestationCredentialAsync(param::hstring const& credential, param::hstring const& containerName) const;
};
template <> struct consume<Windows::Security::Cryptography::Certificates::IKeyAttestationHelperStatics2> { template <typename D> using type = consume_Windows_Security_Cryptography_Certificates_IKeyAttestationHelperStatics2<D>; };

template <typename D>
struct consume_Windows_Security_Cryptography_Certificates_IKeyStorageProviderNamesStatics
{
    hstring SoftwareKeyStorageProvider() const;
    hstring SmartcardKeyStorageProvider() const;
    hstring PlatformKeyStorageProvider() const;
};
template <> struct consume<Windows::Security::Cryptography::Certificates::IKeyStorageProviderNamesStatics> { template <typename D> using type = consume_Windows_Security_Cryptography_Certificates_IKeyStorageProviderNamesStatics<D>; };

template <typename D>
struct consume_Windows_Security_Cryptography_Certificates_IKeyStorageProviderNamesStatics2
{
    hstring PassportKeyStorageProvider() const;
};
template <> struct consume<Windows::Security::Cryptography::Certificates::IKeyStorageProviderNamesStatics2> { template <typename D> using type = consume_Windows_Security_Cryptography_Certificates_IKeyStorageProviderNamesStatics2<D>; };

template <typename D>
struct consume_Windows_Security_Cryptography_Certificates_IPfxImportParameters
{
    Windows::Security::Cryptography::Certificates::ExportOption Exportable() const;
    void Exportable(Windows::Security::Cryptography::Certificates::ExportOption const& value) const;
    Windows::Security::Cryptography::Certificates::KeyProtectionLevel KeyProtectionLevel() const;
    void KeyProtectionLevel(Windows::Security::Cryptography::Certificates::KeyProtectionLevel const& value) const;
    Windows::Security::Cryptography::Certificates::InstallOptions InstallOptions() const;
    void InstallOptions(Windows::Security::Cryptography::Certificates::InstallOptions const& value) const;
    hstring FriendlyName() const;
    void FriendlyName(param::hstring const& value) const;
    hstring KeyStorageProviderName() const;
    void KeyStorageProviderName(param::hstring const& value) const;
    hstring ContainerNamePrefix() const;
    void ContainerNamePrefix(param::hstring const& value) const;
    hstring ReaderName() const;
    void ReaderName(param::hstring const& value) const;
};
template <> struct consume<Windows::Security::Cryptography::Certificates::IPfxImportParameters> { template <typename D> using type = consume_Windows_Security_Cryptography_Certificates_IPfxImportParameters<D>; };

template <typename D>
struct consume_Windows_Security_Cryptography_Certificates_IStandardCertificateStoreNamesStatics
{
    hstring Personal() const;
    hstring TrustedRootCertificationAuthorities() const;
    hstring IntermediateCertificationAuthorities() const;
};
template <> struct consume<Windows::Security::Cryptography::Certificates::IStandardCertificateStoreNamesStatics> { template <typename D> using type = consume_Windows_Security_Cryptography_Certificates_IStandardCertificateStoreNamesStatics<D>; };

template <typename D>
struct consume_Windows_Security_Cryptography_Certificates_ISubjectAlternativeNameInfo
{
    Windows::Foundation::Collections::IVectorView<hstring> EmailName() const;
    Windows::Foundation::Collections::IVectorView<hstring> IPAddress() const;
    Windows::Foundation::Collections::IVectorView<hstring> Url() const;
    Windows::Foundation::Collections::IVectorView<hstring> DnsName() const;
    Windows::Foundation::Collections::IVectorView<hstring> DistinguishedName() const;
    Windows::Foundation::Collections::IVectorView<hstring> PrincipalName() const;
};
template <> struct consume<Windows::Security::Cryptography::Certificates::ISubjectAlternativeNameInfo> { template <typename D> using type = consume_Windows_Security_Cryptography_Certificates_ISubjectAlternativeNameInfo<D>; };

template <typename D>
struct consume_Windows_Security_Cryptography_Certificates_ISubjectAlternativeNameInfo2
{
    Windows::Foundation::Collections::IVector<hstring> EmailNames() const;
    Windows::Foundation::Collections::IVector<hstring> IPAddresses() const;
    Windows::Foundation::Collections::IVector<hstring> Urls() const;
    Windows::Foundation::Collections::IVector<hstring> DnsNames() const;
    Windows::Foundation::Collections::IVector<hstring> DistinguishedNames() const;
    Windows::Foundation::Collections::IVector<hstring> PrincipalNames() const;
    Windows::Security::Cryptography::Certificates::CertificateExtension Extension() const;
};
template <> struct consume<Windows::Security::Cryptography::Certificates::ISubjectAlternativeNameInfo2> { template <typename D> using type = consume_Windows_Security_Cryptography_Certificates_ISubjectAlternativeNameInfo2<D>; };

template <typename D>
struct consume_Windows_Security_Cryptography_Certificates_IUserCertificateEnrollmentManager
{
    Windows::Foundation::IAsyncOperation<hstring> CreateRequestAsync(Windows::Security::Cryptography::Certificates::CertificateRequestProperties const& request) const;
    Windows::Foundation::IAsyncAction InstallCertificateAsync(param::hstring const& certificate, Windows::Security::Cryptography::Certificates::InstallOptions const& installOption) const;
    Windows::Foundation::IAsyncAction ImportPfxDataAsync(param::hstring const& pfxData, param::hstring const& password, Windows::Security::Cryptography::Certificates::ExportOption const& exportable, Windows::Security::Cryptography::Certificates::KeyProtectionLevel const& keyProtectionLevel, Windows::Security::Cryptography::Certificates::InstallOptions const& installOption, param::hstring const& friendlyName) const;
    Windows::Foundation::IAsyncAction ImportPfxDataAsync(param::hstring const& pfxData, param::hstring const& password, Windows::Security::Cryptography::Certificates::ExportOption const& exportable, Windows::Security::Cryptography::Certificates::KeyProtectionLevel const& keyProtectionLevel, Windows::Security::Cryptography::Certificates::InstallOptions const& installOption, param::hstring const& friendlyName, param::hstring const& keyStorageProvider) const;
};
template <> struct consume<Windows::Security::Cryptography::Certificates::IUserCertificateEnrollmentManager> { template <typename D> using type = consume_Windows_Security_Cryptography_Certificates_IUserCertificateEnrollmentManager<D>; };

template <typename D>
struct consume_Windows_Security_Cryptography_Certificates_IUserCertificateEnrollmentManager2
{
    Windows::Foundation::IAsyncAction ImportPfxDataAsync(param::hstring const& pfxData, param::hstring const& password, Windows::Security::Cryptography::Certificates::PfxImportParameters const& pfxImportParameters) const;
};
template <> struct consume<Windows::Security::Cryptography::Certificates::IUserCertificateEnrollmentManager2> { template <typename D> using type = consume_Windows_Security_Cryptography_Certificates_IUserCertificateEnrollmentManager2<D>; };

template <typename D>
struct consume_Windows_Security_Cryptography_Certificates_IUserCertificateStore
{
    Windows::Foundation::IAsyncOperation<bool> RequestAddAsync(Windows::Security::Cryptography::Certificates::Certificate const& certificate) const;
    Windows::Foundation::IAsyncOperation<bool> RequestDeleteAsync(Windows::Security::Cryptography::Certificates::Certificate const& certificate) const;
    hstring Name() const;
};
template <> struct consume<Windows::Security::Cryptography::Certificates::IUserCertificateStore> { template <typename D> using type = consume_Windows_Security_Cryptography_Certificates_IUserCertificateStore<D>; };

}
