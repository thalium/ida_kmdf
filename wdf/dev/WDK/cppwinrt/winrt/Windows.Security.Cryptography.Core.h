// C++/WinRT v1.0.190111.3

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#pragma once

#include "winrt/base.h"

#include "winrt/Windows.Foundation.h"
#include "winrt/Windows.Foundation.Collections.h"
#include "winrt/impl/Windows.Security.Cryptography.Certificates.2.h"
#include "winrt/impl/Windows.Storage.Streams.2.h"
#include "winrt/impl/Windows.Security.Cryptography.Core.2.h"
#include "winrt/Windows.Security.Cryptography.h"

namespace winrt::impl {

template <typename D> hstring consume_Windows_Security_Cryptography_Core_IAsymmetricAlgorithmNamesStatics<D>::RsaPkcs1() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Security::Cryptography::Core::IAsymmetricAlgorithmNamesStatics)->get_RsaPkcs1(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_Security_Cryptography_Core_IAsymmetricAlgorithmNamesStatics<D>::RsaOaepSha1() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Security::Cryptography::Core::IAsymmetricAlgorithmNamesStatics)->get_RsaOaepSha1(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_Security_Cryptography_Core_IAsymmetricAlgorithmNamesStatics<D>::RsaOaepSha256() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Security::Cryptography::Core::IAsymmetricAlgorithmNamesStatics)->get_RsaOaepSha256(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_Security_Cryptography_Core_IAsymmetricAlgorithmNamesStatics<D>::RsaOaepSha384() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Security::Cryptography::Core::IAsymmetricAlgorithmNamesStatics)->get_RsaOaepSha384(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_Security_Cryptography_Core_IAsymmetricAlgorithmNamesStatics<D>::RsaOaepSha512() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Security::Cryptography::Core::IAsymmetricAlgorithmNamesStatics)->get_RsaOaepSha512(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_Security_Cryptography_Core_IAsymmetricAlgorithmNamesStatics<D>::EcdsaP256Sha256() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Security::Cryptography::Core::IAsymmetricAlgorithmNamesStatics)->get_EcdsaP256Sha256(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_Security_Cryptography_Core_IAsymmetricAlgorithmNamesStatics<D>::EcdsaP384Sha384() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Security::Cryptography::Core::IAsymmetricAlgorithmNamesStatics)->get_EcdsaP384Sha384(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_Security_Cryptography_Core_IAsymmetricAlgorithmNamesStatics<D>::EcdsaP521Sha512() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Security::Cryptography::Core::IAsymmetricAlgorithmNamesStatics)->get_EcdsaP521Sha512(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_Security_Cryptography_Core_IAsymmetricAlgorithmNamesStatics<D>::DsaSha1() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Security::Cryptography::Core::IAsymmetricAlgorithmNamesStatics)->get_DsaSha1(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_Security_Cryptography_Core_IAsymmetricAlgorithmNamesStatics<D>::DsaSha256() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Security::Cryptography::Core::IAsymmetricAlgorithmNamesStatics)->get_DsaSha256(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_Security_Cryptography_Core_IAsymmetricAlgorithmNamesStatics<D>::RsaSignPkcs1Sha1() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Security::Cryptography::Core::IAsymmetricAlgorithmNamesStatics)->get_RsaSignPkcs1Sha1(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_Security_Cryptography_Core_IAsymmetricAlgorithmNamesStatics<D>::RsaSignPkcs1Sha256() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Security::Cryptography::Core::IAsymmetricAlgorithmNamesStatics)->get_RsaSignPkcs1Sha256(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_Security_Cryptography_Core_IAsymmetricAlgorithmNamesStatics<D>::RsaSignPkcs1Sha384() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Security::Cryptography::Core::IAsymmetricAlgorithmNamesStatics)->get_RsaSignPkcs1Sha384(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_Security_Cryptography_Core_IAsymmetricAlgorithmNamesStatics<D>::RsaSignPkcs1Sha512() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Security::Cryptography::Core::IAsymmetricAlgorithmNamesStatics)->get_RsaSignPkcs1Sha512(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_Security_Cryptography_Core_IAsymmetricAlgorithmNamesStatics<D>::RsaSignPssSha1() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Security::Cryptography::Core::IAsymmetricAlgorithmNamesStatics)->get_RsaSignPssSha1(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_Security_Cryptography_Core_IAsymmetricAlgorithmNamesStatics<D>::RsaSignPssSha256() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Security::Cryptography::Core::IAsymmetricAlgorithmNamesStatics)->get_RsaSignPssSha256(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_Security_Cryptography_Core_IAsymmetricAlgorithmNamesStatics<D>::RsaSignPssSha384() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Security::Cryptography::Core::IAsymmetricAlgorithmNamesStatics)->get_RsaSignPssSha384(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_Security_Cryptography_Core_IAsymmetricAlgorithmNamesStatics<D>::RsaSignPssSha512() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Security::Cryptography::Core::IAsymmetricAlgorithmNamesStatics)->get_RsaSignPssSha512(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_Security_Cryptography_Core_IAsymmetricAlgorithmNamesStatics2<D>::EcdsaSha256() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Security::Cryptography::Core::IAsymmetricAlgorithmNamesStatics2)->get_EcdsaSha256(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_Security_Cryptography_Core_IAsymmetricAlgorithmNamesStatics2<D>::EcdsaSha384() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Security::Cryptography::Core::IAsymmetricAlgorithmNamesStatics2)->get_EcdsaSha384(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_Security_Cryptography_Core_IAsymmetricAlgorithmNamesStatics2<D>::EcdsaSha512() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Security::Cryptography::Core::IAsymmetricAlgorithmNamesStatics2)->get_EcdsaSha512(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_Security_Cryptography_Core_IAsymmetricKeyAlgorithmProvider<D>::AlgorithmName() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Security::Cryptography::Core::IAsymmetricKeyAlgorithmProvider)->get_AlgorithmName(put_abi(value)));
    return value;
}

template <typename D> Windows::Security::Cryptography::Core::CryptographicKey consume_Windows_Security_Cryptography_Core_IAsymmetricKeyAlgorithmProvider<D>::CreateKeyPair(uint32_t keySize) const
{
    Windows::Security::Cryptography::Core::CryptographicKey key{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Security::Cryptography::Core::IAsymmetricKeyAlgorithmProvider)->CreateKeyPair(keySize, put_abi(key)));
    return key;
}

template <typename D> Windows::Security::Cryptography::Core::CryptographicKey consume_Windows_Security_Cryptography_Core_IAsymmetricKeyAlgorithmProvider<D>::ImportKeyPair(Windows::Storage::Streams::IBuffer const& keyBlob) const
{
    Windows::Security::Cryptography::Core::CryptographicKey key{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Security::Cryptography::Core::IAsymmetricKeyAlgorithmProvider)->ImportDefaultPrivateKeyBlob(get_abi(keyBlob), put_abi(key)));
    return key;
}

template <typename D> Windows::Security::Cryptography::Core::CryptographicKey consume_Windows_Security_Cryptography_Core_IAsymmetricKeyAlgorithmProvider<D>::ImportKeyPair(Windows::Storage::Streams::IBuffer const& keyBlob, Windows::Security::Cryptography::Core::CryptographicPrivateKeyBlobType const& BlobType) const
{
    Windows::Security::Cryptography::Core::CryptographicKey key{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Security::Cryptography::Core::IAsymmetricKeyAlgorithmProvider)->ImportKeyPairWithBlobType(get_abi(keyBlob), get_abi(BlobType), put_abi(key)));
    return key;
}

template <typename D> Windows::Security::Cryptography::Core::CryptographicKey consume_Windows_Security_Cryptography_Core_IAsymmetricKeyAlgorithmProvider<D>::ImportPublicKey(Windows::Storage::Streams::IBuffer const& keyBlob) const
{
    Windows::Security::Cryptography::Core::CryptographicKey key{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Security::Cryptography::Core::IAsymmetricKeyAlgorithmProvider)->ImportDefaultPublicKeyBlob(get_abi(keyBlob), put_abi(key)));
    return key;
}

template <typename D> Windows::Security::Cryptography::Core::CryptographicKey consume_Windows_Security_Cryptography_Core_IAsymmetricKeyAlgorithmProvider<D>::ImportPublicKey(Windows::Storage::Streams::IBuffer const& keyBlob, Windows::Security::Cryptography::Core::CryptographicPublicKeyBlobType const& BlobType) const
{
    Windows::Security::Cryptography::Core::CryptographicKey key{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Security::Cryptography::Core::IAsymmetricKeyAlgorithmProvider)->ImportPublicKeyWithBlobType(get_abi(keyBlob), get_abi(BlobType), put_abi(key)));
    return key;
}

template <typename D> Windows::Security::Cryptography::Core::CryptographicKey consume_Windows_Security_Cryptography_Core_IAsymmetricKeyAlgorithmProvider2<D>::CreateKeyPairWithCurveName(param::hstring const& curveName) const
{
    Windows::Security::Cryptography::Core::CryptographicKey key{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Security::Cryptography::Core::IAsymmetricKeyAlgorithmProvider2)->CreateKeyPairWithCurveName(get_abi(curveName), put_abi(key)));
    return key;
}

template <typename D> Windows::Security::Cryptography::Core::CryptographicKey consume_Windows_Security_Cryptography_Core_IAsymmetricKeyAlgorithmProvider2<D>::CreateKeyPairWithCurveParameters(array_view<uint8_t const> parameters) const
{
    Windows::Security::Cryptography::Core::CryptographicKey key{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Security::Cryptography::Core::IAsymmetricKeyAlgorithmProvider2)->CreateKeyPairWithCurveParameters(parameters.size(), get_abi(parameters), put_abi(key)));
    return key;
}

template <typename D> Windows::Security::Cryptography::Core::AsymmetricKeyAlgorithmProvider consume_Windows_Security_Cryptography_Core_IAsymmetricKeyAlgorithmProviderStatics<D>::OpenAlgorithm(param::hstring const& algorithm) const
{
    Windows::Security::Cryptography::Core::AsymmetricKeyAlgorithmProvider provider{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Security::Cryptography::Core::IAsymmetricKeyAlgorithmProviderStatics)->OpenAlgorithm(get_abi(algorithm), put_abi(provider)));
    return provider;
}

template <typename D> Windows::Storage::Streams::IBuffer consume_Windows_Security_Cryptography_Core_ICryptographicEngineStatics<D>::Encrypt(Windows::Security::Cryptography::Core::CryptographicKey const& key, Windows::Storage::Streams::IBuffer const& data, Windows::Storage::Streams::IBuffer const& iv) const
{
    Windows::Storage::Streams::IBuffer value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Security::Cryptography::Core::ICryptographicEngineStatics)->Encrypt(get_abi(key), get_abi(data), get_abi(iv), put_abi(value)));
    return value;
}

template <typename D> Windows::Storage::Streams::IBuffer consume_Windows_Security_Cryptography_Core_ICryptographicEngineStatics<D>::Decrypt(Windows::Security::Cryptography::Core::CryptographicKey const& key, Windows::Storage::Streams::IBuffer const& data, Windows::Storage::Streams::IBuffer const& iv) const
{
    Windows::Storage::Streams::IBuffer value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Security::Cryptography::Core::ICryptographicEngineStatics)->Decrypt(get_abi(key), get_abi(data), get_abi(iv), put_abi(value)));
    return value;
}

template <typename D> Windows::Security::Cryptography::Core::EncryptedAndAuthenticatedData consume_Windows_Security_Cryptography_Core_ICryptographicEngineStatics<D>::EncryptAndAuthenticate(Windows::Security::Cryptography::Core::CryptographicKey const& key, Windows::Storage::Streams::IBuffer const& data, Windows::Storage::Streams::IBuffer const& nonce, Windows::Storage::Streams::IBuffer const& authenticatedData) const
{
    Windows::Security::Cryptography::Core::EncryptedAndAuthenticatedData value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Security::Cryptography::Core::ICryptographicEngineStatics)->EncryptAndAuthenticate(get_abi(key), get_abi(data), get_abi(nonce), get_abi(authenticatedData), put_abi(value)));
    return value;
}

template <typename D> Windows::Storage::Streams::IBuffer consume_Windows_Security_Cryptography_Core_ICryptographicEngineStatics<D>::DecryptAndAuthenticate(Windows::Security::Cryptography::Core::CryptographicKey const& key, Windows::Storage::Streams::IBuffer const& data, Windows::Storage::Streams::IBuffer const& nonce, Windows::Storage::Streams::IBuffer const& authenticationTag, Windows::Storage::Streams::IBuffer const& authenticatedData) const
{
    Windows::Storage::Streams::IBuffer value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Security::Cryptography::Core::ICryptographicEngineStatics)->DecryptAndAuthenticate(get_abi(key), get_abi(data), get_abi(nonce), get_abi(authenticationTag), get_abi(authenticatedData), put_abi(value)));
    return value;
}

template <typename D> Windows::Storage::Streams::IBuffer consume_Windows_Security_Cryptography_Core_ICryptographicEngineStatics<D>::Sign(Windows::Security::Cryptography::Core::CryptographicKey const& key, Windows::Storage::Streams::IBuffer const& data) const
{
    Windows::Storage::Streams::IBuffer value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Security::Cryptography::Core::ICryptographicEngineStatics)->Sign(get_abi(key), get_abi(data), put_abi(value)));
    return value;
}

template <typename D> bool consume_Windows_Security_Cryptography_Core_ICryptographicEngineStatics<D>::VerifySignature(Windows::Security::Cryptography::Core::CryptographicKey const& key, Windows::Storage::Streams::IBuffer const& data, Windows::Storage::Streams::IBuffer const& signature) const
{
    bool isAuthenticated{};
    check_hresult(WINRT_SHIM(Windows::Security::Cryptography::Core::ICryptographicEngineStatics)->VerifySignature(get_abi(key), get_abi(data), get_abi(signature), &isAuthenticated));
    return isAuthenticated;
}

template <typename D> Windows::Storage::Streams::IBuffer consume_Windows_Security_Cryptography_Core_ICryptographicEngineStatics<D>::DeriveKeyMaterial(Windows::Security::Cryptography::Core::CryptographicKey const& key, Windows::Security::Cryptography::Core::KeyDerivationParameters const& parameters, uint32_t desiredKeySize) const
{
    Windows::Storage::Streams::IBuffer keyMaterial{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Security::Cryptography::Core::ICryptographicEngineStatics)->DeriveKeyMaterial(get_abi(key), get_abi(parameters), desiredKeySize, put_abi(keyMaterial)));
    return keyMaterial;
}

template <typename D> Windows::Storage::Streams::IBuffer consume_Windows_Security_Cryptography_Core_ICryptographicEngineStatics2<D>::SignHashedData(Windows::Security::Cryptography::Core::CryptographicKey const& key, Windows::Storage::Streams::IBuffer const& data) const
{
    Windows::Storage::Streams::IBuffer value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Security::Cryptography::Core::ICryptographicEngineStatics2)->SignHashedData(get_abi(key), get_abi(data), put_abi(value)));
    return value;
}

template <typename D> bool consume_Windows_Security_Cryptography_Core_ICryptographicEngineStatics2<D>::VerifySignatureWithHashInput(Windows::Security::Cryptography::Core::CryptographicKey const& key, Windows::Storage::Streams::IBuffer const& data, Windows::Storage::Streams::IBuffer const& signature) const
{
    bool isAuthenticated{};
    check_hresult(WINRT_SHIM(Windows::Security::Cryptography::Core::ICryptographicEngineStatics2)->VerifySignatureWithHashInput(get_abi(key), get_abi(data), get_abi(signature), &isAuthenticated));
    return isAuthenticated;
}

template <typename D> Windows::Foundation::IAsyncOperation<Windows::Storage::Streams::IBuffer> consume_Windows_Security_Cryptography_Core_ICryptographicEngineStatics2<D>::DecryptAsync(Windows::Security::Cryptography::Core::CryptographicKey const& key, Windows::Storage::Streams::IBuffer const& data, Windows::Storage::Streams::IBuffer const& iv) const
{
    Windows::Foundation::IAsyncOperation<Windows::Storage::Streams::IBuffer> value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Security::Cryptography::Core::ICryptographicEngineStatics2)->DecryptAsync(get_abi(key), get_abi(data), get_abi(iv), put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::IAsyncOperation<Windows::Storage::Streams::IBuffer> consume_Windows_Security_Cryptography_Core_ICryptographicEngineStatics2<D>::SignAsync(Windows::Security::Cryptography::Core::CryptographicKey const& key, Windows::Storage::Streams::IBuffer const& data) const
{
    Windows::Foundation::IAsyncOperation<Windows::Storage::Streams::IBuffer> value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Security::Cryptography::Core::ICryptographicEngineStatics2)->SignAsync(get_abi(key), get_abi(data), put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::IAsyncOperation<Windows::Storage::Streams::IBuffer> consume_Windows_Security_Cryptography_Core_ICryptographicEngineStatics2<D>::SignHashedDataAsync(Windows::Security::Cryptography::Core::CryptographicKey const& key, Windows::Storage::Streams::IBuffer const& data) const
{
    Windows::Foundation::IAsyncOperation<Windows::Storage::Streams::IBuffer> value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Security::Cryptography::Core::ICryptographicEngineStatics2)->SignHashedDataAsync(get_abi(key), get_abi(data), put_abi(value)));
    return value;
}

template <typename D> uint32_t consume_Windows_Security_Cryptography_Core_ICryptographicKey<D>::KeySize() const
{
    uint32_t value{};
    check_hresult(WINRT_SHIM(Windows::Security::Cryptography::Core::ICryptographicKey)->get_KeySize(&value));
    return value;
}

template <typename D> Windows::Storage::Streams::IBuffer consume_Windows_Security_Cryptography_Core_ICryptographicKey<D>::Export() const
{
    Windows::Storage::Streams::IBuffer value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Security::Cryptography::Core::ICryptographicKey)->ExportDefaultPrivateKeyBlobType(put_abi(value)));
    return value;
}

template <typename D> Windows::Storage::Streams::IBuffer consume_Windows_Security_Cryptography_Core_ICryptographicKey<D>::Export(Windows::Security::Cryptography::Core::CryptographicPrivateKeyBlobType const& BlobType) const
{
    Windows::Storage::Streams::IBuffer value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Security::Cryptography::Core::ICryptographicKey)->ExportPrivateKeyWithBlobType(get_abi(BlobType), put_abi(value)));
    return value;
}

template <typename D> Windows::Storage::Streams::IBuffer consume_Windows_Security_Cryptography_Core_ICryptographicKey<D>::ExportPublicKey() const
{
    Windows::Storage::Streams::IBuffer value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Security::Cryptography::Core::ICryptographicKey)->ExportDefaultPublicKeyBlobType(put_abi(value)));
    return value;
}

template <typename D> Windows::Storage::Streams::IBuffer consume_Windows_Security_Cryptography_Core_ICryptographicKey<D>::ExportPublicKey(Windows::Security::Cryptography::Core::CryptographicPublicKeyBlobType const& BlobType) const
{
    Windows::Storage::Streams::IBuffer value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Security::Cryptography::Core::ICryptographicKey)->ExportPublicKeyWithBlobType(get_abi(BlobType), put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_Security_Cryptography_Core_IEccCurveNamesStatics<D>::BrainpoolP160r1() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Security::Cryptography::Core::IEccCurveNamesStatics)->get_BrainpoolP160r1(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_Security_Cryptography_Core_IEccCurveNamesStatics<D>::BrainpoolP160t1() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Security::Cryptography::Core::IEccCurveNamesStatics)->get_BrainpoolP160t1(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_Security_Cryptography_Core_IEccCurveNamesStatics<D>::BrainpoolP192r1() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Security::Cryptography::Core::IEccCurveNamesStatics)->get_BrainpoolP192r1(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_Security_Cryptography_Core_IEccCurveNamesStatics<D>::BrainpoolP192t1() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Security::Cryptography::Core::IEccCurveNamesStatics)->get_BrainpoolP192t1(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_Security_Cryptography_Core_IEccCurveNamesStatics<D>::BrainpoolP224r1() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Security::Cryptography::Core::IEccCurveNamesStatics)->get_BrainpoolP224r1(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_Security_Cryptography_Core_IEccCurveNamesStatics<D>::BrainpoolP224t1() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Security::Cryptography::Core::IEccCurveNamesStatics)->get_BrainpoolP224t1(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_Security_Cryptography_Core_IEccCurveNamesStatics<D>::BrainpoolP256r1() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Security::Cryptography::Core::IEccCurveNamesStatics)->get_BrainpoolP256r1(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_Security_Cryptography_Core_IEccCurveNamesStatics<D>::BrainpoolP256t1() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Security::Cryptography::Core::IEccCurveNamesStatics)->get_BrainpoolP256t1(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_Security_Cryptography_Core_IEccCurveNamesStatics<D>::BrainpoolP320r1() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Security::Cryptography::Core::IEccCurveNamesStatics)->get_BrainpoolP320r1(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_Security_Cryptography_Core_IEccCurveNamesStatics<D>::BrainpoolP320t1() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Security::Cryptography::Core::IEccCurveNamesStatics)->get_BrainpoolP320t1(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_Security_Cryptography_Core_IEccCurveNamesStatics<D>::BrainpoolP384r1() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Security::Cryptography::Core::IEccCurveNamesStatics)->get_BrainpoolP384r1(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_Security_Cryptography_Core_IEccCurveNamesStatics<D>::BrainpoolP384t1() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Security::Cryptography::Core::IEccCurveNamesStatics)->get_BrainpoolP384t1(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_Security_Cryptography_Core_IEccCurveNamesStatics<D>::BrainpoolP512r1() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Security::Cryptography::Core::IEccCurveNamesStatics)->get_BrainpoolP512r1(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_Security_Cryptography_Core_IEccCurveNamesStatics<D>::BrainpoolP512t1() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Security::Cryptography::Core::IEccCurveNamesStatics)->get_BrainpoolP512t1(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_Security_Cryptography_Core_IEccCurveNamesStatics<D>::Curve25519() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Security::Cryptography::Core::IEccCurveNamesStatics)->get_Curve25519(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_Security_Cryptography_Core_IEccCurveNamesStatics<D>::Ec192wapi() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Security::Cryptography::Core::IEccCurveNamesStatics)->get_Ec192wapi(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_Security_Cryptography_Core_IEccCurveNamesStatics<D>::NistP192() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Security::Cryptography::Core::IEccCurveNamesStatics)->get_NistP192(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_Security_Cryptography_Core_IEccCurveNamesStatics<D>::NistP224() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Security::Cryptography::Core::IEccCurveNamesStatics)->get_NistP224(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_Security_Cryptography_Core_IEccCurveNamesStatics<D>::NistP256() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Security::Cryptography::Core::IEccCurveNamesStatics)->get_NistP256(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_Security_Cryptography_Core_IEccCurveNamesStatics<D>::NistP384() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Security::Cryptography::Core::IEccCurveNamesStatics)->get_NistP384(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_Security_Cryptography_Core_IEccCurveNamesStatics<D>::NistP521() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Security::Cryptography::Core::IEccCurveNamesStatics)->get_NistP521(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_Security_Cryptography_Core_IEccCurveNamesStatics<D>::NumsP256t1() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Security::Cryptography::Core::IEccCurveNamesStatics)->get_NumsP256t1(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_Security_Cryptography_Core_IEccCurveNamesStatics<D>::NumsP384t1() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Security::Cryptography::Core::IEccCurveNamesStatics)->get_NumsP384t1(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_Security_Cryptography_Core_IEccCurveNamesStatics<D>::NumsP512t1() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Security::Cryptography::Core::IEccCurveNamesStatics)->get_NumsP512t1(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_Security_Cryptography_Core_IEccCurveNamesStatics<D>::SecP160k1() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Security::Cryptography::Core::IEccCurveNamesStatics)->get_SecP160k1(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_Security_Cryptography_Core_IEccCurveNamesStatics<D>::SecP160r1() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Security::Cryptography::Core::IEccCurveNamesStatics)->get_SecP160r1(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_Security_Cryptography_Core_IEccCurveNamesStatics<D>::SecP160r2() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Security::Cryptography::Core::IEccCurveNamesStatics)->get_SecP160r2(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_Security_Cryptography_Core_IEccCurveNamesStatics<D>::SecP192k1() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Security::Cryptography::Core::IEccCurveNamesStatics)->get_SecP192k1(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_Security_Cryptography_Core_IEccCurveNamesStatics<D>::SecP192r1() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Security::Cryptography::Core::IEccCurveNamesStatics)->get_SecP192r1(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_Security_Cryptography_Core_IEccCurveNamesStatics<D>::SecP224k1() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Security::Cryptography::Core::IEccCurveNamesStatics)->get_SecP224k1(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_Security_Cryptography_Core_IEccCurveNamesStatics<D>::SecP224r1() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Security::Cryptography::Core::IEccCurveNamesStatics)->get_SecP224r1(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_Security_Cryptography_Core_IEccCurveNamesStatics<D>::SecP256k1() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Security::Cryptography::Core::IEccCurveNamesStatics)->get_SecP256k1(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_Security_Cryptography_Core_IEccCurveNamesStatics<D>::SecP256r1() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Security::Cryptography::Core::IEccCurveNamesStatics)->get_SecP256r1(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_Security_Cryptography_Core_IEccCurveNamesStatics<D>::SecP384r1() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Security::Cryptography::Core::IEccCurveNamesStatics)->get_SecP384r1(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_Security_Cryptography_Core_IEccCurveNamesStatics<D>::SecP521r1() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Security::Cryptography::Core::IEccCurveNamesStatics)->get_SecP521r1(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_Security_Cryptography_Core_IEccCurveNamesStatics<D>::Wtls7() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Security::Cryptography::Core::IEccCurveNamesStatics)->get_Wtls7(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_Security_Cryptography_Core_IEccCurveNamesStatics<D>::Wtls9() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Security::Cryptography::Core::IEccCurveNamesStatics)->get_Wtls9(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_Security_Cryptography_Core_IEccCurveNamesStatics<D>::Wtls12() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Security::Cryptography::Core::IEccCurveNamesStatics)->get_Wtls12(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_Security_Cryptography_Core_IEccCurveNamesStatics<D>::X962P192v1() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Security::Cryptography::Core::IEccCurveNamesStatics)->get_X962P192v1(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_Security_Cryptography_Core_IEccCurveNamesStatics<D>::X962P192v2() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Security::Cryptography::Core::IEccCurveNamesStatics)->get_X962P192v2(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_Security_Cryptography_Core_IEccCurveNamesStatics<D>::X962P192v3() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Security::Cryptography::Core::IEccCurveNamesStatics)->get_X962P192v3(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_Security_Cryptography_Core_IEccCurveNamesStatics<D>::X962P239v1() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Security::Cryptography::Core::IEccCurveNamesStatics)->get_X962P239v1(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_Security_Cryptography_Core_IEccCurveNamesStatics<D>::X962P239v2() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Security::Cryptography::Core::IEccCurveNamesStatics)->get_X962P239v2(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_Security_Cryptography_Core_IEccCurveNamesStatics<D>::X962P239v3() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Security::Cryptography::Core::IEccCurveNamesStatics)->get_X962P239v3(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_Security_Cryptography_Core_IEccCurveNamesStatics<D>::X962P256v1() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Security::Cryptography::Core::IEccCurveNamesStatics)->get_X962P256v1(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::Collections::IVectorView<hstring> consume_Windows_Security_Cryptography_Core_IEccCurveNamesStatics<D>::AllEccCurveNames() const
{
    Windows::Foundation::Collections::IVectorView<hstring> value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Security::Cryptography::Core::IEccCurveNamesStatics)->get_AllEccCurveNames(put_abi(value)));
    return value;
}

template <typename D> Windows::Storage::Streams::IBuffer consume_Windows_Security_Cryptography_Core_IEncryptedAndAuthenticatedData<D>::EncryptedData() const
{
    Windows::Storage::Streams::IBuffer value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Security::Cryptography::Core::IEncryptedAndAuthenticatedData)->get_EncryptedData(put_abi(value)));
    return value;
}

template <typename D> Windows::Storage::Streams::IBuffer consume_Windows_Security_Cryptography_Core_IEncryptedAndAuthenticatedData<D>::AuthenticationTag() const
{
    Windows::Storage::Streams::IBuffer value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Security::Cryptography::Core::IEncryptedAndAuthenticatedData)->get_AuthenticationTag(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_Security_Cryptography_Core_IHashAlgorithmNamesStatics<D>::Md5() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Security::Cryptography::Core::IHashAlgorithmNamesStatics)->get_Md5(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_Security_Cryptography_Core_IHashAlgorithmNamesStatics<D>::Sha1() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Security::Cryptography::Core::IHashAlgorithmNamesStatics)->get_Sha1(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_Security_Cryptography_Core_IHashAlgorithmNamesStatics<D>::Sha256() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Security::Cryptography::Core::IHashAlgorithmNamesStatics)->get_Sha256(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_Security_Cryptography_Core_IHashAlgorithmNamesStatics<D>::Sha384() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Security::Cryptography::Core::IHashAlgorithmNamesStatics)->get_Sha384(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_Security_Cryptography_Core_IHashAlgorithmNamesStatics<D>::Sha512() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Security::Cryptography::Core::IHashAlgorithmNamesStatics)->get_Sha512(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_Security_Cryptography_Core_IHashAlgorithmProvider<D>::AlgorithmName() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Security::Cryptography::Core::IHashAlgorithmProvider)->get_AlgorithmName(put_abi(value)));
    return value;
}

template <typename D> uint32_t consume_Windows_Security_Cryptography_Core_IHashAlgorithmProvider<D>::HashLength() const
{
    uint32_t value{};
    check_hresult(WINRT_SHIM(Windows::Security::Cryptography::Core::IHashAlgorithmProvider)->get_HashLength(&value));
    return value;
}

template <typename D> Windows::Storage::Streams::IBuffer consume_Windows_Security_Cryptography_Core_IHashAlgorithmProvider<D>::HashData(Windows::Storage::Streams::IBuffer const& data) const
{
    Windows::Storage::Streams::IBuffer value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Security::Cryptography::Core::IHashAlgorithmProvider)->HashData(get_abi(data), put_abi(value)));
    return value;
}

template <typename D> Windows::Security::Cryptography::Core::CryptographicHash consume_Windows_Security_Cryptography_Core_IHashAlgorithmProvider<D>::CreateHash() const
{
    Windows::Security::Cryptography::Core::CryptographicHash Value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Security::Cryptography::Core::IHashAlgorithmProvider)->CreateHash(put_abi(Value)));
    return Value;
}

template <typename D> Windows::Security::Cryptography::Core::HashAlgorithmProvider consume_Windows_Security_Cryptography_Core_IHashAlgorithmProviderStatics<D>::OpenAlgorithm(param::hstring const& algorithm) const
{
    Windows::Security::Cryptography::Core::HashAlgorithmProvider provider{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Security::Cryptography::Core::IHashAlgorithmProviderStatics)->OpenAlgorithm(get_abi(algorithm), put_abi(provider)));
    return provider;
}

template <typename D> void consume_Windows_Security_Cryptography_Core_IHashComputation<D>::Append(Windows::Storage::Streams::IBuffer const& data) const
{
    check_hresult(WINRT_SHIM(Windows::Security::Cryptography::Core::IHashComputation)->Append(get_abi(data)));
}

template <typename D> Windows::Storage::Streams::IBuffer consume_Windows_Security_Cryptography_Core_IHashComputation<D>::GetValueAndReset() const
{
    Windows::Storage::Streams::IBuffer value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Security::Cryptography::Core::IHashComputation)->GetValueAndReset(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_Security_Cryptography_Core_IKeyDerivationAlgorithmNamesStatics<D>::Pbkdf2Md5() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Security::Cryptography::Core::IKeyDerivationAlgorithmNamesStatics)->get_Pbkdf2Md5(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_Security_Cryptography_Core_IKeyDerivationAlgorithmNamesStatics<D>::Pbkdf2Sha1() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Security::Cryptography::Core::IKeyDerivationAlgorithmNamesStatics)->get_Pbkdf2Sha1(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_Security_Cryptography_Core_IKeyDerivationAlgorithmNamesStatics<D>::Pbkdf2Sha256() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Security::Cryptography::Core::IKeyDerivationAlgorithmNamesStatics)->get_Pbkdf2Sha256(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_Security_Cryptography_Core_IKeyDerivationAlgorithmNamesStatics<D>::Pbkdf2Sha384() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Security::Cryptography::Core::IKeyDerivationAlgorithmNamesStatics)->get_Pbkdf2Sha384(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_Security_Cryptography_Core_IKeyDerivationAlgorithmNamesStatics<D>::Pbkdf2Sha512() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Security::Cryptography::Core::IKeyDerivationAlgorithmNamesStatics)->get_Pbkdf2Sha512(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_Security_Cryptography_Core_IKeyDerivationAlgorithmNamesStatics<D>::Sp800108CtrHmacMd5() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Security::Cryptography::Core::IKeyDerivationAlgorithmNamesStatics)->get_Sp800108CtrHmacMd5(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_Security_Cryptography_Core_IKeyDerivationAlgorithmNamesStatics<D>::Sp800108CtrHmacSha1() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Security::Cryptography::Core::IKeyDerivationAlgorithmNamesStatics)->get_Sp800108CtrHmacSha1(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_Security_Cryptography_Core_IKeyDerivationAlgorithmNamesStatics<D>::Sp800108CtrHmacSha256() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Security::Cryptography::Core::IKeyDerivationAlgorithmNamesStatics)->get_Sp800108CtrHmacSha256(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_Security_Cryptography_Core_IKeyDerivationAlgorithmNamesStatics<D>::Sp800108CtrHmacSha384() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Security::Cryptography::Core::IKeyDerivationAlgorithmNamesStatics)->get_Sp800108CtrHmacSha384(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_Security_Cryptography_Core_IKeyDerivationAlgorithmNamesStatics<D>::Sp800108CtrHmacSha512() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Security::Cryptography::Core::IKeyDerivationAlgorithmNamesStatics)->get_Sp800108CtrHmacSha512(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_Security_Cryptography_Core_IKeyDerivationAlgorithmNamesStatics<D>::Sp80056aConcatMd5() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Security::Cryptography::Core::IKeyDerivationAlgorithmNamesStatics)->get_Sp80056aConcatMd5(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_Security_Cryptography_Core_IKeyDerivationAlgorithmNamesStatics<D>::Sp80056aConcatSha1() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Security::Cryptography::Core::IKeyDerivationAlgorithmNamesStatics)->get_Sp80056aConcatSha1(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_Security_Cryptography_Core_IKeyDerivationAlgorithmNamesStatics<D>::Sp80056aConcatSha256() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Security::Cryptography::Core::IKeyDerivationAlgorithmNamesStatics)->get_Sp80056aConcatSha256(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_Security_Cryptography_Core_IKeyDerivationAlgorithmNamesStatics<D>::Sp80056aConcatSha384() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Security::Cryptography::Core::IKeyDerivationAlgorithmNamesStatics)->get_Sp80056aConcatSha384(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_Security_Cryptography_Core_IKeyDerivationAlgorithmNamesStatics<D>::Sp80056aConcatSha512() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Security::Cryptography::Core::IKeyDerivationAlgorithmNamesStatics)->get_Sp80056aConcatSha512(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_Security_Cryptography_Core_IKeyDerivationAlgorithmNamesStatics2<D>::CapiKdfMd5() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Security::Cryptography::Core::IKeyDerivationAlgorithmNamesStatics2)->get_CapiKdfMd5(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_Security_Cryptography_Core_IKeyDerivationAlgorithmNamesStatics2<D>::CapiKdfSha1() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Security::Cryptography::Core::IKeyDerivationAlgorithmNamesStatics2)->get_CapiKdfSha1(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_Security_Cryptography_Core_IKeyDerivationAlgorithmNamesStatics2<D>::CapiKdfSha256() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Security::Cryptography::Core::IKeyDerivationAlgorithmNamesStatics2)->get_CapiKdfSha256(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_Security_Cryptography_Core_IKeyDerivationAlgorithmNamesStatics2<D>::CapiKdfSha384() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Security::Cryptography::Core::IKeyDerivationAlgorithmNamesStatics2)->get_CapiKdfSha384(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_Security_Cryptography_Core_IKeyDerivationAlgorithmNamesStatics2<D>::CapiKdfSha512() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Security::Cryptography::Core::IKeyDerivationAlgorithmNamesStatics2)->get_CapiKdfSha512(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_Security_Cryptography_Core_IKeyDerivationAlgorithmProvider<D>::AlgorithmName() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Security::Cryptography::Core::IKeyDerivationAlgorithmProvider)->get_AlgorithmName(put_abi(value)));
    return value;
}

template <typename D> Windows::Security::Cryptography::Core::CryptographicKey consume_Windows_Security_Cryptography_Core_IKeyDerivationAlgorithmProvider<D>::CreateKey(Windows::Storage::Streams::IBuffer const& keyMaterial) const
{
    Windows::Security::Cryptography::Core::CryptographicKey key{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Security::Cryptography::Core::IKeyDerivationAlgorithmProvider)->CreateKey(get_abi(keyMaterial), put_abi(key)));
    return key;
}

template <typename D> Windows::Security::Cryptography::Core::KeyDerivationAlgorithmProvider consume_Windows_Security_Cryptography_Core_IKeyDerivationAlgorithmProviderStatics<D>::OpenAlgorithm(param::hstring const& algorithm) const
{
    Windows::Security::Cryptography::Core::KeyDerivationAlgorithmProvider provider{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Security::Cryptography::Core::IKeyDerivationAlgorithmProviderStatics)->OpenAlgorithm(get_abi(algorithm), put_abi(provider)));
    return provider;
}

template <typename D> Windows::Storage::Streams::IBuffer consume_Windows_Security_Cryptography_Core_IKeyDerivationParameters<D>::KdfGenericBinary() const
{
    Windows::Storage::Streams::IBuffer value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Security::Cryptography::Core::IKeyDerivationParameters)->get_KdfGenericBinary(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_Security_Cryptography_Core_IKeyDerivationParameters<D>::KdfGenericBinary(Windows::Storage::Streams::IBuffer const& value) const
{
    check_hresult(WINRT_SHIM(Windows::Security::Cryptography::Core::IKeyDerivationParameters)->put_KdfGenericBinary(get_abi(value)));
}

template <typename D> uint32_t consume_Windows_Security_Cryptography_Core_IKeyDerivationParameters<D>::IterationCount() const
{
    uint32_t value{};
    check_hresult(WINRT_SHIM(Windows::Security::Cryptography::Core::IKeyDerivationParameters)->get_IterationCount(&value));
    return value;
}

template <typename D> Windows::Security::Cryptography::Core::Capi1KdfTargetAlgorithm consume_Windows_Security_Cryptography_Core_IKeyDerivationParameters2<D>::Capi1KdfTargetAlgorithm() const
{
    Windows::Security::Cryptography::Core::Capi1KdfTargetAlgorithm value{};
    check_hresult(WINRT_SHIM(Windows::Security::Cryptography::Core::IKeyDerivationParameters2)->get_Capi1KdfTargetAlgorithm(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_Security_Cryptography_Core_IKeyDerivationParameters2<D>::Capi1KdfTargetAlgorithm(Windows::Security::Cryptography::Core::Capi1KdfTargetAlgorithm const& value) const
{
    check_hresult(WINRT_SHIM(Windows::Security::Cryptography::Core::IKeyDerivationParameters2)->put_Capi1KdfTargetAlgorithm(get_abi(value)));
}

template <typename D> Windows::Security::Cryptography::Core::KeyDerivationParameters consume_Windows_Security_Cryptography_Core_IKeyDerivationParametersStatics<D>::BuildForPbkdf2(Windows::Storage::Streams::IBuffer const& pbkdf2Salt, uint32_t iterationCount) const
{
    Windows::Security::Cryptography::Core::KeyDerivationParameters value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Security::Cryptography::Core::IKeyDerivationParametersStatics)->BuildForPbkdf2(get_abi(pbkdf2Salt), iterationCount, put_abi(value)));
    return value;
}

template <typename D> Windows::Security::Cryptography::Core::KeyDerivationParameters consume_Windows_Security_Cryptography_Core_IKeyDerivationParametersStatics<D>::BuildForSP800108(Windows::Storage::Streams::IBuffer const& label, Windows::Storage::Streams::IBuffer const& context) const
{
    Windows::Security::Cryptography::Core::KeyDerivationParameters value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Security::Cryptography::Core::IKeyDerivationParametersStatics)->BuildForSP800108(get_abi(label), get_abi(context), put_abi(value)));
    return value;
}

template <typename D> Windows::Security::Cryptography::Core::KeyDerivationParameters consume_Windows_Security_Cryptography_Core_IKeyDerivationParametersStatics<D>::BuildForSP80056a(Windows::Storage::Streams::IBuffer const& algorithmId, Windows::Storage::Streams::IBuffer const& partyUInfo, Windows::Storage::Streams::IBuffer const& partyVInfo, Windows::Storage::Streams::IBuffer const& suppPubInfo, Windows::Storage::Streams::IBuffer const& suppPrivInfo) const
{
    Windows::Security::Cryptography::Core::KeyDerivationParameters value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Security::Cryptography::Core::IKeyDerivationParametersStatics)->BuildForSP80056a(get_abi(algorithmId), get_abi(partyUInfo), get_abi(partyVInfo), get_abi(suppPubInfo), get_abi(suppPrivInfo), put_abi(value)));
    return value;
}

template <typename D> Windows::Security::Cryptography::Core::KeyDerivationParameters consume_Windows_Security_Cryptography_Core_IKeyDerivationParametersStatics2<D>::BuildForCapi1Kdf(Windows::Security::Cryptography::Core::Capi1KdfTargetAlgorithm const& capi1KdfTargetAlgorithm) const
{
    Windows::Security::Cryptography::Core::KeyDerivationParameters value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Security::Cryptography::Core::IKeyDerivationParametersStatics2)->BuildForCapi1Kdf(get_abi(capi1KdfTargetAlgorithm), put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_Security_Cryptography_Core_IMacAlgorithmNamesStatics<D>::HmacMd5() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Security::Cryptography::Core::IMacAlgorithmNamesStatics)->get_HmacMd5(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_Security_Cryptography_Core_IMacAlgorithmNamesStatics<D>::HmacSha1() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Security::Cryptography::Core::IMacAlgorithmNamesStatics)->get_HmacSha1(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_Security_Cryptography_Core_IMacAlgorithmNamesStatics<D>::HmacSha256() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Security::Cryptography::Core::IMacAlgorithmNamesStatics)->get_HmacSha256(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_Security_Cryptography_Core_IMacAlgorithmNamesStatics<D>::HmacSha384() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Security::Cryptography::Core::IMacAlgorithmNamesStatics)->get_HmacSha384(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_Security_Cryptography_Core_IMacAlgorithmNamesStatics<D>::HmacSha512() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Security::Cryptography::Core::IMacAlgorithmNamesStatics)->get_HmacSha512(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_Security_Cryptography_Core_IMacAlgorithmNamesStatics<D>::AesCmac() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Security::Cryptography::Core::IMacAlgorithmNamesStatics)->get_AesCmac(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_Security_Cryptography_Core_IMacAlgorithmProvider<D>::AlgorithmName() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Security::Cryptography::Core::IMacAlgorithmProvider)->get_AlgorithmName(put_abi(value)));
    return value;
}

template <typename D> uint32_t consume_Windows_Security_Cryptography_Core_IMacAlgorithmProvider<D>::MacLength() const
{
    uint32_t value{};
    check_hresult(WINRT_SHIM(Windows::Security::Cryptography::Core::IMacAlgorithmProvider)->get_MacLength(&value));
    return value;
}

template <typename D> Windows::Security::Cryptography::Core::CryptographicKey consume_Windows_Security_Cryptography_Core_IMacAlgorithmProvider<D>::CreateKey(Windows::Storage::Streams::IBuffer const& keyMaterial) const
{
    Windows::Security::Cryptography::Core::CryptographicKey macKey{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Security::Cryptography::Core::IMacAlgorithmProvider)->CreateKey(get_abi(keyMaterial), put_abi(macKey)));
    return macKey;
}

template <typename D> Windows::Security::Cryptography::Core::CryptographicHash consume_Windows_Security_Cryptography_Core_IMacAlgorithmProvider2<D>::CreateHash(Windows::Storage::Streams::IBuffer const& keyMaterial) const
{
    Windows::Security::Cryptography::Core::CryptographicHash value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Security::Cryptography::Core::IMacAlgorithmProvider2)->CreateHash(get_abi(keyMaterial), put_abi(value)));
    return value;
}

template <typename D> Windows::Security::Cryptography::Core::MacAlgorithmProvider consume_Windows_Security_Cryptography_Core_IMacAlgorithmProviderStatics<D>::OpenAlgorithm(param::hstring const& algorithm) const
{
    Windows::Security::Cryptography::Core::MacAlgorithmProvider provider{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Security::Cryptography::Core::IMacAlgorithmProviderStatics)->OpenAlgorithm(get_abi(algorithm), put_abi(provider)));
    return provider;
}

template <typename D> Windows::Foundation::IAsyncOperation<Windows::Security::Cryptography::Core::CryptographicKey> consume_Windows_Security_Cryptography_Core_IPersistedKeyProviderStatics<D>::OpenKeyPairFromCertificateAsync(Windows::Security::Cryptography::Certificates::Certificate const& certificate, param::hstring const& hashAlgorithmName, Windows::Security::Cryptography::Core::CryptographicPadding const& padding) const
{
    Windows::Foundation::IAsyncOperation<Windows::Security::Cryptography::Core::CryptographicKey> operation{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Security::Cryptography::Core::IPersistedKeyProviderStatics)->OpenKeyPairFromCertificateAsync(get_abi(certificate), get_abi(hashAlgorithmName), get_abi(padding), put_abi(operation)));
    return operation;
}

template <typename D> Windows::Security::Cryptography::Core::CryptographicKey consume_Windows_Security_Cryptography_Core_IPersistedKeyProviderStatics<D>::OpenPublicKeyFromCertificate(Windows::Security::Cryptography::Certificates::Certificate const& certificate, param::hstring const& hashAlgorithmName, Windows::Security::Cryptography::Core::CryptographicPadding const& padding) const
{
    Windows::Security::Cryptography::Core::CryptographicKey key{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Security::Cryptography::Core::IPersistedKeyProviderStatics)->OpenPublicKeyFromCertificate(get_abi(certificate), get_abi(hashAlgorithmName), get_abi(padding), put_abi(key)));
    return key;
}

template <typename D> hstring consume_Windows_Security_Cryptography_Core_ISymmetricAlgorithmNamesStatics<D>::DesCbc() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Security::Cryptography::Core::ISymmetricAlgorithmNamesStatics)->get_DesCbc(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_Security_Cryptography_Core_ISymmetricAlgorithmNamesStatics<D>::DesEcb() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Security::Cryptography::Core::ISymmetricAlgorithmNamesStatics)->get_DesEcb(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_Security_Cryptography_Core_ISymmetricAlgorithmNamesStatics<D>::TripleDesCbc() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Security::Cryptography::Core::ISymmetricAlgorithmNamesStatics)->get_TripleDesCbc(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_Security_Cryptography_Core_ISymmetricAlgorithmNamesStatics<D>::TripleDesEcb() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Security::Cryptography::Core::ISymmetricAlgorithmNamesStatics)->get_TripleDesEcb(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_Security_Cryptography_Core_ISymmetricAlgorithmNamesStatics<D>::Rc2Cbc() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Security::Cryptography::Core::ISymmetricAlgorithmNamesStatics)->get_Rc2Cbc(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_Security_Cryptography_Core_ISymmetricAlgorithmNamesStatics<D>::Rc2Ecb() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Security::Cryptography::Core::ISymmetricAlgorithmNamesStatics)->get_Rc2Ecb(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_Security_Cryptography_Core_ISymmetricAlgorithmNamesStatics<D>::AesCbc() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Security::Cryptography::Core::ISymmetricAlgorithmNamesStatics)->get_AesCbc(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_Security_Cryptography_Core_ISymmetricAlgorithmNamesStatics<D>::AesEcb() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Security::Cryptography::Core::ISymmetricAlgorithmNamesStatics)->get_AesEcb(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_Security_Cryptography_Core_ISymmetricAlgorithmNamesStatics<D>::AesGcm() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Security::Cryptography::Core::ISymmetricAlgorithmNamesStatics)->get_AesGcm(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_Security_Cryptography_Core_ISymmetricAlgorithmNamesStatics<D>::AesCcm() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Security::Cryptography::Core::ISymmetricAlgorithmNamesStatics)->get_AesCcm(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_Security_Cryptography_Core_ISymmetricAlgorithmNamesStatics<D>::AesCbcPkcs7() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Security::Cryptography::Core::ISymmetricAlgorithmNamesStatics)->get_AesCbcPkcs7(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_Security_Cryptography_Core_ISymmetricAlgorithmNamesStatics<D>::AesEcbPkcs7() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Security::Cryptography::Core::ISymmetricAlgorithmNamesStatics)->get_AesEcbPkcs7(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_Security_Cryptography_Core_ISymmetricAlgorithmNamesStatics<D>::DesCbcPkcs7() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Security::Cryptography::Core::ISymmetricAlgorithmNamesStatics)->get_DesCbcPkcs7(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_Security_Cryptography_Core_ISymmetricAlgorithmNamesStatics<D>::DesEcbPkcs7() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Security::Cryptography::Core::ISymmetricAlgorithmNamesStatics)->get_DesEcbPkcs7(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_Security_Cryptography_Core_ISymmetricAlgorithmNamesStatics<D>::TripleDesCbcPkcs7() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Security::Cryptography::Core::ISymmetricAlgorithmNamesStatics)->get_TripleDesCbcPkcs7(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_Security_Cryptography_Core_ISymmetricAlgorithmNamesStatics<D>::TripleDesEcbPkcs7() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Security::Cryptography::Core::ISymmetricAlgorithmNamesStatics)->get_TripleDesEcbPkcs7(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_Security_Cryptography_Core_ISymmetricAlgorithmNamesStatics<D>::Rc2CbcPkcs7() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Security::Cryptography::Core::ISymmetricAlgorithmNamesStatics)->get_Rc2CbcPkcs7(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_Security_Cryptography_Core_ISymmetricAlgorithmNamesStatics<D>::Rc2EcbPkcs7() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Security::Cryptography::Core::ISymmetricAlgorithmNamesStatics)->get_Rc2EcbPkcs7(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_Security_Cryptography_Core_ISymmetricAlgorithmNamesStatics<D>::Rc4() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Security::Cryptography::Core::ISymmetricAlgorithmNamesStatics)->get_Rc4(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_Security_Cryptography_Core_ISymmetricKeyAlgorithmProvider<D>::AlgorithmName() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Security::Cryptography::Core::ISymmetricKeyAlgorithmProvider)->get_AlgorithmName(put_abi(value)));
    return value;
}

template <typename D> uint32_t consume_Windows_Security_Cryptography_Core_ISymmetricKeyAlgorithmProvider<D>::BlockLength() const
{
    uint32_t value{};
    check_hresult(WINRT_SHIM(Windows::Security::Cryptography::Core::ISymmetricKeyAlgorithmProvider)->get_BlockLength(&value));
    return value;
}

template <typename D> Windows::Security::Cryptography::Core::CryptographicKey consume_Windows_Security_Cryptography_Core_ISymmetricKeyAlgorithmProvider<D>::CreateSymmetricKey(Windows::Storage::Streams::IBuffer const& keyMaterial) const
{
    Windows::Security::Cryptography::Core::CryptographicKey key{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Security::Cryptography::Core::ISymmetricKeyAlgorithmProvider)->CreateSymmetricKey(get_abi(keyMaterial), put_abi(key)));
    return key;
}

template <typename D> Windows::Security::Cryptography::Core::SymmetricKeyAlgorithmProvider consume_Windows_Security_Cryptography_Core_ISymmetricKeyAlgorithmProviderStatics<D>::OpenAlgorithm(param::hstring const& algorithm) const
{
    Windows::Security::Cryptography::Core::SymmetricKeyAlgorithmProvider provider{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Security::Cryptography::Core::ISymmetricKeyAlgorithmProviderStatics)->OpenAlgorithm(get_abi(algorithm), put_abi(provider)));
    return provider;
}

template <typename D>
struct produce<D, Windows::Security::Cryptography::Core::IAsymmetricAlgorithmNamesStatics> : produce_base<D, Windows::Security::Cryptography::Core::IAsymmetricAlgorithmNamesStatics>
{
    int32_t WINRT_CALL get_RsaPkcs1(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(RsaPkcs1, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().RsaPkcs1());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_RsaOaepSha1(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(RsaOaepSha1, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().RsaOaepSha1());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_RsaOaepSha256(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(RsaOaepSha256, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().RsaOaepSha256());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_RsaOaepSha384(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(RsaOaepSha384, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().RsaOaepSha384());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_RsaOaepSha512(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(RsaOaepSha512, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().RsaOaepSha512());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_EcdsaP256Sha256(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(EcdsaP256Sha256, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().EcdsaP256Sha256());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_EcdsaP384Sha384(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(EcdsaP384Sha384, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().EcdsaP384Sha384());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_EcdsaP521Sha512(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(EcdsaP521Sha512, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().EcdsaP521Sha512());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_DsaSha1(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(DsaSha1, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().DsaSha1());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_DsaSha256(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(DsaSha256, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().DsaSha256());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_RsaSignPkcs1Sha1(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(RsaSignPkcs1Sha1, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().RsaSignPkcs1Sha1());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_RsaSignPkcs1Sha256(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(RsaSignPkcs1Sha256, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().RsaSignPkcs1Sha256());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_RsaSignPkcs1Sha384(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(RsaSignPkcs1Sha384, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().RsaSignPkcs1Sha384());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_RsaSignPkcs1Sha512(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(RsaSignPkcs1Sha512, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().RsaSignPkcs1Sha512());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_RsaSignPssSha1(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(RsaSignPssSha1, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().RsaSignPssSha1());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_RsaSignPssSha256(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(RsaSignPssSha256, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().RsaSignPssSha256());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_RsaSignPssSha384(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(RsaSignPssSha384, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().RsaSignPssSha384());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_RsaSignPssSha512(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(RsaSignPssSha512, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().RsaSignPssSha512());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Security::Cryptography::Core::IAsymmetricAlgorithmNamesStatics2> : produce_base<D, Windows::Security::Cryptography::Core::IAsymmetricAlgorithmNamesStatics2>
{
    int32_t WINRT_CALL get_EcdsaSha256(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(EcdsaSha256, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().EcdsaSha256());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_EcdsaSha384(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(EcdsaSha384, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().EcdsaSha384());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_EcdsaSha512(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(EcdsaSha512, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().EcdsaSha512());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Security::Cryptography::Core::IAsymmetricKeyAlgorithmProvider> : produce_base<D, Windows::Security::Cryptography::Core::IAsymmetricKeyAlgorithmProvider>
{
    int32_t WINRT_CALL get_AlgorithmName(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(AlgorithmName, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().AlgorithmName());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL CreateKeyPair(uint32_t keySize, void** key) noexcept final
    {
        try
        {
            *key = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CreateKeyPair, WINRT_WRAP(Windows::Security::Cryptography::Core::CryptographicKey), uint32_t);
            *key = detach_from<Windows::Security::Cryptography::Core::CryptographicKey>(this->shim().CreateKeyPair(keySize));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL ImportDefaultPrivateKeyBlob(void* keyBlob, void** key) noexcept final
    {
        try
        {
            *key = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ImportKeyPair, WINRT_WRAP(Windows::Security::Cryptography::Core::CryptographicKey), Windows::Storage::Streams::IBuffer const&);
            *key = detach_from<Windows::Security::Cryptography::Core::CryptographicKey>(this->shim().ImportKeyPair(*reinterpret_cast<Windows::Storage::Streams::IBuffer const*>(&keyBlob)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL ImportKeyPairWithBlobType(void* keyBlob, Windows::Security::Cryptography::Core::CryptographicPrivateKeyBlobType BlobType, void** key) noexcept final
    {
        try
        {
            *key = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ImportKeyPair, WINRT_WRAP(Windows::Security::Cryptography::Core::CryptographicKey), Windows::Storage::Streams::IBuffer const&, Windows::Security::Cryptography::Core::CryptographicPrivateKeyBlobType const&);
            *key = detach_from<Windows::Security::Cryptography::Core::CryptographicKey>(this->shim().ImportKeyPair(*reinterpret_cast<Windows::Storage::Streams::IBuffer const*>(&keyBlob), *reinterpret_cast<Windows::Security::Cryptography::Core::CryptographicPrivateKeyBlobType const*>(&BlobType)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL ImportDefaultPublicKeyBlob(void* keyBlob, void** key) noexcept final
    {
        try
        {
            *key = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ImportPublicKey, WINRT_WRAP(Windows::Security::Cryptography::Core::CryptographicKey), Windows::Storage::Streams::IBuffer const&);
            *key = detach_from<Windows::Security::Cryptography::Core::CryptographicKey>(this->shim().ImportPublicKey(*reinterpret_cast<Windows::Storage::Streams::IBuffer const*>(&keyBlob)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL ImportPublicKeyWithBlobType(void* keyBlob, Windows::Security::Cryptography::Core::CryptographicPublicKeyBlobType BlobType, void** key) noexcept final
    {
        try
        {
            *key = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ImportPublicKey, WINRT_WRAP(Windows::Security::Cryptography::Core::CryptographicKey), Windows::Storage::Streams::IBuffer const&, Windows::Security::Cryptography::Core::CryptographicPublicKeyBlobType const&);
            *key = detach_from<Windows::Security::Cryptography::Core::CryptographicKey>(this->shim().ImportPublicKey(*reinterpret_cast<Windows::Storage::Streams::IBuffer const*>(&keyBlob), *reinterpret_cast<Windows::Security::Cryptography::Core::CryptographicPublicKeyBlobType const*>(&BlobType)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Security::Cryptography::Core::IAsymmetricKeyAlgorithmProvider2> : produce_base<D, Windows::Security::Cryptography::Core::IAsymmetricKeyAlgorithmProvider2>
{
    int32_t WINRT_CALL CreateKeyPairWithCurveName(void* curveName, void** key) noexcept final
    {
        try
        {
            *key = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CreateKeyPairWithCurveName, WINRT_WRAP(Windows::Security::Cryptography::Core::CryptographicKey), hstring const&);
            *key = detach_from<Windows::Security::Cryptography::Core::CryptographicKey>(this->shim().CreateKeyPairWithCurveName(*reinterpret_cast<hstring const*>(&curveName)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL CreateKeyPairWithCurveParameters(uint32_t __parametersSize, uint8_t* parameters, void** key) noexcept final
    {
        try
        {
            *key = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CreateKeyPairWithCurveParameters, WINRT_WRAP(Windows::Security::Cryptography::Core::CryptographicKey), array_view<uint8_t const>);
            *key = detach_from<Windows::Security::Cryptography::Core::CryptographicKey>(this->shim().CreateKeyPairWithCurveParameters(array_view<uint8_t const>(reinterpret_cast<uint8_t const *>(parameters), reinterpret_cast<uint8_t const *>(parameters) + __parametersSize)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Security::Cryptography::Core::IAsymmetricKeyAlgorithmProviderStatics> : produce_base<D, Windows::Security::Cryptography::Core::IAsymmetricKeyAlgorithmProviderStatics>
{
    int32_t WINRT_CALL OpenAlgorithm(void* algorithm, void** provider) noexcept final
    {
        try
        {
            *provider = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(OpenAlgorithm, WINRT_WRAP(Windows::Security::Cryptography::Core::AsymmetricKeyAlgorithmProvider), hstring const&);
            *provider = detach_from<Windows::Security::Cryptography::Core::AsymmetricKeyAlgorithmProvider>(this->shim().OpenAlgorithm(*reinterpret_cast<hstring const*>(&algorithm)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Security::Cryptography::Core::ICryptographicEngineStatics> : produce_base<D, Windows::Security::Cryptography::Core::ICryptographicEngineStatics>
{
    int32_t WINRT_CALL Encrypt(void* key, void* data, void* iv, void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Encrypt, WINRT_WRAP(Windows::Storage::Streams::IBuffer), Windows::Security::Cryptography::Core::CryptographicKey const&, Windows::Storage::Streams::IBuffer const&, Windows::Storage::Streams::IBuffer const&);
            *value = detach_from<Windows::Storage::Streams::IBuffer>(this->shim().Encrypt(*reinterpret_cast<Windows::Security::Cryptography::Core::CryptographicKey const*>(&key), *reinterpret_cast<Windows::Storage::Streams::IBuffer const*>(&data), *reinterpret_cast<Windows::Storage::Streams::IBuffer const*>(&iv)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL Decrypt(void* key, void* data, void* iv, void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Decrypt, WINRT_WRAP(Windows::Storage::Streams::IBuffer), Windows::Security::Cryptography::Core::CryptographicKey const&, Windows::Storage::Streams::IBuffer const&, Windows::Storage::Streams::IBuffer const&);
            *value = detach_from<Windows::Storage::Streams::IBuffer>(this->shim().Decrypt(*reinterpret_cast<Windows::Security::Cryptography::Core::CryptographicKey const*>(&key), *reinterpret_cast<Windows::Storage::Streams::IBuffer const*>(&data), *reinterpret_cast<Windows::Storage::Streams::IBuffer const*>(&iv)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL EncryptAndAuthenticate(void* key, void* data, void* nonce, void* authenticatedData, void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(EncryptAndAuthenticate, WINRT_WRAP(Windows::Security::Cryptography::Core::EncryptedAndAuthenticatedData), Windows::Security::Cryptography::Core::CryptographicKey const&, Windows::Storage::Streams::IBuffer const&, Windows::Storage::Streams::IBuffer const&, Windows::Storage::Streams::IBuffer const&);
            *value = detach_from<Windows::Security::Cryptography::Core::EncryptedAndAuthenticatedData>(this->shim().EncryptAndAuthenticate(*reinterpret_cast<Windows::Security::Cryptography::Core::CryptographicKey const*>(&key), *reinterpret_cast<Windows::Storage::Streams::IBuffer const*>(&data), *reinterpret_cast<Windows::Storage::Streams::IBuffer const*>(&nonce), *reinterpret_cast<Windows::Storage::Streams::IBuffer const*>(&authenticatedData)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL DecryptAndAuthenticate(void* key, void* data, void* nonce, void* authenticationTag, void* authenticatedData, void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(DecryptAndAuthenticate, WINRT_WRAP(Windows::Storage::Streams::IBuffer), Windows::Security::Cryptography::Core::CryptographicKey const&, Windows::Storage::Streams::IBuffer const&, Windows::Storage::Streams::IBuffer const&, Windows::Storage::Streams::IBuffer const&, Windows::Storage::Streams::IBuffer const&);
            *value = detach_from<Windows::Storage::Streams::IBuffer>(this->shim().DecryptAndAuthenticate(*reinterpret_cast<Windows::Security::Cryptography::Core::CryptographicKey const*>(&key), *reinterpret_cast<Windows::Storage::Streams::IBuffer const*>(&data), *reinterpret_cast<Windows::Storage::Streams::IBuffer const*>(&nonce), *reinterpret_cast<Windows::Storage::Streams::IBuffer const*>(&authenticationTag), *reinterpret_cast<Windows::Storage::Streams::IBuffer const*>(&authenticatedData)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL Sign(void* key, void* data, void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Sign, WINRT_WRAP(Windows::Storage::Streams::IBuffer), Windows::Security::Cryptography::Core::CryptographicKey const&, Windows::Storage::Streams::IBuffer const&);
            *value = detach_from<Windows::Storage::Streams::IBuffer>(this->shim().Sign(*reinterpret_cast<Windows::Security::Cryptography::Core::CryptographicKey const*>(&key), *reinterpret_cast<Windows::Storage::Streams::IBuffer const*>(&data)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL VerifySignature(void* key, void* data, void* signature, bool* isAuthenticated) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(VerifySignature, WINRT_WRAP(bool), Windows::Security::Cryptography::Core::CryptographicKey const&, Windows::Storage::Streams::IBuffer const&, Windows::Storage::Streams::IBuffer const&);
            *isAuthenticated = detach_from<bool>(this->shim().VerifySignature(*reinterpret_cast<Windows::Security::Cryptography::Core::CryptographicKey const*>(&key), *reinterpret_cast<Windows::Storage::Streams::IBuffer const*>(&data), *reinterpret_cast<Windows::Storage::Streams::IBuffer const*>(&signature)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL DeriveKeyMaterial(void* key, void* parameters, uint32_t desiredKeySize, void** keyMaterial) noexcept final
    {
        try
        {
            *keyMaterial = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(DeriveKeyMaterial, WINRT_WRAP(Windows::Storage::Streams::IBuffer), Windows::Security::Cryptography::Core::CryptographicKey const&, Windows::Security::Cryptography::Core::KeyDerivationParameters const&, uint32_t);
            *keyMaterial = detach_from<Windows::Storage::Streams::IBuffer>(this->shim().DeriveKeyMaterial(*reinterpret_cast<Windows::Security::Cryptography::Core::CryptographicKey const*>(&key), *reinterpret_cast<Windows::Security::Cryptography::Core::KeyDerivationParameters const*>(&parameters), desiredKeySize));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Security::Cryptography::Core::ICryptographicEngineStatics2> : produce_base<D, Windows::Security::Cryptography::Core::ICryptographicEngineStatics2>
{
    int32_t WINRT_CALL SignHashedData(void* key, void* data, void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SignHashedData, WINRT_WRAP(Windows::Storage::Streams::IBuffer), Windows::Security::Cryptography::Core::CryptographicKey const&, Windows::Storage::Streams::IBuffer const&);
            *value = detach_from<Windows::Storage::Streams::IBuffer>(this->shim().SignHashedData(*reinterpret_cast<Windows::Security::Cryptography::Core::CryptographicKey const*>(&key), *reinterpret_cast<Windows::Storage::Streams::IBuffer const*>(&data)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL VerifySignatureWithHashInput(void* key, void* data, void* signature, bool* isAuthenticated) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(VerifySignatureWithHashInput, WINRT_WRAP(bool), Windows::Security::Cryptography::Core::CryptographicKey const&, Windows::Storage::Streams::IBuffer const&, Windows::Storage::Streams::IBuffer const&);
            *isAuthenticated = detach_from<bool>(this->shim().VerifySignatureWithHashInput(*reinterpret_cast<Windows::Security::Cryptography::Core::CryptographicKey const*>(&key), *reinterpret_cast<Windows::Storage::Streams::IBuffer const*>(&data), *reinterpret_cast<Windows::Storage::Streams::IBuffer const*>(&signature)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL DecryptAsync(void* key, void* data, void* iv, void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(DecryptAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<Windows::Storage::Streams::IBuffer>), Windows::Security::Cryptography::Core::CryptographicKey const, Windows::Storage::Streams::IBuffer const, Windows::Storage::Streams::IBuffer const);
            *value = detach_from<Windows::Foundation::IAsyncOperation<Windows::Storage::Streams::IBuffer>>(this->shim().DecryptAsync(*reinterpret_cast<Windows::Security::Cryptography::Core::CryptographicKey const*>(&key), *reinterpret_cast<Windows::Storage::Streams::IBuffer const*>(&data), *reinterpret_cast<Windows::Storage::Streams::IBuffer const*>(&iv)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL SignAsync(void* key, void* data, void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SignAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<Windows::Storage::Streams::IBuffer>), Windows::Security::Cryptography::Core::CryptographicKey const, Windows::Storage::Streams::IBuffer const);
            *value = detach_from<Windows::Foundation::IAsyncOperation<Windows::Storage::Streams::IBuffer>>(this->shim().SignAsync(*reinterpret_cast<Windows::Security::Cryptography::Core::CryptographicKey const*>(&key), *reinterpret_cast<Windows::Storage::Streams::IBuffer const*>(&data)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL SignHashedDataAsync(void* key, void* data, void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SignHashedDataAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<Windows::Storage::Streams::IBuffer>), Windows::Security::Cryptography::Core::CryptographicKey const, Windows::Storage::Streams::IBuffer const);
            *value = detach_from<Windows::Foundation::IAsyncOperation<Windows::Storage::Streams::IBuffer>>(this->shim().SignHashedDataAsync(*reinterpret_cast<Windows::Security::Cryptography::Core::CryptographicKey const*>(&key), *reinterpret_cast<Windows::Storage::Streams::IBuffer const*>(&data)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Security::Cryptography::Core::ICryptographicKey> : produce_base<D, Windows::Security::Cryptography::Core::ICryptographicKey>
{
    int32_t WINRT_CALL get_KeySize(uint32_t* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(KeySize, WINRT_WRAP(uint32_t));
            *value = detach_from<uint32_t>(this->shim().KeySize());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL ExportDefaultPrivateKeyBlobType(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Export, WINRT_WRAP(Windows::Storage::Streams::IBuffer));
            *value = detach_from<Windows::Storage::Streams::IBuffer>(this->shim().Export());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL ExportPrivateKeyWithBlobType(Windows::Security::Cryptography::Core::CryptographicPrivateKeyBlobType BlobType, void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Export, WINRT_WRAP(Windows::Storage::Streams::IBuffer), Windows::Security::Cryptography::Core::CryptographicPrivateKeyBlobType const&);
            *value = detach_from<Windows::Storage::Streams::IBuffer>(this->shim().Export(*reinterpret_cast<Windows::Security::Cryptography::Core::CryptographicPrivateKeyBlobType const*>(&BlobType)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL ExportDefaultPublicKeyBlobType(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ExportPublicKey, WINRT_WRAP(Windows::Storage::Streams::IBuffer));
            *value = detach_from<Windows::Storage::Streams::IBuffer>(this->shim().ExportPublicKey());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL ExportPublicKeyWithBlobType(Windows::Security::Cryptography::Core::CryptographicPublicKeyBlobType BlobType, void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ExportPublicKey, WINRT_WRAP(Windows::Storage::Streams::IBuffer), Windows::Security::Cryptography::Core::CryptographicPublicKeyBlobType const&);
            *value = detach_from<Windows::Storage::Streams::IBuffer>(this->shim().ExportPublicKey(*reinterpret_cast<Windows::Security::Cryptography::Core::CryptographicPublicKeyBlobType const*>(&BlobType)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Security::Cryptography::Core::IEccCurveNamesStatics> : produce_base<D, Windows::Security::Cryptography::Core::IEccCurveNamesStatics>
{
    int32_t WINRT_CALL get_BrainpoolP160r1(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(BrainpoolP160r1, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().BrainpoolP160r1());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_BrainpoolP160t1(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(BrainpoolP160t1, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().BrainpoolP160t1());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_BrainpoolP192r1(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(BrainpoolP192r1, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().BrainpoolP192r1());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_BrainpoolP192t1(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(BrainpoolP192t1, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().BrainpoolP192t1());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_BrainpoolP224r1(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(BrainpoolP224r1, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().BrainpoolP224r1());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_BrainpoolP224t1(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(BrainpoolP224t1, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().BrainpoolP224t1());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_BrainpoolP256r1(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(BrainpoolP256r1, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().BrainpoolP256r1());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_BrainpoolP256t1(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(BrainpoolP256t1, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().BrainpoolP256t1());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_BrainpoolP320r1(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(BrainpoolP320r1, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().BrainpoolP320r1());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_BrainpoolP320t1(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(BrainpoolP320t1, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().BrainpoolP320t1());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_BrainpoolP384r1(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(BrainpoolP384r1, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().BrainpoolP384r1());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_BrainpoolP384t1(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(BrainpoolP384t1, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().BrainpoolP384t1());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_BrainpoolP512r1(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(BrainpoolP512r1, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().BrainpoolP512r1());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_BrainpoolP512t1(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(BrainpoolP512t1, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().BrainpoolP512t1());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Curve25519(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Curve25519, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().Curve25519());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Ec192wapi(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Ec192wapi, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().Ec192wapi());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_NistP192(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(NistP192, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().NistP192());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_NistP224(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(NistP224, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().NistP224());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_NistP256(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(NistP256, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().NistP256());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_NistP384(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(NistP384, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().NistP384());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_NistP521(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(NistP521, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().NistP521());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_NumsP256t1(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(NumsP256t1, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().NumsP256t1());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_NumsP384t1(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(NumsP384t1, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().NumsP384t1());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_NumsP512t1(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(NumsP512t1, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().NumsP512t1());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_SecP160k1(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SecP160k1, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().SecP160k1());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_SecP160r1(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SecP160r1, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().SecP160r1());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_SecP160r2(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SecP160r2, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().SecP160r2());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_SecP192k1(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SecP192k1, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().SecP192k1());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_SecP192r1(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SecP192r1, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().SecP192r1());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_SecP224k1(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SecP224k1, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().SecP224k1());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_SecP224r1(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SecP224r1, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().SecP224r1());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_SecP256k1(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SecP256k1, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().SecP256k1());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_SecP256r1(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SecP256r1, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().SecP256r1());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_SecP384r1(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SecP384r1, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().SecP384r1());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_SecP521r1(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SecP521r1, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().SecP521r1());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Wtls7(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Wtls7, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().Wtls7());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Wtls9(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Wtls9, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().Wtls9());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Wtls12(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Wtls12, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().Wtls12());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_X962P192v1(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(X962P192v1, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().X962P192v1());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_X962P192v2(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(X962P192v2, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().X962P192v2());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_X962P192v3(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(X962P192v3, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().X962P192v3());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_X962P239v1(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(X962P239v1, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().X962P239v1());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_X962P239v2(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(X962P239v2, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().X962P239v2());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_X962P239v3(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(X962P239v3, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().X962P239v3());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_X962P256v1(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(X962P256v1, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().X962P256v1());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_AllEccCurveNames(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(AllEccCurveNames, WINRT_WRAP(Windows::Foundation::Collections::IVectorView<hstring>));
            *value = detach_from<Windows::Foundation::Collections::IVectorView<hstring>>(this->shim().AllEccCurveNames());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Security::Cryptography::Core::IEncryptedAndAuthenticatedData> : produce_base<D, Windows::Security::Cryptography::Core::IEncryptedAndAuthenticatedData>
{
    int32_t WINRT_CALL get_EncryptedData(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(EncryptedData, WINRT_WRAP(Windows::Storage::Streams::IBuffer));
            *value = detach_from<Windows::Storage::Streams::IBuffer>(this->shim().EncryptedData());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_AuthenticationTag(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(AuthenticationTag, WINRT_WRAP(Windows::Storage::Streams::IBuffer));
            *value = detach_from<Windows::Storage::Streams::IBuffer>(this->shim().AuthenticationTag());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Security::Cryptography::Core::IHashAlgorithmNamesStatics> : produce_base<D, Windows::Security::Cryptography::Core::IHashAlgorithmNamesStatics>
{
    int32_t WINRT_CALL get_Md5(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Md5, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().Md5());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Sha1(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Sha1, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().Sha1());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Sha256(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Sha256, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().Sha256());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Sha384(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Sha384, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().Sha384());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Sha512(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Sha512, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().Sha512());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Security::Cryptography::Core::IHashAlgorithmProvider> : produce_base<D, Windows::Security::Cryptography::Core::IHashAlgorithmProvider>
{
    int32_t WINRT_CALL get_AlgorithmName(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(AlgorithmName, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().AlgorithmName());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_HashLength(uint32_t* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(HashLength, WINRT_WRAP(uint32_t));
            *value = detach_from<uint32_t>(this->shim().HashLength());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL HashData(void* data, void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(HashData, WINRT_WRAP(Windows::Storage::Streams::IBuffer), Windows::Storage::Streams::IBuffer const&);
            *value = detach_from<Windows::Storage::Streams::IBuffer>(this->shim().HashData(*reinterpret_cast<Windows::Storage::Streams::IBuffer const*>(&data)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL CreateHash(void** Value) noexcept final
    {
        try
        {
            *Value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CreateHash, WINRT_WRAP(Windows::Security::Cryptography::Core::CryptographicHash));
            *Value = detach_from<Windows::Security::Cryptography::Core::CryptographicHash>(this->shim().CreateHash());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Security::Cryptography::Core::IHashAlgorithmProviderStatics> : produce_base<D, Windows::Security::Cryptography::Core::IHashAlgorithmProviderStatics>
{
    int32_t WINRT_CALL OpenAlgorithm(void* algorithm, void** provider) noexcept final
    {
        try
        {
            *provider = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(OpenAlgorithm, WINRT_WRAP(Windows::Security::Cryptography::Core::HashAlgorithmProvider), hstring const&);
            *provider = detach_from<Windows::Security::Cryptography::Core::HashAlgorithmProvider>(this->shim().OpenAlgorithm(*reinterpret_cast<hstring const*>(&algorithm)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Security::Cryptography::Core::IHashComputation> : produce_base<D, Windows::Security::Cryptography::Core::IHashComputation>
{
    int32_t WINRT_CALL Append(void* data) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Append, WINRT_WRAP(void), Windows::Storage::Streams::IBuffer const&);
            this->shim().Append(*reinterpret_cast<Windows::Storage::Streams::IBuffer const*>(&data));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL GetValueAndReset(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetValueAndReset, WINRT_WRAP(Windows::Storage::Streams::IBuffer));
            *value = detach_from<Windows::Storage::Streams::IBuffer>(this->shim().GetValueAndReset());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Security::Cryptography::Core::IKeyDerivationAlgorithmNamesStatics> : produce_base<D, Windows::Security::Cryptography::Core::IKeyDerivationAlgorithmNamesStatics>
{
    int32_t WINRT_CALL get_Pbkdf2Md5(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Pbkdf2Md5, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().Pbkdf2Md5());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Pbkdf2Sha1(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Pbkdf2Sha1, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().Pbkdf2Sha1());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Pbkdf2Sha256(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Pbkdf2Sha256, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().Pbkdf2Sha256());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Pbkdf2Sha384(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Pbkdf2Sha384, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().Pbkdf2Sha384());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Pbkdf2Sha512(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Pbkdf2Sha512, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().Pbkdf2Sha512());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Sp800108CtrHmacMd5(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Sp800108CtrHmacMd5, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().Sp800108CtrHmacMd5());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Sp800108CtrHmacSha1(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Sp800108CtrHmacSha1, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().Sp800108CtrHmacSha1());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Sp800108CtrHmacSha256(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Sp800108CtrHmacSha256, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().Sp800108CtrHmacSha256());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Sp800108CtrHmacSha384(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Sp800108CtrHmacSha384, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().Sp800108CtrHmacSha384());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Sp800108CtrHmacSha512(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Sp800108CtrHmacSha512, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().Sp800108CtrHmacSha512());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Sp80056aConcatMd5(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Sp80056aConcatMd5, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().Sp80056aConcatMd5());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Sp80056aConcatSha1(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Sp80056aConcatSha1, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().Sp80056aConcatSha1());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Sp80056aConcatSha256(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Sp80056aConcatSha256, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().Sp80056aConcatSha256());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Sp80056aConcatSha384(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Sp80056aConcatSha384, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().Sp80056aConcatSha384());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Sp80056aConcatSha512(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Sp80056aConcatSha512, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().Sp80056aConcatSha512());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Security::Cryptography::Core::IKeyDerivationAlgorithmNamesStatics2> : produce_base<D, Windows::Security::Cryptography::Core::IKeyDerivationAlgorithmNamesStatics2>
{
    int32_t WINRT_CALL get_CapiKdfMd5(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CapiKdfMd5, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().CapiKdfMd5());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_CapiKdfSha1(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CapiKdfSha1, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().CapiKdfSha1());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_CapiKdfSha256(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CapiKdfSha256, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().CapiKdfSha256());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_CapiKdfSha384(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CapiKdfSha384, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().CapiKdfSha384());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_CapiKdfSha512(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CapiKdfSha512, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().CapiKdfSha512());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Security::Cryptography::Core::IKeyDerivationAlgorithmProvider> : produce_base<D, Windows::Security::Cryptography::Core::IKeyDerivationAlgorithmProvider>
{
    int32_t WINRT_CALL get_AlgorithmName(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(AlgorithmName, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().AlgorithmName());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL CreateKey(void* keyMaterial, void** key) noexcept final
    {
        try
        {
            *key = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CreateKey, WINRT_WRAP(Windows::Security::Cryptography::Core::CryptographicKey), Windows::Storage::Streams::IBuffer const&);
            *key = detach_from<Windows::Security::Cryptography::Core::CryptographicKey>(this->shim().CreateKey(*reinterpret_cast<Windows::Storage::Streams::IBuffer const*>(&keyMaterial)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Security::Cryptography::Core::IKeyDerivationAlgorithmProviderStatics> : produce_base<D, Windows::Security::Cryptography::Core::IKeyDerivationAlgorithmProviderStatics>
{
    int32_t WINRT_CALL OpenAlgorithm(void* algorithm, void** provider) noexcept final
    {
        try
        {
            *provider = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(OpenAlgorithm, WINRT_WRAP(Windows::Security::Cryptography::Core::KeyDerivationAlgorithmProvider), hstring const&);
            *provider = detach_from<Windows::Security::Cryptography::Core::KeyDerivationAlgorithmProvider>(this->shim().OpenAlgorithm(*reinterpret_cast<hstring const*>(&algorithm)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Security::Cryptography::Core::IKeyDerivationParameters> : produce_base<D, Windows::Security::Cryptography::Core::IKeyDerivationParameters>
{
    int32_t WINRT_CALL get_KdfGenericBinary(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(KdfGenericBinary, WINRT_WRAP(Windows::Storage::Streams::IBuffer));
            *value = detach_from<Windows::Storage::Streams::IBuffer>(this->shim().KdfGenericBinary());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_KdfGenericBinary(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(KdfGenericBinary, WINRT_WRAP(void), Windows::Storage::Streams::IBuffer const&);
            this->shim().KdfGenericBinary(*reinterpret_cast<Windows::Storage::Streams::IBuffer const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_IterationCount(uint32_t* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IterationCount, WINRT_WRAP(uint32_t));
            *value = detach_from<uint32_t>(this->shim().IterationCount());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Security::Cryptography::Core::IKeyDerivationParameters2> : produce_base<D, Windows::Security::Cryptography::Core::IKeyDerivationParameters2>
{
    int32_t WINRT_CALL get_Capi1KdfTargetAlgorithm(Windows::Security::Cryptography::Core::Capi1KdfTargetAlgorithm* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Capi1KdfTargetAlgorithm, WINRT_WRAP(Windows::Security::Cryptography::Core::Capi1KdfTargetAlgorithm));
            *value = detach_from<Windows::Security::Cryptography::Core::Capi1KdfTargetAlgorithm>(this->shim().Capi1KdfTargetAlgorithm());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_Capi1KdfTargetAlgorithm(Windows::Security::Cryptography::Core::Capi1KdfTargetAlgorithm value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Capi1KdfTargetAlgorithm, WINRT_WRAP(void), Windows::Security::Cryptography::Core::Capi1KdfTargetAlgorithm const&);
            this->shim().Capi1KdfTargetAlgorithm(*reinterpret_cast<Windows::Security::Cryptography::Core::Capi1KdfTargetAlgorithm const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Security::Cryptography::Core::IKeyDerivationParametersStatics> : produce_base<D, Windows::Security::Cryptography::Core::IKeyDerivationParametersStatics>
{
    int32_t WINRT_CALL BuildForPbkdf2(void* pbkdf2Salt, uint32_t iterationCount, void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(BuildForPbkdf2, WINRT_WRAP(Windows::Security::Cryptography::Core::KeyDerivationParameters), Windows::Storage::Streams::IBuffer const&, uint32_t);
            *value = detach_from<Windows::Security::Cryptography::Core::KeyDerivationParameters>(this->shim().BuildForPbkdf2(*reinterpret_cast<Windows::Storage::Streams::IBuffer const*>(&pbkdf2Salt), iterationCount));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL BuildForSP800108(void* label, void* context, void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(BuildForSP800108, WINRT_WRAP(Windows::Security::Cryptography::Core::KeyDerivationParameters), Windows::Storage::Streams::IBuffer const&, Windows::Storage::Streams::IBuffer const&);
            *value = detach_from<Windows::Security::Cryptography::Core::KeyDerivationParameters>(this->shim().BuildForSP800108(*reinterpret_cast<Windows::Storage::Streams::IBuffer const*>(&label), *reinterpret_cast<Windows::Storage::Streams::IBuffer const*>(&context)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL BuildForSP80056a(void* algorithmId, void* partyUInfo, void* partyVInfo, void* suppPubInfo, void* suppPrivInfo, void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(BuildForSP80056a, WINRT_WRAP(Windows::Security::Cryptography::Core::KeyDerivationParameters), Windows::Storage::Streams::IBuffer const&, Windows::Storage::Streams::IBuffer const&, Windows::Storage::Streams::IBuffer const&, Windows::Storage::Streams::IBuffer const&, Windows::Storage::Streams::IBuffer const&);
            *value = detach_from<Windows::Security::Cryptography::Core::KeyDerivationParameters>(this->shim().BuildForSP80056a(*reinterpret_cast<Windows::Storage::Streams::IBuffer const*>(&algorithmId), *reinterpret_cast<Windows::Storage::Streams::IBuffer const*>(&partyUInfo), *reinterpret_cast<Windows::Storage::Streams::IBuffer const*>(&partyVInfo), *reinterpret_cast<Windows::Storage::Streams::IBuffer const*>(&suppPubInfo), *reinterpret_cast<Windows::Storage::Streams::IBuffer const*>(&suppPrivInfo)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Security::Cryptography::Core::IKeyDerivationParametersStatics2> : produce_base<D, Windows::Security::Cryptography::Core::IKeyDerivationParametersStatics2>
{
    int32_t WINRT_CALL BuildForCapi1Kdf(Windows::Security::Cryptography::Core::Capi1KdfTargetAlgorithm capi1KdfTargetAlgorithm, void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(BuildForCapi1Kdf, WINRT_WRAP(Windows::Security::Cryptography::Core::KeyDerivationParameters), Windows::Security::Cryptography::Core::Capi1KdfTargetAlgorithm const&);
            *value = detach_from<Windows::Security::Cryptography::Core::KeyDerivationParameters>(this->shim().BuildForCapi1Kdf(*reinterpret_cast<Windows::Security::Cryptography::Core::Capi1KdfTargetAlgorithm const*>(&capi1KdfTargetAlgorithm)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Security::Cryptography::Core::IMacAlgorithmNamesStatics> : produce_base<D, Windows::Security::Cryptography::Core::IMacAlgorithmNamesStatics>
{
    int32_t WINRT_CALL get_HmacMd5(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(HmacMd5, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().HmacMd5());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_HmacSha1(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(HmacSha1, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().HmacSha1());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_HmacSha256(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(HmacSha256, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().HmacSha256());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_HmacSha384(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(HmacSha384, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().HmacSha384());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_HmacSha512(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(HmacSha512, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().HmacSha512());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_AesCmac(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(AesCmac, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().AesCmac());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Security::Cryptography::Core::IMacAlgorithmProvider> : produce_base<D, Windows::Security::Cryptography::Core::IMacAlgorithmProvider>
{
    int32_t WINRT_CALL get_AlgorithmName(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(AlgorithmName, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().AlgorithmName());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_MacLength(uint32_t* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(MacLength, WINRT_WRAP(uint32_t));
            *value = detach_from<uint32_t>(this->shim().MacLength());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL CreateKey(void* keyMaterial, void** macKey) noexcept final
    {
        try
        {
            *macKey = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CreateKey, WINRT_WRAP(Windows::Security::Cryptography::Core::CryptographicKey), Windows::Storage::Streams::IBuffer const&);
            *macKey = detach_from<Windows::Security::Cryptography::Core::CryptographicKey>(this->shim().CreateKey(*reinterpret_cast<Windows::Storage::Streams::IBuffer const*>(&keyMaterial)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Security::Cryptography::Core::IMacAlgorithmProvider2> : produce_base<D, Windows::Security::Cryptography::Core::IMacAlgorithmProvider2>
{
    int32_t WINRT_CALL CreateHash(void* keyMaterial, void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CreateHash, WINRT_WRAP(Windows::Security::Cryptography::Core::CryptographicHash), Windows::Storage::Streams::IBuffer const&);
            *value = detach_from<Windows::Security::Cryptography::Core::CryptographicHash>(this->shim().CreateHash(*reinterpret_cast<Windows::Storage::Streams::IBuffer const*>(&keyMaterial)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Security::Cryptography::Core::IMacAlgorithmProviderStatics> : produce_base<D, Windows::Security::Cryptography::Core::IMacAlgorithmProviderStatics>
{
    int32_t WINRT_CALL OpenAlgorithm(void* algorithm, void** provider) noexcept final
    {
        try
        {
            *provider = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(OpenAlgorithm, WINRT_WRAP(Windows::Security::Cryptography::Core::MacAlgorithmProvider), hstring const&);
            *provider = detach_from<Windows::Security::Cryptography::Core::MacAlgorithmProvider>(this->shim().OpenAlgorithm(*reinterpret_cast<hstring const*>(&algorithm)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Security::Cryptography::Core::IPersistedKeyProviderStatics> : produce_base<D, Windows::Security::Cryptography::Core::IPersistedKeyProviderStatics>
{
    int32_t WINRT_CALL OpenKeyPairFromCertificateAsync(void* certificate, void* hashAlgorithmName, Windows::Security::Cryptography::Core::CryptographicPadding padding, void** operation) noexcept final
    {
        try
        {
            *operation = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(OpenKeyPairFromCertificateAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<Windows::Security::Cryptography::Core::CryptographicKey>), Windows::Security::Cryptography::Certificates::Certificate const, hstring const, Windows::Security::Cryptography::Core::CryptographicPadding const);
            *operation = detach_from<Windows::Foundation::IAsyncOperation<Windows::Security::Cryptography::Core::CryptographicKey>>(this->shim().OpenKeyPairFromCertificateAsync(*reinterpret_cast<Windows::Security::Cryptography::Certificates::Certificate const*>(&certificate), *reinterpret_cast<hstring const*>(&hashAlgorithmName), *reinterpret_cast<Windows::Security::Cryptography::Core::CryptographicPadding const*>(&padding)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL OpenPublicKeyFromCertificate(void* certificate, void* hashAlgorithmName, Windows::Security::Cryptography::Core::CryptographicPadding padding, void** key) noexcept final
    {
        try
        {
            *key = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(OpenPublicKeyFromCertificate, WINRT_WRAP(Windows::Security::Cryptography::Core::CryptographicKey), Windows::Security::Cryptography::Certificates::Certificate const&, hstring const&, Windows::Security::Cryptography::Core::CryptographicPadding const&);
            *key = detach_from<Windows::Security::Cryptography::Core::CryptographicKey>(this->shim().OpenPublicKeyFromCertificate(*reinterpret_cast<Windows::Security::Cryptography::Certificates::Certificate const*>(&certificate), *reinterpret_cast<hstring const*>(&hashAlgorithmName), *reinterpret_cast<Windows::Security::Cryptography::Core::CryptographicPadding const*>(&padding)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Security::Cryptography::Core::ISymmetricAlgorithmNamesStatics> : produce_base<D, Windows::Security::Cryptography::Core::ISymmetricAlgorithmNamesStatics>
{
    int32_t WINRT_CALL get_DesCbc(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(DesCbc, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().DesCbc());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_DesEcb(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(DesEcb, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().DesEcb());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_TripleDesCbc(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(TripleDesCbc, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().TripleDesCbc());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_TripleDesEcb(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(TripleDesEcb, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().TripleDesEcb());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Rc2Cbc(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Rc2Cbc, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().Rc2Cbc());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Rc2Ecb(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Rc2Ecb, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().Rc2Ecb());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_AesCbc(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(AesCbc, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().AesCbc());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_AesEcb(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(AesEcb, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().AesEcb());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_AesGcm(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(AesGcm, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().AesGcm());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_AesCcm(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(AesCcm, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().AesCcm());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_AesCbcPkcs7(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(AesCbcPkcs7, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().AesCbcPkcs7());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_AesEcbPkcs7(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(AesEcbPkcs7, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().AesEcbPkcs7());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_DesCbcPkcs7(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(DesCbcPkcs7, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().DesCbcPkcs7());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_DesEcbPkcs7(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(DesEcbPkcs7, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().DesEcbPkcs7());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_TripleDesCbcPkcs7(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(TripleDesCbcPkcs7, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().TripleDesCbcPkcs7());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_TripleDesEcbPkcs7(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(TripleDesEcbPkcs7, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().TripleDesEcbPkcs7());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Rc2CbcPkcs7(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Rc2CbcPkcs7, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().Rc2CbcPkcs7());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Rc2EcbPkcs7(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Rc2EcbPkcs7, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().Rc2EcbPkcs7());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Rc4(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Rc4, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().Rc4());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Security::Cryptography::Core::ISymmetricKeyAlgorithmProvider> : produce_base<D, Windows::Security::Cryptography::Core::ISymmetricKeyAlgorithmProvider>
{
    int32_t WINRT_CALL get_AlgorithmName(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(AlgorithmName, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().AlgorithmName());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_BlockLength(uint32_t* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(BlockLength, WINRT_WRAP(uint32_t));
            *value = detach_from<uint32_t>(this->shim().BlockLength());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL CreateSymmetricKey(void* keyMaterial, void** key) noexcept final
    {
        try
        {
            *key = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CreateSymmetricKey, WINRT_WRAP(Windows::Security::Cryptography::Core::CryptographicKey), Windows::Storage::Streams::IBuffer const&);
            *key = detach_from<Windows::Security::Cryptography::Core::CryptographicKey>(this->shim().CreateSymmetricKey(*reinterpret_cast<Windows::Storage::Streams::IBuffer const*>(&keyMaterial)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Security::Cryptography::Core::ISymmetricKeyAlgorithmProviderStatics> : produce_base<D, Windows::Security::Cryptography::Core::ISymmetricKeyAlgorithmProviderStatics>
{
    int32_t WINRT_CALL OpenAlgorithm(void* algorithm, void** provider) noexcept final
    {
        try
        {
            *provider = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(OpenAlgorithm, WINRT_WRAP(Windows::Security::Cryptography::Core::SymmetricKeyAlgorithmProvider), hstring const&);
            *provider = detach_from<Windows::Security::Cryptography::Core::SymmetricKeyAlgorithmProvider>(this->shim().OpenAlgorithm(*reinterpret_cast<hstring const*>(&algorithm)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

}

WINRT_EXPORT namespace winrt::Windows::Security::Cryptography::Core {

inline hstring AsymmetricAlgorithmNames::RsaPkcs1()
{
    return impl::call_factory<AsymmetricAlgorithmNames, Windows::Security::Cryptography::Core::IAsymmetricAlgorithmNamesStatics>([&](auto&& f) { return f.RsaPkcs1(); });
}

inline hstring AsymmetricAlgorithmNames::RsaOaepSha1()
{
    return impl::call_factory<AsymmetricAlgorithmNames, Windows::Security::Cryptography::Core::IAsymmetricAlgorithmNamesStatics>([&](auto&& f) { return f.RsaOaepSha1(); });
}

inline hstring AsymmetricAlgorithmNames::RsaOaepSha256()
{
    return impl::call_factory<AsymmetricAlgorithmNames, Windows::Security::Cryptography::Core::IAsymmetricAlgorithmNamesStatics>([&](auto&& f) { return f.RsaOaepSha256(); });
}

inline hstring AsymmetricAlgorithmNames::RsaOaepSha384()
{
    return impl::call_factory<AsymmetricAlgorithmNames, Windows::Security::Cryptography::Core::IAsymmetricAlgorithmNamesStatics>([&](auto&& f) { return f.RsaOaepSha384(); });
}

inline hstring AsymmetricAlgorithmNames::RsaOaepSha512()
{
    return impl::call_factory<AsymmetricAlgorithmNames, Windows::Security::Cryptography::Core::IAsymmetricAlgorithmNamesStatics>([&](auto&& f) { return f.RsaOaepSha512(); });
}

inline hstring AsymmetricAlgorithmNames::EcdsaP256Sha256()
{
    return impl::call_factory<AsymmetricAlgorithmNames, Windows::Security::Cryptography::Core::IAsymmetricAlgorithmNamesStatics>([&](auto&& f) { return f.EcdsaP256Sha256(); });
}

inline hstring AsymmetricAlgorithmNames::EcdsaP384Sha384()
{
    return impl::call_factory<AsymmetricAlgorithmNames, Windows::Security::Cryptography::Core::IAsymmetricAlgorithmNamesStatics>([&](auto&& f) { return f.EcdsaP384Sha384(); });
}

inline hstring AsymmetricAlgorithmNames::EcdsaP521Sha512()
{
    return impl::call_factory<AsymmetricAlgorithmNames, Windows::Security::Cryptography::Core::IAsymmetricAlgorithmNamesStatics>([&](auto&& f) { return f.EcdsaP521Sha512(); });
}

inline hstring AsymmetricAlgorithmNames::DsaSha1()
{
    return impl::call_factory<AsymmetricAlgorithmNames, Windows::Security::Cryptography::Core::IAsymmetricAlgorithmNamesStatics>([&](auto&& f) { return f.DsaSha1(); });
}

inline hstring AsymmetricAlgorithmNames::DsaSha256()
{
    return impl::call_factory<AsymmetricAlgorithmNames, Windows::Security::Cryptography::Core::IAsymmetricAlgorithmNamesStatics>([&](auto&& f) { return f.DsaSha256(); });
}

inline hstring AsymmetricAlgorithmNames::RsaSignPkcs1Sha1()
{
    return impl::call_factory<AsymmetricAlgorithmNames, Windows::Security::Cryptography::Core::IAsymmetricAlgorithmNamesStatics>([&](auto&& f) { return f.RsaSignPkcs1Sha1(); });
}

inline hstring AsymmetricAlgorithmNames::RsaSignPkcs1Sha256()
{
    return impl::call_factory<AsymmetricAlgorithmNames, Windows::Security::Cryptography::Core::IAsymmetricAlgorithmNamesStatics>([&](auto&& f) { return f.RsaSignPkcs1Sha256(); });
}

inline hstring AsymmetricAlgorithmNames::RsaSignPkcs1Sha384()
{
    return impl::call_factory<AsymmetricAlgorithmNames, Windows::Security::Cryptography::Core::IAsymmetricAlgorithmNamesStatics>([&](auto&& f) { return f.RsaSignPkcs1Sha384(); });
}

inline hstring AsymmetricAlgorithmNames::RsaSignPkcs1Sha512()
{
    return impl::call_factory<AsymmetricAlgorithmNames, Windows::Security::Cryptography::Core::IAsymmetricAlgorithmNamesStatics>([&](auto&& f) { return f.RsaSignPkcs1Sha512(); });
}

inline hstring AsymmetricAlgorithmNames::RsaSignPssSha1()
{
    return impl::call_factory<AsymmetricAlgorithmNames, Windows::Security::Cryptography::Core::IAsymmetricAlgorithmNamesStatics>([&](auto&& f) { return f.RsaSignPssSha1(); });
}

inline hstring AsymmetricAlgorithmNames::RsaSignPssSha256()
{
    return impl::call_factory<AsymmetricAlgorithmNames, Windows::Security::Cryptography::Core::IAsymmetricAlgorithmNamesStatics>([&](auto&& f) { return f.RsaSignPssSha256(); });
}

inline hstring AsymmetricAlgorithmNames::RsaSignPssSha384()
{
    return impl::call_factory<AsymmetricAlgorithmNames, Windows::Security::Cryptography::Core::IAsymmetricAlgorithmNamesStatics>([&](auto&& f) { return f.RsaSignPssSha384(); });
}

inline hstring AsymmetricAlgorithmNames::RsaSignPssSha512()
{
    return impl::call_factory<AsymmetricAlgorithmNames, Windows::Security::Cryptography::Core::IAsymmetricAlgorithmNamesStatics>([&](auto&& f) { return f.RsaSignPssSha512(); });
}

inline hstring AsymmetricAlgorithmNames::EcdsaSha256()
{
    return impl::call_factory<AsymmetricAlgorithmNames, Windows::Security::Cryptography::Core::IAsymmetricAlgorithmNamesStatics2>([&](auto&& f) { return f.EcdsaSha256(); });
}

inline hstring AsymmetricAlgorithmNames::EcdsaSha384()
{
    return impl::call_factory<AsymmetricAlgorithmNames, Windows::Security::Cryptography::Core::IAsymmetricAlgorithmNamesStatics2>([&](auto&& f) { return f.EcdsaSha384(); });
}

inline hstring AsymmetricAlgorithmNames::EcdsaSha512()
{
    return impl::call_factory<AsymmetricAlgorithmNames, Windows::Security::Cryptography::Core::IAsymmetricAlgorithmNamesStatics2>([&](auto&& f) { return f.EcdsaSha512(); });
}

inline Windows::Security::Cryptography::Core::AsymmetricKeyAlgorithmProvider AsymmetricKeyAlgorithmProvider::OpenAlgorithm(param::hstring const& algorithm)
{
    return impl::call_factory<AsymmetricKeyAlgorithmProvider, Windows::Security::Cryptography::Core::IAsymmetricKeyAlgorithmProviderStatics>([&](auto&& f) { return f.OpenAlgorithm(algorithm); });
}

inline Windows::Storage::Streams::IBuffer CryptographicEngine::Encrypt(Windows::Security::Cryptography::Core::CryptographicKey const& key, Windows::Storage::Streams::IBuffer const& data, Windows::Storage::Streams::IBuffer const& iv)
{
    return impl::call_factory<CryptographicEngine, Windows::Security::Cryptography::Core::ICryptographicEngineStatics>([&](auto&& f) { return f.Encrypt(key, data, iv); });
}

inline Windows::Storage::Streams::IBuffer CryptographicEngine::Decrypt(Windows::Security::Cryptography::Core::CryptographicKey const& key, Windows::Storage::Streams::IBuffer const& data, Windows::Storage::Streams::IBuffer const& iv)
{
    return impl::call_factory<CryptographicEngine, Windows::Security::Cryptography::Core::ICryptographicEngineStatics>([&](auto&& f) { return f.Decrypt(key, data, iv); });
}

inline Windows::Security::Cryptography::Core::EncryptedAndAuthenticatedData CryptographicEngine::EncryptAndAuthenticate(Windows::Security::Cryptography::Core::CryptographicKey const& key, Windows::Storage::Streams::IBuffer const& data, Windows::Storage::Streams::IBuffer const& nonce, Windows::Storage::Streams::IBuffer const& authenticatedData)
{
    return impl::call_factory<CryptographicEngine, Windows::Security::Cryptography::Core::ICryptographicEngineStatics>([&](auto&& f) { return f.EncryptAndAuthenticate(key, data, nonce, authenticatedData); });
}

inline Windows::Storage::Streams::IBuffer CryptographicEngine::DecryptAndAuthenticate(Windows::Security::Cryptography::Core::CryptographicKey const& key, Windows::Storage::Streams::IBuffer const& data, Windows::Storage::Streams::IBuffer const& nonce, Windows::Storage::Streams::IBuffer const& authenticationTag, Windows::Storage::Streams::IBuffer const& authenticatedData)
{
    return impl::call_factory<CryptographicEngine, Windows::Security::Cryptography::Core::ICryptographicEngineStatics>([&](auto&& f) { return f.DecryptAndAuthenticate(key, data, nonce, authenticationTag, authenticatedData); });
}

inline Windows::Storage::Streams::IBuffer CryptographicEngine::Sign(Windows::Security::Cryptography::Core::CryptographicKey const& key, Windows::Storage::Streams::IBuffer const& data)
{
    return impl::call_factory<CryptographicEngine, Windows::Security::Cryptography::Core::ICryptographicEngineStatics>([&](auto&& f) { return f.Sign(key, data); });
}

inline bool CryptographicEngine::VerifySignature(Windows::Security::Cryptography::Core::CryptographicKey const& key, Windows::Storage::Streams::IBuffer const& data, Windows::Storage::Streams::IBuffer const& signature)
{
    return impl::call_factory<CryptographicEngine, Windows::Security::Cryptography::Core::ICryptographicEngineStatics>([&](auto&& f) { return f.VerifySignature(key, data, signature); });
}

inline Windows::Storage::Streams::IBuffer CryptographicEngine::DeriveKeyMaterial(Windows::Security::Cryptography::Core::CryptographicKey const& key, Windows::Security::Cryptography::Core::KeyDerivationParameters const& parameters, uint32_t desiredKeySize)
{
    return impl::call_factory<CryptographicEngine, Windows::Security::Cryptography::Core::ICryptographicEngineStatics>([&](auto&& f) { return f.DeriveKeyMaterial(key, parameters, desiredKeySize); });
}

inline Windows::Storage::Streams::IBuffer CryptographicEngine::SignHashedData(Windows::Security::Cryptography::Core::CryptographicKey const& key, Windows::Storage::Streams::IBuffer const& data)
{
    return impl::call_factory<CryptographicEngine, Windows::Security::Cryptography::Core::ICryptographicEngineStatics2>([&](auto&& f) { return f.SignHashedData(key, data); });
}

inline bool CryptographicEngine::VerifySignatureWithHashInput(Windows::Security::Cryptography::Core::CryptographicKey const& key, Windows::Storage::Streams::IBuffer const& data, Windows::Storage::Streams::IBuffer const& signature)
{
    return impl::call_factory<CryptographicEngine, Windows::Security::Cryptography::Core::ICryptographicEngineStatics2>([&](auto&& f) { return f.VerifySignatureWithHashInput(key, data, signature); });
}

inline Windows::Foundation::IAsyncOperation<Windows::Storage::Streams::IBuffer> CryptographicEngine::DecryptAsync(Windows::Security::Cryptography::Core::CryptographicKey const& key, Windows::Storage::Streams::IBuffer const& data, Windows::Storage::Streams::IBuffer const& iv)
{
    return impl::call_factory<CryptographicEngine, Windows::Security::Cryptography::Core::ICryptographicEngineStatics2>([&](auto&& f) { return f.DecryptAsync(key, data, iv); });
}

inline Windows::Foundation::IAsyncOperation<Windows::Storage::Streams::IBuffer> CryptographicEngine::SignAsync(Windows::Security::Cryptography::Core::CryptographicKey const& key, Windows::Storage::Streams::IBuffer const& data)
{
    return impl::call_factory<CryptographicEngine, Windows::Security::Cryptography::Core::ICryptographicEngineStatics2>([&](auto&& f) { return f.SignAsync(key, data); });
}

inline Windows::Foundation::IAsyncOperation<Windows::Storage::Streams::IBuffer> CryptographicEngine::SignHashedDataAsync(Windows::Security::Cryptography::Core::CryptographicKey const& key, Windows::Storage::Streams::IBuffer const& data)
{
    return impl::call_factory<CryptographicEngine, Windows::Security::Cryptography::Core::ICryptographicEngineStatics2>([&](auto&& f) { return f.SignHashedDataAsync(key, data); });
}

inline hstring EccCurveNames::BrainpoolP160r1()
{
    return impl::call_factory<EccCurveNames, Windows::Security::Cryptography::Core::IEccCurveNamesStatics>([&](auto&& f) { return f.BrainpoolP160r1(); });
}

inline hstring EccCurveNames::BrainpoolP160t1()
{
    return impl::call_factory<EccCurveNames, Windows::Security::Cryptography::Core::IEccCurveNamesStatics>([&](auto&& f) { return f.BrainpoolP160t1(); });
}

inline hstring EccCurveNames::BrainpoolP192r1()
{
    return impl::call_factory<EccCurveNames, Windows::Security::Cryptography::Core::IEccCurveNamesStatics>([&](auto&& f) { return f.BrainpoolP192r1(); });
}

inline hstring EccCurveNames::BrainpoolP192t1()
{
    return impl::call_factory<EccCurveNames, Windows::Security::Cryptography::Core::IEccCurveNamesStatics>([&](auto&& f) { return f.BrainpoolP192t1(); });
}

inline hstring EccCurveNames::BrainpoolP224r1()
{
    return impl::call_factory<EccCurveNames, Windows::Security::Cryptography::Core::IEccCurveNamesStatics>([&](auto&& f) { return f.BrainpoolP224r1(); });
}

inline hstring EccCurveNames::BrainpoolP224t1()
{
    return impl::call_factory<EccCurveNames, Windows::Security::Cryptography::Core::IEccCurveNamesStatics>([&](auto&& f) { return f.BrainpoolP224t1(); });
}

inline hstring EccCurveNames::BrainpoolP256r1()
{
    return impl::call_factory<EccCurveNames, Windows::Security::Cryptography::Core::IEccCurveNamesStatics>([&](auto&& f) { return f.BrainpoolP256r1(); });
}

inline hstring EccCurveNames::BrainpoolP256t1()
{
    return impl::call_factory<EccCurveNames, Windows::Security::Cryptography::Core::IEccCurveNamesStatics>([&](auto&& f) { return f.BrainpoolP256t1(); });
}

inline hstring EccCurveNames::BrainpoolP320r1()
{
    return impl::call_factory<EccCurveNames, Windows::Security::Cryptography::Core::IEccCurveNamesStatics>([&](auto&& f) { return f.BrainpoolP320r1(); });
}

inline hstring EccCurveNames::BrainpoolP320t1()
{
    return impl::call_factory<EccCurveNames, Windows::Security::Cryptography::Core::IEccCurveNamesStatics>([&](auto&& f) { return f.BrainpoolP320t1(); });
}

inline hstring EccCurveNames::BrainpoolP384r1()
{
    return impl::call_factory<EccCurveNames, Windows::Security::Cryptography::Core::IEccCurveNamesStatics>([&](auto&& f) { return f.BrainpoolP384r1(); });
}

inline hstring EccCurveNames::BrainpoolP384t1()
{
    return impl::call_factory<EccCurveNames, Windows::Security::Cryptography::Core::IEccCurveNamesStatics>([&](auto&& f) { return f.BrainpoolP384t1(); });
}

inline hstring EccCurveNames::BrainpoolP512r1()
{
    return impl::call_factory<EccCurveNames, Windows::Security::Cryptography::Core::IEccCurveNamesStatics>([&](auto&& f) { return f.BrainpoolP512r1(); });
}

inline hstring EccCurveNames::BrainpoolP512t1()
{
    return impl::call_factory<EccCurveNames, Windows::Security::Cryptography::Core::IEccCurveNamesStatics>([&](auto&& f) { return f.BrainpoolP512t1(); });
}

inline hstring EccCurveNames::Curve25519()
{
    return impl::call_factory<EccCurveNames, Windows::Security::Cryptography::Core::IEccCurveNamesStatics>([&](auto&& f) { return f.Curve25519(); });
}

inline hstring EccCurveNames::Ec192wapi()
{
    return impl::call_factory<EccCurveNames, Windows::Security::Cryptography::Core::IEccCurveNamesStatics>([&](auto&& f) { return f.Ec192wapi(); });
}

inline hstring EccCurveNames::NistP192()
{
    return impl::call_factory<EccCurveNames, Windows::Security::Cryptography::Core::IEccCurveNamesStatics>([&](auto&& f) { return f.NistP192(); });
}

inline hstring EccCurveNames::NistP224()
{
    return impl::call_factory<EccCurveNames, Windows::Security::Cryptography::Core::IEccCurveNamesStatics>([&](auto&& f) { return f.NistP224(); });
}

inline hstring EccCurveNames::NistP256()
{
    return impl::call_factory<EccCurveNames, Windows::Security::Cryptography::Core::IEccCurveNamesStatics>([&](auto&& f) { return f.NistP256(); });
}

inline hstring EccCurveNames::NistP384()
{
    return impl::call_factory<EccCurveNames, Windows::Security::Cryptography::Core::IEccCurveNamesStatics>([&](auto&& f) { return f.NistP384(); });
}

inline hstring EccCurveNames::NistP521()
{
    return impl::call_factory<EccCurveNames, Windows::Security::Cryptography::Core::IEccCurveNamesStatics>([&](auto&& f) { return f.NistP521(); });
}

inline hstring EccCurveNames::NumsP256t1()
{
    return impl::call_factory<EccCurveNames, Windows::Security::Cryptography::Core::IEccCurveNamesStatics>([&](auto&& f) { return f.NumsP256t1(); });
}

inline hstring EccCurveNames::NumsP384t1()
{
    return impl::call_factory<EccCurveNames, Windows::Security::Cryptography::Core::IEccCurveNamesStatics>([&](auto&& f) { return f.NumsP384t1(); });
}

inline hstring EccCurveNames::NumsP512t1()
{
    return impl::call_factory<EccCurveNames, Windows::Security::Cryptography::Core::IEccCurveNamesStatics>([&](auto&& f) { return f.NumsP512t1(); });
}

inline hstring EccCurveNames::SecP160k1()
{
    return impl::call_factory<EccCurveNames, Windows::Security::Cryptography::Core::IEccCurveNamesStatics>([&](auto&& f) { return f.SecP160k1(); });
}

inline hstring EccCurveNames::SecP160r1()
{
    return impl::call_factory<EccCurveNames, Windows::Security::Cryptography::Core::IEccCurveNamesStatics>([&](auto&& f) { return f.SecP160r1(); });
}

inline hstring EccCurveNames::SecP160r2()
{
    return impl::call_factory<EccCurveNames, Windows::Security::Cryptography::Core::IEccCurveNamesStatics>([&](auto&& f) { return f.SecP160r2(); });
}

inline hstring EccCurveNames::SecP192k1()
{
    return impl::call_factory<EccCurveNames, Windows::Security::Cryptography::Core::IEccCurveNamesStatics>([&](auto&& f) { return f.SecP192k1(); });
}

inline hstring EccCurveNames::SecP192r1()
{
    return impl::call_factory<EccCurveNames, Windows::Security::Cryptography::Core::IEccCurveNamesStatics>([&](auto&& f) { return f.SecP192r1(); });
}

inline hstring EccCurveNames::SecP224k1()
{
    return impl::call_factory<EccCurveNames, Windows::Security::Cryptography::Core::IEccCurveNamesStatics>([&](auto&& f) { return f.SecP224k1(); });
}

inline hstring EccCurveNames::SecP224r1()
{
    return impl::call_factory<EccCurveNames, Windows::Security::Cryptography::Core::IEccCurveNamesStatics>([&](auto&& f) { return f.SecP224r1(); });
}

inline hstring EccCurveNames::SecP256k1()
{
    return impl::call_factory<EccCurveNames, Windows::Security::Cryptography::Core::IEccCurveNamesStatics>([&](auto&& f) { return f.SecP256k1(); });
}

inline hstring EccCurveNames::SecP256r1()
{
    return impl::call_factory<EccCurveNames, Windows::Security::Cryptography::Core::IEccCurveNamesStatics>([&](auto&& f) { return f.SecP256r1(); });
}

inline hstring EccCurveNames::SecP384r1()
{
    return impl::call_factory<EccCurveNames, Windows::Security::Cryptography::Core::IEccCurveNamesStatics>([&](auto&& f) { return f.SecP384r1(); });
}

inline hstring EccCurveNames::SecP521r1()
{
    return impl::call_factory<EccCurveNames, Windows::Security::Cryptography::Core::IEccCurveNamesStatics>([&](auto&& f) { return f.SecP521r1(); });
}

inline hstring EccCurveNames::Wtls7()
{
    return impl::call_factory<EccCurveNames, Windows::Security::Cryptography::Core::IEccCurveNamesStatics>([&](auto&& f) { return f.Wtls7(); });
}

inline hstring EccCurveNames::Wtls9()
{
    return impl::call_factory<EccCurveNames, Windows::Security::Cryptography::Core::IEccCurveNamesStatics>([&](auto&& f) { return f.Wtls9(); });
}

inline hstring EccCurveNames::Wtls12()
{
    return impl::call_factory<EccCurveNames, Windows::Security::Cryptography::Core::IEccCurveNamesStatics>([&](auto&& f) { return f.Wtls12(); });
}

inline hstring EccCurveNames::X962P192v1()
{
    return impl::call_factory<EccCurveNames, Windows::Security::Cryptography::Core::IEccCurveNamesStatics>([&](auto&& f) { return f.X962P192v1(); });
}

inline hstring EccCurveNames::X962P192v2()
{
    return impl::call_factory<EccCurveNames, Windows::Security::Cryptography::Core::IEccCurveNamesStatics>([&](auto&& f) { return f.X962P192v2(); });
}

inline hstring EccCurveNames::X962P192v3()
{
    return impl::call_factory<EccCurveNames, Windows::Security::Cryptography::Core::IEccCurveNamesStatics>([&](auto&& f) { return f.X962P192v3(); });
}

inline hstring EccCurveNames::X962P239v1()
{
    return impl::call_factory<EccCurveNames, Windows::Security::Cryptography::Core::IEccCurveNamesStatics>([&](auto&& f) { return f.X962P239v1(); });
}

inline hstring EccCurveNames::X962P239v2()
{
    return impl::call_factory<EccCurveNames, Windows::Security::Cryptography::Core::IEccCurveNamesStatics>([&](auto&& f) { return f.X962P239v2(); });
}

inline hstring EccCurveNames::X962P239v3()
{
    return impl::call_factory<EccCurveNames, Windows::Security::Cryptography::Core::IEccCurveNamesStatics>([&](auto&& f) { return f.X962P239v3(); });
}

inline hstring EccCurveNames::X962P256v1()
{
    return impl::call_factory<EccCurveNames, Windows::Security::Cryptography::Core::IEccCurveNamesStatics>([&](auto&& f) { return f.X962P256v1(); });
}

inline Windows::Foundation::Collections::IVectorView<hstring> EccCurveNames::AllEccCurveNames()
{
    return impl::call_factory<EccCurveNames, Windows::Security::Cryptography::Core::IEccCurveNamesStatics>([&](auto&& f) { return f.AllEccCurveNames(); });
}

inline hstring HashAlgorithmNames::Md5()
{
    return impl::call_factory<HashAlgorithmNames, Windows::Security::Cryptography::Core::IHashAlgorithmNamesStatics>([&](auto&& f) { return f.Md5(); });
}

inline hstring HashAlgorithmNames::Sha1()
{
    return impl::call_factory<HashAlgorithmNames, Windows::Security::Cryptography::Core::IHashAlgorithmNamesStatics>([&](auto&& f) { return f.Sha1(); });
}

inline hstring HashAlgorithmNames::Sha256()
{
    return impl::call_factory<HashAlgorithmNames, Windows::Security::Cryptography::Core::IHashAlgorithmNamesStatics>([&](auto&& f) { return f.Sha256(); });
}

inline hstring HashAlgorithmNames::Sha384()
{
    return impl::call_factory<HashAlgorithmNames, Windows::Security::Cryptography::Core::IHashAlgorithmNamesStatics>([&](auto&& f) { return f.Sha384(); });
}

inline hstring HashAlgorithmNames::Sha512()
{
    return impl::call_factory<HashAlgorithmNames, Windows::Security::Cryptography::Core::IHashAlgorithmNamesStatics>([&](auto&& f) { return f.Sha512(); });
}

inline Windows::Security::Cryptography::Core::HashAlgorithmProvider HashAlgorithmProvider::OpenAlgorithm(param::hstring const& algorithm)
{
    return impl::call_factory<HashAlgorithmProvider, Windows::Security::Cryptography::Core::IHashAlgorithmProviderStatics>([&](auto&& f) { return f.OpenAlgorithm(algorithm); });
}

inline hstring KeyDerivationAlgorithmNames::Pbkdf2Md5()
{
    return impl::call_factory<KeyDerivationAlgorithmNames, Windows::Security::Cryptography::Core::IKeyDerivationAlgorithmNamesStatics>([&](auto&& f) { return f.Pbkdf2Md5(); });
}

inline hstring KeyDerivationAlgorithmNames::Pbkdf2Sha1()
{
    return impl::call_factory<KeyDerivationAlgorithmNames, Windows::Security::Cryptography::Core::IKeyDerivationAlgorithmNamesStatics>([&](auto&& f) { return f.Pbkdf2Sha1(); });
}

inline hstring KeyDerivationAlgorithmNames::Pbkdf2Sha256()
{
    return impl::call_factory<KeyDerivationAlgorithmNames, Windows::Security::Cryptography::Core::IKeyDerivationAlgorithmNamesStatics>([&](auto&& f) { return f.Pbkdf2Sha256(); });
}

inline hstring KeyDerivationAlgorithmNames::Pbkdf2Sha384()
{
    return impl::call_factory<KeyDerivationAlgorithmNames, Windows::Security::Cryptography::Core::IKeyDerivationAlgorithmNamesStatics>([&](auto&& f) { return f.Pbkdf2Sha384(); });
}

inline hstring KeyDerivationAlgorithmNames::Pbkdf2Sha512()
{
    return impl::call_factory<KeyDerivationAlgorithmNames, Windows::Security::Cryptography::Core::IKeyDerivationAlgorithmNamesStatics>([&](auto&& f) { return f.Pbkdf2Sha512(); });
}

inline hstring KeyDerivationAlgorithmNames::Sp800108CtrHmacMd5()
{
    return impl::call_factory<KeyDerivationAlgorithmNames, Windows::Security::Cryptography::Core::IKeyDerivationAlgorithmNamesStatics>([&](auto&& f) { return f.Sp800108CtrHmacMd5(); });
}

inline hstring KeyDerivationAlgorithmNames::Sp800108CtrHmacSha1()
{
    return impl::call_factory<KeyDerivationAlgorithmNames, Windows::Security::Cryptography::Core::IKeyDerivationAlgorithmNamesStatics>([&](auto&& f) { return f.Sp800108CtrHmacSha1(); });
}

inline hstring KeyDerivationAlgorithmNames::Sp800108CtrHmacSha256()
{
    return impl::call_factory<KeyDerivationAlgorithmNames, Windows::Security::Cryptography::Core::IKeyDerivationAlgorithmNamesStatics>([&](auto&& f) { return f.Sp800108CtrHmacSha256(); });
}

inline hstring KeyDerivationAlgorithmNames::Sp800108CtrHmacSha384()
{
    return impl::call_factory<KeyDerivationAlgorithmNames, Windows::Security::Cryptography::Core::IKeyDerivationAlgorithmNamesStatics>([&](auto&& f) { return f.Sp800108CtrHmacSha384(); });
}

inline hstring KeyDerivationAlgorithmNames::Sp800108CtrHmacSha512()
{
    return impl::call_factory<KeyDerivationAlgorithmNames, Windows::Security::Cryptography::Core::IKeyDerivationAlgorithmNamesStatics>([&](auto&& f) { return f.Sp800108CtrHmacSha512(); });
}

inline hstring KeyDerivationAlgorithmNames::Sp80056aConcatMd5()
{
    return impl::call_factory<KeyDerivationAlgorithmNames, Windows::Security::Cryptography::Core::IKeyDerivationAlgorithmNamesStatics>([&](auto&& f) { return f.Sp80056aConcatMd5(); });
}

inline hstring KeyDerivationAlgorithmNames::Sp80056aConcatSha1()
{
    return impl::call_factory<KeyDerivationAlgorithmNames, Windows::Security::Cryptography::Core::IKeyDerivationAlgorithmNamesStatics>([&](auto&& f) { return f.Sp80056aConcatSha1(); });
}

inline hstring KeyDerivationAlgorithmNames::Sp80056aConcatSha256()
{
    return impl::call_factory<KeyDerivationAlgorithmNames, Windows::Security::Cryptography::Core::IKeyDerivationAlgorithmNamesStatics>([&](auto&& f) { return f.Sp80056aConcatSha256(); });
}

inline hstring KeyDerivationAlgorithmNames::Sp80056aConcatSha384()
{
    return impl::call_factory<KeyDerivationAlgorithmNames, Windows::Security::Cryptography::Core::IKeyDerivationAlgorithmNamesStatics>([&](auto&& f) { return f.Sp80056aConcatSha384(); });
}

inline hstring KeyDerivationAlgorithmNames::Sp80056aConcatSha512()
{
    return impl::call_factory<KeyDerivationAlgorithmNames, Windows::Security::Cryptography::Core::IKeyDerivationAlgorithmNamesStatics>([&](auto&& f) { return f.Sp80056aConcatSha512(); });
}

inline hstring KeyDerivationAlgorithmNames::CapiKdfMd5()
{
    return impl::call_factory<KeyDerivationAlgorithmNames, Windows::Security::Cryptography::Core::IKeyDerivationAlgorithmNamesStatics2>([&](auto&& f) { return f.CapiKdfMd5(); });
}

inline hstring KeyDerivationAlgorithmNames::CapiKdfSha1()
{
    return impl::call_factory<KeyDerivationAlgorithmNames, Windows::Security::Cryptography::Core::IKeyDerivationAlgorithmNamesStatics2>([&](auto&& f) { return f.CapiKdfSha1(); });
}

inline hstring KeyDerivationAlgorithmNames::CapiKdfSha256()
{
    return impl::call_factory<KeyDerivationAlgorithmNames, Windows::Security::Cryptography::Core::IKeyDerivationAlgorithmNamesStatics2>([&](auto&& f) { return f.CapiKdfSha256(); });
}

inline hstring KeyDerivationAlgorithmNames::CapiKdfSha384()
{
    return impl::call_factory<KeyDerivationAlgorithmNames, Windows::Security::Cryptography::Core::IKeyDerivationAlgorithmNamesStatics2>([&](auto&& f) { return f.CapiKdfSha384(); });
}

inline hstring KeyDerivationAlgorithmNames::CapiKdfSha512()
{
    return impl::call_factory<KeyDerivationAlgorithmNames, Windows::Security::Cryptography::Core::IKeyDerivationAlgorithmNamesStatics2>([&](auto&& f) { return f.CapiKdfSha512(); });
}

inline Windows::Security::Cryptography::Core::KeyDerivationAlgorithmProvider KeyDerivationAlgorithmProvider::OpenAlgorithm(param::hstring const& algorithm)
{
    return impl::call_factory<KeyDerivationAlgorithmProvider, Windows::Security::Cryptography::Core::IKeyDerivationAlgorithmProviderStatics>([&](auto&& f) { return f.OpenAlgorithm(algorithm); });
}

inline Windows::Security::Cryptography::Core::KeyDerivationParameters KeyDerivationParameters::BuildForPbkdf2(Windows::Storage::Streams::IBuffer const& pbkdf2Salt, uint32_t iterationCount)
{
    return impl::call_factory<KeyDerivationParameters, Windows::Security::Cryptography::Core::IKeyDerivationParametersStatics>([&](auto&& f) { return f.BuildForPbkdf2(pbkdf2Salt, iterationCount); });
}

inline Windows::Security::Cryptography::Core::KeyDerivationParameters KeyDerivationParameters::BuildForSP800108(Windows::Storage::Streams::IBuffer const& label, Windows::Storage::Streams::IBuffer const& context)
{
    return impl::call_factory<KeyDerivationParameters, Windows::Security::Cryptography::Core::IKeyDerivationParametersStatics>([&](auto&& f) { return f.BuildForSP800108(label, context); });
}

inline Windows::Security::Cryptography::Core::KeyDerivationParameters KeyDerivationParameters::BuildForSP80056a(Windows::Storage::Streams::IBuffer const& algorithmId, Windows::Storage::Streams::IBuffer const& partyUInfo, Windows::Storage::Streams::IBuffer const& partyVInfo, Windows::Storage::Streams::IBuffer const& suppPubInfo, Windows::Storage::Streams::IBuffer const& suppPrivInfo)
{
    return impl::call_factory<KeyDerivationParameters, Windows::Security::Cryptography::Core::IKeyDerivationParametersStatics>([&](auto&& f) { return f.BuildForSP80056a(algorithmId, partyUInfo, partyVInfo, suppPubInfo, suppPrivInfo); });
}

inline Windows::Security::Cryptography::Core::KeyDerivationParameters KeyDerivationParameters::BuildForCapi1Kdf(Windows::Security::Cryptography::Core::Capi1KdfTargetAlgorithm const& capi1KdfTargetAlgorithm)
{
    return impl::call_factory<KeyDerivationParameters, Windows::Security::Cryptography::Core::IKeyDerivationParametersStatics2>([&](auto&& f) { return f.BuildForCapi1Kdf(capi1KdfTargetAlgorithm); });
}

inline hstring MacAlgorithmNames::HmacMd5()
{
    return impl::call_factory<MacAlgorithmNames, Windows::Security::Cryptography::Core::IMacAlgorithmNamesStatics>([&](auto&& f) { return f.HmacMd5(); });
}

inline hstring MacAlgorithmNames::HmacSha1()
{
    return impl::call_factory<MacAlgorithmNames, Windows::Security::Cryptography::Core::IMacAlgorithmNamesStatics>([&](auto&& f) { return f.HmacSha1(); });
}

inline hstring MacAlgorithmNames::HmacSha256()
{
    return impl::call_factory<MacAlgorithmNames, Windows::Security::Cryptography::Core::IMacAlgorithmNamesStatics>([&](auto&& f) { return f.HmacSha256(); });
}

inline hstring MacAlgorithmNames::HmacSha384()
{
    return impl::call_factory<MacAlgorithmNames, Windows::Security::Cryptography::Core::IMacAlgorithmNamesStatics>([&](auto&& f) { return f.HmacSha384(); });
}

inline hstring MacAlgorithmNames::HmacSha512()
{
    return impl::call_factory<MacAlgorithmNames, Windows::Security::Cryptography::Core::IMacAlgorithmNamesStatics>([&](auto&& f) { return f.HmacSha512(); });
}

inline hstring MacAlgorithmNames::AesCmac()
{
    return impl::call_factory<MacAlgorithmNames, Windows::Security::Cryptography::Core::IMacAlgorithmNamesStatics>([&](auto&& f) { return f.AesCmac(); });
}

inline Windows::Security::Cryptography::Core::MacAlgorithmProvider MacAlgorithmProvider::OpenAlgorithm(param::hstring const& algorithm)
{
    return impl::call_factory<MacAlgorithmProvider, Windows::Security::Cryptography::Core::IMacAlgorithmProviderStatics>([&](auto&& f) { return f.OpenAlgorithm(algorithm); });
}

inline Windows::Foundation::IAsyncOperation<Windows::Security::Cryptography::Core::CryptographicKey> PersistedKeyProvider::OpenKeyPairFromCertificateAsync(Windows::Security::Cryptography::Certificates::Certificate const& certificate, param::hstring const& hashAlgorithmName, Windows::Security::Cryptography::Core::CryptographicPadding const& padding)
{
    return impl::call_factory<PersistedKeyProvider, Windows::Security::Cryptography::Core::IPersistedKeyProviderStatics>([&](auto&& f) { return f.OpenKeyPairFromCertificateAsync(certificate, hashAlgorithmName, padding); });
}

inline Windows::Security::Cryptography::Core::CryptographicKey PersistedKeyProvider::OpenPublicKeyFromCertificate(Windows::Security::Cryptography::Certificates::Certificate const& certificate, param::hstring const& hashAlgorithmName, Windows::Security::Cryptography::Core::CryptographicPadding const& padding)
{
    return impl::call_factory<PersistedKeyProvider, Windows::Security::Cryptography::Core::IPersistedKeyProviderStatics>([&](auto&& f) { return f.OpenPublicKeyFromCertificate(certificate, hashAlgorithmName, padding); });
}

inline hstring SymmetricAlgorithmNames::DesCbc()
{
    return impl::call_factory<SymmetricAlgorithmNames, Windows::Security::Cryptography::Core::ISymmetricAlgorithmNamesStatics>([&](auto&& f) { return f.DesCbc(); });
}

inline hstring SymmetricAlgorithmNames::DesEcb()
{
    return impl::call_factory<SymmetricAlgorithmNames, Windows::Security::Cryptography::Core::ISymmetricAlgorithmNamesStatics>([&](auto&& f) { return f.DesEcb(); });
}

inline hstring SymmetricAlgorithmNames::TripleDesCbc()
{
    return impl::call_factory<SymmetricAlgorithmNames, Windows::Security::Cryptography::Core::ISymmetricAlgorithmNamesStatics>([&](auto&& f) { return f.TripleDesCbc(); });
}

inline hstring SymmetricAlgorithmNames::TripleDesEcb()
{
    return impl::call_factory<SymmetricAlgorithmNames, Windows::Security::Cryptography::Core::ISymmetricAlgorithmNamesStatics>([&](auto&& f) { return f.TripleDesEcb(); });
}

inline hstring SymmetricAlgorithmNames::Rc2Cbc()
{
    return impl::call_factory<SymmetricAlgorithmNames, Windows::Security::Cryptography::Core::ISymmetricAlgorithmNamesStatics>([&](auto&& f) { return f.Rc2Cbc(); });
}

inline hstring SymmetricAlgorithmNames::Rc2Ecb()
{
    return impl::call_factory<SymmetricAlgorithmNames, Windows::Security::Cryptography::Core::ISymmetricAlgorithmNamesStatics>([&](auto&& f) { return f.Rc2Ecb(); });
}

inline hstring SymmetricAlgorithmNames::AesCbc()
{
    return impl::call_factory<SymmetricAlgorithmNames, Windows::Security::Cryptography::Core::ISymmetricAlgorithmNamesStatics>([&](auto&& f) { return f.AesCbc(); });
}

inline hstring SymmetricAlgorithmNames::AesEcb()
{
    return impl::call_factory<SymmetricAlgorithmNames, Windows::Security::Cryptography::Core::ISymmetricAlgorithmNamesStatics>([&](auto&& f) { return f.AesEcb(); });
}

inline hstring SymmetricAlgorithmNames::AesGcm()
{
    return impl::call_factory<SymmetricAlgorithmNames, Windows::Security::Cryptography::Core::ISymmetricAlgorithmNamesStatics>([&](auto&& f) { return f.AesGcm(); });
}

inline hstring SymmetricAlgorithmNames::AesCcm()
{
    return impl::call_factory<SymmetricAlgorithmNames, Windows::Security::Cryptography::Core::ISymmetricAlgorithmNamesStatics>([&](auto&& f) { return f.AesCcm(); });
}

inline hstring SymmetricAlgorithmNames::AesCbcPkcs7()
{
    return impl::call_factory<SymmetricAlgorithmNames, Windows::Security::Cryptography::Core::ISymmetricAlgorithmNamesStatics>([&](auto&& f) { return f.AesCbcPkcs7(); });
}

inline hstring SymmetricAlgorithmNames::AesEcbPkcs7()
{
    return impl::call_factory<SymmetricAlgorithmNames, Windows::Security::Cryptography::Core::ISymmetricAlgorithmNamesStatics>([&](auto&& f) { return f.AesEcbPkcs7(); });
}

inline hstring SymmetricAlgorithmNames::DesCbcPkcs7()
{
    return impl::call_factory<SymmetricAlgorithmNames, Windows::Security::Cryptography::Core::ISymmetricAlgorithmNamesStatics>([&](auto&& f) { return f.DesCbcPkcs7(); });
}

inline hstring SymmetricAlgorithmNames::DesEcbPkcs7()
{
    return impl::call_factory<SymmetricAlgorithmNames, Windows::Security::Cryptography::Core::ISymmetricAlgorithmNamesStatics>([&](auto&& f) { return f.DesEcbPkcs7(); });
}

inline hstring SymmetricAlgorithmNames::TripleDesCbcPkcs7()
{
    return impl::call_factory<SymmetricAlgorithmNames, Windows::Security::Cryptography::Core::ISymmetricAlgorithmNamesStatics>([&](auto&& f) { return f.TripleDesCbcPkcs7(); });
}

inline hstring SymmetricAlgorithmNames::TripleDesEcbPkcs7()
{
    return impl::call_factory<SymmetricAlgorithmNames, Windows::Security::Cryptography::Core::ISymmetricAlgorithmNamesStatics>([&](auto&& f) { return f.TripleDesEcbPkcs7(); });
}

inline hstring SymmetricAlgorithmNames::Rc2CbcPkcs7()
{
    return impl::call_factory<SymmetricAlgorithmNames, Windows::Security::Cryptography::Core::ISymmetricAlgorithmNamesStatics>([&](auto&& f) { return f.Rc2CbcPkcs7(); });
}

inline hstring SymmetricAlgorithmNames::Rc2EcbPkcs7()
{
    return impl::call_factory<SymmetricAlgorithmNames, Windows::Security::Cryptography::Core::ISymmetricAlgorithmNamesStatics>([&](auto&& f) { return f.Rc2EcbPkcs7(); });
}

inline hstring SymmetricAlgorithmNames::Rc4()
{
    return impl::call_factory<SymmetricAlgorithmNames, Windows::Security::Cryptography::Core::ISymmetricAlgorithmNamesStatics>([&](auto&& f) { return f.Rc4(); });
}

inline Windows::Security::Cryptography::Core::SymmetricKeyAlgorithmProvider SymmetricKeyAlgorithmProvider::OpenAlgorithm(param::hstring const& algorithm)
{
    return impl::call_factory<SymmetricKeyAlgorithmProvider, Windows::Security::Cryptography::Core::ISymmetricKeyAlgorithmProviderStatics>([&](auto&& f) { return f.OpenAlgorithm(algorithm); });
}

}

WINRT_EXPORT namespace std {

template<> struct hash<winrt::Windows::Security::Cryptography::Core::IAsymmetricAlgorithmNamesStatics> : winrt::impl::hash_base<winrt::Windows::Security::Cryptography::Core::IAsymmetricAlgorithmNamesStatics> {};
template<> struct hash<winrt::Windows::Security::Cryptography::Core::IAsymmetricAlgorithmNamesStatics2> : winrt::impl::hash_base<winrt::Windows::Security::Cryptography::Core::IAsymmetricAlgorithmNamesStatics2> {};
template<> struct hash<winrt::Windows::Security::Cryptography::Core::IAsymmetricKeyAlgorithmProvider> : winrt::impl::hash_base<winrt::Windows::Security::Cryptography::Core::IAsymmetricKeyAlgorithmProvider> {};
template<> struct hash<winrt::Windows::Security::Cryptography::Core::IAsymmetricKeyAlgorithmProvider2> : winrt::impl::hash_base<winrt::Windows::Security::Cryptography::Core::IAsymmetricKeyAlgorithmProvider2> {};
template<> struct hash<winrt::Windows::Security::Cryptography::Core::IAsymmetricKeyAlgorithmProviderStatics> : winrt::impl::hash_base<winrt::Windows::Security::Cryptography::Core::IAsymmetricKeyAlgorithmProviderStatics> {};
template<> struct hash<winrt::Windows::Security::Cryptography::Core::ICryptographicEngineStatics> : winrt::impl::hash_base<winrt::Windows::Security::Cryptography::Core::ICryptographicEngineStatics> {};
template<> struct hash<winrt::Windows::Security::Cryptography::Core::ICryptographicEngineStatics2> : winrt::impl::hash_base<winrt::Windows::Security::Cryptography::Core::ICryptographicEngineStatics2> {};
template<> struct hash<winrt::Windows::Security::Cryptography::Core::ICryptographicKey> : winrt::impl::hash_base<winrt::Windows::Security::Cryptography::Core::ICryptographicKey> {};
template<> struct hash<winrt::Windows::Security::Cryptography::Core::IEccCurveNamesStatics> : winrt::impl::hash_base<winrt::Windows::Security::Cryptography::Core::IEccCurveNamesStatics> {};
template<> struct hash<winrt::Windows::Security::Cryptography::Core::IEncryptedAndAuthenticatedData> : winrt::impl::hash_base<winrt::Windows::Security::Cryptography::Core::IEncryptedAndAuthenticatedData> {};
template<> struct hash<winrt::Windows::Security::Cryptography::Core::IHashAlgorithmNamesStatics> : winrt::impl::hash_base<winrt::Windows::Security::Cryptography::Core::IHashAlgorithmNamesStatics> {};
template<> struct hash<winrt::Windows::Security::Cryptography::Core::IHashAlgorithmProvider> : winrt::impl::hash_base<winrt::Windows::Security::Cryptography::Core::IHashAlgorithmProvider> {};
template<> struct hash<winrt::Windows::Security::Cryptography::Core::IHashAlgorithmProviderStatics> : winrt::impl::hash_base<winrt::Windows::Security::Cryptography::Core::IHashAlgorithmProviderStatics> {};
template<> struct hash<winrt::Windows::Security::Cryptography::Core::IHashComputation> : winrt::impl::hash_base<winrt::Windows::Security::Cryptography::Core::IHashComputation> {};
template<> struct hash<winrt::Windows::Security::Cryptography::Core::IKeyDerivationAlgorithmNamesStatics> : winrt::impl::hash_base<winrt::Windows::Security::Cryptography::Core::IKeyDerivationAlgorithmNamesStatics> {};
template<> struct hash<winrt::Windows::Security::Cryptography::Core::IKeyDerivationAlgorithmNamesStatics2> : winrt::impl::hash_base<winrt::Windows::Security::Cryptography::Core::IKeyDerivationAlgorithmNamesStatics2> {};
template<> struct hash<winrt::Windows::Security::Cryptography::Core::IKeyDerivationAlgorithmProvider> : winrt::impl::hash_base<winrt::Windows::Security::Cryptography::Core::IKeyDerivationAlgorithmProvider> {};
template<> struct hash<winrt::Windows::Security::Cryptography::Core::IKeyDerivationAlgorithmProviderStatics> : winrt::impl::hash_base<winrt::Windows::Security::Cryptography::Core::IKeyDerivationAlgorithmProviderStatics> {};
template<> struct hash<winrt::Windows::Security::Cryptography::Core::IKeyDerivationParameters> : winrt::impl::hash_base<winrt::Windows::Security::Cryptography::Core::IKeyDerivationParameters> {};
template<> struct hash<winrt::Windows::Security::Cryptography::Core::IKeyDerivationParameters2> : winrt::impl::hash_base<winrt::Windows::Security::Cryptography::Core::IKeyDerivationParameters2> {};
template<> struct hash<winrt::Windows::Security::Cryptography::Core::IKeyDerivationParametersStatics> : winrt::impl::hash_base<winrt::Windows::Security::Cryptography::Core::IKeyDerivationParametersStatics> {};
template<> struct hash<winrt::Windows::Security::Cryptography::Core::IKeyDerivationParametersStatics2> : winrt::impl::hash_base<winrt::Windows::Security::Cryptography::Core::IKeyDerivationParametersStatics2> {};
template<> struct hash<winrt::Windows::Security::Cryptography::Core::IMacAlgorithmNamesStatics> : winrt::impl::hash_base<winrt::Windows::Security::Cryptography::Core::IMacAlgorithmNamesStatics> {};
template<> struct hash<winrt::Windows::Security::Cryptography::Core::IMacAlgorithmProvider> : winrt::impl::hash_base<winrt::Windows::Security::Cryptography::Core::IMacAlgorithmProvider> {};
template<> struct hash<winrt::Windows::Security::Cryptography::Core::IMacAlgorithmProvider2> : winrt::impl::hash_base<winrt::Windows::Security::Cryptography::Core::IMacAlgorithmProvider2> {};
template<> struct hash<winrt::Windows::Security::Cryptography::Core::IMacAlgorithmProviderStatics> : winrt::impl::hash_base<winrt::Windows::Security::Cryptography::Core::IMacAlgorithmProviderStatics> {};
template<> struct hash<winrt::Windows::Security::Cryptography::Core::IPersistedKeyProviderStatics> : winrt::impl::hash_base<winrt::Windows::Security::Cryptography::Core::IPersistedKeyProviderStatics> {};
template<> struct hash<winrt::Windows::Security::Cryptography::Core::ISymmetricAlgorithmNamesStatics> : winrt::impl::hash_base<winrt::Windows::Security::Cryptography::Core::ISymmetricAlgorithmNamesStatics> {};
template<> struct hash<winrt::Windows::Security::Cryptography::Core::ISymmetricKeyAlgorithmProvider> : winrt::impl::hash_base<winrt::Windows::Security::Cryptography::Core::ISymmetricKeyAlgorithmProvider> {};
template<> struct hash<winrt::Windows::Security::Cryptography::Core::ISymmetricKeyAlgorithmProviderStatics> : winrt::impl::hash_base<winrt::Windows::Security::Cryptography::Core::ISymmetricKeyAlgorithmProviderStatics> {};
template<> struct hash<winrt::Windows::Security::Cryptography::Core::AsymmetricAlgorithmNames> : winrt::impl::hash_base<winrt::Windows::Security::Cryptography::Core::AsymmetricAlgorithmNames> {};
template<> struct hash<winrt::Windows::Security::Cryptography::Core::AsymmetricKeyAlgorithmProvider> : winrt::impl::hash_base<winrt::Windows::Security::Cryptography::Core::AsymmetricKeyAlgorithmProvider> {};
template<> struct hash<winrt::Windows::Security::Cryptography::Core::CryptographicEngine> : winrt::impl::hash_base<winrt::Windows::Security::Cryptography::Core::CryptographicEngine> {};
template<> struct hash<winrt::Windows::Security::Cryptography::Core::CryptographicHash> : winrt::impl::hash_base<winrt::Windows::Security::Cryptography::Core::CryptographicHash> {};
template<> struct hash<winrt::Windows::Security::Cryptography::Core::CryptographicKey> : winrt::impl::hash_base<winrt::Windows::Security::Cryptography::Core::CryptographicKey> {};
template<> struct hash<winrt::Windows::Security::Cryptography::Core::EccCurveNames> : winrt::impl::hash_base<winrt::Windows::Security::Cryptography::Core::EccCurveNames> {};
template<> struct hash<winrt::Windows::Security::Cryptography::Core::EncryptedAndAuthenticatedData> : winrt::impl::hash_base<winrt::Windows::Security::Cryptography::Core::EncryptedAndAuthenticatedData> {};
template<> struct hash<winrt::Windows::Security::Cryptography::Core::HashAlgorithmNames> : winrt::impl::hash_base<winrt::Windows::Security::Cryptography::Core::HashAlgorithmNames> {};
template<> struct hash<winrt::Windows::Security::Cryptography::Core::HashAlgorithmProvider> : winrt::impl::hash_base<winrt::Windows::Security::Cryptography::Core::HashAlgorithmProvider> {};
template<> struct hash<winrt::Windows::Security::Cryptography::Core::KeyDerivationAlgorithmNames> : winrt::impl::hash_base<winrt::Windows::Security::Cryptography::Core::KeyDerivationAlgorithmNames> {};
template<> struct hash<winrt::Windows::Security::Cryptography::Core::KeyDerivationAlgorithmProvider> : winrt::impl::hash_base<winrt::Windows::Security::Cryptography::Core::KeyDerivationAlgorithmProvider> {};
template<> struct hash<winrt::Windows::Security::Cryptography::Core::KeyDerivationParameters> : winrt::impl::hash_base<winrt::Windows::Security::Cryptography::Core::KeyDerivationParameters> {};
template<> struct hash<winrt::Windows::Security::Cryptography::Core::MacAlgorithmNames> : winrt::impl::hash_base<winrt::Windows::Security::Cryptography::Core::MacAlgorithmNames> {};
template<> struct hash<winrt::Windows::Security::Cryptography::Core::MacAlgorithmProvider> : winrt::impl::hash_base<winrt::Windows::Security::Cryptography::Core::MacAlgorithmProvider> {};
template<> struct hash<winrt::Windows::Security::Cryptography::Core::PersistedKeyProvider> : winrt::impl::hash_base<winrt::Windows::Security::Cryptography::Core::PersistedKeyProvider> {};
template<> struct hash<winrt::Windows::Security::Cryptography::Core::SymmetricAlgorithmNames> : winrt::impl::hash_base<winrt::Windows::Security::Cryptography::Core::SymmetricAlgorithmNames> {};
template<> struct hash<winrt::Windows::Security::Cryptography::Core::SymmetricKeyAlgorithmProvider> : winrt::impl::hash_base<winrt::Windows::Security::Cryptography::Core::SymmetricKeyAlgorithmProvider> {};

}
