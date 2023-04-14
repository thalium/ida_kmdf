// C++/WinRT v1.0.190111.3

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#pragma once

#include "winrt/base.h"

#include "winrt/Windows.Foundation.h"
#include "winrt/Windows.Foundation.Collections.h"
#include "winrt/impl/Windows.Foundation.2.h"
#include "winrt/impl/Windows.Globalization.2.h"
#include "winrt/impl/Windows.Networking.2.h"
#include "winrt/impl/Windows.Storage.Streams.2.h"
#include "winrt/impl/Windows.Web.Http.2.h"
#include "winrt/impl/Windows.Foundation.Collections.2.h"
#include "winrt/impl/Windows.Web.Http.Headers.2.h"
#include "winrt/Windows.Web.Http.h"

namespace winrt::impl {

template <typename D> Windows::Foundation::IReference<Windows::Foundation::TimeSpan> consume_Windows_Web_Http_Headers_IHttpCacheDirectiveHeaderValueCollection<D>::MaxAge() const
{
    Windows::Foundation::IReference<Windows::Foundation::TimeSpan> value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Web::Http::Headers::IHttpCacheDirectiveHeaderValueCollection)->get_MaxAge(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_Web_Http_Headers_IHttpCacheDirectiveHeaderValueCollection<D>::MaxAge(optional<Windows::Foundation::TimeSpan> const& value) const
{
    check_hresult(WINRT_SHIM(Windows::Web::Http::Headers::IHttpCacheDirectiveHeaderValueCollection)->put_MaxAge(get_abi(value)));
}

template <typename D> Windows::Foundation::IReference<Windows::Foundation::TimeSpan> consume_Windows_Web_Http_Headers_IHttpCacheDirectiveHeaderValueCollection<D>::MaxStale() const
{
    Windows::Foundation::IReference<Windows::Foundation::TimeSpan> value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Web::Http::Headers::IHttpCacheDirectiveHeaderValueCollection)->get_MaxStale(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_Web_Http_Headers_IHttpCacheDirectiveHeaderValueCollection<D>::MaxStale(optional<Windows::Foundation::TimeSpan> const& value) const
{
    check_hresult(WINRT_SHIM(Windows::Web::Http::Headers::IHttpCacheDirectiveHeaderValueCollection)->put_MaxStale(get_abi(value)));
}

template <typename D> Windows::Foundation::IReference<Windows::Foundation::TimeSpan> consume_Windows_Web_Http_Headers_IHttpCacheDirectiveHeaderValueCollection<D>::MinFresh() const
{
    Windows::Foundation::IReference<Windows::Foundation::TimeSpan> value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Web::Http::Headers::IHttpCacheDirectiveHeaderValueCollection)->get_MinFresh(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_Web_Http_Headers_IHttpCacheDirectiveHeaderValueCollection<D>::MinFresh(optional<Windows::Foundation::TimeSpan> const& value) const
{
    check_hresult(WINRT_SHIM(Windows::Web::Http::Headers::IHttpCacheDirectiveHeaderValueCollection)->put_MinFresh(get_abi(value)));
}

template <typename D> Windows::Foundation::IReference<Windows::Foundation::TimeSpan> consume_Windows_Web_Http_Headers_IHttpCacheDirectiveHeaderValueCollection<D>::SharedMaxAge() const
{
    Windows::Foundation::IReference<Windows::Foundation::TimeSpan> value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Web::Http::Headers::IHttpCacheDirectiveHeaderValueCollection)->get_SharedMaxAge(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_Web_Http_Headers_IHttpCacheDirectiveHeaderValueCollection<D>::SharedMaxAge(optional<Windows::Foundation::TimeSpan> const& value) const
{
    check_hresult(WINRT_SHIM(Windows::Web::Http::Headers::IHttpCacheDirectiveHeaderValueCollection)->put_SharedMaxAge(get_abi(value)));
}

template <typename D> void consume_Windows_Web_Http_Headers_IHttpCacheDirectiveHeaderValueCollection<D>::ParseAdd(param::hstring const& input) const
{
    check_hresult(WINRT_SHIM(Windows::Web::Http::Headers::IHttpCacheDirectiveHeaderValueCollection)->ParseAdd(get_abi(input)));
}

template <typename D> bool consume_Windows_Web_Http_Headers_IHttpCacheDirectiveHeaderValueCollection<D>::TryParseAdd(param::hstring const& input) const
{
    bool result{};
    check_hresult(WINRT_SHIM(Windows::Web::Http::Headers::IHttpCacheDirectiveHeaderValueCollection)->TryParseAdd(get_abi(input), &result));
    return result;
}

template <typename D> Windows::Foundation::Collections::IVector<Windows::Web::Http::Headers::HttpNameValueHeaderValue> consume_Windows_Web_Http_Headers_IHttpChallengeHeaderValue<D>::Parameters() const
{
    Windows::Foundation::Collections::IVector<Windows::Web::Http::Headers::HttpNameValueHeaderValue> value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Web::Http::Headers::IHttpChallengeHeaderValue)->get_Parameters(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_Web_Http_Headers_IHttpChallengeHeaderValue<D>::Scheme() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Web::Http::Headers::IHttpChallengeHeaderValue)->get_Scheme(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_Web_Http_Headers_IHttpChallengeHeaderValue<D>::Token() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Web::Http::Headers::IHttpChallengeHeaderValue)->get_Token(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_Web_Http_Headers_IHttpChallengeHeaderValueCollection<D>::ParseAdd(param::hstring const& input) const
{
    check_hresult(WINRT_SHIM(Windows::Web::Http::Headers::IHttpChallengeHeaderValueCollection)->ParseAdd(get_abi(input)));
}

template <typename D> bool consume_Windows_Web_Http_Headers_IHttpChallengeHeaderValueCollection<D>::TryParseAdd(param::hstring const& input) const
{
    bool result{};
    check_hresult(WINRT_SHIM(Windows::Web::Http::Headers::IHttpChallengeHeaderValueCollection)->TryParseAdd(get_abi(input), &result));
    return result;
}

template <typename D> Windows::Web::Http::Headers::HttpChallengeHeaderValue consume_Windows_Web_Http_Headers_IHttpChallengeHeaderValueFactory<D>::CreateFromScheme(param::hstring const& scheme) const
{
    Windows::Web::Http::Headers::HttpChallengeHeaderValue value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Web::Http::Headers::IHttpChallengeHeaderValueFactory)->CreateFromScheme(get_abi(scheme), put_abi(value)));
    return value;
}

template <typename D> Windows::Web::Http::Headers::HttpChallengeHeaderValue consume_Windows_Web_Http_Headers_IHttpChallengeHeaderValueFactory<D>::CreateFromSchemeWithToken(param::hstring const& scheme, param::hstring const& token) const
{
    Windows::Web::Http::Headers::HttpChallengeHeaderValue value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Web::Http::Headers::IHttpChallengeHeaderValueFactory)->CreateFromSchemeWithToken(get_abi(scheme), get_abi(token), put_abi(value)));
    return value;
}

template <typename D> Windows::Web::Http::Headers::HttpChallengeHeaderValue consume_Windows_Web_Http_Headers_IHttpChallengeHeaderValueStatics<D>::Parse(param::hstring const& input) const
{
    Windows::Web::Http::Headers::HttpChallengeHeaderValue result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Web::Http::Headers::IHttpChallengeHeaderValueStatics)->Parse(get_abi(input), put_abi(result)));
    return result;
}

template <typename D> bool consume_Windows_Web_Http_Headers_IHttpChallengeHeaderValueStatics<D>::TryParse(param::hstring const& input, Windows::Web::Http::Headers::HttpChallengeHeaderValue& challengeHeaderValue) const
{
    bool succeeded{};
    check_hresult(WINRT_SHIM(Windows::Web::Http::Headers::IHttpChallengeHeaderValueStatics)->TryParse(get_abi(input), put_abi(challengeHeaderValue), &succeeded));
    return succeeded;
}

template <typename D> hstring consume_Windows_Web_Http_Headers_IHttpConnectionOptionHeaderValue<D>::Token() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Web::Http::Headers::IHttpConnectionOptionHeaderValue)->get_Token(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_Web_Http_Headers_IHttpConnectionOptionHeaderValueCollection<D>::ParseAdd(param::hstring const& input) const
{
    check_hresult(WINRT_SHIM(Windows::Web::Http::Headers::IHttpConnectionOptionHeaderValueCollection)->ParseAdd(get_abi(input)));
}

template <typename D> bool consume_Windows_Web_Http_Headers_IHttpConnectionOptionHeaderValueCollection<D>::TryParseAdd(param::hstring const& input) const
{
    bool result{};
    check_hresult(WINRT_SHIM(Windows::Web::Http::Headers::IHttpConnectionOptionHeaderValueCollection)->TryParseAdd(get_abi(input), &result));
    return result;
}

template <typename D> Windows::Web::Http::Headers::HttpConnectionOptionHeaderValue consume_Windows_Web_Http_Headers_IHttpConnectionOptionHeaderValueFactory<D>::Create(param::hstring const& token) const
{
    Windows::Web::Http::Headers::HttpConnectionOptionHeaderValue value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Web::Http::Headers::IHttpConnectionOptionHeaderValueFactory)->Create(get_abi(token), put_abi(value)));
    return value;
}

template <typename D> Windows::Web::Http::Headers::HttpConnectionOptionHeaderValue consume_Windows_Web_Http_Headers_IHttpConnectionOptionHeaderValueStatics<D>::Parse(param::hstring const& input) const
{
    Windows::Web::Http::Headers::HttpConnectionOptionHeaderValue result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Web::Http::Headers::IHttpConnectionOptionHeaderValueStatics)->Parse(get_abi(input), put_abi(result)));
    return result;
}

template <typename D> bool consume_Windows_Web_Http_Headers_IHttpConnectionOptionHeaderValueStatics<D>::TryParse(param::hstring const& input, Windows::Web::Http::Headers::HttpConnectionOptionHeaderValue& connectionOptionHeaderValue) const
{
    bool succeeded{};
    check_hresult(WINRT_SHIM(Windows::Web::Http::Headers::IHttpConnectionOptionHeaderValueStatics)->TryParse(get_abi(input), put_abi(connectionOptionHeaderValue), &succeeded));
    return succeeded;
}

template <typename D> hstring consume_Windows_Web_Http_Headers_IHttpContentCodingHeaderValue<D>::ContentCoding() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Web::Http::Headers::IHttpContentCodingHeaderValue)->get_ContentCoding(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_Web_Http_Headers_IHttpContentCodingHeaderValueCollection<D>::ParseAdd(param::hstring const& input) const
{
    check_hresult(WINRT_SHIM(Windows::Web::Http::Headers::IHttpContentCodingHeaderValueCollection)->ParseAdd(get_abi(input)));
}

template <typename D> bool consume_Windows_Web_Http_Headers_IHttpContentCodingHeaderValueCollection<D>::TryParseAdd(param::hstring const& input) const
{
    bool result{};
    check_hresult(WINRT_SHIM(Windows::Web::Http::Headers::IHttpContentCodingHeaderValueCollection)->TryParseAdd(get_abi(input), &result));
    return result;
}

template <typename D> Windows::Web::Http::Headers::HttpContentCodingHeaderValue consume_Windows_Web_Http_Headers_IHttpContentCodingHeaderValueFactory<D>::Create(param::hstring const& contentCoding) const
{
    Windows::Web::Http::Headers::HttpContentCodingHeaderValue value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Web::Http::Headers::IHttpContentCodingHeaderValueFactory)->Create(get_abi(contentCoding), put_abi(value)));
    return value;
}

template <typename D> Windows::Web::Http::Headers::HttpContentCodingHeaderValue consume_Windows_Web_Http_Headers_IHttpContentCodingHeaderValueStatics<D>::Parse(param::hstring const& input) const
{
    Windows::Web::Http::Headers::HttpContentCodingHeaderValue result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Web::Http::Headers::IHttpContentCodingHeaderValueStatics)->Parse(get_abi(input), put_abi(result)));
    return result;
}

template <typename D> bool consume_Windows_Web_Http_Headers_IHttpContentCodingHeaderValueStatics<D>::TryParse(param::hstring const& input, Windows::Web::Http::Headers::HttpContentCodingHeaderValue& contentCodingHeaderValue) const
{
    bool succeeded{};
    check_hresult(WINRT_SHIM(Windows::Web::Http::Headers::IHttpContentCodingHeaderValueStatics)->TryParse(get_abi(input), put_abi(contentCodingHeaderValue), &succeeded));
    return succeeded;
}

template <typename D> hstring consume_Windows_Web_Http_Headers_IHttpContentCodingWithQualityHeaderValue<D>::ContentCoding() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Web::Http::Headers::IHttpContentCodingWithQualityHeaderValue)->get_ContentCoding(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::IReference<double> consume_Windows_Web_Http_Headers_IHttpContentCodingWithQualityHeaderValue<D>::Quality() const
{
    Windows::Foundation::IReference<double> value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Web::Http::Headers::IHttpContentCodingWithQualityHeaderValue)->get_Quality(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_Web_Http_Headers_IHttpContentCodingWithQualityHeaderValueCollection<D>::ParseAdd(param::hstring const& input) const
{
    check_hresult(WINRT_SHIM(Windows::Web::Http::Headers::IHttpContentCodingWithQualityHeaderValueCollection)->ParseAdd(get_abi(input)));
}

template <typename D> bool consume_Windows_Web_Http_Headers_IHttpContentCodingWithQualityHeaderValueCollection<D>::TryParseAdd(param::hstring const& input) const
{
    bool result{};
    check_hresult(WINRT_SHIM(Windows::Web::Http::Headers::IHttpContentCodingWithQualityHeaderValueCollection)->TryParseAdd(get_abi(input), &result));
    return result;
}

template <typename D> Windows::Web::Http::Headers::HttpContentCodingWithQualityHeaderValue consume_Windows_Web_Http_Headers_IHttpContentCodingWithQualityHeaderValueFactory<D>::CreateFromValue(param::hstring const& contentCoding) const
{
    Windows::Web::Http::Headers::HttpContentCodingWithQualityHeaderValue value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Web::Http::Headers::IHttpContentCodingWithQualityHeaderValueFactory)->CreateFromValue(get_abi(contentCoding), put_abi(value)));
    return value;
}

template <typename D> Windows::Web::Http::Headers::HttpContentCodingWithQualityHeaderValue consume_Windows_Web_Http_Headers_IHttpContentCodingWithQualityHeaderValueFactory<D>::CreateFromValueWithQuality(param::hstring const& contentCoding, double quality) const
{
    Windows::Web::Http::Headers::HttpContentCodingWithQualityHeaderValue value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Web::Http::Headers::IHttpContentCodingWithQualityHeaderValueFactory)->CreateFromValueWithQuality(get_abi(contentCoding), quality, put_abi(value)));
    return value;
}

template <typename D> Windows::Web::Http::Headers::HttpContentCodingWithQualityHeaderValue consume_Windows_Web_Http_Headers_IHttpContentCodingWithQualityHeaderValueStatics<D>::Parse(param::hstring const& input) const
{
    Windows::Web::Http::Headers::HttpContentCodingWithQualityHeaderValue result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Web::Http::Headers::IHttpContentCodingWithQualityHeaderValueStatics)->Parse(get_abi(input), put_abi(result)));
    return result;
}

template <typename D> bool consume_Windows_Web_Http_Headers_IHttpContentCodingWithQualityHeaderValueStatics<D>::TryParse(param::hstring const& input, Windows::Web::Http::Headers::HttpContentCodingWithQualityHeaderValue& contentCodingWithQualityHeaderValue) const
{
    bool succeeded{};
    check_hresult(WINRT_SHIM(Windows::Web::Http::Headers::IHttpContentCodingWithQualityHeaderValueStatics)->TryParse(get_abi(input), put_abi(contentCodingWithQualityHeaderValue), &succeeded));
    return succeeded;
}

template <typename D> hstring consume_Windows_Web_Http_Headers_IHttpContentDispositionHeaderValue<D>::DispositionType() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Web::Http::Headers::IHttpContentDispositionHeaderValue)->get_DispositionType(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_Web_Http_Headers_IHttpContentDispositionHeaderValue<D>::DispositionType(param::hstring const& value) const
{
    check_hresult(WINRT_SHIM(Windows::Web::Http::Headers::IHttpContentDispositionHeaderValue)->put_DispositionType(get_abi(value)));
}

template <typename D> hstring consume_Windows_Web_Http_Headers_IHttpContentDispositionHeaderValue<D>::FileName() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Web::Http::Headers::IHttpContentDispositionHeaderValue)->get_FileName(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_Web_Http_Headers_IHttpContentDispositionHeaderValue<D>::FileName(param::hstring const& value) const
{
    check_hresult(WINRT_SHIM(Windows::Web::Http::Headers::IHttpContentDispositionHeaderValue)->put_FileName(get_abi(value)));
}

template <typename D> hstring consume_Windows_Web_Http_Headers_IHttpContentDispositionHeaderValue<D>::FileNameStar() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Web::Http::Headers::IHttpContentDispositionHeaderValue)->get_FileNameStar(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_Web_Http_Headers_IHttpContentDispositionHeaderValue<D>::FileNameStar(param::hstring const& value) const
{
    check_hresult(WINRT_SHIM(Windows::Web::Http::Headers::IHttpContentDispositionHeaderValue)->put_FileNameStar(get_abi(value)));
}

template <typename D> hstring consume_Windows_Web_Http_Headers_IHttpContentDispositionHeaderValue<D>::Name() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Web::Http::Headers::IHttpContentDispositionHeaderValue)->get_Name(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_Web_Http_Headers_IHttpContentDispositionHeaderValue<D>::Name(param::hstring const& value) const
{
    check_hresult(WINRT_SHIM(Windows::Web::Http::Headers::IHttpContentDispositionHeaderValue)->put_Name(get_abi(value)));
}

template <typename D> Windows::Foundation::Collections::IVector<Windows::Web::Http::Headers::HttpNameValueHeaderValue> consume_Windows_Web_Http_Headers_IHttpContentDispositionHeaderValue<D>::Parameters() const
{
    Windows::Foundation::Collections::IVector<Windows::Web::Http::Headers::HttpNameValueHeaderValue> value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Web::Http::Headers::IHttpContentDispositionHeaderValue)->get_Parameters(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::IReference<uint64_t> consume_Windows_Web_Http_Headers_IHttpContentDispositionHeaderValue<D>::Size() const
{
    Windows::Foundation::IReference<uint64_t> value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Web::Http::Headers::IHttpContentDispositionHeaderValue)->get_Size(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_Web_Http_Headers_IHttpContentDispositionHeaderValue<D>::Size(optional<uint64_t> const& value) const
{
    check_hresult(WINRT_SHIM(Windows::Web::Http::Headers::IHttpContentDispositionHeaderValue)->put_Size(get_abi(value)));
}

template <typename D> Windows::Web::Http::Headers::HttpContentDispositionHeaderValue consume_Windows_Web_Http_Headers_IHttpContentDispositionHeaderValueFactory<D>::Create(param::hstring const& dispositionType) const
{
    Windows::Web::Http::Headers::HttpContentDispositionHeaderValue value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Web::Http::Headers::IHttpContentDispositionHeaderValueFactory)->Create(get_abi(dispositionType), put_abi(value)));
    return value;
}

template <typename D> Windows::Web::Http::Headers::HttpContentDispositionHeaderValue consume_Windows_Web_Http_Headers_IHttpContentDispositionHeaderValueStatics<D>::Parse(param::hstring const& input) const
{
    Windows::Web::Http::Headers::HttpContentDispositionHeaderValue result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Web::Http::Headers::IHttpContentDispositionHeaderValueStatics)->Parse(get_abi(input), put_abi(result)));
    return result;
}

template <typename D> bool consume_Windows_Web_Http_Headers_IHttpContentDispositionHeaderValueStatics<D>::TryParse(param::hstring const& input, Windows::Web::Http::Headers::HttpContentDispositionHeaderValue& contentDispositionHeaderValue) const
{
    bool succeeded{};
    check_hresult(WINRT_SHIM(Windows::Web::Http::Headers::IHttpContentDispositionHeaderValueStatics)->TryParse(get_abi(input), put_abi(contentDispositionHeaderValue), &succeeded));
    return succeeded;
}

template <typename D> Windows::Web::Http::Headers::HttpContentDispositionHeaderValue consume_Windows_Web_Http_Headers_IHttpContentHeaderCollection<D>::ContentDisposition() const
{
    Windows::Web::Http::Headers::HttpContentDispositionHeaderValue value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Web::Http::Headers::IHttpContentHeaderCollection)->get_ContentDisposition(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_Web_Http_Headers_IHttpContentHeaderCollection<D>::ContentDisposition(Windows::Web::Http::Headers::HttpContentDispositionHeaderValue const& value) const
{
    check_hresult(WINRT_SHIM(Windows::Web::Http::Headers::IHttpContentHeaderCollection)->put_ContentDisposition(get_abi(value)));
}

template <typename D> Windows::Web::Http::Headers::HttpContentCodingHeaderValueCollection consume_Windows_Web_Http_Headers_IHttpContentHeaderCollection<D>::ContentEncoding() const
{
    Windows::Web::Http::Headers::HttpContentCodingHeaderValueCollection value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Web::Http::Headers::IHttpContentHeaderCollection)->get_ContentEncoding(put_abi(value)));
    return value;
}

template <typename D> Windows::Web::Http::Headers::HttpLanguageHeaderValueCollection consume_Windows_Web_Http_Headers_IHttpContentHeaderCollection<D>::ContentLanguage() const
{
    Windows::Web::Http::Headers::HttpLanguageHeaderValueCollection value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Web::Http::Headers::IHttpContentHeaderCollection)->get_ContentLanguage(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::IReference<uint64_t> consume_Windows_Web_Http_Headers_IHttpContentHeaderCollection<D>::ContentLength() const
{
    Windows::Foundation::IReference<uint64_t> value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Web::Http::Headers::IHttpContentHeaderCollection)->get_ContentLength(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_Web_Http_Headers_IHttpContentHeaderCollection<D>::ContentLength(optional<uint64_t> const& value) const
{
    check_hresult(WINRT_SHIM(Windows::Web::Http::Headers::IHttpContentHeaderCollection)->put_ContentLength(get_abi(value)));
}

template <typename D> Windows::Foundation::Uri consume_Windows_Web_Http_Headers_IHttpContentHeaderCollection<D>::ContentLocation() const
{
    Windows::Foundation::Uri value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Web::Http::Headers::IHttpContentHeaderCollection)->get_ContentLocation(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_Web_Http_Headers_IHttpContentHeaderCollection<D>::ContentLocation(Windows::Foundation::Uri const& value) const
{
    check_hresult(WINRT_SHIM(Windows::Web::Http::Headers::IHttpContentHeaderCollection)->put_ContentLocation(get_abi(value)));
}

template <typename D> Windows::Storage::Streams::IBuffer consume_Windows_Web_Http_Headers_IHttpContentHeaderCollection<D>::ContentMD5() const
{
    Windows::Storage::Streams::IBuffer value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Web::Http::Headers::IHttpContentHeaderCollection)->get_ContentMD5(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_Web_Http_Headers_IHttpContentHeaderCollection<D>::ContentMD5(Windows::Storage::Streams::IBuffer const& value) const
{
    check_hresult(WINRT_SHIM(Windows::Web::Http::Headers::IHttpContentHeaderCollection)->put_ContentMD5(get_abi(value)));
}

template <typename D> Windows::Web::Http::Headers::HttpContentRangeHeaderValue consume_Windows_Web_Http_Headers_IHttpContentHeaderCollection<D>::ContentRange() const
{
    Windows::Web::Http::Headers::HttpContentRangeHeaderValue value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Web::Http::Headers::IHttpContentHeaderCollection)->get_ContentRange(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_Web_Http_Headers_IHttpContentHeaderCollection<D>::ContentRange(Windows::Web::Http::Headers::HttpContentRangeHeaderValue const& value) const
{
    check_hresult(WINRT_SHIM(Windows::Web::Http::Headers::IHttpContentHeaderCollection)->put_ContentRange(get_abi(value)));
}

template <typename D> Windows::Web::Http::Headers::HttpMediaTypeHeaderValue consume_Windows_Web_Http_Headers_IHttpContentHeaderCollection<D>::ContentType() const
{
    Windows::Web::Http::Headers::HttpMediaTypeHeaderValue value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Web::Http::Headers::IHttpContentHeaderCollection)->get_ContentType(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_Web_Http_Headers_IHttpContentHeaderCollection<D>::ContentType(Windows::Web::Http::Headers::HttpMediaTypeHeaderValue const& value) const
{
    check_hresult(WINRT_SHIM(Windows::Web::Http::Headers::IHttpContentHeaderCollection)->put_ContentType(get_abi(value)));
}

template <typename D> Windows::Foundation::IReference<Windows::Foundation::DateTime> consume_Windows_Web_Http_Headers_IHttpContentHeaderCollection<D>::Expires() const
{
    Windows::Foundation::IReference<Windows::Foundation::DateTime> value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Web::Http::Headers::IHttpContentHeaderCollection)->get_Expires(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_Web_Http_Headers_IHttpContentHeaderCollection<D>::Expires(optional<Windows::Foundation::DateTime> const& value) const
{
    check_hresult(WINRT_SHIM(Windows::Web::Http::Headers::IHttpContentHeaderCollection)->put_Expires(get_abi(value)));
}

template <typename D> Windows::Foundation::IReference<Windows::Foundation::DateTime> consume_Windows_Web_Http_Headers_IHttpContentHeaderCollection<D>::LastModified() const
{
    Windows::Foundation::IReference<Windows::Foundation::DateTime> value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Web::Http::Headers::IHttpContentHeaderCollection)->get_LastModified(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_Web_Http_Headers_IHttpContentHeaderCollection<D>::LastModified(optional<Windows::Foundation::DateTime> const& value) const
{
    check_hresult(WINRT_SHIM(Windows::Web::Http::Headers::IHttpContentHeaderCollection)->put_LastModified(get_abi(value)));
}

template <typename D> void consume_Windows_Web_Http_Headers_IHttpContentHeaderCollection<D>::Append(param::hstring const& name, param::hstring const& value) const
{
    check_hresult(WINRT_SHIM(Windows::Web::Http::Headers::IHttpContentHeaderCollection)->Append(get_abi(name), get_abi(value)));
}

template <typename D> bool consume_Windows_Web_Http_Headers_IHttpContentHeaderCollection<D>::TryAppendWithoutValidation(param::hstring const& name, param::hstring const& value) const
{
    bool result{};
    check_hresult(WINRT_SHIM(Windows::Web::Http::Headers::IHttpContentHeaderCollection)->TryAppendWithoutValidation(get_abi(name), get_abi(value), &result));
    return result;
}

template <typename D> Windows::Foundation::IReference<uint64_t> consume_Windows_Web_Http_Headers_IHttpContentRangeHeaderValue<D>::FirstBytePosition() const
{
    Windows::Foundation::IReference<uint64_t> value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Web::Http::Headers::IHttpContentRangeHeaderValue)->get_FirstBytePosition(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::IReference<uint64_t> consume_Windows_Web_Http_Headers_IHttpContentRangeHeaderValue<D>::LastBytePosition() const
{
    Windows::Foundation::IReference<uint64_t> value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Web::Http::Headers::IHttpContentRangeHeaderValue)->get_LastBytePosition(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::IReference<uint64_t> consume_Windows_Web_Http_Headers_IHttpContentRangeHeaderValue<D>::Length() const
{
    Windows::Foundation::IReference<uint64_t> value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Web::Http::Headers::IHttpContentRangeHeaderValue)->get_Length(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_Web_Http_Headers_IHttpContentRangeHeaderValue<D>::Unit() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Web::Http::Headers::IHttpContentRangeHeaderValue)->get_Unit(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_Web_Http_Headers_IHttpContentRangeHeaderValue<D>::Unit(param::hstring const& value) const
{
    check_hresult(WINRT_SHIM(Windows::Web::Http::Headers::IHttpContentRangeHeaderValue)->put_Unit(get_abi(value)));
}

template <typename D> Windows::Web::Http::Headers::HttpContentRangeHeaderValue consume_Windows_Web_Http_Headers_IHttpContentRangeHeaderValueFactory<D>::CreateFromLength(uint64_t length) const
{
    Windows::Web::Http::Headers::HttpContentRangeHeaderValue value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Web::Http::Headers::IHttpContentRangeHeaderValueFactory)->CreateFromLength(length, put_abi(value)));
    return value;
}

template <typename D> Windows::Web::Http::Headers::HttpContentRangeHeaderValue consume_Windows_Web_Http_Headers_IHttpContentRangeHeaderValueFactory<D>::CreateFromRange(uint64_t from, uint64_t to) const
{
    Windows::Web::Http::Headers::HttpContentRangeHeaderValue value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Web::Http::Headers::IHttpContentRangeHeaderValueFactory)->CreateFromRange(from, to, put_abi(value)));
    return value;
}

template <typename D> Windows::Web::Http::Headers::HttpContentRangeHeaderValue consume_Windows_Web_Http_Headers_IHttpContentRangeHeaderValueFactory<D>::CreateFromRangeWithLength(uint64_t from, uint64_t to, uint64_t length) const
{
    Windows::Web::Http::Headers::HttpContentRangeHeaderValue value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Web::Http::Headers::IHttpContentRangeHeaderValueFactory)->CreateFromRangeWithLength(from, to, length, put_abi(value)));
    return value;
}

template <typename D> Windows::Web::Http::Headers::HttpContentRangeHeaderValue consume_Windows_Web_Http_Headers_IHttpContentRangeHeaderValueStatics<D>::Parse(param::hstring const& input) const
{
    Windows::Web::Http::Headers::HttpContentRangeHeaderValue result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Web::Http::Headers::IHttpContentRangeHeaderValueStatics)->Parse(get_abi(input), put_abi(result)));
    return result;
}

template <typename D> bool consume_Windows_Web_Http_Headers_IHttpContentRangeHeaderValueStatics<D>::TryParse(param::hstring const& input, Windows::Web::Http::Headers::HttpContentRangeHeaderValue& contentRangeHeaderValue) const
{
    bool succeeded{};
    check_hresult(WINRT_SHIM(Windows::Web::Http::Headers::IHttpContentRangeHeaderValueStatics)->TryParse(get_abi(input), put_abi(contentRangeHeaderValue), &succeeded));
    return succeeded;
}

template <typename D> hstring consume_Windows_Web_Http_Headers_IHttpCookiePairHeaderValue<D>::Name() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Web::Http::Headers::IHttpCookiePairHeaderValue)->get_Name(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_Web_Http_Headers_IHttpCookiePairHeaderValue<D>::Value() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Web::Http::Headers::IHttpCookiePairHeaderValue)->get_Value(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_Web_Http_Headers_IHttpCookiePairHeaderValue<D>::Value(param::hstring const& value) const
{
    check_hresult(WINRT_SHIM(Windows::Web::Http::Headers::IHttpCookiePairHeaderValue)->put_Value(get_abi(value)));
}

template <typename D> void consume_Windows_Web_Http_Headers_IHttpCookiePairHeaderValueCollection<D>::ParseAdd(param::hstring const& input) const
{
    check_hresult(WINRT_SHIM(Windows::Web::Http::Headers::IHttpCookiePairHeaderValueCollection)->ParseAdd(get_abi(input)));
}

template <typename D> bool consume_Windows_Web_Http_Headers_IHttpCookiePairHeaderValueCollection<D>::TryParseAdd(param::hstring const& input) const
{
    bool result{};
    check_hresult(WINRT_SHIM(Windows::Web::Http::Headers::IHttpCookiePairHeaderValueCollection)->TryParseAdd(get_abi(input), &result));
    return result;
}

template <typename D> Windows::Web::Http::Headers::HttpCookiePairHeaderValue consume_Windows_Web_Http_Headers_IHttpCookiePairHeaderValueFactory<D>::CreateFromName(param::hstring const& name) const
{
    Windows::Web::Http::Headers::HttpCookiePairHeaderValue value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Web::Http::Headers::IHttpCookiePairHeaderValueFactory)->CreateFromName(get_abi(name), put_abi(value)));
    return value;
}

template <typename D> Windows::Web::Http::Headers::HttpCookiePairHeaderValue consume_Windows_Web_Http_Headers_IHttpCookiePairHeaderValueFactory<D>::CreateFromNameWithValue(param::hstring const& name, param::hstring const& value) const
{
    Windows::Web::Http::Headers::HttpCookiePairHeaderValue cookiePairHeaderValue{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Web::Http::Headers::IHttpCookiePairHeaderValueFactory)->CreateFromNameWithValue(get_abi(name), get_abi(value), put_abi(cookiePairHeaderValue)));
    return cookiePairHeaderValue;
}

template <typename D> Windows::Web::Http::Headers::HttpCookiePairHeaderValue consume_Windows_Web_Http_Headers_IHttpCookiePairHeaderValueStatics<D>::Parse(param::hstring const& input) const
{
    Windows::Web::Http::Headers::HttpCookiePairHeaderValue result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Web::Http::Headers::IHttpCookiePairHeaderValueStatics)->Parse(get_abi(input), put_abi(result)));
    return result;
}

template <typename D> bool consume_Windows_Web_Http_Headers_IHttpCookiePairHeaderValueStatics<D>::TryParse(param::hstring const& input, Windows::Web::Http::Headers::HttpCookiePairHeaderValue& cookiePairHeaderValue) const
{
    bool succeeded{};
    check_hresult(WINRT_SHIM(Windows::Web::Http::Headers::IHttpCookiePairHeaderValueStatics)->TryParse(get_abi(input), put_abi(cookiePairHeaderValue), &succeeded));
    return succeeded;
}

template <typename D> Windows::Foundation::Collections::IVector<Windows::Web::Http::Headers::HttpNameValueHeaderValue> consume_Windows_Web_Http_Headers_IHttpCredentialsHeaderValue<D>::Parameters() const
{
    Windows::Foundation::Collections::IVector<Windows::Web::Http::Headers::HttpNameValueHeaderValue> value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Web::Http::Headers::IHttpCredentialsHeaderValue)->get_Parameters(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_Web_Http_Headers_IHttpCredentialsHeaderValue<D>::Scheme() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Web::Http::Headers::IHttpCredentialsHeaderValue)->get_Scheme(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_Web_Http_Headers_IHttpCredentialsHeaderValue<D>::Token() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Web::Http::Headers::IHttpCredentialsHeaderValue)->get_Token(put_abi(value)));
    return value;
}

template <typename D> Windows::Web::Http::Headers::HttpCredentialsHeaderValue consume_Windows_Web_Http_Headers_IHttpCredentialsHeaderValueFactory<D>::CreateFromScheme(param::hstring const& scheme) const
{
    Windows::Web::Http::Headers::HttpCredentialsHeaderValue value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Web::Http::Headers::IHttpCredentialsHeaderValueFactory)->CreateFromScheme(get_abi(scheme), put_abi(value)));
    return value;
}

template <typename D> Windows::Web::Http::Headers::HttpCredentialsHeaderValue consume_Windows_Web_Http_Headers_IHttpCredentialsHeaderValueFactory<D>::CreateFromSchemeWithToken(param::hstring const& scheme, param::hstring const& token) const
{
    Windows::Web::Http::Headers::HttpCredentialsHeaderValue value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Web::Http::Headers::IHttpCredentialsHeaderValueFactory)->CreateFromSchemeWithToken(get_abi(scheme), get_abi(token), put_abi(value)));
    return value;
}

template <typename D> Windows::Web::Http::Headers::HttpCredentialsHeaderValue consume_Windows_Web_Http_Headers_IHttpCredentialsHeaderValueStatics<D>::Parse(param::hstring const& input) const
{
    Windows::Web::Http::Headers::HttpCredentialsHeaderValue result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Web::Http::Headers::IHttpCredentialsHeaderValueStatics)->Parse(get_abi(input), put_abi(result)));
    return result;
}

template <typename D> bool consume_Windows_Web_Http_Headers_IHttpCredentialsHeaderValueStatics<D>::TryParse(param::hstring const& input, Windows::Web::Http::Headers::HttpCredentialsHeaderValue& credentialsHeaderValue) const
{
    bool succeeded{};
    check_hresult(WINRT_SHIM(Windows::Web::Http::Headers::IHttpCredentialsHeaderValueStatics)->TryParse(get_abi(input), put_abi(credentialsHeaderValue), &succeeded));
    return succeeded;
}

template <typename D> Windows::Foundation::IReference<Windows::Foundation::DateTime> consume_Windows_Web_Http_Headers_IHttpDateOrDeltaHeaderValue<D>::Date() const
{
    Windows::Foundation::IReference<Windows::Foundation::DateTime> value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Web::Http::Headers::IHttpDateOrDeltaHeaderValue)->get_Date(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::IReference<Windows::Foundation::TimeSpan> consume_Windows_Web_Http_Headers_IHttpDateOrDeltaHeaderValue<D>::Delta() const
{
    Windows::Foundation::IReference<Windows::Foundation::TimeSpan> value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Web::Http::Headers::IHttpDateOrDeltaHeaderValue)->get_Delta(put_abi(value)));
    return value;
}

template <typename D> Windows::Web::Http::Headers::HttpDateOrDeltaHeaderValue consume_Windows_Web_Http_Headers_IHttpDateOrDeltaHeaderValueStatics<D>::Parse(param::hstring const& input) const
{
    Windows::Web::Http::Headers::HttpDateOrDeltaHeaderValue result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Web::Http::Headers::IHttpDateOrDeltaHeaderValueStatics)->Parse(get_abi(input), put_abi(result)));
    return result;
}

template <typename D> bool consume_Windows_Web_Http_Headers_IHttpDateOrDeltaHeaderValueStatics<D>::TryParse(param::hstring const& input, Windows::Web::Http::Headers::HttpDateOrDeltaHeaderValue& dateOrDeltaHeaderValue) const
{
    bool succeeded{};
    check_hresult(WINRT_SHIM(Windows::Web::Http::Headers::IHttpDateOrDeltaHeaderValueStatics)->TryParse(get_abi(input), put_abi(dateOrDeltaHeaderValue), &succeeded));
    return succeeded;
}

template <typename D> hstring consume_Windows_Web_Http_Headers_IHttpExpectationHeaderValue<D>::Name() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Web::Http::Headers::IHttpExpectationHeaderValue)->get_Name(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_Web_Http_Headers_IHttpExpectationHeaderValue<D>::Value() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Web::Http::Headers::IHttpExpectationHeaderValue)->get_Value(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_Web_Http_Headers_IHttpExpectationHeaderValue<D>::Value(param::hstring const& value) const
{
    check_hresult(WINRT_SHIM(Windows::Web::Http::Headers::IHttpExpectationHeaderValue)->put_Value(get_abi(value)));
}

template <typename D> Windows::Foundation::Collections::IVector<Windows::Web::Http::Headers::HttpNameValueHeaderValue> consume_Windows_Web_Http_Headers_IHttpExpectationHeaderValue<D>::Parameters() const
{
    Windows::Foundation::Collections::IVector<Windows::Web::Http::Headers::HttpNameValueHeaderValue> value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Web::Http::Headers::IHttpExpectationHeaderValue)->get_Parameters(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_Web_Http_Headers_IHttpExpectationHeaderValueCollection<D>::ParseAdd(param::hstring const& input) const
{
    check_hresult(WINRT_SHIM(Windows::Web::Http::Headers::IHttpExpectationHeaderValueCollection)->ParseAdd(get_abi(input)));
}

template <typename D> bool consume_Windows_Web_Http_Headers_IHttpExpectationHeaderValueCollection<D>::TryParseAdd(param::hstring const& input) const
{
    bool result{};
    check_hresult(WINRT_SHIM(Windows::Web::Http::Headers::IHttpExpectationHeaderValueCollection)->TryParseAdd(get_abi(input), &result));
    return result;
}

template <typename D> Windows::Web::Http::Headers::HttpExpectationHeaderValue consume_Windows_Web_Http_Headers_IHttpExpectationHeaderValueFactory<D>::CreateFromName(param::hstring const& name) const
{
    Windows::Web::Http::Headers::HttpExpectationHeaderValue value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Web::Http::Headers::IHttpExpectationHeaderValueFactory)->CreateFromName(get_abi(name), put_abi(value)));
    return value;
}

template <typename D> Windows::Web::Http::Headers::HttpExpectationHeaderValue consume_Windows_Web_Http_Headers_IHttpExpectationHeaderValueFactory<D>::CreateFromNameWithValue(param::hstring const& name, param::hstring const& value) const
{
    Windows::Web::Http::Headers::HttpExpectationHeaderValue expectationHeaderValue{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Web::Http::Headers::IHttpExpectationHeaderValueFactory)->CreateFromNameWithValue(get_abi(name), get_abi(value), put_abi(expectationHeaderValue)));
    return expectationHeaderValue;
}

template <typename D> Windows::Web::Http::Headers::HttpExpectationHeaderValue consume_Windows_Web_Http_Headers_IHttpExpectationHeaderValueStatics<D>::Parse(param::hstring const& input) const
{
    Windows::Web::Http::Headers::HttpExpectationHeaderValue result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Web::Http::Headers::IHttpExpectationHeaderValueStatics)->Parse(get_abi(input), put_abi(result)));
    return result;
}

template <typename D> bool consume_Windows_Web_Http_Headers_IHttpExpectationHeaderValueStatics<D>::TryParse(param::hstring const& input, Windows::Web::Http::Headers::HttpExpectationHeaderValue& expectationHeaderValue) const
{
    bool succeeded{};
    check_hresult(WINRT_SHIM(Windows::Web::Http::Headers::IHttpExpectationHeaderValueStatics)->TryParse(get_abi(input), put_abi(expectationHeaderValue), &succeeded));
    return succeeded;
}

template <typename D> void consume_Windows_Web_Http_Headers_IHttpLanguageHeaderValueCollection<D>::ParseAdd(param::hstring const& input) const
{
    check_hresult(WINRT_SHIM(Windows::Web::Http::Headers::IHttpLanguageHeaderValueCollection)->ParseAdd(get_abi(input)));
}

template <typename D> bool consume_Windows_Web_Http_Headers_IHttpLanguageHeaderValueCollection<D>::TryParseAdd(param::hstring const& input) const
{
    bool result{};
    check_hresult(WINRT_SHIM(Windows::Web::Http::Headers::IHttpLanguageHeaderValueCollection)->TryParseAdd(get_abi(input), &result));
    return result;
}

template <typename D> hstring consume_Windows_Web_Http_Headers_IHttpLanguageRangeWithQualityHeaderValue<D>::LanguageRange() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Web::Http::Headers::IHttpLanguageRangeWithQualityHeaderValue)->get_LanguageRange(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::IReference<double> consume_Windows_Web_Http_Headers_IHttpLanguageRangeWithQualityHeaderValue<D>::Quality() const
{
    Windows::Foundation::IReference<double> value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Web::Http::Headers::IHttpLanguageRangeWithQualityHeaderValue)->get_Quality(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_Web_Http_Headers_IHttpLanguageRangeWithQualityHeaderValueCollection<D>::ParseAdd(param::hstring const& input) const
{
    check_hresult(WINRT_SHIM(Windows::Web::Http::Headers::IHttpLanguageRangeWithQualityHeaderValueCollection)->ParseAdd(get_abi(input)));
}

template <typename D> bool consume_Windows_Web_Http_Headers_IHttpLanguageRangeWithQualityHeaderValueCollection<D>::TryParseAdd(param::hstring const& input) const
{
    bool result{};
    check_hresult(WINRT_SHIM(Windows::Web::Http::Headers::IHttpLanguageRangeWithQualityHeaderValueCollection)->TryParseAdd(get_abi(input), &result));
    return result;
}

template <typename D> Windows::Web::Http::Headers::HttpLanguageRangeWithQualityHeaderValue consume_Windows_Web_Http_Headers_IHttpLanguageRangeWithQualityHeaderValueFactory<D>::CreateFromLanguageRange(param::hstring const& languageRange) const
{
    Windows::Web::Http::Headers::HttpLanguageRangeWithQualityHeaderValue value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Web::Http::Headers::IHttpLanguageRangeWithQualityHeaderValueFactory)->CreateFromLanguageRange(get_abi(languageRange), put_abi(value)));
    return value;
}

template <typename D> Windows::Web::Http::Headers::HttpLanguageRangeWithQualityHeaderValue consume_Windows_Web_Http_Headers_IHttpLanguageRangeWithQualityHeaderValueFactory<D>::CreateFromLanguageRangeWithQuality(param::hstring const& languageRange, double quality) const
{
    Windows::Web::Http::Headers::HttpLanguageRangeWithQualityHeaderValue value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Web::Http::Headers::IHttpLanguageRangeWithQualityHeaderValueFactory)->CreateFromLanguageRangeWithQuality(get_abi(languageRange), quality, put_abi(value)));
    return value;
}

template <typename D> Windows::Web::Http::Headers::HttpLanguageRangeWithQualityHeaderValue consume_Windows_Web_Http_Headers_IHttpLanguageRangeWithQualityHeaderValueStatics<D>::Parse(param::hstring const& input) const
{
    Windows::Web::Http::Headers::HttpLanguageRangeWithQualityHeaderValue result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Web::Http::Headers::IHttpLanguageRangeWithQualityHeaderValueStatics)->Parse(get_abi(input), put_abi(result)));
    return result;
}

template <typename D> bool consume_Windows_Web_Http_Headers_IHttpLanguageRangeWithQualityHeaderValueStatics<D>::TryParse(param::hstring const& input, Windows::Web::Http::Headers::HttpLanguageRangeWithQualityHeaderValue& languageRangeWithQualityHeaderValue) const
{
    bool succeeded{};
    check_hresult(WINRT_SHIM(Windows::Web::Http::Headers::IHttpLanguageRangeWithQualityHeaderValueStatics)->TryParse(get_abi(input), put_abi(languageRangeWithQualityHeaderValue), &succeeded));
    return succeeded;
}

template <typename D> hstring consume_Windows_Web_Http_Headers_IHttpMediaTypeHeaderValue<D>::CharSet() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Web::Http::Headers::IHttpMediaTypeHeaderValue)->get_CharSet(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_Web_Http_Headers_IHttpMediaTypeHeaderValue<D>::CharSet(param::hstring const& value) const
{
    check_hresult(WINRT_SHIM(Windows::Web::Http::Headers::IHttpMediaTypeHeaderValue)->put_CharSet(get_abi(value)));
}

template <typename D> hstring consume_Windows_Web_Http_Headers_IHttpMediaTypeHeaderValue<D>::MediaType() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Web::Http::Headers::IHttpMediaTypeHeaderValue)->get_MediaType(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_Web_Http_Headers_IHttpMediaTypeHeaderValue<D>::MediaType(param::hstring const& value) const
{
    check_hresult(WINRT_SHIM(Windows::Web::Http::Headers::IHttpMediaTypeHeaderValue)->put_MediaType(get_abi(value)));
}

template <typename D> Windows::Foundation::Collections::IVector<Windows::Web::Http::Headers::HttpNameValueHeaderValue> consume_Windows_Web_Http_Headers_IHttpMediaTypeHeaderValue<D>::Parameters() const
{
    Windows::Foundation::Collections::IVector<Windows::Web::Http::Headers::HttpNameValueHeaderValue> value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Web::Http::Headers::IHttpMediaTypeHeaderValue)->get_Parameters(put_abi(value)));
    return value;
}

template <typename D> Windows::Web::Http::Headers::HttpMediaTypeHeaderValue consume_Windows_Web_Http_Headers_IHttpMediaTypeHeaderValueFactory<D>::Create(param::hstring const& mediaType) const
{
    Windows::Web::Http::Headers::HttpMediaTypeHeaderValue value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Web::Http::Headers::IHttpMediaTypeHeaderValueFactory)->Create(get_abi(mediaType), put_abi(value)));
    return value;
}

template <typename D> Windows::Web::Http::Headers::HttpMediaTypeHeaderValue consume_Windows_Web_Http_Headers_IHttpMediaTypeHeaderValueStatics<D>::Parse(param::hstring const& input) const
{
    Windows::Web::Http::Headers::HttpMediaTypeHeaderValue result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Web::Http::Headers::IHttpMediaTypeHeaderValueStatics)->Parse(get_abi(input), put_abi(result)));
    return result;
}

template <typename D> bool consume_Windows_Web_Http_Headers_IHttpMediaTypeHeaderValueStatics<D>::TryParse(param::hstring const& input, Windows::Web::Http::Headers::HttpMediaTypeHeaderValue& mediaTypeHeaderValue) const
{
    bool succeeded{};
    check_hresult(WINRT_SHIM(Windows::Web::Http::Headers::IHttpMediaTypeHeaderValueStatics)->TryParse(get_abi(input), put_abi(mediaTypeHeaderValue), &succeeded));
    return succeeded;
}

template <typename D> hstring consume_Windows_Web_Http_Headers_IHttpMediaTypeWithQualityHeaderValue<D>::CharSet() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Web::Http::Headers::IHttpMediaTypeWithQualityHeaderValue)->get_CharSet(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_Web_Http_Headers_IHttpMediaTypeWithQualityHeaderValue<D>::CharSet(param::hstring const& value) const
{
    check_hresult(WINRT_SHIM(Windows::Web::Http::Headers::IHttpMediaTypeWithQualityHeaderValue)->put_CharSet(get_abi(value)));
}

template <typename D> hstring consume_Windows_Web_Http_Headers_IHttpMediaTypeWithQualityHeaderValue<D>::MediaType() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Web::Http::Headers::IHttpMediaTypeWithQualityHeaderValue)->get_MediaType(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_Web_Http_Headers_IHttpMediaTypeWithQualityHeaderValue<D>::MediaType(param::hstring const& value) const
{
    check_hresult(WINRT_SHIM(Windows::Web::Http::Headers::IHttpMediaTypeWithQualityHeaderValue)->put_MediaType(get_abi(value)));
}

template <typename D> Windows::Foundation::Collections::IVector<Windows::Web::Http::Headers::HttpNameValueHeaderValue> consume_Windows_Web_Http_Headers_IHttpMediaTypeWithQualityHeaderValue<D>::Parameters() const
{
    Windows::Foundation::Collections::IVector<Windows::Web::Http::Headers::HttpNameValueHeaderValue> value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Web::Http::Headers::IHttpMediaTypeWithQualityHeaderValue)->get_Parameters(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::IReference<double> consume_Windows_Web_Http_Headers_IHttpMediaTypeWithQualityHeaderValue<D>::Quality() const
{
    Windows::Foundation::IReference<double> value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Web::Http::Headers::IHttpMediaTypeWithQualityHeaderValue)->get_Quality(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_Web_Http_Headers_IHttpMediaTypeWithQualityHeaderValue<D>::Quality(optional<double> const& value) const
{
    check_hresult(WINRT_SHIM(Windows::Web::Http::Headers::IHttpMediaTypeWithQualityHeaderValue)->put_Quality(get_abi(value)));
}

template <typename D> void consume_Windows_Web_Http_Headers_IHttpMediaTypeWithQualityHeaderValueCollection<D>::ParseAdd(param::hstring const& input) const
{
    check_hresult(WINRT_SHIM(Windows::Web::Http::Headers::IHttpMediaTypeWithQualityHeaderValueCollection)->ParseAdd(get_abi(input)));
}

template <typename D> bool consume_Windows_Web_Http_Headers_IHttpMediaTypeWithQualityHeaderValueCollection<D>::TryParseAdd(param::hstring const& input) const
{
    bool result{};
    check_hresult(WINRT_SHIM(Windows::Web::Http::Headers::IHttpMediaTypeWithQualityHeaderValueCollection)->TryParseAdd(get_abi(input), &result));
    return result;
}

template <typename D> Windows::Web::Http::Headers::HttpMediaTypeWithQualityHeaderValue consume_Windows_Web_Http_Headers_IHttpMediaTypeWithQualityHeaderValueFactory<D>::CreateFromMediaType(param::hstring const& mediaType) const
{
    Windows::Web::Http::Headers::HttpMediaTypeWithQualityHeaderValue value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Web::Http::Headers::IHttpMediaTypeWithQualityHeaderValueFactory)->CreateFromMediaType(get_abi(mediaType), put_abi(value)));
    return value;
}

template <typename D> Windows::Web::Http::Headers::HttpMediaTypeWithQualityHeaderValue consume_Windows_Web_Http_Headers_IHttpMediaTypeWithQualityHeaderValueFactory<D>::CreateFromMediaTypeWithQuality(param::hstring const& mediaType, double quality) const
{
    Windows::Web::Http::Headers::HttpMediaTypeWithQualityHeaderValue value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Web::Http::Headers::IHttpMediaTypeWithQualityHeaderValueFactory)->CreateFromMediaTypeWithQuality(get_abi(mediaType), quality, put_abi(value)));
    return value;
}

template <typename D> Windows::Web::Http::Headers::HttpMediaTypeWithQualityHeaderValue consume_Windows_Web_Http_Headers_IHttpMediaTypeWithQualityHeaderValueStatics<D>::Parse(param::hstring const& input) const
{
    Windows::Web::Http::Headers::HttpMediaTypeWithQualityHeaderValue result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Web::Http::Headers::IHttpMediaTypeWithQualityHeaderValueStatics)->Parse(get_abi(input), put_abi(result)));
    return result;
}

template <typename D> bool consume_Windows_Web_Http_Headers_IHttpMediaTypeWithQualityHeaderValueStatics<D>::TryParse(param::hstring const& input, Windows::Web::Http::Headers::HttpMediaTypeWithQualityHeaderValue& mediaTypeWithQualityHeaderValue) const
{
    bool succeeded{};
    check_hresult(WINRT_SHIM(Windows::Web::Http::Headers::IHttpMediaTypeWithQualityHeaderValueStatics)->TryParse(get_abi(input), put_abi(mediaTypeWithQualityHeaderValue), &succeeded));
    return succeeded;
}

template <typename D> void consume_Windows_Web_Http_Headers_IHttpMethodHeaderValueCollection<D>::ParseAdd(param::hstring const& input) const
{
    check_hresult(WINRT_SHIM(Windows::Web::Http::Headers::IHttpMethodHeaderValueCollection)->ParseAdd(get_abi(input)));
}

template <typename D> bool consume_Windows_Web_Http_Headers_IHttpMethodHeaderValueCollection<D>::TryParseAdd(param::hstring const& input) const
{
    bool result{};
    check_hresult(WINRT_SHIM(Windows::Web::Http::Headers::IHttpMethodHeaderValueCollection)->TryParseAdd(get_abi(input), &result));
    return result;
}

template <typename D> hstring consume_Windows_Web_Http_Headers_IHttpNameValueHeaderValue<D>::Name() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Web::Http::Headers::IHttpNameValueHeaderValue)->get_Name(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_Web_Http_Headers_IHttpNameValueHeaderValue<D>::Value() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Web::Http::Headers::IHttpNameValueHeaderValue)->get_Value(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_Web_Http_Headers_IHttpNameValueHeaderValue<D>::Value(param::hstring const& value) const
{
    check_hresult(WINRT_SHIM(Windows::Web::Http::Headers::IHttpNameValueHeaderValue)->put_Value(get_abi(value)));
}

template <typename D> Windows::Web::Http::Headers::HttpNameValueHeaderValue consume_Windows_Web_Http_Headers_IHttpNameValueHeaderValueFactory<D>::CreateFromName(param::hstring const& name) const
{
    Windows::Web::Http::Headers::HttpNameValueHeaderValue value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Web::Http::Headers::IHttpNameValueHeaderValueFactory)->CreateFromName(get_abi(name), put_abi(value)));
    return value;
}

template <typename D> Windows::Web::Http::Headers::HttpNameValueHeaderValue consume_Windows_Web_Http_Headers_IHttpNameValueHeaderValueFactory<D>::CreateFromNameWithValue(param::hstring const& name, param::hstring const& value) const
{
    Windows::Web::Http::Headers::HttpNameValueHeaderValue nameValueHeaderValue{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Web::Http::Headers::IHttpNameValueHeaderValueFactory)->CreateFromNameWithValue(get_abi(name), get_abi(value), put_abi(nameValueHeaderValue)));
    return nameValueHeaderValue;
}

template <typename D> Windows::Web::Http::Headers::HttpNameValueHeaderValue consume_Windows_Web_Http_Headers_IHttpNameValueHeaderValueStatics<D>::Parse(param::hstring const& input) const
{
    Windows::Web::Http::Headers::HttpNameValueHeaderValue result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Web::Http::Headers::IHttpNameValueHeaderValueStatics)->Parse(get_abi(input), put_abi(result)));
    return result;
}

template <typename D> bool consume_Windows_Web_Http_Headers_IHttpNameValueHeaderValueStatics<D>::TryParse(param::hstring const& input, Windows::Web::Http::Headers::HttpNameValueHeaderValue& nameValueHeaderValue) const
{
    bool succeeded{};
    check_hresult(WINRT_SHIM(Windows::Web::Http::Headers::IHttpNameValueHeaderValueStatics)->TryParse(get_abi(input), put_abi(nameValueHeaderValue), &succeeded));
    return succeeded;
}

template <typename D> hstring consume_Windows_Web_Http_Headers_IHttpProductHeaderValue<D>::Name() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Web::Http::Headers::IHttpProductHeaderValue)->get_Name(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_Web_Http_Headers_IHttpProductHeaderValue<D>::Version() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Web::Http::Headers::IHttpProductHeaderValue)->get_Version(put_abi(value)));
    return value;
}

template <typename D> Windows::Web::Http::Headers::HttpProductHeaderValue consume_Windows_Web_Http_Headers_IHttpProductHeaderValueFactory<D>::CreateFromName(param::hstring const& productName) const
{
    Windows::Web::Http::Headers::HttpProductHeaderValue value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Web::Http::Headers::IHttpProductHeaderValueFactory)->CreateFromName(get_abi(productName), put_abi(value)));
    return value;
}

template <typename D> Windows::Web::Http::Headers::HttpProductHeaderValue consume_Windows_Web_Http_Headers_IHttpProductHeaderValueFactory<D>::CreateFromNameWithVersion(param::hstring const& productName, param::hstring const& productVersion) const
{
    Windows::Web::Http::Headers::HttpProductHeaderValue value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Web::Http::Headers::IHttpProductHeaderValueFactory)->CreateFromNameWithVersion(get_abi(productName), get_abi(productVersion), put_abi(value)));
    return value;
}

template <typename D> Windows::Web::Http::Headers::HttpProductHeaderValue consume_Windows_Web_Http_Headers_IHttpProductHeaderValueStatics<D>::Parse(param::hstring const& input) const
{
    Windows::Web::Http::Headers::HttpProductHeaderValue result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Web::Http::Headers::IHttpProductHeaderValueStatics)->Parse(get_abi(input), put_abi(result)));
    return result;
}

template <typename D> bool consume_Windows_Web_Http_Headers_IHttpProductHeaderValueStatics<D>::TryParse(param::hstring const& input, Windows::Web::Http::Headers::HttpProductHeaderValue& productHeaderValue) const
{
    bool succeeded{};
    check_hresult(WINRT_SHIM(Windows::Web::Http::Headers::IHttpProductHeaderValueStatics)->TryParse(get_abi(input), put_abi(productHeaderValue), &succeeded));
    return succeeded;
}

template <typename D> Windows::Web::Http::Headers::HttpProductHeaderValue consume_Windows_Web_Http_Headers_IHttpProductInfoHeaderValue<D>::Product() const
{
    Windows::Web::Http::Headers::HttpProductHeaderValue value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Web::Http::Headers::IHttpProductInfoHeaderValue)->get_Product(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_Web_Http_Headers_IHttpProductInfoHeaderValue<D>::Comment() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Web::Http::Headers::IHttpProductInfoHeaderValue)->get_Comment(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_Web_Http_Headers_IHttpProductInfoHeaderValueCollection<D>::ParseAdd(param::hstring const& input) const
{
    check_hresult(WINRT_SHIM(Windows::Web::Http::Headers::IHttpProductInfoHeaderValueCollection)->ParseAdd(get_abi(input)));
}

template <typename D> bool consume_Windows_Web_Http_Headers_IHttpProductInfoHeaderValueCollection<D>::TryParseAdd(param::hstring const& input) const
{
    bool result{};
    check_hresult(WINRT_SHIM(Windows::Web::Http::Headers::IHttpProductInfoHeaderValueCollection)->TryParseAdd(get_abi(input), &result));
    return result;
}

template <typename D> Windows::Web::Http::Headers::HttpProductInfoHeaderValue consume_Windows_Web_Http_Headers_IHttpProductInfoHeaderValueFactory<D>::CreateFromComment(param::hstring const& productComment) const
{
    Windows::Web::Http::Headers::HttpProductInfoHeaderValue value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Web::Http::Headers::IHttpProductInfoHeaderValueFactory)->CreateFromComment(get_abi(productComment), put_abi(value)));
    return value;
}

template <typename D> Windows::Web::Http::Headers::HttpProductInfoHeaderValue consume_Windows_Web_Http_Headers_IHttpProductInfoHeaderValueFactory<D>::CreateFromNameWithVersion(param::hstring const& productName, param::hstring const& productVersion) const
{
    Windows::Web::Http::Headers::HttpProductInfoHeaderValue value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Web::Http::Headers::IHttpProductInfoHeaderValueFactory)->CreateFromNameWithVersion(get_abi(productName), get_abi(productVersion), put_abi(value)));
    return value;
}

template <typename D> Windows::Web::Http::Headers::HttpProductInfoHeaderValue consume_Windows_Web_Http_Headers_IHttpProductInfoHeaderValueStatics<D>::Parse(param::hstring const& input) const
{
    Windows::Web::Http::Headers::HttpProductInfoHeaderValue result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Web::Http::Headers::IHttpProductInfoHeaderValueStatics)->Parse(get_abi(input), put_abi(result)));
    return result;
}

template <typename D> bool consume_Windows_Web_Http_Headers_IHttpProductInfoHeaderValueStatics<D>::TryParse(param::hstring const& input, Windows::Web::Http::Headers::HttpProductInfoHeaderValue& productInfoHeaderValue) const
{
    bool succeeded{};
    check_hresult(WINRT_SHIM(Windows::Web::Http::Headers::IHttpProductInfoHeaderValueStatics)->TryParse(get_abi(input), put_abi(productInfoHeaderValue), &succeeded));
    return succeeded;
}

template <typename D> Windows::Web::Http::Headers::HttpMediaTypeWithQualityHeaderValueCollection consume_Windows_Web_Http_Headers_IHttpRequestHeaderCollection<D>::Accept() const
{
    Windows::Web::Http::Headers::HttpMediaTypeWithQualityHeaderValueCollection value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Web::Http::Headers::IHttpRequestHeaderCollection)->get_Accept(put_abi(value)));
    return value;
}

template <typename D> Windows::Web::Http::Headers::HttpContentCodingWithQualityHeaderValueCollection consume_Windows_Web_Http_Headers_IHttpRequestHeaderCollection<D>::AcceptEncoding() const
{
    Windows::Web::Http::Headers::HttpContentCodingWithQualityHeaderValueCollection value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Web::Http::Headers::IHttpRequestHeaderCollection)->get_AcceptEncoding(put_abi(value)));
    return value;
}

template <typename D> Windows::Web::Http::Headers::HttpLanguageRangeWithQualityHeaderValueCollection consume_Windows_Web_Http_Headers_IHttpRequestHeaderCollection<D>::AcceptLanguage() const
{
    Windows::Web::Http::Headers::HttpLanguageRangeWithQualityHeaderValueCollection value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Web::Http::Headers::IHttpRequestHeaderCollection)->get_AcceptLanguage(put_abi(value)));
    return value;
}

template <typename D> Windows::Web::Http::Headers::HttpCredentialsHeaderValue consume_Windows_Web_Http_Headers_IHttpRequestHeaderCollection<D>::Authorization() const
{
    Windows::Web::Http::Headers::HttpCredentialsHeaderValue value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Web::Http::Headers::IHttpRequestHeaderCollection)->get_Authorization(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_Web_Http_Headers_IHttpRequestHeaderCollection<D>::Authorization(Windows::Web::Http::Headers::HttpCredentialsHeaderValue const& value) const
{
    check_hresult(WINRT_SHIM(Windows::Web::Http::Headers::IHttpRequestHeaderCollection)->put_Authorization(get_abi(value)));
}

template <typename D> Windows::Web::Http::Headers::HttpCacheDirectiveHeaderValueCollection consume_Windows_Web_Http_Headers_IHttpRequestHeaderCollection<D>::CacheControl() const
{
    Windows::Web::Http::Headers::HttpCacheDirectiveHeaderValueCollection value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Web::Http::Headers::IHttpRequestHeaderCollection)->get_CacheControl(put_abi(value)));
    return value;
}

template <typename D> Windows::Web::Http::Headers::HttpConnectionOptionHeaderValueCollection consume_Windows_Web_Http_Headers_IHttpRequestHeaderCollection<D>::Connection() const
{
    Windows::Web::Http::Headers::HttpConnectionOptionHeaderValueCollection value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Web::Http::Headers::IHttpRequestHeaderCollection)->get_Connection(put_abi(value)));
    return value;
}

template <typename D> Windows::Web::Http::Headers::HttpCookiePairHeaderValueCollection consume_Windows_Web_Http_Headers_IHttpRequestHeaderCollection<D>::Cookie() const
{
    Windows::Web::Http::Headers::HttpCookiePairHeaderValueCollection value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Web::Http::Headers::IHttpRequestHeaderCollection)->get_Cookie(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::IReference<Windows::Foundation::DateTime> consume_Windows_Web_Http_Headers_IHttpRequestHeaderCollection<D>::Date() const
{
    Windows::Foundation::IReference<Windows::Foundation::DateTime> value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Web::Http::Headers::IHttpRequestHeaderCollection)->get_Date(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_Web_Http_Headers_IHttpRequestHeaderCollection<D>::Date(optional<Windows::Foundation::DateTime> const& value) const
{
    check_hresult(WINRT_SHIM(Windows::Web::Http::Headers::IHttpRequestHeaderCollection)->put_Date(get_abi(value)));
}

template <typename D> Windows::Web::Http::Headers::HttpExpectationHeaderValueCollection consume_Windows_Web_Http_Headers_IHttpRequestHeaderCollection<D>::Expect() const
{
    Windows::Web::Http::Headers::HttpExpectationHeaderValueCollection value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Web::Http::Headers::IHttpRequestHeaderCollection)->get_Expect(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_Web_Http_Headers_IHttpRequestHeaderCollection<D>::From() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Web::Http::Headers::IHttpRequestHeaderCollection)->get_From(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_Web_Http_Headers_IHttpRequestHeaderCollection<D>::From(param::hstring const& value) const
{
    check_hresult(WINRT_SHIM(Windows::Web::Http::Headers::IHttpRequestHeaderCollection)->put_From(get_abi(value)));
}

template <typename D> Windows::Networking::HostName consume_Windows_Web_Http_Headers_IHttpRequestHeaderCollection<D>::Host() const
{
    Windows::Networking::HostName value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Web::Http::Headers::IHttpRequestHeaderCollection)->get_Host(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_Web_Http_Headers_IHttpRequestHeaderCollection<D>::Host(Windows::Networking::HostName const& value) const
{
    check_hresult(WINRT_SHIM(Windows::Web::Http::Headers::IHttpRequestHeaderCollection)->put_Host(get_abi(value)));
}

template <typename D> Windows::Foundation::IReference<Windows::Foundation::DateTime> consume_Windows_Web_Http_Headers_IHttpRequestHeaderCollection<D>::IfModifiedSince() const
{
    Windows::Foundation::IReference<Windows::Foundation::DateTime> value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Web::Http::Headers::IHttpRequestHeaderCollection)->get_IfModifiedSince(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_Web_Http_Headers_IHttpRequestHeaderCollection<D>::IfModifiedSince(optional<Windows::Foundation::DateTime> const& value) const
{
    check_hresult(WINRT_SHIM(Windows::Web::Http::Headers::IHttpRequestHeaderCollection)->put_IfModifiedSince(get_abi(value)));
}

template <typename D> Windows::Foundation::IReference<Windows::Foundation::DateTime> consume_Windows_Web_Http_Headers_IHttpRequestHeaderCollection<D>::IfUnmodifiedSince() const
{
    Windows::Foundation::IReference<Windows::Foundation::DateTime> value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Web::Http::Headers::IHttpRequestHeaderCollection)->get_IfUnmodifiedSince(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_Web_Http_Headers_IHttpRequestHeaderCollection<D>::IfUnmodifiedSince(optional<Windows::Foundation::DateTime> const& value) const
{
    check_hresult(WINRT_SHIM(Windows::Web::Http::Headers::IHttpRequestHeaderCollection)->put_IfUnmodifiedSince(get_abi(value)));
}

template <typename D> Windows::Foundation::IReference<uint32_t> consume_Windows_Web_Http_Headers_IHttpRequestHeaderCollection<D>::MaxForwards() const
{
    Windows::Foundation::IReference<uint32_t> value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Web::Http::Headers::IHttpRequestHeaderCollection)->get_MaxForwards(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_Web_Http_Headers_IHttpRequestHeaderCollection<D>::MaxForwards(optional<uint32_t> const& value) const
{
    check_hresult(WINRT_SHIM(Windows::Web::Http::Headers::IHttpRequestHeaderCollection)->put_MaxForwards(get_abi(value)));
}

template <typename D> Windows::Web::Http::Headers::HttpCredentialsHeaderValue consume_Windows_Web_Http_Headers_IHttpRequestHeaderCollection<D>::ProxyAuthorization() const
{
    Windows::Web::Http::Headers::HttpCredentialsHeaderValue value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Web::Http::Headers::IHttpRequestHeaderCollection)->get_ProxyAuthorization(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_Web_Http_Headers_IHttpRequestHeaderCollection<D>::ProxyAuthorization(Windows::Web::Http::Headers::HttpCredentialsHeaderValue const& value) const
{
    check_hresult(WINRT_SHIM(Windows::Web::Http::Headers::IHttpRequestHeaderCollection)->put_ProxyAuthorization(get_abi(value)));
}

template <typename D> Windows::Foundation::Uri consume_Windows_Web_Http_Headers_IHttpRequestHeaderCollection<D>::Referer() const
{
    Windows::Foundation::Uri value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Web::Http::Headers::IHttpRequestHeaderCollection)->get_Referer(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_Web_Http_Headers_IHttpRequestHeaderCollection<D>::Referer(Windows::Foundation::Uri const& value) const
{
    check_hresult(WINRT_SHIM(Windows::Web::Http::Headers::IHttpRequestHeaderCollection)->put_Referer(get_abi(value)));
}

template <typename D> Windows::Web::Http::Headers::HttpTransferCodingHeaderValueCollection consume_Windows_Web_Http_Headers_IHttpRequestHeaderCollection<D>::TransferEncoding() const
{
    Windows::Web::Http::Headers::HttpTransferCodingHeaderValueCollection value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Web::Http::Headers::IHttpRequestHeaderCollection)->get_TransferEncoding(put_abi(value)));
    return value;
}

template <typename D> Windows::Web::Http::Headers::HttpProductInfoHeaderValueCollection consume_Windows_Web_Http_Headers_IHttpRequestHeaderCollection<D>::UserAgent() const
{
    Windows::Web::Http::Headers::HttpProductInfoHeaderValueCollection value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Web::Http::Headers::IHttpRequestHeaderCollection)->get_UserAgent(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_Web_Http_Headers_IHttpRequestHeaderCollection<D>::Append(param::hstring const& name, param::hstring const& value) const
{
    check_hresult(WINRT_SHIM(Windows::Web::Http::Headers::IHttpRequestHeaderCollection)->Append(get_abi(name), get_abi(value)));
}

template <typename D> bool consume_Windows_Web_Http_Headers_IHttpRequestHeaderCollection<D>::TryAppendWithoutValidation(param::hstring const& name, param::hstring const& value) const
{
    bool result{};
    check_hresult(WINRT_SHIM(Windows::Web::Http::Headers::IHttpRequestHeaderCollection)->TryAppendWithoutValidation(get_abi(name), get_abi(value), &result));
    return result;
}

template <typename D> Windows::Foundation::IReference<Windows::Foundation::TimeSpan> consume_Windows_Web_Http_Headers_IHttpResponseHeaderCollection<D>::Age() const
{
    Windows::Foundation::IReference<Windows::Foundation::TimeSpan> value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Web::Http::Headers::IHttpResponseHeaderCollection)->get_Age(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_Web_Http_Headers_IHttpResponseHeaderCollection<D>::Age(optional<Windows::Foundation::TimeSpan> const& value) const
{
    check_hresult(WINRT_SHIM(Windows::Web::Http::Headers::IHttpResponseHeaderCollection)->put_Age(get_abi(value)));
}

template <typename D> Windows::Web::Http::Headers::HttpMethodHeaderValueCollection consume_Windows_Web_Http_Headers_IHttpResponseHeaderCollection<D>::Allow() const
{
    Windows::Web::Http::Headers::HttpMethodHeaderValueCollection value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Web::Http::Headers::IHttpResponseHeaderCollection)->get_Allow(put_abi(value)));
    return value;
}

template <typename D> Windows::Web::Http::Headers::HttpCacheDirectiveHeaderValueCollection consume_Windows_Web_Http_Headers_IHttpResponseHeaderCollection<D>::CacheControl() const
{
    Windows::Web::Http::Headers::HttpCacheDirectiveHeaderValueCollection value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Web::Http::Headers::IHttpResponseHeaderCollection)->get_CacheControl(put_abi(value)));
    return value;
}

template <typename D> Windows::Web::Http::Headers::HttpConnectionOptionHeaderValueCollection consume_Windows_Web_Http_Headers_IHttpResponseHeaderCollection<D>::Connection() const
{
    Windows::Web::Http::Headers::HttpConnectionOptionHeaderValueCollection value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Web::Http::Headers::IHttpResponseHeaderCollection)->get_Connection(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::IReference<Windows::Foundation::DateTime> consume_Windows_Web_Http_Headers_IHttpResponseHeaderCollection<D>::Date() const
{
    Windows::Foundation::IReference<Windows::Foundation::DateTime> value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Web::Http::Headers::IHttpResponseHeaderCollection)->get_Date(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_Web_Http_Headers_IHttpResponseHeaderCollection<D>::Date(optional<Windows::Foundation::DateTime> const& value) const
{
    check_hresult(WINRT_SHIM(Windows::Web::Http::Headers::IHttpResponseHeaderCollection)->put_Date(get_abi(value)));
}

template <typename D> Windows::Foundation::Uri consume_Windows_Web_Http_Headers_IHttpResponseHeaderCollection<D>::Location() const
{
    Windows::Foundation::Uri value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Web::Http::Headers::IHttpResponseHeaderCollection)->get_Location(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_Web_Http_Headers_IHttpResponseHeaderCollection<D>::Location(Windows::Foundation::Uri const& value) const
{
    check_hresult(WINRT_SHIM(Windows::Web::Http::Headers::IHttpResponseHeaderCollection)->put_Location(get_abi(value)));
}

template <typename D> Windows::Web::Http::Headers::HttpChallengeHeaderValueCollection consume_Windows_Web_Http_Headers_IHttpResponseHeaderCollection<D>::ProxyAuthenticate() const
{
    Windows::Web::Http::Headers::HttpChallengeHeaderValueCollection value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Web::Http::Headers::IHttpResponseHeaderCollection)->get_ProxyAuthenticate(put_abi(value)));
    return value;
}

template <typename D> Windows::Web::Http::Headers::HttpDateOrDeltaHeaderValue consume_Windows_Web_Http_Headers_IHttpResponseHeaderCollection<D>::RetryAfter() const
{
    Windows::Web::Http::Headers::HttpDateOrDeltaHeaderValue value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Web::Http::Headers::IHttpResponseHeaderCollection)->get_RetryAfter(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_Web_Http_Headers_IHttpResponseHeaderCollection<D>::RetryAfter(Windows::Web::Http::Headers::HttpDateOrDeltaHeaderValue const& value) const
{
    check_hresult(WINRT_SHIM(Windows::Web::Http::Headers::IHttpResponseHeaderCollection)->put_RetryAfter(get_abi(value)));
}

template <typename D> Windows::Web::Http::Headers::HttpTransferCodingHeaderValueCollection consume_Windows_Web_Http_Headers_IHttpResponseHeaderCollection<D>::TransferEncoding() const
{
    Windows::Web::Http::Headers::HttpTransferCodingHeaderValueCollection value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Web::Http::Headers::IHttpResponseHeaderCollection)->get_TransferEncoding(put_abi(value)));
    return value;
}

template <typename D> Windows::Web::Http::Headers::HttpChallengeHeaderValueCollection consume_Windows_Web_Http_Headers_IHttpResponseHeaderCollection<D>::WwwAuthenticate() const
{
    Windows::Web::Http::Headers::HttpChallengeHeaderValueCollection value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Web::Http::Headers::IHttpResponseHeaderCollection)->get_WwwAuthenticate(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_Web_Http_Headers_IHttpResponseHeaderCollection<D>::Append(param::hstring const& name, param::hstring const& value) const
{
    check_hresult(WINRT_SHIM(Windows::Web::Http::Headers::IHttpResponseHeaderCollection)->Append(get_abi(name), get_abi(value)));
}

template <typename D> bool consume_Windows_Web_Http_Headers_IHttpResponseHeaderCollection<D>::TryAppendWithoutValidation(param::hstring const& name, param::hstring const& value) const
{
    bool result{};
    check_hresult(WINRT_SHIM(Windows::Web::Http::Headers::IHttpResponseHeaderCollection)->TryAppendWithoutValidation(get_abi(name), get_abi(value), &result));
    return result;
}

template <typename D> Windows::Foundation::Collections::IVector<Windows::Web::Http::Headers::HttpNameValueHeaderValue> consume_Windows_Web_Http_Headers_IHttpTransferCodingHeaderValue<D>::Parameters() const
{
    Windows::Foundation::Collections::IVector<Windows::Web::Http::Headers::HttpNameValueHeaderValue> value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Web::Http::Headers::IHttpTransferCodingHeaderValue)->get_Parameters(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_Web_Http_Headers_IHttpTransferCodingHeaderValue<D>::Value() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Web::Http::Headers::IHttpTransferCodingHeaderValue)->get_Value(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_Web_Http_Headers_IHttpTransferCodingHeaderValueCollection<D>::ParseAdd(param::hstring const& input) const
{
    check_hresult(WINRT_SHIM(Windows::Web::Http::Headers::IHttpTransferCodingHeaderValueCollection)->ParseAdd(get_abi(input)));
}

template <typename D> bool consume_Windows_Web_Http_Headers_IHttpTransferCodingHeaderValueCollection<D>::TryParseAdd(param::hstring const& input) const
{
    bool result{};
    check_hresult(WINRT_SHIM(Windows::Web::Http::Headers::IHttpTransferCodingHeaderValueCollection)->TryParseAdd(get_abi(input), &result));
    return result;
}

template <typename D> Windows::Web::Http::Headers::HttpTransferCodingHeaderValue consume_Windows_Web_Http_Headers_IHttpTransferCodingHeaderValueFactory<D>::Create(param::hstring const& input) const
{
    Windows::Web::Http::Headers::HttpTransferCodingHeaderValue value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Web::Http::Headers::IHttpTransferCodingHeaderValueFactory)->Create(get_abi(input), put_abi(value)));
    return value;
}

template <typename D> Windows::Web::Http::Headers::HttpTransferCodingHeaderValue consume_Windows_Web_Http_Headers_IHttpTransferCodingHeaderValueStatics<D>::Parse(param::hstring const& input) const
{
    Windows::Web::Http::Headers::HttpTransferCodingHeaderValue result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Web::Http::Headers::IHttpTransferCodingHeaderValueStatics)->Parse(get_abi(input), put_abi(result)));
    return result;
}

template <typename D> bool consume_Windows_Web_Http_Headers_IHttpTransferCodingHeaderValueStatics<D>::TryParse(param::hstring const& input, Windows::Web::Http::Headers::HttpTransferCodingHeaderValue& transferCodingHeaderValue) const
{
    bool succeeded{};
    check_hresult(WINRT_SHIM(Windows::Web::Http::Headers::IHttpTransferCodingHeaderValueStatics)->TryParse(get_abi(input), put_abi(transferCodingHeaderValue), &succeeded));
    return succeeded;
}

template <typename D>
struct produce<D, Windows::Web::Http::Headers::IHttpCacheDirectiveHeaderValueCollection> : produce_base<D, Windows::Web::Http::Headers::IHttpCacheDirectiveHeaderValueCollection>
{
    int32_t WINRT_CALL get_MaxAge(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(MaxAge, WINRT_WRAP(Windows::Foundation::IReference<Windows::Foundation::TimeSpan>));
            *value = detach_from<Windows::Foundation::IReference<Windows::Foundation::TimeSpan>>(this->shim().MaxAge());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_MaxAge(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(MaxAge, WINRT_WRAP(void), Windows::Foundation::IReference<Windows::Foundation::TimeSpan> const&);
            this->shim().MaxAge(*reinterpret_cast<Windows::Foundation::IReference<Windows::Foundation::TimeSpan> const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_MaxStale(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(MaxStale, WINRT_WRAP(Windows::Foundation::IReference<Windows::Foundation::TimeSpan>));
            *value = detach_from<Windows::Foundation::IReference<Windows::Foundation::TimeSpan>>(this->shim().MaxStale());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_MaxStale(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(MaxStale, WINRT_WRAP(void), Windows::Foundation::IReference<Windows::Foundation::TimeSpan> const&);
            this->shim().MaxStale(*reinterpret_cast<Windows::Foundation::IReference<Windows::Foundation::TimeSpan> const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_MinFresh(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(MinFresh, WINRT_WRAP(Windows::Foundation::IReference<Windows::Foundation::TimeSpan>));
            *value = detach_from<Windows::Foundation::IReference<Windows::Foundation::TimeSpan>>(this->shim().MinFresh());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_MinFresh(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(MinFresh, WINRT_WRAP(void), Windows::Foundation::IReference<Windows::Foundation::TimeSpan> const&);
            this->shim().MinFresh(*reinterpret_cast<Windows::Foundation::IReference<Windows::Foundation::TimeSpan> const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_SharedMaxAge(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SharedMaxAge, WINRT_WRAP(Windows::Foundation::IReference<Windows::Foundation::TimeSpan>));
            *value = detach_from<Windows::Foundation::IReference<Windows::Foundation::TimeSpan>>(this->shim().SharedMaxAge());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_SharedMaxAge(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SharedMaxAge, WINRT_WRAP(void), Windows::Foundation::IReference<Windows::Foundation::TimeSpan> const&);
            this->shim().SharedMaxAge(*reinterpret_cast<Windows::Foundation::IReference<Windows::Foundation::TimeSpan> const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL ParseAdd(void* input) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ParseAdd, WINRT_WRAP(void), hstring const&);
            this->shim().ParseAdd(*reinterpret_cast<hstring const*>(&input));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL TryParseAdd(void* input, bool* result) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(TryParseAdd, WINRT_WRAP(bool), hstring const&);
            *result = detach_from<bool>(this->shim().TryParseAdd(*reinterpret_cast<hstring const*>(&input)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Web::Http::Headers::IHttpChallengeHeaderValue> : produce_base<D, Windows::Web::Http::Headers::IHttpChallengeHeaderValue>
{
    int32_t WINRT_CALL get_Parameters(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Parameters, WINRT_WRAP(Windows::Foundation::Collections::IVector<Windows::Web::Http::Headers::HttpNameValueHeaderValue>));
            *value = detach_from<Windows::Foundation::Collections::IVector<Windows::Web::Http::Headers::HttpNameValueHeaderValue>>(this->shim().Parameters());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Scheme(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Scheme, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().Scheme());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Token(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Token, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().Token());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Web::Http::Headers::IHttpChallengeHeaderValueCollection> : produce_base<D, Windows::Web::Http::Headers::IHttpChallengeHeaderValueCollection>
{
    int32_t WINRT_CALL ParseAdd(void* input) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ParseAdd, WINRT_WRAP(void), hstring const&);
            this->shim().ParseAdd(*reinterpret_cast<hstring const*>(&input));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL TryParseAdd(void* input, bool* result) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(TryParseAdd, WINRT_WRAP(bool), hstring const&);
            *result = detach_from<bool>(this->shim().TryParseAdd(*reinterpret_cast<hstring const*>(&input)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Web::Http::Headers::IHttpChallengeHeaderValueFactory> : produce_base<D, Windows::Web::Http::Headers::IHttpChallengeHeaderValueFactory>
{
    int32_t WINRT_CALL CreateFromScheme(void* scheme, void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CreateFromScheme, WINRT_WRAP(Windows::Web::Http::Headers::HttpChallengeHeaderValue), hstring const&);
            *value = detach_from<Windows::Web::Http::Headers::HttpChallengeHeaderValue>(this->shim().CreateFromScheme(*reinterpret_cast<hstring const*>(&scheme)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL CreateFromSchemeWithToken(void* scheme, void* token, void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CreateFromSchemeWithToken, WINRT_WRAP(Windows::Web::Http::Headers::HttpChallengeHeaderValue), hstring const&, hstring const&);
            *value = detach_from<Windows::Web::Http::Headers::HttpChallengeHeaderValue>(this->shim().CreateFromSchemeWithToken(*reinterpret_cast<hstring const*>(&scheme), *reinterpret_cast<hstring const*>(&token)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Web::Http::Headers::IHttpChallengeHeaderValueStatics> : produce_base<D, Windows::Web::Http::Headers::IHttpChallengeHeaderValueStatics>
{
    int32_t WINRT_CALL Parse(void* input, void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Parse, WINRT_WRAP(Windows::Web::Http::Headers::HttpChallengeHeaderValue), hstring const&);
            *result = detach_from<Windows::Web::Http::Headers::HttpChallengeHeaderValue>(this->shim().Parse(*reinterpret_cast<hstring const*>(&input)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL TryParse(void* input, void** challengeHeaderValue, bool* succeeded) noexcept final
    {
        try
        {
            *challengeHeaderValue = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(TryParse, WINRT_WRAP(bool), hstring const&, Windows::Web::Http::Headers::HttpChallengeHeaderValue&);
            *succeeded = detach_from<bool>(this->shim().TryParse(*reinterpret_cast<hstring const*>(&input), *reinterpret_cast<Windows::Web::Http::Headers::HttpChallengeHeaderValue*>(challengeHeaderValue)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Web::Http::Headers::IHttpConnectionOptionHeaderValue> : produce_base<D, Windows::Web::Http::Headers::IHttpConnectionOptionHeaderValue>
{
    int32_t WINRT_CALL get_Token(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Token, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().Token());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Web::Http::Headers::IHttpConnectionOptionHeaderValueCollection> : produce_base<D, Windows::Web::Http::Headers::IHttpConnectionOptionHeaderValueCollection>
{
    int32_t WINRT_CALL ParseAdd(void* input) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ParseAdd, WINRT_WRAP(void), hstring const&);
            this->shim().ParseAdd(*reinterpret_cast<hstring const*>(&input));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL TryParseAdd(void* input, bool* result) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(TryParseAdd, WINRT_WRAP(bool), hstring const&);
            *result = detach_from<bool>(this->shim().TryParseAdd(*reinterpret_cast<hstring const*>(&input)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Web::Http::Headers::IHttpConnectionOptionHeaderValueFactory> : produce_base<D, Windows::Web::Http::Headers::IHttpConnectionOptionHeaderValueFactory>
{
    int32_t WINRT_CALL Create(void* token, void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Create, WINRT_WRAP(Windows::Web::Http::Headers::HttpConnectionOptionHeaderValue), hstring const&);
            *value = detach_from<Windows::Web::Http::Headers::HttpConnectionOptionHeaderValue>(this->shim().Create(*reinterpret_cast<hstring const*>(&token)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Web::Http::Headers::IHttpConnectionOptionHeaderValueStatics> : produce_base<D, Windows::Web::Http::Headers::IHttpConnectionOptionHeaderValueStatics>
{
    int32_t WINRT_CALL Parse(void* input, void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Parse, WINRT_WRAP(Windows::Web::Http::Headers::HttpConnectionOptionHeaderValue), hstring const&);
            *result = detach_from<Windows::Web::Http::Headers::HttpConnectionOptionHeaderValue>(this->shim().Parse(*reinterpret_cast<hstring const*>(&input)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL TryParse(void* input, void** connectionOptionHeaderValue, bool* succeeded) noexcept final
    {
        try
        {
            *connectionOptionHeaderValue = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(TryParse, WINRT_WRAP(bool), hstring const&, Windows::Web::Http::Headers::HttpConnectionOptionHeaderValue&);
            *succeeded = detach_from<bool>(this->shim().TryParse(*reinterpret_cast<hstring const*>(&input), *reinterpret_cast<Windows::Web::Http::Headers::HttpConnectionOptionHeaderValue*>(connectionOptionHeaderValue)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Web::Http::Headers::IHttpContentCodingHeaderValue> : produce_base<D, Windows::Web::Http::Headers::IHttpContentCodingHeaderValue>
{
    int32_t WINRT_CALL get_ContentCoding(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ContentCoding, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().ContentCoding());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Web::Http::Headers::IHttpContentCodingHeaderValueCollection> : produce_base<D, Windows::Web::Http::Headers::IHttpContentCodingHeaderValueCollection>
{
    int32_t WINRT_CALL ParseAdd(void* input) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ParseAdd, WINRT_WRAP(void), hstring const&);
            this->shim().ParseAdd(*reinterpret_cast<hstring const*>(&input));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL TryParseAdd(void* input, bool* result) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(TryParseAdd, WINRT_WRAP(bool), hstring const&);
            *result = detach_from<bool>(this->shim().TryParseAdd(*reinterpret_cast<hstring const*>(&input)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Web::Http::Headers::IHttpContentCodingHeaderValueFactory> : produce_base<D, Windows::Web::Http::Headers::IHttpContentCodingHeaderValueFactory>
{
    int32_t WINRT_CALL Create(void* contentCoding, void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Create, WINRT_WRAP(Windows::Web::Http::Headers::HttpContentCodingHeaderValue), hstring const&);
            *value = detach_from<Windows::Web::Http::Headers::HttpContentCodingHeaderValue>(this->shim().Create(*reinterpret_cast<hstring const*>(&contentCoding)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Web::Http::Headers::IHttpContentCodingHeaderValueStatics> : produce_base<D, Windows::Web::Http::Headers::IHttpContentCodingHeaderValueStatics>
{
    int32_t WINRT_CALL Parse(void* input, void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Parse, WINRT_WRAP(Windows::Web::Http::Headers::HttpContentCodingHeaderValue), hstring const&);
            *result = detach_from<Windows::Web::Http::Headers::HttpContentCodingHeaderValue>(this->shim().Parse(*reinterpret_cast<hstring const*>(&input)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL TryParse(void* input, void** contentCodingHeaderValue, bool* succeeded) noexcept final
    {
        try
        {
            *contentCodingHeaderValue = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(TryParse, WINRT_WRAP(bool), hstring const&, Windows::Web::Http::Headers::HttpContentCodingHeaderValue&);
            *succeeded = detach_from<bool>(this->shim().TryParse(*reinterpret_cast<hstring const*>(&input), *reinterpret_cast<Windows::Web::Http::Headers::HttpContentCodingHeaderValue*>(contentCodingHeaderValue)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Web::Http::Headers::IHttpContentCodingWithQualityHeaderValue> : produce_base<D, Windows::Web::Http::Headers::IHttpContentCodingWithQualityHeaderValue>
{
    int32_t WINRT_CALL get_ContentCoding(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ContentCoding, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().ContentCoding());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Quality(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Quality, WINRT_WRAP(Windows::Foundation::IReference<double>));
            *value = detach_from<Windows::Foundation::IReference<double>>(this->shim().Quality());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Web::Http::Headers::IHttpContentCodingWithQualityHeaderValueCollection> : produce_base<D, Windows::Web::Http::Headers::IHttpContentCodingWithQualityHeaderValueCollection>
{
    int32_t WINRT_CALL ParseAdd(void* input) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ParseAdd, WINRT_WRAP(void), hstring const&);
            this->shim().ParseAdd(*reinterpret_cast<hstring const*>(&input));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL TryParseAdd(void* input, bool* result) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(TryParseAdd, WINRT_WRAP(bool), hstring const&);
            *result = detach_from<bool>(this->shim().TryParseAdd(*reinterpret_cast<hstring const*>(&input)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Web::Http::Headers::IHttpContentCodingWithQualityHeaderValueFactory> : produce_base<D, Windows::Web::Http::Headers::IHttpContentCodingWithQualityHeaderValueFactory>
{
    int32_t WINRT_CALL CreateFromValue(void* contentCoding, void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CreateFromValue, WINRT_WRAP(Windows::Web::Http::Headers::HttpContentCodingWithQualityHeaderValue), hstring const&);
            *value = detach_from<Windows::Web::Http::Headers::HttpContentCodingWithQualityHeaderValue>(this->shim().CreateFromValue(*reinterpret_cast<hstring const*>(&contentCoding)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL CreateFromValueWithQuality(void* contentCoding, double quality, void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CreateFromValueWithQuality, WINRT_WRAP(Windows::Web::Http::Headers::HttpContentCodingWithQualityHeaderValue), hstring const&, double);
            *value = detach_from<Windows::Web::Http::Headers::HttpContentCodingWithQualityHeaderValue>(this->shim().CreateFromValueWithQuality(*reinterpret_cast<hstring const*>(&contentCoding), quality));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Web::Http::Headers::IHttpContentCodingWithQualityHeaderValueStatics> : produce_base<D, Windows::Web::Http::Headers::IHttpContentCodingWithQualityHeaderValueStatics>
{
    int32_t WINRT_CALL Parse(void* input, void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Parse, WINRT_WRAP(Windows::Web::Http::Headers::HttpContentCodingWithQualityHeaderValue), hstring const&);
            *result = detach_from<Windows::Web::Http::Headers::HttpContentCodingWithQualityHeaderValue>(this->shim().Parse(*reinterpret_cast<hstring const*>(&input)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL TryParse(void* input, void** contentCodingWithQualityHeaderValue, bool* succeeded) noexcept final
    {
        try
        {
            *contentCodingWithQualityHeaderValue = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(TryParse, WINRT_WRAP(bool), hstring const&, Windows::Web::Http::Headers::HttpContentCodingWithQualityHeaderValue&);
            *succeeded = detach_from<bool>(this->shim().TryParse(*reinterpret_cast<hstring const*>(&input), *reinterpret_cast<Windows::Web::Http::Headers::HttpContentCodingWithQualityHeaderValue*>(contentCodingWithQualityHeaderValue)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Web::Http::Headers::IHttpContentDispositionHeaderValue> : produce_base<D, Windows::Web::Http::Headers::IHttpContentDispositionHeaderValue>
{
    int32_t WINRT_CALL get_DispositionType(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(DispositionType, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().DispositionType());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_DispositionType(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(DispositionType, WINRT_WRAP(void), hstring const&);
            this->shim().DispositionType(*reinterpret_cast<hstring const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_FileName(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(FileName, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().FileName());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_FileName(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(FileName, WINRT_WRAP(void), hstring const&);
            this->shim().FileName(*reinterpret_cast<hstring const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_FileNameStar(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(FileNameStar, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().FileNameStar());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_FileNameStar(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(FileNameStar, WINRT_WRAP(void), hstring const&);
            this->shim().FileNameStar(*reinterpret_cast<hstring const*>(&value));
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

    int32_t WINRT_CALL get_Parameters(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Parameters, WINRT_WRAP(Windows::Foundation::Collections::IVector<Windows::Web::Http::Headers::HttpNameValueHeaderValue>));
            *value = detach_from<Windows::Foundation::Collections::IVector<Windows::Web::Http::Headers::HttpNameValueHeaderValue>>(this->shim().Parameters());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Size(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Size, WINRT_WRAP(Windows::Foundation::IReference<uint64_t>));
            *value = detach_from<Windows::Foundation::IReference<uint64_t>>(this->shim().Size());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_Size(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Size, WINRT_WRAP(void), Windows::Foundation::IReference<uint64_t> const&);
            this->shim().Size(*reinterpret_cast<Windows::Foundation::IReference<uint64_t> const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Web::Http::Headers::IHttpContentDispositionHeaderValueFactory> : produce_base<D, Windows::Web::Http::Headers::IHttpContentDispositionHeaderValueFactory>
{
    int32_t WINRT_CALL Create(void* dispositionType, void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Create, WINRT_WRAP(Windows::Web::Http::Headers::HttpContentDispositionHeaderValue), hstring const&);
            *value = detach_from<Windows::Web::Http::Headers::HttpContentDispositionHeaderValue>(this->shim().Create(*reinterpret_cast<hstring const*>(&dispositionType)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Web::Http::Headers::IHttpContentDispositionHeaderValueStatics> : produce_base<D, Windows::Web::Http::Headers::IHttpContentDispositionHeaderValueStatics>
{
    int32_t WINRT_CALL Parse(void* input, void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Parse, WINRT_WRAP(Windows::Web::Http::Headers::HttpContentDispositionHeaderValue), hstring const&);
            *result = detach_from<Windows::Web::Http::Headers::HttpContentDispositionHeaderValue>(this->shim().Parse(*reinterpret_cast<hstring const*>(&input)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL TryParse(void* input, void** contentDispositionHeaderValue, bool* succeeded) noexcept final
    {
        try
        {
            *contentDispositionHeaderValue = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(TryParse, WINRT_WRAP(bool), hstring const&, Windows::Web::Http::Headers::HttpContentDispositionHeaderValue&);
            *succeeded = detach_from<bool>(this->shim().TryParse(*reinterpret_cast<hstring const*>(&input), *reinterpret_cast<Windows::Web::Http::Headers::HttpContentDispositionHeaderValue*>(contentDispositionHeaderValue)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Web::Http::Headers::IHttpContentHeaderCollection> : produce_base<D, Windows::Web::Http::Headers::IHttpContentHeaderCollection>
{
    int32_t WINRT_CALL get_ContentDisposition(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ContentDisposition, WINRT_WRAP(Windows::Web::Http::Headers::HttpContentDispositionHeaderValue));
            *value = detach_from<Windows::Web::Http::Headers::HttpContentDispositionHeaderValue>(this->shim().ContentDisposition());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_ContentDisposition(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ContentDisposition, WINRT_WRAP(void), Windows::Web::Http::Headers::HttpContentDispositionHeaderValue const&);
            this->shim().ContentDisposition(*reinterpret_cast<Windows::Web::Http::Headers::HttpContentDispositionHeaderValue const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_ContentEncoding(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ContentEncoding, WINRT_WRAP(Windows::Web::Http::Headers::HttpContentCodingHeaderValueCollection));
            *value = detach_from<Windows::Web::Http::Headers::HttpContentCodingHeaderValueCollection>(this->shim().ContentEncoding());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_ContentLanguage(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ContentLanguage, WINRT_WRAP(Windows::Web::Http::Headers::HttpLanguageHeaderValueCollection));
            *value = detach_from<Windows::Web::Http::Headers::HttpLanguageHeaderValueCollection>(this->shim().ContentLanguage());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_ContentLength(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ContentLength, WINRT_WRAP(Windows::Foundation::IReference<uint64_t>));
            *value = detach_from<Windows::Foundation::IReference<uint64_t>>(this->shim().ContentLength());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_ContentLength(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ContentLength, WINRT_WRAP(void), Windows::Foundation::IReference<uint64_t> const&);
            this->shim().ContentLength(*reinterpret_cast<Windows::Foundation::IReference<uint64_t> const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_ContentLocation(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ContentLocation, WINRT_WRAP(Windows::Foundation::Uri));
            *value = detach_from<Windows::Foundation::Uri>(this->shim().ContentLocation());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_ContentLocation(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ContentLocation, WINRT_WRAP(void), Windows::Foundation::Uri const&);
            this->shim().ContentLocation(*reinterpret_cast<Windows::Foundation::Uri const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_ContentMD5(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ContentMD5, WINRT_WRAP(Windows::Storage::Streams::IBuffer));
            *value = detach_from<Windows::Storage::Streams::IBuffer>(this->shim().ContentMD5());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_ContentMD5(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ContentMD5, WINRT_WRAP(void), Windows::Storage::Streams::IBuffer const&);
            this->shim().ContentMD5(*reinterpret_cast<Windows::Storage::Streams::IBuffer const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_ContentRange(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ContentRange, WINRT_WRAP(Windows::Web::Http::Headers::HttpContentRangeHeaderValue));
            *value = detach_from<Windows::Web::Http::Headers::HttpContentRangeHeaderValue>(this->shim().ContentRange());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_ContentRange(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ContentRange, WINRT_WRAP(void), Windows::Web::Http::Headers::HttpContentRangeHeaderValue const&);
            this->shim().ContentRange(*reinterpret_cast<Windows::Web::Http::Headers::HttpContentRangeHeaderValue const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_ContentType(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ContentType, WINRT_WRAP(Windows::Web::Http::Headers::HttpMediaTypeHeaderValue));
            *value = detach_from<Windows::Web::Http::Headers::HttpMediaTypeHeaderValue>(this->shim().ContentType());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_ContentType(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ContentType, WINRT_WRAP(void), Windows::Web::Http::Headers::HttpMediaTypeHeaderValue const&);
            this->shim().ContentType(*reinterpret_cast<Windows::Web::Http::Headers::HttpMediaTypeHeaderValue const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Expires(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Expires, WINRT_WRAP(Windows::Foundation::IReference<Windows::Foundation::DateTime>));
            *value = detach_from<Windows::Foundation::IReference<Windows::Foundation::DateTime>>(this->shim().Expires());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_Expires(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Expires, WINRT_WRAP(void), Windows::Foundation::IReference<Windows::Foundation::DateTime> const&);
            this->shim().Expires(*reinterpret_cast<Windows::Foundation::IReference<Windows::Foundation::DateTime> const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_LastModified(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(LastModified, WINRT_WRAP(Windows::Foundation::IReference<Windows::Foundation::DateTime>));
            *value = detach_from<Windows::Foundation::IReference<Windows::Foundation::DateTime>>(this->shim().LastModified());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_LastModified(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(LastModified, WINRT_WRAP(void), Windows::Foundation::IReference<Windows::Foundation::DateTime> const&);
            this->shim().LastModified(*reinterpret_cast<Windows::Foundation::IReference<Windows::Foundation::DateTime> const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL Append(void* name, void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Append, WINRT_WRAP(void), hstring const&, hstring const&);
            this->shim().Append(*reinterpret_cast<hstring const*>(&name), *reinterpret_cast<hstring const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL TryAppendWithoutValidation(void* name, void* value, bool* result) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(TryAppendWithoutValidation, WINRT_WRAP(bool), hstring const&, hstring const&);
            *result = detach_from<bool>(this->shim().TryAppendWithoutValidation(*reinterpret_cast<hstring const*>(&name), *reinterpret_cast<hstring const*>(&value)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Web::Http::Headers::IHttpContentRangeHeaderValue> : produce_base<D, Windows::Web::Http::Headers::IHttpContentRangeHeaderValue>
{
    int32_t WINRT_CALL get_FirstBytePosition(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(FirstBytePosition, WINRT_WRAP(Windows::Foundation::IReference<uint64_t>));
            *value = detach_from<Windows::Foundation::IReference<uint64_t>>(this->shim().FirstBytePosition());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_LastBytePosition(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(LastBytePosition, WINRT_WRAP(Windows::Foundation::IReference<uint64_t>));
            *value = detach_from<Windows::Foundation::IReference<uint64_t>>(this->shim().LastBytePosition());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Length(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Length, WINRT_WRAP(Windows::Foundation::IReference<uint64_t>));
            *value = detach_from<Windows::Foundation::IReference<uint64_t>>(this->shim().Length());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Unit(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Unit, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().Unit());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_Unit(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Unit, WINRT_WRAP(void), hstring const&);
            this->shim().Unit(*reinterpret_cast<hstring const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Web::Http::Headers::IHttpContentRangeHeaderValueFactory> : produce_base<D, Windows::Web::Http::Headers::IHttpContentRangeHeaderValueFactory>
{
    int32_t WINRT_CALL CreateFromLength(uint64_t length, void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CreateFromLength, WINRT_WRAP(Windows::Web::Http::Headers::HttpContentRangeHeaderValue), uint64_t);
            *value = detach_from<Windows::Web::Http::Headers::HttpContentRangeHeaderValue>(this->shim().CreateFromLength(length));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL CreateFromRange(uint64_t from, uint64_t to, void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CreateFromRange, WINRT_WRAP(Windows::Web::Http::Headers::HttpContentRangeHeaderValue), uint64_t, uint64_t);
            *value = detach_from<Windows::Web::Http::Headers::HttpContentRangeHeaderValue>(this->shim().CreateFromRange(from, to));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL CreateFromRangeWithLength(uint64_t from, uint64_t to, uint64_t length, void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CreateFromRangeWithLength, WINRT_WRAP(Windows::Web::Http::Headers::HttpContentRangeHeaderValue), uint64_t, uint64_t, uint64_t);
            *value = detach_from<Windows::Web::Http::Headers::HttpContentRangeHeaderValue>(this->shim().CreateFromRangeWithLength(from, to, length));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Web::Http::Headers::IHttpContentRangeHeaderValueStatics> : produce_base<D, Windows::Web::Http::Headers::IHttpContentRangeHeaderValueStatics>
{
    int32_t WINRT_CALL Parse(void* input, void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Parse, WINRT_WRAP(Windows::Web::Http::Headers::HttpContentRangeHeaderValue), hstring const&);
            *result = detach_from<Windows::Web::Http::Headers::HttpContentRangeHeaderValue>(this->shim().Parse(*reinterpret_cast<hstring const*>(&input)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL TryParse(void* input, void** contentRangeHeaderValue, bool* succeeded) noexcept final
    {
        try
        {
            *contentRangeHeaderValue = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(TryParse, WINRT_WRAP(bool), hstring const&, Windows::Web::Http::Headers::HttpContentRangeHeaderValue&);
            *succeeded = detach_from<bool>(this->shim().TryParse(*reinterpret_cast<hstring const*>(&input), *reinterpret_cast<Windows::Web::Http::Headers::HttpContentRangeHeaderValue*>(contentRangeHeaderValue)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Web::Http::Headers::IHttpCookiePairHeaderValue> : produce_base<D, Windows::Web::Http::Headers::IHttpCookiePairHeaderValue>
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
struct produce<D, Windows::Web::Http::Headers::IHttpCookiePairHeaderValueCollection> : produce_base<D, Windows::Web::Http::Headers::IHttpCookiePairHeaderValueCollection>
{
    int32_t WINRT_CALL ParseAdd(void* input) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ParseAdd, WINRT_WRAP(void), hstring const&);
            this->shim().ParseAdd(*reinterpret_cast<hstring const*>(&input));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL TryParseAdd(void* input, bool* result) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(TryParseAdd, WINRT_WRAP(bool), hstring const&);
            *result = detach_from<bool>(this->shim().TryParseAdd(*reinterpret_cast<hstring const*>(&input)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Web::Http::Headers::IHttpCookiePairHeaderValueFactory> : produce_base<D, Windows::Web::Http::Headers::IHttpCookiePairHeaderValueFactory>
{
    int32_t WINRT_CALL CreateFromName(void* name, void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CreateFromName, WINRT_WRAP(Windows::Web::Http::Headers::HttpCookiePairHeaderValue), hstring const&);
            *value = detach_from<Windows::Web::Http::Headers::HttpCookiePairHeaderValue>(this->shim().CreateFromName(*reinterpret_cast<hstring const*>(&name)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL CreateFromNameWithValue(void* name, void* value, void** cookiePairHeaderValue) noexcept final
    {
        try
        {
            *cookiePairHeaderValue = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CreateFromNameWithValue, WINRT_WRAP(Windows::Web::Http::Headers::HttpCookiePairHeaderValue), hstring const&, hstring const&);
            *cookiePairHeaderValue = detach_from<Windows::Web::Http::Headers::HttpCookiePairHeaderValue>(this->shim().CreateFromNameWithValue(*reinterpret_cast<hstring const*>(&name), *reinterpret_cast<hstring const*>(&value)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Web::Http::Headers::IHttpCookiePairHeaderValueStatics> : produce_base<D, Windows::Web::Http::Headers::IHttpCookiePairHeaderValueStatics>
{
    int32_t WINRT_CALL Parse(void* input, void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Parse, WINRT_WRAP(Windows::Web::Http::Headers::HttpCookiePairHeaderValue), hstring const&);
            *result = detach_from<Windows::Web::Http::Headers::HttpCookiePairHeaderValue>(this->shim().Parse(*reinterpret_cast<hstring const*>(&input)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL TryParse(void* input, void** cookiePairHeaderValue, bool* succeeded) noexcept final
    {
        try
        {
            *cookiePairHeaderValue = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(TryParse, WINRT_WRAP(bool), hstring const&, Windows::Web::Http::Headers::HttpCookiePairHeaderValue&);
            *succeeded = detach_from<bool>(this->shim().TryParse(*reinterpret_cast<hstring const*>(&input), *reinterpret_cast<Windows::Web::Http::Headers::HttpCookiePairHeaderValue*>(cookiePairHeaderValue)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Web::Http::Headers::IHttpCredentialsHeaderValue> : produce_base<D, Windows::Web::Http::Headers::IHttpCredentialsHeaderValue>
{
    int32_t WINRT_CALL get_Parameters(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Parameters, WINRT_WRAP(Windows::Foundation::Collections::IVector<Windows::Web::Http::Headers::HttpNameValueHeaderValue>));
            *value = detach_from<Windows::Foundation::Collections::IVector<Windows::Web::Http::Headers::HttpNameValueHeaderValue>>(this->shim().Parameters());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Scheme(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Scheme, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().Scheme());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Token(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Token, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().Token());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Web::Http::Headers::IHttpCredentialsHeaderValueFactory> : produce_base<D, Windows::Web::Http::Headers::IHttpCredentialsHeaderValueFactory>
{
    int32_t WINRT_CALL CreateFromScheme(void* scheme, void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CreateFromScheme, WINRT_WRAP(Windows::Web::Http::Headers::HttpCredentialsHeaderValue), hstring const&);
            *value = detach_from<Windows::Web::Http::Headers::HttpCredentialsHeaderValue>(this->shim().CreateFromScheme(*reinterpret_cast<hstring const*>(&scheme)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL CreateFromSchemeWithToken(void* scheme, void* token, void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CreateFromSchemeWithToken, WINRT_WRAP(Windows::Web::Http::Headers::HttpCredentialsHeaderValue), hstring const&, hstring const&);
            *value = detach_from<Windows::Web::Http::Headers::HttpCredentialsHeaderValue>(this->shim().CreateFromSchemeWithToken(*reinterpret_cast<hstring const*>(&scheme), *reinterpret_cast<hstring const*>(&token)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Web::Http::Headers::IHttpCredentialsHeaderValueStatics> : produce_base<D, Windows::Web::Http::Headers::IHttpCredentialsHeaderValueStatics>
{
    int32_t WINRT_CALL Parse(void* input, void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Parse, WINRT_WRAP(Windows::Web::Http::Headers::HttpCredentialsHeaderValue), hstring const&);
            *result = detach_from<Windows::Web::Http::Headers::HttpCredentialsHeaderValue>(this->shim().Parse(*reinterpret_cast<hstring const*>(&input)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL TryParse(void* input, void** credentialsHeaderValue, bool* succeeded) noexcept final
    {
        try
        {
            *credentialsHeaderValue = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(TryParse, WINRT_WRAP(bool), hstring const&, Windows::Web::Http::Headers::HttpCredentialsHeaderValue&);
            *succeeded = detach_from<bool>(this->shim().TryParse(*reinterpret_cast<hstring const*>(&input), *reinterpret_cast<Windows::Web::Http::Headers::HttpCredentialsHeaderValue*>(credentialsHeaderValue)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Web::Http::Headers::IHttpDateOrDeltaHeaderValue> : produce_base<D, Windows::Web::Http::Headers::IHttpDateOrDeltaHeaderValue>
{
    int32_t WINRT_CALL get_Date(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Date, WINRT_WRAP(Windows::Foundation::IReference<Windows::Foundation::DateTime>));
            *value = detach_from<Windows::Foundation::IReference<Windows::Foundation::DateTime>>(this->shim().Date());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Delta(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Delta, WINRT_WRAP(Windows::Foundation::IReference<Windows::Foundation::TimeSpan>));
            *value = detach_from<Windows::Foundation::IReference<Windows::Foundation::TimeSpan>>(this->shim().Delta());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Web::Http::Headers::IHttpDateOrDeltaHeaderValueStatics> : produce_base<D, Windows::Web::Http::Headers::IHttpDateOrDeltaHeaderValueStatics>
{
    int32_t WINRT_CALL Parse(void* input, void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Parse, WINRT_WRAP(Windows::Web::Http::Headers::HttpDateOrDeltaHeaderValue), hstring const&);
            *result = detach_from<Windows::Web::Http::Headers::HttpDateOrDeltaHeaderValue>(this->shim().Parse(*reinterpret_cast<hstring const*>(&input)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL TryParse(void* input, void** dateOrDeltaHeaderValue, bool* succeeded) noexcept final
    {
        try
        {
            *dateOrDeltaHeaderValue = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(TryParse, WINRT_WRAP(bool), hstring const&, Windows::Web::Http::Headers::HttpDateOrDeltaHeaderValue&);
            *succeeded = detach_from<bool>(this->shim().TryParse(*reinterpret_cast<hstring const*>(&input), *reinterpret_cast<Windows::Web::Http::Headers::HttpDateOrDeltaHeaderValue*>(dateOrDeltaHeaderValue)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Web::Http::Headers::IHttpExpectationHeaderValue> : produce_base<D, Windows::Web::Http::Headers::IHttpExpectationHeaderValue>
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

    int32_t WINRT_CALL get_Parameters(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Parameters, WINRT_WRAP(Windows::Foundation::Collections::IVector<Windows::Web::Http::Headers::HttpNameValueHeaderValue>));
            *value = detach_from<Windows::Foundation::Collections::IVector<Windows::Web::Http::Headers::HttpNameValueHeaderValue>>(this->shim().Parameters());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Web::Http::Headers::IHttpExpectationHeaderValueCollection> : produce_base<D, Windows::Web::Http::Headers::IHttpExpectationHeaderValueCollection>
{
    int32_t WINRT_CALL ParseAdd(void* input) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ParseAdd, WINRT_WRAP(void), hstring const&);
            this->shim().ParseAdd(*reinterpret_cast<hstring const*>(&input));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL TryParseAdd(void* input, bool* result) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(TryParseAdd, WINRT_WRAP(bool), hstring const&);
            *result = detach_from<bool>(this->shim().TryParseAdd(*reinterpret_cast<hstring const*>(&input)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Web::Http::Headers::IHttpExpectationHeaderValueFactory> : produce_base<D, Windows::Web::Http::Headers::IHttpExpectationHeaderValueFactory>
{
    int32_t WINRT_CALL CreateFromName(void* name, void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CreateFromName, WINRT_WRAP(Windows::Web::Http::Headers::HttpExpectationHeaderValue), hstring const&);
            *value = detach_from<Windows::Web::Http::Headers::HttpExpectationHeaderValue>(this->shim().CreateFromName(*reinterpret_cast<hstring const*>(&name)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL CreateFromNameWithValue(void* name, void* value, void** expectationHeaderValue) noexcept final
    {
        try
        {
            *expectationHeaderValue = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CreateFromNameWithValue, WINRT_WRAP(Windows::Web::Http::Headers::HttpExpectationHeaderValue), hstring const&, hstring const&);
            *expectationHeaderValue = detach_from<Windows::Web::Http::Headers::HttpExpectationHeaderValue>(this->shim().CreateFromNameWithValue(*reinterpret_cast<hstring const*>(&name), *reinterpret_cast<hstring const*>(&value)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Web::Http::Headers::IHttpExpectationHeaderValueStatics> : produce_base<D, Windows::Web::Http::Headers::IHttpExpectationHeaderValueStatics>
{
    int32_t WINRT_CALL Parse(void* input, void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Parse, WINRT_WRAP(Windows::Web::Http::Headers::HttpExpectationHeaderValue), hstring const&);
            *result = detach_from<Windows::Web::Http::Headers::HttpExpectationHeaderValue>(this->shim().Parse(*reinterpret_cast<hstring const*>(&input)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL TryParse(void* input, void** expectationHeaderValue, bool* succeeded) noexcept final
    {
        try
        {
            *expectationHeaderValue = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(TryParse, WINRT_WRAP(bool), hstring const&, Windows::Web::Http::Headers::HttpExpectationHeaderValue&);
            *succeeded = detach_from<bool>(this->shim().TryParse(*reinterpret_cast<hstring const*>(&input), *reinterpret_cast<Windows::Web::Http::Headers::HttpExpectationHeaderValue*>(expectationHeaderValue)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Web::Http::Headers::IHttpLanguageHeaderValueCollection> : produce_base<D, Windows::Web::Http::Headers::IHttpLanguageHeaderValueCollection>
{
    int32_t WINRT_CALL ParseAdd(void* input) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ParseAdd, WINRT_WRAP(void), hstring const&);
            this->shim().ParseAdd(*reinterpret_cast<hstring const*>(&input));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL TryParseAdd(void* input, bool* result) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(TryParseAdd, WINRT_WRAP(bool), hstring const&);
            *result = detach_from<bool>(this->shim().TryParseAdd(*reinterpret_cast<hstring const*>(&input)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Web::Http::Headers::IHttpLanguageRangeWithQualityHeaderValue> : produce_base<D, Windows::Web::Http::Headers::IHttpLanguageRangeWithQualityHeaderValue>
{
    int32_t WINRT_CALL get_LanguageRange(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(LanguageRange, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().LanguageRange());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Quality(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Quality, WINRT_WRAP(Windows::Foundation::IReference<double>));
            *value = detach_from<Windows::Foundation::IReference<double>>(this->shim().Quality());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Web::Http::Headers::IHttpLanguageRangeWithQualityHeaderValueCollection> : produce_base<D, Windows::Web::Http::Headers::IHttpLanguageRangeWithQualityHeaderValueCollection>
{
    int32_t WINRT_CALL ParseAdd(void* input) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ParseAdd, WINRT_WRAP(void), hstring const&);
            this->shim().ParseAdd(*reinterpret_cast<hstring const*>(&input));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL TryParseAdd(void* input, bool* result) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(TryParseAdd, WINRT_WRAP(bool), hstring const&);
            *result = detach_from<bool>(this->shim().TryParseAdd(*reinterpret_cast<hstring const*>(&input)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Web::Http::Headers::IHttpLanguageRangeWithQualityHeaderValueFactory> : produce_base<D, Windows::Web::Http::Headers::IHttpLanguageRangeWithQualityHeaderValueFactory>
{
    int32_t WINRT_CALL CreateFromLanguageRange(void* languageRange, void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CreateFromLanguageRange, WINRT_WRAP(Windows::Web::Http::Headers::HttpLanguageRangeWithQualityHeaderValue), hstring const&);
            *value = detach_from<Windows::Web::Http::Headers::HttpLanguageRangeWithQualityHeaderValue>(this->shim().CreateFromLanguageRange(*reinterpret_cast<hstring const*>(&languageRange)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL CreateFromLanguageRangeWithQuality(void* languageRange, double quality, void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CreateFromLanguageRangeWithQuality, WINRT_WRAP(Windows::Web::Http::Headers::HttpLanguageRangeWithQualityHeaderValue), hstring const&, double);
            *value = detach_from<Windows::Web::Http::Headers::HttpLanguageRangeWithQualityHeaderValue>(this->shim().CreateFromLanguageRangeWithQuality(*reinterpret_cast<hstring const*>(&languageRange), quality));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Web::Http::Headers::IHttpLanguageRangeWithQualityHeaderValueStatics> : produce_base<D, Windows::Web::Http::Headers::IHttpLanguageRangeWithQualityHeaderValueStatics>
{
    int32_t WINRT_CALL Parse(void* input, void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Parse, WINRT_WRAP(Windows::Web::Http::Headers::HttpLanguageRangeWithQualityHeaderValue), hstring const&);
            *result = detach_from<Windows::Web::Http::Headers::HttpLanguageRangeWithQualityHeaderValue>(this->shim().Parse(*reinterpret_cast<hstring const*>(&input)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL TryParse(void* input, void** languageRangeWithQualityHeaderValue, bool* succeeded) noexcept final
    {
        try
        {
            *languageRangeWithQualityHeaderValue = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(TryParse, WINRT_WRAP(bool), hstring const&, Windows::Web::Http::Headers::HttpLanguageRangeWithQualityHeaderValue&);
            *succeeded = detach_from<bool>(this->shim().TryParse(*reinterpret_cast<hstring const*>(&input), *reinterpret_cast<Windows::Web::Http::Headers::HttpLanguageRangeWithQualityHeaderValue*>(languageRangeWithQualityHeaderValue)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Web::Http::Headers::IHttpMediaTypeHeaderValue> : produce_base<D, Windows::Web::Http::Headers::IHttpMediaTypeHeaderValue>
{
    int32_t WINRT_CALL get_CharSet(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CharSet, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().CharSet());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_CharSet(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CharSet, WINRT_WRAP(void), hstring const&);
            this->shim().CharSet(*reinterpret_cast<hstring const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_MediaType(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(MediaType, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().MediaType());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_MediaType(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(MediaType, WINRT_WRAP(void), hstring const&);
            this->shim().MediaType(*reinterpret_cast<hstring const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Parameters(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Parameters, WINRT_WRAP(Windows::Foundation::Collections::IVector<Windows::Web::Http::Headers::HttpNameValueHeaderValue>));
            *value = detach_from<Windows::Foundation::Collections::IVector<Windows::Web::Http::Headers::HttpNameValueHeaderValue>>(this->shim().Parameters());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Web::Http::Headers::IHttpMediaTypeHeaderValueFactory> : produce_base<D, Windows::Web::Http::Headers::IHttpMediaTypeHeaderValueFactory>
{
    int32_t WINRT_CALL Create(void* mediaType, void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Create, WINRT_WRAP(Windows::Web::Http::Headers::HttpMediaTypeHeaderValue), hstring const&);
            *value = detach_from<Windows::Web::Http::Headers::HttpMediaTypeHeaderValue>(this->shim().Create(*reinterpret_cast<hstring const*>(&mediaType)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Web::Http::Headers::IHttpMediaTypeHeaderValueStatics> : produce_base<D, Windows::Web::Http::Headers::IHttpMediaTypeHeaderValueStatics>
{
    int32_t WINRT_CALL Parse(void* input, void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Parse, WINRT_WRAP(Windows::Web::Http::Headers::HttpMediaTypeHeaderValue), hstring const&);
            *result = detach_from<Windows::Web::Http::Headers::HttpMediaTypeHeaderValue>(this->shim().Parse(*reinterpret_cast<hstring const*>(&input)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL TryParse(void* input, void** mediaTypeHeaderValue, bool* succeeded) noexcept final
    {
        try
        {
            *mediaTypeHeaderValue = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(TryParse, WINRT_WRAP(bool), hstring const&, Windows::Web::Http::Headers::HttpMediaTypeHeaderValue&);
            *succeeded = detach_from<bool>(this->shim().TryParse(*reinterpret_cast<hstring const*>(&input), *reinterpret_cast<Windows::Web::Http::Headers::HttpMediaTypeHeaderValue*>(mediaTypeHeaderValue)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Web::Http::Headers::IHttpMediaTypeWithQualityHeaderValue> : produce_base<D, Windows::Web::Http::Headers::IHttpMediaTypeWithQualityHeaderValue>
{
    int32_t WINRT_CALL get_CharSet(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CharSet, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().CharSet());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_CharSet(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CharSet, WINRT_WRAP(void), hstring const&);
            this->shim().CharSet(*reinterpret_cast<hstring const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_MediaType(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(MediaType, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().MediaType());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_MediaType(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(MediaType, WINRT_WRAP(void), hstring const&);
            this->shim().MediaType(*reinterpret_cast<hstring const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Parameters(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Parameters, WINRT_WRAP(Windows::Foundation::Collections::IVector<Windows::Web::Http::Headers::HttpNameValueHeaderValue>));
            *value = detach_from<Windows::Foundation::Collections::IVector<Windows::Web::Http::Headers::HttpNameValueHeaderValue>>(this->shim().Parameters());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Quality(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Quality, WINRT_WRAP(Windows::Foundation::IReference<double>));
            *value = detach_from<Windows::Foundation::IReference<double>>(this->shim().Quality());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_Quality(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Quality, WINRT_WRAP(void), Windows::Foundation::IReference<double> const&);
            this->shim().Quality(*reinterpret_cast<Windows::Foundation::IReference<double> const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Web::Http::Headers::IHttpMediaTypeWithQualityHeaderValueCollection> : produce_base<D, Windows::Web::Http::Headers::IHttpMediaTypeWithQualityHeaderValueCollection>
{
    int32_t WINRT_CALL ParseAdd(void* input) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ParseAdd, WINRT_WRAP(void), hstring const&);
            this->shim().ParseAdd(*reinterpret_cast<hstring const*>(&input));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL TryParseAdd(void* input, bool* result) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(TryParseAdd, WINRT_WRAP(bool), hstring const&);
            *result = detach_from<bool>(this->shim().TryParseAdd(*reinterpret_cast<hstring const*>(&input)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Web::Http::Headers::IHttpMediaTypeWithQualityHeaderValueFactory> : produce_base<D, Windows::Web::Http::Headers::IHttpMediaTypeWithQualityHeaderValueFactory>
{
    int32_t WINRT_CALL CreateFromMediaType(void* mediaType, void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CreateFromMediaType, WINRT_WRAP(Windows::Web::Http::Headers::HttpMediaTypeWithQualityHeaderValue), hstring const&);
            *value = detach_from<Windows::Web::Http::Headers::HttpMediaTypeWithQualityHeaderValue>(this->shim().CreateFromMediaType(*reinterpret_cast<hstring const*>(&mediaType)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL CreateFromMediaTypeWithQuality(void* mediaType, double quality, void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CreateFromMediaTypeWithQuality, WINRT_WRAP(Windows::Web::Http::Headers::HttpMediaTypeWithQualityHeaderValue), hstring const&, double);
            *value = detach_from<Windows::Web::Http::Headers::HttpMediaTypeWithQualityHeaderValue>(this->shim().CreateFromMediaTypeWithQuality(*reinterpret_cast<hstring const*>(&mediaType), quality));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Web::Http::Headers::IHttpMediaTypeWithQualityHeaderValueStatics> : produce_base<D, Windows::Web::Http::Headers::IHttpMediaTypeWithQualityHeaderValueStatics>
{
    int32_t WINRT_CALL Parse(void* input, void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Parse, WINRT_WRAP(Windows::Web::Http::Headers::HttpMediaTypeWithQualityHeaderValue), hstring const&);
            *result = detach_from<Windows::Web::Http::Headers::HttpMediaTypeWithQualityHeaderValue>(this->shim().Parse(*reinterpret_cast<hstring const*>(&input)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL TryParse(void* input, void** mediaTypeWithQualityHeaderValue, bool* succeeded) noexcept final
    {
        try
        {
            *mediaTypeWithQualityHeaderValue = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(TryParse, WINRT_WRAP(bool), hstring const&, Windows::Web::Http::Headers::HttpMediaTypeWithQualityHeaderValue&);
            *succeeded = detach_from<bool>(this->shim().TryParse(*reinterpret_cast<hstring const*>(&input), *reinterpret_cast<Windows::Web::Http::Headers::HttpMediaTypeWithQualityHeaderValue*>(mediaTypeWithQualityHeaderValue)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Web::Http::Headers::IHttpMethodHeaderValueCollection> : produce_base<D, Windows::Web::Http::Headers::IHttpMethodHeaderValueCollection>
{
    int32_t WINRT_CALL ParseAdd(void* input) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ParseAdd, WINRT_WRAP(void), hstring const&);
            this->shim().ParseAdd(*reinterpret_cast<hstring const*>(&input));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL TryParseAdd(void* input, bool* result) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(TryParseAdd, WINRT_WRAP(bool), hstring const&);
            *result = detach_from<bool>(this->shim().TryParseAdd(*reinterpret_cast<hstring const*>(&input)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Web::Http::Headers::IHttpNameValueHeaderValue> : produce_base<D, Windows::Web::Http::Headers::IHttpNameValueHeaderValue>
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
struct produce<D, Windows::Web::Http::Headers::IHttpNameValueHeaderValueFactory> : produce_base<D, Windows::Web::Http::Headers::IHttpNameValueHeaderValueFactory>
{
    int32_t WINRT_CALL CreateFromName(void* name, void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CreateFromName, WINRT_WRAP(Windows::Web::Http::Headers::HttpNameValueHeaderValue), hstring const&);
            *value = detach_from<Windows::Web::Http::Headers::HttpNameValueHeaderValue>(this->shim().CreateFromName(*reinterpret_cast<hstring const*>(&name)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL CreateFromNameWithValue(void* name, void* value, void** nameValueHeaderValue) noexcept final
    {
        try
        {
            *nameValueHeaderValue = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CreateFromNameWithValue, WINRT_WRAP(Windows::Web::Http::Headers::HttpNameValueHeaderValue), hstring const&, hstring const&);
            *nameValueHeaderValue = detach_from<Windows::Web::Http::Headers::HttpNameValueHeaderValue>(this->shim().CreateFromNameWithValue(*reinterpret_cast<hstring const*>(&name), *reinterpret_cast<hstring const*>(&value)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Web::Http::Headers::IHttpNameValueHeaderValueStatics> : produce_base<D, Windows::Web::Http::Headers::IHttpNameValueHeaderValueStatics>
{
    int32_t WINRT_CALL Parse(void* input, void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Parse, WINRT_WRAP(Windows::Web::Http::Headers::HttpNameValueHeaderValue), hstring const&);
            *result = detach_from<Windows::Web::Http::Headers::HttpNameValueHeaderValue>(this->shim().Parse(*reinterpret_cast<hstring const*>(&input)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL TryParse(void* input, void** nameValueHeaderValue, bool* succeeded) noexcept final
    {
        try
        {
            *nameValueHeaderValue = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(TryParse, WINRT_WRAP(bool), hstring const&, Windows::Web::Http::Headers::HttpNameValueHeaderValue&);
            *succeeded = detach_from<bool>(this->shim().TryParse(*reinterpret_cast<hstring const*>(&input), *reinterpret_cast<Windows::Web::Http::Headers::HttpNameValueHeaderValue*>(nameValueHeaderValue)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Web::Http::Headers::IHttpProductHeaderValue> : produce_base<D, Windows::Web::Http::Headers::IHttpProductHeaderValue>
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

    int32_t WINRT_CALL get_Version(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Version, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().Version());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Web::Http::Headers::IHttpProductHeaderValueFactory> : produce_base<D, Windows::Web::Http::Headers::IHttpProductHeaderValueFactory>
{
    int32_t WINRT_CALL CreateFromName(void* productName, void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CreateFromName, WINRT_WRAP(Windows::Web::Http::Headers::HttpProductHeaderValue), hstring const&);
            *value = detach_from<Windows::Web::Http::Headers::HttpProductHeaderValue>(this->shim().CreateFromName(*reinterpret_cast<hstring const*>(&productName)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL CreateFromNameWithVersion(void* productName, void* productVersion, void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CreateFromNameWithVersion, WINRT_WRAP(Windows::Web::Http::Headers::HttpProductHeaderValue), hstring const&, hstring const&);
            *value = detach_from<Windows::Web::Http::Headers::HttpProductHeaderValue>(this->shim().CreateFromNameWithVersion(*reinterpret_cast<hstring const*>(&productName), *reinterpret_cast<hstring const*>(&productVersion)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Web::Http::Headers::IHttpProductHeaderValueStatics> : produce_base<D, Windows::Web::Http::Headers::IHttpProductHeaderValueStatics>
{
    int32_t WINRT_CALL Parse(void* input, void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Parse, WINRT_WRAP(Windows::Web::Http::Headers::HttpProductHeaderValue), hstring const&);
            *result = detach_from<Windows::Web::Http::Headers::HttpProductHeaderValue>(this->shim().Parse(*reinterpret_cast<hstring const*>(&input)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL TryParse(void* input, void** productHeaderValue, bool* succeeded) noexcept final
    {
        try
        {
            *productHeaderValue = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(TryParse, WINRT_WRAP(bool), hstring const&, Windows::Web::Http::Headers::HttpProductHeaderValue&);
            *succeeded = detach_from<bool>(this->shim().TryParse(*reinterpret_cast<hstring const*>(&input), *reinterpret_cast<Windows::Web::Http::Headers::HttpProductHeaderValue*>(productHeaderValue)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Web::Http::Headers::IHttpProductInfoHeaderValue> : produce_base<D, Windows::Web::Http::Headers::IHttpProductInfoHeaderValue>
{
    int32_t WINRT_CALL get_Product(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Product, WINRT_WRAP(Windows::Web::Http::Headers::HttpProductHeaderValue));
            *value = detach_from<Windows::Web::Http::Headers::HttpProductHeaderValue>(this->shim().Product());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Comment(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Comment, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().Comment());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Web::Http::Headers::IHttpProductInfoHeaderValueCollection> : produce_base<D, Windows::Web::Http::Headers::IHttpProductInfoHeaderValueCollection>
{
    int32_t WINRT_CALL ParseAdd(void* input) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ParseAdd, WINRT_WRAP(void), hstring const&);
            this->shim().ParseAdd(*reinterpret_cast<hstring const*>(&input));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL TryParseAdd(void* input, bool* result) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(TryParseAdd, WINRT_WRAP(bool), hstring const&);
            *result = detach_from<bool>(this->shim().TryParseAdd(*reinterpret_cast<hstring const*>(&input)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Web::Http::Headers::IHttpProductInfoHeaderValueFactory> : produce_base<D, Windows::Web::Http::Headers::IHttpProductInfoHeaderValueFactory>
{
    int32_t WINRT_CALL CreateFromComment(void* productComment, void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CreateFromComment, WINRT_WRAP(Windows::Web::Http::Headers::HttpProductInfoHeaderValue), hstring const&);
            *value = detach_from<Windows::Web::Http::Headers::HttpProductInfoHeaderValue>(this->shim().CreateFromComment(*reinterpret_cast<hstring const*>(&productComment)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL CreateFromNameWithVersion(void* productName, void* productVersion, void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CreateFromNameWithVersion, WINRT_WRAP(Windows::Web::Http::Headers::HttpProductInfoHeaderValue), hstring const&, hstring const&);
            *value = detach_from<Windows::Web::Http::Headers::HttpProductInfoHeaderValue>(this->shim().CreateFromNameWithVersion(*reinterpret_cast<hstring const*>(&productName), *reinterpret_cast<hstring const*>(&productVersion)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Web::Http::Headers::IHttpProductInfoHeaderValueStatics> : produce_base<D, Windows::Web::Http::Headers::IHttpProductInfoHeaderValueStatics>
{
    int32_t WINRT_CALL Parse(void* input, void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Parse, WINRT_WRAP(Windows::Web::Http::Headers::HttpProductInfoHeaderValue), hstring const&);
            *result = detach_from<Windows::Web::Http::Headers::HttpProductInfoHeaderValue>(this->shim().Parse(*reinterpret_cast<hstring const*>(&input)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL TryParse(void* input, void** productInfoHeaderValue, bool* succeeded) noexcept final
    {
        try
        {
            *productInfoHeaderValue = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(TryParse, WINRT_WRAP(bool), hstring const&, Windows::Web::Http::Headers::HttpProductInfoHeaderValue&);
            *succeeded = detach_from<bool>(this->shim().TryParse(*reinterpret_cast<hstring const*>(&input), *reinterpret_cast<Windows::Web::Http::Headers::HttpProductInfoHeaderValue*>(productInfoHeaderValue)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Web::Http::Headers::IHttpRequestHeaderCollection> : produce_base<D, Windows::Web::Http::Headers::IHttpRequestHeaderCollection>
{
    int32_t WINRT_CALL get_Accept(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Accept, WINRT_WRAP(Windows::Web::Http::Headers::HttpMediaTypeWithQualityHeaderValueCollection));
            *value = detach_from<Windows::Web::Http::Headers::HttpMediaTypeWithQualityHeaderValueCollection>(this->shim().Accept());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_AcceptEncoding(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(AcceptEncoding, WINRT_WRAP(Windows::Web::Http::Headers::HttpContentCodingWithQualityHeaderValueCollection));
            *value = detach_from<Windows::Web::Http::Headers::HttpContentCodingWithQualityHeaderValueCollection>(this->shim().AcceptEncoding());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_AcceptLanguage(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(AcceptLanguage, WINRT_WRAP(Windows::Web::Http::Headers::HttpLanguageRangeWithQualityHeaderValueCollection));
            *value = detach_from<Windows::Web::Http::Headers::HttpLanguageRangeWithQualityHeaderValueCollection>(this->shim().AcceptLanguage());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Authorization(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Authorization, WINRT_WRAP(Windows::Web::Http::Headers::HttpCredentialsHeaderValue));
            *value = detach_from<Windows::Web::Http::Headers::HttpCredentialsHeaderValue>(this->shim().Authorization());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_Authorization(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Authorization, WINRT_WRAP(void), Windows::Web::Http::Headers::HttpCredentialsHeaderValue const&);
            this->shim().Authorization(*reinterpret_cast<Windows::Web::Http::Headers::HttpCredentialsHeaderValue const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_CacheControl(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CacheControl, WINRT_WRAP(Windows::Web::Http::Headers::HttpCacheDirectiveHeaderValueCollection));
            *value = detach_from<Windows::Web::Http::Headers::HttpCacheDirectiveHeaderValueCollection>(this->shim().CacheControl());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Connection(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Connection, WINRT_WRAP(Windows::Web::Http::Headers::HttpConnectionOptionHeaderValueCollection));
            *value = detach_from<Windows::Web::Http::Headers::HttpConnectionOptionHeaderValueCollection>(this->shim().Connection());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Cookie(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Cookie, WINRT_WRAP(Windows::Web::Http::Headers::HttpCookiePairHeaderValueCollection));
            *value = detach_from<Windows::Web::Http::Headers::HttpCookiePairHeaderValueCollection>(this->shim().Cookie());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Date(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Date, WINRT_WRAP(Windows::Foundation::IReference<Windows::Foundation::DateTime>));
            *value = detach_from<Windows::Foundation::IReference<Windows::Foundation::DateTime>>(this->shim().Date());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_Date(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Date, WINRT_WRAP(void), Windows::Foundation::IReference<Windows::Foundation::DateTime> const&);
            this->shim().Date(*reinterpret_cast<Windows::Foundation::IReference<Windows::Foundation::DateTime> const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Expect(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Expect, WINRT_WRAP(Windows::Web::Http::Headers::HttpExpectationHeaderValueCollection));
            *value = detach_from<Windows::Web::Http::Headers::HttpExpectationHeaderValueCollection>(this->shim().Expect());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_From(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(From, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().From());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_From(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(From, WINRT_WRAP(void), hstring const&);
            this->shim().From(*reinterpret_cast<hstring const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Host(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Host, WINRT_WRAP(Windows::Networking::HostName));
            *value = detach_from<Windows::Networking::HostName>(this->shim().Host());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_Host(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Host, WINRT_WRAP(void), Windows::Networking::HostName const&);
            this->shim().Host(*reinterpret_cast<Windows::Networking::HostName const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_IfModifiedSince(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IfModifiedSince, WINRT_WRAP(Windows::Foundation::IReference<Windows::Foundation::DateTime>));
            *value = detach_from<Windows::Foundation::IReference<Windows::Foundation::DateTime>>(this->shim().IfModifiedSince());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_IfModifiedSince(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IfModifiedSince, WINRT_WRAP(void), Windows::Foundation::IReference<Windows::Foundation::DateTime> const&);
            this->shim().IfModifiedSince(*reinterpret_cast<Windows::Foundation::IReference<Windows::Foundation::DateTime> const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_IfUnmodifiedSince(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IfUnmodifiedSince, WINRT_WRAP(Windows::Foundation::IReference<Windows::Foundation::DateTime>));
            *value = detach_from<Windows::Foundation::IReference<Windows::Foundation::DateTime>>(this->shim().IfUnmodifiedSince());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_IfUnmodifiedSince(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IfUnmodifiedSince, WINRT_WRAP(void), Windows::Foundation::IReference<Windows::Foundation::DateTime> const&);
            this->shim().IfUnmodifiedSince(*reinterpret_cast<Windows::Foundation::IReference<Windows::Foundation::DateTime> const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_MaxForwards(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(MaxForwards, WINRT_WRAP(Windows::Foundation::IReference<uint32_t>));
            *value = detach_from<Windows::Foundation::IReference<uint32_t>>(this->shim().MaxForwards());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_MaxForwards(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(MaxForwards, WINRT_WRAP(void), Windows::Foundation::IReference<uint32_t> const&);
            this->shim().MaxForwards(*reinterpret_cast<Windows::Foundation::IReference<uint32_t> const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_ProxyAuthorization(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ProxyAuthorization, WINRT_WRAP(Windows::Web::Http::Headers::HttpCredentialsHeaderValue));
            *value = detach_from<Windows::Web::Http::Headers::HttpCredentialsHeaderValue>(this->shim().ProxyAuthorization());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_ProxyAuthorization(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ProxyAuthorization, WINRT_WRAP(void), Windows::Web::Http::Headers::HttpCredentialsHeaderValue const&);
            this->shim().ProxyAuthorization(*reinterpret_cast<Windows::Web::Http::Headers::HttpCredentialsHeaderValue const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Referer(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Referer, WINRT_WRAP(Windows::Foundation::Uri));
            *value = detach_from<Windows::Foundation::Uri>(this->shim().Referer());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_Referer(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Referer, WINRT_WRAP(void), Windows::Foundation::Uri const&);
            this->shim().Referer(*reinterpret_cast<Windows::Foundation::Uri const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_TransferEncoding(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(TransferEncoding, WINRT_WRAP(Windows::Web::Http::Headers::HttpTransferCodingHeaderValueCollection));
            *value = detach_from<Windows::Web::Http::Headers::HttpTransferCodingHeaderValueCollection>(this->shim().TransferEncoding());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_UserAgent(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(UserAgent, WINRT_WRAP(Windows::Web::Http::Headers::HttpProductInfoHeaderValueCollection));
            *value = detach_from<Windows::Web::Http::Headers::HttpProductInfoHeaderValueCollection>(this->shim().UserAgent());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL Append(void* name, void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Append, WINRT_WRAP(void), hstring const&, hstring const&);
            this->shim().Append(*reinterpret_cast<hstring const*>(&name), *reinterpret_cast<hstring const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL TryAppendWithoutValidation(void* name, void* value, bool* result) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(TryAppendWithoutValidation, WINRT_WRAP(bool), hstring const&, hstring const&);
            *result = detach_from<bool>(this->shim().TryAppendWithoutValidation(*reinterpret_cast<hstring const*>(&name), *reinterpret_cast<hstring const*>(&value)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Web::Http::Headers::IHttpResponseHeaderCollection> : produce_base<D, Windows::Web::Http::Headers::IHttpResponseHeaderCollection>
{
    int32_t WINRT_CALL get_Age(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Age, WINRT_WRAP(Windows::Foundation::IReference<Windows::Foundation::TimeSpan>));
            *value = detach_from<Windows::Foundation::IReference<Windows::Foundation::TimeSpan>>(this->shim().Age());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_Age(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Age, WINRT_WRAP(void), Windows::Foundation::IReference<Windows::Foundation::TimeSpan> const&);
            this->shim().Age(*reinterpret_cast<Windows::Foundation::IReference<Windows::Foundation::TimeSpan> const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Allow(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Allow, WINRT_WRAP(Windows::Web::Http::Headers::HttpMethodHeaderValueCollection));
            *value = detach_from<Windows::Web::Http::Headers::HttpMethodHeaderValueCollection>(this->shim().Allow());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_CacheControl(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CacheControl, WINRT_WRAP(Windows::Web::Http::Headers::HttpCacheDirectiveHeaderValueCollection));
            *value = detach_from<Windows::Web::Http::Headers::HttpCacheDirectiveHeaderValueCollection>(this->shim().CacheControl());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Connection(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Connection, WINRT_WRAP(Windows::Web::Http::Headers::HttpConnectionOptionHeaderValueCollection));
            *value = detach_from<Windows::Web::Http::Headers::HttpConnectionOptionHeaderValueCollection>(this->shim().Connection());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Date(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Date, WINRT_WRAP(Windows::Foundation::IReference<Windows::Foundation::DateTime>));
            *value = detach_from<Windows::Foundation::IReference<Windows::Foundation::DateTime>>(this->shim().Date());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_Date(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Date, WINRT_WRAP(void), Windows::Foundation::IReference<Windows::Foundation::DateTime> const&);
            this->shim().Date(*reinterpret_cast<Windows::Foundation::IReference<Windows::Foundation::DateTime> const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Location(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Location, WINRT_WRAP(Windows::Foundation::Uri));
            *value = detach_from<Windows::Foundation::Uri>(this->shim().Location());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_Location(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Location, WINRT_WRAP(void), Windows::Foundation::Uri const&);
            this->shim().Location(*reinterpret_cast<Windows::Foundation::Uri const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_ProxyAuthenticate(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ProxyAuthenticate, WINRT_WRAP(Windows::Web::Http::Headers::HttpChallengeHeaderValueCollection));
            *value = detach_from<Windows::Web::Http::Headers::HttpChallengeHeaderValueCollection>(this->shim().ProxyAuthenticate());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_RetryAfter(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(RetryAfter, WINRT_WRAP(Windows::Web::Http::Headers::HttpDateOrDeltaHeaderValue));
            *value = detach_from<Windows::Web::Http::Headers::HttpDateOrDeltaHeaderValue>(this->shim().RetryAfter());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_RetryAfter(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(RetryAfter, WINRT_WRAP(void), Windows::Web::Http::Headers::HttpDateOrDeltaHeaderValue const&);
            this->shim().RetryAfter(*reinterpret_cast<Windows::Web::Http::Headers::HttpDateOrDeltaHeaderValue const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_TransferEncoding(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(TransferEncoding, WINRT_WRAP(Windows::Web::Http::Headers::HttpTransferCodingHeaderValueCollection));
            *value = detach_from<Windows::Web::Http::Headers::HttpTransferCodingHeaderValueCollection>(this->shim().TransferEncoding());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_WwwAuthenticate(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(WwwAuthenticate, WINRT_WRAP(Windows::Web::Http::Headers::HttpChallengeHeaderValueCollection));
            *value = detach_from<Windows::Web::Http::Headers::HttpChallengeHeaderValueCollection>(this->shim().WwwAuthenticate());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL Append(void* name, void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Append, WINRT_WRAP(void), hstring const&, hstring const&);
            this->shim().Append(*reinterpret_cast<hstring const*>(&name), *reinterpret_cast<hstring const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL TryAppendWithoutValidation(void* name, void* value, bool* result) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(TryAppendWithoutValidation, WINRT_WRAP(bool), hstring const&, hstring const&);
            *result = detach_from<bool>(this->shim().TryAppendWithoutValidation(*reinterpret_cast<hstring const*>(&name), *reinterpret_cast<hstring const*>(&value)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Web::Http::Headers::IHttpTransferCodingHeaderValue> : produce_base<D, Windows::Web::Http::Headers::IHttpTransferCodingHeaderValue>
{
    int32_t WINRT_CALL get_Parameters(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Parameters, WINRT_WRAP(Windows::Foundation::Collections::IVector<Windows::Web::Http::Headers::HttpNameValueHeaderValue>));
            *value = detach_from<Windows::Foundation::Collections::IVector<Windows::Web::Http::Headers::HttpNameValueHeaderValue>>(this->shim().Parameters());
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
};

template <typename D>
struct produce<D, Windows::Web::Http::Headers::IHttpTransferCodingHeaderValueCollection> : produce_base<D, Windows::Web::Http::Headers::IHttpTransferCodingHeaderValueCollection>
{
    int32_t WINRT_CALL ParseAdd(void* input) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ParseAdd, WINRT_WRAP(void), hstring const&);
            this->shim().ParseAdd(*reinterpret_cast<hstring const*>(&input));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL TryParseAdd(void* input, bool* result) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(TryParseAdd, WINRT_WRAP(bool), hstring const&);
            *result = detach_from<bool>(this->shim().TryParseAdd(*reinterpret_cast<hstring const*>(&input)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Web::Http::Headers::IHttpTransferCodingHeaderValueFactory> : produce_base<D, Windows::Web::Http::Headers::IHttpTransferCodingHeaderValueFactory>
{
    int32_t WINRT_CALL Create(void* input, void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Create, WINRT_WRAP(Windows::Web::Http::Headers::HttpTransferCodingHeaderValue), hstring const&);
            *value = detach_from<Windows::Web::Http::Headers::HttpTransferCodingHeaderValue>(this->shim().Create(*reinterpret_cast<hstring const*>(&input)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Web::Http::Headers::IHttpTransferCodingHeaderValueStatics> : produce_base<D, Windows::Web::Http::Headers::IHttpTransferCodingHeaderValueStatics>
{
    int32_t WINRT_CALL Parse(void* input, void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Parse, WINRT_WRAP(Windows::Web::Http::Headers::HttpTransferCodingHeaderValue), hstring const&);
            *result = detach_from<Windows::Web::Http::Headers::HttpTransferCodingHeaderValue>(this->shim().Parse(*reinterpret_cast<hstring const*>(&input)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL TryParse(void* input, void** transferCodingHeaderValue, bool* succeeded) noexcept final
    {
        try
        {
            *transferCodingHeaderValue = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(TryParse, WINRT_WRAP(bool), hstring const&, Windows::Web::Http::Headers::HttpTransferCodingHeaderValue&);
            *succeeded = detach_from<bool>(this->shim().TryParse(*reinterpret_cast<hstring const*>(&input), *reinterpret_cast<Windows::Web::Http::Headers::HttpTransferCodingHeaderValue*>(transferCodingHeaderValue)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

}

WINRT_EXPORT namespace winrt::Windows::Web::Http::Headers {

inline HttpChallengeHeaderValue::HttpChallengeHeaderValue(param::hstring const& scheme) :
    HttpChallengeHeaderValue(impl::call_factory<HttpChallengeHeaderValue, Windows::Web::Http::Headers::IHttpChallengeHeaderValueFactory>([&](auto&& f) { return f.CreateFromScheme(scheme); }))
{}

inline HttpChallengeHeaderValue::HttpChallengeHeaderValue(param::hstring const& scheme, param::hstring const& token) :
    HttpChallengeHeaderValue(impl::call_factory<HttpChallengeHeaderValue, Windows::Web::Http::Headers::IHttpChallengeHeaderValueFactory>([&](auto&& f) { return f.CreateFromSchemeWithToken(scheme, token); }))
{}

inline Windows::Web::Http::Headers::HttpChallengeHeaderValue HttpChallengeHeaderValue::Parse(param::hstring const& input)
{
    return impl::call_factory<HttpChallengeHeaderValue, Windows::Web::Http::Headers::IHttpChallengeHeaderValueStatics>([&](auto&& f) { return f.Parse(input); });
}

inline bool HttpChallengeHeaderValue::TryParse(param::hstring const& input, Windows::Web::Http::Headers::HttpChallengeHeaderValue& challengeHeaderValue)
{
    return impl::call_factory<HttpChallengeHeaderValue, Windows::Web::Http::Headers::IHttpChallengeHeaderValueStatics>([&](auto&& f) { return f.TryParse(input, challengeHeaderValue); });
}

inline HttpConnectionOptionHeaderValue::HttpConnectionOptionHeaderValue(param::hstring const& token) :
    HttpConnectionOptionHeaderValue(impl::call_factory<HttpConnectionOptionHeaderValue, Windows::Web::Http::Headers::IHttpConnectionOptionHeaderValueFactory>([&](auto&& f) { return f.Create(token); }))
{}

inline Windows::Web::Http::Headers::HttpConnectionOptionHeaderValue HttpConnectionOptionHeaderValue::Parse(param::hstring const& input)
{
    return impl::call_factory<HttpConnectionOptionHeaderValue, Windows::Web::Http::Headers::IHttpConnectionOptionHeaderValueStatics>([&](auto&& f) { return f.Parse(input); });
}

inline bool HttpConnectionOptionHeaderValue::TryParse(param::hstring const& input, Windows::Web::Http::Headers::HttpConnectionOptionHeaderValue& connectionOptionHeaderValue)
{
    return impl::call_factory<HttpConnectionOptionHeaderValue, Windows::Web::Http::Headers::IHttpConnectionOptionHeaderValueStatics>([&](auto&& f) { return f.TryParse(input, connectionOptionHeaderValue); });
}

inline HttpContentCodingHeaderValue::HttpContentCodingHeaderValue(param::hstring const& contentCoding) :
    HttpContentCodingHeaderValue(impl::call_factory<HttpContentCodingHeaderValue, Windows::Web::Http::Headers::IHttpContentCodingHeaderValueFactory>([&](auto&& f) { return f.Create(contentCoding); }))
{}

inline Windows::Web::Http::Headers::HttpContentCodingHeaderValue HttpContentCodingHeaderValue::Parse(param::hstring const& input)
{
    return impl::call_factory<HttpContentCodingHeaderValue, Windows::Web::Http::Headers::IHttpContentCodingHeaderValueStatics>([&](auto&& f) { return f.Parse(input); });
}

inline bool HttpContentCodingHeaderValue::TryParse(param::hstring const& input, Windows::Web::Http::Headers::HttpContentCodingHeaderValue& contentCodingHeaderValue)
{
    return impl::call_factory<HttpContentCodingHeaderValue, Windows::Web::Http::Headers::IHttpContentCodingHeaderValueStatics>([&](auto&& f) { return f.TryParse(input, contentCodingHeaderValue); });
}

inline HttpContentCodingWithQualityHeaderValue::HttpContentCodingWithQualityHeaderValue(param::hstring const& contentCoding) :
    HttpContentCodingWithQualityHeaderValue(impl::call_factory<HttpContentCodingWithQualityHeaderValue, Windows::Web::Http::Headers::IHttpContentCodingWithQualityHeaderValueFactory>([&](auto&& f) { return f.CreateFromValue(contentCoding); }))
{}

inline HttpContentCodingWithQualityHeaderValue::HttpContentCodingWithQualityHeaderValue(param::hstring const& contentCoding, double quality) :
    HttpContentCodingWithQualityHeaderValue(impl::call_factory<HttpContentCodingWithQualityHeaderValue, Windows::Web::Http::Headers::IHttpContentCodingWithQualityHeaderValueFactory>([&](auto&& f) { return f.CreateFromValueWithQuality(contentCoding, quality); }))
{}

inline Windows::Web::Http::Headers::HttpContentCodingWithQualityHeaderValue HttpContentCodingWithQualityHeaderValue::Parse(param::hstring const& input)
{
    return impl::call_factory<HttpContentCodingWithQualityHeaderValue, Windows::Web::Http::Headers::IHttpContentCodingWithQualityHeaderValueStatics>([&](auto&& f) { return f.Parse(input); });
}

inline bool HttpContentCodingWithQualityHeaderValue::TryParse(param::hstring const& input, Windows::Web::Http::Headers::HttpContentCodingWithQualityHeaderValue& contentCodingWithQualityHeaderValue)
{
    return impl::call_factory<HttpContentCodingWithQualityHeaderValue, Windows::Web::Http::Headers::IHttpContentCodingWithQualityHeaderValueStatics>([&](auto&& f) { return f.TryParse(input, contentCodingWithQualityHeaderValue); });
}

inline HttpContentDispositionHeaderValue::HttpContentDispositionHeaderValue(param::hstring const& dispositionType) :
    HttpContentDispositionHeaderValue(impl::call_factory<HttpContentDispositionHeaderValue, Windows::Web::Http::Headers::IHttpContentDispositionHeaderValueFactory>([&](auto&& f) { return f.Create(dispositionType); }))
{}

inline Windows::Web::Http::Headers::HttpContentDispositionHeaderValue HttpContentDispositionHeaderValue::Parse(param::hstring const& input)
{
    return impl::call_factory<HttpContentDispositionHeaderValue, Windows::Web::Http::Headers::IHttpContentDispositionHeaderValueStatics>([&](auto&& f) { return f.Parse(input); });
}

inline bool HttpContentDispositionHeaderValue::TryParse(param::hstring const& input, Windows::Web::Http::Headers::HttpContentDispositionHeaderValue& contentDispositionHeaderValue)
{
    return impl::call_factory<HttpContentDispositionHeaderValue, Windows::Web::Http::Headers::IHttpContentDispositionHeaderValueStatics>([&](auto&& f) { return f.TryParse(input, contentDispositionHeaderValue); });
}

inline HttpContentHeaderCollection::HttpContentHeaderCollection() :
    HttpContentHeaderCollection(impl::call_factory<HttpContentHeaderCollection>([](auto&& f) { return f.template ActivateInstance<HttpContentHeaderCollection>(); }))
{}

inline HttpContentRangeHeaderValue::HttpContentRangeHeaderValue(uint64_t length) :
    HttpContentRangeHeaderValue(impl::call_factory<HttpContentRangeHeaderValue, Windows::Web::Http::Headers::IHttpContentRangeHeaderValueFactory>([&](auto&& f) { return f.CreateFromLength(length); }))
{}

inline HttpContentRangeHeaderValue::HttpContentRangeHeaderValue(uint64_t from, uint64_t to) :
    HttpContentRangeHeaderValue(impl::call_factory<HttpContentRangeHeaderValue, Windows::Web::Http::Headers::IHttpContentRangeHeaderValueFactory>([&](auto&& f) { return f.CreateFromRange(from, to); }))
{}

inline HttpContentRangeHeaderValue::HttpContentRangeHeaderValue(uint64_t from, uint64_t to, uint64_t length) :
    HttpContentRangeHeaderValue(impl::call_factory<HttpContentRangeHeaderValue, Windows::Web::Http::Headers::IHttpContentRangeHeaderValueFactory>([&](auto&& f) { return f.CreateFromRangeWithLength(from, to, length); }))
{}

inline Windows::Web::Http::Headers::HttpContentRangeHeaderValue HttpContentRangeHeaderValue::Parse(param::hstring const& input)
{
    return impl::call_factory<HttpContentRangeHeaderValue, Windows::Web::Http::Headers::IHttpContentRangeHeaderValueStatics>([&](auto&& f) { return f.Parse(input); });
}

inline bool HttpContentRangeHeaderValue::TryParse(param::hstring const& input, Windows::Web::Http::Headers::HttpContentRangeHeaderValue& contentRangeHeaderValue)
{
    return impl::call_factory<HttpContentRangeHeaderValue, Windows::Web::Http::Headers::IHttpContentRangeHeaderValueStatics>([&](auto&& f) { return f.TryParse(input, contentRangeHeaderValue); });
}

inline HttpCookiePairHeaderValue::HttpCookiePairHeaderValue(param::hstring const& name) :
    HttpCookiePairHeaderValue(impl::call_factory<HttpCookiePairHeaderValue, Windows::Web::Http::Headers::IHttpCookiePairHeaderValueFactory>([&](auto&& f) { return f.CreateFromName(name); }))
{}

inline HttpCookiePairHeaderValue::HttpCookiePairHeaderValue(param::hstring const& name, param::hstring const& value) :
    HttpCookiePairHeaderValue(impl::call_factory<HttpCookiePairHeaderValue, Windows::Web::Http::Headers::IHttpCookiePairHeaderValueFactory>([&](auto&& f) { return f.CreateFromNameWithValue(name, value); }))
{}

inline Windows::Web::Http::Headers::HttpCookiePairHeaderValue HttpCookiePairHeaderValue::Parse(param::hstring const& input)
{
    return impl::call_factory<HttpCookiePairHeaderValue, Windows::Web::Http::Headers::IHttpCookiePairHeaderValueStatics>([&](auto&& f) { return f.Parse(input); });
}

inline bool HttpCookiePairHeaderValue::TryParse(param::hstring const& input, Windows::Web::Http::Headers::HttpCookiePairHeaderValue& cookiePairHeaderValue)
{
    return impl::call_factory<HttpCookiePairHeaderValue, Windows::Web::Http::Headers::IHttpCookiePairHeaderValueStatics>([&](auto&& f) { return f.TryParse(input, cookiePairHeaderValue); });
}

inline HttpCredentialsHeaderValue::HttpCredentialsHeaderValue(param::hstring const& scheme) :
    HttpCredentialsHeaderValue(impl::call_factory<HttpCredentialsHeaderValue, Windows::Web::Http::Headers::IHttpCredentialsHeaderValueFactory>([&](auto&& f) { return f.CreateFromScheme(scheme); }))
{}

inline HttpCredentialsHeaderValue::HttpCredentialsHeaderValue(param::hstring const& scheme, param::hstring const& token) :
    HttpCredentialsHeaderValue(impl::call_factory<HttpCredentialsHeaderValue, Windows::Web::Http::Headers::IHttpCredentialsHeaderValueFactory>([&](auto&& f) { return f.CreateFromSchemeWithToken(scheme, token); }))
{}

inline Windows::Web::Http::Headers::HttpCredentialsHeaderValue HttpCredentialsHeaderValue::Parse(param::hstring const& input)
{
    return impl::call_factory<HttpCredentialsHeaderValue, Windows::Web::Http::Headers::IHttpCredentialsHeaderValueStatics>([&](auto&& f) { return f.Parse(input); });
}

inline bool HttpCredentialsHeaderValue::TryParse(param::hstring const& input, Windows::Web::Http::Headers::HttpCredentialsHeaderValue& credentialsHeaderValue)
{
    return impl::call_factory<HttpCredentialsHeaderValue, Windows::Web::Http::Headers::IHttpCredentialsHeaderValueStatics>([&](auto&& f) { return f.TryParse(input, credentialsHeaderValue); });
}

inline Windows::Web::Http::Headers::HttpDateOrDeltaHeaderValue HttpDateOrDeltaHeaderValue::Parse(param::hstring const& input)
{
    return impl::call_factory<HttpDateOrDeltaHeaderValue, Windows::Web::Http::Headers::IHttpDateOrDeltaHeaderValueStatics>([&](auto&& f) { return f.Parse(input); });
}

inline bool HttpDateOrDeltaHeaderValue::TryParse(param::hstring const& input, Windows::Web::Http::Headers::HttpDateOrDeltaHeaderValue& dateOrDeltaHeaderValue)
{
    return impl::call_factory<HttpDateOrDeltaHeaderValue, Windows::Web::Http::Headers::IHttpDateOrDeltaHeaderValueStatics>([&](auto&& f) { return f.TryParse(input, dateOrDeltaHeaderValue); });
}

inline HttpExpectationHeaderValue::HttpExpectationHeaderValue(param::hstring const& name) :
    HttpExpectationHeaderValue(impl::call_factory<HttpExpectationHeaderValue, Windows::Web::Http::Headers::IHttpExpectationHeaderValueFactory>([&](auto&& f) { return f.CreateFromName(name); }))
{}

inline HttpExpectationHeaderValue::HttpExpectationHeaderValue(param::hstring const& name, param::hstring const& value) :
    HttpExpectationHeaderValue(impl::call_factory<HttpExpectationHeaderValue, Windows::Web::Http::Headers::IHttpExpectationHeaderValueFactory>([&](auto&& f) { return f.CreateFromNameWithValue(name, value); }))
{}

inline Windows::Web::Http::Headers::HttpExpectationHeaderValue HttpExpectationHeaderValue::Parse(param::hstring const& input)
{
    return impl::call_factory<HttpExpectationHeaderValue, Windows::Web::Http::Headers::IHttpExpectationHeaderValueStatics>([&](auto&& f) { return f.Parse(input); });
}

inline bool HttpExpectationHeaderValue::TryParse(param::hstring const& input, Windows::Web::Http::Headers::HttpExpectationHeaderValue& expectationHeaderValue)
{
    return impl::call_factory<HttpExpectationHeaderValue, Windows::Web::Http::Headers::IHttpExpectationHeaderValueStatics>([&](auto&& f) { return f.TryParse(input, expectationHeaderValue); });
}

inline HttpLanguageRangeWithQualityHeaderValue::HttpLanguageRangeWithQualityHeaderValue(param::hstring const& languageRange) :
    HttpLanguageRangeWithQualityHeaderValue(impl::call_factory<HttpLanguageRangeWithQualityHeaderValue, Windows::Web::Http::Headers::IHttpLanguageRangeWithQualityHeaderValueFactory>([&](auto&& f) { return f.CreateFromLanguageRange(languageRange); }))
{}

inline HttpLanguageRangeWithQualityHeaderValue::HttpLanguageRangeWithQualityHeaderValue(param::hstring const& languageRange, double quality) :
    HttpLanguageRangeWithQualityHeaderValue(impl::call_factory<HttpLanguageRangeWithQualityHeaderValue, Windows::Web::Http::Headers::IHttpLanguageRangeWithQualityHeaderValueFactory>([&](auto&& f) { return f.CreateFromLanguageRangeWithQuality(languageRange, quality); }))
{}

inline Windows::Web::Http::Headers::HttpLanguageRangeWithQualityHeaderValue HttpLanguageRangeWithQualityHeaderValue::Parse(param::hstring const& input)
{
    return impl::call_factory<HttpLanguageRangeWithQualityHeaderValue, Windows::Web::Http::Headers::IHttpLanguageRangeWithQualityHeaderValueStatics>([&](auto&& f) { return f.Parse(input); });
}

inline bool HttpLanguageRangeWithQualityHeaderValue::TryParse(param::hstring const& input, Windows::Web::Http::Headers::HttpLanguageRangeWithQualityHeaderValue& languageRangeWithQualityHeaderValue)
{
    return impl::call_factory<HttpLanguageRangeWithQualityHeaderValue, Windows::Web::Http::Headers::IHttpLanguageRangeWithQualityHeaderValueStatics>([&](auto&& f) { return f.TryParse(input, languageRangeWithQualityHeaderValue); });
}

inline HttpMediaTypeHeaderValue::HttpMediaTypeHeaderValue(param::hstring const& mediaType) :
    HttpMediaTypeHeaderValue(impl::call_factory<HttpMediaTypeHeaderValue, Windows::Web::Http::Headers::IHttpMediaTypeHeaderValueFactory>([&](auto&& f) { return f.Create(mediaType); }))
{}

inline Windows::Web::Http::Headers::HttpMediaTypeHeaderValue HttpMediaTypeHeaderValue::Parse(param::hstring const& input)
{
    return impl::call_factory<HttpMediaTypeHeaderValue, Windows::Web::Http::Headers::IHttpMediaTypeHeaderValueStatics>([&](auto&& f) { return f.Parse(input); });
}

inline bool HttpMediaTypeHeaderValue::TryParse(param::hstring const& input, Windows::Web::Http::Headers::HttpMediaTypeHeaderValue& mediaTypeHeaderValue)
{
    return impl::call_factory<HttpMediaTypeHeaderValue, Windows::Web::Http::Headers::IHttpMediaTypeHeaderValueStatics>([&](auto&& f) { return f.TryParse(input, mediaTypeHeaderValue); });
}

inline HttpMediaTypeWithQualityHeaderValue::HttpMediaTypeWithQualityHeaderValue(param::hstring const& mediaType) :
    HttpMediaTypeWithQualityHeaderValue(impl::call_factory<HttpMediaTypeWithQualityHeaderValue, Windows::Web::Http::Headers::IHttpMediaTypeWithQualityHeaderValueFactory>([&](auto&& f) { return f.CreateFromMediaType(mediaType); }))
{}

inline HttpMediaTypeWithQualityHeaderValue::HttpMediaTypeWithQualityHeaderValue(param::hstring const& mediaType, double quality) :
    HttpMediaTypeWithQualityHeaderValue(impl::call_factory<HttpMediaTypeWithQualityHeaderValue, Windows::Web::Http::Headers::IHttpMediaTypeWithQualityHeaderValueFactory>([&](auto&& f) { return f.CreateFromMediaTypeWithQuality(mediaType, quality); }))
{}

inline Windows::Web::Http::Headers::HttpMediaTypeWithQualityHeaderValue HttpMediaTypeWithQualityHeaderValue::Parse(param::hstring const& input)
{
    return impl::call_factory<HttpMediaTypeWithQualityHeaderValue, Windows::Web::Http::Headers::IHttpMediaTypeWithQualityHeaderValueStatics>([&](auto&& f) { return f.Parse(input); });
}

inline bool HttpMediaTypeWithQualityHeaderValue::TryParse(param::hstring const& input, Windows::Web::Http::Headers::HttpMediaTypeWithQualityHeaderValue& mediaTypeWithQualityHeaderValue)
{
    return impl::call_factory<HttpMediaTypeWithQualityHeaderValue, Windows::Web::Http::Headers::IHttpMediaTypeWithQualityHeaderValueStatics>([&](auto&& f) { return f.TryParse(input, mediaTypeWithQualityHeaderValue); });
}

inline HttpNameValueHeaderValue::HttpNameValueHeaderValue(param::hstring const& name) :
    HttpNameValueHeaderValue(impl::call_factory<HttpNameValueHeaderValue, Windows::Web::Http::Headers::IHttpNameValueHeaderValueFactory>([&](auto&& f) { return f.CreateFromName(name); }))
{}

inline HttpNameValueHeaderValue::HttpNameValueHeaderValue(param::hstring const& name, param::hstring const& value) :
    HttpNameValueHeaderValue(impl::call_factory<HttpNameValueHeaderValue, Windows::Web::Http::Headers::IHttpNameValueHeaderValueFactory>([&](auto&& f) { return f.CreateFromNameWithValue(name, value); }))
{}

inline Windows::Web::Http::Headers::HttpNameValueHeaderValue HttpNameValueHeaderValue::Parse(param::hstring const& input)
{
    return impl::call_factory<HttpNameValueHeaderValue, Windows::Web::Http::Headers::IHttpNameValueHeaderValueStatics>([&](auto&& f) { return f.Parse(input); });
}

inline bool HttpNameValueHeaderValue::TryParse(param::hstring const& input, Windows::Web::Http::Headers::HttpNameValueHeaderValue& nameValueHeaderValue)
{
    return impl::call_factory<HttpNameValueHeaderValue, Windows::Web::Http::Headers::IHttpNameValueHeaderValueStatics>([&](auto&& f) { return f.TryParse(input, nameValueHeaderValue); });
}

inline HttpProductHeaderValue::HttpProductHeaderValue(param::hstring const& productName) :
    HttpProductHeaderValue(impl::call_factory<HttpProductHeaderValue, Windows::Web::Http::Headers::IHttpProductHeaderValueFactory>([&](auto&& f) { return f.CreateFromName(productName); }))
{}

inline HttpProductHeaderValue::HttpProductHeaderValue(param::hstring const& productName, param::hstring const& productVersion) :
    HttpProductHeaderValue(impl::call_factory<HttpProductHeaderValue, Windows::Web::Http::Headers::IHttpProductHeaderValueFactory>([&](auto&& f) { return f.CreateFromNameWithVersion(productName, productVersion); }))
{}

inline Windows::Web::Http::Headers::HttpProductHeaderValue HttpProductHeaderValue::Parse(param::hstring const& input)
{
    return impl::call_factory<HttpProductHeaderValue, Windows::Web::Http::Headers::IHttpProductHeaderValueStatics>([&](auto&& f) { return f.Parse(input); });
}

inline bool HttpProductHeaderValue::TryParse(param::hstring const& input, Windows::Web::Http::Headers::HttpProductHeaderValue& productHeaderValue)
{
    return impl::call_factory<HttpProductHeaderValue, Windows::Web::Http::Headers::IHttpProductHeaderValueStatics>([&](auto&& f) { return f.TryParse(input, productHeaderValue); });
}

inline HttpProductInfoHeaderValue::HttpProductInfoHeaderValue(param::hstring const& productComment) :
    HttpProductInfoHeaderValue(impl::call_factory<HttpProductInfoHeaderValue, Windows::Web::Http::Headers::IHttpProductInfoHeaderValueFactory>([&](auto&& f) { return f.CreateFromComment(productComment); }))
{}

inline HttpProductInfoHeaderValue::HttpProductInfoHeaderValue(param::hstring const& productName, param::hstring const& productVersion) :
    HttpProductInfoHeaderValue(impl::call_factory<HttpProductInfoHeaderValue, Windows::Web::Http::Headers::IHttpProductInfoHeaderValueFactory>([&](auto&& f) { return f.CreateFromNameWithVersion(productName, productVersion); }))
{}

inline Windows::Web::Http::Headers::HttpProductInfoHeaderValue HttpProductInfoHeaderValue::Parse(param::hstring const& input)
{
    return impl::call_factory<HttpProductInfoHeaderValue, Windows::Web::Http::Headers::IHttpProductInfoHeaderValueStatics>([&](auto&& f) { return f.Parse(input); });
}

inline bool HttpProductInfoHeaderValue::TryParse(param::hstring const& input, Windows::Web::Http::Headers::HttpProductInfoHeaderValue& productInfoHeaderValue)
{
    return impl::call_factory<HttpProductInfoHeaderValue, Windows::Web::Http::Headers::IHttpProductInfoHeaderValueStatics>([&](auto&& f) { return f.TryParse(input, productInfoHeaderValue); });
}

inline HttpTransferCodingHeaderValue::HttpTransferCodingHeaderValue(param::hstring const& input) :
    HttpTransferCodingHeaderValue(impl::call_factory<HttpTransferCodingHeaderValue, Windows::Web::Http::Headers::IHttpTransferCodingHeaderValueFactory>([&](auto&& f) { return f.Create(input); }))
{}

inline Windows::Web::Http::Headers::HttpTransferCodingHeaderValue HttpTransferCodingHeaderValue::Parse(param::hstring const& input)
{
    return impl::call_factory<HttpTransferCodingHeaderValue, Windows::Web::Http::Headers::IHttpTransferCodingHeaderValueStatics>([&](auto&& f) { return f.Parse(input); });
}

inline bool HttpTransferCodingHeaderValue::TryParse(param::hstring const& input, Windows::Web::Http::Headers::HttpTransferCodingHeaderValue& transferCodingHeaderValue)
{
    return impl::call_factory<HttpTransferCodingHeaderValue, Windows::Web::Http::Headers::IHttpTransferCodingHeaderValueStatics>([&](auto&& f) { return f.TryParse(input, transferCodingHeaderValue); });
}

}

WINRT_EXPORT namespace std {

template<> struct hash<winrt::Windows::Web::Http::Headers::IHttpCacheDirectiveHeaderValueCollection> : winrt::impl::hash_base<winrt::Windows::Web::Http::Headers::IHttpCacheDirectiveHeaderValueCollection> {};
template<> struct hash<winrt::Windows::Web::Http::Headers::IHttpChallengeHeaderValue> : winrt::impl::hash_base<winrt::Windows::Web::Http::Headers::IHttpChallengeHeaderValue> {};
template<> struct hash<winrt::Windows::Web::Http::Headers::IHttpChallengeHeaderValueCollection> : winrt::impl::hash_base<winrt::Windows::Web::Http::Headers::IHttpChallengeHeaderValueCollection> {};
template<> struct hash<winrt::Windows::Web::Http::Headers::IHttpChallengeHeaderValueFactory> : winrt::impl::hash_base<winrt::Windows::Web::Http::Headers::IHttpChallengeHeaderValueFactory> {};
template<> struct hash<winrt::Windows::Web::Http::Headers::IHttpChallengeHeaderValueStatics> : winrt::impl::hash_base<winrt::Windows::Web::Http::Headers::IHttpChallengeHeaderValueStatics> {};
template<> struct hash<winrt::Windows::Web::Http::Headers::IHttpConnectionOptionHeaderValue> : winrt::impl::hash_base<winrt::Windows::Web::Http::Headers::IHttpConnectionOptionHeaderValue> {};
template<> struct hash<winrt::Windows::Web::Http::Headers::IHttpConnectionOptionHeaderValueCollection> : winrt::impl::hash_base<winrt::Windows::Web::Http::Headers::IHttpConnectionOptionHeaderValueCollection> {};
template<> struct hash<winrt::Windows::Web::Http::Headers::IHttpConnectionOptionHeaderValueFactory> : winrt::impl::hash_base<winrt::Windows::Web::Http::Headers::IHttpConnectionOptionHeaderValueFactory> {};
template<> struct hash<winrt::Windows::Web::Http::Headers::IHttpConnectionOptionHeaderValueStatics> : winrt::impl::hash_base<winrt::Windows::Web::Http::Headers::IHttpConnectionOptionHeaderValueStatics> {};
template<> struct hash<winrt::Windows::Web::Http::Headers::IHttpContentCodingHeaderValue> : winrt::impl::hash_base<winrt::Windows::Web::Http::Headers::IHttpContentCodingHeaderValue> {};
template<> struct hash<winrt::Windows::Web::Http::Headers::IHttpContentCodingHeaderValueCollection> : winrt::impl::hash_base<winrt::Windows::Web::Http::Headers::IHttpContentCodingHeaderValueCollection> {};
template<> struct hash<winrt::Windows::Web::Http::Headers::IHttpContentCodingHeaderValueFactory> : winrt::impl::hash_base<winrt::Windows::Web::Http::Headers::IHttpContentCodingHeaderValueFactory> {};
template<> struct hash<winrt::Windows::Web::Http::Headers::IHttpContentCodingHeaderValueStatics> : winrt::impl::hash_base<winrt::Windows::Web::Http::Headers::IHttpContentCodingHeaderValueStatics> {};
template<> struct hash<winrt::Windows::Web::Http::Headers::IHttpContentCodingWithQualityHeaderValue> : winrt::impl::hash_base<winrt::Windows::Web::Http::Headers::IHttpContentCodingWithQualityHeaderValue> {};
template<> struct hash<winrt::Windows::Web::Http::Headers::IHttpContentCodingWithQualityHeaderValueCollection> : winrt::impl::hash_base<winrt::Windows::Web::Http::Headers::IHttpContentCodingWithQualityHeaderValueCollection> {};
template<> struct hash<winrt::Windows::Web::Http::Headers::IHttpContentCodingWithQualityHeaderValueFactory> : winrt::impl::hash_base<winrt::Windows::Web::Http::Headers::IHttpContentCodingWithQualityHeaderValueFactory> {};
template<> struct hash<winrt::Windows::Web::Http::Headers::IHttpContentCodingWithQualityHeaderValueStatics> : winrt::impl::hash_base<winrt::Windows::Web::Http::Headers::IHttpContentCodingWithQualityHeaderValueStatics> {};
template<> struct hash<winrt::Windows::Web::Http::Headers::IHttpContentDispositionHeaderValue> : winrt::impl::hash_base<winrt::Windows::Web::Http::Headers::IHttpContentDispositionHeaderValue> {};
template<> struct hash<winrt::Windows::Web::Http::Headers::IHttpContentDispositionHeaderValueFactory> : winrt::impl::hash_base<winrt::Windows::Web::Http::Headers::IHttpContentDispositionHeaderValueFactory> {};
template<> struct hash<winrt::Windows::Web::Http::Headers::IHttpContentDispositionHeaderValueStatics> : winrt::impl::hash_base<winrt::Windows::Web::Http::Headers::IHttpContentDispositionHeaderValueStatics> {};
template<> struct hash<winrt::Windows::Web::Http::Headers::IHttpContentHeaderCollection> : winrt::impl::hash_base<winrt::Windows::Web::Http::Headers::IHttpContentHeaderCollection> {};
template<> struct hash<winrt::Windows::Web::Http::Headers::IHttpContentRangeHeaderValue> : winrt::impl::hash_base<winrt::Windows::Web::Http::Headers::IHttpContentRangeHeaderValue> {};
template<> struct hash<winrt::Windows::Web::Http::Headers::IHttpContentRangeHeaderValueFactory> : winrt::impl::hash_base<winrt::Windows::Web::Http::Headers::IHttpContentRangeHeaderValueFactory> {};
template<> struct hash<winrt::Windows::Web::Http::Headers::IHttpContentRangeHeaderValueStatics> : winrt::impl::hash_base<winrt::Windows::Web::Http::Headers::IHttpContentRangeHeaderValueStatics> {};
template<> struct hash<winrt::Windows::Web::Http::Headers::IHttpCookiePairHeaderValue> : winrt::impl::hash_base<winrt::Windows::Web::Http::Headers::IHttpCookiePairHeaderValue> {};
template<> struct hash<winrt::Windows::Web::Http::Headers::IHttpCookiePairHeaderValueCollection> : winrt::impl::hash_base<winrt::Windows::Web::Http::Headers::IHttpCookiePairHeaderValueCollection> {};
template<> struct hash<winrt::Windows::Web::Http::Headers::IHttpCookiePairHeaderValueFactory> : winrt::impl::hash_base<winrt::Windows::Web::Http::Headers::IHttpCookiePairHeaderValueFactory> {};
template<> struct hash<winrt::Windows::Web::Http::Headers::IHttpCookiePairHeaderValueStatics> : winrt::impl::hash_base<winrt::Windows::Web::Http::Headers::IHttpCookiePairHeaderValueStatics> {};
template<> struct hash<winrt::Windows::Web::Http::Headers::IHttpCredentialsHeaderValue> : winrt::impl::hash_base<winrt::Windows::Web::Http::Headers::IHttpCredentialsHeaderValue> {};
template<> struct hash<winrt::Windows::Web::Http::Headers::IHttpCredentialsHeaderValueFactory> : winrt::impl::hash_base<winrt::Windows::Web::Http::Headers::IHttpCredentialsHeaderValueFactory> {};
template<> struct hash<winrt::Windows::Web::Http::Headers::IHttpCredentialsHeaderValueStatics> : winrt::impl::hash_base<winrt::Windows::Web::Http::Headers::IHttpCredentialsHeaderValueStatics> {};
template<> struct hash<winrt::Windows::Web::Http::Headers::IHttpDateOrDeltaHeaderValue> : winrt::impl::hash_base<winrt::Windows::Web::Http::Headers::IHttpDateOrDeltaHeaderValue> {};
template<> struct hash<winrt::Windows::Web::Http::Headers::IHttpDateOrDeltaHeaderValueStatics> : winrt::impl::hash_base<winrt::Windows::Web::Http::Headers::IHttpDateOrDeltaHeaderValueStatics> {};
template<> struct hash<winrt::Windows::Web::Http::Headers::IHttpExpectationHeaderValue> : winrt::impl::hash_base<winrt::Windows::Web::Http::Headers::IHttpExpectationHeaderValue> {};
template<> struct hash<winrt::Windows::Web::Http::Headers::IHttpExpectationHeaderValueCollection> : winrt::impl::hash_base<winrt::Windows::Web::Http::Headers::IHttpExpectationHeaderValueCollection> {};
template<> struct hash<winrt::Windows::Web::Http::Headers::IHttpExpectationHeaderValueFactory> : winrt::impl::hash_base<winrt::Windows::Web::Http::Headers::IHttpExpectationHeaderValueFactory> {};
template<> struct hash<winrt::Windows::Web::Http::Headers::IHttpExpectationHeaderValueStatics> : winrt::impl::hash_base<winrt::Windows::Web::Http::Headers::IHttpExpectationHeaderValueStatics> {};
template<> struct hash<winrt::Windows::Web::Http::Headers::IHttpLanguageHeaderValueCollection> : winrt::impl::hash_base<winrt::Windows::Web::Http::Headers::IHttpLanguageHeaderValueCollection> {};
template<> struct hash<winrt::Windows::Web::Http::Headers::IHttpLanguageRangeWithQualityHeaderValue> : winrt::impl::hash_base<winrt::Windows::Web::Http::Headers::IHttpLanguageRangeWithQualityHeaderValue> {};
template<> struct hash<winrt::Windows::Web::Http::Headers::IHttpLanguageRangeWithQualityHeaderValueCollection> : winrt::impl::hash_base<winrt::Windows::Web::Http::Headers::IHttpLanguageRangeWithQualityHeaderValueCollection> {};
template<> struct hash<winrt::Windows::Web::Http::Headers::IHttpLanguageRangeWithQualityHeaderValueFactory> : winrt::impl::hash_base<winrt::Windows::Web::Http::Headers::IHttpLanguageRangeWithQualityHeaderValueFactory> {};
template<> struct hash<winrt::Windows::Web::Http::Headers::IHttpLanguageRangeWithQualityHeaderValueStatics> : winrt::impl::hash_base<winrt::Windows::Web::Http::Headers::IHttpLanguageRangeWithQualityHeaderValueStatics> {};
template<> struct hash<winrt::Windows::Web::Http::Headers::IHttpMediaTypeHeaderValue> : winrt::impl::hash_base<winrt::Windows::Web::Http::Headers::IHttpMediaTypeHeaderValue> {};
template<> struct hash<winrt::Windows::Web::Http::Headers::IHttpMediaTypeHeaderValueFactory> : winrt::impl::hash_base<winrt::Windows::Web::Http::Headers::IHttpMediaTypeHeaderValueFactory> {};
template<> struct hash<winrt::Windows::Web::Http::Headers::IHttpMediaTypeHeaderValueStatics> : winrt::impl::hash_base<winrt::Windows::Web::Http::Headers::IHttpMediaTypeHeaderValueStatics> {};
template<> struct hash<winrt::Windows::Web::Http::Headers::IHttpMediaTypeWithQualityHeaderValue> : winrt::impl::hash_base<winrt::Windows::Web::Http::Headers::IHttpMediaTypeWithQualityHeaderValue> {};
template<> struct hash<winrt::Windows::Web::Http::Headers::IHttpMediaTypeWithQualityHeaderValueCollection> : winrt::impl::hash_base<winrt::Windows::Web::Http::Headers::IHttpMediaTypeWithQualityHeaderValueCollection> {};
template<> struct hash<winrt::Windows::Web::Http::Headers::IHttpMediaTypeWithQualityHeaderValueFactory> : winrt::impl::hash_base<winrt::Windows::Web::Http::Headers::IHttpMediaTypeWithQualityHeaderValueFactory> {};
template<> struct hash<winrt::Windows::Web::Http::Headers::IHttpMediaTypeWithQualityHeaderValueStatics> : winrt::impl::hash_base<winrt::Windows::Web::Http::Headers::IHttpMediaTypeWithQualityHeaderValueStatics> {};
template<> struct hash<winrt::Windows::Web::Http::Headers::IHttpMethodHeaderValueCollection> : winrt::impl::hash_base<winrt::Windows::Web::Http::Headers::IHttpMethodHeaderValueCollection> {};
template<> struct hash<winrt::Windows::Web::Http::Headers::IHttpNameValueHeaderValue> : winrt::impl::hash_base<winrt::Windows::Web::Http::Headers::IHttpNameValueHeaderValue> {};
template<> struct hash<winrt::Windows::Web::Http::Headers::IHttpNameValueHeaderValueFactory> : winrt::impl::hash_base<winrt::Windows::Web::Http::Headers::IHttpNameValueHeaderValueFactory> {};
template<> struct hash<winrt::Windows::Web::Http::Headers::IHttpNameValueHeaderValueStatics> : winrt::impl::hash_base<winrt::Windows::Web::Http::Headers::IHttpNameValueHeaderValueStatics> {};
template<> struct hash<winrt::Windows::Web::Http::Headers::IHttpProductHeaderValue> : winrt::impl::hash_base<winrt::Windows::Web::Http::Headers::IHttpProductHeaderValue> {};
template<> struct hash<winrt::Windows::Web::Http::Headers::IHttpProductHeaderValueFactory> : winrt::impl::hash_base<winrt::Windows::Web::Http::Headers::IHttpProductHeaderValueFactory> {};
template<> struct hash<winrt::Windows::Web::Http::Headers::IHttpProductHeaderValueStatics> : winrt::impl::hash_base<winrt::Windows::Web::Http::Headers::IHttpProductHeaderValueStatics> {};
template<> struct hash<winrt::Windows::Web::Http::Headers::IHttpProductInfoHeaderValue> : winrt::impl::hash_base<winrt::Windows::Web::Http::Headers::IHttpProductInfoHeaderValue> {};
template<> struct hash<winrt::Windows::Web::Http::Headers::IHttpProductInfoHeaderValueCollection> : winrt::impl::hash_base<winrt::Windows::Web::Http::Headers::IHttpProductInfoHeaderValueCollection> {};
template<> struct hash<winrt::Windows::Web::Http::Headers::IHttpProductInfoHeaderValueFactory> : winrt::impl::hash_base<winrt::Windows::Web::Http::Headers::IHttpProductInfoHeaderValueFactory> {};
template<> struct hash<winrt::Windows::Web::Http::Headers::IHttpProductInfoHeaderValueStatics> : winrt::impl::hash_base<winrt::Windows::Web::Http::Headers::IHttpProductInfoHeaderValueStatics> {};
template<> struct hash<winrt::Windows::Web::Http::Headers::IHttpRequestHeaderCollection> : winrt::impl::hash_base<winrt::Windows::Web::Http::Headers::IHttpRequestHeaderCollection> {};
template<> struct hash<winrt::Windows::Web::Http::Headers::IHttpResponseHeaderCollection> : winrt::impl::hash_base<winrt::Windows::Web::Http::Headers::IHttpResponseHeaderCollection> {};
template<> struct hash<winrt::Windows::Web::Http::Headers::IHttpTransferCodingHeaderValue> : winrt::impl::hash_base<winrt::Windows::Web::Http::Headers::IHttpTransferCodingHeaderValue> {};
template<> struct hash<winrt::Windows::Web::Http::Headers::IHttpTransferCodingHeaderValueCollection> : winrt::impl::hash_base<winrt::Windows::Web::Http::Headers::IHttpTransferCodingHeaderValueCollection> {};
template<> struct hash<winrt::Windows::Web::Http::Headers::IHttpTransferCodingHeaderValueFactory> : winrt::impl::hash_base<winrt::Windows::Web::Http::Headers::IHttpTransferCodingHeaderValueFactory> {};
template<> struct hash<winrt::Windows::Web::Http::Headers::IHttpTransferCodingHeaderValueStatics> : winrt::impl::hash_base<winrt::Windows::Web::Http::Headers::IHttpTransferCodingHeaderValueStatics> {};
template<> struct hash<winrt::Windows::Web::Http::Headers::HttpCacheDirectiveHeaderValueCollection> : winrt::impl::hash_base<winrt::Windows::Web::Http::Headers::HttpCacheDirectiveHeaderValueCollection> {};
template<> struct hash<winrt::Windows::Web::Http::Headers::HttpChallengeHeaderValue> : winrt::impl::hash_base<winrt::Windows::Web::Http::Headers::HttpChallengeHeaderValue> {};
template<> struct hash<winrt::Windows::Web::Http::Headers::HttpChallengeHeaderValueCollection> : winrt::impl::hash_base<winrt::Windows::Web::Http::Headers::HttpChallengeHeaderValueCollection> {};
template<> struct hash<winrt::Windows::Web::Http::Headers::HttpConnectionOptionHeaderValue> : winrt::impl::hash_base<winrt::Windows::Web::Http::Headers::HttpConnectionOptionHeaderValue> {};
template<> struct hash<winrt::Windows::Web::Http::Headers::HttpConnectionOptionHeaderValueCollection> : winrt::impl::hash_base<winrt::Windows::Web::Http::Headers::HttpConnectionOptionHeaderValueCollection> {};
template<> struct hash<winrt::Windows::Web::Http::Headers::HttpContentCodingHeaderValue> : winrt::impl::hash_base<winrt::Windows::Web::Http::Headers::HttpContentCodingHeaderValue> {};
template<> struct hash<winrt::Windows::Web::Http::Headers::HttpContentCodingHeaderValueCollection> : winrt::impl::hash_base<winrt::Windows::Web::Http::Headers::HttpContentCodingHeaderValueCollection> {};
template<> struct hash<winrt::Windows::Web::Http::Headers::HttpContentCodingWithQualityHeaderValue> : winrt::impl::hash_base<winrt::Windows::Web::Http::Headers::HttpContentCodingWithQualityHeaderValue> {};
template<> struct hash<winrt::Windows::Web::Http::Headers::HttpContentCodingWithQualityHeaderValueCollection> : winrt::impl::hash_base<winrt::Windows::Web::Http::Headers::HttpContentCodingWithQualityHeaderValueCollection> {};
template<> struct hash<winrt::Windows::Web::Http::Headers::HttpContentDispositionHeaderValue> : winrt::impl::hash_base<winrt::Windows::Web::Http::Headers::HttpContentDispositionHeaderValue> {};
template<> struct hash<winrt::Windows::Web::Http::Headers::HttpContentHeaderCollection> : winrt::impl::hash_base<winrt::Windows::Web::Http::Headers::HttpContentHeaderCollection> {};
template<> struct hash<winrt::Windows::Web::Http::Headers::HttpContentRangeHeaderValue> : winrt::impl::hash_base<winrt::Windows::Web::Http::Headers::HttpContentRangeHeaderValue> {};
template<> struct hash<winrt::Windows::Web::Http::Headers::HttpCookiePairHeaderValue> : winrt::impl::hash_base<winrt::Windows::Web::Http::Headers::HttpCookiePairHeaderValue> {};
template<> struct hash<winrt::Windows::Web::Http::Headers::HttpCookiePairHeaderValueCollection> : winrt::impl::hash_base<winrt::Windows::Web::Http::Headers::HttpCookiePairHeaderValueCollection> {};
template<> struct hash<winrt::Windows::Web::Http::Headers::HttpCredentialsHeaderValue> : winrt::impl::hash_base<winrt::Windows::Web::Http::Headers::HttpCredentialsHeaderValue> {};
template<> struct hash<winrt::Windows::Web::Http::Headers::HttpDateOrDeltaHeaderValue> : winrt::impl::hash_base<winrt::Windows::Web::Http::Headers::HttpDateOrDeltaHeaderValue> {};
template<> struct hash<winrt::Windows::Web::Http::Headers::HttpExpectationHeaderValue> : winrt::impl::hash_base<winrt::Windows::Web::Http::Headers::HttpExpectationHeaderValue> {};
template<> struct hash<winrt::Windows::Web::Http::Headers::HttpExpectationHeaderValueCollection> : winrt::impl::hash_base<winrt::Windows::Web::Http::Headers::HttpExpectationHeaderValueCollection> {};
template<> struct hash<winrt::Windows::Web::Http::Headers::HttpLanguageHeaderValueCollection> : winrt::impl::hash_base<winrt::Windows::Web::Http::Headers::HttpLanguageHeaderValueCollection> {};
template<> struct hash<winrt::Windows::Web::Http::Headers::HttpLanguageRangeWithQualityHeaderValue> : winrt::impl::hash_base<winrt::Windows::Web::Http::Headers::HttpLanguageRangeWithQualityHeaderValue> {};
template<> struct hash<winrt::Windows::Web::Http::Headers::HttpLanguageRangeWithQualityHeaderValueCollection> : winrt::impl::hash_base<winrt::Windows::Web::Http::Headers::HttpLanguageRangeWithQualityHeaderValueCollection> {};
template<> struct hash<winrt::Windows::Web::Http::Headers::HttpMediaTypeHeaderValue> : winrt::impl::hash_base<winrt::Windows::Web::Http::Headers::HttpMediaTypeHeaderValue> {};
template<> struct hash<winrt::Windows::Web::Http::Headers::HttpMediaTypeWithQualityHeaderValue> : winrt::impl::hash_base<winrt::Windows::Web::Http::Headers::HttpMediaTypeWithQualityHeaderValue> {};
template<> struct hash<winrt::Windows::Web::Http::Headers::HttpMediaTypeWithQualityHeaderValueCollection> : winrt::impl::hash_base<winrt::Windows::Web::Http::Headers::HttpMediaTypeWithQualityHeaderValueCollection> {};
template<> struct hash<winrt::Windows::Web::Http::Headers::HttpMethodHeaderValueCollection> : winrt::impl::hash_base<winrt::Windows::Web::Http::Headers::HttpMethodHeaderValueCollection> {};
template<> struct hash<winrt::Windows::Web::Http::Headers::HttpNameValueHeaderValue> : winrt::impl::hash_base<winrt::Windows::Web::Http::Headers::HttpNameValueHeaderValue> {};
template<> struct hash<winrt::Windows::Web::Http::Headers::HttpProductHeaderValue> : winrt::impl::hash_base<winrt::Windows::Web::Http::Headers::HttpProductHeaderValue> {};
template<> struct hash<winrt::Windows::Web::Http::Headers::HttpProductInfoHeaderValue> : winrt::impl::hash_base<winrt::Windows::Web::Http::Headers::HttpProductInfoHeaderValue> {};
template<> struct hash<winrt::Windows::Web::Http::Headers::HttpProductInfoHeaderValueCollection> : winrt::impl::hash_base<winrt::Windows::Web::Http::Headers::HttpProductInfoHeaderValueCollection> {};
template<> struct hash<winrt::Windows::Web::Http::Headers::HttpRequestHeaderCollection> : winrt::impl::hash_base<winrt::Windows::Web::Http::Headers::HttpRequestHeaderCollection> {};
template<> struct hash<winrt::Windows::Web::Http::Headers::HttpResponseHeaderCollection> : winrt::impl::hash_base<winrt::Windows::Web::Http::Headers::HttpResponseHeaderCollection> {};
template<> struct hash<winrt::Windows::Web::Http::Headers::HttpTransferCodingHeaderValue> : winrt::impl::hash_base<winrt::Windows::Web::Http::Headers::HttpTransferCodingHeaderValue> {};
template<> struct hash<winrt::Windows::Web::Http::Headers::HttpTransferCodingHeaderValueCollection> : winrt::impl::hash_base<winrt::Windows::Web::Http::Headers::HttpTransferCodingHeaderValueCollection> {};

}
