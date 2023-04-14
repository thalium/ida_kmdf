// C++/WinRT v1.0.190111.3

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#pragma once

WINRT_EXPORT namespace winrt::Windows::Storage::Streams {

struct IBuffer;

}

WINRT_EXPORT namespace winrt::Windows::Security::Cryptography {

enum class BinaryStringEncoding : int32_t
{
    Utf8 = 0,
    Utf16LE = 1,
    Utf16BE = 2,
};

struct ICryptographicBufferStatics;
struct CryptographicBuffer;

}

namespace winrt::impl {

template <> struct category<Windows::Security::Cryptography::ICryptographicBufferStatics>{ using type = interface_category; };
template <> struct category<Windows::Security::Cryptography::CryptographicBuffer>{ using type = class_category; };
template <> struct category<Windows::Security::Cryptography::BinaryStringEncoding>{ using type = enum_category; };
template <> struct name<Windows::Security::Cryptography::ICryptographicBufferStatics>{ static constexpr auto & value{ L"Windows.Security.Cryptography.ICryptographicBufferStatics" }; };
template <> struct name<Windows::Security::Cryptography::CryptographicBuffer>{ static constexpr auto & value{ L"Windows.Security.Cryptography.CryptographicBuffer" }; };
template <> struct name<Windows::Security::Cryptography::BinaryStringEncoding>{ static constexpr auto & value{ L"Windows.Security.Cryptography.BinaryStringEncoding" }; };
template <> struct guid_storage<Windows::Security::Cryptography::ICryptographicBufferStatics>{ static constexpr guid value{ 0x320B7E22,0x3CB0,0x4CDF,{ 0x86,0x63,0x1D,0x28,0x91,0x00,0x65,0xEB } }; };

template <> struct abi<Windows::Security::Cryptography::ICryptographicBufferStatics>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL Compare(void* object1, void* object2, bool* isEqual) noexcept = 0;
    virtual int32_t WINRT_CALL GenerateRandom(uint32_t length, void** buffer) noexcept = 0;
    virtual int32_t WINRT_CALL GenerateRandomNumber(uint32_t* value) noexcept = 0;
    virtual int32_t WINRT_CALL CreateFromByteArray(uint32_t __valueSize, uint8_t* value, void** buffer) noexcept = 0;
    virtual int32_t WINRT_CALL CopyToByteArray(void* buffer, uint32_t* __valueSize, uint8_t** value) noexcept = 0;
    virtual int32_t WINRT_CALL DecodeFromHexString(void* value, void** buffer) noexcept = 0;
    virtual int32_t WINRT_CALL EncodeToHexString(void* buffer, void** value) noexcept = 0;
    virtual int32_t WINRT_CALL DecodeFromBase64String(void* value, void** buffer) noexcept = 0;
    virtual int32_t WINRT_CALL EncodeToBase64String(void* buffer, void** value) noexcept = 0;
    virtual int32_t WINRT_CALL ConvertStringToBinary(void* value, Windows::Security::Cryptography::BinaryStringEncoding encoding, void** buffer) noexcept = 0;
    virtual int32_t WINRT_CALL ConvertBinaryToString(Windows::Security::Cryptography::BinaryStringEncoding encoding, void* buffer, void** value) noexcept = 0;
};};

template <typename D>
struct consume_Windows_Security_Cryptography_ICryptographicBufferStatics
{
    bool Compare(Windows::Storage::Streams::IBuffer const& object1, Windows::Storage::Streams::IBuffer const& object2) const;
    Windows::Storage::Streams::IBuffer GenerateRandom(uint32_t length) const;
    uint32_t GenerateRandomNumber() const;
    Windows::Storage::Streams::IBuffer CreateFromByteArray(array_view<uint8_t const> value) const;
    void CopyToByteArray(Windows::Storage::Streams::IBuffer const& buffer, com_array<uint8_t>& value) const;
    Windows::Storage::Streams::IBuffer DecodeFromHexString(param::hstring const& value) const;
    hstring EncodeToHexString(Windows::Storage::Streams::IBuffer const& buffer) const;
    Windows::Storage::Streams::IBuffer DecodeFromBase64String(param::hstring const& value) const;
    hstring EncodeToBase64String(Windows::Storage::Streams::IBuffer const& buffer) const;
    Windows::Storage::Streams::IBuffer ConvertStringToBinary(param::hstring const& value, Windows::Security::Cryptography::BinaryStringEncoding const& encoding) const;
    hstring ConvertBinaryToString(Windows::Security::Cryptography::BinaryStringEncoding const& encoding, Windows::Storage::Streams::IBuffer const& buffer) const;
};
template <> struct consume<Windows::Security::Cryptography::ICryptographicBufferStatics> { template <typename D> using type = consume_Windows_Security_Cryptography_ICryptographicBufferStatics<D>; };

}
