// C++/WinRT v1.0.190111.3

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#pragma once

#include "winrt/base.h"

#include "winrt/Windows.Foundation.h"
#include "winrt/Windows.Foundation.Collections.h"
#include "winrt/impl/Windows.Storage.Streams.2.h"
#include "winrt/impl/Windows.Security.Cryptography.2.h"

namespace winrt::impl {

template <typename D> bool consume_Windows_Security_Cryptography_ICryptographicBufferStatics<D>::Compare(Windows::Storage::Streams::IBuffer const& object1, Windows::Storage::Streams::IBuffer const& object2) const
{
    bool isEqual{};
    check_hresult(WINRT_SHIM(Windows::Security::Cryptography::ICryptographicBufferStatics)->Compare(get_abi(object1), get_abi(object2), &isEqual));
    return isEqual;
}

template <typename D> Windows::Storage::Streams::IBuffer consume_Windows_Security_Cryptography_ICryptographicBufferStatics<D>::GenerateRandom(uint32_t length) const
{
    Windows::Storage::Streams::IBuffer buffer{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Security::Cryptography::ICryptographicBufferStatics)->GenerateRandom(length, put_abi(buffer)));
    return buffer;
}

template <typename D> uint32_t consume_Windows_Security_Cryptography_ICryptographicBufferStatics<D>::GenerateRandomNumber() const
{
    uint32_t value{};
    check_hresult(WINRT_SHIM(Windows::Security::Cryptography::ICryptographicBufferStatics)->GenerateRandomNumber(&value));
    return value;
}

template <typename D> Windows::Storage::Streams::IBuffer consume_Windows_Security_Cryptography_ICryptographicBufferStatics<D>::CreateFromByteArray(array_view<uint8_t const> value) const
{
    Windows::Storage::Streams::IBuffer buffer{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Security::Cryptography::ICryptographicBufferStatics)->CreateFromByteArray(value.size(), get_abi(value), put_abi(buffer)));
    return buffer;
}

template <typename D> void consume_Windows_Security_Cryptography_ICryptographicBufferStatics<D>::CopyToByteArray(Windows::Storage::Streams::IBuffer const& buffer, com_array<uint8_t>& value) const
{
    check_hresult(WINRT_SHIM(Windows::Security::Cryptography::ICryptographicBufferStatics)->CopyToByteArray(get_abi(buffer), impl::put_size_abi(value), put_abi(value)));
}

template <typename D> Windows::Storage::Streams::IBuffer consume_Windows_Security_Cryptography_ICryptographicBufferStatics<D>::DecodeFromHexString(param::hstring const& value) const
{
    Windows::Storage::Streams::IBuffer buffer{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Security::Cryptography::ICryptographicBufferStatics)->DecodeFromHexString(get_abi(value), put_abi(buffer)));
    return buffer;
}

template <typename D> hstring consume_Windows_Security_Cryptography_ICryptographicBufferStatics<D>::EncodeToHexString(Windows::Storage::Streams::IBuffer const& buffer) const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Security::Cryptography::ICryptographicBufferStatics)->EncodeToHexString(get_abi(buffer), put_abi(value)));
    return value;
}

template <typename D> Windows::Storage::Streams::IBuffer consume_Windows_Security_Cryptography_ICryptographicBufferStatics<D>::DecodeFromBase64String(param::hstring const& value) const
{
    Windows::Storage::Streams::IBuffer buffer{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Security::Cryptography::ICryptographicBufferStatics)->DecodeFromBase64String(get_abi(value), put_abi(buffer)));
    return buffer;
}

template <typename D> hstring consume_Windows_Security_Cryptography_ICryptographicBufferStatics<D>::EncodeToBase64String(Windows::Storage::Streams::IBuffer const& buffer) const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Security::Cryptography::ICryptographicBufferStatics)->EncodeToBase64String(get_abi(buffer), put_abi(value)));
    return value;
}

template <typename D> Windows::Storage::Streams::IBuffer consume_Windows_Security_Cryptography_ICryptographicBufferStatics<D>::ConvertStringToBinary(param::hstring const& value, Windows::Security::Cryptography::BinaryStringEncoding const& encoding) const
{
    Windows::Storage::Streams::IBuffer buffer{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Security::Cryptography::ICryptographicBufferStatics)->ConvertStringToBinary(get_abi(value), get_abi(encoding), put_abi(buffer)));
    return buffer;
}

template <typename D> hstring consume_Windows_Security_Cryptography_ICryptographicBufferStatics<D>::ConvertBinaryToString(Windows::Security::Cryptography::BinaryStringEncoding const& encoding, Windows::Storage::Streams::IBuffer const& buffer) const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Security::Cryptography::ICryptographicBufferStatics)->ConvertBinaryToString(get_abi(encoding), get_abi(buffer), put_abi(value)));
    return value;
}

template <typename D>
struct produce<D, Windows::Security::Cryptography::ICryptographicBufferStatics> : produce_base<D, Windows::Security::Cryptography::ICryptographicBufferStatics>
{
    int32_t WINRT_CALL Compare(void* object1, void* object2, bool* isEqual) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Compare, WINRT_WRAP(bool), Windows::Storage::Streams::IBuffer const&, Windows::Storage::Streams::IBuffer const&);
            *isEqual = detach_from<bool>(this->shim().Compare(*reinterpret_cast<Windows::Storage::Streams::IBuffer const*>(&object1), *reinterpret_cast<Windows::Storage::Streams::IBuffer const*>(&object2)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL GenerateRandom(uint32_t length, void** buffer) noexcept final
    {
        try
        {
            *buffer = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GenerateRandom, WINRT_WRAP(Windows::Storage::Streams::IBuffer), uint32_t);
            *buffer = detach_from<Windows::Storage::Streams::IBuffer>(this->shim().GenerateRandom(length));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL GenerateRandomNumber(uint32_t* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GenerateRandomNumber, WINRT_WRAP(uint32_t));
            *value = detach_from<uint32_t>(this->shim().GenerateRandomNumber());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL CreateFromByteArray(uint32_t __valueSize, uint8_t* value, void** buffer) noexcept final
    {
        try
        {
            *buffer = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CreateFromByteArray, WINRT_WRAP(Windows::Storage::Streams::IBuffer), array_view<uint8_t const>);
            *buffer = detach_from<Windows::Storage::Streams::IBuffer>(this->shim().CreateFromByteArray(array_view<uint8_t const>(reinterpret_cast<uint8_t const *>(value), reinterpret_cast<uint8_t const *>(value) + __valueSize)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL CopyToByteArray(void* buffer, uint32_t* __valueSize, uint8_t** value) noexcept final
    {
        try
        {
            *__valueSize = 0;
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CopyToByteArray, WINRT_WRAP(void), Windows::Storage::Streams::IBuffer const&, com_array<uint8_t>&);
            this->shim().CopyToByteArray(*reinterpret_cast<Windows::Storage::Streams::IBuffer const*>(&buffer), detach_abi<uint8_t>(__valueSize, value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL DecodeFromHexString(void* value, void** buffer) noexcept final
    {
        try
        {
            *buffer = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(DecodeFromHexString, WINRT_WRAP(Windows::Storage::Streams::IBuffer), hstring const&);
            *buffer = detach_from<Windows::Storage::Streams::IBuffer>(this->shim().DecodeFromHexString(*reinterpret_cast<hstring const*>(&value)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL EncodeToHexString(void* buffer, void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(EncodeToHexString, WINRT_WRAP(hstring), Windows::Storage::Streams::IBuffer const&);
            *value = detach_from<hstring>(this->shim().EncodeToHexString(*reinterpret_cast<Windows::Storage::Streams::IBuffer const*>(&buffer)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL DecodeFromBase64String(void* value, void** buffer) noexcept final
    {
        try
        {
            *buffer = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(DecodeFromBase64String, WINRT_WRAP(Windows::Storage::Streams::IBuffer), hstring const&);
            *buffer = detach_from<Windows::Storage::Streams::IBuffer>(this->shim().DecodeFromBase64String(*reinterpret_cast<hstring const*>(&value)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL EncodeToBase64String(void* buffer, void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(EncodeToBase64String, WINRT_WRAP(hstring), Windows::Storage::Streams::IBuffer const&);
            *value = detach_from<hstring>(this->shim().EncodeToBase64String(*reinterpret_cast<Windows::Storage::Streams::IBuffer const*>(&buffer)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL ConvertStringToBinary(void* value, Windows::Security::Cryptography::BinaryStringEncoding encoding, void** buffer) noexcept final
    {
        try
        {
            *buffer = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ConvertStringToBinary, WINRT_WRAP(Windows::Storage::Streams::IBuffer), hstring const&, Windows::Security::Cryptography::BinaryStringEncoding const&);
            *buffer = detach_from<Windows::Storage::Streams::IBuffer>(this->shim().ConvertStringToBinary(*reinterpret_cast<hstring const*>(&value), *reinterpret_cast<Windows::Security::Cryptography::BinaryStringEncoding const*>(&encoding)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL ConvertBinaryToString(Windows::Security::Cryptography::BinaryStringEncoding encoding, void* buffer, void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ConvertBinaryToString, WINRT_WRAP(hstring), Windows::Security::Cryptography::BinaryStringEncoding const&, Windows::Storage::Streams::IBuffer const&);
            *value = detach_from<hstring>(this->shim().ConvertBinaryToString(*reinterpret_cast<Windows::Security::Cryptography::BinaryStringEncoding const*>(&encoding), *reinterpret_cast<Windows::Storage::Streams::IBuffer const*>(&buffer)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

}

WINRT_EXPORT namespace winrt::Windows::Security::Cryptography {

inline bool CryptographicBuffer::Compare(Windows::Storage::Streams::IBuffer const& object1, Windows::Storage::Streams::IBuffer const& object2)
{
    return impl::call_factory<CryptographicBuffer, Windows::Security::Cryptography::ICryptographicBufferStatics>([&](auto&& f) { return f.Compare(object1, object2); });
}

inline Windows::Storage::Streams::IBuffer CryptographicBuffer::GenerateRandom(uint32_t length)
{
    return impl::call_factory<CryptographicBuffer, Windows::Security::Cryptography::ICryptographicBufferStatics>([&](auto&& f) { return f.GenerateRandom(length); });
}

inline uint32_t CryptographicBuffer::GenerateRandomNumber()
{
    return impl::call_factory<CryptographicBuffer, Windows::Security::Cryptography::ICryptographicBufferStatics>([&](auto&& f) { return f.GenerateRandomNumber(); });
}

inline Windows::Storage::Streams::IBuffer CryptographicBuffer::CreateFromByteArray(array_view<uint8_t const> value)
{
    return impl::call_factory<CryptographicBuffer, Windows::Security::Cryptography::ICryptographicBufferStatics>([&](auto&& f) { return f.CreateFromByteArray(value); });
}

inline void CryptographicBuffer::CopyToByteArray(Windows::Storage::Streams::IBuffer const& buffer, com_array<uint8_t>& value)
{
    impl::call_factory<CryptographicBuffer, Windows::Security::Cryptography::ICryptographicBufferStatics>([&](auto&& f) { return f.CopyToByteArray(buffer, value); });
}

inline Windows::Storage::Streams::IBuffer CryptographicBuffer::DecodeFromHexString(param::hstring const& value)
{
    return impl::call_factory<CryptographicBuffer, Windows::Security::Cryptography::ICryptographicBufferStatics>([&](auto&& f) { return f.DecodeFromHexString(value); });
}

inline hstring CryptographicBuffer::EncodeToHexString(Windows::Storage::Streams::IBuffer const& buffer)
{
    return impl::call_factory<CryptographicBuffer, Windows::Security::Cryptography::ICryptographicBufferStatics>([&](auto&& f) { return f.EncodeToHexString(buffer); });
}

inline Windows::Storage::Streams::IBuffer CryptographicBuffer::DecodeFromBase64String(param::hstring const& value)
{
    return impl::call_factory<CryptographicBuffer, Windows::Security::Cryptography::ICryptographicBufferStatics>([&](auto&& f) { return f.DecodeFromBase64String(value); });
}

inline hstring CryptographicBuffer::EncodeToBase64String(Windows::Storage::Streams::IBuffer const& buffer)
{
    return impl::call_factory<CryptographicBuffer, Windows::Security::Cryptography::ICryptographicBufferStatics>([&](auto&& f) { return f.EncodeToBase64String(buffer); });
}

inline Windows::Storage::Streams::IBuffer CryptographicBuffer::ConvertStringToBinary(param::hstring const& value, Windows::Security::Cryptography::BinaryStringEncoding const& encoding)
{
    return impl::call_factory<CryptographicBuffer, Windows::Security::Cryptography::ICryptographicBufferStatics>([&](auto&& f) { return f.ConvertStringToBinary(value, encoding); });
}

inline hstring CryptographicBuffer::ConvertBinaryToString(Windows::Security::Cryptography::BinaryStringEncoding const& encoding, Windows::Storage::Streams::IBuffer const& buffer)
{
    return impl::call_factory<CryptographicBuffer, Windows::Security::Cryptography::ICryptographicBufferStatics>([&](auto&& f) { return f.ConvertBinaryToString(encoding, buffer); });
}

}

WINRT_EXPORT namespace std {

template<> struct hash<winrt::Windows::Security::Cryptography::ICryptographicBufferStatics> : winrt::impl::hash_base<winrt::Windows::Security::Cryptography::ICryptographicBufferStatics> {};
template<> struct hash<winrt::Windows::Security::Cryptography::CryptographicBuffer> : winrt::impl::hash_base<winrt::Windows::Security::Cryptography::CryptographicBuffer> {};

}
