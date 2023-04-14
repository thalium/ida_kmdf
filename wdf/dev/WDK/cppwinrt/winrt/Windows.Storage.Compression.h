// C++/WinRT v1.0.190111.3

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#pragma once

#include "winrt/base.h"

#include "winrt/Windows.Foundation.h"
#include "winrt/Windows.Foundation.Collections.h"
#include "winrt/impl/Windows.Storage.Streams.2.h"
#include "winrt/impl/Windows.Foundation.2.h"
#include "winrt/impl/Windows.Storage.Compression.2.h"
#include "winrt/Windows.Storage.h"

namespace winrt::impl {

template <typename D> Windows::Foundation::IAsyncOperation<bool> consume_Windows_Storage_Compression_ICompressor<D>::FinishAsync() const
{
    Windows::Foundation::IAsyncOperation<bool> operation{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Storage::Compression::ICompressor)->FinishAsync(put_abi(operation)));
    return operation;
}

template <typename D> Windows::Storage::Streams::IOutputStream consume_Windows_Storage_Compression_ICompressor<D>::DetachStream() const
{
    Windows::Storage::Streams::IOutputStream stream{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Storage::Compression::ICompressor)->DetachStream(put_abi(stream)));
    return stream;
}

template <typename D> Windows::Storage::Compression::Compressor consume_Windows_Storage_Compression_ICompressorFactory<D>::CreateCompressor(Windows::Storage::Streams::IOutputStream const& underlyingStream) const
{
    Windows::Storage::Compression::Compressor createdCompressor{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Storage::Compression::ICompressorFactory)->CreateCompressor(get_abi(underlyingStream), put_abi(createdCompressor)));
    return createdCompressor;
}

template <typename D> Windows::Storage::Compression::Compressor consume_Windows_Storage_Compression_ICompressorFactory<D>::CreateCompressorEx(Windows::Storage::Streams::IOutputStream const& underlyingStream, Windows::Storage::Compression::CompressAlgorithm const& algorithm, uint32_t blockSize) const
{
    Windows::Storage::Compression::Compressor createdCompressor{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Storage::Compression::ICompressorFactory)->CreateCompressorEx(get_abi(underlyingStream), get_abi(algorithm), blockSize, put_abi(createdCompressor)));
    return createdCompressor;
}

template <typename D> Windows::Storage::Streams::IInputStream consume_Windows_Storage_Compression_IDecompressor<D>::DetachStream() const
{
    Windows::Storage::Streams::IInputStream stream{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Storage::Compression::IDecompressor)->DetachStream(put_abi(stream)));
    return stream;
}

template <typename D> Windows::Storage::Compression::Decompressor consume_Windows_Storage_Compression_IDecompressorFactory<D>::CreateDecompressor(Windows::Storage::Streams::IInputStream const& underlyingStream) const
{
    Windows::Storage::Compression::Decompressor createdDecompressor{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Storage::Compression::IDecompressorFactory)->CreateDecompressor(get_abi(underlyingStream), put_abi(createdDecompressor)));
    return createdDecompressor;
}

template <typename D>
struct produce<D, Windows::Storage::Compression::ICompressor> : produce_base<D, Windows::Storage::Compression::ICompressor>
{
    int32_t WINRT_CALL FinishAsync(void** operation) noexcept final
    {
        try
        {
            *operation = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(FinishAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<bool>));
            *operation = detach_from<Windows::Foundation::IAsyncOperation<bool>>(this->shim().FinishAsync());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL DetachStream(void** stream) noexcept final
    {
        try
        {
            *stream = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(DetachStream, WINRT_WRAP(Windows::Storage::Streams::IOutputStream));
            *stream = detach_from<Windows::Storage::Streams::IOutputStream>(this->shim().DetachStream());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Storage::Compression::ICompressorFactory> : produce_base<D, Windows::Storage::Compression::ICompressorFactory>
{
    int32_t WINRT_CALL CreateCompressor(void* underlyingStream, void** createdCompressor) noexcept final
    {
        try
        {
            *createdCompressor = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CreateCompressor, WINRT_WRAP(Windows::Storage::Compression::Compressor), Windows::Storage::Streams::IOutputStream const&);
            *createdCompressor = detach_from<Windows::Storage::Compression::Compressor>(this->shim().CreateCompressor(*reinterpret_cast<Windows::Storage::Streams::IOutputStream const*>(&underlyingStream)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL CreateCompressorEx(void* underlyingStream, Windows::Storage::Compression::CompressAlgorithm algorithm, uint32_t blockSize, void** createdCompressor) noexcept final
    {
        try
        {
            *createdCompressor = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CreateCompressorEx, WINRT_WRAP(Windows::Storage::Compression::Compressor), Windows::Storage::Streams::IOutputStream const&, Windows::Storage::Compression::CompressAlgorithm const&, uint32_t);
            *createdCompressor = detach_from<Windows::Storage::Compression::Compressor>(this->shim().CreateCompressorEx(*reinterpret_cast<Windows::Storage::Streams::IOutputStream const*>(&underlyingStream), *reinterpret_cast<Windows::Storage::Compression::CompressAlgorithm const*>(&algorithm), blockSize));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Storage::Compression::IDecompressor> : produce_base<D, Windows::Storage::Compression::IDecompressor>
{
    int32_t WINRT_CALL DetachStream(void** stream) noexcept final
    {
        try
        {
            *stream = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(DetachStream, WINRT_WRAP(Windows::Storage::Streams::IInputStream));
            *stream = detach_from<Windows::Storage::Streams::IInputStream>(this->shim().DetachStream());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Storage::Compression::IDecompressorFactory> : produce_base<D, Windows::Storage::Compression::IDecompressorFactory>
{
    int32_t WINRT_CALL CreateDecompressor(void* underlyingStream, void** createdDecompressor) noexcept final
    {
        try
        {
            *createdDecompressor = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CreateDecompressor, WINRT_WRAP(Windows::Storage::Compression::Decompressor), Windows::Storage::Streams::IInputStream const&);
            *createdDecompressor = detach_from<Windows::Storage::Compression::Decompressor>(this->shim().CreateDecompressor(*reinterpret_cast<Windows::Storage::Streams::IInputStream const*>(&underlyingStream)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

}

WINRT_EXPORT namespace winrt::Windows::Storage::Compression {

inline Compressor::Compressor(Windows::Storage::Streams::IOutputStream const& underlyingStream) :
    Compressor(impl::call_factory<Compressor, Windows::Storage::Compression::ICompressorFactory>([&](auto&& f) { return f.CreateCompressor(underlyingStream); }))
{}

inline Compressor::Compressor(Windows::Storage::Streams::IOutputStream const& underlyingStream, Windows::Storage::Compression::CompressAlgorithm const& algorithm, uint32_t blockSize) :
    Compressor(impl::call_factory<Compressor, Windows::Storage::Compression::ICompressorFactory>([&](auto&& f) { return f.CreateCompressorEx(underlyingStream, algorithm, blockSize); }))
{}

inline Decompressor::Decompressor(Windows::Storage::Streams::IInputStream const& underlyingStream) :
    Decompressor(impl::call_factory<Decompressor, Windows::Storage::Compression::IDecompressorFactory>([&](auto&& f) { return f.CreateDecompressor(underlyingStream); }))
{}

}

WINRT_EXPORT namespace std {

template<> struct hash<winrt::Windows::Storage::Compression::ICompressor> : winrt::impl::hash_base<winrt::Windows::Storage::Compression::ICompressor> {};
template<> struct hash<winrt::Windows::Storage::Compression::ICompressorFactory> : winrt::impl::hash_base<winrt::Windows::Storage::Compression::ICompressorFactory> {};
template<> struct hash<winrt::Windows::Storage::Compression::IDecompressor> : winrt::impl::hash_base<winrt::Windows::Storage::Compression::IDecompressor> {};
template<> struct hash<winrt::Windows::Storage::Compression::IDecompressorFactory> : winrt::impl::hash_base<winrt::Windows::Storage::Compression::IDecompressorFactory> {};
template<> struct hash<winrt::Windows::Storage::Compression::Compressor> : winrt::impl::hash_base<winrt::Windows::Storage::Compression::Compressor> {};
template<> struct hash<winrt::Windows::Storage::Compression::Decompressor> : winrt::impl::hash_base<winrt::Windows::Storage::Compression::Decompressor> {};

}
