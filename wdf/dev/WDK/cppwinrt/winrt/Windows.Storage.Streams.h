// C++/WinRT v1.0.190111.3

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#pragma once

#include "winrt/base.h"

#include "winrt/Windows.Foundation.h"
#include "winrt/Windows.Foundation.Collections.h"
#include "winrt/impl/Windows.Foundation.2.h"
#include "winrt/impl/Windows.Storage.2.h"
#include "winrt/impl/Windows.System.2.h"
#include "winrt/impl/Windows.Storage.Streams.2.h"
#include "winrt/Windows.Storage.h"

namespace winrt::impl {

template <typename D> uint32_t consume_Windows_Storage_Streams_IBuffer<D>::Capacity() const
{
    uint32_t value{};
    check_hresult(WINRT_SHIM(Windows::Storage::Streams::IBuffer)->get_Capacity(&value));
    return value;
}

template <typename D> uint32_t consume_Windows_Storage_Streams_IBuffer<D>::Length() const
{
    uint32_t value{};
    check_hresult(WINRT_SHIM(Windows::Storage::Streams::IBuffer)->get_Length(&value));
    return value;
}

template <typename D> void consume_Windows_Storage_Streams_IBuffer<D>::Length(uint32_t value) const
{
    check_hresult(WINRT_SHIM(Windows::Storage::Streams::IBuffer)->put_Length(value));
}

template <typename D> Windows::Storage::Streams::Buffer consume_Windows_Storage_Streams_IBufferFactory<D>::Create(uint32_t capacity) const
{
    Windows::Storage::Streams::Buffer value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Storage::Streams::IBufferFactory)->Create(capacity, put_abi(value)));
    return value;
}

template <typename D> Windows::Storage::Streams::Buffer consume_Windows_Storage_Streams_IBufferStatics<D>::CreateCopyFromMemoryBuffer(Windows::Foundation::IMemoryBuffer const& input) const
{
    Windows::Storage::Streams::Buffer value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Storage::Streams::IBufferStatics)->CreateCopyFromMemoryBuffer(get_abi(input), put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::MemoryBuffer consume_Windows_Storage_Streams_IBufferStatics<D>::CreateMemoryBufferOverIBuffer(Windows::Storage::Streams::IBuffer const& input) const
{
    Windows::Foundation::MemoryBuffer value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Storage::Streams::IBufferStatics)->CreateMemoryBufferOverIBuffer(get_abi(input), put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_Storage_Streams_IContentTypeProvider<D>::ContentType() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Storage::Streams::IContentTypeProvider)->get_ContentType(put_abi(value)));
    return value;
}

template <typename D> uint32_t consume_Windows_Storage_Streams_IDataReader<D>::UnconsumedBufferLength() const
{
    uint32_t value{};
    check_hresult(WINRT_SHIM(Windows::Storage::Streams::IDataReader)->get_UnconsumedBufferLength(&value));
    return value;
}

template <typename D> Windows::Storage::Streams::UnicodeEncoding consume_Windows_Storage_Streams_IDataReader<D>::UnicodeEncoding() const
{
    Windows::Storage::Streams::UnicodeEncoding value{};
    check_hresult(WINRT_SHIM(Windows::Storage::Streams::IDataReader)->get_UnicodeEncoding(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_Storage_Streams_IDataReader<D>::UnicodeEncoding(Windows::Storage::Streams::UnicodeEncoding const& value) const
{
    check_hresult(WINRT_SHIM(Windows::Storage::Streams::IDataReader)->put_UnicodeEncoding(get_abi(value)));
}

template <typename D> Windows::Storage::Streams::ByteOrder consume_Windows_Storage_Streams_IDataReader<D>::ByteOrder() const
{
    Windows::Storage::Streams::ByteOrder value{};
    check_hresult(WINRT_SHIM(Windows::Storage::Streams::IDataReader)->get_ByteOrder(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_Storage_Streams_IDataReader<D>::ByteOrder(Windows::Storage::Streams::ByteOrder const& value) const
{
    check_hresult(WINRT_SHIM(Windows::Storage::Streams::IDataReader)->put_ByteOrder(get_abi(value)));
}

template <typename D> Windows::Storage::Streams::InputStreamOptions consume_Windows_Storage_Streams_IDataReader<D>::InputStreamOptions() const
{
    Windows::Storage::Streams::InputStreamOptions value{};
    check_hresult(WINRT_SHIM(Windows::Storage::Streams::IDataReader)->get_InputStreamOptions(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_Storage_Streams_IDataReader<D>::InputStreamOptions(Windows::Storage::Streams::InputStreamOptions const& value) const
{
    check_hresult(WINRT_SHIM(Windows::Storage::Streams::IDataReader)->put_InputStreamOptions(get_abi(value)));
}

template <typename D> uint8_t consume_Windows_Storage_Streams_IDataReader<D>::ReadByte() const
{
    uint8_t value{};
    check_hresult(WINRT_SHIM(Windows::Storage::Streams::IDataReader)->ReadByte(&value));
    return value;
}

template <typename D> void consume_Windows_Storage_Streams_IDataReader<D>::ReadBytes(array_view<uint8_t> value) const
{
    check_hresult(WINRT_SHIM(Windows::Storage::Streams::IDataReader)->ReadBytes(value.size(), get_abi(value)));
}

template <typename D> Windows::Storage::Streams::IBuffer consume_Windows_Storage_Streams_IDataReader<D>::ReadBuffer(uint32_t length) const
{
    Windows::Storage::Streams::IBuffer buffer{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Storage::Streams::IDataReader)->ReadBuffer(length, put_abi(buffer)));
    return buffer;
}

template <typename D> bool consume_Windows_Storage_Streams_IDataReader<D>::ReadBoolean() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::Storage::Streams::IDataReader)->ReadBoolean(&value));
    return value;
}

template <typename D> winrt::guid consume_Windows_Storage_Streams_IDataReader<D>::ReadGuid() const
{
    winrt::guid value{};
    check_hresult(WINRT_SHIM(Windows::Storage::Streams::IDataReader)->ReadGuid(put_abi(value)));
    return value;
}

template <typename D> int16_t consume_Windows_Storage_Streams_IDataReader<D>::ReadInt16() const
{
    int16_t value{};
    check_hresult(WINRT_SHIM(Windows::Storage::Streams::IDataReader)->ReadInt16(&value));
    return value;
}

template <typename D> int32_t consume_Windows_Storage_Streams_IDataReader<D>::ReadInt32() const
{
    int32_t value{};
    check_hresult(WINRT_SHIM(Windows::Storage::Streams::IDataReader)->ReadInt32(&value));
    return value;
}

template <typename D> int64_t consume_Windows_Storage_Streams_IDataReader<D>::ReadInt64() const
{
    int64_t value{};
    check_hresult(WINRT_SHIM(Windows::Storage::Streams::IDataReader)->ReadInt64(&value));
    return value;
}

template <typename D> uint16_t consume_Windows_Storage_Streams_IDataReader<D>::ReadUInt16() const
{
    uint16_t value{};
    check_hresult(WINRT_SHIM(Windows::Storage::Streams::IDataReader)->ReadUInt16(&value));
    return value;
}

template <typename D> uint32_t consume_Windows_Storage_Streams_IDataReader<D>::ReadUInt32() const
{
    uint32_t value{};
    check_hresult(WINRT_SHIM(Windows::Storage::Streams::IDataReader)->ReadUInt32(&value));
    return value;
}

template <typename D> uint64_t consume_Windows_Storage_Streams_IDataReader<D>::ReadUInt64() const
{
    uint64_t value{};
    check_hresult(WINRT_SHIM(Windows::Storage::Streams::IDataReader)->ReadUInt64(&value));
    return value;
}

template <typename D> float consume_Windows_Storage_Streams_IDataReader<D>::ReadSingle() const
{
    float value{};
    check_hresult(WINRT_SHIM(Windows::Storage::Streams::IDataReader)->ReadSingle(&value));
    return value;
}

template <typename D> double consume_Windows_Storage_Streams_IDataReader<D>::ReadDouble() const
{
    double value{};
    check_hresult(WINRT_SHIM(Windows::Storage::Streams::IDataReader)->ReadDouble(&value));
    return value;
}

template <typename D> hstring consume_Windows_Storage_Streams_IDataReader<D>::ReadString(uint32_t codeUnitCount) const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Storage::Streams::IDataReader)->ReadString(codeUnitCount, put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::DateTime consume_Windows_Storage_Streams_IDataReader<D>::ReadDateTime() const
{
    Windows::Foundation::DateTime value{};
    check_hresult(WINRT_SHIM(Windows::Storage::Streams::IDataReader)->ReadDateTime(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::TimeSpan consume_Windows_Storage_Streams_IDataReader<D>::ReadTimeSpan() const
{
    Windows::Foundation::TimeSpan value{};
    check_hresult(WINRT_SHIM(Windows::Storage::Streams::IDataReader)->ReadTimeSpan(put_abi(value)));
    return value;
}

template <typename D> Windows::Storage::Streams::DataReaderLoadOperation consume_Windows_Storage_Streams_IDataReader<D>::LoadAsync(uint32_t count) const
{
    Windows::Storage::Streams::DataReaderLoadOperation operation{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Storage::Streams::IDataReader)->LoadAsync(count, put_abi(operation)));
    return operation;
}

template <typename D> Windows::Storage::Streams::IBuffer consume_Windows_Storage_Streams_IDataReader<D>::DetachBuffer() const
{
    Windows::Storage::Streams::IBuffer buffer{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Storage::Streams::IDataReader)->DetachBuffer(put_abi(buffer)));
    return buffer;
}

template <typename D> Windows::Storage::Streams::IInputStream consume_Windows_Storage_Streams_IDataReader<D>::DetachStream() const
{
    Windows::Storage::Streams::IInputStream stream{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Storage::Streams::IDataReader)->DetachStream(put_abi(stream)));
    return stream;
}

template <typename D> Windows::Storage::Streams::DataReader consume_Windows_Storage_Streams_IDataReaderFactory<D>::CreateDataReader(Windows::Storage::Streams::IInputStream const& inputStream) const
{
    Windows::Storage::Streams::DataReader dataReader{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Storage::Streams::IDataReaderFactory)->CreateDataReader(get_abi(inputStream), put_abi(dataReader)));
    return dataReader;
}

template <typename D> Windows::Storage::Streams::DataReader consume_Windows_Storage_Streams_IDataReaderStatics<D>::FromBuffer(Windows::Storage::Streams::IBuffer const& buffer) const
{
    Windows::Storage::Streams::DataReader dataReader{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Storage::Streams::IDataReaderStatics)->FromBuffer(get_abi(buffer), put_abi(dataReader)));
    return dataReader;
}

template <typename D> uint32_t consume_Windows_Storage_Streams_IDataWriter<D>::UnstoredBufferLength() const
{
    uint32_t value{};
    check_hresult(WINRT_SHIM(Windows::Storage::Streams::IDataWriter)->get_UnstoredBufferLength(&value));
    return value;
}

template <typename D> Windows::Storage::Streams::UnicodeEncoding consume_Windows_Storage_Streams_IDataWriter<D>::UnicodeEncoding() const
{
    Windows::Storage::Streams::UnicodeEncoding value{};
    check_hresult(WINRT_SHIM(Windows::Storage::Streams::IDataWriter)->get_UnicodeEncoding(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_Storage_Streams_IDataWriter<D>::UnicodeEncoding(Windows::Storage::Streams::UnicodeEncoding const& value) const
{
    check_hresult(WINRT_SHIM(Windows::Storage::Streams::IDataWriter)->put_UnicodeEncoding(get_abi(value)));
}

template <typename D> Windows::Storage::Streams::ByteOrder consume_Windows_Storage_Streams_IDataWriter<D>::ByteOrder() const
{
    Windows::Storage::Streams::ByteOrder value{};
    check_hresult(WINRT_SHIM(Windows::Storage::Streams::IDataWriter)->get_ByteOrder(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_Storage_Streams_IDataWriter<D>::ByteOrder(Windows::Storage::Streams::ByteOrder const& value) const
{
    check_hresult(WINRT_SHIM(Windows::Storage::Streams::IDataWriter)->put_ByteOrder(get_abi(value)));
}

template <typename D> void consume_Windows_Storage_Streams_IDataWriter<D>::WriteByte(uint8_t value) const
{
    check_hresult(WINRT_SHIM(Windows::Storage::Streams::IDataWriter)->WriteByte(value));
}

template <typename D> void consume_Windows_Storage_Streams_IDataWriter<D>::WriteBytes(array_view<uint8_t const> value) const
{
    check_hresult(WINRT_SHIM(Windows::Storage::Streams::IDataWriter)->WriteBytes(value.size(), get_abi(value)));
}

template <typename D> void consume_Windows_Storage_Streams_IDataWriter<D>::WriteBuffer(Windows::Storage::Streams::IBuffer const& buffer) const
{
    check_hresult(WINRT_SHIM(Windows::Storage::Streams::IDataWriter)->WriteBuffer(get_abi(buffer)));
}

template <typename D> void consume_Windows_Storage_Streams_IDataWriter<D>::WriteBuffer(Windows::Storage::Streams::IBuffer const& buffer, uint32_t start, uint32_t count) const
{
    check_hresult(WINRT_SHIM(Windows::Storage::Streams::IDataWriter)->WriteBufferRange(get_abi(buffer), start, count));
}

template <typename D> void consume_Windows_Storage_Streams_IDataWriter<D>::WriteBoolean(bool value) const
{
    check_hresult(WINRT_SHIM(Windows::Storage::Streams::IDataWriter)->WriteBoolean(value));
}

template <typename D> void consume_Windows_Storage_Streams_IDataWriter<D>::WriteGuid(winrt::guid const& value) const
{
    check_hresult(WINRT_SHIM(Windows::Storage::Streams::IDataWriter)->WriteGuid(get_abi(value)));
}

template <typename D> void consume_Windows_Storage_Streams_IDataWriter<D>::WriteInt16(int16_t value) const
{
    check_hresult(WINRT_SHIM(Windows::Storage::Streams::IDataWriter)->WriteInt16(value));
}

template <typename D> void consume_Windows_Storage_Streams_IDataWriter<D>::WriteInt32(int32_t value) const
{
    check_hresult(WINRT_SHIM(Windows::Storage::Streams::IDataWriter)->WriteInt32(value));
}

template <typename D> void consume_Windows_Storage_Streams_IDataWriter<D>::WriteInt64(int64_t value) const
{
    check_hresult(WINRT_SHIM(Windows::Storage::Streams::IDataWriter)->WriteInt64(value));
}

template <typename D> void consume_Windows_Storage_Streams_IDataWriter<D>::WriteUInt16(uint16_t value) const
{
    check_hresult(WINRT_SHIM(Windows::Storage::Streams::IDataWriter)->WriteUInt16(value));
}

template <typename D> void consume_Windows_Storage_Streams_IDataWriter<D>::WriteUInt32(uint32_t value) const
{
    check_hresult(WINRT_SHIM(Windows::Storage::Streams::IDataWriter)->WriteUInt32(value));
}

template <typename D> void consume_Windows_Storage_Streams_IDataWriter<D>::WriteUInt64(uint64_t value) const
{
    check_hresult(WINRT_SHIM(Windows::Storage::Streams::IDataWriter)->WriteUInt64(value));
}

template <typename D> void consume_Windows_Storage_Streams_IDataWriter<D>::WriteSingle(float value) const
{
    check_hresult(WINRT_SHIM(Windows::Storage::Streams::IDataWriter)->WriteSingle(value));
}

template <typename D> void consume_Windows_Storage_Streams_IDataWriter<D>::WriteDouble(double value) const
{
    check_hresult(WINRT_SHIM(Windows::Storage::Streams::IDataWriter)->WriteDouble(value));
}

template <typename D> void consume_Windows_Storage_Streams_IDataWriter<D>::WriteDateTime(Windows::Foundation::DateTime const& value) const
{
    check_hresult(WINRT_SHIM(Windows::Storage::Streams::IDataWriter)->WriteDateTime(get_abi(value)));
}

template <typename D> void consume_Windows_Storage_Streams_IDataWriter<D>::WriteTimeSpan(Windows::Foundation::TimeSpan const& value) const
{
    check_hresult(WINRT_SHIM(Windows::Storage::Streams::IDataWriter)->WriteTimeSpan(get_abi(value)));
}

template <typename D> uint32_t consume_Windows_Storage_Streams_IDataWriter<D>::WriteString(param::hstring const& value) const
{
    uint32_t codeUnitCount{};
    check_hresult(WINRT_SHIM(Windows::Storage::Streams::IDataWriter)->WriteString(get_abi(value), &codeUnitCount));
    return codeUnitCount;
}

template <typename D> uint32_t consume_Windows_Storage_Streams_IDataWriter<D>::MeasureString(param::hstring const& value) const
{
    uint32_t codeUnitCount{};
    check_hresult(WINRT_SHIM(Windows::Storage::Streams::IDataWriter)->MeasureString(get_abi(value), &codeUnitCount));
    return codeUnitCount;
}

template <typename D> Windows::Storage::Streams::DataWriterStoreOperation consume_Windows_Storage_Streams_IDataWriter<D>::StoreAsync() const
{
    Windows::Storage::Streams::DataWriterStoreOperation operation{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Storage::Streams::IDataWriter)->StoreAsync(put_abi(operation)));
    return operation;
}

template <typename D> Windows::Foundation::IAsyncOperation<bool> consume_Windows_Storage_Streams_IDataWriter<D>::FlushAsync() const
{
    Windows::Foundation::IAsyncOperation<bool> operation{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Storage::Streams::IDataWriter)->FlushAsync(put_abi(operation)));
    return operation;
}

template <typename D> Windows::Storage::Streams::IBuffer consume_Windows_Storage_Streams_IDataWriter<D>::DetachBuffer() const
{
    Windows::Storage::Streams::IBuffer buffer{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Storage::Streams::IDataWriter)->DetachBuffer(put_abi(buffer)));
    return buffer;
}

template <typename D> Windows::Storage::Streams::IOutputStream consume_Windows_Storage_Streams_IDataWriter<D>::DetachStream() const
{
    Windows::Storage::Streams::IOutputStream outputStream{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Storage::Streams::IDataWriter)->DetachStream(put_abi(outputStream)));
    return outputStream;
}

template <typename D> Windows::Storage::Streams::DataWriter consume_Windows_Storage_Streams_IDataWriterFactory<D>::CreateDataWriter(Windows::Storage::Streams::IOutputStream const& outputStream) const
{
    Windows::Storage::Streams::DataWriter dataWriter{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Storage::Streams::IDataWriterFactory)->CreateDataWriter(get_abi(outputStream), put_abi(dataWriter)));
    return dataWriter;
}

template <typename D> Windows::Foundation::IAsyncOperation<Windows::Storage::Streams::IRandomAccessStream> consume_Windows_Storage_Streams_IFileRandomAccessStreamStatics<D>::OpenAsync(param::hstring const& filePath, Windows::Storage::FileAccessMode const& accessMode) const
{
    Windows::Foundation::IAsyncOperation<Windows::Storage::Streams::IRandomAccessStream> operation{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Storage::Streams::IFileRandomAccessStreamStatics)->OpenAsync(get_abi(filePath), get_abi(accessMode), put_abi(operation)));
    return operation;
}

template <typename D> Windows::Foundation::IAsyncOperation<Windows::Storage::Streams::IRandomAccessStream> consume_Windows_Storage_Streams_IFileRandomAccessStreamStatics<D>::OpenAsync(param::hstring const& filePath, Windows::Storage::FileAccessMode const& accessMode, Windows::Storage::StorageOpenOptions const& sharingOptions, Windows::Storage::Streams::FileOpenDisposition const& openDisposition) const
{
    Windows::Foundation::IAsyncOperation<Windows::Storage::Streams::IRandomAccessStream> operation{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Storage::Streams::IFileRandomAccessStreamStatics)->OpenWithOptionsAsync(get_abi(filePath), get_abi(accessMode), get_abi(sharingOptions), get_abi(openDisposition), put_abi(operation)));
    return operation;
}

template <typename D> Windows::Foundation::IAsyncOperation<Windows::Storage::StorageStreamTransaction> consume_Windows_Storage_Streams_IFileRandomAccessStreamStatics<D>::OpenTransactedWriteAsync(param::hstring const& filePath) const
{
    Windows::Foundation::IAsyncOperation<Windows::Storage::StorageStreamTransaction> operation{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Storage::Streams::IFileRandomAccessStreamStatics)->OpenTransactedWriteAsync(get_abi(filePath), put_abi(operation)));
    return operation;
}

template <typename D> Windows::Foundation::IAsyncOperation<Windows::Storage::StorageStreamTransaction> consume_Windows_Storage_Streams_IFileRandomAccessStreamStatics<D>::OpenTransactedWriteAsync(param::hstring const& filePath, Windows::Storage::StorageOpenOptions const& openOptions, Windows::Storage::Streams::FileOpenDisposition const& openDisposition) const
{
    Windows::Foundation::IAsyncOperation<Windows::Storage::StorageStreamTransaction> operation{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Storage::Streams::IFileRandomAccessStreamStatics)->OpenTransactedWriteWithOptionsAsync(get_abi(filePath), get_abi(openOptions), get_abi(openDisposition), put_abi(operation)));
    return operation;
}

template <typename D> Windows::Foundation::IAsyncOperation<Windows::Storage::Streams::IRandomAccessStream> consume_Windows_Storage_Streams_IFileRandomAccessStreamStatics<D>::OpenForUserAsync(Windows::System::User const& user, param::hstring const& filePath, Windows::Storage::FileAccessMode const& accessMode) const
{
    Windows::Foundation::IAsyncOperation<Windows::Storage::Streams::IRandomAccessStream> operation{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Storage::Streams::IFileRandomAccessStreamStatics)->OpenForUserAsync(get_abi(user), get_abi(filePath), get_abi(accessMode), put_abi(operation)));
    return operation;
}

template <typename D> Windows::Foundation::IAsyncOperation<Windows::Storage::Streams::IRandomAccessStream> consume_Windows_Storage_Streams_IFileRandomAccessStreamStatics<D>::OpenForUserAsync(Windows::System::User const& user, param::hstring const& filePath, Windows::Storage::FileAccessMode const& accessMode, Windows::Storage::StorageOpenOptions const& sharingOptions, Windows::Storage::Streams::FileOpenDisposition const& openDisposition) const
{
    Windows::Foundation::IAsyncOperation<Windows::Storage::Streams::IRandomAccessStream> operation{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Storage::Streams::IFileRandomAccessStreamStatics)->OpenForUserWithOptionsAsync(get_abi(user), get_abi(filePath), get_abi(accessMode), get_abi(sharingOptions), get_abi(openDisposition), put_abi(operation)));
    return operation;
}

template <typename D> Windows::Foundation::IAsyncOperation<Windows::Storage::StorageStreamTransaction> consume_Windows_Storage_Streams_IFileRandomAccessStreamStatics<D>::OpenTransactedWriteForUserAsync(Windows::System::User const& user, param::hstring const& filePath) const
{
    Windows::Foundation::IAsyncOperation<Windows::Storage::StorageStreamTransaction> operation{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Storage::Streams::IFileRandomAccessStreamStatics)->OpenTransactedWriteForUserAsync(get_abi(user), get_abi(filePath), put_abi(operation)));
    return operation;
}

template <typename D> Windows::Foundation::IAsyncOperation<Windows::Storage::StorageStreamTransaction> consume_Windows_Storage_Streams_IFileRandomAccessStreamStatics<D>::OpenTransactedWriteForUserAsync(Windows::System::User const& user, param::hstring const& filePath, Windows::Storage::StorageOpenOptions const& openOptions, Windows::Storage::Streams::FileOpenDisposition const& openDisposition) const
{
    Windows::Foundation::IAsyncOperation<Windows::Storage::StorageStreamTransaction> operation{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Storage::Streams::IFileRandomAccessStreamStatics)->OpenTransactedWriteForUserWithOptionsAsync(get_abi(user), get_abi(filePath), get_abi(openOptions), get_abi(openDisposition), put_abi(operation)));
    return operation;
}

template <typename D> Windows::Foundation::IAsyncOperationWithProgress<Windows::Storage::Streams::IBuffer, uint32_t> consume_Windows_Storage_Streams_IInputStream<D>::ReadAsync(Windows::Storage::Streams::IBuffer const& buffer, uint32_t count, Windows::Storage::Streams::InputStreamOptions const& options) const
{
    Windows::Foundation::IAsyncOperationWithProgress<Windows::Storage::Streams::IBuffer, uint32_t> operation{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Storage::Streams::IInputStream)->ReadAsync(get_abi(buffer), count, get_abi(options), put_abi(operation)));
    return operation;
}

template <typename D> Windows::Foundation::IAsyncOperation<Windows::Storage::Streams::IInputStream> consume_Windows_Storage_Streams_IInputStreamReference<D>::OpenSequentialReadAsync() const
{
    Windows::Foundation::IAsyncOperation<Windows::Storage::Streams::IInputStream> operation{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Storage::Streams::IInputStreamReference)->OpenSequentialReadAsync(put_abi(operation)));
    return operation;
}

template <typename D> Windows::Foundation::IAsyncOperationWithProgress<uint32_t, uint32_t> consume_Windows_Storage_Streams_IOutputStream<D>::WriteAsync(Windows::Storage::Streams::IBuffer const& buffer) const
{
    Windows::Foundation::IAsyncOperationWithProgress<uint32_t, uint32_t> operation{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Storage::Streams::IOutputStream)->WriteAsync(get_abi(buffer), put_abi(operation)));
    return operation;
}

template <typename D> Windows::Foundation::IAsyncOperation<bool> consume_Windows_Storage_Streams_IOutputStream<D>::FlushAsync() const
{
    Windows::Foundation::IAsyncOperation<bool> operation{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Storage::Streams::IOutputStream)->FlushAsync(put_abi(operation)));
    return operation;
}

template <typename D> uint64_t consume_Windows_Storage_Streams_IRandomAccessStream<D>::Size() const
{
    uint64_t value{};
    check_hresult(WINRT_SHIM(Windows::Storage::Streams::IRandomAccessStream)->get_Size(&value));
    return value;
}

template <typename D> void consume_Windows_Storage_Streams_IRandomAccessStream<D>::Size(uint64_t value) const
{
    check_hresult(WINRT_SHIM(Windows::Storage::Streams::IRandomAccessStream)->put_Size(value));
}

template <typename D> Windows::Storage::Streams::IInputStream consume_Windows_Storage_Streams_IRandomAccessStream<D>::GetInputStreamAt(uint64_t position) const
{
    Windows::Storage::Streams::IInputStream stream{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Storage::Streams::IRandomAccessStream)->GetInputStreamAt(position, put_abi(stream)));
    return stream;
}

template <typename D> Windows::Storage::Streams::IOutputStream consume_Windows_Storage_Streams_IRandomAccessStream<D>::GetOutputStreamAt(uint64_t position) const
{
    Windows::Storage::Streams::IOutputStream stream{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Storage::Streams::IRandomAccessStream)->GetOutputStreamAt(position, put_abi(stream)));
    return stream;
}

template <typename D> uint64_t consume_Windows_Storage_Streams_IRandomAccessStream<D>::Position() const
{
    uint64_t value{};
    check_hresult(WINRT_SHIM(Windows::Storage::Streams::IRandomAccessStream)->get_Position(&value));
    return value;
}

template <typename D> void consume_Windows_Storage_Streams_IRandomAccessStream<D>::Seek(uint64_t position) const
{
    check_hresult(WINRT_SHIM(Windows::Storage::Streams::IRandomAccessStream)->Seek(position));
}

template <typename D> Windows::Storage::Streams::IRandomAccessStream consume_Windows_Storage_Streams_IRandomAccessStream<D>::CloneStream() const
{
    Windows::Storage::Streams::IRandomAccessStream stream{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Storage::Streams::IRandomAccessStream)->CloneStream(put_abi(stream)));
    return stream;
}

template <typename D> bool consume_Windows_Storage_Streams_IRandomAccessStream<D>::CanRead() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::Storage::Streams::IRandomAccessStream)->get_CanRead(&value));
    return value;
}

template <typename D> bool consume_Windows_Storage_Streams_IRandomAccessStream<D>::CanWrite() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::Storage::Streams::IRandomAccessStream)->get_CanWrite(&value));
    return value;
}

template <typename D> Windows::Foundation::IAsyncOperation<Windows::Storage::Streams::IRandomAccessStreamWithContentType> consume_Windows_Storage_Streams_IRandomAccessStreamReference<D>::OpenReadAsync() const
{
    Windows::Foundation::IAsyncOperation<Windows::Storage::Streams::IRandomAccessStreamWithContentType> operation{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Storage::Streams::IRandomAccessStreamReference)->OpenReadAsync(put_abi(operation)));
    return operation;
}

template <typename D> Windows::Storage::Streams::RandomAccessStreamReference consume_Windows_Storage_Streams_IRandomAccessStreamReferenceStatics<D>::CreateFromFile(Windows::Storage::IStorageFile const& file) const
{
    Windows::Storage::Streams::RandomAccessStreamReference streamReference{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Storage::Streams::IRandomAccessStreamReferenceStatics)->CreateFromFile(get_abi(file), put_abi(streamReference)));
    return streamReference;
}

template <typename D> Windows::Storage::Streams::RandomAccessStreamReference consume_Windows_Storage_Streams_IRandomAccessStreamReferenceStatics<D>::CreateFromUri(Windows::Foundation::Uri const& uri) const
{
    Windows::Storage::Streams::RandomAccessStreamReference streamReference{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Storage::Streams::IRandomAccessStreamReferenceStatics)->CreateFromUri(get_abi(uri), put_abi(streamReference)));
    return streamReference;
}

template <typename D> Windows::Storage::Streams::RandomAccessStreamReference consume_Windows_Storage_Streams_IRandomAccessStreamReferenceStatics<D>::CreateFromStream(Windows::Storage::Streams::IRandomAccessStream const& stream) const
{
    Windows::Storage::Streams::RandomAccessStreamReference streamReference{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Storage::Streams::IRandomAccessStreamReferenceStatics)->CreateFromStream(get_abi(stream), put_abi(streamReference)));
    return streamReference;
}

template <typename D> Windows::Foundation::IAsyncOperationWithProgress<uint64_t, uint64_t> consume_Windows_Storage_Streams_IRandomAccessStreamStatics<D>::CopyAsync(Windows::Storage::Streams::IInputStream const& source, Windows::Storage::Streams::IOutputStream const& destination) const
{
    Windows::Foundation::IAsyncOperationWithProgress<uint64_t, uint64_t> operation{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Storage::Streams::IRandomAccessStreamStatics)->CopyAsync(get_abi(source), get_abi(destination), put_abi(operation)));
    return operation;
}

template <typename D> Windows::Foundation::IAsyncOperationWithProgress<uint64_t, uint64_t> consume_Windows_Storage_Streams_IRandomAccessStreamStatics<D>::CopyAsync(Windows::Storage::Streams::IInputStream const& source, Windows::Storage::Streams::IOutputStream const& destination, uint64_t bytesToCopy) const
{
    Windows::Foundation::IAsyncOperationWithProgress<uint64_t, uint64_t> operation{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Storage::Streams::IRandomAccessStreamStatics)->CopySizeAsync(get_abi(source), get_abi(destination), bytesToCopy, put_abi(operation)));
    return operation;
}

template <typename D> Windows::Foundation::IAsyncOperationWithProgress<uint64_t, uint64_t> consume_Windows_Storage_Streams_IRandomAccessStreamStatics<D>::CopyAndCloseAsync(Windows::Storage::Streams::IInputStream const& source, Windows::Storage::Streams::IOutputStream const& destination) const
{
    Windows::Foundation::IAsyncOperationWithProgress<uint64_t, uint64_t> operation{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Storage::Streams::IRandomAccessStreamStatics)->CopyAndCloseAsync(get_abi(source), get_abi(destination), put_abi(operation)));
    return operation;
}

template <typename D>
struct produce<D, Windows::Storage::Streams::IBuffer> : produce_base<D, Windows::Storage::Streams::IBuffer>
{
    int32_t WINRT_CALL get_Capacity(uint32_t* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Capacity, WINRT_WRAP(uint32_t));
            *value = detach_from<uint32_t>(this->shim().Capacity());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Length(uint32_t* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Length, WINRT_WRAP(uint32_t));
            *value = detach_from<uint32_t>(this->shim().Length());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_Length(uint32_t value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Length, WINRT_WRAP(void), uint32_t);
            this->shim().Length(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Storage::Streams::IBufferFactory> : produce_base<D, Windows::Storage::Streams::IBufferFactory>
{
    int32_t WINRT_CALL Create(uint32_t capacity, void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Create, WINRT_WRAP(Windows::Storage::Streams::Buffer), uint32_t);
            *value = detach_from<Windows::Storage::Streams::Buffer>(this->shim().Create(capacity));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Storage::Streams::IBufferStatics> : produce_base<D, Windows::Storage::Streams::IBufferStatics>
{
    int32_t WINRT_CALL CreateCopyFromMemoryBuffer(void* input, void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CreateCopyFromMemoryBuffer, WINRT_WRAP(Windows::Storage::Streams::Buffer), Windows::Foundation::IMemoryBuffer const&);
            *value = detach_from<Windows::Storage::Streams::Buffer>(this->shim().CreateCopyFromMemoryBuffer(*reinterpret_cast<Windows::Foundation::IMemoryBuffer const*>(&input)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL CreateMemoryBufferOverIBuffer(void* input, void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CreateMemoryBufferOverIBuffer, WINRT_WRAP(Windows::Foundation::MemoryBuffer), Windows::Storage::Streams::IBuffer const&);
            *value = detach_from<Windows::Foundation::MemoryBuffer>(this->shim().CreateMemoryBufferOverIBuffer(*reinterpret_cast<Windows::Storage::Streams::IBuffer const*>(&input)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Storage::Streams::IContentTypeProvider> : produce_base<D, Windows::Storage::Streams::IContentTypeProvider>
{
    int32_t WINRT_CALL get_ContentType(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ContentType, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().ContentType());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Storage::Streams::IDataReader> : produce_base<D, Windows::Storage::Streams::IDataReader>
{
    int32_t WINRT_CALL get_UnconsumedBufferLength(uint32_t* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(UnconsumedBufferLength, WINRT_WRAP(uint32_t));
            *value = detach_from<uint32_t>(this->shim().UnconsumedBufferLength());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_UnicodeEncoding(Windows::Storage::Streams::UnicodeEncoding* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(UnicodeEncoding, WINRT_WRAP(Windows::Storage::Streams::UnicodeEncoding));
            *value = detach_from<Windows::Storage::Streams::UnicodeEncoding>(this->shim().UnicodeEncoding());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_UnicodeEncoding(Windows::Storage::Streams::UnicodeEncoding value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(UnicodeEncoding, WINRT_WRAP(void), Windows::Storage::Streams::UnicodeEncoding const&);
            this->shim().UnicodeEncoding(*reinterpret_cast<Windows::Storage::Streams::UnicodeEncoding const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_ByteOrder(Windows::Storage::Streams::ByteOrder* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ByteOrder, WINRT_WRAP(Windows::Storage::Streams::ByteOrder));
            *value = detach_from<Windows::Storage::Streams::ByteOrder>(this->shim().ByteOrder());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_ByteOrder(Windows::Storage::Streams::ByteOrder value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ByteOrder, WINRT_WRAP(void), Windows::Storage::Streams::ByteOrder const&);
            this->shim().ByteOrder(*reinterpret_cast<Windows::Storage::Streams::ByteOrder const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_InputStreamOptions(Windows::Storage::Streams::InputStreamOptions* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(InputStreamOptions, WINRT_WRAP(Windows::Storage::Streams::InputStreamOptions));
            *value = detach_from<Windows::Storage::Streams::InputStreamOptions>(this->shim().InputStreamOptions());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_InputStreamOptions(Windows::Storage::Streams::InputStreamOptions value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(InputStreamOptions, WINRT_WRAP(void), Windows::Storage::Streams::InputStreamOptions const&);
            this->shim().InputStreamOptions(*reinterpret_cast<Windows::Storage::Streams::InputStreamOptions const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL ReadByte(uint8_t* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ReadByte, WINRT_WRAP(uint8_t));
            *value = detach_from<uint8_t>(this->shim().ReadByte());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL ReadBytes(uint32_t __valueSize, uint8_t* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ReadBytes, WINRT_WRAP(void), array_view<uint8_t>);
            this->shim().ReadBytes(array_view<uint8_t>(reinterpret_cast<uint8_t*>(value), reinterpret_cast<uint8_t*>(value) + __valueSize));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL ReadBuffer(uint32_t length, void** buffer) noexcept final
    {
        try
        {
            *buffer = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ReadBuffer, WINRT_WRAP(Windows::Storage::Streams::IBuffer), uint32_t);
            *buffer = detach_from<Windows::Storage::Streams::IBuffer>(this->shim().ReadBuffer(length));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL ReadBoolean(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ReadBoolean, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().ReadBoolean());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL ReadGuid(winrt::guid* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ReadGuid, WINRT_WRAP(winrt::guid));
            *value = detach_from<winrt::guid>(this->shim().ReadGuid());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL ReadInt16(int16_t* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ReadInt16, WINRT_WRAP(int16_t));
            *value = detach_from<int16_t>(this->shim().ReadInt16());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL ReadInt32(int32_t* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ReadInt32, WINRT_WRAP(int32_t));
            *value = detach_from<int32_t>(this->shim().ReadInt32());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL ReadInt64(int64_t* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ReadInt64, WINRT_WRAP(int64_t));
            *value = detach_from<int64_t>(this->shim().ReadInt64());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL ReadUInt16(uint16_t* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ReadUInt16, WINRT_WRAP(uint16_t));
            *value = detach_from<uint16_t>(this->shim().ReadUInt16());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL ReadUInt32(uint32_t* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ReadUInt32, WINRT_WRAP(uint32_t));
            *value = detach_from<uint32_t>(this->shim().ReadUInt32());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL ReadUInt64(uint64_t* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ReadUInt64, WINRT_WRAP(uint64_t));
            *value = detach_from<uint64_t>(this->shim().ReadUInt64());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL ReadSingle(float* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ReadSingle, WINRT_WRAP(float));
            *value = detach_from<float>(this->shim().ReadSingle());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL ReadDouble(double* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ReadDouble, WINRT_WRAP(double));
            *value = detach_from<double>(this->shim().ReadDouble());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL ReadString(uint32_t codeUnitCount, void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ReadString, WINRT_WRAP(hstring), uint32_t);
            *value = detach_from<hstring>(this->shim().ReadString(codeUnitCount));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL ReadDateTime(Windows::Foundation::DateTime* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ReadDateTime, WINRT_WRAP(Windows::Foundation::DateTime));
            *value = detach_from<Windows::Foundation::DateTime>(this->shim().ReadDateTime());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL ReadTimeSpan(Windows::Foundation::TimeSpan* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ReadTimeSpan, WINRT_WRAP(Windows::Foundation::TimeSpan));
            *value = detach_from<Windows::Foundation::TimeSpan>(this->shim().ReadTimeSpan());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL LoadAsync(uint32_t count, void** operation) noexcept final
    {
        try
        {
            *operation = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(LoadAsync, WINRT_WRAP(Windows::Storage::Streams::DataReaderLoadOperation), uint32_t);
            *operation = detach_from<Windows::Storage::Streams::DataReaderLoadOperation>(this->shim().LoadAsync(count));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL DetachBuffer(void** buffer) noexcept final
    {
        try
        {
            *buffer = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(DetachBuffer, WINRT_WRAP(Windows::Storage::Streams::IBuffer));
            *buffer = detach_from<Windows::Storage::Streams::IBuffer>(this->shim().DetachBuffer());
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
            WINRT_ASSERT_DECLARATION(DetachStream, WINRT_WRAP(Windows::Storage::Streams::IInputStream));
            *stream = detach_from<Windows::Storage::Streams::IInputStream>(this->shim().DetachStream());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Storage::Streams::IDataReaderFactory> : produce_base<D, Windows::Storage::Streams::IDataReaderFactory>
{
    int32_t WINRT_CALL CreateDataReader(void* inputStream, void** dataReader) noexcept final
    {
        try
        {
            *dataReader = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CreateDataReader, WINRT_WRAP(Windows::Storage::Streams::DataReader), Windows::Storage::Streams::IInputStream const&);
            *dataReader = detach_from<Windows::Storage::Streams::DataReader>(this->shim().CreateDataReader(*reinterpret_cast<Windows::Storage::Streams::IInputStream const*>(&inputStream)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Storage::Streams::IDataReaderStatics> : produce_base<D, Windows::Storage::Streams::IDataReaderStatics>
{
    int32_t WINRT_CALL FromBuffer(void* buffer, void** dataReader) noexcept final
    {
        try
        {
            *dataReader = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(FromBuffer, WINRT_WRAP(Windows::Storage::Streams::DataReader), Windows::Storage::Streams::IBuffer const&);
            *dataReader = detach_from<Windows::Storage::Streams::DataReader>(this->shim().FromBuffer(*reinterpret_cast<Windows::Storage::Streams::IBuffer const*>(&buffer)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Storage::Streams::IDataWriter> : produce_base<D, Windows::Storage::Streams::IDataWriter>
{
    int32_t WINRT_CALL get_UnstoredBufferLength(uint32_t* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(UnstoredBufferLength, WINRT_WRAP(uint32_t));
            *value = detach_from<uint32_t>(this->shim().UnstoredBufferLength());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_UnicodeEncoding(Windows::Storage::Streams::UnicodeEncoding* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(UnicodeEncoding, WINRT_WRAP(Windows::Storage::Streams::UnicodeEncoding));
            *value = detach_from<Windows::Storage::Streams::UnicodeEncoding>(this->shim().UnicodeEncoding());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_UnicodeEncoding(Windows::Storage::Streams::UnicodeEncoding value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(UnicodeEncoding, WINRT_WRAP(void), Windows::Storage::Streams::UnicodeEncoding const&);
            this->shim().UnicodeEncoding(*reinterpret_cast<Windows::Storage::Streams::UnicodeEncoding const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_ByteOrder(Windows::Storage::Streams::ByteOrder* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ByteOrder, WINRT_WRAP(Windows::Storage::Streams::ByteOrder));
            *value = detach_from<Windows::Storage::Streams::ByteOrder>(this->shim().ByteOrder());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_ByteOrder(Windows::Storage::Streams::ByteOrder value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ByteOrder, WINRT_WRAP(void), Windows::Storage::Streams::ByteOrder const&);
            this->shim().ByteOrder(*reinterpret_cast<Windows::Storage::Streams::ByteOrder const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL WriteByte(uint8_t value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(WriteByte, WINRT_WRAP(void), uint8_t);
            this->shim().WriteByte(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL WriteBytes(uint32_t __valueSize, uint8_t* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(WriteBytes, WINRT_WRAP(void), array_view<uint8_t const>);
            this->shim().WriteBytes(array_view<uint8_t const>(reinterpret_cast<uint8_t const *>(value), reinterpret_cast<uint8_t const *>(value) + __valueSize));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL WriteBuffer(void* buffer) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(WriteBuffer, WINRT_WRAP(void), Windows::Storage::Streams::IBuffer const&);
            this->shim().WriteBuffer(*reinterpret_cast<Windows::Storage::Streams::IBuffer const*>(&buffer));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL WriteBufferRange(void* buffer, uint32_t start, uint32_t count) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(WriteBuffer, WINRT_WRAP(void), Windows::Storage::Streams::IBuffer const&, uint32_t, uint32_t);
            this->shim().WriteBuffer(*reinterpret_cast<Windows::Storage::Streams::IBuffer const*>(&buffer), start, count);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL WriteBoolean(bool value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(WriteBoolean, WINRT_WRAP(void), bool);
            this->shim().WriteBoolean(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL WriteGuid(winrt::guid value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(WriteGuid, WINRT_WRAP(void), winrt::guid const&);
            this->shim().WriteGuid(*reinterpret_cast<winrt::guid const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL WriteInt16(int16_t value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(WriteInt16, WINRT_WRAP(void), int16_t);
            this->shim().WriteInt16(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL WriteInt32(int32_t value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(WriteInt32, WINRT_WRAP(void), int32_t);
            this->shim().WriteInt32(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL WriteInt64(int64_t value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(WriteInt64, WINRT_WRAP(void), int64_t);
            this->shim().WriteInt64(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL WriteUInt16(uint16_t value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(WriteUInt16, WINRT_WRAP(void), uint16_t);
            this->shim().WriteUInt16(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL WriteUInt32(uint32_t value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(WriteUInt32, WINRT_WRAP(void), uint32_t);
            this->shim().WriteUInt32(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL WriteUInt64(uint64_t value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(WriteUInt64, WINRT_WRAP(void), uint64_t);
            this->shim().WriteUInt64(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL WriteSingle(float value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(WriteSingle, WINRT_WRAP(void), float);
            this->shim().WriteSingle(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL WriteDouble(double value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(WriteDouble, WINRT_WRAP(void), double);
            this->shim().WriteDouble(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL WriteDateTime(Windows::Foundation::DateTime value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(WriteDateTime, WINRT_WRAP(void), Windows::Foundation::DateTime const&);
            this->shim().WriteDateTime(*reinterpret_cast<Windows::Foundation::DateTime const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL WriteTimeSpan(Windows::Foundation::TimeSpan value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(WriteTimeSpan, WINRT_WRAP(void), Windows::Foundation::TimeSpan const&);
            this->shim().WriteTimeSpan(*reinterpret_cast<Windows::Foundation::TimeSpan const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL WriteString(void* value, uint32_t* codeUnitCount) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(WriteString, WINRT_WRAP(uint32_t), hstring const&);
            *codeUnitCount = detach_from<uint32_t>(this->shim().WriteString(*reinterpret_cast<hstring const*>(&value)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL MeasureString(void* value, uint32_t* codeUnitCount) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(MeasureString, WINRT_WRAP(uint32_t), hstring const&);
            *codeUnitCount = detach_from<uint32_t>(this->shim().MeasureString(*reinterpret_cast<hstring const*>(&value)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL StoreAsync(void** operation) noexcept final
    {
        try
        {
            *operation = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(StoreAsync, WINRT_WRAP(Windows::Storage::Streams::DataWriterStoreOperation));
            *operation = detach_from<Windows::Storage::Streams::DataWriterStoreOperation>(this->shim().StoreAsync());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL FlushAsync(void** operation) noexcept final
    {
        try
        {
            *operation = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(FlushAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<bool>));
            *operation = detach_from<Windows::Foundation::IAsyncOperation<bool>>(this->shim().FlushAsync());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL DetachBuffer(void** buffer) noexcept final
    {
        try
        {
            *buffer = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(DetachBuffer, WINRT_WRAP(Windows::Storage::Streams::IBuffer));
            *buffer = detach_from<Windows::Storage::Streams::IBuffer>(this->shim().DetachBuffer());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL DetachStream(void** outputStream) noexcept final
    {
        try
        {
            *outputStream = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(DetachStream, WINRT_WRAP(Windows::Storage::Streams::IOutputStream));
            *outputStream = detach_from<Windows::Storage::Streams::IOutputStream>(this->shim().DetachStream());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Storage::Streams::IDataWriterFactory> : produce_base<D, Windows::Storage::Streams::IDataWriterFactory>
{
    int32_t WINRT_CALL CreateDataWriter(void* outputStream, void** dataWriter) noexcept final
    {
        try
        {
            *dataWriter = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CreateDataWriter, WINRT_WRAP(Windows::Storage::Streams::DataWriter), Windows::Storage::Streams::IOutputStream const&);
            *dataWriter = detach_from<Windows::Storage::Streams::DataWriter>(this->shim().CreateDataWriter(*reinterpret_cast<Windows::Storage::Streams::IOutputStream const*>(&outputStream)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Storage::Streams::IFileRandomAccessStreamStatics> : produce_base<D, Windows::Storage::Streams::IFileRandomAccessStreamStatics>
{
    int32_t WINRT_CALL OpenAsync(void* filePath, Windows::Storage::FileAccessMode accessMode, void** operation) noexcept final
    {
        try
        {
            *operation = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(OpenAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<Windows::Storage::Streams::IRandomAccessStream>), hstring const, Windows::Storage::FileAccessMode const);
            *operation = detach_from<Windows::Foundation::IAsyncOperation<Windows::Storage::Streams::IRandomAccessStream>>(this->shim().OpenAsync(*reinterpret_cast<hstring const*>(&filePath), *reinterpret_cast<Windows::Storage::FileAccessMode const*>(&accessMode)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL OpenWithOptionsAsync(void* filePath, Windows::Storage::FileAccessMode accessMode, Windows::Storage::StorageOpenOptions sharingOptions, Windows::Storage::Streams::FileOpenDisposition openDisposition, void** operation) noexcept final
    {
        try
        {
            *operation = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(OpenAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<Windows::Storage::Streams::IRandomAccessStream>), hstring const, Windows::Storage::FileAccessMode const, Windows::Storage::StorageOpenOptions const, Windows::Storage::Streams::FileOpenDisposition const);
            *operation = detach_from<Windows::Foundation::IAsyncOperation<Windows::Storage::Streams::IRandomAccessStream>>(this->shim().OpenAsync(*reinterpret_cast<hstring const*>(&filePath), *reinterpret_cast<Windows::Storage::FileAccessMode const*>(&accessMode), *reinterpret_cast<Windows::Storage::StorageOpenOptions const*>(&sharingOptions), *reinterpret_cast<Windows::Storage::Streams::FileOpenDisposition const*>(&openDisposition)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL OpenTransactedWriteAsync(void* filePath, void** operation) noexcept final
    {
        try
        {
            *operation = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(OpenTransactedWriteAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<Windows::Storage::StorageStreamTransaction>), hstring const);
            *operation = detach_from<Windows::Foundation::IAsyncOperation<Windows::Storage::StorageStreamTransaction>>(this->shim().OpenTransactedWriteAsync(*reinterpret_cast<hstring const*>(&filePath)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL OpenTransactedWriteWithOptionsAsync(void* filePath, Windows::Storage::StorageOpenOptions openOptions, Windows::Storage::Streams::FileOpenDisposition openDisposition, void** operation) noexcept final
    {
        try
        {
            *operation = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(OpenTransactedWriteAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<Windows::Storage::StorageStreamTransaction>), hstring const, Windows::Storage::StorageOpenOptions const, Windows::Storage::Streams::FileOpenDisposition const);
            *operation = detach_from<Windows::Foundation::IAsyncOperation<Windows::Storage::StorageStreamTransaction>>(this->shim().OpenTransactedWriteAsync(*reinterpret_cast<hstring const*>(&filePath), *reinterpret_cast<Windows::Storage::StorageOpenOptions const*>(&openOptions), *reinterpret_cast<Windows::Storage::Streams::FileOpenDisposition const*>(&openDisposition)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL OpenForUserAsync(void* user, void* filePath, Windows::Storage::FileAccessMode accessMode, void** operation) noexcept final
    {
        try
        {
            *operation = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(OpenForUserAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<Windows::Storage::Streams::IRandomAccessStream>), Windows::System::User const, hstring const, Windows::Storage::FileAccessMode const);
            *operation = detach_from<Windows::Foundation::IAsyncOperation<Windows::Storage::Streams::IRandomAccessStream>>(this->shim().OpenForUserAsync(*reinterpret_cast<Windows::System::User const*>(&user), *reinterpret_cast<hstring const*>(&filePath), *reinterpret_cast<Windows::Storage::FileAccessMode const*>(&accessMode)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL OpenForUserWithOptionsAsync(void* user, void* filePath, Windows::Storage::FileAccessMode accessMode, Windows::Storage::StorageOpenOptions sharingOptions, Windows::Storage::Streams::FileOpenDisposition openDisposition, void** operation) noexcept final
    {
        try
        {
            *operation = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(OpenForUserAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<Windows::Storage::Streams::IRandomAccessStream>), Windows::System::User const, hstring const, Windows::Storage::FileAccessMode const, Windows::Storage::StorageOpenOptions const, Windows::Storage::Streams::FileOpenDisposition const);
            *operation = detach_from<Windows::Foundation::IAsyncOperation<Windows::Storage::Streams::IRandomAccessStream>>(this->shim().OpenForUserAsync(*reinterpret_cast<Windows::System::User const*>(&user), *reinterpret_cast<hstring const*>(&filePath), *reinterpret_cast<Windows::Storage::FileAccessMode const*>(&accessMode), *reinterpret_cast<Windows::Storage::StorageOpenOptions const*>(&sharingOptions), *reinterpret_cast<Windows::Storage::Streams::FileOpenDisposition const*>(&openDisposition)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL OpenTransactedWriteForUserAsync(void* user, void* filePath, void** operation) noexcept final
    {
        try
        {
            *operation = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(OpenTransactedWriteForUserAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<Windows::Storage::StorageStreamTransaction>), Windows::System::User const, hstring const);
            *operation = detach_from<Windows::Foundation::IAsyncOperation<Windows::Storage::StorageStreamTransaction>>(this->shim().OpenTransactedWriteForUserAsync(*reinterpret_cast<Windows::System::User const*>(&user), *reinterpret_cast<hstring const*>(&filePath)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL OpenTransactedWriteForUserWithOptionsAsync(void* user, void* filePath, Windows::Storage::StorageOpenOptions openOptions, Windows::Storage::Streams::FileOpenDisposition openDisposition, void** operation) noexcept final
    {
        try
        {
            *operation = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(OpenTransactedWriteForUserAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<Windows::Storage::StorageStreamTransaction>), Windows::System::User const, hstring const, Windows::Storage::StorageOpenOptions const, Windows::Storage::Streams::FileOpenDisposition const);
            *operation = detach_from<Windows::Foundation::IAsyncOperation<Windows::Storage::StorageStreamTransaction>>(this->shim().OpenTransactedWriteForUserAsync(*reinterpret_cast<Windows::System::User const*>(&user), *reinterpret_cast<hstring const*>(&filePath), *reinterpret_cast<Windows::Storage::StorageOpenOptions const*>(&openOptions), *reinterpret_cast<Windows::Storage::Streams::FileOpenDisposition const*>(&openDisposition)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Storage::Streams::IInputStream> : produce_base<D, Windows::Storage::Streams::IInputStream>
{
    int32_t WINRT_CALL ReadAsync(void* buffer, uint32_t count, Windows::Storage::Streams::InputStreamOptions options, void** operation) noexcept final
    {
        try
        {
            *operation = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ReadAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperationWithProgress<Windows::Storage::Streams::IBuffer, uint32_t>), Windows::Storage::Streams::IBuffer const, uint32_t, Windows::Storage::Streams::InputStreamOptions const);
            *operation = detach_from<Windows::Foundation::IAsyncOperationWithProgress<Windows::Storage::Streams::IBuffer, uint32_t>>(this->shim().ReadAsync(*reinterpret_cast<Windows::Storage::Streams::IBuffer const*>(&buffer), count, *reinterpret_cast<Windows::Storage::Streams::InputStreamOptions const*>(&options)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Storage::Streams::IInputStreamReference> : produce_base<D, Windows::Storage::Streams::IInputStreamReference>
{
    int32_t WINRT_CALL OpenSequentialReadAsync(void** operation) noexcept final
    {
        try
        {
            *operation = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(OpenSequentialReadAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<Windows::Storage::Streams::IInputStream>));
            *operation = detach_from<Windows::Foundation::IAsyncOperation<Windows::Storage::Streams::IInputStream>>(this->shim().OpenSequentialReadAsync());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Storage::Streams::IOutputStream> : produce_base<D, Windows::Storage::Streams::IOutputStream>
{
    int32_t WINRT_CALL WriteAsync(void* buffer, void** operation) noexcept final
    {
        try
        {
            *operation = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(WriteAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperationWithProgress<uint32_t, uint32_t>), Windows::Storage::Streams::IBuffer const);
            *operation = detach_from<Windows::Foundation::IAsyncOperationWithProgress<uint32_t, uint32_t>>(this->shim().WriteAsync(*reinterpret_cast<Windows::Storage::Streams::IBuffer const*>(&buffer)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL FlushAsync(void** operation) noexcept final
    {
        try
        {
            *operation = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(FlushAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<bool>));
            *operation = detach_from<Windows::Foundation::IAsyncOperation<bool>>(this->shim().FlushAsync());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Storage::Streams::IRandomAccessStream> : produce_base<D, Windows::Storage::Streams::IRandomAccessStream>
{
    int32_t WINRT_CALL get_Size(uint64_t* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Size, WINRT_WRAP(uint64_t));
            *value = detach_from<uint64_t>(this->shim().Size());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_Size(uint64_t value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Size, WINRT_WRAP(void), uint64_t);
            this->shim().Size(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL GetInputStreamAt(uint64_t position, void** stream) noexcept final
    {
        try
        {
            *stream = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetInputStreamAt, WINRT_WRAP(Windows::Storage::Streams::IInputStream), uint64_t);
            *stream = detach_from<Windows::Storage::Streams::IInputStream>(this->shim().GetInputStreamAt(position));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL GetOutputStreamAt(uint64_t position, void** stream) noexcept final
    {
        try
        {
            *stream = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetOutputStreamAt, WINRT_WRAP(Windows::Storage::Streams::IOutputStream), uint64_t);
            *stream = detach_from<Windows::Storage::Streams::IOutputStream>(this->shim().GetOutputStreamAt(position));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Position(uint64_t* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Position, WINRT_WRAP(uint64_t));
            *value = detach_from<uint64_t>(this->shim().Position());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL Seek(uint64_t position) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Seek, WINRT_WRAP(void), uint64_t);
            this->shim().Seek(position);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL CloneStream(void** stream) noexcept final
    {
        try
        {
            *stream = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CloneStream, WINRT_WRAP(Windows::Storage::Streams::IRandomAccessStream));
            *stream = detach_from<Windows::Storage::Streams::IRandomAccessStream>(this->shim().CloneStream());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_CanRead(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CanRead, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().CanRead());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_CanWrite(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CanWrite, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().CanWrite());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Storage::Streams::IRandomAccessStreamReference> : produce_base<D, Windows::Storage::Streams::IRandomAccessStreamReference>
{
    int32_t WINRT_CALL OpenReadAsync(void** operation) noexcept final
    {
        try
        {
            *operation = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(OpenReadAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<Windows::Storage::Streams::IRandomAccessStreamWithContentType>));
            *operation = detach_from<Windows::Foundation::IAsyncOperation<Windows::Storage::Streams::IRandomAccessStreamWithContentType>>(this->shim().OpenReadAsync());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Storage::Streams::IRandomAccessStreamReferenceStatics> : produce_base<D, Windows::Storage::Streams::IRandomAccessStreamReferenceStatics>
{
    int32_t WINRT_CALL CreateFromFile(void* file, void** streamReference) noexcept final
    {
        try
        {
            *streamReference = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CreateFromFile, WINRT_WRAP(Windows::Storage::Streams::RandomAccessStreamReference), Windows::Storage::IStorageFile const&);
            *streamReference = detach_from<Windows::Storage::Streams::RandomAccessStreamReference>(this->shim().CreateFromFile(*reinterpret_cast<Windows::Storage::IStorageFile const*>(&file)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL CreateFromUri(void* uri, void** streamReference) noexcept final
    {
        try
        {
            *streamReference = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CreateFromUri, WINRT_WRAP(Windows::Storage::Streams::RandomAccessStreamReference), Windows::Foundation::Uri const&);
            *streamReference = detach_from<Windows::Storage::Streams::RandomAccessStreamReference>(this->shim().CreateFromUri(*reinterpret_cast<Windows::Foundation::Uri const*>(&uri)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL CreateFromStream(void* stream, void** streamReference) noexcept final
    {
        try
        {
            *streamReference = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CreateFromStream, WINRT_WRAP(Windows::Storage::Streams::RandomAccessStreamReference), Windows::Storage::Streams::IRandomAccessStream const&);
            *streamReference = detach_from<Windows::Storage::Streams::RandomAccessStreamReference>(this->shim().CreateFromStream(*reinterpret_cast<Windows::Storage::Streams::IRandomAccessStream const*>(&stream)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Storage::Streams::IRandomAccessStreamStatics> : produce_base<D, Windows::Storage::Streams::IRandomAccessStreamStatics>
{
    int32_t WINRT_CALL CopyAsync(void* source, void* destination, void** operation) noexcept final
    {
        try
        {
            *operation = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CopyAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperationWithProgress<uint64_t, uint64_t>), Windows::Storage::Streams::IInputStream const, Windows::Storage::Streams::IOutputStream const);
            *operation = detach_from<Windows::Foundation::IAsyncOperationWithProgress<uint64_t, uint64_t>>(this->shim().CopyAsync(*reinterpret_cast<Windows::Storage::Streams::IInputStream const*>(&source), *reinterpret_cast<Windows::Storage::Streams::IOutputStream const*>(&destination)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL CopySizeAsync(void* source, void* destination, uint64_t bytesToCopy, void** operation) noexcept final
    {
        try
        {
            *operation = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CopyAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperationWithProgress<uint64_t, uint64_t>), Windows::Storage::Streams::IInputStream const, Windows::Storage::Streams::IOutputStream const, uint64_t);
            *operation = detach_from<Windows::Foundation::IAsyncOperationWithProgress<uint64_t, uint64_t>>(this->shim().CopyAsync(*reinterpret_cast<Windows::Storage::Streams::IInputStream const*>(&source), *reinterpret_cast<Windows::Storage::Streams::IOutputStream const*>(&destination), bytesToCopy));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL CopyAndCloseAsync(void* source, void* destination, void** operation) noexcept final
    {
        try
        {
            *operation = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CopyAndCloseAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperationWithProgress<uint64_t, uint64_t>), Windows::Storage::Streams::IInputStream const, Windows::Storage::Streams::IOutputStream const);
            *operation = detach_from<Windows::Foundation::IAsyncOperationWithProgress<uint64_t, uint64_t>>(this->shim().CopyAndCloseAsync(*reinterpret_cast<Windows::Storage::Streams::IInputStream const*>(&source), *reinterpret_cast<Windows::Storage::Streams::IOutputStream const*>(&destination)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Storage::Streams::IRandomAccessStreamWithContentType> : produce_base<D, Windows::Storage::Streams::IRandomAccessStreamWithContentType>
{};

}

WINRT_EXPORT namespace winrt::Windows::Storage::Streams {

inline Buffer::Buffer(uint32_t capacity) :
    Buffer(impl::call_factory<Buffer, Windows::Storage::Streams::IBufferFactory>([&](auto&& f) { return f.Create(capacity); }))
{}

inline Windows::Storage::Streams::Buffer Buffer::CreateCopyFromMemoryBuffer(Windows::Foundation::IMemoryBuffer const& input)
{
    return impl::call_factory<Buffer, Windows::Storage::Streams::IBufferStatics>([&](auto&& f) { return f.CreateCopyFromMemoryBuffer(input); });
}

inline Windows::Foundation::MemoryBuffer Buffer::CreateMemoryBufferOverIBuffer(Windows::Storage::Streams::IBuffer const& input)
{
    return impl::call_factory<Buffer, Windows::Storage::Streams::IBufferStatics>([&](auto&& f) { return f.CreateMemoryBufferOverIBuffer(input); });
}

inline DataReader::DataReader(Windows::Storage::Streams::IInputStream const& inputStream) :
    DataReader(impl::call_factory<DataReader, Windows::Storage::Streams::IDataReaderFactory>([&](auto&& f) { return f.CreateDataReader(inputStream); }))
{}

inline Windows::Storage::Streams::DataReader DataReader::FromBuffer(Windows::Storage::Streams::IBuffer const& buffer)
{
    return impl::call_factory<DataReader, Windows::Storage::Streams::IDataReaderStatics>([&](auto&& f) { return f.FromBuffer(buffer); });
}

inline DataWriter::DataWriter() :
    DataWriter(impl::call_factory<DataWriter>([](auto&& f) { return f.template ActivateInstance<DataWriter>(); }))
{}

inline DataWriter::DataWriter(Windows::Storage::Streams::IOutputStream const& outputStream) :
    DataWriter(impl::call_factory<DataWriter, Windows::Storage::Streams::IDataWriterFactory>([&](auto&& f) { return f.CreateDataWriter(outputStream); }))
{}

inline Windows::Foundation::IAsyncOperation<Windows::Storage::Streams::IRandomAccessStream> FileRandomAccessStream::OpenAsync(param::hstring const& filePath, Windows::Storage::FileAccessMode const& accessMode)
{
    return impl::call_factory<FileRandomAccessStream, Windows::Storage::Streams::IFileRandomAccessStreamStatics>([&](auto&& f) { return f.OpenAsync(filePath, accessMode); });
}

inline Windows::Foundation::IAsyncOperation<Windows::Storage::Streams::IRandomAccessStream> FileRandomAccessStream::OpenAsync(param::hstring const& filePath, Windows::Storage::FileAccessMode const& accessMode, Windows::Storage::StorageOpenOptions const& sharingOptions, Windows::Storage::Streams::FileOpenDisposition const& openDisposition)
{
    return impl::call_factory<FileRandomAccessStream, Windows::Storage::Streams::IFileRandomAccessStreamStatics>([&](auto&& f) { return f.OpenAsync(filePath, accessMode, sharingOptions, openDisposition); });
}

inline Windows::Foundation::IAsyncOperation<Windows::Storage::StorageStreamTransaction> FileRandomAccessStream::OpenTransactedWriteAsync(param::hstring const& filePath)
{
    return impl::call_factory<FileRandomAccessStream, Windows::Storage::Streams::IFileRandomAccessStreamStatics>([&](auto&& f) { return f.OpenTransactedWriteAsync(filePath); });
}

inline Windows::Foundation::IAsyncOperation<Windows::Storage::StorageStreamTransaction> FileRandomAccessStream::OpenTransactedWriteAsync(param::hstring const& filePath, Windows::Storage::StorageOpenOptions const& openOptions, Windows::Storage::Streams::FileOpenDisposition const& openDisposition)
{
    return impl::call_factory<FileRandomAccessStream, Windows::Storage::Streams::IFileRandomAccessStreamStatics>([&](auto&& f) { return f.OpenTransactedWriteAsync(filePath, openOptions, openDisposition); });
}

inline Windows::Foundation::IAsyncOperation<Windows::Storage::Streams::IRandomAccessStream> FileRandomAccessStream::OpenForUserAsync(Windows::System::User const& user, param::hstring const& filePath, Windows::Storage::FileAccessMode const& accessMode)
{
    return impl::call_factory<FileRandomAccessStream, Windows::Storage::Streams::IFileRandomAccessStreamStatics>([&](auto&& f) { return f.OpenForUserAsync(user, filePath, accessMode); });
}

inline Windows::Foundation::IAsyncOperation<Windows::Storage::Streams::IRandomAccessStream> FileRandomAccessStream::OpenForUserAsync(Windows::System::User const& user, param::hstring const& filePath, Windows::Storage::FileAccessMode const& accessMode, Windows::Storage::StorageOpenOptions const& sharingOptions, Windows::Storage::Streams::FileOpenDisposition const& openDisposition)
{
    return impl::call_factory<FileRandomAccessStream, Windows::Storage::Streams::IFileRandomAccessStreamStatics>([&](auto&& f) { return f.OpenForUserAsync(user, filePath, accessMode, sharingOptions, openDisposition); });
}

inline Windows::Foundation::IAsyncOperation<Windows::Storage::StorageStreamTransaction> FileRandomAccessStream::OpenTransactedWriteForUserAsync(Windows::System::User const& user, param::hstring const& filePath)
{
    return impl::call_factory<FileRandomAccessStream, Windows::Storage::Streams::IFileRandomAccessStreamStatics>([&](auto&& f) { return f.OpenTransactedWriteForUserAsync(user, filePath); });
}

inline Windows::Foundation::IAsyncOperation<Windows::Storage::StorageStreamTransaction> FileRandomAccessStream::OpenTransactedWriteForUserAsync(Windows::System::User const& user, param::hstring const& filePath, Windows::Storage::StorageOpenOptions const& openOptions, Windows::Storage::Streams::FileOpenDisposition const& openDisposition)
{
    return impl::call_factory<FileRandomAccessStream, Windows::Storage::Streams::IFileRandomAccessStreamStatics>([&](auto&& f) { return f.OpenTransactedWriteForUserAsync(user, filePath, openOptions, openDisposition); });
}

inline InMemoryRandomAccessStream::InMemoryRandomAccessStream() :
    InMemoryRandomAccessStream(impl::call_factory<InMemoryRandomAccessStream>([](auto&& f) { return f.template ActivateInstance<InMemoryRandomAccessStream>(); }))
{}

inline Windows::Foundation::IAsyncOperationWithProgress<uint64_t, uint64_t> RandomAccessStream::CopyAsync(Windows::Storage::Streams::IInputStream const& source, Windows::Storage::Streams::IOutputStream const& destination)
{
    return impl::call_factory<RandomAccessStream, Windows::Storage::Streams::IRandomAccessStreamStatics>([&](auto&& f) { return f.CopyAsync(source, destination); });
}

inline Windows::Foundation::IAsyncOperationWithProgress<uint64_t, uint64_t> RandomAccessStream::CopyAsync(Windows::Storage::Streams::IInputStream const& source, Windows::Storage::Streams::IOutputStream const& destination, uint64_t bytesToCopy)
{
    return impl::call_factory<RandomAccessStream, Windows::Storage::Streams::IRandomAccessStreamStatics>([&](auto&& f) { return f.CopyAsync(source, destination, bytesToCopy); });
}

inline Windows::Foundation::IAsyncOperationWithProgress<uint64_t, uint64_t> RandomAccessStream::CopyAndCloseAsync(Windows::Storage::Streams::IInputStream const& source, Windows::Storage::Streams::IOutputStream const& destination)
{
    return impl::call_factory<RandomAccessStream, Windows::Storage::Streams::IRandomAccessStreamStatics>([&](auto&& f) { return f.CopyAndCloseAsync(source, destination); });
}

inline Windows::Storage::Streams::RandomAccessStreamReference RandomAccessStreamReference::CreateFromFile(Windows::Storage::IStorageFile const& file)
{
    return impl::call_factory<RandomAccessStreamReference, Windows::Storage::Streams::IRandomAccessStreamReferenceStatics>([&](auto&& f) { return f.CreateFromFile(file); });
}

inline Windows::Storage::Streams::RandomAccessStreamReference RandomAccessStreamReference::CreateFromUri(Windows::Foundation::Uri const& uri)
{
    return impl::call_factory<RandomAccessStreamReference, Windows::Storage::Streams::IRandomAccessStreamReferenceStatics>([&](auto&& f) { return f.CreateFromUri(uri); });
}

inline Windows::Storage::Streams::RandomAccessStreamReference RandomAccessStreamReference::CreateFromStream(Windows::Storage::Streams::IRandomAccessStream const& stream)
{
    return impl::call_factory<RandomAccessStreamReference, Windows::Storage::Streams::IRandomAccessStreamReferenceStatics>([&](auto&& f) { return f.CreateFromStream(stream); });
}

}

WINRT_EXPORT namespace std {

template<> struct hash<winrt::Windows::Storage::Streams::IBuffer> : winrt::impl::hash_base<winrt::Windows::Storage::Streams::IBuffer> {};
template<> struct hash<winrt::Windows::Storage::Streams::IBufferFactory> : winrt::impl::hash_base<winrt::Windows::Storage::Streams::IBufferFactory> {};
template<> struct hash<winrt::Windows::Storage::Streams::IBufferStatics> : winrt::impl::hash_base<winrt::Windows::Storage::Streams::IBufferStatics> {};
template<> struct hash<winrt::Windows::Storage::Streams::IContentTypeProvider> : winrt::impl::hash_base<winrt::Windows::Storage::Streams::IContentTypeProvider> {};
template<> struct hash<winrt::Windows::Storage::Streams::IDataReader> : winrt::impl::hash_base<winrt::Windows::Storage::Streams::IDataReader> {};
template<> struct hash<winrt::Windows::Storage::Streams::IDataReaderFactory> : winrt::impl::hash_base<winrt::Windows::Storage::Streams::IDataReaderFactory> {};
template<> struct hash<winrt::Windows::Storage::Streams::IDataReaderStatics> : winrt::impl::hash_base<winrt::Windows::Storage::Streams::IDataReaderStatics> {};
template<> struct hash<winrt::Windows::Storage::Streams::IDataWriter> : winrt::impl::hash_base<winrt::Windows::Storage::Streams::IDataWriter> {};
template<> struct hash<winrt::Windows::Storage::Streams::IDataWriterFactory> : winrt::impl::hash_base<winrt::Windows::Storage::Streams::IDataWriterFactory> {};
template<> struct hash<winrt::Windows::Storage::Streams::IFileRandomAccessStreamStatics> : winrt::impl::hash_base<winrt::Windows::Storage::Streams::IFileRandomAccessStreamStatics> {};
template<> struct hash<winrt::Windows::Storage::Streams::IInputStream> : winrt::impl::hash_base<winrt::Windows::Storage::Streams::IInputStream> {};
template<> struct hash<winrt::Windows::Storage::Streams::IInputStreamReference> : winrt::impl::hash_base<winrt::Windows::Storage::Streams::IInputStreamReference> {};
template<> struct hash<winrt::Windows::Storage::Streams::IOutputStream> : winrt::impl::hash_base<winrt::Windows::Storage::Streams::IOutputStream> {};
template<> struct hash<winrt::Windows::Storage::Streams::IRandomAccessStream> : winrt::impl::hash_base<winrt::Windows::Storage::Streams::IRandomAccessStream> {};
template<> struct hash<winrt::Windows::Storage::Streams::IRandomAccessStreamReference> : winrt::impl::hash_base<winrt::Windows::Storage::Streams::IRandomAccessStreamReference> {};
template<> struct hash<winrt::Windows::Storage::Streams::IRandomAccessStreamReferenceStatics> : winrt::impl::hash_base<winrt::Windows::Storage::Streams::IRandomAccessStreamReferenceStatics> {};
template<> struct hash<winrt::Windows::Storage::Streams::IRandomAccessStreamStatics> : winrt::impl::hash_base<winrt::Windows::Storage::Streams::IRandomAccessStreamStatics> {};
template<> struct hash<winrt::Windows::Storage::Streams::IRandomAccessStreamWithContentType> : winrt::impl::hash_base<winrt::Windows::Storage::Streams::IRandomAccessStreamWithContentType> {};
template<> struct hash<winrt::Windows::Storage::Streams::Buffer> : winrt::impl::hash_base<winrt::Windows::Storage::Streams::Buffer> {};
template<> struct hash<winrt::Windows::Storage::Streams::DataReader> : winrt::impl::hash_base<winrt::Windows::Storage::Streams::DataReader> {};
template<> struct hash<winrt::Windows::Storage::Streams::DataReaderLoadOperation> : winrt::impl::hash_base<winrt::Windows::Storage::Streams::DataReaderLoadOperation> {};
template<> struct hash<winrt::Windows::Storage::Streams::DataWriter> : winrt::impl::hash_base<winrt::Windows::Storage::Streams::DataWriter> {};
template<> struct hash<winrt::Windows::Storage::Streams::DataWriterStoreOperation> : winrt::impl::hash_base<winrt::Windows::Storage::Streams::DataWriterStoreOperation> {};
template<> struct hash<winrt::Windows::Storage::Streams::FileInputStream> : winrt::impl::hash_base<winrt::Windows::Storage::Streams::FileInputStream> {};
template<> struct hash<winrt::Windows::Storage::Streams::FileOutputStream> : winrt::impl::hash_base<winrt::Windows::Storage::Streams::FileOutputStream> {};
template<> struct hash<winrt::Windows::Storage::Streams::FileRandomAccessStream> : winrt::impl::hash_base<winrt::Windows::Storage::Streams::FileRandomAccessStream> {};
template<> struct hash<winrt::Windows::Storage::Streams::InMemoryRandomAccessStream> : winrt::impl::hash_base<winrt::Windows::Storage::Streams::InMemoryRandomAccessStream> {};
template<> struct hash<winrt::Windows::Storage::Streams::InputStreamOverStream> : winrt::impl::hash_base<winrt::Windows::Storage::Streams::InputStreamOverStream> {};
template<> struct hash<winrt::Windows::Storage::Streams::OutputStreamOverStream> : winrt::impl::hash_base<winrt::Windows::Storage::Streams::OutputStreamOverStream> {};
template<> struct hash<winrt::Windows::Storage::Streams::RandomAccessStream> : winrt::impl::hash_base<winrt::Windows::Storage::Streams::RandomAccessStream> {};
template<> struct hash<winrt::Windows::Storage::Streams::RandomAccessStreamOverStream> : winrt::impl::hash_base<winrt::Windows::Storage::Streams::RandomAccessStreamOverStream> {};
template<> struct hash<winrt::Windows::Storage::Streams::RandomAccessStreamReference> : winrt::impl::hash_base<winrt::Windows::Storage::Streams::RandomAccessStreamReference> {};

}
