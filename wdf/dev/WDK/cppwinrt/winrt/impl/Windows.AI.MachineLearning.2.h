// C++/WinRT v1.0.190111.3

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#pragma once
#include "winrt/impl/Windows.Foundation.1.h"
#include "winrt/impl/Windows.Foundation.Collections.1.h"
#include "winrt/impl/Windows.Graphics.1.h"
#include "winrt/impl/Windows.Graphics.DirectX.Direct3D11.1.h"
#include "winrt/impl/Windows.Graphics.Imaging.1.h"
#include "winrt/impl/Windows.Media.1.h"
#include "winrt/impl/Windows.Storage.1.h"
#include "winrt/impl/Windows.Storage.Streams.1.h"
#include "winrt/impl/Windows.Foundation.Collections.1.h"
#include "winrt/impl/Windows.AI.MachineLearning.1.h"

WINRT_EXPORT namespace winrt::Windows::AI::MachineLearning {

}

namespace winrt::impl {

}

WINRT_EXPORT namespace winrt::Windows::AI::MachineLearning {

struct WINRT_EBO ImageFeatureDescriptor :
    Windows::AI::MachineLearning::IImageFeatureDescriptor,
    impl::require<ImageFeatureDescriptor, Windows::AI::MachineLearning::ILearningModelFeatureDescriptor>
{
    ImageFeatureDescriptor(std::nullptr_t) noexcept {}
};

struct WINRT_EBO ImageFeatureValue :
    Windows::AI::MachineLearning::IImageFeatureValue,
    impl::require<ImageFeatureValue, Windows::AI::MachineLearning::ILearningModelFeatureValue>
{
    ImageFeatureValue(std::nullptr_t) noexcept {}
    static Windows::AI::MachineLearning::ImageFeatureValue CreateFromVideoFrame(Windows::Media::VideoFrame const& image);
};

struct WINRT_EBO LearningModel :
    Windows::AI::MachineLearning::ILearningModel,
    impl::require<LearningModel, Windows::Foundation::IClosable>
{
    LearningModel(std::nullptr_t) noexcept {}
    static Windows::Foundation::IAsyncOperation<Windows::AI::MachineLearning::LearningModel> LoadFromStorageFileAsync(Windows::Storage::IStorageFile const& modelFile);
    static Windows::Foundation::IAsyncOperation<Windows::AI::MachineLearning::LearningModel> LoadFromStreamAsync(Windows::Storage::Streams::IRandomAccessStreamReference const& modelStream);
    static Windows::AI::MachineLearning::LearningModel LoadFromFilePath(param::hstring const& filePath);
    static Windows::AI::MachineLearning::LearningModel LoadFromStream(Windows::Storage::Streams::IRandomAccessStreamReference const& modelStream);
    static Windows::Foundation::IAsyncOperation<Windows::AI::MachineLearning::LearningModel> LoadFromStorageFileAsync(Windows::Storage::IStorageFile const& modelFile, Windows::AI::MachineLearning::ILearningModelOperatorProvider const& operatorProvider);
    static Windows::Foundation::IAsyncOperation<Windows::AI::MachineLearning::LearningModel> LoadFromStreamAsync(Windows::Storage::Streams::IRandomAccessStreamReference const& modelStream, Windows::AI::MachineLearning::ILearningModelOperatorProvider const& operatorProvider);
    static Windows::AI::MachineLearning::LearningModel LoadFromFilePath(param::hstring const& filePath, Windows::AI::MachineLearning::ILearningModelOperatorProvider const& operatorProvider);
    static Windows::AI::MachineLearning::LearningModel LoadFromStream(Windows::Storage::Streams::IRandomAccessStreamReference const& modelStream, Windows::AI::MachineLearning::ILearningModelOperatorProvider const& operatorProvider);
};

struct WINRT_EBO LearningModelBinding :
    Windows::AI::MachineLearning::ILearningModelBinding,
    impl::require<LearningModelBinding, Windows::Foundation::Collections::IIterable<Windows::Foundation::Collections::IKeyValuePair<hstring, Windows::Foundation::IInspectable>>, Windows::Foundation::Collections::IMapView<hstring, Windows::Foundation::IInspectable>>
{
    LearningModelBinding(std::nullptr_t) noexcept {}
    LearningModelBinding(Windows::AI::MachineLearning::LearningModelSession const& session);
};

struct WINRT_EBO LearningModelDevice :
    Windows::AI::MachineLearning::ILearningModelDevice
{
    LearningModelDevice(std::nullptr_t) noexcept {}
    LearningModelDevice(Windows::AI::MachineLearning::LearningModelDeviceKind const& deviceKind);
    static Windows::AI::MachineLearning::LearningModelDevice CreateFromDirect3D11Device(Windows::Graphics::DirectX::Direct3D11::IDirect3DDevice const& device);
};

struct WINRT_EBO LearningModelEvaluationResult :
    Windows::AI::MachineLearning::ILearningModelEvaluationResult
{
    LearningModelEvaluationResult(std::nullptr_t) noexcept {}
};

struct WINRT_EBO LearningModelSession :
    Windows::AI::MachineLearning::ILearningModelSession,
    impl::require<LearningModelSession, Windows::Foundation::IClosable>
{
    LearningModelSession(std::nullptr_t) noexcept {}
    LearningModelSession(Windows::AI::MachineLearning::LearningModel const& model);
    LearningModelSession(Windows::AI::MachineLearning::LearningModel const& model, Windows::AI::MachineLearning::LearningModelDevice const& deviceToRunOn);
    LearningModelSession(Windows::AI::MachineLearning::LearningModel const& model, Windows::AI::MachineLearning::LearningModelDevice const& deviceToRunOn, Windows::AI::MachineLearning::LearningModelSessionOptions const& learningModelSessionOptions);
};

struct WINRT_EBO LearningModelSessionOptions :
    Windows::AI::MachineLearning::ILearningModelSessionOptions
{
    LearningModelSessionOptions(std::nullptr_t) noexcept {}
    LearningModelSessionOptions();
};

struct WINRT_EBO MapFeatureDescriptor :
    Windows::AI::MachineLearning::IMapFeatureDescriptor,
    impl::require<MapFeatureDescriptor, Windows::AI::MachineLearning::ILearningModelFeatureDescriptor>
{
    MapFeatureDescriptor(std::nullptr_t) noexcept {}
};

struct WINRT_EBO SequenceFeatureDescriptor :
    Windows::AI::MachineLearning::ISequenceFeatureDescriptor,
    impl::require<SequenceFeatureDescriptor, Windows::AI::MachineLearning::ILearningModelFeatureDescriptor>
{
    SequenceFeatureDescriptor(std::nullptr_t) noexcept {}
};

struct WINRT_EBO TensorBoolean :
    Windows::AI::MachineLearning::ITensorBoolean,
    impl::require<TensorBoolean, Windows::AI::MachineLearning::ILearningModelFeatureValue, Windows::AI::MachineLearning::ITensor, Windows::Foundation::IClosable, Windows::Foundation::IMemoryBuffer>
{
    TensorBoolean(std::nullptr_t) noexcept {}
    static Windows::AI::MachineLearning::TensorBoolean Create();
    static Windows::AI::MachineLearning::TensorBoolean Create(param::iterable<int64_t> const& shape);
    static Windows::AI::MachineLearning::TensorBoolean CreateFromArray(param::iterable<int64_t> const& shape, array_view<bool const> data);
    static Windows::AI::MachineLearning::TensorBoolean CreateFromIterable(param::iterable<int64_t> const& shape, param::iterable<bool> const& data);
    static Windows::AI::MachineLearning::TensorBoolean CreateFromShapeArrayAndDataArray(array_view<int64_t const> shape, array_view<bool const> data);
    static Windows::AI::MachineLearning::TensorBoolean CreateFromBuffer(array_view<int64_t const> shape, Windows::Storage::Streams::IBuffer const& buffer);
};

struct WINRT_EBO TensorDouble :
    Windows::AI::MachineLearning::ITensorDouble,
    impl::require<TensorDouble, Windows::AI::MachineLearning::ILearningModelFeatureValue, Windows::AI::MachineLearning::ITensor, Windows::Foundation::IClosable, Windows::Foundation::IMemoryBuffer>
{
    TensorDouble(std::nullptr_t) noexcept {}
    static Windows::AI::MachineLearning::TensorDouble Create();
    static Windows::AI::MachineLearning::TensorDouble Create(param::iterable<int64_t> const& shape);
    static Windows::AI::MachineLearning::TensorDouble CreateFromArray(param::iterable<int64_t> const& shape, array_view<double const> data);
    static Windows::AI::MachineLearning::TensorDouble CreateFromIterable(param::iterable<int64_t> const& shape, param::iterable<double> const& data);
    static Windows::AI::MachineLearning::TensorDouble CreateFromShapeArrayAndDataArray(array_view<int64_t const> shape, array_view<double const> data);
    static Windows::AI::MachineLearning::TensorDouble CreateFromBuffer(array_view<int64_t const> shape, Windows::Storage::Streams::IBuffer const& buffer);
};

struct WINRT_EBO TensorFeatureDescriptor :
    Windows::AI::MachineLearning::ITensorFeatureDescriptor,
    impl::require<TensorFeatureDescriptor, Windows::AI::MachineLearning::ILearningModelFeatureDescriptor>
{
    TensorFeatureDescriptor(std::nullptr_t) noexcept {}
};

struct WINRT_EBO TensorFloat :
    Windows::AI::MachineLearning::ITensorFloat,
    impl::require<TensorFloat, Windows::AI::MachineLearning::ILearningModelFeatureValue, Windows::AI::MachineLearning::ITensor, Windows::Foundation::IClosable, Windows::Foundation::IMemoryBuffer>
{
    TensorFloat(std::nullptr_t) noexcept {}
    static Windows::AI::MachineLearning::TensorFloat Create();
    static Windows::AI::MachineLearning::TensorFloat Create(param::iterable<int64_t> const& shape);
    static Windows::AI::MachineLearning::TensorFloat CreateFromArray(param::iterable<int64_t> const& shape, array_view<float const> data);
    static Windows::AI::MachineLearning::TensorFloat CreateFromIterable(param::iterable<int64_t> const& shape, param::iterable<float> const& data);
    static Windows::AI::MachineLearning::TensorFloat CreateFromShapeArrayAndDataArray(array_view<int64_t const> shape, array_view<float const> data);
    static Windows::AI::MachineLearning::TensorFloat CreateFromBuffer(array_view<int64_t const> shape, Windows::Storage::Streams::IBuffer const& buffer);
};

struct WINRT_EBO TensorFloat16Bit :
    Windows::AI::MachineLearning::ITensorFloat16Bit,
    impl::require<TensorFloat16Bit, Windows::AI::MachineLearning::ILearningModelFeatureValue, Windows::AI::MachineLearning::ITensor, Windows::Foundation::IClosable, Windows::Foundation::IMemoryBuffer>
{
    TensorFloat16Bit(std::nullptr_t) noexcept {}
    static Windows::AI::MachineLearning::TensorFloat16Bit Create();
    static Windows::AI::MachineLearning::TensorFloat16Bit Create(param::iterable<int64_t> const& shape);
    static Windows::AI::MachineLearning::TensorFloat16Bit CreateFromArray(param::iterable<int64_t> const& shape, array_view<float const> data);
    static Windows::AI::MachineLearning::TensorFloat16Bit CreateFromIterable(param::iterable<int64_t> const& shape, param::iterable<float> const& data);
    static Windows::AI::MachineLearning::TensorFloat16Bit CreateFromShapeArrayAndDataArray(array_view<int64_t const> shape, array_view<float const> data);
    static Windows::AI::MachineLearning::TensorFloat16Bit CreateFromBuffer(array_view<int64_t const> shape, Windows::Storage::Streams::IBuffer const& buffer);
};

struct WINRT_EBO TensorInt16Bit :
    Windows::AI::MachineLearning::ITensorInt16Bit,
    impl::require<TensorInt16Bit, Windows::AI::MachineLearning::ILearningModelFeatureValue, Windows::AI::MachineLearning::ITensor, Windows::Foundation::IClosable, Windows::Foundation::IMemoryBuffer>
{
    TensorInt16Bit(std::nullptr_t) noexcept {}
    static Windows::AI::MachineLearning::TensorInt16Bit Create();
    static Windows::AI::MachineLearning::TensorInt16Bit Create(param::iterable<int64_t> const& shape);
    static Windows::AI::MachineLearning::TensorInt16Bit CreateFromArray(param::iterable<int64_t> const& shape, array_view<int16_t const> data);
    static Windows::AI::MachineLearning::TensorInt16Bit CreateFromIterable(param::iterable<int64_t> const& shape, param::iterable<int16_t> const& data);
    static Windows::AI::MachineLearning::TensorInt16Bit CreateFromShapeArrayAndDataArray(array_view<int64_t const> shape, array_view<int16_t const> data);
    static Windows::AI::MachineLearning::TensorInt16Bit CreateFromBuffer(array_view<int64_t const> shape, Windows::Storage::Streams::IBuffer const& buffer);
};

struct WINRT_EBO TensorInt32Bit :
    Windows::AI::MachineLearning::ITensorInt32Bit,
    impl::require<TensorInt32Bit, Windows::AI::MachineLearning::ILearningModelFeatureValue, Windows::AI::MachineLearning::ITensor, Windows::Foundation::IClosable, Windows::Foundation::IMemoryBuffer>
{
    TensorInt32Bit(std::nullptr_t) noexcept {}
    static Windows::AI::MachineLearning::TensorInt32Bit Create();
    static Windows::AI::MachineLearning::TensorInt32Bit Create(param::iterable<int64_t> const& shape);
    static Windows::AI::MachineLearning::TensorInt32Bit CreateFromArray(param::iterable<int64_t> const& shape, array_view<int32_t const> data);
    static Windows::AI::MachineLearning::TensorInt32Bit CreateFromIterable(param::iterable<int64_t> const& shape, param::iterable<int32_t> const& data);
    static Windows::AI::MachineLearning::TensorInt32Bit CreateFromShapeArrayAndDataArray(array_view<int64_t const> shape, array_view<int32_t const> data);
    static Windows::AI::MachineLearning::TensorInt32Bit CreateFromBuffer(array_view<int64_t const> shape, Windows::Storage::Streams::IBuffer const& buffer);
};

struct WINRT_EBO TensorInt64Bit :
    Windows::AI::MachineLearning::ITensorInt64Bit,
    impl::require<TensorInt64Bit, Windows::AI::MachineLearning::ILearningModelFeatureValue, Windows::AI::MachineLearning::ITensor, Windows::Foundation::IClosable, Windows::Foundation::IMemoryBuffer>
{
    TensorInt64Bit(std::nullptr_t) noexcept {}
    static Windows::AI::MachineLearning::TensorInt64Bit Create();
    static Windows::AI::MachineLearning::TensorInt64Bit Create(param::iterable<int64_t> const& shape);
    static Windows::AI::MachineLearning::TensorInt64Bit CreateFromArray(param::iterable<int64_t> const& shape, array_view<int64_t const> data);
    static Windows::AI::MachineLearning::TensorInt64Bit CreateFromIterable(param::iterable<int64_t> const& shape, param::iterable<int64_t> const& data);
    static Windows::AI::MachineLearning::TensorInt64Bit CreateFromShapeArrayAndDataArray(array_view<int64_t const> shape, array_view<int64_t const> data);
    static Windows::AI::MachineLearning::TensorInt64Bit CreateFromBuffer(array_view<int64_t const> shape, Windows::Storage::Streams::IBuffer const& buffer);
};

struct WINRT_EBO TensorInt8Bit :
    Windows::AI::MachineLearning::ITensorInt8Bit,
    impl::require<TensorInt8Bit, Windows::AI::MachineLearning::ILearningModelFeatureValue, Windows::AI::MachineLearning::ITensor, Windows::Foundation::IClosable, Windows::Foundation::IMemoryBuffer>
{
    TensorInt8Bit(std::nullptr_t) noexcept {}
    static Windows::AI::MachineLearning::TensorInt8Bit Create();
    static Windows::AI::MachineLearning::TensorInt8Bit Create(param::iterable<int64_t> const& shape);
    static Windows::AI::MachineLearning::TensorInt8Bit CreateFromArray(param::iterable<int64_t> const& shape, array_view<uint8_t const> data);
    static Windows::AI::MachineLearning::TensorInt8Bit CreateFromIterable(param::iterable<int64_t> const& shape, param::iterable<uint8_t> const& data);
    static Windows::AI::MachineLearning::TensorInt8Bit CreateFromShapeArrayAndDataArray(array_view<int64_t const> shape, array_view<uint8_t const> data);
    static Windows::AI::MachineLearning::TensorInt8Bit CreateFromBuffer(array_view<int64_t const> shape, Windows::Storage::Streams::IBuffer const& buffer);
};

struct WINRT_EBO TensorString :
    Windows::AI::MachineLearning::ITensorString,
    impl::require<TensorString, Windows::AI::MachineLearning::ILearningModelFeatureValue, Windows::AI::MachineLearning::ITensor, Windows::Foundation::IClosable, Windows::Foundation::IMemoryBuffer>
{
    TensorString(std::nullptr_t) noexcept {}
    static Windows::AI::MachineLearning::TensorString Create();
    static Windows::AI::MachineLearning::TensorString Create(param::iterable<int64_t> const& shape);
    static Windows::AI::MachineLearning::TensorString CreateFromArray(param::iterable<int64_t> const& shape, array_view<hstring const> data);
    static Windows::AI::MachineLearning::TensorString CreateFromIterable(param::iterable<int64_t> const& shape, param::iterable<hstring> const& data);
    static Windows::AI::MachineLearning::TensorString CreateFromShapeArrayAndDataArray(array_view<int64_t const> shape, array_view<hstring const> data);
};

struct WINRT_EBO TensorUInt16Bit :
    Windows::AI::MachineLearning::ITensorUInt16Bit,
    impl::require<TensorUInt16Bit, Windows::AI::MachineLearning::ILearningModelFeatureValue, Windows::AI::MachineLearning::ITensor, Windows::Foundation::IClosable, Windows::Foundation::IMemoryBuffer>
{
    TensorUInt16Bit(std::nullptr_t) noexcept {}
    static Windows::AI::MachineLearning::TensorUInt16Bit Create();
    static Windows::AI::MachineLearning::TensorUInt16Bit Create(param::iterable<int64_t> const& shape);
    static Windows::AI::MachineLearning::TensorUInt16Bit CreateFromArray(param::iterable<int64_t> const& shape, array_view<uint16_t const> data);
    static Windows::AI::MachineLearning::TensorUInt16Bit CreateFromIterable(param::iterable<int64_t> const& shape, param::iterable<uint16_t> const& data);
    static Windows::AI::MachineLearning::TensorUInt16Bit CreateFromShapeArrayAndDataArray(array_view<int64_t const> shape, array_view<uint16_t const> data);
    static Windows::AI::MachineLearning::TensorUInt16Bit CreateFromBuffer(array_view<int64_t const> shape, Windows::Storage::Streams::IBuffer const& buffer);
};

struct WINRT_EBO TensorUInt32Bit :
    Windows::AI::MachineLearning::ITensorUInt32Bit,
    impl::require<TensorUInt32Bit, Windows::AI::MachineLearning::ILearningModelFeatureValue, Windows::AI::MachineLearning::ITensor, Windows::Foundation::IClosable, Windows::Foundation::IMemoryBuffer>
{
    TensorUInt32Bit(std::nullptr_t) noexcept {}
    static Windows::AI::MachineLearning::TensorUInt32Bit Create();
    static Windows::AI::MachineLearning::TensorUInt32Bit Create(param::iterable<int64_t> const& shape);
    static Windows::AI::MachineLearning::TensorUInt32Bit CreateFromArray(param::iterable<int64_t> const& shape, array_view<uint32_t const> data);
    static Windows::AI::MachineLearning::TensorUInt32Bit CreateFromIterable(param::iterable<int64_t> const& shape, param::iterable<uint32_t> const& data);
    static Windows::AI::MachineLearning::TensorUInt32Bit CreateFromShapeArrayAndDataArray(array_view<int64_t const> shape, array_view<uint32_t const> data);
    static Windows::AI::MachineLearning::TensorUInt32Bit CreateFromBuffer(array_view<int64_t const> shape, Windows::Storage::Streams::IBuffer const& buffer);
};

struct WINRT_EBO TensorUInt64Bit :
    Windows::AI::MachineLearning::ITensorUInt64Bit,
    impl::require<TensorUInt64Bit, Windows::AI::MachineLearning::ILearningModelFeatureValue, Windows::AI::MachineLearning::ITensor, Windows::Foundation::IClosable, Windows::Foundation::IMemoryBuffer>
{
    TensorUInt64Bit(std::nullptr_t) noexcept {}
    static Windows::AI::MachineLearning::TensorUInt64Bit Create();
    static Windows::AI::MachineLearning::TensorUInt64Bit Create(param::iterable<int64_t> const& shape);
    static Windows::AI::MachineLearning::TensorUInt64Bit CreateFromArray(param::iterable<int64_t> const& shape, array_view<uint64_t const> data);
    static Windows::AI::MachineLearning::TensorUInt64Bit CreateFromIterable(param::iterable<int64_t> const& shape, param::iterable<uint64_t> const& data);
    static Windows::AI::MachineLearning::TensorUInt64Bit CreateFromShapeArrayAndDataArray(array_view<int64_t const> shape, array_view<uint64_t const> data);
    static Windows::AI::MachineLearning::TensorUInt64Bit CreateFromBuffer(array_view<int64_t const> shape, Windows::Storage::Streams::IBuffer const& buffer);
};

struct WINRT_EBO TensorUInt8Bit :
    Windows::AI::MachineLearning::ITensorUInt8Bit,
    impl::require<TensorUInt8Bit, Windows::AI::MachineLearning::ILearningModelFeatureValue, Windows::AI::MachineLearning::ITensor, Windows::Foundation::IClosable, Windows::Foundation::IMemoryBuffer>
{
    TensorUInt8Bit(std::nullptr_t) noexcept {}
    static Windows::AI::MachineLearning::TensorUInt8Bit Create();
    static Windows::AI::MachineLearning::TensorUInt8Bit Create(param::iterable<int64_t> const& shape);
    static Windows::AI::MachineLearning::TensorUInt8Bit CreateFromArray(param::iterable<int64_t> const& shape, array_view<uint8_t const> data);
    static Windows::AI::MachineLearning::TensorUInt8Bit CreateFromIterable(param::iterable<int64_t> const& shape, param::iterable<uint8_t> const& data);
    static Windows::AI::MachineLearning::TensorUInt8Bit CreateFromShapeArrayAndDataArray(array_view<int64_t const> shape, array_view<uint8_t const> data);
    static Windows::AI::MachineLearning::TensorUInt8Bit CreateFromBuffer(array_view<int64_t const> shape, Windows::Storage::Streams::IBuffer const& buffer);
};

}
