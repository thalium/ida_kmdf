// C++/WinRT v1.0.190111.3

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#pragma once

#include "winrt/base.h"

#include "winrt/Windows.Foundation.h"
#include "winrt/Windows.Foundation.Collections.h"
#include "winrt/impl/Windows.Foundation.2.h"
#include "winrt/impl/Windows.Foundation.Collections.2.h"
#include "winrt/impl/Windows.Graphics.2.h"
#include "winrt/impl/Windows.Graphics.DirectX.Direct3D11.2.h"
#include "winrt/impl/Windows.Graphics.Imaging.2.h"
#include "winrt/impl/Windows.Media.2.h"
#include "winrt/impl/Windows.Storage.2.h"
#include "winrt/impl/Windows.Storage.Streams.2.h"
#include "winrt/impl/Windows.Foundation.Collections.2.h"
#include "winrt/impl/Windows.AI.MachineLearning.2.h"

namespace winrt::impl {

template <typename D> Windows::Graphics::Imaging::BitmapPixelFormat consume_Windows_AI_MachineLearning_IImageFeatureDescriptor<D>::BitmapPixelFormat() const
{
    Windows::Graphics::Imaging::BitmapPixelFormat value{};
    check_hresult(WINRT_SHIM(Windows::AI::MachineLearning::IImageFeatureDescriptor)->get_BitmapPixelFormat(put_abi(value)));
    return value;
}

template <typename D> Windows::Graphics::Imaging::BitmapAlphaMode consume_Windows_AI_MachineLearning_IImageFeatureDescriptor<D>::BitmapAlphaMode() const
{
    Windows::Graphics::Imaging::BitmapAlphaMode value{};
    check_hresult(WINRT_SHIM(Windows::AI::MachineLearning::IImageFeatureDescriptor)->get_BitmapAlphaMode(put_abi(value)));
    return value;
}

template <typename D> uint32_t consume_Windows_AI_MachineLearning_IImageFeatureDescriptor<D>::Width() const
{
    uint32_t value{};
    check_hresult(WINRT_SHIM(Windows::AI::MachineLearning::IImageFeatureDescriptor)->get_Width(&value));
    return value;
}

template <typename D> uint32_t consume_Windows_AI_MachineLearning_IImageFeatureDescriptor<D>::Height() const
{
    uint32_t value{};
    check_hresult(WINRT_SHIM(Windows::AI::MachineLearning::IImageFeatureDescriptor)->get_Height(&value));
    return value;
}

template <typename D> Windows::Media::VideoFrame consume_Windows_AI_MachineLearning_IImageFeatureValue<D>::VideoFrame() const
{
    Windows::Media::VideoFrame value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::AI::MachineLearning::IImageFeatureValue)->get_VideoFrame(put_abi(value)));
    return value;
}

template <typename D> Windows::AI::MachineLearning::ImageFeatureValue consume_Windows_AI_MachineLearning_IImageFeatureValueStatics<D>::CreateFromVideoFrame(Windows::Media::VideoFrame const& image) const
{
    Windows::AI::MachineLearning::ImageFeatureValue result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::AI::MachineLearning::IImageFeatureValueStatics)->CreateFromVideoFrame(get_abi(image), put_abi(result)));
    return result;
}

template <typename D> hstring consume_Windows_AI_MachineLearning_ILearningModel<D>::Author() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::AI::MachineLearning::ILearningModel)->get_Author(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_AI_MachineLearning_ILearningModel<D>::Name() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::AI::MachineLearning::ILearningModel)->get_Name(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_AI_MachineLearning_ILearningModel<D>::Domain() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::AI::MachineLearning::ILearningModel)->get_Domain(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_AI_MachineLearning_ILearningModel<D>::Description() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::AI::MachineLearning::ILearningModel)->get_Description(put_abi(value)));
    return value;
}

template <typename D> int64_t consume_Windows_AI_MachineLearning_ILearningModel<D>::Version() const
{
    int64_t value{};
    check_hresult(WINRT_SHIM(Windows::AI::MachineLearning::ILearningModel)->get_Version(&value));
    return value;
}

template <typename D> Windows::Foundation::Collections::IMapView<hstring, hstring> consume_Windows_AI_MachineLearning_ILearningModel<D>::Metadata() const
{
    Windows::Foundation::Collections::IMapView<hstring, hstring> value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::AI::MachineLearning::ILearningModel)->get_Metadata(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::Collections::IVectorView<Windows::AI::MachineLearning::ILearningModelFeatureDescriptor> consume_Windows_AI_MachineLearning_ILearningModel<D>::InputFeatures() const
{
    Windows::Foundation::Collections::IVectorView<Windows::AI::MachineLearning::ILearningModelFeatureDescriptor> value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::AI::MachineLearning::ILearningModel)->get_InputFeatures(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::Collections::IVectorView<Windows::AI::MachineLearning::ILearningModelFeatureDescriptor> consume_Windows_AI_MachineLearning_ILearningModel<D>::OutputFeatures() const
{
    Windows::Foundation::Collections::IVectorView<Windows::AI::MachineLearning::ILearningModelFeatureDescriptor> value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::AI::MachineLearning::ILearningModel)->get_OutputFeatures(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_AI_MachineLearning_ILearningModelBinding<D>::Bind(param::hstring const& name, Windows::Foundation::IInspectable const& value) const
{
    check_hresult(WINRT_SHIM(Windows::AI::MachineLearning::ILearningModelBinding)->Bind(get_abi(name), get_abi(value)));
}

template <typename D> void consume_Windows_AI_MachineLearning_ILearningModelBinding<D>::Bind(param::hstring const& name, Windows::Foundation::IInspectable const& value, Windows::Foundation::Collections::IPropertySet const& props) const
{
    check_hresult(WINRT_SHIM(Windows::AI::MachineLearning::ILearningModelBinding)->BindWithProperties(get_abi(name), get_abi(value), get_abi(props)));
}

template <typename D> void consume_Windows_AI_MachineLearning_ILearningModelBinding<D>::Clear() const
{
    check_hresult(WINRT_SHIM(Windows::AI::MachineLearning::ILearningModelBinding)->Clear());
}

template <typename D> Windows::AI::MachineLearning::LearningModelBinding consume_Windows_AI_MachineLearning_ILearningModelBindingFactory<D>::CreateFromSession(Windows::AI::MachineLearning::LearningModelSession const& session) const
{
    Windows::AI::MachineLearning::LearningModelBinding value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::AI::MachineLearning::ILearningModelBindingFactory)->CreateFromSession(get_abi(session), put_abi(value)));
    return value;
}

template <typename D> Windows::Graphics::DisplayAdapterId consume_Windows_AI_MachineLearning_ILearningModelDevice<D>::AdapterId() const
{
    Windows::Graphics::DisplayAdapterId value{};
    check_hresult(WINRT_SHIM(Windows::AI::MachineLearning::ILearningModelDevice)->get_AdapterId(put_abi(value)));
    return value;
}

template <typename D> Windows::Graphics::DirectX::Direct3D11::IDirect3DDevice consume_Windows_AI_MachineLearning_ILearningModelDevice<D>::Direct3D11Device() const
{
    Windows::Graphics::DirectX::Direct3D11::IDirect3DDevice value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::AI::MachineLearning::ILearningModelDevice)->get_Direct3D11Device(put_abi(value)));
    return value;
}

template <typename D> Windows::AI::MachineLearning::LearningModelDevice consume_Windows_AI_MachineLearning_ILearningModelDeviceFactory<D>::Create(Windows::AI::MachineLearning::LearningModelDeviceKind const& deviceKind) const
{
    Windows::AI::MachineLearning::LearningModelDevice value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::AI::MachineLearning::ILearningModelDeviceFactory)->Create(get_abi(deviceKind), put_abi(value)));
    return value;
}

template <typename D> Windows::AI::MachineLearning::LearningModelDevice consume_Windows_AI_MachineLearning_ILearningModelDeviceStatics<D>::CreateFromDirect3D11Device(Windows::Graphics::DirectX::Direct3D11::IDirect3DDevice const& device) const
{
    Windows::AI::MachineLearning::LearningModelDevice result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::AI::MachineLearning::ILearningModelDeviceStatics)->CreateFromDirect3D11Device(get_abi(device), put_abi(result)));
    return result;
}

template <typename D> hstring consume_Windows_AI_MachineLearning_ILearningModelEvaluationResult<D>::CorrelationId() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::AI::MachineLearning::ILearningModelEvaluationResult)->get_CorrelationId(put_abi(value)));
    return value;
}

template <typename D> int32_t consume_Windows_AI_MachineLearning_ILearningModelEvaluationResult<D>::ErrorStatus() const
{
    int32_t value{};
    check_hresult(WINRT_SHIM(Windows::AI::MachineLearning::ILearningModelEvaluationResult)->get_ErrorStatus(&value));
    return value;
}

template <typename D> bool consume_Windows_AI_MachineLearning_ILearningModelEvaluationResult<D>::Succeeded() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::AI::MachineLearning::ILearningModelEvaluationResult)->get_Succeeded(&value));
    return value;
}

template <typename D> Windows::Foundation::Collections::IMapView<hstring, Windows::Foundation::IInspectable> consume_Windows_AI_MachineLearning_ILearningModelEvaluationResult<D>::Outputs() const
{
    Windows::Foundation::Collections::IMapView<hstring, Windows::Foundation::IInspectable> value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::AI::MachineLearning::ILearningModelEvaluationResult)->get_Outputs(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_AI_MachineLearning_ILearningModelFeatureDescriptor<D>::Name() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::AI::MachineLearning::ILearningModelFeatureDescriptor)->get_Name(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_AI_MachineLearning_ILearningModelFeatureDescriptor<D>::Description() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::AI::MachineLearning::ILearningModelFeatureDescriptor)->get_Description(put_abi(value)));
    return value;
}

template <typename D> Windows::AI::MachineLearning::LearningModelFeatureKind consume_Windows_AI_MachineLearning_ILearningModelFeatureDescriptor<D>::Kind() const
{
    Windows::AI::MachineLearning::LearningModelFeatureKind value{};
    check_hresult(WINRT_SHIM(Windows::AI::MachineLearning::ILearningModelFeatureDescriptor)->get_Kind(put_abi(value)));
    return value;
}

template <typename D> bool consume_Windows_AI_MachineLearning_ILearningModelFeatureDescriptor<D>::IsRequired() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::AI::MachineLearning::ILearningModelFeatureDescriptor)->get_IsRequired(&value));
    return value;
}

template <typename D> Windows::AI::MachineLearning::LearningModelFeatureKind consume_Windows_AI_MachineLearning_ILearningModelFeatureValue<D>::Kind() const
{
    Windows::AI::MachineLearning::LearningModelFeatureKind value{};
    check_hresult(WINRT_SHIM(Windows::AI::MachineLearning::ILearningModelFeatureValue)->get_Kind(put_abi(value)));
    return value;
}

template <typename D> Windows::AI::MachineLearning::LearningModel consume_Windows_AI_MachineLearning_ILearningModelSession<D>::Model() const
{
    Windows::AI::MachineLearning::LearningModel value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::AI::MachineLearning::ILearningModelSession)->get_Model(put_abi(value)));
    return value;
}

template <typename D> Windows::AI::MachineLearning::LearningModelDevice consume_Windows_AI_MachineLearning_ILearningModelSession<D>::Device() const
{
    Windows::AI::MachineLearning::LearningModelDevice value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::AI::MachineLearning::ILearningModelSession)->get_Device(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::Collections::IPropertySet consume_Windows_AI_MachineLearning_ILearningModelSession<D>::EvaluationProperties() const
{
    Windows::Foundation::Collections::IPropertySet value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::AI::MachineLearning::ILearningModelSession)->get_EvaluationProperties(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::IAsyncOperation<Windows::AI::MachineLearning::LearningModelEvaluationResult> consume_Windows_AI_MachineLearning_ILearningModelSession<D>::EvaluateAsync(Windows::AI::MachineLearning::LearningModelBinding const& bindings, param::hstring const& correlationId) const
{
    Windows::Foundation::IAsyncOperation<Windows::AI::MachineLearning::LearningModelEvaluationResult> operation{ nullptr };
    check_hresult(WINRT_SHIM(Windows::AI::MachineLearning::ILearningModelSession)->EvaluateAsync(get_abi(bindings), get_abi(correlationId), put_abi(operation)));
    return operation;
}

template <typename D> Windows::Foundation::IAsyncOperation<Windows::AI::MachineLearning::LearningModelEvaluationResult> consume_Windows_AI_MachineLearning_ILearningModelSession<D>::EvaluateFeaturesAsync(param::map<hstring, Windows::Foundation::IInspectable> const& features, param::hstring const& correlationId) const
{
    Windows::Foundation::IAsyncOperation<Windows::AI::MachineLearning::LearningModelEvaluationResult> operation{ nullptr };
    check_hresult(WINRT_SHIM(Windows::AI::MachineLearning::ILearningModelSession)->EvaluateFeaturesAsync(get_abi(features), get_abi(correlationId), put_abi(operation)));
    return operation;
}

template <typename D> Windows::AI::MachineLearning::LearningModelEvaluationResult consume_Windows_AI_MachineLearning_ILearningModelSession<D>::Evaluate(Windows::AI::MachineLearning::LearningModelBinding const& bindings, param::hstring const& correlationId) const
{
    Windows::AI::MachineLearning::LearningModelEvaluationResult result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::AI::MachineLearning::ILearningModelSession)->Evaluate(get_abi(bindings), get_abi(correlationId), put_abi(result)));
    return result;
}

template <typename D> Windows::AI::MachineLearning::LearningModelEvaluationResult consume_Windows_AI_MachineLearning_ILearningModelSession<D>::EvaluateFeatures(param::map<hstring, Windows::Foundation::IInspectable> const& features, param::hstring const& correlationId) const
{
    Windows::AI::MachineLearning::LearningModelEvaluationResult result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::AI::MachineLearning::ILearningModelSession)->EvaluateFeatures(get_abi(features), get_abi(correlationId), put_abi(result)));
    return result;
}

template <typename D> Windows::AI::MachineLearning::LearningModelSession consume_Windows_AI_MachineLearning_ILearningModelSessionFactory<D>::CreateFromModel(Windows::AI::MachineLearning::LearningModel const& model) const
{
    Windows::AI::MachineLearning::LearningModelSession value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::AI::MachineLearning::ILearningModelSessionFactory)->CreateFromModel(get_abi(model), put_abi(value)));
    return value;
}

template <typename D> Windows::AI::MachineLearning::LearningModelSession consume_Windows_AI_MachineLearning_ILearningModelSessionFactory<D>::CreateFromModelOnDevice(Windows::AI::MachineLearning::LearningModel const& model, Windows::AI::MachineLearning::LearningModelDevice const& deviceToRunOn) const
{
    Windows::AI::MachineLearning::LearningModelSession value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::AI::MachineLearning::ILearningModelSessionFactory)->CreateFromModelOnDevice(get_abi(model), get_abi(deviceToRunOn), put_abi(value)));
    return value;
}

template <typename D> Windows::AI::MachineLearning::LearningModelSession consume_Windows_AI_MachineLearning_ILearningModelSessionFactory2<D>::CreateFromModelOnDeviceWithSessionOptions(Windows::AI::MachineLearning::LearningModel const& model, Windows::AI::MachineLearning::LearningModelDevice const& deviceToRunOn, Windows::AI::MachineLearning::LearningModelSessionOptions const& learningModelSessionOptions) const
{
    Windows::AI::MachineLearning::LearningModelSession value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::AI::MachineLearning::ILearningModelSessionFactory2)->CreateFromModelOnDeviceWithSessionOptions(get_abi(model), get_abi(deviceToRunOn), get_abi(learningModelSessionOptions), put_abi(value)));
    return value;
}

template <typename D> uint32_t consume_Windows_AI_MachineLearning_ILearningModelSessionOptions<D>::BatchSizeOverride() const
{
    uint32_t value{};
    check_hresult(WINRT_SHIM(Windows::AI::MachineLearning::ILearningModelSessionOptions)->get_BatchSizeOverride(&value));
    return value;
}

template <typename D> void consume_Windows_AI_MachineLearning_ILearningModelSessionOptions<D>::BatchSizeOverride(uint32_t value) const
{
    check_hresult(WINRT_SHIM(Windows::AI::MachineLearning::ILearningModelSessionOptions)->put_BatchSizeOverride(value));
}

template <typename D> Windows::Foundation::IAsyncOperation<Windows::AI::MachineLearning::LearningModel> consume_Windows_AI_MachineLearning_ILearningModelStatics<D>::LoadFromStorageFileAsync(Windows::Storage::IStorageFile const& modelFile) const
{
    Windows::Foundation::IAsyncOperation<Windows::AI::MachineLearning::LearningModel> operation{ nullptr };
    check_hresult(WINRT_SHIM(Windows::AI::MachineLearning::ILearningModelStatics)->LoadFromStorageFileAsync(get_abi(modelFile), put_abi(operation)));
    return operation;
}

template <typename D> Windows::Foundation::IAsyncOperation<Windows::AI::MachineLearning::LearningModel> consume_Windows_AI_MachineLearning_ILearningModelStatics<D>::LoadFromStreamAsync(Windows::Storage::Streams::IRandomAccessStreamReference const& modelStream) const
{
    Windows::Foundation::IAsyncOperation<Windows::AI::MachineLearning::LearningModel> operation{ nullptr };
    check_hresult(WINRT_SHIM(Windows::AI::MachineLearning::ILearningModelStatics)->LoadFromStreamAsync(get_abi(modelStream), put_abi(operation)));
    return operation;
}

template <typename D> Windows::AI::MachineLearning::LearningModel consume_Windows_AI_MachineLearning_ILearningModelStatics<D>::LoadFromFilePath(param::hstring const& filePath) const
{
    Windows::AI::MachineLearning::LearningModel result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::AI::MachineLearning::ILearningModelStatics)->LoadFromFilePath(get_abi(filePath), put_abi(result)));
    return result;
}

template <typename D> Windows::AI::MachineLearning::LearningModel consume_Windows_AI_MachineLearning_ILearningModelStatics<D>::LoadFromStream(Windows::Storage::Streams::IRandomAccessStreamReference const& modelStream) const
{
    Windows::AI::MachineLearning::LearningModel result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::AI::MachineLearning::ILearningModelStatics)->LoadFromStream(get_abi(modelStream), put_abi(result)));
    return result;
}

template <typename D> Windows::Foundation::IAsyncOperation<Windows::AI::MachineLearning::LearningModel> consume_Windows_AI_MachineLearning_ILearningModelStatics<D>::LoadFromStorageFileAsync(Windows::Storage::IStorageFile const& modelFile, Windows::AI::MachineLearning::ILearningModelOperatorProvider const& operatorProvider) const
{
    Windows::Foundation::IAsyncOperation<Windows::AI::MachineLearning::LearningModel> operation{ nullptr };
    check_hresult(WINRT_SHIM(Windows::AI::MachineLearning::ILearningModelStatics)->LoadFromStorageFileWithOperatorProviderAsync(get_abi(modelFile), get_abi(operatorProvider), put_abi(operation)));
    return operation;
}

template <typename D> Windows::Foundation::IAsyncOperation<Windows::AI::MachineLearning::LearningModel> consume_Windows_AI_MachineLearning_ILearningModelStatics<D>::LoadFromStreamAsync(Windows::Storage::Streams::IRandomAccessStreamReference const& modelStream, Windows::AI::MachineLearning::ILearningModelOperatorProvider const& operatorProvider) const
{
    Windows::Foundation::IAsyncOperation<Windows::AI::MachineLearning::LearningModel> operation{ nullptr };
    check_hresult(WINRT_SHIM(Windows::AI::MachineLearning::ILearningModelStatics)->LoadFromStreamWithOperatorProviderAsync(get_abi(modelStream), get_abi(operatorProvider), put_abi(operation)));
    return operation;
}

template <typename D> Windows::AI::MachineLearning::LearningModel consume_Windows_AI_MachineLearning_ILearningModelStatics<D>::LoadFromFilePath(param::hstring const& filePath, Windows::AI::MachineLearning::ILearningModelOperatorProvider const& operatorProvider) const
{
    Windows::AI::MachineLearning::LearningModel result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::AI::MachineLearning::ILearningModelStatics)->LoadFromFilePathWithOperatorProvider(get_abi(filePath), get_abi(operatorProvider), put_abi(result)));
    return result;
}

template <typename D> Windows::AI::MachineLearning::LearningModel consume_Windows_AI_MachineLearning_ILearningModelStatics<D>::LoadFromStream(Windows::Storage::Streams::IRandomAccessStreamReference const& modelStream, Windows::AI::MachineLearning::ILearningModelOperatorProvider const& operatorProvider) const
{
    Windows::AI::MachineLearning::LearningModel result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::AI::MachineLearning::ILearningModelStatics)->LoadFromStreamWithOperatorProvider(get_abi(modelStream), get_abi(operatorProvider), put_abi(result)));
    return result;
}

template <typename D> Windows::AI::MachineLearning::TensorKind consume_Windows_AI_MachineLearning_IMapFeatureDescriptor<D>::KeyKind() const
{
    Windows::AI::MachineLearning::TensorKind value{};
    check_hresult(WINRT_SHIM(Windows::AI::MachineLearning::IMapFeatureDescriptor)->get_KeyKind(put_abi(value)));
    return value;
}

template <typename D> Windows::AI::MachineLearning::ILearningModelFeatureDescriptor consume_Windows_AI_MachineLearning_IMapFeatureDescriptor<D>::ValueDescriptor() const
{
    Windows::AI::MachineLearning::ILearningModelFeatureDescriptor value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::AI::MachineLearning::IMapFeatureDescriptor)->get_ValueDescriptor(put_abi(value)));
    return value;
}

template <typename D> Windows::AI::MachineLearning::ILearningModelFeatureDescriptor consume_Windows_AI_MachineLearning_ISequenceFeatureDescriptor<D>::ElementDescriptor() const
{
    Windows::AI::MachineLearning::ILearningModelFeatureDescriptor value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::AI::MachineLearning::ISequenceFeatureDescriptor)->get_ElementDescriptor(put_abi(value)));
    return value;
}

template <typename D> Windows::AI::MachineLearning::TensorKind consume_Windows_AI_MachineLearning_ITensor<D>::TensorKind() const
{
    Windows::AI::MachineLearning::TensorKind value{};
    check_hresult(WINRT_SHIM(Windows::AI::MachineLearning::ITensor)->get_TensorKind(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::Collections::IVectorView<int64_t> consume_Windows_AI_MachineLearning_ITensor<D>::Shape() const
{
    Windows::Foundation::Collections::IVectorView<int64_t> value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::AI::MachineLearning::ITensor)->get_Shape(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::Collections::IVectorView<bool> consume_Windows_AI_MachineLearning_ITensorBoolean<D>::GetAsVectorView() const
{
    Windows::Foundation::Collections::IVectorView<bool> result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::AI::MachineLearning::ITensorBoolean)->GetAsVectorView(put_abi(result)));
    return result;
}

template <typename D> Windows::AI::MachineLearning::TensorBoolean consume_Windows_AI_MachineLearning_ITensorBooleanStatics<D>::Create() const
{
    Windows::AI::MachineLearning::TensorBoolean result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::AI::MachineLearning::ITensorBooleanStatics)->Create(put_abi(result)));
    return result;
}

template <typename D> Windows::AI::MachineLearning::TensorBoolean consume_Windows_AI_MachineLearning_ITensorBooleanStatics<D>::Create(param::iterable<int64_t> const& shape) const
{
    Windows::AI::MachineLearning::TensorBoolean result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::AI::MachineLearning::ITensorBooleanStatics)->Create2(get_abi(shape), put_abi(result)));
    return result;
}

template <typename D> Windows::AI::MachineLearning::TensorBoolean consume_Windows_AI_MachineLearning_ITensorBooleanStatics<D>::CreateFromArray(param::iterable<int64_t> const& shape, array_view<bool const> data) const
{
    Windows::AI::MachineLearning::TensorBoolean result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::AI::MachineLearning::ITensorBooleanStatics)->CreateFromArray(get_abi(shape), data.size(), get_abi(data), put_abi(result)));
    return result;
}

template <typename D> Windows::AI::MachineLearning::TensorBoolean consume_Windows_AI_MachineLearning_ITensorBooleanStatics<D>::CreateFromIterable(param::iterable<int64_t> const& shape, param::iterable<bool> const& data) const
{
    Windows::AI::MachineLearning::TensorBoolean result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::AI::MachineLearning::ITensorBooleanStatics)->CreateFromIterable(get_abi(shape), get_abi(data), put_abi(result)));
    return result;
}

template <typename D> Windows::AI::MachineLearning::TensorBoolean consume_Windows_AI_MachineLearning_ITensorBooleanStatics2<D>::CreateFromShapeArrayAndDataArray(array_view<int64_t const> shape, array_view<bool const> data) const
{
    Windows::AI::MachineLearning::TensorBoolean result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::AI::MachineLearning::ITensorBooleanStatics2)->CreateFromShapeArrayAndDataArray(shape.size(), get_abi(shape), data.size(), get_abi(data), put_abi(result)));
    return result;
}

template <typename D> Windows::AI::MachineLearning::TensorBoolean consume_Windows_AI_MachineLearning_ITensorBooleanStatics2<D>::CreateFromBuffer(array_view<int64_t const> shape, Windows::Storage::Streams::IBuffer const& buffer) const
{
    Windows::AI::MachineLearning::TensorBoolean result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::AI::MachineLearning::ITensorBooleanStatics2)->CreateFromBuffer(shape.size(), get_abi(shape), get_abi(buffer), put_abi(result)));
    return result;
}

template <typename D> Windows::Foundation::Collections::IVectorView<double> consume_Windows_AI_MachineLearning_ITensorDouble<D>::GetAsVectorView() const
{
    Windows::Foundation::Collections::IVectorView<double> result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::AI::MachineLearning::ITensorDouble)->GetAsVectorView(put_abi(result)));
    return result;
}

template <typename D> Windows::AI::MachineLearning::TensorDouble consume_Windows_AI_MachineLearning_ITensorDoubleStatics<D>::Create() const
{
    Windows::AI::MachineLearning::TensorDouble result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::AI::MachineLearning::ITensorDoubleStatics)->Create(put_abi(result)));
    return result;
}

template <typename D> Windows::AI::MachineLearning::TensorDouble consume_Windows_AI_MachineLearning_ITensorDoubleStatics<D>::Create(param::iterable<int64_t> const& shape) const
{
    Windows::AI::MachineLearning::TensorDouble result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::AI::MachineLearning::ITensorDoubleStatics)->Create2(get_abi(shape), put_abi(result)));
    return result;
}

template <typename D> Windows::AI::MachineLearning::TensorDouble consume_Windows_AI_MachineLearning_ITensorDoubleStatics<D>::CreateFromArray(param::iterable<int64_t> const& shape, array_view<double const> data) const
{
    Windows::AI::MachineLearning::TensorDouble result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::AI::MachineLearning::ITensorDoubleStatics)->CreateFromArray(get_abi(shape), data.size(), get_abi(data), put_abi(result)));
    return result;
}

template <typename D> Windows::AI::MachineLearning::TensorDouble consume_Windows_AI_MachineLearning_ITensorDoubleStatics<D>::CreateFromIterable(param::iterable<int64_t> const& shape, param::iterable<double> const& data) const
{
    Windows::AI::MachineLearning::TensorDouble result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::AI::MachineLearning::ITensorDoubleStatics)->CreateFromIterable(get_abi(shape), get_abi(data), put_abi(result)));
    return result;
}

template <typename D> Windows::AI::MachineLearning::TensorDouble consume_Windows_AI_MachineLearning_ITensorDoubleStatics2<D>::CreateFromShapeArrayAndDataArray(array_view<int64_t const> shape, array_view<double const> data) const
{
    Windows::AI::MachineLearning::TensorDouble result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::AI::MachineLearning::ITensorDoubleStatics2)->CreateFromShapeArrayAndDataArray(shape.size(), get_abi(shape), data.size(), get_abi(data), put_abi(result)));
    return result;
}

template <typename D> Windows::AI::MachineLearning::TensorDouble consume_Windows_AI_MachineLearning_ITensorDoubleStatics2<D>::CreateFromBuffer(array_view<int64_t const> shape, Windows::Storage::Streams::IBuffer const& buffer) const
{
    Windows::AI::MachineLearning::TensorDouble result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::AI::MachineLearning::ITensorDoubleStatics2)->CreateFromBuffer(shape.size(), get_abi(shape), get_abi(buffer), put_abi(result)));
    return result;
}

template <typename D> Windows::AI::MachineLearning::TensorKind consume_Windows_AI_MachineLearning_ITensorFeatureDescriptor<D>::TensorKind() const
{
    Windows::AI::MachineLearning::TensorKind value{};
    check_hresult(WINRT_SHIM(Windows::AI::MachineLearning::ITensorFeatureDescriptor)->get_TensorKind(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::Collections::IVectorView<int64_t> consume_Windows_AI_MachineLearning_ITensorFeatureDescriptor<D>::Shape() const
{
    Windows::Foundation::Collections::IVectorView<int64_t> value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::AI::MachineLearning::ITensorFeatureDescriptor)->get_Shape(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::Collections::IVectorView<float> consume_Windows_AI_MachineLearning_ITensorFloat<D>::GetAsVectorView() const
{
    Windows::Foundation::Collections::IVectorView<float> result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::AI::MachineLearning::ITensorFloat)->GetAsVectorView(put_abi(result)));
    return result;
}

template <typename D> Windows::Foundation::Collections::IVectorView<float> consume_Windows_AI_MachineLearning_ITensorFloat16Bit<D>::GetAsVectorView() const
{
    Windows::Foundation::Collections::IVectorView<float> result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::AI::MachineLearning::ITensorFloat16Bit)->GetAsVectorView(put_abi(result)));
    return result;
}

template <typename D> Windows::AI::MachineLearning::TensorFloat16Bit consume_Windows_AI_MachineLearning_ITensorFloat16BitStatics<D>::Create() const
{
    Windows::AI::MachineLearning::TensorFloat16Bit result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::AI::MachineLearning::ITensorFloat16BitStatics)->Create(put_abi(result)));
    return result;
}

template <typename D> Windows::AI::MachineLearning::TensorFloat16Bit consume_Windows_AI_MachineLearning_ITensorFloat16BitStatics<D>::Create(param::iterable<int64_t> const& shape) const
{
    Windows::AI::MachineLearning::TensorFloat16Bit result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::AI::MachineLearning::ITensorFloat16BitStatics)->Create2(get_abi(shape), put_abi(result)));
    return result;
}

template <typename D> Windows::AI::MachineLearning::TensorFloat16Bit consume_Windows_AI_MachineLearning_ITensorFloat16BitStatics<D>::CreateFromArray(param::iterable<int64_t> const& shape, array_view<float const> data) const
{
    Windows::AI::MachineLearning::TensorFloat16Bit result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::AI::MachineLearning::ITensorFloat16BitStatics)->CreateFromArray(get_abi(shape), data.size(), get_abi(data), put_abi(result)));
    return result;
}

template <typename D> Windows::AI::MachineLearning::TensorFloat16Bit consume_Windows_AI_MachineLearning_ITensorFloat16BitStatics<D>::CreateFromIterable(param::iterable<int64_t> const& shape, param::iterable<float> const& data) const
{
    Windows::AI::MachineLearning::TensorFloat16Bit result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::AI::MachineLearning::ITensorFloat16BitStatics)->CreateFromIterable(get_abi(shape), get_abi(data), put_abi(result)));
    return result;
}

template <typename D> Windows::AI::MachineLearning::TensorFloat16Bit consume_Windows_AI_MachineLearning_ITensorFloat16BitStatics2<D>::CreateFromShapeArrayAndDataArray(array_view<int64_t const> shape, array_view<float const> data) const
{
    Windows::AI::MachineLearning::TensorFloat16Bit result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::AI::MachineLearning::ITensorFloat16BitStatics2)->CreateFromShapeArrayAndDataArray(shape.size(), get_abi(shape), data.size(), get_abi(data), put_abi(result)));
    return result;
}

template <typename D> Windows::AI::MachineLearning::TensorFloat16Bit consume_Windows_AI_MachineLearning_ITensorFloat16BitStatics2<D>::CreateFromBuffer(array_view<int64_t const> shape, Windows::Storage::Streams::IBuffer const& buffer) const
{
    Windows::AI::MachineLearning::TensorFloat16Bit result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::AI::MachineLearning::ITensorFloat16BitStatics2)->CreateFromBuffer(shape.size(), get_abi(shape), get_abi(buffer), put_abi(result)));
    return result;
}

template <typename D> Windows::AI::MachineLearning::TensorFloat consume_Windows_AI_MachineLearning_ITensorFloatStatics<D>::Create() const
{
    Windows::AI::MachineLearning::TensorFloat result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::AI::MachineLearning::ITensorFloatStatics)->Create(put_abi(result)));
    return result;
}

template <typename D> Windows::AI::MachineLearning::TensorFloat consume_Windows_AI_MachineLearning_ITensorFloatStatics<D>::Create(param::iterable<int64_t> const& shape) const
{
    Windows::AI::MachineLearning::TensorFloat result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::AI::MachineLearning::ITensorFloatStatics)->Create2(get_abi(shape), put_abi(result)));
    return result;
}

template <typename D> Windows::AI::MachineLearning::TensorFloat consume_Windows_AI_MachineLearning_ITensorFloatStatics<D>::CreateFromArray(param::iterable<int64_t> const& shape, array_view<float const> data) const
{
    Windows::AI::MachineLearning::TensorFloat result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::AI::MachineLearning::ITensorFloatStatics)->CreateFromArray(get_abi(shape), data.size(), get_abi(data), put_abi(result)));
    return result;
}

template <typename D> Windows::AI::MachineLearning::TensorFloat consume_Windows_AI_MachineLearning_ITensorFloatStatics<D>::CreateFromIterable(param::iterable<int64_t> const& shape, param::iterable<float> const& data) const
{
    Windows::AI::MachineLearning::TensorFloat result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::AI::MachineLearning::ITensorFloatStatics)->CreateFromIterable(get_abi(shape), get_abi(data), put_abi(result)));
    return result;
}

template <typename D> Windows::AI::MachineLearning::TensorFloat consume_Windows_AI_MachineLearning_ITensorFloatStatics2<D>::CreateFromShapeArrayAndDataArray(array_view<int64_t const> shape, array_view<float const> data) const
{
    Windows::AI::MachineLearning::TensorFloat result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::AI::MachineLearning::ITensorFloatStatics2)->CreateFromShapeArrayAndDataArray(shape.size(), get_abi(shape), data.size(), get_abi(data), put_abi(result)));
    return result;
}

template <typename D> Windows::AI::MachineLearning::TensorFloat consume_Windows_AI_MachineLearning_ITensorFloatStatics2<D>::CreateFromBuffer(array_view<int64_t const> shape, Windows::Storage::Streams::IBuffer const& buffer) const
{
    Windows::AI::MachineLearning::TensorFloat result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::AI::MachineLearning::ITensorFloatStatics2)->CreateFromBuffer(shape.size(), get_abi(shape), get_abi(buffer), put_abi(result)));
    return result;
}

template <typename D> Windows::Foundation::Collections::IVectorView<int16_t> consume_Windows_AI_MachineLearning_ITensorInt16Bit<D>::GetAsVectorView() const
{
    Windows::Foundation::Collections::IVectorView<int16_t> result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::AI::MachineLearning::ITensorInt16Bit)->GetAsVectorView(put_abi(result)));
    return result;
}

template <typename D> Windows::AI::MachineLearning::TensorInt16Bit consume_Windows_AI_MachineLearning_ITensorInt16BitStatics<D>::Create() const
{
    Windows::AI::MachineLearning::TensorInt16Bit result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::AI::MachineLearning::ITensorInt16BitStatics)->Create(put_abi(result)));
    return result;
}

template <typename D> Windows::AI::MachineLearning::TensorInt16Bit consume_Windows_AI_MachineLearning_ITensorInt16BitStatics<D>::Create(param::iterable<int64_t> const& shape) const
{
    Windows::AI::MachineLearning::TensorInt16Bit result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::AI::MachineLearning::ITensorInt16BitStatics)->Create2(get_abi(shape), put_abi(result)));
    return result;
}

template <typename D> Windows::AI::MachineLearning::TensorInt16Bit consume_Windows_AI_MachineLearning_ITensorInt16BitStatics<D>::CreateFromArray(param::iterable<int64_t> const& shape, array_view<int16_t const> data) const
{
    Windows::AI::MachineLearning::TensorInt16Bit result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::AI::MachineLearning::ITensorInt16BitStatics)->CreateFromArray(get_abi(shape), data.size(), get_abi(data), put_abi(result)));
    return result;
}

template <typename D> Windows::AI::MachineLearning::TensorInt16Bit consume_Windows_AI_MachineLearning_ITensorInt16BitStatics<D>::CreateFromIterable(param::iterable<int64_t> const& shape, param::iterable<int16_t> const& data) const
{
    Windows::AI::MachineLearning::TensorInt16Bit result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::AI::MachineLearning::ITensorInt16BitStatics)->CreateFromIterable(get_abi(shape), get_abi(data), put_abi(result)));
    return result;
}

template <typename D> Windows::AI::MachineLearning::TensorInt16Bit consume_Windows_AI_MachineLearning_ITensorInt16BitStatics2<D>::CreateFromShapeArrayAndDataArray(array_view<int64_t const> shape, array_view<int16_t const> data) const
{
    Windows::AI::MachineLearning::TensorInt16Bit result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::AI::MachineLearning::ITensorInt16BitStatics2)->CreateFromShapeArrayAndDataArray(shape.size(), get_abi(shape), data.size(), get_abi(data), put_abi(result)));
    return result;
}

template <typename D> Windows::AI::MachineLearning::TensorInt16Bit consume_Windows_AI_MachineLearning_ITensorInt16BitStatics2<D>::CreateFromBuffer(array_view<int64_t const> shape, Windows::Storage::Streams::IBuffer const& buffer) const
{
    Windows::AI::MachineLearning::TensorInt16Bit result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::AI::MachineLearning::ITensorInt16BitStatics2)->CreateFromBuffer(shape.size(), get_abi(shape), get_abi(buffer), put_abi(result)));
    return result;
}

template <typename D> Windows::Foundation::Collections::IVectorView<int32_t> consume_Windows_AI_MachineLearning_ITensorInt32Bit<D>::GetAsVectorView() const
{
    Windows::Foundation::Collections::IVectorView<int32_t> result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::AI::MachineLearning::ITensorInt32Bit)->GetAsVectorView(put_abi(result)));
    return result;
}

template <typename D> Windows::AI::MachineLearning::TensorInt32Bit consume_Windows_AI_MachineLearning_ITensorInt32BitStatics<D>::Create() const
{
    Windows::AI::MachineLearning::TensorInt32Bit result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::AI::MachineLearning::ITensorInt32BitStatics)->Create(put_abi(result)));
    return result;
}

template <typename D> Windows::AI::MachineLearning::TensorInt32Bit consume_Windows_AI_MachineLearning_ITensorInt32BitStatics<D>::Create(param::iterable<int64_t> const& shape) const
{
    Windows::AI::MachineLearning::TensorInt32Bit result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::AI::MachineLearning::ITensorInt32BitStatics)->Create2(get_abi(shape), put_abi(result)));
    return result;
}

template <typename D> Windows::AI::MachineLearning::TensorInt32Bit consume_Windows_AI_MachineLearning_ITensorInt32BitStatics<D>::CreateFromArray(param::iterable<int64_t> const& shape, array_view<int32_t const> data) const
{
    Windows::AI::MachineLearning::TensorInt32Bit result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::AI::MachineLearning::ITensorInt32BitStatics)->CreateFromArray(get_abi(shape), data.size(), get_abi(data), put_abi(result)));
    return result;
}

template <typename D> Windows::AI::MachineLearning::TensorInt32Bit consume_Windows_AI_MachineLearning_ITensorInt32BitStatics<D>::CreateFromIterable(param::iterable<int64_t> const& shape, param::iterable<int32_t> const& data) const
{
    Windows::AI::MachineLearning::TensorInt32Bit result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::AI::MachineLearning::ITensorInt32BitStatics)->CreateFromIterable(get_abi(shape), get_abi(data), put_abi(result)));
    return result;
}

template <typename D> Windows::AI::MachineLearning::TensorInt32Bit consume_Windows_AI_MachineLearning_ITensorInt32BitStatics2<D>::CreateFromShapeArrayAndDataArray(array_view<int64_t const> shape, array_view<int32_t const> data) const
{
    Windows::AI::MachineLearning::TensorInt32Bit result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::AI::MachineLearning::ITensorInt32BitStatics2)->CreateFromShapeArrayAndDataArray(shape.size(), get_abi(shape), data.size(), get_abi(data), put_abi(result)));
    return result;
}

template <typename D> Windows::AI::MachineLearning::TensorInt32Bit consume_Windows_AI_MachineLearning_ITensorInt32BitStatics2<D>::CreateFromBuffer(array_view<int64_t const> shape, Windows::Storage::Streams::IBuffer const& buffer) const
{
    Windows::AI::MachineLearning::TensorInt32Bit result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::AI::MachineLearning::ITensorInt32BitStatics2)->CreateFromBuffer(shape.size(), get_abi(shape), get_abi(buffer), put_abi(result)));
    return result;
}

template <typename D> Windows::Foundation::Collections::IVectorView<int64_t> consume_Windows_AI_MachineLearning_ITensorInt64Bit<D>::GetAsVectorView() const
{
    Windows::Foundation::Collections::IVectorView<int64_t> result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::AI::MachineLearning::ITensorInt64Bit)->GetAsVectorView(put_abi(result)));
    return result;
}

template <typename D> Windows::AI::MachineLearning::TensorInt64Bit consume_Windows_AI_MachineLearning_ITensorInt64BitStatics<D>::Create() const
{
    Windows::AI::MachineLearning::TensorInt64Bit result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::AI::MachineLearning::ITensorInt64BitStatics)->Create(put_abi(result)));
    return result;
}

template <typename D> Windows::AI::MachineLearning::TensorInt64Bit consume_Windows_AI_MachineLearning_ITensorInt64BitStatics<D>::Create(param::iterable<int64_t> const& shape) const
{
    Windows::AI::MachineLearning::TensorInt64Bit result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::AI::MachineLearning::ITensorInt64BitStatics)->Create2(get_abi(shape), put_abi(result)));
    return result;
}

template <typename D> Windows::AI::MachineLearning::TensorInt64Bit consume_Windows_AI_MachineLearning_ITensorInt64BitStatics<D>::CreateFromArray(param::iterable<int64_t> const& shape, array_view<int64_t const> data) const
{
    Windows::AI::MachineLearning::TensorInt64Bit result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::AI::MachineLearning::ITensorInt64BitStatics)->CreateFromArray(get_abi(shape), data.size(), get_abi(data), put_abi(result)));
    return result;
}

template <typename D> Windows::AI::MachineLearning::TensorInt64Bit consume_Windows_AI_MachineLearning_ITensorInt64BitStatics<D>::CreateFromIterable(param::iterable<int64_t> const& shape, param::iterable<int64_t> const& data) const
{
    Windows::AI::MachineLearning::TensorInt64Bit result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::AI::MachineLearning::ITensorInt64BitStatics)->CreateFromIterable(get_abi(shape), get_abi(data), put_abi(result)));
    return result;
}

template <typename D> Windows::AI::MachineLearning::TensorInt64Bit consume_Windows_AI_MachineLearning_ITensorInt64BitStatics2<D>::CreateFromShapeArrayAndDataArray(array_view<int64_t const> shape, array_view<int64_t const> data) const
{
    Windows::AI::MachineLearning::TensorInt64Bit result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::AI::MachineLearning::ITensorInt64BitStatics2)->CreateFromShapeArrayAndDataArray(shape.size(), get_abi(shape), data.size(), get_abi(data), put_abi(result)));
    return result;
}

template <typename D> Windows::AI::MachineLearning::TensorInt64Bit consume_Windows_AI_MachineLearning_ITensorInt64BitStatics2<D>::CreateFromBuffer(array_view<int64_t const> shape, Windows::Storage::Streams::IBuffer const& buffer) const
{
    Windows::AI::MachineLearning::TensorInt64Bit result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::AI::MachineLearning::ITensorInt64BitStatics2)->CreateFromBuffer(shape.size(), get_abi(shape), get_abi(buffer), put_abi(result)));
    return result;
}

template <typename D> Windows::Foundation::Collections::IVectorView<uint8_t> consume_Windows_AI_MachineLearning_ITensorInt8Bit<D>::GetAsVectorView() const
{
    Windows::Foundation::Collections::IVectorView<uint8_t> result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::AI::MachineLearning::ITensorInt8Bit)->GetAsVectorView(put_abi(result)));
    return result;
}

template <typename D> Windows::AI::MachineLearning::TensorInt8Bit consume_Windows_AI_MachineLearning_ITensorInt8BitStatics<D>::Create() const
{
    Windows::AI::MachineLearning::TensorInt8Bit result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::AI::MachineLearning::ITensorInt8BitStatics)->Create(put_abi(result)));
    return result;
}

template <typename D> Windows::AI::MachineLearning::TensorInt8Bit consume_Windows_AI_MachineLearning_ITensorInt8BitStatics<D>::Create(param::iterable<int64_t> const& shape) const
{
    Windows::AI::MachineLearning::TensorInt8Bit result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::AI::MachineLearning::ITensorInt8BitStatics)->Create2(get_abi(shape), put_abi(result)));
    return result;
}

template <typename D> Windows::AI::MachineLearning::TensorInt8Bit consume_Windows_AI_MachineLearning_ITensorInt8BitStatics<D>::CreateFromArray(param::iterable<int64_t> const& shape, array_view<uint8_t const> data) const
{
    Windows::AI::MachineLearning::TensorInt8Bit result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::AI::MachineLearning::ITensorInt8BitStatics)->CreateFromArray(get_abi(shape), data.size(), get_abi(data), put_abi(result)));
    return result;
}

template <typename D> Windows::AI::MachineLearning::TensorInt8Bit consume_Windows_AI_MachineLearning_ITensorInt8BitStatics<D>::CreateFromIterable(param::iterable<int64_t> const& shape, param::iterable<uint8_t> const& data) const
{
    Windows::AI::MachineLearning::TensorInt8Bit result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::AI::MachineLearning::ITensorInt8BitStatics)->CreateFromIterable(get_abi(shape), get_abi(data), put_abi(result)));
    return result;
}

template <typename D> Windows::AI::MachineLearning::TensorInt8Bit consume_Windows_AI_MachineLearning_ITensorInt8BitStatics2<D>::CreateFromShapeArrayAndDataArray(array_view<int64_t const> shape, array_view<uint8_t const> data) const
{
    Windows::AI::MachineLearning::TensorInt8Bit result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::AI::MachineLearning::ITensorInt8BitStatics2)->CreateFromShapeArrayAndDataArray(shape.size(), get_abi(shape), data.size(), get_abi(data), put_abi(result)));
    return result;
}

template <typename D> Windows::AI::MachineLearning::TensorInt8Bit consume_Windows_AI_MachineLearning_ITensorInt8BitStatics2<D>::CreateFromBuffer(array_view<int64_t const> shape, Windows::Storage::Streams::IBuffer const& buffer) const
{
    Windows::AI::MachineLearning::TensorInt8Bit result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::AI::MachineLearning::ITensorInt8BitStatics2)->CreateFromBuffer(shape.size(), get_abi(shape), get_abi(buffer), put_abi(result)));
    return result;
}

template <typename D> Windows::Foundation::Collections::IVectorView<hstring> consume_Windows_AI_MachineLearning_ITensorString<D>::GetAsVectorView() const
{
    Windows::Foundation::Collections::IVectorView<hstring> result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::AI::MachineLearning::ITensorString)->GetAsVectorView(put_abi(result)));
    return result;
}

template <typename D> Windows::AI::MachineLearning::TensorString consume_Windows_AI_MachineLearning_ITensorStringStatics<D>::Create() const
{
    Windows::AI::MachineLearning::TensorString result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::AI::MachineLearning::ITensorStringStatics)->Create(put_abi(result)));
    return result;
}

template <typename D> Windows::AI::MachineLearning::TensorString consume_Windows_AI_MachineLearning_ITensorStringStatics<D>::Create(param::iterable<int64_t> const& shape) const
{
    Windows::AI::MachineLearning::TensorString result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::AI::MachineLearning::ITensorStringStatics)->Create2(get_abi(shape), put_abi(result)));
    return result;
}

template <typename D> Windows::AI::MachineLearning::TensorString consume_Windows_AI_MachineLearning_ITensorStringStatics<D>::CreateFromArray(param::iterable<int64_t> const& shape, array_view<hstring const> data) const
{
    Windows::AI::MachineLearning::TensorString result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::AI::MachineLearning::ITensorStringStatics)->CreateFromArray(get_abi(shape), data.size(), get_abi(data), put_abi(result)));
    return result;
}

template <typename D> Windows::AI::MachineLearning::TensorString consume_Windows_AI_MachineLearning_ITensorStringStatics<D>::CreateFromIterable(param::iterable<int64_t> const& shape, param::iterable<hstring> const& data) const
{
    Windows::AI::MachineLearning::TensorString result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::AI::MachineLearning::ITensorStringStatics)->CreateFromIterable(get_abi(shape), get_abi(data), put_abi(result)));
    return result;
}

template <typename D> Windows::AI::MachineLearning::TensorString consume_Windows_AI_MachineLearning_ITensorStringStatics2<D>::CreateFromShapeArrayAndDataArray(array_view<int64_t const> shape, array_view<hstring const> data) const
{
    Windows::AI::MachineLearning::TensorString result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::AI::MachineLearning::ITensorStringStatics2)->CreateFromShapeArrayAndDataArray(shape.size(), get_abi(shape), data.size(), get_abi(data), put_abi(result)));
    return result;
}

template <typename D> Windows::Foundation::Collections::IVectorView<uint16_t> consume_Windows_AI_MachineLearning_ITensorUInt16Bit<D>::GetAsVectorView() const
{
    Windows::Foundation::Collections::IVectorView<uint16_t> result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::AI::MachineLearning::ITensorUInt16Bit)->GetAsVectorView(put_abi(result)));
    return result;
}

template <typename D> Windows::AI::MachineLearning::TensorUInt16Bit consume_Windows_AI_MachineLearning_ITensorUInt16BitStatics<D>::Create() const
{
    Windows::AI::MachineLearning::TensorUInt16Bit result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::AI::MachineLearning::ITensorUInt16BitStatics)->Create(put_abi(result)));
    return result;
}

template <typename D> Windows::AI::MachineLearning::TensorUInt16Bit consume_Windows_AI_MachineLearning_ITensorUInt16BitStatics<D>::Create(param::iterable<int64_t> const& shape) const
{
    Windows::AI::MachineLearning::TensorUInt16Bit result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::AI::MachineLearning::ITensorUInt16BitStatics)->Create2(get_abi(shape), put_abi(result)));
    return result;
}

template <typename D> Windows::AI::MachineLearning::TensorUInt16Bit consume_Windows_AI_MachineLearning_ITensorUInt16BitStatics<D>::CreateFromArray(param::iterable<int64_t> const& shape, array_view<uint16_t const> data) const
{
    Windows::AI::MachineLearning::TensorUInt16Bit result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::AI::MachineLearning::ITensorUInt16BitStatics)->CreateFromArray(get_abi(shape), data.size(), get_abi(data), put_abi(result)));
    return result;
}

template <typename D> Windows::AI::MachineLearning::TensorUInt16Bit consume_Windows_AI_MachineLearning_ITensorUInt16BitStatics<D>::CreateFromIterable(param::iterable<int64_t> const& shape, param::iterable<uint16_t> const& data) const
{
    Windows::AI::MachineLearning::TensorUInt16Bit result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::AI::MachineLearning::ITensorUInt16BitStatics)->CreateFromIterable(get_abi(shape), get_abi(data), put_abi(result)));
    return result;
}

template <typename D> Windows::AI::MachineLearning::TensorUInt16Bit consume_Windows_AI_MachineLearning_ITensorUInt16BitStatics2<D>::CreateFromShapeArrayAndDataArray(array_view<int64_t const> shape, array_view<uint16_t const> data) const
{
    Windows::AI::MachineLearning::TensorUInt16Bit result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::AI::MachineLearning::ITensorUInt16BitStatics2)->CreateFromShapeArrayAndDataArray(shape.size(), get_abi(shape), data.size(), get_abi(data), put_abi(result)));
    return result;
}

template <typename D> Windows::AI::MachineLearning::TensorUInt16Bit consume_Windows_AI_MachineLearning_ITensorUInt16BitStatics2<D>::CreateFromBuffer(array_view<int64_t const> shape, Windows::Storage::Streams::IBuffer const& buffer) const
{
    Windows::AI::MachineLearning::TensorUInt16Bit result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::AI::MachineLearning::ITensorUInt16BitStatics2)->CreateFromBuffer(shape.size(), get_abi(shape), get_abi(buffer), put_abi(result)));
    return result;
}

template <typename D> Windows::Foundation::Collections::IVectorView<uint32_t> consume_Windows_AI_MachineLearning_ITensorUInt32Bit<D>::GetAsVectorView() const
{
    Windows::Foundation::Collections::IVectorView<uint32_t> result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::AI::MachineLearning::ITensorUInt32Bit)->GetAsVectorView(put_abi(result)));
    return result;
}

template <typename D> Windows::AI::MachineLearning::TensorUInt32Bit consume_Windows_AI_MachineLearning_ITensorUInt32BitStatics<D>::Create() const
{
    Windows::AI::MachineLearning::TensorUInt32Bit result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::AI::MachineLearning::ITensorUInt32BitStatics)->Create(put_abi(result)));
    return result;
}

template <typename D> Windows::AI::MachineLearning::TensorUInt32Bit consume_Windows_AI_MachineLearning_ITensorUInt32BitStatics<D>::Create(param::iterable<int64_t> const& shape) const
{
    Windows::AI::MachineLearning::TensorUInt32Bit result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::AI::MachineLearning::ITensorUInt32BitStatics)->Create2(get_abi(shape), put_abi(result)));
    return result;
}

template <typename D> Windows::AI::MachineLearning::TensorUInt32Bit consume_Windows_AI_MachineLearning_ITensorUInt32BitStatics<D>::CreateFromArray(param::iterable<int64_t> const& shape, array_view<uint32_t const> data) const
{
    Windows::AI::MachineLearning::TensorUInt32Bit result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::AI::MachineLearning::ITensorUInt32BitStatics)->CreateFromArray(get_abi(shape), data.size(), get_abi(data), put_abi(result)));
    return result;
}

template <typename D> Windows::AI::MachineLearning::TensorUInt32Bit consume_Windows_AI_MachineLearning_ITensorUInt32BitStatics<D>::CreateFromIterable(param::iterable<int64_t> const& shape, param::iterable<uint32_t> const& data) const
{
    Windows::AI::MachineLearning::TensorUInt32Bit result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::AI::MachineLearning::ITensorUInt32BitStatics)->CreateFromIterable(get_abi(shape), get_abi(data), put_abi(result)));
    return result;
}

template <typename D> Windows::AI::MachineLearning::TensorUInt32Bit consume_Windows_AI_MachineLearning_ITensorUInt32BitStatics2<D>::CreateFromShapeArrayAndDataArray(array_view<int64_t const> shape, array_view<uint32_t const> data) const
{
    Windows::AI::MachineLearning::TensorUInt32Bit result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::AI::MachineLearning::ITensorUInt32BitStatics2)->CreateFromShapeArrayAndDataArray(shape.size(), get_abi(shape), data.size(), get_abi(data), put_abi(result)));
    return result;
}

template <typename D> Windows::AI::MachineLearning::TensorUInt32Bit consume_Windows_AI_MachineLearning_ITensorUInt32BitStatics2<D>::CreateFromBuffer(array_view<int64_t const> shape, Windows::Storage::Streams::IBuffer const& buffer) const
{
    Windows::AI::MachineLearning::TensorUInt32Bit result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::AI::MachineLearning::ITensorUInt32BitStatics2)->CreateFromBuffer(shape.size(), get_abi(shape), get_abi(buffer), put_abi(result)));
    return result;
}

template <typename D> Windows::Foundation::Collections::IVectorView<uint64_t> consume_Windows_AI_MachineLearning_ITensorUInt64Bit<D>::GetAsVectorView() const
{
    Windows::Foundation::Collections::IVectorView<uint64_t> result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::AI::MachineLearning::ITensorUInt64Bit)->GetAsVectorView(put_abi(result)));
    return result;
}

template <typename D> Windows::AI::MachineLearning::TensorUInt64Bit consume_Windows_AI_MachineLearning_ITensorUInt64BitStatics<D>::Create() const
{
    Windows::AI::MachineLearning::TensorUInt64Bit result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::AI::MachineLearning::ITensorUInt64BitStatics)->Create(put_abi(result)));
    return result;
}

template <typename D> Windows::AI::MachineLearning::TensorUInt64Bit consume_Windows_AI_MachineLearning_ITensorUInt64BitStatics<D>::Create(param::iterable<int64_t> const& shape) const
{
    Windows::AI::MachineLearning::TensorUInt64Bit result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::AI::MachineLearning::ITensorUInt64BitStatics)->Create2(get_abi(shape), put_abi(result)));
    return result;
}

template <typename D> Windows::AI::MachineLearning::TensorUInt64Bit consume_Windows_AI_MachineLearning_ITensorUInt64BitStatics<D>::CreateFromArray(param::iterable<int64_t> const& shape, array_view<uint64_t const> data) const
{
    Windows::AI::MachineLearning::TensorUInt64Bit result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::AI::MachineLearning::ITensorUInt64BitStatics)->CreateFromArray(get_abi(shape), data.size(), get_abi(data), put_abi(result)));
    return result;
}

template <typename D> Windows::AI::MachineLearning::TensorUInt64Bit consume_Windows_AI_MachineLearning_ITensorUInt64BitStatics<D>::CreateFromIterable(param::iterable<int64_t> const& shape, param::iterable<uint64_t> const& data) const
{
    Windows::AI::MachineLearning::TensorUInt64Bit result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::AI::MachineLearning::ITensorUInt64BitStatics)->CreateFromIterable(get_abi(shape), get_abi(data), put_abi(result)));
    return result;
}

template <typename D> Windows::AI::MachineLearning::TensorUInt64Bit consume_Windows_AI_MachineLearning_ITensorUInt64BitStatics2<D>::CreateFromShapeArrayAndDataArray(array_view<int64_t const> shape, array_view<uint64_t const> data) const
{
    Windows::AI::MachineLearning::TensorUInt64Bit result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::AI::MachineLearning::ITensorUInt64BitStatics2)->CreateFromShapeArrayAndDataArray(shape.size(), get_abi(shape), data.size(), get_abi(data), put_abi(result)));
    return result;
}

template <typename D> Windows::AI::MachineLearning::TensorUInt64Bit consume_Windows_AI_MachineLearning_ITensorUInt64BitStatics2<D>::CreateFromBuffer(array_view<int64_t const> shape, Windows::Storage::Streams::IBuffer const& buffer) const
{
    Windows::AI::MachineLearning::TensorUInt64Bit result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::AI::MachineLearning::ITensorUInt64BitStatics2)->CreateFromBuffer(shape.size(), get_abi(shape), get_abi(buffer), put_abi(result)));
    return result;
}

template <typename D> Windows::Foundation::Collections::IVectorView<uint8_t> consume_Windows_AI_MachineLearning_ITensorUInt8Bit<D>::GetAsVectorView() const
{
    Windows::Foundation::Collections::IVectorView<uint8_t> result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::AI::MachineLearning::ITensorUInt8Bit)->GetAsVectorView(put_abi(result)));
    return result;
}

template <typename D> Windows::AI::MachineLearning::TensorUInt8Bit consume_Windows_AI_MachineLearning_ITensorUInt8BitStatics<D>::Create() const
{
    Windows::AI::MachineLearning::TensorUInt8Bit result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::AI::MachineLearning::ITensorUInt8BitStatics)->Create(put_abi(result)));
    return result;
}

template <typename D> Windows::AI::MachineLearning::TensorUInt8Bit consume_Windows_AI_MachineLearning_ITensorUInt8BitStatics<D>::Create(param::iterable<int64_t> const& shape) const
{
    Windows::AI::MachineLearning::TensorUInt8Bit result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::AI::MachineLearning::ITensorUInt8BitStatics)->Create2(get_abi(shape), put_abi(result)));
    return result;
}

template <typename D> Windows::AI::MachineLearning::TensorUInt8Bit consume_Windows_AI_MachineLearning_ITensorUInt8BitStatics<D>::CreateFromArray(param::iterable<int64_t> const& shape, array_view<uint8_t const> data) const
{
    Windows::AI::MachineLearning::TensorUInt8Bit result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::AI::MachineLearning::ITensorUInt8BitStatics)->CreateFromArray(get_abi(shape), data.size(), get_abi(data), put_abi(result)));
    return result;
}

template <typename D> Windows::AI::MachineLearning::TensorUInt8Bit consume_Windows_AI_MachineLearning_ITensorUInt8BitStatics<D>::CreateFromIterable(param::iterable<int64_t> const& shape, param::iterable<uint8_t> const& data) const
{
    Windows::AI::MachineLearning::TensorUInt8Bit result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::AI::MachineLearning::ITensorUInt8BitStatics)->CreateFromIterable(get_abi(shape), get_abi(data), put_abi(result)));
    return result;
}

template <typename D> Windows::AI::MachineLearning::TensorUInt8Bit consume_Windows_AI_MachineLearning_ITensorUInt8BitStatics2<D>::CreateFromShapeArrayAndDataArray(array_view<int64_t const> shape, array_view<uint8_t const> data) const
{
    Windows::AI::MachineLearning::TensorUInt8Bit result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::AI::MachineLearning::ITensorUInt8BitStatics2)->CreateFromShapeArrayAndDataArray(shape.size(), get_abi(shape), data.size(), get_abi(data), put_abi(result)));
    return result;
}

template <typename D> Windows::AI::MachineLearning::TensorUInt8Bit consume_Windows_AI_MachineLearning_ITensorUInt8BitStatics2<D>::CreateFromBuffer(array_view<int64_t const> shape, Windows::Storage::Streams::IBuffer const& buffer) const
{
    Windows::AI::MachineLearning::TensorUInt8Bit result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::AI::MachineLearning::ITensorUInt8BitStatics2)->CreateFromBuffer(shape.size(), get_abi(shape), get_abi(buffer), put_abi(result)));
    return result;
}

template <typename D>
struct produce<D, Windows::AI::MachineLearning::IImageFeatureDescriptor> : produce_base<D, Windows::AI::MachineLearning::IImageFeatureDescriptor>
{
    int32_t WINRT_CALL get_BitmapPixelFormat(Windows::Graphics::Imaging::BitmapPixelFormat* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(BitmapPixelFormat, WINRT_WRAP(Windows::Graphics::Imaging::BitmapPixelFormat));
            *value = detach_from<Windows::Graphics::Imaging::BitmapPixelFormat>(this->shim().BitmapPixelFormat());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_BitmapAlphaMode(Windows::Graphics::Imaging::BitmapAlphaMode* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(BitmapAlphaMode, WINRT_WRAP(Windows::Graphics::Imaging::BitmapAlphaMode));
            *value = detach_from<Windows::Graphics::Imaging::BitmapAlphaMode>(this->shim().BitmapAlphaMode());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Width(uint32_t* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Width, WINRT_WRAP(uint32_t));
            *value = detach_from<uint32_t>(this->shim().Width());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Height(uint32_t* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Height, WINRT_WRAP(uint32_t));
            *value = detach_from<uint32_t>(this->shim().Height());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::AI::MachineLearning::IImageFeatureValue> : produce_base<D, Windows::AI::MachineLearning::IImageFeatureValue>
{
    int32_t WINRT_CALL get_VideoFrame(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(VideoFrame, WINRT_WRAP(Windows::Media::VideoFrame));
            *value = detach_from<Windows::Media::VideoFrame>(this->shim().VideoFrame());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::AI::MachineLearning::IImageFeatureValueStatics> : produce_base<D, Windows::AI::MachineLearning::IImageFeatureValueStatics>
{
    int32_t WINRT_CALL CreateFromVideoFrame(void* image, void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CreateFromVideoFrame, WINRT_WRAP(Windows::AI::MachineLearning::ImageFeatureValue), Windows::Media::VideoFrame const&);
            *result = detach_from<Windows::AI::MachineLearning::ImageFeatureValue>(this->shim().CreateFromVideoFrame(*reinterpret_cast<Windows::Media::VideoFrame const*>(&image)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::AI::MachineLearning::ILearningModel> : produce_base<D, Windows::AI::MachineLearning::ILearningModel>
{
    int32_t WINRT_CALL get_Author(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Author, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().Author());
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

    int32_t WINRT_CALL get_Domain(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Domain, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().Domain());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Description(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Description, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().Description());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Version(int64_t* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Version, WINRT_WRAP(int64_t));
            *value = detach_from<int64_t>(this->shim().Version());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Metadata(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Metadata, WINRT_WRAP(Windows::Foundation::Collections::IMapView<hstring, hstring>));
            *value = detach_from<Windows::Foundation::Collections::IMapView<hstring, hstring>>(this->shim().Metadata());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_InputFeatures(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(InputFeatures, WINRT_WRAP(Windows::Foundation::Collections::IVectorView<Windows::AI::MachineLearning::ILearningModelFeatureDescriptor>));
            *value = detach_from<Windows::Foundation::Collections::IVectorView<Windows::AI::MachineLearning::ILearningModelFeatureDescriptor>>(this->shim().InputFeatures());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_OutputFeatures(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(OutputFeatures, WINRT_WRAP(Windows::Foundation::Collections::IVectorView<Windows::AI::MachineLearning::ILearningModelFeatureDescriptor>));
            *value = detach_from<Windows::Foundation::Collections::IVectorView<Windows::AI::MachineLearning::ILearningModelFeatureDescriptor>>(this->shim().OutputFeatures());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::AI::MachineLearning::ILearningModelBinding> : produce_base<D, Windows::AI::MachineLearning::ILearningModelBinding>
{
    int32_t WINRT_CALL Bind(void* name, void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Bind, WINRT_WRAP(void), hstring const&, Windows::Foundation::IInspectable const&);
            this->shim().Bind(*reinterpret_cast<hstring const*>(&name), *reinterpret_cast<Windows::Foundation::IInspectable const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL BindWithProperties(void* name, void* value, void* props) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Bind, WINRT_WRAP(void), hstring const&, Windows::Foundation::IInspectable const&, Windows::Foundation::Collections::IPropertySet const&);
            this->shim().Bind(*reinterpret_cast<hstring const*>(&name), *reinterpret_cast<Windows::Foundation::IInspectable const*>(&value), *reinterpret_cast<Windows::Foundation::Collections::IPropertySet const*>(&props));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL Clear() noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Clear, WINRT_WRAP(void));
            this->shim().Clear();
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::AI::MachineLearning::ILearningModelBindingFactory> : produce_base<D, Windows::AI::MachineLearning::ILearningModelBindingFactory>
{
    int32_t WINRT_CALL CreateFromSession(void* session, void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CreateFromSession, WINRT_WRAP(Windows::AI::MachineLearning::LearningModelBinding), Windows::AI::MachineLearning::LearningModelSession const&);
            *value = detach_from<Windows::AI::MachineLearning::LearningModelBinding>(this->shim().CreateFromSession(*reinterpret_cast<Windows::AI::MachineLearning::LearningModelSession const*>(&session)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::AI::MachineLearning::ILearningModelDevice> : produce_base<D, Windows::AI::MachineLearning::ILearningModelDevice>
{
    int32_t WINRT_CALL get_AdapterId(struct struct_Windows_Graphics_DisplayAdapterId* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(AdapterId, WINRT_WRAP(Windows::Graphics::DisplayAdapterId));
            *value = detach_from<Windows::Graphics::DisplayAdapterId>(this->shim().AdapterId());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Direct3D11Device(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Direct3D11Device, WINRT_WRAP(Windows::Graphics::DirectX::Direct3D11::IDirect3DDevice));
            *value = detach_from<Windows::Graphics::DirectX::Direct3D11::IDirect3DDevice>(this->shim().Direct3D11Device());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::AI::MachineLearning::ILearningModelDeviceFactory> : produce_base<D, Windows::AI::MachineLearning::ILearningModelDeviceFactory>
{
    int32_t WINRT_CALL Create(Windows::AI::MachineLearning::LearningModelDeviceKind deviceKind, void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Create, WINRT_WRAP(Windows::AI::MachineLearning::LearningModelDevice), Windows::AI::MachineLearning::LearningModelDeviceKind const&);
            *value = detach_from<Windows::AI::MachineLearning::LearningModelDevice>(this->shim().Create(*reinterpret_cast<Windows::AI::MachineLearning::LearningModelDeviceKind const*>(&deviceKind)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::AI::MachineLearning::ILearningModelDeviceStatics> : produce_base<D, Windows::AI::MachineLearning::ILearningModelDeviceStatics>
{
    int32_t WINRT_CALL CreateFromDirect3D11Device(void* device, void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CreateFromDirect3D11Device, WINRT_WRAP(Windows::AI::MachineLearning::LearningModelDevice), Windows::Graphics::DirectX::Direct3D11::IDirect3DDevice const&);
            *result = detach_from<Windows::AI::MachineLearning::LearningModelDevice>(this->shim().CreateFromDirect3D11Device(*reinterpret_cast<Windows::Graphics::DirectX::Direct3D11::IDirect3DDevice const*>(&device)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::AI::MachineLearning::ILearningModelEvaluationResult> : produce_base<D, Windows::AI::MachineLearning::ILearningModelEvaluationResult>
{
    int32_t WINRT_CALL get_CorrelationId(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CorrelationId, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().CorrelationId());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_ErrorStatus(int32_t* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ErrorStatus, WINRT_WRAP(int32_t));
            *value = detach_from<int32_t>(this->shim().ErrorStatus());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Succeeded(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Succeeded, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().Succeeded());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Outputs(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Outputs, WINRT_WRAP(Windows::Foundation::Collections::IMapView<hstring, Windows::Foundation::IInspectable>));
            *value = detach_from<Windows::Foundation::Collections::IMapView<hstring, Windows::Foundation::IInspectable>>(this->shim().Outputs());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::AI::MachineLearning::ILearningModelFeatureDescriptor> : produce_base<D, Windows::AI::MachineLearning::ILearningModelFeatureDescriptor>
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

    int32_t WINRT_CALL get_Description(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Description, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().Description());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Kind(Windows::AI::MachineLearning::LearningModelFeatureKind* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Kind, WINRT_WRAP(Windows::AI::MachineLearning::LearningModelFeatureKind));
            *value = detach_from<Windows::AI::MachineLearning::LearningModelFeatureKind>(this->shim().Kind());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_IsRequired(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IsRequired, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().IsRequired());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::AI::MachineLearning::ILearningModelFeatureValue> : produce_base<D, Windows::AI::MachineLearning::ILearningModelFeatureValue>
{
    int32_t WINRT_CALL get_Kind(Windows::AI::MachineLearning::LearningModelFeatureKind* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Kind, WINRT_WRAP(Windows::AI::MachineLearning::LearningModelFeatureKind));
            *value = detach_from<Windows::AI::MachineLearning::LearningModelFeatureKind>(this->shim().Kind());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::AI::MachineLearning::ILearningModelOperatorProvider> : produce_base<D, Windows::AI::MachineLearning::ILearningModelOperatorProvider>
{};

template <typename D>
struct produce<D, Windows::AI::MachineLearning::ILearningModelSession> : produce_base<D, Windows::AI::MachineLearning::ILearningModelSession>
{
    int32_t WINRT_CALL get_Model(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Model, WINRT_WRAP(Windows::AI::MachineLearning::LearningModel));
            *value = detach_from<Windows::AI::MachineLearning::LearningModel>(this->shim().Model());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Device(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Device, WINRT_WRAP(Windows::AI::MachineLearning::LearningModelDevice));
            *value = detach_from<Windows::AI::MachineLearning::LearningModelDevice>(this->shim().Device());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_EvaluationProperties(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(EvaluationProperties, WINRT_WRAP(Windows::Foundation::Collections::IPropertySet));
            *value = detach_from<Windows::Foundation::Collections::IPropertySet>(this->shim().EvaluationProperties());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL EvaluateAsync(void* bindings, void* correlationId, void** operation) noexcept final
    {
        try
        {
            *operation = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(EvaluateAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<Windows::AI::MachineLearning::LearningModelEvaluationResult>), Windows::AI::MachineLearning::LearningModelBinding const, hstring const);
            *operation = detach_from<Windows::Foundation::IAsyncOperation<Windows::AI::MachineLearning::LearningModelEvaluationResult>>(this->shim().EvaluateAsync(*reinterpret_cast<Windows::AI::MachineLearning::LearningModelBinding const*>(&bindings), *reinterpret_cast<hstring const*>(&correlationId)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL EvaluateFeaturesAsync(void* features, void* correlationId, void** operation) noexcept final
    {
        try
        {
            *operation = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(EvaluateFeaturesAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<Windows::AI::MachineLearning::LearningModelEvaluationResult>), Windows::Foundation::Collections::IMap<hstring, Windows::Foundation::IInspectable> const, hstring const);
            *operation = detach_from<Windows::Foundation::IAsyncOperation<Windows::AI::MachineLearning::LearningModelEvaluationResult>>(this->shim().EvaluateFeaturesAsync(*reinterpret_cast<Windows::Foundation::Collections::IMap<hstring, Windows::Foundation::IInspectable> const*>(&features), *reinterpret_cast<hstring const*>(&correlationId)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL Evaluate(void* bindings, void* correlationId, void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Evaluate, WINRT_WRAP(Windows::AI::MachineLearning::LearningModelEvaluationResult), Windows::AI::MachineLearning::LearningModelBinding const&, hstring const&);
            *result = detach_from<Windows::AI::MachineLearning::LearningModelEvaluationResult>(this->shim().Evaluate(*reinterpret_cast<Windows::AI::MachineLearning::LearningModelBinding const*>(&bindings), *reinterpret_cast<hstring const*>(&correlationId)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL EvaluateFeatures(void* features, void* correlationId, void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(EvaluateFeatures, WINRT_WRAP(Windows::AI::MachineLearning::LearningModelEvaluationResult), Windows::Foundation::Collections::IMap<hstring, Windows::Foundation::IInspectable> const&, hstring const&);
            *result = detach_from<Windows::AI::MachineLearning::LearningModelEvaluationResult>(this->shim().EvaluateFeatures(*reinterpret_cast<Windows::Foundation::Collections::IMap<hstring, Windows::Foundation::IInspectable> const*>(&features), *reinterpret_cast<hstring const*>(&correlationId)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::AI::MachineLearning::ILearningModelSessionFactory> : produce_base<D, Windows::AI::MachineLearning::ILearningModelSessionFactory>
{
    int32_t WINRT_CALL CreateFromModel(void* model, void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CreateFromModel, WINRT_WRAP(Windows::AI::MachineLearning::LearningModelSession), Windows::AI::MachineLearning::LearningModel const&);
            *value = detach_from<Windows::AI::MachineLearning::LearningModelSession>(this->shim().CreateFromModel(*reinterpret_cast<Windows::AI::MachineLearning::LearningModel const*>(&model)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL CreateFromModelOnDevice(void* model, void* deviceToRunOn, void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CreateFromModelOnDevice, WINRT_WRAP(Windows::AI::MachineLearning::LearningModelSession), Windows::AI::MachineLearning::LearningModel const&, Windows::AI::MachineLearning::LearningModelDevice const&);
            *value = detach_from<Windows::AI::MachineLearning::LearningModelSession>(this->shim().CreateFromModelOnDevice(*reinterpret_cast<Windows::AI::MachineLearning::LearningModel const*>(&model), *reinterpret_cast<Windows::AI::MachineLearning::LearningModelDevice const*>(&deviceToRunOn)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::AI::MachineLearning::ILearningModelSessionFactory2> : produce_base<D, Windows::AI::MachineLearning::ILearningModelSessionFactory2>
{
    int32_t WINRT_CALL CreateFromModelOnDeviceWithSessionOptions(void* model, void* deviceToRunOn, void* learningModelSessionOptions, void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CreateFromModelOnDeviceWithSessionOptions, WINRT_WRAP(Windows::AI::MachineLearning::LearningModelSession), Windows::AI::MachineLearning::LearningModel const&, Windows::AI::MachineLearning::LearningModelDevice const&, Windows::AI::MachineLearning::LearningModelSessionOptions const&);
            *value = detach_from<Windows::AI::MachineLearning::LearningModelSession>(this->shim().CreateFromModelOnDeviceWithSessionOptions(*reinterpret_cast<Windows::AI::MachineLearning::LearningModel const*>(&model), *reinterpret_cast<Windows::AI::MachineLearning::LearningModelDevice const*>(&deviceToRunOn), *reinterpret_cast<Windows::AI::MachineLearning::LearningModelSessionOptions const*>(&learningModelSessionOptions)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::AI::MachineLearning::ILearningModelSessionOptions> : produce_base<D, Windows::AI::MachineLearning::ILearningModelSessionOptions>
{
    int32_t WINRT_CALL get_BatchSizeOverride(uint32_t* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(BatchSizeOverride, WINRT_WRAP(uint32_t));
            *value = detach_from<uint32_t>(this->shim().BatchSizeOverride());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_BatchSizeOverride(uint32_t value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(BatchSizeOverride, WINRT_WRAP(void), uint32_t);
            this->shim().BatchSizeOverride(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::AI::MachineLearning::ILearningModelStatics> : produce_base<D, Windows::AI::MachineLearning::ILearningModelStatics>
{
    int32_t WINRT_CALL LoadFromStorageFileAsync(void* modelFile, void** operation) noexcept final
    {
        try
        {
            *operation = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(LoadFromStorageFileAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<Windows::AI::MachineLearning::LearningModel>), Windows::Storage::IStorageFile const);
            *operation = detach_from<Windows::Foundation::IAsyncOperation<Windows::AI::MachineLearning::LearningModel>>(this->shim().LoadFromStorageFileAsync(*reinterpret_cast<Windows::Storage::IStorageFile const*>(&modelFile)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL LoadFromStreamAsync(void* modelStream, void** operation) noexcept final
    {
        try
        {
            *operation = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(LoadFromStreamAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<Windows::AI::MachineLearning::LearningModel>), Windows::Storage::Streams::IRandomAccessStreamReference const);
            *operation = detach_from<Windows::Foundation::IAsyncOperation<Windows::AI::MachineLearning::LearningModel>>(this->shim().LoadFromStreamAsync(*reinterpret_cast<Windows::Storage::Streams::IRandomAccessStreamReference const*>(&modelStream)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL LoadFromFilePath(void* filePath, void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(LoadFromFilePath, WINRT_WRAP(Windows::AI::MachineLearning::LearningModel), hstring const&);
            *result = detach_from<Windows::AI::MachineLearning::LearningModel>(this->shim().LoadFromFilePath(*reinterpret_cast<hstring const*>(&filePath)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL LoadFromStream(void* modelStream, void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(LoadFromStream, WINRT_WRAP(Windows::AI::MachineLearning::LearningModel), Windows::Storage::Streams::IRandomAccessStreamReference const&);
            *result = detach_from<Windows::AI::MachineLearning::LearningModel>(this->shim().LoadFromStream(*reinterpret_cast<Windows::Storage::Streams::IRandomAccessStreamReference const*>(&modelStream)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL LoadFromStorageFileWithOperatorProviderAsync(void* modelFile, void* operatorProvider, void** operation) noexcept final
    {
        try
        {
            *operation = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(LoadFromStorageFileAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<Windows::AI::MachineLearning::LearningModel>), Windows::Storage::IStorageFile const, Windows::AI::MachineLearning::ILearningModelOperatorProvider const);
            *operation = detach_from<Windows::Foundation::IAsyncOperation<Windows::AI::MachineLearning::LearningModel>>(this->shim().LoadFromStorageFileAsync(*reinterpret_cast<Windows::Storage::IStorageFile const*>(&modelFile), *reinterpret_cast<Windows::AI::MachineLearning::ILearningModelOperatorProvider const*>(&operatorProvider)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL LoadFromStreamWithOperatorProviderAsync(void* modelStream, void* operatorProvider, void** operation) noexcept final
    {
        try
        {
            *operation = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(LoadFromStreamAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<Windows::AI::MachineLearning::LearningModel>), Windows::Storage::Streams::IRandomAccessStreamReference const, Windows::AI::MachineLearning::ILearningModelOperatorProvider const);
            *operation = detach_from<Windows::Foundation::IAsyncOperation<Windows::AI::MachineLearning::LearningModel>>(this->shim().LoadFromStreamAsync(*reinterpret_cast<Windows::Storage::Streams::IRandomAccessStreamReference const*>(&modelStream), *reinterpret_cast<Windows::AI::MachineLearning::ILearningModelOperatorProvider const*>(&operatorProvider)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL LoadFromFilePathWithOperatorProvider(void* filePath, void* operatorProvider, void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(LoadFromFilePath, WINRT_WRAP(Windows::AI::MachineLearning::LearningModel), hstring const&, Windows::AI::MachineLearning::ILearningModelOperatorProvider const&);
            *result = detach_from<Windows::AI::MachineLearning::LearningModel>(this->shim().LoadFromFilePath(*reinterpret_cast<hstring const*>(&filePath), *reinterpret_cast<Windows::AI::MachineLearning::ILearningModelOperatorProvider const*>(&operatorProvider)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL LoadFromStreamWithOperatorProvider(void* modelStream, void* operatorProvider, void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(LoadFromStream, WINRT_WRAP(Windows::AI::MachineLearning::LearningModel), Windows::Storage::Streams::IRandomAccessStreamReference const&, Windows::AI::MachineLearning::ILearningModelOperatorProvider const&);
            *result = detach_from<Windows::AI::MachineLearning::LearningModel>(this->shim().LoadFromStream(*reinterpret_cast<Windows::Storage::Streams::IRandomAccessStreamReference const*>(&modelStream), *reinterpret_cast<Windows::AI::MachineLearning::ILearningModelOperatorProvider const*>(&operatorProvider)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::AI::MachineLearning::IMapFeatureDescriptor> : produce_base<D, Windows::AI::MachineLearning::IMapFeatureDescriptor>
{
    int32_t WINRT_CALL get_KeyKind(Windows::AI::MachineLearning::TensorKind* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(KeyKind, WINRT_WRAP(Windows::AI::MachineLearning::TensorKind));
            *value = detach_from<Windows::AI::MachineLearning::TensorKind>(this->shim().KeyKind());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_ValueDescriptor(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ValueDescriptor, WINRT_WRAP(Windows::AI::MachineLearning::ILearningModelFeatureDescriptor));
            *value = detach_from<Windows::AI::MachineLearning::ILearningModelFeatureDescriptor>(this->shim().ValueDescriptor());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::AI::MachineLearning::ISequenceFeatureDescriptor> : produce_base<D, Windows::AI::MachineLearning::ISequenceFeatureDescriptor>
{
    int32_t WINRT_CALL get_ElementDescriptor(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ElementDescriptor, WINRT_WRAP(Windows::AI::MachineLearning::ILearningModelFeatureDescriptor));
            *value = detach_from<Windows::AI::MachineLearning::ILearningModelFeatureDescriptor>(this->shim().ElementDescriptor());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::AI::MachineLearning::ITensor> : produce_base<D, Windows::AI::MachineLearning::ITensor>
{
    int32_t WINRT_CALL get_TensorKind(Windows::AI::MachineLearning::TensorKind* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(TensorKind, WINRT_WRAP(Windows::AI::MachineLearning::TensorKind));
            *value = detach_from<Windows::AI::MachineLearning::TensorKind>(this->shim().TensorKind());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Shape(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Shape, WINRT_WRAP(Windows::Foundation::Collections::IVectorView<int64_t>));
            *value = detach_from<Windows::Foundation::Collections::IVectorView<int64_t>>(this->shim().Shape());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::AI::MachineLearning::ITensorBoolean> : produce_base<D, Windows::AI::MachineLearning::ITensorBoolean>
{
    int32_t WINRT_CALL GetAsVectorView(void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetAsVectorView, WINRT_WRAP(Windows::Foundation::Collections::IVectorView<bool>));
            *result = detach_from<Windows::Foundation::Collections::IVectorView<bool>>(this->shim().GetAsVectorView());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::AI::MachineLearning::ITensorBooleanStatics> : produce_base<D, Windows::AI::MachineLearning::ITensorBooleanStatics>
{
    int32_t WINRT_CALL Create(void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Create, WINRT_WRAP(Windows::AI::MachineLearning::TensorBoolean));
            *result = detach_from<Windows::AI::MachineLearning::TensorBoolean>(this->shim().Create());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL Create2(void* shape, void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Create, WINRT_WRAP(Windows::AI::MachineLearning::TensorBoolean), Windows::Foundation::Collections::IIterable<int64_t> const&);
            *result = detach_from<Windows::AI::MachineLearning::TensorBoolean>(this->shim().Create(*reinterpret_cast<Windows::Foundation::Collections::IIterable<int64_t> const*>(&shape)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL CreateFromArray(void* shape, uint32_t __dataSize, bool* data, void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CreateFromArray, WINRT_WRAP(Windows::AI::MachineLearning::TensorBoolean), Windows::Foundation::Collections::IIterable<int64_t> const&, array_view<bool const>);
            *result = detach_from<Windows::AI::MachineLearning::TensorBoolean>(this->shim().CreateFromArray(*reinterpret_cast<Windows::Foundation::Collections::IIterable<int64_t> const*>(&shape), array_view<bool const>(reinterpret_cast<bool const *>(data), reinterpret_cast<bool const *>(data) + __dataSize)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL CreateFromIterable(void* shape, void* data, void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CreateFromIterable, WINRT_WRAP(Windows::AI::MachineLearning::TensorBoolean), Windows::Foundation::Collections::IIterable<int64_t> const&, Windows::Foundation::Collections::IIterable<bool> const&);
            *result = detach_from<Windows::AI::MachineLearning::TensorBoolean>(this->shim().CreateFromIterable(*reinterpret_cast<Windows::Foundation::Collections::IIterable<int64_t> const*>(&shape), *reinterpret_cast<Windows::Foundation::Collections::IIterable<bool> const*>(&data)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::AI::MachineLearning::ITensorBooleanStatics2> : produce_base<D, Windows::AI::MachineLearning::ITensorBooleanStatics2>
{
    int32_t WINRT_CALL CreateFromShapeArrayAndDataArray(uint32_t __shapeSize, int64_t* shape, uint32_t __dataSize, bool* data, void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CreateFromShapeArrayAndDataArray, WINRT_WRAP(Windows::AI::MachineLearning::TensorBoolean), array_view<int64_t const>, array_view<bool const>);
            *result = detach_from<Windows::AI::MachineLearning::TensorBoolean>(this->shim().CreateFromShapeArrayAndDataArray(array_view<int64_t const>(reinterpret_cast<int64_t const *>(shape), reinterpret_cast<int64_t const *>(shape) + __shapeSize), array_view<bool const>(reinterpret_cast<bool const *>(data), reinterpret_cast<bool const *>(data) + __dataSize)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL CreateFromBuffer(uint32_t __shapeSize, int64_t* shape, void* buffer, void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CreateFromBuffer, WINRT_WRAP(Windows::AI::MachineLearning::TensorBoolean), array_view<int64_t const>, Windows::Storage::Streams::IBuffer const&);
            *result = detach_from<Windows::AI::MachineLearning::TensorBoolean>(this->shim().CreateFromBuffer(array_view<int64_t const>(reinterpret_cast<int64_t const *>(shape), reinterpret_cast<int64_t const *>(shape) + __shapeSize), *reinterpret_cast<Windows::Storage::Streams::IBuffer const*>(&buffer)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::AI::MachineLearning::ITensorDouble> : produce_base<D, Windows::AI::MachineLearning::ITensorDouble>
{
    int32_t WINRT_CALL GetAsVectorView(void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetAsVectorView, WINRT_WRAP(Windows::Foundation::Collections::IVectorView<double>));
            *result = detach_from<Windows::Foundation::Collections::IVectorView<double>>(this->shim().GetAsVectorView());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::AI::MachineLearning::ITensorDoubleStatics> : produce_base<D, Windows::AI::MachineLearning::ITensorDoubleStatics>
{
    int32_t WINRT_CALL Create(void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Create, WINRT_WRAP(Windows::AI::MachineLearning::TensorDouble));
            *result = detach_from<Windows::AI::MachineLearning::TensorDouble>(this->shim().Create());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL Create2(void* shape, void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Create, WINRT_WRAP(Windows::AI::MachineLearning::TensorDouble), Windows::Foundation::Collections::IIterable<int64_t> const&);
            *result = detach_from<Windows::AI::MachineLearning::TensorDouble>(this->shim().Create(*reinterpret_cast<Windows::Foundation::Collections::IIterable<int64_t> const*>(&shape)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL CreateFromArray(void* shape, uint32_t __dataSize, double* data, void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CreateFromArray, WINRT_WRAP(Windows::AI::MachineLearning::TensorDouble), Windows::Foundation::Collections::IIterable<int64_t> const&, array_view<double const>);
            *result = detach_from<Windows::AI::MachineLearning::TensorDouble>(this->shim().CreateFromArray(*reinterpret_cast<Windows::Foundation::Collections::IIterable<int64_t> const*>(&shape), array_view<double const>(reinterpret_cast<double const *>(data), reinterpret_cast<double const *>(data) + __dataSize)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL CreateFromIterable(void* shape, void* data, void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CreateFromIterable, WINRT_WRAP(Windows::AI::MachineLearning::TensorDouble), Windows::Foundation::Collections::IIterable<int64_t> const&, Windows::Foundation::Collections::IIterable<double> const&);
            *result = detach_from<Windows::AI::MachineLearning::TensorDouble>(this->shim().CreateFromIterable(*reinterpret_cast<Windows::Foundation::Collections::IIterable<int64_t> const*>(&shape), *reinterpret_cast<Windows::Foundation::Collections::IIterable<double> const*>(&data)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::AI::MachineLearning::ITensorDoubleStatics2> : produce_base<D, Windows::AI::MachineLearning::ITensorDoubleStatics2>
{
    int32_t WINRT_CALL CreateFromShapeArrayAndDataArray(uint32_t __shapeSize, int64_t* shape, uint32_t __dataSize, double* data, void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CreateFromShapeArrayAndDataArray, WINRT_WRAP(Windows::AI::MachineLearning::TensorDouble), array_view<int64_t const>, array_view<double const>);
            *result = detach_from<Windows::AI::MachineLearning::TensorDouble>(this->shim().CreateFromShapeArrayAndDataArray(array_view<int64_t const>(reinterpret_cast<int64_t const *>(shape), reinterpret_cast<int64_t const *>(shape) + __shapeSize), array_view<double const>(reinterpret_cast<double const *>(data), reinterpret_cast<double const *>(data) + __dataSize)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL CreateFromBuffer(uint32_t __shapeSize, int64_t* shape, void* buffer, void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CreateFromBuffer, WINRT_WRAP(Windows::AI::MachineLearning::TensorDouble), array_view<int64_t const>, Windows::Storage::Streams::IBuffer const&);
            *result = detach_from<Windows::AI::MachineLearning::TensorDouble>(this->shim().CreateFromBuffer(array_view<int64_t const>(reinterpret_cast<int64_t const *>(shape), reinterpret_cast<int64_t const *>(shape) + __shapeSize), *reinterpret_cast<Windows::Storage::Streams::IBuffer const*>(&buffer)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::AI::MachineLearning::ITensorFeatureDescriptor> : produce_base<D, Windows::AI::MachineLearning::ITensorFeatureDescriptor>
{
    int32_t WINRT_CALL get_TensorKind(Windows::AI::MachineLearning::TensorKind* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(TensorKind, WINRT_WRAP(Windows::AI::MachineLearning::TensorKind));
            *value = detach_from<Windows::AI::MachineLearning::TensorKind>(this->shim().TensorKind());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Shape(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Shape, WINRT_WRAP(Windows::Foundation::Collections::IVectorView<int64_t>));
            *value = detach_from<Windows::Foundation::Collections::IVectorView<int64_t>>(this->shim().Shape());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::AI::MachineLearning::ITensorFloat> : produce_base<D, Windows::AI::MachineLearning::ITensorFloat>
{
    int32_t WINRT_CALL GetAsVectorView(void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetAsVectorView, WINRT_WRAP(Windows::Foundation::Collections::IVectorView<float>));
            *result = detach_from<Windows::Foundation::Collections::IVectorView<float>>(this->shim().GetAsVectorView());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::AI::MachineLearning::ITensorFloat16Bit> : produce_base<D, Windows::AI::MachineLearning::ITensorFloat16Bit>
{
    int32_t WINRT_CALL GetAsVectorView(void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetAsVectorView, WINRT_WRAP(Windows::Foundation::Collections::IVectorView<float>));
            *result = detach_from<Windows::Foundation::Collections::IVectorView<float>>(this->shim().GetAsVectorView());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::AI::MachineLearning::ITensorFloat16BitStatics> : produce_base<D, Windows::AI::MachineLearning::ITensorFloat16BitStatics>
{
    int32_t WINRT_CALL Create(void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Create, WINRT_WRAP(Windows::AI::MachineLearning::TensorFloat16Bit));
            *result = detach_from<Windows::AI::MachineLearning::TensorFloat16Bit>(this->shim().Create());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL Create2(void* shape, void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Create, WINRT_WRAP(Windows::AI::MachineLearning::TensorFloat16Bit), Windows::Foundation::Collections::IIterable<int64_t> const&);
            *result = detach_from<Windows::AI::MachineLearning::TensorFloat16Bit>(this->shim().Create(*reinterpret_cast<Windows::Foundation::Collections::IIterable<int64_t> const*>(&shape)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL CreateFromArray(void* shape, uint32_t __dataSize, float* data, void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CreateFromArray, WINRT_WRAP(Windows::AI::MachineLearning::TensorFloat16Bit), Windows::Foundation::Collections::IIterable<int64_t> const&, array_view<float const>);
            *result = detach_from<Windows::AI::MachineLearning::TensorFloat16Bit>(this->shim().CreateFromArray(*reinterpret_cast<Windows::Foundation::Collections::IIterable<int64_t> const*>(&shape), array_view<float const>(reinterpret_cast<float const *>(data), reinterpret_cast<float const *>(data) + __dataSize)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL CreateFromIterable(void* shape, void* data, void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CreateFromIterable, WINRT_WRAP(Windows::AI::MachineLearning::TensorFloat16Bit), Windows::Foundation::Collections::IIterable<int64_t> const&, Windows::Foundation::Collections::IIterable<float> const&);
            *result = detach_from<Windows::AI::MachineLearning::TensorFloat16Bit>(this->shim().CreateFromIterable(*reinterpret_cast<Windows::Foundation::Collections::IIterable<int64_t> const*>(&shape), *reinterpret_cast<Windows::Foundation::Collections::IIterable<float> const*>(&data)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::AI::MachineLearning::ITensorFloat16BitStatics2> : produce_base<D, Windows::AI::MachineLearning::ITensorFloat16BitStatics2>
{
    int32_t WINRT_CALL CreateFromShapeArrayAndDataArray(uint32_t __shapeSize, int64_t* shape, uint32_t __dataSize, float* data, void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CreateFromShapeArrayAndDataArray, WINRT_WRAP(Windows::AI::MachineLearning::TensorFloat16Bit), array_view<int64_t const>, array_view<float const>);
            *result = detach_from<Windows::AI::MachineLearning::TensorFloat16Bit>(this->shim().CreateFromShapeArrayAndDataArray(array_view<int64_t const>(reinterpret_cast<int64_t const *>(shape), reinterpret_cast<int64_t const *>(shape) + __shapeSize), array_view<float const>(reinterpret_cast<float const *>(data), reinterpret_cast<float const *>(data) + __dataSize)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL CreateFromBuffer(uint32_t __shapeSize, int64_t* shape, void* buffer, void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CreateFromBuffer, WINRT_WRAP(Windows::AI::MachineLearning::TensorFloat16Bit), array_view<int64_t const>, Windows::Storage::Streams::IBuffer const&);
            *result = detach_from<Windows::AI::MachineLearning::TensorFloat16Bit>(this->shim().CreateFromBuffer(array_view<int64_t const>(reinterpret_cast<int64_t const *>(shape), reinterpret_cast<int64_t const *>(shape) + __shapeSize), *reinterpret_cast<Windows::Storage::Streams::IBuffer const*>(&buffer)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::AI::MachineLearning::ITensorFloatStatics> : produce_base<D, Windows::AI::MachineLearning::ITensorFloatStatics>
{
    int32_t WINRT_CALL Create(void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Create, WINRT_WRAP(Windows::AI::MachineLearning::TensorFloat));
            *result = detach_from<Windows::AI::MachineLearning::TensorFloat>(this->shim().Create());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL Create2(void* shape, void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Create, WINRT_WRAP(Windows::AI::MachineLearning::TensorFloat), Windows::Foundation::Collections::IIterable<int64_t> const&);
            *result = detach_from<Windows::AI::MachineLearning::TensorFloat>(this->shim().Create(*reinterpret_cast<Windows::Foundation::Collections::IIterable<int64_t> const*>(&shape)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL CreateFromArray(void* shape, uint32_t __dataSize, float* data, void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CreateFromArray, WINRT_WRAP(Windows::AI::MachineLearning::TensorFloat), Windows::Foundation::Collections::IIterable<int64_t> const&, array_view<float const>);
            *result = detach_from<Windows::AI::MachineLearning::TensorFloat>(this->shim().CreateFromArray(*reinterpret_cast<Windows::Foundation::Collections::IIterable<int64_t> const*>(&shape), array_view<float const>(reinterpret_cast<float const *>(data), reinterpret_cast<float const *>(data) + __dataSize)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL CreateFromIterable(void* shape, void* data, void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CreateFromIterable, WINRT_WRAP(Windows::AI::MachineLearning::TensorFloat), Windows::Foundation::Collections::IIterable<int64_t> const&, Windows::Foundation::Collections::IIterable<float> const&);
            *result = detach_from<Windows::AI::MachineLearning::TensorFloat>(this->shim().CreateFromIterable(*reinterpret_cast<Windows::Foundation::Collections::IIterable<int64_t> const*>(&shape), *reinterpret_cast<Windows::Foundation::Collections::IIterable<float> const*>(&data)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::AI::MachineLearning::ITensorFloatStatics2> : produce_base<D, Windows::AI::MachineLearning::ITensorFloatStatics2>
{
    int32_t WINRT_CALL CreateFromShapeArrayAndDataArray(uint32_t __shapeSize, int64_t* shape, uint32_t __dataSize, float* data, void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CreateFromShapeArrayAndDataArray, WINRT_WRAP(Windows::AI::MachineLearning::TensorFloat), array_view<int64_t const>, array_view<float const>);
            *result = detach_from<Windows::AI::MachineLearning::TensorFloat>(this->shim().CreateFromShapeArrayAndDataArray(array_view<int64_t const>(reinterpret_cast<int64_t const *>(shape), reinterpret_cast<int64_t const *>(shape) + __shapeSize), array_view<float const>(reinterpret_cast<float const *>(data), reinterpret_cast<float const *>(data) + __dataSize)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL CreateFromBuffer(uint32_t __shapeSize, int64_t* shape, void* buffer, void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CreateFromBuffer, WINRT_WRAP(Windows::AI::MachineLearning::TensorFloat), array_view<int64_t const>, Windows::Storage::Streams::IBuffer const&);
            *result = detach_from<Windows::AI::MachineLearning::TensorFloat>(this->shim().CreateFromBuffer(array_view<int64_t const>(reinterpret_cast<int64_t const *>(shape), reinterpret_cast<int64_t const *>(shape) + __shapeSize), *reinterpret_cast<Windows::Storage::Streams::IBuffer const*>(&buffer)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::AI::MachineLearning::ITensorInt16Bit> : produce_base<D, Windows::AI::MachineLearning::ITensorInt16Bit>
{
    int32_t WINRT_CALL GetAsVectorView(void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetAsVectorView, WINRT_WRAP(Windows::Foundation::Collections::IVectorView<int16_t>));
            *result = detach_from<Windows::Foundation::Collections::IVectorView<int16_t>>(this->shim().GetAsVectorView());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::AI::MachineLearning::ITensorInt16BitStatics> : produce_base<D, Windows::AI::MachineLearning::ITensorInt16BitStatics>
{
    int32_t WINRT_CALL Create(void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Create, WINRT_WRAP(Windows::AI::MachineLearning::TensorInt16Bit));
            *result = detach_from<Windows::AI::MachineLearning::TensorInt16Bit>(this->shim().Create());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL Create2(void* shape, void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Create, WINRT_WRAP(Windows::AI::MachineLearning::TensorInt16Bit), Windows::Foundation::Collections::IIterable<int64_t> const&);
            *result = detach_from<Windows::AI::MachineLearning::TensorInt16Bit>(this->shim().Create(*reinterpret_cast<Windows::Foundation::Collections::IIterable<int64_t> const*>(&shape)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL CreateFromArray(void* shape, uint32_t __dataSize, int16_t* data, void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CreateFromArray, WINRT_WRAP(Windows::AI::MachineLearning::TensorInt16Bit), Windows::Foundation::Collections::IIterable<int64_t> const&, array_view<int16_t const>);
            *result = detach_from<Windows::AI::MachineLearning::TensorInt16Bit>(this->shim().CreateFromArray(*reinterpret_cast<Windows::Foundation::Collections::IIterable<int64_t> const*>(&shape), array_view<int16_t const>(reinterpret_cast<int16_t const *>(data), reinterpret_cast<int16_t const *>(data) + __dataSize)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL CreateFromIterable(void* shape, void* data, void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CreateFromIterable, WINRT_WRAP(Windows::AI::MachineLearning::TensorInt16Bit), Windows::Foundation::Collections::IIterable<int64_t> const&, Windows::Foundation::Collections::IIterable<int16_t> const&);
            *result = detach_from<Windows::AI::MachineLearning::TensorInt16Bit>(this->shim().CreateFromIterable(*reinterpret_cast<Windows::Foundation::Collections::IIterable<int64_t> const*>(&shape), *reinterpret_cast<Windows::Foundation::Collections::IIterable<int16_t> const*>(&data)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::AI::MachineLearning::ITensorInt16BitStatics2> : produce_base<D, Windows::AI::MachineLearning::ITensorInt16BitStatics2>
{
    int32_t WINRT_CALL CreateFromShapeArrayAndDataArray(uint32_t __shapeSize, int64_t* shape, uint32_t __dataSize, int16_t* data, void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CreateFromShapeArrayAndDataArray, WINRT_WRAP(Windows::AI::MachineLearning::TensorInt16Bit), array_view<int64_t const>, array_view<int16_t const>);
            *result = detach_from<Windows::AI::MachineLearning::TensorInt16Bit>(this->shim().CreateFromShapeArrayAndDataArray(array_view<int64_t const>(reinterpret_cast<int64_t const *>(shape), reinterpret_cast<int64_t const *>(shape) + __shapeSize), array_view<int16_t const>(reinterpret_cast<int16_t const *>(data), reinterpret_cast<int16_t const *>(data) + __dataSize)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL CreateFromBuffer(uint32_t __shapeSize, int64_t* shape, void* buffer, void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CreateFromBuffer, WINRT_WRAP(Windows::AI::MachineLearning::TensorInt16Bit), array_view<int64_t const>, Windows::Storage::Streams::IBuffer const&);
            *result = detach_from<Windows::AI::MachineLearning::TensorInt16Bit>(this->shim().CreateFromBuffer(array_view<int64_t const>(reinterpret_cast<int64_t const *>(shape), reinterpret_cast<int64_t const *>(shape) + __shapeSize), *reinterpret_cast<Windows::Storage::Streams::IBuffer const*>(&buffer)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::AI::MachineLearning::ITensorInt32Bit> : produce_base<D, Windows::AI::MachineLearning::ITensorInt32Bit>
{
    int32_t WINRT_CALL GetAsVectorView(void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetAsVectorView, WINRT_WRAP(Windows::Foundation::Collections::IVectorView<int32_t>));
            *result = detach_from<Windows::Foundation::Collections::IVectorView<int32_t>>(this->shim().GetAsVectorView());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::AI::MachineLearning::ITensorInt32BitStatics> : produce_base<D, Windows::AI::MachineLearning::ITensorInt32BitStatics>
{
    int32_t WINRT_CALL Create(void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Create, WINRT_WRAP(Windows::AI::MachineLearning::TensorInt32Bit));
            *result = detach_from<Windows::AI::MachineLearning::TensorInt32Bit>(this->shim().Create());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL Create2(void* shape, void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Create, WINRT_WRAP(Windows::AI::MachineLearning::TensorInt32Bit), Windows::Foundation::Collections::IIterable<int64_t> const&);
            *result = detach_from<Windows::AI::MachineLearning::TensorInt32Bit>(this->shim().Create(*reinterpret_cast<Windows::Foundation::Collections::IIterable<int64_t> const*>(&shape)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL CreateFromArray(void* shape, uint32_t __dataSize, int32_t* data, void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CreateFromArray, WINRT_WRAP(Windows::AI::MachineLearning::TensorInt32Bit), Windows::Foundation::Collections::IIterable<int64_t> const&, array_view<int32_t const>);
            *result = detach_from<Windows::AI::MachineLearning::TensorInt32Bit>(this->shim().CreateFromArray(*reinterpret_cast<Windows::Foundation::Collections::IIterable<int64_t> const*>(&shape), array_view<int32_t const>(reinterpret_cast<int32_t const *>(data), reinterpret_cast<int32_t const *>(data) + __dataSize)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL CreateFromIterable(void* shape, void* data, void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CreateFromIterable, WINRT_WRAP(Windows::AI::MachineLearning::TensorInt32Bit), Windows::Foundation::Collections::IIterable<int64_t> const&, Windows::Foundation::Collections::IIterable<int32_t> const&);
            *result = detach_from<Windows::AI::MachineLearning::TensorInt32Bit>(this->shim().CreateFromIterable(*reinterpret_cast<Windows::Foundation::Collections::IIterable<int64_t> const*>(&shape), *reinterpret_cast<Windows::Foundation::Collections::IIterable<int32_t> const*>(&data)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::AI::MachineLearning::ITensorInt32BitStatics2> : produce_base<D, Windows::AI::MachineLearning::ITensorInt32BitStatics2>
{
    int32_t WINRT_CALL CreateFromShapeArrayAndDataArray(uint32_t __shapeSize, int64_t* shape, uint32_t __dataSize, int32_t* data, void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CreateFromShapeArrayAndDataArray, WINRT_WRAP(Windows::AI::MachineLearning::TensorInt32Bit), array_view<int64_t const>, array_view<int32_t const>);
            *result = detach_from<Windows::AI::MachineLearning::TensorInt32Bit>(this->shim().CreateFromShapeArrayAndDataArray(array_view<int64_t const>(reinterpret_cast<int64_t const *>(shape), reinterpret_cast<int64_t const *>(shape) + __shapeSize), array_view<int32_t const>(reinterpret_cast<int32_t const *>(data), reinterpret_cast<int32_t const *>(data) + __dataSize)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL CreateFromBuffer(uint32_t __shapeSize, int64_t* shape, void* buffer, void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CreateFromBuffer, WINRT_WRAP(Windows::AI::MachineLearning::TensorInt32Bit), array_view<int64_t const>, Windows::Storage::Streams::IBuffer const&);
            *result = detach_from<Windows::AI::MachineLearning::TensorInt32Bit>(this->shim().CreateFromBuffer(array_view<int64_t const>(reinterpret_cast<int64_t const *>(shape), reinterpret_cast<int64_t const *>(shape) + __shapeSize), *reinterpret_cast<Windows::Storage::Streams::IBuffer const*>(&buffer)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::AI::MachineLearning::ITensorInt64Bit> : produce_base<D, Windows::AI::MachineLearning::ITensorInt64Bit>
{
    int32_t WINRT_CALL GetAsVectorView(void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetAsVectorView, WINRT_WRAP(Windows::Foundation::Collections::IVectorView<int64_t>));
            *result = detach_from<Windows::Foundation::Collections::IVectorView<int64_t>>(this->shim().GetAsVectorView());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::AI::MachineLearning::ITensorInt64BitStatics> : produce_base<D, Windows::AI::MachineLearning::ITensorInt64BitStatics>
{
    int32_t WINRT_CALL Create(void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Create, WINRT_WRAP(Windows::AI::MachineLearning::TensorInt64Bit));
            *result = detach_from<Windows::AI::MachineLearning::TensorInt64Bit>(this->shim().Create());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL Create2(void* shape, void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Create, WINRT_WRAP(Windows::AI::MachineLearning::TensorInt64Bit), Windows::Foundation::Collections::IIterable<int64_t> const&);
            *result = detach_from<Windows::AI::MachineLearning::TensorInt64Bit>(this->shim().Create(*reinterpret_cast<Windows::Foundation::Collections::IIterable<int64_t> const*>(&shape)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL CreateFromArray(void* shape, uint32_t __dataSize, int64_t* data, void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CreateFromArray, WINRT_WRAP(Windows::AI::MachineLearning::TensorInt64Bit), Windows::Foundation::Collections::IIterable<int64_t> const&, array_view<int64_t const>);
            *result = detach_from<Windows::AI::MachineLearning::TensorInt64Bit>(this->shim().CreateFromArray(*reinterpret_cast<Windows::Foundation::Collections::IIterable<int64_t> const*>(&shape), array_view<int64_t const>(reinterpret_cast<int64_t const *>(data), reinterpret_cast<int64_t const *>(data) + __dataSize)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL CreateFromIterable(void* shape, void* data, void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CreateFromIterable, WINRT_WRAP(Windows::AI::MachineLearning::TensorInt64Bit), Windows::Foundation::Collections::IIterable<int64_t> const&, Windows::Foundation::Collections::IIterable<int64_t> const&);
            *result = detach_from<Windows::AI::MachineLearning::TensorInt64Bit>(this->shim().CreateFromIterable(*reinterpret_cast<Windows::Foundation::Collections::IIterable<int64_t> const*>(&shape), *reinterpret_cast<Windows::Foundation::Collections::IIterable<int64_t> const*>(&data)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::AI::MachineLearning::ITensorInt64BitStatics2> : produce_base<D, Windows::AI::MachineLearning::ITensorInt64BitStatics2>
{
    int32_t WINRT_CALL CreateFromShapeArrayAndDataArray(uint32_t __shapeSize, int64_t* shape, uint32_t __dataSize, int64_t* data, void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CreateFromShapeArrayAndDataArray, WINRT_WRAP(Windows::AI::MachineLearning::TensorInt64Bit), array_view<int64_t const>, array_view<int64_t const>);
            *result = detach_from<Windows::AI::MachineLearning::TensorInt64Bit>(this->shim().CreateFromShapeArrayAndDataArray(array_view<int64_t const>(reinterpret_cast<int64_t const *>(shape), reinterpret_cast<int64_t const *>(shape) + __shapeSize), array_view<int64_t const>(reinterpret_cast<int64_t const *>(data), reinterpret_cast<int64_t const *>(data) + __dataSize)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL CreateFromBuffer(uint32_t __shapeSize, int64_t* shape, void* buffer, void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CreateFromBuffer, WINRT_WRAP(Windows::AI::MachineLearning::TensorInt64Bit), array_view<int64_t const>, Windows::Storage::Streams::IBuffer const&);
            *result = detach_from<Windows::AI::MachineLearning::TensorInt64Bit>(this->shim().CreateFromBuffer(array_view<int64_t const>(reinterpret_cast<int64_t const *>(shape), reinterpret_cast<int64_t const *>(shape) + __shapeSize), *reinterpret_cast<Windows::Storage::Streams::IBuffer const*>(&buffer)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::AI::MachineLearning::ITensorInt8Bit> : produce_base<D, Windows::AI::MachineLearning::ITensorInt8Bit>
{
    int32_t WINRT_CALL GetAsVectorView(void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetAsVectorView, WINRT_WRAP(Windows::Foundation::Collections::IVectorView<uint8_t>));
            *result = detach_from<Windows::Foundation::Collections::IVectorView<uint8_t>>(this->shim().GetAsVectorView());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::AI::MachineLearning::ITensorInt8BitStatics> : produce_base<D, Windows::AI::MachineLearning::ITensorInt8BitStatics>
{
    int32_t WINRT_CALL Create(void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Create, WINRT_WRAP(Windows::AI::MachineLearning::TensorInt8Bit));
            *result = detach_from<Windows::AI::MachineLearning::TensorInt8Bit>(this->shim().Create());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL Create2(void* shape, void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Create, WINRT_WRAP(Windows::AI::MachineLearning::TensorInt8Bit), Windows::Foundation::Collections::IIterable<int64_t> const&);
            *result = detach_from<Windows::AI::MachineLearning::TensorInt8Bit>(this->shim().Create(*reinterpret_cast<Windows::Foundation::Collections::IIterable<int64_t> const*>(&shape)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL CreateFromArray(void* shape, uint32_t __dataSize, uint8_t* data, void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CreateFromArray, WINRT_WRAP(Windows::AI::MachineLearning::TensorInt8Bit), Windows::Foundation::Collections::IIterable<int64_t> const&, array_view<uint8_t const>);
            *result = detach_from<Windows::AI::MachineLearning::TensorInt8Bit>(this->shim().CreateFromArray(*reinterpret_cast<Windows::Foundation::Collections::IIterable<int64_t> const*>(&shape), array_view<uint8_t const>(reinterpret_cast<uint8_t const *>(data), reinterpret_cast<uint8_t const *>(data) + __dataSize)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL CreateFromIterable(void* shape, void* data, void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CreateFromIterable, WINRT_WRAP(Windows::AI::MachineLearning::TensorInt8Bit), Windows::Foundation::Collections::IIterable<int64_t> const&, Windows::Foundation::Collections::IIterable<uint8_t> const&);
            *result = detach_from<Windows::AI::MachineLearning::TensorInt8Bit>(this->shim().CreateFromIterable(*reinterpret_cast<Windows::Foundation::Collections::IIterable<int64_t> const*>(&shape), *reinterpret_cast<Windows::Foundation::Collections::IIterable<uint8_t> const*>(&data)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::AI::MachineLearning::ITensorInt8BitStatics2> : produce_base<D, Windows::AI::MachineLearning::ITensorInt8BitStatics2>
{
    int32_t WINRT_CALL CreateFromShapeArrayAndDataArray(uint32_t __shapeSize, int64_t* shape, uint32_t __dataSize, uint8_t* data, void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CreateFromShapeArrayAndDataArray, WINRT_WRAP(Windows::AI::MachineLearning::TensorInt8Bit), array_view<int64_t const>, array_view<uint8_t const>);
            *result = detach_from<Windows::AI::MachineLearning::TensorInt8Bit>(this->shim().CreateFromShapeArrayAndDataArray(array_view<int64_t const>(reinterpret_cast<int64_t const *>(shape), reinterpret_cast<int64_t const *>(shape) + __shapeSize), array_view<uint8_t const>(reinterpret_cast<uint8_t const *>(data), reinterpret_cast<uint8_t const *>(data) + __dataSize)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL CreateFromBuffer(uint32_t __shapeSize, int64_t* shape, void* buffer, void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CreateFromBuffer, WINRT_WRAP(Windows::AI::MachineLearning::TensorInt8Bit), array_view<int64_t const>, Windows::Storage::Streams::IBuffer const&);
            *result = detach_from<Windows::AI::MachineLearning::TensorInt8Bit>(this->shim().CreateFromBuffer(array_view<int64_t const>(reinterpret_cast<int64_t const *>(shape), reinterpret_cast<int64_t const *>(shape) + __shapeSize), *reinterpret_cast<Windows::Storage::Streams::IBuffer const*>(&buffer)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::AI::MachineLearning::ITensorString> : produce_base<D, Windows::AI::MachineLearning::ITensorString>
{
    int32_t WINRT_CALL GetAsVectorView(void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetAsVectorView, WINRT_WRAP(Windows::Foundation::Collections::IVectorView<hstring>));
            *result = detach_from<Windows::Foundation::Collections::IVectorView<hstring>>(this->shim().GetAsVectorView());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::AI::MachineLearning::ITensorStringStatics> : produce_base<D, Windows::AI::MachineLearning::ITensorStringStatics>
{
    int32_t WINRT_CALL Create(void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Create, WINRT_WRAP(Windows::AI::MachineLearning::TensorString));
            *result = detach_from<Windows::AI::MachineLearning::TensorString>(this->shim().Create());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL Create2(void* shape, void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Create, WINRT_WRAP(Windows::AI::MachineLearning::TensorString), Windows::Foundation::Collections::IIterable<int64_t> const&);
            *result = detach_from<Windows::AI::MachineLearning::TensorString>(this->shim().Create(*reinterpret_cast<Windows::Foundation::Collections::IIterable<int64_t> const*>(&shape)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL CreateFromArray(void* shape, uint32_t __dataSize, void** data, void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CreateFromArray, WINRT_WRAP(Windows::AI::MachineLearning::TensorString), Windows::Foundation::Collections::IIterable<int64_t> const&, array_view<hstring const>);
            *result = detach_from<Windows::AI::MachineLearning::TensorString>(this->shim().CreateFromArray(*reinterpret_cast<Windows::Foundation::Collections::IIterable<int64_t> const*>(&shape), array_view<hstring const>(reinterpret_cast<hstring const *>(data), reinterpret_cast<hstring const *>(data) + __dataSize)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL CreateFromIterable(void* shape, void* data, void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CreateFromIterable, WINRT_WRAP(Windows::AI::MachineLearning::TensorString), Windows::Foundation::Collections::IIterable<int64_t> const&, Windows::Foundation::Collections::IIterable<hstring> const&);
            *result = detach_from<Windows::AI::MachineLearning::TensorString>(this->shim().CreateFromIterable(*reinterpret_cast<Windows::Foundation::Collections::IIterable<int64_t> const*>(&shape), *reinterpret_cast<Windows::Foundation::Collections::IIterable<hstring> const*>(&data)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::AI::MachineLearning::ITensorStringStatics2> : produce_base<D, Windows::AI::MachineLearning::ITensorStringStatics2>
{
    int32_t WINRT_CALL CreateFromShapeArrayAndDataArray(uint32_t __shapeSize, int64_t* shape, uint32_t __dataSize, void** data, void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CreateFromShapeArrayAndDataArray, WINRT_WRAP(Windows::AI::MachineLearning::TensorString), array_view<int64_t const>, array_view<hstring const>);
            *result = detach_from<Windows::AI::MachineLearning::TensorString>(this->shim().CreateFromShapeArrayAndDataArray(array_view<int64_t const>(reinterpret_cast<int64_t const *>(shape), reinterpret_cast<int64_t const *>(shape) + __shapeSize), array_view<hstring const>(reinterpret_cast<hstring const *>(data), reinterpret_cast<hstring const *>(data) + __dataSize)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::AI::MachineLearning::ITensorUInt16Bit> : produce_base<D, Windows::AI::MachineLearning::ITensorUInt16Bit>
{
    int32_t WINRT_CALL GetAsVectorView(void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetAsVectorView, WINRT_WRAP(Windows::Foundation::Collections::IVectorView<uint16_t>));
            *result = detach_from<Windows::Foundation::Collections::IVectorView<uint16_t>>(this->shim().GetAsVectorView());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::AI::MachineLearning::ITensorUInt16BitStatics> : produce_base<D, Windows::AI::MachineLearning::ITensorUInt16BitStatics>
{
    int32_t WINRT_CALL Create(void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Create, WINRT_WRAP(Windows::AI::MachineLearning::TensorUInt16Bit));
            *result = detach_from<Windows::AI::MachineLearning::TensorUInt16Bit>(this->shim().Create());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL Create2(void* shape, void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Create, WINRT_WRAP(Windows::AI::MachineLearning::TensorUInt16Bit), Windows::Foundation::Collections::IIterable<int64_t> const&);
            *result = detach_from<Windows::AI::MachineLearning::TensorUInt16Bit>(this->shim().Create(*reinterpret_cast<Windows::Foundation::Collections::IIterable<int64_t> const*>(&shape)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL CreateFromArray(void* shape, uint32_t __dataSize, uint16_t* data, void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CreateFromArray, WINRT_WRAP(Windows::AI::MachineLearning::TensorUInt16Bit), Windows::Foundation::Collections::IIterable<int64_t> const&, array_view<uint16_t const>);
            *result = detach_from<Windows::AI::MachineLearning::TensorUInt16Bit>(this->shim().CreateFromArray(*reinterpret_cast<Windows::Foundation::Collections::IIterable<int64_t> const*>(&shape), array_view<uint16_t const>(reinterpret_cast<uint16_t const *>(data), reinterpret_cast<uint16_t const *>(data) + __dataSize)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL CreateFromIterable(void* shape, void* data, void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CreateFromIterable, WINRT_WRAP(Windows::AI::MachineLearning::TensorUInt16Bit), Windows::Foundation::Collections::IIterable<int64_t> const&, Windows::Foundation::Collections::IIterable<uint16_t> const&);
            *result = detach_from<Windows::AI::MachineLearning::TensorUInt16Bit>(this->shim().CreateFromIterable(*reinterpret_cast<Windows::Foundation::Collections::IIterable<int64_t> const*>(&shape), *reinterpret_cast<Windows::Foundation::Collections::IIterable<uint16_t> const*>(&data)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::AI::MachineLearning::ITensorUInt16BitStatics2> : produce_base<D, Windows::AI::MachineLearning::ITensorUInt16BitStatics2>
{
    int32_t WINRT_CALL CreateFromShapeArrayAndDataArray(uint32_t __shapeSize, int64_t* shape, uint32_t __dataSize, uint16_t* data, void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CreateFromShapeArrayAndDataArray, WINRT_WRAP(Windows::AI::MachineLearning::TensorUInt16Bit), array_view<int64_t const>, array_view<uint16_t const>);
            *result = detach_from<Windows::AI::MachineLearning::TensorUInt16Bit>(this->shim().CreateFromShapeArrayAndDataArray(array_view<int64_t const>(reinterpret_cast<int64_t const *>(shape), reinterpret_cast<int64_t const *>(shape) + __shapeSize), array_view<uint16_t const>(reinterpret_cast<uint16_t const *>(data), reinterpret_cast<uint16_t const *>(data) + __dataSize)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL CreateFromBuffer(uint32_t __shapeSize, int64_t* shape, void* buffer, void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CreateFromBuffer, WINRT_WRAP(Windows::AI::MachineLearning::TensorUInt16Bit), array_view<int64_t const>, Windows::Storage::Streams::IBuffer const&);
            *result = detach_from<Windows::AI::MachineLearning::TensorUInt16Bit>(this->shim().CreateFromBuffer(array_view<int64_t const>(reinterpret_cast<int64_t const *>(shape), reinterpret_cast<int64_t const *>(shape) + __shapeSize), *reinterpret_cast<Windows::Storage::Streams::IBuffer const*>(&buffer)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::AI::MachineLearning::ITensorUInt32Bit> : produce_base<D, Windows::AI::MachineLearning::ITensorUInt32Bit>
{
    int32_t WINRT_CALL GetAsVectorView(void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetAsVectorView, WINRT_WRAP(Windows::Foundation::Collections::IVectorView<uint32_t>));
            *result = detach_from<Windows::Foundation::Collections::IVectorView<uint32_t>>(this->shim().GetAsVectorView());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::AI::MachineLearning::ITensorUInt32BitStatics> : produce_base<D, Windows::AI::MachineLearning::ITensorUInt32BitStatics>
{
    int32_t WINRT_CALL Create(void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Create, WINRT_WRAP(Windows::AI::MachineLearning::TensorUInt32Bit));
            *result = detach_from<Windows::AI::MachineLearning::TensorUInt32Bit>(this->shim().Create());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL Create2(void* shape, void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Create, WINRT_WRAP(Windows::AI::MachineLearning::TensorUInt32Bit), Windows::Foundation::Collections::IIterable<int64_t> const&);
            *result = detach_from<Windows::AI::MachineLearning::TensorUInt32Bit>(this->shim().Create(*reinterpret_cast<Windows::Foundation::Collections::IIterable<int64_t> const*>(&shape)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL CreateFromArray(void* shape, uint32_t __dataSize, uint32_t* data, void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CreateFromArray, WINRT_WRAP(Windows::AI::MachineLearning::TensorUInt32Bit), Windows::Foundation::Collections::IIterable<int64_t> const&, array_view<uint32_t const>);
            *result = detach_from<Windows::AI::MachineLearning::TensorUInt32Bit>(this->shim().CreateFromArray(*reinterpret_cast<Windows::Foundation::Collections::IIterable<int64_t> const*>(&shape), array_view<uint32_t const>(reinterpret_cast<uint32_t const *>(data), reinterpret_cast<uint32_t const *>(data) + __dataSize)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL CreateFromIterable(void* shape, void* data, void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CreateFromIterable, WINRT_WRAP(Windows::AI::MachineLearning::TensorUInt32Bit), Windows::Foundation::Collections::IIterable<int64_t> const&, Windows::Foundation::Collections::IIterable<uint32_t> const&);
            *result = detach_from<Windows::AI::MachineLearning::TensorUInt32Bit>(this->shim().CreateFromIterable(*reinterpret_cast<Windows::Foundation::Collections::IIterable<int64_t> const*>(&shape), *reinterpret_cast<Windows::Foundation::Collections::IIterable<uint32_t> const*>(&data)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::AI::MachineLearning::ITensorUInt32BitStatics2> : produce_base<D, Windows::AI::MachineLearning::ITensorUInt32BitStatics2>
{
    int32_t WINRT_CALL CreateFromShapeArrayAndDataArray(uint32_t __shapeSize, int64_t* shape, uint32_t __dataSize, uint32_t* data, void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CreateFromShapeArrayAndDataArray, WINRT_WRAP(Windows::AI::MachineLearning::TensorUInt32Bit), array_view<int64_t const>, array_view<uint32_t const>);
            *result = detach_from<Windows::AI::MachineLearning::TensorUInt32Bit>(this->shim().CreateFromShapeArrayAndDataArray(array_view<int64_t const>(reinterpret_cast<int64_t const *>(shape), reinterpret_cast<int64_t const *>(shape) + __shapeSize), array_view<uint32_t const>(reinterpret_cast<uint32_t const *>(data), reinterpret_cast<uint32_t const *>(data) + __dataSize)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL CreateFromBuffer(uint32_t __shapeSize, int64_t* shape, void* buffer, void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CreateFromBuffer, WINRT_WRAP(Windows::AI::MachineLearning::TensorUInt32Bit), array_view<int64_t const>, Windows::Storage::Streams::IBuffer const&);
            *result = detach_from<Windows::AI::MachineLearning::TensorUInt32Bit>(this->shim().CreateFromBuffer(array_view<int64_t const>(reinterpret_cast<int64_t const *>(shape), reinterpret_cast<int64_t const *>(shape) + __shapeSize), *reinterpret_cast<Windows::Storage::Streams::IBuffer const*>(&buffer)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::AI::MachineLearning::ITensorUInt64Bit> : produce_base<D, Windows::AI::MachineLearning::ITensorUInt64Bit>
{
    int32_t WINRT_CALL GetAsVectorView(void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetAsVectorView, WINRT_WRAP(Windows::Foundation::Collections::IVectorView<uint64_t>));
            *result = detach_from<Windows::Foundation::Collections::IVectorView<uint64_t>>(this->shim().GetAsVectorView());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::AI::MachineLearning::ITensorUInt64BitStatics> : produce_base<D, Windows::AI::MachineLearning::ITensorUInt64BitStatics>
{
    int32_t WINRT_CALL Create(void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Create, WINRT_WRAP(Windows::AI::MachineLearning::TensorUInt64Bit));
            *result = detach_from<Windows::AI::MachineLearning::TensorUInt64Bit>(this->shim().Create());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL Create2(void* shape, void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Create, WINRT_WRAP(Windows::AI::MachineLearning::TensorUInt64Bit), Windows::Foundation::Collections::IIterable<int64_t> const&);
            *result = detach_from<Windows::AI::MachineLearning::TensorUInt64Bit>(this->shim().Create(*reinterpret_cast<Windows::Foundation::Collections::IIterable<int64_t> const*>(&shape)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL CreateFromArray(void* shape, uint32_t __dataSize, uint64_t* data, void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CreateFromArray, WINRT_WRAP(Windows::AI::MachineLearning::TensorUInt64Bit), Windows::Foundation::Collections::IIterable<int64_t> const&, array_view<uint64_t const>);
            *result = detach_from<Windows::AI::MachineLearning::TensorUInt64Bit>(this->shim().CreateFromArray(*reinterpret_cast<Windows::Foundation::Collections::IIterable<int64_t> const*>(&shape), array_view<uint64_t const>(reinterpret_cast<uint64_t const *>(data), reinterpret_cast<uint64_t const *>(data) + __dataSize)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL CreateFromIterable(void* shape, void* data, void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CreateFromIterable, WINRT_WRAP(Windows::AI::MachineLearning::TensorUInt64Bit), Windows::Foundation::Collections::IIterable<int64_t> const&, Windows::Foundation::Collections::IIterable<uint64_t> const&);
            *result = detach_from<Windows::AI::MachineLearning::TensorUInt64Bit>(this->shim().CreateFromIterable(*reinterpret_cast<Windows::Foundation::Collections::IIterable<int64_t> const*>(&shape), *reinterpret_cast<Windows::Foundation::Collections::IIterable<uint64_t> const*>(&data)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::AI::MachineLearning::ITensorUInt64BitStatics2> : produce_base<D, Windows::AI::MachineLearning::ITensorUInt64BitStatics2>
{
    int32_t WINRT_CALL CreateFromShapeArrayAndDataArray(uint32_t __shapeSize, int64_t* shape, uint32_t __dataSize, uint64_t* data, void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CreateFromShapeArrayAndDataArray, WINRT_WRAP(Windows::AI::MachineLearning::TensorUInt64Bit), array_view<int64_t const>, array_view<uint64_t const>);
            *result = detach_from<Windows::AI::MachineLearning::TensorUInt64Bit>(this->shim().CreateFromShapeArrayAndDataArray(array_view<int64_t const>(reinterpret_cast<int64_t const *>(shape), reinterpret_cast<int64_t const *>(shape) + __shapeSize), array_view<uint64_t const>(reinterpret_cast<uint64_t const *>(data), reinterpret_cast<uint64_t const *>(data) + __dataSize)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL CreateFromBuffer(uint32_t __shapeSize, int64_t* shape, void* buffer, void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CreateFromBuffer, WINRT_WRAP(Windows::AI::MachineLearning::TensorUInt64Bit), array_view<int64_t const>, Windows::Storage::Streams::IBuffer const&);
            *result = detach_from<Windows::AI::MachineLearning::TensorUInt64Bit>(this->shim().CreateFromBuffer(array_view<int64_t const>(reinterpret_cast<int64_t const *>(shape), reinterpret_cast<int64_t const *>(shape) + __shapeSize), *reinterpret_cast<Windows::Storage::Streams::IBuffer const*>(&buffer)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::AI::MachineLearning::ITensorUInt8Bit> : produce_base<D, Windows::AI::MachineLearning::ITensorUInt8Bit>
{
    int32_t WINRT_CALL GetAsVectorView(void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetAsVectorView, WINRT_WRAP(Windows::Foundation::Collections::IVectorView<uint8_t>));
            *result = detach_from<Windows::Foundation::Collections::IVectorView<uint8_t>>(this->shim().GetAsVectorView());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::AI::MachineLearning::ITensorUInt8BitStatics> : produce_base<D, Windows::AI::MachineLearning::ITensorUInt8BitStatics>
{
    int32_t WINRT_CALL Create(void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Create, WINRT_WRAP(Windows::AI::MachineLearning::TensorUInt8Bit));
            *result = detach_from<Windows::AI::MachineLearning::TensorUInt8Bit>(this->shim().Create());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL Create2(void* shape, void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Create, WINRT_WRAP(Windows::AI::MachineLearning::TensorUInt8Bit), Windows::Foundation::Collections::IIterable<int64_t> const&);
            *result = detach_from<Windows::AI::MachineLearning::TensorUInt8Bit>(this->shim().Create(*reinterpret_cast<Windows::Foundation::Collections::IIterable<int64_t> const*>(&shape)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL CreateFromArray(void* shape, uint32_t __dataSize, uint8_t* data, void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CreateFromArray, WINRT_WRAP(Windows::AI::MachineLearning::TensorUInt8Bit), Windows::Foundation::Collections::IIterable<int64_t> const&, array_view<uint8_t const>);
            *result = detach_from<Windows::AI::MachineLearning::TensorUInt8Bit>(this->shim().CreateFromArray(*reinterpret_cast<Windows::Foundation::Collections::IIterable<int64_t> const*>(&shape), array_view<uint8_t const>(reinterpret_cast<uint8_t const *>(data), reinterpret_cast<uint8_t const *>(data) + __dataSize)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL CreateFromIterable(void* shape, void* data, void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CreateFromIterable, WINRT_WRAP(Windows::AI::MachineLearning::TensorUInt8Bit), Windows::Foundation::Collections::IIterable<int64_t> const&, Windows::Foundation::Collections::IIterable<uint8_t> const&);
            *result = detach_from<Windows::AI::MachineLearning::TensorUInt8Bit>(this->shim().CreateFromIterable(*reinterpret_cast<Windows::Foundation::Collections::IIterable<int64_t> const*>(&shape), *reinterpret_cast<Windows::Foundation::Collections::IIterable<uint8_t> const*>(&data)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::AI::MachineLearning::ITensorUInt8BitStatics2> : produce_base<D, Windows::AI::MachineLearning::ITensorUInt8BitStatics2>
{
    int32_t WINRT_CALL CreateFromShapeArrayAndDataArray(uint32_t __shapeSize, int64_t* shape, uint32_t __dataSize, uint8_t* data, void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CreateFromShapeArrayAndDataArray, WINRT_WRAP(Windows::AI::MachineLearning::TensorUInt8Bit), array_view<int64_t const>, array_view<uint8_t const>);
            *result = detach_from<Windows::AI::MachineLearning::TensorUInt8Bit>(this->shim().CreateFromShapeArrayAndDataArray(array_view<int64_t const>(reinterpret_cast<int64_t const *>(shape), reinterpret_cast<int64_t const *>(shape) + __shapeSize), array_view<uint8_t const>(reinterpret_cast<uint8_t const *>(data), reinterpret_cast<uint8_t const *>(data) + __dataSize)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL CreateFromBuffer(uint32_t __shapeSize, int64_t* shape, void* buffer, void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CreateFromBuffer, WINRT_WRAP(Windows::AI::MachineLearning::TensorUInt8Bit), array_view<int64_t const>, Windows::Storage::Streams::IBuffer const&);
            *result = detach_from<Windows::AI::MachineLearning::TensorUInt8Bit>(this->shim().CreateFromBuffer(array_view<int64_t const>(reinterpret_cast<int64_t const *>(shape), reinterpret_cast<int64_t const *>(shape) + __shapeSize), *reinterpret_cast<Windows::Storage::Streams::IBuffer const*>(&buffer)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

}

WINRT_EXPORT namespace winrt::Windows::AI::MachineLearning {

inline Windows::AI::MachineLearning::ImageFeatureValue ImageFeatureValue::CreateFromVideoFrame(Windows::Media::VideoFrame const& image)
{
    return impl::call_factory<ImageFeatureValue, Windows::AI::MachineLearning::IImageFeatureValueStatics>([&](auto&& f) { return f.CreateFromVideoFrame(image); });
}

inline Windows::Foundation::IAsyncOperation<Windows::AI::MachineLearning::LearningModel> LearningModel::LoadFromStorageFileAsync(Windows::Storage::IStorageFile const& modelFile)
{
    return impl::call_factory<LearningModel, Windows::AI::MachineLearning::ILearningModelStatics>([&](auto&& f) { return f.LoadFromStorageFileAsync(modelFile); });
}

inline Windows::Foundation::IAsyncOperation<Windows::AI::MachineLearning::LearningModel> LearningModel::LoadFromStreamAsync(Windows::Storage::Streams::IRandomAccessStreamReference const& modelStream)
{
    return impl::call_factory<LearningModel, Windows::AI::MachineLearning::ILearningModelStatics>([&](auto&& f) { return f.LoadFromStreamAsync(modelStream); });
}

inline Windows::AI::MachineLearning::LearningModel LearningModel::LoadFromFilePath(param::hstring const& filePath)
{
    return impl::call_factory<LearningModel, Windows::AI::MachineLearning::ILearningModelStatics>([&](auto&& f) { return f.LoadFromFilePath(filePath); });
}

inline Windows::AI::MachineLearning::LearningModel LearningModel::LoadFromStream(Windows::Storage::Streams::IRandomAccessStreamReference const& modelStream)
{
    return impl::call_factory<LearningModel, Windows::AI::MachineLearning::ILearningModelStatics>([&](auto&& f) { return f.LoadFromStream(modelStream); });
}

inline Windows::Foundation::IAsyncOperation<Windows::AI::MachineLearning::LearningModel> LearningModel::LoadFromStorageFileAsync(Windows::Storage::IStorageFile const& modelFile, Windows::AI::MachineLearning::ILearningModelOperatorProvider const& operatorProvider)
{
    return impl::call_factory<LearningModel, Windows::AI::MachineLearning::ILearningModelStatics>([&](auto&& f) { return f.LoadFromStorageFileAsync(modelFile, operatorProvider); });
}

inline Windows::Foundation::IAsyncOperation<Windows::AI::MachineLearning::LearningModel> LearningModel::LoadFromStreamAsync(Windows::Storage::Streams::IRandomAccessStreamReference const& modelStream, Windows::AI::MachineLearning::ILearningModelOperatorProvider const& operatorProvider)
{
    return impl::call_factory<LearningModel, Windows::AI::MachineLearning::ILearningModelStatics>([&](auto&& f) { return f.LoadFromStreamAsync(modelStream, operatorProvider); });
}

inline Windows::AI::MachineLearning::LearningModel LearningModel::LoadFromFilePath(param::hstring const& filePath, Windows::AI::MachineLearning::ILearningModelOperatorProvider const& operatorProvider)
{
    return impl::call_factory<LearningModel, Windows::AI::MachineLearning::ILearningModelStatics>([&](auto&& f) { return f.LoadFromFilePath(filePath, operatorProvider); });
}

inline Windows::AI::MachineLearning::LearningModel LearningModel::LoadFromStream(Windows::Storage::Streams::IRandomAccessStreamReference const& modelStream, Windows::AI::MachineLearning::ILearningModelOperatorProvider const& operatorProvider)
{
    return impl::call_factory<LearningModel, Windows::AI::MachineLearning::ILearningModelStatics>([&](auto&& f) { return f.LoadFromStream(modelStream, operatorProvider); });
}

inline LearningModelBinding::LearningModelBinding(Windows::AI::MachineLearning::LearningModelSession const& session) :
    LearningModelBinding(impl::call_factory<LearningModelBinding, Windows::AI::MachineLearning::ILearningModelBindingFactory>([&](auto&& f) { return f.CreateFromSession(session); }))
{}

inline LearningModelDevice::LearningModelDevice(Windows::AI::MachineLearning::LearningModelDeviceKind const& deviceKind) :
    LearningModelDevice(impl::call_factory<LearningModelDevice, Windows::AI::MachineLearning::ILearningModelDeviceFactory>([&](auto&& f) { return f.Create(deviceKind); }))
{}

inline Windows::AI::MachineLearning::LearningModelDevice LearningModelDevice::CreateFromDirect3D11Device(Windows::Graphics::DirectX::Direct3D11::IDirect3DDevice const& device)
{
    return impl::call_factory<LearningModelDevice, Windows::AI::MachineLearning::ILearningModelDeviceStatics>([&](auto&& f) { return f.CreateFromDirect3D11Device(device); });
}

inline LearningModelSession::LearningModelSession(Windows::AI::MachineLearning::LearningModel const& model) :
    LearningModelSession(impl::call_factory<LearningModelSession, Windows::AI::MachineLearning::ILearningModelSessionFactory>([&](auto&& f) { return f.CreateFromModel(model); }))
{}

inline LearningModelSession::LearningModelSession(Windows::AI::MachineLearning::LearningModel const& model, Windows::AI::MachineLearning::LearningModelDevice const& deviceToRunOn) :
    LearningModelSession(impl::call_factory<LearningModelSession, Windows::AI::MachineLearning::ILearningModelSessionFactory>([&](auto&& f) { return f.CreateFromModelOnDevice(model, deviceToRunOn); }))
{}

inline LearningModelSession::LearningModelSession(Windows::AI::MachineLearning::LearningModel const& model, Windows::AI::MachineLearning::LearningModelDevice const& deviceToRunOn, Windows::AI::MachineLearning::LearningModelSessionOptions const& learningModelSessionOptions) :
    LearningModelSession(impl::call_factory<LearningModelSession, Windows::AI::MachineLearning::ILearningModelSessionFactory2>([&](auto&& f) { return f.CreateFromModelOnDeviceWithSessionOptions(model, deviceToRunOn, learningModelSessionOptions); }))
{}

inline LearningModelSessionOptions::LearningModelSessionOptions() :
    LearningModelSessionOptions(impl::call_factory<LearningModelSessionOptions>([](auto&& f) { return f.template ActivateInstance<LearningModelSessionOptions>(); }))
{}

inline Windows::AI::MachineLearning::TensorBoolean TensorBoolean::Create()
{
    return impl::call_factory<TensorBoolean, Windows::AI::MachineLearning::ITensorBooleanStatics>([&](auto&& f) { return f.Create(); });
}

inline Windows::AI::MachineLearning::TensorBoolean TensorBoolean::Create(param::iterable<int64_t> const& shape)
{
    return impl::call_factory<TensorBoolean, Windows::AI::MachineLearning::ITensorBooleanStatics>([&](auto&& f) { return f.Create(shape); });
}

inline Windows::AI::MachineLearning::TensorBoolean TensorBoolean::CreateFromArray(param::iterable<int64_t> const& shape, array_view<bool const> data)
{
    return impl::call_factory<TensorBoolean, Windows::AI::MachineLearning::ITensorBooleanStatics>([&](auto&& f) { return f.CreateFromArray(shape, data); });
}

inline Windows::AI::MachineLearning::TensorBoolean TensorBoolean::CreateFromIterable(param::iterable<int64_t> const& shape, param::iterable<bool> const& data)
{
    return impl::call_factory<TensorBoolean, Windows::AI::MachineLearning::ITensorBooleanStatics>([&](auto&& f) { return f.CreateFromIterable(shape, data); });
}

inline Windows::AI::MachineLearning::TensorBoolean TensorBoolean::CreateFromShapeArrayAndDataArray(array_view<int64_t const> shape, array_view<bool const> data)
{
    return impl::call_factory<TensorBoolean, Windows::AI::MachineLearning::ITensorBooleanStatics2>([&](auto&& f) { return f.CreateFromShapeArrayAndDataArray(shape, data); });
}

inline Windows::AI::MachineLearning::TensorBoolean TensorBoolean::CreateFromBuffer(array_view<int64_t const> shape, Windows::Storage::Streams::IBuffer const& buffer)
{
    return impl::call_factory<TensorBoolean, Windows::AI::MachineLearning::ITensorBooleanStatics2>([&](auto&& f) { return f.CreateFromBuffer(shape, buffer); });
}

inline Windows::AI::MachineLearning::TensorDouble TensorDouble::Create()
{
    return impl::call_factory<TensorDouble, Windows::AI::MachineLearning::ITensorDoubleStatics>([&](auto&& f) { return f.Create(); });
}

inline Windows::AI::MachineLearning::TensorDouble TensorDouble::Create(param::iterable<int64_t> const& shape)
{
    return impl::call_factory<TensorDouble, Windows::AI::MachineLearning::ITensorDoubleStatics>([&](auto&& f) { return f.Create(shape); });
}

inline Windows::AI::MachineLearning::TensorDouble TensorDouble::CreateFromArray(param::iterable<int64_t> const& shape, array_view<double const> data)
{
    return impl::call_factory<TensorDouble, Windows::AI::MachineLearning::ITensorDoubleStatics>([&](auto&& f) { return f.CreateFromArray(shape, data); });
}

inline Windows::AI::MachineLearning::TensorDouble TensorDouble::CreateFromIterable(param::iterable<int64_t> const& shape, param::iterable<double> const& data)
{
    return impl::call_factory<TensorDouble, Windows::AI::MachineLearning::ITensorDoubleStatics>([&](auto&& f) { return f.CreateFromIterable(shape, data); });
}

inline Windows::AI::MachineLearning::TensorDouble TensorDouble::CreateFromShapeArrayAndDataArray(array_view<int64_t const> shape, array_view<double const> data)
{
    return impl::call_factory<TensorDouble, Windows::AI::MachineLearning::ITensorDoubleStatics2>([&](auto&& f) { return f.CreateFromShapeArrayAndDataArray(shape, data); });
}

inline Windows::AI::MachineLearning::TensorDouble TensorDouble::CreateFromBuffer(array_view<int64_t const> shape, Windows::Storage::Streams::IBuffer const& buffer)
{
    return impl::call_factory<TensorDouble, Windows::AI::MachineLearning::ITensorDoubleStatics2>([&](auto&& f) { return f.CreateFromBuffer(shape, buffer); });
}

inline Windows::AI::MachineLearning::TensorFloat TensorFloat::Create()
{
    return impl::call_factory<TensorFloat, Windows::AI::MachineLearning::ITensorFloatStatics>([&](auto&& f) { return f.Create(); });
}

inline Windows::AI::MachineLearning::TensorFloat TensorFloat::Create(param::iterable<int64_t> const& shape)
{
    return impl::call_factory<TensorFloat, Windows::AI::MachineLearning::ITensorFloatStatics>([&](auto&& f) { return f.Create(shape); });
}

inline Windows::AI::MachineLearning::TensorFloat TensorFloat::CreateFromArray(param::iterable<int64_t> const& shape, array_view<float const> data)
{
    return impl::call_factory<TensorFloat, Windows::AI::MachineLearning::ITensorFloatStatics>([&](auto&& f) { return f.CreateFromArray(shape, data); });
}

inline Windows::AI::MachineLearning::TensorFloat TensorFloat::CreateFromIterable(param::iterable<int64_t> const& shape, param::iterable<float> const& data)
{
    return impl::call_factory<TensorFloat, Windows::AI::MachineLearning::ITensorFloatStatics>([&](auto&& f) { return f.CreateFromIterable(shape, data); });
}

inline Windows::AI::MachineLearning::TensorFloat TensorFloat::CreateFromShapeArrayAndDataArray(array_view<int64_t const> shape, array_view<float const> data)
{
    return impl::call_factory<TensorFloat, Windows::AI::MachineLearning::ITensorFloatStatics2>([&](auto&& f) { return f.CreateFromShapeArrayAndDataArray(shape, data); });
}

inline Windows::AI::MachineLearning::TensorFloat TensorFloat::CreateFromBuffer(array_view<int64_t const> shape, Windows::Storage::Streams::IBuffer const& buffer)
{
    return impl::call_factory<TensorFloat, Windows::AI::MachineLearning::ITensorFloatStatics2>([&](auto&& f) { return f.CreateFromBuffer(shape, buffer); });
}

inline Windows::AI::MachineLearning::TensorFloat16Bit TensorFloat16Bit::Create()
{
    return impl::call_factory<TensorFloat16Bit, Windows::AI::MachineLearning::ITensorFloat16BitStatics>([&](auto&& f) { return f.Create(); });
}

inline Windows::AI::MachineLearning::TensorFloat16Bit TensorFloat16Bit::Create(param::iterable<int64_t> const& shape)
{
    return impl::call_factory<TensorFloat16Bit, Windows::AI::MachineLearning::ITensorFloat16BitStatics>([&](auto&& f) { return f.Create(shape); });
}

inline Windows::AI::MachineLearning::TensorFloat16Bit TensorFloat16Bit::CreateFromArray(param::iterable<int64_t> const& shape, array_view<float const> data)
{
    return impl::call_factory<TensorFloat16Bit, Windows::AI::MachineLearning::ITensorFloat16BitStatics>([&](auto&& f) { return f.CreateFromArray(shape, data); });
}

inline Windows::AI::MachineLearning::TensorFloat16Bit TensorFloat16Bit::CreateFromIterable(param::iterable<int64_t> const& shape, param::iterable<float> const& data)
{
    return impl::call_factory<TensorFloat16Bit, Windows::AI::MachineLearning::ITensorFloat16BitStatics>([&](auto&& f) { return f.CreateFromIterable(shape, data); });
}

inline Windows::AI::MachineLearning::TensorFloat16Bit TensorFloat16Bit::CreateFromShapeArrayAndDataArray(array_view<int64_t const> shape, array_view<float const> data)
{
    return impl::call_factory<TensorFloat16Bit, Windows::AI::MachineLearning::ITensorFloat16BitStatics2>([&](auto&& f) { return f.CreateFromShapeArrayAndDataArray(shape, data); });
}

inline Windows::AI::MachineLearning::TensorFloat16Bit TensorFloat16Bit::CreateFromBuffer(array_view<int64_t const> shape, Windows::Storage::Streams::IBuffer const& buffer)
{
    return impl::call_factory<TensorFloat16Bit, Windows::AI::MachineLearning::ITensorFloat16BitStatics2>([&](auto&& f) { return f.CreateFromBuffer(shape, buffer); });
}

inline Windows::AI::MachineLearning::TensorInt16Bit TensorInt16Bit::Create()
{
    return impl::call_factory<TensorInt16Bit, Windows::AI::MachineLearning::ITensorInt16BitStatics>([&](auto&& f) { return f.Create(); });
}

inline Windows::AI::MachineLearning::TensorInt16Bit TensorInt16Bit::Create(param::iterable<int64_t> const& shape)
{
    return impl::call_factory<TensorInt16Bit, Windows::AI::MachineLearning::ITensorInt16BitStatics>([&](auto&& f) { return f.Create(shape); });
}

inline Windows::AI::MachineLearning::TensorInt16Bit TensorInt16Bit::CreateFromArray(param::iterable<int64_t> const& shape, array_view<int16_t const> data)
{
    return impl::call_factory<TensorInt16Bit, Windows::AI::MachineLearning::ITensorInt16BitStatics>([&](auto&& f) { return f.CreateFromArray(shape, data); });
}

inline Windows::AI::MachineLearning::TensorInt16Bit TensorInt16Bit::CreateFromIterable(param::iterable<int64_t> const& shape, param::iterable<int16_t> const& data)
{
    return impl::call_factory<TensorInt16Bit, Windows::AI::MachineLearning::ITensorInt16BitStatics>([&](auto&& f) { return f.CreateFromIterable(shape, data); });
}

inline Windows::AI::MachineLearning::TensorInt16Bit TensorInt16Bit::CreateFromShapeArrayAndDataArray(array_view<int64_t const> shape, array_view<int16_t const> data)
{
    return impl::call_factory<TensorInt16Bit, Windows::AI::MachineLearning::ITensorInt16BitStatics2>([&](auto&& f) { return f.CreateFromShapeArrayAndDataArray(shape, data); });
}

inline Windows::AI::MachineLearning::TensorInt16Bit TensorInt16Bit::CreateFromBuffer(array_view<int64_t const> shape, Windows::Storage::Streams::IBuffer const& buffer)
{
    return impl::call_factory<TensorInt16Bit, Windows::AI::MachineLearning::ITensorInt16BitStatics2>([&](auto&& f) { return f.CreateFromBuffer(shape, buffer); });
}

inline Windows::AI::MachineLearning::TensorInt32Bit TensorInt32Bit::Create()
{
    return impl::call_factory<TensorInt32Bit, Windows::AI::MachineLearning::ITensorInt32BitStatics>([&](auto&& f) { return f.Create(); });
}

inline Windows::AI::MachineLearning::TensorInt32Bit TensorInt32Bit::Create(param::iterable<int64_t> const& shape)
{
    return impl::call_factory<TensorInt32Bit, Windows::AI::MachineLearning::ITensorInt32BitStatics>([&](auto&& f) { return f.Create(shape); });
}

inline Windows::AI::MachineLearning::TensorInt32Bit TensorInt32Bit::CreateFromArray(param::iterable<int64_t> const& shape, array_view<int32_t const> data)
{
    return impl::call_factory<TensorInt32Bit, Windows::AI::MachineLearning::ITensorInt32BitStatics>([&](auto&& f) { return f.CreateFromArray(shape, data); });
}

inline Windows::AI::MachineLearning::TensorInt32Bit TensorInt32Bit::CreateFromIterable(param::iterable<int64_t> const& shape, param::iterable<int32_t> const& data)
{
    return impl::call_factory<TensorInt32Bit, Windows::AI::MachineLearning::ITensorInt32BitStatics>([&](auto&& f) { return f.CreateFromIterable(shape, data); });
}

inline Windows::AI::MachineLearning::TensorInt32Bit TensorInt32Bit::CreateFromShapeArrayAndDataArray(array_view<int64_t const> shape, array_view<int32_t const> data)
{
    return impl::call_factory<TensorInt32Bit, Windows::AI::MachineLearning::ITensorInt32BitStatics2>([&](auto&& f) { return f.CreateFromShapeArrayAndDataArray(shape, data); });
}

inline Windows::AI::MachineLearning::TensorInt32Bit TensorInt32Bit::CreateFromBuffer(array_view<int64_t const> shape, Windows::Storage::Streams::IBuffer const& buffer)
{
    return impl::call_factory<TensorInt32Bit, Windows::AI::MachineLearning::ITensorInt32BitStatics2>([&](auto&& f) { return f.CreateFromBuffer(shape, buffer); });
}

inline Windows::AI::MachineLearning::TensorInt64Bit TensorInt64Bit::Create()
{
    return impl::call_factory<TensorInt64Bit, Windows::AI::MachineLearning::ITensorInt64BitStatics>([&](auto&& f) { return f.Create(); });
}

inline Windows::AI::MachineLearning::TensorInt64Bit TensorInt64Bit::Create(param::iterable<int64_t> const& shape)
{
    return impl::call_factory<TensorInt64Bit, Windows::AI::MachineLearning::ITensorInt64BitStatics>([&](auto&& f) { return f.Create(shape); });
}

inline Windows::AI::MachineLearning::TensorInt64Bit TensorInt64Bit::CreateFromArray(param::iterable<int64_t> const& shape, array_view<int64_t const> data)
{
    return impl::call_factory<TensorInt64Bit, Windows::AI::MachineLearning::ITensorInt64BitStatics>([&](auto&& f) { return f.CreateFromArray(shape, data); });
}

inline Windows::AI::MachineLearning::TensorInt64Bit TensorInt64Bit::CreateFromIterable(param::iterable<int64_t> const& shape, param::iterable<int64_t> const& data)
{
    return impl::call_factory<TensorInt64Bit, Windows::AI::MachineLearning::ITensorInt64BitStatics>([&](auto&& f) { return f.CreateFromIterable(shape, data); });
}

inline Windows::AI::MachineLearning::TensorInt64Bit TensorInt64Bit::CreateFromShapeArrayAndDataArray(array_view<int64_t const> shape, array_view<int64_t const> data)
{
    return impl::call_factory<TensorInt64Bit, Windows::AI::MachineLearning::ITensorInt64BitStatics2>([&](auto&& f) { return f.CreateFromShapeArrayAndDataArray(shape, data); });
}

inline Windows::AI::MachineLearning::TensorInt64Bit TensorInt64Bit::CreateFromBuffer(array_view<int64_t const> shape, Windows::Storage::Streams::IBuffer const& buffer)
{
    return impl::call_factory<TensorInt64Bit, Windows::AI::MachineLearning::ITensorInt64BitStatics2>([&](auto&& f) { return f.CreateFromBuffer(shape, buffer); });
}

inline Windows::AI::MachineLearning::TensorInt8Bit TensorInt8Bit::Create()
{
    return impl::call_factory<TensorInt8Bit, Windows::AI::MachineLearning::ITensorInt8BitStatics>([&](auto&& f) { return f.Create(); });
}

inline Windows::AI::MachineLearning::TensorInt8Bit TensorInt8Bit::Create(param::iterable<int64_t> const& shape)
{
    return impl::call_factory<TensorInt8Bit, Windows::AI::MachineLearning::ITensorInt8BitStatics>([&](auto&& f) { return f.Create(shape); });
}

inline Windows::AI::MachineLearning::TensorInt8Bit TensorInt8Bit::CreateFromArray(param::iterable<int64_t> const& shape, array_view<uint8_t const> data)
{
    return impl::call_factory<TensorInt8Bit, Windows::AI::MachineLearning::ITensorInt8BitStatics>([&](auto&& f) { return f.CreateFromArray(shape, data); });
}

inline Windows::AI::MachineLearning::TensorInt8Bit TensorInt8Bit::CreateFromIterable(param::iterable<int64_t> const& shape, param::iterable<uint8_t> const& data)
{
    return impl::call_factory<TensorInt8Bit, Windows::AI::MachineLearning::ITensorInt8BitStatics>([&](auto&& f) { return f.CreateFromIterable(shape, data); });
}

inline Windows::AI::MachineLearning::TensorInt8Bit TensorInt8Bit::CreateFromShapeArrayAndDataArray(array_view<int64_t const> shape, array_view<uint8_t const> data)
{
    return impl::call_factory<TensorInt8Bit, Windows::AI::MachineLearning::ITensorInt8BitStatics2>([&](auto&& f) { return f.CreateFromShapeArrayAndDataArray(shape, data); });
}

inline Windows::AI::MachineLearning::TensorInt8Bit TensorInt8Bit::CreateFromBuffer(array_view<int64_t const> shape, Windows::Storage::Streams::IBuffer const& buffer)
{
    return impl::call_factory<TensorInt8Bit, Windows::AI::MachineLearning::ITensorInt8BitStatics2>([&](auto&& f) { return f.CreateFromBuffer(shape, buffer); });
}

inline Windows::AI::MachineLearning::TensorString TensorString::Create()
{
    return impl::call_factory<TensorString, Windows::AI::MachineLearning::ITensorStringStatics>([&](auto&& f) { return f.Create(); });
}

inline Windows::AI::MachineLearning::TensorString TensorString::Create(param::iterable<int64_t> const& shape)
{
    return impl::call_factory<TensorString, Windows::AI::MachineLearning::ITensorStringStatics>([&](auto&& f) { return f.Create(shape); });
}

inline Windows::AI::MachineLearning::TensorString TensorString::CreateFromArray(param::iterable<int64_t> const& shape, array_view<hstring const> data)
{
    return impl::call_factory<TensorString, Windows::AI::MachineLearning::ITensorStringStatics>([&](auto&& f) { return f.CreateFromArray(shape, data); });
}

inline Windows::AI::MachineLearning::TensorString TensorString::CreateFromIterable(param::iterable<int64_t> const& shape, param::iterable<hstring> const& data)
{
    return impl::call_factory<TensorString, Windows::AI::MachineLearning::ITensorStringStatics>([&](auto&& f) { return f.CreateFromIterable(shape, data); });
}

inline Windows::AI::MachineLearning::TensorString TensorString::CreateFromShapeArrayAndDataArray(array_view<int64_t const> shape, array_view<hstring const> data)
{
    return impl::call_factory<TensorString, Windows::AI::MachineLearning::ITensorStringStatics2>([&](auto&& f) { return f.CreateFromShapeArrayAndDataArray(shape, data); });
}

inline Windows::AI::MachineLearning::TensorUInt16Bit TensorUInt16Bit::Create()
{
    return impl::call_factory<TensorUInt16Bit, Windows::AI::MachineLearning::ITensorUInt16BitStatics>([&](auto&& f) { return f.Create(); });
}

inline Windows::AI::MachineLearning::TensorUInt16Bit TensorUInt16Bit::Create(param::iterable<int64_t> const& shape)
{
    return impl::call_factory<TensorUInt16Bit, Windows::AI::MachineLearning::ITensorUInt16BitStatics>([&](auto&& f) { return f.Create(shape); });
}

inline Windows::AI::MachineLearning::TensorUInt16Bit TensorUInt16Bit::CreateFromArray(param::iterable<int64_t> const& shape, array_view<uint16_t const> data)
{
    return impl::call_factory<TensorUInt16Bit, Windows::AI::MachineLearning::ITensorUInt16BitStatics>([&](auto&& f) { return f.CreateFromArray(shape, data); });
}

inline Windows::AI::MachineLearning::TensorUInt16Bit TensorUInt16Bit::CreateFromIterable(param::iterable<int64_t> const& shape, param::iterable<uint16_t> const& data)
{
    return impl::call_factory<TensorUInt16Bit, Windows::AI::MachineLearning::ITensorUInt16BitStatics>([&](auto&& f) { return f.CreateFromIterable(shape, data); });
}

inline Windows::AI::MachineLearning::TensorUInt16Bit TensorUInt16Bit::CreateFromShapeArrayAndDataArray(array_view<int64_t const> shape, array_view<uint16_t const> data)
{
    return impl::call_factory<TensorUInt16Bit, Windows::AI::MachineLearning::ITensorUInt16BitStatics2>([&](auto&& f) { return f.CreateFromShapeArrayAndDataArray(shape, data); });
}

inline Windows::AI::MachineLearning::TensorUInt16Bit TensorUInt16Bit::CreateFromBuffer(array_view<int64_t const> shape, Windows::Storage::Streams::IBuffer const& buffer)
{
    return impl::call_factory<TensorUInt16Bit, Windows::AI::MachineLearning::ITensorUInt16BitStatics2>([&](auto&& f) { return f.CreateFromBuffer(shape, buffer); });
}

inline Windows::AI::MachineLearning::TensorUInt32Bit TensorUInt32Bit::Create()
{
    return impl::call_factory<TensorUInt32Bit, Windows::AI::MachineLearning::ITensorUInt32BitStatics>([&](auto&& f) { return f.Create(); });
}

inline Windows::AI::MachineLearning::TensorUInt32Bit TensorUInt32Bit::Create(param::iterable<int64_t> const& shape)
{
    return impl::call_factory<TensorUInt32Bit, Windows::AI::MachineLearning::ITensorUInt32BitStatics>([&](auto&& f) { return f.Create(shape); });
}

inline Windows::AI::MachineLearning::TensorUInt32Bit TensorUInt32Bit::CreateFromArray(param::iterable<int64_t> const& shape, array_view<uint32_t const> data)
{
    return impl::call_factory<TensorUInt32Bit, Windows::AI::MachineLearning::ITensorUInt32BitStatics>([&](auto&& f) { return f.CreateFromArray(shape, data); });
}

inline Windows::AI::MachineLearning::TensorUInt32Bit TensorUInt32Bit::CreateFromIterable(param::iterable<int64_t> const& shape, param::iterable<uint32_t> const& data)
{
    return impl::call_factory<TensorUInt32Bit, Windows::AI::MachineLearning::ITensorUInt32BitStatics>([&](auto&& f) { return f.CreateFromIterable(shape, data); });
}

inline Windows::AI::MachineLearning::TensorUInt32Bit TensorUInt32Bit::CreateFromShapeArrayAndDataArray(array_view<int64_t const> shape, array_view<uint32_t const> data)
{
    return impl::call_factory<TensorUInt32Bit, Windows::AI::MachineLearning::ITensorUInt32BitStatics2>([&](auto&& f) { return f.CreateFromShapeArrayAndDataArray(shape, data); });
}

inline Windows::AI::MachineLearning::TensorUInt32Bit TensorUInt32Bit::CreateFromBuffer(array_view<int64_t const> shape, Windows::Storage::Streams::IBuffer const& buffer)
{
    return impl::call_factory<TensorUInt32Bit, Windows::AI::MachineLearning::ITensorUInt32BitStatics2>([&](auto&& f) { return f.CreateFromBuffer(shape, buffer); });
}

inline Windows::AI::MachineLearning::TensorUInt64Bit TensorUInt64Bit::Create()
{
    return impl::call_factory<TensorUInt64Bit, Windows::AI::MachineLearning::ITensorUInt64BitStatics>([&](auto&& f) { return f.Create(); });
}

inline Windows::AI::MachineLearning::TensorUInt64Bit TensorUInt64Bit::Create(param::iterable<int64_t> const& shape)
{
    return impl::call_factory<TensorUInt64Bit, Windows::AI::MachineLearning::ITensorUInt64BitStatics>([&](auto&& f) { return f.Create(shape); });
}

inline Windows::AI::MachineLearning::TensorUInt64Bit TensorUInt64Bit::CreateFromArray(param::iterable<int64_t> const& shape, array_view<uint64_t const> data)
{
    return impl::call_factory<TensorUInt64Bit, Windows::AI::MachineLearning::ITensorUInt64BitStatics>([&](auto&& f) { return f.CreateFromArray(shape, data); });
}

inline Windows::AI::MachineLearning::TensorUInt64Bit TensorUInt64Bit::CreateFromIterable(param::iterable<int64_t> const& shape, param::iterable<uint64_t> const& data)
{
    return impl::call_factory<TensorUInt64Bit, Windows::AI::MachineLearning::ITensorUInt64BitStatics>([&](auto&& f) { return f.CreateFromIterable(shape, data); });
}

inline Windows::AI::MachineLearning::TensorUInt64Bit TensorUInt64Bit::CreateFromShapeArrayAndDataArray(array_view<int64_t const> shape, array_view<uint64_t const> data)
{
    return impl::call_factory<TensorUInt64Bit, Windows::AI::MachineLearning::ITensorUInt64BitStatics2>([&](auto&& f) { return f.CreateFromShapeArrayAndDataArray(shape, data); });
}

inline Windows::AI::MachineLearning::TensorUInt64Bit TensorUInt64Bit::CreateFromBuffer(array_view<int64_t const> shape, Windows::Storage::Streams::IBuffer const& buffer)
{
    return impl::call_factory<TensorUInt64Bit, Windows::AI::MachineLearning::ITensorUInt64BitStatics2>([&](auto&& f) { return f.CreateFromBuffer(shape, buffer); });
}

inline Windows::AI::MachineLearning::TensorUInt8Bit TensorUInt8Bit::Create()
{
    return impl::call_factory<TensorUInt8Bit, Windows::AI::MachineLearning::ITensorUInt8BitStatics>([&](auto&& f) { return f.Create(); });
}

inline Windows::AI::MachineLearning::TensorUInt8Bit TensorUInt8Bit::Create(param::iterable<int64_t> const& shape)
{
    return impl::call_factory<TensorUInt8Bit, Windows::AI::MachineLearning::ITensorUInt8BitStatics>([&](auto&& f) { return f.Create(shape); });
}

inline Windows::AI::MachineLearning::TensorUInt8Bit TensorUInt8Bit::CreateFromArray(param::iterable<int64_t> const& shape, array_view<uint8_t const> data)
{
    return impl::call_factory<TensorUInt8Bit, Windows::AI::MachineLearning::ITensorUInt8BitStatics>([&](auto&& f) { return f.CreateFromArray(shape, data); });
}

inline Windows::AI::MachineLearning::TensorUInt8Bit TensorUInt8Bit::CreateFromIterable(param::iterable<int64_t> const& shape, param::iterable<uint8_t> const& data)
{
    return impl::call_factory<TensorUInt8Bit, Windows::AI::MachineLearning::ITensorUInt8BitStatics>([&](auto&& f) { return f.CreateFromIterable(shape, data); });
}

inline Windows::AI::MachineLearning::TensorUInt8Bit TensorUInt8Bit::CreateFromShapeArrayAndDataArray(array_view<int64_t const> shape, array_view<uint8_t const> data)
{
    return impl::call_factory<TensorUInt8Bit, Windows::AI::MachineLearning::ITensorUInt8BitStatics2>([&](auto&& f) { return f.CreateFromShapeArrayAndDataArray(shape, data); });
}

inline Windows::AI::MachineLearning::TensorUInt8Bit TensorUInt8Bit::CreateFromBuffer(array_view<int64_t const> shape, Windows::Storage::Streams::IBuffer const& buffer)
{
    return impl::call_factory<TensorUInt8Bit, Windows::AI::MachineLearning::ITensorUInt8BitStatics2>([&](auto&& f) { return f.CreateFromBuffer(shape, buffer); });
}

}

WINRT_EXPORT namespace std {

template<> struct hash<winrt::Windows::AI::MachineLearning::IImageFeatureDescriptor> : winrt::impl::hash_base<winrt::Windows::AI::MachineLearning::IImageFeatureDescriptor> {};
template<> struct hash<winrt::Windows::AI::MachineLearning::IImageFeatureValue> : winrt::impl::hash_base<winrt::Windows::AI::MachineLearning::IImageFeatureValue> {};
template<> struct hash<winrt::Windows::AI::MachineLearning::IImageFeatureValueStatics> : winrt::impl::hash_base<winrt::Windows::AI::MachineLearning::IImageFeatureValueStatics> {};
template<> struct hash<winrt::Windows::AI::MachineLearning::ILearningModel> : winrt::impl::hash_base<winrt::Windows::AI::MachineLearning::ILearningModel> {};
template<> struct hash<winrt::Windows::AI::MachineLearning::ILearningModelBinding> : winrt::impl::hash_base<winrt::Windows::AI::MachineLearning::ILearningModelBinding> {};
template<> struct hash<winrt::Windows::AI::MachineLearning::ILearningModelBindingFactory> : winrt::impl::hash_base<winrt::Windows::AI::MachineLearning::ILearningModelBindingFactory> {};
template<> struct hash<winrt::Windows::AI::MachineLearning::ILearningModelDevice> : winrt::impl::hash_base<winrt::Windows::AI::MachineLearning::ILearningModelDevice> {};
template<> struct hash<winrt::Windows::AI::MachineLearning::ILearningModelDeviceFactory> : winrt::impl::hash_base<winrt::Windows::AI::MachineLearning::ILearningModelDeviceFactory> {};
template<> struct hash<winrt::Windows::AI::MachineLearning::ILearningModelDeviceStatics> : winrt::impl::hash_base<winrt::Windows::AI::MachineLearning::ILearningModelDeviceStatics> {};
template<> struct hash<winrt::Windows::AI::MachineLearning::ILearningModelEvaluationResult> : winrt::impl::hash_base<winrt::Windows::AI::MachineLearning::ILearningModelEvaluationResult> {};
template<> struct hash<winrt::Windows::AI::MachineLearning::ILearningModelFeatureDescriptor> : winrt::impl::hash_base<winrt::Windows::AI::MachineLearning::ILearningModelFeatureDescriptor> {};
template<> struct hash<winrt::Windows::AI::MachineLearning::ILearningModelFeatureValue> : winrt::impl::hash_base<winrt::Windows::AI::MachineLearning::ILearningModelFeatureValue> {};
template<> struct hash<winrt::Windows::AI::MachineLearning::ILearningModelOperatorProvider> : winrt::impl::hash_base<winrt::Windows::AI::MachineLearning::ILearningModelOperatorProvider> {};
template<> struct hash<winrt::Windows::AI::MachineLearning::ILearningModelSession> : winrt::impl::hash_base<winrt::Windows::AI::MachineLearning::ILearningModelSession> {};
template<> struct hash<winrt::Windows::AI::MachineLearning::ILearningModelSessionFactory> : winrt::impl::hash_base<winrt::Windows::AI::MachineLearning::ILearningModelSessionFactory> {};
template<> struct hash<winrt::Windows::AI::MachineLearning::ILearningModelSessionFactory2> : winrt::impl::hash_base<winrt::Windows::AI::MachineLearning::ILearningModelSessionFactory2> {};
template<> struct hash<winrt::Windows::AI::MachineLearning::ILearningModelSessionOptions> : winrt::impl::hash_base<winrt::Windows::AI::MachineLearning::ILearningModelSessionOptions> {};
template<> struct hash<winrt::Windows::AI::MachineLearning::ILearningModelStatics> : winrt::impl::hash_base<winrt::Windows::AI::MachineLearning::ILearningModelStatics> {};
template<> struct hash<winrt::Windows::AI::MachineLearning::IMapFeatureDescriptor> : winrt::impl::hash_base<winrt::Windows::AI::MachineLearning::IMapFeatureDescriptor> {};
template<> struct hash<winrt::Windows::AI::MachineLearning::ISequenceFeatureDescriptor> : winrt::impl::hash_base<winrt::Windows::AI::MachineLearning::ISequenceFeatureDescriptor> {};
template<> struct hash<winrt::Windows::AI::MachineLearning::ITensor> : winrt::impl::hash_base<winrt::Windows::AI::MachineLearning::ITensor> {};
template<> struct hash<winrt::Windows::AI::MachineLearning::ITensorBoolean> : winrt::impl::hash_base<winrt::Windows::AI::MachineLearning::ITensorBoolean> {};
template<> struct hash<winrt::Windows::AI::MachineLearning::ITensorBooleanStatics> : winrt::impl::hash_base<winrt::Windows::AI::MachineLearning::ITensorBooleanStatics> {};
template<> struct hash<winrt::Windows::AI::MachineLearning::ITensorBooleanStatics2> : winrt::impl::hash_base<winrt::Windows::AI::MachineLearning::ITensorBooleanStatics2> {};
template<> struct hash<winrt::Windows::AI::MachineLearning::ITensorDouble> : winrt::impl::hash_base<winrt::Windows::AI::MachineLearning::ITensorDouble> {};
template<> struct hash<winrt::Windows::AI::MachineLearning::ITensorDoubleStatics> : winrt::impl::hash_base<winrt::Windows::AI::MachineLearning::ITensorDoubleStatics> {};
template<> struct hash<winrt::Windows::AI::MachineLearning::ITensorDoubleStatics2> : winrt::impl::hash_base<winrt::Windows::AI::MachineLearning::ITensorDoubleStatics2> {};
template<> struct hash<winrt::Windows::AI::MachineLearning::ITensorFeatureDescriptor> : winrt::impl::hash_base<winrt::Windows::AI::MachineLearning::ITensorFeatureDescriptor> {};
template<> struct hash<winrt::Windows::AI::MachineLearning::ITensorFloat> : winrt::impl::hash_base<winrt::Windows::AI::MachineLearning::ITensorFloat> {};
template<> struct hash<winrt::Windows::AI::MachineLearning::ITensorFloat16Bit> : winrt::impl::hash_base<winrt::Windows::AI::MachineLearning::ITensorFloat16Bit> {};
template<> struct hash<winrt::Windows::AI::MachineLearning::ITensorFloat16BitStatics> : winrt::impl::hash_base<winrt::Windows::AI::MachineLearning::ITensorFloat16BitStatics> {};
template<> struct hash<winrt::Windows::AI::MachineLearning::ITensorFloat16BitStatics2> : winrt::impl::hash_base<winrt::Windows::AI::MachineLearning::ITensorFloat16BitStatics2> {};
template<> struct hash<winrt::Windows::AI::MachineLearning::ITensorFloatStatics> : winrt::impl::hash_base<winrt::Windows::AI::MachineLearning::ITensorFloatStatics> {};
template<> struct hash<winrt::Windows::AI::MachineLearning::ITensorFloatStatics2> : winrt::impl::hash_base<winrt::Windows::AI::MachineLearning::ITensorFloatStatics2> {};
template<> struct hash<winrt::Windows::AI::MachineLearning::ITensorInt16Bit> : winrt::impl::hash_base<winrt::Windows::AI::MachineLearning::ITensorInt16Bit> {};
template<> struct hash<winrt::Windows::AI::MachineLearning::ITensorInt16BitStatics> : winrt::impl::hash_base<winrt::Windows::AI::MachineLearning::ITensorInt16BitStatics> {};
template<> struct hash<winrt::Windows::AI::MachineLearning::ITensorInt16BitStatics2> : winrt::impl::hash_base<winrt::Windows::AI::MachineLearning::ITensorInt16BitStatics2> {};
template<> struct hash<winrt::Windows::AI::MachineLearning::ITensorInt32Bit> : winrt::impl::hash_base<winrt::Windows::AI::MachineLearning::ITensorInt32Bit> {};
template<> struct hash<winrt::Windows::AI::MachineLearning::ITensorInt32BitStatics> : winrt::impl::hash_base<winrt::Windows::AI::MachineLearning::ITensorInt32BitStatics> {};
template<> struct hash<winrt::Windows::AI::MachineLearning::ITensorInt32BitStatics2> : winrt::impl::hash_base<winrt::Windows::AI::MachineLearning::ITensorInt32BitStatics2> {};
template<> struct hash<winrt::Windows::AI::MachineLearning::ITensorInt64Bit> : winrt::impl::hash_base<winrt::Windows::AI::MachineLearning::ITensorInt64Bit> {};
template<> struct hash<winrt::Windows::AI::MachineLearning::ITensorInt64BitStatics> : winrt::impl::hash_base<winrt::Windows::AI::MachineLearning::ITensorInt64BitStatics> {};
template<> struct hash<winrt::Windows::AI::MachineLearning::ITensorInt64BitStatics2> : winrt::impl::hash_base<winrt::Windows::AI::MachineLearning::ITensorInt64BitStatics2> {};
template<> struct hash<winrt::Windows::AI::MachineLearning::ITensorInt8Bit> : winrt::impl::hash_base<winrt::Windows::AI::MachineLearning::ITensorInt8Bit> {};
template<> struct hash<winrt::Windows::AI::MachineLearning::ITensorInt8BitStatics> : winrt::impl::hash_base<winrt::Windows::AI::MachineLearning::ITensorInt8BitStatics> {};
template<> struct hash<winrt::Windows::AI::MachineLearning::ITensorInt8BitStatics2> : winrt::impl::hash_base<winrt::Windows::AI::MachineLearning::ITensorInt8BitStatics2> {};
template<> struct hash<winrt::Windows::AI::MachineLearning::ITensorString> : winrt::impl::hash_base<winrt::Windows::AI::MachineLearning::ITensorString> {};
template<> struct hash<winrt::Windows::AI::MachineLearning::ITensorStringStatics> : winrt::impl::hash_base<winrt::Windows::AI::MachineLearning::ITensorStringStatics> {};
template<> struct hash<winrt::Windows::AI::MachineLearning::ITensorStringStatics2> : winrt::impl::hash_base<winrt::Windows::AI::MachineLearning::ITensorStringStatics2> {};
template<> struct hash<winrt::Windows::AI::MachineLearning::ITensorUInt16Bit> : winrt::impl::hash_base<winrt::Windows::AI::MachineLearning::ITensorUInt16Bit> {};
template<> struct hash<winrt::Windows::AI::MachineLearning::ITensorUInt16BitStatics> : winrt::impl::hash_base<winrt::Windows::AI::MachineLearning::ITensorUInt16BitStatics> {};
template<> struct hash<winrt::Windows::AI::MachineLearning::ITensorUInt16BitStatics2> : winrt::impl::hash_base<winrt::Windows::AI::MachineLearning::ITensorUInt16BitStatics2> {};
template<> struct hash<winrt::Windows::AI::MachineLearning::ITensorUInt32Bit> : winrt::impl::hash_base<winrt::Windows::AI::MachineLearning::ITensorUInt32Bit> {};
template<> struct hash<winrt::Windows::AI::MachineLearning::ITensorUInt32BitStatics> : winrt::impl::hash_base<winrt::Windows::AI::MachineLearning::ITensorUInt32BitStatics> {};
template<> struct hash<winrt::Windows::AI::MachineLearning::ITensorUInt32BitStatics2> : winrt::impl::hash_base<winrt::Windows::AI::MachineLearning::ITensorUInt32BitStatics2> {};
template<> struct hash<winrt::Windows::AI::MachineLearning::ITensorUInt64Bit> : winrt::impl::hash_base<winrt::Windows::AI::MachineLearning::ITensorUInt64Bit> {};
template<> struct hash<winrt::Windows::AI::MachineLearning::ITensorUInt64BitStatics> : winrt::impl::hash_base<winrt::Windows::AI::MachineLearning::ITensorUInt64BitStatics> {};
template<> struct hash<winrt::Windows::AI::MachineLearning::ITensorUInt64BitStatics2> : winrt::impl::hash_base<winrt::Windows::AI::MachineLearning::ITensorUInt64BitStatics2> {};
template<> struct hash<winrt::Windows::AI::MachineLearning::ITensorUInt8Bit> : winrt::impl::hash_base<winrt::Windows::AI::MachineLearning::ITensorUInt8Bit> {};
template<> struct hash<winrt::Windows::AI::MachineLearning::ITensorUInt8BitStatics> : winrt::impl::hash_base<winrt::Windows::AI::MachineLearning::ITensorUInt8BitStatics> {};
template<> struct hash<winrt::Windows::AI::MachineLearning::ITensorUInt8BitStatics2> : winrt::impl::hash_base<winrt::Windows::AI::MachineLearning::ITensorUInt8BitStatics2> {};
template<> struct hash<winrt::Windows::AI::MachineLearning::ImageFeatureDescriptor> : winrt::impl::hash_base<winrt::Windows::AI::MachineLearning::ImageFeatureDescriptor> {};
template<> struct hash<winrt::Windows::AI::MachineLearning::ImageFeatureValue> : winrt::impl::hash_base<winrt::Windows::AI::MachineLearning::ImageFeatureValue> {};
template<> struct hash<winrt::Windows::AI::MachineLearning::LearningModel> : winrt::impl::hash_base<winrt::Windows::AI::MachineLearning::LearningModel> {};
template<> struct hash<winrt::Windows::AI::MachineLearning::LearningModelBinding> : winrt::impl::hash_base<winrt::Windows::AI::MachineLearning::LearningModelBinding> {};
template<> struct hash<winrt::Windows::AI::MachineLearning::LearningModelDevice> : winrt::impl::hash_base<winrt::Windows::AI::MachineLearning::LearningModelDevice> {};
template<> struct hash<winrt::Windows::AI::MachineLearning::LearningModelEvaluationResult> : winrt::impl::hash_base<winrt::Windows::AI::MachineLearning::LearningModelEvaluationResult> {};
template<> struct hash<winrt::Windows::AI::MachineLearning::LearningModelSession> : winrt::impl::hash_base<winrt::Windows::AI::MachineLearning::LearningModelSession> {};
template<> struct hash<winrt::Windows::AI::MachineLearning::LearningModelSessionOptions> : winrt::impl::hash_base<winrt::Windows::AI::MachineLearning::LearningModelSessionOptions> {};
template<> struct hash<winrt::Windows::AI::MachineLearning::MapFeatureDescriptor> : winrt::impl::hash_base<winrt::Windows::AI::MachineLearning::MapFeatureDescriptor> {};
template<> struct hash<winrt::Windows::AI::MachineLearning::SequenceFeatureDescriptor> : winrt::impl::hash_base<winrt::Windows::AI::MachineLearning::SequenceFeatureDescriptor> {};
template<> struct hash<winrt::Windows::AI::MachineLearning::TensorBoolean> : winrt::impl::hash_base<winrt::Windows::AI::MachineLearning::TensorBoolean> {};
template<> struct hash<winrt::Windows::AI::MachineLearning::TensorDouble> : winrt::impl::hash_base<winrt::Windows::AI::MachineLearning::TensorDouble> {};
template<> struct hash<winrt::Windows::AI::MachineLearning::TensorFeatureDescriptor> : winrt::impl::hash_base<winrt::Windows::AI::MachineLearning::TensorFeatureDescriptor> {};
template<> struct hash<winrt::Windows::AI::MachineLearning::TensorFloat> : winrt::impl::hash_base<winrt::Windows::AI::MachineLearning::TensorFloat> {};
template<> struct hash<winrt::Windows::AI::MachineLearning::TensorFloat16Bit> : winrt::impl::hash_base<winrt::Windows::AI::MachineLearning::TensorFloat16Bit> {};
template<> struct hash<winrt::Windows::AI::MachineLearning::TensorInt16Bit> : winrt::impl::hash_base<winrt::Windows::AI::MachineLearning::TensorInt16Bit> {};
template<> struct hash<winrt::Windows::AI::MachineLearning::TensorInt32Bit> : winrt::impl::hash_base<winrt::Windows::AI::MachineLearning::TensorInt32Bit> {};
template<> struct hash<winrt::Windows::AI::MachineLearning::TensorInt64Bit> : winrt::impl::hash_base<winrt::Windows::AI::MachineLearning::TensorInt64Bit> {};
template<> struct hash<winrt::Windows::AI::MachineLearning::TensorInt8Bit> : winrt::impl::hash_base<winrt::Windows::AI::MachineLearning::TensorInt8Bit> {};
template<> struct hash<winrt::Windows::AI::MachineLearning::TensorString> : winrt::impl::hash_base<winrt::Windows::AI::MachineLearning::TensorString> {};
template<> struct hash<winrt::Windows::AI::MachineLearning::TensorUInt16Bit> : winrt::impl::hash_base<winrt::Windows::AI::MachineLearning::TensorUInt16Bit> {};
template<> struct hash<winrt::Windows::AI::MachineLearning::TensorUInt32Bit> : winrt::impl::hash_base<winrt::Windows::AI::MachineLearning::TensorUInt32Bit> {};
template<> struct hash<winrt::Windows::AI::MachineLearning::TensorUInt64Bit> : winrt::impl::hash_base<winrt::Windows::AI::MachineLearning::TensorUInt64Bit> {};
template<> struct hash<winrt::Windows::AI::MachineLearning::TensorUInt8Bit> : winrt::impl::hash_base<winrt::Windows::AI::MachineLearning::TensorUInt8Bit> {};

}
