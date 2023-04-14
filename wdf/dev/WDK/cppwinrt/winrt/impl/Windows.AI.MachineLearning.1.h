// C++/WinRT v1.0.190111.3

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#pragma once
#include "winrt/impl/Windows.Foundation.0.h"
#include "winrt/impl/Windows.Foundation.Collections.0.h"
#include "winrt/impl/Windows.Graphics.0.h"
#include "winrt/impl/Windows.Graphics.DirectX.Direct3D11.0.h"
#include "winrt/impl/Windows.Graphics.Imaging.0.h"
#include "winrt/impl/Windows.Media.0.h"
#include "winrt/impl/Windows.Storage.0.h"
#include "winrt/impl/Windows.Storage.Streams.0.h"
#include "winrt/impl/Windows.Foundation.Collections.0.h"
#include "winrt/impl/Windows.AI.MachineLearning.0.h"

WINRT_EXPORT namespace winrt::Windows::AI::MachineLearning {

struct WINRT_EBO IImageFeatureDescriptor :
    Windows::Foundation::IInspectable,
    impl::consume_t<IImageFeatureDescriptor>
{
    IImageFeatureDescriptor(std::nullptr_t = nullptr) noexcept {}
};

struct WINRT_EBO IImageFeatureValue :
    Windows::Foundation::IInspectable,
    impl::consume_t<IImageFeatureValue>
{
    IImageFeatureValue(std::nullptr_t = nullptr) noexcept {}
};

struct WINRT_EBO IImageFeatureValueStatics :
    Windows::Foundation::IInspectable,
    impl::consume_t<IImageFeatureValueStatics>
{
    IImageFeatureValueStatics(std::nullptr_t = nullptr) noexcept {}
};

struct WINRT_EBO ILearningModel :
    Windows::Foundation::IInspectable,
    impl::consume_t<ILearningModel>
{
    ILearningModel(std::nullptr_t = nullptr) noexcept {}
};

struct WINRT_EBO ILearningModelBinding :
    Windows::Foundation::IInspectable,
    impl::consume_t<ILearningModelBinding>
{
    ILearningModelBinding(std::nullptr_t = nullptr) noexcept {}
};

struct WINRT_EBO ILearningModelBindingFactory :
    Windows::Foundation::IInspectable,
    impl::consume_t<ILearningModelBindingFactory>
{
    ILearningModelBindingFactory(std::nullptr_t = nullptr) noexcept {}
};

struct WINRT_EBO ILearningModelDevice :
    Windows::Foundation::IInspectable,
    impl::consume_t<ILearningModelDevice>
{
    ILearningModelDevice(std::nullptr_t = nullptr) noexcept {}
};

struct WINRT_EBO ILearningModelDeviceFactory :
    Windows::Foundation::IInspectable,
    impl::consume_t<ILearningModelDeviceFactory>
{
    ILearningModelDeviceFactory(std::nullptr_t = nullptr) noexcept {}
};

struct WINRT_EBO ILearningModelDeviceStatics :
    Windows::Foundation::IInspectable,
    impl::consume_t<ILearningModelDeviceStatics>
{
    ILearningModelDeviceStatics(std::nullptr_t = nullptr) noexcept {}
};

struct WINRT_EBO ILearningModelEvaluationResult :
    Windows::Foundation::IInspectable,
    impl::consume_t<ILearningModelEvaluationResult>
{
    ILearningModelEvaluationResult(std::nullptr_t = nullptr) noexcept {}
};

struct WINRT_EBO ILearningModelFeatureDescriptor :
    Windows::Foundation::IInspectable,
    impl::consume_t<ILearningModelFeatureDescriptor>
{
    ILearningModelFeatureDescriptor(std::nullptr_t = nullptr) noexcept {}
};

struct WINRT_EBO ILearningModelFeatureValue :
    Windows::Foundation::IInspectable,
    impl::consume_t<ILearningModelFeatureValue>
{
    ILearningModelFeatureValue(std::nullptr_t = nullptr) noexcept {}
};

struct WINRT_EBO ILearningModelOperatorProvider :
    Windows::Foundation::IInspectable,
    impl::consume_t<ILearningModelOperatorProvider>
{
    ILearningModelOperatorProvider(std::nullptr_t = nullptr) noexcept {}
};

struct WINRT_EBO ILearningModelSession :
    Windows::Foundation::IInspectable,
    impl::consume_t<ILearningModelSession>
{
    ILearningModelSession(std::nullptr_t = nullptr) noexcept {}
};

struct WINRT_EBO ILearningModelSessionFactory :
    Windows::Foundation::IInspectable,
    impl::consume_t<ILearningModelSessionFactory>
{
    ILearningModelSessionFactory(std::nullptr_t = nullptr) noexcept {}
};

struct WINRT_EBO ILearningModelSessionFactory2 :
    Windows::Foundation::IInspectable,
    impl::consume_t<ILearningModelSessionFactory2>
{
    ILearningModelSessionFactory2(std::nullptr_t = nullptr) noexcept {}
};

struct WINRT_EBO ILearningModelSessionOptions :
    Windows::Foundation::IInspectable,
    impl::consume_t<ILearningModelSessionOptions>
{
    ILearningModelSessionOptions(std::nullptr_t = nullptr) noexcept {}
};

struct WINRT_EBO ILearningModelStatics :
    Windows::Foundation::IInspectable,
    impl::consume_t<ILearningModelStatics>
{
    ILearningModelStatics(std::nullptr_t = nullptr) noexcept {}
};

struct WINRT_EBO IMapFeatureDescriptor :
    Windows::Foundation::IInspectable,
    impl::consume_t<IMapFeatureDescriptor>
{
    IMapFeatureDescriptor(std::nullptr_t = nullptr) noexcept {}
};

struct WINRT_EBO ISequenceFeatureDescriptor :
    Windows::Foundation::IInspectable,
    impl::consume_t<ISequenceFeatureDescriptor>
{
    ISequenceFeatureDescriptor(std::nullptr_t = nullptr) noexcept {}
};

struct WINRT_EBO ITensor :
    Windows::Foundation::IInspectable,
    impl::consume_t<ITensor>,
    impl::require<ITensor, Windows::AI::MachineLearning::ILearningModelFeatureValue>
{
    ITensor(std::nullptr_t = nullptr) noexcept {}
};

struct WINRT_EBO ITensorBoolean :
    Windows::Foundation::IInspectable,
    impl::consume_t<ITensorBoolean>
{
    ITensorBoolean(std::nullptr_t = nullptr) noexcept {}
};

struct WINRT_EBO ITensorBooleanStatics :
    Windows::Foundation::IInspectable,
    impl::consume_t<ITensorBooleanStatics>
{
    ITensorBooleanStatics(std::nullptr_t = nullptr) noexcept {}
};

struct WINRT_EBO ITensorBooleanStatics2 :
    Windows::Foundation::IInspectable,
    impl::consume_t<ITensorBooleanStatics2>
{
    ITensorBooleanStatics2(std::nullptr_t = nullptr) noexcept {}
};

struct WINRT_EBO ITensorDouble :
    Windows::Foundation::IInspectable,
    impl::consume_t<ITensorDouble>
{
    ITensorDouble(std::nullptr_t = nullptr) noexcept {}
};

struct WINRT_EBO ITensorDoubleStatics :
    Windows::Foundation::IInspectable,
    impl::consume_t<ITensorDoubleStatics>
{
    ITensorDoubleStatics(std::nullptr_t = nullptr) noexcept {}
};

struct WINRT_EBO ITensorDoubleStatics2 :
    Windows::Foundation::IInspectable,
    impl::consume_t<ITensorDoubleStatics2>
{
    ITensorDoubleStatics2(std::nullptr_t = nullptr) noexcept {}
};

struct WINRT_EBO ITensorFeatureDescriptor :
    Windows::Foundation::IInspectable,
    impl::consume_t<ITensorFeatureDescriptor>
{
    ITensorFeatureDescriptor(std::nullptr_t = nullptr) noexcept {}
};

struct WINRT_EBO ITensorFloat :
    Windows::Foundation::IInspectable,
    impl::consume_t<ITensorFloat>
{
    ITensorFloat(std::nullptr_t = nullptr) noexcept {}
};

struct WINRT_EBO ITensorFloat16Bit :
    Windows::Foundation::IInspectable,
    impl::consume_t<ITensorFloat16Bit>
{
    ITensorFloat16Bit(std::nullptr_t = nullptr) noexcept {}
};

struct WINRT_EBO ITensorFloat16BitStatics :
    Windows::Foundation::IInspectable,
    impl::consume_t<ITensorFloat16BitStatics>
{
    ITensorFloat16BitStatics(std::nullptr_t = nullptr) noexcept {}
};

struct WINRT_EBO ITensorFloat16BitStatics2 :
    Windows::Foundation::IInspectable,
    impl::consume_t<ITensorFloat16BitStatics2>
{
    ITensorFloat16BitStatics2(std::nullptr_t = nullptr) noexcept {}
};

struct WINRT_EBO ITensorFloatStatics :
    Windows::Foundation::IInspectable,
    impl::consume_t<ITensorFloatStatics>
{
    ITensorFloatStatics(std::nullptr_t = nullptr) noexcept {}
};

struct WINRT_EBO ITensorFloatStatics2 :
    Windows::Foundation::IInspectable,
    impl::consume_t<ITensorFloatStatics2>
{
    ITensorFloatStatics2(std::nullptr_t = nullptr) noexcept {}
};

struct WINRT_EBO ITensorInt16Bit :
    Windows::Foundation::IInspectable,
    impl::consume_t<ITensorInt16Bit>
{
    ITensorInt16Bit(std::nullptr_t = nullptr) noexcept {}
};

struct WINRT_EBO ITensorInt16BitStatics :
    Windows::Foundation::IInspectable,
    impl::consume_t<ITensorInt16BitStatics>
{
    ITensorInt16BitStatics(std::nullptr_t = nullptr) noexcept {}
};

struct WINRT_EBO ITensorInt16BitStatics2 :
    Windows::Foundation::IInspectable,
    impl::consume_t<ITensorInt16BitStatics2>
{
    ITensorInt16BitStatics2(std::nullptr_t = nullptr) noexcept {}
};

struct WINRT_EBO ITensorInt32Bit :
    Windows::Foundation::IInspectable,
    impl::consume_t<ITensorInt32Bit>
{
    ITensorInt32Bit(std::nullptr_t = nullptr) noexcept {}
};

struct WINRT_EBO ITensorInt32BitStatics :
    Windows::Foundation::IInspectable,
    impl::consume_t<ITensorInt32BitStatics>
{
    ITensorInt32BitStatics(std::nullptr_t = nullptr) noexcept {}
};

struct WINRT_EBO ITensorInt32BitStatics2 :
    Windows::Foundation::IInspectable,
    impl::consume_t<ITensorInt32BitStatics2>
{
    ITensorInt32BitStatics2(std::nullptr_t = nullptr) noexcept {}
};

struct WINRT_EBO ITensorInt64Bit :
    Windows::Foundation::IInspectable,
    impl::consume_t<ITensorInt64Bit>
{
    ITensorInt64Bit(std::nullptr_t = nullptr) noexcept {}
};

struct WINRT_EBO ITensorInt64BitStatics :
    Windows::Foundation::IInspectable,
    impl::consume_t<ITensorInt64BitStatics>
{
    ITensorInt64BitStatics(std::nullptr_t = nullptr) noexcept {}
};

struct WINRT_EBO ITensorInt64BitStatics2 :
    Windows::Foundation::IInspectable,
    impl::consume_t<ITensorInt64BitStatics2>
{
    ITensorInt64BitStatics2(std::nullptr_t = nullptr) noexcept {}
};

struct WINRT_EBO ITensorInt8Bit :
    Windows::Foundation::IInspectable,
    impl::consume_t<ITensorInt8Bit>
{
    ITensorInt8Bit(std::nullptr_t = nullptr) noexcept {}
};

struct WINRT_EBO ITensorInt8BitStatics :
    Windows::Foundation::IInspectable,
    impl::consume_t<ITensorInt8BitStatics>
{
    ITensorInt8BitStatics(std::nullptr_t = nullptr) noexcept {}
};

struct WINRT_EBO ITensorInt8BitStatics2 :
    Windows::Foundation::IInspectable,
    impl::consume_t<ITensorInt8BitStatics2>
{
    ITensorInt8BitStatics2(std::nullptr_t = nullptr) noexcept {}
};

struct WINRT_EBO ITensorString :
    Windows::Foundation::IInspectable,
    impl::consume_t<ITensorString>
{
    ITensorString(std::nullptr_t = nullptr) noexcept {}
};

struct WINRT_EBO ITensorStringStatics :
    Windows::Foundation::IInspectable,
    impl::consume_t<ITensorStringStatics>
{
    ITensorStringStatics(std::nullptr_t = nullptr) noexcept {}
};

struct WINRT_EBO ITensorStringStatics2 :
    Windows::Foundation::IInspectable,
    impl::consume_t<ITensorStringStatics2>
{
    ITensorStringStatics2(std::nullptr_t = nullptr) noexcept {}
};

struct WINRT_EBO ITensorUInt16Bit :
    Windows::Foundation::IInspectable,
    impl::consume_t<ITensorUInt16Bit>
{
    ITensorUInt16Bit(std::nullptr_t = nullptr) noexcept {}
};

struct WINRT_EBO ITensorUInt16BitStatics :
    Windows::Foundation::IInspectable,
    impl::consume_t<ITensorUInt16BitStatics>
{
    ITensorUInt16BitStatics(std::nullptr_t = nullptr) noexcept {}
};

struct WINRT_EBO ITensorUInt16BitStatics2 :
    Windows::Foundation::IInspectable,
    impl::consume_t<ITensorUInt16BitStatics2>
{
    ITensorUInt16BitStatics2(std::nullptr_t = nullptr) noexcept {}
};

struct WINRT_EBO ITensorUInt32Bit :
    Windows::Foundation::IInspectable,
    impl::consume_t<ITensorUInt32Bit>
{
    ITensorUInt32Bit(std::nullptr_t = nullptr) noexcept {}
};

struct WINRT_EBO ITensorUInt32BitStatics :
    Windows::Foundation::IInspectable,
    impl::consume_t<ITensorUInt32BitStatics>
{
    ITensorUInt32BitStatics(std::nullptr_t = nullptr) noexcept {}
};

struct WINRT_EBO ITensorUInt32BitStatics2 :
    Windows::Foundation::IInspectable,
    impl::consume_t<ITensorUInt32BitStatics2>
{
    ITensorUInt32BitStatics2(std::nullptr_t = nullptr) noexcept {}
};

struct WINRT_EBO ITensorUInt64Bit :
    Windows::Foundation::IInspectable,
    impl::consume_t<ITensorUInt64Bit>
{
    ITensorUInt64Bit(std::nullptr_t = nullptr) noexcept {}
};

struct WINRT_EBO ITensorUInt64BitStatics :
    Windows::Foundation::IInspectable,
    impl::consume_t<ITensorUInt64BitStatics>
{
    ITensorUInt64BitStatics(std::nullptr_t = nullptr) noexcept {}
};

struct WINRT_EBO ITensorUInt64BitStatics2 :
    Windows::Foundation::IInspectable,
    impl::consume_t<ITensorUInt64BitStatics2>
{
    ITensorUInt64BitStatics2(std::nullptr_t = nullptr) noexcept {}
};

struct WINRT_EBO ITensorUInt8Bit :
    Windows::Foundation::IInspectable,
    impl::consume_t<ITensorUInt8Bit>
{
    ITensorUInt8Bit(std::nullptr_t = nullptr) noexcept {}
};

struct WINRT_EBO ITensorUInt8BitStatics :
    Windows::Foundation::IInspectable,
    impl::consume_t<ITensorUInt8BitStatics>
{
    ITensorUInt8BitStatics(std::nullptr_t = nullptr) noexcept {}
};

struct WINRT_EBO ITensorUInt8BitStatics2 :
    Windows::Foundation::IInspectable,
    impl::consume_t<ITensorUInt8BitStatics2>
{
    ITensorUInt8BitStatics2(std::nullptr_t = nullptr) noexcept {}
};

}
