// C++/WinRT v1.0.190111.3

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#pragma once
#include "winrt/impl/Windows.Foundation.Collections.0.h"
#include "winrt/impl/Windows.Graphics.Imaging.0.h"
#include "winrt/impl/Windows.Storage.0.h"
#include "winrt/impl/Windows.Storage.Streams.0.h"
#include "winrt/impl/Windows.Foundation.Collections.0.h"
#include "winrt/impl/Windows.AI.MachineLearning.Preview.0.h"

WINRT_EXPORT namespace winrt::Windows::AI::MachineLearning::Preview {

struct WINRT_EBO IImageVariableDescriptorPreview :
    Windows::Foundation::IInspectable,
    impl::consume_t<IImageVariableDescriptorPreview>,
    impl::require<IImageVariableDescriptorPreview, Windows::AI::MachineLearning::Preview::ILearningModelVariableDescriptorPreview>
{
    IImageVariableDescriptorPreview(std::nullptr_t = nullptr) noexcept {}
};

struct WINRT_EBO IInferencingOptionsPreview :
    Windows::Foundation::IInspectable,
    impl::consume_t<IInferencingOptionsPreview>
{
    IInferencingOptionsPreview(std::nullptr_t = nullptr) noexcept {}
};

struct WINRT_EBO ILearningModelBindingPreview :
    Windows::Foundation::IInspectable,
    impl::consume_t<ILearningModelBindingPreview>,
    impl::require<ILearningModelBindingPreview, Windows::Foundation::Collections::IIterable<Windows::Foundation::Collections::IKeyValuePair<hstring, Windows::Foundation::IInspectable>>, Windows::Foundation::Collections::IMapView<hstring, Windows::Foundation::IInspectable>>
{
    ILearningModelBindingPreview(std::nullptr_t = nullptr) noexcept {}
};

struct WINRT_EBO ILearningModelBindingPreviewFactory :
    Windows::Foundation::IInspectable,
    impl::consume_t<ILearningModelBindingPreviewFactory>
{
    ILearningModelBindingPreviewFactory(std::nullptr_t = nullptr) noexcept {}
};

struct WINRT_EBO ILearningModelDescriptionPreview :
    Windows::Foundation::IInspectable,
    impl::consume_t<ILearningModelDescriptionPreview>
{
    ILearningModelDescriptionPreview(std::nullptr_t = nullptr) noexcept {}
};

struct WINRT_EBO ILearningModelEvaluationResultPreview :
    Windows::Foundation::IInspectable,
    impl::consume_t<ILearningModelEvaluationResultPreview>
{
    ILearningModelEvaluationResultPreview(std::nullptr_t = nullptr) noexcept {}
};

struct WINRT_EBO ILearningModelPreview :
    Windows::Foundation::IInspectable,
    impl::consume_t<ILearningModelPreview>
{
    ILearningModelPreview(std::nullptr_t = nullptr) noexcept {}
};

struct WINRT_EBO ILearningModelPreviewStatics :
    Windows::Foundation::IInspectable,
    impl::consume_t<ILearningModelPreviewStatics>
{
    ILearningModelPreviewStatics(std::nullptr_t = nullptr) noexcept {}
};

struct WINRT_EBO ILearningModelVariableDescriptorPreview :
    Windows::Foundation::IInspectable,
    impl::consume_t<ILearningModelVariableDescriptorPreview>
{
    ILearningModelVariableDescriptorPreview(std::nullptr_t = nullptr) noexcept {}
};

struct WINRT_EBO IMapVariableDescriptorPreview :
    Windows::Foundation::IInspectable,
    impl::consume_t<IMapVariableDescriptorPreview>,
    impl::require<IMapVariableDescriptorPreview, Windows::AI::MachineLearning::Preview::ILearningModelVariableDescriptorPreview>
{
    IMapVariableDescriptorPreview(std::nullptr_t = nullptr) noexcept {}
};

struct WINRT_EBO ISequenceVariableDescriptorPreview :
    Windows::Foundation::IInspectable,
    impl::consume_t<ISequenceVariableDescriptorPreview>,
    impl::require<ISequenceVariableDescriptorPreview, Windows::AI::MachineLearning::Preview::ILearningModelVariableDescriptorPreview>
{
    ISequenceVariableDescriptorPreview(std::nullptr_t = nullptr) noexcept {}
};

struct WINRT_EBO ITensorVariableDescriptorPreview :
    Windows::Foundation::IInspectable,
    impl::consume_t<ITensorVariableDescriptorPreview>,
    impl::require<ITensorVariableDescriptorPreview, Windows::AI::MachineLearning::Preview::ILearningModelVariableDescriptorPreview>
{
    ITensorVariableDescriptorPreview(std::nullptr_t = nullptr) noexcept {}
};

}
