// C++/WinRT v1.0.190111.3

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#pragma once
#include "winrt/impl/Windows.Foundation.Collections.1.h"
#include "winrt/impl/Windows.Graphics.Imaging.1.h"
#include "winrt/impl/Windows.Storage.1.h"
#include "winrt/impl/Windows.Storage.Streams.1.h"
#include "winrt/impl/Windows.Foundation.Collections.1.h"
#include "winrt/impl/Windows.AI.MachineLearning.Preview.1.h"

WINRT_EXPORT namespace winrt::Windows::AI::MachineLearning::Preview {

}

namespace winrt::impl {

}

WINRT_EXPORT namespace winrt::Windows::AI::MachineLearning::Preview {

struct WINRT_EBO ImageVariableDescriptorPreview :
    Windows::AI::MachineLearning::Preview::IImageVariableDescriptorPreview
{
    ImageVariableDescriptorPreview(std::nullptr_t) noexcept {}
};

struct WINRT_EBO InferencingOptionsPreview :
    Windows::AI::MachineLearning::Preview::IInferencingOptionsPreview
{
    InferencingOptionsPreview(std::nullptr_t) noexcept {}
};

struct WINRT_EBO LearningModelBindingPreview :
    Windows::AI::MachineLearning::Preview::ILearningModelBindingPreview
{
    LearningModelBindingPreview(std::nullptr_t) noexcept {}
    LearningModelBindingPreview(Windows::AI::MachineLearning::Preview::LearningModelPreview const& model);
};

struct WINRT_EBO LearningModelDescriptionPreview :
    Windows::AI::MachineLearning::Preview::ILearningModelDescriptionPreview
{
    LearningModelDescriptionPreview(std::nullptr_t) noexcept {}
};

struct WINRT_EBO LearningModelEvaluationResultPreview :
    Windows::AI::MachineLearning::Preview::ILearningModelEvaluationResultPreview
{
    LearningModelEvaluationResultPreview(std::nullptr_t) noexcept {}
};

struct WINRT_EBO LearningModelPreview :
    Windows::AI::MachineLearning::Preview::ILearningModelPreview
{
    LearningModelPreview(std::nullptr_t) noexcept {}
    static Windows::Foundation::IAsyncOperation<Windows::AI::MachineLearning::Preview::LearningModelPreview> LoadModelFromStorageFileAsync(Windows::Storage::IStorageFile const& modelFile);
    static Windows::Foundation::IAsyncOperation<Windows::AI::MachineLearning::Preview::LearningModelPreview> LoadModelFromStreamAsync(Windows::Storage::Streams::IRandomAccessStreamReference const& modelStream);
};

struct WINRT_EBO LearningModelVariableDescriptorPreview :
    Windows::AI::MachineLearning::Preview::ILearningModelVariableDescriptorPreview
{
    LearningModelVariableDescriptorPreview(std::nullptr_t) noexcept {}
};

struct WINRT_EBO MapVariableDescriptorPreview :
    Windows::AI::MachineLearning::Preview::IMapVariableDescriptorPreview
{
    MapVariableDescriptorPreview(std::nullptr_t) noexcept {}
};

struct WINRT_EBO SequenceVariableDescriptorPreview :
    Windows::AI::MachineLearning::Preview::ISequenceVariableDescriptorPreview
{
    SequenceVariableDescriptorPreview(std::nullptr_t) noexcept {}
};

struct WINRT_EBO TensorVariableDescriptorPreview :
    Windows::AI::MachineLearning::Preview::ITensorVariableDescriptorPreview
{
    TensorVariableDescriptorPreview(std::nullptr_t) noexcept {}
};

}
