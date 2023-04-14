// C++/WinRT v1.0.190111.3

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#pragma once

WINRT_EXPORT namespace winrt::Windows::Foundation::Collections {

struct IPropertySet;

}

WINRT_EXPORT namespace winrt::Windows::Graphics::Imaging {

enum class BitmapPixelFormat;

}

WINRT_EXPORT namespace winrt::Windows::Storage {

struct IStorageFile;

}

WINRT_EXPORT namespace winrt::Windows::Storage::Streams {

struct IRandomAccessStreamReference;

}

WINRT_EXPORT namespace winrt::Windows::AI::MachineLearning::Preview {

enum class FeatureElementKindPreview : int32_t
{
    Undefined = 0,
    Float = 1,
    UInt8 = 2,
    Int8 = 3,
    UInt16 = 4,
    Int16 = 5,
    Int32 = 6,
    Int64 = 7,
    String = 8,
    Boolean = 9,
    Float16 = 10,
    Double = 11,
    UInt32 = 12,
    UInt64 = 13,
    Complex64 = 14,
    Complex128 = 15,
};

enum class LearningModelDeviceKindPreview : int32_t
{
    LearningDeviceAny = 0,
    LearningDeviceCpu = 1,
    LearningDeviceGpu = 2,
    LearningDeviceNpu = 3,
    LearningDeviceDsp = 4,
    LearningDeviceFpga = 5,
};

enum class LearningModelFeatureKindPreview : int32_t
{
    Undefined = 0,
    Tensor = 1,
    Sequence = 2,
    Map = 3,
    Image = 4,
};

struct IImageVariableDescriptorPreview;
struct IInferencingOptionsPreview;
struct ILearningModelBindingPreview;
struct ILearningModelBindingPreviewFactory;
struct ILearningModelDescriptionPreview;
struct ILearningModelEvaluationResultPreview;
struct ILearningModelPreview;
struct ILearningModelPreviewStatics;
struct ILearningModelVariableDescriptorPreview;
struct IMapVariableDescriptorPreview;
struct ISequenceVariableDescriptorPreview;
struct ITensorVariableDescriptorPreview;
struct ImageVariableDescriptorPreview;
struct InferencingOptionsPreview;
struct LearningModelBindingPreview;
struct LearningModelDescriptionPreview;
struct LearningModelEvaluationResultPreview;
struct LearningModelPreview;
struct LearningModelVariableDescriptorPreview;
struct MapVariableDescriptorPreview;
struct SequenceVariableDescriptorPreview;
struct TensorVariableDescriptorPreview;

}

namespace winrt::impl {

template <> struct category<Windows::AI::MachineLearning::Preview::IImageVariableDescriptorPreview>{ using type = interface_category; };
template <> struct category<Windows::AI::MachineLearning::Preview::IInferencingOptionsPreview>{ using type = interface_category; };
template <> struct category<Windows::AI::MachineLearning::Preview::ILearningModelBindingPreview>{ using type = interface_category; };
template <> struct category<Windows::AI::MachineLearning::Preview::ILearningModelBindingPreviewFactory>{ using type = interface_category; };
template <> struct category<Windows::AI::MachineLearning::Preview::ILearningModelDescriptionPreview>{ using type = interface_category; };
template <> struct category<Windows::AI::MachineLearning::Preview::ILearningModelEvaluationResultPreview>{ using type = interface_category; };
template <> struct category<Windows::AI::MachineLearning::Preview::ILearningModelPreview>{ using type = interface_category; };
template <> struct category<Windows::AI::MachineLearning::Preview::ILearningModelPreviewStatics>{ using type = interface_category; };
template <> struct category<Windows::AI::MachineLearning::Preview::ILearningModelVariableDescriptorPreview>{ using type = interface_category; };
template <> struct category<Windows::AI::MachineLearning::Preview::IMapVariableDescriptorPreview>{ using type = interface_category; };
template <> struct category<Windows::AI::MachineLearning::Preview::ISequenceVariableDescriptorPreview>{ using type = interface_category; };
template <> struct category<Windows::AI::MachineLearning::Preview::ITensorVariableDescriptorPreview>{ using type = interface_category; };
template <> struct category<Windows::AI::MachineLearning::Preview::ImageVariableDescriptorPreview>{ using type = class_category; };
template <> struct category<Windows::AI::MachineLearning::Preview::InferencingOptionsPreview>{ using type = class_category; };
template <> struct category<Windows::AI::MachineLearning::Preview::LearningModelBindingPreview>{ using type = class_category; };
template <> struct category<Windows::AI::MachineLearning::Preview::LearningModelDescriptionPreview>{ using type = class_category; };
template <> struct category<Windows::AI::MachineLearning::Preview::LearningModelEvaluationResultPreview>{ using type = class_category; };
template <> struct category<Windows::AI::MachineLearning::Preview::LearningModelPreview>{ using type = class_category; };
template <> struct category<Windows::AI::MachineLearning::Preview::LearningModelVariableDescriptorPreview>{ using type = class_category; };
template <> struct category<Windows::AI::MachineLearning::Preview::MapVariableDescriptorPreview>{ using type = class_category; };
template <> struct category<Windows::AI::MachineLearning::Preview::SequenceVariableDescriptorPreview>{ using type = class_category; };
template <> struct category<Windows::AI::MachineLearning::Preview::TensorVariableDescriptorPreview>{ using type = class_category; };
template <> struct category<Windows::AI::MachineLearning::Preview::FeatureElementKindPreview>{ using type = enum_category; };
template <> struct category<Windows::AI::MachineLearning::Preview::LearningModelDeviceKindPreview>{ using type = enum_category; };
template <> struct category<Windows::AI::MachineLearning::Preview::LearningModelFeatureKindPreview>{ using type = enum_category; };
template <> struct name<Windows::AI::MachineLearning::Preview::IImageVariableDescriptorPreview>{ static constexpr auto & value{ L"Windows.AI.MachineLearning.Preview.IImageVariableDescriptorPreview" }; };
template <> struct name<Windows::AI::MachineLearning::Preview::IInferencingOptionsPreview>{ static constexpr auto & value{ L"Windows.AI.MachineLearning.Preview.IInferencingOptionsPreview" }; };
template <> struct name<Windows::AI::MachineLearning::Preview::ILearningModelBindingPreview>{ static constexpr auto & value{ L"Windows.AI.MachineLearning.Preview.ILearningModelBindingPreview" }; };
template <> struct name<Windows::AI::MachineLearning::Preview::ILearningModelBindingPreviewFactory>{ static constexpr auto & value{ L"Windows.AI.MachineLearning.Preview.ILearningModelBindingPreviewFactory" }; };
template <> struct name<Windows::AI::MachineLearning::Preview::ILearningModelDescriptionPreview>{ static constexpr auto & value{ L"Windows.AI.MachineLearning.Preview.ILearningModelDescriptionPreview" }; };
template <> struct name<Windows::AI::MachineLearning::Preview::ILearningModelEvaluationResultPreview>{ static constexpr auto & value{ L"Windows.AI.MachineLearning.Preview.ILearningModelEvaluationResultPreview" }; };
template <> struct name<Windows::AI::MachineLearning::Preview::ILearningModelPreview>{ static constexpr auto & value{ L"Windows.AI.MachineLearning.Preview.ILearningModelPreview" }; };
template <> struct name<Windows::AI::MachineLearning::Preview::ILearningModelPreviewStatics>{ static constexpr auto & value{ L"Windows.AI.MachineLearning.Preview.ILearningModelPreviewStatics" }; };
template <> struct name<Windows::AI::MachineLearning::Preview::ILearningModelVariableDescriptorPreview>{ static constexpr auto & value{ L"Windows.AI.MachineLearning.Preview.ILearningModelVariableDescriptorPreview" }; };
template <> struct name<Windows::AI::MachineLearning::Preview::IMapVariableDescriptorPreview>{ static constexpr auto & value{ L"Windows.AI.MachineLearning.Preview.IMapVariableDescriptorPreview" }; };
template <> struct name<Windows::AI::MachineLearning::Preview::ISequenceVariableDescriptorPreview>{ static constexpr auto & value{ L"Windows.AI.MachineLearning.Preview.ISequenceVariableDescriptorPreview" }; };
template <> struct name<Windows::AI::MachineLearning::Preview::ITensorVariableDescriptorPreview>{ static constexpr auto & value{ L"Windows.AI.MachineLearning.Preview.ITensorVariableDescriptorPreview" }; };
template <> struct name<Windows::AI::MachineLearning::Preview::ImageVariableDescriptorPreview>{ static constexpr auto & value{ L"Windows.AI.MachineLearning.Preview.ImageVariableDescriptorPreview" }; };
template <> struct name<Windows::AI::MachineLearning::Preview::InferencingOptionsPreview>{ static constexpr auto & value{ L"Windows.AI.MachineLearning.Preview.InferencingOptionsPreview" }; };
template <> struct name<Windows::AI::MachineLearning::Preview::LearningModelBindingPreview>{ static constexpr auto & value{ L"Windows.AI.MachineLearning.Preview.LearningModelBindingPreview" }; };
template <> struct name<Windows::AI::MachineLearning::Preview::LearningModelDescriptionPreview>{ static constexpr auto & value{ L"Windows.AI.MachineLearning.Preview.LearningModelDescriptionPreview" }; };
template <> struct name<Windows::AI::MachineLearning::Preview::LearningModelEvaluationResultPreview>{ static constexpr auto & value{ L"Windows.AI.MachineLearning.Preview.LearningModelEvaluationResultPreview" }; };
template <> struct name<Windows::AI::MachineLearning::Preview::LearningModelPreview>{ static constexpr auto & value{ L"Windows.AI.MachineLearning.Preview.LearningModelPreview" }; };
template <> struct name<Windows::AI::MachineLearning::Preview::LearningModelVariableDescriptorPreview>{ static constexpr auto & value{ L"Windows.AI.MachineLearning.Preview.LearningModelVariableDescriptorPreview" }; };
template <> struct name<Windows::AI::MachineLearning::Preview::MapVariableDescriptorPreview>{ static constexpr auto & value{ L"Windows.AI.MachineLearning.Preview.MapVariableDescriptorPreview" }; };
template <> struct name<Windows::AI::MachineLearning::Preview::SequenceVariableDescriptorPreview>{ static constexpr auto & value{ L"Windows.AI.MachineLearning.Preview.SequenceVariableDescriptorPreview" }; };
template <> struct name<Windows::AI::MachineLearning::Preview::TensorVariableDescriptorPreview>{ static constexpr auto & value{ L"Windows.AI.MachineLearning.Preview.TensorVariableDescriptorPreview" }; };
template <> struct name<Windows::AI::MachineLearning::Preview::FeatureElementKindPreview>{ static constexpr auto & value{ L"Windows.AI.MachineLearning.Preview.FeatureElementKindPreview" }; };
template <> struct name<Windows::AI::MachineLearning::Preview::LearningModelDeviceKindPreview>{ static constexpr auto & value{ L"Windows.AI.MachineLearning.Preview.LearningModelDeviceKindPreview" }; };
template <> struct name<Windows::AI::MachineLearning::Preview::LearningModelFeatureKindPreview>{ static constexpr auto & value{ L"Windows.AI.MachineLearning.Preview.LearningModelFeatureKindPreview" }; };
template <> struct guid_storage<Windows::AI::MachineLearning::Preview::IImageVariableDescriptorPreview>{ static constexpr guid value{ 0x7AE1FA72,0x029E,0x4DC5,{ 0xA2,0xF8,0x5F,0xB7,0x63,0x15,0x41,0x50 } }; };
template <> struct guid_storage<Windows::AI::MachineLearning::Preview::IInferencingOptionsPreview>{ static constexpr guid value{ 0x47BC8205,0x4D36,0x47A9,{ 0x8F,0x68,0xFF,0xCB,0x33,0x9D,0xD0,0xFC } }; };
template <> struct guid_storage<Windows::AI::MachineLearning::Preview::ILearningModelBindingPreview>{ static constexpr guid value{ 0x93C901E8,0x6C78,0x4B4F,{ 0xAE,0xC1,0xA6,0xBB,0x9E,0x69,0x16,0x24 } }; };
template <> struct guid_storage<Windows::AI::MachineLearning::Preview::ILearningModelBindingPreviewFactory>{ static constexpr guid value{ 0x48B8219F,0x1E51,0x4D77,{ 0xAE,0x50,0x3E,0xC1,0x64,0xAD,0x34,0x80 } }; };
template <> struct guid_storage<Windows::AI::MachineLearning::Preview::ILearningModelDescriptionPreview>{ static constexpr guid value{ 0xF52C09C6,0x8611,0x40AD,{ 0x8E,0x59,0xDE,0x3F,0xD7,0x03,0x0A,0x40 } }; };
template <> struct guid_storage<Windows::AI::MachineLearning::Preview::ILearningModelEvaluationResultPreview>{ static constexpr guid value{ 0xDF25EA9F,0x9863,0x4088,{ 0x84,0x98,0x87,0xA1,0xF4,0x68,0x6F,0x92 } }; };
template <> struct guid_storage<Windows::AI::MachineLearning::Preview::ILearningModelPreview>{ static constexpr guid value{ 0x049C266A,0x93B4,0x478C,{ 0xAE,0xB8,0x70,0x15,0x7B,0xF0,0xFF,0x94 } }; };
template <> struct guid_storage<Windows::AI::MachineLearning::Preview::ILearningModelPreviewStatics>{ static constexpr guid value{ 0x164BBB60,0x8465,0x4786,{ 0x8B,0x93,0x2C,0x16,0xA8,0x92,0x89,0xD7 } }; };
template <> struct guid_storage<Windows::AI::MachineLearning::Preview::ILearningModelVariableDescriptorPreview>{ static constexpr guid value{ 0xB13DF682,0xFC30,0x492B,{ 0x8E,0xA0,0xED,0x1F,0x53,0xC0,0xB0,0x38 } }; };
template <> struct guid_storage<Windows::AI::MachineLearning::Preview::IMapVariableDescriptorPreview>{ static constexpr guid value{ 0x3CB38370,0xC02B,0x4236,{ 0xB3,0xE8,0x6B,0xDC,0xA4,0x9C,0x31,0x29 } }; };
template <> struct guid_storage<Windows::AI::MachineLearning::Preview::ISequenceVariableDescriptorPreview>{ static constexpr guid value{ 0x9CD8F292,0x98B2,0x4530,{ 0xA1,0xB6,0x2D,0xED,0x5F,0xEC,0xBC,0x26 } }; };
template <> struct guid_storage<Windows::AI::MachineLearning::Preview::ITensorVariableDescriptorPreview>{ static constexpr guid value{ 0xA80F501A,0x9AAC,0x4233,{ 0x97,0x84,0xAC,0xEA,0xF9,0x25,0x10,0xB5 } }; };
template <> struct default_interface<Windows::AI::MachineLearning::Preview::ImageVariableDescriptorPreview>{ using type = Windows::AI::MachineLearning::Preview::IImageVariableDescriptorPreview; };
template <> struct default_interface<Windows::AI::MachineLearning::Preview::InferencingOptionsPreview>{ using type = Windows::AI::MachineLearning::Preview::IInferencingOptionsPreview; };
template <> struct default_interface<Windows::AI::MachineLearning::Preview::LearningModelBindingPreview>{ using type = Windows::AI::MachineLearning::Preview::ILearningModelBindingPreview; };
template <> struct default_interface<Windows::AI::MachineLearning::Preview::LearningModelDescriptionPreview>{ using type = Windows::AI::MachineLearning::Preview::ILearningModelDescriptionPreview; };
template <> struct default_interface<Windows::AI::MachineLearning::Preview::LearningModelEvaluationResultPreview>{ using type = Windows::AI::MachineLearning::Preview::ILearningModelEvaluationResultPreview; };
template <> struct default_interface<Windows::AI::MachineLearning::Preview::LearningModelPreview>{ using type = Windows::AI::MachineLearning::Preview::ILearningModelPreview; };
template <> struct default_interface<Windows::AI::MachineLearning::Preview::LearningModelVariableDescriptorPreview>{ using type = Windows::AI::MachineLearning::Preview::ILearningModelVariableDescriptorPreview; };
template <> struct default_interface<Windows::AI::MachineLearning::Preview::MapVariableDescriptorPreview>{ using type = Windows::AI::MachineLearning::Preview::IMapVariableDescriptorPreview; };
template <> struct default_interface<Windows::AI::MachineLearning::Preview::SequenceVariableDescriptorPreview>{ using type = Windows::AI::MachineLearning::Preview::ISequenceVariableDescriptorPreview; };
template <> struct default_interface<Windows::AI::MachineLearning::Preview::TensorVariableDescriptorPreview>{ using type = Windows::AI::MachineLearning::Preview::ITensorVariableDescriptorPreview; };

template <> struct abi<Windows::AI::MachineLearning::Preview::IImageVariableDescriptorPreview>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL get_BitmapPixelFormat(Windows::Graphics::Imaging::BitmapPixelFormat* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_Width(uint32_t* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_Height(uint32_t* value) noexcept = 0;
};};

template <> struct abi<Windows::AI::MachineLearning::Preview::IInferencingOptionsPreview>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL get_PreferredDeviceKind(Windows::AI::MachineLearning::Preview::LearningModelDeviceKindPreview* value) noexcept = 0;
    virtual int32_t WINRT_CALL put_PreferredDeviceKind(Windows::AI::MachineLearning::Preview::LearningModelDeviceKindPreview value) noexcept = 0;
    virtual int32_t WINRT_CALL get_IsTracingEnabled(bool* value) noexcept = 0;
    virtual int32_t WINRT_CALL put_IsTracingEnabled(bool value) noexcept = 0;
    virtual int32_t WINRT_CALL get_MaxBatchSize(int32_t* value) noexcept = 0;
    virtual int32_t WINRT_CALL put_MaxBatchSize(int32_t value) noexcept = 0;
    virtual int32_t WINRT_CALL get_MinimizeMemoryAllocation(bool* value) noexcept = 0;
    virtual int32_t WINRT_CALL put_MinimizeMemoryAllocation(bool value) noexcept = 0;
    virtual int32_t WINRT_CALL get_ReclaimMemoryAfterEvaluation(bool* value) noexcept = 0;
    virtual int32_t WINRT_CALL put_ReclaimMemoryAfterEvaluation(bool value) noexcept = 0;
};};

template <> struct abi<Windows::AI::MachineLearning::Preview::ILearningModelBindingPreview>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL Bind(void* name, void* value) noexcept = 0;
    virtual int32_t WINRT_CALL BindWithProperties(void* name, void* value, void* metadata) noexcept = 0;
    virtual int32_t WINRT_CALL Clear() noexcept = 0;
};};

template <> struct abi<Windows::AI::MachineLearning::Preview::ILearningModelBindingPreviewFactory>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL CreateFromModel(void* model, void** value) noexcept = 0;
};};

template <> struct abi<Windows::AI::MachineLearning::Preview::ILearningModelDescriptionPreview>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL get_Author(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_Name(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_Domain(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_Description(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_Version(int64_t* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_Metadata(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_InputFeatures(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_OutputFeatures(void** value) noexcept = 0;
};};

template <> struct abi<Windows::AI::MachineLearning::Preview::ILearningModelEvaluationResultPreview>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL get_CorrelationId(void** correlationId) noexcept = 0;
    virtual int32_t WINRT_CALL get_Outputs(void** value) noexcept = 0;
};};

template <> struct abi<Windows::AI::MachineLearning::Preview::ILearningModelPreview>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL EvaluateAsync(void* binding, void* correlationId, void** evalOperation) noexcept = 0;
    virtual int32_t WINRT_CALL EvaluateFeaturesAsync(void* features, void* correlationId, void** evalOperation) noexcept = 0;
    virtual int32_t WINRT_CALL get_Description(void** returnValue) noexcept = 0;
    virtual int32_t WINRT_CALL get_InferencingOptions(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL put_InferencingOptions(void* value) noexcept = 0;
};};

template <> struct abi<Windows::AI::MachineLearning::Preview::ILearningModelPreviewStatics>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL LoadModelFromStorageFileAsync(void* modelFile, void** modelCreationOperation) noexcept = 0;
    virtual int32_t WINRT_CALL LoadModelFromStreamAsync(void* modelStream, void** modelCreationOperation) noexcept = 0;
};};

template <> struct abi<Windows::AI::MachineLearning::Preview::ILearningModelVariableDescriptorPreview>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL get_Name(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_Description(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_ModelFeatureKind(Windows::AI::MachineLearning::Preview::LearningModelFeatureKindPreview* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_IsRequired(bool* value) noexcept = 0;
};};

template <> struct abi<Windows::AI::MachineLearning::Preview::IMapVariableDescriptorPreview>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL get_KeyKind(Windows::AI::MachineLearning::Preview::FeatureElementKindPreview* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_ValidStringKeys(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_ValidIntegerKeys(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_Fields(void** value) noexcept = 0;
};};

template <> struct abi<Windows::AI::MachineLearning::Preview::ISequenceVariableDescriptorPreview>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL get_ElementType(void** value) noexcept = 0;
};};

template <> struct abi<Windows::AI::MachineLearning::Preview::ITensorVariableDescriptorPreview>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL get_DataType(Windows::AI::MachineLearning::Preview::FeatureElementKindPreview* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_Shape(void** value) noexcept = 0;
};};

template <typename D>
struct consume_Windows_AI_MachineLearning_Preview_IImageVariableDescriptorPreview
{
    Windows::Graphics::Imaging::BitmapPixelFormat BitmapPixelFormat() const;
    uint32_t Width() const;
    uint32_t Height() const;
};
template <> struct consume<Windows::AI::MachineLearning::Preview::IImageVariableDescriptorPreview> { template <typename D> using type = consume_Windows_AI_MachineLearning_Preview_IImageVariableDescriptorPreview<D>; };

template <typename D>
struct consume_Windows_AI_MachineLearning_Preview_IInferencingOptionsPreview
{
    Windows::AI::MachineLearning::Preview::LearningModelDeviceKindPreview PreferredDeviceKind() const;
    void PreferredDeviceKind(Windows::AI::MachineLearning::Preview::LearningModelDeviceKindPreview const& value) const;
    bool IsTracingEnabled() const;
    void IsTracingEnabled(bool value) const;
    int32_t MaxBatchSize() const;
    void MaxBatchSize(int32_t value) const;
    bool MinimizeMemoryAllocation() const;
    void MinimizeMemoryAllocation(bool value) const;
    bool ReclaimMemoryAfterEvaluation() const;
    void ReclaimMemoryAfterEvaluation(bool value) const;
};
template <> struct consume<Windows::AI::MachineLearning::Preview::IInferencingOptionsPreview> { template <typename D> using type = consume_Windows_AI_MachineLearning_Preview_IInferencingOptionsPreview<D>; };

template <typename D>
struct consume_Windows_AI_MachineLearning_Preview_ILearningModelBindingPreview
{
    void Bind(param::hstring const& name, Windows::Foundation::IInspectable const& value) const;
    void Bind(param::hstring const& name, Windows::Foundation::IInspectable const& value, Windows::Foundation::Collections::IPropertySet const& metadata) const;
    void Clear() const;
};
template <> struct consume<Windows::AI::MachineLearning::Preview::ILearningModelBindingPreview> { template <typename D> using type = consume_Windows_AI_MachineLearning_Preview_ILearningModelBindingPreview<D>; };

template <typename D>
struct consume_Windows_AI_MachineLearning_Preview_ILearningModelBindingPreviewFactory
{
    Windows::AI::MachineLearning::Preview::LearningModelBindingPreview CreateFromModel(Windows::AI::MachineLearning::Preview::LearningModelPreview const& model) const;
};
template <> struct consume<Windows::AI::MachineLearning::Preview::ILearningModelBindingPreviewFactory> { template <typename D> using type = consume_Windows_AI_MachineLearning_Preview_ILearningModelBindingPreviewFactory<D>; };

template <typename D>
struct consume_Windows_AI_MachineLearning_Preview_ILearningModelDescriptionPreview
{
    hstring Author() const;
    hstring Name() const;
    hstring Domain() const;
    hstring Description() const;
    int64_t Version() const;
    Windows::Foundation::Collections::IMapView<hstring, hstring> Metadata() const;
    Windows::Foundation::Collections::IIterable<Windows::AI::MachineLearning::Preview::ILearningModelVariableDescriptorPreview> InputFeatures() const;
    Windows::Foundation::Collections::IIterable<Windows::AI::MachineLearning::Preview::ILearningModelVariableDescriptorPreview> OutputFeatures() const;
};
template <> struct consume<Windows::AI::MachineLearning::Preview::ILearningModelDescriptionPreview> { template <typename D> using type = consume_Windows_AI_MachineLearning_Preview_ILearningModelDescriptionPreview<D>; };

template <typename D>
struct consume_Windows_AI_MachineLearning_Preview_ILearningModelEvaluationResultPreview
{
    hstring CorrelationId() const;
    Windows::Foundation::Collections::IMapView<hstring, Windows::Foundation::IInspectable> Outputs() const;
};
template <> struct consume<Windows::AI::MachineLearning::Preview::ILearningModelEvaluationResultPreview> { template <typename D> using type = consume_Windows_AI_MachineLearning_Preview_ILearningModelEvaluationResultPreview<D>; };

template <typename D>
struct consume_Windows_AI_MachineLearning_Preview_ILearningModelPreview
{
    Windows::Foundation::IAsyncOperation<Windows::AI::MachineLearning::Preview::LearningModelEvaluationResultPreview> EvaluateAsync(Windows::AI::MachineLearning::Preview::LearningModelBindingPreview const& binding, param::hstring const& correlationId) const;
    Windows::Foundation::IAsyncOperation<Windows::AI::MachineLearning::Preview::LearningModelEvaluationResultPreview> EvaluateFeaturesAsync(param::map<hstring, Windows::Foundation::IInspectable> const& features, param::hstring const& correlationId) const;
    Windows::AI::MachineLearning::Preview::LearningModelDescriptionPreview Description() const;
    Windows::AI::MachineLearning::Preview::InferencingOptionsPreview InferencingOptions() const;
    void InferencingOptions(Windows::AI::MachineLearning::Preview::InferencingOptionsPreview const& value) const;
};
template <> struct consume<Windows::AI::MachineLearning::Preview::ILearningModelPreview> { template <typename D> using type = consume_Windows_AI_MachineLearning_Preview_ILearningModelPreview<D>; };

template <typename D>
struct consume_Windows_AI_MachineLearning_Preview_ILearningModelPreviewStatics
{
    Windows::Foundation::IAsyncOperation<Windows::AI::MachineLearning::Preview::LearningModelPreview> LoadModelFromStorageFileAsync(Windows::Storage::IStorageFile const& modelFile) const;
    Windows::Foundation::IAsyncOperation<Windows::AI::MachineLearning::Preview::LearningModelPreview> LoadModelFromStreamAsync(Windows::Storage::Streams::IRandomAccessStreamReference const& modelStream) const;
};
template <> struct consume<Windows::AI::MachineLearning::Preview::ILearningModelPreviewStatics> { template <typename D> using type = consume_Windows_AI_MachineLearning_Preview_ILearningModelPreviewStatics<D>; };

template <typename D>
struct consume_Windows_AI_MachineLearning_Preview_ILearningModelVariableDescriptorPreview
{
    hstring Name() const;
    hstring Description() const;
    Windows::AI::MachineLearning::Preview::LearningModelFeatureKindPreview ModelFeatureKind() const;
    bool IsRequired() const;
};
template <> struct consume<Windows::AI::MachineLearning::Preview::ILearningModelVariableDescriptorPreview> { template <typename D> using type = consume_Windows_AI_MachineLearning_Preview_ILearningModelVariableDescriptorPreview<D>; };

template <typename D>
struct consume_Windows_AI_MachineLearning_Preview_IMapVariableDescriptorPreview
{
    Windows::AI::MachineLearning::Preview::FeatureElementKindPreview KeyKind() const;
    Windows::Foundation::Collections::IIterable<hstring> ValidStringKeys() const;
    Windows::Foundation::Collections::IIterable<int64_t> ValidIntegerKeys() const;
    Windows::AI::MachineLearning::Preview::ILearningModelVariableDescriptorPreview Fields() const;
};
template <> struct consume<Windows::AI::MachineLearning::Preview::IMapVariableDescriptorPreview> { template <typename D> using type = consume_Windows_AI_MachineLearning_Preview_IMapVariableDescriptorPreview<D>; };

template <typename D>
struct consume_Windows_AI_MachineLearning_Preview_ISequenceVariableDescriptorPreview
{
    Windows::AI::MachineLearning::Preview::ILearningModelVariableDescriptorPreview ElementType() const;
};
template <> struct consume<Windows::AI::MachineLearning::Preview::ISequenceVariableDescriptorPreview> { template <typename D> using type = consume_Windows_AI_MachineLearning_Preview_ISequenceVariableDescriptorPreview<D>; };

template <typename D>
struct consume_Windows_AI_MachineLearning_Preview_ITensorVariableDescriptorPreview
{
    Windows::AI::MachineLearning::Preview::FeatureElementKindPreview DataType() const;
    Windows::Foundation::Collections::IIterable<int64_t> Shape() const;
};
template <> struct consume<Windows::AI::MachineLearning::Preview::ITensorVariableDescriptorPreview> { template <typename D> using type = consume_Windows_AI_MachineLearning_Preview_ITensorVariableDescriptorPreview<D>; };

}
