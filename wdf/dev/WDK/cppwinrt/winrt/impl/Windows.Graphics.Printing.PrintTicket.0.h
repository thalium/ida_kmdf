// C++/WinRT v1.0.190111.3

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#pragma once

WINRT_EXPORT namespace winrt::Windows::Data::Xml::Dom {

struct IXmlNode;

}

WINRT_EXPORT namespace winrt::Windows::Graphics::Printing::PrintTicket {

enum class PrintTicketFeatureSelectionType : int32_t
{
    PickOne = 0,
    PickMany = 1,
};

enum class PrintTicketParameterDataType : int32_t
{
    Integer = 0,
    NumericString = 1,
    String = 2,
};

enum class PrintTicketValueType : int32_t
{
    Integer = 0,
    String = 1,
    Unknown = 2,
};

struct IPrintTicketCapabilities;
struct IPrintTicketFeature;
struct IPrintTicketOption;
struct IPrintTicketParameterDefinition;
struct IPrintTicketParameterInitializer;
struct IPrintTicketValue;
struct IWorkflowPrintTicket;
struct IWorkflowPrintTicketValidationResult;
struct PrintTicketCapabilities;
struct PrintTicketFeature;
struct PrintTicketOption;
struct PrintTicketParameterDefinition;
struct PrintTicketParameterInitializer;
struct PrintTicketValue;
struct WorkflowPrintTicket;
struct WorkflowPrintTicketValidationResult;

}

namespace winrt::impl {

template <> struct category<Windows::Graphics::Printing::PrintTicket::IPrintTicketCapabilities>{ using type = interface_category; };
template <> struct category<Windows::Graphics::Printing::PrintTicket::IPrintTicketFeature>{ using type = interface_category; };
template <> struct category<Windows::Graphics::Printing::PrintTicket::IPrintTicketOption>{ using type = interface_category; };
template <> struct category<Windows::Graphics::Printing::PrintTicket::IPrintTicketParameterDefinition>{ using type = interface_category; };
template <> struct category<Windows::Graphics::Printing::PrintTicket::IPrintTicketParameterInitializer>{ using type = interface_category; };
template <> struct category<Windows::Graphics::Printing::PrintTicket::IPrintTicketValue>{ using type = interface_category; };
template <> struct category<Windows::Graphics::Printing::PrintTicket::IWorkflowPrintTicket>{ using type = interface_category; };
template <> struct category<Windows::Graphics::Printing::PrintTicket::IWorkflowPrintTicketValidationResult>{ using type = interface_category; };
template <> struct category<Windows::Graphics::Printing::PrintTicket::PrintTicketCapabilities>{ using type = class_category; };
template <> struct category<Windows::Graphics::Printing::PrintTicket::PrintTicketFeature>{ using type = class_category; };
template <> struct category<Windows::Graphics::Printing::PrintTicket::PrintTicketOption>{ using type = class_category; };
template <> struct category<Windows::Graphics::Printing::PrintTicket::PrintTicketParameterDefinition>{ using type = class_category; };
template <> struct category<Windows::Graphics::Printing::PrintTicket::PrintTicketParameterInitializer>{ using type = class_category; };
template <> struct category<Windows::Graphics::Printing::PrintTicket::PrintTicketValue>{ using type = class_category; };
template <> struct category<Windows::Graphics::Printing::PrintTicket::WorkflowPrintTicket>{ using type = class_category; };
template <> struct category<Windows::Graphics::Printing::PrintTicket::WorkflowPrintTicketValidationResult>{ using type = class_category; };
template <> struct category<Windows::Graphics::Printing::PrintTicket::PrintTicketFeatureSelectionType>{ using type = enum_category; };
template <> struct category<Windows::Graphics::Printing::PrintTicket::PrintTicketParameterDataType>{ using type = enum_category; };
template <> struct category<Windows::Graphics::Printing::PrintTicket::PrintTicketValueType>{ using type = enum_category; };
template <> struct name<Windows::Graphics::Printing::PrintTicket::IPrintTicketCapabilities>{ static constexpr auto & value{ L"Windows.Graphics.Printing.PrintTicket.IPrintTicketCapabilities" }; };
template <> struct name<Windows::Graphics::Printing::PrintTicket::IPrintTicketFeature>{ static constexpr auto & value{ L"Windows.Graphics.Printing.PrintTicket.IPrintTicketFeature" }; };
template <> struct name<Windows::Graphics::Printing::PrintTicket::IPrintTicketOption>{ static constexpr auto & value{ L"Windows.Graphics.Printing.PrintTicket.IPrintTicketOption" }; };
template <> struct name<Windows::Graphics::Printing::PrintTicket::IPrintTicketParameterDefinition>{ static constexpr auto & value{ L"Windows.Graphics.Printing.PrintTicket.IPrintTicketParameterDefinition" }; };
template <> struct name<Windows::Graphics::Printing::PrintTicket::IPrintTicketParameterInitializer>{ static constexpr auto & value{ L"Windows.Graphics.Printing.PrintTicket.IPrintTicketParameterInitializer" }; };
template <> struct name<Windows::Graphics::Printing::PrintTicket::IPrintTicketValue>{ static constexpr auto & value{ L"Windows.Graphics.Printing.PrintTicket.IPrintTicketValue" }; };
template <> struct name<Windows::Graphics::Printing::PrintTicket::IWorkflowPrintTicket>{ static constexpr auto & value{ L"Windows.Graphics.Printing.PrintTicket.IWorkflowPrintTicket" }; };
template <> struct name<Windows::Graphics::Printing::PrintTicket::IWorkflowPrintTicketValidationResult>{ static constexpr auto & value{ L"Windows.Graphics.Printing.PrintTicket.IWorkflowPrintTicketValidationResult" }; };
template <> struct name<Windows::Graphics::Printing::PrintTicket::PrintTicketCapabilities>{ static constexpr auto & value{ L"Windows.Graphics.Printing.PrintTicket.PrintTicketCapabilities" }; };
template <> struct name<Windows::Graphics::Printing::PrintTicket::PrintTicketFeature>{ static constexpr auto & value{ L"Windows.Graphics.Printing.PrintTicket.PrintTicketFeature" }; };
template <> struct name<Windows::Graphics::Printing::PrintTicket::PrintTicketOption>{ static constexpr auto & value{ L"Windows.Graphics.Printing.PrintTicket.PrintTicketOption" }; };
template <> struct name<Windows::Graphics::Printing::PrintTicket::PrintTicketParameterDefinition>{ static constexpr auto & value{ L"Windows.Graphics.Printing.PrintTicket.PrintTicketParameterDefinition" }; };
template <> struct name<Windows::Graphics::Printing::PrintTicket::PrintTicketParameterInitializer>{ static constexpr auto & value{ L"Windows.Graphics.Printing.PrintTicket.PrintTicketParameterInitializer" }; };
template <> struct name<Windows::Graphics::Printing::PrintTicket::PrintTicketValue>{ static constexpr auto & value{ L"Windows.Graphics.Printing.PrintTicket.PrintTicketValue" }; };
template <> struct name<Windows::Graphics::Printing::PrintTicket::WorkflowPrintTicket>{ static constexpr auto & value{ L"Windows.Graphics.Printing.PrintTicket.WorkflowPrintTicket" }; };
template <> struct name<Windows::Graphics::Printing::PrintTicket::WorkflowPrintTicketValidationResult>{ static constexpr auto & value{ L"Windows.Graphics.Printing.PrintTicket.WorkflowPrintTicketValidationResult" }; };
template <> struct name<Windows::Graphics::Printing::PrintTicket::PrintTicketFeatureSelectionType>{ static constexpr auto & value{ L"Windows.Graphics.Printing.PrintTicket.PrintTicketFeatureSelectionType" }; };
template <> struct name<Windows::Graphics::Printing::PrintTicket::PrintTicketParameterDataType>{ static constexpr auto & value{ L"Windows.Graphics.Printing.PrintTicket.PrintTicketParameterDataType" }; };
template <> struct name<Windows::Graphics::Printing::PrintTicket::PrintTicketValueType>{ static constexpr auto & value{ L"Windows.Graphics.Printing.PrintTicket.PrintTicketValueType" }; };
template <> struct guid_storage<Windows::Graphics::Printing::PrintTicket::IPrintTicketCapabilities>{ static constexpr guid value{ 0x8C45508B,0xBBDC,0x4256,{ 0xA1,0x42,0x2F,0xD6,0x15,0xEC,0xB4,0x16 } }; };
template <> struct guid_storage<Windows::Graphics::Printing::PrintTicket::IPrintTicketFeature>{ static constexpr guid value{ 0xE7607D6A,0x59F5,0x4103,{ 0x88,0x58,0xB9,0x77,0x10,0x96,0x3D,0x39 } }; };
template <> struct guid_storage<Windows::Graphics::Printing::PrintTicket::IPrintTicketOption>{ static constexpr guid value{ 0xB086CF90,0xB367,0x4E4B,{ 0xBD,0x48,0x9C,0x78,0xA0,0xBB,0x31,0xCE } }; };
template <> struct guid_storage<Windows::Graphics::Printing::PrintTicket::IPrintTicketParameterDefinition>{ static constexpr guid value{ 0xD6BAB4E4,0x2962,0x4C01,{ 0xB7,0xF3,0x9A,0x92,0x94,0xEB,0x83,0x35 } }; };
template <> struct guid_storage<Windows::Graphics::Printing::PrintTicket::IPrintTicketParameterInitializer>{ static constexpr guid value{ 0x5E3335BB,0xA0A5,0x48B1,{ 0x9D,0x5C,0x07,0x11,0x6D,0xDC,0x59,0x7A } }; };
template <> struct guid_storage<Windows::Graphics::Printing::PrintTicket::IPrintTicketValue>{ static constexpr guid value{ 0x66B30A32,0x244D,0x4E22,{ 0xA9,0x8B,0xBB,0x3C,0xF1,0xF2,0xDD,0x91 } }; };
template <> struct guid_storage<Windows::Graphics::Printing::PrintTicket::IWorkflowPrintTicket>{ static constexpr guid value{ 0x41D52285,0x35E8,0x448E,{ 0xA8,0xC5,0xE4,0xB6,0xA2,0xCF,0x82,0x6C } }; };
template <> struct guid_storage<Windows::Graphics::Printing::PrintTicket::IWorkflowPrintTicketValidationResult>{ static constexpr guid value{ 0x0AD1F392,0xDA7B,0x4A36,{ 0xBF,0x36,0x6A,0x99,0xA6,0x2E,0x20,0x59 } }; };
template <> struct default_interface<Windows::Graphics::Printing::PrintTicket::PrintTicketCapabilities>{ using type = Windows::Graphics::Printing::PrintTicket::IPrintTicketCapabilities; };
template <> struct default_interface<Windows::Graphics::Printing::PrintTicket::PrintTicketFeature>{ using type = Windows::Graphics::Printing::PrintTicket::IPrintTicketFeature; };
template <> struct default_interface<Windows::Graphics::Printing::PrintTicket::PrintTicketOption>{ using type = Windows::Graphics::Printing::PrintTicket::IPrintTicketOption; };
template <> struct default_interface<Windows::Graphics::Printing::PrintTicket::PrintTicketParameterDefinition>{ using type = Windows::Graphics::Printing::PrintTicket::IPrintTicketParameterDefinition; };
template <> struct default_interface<Windows::Graphics::Printing::PrintTicket::PrintTicketParameterInitializer>{ using type = Windows::Graphics::Printing::PrintTicket::IPrintTicketParameterInitializer; };
template <> struct default_interface<Windows::Graphics::Printing::PrintTicket::PrintTicketValue>{ using type = Windows::Graphics::Printing::PrintTicket::IPrintTicketValue; };
template <> struct default_interface<Windows::Graphics::Printing::PrintTicket::WorkflowPrintTicket>{ using type = Windows::Graphics::Printing::PrintTicket::IWorkflowPrintTicket; };
template <> struct default_interface<Windows::Graphics::Printing::PrintTicket::WorkflowPrintTicketValidationResult>{ using type = Windows::Graphics::Printing::PrintTicket::IWorkflowPrintTicketValidationResult; };

template <> struct abi<Windows::Graphics::Printing::PrintTicket::IPrintTicketCapabilities>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL get_Name(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_XmlNamespace(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_XmlNode(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_DocumentBindingFeature(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_DocumentCollateFeature(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_DocumentDuplexFeature(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_DocumentHolePunchFeature(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_DocumentInputBinFeature(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_DocumentNUpFeature(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_DocumentStapleFeature(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_JobPasscodeFeature(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_PageBorderlessFeature(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_PageMediaSizeFeature(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_PageMediaTypeFeature(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_PageOrientationFeature(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_PageOutputColorFeature(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_PageOutputQualityFeature(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_PageResolutionFeature(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL GetFeature(void* name, void* xmlNamespace, void** result) noexcept = 0;
    virtual int32_t WINRT_CALL GetParameterDefinition(void* name, void* xmlNamespace, void** result) noexcept = 0;
};};

template <> struct abi<Windows::Graphics::Printing::PrintTicket::IPrintTicketFeature>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL get_Name(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_XmlNamespace(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_XmlNode(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_DisplayName(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL GetOption(void* name, void* xmlNamespace, void** result) noexcept = 0;
    virtual int32_t WINRT_CALL get_Options(void** result) noexcept = 0;
    virtual int32_t WINRT_CALL GetSelectedOption(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL SetSelectedOption(void* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_SelectionType(Windows::Graphics::Printing::PrintTicket::PrintTicketFeatureSelectionType* value) noexcept = 0;
};};

template <> struct abi<Windows::Graphics::Printing::PrintTicket::IPrintTicketOption>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL get_Name(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_XmlNamespace(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_XmlNode(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_DisplayName(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL GetPropertyNode(void* name, void* xmlNamespace, void** result) noexcept = 0;
    virtual int32_t WINRT_CALL GetScoredPropertyNode(void* name, void* xmlNamespace, void** result) noexcept = 0;
    virtual int32_t WINRT_CALL GetPropertyValue(void* name, void* xmlNamespace, void** result) noexcept = 0;
    virtual int32_t WINRT_CALL GetScoredPropertyValue(void* name, void* xmlNamespace, void** result) noexcept = 0;
};};

template <> struct abi<Windows::Graphics::Printing::PrintTicket::IPrintTicketParameterDefinition>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL get_Name(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_XmlNamespace(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_XmlNode(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_DataType(Windows::Graphics::Printing::PrintTicket::PrintTicketParameterDataType* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_UnitType(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_RangeMin(int32_t* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_RangeMax(int32_t* value) noexcept = 0;
};};

template <> struct abi<Windows::Graphics::Printing::PrintTicket::IPrintTicketParameterInitializer>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL get_Name(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_XmlNamespace(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_XmlNode(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL put_Value(void* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_Value(void** value) noexcept = 0;
};};

template <> struct abi<Windows::Graphics::Printing::PrintTicket::IPrintTicketValue>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL get_Type(Windows::Graphics::Printing::PrintTicket::PrintTicketValueType* value) noexcept = 0;
    virtual int32_t WINRT_CALL GetValueAsInteger(int32_t* value) noexcept = 0;
    virtual int32_t WINRT_CALL GetValueAsString(void** value) noexcept = 0;
};};

template <> struct abi<Windows::Graphics::Printing::PrintTicket::IWorkflowPrintTicket>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL get_Name(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_XmlNamespace(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_XmlNode(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL GetCapabilities(void** result) noexcept = 0;
    virtual int32_t WINRT_CALL get_DocumentBindingFeature(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_DocumentCollateFeature(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_DocumentDuplexFeature(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_DocumentHolePunchFeature(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_DocumentInputBinFeature(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_DocumentNUpFeature(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_DocumentStapleFeature(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_JobPasscodeFeature(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_PageBorderlessFeature(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_PageMediaSizeFeature(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_PageMediaTypeFeature(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_PageOrientationFeature(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_PageOutputColorFeature(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_PageOutputQualityFeature(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_PageResolutionFeature(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL GetFeature(void* name, void* xmlNamespace, void** result) noexcept = 0;
    virtual int32_t WINRT_CALL NotifyXmlChangedAsync(void** operation) noexcept = 0;
    virtual int32_t WINRT_CALL ValidateAsync(void** operation) noexcept = 0;
    virtual int32_t WINRT_CALL GetParameterInitializer(void* name, void* xmlNamespace, void** result) noexcept = 0;
    virtual int32_t WINRT_CALL SetParameterInitializerAsInteger(void* name, void* xmlNamespace, int32_t integerValue, void** result) noexcept = 0;
    virtual int32_t WINRT_CALL SetParameterInitializerAsString(void* name, void* xmlNamespace, void* stringValue, void** result) noexcept = 0;
    virtual int32_t WINRT_CALL MergeAndValidateTicket(void* deltaShemaTicket, void** result) noexcept = 0;
};};

template <> struct abi<Windows::Graphics::Printing::PrintTicket::IWorkflowPrintTicketValidationResult>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL get_Validated(bool* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_ExtendedError(winrt::hresult* value) noexcept = 0;
};};

template <typename D>
struct consume_Windows_Graphics_Printing_PrintTicket_IPrintTicketCapabilities
{
    hstring Name() const;
    hstring XmlNamespace() const;
    Windows::Data::Xml::Dom::IXmlNode XmlNode() const;
    Windows::Graphics::Printing::PrintTicket::PrintTicketFeature DocumentBindingFeature() const;
    Windows::Graphics::Printing::PrintTicket::PrintTicketFeature DocumentCollateFeature() const;
    Windows::Graphics::Printing::PrintTicket::PrintTicketFeature DocumentDuplexFeature() const;
    Windows::Graphics::Printing::PrintTicket::PrintTicketFeature DocumentHolePunchFeature() const;
    Windows::Graphics::Printing::PrintTicket::PrintTicketFeature DocumentInputBinFeature() const;
    Windows::Graphics::Printing::PrintTicket::PrintTicketFeature DocumentNUpFeature() const;
    Windows::Graphics::Printing::PrintTicket::PrintTicketFeature DocumentStapleFeature() const;
    Windows::Graphics::Printing::PrintTicket::PrintTicketFeature JobPasscodeFeature() const;
    Windows::Graphics::Printing::PrintTicket::PrintTicketFeature PageBorderlessFeature() const;
    Windows::Graphics::Printing::PrintTicket::PrintTicketFeature PageMediaSizeFeature() const;
    Windows::Graphics::Printing::PrintTicket::PrintTicketFeature PageMediaTypeFeature() const;
    Windows::Graphics::Printing::PrintTicket::PrintTicketFeature PageOrientationFeature() const;
    Windows::Graphics::Printing::PrintTicket::PrintTicketFeature PageOutputColorFeature() const;
    Windows::Graphics::Printing::PrintTicket::PrintTicketFeature PageOutputQualityFeature() const;
    Windows::Graphics::Printing::PrintTicket::PrintTicketFeature PageResolutionFeature() const;
    Windows::Graphics::Printing::PrintTicket::PrintTicketFeature GetFeature(param::hstring const& name, param::hstring const& xmlNamespace) const;
    Windows::Graphics::Printing::PrintTicket::PrintTicketParameterDefinition GetParameterDefinition(param::hstring const& name, param::hstring const& xmlNamespace) const;
};
template <> struct consume<Windows::Graphics::Printing::PrintTicket::IPrintTicketCapabilities> { template <typename D> using type = consume_Windows_Graphics_Printing_PrintTicket_IPrintTicketCapabilities<D>; };

template <typename D>
struct consume_Windows_Graphics_Printing_PrintTicket_IPrintTicketFeature
{
    hstring Name() const;
    hstring XmlNamespace() const;
    Windows::Data::Xml::Dom::IXmlNode XmlNode() const;
    hstring DisplayName() const;
    Windows::Graphics::Printing::PrintTicket::PrintTicketOption GetOption(param::hstring const& name, param::hstring const& xmlNamespace) const;
    Windows::Foundation::Collections::IVectorView<Windows::Graphics::Printing::PrintTicket::PrintTicketOption> Options() const;
    Windows::Graphics::Printing::PrintTicket::PrintTicketOption GetSelectedOption() const;
    void SetSelectedOption(Windows::Graphics::Printing::PrintTicket::PrintTicketOption const& value) const;
    Windows::Graphics::Printing::PrintTicket::PrintTicketFeatureSelectionType SelectionType() const;
};
template <> struct consume<Windows::Graphics::Printing::PrintTicket::IPrintTicketFeature> { template <typename D> using type = consume_Windows_Graphics_Printing_PrintTicket_IPrintTicketFeature<D>; };

template <typename D>
struct consume_Windows_Graphics_Printing_PrintTicket_IPrintTicketOption
{
    hstring Name() const;
    hstring XmlNamespace() const;
    Windows::Data::Xml::Dom::IXmlNode XmlNode() const;
    hstring DisplayName() const;
    Windows::Data::Xml::Dom::IXmlNode GetPropertyNode(param::hstring const& name, param::hstring const& xmlNamespace) const;
    Windows::Data::Xml::Dom::IXmlNode GetScoredPropertyNode(param::hstring const& name, param::hstring const& xmlNamespace) const;
    Windows::Graphics::Printing::PrintTicket::PrintTicketValue GetPropertyValue(param::hstring const& name, param::hstring const& xmlNamespace) const;
    Windows::Graphics::Printing::PrintTicket::PrintTicketValue GetScoredPropertyValue(param::hstring const& name, param::hstring const& xmlNamespace) const;
};
template <> struct consume<Windows::Graphics::Printing::PrintTicket::IPrintTicketOption> { template <typename D> using type = consume_Windows_Graphics_Printing_PrintTicket_IPrintTicketOption<D>; };

template <typename D>
struct consume_Windows_Graphics_Printing_PrintTicket_IPrintTicketParameterDefinition
{
    hstring Name() const;
    hstring XmlNamespace() const;
    Windows::Data::Xml::Dom::IXmlNode XmlNode() const;
    Windows::Graphics::Printing::PrintTicket::PrintTicketParameterDataType DataType() const;
    hstring UnitType() const;
    int32_t RangeMin() const;
    int32_t RangeMax() const;
};
template <> struct consume<Windows::Graphics::Printing::PrintTicket::IPrintTicketParameterDefinition> { template <typename D> using type = consume_Windows_Graphics_Printing_PrintTicket_IPrintTicketParameterDefinition<D>; };

template <typename D>
struct consume_Windows_Graphics_Printing_PrintTicket_IPrintTicketParameterInitializer
{
    hstring Name() const;
    hstring XmlNamespace() const;
    Windows::Data::Xml::Dom::IXmlNode XmlNode() const;
    void Value(Windows::Graphics::Printing::PrintTicket::PrintTicketValue const& value) const;
    Windows::Graphics::Printing::PrintTicket::PrintTicketValue Value() const;
};
template <> struct consume<Windows::Graphics::Printing::PrintTicket::IPrintTicketParameterInitializer> { template <typename D> using type = consume_Windows_Graphics_Printing_PrintTicket_IPrintTicketParameterInitializer<D>; };

template <typename D>
struct consume_Windows_Graphics_Printing_PrintTicket_IPrintTicketValue
{
    Windows::Graphics::Printing::PrintTicket::PrintTicketValueType Type() const;
    int32_t GetValueAsInteger() const;
    hstring GetValueAsString() const;
};
template <> struct consume<Windows::Graphics::Printing::PrintTicket::IPrintTicketValue> { template <typename D> using type = consume_Windows_Graphics_Printing_PrintTicket_IPrintTicketValue<D>; };

template <typename D>
struct consume_Windows_Graphics_Printing_PrintTicket_IWorkflowPrintTicket
{
    hstring Name() const;
    hstring XmlNamespace() const;
    Windows::Data::Xml::Dom::IXmlNode XmlNode() const;
    Windows::Graphics::Printing::PrintTicket::PrintTicketCapabilities GetCapabilities() const;
    Windows::Graphics::Printing::PrintTicket::PrintTicketFeature DocumentBindingFeature() const;
    Windows::Graphics::Printing::PrintTicket::PrintTicketFeature DocumentCollateFeature() const;
    Windows::Graphics::Printing::PrintTicket::PrintTicketFeature DocumentDuplexFeature() const;
    Windows::Graphics::Printing::PrintTicket::PrintTicketFeature DocumentHolePunchFeature() const;
    Windows::Graphics::Printing::PrintTicket::PrintTicketFeature DocumentInputBinFeature() const;
    Windows::Graphics::Printing::PrintTicket::PrintTicketFeature DocumentNUpFeature() const;
    Windows::Graphics::Printing::PrintTicket::PrintTicketFeature DocumentStapleFeature() const;
    Windows::Graphics::Printing::PrintTicket::PrintTicketFeature JobPasscodeFeature() const;
    Windows::Graphics::Printing::PrintTicket::PrintTicketFeature PageBorderlessFeature() const;
    Windows::Graphics::Printing::PrintTicket::PrintTicketFeature PageMediaSizeFeature() const;
    Windows::Graphics::Printing::PrintTicket::PrintTicketFeature PageMediaTypeFeature() const;
    Windows::Graphics::Printing::PrintTicket::PrintTicketFeature PageOrientationFeature() const;
    Windows::Graphics::Printing::PrintTicket::PrintTicketFeature PageOutputColorFeature() const;
    Windows::Graphics::Printing::PrintTicket::PrintTicketFeature PageOutputQualityFeature() const;
    Windows::Graphics::Printing::PrintTicket::PrintTicketFeature PageResolutionFeature() const;
    Windows::Graphics::Printing::PrintTicket::PrintTicketFeature GetFeature(param::hstring const& name, param::hstring const& xmlNamespace) const;
    Windows::Foundation::IAsyncAction NotifyXmlChangedAsync() const;
    Windows::Foundation::IAsyncOperation<Windows::Graphics::Printing::PrintTicket::WorkflowPrintTicketValidationResult> ValidateAsync() const;
    Windows::Graphics::Printing::PrintTicket::PrintTicketParameterInitializer GetParameterInitializer(param::hstring const& name, param::hstring const& xmlNamespace) const;
    Windows::Graphics::Printing::PrintTicket::PrintTicketParameterInitializer SetParameterInitializerAsInteger(param::hstring const& name, param::hstring const& xmlNamespace, int32_t integerValue) const;
    Windows::Graphics::Printing::PrintTicket::PrintTicketParameterInitializer SetParameterInitializerAsString(param::hstring const& name, param::hstring const& xmlNamespace, param::hstring const& stringValue) const;
    Windows::Graphics::Printing::PrintTicket::WorkflowPrintTicket MergeAndValidateTicket(Windows::Graphics::Printing::PrintTicket::WorkflowPrintTicket const& deltaShemaTicket) const;
};
template <> struct consume<Windows::Graphics::Printing::PrintTicket::IWorkflowPrintTicket> { template <typename D> using type = consume_Windows_Graphics_Printing_PrintTicket_IWorkflowPrintTicket<D>; };

template <typename D>
struct consume_Windows_Graphics_Printing_PrintTicket_IWorkflowPrintTicketValidationResult
{
    bool Validated() const;
    winrt::hresult ExtendedError() const;
};
template <> struct consume<Windows::Graphics::Printing::PrintTicket::IWorkflowPrintTicketValidationResult> { template <typename D> using type = consume_Windows_Graphics_Printing_PrintTicket_IWorkflowPrintTicketValidationResult<D>; };

}
