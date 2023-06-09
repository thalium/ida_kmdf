﻿// C++/WinRT v1.0.190111.3

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#pragma once

WINRT_EXPORT namespace winrt::Windows::Foundation {

struct Uri;

}

WINRT_EXPORT namespace winrt::Windows::Storage::Streams {

struct IRandomAccessStream;

}

WINRT_EXPORT namespace winrt::Windows::UI::Xaml {

struct DependencyObject;
struct DependencyProperty;
struct UIElement;

}

WINRT_EXPORT namespace winrt::Windows::UI::Xaml::Interop {

struct TypeName;

}

WINRT_EXPORT namespace winrt::Windows::UI::Xaml::Markup {

struct IComponentConnector;
struct IComponentConnector2;
struct IDataTemplateComponent;
struct IMarkupExtension;
struct IMarkupExtensionFactory;
struct IMarkupExtensionOverrides;
struct IXamlBinaryWriter;
struct IXamlBinaryWriterStatics;
struct IXamlBindScopeDiagnostics;
struct IXamlBindingHelper;
struct IXamlBindingHelperStatics;
struct IXamlMarkupHelper;
struct IXamlMarkupHelperStatics;
struct IXamlMember;
struct IXamlMetadataProvider;
struct IXamlReader;
struct IXamlReaderStatics;
struct IXamlType;
struct IXamlType2;
struct MarkupExtension;
struct XamlBinaryWriter;
struct XamlBindingHelper;
struct XamlMarkupHelper;
struct XamlReader;
struct XamlBinaryWriterErrorInformation;
struct XmlnsDefinition;

}

namespace winrt::impl {

template <> struct category<Windows::UI::Xaml::Markup::IComponentConnector>{ using type = interface_category; };
template <> struct category<Windows::UI::Xaml::Markup::IComponentConnector2>{ using type = interface_category; };
template <> struct category<Windows::UI::Xaml::Markup::IDataTemplateComponent>{ using type = interface_category; };
template <> struct category<Windows::UI::Xaml::Markup::IMarkupExtension>{ using type = interface_category; };
template <> struct category<Windows::UI::Xaml::Markup::IMarkupExtensionFactory>{ using type = interface_category; };
template <> struct category<Windows::UI::Xaml::Markup::IMarkupExtensionOverrides>{ using type = interface_category; };
template <> struct category<Windows::UI::Xaml::Markup::IXamlBinaryWriter>{ using type = interface_category; };
template <> struct category<Windows::UI::Xaml::Markup::IXamlBinaryWriterStatics>{ using type = interface_category; };
template <> struct category<Windows::UI::Xaml::Markup::IXamlBindScopeDiagnostics>{ using type = interface_category; };
template <> struct category<Windows::UI::Xaml::Markup::IXamlBindingHelper>{ using type = interface_category; };
template <> struct category<Windows::UI::Xaml::Markup::IXamlBindingHelperStatics>{ using type = interface_category; };
template <> struct category<Windows::UI::Xaml::Markup::IXamlMarkupHelper>{ using type = interface_category; };
template <> struct category<Windows::UI::Xaml::Markup::IXamlMarkupHelperStatics>{ using type = interface_category; };
template <> struct category<Windows::UI::Xaml::Markup::IXamlMember>{ using type = interface_category; };
template <> struct category<Windows::UI::Xaml::Markup::IXamlMetadataProvider>{ using type = interface_category; };
template <> struct category<Windows::UI::Xaml::Markup::IXamlReader>{ using type = interface_category; };
template <> struct category<Windows::UI::Xaml::Markup::IXamlReaderStatics>{ using type = interface_category; };
template <> struct category<Windows::UI::Xaml::Markup::IXamlType>{ using type = interface_category; };
template <> struct category<Windows::UI::Xaml::Markup::IXamlType2>{ using type = interface_category; };
template <> struct category<Windows::UI::Xaml::Markup::MarkupExtension>{ using type = class_category; };
template <> struct category<Windows::UI::Xaml::Markup::XamlBinaryWriter>{ using type = class_category; };
template <> struct category<Windows::UI::Xaml::Markup::XamlBindingHelper>{ using type = class_category; };
template <> struct category<Windows::UI::Xaml::Markup::XamlMarkupHelper>{ using type = class_category; };
template <> struct category<Windows::UI::Xaml::Markup::XamlReader>{ using type = class_category; };
template <> struct category<Windows::UI::Xaml::Markup::XamlBinaryWriterErrorInformation>{ using type = struct_category<uint32_t,uint32_t,uint32_t>; };
template <> struct category<Windows::UI::Xaml::Markup::XmlnsDefinition>{ using type = struct_category<hstring,hstring>; };
template <> struct name<Windows::UI::Xaml::Markup::IComponentConnector>{ static constexpr auto & value{ L"Windows.UI.Xaml.Markup.IComponentConnector" }; };
template <> struct name<Windows::UI::Xaml::Markup::IComponentConnector2>{ static constexpr auto & value{ L"Windows.UI.Xaml.Markup.IComponentConnector2" }; };
template <> struct name<Windows::UI::Xaml::Markup::IDataTemplateComponent>{ static constexpr auto & value{ L"Windows.UI.Xaml.Markup.IDataTemplateComponent" }; };
template <> struct name<Windows::UI::Xaml::Markup::IMarkupExtension>{ static constexpr auto & value{ L"Windows.UI.Xaml.Markup.IMarkupExtension" }; };
template <> struct name<Windows::UI::Xaml::Markup::IMarkupExtensionFactory>{ static constexpr auto & value{ L"Windows.UI.Xaml.Markup.IMarkupExtensionFactory" }; };
template <> struct name<Windows::UI::Xaml::Markup::IMarkupExtensionOverrides>{ static constexpr auto & value{ L"Windows.UI.Xaml.Markup.IMarkupExtensionOverrides" }; };
template <> struct name<Windows::UI::Xaml::Markup::IXamlBinaryWriter>{ static constexpr auto & value{ L"Windows.UI.Xaml.Markup.IXamlBinaryWriter" }; };
template <> struct name<Windows::UI::Xaml::Markup::IXamlBinaryWriterStatics>{ static constexpr auto & value{ L"Windows.UI.Xaml.Markup.IXamlBinaryWriterStatics" }; };
template <> struct name<Windows::UI::Xaml::Markup::IXamlBindScopeDiagnostics>{ static constexpr auto & value{ L"Windows.UI.Xaml.Markup.IXamlBindScopeDiagnostics" }; };
template <> struct name<Windows::UI::Xaml::Markup::IXamlBindingHelper>{ static constexpr auto & value{ L"Windows.UI.Xaml.Markup.IXamlBindingHelper" }; };
template <> struct name<Windows::UI::Xaml::Markup::IXamlBindingHelperStatics>{ static constexpr auto & value{ L"Windows.UI.Xaml.Markup.IXamlBindingHelperStatics" }; };
template <> struct name<Windows::UI::Xaml::Markup::IXamlMarkupHelper>{ static constexpr auto & value{ L"Windows.UI.Xaml.Markup.IXamlMarkupHelper" }; };
template <> struct name<Windows::UI::Xaml::Markup::IXamlMarkupHelperStatics>{ static constexpr auto & value{ L"Windows.UI.Xaml.Markup.IXamlMarkupHelperStatics" }; };
template <> struct name<Windows::UI::Xaml::Markup::IXamlMember>{ static constexpr auto & value{ L"Windows.UI.Xaml.Markup.IXamlMember" }; };
template <> struct name<Windows::UI::Xaml::Markup::IXamlMetadataProvider>{ static constexpr auto & value{ L"Windows.UI.Xaml.Markup.IXamlMetadataProvider" }; };
template <> struct name<Windows::UI::Xaml::Markup::IXamlReader>{ static constexpr auto & value{ L"Windows.UI.Xaml.Markup.IXamlReader" }; };
template <> struct name<Windows::UI::Xaml::Markup::IXamlReaderStatics>{ static constexpr auto & value{ L"Windows.UI.Xaml.Markup.IXamlReaderStatics" }; };
template <> struct name<Windows::UI::Xaml::Markup::IXamlType>{ static constexpr auto & value{ L"Windows.UI.Xaml.Markup.IXamlType" }; };
template <> struct name<Windows::UI::Xaml::Markup::IXamlType2>{ static constexpr auto & value{ L"Windows.UI.Xaml.Markup.IXamlType2" }; };
template <> struct name<Windows::UI::Xaml::Markup::MarkupExtension>{ static constexpr auto & value{ L"Windows.UI.Xaml.Markup.MarkupExtension" }; };
template <> struct name<Windows::UI::Xaml::Markup::XamlBinaryWriter>{ static constexpr auto & value{ L"Windows.UI.Xaml.Markup.XamlBinaryWriter" }; };
template <> struct name<Windows::UI::Xaml::Markup::XamlBindingHelper>{ static constexpr auto & value{ L"Windows.UI.Xaml.Markup.XamlBindingHelper" }; };
template <> struct name<Windows::UI::Xaml::Markup::XamlMarkupHelper>{ static constexpr auto & value{ L"Windows.UI.Xaml.Markup.XamlMarkupHelper" }; };
template <> struct name<Windows::UI::Xaml::Markup::XamlReader>{ static constexpr auto & value{ L"Windows.UI.Xaml.Markup.XamlReader" }; };
template <> struct name<Windows::UI::Xaml::Markup::XamlBinaryWriterErrorInformation>{ static constexpr auto & value{ L"Windows.UI.Xaml.Markup.XamlBinaryWriterErrorInformation" }; };
template <> struct name<Windows::UI::Xaml::Markup::XmlnsDefinition>{ static constexpr auto & value{ L"Windows.UI.Xaml.Markup.XmlnsDefinition" }; };
template <> struct guid_storage<Windows::UI::Xaml::Markup::IComponentConnector>{ static constexpr guid value{ 0xF6790987,0xE6E5,0x47F2,{ 0x92,0xC6,0xEC,0xCC,0xE4,0xBA,0x15,0x9A } }; };
template <> struct guid_storage<Windows::UI::Xaml::Markup::IComponentConnector2>{ static constexpr guid value{ 0xDC8F368B,0xECCC,0x498E,{ 0xB1,0x39,0x91,0x14,0x22,0x54,0xD7,0xAE } }; };
template <> struct guid_storage<Windows::UI::Xaml::Markup::IDataTemplateComponent>{ static constexpr guid value{ 0x08429DC8,0x8AB0,0x4747,{ 0xAA,0x9A,0xFE,0xAD,0xFC,0x8D,0xA8,0xE1 } }; };
template <> struct guid_storage<Windows::UI::Xaml::Markup::IMarkupExtension>{ static constexpr guid value{ 0x1EE3416D,0x562B,0x486E,{ 0x9E,0xE5,0x0F,0x0C,0xBC,0xC8,0x04,0x8C } }; };
template <> struct guid_storage<Windows::UI::Xaml::Markup::IMarkupExtensionFactory>{ static constexpr guid value{ 0x65329C05,0xFB5A,0x4567,{ 0x9D,0x55,0x5C,0xDF,0xBA,0xDA,0x27,0x39 } }; };
template <> struct guid_storage<Windows::UI::Xaml::Markup::IMarkupExtensionOverrides>{ static constexpr guid value{ 0x393779BF,0xB9C0,0x4FFB,{ 0xA5,0x7F,0x58,0xE7,0x35,0x6E,0x42,0x5F } }; };
template <> struct guid_storage<Windows::UI::Xaml::Markup::IXamlBinaryWriter>{ static constexpr guid value{ 0x829D2AD3,0x620A,0x46F6,{ 0x84,0x5D,0x43,0x6A,0x05,0x92,0x71,0x00 } }; };
template <> struct guid_storage<Windows::UI::Xaml::Markup::IXamlBinaryWriterStatics>{ static constexpr guid value{ 0x0D8ED07A,0x9B82,0x4AA8,{ 0xB6,0x8B,0x02,0x6F,0x2D,0xE1,0xCC,0x86 } }; };
template <> struct guid_storage<Windows::UI::Xaml::Markup::IXamlBindScopeDiagnostics>{ static constexpr guid value{ 0xF264A29D,0xBDED,0x43AA,{ 0xA5,0xB0,0x26,0xAC,0x21,0xA8,0x1E,0xB8 } }; };
template <> struct guid_storage<Windows::UI::Xaml::Markup::IXamlBindingHelper>{ static constexpr guid value{ 0xFAA6FB06,0x8AB9,0x4EF7,{ 0x8A,0xE7,0xFB,0xD3,0x0B,0xBF,0xD0,0x6D } }; };
template <> struct guid_storage<Windows::UI::Xaml::Markup::IXamlBindingHelperStatics>{ static constexpr guid value{ 0xF65CFB71,0xC80C,0x4FFA,{ 0x86,0xEE,0x55,0x87,0x54,0xEE,0x33,0x6D } }; };
template <> struct guid_storage<Windows::UI::Xaml::Markup::IXamlMarkupHelper>{ static constexpr guid value{ 0xD0E6673C,0x5342,0x44EF,{ 0x85,0xA7,0xED,0x32,0x7A,0x73,0x9D,0x9A } }; };
template <> struct guid_storage<Windows::UI::Xaml::Markup::IXamlMarkupHelperStatics>{ static constexpr guid value{ 0xC9BC3725,0xF34F,0x445C,{ 0x81,0xA2,0x6B,0x72,0xA5,0xE8,0xF0,0x72 } }; };
template <> struct guid_storage<Windows::UI::Xaml::Markup::IXamlMember>{ static constexpr guid value{ 0xC541F58C,0x43A9,0x4216,{ 0xB7,0x18,0xE0,0xB1,0x1B,0x14,0xE9,0x3E } }; };
template <> struct guid_storage<Windows::UI::Xaml::Markup::IXamlMetadataProvider>{ static constexpr guid value{ 0xB3765D69,0x68A5,0x4B32,{ 0x88,0x61,0xFD,0xB9,0x0C,0x1F,0x58,0x36 } }; };
template <> struct guid_storage<Windows::UI::Xaml::Markup::IXamlReader>{ static constexpr guid value{ 0x24374CF1,0xCCEB,0x48BF,{ 0xA5,0x14,0x41,0xB0,0x18,0x6F,0x84,0xC2 } }; };
template <> struct guid_storage<Windows::UI::Xaml::Markup::IXamlReaderStatics>{ static constexpr guid value{ 0x9891C6BD,0x534F,0x4955,{ 0xB8,0x5A,0x8A,0x8D,0xC0,0xDC,0xA6,0x02 } }; };
template <> struct guid_storage<Windows::UI::Xaml::Markup::IXamlType>{ static constexpr guid value{ 0x7920EAB1,0xA2E5,0x479A,{ 0xBD,0x50,0x6C,0xEF,0x3C,0x0B,0x49,0x70 } }; };
template <> struct guid_storage<Windows::UI::Xaml::Markup::IXamlType2>{ static constexpr guid value{ 0x9F0C6E3B,0x433B,0x56AD,{ 0x8F,0x69,0x78,0xA4,0xDD,0x3E,0x64,0xF9 } }; };
template <> struct default_interface<Windows::UI::Xaml::Markup::MarkupExtension>{ using type = Windows::UI::Xaml::Markup::IMarkupExtension; };
template <> struct default_interface<Windows::UI::Xaml::Markup::XamlBinaryWriter>{ using type = Windows::UI::Xaml::Markup::IXamlBinaryWriter; };
template <> struct default_interface<Windows::UI::Xaml::Markup::XamlBindingHelper>{ using type = Windows::UI::Xaml::Markup::IXamlBindingHelper; };
template <> struct default_interface<Windows::UI::Xaml::Markup::XamlMarkupHelper>{ using type = Windows::UI::Xaml::Markup::IXamlMarkupHelper; };
template <> struct default_interface<Windows::UI::Xaml::Markup::XamlReader>{ using type = Windows::UI::Xaml::Markup::IXamlReader; };

template <> struct abi<Windows::UI::Xaml::Markup::IComponentConnector>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL Connect(int32_t connectionId, void* target) noexcept = 0;
};};

template <> struct abi<Windows::UI::Xaml::Markup::IComponentConnector2>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL GetBindingConnector(int32_t connectionId, void* target, void** result) noexcept = 0;
};};

template <> struct abi<Windows::UI::Xaml::Markup::IDataTemplateComponent>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL Recycle() noexcept = 0;
    virtual int32_t WINRT_CALL ProcessBindings(void* item, int32_t itemIndex, int32_t phase, int32_t* nextPhase) noexcept = 0;
};};

template <> struct abi<Windows::UI::Xaml::Markup::IMarkupExtension>{ struct type : IInspectable
{
};};

template <> struct abi<Windows::UI::Xaml::Markup::IMarkupExtensionFactory>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL CreateInstance(void* baseInterface, void** innerInterface, void** value) noexcept = 0;
};};

template <> struct abi<Windows::UI::Xaml::Markup::IMarkupExtensionOverrides>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL ProvideValue(void** result) noexcept = 0;
};};

template <> struct abi<Windows::UI::Xaml::Markup::IXamlBinaryWriter>{ struct type : IInspectable
{
};};

template <> struct abi<Windows::UI::Xaml::Markup::IXamlBinaryWriterStatics>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL Write(void* inputStreams, void* outputStreams, void* xamlMetadataProvider, struct struct_Windows_UI_Xaml_Markup_XamlBinaryWriterErrorInformation* result) noexcept = 0;
};};

template <> struct abi<Windows::UI::Xaml::Markup::IXamlBindScopeDiagnostics>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL Disable(int32_t lineNumber, int32_t columnNumber) noexcept = 0;
};};

template <> struct abi<Windows::UI::Xaml::Markup::IXamlBindingHelper>{ struct type : IInspectable
{
};};

template <> struct abi<Windows::UI::Xaml::Markup::IXamlBindingHelperStatics>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL get_DataTemplateComponentProperty(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL GetDataTemplateComponent(void* element, void** result) noexcept = 0;
    virtual int32_t WINRT_CALL SetDataTemplateComponent(void* element, void* value) noexcept = 0;
    virtual int32_t WINRT_CALL SuspendRendering(void* target) noexcept = 0;
    virtual int32_t WINRT_CALL ResumeRendering(void* target) noexcept = 0;
    virtual int32_t WINRT_CALL ConvertValue(struct struct_Windows_UI_Xaml_Interop_TypeName type, void* value, void** result) noexcept = 0;
    virtual int32_t WINRT_CALL SetPropertyFromString(void* dependencyObject, void* propertyToSet, void* value) noexcept = 0;
    virtual int32_t WINRT_CALL SetPropertyFromBoolean(void* dependencyObject, void* propertyToSet, bool value) noexcept = 0;
    virtual int32_t WINRT_CALL SetPropertyFromChar16(void* dependencyObject, void* propertyToSet, char16_t value) noexcept = 0;
    virtual int32_t WINRT_CALL SetPropertyFromDateTime(void* dependencyObject, void* propertyToSet, Windows::Foundation::DateTime value) noexcept = 0;
    virtual int32_t WINRT_CALL SetPropertyFromDouble(void* dependencyObject, void* propertyToSet, double value) noexcept = 0;
    virtual int32_t WINRT_CALL SetPropertyFromInt32(void* dependencyObject, void* propertyToSet, int32_t value) noexcept = 0;
    virtual int32_t WINRT_CALL SetPropertyFromUInt32(void* dependencyObject, void* propertyToSet, uint32_t value) noexcept = 0;
    virtual int32_t WINRT_CALL SetPropertyFromInt64(void* dependencyObject, void* propertyToSet, int64_t value) noexcept = 0;
    virtual int32_t WINRT_CALL SetPropertyFromUInt64(void* dependencyObject, void* propertyToSet, uint64_t value) noexcept = 0;
    virtual int32_t WINRT_CALL SetPropertyFromSingle(void* dependencyObject, void* propertyToSet, float value) noexcept = 0;
    virtual int32_t WINRT_CALL SetPropertyFromPoint(void* dependencyObject, void* propertyToSet, Windows::Foundation::Point value) noexcept = 0;
    virtual int32_t WINRT_CALL SetPropertyFromRect(void* dependencyObject, void* propertyToSet, Windows::Foundation::Rect value) noexcept = 0;
    virtual int32_t WINRT_CALL SetPropertyFromSize(void* dependencyObject, void* propertyToSet, Windows::Foundation::Size value) noexcept = 0;
    virtual int32_t WINRT_CALL SetPropertyFromTimeSpan(void* dependencyObject, void* propertyToSet, Windows::Foundation::TimeSpan value) noexcept = 0;
    virtual int32_t WINRT_CALL SetPropertyFromByte(void* dependencyObject, void* propertyToSet, uint8_t value) noexcept = 0;
    virtual int32_t WINRT_CALL SetPropertyFromUri(void* dependencyObject, void* propertyToSet, void* value) noexcept = 0;
    virtual int32_t WINRT_CALL SetPropertyFromObject(void* dependencyObject, void* propertyToSet, void* value) noexcept = 0;
};};

template <> struct abi<Windows::UI::Xaml::Markup::IXamlMarkupHelper>{ struct type : IInspectable
{
};};

template <> struct abi<Windows::UI::Xaml::Markup::IXamlMarkupHelperStatics>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL UnloadObject(void* element) noexcept = 0;
};};

template <> struct abi<Windows::UI::Xaml::Markup::IXamlMember>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL get_IsAttachable(bool* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_IsDependencyProperty(bool* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_IsReadOnly(bool* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_Name(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_TargetType(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_Type(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL GetValue(void* instance, void** result) noexcept = 0;
    virtual int32_t WINRT_CALL SetValue(void* instance, void* value) noexcept = 0;
};};

template <> struct abi<Windows::UI::Xaml::Markup::IXamlMetadataProvider>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL GetXamlType(struct struct_Windows_UI_Xaml_Interop_TypeName type, void** result) noexcept = 0;
    virtual int32_t WINRT_CALL GetXamlTypeByFullName(void* fullName, void** result) noexcept = 0;
    virtual int32_t WINRT_CALL GetXmlnsDefinitions(uint32_t* __resultSize, struct struct_Windows_UI_Xaml_Markup_XmlnsDefinition** result) noexcept = 0;
};};

template <> struct abi<Windows::UI::Xaml::Markup::IXamlReader>{ struct type : IInspectable
{
};};

template <> struct abi<Windows::UI::Xaml::Markup::IXamlReaderStatics>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL Load(void* xaml, void** result) noexcept = 0;
    virtual int32_t WINRT_CALL LoadWithInitialTemplateValidation(void* xaml, void** result) noexcept = 0;
};};

template <> struct abi<Windows::UI::Xaml::Markup::IXamlType>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL get_BaseType(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_ContentProperty(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_FullName(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_IsArray(bool* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_IsCollection(bool* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_IsConstructible(bool* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_IsDictionary(bool* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_IsMarkupExtension(bool* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_IsBindable(bool* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_ItemType(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_KeyType(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_UnderlyingType(struct struct_Windows_UI_Xaml_Interop_TypeName* value) noexcept = 0;
    virtual int32_t WINRT_CALL ActivateInstance(void** result) noexcept = 0;
    virtual int32_t WINRT_CALL CreateFromString(void* value, void** result) noexcept = 0;
    virtual int32_t WINRT_CALL GetMember(void* name, void** result) noexcept = 0;
    virtual int32_t WINRT_CALL AddToVector(void* instance, void* value) noexcept = 0;
    virtual int32_t WINRT_CALL AddToMap(void* instance, void* key, void* value) noexcept = 0;
    virtual int32_t WINRT_CALL RunInitializer() noexcept = 0;
};};

template <> struct abi<Windows::UI::Xaml::Markup::IXamlType2>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL get_BoxedType(void** value) noexcept = 0;
};};

template <typename D>
struct consume_Windows_UI_Xaml_Markup_IComponentConnector
{
    void Connect(int32_t connectionId, Windows::Foundation::IInspectable const& target) const;
};
template <> struct consume<Windows::UI::Xaml::Markup::IComponentConnector> { template <typename D> using type = consume_Windows_UI_Xaml_Markup_IComponentConnector<D>; };

template <typename D>
struct consume_Windows_UI_Xaml_Markup_IComponentConnector2
{
    Windows::UI::Xaml::Markup::IComponentConnector GetBindingConnector(int32_t connectionId, Windows::Foundation::IInspectable const& target) const;
};
template <> struct consume<Windows::UI::Xaml::Markup::IComponentConnector2> { template <typename D> using type = consume_Windows_UI_Xaml_Markup_IComponentConnector2<D>; };

template <typename D>
struct consume_Windows_UI_Xaml_Markup_IDataTemplateComponent
{
    void Recycle() const;
    void ProcessBindings(Windows::Foundation::IInspectable const& item, int32_t itemIndex, int32_t phase, int32_t& nextPhase) const;
};
template <> struct consume<Windows::UI::Xaml::Markup::IDataTemplateComponent> { template <typename D> using type = consume_Windows_UI_Xaml_Markup_IDataTemplateComponent<D>; };

template <typename D>
struct consume_Windows_UI_Xaml_Markup_IMarkupExtension
{
};
template <> struct consume<Windows::UI::Xaml::Markup::IMarkupExtension> { template <typename D> using type = consume_Windows_UI_Xaml_Markup_IMarkupExtension<D>; };

template <typename D>
struct consume_Windows_UI_Xaml_Markup_IMarkupExtensionFactory
{
    Windows::UI::Xaml::Markup::MarkupExtension CreateInstance(Windows::Foundation::IInspectable const& baseInterface, Windows::Foundation::IInspectable& innerInterface) const;
};
template <> struct consume<Windows::UI::Xaml::Markup::IMarkupExtensionFactory> { template <typename D> using type = consume_Windows_UI_Xaml_Markup_IMarkupExtensionFactory<D>; };

template <typename D>
struct consume_Windows_UI_Xaml_Markup_IMarkupExtensionOverrides
{
    Windows::Foundation::IInspectable ProvideValue() const;
};
template <> struct consume<Windows::UI::Xaml::Markup::IMarkupExtensionOverrides> { template <typename D> using type = consume_Windows_UI_Xaml_Markup_IMarkupExtensionOverrides<D>; };

template <typename D>
struct consume_Windows_UI_Xaml_Markup_IXamlBinaryWriter
{
};
template <> struct consume<Windows::UI::Xaml::Markup::IXamlBinaryWriter> { template <typename D> using type = consume_Windows_UI_Xaml_Markup_IXamlBinaryWriter<D>; };

template <typename D>
struct consume_Windows_UI_Xaml_Markup_IXamlBinaryWriterStatics
{
    Windows::UI::Xaml::Markup::XamlBinaryWriterErrorInformation Write(param::vector<Windows::Storage::Streams::IRandomAccessStream> const& inputStreams, param::vector<Windows::Storage::Streams::IRandomAccessStream> const& outputStreams, Windows::UI::Xaml::Markup::IXamlMetadataProvider const& xamlMetadataProvider) const;
};
template <> struct consume<Windows::UI::Xaml::Markup::IXamlBinaryWriterStatics> { template <typename D> using type = consume_Windows_UI_Xaml_Markup_IXamlBinaryWriterStatics<D>; };

template <typename D>
struct consume_Windows_UI_Xaml_Markup_IXamlBindScopeDiagnostics
{
    void Disable(int32_t lineNumber, int32_t columnNumber) const;
};
template <> struct consume<Windows::UI::Xaml::Markup::IXamlBindScopeDiagnostics> { template <typename D> using type = consume_Windows_UI_Xaml_Markup_IXamlBindScopeDiagnostics<D>; };

template <typename D>
struct consume_Windows_UI_Xaml_Markup_IXamlBindingHelper
{
};
template <> struct consume<Windows::UI::Xaml::Markup::IXamlBindingHelper> { template <typename D> using type = consume_Windows_UI_Xaml_Markup_IXamlBindingHelper<D>; };

template <typename D>
struct consume_Windows_UI_Xaml_Markup_IXamlBindingHelperStatics
{
    Windows::UI::Xaml::DependencyProperty DataTemplateComponentProperty() const;
    Windows::UI::Xaml::Markup::IDataTemplateComponent GetDataTemplateComponent(Windows::UI::Xaml::DependencyObject const& element) const;
    void SetDataTemplateComponent(Windows::UI::Xaml::DependencyObject const& element, Windows::UI::Xaml::Markup::IDataTemplateComponent const& value) const;
    void SuspendRendering(Windows::UI::Xaml::UIElement const& target) const;
    void ResumeRendering(Windows::UI::Xaml::UIElement const& target) const;
    Windows::Foundation::IInspectable ConvertValue(Windows::UI::Xaml::Interop::TypeName const& type, Windows::Foundation::IInspectable const& value) const;
    void SetPropertyFromString(Windows::Foundation::IInspectable const& dependencyObject, Windows::UI::Xaml::DependencyProperty const& propertyToSet, param::hstring const& value) const;
    void SetPropertyFromBoolean(Windows::Foundation::IInspectable const& dependencyObject, Windows::UI::Xaml::DependencyProperty const& propertyToSet, bool value) const;
    void SetPropertyFromChar16(Windows::Foundation::IInspectable const& dependencyObject, Windows::UI::Xaml::DependencyProperty const& propertyToSet, char16_t value) const;
    void SetPropertyFromDateTime(Windows::Foundation::IInspectable const& dependencyObject, Windows::UI::Xaml::DependencyProperty const& propertyToSet, Windows::Foundation::DateTime const& value) const;
    void SetPropertyFromDouble(Windows::Foundation::IInspectable const& dependencyObject, Windows::UI::Xaml::DependencyProperty const& propertyToSet, double value) const;
    void SetPropertyFromInt32(Windows::Foundation::IInspectable const& dependencyObject, Windows::UI::Xaml::DependencyProperty const& propertyToSet, int32_t value) const;
    void SetPropertyFromUInt32(Windows::Foundation::IInspectable const& dependencyObject, Windows::UI::Xaml::DependencyProperty const& propertyToSet, uint32_t value) const;
    void SetPropertyFromInt64(Windows::Foundation::IInspectable const& dependencyObject, Windows::UI::Xaml::DependencyProperty const& propertyToSet, int64_t value) const;
    void SetPropertyFromUInt64(Windows::Foundation::IInspectable const& dependencyObject, Windows::UI::Xaml::DependencyProperty const& propertyToSet, uint64_t value) const;
    void SetPropertyFromSingle(Windows::Foundation::IInspectable const& dependencyObject, Windows::UI::Xaml::DependencyProperty const& propertyToSet, float value) const;
    void SetPropertyFromPoint(Windows::Foundation::IInspectable const& dependencyObject, Windows::UI::Xaml::DependencyProperty const& propertyToSet, Windows::Foundation::Point const& value) const;
    void SetPropertyFromRect(Windows::Foundation::IInspectable const& dependencyObject, Windows::UI::Xaml::DependencyProperty const& propertyToSet, Windows::Foundation::Rect const& value) const;
    void SetPropertyFromSize(Windows::Foundation::IInspectable const& dependencyObject, Windows::UI::Xaml::DependencyProperty const& propertyToSet, Windows::Foundation::Size const& value) const;
    void SetPropertyFromTimeSpan(Windows::Foundation::IInspectable const& dependencyObject, Windows::UI::Xaml::DependencyProperty const& propertyToSet, Windows::Foundation::TimeSpan const& value) const;
    void SetPropertyFromByte(Windows::Foundation::IInspectable const& dependencyObject, Windows::UI::Xaml::DependencyProperty const& propertyToSet, uint8_t value) const;
    void SetPropertyFromUri(Windows::Foundation::IInspectable const& dependencyObject, Windows::UI::Xaml::DependencyProperty const& propertyToSet, Windows::Foundation::Uri const& value) const;
    void SetPropertyFromObject(Windows::Foundation::IInspectable const& dependencyObject, Windows::UI::Xaml::DependencyProperty const& propertyToSet, Windows::Foundation::IInspectable const& value) const;
};
template <> struct consume<Windows::UI::Xaml::Markup::IXamlBindingHelperStatics> { template <typename D> using type = consume_Windows_UI_Xaml_Markup_IXamlBindingHelperStatics<D>; };

template <typename D>
struct consume_Windows_UI_Xaml_Markup_IXamlMarkupHelper
{
};
template <> struct consume<Windows::UI::Xaml::Markup::IXamlMarkupHelper> { template <typename D> using type = consume_Windows_UI_Xaml_Markup_IXamlMarkupHelper<D>; };

template <typename D>
struct consume_Windows_UI_Xaml_Markup_IXamlMarkupHelperStatics
{
    void UnloadObject(Windows::UI::Xaml::DependencyObject const& element) const;
};
template <> struct consume<Windows::UI::Xaml::Markup::IXamlMarkupHelperStatics> { template <typename D> using type = consume_Windows_UI_Xaml_Markup_IXamlMarkupHelperStatics<D>; };

template <typename D>
struct consume_Windows_UI_Xaml_Markup_IXamlMember
{
    bool IsAttachable() const;
    bool IsDependencyProperty() const;
    bool IsReadOnly() const;
    hstring Name() const;
    Windows::UI::Xaml::Markup::IXamlType TargetType() const;
    Windows::UI::Xaml::Markup::IXamlType Type() const;
    Windows::Foundation::IInspectable GetValue(Windows::Foundation::IInspectable const& instance) const;
    void SetValue(Windows::Foundation::IInspectable const& instance, Windows::Foundation::IInspectable const& value) const;
};
template <> struct consume<Windows::UI::Xaml::Markup::IXamlMember> { template <typename D> using type = consume_Windows_UI_Xaml_Markup_IXamlMember<D>; };

template <typename D>
struct consume_Windows_UI_Xaml_Markup_IXamlMetadataProvider
{
    Windows::UI::Xaml::Markup::IXamlType GetXamlType(Windows::UI::Xaml::Interop::TypeName const& type) const;
    Windows::UI::Xaml::Markup::IXamlType GetXamlType(param::hstring const& fullName) const;
    com_array<Windows::UI::Xaml::Markup::XmlnsDefinition> GetXmlnsDefinitions() const;
};
template <> struct consume<Windows::UI::Xaml::Markup::IXamlMetadataProvider> { template <typename D> using type = consume_Windows_UI_Xaml_Markup_IXamlMetadataProvider<D>; };

template <typename D>
struct consume_Windows_UI_Xaml_Markup_IXamlReader
{
};
template <> struct consume<Windows::UI::Xaml::Markup::IXamlReader> { template <typename D> using type = consume_Windows_UI_Xaml_Markup_IXamlReader<D>; };

template <typename D>
struct consume_Windows_UI_Xaml_Markup_IXamlReaderStatics
{
    Windows::Foundation::IInspectable Load(param::hstring const& xaml) const;
    Windows::Foundation::IInspectable LoadWithInitialTemplateValidation(param::hstring const& xaml) const;
};
template <> struct consume<Windows::UI::Xaml::Markup::IXamlReaderStatics> { template <typename D> using type = consume_Windows_UI_Xaml_Markup_IXamlReaderStatics<D>; };

template <typename D>
struct consume_Windows_UI_Xaml_Markup_IXamlType
{
    Windows::UI::Xaml::Markup::IXamlType BaseType() const;
    Windows::UI::Xaml::Markup::IXamlMember ContentProperty() const;
    hstring FullName() const;
    bool IsArray() const;
    bool IsCollection() const;
    bool IsConstructible() const;
    bool IsDictionary() const;
    bool IsMarkupExtension() const;
    bool IsBindable() const;
    Windows::UI::Xaml::Markup::IXamlType ItemType() const;
    Windows::UI::Xaml::Markup::IXamlType KeyType() const;
    Windows::UI::Xaml::Interop::TypeName UnderlyingType() const;
    Windows::Foundation::IInspectable ActivateInstance() const;
    Windows::Foundation::IInspectable CreateFromString(param::hstring const& value) const;
    Windows::UI::Xaml::Markup::IXamlMember GetMember(param::hstring const& name) const;
    void AddToVector(Windows::Foundation::IInspectable const& instance, Windows::Foundation::IInspectable const& value) const;
    void AddToMap(Windows::Foundation::IInspectable const& instance, Windows::Foundation::IInspectable const& key, Windows::Foundation::IInspectable const& value) const;
    void RunInitializer() const;
};
template <> struct consume<Windows::UI::Xaml::Markup::IXamlType> { template <typename D> using type = consume_Windows_UI_Xaml_Markup_IXamlType<D>; };

template <typename D>
struct consume_Windows_UI_Xaml_Markup_IXamlType2
{
    Windows::UI::Xaml::Markup::IXamlType BoxedType() const;
};
template <> struct consume<Windows::UI::Xaml::Markup::IXamlType2> { template <typename D> using type = consume_Windows_UI_Xaml_Markup_IXamlType2<D>; };

struct struct_Windows_UI_Xaml_Markup_XamlBinaryWriterErrorInformation
{
    uint32_t InputStreamIndex;
    uint32_t LineNumber;
    uint32_t LinePosition;
};
template <> struct abi<Windows::UI::Xaml::Markup::XamlBinaryWriterErrorInformation>{ using type = struct_Windows_UI_Xaml_Markup_XamlBinaryWriterErrorInformation; };


struct struct_Windows_UI_Xaml_Markup_XmlnsDefinition
{
    void* XmlNamespace;
    void* Namespace;
};
template <> struct abi<Windows::UI::Xaml::Markup::XmlnsDefinition>{ using type = struct_Windows_UI_Xaml_Markup_XmlnsDefinition; };


}
