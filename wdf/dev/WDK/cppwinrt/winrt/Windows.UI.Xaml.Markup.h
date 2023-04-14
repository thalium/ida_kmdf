// C++/WinRT v1.0.190111.3

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#pragma once

#include "winrt/base.h"

#include "winrt/Windows.Foundation.h"
#include "winrt/Windows.Foundation.Collections.h"
#include "winrt/impl/Windows.Foundation.2.h"
#include "winrt/impl/Windows.Storage.Streams.2.h"
#include "winrt/impl/Windows.UI.Xaml.2.h"
#include "winrt/impl/Windows.UI.Xaml.Interop.2.h"
#include "winrt/impl/Windows.UI.Xaml.Markup.2.h"
#include "winrt/Windows.UI.Xaml.h"

namespace winrt::impl {

template <typename D> void consume_Windows_UI_Xaml_Markup_IComponentConnector<D>::Connect(int32_t connectionId, Windows::Foundation::IInspectable const& target) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Markup::IComponentConnector)->Connect(connectionId, get_abi(target)));
}

template <typename D> Windows::UI::Xaml::Markup::IComponentConnector consume_Windows_UI_Xaml_Markup_IComponentConnector2<D>::GetBindingConnector(int32_t connectionId, Windows::Foundation::IInspectable const& target) const
{
    Windows::UI::Xaml::Markup::IComponentConnector result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Markup::IComponentConnector2)->GetBindingConnector(connectionId, get_abi(target), put_abi(result)));
    return result;
}

template <typename D> void consume_Windows_UI_Xaml_Markup_IDataTemplateComponent<D>::Recycle() const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Markup::IDataTemplateComponent)->Recycle());
}

template <typename D> void consume_Windows_UI_Xaml_Markup_IDataTemplateComponent<D>::ProcessBindings(Windows::Foundation::IInspectable const& item, int32_t itemIndex, int32_t phase, int32_t& nextPhase) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Markup::IDataTemplateComponent)->ProcessBindings(get_abi(item), itemIndex, phase, &nextPhase));
}

template <typename D> Windows::UI::Xaml::Markup::MarkupExtension consume_Windows_UI_Xaml_Markup_IMarkupExtensionFactory<D>::CreateInstance(Windows::Foundation::IInspectable const& baseInterface, Windows::Foundation::IInspectable& innerInterface) const
{
    Windows::UI::Xaml::Markup::MarkupExtension value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Markup::IMarkupExtensionFactory)->CreateInstance(get_abi(baseInterface), put_abi(innerInterface), put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::IInspectable consume_Windows_UI_Xaml_Markup_IMarkupExtensionOverrides<D>::ProvideValue() const
{
    Windows::Foundation::IInspectable result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Markup::IMarkupExtensionOverrides)->ProvideValue(put_abi(result)));
    return result;
}

template <typename D> Windows::UI::Xaml::Markup::XamlBinaryWriterErrorInformation consume_Windows_UI_Xaml_Markup_IXamlBinaryWriterStatics<D>::Write(param::vector<Windows::Storage::Streams::IRandomAccessStream> const& inputStreams, param::vector<Windows::Storage::Streams::IRandomAccessStream> const& outputStreams, Windows::UI::Xaml::Markup::IXamlMetadataProvider const& xamlMetadataProvider) const
{
    Windows::UI::Xaml::Markup::XamlBinaryWriterErrorInformation result{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Markup::IXamlBinaryWriterStatics)->Write(get_abi(inputStreams), get_abi(outputStreams), get_abi(xamlMetadataProvider), put_abi(result)));
    return result;
}

template <typename D> void consume_Windows_UI_Xaml_Markup_IXamlBindScopeDiagnostics<D>::Disable(int32_t lineNumber, int32_t columnNumber) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Markup::IXamlBindScopeDiagnostics)->Disable(lineNumber, columnNumber));
}

template <typename D> Windows::UI::Xaml::DependencyProperty consume_Windows_UI_Xaml_Markup_IXamlBindingHelperStatics<D>::DataTemplateComponentProperty() const
{
    Windows::UI::Xaml::DependencyProperty value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Markup::IXamlBindingHelperStatics)->get_DataTemplateComponentProperty(put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Xaml::Markup::IDataTemplateComponent consume_Windows_UI_Xaml_Markup_IXamlBindingHelperStatics<D>::GetDataTemplateComponent(Windows::UI::Xaml::DependencyObject const& element) const
{
    Windows::UI::Xaml::Markup::IDataTemplateComponent result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Markup::IXamlBindingHelperStatics)->GetDataTemplateComponent(get_abi(element), put_abi(result)));
    return result;
}

template <typename D> void consume_Windows_UI_Xaml_Markup_IXamlBindingHelperStatics<D>::SetDataTemplateComponent(Windows::UI::Xaml::DependencyObject const& element, Windows::UI::Xaml::Markup::IDataTemplateComponent const& value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Markup::IXamlBindingHelperStatics)->SetDataTemplateComponent(get_abi(element), get_abi(value)));
}

template <typename D> void consume_Windows_UI_Xaml_Markup_IXamlBindingHelperStatics<D>::SuspendRendering(Windows::UI::Xaml::UIElement const& target) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Markup::IXamlBindingHelperStatics)->SuspendRendering(get_abi(target)));
}

template <typename D> void consume_Windows_UI_Xaml_Markup_IXamlBindingHelperStatics<D>::ResumeRendering(Windows::UI::Xaml::UIElement const& target) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Markup::IXamlBindingHelperStatics)->ResumeRendering(get_abi(target)));
}

template <typename D> Windows::Foundation::IInspectable consume_Windows_UI_Xaml_Markup_IXamlBindingHelperStatics<D>::ConvertValue(Windows::UI::Xaml::Interop::TypeName const& type, Windows::Foundation::IInspectable const& value) const
{
    Windows::Foundation::IInspectable result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Markup::IXamlBindingHelperStatics)->ConvertValue(get_abi(type), get_abi(value), put_abi(result)));
    return result;
}

template <typename D> void consume_Windows_UI_Xaml_Markup_IXamlBindingHelperStatics<D>::SetPropertyFromString(Windows::Foundation::IInspectable const& dependencyObject, Windows::UI::Xaml::DependencyProperty const& propertyToSet, param::hstring const& value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Markup::IXamlBindingHelperStatics)->SetPropertyFromString(get_abi(dependencyObject), get_abi(propertyToSet), get_abi(value)));
}

template <typename D> void consume_Windows_UI_Xaml_Markup_IXamlBindingHelperStatics<D>::SetPropertyFromBoolean(Windows::Foundation::IInspectable const& dependencyObject, Windows::UI::Xaml::DependencyProperty const& propertyToSet, bool value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Markup::IXamlBindingHelperStatics)->SetPropertyFromBoolean(get_abi(dependencyObject), get_abi(propertyToSet), value));
}

template <typename D> void consume_Windows_UI_Xaml_Markup_IXamlBindingHelperStatics<D>::SetPropertyFromChar16(Windows::Foundation::IInspectable const& dependencyObject, Windows::UI::Xaml::DependencyProperty const& propertyToSet, char16_t value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Markup::IXamlBindingHelperStatics)->SetPropertyFromChar16(get_abi(dependencyObject), get_abi(propertyToSet), value));
}

template <typename D> void consume_Windows_UI_Xaml_Markup_IXamlBindingHelperStatics<D>::SetPropertyFromDateTime(Windows::Foundation::IInspectable const& dependencyObject, Windows::UI::Xaml::DependencyProperty const& propertyToSet, Windows::Foundation::DateTime const& value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Markup::IXamlBindingHelperStatics)->SetPropertyFromDateTime(get_abi(dependencyObject), get_abi(propertyToSet), get_abi(value)));
}

template <typename D> void consume_Windows_UI_Xaml_Markup_IXamlBindingHelperStatics<D>::SetPropertyFromDouble(Windows::Foundation::IInspectable const& dependencyObject, Windows::UI::Xaml::DependencyProperty const& propertyToSet, double value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Markup::IXamlBindingHelperStatics)->SetPropertyFromDouble(get_abi(dependencyObject), get_abi(propertyToSet), value));
}

template <typename D> void consume_Windows_UI_Xaml_Markup_IXamlBindingHelperStatics<D>::SetPropertyFromInt32(Windows::Foundation::IInspectable const& dependencyObject, Windows::UI::Xaml::DependencyProperty const& propertyToSet, int32_t value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Markup::IXamlBindingHelperStatics)->SetPropertyFromInt32(get_abi(dependencyObject), get_abi(propertyToSet), value));
}

template <typename D> void consume_Windows_UI_Xaml_Markup_IXamlBindingHelperStatics<D>::SetPropertyFromUInt32(Windows::Foundation::IInspectable const& dependencyObject, Windows::UI::Xaml::DependencyProperty const& propertyToSet, uint32_t value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Markup::IXamlBindingHelperStatics)->SetPropertyFromUInt32(get_abi(dependencyObject), get_abi(propertyToSet), value));
}

template <typename D> void consume_Windows_UI_Xaml_Markup_IXamlBindingHelperStatics<D>::SetPropertyFromInt64(Windows::Foundation::IInspectable const& dependencyObject, Windows::UI::Xaml::DependencyProperty const& propertyToSet, int64_t value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Markup::IXamlBindingHelperStatics)->SetPropertyFromInt64(get_abi(dependencyObject), get_abi(propertyToSet), value));
}

template <typename D> void consume_Windows_UI_Xaml_Markup_IXamlBindingHelperStatics<D>::SetPropertyFromUInt64(Windows::Foundation::IInspectable const& dependencyObject, Windows::UI::Xaml::DependencyProperty const& propertyToSet, uint64_t value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Markup::IXamlBindingHelperStatics)->SetPropertyFromUInt64(get_abi(dependencyObject), get_abi(propertyToSet), value));
}

template <typename D> void consume_Windows_UI_Xaml_Markup_IXamlBindingHelperStatics<D>::SetPropertyFromSingle(Windows::Foundation::IInspectable const& dependencyObject, Windows::UI::Xaml::DependencyProperty const& propertyToSet, float value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Markup::IXamlBindingHelperStatics)->SetPropertyFromSingle(get_abi(dependencyObject), get_abi(propertyToSet), value));
}

template <typename D> void consume_Windows_UI_Xaml_Markup_IXamlBindingHelperStatics<D>::SetPropertyFromPoint(Windows::Foundation::IInspectable const& dependencyObject, Windows::UI::Xaml::DependencyProperty const& propertyToSet, Windows::Foundation::Point const& value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Markup::IXamlBindingHelperStatics)->SetPropertyFromPoint(get_abi(dependencyObject), get_abi(propertyToSet), get_abi(value)));
}

template <typename D> void consume_Windows_UI_Xaml_Markup_IXamlBindingHelperStatics<D>::SetPropertyFromRect(Windows::Foundation::IInspectable const& dependencyObject, Windows::UI::Xaml::DependencyProperty const& propertyToSet, Windows::Foundation::Rect const& value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Markup::IXamlBindingHelperStatics)->SetPropertyFromRect(get_abi(dependencyObject), get_abi(propertyToSet), get_abi(value)));
}

template <typename D> void consume_Windows_UI_Xaml_Markup_IXamlBindingHelperStatics<D>::SetPropertyFromSize(Windows::Foundation::IInspectable const& dependencyObject, Windows::UI::Xaml::DependencyProperty const& propertyToSet, Windows::Foundation::Size const& value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Markup::IXamlBindingHelperStatics)->SetPropertyFromSize(get_abi(dependencyObject), get_abi(propertyToSet), get_abi(value)));
}

template <typename D> void consume_Windows_UI_Xaml_Markup_IXamlBindingHelperStatics<D>::SetPropertyFromTimeSpan(Windows::Foundation::IInspectable const& dependencyObject, Windows::UI::Xaml::DependencyProperty const& propertyToSet, Windows::Foundation::TimeSpan const& value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Markup::IXamlBindingHelperStatics)->SetPropertyFromTimeSpan(get_abi(dependencyObject), get_abi(propertyToSet), get_abi(value)));
}

template <typename D> void consume_Windows_UI_Xaml_Markup_IXamlBindingHelperStatics<D>::SetPropertyFromByte(Windows::Foundation::IInspectable const& dependencyObject, Windows::UI::Xaml::DependencyProperty const& propertyToSet, uint8_t value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Markup::IXamlBindingHelperStatics)->SetPropertyFromByte(get_abi(dependencyObject), get_abi(propertyToSet), value));
}

template <typename D> void consume_Windows_UI_Xaml_Markup_IXamlBindingHelperStatics<D>::SetPropertyFromUri(Windows::Foundation::IInspectable const& dependencyObject, Windows::UI::Xaml::DependencyProperty const& propertyToSet, Windows::Foundation::Uri const& value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Markup::IXamlBindingHelperStatics)->SetPropertyFromUri(get_abi(dependencyObject), get_abi(propertyToSet), get_abi(value)));
}

template <typename D> void consume_Windows_UI_Xaml_Markup_IXamlBindingHelperStatics<D>::SetPropertyFromObject(Windows::Foundation::IInspectable const& dependencyObject, Windows::UI::Xaml::DependencyProperty const& propertyToSet, Windows::Foundation::IInspectable const& value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Markup::IXamlBindingHelperStatics)->SetPropertyFromObject(get_abi(dependencyObject), get_abi(propertyToSet), get_abi(value)));
}

template <typename D> void consume_Windows_UI_Xaml_Markup_IXamlMarkupHelperStatics<D>::UnloadObject(Windows::UI::Xaml::DependencyObject const& element) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Markup::IXamlMarkupHelperStatics)->UnloadObject(get_abi(element)));
}

template <typename D> bool consume_Windows_UI_Xaml_Markup_IXamlMember<D>::IsAttachable() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Markup::IXamlMember)->get_IsAttachable(&value));
    return value;
}

template <typename D> bool consume_Windows_UI_Xaml_Markup_IXamlMember<D>::IsDependencyProperty() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Markup::IXamlMember)->get_IsDependencyProperty(&value));
    return value;
}

template <typename D> bool consume_Windows_UI_Xaml_Markup_IXamlMember<D>::IsReadOnly() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Markup::IXamlMember)->get_IsReadOnly(&value));
    return value;
}

template <typename D> hstring consume_Windows_UI_Xaml_Markup_IXamlMember<D>::Name() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Markup::IXamlMember)->get_Name(put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Xaml::Markup::IXamlType consume_Windows_UI_Xaml_Markup_IXamlMember<D>::TargetType() const
{
    Windows::UI::Xaml::Markup::IXamlType value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Markup::IXamlMember)->get_TargetType(put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Xaml::Markup::IXamlType consume_Windows_UI_Xaml_Markup_IXamlMember<D>::Type() const
{
    Windows::UI::Xaml::Markup::IXamlType value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Markup::IXamlMember)->get_Type(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::IInspectable consume_Windows_UI_Xaml_Markup_IXamlMember<D>::GetValue(Windows::Foundation::IInspectable const& instance) const
{
    Windows::Foundation::IInspectable result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Markup::IXamlMember)->GetValue(get_abi(instance), put_abi(result)));
    return result;
}

template <typename D> void consume_Windows_UI_Xaml_Markup_IXamlMember<D>::SetValue(Windows::Foundation::IInspectable const& instance, Windows::Foundation::IInspectable const& value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Markup::IXamlMember)->SetValue(get_abi(instance), get_abi(value)));
}

template <typename D> Windows::UI::Xaml::Markup::IXamlType consume_Windows_UI_Xaml_Markup_IXamlMetadataProvider<D>::GetXamlType(Windows::UI::Xaml::Interop::TypeName const& type) const
{
    Windows::UI::Xaml::Markup::IXamlType result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Markup::IXamlMetadataProvider)->GetXamlType(get_abi(type), put_abi(result)));
    return result;
}

template <typename D> Windows::UI::Xaml::Markup::IXamlType consume_Windows_UI_Xaml_Markup_IXamlMetadataProvider<D>::GetXamlType(param::hstring const& fullName) const
{
    Windows::UI::Xaml::Markup::IXamlType result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Markup::IXamlMetadataProvider)->GetXamlTypeByFullName(get_abi(fullName), put_abi(result)));
    return result;
}

template <typename D> com_array<Windows::UI::Xaml::Markup::XmlnsDefinition> consume_Windows_UI_Xaml_Markup_IXamlMetadataProvider<D>::GetXmlnsDefinitions() const
{
    com_array<Windows::UI::Xaml::Markup::XmlnsDefinition> result;
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Markup::IXamlMetadataProvider)->GetXmlnsDefinitions(impl::put_size_abi(result), put_abi(result)));
    return result;
}

template <typename D> Windows::Foundation::IInspectable consume_Windows_UI_Xaml_Markup_IXamlReaderStatics<D>::Load(param::hstring const& xaml) const
{
    Windows::Foundation::IInspectable result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Markup::IXamlReaderStatics)->Load(get_abi(xaml), put_abi(result)));
    return result;
}

template <typename D> Windows::Foundation::IInspectable consume_Windows_UI_Xaml_Markup_IXamlReaderStatics<D>::LoadWithInitialTemplateValidation(param::hstring const& xaml) const
{
    Windows::Foundation::IInspectable result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Markup::IXamlReaderStatics)->LoadWithInitialTemplateValidation(get_abi(xaml), put_abi(result)));
    return result;
}

template <typename D> Windows::UI::Xaml::Markup::IXamlType consume_Windows_UI_Xaml_Markup_IXamlType<D>::BaseType() const
{
    Windows::UI::Xaml::Markup::IXamlType value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Markup::IXamlType)->get_BaseType(put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Xaml::Markup::IXamlMember consume_Windows_UI_Xaml_Markup_IXamlType<D>::ContentProperty() const
{
    Windows::UI::Xaml::Markup::IXamlMember value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Markup::IXamlType)->get_ContentProperty(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_UI_Xaml_Markup_IXamlType<D>::FullName() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Markup::IXamlType)->get_FullName(put_abi(value)));
    return value;
}

template <typename D> bool consume_Windows_UI_Xaml_Markup_IXamlType<D>::IsArray() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Markup::IXamlType)->get_IsArray(&value));
    return value;
}

template <typename D> bool consume_Windows_UI_Xaml_Markup_IXamlType<D>::IsCollection() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Markup::IXamlType)->get_IsCollection(&value));
    return value;
}

template <typename D> bool consume_Windows_UI_Xaml_Markup_IXamlType<D>::IsConstructible() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Markup::IXamlType)->get_IsConstructible(&value));
    return value;
}

template <typename D> bool consume_Windows_UI_Xaml_Markup_IXamlType<D>::IsDictionary() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Markup::IXamlType)->get_IsDictionary(&value));
    return value;
}

template <typename D> bool consume_Windows_UI_Xaml_Markup_IXamlType<D>::IsMarkupExtension() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Markup::IXamlType)->get_IsMarkupExtension(&value));
    return value;
}

template <typename D> bool consume_Windows_UI_Xaml_Markup_IXamlType<D>::IsBindable() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Markup::IXamlType)->get_IsBindable(&value));
    return value;
}

template <typename D> Windows::UI::Xaml::Markup::IXamlType consume_Windows_UI_Xaml_Markup_IXamlType<D>::ItemType() const
{
    Windows::UI::Xaml::Markup::IXamlType value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Markup::IXamlType)->get_ItemType(put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Xaml::Markup::IXamlType consume_Windows_UI_Xaml_Markup_IXamlType<D>::KeyType() const
{
    Windows::UI::Xaml::Markup::IXamlType value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Markup::IXamlType)->get_KeyType(put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Xaml::Interop::TypeName consume_Windows_UI_Xaml_Markup_IXamlType<D>::UnderlyingType() const
{
    Windows::UI::Xaml::Interop::TypeName value{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Markup::IXamlType)->get_UnderlyingType(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::IInspectable consume_Windows_UI_Xaml_Markup_IXamlType<D>::ActivateInstance() const
{
    Windows::Foundation::IInspectable result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Markup::IXamlType)->ActivateInstance(put_abi(result)));
    return result;
}

template <typename D> Windows::Foundation::IInspectable consume_Windows_UI_Xaml_Markup_IXamlType<D>::CreateFromString(param::hstring const& value) const
{
    Windows::Foundation::IInspectable result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Markup::IXamlType)->CreateFromString(get_abi(value), put_abi(result)));
    return result;
}

template <typename D> Windows::UI::Xaml::Markup::IXamlMember consume_Windows_UI_Xaml_Markup_IXamlType<D>::GetMember(param::hstring const& name) const
{
    Windows::UI::Xaml::Markup::IXamlMember result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Markup::IXamlType)->GetMember(get_abi(name), put_abi(result)));
    return result;
}

template <typename D> void consume_Windows_UI_Xaml_Markup_IXamlType<D>::AddToVector(Windows::Foundation::IInspectable const& instance, Windows::Foundation::IInspectable const& value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Markup::IXamlType)->AddToVector(get_abi(instance), get_abi(value)));
}

template <typename D> void consume_Windows_UI_Xaml_Markup_IXamlType<D>::AddToMap(Windows::Foundation::IInspectable const& instance, Windows::Foundation::IInspectable const& key, Windows::Foundation::IInspectable const& value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Markup::IXamlType)->AddToMap(get_abi(instance), get_abi(key), get_abi(value)));
}

template <typename D> void consume_Windows_UI_Xaml_Markup_IXamlType<D>::RunInitializer() const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Markup::IXamlType)->RunInitializer());
}

template <typename D> Windows::UI::Xaml::Markup::IXamlType consume_Windows_UI_Xaml_Markup_IXamlType2<D>::BoxedType() const
{
    Windows::UI::Xaml::Markup::IXamlType value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Markup::IXamlType2)->get_BoxedType(put_abi(value)));
    return value;
}

template <typename D>
struct produce<D, Windows::UI::Xaml::Markup::IComponentConnector> : produce_base<D, Windows::UI::Xaml::Markup::IComponentConnector>
{
    int32_t WINRT_CALL Connect(int32_t connectionId, void* target) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Connect, WINRT_WRAP(void), int32_t, Windows::Foundation::IInspectable const&);
            this->shim().Connect(connectionId, *reinterpret_cast<Windows::Foundation::IInspectable const*>(&target));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Xaml::Markup::IComponentConnector2> : produce_base<D, Windows::UI::Xaml::Markup::IComponentConnector2>
{
    int32_t WINRT_CALL GetBindingConnector(int32_t connectionId, void* target, void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetBindingConnector, WINRT_WRAP(Windows::UI::Xaml::Markup::IComponentConnector), int32_t, Windows::Foundation::IInspectable const&);
            *result = detach_from<Windows::UI::Xaml::Markup::IComponentConnector>(this->shim().GetBindingConnector(connectionId, *reinterpret_cast<Windows::Foundation::IInspectable const*>(&target)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Xaml::Markup::IDataTemplateComponent> : produce_base<D, Windows::UI::Xaml::Markup::IDataTemplateComponent>
{
    int32_t WINRT_CALL Recycle() noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Recycle, WINRT_WRAP(void));
            this->shim().Recycle();
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL ProcessBindings(void* item, int32_t itemIndex, int32_t phase, int32_t* nextPhase) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ProcessBindings, WINRT_WRAP(void), Windows::Foundation::IInspectable const&, int32_t, int32_t, int32_t&);
            this->shim().ProcessBindings(*reinterpret_cast<Windows::Foundation::IInspectable const*>(&item), itemIndex, phase, *nextPhase);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Xaml::Markup::IMarkupExtension> : produce_base<D, Windows::UI::Xaml::Markup::IMarkupExtension>
{};

template <typename D>
struct produce<D, Windows::UI::Xaml::Markup::IMarkupExtensionFactory> : produce_base<D, Windows::UI::Xaml::Markup::IMarkupExtensionFactory>
{
    int32_t WINRT_CALL CreateInstance(void* baseInterface, void** innerInterface, void** value) noexcept final
    {
        try
        {
            if (innerInterface) *innerInterface = nullptr;
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            Windows::Foundation::IInspectable __local_innerInterface;
            WINRT_ASSERT_DECLARATION(CreateInstance, WINRT_WRAP(Windows::UI::Xaml::Markup::MarkupExtension), Windows::Foundation::IInspectable const&, Windows::Foundation::IInspectable&);
            *value = detach_from<Windows::UI::Xaml::Markup::MarkupExtension>(this->shim().CreateInstance(*reinterpret_cast<Windows::Foundation::IInspectable const*>(&baseInterface), __local_innerInterface));
            if (innerInterface) *innerInterface = detach_abi(__local_innerInterface);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Xaml::Markup::IMarkupExtensionOverrides> : produce_base<D, Windows::UI::Xaml::Markup::IMarkupExtensionOverrides>
{
    int32_t WINRT_CALL ProvideValue(void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ProvideValue, WINRT_WRAP(Windows::Foundation::IInspectable));
            *result = detach_from<Windows::Foundation::IInspectable>(this->shim().ProvideValue());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Xaml::Markup::IXamlBinaryWriter> : produce_base<D, Windows::UI::Xaml::Markup::IXamlBinaryWriter>
{};

template <typename D>
struct produce<D, Windows::UI::Xaml::Markup::IXamlBinaryWriterStatics> : produce_base<D, Windows::UI::Xaml::Markup::IXamlBinaryWriterStatics>
{
    int32_t WINRT_CALL Write(void* inputStreams, void* outputStreams, void* xamlMetadataProvider, struct struct_Windows_UI_Xaml_Markup_XamlBinaryWriterErrorInformation* result) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Write, WINRT_WRAP(Windows::UI::Xaml::Markup::XamlBinaryWriterErrorInformation), Windows::Foundation::Collections::IVector<Windows::Storage::Streams::IRandomAccessStream> const&, Windows::Foundation::Collections::IVector<Windows::Storage::Streams::IRandomAccessStream> const&, Windows::UI::Xaml::Markup::IXamlMetadataProvider const&);
            *result = detach_from<Windows::UI::Xaml::Markup::XamlBinaryWriterErrorInformation>(this->shim().Write(*reinterpret_cast<Windows::Foundation::Collections::IVector<Windows::Storage::Streams::IRandomAccessStream> const*>(&inputStreams), *reinterpret_cast<Windows::Foundation::Collections::IVector<Windows::Storage::Streams::IRandomAccessStream> const*>(&outputStreams), *reinterpret_cast<Windows::UI::Xaml::Markup::IXamlMetadataProvider const*>(&xamlMetadataProvider)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Xaml::Markup::IXamlBindScopeDiagnostics> : produce_base<D, Windows::UI::Xaml::Markup::IXamlBindScopeDiagnostics>
{
    int32_t WINRT_CALL Disable(int32_t lineNumber, int32_t columnNumber) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Disable, WINRT_WRAP(void), int32_t, int32_t);
            this->shim().Disable(lineNumber, columnNumber);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Xaml::Markup::IXamlBindingHelper> : produce_base<D, Windows::UI::Xaml::Markup::IXamlBindingHelper>
{};

template <typename D>
struct produce<D, Windows::UI::Xaml::Markup::IXamlBindingHelperStatics> : produce_base<D, Windows::UI::Xaml::Markup::IXamlBindingHelperStatics>
{
    int32_t WINRT_CALL get_DataTemplateComponentProperty(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(DataTemplateComponentProperty, WINRT_WRAP(Windows::UI::Xaml::DependencyProperty));
            *value = detach_from<Windows::UI::Xaml::DependencyProperty>(this->shim().DataTemplateComponentProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL GetDataTemplateComponent(void* element, void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetDataTemplateComponent, WINRT_WRAP(Windows::UI::Xaml::Markup::IDataTemplateComponent), Windows::UI::Xaml::DependencyObject const&);
            *result = detach_from<Windows::UI::Xaml::Markup::IDataTemplateComponent>(this->shim().GetDataTemplateComponent(*reinterpret_cast<Windows::UI::Xaml::DependencyObject const*>(&element)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL SetDataTemplateComponent(void* element, void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SetDataTemplateComponent, WINRT_WRAP(void), Windows::UI::Xaml::DependencyObject const&, Windows::UI::Xaml::Markup::IDataTemplateComponent const&);
            this->shim().SetDataTemplateComponent(*reinterpret_cast<Windows::UI::Xaml::DependencyObject const*>(&element), *reinterpret_cast<Windows::UI::Xaml::Markup::IDataTemplateComponent const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL SuspendRendering(void* target) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SuspendRendering, WINRT_WRAP(void), Windows::UI::Xaml::UIElement const&);
            this->shim().SuspendRendering(*reinterpret_cast<Windows::UI::Xaml::UIElement const*>(&target));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL ResumeRendering(void* target) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ResumeRendering, WINRT_WRAP(void), Windows::UI::Xaml::UIElement const&);
            this->shim().ResumeRendering(*reinterpret_cast<Windows::UI::Xaml::UIElement const*>(&target));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL ConvertValue(struct struct_Windows_UI_Xaml_Interop_TypeName type, void* value, void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ConvertValue, WINRT_WRAP(Windows::Foundation::IInspectable), Windows::UI::Xaml::Interop::TypeName const&, Windows::Foundation::IInspectable const&);
            *result = detach_from<Windows::Foundation::IInspectable>(this->shim().ConvertValue(*reinterpret_cast<Windows::UI::Xaml::Interop::TypeName const*>(&type), *reinterpret_cast<Windows::Foundation::IInspectable const*>(&value)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL SetPropertyFromString(void* dependencyObject, void* propertyToSet, void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SetPropertyFromString, WINRT_WRAP(void), Windows::Foundation::IInspectable const&, Windows::UI::Xaml::DependencyProperty const&, hstring const&);
            this->shim().SetPropertyFromString(*reinterpret_cast<Windows::Foundation::IInspectable const*>(&dependencyObject), *reinterpret_cast<Windows::UI::Xaml::DependencyProperty const*>(&propertyToSet), *reinterpret_cast<hstring const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL SetPropertyFromBoolean(void* dependencyObject, void* propertyToSet, bool value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SetPropertyFromBoolean, WINRT_WRAP(void), Windows::Foundation::IInspectable const&, Windows::UI::Xaml::DependencyProperty const&, bool);
            this->shim().SetPropertyFromBoolean(*reinterpret_cast<Windows::Foundation::IInspectable const*>(&dependencyObject), *reinterpret_cast<Windows::UI::Xaml::DependencyProperty const*>(&propertyToSet), value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL SetPropertyFromChar16(void* dependencyObject, void* propertyToSet, char16_t value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SetPropertyFromChar16, WINRT_WRAP(void), Windows::Foundation::IInspectable const&, Windows::UI::Xaml::DependencyProperty const&, char16_t);
            this->shim().SetPropertyFromChar16(*reinterpret_cast<Windows::Foundation::IInspectable const*>(&dependencyObject), *reinterpret_cast<Windows::UI::Xaml::DependencyProperty const*>(&propertyToSet), value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL SetPropertyFromDateTime(void* dependencyObject, void* propertyToSet, Windows::Foundation::DateTime value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SetPropertyFromDateTime, WINRT_WRAP(void), Windows::Foundation::IInspectable const&, Windows::UI::Xaml::DependencyProperty const&, Windows::Foundation::DateTime const&);
            this->shim().SetPropertyFromDateTime(*reinterpret_cast<Windows::Foundation::IInspectable const*>(&dependencyObject), *reinterpret_cast<Windows::UI::Xaml::DependencyProperty const*>(&propertyToSet), *reinterpret_cast<Windows::Foundation::DateTime const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL SetPropertyFromDouble(void* dependencyObject, void* propertyToSet, double value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SetPropertyFromDouble, WINRT_WRAP(void), Windows::Foundation::IInspectable const&, Windows::UI::Xaml::DependencyProperty const&, double);
            this->shim().SetPropertyFromDouble(*reinterpret_cast<Windows::Foundation::IInspectable const*>(&dependencyObject), *reinterpret_cast<Windows::UI::Xaml::DependencyProperty const*>(&propertyToSet), value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL SetPropertyFromInt32(void* dependencyObject, void* propertyToSet, int32_t value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SetPropertyFromInt32, WINRT_WRAP(void), Windows::Foundation::IInspectable const&, Windows::UI::Xaml::DependencyProperty const&, int32_t);
            this->shim().SetPropertyFromInt32(*reinterpret_cast<Windows::Foundation::IInspectable const*>(&dependencyObject), *reinterpret_cast<Windows::UI::Xaml::DependencyProperty const*>(&propertyToSet), value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL SetPropertyFromUInt32(void* dependencyObject, void* propertyToSet, uint32_t value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SetPropertyFromUInt32, WINRT_WRAP(void), Windows::Foundation::IInspectable const&, Windows::UI::Xaml::DependencyProperty const&, uint32_t);
            this->shim().SetPropertyFromUInt32(*reinterpret_cast<Windows::Foundation::IInspectable const*>(&dependencyObject), *reinterpret_cast<Windows::UI::Xaml::DependencyProperty const*>(&propertyToSet), value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL SetPropertyFromInt64(void* dependencyObject, void* propertyToSet, int64_t value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SetPropertyFromInt64, WINRT_WRAP(void), Windows::Foundation::IInspectable const&, Windows::UI::Xaml::DependencyProperty const&, int64_t);
            this->shim().SetPropertyFromInt64(*reinterpret_cast<Windows::Foundation::IInspectable const*>(&dependencyObject), *reinterpret_cast<Windows::UI::Xaml::DependencyProperty const*>(&propertyToSet), value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL SetPropertyFromUInt64(void* dependencyObject, void* propertyToSet, uint64_t value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SetPropertyFromUInt64, WINRT_WRAP(void), Windows::Foundation::IInspectable const&, Windows::UI::Xaml::DependencyProperty const&, uint64_t);
            this->shim().SetPropertyFromUInt64(*reinterpret_cast<Windows::Foundation::IInspectable const*>(&dependencyObject), *reinterpret_cast<Windows::UI::Xaml::DependencyProperty const*>(&propertyToSet), value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL SetPropertyFromSingle(void* dependencyObject, void* propertyToSet, float value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SetPropertyFromSingle, WINRT_WRAP(void), Windows::Foundation::IInspectable const&, Windows::UI::Xaml::DependencyProperty const&, float);
            this->shim().SetPropertyFromSingle(*reinterpret_cast<Windows::Foundation::IInspectable const*>(&dependencyObject), *reinterpret_cast<Windows::UI::Xaml::DependencyProperty const*>(&propertyToSet), value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL SetPropertyFromPoint(void* dependencyObject, void* propertyToSet, Windows::Foundation::Point value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SetPropertyFromPoint, WINRT_WRAP(void), Windows::Foundation::IInspectable const&, Windows::UI::Xaml::DependencyProperty const&, Windows::Foundation::Point const&);
            this->shim().SetPropertyFromPoint(*reinterpret_cast<Windows::Foundation::IInspectable const*>(&dependencyObject), *reinterpret_cast<Windows::UI::Xaml::DependencyProperty const*>(&propertyToSet), *reinterpret_cast<Windows::Foundation::Point const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL SetPropertyFromRect(void* dependencyObject, void* propertyToSet, Windows::Foundation::Rect value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SetPropertyFromRect, WINRT_WRAP(void), Windows::Foundation::IInspectable const&, Windows::UI::Xaml::DependencyProperty const&, Windows::Foundation::Rect const&);
            this->shim().SetPropertyFromRect(*reinterpret_cast<Windows::Foundation::IInspectable const*>(&dependencyObject), *reinterpret_cast<Windows::UI::Xaml::DependencyProperty const*>(&propertyToSet), *reinterpret_cast<Windows::Foundation::Rect const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL SetPropertyFromSize(void* dependencyObject, void* propertyToSet, Windows::Foundation::Size value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SetPropertyFromSize, WINRT_WRAP(void), Windows::Foundation::IInspectable const&, Windows::UI::Xaml::DependencyProperty const&, Windows::Foundation::Size const&);
            this->shim().SetPropertyFromSize(*reinterpret_cast<Windows::Foundation::IInspectable const*>(&dependencyObject), *reinterpret_cast<Windows::UI::Xaml::DependencyProperty const*>(&propertyToSet), *reinterpret_cast<Windows::Foundation::Size const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL SetPropertyFromTimeSpan(void* dependencyObject, void* propertyToSet, Windows::Foundation::TimeSpan value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SetPropertyFromTimeSpan, WINRT_WRAP(void), Windows::Foundation::IInspectable const&, Windows::UI::Xaml::DependencyProperty const&, Windows::Foundation::TimeSpan const&);
            this->shim().SetPropertyFromTimeSpan(*reinterpret_cast<Windows::Foundation::IInspectable const*>(&dependencyObject), *reinterpret_cast<Windows::UI::Xaml::DependencyProperty const*>(&propertyToSet), *reinterpret_cast<Windows::Foundation::TimeSpan const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL SetPropertyFromByte(void* dependencyObject, void* propertyToSet, uint8_t value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SetPropertyFromByte, WINRT_WRAP(void), Windows::Foundation::IInspectable const&, Windows::UI::Xaml::DependencyProperty const&, uint8_t);
            this->shim().SetPropertyFromByte(*reinterpret_cast<Windows::Foundation::IInspectable const*>(&dependencyObject), *reinterpret_cast<Windows::UI::Xaml::DependencyProperty const*>(&propertyToSet), value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL SetPropertyFromUri(void* dependencyObject, void* propertyToSet, void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SetPropertyFromUri, WINRT_WRAP(void), Windows::Foundation::IInspectable const&, Windows::UI::Xaml::DependencyProperty const&, Windows::Foundation::Uri const&);
            this->shim().SetPropertyFromUri(*reinterpret_cast<Windows::Foundation::IInspectable const*>(&dependencyObject), *reinterpret_cast<Windows::UI::Xaml::DependencyProperty const*>(&propertyToSet), *reinterpret_cast<Windows::Foundation::Uri const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL SetPropertyFromObject(void* dependencyObject, void* propertyToSet, void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SetPropertyFromObject, WINRT_WRAP(void), Windows::Foundation::IInspectable const&, Windows::UI::Xaml::DependencyProperty const&, Windows::Foundation::IInspectable const&);
            this->shim().SetPropertyFromObject(*reinterpret_cast<Windows::Foundation::IInspectable const*>(&dependencyObject), *reinterpret_cast<Windows::UI::Xaml::DependencyProperty const*>(&propertyToSet), *reinterpret_cast<Windows::Foundation::IInspectable const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Xaml::Markup::IXamlMarkupHelper> : produce_base<D, Windows::UI::Xaml::Markup::IXamlMarkupHelper>
{};

template <typename D>
struct produce<D, Windows::UI::Xaml::Markup::IXamlMarkupHelperStatics> : produce_base<D, Windows::UI::Xaml::Markup::IXamlMarkupHelperStatics>
{
    int32_t WINRT_CALL UnloadObject(void* element) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(UnloadObject, WINRT_WRAP(void), Windows::UI::Xaml::DependencyObject const&);
            this->shim().UnloadObject(*reinterpret_cast<Windows::UI::Xaml::DependencyObject const*>(&element));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Xaml::Markup::IXamlMember> : produce_base<D, Windows::UI::Xaml::Markup::IXamlMember>
{
    int32_t WINRT_CALL get_IsAttachable(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IsAttachable, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().IsAttachable());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_IsDependencyProperty(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IsDependencyProperty, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().IsDependencyProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_IsReadOnly(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IsReadOnly, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().IsReadOnly());
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

    int32_t WINRT_CALL get_TargetType(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(TargetType, WINRT_WRAP(Windows::UI::Xaml::Markup::IXamlType));
            *value = detach_from<Windows::UI::Xaml::Markup::IXamlType>(this->shim().TargetType());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Type(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Type, WINRT_WRAP(Windows::UI::Xaml::Markup::IXamlType));
            *value = detach_from<Windows::UI::Xaml::Markup::IXamlType>(this->shim().Type());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL GetValue(void* instance, void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetValue, WINRT_WRAP(Windows::Foundation::IInspectable), Windows::Foundation::IInspectable const&);
            *result = detach_from<Windows::Foundation::IInspectable>(this->shim().GetValue(*reinterpret_cast<Windows::Foundation::IInspectable const*>(&instance)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL SetValue(void* instance, void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SetValue, WINRT_WRAP(void), Windows::Foundation::IInspectable const&, Windows::Foundation::IInspectable const&);
            this->shim().SetValue(*reinterpret_cast<Windows::Foundation::IInspectable const*>(&instance), *reinterpret_cast<Windows::Foundation::IInspectable const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Xaml::Markup::IXamlMetadataProvider> : produce_base<D, Windows::UI::Xaml::Markup::IXamlMetadataProvider>
{
    int32_t WINRT_CALL GetXamlType(struct struct_Windows_UI_Xaml_Interop_TypeName type, void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetXamlType, WINRT_WRAP(Windows::UI::Xaml::Markup::IXamlType), Windows::UI::Xaml::Interop::TypeName const&);
            *result = detach_from<Windows::UI::Xaml::Markup::IXamlType>(this->shim().GetXamlType(*reinterpret_cast<Windows::UI::Xaml::Interop::TypeName const*>(&type)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL GetXamlTypeByFullName(void* fullName, void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetXamlType, WINRT_WRAP(Windows::UI::Xaml::Markup::IXamlType), hstring const&);
            *result = detach_from<Windows::UI::Xaml::Markup::IXamlType>(this->shim().GetXamlType(*reinterpret_cast<hstring const*>(&fullName)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL GetXmlnsDefinitions(uint32_t* __resultSize, struct struct_Windows_UI_Xaml_Markup_XmlnsDefinition** result) noexcept final
    {
        try
        {
            *__resultSize = 0;
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetXmlnsDefinitions, WINRT_WRAP(com_array<Windows::UI::Xaml::Markup::XmlnsDefinition>));
            std::tie(*__resultSize, *result) = detach_abi(this->shim().GetXmlnsDefinitions());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Xaml::Markup::IXamlReader> : produce_base<D, Windows::UI::Xaml::Markup::IXamlReader>
{};

template <typename D>
struct produce<D, Windows::UI::Xaml::Markup::IXamlReaderStatics> : produce_base<D, Windows::UI::Xaml::Markup::IXamlReaderStatics>
{
    int32_t WINRT_CALL Load(void* xaml, void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Load, WINRT_WRAP(Windows::Foundation::IInspectable), hstring const&);
            *result = detach_from<Windows::Foundation::IInspectable>(this->shim().Load(*reinterpret_cast<hstring const*>(&xaml)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL LoadWithInitialTemplateValidation(void* xaml, void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(LoadWithInitialTemplateValidation, WINRT_WRAP(Windows::Foundation::IInspectable), hstring const&);
            *result = detach_from<Windows::Foundation::IInspectable>(this->shim().LoadWithInitialTemplateValidation(*reinterpret_cast<hstring const*>(&xaml)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Xaml::Markup::IXamlType> : produce_base<D, Windows::UI::Xaml::Markup::IXamlType>
{
    int32_t WINRT_CALL get_BaseType(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(BaseType, WINRT_WRAP(Windows::UI::Xaml::Markup::IXamlType));
            *value = detach_from<Windows::UI::Xaml::Markup::IXamlType>(this->shim().BaseType());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_ContentProperty(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ContentProperty, WINRT_WRAP(Windows::UI::Xaml::Markup::IXamlMember));
            *value = detach_from<Windows::UI::Xaml::Markup::IXamlMember>(this->shim().ContentProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_FullName(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(FullName, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().FullName());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_IsArray(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IsArray, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().IsArray());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_IsCollection(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IsCollection, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().IsCollection());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_IsConstructible(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IsConstructible, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().IsConstructible());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_IsDictionary(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IsDictionary, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().IsDictionary());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_IsMarkupExtension(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IsMarkupExtension, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().IsMarkupExtension());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_IsBindable(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IsBindable, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().IsBindable());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_ItemType(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ItemType, WINRT_WRAP(Windows::UI::Xaml::Markup::IXamlType));
            *value = detach_from<Windows::UI::Xaml::Markup::IXamlType>(this->shim().ItemType());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_KeyType(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(KeyType, WINRT_WRAP(Windows::UI::Xaml::Markup::IXamlType));
            *value = detach_from<Windows::UI::Xaml::Markup::IXamlType>(this->shim().KeyType());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_UnderlyingType(struct struct_Windows_UI_Xaml_Interop_TypeName* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(UnderlyingType, WINRT_WRAP(Windows::UI::Xaml::Interop::TypeName));
            *value = detach_from<Windows::UI::Xaml::Interop::TypeName>(this->shim().UnderlyingType());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL ActivateInstance(void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ActivateInstance, WINRT_WRAP(Windows::Foundation::IInspectable));
            *result = detach_from<Windows::Foundation::IInspectable>(this->shim().ActivateInstance());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL CreateFromString(void* value, void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CreateFromString, WINRT_WRAP(Windows::Foundation::IInspectable), hstring const&);
            *result = detach_from<Windows::Foundation::IInspectable>(this->shim().CreateFromString(*reinterpret_cast<hstring const*>(&value)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL GetMember(void* name, void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetMember, WINRT_WRAP(Windows::UI::Xaml::Markup::IXamlMember), hstring const&);
            *result = detach_from<Windows::UI::Xaml::Markup::IXamlMember>(this->shim().GetMember(*reinterpret_cast<hstring const*>(&name)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL AddToVector(void* instance, void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(AddToVector, WINRT_WRAP(void), Windows::Foundation::IInspectable const&, Windows::Foundation::IInspectable const&);
            this->shim().AddToVector(*reinterpret_cast<Windows::Foundation::IInspectable const*>(&instance), *reinterpret_cast<Windows::Foundation::IInspectable const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL AddToMap(void* instance, void* key, void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(AddToMap, WINRT_WRAP(void), Windows::Foundation::IInspectable const&, Windows::Foundation::IInspectable const&, Windows::Foundation::IInspectable const&);
            this->shim().AddToMap(*reinterpret_cast<Windows::Foundation::IInspectable const*>(&instance), *reinterpret_cast<Windows::Foundation::IInspectable const*>(&key), *reinterpret_cast<Windows::Foundation::IInspectable const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL RunInitializer() noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(RunInitializer, WINRT_WRAP(void));
            this->shim().RunInitializer();
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Xaml::Markup::IXamlType2> : produce_base<D, Windows::UI::Xaml::Markup::IXamlType2>
{
    int32_t WINRT_CALL get_BoxedType(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(BoxedType, WINRT_WRAP(Windows::UI::Xaml::Markup::IXamlType));
            *value = detach_from<Windows::UI::Xaml::Markup::IXamlType>(this->shim().BoxedType());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename T, typename D>
struct WINRT_EBO produce_dispatch_to_overridable<T, D, Windows::UI::Xaml::Markup::IMarkupExtensionOverrides>
    : produce_dispatch_to_overridable_base<T, D, Windows::UI::Xaml::Markup::IMarkupExtensionOverrides>
{
    Windows::Foundation::IInspectable ProvideValue()
    {
        Windows::UI::Xaml::Markup::IMarkupExtensionOverrides overridable = this->shim_overridable();
        if (overridable)
        {
            return overridable.ProvideValue();
        }
        return this->shim().ProvideValue();
    }
};
}

WINRT_EXPORT namespace winrt::Windows::UI::Xaml::Markup {

inline MarkupExtension::MarkupExtension()
{
    Windows::Foundation::IInspectable baseInterface, innerInterface;
    *this = impl::call_factory<MarkupExtension, Windows::UI::Xaml::Markup::IMarkupExtensionFactory>([&](auto&& f) { return f.CreateInstance(baseInterface, innerInterface); });
}

inline Windows::UI::Xaml::Markup::XamlBinaryWriterErrorInformation XamlBinaryWriter::Write(param::vector<Windows::Storage::Streams::IRandomAccessStream> const& inputStreams, param::vector<Windows::Storage::Streams::IRandomAccessStream> const& outputStreams, Windows::UI::Xaml::Markup::IXamlMetadataProvider const& xamlMetadataProvider)
{
    return impl::call_factory<XamlBinaryWriter, Windows::UI::Xaml::Markup::IXamlBinaryWriterStatics>([&](auto&& f) { return f.Write(inputStreams, outputStreams, xamlMetadataProvider); });
}

inline Windows::UI::Xaml::DependencyProperty XamlBindingHelper::DataTemplateComponentProperty()
{
    return impl::call_factory<XamlBindingHelper, Windows::UI::Xaml::Markup::IXamlBindingHelperStatics>([&](auto&& f) { return f.DataTemplateComponentProperty(); });
}

inline Windows::UI::Xaml::Markup::IDataTemplateComponent XamlBindingHelper::GetDataTemplateComponent(Windows::UI::Xaml::DependencyObject const& element)
{
    return impl::call_factory<XamlBindingHelper, Windows::UI::Xaml::Markup::IXamlBindingHelperStatics>([&](auto&& f) { return f.GetDataTemplateComponent(element); });
}

inline void XamlBindingHelper::SetDataTemplateComponent(Windows::UI::Xaml::DependencyObject const& element, Windows::UI::Xaml::Markup::IDataTemplateComponent const& value)
{
    impl::call_factory<XamlBindingHelper, Windows::UI::Xaml::Markup::IXamlBindingHelperStatics>([&](auto&& f) { return f.SetDataTemplateComponent(element, value); });
}

inline void XamlBindingHelper::SuspendRendering(Windows::UI::Xaml::UIElement const& target)
{
    impl::call_factory<XamlBindingHelper, Windows::UI::Xaml::Markup::IXamlBindingHelperStatics>([&](auto&& f) { return f.SuspendRendering(target); });
}

inline void XamlBindingHelper::ResumeRendering(Windows::UI::Xaml::UIElement const& target)
{
    impl::call_factory<XamlBindingHelper, Windows::UI::Xaml::Markup::IXamlBindingHelperStatics>([&](auto&& f) { return f.ResumeRendering(target); });
}

inline Windows::Foundation::IInspectable XamlBindingHelper::ConvertValue(Windows::UI::Xaml::Interop::TypeName const& type, Windows::Foundation::IInspectable const& value)
{
    return impl::call_factory<XamlBindingHelper, Windows::UI::Xaml::Markup::IXamlBindingHelperStatics>([&](auto&& f) { return f.ConvertValue(type, value); });
}

inline void XamlBindingHelper::SetPropertyFromString(Windows::Foundation::IInspectable const& dependencyObject, Windows::UI::Xaml::DependencyProperty const& propertyToSet, param::hstring const& value)
{
    impl::call_factory<XamlBindingHelper, Windows::UI::Xaml::Markup::IXamlBindingHelperStatics>([&](auto&& f) { return f.SetPropertyFromString(dependencyObject, propertyToSet, value); });
}

inline void XamlBindingHelper::SetPropertyFromBoolean(Windows::Foundation::IInspectable const& dependencyObject, Windows::UI::Xaml::DependencyProperty const& propertyToSet, bool value)
{
    impl::call_factory<XamlBindingHelper, Windows::UI::Xaml::Markup::IXamlBindingHelperStatics>([&](auto&& f) { return f.SetPropertyFromBoolean(dependencyObject, propertyToSet, value); });
}

inline void XamlBindingHelper::SetPropertyFromChar16(Windows::Foundation::IInspectable const& dependencyObject, Windows::UI::Xaml::DependencyProperty const& propertyToSet, char16_t value)
{
    impl::call_factory<XamlBindingHelper, Windows::UI::Xaml::Markup::IXamlBindingHelperStatics>([&](auto&& f) { return f.SetPropertyFromChar16(dependencyObject, propertyToSet, value); });
}

inline void XamlBindingHelper::SetPropertyFromDateTime(Windows::Foundation::IInspectable const& dependencyObject, Windows::UI::Xaml::DependencyProperty const& propertyToSet, Windows::Foundation::DateTime const& value)
{
    impl::call_factory<XamlBindingHelper, Windows::UI::Xaml::Markup::IXamlBindingHelperStatics>([&](auto&& f) { return f.SetPropertyFromDateTime(dependencyObject, propertyToSet, value); });
}

inline void XamlBindingHelper::SetPropertyFromDouble(Windows::Foundation::IInspectable const& dependencyObject, Windows::UI::Xaml::DependencyProperty const& propertyToSet, double value)
{
    impl::call_factory<XamlBindingHelper, Windows::UI::Xaml::Markup::IXamlBindingHelperStatics>([&](auto&& f) { return f.SetPropertyFromDouble(dependencyObject, propertyToSet, value); });
}

inline void XamlBindingHelper::SetPropertyFromInt32(Windows::Foundation::IInspectable const& dependencyObject, Windows::UI::Xaml::DependencyProperty const& propertyToSet, int32_t value)
{
    impl::call_factory<XamlBindingHelper, Windows::UI::Xaml::Markup::IXamlBindingHelperStatics>([&](auto&& f) { return f.SetPropertyFromInt32(dependencyObject, propertyToSet, value); });
}

inline void XamlBindingHelper::SetPropertyFromUInt32(Windows::Foundation::IInspectable const& dependencyObject, Windows::UI::Xaml::DependencyProperty const& propertyToSet, uint32_t value)
{
    impl::call_factory<XamlBindingHelper, Windows::UI::Xaml::Markup::IXamlBindingHelperStatics>([&](auto&& f) { return f.SetPropertyFromUInt32(dependencyObject, propertyToSet, value); });
}

inline void XamlBindingHelper::SetPropertyFromInt64(Windows::Foundation::IInspectable const& dependencyObject, Windows::UI::Xaml::DependencyProperty const& propertyToSet, int64_t value)
{
    impl::call_factory<XamlBindingHelper, Windows::UI::Xaml::Markup::IXamlBindingHelperStatics>([&](auto&& f) { return f.SetPropertyFromInt64(dependencyObject, propertyToSet, value); });
}

inline void XamlBindingHelper::SetPropertyFromUInt64(Windows::Foundation::IInspectable const& dependencyObject, Windows::UI::Xaml::DependencyProperty const& propertyToSet, uint64_t value)
{
    impl::call_factory<XamlBindingHelper, Windows::UI::Xaml::Markup::IXamlBindingHelperStatics>([&](auto&& f) { return f.SetPropertyFromUInt64(dependencyObject, propertyToSet, value); });
}

inline void XamlBindingHelper::SetPropertyFromSingle(Windows::Foundation::IInspectable const& dependencyObject, Windows::UI::Xaml::DependencyProperty const& propertyToSet, float value)
{
    impl::call_factory<XamlBindingHelper, Windows::UI::Xaml::Markup::IXamlBindingHelperStatics>([&](auto&& f) { return f.SetPropertyFromSingle(dependencyObject, propertyToSet, value); });
}

inline void XamlBindingHelper::SetPropertyFromPoint(Windows::Foundation::IInspectable const& dependencyObject, Windows::UI::Xaml::DependencyProperty const& propertyToSet, Windows::Foundation::Point const& value)
{
    impl::call_factory<XamlBindingHelper, Windows::UI::Xaml::Markup::IXamlBindingHelperStatics>([&](auto&& f) { return f.SetPropertyFromPoint(dependencyObject, propertyToSet, value); });
}

inline void XamlBindingHelper::SetPropertyFromRect(Windows::Foundation::IInspectable const& dependencyObject, Windows::UI::Xaml::DependencyProperty const& propertyToSet, Windows::Foundation::Rect const& value)
{
    impl::call_factory<XamlBindingHelper, Windows::UI::Xaml::Markup::IXamlBindingHelperStatics>([&](auto&& f) { return f.SetPropertyFromRect(dependencyObject, propertyToSet, value); });
}

inline void XamlBindingHelper::SetPropertyFromSize(Windows::Foundation::IInspectable const& dependencyObject, Windows::UI::Xaml::DependencyProperty const& propertyToSet, Windows::Foundation::Size const& value)
{
    impl::call_factory<XamlBindingHelper, Windows::UI::Xaml::Markup::IXamlBindingHelperStatics>([&](auto&& f) { return f.SetPropertyFromSize(dependencyObject, propertyToSet, value); });
}

inline void XamlBindingHelper::SetPropertyFromTimeSpan(Windows::Foundation::IInspectable const& dependencyObject, Windows::UI::Xaml::DependencyProperty const& propertyToSet, Windows::Foundation::TimeSpan const& value)
{
    impl::call_factory<XamlBindingHelper, Windows::UI::Xaml::Markup::IXamlBindingHelperStatics>([&](auto&& f) { return f.SetPropertyFromTimeSpan(dependencyObject, propertyToSet, value); });
}

inline void XamlBindingHelper::SetPropertyFromByte(Windows::Foundation::IInspectable const& dependencyObject, Windows::UI::Xaml::DependencyProperty const& propertyToSet, uint8_t value)
{
    impl::call_factory<XamlBindingHelper, Windows::UI::Xaml::Markup::IXamlBindingHelperStatics>([&](auto&& f) { return f.SetPropertyFromByte(dependencyObject, propertyToSet, value); });
}

inline void XamlBindingHelper::SetPropertyFromUri(Windows::Foundation::IInspectable const& dependencyObject, Windows::UI::Xaml::DependencyProperty const& propertyToSet, Windows::Foundation::Uri const& value)
{
    impl::call_factory<XamlBindingHelper, Windows::UI::Xaml::Markup::IXamlBindingHelperStatics>([&](auto&& f) { return f.SetPropertyFromUri(dependencyObject, propertyToSet, value); });
}

inline void XamlBindingHelper::SetPropertyFromObject(Windows::Foundation::IInspectable const& dependencyObject, Windows::UI::Xaml::DependencyProperty const& propertyToSet, Windows::Foundation::IInspectable const& value)
{
    impl::call_factory<XamlBindingHelper, Windows::UI::Xaml::Markup::IXamlBindingHelperStatics>([&](auto&& f) { return f.SetPropertyFromObject(dependencyObject, propertyToSet, value); });
}

inline void XamlMarkupHelper::UnloadObject(Windows::UI::Xaml::DependencyObject const& element)
{
    impl::call_factory<XamlMarkupHelper, Windows::UI::Xaml::Markup::IXamlMarkupHelperStatics>([&](auto&& f) { return f.UnloadObject(element); });
}

inline Windows::Foundation::IInspectable XamlReader::Load(param::hstring const& xaml)
{
    return impl::call_factory<XamlReader, Windows::UI::Xaml::Markup::IXamlReaderStatics>([&](auto&& f) { return f.Load(xaml); });
}

inline Windows::Foundation::IInspectable XamlReader::LoadWithInitialTemplateValidation(param::hstring const& xaml)
{
    return impl::call_factory<XamlReader, Windows::UI::Xaml::Markup::IXamlReaderStatics>([&](auto&& f) { return f.LoadWithInitialTemplateValidation(xaml); });
}

template <typename D> Windows::Foundation::IInspectable IMarkupExtensionOverridesT<D>::ProvideValue() const
{
    return shim().template try_as<IMarkupExtensionOverrides>().ProvideValue();
}

template <typename D, typename... Interfaces>
struct MarkupExtensionT :
    implements<D, Windows::UI::Xaml::Markup::IMarkupExtensionOverrides, composing, Interfaces...>,
    impl::require<D, Windows::UI::Xaml::Markup::IMarkupExtension>,
    impl::base<D, Windows::UI::Xaml::Markup::MarkupExtension>,
    Windows::UI::Xaml::Markup::IMarkupExtensionOverridesT<D>
{
    using composable = MarkupExtension;

protected:
    MarkupExtensionT()
    {
        impl::call_factory<Windows::UI::Xaml::Markup::MarkupExtension, Windows::UI::Xaml::Markup::IMarkupExtensionFactory>([&](auto&& f) { f.CreateInstance(*this, this->m_inner); });
    }
};

}

WINRT_EXPORT namespace std {

template<> struct hash<winrt::Windows::UI::Xaml::Markup::IComponentConnector> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Markup::IComponentConnector> {};
template<> struct hash<winrt::Windows::UI::Xaml::Markup::IComponentConnector2> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Markup::IComponentConnector2> {};
template<> struct hash<winrt::Windows::UI::Xaml::Markup::IDataTemplateComponent> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Markup::IDataTemplateComponent> {};
template<> struct hash<winrt::Windows::UI::Xaml::Markup::IMarkupExtension> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Markup::IMarkupExtension> {};
template<> struct hash<winrt::Windows::UI::Xaml::Markup::IMarkupExtensionFactory> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Markup::IMarkupExtensionFactory> {};
template<> struct hash<winrt::Windows::UI::Xaml::Markup::IMarkupExtensionOverrides> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Markup::IMarkupExtensionOverrides> {};
template<> struct hash<winrt::Windows::UI::Xaml::Markup::IXamlBinaryWriter> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Markup::IXamlBinaryWriter> {};
template<> struct hash<winrt::Windows::UI::Xaml::Markup::IXamlBinaryWriterStatics> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Markup::IXamlBinaryWriterStatics> {};
template<> struct hash<winrt::Windows::UI::Xaml::Markup::IXamlBindScopeDiagnostics> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Markup::IXamlBindScopeDiagnostics> {};
template<> struct hash<winrt::Windows::UI::Xaml::Markup::IXamlBindingHelper> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Markup::IXamlBindingHelper> {};
template<> struct hash<winrt::Windows::UI::Xaml::Markup::IXamlBindingHelperStatics> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Markup::IXamlBindingHelperStatics> {};
template<> struct hash<winrt::Windows::UI::Xaml::Markup::IXamlMarkupHelper> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Markup::IXamlMarkupHelper> {};
template<> struct hash<winrt::Windows::UI::Xaml::Markup::IXamlMarkupHelperStatics> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Markup::IXamlMarkupHelperStatics> {};
template<> struct hash<winrt::Windows::UI::Xaml::Markup::IXamlMember> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Markup::IXamlMember> {};
template<> struct hash<winrt::Windows::UI::Xaml::Markup::IXamlMetadataProvider> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Markup::IXamlMetadataProvider> {};
template<> struct hash<winrt::Windows::UI::Xaml::Markup::IXamlReader> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Markup::IXamlReader> {};
template<> struct hash<winrt::Windows::UI::Xaml::Markup::IXamlReaderStatics> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Markup::IXamlReaderStatics> {};
template<> struct hash<winrt::Windows::UI::Xaml::Markup::IXamlType> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Markup::IXamlType> {};
template<> struct hash<winrt::Windows::UI::Xaml::Markup::IXamlType2> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Markup::IXamlType2> {};
template<> struct hash<winrt::Windows::UI::Xaml::Markup::MarkupExtension> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Markup::MarkupExtension> {};
template<> struct hash<winrt::Windows::UI::Xaml::Markup::XamlBinaryWriter> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Markup::XamlBinaryWriter> {};
template<> struct hash<winrt::Windows::UI::Xaml::Markup::XamlBindingHelper> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Markup::XamlBindingHelper> {};
template<> struct hash<winrt::Windows::UI::Xaml::Markup::XamlMarkupHelper> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Markup::XamlMarkupHelper> {};
template<> struct hash<winrt::Windows::UI::Xaml::Markup::XamlReader> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Markup::XamlReader> {};

}
