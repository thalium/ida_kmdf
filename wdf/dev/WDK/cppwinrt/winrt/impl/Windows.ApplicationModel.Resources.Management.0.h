// C++/WinRT v1.0.190111.3

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#pragma once

WINRT_EXPORT namespace winrt::Windows::Foundation {

struct Uri;

}

WINRT_EXPORT namespace winrt::Windows::ApplicationModel::Resources::Management {

enum class IndexedResourceType : int32_t
{
    String = 0,
    Path = 1,
    EmbeddedData = 2,
};

struct IIndexedResourceCandidate;
struct IIndexedResourceQualifier;
struct IResourceIndexer;
struct IResourceIndexerFactory;
struct IResourceIndexerFactory2;
struct IndexedResourceCandidate;
struct IndexedResourceQualifier;
struct ResourceIndexer;

}

namespace winrt::impl {

template <> struct category<Windows::ApplicationModel::Resources::Management::IIndexedResourceCandidate>{ using type = interface_category; };
template <> struct category<Windows::ApplicationModel::Resources::Management::IIndexedResourceQualifier>{ using type = interface_category; };
template <> struct category<Windows::ApplicationModel::Resources::Management::IResourceIndexer>{ using type = interface_category; };
template <> struct category<Windows::ApplicationModel::Resources::Management::IResourceIndexerFactory>{ using type = interface_category; };
template <> struct category<Windows::ApplicationModel::Resources::Management::IResourceIndexerFactory2>{ using type = interface_category; };
template <> struct category<Windows::ApplicationModel::Resources::Management::IndexedResourceCandidate>{ using type = class_category; };
template <> struct category<Windows::ApplicationModel::Resources::Management::IndexedResourceQualifier>{ using type = class_category; };
template <> struct category<Windows::ApplicationModel::Resources::Management::ResourceIndexer>{ using type = class_category; };
template <> struct category<Windows::ApplicationModel::Resources::Management::IndexedResourceType>{ using type = enum_category; };
template <> struct name<Windows::ApplicationModel::Resources::Management::IIndexedResourceCandidate>{ static constexpr auto & value{ L"Windows.ApplicationModel.Resources.Management.IIndexedResourceCandidate" }; };
template <> struct name<Windows::ApplicationModel::Resources::Management::IIndexedResourceQualifier>{ static constexpr auto & value{ L"Windows.ApplicationModel.Resources.Management.IIndexedResourceQualifier" }; };
template <> struct name<Windows::ApplicationModel::Resources::Management::IResourceIndexer>{ static constexpr auto & value{ L"Windows.ApplicationModel.Resources.Management.IResourceIndexer" }; };
template <> struct name<Windows::ApplicationModel::Resources::Management::IResourceIndexerFactory>{ static constexpr auto & value{ L"Windows.ApplicationModel.Resources.Management.IResourceIndexerFactory" }; };
template <> struct name<Windows::ApplicationModel::Resources::Management::IResourceIndexerFactory2>{ static constexpr auto & value{ L"Windows.ApplicationModel.Resources.Management.IResourceIndexerFactory2" }; };
template <> struct name<Windows::ApplicationModel::Resources::Management::IndexedResourceCandidate>{ static constexpr auto & value{ L"Windows.ApplicationModel.Resources.Management.IndexedResourceCandidate" }; };
template <> struct name<Windows::ApplicationModel::Resources::Management::IndexedResourceQualifier>{ static constexpr auto & value{ L"Windows.ApplicationModel.Resources.Management.IndexedResourceQualifier" }; };
template <> struct name<Windows::ApplicationModel::Resources::Management::ResourceIndexer>{ static constexpr auto & value{ L"Windows.ApplicationModel.Resources.Management.ResourceIndexer" }; };
template <> struct name<Windows::ApplicationModel::Resources::Management::IndexedResourceType>{ static constexpr auto & value{ L"Windows.ApplicationModel.Resources.Management.IndexedResourceType" }; };
template <> struct guid_storage<Windows::ApplicationModel::Resources::Management::IIndexedResourceCandidate>{ static constexpr guid value{ 0x0E619EF3,0xFAEC,0x4414,{ 0xA9,0xD7,0x54,0xAC,0xD5,0x95,0x3F,0x29 } }; };
template <> struct guid_storage<Windows::ApplicationModel::Resources::Management::IIndexedResourceQualifier>{ static constexpr guid value{ 0xDAE3BB9B,0xD304,0x497F,{ 0xA1,0x68,0xA3,0x40,0x04,0x2C,0x8A,0xDB } }; };
template <> struct guid_storage<Windows::ApplicationModel::Resources::Management::IResourceIndexer>{ static constexpr guid value{ 0x2D4CF9A5,0xE32F,0x4AB2,{ 0x87,0x48,0x96,0x35,0x0A,0x01,0x6D,0xA3 } }; };
template <> struct guid_storage<Windows::ApplicationModel::Resources::Management::IResourceIndexerFactory>{ static constexpr guid value{ 0xB8DE3F09,0x31CD,0x4D97,{ 0xBD,0x30,0x8D,0x39,0xF7,0x42,0xBC,0x61 } }; };
template <> struct guid_storage<Windows::ApplicationModel::Resources::Management::IResourceIndexerFactory2>{ static constexpr guid value{ 0x6040F18D,0xD5E5,0x4B60,{ 0x92,0x01,0xCD,0x27,0x9C,0xBC,0xFE,0xD9 } }; };
template <> struct default_interface<Windows::ApplicationModel::Resources::Management::IndexedResourceCandidate>{ using type = Windows::ApplicationModel::Resources::Management::IIndexedResourceCandidate; };
template <> struct default_interface<Windows::ApplicationModel::Resources::Management::IndexedResourceQualifier>{ using type = Windows::ApplicationModel::Resources::Management::IIndexedResourceQualifier; };
template <> struct default_interface<Windows::ApplicationModel::Resources::Management::ResourceIndexer>{ using type = Windows::ApplicationModel::Resources::Management::IResourceIndexer; };

template <> struct abi<Windows::ApplicationModel::Resources::Management::IIndexedResourceCandidate>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL get_Type(Windows::ApplicationModel::Resources::Management::IndexedResourceType* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_Uri(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_Metadata(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_Qualifiers(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_ValueAsString(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL GetQualifierValue(void* qualifierName, void** qualifierValue) noexcept = 0;
};};

template <> struct abi<Windows::ApplicationModel::Resources::Management::IIndexedResourceQualifier>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL get_QualifierName(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_QualifierValue(void** value) noexcept = 0;
};};

template <> struct abi<Windows::ApplicationModel::Resources::Management::IResourceIndexer>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL IndexFilePath(void* filePath, void** candidate) noexcept = 0;
    virtual int32_t WINRT_CALL IndexFileContentsAsync(void* file, void** operation) noexcept = 0;
};};

template <> struct abi<Windows::ApplicationModel::Resources::Management::IResourceIndexerFactory>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL CreateResourceIndexer(void* projectRoot, void** indexer) noexcept = 0;
};};

template <> struct abi<Windows::ApplicationModel::Resources::Management::IResourceIndexerFactory2>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL CreateResourceIndexerWithExtension(void* projectRoot, void* extensionDllPath, void** indexer) noexcept = 0;
};};

template <typename D>
struct consume_Windows_ApplicationModel_Resources_Management_IIndexedResourceCandidate
{
    Windows::ApplicationModel::Resources::Management::IndexedResourceType Type() const;
    Windows::Foundation::Uri Uri() const;
    Windows::Foundation::Collections::IMapView<hstring, hstring> Metadata() const;
    Windows::Foundation::Collections::IVectorView<Windows::ApplicationModel::Resources::Management::IndexedResourceQualifier> Qualifiers() const;
    hstring ValueAsString() const;
    hstring GetQualifierValue(param::hstring const& qualifierName) const;
};
template <> struct consume<Windows::ApplicationModel::Resources::Management::IIndexedResourceCandidate> { template <typename D> using type = consume_Windows_ApplicationModel_Resources_Management_IIndexedResourceCandidate<D>; };

template <typename D>
struct consume_Windows_ApplicationModel_Resources_Management_IIndexedResourceQualifier
{
    hstring QualifierName() const;
    hstring QualifierValue() const;
};
template <> struct consume<Windows::ApplicationModel::Resources::Management::IIndexedResourceQualifier> { template <typename D> using type = consume_Windows_ApplicationModel_Resources_Management_IIndexedResourceQualifier<D>; };

template <typename D>
struct consume_Windows_ApplicationModel_Resources_Management_IResourceIndexer
{
    Windows::ApplicationModel::Resources::Management::IndexedResourceCandidate IndexFilePath(Windows::Foundation::Uri const& filePath) const;
    Windows::Foundation::IAsyncOperation<Windows::Foundation::Collections::IVectorView<Windows::ApplicationModel::Resources::Management::IndexedResourceCandidate>> IndexFileContentsAsync(Windows::Foundation::Uri const& file) const;
};
template <> struct consume<Windows::ApplicationModel::Resources::Management::IResourceIndexer> { template <typename D> using type = consume_Windows_ApplicationModel_Resources_Management_IResourceIndexer<D>; };

template <typename D>
struct consume_Windows_ApplicationModel_Resources_Management_IResourceIndexerFactory
{
    Windows::ApplicationModel::Resources::Management::ResourceIndexer CreateResourceIndexer(Windows::Foundation::Uri const& projectRoot) const;
};
template <> struct consume<Windows::ApplicationModel::Resources::Management::IResourceIndexerFactory> { template <typename D> using type = consume_Windows_ApplicationModel_Resources_Management_IResourceIndexerFactory<D>; };

template <typename D>
struct consume_Windows_ApplicationModel_Resources_Management_IResourceIndexerFactory2
{
    Windows::ApplicationModel::Resources::Management::ResourceIndexer CreateResourceIndexerWithExtension(Windows::Foundation::Uri const& projectRoot, Windows::Foundation::Uri const& extensionDllPath) const;
};
template <> struct consume<Windows::ApplicationModel::Resources::Management::IResourceIndexerFactory2> { template <typename D> using type = consume_Windows_ApplicationModel_Resources_Management_IResourceIndexerFactory2<D>; };

}
