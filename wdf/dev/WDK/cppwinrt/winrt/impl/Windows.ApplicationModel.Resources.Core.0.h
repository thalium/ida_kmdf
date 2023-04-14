// C++/WinRT v1.0.190111.3

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#pragma once

WINRT_EXPORT namespace winrt::Windows::Foundation {

struct Uri;

}

WINRT_EXPORT namespace winrt::Windows::Storage {

struct IStorageFile;
struct StorageFile;

}

WINRT_EXPORT namespace winrt::Windows::Storage::Streams {

struct IRandomAccessStream;

}

WINRT_EXPORT namespace winrt::Windows::UI {

struct UIContext;

}

WINRT_EXPORT namespace winrt::Windows::ApplicationModel::Resources::Core {

enum class ResourceCandidateKind : int32_t
{
    String = 0,
    File = 1,
    EmbeddedData = 2,
};

enum class ResourceQualifierPersistence : int32_t
{
    None = 0,
    LocalMachine = 1,
};

struct INamedResource;
struct IResourceCandidate;
struct IResourceCandidate2;
struct IResourceCandidate3;
struct IResourceContext;
struct IResourceContextStatics;
struct IResourceContextStatics2;
struct IResourceContextStatics3;
struct IResourceContextStatics4;
struct IResourceManager;
struct IResourceManager2;
struct IResourceManagerStatics;
struct IResourceMap;
struct IResourceQualifier;
struct NamedResource;
struct ResourceCandidate;
struct ResourceCandidateVectorView;
struct ResourceContext;
struct ResourceContextLanguagesVectorView;
struct ResourceManager;
struct ResourceMap;
struct ResourceMapIterator;
struct ResourceMapMapView;
struct ResourceMapMapViewIterator;
struct ResourceQualifier;
struct ResourceQualifierMapView;
struct ResourceQualifierObservableMap;
struct ResourceQualifierVectorView;
struct ResourceLayoutInfo;

}

namespace winrt::impl {

template <> struct category<Windows::ApplicationModel::Resources::Core::INamedResource>{ using type = interface_category; };
template <> struct category<Windows::ApplicationModel::Resources::Core::IResourceCandidate>{ using type = interface_category; };
template <> struct category<Windows::ApplicationModel::Resources::Core::IResourceCandidate2>{ using type = interface_category; };
template <> struct category<Windows::ApplicationModel::Resources::Core::IResourceCandidate3>{ using type = interface_category; };
template <> struct category<Windows::ApplicationModel::Resources::Core::IResourceContext>{ using type = interface_category; };
template <> struct category<Windows::ApplicationModel::Resources::Core::IResourceContextStatics>{ using type = interface_category; };
template <> struct category<Windows::ApplicationModel::Resources::Core::IResourceContextStatics2>{ using type = interface_category; };
template <> struct category<Windows::ApplicationModel::Resources::Core::IResourceContextStatics3>{ using type = interface_category; };
template <> struct category<Windows::ApplicationModel::Resources::Core::IResourceContextStatics4>{ using type = interface_category; };
template <> struct category<Windows::ApplicationModel::Resources::Core::IResourceManager>{ using type = interface_category; };
template <> struct category<Windows::ApplicationModel::Resources::Core::IResourceManager2>{ using type = interface_category; };
template <> struct category<Windows::ApplicationModel::Resources::Core::IResourceManagerStatics>{ using type = interface_category; };
template <> struct category<Windows::ApplicationModel::Resources::Core::IResourceMap>{ using type = interface_category; };
template <> struct category<Windows::ApplicationModel::Resources::Core::IResourceQualifier>{ using type = interface_category; };
template <> struct category<Windows::ApplicationModel::Resources::Core::NamedResource>{ using type = class_category; };
template <> struct category<Windows::ApplicationModel::Resources::Core::ResourceCandidate>{ using type = class_category; };
template <> struct category<Windows::ApplicationModel::Resources::Core::ResourceCandidateVectorView>{ using type = class_category; };
template <> struct category<Windows::ApplicationModel::Resources::Core::ResourceContext>{ using type = class_category; };
template <> struct category<Windows::ApplicationModel::Resources::Core::ResourceContextLanguagesVectorView>{ using type = class_category; };
template <> struct category<Windows::ApplicationModel::Resources::Core::ResourceManager>{ using type = class_category; };
template <> struct category<Windows::ApplicationModel::Resources::Core::ResourceMap>{ using type = class_category; };
template <> struct category<Windows::ApplicationModel::Resources::Core::ResourceMapIterator>{ using type = class_category; };
template <> struct category<Windows::ApplicationModel::Resources::Core::ResourceMapMapView>{ using type = class_category; };
template <> struct category<Windows::ApplicationModel::Resources::Core::ResourceMapMapViewIterator>{ using type = class_category; };
template <> struct category<Windows::ApplicationModel::Resources::Core::ResourceQualifier>{ using type = class_category; };
template <> struct category<Windows::ApplicationModel::Resources::Core::ResourceQualifierMapView>{ using type = class_category; };
template <> struct category<Windows::ApplicationModel::Resources::Core::ResourceQualifierObservableMap>{ using type = class_category; };
template <> struct category<Windows::ApplicationModel::Resources::Core::ResourceQualifierVectorView>{ using type = class_category; };
template <> struct category<Windows::ApplicationModel::Resources::Core::ResourceCandidateKind>{ using type = enum_category; };
template <> struct category<Windows::ApplicationModel::Resources::Core::ResourceQualifierPersistence>{ using type = enum_category; };
template <> struct category<Windows::ApplicationModel::Resources::Core::ResourceLayoutInfo>{ using type = struct_category<uint32_t,uint32_t,uint32_t,uint32_t,int32_t>; };
template <> struct name<Windows::ApplicationModel::Resources::Core::INamedResource>{ static constexpr auto & value{ L"Windows.ApplicationModel.Resources.Core.INamedResource" }; };
template <> struct name<Windows::ApplicationModel::Resources::Core::IResourceCandidate>{ static constexpr auto & value{ L"Windows.ApplicationModel.Resources.Core.IResourceCandidate" }; };
template <> struct name<Windows::ApplicationModel::Resources::Core::IResourceCandidate2>{ static constexpr auto & value{ L"Windows.ApplicationModel.Resources.Core.IResourceCandidate2" }; };
template <> struct name<Windows::ApplicationModel::Resources::Core::IResourceCandidate3>{ static constexpr auto & value{ L"Windows.ApplicationModel.Resources.Core.IResourceCandidate3" }; };
template <> struct name<Windows::ApplicationModel::Resources::Core::IResourceContext>{ static constexpr auto & value{ L"Windows.ApplicationModel.Resources.Core.IResourceContext" }; };
template <> struct name<Windows::ApplicationModel::Resources::Core::IResourceContextStatics>{ static constexpr auto & value{ L"Windows.ApplicationModel.Resources.Core.IResourceContextStatics" }; };
template <> struct name<Windows::ApplicationModel::Resources::Core::IResourceContextStatics2>{ static constexpr auto & value{ L"Windows.ApplicationModel.Resources.Core.IResourceContextStatics2" }; };
template <> struct name<Windows::ApplicationModel::Resources::Core::IResourceContextStatics3>{ static constexpr auto & value{ L"Windows.ApplicationModel.Resources.Core.IResourceContextStatics3" }; };
template <> struct name<Windows::ApplicationModel::Resources::Core::IResourceContextStatics4>{ static constexpr auto & value{ L"Windows.ApplicationModel.Resources.Core.IResourceContextStatics4" }; };
template <> struct name<Windows::ApplicationModel::Resources::Core::IResourceManager>{ static constexpr auto & value{ L"Windows.ApplicationModel.Resources.Core.IResourceManager" }; };
template <> struct name<Windows::ApplicationModel::Resources::Core::IResourceManager2>{ static constexpr auto & value{ L"Windows.ApplicationModel.Resources.Core.IResourceManager2" }; };
template <> struct name<Windows::ApplicationModel::Resources::Core::IResourceManagerStatics>{ static constexpr auto & value{ L"Windows.ApplicationModel.Resources.Core.IResourceManagerStatics" }; };
template <> struct name<Windows::ApplicationModel::Resources::Core::IResourceMap>{ static constexpr auto & value{ L"Windows.ApplicationModel.Resources.Core.IResourceMap" }; };
template <> struct name<Windows::ApplicationModel::Resources::Core::IResourceQualifier>{ static constexpr auto & value{ L"Windows.ApplicationModel.Resources.Core.IResourceQualifier" }; };
template <> struct name<Windows::ApplicationModel::Resources::Core::NamedResource>{ static constexpr auto & value{ L"Windows.ApplicationModel.Resources.Core.NamedResource" }; };
template <> struct name<Windows::ApplicationModel::Resources::Core::ResourceCandidate>{ static constexpr auto & value{ L"Windows.ApplicationModel.Resources.Core.ResourceCandidate" }; };
template <> struct name<Windows::ApplicationModel::Resources::Core::ResourceCandidateVectorView>{ static constexpr auto & value{ L"Windows.ApplicationModel.Resources.Core.ResourceCandidateVectorView" }; };
template <> struct name<Windows::ApplicationModel::Resources::Core::ResourceContext>{ static constexpr auto & value{ L"Windows.ApplicationModel.Resources.Core.ResourceContext" }; };
template <> struct name<Windows::ApplicationModel::Resources::Core::ResourceContextLanguagesVectorView>{ static constexpr auto & value{ L"Windows.ApplicationModel.Resources.Core.ResourceContextLanguagesVectorView" }; };
template <> struct name<Windows::ApplicationModel::Resources::Core::ResourceManager>{ static constexpr auto & value{ L"Windows.ApplicationModel.Resources.Core.ResourceManager" }; };
template <> struct name<Windows::ApplicationModel::Resources::Core::ResourceMap>{ static constexpr auto & value{ L"Windows.ApplicationModel.Resources.Core.ResourceMap" }; };
template <> struct name<Windows::ApplicationModel::Resources::Core::ResourceMapIterator>{ static constexpr auto & value{ L"Windows.ApplicationModel.Resources.Core.ResourceMapIterator" }; };
template <> struct name<Windows::ApplicationModel::Resources::Core::ResourceMapMapView>{ static constexpr auto & value{ L"Windows.ApplicationModel.Resources.Core.ResourceMapMapView" }; };
template <> struct name<Windows::ApplicationModel::Resources::Core::ResourceMapMapViewIterator>{ static constexpr auto & value{ L"Windows.ApplicationModel.Resources.Core.ResourceMapMapViewIterator" }; };
template <> struct name<Windows::ApplicationModel::Resources::Core::ResourceQualifier>{ static constexpr auto & value{ L"Windows.ApplicationModel.Resources.Core.ResourceQualifier" }; };
template <> struct name<Windows::ApplicationModel::Resources::Core::ResourceQualifierMapView>{ static constexpr auto & value{ L"Windows.ApplicationModel.Resources.Core.ResourceQualifierMapView" }; };
template <> struct name<Windows::ApplicationModel::Resources::Core::ResourceQualifierObservableMap>{ static constexpr auto & value{ L"Windows.ApplicationModel.Resources.Core.ResourceQualifierObservableMap" }; };
template <> struct name<Windows::ApplicationModel::Resources::Core::ResourceQualifierVectorView>{ static constexpr auto & value{ L"Windows.ApplicationModel.Resources.Core.ResourceQualifierVectorView" }; };
template <> struct name<Windows::ApplicationModel::Resources::Core::ResourceCandidateKind>{ static constexpr auto & value{ L"Windows.ApplicationModel.Resources.Core.ResourceCandidateKind" }; };
template <> struct name<Windows::ApplicationModel::Resources::Core::ResourceQualifierPersistence>{ static constexpr auto & value{ L"Windows.ApplicationModel.Resources.Core.ResourceQualifierPersistence" }; };
template <> struct name<Windows::ApplicationModel::Resources::Core::ResourceLayoutInfo>{ static constexpr auto & value{ L"Windows.ApplicationModel.Resources.Core.ResourceLayoutInfo" }; };
template <> struct guid_storage<Windows::ApplicationModel::Resources::Core::INamedResource>{ static constexpr guid value{ 0x1C98C219,0x0B13,0x4240,{ 0x89,0xA5,0xD4,0x95,0xDC,0x18,0x9A,0x00 } }; };
template <> struct guid_storage<Windows::ApplicationModel::Resources::Core::IResourceCandidate>{ static constexpr guid value{ 0xAF5207D9,0xC433,0x4764,{ 0xB3,0xFD,0x8F,0xA6,0xBF,0xBC,0xBA,0xDC } }; };
template <> struct guid_storage<Windows::ApplicationModel::Resources::Core::IResourceCandidate2>{ static constexpr guid value{ 0x69E5B468,0xF6FC,0x4013,{ 0xAA,0xA2,0xD5,0x3F,0x17,0x57,0xD3,0xB5 } }; };
template <> struct guid_storage<Windows::ApplicationModel::Resources::Core::IResourceCandidate3>{ static constexpr guid value{ 0x08AE97F8,0x517A,0x4674,{ 0x95,0x8C,0x4A,0x3C,0x7C,0xD2,0xCC,0x6B } }; };
template <> struct guid_storage<Windows::ApplicationModel::Resources::Core::IResourceContext>{ static constexpr guid value{ 0x2FA22F4B,0x707E,0x4B27,{ 0xAD,0x0D,0xD0,0xD8,0xCD,0x46,0x8F,0xD2 } }; };
template <> struct guid_storage<Windows::ApplicationModel::Resources::Core::IResourceContextStatics>{ static constexpr guid value{ 0x98BE9D6C,0x6338,0x4B31,{ 0x99,0xDF,0xB2,0xB4,0x42,0xF1,0x71,0x49 } }; };
template <> struct guid_storage<Windows::ApplicationModel::Resources::Core::IResourceContextStatics2>{ static constexpr guid value{ 0x41F752EF,0x12AF,0x41B9,{ 0xAB,0x36,0xB1,0xEB,0x4B,0x51,0x24,0x60 } }; };
template <> struct guid_storage<Windows::ApplicationModel::Resources::Core::IResourceContextStatics3>{ static constexpr guid value{ 0x20CF492C,0xAF0F,0x450B,{ 0x9D,0xA6,0x10,0x6D,0xD0,0xC2,0x9A,0x39 } }; };
template <> struct guid_storage<Windows::ApplicationModel::Resources::Core::IResourceContextStatics4>{ static constexpr guid value{ 0x22EB9CCD,0xFB31,0x4BFA,{ 0xB8,0x6B,0xDF,0x9D,0x9D,0x7B,0xDC,0x39 } }; };
template <> struct guid_storage<Windows::ApplicationModel::Resources::Core::IResourceManager>{ static constexpr guid value{ 0xF744D97B,0x9988,0x44FB,{ 0xAB,0xD6,0x53,0x78,0x84,0x4C,0xFA,0x8B } }; };
template <> struct guid_storage<Windows::ApplicationModel::Resources::Core::IResourceManager2>{ static constexpr guid value{ 0x9D66FE6C,0xA4D7,0x4C23,{ 0x9E,0x85,0x67,0x5F,0x30,0x4C,0x25,0x2D } }; };
template <> struct guid_storage<Windows::ApplicationModel::Resources::Core::IResourceManagerStatics>{ static constexpr guid value{ 0x1CC0FDFC,0x69EE,0x4E43,{ 0x99,0x01,0x47,0xF1,0x26,0x87,0xBA,0xF7 } }; };
template <> struct guid_storage<Windows::ApplicationModel::Resources::Core::IResourceMap>{ static constexpr guid value{ 0x72284824,0xDB8C,0x42F8,{ 0xB0,0x8C,0x53,0xFF,0x35,0x7D,0xAD,0x82 } }; };
template <> struct guid_storage<Windows::ApplicationModel::Resources::Core::IResourceQualifier>{ static constexpr guid value{ 0x785DA5B2,0x4AFD,0x4376,{ 0xA8,0x88,0xC5,0xF9,0xA6,0xB7,0xA0,0x5C } }; };
template <> struct default_interface<Windows::ApplicationModel::Resources::Core::NamedResource>{ using type = Windows::ApplicationModel::Resources::Core::INamedResource; };
template <> struct default_interface<Windows::ApplicationModel::Resources::Core::ResourceCandidate>{ using type = Windows::ApplicationModel::Resources::Core::IResourceCandidate; };
template <> struct default_interface<Windows::ApplicationModel::Resources::Core::ResourceCandidateVectorView>{ using type = Windows::Foundation::Collections::IVectorView<Windows::ApplicationModel::Resources::Core::ResourceCandidate>; };
template <> struct default_interface<Windows::ApplicationModel::Resources::Core::ResourceContext>{ using type = Windows::ApplicationModel::Resources::Core::IResourceContext; };
template <> struct default_interface<Windows::ApplicationModel::Resources::Core::ResourceContextLanguagesVectorView>{ using type = Windows::Foundation::Collections::IVectorView<hstring>; };
template <> struct default_interface<Windows::ApplicationModel::Resources::Core::ResourceManager>{ using type = Windows::ApplicationModel::Resources::Core::IResourceManager; };
template <> struct default_interface<Windows::ApplicationModel::Resources::Core::ResourceMap>{ using type = Windows::ApplicationModel::Resources::Core::IResourceMap; };
template <> struct default_interface<Windows::ApplicationModel::Resources::Core::ResourceMapIterator>{ using type = Windows::Foundation::Collections::IIterator<Windows::Foundation::Collections::IKeyValuePair<hstring, Windows::ApplicationModel::Resources::Core::NamedResource>>; };
template <> struct default_interface<Windows::ApplicationModel::Resources::Core::ResourceMapMapView>{ using type = Windows::Foundation::Collections::IMapView<hstring, Windows::ApplicationModel::Resources::Core::ResourceMap>; };
template <> struct default_interface<Windows::ApplicationModel::Resources::Core::ResourceMapMapViewIterator>{ using type = Windows::Foundation::Collections::IIterator<Windows::Foundation::Collections::IKeyValuePair<hstring, Windows::ApplicationModel::Resources::Core::ResourceMap>>; };
template <> struct default_interface<Windows::ApplicationModel::Resources::Core::ResourceQualifier>{ using type = Windows::ApplicationModel::Resources::Core::IResourceQualifier; };
template <> struct default_interface<Windows::ApplicationModel::Resources::Core::ResourceQualifierMapView>{ using type = Windows::Foundation::Collections::IMapView<hstring, hstring>; };
template <> struct default_interface<Windows::ApplicationModel::Resources::Core::ResourceQualifierObservableMap>{ using type = Windows::Foundation::Collections::IObservableMap<hstring, hstring>; };
template <> struct default_interface<Windows::ApplicationModel::Resources::Core::ResourceQualifierVectorView>{ using type = Windows::Foundation::Collections::IVectorView<Windows::ApplicationModel::Resources::Core::ResourceQualifier>; };

template <> struct abi<Windows::ApplicationModel::Resources::Core::INamedResource>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL get_Uri(void** uri) noexcept = 0;
    virtual int32_t WINRT_CALL get_Candidates(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL Resolve(void** result) noexcept = 0;
    virtual int32_t WINRT_CALL ResolveForContext(void* resourceContext, void** result) noexcept = 0;
    virtual int32_t WINRT_CALL ResolveAll(void** result) noexcept = 0;
    virtual int32_t WINRT_CALL ResolveAllForContext(void* resourceContext, void** instances) noexcept = 0;
};};

template <> struct abi<Windows::ApplicationModel::Resources::Core::IResourceCandidate>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL get_Qualifiers(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_IsMatch(bool* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_IsMatchAsDefault(bool* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_IsDefault(bool* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_ValueAsString(void** result) noexcept = 0;
    virtual int32_t WINRT_CALL GetValueAsFileAsync(void** operation) noexcept = 0;
    virtual int32_t WINRT_CALL GetQualifierValue(void* qualifierName, void** value) noexcept = 0;
};};

template <> struct abi<Windows::ApplicationModel::Resources::Core::IResourceCandidate2>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL GetValueAsStreamAsync(void** operation) noexcept = 0;
};};

template <> struct abi<Windows::ApplicationModel::Resources::Core::IResourceCandidate3>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL get_Kind(Windows::ApplicationModel::Resources::Core::ResourceCandidateKind* value) noexcept = 0;
};};

template <> struct abi<Windows::ApplicationModel::Resources::Core::IResourceContext>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL get_QualifierValues(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL Reset() noexcept = 0;
    virtual int32_t WINRT_CALL ResetQualifierValues(void* qualifierNames) noexcept = 0;
    virtual int32_t WINRT_CALL OverrideToMatch(void* result) noexcept = 0;
    virtual int32_t WINRT_CALL Clone(void** clone) noexcept = 0;
    virtual int32_t WINRT_CALL get_Languages(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL put_Languages(void* languages) noexcept = 0;
};};

template <> struct abi<Windows::ApplicationModel::Resources::Core::IResourceContextStatics>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL CreateMatchingContext(void* result, void** value) noexcept = 0;
};};

template <> struct abi<Windows::ApplicationModel::Resources::Core::IResourceContextStatics2>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL GetForCurrentView(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL SetGlobalQualifierValue(void* key, void* value) noexcept = 0;
    virtual int32_t WINRT_CALL ResetGlobalQualifierValues() noexcept = 0;
    virtual int32_t WINRT_CALL ResetGlobalQualifierValuesForSpecifiedQualifiers(void* qualifierNames) noexcept = 0;
    virtual int32_t WINRT_CALL GetForViewIndependentUse(void** loader) noexcept = 0;
};};

template <> struct abi<Windows::ApplicationModel::Resources::Core::IResourceContextStatics3>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL SetGlobalQualifierValueWithPersistence(void* key, void* value, Windows::ApplicationModel::Resources::Core::ResourceQualifierPersistence persistence) noexcept = 0;
};};

template <> struct abi<Windows::ApplicationModel::Resources::Core::IResourceContextStatics4>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL GetForUIContext(void* context, void** value) noexcept = 0;
};};

template <> struct abi<Windows::ApplicationModel::Resources::Core::IResourceManager>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL get_MainResourceMap(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_AllResourceMaps(void** maps) noexcept = 0;
    virtual int32_t WINRT_CALL get_DefaultContext(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL LoadPriFiles(void* files) noexcept = 0;
    virtual int32_t WINRT_CALL UnloadPriFiles(void* files) noexcept = 0;
};};

template <> struct abi<Windows::ApplicationModel::Resources::Core::IResourceManager2>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL GetAllNamedResourcesForPackage(void* packageName, struct struct_Windows_ApplicationModel_Resources_Core_ResourceLayoutInfo resourceLayoutInfo, void** table) noexcept = 0;
    virtual int32_t WINRT_CALL GetAllSubtreesForPackage(void* packageName, struct struct_Windows_ApplicationModel_Resources_Core_ResourceLayoutInfo resourceLayoutInfo, void** table) noexcept = 0;
};};

template <> struct abi<Windows::ApplicationModel::Resources::Core::IResourceManagerStatics>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL get_Current(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL IsResourceReference(void* resourceReference, bool* isReference) noexcept = 0;
};};

template <> struct abi<Windows::ApplicationModel::Resources::Core::IResourceMap>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL get_Uri(void** uri) noexcept = 0;
    virtual int32_t WINRT_CALL GetValue(void* resource, void** value) noexcept = 0;
    virtual int32_t WINRT_CALL GetValueForContext(void* resource, void* context, void** value) noexcept = 0;
    virtual int32_t WINRT_CALL GetSubtree(void* reference, void** map) noexcept = 0;
};};

template <> struct abi<Windows::ApplicationModel::Resources::Core::IResourceQualifier>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL get_QualifierName(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_QualifierValue(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_IsDefault(bool* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_IsMatch(bool* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_Score(double* value) noexcept = 0;
};};

template <typename D>
struct consume_Windows_ApplicationModel_Resources_Core_INamedResource
{
    Windows::Foundation::Uri Uri() const;
    Windows::Foundation::Collections::IVectorView<Windows::ApplicationModel::Resources::Core::ResourceCandidate> Candidates() const;
    Windows::ApplicationModel::Resources::Core::ResourceCandidate Resolve() const;
    Windows::ApplicationModel::Resources::Core::ResourceCandidate Resolve(Windows::ApplicationModel::Resources::Core::ResourceContext const& resourceContext) const;
    Windows::Foundation::Collections::IVectorView<Windows::ApplicationModel::Resources::Core::ResourceCandidate> ResolveAll() const;
    Windows::Foundation::Collections::IVectorView<Windows::ApplicationModel::Resources::Core::ResourceCandidate> ResolveAll(Windows::ApplicationModel::Resources::Core::ResourceContext const& resourceContext) const;
};
template <> struct consume<Windows::ApplicationModel::Resources::Core::INamedResource> { template <typename D> using type = consume_Windows_ApplicationModel_Resources_Core_INamedResource<D>; };

template <typename D>
struct consume_Windows_ApplicationModel_Resources_Core_IResourceCandidate
{
    Windows::Foundation::Collections::IVectorView<Windows::ApplicationModel::Resources::Core::ResourceQualifier> Qualifiers() const;
    bool IsMatch() const;
    bool IsMatchAsDefault() const;
    bool IsDefault() const;
    hstring ValueAsString() const;
    Windows::Foundation::IAsyncOperation<Windows::Storage::StorageFile> GetValueAsFileAsync() const;
    hstring GetQualifierValue(param::hstring const& qualifierName) const;
};
template <> struct consume<Windows::ApplicationModel::Resources::Core::IResourceCandidate> { template <typename D> using type = consume_Windows_ApplicationModel_Resources_Core_IResourceCandidate<D>; };

template <typename D>
struct consume_Windows_ApplicationModel_Resources_Core_IResourceCandidate2
{
    Windows::Foundation::IAsyncOperation<Windows::Storage::Streams::IRandomAccessStream> GetValueAsStreamAsync() const;
};
template <> struct consume<Windows::ApplicationModel::Resources::Core::IResourceCandidate2> { template <typename D> using type = consume_Windows_ApplicationModel_Resources_Core_IResourceCandidate2<D>; };

template <typename D>
struct consume_Windows_ApplicationModel_Resources_Core_IResourceCandidate3
{
    Windows::ApplicationModel::Resources::Core::ResourceCandidateKind Kind() const;
};
template <> struct consume<Windows::ApplicationModel::Resources::Core::IResourceCandidate3> { template <typename D> using type = consume_Windows_ApplicationModel_Resources_Core_IResourceCandidate3<D>; };

template <typename D>
struct consume_Windows_ApplicationModel_Resources_Core_IResourceContext
{
    Windows::Foundation::Collections::IObservableMap<hstring, hstring> QualifierValues() const;
    void Reset() const;
    void Reset(param::iterable<hstring> const& qualifierNames) const;
    void OverrideToMatch(param::iterable<Windows::ApplicationModel::Resources::Core::ResourceQualifier> const& result) const;
    Windows::ApplicationModel::Resources::Core::ResourceContext Clone() const;
    Windows::Foundation::Collections::IVectorView<hstring> Languages() const;
    void Languages(param::async_vector_view<hstring> const& languages) const;
};
template <> struct consume<Windows::ApplicationModel::Resources::Core::IResourceContext> { template <typename D> using type = consume_Windows_ApplicationModel_Resources_Core_IResourceContext<D>; };

template <typename D>
struct consume_Windows_ApplicationModel_Resources_Core_IResourceContextStatics
{
    Windows::ApplicationModel::Resources::Core::ResourceContext CreateMatchingContext(param::iterable<Windows::ApplicationModel::Resources::Core::ResourceQualifier> const& result) const;
};
template <> struct consume<Windows::ApplicationModel::Resources::Core::IResourceContextStatics> { template <typename D> using type = consume_Windows_ApplicationModel_Resources_Core_IResourceContextStatics<D>; };

template <typename D>
struct consume_Windows_ApplicationModel_Resources_Core_IResourceContextStatics2
{
    Windows::ApplicationModel::Resources::Core::ResourceContext GetForCurrentView() const;
    void SetGlobalQualifierValue(param::hstring const& key, param::hstring const& value) const;
    void ResetGlobalQualifierValues() const;
    void ResetGlobalQualifierValues(param::iterable<hstring> const& qualifierNames) const;
    Windows::ApplicationModel::Resources::Core::ResourceContext GetForViewIndependentUse() const;
};
template <> struct consume<Windows::ApplicationModel::Resources::Core::IResourceContextStatics2> { template <typename D> using type = consume_Windows_ApplicationModel_Resources_Core_IResourceContextStatics2<D>; };

template <typename D>
struct consume_Windows_ApplicationModel_Resources_Core_IResourceContextStatics3
{
    void SetGlobalQualifierValue(param::hstring const& key, param::hstring const& value, Windows::ApplicationModel::Resources::Core::ResourceQualifierPersistence const& persistence) const;
};
template <> struct consume<Windows::ApplicationModel::Resources::Core::IResourceContextStatics3> { template <typename D> using type = consume_Windows_ApplicationModel_Resources_Core_IResourceContextStatics3<D>; };

template <typename D>
struct consume_Windows_ApplicationModel_Resources_Core_IResourceContextStatics4
{
    Windows::ApplicationModel::Resources::Core::ResourceContext GetForUIContext(Windows::UI::UIContext const& context) const;
};
template <> struct consume<Windows::ApplicationModel::Resources::Core::IResourceContextStatics4> { template <typename D> using type = consume_Windows_ApplicationModel_Resources_Core_IResourceContextStatics4<D>; };

template <typename D>
struct consume_Windows_ApplicationModel_Resources_Core_IResourceManager
{
    Windows::ApplicationModel::Resources::Core::ResourceMap MainResourceMap() const;
    Windows::Foundation::Collections::IMapView<hstring, Windows::ApplicationModel::Resources::Core::ResourceMap> AllResourceMaps() const;
    Windows::ApplicationModel::Resources::Core::ResourceContext DefaultContext() const;
    void LoadPriFiles(param::iterable<Windows::Storage::IStorageFile> const& files) const;
    void UnloadPriFiles(param::iterable<Windows::Storage::IStorageFile> const& files) const;
};
template <> struct consume<Windows::ApplicationModel::Resources::Core::IResourceManager> { template <typename D> using type = consume_Windows_ApplicationModel_Resources_Core_IResourceManager<D>; };

template <typename D>
struct consume_Windows_ApplicationModel_Resources_Core_IResourceManager2
{
    Windows::Foundation::Collections::IVectorView<Windows::ApplicationModel::Resources::Core::NamedResource> GetAllNamedResourcesForPackage(param::hstring const& packageName, Windows::ApplicationModel::Resources::Core::ResourceLayoutInfo const& resourceLayoutInfo) const;
    Windows::Foundation::Collections::IVectorView<Windows::ApplicationModel::Resources::Core::ResourceMap> GetAllSubtreesForPackage(param::hstring const& packageName, Windows::ApplicationModel::Resources::Core::ResourceLayoutInfo const& resourceLayoutInfo) const;
};
template <> struct consume<Windows::ApplicationModel::Resources::Core::IResourceManager2> { template <typename D> using type = consume_Windows_ApplicationModel_Resources_Core_IResourceManager2<D>; };

template <typename D>
struct consume_Windows_ApplicationModel_Resources_Core_IResourceManagerStatics
{
    Windows::ApplicationModel::Resources::Core::ResourceManager Current() const;
    bool IsResourceReference(param::hstring const& resourceReference) const;
};
template <> struct consume<Windows::ApplicationModel::Resources::Core::IResourceManagerStatics> { template <typename D> using type = consume_Windows_ApplicationModel_Resources_Core_IResourceManagerStatics<D>; };

template <typename D>
struct consume_Windows_ApplicationModel_Resources_Core_IResourceMap
{
    Windows::Foundation::Uri Uri() const;
    Windows::ApplicationModel::Resources::Core::ResourceCandidate GetValue(param::hstring const& resource) const;
    Windows::ApplicationModel::Resources::Core::ResourceCandidate GetValue(param::hstring const& resource, Windows::ApplicationModel::Resources::Core::ResourceContext const& context) const;
    Windows::ApplicationModel::Resources::Core::ResourceMap GetSubtree(param::hstring const& reference) const;
};
template <> struct consume<Windows::ApplicationModel::Resources::Core::IResourceMap> { template <typename D> using type = consume_Windows_ApplicationModel_Resources_Core_IResourceMap<D>; };

template <typename D>
struct consume_Windows_ApplicationModel_Resources_Core_IResourceQualifier
{
    hstring QualifierName() const;
    hstring QualifierValue() const;
    bool IsDefault() const;
    bool IsMatch() const;
    double Score() const;
};
template <> struct consume<Windows::ApplicationModel::Resources::Core::IResourceQualifier> { template <typename D> using type = consume_Windows_ApplicationModel_Resources_Core_IResourceQualifier<D>; };

struct struct_Windows_ApplicationModel_Resources_Core_ResourceLayoutInfo
{
    uint32_t MajorVersion;
    uint32_t MinorVersion;
    uint32_t ResourceSubtreeCount;
    uint32_t NamedResourceCount;
    int32_t Checksum;
};
template <> struct abi<Windows::ApplicationModel::Resources::Core::ResourceLayoutInfo>{ using type = struct_Windows_ApplicationModel_Resources_Core_ResourceLayoutInfo; };


}
