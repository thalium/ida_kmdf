// C++/WinRT v1.0.190111.3

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#pragma once

#include "winrt/base.h"

#include "winrt/Windows.Foundation.h"
#include "winrt/Windows.Foundation.Collections.h"
#include "winrt/impl/Windows.Foundation.2.h"
#include "winrt/impl/Windows.Storage.2.h"
#include "winrt/impl/Windows.Storage.Streams.2.h"
#include "winrt/impl/Windows.UI.2.h"
#include "winrt/impl/Windows.Foundation.Collections.2.h"
#include "winrt/impl/Windows.ApplicationModel.Resources.Core.2.h"
#include "winrt/Windows.ApplicationModel.Resources.h"

namespace winrt::impl {

template <typename D> Windows::Foundation::Uri consume_Windows_ApplicationModel_Resources_Core_INamedResource<D>::Uri() const
{
    Windows::Foundation::Uri uri{ nullptr };
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Resources::Core::INamedResource)->get_Uri(put_abi(uri)));
    return uri;
}

template <typename D> Windows::Foundation::Collections::IVectorView<Windows::ApplicationModel::Resources::Core::ResourceCandidate> consume_Windows_ApplicationModel_Resources_Core_INamedResource<D>::Candidates() const
{
    Windows::Foundation::Collections::IVectorView<Windows::ApplicationModel::Resources::Core::ResourceCandidate> value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Resources::Core::INamedResource)->get_Candidates(put_abi(value)));
    return value;
}

template <typename D> Windows::ApplicationModel::Resources::Core::ResourceCandidate consume_Windows_ApplicationModel_Resources_Core_INamedResource<D>::Resolve() const
{
    Windows::ApplicationModel::Resources::Core::ResourceCandidate result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Resources::Core::INamedResource)->Resolve(put_abi(result)));
    return result;
}

template <typename D> Windows::ApplicationModel::Resources::Core::ResourceCandidate consume_Windows_ApplicationModel_Resources_Core_INamedResource<D>::Resolve(Windows::ApplicationModel::Resources::Core::ResourceContext const& resourceContext) const
{
    Windows::ApplicationModel::Resources::Core::ResourceCandidate result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Resources::Core::INamedResource)->ResolveForContext(get_abi(resourceContext), put_abi(result)));
    return result;
}

template <typename D> Windows::Foundation::Collections::IVectorView<Windows::ApplicationModel::Resources::Core::ResourceCandidate> consume_Windows_ApplicationModel_Resources_Core_INamedResource<D>::ResolveAll() const
{
    Windows::Foundation::Collections::IVectorView<Windows::ApplicationModel::Resources::Core::ResourceCandidate> result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Resources::Core::INamedResource)->ResolveAll(put_abi(result)));
    return result;
}

template <typename D> Windows::Foundation::Collections::IVectorView<Windows::ApplicationModel::Resources::Core::ResourceCandidate> consume_Windows_ApplicationModel_Resources_Core_INamedResource<D>::ResolveAll(Windows::ApplicationModel::Resources::Core::ResourceContext const& resourceContext) const
{
    Windows::Foundation::Collections::IVectorView<Windows::ApplicationModel::Resources::Core::ResourceCandidate> instances{ nullptr };
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Resources::Core::INamedResource)->ResolveAllForContext(get_abi(resourceContext), put_abi(instances)));
    return instances;
}

template <typename D> Windows::Foundation::Collections::IVectorView<Windows::ApplicationModel::Resources::Core::ResourceQualifier> consume_Windows_ApplicationModel_Resources_Core_IResourceCandidate<D>::Qualifiers() const
{
    Windows::Foundation::Collections::IVectorView<Windows::ApplicationModel::Resources::Core::ResourceQualifier> value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Resources::Core::IResourceCandidate)->get_Qualifiers(put_abi(value)));
    return value;
}

template <typename D> bool consume_Windows_ApplicationModel_Resources_Core_IResourceCandidate<D>::IsMatch() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Resources::Core::IResourceCandidate)->get_IsMatch(&value));
    return value;
}

template <typename D> bool consume_Windows_ApplicationModel_Resources_Core_IResourceCandidate<D>::IsMatchAsDefault() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Resources::Core::IResourceCandidate)->get_IsMatchAsDefault(&value));
    return value;
}

template <typename D> bool consume_Windows_ApplicationModel_Resources_Core_IResourceCandidate<D>::IsDefault() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Resources::Core::IResourceCandidate)->get_IsDefault(&value));
    return value;
}

template <typename D> hstring consume_Windows_ApplicationModel_Resources_Core_IResourceCandidate<D>::ValueAsString() const
{
    hstring result{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Resources::Core::IResourceCandidate)->get_ValueAsString(put_abi(result)));
    return result;
}

template <typename D> Windows::Foundation::IAsyncOperation<Windows::Storage::StorageFile> consume_Windows_ApplicationModel_Resources_Core_IResourceCandidate<D>::GetValueAsFileAsync() const
{
    Windows::Foundation::IAsyncOperation<Windows::Storage::StorageFile> operation{ nullptr };
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Resources::Core::IResourceCandidate)->GetValueAsFileAsync(put_abi(operation)));
    return operation;
}

template <typename D> hstring consume_Windows_ApplicationModel_Resources_Core_IResourceCandidate<D>::GetQualifierValue(param::hstring const& qualifierName) const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Resources::Core::IResourceCandidate)->GetQualifierValue(get_abi(qualifierName), put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::IAsyncOperation<Windows::Storage::Streams::IRandomAccessStream> consume_Windows_ApplicationModel_Resources_Core_IResourceCandidate2<D>::GetValueAsStreamAsync() const
{
    Windows::Foundation::IAsyncOperation<Windows::Storage::Streams::IRandomAccessStream> operation{ nullptr };
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Resources::Core::IResourceCandidate2)->GetValueAsStreamAsync(put_abi(operation)));
    return operation;
}

template <typename D> Windows::ApplicationModel::Resources::Core::ResourceCandidateKind consume_Windows_ApplicationModel_Resources_Core_IResourceCandidate3<D>::Kind() const
{
    Windows::ApplicationModel::Resources::Core::ResourceCandidateKind value{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Resources::Core::IResourceCandidate3)->get_Kind(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::Collections::IObservableMap<hstring, hstring> consume_Windows_ApplicationModel_Resources_Core_IResourceContext<D>::QualifierValues() const
{
    Windows::Foundation::Collections::IObservableMap<hstring, hstring> value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Resources::Core::IResourceContext)->get_QualifierValues(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_ApplicationModel_Resources_Core_IResourceContext<D>::Reset() const
{
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Resources::Core::IResourceContext)->Reset());
}

template <typename D> void consume_Windows_ApplicationModel_Resources_Core_IResourceContext<D>::Reset(param::iterable<hstring> const& qualifierNames) const
{
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Resources::Core::IResourceContext)->ResetQualifierValues(get_abi(qualifierNames)));
}

template <typename D> void consume_Windows_ApplicationModel_Resources_Core_IResourceContext<D>::OverrideToMatch(param::iterable<Windows::ApplicationModel::Resources::Core::ResourceQualifier> const& result) const
{
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Resources::Core::IResourceContext)->OverrideToMatch(get_abi(result)));
}

template <typename D> Windows::ApplicationModel::Resources::Core::ResourceContext consume_Windows_ApplicationModel_Resources_Core_IResourceContext<D>::Clone() const
{
    Windows::ApplicationModel::Resources::Core::ResourceContext clone{ nullptr };
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Resources::Core::IResourceContext)->Clone(put_abi(clone)));
    return clone;
}

template <typename D> Windows::Foundation::Collections::IVectorView<hstring> consume_Windows_ApplicationModel_Resources_Core_IResourceContext<D>::Languages() const
{
    Windows::Foundation::Collections::IVectorView<hstring> value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Resources::Core::IResourceContext)->get_Languages(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_ApplicationModel_Resources_Core_IResourceContext<D>::Languages(param::async_vector_view<hstring> const& languages) const
{
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Resources::Core::IResourceContext)->put_Languages(get_abi(languages)));
}

template <typename D> Windows::ApplicationModel::Resources::Core::ResourceContext consume_Windows_ApplicationModel_Resources_Core_IResourceContextStatics<D>::CreateMatchingContext(param::iterable<Windows::ApplicationModel::Resources::Core::ResourceQualifier> const& result) const
{
    Windows::ApplicationModel::Resources::Core::ResourceContext value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Resources::Core::IResourceContextStatics)->CreateMatchingContext(get_abi(result), put_abi(value)));
    return value;
}

template <typename D> Windows::ApplicationModel::Resources::Core::ResourceContext consume_Windows_ApplicationModel_Resources_Core_IResourceContextStatics2<D>::GetForCurrentView() const
{
    Windows::ApplicationModel::Resources::Core::ResourceContext value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Resources::Core::IResourceContextStatics2)->GetForCurrentView(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_ApplicationModel_Resources_Core_IResourceContextStatics2<D>::SetGlobalQualifierValue(param::hstring const& key, param::hstring const& value) const
{
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Resources::Core::IResourceContextStatics2)->SetGlobalQualifierValue(get_abi(key), get_abi(value)));
}

template <typename D> void consume_Windows_ApplicationModel_Resources_Core_IResourceContextStatics2<D>::ResetGlobalQualifierValues() const
{
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Resources::Core::IResourceContextStatics2)->ResetGlobalQualifierValues());
}

template <typename D> void consume_Windows_ApplicationModel_Resources_Core_IResourceContextStatics2<D>::ResetGlobalQualifierValues(param::iterable<hstring> const& qualifierNames) const
{
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Resources::Core::IResourceContextStatics2)->ResetGlobalQualifierValuesForSpecifiedQualifiers(get_abi(qualifierNames)));
}

template <typename D> Windows::ApplicationModel::Resources::Core::ResourceContext consume_Windows_ApplicationModel_Resources_Core_IResourceContextStatics2<D>::GetForViewIndependentUse() const
{
    Windows::ApplicationModel::Resources::Core::ResourceContext loader{ nullptr };
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Resources::Core::IResourceContextStatics2)->GetForViewIndependentUse(put_abi(loader)));
    return loader;
}

template <typename D> void consume_Windows_ApplicationModel_Resources_Core_IResourceContextStatics3<D>::SetGlobalQualifierValue(param::hstring const& key, param::hstring const& value, Windows::ApplicationModel::Resources::Core::ResourceQualifierPersistence const& persistence) const
{
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Resources::Core::IResourceContextStatics3)->SetGlobalQualifierValueWithPersistence(get_abi(key), get_abi(value), get_abi(persistence)));
}

template <typename D> Windows::ApplicationModel::Resources::Core::ResourceContext consume_Windows_ApplicationModel_Resources_Core_IResourceContextStatics4<D>::GetForUIContext(Windows::UI::UIContext const& context) const
{
    Windows::ApplicationModel::Resources::Core::ResourceContext value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Resources::Core::IResourceContextStatics4)->GetForUIContext(get_abi(context), put_abi(value)));
    return value;
}

template <typename D> Windows::ApplicationModel::Resources::Core::ResourceMap consume_Windows_ApplicationModel_Resources_Core_IResourceManager<D>::MainResourceMap() const
{
    Windows::ApplicationModel::Resources::Core::ResourceMap value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Resources::Core::IResourceManager)->get_MainResourceMap(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::Collections::IMapView<hstring, Windows::ApplicationModel::Resources::Core::ResourceMap> consume_Windows_ApplicationModel_Resources_Core_IResourceManager<D>::AllResourceMaps() const
{
    Windows::Foundation::Collections::IMapView<hstring, Windows::ApplicationModel::Resources::Core::ResourceMap> maps{ nullptr };
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Resources::Core::IResourceManager)->get_AllResourceMaps(put_abi(maps)));
    return maps;
}

template <typename D> Windows::ApplicationModel::Resources::Core::ResourceContext consume_Windows_ApplicationModel_Resources_Core_IResourceManager<D>::DefaultContext() const
{
    Windows::ApplicationModel::Resources::Core::ResourceContext value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Resources::Core::IResourceManager)->get_DefaultContext(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_ApplicationModel_Resources_Core_IResourceManager<D>::LoadPriFiles(param::iterable<Windows::Storage::IStorageFile> const& files) const
{
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Resources::Core::IResourceManager)->LoadPriFiles(get_abi(files)));
}

template <typename D> void consume_Windows_ApplicationModel_Resources_Core_IResourceManager<D>::UnloadPriFiles(param::iterable<Windows::Storage::IStorageFile> const& files) const
{
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Resources::Core::IResourceManager)->UnloadPriFiles(get_abi(files)));
}

template <typename D> Windows::Foundation::Collections::IVectorView<Windows::ApplicationModel::Resources::Core::NamedResource> consume_Windows_ApplicationModel_Resources_Core_IResourceManager2<D>::GetAllNamedResourcesForPackage(param::hstring const& packageName, Windows::ApplicationModel::Resources::Core::ResourceLayoutInfo const& resourceLayoutInfo) const
{
    Windows::Foundation::Collections::IVectorView<Windows::ApplicationModel::Resources::Core::NamedResource> table{ nullptr };
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Resources::Core::IResourceManager2)->GetAllNamedResourcesForPackage(get_abi(packageName), get_abi(resourceLayoutInfo), put_abi(table)));
    return table;
}

template <typename D> Windows::Foundation::Collections::IVectorView<Windows::ApplicationModel::Resources::Core::ResourceMap> consume_Windows_ApplicationModel_Resources_Core_IResourceManager2<D>::GetAllSubtreesForPackage(param::hstring const& packageName, Windows::ApplicationModel::Resources::Core::ResourceLayoutInfo const& resourceLayoutInfo) const
{
    Windows::Foundation::Collections::IVectorView<Windows::ApplicationModel::Resources::Core::ResourceMap> table{ nullptr };
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Resources::Core::IResourceManager2)->GetAllSubtreesForPackage(get_abi(packageName), get_abi(resourceLayoutInfo), put_abi(table)));
    return table;
}

template <typename D> Windows::ApplicationModel::Resources::Core::ResourceManager consume_Windows_ApplicationModel_Resources_Core_IResourceManagerStatics<D>::Current() const
{
    Windows::ApplicationModel::Resources::Core::ResourceManager value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Resources::Core::IResourceManagerStatics)->get_Current(put_abi(value)));
    return value;
}

template <typename D> bool consume_Windows_ApplicationModel_Resources_Core_IResourceManagerStatics<D>::IsResourceReference(param::hstring const& resourceReference) const
{
    bool isReference{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Resources::Core::IResourceManagerStatics)->IsResourceReference(get_abi(resourceReference), &isReference));
    return isReference;
}

template <typename D> Windows::Foundation::Uri consume_Windows_ApplicationModel_Resources_Core_IResourceMap<D>::Uri() const
{
    Windows::Foundation::Uri uri{ nullptr };
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Resources::Core::IResourceMap)->get_Uri(put_abi(uri)));
    return uri;
}

template <typename D> Windows::ApplicationModel::Resources::Core::ResourceCandidate consume_Windows_ApplicationModel_Resources_Core_IResourceMap<D>::GetValue(param::hstring const& resource) const
{
    Windows::ApplicationModel::Resources::Core::ResourceCandidate value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Resources::Core::IResourceMap)->GetValue(get_abi(resource), put_abi(value)));
    return value;
}

template <typename D> Windows::ApplicationModel::Resources::Core::ResourceCandidate consume_Windows_ApplicationModel_Resources_Core_IResourceMap<D>::GetValue(param::hstring const& resource, Windows::ApplicationModel::Resources::Core::ResourceContext const& context) const
{
    Windows::ApplicationModel::Resources::Core::ResourceCandidate value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Resources::Core::IResourceMap)->GetValueForContext(get_abi(resource), get_abi(context), put_abi(value)));
    return value;
}

template <typename D> Windows::ApplicationModel::Resources::Core::ResourceMap consume_Windows_ApplicationModel_Resources_Core_IResourceMap<D>::GetSubtree(param::hstring const& reference) const
{
    Windows::ApplicationModel::Resources::Core::ResourceMap map{ nullptr };
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Resources::Core::IResourceMap)->GetSubtree(get_abi(reference), put_abi(map)));
    return map;
}

template <typename D> hstring consume_Windows_ApplicationModel_Resources_Core_IResourceQualifier<D>::QualifierName() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Resources::Core::IResourceQualifier)->get_QualifierName(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_ApplicationModel_Resources_Core_IResourceQualifier<D>::QualifierValue() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Resources::Core::IResourceQualifier)->get_QualifierValue(put_abi(value)));
    return value;
}

template <typename D> bool consume_Windows_ApplicationModel_Resources_Core_IResourceQualifier<D>::IsDefault() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Resources::Core::IResourceQualifier)->get_IsDefault(&value));
    return value;
}

template <typename D> bool consume_Windows_ApplicationModel_Resources_Core_IResourceQualifier<D>::IsMatch() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Resources::Core::IResourceQualifier)->get_IsMatch(&value));
    return value;
}

template <typename D> double consume_Windows_ApplicationModel_Resources_Core_IResourceQualifier<D>::Score() const
{
    double value{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Resources::Core::IResourceQualifier)->get_Score(&value));
    return value;
}

template <typename D>
struct produce<D, Windows::ApplicationModel::Resources::Core::INamedResource> : produce_base<D, Windows::ApplicationModel::Resources::Core::INamedResource>
{
    int32_t WINRT_CALL get_Uri(void** uri) noexcept final
    {
        try
        {
            *uri = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Uri, WINRT_WRAP(Windows::Foundation::Uri));
            *uri = detach_from<Windows::Foundation::Uri>(this->shim().Uri());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Candidates(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Candidates, WINRT_WRAP(Windows::Foundation::Collections::IVectorView<Windows::ApplicationModel::Resources::Core::ResourceCandidate>));
            *value = detach_from<Windows::Foundation::Collections::IVectorView<Windows::ApplicationModel::Resources::Core::ResourceCandidate>>(this->shim().Candidates());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL Resolve(void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Resolve, WINRT_WRAP(Windows::ApplicationModel::Resources::Core::ResourceCandidate));
            *result = detach_from<Windows::ApplicationModel::Resources::Core::ResourceCandidate>(this->shim().Resolve());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL ResolveForContext(void* resourceContext, void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Resolve, WINRT_WRAP(Windows::ApplicationModel::Resources::Core::ResourceCandidate), Windows::ApplicationModel::Resources::Core::ResourceContext const&);
            *result = detach_from<Windows::ApplicationModel::Resources::Core::ResourceCandidate>(this->shim().Resolve(*reinterpret_cast<Windows::ApplicationModel::Resources::Core::ResourceContext const*>(&resourceContext)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL ResolveAll(void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ResolveAll, WINRT_WRAP(Windows::Foundation::Collections::IVectorView<Windows::ApplicationModel::Resources::Core::ResourceCandidate>));
            *result = detach_from<Windows::Foundation::Collections::IVectorView<Windows::ApplicationModel::Resources::Core::ResourceCandidate>>(this->shim().ResolveAll());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL ResolveAllForContext(void* resourceContext, void** instances) noexcept final
    {
        try
        {
            *instances = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ResolveAll, WINRT_WRAP(Windows::Foundation::Collections::IVectorView<Windows::ApplicationModel::Resources::Core::ResourceCandidate>), Windows::ApplicationModel::Resources::Core::ResourceContext const&);
            *instances = detach_from<Windows::Foundation::Collections::IVectorView<Windows::ApplicationModel::Resources::Core::ResourceCandidate>>(this->shim().ResolveAll(*reinterpret_cast<Windows::ApplicationModel::Resources::Core::ResourceContext const*>(&resourceContext)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::ApplicationModel::Resources::Core::IResourceCandidate> : produce_base<D, Windows::ApplicationModel::Resources::Core::IResourceCandidate>
{
    int32_t WINRT_CALL get_Qualifiers(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Qualifiers, WINRT_WRAP(Windows::Foundation::Collections::IVectorView<Windows::ApplicationModel::Resources::Core::ResourceQualifier>));
            *value = detach_from<Windows::Foundation::Collections::IVectorView<Windows::ApplicationModel::Resources::Core::ResourceQualifier>>(this->shim().Qualifiers());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_IsMatch(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IsMatch, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().IsMatch());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_IsMatchAsDefault(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IsMatchAsDefault, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().IsMatchAsDefault());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_IsDefault(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IsDefault, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().IsDefault());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_ValueAsString(void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ValueAsString, WINRT_WRAP(hstring));
            *result = detach_from<hstring>(this->shim().ValueAsString());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL GetValueAsFileAsync(void** operation) noexcept final
    {
        try
        {
            *operation = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetValueAsFileAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<Windows::Storage::StorageFile>));
            *operation = detach_from<Windows::Foundation::IAsyncOperation<Windows::Storage::StorageFile>>(this->shim().GetValueAsFileAsync());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL GetQualifierValue(void* qualifierName, void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetQualifierValue, WINRT_WRAP(hstring), hstring const&);
            *value = detach_from<hstring>(this->shim().GetQualifierValue(*reinterpret_cast<hstring const*>(&qualifierName)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::ApplicationModel::Resources::Core::IResourceCandidate2> : produce_base<D, Windows::ApplicationModel::Resources::Core::IResourceCandidate2>
{
    int32_t WINRT_CALL GetValueAsStreamAsync(void** operation) noexcept final
    {
        try
        {
            *operation = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetValueAsStreamAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<Windows::Storage::Streams::IRandomAccessStream>));
            *operation = detach_from<Windows::Foundation::IAsyncOperation<Windows::Storage::Streams::IRandomAccessStream>>(this->shim().GetValueAsStreamAsync());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::ApplicationModel::Resources::Core::IResourceCandidate3> : produce_base<D, Windows::ApplicationModel::Resources::Core::IResourceCandidate3>
{
    int32_t WINRT_CALL get_Kind(Windows::ApplicationModel::Resources::Core::ResourceCandidateKind* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Kind, WINRT_WRAP(Windows::ApplicationModel::Resources::Core::ResourceCandidateKind));
            *value = detach_from<Windows::ApplicationModel::Resources::Core::ResourceCandidateKind>(this->shim().Kind());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::ApplicationModel::Resources::Core::IResourceContext> : produce_base<D, Windows::ApplicationModel::Resources::Core::IResourceContext>
{
    int32_t WINRT_CALL get_QualifierValues(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(QualifierValues, WINRT_WRAP(Windows::Foundation::Collections::IObservableMap<hstring, hstring>));
            *value = detach_from<Windows::Foundation::Collections::IObservableMap<hstring, hstring>>(this->shim().QualifierValues());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL Reset() noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Reset, WINRT_WRAP(void));
            this->shim().Reset();
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL ResetQualifierValues(void* qualifierNames) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Reset, WINRT_WRAP(void), Windows::Foundation::Collections::IIterable<hstring> const&);
            this->shim().Reset(*reinterpret_cast<Windows::Foundation::Collections::IIterable<hstring> const*>(&qualifierNames));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL OverrideToMatch(void* result) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(OverrideToMatch, WINRT_WRAP(void), Windows::Foundation::Collections::IIterable<Windows::ApplicationModel::Resources::Core::ResourceQualifier> const&);
            this->shim().OverrideToMatch(*reinterpret_cast<Windows::Foundation::Collections::IIterable<Windows::ApplicationModel::Resources::Core::ResourceQualifier> const*>(&result));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL Clone(void** clone) noexcept final
    {
        try
        {
            *clone = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Clone, WINRT_WRAP(Windows::ApplicationModel::Resources::Core::ResourceContext));
            *clone = detach_from<Windows::ApplicationModel::Resources::Core::ResourceContext>(this->shim().Clone());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Languages(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Languages, WINRT_WRAP(Windows::Foundation::Collections::IVectorView<hstring>));
            *value = detach_from<Windows::Foundation::Collections::IVectorView<hstring>>(this->shim().Languages());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_Languages(void* languages) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Languages, WINRT_WRAP(void), Windows::Foundation::Collections::IVectorView<hstring> const&);
            this->shim().Languages(*reinterpret_cast<Windows::Foundation::Collections::IVectorView<hstring> const*>(&languages));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::ApplicationModel::Resources::Core::IResourceContextStatics> : produce_base<D, Windows::ApplicationModel::Resources::Core::IResourceContextStatics>
{
    int32_t WINRT_CALL CreateMatchingContext(void* result, void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CreateMatchingContext, WINRT_WRAP(Windows::ApplicationModel::Resources::Core::ResourceContext), Windows::Foundation::Collections::IIterable<Windows::ApplicationModel::Resources::Core::ResourceQualifier> const&);
            *value = detach_from<Windows::ApplicationModel::Resources::Core::ResourceContext>(this->shim().CreateMatchingContext(*reinterpret_cast<Windows::Foundation::Collections::IIterable<Windows::ApplicationModel::Resources::Core::ResourceQualifier> const*>(&result)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::ApplicationModel::Resources::Core::IResourceContextStatics2> : produce_base<D, Windows::ApplicationModel::Resources::Core::IResourceContextStatics2>
{
    int32_t WINRT_CALL GetForCurrentView(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetForCurrentView, WINRT_WRAP(Windows::ApplicationModel::Resources::Core::ResourceContext));
            *value = detach_from<Windows::ApplicationModel::Resources::Core::ResourceContext>(this->shim().GetForCurrentView());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL SetGlobalQualifierValue(void* key, void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SetGlobalQualifierValue, WINRT_WRAP(void), hstring const&, hstring const&);
            this->shim().SetGlobalQualifierValue(*reinterpret_cast<hstring const*>(&key), *reinterpret_cast<hstring const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL ResetGlobalQualifierValues() noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ResetGlobalQualifierValues, WINRT_WRAP(void));
            this->shim().ResetGlobalQualifierValues();
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL ResetGlobalQualifierValuesForSpecifiedQualifiers(void* qualifierNames) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ResetGlobalQualifierValues, WINRT_WRAP(void), Windows::Foundation::Collections::IIterable<hstring> const&);
            this->shim().ResetGlobalQualifierValues(*reinterpret_cast<Windows::Foundation::Collections::IIterable<hstring> const*>(&qualifierNames));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL GetForViewIndependentUse(void** loader) noexcept final
    {
        try
        {
            *loader = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetForViewIndependentUse, WINRT_WRAP(Windows::ApplicationModel::Resources::Core::ResourceContext));
            *loader = detach_from<Windows::ApplicationModel::Resources::Core::ResourceContext>(this->shim().GetForViewIndependentUse());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::ApplicationModel::Resources::Core::IResourceContextStatics3> : produce_base<D, Windows::ApplicationModel::Resources::Core::IResourceContextStatics3>
{
    int32_t WINRT_CALL SetGlobalQualifierValueWithPersistence(void* key, void* value, Windows::ApplicationModel::Resources::Core::ResourceQualifierPersistence persistence) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SetGlobalQualifierValue, WINRT_WRAP(void), hstring const&, hstring const&, Windows::ApplicationModel::Resources::Core::ResourceQualifierPersistence const&);
            this->shim().SetGlobalQualifierValue(*reinterpret_cast<hstring const*>(&key), *reinterpret_cast<hstring const*>(&value), *reinterpret_cast<Windows::ApplicationModel::Resources::Core::ResourceQualifierPersistence const*>(&persistence));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::ApplicationModel::Resources::Core::IResourceContextStatics4> : produce_base<D, Windows::ApplicationModel::Resources::Core::IResourceContextStatics4>
{
    int32_t WINRT_CALL GetForUIContext(void* context, void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetForUIContext, WINRT_WRAP(Windows::ApplicationModel::Resources::Core::ResourceContext), Windows::UI::UIContext const&);
            *value = detach_from<Windows::ApplicationModel::Resources::Core::ResourceContext>(this->shim().GetForUIContext(*reinterpret_cast<Windows::UI::UIContext const*>(&context)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::ApplicationModel::Resources::Core::IResourceManager> : produce_base<D, Windows::ApplicationModel::Resources::Core::IResourceManager>
{
    int32_t WINRT_CALL get_MainResourceMap(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(MainResourceMap, WINRT_WRAP(Windows::ApplicationModel::Resources::Core::ResourceMap));
            *value = detach_from<Windows::ApplicationModel::Resources::Core::ResourceMap>(this->shim().MainResourceMap());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_AllResourceMaps(void** maps) noexcept final
    {
        try
        {
            *maps = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(AllResourceMaps, WINRT_WRAP(Windows::Foundation::Collections::IMapView<hstring, Windows::ApplicationModel::Resources::Core::ResourceMap>));
            *maps = detach_from<Windows::Foundation::Collections::IMapView<hstring, Windows::ApplicationModel::Resources::Core::ResourceMap>>(this->shim().AllResourceMaps());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_DefaultContext(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(DefaultContext, WINRT_WRAP(Windows::ApplicationModel::Resources::Core::ResourceContext));
            *value = detach_from<Windows::ApplicationModel::Resources::Core::ResourceContext>(this->shim().DefaultContext());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL LoadPriFiles(void* files) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(LoadPriFiles, WINRT_WRAP(void), Windows::Foundation::Collections::IIterable<Windows::Storage::IStorageFile> const&);
            this->shim().LoadPriFiles(*reinterpret_cast<Windows::Foundation::Collections::IIterable<Windows::Storage::IStorageFile> const*>(&files));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL UnloadPriFiles(void* files) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(UnloadPriFiles, WINRT_WRAP(void), Windows::Foundation::Collections::IIterable<Windows::Storage::IStorageFile> const&);
            this->shim().UnloadPriFiles(*reinterpret_cast<Windows::Foundation::Collections::IIterable<Windows::Storage::IStorageFile> const*>(&files));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::ApplicationModel::Resources::Core::IResourceManager2> : produce_base<D, Windows::ApplicationModel::Resources::Core::IResourceManager2>
{
    int32_t WINRT_CALL GetAllNamedResourcesForPackage(void* packageName, struct struct_Windows_ApplicationModel_Resources_Core_ResourceLayoutInfo resourceLayoutInfo, void** table) noexcept final
    {
        try
        {
            *table = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetAllNamedResourcesForPackage, WINRT_WRAP(Windows::Foundation::Collections::IVectorView<Windows::ApplicationModel::Resources::Core::NamedResource>), hstring const&, Windows::ApplicationModel::Resources::Core::ResourceLayoutInfo const&);
            *table = detach_from<Windows::Foundation::Collections::IVectorView<Windows::ApplicationModel::Resources::Core::NamedResource>>(this->shim().GetAllNamedResourcesForPackage(*reinterpret_cast<hstring const*>(&packageName), *reinterpret_cast<Windows::ApplicationModel::Resources::Core::ResourceLayoutInfo const*>(&resourceLayoutInfo)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL GetAllSubtreesForPackage(void* packageName, struct struct_Windows_ApplicationModel_Resources_Core_ResourceLayoutInfo resourceLayoutInfo, void** table) noexcept final
    {
        try
        {
            *table = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetAllSubtreesForPackage, WINRT_WRAP(Windows::Foundation::Collections::IVectorView<Windows::ApplicationModel::Resources::Core::ResourceMap>), hstring const&, Windows::ApplicationModel::Resources::Core::ResourceLayoutInfo const&);
            *table = detach_from<Windows::Foundation::Collections::IVectorView<Windows::ApplicationModel::Resources::Core::ResourceMap>>(this->shim().GetAllSubtreesForPackage(*reinterpret_cast<hstring const*>(&packageName), *reinterpret_cast<Windows::ApplicationModel::Resources::Core::ResourceLayoutInfo const*>(&resourceLayoutInfo)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::ApplicationModel::Resources::Core::IResourceManagerStatics> : produce_base<D, Windows::ApplicationModel::Resources::Core::IResourceManagerStatics>
{
    int32_t WINRT_CALL get_Current(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Current, WINRT_WRAP(Windows::ApplicationModel::Resources::Core::ResourceManager));
            *value = detach_from<Windows::ApplicationModel::Resources::Core::ResourceManager>(this->shim().Current());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL IsResourceReference(void* resourceReference, bool* isReference) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IsResourceReference, WINRT_WRAP(bool), hstring const&);
            *isReference = detach_from<bool>(this->shim().IsResourceReference(*reinterpret_cast<hstring const*>(&resourceReference)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::ApplicationModel::Resources::Core::IResourceMap> : produce_base<D, Windows::ApplicationModel::Resources::Core::IResourceMap>
{
    int32_t WINRT_CALL get_Uri(void** uri) noexcept final
    {
        try
        {
            *uri = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Uri, WINRT_WRAP(Windows::Foundation::Uri));
            *uri = detach_from<Windows::Foundation::Uri>(this->shim().Uri());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL GetValue(void* resource, void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetValue, WINRT_WRAP(Windows::ApplicationModel::Resources::Core::ResourceCandidate), hstring const&);
            *value = detach_from<Windows::ApplicationModel::Resources::Core::ResourceCandidate>(this->shim().GetValue(*reinterpret_cast<hstring const*>(&resource)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL GetValueForContext(void* resource, void* context, void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetValue, WINRT_WRAP(Windows::ApplicationModel::Resources::Core::ResourceCandidate), hstring const&, Windows::ApplicationModel::Resources::Core::ResourceContext const&);
            *value = detach_from<Windows::ApplicationModel::Resources::Core::ResourceCandidate>(this->shim().GetValue(*reinterpret_cast<hstring const*>(&resource), *reinterpret_cast<Windows::ApplicationModel::Resources::Core::ResourceContext const*>(&context)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL GetSubtree(void* reference, void** map) noexcept final
    {
        try
        {
            *map = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetSubtree, WINRT_WRAP(Windows::ApplicationModel::Resources::Core::ResourceMap), hstring const&);
            *map = detach_from<Windows::ApplicationModel::Resources::Core::ResourceMap>(this->shim().GetSubtree(*reinterpret_cast<hstring const*>(&reference)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::ApplicationModel::Resources::Core::IResourceQualifier> : produce_base<D, Windows::ApplicationModel::Resources::Core::IResourceQualifier>
{
    int32_t WINRT_CALL get_QualifierName(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(QualifierName, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().QualifierName());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_QualifierValue(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(QualifierValue, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().QualifierValue());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_IsDefault(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IsDefault, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().IsDefault());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_IsMatch(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IsMatch, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().IsMatch());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Score(double* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Score, WINRT_WRAP(double));
            *value = detach_from<double>(this->shim().Score());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

}

WINRT_EXPORT namespace winrt::Windows::ApplicationModel::Resources::Core {

inline ResourceContext::ResourceContext() :
    ResourceContext(impl::call_factory<ResourceContext>([](auto&& f) { return f.template ActivateInstance<ResourceContext>(); }))
{}

inline Windows::ApplicationModel::Resources::Core::ResourceContext ResourceContext::CreateMatchingContext(param::iterable<Windows::ApplicationModel::Resources::Core::ResourceQualifier> const& result)
{
    return impl::call_factory<ResourceContext, Windows::ApplicationModel::Resources::Core::IResourceContextStatics>([&](auto&& f) { return f.CreateMatchingContext(result); });
}

inline Windows::ApplicationModel::Resources::Core::ResourceContext ResourceContext::GetForCurrentView()
{
    return impl::call_factory<ResourceContext, Windows::ApplicationModel::Resources::Core::IResourceContextStatics2>([&](auto&& f) { return f.GetForCurrentView(); });
}

inline void ResourceContext::SetGlobalQualifierValue(param::hstring const& key, param::hstring const& value)
{
    impl::call_factory<ResourceContext, Windows::ApplicationModel::Resources::Core::IResourceContextStatics2>([&](auto&& f) { return f.SetGlobalQualifierValue(key, value); });
}

inline void ResourceContext::ResetGlobalQualifierValues()
{
    impl::call_factory<ResourceContext, Windows::ApplicationModel::Resources::Core::IResourceContextStatics2>([&](auto&& f) { return f.ResetGlobalQualifierValues(); });
}

inline void ResourceContext::ResetGlobalQualifierValues(param::iterable<hstring> const& qualifierNames)
{
    impl::call_factory<ResourceContext, Windows::ApplicationModel::Resources::Core::IResourceContextStatics2>([&](auto&& f) { return f.ResetGlobalQualifierValues(qualifierNames); });
}

inline Windows::ApplicationModel::Resources::Core::ResourceContext ResourceContext::GetForViewIndependentUse()
{
    return impl::call_factory<ResourceContext, Windows::ApplicationModel::Resources::Core::IResourceContextStatics2>([&](auto&& f) { return f.GetForViewIndependentUse(); });
}

inline void ResourceContext::SetGlobalQualifierValue(param::hstring const& key, param::hstring const& value, Windows::ApplicationModel::Resources::Core::ResourceQualifierPersistence const& persistence)
{
    impl::call_factory<ResourceContext, Windows::ApplicationModel::Resources::Core::IResourceContextStatics3>([&](auto&& f) { return f.SetGlobalQualifierValue(key, value, persistence); });
}

inline Windows::ApplicationModel::Resources::Core::ResourceContext ResourceContext::GetForUIContext(Windows::UI::UIContext const& context)
{
    return impl::call_factory<ResourceContext, Windows::ApplicationModel::Resources::Core::IResourceContextStatics4>([&](auto&& f) { return f.GetForUIContext(context); });
}

inline Windows::ApplicationModel::Resources::Core::ResourceManager ResourceManager::Current()
{
    return impl::call_factory<ResourceManager, Windows::ApplicationModel::Resources::Core::IResourceManagerStatics>([&](auto&& f) { return f.Current(); });
}

inline bool ResourceManager::IsResourceReference(param::hstring const& resourceReference)
{
    return impl::call_factory<ResourceManager, Windows::ApplicationModel::Resources::Core::IResourceManagerStatics>([&](auto&& f) { return f.IsResourceReference(resourceReference); });
}

}

WINRT_EXPORT namespace std {

template<> struct hash<winrt::Windows::ApplicationModel::Resources::Core::INamedResource> : winrt::impl::hash_base<winrt::Windows::ApplicationModel::Resources::Core::INamedResource> {};
template<> struct hash<winrt::Windows::ApplicationModel::Resources::Core::IResourceCandidate> : winrt::impl::hash_base<winrt::Windows::ApplicationModel::Resources::Core::IResourceCandidate> {};
template<> struct hash<winrt::Windows::ApplicationModel::Resources::Core::IResourceCandidate2> : winrt::impl::hash_base<winrt::Windows::ApplicationModel::Resources::Core::IResourceCandidate2> {};
template<> struct hash<winrt::Windows::ApplicationModel::Resources::Core::IResourceCandidate3> : winrt::impl::hash_base<winrt::Windows::ApplicationModel::Resources::Core::IResourceCandidate3> {};
template<> struct hash<winrt::Windows::ApplicationModel::Resources::Core::IResourceContext> : winrt::impl::hash_base<winrt::Windows::ApplicationModel::Resources::Core::IResourceContext> {};
template<> struct hash<winrt::Windows::ApplicationModel::Resources::Core::IResourceContextStatics> : winrt::impl::hash_base<winrt::Windows::ApplicationModel::Resources::Core::IResourceContextStatics> {};
template<> struct hash<winrt::Windows::ApplicationModel::Resources::Core::IResourceContextStatics2> : winrt::impl::hash_base<winrt::Windows::ApplicationModel::Resources::Core::IResourceContextStatics2> {};
template<> struct hash<winrt::Windows::ApplicationModel::Resources::Core::IResourceContextStatics3> : winrt::impl::hash_base<winrt::Windows::ApplicationModel::Resources::Core::IResourceContextStatics3> {};
template<> struct hash<winrt::Windows::ApplicationModel::Resources::Core::IResourceContextStatics4> : winrt::impl::hash_base<winrt::Windows::ApplicationModel::Resources::Core::IResourceContextStatics4> {};
template<> struct hash<winrt::Windows::ApplicationModel::Resources::Core::IResourceManager> : winrt::impl::hash_base<winrt::Windows::ApplicationModel::Resources::Core::IResourceManager> {};
template<> struct hash<winrt::Windows::ApplicationModel::Resources::Core::IResourceManager2> : winrt::impl::hash_base<winrt::Windows::ApplicationModel::Resources::Core::IResourceManager2> {};
template<> struct hash<winrt::Windows::ApplicationModel::Resources::Core::IResourceManagerStatics> : winrt::impl::hash_base<winrt::Windows::ApplicationModel::Resources::Core::IResourceManagerStatics> {};
template<> struct hash<winrt::Windows::ApplicationModel::Resources::Core::IResourceMap> : winrt::impl::hash_base<winrt::Windows::ApplicationModel::Resources::Core::IResourceMap> {};
template<> struct hash<winrt::Windows::ApplicationModel::Resources::Core::IResourceQualifier> : winrt::impl::hash_base<winrt::Windows::ApplicationModel::Resources::Core::IResourceQualifier> {};
template<> struct hash<winrt::Windows::ApplicationModel::Resources::Core::NamedResource> : winrt::impl::hash_base<winrt::Windows::ApplicationModel::Resources::Core::NamedResource> {};
template<> struct hash<winrt::Windows::ApplicationModel::Resources::Core::ResourceCandidate> : winrt::impl::hash_base<winrt::Windows::ApplicationModel::Resources::Core::ResourceCandidate> {};
template<> struct hash<winrt::Windows::ApplicationModel::Resources::Core::ResourceCandidateVectorView> : winrt::impl::hash_base<winrt::Windows::ApplicationModel::Resources::Core::ResourceCandidateVectorView> {};
template<> struct hash<winrt::Windows::ApplicationModel::Resources::Core::ResourceContext> : winrt::impl::hash_base<winrt::Windows::ApplicationModel::Resources::Core::ResourceContext> {};
template<> struct hash<winrt::Windows::ApplicationModel::Resources::Core::ResourceContextLanguagesVectorView> : winrt::impl::hash_base<winrt::Windows::ApplicationModel::Resources::Core::ResourceContextLanguagesVectorView> {};
template<> struct hash<winrt::Windows::ApplicationModel::Resources::Core::ResourceManager> : winrt::impl::hash_base<winrt::Windows::ApplicationModel::Resources::Core::ResourceManager> {};
template<> struct hash<winrt::Windows::ApplicationModel::Resources::Core::ResourceMap> : winrt::impl::hash_base<winrt::Windows::ApplicationModel::Resources::Core::ResourceMap> {};
template<> struct hash<winrt::Windows::ApplicationModel::Resources::Core::ResourceMapIterator> : winrt::impl::hash_base<winrt::Windows::ApplicationModel::Resources::Core::ResourceMapIterator> {};
template<> struct hash<winrt::Windows::ApplicationModel::Resources::Core::ResourceMapMapView> : winrt::impl::hash_base<winrt::Windows::ApplicationModel::Resources::Core::ResourceMapMapView> {};
template<> struct hash<winrt::Windows::ApplicationModel::Resources::Core::ResourceMapMapViewIterator> : winrt::impl::hash_base<winrt::Windows::ApplicationModel::Resources::Core::ResourceMapMapViewIterator> {};
template<> struct hash<winrt::Windows::ApplicationModel::Resources::Core::ResourceQualifier> : winrt::impl::hash_base<winrt::Windows::ApplicationModel::Resources::Core::ResourceQualifier> {};
template<> struct hash<winrt::Windows::ApplicationModel::Resources::Core::ResourceQualifierMapView> : winrt::impl::hash_base<winrt::Windows::ApplicationModel::Resources::Core::ResourceQualifierMapView> {};
template<> struct hash<winrt::Windows::ApplicationModel::Resources::Core::ResourceQualifierObservableMap> : winrt::impl::hash_base<winrt::Windows::ApplicationModel::Resources::Core::ResourceQualifierObservableMap> {};
template<> struct hash<winrt::Windows::ApplicationModel::Resources::Core::ResourceQualifierVectorView> : winrt::impl::hash_base<winrt::Windows::ApplicationModel::Resources::Core::ResourceQualifierVectorView> {};

}
