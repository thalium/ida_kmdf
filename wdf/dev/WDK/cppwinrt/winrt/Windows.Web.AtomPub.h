// C++/WinRT v1.0.190111.3

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#pragma once

#include "winrt/base.h"

#include "winrt/Windows.Foundation.h"
#include "winrt/Windows.Foundation.Collections.h"
#include "winrt/impl/Windows.Data.Xml.Dom.2.h"
#include "winrt/impl/Windows.Foundation.2.h"
#include "winrt/impl/Windows.Security.Credentials.2.h"
#include "winrt/impl/Windows.Storage.Streams.2.h"
#include "winrt/impl/Windows.Web.Syndication.2.h"
#include "winrt/impl/Windows.Web.AtomPub.2.h"
#include "winrt/Windows.Web.h"

namespace winrt::impl {

template <typename D> Windows::Foundation::IAsyncOperationWithProgress<Windows::Web::AtomPub::ServiceDocument, Windows::Web::Syndication::RetrievalProgress> consume_Windows_Web_AtomPub_IAtomPubClient<D>::RetrieveServiceDocumentAsync(Windows::Foundation::Uri const& uri) const
{
    Windows::Foundation::IAsyncOperationWithProgress<Windows::Web::AtomPub::ServiceDocument, Windows::Web::Syndication::RetrievalProgress> operation{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Web::AtomPub::IAtomPubClient)->RetrieveServiceDocumentAsync(get_abi(uri), put_abi(operation)));
    return operation;
}

template <typename D> Windows::Foundation::IAsyncOperationWithProgress<Windows::Storage::Streams::IInputStream, Windows::Web::Syndication::RetrievalProgress> consume_Windows_Web_AtomPub_IAtomPubClient<D>::RetrieveMediaResourceAsync(Windows::Foundation::Uri const& uri) const
{
    Windows::Foundation::IAsyncOperationWithProgress<Windows::Storage::Streams::IInputStream, Windows::Web::Syndication::RetrievalProgress> operation{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Web::AtomPub::IAtomPubClient)->RetrieveMediaResourceAsync(get_abi(uri), put_abi(operation)));
    return operation;
}

template <typename D> Windows::Foundation::IAsyncOperationWithProgress<Windows::Web::Syndication::SyndicationItem, Windows::Web::Syndication::RetrievalProgress> consume_Windows_Web_AtomPub_IAtomPubClient<D>::RetrieveResourceAsync(Windows::Foundation::Uri const& uri) const
{
    Windows::Foundation::IAsyncOperationWithProgress<Windows::Web::Syndication::SyndicationItem, Windows::Web::Syndication::RetrievalProgress> operation{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Web::AtomPub::IAtomPubClient)->RetrieveResourceAsync(get_abi(uri), put_abi(operation)));
    return operation;
}

template <typename D> Windows::Foundation::IAsyncOperationWithProgress<Windows::Web::Syndication::SyndicationItem, Windows::Web::Syndication::TransferProgress> consume_Windows_Web_AtomPub_IAtomPubClient<D>::CreateResourceAsync(Windows::Foundation::Uri const& uri, param::hstring const& description, Windows::Web::Syndication::SyndicationItem const& item) const
{
    Windows::Foundation::IAsyncOperationWithProgress<Windows::Web::Syndication::SyndicationItem, Windows::Web::Syndication::TransferProgress> operation{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Web::AtomPub::IAtomPubClient)->CreateResourceAsync(get_abi(uri), get_abi(description), get_abi(item), put_abi(operation)));
    return operation;
}

template <typename D> Windows::Foundation::IAsyncOperationWithProgress<Windows::Web::Syndication::SyndicationItem, Windows::Web::Syndication::TransferProgress> consume_Windows_Web_AtomPub_IAtomPubClient<D>::CreateMediaResourceAsync(Windows::Foundation::Uri const& uri, param::hstring const& mediaType, param::hstring const& description, Windows::Storage::Streams::IInputStream const& mediaStream) const
{
    Windows::Foundation::IAsyncOperationWithProgress<Windows::Web::Syndication::SyndicationItem, Windows::Web::Syndication::TransferProgress> operation{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Web::AtomPub::IAtomPubClient)->CreateMediaResourceAsync(get_abi(uri), get_abi(mediaType), get_abi(description), get_abi(mediaStream), put_abi(operation)));
    return operation;
}

template <typename D> Windows::Foundation::IAsyncActionWithProgress<Windows::Web::Syndication::TransferProgress> consume_Windows_Web_AtomPub_IAtomPubClient<D>::UpdateMediaResourceAsync(Windows::Foundation::Uri const& uri, param::hstring const& mediaType, Windows::Storage::Streams::IInputStream const& mediaStream) const
{
    Windows::Foundation::IAsyncActionWithProgress<Windows::Web::Syndication::TransferProgress> operation{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Web::AtomPub::IAtomPubClient)->UpdateMediaResourceAsync(get_abi(uri), get_abi(mediaType), get_abi(mediaStream), put_abi(operation)));
    return operation;
}

template <typename D> Windows::Foundation::IAsyncActionWithProgress<Windows::Web::Syndication::TransferProgress> consume_Windows_Web_AtomPub_IAtomPubClient<D>::UpdateResourceAsync(Windows::Foundation::Uri const& uri, Windows::Web::Syndication::SyndicationItem const& item) const
{
    Windows::Foundation::IAsyncActionWithProgress<Windows::Web::Syndication::TransferProgress> operation{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Web::AtomPub::IAtomPubClient)->UpdateResourceAsync(get_abi(uri), get_abi(item), put_abi(operation)));
    return operation;
}

template <typename D> Windows::Foundation::IAsyncActionWithProgress<Windows::Web::Syndication::TransferProgress> consume_Windows_Web_AtomPub_IAtomPubClient<D>::UpdateResourceItemAsync(Windows::Web::Syndication::SyndicationItem const& item) const
{
    Windows::Foundation::IAsyncActionWithProgress<Windows::Web::Syndication::TransferProgress> operation{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Web::AtomPub::IAtomPubClient)->UpdateResourceItemAsync(get_abi(item), put_abi(operation)));
    return operation;
}

template <typename D> Windows::Foundation::IAsyncActionWithProgress<Windows::Web::Syndication::TransferProgress> consume_Windows_Web_AtomPub_IAtomPubClient<D>::DeleteResourceAsync(Windows::Foundation::Uri const& uri) const
{
    Windows::Foundation::IAsyncActionWithProgress<Windows::Web::Syndication::TransferProgress> operation{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Web::AtomPub::IAtomPubClient)->DeleteResourceAsync(get_abi(uri), put_abi(operation)));
    return operation;
}

template <typename D> Windows::Foundation::IAsyncActionWithProgress<Windows::Web::Syndication::TransferProgress> consume_Windows_Web_AtomPub_IAtomPubClient<D>::DeleteResourceItemAsync(Windows::Web::Syndication::SyndicationItem const& item) const
{
    Windows::Foundation::IAsyncActionWithProgress<Windows::Web::Syndication::TransferProgress> operation{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Web::AtomPub::IAtomPubClient)->DeleteResourceItemAsync(get_abi(item), put_abi(operation)));
    return operation;
}

template <typename D> void consume_Windows_Web_AtomPub_IAtomPubClient<D>::CancelAsyncOperations() const
{
    check_hresult(WINRT_SHIM(Windows::Web::AtomPub::IAtomPubClient)->CancelAsyncOperations());
}

template <typename D> Windows::Web::AtomPub::AtomPubClient consume_Windows_Web_AtomPub_IAtomPubClientFactory<D>::CreateAtomPubClientWithCredentials(Windows::Security::Credentials::PasswordCredential const& serverCredential) const
{
    Windows::Web::AtomPub::AtomPubClient atomPubClient{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Web::AtomPub::IAtomPubClientFactory)->CreateAtomPubClientWithCredentials(get_abi(serverCredential), put_abi(atomPubClient)));
    return atomPubClient;
}

template <typename D> Windows::Web::Syndication::ISyndicationText consume_Windows_Web_AtomPub_IResourceCollection<D>::Title() const
{
    Windows::Web::Syndication::ISyndicationText value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Web::AtomPub::IResourceCollection)->get_Title(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::Uri consume_Windows_Web_AtomPub_IResourceCollection<D>::Uri() const
{
    Windows::Foundation::Uri value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Web::AtomPub::IResourceCollection)->get_Uri(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::Collections::IVectorView<Windows::Web::Syndication::SyndicationCategory> consume_Windows_Web_AtomPub_IResourceCollection<D>::Categories() const
{
    Windows::Foundation::Collections::IVectorView<Windows::Web::Syndication::SyndicationCategory> value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Web::AtomPub::IResourceCollection)->get_Categories(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::Collections::IVectorView<hstring> consume_Windows_Web_AtomPub_IResourceCollection<D>::Accepts() const
{
    Windows::Foundation::Collections::IVectorView<hstring> value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Web::AtomPub::IResourceCollection)->get_Accepts(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::Collections::IVectorView<Windows::Web::AtomPub::Workspace> consume_Windows_Web_AtomPub_IServiceDocument<D>::Workspaces() const
{
    Windows::Foundation::Collections::IVectorView<Windows::Web::AtomPub::Workspace> value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Web::AtomPub::IServiceDocument)->get_Workspaces(put_abi(value)));
    return value;
}

template <typename D> Windows::Web::Syndication::ISyndicationText consume_Windows_Web_AtomPub_IWorkspace<D>::Title() const
{
    Windows::Web::Syndication::ISyndicationText value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Web::AtomPub::IWorkspace)->get_Title(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::Collections::IVectorView<Windows::Web::AtomPub::ResourceCollection> consume_Windows_Web_AtomPub_IWorkspace<D>::Collections() const
{
    Windows::Foundation::Collections::IVectorView<Windows::Web::AtomPub::ResourceCollection> value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Web::AtomPub::IWorkspace)->get_Collections(put_abi(value)));
    return value;
}

template <typename D>
struct produce<D, Windows::Web::AtomPub::IAtomPubClient> : produce_base<D, Windows::Web::AtomPub::IAtomPubClient>
{
    int32_t WINRT_CALL RetrieveServiceDocumentAsync(void* uri, void** operation) noexcept final
    {
        try
        {
            *operation = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(RetrieveServiceDocumentAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperationWithProgress<Windows::Web::AtomPub::ServiceDocument, Windows::Web::Syndication::RetrievalProgress>), Windows::Foundation::Uri const);
            *operation = detach_from<Windows::Foundation::IAsyncOperationWithProgress<Windows::Web::AtomPub::ServiceDocument, Windows::Web::Syndication::RetrievalProgress>>(this->shim().RetrieveServiceDocumentAsync(*reinterpret_cast<Windows::Foundation::Uri const*>(&uri)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL RetrieveMediaResourceAsync(void* uri, void** operation) noexcept final
    {
        try
        {
            *operation = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(RetrieveMediaResourceAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperationWithProgress<Windows::Storage::Streams::IInputStream, Windows::Web::Syndication::RetrievalProgress>), Windows::Foundation::Uri const);
            *operation = detach_from<Windows::Foundation::IAsyncOperationWithProgress<Windows::Storage::Streams::IInputStream, Windows::Web::Syndication::RetrievalProgress>>(this->shim().RetrieveMediaResourceAsync(*reinterpret_cast<Windows::Foundation::Uri const*>(&uri)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL RetrieveResourceAsync(void* uri, void** operation) noexcept final
    {
        try
        {
            *operation = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(RetrieveResourceAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperationWithProgress<Windows::Web::Syndication::SyndicationItem, Windows::Web::Syndication::RetrievalProgress>), Windows::Foundation::Uri const);
            *operation = detach_from<Windows::Foundation::IAsyncOperationWithProgress<Windows::Web::Syndication::SyndicationItem, Windows::Web::Syndication::RetrievalProgress>>(this->shim().RetrieveResourceAsync(*reinterpret_cast<Windows::Foundation::Uri const*>(&uri)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL CreateResourceAsync(void* uri, void* description, void* item, void** operation) noexcept final
    {
        try
        {
            *operation = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CreateResourceAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperationWithProgress<Windows::Web::Syndication::SyndicationItem, Windows::Web::Syndication::TransferProgress>), Windows::Foundation::Uri const, hstring const, Windows::Web::Syndication::SyndicationItem const);
            *operation = detach_from<Windows::Foundation::IAsyncOperationWithProgress<Windows::Web::Syndication::SyndicationItem, Windows::Web::Syndication::TransferProgress>>(this->shim().CreateResourceAsync(*reinterpret_cast<Windows::Foundation::Uri const*>(&uri), *reinterpret_cast<hstring const*>(&description), *reinterpret_cast<Windows::Web::Syndication::SyndicationItem const*>(&item)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL CreateMediaResourceAsync(void* uri, void* mediaType, void* description, void* mediaStream, void** operation) noexcept final
    {
        try
        {
            *operation = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CreateMediaResourceAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperationWithProgress<Windows::Web::Syndication::SyndicationItem, Windows::Web::Syndication::TransferProgress>), Windows::Foundation::Uri const, hstring const, hstring const, Windows::Storage::Streams::IInputStream const);
            *operation = detach_from<Windows::Foundation::IAsyncOperationWithProgress<Windows::Web::Syndication::SyndicationItem, Windows::Web::Syndication::TransferProgress>>(this->shim().CreateMediaResourceAsync(*reinterpret_cast<Windows::Foundation::Uri const*>(&uri), *reinterpret_cast<hstring const*>(&mediaType), *reinterpret_cast<hstring const*>(&description), *reinterpret_cast<Windows::Storage::Streams::IInputStream const*>(&mediaStream)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL UpdateMediaResourceAsync(void* uri, void* mediaType, void* mediaStream, void** operation) noexcept final
    {
        try
        {
            *operation = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(UpdateMediaResourceAsync, WINRT_WRAP(Windows::Foundation::IAsyncActionWithProgress<Windows::Web::Syndication::TransferProgress>), Windows::Foundation::Uri const, hstring const, Windows::Storage::Streams::IInputStream const);
            *operation = detach_from<Windows::Foundation::IAsyncActionWithProgress<Windows::Web::Syndication::TransferProgress>>(this->shim().UpdateMediaResourceAsync(*reinterpret_cast<Windows::Foundation::Uri const*>(&uri), *reinterpret_cast<hstring const*>(&mediaType), *reinterpret_cast<Windows::Storage::Streams::IInputStream const*>(&mediaStream)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL UpdateResourceAsync(void* uri, void* item, void** operation) noexcept final
    {
        try
        {
            *operation = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(UpdateResourceAsync, WINRT_WRAP(Windows::Foundation::IAsyncActionWithProgress<Windows::Web::Syndication::TransferProgress>), Windows::Foundation::Uri const, Windows::Web::Syndication::SyndicationItem const);
            *operation = detach_from<Windows::Foundation::IAsyncActionWithProgress<Windows::Web::Syndication::TransferProgress>>(this->shim().UpdateResourceAsync(*reinterpret_cast<Windows::Foundation::Uri const*>(&uri), *reinterpret_cast<Windows::Web::Syndication::SyndicationItem const*>(&item)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL UpdateResourceItemAsync(void* item, void** operation) noexcept final
    {
        try
        {
            *operation = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(UpdateResourceItemAsync, WINRT_WRAP(Windows::Foundation::IAsyncActionWithProgress<Windows::Web::Syndication::TransferProgress>), Windows::Web::Syndication::SyndicationItem const);
            *operation = detach_from<Windows::Foundation::IAsyncActionWithProgress<Windows::Web::Syndication::TransferProgress>>(this->shim().UpdateResourceItemAsync(*reinterpret_cast<Windows::Web::Syndication::SyndicationItem const*>(&item)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL DeleteResourceAsync(void* uri, void** operation) noexcept final
    {
        try
        {
            *operation = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(DeleteResourceAsync, WINRT_WRAP(Windows::Foundation::IAsyncActionWithProgress<Windows::Web::Syndication::TransferProgress>), Windows::Foundation::Uri const);
            *operation = detach_from<Windows::Foundation::IAsyncActionWithProgress<Windows::Web::Syndication::TransferProgress>>(this->shim().DeleteResourceAsync(*reinterpret_cast<Windows::Foundation::Uri const*>(&uri)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL DeleteResourceItemAsync(void* item, void** operation) noexcept final
    {
        try
        {
            *operation = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(DeleteResourceItemAsync, WINRT_WRAP(Windows::Foundation::IAsyncActionWithProgress<Windows::Web::Syndication::TransferProgress>), Windows::Web::Syndication::SyndicationItem const);
            *operation = detach_from<Windows::Foundation::IAsyncActionWithProgress<Windows::Web::Syndication::TransferProgress>>(this->shim().DeleteResourceItemAsync(*reinterpret_cast<Windows::Web::Syndication::SyndicationItem const*>(&item)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL CancelAsyncOperations() noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CancelAsyncOperations, WINRT_WRAP(void));
            this->shim().CancelAsyncOperations();
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Web::AtomPub::IAtomPubClientFactory> : produce_base<D, Windows::Web::AtomPub::IAtomPubClientFactory>
{
    int32_t WINRT_CALL CreateAtomPubClientWithCredentials(void* serverCredential, void** atomPubClient) noexcept final
    {
        try
        {
            *atomPubClient = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CreateAtomPubClientWithCredentials, WINRT_WRAP(Windows::Web::AtomPub::AtomPubClient), Windows::Security::Credentials::PasswordCredential const&);
            *atomPubClient = detach_from<Windows::Web::AtomPub::AtomPubClient>(this->shim().CreateAtomPubClientWithCredentials(*reinterpret_cast<Windows::Security::Credentials::PasswordCredential const*>(&serverCredential)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Web::AtomPub::IResourceCollection> : produce_base<D, Windows::Web::AtomPub::IResourceCollection>
{
    int32_t WINRT_CALL get_Title(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Title, WINRT_WRAP(Windows::Web::Syndication::ISyndicationText));
            *value = detach_from<Windows::Web::Syndication::ISyndicationText>(this->shim().Title());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Uri(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Uri, WINRT_WRAP(Windows::Foundation::Uri));
            *value = detach_from<Windows::Foundation::Uri>(this->shim().Uri());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Categories(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Categories, WINRT_WRAP(Windows::Foundation::Collections::IVectorView<Windows::Web::Syndication::SyndicationCategory>));
            *value = detach_from<Windows::Foundation::Collections::IVectorView<Windows::Web::Syndication::SyndicationCategory>>(this->shim().Categories());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Accepts(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Accepts, WINRT_WRAP(Windows::Foundation::Collections::IVectorView<hstring>));
            *value = detach_from<Windows::Foundation::Collections::IVectorView<hstring>>(this->shim().Accepts());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Web::AtomPub::IServiceDocument> : produce_base<D, Windows::Web::AtomPub::IServiceDocument>
{
    int32_t WINRT_CALL get_Workspaces(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Workspaces, WINRT_WRAP(Windows::Foundation::Collections::IVectorView<Windows::Web::AtomPub::Workspace>));
            *value = detach_from<Windows::Foundation::Collections::IVectorView<Windows::Web::AtomPub::Workspace>>(this->shim().Workspaces());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Web::AtomPub::IWorkspace> : produce_base<D, Windows::Web::AtomPub::IWorkspace>
{
    int32_t WINRT_CALL get_Title(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Title, WINRT_WRAP(Windows::Web::Syndication::ISyndicationText));
            *value = detach_from<Windows::Web::Syndication::ISyndicationText>(this->shim().Title());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Collections(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Collections, WINRT_WRAP(Windows::Foundation::Collections::IVectorView<Windows::Web::AtomPub::ResourceCollection>));
            *value = detach_from<Windows::Foundation::Collections::IVectorView<Windows::Web::AtomPub::ResourceCollection>>(this->shim().Collections());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

}

WINRT_EXPORT namespace winrt::Windows::Web::AtomPub {

inline AtomPubClient::AtomPubClient() :
    AtomPubClient(impl::call_factory<AtomPubClient>([](auto&& f) { return f.template ActivateInstance<AtomPubClient>(); }))
{}

inline AtomPubClient::AtomPubClient(Windows::Security::Credentials::PasswordCredential const& serverCredential) :
    AtomPubClient(impl::call_factory<AtomPubClient, Windows::Web::AtomPub::IAtomPubClientFactory>([&](auto&& f) { return f.CreateAtomPubClientWithCredentials(serverCredential); }))
{}

}

WINRT_EXPORT namespace std {

template<> struct hash<winrt::Windows::Web::AtomPub::IAtomPubClient> : winrt::impl::hash_base<winrt::Windows::Web::AtomPub::IAtomPubClient> {};
template<> struct hash<winrt::Windows::Web::AtomPub::IAtomPubClientFactory> : winrt::impl::hash_base<winrt::Windows::Web::AtomPub::IAtomPubClientFactory> {};
template<> struct hash<winrt::Windows::Web::AtomPub::IResourceCollection> : winrt::impl::hash_base<winrt::Windows::Web::AtomPub::IResourceCollection> {};
template<> struct hash<winrt::Windows::Web::AtomPub::IServiceDocument> : winrt::impl::hash_base<winrt::Windows::Web::AtomPub::IServiceDocument> {};
template<> struct hash<winrt::Windows::Web::AtomPub::IWorkspace> : winrt::impl::hash_base<winrt::Windows::Web::AtomPub::IWorkspace> {};
template<> struct hash<winrt::Windows::Web::AtomPub::AtomPubClient> : winrt::impl::hash_base<winrt::Windows::Web::AtomPub::AtomPubClient> {};
template<> struct hash<winrt::Windows::Web::AtomPub::ResourceCollection> : winrt::impl::hash_base<winrt::Windows::Web::AtomPub::ResourceCollection> {};
template<> struct hash<winrt::Windows::Web::AtomPub::ServiceDocument> : winrt::impl::hash_base<winrt::Windows::Web::AtomPub::ServiceDocument> {};
template<> struct hash<winrt::Windows::Web::AtomPub::Workspace> : winrt::impl::hash_base<winrt::Windows::Web::AtomPub::Workspace> {};

}
