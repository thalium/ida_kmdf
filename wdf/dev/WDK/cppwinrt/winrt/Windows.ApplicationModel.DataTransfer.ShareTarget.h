// C++/WinRT v1.0.190111.3

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#pragma once

#include "winrt/base.h"

#include "winrt/Windows.Foundation.h"
#include "winrt/Windows.Foundation.Collections.h"
#include "winrt/impl/Windows.ApplicationModel.Contacts.2.h"
#include "winrt/impl/Windows.ApplicationModel.DataTransfer.2.h"
#include "winrt/impl/Windows.Storage.Streams.2.h"
#include "winrt/impl/Windows.ApplicationModel.DataTransfer.ShareTarget.2.h"
#include "winrt/Windows.ApplicationModel.DataTransfer.h"

namespace winrt::impl {

template <typename D> hstring consume_Windows_ApplicationModel_DataTransfer_ShareTarget_IQuickLink<D>::Title() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::DataTransfer::ShareTarget::IQuickLink)->get_Title(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_ApplicationModel_DataTransfer_ShareTarget_IQuickLink<D>::Title(param::hstring const& value) const
{
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::DataTransfer::ShareTarget::IQuickLink)->put_Title(get_abi(value)));
}

template <typename D> Windows::Storage::Streams::RandomAccessStreamReference consume_Windows_ApplicationModel_DataTransfer_ShareTarget_IQuickLink<D>::Thumbnail() const
{
    Windows::Storage::Streams::RandomAccessStreamReference value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::DataTransfer::ShareTarget::IQuickLink)->get_Thumbnail(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_ApplicationModel_DataTransfer_ShareTarget_IQuickLink<D>::Thumbnail(Windows::Storage::Streams::RandomAccessStreamReference const& value) const
{
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::DataTransfer::ShareTarget::IQuickLink)->put_Thumbnail(get_abi(value)));
}

template <typename D> hstring consume_Windows_ApplicationModel_DataTransfer_ShareTarget_IQuickLink<D>::Id() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::DataTransfer::ShareTarget::IQuickLink)->get_Id(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_ApplicationModel_DataTransfer_ShareTarget_IQuickLink<D>::Id(param::hstring const& value) const
{
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::DataTransfer::ShareTarget::IQuickLink)->put_Id(get_abi(value)));
}

template <typename D> Windows::Foundation::Collections::IVector<hstring> consume_Windows_ApplicationModel_DataTransfer_ShareTarget_IQuickLink<D>::SupportedDataFormats() const
{
    Windows::Foundation::Collections::IVector<hstring> value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::DataTransfer::ShareTarget::IQuickLink)->get_SupportedDataFormats(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::Collections::IVector<hstring> consume_Windows_ApplicationModel_DataTransfer_ShareTarget_IQuickLink<D>::SupportedFileTypes() const
{
    Windows::Foundation::Collections::IVector<hstring> value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::DataTransfer::ShareTarget::IQuickLink)->get_SupportedFileTypes(put_abi(value)));
    return value;
}

template <typename D> Windows::ApplicationModel::DataTransfer::DataPackageView consume_Windows_ApplicationModel_DataTransfer_ShareTarget_IShareOperation<D>::Data() const
{
    Windows::ApplicationModel::DataTransfer::DataPackageView value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::DataTransfer::ShareTarget::IShareOperation)->get_Data(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_ApplicationModel_DataTransfer_ShareTarget_IShareOperation<D>::QuickLinkId() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::DataTransfer::ShareTarget::IShareOperation)->get_QuickLinkId(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_ApplicationModel_DataTransfer_ShareTarget_IShareOperation<D>::RemoveThisQuickLink() const
{
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::DataTransfer::ShareTarget::IShareOperation)->RemoveThisQuickLink());
}

template <typename D> void consume_Windows_ApplicationModel_DataTransfer_ShareTarget_IShareOperation<D>::ReportStarted() const
{
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::DataTransfer::ShareTarget::IShareOperation)->ReportStarted());
}

template <typename D> void consume_Windows_ApplicationModel_DataTransfer_ShareTarget_IShareOperation<D>::ReportDataRetrieved() const
{
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::DataTransfer::ShareTarget::IShareOperation)->ReportDataRetrieved());
}

template <typename D> void consume_Windows_ApplicationModel_DataTransfer_ShareTarget_IShareOperation<D>::ReportSubmittedBackgroundTask() const
{
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::DataTransfer::ShareTarget::IShareOperation)->ReportSubmittedBackgroundTask());
}

template <typename D> void consume_Windows_ApplicationModel_DataTransfer_ShareTarget_IShareOperation<D>::ReportCompleted(Windows::ApplicationModel::DataTransfer::ShareTarget::QuickLink const& quicklink) const
{
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::DataTransfer::ShareTarget::IShareOperation)->ReportCompletedWithQuickLink(get_abi(quicklink)));
}

template <typename D> void consume_Windows_ApplicationModel_DataTransfer_ShareTarget_IShareOperation<D>::ReportCompleted() const
{
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::DataTransfer::ShareTarget::IShareOperation)->ReportCompleted());
}

template <typename D> void consume_Windows_ApplicationModel_DataTransfer_ShareTarget_IShareOperation<D>::ReportError(param::hstring const& value) const
{
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::DataTransfer::ShareTarget::IShareOperation)->ReportError(get_abi(value)));
}

template <typename D> void consume_Windows_ApplicationModel_DataTransfer_ShareTarget_IShareOperation2<D>::DismissUI() const
{
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::DataTransfer::ShareTarget::IShareOperation2)->DismissUI());
}

template <typename D> Windows::Foundation::Collections::IVectorView<Windows::ApplicationModel::Contacts::Contact> consume_Windows_ApplicationModel_DataTransfer_ShareTarget_IShareOperation3<D>::Contacts() const
{
    Windows::Foundation::Collections::IVectorView<Windows::ApplicationModel::Contacts::Contact> value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::DataTransfer::ShareTarget::IShareOperation3)->get_Contacts(put_abi(value)));
    return value;
}

template <typename D>
struct produce<D, Windows::ApplicationModel::DataTransfer::ShareTarget::IQuickLink> : produce_base<D, Windows::ApplicationModel::DataTransfer::ShareTarget::IQuickLink>
{
    int32_t WINRT_CALL get_Title(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Title, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().Title());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_Title(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Title, WINRT_WRAP(void), hstring const&);
            this->shim().Title(*reinterpret_cast<hstring const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Thumbnail(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Thumbnail, WINRT_WRAP(Windows::Storage::Streams::RandomAccessStreamReference));
            *value = detach_from<Windows::Storage::Streams::RandomAccessStreamReference>(this->shim().Thumbnail());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_Thumbnail(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Thumbnail, WINRT_WRAP(void), Windows::Storage::Streams::RandomAccessStreamReference const&);
            this->shim().Thumbnail(*reinterpret_cast<Windows::Storage::Streams::RandomAccessStreamReference const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Id(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Id, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().Id());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_Id(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Id, WINRT_WRAP(void), hstring const&);
            this->shim().Id(*reinterpret_cast<hstring const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_SupportedDataFormats(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SupportedDataFormats, WINRT_WRAP(Windows::Foundation::Collections::IVector<hstring>));
            *value = detach_from<Windows::Foundation::Collections::IVector<hstring>>(this->shim().SupportedDataFormats());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_SupportedFileTypes(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SupportedFileTypes, WINRT_WRAP(Windows::Foundation::Collections::IVector<hstring>));
            *value = detach_from<Windows::Foundation::Collections::IVector<hstring>>(this->shim().SupportedFileTypes());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::ApplicationModel::DataTransfer::ShareTarget::IShareOperation> : produce_base<D, Windows::ApplicationModel::DataTransfer::ShareTarget::IShareOperation>
{
    int32_t WINRT_CALL get_Data(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Data, WINRT_WRAP(Windows::ApplicationModel::DataTransfer::DataPackageView));
            *value = detach_from<Windows::ApplicationModel::DataTransfer::DataPackageView>(this->shim().Data());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_QuickLinkId(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(QuickLinkId, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().QuickLinkId());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL RemoveThisQuickLink() noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(RemoveThisQuickLink, WINRT_WRAP(void));
            this->shim().RemoveThisQuickLink();
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL ReportStarted() noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ReportStarted, WINRT_WRAP(void));
            this->shim().ReportStarted();
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL ReportDataRetrieved() noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ReportDataRetrieved, WINRT_WRAP(void));
            this->shim().ReportDataRetrieved();
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL ReportSubmittedBackgroundTask() noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ReportSubmittedBackgroundTask, WINRT_WRAP(void));
            this->shim().ReportSubmittedBackgroundTask();
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL ReportCompletedWithQuickLink(void* quicklink) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ReportCompleted, WINRT_WRAP(void), Windows::ApplicationModel::DataTransfer::ShareTarget::QuickLink const&);
            this->shim().ReportCompleted(*reinterpret_cast<Windows::ApplicationModel::DataTransfer::ShareTarget::QuickLink const*>(&quicklink));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL ReportCompleted() noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ReportCompleted, WINRT_WRAP(void));
            this->shim().ReportCompleted();
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL ReportError(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ReportError, WINRT_WRAP(void), hstring const&);
            this->shim().ReportError(*reinterpret_cast<hstring const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::ApplicationModel::DataTransfer::ShareTarget::IShareOperation2> : produce_base<D, Windows::ApplicationModel::DataTransfer::ShareTarget::IShareOperation2>
{
    int32_t WINRT_CALL DismissUI() noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(DismissUI, WINRT_WRAP(void));
            this->shim().DismissUI();
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::ApplicationModel::DataTransfer::ShareTarget::IShareOperation3> : produce_base<D, Windows::ApplicationModel::DataTransfer::ShareTarget::IShareOperation3>
{
    int32_t WINRT_CALL get_Contacts(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Contacts, WINRT_WRAP(Windows::Foundation::Collections::IVectorView<Windows::ApplicationModel::Contacts::Contact>));
            *value = detach_from<Windows::Foundation::Collections::IVectorView<Windows::ApplicationModel::Contacts::Contact>>(this->shim().Contacts());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

}

WINRT_EXPORT namespace winrt::Windows::ApplicationModel::DataTransfer::ShareTarget {

inline QuickLink::QuickLink() :
    QuickLink(impl::call_factory<QuickLink>([](auto&& f) { return f.template ActivateInstance<QuickLink>(); }))
{}

}

WINRT_EXPORT namespace std {

template<> struct hash<winrt::Windows::ApplicationModel::DataTransfer::ShareTarget::IQuickLink> : winrt::impl::hash_base<winrt::Windows::ApplicationModel::DataTransfer::ShareTarget::IQuickLink> {};
template<> struct hash<winrt::Windows::ApplicationModel::DataTransfer::ShareTarget::IShareOperation> : winrt::impl::hash_base<winrt::Windows::ApplicationModel::DataTransfer::ShareTarget::IShareOperation> {};
template<> struct hash<winrt::Windows::ApplicationModel::DataTransfer::ShareTarget::IShareOperation2> : winrt::impl::hash_base<winrt::Windows::ApplicationModel::DataTransfer::ShareTarget::IShareOperation2> {};
template<> struct hash<winrt::Windows::ApplicationModel::DataTransfer::ShareTarget::IShareOperation3> : winrt::impl::hash_base<winrt::Windows::ApplicationModel::DataTransfer::ShareTarget::IShareOperation3> {};
template<> struct hash<winrt::Windows::ApplicationModel::DataTransfer::ShareTarget::QuickLink> : winrt::impl::hash_base<winrt::Windows::ApplicationModel::DataTransfer::ShareTarget::QuickLink> {};
template<> struct hash<winrt::Windows::ApplicationModel::DataTransfer::ShareTarget::ShareOperation> : winrt::impl::hash_base<winrt::Windows::ApplicationModel::DataTransfer::ShareTarget::ShareOperation> {};

}
