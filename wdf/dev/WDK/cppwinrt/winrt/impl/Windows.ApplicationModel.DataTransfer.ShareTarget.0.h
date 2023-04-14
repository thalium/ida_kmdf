// C++/WinRT v1.0.190111.3

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#pragma once

WINRT_EXPORT namespace winrt::Windows::ApplicationModel::Contacts {

struct Contact;

}

WINRT_EXPORT namespace winrt::Windows::ApplicationModel::DataTransfer {

struct DataPackageView;

}

WINRT_EXPORT namespace winrt::Windows::Storage::Streams {

struct RandomAccessStreamReference;

}

WINRT_EXPORT namespace winrt::Windows::ApplicationModel::DataTransfer::ShareTarget {

struct IQuickLink;
struct IShareOperation;
struct IShareOperation2;
struct IShareOperation3;
struct QuickLink;
struct ShareOperation;

}

namespace winrt::impl {

template <> struct category<Windows::ApplicationModel::DataTransfer::ShareTarget::IQuickLink>{ using type = interface_category; };
template <> struct category<Windows::ApplicationModel::DataTransfer::ShareTarget::IShareOperation>{ using type = interface_category; };
template <> struct category<Windows::ApplicationModel::DataTransfer::ShareTarget::IShareOperation2>{ using type = interface_category; };
template <> struct category<Windows::ApplicationModel::DataTransfer::ShareTarget::IShareOperation3>{ using type = interface_category; };
template <> struct category<Windows::ApplicationModel::DataTransfer::ShareTarget::QuickLink>{ using type = class_category; };
template <> struct category<Windows::ApplicationModel::DataTransfer::ShareTarget::ShareOperation>{ using type = class_category; };
template <> struct name<Windows::ApplicationModel::DataTransfer::ShareTarget::IQuickLink>{ static constexpr auto & value{ L"Windows.ApplicationModel.DataTransfer.ShareTarget.IQuickLink" }; };
template <> struct name<Windows::ApplicationModel::DataTransfer::ShareTarget::IShareOperation>{ static constexpr auto & value{ L"Windows.ApplicationModel.DataTransfer.ShareTarget.IShareOperation" }; };
template <> struct name<Windows::ApplicationModel::DataTransfer::ShareTarget::IShareOperation2>{ static constexpr auto & value{ L"Windows.ApplicationModel.DataTransfer.ShareTarget.IShareOperation2" }; };
template <> struct name<Windows::ApplicationModel::DataTransfer::ShareTarget::IShareOperation3>{ static constexpr auto & value{ L"Windows.ApplicationModel.DataTransfer.ShareTarget.IShareOperation3" }; };
template <> struct name<Windows::ApplicationModel::DataTransfer::ShareTarget::QuickLink>{ static constexpr auto & value{ L"Windows.ApplicationModel.DataTransfer.ShareTarget.QuickLink" }; };
template <> struct name<Windows::ApplicationModel::DataTransfer::ShareTarget::ShareOperation>{ static constexpr auto & value{ L"Windows.ApplicationModel.DataTransfer.ShareTarget.ShareOperation" }; };
template <> struct guid_storage<Windows::ApplicationModel::DataTransfer::ShareTarget::IQuickLink>{ static constexpr guid value{ 0x603E4308,0xF0BE,0x4ADC,{ 0xAC,0xC9,0x8B,0x27,0xAB,0x9C,0xF5,0x56 } }; };
template <> struct guid_storage<Windows::ApplicationModel::DataTransfer::ShareTarget::IShareOperation>{ static constexpr guid value{ 0x2246BAB8,0xD0F8,0x41C1,{ 0xA8,0x2A,0x41,0x37,0xDB,0x65,0x04,0xFB } }; };
template <> struct guid_storage<Windows::ApplicationModel::DataTransfer::ShareTarget::IShareOperation2>{ static constexpr guid value{ 0x0FFB97C1,0x9778,0x4A09,{ 0x8E,0x5B,0xCB,0x5E,0x48,0x2D,0x05,0x55 } }; };
template <> struct guid_storage<Windows::ApplicationModel::DataTransfer::ShareTarget::IShareOperation3>{ static constexpr guid value{ 0x5EF6B382,0xB7A7,0x4571,{ 0xA2,0xA6,0x99,0x4A,0x03,0x49,0x88,0xB2 } }; };
template <> struct default_interface<Windows::ApplicationModel::DataTransfer::ShareTarget::QuickLink>{ using type = Windows::ApplicationModel::DataTransfer::ShareTarget::IQuickLink; };
template <> struct default_interface<Windows::ApplicationModel::DataTransfer::ShareTarget::ShareOperation>{ using type = Windows::ApplicationModel::DataTransfer::ShareTarget::IShareOperation; };

template <> struct abi<Windows::ApplicationModel::DataTransfer::ShareTarget::IQuickLink>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL get_Title(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL put_Title(void* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_Thumbnail(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL put_Thumbnail(void* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_Id(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL put_Id(void* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_SupportedDataFormats(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_SupportedFileTypes(void** value) noexcept = 0;
};};

template <> struct abi<Windows::ApplicationModel::DataTransfer::ShareTarget::IShareOperation>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL get_Data(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_QuickLinkId(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL RemoveThisQuickLink() noexcept = 0;
    virtual int32_t WINRT_CALL ReportStarted() noexcept = 0;
    virtual int32_t WINRT_CALL ReportDataRetrieved() noexcept = 0;
    virtual int32_t WINRT_CALL ReportSubmittedBackgroundTask() noexcept = 0;
    virtual int32_t WINRT_CALL ReportCompletedWithQuickLink(void* quicklink) noexcept = 0;
    virtual int32_t WINRT_CALL ReportCompleted() noexcept = 0;
    virtual int32_t WINRT_CALL ReportError(void* value) noexcept = 0;
};};

template <> struct abi<Windows::ApplicationModel::DataTransfer::ShareTarget::IShareOperation2>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL DismissUI() noexcept = 0;
};};

template <> struct abi<Windows::ApplicationModel::DataTransfer::ShareTarget::IShareOperation3>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL get_Contacts(void** value) noexcept = 0;
};};

template <typename D>
struct consume_Windows_ApplicationModel_DataTransfer_ShareTarget_IQuickLink
{
    hstring Title() const;
    void Title(param::hstring const& value) const;
    Windows::Storage::Streams::RandomAccessStreamReference Thumbnail() const;
    void Thumbnail(Windows::Storage::Streams::RandomAccessStreamReference const& value) const;
    hstring Id() const;
    void Id(param::hstring const& value) const;
    Windows::Foundation::Collections::IVector<hstring> SupportedDataFormats() const;
    Windows::Foundation::Collections::IVector<hstring> SupportedFileTypes() const;
};
template <> struct consume<Windows::ApplicationModel::DataTransfer::ShareTarget::IQuickLink> { template <typename D> using type = consume_Windows_ApplicationModel_DataTransfer_ShareTarget_IQuickLink<D>; };

template <typename D>
struct consume_Windows_ApplicationModel_DataTransfer_ShareTarget_IShareOperation
{
    Windows::ApplicationModel::DataTransfer::DataPackageView Data() const;
    hstring QuickLinkId() const;
    void RemoveThisQuickLink() const;
    void ReportStarted() const;
    void ReportDataRetrieved() const;
    void ReportSubmittedBackgroundTask() const;
    void ReportCompleted(Windows::ApplicationModel::DataTransfer::ShareTarget::QuickLink const& quicklink) const;
    void ReportCompleted() const;
    void ReportError(param::hstring const& value) const;
};
template <> struct consume<Windows::ApplicationModel::DataTransfer::ShareTarget::IShareOperation> { template <typename D> using type = consume_Windows_ApplicationModel_DataTransfer_ShareTarget_IShareOperation<D>; };

template <typename D>
struct consume_Windows_ApplicationModel_DataTransfer_ShareTarget_IShareOperation2
{
    void DismissUI() const;
};
template <> struct consume<Windows::ApplicationModel::DataTransfer::ShareTarget::IShareOperation2> { template <typename D> using type = consume_Windows_ApplicationModel_DataTransfer_ShareTarget_IShareOperation2<D>; };

template <typename D>
struct consume_Windows_ApplicationModel_DataTransfer_ShareTarget_IShareOperation3
{
    Windows::Foundation::Collections::IVectorView<Windows::ApplicationModel::Contacts::Contact> Contacts() const;
};
template <> struct consume<Windows::ApplicationModel::DataTransfer::ShareTarget::IShareOperation3> { template <typename D> using type = consume_Windows_ApplicationModel_DataTransfer_ShareTarget_IShareOperation3<D>; };

}
