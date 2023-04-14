// C++/WinRT v1.0.190111.3

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#pragma once

WINRT_EXPORT namespace winrt::Windows::Storage {

struct IStorageFile;

}

WINRT_EXPORT namespace winrt::Windows::Storage::Streams {

struct IRandomAccessStream;

}

WINRT_EXPORT namespace winrt::Windows::UI {

struct Color;

}

WINRT_EXPORT namespace winrt::Windows::Data::Pdf {

enum class PdfPageRotation : int32_t
{
    Normal = 0,
    Rotate90 = 1,
    Rotate180 = 2,
    Rotate270 = 3,
};

struct IPdfDocument;
struct IPdfDocumentStatics;
struct IPdfPage;
struct IPdfPageDimensions;
struct IPdfPageRenderOptions;
struct PdfDocument;
struct PdfPage;
struct PdfPageDimensions;
struct PdfPageRenderOptions;

}

namespace winrt::impl {

template <> struct category<Windows::Data::Pdf::IPdfDocument>{ using type = interface_category; };
template <> struct category<Windows::Data::Pdf::IPdfDocumentStatics>{ using type = interface_category; };
template <> struct category<Windows::Data::Pdf::IPdfPage>{ using type = interface_category; };
template <> struct category<Windows::Data::Pdf::IPdfPageDimensions>{ using type = interface_category; };
template <> struct category<Windows::Data::Pdf::IPdfPageRenderOptions>{ using type = interface_category; };
template <> struct category<Windows::Data::Pdf::PdfDocument>{ using type = class_category; };
template <> struct category<Windows::Data::Pdf::PdfPage>{ using type = class_category; };
template <> struct category<Windows::Data::Pdf::PdfPageDimensions>{ using type = class_category; };
template <> struct category<Windows::Data::Pdf::PdfPageRenderOptions>{ using type = class_category; };
template <> struct category<Windows::Data::Pdf::PdfPageRotation>{ using type = enum_category; };
template <> struct name<Windows::Data::Pdf::IPdfDocument>{ static constexpr auto & value{ L"Windows.Data.Pdf.IPdfDocument" }; };
template <> struct name<Windows::Data::Pdf::IPdfDocumentStatics>{ static constexpr auto & value{ L"Windows.Data.Pdf.IPdfDocumentStatics" }; };
template <> struct name<Windows::Data::Pdf::IPdfPage>{ static constexpr auto & value{ L"Windows.Data.Pdf.IPdfPage" }; };
template <> struct name<Windows::Data::Pdf::IPdfPageDimensions>{ static constexpr auto & value{ L"Windows.Data.Pdf.IPdfPageDimensions" }; };
template <> struct name<Windows::Data::Pdf::IPdfPageRenderOptions>{ static constexpr auto & value{ L"Windows.Data.Pdf.IPdfPageRenderOptions" }; };
template <> struct name<Windows::Data::Pdf::PdfDocument>{ static constexpr auto & value{ L"Windows.Data.Pdf.PdfDocument" }; };
template <> struct name<Windows::Data::Pdf::PdfPage>{ static constexpr auto & value{ L"Windows.Data.Pdf.PdfPage" }; };
template <> struct name<Windows::Data::Pdf::PdfPageDimensions>{ static constexpr auto & value{ L"Windows.Data.Pdf.PdfPageDimensions" }; };
template <> struct name<Windows::Data::Pdf::PdfPageRenderOptions>{ static constexpr auto & value{ L"Windows.Data.Pdf.PdfPageRenderOptions" }; };
template <> struct name<Windows::Data::Pdf::PdfPageRotation>{ static constexpr auto & value{ L"Windows.Data.Pdf.PdfPageRotation" }; };
template <> struct guid_storage<Windows::Data::Pdf::IPdfDocument>{ static constexpr guid value{ 0xAC7EBEDD,0x80FA,0x4089,{ 0x84,0x6E,0x81,0xB7,0x7F,0xF5,0xA8,0x6C } }; };
template <> struct guid_storage<Windows::Data::Pdf::IPdfDocumentStatics>{ static constexpr guid value{ 0x433A0B5F,0xC007,0x4788,{ 0x90,0xF2,0x08,0x14,0x3D,0x92,0x25,0x99 } }; };
template <> struct guid_storage<Windows::Data::Pdf::IPdfPage>{ static constexpr guid value{ 0x9DB4B0C8,0x5320,0x4CFC,{ 0xAD,0x76,0x49,0x3F,0xDA,0xD0,0xE5,0x94 } }; };
template <> struct guid_storage<Windows::Data::Pdf::IPdfPageDimensions>{ static constexpr guid value{ 0x22170471,0x313E,0x44E8,{ 0x83,0x5D,0x63,0xA3,0xE7,0x62,0x4A,0x10 } }; };
template <> struct guid_storage<Windows::Data::Pdf::IPdfPageRenderOptions>{ static constexpr guid value{ 0x3C98056F,0xB7CF,0x4C29,{ 0x9A,0x04,0x52,0xD9,0x02,0x67,0xF4,0x25 } }; };
template <> struct default_interface<Windows::Data::Pdf::PdfDocument>{ using type = Windows::Data::Pdf::IPdfDocument; };
template <> struct default_interface<Windows::Data::Pdf::PdfPage>{ using type = Windows::Data::Pdf::IPdfPage; };
template <> struct default_interface<Windows::Data::Pdf::PdfPageDimensions>{ using type = Windows::Data::Pdf::IPdfPageDimensions; };
template <> struct default_interface<Windows::Data::Pdf::PdfPageRenderOptions>{ using type = Windows::Data::Pdf::IPdfPageRenderOptions; };

template <> struct abi<Windows::Data::Pdf::IPdfDocument>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL GetPage(uint32_t pageIndex, void** pdfPage) noexcept = 0;
    virtual int32_t WINRT_CALL get_PageCount(uint32_t* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_IsPasswordProtected(bool* value) noexcept = 0;
};};

template <> struct abi<Windows::Data::Pdf::IPdfDocumentStatics>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL LoadFromFileAsync(void* file, void** asyncInfo) noexcept = 0;
    virtual int32_t WINRT_CALL LoadFromFileWithPasswordAsync(void* file, void* password, void** asyncInfo) noexcept = 0;
    virtual int32_t WINRT_CALL LoadFromStreamAsync(void* inputStream, void** asyncInfo) noexcept = 0;
    virtual int32_t WINRT_CALL LoadFromStreamWithPasswordAsync(void* inputStream, void* password, void** asyncInfo) noexcept = 0;
};};

template <> struct abi<Windows::Data::Pdf::IPdfPage>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL RenderToStreamAsync(void* outputStream, void** asyncInfo) noexcept = 0;
    virtual int32_t WINRT_CALL RenderWithOptionsToStreamAsync(void* outputStream, void* options, void** asyncInfo) noexcept = 0;
    virtual int32_t WINRT_CALL PreparePageAsync(void** asyncInfo) noexcept = 0;
    virtual int32_t WINRT_CALL get_Index(uint32_t* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_Size(Windows::Foundation::Size* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_Dimensions(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_Rotation(Windows::Data::Pdf::PdfPageRotation* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_PreferredZoom(float* value) noexcept = 0;
};};

template <> struct abi<Windows::Data::Pdf::IPdfPageDimensions>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL get_MediaBox(Windows::Foundation::Rect* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_CropBox(Windows::Foundation::Rect* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_BleedBox(Windows::Foundation::Rect* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_TrimBox(Windows::Foundation::Rect* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_ArtBox(Windows::Foundation::Rect* value) noexcept = 0;
};};

template <> struct abi<Windows::Data::Pdf::IPdfPageRenderOptions>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL get_SourceRect(Windows::Foundation::Rect* value) noexcept = 0;
    virtual int32_t WINRT_CALL put_SourceRect(Windows::Foundation::Rect value) noexcept = 0;
    virtual int32_t WINRT_CALL get_DestinationWidth(uint32_t* value) noexcept = 0;
    virtual int32_t WINRT_CALL put_DestinationWidth(uint32_t value) noexcept = 0;
    virtual int32_t WINRT_CALL get_DestinationHeight(uint32_t* value) noexcept = 0;
    virtual int32_t WINRT_CALL put_DestinationHeight(uint32_t value) noexcept = 0;
    virtual int32_t WINRT_CALL get_BackgroundColor(struct struct_Windows_UI_Color* value) noexcept = 0;
    virtual int32_t WINRT_CALL put_BackgroundColor(struct struct_Windows_UI_Color value) noexcept = 0;
    virtual int32_t WINRT_CALL get_IsIgnoringHighContrast(bool* value) noexcept = 0;
    virtual int32_t WINRT_CALL put_IsIgnoringHighContrast(bool value) noexcept = 0;
    virtual int32_t WINRT_CALL get_BitmapEncoderId(winrt::guid* value) noexcept = 0;
    virtual int32_t WINRT_CALL put_BitmapEncoderId(winrt::guid value) noexcept = 0;
};};

template <typename D>
struct consume_Windows_Data_Pdf_IPdfDocument
{
    Windows::Data::Pdf::PdfPage GetPage(uint32_t pageIndex) const;
    uint32_t PageCount() const;
    bool IsPasswordProtected() const;
};
template <> struct consume<Windows::Data::Pdf::IPdfDocument> { template <typename D> using type = consume_Windows_Data_Pdf_IPdfDocument<D>; };

template <typename D>
struct consume_Windows_Data_Pdf_IPdfDocumentStatics
{
    Windows::Foundation::IAsyncOperation<Windows::Data::Pdf::PdfDocument> LoadFromFileAsync(Windows::Storage::IStorageFile const& file) const;
    Windows::Foundation::IAsyncOperation<Windows::Data::Pdf::PdfDocument> LoadFromFileAsync(Windows::Storage::IStorageFile const& file, param::hstring const& password) const;
    Windows::Foundation::IAsyncOperation<Windows::Data::Pdf::PdfDocument> LoadFromStreamAsync(Windows::Storage::Streams::IRandomAccessStream const& inputStream) const;
    Windows::Foundation::IAsyncOperation<Windows::Data::Pdf::PdfDocument> LoadFromStreamAsync(Windows::Storage::Streams::IRandomAccessStream const& inputStream, param::hstring const& password) const;
};
template <> struct consume<Windows::Data::Pdf::IPdfDocumentStatics> { template <typename D> using type = consume_Windows_Data_Pdf_IPdfDocumentStatics<D>; };

template <typename D>
struct consume_Windows_Data_Pdf_IPdfPage
{
    Windows::Foundation::IAsyncAction RenderToStreamAsync(Windows::Storage::Streams::IRandomAccessStream const& outputStream) const;
    Windows::Foundation::IAsyncAction RenderToStreamAsync(Windows::Storage::Streams::IRandomAccessStream const& outputStream, Windows::Data::Pdf::PdfPageRenderOptions const& options) const;
    Windows::Foundation::IAsyncAction PreparePageAsync() const;
    uint32_t Index() const;
    Windows::Foundation::Size Size() const;
    Windows::Data::Pdf::PdfPageDimensions Dimensions() const;
    Windows::Data::Pdf::PdfPageRotation Rotation() const;
    float PreferredZoom() const;
};
template <> struct consume<Windows::Data::Pdf::IPdfPage> { template <typename D> using type = consume_Windows_Data_Pdf_IPdfPage<D>; };

template <typename D>
struct consume_Windows_Data_Pdf_IPdfPageDimensions
{
    Windows::Foundation::Rect MediaBox() const;
    Windows::Foundation::Rect CropBox() const;
    Windows::Foundation::Rect BleedBox() const;
    Windows::Foundation::Rect TrimBox() const;
    Windows::Foundation::Rect ArtBox() const;
};
template <> struct consume<Windows::Data::Pdf::IPdfPageDimensions> { template <typename D> using type = consume_Windows_Data_Pdf_IPdfPageDimensions<D>; };

template <typename D>
struct consume_Windows_Data_Pdf_IPdfPageRenderOptions
{
    Windows::Foundation::Rect SourceRect() const;
    void SourceRect(Windows::Foundation::Rect const& value) const;
    uint32_t DestinationWidth() const;
    void DestinationWidth(uint32_t value) const;
    uint32_t DestinationHeight() const;
    void DestinationHeight(uint32_t value) const;
    Windows::UI::Color BackgroundColor() const;
    void BackgroundColor(Windows::UI::Color const& value) const;
    bool IsIgnoringHighContrast() const;
    void IsIgnoringHighContrast(bool value) const;
    winrt::guid BitmapEncoderId() const;
    void BitmapEncoderId(winrt::guid const& value) const;
};
template <> struct consume<Windows::Data::Pdf::IPdfPageRenderOptions> { template <typename D> using type = consume_Windows_Data_Pdf_IPdfPageRenderOptions<D>; };

}
