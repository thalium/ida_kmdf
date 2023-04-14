// C++/WinRT v1.0.190111.3

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#pragma once

#include "winrt/base.h"

#include "winrt/Windows.Foundation.h"
#include "winrt/Windows.Foundation.Collections.h"
#include "winrt/impl/Windows.Storage.2.h"
#include "winrt/impl/Windows.Storage.Streams.2.h"
#include "winrt/impl/Windows.UI.2.h"
#include "winrt/impl/Windows.Foundation.2.h"
#include "winrt/impl/Windows.Data.Pdf.2.h"

namespace winrt::impl {

template <typename D> Windows::Data::Pdf::PdfPage consume_Windows_Data_Pdf_IPdfDocument<D>::GetPage(uint32_t pageIndex) const
{
    Windows::Data::Pdf::PdfPage pdfPage{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Data::Pdf::IPdfDocument)->GetPage(pageIndex, put_abi(pdfPage)));
    return pdfPage;
}

template <typename D> uint32_t consume_Windows_Data_Pdf_IPdfDocument<D>::PageCount() const
{
    uint32_t value{};
    check_hresult(WINRT_SHIM(Windows::Data::Pdf::IPdfDocument)->get_PageCount(&value));
    return value;
}

template <typename D> bool consume_Windows_Data_Pdf_IPdfDocument<D>::IsPasswordProtected() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::Data::Pdf::IPdfDocument)->get_IsPasswordProtected(&value));
    return value;
}

template <typename D> Windows::Foundation::IAsyncOperation<Windows::Data::Pdf::PdfDocument> consume_Windows_Data_Pdf_IPdfDocumentStatics<D>::LoadFromFileAsync(Windows::Storage::IStorageFile const& file) const
{
    Windows::Foundation::IAsyncOperation<Windows::Data::Pdf::PdfDocument> asyncInfo{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Data::Pdf::IPdfDocumentStatics)->LoadFromFileAsync(get_abi(file), put_abi(asyncInfo)));
    return asyncInfo;
}

template <typename D> Windows::Foundation::IAsyncOperation<Windows::Data::Pdf::PdfDocument> consume_Windows_Data_Pdf_IPdfDocumentStatics<D>::LoadFromFileAsync(Windows::Storage::IStorageFile const& file, param::hstring const& password) const
{
    Windows::Foundation::IAsyncOperation<Windows::Data::Pdf::PdfDocument> asyncInfo{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Data::Pdf::IPdfDocumentStatics)->LoadFromFileWithPasswordAsync(get_abi(file), get_abi(password), put_abi(asyncInfo)));
    return asyncInfo;
}

template <typename D> Windows::Foundation::IAsyncOperation<Windows::Data::Pdf::PdfDocument> consume_Windows_Data_Pdf_IPdfDocumentStatics<D>::LoadFromStreamAsync(Windows::Storage::Streams::IRandomAccessStream const& inputStream) const
{
    Windows::Foundation::IAsyncOperation<Windows::Data::Pdf::PdfDocument> asyncInfo{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Data::Pdf::IPdfDocumentStatics)->LoadFromStreamAsync(get_abi(inputStream), put_abi(asyncInfo)));
    return asyncInfo;
}

template <typename D> Windows::Foundation::IAsyncOperation<Windows::Data::Pdf::PdfDocument> consume_Windows_Data_Pdf_IPdfDocumentStatics<D>::LoadFromStreamAsync(Windows::Storage::Streams::IRandomAccessStream const& inputStream, param::hstring const& password) const
{
    Windows::Foundation::IAsyncOperation<Windows::Data::Pdf::PdfDocument> asyncInfo{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Data::Pdf::IPdfDocumentStatics)->LoadFromStreamWithPasswordAsync(get_abi(inputStream), get_abi(password), put_abi(asyncInfo)));
    return asyncInfo;
}

template <typename D> Windows::Foundation::IAsyncAction consume_Windows_Data_Pdf_IPdfPage<D>::RenderToStreamAsync(Windows::Storage::Streams::IRandomAccessStream const& outputStream) const
{
    Windows::Foundation::IAsyncAction asyncInfo{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Data::Pdf::IPdfPage)->RenderToStreamAsync(get_abi(outputStream), put_abi(asyncInfo)));
    return asyncInfo;
}

template <typename D> Windows::Foundation::IAsyncAction consume_Windows_Data_Pdf_IPdfPage<D>::RenderToStreamAsync(Windows::Storage::Streams::IRandomAccessStream const& outputStream, Windows::Data::Pdf::PdfPageRenderOptions const& options) const
{
    Windows::Foundation::IAsyncAction asyncInfo{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Data::Pdf::IPdfPage)->RenderWithOptionsToStreamAsync(get_abi(outputStream), get_abi(options), put_abi(asyncInfo)));
    return asyncInfo;
}

template <typename D> Windows::Foundation::IAsyncAction consume_Windows_Data_Pdf_IPdfPage<D>::PreparePageAsync() const
{
    Windows::Foundation::IAsyncAction asyncInfo{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Data::Pdf::IPdfPage)->PreparePageAsync(put_abi(asyncInfo)));
    return asyncInfo;
}

template <typename D> uint32_t consume_Windows_Data_Pdf_IPdfPage<D>::Index() const
{
    uint32_t value{};
    check_hresult(WINRT_SHIM(Windows::Data::Pdf::IPdfPage)->get_Index(&value));
    return value;
}

template <typename D> Windows::Foundation::Size consume_Windows_Data_Pdf_IPdfPage<D>::Size() const
{
    Windows::Foundation::Size value{};
    check_hresult(WINRT_SHIM(Windows::Data::Pdf::IPdfPage)->get_Size(put_abi(value)));
    return value;
}

template <typename D> Windows::Data::Pdf::PdfPageDimensions consume_Windows_Data_Pdf_IPdfPage<D>::Dimensions() const
{
    Windows::Data::Pdf::PdfPageDimensions value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Data::Pdf::IPdfPage)->get_Dimensions(put_abi(value)));
    return value;
}

template <typename D> Windows::Data::Pdf::PdfPageRotation consume_Windows_Data_Pdf_IPdfPage<D>::Rotation() const
{
    Windows::Data::Pdf::PdfPageRotation value{};
    check_hresult(WINRT_SHIM(Windows::Data::Pdf::IPdfPage)->get_Rotation(put_abi(value)));
    return value;
}

template <typename D> float consume_Windows_Data_Pdf_IPdfPage<D>::PreferredZoom() const
{
    float value{};
    check_hresult(WINRT_SHIM(Windows::Data::Pdf::IPdfPage)->get_PreferredZoom(&value));
    return value;
}

template <typename D> Windows::Foundation::Rect consume_Windows_Data_Pdf_IPdfPageDimensions<D>::MediaBox() const
{
    Windows::Foundation::Rect value{};
    check_hresult(WINRT_SHIM(Windows::Data::Pdf::IPdfPageDimensions)->get_MediaBox(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::Rect consume_Windows_Data_Pdf_IPdfPageDimensions<D>::CropBox() const
{
    Windows::Foundation::Rect value{};
    check_hresult(WINRT_SHIM(Windows::Data::Pdf::IPdfPageDimensions)->get_CropBox(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::Rect consume_Windows_Data_Pdf_IPdfPageDimensions<D>::BleedBox() const
{
    Windows::Foundation::Rect value{};
    check_hresult(WINRT_SHIM(Windows::Data::Pdf::IPdfPageDimensions)->get_BleedBox(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::Rect consume_Windows_Data_Pdf_IPdfPageDimensions<D>::TrimBox() const
{
    Windows::Foundation::Rect value{};
    check_hresult(WINRT_SHIM(Windows::Data::Pdf::IPdfPageDimensions)->get_TrimBox(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::Rect consume_Windows_Data_Pdf_IPdfPageDimensions<D>::ArtBox() const
{
    Windows::Foundation::Rect value{};
    check_hresult(WINRT_SHIM(Windows::Data::Pdf::IPdfPageDimensions)->get_ArtBox(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::Rect consume_Windows_Data_Pdf_IPdfPageRenderOptions<D>::SourceRect() const
{
    Windows::Foundation::Rect value{};
    check_hresult(WINRT_SHIM(Windows::Data::Pdf::IPdfPageRenderOptions)->get_SourceRect(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_Data_Pdf_IPdfPageRenderOptions<D>::SourceRect(Windows::Foundation::Rect const& value) const
{
    check_hresult(WINRT_SHIM(Windows::Data::Pdf::IPdfPageRenderOptions)->put_SourceRect(get_abi(value)));
}

template <typename D> uint32_t consume_Windows_Data_Pdf_IPdfPageRenderOptions<D>::DestinationWidth() const
{
    uint32_t value{};
    check_hresult(WINRT_SHIM(Windows::Data::Pdf::IPdfPageRenderOptions)->get_DestinationWidth(&value));
    return value;
}

template <typename D> void consume_Windows_Data_Pdf_IPdfPageRenderOptions<D>::DestinationWidth(uint32_t value) const
{
    check_hresult(WINRT_SHIM(Windows::Data::Pdf::IPdfPageRenderOptions)->put_DestinationWidth(value));
}

template <typename D> uint32_t consume_Windows_Data_Pdf_IPdfPageRenderOptions<D>::DestinationHeight() const
{
    uint32_t value{};
    check_hresult(WINRT_SHIM(Windows::Data::Pdf::IPdfPageRenderOptions)->get_DestinationHeight(&value));
    return value;
}

template <typename D> void consume_Windows_Data_Pdf_IPdfPageRenderOptions<D>::DestinationHeight(uint32_t value) const
{
    check_hresult(WINRT_SHIM(Windows::Data::Pdf::IPdfPageRenderOptions)->put_DestinationHeight(value));
}

template <typename D> Windows::UI::Color consume_Windows_Data_Pdf_IPdfPageRenderOptions<D>::BackgroundColor() const
{
    Windows::UI::Color value{};
    check_hresult(WINRT_SHIM(Windows::Data::Pdf::IPdfPageRenderOptions)->get_BackgroundColor(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_Data_Pdf_IPdfPageRenderOptions<D>::BackgroundColor(Windows::UI::Color const& value) const
{
    check_hresult(WINRT_SHIM(Windows::Data::Pdf::IPdfPageRenderOptions)->put_BackgroundColor(get_abi(value)));
}

template <typename D> bool consume_Windows_Data_Pdf_IPdfPageRenderOptions<D>::IsIgnoringHighContrast() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::Data::Pdf::IPdfPageRenderOptions)->get_IsIgnoringHighContrast(&value));
    return value;
}

template <typename D> void consume_Windows_Data_Pdf_IPdfPageRenderOptions<D>::IsIgnoringHighContrast(bool value) const
{
    check_hresult(WINRT_SHIM(Windows::Data::Pdf::IPdfPageRenderOptions)->put_IsIgnoringHighContrast(value));
}

template <typename D> winrt::guid consume_Windows_Data_Pdf_IPdfPageRenderOptions<D>::BitmapEncoderId() const
{
    winrt::guid value{};
    check_hresult(WINRT_SHIM(Windows::Data::Pdf::IPdfPageRenderOptions)->get_BitmapEncoderId(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_Data_Pdf_IPdfPageRenderOptions<D>::BitmapEncoderId(winrt::guid const& value) const
{
    check_hresult(WINRT_SHIM(Windows::Data::Pdf::IPdfPageRenderOptions)->put_BitmapEncoderId(get_abi(value)));
}

template <typename D>
struct produce<D, Windows::Data::Pdf::IPdfDocument> : produce_base<D, Windows::Data::Pdf::IPdfDocument>
{
    int32_t WINRT_CALL GetPage(uint32_t pageIndex, void** pdfPage) noexcept final
    {
        try
        {
            *pdfPage = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetPage, WINRT_WRAP(Windows::Data::Pdf::PdfPage), uint32_t);
            *pdfPage = detach_from<Windows::Data::Pdf::PdfPage>(this->shim().GetPage(pageIndex));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_PageCount(uint32_t* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(PageCount, WINRT_WRAP(uint32_t));
            *value = detach_from<uint32_t>(this->shim().PageCount());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_IsPasswordProtected(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IsPasswordProtected, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().IsPasswordProtected());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Data::Pdf::IPdfDocumentStatics> : produce_base<D, Windows::Data::Pdf::IPdfDocumentStatics>
{
    int32_t WINRT_CALL LoadFromFileAsync(void* file, void** asyncInfo) noexcept final
    {
        try
        {
            *asyncInfo = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(LoadFromFileAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<Windows::Data::Pdf::PdfDocument>), Windows::Storage::IStorageFile const);
            *asyncInfo = detach_from<Windows::Foundation::IAsyncOperation<Windows::Data::Pdf::PdfDocument>>(this->shim().LoadFromFileAsync(*reinterpret_cast<Windows::Storage::IStorageFile const*>(&file)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL LoadFromFileWithPasswordAsync(void* file, void* password, void** asyncInfo) noexcept final
    {
        try
        {
            *asyncInfo = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(LoadFromFileAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<Windows::Data::Pdf::PdfDocument>), Windows::Storage::IStorageFile const, hstring const);
            *asyncInfo = detach_from<Windows::Foundation::IAsyncOperation<Windows::Data::Pdf::PdfDocument>>(this->shim().LoadFromFileAsync(*reinterpret_cast<Windows::Storage::IStorageFile const*>(&file), *reinterpret_cast<hstring const*>(&password)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL LoadFromStreamAsync(void* inputStream, void** asyncInfo) noexcept final
    {
        try
        {
            *asyncInfo = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(LoadFromStreamAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<Windows::Data::Pdf::PdfDocument>), Windows::Storage::Streams::IRandomAccessStream const);
            *asyncInfo = detach_from<Windows::Foundation::IAsyncOperation<Windows::Data::Pdf::PdfDocument>>(this->shim().LoadFromStreamAsync(*reinterpret_cast<Windows::Storage::Streams::IRandomAccessStream const*>(&inputStream)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL LoadFromStreamWithPasswordAsync(void* inputStream, void* password, void** asyncInfo) noexcept final
    {
        try
        {
            *asyncInfo = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(LoadFromStreamAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<Windows::Data::Pdf::PdfDocument>), Windows::Storage::Streams::IRandomAccessStream const, hstring const);
            *asyncInfo = detach_from<Windows::Foundation::IAsyncOperation<Windows::Data::Pdf::PdfDocument>>(this->shim().LoadFromStreamAsync(*reinterpret_cast<Windows::Storage::Streams::IRandomAccessStream const*>(&inputStream), *reinterpret_cast<hstring const*>(&password)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Data::Pdf::IPdfPage> : produce_base<D, Windows::Data::Pdf::IPdfPage>
{
    int32_t WINRT_CALL RenderToStreamAsync(void* outputStream, void** asyncInfo) noexcept final
    {
        try
        {
            *asyncInfo = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(RenderToStreamAsync, WINRT_WRAP(Windows::Foundation::IAsyncAction), Windows::Storage::Streams::IRandomAccessStream const);
            *asyncInfo = detach_from<Windows::Foundation::IAsyncAction>(this->shim().RenderToStreamAsync(*reinterpret_cast<Windows::Storage::Streams::IRandomAccessStream const*>(&outputStream)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL RenderWithOptionsToStreamAsync(void* outputStream, void* options, void** asyncInfo) noexcept final
    {
        try
        {
            *asyncInfo = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(RenderToStreamAsync, WINRT_WRAP(Windows::Foundation::IAsyncAction), Windows::Storage::Streams::IRandomAccessStream const, Windows::Data::Pdf::PdfPageRenderOptions const);
            *asyncInfo = detach_from<Windows::Foundation::IAsyncAction>(this->shim().RenderToStreamAsync(*reinterpret_cast<Windows::Storage::Streams::IRandomAccessStream const*>(&outputStream), *reinterpret_cast<Windows::Data::Pdf::PdfPageRenderOptions const*>(&options)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL PreparePageAsync(void** asyncInfo) noexcept final
    {
        try
        {
            *asyncInfo = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(PreparePageAsync, WINRT_WRAP(Windows::Foundation::IAsyncAction));
            *asyncInfo = detach_from<Windows::Foundation::IAsyncAction>(this->shim().PreparePageAsync());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Index(uint32_t* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Index, WINRT_WRAP(uint32_t));
            *value = detach_from<uint32_t>(this->shim().Index());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Size(Windows::Foundation::Size* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Size, WINRT_WRAP(Windows::Foundation::Size));
            *value = detach_from<Windows::Foundation::Size>(this->shim().Size());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Dimensions(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Dimensions, WINRT_WRAP(Windows::Data::Pdf::PdfPageDimensions));
            *value = detach_from<Windows::Data::Pdf::PdfPageDimensions>(this->shim().Dimensions());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Rotation(Windows::Data::Pdf::PdfPageRotation* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Rotation, WINRT_WRAP(Windows::Data::Pdf::PdfPageRotation));
            *value = detach_from<Windows::Data::Pdf::PdfPageRotation>(this->shim().Rotation());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_PreferredZoom(float* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(PreferredZoom, WINRT_WRAP(float));
            *value = detach_from<float>(this->shim().PreferredZoom());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Data::Pdf::IPdfPageDimensions> : produce_base<D, Windows::Data::Pdf::IPdfPageDimensions>
{
    int32_t WINRT_CALL get_MediaBox(Windows::Foundation::Rect* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(MediaBox, WINRT_WRAP(Windows::Foundation::Rect));
            *value = detach_from<Windows::Foundation::Rect>(this->shim().MediaBox());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_CropBox(Windows::Foundation::Rect* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CropBox, WINRT_WRAP(Windows::Foundation::Rect));
            *value = detach_from<Windows::Foundation::Rect>(this->shim().CropBox());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_BleedBox(Windows::Foundation::Rect* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(BleedBox, WINRT_WRAP(Windows::Foundation::Rect));
            *value = detach_from<Windows::Foundation::Rect>(this->shim().BleedBox());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_TrimBox(Windows::Foundation::Rect* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(TrimBox, WINRT_WRAP(Windows::Foundation::Rect));
            *value = detach_from<Windows::Foundation::Rect>(this->shim().TrimBox());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_ArtBox(Windows::Foundation::Rect* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ArtBox, WINRT_WRAP(Windows::Foundation::Rect));
            *value = detach_from<Windows::Foundation::Rect>(this->shim().ArtBox());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Data::Pdf::IPdfPageRenderOptions> : produce_base<D, Windows::Data::Pdf::IPdfPageRenderOptions>
{
    int32_t WINRT_CALL get_SourceRect(Windows::Foundation::Rect* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SourceRect, WINRT_WRAP(Windows::Foundation::Rect));
            *value = detach_from<Windows::Foundation::Rect>(this->shim().SourceRect());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_SourceRect(Windows::Foundation::Rect value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SourceRect, WINRT_WRAP(void), Windows::Foundation::Rect const&);
            this->shim().SourceRect(*reinterpret_cast<Windows::Foundation::Rect const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_DestinationWidth(uint32_t* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(DestinationWidth, WINRT_WRAP(uint32_t));
            *value = detach_from<uint32_t>(this->shim().DestinationWidth());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_DestinationWidth(uint32_t value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(DestinationWidth, WINRT_WRAP(void), uint32_t);
            this->shim().DestinationWidth(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_DestinationHeight(uint32_t* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(DestinationHeight, WINRT_WRAP(uint32_t));
            *value = detach_from<uint32_t>(this->shim().DestinationHeight());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_DestinationHeight(uint32_t value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(DestinationHeight, WINRT_WRAP(void), uint32_t);
            this->shim().DestinationHeight(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_BackgroundColor(struct struct_Windows_UI_Color* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(BackgroundColor, WINRT_WRAP(Windows::UI::Color));
            *value = detach_from<Windows::UI::Color>(this->shim().BackgroundColor());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_BackgroundColor(struct struct_Windows_UI_Color value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(BackgroundColor, WINRT_WRAP(void), Windows::UI::Color const&);
            this->shim().BackgroundColor(*reinterpret_cast<Windows::UI::Color const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_IsIgnoringHighContrast(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IsIgnoringHighContrast, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().IsIgnoringHighContrast());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_IsIgnoringHighContrast(bool value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IsIgnoringHighContrast, WINRT_WRAP(void), bool);
            this->shim().IsIgnoringHighContrast(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_BitmapEncoderId(winrt::guid* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(BitmapEncoderId, WINRT_WRAP(winrt::guid));
            *value = detach_from<winrt::guid>(this->shim().BitmapEncoderId());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_BitmapEncoderId(winrt::guid value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(BitmapEncoderId, WINRT_WRAP(void), winrt::guid const&);
            this->shim().BitmapEncoderId(*reinterpret_cast<winrt::guid const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

}

WINRT_EXPORT namespace winrt::Windows::Data::Pdf {

inline Windows::Foundation::IAsyncOperation<Windows::Data::Pdf::PdfDocument> PdfDocument::LoadFromFileAsync(Windows::Storage::IStorageFile const& file)
{
    return impl::call_factory<PdfDocument, Windows::Data::Pdf::IPdfDocumentStatics>([&](auto&& f) { return f.LoadFromFileAsync(file); });
}

inline Windows::Foundation::IAsyncOperation<Windows::Data::Pdf::PdfDocument> PdfDocument::LoadFromFileAsync(Windows::Storage::IStorageFile const& file, param::hstring const& password)
{
    return impl::call_factory<PdfDocument, Windows::Data::Pdf::IPdfDocumentStatics>([&](auto&& f) { return f.LoadFromFileAsync(file, password); });
}

inline Windows::Foundation::IAsyncOperation<Windows::Data::Pdf::PdfDocument> PdfDocument::LoadFromStreamAsync(Windows::Storage::Streams::IRandomAccessStream const& inputStream)
{
    return impl::call_factory<PdfDocument, Windows::Data::Pdf::IPdfDocumentStatics>([&](auto&& f) { return f.LoadFromStreamAsync(inputStream); });
}

inline Windows::Foundation::IAsyncOperation<Windows::Data::Pdf::PdfDocument> PdfDocument::LoadFromStreamAsync(Windows::Storage::Streams::IRandomAccessStream const& inputStream, param::hstring const& password)
{
    return impl::call_factory<PdfDocument, Windows::Data::Pdf::IPdfDocumentStatics>([&](auto&& f) { return f.LoadFromStreamAsync(inputStream, password); });
}

inline PdfPageRenderOptions::PdfPageRenderOptions() :
    PdfPageRenderOptions(impl::call_factory<PdfPageRenderOptions>([](auto&& f) { return f.template ActivateInstance<PdfPageRenderOptions>(); }))
{}

}

WINRT_EXPORT namespace std {

template<> struct hash<winrt::Windows::Data::Pdf::IPdfDocument> : winrt::impl::hash_base<winrt::Windows::Data::Pdf::IPdfDocument> {};
template<> struct hash<winrt::Windows::Data::Pdf::IPdfDocumentStatics> : winrt::impl::hash_base<winrt::Windows::Data::Pdf::IPdfDocumentStatics> {};
template<> struct hash<winrt::Windows::Data::Pdf::IPdfPage> : winrt::impl::hash_base<winrt::Windows::Data::Pdf::IPdfPage> {};
template<> struct hash<winrt::Windows::Data::Pdf::IPdfPageDimensions> : winrt::impl::hash_base<winrt::Windows::Data::Pdf::IPdfPageDimensions> {};
template<> struct hash<winrt::Windows::Data::Pdf::IPdfPageRenderOptions> : winrt::impl::hash_base<winrt::Windows::Data::Pdf::IPdfPageRenderOptions> {};
template<> struct hash<winrt::Windows::Data::Pdf::PdfDocument> : winrt::impl::hash_base<winrt::Windows::Data::Pdf::PdfDocument> {};
template<> struct hash<winrt::Windows::Data::Pdf::PdfPage> : winrt::impl::hash_base<winrt::Windows::Data::Pdf::PdfPage> {};
template<> struct hash<winrt::Windows::Data::Pdf::PdfPageDimensions> : winrt::impl::hash_base<winrt::Windows::Data::Pdf::PdfPageDimensions> {};
template<> struct hash<winrt::Windows::Data::Pdf::PdfPageRenderOptions> : winrt::impl::hash_base<winrt::Windows::Data::Pdf::PdfPageRenderOptions> {};

}
