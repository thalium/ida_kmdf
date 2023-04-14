// C++/WinRT v1.0.190111.3

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#pragma once

#include "winrt/base.h"

#include "winrt/Windows.Foundation.h"
#include "winrt/Windows.Foundation.Collections.h"
#include "winrt/impl/Windows.Graphics.Display.Core.2.h"
#include "winrt/Windows.Graphics.Display.h"

namespace winrt::impl {

template <typename D> Windows::Foundation::Collections::IVectorView<Windows::Graphics::Display::Core::HdmiDisplayMode> consume_Windows_Graphics_Display_Core_IHdmiDisplayInformation<D>::GetSupportedDisplayModes() const
{
    Windows::Foundation::Collections::IVectorView<Windows::Graphics::Display::Core::HdmiDisplayMode> result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Graphics::Display::Core::IHdmiDisplayInformation)->GetSupportedDisplayModes(put_abi(result)));
    return result;
}

template <typename D> Windows::Graphics::Display::Core::HdmiDisplayMode consume_Windows_Graphics_Display_Core_IHdmiDisplayInformation<D>::GetCurrentDisplayMode() const
{
    Windows::Graphics::Display::Core::HdmiDisplayMode result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Graphics::Display::Core::IHdmiDisplayInformation)->GetCurrentDisplayMode(put_abi(result)));
    return result;
}

template <typename D> Windows::Foundation::IAsyncAction consume_Windows_Graphics_Display_Core_IHdmiDisplayInformation<D>::SetDefaultDisplayModeAsync() const
{
    Windows::Foundation::IAsyncAction operation{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Graphics::Display::Core::IHdmiDisplayInformation)->SetDefaultDisplayModeAsync(put_abi(operation)));
    return operation;
}

template <typename D> Windows::Foundation::IAsyncOperation<bool> consume_Windows_Graphics_Display_Core_IHdmiDisplayInformation<D>::RequestSetCurrentDisplayModeAsync(Windows::Graphics::Display::Core::HdmiDisplayMode const& mode) const
{
    Windows::Foundation::IAsyncOperation<bool> operation{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Graphics::Display::Core::IHdmiDisplayInformation)->RequestSetCurrentDisplayModeAsync(get_abi(mode), put_abi(operation)));
    return operation;
}

template <typename D> Windows::Foundation::IAsyncOperation<bool> consume_Windows_Graphics_Display_Core_IHdmiDisplayInformation<D>::RequestSetCurrentDisplayModeAsync(Windows::Graphics::Display::Core::HdmiDisplayMode const& mode, Windows::Graphics::Display::Core::HdmiDisplayHdrOption const& hdrOption) const
{
    Windows::Foundation::IAsyncOperation<bool> operation{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Graphics::Display::Core::IHdmiDisplayInformation)->RequestSetCurrentDisplayModeWithHdrAsync(get_abi(mode), get_abi(hdrOption), put_abi(operation)));
    return operation;
}

template <typename D> Windows::Foundation::IAsyncOperation<bool> consume_Windows_Graphics_Display_Core_IHdmiDisplayInformation<D>::RequestSetCurrentDisplayModeAsync(Windows::Graphics::Display::Core::HdmiDisplayMode const& mode, Windows::Graphics::Display::Core::HdmiDisplayHdrOption const& hdrOption, Windows::Graphics::Display::Core::HdmiDisplayHdr2086Metadata const& hdrMetadata) const
{
    Windows::Foundation::IAsyncOperation<bool> operation{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Graphics::Display::Core::IHdmiDisplayInformation)->RequestSetCurrentDisplayModeWithHdrAndMetadataAsync(get_abi(mode), get_abi(hdrOption), get_abi(hdrMetadata), put_abi(operation)));
    return operation;
}

template <typename D> winrt::event_token consume_Windows_Graphics_Display_Core_IHdmiDisplayInformation<D>::DisplayModesChanged(Windows::Foundation::TypedEventHandler<Windows::Graphics::Display::Core::HdmiDisplayInformation, Windows::Foundation::IInspectable> const& value) const
{
    winrt::event_token token{};
    check_hresult(WINRT_SHIM(Windows::Graphics::Display::Core::IHdmiDisplayInformation)->add_DisplayModesChanged(get_abi(value), put_abi(token)));
    return token;
}

template <typename D> typename consume_Windows_Graphics_Display_Core_IHdmiDisplayInformation<D>::DisplayModesChanged_revoker consume_Windows_Graphics_Display_Core_IHdmiDisplayInformation<D>::DisplayModesChanged(auto_revoke_t, Windows::Foundation::TypedEventHandler<Windows::Graphics::Display::Core::HdmiDisplayInformation, Windows::Foundation::IInspectable> const& value) const
{
    return impl::make_event_revoker<D, DisplayModesChanged_revoker>(this, DisplayModesChanged(value));
}

template <typename D> void consume_Windows_Graphics_Display_Core_IHdmiDisplayInformation<D>::DisplayModesChanged(winrt::event_token const& token) const noexcept
{
    WINRT_VERIFY_(0, WINRT_SHIM(Windows::Graphics::Display::Core::IHdmiDisplayInformation)->remove_DisplayModesChanged(get_abi(token)));
}

template <typename D> Windows::Graphics::Display::Core::HdmiDisplayInformation consume_Windows_Graphics_Display_Core_IHdmiDisplayInformationStatics<D>::GetForCurrentView() const
{
    Windows::Graphics::Display::Core::HdmiDisplayInformation result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Graphics::Display::Core::IHdmiDisplayInformationStatics)->GetForCurrentView(put_abi(result)));
    return result;
}

template <typename D> uint32_t consume_Windows_Graphics_Display_Core_IHdmiDisplayMode<D>::ResolutionWidthInRawPixels() const
{
    uint32_t value{};
    check_hresult(WINRT_SHIM(Windows::Graphics::Display::Core::IHdmiDisplayMode)->get_ResolutionWidthInRawPixels(&value));
    return value;
}

template <typename D> uint32_t consume_Windows_Graphics_Display_Core_IHdmiDisplayMode<D>::ResolutionHeightInRawPixels() const
{
    uint32_t value{};
    check_hresult(WINRT_SHIM(Windows::Graphics::Display::Core::IHdmiDisplayMode)->get_ResolutionHeightInRawPixels(&value));
    return value;
}

template <typename D> double consume_Windows_Graphics_Display_Core_IHdmiDisplayMode<D>::RefreshRate() const
{
    double value{};
    check_hresult(WINRT_SHIM(Windows::Graphics::Display::Core::IHdmiDisplayMode)->get_RefreshRate(&value));
    return value;
}

template <typename D> bool consume_Windows_Graphics_Display_Core_IHdmiDisplayMode<D>::StereoEnabled() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::Graphics::Display::Core::IHdmiDisplayMode)->get_StereoEnabled(&value));
    return value;
}

template <typename D> uint16_t consume_Windows_Graphics_Display_Core_IHdmiDisplayMode<D>::BitsPerPixel() const
{
    uint16_t value{};
    check_hresult(WINRT_SHIM(Windows::Graphics::Display::Core::IHdmiDisplayMode)->get_BitsPerPixel(&value));
    return value;
}

template <typename D> bool consume_Windows_Graphics_Display_Core_IHdmiDisplayMode<D>::IsEqual(Windows::Graphics::Display::Core::HdmiDisplayMode const& mode) const
{
    bool result{};
    check_hresult(WINRT_SHIM(Windows::Graphics::Display::Core::IHdmiDisplayMode)->IsEqual(get_abi(mode), &result));
    return result;
}

template <typename D> Windows::Graphics::Display::Core::HdmiDisplayColorSpace consume_Windows_Graphics_Display_Core_IHdmiDisplayMode<D>::ColorSpace() const
{
    Windows::Graphics::Display::Core::HdmiDisplayColorSpace value{};
    check_hresult(WINRT_SHIM(Windows::Graphics::Display::Core::IHdmiDisplayMode)->get_ColorSpace(put_abi(value)));
    return value;
}

template <typename D> Windows::Graphics::Display::Core::HdmiDisplayPixelEncoding consume_Windows_Graphics_Display_Core_IHdmiDisplayMode<D>::PixelEncoding() const
{
    Windows::Graphics::Display::Core::HdmiDisplayPixelEncoding value{};
    check_hresult(WINRT_SHIM(Windows::Graphics::Display::Core::IHdmiDisplayMode)->get_PixelEncoding(put_abi(value)));
    return value;
}

template <typename D> bool consume_Windows_Graphics_Display_Core_IHdmiDisplayMode<D>::IsSdrLuminanceSupported() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::Graphics::Display::Core::IHdmiDisplayMode)->get_IsSdrLuminanceSupported(&value));
    return value;
}

template <typename D> bool consume_Windows_Graphics_Display_Core_IHdmiDisplayMode<D>::IsSmpte2084Supported() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::Graphics::Display::Core::IHdmiDisplayMode)->get_IsSmpte2084Supported(&value));
    return value;
}

template <typename D> bool consume_Windows_Graphics_Display_Core_IHdmiDisplayMode<D>::Is2086MetadataSupported() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::Graphics::Display::Core::IHdmiDisplayMode)->get_Is2086MetadataSupported(&value));
    return value;
}

template <typename D> bool consume_Windows_Graphics_Display_Core_IHdmiDisplayMode2<D>::IsDolbyVisionLowLatencySupported() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::Graphics::Display::Core::IHdmiDisplayMode2)->get_IsDolbyVisionLowLatencySupported(&value));
    return value;
}

template <typename D>
struct produce<D, Windows::Graphics::Display::Core::IHdmiDisplayInformation> : produce_base<D, Windows::Graphics::Display::Core::IHdmiDisplayInformation>
{
    int32_t WINRT_CALL GetSupportedDisplayModes(void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetSupportedDisplayModes, WINRT_WRAP(Windows::Foundation::Collections::IVectorView<Windows::Graphics::Display::Core::HdmiDisplayMode>));
            *result = detach_from<Windows::Foundation::Collections::IVectorView<Windows::Graphics::Display::Core::HdmiDisplayMode>>(this->shim().GetSupportedDisplayModes());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL GetCurrentDisplayMode(void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetCurrentDisplayMode, WINRT_WRAP(Windows::Graphics::Display::Core::HdmiDisplayMode));
            *result = detach_from<Windows::Graphics::Display::Core::HdmiDisplayMode>(this->shim().GetCurrentDisplayMode());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL SetDefaultDisplayModeAsync(void** operation) noexcept final
    {
        try
        {
            *operation = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SetDefaultDisplayModeAsync, WINRT_WRAP(Windows::Foundation::IAsyncAction));
            *operation = detach_from<Windows::Foundation::IAsyncAction>(this->shim().SetDefaultDisplayModeAsync());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL RequestSetCurrentDisplayModeAsync(void* mode, void** operation) noexcept final
    {
        try
        {
            *operation = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(RequestSetCurrentDisplayModeAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<bool>), Windows::Graphics::Display::Core::HdmiDisplayMode const);
            *operation = detach_from<Windows::Foundation::IAsyncOperation<bool>>(this->shim().RequestSetCurrentDisplayModeAsync(*reinterpret_cast<Windows::Graphics::Display::Core::HdmiDisplayMode const*>(&mode)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL RequestSetCurrentDisplayModeWithHdrAsync(void* mode, Windows::Graphics::Display::Core::HdmiDisplayHdrOption hdrOption, void** operation) noexcept final
    {
        try
        {
            *operation = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(RequestSetCurrentDisplayModeAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<bool>), Windows::Graphics::Display::Core::HdmiDisplayMode const, Windows::Graphics::Display::Core::HdmiDisplayHdrOption const);
            *operation = detach_from<Windows::Foundation::IAsyncOperation<bool>>(this->shim().RequestSetCurrentDisplayModeAsync(*reinterpret_cast<Windows::Graphics::Display::Core::HdmiDisplayMode const*>(&mode), *reinterpret_cast<Windows::Graphics::Display::Core::HdmiDisplayHdrOption const*>(&hdrOption)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL RequestSetCurrentDisplayModeWithHdrAndMetadataAsync(void* mode, Windows::Graphics::Display::Core::HdmiDisplayHdrOption hdrOption, struct struct_Windows_Graphics_Display_Core_HdmiDisplayHdr2086Metadata hdrMetadata, void** operation) noexcept final
    {
        try
        {
            *operation = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(RequestSetCurrentDisplayModeAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<bool>), Windows::Graphics::Display::Core::HdmiDisplayMode const, Windows::Graphics::Display::Core::HdmiDisplayHdrOption const, Windows::Graphics::Display::Core::HdmiDisplayHdr2086Metadata const);
            *operation = detach_from<Windows::Foundation::IAsyncOperation<bool>>(this->shim().RequestSetCurrentDisplayModeAsync(*reinterpret_cast<Windows::Graphics::Display::Core::HdmiDisplayMode const*>(&mode), *reinterpret_cast<Windows::Graphics::Display::Core::HdmiDisplayHdrOption const*>(&hdrOption), *reinterpret_cast<Windows::Graphics::Display::Core::HdmiDisplayHdr2086Metadata const*>(&hdrMetadata)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL add_DisplayModesChanged(void* value, winrt::event_token* token) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(DisplayModesChanged, WINRT_WRAP(winrt::event_token), Windows::Foundation::TypedEventHandler<Windows::Graphics::Display::Core::HdmiDisplayInformation, Windows::Foundation::IInspectable> const&);
            *token = detach_from<winrt::event_token>(this->shim().DisplayModesChanged(*reinterpret_cast<Windows::Foundation::TypedEventHandler<Windows::Graphics::Display::Core::HdmiDisplayInformation, Windows::Foundation::IInspectable> const*>(&value)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL remove_DisplayModesChanged(winrt::event_token token) noexcept final
    {
        typename D::abi_guard guard(this->shim());
        WINRT_ASSERT_DECLARATION(DisplayModesChanged, WINRT_WRAP(void), winrt::event_token const&);
        this->shim().DisplayModesChanged(*reinterpret_cast<winrt::event_token const*>(&token));
        return 0;
    }
};

template <typename D>
struct produce<D, Windows::Graphics::Display::Core::IHdmiDisplayInformationStatics> : produce_base<D, Windows::Graphics::Display::Core::IHdmiDisplayInformationStatics>
{
    int32_t WINRT_CALL GetForCurrentView(void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetForCurrentView, WINRT_WRAP(Windows::Graphics::Display::Core::HdmiDisplayInformation));
            *result = detach_from<Windows::Graphics::Display::Core::HdmiDisplayInformation>(this->shim().GetForCurrentView());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Graphics::Display::Core::IHdmiDisplayMode> : produce_base<D, Windows::Graphics::Display::Core::IHdmiDisplayMode>
{
    int32_t WINRT_CALL get_ResolutionWidthInRawPixels(uint32_t* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ResolutionWidthInRawPixels, WINRT_WRAP(uint32_t));
            *value = detach_from<uint32_t>(this->shim().ResolutionWidthInRawPixels());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_ResolutionHeightInRawPixels(uint32_t* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ResolutionHeightInRawPixels, WINRT_WRAP(uint32_t));
            *value = detach_from<uint32_t>(this->shim().ResolutionHeightInRawPixels());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_RefreshRate(double* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(RefreshRate, WINRT_WRAP(double));
            *value = detach_from<double>(this->shim().RefreshRate());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_StereoEnabled(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(StereoEnabled, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().StereoEnabled());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_BitsPerPixel(uint16_t* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(BitsPerPixel, WINRT_WRAP(uint16_t));
            *value = detach_from<uint16_t>(this->shim().BitsPerPixel());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL IsEqual(void* mode, bool* result) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IsEqual, WINRT_WRAP(bool), Windows::Graphics::Display::Core::HdmiDisplayMode const&);
            *result = detach_from<bool>(this->shim().IsEqual(*reinterpret_cast<Windows::Graphics::Display::Core::HdmiDisplayMode const*>(&mode)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_ColorSpace(Windows::Graphics::Display::Core::HdmiDisplayColorSpace* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ColorSpace, WINRT_WRAP(Windows::Graphics::Display::Core::HdmiDisplayColorSpace));
            *value = detach_from<Windows::Graphics::Display::Core::HdmiDisplayColorSpace>(this->shim().ColorSpace());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_PixelEncoding(Windows::Graphics::Display::Core::HdmiDisplayPixelEncoding* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(PixelEncoding, WINRT_WRAP(Windows::Graphics::Display::Core::HdmiDisplayPixelEncoding));
            *value = detach_from<Windows::Graphics::Display::Core::HdmiDisplayPixelEncoding>(this->shim().PixelEncoding());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_IsSdrLuminanceSupported(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IsSdrLuminanceSupported, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().IsSdrLuminanceSupported());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_IsSmpte2084Supported(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IsSmpte2084Supported, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().IsSmpte2084Supported());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Is2086MetadataSupported(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Is2086MetadataSupported, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().Is2086MetadataSupported());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Graphics::Display::Core::IHdmiDisplayMode2> : produce_base<D, Windows::Graphics::Display::Core::IHdmiDisplayMode2>
{
    int32_t WINRT_CALL get_IsDolbyVisionLowLatencySupported(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IsDolbyVisionLowLatencySupported, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().IsDolbyVisionLowLatencySupported());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

}

WINRT_EXPORT namespace winrt::Windows::Graphics::Display::Core {

inline Windows::Graphics::Display::Core::HdmiDisplayInformation HdmiDisplayInformation::GetForCurrentView()
{
    return impl::call_factory<HdmiDisplayInformation, Windows::Graphics::Display::Core::IHdmiDisplayInformationStatics>([&](auto&& f) { return f.GetForCurrentView(); });
}

}

WINRT_EXPORT namespace std {

template<> struct hash<winrt::Windows::Graphics::Display::Core::IHdmiDisplayInformation> : winrt::impl::hash_base<winrt::Windows::Graphics::Display::Core::IHdmiDisplayInformation> {};
template<> struct hash<winrt::Windows::Graphics::Display::Core::IHdmiDisplayInformationStatics> : winrt::impl::hash_base<winrt::Windows::Graphics::Display::Core::IHdmiDisplayInformationStatics> {};
template<> struct hash<winrt::Windows::Graphics::Display::Core::IHdmiDisplayMode> : winrt::impl::hash_base<winrt::Windows::Graphics::Display::Core::IHdmiDisplayMode> {};
template<> struct hash<winrt::Windows::Graphics::Display::Core::IHdmiDisplayMode2> : winrt::impl::hash_base<winrt::Windows::Graphics::Display::Core::IHdmiDisplayMode2> {};
template<> struct hash<winrt::Windows::Graphics::Display::Core::HdmiDisplayInformation> : winrt::impl::hash_base<winrt::Windows::Graphics::Display::Core::HdmiDisplayInformation> {};
template<> struct hash<winrt::Windows::Graphics::Display::Core::HdmiDisplayMode> : winrt::impl::hash_base<winrt::Windows::Graphics::Display::Core::HdmiDisplayMode> {};

}
