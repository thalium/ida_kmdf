// C++/WinRT v1.0.190111.3

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#pragma once

#include "winrt/base.h"

#include "winrt/Windows.Foundation.h"
#include "winrt/Windows.Foundation.Collections.h"
#include "winrt/impl/Windows.Media.Capture.2.h"
#include "winrt/impl/Windows.Media.Capture.Core.2.h"
#include "winrt/Windows.Media.Capture.h"

namespace winrt::impl {

template <typename D> Windows::Media::Capture::CapturedFrame consume_Windows_Media_Capture_Core_IVariablePhotoCapturedEventArgs<D>::Frame() const
{
    Windows::Media::Capture::CapturedFrame value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Media::Capture::Core::IVariablePhotoCapturedEventArgs)->get_Frame(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::TimeSpan consume_Windows_Media_Capture_Core_IVariablePhotoCapturedEventArgs<D>::CaptureTimeOffset() const
{
    Windows::Foundation::TimeSpan value{};
    check_hresult(WINRT_SHIM(Windows::Media::Capture::Core::IVariablePhotoCapturedEventArgs)->get_CaptureTimeOffset(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::IReference<uint32_t> consume_Windows_Media_Capture_Core_IVariablePhotoCapturedEventArgs<D>::UsedFrameControllerIndex() const
{
    Windows::Foundation::IReference<uint32_t> value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Media::Capture::Core::IVariablePhotoCapturedEventArgs)->get_UsedFrameControllerIndex(put_abi(value)));
    return value;
}

template <typename D> Windows::Media::Capture::CapturedFrameControlValues consume_Windows_Media_Capture_Core_IVariablePhotoCapturedEventArgs<D>::CapturedFrameControlValues() const
{
    Windows::Media::Capture::CapturedFrameControlValues value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Media::Capture::Core::IVariablePhotoCapturedEventArgs)->get_CapturedFrameControlValues(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::IAsyncAction consume_Windows_Media_Capture_Core_IVariablePhotoSequenceCapture<D>::StartAsync() const
{
    Windows::Foundation::IAsyncAction operation{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Media::Capture::Core::IVariablePhotoSequenceCapture)->StartAsync(put_abi(operation)));
    return operation;
}

template <typename D> Windows::Foundation::IAsyncAction consume_Windows_Media_Capture_Core_IVariablePhotoSequenceCapture<D>::StopAsync() const
{
    Windows::Foundation::IAsyncAction operation{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Media::Capture::Core::IVariablePhotoSequenceCapture)->StopAsync(put_abi(operation)));
    return operation;
}

template <typename D> Windows::Foundation::IAsyncAction consume_Windows_Media_Capture_Core_IVariablePhotoSequenceCapture<D>::FinishAsync() const
{
    Windows::Foundation::IAsyncAction operation{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Media::Capture::Core::IVariablePhotoSequenceCapture)->FinishAsync(put_abi(operation)));
    return operation;
}

template <typename D> winrt::event_token consume_Windows_Media_Capture_Core_IVariablePhotoSequenceCapture<D>::PhotoCaptured(Windows::Foundation::TypedEventHandler<Windows::Media::Capture::Core::VariablePhotoSequenceCapture, Windows::Media::Capture::Core::VariablePhotoCapturedEventArgs> const& handler) const
{
    winrt::event_token token{};
    check_hresult(WINRT_SHIM(Windows::Media::Capture::Core::IVariablePhotoSequenceCapture)->add_PhotoCaptured(get_abi(handler), put_abi(token)));
    return token;
}

template <typename D> typename consume_Windows_Media_Capture_Core_IVariablePhotoSequenceCapture<D>::PhotoCaptured_revoker consume_Windows_Media_Capture_Core_IVariablePhotoSequenceCapture<D>::PhotoCaptured(auto_revoke_t, Windows::Foundation::TypedEventHandler<Windows::Media::Capture::Core::VariablePhotoSequenceCapture, Windows::Media::Capture::Core::VariablePhotoCapturedEventArgs> const& handler) const
{
    return impl::make_event_revoker<D, PhotoCaptured_revoker>(this, PhotoCaptured(handler));
}

template <typename D> void consume_Windows_Media_Capture_Core_IVariablePhotoSequenceCapture<D>::PhotoCaptured(winrt::event_token const& token) const noexcept
{
    WINRT_VERIFY_(0, WINRT_SHIM(Windows::Media::Capture::Core::IVariablePhotoSequenceCapture)->remove_PhotoCaptured(get_abi(token)));
}

template <typename D> winrt::event_token consume_Windows_Media_Capture_Core_IVariablePhotoSequenceCapture<D>::Stopped(Windows::Foundation::TypedEventHandler<Windows::Media::Capture::Core::VariablePhotoSequenceCapture, Windows::Foundation::IInspectable> const& handler) const
{
    winrt::event_token token{};
    check_hresult(WINRT_SHIM(Windows::Media::Capture::Core::IVariablePhotoSequenceCapture)->add_Stopped(get_abi(handler), put_abi(token)));
    return token;
}

template <typename D> typename consume_Windows_Media_Capture_Core_IVariablePhotoSequenceCapture<D>::Stopped_revoker consume_Windows_Media_Capture_Core_IVariablePhotoSequenceCapture<D>::Stopped(auto_revoke_t, Windows::Foundation::TypedEventHandler<Windows::Media::Capture::Core::VariablePhotoSequenceCapture, Windows::Foundation::IInspectable> const& handler) const
{
    return impl::make_event_revoker<D, Stopped_revoker>(this, Stopped(handler));
}

template <typename D> void consume_Windows_Media_Capture_Core_IVariablePhotoSequenceCapture<D>::Stopped(winrt::event_token const& token) const noexcept
{
    WINRT_VERIFY_(0, WINRT_SHIM(Windows::Media::Capture::Core::IVariablePhotoSequenceCapture)->remove_Stopped(get_abi(token)));
}

template <typename D> Windows::Foundation::IAsyncAction consume_Windows_Media_Capture_Core_IVariablePhotoSequenceCapture2<D>::UpdateSettingsAsync() const
{
    Windows::Foundation::IAsyncAction operation{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Media::Capture::Core::IVariablePhotoSequenceCapture2)->UpdateSettingsAsync(put_abi(operation)));
    return operation;
}

template <typename D>
struct produce<D, Windows::Media::Capture::Core::IVariablePhotoCapturedEventArgs> : produce_base<D, Windows::Media::Capture::Core::IVariablePhotoCapturedEventArgs>
{
    int32_t WINRT_CALL get_Frame(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Frame, WINRT_WRAP(Windows::Media::Capture::CapturedFrame));
            *value = detach_from<Windows::Media::Capture::CapturedFrame>(this->shim().Frame());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_CaptureTimeOffset(Windows::Foundation::TimeSpan* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CaptureTimeOffset, WINRT_WRAP(Windows::Foundation::TimeSpan));
            *value = detach_from<Windows::Foundation::TimeSpan>(this->shim().CaptureTimeOffset());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_UsedFrameControllerIndex(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(UsedFrameControllerIndex, WINRT_WRAP(Windows::Foundation::IReference<uint32_t>));
            *value = detach_from<Windows::Foundation::IReference<uint32_t>>(this->shim().UsedFrameControllerIndex());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_CapturedFrameControlValues(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CapturedFrameControlValues, WINRT_WRAP(Windows::Media::Capture::CapturedFrameControlValues));
            *value = detach_from<Windows::Media::Capture::CapturedFrameControlValues>(this->shim().CapturedFrameControlValues());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Media::Capture::Core::IVariablePhotoSequenceCapture> : produce_base<D, Windows::Media::Capture::Core::IVariablePhotoSequenceCapture>
{
    int32_t WINRT_CALL StartAsync(void** operation) noexcept final
    {
        try
        {
            *operation = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(StartAsync, WINRT_WRAP(Windows::Foundation::IAsyncAction));
            *operation = detach_from<Windows::Foundation::IAsyncAction>(this->shim().StartAsync());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL StopAsync(void** operation) noexcept final
    {
        try
        {
            *operation = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(StopAsync, WINRT_WRAP(Windows::Foundation::IAsyncAction));
            *operation = detach_from<Windows::Foundation::IAsyncAction>(this->shim().StopAsync());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL FinishAsync(void** operation) noexcept final
    {
        try
        {
            *operation = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(FinishAsync, WINRT_WRAP(Windows::Foundation::IAsyncAction));
            *operation = detach_from<Windows::Foundation::IAsyncAction>(this->shim().FinishAsync());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL add_PhotoCaptured(void* handler, winrt::event_token* token) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(PhotoCaptured, WINRT_WRAP(winrt::event_token), Windows::Foundation::TypedEventHandler<Windows::Media::Capture::Core::VariablePhotoSequenceCapture, Windows::Media::Capture::Core::VariablePhotoCapturedEventArgs> const&);
            *token = detach_from<winrt::event_token>(this->shim().PhotoCaptured(*reinterpret_cast<Windows::Foundation::TypedEventHandler<Windows::Media::Capture::Core::VariablePhotoSequenceCapture, Windows::Media::Capture::Core::VariablePhotoCapturedEventArgs> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL remove_PhotoCaptured(winrt::event_token token) noexcept final
    {
        typename D::abi_guard guard(this->shim());
        WINRT_ASSERT_DECLARATION(PhotoCaptured, WINRT_WRAP(void), winrt::event_token const&);
        this->shim().PhotoCaptured(*reinterpret_cast<winrt::event_token const*>(&token));
        return 0;
    }

    int32_t WINRT_CALL add_Stopped(void* handler, winrt::event_token* token) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Stopped, WINRT_WRAP(winrt::event_token), Windows::Foundation::TypedEventHandler<Windows::Media::Capture::Core::VariablePhotoSequenceCapture, Windows::Foundation::IInspectable> const&);
            *token = detach_from<winrt::event_token>(this->shim().Stopped(*reinterpret_cast<Windows::Foundation::TypedEventHandler<Windows::Media::Capture::Core::VariablePhotoSequenceCapture, Windows::Foundation::IInspectable> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL remove_Stopped(winrt::event_token token) noexcept final
    {
        typename D::abi_guard guard(this->shim());
        WINRT_ASSERT_DECLARATION(Stopped, WINRT_WRAP(void), winrt::event_token const&);
        this->shim().Stopped(*reinterpret_cast<winrt::event_token const*>(&token));
        return 0;
    }
};

template <typename D>
struct produce<D, Windows::Media::Capture::Core::IVariablePhotoSequenceCapture2> : produce_base<D, Windows::Media::Capture::Core::IVariablePhotoSequenceCapture2>
{
    int32_t WINRT_CALL UpdateSettingsAsync(void** operation) noexcept final
    {
        try
        {
            *operation = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(UpdateSettingsAsync, WINRT_WRAP(Windows::Foundation::IAsyncAction));
            *operation = detach_from<Windows::Foundation::IAsyncAction>(this->shim().UpdateSettingsAsync());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

}

WINRT_EXPORT namespace winrt::Windows::Media::Capture::Core {

}

WINRT_EXPORT namespace std {

template<> struct hash<winrt::Windows::Media::Capture::Core::IVariablePhotoCapturedEventArgs> : winrt::impl::hash_base<winrt::Windows::Media::Capture::Core::IVariablePhotoCapturedEventArgs> {};
template<> struct hash<winrt::Windows::Media::Capture::Core::IVariablePhotoSequenceCapture> : winrt::impl::hash_base<winrt::Windows::Media::Capture::Core::IVariablePhotoSequenceCapture> {};
template<> struct hash<winrt::Windows::Media::Capture::Core::IVariablePhotoSequenceCapture2> : winrt::impl::hash_base<winrt::Windows::Media::Capture::Core::IVariablePhotoSequenceCapture2> {};
template<> struct hash<winrt::Windows::Media::Capture::Core::VariablePhotoCapturedEventArgs> : winrt::impl::hash_base<winrt::Windows::Media::Capture::Core::VariablePhotoCapturedEventArgs> {};
template<> struct hash<winrt::Windows::Media::Capture::Core::VariablePhotoSequenceCapture> : winrt::impl::hash_base<winrt::Windows::Media::Capture::Core::VariablePhotoSequenceCapture> {};

}
