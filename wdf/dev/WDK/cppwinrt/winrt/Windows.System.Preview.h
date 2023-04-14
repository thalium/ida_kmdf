// C++/WinRT v1.0.190111.3

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#pragma once

#include "winrt/base.h"

#include "winrt/Windows.Foundation.h"
#include "winrt/Windows.Foundation.Collections.h"
#include "winrt/impl/Windows.Devices.Sensors.2.h"
#include "winrt/impl/Windows.System.Preview.2.h"
#include "winrt/Windows.System.h"

namespace winrt::impl {

template <typename D> Windows::Foundation::IAsyncOperation<Windows::System::Preview::TwoPanelHingedDevicePosturePreviewReading> consume_Windows_System_Preview_ITwoPanelHingedDevicePosturePreview<D>::GetCurrentPostureAsync() const
{
    Windows::Foundation::IAsyncOperation<Windows::System::Preview::TwoPanelHingedDevicePosturePreviewReading> value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::System::Preview::ITwoPanelHingedDevicePosturePreview)->GetCurrentPostureAsync(put_abi(value)));
    return value;
}

template <typename D> winrt::event_token consume_Windows_System_Preview_ITwoPanelHingedDevicePosturePreview<D>::PostureChanged(Windows::Foundation::TypedEventHandler<Windows::System::Preview::TwoPanelHingedDevicePosturePreview, Windows::System::Preview::TwoPanelHingedDevicePosturePreviewReadingChangedEventArgs> const& handler) const
{
    winrt::event_token token{};
    check_hresult(WINRT_SHIM(Windows::System::Preview::ITwoPanelHingedDevicePosturePreview)->add_PostureChanged(get_abi(handler), put_abi(token)));
    return token;
}

template <typename D> typename consume_Windows_System_Preview_ITwoPanelHingedDevicePosturePreview<D>::PostureChanged_revoker consume_Windows_System_Preview_ITwoPanelHingedDevicePosturePreview<D>::PostureChanged(auto_revoke_t, Windows::Foundation::TypedEventHandler<Windows::System::Preview::TwoPanelHingedDevicePosturePreview, Windows::System::Preview::TwoPanelHingedDevicePosturePreviewReadingChangedEventArgs> const& handler) const
{
    return impl::make_event_revoker<D, PostureChanged_revoker>(this, PostureChanged(handler));
}

template <typename D> void consume_Windows_System_Preview_ITwoPanelHingedDevicePosturePreview<D>::PostureChanged(winrt::event_token const& token) const noexcept
{
    WINRT_VERIFY_(0, WINRT_SHIM(Windows::System::Preview::ITwoPanelHingedDevicePosturePreview)->remove_PostureChanged(get_abi(token)));
}

template <typename D> Windows::Foundation::DateTime consume_Windows_System_Preview_ITwoPanelHingedDevicePosturePreviewReading<D>::Timestamp() const
{
    Windows::Foundation::DateTime value{};
    check_hresult(WINRT_SHIM(Windows::System::Preview::ITwoPanelHingedDevicePosturePreviewReading)->get_Timestamp(put_abi(value)));
    return value;
}

template <typename D> Windows::System::Preview::HingeState consume_Windows_System_Preview_ITwoPanelHingedDevicePosturePreviewReading<D>::HingeState() const
{
    Windows::System::Preview::HingeState value{};
    check_hresult(WINRT_SHIM(Windows::System::Preview::ITwoPanelHingedDevicePosturePreviewReading)->get_HingeState(put_abi(value)));
    return value;
}

template <typename D> Windows::Devices::Sensors::SimpleOrientation consume_Windows_System_Preview_ITwoPanelHingedDevicePosturePreviewReading<D>::Panel1Orientation() const
{
    Windows::Devices::Sensors::SimpleOrientation value{};
    check_hresult(WINRT_SHIM(Windows::System::Preview::ITwoPanelHingedDevicePosturePreviewReading)->get_Panel1Orientation(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_System_Preview_ITwoPanelHingedDevicePosturePreviewReading<D>::Panel1Id() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::System::Preview::ITwoPanelHingedDevicePosturePreviewReading)->get_Panel1Id(put_abi(value)));
    return value;
}

template <typename D> Windows::Devices::Sensors::SimpleOrientation consume_Windows_System_Preview_ITwoPanelHingedDevicePosturePreviewReading<D>::Panel2Orientation() const
{
    Windows::Devices::Sensors::SimpleOrientation value{};
    check_hresult(WINRT_SHIM(Windows::System::Preview::ITwoPanelHingedDevicePosturePreviewReading)->get_Panel2Orientation(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_System_Preview_ITwoPanelHingedDevicePosturePreviewReading<D>::Panel2Id() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::System::Preview::ITwoPanelHingedDevicePosturePreviewReading)->get_Panel2Id(put_abi(value)));
    return value;
}

template <typename D> Windows::System::Preview::TwoPanelHingedDevicePosturePreviewReading consume_Windows_System_Preview_ITwoPanelHingedDevicePosturePreviewReadingChangedEventArgs<D>::Reading() const
{
    Windows::System::Preview::TwoPanelHingedDevicePosturePreviewReading value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::System::Preview::ITwoPanelHingedDevicePosturePreviewReadingChangedEventArgs)->get_Reading(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::IAsyncOperation<Windows::System::Preview::TwoPanelHingedDevicePosturePreview> consume_Windows_System_Preview_ITwoPanelHingedDevicePosturePreviewStatics<D>::GetDefaultAsync() const
{
    Windows::Foundation::IAsyncOperation<Windows::System::Preview::TwoPanelHingedDevicePosturePreview> result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::System::Preview::ITwoPanelHingedDevicePosturePreviewStatics)->GetDefaultAsync(put_abi(result)));
    return result;
}

template <typename D>
struct produce<D, Windows::System::Preview::ITwoPanelHingedDevicePosturePreview> : produce_base<D, Windows::System::Preview::ITwoPanelHingedDevicePosturePreview>
{
    int32_t WINRT_CALL GetCurrentPostureAsync(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetCurrentPostureAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<Windows::System::Preview::TwoPanelHingedDevicePosturePreviewReading>));
            *value = detach_from<Windows::Foundation::IAsyncOperation<Windows::System::Preview::TwoPanelHingedDevicePosturePreviewReading>>(this->shim().GetCurrentPostureAsync());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL add_PostureChanged(void* handler, winrt::event_token* token) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(PostureChanged, WINRT_WRAP(winrt::event_token), Windows::Foundation::TypedEventHandler<Windows::System::Preview::TwoPanelHingedDevicePosturePreview, Windows::System::Preview::TwoPanelHingedDevicePosturePreviewReadingChangedEventArgs> const&);
            *token = detach_from<winrt::event_token>(this->shim().PostureChanged(*reinterpret_cast<Windows::Foundation::TypedEventHandler<Windows::System::Preview::TwoPanelHingedDevicePosturePreview, Windows::System::Preview::TwoPanelHingedDevicePosturePreviewReadingChangedEventArgs> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL remove_PostureChanged(winrt::event_token token) noexcept final
    {
        typename D::abi_guard guard(this->shim());
        WINRT_ASSERT_DECLARATION(PostureChanged, WINRT_WRAP(void), winrt::event_token const&);
        this->shim().PostureChanged(*reinterpret_cast<winrt::event_token const*>(&token));
        return 0;
    }
};

template <typename D>
struct produce<D, Windows::System::Preview::ITwoPanelHingedDevicePosturePreviewReading> : produce_base<D, Windows::System::Preview::ITwoPanelHingedDevicePosturePreviewReading>
{
    int32_t WINRT_CALL get_Timestamp(Windows::Foundation::DateTime* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Timestamp, WINRT_WRAP(Windows::Foundation::DateTime));
            *value = detach_from<Windows::Foundation::DateTime>(this->shim().Timestamp());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_HingeState(Windows::System::Preview::HingeState* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(HingeState, WINRT_WRAP(Windows::System::Preview::HingeState));
            *value = detach_from<Windows::System::Preview::HingeState>(this->shim().HingeState());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Panel1Orientation(Windows::Devices::Sensors::SimpleOrientation* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Panel1Orientation, WINRT_WRAP(Windows::Devices::Sensors::SimpleOrientation));
            *value = detach_from<Windows::Devices::Sensors::SimpleOrientation>(this->shim().Panel1Orientation());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Panel1Id(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Panel1Id, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().Panel1Id());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Panel2Orientation(Windows::Devices::Sensors::SimpleOrientation* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Panel2Orientation, WINRT_WRAP(Windows::Devices::Sensors::SimpleOrientation));
            *value = detach_from<Windows::Devices::Sensors::SimpleOrientation>(this->shim().Panel2Orientation());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Panel2Id(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Panel2Id, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().Panel2Id());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::System::Preview::ITwoPanelHingedDevicePosturePreviewReadingChangedEventArgs> : produce_base<D, Windows::System::Preview::ITwoPanelHingedDevicePosturePreviewReadingChangedEventArgs>
{
    int32_t WINRT_CALL get_Reading(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Reading, WINRT_WRAP(Windows::System::Preview::TwoPanelHingedDevicePosturePreviewReading));
            *value = detach_from<Windows::System::Preview::TwoPanelHingedDevicePosturePreviewReading>(this->shim().Reading());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::System::Preview::ITwoPanelHingedDevicePosturePreviewStatics> : produce_base<D, Windows::System::Preview::ITwoPanelHingedDevicePosturePreviewStatics>
{
    int32_t WINRT_CALL GetDefaultAsync(void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetDefaultAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<Windows::System::Preview::TwoPanelHingedDevicePosturePreview>));
            *result = detach_from<Windows::Foundation::IAsyncOperation<Windows::System::Preview::TwoPanelHingedDevicePosturePreview>>(this->shim().GetDefaultAsync());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

}

WINRT_EXPORT namespace winrt::Windows::System::Preview {

inline Windows::Foundation::IAsyncOperation<Windows::System::Preview::TwoPanelHingedDevicePosturePreview> TwoPanelHingedDevicePosturePreview::GetDefaultAsync()
{
    return impl::call_factory<TwoPanelHingedDevicePosturePreview, Windows::System::Preview::ITwoPanelHingedDevicePosturePreviewStatics>([&](auto&& f) { return f.GetDefaultAsync(); });
}

}

WINRT_EXPORT namespace std {

template<> struct hash<winrt::Windows::System::Preview::ITwoPanelHingedDevicePosturePreview> : winrt::impl::hash_base<winrt::Windows::System::Preview::ITwoPanelHingedDevicePosturePreview> {};
template<> struct hash<winrt::Windows::System::Preview::ITwoPanelHingedDevicePosturePreviewReading> : winrt::impl::hash_base<winrt::Windows::System::Preview::ITwoPanelHingedDevicePosturePreviewReading> {};
template<> struct hash<winrt::Windows::System::Preview::ITwoPanelHingedDevicePosturePreviewReadingChangedEventArgs> : winrt::impl::hash_base<winrt::Windows::System::Preview::ITwoPanelHingedDevicePosturePreviewReadingChangedEventArgs> {};
template<> struct hash<winrt::Windows::System::Preview::ITwoPanelHingedDevicePosturePreviewStatics> : winrt::impl::hash_base<winrt::Windows::System::Preview::ITwoPanelHingedDevicePosturePreviewStatics> {};
template<> struct hash<winrt::Windows::System::Preview::TwoPanelHingedDevicePosturePreview> : winrt::impl::hash_base<winrt::Windows::System::Preview::TwoPanelHingedDevicePosturePreview> {};
template<> struct hash<winrt::Windows::System::Preview::TwoPanelHingedDevicePosturePreviewReading> : winrt::impl::hash_base<winrt::Windows::System::Preview::TwoPanelHingedDevicePosturePreviewReading> {};
template<> struct hash<winrt::Windows::System::Preview::TwoPanelHingedDevicePosturePreviewReadingChangedEventArgs> : winrt::impl::hash_base<winrt::Windows::System::Preview::TwoPanelHingedDevicePosturePreviewReadingChangedEventArgs> {};

}
