// C++/WinRT v1.0.190111.3

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#pragma once

#include "winrt/base.h"

#include "winrt/Windows.Foundation.h"
#include "winrt/Windows.Foundation.Collections.h"
#include "winrt/impl/Windows.Devices.Enumeration.2.h"
#include "winrt/impl/Windows.Foundation.2.h"
#include "winrt/impl/Windows.Storage.Streams.2.h"
#include "winrt/impl/Windows.UI.Popups.2.h"
#include "winrt/impl/Windows.Media.Casting.2.h"
#include "winrt/Windows.Media.h"

namespace winrt::impl {

template <typename D> Windows::Media::Casting::CastingConnectionState consume_Windows_Media_Casting_ICastingConnection<D>::State() const
{
    Windows::Media::Casting::CastingConnectionState value{};
    check_hresult(WINRT_SHIM(Windows::Media::Casting::ICastingConnection)->get_State(put_abi(value)));
    return value;
}

template <typename D> Windows::Media::Casting::CastingDevice consume_Windows_Media_Casting_ICastingConnection<D>::Device() const
{
    Windows::Media::Casting::CastingDevice value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Media::Casting::ICastingConnection)->get_Device(put_abi(value)));
    return value;
}

template <typename D> Windows::Media::Casting::CastingSource consume_Windows_Media_Casting_ICastingConnection<D>::Source() const
{
    Windows::Media::Casting::CastingSource value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Media::Casting::ICastingConnection)->get_Source(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_Media_Casting_ICastingConnection<D>::Source(Windows::Media::Casting::CastingSource const& value) const
{
    check_hresult(WINRT_SHIM(Windows::Media::Casting::ICastingConnection)->put_Source(get_abi(value)));
}

template <typename D> winrt::event_token consume_Windows_Media_Casting_ICastingConnection<D>::StateChanged(Windows::Foundation::TypedEventHandler<Windows::Media::Casting::CastingConnection, Windows::Foundation::IInspectable> const& handler) const
{
    winrt::event_token token{};
    check_hresult(WINRT_SHIM(Windows::Media::Casting::ICastingConnection)->add_StateChanged(get_abi(handler), put_abi(token)));
    return token;
}

template <typename D> typename consume_Windows_Media_Casting_ICastingConnection<D>::StateChanged_revoker consume_Windows_Media_Casting_ICastingConnection<D>::StateChanged(auto_revoke_t, Windows::Foundation::TypedEventHandler<Windows::Media::Casting::CastingConnection, Windows::Foundation::IInspectable> const& handler) const
{
    return impl::make_event_revoker<D, StateChanged_revoker>(this, StateChanged(handler));
}

template <typename D> void consume_Windows_Media_Casting_ICastingConnection<D>::StateChanged(winrt::event_token const& token) const noexcept
{
    WINRT_VERIFY_(0, WINRT_SHIM(Windows::Media::Casting::ICastingConnection)->remove_StateChanged(get_abi(token)));
}

template <typename D> winrt::event_token consume_Windows_Media_Casting_ICastingConnection<D>::ErrorOccurred(Windows::Foundation::TypedEventHandler<Windows::Media::Casting::CastingConnection, Windows::Media::Casting::CastingConnectionErrorOccurredEventArgs> const& handler) const
{
    winrt::event_token token{};
    check_hresult(WINRT_SHIM(Windows::Media::Casting::ICastingConnection)->add_ErrorOccurred(get_abi(handler), put_abi(token)));
    return token;
}

template <typename D> typename consume_Windows_Media_Casting_ICastingConnection<D>::ErrorOccurred_revoker consume_Windows_Media_Casting_ICastingConnection<D>::ErrorOccurred(auto_revoke_t, Windows::Foundation::TypedEventHandler<Windows::Media::Casting::CastingConnection, Windows::Media::Casting::CastingConnectionErrorOccurredEventArgs> const& handler) const
{
    return impl::make_event_revoker<D, ErrorOccurred_revoker>(this, ErrorOccurred(handler));
}

template <typename D> void consume_Windows_Media_Casting_ICastingConnection<D>::ErrorOccurred(winrt::event_token const& token) const noexcept
{
    WINRT_VERIFY_(0, WINRT_SHIM(Windows::Media::Casting::ICastingConnection)->remove_ErrorOccurred(get_abi(token)));
}

template <typename D> Windows::Foundation::IAsyncOperation<Windows::Media::Casting::CastingConnectionErrorStatus> consume_Windows_Media_Casting_ICastingConnection<D>::RequestStartCastingAsync(Windows::Media::Casting::CastingSource const& value) const
{
    Windows::Foundation::IAsyncOperation<Windows::Media::Casting::CastingConnectionErrorStatus> operation{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Media::Casting::ICastingConnection)->RequestStartCastingAsync(get_abi(value), put_abi(operation)));
    return operation;
}

template <typename D> Windows::Foundation::IAsyncOperation<Windows::Media::Casting::CastingConnectionErrorStatus> consume_Windows_Media_Casting_ICastingConnection<D>::DisconnectAsync() const
{
    Windows::Foundation::IAsyncOperation<Windows::Media::Casting::CastingConnectionErrorStatus> operation{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Media::Casting::ICastingConnection)->DisconnectAsync(put_abi(operation)));
    return operation;
}

template <typename D> Windows::Media::Casting::CastingConnectionErrorStatus consume_Windows_Media_Casting_ICastingConnectionErrorOccurredEventArgs<D>::ErrorStatus() const
{
    Windows::Media::Casting::CastingConnectionErrorStatus value{};
    check_hresult(WINRT_SHIM(Windows::Media::Casting::ICastingConnectionErrorOccurredEventArgs)->get_ErrorStatus(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_Media_Casting_ICastingConnectionErrorOccurredEventArgs<D>::Message() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Media::Casting::ICastingConnectionErrorOccurredEventArgs)->get_Message(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_Media_Casting_ICastingDevice<D>::Id() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Media::Casting::ICastingDevice)->get_Id(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_Media_Casting_ICastingDevice<D>::FriendlyName() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Media::Casting::ICastingDevice)->get_FriendlyName(put_abi(value)));
    return value;
}

template <typename D> Windows::Storage::Streams::IRandomAccessStreamWithContentType consume_Windows_Media_Casting_ICastingDevice<D>::Icon() const
{
    Windows::Storage::Streams::IRandomAccessStreamWithContentType value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Media::Casting::ICastingDevice)->get_Icon(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::IAsyncOperation<Windows::Media::Casting::CastingPlaybackTypes> consume_Windows_Media_Casting_ICastingDevice<D>::GetSupportedCastingPlaybackTypesAsync() const
{
    Windows::Foundation::IAsyncOperation<Windows::Media::Casting::CastingPlaybackTypes> operation{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Media::Casting::ICastingDevice)->GetSupportedCastingPlaybackTypesAsync(put_abi(operation)));
    return operation;
}

template <typename D> Windows::Media::Casting::CastingConnection consume_Windows_Media_Casting_ICastingDevice<D>::CreateCastingConnection() const
{
    Windows::Media::Casting::CastingConnection value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Media::Casting::ICastingDevice)->CreateCastingConnection(put_abi(value)));
    return value;
}

template <typename D> Windows::Media::Casting::CastingDevicePickerFilter consume_Windows_Media_Casting_ICastingDevicePicker<D>::Filter() const
{
    Windows::Media::Casting::CastingDevicePickerFilter value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Media::Casting::ICastingDevicePicker)->get_Filter(put_abi(value)));
    return value;
}

template <typename D> Windows::Devices::Enumeration::DevicePickerAppearance consume_Windows_Media_Casting_ICastingDevicePicker<D>::Appearance() const
{
    Windows::Devices::Enumeration::DevicePickerAppearance value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Media::Casting::ICastingDevicePicker)->get_Appearance(put_abi(value)));
    return value;
}

template <typename D> winrt::event_token consume_Windows_Media_Casting_ICastingDevicePicker<D>::CastingDeviceSelected(Windows::Foundation::TypedEventHandler<Windows::Media::Casting::CastingDevicePicker, Windows::Media::Casting::CastingDeviceSelectedEventArgs> const& handler) const
{
    winrt::event_token token{};
    check_hresult(WINRT_SHIM(Windows::Media::Casting::ICastingDevicePicker)->add_CastingDeviceSelected(get_abi(handler), put_abi(token)));
    return token;
}

template <typename D> typename consume_Windows_Media_Casting_ICastingDevicePicker<D>::CastingDeviceSelected_revoker consume_Windows_Media_Casting_ICastingDevicePicker<D>::CastingDeviceSelected(auto_revoke_t, Windows::Foundation::TypedEventHandler<Windows::Media::Casting::CastingDevicePicker, Windows::Media::Casting::CastingDeviceSelectedEventArgs> const& handler) const
{
    return impl::make_event_revoker<D, CastingDeviceSelected_revoker>(this, CastingDeviceSelected(handler));
}

template <typename D> void consume_Windows_Media_Casting_ICastingDevicePicker<D>::CastingDeviceSelected(winrt::event_token const& token) const noexcept
{
    WINRT_VERIFY_(0, WINRT_SHIM(Windows::Media::Casting::ICastingDevicePicker)->remove_CastingDeviceSelected(get_abi(token)));
}

template <typename D> winrt::event_token consume_Windows_Media_Casting_ICastingDevicePicker<D>::CastingDevicePickerDismissed(Windows::Foundation::TypedEventHandler<Windows::Media::Casting::CastingDevicePicker, Windows::Foundation::IInspectable> const& handler) const
{
    winrt::event_token token{};
    check_hresult(WINRT_SHIM(Windows::Media::Casting::ICastingDevicePicker)->add_CastingDevicePickerDismissed(get_abi(handler), put_abi(token)));
    return token;
}

template <typename D> typename consume_Windows_Media_Casting_ICastingDevicePicker<D>::CastingDevicePickerDismissed_revoker consume_Windows_Media_Casting_ICastingDevicePicker<D>::CastingDevicePickerDismissed(auto_revoke_t, Windows::Foundation::TypedEventHandler<Windows::Media::Casting::CastingDevicePicker, Windows::Foundation::IInspectable> const& handler) const
{
    return impl::make_event_revoker<D, CastingDevicePickerDismissed_revoker>(this, CastingDevicePickerDismissed(handler));
}

template <typename D> void consume_Windows_Media_Casting_ICastingDevicePicker<D>::CastingDevicePickerDismissed(winrt::event_token const& token) const noexcept
{
    WINRT_VERIFY_(0, WINRT_SHIM(Windows::Media::Casting::ICastingDevicePicker)->remove_CastingDevicePickerDismissed(get_abi(token)));
}

template <typename D> void consume_Windows_Media_Casting_ICastingDevicePicker<D>::Show(Windows::Foundation::Rect const& selection) const
{
    check_hresult(WINRT_SHIM(Windows::Media::Casting::ICastingDevicePicker)->Show(get_abi(selection)));
}

template <typename D> void consume_Windows_Media_Casting_ICastingDevicePicker<D>::Show(Windows::Foundation::Rect const& selection, Windows::UI::Popups::Placement const& preferredPlacement) const
{
    check_hresult(WINRT_SHIM(Windows::Media::Casting::ICastingDevicePicker)->ShowWithPlacement(get_abi(selection), get_abi(preferredPlacement)));
}

template <typename D> void consume_Windows_Media_Casting_ICastingDevicePicker<D>::Hide() const
{
    check_hresult(WINRT_SHIM(Windows::Media::Casting::ICastingDevicePicker)->Hide());
}

template <typename D> bool consume_Windows_Media_Casting_ICastingDevicePickerFilter<D>::SupportsAudio() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::Media::Casting::ICastingDevicePickerFilter)->get_SupportsAudio(&value));
    return value;
}

template <typename D> void consume_Windows_Media_Casting_ICastingDevicePickerFilter<D>::SupportsAudio(bool value) const
{
    check_hresult(WINRT_SHIM(Windows::Media::Casting::ICastingDevicePickerFilter)->put_SupportsAudio(value));
}

template <typename D> bool consume_Windows_Media_Casting_ICastingDevicePickerFilter<D>::SupportsVideo() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::Media::Casting::ICastingDevicePickerFilter)->get_SupportsVideo(&value));
    return value;
}

template <typename D> void consume_Windows_Media_Casting_ICastingDevicePickerFilter<D>::SupportsVideo(bool value) const
{
    check_hresult(WINRT_SHIM(Windows::Media::Casting::ICastingDevicePickerFilter)->put_SupportsVideo(value));
}

template <typename D> bool consume_Windows_Media_Casting_ICastingDevicePickerFilter<D>::SupportsPictures() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::Media::Casting::ICastingDevicePickerFilter)->get_SupportsPictures(&value));
    return value;
}

template <typename D> void consume_Windows_Media_Casting_ICastingDevicePickerFilter<D>::SupportsPictures(bool value) const
{
    check_hresult(WINRT_SHIM(Windows::Media::Casting::ICastingDevicePickerFilter)->put_SupportsPictures(value));
}

template <typename D> Windows::Foundation::Collections::IVector<Windows::Media::Casting::CastingSource> consume_Windows_Media_Casting_ICastingDevicePickerFilter<D>::SupportedCastingSources() const
{
    Windows::Foundation::Collections::IVector<Windows::Media::Casting::CastingSource> value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Media::Casting::ICastingDevicePickerFilter)->get_SupportedCastingSources(put_abi(value)));
    return value;
}

template <typename D> Windows::Media::Casting::CastingDevice consume_Windows_Media_Casting_ICastingDeviceSelectedEventArgs<D>::SelectedCastingDevice() const
{
    Windows::Media::Casting::CastingDevice value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Media::Casting::ICastingDeviceSelectedEventArgs)->get_SelectedCastingDevice(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_Media_Casting_ICastingDeviceStatics<D>::GetDeviceSelector(Windows::Media::Casting::CastingPlaybackTypes const& type) const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Media::Casting::ICastingDeviceStatics)->GetDeviceSelector(get_abi(type), put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::IAsyncOperation<hstring> consume_Windows_Media_Casting_ICastingDeviceStatics<D>::GetDeviceSelectorFromCastingSourceAsync(Windows::Media::Casting::CastingSource const& castingSource) const
{
    Windows::Foundation::IAsyncOperation<hstring> operation{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Media::Casting::ICastingDeviceStatics)->GetDeviceSelectorFromCastingSourceAsync(get_abi(castingSource), put_abi(operation)));
    return operation;
}

template <typename D> Windows::Foundation::IAsyncOperation<Windows::Media::Casting::CastingDevice> consume_Windows_Media_Casting_ICastingDeviceStatics<D>::FromIdAsync(param::hstring const& value) const
{
    Windows::Foundation::IAsyncOperation<Windows::Media::Casting::CastingDevice> operation{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Media::Casting::ICastingDeviceStatics)->FromIdAsync(get_abi(value), put_abi(operation)));
    return operation;
}

template <typename D> Windows::Foundation::IAsyncOperation<bool> consume_Windows_Media_Casting_ICastingDeviceStatics<D>::DeviceInfoSupportsCastingAsync(Windows::Devices::Enumeration::DeviceInformation const& device) const
{
    Windows::Foundation::IAsyncOperation<bool> operation{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Media::Casting::ICastingDeviceStatics)->DeviceInfoSupportsCastingAsync(get_abi(device), put_abi(operation)));
    return operation;
}

template <typename D> Windows::Foundation::Uri consume_Windows_Media_Casting_ICastingSource<D>::PreferredSourceUri() const
{
    Windows::Foundation::Uri value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Media::Casting::ICastingSource)->get_PreferredSourceUri(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_Media_Casting_ICastingSource<D>::PreferredSourceUri(Windows::Foundation::Uri const& value) const
{
    check_hresult(WINRT_SHIM(Windows::Media::Casting::ICastingSource)->put_PreferredSourceUri(get_abi(value)));
}

template <typename D>
struct produce<D, Windows::Media::Casting::ICastingConnection> : produce_base<D, Windows::Media::Casting::ICastingConnection>
{
    int32_t WINRT_CALL get_State(Windows::Media::Casting::CastingConnectionState* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(State, WINRT_WRAP(Windows::Media::Casting::CastingConnectionState));
            *value = detach_from<Windows::Media::Casting::CastingConnectionState>(this->shim().State());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Device(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Device, WINRT_WRAP(Windows::Media::Casting::CastingDevice));
            *value = detach_from<Windows::Media::Casting::CastingDevice>(this->shim().Device());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Source(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Source, WINRT_WRAP(Windows::Media::Casting::CastingSource));
            *value = detach_from<Windows::Media::Casting::CastingSource>(this->shim().Source());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_Source(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Source, WINRT_WRAP(void), Windows::Media::Casting::CastingSource const&);
            this->shim().Source(*reinterpret_cast<Windows::Media::Casting::CastingSource const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL add_StateChanged(void* handler, winrt::event_token* token) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(StateChanged, WINRT_WRAP(winrt::event_token), Windows::Foundation::TypedEventHandler<Windows::Media::Casting::CastingConnection, Windows::Foundation::IInspectable> const&);
            *token = detach_from<winrt::event_token>(this->shim().StateChanged(*reinterpret_cast<Windows::Foundation::TypedEventHandler<Windows::Media::Casting::CastingConnection, Windows::Foundation::IInspectable> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL remove_StateChanged(winrt::event_token token) noexcept final
    {
        typename D::abi_guard guard(this->shim());
        WINRT_ASSERT_DECLARATION(StateChanged, WINRT_WRAP(void), winrt::event_token const&);
        this->shim().StateChanged(*reinterpret_cast<winrt::event_token const*>(&token));
        return 0;
    }

    int32_t WINRT_CALL add_ErrorOccurred(void* handler, winrt::event_token* token) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ErrorOccurred, WINRT_WRAP(winrt::event_token), Windows::Foundation::TypedEventHandler<Windows::Media::Casting::CastingConnection, Windows::Media::Casting::CastingConnectionErrorOccurredEventArgs> const&);
            *token = detach_from<winrt::event_token>(this->shim().ErrorOccurred(*reinterpret_cast<Windows::Foundation::TypedEventHandler<Windows::Media::Casting::CastingConnection, Windows::Media::Casting::CastingConnectionErrorOccurredEventArgs> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL remove_ErrorOccurred(winrt::event_token token) noexcept final
    {
        typename D::abi_guard guard(this->shim());
        WINRT_ASSERT_DECLARATION(ErrorOccurred, WINRT_WRAP(void), winrt::event_token const&);
        this->shim().ErrorOccurred(*reinterpret_cast<winrt::event_token const*>(&token));
        return 0;
    }

    int32_t WINRT_CALL RequestStartCastingAsync(void* value, void** operation) noexcept final
    {
        try
        {
            *operation = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(RequestStartCastingAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<Windows::Media::Casting::CastingConnectionErrorStatus>), Windows::Media::Casting::CastingSource const);
            *operation = detach_from<Windows::Foundation::IAsyncOperation<Windows::Media::Casting::CastingConnectionErrorStatus>>(this->shim().RequestStartCastingAsync(*reinterpret_cast<Windows::Media::Casting::CastingSource const*>(&value)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL DisconnectAsync(void** operation) noexcept final
    {
        try
        {
            *operation = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(DisconnectAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<Windows::Media::Casting::CastingConnectionErrorStatus>));
            *operation = detach_from<Windows::Foundation::IAsyncOperation<Windows::Media::Casting::CastingConnectionErrorStatus>>(this->shim().DisconnectAsync());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Media::Casting::ICastingConnectionErrorOccurredEventArgs> : produce_base<D, Windows::Media::Casting::ICastingConnectionErrorOccurredEventArgs>
{
    int32_t WINRT_CALL get_ErrorStatus(Windows::Media::Casting::CastingConnectionErrorStatus* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ErrorStatus, WINRT_WRAP(Windows::Media::Casting::CastingConnectionErrorStatus));
            *value = detach_from<Windows::Media::Casting::CastingConnectionErrorStatus>(this->shim().ErrorStatus());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Message(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Message, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().Message());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Media::Casting::ICastingDevice> : produce_base<D, Windows::Media::Casting::ICastingDevice>
{
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

    int32_t WINRT_CALL get_FriendlyName(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(FriendlyName, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().FriendlyName());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Icon(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Icon, WINRT_WRAP(Windows::Storage::Streams::IRandomAccessStreamWithContentType));
            *value = detach_from<Windows::Storage::Streams::IRandomAccessStreamWithContentType>(this->shim().Icon());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL GetSupportedCastingPlaybackTypesAsync(void** operation) noexcept final
    {
        try
        {
            *operation = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetSupportedCastingPlaybackTypesAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<Windows::Media::Casting::CastingPlaybackTypes>));
            *operation = detach_from<Windows::Foundation::IAsyncOperation<Windows::Media::Casting::CastingPlaybackTypes>>(this->shim().GetSupportedCastingPlaybackTypesAsync());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL CreateCastingConnection(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CreateCastingConnection, WINRT_WRAP(Windows::Media::Casting::CastingConnection));
            *value = detach_from<Windows::Media::Casting::CastingConnection>(this->shim().CreateCastingConnection());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Media::Casting::ICastingDevicePicker> : produce_base<D, Windows::Media::Casting::ICastingDevicePicker>
{
    int32_t WINRT_CALL get_Filter(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Filter, WINRT_WRAP(Windows::Media::Casting::CastingDevicePickerFilter));
            *value = detach_from<Windows::Media::Casting::CastingDevicePickerFilter>(this->shim().Filter());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Appearance(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Appearance, WINRT_WRAP(Windows::Devices::Enumeration::DevicePickerAppearance));
            *value = detach_from<Windows::Devices::Enumeration::DevicePickerAppearance>(this->shim().Appearance());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL add_CastingDeviceSelected(void* handler, winrt::event_token* token) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CastingDeviceSelected, WINRT_WRAP(winrt::event_token), Windows::Foundation::TypedEventHandler<Windows::Media::Casting::CastingDevicePicker, Windows::Media::Casting::CastingDeviceSelectedEventArgs> const&);
            *token = detach_from<winrt::event_token>(this->shim().CastingDeviceSelected(*reinterpret_cast<Windows::Foundation::TypedEventHandler<Windows::Media::Casting::CastingDevicePicker, Windows::Media::Casting::CastingDeviceSelectedEventArgs> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL remove_CastingDeviceSelected(winrt::event_token token) noexcept final
    {
        typename D::abi_guard guard(this->shim());
        WINRT_ASSERT_DECLARATION(CastingDeviceSelected, WINRT_WRAP(void), winrt::event_token const&);
        this->shim().CastingDeviceSelected(*reinterpret_cast<winrt::event_token const*>(&token));
        return 0;
    }

    int32_t WINRT_CALL add_CastingDevicePickerDismissed(void* handler, winrt::event_token* token) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CastingDevicePickerDismissed, WINRT_WRAP(winrt::event_token), Windows::Foundation::TypedEventHandler<Windows::Media::Casting::CastingDevicePicker, Windows::Foundation::IInspectable> const&);
            *token = detach_from<winrt::event_token>(this->shim().CastingDevicePickerDismissed(*reinterpret_cast<Windows::Foundation::TypedEventHandler<Windows::Media::Casting::CastingDevicePicker, Windows::Foundation::IInspectable> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL remove_CastingDevicePickerDismissed(winrt::event_token token) noexcept final
    {
        typename D::abi_guard guard(this->shim());
        WINRT_ASSERT_DECLARATION(CastingDevicePickerDismissed, WINRT_WRAP(void), winrt::event_token const&);
        this->shim().CastingDevicePickerDismissed(*reinterpret_cast<winrt::event_token const*>(&token));
        return 0;
    }

    int32_t WINRT_CALL Show(Windows::Foundation::Rect selection) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Show, WINRT_WRAP(void), Windows::Foundation::Rect const&);
            this->shim().Show(*reinterpret_cast<Windows::Foundation::Rect const*>(&selection));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL ShowWithPlacement(Windows::Foundation::Rect selection, Windows::UI::Popups::Placement preferredPlacement) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Show, WINRT_WRAP(void), Windows::Foundation::Rect const&, Windows::UI::Popups::Placement const&);
            this->shim().Show(*reinterpret_cast<Windows::Foundation::Rect const*>(&selection), *reinterpret_cast<Windows::UI::Popups::Placement const*>(&preferredPlacement));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL Hide() noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Hide, WINRT_WRAP(void));
            this->shim().Hide();
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Media::Casting::ICastingDevicePickerFilter> : produce_base<D, Windows::Media::Casting::ICastingDevicePickerFilter>
{
    int32_t WINRT_CALL get_SupportsAudio(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SupportsAudio, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().SupportsAudio());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_SupportsAudio(bool value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SupportsAudio, WINRT_WRAP(void), bool);
            this->shim().SupportsAudio(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_SupportsVideo(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SupportsVideo, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().SupportsVideo());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_SupportsVideo(bool value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SupportsVideo, WINRT_WRAP(void), bool);
            this->shim().SupportsVideo(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_SupportsPictures(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SupportsPictures, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().SupportsPictures());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_SupportsPictures(bool value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SupportsPictures, WINRT_WRAP(void), bool);
            this->shim().SupportsPictures(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_SupportedCastingSources(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SupportedCastingSources, WINRT_WRAP(Windows::Foundation::Collections::IVector<Windows::Media::Casting::CastingSource>));
            *value = detach_from<Windows::Foundation::Collections::IVector<Windows::Media::Casting::CastingSource>>(this->shim().SupportedCastingSources());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Media::Casting::ICastingDeviceSelectedEventArgs> : produce_base<D, Windows::Media::Casting::ICastingDeviceSelectedEventArgs>
{
    int32_t WINRT_CALL get_SelectedCastingDevice(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SelectedCastingDevice, WINRT_WRAP(Windows::Media::Casting::CastingDevice));
            *value = detach_from<Windows::Media::Casting::CastingDevice>(this->shim().SelectedCastingDevice());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Media::Casting::ICastingDeviceStatics> : produce_base<D, Windows::Media::Casting::ICastingDeviceStatics>
{
    int32_t WINRT_CALL GetDeviceSelector(Windows::Media::Casting::CastingPlaybackTypes type, void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetDeviceSelector, WINRT_WRAP(hstring), Windows::Media::Casting::CastingPlaybackTypes const&);
            *value = detach_from<hstring>(this->shim().GetDeviceSelector(*reinterpret_cast<Windows::Media::Casting::CastingPlaybackTypes const*>(&type)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL GetDeviceSelectorFromCastingSourceAsync(void* castingSource, void** operation) noexcept final
    {
        try
        {
            *operation = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetDeviceSelectorFromCastingSourceAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<hstring>), Windows::Media::Casting::CastingSource const);
            *operation = detach_from<Windows::Foundation::IAsyncOperation<hstring>>(this->shim().GetDeviceSelectorFromCastingSourceAsync(*reinterpret_cast<Windows::Media::Casting::CastingSource const*>(&castingSource)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL FromIdAsync(void* value, void** operation) noexcept final
    {
        try
        {
            *operation = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(FromIdAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<Windows::Media::Casting::CastingDevice>), hstring const);
            *operation = detach_from<Windows::Foundation::IAsyncOperation<Windows::Media::Casting::CastingDevice>>(this->shim().FromIdAsync(*reinterpret_cast<hstring const*>(&value)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL DeviceInfoSupportsCastingAsync(void* device, void** operation) noexcept final
    {
        try
        {
            *operation = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(DeviceInfoSupportsCastingAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<bool>), Windows::Devices::Enumeration::DeviceInformation const);
            *operation = detach_from<Windows::Foundation::IAsyncOperation<bool>>(this->shim().DeviceInfoSupportsCastingAsync(*reinterpret_cast<Windows::Devices::Enumeration::DeviceInformation const*>(&device)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Media::Casting::ICastingSource> : produce_base<D, Windows::Media::Casting::ICastingSource>
{
    int32_t WINRT_CALL get_PreferredSourceUri(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(PreferredSourceUri, WINRT_WRAP(Windows::Foundation::Uri));
            *value = detach_from<Windows::Foundation::Uri>(this->shim().PreferredSourceUri());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_PreferredSourceUri(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(PreferredSourceUri, WINRT_WRAP(void), Windows::Foundation::Uri const&);
            this->shim().PreferredSourceUri(*reinterpret_cast<Windows::Foundation::Uri const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

}

WINRT_EXPORT namespace winrt::Windows::Media::Casting {

inline hstring CastingDevice::GetDeviceSelector(Windows::Media::Casting::CastingPlaybackTypes const& type)
{
    return impl::call_factory<CastingDevice, Windows::Media::Casting::ICastingDeviceStatics>([&](auto&& f) { return f.GetDeviceSelector(type); });
}

inline Windows::Foundation::IAsyncOperation<hstring> CastingDevice::GetDeviceSelectorFromCastingSourceAsync(Windows::Media::Casting::CastingSource const& castingSource)
{
    return impl::call_factory<CastingDevice, Windows::Media::Casting::ICastingDeviceStatics>([&](auto&& f) { return f.GetDeviceSelectorFromCastingSourceAsync(castingSource); });
}

inline Windows::Foundation::IAsyncOperation<Windows::Media::Casting::CastingDevice> CastingDevice::FromIdAsync(param::hstring const& value)
{
    return impl::call_factory<CastingDevice, Windows::Media::Casting::ICastingDeviceStatics>([&](auto&& f) { return f.FromIdAsync(value); });
}

inline Windows::Foundation::IAsyncOperation<bool> CastingDevice::DeviceInfoSupportsCastingAsync(Windows::Devices::Enumeration::DeviceInformation const& device)
{
    return impl::call_factory<CastingDevice, Windows::Media::Casting::ICastingDeviceStatics>([&](auto&& f) { return f.DeviceInfoSupportsCastingAsync(device); });
}

inline CastingDevicePicker::CastingDevicePicker() :
    CastingDevicePicker(impl::call_factory<CastingDevicePicker>([](auto&& f) { return f.template ActivateInstance<CastingDevicePicker>(); }))
{}

}

WINRT_EXPORT namespace std {

template<> struct hash<winrt::Windows::Media::Casting::ICastingConnection> : winrt::impl::hash_base<winrt::Windows::Media::Casting::ICastingConnection> {};
template<> struct hash<winrt::Windows::Media::Casting::ICastingConnectionErrorOccurredEventArgs> : winrt::impl::hash_base<winrt::Windows::Media::Casting::ICastingConnectionErrorOccurredEventArgs> {};
template<> struct hash<winrt::Windows::Media::Casting::ICastingDevice> : winrt::impl::hash_base<winrt::Windows::Media::Casting::ICastingDevice> {};
template<> struct hash<winrt::Windows::Media::Casting::ICastingDevicePicker> : winrt::impl::hash_base<winrt::Windows::Media::Casting::ICastingDevicePicker> {};
template<> struct hash<winrt::Windows::Media::Casting::ICastingDevicePickerFilter> : winrt::impl::hash_base<winrt::Windows::Media::Casting::ICastingDevicePickerFilter> {};
template<> struct hash<winrt::Windows::Media::Casting::ICastingDeviceSelectedEventArgs> : winrt::impl::hash_base<winrt::Windows::Media::Casting::ICastingDeviceSelectedEventArgs> {};
template<> struct hash<winrt::Windows::Media::Casting::ICastingDeviceStatics> : winrt::impl::hash_base<winrt::Windows::Media::Casting::ICastingDeviceStatics> {};
template<> struct hash<winrt::Windows::Media::Casting::ICastingSource> : winrt::impl::hash_base<winrt::Windows::Media::Casting::ICastingSource> {};
template<> struct hash<winrt::Windows::Media::Casting::CastingConnection> : winrt::impl::hash_base<winrt::Windows::Media::Casting::CastingConnection> {};
template<> struct hash<winrt::Windows::Media::Casting::CastingConnectionErrorOccurredEventArgs> : winrt::impl::hash_base<winrt::Windows::Media::Casting::CastingConnectionErrorOccurredEventArgs> {};
template<> struct hash<winrt::Windows::Media::Casting::CastingDevice> : winrt::impl::hash_base<winrt::Windows::Media::Casting::CastingDevice> {};
template<> struct hash<winrt::Windows::Media::Casting::CastingDevicePicker> : winrt::impl::hash_base<winrt::Windows::Media::Casting::CastingDevicePicker> {};
template<> struct hash<winrt::Windows::Media::Casting::CastingDevicePickerFilter> : winrt::impl::hash_base<winrt::Windows::Media::Casting::CastingDevicePickerFilter> {};
template<> struct hash<winrt::Windows::Media::Casting::CastingDeviceSelectedEventArgs> : winrt::impl::hash_base<winrt::Windows::Media::Casting::CastingDeviceSelectedEventArgs> {};
template<> struct hash<winrt::Windows::Media::Casting::CastingSource> : winrt::impl::hash_base<winrt::Windows::Media::Casting::CastingSource> {};

}
