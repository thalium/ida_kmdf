// C++/WinRT v1.0.190111.3

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#pragma once

#include "winrt/base.h"

#include "winrt/Windows.Foundation.h"
#include "winrt/Windows.Foundation.Collections.h"
#include "winrt/impl/Windows.Devices.Enumeration.2.h"
#include "winrt/impl/Windows.Storage.Streams.2.h"
#include "winrt/impl/Windows.UI.Popups.2.h"
#include "winrt/impl/Windows.Media.DialProtocol.2.h"
#include "winrt/Windows.Media.h"

namespace winrt::impl {

template <typename D> hstring consume_Windows_Media_DialProtocol_IDialApp<D>::AppName() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Media::DialProtocol::IDialApp)->get_AppName(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::IAsyncOperation<Windows::Media::DialProtocol::DialAppLaunchResult> consume_Windows_Media_DialProtocol_IDialApp<D>::RequestLaunchAsync(param::hstring const& appArgument) const
{
    Windows::Foundation::IAsyncOperation<Windows::Media::DialProtocol::DialAppLaunchResult> value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Media::DialProtocol::IDialApp)->RequestLaunchAsync(get_abi(appArgument), put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::IAsyncOperation<Windows::Media::DialProtocol::DialAppStopResult> consume_Windows_Media_DialProtocol_IDialApp<D>::StopAsync() const
{
    Windows::Foundation::IAsyncOperation<Windows::Media::DialProtocol::DialAppStopResult> value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Media::DialProtocol::IDialApp)->StopAsync(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::IAsyncOperation<Windows::Media::DialProtocol::DialAppStateDetails> consume_Windows_Media_DialProtocol_IDialApp<D>::GetAppStateAsync() const
{
    Windows::Foundation::IAsyncOperation<Windows::Media::DialProtocol::DialAppStateDetails> value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Media::DialProtocol::IDialApp)->GetAppStateAsync(put_abi(value)));
    return value;
}

template <typename D> Windows::Media::DialProtocol::DialAppState consume_Windows_Media_DialProtocol_IDialAppStateDetails<D>::State() const
{
    Windows::Media::DialProtocol::DialAppState value{};
    check_hresult(WINRT_SHIM(Windows::Media::DialProtocol::IDialAppStateDetails)->get_State(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_Media_DialProtocol_IDialAppStateDetails<D>::FullXml() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Media::DialProtocol::IDialAppStateDetails)->get_FullXml(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_Media_DialProtocol_IDialDevice<D>::Id() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Media::DialProtocol::IDialDevice)->get_Id(put_abi(value)));
    return value;
}

template <typename D> Windows::Media::DialProtocol::DialApp consume_Windows_Media_DialProtocol_IDialDevice<D>::GetDialApp(param::hstring const& appName) const
{
    Windows::Media::DialProtocol::DialApp value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Media::DialProtocol::IDialDevice)->GetDialApp(get_abi(appName), put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_Media_DialProtocol_IDialDevice2<D>::FriendlyName() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Media::DialProtocol::IDialDevice2)->get_FriendlyName(put_abi(value)));
    return value;
}

template <typename D> Windows::Storage::Streams::IRandomAccessStreamReference consume_Windows_Media_DialProtocol_IDialDevice2<D>::Thumbnail() const
{
    Windows::Storage::Streams::IRandomAccessStreamReference value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Media::DialProtocol::IDialDevice2)->get_Thumbnail(put_abi(value)));
    return value;
}

template <typename D> Windows::Media::DialProtocol::DialDevicePickerFilter consume_Windows_Media_DialProtocol_IDialDevicePicker<D>::Filter() const
{
    Windows::Media::DialProtocol::DialDevicePickerFilter value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Media::DialProtocol::IDialDevicePicker)->get_Filter(put_abi(value)));
    return value;
}

template <typename D> Windows::Devices::Enumeration::DevicePickerAppearance consume_Windows_Media_DialProtocol_IDialDevicePicker<D>::Appearance() const
{
    Windows::Devices::Enumeration::DevicePickerAppearance value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Media::DialProtocol::IDialDevicePicker)->get_Appearance(put_abi(value)));
    return value;
}

template <typename D> winrt::event_token consume_Windows_Media_DialProtocol_IDialDevicePicker<D>::DialDeviceSelected(Windows::Foundation::TypedEventHandler<Windows::Media::DialProtocol::DialDevicePicker, Windows::Media::DialProtocol::DialDeviceSelectedEventArgs> const& handler) const
{
    winrt::event_token token{};
    check_hresult(WINRT_SHIM(Windows::Media::DialProtocol::IDialDevicePicker)->add_DialDeviceSelected(get_abi(handler), put_abi(token)));
    return token;
}

template <typename D> typename consume_Windows_Media_DialProtocol_IDialDevicePicker<D>::DialDeviceSelected_revoker consume_Windows_Media_DialProtocol_IDialDevicePicker<D>::DialDeviceSelected(auto_revoke_t, Windows::Foundation::TypedEventHandler<Windows::Media::DialProtocol::DialDevicePicker, Windows::Media::DialProtocol::DialDeviceSelectedEventArgs> const& handler) const
{
    return impl::make_event_revoker<D, DialDeviceSelected_revoker>(this, DialDeviceSelected(handler));
}

template <typename D> void consume_Windows_Media_DialProtocol_IDialDevicePicker<D>::DialDeviceSelected(winrt::event_token const& token) const noexcept
{
    WINRT_VERIFY_(0, WINRT_SHIM(Windows::Media::DialProtocol::IDialDevicePicker)->remove_DialDeviceSelected(get_abi(token)));
}

template <typename D> winrt::event_token consume_Windows_Media_DialProtocol_IDialDevicePicker<D>::DisconnectButtonClicked(Windows::Foundation::TypedEventHandler<Windows::Media::DialProtocol::DialDevicePicker, Windows::Media::DialProtocol::DialDisconnectButtonClickedEventArgs> const& handler) const
{
    winrt::event_token token{};
    check_hresult(WINRT_SHIM(Windows::Media::DialProtocol::IDialDevicePicker)->add_DisconnectButtonClicked(get_abi(handler), put_abi(token)));
    return token;
}

template <typename D> typename consume_Windows_Media_DialProtocol_IDialDevicePicker<D>::DisconnectButtonClicked_revoker consume_Windows_Media_DialProtocol_IDialDevicePicker<D>::DisconnectButtonClicked(auto_revoke_t, Windows::Foundation::TypedEventHandler<Windows::Media::DialProtocol::DialDevicePicker, Windows::Media::DialProtocol::DialDisconnectButtonClickedEventArgs> const& handler) const
{
    return impl::make_event_revoker<D, DisconnectButtonClicked_revoker>(this, DisconnectButtonClicked(handler));
}

template <typename D> void consume_Windows_Media_DialProtocol_IDialDevicePicker<D>::DisconnectButtonClicked(winrt::event_token const& token) const noexcept
{
    WINRT_VERIFY_(0, WINRT_SHIM(Windows::Media::DialProtocol::IDialDevicePicker)->remove_DisconnectButtonClicked(get_abi(token)));
}

template <typename D> winrt::event_token consume_Windows_Media_DialProtocol_IDialDevicePicker<D>::DialDevicePickerDismissed(Windows::Foundation::TypedEventHandler<Windows::Media::DialProtocol::DialDevicePicker, Windows::Foundation::IInspectable> const& handler) const
{
    winrt::event_token token{};
    check_hresult(WINRT_SHIM(Windows::Media::DialProtocol::IDialDevicePicker)->add_DialDevicePickerDismissed(get_abi(handler), put_abi(token)));
    return token;
}

template <typename D> typename consume_Windows_Media_DialProtocol_IDialDevicePicker<D>::DialDevicePickerDismissed_revoker consume_Windows_Media_DialProtocol_IDialDevicePicker<D>::DialDevicePickerDismissed(auto_revoke_t, Windows::Foundation::TypedEventHandler<Windows::Media::DialProtocol::DialDevicePicker, Windows::Foundation::IInspectable> const& handler) const
{
    return impl::make_event_revoker<D, DialDevicePickerDismissed_revoker>(this, DialDevicePickerDismissed(handler));
}

template <typename D> void consume_Windows_Media_DialProtocol_IDialDevicePicker<D>::DialDevicePickerDismissed(winrt::event_token const& token) const noexcept
{
    WINRT_VERIFY_(0, WINRT_SHIM(Windows::Media::DialProtocol::IDialDevicePicker)->remove_DialDevicePickerDismissed(get_abi(token)));
}

template <typename D> void consume_Windows_Media_DialProtocol_IDialDevicePicker<D>::Show(Windows::Foundation::Rect const& selection) const
{
    check_hresult(WINRT_SHIM(Windows::Media::DialProtocol::IDialDevicePicker)->Show(get_abi(selection)));
}

template <typename D> void consume_Windows_Media_DialProtocol_IDialDevicePicker<D>::Show(Windows::Foundation::Rect const& selection, Windows::UI::Popups::Placement const& preferredPlacement) const
{
    check_hresult(WINRT_SHIM(Windows::Media::DialProtocol::IDialDevicePicker)->ShowWithPlacement(get_abi(selection), get_abi(preferredPlacement)));
}

template <typename D> Windows::Foundation::IAsyncOperation<Windows::Media::DialProtocol::DialDevice> consume_Windows_Media_DialProtocol_IDialDevicePicker<D>::PickSingleDialDeviceAsync(Windows::Foundation::Rect const& selection) const
{
    Windows::Foundation::IAsyncOperation<Windows::Media::DialProtocol::DialDevice> operation{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Media::DialProtocol::IDialDevicePicker)->PickSingleDialDeviceAsync(get_abi(selection), put_abi(operation)));
    return operation;
}

template <typename D> Windows::Foundation::IAsyncOperation<Windows::Media::DialProtocol::DialDevice> consume_Windows_Media_DialProtocol_IDialDevicePicker<D>::PickSingleDialDeviceAsync(Windows::Foundation::Rect const& selection, Windows::UI::Popups::Placement const& preferredPlacement) const
{
    Windows::Foundation::IAsyncOperation<Windows::Media::DialProtocol::DialDevice> operation{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Media::DialProtocol::IDialDevicePicker)->PickSingleDialDeviceAsyncWithPlacement(get_abi(selection), get_abi(preferredPlacement), put_abi(operation)));
    return operation;
}

template <typename D> void consume_Windows_Media_DialProtocol_IDialDevicePicker<D>::Hide() const
{
    check_hresult(WINRT_SHIM(Windows::Media::DialProtocol::IDialDevicePicker)->Hide());
}

template <typename D> void consume_Windows_Media_DialProtocol_IDialDevicePicker<D>::SetDisplayStatus(Windows::Media::DialProtocol::DialDevice const& device, Windows::Media::DialProtocol::DialDeviceDisplayStatus const& status) const
{
    check_hresult(WINRT_SHIM(Windows::Media::DialProtocol::IDialDevicePicker)->SetDisplayStatus(get_abi(device), get_abi(status)));
}

template <typename D> Windows::Foundation::Collections::IVector<hstring> consume_Windows_Media_DialProtocol_IDialDevicePickerFilter<D>::SupportedAppNames() const
{
    Windows::Foundation::Collections::IVector<hstring> value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Media::DialProtocol::IDialDevicePickerFilter)->get_SupportedAppNames(put_abi(value)));
    return value;
}

template <typename D> Windows::Media::DialProtocol::DialDevice consume_Windows_Media_DialProtocol_IDialDeviceSelectedEventArgs<D>::SelectedDialDevice() const
{
    Windows::Media::DialProtocol::DialDevice value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Media::DialProtocol::IDialDeviceSelectedEventArgs)->get_SelectedDialDevice(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_Media_DialProtocol_IDialDeviceStatics<D>::GetDeviceSelector(param::hstring const& appName) const
{
    hstring selector{};
    check_hresult(WINRT_SHIM(Windows::Media::DialProtocol::IDialDeviceStatics)->GetDeviceSelector(get_abi(appName), put_abi(selector)));
    return selector;
}

template <typename D> Windows::Foundation::IAsyncOperation<Windows::Media::DialProtocol::DialDevice> consume_Windows_Media_DialProtocol_IDialDeviceStatics<D>::FromIdAsync(param::hstring const& value) const
{
    Windows::Foundation::IAsyncOperation<Windows::Media::DialProtocol::DialDevice> operation{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Media::DialProtocol::IDialDeviceStatics)->FromIdAsync(get_abi(value), put_abi(operation)));
    return operation;
}

template <typename D> Windows::Foundation::IAsyncOperation<bool> consume_Windows_Media_DialProtocol_IDialDeviceStatics<D>::DeviceInfoSupportsDialAsync(Windows::Devices::Enumeration::DeviceInformation const& device) const
{
    Windows::Foundation::IAsyncOperation<bool> operation{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Media::DialProtocol::IDialDeviceStatics)->DeviceInfoSupportsDialAsync(get_abi(device), put_abi(operation)));
    return operation;
}

template <typename D> Windows::Media::DialProtocol::DialDevice consume_Windows_Media_DialProtocol_IDialDisconnectButtonClickedEventArgs<D>::Device() const
{
    Windows::Media::DialProtocol::DialDevice value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Media::DialProtocol::IDialDisconnectButtonClickedEventArgs)->get_Device(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::IAsyncOperation<Windows::Foundation::Collections::IMap<hstring, hstring>> consume_Windows_Media_DialProtocol_IDialReceiverApp<D>::GetAdditionalDataAsync() const
{
    Windows::Foundation::IAsyncOperation<Windows::Foundation::Collections::IMap<hstring, hstring>> operation{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Media::DialProtocol::IDialReceiverApp)->GetAdditionalDataAsync(put_abi(operation)));
    return operation;
}

template <typename D> Windows::Foundation::IAsyncAction consume_Windows_Media_DialProtocol_IDialReceiverApp<D>::SetAdditionalDataAsync(param::async_iterable<Windows::Foundation::Collections::IKeyValuePair<hstring, hstring>> const& additionalData) const
{
    Windows::Foundation::IAsyncAction operation{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Media::DialProtocol::IDialReceiverApp)->SetAdditionalDataAsync(get_abi(additionalData), put_abi(operation)));
    return operation;
}

template <typename D> Windows::Foundation::IAsyncOperation<hstring> consume_Windows_Media_DialProtocol_IDialReceiverApp2<D>::GetUniqueDeviceNameAsync() const
{
    Windows::Foundation::IAsyncOperation<hstring> operation{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Media::DialProtocol::IDialReceiverApp2)->GetUniqueDeviceNameAsync(put_abi(operation)));
    return operation;
}

template <typename D> Windows::Media::DialProtocol::DialReceiverApp consume_Windows_Media_DialProtocol_IDialReceiverAppStatics<D>::Current() const
{
    Windows::Media::DialProtocol::DialReceiverApp value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Media::DialProtocol::IDialReceiverAppStatics)->get_Current(put_abi(value)));
    return value;
}

template <typename D>
struct produce<D, Windows::Media::DialProtocol::IDialApp> : produce_base<D, Windows::Media::DialProtocol::IDialApp>
{
    int32_t WINRT_CALL get_AppName(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(AppName, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().AppName());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL RequestLaunchAsync(void* appArgument, void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(RequestLaunchAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<Windows::Media::DialProtocol::DialAppLaunchResult>), hstring const);
            *value = detach_from<Windows::Foundation::IAsyncOperation<Windows::Media::DialProtocol::DialAppLaunchResult>>(this->shim().RequestLaunchAsync(*reinterpret_cast<hstring const*>(&appArgument)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL StopAsync(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(StopAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<Windows::Media::DialProtocol::DialAppStopResult>));
            *value = detach_from<Windows::Foundation::IAsyncOperation<Windows::Media::DialProtocol::DialAppStopResult>>(this->shim().StopAsync());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL GetAppStateAsync(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetAppStateAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<Windows::Media::DialProtocol::DialAppStateDetails>));
            *value = detach_from<Windows::Foundation::IAsyncOperation<Windows::Media::DialProtocol::DialAppStateDetails>>(this->shim().GetAppStateAsync());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Media::DialProtocol::IDialAppStateDetails> : produce_base<D, Windows::Media::DialProtocol::IDialAppStateDetails>
{
    int32_t WINRT_CALL get_State(Windows::Media::DialProtocol::DialAppState* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(State, WINRT_WRAP(Windows::Media::DialProtocol::DialAppState));
            *value = detach_from<Windows::Media::DialProtocol::DialAppState>(this->shim().State());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_FullXml(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(FullXml, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().FullXml());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Media::DialProtocol::IDialDevice> : produce_base<D, Windows::Media::DialProtocol::IDialDevice>
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

    int32_t WINRT_CALL GetDialApp(void* appName, void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetDialApp, WINRT_WRAP(Windows::Media::DialProtocol::DialApp), hstring const&);
            *value = detach_from<Windows::Media::DialProtocol::DialApp>(this->shim().GetDialApp(*reinterpret_cast<hstring const*>(&appName)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Media::DialProtocol::IDialDevice2> : produce_base<D, Windows::Media::DialProtocol::IDialDevice2>
{
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

    int32_t WINRT_CALL get_Thumbnail(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Thumbnail, WINRT_WRAP(Windows::Storage::Streams::IRandomAccessStreamReference));
            *value = detach_from<Windows::Storage::Streams::IRandomAccessStreamReference>(this->shim().Thumbnail());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Media::DialProtocol::IDialDevicePicker> : produce_base<D, Windows::Media::DialProtocol::IDialDevicePicker>
{
    int32_t WINRT_CALL get_Filter(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Filter, WINRT_WRAP(Windows::Media::DialProtocol::DialDevicePickerFilter));
            *value = detach_from<Windows::Media::DialProtocol::DialDevicePickerFilter>(this->shim().Filter());
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

    int32_t WINRT_CALL add_DialDeviceSelected(void* handler, winrt::event_token* token) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(DialDeviceSelected, WINRT_WRAP(winrt::event_token), Windows::Foundation::TypedEventHandler<Windows::Media::DialProtocol::DialDevicePicker, Windows::Media::DialProtocol::DialDeviceSelectedEventArgs> const&);
            *token = detach_from<winrt::event_token>(this->shim().DialDeviceSelected(*reinterpret_cast<Windows::Foundation::TypedEventHandler<Windows::Media::DialProtocol::DialDevicePicker, Windows::Media::DialProtocol::DialDeviceSelectedEventArgs> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL remove_DialDeviceSelected(winrt::event_token token) noexcept final
    {
        typename D::abi_guard guard(this->shim());
        WINRT_ASSERT_DECLARATION(DialDeviceSelected, WINRT_WRAP(void), winrt::event_token const&);
        this->shim().DialDeviceSelected(*reinterpret_cast<winrt::event_token const*>(&token));
        return 0;
    }

    int32_t WINRT_CALL add_DisconnectButtonClicked(void* handler, winrt::event_token* token) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(DisconnectButtonClicked, WINRT_WRAP(winrt::event_token), Windows::Foundation::TypedEventHandler<Windows::Media::DialProtocol::DialDevicePicker, Windows::Media::DialProtocol::DialDisconnectButtonClickedEventArgs> const&);
            *token = detach_from<winrt::event_token>(this->shim().DisconnectButtonClicked(*reinterpret_cast<Windows::Foundation::TypedEventHandler<Windows::Media::DialProtocol::DialDevicePicker, Windows::Media::DialProtocol::DialDisconnectButtonClickedEventArgs> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL remove_DisconnectButtonClicked(winrt::event_token token) noexcept final
    {
        typename D::abi_guard guard(this->shim());
        WINRT_ASSERT_DECLARATION(DisconnectButtonClicked, WINRT_WRAP(void), winrt::event_token const&);
        this->shim().DisconnectButtonClicked(*reinterpret_cast<winrt::event_token const*>(&token));
        return 0;
    }

    int32_t WINRT_CALL add_DialDevicePickerDismissed(void* handler, winrt::event_token* token) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(DialDevicePickerDismissed, WINRT_WRAP(winrt::event_token), Windows::Foundation::TypedEventHandler<Windows::Media::DialProtocol::DialDevicePicker, Windows::Foundation::IInspectable> const&);
            *token = detach_from<winrt::event_token>(this->shim().DialDevicePickerDismissed(*reinterpret_cast<Windows::Foundation::TypedEventHandler<Windows::Media::DialProtocol::DialDevicePicker, Windows::Foundation::IInspectable> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL remove_DialDevicePickerDismissed(winrt::event_token token) noexcept final
    {
        typename D::abi_guard guard(this->shim());
        WINRT_ASSERT_DECLARATION(DialDevicePickerDismissed, WINRT_WRAP(void), winrt::event_token const&);
        this->shim().DialDevicePickerDismissed(*reinterpret_cast<winrt::event_token const*>(&token));
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

    int32_t WINRT_CALL PickSingleDialDeviceAsync(Windows::Foundation::Rect selection, void** operation) noexcept final
    {
        try
        {
            *operation = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(PickSingleDialDeviceAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<Windows::Media::DialProtocol::DialDevice>), Windows::Foundation::Rect const);
            *operation = detach_from<Windows::Foundation::IAsyncOperation<Windows::Media::DialProtocol::DialDevice>>(this->shim().PickSingleDialDeviceAsync(*reinterpret_cast<Windows::Foundation::Rect const*>(&selection)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL PickSingleDialDeviceAsyncWithPlacement(Windows::Foundation::Rect selection, Windows::UI::Popups::Placement preferredPlacement, void** operation) noexcept final
    {
        try
        {
            *operation = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(PickSingleDialDeviceAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<Windows::Media::DialProtocol::DialDevice>), Windows::Foundation::Rect const, Windows::UI::Popups::Placement const);
            *operation = detach_from<Windows::Foundation::IAsyncOperation<Windows::Media::DialProtocol::DialDevice>>(this->shim().PickSingleDialDeviceAsync(*reinterpret_cast<Windows::Foundation::Rect const*>(&selection), *reinterpret_cast<Windows::UI::Popups::Placement const*>(&preferredPlacement)));
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

    int32_t WINRT_CALL SetDisplayStatus(void* device, Windows::Media::DialProtocol::DialDeviceDisplayStatus status) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SetDisplayStatus, WINRT_WRAP(void), Windows::Media::DialProtocol::DialDevice const&, Windows::Media::DialProtocol::DialDeviceDisplayStatus const&);
            this->shim().SetDisplayStatus(*reinterpret_cast<Windows::Media::DialProtocol::DialDevice const*>(&device), *reinterpret_cast<Windows::Media::DialProtocol::DialDeviceDisplayStatus const*>(&status));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Media::DialProtocol::IDialDevicePickerFilter> : produce_base<D, Windows::Media::DialProtocol::IDialDevicePickerFilter>
{
    int32_t WINRT_CALL get_SupportedAppNames(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SupportedAppNames, WINRT_WRAP(Windows::Foundation::Collections::IVector<hstring>));
            *value = detach_from<Windows::Foundation::Collections::IVector<hstring>>(this->shim().SupportedAppNames());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Media::DialProtocol::IDialDeviceSelectedEventArgs> : produce_base<D, Windows::Media::DialProtocol::IDialDeviceSelectedEventArgs>
{
    int32_t WINRT_CALL get_SelectedDialDevice(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SelectedDialDevice, WINRT_WRAP(Windows::Media::DialProtocol::DialDevice));
            *value = detach_from<Windows::Media::DialProtocol::DialDevice>(this->shim().SelectedDialDevice());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Media::DialProtocol::IDialDeviceStatics> : produce_base<D, Windows::Media::DialProtocol::IDialDeviceStatics>
{
    int32_t WINRT_CALL GetDeviceSelector(void* appName, void** selector) noexcept final
    {
        try
        {
            *selector = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetDeviceSelector, WINRT_WRAP(hstring), hstring const&);
            *selector = detach_from<hstring>(this->shim().GetDeviceSelector(*reinterpret_cast<hstring const*>(&appName)));
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
            WINRT_ASSERT_DECLARATION(FromIdAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<Windows::Media::DialProtocol::DialDevice>), hstring const);
            *operation = detach_from<Windows::Foundation::IAsyncOperation<Windows::Media::DialProtocol::DialDevice>>(this->shim().FromIdAsync(*reinterpret_cast<hstring const*>(&value)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL DeviceInfoSupportsDialAsync(void* device, void** operation) noexcept final
    {
        try
        {
            *operation = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(DeviceInfoSupportsDialAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<bool>), Windows::Devices::Enumeration::DeviceInformation const);
            *operation = detach_from<Windows::Foundation::IAsyncOperation<bool>>(this->shim().DeviceInfoSupportsDialAsync(*reinterpret_cast<Windows::Devices::Enumeration::DeviceInformation const*>(&device)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Media::DialProtocol::IDialDisconnectButtonClickedEventArgs> : produce_base<D, Windows::Media::DialProtocol::IDialDisconnectButtonClickedEventArgs>
{
    int32_t WINRT_CALL get_Device(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Device, WINRT_WRAP(Windows::Media::DialProtocol::DialDevice));
            *value = detach_from<Windows::Media::DialProtocol::DialDevice>(this->shim().Device());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Media::DialProtocol::IDialReceiverApp> : produce_base<D, Windows::Media::DialProtocol::IDialReceiverApp>
{
    int32_t WINRT_CALL GetAdditionalDataAsync(void** operation) noexcept final
    {
        try
        {
            *operation = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetAdditionalDataAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<Windows::Foundation::Collections::IMap<hstring, hstring>>));
            *operation = detach_from<Windows::Foundation::IAsyncOperation<Windows::Foundation::Collections::IMap<hstring, hstring>>>(this->shim().GetAdditionalDataAsync());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL SetAdditionalDataAsync(void* additionalData, void** operation) noexcept final
    {
        try
        {
            *operation = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SetAdditionalDataAsync, WINRT_WRAP(Windows::Foundation::IAsyncAction), Windows::Foundation::Collections::IIterable<Windows::Foundation::Collections::IKeyValuePair<hstring, hstring>> const);
            *operation = detach_from<Windows::Foundation::IAsyncAction>(this->shim().SetAdditionalDataAsync(*reinterpret_cast<Windows::Foundation::Collections::IIterable<Windows::Foundation::Collections::IKeyValuePair<hstring, hstring>> const*>(&additionalData)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Media::DialProtocol::IDialReceiverApp2> : produce_base<D, Windows::Media::DialProtocol::IDialReceiverApp2>
{
    int32_t WINRT_CALL GetUniqueDeviceNameAsync(void** operation) noexcept final
    {
        try
        {
            *operation = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetUniqueDeviceNameAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<hstring>));
            *operation = detach_from<Windows::Foundation::IAsyncOperation<hstring>>(this->shim().GetUniqueDeviceNameAsync());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Media::DialProtocol::IDialReceiverAppStatics> : produce_base<D, Windows::Media::DialProtocol::IDialReceiverAppStatics>
{
    int32_t WINRT_CALL get_Current(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Current, WINRT_WRAP(Windows::Media::DialProtocol::DialReceiverApp));
            *value = detach_from<Windows::Media::DialProtocol::DialReceiverApp>(this->shim().Current());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

}

WINRT_EXPORT namespace winrt::Windows::Media::DialProtocol {

inline hstring DialDevice::GetDeviceSelector(param::hstring const& appName)
{
    return impl::call_factory<DialDevice, Windows::Media::DialProtocol::IDialDeviceStatics>([&](auto&& f) { return f.GetDeviceSelector(appName); });
}

inline Windows::Foundation::IAsyncOperation<Windows::Media::DialProtocol::DialDevice> DialDevice::FromIdAsync(param::hstring const& value)
{
    return impl::call_factory<DialDevice, Windows::Media::DialProtocol::IDialDeviceStatics>([&](auto&& f) { return f.FromIdAsync(value); });
}

inline Windows::Foundation::IAsyncOperation<bool> DialDevice::DeviceInfoSupportsDialAsync(Windows::Devices::Enumeration::DeviceInformation const& device)
{
    return impl::call_factory<DialDevice, Windows::Media::DialProtocol::IDialDeviceStatics>([&](auto&& f) { return f.DeviceInfoSupportsDialAsync(device); });
}

inline DialDevicePicker::DialDevicePicker() :
    DialDevicePicker(impl::call_factory<DialDevicePicker>([](auto&& f) { return f.template ActivateInstance<DialDevicePicker>(); }))
{}

inline Windows::Media::DialProtocol::DialReceiverApp DialReceiverApp::Current()
{
    return impl::call_factory<DialReceiverApp, Windows::Media::DialProtocol::IDialReceiverAppStatics>([&](auto&& f) { return f.Current(); });
}

}

WINRT_EXPORT namespace std {

template<> struct hash<winrt::Windows::Media::DialProtocol::IDialApp> : winrt::impl::hash_base<winrt::Windows::Media::DialProtocol::IDialApp> {};
template<> struct hash<winrt::Windows::Media::DialProtocol::IDialAppStateDetails> : winrt::impl::hash_base<winrt::Windows::Media::DialProtocol::IDialAppStateDetails> {};
template<> struct hash<winrt::Windows::Media::DialProtocol::IDialDevice> : winrt::impl::hash_base<winrt::Windows::Media::DialProtocol::IDialDevice> {};
template<> struct hash<winrt::Windows::Media::DialProtocol::IDialDevice2> : winrt::impl::hash_base<winrt::Windows::Media::DialProtocol::IDialDevice2> {};
template<> struct hash<winrt::Windows::Media::DialProtocol::IDialDevicePicker> : winrt::impl::hash_base<winrt::Windows::Media::DialProtocol::IDialDevicePicker> {};
template<> struct hash<winrt::Windows::Media::DialProtocol::IDialDevicePickerFilter> : winrt::impl::hash_base<winrt::Windows::Media::DialProtocol::IDialDevicePickerFilter> {};
template<> struct hash<winrt::Windows::Media::DialProtocol::IDialDeviceSelectedEventArgs> : winrt::impl::hash_base<winrt::Windows::Media::DialProtocol::IDialDeviceSelectedEventArgs> {};
template<> struct hash<winrt::Windows::Media::DialProtocol::IDialDeviceStatics> : winrt::impl::hash_base<winrt::Windows::Media::DialProtocol::IDialDeviceStatics> {};
template<> struct hash<winrt::Windows::Media::DialProtocol::IDialDisconnectButtonClickedEventArgs> : winrt::impl::hash_base<winrt::Windows::Media::DialProtocol::IDialDisconnectButtonClickedEventArgs> {};
template<> struct hash<winrt::Windows::Media::DialProtocol::IDialReceiverApp> : winrt::impl::hash_base<winrt::Windows::Media::DialProtocol::IDialReceiverApp> {};
template<> struct hash<winrt::Windows::Media::DialProtocol::IDialReceiverApp2> : winrt::impl::hash_base<winrt::Windows::Media::DialProtocol::IDialReceiverApp2> {};
template<> struct hash<winrt::Windows::Media::DialProtocol::IDialReceiverAppStatics> : winrt::impl::hash_base<winrt::Windows::Media::DialProtocol::IDialReceiverAppStatics> {};
template<> struct hash<winrt::Windows::Media::DialProtocol::DialApp> : winrt::impl::hash_base<winrt::Windows::Media::DialProtocol::DialApp> {};
template<> struct hash<winrt::Windows::Media::DialProtocol::DialAppStateDetails> : winrt::impl::hash_base<winrt::Windows::Media::DialProtocol::DialAppStateDetails> {};
template<> struct hash<winrt::Windows::Media::DialProtocol::DialDevice> : winrt::impl::hash_base<winrt::Windows::Media::DialProtocol::DialDevice> {};
template<> struct hash<winrt::Windows::Media::DialProtocol::DialDevicePicker> : winrt::impl::hash_base<winrt::Windows::Media::DialProtocol::DialDevicePicker> {};
template<> struct hash<winrt::Windows::Media::DialProtocol::DialDevicePickerFilter> : winrt::impl::hash_base<winrt::Windows::Media::DialProtocol::DialDevicePickerFilter> {};
template<> struct hash<winrt::Windows::Media::DialProtocol::DialDeviceSelectedEventArgs> : winrt::impl::hash_base<winrt::Windows::Media::DialProtocol::DialDeviceSelectedEventArgs> {};
template<> struct hash<winrt::Windows::Media::DialProtocol::DialDisconnectButtonClickedEventArgs> : winrt::impl::hash_base<winrt::Windows::Media::DialProtocol::DialDisconnectButtonClickedEventArgs> {};
template<> struct hash<winrt::Windows::Media::DialProtocol::DialReceiverApp> : winrt::impl::hash_base<winrt::Windows::Media::DialProtocol::DialReceiverApp> {};

}
