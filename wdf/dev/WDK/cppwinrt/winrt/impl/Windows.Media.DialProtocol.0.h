// C++/WinRT v1.0.190111.3

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#pragma once

WINRT_EXPORT namespace winrt::Windows::Devices::Enumeration {

struct DeviceInformation;
struct DevicePickerAppearance;

}

WINRT_EXPORT namespace winrt::Windows::Storage::Streams {

struct IRandomAccessStreamReference;

}

WINRT_EXPORT namespace winrt::Windows::UI::Popups {

enum class Placement;

}

WINRT_EXPORT namespace winrt::Windows::Media::DialProtocol {

enum class DialAppLaunchResult : int32_t
{
    Launched = 0,
    FailedToLaunch = 1,
    NotFound = 2,
    NetworkFailure = 3,
};

enum class DialAppState : int32_t
{
    Unknown = 0,
    Stopped = 1,
    Running = 2,
    NetworkFailure = 3,
};

enum class DialAppStopResult : int32_t
{
    Stopped = 0,
    StopFailed = 1,
    OperationNotSupported = 2,
    NetworkFailure = 3,
};

enum class DialDeviceDisplayStatus : int32_t
{
    None = 0,
    Connecting = 1,
    Connected = 2,
    Disconnecting = 3,
    Disconnected = 4,
    Error = 5,
};

struct IDialApp;
struct IDialAppStateDetails;
struct IDialDevice;
struct IDialDevice2;
struct IDialDevicePicker;
struct IDialDevicePickerFilter;
struct IDialDeviceSelectedEventArgs;
struct IDialDeviceStatics;
struct IDialDisconnectButtonClickedEventArgs;
struct IDialReceiverApp;
struct IDialReceiverApp2;
struct IDialReceiverAppStatics;
struct DialApp;
struct DialAppStateDetails;
struct DialDevice;
struct DialDevicePicker;
struct DialDevicePickerFilter;
struct DialDeviceSelectedEventArgs;
struct DialDisconnectButtonClickedEventArgs;
struct DialReceiverApp;

}

namespace winrt::impl {

template <> struct category<Windows::Media::DialProtocol::IDialApp>{ using type = interface_category; };
template <> struct category<Windows::Media::DialProtocol::IDialAppStateDetails>{ using type = interface_category; };
template <> struct category<Windows::Media::DialProtocol::IDialDevice>{ using type = interface_category; };
template <> struct category<Windows::Media::DialProtocol::IDialDevice2>{ using type = interface_category; };
template <> struct category<Windows::Media::DialProtocol::IDialDevicePicker>{ using type = interface_category; };
template <> struct category<Windows::Media::DialProtocol::IDialDevicePickerFilter>{ using type = interface_category; };
template <> struct category<Windows::Media::DialProtocol::IDialDeviceSelectedEventArgs>{ using type = interface_category; };
template <> struct category<Windows::Media::DialProtocol::IDialDeviceStatics>{ using type = interface_category; };
template <> struct category<Windows::Media::DialProtocol::IDialDisconnectButtonClickedEventArgs>{ using type = interface_category; };
template <> struct category<Windows::Media::DialProtocol::IDialReceiverApp>{ using type = interface_category; };
template <> struct category<Windows::Media::DialProtocol::IDialReceiverApp2>{ using type = interface_category; };
template <> struct category<Windows::Media::DialProtocol::IDialReceiverAppStatics>{ using type = interface_category; };
template <> struct category<Windows::Media::DialProtocol::DialApp>{ using type = class_category; };
template <> struct category<Windows::Media::DialProtocol::DialAppStateDetails>{ using type = class_category; };
template <> struct category<Windows::Media::DialProtocol::DialDevice>{ using type = class_category; };
template <> struct category<Windows::Media::DialProtocol::DialDevicePicker>{ using type = class_category; };
template <> struct category<Windows::Media::DialProtocol::DialDevicePickerFilter>{ using type = class_category; };
template <> struct category<Windows::Media::DialProtocol::DialDeviceSelectedEventArgs>{ using type = class_category; };
template <> struct category<Windows::Media::DialProtocol::DialDisconnectButtonClickedEventArgs>{ using type = class_category; };
template <> struct category<Windows::Media::DialProtocol::DialReceiverApp>{ using type = class_category; };
template <> struct category<Windows::Media::DialProtocol::DialAppLaunchResult>{ using type = enum_category; };
template <> struct category<Windows::Media::DialProtocol::DialAppState>{ using type = enum_category; };
template <> struct category<Windows::Media::DialProtocol::DialAppStopResult>{ using type = enum_category; };
template <> struct category<Windows::Media::DialProtocol::DialDeviceDisplayStatus>{ using type = enum_category; };
template <> struct name<Windows::Media::DialProtocol::IDialApp>{ static constexpr auto & value{ L"Windows.Media.DialProtocol.IDialApp" }; };
template <> struct name<Windows::Media::DialProtocol::IDialAppStateDetails>{ static constexpr auto & value{ L"Windows.Media.DialProtocol.IDialAppStateDetails" }; };
template <> struct name<Windows::Media::DialProtocol::IDialDevice>{ static constexpr auto & value{ L"Windows.Media.DialProtocol.IDialDevice" }; };
template <> struct name<Windows::Media::DialProtocol::IDialDevice2>{ static constexpr auto & value{ L"Windows.Media.DialProtocol.IDialDevice2" }; };
template <> struct name<Windows::Media::DialProtocol::IDialDevicePicker>{ static constexpr auto & value{ L"Windows.Media.DialProtocol.IDialDevicePicker" }; };
template <> struct name<Windows::Media::DialProtocol::IDialDevicePickerFilter>{ static constexpr auto & value{ L"Windows.Media.DialProtocol.IDialDevicePickerFilter" }; };
template <> struct name<Windows::Media::DialProtocol::IDialDeviceSelectedEventArgs>{ static constexpr auto & value{ L"Windows.Media.DialProtocol.IDialDeviceSelectedEventArgs" }; };
template <> struct name<Windows::Media::DialProtocol::IDialDeviceStatics>{ static constexpr auto & value{ L"Windows.Media.DialProtocol.IDialDeviceStatics" }; };
template <> struct name<Windows::Media::DialProtocol::IDialDisconnectButtonClickedEventArgs>{ static constexpr auto & value{ L"Windows.Media.DialProtocol.IDialDisconnectButtonClickedEventArgs" }; };
template <> struct name<Windows::Media::DialProtocol::IDialReceiverApp>{ static constexpr auto & value{ L"Windows.Media.DialProtocol.IDialReceiverApp" }; };
template <> struct name<Windows::Media::DialProtocol::IDialReceiverApp2>{ static constexpr auto & value{ L"Windows.Media.DialProtocol.IDialReceiverApp2" }; };
template <> struct name<Windows::Media::DialProtocol::IDialReceiverAppStatics>{ static constexpr auto & value{ L"Windows.Media.DialProtocol.IDialReceiverAppStatics" }; };
template <> struct name<Windows::Media::DialProtocol::DialApp>{ static constexpr auto & value{ L"Windows.Media.DialProtocol.DialApp" }; };
template <> struct name<Windows::Media::DialProtocol::DialAppStateDetails>{ static constexpr auto & value{ L"Windows.Media.DialProtocol.DialAppStateDetails" }; };
template <> struct name<Windows::Media::DialProtocol::DialDevice>{ static constexpr auto & value{ L"Windows.Media.DialProtocol.DialDevice" }; };
template <> struct name<Windows::Media::DialProtocol::DialDevicePicker>{ static constexpr auto & value{ L"Windows.Media.DialProtocol.DialDevicePicker" }; };
template <> struct name<Windows::Media::DialProtocol::DialDevicePickerFilter>{ static constexpr auto & value{ L"Windows.Media.DialProtocol.DialDevicePickerFilter" }; };
template <> struct name<Windows::Media::DialProtocol::DialDeviceSelectedEventArgs>{ static constexpr auto & value{ L"Windows.Media.DialProtocol.DialDeviceSelectedEventArgs" }; };
template <> struct name<Windows::Media::DialProtocol::DialDisconnectButtonClickedEventArgs>{ static constexpr auto & value{ L"Windows.Media.DialProtocol.DialDisconnectButtonClickedEventArgs" }; };
template <> struct name<Windows::Media::DialProtocol::DialReceiverApp>{ static constexpr auto & value{ L"Windows.Media.DialProtocol.DialReceiverApp" }; };
template <> struct name<Windows::Media::DialProtocol::DialAppLaunchResult>{ static constexpr auto & value{ L"Windows.Media.DialProtocol.DialAppLaunchResult" }; };
template <> struct name<Windows::Media::DialProtocol::DialAppState>{ static constexpr auto & value{ L"Windows.Media.DialProtocol.DialAppState" }; };
template <> struct name<Windows::Media::DialProtocol::DialAppStopResult>{ static constexpr auto & value{ L"Windows.Media.DialProtocol.DialAppStopResult" }; };
template <> struct name<Windows::Media::DialProtocol::DialDeviceDisplayStatus>{ static constexpr auto & value{ L"Windows.Media.DialProtocol.DialDeviceDisplayStatus" }; };
template <> struct guid_storage<Windows::Media::DialProtocol::IDialApp>{ static constexpr guid value{ 0x555FFBD3,0x45B7,0x49F3,{ 0xBB,0xD7,0x30,0x2D,0xB6,0x08,0x46,0x46 } }; };
template <> struct guid_storage<Windows::Media::DialProtocol::IDialAppStateDetails>{ static constexpr guid value{ 0xDDC4A4A1,0xF5DE,0x400D,{ 0xBE,0xA4,0x8C,0x84,0x66,0xBB,0x29,0x61 } }; };
template <> struct guid_storage<Windows::Media::DialProtocol::IDialDevice>{ static constexpr guid value{ 0xFFF0EDAF,0x759F,0x41D2,{ 0xA2,0x0A,0x7F,0x29,0xCE,0x0B,0x37,0x84 } }; };
template <> struct guid_storage<Windows::Media::DialProtocol::IDialDevice2>{ static constexpr guid value{ 0xBAB7F3D5,0x5BFB,0x4EBA,{ 0x8B,0x32,0xB5,0x7C,0x5C,0x5E,0xE5,0xC9 } }; };
template <> struct guid_storage<Windows::Media::DialProtocol::IDialDevicePicker>{ static constexpr guid value{ 0xBA7E520A,0xFF59,0x4F4B,{ 0xBD,0xAC,0xD8,0x9F,0x49,0x5A,0xD6,0xE1 } }; };
template <> struct guid_storage<Windows::Media::DialProtocol::IDialDevicePickerFilter>{ static constexpr guid value{ 0xC17C93BA,0x86C0,0x485D,{ 0xB8,0xD6,0x0F,0x9A,0x8F,0x64,0x15,0x90 } }; };
template <> struct guid_storage<Windows::Media::DialProtocol::IDialDeviceSelectedEventArgs>{ static constexpr guid value{ 0x480B92AD,0xAC76,0x47EB,{ 0x9C,0x06,0xA1,0x93,0x04,0xDA,0x02,0x47 } }; };
template <> struct guid_storage<Windows::Media::DialProtocol::IDialDeviceStatics>{ static constexpr guid value{ 0xAA69CC95,0x01F8,0x4758,{ 0x84,0x61,0x2B,0xBD,0x1C,0xDC,0x3C,0xF3 } }; };
template <> struct guid_storage<Windows::Media::DialProtocol::IDialDisconnectButtonClickedEventArgs>{ static constexpr guid value{ 0x52765152,0x9C81,0x4E55,{ 0xAD,0xC2,0x0E,0xBE,0x99,0xCD,0xE3,0xB6 } }; };
template <> struct guid_storage<Windows::Media::DialProtocol::IDialReceiverApp>{ static constexpr guid value{ 0xFD3E7C57,0x5045,0x470E,{ 0xB3,0x04,0x4D,0xD9,0xB1,0x3E,0x7D,0x11 } }; };
template <> struct guid_storage<Windows::Media::DialProtocol::IDialReceiverApp2>{ static constexpr guid value{ 0x530C5805,0x9130,0x42AC,{ 0xA5,0x04,0x19,0x77,0xDC,0xB2,0xEA,0x8A } }; };
template <> struct guid_storage<Windows::Media::DialProtocol::IDialReceiverAppStatics>{ static constexpr guid value{ 0x53183A3C,0x4C36,0x4D02,{ 0xB2,0x8A,0xF2,0xA9,0xDA,0x38,0xEC,0x52 } }; };
template <> struct default_interface<Windows::Media::DialProtocol::DialApp>{ using type = Windows::Media::DialProtocol::IDialApp; };
template <> struct default_interface<Windows::Media::DialProtocol::DialAppStateDetails>{ using type = Windows::Media::DialProtocol::IDialAppStateDetails; };
template <> struct default_interface<Windows::Media::DialProtocol::DialDevice>{ using type = Windows::Media::DialProtocol::IDialDevice; };
template <> struct default_interface<Windows::Media::DialProtocol::DialDevicePicker>{ using type = Windows::Media::DialProtocol::IDialDevicePicker; };
template <> struct default_interface<Windows::Media::DialProtocol::DialDevicePickerFilter>{ using type = Windows::Media::DialProtocol::IDialDevicePickerFilter; };
template <> struct default_interface<Windows::Media::DialProtocol::DialDeviceSelectedEventArgs>{ using type = Windows::Media::DialProtocol::IDialDeviceSelectedEventArgs; };
template <> struct default_interface<Windows::Media::DialProtocol::DialDisconnectButtonClickedEventArgs>{ using type = Windows::Media::DialProtocol::IDialDisconnectButtonClickedEventArgs; };
template <> struct default_interface<Windows::Media::DialProtocol::DialReceiverApp>{ using type = Windows::Media::DialProtocol::IDialReceiverApp; };

template <> struct abi<Windows::Media::DialProtocol::IDialApp>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL get_AppName(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL RequestLaunchAsync(void* appArgument, void** value) noexcept = 0;
    virtual int32_t WINRT_CALL StopAsync(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL GetAppStateAsync(void** value) noexcept = 0;
};};

template <> struct abi<Windows::Media::DialProtocol::IDialAppStateDetails>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL get_State(Windows::Media::DialProtocol::DialAppState* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_FullXml(void** value) noexcept = 0;
};};

template <> struct abi<Windows::Media::DialProtocol::IDialDevice>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL get_Id(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL GetDialApp(void* appName, void** value) noexcept = 0;
};};

template <> struct abi<Windows::Media::DialProtocol::IDialDevice2>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL get_FriendlyName(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_Thumbnail(void** value) noexcept = 0;
};};

template <> struct abi<Windows::Media::DialProtocol::IDialDevicePicker>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL get_Filter(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_Appearance(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL add_DialDeviceSelected(void* handler, winrt::event_token* token) noexcept = 0;
    virtual int32_t WINRT_CALL remove_DialDeviceSelected(winrt::event_token token) noexcept = 0;
    virtual int32_t WINRT_CALL add_DisconnectButtonClicked(void* handler, winrt::event_token* token) noexcept = 0;
    virtual int32_t WINRT_CALL remove_DisconnectButtonClicked(winrt::event_token token) noexcept = 0;
    virtual int32_t WINRT_CALL add_DialDevicePickerDismissed(void* handler, winrt::event_token* token) noexcept = 0;
    virtual int32_t WINRT_CALL remove_DialDevicePickerDismissed(winrt::event_token token) noexcept = 0;
    virtual int32_t WINRT_CALL Show(Windows::Foundation::Rect selection) noexcept = 0;
    virtual int32_t WINRT_CALL ShowWithPlacement(Windows::Foundation::Rect selection, Windows::UI::Popups::Placement preferredPlacement) noexcept = 0;
    virtual int32_t WINRT_CALL PickSingleDialDeviceAsync(Windows::Foundation::Rect selection, void** operation) noexcept = 0;
    virtual int32_t WINRT_CALL PickSingleDialDeviceAsyncWithPlacement(Windows::Foundation::Rect selection, Windows::UI::Popups::Placement preferredPlacement, void** operation) noexcept = 0;
    virtual int32_t WINRT_CALL Hide() noexcept = 0;
    virtual int32_t WINRT_CALL SetDisplayStatus(void* device, Windows::Media::DialProtocol::DialDeviceDisplayStatus status) noexcept = 0;
};};

template <> struct abi<Windows::Media::DialProtocol::IDialDevicePickerFilter>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL get_SupportedAppNames(void** value) noexcept = 0;
};};

template <> struct abi<Windows::Media::DialProtocol::IDialDeviceSelectedEventArgs>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL get_SelectedDialDevice(void** value) noexcept = 0;
};};

template <> struct abi<Windows::Media::DialProtocol::IDialDeviceStatics>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL GetDeviceSelector(void* appName, void** selector) noexcept = 0;
    virtual int32_t WINRT_CALL FromIdAsync(void* value, void** operation) noexcept = 0;
    virtual int32_t WINRT_CALL DeviceInfoSupportsDialAsync(void* device, void** operation) noexcept = 0;
};};

template <> struct abi<Windows::Media::DialProtocol::IDialDisconnectButtonClickedEventArgs>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL get_Device(void** value) noexcept = 0;
};};

template <> struct abi<Windows::Media::DialProtocol::IDialReceiverApp>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL GetAdditionalDataAsync(void** operation) noexcept = 0;
    virtual int32_t WINRT_CALL SetAdditionalDataAsync(void* additionalData, void** operation) noexcept = 0;
};};

template <> struct abi<Windows::Media::DialProtocol::IDialReceiverApp2>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL GetUniqueDeviceNameAsync(void** operation) noexcept = 0;
};};

template <> struct abi<Windows::Media::DialProtocol::IDialReceiverAppStatics>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL get_Current(void** value) noexcept = 0;
};};

template <typename D>
struct consume_Windows_Media_DialProtocol_IDialApp
{
    hstring AppName() const;
    Windows::Foundation::IAsyncOperation<Windows::Media::DialProtocol::DialAppLaunchResult> RequestLaunchAsync(param::hstring const& appArgument) const;
    Windows::Foundation::IAsyncOperation<Windows::Media::DialProtocol::DialAppStopResult> StopAsync() const;
    Windows::Foundation::IAsyncOperation<Windows::Media::DialProtocol::DialAppStateDetails> GetAppStateAsync() const;
};
template <> struct consume<Windows::Media::DialProtocol::IDialApp> { template <typename D> using type = consume_Windows_Media_DialProtocol_IDialApp<D>; };

template <typename D>
struct consume_Windows_Media_DialProtocol_IDialAppStateDetails
{
    Windows::Media::DialProtocol::DialAppState State() const;
    hstring FullXml() const;
};
template <> struct consume<Windows::Media::DialProtocol::IDialAppStateDetails> { template <typename D> using type = consume_Windows_Media_DialProtocol_IDialAppStateDetails<D>; };

template <typename D>
struct consume_Windows_Media_DialProtocol_IDialDevice
{
    hstring Id() const;
    Windows::Media::DialProtocol::DialApp GetDialApp(param::hstring const& appName) const;
};
template <> struct consume<Windows::Media::DialProtocol::IDialDevice> { template <typename D> using type = consume_Windows_Media_DialProtocol_IDialDevice<D>; };

template <typename D>
struct consume_Windows_Media_DialProtocol_IDialDevice2
{
    hstring FriendlyName() const;
    Windows::Storage::Streams::IRandomAccessStreamReference Thumbnail() const;
};
template <> struct consume<Windows::Media::DialProtocol::IDialDevice2> { template <typename D> using type = consume_Windows_Media_DialProtocol_IDialDevice2<D>; };

template <typename D>
struct consume_Windows_Media_DialProtocol_IDialDevicePicker
{
    Windows::Media::DialProtocol::DialDevicePickerFilter Filter() const;
    Windows::Devices::Enumeration::DevicePickerAppearance Appearance() const;
    winrt::event_token DialDeviceSelected(Windows::Foundation::TypedEventHandler<Windows::Media::DialProtocol::DialDevicePicker, Windows::Media::DialProtocol::DialDeviceSelectedEventArgs> const& handler) const;
    using DialDeviceSelected_revoker = impl::event_revoker<Windows::Media::DialProtocol::IDialDevicePicker, &impl::abi_t<Windows::Media::DialProtocol::IDialDevicePicker>::remove_DialDeviceSelected>;
    DialDeviceSelected_revoker DialDeviceSelected(auto_revoke_t, Windows::Foundation::TypedEventHandler<Windows::Media::DialProtocol::DialDevicePicker, Windows::Media::DialProtocol::DialDeviceSelectedEventArgs> const& handler) const;
    void DialDeviceSelected(winrt::event_token const& token) const noexcept;
    winrt::event_token DisconnectButtonClicked(Windows::Foundation::TypedEventHandler<Windows::Media::DialProtocol::DialDevicePicker, Windows::Media::DialProtocol::DialDisconnectButtonClickedEventArgs> const& handler) const;
    using DisconnectButtonClicked_revoker = impl::event_revoker<Windows::Media::DialProtocol::IDialDevicePicker, &impl::abi_t<Windows::Media::DialProtocol::IDialDevicePicker>::remove_DisconnectButtonClicked>;
    DisconnectButtonClicked_revoker DisconnectButtonClicked(auto_revoke_t, Windows::Foundation::TypedEventHandler<Windows::Media::DialProtocol::DialDevicePicker, Windows::Media::DialProtocol::DialDisconnectButtonClickedEventArgs> const& handler) const;
    void DisconnectButtonClicked(winrt::event_token const& token) const noexcept;
    winrt::event_token DialDevicePickerDismissed(Windows::Foundation::TypedEventHandler<Windows::Media::DialProtocol::DialDevicePicker, Windows::Foundation::IInspectable> const& handler) const;
    using DialDevicePickerDismissed_revoker = impl::event_revoker<Windows::Media::DialProtocol::IDialDevicePicker, &impl::abi_t<Windows::Media::DialProtocol::IDialDevicePicker>::remove_DialDevicePickerDismissed>;
    DialDevicePickerDismissed_revoker DialDevicePickerDismissed(auto_revoke_t, Windows::Foundation::TypedEventHandler<Windows::Media::DialProtocol::DialDevicePicker, Windows::Foundation::IInspectable> const& handler) const;
    void DialDevicePickerDismissed(winrt::event_token const& token) const noexcept;
    void Show(Windows::Foundation::Rect const& selection) const;
    void Show(Windows::Foundation::Rect const& selection, Windows::UI::Popups::Placement const& preferredPlacement) const;
    Windows::Foundation::IAsyncOperation<Windows::Media::DialProtocol::DialDevice> PickSingleDialDeviceAsync(Windows::Foundation::Rect const& selection) const;
    Windows::Foundation::IAsyncOperation<Windows::Media::DialProtocol::DialDevice> PickSingleDialDeviceAsync(Windows::Foundation::Rect const& selection, Windows::UI::Popups::Placement const& preferredPlacement) const;
    void Hide() const;
    void SetDisplayStatus(Windows::Media::DialProtocol::DialDevice const& device, Windows::Media::DialProtocol::DialDeviceDisplayStatus const& status) const;
};
template <> struct consume<Windows::Media::DialProtocol::IDialDevicePicker> { template <typename D> using type = consume_Windows_Media_DialProtocol_IDialDevicePicker<D>; };

template <typename D>
struct consume_Windows_Media_DialProtocol_IDialDevicePickerFilter
{
    Windows::Foundation::Collections::IVector<hstring> SupportedAppNames() const;
};
template <> struct consume<Windows::Media::DialProtocol::IDialDevicePickerFilter> { template <typename D> using type = consume_Windows_Media_DialProtocol_IDialDevicePickerFilter<D>; };

template <typename D>
struct consume_Windows_Media_DialProtocol_IDialDeviceSelectedEventArgs
{
    Windows::Media::DialProtocol::DialDevice SelectedDialDevice() const;
};
template <> struct consume<Windows::Media::DialProtocol::IDialDeviceSelectedEventArgs> { template <typename D> using type = consume_Windows_Media_DialProtocol_IDialDeviceSelectedEventArgs<D>; };

template <typename D>
struct consume_Windows_Media_DialProtocol_IDialDeviceStatics
{
    hstring GetDeviceSelector(param::hstring const& appName) const;
    Windows::Foundation::IAsyncOperation<Windows::Media::DialProtocol::DialDevice> FromIdAsync(param::hstring const& value) const;
    Windows::Foundation::IAsyncOperation<bool> DeviceInfoSupportsDialAsync(Windows::Devices::Enumeration::DeviceInformation const& device) const;
};
template <> struct consume<Windows::Media::DialProtocol::IDialDeviceStatics> { template <typename D> using type = consume_Windows_Media_DialProtocol_IDialDeviceStatics<D>; };

template <typename D>
struct consume_Windows_Media_DialProtocol_IDialDisconnectButtonClickedEventArgs
{
    Windows::Media::DialProtocol::DialDevice Device() const;
};
template <> struct consume<Windows::Media::DialProtocol::IDialDisconnectButtonClickedEventArgs> { template <typename D> using type = consume_Windows_Media_DialProtocol_IDialDisconnectButtonClickedEventArgs<D>; };

template <typename D>
struct consume_Windows_Media_DialProtocol_IDialReceiverApp
{
    Windows::Foundation::IAsyncOperation<Windows::Foundation::Collections::IMap<hstring, hstring>> GetAdditionalDataAsync() const;
    Windows::Foundation::IAsyncAction SetAdditionalDataAsync(param::async_iterable<Windows::Foundation::Collections::IKeyValuePair<hstring, hstring>> const& additionalData) const;
};
template <> struct consume<Windows::Media::DialProtocol::IDialReceiverApp> { template <typename D> using type = consume_Windows_Media_DialProtocol_IDialReceiverApp<D>; };

template <typename D>
struct consume_Windows_Media_DialProtocol_IDialReceiverApp2
{
    Windows::Foundation::IAsyncOperation<hstring> GetUniqueDeviceNameAsync() const;
};
template <> struct consume<Windows::Media::DialProtocol::IDialReceiverApp2> { template <typename D> using type = consume_Windows_Media_DialProtocol_IDialReceiverApp2<D>; };

template <typename D>
struct consume_Windows_Media_DialProtocol_IDialReceiverAppStatics
{
    Windows::Media::DialProtocol::DialReceiverApp Current() const;
};
template <> struct consume<Windows::Media::DialProtocol::IDialReceiverAppStatics> { template <typename D> using type = consume_Windows_Media_DialProtocol_IDialReceiverAppStatics<D>; };

}
