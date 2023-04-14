// C++/WinRT v1.0.190111.3

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#pragma once

WINRT_EXPORT namespace winrt::Windows::Devices::Enumeration {

struct DeviceInformation;
struct DevicePickerAppearance;

}

WINRT_EXPORT namespace winrt::Windows::Foundation {

struct Uri;

}

WINRT_EXPORT namespace winrt::Windows::Storage::Streams {

struct IRandomAccessStreamWithContentType;

}

WINRT_EXPORT namespace winrt::Windows::UI::Popups {

enum class Placement;

}

WINRT_EXPORT namespace winrt::Windows::Media::Casting {

enum class CastingConnectionErrorStatus : int32_t
{
    Succeeded = 0,
    DeviceDidNotRespond = 1,
    DeviceError = 2,
    DeviceLocked = 3,
    ProtectedPlaybackFailed = 4,
    InvalidCastingSource = 5,
    Unknown = 6,
};

enum class CastingConnectionState : int32_t
{
    Disconnected = 0,
    Connected = 1,
    Rendering = 2,
    Disconnecting = 3,
    Connecting = 4,
};

enum class CastingPlaybackTypes : uint32_t
{
    None = 0x0,
    Audio = 0x1,
    Video = 0x2,
    Picture = 0x4,
};

struct ICastingConnection;
struct ICastingConnectionErrorOccurredEventArgs;
struct ICastingDevice;
struct ICastingDevicePicker;
struct ICastingDevicePickerFilter;
struct ICastingDeviceSelectedEventArgs;
struct ICastingDeviceStatics;
struct ICastingSource;
struct CastingConnection;
struct CastingConnectionErrorOccurredEventArgs;
struct CastingDevice;
struct CastingDevicePicker;
struct CastingDevicePickerFilter;
struct CastingDeviceSelectedEventArgs;
struct CastingSource;

}

namespace winrt::impl {

template<> struct is_enum_flag<Windows::Media::Casting::CastingPlaybackTypes> : std::true_type {};
template <> struct category<Windows::Media::Casting::ICastingConnection>{ using type = interface_category; };
template <> struct category<Windows::Media::Casting::ICastingConnectionErrorOccurredEventArgs>{ using type = interface_category; };
template <> struct category<Windows::Media::Casting::ICastingDevice>{ using type = interface_category; };
template <> struct category<Windows::Media::Casting::ICastingDevicePicker>{ using type = interface_category; };
template <> struct category<Windows::Media::Casting::ICastingDevicePickerFilter>{ using type = interface_category; };
template <> struct category<Windows::Media::Casting::ICastingDeviceSelectedEventArgs>{ using type = interface_category; };
template <> struct category<Windows::Media::Casting::ICastingDeviceStatics>{ using type = interface_category; };
template <> struct category<Windows::Media::Casting::ICastingSource>{ using type = interface_category; };
template <> struct category<Windows::Media::Casting::CastingConnection>{ using type = class_category; };
template <> struct category<Windows::Media::Casting::CastingConnectionErrorOccurredEventArgs>{ using type = class_category; };
template <> struct category<Windows::Media::Casting::CastingDevice>{ using type = class_category; };
template <> struct category<Windows::Media::Casting::CastingDevicePicker>{ using type = class_category; };
template <> struct category<Windows::Media::Casting::CastingDevicePickerFilter>{ using type = class_category; };
template <> struct category<Windows::Media::Casting::CastingDeviceSelectedEventArgs>{ using type = class_category; };
template <> struct category<Windows::Media::Casting::CastingSource>{ using type = class_category; };
template <> struct category<Windows::Media::Casting::CastingConnectionErrorStatus>{ using type = enum_category; };
template <> struct category<Windows::Media::Casting::CastingConnectionState>{ using type = enum_category; };
template <> struct category<Windows::Media::Casting::CastingPlaybackTypes>{ using type = enum_category; };
template <> struct name<Windows::Media::Casting::ICastingConnection>{ static constexpr auto & value{ L"Windows.Media.Casting.ICastingConnection" }; };
template <> struct name<Windows::Media::Casting::ICastingConnectionErrorOccurredEventArgs>{ static constexpr auto & value{ L"Windows.Media.Casting.ICastingConnectionErrorOccurredEventArgs" }; };
template <> struct name<Windows::Media::Casting::ICastingDevice>{ static constexpr auto & value{ L"Windows.Media.Casting.ICastingDevice" }; };
template <> struct name<Windows::Media::Casting::ICastingDevicePicker>{ static constexpr auto & value{ L"Windows.Media.Casting.ICastingDevicePicker" }; };
template <> struct name<Windows::Media::Casting::ICastingDevicePickerFilter>{ static constexpr auto & value{ L"Windows.Media.Casting.ICastingDevicePickerFilter" }; };
template <> struct name<Windows::Media::Casting::ICastingDeviceSelectedEventArgs>{ static constexpr auto & value{ L"Windows.Media.Casting.ICastingDeviceSelectedEventArgs" }; };
template <> struct name<Windows::Media::Casting::ICastingDeviceStatics>{ static constexpr auto & value{ L"Windows.Media.Casting.ICastingDeviceStatics" }; };
template <> struct name<Windows::Media::Casting::ICastingSource>{ static constexpr auto & value{ L"Windows.Media.Casting.ICastingSource" }; };
template <> struct name<Windows::Media::Casting::CastingConnection>{ static constexpr auto & value{ L"Windows.Media.Casting.CastingConnection" }; };
template <> struct name<Windows::Media::Casting::CastingConnectionErrorOccurredEventArgs>{ static constexpr auto & value{ L"Windows.Media.Casting.CastingConnectionErrorOccurredEventArgs" }; };
template <> struct name<Windows::Media::Casting::CastingDevice>{ static constexpr auto & value{ L"Windows.Media.Casting.CastingDevice" }; };
template <> struct name<Windows::Media::Casting::CastingDevicePicker>{ static constexpr auto & value{ L"Windows.Media.Casting.CastingDevicePicker" }; };
template <> struct name<Windows::Media::Casting::CastingDevicePickerFilter>{ static constexpr auto & value{ L"Windows.Media.Casting.CastingDevicePickerFilter" }; };
template <> struct name<Windows::Media::Casting::CastingDeviceSelectedEventArgs>{ static constexpr auto & value{ L"Windows.Media.Casting.CastingDeviceSelectedEventArgs" }; };
template <> struct name<Windows::Media::Casting::CastingSource>{ static constexpr auto & value{ L"Windows.Media.Casting.CastingSource" }; };
template <> struct name<Windows::Media::Casting::CastingConnectionErrorStatus>{ static constexpr auto & value{ L"Windows.Media.Casting.CastingConnectionErrorStatus" }; };
template <> struct name<Windows::Media::Casting::CastingConnectionState>{ static constexpr auto & value{ L"Windows.Media.Casting.CastingConnectionState" }; };
template <> struct name<Windows::Media::Casting::CastingPlaybackTypes>{ static constexpr auto & value{ L"Windows.Media.Casting.CastingPlaybackTypes" }; };
template <> struct guid_storage<Windows::Media::Casting::ICastingConnection>{ static constexpr guid value{ 0xCD951653,0xC2F1,0x4498,{ 0x8B,0x78,0x5F,0xB4,0xCD,0x36,0x40,0xDD } }; };
template <> struct guid_storage<Windows::Media::Casting::ICastingConnectionErrorOccurredEventArgs>{ static constexpr guid value{ 0xA7FB3C69,0x8719,0x4F00,{ 0x81,0xFB,0x96,0x18,0x63,0xC7,0x9A,0x32 } }; };
template <> struct guid_storage<Windows::Media::Casting::ICastingDevice>{ static constexpr guid value{ 0xDE721C83,0x4A43,0x4AD1,{ 0xA6,0xD2,0x24,0x92,0xA7,0x96,0xC3,0xF2 } }; };
template <> struct guid_storage<Windows::Media::Casting::ICastingDevicePicker>{ static constexpr guid value{ 0xDCD39924,0x0591,0x49BE,{ 0xAA,0xCB,0x4B,0x82,0xEE,0x75,0x6A,0x95 } }; };
template <> struct guid_storage<Windows::Media::Casting::ICastingDevicePickerFilter>{ static constexpr guid value{ 0xBE8C619C,0xB563,0x4354,{ 0xAE,0x33,0x9F,0xDA,0xAD,0x8C,0x62,0x91 } }; };
template <> struct guid_storage<Windows::Media::Casting::ICastingDeviceSelectedEventArgs>{ static constexpr guid value{ 0xDC439E86,0xDD57,0x4D0D,{ 0x94,0x00,0xAF,0x45,0xE4,0xFB,0x36,0x63 } }; };
template <> struct guid_storage<Windows::Media::Casting::ICastingDeviceStatics>{ static constexpr guid value{ 0xE7D958D7,0x4D13,0x4237,{ 0xA3,0x65,0x4C,0x4F,0x6A,0x4C,0xFD,0x2F } }; };
template <> struct guid_storage<Windows::Media::Casting::ICastingSource>{ static constexpr guid value{ 0xF429EA72,0x3467,0x47E6,{ 0xA0,0x27,0x52,0x29,0x23,0xE9,0xD7,0x27 } }; };
template <> struct default_interface<Windows::Media::Casting::CastingConnection>{ using type = Windows::Media::Casting::ICastingConnection; };
template <> struct default_interface<Windows::Media::Casting::CastingConnectionErrorOccurredEventArgs>{ using type = Windows::Media::Casting::ICastingConnectionErrorOccurredEventArgs; };
template <> struct default_interface<Windows::Media::Casting::CastingDevice>{ using type = Windows::Media::Casting::ICastingDevice; };
template <> struct default_interface<Windows::Media::Casting::CastingDevicePicker>{ using type = Windows::Media::Casting::ICastingDevicePicker; };
template <> struct default_interface<Windows::Media::Casting::CastingDevicePickerFilter>{ using type = Windows::Media::Casting::ICastingDevicePickerFilter; };
template <> struct default_interface<Windows::Media::Casting::CastingDeviceSelectedEventArgs>{ using type = Windows::Media::Casting::ICastingDeviceSelectedEventArgs; };
template <> struct default_interface<Windows::Media::Casting::CastingSource>{ using type = Windows::Media::Casting::ICastingSource; };

template <> struct abi<Windows::Media::Casting::ICastingConnection>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL get_State(Windows::Media::Casting::CastingConnectionState* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_Device(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_Source(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL put_Source(void* value) noexcept = 0;
    virtual int32_t WINRT_CALL add_StateChanged(void* handler, winrt::event_token* token) noexcept = 0;
    virtual int32_t WINRT_CALL remove_StateChanged(winrt::event_token token) noexcept = 0;
    virtual int32_t WINRT_CALL add_ErrorOccurred(void* handler, winrt::event_token* token) noexcept = 0;
    virtual int32_t WINRT_CALL remove_ErrorOccurred(winrt::event_token token) noexcept = 0;
    virtual int32_t WINRT_CALL RequestStartCastingAsync(void* value, void** operation) noexcept = 0;
    virtual int32_t WINRT_CALL DisconnectAsync(void** operation) noexcept = 0;
};};

template <> struct abi<Windows::Media::Casting::ICastingConnectionErrorOccurredEventArgs>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL get_ErrorStatus(Windows::Media::Casting::CastingConnectionErrorStatus* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_Message(void** value) noexcept = 0;
};};

template <> struct abi<Windows::Media::Casting::ICastingDevice>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL get_Id(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_FriendlyName(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_Icon(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL GetSupportedCastingPlaybackTypesAsync(void** operation) noexcept = 0;
    virtual int32_t WINRT_CALL CreateCastingConnection(void** value) noexcept = 0;
};};

template <> struct abi<Windows::Media::Casting::ICastingDevicePicker>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL get_Filter(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_Appearance(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL add_CastingDeviceSelected(void* handler, winrt::event_token* token) noexcept = 0;
    virtual int32_t WINRT_CALL remove_CastingDeviceSelected(winrt::event_token token) noexcept = 0;
    virtual int32_t WINRT_CALL add_CastingDevicePickerDismissed(void* handler, winrt::event_token* token) noexcept = 0;
    virtual int32_t WINRT_CALL remove_CastingDevicePickerDismissed(winrt::event_token token) noexcept = 0;
    virtual int32_t WINRT_CALL Show(Windows::Foundation::Rect selection) noexcept = 0;
    virtual int32_t WINRT_CALL ShowWithPlacement(Windows::Foundation::Rect selection, Windows::UI::Popups::Placement preferredPlacement) noexcept = 0;
    virtual int32_t WINRT_CALL Hide() noexcept = 0;
};};

template <> struct abi<Windows::Media::Casting::ICastingDevicePickerFilter>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL get_SupportsAudio(bool* value) noexcept = 0;
    virtual int32_t WINRT_CALL put_SupportsAudio(bool value) noexcept = 0;
    virtual int32_t WINRT_CALL get_SupportsVideo(bool* value) noexcept = 0;
    virtual int32_t WINRT_CALL put_SupportsVideo(bool value) noexcept = 0;
    virtual int32_t WINRT_CALL get_SupportsPictures(bool* value) noexcept = 0;
    virtual int32_t WINRT_CALL put_SupportsPictures(bool value) noexcept = 0;
    virtual int32_t WINRT_CALL get_SupportedCastingSources(void** value) noexcept = 0;
};};

template <> struct abi<Windows::Media::Casting::ICastingDeviceSelectedEventArgs>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL get_SelectedCastingDevice(void** value) noexcept = 0;
};};

template <> struct abi<Windows::Media::Casting::ICastingDeviceStatics>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL GetDeviceSelector(Windows::Media::Casting::CastingPlaybackTypes type, void** value) noexcept = 0;
    virtual int32_t WINRT_CALL GetDeviceSelectorFromCastingSourceAsync(void* castingSource, void** operation) noexcept = 0;
    virtual int32_t WINRT_CALL FromIdAsync(void* value, void** operation) noexcept = 0;
    virtual int32_t WINRT_CALL DeviceInfoSupportsCastingAsync(void* device, void** operation) noexcept = 0;
};};

template <> struct abi<Windows::Media::Casting::ICastingSource>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL get_PreferredSourceUri(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL put_PreferredSourceUri(void* value) noexcept = 0;
};};

template <typename D>
struct consume_Windows_Media_Casting_ICastingConnection
{
    Windows::Media::Casting::CastingConnectionState State() const;
    Windows::Media::Casting::CastingDevice Device() const;
    Windows::Media::Casting::CastingSource Source() const;
    void Source(Windows::Media::Casting::CastingSource const& value) const;
    winrt::event_token StateChanged(Windows::Foundation::TypedEventHandler<Windows::Media::Casting::CastingConnection, Windows::Foundation::IInspectable> const& handler) const;
    using StateChanged_revoker = impl::event_revoker<Windows::Media::Casting::ICastingConnection, &impl::abi_t<Windows::Media::Casting::ICastingConnection>::remove_StateChanged>;
    StateChanged_revoker StateChanged(auto_revoke_t, Windows::Foundation::TypedEventHandler<Windows::Media::Casting::CastingConnection, Windows::Foundation::IInspectable> const& handler) const;
    void StateChanged(winrt::event_token const& token) const noexcept;
    winrt::event_token ErrorOccurred(Windows::Foundation::TypedEventHandler<Windows::Media::Casting::CastingConnection, Windows::Media::Casting::CastingConnectionErrorOccurredEventArgs> const& handler) const;
    using ErrorOccurred_revoker = impl::event_revoker<Windows::Media::Casting::ICastingConnection, &impl::abi_t<Windows::Media::Casting::ICastingConnection>::remove_ErrorOccurred>;
    ErrorOccurred_revoker ErrorOccurred(auto_revoke_t, Windows::Foundation::TypedEventHandler<Windows::Media::Casting::CastingConnection, Windows::Media::Casting::CastingConnectionErrorOccurredEventArgs> const& handler) const;
    void ErrorOccurred(winrt::event_token const& token) const noexcept;
    Windows::Foundation::IAsyncOperation<Windows::Media::Casting::CastingConnectionErrorStatus> RequestStartCastingAsync(Windows::Media::Casting::CastingSource const& value) const;
    Windows::Foundation::IAsyncOperation<Windows::Media::Casting::CastingConnectionErrorStatus> DisconnectAsync() const;
};
template <> struct consume<Windows::Media::Casting::ICastingConnection> { template <typename D> using type = consume_Windows_Media_Casting_ICastingConnection<D>; };

template <typename D>
struct consume_Windows_Media_Casting_ICastingConnectionErrorOccurredEventArgs
{
    Windows::Media::Casting::CastingConnectionErrorStatus ErrorStatus() const;
    hstring Message() const;
};
template <> struct consume<Windows::Media::Casting::ICastingConnectionErrorOccurredEventArgs> { template <typename D> using type = consume_Windows_Media_Casting_ICastingConnectionErrorOccurredEventArgs<D>; };

template <typename D>
struct consume_Windows_Media_Casting_ICastingDevice
{
    hstring Id() const;
    hstring FriendlyName() const;
    Windows::Storage::Streams::IRandomAccessStreamWithContentType Icon() const;
    Windows::Foundation::IAsyncOperation<Windows::Media::Casting::CastingPlaybackTypes> GetSupportedCastingPlaybackTypesAsync() const;
    Windows::Media::Casting::CastingConnection CreateCastingConnection() const;
};
template <> struct consume<Windows::Media::Casting::ICastingDevice> { template <typename D> using type = consume_Windows_Media_Casting_ICastingDevice<D>; };

template <typename D>
struct consume_Windows_Media_Casting_ICastingDevicePicker
{
    Windows::Media::Casting::CastingDevicePickerFilter Filter() const;
    Windows::Devices::Enumeration::DevicePickerAppearance Appearance() const;
    winrt::event_token CastingDeviceSelected(Windows::Foundation::TypedEventHandler<Windows::Media::Casting::CastingDevicePicker, Windows::Media::Casting::CastingDeviceSelectedEventArgs> const& handler) const;
    using CastingDeviceSelected_revoker = impl::event_revoker<Windows::Media::Casting::ICastingDevicePicker, &impl::abi_t<Windows::Media::Casting::ICastingDevicePicker>::remove_CastingDeviceSelected>;
    CastingDeviceSelected_revoker CastingDeviceSelected(auto_revoke_t, Windows::Foundation::TypedEventHandler<Windows::Media::Casting::CastingDevicePicker, Windows::Media::Casting::CastingDeviceSelectedEventArgs> const& handler) const;
    void CastingDeviceSelected(winrt::event_token const& token) const noexcept;
    winrt::event_token CastingDevicePickerDismissed(Windows::Foundation::TypedEventHandler<Windows::Media::Casting::CastingDevicePicker, Windows::Foundation::IInspectable> const& handler) const;
    using CastingDevicePickerDismissed_revoker = impl::event_revoker<Windows::Media::Casting::ICastingDevicePicker, &impl::abi_t<Windows::Media::Casting::ICastingDevicePicker>::remove_CastingDevicePickerDismissed>;
    CastingDevicePickerDismissed_revoker CastingDevicePickerDismissed(auto_revoke_t, Windows::Foundation::TypedEventHandler<Windows::Media::Casting::CastingDevicePicker, Windows::Foundation::IInspectable> const& handler) const;
    void CastingDevicePickerDismissed(winrt::event_token const& token) const noexcept;
    void Show(Windows::Foundation::Rect const& selection) const;
    void Show(Windows::Foundation::Rect const& selection, Windows::UI::Popups::Placement const& preferredPlacement) const;
    void Hide() const;
};
template <> struct consume<Windows::Media::Casting::ICastingDevicePicker> { template <typename D> using type = consume_Windows_Media_Casting_ICastingDevicePicker<D>; };

template <typename D>
struct consume_Windows_Media_Casting_ICastingDevicePickerFilter
{
    bool SupportsAudio() const;
    void SupportsAudio(bool value) const;
    bool SupportsVideo() const;
    void SupportsVideo(bool value) const;
    bool SupportsPictures() const;
    void SupportsPictures(bool value) const;
    Windows::Foundation::Collections::IVector<Windows::Media::Casting::CastingSource> SupportedCastingSources() const;
};
template <> struct consume<Windows::Media::Casting::ICastingDevicePickerFilter> { template <typename D> using type = consume_Windows_Media_Casting_ICastingDevicePickerFilter<D>; };

template <typename D>
struct consume_Windows_Media_Casting_ICastingDeviceSelectedEventArgs
{
    Windows::Media::Casting::CastingDevice SelectedCastingDevice() const;
};
template <> struct consume<Windows::Media::Casting::ICastingDeviceSelectedEventArgs> { template <typename D> using type = consume_Windows_Media_Casting_ICastingDeviceSelectedEventArgs<D>; };

template <typename D>
struct consume_Windows_Media_Casting_ICastingDeviceStatics
{
    hstring GetDeviceSelector(Windows::Media::Casting::CastingPlaybackTypes const& type) const;
    Windows::Foundation::IAsyncOperation<hstring> GetDeviceSelectorFromCastingSourceAsync(Windows::Media::Casting::CastingSource const& castingSource) const;
    Windows::Foundation::IAsyncOperation<Windows::Media::Casting::CastingDevice> FromIdAsync(param::hstring const& value) const;
    Windows::Foundation::IAsyncOperation<bool> DeviceInfoSupportsCastingAsync(Windows::Devices::Enumeration::DeviceInformation const& device) const;
};
template <> struct consume<Windows::Media::Casting::ICastingDeviceStatics> { template <typename D> using type = consume_Windows_Media_Casting_ICastingDeviceStatics<D>; };

template <typename D>
struct consume_Windows_Media_Casting_ICastingSource
{
    Windows::Foundation::Uri PreferredSourceUri() const;
    void PreferredSourceUri(Windows::Foundation::Uri const& value) const;
};
template <> struct consume<Windows::Media::Casting::ICastingSource> { template <typename D> using type = consume_Windows_Media_Casting_ICastingSource<D>; };

}
