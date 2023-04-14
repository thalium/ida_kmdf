// C++/WinRT v1.0.190111.3

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#pragma once

WINRT_EXPORT namespace winrt::Windows::System::Update {

enum class SystemUpdateAttentionRequiredReason : int32_t
{
    None = 0,
    NetworkRequired = 1,
    InsufficientDiskSpace = 2,
    InsufficientBattery = 3,
    UpdateBlocked = 4,
};

enum class SystemUpdateItemState : int32_t
{
    NotStarted = 0,
    Initializing = 1,
    Preparing = 2,
    Calculating = 3,
    Downloading = 4,
    Installing = 5,
    Completed = 6,
    RebootRequired = 7,
    Error = 8,
};

enum class SystemUpdateManagerState : int32_t
{
    Idle = 0,
    Detecting = 1,
    ReadyToDownload = 2,
    Downloading = 3,
    ReadyToInstall = 4,
    Installing = 5,
    RebootRequired = 6,
    ReadyToFinalize = 7,
    Finalizing = 8,
    Completed = 9,
    AttentionRequired = 10,
    Error = 11,
};

enum class SystemUpdateStartInstallAction : int32_t
{
    UpToReboot = 0,
    AllowReboot = 1,
};

struct ISystemUpdateItem;
struct ISystemUpdateLastErrorInfo;
struct ISystemUpdateManagerStatics;
struct SystemUpdateItem;
struct SystemUpdateLastErrorInfo;
struct SystemUpdateManager;

}

namespace winrt::impl {

template <> struct category<Windows::System::Update::ISystemUpdateItem>{ using type = interface_category; };
template <> struct category<Windows::System::Update::ISystemUpdateLastErrorInfo>{ using type = interface_category; };
template <> struct category<Windows::System::Update::ISystemUpdateManagerStatics>{ using type = interface_category; };
template <> struct category<Windows::System::Update::SystemUpdateItem>{ using type = class_category; };
template <> struct category<Windows::System::Update::SystemUpdateLastErrorInfo>{ using type = class_category; };
template <> struct category<Windows::System::Update::SystemUpdateManager>{ using type = class_category; };
template <> struct category<Windows::System::Update::SystemUpdateAttentionRequiredReason>{ using type = enum_category; };
template <> struct category<Windows::System::Update::SystemUpdateItemState>{ using type = enum_category; };
template <> struct category<Windows::System::Update::SystemUpdateManagerState>{ using type = enum_category; };
template <> struct category<Windows::System::Update::SystemUpdateStartInstallAction>{ using type = enum_category; };
template <> struct name<Windows::System::Update::ISystemUpdateItem>{ static constexpr auto & value{ L"Windows.System.Update.ISystemUpdateItem" }; };
template <> struct name<Windows::System::Update::ISystemUpdateLastErrorInfo>{ static constexpr auto & value{ L"Windows.System.Update.ISystemUpdateLastErrorInfo" }; };
template <> struct name<Windows::System::Update::ISystemUpdateManagerStatics>{ static constexpr auto & value{ L"Windows.System.Update.ISystemUpdateManagerStatics" }; };
template <> struct name<Windows::System::Update::SystemUpdateItem>{ static constexpr auto & value{ L"Windows.System.Update.SystemUpdateItem" }; };
template <> struct name<Windows::System::Update::SystemUpdateLastErrorInfo>{ static constexpr auto & value{ L"Windows.System.Update.SystemUpdateLastErrorInfo" }; };
template <> struct name<Windows::System::Update::SystemUpdateManager>{ static constexpr auto & value{ L"Windows.System.Update.SystemUpdateManager" }; };
template <> struct name<Windows::System::Update::SystemUpdateAttentionRequiredReason>{ static constexpr auto & value{ L"Windows.System.Update.SystemUpdateAttentionRequiredReason" }; };
template <> struct name<Windows::System::Update::SystemUpdateItemState>{ static constexpr auto & value{ L"Windows.System.Update.SystemUpdateItemState" }; };
template <> struct name<Windows::System::Update::SystemUpdateManagerState>{ static constexpr auto & value{ L"Windows.System.Update.SystemUpdateManagerState" }; };
template <> struct name<Windows::System::Update::SystemUpdateStartInstallAction>{ static constexpr auto & value{ L"Windows.System.Update.SystemUpdateStartInstallAction" }; };
template <> struct guid_storage<Windows::System::Update::ISystemUpdateItem>{ static constexpr guid value{ 0x779740EB,0x5624,0x519E,{ 0xA8,0xE2,0x09,0xE9,0x17,0x3B,0x3F,0xB7 } }; };
template <> struct guid_storage<Windows::System::Update::ISystemUpdateLastErrorInfo>{ static constexpr guid value{ 0x7EE887F7,0x8A44,0x5B6E,{ 0xBD,0x07,0x7A,0xEC,0xE4,0x11,0x6E,0xA9 } }; };
template <> struct guid_storage<Windows::System::Update::ISystemUpdateManagerStatics>{ static constexpr guid value{ 0xB2D3FCEF,0x2971,0x51BE,{ 0xB4,0x1A,0x8B,0xD7,0x03,0xBB,0x70,0x1A } }; };
template <> struct default_interface<Windows::System::Update::SystemUpdateItem>{ using type = Windows::System::Update::ISystemUpdateItem; };
template <> struct default_interface<Windows::System::Update::SystemUpdateLastErrorInfo>{ using type = Windows::System::Update::ISystemUpdateLastErrorInfo; };

template <> struct abi<Windows::System::Update::ISystemUpdateItem>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL get_State(Windows::System::Update::SystemUpdateItemState* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_Title(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_Description(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_Id(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_Revision(uint32_t* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_DownloadProgress(double* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_InstallProgress(double* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_ExtendedError(winrt::hresult* value) noexcept = 0;
};};

template <> struct abi<Windows::System::Update::ISystemUpdateLastErrorInfo>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL get_State(Windows::System::Update::SystemUpdateManagerState* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_ExtendedError(winrt::hresult* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_IsInteractive(bool* value) noexcept = 0;
};};

template <> struct abi<Windows::System::Update::ISystemUpdateManagerStatics>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL IsSupported(bool* result) noexcept = 0;
    virtual int32_t WINRT_CALL get_State(Windows::System::Update::SystemUpdateManagerState* value) noexcept = 0;
    virtual int32_t WINRT_CALL add_StateChanged(void* handler, winrt::event_token* token) noexcept = 0;
    virtual int32_t WINRT_CALL remove_StateChanged(winrt::event_token token) noexcept = 0;
    virtual int32_t WINRT_CALL get_DownloadProgress(double* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_InstallProgress(double* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_UserActiveHoursStart(Windows::Foundation::TimeSpan* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_UserActiveHoursEnd(Windows::Foundation::TimeSpan* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_UserActiveHoursMax(int32_t* value) noexcept = 0;
    virtual int32_t WINRT_CALL TrySetUserActiveHours(Windows::Foundation::TimeSpan start, Windows::Foundation::TimeSpan end, bool* result) noexcept = 0;
    virtual int32_t WINRT_CALL get_LastUpdateCheckTime(Windows::Foundation::DateTime* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_LastUpdateInstallTime(Windows::Foundation::DateTime* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_LastErrorInfo(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL GetAutomaticRebootBlockIds(void** result) noexcept = 0;
    virtual int32_t WINRT_CALL BlockAutomaticRebootAsync(void* lockId, void** operation) noexcept = 0;
    virtual int32_t WINRT_CALL UnblockAutomaticRebootAsync(void* lockId, void** operation) noexcept = 0;
    virtual int32_t WINRT_CALL get_ExtendedError(winrt::hresult* value) noexcept = 0;
    virtual int32_t WINRT_CALL GetUpdateItems(void** result) noexcept = 0;
    virtual int32_t WINRT_CALL get_AttentionRequiredReason(Windows::System::Update::SystemUpdateAttentionRequiredReason* value) noexcept = 0;
    virtual int32_t WINRT_CALL SetFlightRing(void* flightRing, bool* result) noexcept = 0;
    virtual int32_t WINRT_CALL GetFlightRing(void** result) noexcept = 0;
    virtual int32_t WINRT_CALL StartInstall(Windows::System::Update::SystemUpdateStartInstallAction action) noexcept = 0;
    virtual int32_t WINRT_CALL RebootToCompleteInstall() noexcept = 0;
    virtual int32_t WINRT_CALL StartCancelUpdates() noexcept = 0;
};};

template <typename D>
struct consume_Windows_System_Update_ISystemUpdateItem
{
    Windows::System::Update::SystemUpdateItemState State() const;
    hstring Title() const;
    hstring Description() const;
    hstring Id() const;
    uint32_t Revision() const;
    double DownloadProgress() const;
    double InstallProgress() const;
    winrt::hresult ExtendedError() const;
};
template <> struct consume<Windows::System::Update::ISystemUpdateItem> { template <typename D> using type = consume_Windows_System_Update_ISystemUpdateItem<D>; };

template <typename D>
struct consume_Windows_System_Update_ISystemUpdateLastErrorInfo
{
    Windows::System::Update::SystemUpdateManagerState State() const;
    winrt::hresult ExtendedError() const;
    bool IsInteractive() const;
};
template <> struct consume<Windows::System::Update::ISystemUpdateLastErrorInfo> { template <typename D> using type = consume_Windows_System_Update_ISystemUpdateLastErrorInfo<D>; };

template <typename D>
struct consume_Windows_System_Update_ISystemUpdateManagerStatics
{
    bool IsSupported() const;
    Windows::System::Update::SystemUpdateManagerState State() const;
    winrt::event_token StateChanged(Windows::Foundation::EventHandler<Windows::Foundation::IInspectable> const& handler) const;
    using StateChanged_revoker = impl::event_revoker<Windows::System::Update::ISystemUpdateManagerStatics, &impl::abi_t<Windows::System::Update::ISystemUpdateManagerStatics>::remove_StateChanged>;
    StateChanged_revoker StateChanged(auto_revoke_t, Windows::Foundation::EventHandler<Windows::Foundation::IInspectable> const& handler) const;
    void StateChanged(winrt::event_token const& token) const noexcept;
    double DownloadProgress() const;
    double InstallProgress() const;
    Windows::Foundation::TimeSpan UserActiveHoursStart() const;
    Windows::Foundation::TimeSpan UserActiveHoursEnd() const;
    int32_t UserActiveHoursMax() const;
    bool TrySetUserActiveHours(Windows::Foundation::TimeSpan const& start, Windows::Foundation::TimeSpan const& end) const;
    Windows::Foundation::DateTime LastUpdateCheckTime() const;
    Windows::Foundation::DateTime LastUpdateInstallTime() const;
    Windows::System::Update::SystemUpdateLastErrorInfo LastErrorInfo() const;
    Windows::Foundation::Collections::IVectorView<hstring> GetAutomaticRebootBlockIds() const;
    Windows::Foundation::IAsyncOperation<bool> BlockAutomaticRebootAsync(param::hstring const& lockId) const;
    Windows::Foundation::IAsyncOperation<bool> UnblockAutomaticRebootAsync(param::hstring const& lockId) const;
    winrt::hresult ExtendedError() const;
    Windows::Foundation::Collections::IVectorView<Windows::System::Update::SystemUpdateItem> GetUpdateItems() const;
    Windows::System::Update::SystemUpdateAttentionRequiredReason AttentionRequiredReason() const;
    bool SetFlightRing(param::hstring const& flightRing) const;
    hstring GetFlightRing() const;
    void StartInstall(Windows::System::Update::SystemUpdateStartInstallAction const& action) const;
    void RebootToCompleteInstall() const;
    void StartCancelUpdates() const;
};
template <> struct consume<Windows::System::Update::ISystemUpdateManagerStatics> { template <typename D> using type = consume_Windows_System_Update_ISystemUpdateManagerStatics<D>; };

}
