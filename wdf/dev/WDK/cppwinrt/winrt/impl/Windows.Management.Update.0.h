// C++/WinRT v1.0.190111.3

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#pragma once

WINRT_EXPORT namespace winrt::Windows::Foundation::Collections {

struct ValueSet;

}

WINRT_EXPORT namespace winrt::Windows::Management::Update {

struct IPreviewBuildsManager;
struct IPreviewBuildsManagerStatics;
struct IPreviewBuildsState;
struct PreviewBuildsManager;
struct PreviewBuildsState;

}

namespace winrt::impl {

template <> struct category<Windows::Management::Update::IPreviewBuildsManager>{ using type = interface_category; };
template <> struct category<Windows::Management::Update::IPreviewBuildsManagerStatics>{ using type = interface_category; };
template <> struct category<Windows::Management::Update::IPreviewBuildsState>{ using type = interface_category; };
template <> struct category<Windows::Management::Update::PreviewBuildsManager>{ using type = class_category; };
template <> struct category<Windows::Management::Update::PreviewBuildsState>{ using type = class_category; };
template <> struct name<Windows::Management::Update::IPreviewBuildsManager>{ static constexpr auto & value{ L"Windows.Management.Update.IPreviewBuildsManager" }; };
template <> struct name<Windows::Management::Update::IPreviewBuildsManagerStatics>{ static constexpr auto & value{ L"Windows.Management.Update.IPreviewBuildsManagerStatics" }; };
template <> struct name<Windows::Management::Update::IPreviewBuildsState>{ static constexpr auto & value{ L"Windows.Management.Update.IPreviewBuildsState" }; };
template <> struct name<Windows::Management::Update::PreviewBuildsManager>{ static constexpr auto & value{ L"Windows.Management.Update.PreviewBuildsManager" }; };
template <> struct name<Windows::Management::Update::PreviewBuildsState>{ static constexpr auto & value{ L"Windows.Management.Update.PreviewBuildsState" }; };
template <> struct guid_storage<Windows::Management::Update::IPreviewBuildsManager>{ static constexpr guid value{ 0xFA07DD61,0x7E4F,0x59F7,{ 0x7C,0x9F,0xDE,0xF9,0x05,0x1C,0x5F,0x62 } }; };
template <> struct guid_storage<Windows::Management::Update::IPreviewBuildsManagerStatics>{ static constexpr guid value{ 0x3E422887,0xB112,0x5A70,{ 0x7D,0xA1,0x97,0xD7,0x8D,0x32,0xAA,0x29 } }; };
template <> struct guid_storage<Windows::Management::Update::IPreviewBuildsState>{ static constexpr guid value{ 0xA2F2903E,0xB223,0x5F63,{ 0x75,0x46,0x3E,0x8E,0xAC,0x07,0x0A,0x2E } }; };
template <> struct default_interface<Windows::Management::Update::PreviewBuildsManager>{ using type = Windows::Management::Update::IPreviewBuildsManager; };
template <> struct default_interface<Windows::Management::Update::PreviewBuildsState>{ using type = Windows::Management::Update::IPreviewBuildsState; };

template <> struct abi<Windows::Management::Update::IPreviewBuildsManager>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL get_ArePreviewBuildsAllowed(bool* value) noexcept = 0;
    virtual int32_t WINRT_CALL put_ArePreviewBuildsAllowed(bool value) noexcept = 0;
    virtual int32_t WINRT_CALL GetCurrentState(void** result) noexcept = 0;
    virtual int32_t WINRT_CALL SyncAsync(void** result) noexcept = 0;
};};

template <> struct abi<Windows::Management::Update::IPreviewBuildsManagerStatics>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL GetDefault(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL IsSupported(bool* result) noexcept = 0;
};};

template <> struct abi<Windows::Management::Update::IPreviewBuildsState>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL get_Properties(void** value) noexcept = 0;
};};

template <typename D>
struct consume_Windows_Management_Update_IPreviewBuildsManager
{
    bool ArePreviewBuildsAllowed() const;
    void ArePreviewBuildsAllowed(bool value) const;
    Windows::Management::Update::PreviewBuildsState GetCurrentState() const;
    Windows::Foundation::IAsyncOperation<bool> SyncAsync() const;
};
template <> struct consume<Windows::Management::Update::IPreviewBuildsManager> { template <typename D> using type = consume_Windows_Management_Update_IPreviewBuildsManager<D>; };

template <typename D>
struct consume_Windows_Management_Update_IPreviewBuildsManagerStatics
{
    Windows::Management::Update::PreviewBuildsManager GetDefault() const;
    bool IsSupported() const;
};
template <> struct consume<Windows::Management::Update::IPreviewBuildsManagerStatics> { template <typename D> using type = consume_Windows_Management_Update_IPreviewBuildsManagerStatics<D>; };

template <typename D>
struct consume_Windows_Management_Update_IPreviewBuildsState
{
    Windows::Foundation::Collections::ValueSet Properties() const;
};
template <> struct consume<Windows::Management::Update::IPreviewBuildsState> { template <typename D> using type = consume_Windows_Management_Update_IPreviewBuildsState<D>; };

}
