// C++/WinRT v1.0.190111.3

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#pragma once

WINRT_EXPORT namespace winrt::Windows::Graphics::Imaging {

struct SoftwareBitmap;

}

WINRT_EXPORT namespace winrt::Windows::ApplicationModel::Preview::InkWorkspace {

struct IInkWorkspaceHostedAppManager;
struct IInkWorkspaceHostedAppManagerStatics;
struct InkWorkspaceHostedAppManager;

}

namespace winrt::impl {

template <> struct category<Windows::ApplicationModel::Preview::InkWorkspace::IInkWorkspaceHostedAppManager>{ using type = interface_category; };
template <> struct category<Windows::ApplicationModel::Preview::InkWorkspace::IInkWorkspaceHostedAppManagerStatics>{ using type = interface_category; };
template <> struct category<Windows::ApplicationModel::Preview::InkWorkspace::InkWorkspaceHostedAppManager>{ using type = class_category; };
template <> struct name<Windows::ApplicationModel::Preview::InkWorkspace::IInkWorkspaceHostedAppManager>{ static constexpr auto & value{ L"Windows.ApplicationModel.Preview.InkWorkspace.IInkWorkspaceHostedAppManager" }; };
template <> struct name<Windows::ApplicationModel::Preview::InkWorkspace::IInkWorkspaceHostedAppManagerStatics>{ static constexpr auto & value{ L"Windows.ApplicationModel.Preview.InkWorkspace.IInkWorkspaceHostedAppManagerStatics" }; };
template <> struct name<Windows::ApplicationModel::Preview::InkWorkspace::InkWorkspaceHostedAppManager>{ static constexpr auto & value{ L"Windows.ApplicationModel.Preview.InkWorkspace.InkWorkspaceHostedAppManager" }; };
template <> struct guid_storage<Windows::ApplicationModel::Preview::InkWorkspace::IInkWorkspaceHostedAppManager>{ static constexpr guid value{ 0xFE0A7990,0x5E59,0x4BB7,{ 0x8A,0x63,0x7D,0x21,0x8C,0xD9,0x63,0x00 } }; };
template <> struct guid_storage<Windows::ApplicationModel::Preview::InkWorkspace::IInkWorkspaceHostedAppManagerStatics>{ static constexpr guid value{ 0xCBFD8CC5,0xA162,0x4BC4,{ 0x84,0xEE,0xE8,0x71,0x6D,0x52,0x33,0xC5 } }; };
template <> struct default_interface<Windows::ApplicationModel::Preview::InkWorkspace::InkWorkspaceHostedAppManager>{ using type = Windows::ApplicationModel::Preview::InkWorkspace::IInkWorkspaceHostedAppManager; };

template <> struct abi<Windows::ApplicationModel::Preview::InkWorkspace::IInkWorkspaceHostedAppManager>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL SetThumbnailAsync(void* bitmap, void** action) noexcept = 0;
};};

template <> struct abi<Windows::ApplicationModel::Preview::InkWorkspace::IInkWorkspaceHostedAppManagerStatics>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL GetForCurrentApp(void** current) noexcept = 0;
};};

template <typename D>
struct consume_Windows_ApplicationModel_Preview_InkWorkspace_IInkWorkspaceHostedAppManager
{
    Windows::Foundation::IAsyncAction SetThumbnailAsync(Windows::Graphics::Imaging::SoftwareBitmap const& bitmap) const;
};
template <> struct consume<Windows::ApplicationModel::Preview::InkWorkspace::IInkWorkspaceHostedAppManager> { template <typename D> using type = consume_Windows_ApplicationModel_Preview_InkWorkspace_IInkWorkspaceHostedAppManager<D>; };

template <typename D>
struct consume_Windows_ApplicationModel_Preview_InkWorkspace_IInkWorkspaceHostedAppManagerStatics
{
    Windows::ApplicationModel::Preview::InkWorkspace::InkWorkspaceHostedAppManager GetForCurrentApp() const;
};
template <> struct consume<Windows::ApplicationModel::Preview::InkWorkspace::IInkWorkspaceHostedAppManagerStatics> { template <typename D> using type = consume_Windows_ApplicationModel_Preview_InkWorkspace_IInkWorkspaceHostedAppManagerStatics<D>; };

}
