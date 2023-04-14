// C++/WinRT v1.0.190111.3

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#pragma once

WINRT_EXPORT namespace winrt::Windows::Storage {

struct ApplicationData;

}

WINRT_EXPORT namespace winrt::Windows::Management::Core {

struct IApplicationDataManager;
struct IApplicationDataManagerStatics;
struct ApplicationDataManager;

}

namespace winrt::impl {

template <> struct category<Windows::Management::Core::IApplicationDataManager>{ using type = interface_category; };
template <> struct category<Windows::Management::Core::IApplicationDataManagerStatics>{ using type = interface_category; };
template <> struct category<Windows::Management::Core::ApplicationDataManager>{ using type = class_category; };
template <> struct name<Windows::Management::Core::IApplicationDataManager>{ static constexpr auto & value{ L"Windows.Management.Core.IApplicationDataManager" }; };
template <> struct name<Windows::Management::Core::IApplicationDataManagerStatics>{ static constexpr auto & value{ L"Windows.Management.Core.IApplicationDataManagerStatics" }; };
template <> struct name<Windows::Management::Core::ApplicationDataManager>{ static constexpr auto & value{ L"Windows.Management.Core.ApplicationDataManager" }; };
template <> struct guid_storage<Windows::Management::Core::IApplicationDataManager>{ static constexpr guid value{ 0x74D10432,0x2E99,0x4000,{ 0x9A,0x3A,0x64,0x30,0x7E,0x85,0x81,0x29 } }; };
template <> struct guid_storage<Windows::Management::Core::IApplicationDataManagerStatics>{ static constexpr guid value{ 0x1E1862E3,0x698E,0x49A1,{ 0x97,0x52,0xDE,0xE9,0x49,0x25,0xB9,0xB3 } }; };
template <> struct default_interface<Windows::Management::Core::ApplicationDataManager>{ using type = Windows::Management::Core::IApplicationDataManager; };

template <> struct abi<Windows::Management::Core::IApplicationDataManager>{ struct type : IInspectable
{
};};

template <> struct abi<Windows::Management::Core::IApplicationDataManagerStatics>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL CreateForPackageFamily(void* packageFamilyName, void** applicationData) noexcept = 0;
};};

template <typename D>
struct consume_Windows_Management_Core_IApplicationDataManager
{
};
template <> struct consume<Windows::Management::Core::IApplicationDataManager> { template <typename D> using type = consume_Windows_Management_Core_IApplicationDataManager<D>; };

template <typename D>
struct consume_Windows_Management_Core_IApplicationDataManagerStatics
{
    Windows::Storage::ApplicationData CreateForPackageFamily(param::hstring const& packageFamilyName) const;
};
template <> struct consume<Windows::Management::Core::IApplicationDataManagerStatics> { template <typename D> using type = consume_Windows_Management_Core_IApplicationDataManagerStatics<D>; };

}
