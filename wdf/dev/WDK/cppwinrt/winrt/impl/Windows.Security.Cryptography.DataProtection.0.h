// C++/WinRT v1.0.190111.3

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#pragma once

WINRT_EXPORT namespace winrt::Windows::Storage::Streams {

struct IBuffer;
struct IInputStream;
struct IOutputStream;

}

WINRT_EXPORT namespace winrt::Windows::Security::Cryptography::DataProtection {

struct IDataProtectionProvider;
struct IDataProtectionProviderFactory;
struct DataProtectionProvider;

}

namespace winrt::impl {

template <> struct category<Windows::Security::Cryptography::DataProtection::IDataProtectionProvider>{ using type = interface_category; };
template <> struct category<Windows::Security::Cryptography::DataProtection::IDataProtectionProviderFactory>{ using type = interface_category; };
template <> struct category<Windows::Security::Cryptography::DataProtection::DataProtectionProvider>{ using type = class_category; };
template <> struct name<Windows::Security::Cryptography::DataProtection::IDataProtectionProvider>{ static constexpr auto & value{ L"Windows.Security.Cryptography.DataProtection.IDataProtectionProvider" }; };
template <> struct name<Windows::Security::Cryptography::DataProtection::IDataProtectionProviderFactory>{ static constexpr auto & value{ L"Windows.Security.Cryptography.DataProtection.IDataProtectionProviderFactory" }; };
template <> struct name<Windows::Security::Cryptography::DataProtection::DataProtectionProvider>{ static constexpr auto & value{ L"Windows.Security.Cryptography.DataProtection.DataProtectionProvider" }; };
template <> struct guid_storage<Windows::Security::Cryptography::DataProtection::IDataProtectionProvider>{ static constexpr guid value{ 0x09639948,0xED22,0x4270,{ 0xBD,0x1C,0x6D,0x72,0xC0,0x0F,0x87,0x87 } }; };
template <> struct guid_storage<Windows::Security::Cryptography::DataProtection::IDataProtectionProviderFactory>{ static constexpr guid value{ 0xADF33DAC,0x4932,0x4CDF,{ 0xAC,0x41,0x72,0x14,0x33,0x35,0x14,0xCA } }; };
template <> struct default_interface<Windows::Security::Cryptography::DataProtection::DataProtectionProvider>{ using type = Windows::Security::Cryptography::DataProtection::IDataProtectionProvider; };

template <> struct abi<Windows::Security::Cryptography::DataProtection::IDataProtectionProvider>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL ProtectAsync(void* data, void** value) noexcept = 0;
    virtual int32_t WINRT_CALL UnprotectAsync(void* data, void** value) noexcept = 0;
    virtual int32_t WINRT_CALL ProtectStreamAsync(void* src, void* dest, void** value) noexcept = 0;
    virtual int32_t WINRT_CALL UnprotectStreamAsync(void* src, void* dest, void** value) noexcept = 0;
};};

template <> struct abi<Windows::Security::Cryptography::DataProtection::IDataProtectionProviderFactory>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL CreateOverloadExplicit(void* protectionDescriptor, void** value) noexcept = 0;
};};

template <typename D>
struct consume_Windows_Security_Cryptography_DataProtection_IDataProtectionProvider
{
    Windows::Foundation::IAsyncOperation<Windows::Storage::Streams::IBuffer> ProtectAsync(Windows::Storage::Streams::IBuffer const& data) const;
    Windows::Foundation::IAsyncOperation<Windows::Storage::Streams::IBuffer> UnprotectAsync(Windows::Storage::Streams::IBuffer const& data) const;
    Windows::Foundation::IAsyncAction ProtectStreamAsync(Windows::Storage::Streams::IInputStream const& src, Windows::Storage::Streams::IOutputStream const& dest) const;
    Windows::Foundation::IAsyncAction UnprotectStreamAsync(Windows::Storage::Streams::IInputStream const& src, Windows::Storage::Streams::IOutputStream const& dest) const;
};
template <> struct consume<Windows::Security::Cryptography::DataProtection::IDataProtectionProvider> { template <typename D> using type = consume_Windows_Security_Cryptography_DataProtection_IDataProtectionProvider<D>; };

template <typename D>
struct consume_Windows_Security_Cryptography_DataProtection_IDataProtectionProviderFactory
{
    Windows::Security::Cryptography::DataProtection::DataProtectionProvider CreateOverloadExplicit(param::hstring const& protectionDescriptor) const;
};
template <> struct consume<Windows::Security::Cryptography::DataProtection::IDataProtectionProviderFactory> { template <typename D> using type = consume_Windows_Security_Cryptography_DataProtection_IDataProtectionProviderFactory<D>; };

}
