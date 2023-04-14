// C++/WinRT v1.0.190111.3

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#pragma once
#include "winrt/impl/Windows.Foundation.Collections.0.h"
#include "winrt/impl/Windows.Storage.0.h"
#include "winrt/impl/Windows.System.0.h"
#include "winrt/impl/Windows.Storage.Pickers.0.h"

WINRT_EXPORT namespace winrt::Windows::Storage::Pickers {

struct WINRT_EBO IFileOpenPicker :
    Windows::Foundation::IInspectable,
    impl::consume_t<IFileOpenPicker>
{
    IFileOpenPicker(std::nullptr_t = nullptr) noexcept {}
};

struct WINRT_EBO IFileOpenPicker2 :
    Windows::Foundation::IInspectable,
    impl::consume_t<IFileOpenPicker2>
{
    IFileOpenPicker2(std::nullptr_t = nullptr) noexcept {}
};

struct WINRT_EBO IFileOpenPicker3 :
    Windows::Foundation::IInspectable,
    impl::consume_t<IFileOpenPicker3>
{
    IFileOpenPicker3(std::nullptr_t = nullptr) noexcept {}
};

struct WINRT_EBO IFileOpenPickerStatics :
    Windows::Foundation::IInspectable,
    impl::consume_t<IFileOpenPickerStatics>
{
    IFileOpenPickerStatics(std::nullptr_t = nullptr) noexcept {}
};

struct WINRT_EBO IFileOpenPickerStatics2 :
    Windows::Foundation::IInspectable,
    impl::consume_t<IFileOpenPickerStatics2>
{
    IFileOpenPickerStatics2(std::nullptr_t = nullptr) noexcept {}
};

struct WINRT_EBO IFileOpenPickerWithOperationId :
    Windows::Foundation::IInspectable,
    impl::consume_t<IFileOpenPickerWithOperationId>
{
    IFileOpenPickerWithOperationId(std::nullptr_t = nullptr) noexcept {}
};

struct WINRT_EBO IFileSavePicker :
    Windows::Foundation::IInspectable,
    impl::consume_t<IFileSavePicker>
{
    IFileSavePicker(std::nullptr_t = nullptr) noexcept {}
};

struct WINRT_EBO IFileSavePicker2 :
    Windows::Foundation::IInspectable,
    impl::consume_t<IFileSavePicker2>
{
    IFileSavePicker2(std::nullptr_t = nullptr) noexcept {}
};

struct WINRT_EBO IFileSavePicker3 :
    Windows::Foundation::IInspectable,
    impl::consume_t<IFileSavePicker3>
{
    IFileSavePicker3(std::nullptr_t = nullptr) noexcept {}
};

struct WINRT_EBO IFileSavePicker4 :
    Windows::Foundation::IInspectable,
    impl::consume_t<IFileSavePicker4>
{
    IFileSavePicker4(std::nullptr_t = nullptr) noexcept {}
};

struct WINRT_EBO IFileSavePickerStatics :
    Windows::Foundation::IInspectable,
    impl::consume_t<IFileSavePickerStatics>
{
    IFileSavePickerStatics(std::nullptr_t = nullptr) noexcept {}
};

struct WINRT_EBO IFolderPicker :
    Windows::Foundation::IInspectable,
    impl::consume_t<IFolderPicker>
{
    IFolderPicker(std::nullptr_t = nullptr) noexcept {}
};

struct WINRT_EBO IFolderPicker2 :
    Windows::Foundation::IInspectable,
    impl::consume_t<IFolderPicker2>
{
    IFolderPicker2(std::nullptr_t = nullptr) noexcept {}
};

struct WINRT_EBO IFolderPicker3 :
    Windows::Foundation::IInspectable,
    impl::consume_t<IFolderPicker3>
{
    IFolderPicker3(std::nullptr_t = nullptr) noexcept {}
};

struct WINRT_EBO IFolderPickerStatics :
    Windows::Foundation::IInspectable,
    impl::consume_t<IFolderPickerStatics>
{
    IFolderPickerStatics(std::nullptr_t = nullptr) noexcept {}
};

}
