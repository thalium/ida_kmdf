// C++/WinRT v1.0.190111.3

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#pragma once
#include "winrt/impl/Windows.Foundation.Collections.1.h"
#include "winrt/impl/Windows.Storage.1.h"
#include "winrt/impl/Windows.System.1.h"
#include "winrt/impl/Windows.Storage.Pickers.1.h"

WINRT_EXPORT namespace winrt::Windows::Storage::Pickers {

}

namespace winrt::impl {

}

WINRT_EXPORT namespace winrt::Windows::Storage::Pickers {

struct WINRT_EBO FileExtensionVector :
    Windows::Foundation::Collections::IVector<hstring>
{
    FileExtensionVector(std::nullptr_t) noexcept {}
};

struct WINRT_EBO FileOpenPicker :
    Windows::Storage::Pickers::IFileOpenPicker,
    impl::require<FileOpenPicker, Windows::Storage::Pickers::IFileOpenPicker2, Windows::Storage::Pickers::IFileOpenPicker3, Windows::Storage::Pickers::IFileOpenPickerWithOperationId>
{
    FileOpenPicker(std::nullptr_t) noexcept {}
    FileOpenPicker();
    using impl::consume_t<FileOpenPicker, Windows::Storage::Pickers::IFileOpenPickerWithOperationId>::PickSingleFileAsync;
    using Windows::Storage::Pickers::IFileOpenPicker::PickSingleFileAsync;
    static Windows::Foundation::IAsyncOperation<Windows::Storage::StorageFile> ResumePickSingleFileAsync();
    static Windows::Storage::Pickers::FileOpenPicker CreateForUser(Windows::System::User const& user);
};

struct WINRT_EBO FilePickerFileTypesOrderedMap :
    Windows::Foundation::Collections::IMap<hstring, Windows::Foundation::Collections::IVector<hstring>>
{
    FilePickerFileTypesOrderedMap(std::nullptr_t) noexcept {}
};

struct WINRT_EBO FilePickerSelectedFilesArray :
    Windows::Foundation::Collections::IVectorView<Windows::Storage::StorageFile>
{
    FilePickerSelectedFilesArray(std::nullptr_t) noexcept {}
};

struct WINRT_EBO FileSavePicker :
    Windows::Storage::Pickers::IFileSavePicker,
    impl::require<FileSavePicker, Windows::Storage::Pickers::IFileSavePicker2, Windows::Storage::Pickers::IFileSavePicker3, Windows::Storage::Pickers::IFileSavePicker4>
{
    FileSavePicker(std::nullptr_t) noexcept {}
    FileSavePicker();
    static Windows::Storage::Pickers::FileSavePicker CreateForUser(Windows::System::User const& user);
};

struct WINRT_EBO FolderPicker :
    Windows::Storage::Pickers::IFolderPicker,
    impl::require<FolderPicker, Windows::Storage::Pickers::IFolderPicker2, Windows::Storage::Pickers::IFolderPicker3>
{
    FolderPicker(std::nullptr_t) noexcept {}
    FolderPicker();
    static Windows::Storage::Pickers::FolderPicker CreateForUser(Windows::System::User const& user);
};

}
