// C++/WinRT v1.0.190111.3

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#pragma once
#include "winrt/impl/Windows.UI.Popups.0.h"

WINRT_EXPORT namespace winrt::Windows::UI::Popups {

struct WINRT_EBO IMessageDialog :
    Windows::Foundation::IInspectable,
    impl::consume_t<IMessageDialog>
{
    IMessageDialog(std::nullptr_t = nullptr) noexcept {}
};

struct WINRT_EBO IMessageDialogFactory :
    Windows::Foundation::IInspectable,
    impl::consume_t<IMessageDialogFactory>
{
    IMessageDialogFactory(std::nullptr_t = nullptr) noexcept {}
};

struct WINRT_EBO IPopupMenu :
    Windows::Foundation::IInspectable,
    impl::consume_t<IPopupMenu>
{
    IPopupMenu(std::nullptr_t = nullptr) noexcept {}
};

struct WINRT_EBO IUICommand :
    Windows::Foundation::IInspectable,
    impl::consume_t<IUICommand>
{
    IUICommand(std::nullptr_t = nullptr) noexcept {}
};

struct WINRT_EBO IUICommandFactory :
    Windows::Foundation::IInspectable,
    impl::consume_t<IUICommandFactory>
{
    IUICommandFactory(std::nullptr_t = nullptr) noexcept {}
};

}
