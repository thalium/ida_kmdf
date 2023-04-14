// C++/WinRT v1.0.190111.3

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#pragma once
#include "winrt/impl/Windows.UI.0.h"
#include "winrt/impl/Windows.UI.ViewManagement.Core.0.h"

WINRT_EXPORT namespace winrt::Windows::UI::ViewManagement::Core {

struct WINRT_EBO ICoreInputView :
    Windows::Foundation::IInspectable,
    impl::consume_t<ICoreInputView>
{
    ICoreInputView(std::nullptr_t = nullptr) noexcept {}
};

struct WINRT_EBO ICoreInputView2 :
    Windows::Foundation::IInspectable,
    impl::consume_t<ICoreInputView2>
{
    ICoreInputView2(std::nullptr_t = nullptr) noexcept {}
};

struct WINRT_EBO ICoreInputView3 :
    Windows::Foundation::IInspectable,
    impl::consume_t<ICoreInputView3>
{
    ICoreInputView3(std::nullptr_t = nullptr) noexcept {}
};

struct WINRT_EBO ICoreInputViewOcclusion :
    Windows::Foundation::IInspectable,
    impl::consume_t<ICoreInputViewOcclusion>
{
    ICoreInputViewOcclusion(std::nullptr_t = nullptr) noexcept {}
};

struct WINRT_EBO ICoreInputViewOcclusionsChangedEventArgs :
    Windows::Foundation::IInspectable,
    impl::consume_t<ICoreInputViewOcclusionsChangedEventArgs>
{
    ICoreInputViewOcclusionsChangedEventArgs(std::nullptr_t = nullptr) noexcept {}
};

struct WINRT_EBO ICoreInputViewStatics :
    Windows::Foundation::IInspectable,
    impl::consume_t<ICoreInputViewStatics>
{
    ICoreInputViewStatics(std::nullptr_t = nullptr) noexcept {}
};

struct WINRT_EBO ICoreInputViewStatics2 :
    Windows::Foundation::IInspectable,
    impl::consume_t<ICoreInputViewStatics2>
{
    ICoreInputViewStatics2(std::nullptr_t = nullptr) noexcept {}
};

struct WINRT_EBO ICoreInputViewTransferringXYFocusEventArgs :
    Windows::Foundation::IInspectable,
    impl::consume_t<ICoreInputViewTransferringXYFocusEventArgs>
{
    ICoreInputViewTransferringXYFocusEventArgs(std::nullptr_t = nullptr) noexcept {}
};

}
