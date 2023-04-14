// C++/WinRT v1.0.190111.3

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#pragma once
#include "winrt/impl/Windows.ApplicationModel.Activation.0.h"
#include "winrt/impl/Windows.Foundation.Collections.0.h"
#include "winrt/impl/Windows.Gaming.UI.0.h"

WINRT_EXPORT namespace winrt::Windows::Gaming::UI {

struct WINRT_EBO IGameBarStatics :
    Windows::Foundation::IInspectable,
    impl::consume_t<IGameBarStatics>
{
    IGameBarStatics(std::nullptr_t = nullptr) noexcept {}
};

struct WINRT_EBO IGameChatMessageReceivedEventArgs :
    Windows::Foundation::IInspectable,
    impl::consume_t<IGameChatMessageReceivedEventArgs>
{
    IGameChatMessageReceivedEventArgs(std::nullptr_t = nullptr) noexcept {}
};

struct WINRT_EBO IGameChatOverlay :
    Windows::Foundation::IInspectable,
    impl::consume_t<IGameChatOverlay>
{
    IGameChatOverlay(std::nullptr_t = nullptr) noexcept {}
};

struct WINRT_EBO IGameChatOverlayMessageSource :
    Windows::Foundation::IInspectable,
    impl::consume_t<IGameChatOverlayMessageSource>
{
    IGameChatOverlayMessageSource(std::nullptr_t = nullptr) noexcept {}
};

struct WINRT_EBO IGameChatOverlayStatics :
    Windows::Foundation::IInspectable,
    impl::consume_t<IGameChatOverlayStatics>
{
    IGameChatOverlayStatics(std::nullptr_t = nullptr) noexcept {}
};

struct WINRT_EBO IGameUIProviderActivatedEventArgs :
    Windows::Foundation::IInspectable,
    impl::consume_t<IGameUIProviderActivatedEventArgs>,
    impl::require<IGameUIProviderActivatedEventArgs, Windows::ApplicationModel::Activation::IActivatedEventArgs>
{
    IGameUIProviderActivatedEventArgs(std::nullptr_t = nullptr) noexcept {}
};

}
