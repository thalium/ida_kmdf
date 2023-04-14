// C++/WinRT v1.0.190111.3

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#pragma once
#include "winrt/impl/Windows.Security.Credentials.0.h"
#include "winrt/impl/Windows.System.0.h"
#include "winrt/impl/Windows.UI.Popups.0.h"
#include "winrt/impl/Windows.UI.ApplicationSettings.0.h"

WINRT_EXPORT namespace winrt::Windows::UI::ApplicationSettings {

struct WINRT_EBO IAccountsSettingsPane :
    Windows::Foundation::IInspectable,
    impl::consume_t<IAccountsSettingsPane>
{
    IAccountsSettingsPane(std::nullptr_t = nullptr) noexcept {}
};

struct WINRT_EBO IAccountsSettingsPaneCommandsRequestedEventArgs :
    Windows::Foundation::IInspectable,
    impl::consume_t<IAccountsSettingsPaneCommandsRequestedEventArgs>
{
    IAccountsSettingsPaneCommandsRequestedEventArgs(std::nullptr_t = nullptr) noexcept {}
};

struct WINRT_EBO IAccountsSettingsPaneCommandsRequestedEventArgs2 :
    Windows::Foundation::IInspectable,
    impl::consume_t<IAccountsSettingsPaneCommandsRequestedEventArgs2>
{
    IAccountsSettingsPaneCommandsRequestedEventArgs2(std::nullptr_t = nullptr) noexcept {}
};

struct WINRT_EBO IAccountsSettingsPaneEventDeferral :
    Windows::Foundation::IInspectable,
    impl::consume_t<IAccountsSettingsPaneEventDeferral>
{
    IAccountsSettingsPaneEventDeferral(std::nullptr_t = nullptr) noexcept {}
};

struct WINRT_EBO IAccountsSettingsPaneStatics :
    Windows::Foundation::IInspectable,
    impl::consume_t<IAccountsSettingsPaneStatics>
{
    IAccountsSettingsPaneStatics(std::nullptr_t = nullptr) noexcept {}
};

struct WINRT_EBO IAccountsSettingsPaneStatics2 :
    Windows::Foundation::IInspectable,
    impl::consume_t<IAccountsSettingsPaneStatics2>,
    impl::require<IAccountsSettingsPaneStatics2, Windows::UI::ApplicationSettings::IAccountsSettingsPaneStatics>
{
    IAccountsSettingsPaneStatics2(std::nullptr_t = nullptr) noexcept {}
};

struct WINRT_EBO IAccountsSettingsPaneStatics3 :
    Windows::Foundation::IInspectable,
    impl::consume_t<IAccountsSettingsPaneStatics3>
{
    IAccountsSettingsPaneStatics3(std::nullptr_t = nullptr) noexcept {}
};

struct WINRT_EBO ICredentialCommand :
    Windows::Foundation::IInspectable,
    impl::consume_t<ICredentialCommand>
{
    ICredentialCommand(std::nullptr_t = nullptr) noexcept {}
};

struct WINRT_EBO ICredentialCommandFactory :
    Windows::Foundation::IInspectable,
    impl::consume_t<ICredentialCommandFactory>
{
    ICredentialCommandFactory(std::nullptr_t = nullptr) noexcept {}
};

struct WINRT_EBO ISettingsCommandFactory :
    Windows::Foundation::IInspectable,
    impl::consume_t<ISettingsCommandFactory>
{
    ISettingsCommandFactory(std::nullptr_t = nullptr) noexcept {}
};

struct WINRT_EBO ISettingsCommandStatics :
    Windows::Foundation::IInspectable,
    impl::consume_t<ISettingsCommandStatics>
{
    ISettingsCommandStatics(std::nullptr_t = nullptr) noexcept {}
};

struct WINRT_EBO ISettingsPane :
    Windows::Foundation::IInspectable,
    impl::consume_t<ISettingsPane>
{
    ISettingsPane(std::nullptr_t = nullptr) noexcept {}
};

struct WINRT_EBO ISettingsPaneCommandsRequest :
    Windows::Foundation::IInspectable,
    impl::consume_t<ISettingsPaneCommandsRequest>
{
    ISettingsPaneCommandsRequest(std::nullptr_t = nullptr) noexcept {}
};

struct WINRT_EBO ISettingsPaneCommandsRequestedEventArgs :
    Windows::Foundation::IInspectable,
    impl::consume_t<ISettingsPaneCommandsRequestedEventArgs>
{
    ISettingsPaneCommandsRequestedEventArgs(std::nullptr_t = nullptr) noexcept {}
};

struct WINRT_EBO ISettingsPaneStatics :
    Windows::Foundation::IInspectable,
    impl::consume_t<ISettingsPaneStatics>
{
    ISettingsPaneStatics(std::nullptr_t = nullptr) noexcept {}
};

struct WINRT_EBO IWebAccountCommand :
    Windows::Foundation::IInspectable,
    impl::consume_t<IWebAccountCommand>
{
    IWebAccountCommand(std::nullptr_t = nullptr) noexcept {}
};

struct WINRT_EBO IWebAccountCommandFactory :
    Windows::Foundation::IInspectable,
    impl::consume_t<IWebAccountCommandFactory>
{
    IWebAccountCommandFactory(std::nullptr_t = nullptr) noexcept {}
};

struct WINRT_EBO IWebAccountInvokedArgs :
    Windows::Foundation::IInspectable,
    impl::consume_t<IWebAccountInvokedArgs>
{
    IWebAccountInvokedArgs(std::nullptr_t = nullptr) noexcept {}
};

struct WINRT_EBO IWebAccountProviderCommand :
    Windows::Foundation::IInspectable,
    impl::consume_t<IWebAccountProviderCommand>
{
    IWebAccountProviderCommand(std::nullptr_t = nullptr) noexcept {}
};

struct WINRT_EBO IWebAccountProviderCommandFactory :
    Windows::Foundation::IInspectable,
    impl::consume_t<IWebAccountProviderCommandFactory>
{
    IWebAccountProviderCommandFactory(std::nullptr_t = nullptr) noexcept {}
};

}
