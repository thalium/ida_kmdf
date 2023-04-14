// C++/WinRT v1.0.190111.3

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#pragma once
#include "winrt/impl/Windows.ApplicationModel.CommunicationBlocking.1.h"

WINRT_EXPORT namespace winrt::Windows::ApplicationModel::CommunicationBlocking {

}

namespace winrt::impl {

}

WINRT_EXPORT namespace winrt::Windows::ApplicationModel::CommunicationBlocking {

struct CommunicationBlockingAccessManager
{
    CommunicationBlockingAccessManager() = delete;
    static bool IsBlockingActive();
    static Windows::Foundation::IAsyncOperation<bool> IsBlockedNumberAsync(param::hstring const& number);
    static bool ShowBlockNumbersUI(param::iterable<hstring> const& phoneNumbers);
    static bool ShowUnblockNumbersUI(param::iterable<hstring> const& phoneNumbers);
    static void ShowBlockedCallsUI();
    static void ShowBlockedMessagesUI();
};

struct CommunicationBlockingAppManager
{
    CommunicationBlockingAppManager() = delete;
    static bool IsCurrentAppActiveBlockingApp();
    static void ShowCommunicationBlockingSettingsUI();
    static Windows::Foundation::IAsyncOperation<bool> RequestSetAsActiveBlockingAppAsync();
};

}
