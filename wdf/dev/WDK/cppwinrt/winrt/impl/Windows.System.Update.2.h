// C++/WinRT v1.0.190111.3

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#pragma once
#include "winrt/impl/Windows.System.Update.1.h"

WINRT_EXPORT namespace winrt::Windows::System::Update {

}

namespace winrt::impl {

}

WINRT_EXPORT namespace winrt::Windows::System::Update {

struct WINRT_EBO SystemUpdateItem :
    Windows::System::Update::ISystemUpdateItem
{
    SystemUpdateItem(std::nullptr_t) noexcept {}
};

struct WINRT_EBO SystemUpdateLastErrorInfo :
    Windows::System::Update::ISystemUpdateLastErrorInfo
{
    SystemUpdateLastErrorInfo(std::nullptr_t) noexcept {}
};

struct SystemUpdateManager
{
    SystemUpdateManager() = delete;
    static bool IsSupported();
    static Windows::System::Update::SystemUpdateManagerState State();
    static winrt::event_token StateChanged(Windows::Foundation::EventHandler<Windows::Foundation::IInspectable> const& handler);
    using StateChanged_revoker = impl::factory_event_revoker<Windows::System::Update::ISystemUpdateManagerStatics, &impl::abi_t<Windows::System::Update::ISystemUpdateManagerStatics>::remove_StateChanged>;
    static StateChanged_revoker StateChanged(auto_revoke_t, Windows::Foundation::EventHandler<Windows::Foundation::IInspectable> const& handler);
    static void StateChanged(winrt::event_token const& token);
    static double DownloadProgress();
    static double InstallProgress();
    static Windows::Foundation::TimeSpan UserActiveHoursStart();
    static Windows::Foundation::TimeSpan UserActiveHoursEnd();
    static int32_t UserActiveHoursMax();
    static bool TrySetUserActiveHours(Windows::Foundation::TimeSpan const& start, Windows::Foundation::TimeSpan const& end);
    static Windows::Foundation::DateTime LastUpdateCheckTime();
    static Windows::Foundation::DateTime LastUpdateInstallTime();
    static Windows::System::Update::SystemUpdateLastErrorInfo LastErrorInfo();
    static Windows::Foundation::Collections::IVectorView<hstring> GetAutomaticRebootBlockIds();
    static Windows::Foundation::IAsyncOperation<bool> BlockAutomaticRebootAsync(param::hstring const& lockId);
    static Windows::Foundation::IAsyncOperation<bool> UnblockAutomaticRebootAsync(param::hstring const& lockId);
    static winrt::hresult ExtendedError();
    static Windows::Foundation::Collections::IVectorView<Windows::System::Update::SystemUpdateItem> GetUpdateItems();
    static Windows::System::Update::SystemUpdateAttentionRequiredReason AttentionRequiredReason();
    static bool SetFlightRing(param::hstring const& flightRing);
    static hstring GetFlightRing();
    static void StartInstall(Windows::System::Update::SystemUpdateStartInstallAction const& action);
    static void RebootToCompleteInstall();
    static void StartCancelUpdates();
};

}
