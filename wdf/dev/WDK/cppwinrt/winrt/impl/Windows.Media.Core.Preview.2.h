// C++/WinRT v1.0.190111.3

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#pragma once
#include "winrt/impl/Windows.Media.1.h"
#include "winrt/impl/Windows.Media.Core.Preview.1.h"

WINRT_EXPORT namespace winrt::Windows::Media::Core::Preview {

}

namespace winrt::impl {

}

WINRT_EXPORT namespace winrt::Windows::Media::Core::Preview {

struct SoundLevelBroker
{
    SoundLevelBroker() = delete;
    static Windows::Media::SoundLevel SoundLevel();
    static winrt::event_token SoundLevelChanged(Windows::Foundation::EventHandler<Windows::Foundation::IInspectable> const& handler);
    using SoundLevelChanged_revoker = impl::factory_event_revoker<Windows::Media::Core::Preview::ISoundLevelBrokerStatics, &impl::abi_t<Windows::Media::Core::Preview::ISoundLevelBrokerStatics>::remove_SoundLevelChanged>;
    static SoundLevelChanged_revoker SoundLevelChanged(auto_revoke_t, Windows::Foundation::EventHandler<Windows::Foundation::IInspectable> const& handler);
    static void SoundLevelChanged(winrt::event_token const& token);
};

}
