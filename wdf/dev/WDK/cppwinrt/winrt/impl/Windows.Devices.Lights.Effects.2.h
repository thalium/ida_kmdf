// C++/WinRT v1.0.190111.3

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#pragma once
#include "winrt/impl/Windows.Devices.Lights.1.h"
#include "winrt/impl/Windows.Graphics.Imaging.1.h"
#include "winrt/impl/Windows.UI.1.h"
#include "winrt/impl/Windows.Foundation.Collections.1.h"
#include "winrt/impl/Windows.Devices.Lights.Effects.1.h"

WINRT_EXPORT namespace winrt::Windows::Devices::Lights::Effects {

}

namespace winrt::impl {

}

WINRT_EXPORT namespace winrt::Windows::Devices::Lights::Effects {

struct WINRT_EBO LampArrayBitmapEffect :
    Windows::Devices::Lights::Effects::ILampArrayBitmapEffect,
    impl::require<LampArrayBitmapEffect, Windows::Devices::Lights::Effects::ILampArrayEffect>
{
    LampArrayBitmapEffect(std::nullptr_t) noexcept {}
    LampArrayBitmapEffect(Windows::Devices::Lights::LampArray const& lampArray, array_view<int32_t const> lampIndexes);
};

struct WINRT_EBO LampArrayBitmapRequestedEventArgs :
    Windows::Devices::Lights::Effects::ILampArrayBitmapRequestedEventArgs
{
    LampArrayBitmapRequestedEventArgs(std::nullptr_t) noexcept {}
};

struct WINRT_EBO LampArrayBlinkEffect :
    Windows::Devices::Lights::Effects::ILampArrayBlinkEffect,
    impl::require<LampArrayBlinkEffect, Windows::Devices::Lights::Effects::ILampArrayEffect>
{
    LampArrayBlinkEffect(std::nullptr_t) noexcept {}
    LampArrayBlinkEffect(Windows::Devices::Lights::LampArray const& lampArray, array_view<int32_t const> lampIndexes);
};

struct WINRT_EBO LampArrayColorRampEffect :
    Windows::Devices::Lights::Effects::ILampArrayColorRampEffect,
    impl::require<LampArrayColorRampEffect, Windows::Devices::Lights::Effects::ILampArrayEffect>
{
    LampArrayColorRampEffect(std::nullptr_t) noexcept {}
    LampArrayColorRampEffect(Windows::Devices::Lights::LampArray const& lampArray, array_view<int32_t const> lampIndexes);
};

struct WINRT_EBO LampArrayCustomEffect :
    Windows::Devices::Lights::Effects::ILampArrayCustomEffect,
    impl::require<LampArrayCustomEffect, Windows::Devices::Lights::Effects::ILampArrayEffect>
{
    LampArrayCustomEffect(std::nullptr_t) noexcept {}
    LampArrayCustomEffect(Windows::Devices::Lights::LampArray const& lampArray, array_view<int32_t const> lampIndexes);
};

struct WINRT_EBO LampArrayEffectPlaylist :
    Windows::Devices::Lights::Effects::ILampArrayEffectPlaylist,
    impl::require<LampArrayEffectPlaylist, Windows::Foundation::Collections::IIterable<Windows::Devices::Lights::Effects::ILampArrayEffect>, Windows::Foundation::Collections::IVectorView<Windows::Devices::Lights::Effects::ILampArrayEffect>>
{
    LampArrayEffectPlaylist(std::nullptr_t) noexcept {}
    LampArrayEffectPlaylist();
    static void StartAll(param::iterable<Windows::Devices::Lights::Effects::LampArrayEffectPlaylist> const& value);
    static void StopAll(param::iterable<Windows::Devices::Lights::Effects::LampArrayEffectPlaylist> const& value);
    static void PauseAll(param::iterable<Windows::Devices::Lights::Effects::LampArrayEffectPlaylist> const& value);
};

struct WINRT_EBO LampArraySolidEffect :
    Windows::Devices::Lights::Effects::ILampArraySolidEffect,
    impl::require<LampArraySolidEffect, Windows::Devices::Lights::Effects::ILampArrayEffect>
{
    LampArraySolidEffect(std::nullptr_t) noexcept {}
    LampArraySolidEffect(Windows::Devices::Lights::LampArray const& lampArray, array_view<int32_t const> lampIndexes);
};

struct WINRT_EBO LampArrayUpdateRequestedEventArgs :
    Windows::Devices::Lights::Effects::ILampArrayUpdateRequestedEventArgs
{
    LampArrayUpdateRequestedEventArgs(std::nullptr_t) noexcept {}
};

}
