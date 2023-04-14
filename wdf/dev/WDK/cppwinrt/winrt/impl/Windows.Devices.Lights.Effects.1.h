// C++/WinRT v1.0.190111.3

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#pragma once
#include "winrt/impl/Windows.Devices.Lights.0.h"
#include "winrt/impl/Windows.Graphics.Imaging.0.h"
#include "winrt/impl/Windows.UI.0.h"
#include "winrt/impl/Windows.Foundation.Collections.0.h"
#include "winrt/impl/Windows.Devices.Lights.Effects.0.h"

WINRT_EXPORT namespace winrt::Windows::Devices::Lights::Effects {

struct WINRT_EBO ILampArrayBitmapEffect :
    Windows::Foundation::IInspectable,
    impl::consume_t<ILampArrayBitmapEffect>
{
    ILampArrayBitmapEffect(std::nullptr_t = nullptr) noexcept {}
};

struct WINRT_EBO ILampArrayBitmapEffectFactory :
    Windows::Foundation::IInspectable,
    impl::consume_t<ILampArrayBitmapEffectFactory>
{
    ILampArrayBitmapEffectFactory(std::nullptr_t = nullptr) noexcept {}
};

struct WINRT_EBO ILampArrayBitmapRequestedEventArgs :
    Windows::Foundation::IInspectable,
    impl::consume_t<ILampArrayBitmapRequestedEventArgs>
{
    ILampArrayBitmapRequestedEventArgs(std::nullptr_t = nullptr) noexcept {}
};

struct WINRT_EBO ILampArrayBlinkEffect :
    Windows::Foundation::IInspectable,
    impl::consume_t<ILampArrayBlinkEffect>
{
    ILampArrayBlinkEffect(std::nullptr_t = nullptr) noexcept {}
};

struct WINRT_EBO ILampArrayBlinkEffectFactory :
    Windows::Foundation::IInspectable,
    impl::consume_t<ILampArrayBlinkEffectFactory>
{
    ILampArrayBlinkEffectFactory(std::nullptr_t = nullptr) noexcept {}
};

struct WINRT_EBO ILampArrayColorRampEffect :
    Windows::Foundation::IInspectable,
    impl::consume_t<ILampArrayColorRampEffect>
{
    ILampArrayColorRampEffect(std::nullptr_t = nullptr) noexcept {}
};

struct WINRT_EBO ILampArrayColorRampEffectFactory :
    Windows::Foundation::IInspectable,
    impl::consume_t<ILampArrayColorRampEffectFactory>
{
    ILampArrayColorRampEffectFactory(std::nullptr_t = nullptr) noexcept {}
};

struct WINRT_EBO ILampArrayCustomEffect :
    Windows::Foundation::IInspectable,
    impl::consume_t<ILampArrayCustomEffect>
{
    ILampArrayCustomEffect(std::nullptr_t = nullptr) noexcept {}
};

struct WINRT_EBO ILampArrayCustomEffectFactory :
    Windows::Foundation::IInspectable,
    impl::consume_t<ILampArrayCustomEffectFactory>
{
    ILampArrayCustomEffectFactory(std::nullptr_t = nullptr) noexcept {}
};

struct WINRT_EBO ILampArrayEffect :
    Windows::Foundation::IInspectable,
    impl::consume_t<ILampArrayEffect>
{
    ILampArrayEffect(std::nullptr_t = nullptr) noexcept {}
};

struct WINRT_EBO ILampArrayEffectPlaylist :
    Windows::Foundation::IInspectable,
    impl::consume_t<ILampArrayEffectPlaylist>
{
    ILampArrayEffectPlaylist(std::nullptr_t = nullptr) noexcept {}
};

struct WINRT_EBO ILampArrayEffectPlaylistStatics :
    Windows::Foundation::IInspectable,
    impl::consume_t<ILampArrayEffectPlaylistStatics>
{
    ILampArrayEffectPlaylistStatics(std::nullptr_t = nullptr) noexcept {}
};

struct WINRT_EBO ILampArraySolidEffect :
    Windows::Foundation::IInspectable,
    impl::consume_t<ILampArraySolidEffect>
{
    ILampArraySolidEffect(std::nullptr_t = nullptr) noexcept {}
};

struct WINRT_EBO ILampArraySolidEffectFactory :
    Windows::Foundation::IInspectable,
    impl::consume_t<ILampArraySolidEffectFactory>
{
    ILampArraySolidEffectFactory(std::nullptr_t = nullptr) noexcept {}
};

struct WINRT_EBO ILampArrayUpdateRequestedEventArgs :
    Windows::Foundation::IInspectable,
    impl::consume_t<ILampArrayUpdateRequestedEventArgs>
{
    ILampArrayUpdateRequestedEventArgs(std::nullptr_t = nullptr) noexcept {}
};

}
