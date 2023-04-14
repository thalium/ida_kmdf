// C++/WinRT v1.0.190111.3

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#pragma once

WINRT_EXPORT namespace winrt::Windows::Media::Render {

enum class AudioRenderCategory : int32_t
{
    Other = 0,
    ForegroundOnlyMedia = 1,
    BackgroundCapableMedia = 2,
    Communications = 3,
    Alerts = 4,
    SoundEffects = 5,
    GameEffects = 6,
    GameMedia = 7,
    GameChat = 8,
    Speech = 9,
    Movie = 10,
    Media = 11,
};

}

namespace winrt::impl {

template <> struct category<Windows::Media::Render::AudioRenderCategory>{ using type = enum_category; };
template <> struct name<Windows::Media::Render::AudioRenderCategory>{ static constexpr auto & value{ L"Windows.Media.Render.AudioRenderCategory" }; };

}
