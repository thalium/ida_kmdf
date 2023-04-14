// C++/WinRT v1.0.190111.3

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#pragma once

WINRT_EXPORT namespace winrt::Windows::Devices::Lights {

struct LampArray;

}

WINRT_EXPORT namespace winrt::Windows::Graphics::Imaging {

struct SoftwareBitmap;

}

WINRT_EXPORT namespace winrt::Windows::UI {

struct Color;

}

WINRT_EXPORT namespace winrt::Windows::Devices::Lights::Effects {

enum class LampArrayEffectCompletionBehavior : int32_t
{
    ClearState = 0,
    KeepState = 1,
};

enum class LampArrayEffectStartMode : int32_t
{
    Sequential = 0,
    Simultaneous = 1,
};

enum class LampArrayRepetitionMode : int32_t
{
    Occurrences = 0,
    Forever = 1,
};

struct ILampArrayBitmapEffect;
struct ILampArrayBitmapEffectFactory;
struct ILampArrayBitmapRequestedEventArgs;
struct ILampArrayBlinkEffect;
struct ILampArrayBlinkEffectFactory;
struct ILampArrayColorRampEffect;
struct ILampArrayColorRampEffectFactory;
struct ILampArrayCustomEffect;
struct ILampArrayCustomEffectFactory;
struct ILampArrayEffect;
struct ILampArrayEffectPlaylist;
struct ILampArrayEffectPlaylistStatics;
struct ILampArraySolidEffect;
struct ILampArraySolidEffectFactory;
struct ILampArrayUpdateRequestedEventArgs;
struct LampArrayBitmapEffect;
struct LampArrayBitmapRequestedEventArgs;
struct LampArrayBlinkEffect;
struct LampArrayColorRampEffect;
struct LampArrayCustomEffect;
struct LampArrayEffectPlaylist;
struct LampArraySolidEffect;
struct LampArrayUpdateRequestedEventArgs;

}

namespace winrt::impl {

template <> struct category<Windows::Devices::Lights::Effects::ILampArrayBitmapEffect>{ using type = interface_category; };
template <> struct category<Windows::Devices::Lights::Effects::ILampArrayBitmapEffectFactory>{ using type = interface_category; };
template <> struct category<Windows::Devices::Lights::Effects::ILampArrayBitmapRequestedEventArgs>{ using type = interface_category; };
template <> struct category<Windows::Devices::Lights::Effects::ILampArrayBlinkEffect>{ using type = interface_category; };
template <> struct category<Windows::Devices::Lights::Effects::ILampArrayBlinkEffectFactory>{ using type = interface_category; };
template <> struct category<Windows::Devices::Lights::Effects::ILampArrayColorRampEffect>{ using type = interface_category; };
template <> struct category<Windows::Devices::Lights::Effects::ILampArrayColorRampEffectFactory>{ using type = interface_category; };
template <> struct category<Windows::Devices::Lights::Effects::ILampArrayCustomEffect>{ using type = interface_category; };
template <> struct category<Windows::Devices::Lights::Effects::ILampArrayCustomEffectFactory>{ using type = interface_category; };
template <> struct category<Windows::Devices::Lights::Effects::ILampArrayEffect>{ using type = interface_category; };
template <> struct category<Windows::Devices::Lights::Effects::ILampArrayEffectPlaylist>{ using type = interface_category; };
template <> struct category<Windows::Devices::Lights::Effects::ILampArrayEffectPlaylistStatics>{ using type = interface_category; };
template <> struct category<Windows::Devices::Lights::Effects::ILampArraySolidEffect>{ using type = interface_category; };
template <> struct category<Windows::Devices::Lights::Effects::ILampArraySolidEffectFactory>{ using type = interface_category; };
template <> struct category<Windows::Devices::Lights::Effects::ILampArrayUpdateRequestedEventArgs>{ using type = interface_category; };
template <> struct category<Windows::Devices::Lights::Effects::LampArrayBitmapEffect>{ using type = class_category; };
template <> struct category<Windows::Devices::Lights::Effects::LampArrayBitmapRequestedEventArgs>{ using type = class_category; };
template <> struct category<Windows::Devices::Lights::Effects::LampArrayBlinkEffect>{ using type = class_category; };
template <> struct category<Windows::Devices::Lights::Effects::LampArrayColorRampEffect>{ using type = class_category; };
template <> struct category<Windows::Devices::Lights::Effects::LampArrayCustomEffect>{ using type = class_category; };
template <> struct category<Windows::Devices::Lights::Effects::LampArrayEffectPlaylist>{ using type = class_category; };
template <> struct category<Windows::Devices::Lights::Effects::LampArraySolidEffect>{ using type = class_category; };
template <> struct category<Windows::Devices::Lights::Effects::LampArrayUpdateRequestedEventArgs>{ using type = class_category; };
template <> struct category<Windows::Devices::Lights::Effects::LampArrayEffectCompletionBehavior>{ using type = enum_category; };
template <> struct category<Windows::Devices::Lights::Effects::LampArrayEffectStartMode>{ using type = enum_category; };
template <> struct category<Windows::Devices::Lights::Effects::LampArrayRepetitionMode>{ using type = enum_category; };
template <> struct name<Windows::Devices::Lights::Effects::ILampArrayBitmapEffect>{ static constexpr auto & value{ L"Windows.Devices.Lights.Effects.ILampArrayBitmapEffect" }; };
template <> struct name<Windows::Devices::Lights::Effects::ILampArrayBitmapEffectFactory>{ static constexpr auto & value{ L"Windows.Devices.Lights.Effects.ILampArrayBitmapEffectFactory" }; };
template <> struct name<Windows::Devices::Lights::Effects::ILampArrayBitmapRequestedEventArgs>{ static constexpr auto & value{ L"Windows.Devices.Lights.Effects.ILampArrayBitmapRequestedEventArgs" }; };
template <> struct name<Windows::Devices::Lights::Effects::ILampArrayBlinkEffect>{ static constexpr auto & value{ L"Windows.Devices.Lights.Effects.ILampArrayBlinkEffect" }; };
template <> struct name<Windows::Devices::Lights::Effects::ILampArrayBlinkEffectFactory>{ static constexpr auto & value{ L"Windows.Devices.Lights.Effects.ILampArrayBlinkEffectFactory" }; };
template <> struct name<Windows::Devices::Lights::Effects::ILampArrayColorRampEffect>{ static constexpr auto & value{ L"Windows.Devices.Lights.Effects.ILampArrayColorRampEffect" }; };
template <> struct name<Windows::Devices::Lights::Effects::ILampArrayColorRampEffectFactory>{ static constexpr auto & value{ L"Windows.Devices.Lights.Effects.ILampArrayColorRampEffectFactory" }; };
template <> struct name<Windows::Devices::Lights::Effects::ILampArrayCustomEffect>{ static constexpr auto & value{ L"Windows.Devices.Lights.Effects.ILampArrayCustomEffect" }; };
template <> struct name<Windows::Devices::Lights::Effects::ILampArrayCustomEffectFactory>{ static constexpr auto & value{ L"Windows.Devices.Lights.Effects.ILampArrayCustomEffectFactory" }; };
template <> struct name<Windows::Devices::Lights::Effects::ILampArrayEffect>{ static constexpr auto & value{ L"Windows.Devices.Lights.Effects.ILampArrayEffect" }; };
template <> struct name<Windows::Devices::Lights::Effects::ILampArrayEffectPlaylist>{ static constexpr auto & value{ L"Windows.Devices.Lights.Effects.ILampArrayEffectPlaylist" }; };
template <> struct name<Windows::Devices::Lights::Effects::ILampArrayEffectPlaylistStatics>{ static constexpr auto & value{ L"Windows.Devices.Lights.Effects.ILampArrayEffectPlaylistStatics" }; };
template <> struct name<Windows::Devices::Lights::Effects::ILampArraySolidEffect>{ static constexpr auto & value{ L"Windows.Devices.Lights.Effects.ILampArraySolidEffect" }; };
template <> struct name<Windows::Devices::Lights::Effects::ILampArraySolidEffectFactory>{ static constexpr auto & value{ L"Windows.Devices.Lights.Effects.ILampArraySolidEffectFactory" }; };
template <> struct name<Windows::Devices::Lights::Effects::ILampArrayUpdateRequestedEventArgs>{ static constexpr auto & value{ L"Windows.Devices.Lights.Effects.ILampArrayUpdateRequestedEventArgs" }; };
template <> struct name<Windows::Devices::Lights::Effects::LampArrayBitmapEffect>{ static constexpr auto & value{ L"Windows.Devices.Lights.Effects.LampArrayBitmapEffect" }; };
template <> struct name<Windows::Devices::Lights::Effects::LampArrayBitmapRequestedEventArgs>{ static constexpr auto & value{ L"Windows.Devices.Lights.Effects.LampArrayBitmapRequestedEventArgs" }; };
template <> struct name<Windows::Devices::Lights::Effects::LampArrayBlinkEffect>{ static constexpr auto & value{ L"Windows.Devices.Lights.Effects.LampArrayBlinkEffect" }; };
template <> struct name<Windows::Devices::Lights::Effects::LampArrayColorRampEffect>{ static constexpr auto & value{ L"Windows.Devices.Lights.Effects.LampArrayColorRampEffect" }; };
template <> struct name<Windows::Devices::Lights::Effects::LampArrayCustomEffect>{ static constexpr auto & value{ L"Windows.Devices.Lights.Effects.LampArrayCustomEffect" }; };
template <> struct name<Windows::Devices::Lights::Effects::LampArrayEffectPlaylist>{ static constexpr auto & value{ L"Windows.Devices.Lights.Effects.LampArrayEffectPlaylist" }; };
template <> struct name<Windows::Devices::Lights::Effects::LampArraySolidEffect>{ static constexpr auto & value{ L"Windows.Devices.Lights.Effects.LampArraySolidEffect" }; };
template <> struct name<Windows::Devices::Lights::Effects::LampArrayUpdateRequestedEventArgs>{ static constexpr auto & value{ L"Windows.Devices.Lights.Effects.LampArrayUpdateRequestedEventArgs" }; };
template <> struct name<Windows::Devices::Lights::Effects::LampArrayEffectCompletionBehavior>{ static constexpr auto & value{ L"Windows.Devices.Lights.Effects.LampArrayEffectCompletionBehavior" }; };
template <> struct name<Windows::Devices::Lights::Effects::LampArrayEffectStartMode>{ static constexpr auto & value{ L"Windows.Devices.Lights.Effects.LampArrayEffectStartMode" }; };
template <> struct name<Windows::Devices::Lights::Effects::LampArrayRepetitionMode>{ static constexpr auto & value{ L"Windows.Devices.Lights.Effects.LampArrayRepetitionMode" }; };
template <> struct guid_storage<Windows::Devices::Lights::Effects::ILampArrayBitmapEffect>{ static constexpr guid value{ 0x3238E065,0xD877,0x4627,{ 0x89,0xE5,0x2A,0x88,0xF7,0x05,0x2F,0xA6 } }; };
template <> struct guid_storage<Windows::Devices::Lights::Effects::ILampArrayBitmapEffectFactory>{ static constexpr guid value{ 0x13608090,0xE336,0x4C8F,{ 0x90,0x53,0xA9,0x24,0x07,0xCA,0x7B,0x1D } }; };
template <> struct guid_storage<Windows::Devices::Lights::Effects::ILampArrayBitmapRequestedEventArgs>{ static constexpr guid value{ 0xC8B4AF9E,0xFE63,0x4D51,{ 0xBA,0xBD,0x61,0x9D,0xEF,0xB4,0x54,0xBA } }; };
template <> struct guid_storage<Windows::Devices::Lights::Effects::ILampArrayBlinkEffect>{ static constexpr guid value{ 0xEBBF35F6,0x2FC5,0x4BB3,{ 0xB3,0xC3,0x62,0x21,0xA7,0x68,0x0D,0x13 } }; };
template <> struct guid_storage<Windows::Devices::Lights::Effects::ILampArrayBlinkEffectFactory>{ static constexpr guid value{ 0x879F1D97,0x9F50,0x49B2,{ 0xA5,0x6F,0x01,0x3A,0xA0,0x8D,0x55,0xE0 } }; };
template <> struct guid_storage<Windows::Devices::Lights::Effects::ILampArrayColorRampEffect>{ static constexpr guid value{ 0x2B004437,0x40A7,0x432E,{ 0xA0,0xB9,0x0D,0x57,0x0C,0x21,0x53,0xFF } }; };
template <> struct guid_storage<Windows::Devices::Lights::Effects::ILampArrayColorRampEffectFactory>{ static constexpr guid value{ 0x520BD133,0x0C74,0x4DF5,{ 0xBE,0xA7,0x48,0x99,0xE0,0x26,0x6B,0x0F } }; };
template <> struct guid_storage<Windows::Devices::Lights::Effects::ILampArrayCustomEffect>{ static constexpr guid value{ 0xEC579170,0x3C34,0x4876,{ 0x81,0x8B,0x57,0x65,0xF7,0x8B,0x0E,0xE4 } }; };
template <> struct guid_storage<Windows::Devices::Lights::Effects::ILampArrayCustomEffectFactory>{ static constexpr guid value{ 0x68B4774D,0x63E5,0x4AF0,{ 0xA5,0x8B,0x3E,0x53,0x5B,0x94,0xE8,0xC9 } }; };
template <> struct guid_storage<Windows::Devices::Lights::Effects::ILampArrayEffect>{ static constexpr guid value{ 0x11D45590,0x57FB,0x4546,{ 0xB1,0xCE,0x86,0x31,0x07,0xF7,0x40,0xDF } }; };
template <> struct guid_storage<Windows::Devices::Lights::Effects::ILampArrayEffectPlaylist>{ static constexpr guid value{ 0x7DE58BFE,0x6F61,0x4103,{ 0x98,0xC7,0xD6,0x63,0x2F,0x7B,0x91,0x69 } }; };
template <> struct guid_storage<Windows::Devices::Lights::Effects::ILampArrayEffectPlaylistStatics>{ static constexpr guid value{ 0xFB15235C,0xEA35,0x4C7F,{ 0xA0,0x16,0xF3,0xBF,0xC6,0xA6,0xC4,0x7D } }; };
template <> struct guid_storage<Windows::Devices::Lights::Effects::ILampArraySolidEffect>{ static constexpr guid value{ 0x441F8213,0x43CC,0x4B33,{ 0x80,0xEB,0xC6,0xDD,0xDE,0x7D,0xC8,0xED } }; };
template <> struct guid_storage<Windows::Devices::Lights::Effects::ILampArraySolidEffectFactory>{ static constexpr guid value{ 0xF862A32C,0x5576,0x4341,{ 0x96,0x1B,0xAE,0xE1,0xF1,0x3C,0xF9,0xDD } }; };
template <> struct guid_storage<Windows::Devices::Lights::Effects::ILampArrayUpdateRequestedEventArgs>{ static constexpr guid value{ 0x73560D6A,0x576A,0x48AF,{ 0x85,0x39,0x67,0xFF,0xA0,0xAB,0x35,0x16 } }; };
template <> struct default_interface<Windows::Devices::Lights::Effects::LampArrayBitmapEffect>{ using type = Windows::Devices::Lights::Effects::ILampArrayBitmapEffect; };
template <> struct default_interface<Windows::Devices::Lights::Effects::LampArrayBitmapRequestedEventArgs>{ using type = Windows::Devices::Lights::Effects::ILampArrayBitmapRequestedEventArgs; };
template <> struct default_interface<Windows::Devices::Lights::Effects::LampArrayBlinkEffect>{ using type = Windows::Devices::Lights::Effects::ILampArrayBlinkEffect; };
template <> struct default_interface<Windows::Devices::Lights::Effects::LampArrayColorRampEffect>{ using type = Windows::Devices::Lights::Effects::ILampArrayColorRampEffect; };
template <> struct default_interface<Windows::Devices::Lights::Effects::LampArrayCustomEffect>{ using type = Windows::Devices::Lights::Effects::ILampArrayCustomEffect; };
template <> struct default_interface<Windows::Devices::Lights::Effects::LampArrayEffectPlaylist>{ using type = Windows::Devices::Lights::Effects::ILampArrayEffectPlaylist; };
template <> struct default_interface<Windows::Devices::Lights::Effects::LampArraySolidEffect>{ using type = Windows::Devices::Lights::Effects::ILampArraySolidEffect; };
template <> struct default_interface<Windows::Devices::Lights::Effects::LampArrayUpdateRequestedEventArgs>{ using type = Windows::Devices::Lights::Effects::ILampArrayUpdateRequestedEventArgs; };

template <> struct abi<Windows::Devices::Lights::Effects::ILampArrayBitmapEffect>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL get_Duration(Windows::Foundation::TimeSpan* value) noexcept = 0;
    virtual int32_t WINRT_CALL put_Duration(Windows::Foundation::TimeSpan value) noexcept = 0;
    virtual int32_t WINRT_CALL get_StartDelay(Windows::Foundation::TimeSpan* value) noexcept = 0;
    virtual int32_t WINRT_CALL put_StartDelay(Windows::Foundation::TimeSpan value) noexcept = 0;
    virtual int32_t WINRT_CALL get_UpdateInterval(Windows::Foundation::TimeSpan* value) noexcept = 0;
    virtual int32_t WINRT_CALL put_UpdateInterval(Windows::Foundation::TimeSpan value) noexcept = 0;
    virtual int32_t WINRT_CALL get_SuggestedBitmapSize(Windows::Foundation::Size* value) noexcept = 0;
    virtual int32_t WINRT_CALL add_BitmapRequested(void* handler, winrt::event_token* token) noexcept = 0;
    virtual int32_t WINRT_CALL remove_BitmapRequested(winrt::event_token token) noexcept = 0;
};};

template <> struct abi<Windows::Devices::Lights::Effects::ILampArrayBitmapEffectFactory>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL CreateInstance(void* lampArray, uint32_t __lampIndexesSize, int32_t* lampIndexes, void** value) noexcept = 0;
};};

template <> struct abi<Windows::Devices::Lights::Effects::ILampArrayBitmapRequestedEventArgs>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL get_SinceStarted(Windows::Foundation::TimeSpan* value) noexcept = 0;
    virtual int32_t WINRT_CALL UpdateBitmap(void* bitmap) noexcept = 0;
};};

template <> struct abi<Windows::Devices::Lights::Effects::ILampArrayBlinkEffect>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL get_Color(struct struct_Windows_UI_Color* value) noexcept = 0;
    virtual int32_t WINRT_CALL put_Color(struct struct_Windows_UI_Color value) noexcept = 0;
    virtual int32_t WINRT_CALL get_AttackDuration(Windows::Foundation::TimeSpan* value) noexcept = 0;
    virtual int32_t WINRT_CALL put_AttackDuration(Windows::Foundation::TimeSpan value) noexcept = 0;
    virtual int32_t WINRT_CALL get_SustainDuration(Windows::Foundation::TimeSpan* value) noexcept = 0;
    virtual int32_t WINRT_CALL put_SustainDuration(Windows::Foundation::TimeSpan value) noexcept = 0;
    virtual int32_t WINRT_CALL get_DecayDuration(Windows::Foundation::TimeSpan* value) noexcept = 0;
    virtual int32_t WINRT_CALL put_DecayDuration(Windows::Foundation::TimeSpan value) noexcept = 0;
    virtual int32_t WINRT_CALL get_RepetitionDelay(Windows::Foundation::TimeSpan* value) noexcept = 0;
    virtual int32_t WINRT_CALL put_RepetitionDelay(Windows::Foundation::TimeSpan value) noexcept = 0;
    virtual int32_t WINRT_CALL get_StartDelay(Windows::Foundation::TimeSpan* value) noexcept = 0;
    virtual int32_t WINRT_CALL put_StartDelay(Windows::Foundation::TimeSpan value) noexcept = 0;
    virtual int32_t WINRT_CALL get_Occurrences(int32_t* value) noexcept = 0;
    virtual int32_t WINRT_CALL put_Occurrences(int32_t value) noexcept = 0;
    virtual int32_t WINRT_CALL get_RepetitionMode(Windows::Devices::Lights::Effects::LampArrayRepetitionMode* value) noexcept = 0;
    virtual int32_t WINRT_CALL put_RepetitionMode(Windows::Devices::Lights::Effects::LampArrayRepetitionMode value) noexcept = 0;
};};

template <> struct abi<Windows::Devices::Lights::Effects::ILampArrayBlinkEffectFactory>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL CreateInstance(void* lampArray, uint32_t __lampIndexesSize, int32_t* lampIndexes, void** value) noexcept = 0;
};};

template <> struct abi<Windows::Devices::Lights::Effects::ILampArrayColorRampEffect>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL get_Color(struct struct_Windows_UI_Color* value) noexcept = 0;
    virtual int32_t WINRT_CALL put_Color(struct struct_Windows_UI_Color value) noexcept = 0;
    virtual int32_t WINRT_CALL get_RampDuration(Windows::Foundation::TimeSpan* value) noexcept = 0;
    virtual int32_t WINRT_CALL put_RampDuration(Windows::Foundation::TimeSpan value) noexcept = 0;
    virtual int32_t WINRT_CALL get_StartDelay(Windows::Foundation::TimeSpan* value) noexcept = 0;
    virtual int32_t WINRT_CALL put_StartDelay(Windows::Foundation::TimeSpan value) noexcept = 0;
    virtual int32_t WINRT_CALL get_CompletionBehavior(Windows::Devices::Lights::Effects::LampArrayEffectCompletionBehavior* value) noexcept = 0;
    virtual int32_t WINRT_CALL put_CompletionBehavior(Windows::Devices::Lights::Effects::LampArrayEffectCompletionBehavior value) noexcept = 0;
};};

template <> struct abi<Windows::Devices::Lights::Effects::ILampArrayColorRampEffectFactory>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL CreateInstance(void* lampArray, uint32_t __lampIndexesSize, int32_t* lampIndexes, void** value) noexcept = 0;
};};

template <> struct abi<Windows::Devices::Lights::Effects::ILampArrayCustomEffect>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL get_Duration(Windows::Foundation::TimeSpan* value) noexcept = 0;
    virtual int32_t WINRT_CALL put_Duration(Windows::Foundation::TimeSpan value) noexcept = 0;
    virtual int32_t WINRT_CALL get_UpdateInterval(Windows::Foundation::TimeSpan* value) noexcept = 0;
    virtual int32_t WINRT_CALL put_UpdateInterval(Windows::Foundation::TimeSpan value) noexcept = 0;
    virtual int32_t WINRT_CALL add_UpdateRequested(void* handler, winrt::event_token* token) noexcept = 0;
    virtual int32_t WINRT_CALL remove_UpdateRequested(winrt::event_token token) noexcept = 0;
};};

template <> struct abi<Windows::Devices::Lights::Effects::ILampArrayCustomEffectFactory>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL CreateInstance(void* lampArray, uint32_t __lampIndexesSize, int32_t* lampIndexes, void** value) noexcept = 0;
};};

template <> struct abi<Windows::Devices::Lights::Effects::ILampArrayEffect>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL get_ZIndex(int32_t* value) noexcept = 0;
    virtual int32_t WINRT_CALL put_ZIndex(int32_t value) noexcept = 0;
};};

template <> struct abi<Windows::Devices::Lights::Effects::ILampArrayEffectPlaylist>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL Append(void* effect) noexcept = 0;
    virtual int32_t WINRT_CALL OverrideZIndex(int32_t zIndex) noexcept = 0;
    virtual int32_t WINRT_CALL Start() noexcept = 0;
    virtual int32_t WINRT_CALL Stop() noexcept = 0;
    virtual int32_t WINRT_CALL Pause() noexcept = 0;
    virtual int32_t WINRT_CALL get_EffectStartMode(Windows::Devices::Lights::Effects::LampArrayEffectStartMode* value) noexcept = 0;
    virtual int32_t WINRT_CALL put_EffectStartMode(Windows::Devices::Lights::Effects::LampArrayEffectStartMode value) noexcept = 0;
    virtual int32_t WINRT_CALL get_Occurrences(int32_t* value) noexcept = 0;
    virtual int32_t WINRT_CALL put_Occurrences(int32_t value) noexcept = 0;
    virtual int32_t WINRT_CALL get_RepetitionMode(Windows::Devices::Lights::Effects::LampArrayRepetitionMode* value) noexcept = 0;
    virtual int32_t WINRT_CALL put_RepetitionMode(Windows::Devices::Lights::Effects::LampArrayRepetitionMode value) noexcept = 0;
};};

template <> struct abi<Windows::Devices::Lights::Effects::ILampArrayEffectPlaylistStatics>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL StartAll(void* value) noexcept = 0;
    virtual int32_t WINRT_CALL StopAll(void* value) noexcept = 0;
    virtual int32_t WINRT_CALL PauseAll(void* value) noexcept = 0;
};};

template <> struct abi<Windows::Devices::Lights::Effects::ILampArraySolidEffect>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL get_Color(struct struct_Windows_UI_Color* value) noexcept = 0;
    virtual int32_t WINRT_CALL put_Color(struct struct_Windows_UI_Color value) noexcept = 0;
    virtual int32_t WINRT_CALL get_Duration(Windows::Foundation::TimeSpan* value) noexcept = 0;
    virtual int32_t WINRT_CALL put_Duration(Windows::Foundation::TimeSpan value) noexcept = 0;
    virtual int32_t WINRT_CALL get_StartDelay(Windows::Foundation::TimeSpan* value) noexcept = 0;
    virtual int32_t WINRT_CALL put_StartDelay(Windows::Foundation::TimeSpan value) noexcept = 0;
    virtual int32_t WINRT_CALL get_CompletionBehavior(Windows::Devices::Lights::Effects::LampArrayEffectCompletionBehavior* value) noexcept = 0;
    virtual int32_t WINRT_CALL put_CompletionBehavior(Windows::Devices::Lights::Effects::LampArrayEffectCompletionBehavior value) noexcept = 0;
};};

template <> struct abi<Windows::Devices::Lights::Effects::ILampArraySolidEffectFactory>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL CreateInstance(void* lampArray, uint32_t __lampIndexesSize, int32_t* lampIndexes, void** value) noexcept = 0;
};};

template <> struct abi<Windows::Devices::Lights::Effects::ILampArrayUpdateRequestedEventArgs>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL get_SinceStarted(Windows::Foundation::TimeSpan* value) noexcept = 0;
    virtual int32_t WINRT_CALL SetColor(struct struct_Windows_UI_Color desiredColor) noexcept = 0;
    virtual int32_t WINRT_CALL SetColorForIndex(int32_t lampIndex, struct struct_Windows_UI_Color desiredColor) noexcept = 0;
    virtual int32_t WINRT_CALL SetSingleColorForIndices(struct struct_Windows_UI_Color desiredColor, uint32_t __lampIndexesSize, int32_t* lampIndexes) noexcept = 0;
    virtual int32_t WINRT_CALL SetColorsForIndices(uint32_t __desiredColorsSize, struct struct_Windows_UI_Color* desiredColors, uint32_t __lampIndexesSize, int32_t* lampIndexes) noexcept = 0;
};};

template <typename D>
struct consume_Windows_Devices_Lights_Effects_ILampArrayBitmapEffect
{
    Windows::Foundation::TimeSpan Duration() const;
    void Duration(Windows::Foundation::TimeSpan const& value) const;
    Windows::Foundation::TimeSpan StartDelay() const;
    void StartDelay(Windows::Foundation::TimeSpan const& value) const;
    Windows::Foundation::TimeSpan UpdateInterval() const;
    void UpdateInterval(Windows::Foundation::TimeSpan const& value) const;
    Windows::Foundation::Size SuggestedBitmapSize() const;
    winrt::event_token BitmapRequested(Windows::Foundation::TypedEventHandler<Windows::Devices::Lights::Effects::LampArrayBitmapEffect, Windows::Devices::Lights::Effects::LampArrayBitmapRequestedEventArgs> const& handler) const;
    using BitmapRequested_revoker = impl::event_revoker<Windows::Devices::Lights::Effects::ILampArrayBitmapEffect, &impl::abi_t<Windows::Devices::Lights::Effects::ILampArrayBitmapEffect>::remove_BitmapRequested>;
    BitmapRequested_revoker BitmapRequested(auto_revoke_t, Windows::Foundation::TypedEventHandler<Windows::Devices::Lights::Effects::LampArrayBitmapEffect, Windows::Devices::Lights::Effects::LampArrayBitmapRequestedEventArgs> const& handler) const;
    void BitmapRequested(winrt::event_token const& token) const noexcept;
};
template <> struct consume<Windows::Devices::Lights::Effects::ILampArrayBitmapEffect> { template <typename D> using type = consume_Windows_Devices_Lights_Effects_ILampArrayBitmapEffect<D>; };

template <typename D>
struct consume_Windows_Devices_Lights_Effects_ILampArrayBitmapEffectFactory
{
    Windows::Devices::Lights::Effects::LampArrayBitmapEffect CreateInstance(Windows::Devices::Lights::LampArray const& lampArray, array_view<int32_t const> lampIndexes) const;
};
template <> struct consume<Windows::Devices::Lights::Effects::ILampArrayBitmapEffectFactory> { template <typename D> using type = consume_Windows_Devices_Lights_Effects_ILampArrayBitmapEffectFactory<D>; };

template <typename D>
struct consume_Windows_Devices_Lights_Effects_ILampArrayBitmapRequestedEventArgs
{
    Windows::Foundation::TimeSpan SinceStarted() const;
    void UpdateBitmap(Windows::Graphics::Imaging::SoftwareBitmap const& bitmap) const;
};
template <> struct consume<Windows::Devices::Lights::Effects::ILampArrayBitmapRequestedEventArgs> { template <typename D> using type = consume_Windows_Devices_Lights_Effects_ILampArrayBitmapRequestedEventArgs<D>; };

template <typename D>
struct consume_Windows_Devices_Lights_Effects_ILampArrayBlinkEffect
{
    Windows::UI::Color Color() const;
    void Color(Windows::UI::Color const& value) const;
    Windows::Foundation::TimeSpan AttackDuration() const;
    void AttackDuration(Windows::Foundation::TimeSpan const& value) const;
    Windows::Foundation::TimeSpan SustainDuration() const;
    void SustainDuration(Windows::Foundation::TimeSpan const& value) const;
    Windows::Foundation::TimeSpan DecayDuration() const;
    void DecayDuration(Windows::Foundation::TimeSpan const& value) const;
    Windows::Foundation::TimeSpan RepetitionDelay() const;
    void RepetitionDelay(Windows::Foundation::TimeSpan const& value) const;
    Windows::Foundation::TimeSpan StartDelay() const;
    void StartDelay(Windows::Foundation::TimeSpan const& value) const;
    int32_t Occurrences() const;
    void Occurrences(int32_t value) const;
    Windows::Devices::Lights::Effects::LampArrayRepetitionMode RepetitionMode() const;
    void RepetitionMode(Windows::Devices::Lights::Effects::LampArrayRepetitionMode const& value) const;
};
template <> struct consume<Windows::Devices::Lights::Effects::ILampArrayBlinkEffect> { template <typename D> using type = consume_Windows_Devices_Lights_Effects_ILampArrayBlinkEffect<D>; };

template <typename D>
struct consume_Windows_Devices_Lights_Effects_ILampArrayBlinkEffectFactory
{
    Windows::Devices::Lights::Effects::LampArrayBlinkEffect CreateInstance(Windows::Devices::Lights::LampArray const& lampArray, array_view<int32_t const> lampIndexes) const;
};
template <> struct consume<Windows::Devices::Lights::Effects::ILampArrayBlinkEffectFactory> { template <typename D> using type = consume_Windows_Devices_Lights_Effects_ILampArrayBlinkEffectFactory<D>; };

template <typename D>
struct consume_Windows_Devices_Lights_Effects_ILampArrayColorRampEffect
{
    Windows::UI::Color Color() const;
    void Color(Windows::UI::Color const& value) const;
    Windows::Foundation::TimeSpan RampDuration() const;
    void RampDuration(Windows::Foundation::TimeSpan const& value) const;
    Windows::Foundation::TimeSpan StartDelay() const;
    void StartDelay(Windows::Foundation::TimeSpan const& value) const;
    Windows::Devices::Lights::Effects::LampArrayEffectCompletionBehavior CompletionBehavior() const;
    void CompletionBehavior(Windows::Devices::Lights::Effects::LampArrayEffectCompletionBehavior const& value) const;
};
template <> struct consume<Windows::Devices::Lights::Effects::ILampArrayColorRampEffect> { template <typename D> using type = consume_Windows_Devices_Lights_Effects_ILampArrayColorRampEffect<D>; };

template <typename D>
struct consume_Windows_Devices_Lights_Effects_ILampArrayColorRampEffectFactory
{
    Windows::Devices::Lights::Effects::LampArrayColorRampEffect CreateInstance(Windows::Devices::Lights::LampArray const& lampArray, array_view<int32_t const> lampIndexes) const;
};
template <> struct consume<Windows::Devices::Lights::Effects::ILampArrayColorRampEffectFactory> { template <typename D> using type = consume_Windows_Devices_Lights_Effects_ILampArrayColorRampEffectFactory<D>; };

template <typename D>
struct consume_Windows_Devices_Lights_Effects_ILampArrayCustomEffect
{
    Windows::Foundation::TimeSpan Duration() const;
    void Duration(Windows::Foundation::TimeSpan const& value) const;
    Windows::Foundation::TimeSpan UpdateInterval() const;
    void UpdateInterval(Windows::Foundation::TimeSpan const& value) const;
    winrt::event_token UpdateRequested(Windows::Foundation::TypedEventHandler<Windows::Devices::Lights::Effects::LampArrayCustomEffect, Windows::Devices::Lights::Effects::LampArrayUpdateRequestedEventArgs> const& handler) const;
    using UpdateRequested_revoker = impl::event_revoker<Windows::Devices::Lights::Effects::ILampArrayCustomEffect, &impl::abi_t<Windows::Devices::Lights::Effects::ILampArrayCustomEffect>::remove_UpdateRequested>;
    UpdateRequested_revoker UpdateRequested(auto_revoke_t, Windows::Foundation::TypedEventHandler<Windows::Devices::Lights::Effects::LampArrayCustomEffect, Windows::Devices::Lights::Effects::LampArrayUpdateRequestedEventArgs> const& handler) const;
    void UpdateRequested(winrt::event_token const& token) const noexcept;
};
template <> struct consume<Windows::Devices::Lights::Effects::ILampArrayCustomEffect> { template <typename D> using type = consume_Windows_Devices_Lights_Effects_ILampArrayCustomEffect<D>; };

template <typename D>
struct consume_Windows_Devices_Lights_Effects_ILampArrayCustomEffectFactory
{
    Windows::Devices::Lights::Effects::LampArrayCustomEffect CreateInstance(Windows::Devices::Lights::LampArray const& lampArray, array_view<int32_t const> lampIndexes) const;
};
template <> struct consume<Windows::Devices::Lights::Effects::ILampArrayCustomEffectFactory> { template <typename D> using type = consume_Windows_Devices_Lights_Effects_ILampArrayCustomEffectFactory<D>; };

template <typename D>
struct consume_Windows_Devices_Lights_Effects_ILampArrayEffect
{
    int32_t ZIndex() const;
    void ZIndex(int32_t value) const;
};
template <> struct consume<Windows::Devices::Lights::Effects::ILampArrayEffect> { template <typename D> using type = consume_Windows_Devices_Lights_Effects_ILampArrayEffect<D>; };

template <typename D>
struct consume_Windows_Devices_Lights_Effects_ILampArrayEffectPlaylist
{
    void Append(Windows::Devices::Lights::Effects::ILampArrayEffect const& effect) const;
    void OverrideZIndex(int32_t zIndex) const;
    void Start() const;
    void Stop() const;
    void Pause() const;
    Windows::Devices::Lights::Effects::LampArrayEffectStartMode EffectStartMode() const;
    void EffectStartMode(Windows::Devices::Lights::Effects::LampArrayEffectStartMode const& value) const;
    int32_t Occurrences() const;
    void Occurrences(int32_t value) const;
    Windows::Devices::Lights::Effects::LampArrayRepetitionMode RepetitionMode() const;
    void RepetitionMode(Windows::Devices::Lights::Effects::LampArrayRepetitionMode const& value) const;
};
template <> struct consume<Windows::Devices::Lights::Effects::ILampArrayEffectPlaylist> { template <typename D> using type = consume_Windows_Devices_Lights_Effects_ILampArrayEffectPlaylist<D>; };

template <typename D>
struct consume_Windows_Devices_Lights_Effects_ILampArrayEffectPlaylistStatics
{
    void StartAll(param::iterable<Windows::Devices::Lights::Effects::LampArrayEffectPlaylist> const& value) const;
    void StopAll(param::iterable<Windows::Devices::Lights::Effects::LampArrayEffectPlaylist> const& value) const;
    void PauseAll(param::iterable<Windows::Devices::Lights::Effects::LampArrayEffectPlaylist> const& value) const;
};
template <> struct consume<Windows::Devices::Lights::Effects::ILampArrayEffectPlaylistStatics> { template <typename D> using type = consume_Windows_Devices_Lights_Effects_ILampArrayEffectPlaylistStatics<D>; };

template <typename D>
struct consume_Windows_Devices_Lights_Effects_ILampArraySolidEffect
{
    Windows::UI::Color Color() const;
    void Color(Windows::UI::Color const& value) const;
    Windows::Foundation::TimeSpan Duration() const;
    void Duration(Windows::Foundation::TimeSpan const& value) const;
    Windows::Foundation::TimeSpan StartDelay() const;
    void StartDelay(Windows::Foundation::TimeSpan const& value) const;
    Windows::Devices::Lights::Effects::LampArrayEffectCompletionBehavior CompletionBehavior() const;
    void CompletionBehavior(Windows::Devices::Lights::Effects::LampArrayEffectCompletionBehavior const& value) const;
};
template <> struct consume<Windows::Devices::Lights::Effects::ILampArraySolidEffect> { template <typename D> using type = consume_Windows_Devices_Lights_Effects_ILampArraySolidEffect<D>; };

template <typename D>
struct consume_Windows_Devices_Lights_Effects_ILampArraySolidEffectFactory
{
    Windows::Devices::Lights::Effects::LampArraySolidEffect CreateInstance(Windows::Devices::Lights::LampArray const& lampArray, array_view<int32_t const> lampIndexes) const;
};
template <> struct consume<Windows::Devices::Lights::Effects::ILampArraySolidEffectFactory> { template <typename D> using type = consume_Windows_Devices_Lights_Effects_ILampArraySolidEffectFactory<D>; };

template <typename D>
struct consume_Windows_Devices_Lights_Effects_ILampArrayUpdateRequestedEventArgs
{
    Windows::Foundation::TimeSpan SinceStarted() const;
    void SetColor(Windows::UI::Color const& desiredColor) const;
    void SetColorForIndex(int32_t lampIndex, Windows::UI::Color const& desiredColor) const;
    void SetSingleColorForIndices(Windows::UI::Color const& desiredColor, array_view<int32_t const> lampIndexes) const;
    void SetColorsForIndices(array_view<Windows::UI::Color const> desiredColors, array_view<int32_t const> lampIndexes) const;
};
template <> struct consume<Windows::Devices::Lights::Effects::ILampArrayUpdateRequestedEventArgs> { template <typename D> using type = consume_Windows_Devices_Lights_Effects_ILampArrayUpdateRequestedEventArgs<D>; };

}
