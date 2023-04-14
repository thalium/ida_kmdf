// C++/WinRT v1.0.190111.3

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#pragma once

WINRT_EXPORT namespace winrt::Windows::Media {

enum class SoundLevel;

}

WINRT_EXPORT namespace winrt::Windows::Media::Core::Preview {

struct ISoundLevelBrokerStatics;
struct SoundLevelBroker;

}

namespace winrt::impl {

template <> struct category<Windows::Media::Core::Preview::ISoundLevelBrokerStatics>{ using type = interface_category; };
template <> struct category<Windows::Media::Core::Preview::SoundLevelBroker>{ using type = class_category; };
template <> struct name<Windows::Media::Core::Preview::ISoundLevelBrokerStatics>{ static constexpr auto & value{ L"Windows.Media.Core.Preview.ISoundLevelBrokerStatics" }; };
template <> struct name<Windows::Media::Core::Preview::SoundLevelBroker>{ static constexpr auto & value{ L"Windows.Media.Core.Preview.SoundLevelBroker" }; };
template <> struct guid_storage<Windows::Media::Core::Preview::ISoundLevelBrokerStatics>{ static constexpr guid value{ 0x6A633961,0xDBED,0x464C,{ 0xA0,0x9A,0x33,0x41,0x2F,0x5C,0xAA,0x3F } }; };

template <> struct abi<Windows::Media::Core::Preview::ISoundLevelBrokerStatics>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL get_SoundLevel(Windows::Media::SoundLevel* value) noexcept = 0;
    virtual int32_t WINRT_CALL add_SoundLevelChanged(void* handler, winrt::event_token* token) noexcept = 0;
    virtual int32_t WINRT_CALL remove_SoundLevelChanged(winrt::event_token token) noexcept = 0;
};};

template <typename D>
struct consume_Windows_Media_Core_Preview_ISoundLevelBrokerStatics
{
    Windows::Media::SoundLevel SoundLevel() const;
    winrt::event_token SoundLevelChanged(Windows::Foundation::EventHandler<Windows::Foundation::IInspectable> const& handler) const;
    using SoundLevelChanged_revoker = impl::event_revoker<Windows::Media::Core::Preview::ISoundLevelBrokerStatics, &impl::abi_t<Windows::Media::Core::Preview::ISoundLevelBrokerStatics>::remove_SoundLevelChanged>;
    SoundLevelChanged_revoker SoundLevelChanged(auto_revoke_t, Windows::Foundation::EventHandler<Windows::Foundation::IInspectable> const& handler) const;
    void SoundLevelChanged(winrt::event_token const& token) const noexcept;
};
template <> struct consume<Windows::Media::Core::Preview::ISoundLevelBrokerStatics> { template <typename D> using type = consume_Windows_Media_Core_Preview_ISoundLevelBrokerStatics<D>; };

}
