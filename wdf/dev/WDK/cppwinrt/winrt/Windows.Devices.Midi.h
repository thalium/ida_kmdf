// C++/WinRT v1.0.190111.3

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#pragma once

#include "winrt/base.h"

#include "winrt/Windows.Foundation.h"
#include "winrt/Windows.Foundation.Collections.h"
#include "winrt/impl/Windows.Devices.Enumeration.2.h"
#include "winrt/impl/Windows.Storage.Streams.2.h"
#include "winrt/impl/Windows.Foundation.2.h"
#include "winrt/impl/Windows.Devices.Midi.2.h"
#include "winrt/Windows.Devices.h"

namespace winrt::impl {

template <typename D> uint8_t consume_Windows_Devices_Midi_IMidiChannelPressureMessage<D>::Channel() const
{
    uint8_t value{};
    check_hresult(WINRT_SHIM(Windows::Devices::Midi::IMidiChannelPressureMessage)->get_Channel(&value));
    return value;
}

template <typename D> uint8_t consume_Windows_Devices_Midi_IMidiChannelPressureMessage<D>::Pressure() const
{
    uint8_t value{};
    check_hresult(WINRT_SHIM(Windows::Devices::Midi::IMidiChannelPressureMessage)->get_Pressure(&value));
    return value;
}

template <typename D> Windows::Devices::Midi::MidiChannelPressureMessage consume_Windows_Devices_Midi_IMidiChannelPressureMessageFactory<D>::CreateMidiChannelPressureMessage(uint8_t channel, uint8_t pressure) const
{
    Windows::Devices::Midi::MidiChannelPressureMessage value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Devices::Midi::IMidiChannelPressureMessageFactory)->CreateMidiChannelPressureMessage(channel, pressure, put_abi(value)));
    return value;
}

template <typename D> uint8_t consume_Windows_Devices_Midi_IMidiControlChangeMessage<D>::Channel() const
{
    uint8_t value{};
    check_hresult(WINRT_SHIM(Windows::Devices::Midi::IMidiControlChangeMessage)->get_Channel(&value));
    return value;
}

template <typename D> uint8_t consume_Windows_Devices_Midi_IMidiControlChangeMessage<D>::Controller() const
{
    uint8_t value{};
    check_hresult(WINRT_SHIM(Windows::Devices::Midi::IMidiControlChangeMessage)->get_Controller(&value));
    return value;
}

template <typename D> uint8_t consume_Windows_Devices_Midi_IMidiControlChangeMessage<D>::ControlValue() const
{
    uint8_t value{};
    check_hresult(WINRT_SHIM(Windows::Devices::Midi::IMidiControlChangeMessage)->get_ControlValue(&value));
    return value;
}

template <typename D> Windows::Devices::Midi::MidiControlChangeMessage consume_Windows_Devices_Midi_IMidiControlChangeMessageFactory<D>::CreateMidiControlChangeMessage(uint8_t channel, uint8_t controller, uint8_t controlValue) const
{
    Windows::Devices::Midi::MidiControlChangeMessage value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Devices::Midi::IMidiControlChangeMessageFactory)->CreateMidiControlChangeMessage(channel, controller, controlValue, put_abi(value)));
    return value;
}

template <typename D> winrt::event_token consume_Windows_Devices_Midi_IMidiInPort<D>::MessageReceived(Windows::Foundation::TypedEventHandler<Windows::Devices::Midi::MidiInPort, Windows::Devices::Midi::MidiMessageReceivedEventArgs> const& handler) const
{
    winrt::event_token token{};
    check_hresult(WINRT_SHIM(Windows::Devices::Midi::IMidiInPort)->add_MessageReceived(get_abi(handler), put_abi(token)));
    return token;
}

template <typename D> typename consume_Windows_Devices_Midi_IMidiInPort<D>::MessageReceived_revoker consume_Windows_Devices_Midi_IMidiInPort<D>::MessageReceived(auto_revoke_t, Windows::Foundation::TypedEventHandler<Windows::Devices::Midi::MidiInPort, Windows::Devices::Midi::MidiMessageReceivedEventArgs> const& handler) const
{
    return impl::make_event_revoker<D, MessageReceived_revoker>(this, MessageReceived(handler));
}

template <typename D> void consume_Windows_Devices_Midi_IMidiInPort<D>::MessageReceived(winrt::event_token const& token) const noexcept
{
    WINRT_VERIFY_(0, WINRT_SHIM(Windows::Devices::Midi::IMidiInPort)->remove_MessageReceived(get_abi(token)));
}

template <typename D> hstring consume_Windows_Devices_Midi_IMidiInPort<D>::DeviceId() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Devices::Midi::IMidiInPort)->get_DeviceId(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::IAsyncOperation<Windows::Devices::Midi::MidiInPort> consume_Windows_Devices_Midi_IMidiInPortStatics<D>::FromIdAsync(param::hstring const& deviceId) const
{
    Windows::Foundation::IAsyncOperation<Windows::Devices::Midi::MidiInPort> value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Devices::Midi::IMidiInPortStatics)->FromIdAsync(get_abi(deviceId), put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_Devices_Midi_IMidiInPortStatics<D>::GetDeviceSelector() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Devices::Midi::IMidiInPortStatics)->GetDeviceSelector(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::TimeSpan consume_Windows_Devices_Midi_IMidiMessage<D>::Timestamp() const
{
    Windows::Foundation::TimeSpan value{};
    check_hresult(WINRT_SHIM(Windows::Devices::Midi::IMidiMessage)->get_Timestamp(put_abi(value)));
    return value;
}

template <typename D> Windows::Storage::Streams::IBuffer consume_Windows_Devices_Midi_IMidiMessage<D>::RawData() const
{
    Windows::Storage::Streams::IBuffer value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Devices::Midi::IMidiMessage)->get_RawData(put_abi(value)));
    return value;
}

template <typename D> Windows::Devices::Midi::MidiMessageType consume_Windows_Devices_Midi_IMidiMessage<D>::Type() const
{
    Windows::Devices::Midi::MidiMessageType value{};
    check_hresult(WINRT_SHIM(Windows::Devices::Midi::IMidiMessage)->get_Type(put_abi(value)));
    return value;
}

template <typename D> Windows::Devices::Midi::IMidiMessage consume_Windows_Devices_Midi_IMidiMessageReceivedEventArgs<D>::Message() const
{
    Windows::Devices::Midi::IMidiMessage value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Devices::Midi::IMidiMessageReceivedEventArgs)->get_Message(put_abi(value)));
    return value;
}

template <typename D> uint8_t consume_Windows_Devices_Midi_IMidiNoteOffMessage<D>::Channel() const
{
    uint8_t value{};
    check_hresult(WINRT_SHIM(Windows::Devices::Midi::IMidiNoteOffMessage)->get_Channel(&value));
    return value;
}

template <typename D> uint8_t consume_Windows_Devices_Midi_IMidiNoteOffMessage<D>::Note() const
{
    uint8_t value{};
    check_hresult(WINRT_SHIM(Windows::Devices::Midi::IMidiNoteOffMessage)->get_Note(&value));
    return value;
}

template <typename D> uint8_t consume_Windows_Devices_Midi_IMidiNoteOffMessage<D>::Velocity() const
{
    uint8_t value{};
    check_hresult(WINRT_SHIM(Windows::Devices::Midi::IMidiNoteOffMessage)->get_Velocity(&value));
    return value;
}

template <typename D> Windows::Devices::Midi::MidiNoteOffMessage consume_Windows_Devices_Midi_IMidiNoteOffMessageFactory<D>::CreateMidiNoteOffMessage(uint8_t channel, uint8_t note, uint8_t velocity) const
{
    Windows::Devices::Midi::MidiNoteOffMessage value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Devices::Midi::IMidiNoteOffMessageFactory)->CreateMidiNoteOffMessage(channel, note, velocity, put_abi(value)));
    return value;
}

template <typename D> uint8_t consume_Windows_Devices_Midi_IMidiNoteOnMessage<D>::Channel() const
{
    uint8_t value{};
    check_hresult(WINRT_SHIM(Windows::Devices::Midi::IMidiNoteOnMessage)->get_Channel(&value));
    return value;
}

template <typename D> uint8_t consume_Windows_Devices_Midi_IMidiNoteOnMessage<D>::Note() const
{
    uint8_t value{};
    check_hresult(WINRT_SHIM(Windows::Devices::Midi::IMidiNoteOnMessage)->get_Note(&value));
    return value;
}

template <typename D> uint8_t consume_Windows_Devices_Midi_IMidiNoteOnMessage<D>::Velocity() const
{
    uint8_t value{};
    check_hresult(WINRT_SHIM(Windows::Devices::Midi::IMidiNoteOnMessage)->get_Velocity(&value));
    return value;
}

template <typename D> Windows::Devices::Midi::MidiNoteOnMessage consume_Windows_Devices_Midi_IMidiNoteOnMessageFactory<D>::CreateMidiNoteOnMessage(uint8_t channel, uint8_t note, uint8_t velocity) const
{
    Windows::Devices::Midi::MidiNoteOnMessage value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Devices::Midi::IMidiNoteOnMessageFactory)->CreateMidiNoteOnMessage(channel, note, velocity, put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_Devices_Midi_IMidiOutPort<D>::SendMessage(Windows::Devices::Midi::IMidiMessage const& midiMessage) const
{
    check_hresult(WINRT_SHIM(Windows::Devices::Midi::IMidiOutPort)->SendMessage(get_abi(midiMessage)));
}

template <typename D> void consume_Windows_Devices_Midi_IMidiOutPort<D>::SendBuffer(Windows::Storage::Streams::IBuffer const& midiData) const
{
    check_hresult(WINRT_SHIM(Windows::Devices::Midi::IMidiOutPort)->SendBuffer(get_abi(midiData)));
}

template <typename D> hstring consume_Windows_Devices_Midi_IMidiOutPort<D>::DeviceId() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Devices::Midi::IMidiOutPort)->get_DeviceId(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::IAsyncOperation<Windows::Devices::Midi::IMidiOutPort> consume_Windows_Devices_Midi_IMidiOutPortStatics<D>::FromIdAsync(param::hstring const& deviceId) const
{
    Windows::Foundation::IAsyncOperation<Windows::Devices::Midi::IMidiOutPort> value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Devices::Midi::IMidiOutPortStatics)->FromIdAsync(get_abi(deviceId), put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_Devices_Midi_IMidiOutPortStatics<D>::GetDeviceSelector() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Devices::Midi::IMidiOutPortStatics)->GetDeviceSelector(put_abi(value)));
    return value;
}

template <typename D> uint8_t consume_Windows_Devices_Midi_IMidiPitchBendChangeMessage<D>::Channel() const
{
    uint8_t value{};
    check_hresult(WINRT_SHIM(Windows::Devices::Midi::IMidiPitchBendChangeMessage)->get_Channel(&value));
    return value;
}

template <typename D> uint16_t consume_Windows_Devices_Midi_IMidiPitchBendChangeMessage<D>::Bend() const
{
    uint16_t value{};
    check_hresult(WINRT_SHIM(Windows::Devices::Midi::IMidiPitchBendChangeMessage)->get_Bend(&value));
    return value;
}

template <typename D> Windows::Devices::Midi::MidiPitchBendChangeMessage consume_Windows_Devices_Midi_IMidiPitchBendChangeMessageFactory<D>::CreateMidiPitchBendChangeMessage(uint8_t channel, uint16_t bend) const
{
    Windows::Devices::Midi::MidiPitchBendChangeMessage value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Devices::Midi::IMidiPitchBendChangeMessageFactory)->CreateMidiPitchBendChangeMessage(channel, bend, put_abi(value)));
    return value;
}

template <typename D> uint8_t consume_Windows_Devices_Midi_IMidiPolyphonicKeyPressureMessage<D>::Channel() const
{
    uint8_t value{};
    check_hresult(WINRT_SHIM(Windows::Devices::Midi::IMidiPolyphonicKeyPressureMessage)->get_Channel(&value));
    return value;
}

template <typename D> uint8_t consume_Windows_Devices_Midi_IMidiPolyphonicKeyPressureMessage<D>::Note() const
{
    uint8_t value{};
    check_hresult(WINRT_SHIM(Windows::Devices::Midi::IMidiPolyphonicKeyPressureMessage)->get_Note(&value));
    return value;
}

template <typename D> uint8_t consume_Windows_Devices_Midi_IMidiPolyphonicKeyPressureMessage<D>::Pressure() const
{
    uint8_t value{};
    check_hresult(WINRT_SHIM(Windows::Devices::Midi::IMidiPolyphonicKeyPressureMessage)->get_Pressure(&value));
    return value;
}

template <typename D> Windows::Devices::Midi::MidiPolyphonicKeyPressureMessage consume_Windows_Devices_Midi_IMidiPolyphonicKeyPressureMessageFactory<D>::CreateMidiPolyphonicKeyPressureMessage(uint8_t channel, uint8_t note, uint8_t pressure) const
{
    Windows::Devices::Midi::MidiPolyphonicKeyPressureMessage value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Devices::Midi::IMidiPolyphonicKeyPressureMessageFactory)->CreateMidiPolyphonicKeyPressureMessage(channel, note, pressure, put_abi(value)));
    return value;
}

template <typename D> uint8_t consume_Windows_Devices_Midi_IMidiProgramChangeMessage<D>::Channel() const
{
    uint8_t value{};
    check_hresult(WINRT_SHIM(Windows::Devices::Midi::IMidiProgramChangeMessage)->get_Channel(&value));
    return value;
}

template <typename D> uint8_t consume_Windows_Devices_Midi_IMidiProgramChangeMessage<D>::Program() const
{
    uint8_t value{};
    check_hresult(WINRT_SHIM(Windows::Devices::Midi::IMidiProgramChangeMessage)->get_Program(&value));
    return value;
}

template <typename D> Windows::Devices::Midi::MidiProgramChangeMessage consume_Windows_Devices_Midi_IMidiProgramChangeMessageFactory<D>::CreateMidiProgramChangeMessage(uint8_t channel, uint8_t program) const
{
    Windows::Devices::Midi::MidiProgramChangeMessage value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Devices::Midi::IMidiProgramChangeMessageFactory)->CreateMidiProgramChangeMessage(channel, program, put_abi(value)));
    return value;
}

template <typename D> uint16_t consume_Windows_Devices_Midi_IMidiSongPositionPointerMessage<D>::Beats() const
{
    uint16_t value{};
    check_hresult(WINRT_SHIM(Windows::Devices::Midi::IMidiSongPositionPointerMessage)->get_Beats(&value));
    return value;
}

template <typename D> Windows::Devices::Midi::MidiSongPositionPointerMessage consume_Windows_Devices_Midi_IMidiSongPositionPointerMessageFactory<D>::CreateMidiSongPositionPointerMessage(uint16_t beats) const
{
    Windows::Devices::Midi::MidiSongPositionPointerMessage value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Devices::Midi::IMidiSongPositionPointerMessageFactory)->CreateMidiSongPositionPointerMessage(beats, put_abi(value)));
    return value;
}

template <typename D> uint8_t consume_Windows_Devices_Midi_IMidiSongSelectMessage<D>::Song() const
{
    uint8_t value{};
    check_hresult(WINRT_SHIM(Windows::Devices::Midi::IMidiSongSelectMessage)->get_Song(&value));
    return value;
}

template <typename D> Windows::Devices::Midi::MidiSongSelectMessage consume_Windows_Devices_Midi_IMidiSongSelectMessageFactory<D>::CreateMidiSongSelectMessage(uint8_t song) const
{
    Windows::Devices::Midi::MidiSongSelectMessage value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Devices::Midi::IMidiSongSelectMessageFactory)->CreateMidiSongSelectMessage(song, put_abi(value)));
    return value;
}

template <typename D> Windows::Devices::Enumeration::DeviceInformation consume_Windows_Devices_Midi_IMidiSynthesizer<D>::AudioDevice() const
{
    Windows::Devices::Enumeration::DeviceInformation value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Devices::Midi::IMidiSynthesizer)->get_AudioDevice(put_abi(value)));
    return value;
}

template <typename D> double consume_Windows_Devices_Midi_IMidiSynthesizer<D>::Volume() const
{
    double value{};
    check_hresult(WINRT_SHIM(Windows::Devices::Midi::IMidiSynthesizer)->get_Volume(&value));
    return value;
}

template <typename D> void consume_Windows_Devices_Midi_IMidiSynthesizer<D>::Volume(double value) const
{
    check_hresult(WINRT_SHIM(Windows::Devices::Midi::IMidiSynthesizer)->put_Volume(value));
}

template <typename D> Windows::Foundation::IAsyncOperation<Windows::Devices::Midi::MidiSynthesizer> consume_Windows_Devices_Midi_IMidiSynthesizerStatics<D>::CreateAsync() const
{
    Windows::Foundation::IAsyncOperation<Windows::Devices::Midi::MidiSynthesizer> value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Devices::Midi::IMidiSynthesizerStatics)->CreateAsync(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::IAsyncOperation<Windows::Devices::Midi::MidiSynthesizer> consume_Windows_Devices_Midi_IMidiSynthesizerStatics<D>::CreateAsync(Windows::Devices::Enumeration::DeviceInformation const& audioDevice) const
{
    Windows::Foundation::IAsyncOperation<Windows::Devices::Midi::MidiSynthesizer> value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Devices::Midi::IMidiSynthesizerStatics)->CreateFromAudioDeviceAsync(get_abi(audioDevice), put_abi(value)));
    return value;
}

template <typename D> bool consume_Windows_Devices_Midi_IMidiSynthesizerStatics<D>::IsSynthesizer(Windows::Devices::Enumeration::DeviceInformation const& midiDevice) const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::Devices::Midi::IMidiSynthesizerStatics)->IsSynthesizer(get_abi(midiDevice), &value));
    return value;
}

template <typename D> Windows::Devices::Midi::MidiSystemExclusiveMessage consume_Windows_Devices_Midi_IMidiSystemExclusiveMessageFactory<D>::CreateMidiSystemExclusiveMessage(Windows::Storage::Streams::IBuffer const& rawData) const
{
    Windows::Devices::Midi::MidiSystemExclusiveMessage value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Devices::Midi::IMidiSystemExclusiveMessageFactory)->CreateMidiSystemExclusiveMessage(get_abi(rawData), put_abi(value)));
    return value;
}

template <typename D> uint8_t consume_Windows_Devices_Midi_IMidiTimeCodeMessage<D>::FrameType() const
{
    uint8_t value{};
    check_hresult(WINRT_SHIM(Windows::Devices::Midi::IMidiTimeCodeMessage)->get_FrameType(&value));
    return value;
}

template <typename D> uint8_t consume_Windows_Devices_Midi_IMidiTimeCodeMessage<D>::Values() const
{
    uint8_t value{};
    check_hresult(WINRT_SHIM(Windows::Devices::Midi::IMidiTimeCodeMessage)->get_Values(&value));
    return value;
}

template <typename D> Windows::Devices::Midi::MidiTimeCodeMessage consume_Windows_Devices_Midi_IMidiTimeCodeMessageFactory<D>::CreateMidiTimeCodeMessage(uint8_t frameType, uint8_t values) const
{
    Windows::Devices::Midi::MidiTimeCodeMessage value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Devices::Midi::IMidiTimeCodeMessageFactory)->CreateMidiTimeCodeMessage(frameType, values, put_abi(value)));
    return value;
}

template <typename D>
struct produce<D, Windows::Devices::Midi::IMidiChannelPressureMessage> : produce_base<D, Windows::Devices::Midi::IMidiChannelPressureMessage>
{
    int32_t WINRT_CALL get_Channel(uint8_t* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Channel, WINRT_WRAP(uint8_t));
            *value = detach_from<uint8_t>(this->shim().Channel());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Pressure(uint8_t* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Pressure, WINRT_WRAP(uint8_t));
            *value = detach_from<uint8_t>(this->shim().Pressure());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Devices::Midi::IMidiChannelPressureMessageFactory> : produce_base<D, Windows::Devices::Midi::IMidiChannelPressureMessageFactory>
{
    int32_t WINRT_CALL CreateMidiChannelPressureMessage(uint8_t channel, uint8_t pressure, void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CreateMidiChannelPressureMessage, WINRT_WRAP(Windows::Devices::Midi::MidiChannelPressureMessage), uint8_t, uint8_t);
            *value = detach_from<Windows::Devices::Midi::MidiChannelPressureMessage>(this->shim().CreateMidiChannelPressureMessage(channel, pressure));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Devices::Midi::IMidiControlChangeMessage> : produce_base<D, Windows::Devices::Midi::IMidiControlChangeMessage>
{
    int32_t WINRT_CALL get_Channel(uint8_t* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Channel, WINRT_WRAP(uint8_t));
            *value = detach_from<uint8_t>(this->shim().Channel());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Controller(uint8_t* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Controller, WINRT_WRAP(uint8_t));
            *value = detach_from<uint8_t>(this->shim().Controller());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_ControlValue(uint8_t* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ControlValue, WINRT_WRAP(uint8_t));
            *value = detach_from<uint8_t>(this->shim().ControlValue());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Devices::Midi::IMidiControlChangeMessageFactory> : produce_base<D, Windows::Devices::Midi::IMidiControlChangeMessageFactory>
{
    int32_t WINRT_CALL CreateMidiControlChangeMessage(uint8_t channel, uint8_t controller, uint8_t controlValue, void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CreateMidiControlChangeMessage, WINRT_WRAP(Windows::Devices::Midi::MidiControlChangeMessage), uint8_t, uint8_t, uint8_t);
            *value = detach_from<Windows::Devices::Midi::MidiControlChangeMessage>(this->shim().CreateMidiControlChangeMessage(channel, controller, controlValue));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Devices::Midi::IMidiInPort> : produce_base<D, Windows::Devices::Midi::IMidiInPort>
{
    int32_t WINRT_CALL add_MessageReceived(void* handler, winrt::event_token* token) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(MessageReceived, WINRT_WRAP(winrt::event_token), Windows::Foundation::TypedEventHandler<Windows::Devices::Midi::MidiInPort, Windows::Devices::Midi::MidiMessageReceivedEventArgs> const&);
            *token = detach_from<winrt::event_token>(this->shim().MessageReceived(*reinterpret_cast<Windows::Foundation::TypedEventHandler<Windows::Devices::Midi::MidiInPort, Windows::Devices::Midi::MidiMessageReceivedEventArgs> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL remove_MessageReceived(winrt::event_token token) noexcept final
    {
        typename D::abi_guard guard(this->shim());
        WINRT_ASSERT_DECLARATION(MessageReceived, WINRT_WRAP(void), winrt::event_token const&);
        this->shim().MessageReceived(*reinterpret_cast<winrt::event_token const*>(&token));
        return 0;
    }

    int32_t WINRT_CALL get_DeviceId(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(DeviceId, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().DeviceId());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Devices::Midi::IMidiInPortStatics> : produce_base<D, Windows::Devices::Midi::IMidiInPortStatics>
{
    int32_t WINRT_CALL FromIdAsync(void* deviceId, void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(FromIdAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<Windows::Devices::Midi::MidiInPort>), hstring const);
            *value = detach_from<Windows::Foundation::IAsyncOperation<Windows::Devices::Midi::MidiInPort>>(this->shim().FromIdAsync(*reinterpret_cast<hstring const*>(&deviceId)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL GetDeviceSelector(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetDeviceSelector, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().GetDeviceSelector());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Devices::Midi::IMidiMessage> : produce_base<D, Windows::Devices::Midi::IMidiMessage>
{
    int32_t WINRT_CALL get_Timestamp(Windows::Foundation::TimeSpan* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Timestamp, WINRT_WRAP(Windows::Foundation::TimeSpan));
            *value = detach_from<Windows::Foundation::TimeSpan>(this->shim().Timestamp());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_RawData(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(RawData, WINRT_WRAP(Windows::Storage::Streams::IBuffer));
            *value = detach_from<Windows::Storage::Streams::IBuffer>(this->shim().RawData());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Type(Windows::Devices::Midi::MidiMessageType* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Type, WINRT_WRAP(Windows::Devices::Midi::MidiMessageType));
            *value = detach_from<Windows::Devices::Midi::MidiMessageType>(this->shim().Type());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Devices::Midi::IMidiMessageReceivedEventArgs> : produce_base<D, Windows::Devices::Midi::IMidiMessageReceivedEventArgs>
{
    int32_t WINRT_CALL get_Message(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Message, WINRT_WRAP(Windows::Devices::Midi::IMidiMessage));
            *value = detach_from<Windows::Devices::Midi::IMidiMessage>(this->shim().Message());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Devices::Midi::IMidiNoteOffMessage> : produce_base<D, Windows::Devices::Midi::IMidiNoteOffMessage>
{
    int32_t WINRT_CALL get_Channel(uint8_t* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Channel, WINRT_WRAP(uint8_t));
            *value = detach_from<uint8_t>(this->shim().Channel());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Note(uint8_t* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Note, WINRT_WRAP(uint8_t));
            *value = detach_from<uint8_t>(this->shim().Note());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Velocity(uint8_t* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Velocity, WINRT_WRAP(uint8_t));
            *value = detach_from<uint8_t>(this->shim().Velocity());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Devices::Midi::IMidiNoteOffMessageFactory> : produce_base<D, Windows::Devices::Midi::IMidiNoteOffMessageFactory>
{
    int32_t WINRT_CALL CreateMidiNoteOffMessage(uint8_t channel, uint8_t note, uint8_t velocity, void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CreateMidiNoteOffMessage, WINRT_WRAP(Windows::Devices::Midi::MidiNoteOffMessage), uint8_t, uint8_t, uint8_t);
            *value = detach_from<Windows::Devices::Midi::MidiNoteOffMessage>(this->shim().CreateMidiNoteOffMessage(channel, note, velocity));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Devices::Midi::IMidiNoteOnMessage> : produce_base<D, Windows::Devices::Midi::IMidiNoteOnMessage>
{
    int32_t WINRT_CALL get_Channel(uint8_t* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Channel, WINRT_WRAP(uint8_t));
            *value = detach_from<uint8_t>(this->shim().Channel());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Note(uint8_t* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Note, WINRT_WRAP(uint8_t));
            *value = detach_from<uint8_t>(this->shim().Note());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Velocity(uint8_t* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Velocity, WINRT_WRAP(uint8_t));
            *value = detach_from<uint8_t>(this->shim().Velocity());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Devices::Midi::IMidiNoteOnMessageFactory> : produce_base<D, Windows::Devices::Midi::IMidiNoteOnMessageFactory>
{
    int32_t WINRT_CALL CreateMidiNoteOnMessage(uint8_t channel, uint8_t note, uint8_t velocity, void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CreateMidiNoteOnMessage, WINRT_WRAP(Windows::Devices::Midi::MidiNoteOnMessage), uint8_t, uint8_t, uint8_t);
            *value = detach_from<Windows::Devices::Midi::MidiNoteOnMessage>(this->shim().CreateMidiNoteOnMessage(channel, note, velocity));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Devices::Midi::IMidiOutPort> : produce_base<D, Windows::Devices::Midi::IMidiOutPort>
{
    int32_t WINRT_CALL SendMessage(void* midiMessage) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SendMessage, WINRT_WRAP(void), Windows::Devices::Midi::IMidiMessage const&);
            this->shim().SendMessage(*reinterpret_cast<Windows::Devices::Midi::IMidiMessage const*>(&midiMessage));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL SendBuffer(void* midiData) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SendBuffer, WINRT_WRAP(void), Windows::Storage::Streams::IBuffer const&);
            this->shim().SendBuffer(*reinterpret_cast<Windows::Storage::Streams::IBuffer const*>(&midiData));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_DeviceId(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(DeviceId, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().DeviceId());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Devices::Midi::IMidiOutPortStatics> : produce_base<D, Windows::Devices::Midi::IMidiOutPortStatics>
{
    int32_t WINRT_CALL FromIdAsync(void* deviceId, void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(FromIdAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<Windows::Devices::Midi::IMidiOutPort>), hstring const);
            *value = detach_from<Windows::Foundation::IAsyncOperation<Windows::Devices::Midi::IMidiOutPort>>(this->shim().FromIdAsync(*reinterpret_cast<hstring const*>(&deviceId)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL GetDeviceSelector(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetDeviceSelector, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().GetDeviceSelector());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Devices::Midi::IMidiPitchBendChangeMessage> : produce_base<D, Windows::Devices::Midi::IMidiPitchBendChangeMessage>
{
    int32_t WINRT_CALL get_Channel(uint8_t* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Channel, WINRT_WRAP(uint8_t));
            *value = detach_from<uint8_t>(this->shim().Channel());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Bend(uint16_t* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Bend, WINRT_WRAP(uint16_t));
            *value = detach_from<uint16_t>(this->shim().Bend());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Devices::Midi::IMidiPitchBendChangeMessageFactory> : produce_base<D, Windows::Devices::Midi::IMidiPitchBendChangeMessageFactory>
{
    int32_t WINRT_CALL CreateMidiPitchBendChangeMessage(uint8_t channel, uint16_t bend, void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CreateMidiPitchBendChangeMessage, WINRT_WRAP(Windows::Devices::Midi::MidiPitchBendChangeMessage), uint8_t, uint16_t);
            *value = detach_from<Windows::Devices::Midi::MidiPitchBendChangeMessage>(this->shim().CreateMidiPitchBendChangeMessage(channel, bend));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Devices::Midi::IMidiPolyphonicKeyPressureMessage> : produce_base<D, Windows::Devices::Midi::IMidiPolyphonicKeyPressureMessage>
{
    int32_t WINRT_CALL get_Channel(uint8_t* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Channel, WINRT_WRAP(uint8_t));
            *value = detach_from<uint8_t>(this->shim().Channel());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Note(uint8_t* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Note, WINRT_WRAP(uint8_t));
            *value = detach_from<uint8_t>(this->shim().Note());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Pressure(uint8_t* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Pressure, WINRT_WRAP(uint8_t));
            *value = detach_from<uint8_t>(this->shim().Pressure());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Devices::Midi::IMidiPolyphonicKeyPressureMessageFactory> : produce_base<D, Windows::Devices::Midi::IMidiPolyphonicKeyPressureMessageFactory>
{
    int32_t WINRT_CALL CreateMidiPolyphonicKeyPressureMessage(uint8_t channel, uint8_t note, uint8_t pressure, void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CreateMidiPolyphonicKeyPressureMessage, WINRT_WRAP(Windows::Devices::Midi::MidiPolyphonicKeyPressureMessage), uint8_t, uint8_t, uint8_t);
            *value = detach_from<Windows::Devices::Midi::MidiPolyphonicKeyPressureMessage>(this->shim().CreateMidiPolyphonicKeyPressureMessage(channel, note, pressure));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Devices::Midi::IMidiProgramChangeMessage> : produce_base<D, Windows::Devices::Midi::IMidiProgramChangeMessage>
{
    int32_t WINRT_CALL get_Channel(uint8_t* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Channel, WINRT_WRAP(uint8_t));
            *value = detach_from<uint8_t>(this->shim().Channel());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Program(uint8_t* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Program, WINRT_WRAP(uint8_t));
            *value = detach_from<uint8_t>(this->shim().Program());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Devices::Midi::IMidiProgramChangeMessageFactory> : produce_base<D, Windows::Devices::Midi::IMidiProgramChangeMessageFactory>
{
    int32_t WINRT_CALL CreateMidiProgramChangeMessage(uint8_t channel, uint8_t program, void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CreateMidiProgramChangeMessage, WINRT_WRAP(Windows::Devices::Midi::MidiProgramChangeMessage), uint8_t, uint8_t);
            *value = detach_from<Windows::Devices::Midi::MidiProgramChangeMessage>(this->shim().CreateMidiProgramChangeMessage(channel, program));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Devices::Midi::IMidiSongPositionPointerMessage> : produce_base<D, Windows::Devices::Midi::IMidiSongPositionPointerMessage>
{
    int32_t WINRT_CALL get_Beats(uint16_t* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Beats, WINRT_WRAP(uint16_t));
            *value = detach_from<uint16_t>(this->shim().Beats());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Devices::Midi::IMidiSongPositionPointerMessageFactory> : produce_base<D, Windows::Devices::Midi::IMidiSongPositionPointerMessageFactory>
{
    int32_t WINRT_CALL CreateMidiSongPositionPointerMessage(uint16_t beats, void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CreateMidiSongPositionPointerMessage, WINRT_WRAP(Windows::Devices::Midi::MidiSongPositionPointerMessage), uint16_t);
            *value = detach_from<Windows::Devices::Midi::MidiSongPositionPointerMessage>(this->shim().CreateMidiSongPositionPointerMessage(beats));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Devices::Midi::IMidiSongSelectMessage> : produce_base<D, Windows::Devices::Midi::IMidiSongSelectMessage>
{
    int32_t WINRT_CALL get_Song(uint8_t* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Song, WINRT_WRAP(uint8_t));
            *value = detach_from<uint8_t>(this->shim().Song());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Devices::Midi::IMidiSongSelectMessageFactory> : produce_base<D, Windows::Devices::Midi::IMidiSongSelectMessageFactory>
{
    int32_t WINRT_CALL CreateMidiSongSelectMessage(uint8_t song, void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CreateMidiSongSelectMessage, WINRT_WRAP(Windows::Devices::Midi::MidiSongSelectMessage), uint8_t);
            *value = detach_from<Windows::Devices::Midi::MidiSongSelectMessage>(this->shim().CreateMidiSongSelectMessage(song));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Devices::Midi::IMidiSynthesizer> : produce_base<D, Windows::Devices::Midi::IMidiSynthesizer>
{
    int32_t WINRT_CALL get_AudioDevice(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(AudioDevice, WINRT_WRAP(Windows::Devices::Enumeration::DeviceInformation));
            *value = detach_from<Windows::Devices::Enumeration::DeviceInformation>(this->shim().AudioDevice());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Volume(double* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Volume, WINRT_WRAP(double));
            *value = detach_from<double>(this->shim().Volume());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_Volume(double value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Volume, WINRT_WRAP(void), double);
            this->shim().Volume(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Devices::Midi::IMidiSynthesizerStatics> : produce_base<D, Windows::Devices::Midi::IMidiSynthesizerStatics>
{
    int32_t WINRT_CALL CreateAsync(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CreateAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<Windows::Devices::Midi::MidiSynthesizer>));
            *value = detach_from<Windows::Foundation::IAsyncOperation<Windows::Devices::Midi::MidiSynthesizer>>(this->shim().CreateAsync());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL CreateFromAudioDeviceAsync(void* audioDevice, void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CreateAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<Windows::Devices::Midi::MidiSynthesizer>), Windows::Devices::Enumeration::DeviceInformation const);
            *value = detach_from<Windows::Foundation::IAsyncOperation<Windows::Devices::Midi::MidiSynthesizer>>(this->shim().CreateAsync(*reinterpret_cast<Windows::Devices::Enumeration::DeviceInformation const*>(&audioDevice)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL IsSynthesizer(void* midiDevice, bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IsSynthesizer, WINRT_WRAP(bool), Windows::Devices::Enumeration::DeviceInformation const&);
            *value = detach_from<bool>(this->shim().IsSynthesizer(*reinterpret_cast<Windows::Devices::Enumeration::DeviceInformation const*>(&midiDevice)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Devices::Midi::IMidiSystemExclusiveMessageFactory> : produce_base<D, Windows::Devices::Midi::IMidiSystemExclusiveMessageFactory>
{
    int32_t WINRT_CALL CreateMidiSystemExclusiveMessage(void* rawData, void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CreateMidiSystemExclusiveMessage, WINRT_WRAP(Windows::Devices::Midi::MidiSystemExclusiveMessage), Windows::Storage::Streams::IBuffer const&);
            *value = detach_from<Windows::Devices::Midi::MidiSystemExclusiveMessage>(this->shim().CreateMidiSystemExclusiveMessage(*reinterpret_cast<Windows::Storage::Streams::IBuffer const*>(&rawData)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Devices::Midi::IMidiTimeCodeMessage> : produce_base<D, Windows::Devices::Midi::IMidiTimeCodeMessage>
{
    int32_t WINRT_CALL get_FrameType(uint8_t* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(FrameType, WINRT_WRAP(uint8_t));
            *value = detach_from<uint8_t>(this->shim().FrameType());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Values(uint8_t* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Values, WINRT_WRAP(uint8_t));
            *value = detach_from<uint8_t>(this->shim().Values());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Devices::Midi::IMidiTimeCodeMessageFactory> : produce_base<D, Windows::Devices::Midi::IMidiTimeCodeMessageFactory>
{
    int32_t WINRT_CALL CreateMidiTimeCodeMessage(uint8_t frameType, uint8_t values, void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CreateMidiTimeCodeMessage, WINRT_WRAP(Windows::Devices::Midi::MidiTimeCodeMessage), uint8_t, uint8_t);
            *value = detach_from<Windows::Devices::Midi::MidiTimeCodeMessage>(this->shim().CreateMidiTimeCodeMessage(frameType, values));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

}

WINRT_EXPORT namespace winrt::Windows::Devices::Midi {

inline MidiActiveSensingMessage::MidiActiveSensingMessage() :
    MidiActiveSensingMessage(impl::call_factory<MidiActiveSensingMessage>([](auto&& f) { return f.template ActivateInstance<MidiActiveSensingMessage>(); }))
{}

inline MidiChannelPressureMessage::MidiChannelPressureMessage(uint8_t channel, uint8_t pressure) :
    MidiChannelPressureMessage(impl::call_factory<MidiChannelPressureMessage, Windows::Devices::Midi::IMidiChannelPressureMessageFactory>([&](auto&& f) { return f.CreateMidiChannelPressureMessage(channel, pressure); }))
{}

inline MidiContinueMessage::MidiContinueMessage() :
    MidiContinueMessage(impl::call_factory<MidiContinueMessage>([](auto&& f) { return f.template ActivateInstance<MidiContinueMessage>(); }))
{}

inline MidiControlChangeMessage::MidiControlChangeMessage(uint8_t channel, uint8_t controller, uint8_t controlValue) :
    MidiControlChangeMessage(impl::call_factory<MidiControlChangeMessage, Windows::Devices::Midi::IMidiControlChangeMessageFactory>([&](auto&& f) { return f.CreateMidiControlChangeMessage(channel, controller, controlValue); }))
{}

inline Windows::Foundation::IAsyncOperation<Windows::Devices::Midi::MidiInPort> MidiInPort::FromIdAsync(param::hstring const& deviceId)
{
    return impl::call_factory<MidiInPort, Windows::Devices::Midi::IMidiInPortStatics>([&](auto&& f) { return f.FromIdAsync(deviceId); });
}

inline hstring MidiInPort::GetDeviceSelector()
{
    return impl::call_factory<MidiInPort, Windows::Devices::Midi::IMidiInPortStatics>([&](auto&& f) { return f.GetDeviceSelector(); });
}

inline MidiNoteOffMessage::MidiNoteOffMessage(uint8_t channel, uint8_t note, uint8_t velocity) :
    MidiNoteOffMessage(impl::call_factory<MidiNoteOffMessage, Windows::Devices::Midi::IMidiNoteOffMessageFactory>([&](auto&& f) { return f.CreateMidiNoteOffMessage(channel, note, velocity); }))
{}

inline MidiNoteOnMessage::MidiNoteOnMessage(uint8_t channel, uint8_t note, uint8_t velocity) :
    MidiNoteOnMessage(impl::call_factory<MidiNoteOnMessage, Windows::Devices::Midi::IMidiNoteOnMessageFactory>([&](auto&& f) { return f.CreateMidiNoteOnMessage(channel, note, velocity); }))
{}

inline Windows::Foundation::IAsyncOperation<Windows::Devices::Midi::IMidiOutPort> MidiOutPort::FromIdAsync(param::hstring const& deviceId)
{
    return impl::call_factory<MidiOutPort, Windows::Devices::Midi::IMidiOutPortStatics>([&](auto&& f) { return f.FromIdAsync(deviceId); });
}

inline hstring MidiOutPort::GetDeviceSelector()
{
    return impl::call_factory<MidiOutPort, Windows::Devices::Midi::IMidiOutPortStatics>([&](auto&& f) { return f.GetDeviceSelector(); });
}

inline MidiPitchBendChangeMessage::MidiPitchBendChangeMessage(uint8_t channel, uint16_t bend) :
    MidiPitchBendChangeMessage(impl::call_factory<MidiPitchBendChangeMessage, Windows::Devices::Midi::IMidiPitchBendChangeMessageFactory>([&](auto&& f) { return f.CreateMidiPitchBendChangeMessage(channel, bend); }))
{}

inline MidiPolyphonicKeyPressureMessage::MidiPolyphonicKeyPressureMessage(uint8_t channel, uint8_t note, uint8_t pressure) :
    MidiPolyphonicKeyPressureMessage(impl::call_factory<MidiPolyphonicKeyPressureMessage, Windows::Devices::Midi::IMidiPolyphonicKeyPressureMessageFactory>([&](auto&& f) { return f.CreateMidiPolyphonicKeyPressureMessage(channel, note, pressure); }))
{}

inline MidiProgramChangeMessage::MidiProgramChangeMessage(uint8_t channel, uint8_t program) :
    MidiProgramChangeMessage(impl::call_factory<MidiProgramChangeMessage, Windows::Devices::Midi::IMidiProgramChangeMessageFactory>([&](auto&& f) { return f.CreateMidiProgramChangeMessage(channel, program); }))
{}

inline MidiSongPositionPointerMessage::MidiSongPositionPointerMessage(uint16_t beats) :
    MidiSongPositionPointerMessage(impl::call_factory<MidiSongPositionPointerMessage, Windows::Devices::Midi::IMidiSongPositionPointerMessageFactory>([&](auto&& f) { return f.CreateMidiSongPositionPointerMessage(beats); }))
{}

inline MidiSongSelectMessage::MidiSongSelectMessage(uint8_t song) :
    MidiSongSelectMessage(impl::call_factory<MidiSongSelectMessage, Windows::Devices::Midi::IMidiSongSelectMessageFactory>([&](auto&& f) { return f.CreateMidiSongSelectMessage(song); }))
{}

inline MidiStartMessage::MidiStartMessage() :
    MidiStartMessage(impl::call_factory<MidiStartMessage>([](auto&& f) { return f.template ActivateInstance<MidiStartMessage>(); }))
{}

inline MidiStopMessage::MidiStopMessage() :
    MidiStopMessage(impl::call_factory<MidiStopMessage>([](auto&& f) { return f.template ActivateInstance<MidiStopMessage>(); }))
{}

inline Windows::Foundation::IAsyncOperation<Windows::Devices::Midi::MidiSynthesizer> MidiSynthesizer::CreateAsync()
{
    return impl::call_factory<MidiSynthesizer, Windows::Devices::Midi::IMidiSynthesizerStatics>([&](auto&& f) { return f.CreateAsync(); });
}

inline Windows::Foundation::IAsyncOperation<Windows::Devices::Midi::MidiSynthesizer> MidiSynthesizer::CreateAsync(Windows::Devices::Enumeration::DeviceInformation const& audioDevice)
{
    return impl::call_factory<MidiSynthesizer, Windows::Devices::Midi::IMidiSynthesizerStatics>([&](auto&& f) { return f.CreateAsync(audioDevice); });
}

inline bool MidiSynthesizer::IsSynthesizer(Windows::Devices::Enumeration::DeviceInformation const& midiDevice)
{
    return impl::call_factory<MidiSynthesizer, Windows::Devices::Midi::IMidiSynthesizerStatics>([&](auto&& f) { return f.IsSynthesizer(midiDevice); });
}

inline MidiSystemExclusiveMessage::MidiSystemExclusiveMessage(Windows::Storage::Streams::IBuffer const& rawData) :
    MidiSystemExclusiveMessage(impl::call_factory<MidiSystemExclusiveMessage, Windows::Devices::Midi::IMidiSystemExclusiveMessageFactory>([&](auto&& f) { return f.CreateMidiSystemExclusiveMessage(rawData); }))
{}

inline MidiSystemResetMessage::MidiSystemResetMessage() :
    MidiSystemResetMessage(impl::call_factory<MidiSystemResetMessage>([](auto&& f) { return f.template ActivateInstance<MidiSystemResetMessage>(); }))
{}

inline MidiTimeCodeMessage::MidiTimeCodeMessage(uint8_t frameType, uint8_t values) :
    MidiTimeCodeMessage(impl::call_factory<MidiTimeCodeMessage, Windows::Devices::Midi::IMidiTimeCodeMessageFactory>([&](auto&& f) { return f.CreateMidiTimeCodeMessage(frameType, values); }))
{}

inline MidiTimingClockMessage::MidiTimingClockMessage() :
    MidiTimingClockMessage(impl::call_factory<MidiTimingClockMessage>([](auto&& f) { return f.template ActivateInstance<MidiTimingClockMessage>(); }))
{}

inline MidiTuneRequestMessage::MidiTuneRequestMessage() :
    MidiTuneRequestMessage(impl::call_factory<MidiTuneRequestMessage>([](auto&& f) { return f.template ActivateInstance<MidiTuneRequestMessage>(); }))
{}

}

WINRT_EXPORT namespace std {

template<> struct hash<winrt::Windows::Devices::Midi::IMidiChannelPressureMessage> : winrt::impl::hash_base<winrt::Windows::Devices::Midi::IMidiChannelPressureMessage> {};
template<> struct hash<winrt::Windows::Devices::Midi::IMidiChannelPressureMessageFactory> : winrt::impl::hash_base<winrt::Windows::Devices::Midi::IMidiChannelPressureMessageFactory> {};
template<> struct hash<winrt::Windows::Devices::Midi::IMidiControlChangeMessage> : winrt::impl::hash_base<winrt::Windows::Devices::Midi::IMidiControlChangeMessage> {};
template<> struct hash<winrt::Windows::Devices::Midi::IMidiControlChangeMessageFactory> : winrt::impl::hash_base<winrt::Windows::Devices::Midi::IMidiControlChangeMessageFactory> {};
template<> struct hash<winrt::Windows::Devices::Midi::IMidiInPort> : winrt::impl::hash_base<winrt::Windows::Devices::Midi::IMidiInPort> {};
template<> struct hash<winrt::Windows::Devices::Midi::IMidiInPortStatics> : winrt::impl::hash_base<winrt::Windows::Devices::Midi::IMidiInPortStatics> {};
template<> struct hash<winrt::Windows::Devices::Midi::IMidiMessage> : winrt::impl::hash_base<winrt::Windows::Devices::Midi::IMidiMessage> {};
template<> struct hash<winrt::Windows::Devices::Midi::IMidiMessageReceivedEventArgs> : winrt::impl::hash_base<winrt::Windows::Devices::Midi::IMidiMessageReceivedEventArgs> {};
template<> struct hash<winrt::Windows::Devices::Midi::IMidiNoteOffMessage> : winrt::impl::hash_base<winrt::Windows::Devices::Midi::IMidiNoteOffMessage> {};
template<> struct hash<winrt::Windows::Devices::Midi::IMidiNoteOffMessageFactory> : winrt::impl::hash_base<winrt::Windows::Devices::Midi::IMidiNoteOffMessageFactory> {};
template<> struct hash<winrt::Windows::Devices::Midi::IMidiNoteOnMessage> : winrt::impl::hash_base<winrt::Windows::Devices::Midi::IMidiNoteOnMessage> {};
template<> struct hash<winrt::Windows::Devices::Midi::IMidiNoteOnMessageFactory> : winrt::impl::hash_base<winrt::Windows::Devices::Midi::IMidiNoteOnMessageFactory> {};
template<> struct hash<winrt::Windows::Devices::Midi::IMidiOutPort> : winrt::impl::hash_base<winrt::Windows::Devices::Midi::IMidiOutPort> {};
template<> struct hash<winrt::Windows::Devices::Midi::IMidiOutPortStatics> : winrt::impl::hash_base<winrt::Windows::Devices::Midi::IMidiOutPortStatics> {};
template<> struct hash<winrt::Windows::Devices::Midi::IMidiPitchBendChangeMessage> : winrt::impl::hash_base<winrt::Windows::Devices::Midi::IMidiPitchBendChangeMessage> {};
template<> struct hash<winrt::Windows::Devices::Midi::IMidiPitchBendChangeMessageFactory> : winrt::impl::hash_base<winrt::Windows::Devices::Midi::IMidiPitchBendChangeMessageFactory> {};
template<> struct hash<winrt::Windows::Devices::Midi::IMidiPolyphonicKeyPressureMessage> : winrt::impl::hash_base<winrt::Windows::Devices::Midi::IMidiPolyphonicKeyPressureMessage> {};
template<> struct hash<winrt::Windows::Devices::Midi::IMidiPolyphonicKeyPressureMessageFactory> : winrt::impl::hash_base<winrt::Windows::Devices::Midi::IMidiPolyphonicKeyPressureMessageFactory> {};
template<> struct hash<winrt::Windows::Devices::Midi::IMidiProgramChangeMessage> : winrt::impl::hash_base<winrt::Windows::Devices::Midi::IMidiProgramChangeMessage> {};
template<> struct hash<winrt::Windows::Devices::Midi::IMidiProgramChangeMessageFactory> : winrt::impl::hash_base<winrt::Windows::Devices::Midi::IMidiProgramChangeMessageFactory> {};
template<> struct hash<winrt::Windows::Devices::Midi::IMidiSongPositionPointerMessage> : winrt::impl::hash_base<winrt::Windows::Devices::Midi::IMidiSongPositionPointerMessage> {};
template<> struct hash<winrt::Windows::Devices::Midi::IMidiSongPositionPointerMessageFactory> : winrt::impl::hash_base<winrt::Windows::Devices::Midi::IMidiSongPositionPointerMessageFactory> {};
template<> struct hash<winrt::Windows::Devices::Midi::IMidiSongSelectMessage> : winrt::impl::hash_base<winrt::Windows::Devices::Midi::IMidiSongSelectMessage> {};
template<> struct hash<winrt::Windows::Devices::Midi::IMidiSongSelectMessageFactory> : winrt::impl::hash_base<winrt::Windows::Devices::Midi::IMidiSongSelectMessageFactory> {};
template<> struct hash<winrt::Windows::Devices::Midi::IMidiSynthesizer> : winrt::impl::hash_base<winrt::Windows::Devices::Midi::IMidiSynthesizer> {};
template<> struct hash<winrt::Windows::Devices::Midi::IMidiSynthesizerStatics> : winrt::impl::hash_base<winrt::Windows::Devices::Midi::IMidiSynthesizerStatics> {};
template<> struct hash<winrt::Windows::Devices::Midi::IMidiSystemExclusiveMessageFactory> : winrt::impl::hash_base<winrt::Windows::Devices::Midi::IMidiSystemExclusiveMessageFactory> {};
template<> struct hash<winrt::Windows::Devices::Midi::IMidiTimeCodeMessage> : winrt::impl::hash_base<winrt::Windows::Devices::Midi::IMidiTimeCodeMessage> {};
template<> struct hash<winrt::Windows::Devices::Midi::IMidiTimeCodeMessageFactory> : winrt::impl::hash_base<winrt::Windows::Devices::Midi::IMidiTimeCodeMessageFactory> {};
template<> struct hash<winrt::Windows::Devices::Midi::MidiActiveSensingMessage> : winrt::impl::hash_base<winrt::Windows::Devices::Midi::MidiActiveSensingMessage> {};
template<> struct hash<winrt::Windows::Devices::Midi::MidiChannelPressureMessage> : winrt::impl::hash_base<winrt::Windows::Devices::Midi::MidiChannelPressureMessage> {};
template<> struct hash<winrt::Windows::Devices::Midi::MidiContinueMessage> : winrt::impl::hash_base<winrt::Windows::Devices::Midi::MidiContinueMessage> {};
template<> struct hash<winrt::Windows::Devices::Midi::MidiControlChangeMessage> : winrt::impl::hash_base<winrt::Windows::Devices::Midi::MidiControlChangeMessage> {};
template<> struct hash<winrt::Windows::Devices::Midi::MidiInPort> : winrt::impl::hash_base<winrt::Windows::Devices::Midi::MidiInPort> {};
template<> struct hash<winrt::Windows::Devices::Midi::MidiMessageReceivedEventArgs> : winrt::impl::hash_base<winrt::Windows::Devices::Midi::MidiMessageReceivedEventArgs> {};
template<> struct hash<winrt::Windows::Devices::Midi::MidiNoteOffMessage> : winrt::impl::hash_base<winrt::Windows::Devices::Midi::MidiNoteOffMessage> {};
template<> struct hash<winrt::Windows::Devices::Midi::MidiNoteOnMessage> : winrt::impl::hash_base<winrt::Windows::Devices::Midi::MidiNoteOnMessage> {};
template<> struct hash<winrt::Windows::Devices::Midi::MidiOutPort> : winrt::impl::hash_base<winrt::Windows::Devices::Midi::MidiOutPort> {};
template<> struct hash<winrt::Windows::Devices::Midi::MidiPitchBendChangeMessage> : winrt::impl::hash_base<winrt::Windows::Devices::Midi::MidiPitchBendChangeMessage> {};
template<> struct hash<winrt::Windows::Devices::Midi::MidiPolyphonicKeyPressureMessage> : winrt::impl::hash_base<winrt::Windows::Devices::Midi::MidiPolyphonicKeyPressureMessage> {};
template<> struct hash<winrt::Windows::Devices::Midi::MidiProgramChangeMessage> : winrt::impl::hash_base<winrt::Windows::Devices::Midi::MidiProgramChangeMessage> {};
template<> struct hash<winrt::Windows::Devices::Midi::MidiSongPositionPointerMessage> : winrt::impl::hash_base<winrt::Windows::Devices::Midi::MidiSongPositionPointerMessage> {};
template<> struct hash<winrt::Windows::Devices::Midi::MidiSongSelectMessage> : winrt::impl::hash_base<winrt::Windows::Devices::Midi::MidiSongSelectMessage> {};
template<> struct hash<winrt::Windows::Devices::Midi::MidiStartMessage> : winrt::impl::hash_base<winrt::Windows::Devices::Midi::MidiStartMessage> {};
template<> struct hash<winrt::Windows::Devices::Midi::MidiStopMessage> : winrt::impl::hash_base<winrt::Windows::Devices::Midi::MidiStopMessage> {};
template<> struct hash<winrt::Windows::Devices::Midi::MidiSynthesizer> : winrt::impl::hash_base<winrt::Windows::Devices::Midi::MidiSynthesizer> {};
template<> struct hash<winrt::Windows::Devices::Midi::MidiSystemExclusiveMessage> : winrt::impl::hash_base<winrt::Windows::Devices::Midi::MidiSystemExclusiveMessage> {};
template<> struct hash<winrt::Windows::Devices::Midi::MidiSystemResetMessage> : winrt::impl::hash_base<winrt::Windows::Devices::Midi::MidiSystemResetMessage> {};
template<> struct hash<winrt::Windows::Devices::Midi::MidiTimeCodeMessage> : winrt::impl::hash_base<winrt::Windows::Devices::Midi::MidiTimeCodeMessage> {};
template<> struct hash<winrt::Windows::Devices::Midi::MidiTimingClockMessage> : winrt::impl::hash_base<winrt::Windows::Devices::Midi::MidiTimingClockMessage> {};
template<> struct hash<winrt::Windows::Devices::Midi::MidiTuneRequestMessage> : winrt::impl::hash_base<winrt::Windows::Devices::Midi::MidiTuneRequestMessage> {};

}
