// C++/WinRT v1.0.190111.3

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#pragma once

WINRT_EXPORT namespace winrt::Windows::Perception {

struct IPerceptionTimestamp;
struct IPerceptionTimestamp2;
struct IPerceptionTimestampHelperStatics;
struct IPerceptionTimestampHelperStatics2;
struct PerceptionTimestamp;
struct PerceptionTimestampHelper;

}

namespace winrt::impl {

template <> struct category<Windows::Perception::IPerceptionTimestamp>{ using type = interface_category; };
template <> struct category<Windows::Perception::IPerceptionTimestamp2>{ using type = interface_category; };
template <> struct category<Windows::Perception::IPerceptionTimestampHelperStatics>{ using type = interface_category; };
template <> struct category<Windows::Perception::IPerceptionTimestampHelperStatics2>{ using type = interface_category; };
template <> struct category<Windows::Perception::PerceptionTimestamp>{ using type = class_category; };
template <> struct category<Windows::Perception::PerceptionTimestampHelper>{ using type = class_category; };
template <> struct name<Windows::Perception::IPerceptionTimestamp>{ static constexpr auto & value{ L"Windows.Perception.IPerceptionTimestamp" }; };
template <> struct name<Windows::Perception::IPerceptionTimestamp2>{ static constexpr auto & value{ L"Windows.Perception.IPerceptionTimestamp2" }; };
template <> struct name<Windows::Perception::IPerceptionTimestampHelperStatics>{ static constexpr auto & value{ L"Windows.Perception.IPerceptionTimestampHelperStatics" }; };
template <> struct name<Windows::Perception::IPerceptionTimestampHelperStatics2>{ static constexpr auto & value{ L"Windows.Perception.IPerceptionTimestampHelperStatics2" }; };
template <> struct name<Windows::Perception::PerceptionTimestamp>{ static constexpr auto & value{ L"Windows.Perception.PerceptionTimestamp" }; };
template <> struct name<Windows::Perception::PerceptionTimestampHelper>{ static constexpr auto & value{ L"Windows.Perception.PerceptionTimestampHelper" }; };
template <> struct guid_storage<Windows::Perception::IPerceptionTimestamp>{ static constexpr guid value{ 0x87C24804,0xA22E,0x4ADB,{ 0xBA,0x26,0xD7,0x8E,0xF6,0x39,0xBC,0xF4 } }; };
template <> struct guid_storage<Windows::Perception::IPerceptionTimestamp2>{ static constexpr guid value{ 0xE354B7ED,0x2BD1,0x41B7,{ 0x9E,0xD0,0x74,0xA1,0x5C,0x35,0x45,0x37 } }; };
template <> struct guid_storage<Windows::Perception::IPerceptionTimestampHelperStatics>{ static constexpr guid value{ 0x47A611D4,0xA9DF,0x4EDC,{ 0x85,0x5D,0xF4,0xD3,0x39,0xD9,0x67,0xAC } }; };
template <> struct guid_storage<Windows::Perception::IPerceptionTimestampHelperStatics2>{ static constexpr guid value{ 0x73D1A7FE,0x3FB9,0x4571,{ 0x87,0xD4,0x3C,0x92,0x0A,0x5E,0x86,0xEB } }; };
template <> struct default_interface<Windows::Perception::PerceptionTimestamp>{ using type = Windows::Perception::IPerceptionTimestamp; };

template <> struct abi<Windows::Perception::IPerceptionTimestamp>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL get_TargetTime(Windows::Foundation::DateTime* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_PredictionAmount(Windows::Foundation::TimeSpan* value) noexcept = 0;
};};

template <> struct abi<Windows::Perception::IPerceptionTimestamp2>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL get_SystemRelativeTargetTime(Windows::Foundation::TimeSpan* value) noexcept = 0;
};};

template <> struct abi<Windows::Perception::IPerceptionTimestampHelperStatics>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL FromHistoricalTargetTime(Windows::Foundation::DateTime targetTime, void** value) noexcept = 0;
};};

template <> struct abi<Windows::Perception::IPerceptionTimestampHelperStatics2>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL FromSystemRelativeTargetTime(Windows::Foundation::TimeSpan targetTime, void** value) noexcept = 0;
};};

template <typename D>
struct consume_Windows_Perception_IPerceptionTimestamp
{
    Windows::Foundation::DateTime TargetTime() const;
    Windows::Foundation::TimeSpan PredictionAmount() const;
};
template <> struct consume<Windows::Perception::IPerceptionTimestamp> { template <typename D> using type = consume_Windows_Perception_IPerceptionTimestamp<D>; };

template <typename D>
struct consume_Windows_Perception_IPerceptionTimestamp2
{
    Windows::Foundation::TimeSpan SystemRelativeTargetTime() const;
};
template <> struct consume<Windows::Perception::IPerceptionTimestamp2> { template <typename D> using type = consume_Windows_Perception_IPerceptionTimestamp2<D>; };

template <typename D>
struct consume_Windows_Perception_IPerceptionTimestampHelperStatics
{
    Windows::Perception::PerceptionTimestamp FromHistoricalTargetTime(Windows::Foundation::DateTime const& targetTime) const;
};
template <> struct consume<Windows::Perception::IPerceptionTimestampHelperStatics> { template <typename D> using type = consume_Windows_Perception_IPerceptionTimestampHelperStatics<D>; };

template <typename D>
struct consume_Windows_Perception_IPerceptionTimestampHelperStatics2
{
    Windows::Perception::PerceptionTimestamp FromSystemRelativeTargetTime(Windows::Foundation::TimeSpan const& targetTime) const;
};
template <> struct consume<Windows::Perception::IPerceptionTimestampHelperStatics2> { template <typename D> using type = consume_Windows_Perception_IPerceptionTimestampHelperStatics2<D>; };

}
