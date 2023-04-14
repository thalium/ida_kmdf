// C++/WinRT v1.0.190111.3

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#pragma once

WINRT_EXPORT namespace winrt::Windows::Globalization::DateTimeFormatting {

enum class DayFormat : int32_t
{
    None = 0,
    Default = 1,
};

enum class DayOfWeekFormat : int32_t
{
    None = 0,
    Default = 1,
    Abbreviated = 2,
    Full = 3,
};

enum class HourFormat : int32_t
{
    None = 0,
    Default = 1,
};

enum class MinuteFormat : int32_t
{
    None = 0,
    Default = 1,
};

enum class MonthFormat : int32_t
{
    None = 0,
    Default = 1,
    Abbreviated = 2,
    Full = 3,
    Numeric = 4,
};

enum class SecondFormat : int32_t
{
    None = 0,
    Default = 1,
};

enum class YearFormat : int32_t
{
    None = 0,
    Default = 1,
    Abbreviated = 2,
    Full = 3,
};

struct IDateTimeFormatter;
struct IDateTimeFormatter2;
struct IDateTimeFormatterFactory;
struct IDateTimeFormatterStatics;
struct DateTimeFormatter;

}

namespace winrt::impl {

template <> struct category<Windows::Globalization::DateTimeFormatting::IDateTimeFormatter>{ using type = interface_category; };
template <> struct category<Windows::Globalization::DateTimeFormatting::IDateTimeFormatter2>{ using type = interface_category; };
template <> struct category<Windows::Globalization::DateTimeFormatting::IDateTimeFormatterFactory>{ using type = interface_category; };
template <> struct category<Windows::Globalization::DateTimeFormatting::IDateTimeFormatterStatics>{ using type = interface_category; };
template <> struct category<Windows::Globalization::DateTimeFormatting::DateTimeFormatter>{ using type = class_category; };
template <> struct category<Windows::Globalization::DateTimeFormatting::DayFormat>{ using type = enum_category; };
template <> struct category<Windows::Globalization::DateTimeFormatting::DayOfWeekFormat>{ using type = enum_category; };
template <> struct category<Windows::Globalization::DateTimeFormatting::HourFormat>{ using type = enum_category; };
template <> struct category<Windows::Globalization::DateTimeFormatting::MinuteFormat>{ using type = enum_category; };
template <> struct category<Windows::Globalization::DateTimeFormatting::MonthFormat>{ using type = enum_category; };
template <> struct category<Windows::Globalization::DateTimeFormatting::SecondFormat>{ using type = enum_category; };
template <> struct category<Windows::Globalization::DateTimeFormatting::YearFormat>{ using type = enum_category; };
template <> struct name<Windows::Globalization::DateTimeFormatting::IDateTimeFormatter>{ static constexpr auto & value{ L"Windows.Globalization.DateTimeFormatting.IDateTimeFormatter" }; };
template <> struct name<Windows::Globalization::DateTimeFormatting::IDateTimeFormatter2>{ static constexpr auto & value{ L"Windows.Globalization.DateTimeFormatting.IDateTimeFormatter2" }; };
template <> struct name<Windows::Globalization::DateTimeFormatting::IDateTimeFormatterFactory>{ static constexpr auto & value{ L"Windows.Globalization.DateTimeFormatting.IDateTimeFormatterFactory" }; };
template <> struct name<Windows::Globalization::DateTimeFormatting::IDateTimeFormatterStatics>{ static constexpr auto & value{ L"Windows.Globalization.DateTimeFormatting.IDateTimeFormatterStatics" }; };
template <> struct name<Windows::Globalization::DateTimeFormatting::DateTimeFormatter>{ static constexpr auto & value{ L"Windows.Globalization.DateTimeFormatting.DateTimeFormatter" }; };
template <> struct name<Windows::Globalization::DateTimeFormatting::DayFormat>{ static constexpr auto & value{ L"Windows.Globalization.DateTimeFormatting.DayFormat" }; };
template <> struct name<Windows::Globalization::DateTimeFormatting::DayOfWeekFormat>{ static constexpr auto & value{ L"Windows.Globalization.DateTimeFormatting.DayOfWeekFormat" }; };
template <> struct name<Windows::Globalization::DateTimeFormatting::HourFormat>{ static constexpr auto & value{ L"Windows.Globalization.DateTimeFormatting.HourFormat" }; };
template <> struct name<Windows::Globalization::DateTimeFormatting::MinuteFormat>{ static constexpr auto & value{ L"Windows.Globalization.DateTimeFormatting.MinuteFormat" }; };
template <> struct name<Windows::Globalization::DateTimeFormatting::MonthFormat>{ static constexpr auto & value{ L"Windows.Globalization.DateTimeFormatting.MonthFormat" }; };
template <> struct name<Windows::Globalization::DateTimeFormatting::SecondFormat>{ static constexpr auto & value{ L"Windows.Globalization.DateTimeFormatting.SecondFormat" }; };
template <> struct name<Windows::Globalization::DateTimeFormatting::YearFormat>{ static constexpr auto & value{ L"Windows.Globalization.DateTimeFormatting.YearFormat" }; };
template <> struct guid_storage<Windows::Globalization::DateTimeFormatting::IDateTimeFormatter>{ static constexpr guid value{ 0x95EECA10,0x73E0,0x4E4B,{ 0xA1,0x83,0x3D,0x6A,0xD0,0xBA,0x35,0xEC } }; };
template <> struct guid_storage<Windows::Globalization::DateTimeFormatting::IDateTimeFormatter2>{ static constexpr guid value{ 0x27C91A86,0xBDAA,0x4FD0,{ 0x9E,0x36,0x67,0x1D,0x5A,0xA5,0xEE,0x03 } }; };
template <> struct guid_storage<Windows::Globalization::DateTimeFormatting::IDateTimeFormatterFactory>{ static constexpr guid value{ 0xEC8D8A53,0x1A2E,0x412D,{ 0x88,0x15,0x3B,0x74,0x5F,0xB1,0xA2,0xA0 } }; };
template <> struct guid_storage<Windows::Globalization::DateTimeFormatting::IDateTimeFormatterStatics>{ static constexpr guid value{ 0xBFCDE7C0,0xDF4C,0x4A2E,{ 0x90,0x12,0xF4,0x7D,0xAF,0x3F,0x12,0x12 } }; };
template <> struct default_interface<Windows::Globalization::DateTimeFormatting::DateTimeFormatter>{ using type = Windows::Globalization::DateTimeFormatting::IDateTimeFormatter; };

template <> struct abi<Windows::Globalization::DateTimeFormatting::IDateTimeFormatter>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL get_Languages(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_GeographicRegion(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_Calendar(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_Clock(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_NumeralSystem(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL put_NumeralSystem(void* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_Patterns(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_Template(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL Format(Windows::Foundation::DateTime value, void** result) noexcept = 0;
    virtual int32_t WINRT_CALL get_IncludeYear(Windows::Globalization::DateTimeFormatting::YearFormat* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_IncludeMonth(Windows::Globalization::DateTimeFormatting::MonthFormat* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_IncludeDayOfWeek(Windows::Globalization::DateTimeFormatting::DayOfWeekFormat* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_IncludeDay(Windows::Globalization::DateTimeFormatting::DayFormat* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_IncludeHour(Windows::Globalization::DateTimeFormatting::HourFormat* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_IncludeMinute(Windows::Globalization::DateTimeFormatting::MinuteFormat* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_IncludeSecond(Windows::Globalization::DateTimeFormatting::SecondFormat* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_ResolvedLanguage(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_ResolvedGeographicRegion(void** value) noexcept = 0;
};};

template <> struct abi<Windows::Globalization::DateTimeFormatting::IDateTimeFormatter2>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL FormatUsingTimeZone(Windows::Foundation::DateTime datetime, void* timeZoneId, void** result) noexcept = 0;
};};

template <> struct abi<Windows::Globalization::DateTimeFormatting::IDateTimeFormatterFactory>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL CreateDateTimeFormatter(void* formatTemplate, void** result) noexcept = 0;
    virtual int32_t WINRT_CALL CreateDateTimeFormatterLanguages(void* formatTemplate, void* languages, void** result) noexcept = 0;
    virtual int32_t WINRT_CALL CreateDateTimeFormatterContext(void* formatTemplate, void* languages, void* geographicRegion, void* calendar, void* clock, void** result) noexcept = 0;
    virtual int32_t WINRT_CALL CreateDateTimeFormatterDate(Windows::Globalization::DateTimeFormatting::YearFormat yearFormat, Windows::Globalization::DateTimeFormatting::MonthFormat monthFormat, Windows::Globalization::DateTimeFormatting::DayFormat dayFormat, Windows::Globalization::DateTimeFormatting::DayOfWeekFormat dayOfWeekFormat, void** result) noexcept = 0;
    virtual int32_t WINRT_CALL CreateDateTimeFormatterTime(Windows::Globalization::DateTimeFormatting::HourFormat hourFormat, Windows::Globalization::DateTimeFormatting::MinuteFormat minuteFormat, Windows::Globalization::DateTimeFormatting::SecondFormat secondFormat, void** result) noexcept = 0;
    virtual int32_t WINRT_CALL CreateDateTimeFormatterDateTimeLanguages(Windows::Globalization::DateTimeFormatting::YearFormat yearFormat, Windows::Globalization::DateTimeFormatting::MonthFormat monthFormat, Windows::Globalization::DateTimeFormatting::DayFormat dayFormat, Windows::Globalization::DateTimeFormatting::DayOfWeekFormat dayOfWeekFormat, Windows::Globalization::DateTimeFormatting::HourFormat hourFormat, Windows::Globalization::DateTimeFormatting::MinuteFormat minuteFormat, Windows::Globalization::DateTimeFormatting::SecondFormat secondFormat, void* languages, void** result) noexcept = 0;
    virtual int32_t WINRT_CALL CreateDateTimeFormatterDateTimeContext(Windows::Globalization::DateTimeFormatting::YearFormat yearFormat, Windows::Globalization::DateTimeFormatting::MonthFormat monthFormat, Windows::Globalization::DateTimeFormatting::DayFormat dayFormat, Windows::Globalization::DateTimeFormatting::DayOfWeekFormat dayOfWeekFormat, Windows::Globalization::DateTimeFormatting::HourFormat hourFormat, Windows::Globalization::DateTimeFormatting::MinuteFormat minuteFormat, Windows::Globalization::DateTimeFormatting::SecondFormat secondFormat, void* languages, void* geographicRegion, void* calendar, void* clock, void** result) noexcept = 0;
};};

template <> struct abi<Windows::Globalization::DateTimeFormatting::IDateTimeFormatterStatics>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL get_LongDate(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_LongTime(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_ShortDate(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_ShortTime(void** value) noexcept = 0;
};};

template <typename D>
struct consume_Windows_Globalization_DateTimeFormatting_IDateTimeFormatter
{
    Windows::Foundation::Collections::IVectorView<hstring> Languages() const;
    hstring GeographicRegion() const;
    hstring Calendar() const;
    hstring Clock() const;
    hstring NumeralSystem() const;
    void NumeralSystem(param::hstring const& value) const;
    Windows::Foundation::Collections::IVectorView<hstring> Patterns() const;
    hstring Template() const;
    hstring Format(Windows::Foundation::DateTime const& value) const;
    Windows::Globalization::DateTimeFormatting::YearFormat IncludeYear() const;
    Windows::Globalization::DateTimeFormatting::MonthFormat IncludeMonth() const;
    Windows::Globalization::DateTimeFormatting::DayOfWeekFormat IncludeDayOfWeek() const;
    Windows::Globalization::DateTimeFormatting::DayFormat IncludeDay() const;
    Windows::Globalization::DateTimeFormatting::HourFormat IncludeHour() const;
    Windows::Globalization::DateTimeFormatting::MinuteFormat IncludeMinute() const;
    Windows::Globalization::DateTimeFormatting::SecondFormat IncludeSecond() const;
    hstring ResolvedLanguage() const;
    hstring ResolvedGeographicRegion() const;
};
template <> struct consume<Windows::Globalization::DateTimeFormatting::IDateTimeFormatter> { template <typename D> using type = consume_Windows_Globalization_DateTimeFormatting_IDateTimeFormatter<D>; };

template <typename D>
struct consume_Windows_Globalization_DateTimeFormatting_IDateTimeFormatter2
{
    hstring Format(Windows::Foundation::DateTime const& datetime, param::hstring const& timeZoneId) const;
};
template <> struct consume<Windows::Globalization::DateTimeFormatting::IDateTimeFormatter2> { template <typename D> using type = consume_Windows_Globalization_DateTimeFormatting_IDateTimeFormatter2<D>; };

template <typename D>
struct consume_Windows_Globalization_DateTimeFormatting_IDateTimeFormatterFactory
{
    Windows::Globalization::DateTimeFormatting::DateTimeFormatter CreateDateTimeFormatter(param::hstring const& formatTemplate) const;
    Windows::Globalization::DateTimeFormatting::DateTimeFormatter CreateDateTimeFormatterLanguages(param::hstring const& formatTemplate, param::iterable<hstring> const& languages) const;
    Windows::Globalization::DateTimeFormatting::DateTimeFormatter CreateDateTimeFormatterContext(param::hstring const& formatTemplate, param::iterable<hstring> const& languages, param::hstring const& geographicRegion, param::hstring const& calendar, param::hstring const& clock) const;
    Windows::Globalization::DateTimeFormatting::DateTimeFormatter CreateDateTimeFormatterDate(Windows::Globalization::DateTimeFormatting::YearFormat const& yearFormat, Windows::Globalization::DateTimeFormatting::MonthFormat const& monthFormat, Windows::Globalization::DateTimeFormatting::DayFormat const& dayFormat, Windows::Globalization::DateTimeFormatting::DayOfWeekFormat const& dayOfWeekFormat) const;
    Windows::Globalization::DateTimeFormatting::DateTimeFormatter CreateDateTimeFormatterTime(Windows::Globalization::DateTimeFormatting::HourFormat const& hourFormat, Windows::Globalization::DateTimeFormatting::MinuteFormat const& minuteFormat, Windows::Globalization::DateTimeFormatting::SecondFormat const& secondFormat) const;
    Windows::Globalization::DateTimeFormatting::DateTimeFormatter CreateDateTimeFormatterDateTimeLanguages(Windows::Globalization::DateTimeFormatting::YearFormat const& yearFormat, Windows::Globalization::DateTimeFormatting::MonthFormat const& monthFormat, Windows::Globalization::DateTimeFormatting::DayFormat const& dayFormat, Windows::Globalization::DateTimeFormatting::DayOfWeekFormat const& dayOfWeekFormat, Windows::Globalization::DateTimeFormatting::HourFormat const& hourFormat, Windows::Globalization::DateTimeFormatting::MinuteFormat const& minuteFormat, Windows::Globalization::DateTimeFormatting::SecondFormat const& secondFormat, param::iterable<hstring> const& languages) const;
    Windows::Globalization::DateTimeFormatting::DateTimeFormatter CreateDateTimeFormatterDateTimeContext(Windows::Globalization::DateTimeFormatting::YearFormat const& yearFormat, Windows::Globalization::DateTimeFormatting::MonthFormat const& monthFormat, Windows::Globalization::DateTimeFormatting::DayFormat const& dayFormat, Windows::Globalization::DateTimeFormatting::DayOfWeekFormat const& dayOfWeekFormat, Windows::Globalization::DateTimeFormatting::HourFormat const& hourFormat, Windows::Globalization::DateTimeFormatting::MinuteFormat const& minuteFormat, Windows::Globalization::DateTimeFormatting::SecondFormat const& secondFormat, param::iterable<hstring> const& languages, param::hstring const& geographicRegion, param::hstring const& calendar, param::hstring const& clock) const;
};
template <> struct consume<Windows::Globalization::DateTimeFormatting::IDateTimeFormatterFactory> { template <typename D> using type = consume_Windows_Globalization_DateTimeFormatting_IDateTimeFormatterFactory<D>; };

template <typename D>
struct consume_Windows_Globalization_DateTimeFormatting_IDateTimeFormatterStatics
{
    Windows::Globalization::DateTimeFormatting::DateTimeFormatter LongDate() const;
    Windows::Globalization::DateTimeFormatting::DateTimeFormatter LongTime() const;
    Windows::Globalization::DateTimeFormatting::DateTimeFormatter ShortDate() const;
    Windows::Globalization::DateTimeFormatting::DateTimeFormatter ShortTime() const;
};
template <> struct consume<Windows::Globalization::DateTimeFormatting::IDateTimeFormatterStatics> { template <typename D> using type = consume_Windows_Globalization_DateTimeFormatting_IDateTimeFormatterStatics<D>; };

}
