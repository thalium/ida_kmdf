// C++/WinRT v1.0.190111.3

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#pragma once

WINRT_EXPORT namespace winrt::Windows::System {

struct User;

}

WINRT_EXPORT namespace winrt::Windows::Globalization {

enum class DayOfWeek : int32_t
{
    Sunday = 0,
    Monday = 1,
    Tuesday = 2,
    Wednesday = 3,
    Thursday = 4,
    Friday = 5,
    Saturday = 6,
};

enum class LanguageLayoutDirection : int32_t
{
    Ltr = 0,
    Rtl = 1,
    TtbLtr = 2,
    TtbRtl = 3,
};

struct IApplicationLanguagesStatics;
struct IApplicationLanguagesStatics2;
struct ICalendar;
struct ICalendarFactory;
struct ICalendarFactory2;
struct ICalendarIdentifiersStatics;
struct ICalendarIdentifiersStatics2;
struct ICalendarIdentifiersStatics3;
struct IClockIdentifiersStatics;
struct ICurrencyAmount;
struct ICurrencyAmountFactory;
struct ICurrencyIdentifiersStatics;
struct ICurrencyIdentifiersStatics2;
struct ICurrencyIdentifiersStatics3;
struct IGeographicRegion;
struct IGeographicRegionFactory;
struct IGeographicRegionStatics;
struct IJapanesePhoneme;
struct IJapanesePhoneticAnalyzerStatics;
struct ILanguage;
struct ILanguage2;
struct ILanguageExtensionSubtags;
struct ILanguageFactory;
struct ILanguageStatics;
struct ILanguageStatics2;
struct INumeralSystemIdentifiersStatics;
struct INumeralSystemIdentifiersStatics2;
struct ITimeZoneOnCalendar;
struct ApplicationLanguages;
struct Calendar;
struct CalendarIdentifiers;
struct ClockIdentifiers;
struct CurrencyAmount;
struct CurrencyIdentifiers;
struct GeographicRegion;
struct JapanesePhoneme;
struct JapanesePhoneticAnalyzer;
struct Language;
struct NumeralSystemIdentifiers;

}

namespace winrt::impl {

template <> struct category<Windows::Globalization::IApplicationLanguagesStatics>{ using type = interface_category; };
template <> struct category<Windows::Globalization::IApplicationLanguagesStatics2>{ using type = interface_category; };
template <> struct category<Windows::Globalization::ICalendar>{ using type = interface_category; };
template <> struct category<Windows::Globalization::ICalendarFactory>{ using type = interface_category; };
template <> struct category<Windows::Globalization::ICalendarFactory2>{ using type = interface_category; };
template <> struct category<Windows::Globalization::ICalendarIdentifiersStatics>{ using type = interface_category; };
template <> struct category<Windows::Globalization::ICalendarIdentifiersStatics2>{ using type = interface_category; };
template <> struct category<Windows::Globalization::ICalendarIdentifiersStatics3>{ using type = interface_category; };
template <> struct category<Windows::Globalization::IClockIdentifiersStatics>{ using type = interface_category; };
template <> struct category<Windows::Globalization::ICurrencyAmount>{ using type = interface_category; };
template <> struct category<Windows::Globalization::ICurrencyAmountFactory>{ using type = interface_category; };
template <> struct category<Windows::Globalization::ICurrencyIdentifiersStatics>{ using type = interface_category; };
template <> struct category<Windows::Globalization::ICurrencyIdentifiersStatics2>{ using type = interface_category; };
template <> struct category<Windows::Globalization::ICurrencyIdentifiersStatics3>{ using type = interface_category; };
template <> struct category<Windows::Globalization::IGeographicRegion>{ using type = interface_category; };
template <> struct category<Windows::Globalization::IGeographicRegionFactory>{ using type = interface_category; };
template <> struct category<Windows::Globalization::IGeographicRegionStatics>{ using type = interface_category; };
template <> struct category<Windows::Globalization::IJapanesePhoneme>{ using type = interface_category; };
template <> struct category<Windows::Globalization::IJapanesePhoneticAnalyzerStatics>{ using type = interface_category; };
template <> struct category<Windows::Globalization::ILanguage>{ using type = interface_category; };
template <> struct category<Windows::Globalization::ILanguage2>{ using type = interface_category; };
template <> struct category<Windows::Globalization::ILanguageExtensionSubtags>{ using type = interface_category; };
template <> struct category<Windows::Globalization::ILanguageFactory>{ using type = interface_category; };
template <> struct category<Windows::Globalization::ILanguageStatics>{ using type = interface_category; };
template <> struct category<Windows::Globalization::ILanguageStatics2>{ using type = interface_category; };
template <> struct category<Windows::Globalization::INumeralSystemIdentifiersStatics>{ using type = interface_category; };
template <> struct category<Windows::Globalization::INumeralSystemIdentifiersStatics2>{ using type = interface_category; };
template <> struct category<Windows::Globalization::ITimeZoneOnCalendar>{ using type = interface_category; };
template <> struct category<Windows::Globalization::ApplicationLanguages>{ using type = class_category; };
template <> struct category<Windows::Globalization::Calendar>{ using type = class_category; };
template <> struct category<Windows::Globalization::CalendarIdentifiers>{ using type = class_category; };
template <> struct category<Windows::Globalization::ClockIdentifiers>{ using type = class_category; };
template <> struct category<Windows::Globalization::CurrencyAmount>{ using type = class_category; };
template <> struct category<Windows::Globalization::CurrencyIdentifiers>{ using type = class_category; };
template <> struct category<Windows::Globalization::GeographicRegion>{ using type = class_category; };
template <> struct category<Windows::Globalization::JapanesePhoneme>{ using type = class_category; };
template <> struct category<Windows::Globalization::JapanesePhoneticAnalyzer>{ using type = class_category; };
template <> struct category<Windows::Globalization::Language>{ using type = class_category; };
template <> struct category<Windows::Globalization::NumeralSystemIdentifiers>{ using type = class_category; };
template <> struct category<Windows::Globalization::DayOfWeek>{ using type = enum_category; };
template <> struct category<Windows::Globalization::LanguageLayoutDirection>{ using type = enum_category; };
template <> struct name<Windows::Globalization::IApplicationLanguagesStatics>{ static constexpr auto & value{ L"Windows.Globalization.IApplicationLanguagesStatics" }; };
template <> struct name<Windows::Globalization::IApplicationLanguagesStatics2>{ static constexpr auto & value{ L"Windows.Globalization.IApplicationLanguagesStatics2" }; };
template <> struct name<Windows::Globalization::ICalendar>{ static constexpr auto & value{ L"Windows.Globalization.ICalendar" }; };
template <> struct name<Windows::Globalization::ICalendarFactory>{ static constexpr auto & value{ L"Windows.Globalization.ICalendarFactory" }; };
template <> struct name<Windows::Globalization::ICalendarFactory2>{ static constexpr auto & value{ L"Windows.Globalization.ICalendarFactory2" }; };
template <> struct name<Windows::Globalization::ICalendarIdentifiersStatics>{ static constexpr auto & value{ L"Windows.Globalization.ICalendarIdentifiersStatics" }; };
template <> struct name<Windows::Globalization::ICalendarIdentifiersStatics2>{ static constexpr auto & value{ L"Windows.Globalization.ICalendarIdentifiersStatics2" }; };
template <> struct name<Windows::Globalization::ICalendarIdentifiersStatics3>{ static constexpr auto & value{ L"Windows.Globalization.ICalendarIdentifiersStatics3" }; };
template <> struct name<Windows::Globalization::IClockIdentifiersStatics>{ static constexpr auto & value{ L"Windows.Globalization.IClockIdentifiersStatics" }; };
template <> struct name<Windows::Globalization::ICurrencyAmount>{ static constexpr auto & value{ L"Windows.Globalization.ICurrencyAmount" }; };
template <> struct name<Windows::Globalization::ICurrencyAmountFactory>{ static constexpr auto & value{ L"Windows.Globalization.ICurrencyAmountFactory" }; };
template <> struct name<Windows::Globalization::ICurrencyIdentifiersStatics>{ static constexpr auto & value{ L"Windows.Globalization.ICurrencyIdentifiersStatics" }; };
template <> struct name<Windows::Globalization::ICurrencyIdentifiersStatics2>{ static constexpr auto & value{ L"Windows.Globalization.ICurrencyIdentifiersStatics2" }; };
template <> struct name<Windows::Globalization::ICurrencyIdentifiersStatics3>{ static constexpr auto & value{ L"Windows.Globalization.ICurrencyIdentifiersStatics3" }; };
template <> struct name<Windows::Globalization::IGeographicRegion>{ static constexpr auto & value{ L"Windows.Globalization.IGeographicRegion" }; };
template <> struct name<Windows::Globalization::IGeographicRegionFactory>{ static constexpr auto & value{ L"Windows.Globalization.IGeographicRegionFactory" }; };
template <> struct name<Windows::Globalization::IGeographicRegionStatics>{ static constexpr auto & value{ L"Windows.Globalization.IGeographicRegionStatics" }; };
template <> struct name<Windows::Globalization::IJapanesePhoneme>{ static constexpr auto & value{ L"Windows.Globalization.IJapanesePhoneme" }; };
template <> struct name<Windows::Globalization::IJapanesePhoneticAnalyzerStatics>{ static constexpr auto & value{ L"Windows.Globalization.IJapanesePhoneticAnalyzerStatics" }; };
template <> struct name<Windows::Globalization::ILanguage>{ static constexpr auto & value{ L"Windows.Globalization.ILanguage" }; };
template <> struct name<Windows::Globalization::ILanguage2>{ static constexpr auto & value{ L"Windows.Globalization.ILanguage2" }; };
template <> struct name<Windows::Globalization::ILanguageExtensionSubtags>{ static constexpr auto & value{ L"Windows.Globalization.ILanguageExtensionSubtags" }; };
template <> struct name<Windows::Globalization::ILanguageFactory>{ static constexpr auto & value{ L"Windows.Globalization.ILanguageFactory" }; };
template <> struct name<Windows::Globalization::ILanguageStatics>{ static constexpr auto & value{ L"Windows.Globalization.ILanguageStatics" }; };
template <> struct name<Windows::Globalization::ILanguageStatics2>{ static constexpr auto & value{ L"Windows.Globalization.ILanguageStatics2" }; };
template <> struct name<Windows::Globalization::INumeralSystemIdentifiersStatics>{ static constexpr auto & value{ L"Windows.Globalization.INumeralSystemIdentifiersStatics" }; };
template <> struct name<Windows::Globalization::INumeralSystemIdentifiersStatics2>{ static constexpr auto & value{ L"Windows.Globalization.INumeralSystemIdentifiersStatics2" }; };
template <> struct name<Windows::Globalization::ITimeZoneOnCalendar>{ static constexpr auto & value{ L"Windows.Globalization.ITimeZoneOnCalendar" }; };
template <> struct name<Windows::Globalization::ApplicationLanguages>{ static constexpr auto & value{ L"Windows.Globalization.ApplicationLanguages" }; };
template <> struct name<Windows::Globalization::Calendar>{ static constexpr auto & value{ L"Windows.Globalization.Calendar" }; };
template <> struct name<Windows::Globalization::CalendarIdentifiers>{ static constexpr auto & value{ L"Windows.Globalization.CalendarIdentifiers" }; };
template <> struct name<Windows::Globalization::ClockIdentifiers>{ static constexpr auto & value{ L"Windows.Globalization.ClockIdentifiers" }; };
template <> struct name<Windows::Globalization::CurrencyAmount>{ static constexpr auto & value{ L"Windows.Globalization.CurrencyAmount" }; };
template <> struct name<Windows::Globalization::CurrencyIdentifiers>{ static constexpr auto & value{ L"Windows.Globalization.CurrencyIdentifiers" }; };
template <> struct name<Windows::Globalization::GeographicRegion>{ static constexpr auto & value{ L"Windows.Globalization.GeographicRegion" }; };
template <> struct name<Windows::Globalization::JapanesePhoneme>{ static constexpr auto & value{ L"Windows.Globalization.JapanesePhoneme" }; };
template <> struct name<Windows::Globalization::JapanesePhoneticAnalyzer>{ static constexpr auto & value{ L"Windows.Globalization.JapanesePhoneticAnalyzer" }; };
template <> struct name<Windows::Globalization::Language>{ static constexpr auto & value{ L"Windows.Globalization.Language" }; };
template <> struct name<Windows::Globalization::NumeralSystemIdentifiers>{ static constexpr auto & value{ L"Windows.Globalization.NumeralSystemIdentifiers" }; };
template <> struct name<Windows::Globalization::DayOfWeek>{ static constexpr auto & value{ L"Windows.Globalization.DayOfWeek" }; };
template <> struct name<Windows::Globalization::LanguageLayoutDirection>{ static constexpr auto & value{ L"Windows.Globalization.LanguageLayoutDirection" }; };
template <> struct guid_storage<Windows::Globalization::IApplicationLanguagesStatics>{ static constexpr guid value{ 0x75B40847,0x0A4C,0x4A92,{ 0x95,0x65,0xFD,0x63,0xC9,0x5F,0x7A,0xED } }; };
template <> struct guid_storage<Windows::Globalization::IApplicationLanguagesStatics2>{ static constexpr guid value{ 0x1DF0DE4F,0x072B,0x4D7B,{ 0x8F,0x06,0xCB,0x2D,0xB4,0x0F,0x2B,0xB5 } }; };
template <> struct guid_storage<Windows::Globalization::ICalendar>{ static constexpr guid value{ 0xCA30221D,0x86D9,0x40FB,{ 0xA2,0x6B,0xD4,0x4E,0xB7,0xCF,0x08,0xEA } }; };
template <> struct guid_storage<Windows::Globalization::ICalendarFactory>{ static constexpr guid value{ 0x83F58412,0xE56B,0x4C75,{ 0xA6,0x6E,0x0F,0x63,0xD5,0x77,0x58,0xA6 } }; };
template <> struct guid_storage<Windows::Globalization::ICalendarFactory2>{ static constexpr guid value{ 0xB44B378C,0xCA7E,0x4590,{ 0x9E,0x72,0xEA,0x2B,0xEC,0x1A,0x51,0x15 } }; };
template <> struct guid_storage<Windows::Globalization::ICalendarIdentifiersStatics>{ static constexpr guid value{ 0x80653F68,0x2CB2,0x4C1F,{ 0xB5,0x90,0xF0,0xF5,0x2B,0xF4,0xFD,0x1A } }; };
template <> struct guid_storage<Windows::Globalization::ICalendarIdentifiersStatics2>{ static constexpr guid value{ 0x7DF4D488,0x5FD0,0x42A7,{ 0x95,0xB5,0x7D,0x98,0xD8,0x23,0x07,0x5F } }; };
template <> struct guid_storage<Windows::Globalization::ICalendarIdentifiersStatics3>{ static constexpr guid value{ 0x2C225423,0x1FAD,0x40C0,{ 0x93,0x34,0xA8,0xEB,0x90,0xDB,0x04,0xF5 } }; };
template <> struct guid_storage<Windows::Globalization::IClockIdentifiersStatics>{ static constexpr guid value{ 0x523805BB,0x12EC,0x4F83,{ 0xBC,0x31,0xB1,0xB4,0x37,0x6B,0x08,0x08 } }; };
template <> struct guid_storage<Windows::Globalization::ICurrencyAmount>{ static constexpr guid value{ 0x74B49942,0xEB75,0x443A,{ 0x95,0xB3,0x7D,0x72,0x3F,0x56,0xF9,0x3C } }; };
template <> struct guid_storage<Windows::Globalization::ICurrencyAmountFactory>{ static constexpr guid value{ 0x48D7168F,0xEF3B,0x4AEE,{ 0xA6,0xA1,0x4B,0x03,0x6F,0xE0,0x3F,0xF0 } }; };
template <> struct guid_storage<Windows::Globalization::ICurrencyIdentifiersStatics>{ static constexpr guid value{ 0x9F1D091B,0xD586,0x4913,{ 0x9B,0x6A,0xA9,0xBD,0x2D,0xC1,0x28,0x74 } }; };
template <> struct guid_storage<Windows::Globalization::ICurrencyIdentifiersStatics2>{ static constexpr guid value{ 0x1814797F,0xC3B2,0x4C33,{ 0x95,0x91,0x98,0x00,0x11,0x95,0x0D,0x37 } }; };
template <> struct guid_storage<Windows::Globalization::ICurrencyIdentifiersStatics3>{ static constexpr guid value{ 0x4FB23BFA,0xED25,0x4F4D,{ 0x85,0x7F,0x23,0x7F,0x17,0x48,0xC2,0x1C } }; };
template <> struct guid_storage<Windows::Globalization::IGeographicRegion>{ static constexpr guid value{ 0x01E9A621,0x4A64,0x4ED9,{ 0x95,0x4F,0x9E,0xDE,0xB0,0x7B,0xD9,0x03 } }; };
template <> struct guid_storage<Windows::Globalization::IGeographicRegionFactory>{ static constexpr guid value{ 0x53425270,0x77B4,0x426B,{ 0x85,0x9F,0x81,0xE1,0x9D,0x51,0x25,0x46 } }; };
template <> struct guid_storage<Windows::Globalization::IGeographicRegionStatics>{ static constexpr guid value{ 0x29E28974,0x7AD9,0x4EF4,{ 0x87,0x99,0xB3,0xB4,0x4F,0xAD,0xEC,0x08 } }; };
template <> struct guid_storage<Windows::Globalization::IJapanesePhoneme>{ static constexpr guid value{ 0x2F6A9300,0xE85B,0x43E6,{ 0x89,0x7D,0x5D,0x82,0xF8,0x62,0xDF,0x21 } }; };
template <> struct guid_storage<Windows::Globalization::IJapanesePhoneticAnalyzerStatics>{ static constexpr guid value{ 0x88AB9E90,0x93DE,0x41B2,{ 0xB4,0xD5,0x8E,0xDB,0x22,0x7F,0xD1,0xC2 } }; };
template <> struct guid_storage<Windows::Globalization::ILanguage>{ static constexpr guid value{ 0xEA79A752,0xF7C2,0x4265,{ 0xB1,0xBD,0xC4,0xDE,0xC4,0xE4,0xF0,0x80 } }; };
template <> struct guid_storage<Windows::Globalization::ILanguage2>{ static constexpr guid value{ 0x6A47E5B5,0xD94D,0x4886,{ 0xA4,0x04,0xA5,0xA5,0xB9,0xD5,0xB4,0x94 } }; };
template <> struct guid_storage<Windows::Globalization::ILanguageExtensionSubtags>{ static constexpr guid value{ 0x7D7DAF45,0x368D,0x4364,{ 0x85,0x2B,0xDE,0xC9,0x27,0x03,0x7B,0x85 } }; };
template <> struct guid_storage<Windows::Globalization::ILanguageFactory>{ static constexpr guid value{ 0x9B0252AC,0x0C27,0x44F8,{ 0xB7,0x92,0x97,0x93,0xFB,0x66,0xC6,0x3E } }; };
template <> struct guid_storage<Windows::Globalization::ILanguageStatics>{ static constexpr guid value{ 0xB23CD557,0x0865,0x46D4,{ 0x89,0xB8,0xD5,0x9B,0xE8,0x99,0x0F,0x0D } }; };
template <> struct guid_storage<Windows::Globalization::ILanguageStatics2>{ static constexpr guid value{ 0x30199F6E,0x914B,0x4B2A,{ 0x9D,0x6E,0xE3,0xB0,0xE2,0x7D,0xBE,0x4F } }; };
template <> struct guid_storage<Windows::Globalization::INumeralSystemIdentifiersStatics>{ static constexpr guid value{ 0xA5C662C3,0x68C9,0x4D3D,{ 0xB7,0x65,0x97,0x20,0x29,0xE2,0x1D,0xEC } }; };
template <> struct guid_storage<Windows::Globalization::INumeralSystemIdentifiersStatics2>{ static constexpr guid value{ 0x7F003228,0x9DDB,0x4A34,{ 0x91,0x04,0x02,0x60,0xC0,0x91,0xA7,0xC7 } }; };
template <> struct guid_storage<Windows::Globalization::ITimeZoneOnCalendar>{ static constexpr guid value{ 0xBB3C25E5,0x46CF,0x4317,{ 0xA3,0xF5,0x02,0x62,0x1A,0xD5,0x44,0x78 } }; };
template <> struct default_interface<Windows::Globalization::Calendar>{ using type = Windows::Globalization::ICalendar; };
template <> struct default_interface<Windows::Globalization::CurrencyAmount>{ using type = Windows::Globalization::ICurrencyAmount; };
template <> struct default_interface<Windows::Globalization::GeographicRegion>{ using type = Windows::Globalization::IGeographicRegion; };
template <> struct default_interface<Windows::Globalization::JapanesePhoneme>{ using type = Windows::Globalization::IJapanesePhoneme; };
template <> struct default_interface<Windows::Globalization::Language>{ using type = Windows::Globalization::ILanguage; };

template <> struct abi<Windows::Globalization::IApplicationLanguagesStatics>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL get_PrimaryLanguageOverride(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL put_PrimaryLanguageOverride(void* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_Languages(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_ManifestLanguages(void** value) noexcept = 0;
};};

template <> struct abi<Windows::Globalization::IApplicationLanguagesStatics2>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL GetLanguagesForUser(void* user, void** value) noexcept = 0;
};};

template <> struct abi<Windows::Globalization::ICalendar>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL Clone(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL SetToMin() noexcept = 0;
    virtual int32_t WINRT_CALL SetToMax() noexcept = 0;
    virtual int32_t WINRT_CALL get_Languages(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_NumeralSystem(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL put_NumeralSystem(void* value) noexcept = 0;
    virtual int32_t WINRT_CALL GetCalendarSystem(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL ChangeCalendarSystem(void* value) noexcept = 0;
    virtual int32_t WINRT_CALL GetClock(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL ChangeClock(void* value) noexcept = 0;
    virtual int32_t WINRT_CALL GetDateTime(Windows::Foundation::DateTime* result) noexcept = 0;
    virtual int32_t WINRT_CALL SetDateTime(Windows::Foundation::DateTime value) noexcept = 0;
    virtual int32_t WINRT_CALL SetToNow() noexcept = 0;
    virtual int32_t WINRT_CALL get_FirstEra(int32_t* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_LastEra(int32_t* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_NumberOfEras(int32_t* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_Era(int32_t* value) noexcept = 0;
    virtual int32_t WINRT_CALL put_Era(int32_t value) noexcept = 0;
    virtual int32_t WINRT_CALL AddEras(int32_t eras) noexcept = 0;
    virtual int32_t WINRT_CALL EraAsFullString(void** result) noexcept = 0;
    virtual int32_t WINRT_CALL EraAsString(int32_t idealLength, void** result) noexcept = 0;
    virtual int32_t WINRT_CALL get_FirstYearInThisEra(int32_t* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_LastYearInThisEra(int32_t* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_NumberOfYearsInThisEra(int32_t* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_Year(int32_t* value) noexcept = 0;
    virtual int32_t WINRT_CALL put_Year(int32_t value) noexcept = 0;
    virtual int32_t WINRT_CALL AddYears(int32_t years) noexcept = 0;
    virtual int32_t WINRT_CALL YearAsString(void** result) noexcept = 0;
    virtual int32_t WINRT_CALL YearAsTruncatedString(int32_t remainingDigits, void** result) noexcept = 0;
    virtual int32_t WINRT_CALL YearAsPaddedString(int32_t minDigits, void** result) noexcept = 0;
    virtual int32_t WINRT_CALL get_FirstMonthInThisYear(int32_t* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_LastMonthInThisYear(int32_t* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_NumberOfMonthsInThisYear(int32_t* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_Month(int32_t* value) noexcept = 0;
    virtual int32_t WINRT_CALL put_Month(int32_t value) noexcept = 0;
    virtual int32_t WINRT_CALL AddMonths(int32_t months) noexcept = 0;
    virtual int32_t WINRT_CALL MonthAsFullString(void** result) noexcept = 0;
    virtual int32_t WINRT_CALL MonthAsString(int32_t idealLength, void** result) noexcept = 0;
    virtual int32_t WINRT_CALL MonthAsFullSoloString(void** result) noexcept = 0;
    virtual int32_t WINRT_CALL MonthAsSoloString(int32_t idealLength, void** result) noexcept = 0;
    virtual int32_t WINRT_CALL MonthAsNumericString(void** result) noexcept = 0;
    virtual int32_t WINRT_CALL MonthAsPaddedNumericString(int32_t minDigits, void** result) noexcept = 0;
    virtual int32_t WINRT_CALL AddWeeks(int32_t weeks) noexcept = 0;
    virtual int32_t WINRT_CALL get_FirstDayInThisMonth(int32_t* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_LastDayInThisMonth(int32_t* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_NumberOfDaysInThisMonth(int32_t* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_Day(int32_t* value) noexcept = 0;
    virtual int32_t WINRT_CALL put_Day(int32_t value) noexcept = 0;
    virtual int32_t WINRT_CALL AddDays(int32_t days) noexcept = 0;
    virtual int32_t WINRT_CALL DayAsString(void** result) noexcept = 0;
    virtual int32_t WINRT_CALL DayAsPaddedString(int32_t minDigits, void** result) noexcept = 0;
    virtual int32_t WINRT_CALL get_DayOfWeek(Windows::Globalization::DayOfWeek* value) noexcept = 0;
    virtual int32_t WINRT_CALL DayOfWeekAsFullString(void** result) noexcept = 0;
    virtual int32_t WINRT_CALL DayOfWeekAsString(int32_t idealLength, void** result) noexcept = 0;
    virtual int32_t WINRT_CALL DayOfWeekAsFullSoloString(void** result) noexcept = 0;
    virtual int32_t WINRT_CALL DayOfWeekAsSoloString(int32_t idealLength, void** result) noexcept = 0;
    virtual int32_t WINRT_CALL get_FirstPeriodInThisDay(int32_t* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_LastPeriodInThisDay(int32_t* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_NumberOfPeriodsInThisDay(int32_t* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_Period(int32_t* value) noexcept = 0;
    virtual int32_t WINRT_CALL put_Period(int32_t value) noexcept = 0;
    virtual int32_t WINRT_CALL AddPeriods(int32_t periods) noexcept = 0;
    virtual int32_t WINRT_CALL PeriodAsFullString(void** result) noexcept = 0;
    virtual int32_t WINRT_CALL PeriodAsString(int32_t idealLength, void** result) noexcept = 0;
    virtual int32_t WINRT_CALL get_FirstHourInThisPeriod(int32_t* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_LastHourInThisPeriod(int32_t* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_NumberOfHoursInThisPeriod(int32_t* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_Hour(int32_t* value) noexcept = 0;
    virtual int32_t WINRT_CALL put_Hour(int32_t value) noexcept = 0;
    virtual int32_t WINRT_CALL AddHours(int32_t hours) noexcept = 0;
    virtual int32_t WINRT_CALL HourAsString(void** result) noexcept = 0;
    virtual int32_t WINRT_CALL HourAsPaddedString(int32_t minDigits, void** result) noexcept = 0;
    virtual int32_t WINRT_CALL get_Minute(int32_t* value) noexcept = 0;
    virtual int32_t WINRT_CALL put_Minute(int32_t value) noexcept = 0;
    virtual int32_t WINRT_CALL AddMinutes(int32_t minutes) noexcept = 0;
    virtual int32_t WINRT_CALL MinuteAsString(void** result) noexcept = 0;
    virtual int32_t WINRT_CALL MinuteAsPaddedString(int32_t minDigits, void** result) noexcept = 0;
    virtual int32_t WINRT_CALL get_Second(int32_t* value) noexcept = 0;
    virtual int32_t WINRT_CALL put_Second(int32_t value) noexcept = 0;
    virtual int32_t WINRT_CALL AddSeconds(int32_t seconds) noexcept = 0;
    virtual int32_t WINRT_CALL SecondAsString(void** result) noexcept = 0;
    virtual int32_t WINRT_CALL SecondAsPaddedString(int32_t minDigits, void** result) noexcept = 0;
    virtual int32_t WINRT_CALL get_Nanosecond(int32_t* value) noexcept = 0;
    virtual int32_t WINRT_CALL put_Nanosecond(int32_t value) noexcept = 0;
    virtual int32_t WINRT_CALL AddNanoseconds(int32_t nanoseconds) noexcept = 0;
    virtual int32_t WINRT_CALL NanosecondAsString(void** result) noexcept = 0;
    virtual int32_t WINRT_CALL NanosecondAsPaddedString(int32_t minDigits, void** result) noexcept = 0;
    virtual int32_t WINRT_CALL Compare(void* other, int32_t* result) noexcept = 0;
    virtual int32_t WINRT_CALL CompareDateTime(Windows::Foundation::DateTime other, int32_t* result) noexcept = 0;
    virtual int32_t WINRT_CALL CopyTo(void* other) noexcept = 0;
    virtual int32_t WINRT_CALL get_FirstMinuteInThisHour(int32_t* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_LastMinuteInThisHour(int32_t* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_NumberOfMinutesInThisHour(int32_t* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_FirstSecondInThisMinute(int32_t* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_LastSecondInThisMinute(int32_t* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_NumberOfSecondsInThisMinute(int32_t* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_ResolvedLanguage(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_IsDaylightSavingTime(bool* value) noexcept = 0;
};};

template <> struct abi<Windows::Globalization::ICalendarFactory>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL CreateCalendarDefaultCalendarAndClock(void* languages, void** result) noexcept = 0;
    virtual int32_t WINRT_CALL CreateCalendar(void* languages, void* calendar, void* clock, void** result) noexcept = 0;
};};

template <> struct abi<Windows::Globalization::ICalendarFactory2>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL CreateCalendarWithTimeZone(void* languages, void* calendar, void* clock, void* timeZoneId, void** result) noexcept = 0;
};};

template <> struct abi<Windows::Globalization::ICalendarIdentifiersStatics>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL get_Gregorian(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_Hebrew(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_Hijri(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_Japanese(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_Julian(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_Korean(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_Taiwan(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_Thai(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_UmAlQura(void** value) noexcept = 0;
};};

template <> struct abi<Windows::Globalization::ICalendarIdentifiersStatics2>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL get_Persian(void** value) noexcept = 0;
};};

template <> struct abi<Windows::Globalization::ICalendarIdentifiersStatics3>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL get_ChineseLunar(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_JapaneseLunar(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_KoreanLunar(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_TaiwanLunar(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_VietnameseLunar(void** value) noexcept = 0;
};};

template <> struct abi<Windows::Globalization::IClockIdentifiersStatics>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL get_TwelveHour(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_TwentyFourHour(void** value) noexcept = 0;
};};

template <> struct abi<Windows::Globalization::ICurrencyAmount>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL get_Amount(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_Currency(void** value) noexcept = 0;
};};

template <> struct abi<Windows::Globalization::ICurrencyAmountFactory>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL Create(void* amount, void* currency, void** result) noexcept = 0;
};};

template <> struct abi<Windows::Globalization::ICurrencyIdentifiersStatics>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL get_AED(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_AFN(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_ALL(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_AMD(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_ANG(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_AOA(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_ARS(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_AUD(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_AWG(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_AZN(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_BAM(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_BBD(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_BDT(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_BGN(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_BHD(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_BIF(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_BMD(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_BND(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_BOB(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_BRL(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_BSD(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_BTN(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_BWP(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_BYR(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_BZD(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_CAD(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_CDF(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_CHF(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_CLP(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_CNY(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_COP(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_CRC(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_CUP(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_CVE(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_CZK(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_DJF(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_DKK(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_DOP(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_DZD(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_EGP(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_ERN(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_ETB(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_EUR(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_FJD(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_FKP(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_GBP(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_GEL(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_GHS(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_GIP(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_GMD(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_GNF(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_GTQ(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_GYD(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_HKD(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_HNL(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_HRK(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_HTG(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_HUF(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_IDR(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_ILS(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_INR(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_IQD(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_IRR(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_ISK(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_JMD(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_JOD(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_JPY(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_KES(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_KGS(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_KHR(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_KMF(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_KPW(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_KRW(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_KWD(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_KYD(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_KZT(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_LAK(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_LBP(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_LKR(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_LRD(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_LSL(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_LTL(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_LVL(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_LYD(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_MAD(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_MDL(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_MGA(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_MKD(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_MMK(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_MNT(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_MOP(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_MRO(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_MUR(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_MVR(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_MWK(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_MXN(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_MYR(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_MZN(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_NAD(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_NGN(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_NIO(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_NOK(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_NPR(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_NZD(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_OMR(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_PAB(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_PEN(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_PGK(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_PHP(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_PKR(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_PLN(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_PYG(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_QAR(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_RON(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_RSD(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_RUB(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_RWF(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_SAR(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_SBD(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_SCR(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_SDG(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_SEK(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_SGD(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_SHP(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_SLL(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_SOS(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_SRD(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_STD(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_SYP(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_SZL(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_THB(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_TJS(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_TMT(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_TND(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_TOP(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_TRY(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_TTD(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_TWD(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_TZS(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_UAH(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_UGX(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_USD(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_UYU(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_UZS(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_VEF(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_VND(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_VUV(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_WST(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_XAF(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_XCD(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_XOF(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_XPF(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_XXX(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_YER(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_ZAR(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_ZMW(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_ZWL(void** value) noexcept = 0;
};};

template <> struct abi<Windows::Globalization::ICurrencyIdentifiersStatics2>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL get_BYN(void** value) noexcept = 0;
};};

template <> struct abi<Windows::Globalization::ICurrencyIdentifiersStatics3>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL get_MRU(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_SSP(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_STN(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_VES(void** value) noexcept = 0;
};};

template <> struct abi<Windows::Globalization::IGeographicRegion>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL get_Code(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_CodeTwoLetter(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_CodeThreeLetter(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_CodeThreeDigit(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_DisplayName(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_NativeName(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_CurrenciesInUse(void** value) noexcept = 0;
};};

template <> struct abi<Windows::Globalization::IGeographicRegionFactory>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL CreateGeographicRegion(void* geographicRegionCode, void** result) noexcept = 0;
};};

template <> struct abi<Windows::Globalization::IGeographicRegionStatics>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL IsSupported(void* geographicRegionCode, bool* result) noexcept = 0;
};};

template <> struct abi<Windows::Globalization::IJapanesePhoneme>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL get_DisplayText(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_YomiText(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_IsPhraseStart(bool* value) noexcept = 0;
};};

template <> struct abi<Windows::Globalization::IJapanesePhoneticAnalyzerStatics>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL GetWords(void* input, void** result) noexcept = 0;
    virtual int32_t WINRT_CALL GetWordsWithMonoRubyOption(void* input, bool monoRuby, void** result) noexcept = 0;
};};

template <> struct abi<Windows::Globalization::ILanguage>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL get_LanguageTag(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_DisplayName(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_NativeName(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_Script(void** value) noexcept = 0;
};};

template <> struct abi<Windows::Globalization::ILanguage2>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL get_LayoutDirection(Windows::Globalization::LanguageLayoutDirection* value) noexcept = 0;
};};

template <> struct abi<Windows::Globalization::ILanguageExtensionSubtags>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL GetExtensionSubtags(void* singleton, void** value) noexcept = 0;
};};

template <> struct abi<Windows::Globalization::ILanguageFactory>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL CreateLanguage(void* languageTag, void** result) noexcept = 0;
};};

template <> struct abi<Windows::Globalization::ILanguageStatics>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL IsWellFormed(void* languageTag, bool* result) noexcept = 0;
    virtual int32_t WINRT_CALL get_CurrentInputMethodLanguageTag(void** value) noexcept = 0;
};};

template <> struct abi<Windows::Globalization::ILanguageStatics2>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL TrySetInputMethodLanguageTag(void* languageTag, bool* result) noexcept = 0;
};};

template <> struct abi<Windows::Globalization::INumeralSystemIdentifiersStatics>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL get_Arab(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_ArabExt(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_Bali(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_Beng(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_Cham(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_Deva(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_FullWide(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_Gujr(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_Guru(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_HaniDec(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_Java(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_Kali(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_Khmr(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_Knda(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_Lana(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_LanaTham(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_Laoo(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_Latn(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_Lepc(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_Limb(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_Mlym(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_Mong(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_Mtei(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_Mymr(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_MymrShan(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_Nkoo(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_Olck(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_Orya(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_Saur(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_Sund(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_Talu(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_TamlDec(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_Telu(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_Thai(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_Tibt(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_Vaii(void** value) noexcept = 0;
};};

template <> struct abi<Windows::Globalization::INumeralSystemIdentifiersStatics2>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL get_Brah(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_Osma(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_MathBold(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_MathDbl(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_MathSans(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_MathSanb(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_MathMono(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_ZmthBold(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_ZmthDbl(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_ZmthSans(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_ZmthSanb(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_ZmthMono(void** value) noexcept = 0;
};};

template <> struct abi<Windows::Globalization::ITimeZoneOnCalendar>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL GetTimeZone(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL ChangeTimeZone(void* timeZoneId) noexcept = 0;
    virtual int32_t WINRT_CALL TimeZoneAsFullString(void** result) noexcept = 0;
    virtual int32_t WINRT_CALL TimeZoneAsString(int32_t idealLength, void** result) noexcept = 0;
};};

template <typename D>
struct consume_Windows_Globalization_IApplicationLanguagesStatics
{
    hstring PrimaryLanguageOverride() const;
    void PrimaryLanguageOverride(param::hstring const& value) const;
    Windows::Foundation::Collections::IVectorView<hstring> Languages() const;
    Windows::Foundation::Collections::IVectorView<hstring> ManifestLanguages() const;
};
template <> struct consume<Windows::Globalization::IApplicationLanguagesStatics> { template <typename D> using type = consume_Windows_Globalization_IApplicationLanguagesStatics<D>; };

template <typename D>
struct consume_Windows_Globalization_IApplicationLanguagesStatics2
{
    Windows::Foundation::Collections::IVectorView<hstring> GetLanguagesForUser(Windows::System::User const& user) const;
};
template <> struct consume<Windows::Globalization::IApplicationLanguagesStatics2> { template <typename D> using type = consume_Windows_Globalization_IApplicationLanguagesStatics2<D>; };

template <typename D>
struct consume_Windows_Globalization_ICalendar
{
    Windows::Globalization::Calendar Clone() const;
    void SetToMin() const;
    void SetToMax() const;
    Windows::Foundation::Collections::IVectorView<hstring> Languages() const;
    hstring NumeralSystem() const;
    void NumeralSystem(param::hstring const& value) const;
    hstring GetCalendarSystem() const;
    void ChangeCalendarSystem(param::hstring const& value) const;
    hstring GetClock() const;
    void ChangeClock(param::hstring const& value) const;
    Windows::Foundation::DateTime GetDateTime() const;
    void SetDateTime(Windows::Foundation::DateTime const& value) const;
    void SetToNow() const;
    int32_t FirstEra() const;
    int32_t LastEra() const;
    int32_t NumberOfEras() const;
    int32_t Era() const;
    void Era(int32_t value) const;
    void AddEras(int32_t eras) const;
    hstring EraAsString() const;
    hstring EraAsString(int32_t idealLength) const;
    int32_t FirstYearInThisEra() const;
    int32_t LastYearInThisEra() const;
    int32_t NumberOfYearsInThisEra() const;
    int32_t Year() const;
    void Year(int32_t value) const;
    void AddYears(int32_t years) const;
    hstring YearAsString() const;
    hstring YearAsTruncatedString(int32_t remainingDigits) const;
    hstring YearAsPaddedString(int32_t minDigits) const;
    int32_t FirstMonthInThisYear() const;
    int32_t LastMonthInThisYear() const;
    int32_t NumberOfMonthsInThisYear() const;
    int32_t Month() const;
    void Month(int32_t value) const;
    void AddMonths(int32_t months) const;
    hstring MonthAsString() const;
    hstring MonthAsString(int32_t idealLength) const;
    hstring MonthAsSoloString() const;
    hstring MonthAsSoloString(int32_t idealLength) const;
    hstring MonthAsNumericString() const;
    hstring MonthAsPaddedNumericString(int32_t minDigits) const;
    void AddWeeks(int32_t weeks) const;
    int32_t FirstDayInThisMonth() const;
    int32_t LastDayInThisMonth() const;
    int32_t NumberOfDaysInThisMonth() const;
    int32_t Day() const;
    void Day(int32_t value) const;
    void AddDays(int32_t days) const;
    hstring DayAsString() const;
    hstring DayAsPaddedString(int32_t minDigits) const;
    Windows::Globalization::DayOfWeek DayOfWeek() const;
    hstring DayOfWeekAsString() const;
    hstring DayOfWeekAsString(int32_t idealLength) const;
    hstring DayOfWeekAsSoloString() const;
    hstring DayOfWeekAsSoloString(int32_t idealLength) const;
    int32_t FirstPeriodInThisDay() const;
    int32_t LastPeriodInThisDay() const;
    int32_t NumberOfPeriodsInThisDay() const;
    int32_t Period() const;
    void Period(int32_t value) const;
    void AddPeriods(int32_t periods) const;
    hstring PeriodAsString() const;
    hstring PeriodAsString(int32_t idealLength) const;
    int32_t FirstHourInThisPeriod() const;
    int32_t LastHourInThisPeriod() const;
    int32_t NumberOfHoursInThisPeriod() const;
    int32_t Hour() const;
    void Hour(int32_t value) const;
    void AddHours(int32_t hours) const;
    hstring HourAsString() const;
    hstring HourAsPaddedString(int32_t minDigits) const;
    int32_t Minute() const;
    void Minute(int32_t value) const;
    void AddMinutes(int32_t minutes) const;
    hstring MinuteAsString() const;
    hstring MinuteAsPaddedString(int32_t minDigits) const;
    int32_t Second() const;
    void Second(int32_t value) const;
    void AddSeconds(int32_t seconds) const;
    hstring SecondAsString() const;
    hstring SecondAsPaddedString(int32_t minDigits) const;
    int32_t Nanosecond() const;
    void Nanosecond(int32_t value) const;
    void AddNanoseconds(int32_t nanoseconds) const;
    hstring NanosecondAsString() const;
    hstring NanosecondAsPaddedString(int32_t minDigits) const;
    int32_t Compare(Windows::Globalization::Calendar const& other) const;
    int32_t CompareDateTime(Windows::Foundation::DateTime const& other) const;
    void CopyTo(Windows::Globalization::Calendar const& other) const;
    int32_t FirstMinuteInThisHour() const;
    int32_t LastMinuteInThisHour() const;
    int32_t NumberOfMinutesInThisHour() const;
    int32_t FirstSecondInThisMinute() const;
    int32_t LastSecondInThisMinute() const;
    int32_t NumberOfSecondsInThisMinute() const;
    hstring ResolvedLanguage() const;
    bool IsDaylightSavingTime() const;
};
template <> struct consume<Windows::Globalization::ICalendar> { template <typename D> using type = consume_Windows_Globalization_ICalendar<D>; };

template <typename D>
struct consume_Windows_Globalization_ICalendarFactory
{
    Windows::Globalization::Calendar CreateCalendarDefaultCalendarAndClock(param::iterable<hstring> const& languages) const;
    Windows::Globalization::Calendar CreateCalendar(param::iterable<hstring> const& languages, param::hstring const& calendar, param::hstring const& clock) const;
};
template <> struct consume<Windows::Globalization::ICalendarFactory> { template <typename D> using type = consume_Windows_Globalization_ICalendarFactory<D>; };

template <typename D>
struct consume_Windows_Globalization_ICalendarFactory2
{
    Windows::Globalization::Calendar CreateCalendarWithTimeZone(param::iterable<hstring> const& languages, param::hstring const& calendar, param::hstring const& clock, param::hstring const& timeZoneId) const;
};
template <> struct consume<Windows::Globalization::ICalendarFactory2> { template <typename D> using type = consume_Windows_Globalization_ICalendarFactory2<D>; };

template <typename D>
struct consume_Windows_Globalization_ICalendarIdentifiersStatics
{
    hstring Gregorian() const;
    hstring Hebrew() const;
    hstring Hijri() const;
    hstring Japanese() const;
    hstring Julian() const;
    hstring Korean() const;
    hstring Taiwan() const;
    hstring Thai() const;
    hstring UmAlQura() const;
};
template <> struct consume<Windows::Globalization::ICalendarIdentifiersStatics> { template <typename D> using type = consume_Windows_Globalization_ICalendarIdentifiersStatics<D>; };

template <typename D>
struct consume_Windows_Globalization_ICalendarIdentifiersStatics2
{
    hstring Persian() const;
};
template <> struct consume<Windows::Globalization::ICalendarIdentifiersStatics2> { template <typename D> using type = consume_Windows_Globalization_ICalendarIdentifiersStatics2<D>; };

template <typename D>
struct consume_Windows_Globalization_ICalendarIdentifiersStatics3
{
    hstring ChineseLunar() const;
    hstring JapaneseLunar() const;
    hstring KoreanLunar() const;
    hstring TaiwanLunar() const;
    hstring VietnameseLunar() const;
};
template <> struct consume<Windows::Globalization::ICalendarIdentifiersStatics3> { template <typename D> using type = consume_Windows_Globalization_ICalendarIdentifiersStatics3<D>; };

template <typename D>
struct consume_Windows_Globalization_IClockIdentifiersStatics
{
    hstring TwelveHour() const;
    hstring TwentyFourHour() const;
};
template <> struct consume<Windows::Globalization::IClockIdentifiersStatics> { template <typename D> using type = consume_Windows_Globalization_IClockIdentifiersStatics<D>; };

template <typename D>
struct consume_Windows_Globalization_ICurrencyAmount
{
    hstring Amount() const;
    hstring Currency() const;
};
template <> struct consume<Windows::Globalization::ICurrencyAmount> { template <typename D> using type = consume_Windows_Globalization_ICurrencyAmount<D>; };

template <typename D>
struct consume_Windows_Globalization_ICurrencyAmountFactory
{
    Windows::Globalization::CurrencyAmount Create(param::hstring const& amount, param::hstring const& currency) const;
};
template <> struct consume<Windows::Globalization::ICurrencyAmountFactory> { template <typename D> using type = consume_Windows_Globalization_ICurrencyAmountFactory<D>; };

template <typename D>
struct consume_Windows_Globalization_ICurrencyIdentifiersStatics
{
    hstring AED() const;
    hstring AFN() const;
    hstring ALL() const;
    hstring AMD() const;
    hstring ANG() const;
    hstring AOA() const;
    hstring ARS() const;
    hstring AUD() const;
    hstring AWG() const;
    hstring AZN() const;
    hstring BAM() const;
    hstring BBD() const;
    hstring BDT() const;
    hstring BGN() const;
    hstring BHD() const;
    hstring BIF() const;
    hstring BMD() const;
    hstring BND() const;
    hstring BOB() const;
    hstring BRL() const;
    hstring BSD() const;
    hstring BTN() const;
    hstring BWP() const;
    hstring BYR() const;
    hstring BZD() const;
    hstring CAD() const;
    hstring CDF() const;
    hstring CHF() const;
    hstring CLP() const;
    hstring CNY() const;
    hstring COP() const;
    hstring CRC() const;
    hstring CUP() const;
    hstring CVE() const;
    hstring CZK() const;
    hstring DJF() const;
    hstring DKK() const;
    hstring DOP() const;
    hstring DZD() const;
    hstring EGP() const;
    hstring ERN() const;
    hstring ETB() const;
    hstring EUR() const;
    hstring FJD() const;
    hstring FKP() const;
    hstring GBP() const;
    hstring GEL() const;
    hstring GHS() const;
    hstring GIP() const;
    hstring GMD() const;
    hstring GNF() const;
    hstring GTQ() const;
    hstring GYD() const;
    hstring HKD() const;
    hstring HNL() const;
    hstring HRK() const;
    hstring HTG() const;
    hstring HUF() const;
    hstring IDR() const;
    hstring ILS() const;
    hstring INR() const;
    hstring IQD() const;
    hstring IRR() const;
    hstring ISK() const;
    hstring JMD() const;
    hstring JOD() const;
    hstring JPY() const;
    hstring KES() const;
    hstring KGS() const;
    hstring KHR() const;
    hstring KMF() const;
    hstring KPW() const;
    hstring KRW() const;
    hstring KWD() const;
    hstring KYD() const;
    hstring KZT() const;
    hstring LAK() const;
    hstring LBP() const;
    hstring LKR() const;
    hstring LRD() const;
    hstring LSL() const;
    hstring LTL() const;
    hstring LVL() const;
    hstring LYD() const;
    hstring MAD() const;
    hstring MDL() const;
    hstring MGA() const;
    hstring MKD() const;
    hstring MMK() const;
    hstring MNT() const;
    hstring MOP() const;
    hstring MRO() const;
    hstring MUR() const;
    hstring MVR() const;
    hstring MWK() const;
    hstring MXN() const;
    hstring MYR() const;
    hstring MZN() const;
    hstring NAD() const;
    hstring NGN() const;
    hstring NIO() const;
    hstring NOK() const;
    hstring NPR() const;
    hstring NZD() const;
    hstring OMR() const;
    hstring PAB() const;
    hstring PEN() const;
    hstring PGK() const;
    hstring PHP() const;
    hstring PKR() const;
    hstring PLN() const;
    hstring PYG() const;
    hstring QAR() const;
    hstring RON() const;
    hstring RSD() const;
    hstring RUB() const;
    hstring RWF() const;
    hstring SAR() const;
    hstring SBD() const;
    hstring SCR() const;
    hstring SDG() const;
    hstring SEK() const;
    hstring SGD() const;
    hstring SHP() const;
    hstring SLL() const;
    hstring SOS() const;
    hstring SRD() const;
    hstring STD() const;
    hstring SYP() const;
    hstring SZL() const;
    hstring THB() const;
    hstring TJS() const;
    hstring TMT() const;
    hstring TND() const;
    hstring TOP() const;
    hstring TRY() const;
    hstring TTD() const;
    hstring TWD() const;
    hstring TZS() const;
    hstring UAH() const;
    hstring UGX() const;
    hstring USD() const;
    hstring UYU() const;
    hstring UZS() const;
    hstring VEF() const;
    hstring VND() const;
    hstring VUV() const;
    hstring WST() const;
    hstring XAF() const;
    hstring XCD() const;
    hstring XOF() const;
    hstring XPF() const;
    hstring XXX() const;
    hstring YER() const;
    hstring ZAR() const;
    hstring ZMW() const;
    hstring ZWL() const;
};
template <> struct consume<Windows::Globalization::ICurrencyIdentifiersStatics> { template <typename D> using type = consume_Windows_Globalization_ICurrencyIdentifiersStatics<D>; };

template <typename D>
struct consume_Windows_Globalization_ICurrencyIdentifiersStatics2
{
    hstring BYN() const;
};
template <> struct consume<Windows::Globalization::ICurrencyIdentifiersStatics2> { template <typename D> using type = consume_Windows_Globalization_ICurrencyIdentifiersStatics2<D>; };

template <typename D>
struct consume_Windows_Globalization_ICurrencyIdentifiersStatics3
{
    hstring MRU() const;
    hstring SSP() const;
    hstring STN() const;
    hstring VES() const;
};
template <> struct consume<Windows::Globalization::ICurrencyIdentifiersStatics3> { template <typename D> using type = consume_Windows_Globalization_ICurrencyIdentifiersStatics3<D>; };

template <typename D>
struct consume_Windows_Globalization_IGeographicRegion
{
    hstring Code() const;
    hstring CodeTwoLetter() const;
    hstring CodeThreeLetter() const;
    hstring CodeThreeDigit() const;
    hstring DisplayName() const;
    hstring NativeName() const;
    Windows::Foundation::Collections::IVectorView<hstring> CurrenciesInUse() const;
};
template <> struct consume<Windows::Globalization::IGeographicRegion> { template <typename D> using type = consume_Windows_Globalization_IGeographicRegion<D>; };

template <typename D>
struct consume_Windows_Globalization_IGeographicRegionFactory
{
    Windows::Globalization::GeographicRegion CreateGeographicRegion(param::hstring const& geographicRegionCode) const;
};
template <> struct consume<Windows::Globalization::IGeographicRegionFactory> { template <typename D> using type = consume_Windows_Globalization_IGeographicRegionFactory<D>; };

template <typename D>
struct consume_Windows_Globalization_IGeographicRegionStatics
{
    bool IsSupported(param::hstring const& geographicRegionCode) const;
};
template <> struct consume<Windows::Globalization::IGeographicRegionStatics> { template <typename D> using type = consume_Windows_Globalization_IGeographicRegionStatics<D>; };

template <typename D>
struct consume_Windows_Globalization_IJapanesePhoneme
{
    hstring DisplayText() const;
    hstring YomiText() const;
    bool IsPhraseStart() const;
};
template <> struct consume<Windows::Globalization::IJapanesePhoneme> { template <typename D> using type = consume_Windows_Globalization_IJapanesePhoneme<D>; };

template <typename D>
struct consume_Windows_Globalization_IJapanesePhoneticAnalyzerStatics
{
    Windows::Foundation::Collections::IVectorView<Windows::Globalization::JapanesePhoneme> GetWords(param::hstring const& input) const;
    Windows::Foundation::Collections::IVectorView<Windows::Globalization::JapanesePhoneme> GetWords(param::hstring const& input, bool monoRuby) const;
};
template <> struct consume<Windows::Globalization::IJapanesePhoneticAnalyzerStatics> { template <typename D> using type = consume_Windows_Globalization_IJapanesePhoneticAnalyzerStatics<D>; };

template <typename D>
struct consume_Windows_Globalization_ILanguage
{
    hstring LanguageTag() const;
    hstring DisplayName() const;
    hstring NativeName() const;
    hstring Script() const;
};
template <> struct consume<Windows::Globalization::ILanguage> { template <typename D> using type = consume_Windows_Globalization_ILanguage<D>; };

template <typename D>
struct consume_Windows_Globalization_ILanguage2
{
    Windows::Globalization::LanguageLayoutDirection LayoutDirection() const;
};
template <> struct consume<Windows::Globalization::ILanguage2> { template <typename D> using type = consume_Windows_Globalization_ILanguage2<D>; };

template <typename D>
struct consume_Windows_Globalization_ILanguageExtensionSubtags
{
    Windows::Foundation::Collections::IVectorView<hstring> GetExtensionSubtags(param::hstring const& singleton) const;
};
template <> struct consume<Windows::Globalization::ILanguageExtensionSubtags> { template <typename D> using type = consume_Windows_Globalization_ILanguageExtensionSubtags<D>; };

template <typename D>
struct consume_Windows_Globalization_ILanguageFactory
{
    Windows::Globalization::Language CreateLanguage(param::hstring const& languageTag) const;
};
template <> struct consume<Windows::Globalization::ILanguageFactory> { template <typename D> using type = consume_Windows_Globalization_ILanguageFactory<D>; };

template <typename D>
struct consume_Windows_Globalization_ILanguageStatics
{
    bool IsWellFormed(param::hstring const& languageTag) const;
    hstring CurrentInputMethodLanguageTag() const;
};
template <> struct consume<Windows::Globalization::ILanguageStatics> { template <typename D> using type = consume_Windows_Globalization_ILanguageStatics<D>; };

template <typename D>
struct consume_Windows_Globalization_ILanguageStatics2
{
    bool TrySetInputMethodLanguageTag(param::hstring const& languageTag) const;
};
template <> struct consume<Windows::Globalization::ILanguageStatics2> { template <typename D> using type = consume_Windows_Globalization_ILanguageStatics2<D>; };

template <typename D>
struct consume_Windows_Globalization_INumeralSystemIdentifiersStatics
{
    hstring Arab() const;
    hstring ArabExt() const;
    hstring Bali() const;
    hstring Beng() const;
    hstring Cham() const;
    hstring Deva() const;
    hstring FullWide() const;
    hstring Gujr() const;
    hstring Guru() const;
    hstring HaniDec() const;
    hstring Java() const;
    hstring Kali() const;
    hstring Khmr() const;
    hstring Knda() const;
    hstring Lana() const;
    hstring LanaTham() const;
    hstring Laoo() const;
    hstring Latn() const;
    hstring Lepc() const;
    hstring Limb() const;
    hstring Mlym() const;
    hstring Mong() const;
    hstring Mtei() const;
    hstring Mymr() const;
    hstring MymrShan() const;
    hstring Nkoo() const;
    hstring Olck() const;
    hstring Orya() const;
    hstring Saur() const;
    hstring Sund() const;
    hstring Talu() const;
    hstring TamlDec() const;
    hstring Telu() const;
    hstring Thai() const;
    hstring Tibt() const;
    hstring Vaii() const;
};
template <> struct consume<Windows::Globalization::INumeralSystemIdentifiersStatics> { template <typename D> using type = consume_Windows_Globalization_INumeralSystemIdentifiersStatics<D>; };

template <typename D>
struct consume_Windows_Globalization_INumeralSystemIdentifiersStatics2
{
    hstring Brah() const;
    hstring Osma() const;
    hstring MathBold() const;
    hstring MathDbl() const;
    hstring MathSans() const;
    hstring MathSanb() const;
    hstring MathMono() const;
    hstring ZmthBold() const;
    hstring ZmthDbl() const;
    hstring ZmthSans() const;
    hstring ZmthSanb() const;
    hstring ZmthMono() const;
};
template <> struct consume<Windows::Globalization::INumeralSystemIdentifiersStatics2> { template <typename D> using type = consume_Windows_Globalization_INumeralSystemIdentifiersStatics2<D>; };

template <typename D>
struct consume_Windows_Globalization_ITimeZoneOnCalendar
{
    hstring GetTimeZone() const;
    void ChangeTimeZone(param::hstring const& timeZoneId) const;
    hstring TimeZoneAsString() const;
    hstring TimeZoneAsString(int32_t idealLength) const;
};
template <> struct consume<Windows::Globalization::ITimeZoneOnCalendar> { template <typename D> using type = consume_Windows_Globalization_ITimeZoneOnCalendar<D>; };

}
