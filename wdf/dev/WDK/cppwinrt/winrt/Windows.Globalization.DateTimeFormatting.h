// C++/WinRT v1.0.190111.3

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#pragma once

#include "winrt/base.h"

#include "winrt/Windows.Foundation.h"
#include "winrt/Windows.Foundation.Collections.h"
#include "winrt/impl/Windows.Globalization.DateTimeFormatting.2.h"
#include "winrt/Windows.Globalization.h"

namespace winrt::impl {

template <typename D> Windows::Foundation::Collections::IVectorView<hstring> consume_Windows_Globalization_DateTimeFormatting_IDateTimeFormatter<D>::Languages() const
{
    Windows::Foundation::Collections::IVectorView<hstring> value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Globalization::DateTimeFormatting::IDateTimeFormatter)->get_Languages(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_Globalization_DateTimeFormatting_IDateTimeFormatter<D>::GeographicRegion() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Globalization::DateTimeFormatting::IDateTimeFormatter)->get_GeographicRegion(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_Globalization_DateTimeFormatting_IDateTimeFormatter<D>::Calendar() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Globalization::DateTimeFormatting::IDateTimeFormatter)->get_Calendar(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_Globalization_DateTimeFormatting_IDateTimeFormatter<D>::Clock() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Globalization::DateTimeFormatting::IDateTimeFormatter)->get_Clock(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_Globalization_DateTimeFormatting_IDateTimeFormatter<D>::NumeralSystem() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Globalization::DateTimeFormatting::IDateTimeFormatter)->get_NumeralSystem(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_Globalization_DateTimeFormatting_IDateTimeFormatter<D>::NumeralSystem(param::hstring const& value) const
{
    check_hresult(WINRT_SHIM(Windows::Globalization::DateTimeFormatting::IDateTimeFormatter)->put_NumeralSystem(get_abi(value)));
}

template <typename D> Windows::Foundation::Collections::IVectorView<hstring> consume_Windows_Globalization_DateTimeFormatting_IDateTimeFormatter<D>::Patterns() const
{
    Windows::Foundation::Collections::IVectorView<hstring> value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Globalization::DateTimeFormatting::IDateTimeFormatter)->get_Patterns(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_Globalization_DateTimeFormatting_IDateTimeFormatter<D>::Template() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Globalization::DateTimeFormatting::IDateTimeFormatter)->get_Template(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_Globalization_DateTimeFormatting_IDateTimeFormatter<D>::Format(Windows::Foundation::DateTime const& value) const
{
    hstring result{};
    check_hresult(WINRT_SHIM(Windows::Globalization::DateTimeFormatting::IDateTimeFormatter)->Format(get_abi(value), put_abi(result)));
    return result;
}

template <typename D> Windows::Globalization::DateTimeFormatting::YearFormat consume_Windows_Globalization_DateTimeFormatting_IDateTimeFormatter<D>::IncludeYear() const
{
    Windows::Globalization::DateTimeFormatting::YearFormat value{};
    check_hresult(WINRT_SHIM(Windows::Globalization::DateTimeFormatting::IDateTimeFormatter)->get_IncludeYear(put_abi(value)));
    return value;
}

template <typename D> Windows::Globalization::DateTimeFormatting::MonthFormat consume_Windows_Globalization_DateTimeFormatting_IDateTimeFormatter<D>::IncludeMonth() const
{
    Windows::Globalization::DateTimeFormatting::MonthFormat value{};
    check_hresult(WINRT_SHIM(Windows::Globalization::DateTimeFormatting::IDateTimeFormatter)->get_IncludeMonth(put_abi(value)));
    return value;
}

template <typename D> Windows::Globalization::DateTimeFormatting::DayOfWeekFormat consume_Windows_Globalization_DateTimeFormatting_IDateTimeFormatter<D>::IncludeDayOfWeek() const
{
    Windows::Globalization::DateTimeFormatting::DayOfWeekFormat value{};
    check_hresult(WINRT_SHIM(Windows::Globalization::DateTimeFormatting::IDateTimeFormatter)->get_IncludeDayOfWeek(put_abi(value)));
    return value;
}

template <typename D> Windows::Globalization::DateTimeFormatting::DayFormat consume_Windows_Globalization_DateTimeFormatting_IDateTimeFormatter<D>::IncludeDay() const
{
    Windows::Globalization::DateTimeFormatting::DayFormat value{};
    check_hresult(WINRT_SHIM(Windows::Globalization::DateTimeFormatting::IDateTimeFormatter)->get_IncludeDay(put_abi(value)));
    return value;
}

template <typename D> Windows::Globalization::DateTimeFormatting::HourFormat consume_Windows_Globalization_DateTimeFormatting_IDateTimeFormatter<D>::IncludeHour() const
{
    Windows::Globalization::DateTimeFormatting::HourFormat value{};
    check_hresult(WINRT_SHIM(Windows::Globalization::DateTimeFormatting::IDateTimeFormatter)->get_IncludeHour(put_abi(value)));
    return value;
}

template <typename D> Windows::Globalization::DateTimeFormatting::MinuteFormat consume_Windows_Globalization_DateTimeFormatting_IDateTimeFormatter<D>::IncludeMinute() const
{
    Windows::Globalization::DateTimeFormatting::MinuteFormat value{};
    check_hresult(WINRT_SHIM(Windows::Globalization::DateTimeFormatting::IDateTimeFormatter)->get_IncludeMinute(put_abi(value)));
    return value;
}

template <typename D> Windows::Globalization::DateTimeFormatting::SecondFormat consume_Windows_Globalization_DateTimeFormatting_IDateTimeFormatter<D>::IncludeSecond() const
{
    Windows::Globalization::DateTimeFormatting::SecondFormat value{};
    check_hresult(WINRT_SHIM(Windows::Globalization::DateTimeFormatting::IDateTimeFormatter)->get_IncludeSecond(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_Globalization_DateTimeFormatting_IDateTimeFormatter<D>::ResolvedLanguage() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Globalization::DateTimeFormatting::IDateTimeFormatter)->get_ResolvedLanguage(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_Globalization_DateTimeFormatting_IDateTimeFormatter<D>::ResolvedGeographicRegion() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Globalization::DateTimeFormatting::IDateTimeFormatter)->get_ResolvedGeographicRegion(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_Globalization_DateTimeFormatting_IDateTimeFormatter2<D>::Format(Windows::Foundation::DateTime const& datetime, param::hstring const& timeZoneId) const
{
    hstring result{};
    check_hresult(WINRT_SHIM(Windows::Globalization::DateTimeFormatting::IDateTimeFormatter2)->FormatUsingTimeZone(get_abi(datetime), get_abi(timeZoneId), put_abi(result)));
    return result;
}

template <typename D> Windows::Globalization::DateTimeFormatting::DateTimeFormatter consume_Windows_Globalization_DateTimeFormatting_IDateTimeFormatterFactory<D>::CreateDateTimeFormatter(param::hstring const& formatTemplate) const
{
    Windows::Globalization::DateTimeFormatting::DateTimeFormatter result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Globalization::DateTimeFormatting::IDateTimeFormatterFactory)->CreateDateTimeFormatter(get_abi(formatTemplate), put_abi(result)));
    return result;
}

template <typename D> Windows::Globalization::DateTimeFormatting::DateTimeFormatter consume_Windows_Globalization_DateTimeFormatting_IDateTimeFormatterFactory<D>::CreateDateTimeFormatterLanguages(param::hstring const& formatTemplate, param::iterable<hstring> const& languages) const
{
    Windows::Globalization::DateTimeFormatting::DateTimeFormatter result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Globalization::DateTimeFormatting::IDateTimeFormatterFactory)->CreateDateTimeFormatterLanguages(get_abi(formatTemplate), get_abi(languages), put_abi(result)));
    return result;
}

template <typename D> Windows::Globalization::DateTimeFormatting::DateTimeFormatter consume_Windows_Globalization_DateTimeFormatting_IDateTimeFormatterFactory<D>::CreateDateTimeFormatterContext(param::hstring const& formatTemplate, param::iterable<hstring> const& languages, param::hstring const& geographicRegion, param::hstring const& calendar, param::hstring const& clock) const
{
    Windows::Globalization::DateTimeFormatting::DateTimeFormatter result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Globalization::DateTimeFormatting::IDateTimeFormatterFactory)->CreateDateTimeFormatterContext(get_abi(formatTemplate), get_abi(languages), get_abi(geographicRegion), get_abi(calendar), get_abi(clock), put_abi(result)));
    return result;
}

template <typename D> Windows::Globalization::DateTimeFormatting::DateTimeFormatter consume_Windows_Globalization_DateTimeFormatting_IDateTimeFormatterFactory<D>::CreateDateTimeFormatterDate(Windows::Globalization::DateTimeFormatting::YearFormat const& yearFormat, Windows::Globalization::DateTimeFormatting::MonthFormat const& monthFormat, Windows::Globalization::DateTimeFormatting::DayFormat const& dayFormat, Windows::Globalization::DateTimeFormatting::DayOfWeekFormat const& dayOfWeekFormat) const
{
    Windows::Globalization::DateTimeFormatting::DateTimeFormatter result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Globalization::DateTimeFormatting::IDateTimeFormatterFactory)->CreateDateTimeFormatterDate(get_abi(yearFormat), get_abi(monthFormat), get_abi(dayFormat), get_abi(dayOfWeekFormat), put_abi(result)));
    return result;
}

template <typename D> Windows::Globalization::DateTimeFormatting::DateTimeFormatter consume_Windows_Globalization_DateTimeFormatting_IDateTimeFormatterFactory<D>::CreateDateTimeFormatterTime(Windows::Globalization::DateTimeFormatting::HourFormat const& hourFormat, Windows::Globalization::DateTimeFormatting::MinuteFormat const& minuteFormat, Windows::Globalization::DateTimeFormatting::SecondFormat const& secondFormat) const
{
    Windows::Globalization::DateTimeFormatting::DateTimeFormatter result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Globalization::DateTimeFormatting::IDateTimeFormatterFactory)->CreateDateTimeFormatterTime(get_abi(hourFormat), get_abi(minuteFormat), get_abi(secondFormat), put_abi(result)));
    return result;
}

template <typename D> Windows::Globalization::DateTimeFormatting::DateTimeFormatter consume_Windows_Globalization_DateTimeFormatting_IDateTimeFormatterFactory<D>::CreateDateTimeFormatterDateTimeLanguages(Windows::Globalization::DateTimeFormatting::YearFormat const& yearFormat, Windows::Globalization::DateTimeFormatting::MonthFormat const& monthFormat, Windows::Globalization::DateTimeFormatting::DayFormat const& dayFormat, Windows::Globalization::DateTimeFormatting::DayOfWeekFormat const& dayOfWeekFormat, Windows::Globalization::DateTimeFormatting::HourFormat const& hourFormat, Windows::Globalization::DateTimeFormatting::MinuteFormat const& minuteFormat, Windows::Globalization::DateTimeFormatting::SecondFormat const& secondFormat, param::iterable<hstring> const& languages) const
{
    Windows::Globalization::DateTimeFormatting::DateTimeFormatter result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Globalization::DateTimeFormatting::IDateTimeFormatterFactory)->CreateDateTimeFormatterDateTimeLanguages(get_abi(yearFormat), get_abi(monthFormat), get_abi(dayFormat), get_abi(dayOfWeekFormat), get_abi(hourFormat), get_abi(minuteFormat), get_abi(secondFormat), get_abi(languages), put_abi(result)));
    return result;
}

template <typename D> Windows::Globalization::DateTimeFormatting::DateTimeFormatter consume_Windows_Globalization_DateTimeFormatting_IDateTimeFormatterFactory<D>::CreateDateTimeFormatterDateTimeContext(Windows::Globalization::DateTimeFormatting::YearFormat const& yearFormat, Windows::Globalization::DateTimeFormatting::MonthFormat const& monthFormat, Windows::Globalization::DateTimeFormatting::DayFormat const& dayFormat, Windows::Globalization::DateTimeFormatting::DayOfWeekFormat const& dayOfWeekFormat, Windows::Globalization::DateTimeFormatting::HourFormat const& hourFormat, Windows::Globalization::DateTimeFormatting::MinuteFormat const& minuteFormat, Windows::Globalization::DateTimeFormatting::SecondFormat const& secondFormat, param::iterable<hstring> const& languages, param::hstring const& geographicRegion, param::hstring const& calendar, param::hstring const& clock) const
{
    Windows::Globalization::DateTimeFormatting::DateTimeFormatter result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Globalization::DateTimeFormatting::IDateTimeFormatterFactory)->CreateDateTimeFormatterDateTimeContext(get_abi(yearFormat), get_abi(monthFormat), get_abi(dayFormat), get_abi(dayOfWeekFormat), get_abi(hourFormat), get_abi(minuteFormat), get_abi(secondFormat), get_abi(languages), get_abi(geographicRegion), get_abi(calendar), get_abi(clock), put_abi(result)));
    return result;
}

template <typename D> Windows::Globalization::DateTimeFormatting::DateTimeFormatter consume_Windows_Globalization_DateTimeFormatting_IDateTimeFormatterStatics<D>::LongDate() const
{
    Windows::Globalization::DateTimeFormatting::DateTimeFormatter value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Globalization::DateTimeFormatting::IDateTimeFormatterStatics)->get_LongDate(put_abi(value)));
    return value;
}

template <typename D> Windows::Globalization::DateTimeFormatting::DateTimeFormatter consume_Windows_Globalization_DateTimeFormatting_IDateTimeFormatterStatics<D>::LongTime() const
{
    Windows::Globalization::DateTimeFormatting::DateTimeFormatter value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Globalization::DateTimeFormatting::IDateTimeFormatterStatics)->get_LongTime(put_abi(value)));
    return value;
}

template <typename D> Windows::Globalization::DateTimeFormatting::DateTimeFormatter consume_Windows_Globalization_DateTimeFormatting_IDateTimeFormatterStatics<D>::ShortDate() const
{
    Windows::Globalization::DateTimeFormatting::DateTimeFormatter value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Globalization::DateTimeFormatting::IDateTimeFormatterStatics)->get_ShortDate(put_abi(value)));
    return value;
}

template <typename D> Windows::Globalization::DateTimeFormatting::DateTimeFormatter consume_Windows_Globalization_DateTimeFormatting_IDateTimeFormatterStatics<D>::ShortTime() const
{
    Windows::Globalization::DateTimeFormatting::DateTimeFormatter value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Globalization::DateTimeFormatting::IDateTimeFormatterStatics)->get_ShortTime(put_abi(value)));
    return value;
}

template <typename D>
struct produce<D, Windows::Globalization::DateTimeFormatting::IDateTimeFormatter> : produce_base<D, Windows::Globalization::DateTimeFormatting::IDateTimeFormatter>
{
    int32_t WINRT_CALL get_Languages(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Languages, WINRT_WRAP(Windows::Foundation::Collections::IVectorView<hstring>));
            *value = detach_from<Windows::Foundation::Collections::IVectorView<hstring>>(this->shim().Languages());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_GeographicRegion(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GeographicRegion, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().GeographicRegion());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Calendar(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Calendar, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().Calendar());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Clock(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Clock, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().Clock());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_NumeralSystem(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(NumeralSystem, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().NumeralSystem());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_NumeralSystem(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(NumeralSystem, WINRT_WRAP(void), hstring const&);
            this->shim().NumeralSystem(*reinterpret_cast<hstring const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Patterns(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Patterns, WINRT_WRAP(Windows::Foundation::Collections::IVectorView<hstring>));
            *value = detach_from<Windows::Foundation::Collections::IVectorView<hstring>>(this->shim().Patterns());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Template(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Template, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().Template());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL Format(Windows::Foundation::DateTime value, void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Format, WINRT_WRAP(hstring), Windows::Foundation::DateTime const&);
            *result = detach_from<hstring>(this->shim().Format(*reinterpret_cast<Windows::Foundation::DateTime const*>(&value)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_IncludeYear(Windows::Globalization::DateTimeFormatting::YearFormat* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IncludeYear, WINRT_WRAP(Windows::Globalization::DateTimeFormatting::YearFormat));
            *value = detach_from<Windows::Globalization::DateTimeFormatting::YearFormat>(this->shim().IncludeYear());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_IncludeMonth(Windows::Globalization::DateTimeFormatting::MonthFormat* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IncludeMonth, WINRT_WRAP(Windows::Globalization::DateTimeFormatting::MonthFormat));
            *value = detach_from<Windows::Globalization::DateTimeFormatting::MonthFormat>(this->shim().IncludeMonth());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_IncludeDayOfWeek(Windows::Globalization::DateTimeFormatting::DayOfWeekFormat* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IncludeDayOfWeek, WINRT_WRAP(Windows::Globalization::DateTimeFormatting::DayOfWeekFormat));
            *value = detach_from<Windows::Globalization::DateTimeFormatting::DayOfWeekFormat>(this->shim().IncludeDayOfWeek());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_IncludeDay(Windows::Globalization::DateTimeFormatting::DayFormat* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IncludeDay, WINRT_WRAP(Windows::Globalization::DateTimeFormatting::DayFormat));
            *value = detach_from<Windows::Globalization::DateTimeFormatting::DayFormat>(this->shim().IncludeDay());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_IncludeHour(Windows::Globalization::DateTimeFormatting::HourFormat* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IncludeHour, WINRT_WRAP(Windows::Globalization::DateTimeFormatting::HourFormat));
            *value = detach_from<Windows::Globalization::DateTimeFormatting::HourFormat>(this->shim().IncludeHour());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_IncludeMinute(Windows::Globalization::DateTimeFormatting::MinuteFormat* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IncludeMinute, WINRT_WRAP(Windows::Globalization::DateTimeFormatting::MinuteFormat));
            *value = detach_from<Windows::Globalization::DateTimeFormatting::MinuteFormat>(this->shim().IncludeMinute());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_IncludeSecond(Windows::Globalization::DateTimeFormatting::SecondFormat* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IncludeSecond, WINRT_WRAP(Windows::Globalization::DateTimeFormatting::SecondFormat));
            *value = detach_from<Windows::Globalization::DateTimeFormatting::SecondFormat>(this->shim().IncludeSecond());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_ResolvedLanguage(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ResolvedLanguage, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().ResolvedLanguage());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_ResolvedGeographicRegion(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ResolvedGeographicRegion, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().ResolvedGeographicRegion());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Globalization::DateTimeFormatting::IDateTimeFormatter2> : produce_base<D, Windows::Globalization::DateTimeFormatting::IDateTimeFormatter2>
{
    int32_t WINRT_CALL FormatUsingTimeZone(Windows::Foundation::DateTime datetime, void* timeZoneId, void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Format, WINRT_WRAP(hstring), Windows::Foundation::DateTime const&, hstring const&);
            *result = detach_from<hstring>(this->shim().Format(*reinterpret_cast<Windows::Foundation::DateTime const*>(&datetime), *reinterpret_cast<hstring const*>(&timeZoneId)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Globalization::DateTimeFormatting::IDateTimeFormatterFactory> : produce_base<D, Windows::Globalization::DateTimeFormatting::IDateTimeFormatterFactory>
{
    int32_t WINRT_CALL CreateDateTimeFormatter(void* formatTemplate, void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CreateDateTimeFormatter, WINRT_WRAP(Windows::Globalization::DateTimeFormatting::DateTimeFormatter), hstring const&);
            *result = detach_from<Windows::Globalization::DateTimeFormatting::DateTimeFormatter>(this->shim().CreateDateTimeFormatter(*reinterpret_cast<hstring const*>(&formatTemplate)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL CreateDateTimeFormatterLanguages(void* formatTemplate, void* languages, void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CreateDateTimeFormatterLanguages, WINRT_WRAP(Windows::Globalization::DateTimeFormatting::DateTimeFormatter), hstring const&, Windows::Foundation::Collections::IIterable<hstring> const&);
            *result = detach_from<Windows::Globalization::DateTimeFormatting::DateTimeFormatter>(this->shim().CreateDateTimeFormatterLanguages(*reinterpret_cast<hstring const*>(&formatTemplate), *reinterpret_cast<Windows::Foundation::Collections::IIterable<hstring> const*>(&languages)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL CreateDateTimeFormatterContext(void* formatTemplate, void* languages, void* geographicRegion, void* calendar, void* clock, void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CreateDateTimeFormatterContext, WINRT_WRAP(Windows::Globalization::DateTimeFormatting::DateTimeFormatter), hstring const&, Windows::Foundation::Collections::IIterable<hstring> const&, hstring const&, hstring const&, hstring const&);
            *result = detach_from<Windows::Globalization::DateTimeFormatting::DateTimeFormatter>(this->shim().CreateDateTimeFormatterContext(*reinterpret_cast<hstring const*>(&formatTemplate), *reinterpret_cast<Windows::Foundation::Collections::IIterable<hstring> const*>(&languages), *reinterpret_cast<hstring const*>(&geographicRegion), *reinterpret_cast<hstring const*>(&calendar), *reinterpret_cast<hstring const*>(&clock)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL CreateDateTimeFormatterDate(Windows::Globalization::DateTimeFormatting::YearFormat yearFormat, Windows::Globalization::DateTimeFormatting::MonthFormat monthFormat, Windows::Globalization::DateTimeFormatting::DayFormat dayFormat, Windows::Globalization::DateTimeFormatting::DayOfWeekFormat dayOfWeekFormat, void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CreateDateTimeFormatterDate, WINRT_WRAP(Windows::Globalization::DateTimeFormatting::DateTimeFormatter), Windows::Globalization::DateTimeFormatting::YearFormat const&, Windows::Globalization::DateTimeFormatting::MonthFormat const&, Windows::Globalization::DateTimeFormatting::DayFormat const&, Windows::Globalization::DateTimeFormatting::DayOfWeekFormat const&);
            *result = detach_from<Windows::Globalization::DateTimeFormatting::DateTimeFormatter>(this->shim().CreateDateTimeFormatterDate(*reinterpret_cast<Windows::Globalization::DateTimeFormatting::YearFormat const*>(&yearFormat), *reinterpret_cast<Windows::Globalization::DateTimeFormatting::MonthFormat const*>(&monthFormat), *reinterpret_cast<Windows::Globalization::DateTimeFormatting::DayFormat const*>(&dayFormat), *reinterpret_cast<Windows::Globalization::DateTimeFormatting::DayOfWeekFormat const*>(&dayOfWeekFormat)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL CreateDateTimeFormatterTime(Windows::Globalization::DateTimeFormatting::HourFormat hourFormat, Windows::Globalization::DateTimeFormatting::MinuteFormat minuteFormat, Windows::Globalization::DateTimeFormatting::SecondFormat secondFormat, void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CreateDateTimeFormatterTime, WINRT_WRAP(Windows::Globalization::DateTimeFormatting::DateTimeFormatter), Windows::Globalization::DateTimeFormatting::HourFormat const&, Windows::Globalization::DateTimeFormatting::MinuteFormat const&, Windows::Globalization::DateTimeFormatting::SecondFormat const&);
            *result = detach_from<Windows::Globalization::DateTimeFormatting::DateTimeFormatter>(this->shim().CreateDateTimeFormatterTime(*reinterpret_cast<Windows::Globalization::DateTimeFormatting::HourFormat const*>(&hourFormat), *reinterpret_cast<Windows::Globalization::DateTimeFormatting::MinuteFormat const*>(&minuteFormat), *reinterpret_cast<Windows::Globalization::DateTimeFormatting::SecondFormat const*>(&secondFormat)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL CreateDateTimeFormatterDateTimeLanguages(Windows::Globalization::DateTimeFormatting::YearFormat yearFormat, Windows::Globalization::DateTimeFormatting::MonthFormat monthFormat, Windows::Globalization::DateTimeFormatting::DayFormat dayFormat, Windows::Globalization::DateTimeFormatting::DayOfWeekFormat dayOfWeekFormat, Windows::Globalization::DateTimeFormatting::HourFormat hourFormat, Windows::Globalization::DateTimeFormatting::MinuteFormat minuteFormat, Windows::Globalization::DateTimeFormatting::SecondFormat secondFormat, void* languages, void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CreateDateTimeFormatterDateTimeLanguages, WINRT_WRAP(Windows::Globalization::DateTimeFormatting::DateTimeFormatter), Windows::Globalization::DateTimeFormatting::YearFormat const&, Windows::Globalization::DateTimeFormatting::MonthFormat const&, Windows::Globalization::DateTimeFormatting::DayFormat const&, Windows::Globalization::DateTimeFormatting::DayOfWeekFormat const&, Windows::Globalization::DateTimeFormatting::HourFormat const&, Windows::Globalization::DateTimeFormatting::MinuteFormat const&, Windows::Globalization::DateTimeFormatting::SecondFormat const&, Windows::Foundation::Collections::IIterable<hstring> const&);
            *result = detach_from<Windows::Globalization::DateTimeFormatting::DateTimeFormatter>(this->shim().CreateDateTimeFormatterDateTimeLanguages(*reinterpret_cast<Windows::Globalization::DateTimeFormatting::YearFormat const*>(&yearFormat), *reinterpret_cast<Windows::Globalization::DateTimeFormatting::MonthFormat const*>(&monthFormat), *reinterpret_cast<Windows::Globalization::DateTimeFormatting::DayFormat const*>(&dayFormat), *reinterpret_cast<Windows::Globalization::DateTimeFormatting::DayOfWeekFormat const*>(&dayOfWeekFormat), *reinterpret_cast<Windows::Globalization::DateTimeFormatting::HourFormat const*>(&hourFormat), *reinterpret_cast<Windows::Globalization::DateTimeFormatting::MinuteFormat const*>(&minuteFormat), *reinterpret_cast<Windows::Globalization::DateTimeFormatting::SecondFormat const*>(&secondFormat), *reinterpret_cast<Windows::Foundation::Collections::IIterable<hstring> const*>(&languages)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL CreateDateTimeFormatterDateTimeContext(Windows::Globalization::DateTimeFormatting::YearFormat yearFormat, Windows::Globalization::DateTimeFormatting::MonthFormat monthFormat, Windows::Globalization::DateTimeFormatting::DayFormat dayFormat, Windows::Globalization::DateTimeFormatting::DayOfWeekFormat dayOfWeekFormat, Windows::Globalization::DateTimeFormatting::HourFormat hourFormat, Windows::Globalization::DateTimeFormatting::MinuteFormat minuteFormat, Windows::Globalization::DateTimeFormatting::SecondFormat secondFormat, void* languages, void* geographicRegion, void* calendar, void* clock, void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CreateDateTimeFormatterDateTimeContext, WINRT_WRAP(Windows::Globalization::DateTimeFormatting::DateTimeFormatter), Windows::Globalization::DateTimeFormatting::YearFormat const&, Windows::Globalization::DateTimeFormatting::MonthFormat const&, Windows::Globalization::DateTimeFormatting::DayFormat const&, Windows::Globalization::DateTimeFormatting::DayOfWeekFormat const&, Windows::Globalization::DateTimeFormatting::HourFormat const&, Windows::Globalization::DateTimeFormatting::MinuteFormat const&, Windows::Globalization::DateTimeFormatting::SecondFormat const&, Windows::Foundation::Collections::IIterable<hstring> const&, hstring const&, hstring const&, hstring const&);
            *result = detach_from<Windows::Globalization::DateTimeFormatting::DateTimeFormatter>(this->shim().CreateDateTimeFormatterDateTimeContext(*reinterpret_cast<Windows::Globalization::DateTimeFormatting::YearFormat const*>(&yearFormat), *reinterpret_cast<Windows::Globalization::DateTimeFormatting::MonthFormat const*>(&monthFormat), *reinterpret_cast<Windows::Globalization::DateTimeFormatting::DayFormat const*>(&dayFormat), *reinterpret_cast<Windows::Globalization::DateTimeFormatting::DayOfWeekFormat const*>(&dayOfWeekFormat), *reinterpret_cast<Windows::Globalization::DateTimeFormatting::HourFormat const*>(&hourFormat), *reinterpret_cast<Windows::Globalization::DateTimeFormatting::MinuteFormat const*>(&minuteFormat), *reinterpret_cast<Windows::Globalization::DateTimeFormatting::SecondFormat const*>(&secondFormat), *reinterpret_cast<Windows::Foundation::Collections::IIterable<hstring> const*>(&languages), *reinterpret_cast<hstring const*>(&geographicRegion), *reinterpret_cast<hstring const*>(&calendar), *reinterpret_cast<hstring const*>(&clock)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Globalization::DateTimeFormatting::IDateTimeFormatterStatics> : produce_base<D, Windows::Globalization::DateTimeFormatting::IDateTimeFormatterStatics>
{
    int32_t WINRT_CALL get_LongDate(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(LongDate, WINRT_WRAP(Windows::Globalization::DateTimeFormatting::DateTimeFormatter));
            *value = detach_from<Windows::Globalization::DateTimeFormatting::DateTimeFormatter>(this->shim().LongDate());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_LongTime(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(LongTime, WINRT_WRAP(Windows::Globalization::DateTimeFormatting::DateTimeFormatter));
            *value = detach_from<Windows::Globalization::DateTimeFormatting::DateTimeFormatter>(this->shim().LongTime());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_ShortDate(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ShortDate, WINRT_WRAP(Windows::Globalization::DateTimeFormatting::DateTimeFormatter));
            *value = detach_from<Windows::Globalization::DateTimeFormatting::DateTimeFormatter>(this->shim().ShortDate());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_ShortTime(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ShortTime, WINRT_WRAP(Windows::Globalization::DateTimeFormatting::DateTimeFormatter));
            *value = detach_from<Windows::Globalization::DateTimeFormatting::DateTimeFormatter>(this->shim().ShortTime());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

}

WINRT_EXPORT namespace winrt::Windows::Globalization::DateTimeFormatting {

inline DateTimeFormatter::DateTimeFormatter(param::hstring const& formatTemplate) :
    DateTimeFormatter(impl::call_factory<DateTimeFormatter, Windows::Globalization::DateTimeFormatting::IDateTimeFormatterFactory>([&](auto&& f) { return f.CreateDateTimeFormatter(formatTemplate); }))
{}

inline DateTimeFormatter::DateTimeFormatter(param::hstring const& formatTemplate, param::iterable<hstring> const& languages) :
    DateTimeFormatter(impl::call_factory<DateTimeFormatter, Windows::Globalization::DateTimeFormatting::IDateTimeFormatterFactory>([&](auto&& f) { return f.CreateDateTimeFormatterLanguages(formatTemplate, languages); }))
{}

inline DateTimeFormatter::DateTimeFormatter(param::hstring const& formatTemplate, param::iterable<hstring> const& languages, param::hstring const& geographicRegion, param::hstring const& calendar, param::hstring const& clock) :
    DateTimeFormatter(impl::call_factory<DateTimeFormatter, Windows::Globalization::DateTimeFormatting::IDateTimeFormatterFactory>([&](auto&& f) { return f.CreateDateTimeFormatterContext(formatTemplate, languages, geographicRegion, calendar, clock); }))
{}

inline DateTimeFormatter::DateTimeFormatter(Windows::Globalization::DateTimeFormatting::YearFormat const& yearFormat, Windows::Globalization::DateTimeFormatting::MonthFormat const& monthFormat, Windows::Globalization::DateTimeFormatting::DayFormat const& dayFormat, Windows::Globalization::DateTimeFormatting::DayOfWeekFormat const& dayOfWeekFormat) :
    DateTimeFormatter(impl::call_factory<DateTimeFormatter, Windows::Globalization::DateTimeFormatting::IDateTimeFormatterFactory>([&](auto&& f) { return f.CreateDateTimeFormatterDate(yearFormat, monthFormat, dayFormat, dayOfWeekFormat); }))
{}

inline DateTimeFormatter::DateTimeFormatter(Windows::Globalization::DateTimeFormatting::HourFormat const& hourFormat, Windows::Globalization::DateTimeFormatting::MinuteFormat const& minuteFormat, Windows::Globalization::DateTimeFormatting::SecondFormat const& secondFormat) :
    DateTimeFormatter(impl::call_factory<DateTimeFormatter, Windows::Globalization::DateTimeFormatting::IDateTimeFormatterFactory>([&](auto&& f) { return f.CreateDateTimeFormatterTime(hourFormat, minuteFormat, secondFormat); }))
{}

inline DateTimeFormatter::DateTimeFormatter(Windows::Globalization::DateTimeFormatting::YearFormat const& yearFormat, Windows::Globalization::DateTimeFormatting::MonthFormat const& monthFormat, Windows::Globalization::DateTimeFormatting::DayFormat const& dayFormat, Windows::Globalization::DateTimeFormatting::DayOfWeekFormat const& dayOfWeekFormat, Windows::Globalization::DateTimeFormatting::HourFormat const& hourFormat, Windows::Globalization::DateTimeFormatting::MinuteFormat const& minuteFormat, Windows::Globalization::DateTimeFormatting::SecondFormat const& secondFormat, param::iterable<hstring> const& languages) :
    DateTimeFormatter(impl::call_factory<DateTimeFormatter, Windows::Globalization::DateTimeFormatting::IDateTimeFormatterFactory>([&](auto&& f) { return f.CreateDateTimeFormatterDateTimeLanguages(yearFormat, monthFormat, dayFormat, dayOfWeekFormat, hourFormat, minuteFormat, secondFormat, languages); }))
{}

inline DateTimeFormatter::DateTimeFormatter(Windows::Globalization::DateTimeFormatting::YearFormat const& yearFormat, Windows::Globalization::DateTimeFormatting::MonthFormat const& monthFormat, Windows::Globalization::DateTimeFormatting::DayFormat const& dayFormat, Windows::Globalization::DateTimeFormatting::DayOfWeekFormat const& dayOfWeekFormat, Windows::Globalization::DateTimeFormatting::HourFormat const& hourFormat, Windows::Globalization::DateTimeFormatting::MinuteFormat const& minuteFormat, Windows::Globalization::DateTimeFormatting::SecondFormat const& secondFormat, param::iterable<hstring> const& languages, param::hstring const& geographicRegion, param::hstring const& calendar, param::hstring const& clock) :
    DateTimeFormatter(impl::call_factory<DateTimeFormatter, Windows::Globalization::DateTimeFormatting::IDateTimeFormatterFactory>([&](auto&& f) { return f.CreateDateTimeFormatterDateTimeContext(yearFormat, monthFormat, dayFormat, dayOfWeekFormat, hourFormat, minuteFormat, secondFormat, languages, geographicRegion, calendar, clock); }))
{}

inline Windows::Globalization::DateTimeFormatting::DateTimeFormatter DateTimeFormatter::LongDate()
{
    return impl::call_factory<DateTimeFormatter, Windows::Globalization::DateTimeFormatting::IDateTimeFormatterStatics>([&](auto&& f) { return f.LongDate(); });
}

inline Windows::Globalization::DateTimeFormatting::DateTimeFormatter DateTimeFormatter::LongTime()
{
    return impl::call_factory<DateTimeFormatter, Windows::Globalization::DateTimeFormatting::IDateTimeFormatterStatics>([&](auto&& f) { return f.LongTime(); });
}

inline Windows::Globalization::DateTimeFormatting::DateTimeFormatter DateTimeFormatter::ShortDate()
{
    return impl::call_factory<DateTimeFormatter, Windows::Globalization::DateTimeFormatting::IDateTimeFormatterStatics>([&](auto&& f) { return f.ShortDate(); });
}

inline Windows::Globalization::DateTimeFormatting::DateTimeFormatter DateTimeFormatter::ShortTime()
{
    return impl::call_factory<DateTimeFormatter, Windows::Globalization::DateTimeFormatting::IDateTimeFormatterStatics>([&](auto&& f) { return f.ShortTime(); });
}

}

WINRT_EXPORT namespace std {

template<> struct hash<winrt::Windows::Globalization::DateTimeFormatting::IDateTimeFormatter> : winrt::impl::hash_base<winrt::Windows::Globalization::DateTimeFormatting::IDateTimeFormatter> {};
template<> struct hash<winrt::Windows::Globalization::DateTimeFormatting::IDateTimeFormatter2> : winrt::impl::hash_base<winrt::Windows::Globalization::DateTimeFormatting::IDateTimeFormatter2> {};
template<> struct hash<winrt::Windows::Globalization::DateTimeFormatting::IDateTimeFormatterFactory> : winrt::impl::hash_base<winrt::Windows::Globalization::DateTimeFormatting::IDateTimeFormatterFactory> {};
template<> struct hash<winrt::Windows::Globalization::DateTimeFormatting::IDateTimeFormatterStatics> : winrt::impl::hash_base<winrt::Windows::Globalization::DateTimeFormatting::IDateTimeFormatterStatics> {};
template<> struct hash<winrt::Windows::Globalization::DateTimeFormatting::DateTimeFormatter> : winrt::impl::hash_base<winrt::Windows::Globalization::DateTimeFormatting::DateTimeFormatter> {};

}
