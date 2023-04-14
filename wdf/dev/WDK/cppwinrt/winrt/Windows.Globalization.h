// C++/WinRT v1.0.190111.3

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#pragma once

#include "winrt/base.h"

#include "winrt/Windows.Foundation.h"
#include "winrt/Windows.Foundation.Collections.h"
#include "winrt/impl/Windows.System.2.h"
#include "winrt/impl/Windows.Globalization.2.h"

namespace winrt::impl {

template <typename D> hstring consume_Windows_Globalization_IApplicationLanguagesStatics<D>::PrimaryLanguageOverride() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Globalization::IApplicationLanguagesStatics)->get_PrimaryLanguageOverride(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_Globalization_IApplicationLanguagesStatics<D>::PrimaryLanguageOverride(param::hstring const& value) const
{
    check_hresult(WINRT_SHIM(Windows::Globalization::IApplicationLanguagesStatics)->put_PrimaryLanguageOverride(get_abi(value)));
}

template <typename D> Windows::Foundation::Collections::IVectorView<hstring> consume_Windows_Globalization_IApplicationLanguagesStatics<D>::Languages() const
{
    Windows::Foundation::Collections::IVectorView<hstring> value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Globalization::IApplicationLanguagesStatics)->get_Languages(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::Collections::IVectorView<hstring> consume_Windows_Globalization_IApplicationLanguagesStatics<D>::ManifestLanguages() const
{
    Windows::Foundation::Collections::IVectorView<hstring> value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Globalization::IApplicationLanguagesStatics)->get_ManifestLanguages(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::Collections::IVectorView<hstring> consume_Windows_Globalization_IApplicationLanguagesStatics2<D>::GetLanguagesForUser(Windows::System::User const& user) const
{
    Windows::Foundation::Collections::IVectorView<hstring> value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Globalization::IApplicationLanguagesStatics2)->GetLanguagesForUser(get_abi(user), put_abi(value)));
    return value;
}

template <typename D> Windows::Globalization::Calendar consume_Windows_Globalization_ICalendar<D>::Clone() const
{
    Windows::Globalization::Calendar value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Globalization::ICalendar)->Clone(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_Globalization_ICalendar<D>::SetToMin() const
{
    check_hresult(WINRT_SHIM(Windows::Globalization::ICalendar)->SetToMin());
}

template <typename D> void consume_Windows_Globalization_ICalendar<D>::SetToMax() const
{
    check_hresult(WINRT_SHIM(Windows::Globalization::ICalendar)->SetToMax());
}

template <typename D> Windows::Foundation::Collections::IVectorView<hstring> consume_Windows_Globalization_ICalendar<D>::Languages() const
{
    Windows::Foundation::Collections::IVectorView<hstring> value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Globalization::ICalendar)->get_Languages(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_Globalization_ICalendar<D>::NumeralSystem() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Globalization::ICalendar)->get_NumeralSystem(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_Globalization_ICalendar<D>::NumeralSystem(param::hstring const& value) const
{
    check_hresult(WINRT_SHIM(Windows::Globalization::ICalendar)->put_NumeralSystem(get_abi(value)));
}

template <typename D> hstring consume_Windows_Globalization_ICalendar<D>::GetCalendarSystem() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Globalization::ICalendar)->GetCalendarSystem(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_Globalization_ICalendar<D>::ChangeCalendarSystem(param::hstring const& value) const
{
    check_hresult(WINRT_SHIM(Windows::Globalization::ICalendar)->ChangeCalendarSystem(get_abi(value)));
}

template <typename D> hstring consume_Windows_Globalization_ICalendar<D>::GetClock() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Globalization::ICalendar)->GetClock(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_Globalization_ICalendar<D>::ChangeClock(param::hstring const& value) const
{
    check_hresult(WINRT_SHIM(Windows::Globalization::ICalendar)->ChangeClock(get_abi(value)));
}

template <typename D> Windows::Foundation::DateTime consume_Windows_Globalization_ICalendar<D>::GetDateTime() const
{
    Windows::Foundation::DateTime result{};
    check_hresult(WINRT_SHIM(Windows::Globalization::ICalendar)->GetDateTime(put_abi(result)));
    return result;
}

template <typename D> void consume_Windows_Globalization_ICalendar<D>::SetDateTime(Windows::Foundation::DateTime const& value) const
{
    check_hresult(WINRT_SHIM(Windows::Globalization::ICalendar)->SetDateTime(get_abi(value)));
}

template <typename D> void consume_Windows_Globalization_ICalendar<D>::SetToNow() const
{
    check_hresult(WINRT_SHIM(Windows::Globalization::ICalendar)->SetToNow());
}

template <typename D> int32_t consume_Windows_Globalization_ICalendar<D>::FirstEra() const
{
    int32_t value{};
    check_hresult(WINRT_SHIM(Windows::Globalization::ICalendar)->get_FirstEra(&value));
    return value;
}

template <typename D> int32_t consume_Windows_Globalization_ICalendar<D>::LastEra() const
{
    int32_t value{};
    check_hresult(WINRT_SHIM(Windows::Globalization::ICalendar)->get_LastEra(&value));
    return value;
}

template <typename D> int32_t consume_Windows_Globalization_ICalendar<D>::NumberOfEras() const
{
    int32_t value{};
    check_hresult(WINRT_SHIM(Windows::Globalization::ICalendar)->get_NumberOfEras(&value));
    return value;
}

template <typename D> int32_t consume_Windows_Globalization_ICalendar<D>::Era() const
{
    int32_t value{};
    check_hresult(WINRT_SHIM(Windows::Globalization::ICalendar)->get_Era(&value));
    return value;
}

template <typename D> void consume_Windows_Globalization_ICalendar<D>::Era(int32_t value) const
{
    check_hresult(WINRT_SHIM(Windows::Globalization::ICalendar)->put_Era(value));
}

template <typename D> void consume_Windows_Globalization_ICalendar<D>::AddEras(int32_t eras) const
{
    check_hresult(WINRT_SHIM(Windows::Globalization::ICalendar)->AddEras(eras));
}

template <typename D> hstring consume_Windows_Globalization_ICalendar<D>::EraAsString() const
{
    hstring result{};
    check_hresult(WINRT_SHIM(Windows::Globalization::ICalendar)->EraAsFullString(put_abi(result)));
    return result;
}

template <typename D> hstring consume_Windows_Globalization_ICalendar<D>::EraAsString(int32_t idealLength) const
{
    hstring result{};
    check_hresult(WINRT_SHIM(Windows::Globalization::ICalendar)->EraAsString(idealLength, put_abi(result)));
    return result;
}

template <typename D> int32_t consume_Windows_Globalization_ICalendar<D>::FirstYearInThisEra() const
{
    int32_t value{};
    check_hresult(WINRT_SHIM(Windows::Globalization::ICalendar)->get_FirstYearInThisEra(&value));
    return value;
}

template <typename D> int32_t consume_Windows_Globalization_ICalendar<D>::LastYearInThisEra() const
{
    int32_t value{};
    check_hresult(WINRT_SHIM(Windows::Globalization::ICalendar)->get_LastYearInThisEra(&value));
    return value;
}

template <typename D> int32_t consume_Windows_Globalization_ICalendar<D>::NumberOfYearsInThisEra() const
{
    int32_t value{};
    check_hresult(WINRT_SHIM(Windows::Globalization::ICalendar)->get_NumberOfYearsInThisEra(&value));
    return value;
}

template <typename D> int32_t consume_Windows_Globalization_ICalendar<D>::Year() const
{
    int32_t value{};
    check_hresult(WINRT_SHIM(Windows::Globalization::ICalendar)->get_Year(&value));
    return value;
}

template <typename D> void consume_Windows_Globalization_ICalendar<D>::Year(int32_t value) const
{
    check_hresult(WINRT_SHIM(Windows::Globalization::ICalendar)->put_Year(value));
}

template <typename D> void consume_Windows_Globalization_ICalendar<D>::AddYears(int32_t years) const
{
    check_hresult(WINRT_SHIM(Windows::Globalization::ICalendar)->AddYears(years));
}

template <typename D> hstring consume_Windows_Globalization_ICalendar<D>::YearAsString() const
{
    hstring result{};
    check_hresult(WINRT_SHIM(Windows::Globalization::ICalendar)->YearAsString(put_abi(result)));
    return result;
}

template <typename D> hstring consume_Windows_Globalization_ICalendar<D>::YearAsTruncatedString(int32_t remainingDigits) const
{
    hstring result{};
    check_hresult(WINRT_SHIM(Windows::Globalization::ICalendar)->YearAsTruncatedString(remainingDigits, put_abi(result)));
    return result;
}

template <typename D> hstring consume_Windows_Globalization_ICalendar<D>::YearAsPaddedString(int32_t minDigits) const
{
    hstring result{};
    check_hresult(WINRT_SHIM(Windows::Globalization::ICalendar)->YearAsPaddedString(minDigits, put_abi(result)));
    return result;
}

template <typename D> int32_t consume_Windows_Globalization_ICalendar<D>::FirstMonthInThisYear() const
{
    int32_t value{};
    check_hresult(WINRT_SHIM(Windows::Globalization::ICalendar)->get_FirstMonthInThisYear(&value));
    return value;
}

template <typename D> int32_t consume_Windows_Globalization_ICalendar<D>::LastMonthInThisYear() const
{
    int32_t value{};
    check_hresult(WINRT_SHIM(Windows::Globalization::ICalendar)->get_LastMonthInThisYear(&value));
    return value;
}

template <typename D> int32_t consume_Windows_Globalization_ICalendar<D>::NumberOfMonthsInThisYear() const
{
    int32_t value{};
    check_hresult(WINRT_SHIM(Windows::Globalization::ICalendar)->get_NumberOfMonthsInThisYear(&value));
    return value;
}

template <typename D> int32_t consume_Windows_Globalization_ICalendar<D>::Month() const
{
    int32_t value{};
    check_hresult(WINRT_SHIM(Windows::Globalization::ICalendar)->get_Month(&value));
    return value;
}

template <typename D> void consume_Windows_Globalization_ICalendar<D>::Month(int32_t value) const
{
    check_hresult(WINRT_SHIM(Windows::Globalization::ICalendar)->put_Month(value));
}

template <typename D> void consume_Windows_Globalization_ICalendar<D>::AddMonths(int32_t months) const
{
    check_hresult(WINRT_SHIM(Windows::Globalization::ICalendar)->AddMonths(months));
}

template <typename D> hstring consume_Windows_Globalization_ICalendar<D>::MonthAsString() const
{
    hstring result{};
    check_hresult(WINRT_SHIM(Windows::Globalization::ICalendar)->MonthAsFullString(put_abi(result)));
    return result;
}

template <typename D> hstring consume_Windows_Globalization_ICalendar<D>::MonthAsString(int32_t idealLength) const
{
    hstring result{};
    check_hresult(WINRT_SHIM(Windows::Globalization::ICalendar)->MonthAsString(idealLength, put_abi(result)));
    return result;
}

template <typename D> hstring consume_Windows_Globalization_ICalendar<D>::MonthAsSoloString() const
{
    hstring result{};
    check_hresult(WINRT_SHIM(Windows::Globalization::ICalendar)->MonthAsFullSoloString(put_abi(result)));
    return result;
}

template <typename D> hstring consume_Windows_Globalization_ICalendar<D>::MonthAsSoloString(int32_t idealLength) const
{
    hstring result{};
    check_hresult(WINRT_SHIM(Windows::Globalization::ICalendar)->MonthAsSoloString(idealLength, put_abi(result)));
    return result;
}

template <typename D> hstring consume_Windows_Globalization_ICalendar<D>::MonthAsNumericString() const
{
    hstring result{};
    check_hresult(WINRT_SHIM(Windows::Globalization::ICalendar)->MonthAsNumericString(put_abi(result)));
    return result;
}

template <typename D> hstring consume_Windows_Globalization_ICalendar<D>::MonthAsPaddedNumericString(int32_t minDigits) const
{
    hstring result{};
    check_hresult(WINRT_SHIM(Windows::Globalization::ICalendar)->MonthAsPaddedNumericString(minDigits, put_abi(result)));
    return result;
}

template <typename D> void consume_Windows_Globalization_ICalendar<D>::AddWeeks(int32_t weeks) const
{
    check_hresult(WINRT_SHIM(Windows::Globalization::ICalendar)->AddWeeks(weeks));
}

template <typename D> int32_t consume_Windows_Globalization_ICalendar<D>::FirstDayInThisMonth() const
{
    int32_t value{};
    check_hresult(WINRT_SHIM(Windows::Globalization::ICalendar)->get_FirstDayInThisMonth(&value));
    return value;
}

template <typename D> int32_t consume_Windows_Globalization_ICalendar<D>::LastDayInThisMonth() const
{
    int32_t value{};
    check_hresult(WINRT_SHIM(Windows::Globalization::ICalendar)->get_LastDayInThisMonth(&value));
    return value;
}

template <typename D> int32_t consume_Windows_Globalization_ICalendar<D>::NumberOfDaysInThisMonth() const
{
    int32_t value{};
    check_hresult(WINRT_SHIM(Windows::Globalization::ICalendar)->get_NumberOfDaysInThisMonth(&value));
    return value;
}

template <typename D> int32_t consume_Windows_Globalization_ICalendar<D>::Day() const
{
    int32_t value{};
    check_hresult(WINRT_SHIM(Windows::Globalization::ICalendar)->get_Day(&value));
    return value;
}

template <typename D> void consume_Windows_Globalization_ICalendar<D>::Day(int32_t value) const
{
    check_hresult(WINRT_SHIM(Windows::Globalization::ICalendar)->put_Day(value));
}

template <typename D> void consume_Windows_Globalization_ICalendar<D>::AddDays(int32_t days) const
{
    check_hresult(WINRT_SHIM(Windows::Globalization::ICalendar)->AddDays(days));
}

template <typename D> hstring consume_Windows_Globalization_ICalendar<D>::DayAsString() const
{
    hstring result{};
    check_hresult(WINRT_SHIM(Windows::Globalization::ICalendar)->DayAsString(put_abi(result)));
    return result;
}

template <typename D> hstring consume_Windows_Globalization_ICalendar<D>::DayAsPaddedString(int32_t minDigits) const
{
    hstring result{};
    check_hresult(WINRT_SHIM(Windows::Globalization::ICalendar)->DayAsPaddedString(minDigits, put_abi(result)));
    return result;
}

template <typename D> Windows::Globalization::DayOfWeek consume_Windows_Globalization_ICalendar<D>::DayOfWeek() const
{
    Windows::Globalization::DayOfWeek value{};
    check_hresult(WINRT_SHIM(Windows::Globalization::ICalendar)->get_DayOfWeek(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_Globalization_ICalendar<D>::DayOfWeekAsString() const
{
    hstring result{};
    check_hresult(WINRT_SHIM(Windows::Globalization::ICalendar)->DayOfWeekAsFullString(put_abi(result)));
    return result;
}

template <typename D> hstring consume_Windows_Globalization_ICalendar<D>::DayOfWeekAsString(int32_t idealLength) const
{
    hstring result{};
    check_hresult(WINRT_SHIM(Windows::Globalization::ICalendar)->DayOfWeekAsString(idealLength, put_abi(result)));
    return result;
}

template <typename D> hstring consume_Windows_Globalization_ICalendar<D>::DayOfWeekAsSoloString() const
{
    hstring result{};
    check_hresult(WINRT_SHIM(Windows::Globalization::ICalendar)->DayOfWeekAsFullSoloString(put_abi(result)));
    return result;
}

template <typename D> hstring consume_Windows_Globalization_ICalendar<D>::DayOfWeekAsSoloString(int32_t idealLength) const
{
    hstring result{};
    check_hresult(WINRT_SHIM(Windows::Globalization::ICalendar)->DayOfWeekAsSoloString(idealLength, put_abi(result)));
    return result;
}

template <typename D> int32_t consume_Windows_Globalization_ICalendar<D>::FirstPeriodInThisDay() const
{
    int32_t value{};
    check_hresult(WINRT_SHIM(Windows::Globalization::ICalendar)->get_FirstPeriodInThisDay(&value));
    return value;
}

template <typename D> int32_t consume_Windows_Globalization_ICalendar<D>::LastPeriodInThisDay() const
{
    int32_t value{};
    check_hresult(WINRT_SHIM(Windows::Globalization::ICalendar)->get_LastPeriodInThisDay(&value));
    return value;
}

template <typename D> int32_t consume_Windows_Globalization_ICalendar<D>::NumberOfPeriodsInThisDay() const
{
    int32_t value{};
    check_hresult(WINRT_SHIM(Windows::Globalization::ICalendar)->get_NumberOfPeriodsInThisDay(&value));
    return value;
}

template <typename D> int32_t consume_Windows_Globalization_ICalendar<D>::Period() const
{
    int32_t value{};
    check_hresult(WINRT_SHIM(Windows::Globalization::ICalendar)->get_Period(&value));
    return value;
}

template <typename D> void consume_Windows_Globalization_ICalendar<D>::Period(int32_t value) const
{
    check_hresult(WINRT_SHIM(Windows::Globalization::ICalendar)->put_Period(value));
}

template <typename D> void consume_Windows_Globalization_ICalendar<D>::AddPeriods(int32_t periods) const
{
    check_hresult(WINRT_SHIM(Windows::Globalization::ICalendar)->AddPeriods(periods));
}

template <typename D> hstring consume_Windows_Globalization_ICalendar<D>::PeriodAsString() const
{
    hstring result{};
    check_hresult(WINRT_SHIM(Windows::Globalization::ICalendar)->PeriodAsFullString(put_abi(result)));
    return result;
}

template <typename D> hstring consume_Windows_Globalization_ICalendar<D>::PeriodAsString(int32_t idealLength) const
{
    hstring result{};
    check_hresult(WINRT_SHIM(Windows::Globalization::ICalendar)->PeriodAsString(idealLength, put_abi(result)));
    return result;
}

template <typename D> int32_t consume_Windows_Globalization_ICalendar<D>::FirstHourInThisPeriod() const
{
    int32_t value{};
    check_hresult(WINRT_SHIM(Windows::Globalization::ICalendar)->get_FirstHourInThisPeriod(&value));
    return value;
}

template <typename D> int32_t consume_Windows_Globalization_ICalendar<D>::LastHourInThisPeriod() const
{
    int32_t value{};
    check_hresult(WINRT_SHIM(Windows::Globalization::ICalendar)->get_LastHourInThisPeriod(&value));
    return value;
}

template <typename D> int32_t consume_Windows_Globalization_ICalendar<D>::NumberOfHoursInThisPeriod() const
{
    int32_t value{};
    check_hresult(WINRT_SHIM(Windows::Globalization::ICalendar)->get_NumberOfHoursInThisPeriod(&value));
    return value;
}

template <typename D> int32_t consume_Windows_Globalization_ICalendar<D>::Hour() const
{
    int32_t value{};
    check_hresult(WINRT_SHIM(Windows::Globalization::ICalendar)->get_Hour(&value));
    return value;
}

template <typename D> void consume_Windows_Globalization_ICalendar<D>::Hour(int32_t value) const
{
    check_hresult(WINRT_SHIM(Windows::Globalization::ICalendar)->put_Hour(value));
}

template <typename D> void consume_Windows_Globalization_ICalendar<D>::AddHours(int32_t hours) const
{
    check_hresult(WINRT_SHIM(Windows::Globalization::ICalendar)->AddHours(hours));
}

template <typename D> hstring consume_Windows_Globalization_ICalendar<D>::HourAsString() const
{
    hstring result{};
    check_hresult(WINRT_SHIM(Windows::Globalization::ICalendar)->HourAsString(put_abi(result)));
    return result;
}

template <typename D> hstring consume_Windows_Globalization_ICalendar<D>::HourAsPaddedString(int32_t minDigits) const
{
    hstring result{};
    check_hresult(WINRT_SHIM(Windows::Globalization::ICalendar)->HourAsPaddedString(minDigits, put_abi(result)));
    return result;
}

template <typename D> int32_t consume_Windows_Globalization_ICalendar<D>::Minute() const
{
    int32_t value{};
    check_hresult(WINRT_SHIM(Windows::Globalization::ICalendar)->get_Minute(&value));
    return value;
}

template <typename D> void consume_Windows_Globalization_ICalendar<D>::Minute(int32_t value) const
{
    check_hresult(WINRT_SHIM(Windows::Globalization::ICalendar)->put_Minute(value));
}

template <typename D> void consume_Windows_Globalization_ICalendar<D>::AddMinutes(int32_t minutes) const
{
    check_hresult(WINRT_SHIM(Windows::Globalization::ICalendar)->AddMinutes(minutes));
}

template <typename D> hstring consume_Windows_Globalization_ICalendar<D>::MinuteAsString() const
{
    hstring result{};
    check_hresult(WINRT_SHIM(Windows::Globalization::ICalendar)->MinuteAsString(put_abi(result)));
    return result;
}

template <typename D> hstring consume_Windows_Globalization_ICalendar<D>::MinuteAsPaddedString(int32_t minDigits) const
{
    hstring result{};
    check_hresult(WINRT_SHIM(Windows::Globalization::ICalendar)->MinuteAsPaddedString(minDigits, put_abi(result)));
    return result;
}

template <typename D> int32_t consume_Windows_Globalization_ICalendar<D>::Second() const
{
    int32_t value{};
    check_hresult(WINRT_SHIM(Windows::Globalization::ICalendar)->get_Second(&value));
    return value;
}

template <typename D> void consume_Windows_Globalization_ICalendar<D>::Second(int32_t value) const
{
    check_hresult(WINRT_SHIM(Windows::Globalization::ICalendar)->put_Second(value));
}

template <typename D> void consume_Windows_Globalization_ICalendar<D>::AddSeconds(int32_t seconds) const
{
    check_hresult(WINRT_SHIM(Windows::Globalization::ICalendar)->AddSeconds(seconds));
}

template <typename D> hstring consume_Windows_Globalization_ICalendar<D>::SecondAsString() const
{
    hstring result{};
    check_hresult(WINRT_SHIM(Windows::Globalization::ICalendar)->SecondAsString(put_abi(result)));
    return result;
}

template <typename D> hstring consume_Windows_Globalization_ICalendar<D>::SecondAsPaddedString(int32_t minDigits) const
{
    hstring result{};
    check_hresult(WINRT_SHIM(Windows::Globalization::ICalendar)->SecondAsPaddedString(minDigits, put_abi(result)));
    return result;
}

template <typename D> int32_t consume_Windows_Globalization_ICalendar<D>::Nanosecond() const
{
    int32_t value{};
    check_hresult(WINRT_SHIM(Windows::Globalization::ICalendar)->get_Nanosecond(&value));
    return value;
}

template <typename D> void consume_Windows_Globalization_ICalendar<D>::Nanosecond(int32_t value) const
{
    check_hresult(WINRT_SHIM(Windows::Globalization::ICalendar)->put_Nanosecond(value));
}

template <typename D> void consume_Windows_Globalization_ICalendar<D>::AddNanoseconds(int32_t nanoseconds) const
{
    check_hresult(WINRT_SHIM(Windows::Globalization::ICalendar)->AddNanoseconds(nanoseconds));
}

template <typename D> hstring consume_Windows_Globalization_ICalendar<D>::NanosecondAsString() const
{
    hstring result{};
    check_hresult(WINRT_SHIM(Windows::Globalization::ICalendar)->NanosecondAsString(put_abi(result)));
    return result;
}

template <typename D> hstring consume_Windows_Globalization_ICalendar<D>::NanosecondAsPaddedString(int32_t minDigits) const
{
    hstring result{};
    check_hresult(WINRT_SHIM(Windows::Globalization::ICalendar)->NanosecondAsPaddedString(minDigits, put_abi(result)));
    return result;
}

template <typename D> int32_t consume_Windows_Globalization_ICalendar<D>::Compare(Windows::Globalization::Calendar const& other) const
{
    int32_t result{};
    check_hresult(WINRT_SHIM(Windows::Globalization::ICalendar)->Compare(get_abi(other), &result));
    return result;
}

template <typename D> int32_t consume_Windows_Globalization_ICalendar<D>::CompareDateTime(Windows::Foundation::DateTime const& other) const
{
    int32_t result{};
    check_hresult(WINRT_SHIM(Windows::Globalization::ICalendar)->CompareDateTime(get_abi(other), &result));
    return result;
}

template <typename D> void consume_Windows_Globalization_ICalendar<D>::CopyTo(Windows::Globalization::Calendar const& other) const
{
    check_hresult(WINRT_SHIM(Windows::Globalization::ICalendar)->CopyTo(get_abi(other)));
}

template <typename D> int32_t consume_Windows_Globalization_ICalendar<D>::FirstMinuteInThisHour() const
{
    int32_t value{};
    check_hresult(WINRT_SHIM(Windows::Globalization::ICalendar)->get_FirstMinuteInThisHour(&value));
    return value;
}

template <typename D> int32_t consume_Windows_Globalization_ICalendar<D>::LastMinuteInThisHour() const
{
    int32_t value{};
    check_hresult(WINRT_SHIM(Windows::Globalization::ICalendar)->get_LastMinuteInThisHour(&value));
    return value;
}

template <typename D> int32_t consume_Windows_Globalization_ICalendar<D>::NumberOfMinutesInThisHour() const
{
    int32_t value{};
    check_hresult(WINRT_SHIM(Windows::Globalization::ICalendar)->get_NumberOfMinutesInThisHour(&value));
    return value;
}

template <typename D> int32_t consume_Windows_Globalization_ICalendar<D>::FirstSecondInThisMinute() const
{
    int32_t value{};
    check_hresult(WINRT_SHIM(Windows::Globalization::ICalendar)->get_FirstSecondInThisMinute(&value));
    return value;
}

template <typename D> int32_t consume_Windows_Globalization_ICalendar<D>::LastSecondInThisMinute() const
{
    int32_t value{};
    check_hresult(WINRT_SHIM(Windows::Globalization::ICalendar)->get_LastSecondInThisMinute(&value));
    return value;
}

template <typename D> int32_t consume_Windows_Globalization_ICalendar<D>::NumberOfSecondsInThisMinute() const
{
    int32_t value{};
    check_hresult(WINRT_SHIM(Windows::Globalization::ICalendar)->get_NumberOfSecondsInThisMinute(&value));
    return value;
}

template <typename D> hstring consume_Windows_Globalization_ICalendar<D>::ResolvedLanguage() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Globalization::ICalendar)->get_ResolvedLanguage(put_abi(value)));
    return value;
}

template <typename D> bool consume_Windows_Globalization_ICalendar<D>::IsDaylightSavingTime() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::Globalization::ICalendar)->get_IsDaylightSavingTime(&value));
    return value;
}

template <typename D> Windows::Globalization::Calendar consume_Windows_Globalization_ICalendarFactory<D>::CreateCalendarDefaultCalendarAndClock(param::iterable<hstring> const& languages) const
{
    Windows::Globalization::Calendar result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Globalization::ICalendarFactory)->CreateCalendarDefaultCalendarAndClock(get_abi(languages), put_abi(result)));
    return result;
}

template <typename D> Windows::Globalization::Calendar consume_Windows_Globalization_ICalendarFactory<D>::CreateCalendar(param::iterable<hstring> const& languages, param::hstring const& calendar, param::hstring const& clock) const
{
    Windows::Globalization::Calendar result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Globalization::ICalendarFactory)->CreateCalendar(get_abi(languages), get_abi(calendar), get_abi(clock), put_abi(result)));
    return result;
}

template <typename D> Windows::Globalization::Calendar consume_Windows_Globalization_ICalendarFactory2<D>::CreateCalendarWithTimeZone(param::iterable<hstring> const& languages, param::hstring const& calendar, param::hstring const& clock, param::hstring const& timeZoneId) const
{
    Windows::Globalization::Calendar result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Globalization::ICalendarFactory2)->CreateCalendarWithTimeZone(get_abi(languages), get_abi(calendar), get_abi(clock), get_abi(timeZoneId), put_abi(result)));
    return result;
}

template <typename D> hstring consume_Windows_Globalization_ICalendarIdentifiersStatics<D>::Gregorian() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Globalization::ICalendarIdentifiersStatics)->get_Gregorian(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_Globalization_ICalendarIdentifiersStatics<D>::Hebrew() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Globalization::ICalendarIdentifiersStatics)->get_Hebrew(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_Globalization_ICalendarIdentifiersStatics<D>::Hijri() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Globalization::ICalendarIdentifiersStatics)->get_Hijri(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_Globalization_ICalendarIdentifiersStatics<D>::Japanese() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Globalization::ICalendarIdentifiersStatics)->get_Japanese(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_Globalization_ICalendarIdentifiersStatics<D>::Julian() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Globalization::ICalendarIdentifiersStatics)->get_Julian(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_Globalization_ICalendarIdentifiersStatics<D>::Korean() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Globalization::ICalendarIdentifiersStatics)->get_Korean(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_Globalization_ICalendarIdentifiersStatics<D>::Taiwan() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Globalization::ICalendarIdentifiersStatics)->get_Taiwan(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_Globalization_ICalendarIdentifiersStatics<D>::Thai() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Globalization::ICalendarIdentifiersStatics)->get_Thai(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_Globalization_ICalendarIdentifiersStatics<D>::UmAlQura() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Globalization::ICalendarIdentifiersStatics)->get_UmAlQura(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_Globalization_ICalendarIdentifiersStatics2<D>::Persian() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Globalization::ICalendarIdentifiersStatics2)->get_Persian(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_Globalization_ICalendarIdentifiersStatics3<D>::ChineseLunar() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Globalization::ICalendarIdentifiersStatics3)->get_ChineseLunar(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_Globalization_ICalendarIdentifiersStatics3<D>::JapaneseLunar() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Globalization::ICalendarIdentifiersStatics3)->get_JapaneseLunar(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_Globalization_ICalendarIdentifiersStatics3<D>::KoreanLunar() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Globalization::ICalendarIdentifiersStatics3)->get_KoreanLunar(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_Globalization_ICalendarIdentifiersStatics3<D>::TaiwanLunar() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Globalization::ICalendarIdentifiersStatics3)->get_TaiwanLunar(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_Globalization_ICalendarIdentifiersStatics3<D>::VietnameseLunar() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Globalization::ICalendarIdentifiersStatics3)->get_VietnameseLunar(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_Globalization_IClockIdentifiersStatics<D>::TwelveHour() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Globalization::IClockIdentifiersStatics)->get_TwelveHour(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_Globalization_IClockIdentifiersStatics<D>::TwentyFourHour() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Globalization::IClockIdentifiersStatics)->get_TwentyFourHour(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_Globalization_ICurrencyAmount<D>::Amount() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Globalization::ICurrencyAmount)->get_Amount(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_Globalization_ICurrencyAmount<D>::Currency() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Globalization::ICurrencyAmount)->get_Currency(put_abi(value)));
    return value;
}

template <typename D> Windows::Globalization::CurrencyAmount consume_Windows_Globalization_ICurrencyAmountFactory<D>::Create(param::hstring const& amount, param::hstring const& currency) const
{
    Windows::Globalization::CurrencyAmount result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Globalization::ICurrencyAmountFactory)->Create(get_abi(amount), get_abi(currency), put_abi(result)));
    return result;
}

template <typename D> hstring consume_Windows_Globalization_ICurrencyIdentifiersStatics<D>::AED() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Globalization::ICurrencyIdentifiersStatics)->get_AED(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_Globalization_ICurrencyIdentifiersStatics<D>::AFN() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Globalization::ICurrencyIdentifiersStatics)->get_AFN(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_Globalization_ICurrencyIdentifiersStatics<D>::ALL() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Globalization::ICurrencyIdentifiersStatics)->get_ALL(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_Globalization_ICurrencyIdentifiersStatics<D>::AMD() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Globalization::ICurrencyIdentifiersStatics)->get_AMD(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_Globalization_ICurrencyIdentifiersStatics<D>::ANG() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Globalization::ICurrencyIdentifiersStatics)->get_ANG(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_Globalization_ICurrencyIdentifiersStatics<D>::AOA() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Globalization::ICurrencyIdentifiersStatics)->get_AOA(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_Globalization_ICurrencyIdentifiersStatics<D>::ARS() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Globalization::ICurrencyIdentifiersStatics)->get_ARS(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_Globalization_ICurrencyIdentifiersStatics<D>::AUD() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Globalization::ICurrencyIdentifiersStatics)->get_AUD(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_Globalization_ICurrencyIdentifiersStatics<D>::AWG() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Globalization::ICurrencyIdentifiersStatics)->get_AWG(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_Globalization_ICurrencyIdentifiersStatics<D>::AZN() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Globalization::ICurrencyIdentifiersStatics)->get_AZN(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_Globalization_ICurrencyIdentifiersStatics<D>::BAM() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Globalization::ICurrencyIdentifiersStatics)->get_BAM(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_Globalization_ICurrencyIdentifiersStatics<D>::BBD() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Globalization::ICurrencyIdentifiersStatics)->get_BBD(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_Globalization_ICurrencyIdentifiersStatics<D>::BDT() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Globalization::ICurrencyIdentifiersStatics)->get_BDT(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_Globalization_ICurrencyIdentifiersStatics<D>::BGN() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Globalization::ICurrencyIdentifiersStatics)->get_BGN(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_Globalization_ICurrencyIdentifiersStatics<D>::BHD() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Globalization::ICurrencyIdentifiersStatics)->get_BHD(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_Globalization_ICurrencyIdentifiersStatics<D>::BIF() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Globalization::ICurrencyIdentifiersStatics)->get_BIF(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_Globalization_ICurrencyIdentifiersStatics<D>::BMD() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Globalization::ICurrencyIdentifiersStatics)->get_BMD(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_Globalization_ICurrencyIdentifiersStatics<D>::BND() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Globalization::ICurrencyIdentifiersStatics)->get_BND(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_Globalization_ICurrencyIdentifiersStatics<D>::BOB() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Globalization::ICurrencyIdentifiersStatics)->get_BOB(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_Globalization_ICurrencyIdentifiersStatics<D>::BRL() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Globalization::ICurrencyIdentifiersStatics)->get_BRL(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_Globalization_ICurrencyIdentifiersStatics<D>::BSD() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Globalization::ICurrencyIdentifiersStatics)->get_BSD(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_Globalization_ICurrencyIdentifiersStatics<D>::BTN() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Globalization::ICurrencyIdentifiersStatics)->get_BTN(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_Globalization_ICurrencyIdentifiersStatics<D>::BWP() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Globalization::ICurrencyIdentifiersStatics)->get_BWP(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_Globalization_ICurrencyIdentifiersStatics<D>::BYR() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Globalization::ICurrencyIdentifiersStatics)->get_BYR(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_Globalization_ICurrencyIdentifiersStatics<D>::BZD() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Globalization::ICurrencyIdentifiersStatics)->get_BZD(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_Globalization_ICurrencyIdentifiersStatics<D>::CAD() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Globalization::ICurrencyIdentifiersStatics)->get_CAD(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_Globalization_ICurrencyIdentifiersStatics<D>::CDF() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Globalization::ICurrencyIdentifiersStatics)->get_CDF(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_Globalization_ICurrencyIdentifiersStatics<D>::CHF() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Globalization::ICurrencyIdentifiersStatics)->get_CHF(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_Globalization_ICurrencyIdentifiersStatics<D>::CLP() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Globalization::ICurrencyIdentifiersStatics)->get_CLP(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_Globalization_ICurrencyIdentifiersStatics<D>::CNY() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Globalization::ICurrencyIdentifiersStatics)->get_CNY(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_Globalization_ICurrencyIdentifiersStatics<D>::COP() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Globalization::ICurrencyIdentifiersStatics)->get_COP(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_Globalization_ICurrencyIdentifiersStatics<D>::CRC() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Globalization::ICurrencyIdentifiersStatics)->get_CRC(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_Globalization_ICurrencyIdentifiersStatics<D>::CUP() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Globalization::ICurrencyIdentifiersStatics)->get_CUP(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_Globalization_ICurrencyIdentifiersStatics<D>::CVE() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Globalization::ICurrencyIdentifiersStatics)->get_CVE(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_Globalization_ICurrencyIdentifiersStatics<D>::CZK() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Globalization::ICurrencyIdentifiersStatics)->get_CZK(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_Globalization_ICurrencyIdentifiersStatics<D>::DJF() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Globalization::ICurrencyIdentifiersStatics)->get_DJF(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_Globalization_ICurrencyIdentifiersStatics<D>::DKK() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Globalization::ICurrencyIdentifiersStatics)->get_DKK(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_Globalization_ICurrencyIdentifiersStatics<D>::DOP() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Globalization::ICurrencyIdentifiersStatics)->get_DOP(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_Globalization_ICurrencyIdentifiersStatics<D>::DZD() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Globalization::ICurrencyIdentifiersStatics)->get_DZD(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_Globalization_ICurrencyIdentifiersStatics<D>::EGP() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Globalization::ICurrencyIdentifiersStatics)->get_EGP(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_Globalization_ICurrencyIdentifiersStatics<D>::ERN() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Globalization::ICurrencyIdentifiersStatics)->get_ERN(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_Globalization_ICurrencyIdentifiersStatics<D>::ETB() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Globalization::ICurrencyIdentifiersStatics)->get_ETB(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_Globalization_ICurrencyIdentifiersStatics<D>::EUR() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Globalization::ICurrencyIdentifiersStatics)->get_EUR(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_Globalization_ICurrencyIdentifiersStatics<D>::FJD() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Globalization::ICurrencyIdentifiersStatics)->get_FJD(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_Globalization_ICurrencyIdentifiersStatics<D>::FKP() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Globalization::ICurrencyIdentifiersStatics)->get_FKP(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_Globalization_ICurrencyIdentifiersStatics<D>::GBP() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Globalization::ICurrencyIdentifiersStatics)->get_GBP(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_Globalization_ICurrencyIdentifiersStatics<D>::GEL() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Globalization::ICurrencyIdentifiersStatics)->get_GEL(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_Globalization_ICurrencyIdentifiersStatics<D>::GHS() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Globalization::ICurrencyIdentifiersStatics)->get_GHS(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_Globalization_ICurrencyIdentifiersStatics<D>::GIP() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Globalization::ICurrencyIdentifiersStatics)->get_GIP(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_Globalization_ICurrencyIdentifiersStatics<D>::GMD() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Globalization::ICurrencyIdentifiersStatics)->get_GMD(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_Globalization_ICurrencyIdentifiersStatics<D>::GNF() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Globalization::ICurrencyIdentifiersStatics)->get_GNF(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_Globalization_ICurrencyIdentifiersStatics<D>::GTQ() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Globalization::ICurrencyIdentifiersStatics)->get_GTQ(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_Globalization_ICurrencyIdentifiersStatics<D>::GYD() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Globalization::ICurrencyIdentifiersStatics)->get_GYD(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_Globalization_ICurrencyIdentifiersStatics<D>::HKD() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Globalization::ICurrencyIdentifiersStatics)->get_HKD(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_Globalization_ICurrencyIdentifiersStatics<D>::HNL() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Globalization::ICurrencyIdentifiersStatics)->get_HNL(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_Globalization_ICurrencyIdentifiersStatics<D>::HRK() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Globalization::ICurrencyIdentifiersStatics)->get_HRK(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_Globalization_ICurrencyIdentifiersStatics<D>::HTG() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Globalization::ICurrencyIdentifiersStatics)->get_HTG(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_Globalization_ICurrencyIdentifiersStatics<D>::HUF() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Globalization::ICurrencyIdentifiersStatics)->get_HUF(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_Globalization_ICurrencyIdentifiersStatics<D>::IDR() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Globalization::ICurrencyIdentifiersStatics)->get_IDR(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_Globalization_ICurrencyIdentifiersStatics<D>::ILS() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Globalization::ICurrencyIdentifiersStatics)->get_ILS(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_Globalization_ICurrencyIdentifiersStatics<D>::INR() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Globalization::ICurrencyIdentifiersStatics)->get_INR(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_Globalization_ICurrencyIdentifiersStatics<D>::IQD() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Globalization::ICurrencyIdentifiersStatics)->get_IQD(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_Globalization_ICurrencyIdentifiersStatics<D>::IRR() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Globalization::ICurrencyIdentifiersStatics)->get_IRR(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_Globalization_ICurrencyIdentifiersStatics<D>::ISK() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Globalization::ICurrencyIdentifiersStatics)->get_ISK(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_Globalization_ICurrencyIdentifiersStatics<D>::JMD() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Globalization::ICurrencyIdentifiersStatics)->get_JMD(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_Globalization_ICurrencyIdentifiersStatics<D>::JOD() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Globalization::ICurrencyIdentifiersStatics)->get_JOD(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_Globalization_ICurrencyIdentifiersStatics<D>::JPY() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Globalization::ICurrencyIdentifiersStatics)->get_JPY(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_Globalization_ICurrencyIdentifiersStatics<D>::KES() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Globalization::ICurrencyIdentifiersStatics)->get_KES(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_Globalization_ICurrencyIdentifiersStatics<D>::KGS() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Globalization::ICurrencyIdentifiersStatics)->get_KGS(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_Globalization_ICurrencyIdentifiersStatics<D>::KHR() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Globalization::ICurrencyIdentifiersStatics)->get_KHR(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_Globalization_ICurrencyIdentifiersStatics<D>::KMF() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Globalization::ICurrencyIdentifiersStatics)->get_KMF(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_Globalization_ICurrencyIdentifiersStatics<D>::KPW() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Globalization::ICurrencyIdentifiersStatics)->get_KPW(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_Globalization_ICurrencyIdentifiersStatics<D>::KRW() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Globalization::ICurrencyIdentifiersStatics)->get_KRW(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_Globalization_ICurrencyIdentifiersStatics<D>::KWD() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Globalization::ICurrencyIdentifiersStatics)->get_KWD(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_Globalization_ICurrencyIdentifiersStatics<D>::KYD() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Globalization::ICurrencyIdentifiersStatics)->get_KYD(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_Globalization_ICurrencyIdentifiersStatics<D>::KZT() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Globalization::ICurrencyIdentifiersStatics)->get_KZT(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_Globalization_ICurrencyIdentifiersStatics<D>::LAK() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Globalization::ICurrencyIdentifiersStatics)->get_LAK(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_Globalization_ICurrencyIdentifiersStatics<D>::LBP() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Globalization::ICurrencyIdentifiersStatics)->get_LBP(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_Globalization_ICurrencyIdentifiersStatics<D>::LKR() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Globalization::ICurrencyIdentifiersStatics)->get_LKR(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_Globalization_ICurrencyIdentifiersStatics<D>::LRD() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Globalization::ICurrencyIdentifiersStatics)->get_LRD(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_Globalization_ICurrencyIdentifiersStatics<D>::LSL() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Globalization::ICurrencyIdentifiersStatics)->get_LSL(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_Globalization_ICurrencyIdentifiersStatics<D>::LTL() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Globalization::ICurrencyIdentifiersStatics)->get_LTL(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_Globalization_ICurrencyIdentifiersStatics<D>::LVL() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Globalization::ICurrencyIdentifiersStatics)->get_LVL(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_Globalization_ICurrencyIdentifiersStatics<D>::LYD() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Globalization::ICurrencyIdentifiersStatics)->get_LYD(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_Globalization_ICurrencyIdentifiersStatics<D>::MAD() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Globalization::ICurrencyIdentifiersStatics)->get_MAD(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_Globalization_ICurrencyIdentifiersStatics<D>::MDL() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Globalization::ICurrencyIdentifiersStatics)->get_MDL(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_Globalization_ICurrencyIdentifiersStatics<D>::MGA() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Globalization::ICurrencyIdentifiersStatics)->get_MGA(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_Globalization_ICurrencyIdentifiersStatics<D>::MKD() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Globalization::ICurrencyIdentifiersStatics)->get_MKD(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_Globalization_ICurrencyIdentifiersStatics<D>::MMK() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Globalization::ICurrencyIdentifiersStatics)->get_MMK(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_Globalization_ICurrencyIdentifiersStatics<D>::MNT() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Globalization::ICurrencyIdentifiersStatics)->get_MNT(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_Globalization_ICurrencyIdentifiersStatics<D>::MOP() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Globalization::ICurrencyIdentifiersStatics)->get_MOP(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_Globalization_ICurrencyIdentifiersStatics<D>::MRO() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Globalization::ICurrencyIdentifiersStatics)->get_MRO(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_Globalization_ICurrencyIdentifiersStatics<D>::MUR() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Globalization::ICurrencyIdentifiersStatics)->get_MUR(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_Globalization_ICurrencyIdentifiersStatics<D>::MVR() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Globalization::ICurrencyIdentifiersStatics)->get_MVR(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_Globalization_ICurrencyIdentifiersStatics<D>::MWK() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Globalization::ICurrencyIdentifiersStatics)->get_MWK(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_Globalization_ICurrencyIdentifiersStatics<D>::MXN() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Globalization::ICurrencyIdentifiersStatics)->get_MXN(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_Globalization_ICurrencyIdentifiersStatics<D>::MYR() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Globalization::ICurrencyIdentifiersStatics)->get_MYR(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_Globalization_ICurrencyIdentifiersStatics<D>::MZN() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Globalization::ICurrencyIdentifiersStatics)->get_MZN(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_Globalization_ICurrencyIdentifiersStatics<D>::NAD() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Globalization::ICurrencyIdentifiersStatics)->get_NAD(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_Globalization_ICurrencyIdentifiersStatics<D>::NGN() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Globalization::ICurrencyIdentifiersStatics)->get_NGN(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_Globalization_ICurrencyIdentifiersStatics<D>::NIO() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Globalization::ICurrencyIdentifiersStatics)->get_NIO(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_Globalization_ICurrencyIdentifiersStatics<D>::NOK() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Globalization::ICurrencyIdentifiersStatics)->get_NOK(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_Globalization_ICurrencyIdentifiersStatics<D>::NPR() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Globalization::ICurrencyIdentifiersStatics)->get_NPR(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_Globalization_ICurrencyIdentifiersStatics<D>::NZD() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Globalization::ICurrencyIdentifiersStatics)->get_NZD(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_Globalization_ICurrencyIdentifiersStatics<D>::OMR() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Globalization::ICurrencyIdentifiersStatics)->get_OMR(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_Globalization_ICurrencyIdentifiersStatics<D>::PAB() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Globalization::ICurrencyIdentifiersStatics)->get_PAB(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_Globalization_ICurrencyIdentifiersStatics<D>::PEN() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Globalization::ICurrencyIdentifiersStatics)->get_PEN(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_Globalization_ICurrencyIdentifiersStatics<D>::PGK() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Globalization::ICurrencyIdentifiersStatics)->get_PGK(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_Globalization_ICurrencyIdentifiersStatics<D>::PHP() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Globalization::ICurrencyIdentifiersStatics)->get_PHP(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_Globalization_ICurrencyIdentifiersStatics<D>::PKR() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Globalization::ICurrencyIdentifiersStatics)->get_PKR(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_Globalization_ICurrencyIdentifiersStatics<D>::PLN() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Globalization::ICurrencyIdentifiersStatics)->get_PLN(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_Globalization_ICurrencyIdentifiersStatics<D>::PYG() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Globalization::ICurrencyIdentifiersStatics)->get_PYG(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_Globalization_ICurrencyIdentifiersStatics<D>::QAR() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Globalization::ICurrencyIdentifiersStatics)->get_QAR(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_Globalization_ICurrencyIdentifiersStatics<D>::RON() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Globalization::ICurrencyIdentifiersStatics)->get_RON(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_Globalization_ICurrencyIdentifiersStatics<D>::RSD() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Globalization::ICurrencyIdentifiersStatics)->get_RSD(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_Globalization_ICurrencyIdentifiersStatics<D>::RUB() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Globalization::ICurrencyIdentifiersStatics)->get_RUB(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_Globalization_ICurrencyIdentifiersStatics<D>::RWF() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Globalization::ICurrencyIdentifiersStatics)->get_RWF(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_Globalization_ICurrencyIdentifiersStatics<D>::SAR() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Globalization::ICurrencyIdentifiersStatics)->get_SAR(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_Globalization_ICurrencyIdentifiersStatics<D>::SBD() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Globalization::ICurrencyIdentifiersStatics)->get_SBD(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_Globalization_ICurrencyIdentifiersStatics<D>::SCR() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Globalization::ICurrencyIdentifiersStatics)->get_SCR(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_Globalization_ICurrencyIdentifiersStatics<D>::SDG() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Globalization::ICurrencyIdentifiersStatics)->get_SDG(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_Globalization_ICurrencyIdentifiersStatics<D>::SEK() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Globalization::ICurrencyIdentifiersStatics)->get_SEK(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_Globalization_ICurrencyIdentifiersStatics<D>::SGD() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Globalization::ICurrencyIdentifiersStatics)->get_SGD(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_Globalization_ICurrencyIdentifiersStatics<D>::SHP() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Globalization::ICurrencyIdentifiersStatics)->get_SHP(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_Globalization_ICurrencyIdentifiersStatics<D>::SLL() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Globalization::ICurrencyIdentifiersStatics)->get_SLL(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_Globalization_ICurrencyIdentifiersStatics<D>::SOS() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Globalization::ICurrencyIdentifiersStatics)->get_SOS(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_Globalization_ICurrencyIdentifiersStatics<D>::SRD() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Globalization::ICurrencyIdentifiersStatics)->get_SRD(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_Globalization_ICurrencyIdentifiersStatics<D>::STD() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Globalization::ICurrencyIdentifiersStatics)->get_STD(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_Globalization_ICurrencyIdentifiersStatics<D>::SYP() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Globalization::ICurrencyIdentifiersStatics)->get_SYP(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_Globalization_ICurrencyIdentifiersStatics<D>::SZL() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Globalization::ICurrencyIdentifiersStatics)->get_SZL(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_Globalization_ICurrencyIdentifiersStatics<D>::THB() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Globalization::ICurrencyIdentifiersStatics)->get_THB(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_Globalization_ICurrencyIdentifiersStatics<D>::TJS() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Globalization::ICurrencyIdentifiersStatics)->get_TJS(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_Globalization_ICurrencyIdentifiersStatics<D>::TMT() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Globalization::ICurrencyIdentifiersStatics)->get_TMT(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_Globalization_ICurrencyIdentifiersStatics<D>::TND() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Globalization::ICurrencyIdentifiersStatics)->get_TND(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_Globalization_ICurrencyIdentifiersStatics<D>::TOP() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Globalization::ICurrencyIdentifiersStatics)->get_TOP(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_Globalization_ICurrencyIdentifiersStatics<D>::TRY() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Globalization::ICurrencyIdentifiersStatics)->get_TRY(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_Globalization_ICurrencyIdentifiersStatics<D>::TTD() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Globalization::ICurrencyIdentifiersStatics)->get_TTD(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_Globalization_ICurrencyIdentifiersStatics<D>::TWD() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Globalization::ICurrencyIdentifiersStatics)->get_TWD(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_Globalization_ICurrencyIdentifiersStatics<D>::TZS() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Globalization::ICurrencyIdentifiersStatics)->get_TZS(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_Globalization_ICurrencyIdentifiersStatics<D>::UAH() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Globalization::ICurrencyIdentifiersStatics)->get_UAH(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_Globalization_ICurrencyIdentifiersStatics<D>::UGX() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Globalization::ICurrencyIdentifiersStatics)->get_UGX(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_Globalization_ICurrencyIdentifiersStatics<D>::USD() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Globalization::ICurrencyIdentifiersStatics)->get_USD(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_Globalization_ICurrencyIdentifiersStatics<D>::UYU() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Globalization::ICurrencyIdentifiersStatics)->get_UYU(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_Globalization_ICurrencyIdentifiersStatics<D>::UZS() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Globalization::ICurrencyIdentifiersStatics)->get_UZS(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_Globalization_ICurrencyIdentifiersStatics<D>::VEF() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Globalization::ICurrencyIdentifiersStatics)->get_VEF(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_Globalization_ICurrencyIdentifiersStatics<D>::VND() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Globalization::ICurrencyIdentifiersStatics)->get_VND(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_Globalization_ICurrencyIdentifiersStatics<D>::VUV() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Globalization::ICurrencyIdentifiersStatics)->get_VUV(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_Globalization_ICurrencyIdentifiersStatics<D>::WST() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Globalization::ICurrencyIdentifiersStatics)->get_WST(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_Globalization_ICurrencyIdentifiersStatics<D>::XAF() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Globalization::ICurrencyIdentifiersStatics)->get_XAF(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_Globalization_ICurrencyIdentifiersStatics<D>::XCD() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Globalization::ICurrencyIdentifiersStatics)->get_XCD(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_Globalization_ICurrencyIdentifiersStatics<D>::XOF() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Globalization::ICurrencyIdentifiersStatics)->get_XOF(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_Globalization_ICurrencyIdentifiersStatics<D>::XPF() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Globalization::ICurrencyIdentifiersStatics)->get_XPF(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_Globalization_ICurrencyIdentifiersStatics<D>::XXX() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Globalization::ICurrencyIdentifiersStatics)->get_XXX(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_Globalization_ICurrencyIdentifiersStatics<D>::YER() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Globalization::ICurrencyIdentifiersStatics)->get_YER(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_Globalization_ICurrencyIdentifiersStatics<D>::ZAR() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Globalization::ICurrencyIdentifiersStatics)->get_ZAR(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_Globalization_ICurrencyIdentifiersStatics<D>::ZMW() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Globalization::ICurrencyIdentifiersStatics)->get_ZMW(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_Globalization_ICurrencyIdentifiersStatics<D>::ZWL() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Globalization::ICurrencyIdentifiersStatics)->get_ZWL(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_Globalization_ICurrencyIdentifiersStatics2<D>::BYN() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Globalization::ICurrencyIdentifiersStatics2)->get_BYN(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_Globalization_ICurrencyIdentifiersStatics3<D>::MRU() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Globalization::ICurrencyIdentifiersStatics3)->get_MRU(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_Globalization_ICurrencyIdentifiersStatics3<D>::SSP() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Globalization::ICurrencyIdentifiersStatics3)->get_SSP(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_Globalization_ICurrencyIdentifiersStatics3<D>::STN() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Globalization::ICurrencyIdentifiersStatics3)->get_STN(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_Globalization_ICurrencyIdentifiersStatics3<D>::VES() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Globalization::ICurrencyIdentifiersStatics3)->get_VES(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_Globalization_IGeographicRegion<D>::Code() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Globalization::IGeographicRegion)->get_Code(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_Globalization_IGeographicRegion<D>::CodeTwoLetter() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Globalization::IGeographicRegion)->get_CodeTwoLetter(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_Globalization_IGeographicRegion<D>::CodeThreeLetter() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Globalization::IGeographicRegion)->get_CodeThreeLetter(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_Globalization_IGeographicRegion<D>::CodeThreeDigit() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Globalization::IGeographicRegion)->get_CodeThreeDigit(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_Globalization_IGeographicRegion<D>::DisplayName() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Globalization::IGeographicRegion)->get_DisplayName(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_Globalization_IGeographicRegion<D>::NativeName() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Globalization::IGeographicRegion)->get_NativeName(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::Collections::IVectorView<hstring> consume_Windows_Globalization_IGeographicRegion<D>::CurrenciesInUse() const
{
    Windows::Foundation::Collections::IVectorView<hstring> value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Globalization::IGeographicRegion)->get_CurrenciesInUse(put_abi(value)));
    return value;
}

template <typename D> Windows::Globalization::GeographicRegion consume_Windows_Globalization_IGeographicRegionFactory<D>::CreateGeographicRegion(param::hstring const& geographicRegionCode) const
{
    Windows::Globalization::GeographicRegion result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Globalization::IGeographicRegionFactory)->CreateGeographicRegion(get_abi(geographicRegionCode), put_abi(result)));
    return result;
}

template <typename D> bool consume_Windows_Globalization_IGeographicRegionStatics<D>::IsSupported(param::hstring const& geographicRegionCode) const
{
    bool result{};
    check_hresult(WINRT_SHIM(Windows::Globalization::IGeographicRegionStatics)->IsSupported(get_abi(geographicRegionCode), &result));
    return result;
}

template <typename D> hstring consume_Windows_Globalization_IJapanesePhoneme<D>::DisplayText() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Globalization::IJapanesePhoneme)->get_DisplayText(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_Globalization_IJapanesePhoneme<D>::YomiText() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Globalization::IJapanesePhoneme)->get_YomiText(put_abi(value)));
    return value;
}

template <typename D> bool consume_Windows_Globalization_IJapanesePhoneme<D>::IsPhraseStart() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::Globalization::IJapanesePhoneme)->get_IsPhraseStart(&value));
    return value;
}

template <typename D> Windows::Foundation::Collections::IVectorView<Windows::Globalization::JapanesePhoneme> consume_Windows_Globalization_IJapanesePhoneticAnalyzerStatics<D>::GetWords(param::hstring const& input) const
{
    Windows::Foundation::Collections::IVectorView<Windows::Globalization::JapanesePhoneme> result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Globalization::IJapanesePhoneticAnalyzerStatics)->GetWords(get_abi(input), put_abi(result)));
    return result;
}

template <typename D> Windows::Foundation::Collections::IVectorView<Windows::Globalization::JapanesePhoneme> consume_Windows_Globalization_IJapanesePhoneticAnalyzerStatics<D>::GetWords(param::hstring const& input, bool monoRuby) const
{
    Windows::Foundation::Collections::IVectorView<Windows::Globalization::JapanesePhoneme> result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Globalization::IJapanesePhoneticAnalyzerStatics)->GetWordsWithMonoRubyOption(get_abi(input), monoRuby, put_abi(result)));
    return result;
}

template <typename D> hstring consume_Windows_Globalization_ILanguage<D>::LanguageTag() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Globalization::ILanguage)->get_LanguageTag(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_Globalization_ILanguage<D>::DisplayName() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Globalization::ILanguage)->get_DisplayName(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_Globalization_ILanguage<D>::NativeName() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Globalization::ILanguage)->get_NativeName(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_Globalization_ILanguage<D>::Script() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Globalization::ILanguage)->get_Script(put_abi(value)));
    return value;
}

template <typename D> Windows::Globalization::LanguageLayoutDirection consume_Windows_Globalization_ILanguage2<D>::LayoutDirection() const
{
    Windows::Globalization::LanguageLayoutDirection value{};
    check_hresult(WINRT_SHIM(Windows::Globalization::ILanguage2)->get_LayoutDirection(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::Collections::IVectorView<hstring> consume_Windows_Globalization_ILanguageExtensionSubtags<D>::GetExtensionSubtags(param::hstring const& singleton) const
{
    Windows::Foundation::Collections::IVectorView<hstring> value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Globalization::ILanguageExtensionSubtags)->GetExtensionSubtags(get_abi(singleton), put_abi(value)));
    return value;
}

template <typename D> Windows::Globalization::Language consume_Windows_Globalization_ILanguageFactory<D>::CreateLanguage(param::hstring const& languageTag) const
{
    Windows::Globalization::Language result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Globalization::ILanguageFactory)->CreateLanguage(get_abi(languageTag), put_abi(result)));
    return result;
}

template <typename D> bool consume_Windows_Globalization_ILanguageStatics<D>::IsWellFormed(param::hstring const& languageTag) const
{
    bool result{};
    check_hresult(WINRT_SHIM(Windows::Globalization::ILanguageStatics)->IsWellFormed(get_abi(languageTag), &result));
    return result;
}

template <typename D> hstring consume_Windows_Globalization_ILanguageStatics<D>::CurrentInputMethodLanguageTag() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Globalization::ILanguageStatics)->get_CurrentInputMethodLanguageTag(put_abi(value)));
    return value;
}

template <typename D> bool consume_Windows_Globalization_ILanguageStatics2<D>::TrySetInputMethodLanguageTag(param::hstring const& languageTag) const
{
    bool result{};
    check_hresult(WINRT_SHIM(Windows::Globalization::ILanguageStatics2)->TrySetInputMethodLanguageTag(get_abi(languageTag), &result));
    return result;
}

template <typename D> hstring consume_Windows_Globalization_INumeralSystemIdentifiersStatics<D>::Arab() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Globalization::INumeralSystemIdentifiersStatics)->get_Arab(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_Globalization_INumeralSystemIdentifiersStatics<D>::ArabExt() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Globalization::INumeralSystemIdentifiersStatics)->get_ArabExt(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_Globalization_INumeralSystemIdentifiersStatics<D>::Bali() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Globalization::INumeralSystemIdentifiersStatics)->get_Bali(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_Globalization_INumeralSystemIdentifiersStatics<D>::Beng() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Globalization::INumeralSystemIdentifiersStatics)->get_Beng(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_Globalization_INumeralSystemIdentifiersStatics<D>::Cham() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Globalization::INumeralSystemIdentifiersStatics)->get_Cham(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_Globalization_INumeralSystemIdentifiersStatics<D>::Deva() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Globalization::INumeralSystemIdentifiersStatics)->get_Deva(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_Globalization_INumeralSystemIdentifiersStatics<D>::FullWide() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Globalization::INumeralSystemIdentifiersStatics)->get_FullWide(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_Globalization_INumeralSystemIdentifiersStatics<D>::Gujr() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Globalization::INumeralSystemIdentifiersStatics)->get_Gujr(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_Globalization_INumeralSystemIdentifiersStatics<D>::Guru() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Globalization::INumeralSystemIdentifiersStatics)->get_Guru(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_Globalization_INumeralSystemIdentifiersStatics<D>::HaniDec() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Globalization::INumeralSystemIdentifiersStatics)->get_HaniDec(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_Globalization_INumeralSystemIdentifiersStatics<D>::Java() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Globalization::INumeralSystemIdentifiersStatics)->get_Java(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_Globalization_INumeralSystemIdentifiersStatics<D>::Kali() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Globalization::INumeralSystemIdentifiersStatics)->get_Kali(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_Globalization_INumeralSystemIdentifiersStatics<D>::Khmr() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Globalization::INumeralSystemIdentifiersStatics)->get_Khmr(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_Globalization_INumeralSystemIdentifiersStatics<D>::Knda() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Globalization::INumeralSystemIdentifiersStatics)->get_Knda(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_Globalization_INumeralSystemIdentifiersStatics<D>::Lana() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Globalization::INumeralSystemIdentifiersStatics)->get_Lana(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_Globalization_INumeralSystemIdentifiersStatics<D>::LanaTham() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Globalization::INumeralSystemIdentifiersStatics)->get_LanaTham(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_Globalization_INumeralSystemIdentifiersStatics<D>::Laoo() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Globalization::INumeralSystemIdentifiersStatics)->get_Laoo(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_Globalization_INumeralSystemIdentifiersStatics<D>::Latn() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Globalization::INumeralSystemIdentifiersStatics)->get_Latn(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_Globalization_INumeralSystemIdentifiersStatics<D>::Lepc() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Globalization::INumeralSystemIdentifiersStatics)->get_Lepc(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_Globalization_INumeralSystemIdentifiersStatics<D>::Limb() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Globalization::INumeralSystemIdentifiersStatics)->get_Limb(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_Globalization_INumeralSystemIdentifiersStatics<D>::Mlym() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Globalization::INumeralSystemIdentifiersStatics)->get_Mlym(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_Globalization_INumeralSystemIdentifiersStatics<D>::Mong() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Globalization::INumeralSystemIdentifiersStatics)->get_Mong(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_Globalization_INumeralSystemIdentifiersStatics<D>::Mtei() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Globalization::INumeralSystemIdentifiersStatics)->get_Mtei(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_Globalization_INumeralSystemIdentifiersStatics<D>::Mymr() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Globalization::INumeralSystemIdentifiersStatics)->get_Mymr(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_Globalization_INumeralSystemIdentifiersStatics<D>::MymrShan() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Globalization::INumeralSystemIdentifiersStatics)->get_MymrShan(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_Globalization_INumeralSystemIdentifiersStatics<D>::Nkoo() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Globalization::INumeralSystemIdentifiersStatics)->get_Nkoo(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_Globalization_INumeralSystemIdentifiersStatics<D>::Olck() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Globalization::INumeralSystemIdentifiersStatics)->get_Olck(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_Globalization_INumeralSystemIdentifiersStatics<D>::Orya() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Globalization::INumeralSystemIdentifiersStatics)->get_Orya(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_Globalization_INumeralSystemIdentifiersStatics<D>::Saur() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Globalization::INumeralSystemIdentifiersStatics)->get_Saur(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_Globalization_INumeralSystemIdentifiersStatics<D>::Sund() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Globalization::INumeralSystemIdentifiersStatics)->get_Sund(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_Globalization_INumeralSystemIdentifiersStatics<D>::Talu() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Globalization::INumeralSystemIdentifiersStatics)->get_Talu(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_Globalization_INumeralSystemIdentifiersStatics<D>::TamlDec() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Globalization::INumeralSystemIdentifiersStatics)->get_TamlDec(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_Globalization_INumeralSystemIdentifiersStatics<D>::Telu() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Globalization::INumeralSystemIdentifiersStatics)->get_Telu(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_Globalization_INumeralSystemIdentifiersStatics<D>::Thai() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Globalization::INumeralSystemIdentifiersStatics)->get_Thai(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_Globalization_INumeralSystemIdentifiersStatics<D>::Tibt() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Globalization::INumeralSystemIdentifiersStatics)->get_Tibt(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_Globalization_INumeralSystemIdentifiersStatics<D>::Vaii() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Globalization::INumeralSystemIdentifiersStatics)->get_Vaii(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_Globalization_INumeralSystemIdentifiersStatics2<D>::Brah() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Globalization::INumeralSystemIdentifiersStatics2)->get_Brah(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_Globalization_INumeralSystemIdentifiersStatics2<D>::Osma() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Globalization::INumeralSystemIdentifiersStatics2)->get_Osma(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_Globalization_INumeralSystemIdentifiersStatics2<D>::MathBold() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Globalization::INumeralSystemIdentifiersStatics2)->get_MathBold(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_Globalization_INumeralSystemIdentifiersStatics2<D>::MathDbl() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Globalization::INumeralSystemIdentifiersStatics2)->get_MathDbl(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_Globalization_INumeralSystemIdentifiersStatics2<D>::MathSans() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Globalization::INumeralSystemIdentifiersStatics2)->get_MathSans(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_Globalization_INumeralSystemIdentifiersStatics2<D>::MathSanb() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Globalization::INumeralSystemIdentifiersStatics2)->get_MathSanb(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_Globalization_INumeralSystemIdentifiersStatics2<D>::MathMono() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Globalization::INumeralSystemIdentifiersStatics2)->get_MathMono(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_Globalization_INumeralSystemIdentifiersStatics2<D>::ZmthBold() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Globalization::INumeralSystemIdentifiersStatics2)->get_ZmthBold(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_Globalization_INumeralSystemIdentifiersStatics2<D>::ZmthDbl() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Globalization::INumeralSystemIdentifiersStatics2)->get_ZmthDbl(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_Globalization_INumeralSystemIdentifiersStatics2<D>::ZmthSans() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Globalization::INumeralSystemIdentifiersStatics2)->get_ZmthSans(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_Globalization_INumeralSystemIdentifiersStatics2<D>::ZmthSanb() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Globalization::INumeralSystemIdentifiersStatics2)->get_ZmthSanb(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_Globalization_INumeralSystemIdentifiersStatics2<D>::ZmthMono() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Globalization::INumeralSystemIdentifiersStatics2)->get_ZmthMono(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_Globalization_ITimeZoneOnCalendar<D>::GetTimeZone() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Globalization::ITimeZoneOnCalendar)->GetTimeZone(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_Globalization_ITimeZoneOnCalendar<D>::ChangeTimeZone(param::hstring const& timeZoneId) const
{
    check_hresult(WINRT_SHIM(Windows::Globalization::ITimeZoneOnCalendar)->ChangeTimeZone(get_abi(timeZoneId)));
}

template <typename D> hstring consume_Windows_Globalization_ITimeZoneOnCalendar<D>::TimeZoneAsString() const
{
    hstring result{};
    check_hresult(WINRT_SHIM(Windows::Globalization::ITimeZoneOnCalendar)->TimeZoneAsFullString(put_abi(result)));
    return result;
}

template <typename D> hstring consume_Windows_Globalization_ITimeZoneOnCalendar<D>::TimeZoneAsString(int32_t idealLength) const
{
    hstring result{};
    check_hresult(WINRT_SHIM(Windows::Globalization::ITimeZoneOnCalendar)->TimeZoneAsString(idealLength, put_abi(result)));
    return result;
}

template <typename D>
struct produce<D, Windows::Globalization::IApplicationLanguagesStatics> : produce_base<D, Windows::Globalization::IApplicationLanguagesStatics>
{
    int32_t WINRT_CALL get_PrimaryLanguageOverride(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(PrimaryLanguageOverride, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().PrimaryLanguageOverride());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_PrimaryLanguageOverride(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(PrimaryLanguageOverride, WINRT_WRAP(void), hstring const&);
            this->shim().PrimaryLanguageOverride(*reinterpret_cast<hstring const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

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

    int32_t WINRT_CALL get_ManifestLanguages(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ManifestLanguages, WINRT_WRAP(Windows::Foundation::Collections::IVectorView<hstring>));
            *value = detach_from<Windows::Foundation::Collections::IVectorView<hstring>>(this->shim().ManifestLanguages());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Globalization::IApplicationLanguagesStatics2> : produce_base<D, Windows::Globalization::IApplicationLanguagesStatics2>
{
    int32_t WINRT_CALL GetLanguagesForUser(void* user, void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetLanguagesForUser, WINRT_WRAP(Windows::Foundation::Collections::IVectorView<hstring>), Windows::System::User const&);
            *value = detach_from<Windows::Foundation::Collections::IVectorView<hstring>>(this->shim().GetLanguagesForUser(*reinterpret_cast<Windows::System::User const*>(&user)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Globalization::ICalendar> : produce_base<D, Windows::Globalization::ICalendar>
{
    int32_t WINRT_CALL Clone(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Clone, WINRT_WRAP(Windows::Globalization::Calendar));
            *value = detach_from<Windows::Globalization::Calendar>(this->shim().Clone());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL SetToMin() noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SetToMin, WINRT_WRAP(void));
            this->shim().SetToMin();
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL SetToMax() noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SetToMax, WINRT_WRAP(void));
            this->shim().SetToMax();
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

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

    int32_t WINRT_CALL GetCalendarSystem(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetCalendarSystem, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().GetCalendarSystem());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL ChangeCalendarSystem(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ChangeCalendarSystem, WINRT_WRAP(void), hstring const&);
            this->shim().ChangeCalendarSystem(*reinterpret_cast<hstring const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL GetClock(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetClock, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().GetClock());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL ChangeClock(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ChangeClock, WINRT_WRAP(void), hstring const&);
            this->shim().ChangeClock(*reinterpret_cast<hstring const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL GetDateTime(Windows::Foundation::DateTime* result) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetDateTime, WINRT_WRAP(Windows::Foundation::DateTime));
            *result = detach_from<Windows::Foundation::DateTime>(this->shim().GetDateTime());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL SetDateTime(Windows::Foundation::DateTime value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SetDateTime, WINRT_WRAP(void), Windows::Foundation::DateTime const&);
            this->shim().SetDateTime(*reinterpret_cast<Windows::Foundation::DateTime const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL SetToNow() noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SetToNow, WINRT_WRAP(void));
            this->shim().SetToNow();
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_FirstEra(int32_t* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(FirstEra, WINRT_WRAP(int32_t));
            *value = detach_from<int32_t>(this->shim().FirstEra());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_LastEra(int32_t* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(LastEra, WINRT_WRAP(int32_t));
            *value = detach_from<int32_t>(this->shim().LastEra());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_NumberOfEras(int32_t* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(NumberOfEras, WINRT_WRAP(int32_t));
            *value = detach_from<int32_t>(this->shim().NumberOfEras());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Era(int32_t* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Era, WINRT_WRAP(int32_t));
            *value = detach_from<int32_t>(this->shim().Era());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_Era(int32_t value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Era, WINRT_WRAP(void), int32_t);
            this->shim().Era(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL AddEras(int32_t eras) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(AddEras, WINRT_WRAP(void), int32_t);
            this->shim().AddEras(eras);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL EraAsFullString(void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(EraAsString, WINRT_WRAP(hstring));
            *result = detach_from<hstring>(this->shim().EraAsString());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL EraAsString(int32_t idealLength, void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(EraAsString, WINRT_WRAP(hstring), int32_t);
            *result = detach_from<hstring>(this->shim().EraAsString(idealLength));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_FirstYearInThisEra(int32_t* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(FirstYearInThisEra, WINRT_WRAP(int32_t));
            *value = detach_from<int32_t>(this->shim().FirstYearInThisEra());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_LastYearInThisEra(int32_t* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(LastYearInThisEra, WINRT_WRAP(int32_t));
            *value = detach_from<int32_t>(this->shim().LastYearInThisEra());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_NumberOfYearsInThisEra(int32_t* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(NumberOfYearsInThisEra, WINRT_WRAP(int32_t));
            *value = detach_from<int32_t>(this->shim().NumberOfYearsInThisEra());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Year(int32_t* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Year, WINRT_WRAP(int32_t));
            *value = detach_from<int32_t>(this->shim().Year());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_Year(int32_t value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Year, WINRT_WRAP(void), int32_t);
            this->shim().Year(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL AddYears(int32_t years) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(AddYears, WINRT_WRAP(void), int32_t);
            this->shim().AddYears(years);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL YearAsString(void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(YearAsString, WINRT_WRAP(hstring));
            *result = detach_from<hstring>(this->shim().YearAsString());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL YearAsTruncatedString(int32_t remainingDigits, void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(YearAsTruncatedString, WINRT_WRAP(hstring), int32_t);
            *result = detach_from<hstring>(this->shim().YearAsTruncatedString(remainingDigits));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL YearAsPaddedString(int32_t minDigits, void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(YearAsPaddedString, WINRT_WRAP(hstring), int32_t);
            *result = detach_from<hstring>(this->shim().YearAsPaddedString(minDigits));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_FirstMonthInThisYear(int32_t* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(FirstMonthInThisYear, WINRT_WRAP(int32_t));
            *value = detach_from<int32_t>(this->shim().FirstMonthInThisYear());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_LastMonthInThisYear(int32_t* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(LastMonthInThisYear, WINRT_WRAP(int32_t));
            *value = detach_from<int32_t>(this->shim().LastMonthInThisYear());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_NumberOfMonthsInThisYear(int32_t* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(NumberOfMonthsInThisYear, WINRT_WRAP(int32_t));
            *value = detach_from<int32_t>(this->shim().NumberOfMonthsInThisYear());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Month(int32_t* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Month, WINRT_WRAP(int32_t));
            *value = detach_from<int32_t>(this->shim().Month());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_Month(int32_t value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Month, WINRT_WRAP(void), int32_t);
            this->shim().Month(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL AddMonths(int32_t months) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(AddMonths, WINRT_WRAP(void), int32_t);
            this->shim().AddMonths(months);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL MonthAsFullString(void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(MonthAsString, WINRT_WRAP(hstring));
            *result = detach_from<hstring>(this->shim().MonthAsString());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL MonthAsString(int32_t idealLength, void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(MonthAsString, WINRT_WRAP(hstring), int32_t);
            *result = detach_from<hstring>(this->shim().MonthAsString(idealLength));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL MonthAsFullSoloString(void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(MonthAsSoloString, WINRT_WRAP(hstring));
            *result = detach_from<hstring>(this->shim().MonthAsSoloString());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL MonthAsSoloString(int32_t idealLength, void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(MonthAsSoloString, WINRT_WRAP(hstring), int32_t);
            *result = detach_from<hstring>(this->shim().MonthAsSoloString(idealLength));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL MonthAsNumericString(void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(MonthAsNumericString, WINRT_WRAP(hstring));
            *result = detach_from<hstring>(this->shim().MonthAsNumericString());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL MonthAsPaddedNumericString(int32_t minDigits, void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(MonthAsPaddedNumericString, WINRT_WRAP(hstring), int32_t);
            *result = detach_from<hstring>(this->shim().MonthAsPaddedNumericString(minDigits));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL AddWeeks(int32_t weeks) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(AddWeeks, WINRT_WRAP(void), int32_t);
            this->shim().AddWeeks(weeks);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_FirstDayInThisMonth(int32_t* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(FirstDayInThisMonth, WINRT_WRAP(int32_t));
            *value = detach_from<int32_t>(this->shim().FirstDayInThisMonth());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_LastDayInThisMonth(int32_t* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(LastDayInThisMonth, WINRT_WRAP(int32_t));
            *value = detach_from<int32_t>(this->shim().LastDayInThisMonth());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_NumberOfDaysInThisMonth(int32_t* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(NumberOfDaysInThisMonth, WINRT_WRAP(int32_t));
            *value = detach_from<int32_t>(this->shim().NumberOfDaysInThisMonth());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Day(int32_t* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Day, WINRT_WRAP(int32_t));
            *value = detach_from<int32_t>(this->shim().Day());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_Day(int32_t value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Day, WINRT_WRAP(void), int32_t);
            this->shim().Day(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL AddDays(int32_t days) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(AddDays, WINRT_WRAP(void), int32_t);
            this->shim().AddDays(days);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL DayAsString(void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(DayAsString, WINRT_WRAP(hstring));
            *result = detach_from<hstring>(this->shim().DayAsString());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL DayAsPaddedString(int32_t minDigits, void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(DayAsPaddedString, WINRT_WRAP(hstring), int32_t);
            *result = detach_from<hstring>(this->shim().DayAsPaddedString(minDigits));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_DayOfWeek(Windows::Globalization::DayOfWeek* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(DayOfWeek, WINRT_WRAP(Windows::Globalization::DayOfWeek));
            *value = detach_from<Windows::Globalization::DayOfWeek>(this->shim().DayOfWeek());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL DayOfWeekAsFullString(void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(DayOfWeekAsString, WINRT_WRAP(hstring));
            *result = detach_from<hstring>(this->shim().DayOfWeekAsString());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL DayOfWeekAsString(int32_t idealLength, void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(DayOfWeekAsString, WINRT_WRAP(hstring), int32_t);
            *result = detach_from<hstring>(this->shim().DayOfWeekAsString(idealLength));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL DayOfWeekAsFullSoloString(void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(DayOfWeekAsSoloString, WINRT_WRAP(hstring));
            *result = detach_from<hstring>(this->shim().DayOfWeekAsSoloString());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL DayOfWeekAsSoloString(int32_t idealLength, void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(DayOfWeekAsSoloString, WINRT_WRAP(hstring), int32_t);
            *result = detach_from<hstring>(this->shim().DayOfWeekAsSoloString(idealLength));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_FirstPeriodInThisDay(int32_t* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(FirstPeriodInThisDay, WINRT_WRAP(int32_t));
            *value = detach_from<int32_t>(this->shim().FirstPeriodInThisDay());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_LastPeriodInThisDay(int32_t* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(LastPeriodInThisDay, WINRT_WRAP(int32_t));
            *value = detach_from<int32_t>(this->shim().LastPeriodInThisDay());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_NumberOfPeriodsInThisDay(int32_t* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(NumberOfPeriodsInThisDay, WINRT_WRAP(int32_t));
            *value = detach_from<int32_t>(this->shim().NumberOfPeriodsInThisDay());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Period(int32_t* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Period, WINRT_WRAP(int32_t));
            *value = detach_from<int32_t>(this->shim().Period());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_Period(int32_t value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Period, WINRT_WRAP(void), int32_t);
            this->shim().Period(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL AddPeriods(int32_t periods) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(AddPeriods, WINRT_WRAP(void), int32_t);
            this->shim().AddPeriods(periods);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL PeriodAsFullString(void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(PeriodAsString, WINRT_WRAP(hstring));
            *result = detach_from<hstring>(this->shim().PeriodAsString());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL PeriodAsString(int32_t idealLength, void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(PeriodAsString, WINRT_WRAP(hstring), int32_t);
            *result = detach_from<hstring>(this->shim().PeriodAsString(idealLength));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_FirstHourInThisPeriod(int32_t* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(FirstHourInThisPeriod, WINRT_WRAP(int32_t));
            *value = detach_from<int32_t>(this->shim().FirstHourInThisPeriod());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_LastHourInThisPeriod(int32_t* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(LastHourInThisPeriod, WINRT_WRAP(int32_t));
            *value = detach_from<int32_t>(this->shim().LastHourInThisPeriod());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_NumberOfHoursInThisPeriod(int32_t* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(NumberOfHoursInThisPeriod, WINRT_WRAP(int32_t));
            *value = detach_from<int32_t>(this->shim().NumberOfHoursInThisPeriod());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Hour(int32_t* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Hour, WINRT_WRAP(int32_t));
            *value = detach_from<int32_t>(this->shim().Hour());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_Hour(int32_t value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Hour, WINRT_WRAP(void), int32_t);
            this->shim().Hour(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL AddHours(int32_t hours) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(AddHours, WINRT_WRAP(void), int32_t);
            this->shim().AddHours(hours);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL HourAsString(void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(HourAsString, WINRT_WRAP(hstring));
            *result = detach_from<hstring>(this->shim().HourAsString());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL HourAsPaddedString(int32_t minDigits, void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(HourAsPaddedString, WINRT_WRAP(hstring), int32_t);
            *result = detach_from<hstring>(this->shim().HourAsPaddedString(minDigits));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Minute(int32_t* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Minute, WINRT_WRAP(int32_t));
            *value = detach_from<int32_t>(this->shim().Minute());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_Minute(int32_t value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Minute, WINRT_WRAP(void), int32_t);
            this->shim().Minute(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL AddMinutes(int32_t minutes) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(AddMinutes, WINRT_WRAP(void), int32_t);
            this->shim().AddMinutes(minutes);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL MinuteAsString(void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(MinuteAsString, WINRT_WRAP(hstring));
            *result = detach_from<hstring>(this->shim().MinuteAsString());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL MinuteAsPaddedString(int32_t minDigits, void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(MinuteAsPaddedString, WINRT_WRAP(hstring), int32_t);
            *result = detach_from<hstring>(this->shim().MinuteAsPaddedString(minDigits));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Second(int32_t* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Second, WINRT_WRAP(int32_t));
            *value = detach_from<int32_t>(this->shim().Second());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_Second(int32_t value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Second, WINRT_WRAP(void), int32_t);
            this->shim().Second(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL AddSeconds(int32_t seconds) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(AddSeconds, WINRT_WRAP(void), int32_t);
            this->shim().AddSeconds(seconds);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL SecondAsString(void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SecondAsString, WINRT_WRAP(hstring));
            *result = detach_from<hstring>(this->shim().SecondAsString());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL SecondAsPaddedString(int32_t minDigits, void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SecondAsPaddedString, WINRT_WRAP(hstring), int32_t);
            *result = detach_from<hstring>(this->shim().SecondAsPaddedString(minDigits));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Nanosecond(int32_t* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Nanosecond, WINRT_WRAP(int32_t));
            *value = detach_from<int32_t>(this->shim().Nanosecond());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_Nanosecond(int32_t value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Nanosecond, WINRT_WRAP(void), int32_t);
            this->shim().Nanosecond(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL AddNanoseconds(int32_t nanoseconds) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(AddNanoseconds, WINRT_WRAP(void), int32_t);
            this->shim().AddNanoseconds(nanoseconds);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL NanosecondAsString(void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(NanosecondAsString, WINRT_WRAP(hstring));
            *result = detach_from<hstring>(this->shim().NanosecondAsString());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL NanosecondAsPaddedString(int32_t minDigits, void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(NanosecondAsPaddedString, WINRT_WRAP(hstring), int32_t);
            *result = detach_from<hstring>(this->shim().NanosecondAsPaddedString(minDigits));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL Compare(void* other, int32_t* result) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Compare, WINRT_WRAP(int32_t), Windows::Globalization::Calendar const&);
            *result = detach_from<int32_t>(this->shim().Compare(*reinterpret_cast<Windows::Globalization::Calendar const*>(&other)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL CompareDateTime(Windows::Foundation::DateTime other, int32_t* result) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CompareDateTime, WINRT_WRAP(int32_t), Windows::Foundation::DateTime const&);
            *result = detach_from<int32_t>(this->shim().CompareDateTime(*reinterpret_cast<Windows::Foundation::DateTime const*>(&other)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL CopyTo(void* other) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CopyTo, WINRT_WRAP(void), Windows::Globalization::Calendar const&);
            this->shim().CopyTo(*reinterpret_cast<Windows::Globalization::Calendar const*>(&other));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_FirstMinuteInThisHour(int32_t* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(FirstMinuteInThisHour, WINRT_WRAP(int32_t));
            *value = detach_from<int32_t>(this->shim().FirstMinuteInThisHour());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_LastMinuteInThisHour(int32_t* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(LastMinuteInThisHour, WINRT_WRAP(int32_t));
            *value = detach_from<int32_t>(this->shim().LastMinuteInThisHour());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_NumberOfMinutesInThisHour(int32_t* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(NumberOfMinutesInThisHour, WINRT_WRAP(int32_t));
            *value = detach_from<int32_t>(this->shim().NumberOfMinutesInThisHour());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_FirstSecondInThisMinute(int32_t* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(FirstSecondInThisMinute, WINRT_WRAP(int32_t));
            *value = detach_from<int32_t>(this->shim().FirstSecondInThisMinute());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_LastSecondInThisMinute(int32_t* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(LastSecondInThisMinute, WINRT_WRAP(int32_t));
            *value = detach_from<int32_t>(this->shim().LastSecondInThisMinute());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_NumberOfSecondsInThisMinute(int32_t* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(NumberOfSecondsInThisMinute, WINRT_WRAP(int32_t));
            *value = detach_from<int32_t>(this->shim().NumberOfSecondsInThisMinute());
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

    int32_t WINRT_CALL get_IsDaylightSavingTime(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IsDaylightSavingTime, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().IsDaylightSavingTime());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Globalization::ICalendarFactory> : produce_base<D, Windows::Globalization::ICalendarFactory>
{
    int32_t WINRT_CALL CreateCalendarDefaultCalendarAndClock(void* languages, void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CreateCalendarDefaultCalendarAndClock, WINRT_WRAP(Windows::Globalization::Calendar), Windows::Foundation::Collections::IIterable<hstring> const&);
            *result = detach_from<Windows::Globalization::Calendar>(this->shim().CreateCalendarDefaultCalendarAndClock(*reinterpret_cast<Windows::Foundation::Collections::IIterable<hstring> const*>(&languages)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL CreateCalendar(void* languages, void* calendar, void* clock, void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CreateCalendar, WINRT_WRAP(Windows::Globalization::Calendar), Windows::Foundation::Collections::IIterable<hstring> const&, hstring const&, hstring const&);
            *result = detach_from<Windows::Globalization::Calendar>(this->shim().CreateCalendar(*reinterpret_cast<Windows::Foundation::Collections::IIterable<hstring> const*>(&languages), *reinterpret_cast<hstring const*>(&calendar), *reinterpret_cast<hstring const*>(&clock)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Globalization::ICalendarFactory2> : produce_base<D, Windows::Globalization::ICalendarFactory2>
{
    int32_t WINRT_CALL CreateCalendarWithTimeZone(void* languages, void* calendar, void* clock, void* timeZoneId, void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CreateCalendarWithTimeZone, WINRT_WRAP(Windows::Globalization::Calendar), Windows::Foundation::Collections::IIterable<hstring> const&, hstring const&, hstring const&, hstring const&);
            *result = detach_from<Windows::Globalization::Calendar>(this->shim().CreateCalendarWithTimeZone(*reinterpret_cast<Windows::Foundation::Collections::IIterable<hstring> const*>(&languages), *reinterpret_cast<hstring const*>(&calendar), *reinterpret_cast<hstring const*>(&clock), *reinterpret_cast<hstring const*>(&timeZoneId)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Globalization::ICalendarIdentifiersStatics> : produce_base<D, Windows::Globalization::ICalendarIdentifiersStatics>
{
    int32_t WINRT_CALL get_Gregorian(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Gregorian, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().Gregorian());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Hebrew(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Hebrew, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().Hebrew());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Hijri(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Hijri, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().Hijri());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Japanese(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Japanese, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().Japanese());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Julian(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Julian, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().Julian());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Korean(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Korean, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().Korean());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Taiwan(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Taiwan, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().Taiwan());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Thai(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Thai, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().Thai());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_UmAlQura(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(UmAlQura, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().UmAlQura());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Globalization::ICalendarIdentifiersStatics2> : produce_base<D, Windows::Globalization::ICalendarIdentifiersStatics2>
{
    int32_t WINRT_CALL get_Persian(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Persian, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().Persian());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Globalization::ICalendarIdentifiersStatics3> : produce_base<D, Windows::Globalization::ICalendarIdentifiersStatics3>
{
    int32_t WINRT_CALL get_ChineseLunar(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ChineseLunar, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().ChineseLunar());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_JapaneseLunar(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(JapaneseLunar, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().JapaneseLunar());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_KoreanLunar(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(KoreanLunar, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().KoreanLunar());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_TaiwanLunar(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(TaiwanLunar, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().TaiwanLunar());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_VietnameseLunar(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(VietnameseLunar, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().VietnameseLunar());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Globalization::IClockIdentifiersStatics> : produce_base<D, Windows::Globalization::IClockIdentifiersStatics>
{
    int32_t WINRT_CALL get_TwelveHour(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(TwelveHour, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().TwelveHour());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_TwentyFourHour(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(TwentyFourHour, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().TwentyFourHour());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Globalization::ICurrencyAmount> : produce_base<D, Windows::Globalization::ICurrencyAmount>
{
    int32_t WINRT_CALL get_Amount(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Amount, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().Amount());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Currency(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Currency, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().Currency());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Globalization::ICurrencyAmountFactory> : produce_base<D, Windows::Globalization::ICurrencyAmountFactory>
{
    int32_t WINRT_CALL Create(void* amount, void* currency, void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Create, WINRT_WRAP(Windows::Globalization::CurrencyAmount), hstring const&, hstring const&);
            *result = detach_from<Windows::Globalization::CurrencyAmount>(this->shim().Create(*reinterpret_cast<hstring const*>(&amount), *reinterpret_cast<hstring const*>(&currency)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Globalization::ICurrencyIdentifiersStatics> : produce_base<D, Windows::Globalization::ICurrencyIdentifiersStatics>
{
    int32_t WINRT_CALL get_AED(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(AED, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().AED());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_AFN(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(AFN, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().AFN());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_ALL(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ALL, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().ALL());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_AMD(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(AMD, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().AMD());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_ANG(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ANG, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().ANG());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_AOA(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(AOA, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().AOA());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_ARS(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ARS, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().ARS());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_AUD(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(AUD, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().AUD());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_AWG(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(AWG, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().AWG());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_AZN(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(AZN, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().AZN());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_BAM(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(BAM, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().BAM());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_BBD(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(BBD, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().BBD());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_BDT(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(BDT, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().BDT());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_BGN(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(BGN, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().BGN());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_BHD(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(BHD, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().BHD());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_BIF(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(BIF, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().BIF());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_BMD(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(BMD, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().BMD());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_BND(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(BND, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().BND());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_BOB(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(BOB, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().BOB());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_BRL(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(BRL, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().BRL());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_BSD(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(BSD, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().BSD());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_BTN(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(BTN, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().BTN());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_BWP(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(BWP, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().BWP());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_BYR(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(BYR, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().BYR());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_BZD(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(BZD, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().BZD());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_CAD(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CAD, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().CAD());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_CDF(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CDF, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().CDF());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_CHF(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CHF, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().CHF());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_CLP(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CLP, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().CLP());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_CNY(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CNY, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().CNY());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_COP(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(COP, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().COP());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_CRC(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CRC, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().CRC());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_CUP(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CUP, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().CUP());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_CVE(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CVE, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().CVE());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_CZK(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CZK, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().CZK());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_DJF(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(DJF, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().DJF());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_DKK(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(DKK, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().DKK());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_DOP(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(DOP, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().DOP());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_DZD(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(DZD, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().DZD());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_EGP(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(EGP, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().EGP());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_ERN(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ERN, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().ERN());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_ETB(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ETB, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().ETB());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_EUR(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(EUR, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().EUR());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_FJD(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(FJD, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().FJD());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_FKP(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(FKP, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().FKP());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_GBP(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GBP, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().GBP());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_GEL(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GEL, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().GEL());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_GHS(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GHS, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().GHS());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_GIP(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GIP, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().GIP());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_GMD(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GMD, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().GMD());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_GNF(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GNF, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().GNF());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_GTQ(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GTQ, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().GTQ());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_GYD(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GYD, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().GYD());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_HKD(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(HKD, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().HKD());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_HNL(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(HNL, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().HNL());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_HRK(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(HRK, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().HRK());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_HTG(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(HTG, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().HTG());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_HUF(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(HUF, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().HUF());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_IDR(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IDR, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().IDR());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_ILS(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ILS, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().ILS());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_INR(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(INR, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().INR());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_IQD(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IQD, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().IQD());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_IRR(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IRR, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().IRR());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_ISK(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ISK, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().ISK());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_JMD(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(JMD, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().JMD());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_JOD(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(JOD, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().JOD());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_JPY(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(JPY, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().JPY());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_KES(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(KES, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().KES());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_KGS(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(KGS, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().KGS());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_KHR(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(KHR, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().KHR());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_KMF(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(KMF, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().KMF());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_KPW(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(KPW, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().KPW());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_KRW(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(KRW, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().KRW());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_KWD(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(KWD, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().KWD());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_KYD(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(KYD, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().KYD());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_KZT(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(KZT, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().KZT());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_LAK(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(LAK, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().LAK());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_LBP(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(LBP, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().LBP());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_LKR(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(LKR, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().LKR());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_LRD(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(LRD, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().LRD());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_LSL(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(LSL, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().LSL());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_LTL(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(LTL, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().LTL());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_LVL(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(LVL, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().LVL());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_LYD(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(LYD, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().LYD());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_MAD(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(MAD, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().MAD());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_MDL(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(MDL, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().MDL());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_MGA(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(MGA, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().MGA());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_MKD(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(MKD, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().MKD());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_MMK(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(MMK, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().MMK());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_MNT(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(MNT, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().MNT());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_MOP(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(MOP, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().MOP());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_MRO(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(MRO, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().MRO());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_MUR(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(MUR, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().MUR());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_MVR(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(MVR, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().MVR());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_MWK(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(MWK, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().MWK());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_MXN(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(MXN, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().MXN());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_MYR(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(MYR, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().MYR());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_MZN(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(MZN, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().MZN());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_NAD(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(NAD, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().NAD());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_NGN(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(NGN, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().NGN());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_NIO(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(NIO, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().NIO());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_NOK(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(NOK, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().NOK());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_NPR(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(NPR, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().NPR());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_NZD(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(NZD, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().NZD());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_OMR(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(OMR, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().OMR());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_PAB(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(PAB, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().PAB());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_PEN(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(PEN, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().PEN());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_PGK(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(PGK, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().PGK());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_PHP(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(PHP, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().PHP());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_PKR(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(PKR, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().PKR());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_PLN(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(PLN, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().PLN());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_PYG(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(PYG, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().PYG());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_QAR(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(QAR, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().QAR());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_RON(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(RON, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().RON());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_RSD(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(RSD, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().RSD());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_RUB(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(RUB, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().RUB());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_RWF(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(RWF, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().RWF());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_SAR(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SAR, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().SAR());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_SBD(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SBD, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().SBD());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_SCR(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SCR, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().SCR());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_SDG(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SDG, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().SDG());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_SEK(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SEK, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().SEK());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_SGD(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SGD, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().SGD());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_SHP(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SHP, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().SHP());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_SLL(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SLL, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().SLL());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_SOS(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SOS, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().SOS());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_SRD(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SRD, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().SRD());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_STD(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(STD, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().STD());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_SYP(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SYP, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().SYP());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_SZL(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SZL, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().SZL());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_THB(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(THB, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().THB());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_TJS(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(TJS, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().TJS());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_TMT(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(TMT, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().TMT());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_TND(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(TND, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().TND());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_TOP(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(TOP, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().TOP());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_TRY(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(TRY, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().TRY());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_TTD(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(TTD, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().TTD());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_TWD(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(TWD, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().TWD());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_TZS(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(TZS, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().TZS());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_UAH(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(UAH, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().UAH());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_UGX(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(UGX, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().UGX());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_USD(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(USD, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().USD());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_UYU(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(UYU, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().UYU());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_UZS(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(UZS, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().UZS());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_VEF(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(VEF, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().VEF());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_VND(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(VND, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().VND());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_VUV(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(VUV, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().VUV());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_WST(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(WST, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().WST());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_XAF(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(XAF, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().XAF());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_XCD(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(XCD, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().XCD());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_XOF(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(XOF, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().XOF());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_XPF(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(XPF, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().XPF());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_XXX(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(XXX, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().XXX());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_YER(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(YER, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().YER());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_ZAR(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ZAR, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().ZAR());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_ZMW(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ZMW, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().ZMW());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_ZWL(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ZWL, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().ZWL());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Globalization::ICurrencyIdentifiersStatics2> : produce_base<D, Windows::Globalization::ICurrencyIdentifiersStatics2>
{
    int32_t WINRT_CALL get_BYN(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(BYN, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().BYN());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Globalization::ICurrencyIdentifiersStatics3> : produce_base<D, Windows::Globalization::ICurrencyIdentifiersStatics3>
{
    int32_t WINRT_CALL get_MRU(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(MRU, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().MRU());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_SSP(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SSP, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().SSP());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_STN(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(STN, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().STN());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_VES(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(VES, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().VES());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Globalization::IGeographicRegion> : produce_base<D, Windows::Globalization::IGeographicRegion>
{
    int32_t WINRT_CALL get_Code(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Code, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().Code());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_CodeTwoLetter(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CodeTwoLetter, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().CodeTwoLetter());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_CodeThreeLetter(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CodeThreeLetter, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().CodeThreeLetter());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_CodeThreeDigit(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CodeThreeDigit, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().CodeThreeDigit());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_DisplayName(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(DisplayName, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().DisplayName());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_NativeName(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(NativeName, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().NativeName());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_CurrenciesInUse(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CurrenciesInUse, WINRT_WRAP(Windows::Foundation::Collections::IVectorView<hstring>));
            *value = detach_from<Windows::Foundation::Collections::IVectorView<hstring>>(this->shim().CurrenciesInUse());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Globalization::IGeographicRegionFactory> : produce_base<D, Windows::Globalization::IGeographicRegionFactory>
{
    int32_t WINRT_CALL CreateGeographicRegion(void* geographicRegionCode, void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CreateGeographicRegion, WINRT_WRAP(Windows::Globalization::GeographicRegion), hstring const&);
            *result = detach_from<Windows::Globalization::GeographicRegion>(this->shim().CreateGeographicRegion(*reinterpret_cast<hstring const*>(&geographicRegionCode)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Globalization::IGeographicRegionStatics> : produce_base<D, Windows::Globalization::IGeographicRegionStatics>
{
    int32_t WINRT_CALL IsSupported(void* geographicRegionCode, bool* result) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IsSupported, WINRT_WRAP(bool), hstring const&);
            *result = detach_from<bool>(this->shim().IsSupported(*reinterpret_cast<hstring const*>(&geographicRegionCode)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Globalization::IJapanesePhoneme> : produce_base<D, Windows::Globalization::IJapanesePhoneme>
{
    int32_t WINRT_CALL get_DisplayText(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(DisplayText, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().DisplayText());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_YomiText(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(YomiText, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().YomiText());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_IsPhraseStart(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IsPhraseStart, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().IsPhraseStart());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Globalization::IJapanesePhoneticAnalyzerStatics> : produce_base<D, Windows::Globalization::IJapanesePhoneticAnalyzerStatics>
{
    int32_t WINRT_CALL GetWords(void* input, void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetWords, WINRT_WRAP(Windows::Foundation::Collections::IVectorView<Windows::Globalization::JapanesePhoneme>), hstring const&);
            *result = detach_from<Windows::Foundation::Collections::IVectorView<Windows::Globalization::JapanesePhoneme>>(this->shim().GetWords(*reinterpret_cast<hstring const*>(&input)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL GetWordsWithMonoRubyOption(void* input, bool monoRuby, void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetWords, WINRT_WRAP(Windows::Foundation::Collections::IVectorView<Windows::Globalization::JapanesePhoneme>), hstring const&, bool);
            *result = detach_from<Windows::Foundation::Collections::IVectorView<Windows::Globalization::JapanesePhoneme>>(this->shim().GetWords(*reinterpret_cast<hstring const*>(&input), monoRuby));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Globalization::ILanguage> : produce_base<D, Windows::Globalization::ILanguage>
{
    int32_t WINRT_CALL get_LanguageTag(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(LanguageTag, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().LanguageTag());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_DisplayName(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(DisplayName, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().DisplayName());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_NativeName(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(NativeName, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().NativeName());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Script(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Script, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().Script());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Globalization::ILanguage2> : produce_base<D, Windows::Globalization::ILanguage2>
{
    int32_t WINRT_CALL get_LayoutDirection(Windows::Globalization::LanguageLayoutDirection* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(LayoutDirection, WINRT_WRAP(Windows::Globalization::LanguageLayoutDirection));
            *value = detach_from<Windows::Globalization::LanguageLayoutDirection>(this->shim().LayoutDirection());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Globalization::ILanguageExtensionSubtags> : produce_base<D, Windows::Globalization::ILanguageExtensionSubtags>
{
    int32_t WINRT_CALL GetExtensionSubtags(void* singleton, void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetExtensionSubtags, WINRT_WRAP(Windows::Foundation::Collections::IVectorView<hstring>), hstring const&);
            *value = detach_from<Windows::Foundation::Collections::IVectorView<hstring>>(this->shim().GetExtensionSubtags(*reinterpret_cast<hstring const*>(&singleton)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Globalization::ILanguageFactory> : produce_base<D, Windows::Globalization::ILanguageFactory>
{
    int32_t WINRT_CALL CreateLanguage(void* languageTag, void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CreateLanguage, WINRT_WRAP(Windows::Globalization::Language), hstring const&);
            *result = detach_from<Windows::Globalization::Language>(this->shim().CreateLanguage(*reinterpret_cast<hstring const*>(&languageTag)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Globalization::ILanguageStatics> : produce_base<D, Windows::Globalization::ILanguageStatics>
{
    int32_t WINRT_CALL IsWellFormed(void* languageTag, bool* result) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IsWellFormed, WINRT_WRAP(bool), hstring const&);
            *result = detach_from<bool>(this->shim().IsWellFormed(*reinterpret_cast<hstring const*>(&languageTag)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_CurrentInputMethodLanguageTag(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CurrentInputMethodLanguageTag, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().CurrentInputMethodLanguageTag());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Globalization::ILanguageStatics2> : produce_base<D, Windows::Globalization::ILanguageStatics2>
{
    int32_t WINRT_CALL TrySetInputMethodLanguageTag(void* languageTag, bool* result) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(TrySetInputMethodLanguageTag, WINRT_WRAP(bool), hstring const&);
            *result = detach_from<bool>(this->shim().TrySetInputMethodLanguageTag(*reinterpret_cast<hstring const*>(&languageTag)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Globalization::INumeralSystemIdentifiersStatics> : produce_base<D, Windows::Globalization::INumeralSystemIdentifiersStatics>
{
    int32_t WINRT_CALL get_Arab(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Arab, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().Arab());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_ArabExt(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ArabExt, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().ArabExt());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Bali(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Bali, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().Bali());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Beng(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Beng, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().Beng());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Cham(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Cham, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().Cham());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Deva(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Deva, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().Deva());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_FullWide(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(FullWide, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().FullWide());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Gujr(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Gujr, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().Gujr());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Guru(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Guru, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().Guru());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_HaniDec(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(HaniDec, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().HaniDec());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Java(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Java, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().Java());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Kali(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Kali, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().Kali());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Khmr(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Khmr, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().Khmr());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Knda(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Knda, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().Knda());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Lana(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Lana, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().Lana());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_LanaTham(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(LanaTham, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().LanaTham());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Laoo(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Laoo, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().Laoo());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Latn(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Latn, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().Latn());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Lepc(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Lepc, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().Lepc());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Limb(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Limb, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().Limb());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Mlym(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Mlym, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().Mlym());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Mong(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Mong, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().Mong());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Mtei(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Mtei, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().Mtei());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Mymr(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Mymr, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().Mymr());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_MymrShan(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(MymrShan, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().MymrShan());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Nkoo(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Nkoo, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().Nkoo());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Olck(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Olck, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().Olck());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Orya(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Orya, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().Orya());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Saur(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Saur, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().Saur());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Sund(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Sund, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().Sund());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Talu(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Talu, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().Talu());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_TamlDec(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(TamlDec, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().TamlDec());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Telu(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Telu, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().Telu());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Thai(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Thai, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().Thai());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Tibt(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Tibt, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().Tibt());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Vaii(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Vaii, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().Vaii());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Globalization::INumeralSystemIdentifiersStatics2> : produce_base<D, Windows::Globalization::INumeralSystemIdentifiersStatics2>
{
    int32_t WINRT_CALL get_Brah(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Brah, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().Brah());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Osma(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Osma, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().Osma());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_MathBold(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(MathBold, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().MathBold());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_MathDbl(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(MathDbl, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().MathDbl());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_MathSans(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(MathSans, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().MathSans());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_MathSanb(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(MathSanb, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().MathSanb());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_MathMono(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(MathMono, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().MathMono());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_ZmthBold(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ZmthBold, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().ZmthBold());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_ZmthDbl(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ZmthDbl, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().ZmthDbl());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_ZmthSans(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ZmthSans, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().ZmthSans());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_ZmthSanb(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ZmthSanb, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().ZmthSanb());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_ZmthMono(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ZmthMono, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().ZmthMono());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Globalization::ITimeZoneOnCalendar> : produce_base<D, Windows::Globalization::ITimeZoneOnCalendar>
{
    int32_t WINRT_CALL GetTimeZone(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetTimeZone, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().GetTimeZone());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL ChangeTimeZone(void* timeZoneId) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ChangeTimeZone, WINRT_WRAP(void), hstring const&);
            this->shim().ChangeTimeZone(*reinterpret_cast<hstring const*>(&timeZoneId));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL TimeZoneAsFullString(void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(TimeZoneAsString, WINRT_WRAP(hstring));
            *result = detach_from<hstring>(this->shim().TimeZoneAsString());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL TimeZoneAsString(int32_t idealLength, void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(TimeZoneAsString, WINRT_WRAP(hstring), int32_t);
            *result = detach_from<hstring>(this->shim().TimeZoneAsString(idealLength));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

}

WINRT_EXPORT namespace winrt::Windows::Globalization {

inline hstring ApplicationLanguages::PrimaryLanguageOverride()
{
    return impl::call_factory<ApplicationLanguages, Windows::Globalization::IApplicationLanguagesStatics>([&](auto&& f) { return f.PrimaryLanguageOverride(); });
}

inline void ApplicationLanguages::PrimaryLanguageOverride(param::hstring const& value)
{
    impl::call_factory<ApplicationLanguages, Windows::Globalization::IApplicationLanguagesStatics>([&](auto&& f) { return f.PrimaryLanguageOverride(value); });
}

inline Windows::Foundation::Collections::IVectorView<hstring> ApplicationLanguages::Languages()
{
    return impl::call_factory<ApplicationLanguages, Windows::Globalization::IApplicationLanguagesStatics>([&](auto&& f) { return f.Languages(); });
}

inline Windows::Foundation::Collections::IVectorView<hstring> ApplicationLanguages::ManifestLanguages()
{
    return impl::call_factory<ApplicationLanguages, Windows::Globalization::IApplicationLanguagesStatics>([&](auto&& f) { return f.ManifestLanguages(); });
}

inline Windows::Foundation::Collections::IVectorView<hstring> ApplicationLanguages::GetLanguagesForUser(Windows::System::User const& user)
{
    return impl::call_factory<ApplicationLanguages, Windows::Globalization::IApplicationLanguagesStatics2>([&](auto&& f) { return f.GetLanguagesForUser(user); });
}

inline Calendar::Calendar() :
    Calendar(impl::call_factory<Calendar>([](auto&& f) { return f.template ActivateInstance<Calendar>(); }))
{}

inline Calendar::Calendar(param::iterable<hstring> const& languages) :
    Calendar(impl::call_factory<Calendar, Windows::Globalization::ICalendarFactory>([&](auto&& f) { return f.CreateCalendarDefaultCalendarAndClock(languages); }))
{}

inline Calendar::Calendar(param::iterable<hstring> const& languages, param::hstring const& calendar, param::hstring const& clock) :
    Calendar(impl::call_factory<Calendar, Windows::Globalization::ICalendarFactory>([&](auto&& f) { return f.CreateCalendar(languages, calendar, clock); }))
{}

inline Calendar::Calendar(param::iterable<hstring> const& languages, param::hstring const& calendar, param::hstring const& clock, param::hstring const& timeZoneId) :
    Calendar(impl::call_factory<Calendar, Windows::Globalization::ICalendarFactory2>([&](auto&& f) { return f.CreateCalendarWithTimeZone(languages, calendar, clock, timeZoneId); }))
{}

inline hstring CalendarIdentifiers::Gregorian()
{
    return impl::call_factory<CalendarIdentifiers, Windows::Globalization::ICalendarIdentifiersStatics>([&](auto&& f) { return f.Gregorian(); });
}

inline hstring CalendarIdentifiers::Hebrew()
{
    return impl::call_factory<CalendarIdentifiers, Windows::Globalization::ICalendarIdentifiersStatics>([&](auto&& f) { return f.Hebrew(); });
}

inline hstring CalendarIdentifiers::Hijri()
{
    return impl::call_factory<CalendarIdentifiers, Windows::Globalization::ICalendarIdentifiersStatics>([&](auto&& f) { return f.Hijri(); });
}

inline hstring CalendarIdentifiers::Japanese()
{
    return impl::call_factory<CalendarIdentifiers, Windows::Globalization::ICalendarIdentifiersStatics>([&](auto&& f) { return f.Japanese(); });
}

inline hstring CalendarIdentifiers::Julian()
{
    return impl::call_factory<CalendarIdentifiers, Windows::Globalization::ICalendarIdentifiersStatics>([&](auto&& f) { return f.Julian(); });
}

inline hstring CalendarIdentifiers::Korean()
{
    return impl::call_factory<CalendarIdentifiers, Windows::Globalization::ICalendarIdentifiersStatics>([&](auto&& f) { return f.Korean(); });
}

inline hstring CalendarIdentifiers::Taiwan()
{
    return impl::call_factory<CalendarIdentifiers, Windows::Globalization::ICalendarIdentifiersStatics>([&](auto&& f) { return f.Taiwan(); });
}

inline hstring CalendarIdentifiers::Thai()
{
    return impl::call_factory<CalendarIdentifiers, Windows::Globalization::ICalendarIdentifiersStatics>([&](auto&& f) { return f.Thai(); });
}

inline hstring CalendarIdentifiers::UmAlQura()
{
    return impl::call_factory<CalendarIdentifiers, Windows::Globalization::ICalendarIdentifiersStatics>([&](auto&& f) { return f.UmAlQura(); });
}

inline hstring CalendarIdentifiers::Persian()
{
    return impl::call_factory<CalendarIdentifiers, Windows::Globalization::ICalendarIdentifiersStatics2>([&](auto&& f) { return f.Persian(); });
}

inline hstring CalendarIdentifiers::ChineseLunar()
{
    return impl::call_factory<CalendarIdentifiers, Windows::Globalization::ICalendarIdentifiersStatics3>([&](auto&& f) { return f.ChineseLunar(); });
}

inline hstring CalendarIdentifiers::JapaneseLunar()
{
    return impl::call_factory<CalendarIdentifiers, Windows::Globalization::ICalendarIdentifiersStatics3>([&](auto&& f) { return f.JapaneseLunar(); });
}

inline hstring CalendarIdentifiers::KoreanLunar()
{
    return impl::call_factory<CalendarIdentifiers, Windows::Globalization::ICalendarIdentifiersStatics3>([&](auto&& f) { return f.KoreanLunar(); });
}

inline hstring CalendarIdentifiers::TaiwanLunar()
{
    return impl::call_factory<CalendarIdentifiers, Windows::Globalization::ICalendarIdentifiersStatics3>([&](auto&& f) { return f.TaiwanLunar(); });
}

inline hstring CalendarIdentifiers::VietnameseLunar()
{
    return impl::call_factory<CalendarIdentifiers, Windows::Globalization::ICalendarIdentifiersStatics3>([&](auto&& f) { return f.VietnameseLunar(); });
}

inline hstring ClockIdentifiers::TwelveHour()
{
    return impl::call_factory<ClockIdentifiers, Windows::Globalization::IClockIdentifiersStatics>([&](auto&& f) { return f.TwelveHour(); });
}

inline hstring ClockIdentifiers::TwentyFourHour()
{
    return impl::call_factory<ClockIdentifiers, Windows::Globalization::IClockIdentifiersStatics>([&](auto&& f) { return f.TwentyFourHour(); });
}

inline CurrencyAmount::CurrencyAmount(param::hstring const& amount, param::hstring const& currency) :
    CurrencyAmount(impl::call_factory<CurrencyAmount, Windows::Globalization::ICurrencyAmountFactory>([&](auto&& f) { return f.Create(amount, currency); }))
{}

inline hstring CurrencyIdentifiers::AED()
{
    return impl::call_factory<CurrencyIdentifiers, Windows::Globalization::ICurrencyIdentifiersStatics>([&](auto&& f) { return f.AED(); });
}

inline hstring CurrencyIdentifiers::AFN()
{
    return impl::call_factory<CurrencyIdentifiers, Windows::Globalization::ICurrencyIdentifiersStatics>([&](auto&& f) { return f.AFN(); });
}

inline hstring CurrencyIdentifiers::ALL()
{
    return impl::call_factory<CurrencyIdentifiers, Windows::Globalization::ICurrencyIdentifiersStatics>([&](auto&& f) { return f.ALL(); });
}

inline hstring CurrencyIdentifiers::AMD()
{
    return impl::call_factory<CurrencyIdentifiers, Windows::Globalization::ICurrencyIdentifiersStatics>([&](auto&& f) { return f.AMD(); });
}

inline hstring CurrencyIdentifiers::ANG()
{
    return impl::call_factory<CurrencyIdentifiers, Windows::Globalization::ICurrencyIdentifiersStatics>([&](auto&& f) { return f.ANG(); });
}

inline hstring CurrencyIdentifiers::AOA()
{
    return impl::call_factory<CurrencyIdentifiers, Windows::Globalization::ICurrencyIdentifiersStatics>([&](auto&& f) { return f.AOA(); });
}

inline hstring CurrencyIdentifiers::ARS()
{
    return impl::call_factory<CurrencyIdentifiers, Windows::Globalization::ICurrencyIdentifiersStatics>([&](auto&& f) { return f.ARS(); });
}

inline hstring CurrencyIdentifiers::AUD()
{
    return impl::call_factory<CurrencyIdentifiers, Windows::Globalization::ICurrencyIdentifiersStatics>([&](auto&& f) { return f.AUD(); });
}

inline hstring CurrencyIdentifiers::AWG()
{
    return impl::call_factory<CurrencyIdentifiers, Windows::Globalization::ICurrencyIdentifiersStatics>([&](auto&& f) { return f.AWG(); });
}

inline hstring CurrencyIdentifiers::AZN()
{
    return impl::call_factory<CurrencyIdentifiers, Windows::Globalization::ICurrencyIdentifiersStatics>([&](auto&& f) { return f.AZN(); });
}

inline hstring CurrencyIdentifiers::BAM()
{
    return impl::call_factory<CurrencyIdentifiers, Windows::Globalization::ICurrencyIdentifiersStatics>([&](auto&& f) { return f.BAM(); });
}

inline hstring CurrencyIdentifiers::BBD()
{
    return impl::call_factory<CurrencyIdentifiers, Windows::Globalization::ICurrencyIdentifiersStatics>([&](auto&& f) { return f.BBD(); });
}

inline hstring CurrencyIdentifiers::BDT()
{
    return impl::call_factory<CurrencyIdentifiers, Windows::Globalization::ICurrencyIdentifiersStatics>([&](auto&& f) { return f.BDT(); });
}

inline hstring CurrencyIdentifiers::BGN()
{
    return impl::call_factory<CurrencyIdentifiers, Windows::Globalization::ICurrencyIdentifiersStatics>([&](auto&& f) { return f.BGN(); });
}

inline hstring CurrencyIdentifiers::BHD()
{
    return impl::call_factory<CurrencyIdentifiers, Windows::Globalization::ICurrencyIdentifiersStatics>([&](auto&& f) { return f.BHD(); });
}

inline hstring CurrencyIdentifiers::BIF()
{
    return impl::call_factory<CurrencyIdentifiers, Windows::Globalization::ICurrencyIdentifiersStatics>([&](auto&& f) { return f.BIF(); });
}

inline hstring CurrencyIdentifiers::BMD()
{
    return impl::call_factory<CurrencyIdentifiers, Windows::Globalization::ICurrencyIdentifiersStatics>([&](auto&& f) { return f.BMD(); });
}

inline hstring CurrencyIdentifiers::BND()
{
    return impl::call_factory<CurrencyIdentifiers, Windows::Globalization::ICurrencyIdentifiersStatics>([&](auto&& f) { return f.BND(); });
}

inline hstring CurrencyIdentifiers::BOB()
{
    return impl::call_factory<CurrencyIdentifiers, Windows::Globalization::ICurrencyIdentifiersStatics>([&](auto&& f) { return f.BOB(); });
}

inline hstring CurrencyIdentifiers::BRL()
{
    return impl::call_factory<CurrencyIdentifiers, Windows::Globalization::ICurrencyIdentifiersStatics>([&](auto&& f) { return f.BRL(); });
}

inline hstring CurrencyIdentifiers::BSD()
{
    return impl::call_factory<CurrencyIdentifiers, Windows::Globalization::ICurrencyIdentifiersStatics>([&](auto&& f) { return f.BSD(); });
}

inline hstring CurrencyIdentifiers::BTN()
{
    return impl::call_factory<CurrencyIdentifiers, Windows::Globalization::ICurrencyIdentifiersStatics>([&](auto&& f) { return f.BTN(); });
}

inline hstring CurrencyIdentifiers::BWP()
{
    return impl::call_factory<CurrencyIdentifiers, Windows::Globalization::ICurrencyIdentifiersStatics>([&](auto&& f) { return f.BWP(); });
}

inline hstring CurrencyIdentifiers::BYR()
{
    return impl::call_factory<CurrencyIdentifiers, Windows::Globalization::ICurrencyIdentifiersStatics>([&](auto&& f) { return f.BYR(); });
}

inline hstring CurrencyIdentifiers::BZD()
{
    return impl::call_factory<CurrencyIdentifiers, Windows::Globalization::ICurrencyIdentifiersStatics>([&](auto&& f) { return f.BZD(); });
}

inline hstring CurrencyIdentifiers::CAD()
{
    return impl::call_factory<CurrencyIdentifiers, Windows::Globalization::ICurrencyIdentifiersStatics>([&](auto&& f) { return f.CAD(); });
}

inline hstring CurrencyIdentifiers::CDF()
{
    return impl::call_factory<CurrencyIdentifiers, Windows::Globalization::ICurrencyIdentifiersStatics>([&](auto&& f) { return f.CDF(); });
}

inline hstring CurrencyIdentifiers::CHF()
{
    return impl::call_factory<CurrencyIdentifiers, Windows::Globalization::ICurrencyIdentifiersStatics>([&](auto&& f) { return f.CHF(); });
}

inline hstring CurrencyIdentifiers::CLP()
{
    return impl::call_factory<CurrencyIdentifiers, Windows::Globalization::ICurrencyIdentifiersStatics>([&](auto&& f) { return f.CLP(); });
}

inline hstring CurrencyIdentifiers::CNY()
{
    return impl::call_factory<CurrencyIdentifiers, Windows::Globalization::ICurrencyIdentifiersStatics>([&](auto&& f) { return f.CNY(); });
}

inline hstring CurrencyIdentifiers::COP()
{
    return impl::call_factory<CurrencyIdentifiers, Windows::Globalization::ICurrencyIdentifiersStatics>([&](auto&& f) { return f.COP(); });
}

inline hstring CurrencyIdentifiers::CRC()
{
    return impl::call_factory<CurrencyIdentifiers, Windows::Globalization::ICurrencyIdentifiersStatics>([&](auto&& f) { return f.CRC(); });
}

inline hstring CurrencyIdentifiers::CUP()
{
    return impl::call_factory<CurrencyIdentifiers, Windows::Globalization::ICurrencyIdentifiersStatics>([&](auto&& f) { return f.CUP(); });
}

inline hstring CurrencyIdentifiers::CVE()
{
    return impl::call_factory<CurrencyIdentifiers, Windows::Globalization::ICurrencyIdentifiersStatics>([&](auto&& f) { return f.CVE(); });
}

inline hstring CurrencyIdentifiers::CZK()
{
    return impl::call_factory<CurrencyIdentifiers, Windows::Globalization::ICurrencyIdentifiersStatics>([&](auto&& f) { return f.CZK(); });
}

inline hstring CurrencyIdentifiers::DJF()
{
    return impl::call_factory<CurrencyIdentifiers, Windows::Globalization::ICurrencyIdentifiersStatics>([&](auto&& f) { return f.DJF(); });
}

inline hstring CurrencyIdentifiers::DKK()
{
    return impl::call_factory<CurrencyIdentifiers, Windows::Globalization::ICurrencyIdentifiersStatics>([&](auto&& f) { return f.DKK(); });
}

inline hstring CurrencyIdentifiers::DOP()
{
    return impl::call_factory<CurrencyIdentifiers, Windows::Globalization::ICurrencyIdentifiersStatics>([&](auto&& f) { return f.DOP(); });
}

inline hstring CurrencyIdentifiers::DZD()
{
    return impl::call_factory<CurrencyIdentifiers, Windows::Globalization::ICurrencyIdentifiersStatics>([&](auto&& f) { return f.DZD(); });
}

inline hstring CurrencyIdentifiers::EGP()
{
    return impl::call_factory<CurrencyIdentifiers, Windows::Globalization::ICurrencyIdentifiersStatics>([&](auto&& f) { return f.EGP(); });
}

inline hstring CurrencyIdentifiers::ERN()
{
    return impl::call_factory<CurrencyIdentifiers, Windows::Globalization::ICurrencyIdentifiersStatics>([&](auto&& f) { return f.ERN(); });
}

inline hstring CurrencyIdentifiers::ETB()
{
    return impl::call_factory<CurrencyIdentifiers, Windows::Globalization::ICurrencyIdentifiersStatics>([&](auto&& f) { return f.ETB(); });
}

inline hstring CurrencyIdentifiers::EUR()
{
    return impl::call_factory<CurrencyIdentifiers, Windows::Globalization::ICurrencyIdentifiersStatics>([&](auto&& f) { return f.EUR(); });
}

inline hstring CurrencyIdentifiers::FJD()
{
    return impl::call_factory<CurrencyIdentifiers, Windows::Globalization::ICurrencyIdentifiersStatics>([&](auto&& f) { return f.FJD(); });
}

inline hstring CurrencyIdentifiers::FKP()
{
    return impl::call_factory<CurrencyIdentifiers, Windows::Globalization::ICurrencyIdentifiersStatics>([&](auto&& f) { return f.FKP(); });
}

inline hstring CurrencyIdentifiers::GBP()
{
    return impl::call_factory<CurrencyIdentifiers, Windows::Globalization::ICurrencyIdentifiersStatics>([&](auto&& f) { return f.GBP(); });
}

inline hstring CurrencyIdentifiers::GEL()
{
    return impl::call_factory<CurrencyIdentifiers, Windows::Globalization::ICurrencyIdentifiersStatics>([&](auto&& f) { return f.GEL(); });
}

inline hstring CurrencyIdentifiers::GHS()
{
    return impl::call_factory<CurrencyIdentifiers, Windows::Globalization::ICurrencyIdentifiersStatics>([&](auto&& f) { return f.GHS(); });
}

inline hstring CurrencyIdentifiers::GIP()
{
    return impl::call_factory<CurrencyIdentifiers, Windows::Globalization::ICurrencyIdentifiersStatics>([&](auto&& f) { return f.GIP(); });
}

inline hstring CurrencyIdentifiers::GMD()
{
    return impl::call_factory<CurrencyIdentifiers, Windows::Globalization::ICurrencyIdentifiersStatics>([&](auto&& f) { return f.GMD(); });
}

inline hstring CurrencyIdentifiers::GNF()
{
    return impl::call_factory<CurrencyIdentifiers, Windows::Globalization::ICurrencyIdentifiersStatics>([&](auto&& f) { return f.GNF(); });
}

inline hstring CurrencyIdentifiers::GTQ()
{
    return impl::call_factory<CurrencyIdentifiers, Windows::Globalization::ICurrencyIdentifiersStatics>([&](auto&& f) { return f.GTQ(); });
}

inline hstring CurrencyIdentifiers::GYD()
{
    return impl::call_factory<CurrencyIdentifiers, Windows::Globalization::ICurrencyIdentifiersStatics>([&](auto&& f) { return f.GYD(); });
}

inline hstring CurrencyIdentifiers::HKD()
{
    return impl::call_factory<CurrencyIdentifiers, Windows::Globalization::ICurrencyIdentifiersStatics>([&](auto&& f) { return f.HKD(); });
}

inline hstring CurrencyIdentifiers::HNL()
{
    return impl::call_factory<CurrencyIdentifiers, Windows::Globalization::ICurrencyIdentifiersStatics>([&](auto&& f) { return f.HNL(); });
}

inline hstring CurrencyIdentifiers::HRK()
{
    return impl::call_factory<CurrencyIdentifiers, Windows::Globalization::ICurrencyIdentifiersStatics>([&](auto&& f) { return f.HRK(); });
}

inline hstring CurrencyIdentifiers::HTG()
{
    return impl::call_factory<CurrencyIdentifiers, Windows::Globalization::ICurrencyIdentifiersStatics>([&](auto&& f) { return f.HTG(); });
}

inline hstring CurrencyIdentifiers::HUF()
{
    return impl::call_factory<CurrencyIdentifiers, Windows::Globalization::ICurrencyIdentifiersStatics>([&](auto&& f) { return f.HUF(); });
}

inline hstring CurrencyIdentifiers::IDR()
{
    return impl::call_factory<CurrencyIdentifiers, Windows::Globalization::ICurrencyIdentifiersStatics>([&](auto&& f) { return f.IDR(); });
}

inline hstring CurrencyIdentifiers::ILS()
{
    return impl::call_factory<CurrencyIdentifiers, Windows::Globalization::ICurrencyIdentifiersStatics>([&](auto&& f) { return f.ILS(); });
}

inline hstring CurrencyIdentifiers::INR()
{
    return impl::call_factory<CurrencyIdentifiers, Windows::Globalization::ICurrencyIdentifiersStatics>([&](auto&& f) { return f.INR(); });
}

inline hstring CurrencyIdentifiers::IQD()
{
    return impl::call_factory<CurrencyIdentifiers, Windows::Globalization::ICurrencyIdentifiersStatics>([&](auto&& f) { return f.IQD(); });
}

inline hstring CurrencyIdentifiers::IRR()
{
    return impl::call_factory<CurrencyIdentifiers, Windows::Globalization::ICurrencyIdentifiersStatics>([&](auto&& f) { return f.IRR(); });
}

inline hstring CurrencyIdentifiers::ISK()
{
    return impl::call_factory<CurrencyIdentifiers, Windows::Globalization::ICurrencyIdentifiersStatics>([&](auto&& f) { return f.ISK(); });
}

inline hstring CurrencyIdentifiers::JMD()
{
    return impl::call_factory<CurrencyIdentifiers, Windows::Globalization::ICurrencyIdentifiersStatics>([&](auto&& f) { return f.JMD(); });
}

inline hstring CurrencyIdentifiers::JOD()
{
    return impl::call_factory<CurrencyIdentifiers, Windows::Globalization::ICurrencyIdentifiersStatics>([&](auto&& f) { return f.JOD(); });
}

inline hstring CurrencyIdentifiers::JPY()
{
    return impl::call_factory<CurrencyIdentifiers, Windows::Globalization::ICurrencyIdentifiersStatics>([&](auto&& f) { return f.JPY(); });
}

inline hstring CurrencyIdentifiers::KES()
{
    return impl::call_factory<CurrencyIdentifiers, Windows::Globalization::ICurrencyIdentifiersStatics>([&](auto&& f) { return f.KES(); });
}

inline hstring CurrencyIdentifiers::KGS()
{
    return impl::call_factory<CurrencyIdentifiers, Windows::Globalization::ICurrencyIdentifiersStatics>([&](auto&& f) { return f.KGS(); });
}

inline hstring CurrencyIdentifiers::KHR()
{
    return impl::call_factory<CurrencyIdentifiers, Windows::Globalization::ICurrencyIdentifiersStatics>([&](auto&& f) { return f.KHR(); });
}

inline hstring CurrencyIdentifiers::KMF()
{
    return impl::call_factory<CurrencyIdentifiers, Windows::Globalization::ICurrencyIdentifiersStatics>([&](auto&& f) { return f.KMF(); });
}

inline hstring CurrencyIdentifiers::KPW()
{
    return impl::call_factory<CurrencyIdentifiers, Windows::Globalization::ICurrencyIdentifiersStatics>([&](auto&& f) { return f.KPW(); });
}

inline hstring CurrencyIdentifiers::KRW()
{
    return impl::call_factory<CurrencyIdentifiers, Windows::Globalization::ICurrencyIdentifiersStatics>([&](auto&& f) { return f.KRW(); });
}

inline hstring CurrencyIdentifiers::KWD()
{
    return impl::call_factory<CurrencyIdentifiers, Windows::Globalization::ICurrencyIdentifiersStatics>([&](auto&& f) { return f.KWD(); });
}

inline hstring CurrencyIdentifiers::KYD()
{
    return impl::call_factory<CurrencyIdentifiers, Windows::Globalization::ICurrencyIdentifiersStatics>([&](auto&& f) { return f.KYD(); });
}

inline hstring CurrencyIdentifiers::KZT()
{
    return impl::call_factory<CurrencyIdentifiers, Windows::Globalization::ICurrencyIdentifiersStatics>([&](auto&& f) { return f.KZT(); });
}

inline hstring CurrencyIdentifiers::LAK()
{
    return impl::call_factory<CurrencyIdentifiers, Windows::Globalization::ICurrencyIdentifiersStatics>([&](auto&& f) { return f.LAK(); });
}

inline hstring CurrencyIdentifiers::LBP()
{
    return impl::call_factory<CurrencyIdentifiers, Windows::Globalization::ICurrencyIdentifiersStatics>([&](auto&& f) { return f.LBP(); });
}

inline hstring CurrencyIdentifiers::LKR()
{
    return impl::call_factory<CurrencyIdentifiers, Windows::Globalization::ICurrencyIdentifiersStatics>([&](auto&& f) { return f.LKR(); });
}

inline hstring CurrencyIdentifiers::LRD()
{
    return impl::call_factory<CurrencyIdentifiers, Windows::Globalization::ICurrencyIdentifiersStatics>([&](auto&& f) { return f.LRD(); });
}

inline hstring CurrencyIdentifiers::LSL()
{
    return impl::call_factory<CurrencyIdentifiers, Windows::Globalization::ICurrencyIdentifiersStatics>([&](auto&& f) { return f.LSL(); });
}

inline hstring CurrencyIdentifiers::LTL()
{
    return impl::call_factory<CurrencyIdentifiers, Windows::Globalization::ICurrencyIdentifiersStatics>([&](auto&& f) { return f.LTL(); });
}

inline hstring CurrencyIdentifiers::LVL()
{
    return impl::call_factory<CurrencyIdentifiers, Windows::Globalization::ICurrencyIdentifiersStatics>([&](auto&& f) { return f.LVL(); });
}

inline hstring CurrencyIdentifiers::LYD()
{
    return impl::call_factory<CurrencyIdentifiers, Windows::Globalization::ICurrencyIdentifiersStatics>([&](auto&& f) { return f.LYD(); });
}

inline hstring CurrencyIdentifiers::MAD()
{
    return impl::call_factory<CurrencyIdentifiers, Windows::Globalization::ICurrencyIdentifiersStatics>([&](auto&& f) { return f.MAD(); });
}

inline hstring CurrencyIdentifiers::MDL()
{
    return impl::call_factory<CurrencyIdentifiers, Windows::Globalization::ICurrencyIdentifiersStatics>([&](auto&& f) { return f.MDL(); });
}

inline hstring CurrencyIdentifiers::MGA()
{
    return impl::call_factory<CurrencyIdentifiers, Windows::Globalization::ICurrencyIdentifiersStatics>([&](auto&& f) { return f.MGA(); });
}

inline hstring CurrencyIdentifiers::MKD()
{
    return impl::call_factory<CurrencyIdentifiers, Windows::Globalization::ICurrencyIdentifiersStatics>([&](auto&& f) { return f.MKD(); });
}

inline hstring CurrencyIdentifiers::MMK()
{
    return impl::call_factory<CurrencyIdentifiers, Windows::Globalization::ICurrencyIdentifiersStatics>([&](auto&& f) { return f.MMK(); });
}

inline hstring CurrencyIdentifiers::MNT()
{
    return impl::call_factory<CurrencyIdentifiers, Windows::Globalization::ICurrencyIdentifiersStatics>([&](auto&& f) { return f.MNT(); });
}

inline hstring CurrencyIdentifiers::MOP()
{
    return impl::call_factory<CurrencyIdentifiers, Windows::Globalization::ICurrencyIdentifiersStatics>([&](auto&& f) { return f.MOP(); });
}

inline hstring CurrencyIdentifiers::MRO()
{
    return impl::call_factory<CurrencyIdentifiers, Windows::Globalization::ICurrencyIdentifiersStatics>([&](auto&& f) { return f.MRO(); });
}

inline hstring CurrencyIdentifiers::MUR()
{
    return impl::call_factory<CurrencyIdentifiers, Windows::Globalization::ICurrencyIdentifiersStatics>([&](auto&& f) { return f.MUR(); });
}

inline hstring CurrencyIdentifiers::MVR()
{
    return impl::call_factory<CurrencyIdentifiers, Windows::Globalization::ICurrencyIdentifiersStatics>([&](auto&& f) { return f.MVR(); });
}

inline hstring CurrencyIdentifiers::MWK()
{
    return impl::call_factory<CurrencyIdentifiers, Windows::Globalization::ICurrencyIdentifiersStatics>([&](auto&& f) { return f.MWK(); });
}

inline hstring CurrencyIdentifiers::MXN()
{
    return impl::call_factory<CurrencyIdentifiers, Windows::Globalization::ICurrencyIdentifiersStatics>([&](auto&& f) { return f.MXN(); });
}

inline hstring CurrencyIdentifiers::MYR()
{
    return impl::call_factory<CurrencyIdentifiers, Windows::Globalization::ICurrencyIdentifiersStatics>([&](auto&& f) { return f.MYR(); });
}

inline hstring CurrencyIdentifiers::MZN()
{
    return impl::call_factory<CurrencyIdentifiers, Windows::Globalization::ICurrencyIdentifiersStatics>([&](auto&& f) { return f.MZN(); });
}

inline hstring CurrencyIdentifiers::NAD()
{
    return impl::call_factory<CurrencyIdentifiers, Windows::Globalization::ICurrencyIdentifiersStatics>([&](auto&& f) { return f.NAD(); });
}

inline hstring CurrencyIdentifiers::NGN()
{
    return impl::call_factory<CurrencyIdentifiers, Windows::Globalization::ICurrencyIdentifiersStatics>([&](auto&& f) { return f.NGN(); });
}

inline hstring CurrencyIdentifiers::NIO()
{
    return impl::call_factory<CurrencyIdentifiers, Windows::Globalization::ICurrencyIdentifiersStatics>([&](auto&& f) { return f.NIO(); });
}

inline hstring CurrencyIdentifiers::NOK()
{
    return impl::call_factory<CurrencyIdentifiers, Windows::Globalization::ICurrencyIdentifiersStatics>([&](auto&& f) { return f.NOK(); });
}

inline hstring CurrencyIdentifiers::NPR()
{
    return impl::call_factory<CurrencyIdentifiers, Windows::Globalization::ICurrencyIdentifiersStatics>([&](auto&& f) { return f.NPR(); });
}

inline hstring CurrencyIdentifiers::NZD()
{
    return impl::call_factory<CurrencyIdentifiers, Windows::Globalization::ICurrencyIdentifiersStatics>([&](auto&& f) { return f.NZD(); });
}

inline hstring CurrencyIdentifiers::OMR()
{
    return impl::call_factory<CurrencyIdentifiers, Windows::Globalization::ICurrencyIdentifiersStatics>([&](auto&& f) { return f.OMR(); });
}

inline hstring CurrencyIdentifiers::PAB()
{
    return impl::call_factory<CurrencyIdentifiers, Windows::Globalization::ICurrencyIdentifiersStatics>([&](auto&& f) { return f.PAB(); });
}

inline hstring CurrencyIdentifiers::PEN()
{
    return impl::call_factory<CurrencyIdentifiers, Windows::Globalization::ICurrencyIdentifiersStatics>([&](auto&& f) { return f.PEN(); });
}

inline hstring CurrencyIdentifiers::PGK()
{
    return impl::call_factory<CurrencyIdentifiers, Windows::Globalization::ICurrencyIdentifiersStatics>([&](auto&& f) { return f.PGK(); });
}

inline hstring CurrencyIdentifiers::PHP()
{
    return impl::call_factory<CurrencyIdentifiers, Windows::Globalization::ICurrencyIdentifiersStatics>([&](auto&& f) { return f.PHP(); });
}

inline hstring CurrencyIdentifiers::PKR()
{
    return impl::call_factory<CurrencyIdentifiers, Windows::Globalization::ICurrencyIdentifiersStatics>([&](auto&& f) { return f.PKR(); });
}

inline hstring CurrencyIdentifiers::PLN()
{
    return impl::call_factory<CurrencyIdentifiers, Windows::Globalization::ICurrencyIdentifiersStatics>([&](auto&& f) { return f.PLN(); });
}

inline hstring CurrencyIdentifiers::PYG()
{
    return impl::call_factory<CurrencyIdentifiers, Windows::Globalization::ICurrencyIdentifiersStatics>([&](auto&& f) { return f.PYG(); });
}

inline hstring CurrencyIdentifiers::QAR()
{
    return impl::call_factory<CurrencyIdentifiers, Windows::Globalization::ICurrencyIdentifiersStatics>([&](auto&& f) { return f.QAR(); });
}

inline hstring CurrencyIdentifiers::RON()
{
    return impl::call_factory<CurrencyIdentifiers, Windows::Globalization::ICurrencyIdentifiersStatics>([&](auto&& f) { return f.RON(); });
}

inline hstring CurrencyIdentifiers::RSD()
{
    return impl::call_factory<CurrencyIdentifiers, Windows::Globalization::ICurrencyIdentifiersStatics>([&](auto&& f) { return f.RSD(); });
}

inline hstring CurrencyIdentifiers::RUB()
{
    return impl::call_factory<CurrencyIdentifiers, Windows::Globalization::ICurrencyIdentifiersStatics>([&](auto&& f) { return f.RUB(); });
}

inline hstring CurrencyIdentifiers::RWF()
{
    return impl::call_factory<CurrencyIdentifiers, Windows::Globalization::ICurrencyIdentifiersStatics>([&](auto&& f) { return f.RWF(); });
}

inline hstring CurrencyIdentifiers::SAR()
{
    return impl::call_factory<CurrencyIdentifiers, Windows::Globalization::ICurrencyIdentifiersStatics>([&](auto&& f) { return f.SAR(); });
}

inline hstring CurrencyIdentifiers::SBD()
{
    return impl::call_factory<CurrencyIdentifiers, Windows::Globalization::ICurrencyIdentifiersStatics>([&](auto&& f) { return f.SBD(); });
}

inline hstring CurrencyIdentifiers::SCR()
{
    return impl::call_factory<CurrencyIdentifiers, Windows::Globalization::ICurrencyIdentifiersStatics>([&](auto&& f) { return f.SCR(); });
}

inline hstring CurrencyIdentifiers::SDG()
{
    return impl::call_factory<CurrencyIdentifiers, Windows::Globalization::ICurrencyIdentifiersStatics>([&](auto&& f) { return f.SDG(); });
}

inline hstring CurrencyIdentifiers::SEK()
{
    return impl::call_factory<CurrencyIdentifiers, Windows::Globalization::ICurrencyIdentifiersStatics>([&](auto&& f) { return f.SEK(); });
}

inline hstring CurrencyIdentifiers::SGD()
{
    return impl::call_factory<CurrencyIdentifiers, Windows::Globalization::ICurrencyIdentifiersStatics>([&](auto&& f) { return f.SGD(); });
}

inline hstring CurrencyIdentifiers::SHP()
{
    return impl::call_factory<CurrencyIdentifiers, Windows::Globalization::ICurrencyIdentifiersStatics>([&](auto&& f) { return f.SHP(); });
}

inline hstring CurrencyIdentifiers::SLL()
{
    return impl::call_factory<CurrencyIdentifiers, Windows::Globalization::ICurrencyIdentifiersStatics>([&](auto&& f) { return f.SLL(); });
}

inline hstring CurrencyIdentifiers::SOS()
{
    return impl::call_factory<CurrencyIdentifiers, Windows::Globalization::ICurrencyIdentifiersStatics>([&](auto&& f) { return f.SOS(); });
}

inline hstring CurrencyIdentifiers::SRD()
{
    return impl::call_factory<CurrencyIdentifiers, Windows::Globalization::ICurrencyIdentifiersStatics>([&](auto&& f) { return f.SRD(); });
}

inline hstring CurrencyIdentifiers::STD()
{
    return impl::call_factory<CurrencyIdentifiers, Windows::Globalization::ICurrencyIdentifiersStatics>([&](auto&& f) { return f.STD(); });
}

inline hstring CurrencyIdentifiers::SYP()
{
    return impl::call_factory<CurrencyIdentifiers, Windows::Globalization::ICurrencyIdentifiersStatics>([&](auto&& f) { return f.SYP(); });
}

inline hstring CurrencyIdentifiers::SZL()
{
    return impl::call_factory<CurrencyIdentifiers, Windows::Globalization::ICurrencyIdentifiersStatics>([&](auto&& f) { return f.SZL(); });
}

inline hstring CurrencyIdentifiers::THB()
{
    return impl::call_factory<CurrencyIdentifiers, Windows::Globalization::ICurrencyIdentifiersStatics>([&](auto&& f) { return f.THB(); });
}

inline hstring CurrencyIdentifiers::TJS()
{
    return impl::call_factory<CurrencyIdentifiers, Windows::Globalization::ICurrencyIdentifiersStatics>([&](auto&& f) { return f.TJS(); });
}

inline hstring CurrencyIdentifiers::TMT()
{
    return impl::call_factory<CurrencyIdentifiers, Windows::Globalization::ICurrencyIdentifiersStatics>([&](auto&& f) { return f.TMT(); });
}

inline hstring CurrencyIdentifiers::TND()
{
    return impl::call_factory<CurrencyIdentifiers, Windows::Globalization::ICurrencyIdentifiersStatics>([&](auto&& f) { return f.TND(); });
}

inline hstring CurrencyIdentifiers::TOP()
{
    return impl::call_factory<CurrencyIdentifiers, Windows::Globalization::ICurrencyIdentifiersStatics>([&](auto&& f) { return f.TOP(); });
}

inline hstring CurrencyIdentifiers::TRY()
{
    return impl::call_factory<CurrencyIdentifiers, Windows::Globalization::ICurrencyIdentifiersStatics>([&](auto&& f) { return f.TRY(); });
}

inline hstring CurrencyIdentifiers::TTD()
{
    return impl::call_factory<CurrencyIdentifiers, Windows::Globalization::ICurrencyIdentifiersStatics>([&](auto&& f) { return f.TTD(); });
}

inline hstring CurrencyIdentifiers::TWD()
{
    return impl::call_factory<CurrencyIdentifiers, Windows::Globalization::ICurrencyIdentifiersStatics>([&](auto&& f) { return f.TWD(); });
}

inline hstring CurrencyIdentifiers::TZS()
{
    return impl::call_factory<CurrencyIdentifiers, Windows::Globalization::ICurrencyIdentifiersStatics>([&](auto&& f) { return f.TZS(); });
}

inline hstring CurrencyIdentifiers::UAH()
{
    return impl::call_factory<CurrencyIdentifiers, Windows::Globalization::ICurrencyIdentifiersStatics>([&](auto&& f) { return f.UAH(); });
}

inline hstring CurrencyIdentifiers::UGX()
{
    return impl::call_factory<CurrencyIdentifiers, Windows::Globalization::ICurrencyIdentifiersStatics>([&](auto&& f) { return f.UGX(); });
}

inline hstring CurrencyIdentifiers::USD()
{
    return impl::call_factory<CurrencyIdentifiers, Windows::Globalization::ICurrencyIdentifiersStatics>([&](auto&& f) { return f.USD(); });
}

inline hstring CurrencyIdentifiers::UYU()
{
    return impl::call_factory<CurrencyIdentifiers, Windows::Globalization::ICurrencyIdentifiersStatics>([&](auto&& f) { return f.UYU(); });
}

inline hstring CurrencyIdentifiers::UZS()
{
    return impl::call_factory<CurrencyIdentifiers, Windows::Globalization::ICurrencyIdentifiersStatics>([&](auto&& f) { return f.UZS(); });
}

inline hstring CurrencyIdentifiers::VEF()
{
    return impl::call_factory<CurrencyIdentifiers, Windows::Globalization::ICurrencyIdentifiersStatics>([&](auto&& f) { return f.VEF(); });
}

inline hstring CurrencyIdentifiers::VND()
{
    return impl::call_factory<CurrencyIdentifiers, Windows::Globalization::ICurrencyIdentifiersStatics>([&](auto&& f) { return f.VND(); });
}

inline hstring CurrencyIdentifiers::VUV()
{
    return impl::call_factory<CurrencyIdentifiers, Windows::Globalization::ICurrencyIdentifiersStatics>([&](auto&& f) { return f.VUV(); });
}

inline hstring CurrencyIdentifiers::WST()
{
    return impl::call_factory<CurrencyIdentifiers, Windows::Globalization::ICurrencyIdentifiersStatics>([&](auto&& f) { return f.WST(); });
}

inline hstring CurrencyIdentifiers::XAF()
{
    return impl::call_factory<CurrencyIdentifiers, Windows::Globalization::ICurrencyIdentifiersStatics>([&](auto&& f) { return f.XAF(); });
}

inline hstring CurrencyIdentifiers::XCD()
{
    return impl::call_factory<CurrencyIdentifiers, Windows::Globalization::ICurrencyIdentifiersStatics>([&](auto&& f) { return f.XCD(); });
}

inline hstring CurrencyIdentifiers::XOF()
{
    return impl::call_factory<CurrencyIdentifiers, Windows::Globalization::ICurrencyIdentifiersStatics>([&](auto&& f) { return f.XOF(); });
}

inline hstring CurrencyIdentifiers::XPF()
{
    return impl::call_factory<CurrencyIdentifiers, Windows::Globalization::ICurrencyIdentifiersStatics>([&](auto&& f) { return f.XPF(); });
}

inline hstring CurrencyIdentifiers::XXX()
{
    return impl::call_factory<CurrencyIdentifiers, Windows::Globalization::ICurrencyIdentifiersStatics>([&](auto&& f) { return f.XXX(); });
}

inline hstring CurrencyIdentifiers::YER()
{
    return impl::call_factory<CurrencyIdentifiers, Windows::Globalization::ICurrencyIdentifiersStatics>([&](auto&& f) { return f.YER(); });
}

inline hstring CurrencyIdentifiers::ZAR()
{
    return impl::call_factory<CurrencyIdentifiers, Windows::Globalization::ICurrencyIdentifiersStatics>([&](auto&& f) { return f.ZAR(); });
}

inline hstring CurrencyIdentifiers::ZMW()
{
    return impl::call_factory<CurrencyIdentifiers, Windows::Globalization::ICurrencyIdentifiersStatics>([&](auto&& f) { return f.ZMW(); });
}

inline hstring CurrencyIdentifiers::ZWL()
{
    return impl::call_factory<CurrencyIdentifiers, Windows::Globalization::ICurrencyIdentifiersStatics>([&](auto&& f) { return f.ZWL(); });
}

inline hstring CurrencyIdentifiers::BYN()
{
    return impl::call_factory<CurrencyIdentifiers, Windows::Globalization::ICurrencyIdentifiersStatics2>([&](auto&& f) { return f.BYN(); });
}

inline hstring CurrencyIdentifiers::MRU()
{
    return impl::call_factory<CurrencyIdentifiers, Windows::Globalization::ICurrencyIdentifiersStatics3>([&](auto&& f) { return f.MRU(); });
}

inline hstring CurrencyIdentifiers::SSP()
{
    return impl::call_factory<CurrencyIdentifiers, Windows::Globalization::ICurrencyIdentifiersStatics3>([&](auto&& f) { return f.SSP(); });
}

inline hstring CurrencyIdentifiers::STN()
{
    return impl::call_factory<CurrencyIdentifiers, Windows::Globalization::ICurrencyIdentifiersStatics3>([&](auto&& f) { return f.STN(); });
}

inline hstring CurrencyIdentifiers::VES()
{
    return impl::call_factory<CurrencyIdentifiers, Windows::Globalization::ICurrencyIdentifiersStatics3>([&](auto&& f) { return f.VES(); });
}

inline GeographicRegion::GeographicRegion() :
    GeographicRegion(impl::call_factory<GeographicRegion>([](auto&& f) { return f.template ActivateInstance<GeographicRegion>(); }))
{}

inline GeographicRegion::GeographicRegion(param::hstring const& geographicRegionCode) :
    GeographicRegion(impl::call_factory<GeographicRegion, Windows::Globalization::IGeographicRegionFactory>([&](auto&& f) { return f.CreateGeographicRegion(geographicRegionCode); }))
{}

inline bool GeographicRegion::IsSupported(param::hstring const& geographicRegionCode)
{
    return impl::call_factory<GeographicRegion, Windows::Globalization::IGeographicRegionStatics>([&](auto&& f) { return f.IsSupported(geographicRegionCode); });
}

inline Windows::Foundation::Collections::IVectorView<Windows::Globalization::JapanesePhoneme> JapanesePhoneticAnalyzer::GetWords(param::hstring const& input)
{
    return impl::call_factory<JapanesePhoneticAnalyzer, Windows::Globalization::IJapanesePhoneticAnalyzerStatics>([&](auto&& f) { return f.GetWords(input); });
}

inline Windows::Foundation::Collections::IVectorView<Windows::Globalization::JapanesePhoneme> JapanesePhoneticAnalyzer::GetWords(param::hstring const& input, bool monoRuby)
{
    return impl::call_factory<JapanesePhoneticAnalyzer, Windows::Globalization::IJapanesePhoneticAnalyzerStatics>([&](auto&& f) { return f.GetWords(input, monoRuby); });
}

inline Language::Language(param::hstring const& languageTag) :
    Language(impl::call_factory<Language, Windows::Globalization::ILanguageFactory>([&](auto&& f) { return f.CreateLanguage(languageTag); }))
{}

inline bool Language::IsWellFormed(param::hstring const& languageTag)
{
    return impl::call_factory<Language, Windows::Globalization::ILanguageStatics>([&](auto&& f) { return f.IsWellFormed(languageTag); });
}

inline hstring Language::CurrentInputMethodLanguageTag()
{
    return impl::call_factory<Language, Windows::Globalization::ILanguageStatics>([&](auto&& f) { return f.CurrentInputMethodLanguageTag(); });
}

inline bool Language::TrySetInputMethodLanguageTag(param::hstring const& languageTag)
{
    return impl::call_factory<Language, Windows::Globalization::ILanguageStatics2>([&](auto&& f) { return f.TrySetInputMethodLanguageTag(languageTag); });
}

inline hstring NumeralSystemIdentifiers::Arab()
{
    return impl::call_factory<NumeralSystemIdentifiers, Windows::Globalization::INumeralSystemIdentifiersStatics>([&](auto&& f) { return f.Arab(); });
}

inline hstring NumeralSystemIdentifiers::ArabExt()
{
    return impl::call_factory<NumeralSystemIdentifiers, Windows::Globalization::INumeralSystemIdentifiersStatics>([&](auto&& f) { return f.ArabExt(); });
}

inline hstring NumeralSystemIdentifiers::Bali()
{
    return impl::call_factory<NumeralSystemIdentifiers, Windows::Globalization::INumeralSystemIdentifiersStatics>([&](auto&& f) { return f.Bali(); });
}

inline hstring NumeralSystemIdentifiers::Beng()
{
    return impl::call_factory<NumeralSystemIdentifiers, Windows::Globalization::INumeralSystemIdentifiersStatics>([&](auto&& f) { return f.Beng(); });
}

inline hstring NumeralSystemIdentifiers::Cham()
{
    return impl::call_factory<NumeralSystemIdentifiers, Windows::Globalization::INumeralSystemIdentifiersStatics>([&](auto&& f) { return f.Cham(); });
}

inline hstring NumeralSystemIdentifiers::Deva()
{
    return impl::call_factory<NumeralSystemIdentifiers, Windows::Globalization::INumeralSystemIdentifiersStatics>([&](auto&& f) { return f.Deva(); });
}

inline hstring NumeralSystemIdentifiers::FullWide()
{
    return impl::call_factory<NumeralSystemIdentifiers, Windows::Globalization::INumeralSystemIdentifiersStatics>([&](auto&& f) { return f.FullWide(); });
}

inline hstring NumeralSystemIdentifiers::Gujr()
{
    return impl::call_factory<NumeralSystemIdentifiers, Windows::Globalization::INumeralSystemIdentifiersStatics>([&](auto&& f) { return f.Gujr(); });
}

inline hstring NumeralSystemIdentifiers::Guru()
{
    return impl::call_factory<NumeralSystemIdentifiers, Windows::Globalization::INumeralSystemIdentifiersStatics>([&](auto&& f) { return f.Guru(); });
}

inline hstring NumeralSystemIdentifiers::HaniDec()
{
    return impl::call_factory<NumeralSystemIdentifiers, Windows::Globalization::INumeralSystemIdentifiersStatics>([&](auto&& f) { return f.HaniDec(); });
}

inline hstring NumeralSystemIdentifiers::Java()
{
    return impl::call_factory<NumeralSystemIdentifiers, Windows::Globalization::INumeralSystemIdentifiersStatics>([&](auto&& f) { return f.Java(); });
}

inline hstring NumeralSystemIdentifiers::Kali()
{
    return impl::call_factory<NumeralSystemIdentifiers, Windows::Globalization::INumeralSystemIdentifiersStatics>([&](auto&& f) { return f.Kali(); });
}

inline hstring NumeralSystemIdentifiers::Khmr()
{
    return impl::call_factory<NumeralSystemIdentifiers, Windows::Globalization::INumeralSystemIdentifiersStatics>([&](auto&& f) { return f.Khmr(); });
}

inline hstring NumeralSystemIdentifiers::Knda()
{
    return impl::call_factory<NumeralSystemIdentifiers, Windows::Globalization::INumeralSystemIdentifiersStatics>([&](auto&& f) { return f.Knda(); });
}

inline hstring NumeralSystemIdentifiers::Lana()
{
    return impl::call_factory<NumeralSystemIdentifiers, Windows::Globalization::INumeralSystemIdentifiersStatics>([&](auto&& f) { return f.Lana(); });
}

inline hstring NumeralSystemIdentifiers::LanaTham()
{
    return impl::call_factory<NumeralSystemIdentifiers, Windows::Globalization::INumeralSystemIdentifiersStatics>([&](auto&& f) { return f.LanaTham(); });
}

inline hstring NumeralSystemIdentifiers::Laoo()
{
    return impl::call_factory<NumeralSystemIdentifiers, Windows::Globalization::INumeralSystemIdentifiersStatics>([&](auto&& f) { return f.Laoo(); });
}

inline hstring NumeralSystemIdentifiers::Latn()
{
    return impl::call_factory<NumeralSystemIdentifiers, Windows::Globalization::INumeralSystemIdentifiersStatics>([&](auto&& f) { return f.Latn(); });
}

inline hstring NumeralSystemIdentifiers::Lepc()
{
    return impl::call_factory<NumeralSystemIdentifiers, Windows::Globalization::INumeralSystemIdentifiersStatics>([&](auto&& f) { return f.Lepc(); });
}

inline hstring NumeralSystemIdentifiers::Limb()
{
    return impl::call_factory<NumeralSystemIdentifiers, Windows::Globalization::INumeralSystemIdentifiersStatics>([&](auto&& f) { return f.Limb(); });
}

inline hstring NumeralSystemIdentifiers::Mlym()
{
    return impl::call_factory<NumeralSystemIdentifiers, Windows::Globalization::INumeralSystemIdentifiersStatics>([&](auto&& f) { return f.Mlym(); });
}

inline hstring NumeralSystemIdentifiers::Mong()
{
    return impl::call_factory<NumeralSystemIdentifiers, Windows::Globalization::INumeralSystemIdentifiersStatics>([&](auto&& f) { return f.Mong(); });
}

inline hstring NumeralSystemIdentifiers::Mtei()
{
    return impl::call_factory<NumeralSystemIdentifiers, Windows::Globalization::INumeralSystemIdentifiersStatics>([&](auto&& f) { return f.Mtei(); });
}

inline hstring NumeralSystemIdentifiers::Mymr()
{
    return impl::call_factory<NumeralSystemIdentifiers, Windows::Globalization::INumeralSystemIdentifiersStatics>([&](auto&& f) { return f.Mymr(); });
}

inline hstring NumeralSystemIdentifiers::MymrShan()
{
    return impl::call_factory<NumeralSystemIdentifiers, Windows::Globalization::INumeralSystemIdentifiersStatics>([&](auto&& f) { return f.MymrShan(); });
}

inline hstring NumeralSystemIdentifiers::Nkoo()
{
    return impl::call_factory<NumeralSystemIdentifiers, Windows::Globalization::INumeralSystemIdentifiersStatics>([&](auto&& f) { return f.Nkoo(); });
}

inline hstring NumeralSystemIdentifiers::Olck()
{
    return impl::call_factory<NumeralSystemIdentifiers, Windows::Globalization::INumeralSystemIdentifiersStatics>([&](auto&& f) { return f.Olck(); });
}

inline hstring NumeralSystemIdentifiers::Orya()
{
    return impl::call_factory<NumeralSystemIdentifiers, Windows::Globalization::INumeralSystemIdentifiersStatics>([&](auto&& f) { return f.Orya(); });
}

inline hstring NumeralSystemIdentifiers::Saur()
{
    return impl::call_factory<NumeralSystemIdentifiers, Windows::Globalization::INumeralSystemIdentifiersStatics>([&](auto&& f) { return f.Saur(); });
}

inline hstring NumeralSystemIdentifiers::Sund()
{
    return impl::call_factory<NumeralSystemIdentifiers, Windows::Globalization::INumeralSystemIdentifiersStatics>([&](auto&& f) { return f.Sund(); });
}

inline hstring NumeralSystemIdentifiers::Talu()
{
    return impl::call_factory<NumeralSystemIdentifiers, Windows::Globalization::INumeralSystemIdentifiersStatics>([&](auto&& f) { return f.Talu(); });
}

inline hstring NumeralSystemIdentifiers::TamlDec()
{
    return impl::call_factory<NumeralSystemIdentifiers, Windows::Globalization::INumeralSystemIdentifiersStatics>([&](auto&& f) { return f.TamlDec(); });
}

inline hstring NumeralSystemIdentifiers::Telu()
{
    return impl::call_factory<NumeralSystemIdentifiers, Windows::Globalization::INumeralSystemIdentifiersStatics>([&](auto&& f) { return f.Telu(); });
}

inline hstring NumeralSystemIdentifiers::Thai()
{
    return impl::call_factory<NumeralSystemIdentifiers, Windows::Globalization::INumeralSystemIdentifiersStatics>([&](auto&& f) { return f.Thai(); });
}

inline hstring NumeralSystemIdentifiers::Tibt()
{
    return impl::call_factory<NumeralSystemIdentifiers, Windows::Globalization::INumeralSystemIdentifiersStatics>([&](auto&& f) { return f.Tibt(); });
}

inline hstring NumeralSystemIdentifiers::Vaii()
{
    return impl::call_factory<NumeralSystemIdentifiers, Windows::Globalization::INumeralSystemIdentifiersStatics>([&](auto&& f) { return f.Vaii(); });
}

inline hstring NumeralSystemIdentifiers::Brah()
{
    return impl::call_factory<NumeralSystemIdentifiers, Windows::Globalization::INumeralSystemIdentifiersStatics2>([&](auto&& f) { return f.Brah(); });
}

inline hstring NumeralSystemIdentifiers::Osma()
{
    return impl::call_factory<NumeralSystemIdentifiers, Windows::Globalization::INumeralSystemIdentifiersStatics2>([&](auto&& f) { return f.Osma(); });
}

inline hstring NumeralSystemIdentifiers::MathBold()
{
    return impl::call_factory<NumeralSystemIdentifiers, Windows::Globalization::INumeralSystemIdentifiersStatics2>([&](auto&& f) { return f.MathBold(); });
}

inline hstring NumeralSystemIdentifiers::MathDbl()
{
    return impl::call_factory<NumeralSystemIdentifiers, Windows::Globalization::INumeralSystemIdentifiersStatics2>([&](auto&& f) { return f.MathDbl(); });
}

inline hstring NumeralSystemIdentifiers::MathSans()
{
    return impl::call_factory<NumeralSystemIdentifiers, Windows::Globalization::INumeralSystemIdentifiersStatics2>([&](auto&& f) { return f.MathSans(); });
}

inline hstring NumeralSystemIdentifiers::MathSanb()
{
    return impl::call_factory<NumeralSystemIdentifiers, Windows::Globalization::INumeralSystemIdentifiersStatics2>([&](auto&& f) { return f.MathSanb(); });
}

inline hstring NumeralSystemIdentifiers::MathMono()
{
    return impl::call_factory<NumeralSystemIdentifiers, Windows::Globalization::INumeralSystemIdentifiersStatics2>([&](auto&& f) { return f.MathMono(); });
}

inline hstring NumeralSystemIdentifiers::ZmthBold()
{
    return impl::call_factory<NumeralSystemIdentifiers, Windows::Globalization::INumeralSystemIdentifiersStatics2>([&](auto&& f) { return f.ZmthBold(); });
}

inline hstring NumeralSystemIdentifiers::ZmthDbl()
{
    return impl::call_factory<NumeralSystemIdentifiers, Windows::Globalization::INumeralSystemIdentifiersStatics2>([&](auto&& f) { return f.ZmthDbl(); });
}

inline hstring NumeralSystemIdentifiers::ZmthSans()
{
    return impl::call_factory<NumeralSystemIdentifiers, Windows::Globalization::INumeralSystemIdentifiersStatics2>([&](auto&& f) { return f.ZmthSans(); });
}

inline hstring NumeralSystemIdentifiers::ZmthSanb()
{
    return impl::call_factory<NumeralSystemIdentifiers, Windows::Globalization::INumeralSystemIdentifiersStatics2>([&](auto&& f) { return f.ZmthSanb(); });
}

inline hstring NumeralSystemIdentifiers::ZmthMono()
{
    return impl::call_factory<NumeralSystemIdentifiers, Windows::Globalization::INumeralSystemIdentifiersStatics2>([&](auto&& f) { return f.ZmthMono(); });
}

}

WINRT_EXPORT namespace std {

template<> struct hash<winrt::Windows::Globalization::IApplicationLanguagesStatics> : winrt::impl::hash_base<winrt::Windows::Globalization::IApplicationLanguagesStatics> {};
template<> struct hash<winrt::Windows::Globalization::IApplicationLanguagesStatics2> : winrt::impl::hash_base<winrt::Windows::Globalization::IApplicationLanguagesStatics2> {};
template<> struct hash<winrt::Windows::Globalization::ICalendar> : winrt::impl::hash_base<winrt::Windows::Globalization::ICalendar> {};
template<> struct hash<winrt::Windows::Globalization::ICalendarFactory> : winrt::impl::hash_base<winrt::Windows::Globalization::ICalendarFactory> {};
template<> struct hash<winrt::Windows::Globalization::ICalendarFactory2> : winrt::impl::hash_base<winrt::Windows::Globalization::ICalendarFactory2> {};
template<> struct hash<winrt::Windows::Globalization::ICalendarIdentifiersStatics> : winrt::impl::hash_base<winrt::Windows::Globalization::ICalendarIdentifiersStatics> {};
template<> struct hash<winrt::Windows::Globalization::ICalendarIdentifiersStatics2> : winrt::impl::hash_base<winrt::Windows::Globalization::ICalendarIdentifiersStatics2> {};
template<> struct hash<winrt::Windows::Globalization::ICalendarIdentifiersStatics3> : winrt::impl::hash_base<winrt::Windows::Globalization::ICalendarIdentifiersStatics3> {};
template<> struct hash<winrt::Windows::Globalization::IClockIdentifiersStatics> : winrt::impl::hash_base<winrt::Windows::Globalization::IClockIdentifiersStatics> {};
template<> struct hash<winrt::Windows::Globalization::ICurrencyAmount> : winrt::impl::hash_base<winrt::Windows::Globalization::ICurrencyAmount> {};
template<> struct hash<winrt::Windows::Globalization::ICurrencyAmountFactory> : winrt::impl::hash_base<winrt::Windows::Globalization::ICurrencyAmountFactory> {};
template<> struct hash<winrt::Windows::Globalization::ICurrencyIdentifiersStatics> : winrt::impl::hash_base<winrt::Windows::Globalization::ICurrencyIdentifiersStatics> {};
template<> struct hash<winrt::Windows::Globalization::ICurrencyIdentifiersStatics2> : winrt::impl::hash_base<winrt::Windows::Globalization::ICurrencyIdentifiersStatics2> {};
template<> struct hash<winrt::Windows::Globalization::ICurrencyIdentifiersStatics3> : winrt::impl::hash_base<winrt::Windows::Globalization::ICurrencyIdentifiersStatics3> {};
template<> struct hash<winrt::Windows::Globalization::IGeographicRegion> : winrt::impl::hash_base<winrt::Windows::Globalization::IGeographicRegion> {};
template<> struct hash<winrt::Windows::Globalization::IGeographicRegionFactory> : winrt::impl::hash_base<winrt::Windows::Globalization::IGeographicRegionFactory> {};
template<> struct hash<winrt::Windows::Globalization::IGeographicRegionStatics> : winrt::impl::hash_base<winrt::Windows::Globalization::IGeographicRegionStatics> {};
template<> struct hash<winrt::Windows::Globalization::IJapanesePhoneme> : winrt::impl::hash_base<winrt::Windows::Globalization::IJapanesePhoneme> {};
template<> struct hash<winrt::Windows::Globalization::IJapanesePhoneticAnalyzerStatics> : winrt::impl::hash_base<winrt::Windows::Globalization::IJapanesePhoneticAnalyzerStatics> {};
template<> struct hash<winrt::Windows::Globalization::ILanguage> : winrt::impl::hash_base<winrt::Windows::Globalization::ILanguage> {};
template<> struct hash<winrt::Windows::Globalization::ILanguage2> : winrt::impl::hash_base<winrt::Windows::Globalization::ILanguage2> {};
template<> struct hash<winrt::Windows::Globalization::ILanguageExtensionSubtags> : winrt::impl::hash_base<winrt::Windows::Globalization::ILanguageExtensionSubtags> {};
template<> struct hash<winrt::Windows::Globalization::ILanguageFactory> : winrt::impl::hash_base<winrt::Windows::Globalization::ILanguageFactory> {};
template<> struct hash<winrt::Windows::Globalization::ILanguageStatics> : winrt::impl::hash_base<winrt::Windows::Globalization::ILanguageStatics> {};
template<> struct hash<winrt::Windows::Globalization::ILanguageStatics2> : winrt::impl::hash_base<winrt::Windows::Globalization::ILanguageStatics2> {};
template<> struct hash<winrt::Windows::Globalization::INumeralSystemIdentifiersStatics> : winrt::impl::hash_base<winrt::Windows::Globalization::INumeralSystemIdentifiersStatics> {};
template<> struct hash<winrt::Windows::Globalization::INumeralSystemIdentifiersStatics2> : winrt::impl::hash_base<winrt::Windows::Globalization::INumeralSystemIdentifiersStatics2> {};
template<> struct hash<winrt::Windows::Globalization::ITimeZoneOnCalendar> : winrt::impl::hash_base<winrt::Windows::Globalization::ITimeZoneOnCalendar> {};
template<> struct hash<winrt::Windows::Globalization::ApplicationLanguages> : winrt::impl::hash_base<winrt::Windows::Globalization::ApplicationLanguages> {};
template<> struct hash<winrt::Windows::Globalization::Calendar> : winrt::impl::hash_base<winrt::Windows::Globalization::Calendar> {};
template<> struct hash<winrt::Windows::Globalization::CalendarIdentifiers> : winrt::impl::hash_base<winrt::Windows::Globalization::CalendarIdentifiers> {};
template<> struct hash<winrt::Windows::Globalization::ClockIdentifiers> : winrt::impl::hash_base<winrt::Windows::Globalization::ClockIdentifiers> {};
template<> struct hash<winrt::Windows::Globalization::CurrencyAmount> : winrt::impl::hash_base<winrt::Windows::Globalization::CurrencyAmount> {};
template<> struct hash<winrt::Windows::Globalization::CurrencyIdentifiers> : winrt::impl::hash_base<winrt::Windows::Globalization::CurrencyIdentifiers> {};
template<> struct hash<winrt::Windows::Globalization::GeographicRegion> : winrt::impl::hash_base<winrt::Windows::Globalization::GeographicRegion> {};
template<> struct hash<winrt::Windows::Globalization::JapanesePhoneme> : winrt::impl::hash_base<winrt::Windows::Globalization::JapanesePhoneme> {};
template<> struct hash<winrt::Windows::Globalization::JapanesePhoneticAnalyzer> : winrt::impl::hash_base<winrt::Windows::Globalization::JapanesePhoneticAnalyzer> {};
template<> struct hash<winrt::Windows::Globalization::Language> : winrt::impl::hash_base<winrt::Windows::Globalization::Language> {};
template<> struct hash<winrt::Windows::Globalization::NumeralSystemIdentifiers> : winrt::impl::hash_base<winrt::Windows::Globalization::NumeralSystemIdentifiers> {};

}
