// C++/WinRT v1.0.190111.3

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#pragma once

#include "winrt/base.h"

#include "winrt/Windows.Foundation.h"
#include "winrt/Windows.Foundation.Collections.h"
#include "winrt/impl/Windows.Foundation.2.h"
#include "winrt/impl/Windows.Globalization.PhoneNumberFormatting.2.h"
#include "winrt/Windows.Globalization.h"

namespace winrt::impl {

template <typename D> hstring consume_Windows_Globalization_PhoneNumberFormatting_IPhoneNumberFormatter<D>::Format(Windows::Globalization::PhoneNumberFormatting::PhoneNumberInfo const& number) const
{
    hstring result{};
    check_hresult(WINRT_SHIM(Windows::Globalization::PhoneNumberFormatting::IPhoneNumberFormatter)->Format(get_abi(number), put_abi(result)));
    return result;
}

template <typename D> hstring consume_Windows_Globalization_PhoneNumberFormatting_IPhoneNumberFormatter<D>::Format(Windows::Globalization::PhoneNumberFormatting::PhoneNumberInfo const& number, Windows::Globalization::PhoneNumberFormatting::PhoneNumberFormat const& numberFormat) const
{
    hstring result{};
    check_hresult(WINRT_SHIM(Windows::Globalization::PhoneNumberFormatting::IPhoneNumberFormatter)->FormatWithOutputFormat(get_abi(number), get_abi(numberFormat), put_abi(result)));
    return result;
}

template <typename D> hstring consume_Windows_Globalization_PhoneNumberFormatting_IPhoneNumberFormatter<D>::FormatPartialString(param::hstring const& number) const
{
    hstring result{};
    check_hresult(WINRT_SHIM(Windows::Globalization::PhoneNumberFormatting::IPhoneNumberFormatter)->FormatPartialString(get_abi(number), put_abi(result)));
    return result;
}

template <typename D> hstring consume_Windows_Globalization_PhoneNumberFormatting_IPhoneNumberFormatter<D>::FormatString(param::hstring const& number) const
{
    hstring result{};
    check_hresult(WINRT_SHIM(Windows::Globalization::PhoneNumberFormatting::IPhoneNumberFormatter)->FormatString(get_abi(number), put_abi(result)));
    return result;
}

template <typename D> hstring consume_Windows_Globalization_PhoneNumberFormatting_IPhoneNumberFormatter<D>::FormatStringWithLeftToRightMarkers(param::hstring const& number) const
{
    hstring result{};
    check_hresult(WINRT_SHIM(Windows::Globalization::PhoneNumberFormatting::IPhoneNumberFormatter)->FormatStringWithLeftToRightMarkers(get_abi(number), put_abi(result)));
    return result;
}

template <typename D> void consume_Windows_Globalization_PhoneNumberFormatting_IPhoneNumberFormatterStatics<D>::TryCreate(param::hstring const& regionCode, Windows::Globalization::PhoneNumberFormatting::PhoneNumberFormatter& phoneNumber) const
{
    check_hresult(WINRT_SHIM(Windows::Globalization::PhoneNumberFormatting::IPhoneNumberFormatterStatics)->TryCreate(get_abi(regionCode), put_abi(phoneNumber)));
}

template <typename D> int32_t consume_Windows_Globalization_PhoneNumberFormatting_IPhoneNumberFormatterStatics<D>::GetCountryCodeForRegion(param::hstring const& regionCode) const
{
    int32_t result{};
    check_hresult(WINRT_SHIM(Windows::Globalization::PhoneNumberFormatting::IPhoneNumberFormatterStatics)->GetCountryCodeForRegion(get_abi(regionCode), &result));
    return result;
}

template <typename D> hstring consume_Windows_Globalization_PhoneNumberFormatting_IPhoneNumberFormatterStatics<D>::GetNationalDirectDialingPrefixForRegion(param::hstring const& regionCode, bool stripNonDigit) const
{
    hstring result{};
    check_hresult(WINRT_SHIM(Windows::Globalization::PhoneNumberFormatting::IPhoneNumberFormatterStatics)->GetNationalDirectDialingPrefixForRegion(get_abi(regionCode), stripNonDigit, put_abi(result)));
    return result;
}

template <typename D> hstring consume_Windows_Globalization_PhoneNumberFormatting_IPhoneNumberFormatterStatics<D>::WrapWithLeftToRightMarkers(param::hstring const& number) const
{
    hstring result{};
    check_hresult(WINRT_SHIM(Windows::Globalization::PhoneNumberFormatting::IPhoneNumberFormatterStatics)->WrapWithLeftToRightMarkers(get_abi(number), put_abi(result)));
    return result;
}

template <typename D> int32_t consume_Windows_Globalization_PhoneNumberFormatting_IPhoneNumberInfo<D>::CountryCode() const
{
    int32_t value{};
    check_hresult(WINRT_SHIM(Windows::Globalization::PhoneNumberFormatting::IPhoneNumberInfo)->get_CountryCode(&value));
    return value;
}

template <typename D> hstring consume_Windows_Globalization_PhoneNumberFormatting_IPhoneNumberInfo<D>::PhoneNumber() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Globalization::PhoneNumberFormatting::IPhoneNumberInfo)->get_PhoneNumber(put_abi(value)));
    return value;
}

template <typename D> int32_t consume_Windows_Globalization_PhoneNumberFormatting_IPhoneNumberInfo<D>::GetLengthOfGeographicalAreaCode() const
{
    int32_t result{};
    check_hresult(WINRT_SHIM(Windows::Globalization::PhoneNumberFormatting::IPhoneNumberInfo)->GetLengthOfGeographicalAreaCode(&result));
    return result;
}

template <typename D> hstring consume_Windows_Globalization_PhoneNumberFormatting_IPhoneNumberInfo<D>::GetNationalSignificantNumber() const
{
    hstring result{};
    check_hresult(WINRT_SHIM(Windows::Globalization::PhoneNumberFormatting::IPhoneNumberInfo)->GetNationalSignificantNumber(put_abi(result)));
    return result;
}

template <typename D> int32_t consume_Windows_Globalization_PhoneNumberFormatting_IPhoneNumberInfo<D>::GetLengthOfNationalDestinationCode() const
{
    int32_t result{};
    check_hresult(WINRT_SHIM(Windows::Globalization::PhoneNumberFormatting::IPhoneNumberInfo)->GetLengthOfNationalDestinationCode(&result));
    return result;
}

template <typename D> Windows::Globalization::PhoneNumberFormatting::PredictedPhoneNumberKind consume_Windows_Globalization_PhoneNumberFormatting_IPhoneNumberInfo<D>::PredictNumberKind() const
{
    Windows::Globalization::PhoneNumberFormatting::PredictedPhoneNumberKind result{};
    check_hresult(WINRT_SHIM(Windows::Globalization::PhoneNumberFormatting::IPhoneNumberInfo)->PredictNumberKind(put_abi(result)));
    return result;
}

template <typename D> hstring consume_Windows_Globalization_PhoneNumberFormatting_IPhoneNumberInfo<D>::GetGeographicRegionCode() const
{
    hstring result{};
    check_hresult(WINRT_SHIM(Windows::Globalization::PhoneNumberFormatting::IPhoneNumberInfo)->GetGeographicRegionCode(put_abi(result)));
    return result;
}

template <typename D> Windows::Globalization::PhoneNumberFormatting::PhoneNumberMatchResult consume_Windows_Globalization_PhoneNumberFormatting_IPhoneNumberInfo<D>::CheckNumberMatch(Windows::Globalization::PhoneNumberFormatting::PhoneNumberInfo const& otherNumber) const
{
    Windows::Globalization::PhoneNumberFormatting::PhoneNumberMatchResult result{};
    check_hresult(WINRT_SHIM(Windows::Globalization::PhoneNumberFormatting::IPhoneNumberInfo)->CheckNumberMatch(get_abi(otherNumber), put_abi(result)));
    return result;
}

template <typename D> Windows::Globalization::PhoneNumberFormatting::PhoneNumberInfo consume_Windows_Globalization_PhoneNumberFormatting_IPhoneNumberInfoFactory<D>::Create(param::hstring const& number) const
{
    Windows::Globalization::PhoneNumberFormatting::PhoneNumberInfo result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Globalization::PhoneNumberFormatting::IPhoneNumberInfoFactory)->Create(get_abi(number), put_abi(result)));
    return result;
}

template <typename D> Windows::Globalization::PhoneNumberFormatting::PhoneNumberParseResult consume_Windows_Globalization_PhoneNumberFormatting_IPhoneNumberInfoStatics<D>::TryParse(param::hstring const& input, Windows::Globalization::PhoneNumberFormatting::PhoneNumberInfo& phoneNumber) const
{
    Windows::Globalization::PhoneNumberFormatting::PhoneNumberParseResult result{};
    check_hresult(WINRT_SHIM(Windows::Globalization::PhoneNumberFormatting::IPhoneNumberInfoStatics)->TryParse(get_abi(input), put_abi(phoneNumber), put_abi(result)));
    return result;
}

template <typename D> Windows::Globalization::PhoneNumberFormatting::PhoneNumberParseResult consume_Windows_Globalization_PhoneNumberFormatting_IPhoneNumberInfoStatics<D>::TryParse(param::hstring const& input, param::hstring const& regionCode, Windows::Globalization::PhoneNumberFormatting::PhoneNumberInfo& phoneNumber) const
{
    Windows::Globalization::PhoneNumberFormatting::PhoneNumberParseResult result{};
    check_hresult(WINRT_SHIM(Windows::Globalization::PhoneNumberFormatting::IPhoneNumberInfoStatics)->TryParseWithRegion(get_abi(input), get_abi(regionCode), put_abi(phoneNumber), put_abi(result)));
    return result;
}

template <typename D>
struct produce<D, Windows::Globalization::PhoneNumberFormatting::IPhoneNumberFormatter> : produce_base<D, Windows::Globalization::PhoneNumberFormatting::IPhoneNumberFormatter>
{
    int32_t WINRT_CALL Format(void* number, void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Format, WINRT_WRAP(hstring), Windows::Globalization::PhoneNumberFormatting::PhoneNumberInfo const&);
            *result = detach_from<hstring>(this->shim().Format(*reinterpret_cast<Windows::Globalization::PhoneNumberFormatting::PhoneNumberInfo const*>(&number)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL FormatWithOutputFormat(void* number, Windows::Globalization::PhoneNumberFormatting::PhoneNumberFormat numberFormat, void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Format, WINRT_WRAP(hstring), Windows::Globalization::PhoneNumberFormatting::PhoneNumberInfo const&, Windows::Globalization::PhoneNumberFormatting::PhoneNumberFormat const&);
            *result = detach_from<hstring>(this->shim().Format(*reinterpret_cast<Windows::Globalization::PhoneNumberFormatting::PhoneNumberInfo const*>(&number), *reinterpret_cast<Windows::Globalization::PhoneNumberFormatting::PhoneNumberFormat const*>(&numberFormat)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL FormatPartialString(void* number, void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(FormatPartialString, WINRT_WRAP(hstring), hstring const&);
            *result = detach_from<hstring>(this->shim().FormatPartialString(*reinterpret_cast<hstring const*>(&number)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL FormatString(void* number, void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(FormatString, WINRT_WRAP(hstring), hstring const&);
            *result = detach_from<hstring>(this->shim().FormatString(*reinterpret_cast<hstring const*>(&number)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL FormatStringWithLeftToRightMarkers(void* number, void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(FormatStringWithLeftToRightMarkers, WINRT_WRAP(hstring), hstring const&);
            *result = detach_from<hstring>(this->shim().FormatStringWithLeftToRightMarkers(*reinterpret_cast<hstring const*>(&number)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Globalization::PhoneNumberFormatting::IPhoneNumberFormatterStatics> : produce_base<D, Windows::Globalization::PhoneNumberFormatting::IPhoneNumberFormatterStatics>
{
    int32_t WINRT_CALL TryCreate(void* regionCode, void** phoneNumber) noexcept final
    {
        try
        {
            *phoneNumber = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(TryCreate, WINRT_WRAP(void), hstring const&, Windows::Globalization::PhoneNumberFormatting::PhoneNumberFormatter&);
            this->shim().TryCreate(*reinterpret_cast<hstring const*>(&regionCode), *reinterpret_cast<Windows::Globalization::PhoneNumberFormatting::PhoneNumberFormatter*>(phoneNumber));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL GetCountryCodeForRegion(void* regionCode, int32_t* result) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetCountryCodeForRegion, WINRT_WRAP(int32_t), hstring const&);
            *result = detach_from<int32_t>(this->shim().GetCountryCodeForRegion(*reinterpret_cast<hstring const*>(&regionCode)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL GetNationalDirectDialingPrefixForRegion(void* regionCode, bool stripNonDigit, void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetNationalDirectDialingPrefixForRegion, WINRT_WRAP(hstring), hstring const&, bool);
            *result = detach_from<hstring>(this->shim().GetNationalDirectDialingPrefixForRegion(*reinterpret_cast<hstring const*>(&regionCode), stripNonDigit));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL WrapWithLeftToRightMarkers(void* number, void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(WrapWithLeftToRightMarkers, WINRT_WRAP(hstring), hstring const&);
            *result = detach_from<hstring>(this->shim().WrapWithLeftToRightMarkers(*reinterpret_cast<hstring const*>(&number)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Globalization::PhoneNumberFormatting::IPhoneNumberInfo> : produce_base<D, Windows::Globalization::PhoneNumberFormatting::IPhoneNumberInfo>
{
    int32_t WINRT_CALL get_CountryCode(int32_t* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CountryCode, WINRT_WRAP(int32_t));
            *value = detach_from<int32_t>(this->shim().CountryCode());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_PhoneNumber(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(PhoneNumber, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().PhoneNumber());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL GetLengthOfGeographicalAreaCode(int32_t* result) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetLengthOfGeographicalAreaCode, WINRT_WRAP(int32_t));
            *result = detach_from<int32_t>(this->shim().GetLengthOfGeographicalAreaCode());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL GetNationalSignificantNumber(void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetNationalSignificantNumber, WINRT_WRAP(hstring));
            *result = detach_from<hstring>(this->shim().GetNationalSignificantNumber());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL GetLengthOfNationalDestinationCode(int32_t* result) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetLengthOfNationalDestinationCode, WINRT_WRAP(int32_t));
            *result = detach_from<int32_t>(this->shim().GetLengthOfNationalDestinationCode());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL PredictNumberKind(Windows::Globalization::PhoneNumberFormatting::PredictedPhoneNumberKind* result) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(PredictNumberKind, WINRT_WRAP(Windows::Globalization::PhoneNumberFormatting::PredictedPhoneNumberKind));
            *result = detach_from<Windows::Globalization::PhoneNumberFormatting::PredictedPhoneNumberKind>(this->shim().PredictNumberKind());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL GetGeographicRegionCode(void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetGeographicRegionCode, WINRT_WRAP(hstring));
            *result = detach_from<hstring>(this->shim().GetGeographicRegionCode());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL CheckNumberMatch(void* otherNumber, Windows::Globalization::PhoneNumberFormatting::PhoneNumberMatchResult* result) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CheckNumberMatch, WINRT_WRAP(Windows::Globalization::PhoneNumberFormatting::PhoneNumberMatchResult), Windows::Globalization::PhoneNumberFormatting::PhoneNumberInfo const&);
            *result = detach_from<Windows::Globalization::PhoneNumberFormatting::PhoneNumberMatchResult>(this->shim().CheckNumberMatch(*reinterpret_cast<Windows::Globalization::PhoneNumberFormatting::PhoneNumberInfo const*>(&otherNumber)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Globalization::PhoneNumberFormatting::IPhoneNumberInfoFactory> : produce_base<D, Windows::Globalization::PhoneNumberFormatting::IPhoneNumberInfoFactory>
{
    int32_t WINRT_CALL Create(void* number, void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Create, WINRT_WRAP(Windows::Globalization::PhoneNumberFormatting::PhoneNumberInfo), hstring const&);
            *result = detach_from<Windows::Globalization::PhoneNumberFormatting::PhoneNumberInfo>(this->shim().Create(*reinterpret_cast<hstring const*>(&number)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Globalization::PhoneNumberFormatting::IPhoneNumberInfoStatics> : produce_base<D, Windows::Globalization::PhoneNumberFormatting::IPhoneNumberInfoStatics>
{
    int32_t WINRT_CALL TryParse(void* input, void** phoneNumber, Windows::Globalization::PhoneNumberFormatting::PhoneNumberParseResult* result) noexcept final
    {
        try
        {
            *phoneNumber = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(TryParse, WINRT_WRAP(Windows::Globalization::PhoneNumberFormatting::PhoneNumberParseResult), hstring const&, Windows::Globalization::PhoneNumberFormatting::PhoneNumberInfo&);
            *result = detach_from<Windows::Globalization::PhoneNumberFormatting::PhoneNumberParseResult>(this->shim().TryParse(*reinterpret_cast<hstring const*>(&input), *reinterpret_cast<Windows::Globalization::PhoneNumberFormatting::PhoneNumberInfo*>(phoneNumber)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL TryParseWithRegion(void* input, void* regionCode, void** phoneNumber, Windows::Globalization::PhoneNumberFormatting::PhoneNumberParseResult* result) noexcept final
    {
        try
        {
            *phoneNumber = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(TryParse, WINRT_WRAP(Windows::Globalization::PhoneNumberFormatting::PhoneNumberParseResult), hstring const&, hstring const&, Windows::Globalization::PhoneNumberFormatting::PhoneNumberInfo&);
            *result = detach_from<Windows::Globalization::PhoneNumberFormatting::PhoneNumberParseResult>(this->shim().TryParse(*reinterpret_cast<hstring const*>(&input), *reinterpret_cast<hstring const*>(&regionCode), *reinterpret_cast<Windows::Globalization::PhoneNumberFormatting::PhoneNumberInfo*>(phoneNumber)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

}

WINRT_EXPORT namespace winrt::Windows::Globalization::PhoneNumberFormatting {

inline PhoneNumberFormatter::PhoneNumberFormatter() :
    PhoneNumberFormatter(impl::call_factory<PhoneNumberFormatter>([](auto&& f) { return f.template ActivateInstance<PhoneNumberFormatter>(); }))
{}

inline void PhoneNumberFormatter::TryCreate(param::hstring const& regionCode, Windows::Globalization::PhoneNumberFormatting::PhoneNumberFormatter& phoneNumber)
{
    impl::call_factory<PhoneNumberFormatter, Windows::Globalization::PhoneNumberFormatting::IPhoneNumberFormatterStatics>([&](auto&& f) { return f.TryCreate(regionCode, phoneNumber); });
}

inline int32_t PhoneNumberFormatter::GetCountryCodeForRegion(param::hstring const& regionCode)
{
    return impl::call_factory<PhoneNumberFormatter, Windows::Globalization::PhoneNumberFormatting::IPhoneNumberFormatterStatics>([&](auto&& f) { return f.GetCountryCodeForRegion(regionCode); });
}

inline hstring PhoneNumberFormatter::GetNationalDirectDialingPrefixForRegion(param::hstring const& regionCode, bool stripNonDigit)
{
    return impl::call_factory<PhoneNumberFormatter, Windows::Globalization::PhoneNumberFormatting::IPhoneNumberFormatterStatics>([&](auto&& f) { return f.GetNationalDirectDialingPrefixForRegion(regionCode, stripNonDigit); });
}

inline hstring PhoneNumberFormatter::WrapWithLeftToRightMarkers(param::hstring const& number)
{
    return impl::call_factory<PhoneNumberFormatter, Windows::Globalization::PhoneNumberFormatting::IPhoneNumberFormatterStatics>([&](auto&& f) { return f.WrapWithLeftToRightMarkers(number); });
}

inline PhoneNumberInfo::PhoneNumberInfo(param::hstring const& number) :
    PhoneNumberInfo(impl::call_factory<PhoneNumberInfo, Windows::Globalization::PhoneNumberFormatting::IPhoneNumberInfoFactory>([&](auto&& f) { return f.Create(number); }))
{}

inline Windows::Globalization::PhoneNumberFormatting::PhoneNumberParseResult PhoneNumberInfo::TryParse(param::hstring const& input, Windows::Globalization::PhoneNumberFormatting::PhoneNumberInfo& phoneNumber)
{
    return impl::call_factory<PhoneNumberInfo, Windows::Globalization::PhoneNumberFormatting::IPhoneNumberInfoStatics>([&](auto&& f) { return f.TryParse(input, phoneNumber); });
}

inline Windows::Globalization::PhoneNumberFormatting::PhoneNumberParseResult PhoneNumberInfo::TryParse(param::hstring const& input, param::hstring const& regionCode, Windows::Globalization::PhoneNumberFormatting::PhoneNumberInfo& phoneNumber)
{
    return impl::call_factory<PhoneNumberInfo, Windows::Globalization::PhoneNumberFormatting::IPhoneNumberInfoStatics>([&](auto&& f) { return f.TryParse(input, regionCode, phoneNumber); });
}

}

WINRT_EXPORT namespace std {

template<> struct hash<winrt::Windows::Globalization::PhoneNumberFormatting::IPhoneNumberFormatter> : winrt::impl::hash_base<winrt::Windows::Globalization::PhoneNumberFormatting::IPhoneNumberFormatter> {};
template<> struct hash<winrt::Windows::Globalization::PhoneNumberFormatting::IPhoneNumberFormatterStatics> : winrt::impl::hash_base<winrt::Windows::Globalization::PhoneNumberFormatting::IPhoneNumberFormatterStatics> {};
template<> struct hash<winrt::Windows::Globalization::PhoneNumberFormatting::IPhoneNumberInfo> : winrt::impl::hash_base<winrt::Windows::Globalization::PhoneNumberFormatting::IPhoneNumberInfo> {};
template<> struct hash<winrt::Windows::Globalization::PhoneNumberFormatting::IPhoneNumberInfoFactory> : winrt::impl::hash_base<winrt::Windows::Globalization::PhoneNumberFormatting::IPhoneNumberInfoFactory> {};
template<> struct hash<winrt::Windows::Globalization::PhoneNumberFormatting::IPhoneNumberInfoStatics> : winrt::impl::hash_base<winrt::Windows::Globalization::PhoneNumberFormatting::IPhoneNumberInfoStatics> {};
template<> struct hash<winrt::Windows::Globalization::PhoneNumberFormatting::PhoneNumberFormatter> : winrt::impl::hash_base<winrt::Windows::Globalization::PhoneNumberFormatting::PhoneNumberFormatter> {};
template<> struct hash<winrt::Windows::Globalization::PhoneNumberFormatting::PhoneNumberInfo> : winrt::impl::hash_base<winrt::Windows::Globalization::PhoneNumberFormatting::PhoneNumberInfo> {};

}
