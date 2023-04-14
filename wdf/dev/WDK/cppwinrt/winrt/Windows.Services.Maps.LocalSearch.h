// C++/WinRT v1.0.190111.3

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#pragma once

#include "winrt/base.h"

#include "winrt/Windows.Foundation.h"
#include "winrt/Windows.Foundation.Collections.h"
#include "winrt/impl/Windows.Devices.Geolocation.2.h"
#include "winrt/impl/Windows.Globalization.2.h"
#include "winrt/impl/Windows.Services.Maps.2.h"
#include "winrt/impl/Windows.Services.Maps.LocalSearch.2.h"
#include "winrt/Windows.Services.Maps.h"

namespace winrt::impl {

template <typename D> hstring consume_Windows_Services_Maps_LocalSearch_ILocalCategoriesStatics<D>::BankAndCreditUnions() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Services::Maps::LocalSearch::ILocalCategoriesStatics)->get_BankAndCreditUnions(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_Services_Maps_LocalSearch_ILocalCategoriesStatics<D>::EatDrink() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Services::Maps::LocalSearch::ILocalCategoriesStatics)->get_EatDrink(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_Services_Maps_LocalSearch_ILocalCategoriesStatics<D>::Hospitals() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Services::Maps::LocalSearch::ILocalCategoriesStatics)->get_Hospitals(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_Services_Maps_LocalSearch_ILocalCategoriesStatics<D>::HotelsAndMotels() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Services::Maps::LocalSearch::ILocalCategoriesStatics)->get_HotelsAndMotels(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_Services_Maps_LocalSearch_ILocalCategoriesStatics<D>::All() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Services::Maps::LocalSearch::ILocalCategoriesStatics)->get_All(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_Services_Maps_LocalSearch_ILocalCategoriesStatics<D>::Parking() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Services::Maps::LocalSearch::ILocalCategoriesStatics)->get_Parking(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_Services_Maps_LocalSearch_ILocalCategoriesStatics<D>::SeeDo() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Services::Maps::LocalSearch::ILocalCategoriesStatics)->get_SeeDo(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_Services_Maps_LocalSearch_ILocalCategoriesStatics<D>::Shop() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Services::Maps::LocalSearch::ILocalCategoriesStatics)->get_Shop(put_abi(value)));
    return value;
}

template <typename D> Windows::Services::Maps::MapAddress consume_Windows_Services_Maps_LocalSearch_ILocalLocation<D>::Address() const
{
    Windows::Services::Maps::MapAddress value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Services::Maps::LocalSearch::ILocalLocation)->get_Address(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_Services_Maps_LocalSearch_ILocalLocation<D>::Identifier() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Services::Maps::LocalSearch::ILocalLocation)->get_Identifier(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_Services_Maps_LocalSearch_ILocalLocation<D>::Description() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Services::Maps::LocalSearch::ILocalLocation)->get_Description(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_Services_Maps_LocalSearch_ILocalLocation<D>::DisplayName() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Services::Maps::LocalSearch::ILocalLocation)->get_DisplayName(put_abi(value)));
    return value;
}

template <typename D> Windows::Devices::Geolocation::Geopoint consume_Windows_Services_Maps_LocalSearch_ILocalLocation<D>::Point() const
{
    Windows::Devices::Geolocation::Geopoint value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Services::Maps::LocalSearch::ILocalLocation)->get_Point(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_Services_Maps_LocalSearch_ILocalLocation<D>::PhoneNumber() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Services::Maps::LocalSearch::ILocalLocation)->get_PhoneNumber(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_Services_Maps_LocalSearch_ILocalLocation<D>::DataAttribution() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Services::Maps::LocalSearch::ILocalLocation)->get_DataAttribution(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_Services_Maps_LocalSearch_ILocalLocation2<D>::Category() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Services::Maps::LocalSearch::ILocalLocation2)->get_Category(put_abi(value)));
    return value;
}

template <typename D> Windows::Services::Maps::LocalSearch::LocalLocationRatingInfo consume_Windows_Services_Maps_LocalSearch_ILocalLocation2<D>::RatingInfo() const
{
    Windows::Services::Maps::LocalSearch::LocalLocationRatingInfo value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Services::Maps::LocalSearch::ILocalLocation2)->get_RatingInfo(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::Collections::IVectorView<Windows::Services::Maps::LocalSearch::LocalLocationHoursOfOperationItem> consume_Windows_Services_Maps_LocalSearch_ILocalLocation2<D>::HoursOfOperation() const
{
    Windows::Foundation::Collections::IVectorView<Windows::Services::Maps::LocalSearch::LocalLocationHoursOfOperationItem> value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Services::Maps::LocalSearch::ILocalLocation2)->get_HoursOfOperation(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::Collections::IVectorView<Windows::Services::Maps::LocalSearch::LocalLocation> consume_Windows_Services_Maps_LocalSearch_ILocalLocationFinderResult<D>::LocalLocations() const
{
    Windows::Foundation::Collections::IVectorView<Windows::Services::Maps::LocalSearch::LocalLocation> value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Services::Maps::LocalSearch::ILocalLocationFinderResult)->get_LocalLocations(put_abi(value)));
    return value;
}

template <typename D> Windows::Services::Maps::LocalSearch::LocalLocationFinderStatus consume_Windows_Services_Maps_LocalSearch_ILocalLocationFinderResult<D>::Status() const
{
    Windows::Services::Maps::LocalSearch::LocalLocationFinderStatus value{};
    check_hresult(WINRT_SHIM(Windows::Services::Maps::LocalSearch::ILocalLocationFinderResult)->get_Status(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::IAsyncOperation<Windows::Services::Maps::LocalSearch::LocalLocationFinderResult> consume_Windows_Services_Maps_LocalSearch_ILocalLocationFinderStatics<D>::FindLocalLocationsAsync(param::hstring const& searchTerm, Windows::Devices::Geolocation::Geocircle const& searchArea, param::hstring const& localCategory, uint32_t maxResults) const
{
    Windows::Foundation::IAsyncOperation<Windows::Services::Maps::LocalSearch::LocalLocationFinderResult> result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Services::Maps::LocalSearch::ILocalLocationFinderStatics)->FindLocalLocationsAsync(get_abi(searchTerm), get_abi(searchArea), get_abi(localCategory), maxResults, put_abi(result)));
    return result;
}

template <typename D> Windows::Globalization::DayOfWeek consume_Windows_Services_Maps_LocalSearch_ILocalLocationHoursOfOperationItem<D>::Day() const
{
    Windows::Globalization::DayOfWeek value{};
    check_hresult(WINRT_SHIM(Windows::Services::Maps::LocalSearch::ILocalLocationHoursOfOperationItem)->get_Day(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::TimeSpan consume_Windows_Services_Maps_LocalSearch_ILocalLocationHoursOfOperationItem<D>::Start() const
{
    Windows::Foundation::TimeSpan value{};
    check_hresult(WINRT_SHIM(Windows::Services::Maps::LocalSearch::ILocalLocationHoursOfOperationItem)->get_Start(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::TimeSpan consume_Windows_Services_Maps_LocalSearch_ILocalLocationHoursOfOperationItem<D>::Span() const
{
    Windows::Foundation::TimeSpan value{};
    check_hresult(WINRT_SHIM(Windows::Services::Maps::LocalSearch::ILocalLocationHoursOfOperationItem)->get_Span(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::IReference<double> consume_Windows_Services_Maps_LocalSearch_ILocalLocationRatingInfo<D>::AggregateRating() const
{
    Windows::Foundation::IReference<double> value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Services::Maps::LocalSearch::ILocalLocationRatingInfo)->get_AggregateRating(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::IReference<int32_t> consume_Windows_Services_Maps_LocalSearch_ILocalLocationRatingInfo<D>::RatingCount() const
{
    Windows::Foundation::IReference<int32_t> value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Services::Maps::LocalSearch::ILocalLocationRatingInfo)->get_RatingCount(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_Services_Maps_LocalSearch_ILocalLocationRatingInfo<D>::ProviderIdentifier() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Services::Maps::LocalSearch::ILocalLocationRatingInfo)->get_ProviderIdentifier(put_abi(value)));
    return value;
}

template <typename D> Windows::Services::Maps::PlaceInfo consume_Windows_Services_Maps_LocalSearch_IPlaceInfoHelperStatics<D>::CreateFromLocalLocation(Windows::Services::Maps::LocalSearch::LocalLocation const& location) const
{
    Windows::Services::Maps::PlaceInfo resultValue{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Services::Maps::LocalSearch::IPlaceInfoHelperStatics)->CreateFromLocalLocation(get_abi(location), put_abi(resultValue)));
    return resultValue;
}

template <typename D>
struct produce<D, Windows::Services::Maps::LocalSearch::ILocalCategoriesStatics> : produce_base<D, Windows::Services::Maps::LocalSearch::ILocalCategoriesStatics>
{
    int32_t WINRT_CALL get_BankAndCreditUnions(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(BankAndCreditUnions, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().BankAndCreditUnions());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_EatDrink(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(EatDrink, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().EatDrink());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Hospitals(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Hospitals, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().Hospitals());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_HotelsAndMotels(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(HotelsAndMotels, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().HotelsAndMotels());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_All(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(All, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().All());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Parking(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Parking, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().Parking());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_SeeDo(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SeeDo, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().SeeDo());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Shop(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Shop, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().Shop());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Services::Maps::LocalSearch::ILocalLocation> : produce_base<D, Windows::Services::Maps::LocalSearch::ILocalLocation>
{
    int32_t WINRT_CALL get_Address(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Address, WINRT_WRAP(Windows::Services::Maps::MapAddress));
            *value = detach_from<Windows::Services::Maps::MapAddress>(this->shim().Address());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Identifier(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Identifier, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().Identifier());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Description(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Description, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().Description());
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

    int32_t WINRT_CALL get_Point(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Point, WINRT_WRAP(Windows::Devices::Geolocation::Geopoint));
            *value = detach_from<Windows::Devices::Geolocation::Geopoint>(this->shim().Point());
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

    int32_t WINRT_CALL get_DataAttribution(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(DataAttribution, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().DataAttribution());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Services::Maps::LocalSearch::ILocalLocation2> : produce_base<D, Windows::Services::Maps::LocalSearch::ILocalLocation2>
{
    int32_t WINRT_CALL get_Category(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Category, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().Category());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_RatingInfo(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(RatingInfo, WINRT_WRAP(Windows::Services::Maps::LocalSearch::LocalLocationRatingInfo));
            *value = detach_from<Windows::Services::Maps::LocalSearch::LocalLocationRatingInfo>(this->shim().RatingInfo());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_HoursOfOperation(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(HoursOfOperation, WINRT_WRAP(Windows::Foundation::Collections::IVectorView<Windows::Services::Maps::LocalSearch::LocalLocationHoursOfOperationItem>));
            *value = detach_from<Windows::Foundation::Collections::IVectorView<Windows::Services::Maps::LocalSearch::LocalLocationHoursOfOperationItem>>(this->shim().HoursOfOperation());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Services::Maps::LocalSearch::ILocalLocationFinderResult> : produce_base<D, Windows::Services::Maps::LocalSearch::ILocalLocationFinderResult>
{
    int32_t WINRT_CALL get_LocalLocations(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(LocalLocations, WINRT_WRAP(Windows::Foundation::Collections::IVectorView<Windows::Services::Maps::LocalSearch::LocalLocation>));
            *value = detach_from<Windows::Foundation::Collections::IVectorView<Windows::Services::Maps::LocalSearch::LocalLocation>>(this->shim().LocalLocations());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Status(Windows::Services::Maps::LocalSearch::LocalLocationFinderStatus* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Status, WINRT_WRAP(Windows::Services::Maps::LocalSearch::LocalLocationFinderStatus));
            *value = detach_from<Windows::Services::Maps::LocalSearch::LocalLocationFinderStatus>(this->shim().Status());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Services::Maps::LocalSearch::ILocalLocationFinderStatics> : produce_base<D, Windows::Services::Maps::LocalSearch::ILocalLocationFinderStatics>
{
    int32_t WINRT_CALL FindLocalLocationsAsync(void* searchTerm, void* searchArea, void* localCategory, uint32_t maxResults, void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(FindLocalLocationsAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<Windows::Services::Maps::LocalSearch::LocalLocationFinderResult>), hstring const, Windows::Devices::Geolocation::Geocircle const, hstring const, uint32_t);
            *result = detach_from<Windows::Foundation::IAsyncOperation<Windows::Services::Maps::LocalSearch::LocalLocationFinderResult>>(this->shim().FindLocalLocationsAsync(*reinterpret_cast<hstring const*>(&searchTerm), *reinterpret_cast<Windows::Devices::Geolocation::Geocircle const*>(&searchArea), *reinterpret_cast<hstring const*>(&localCategory), maxResults));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Services::Maps::LocalSearch::ILocalLocationHoursOfOperationItem> : produce_base<D, Windows::Services::Maps::LocalSearch::ILocalLocationHoursOfOperationItem>
{
    int32_t WINRT_CALL get_Day(Windows::Globalization::DayOfWeek* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Day, WINRT_WRAP(Windows::Globalization::DayOfWeek));
            *value = detach_from<Windows::Globalization::DayOfWeek>(this->shim().Day());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Start(Windows::Foundation::TimeSpan* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Start, WINRT_WRAP(Windows::Foundation::TimeSpan));
            *value = detach_from<Windows::Foundation::TimeSpan>(this->shim().Start());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Span(Windows::Foundation::TimeSpan* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Span, WINRT_WRAP(Windows::Foundation::TimeSpan));
            *value = detach_from<Windows::Foundation::TimeSpan>(this->shim().Span());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Services::Maps::LocalSearch::ILocalLocationRatingInfo> : produce_base<D, Windows::Services::Maps::LocalSearch::ILocalLocationRatingInfo>
{
    int32_t WINRT_CALL get_AggregateRating(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(AggregateRating, WINRT_WRAP(Windows::Foundation::IReference<double>));
            *value = detach_from<Windows::Foundation::IReference<double>>(this->shim().AggregateRating());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_RatingCount(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(RatingCount, WINRT_WRAP(Windows::Foundation::IReference<int32_t>));
            *value = detach_from<Windows::Foundation::IReference<int32_t>>(this->shim().RatingCount());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_ProviderIdentifier(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ProviderIdentifier, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().ProviderIdentifier());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Services::Maps::LocalSearch::IPlaceInfoHelperStatics> : produce_base<D, Windows::Services::Maps::LocalSearch::IPlaceInfoHelperStatics>
{
    int32_t WINRT_CALL CreateFromLocalLocation(void* location, void** resultValue) noexcept final
    {
        try
        {
            *resultValue = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CreateFromLocalLocation, WINRT_WRAP(Windows::Services::Maps::PlaceInfo), Windows::Services::Maps::LocalSearch::LocalLocation const&);
            *resultValue = detach_from<Windows::Services::Maps::PlaceInfo>(this->shim().CreateFromLocalLocation(*reinterpret_cast<Windows::Services::Maps::LocalSearch::LocalLocation const*>(&location)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

}

WINRT_EXPORT namespace winrt::Windows::Services::Maps::LocalSearch {

inline hstring LocalCategories::BankAndCreditUnions()
{
    return impl::call_factory<LocalCategories, Windows::Services::Maps::LocalSearch::ILocalCategoriesStatics>([&](auto&& f) { return f.BankAndCreditUnions(); });
}

inline hstring LocalCategories::EatDrink()
{
    return impl::call_factory<LocalCategories, Windows::Services::Maps::LocalSearch::ILocalCategoriesStatics>([&](auto&& f) { return f.EatDrink(); });
}

inline hstring LocalCategories::Hospitals()
{
    return impl::call_factory<LocalCategories, Windows::Services::Maps::LocalSearch::ILocalCategoriesStatics>([&](auto&& f) { return f.Hospitals(); });
}

inline hstring LocalCategories::HotelsAndMotels()
{
    return impl::call_factory<LocalCategories, Windows::Services::Maps::LocalSearch::ILocalCategoriesStatics>([&](auto&& f) { return f.HotelsAndMotels(); });
}

inline hstring LocalCategories::All()
{
    return impl::call_factory<LocalCategories, Windows::Services::Maps::LocalSearch::ILocalCategoriesStatics>([&](auto&& f) { return f.All(); });
}

inline hstring LocalCategories::Parking()
{
    return impl::call_factory<LocalCategories, Windows::Services::Maps::LocalSearch::ILocalCategoriesStatics>([&](auto&& f) { return f.Parking(); });
}

inline hstring LocalCategories::SeeDo()
{
    return impl::call_factory<LocalCategories, Windows::Services::Maps::LocalSearch::ILocalCategoriesStatics>([&](auto&& f) { return f.SeeDo(); });
}

inline hstring LocalCategories::Shop()
{
    return impl::call_factory<LocalCategories, Windows::Services::Maps::LocalSearch::ILocalCategoriesStatics>([&](auto&& f) { return f.Shop(); });
}

inline Windows::Foundation::IAsyncOperation<Windows::Services::Maps::LocalSearch::LocalLocationFinderResult> LocalLocationFinder::FindLocalLocationsAsync(param::hstring const& searchTerm, Windows::Devices::Geolocation::Geocircle const& searchArea, param::hstring const& localCategory, uint32_t maxResults)
{
    return impl::call_factory<LocalLocationFinder, Windows::Services::Maps::LocalSearch::ILocalLocationFinderStatics>([&](auto&& f) { return f.FindLocalLocationsAsync(searchTerm, searchArea, localCategory, maxResults); });
}

inline Windows::Services::Maps::PlaceInfo PlaceInfoHelper::CreateFromLocalLocation(Windows::Services::Maps::LocalSearch::LocalLocation const& location)
{
    return impl::call_factory<PlaceInfoHelper, Windows::Services::Maps::LocalSearch::IPlaceInfoHelperStatics>([&](auto&& f) { return f.CreateFromLocalLocation(location); });
}

}

WINRT_EXPORT namespace std {

template<> struct hash<winrt::Windows::Services::Maps::LocalSearch::ILocalCategoriesStatics> : winrt::impl::hash_base<winrt::Windows::Services::Maps::LocalSearch::ILocalCategoriesStatics> {};
template<> struct hash<winrt::Windows::Services::Maps::LocalSearch::ILocalLocation> : winrt::impl::hash_base<winrt::Windows::Services::Maps::LocalSearch::ILocalLocation> {};
template<> struct hash<winrt::Windows::Services::Maps::LocalSearch::ILocalLocation2> : winrt::impl::hash_base<winrt::Windows::Services::Maps::LocalSearch::ILocalLocation2> {};
template<> struct hash<winrt::Windows::Services::Maps::LocalSearch::ILocalLocationFinderResult> : winrt::impl::hash_base<winrt::Windows::Services::Maps::LocalSearch::ILocalLocationFinderResult> {};
template<> struct hash<winrt::Windows::Services::Maps::LocalSearch::ILocalLocationFinderStatics> : winrt::impl::hash_base<winrt::Windows::Services::Maps::LocalSearch::ILocalLocationFinderStatics> {};
template<> struct hash<winrt::Windows::Services::Maps::LocalSearch::ILocalLocationHoursOfOperationItem> : winrt::impl::hash_base<winrt::Windows::Services::Maps::LocalSearch::ILocalLocationHoursOfOperationItem> {};
template<> struct hash<winrt::Windows::Services::Maps::LocalSearch::ILocalLocationRatingInfo> : winrt::impl::hash_base<winrt::Windows::Services::Maps::LocalSearch::ILocalLocationRatingInfo> {};
template<> struct hash<winrt::Windows::Services::Maps::LocalSearch::IPlaceInfoHelperStatics> : winrt::impl::hash_base<winrt::Windows::Services::Maps::LocalSearch::IPlaceInfoHelperStatics> {};
template<> struct hash<winrt::Windows::Services::Maps::LocalSearch::LocalCategories> : winrt::impl::hash_base<winrt::Windows::Services::Maps::LocalSearch::LocalCategories> {};
template<> struct hash<winrt::Windows::Services::Maps::LocalSearch::LocalLocation> : winrt::impl::hash_base<winrt::Windows::Services::Maps::LocalSearch::LocalLocation> {};
template<> struct hash<winrt::Windows::Services::Maps::LocalSearch::LocalLocationFinder> : winrt::impl::hash_base<winrt::Windows::Services::Maps::LocalSearch::LocalLocationFinder> {};
template<> struct hash<winrt::Windows::Services::Maps::LocalSearch::LocalLocationFinderResult> : winrt::impl::hash_base<winrt::Windows::Services::Maps::LocalSearch::LocalLocationFinderResult> {};
template<> struct hash<winrt::Windows::Services::Maps::LocalSearch::LocalLocationHoursOfOperationItem> : winrt::impl::hash_base<winrt::Windows::Services::Maps::LocalSearch::LocalLocationHoursOfOperationItem> {};
template<> struct hash<winrt::Windows::Services::Maps::LocalSearch::LocalLocationRatingInfo> : winrt::impl::hash_base<winrt::Windows::Services::Maps::LocalSearch::LocalLocationRatingInfo> {};
template<> struct hash<winrt::Windows::Services::Maps::LocalSearch::PlaceInfoHelper> : winrt::impl::hash_base<winrt::Windows::Services::Maps::LocalSearch::PlaceInfoHelper> {};

}
