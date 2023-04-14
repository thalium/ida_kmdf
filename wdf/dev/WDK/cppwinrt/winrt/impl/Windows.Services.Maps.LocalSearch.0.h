// C++/WinRT v1.0.190111.3

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#pragma once

WINRT_EXPORT namespace winrt::Windows::Devices::Geolocation {

struct Geocircle;
struct Geopoint;

}

WINRT_EXPORT namespace winrt::Windows::Globalization {

enum class DayOfWeek;

}

WINRT_EXPORT namespace winrt::Windows::Services::Maps {

struct MapAddress;
struct PlaceInfo;

}

WINRT_EXPORT namespace winrt::Windows::Services::Maps::LocalSearch {

enum class LocalLocationFinderStatus : int32_t
{
    Success = 0,
    UnknownError = 1,
    InvalidCredentials = 2,
    InvalidCategory = 3,
    InvalidSearchTerm = 4,
    InvalidSearchArea = 5,
    NetworkFailure = 6,
    NotSupported = 7,
};

struct ILocalCategoriesStatics;
struct ILocalLocation;
struct ILocalLocation2;
struct ILocalLocationFinderResult;
struct ILocalLocationFinderStatics;
struct ILocalLocationHoursOfOperationItem;
struct ILocalLocationRatingInfo;
struct IPlaceInfoHelperStatics;
struct LocalCategories;
struct LocalLocation;
struct LocalLocationFinder;
struct LocalLocationFinderResult;
struct LocalLocationHoursOfOperationItem;
struct LocalLocationRatingInfo;
struct PlaceInfoHelper;

}

namespace winrt::impl {

template <> struct category<Windows::Services::Maps::LocalSearch::ILocalCategoriesStatics>{ using type = interface_category; };
template <> struct category<Windows::Services::Maps::LocalSearch::ILocalLocation>{ using type = interface_category; };
template <> struct category<Windows::Services::Maps::LocalSearch::ILocalLocation2>{ using type = interface_category; };
template <> struct category<Windows::Services::Maps::LocalSearch::ILocalLocationFinderResult>{ using type = interface_category; };
template <> struct category<Windows::Services::Maps::LocalSearch::ILocalLocationFinderStatics>{ using type = interface_category; };
template <> struct category<Windows::Services::Maps::LocalSearch::ILocalLocationHoursOfOperationItem>{ using type = interface_category; };
template <> struct category<Windows::Services::Maps::LocalSearch::ILocalLocationRatingInfo>{ using type = interface_category; };
template <> struct category<Windows::Services::Maps::LocalSearch::IPlaceInfoHelperStatics>{ using type = interface_category; };
template <> struct category<Windows::Services::Maps::LocalSearch::LocalCategories>{ using type = class_category; };
template <> struct category<Windows::Services::Maps::LocalSearch::LocalLocation>{ using type = class_category; };
template <> struct category<Windows::Services::Maps::LocalSearch::LocalLocationFinder>{ using type = class_category; };
template <> struct category<Windows::Services::Maps::LocalSearch::LocalLocationFinderResult>{ using type = class_category; };
template <> struct category<Windows::Services::Maps::LocalSearch::LocalLocationHoursOfOperationItem>{ using type = class_category; };
template <> struct category<Windows::Services::Maps::LocalSearch::LocalLocationRatingInfo>{ using type = class_category; };
template <> struct category<Windows::Services::Maps::LocalSearch::PlaceInfoHelper>{ using type = class_category; };
template <> struct category<Windows::Services::Maps::LocalSearch::LocalLocationFinderStatus>{ using type = enum_category; };
template <> struct name<Windows::Services::Maps::LocalSearch::ILocalCategoriesStatics>{ static constexpr auto & value{ L"Windows.Services.Maps.LocalSearch.ILocalCategoriesStatics" }; };
template <> struct name<Windows::Services::Maps::LocalSearch::ILocalLocation>{ static constexpr auto & value{ L"Windows.Services.Maps.LocalSearch.ILocalLocation" }; };
template <> struct name<Windows::Services::Maps::LocalSearch::ILocalLocation2>{ static constexpr auto & value{ L"Windows.Services.Maps.LocalSearch.ILocalLocation2" }; };
template <> struct name<Windows::Services::Maps::LocalSearch::ILocalLocationFinderResult>{ static constexpr auto & value{ L"Windows.Services.Maps.LocalSearch.ILocalLocationFinderResult" }; };
template <> struct name<Windows::Services::Maps::LocalSearch::ILocalLocationFinderStatics>{ static constexpr auto & value{ L"Windows.Services.Maps.LocalSearch.ILocalLocationFinderStatics" }; };
template <> struct name<Windows::Services::Maps::LocalSearch::ILocalLocationHoursOfOperationItem>{ static constexpr auto & value{ L"Windows.Services.Maps.LocalSearch.ILocalLocationHoursOfOperationItem" }; };
template <> struct name<Windows::Services::Maps::LocalSearch::ILocalLocationRatingInfo>{ static constexpr auto & value{ L"Windows.Services.Maps.LocalSearch.ILocalLocationRatingInfo" }; };
template <> struct name<Windows::Services::Maps::LocalSearch::IPlaceInfoHelperStatics>{ static constexpr auto & value{ L"Windows.Services.Maps.LocalSearch.IPlaceInfoHelperStatics" }; };
template <> struct name<Windows::Services::Maps::LocalSearch::LocalCategories>{ static constexpr auto & value{ L"Windows.Services.Maps.LocalSearch.LocalCategories" }; };
template <> struct name<Windows::Services::Maps::LocalSearch::LocalLocation>{ static constexpr auto & value{ L"Windows.Services.Maps.LocalSearch.LocalLocation" }; };
template <> struct name<Windows::Services::Maps::LocalSearch::LocalLocationFinder>{ static constexpr auto & value{ L"Windows.Services.Maps.LocalSearch.LocalLocationFinder" }; };
template <> struct name<Windows::Services::Maps::LocalSearch::LocalLocationFinderResult>{ static constexpr auto & value{ L"Windows.Services.Maps.LocalSearch.LocalLocationFinderResult" }; };
template <> struct name<Windows::Services::Maps::LocalSearch::LocalLocationHoursOfOperationItem>{ static constexpr auto & value{ L"Windows.Services.Maps.LocalSearch.LocalLocationHoursOfOperationItem" }; };
template <> struct name<Windows::Services::Maps::LocalSearch::LocalLocationRatingInfo>{ static constexpr auto & value{ L"Windows.Services.Maps.LocalSearch.LocalLocationRatingInfo" }; };
template <> struct name<Windows::Services::Maps::LocalSearch::PlaceInfoHelper>{ static constexpr auto & value{ L"Windows.Services.Maps.LocalSearch.PlaceInfoHelper" }; };
template <> struct name<Windows::Services::Maps::LocalSearch::LocalLocationFinderStatus>{ static constexpr auto & value{ L"Windows.Services.Maps.LocalSearch.LocalLocationFinderStatus" }; };
template <> struct guid_storage<Windows::Services::Maps::LocalSearch::ILocalCategoriesStatics>{ static constexpr guid value{ 0xF49399F5,0x8261,0x4321,{ 0x99,0x74,0xEF,0x92,0xD4,0x9A,0x8D,0xCA } }; };
template <> struct guid_storage<Windows::Services::Maps::LocalSearch::ILocalLocation>{ static constexpr guid value{ 0xBB0FE9AB,0x4502,0x4F2C,{ 0x94,0xA9,0x0D,0x60,0xDE,0x0E,0x21,0x63 } }; };
template <> struct guid_storage<Windows::Services::Maps::LocalSearch::ILocalLocation2>{ static constexpr guid value{ 0x6E9E307C,0xECB5,0x4FFC,{ 0xBB,0x8C,0xBA,0x50,0xBA,0x8C,0x2D,0xC6 } }; };
template <> struct guid_storage<Windows::Services::Maps::LocalSearch::ILocalLocationFinderResult>{ static constexpr guid value{ 0xD09B6CC6,0xF338,0x4191,{ 0x9F,0xD8,0x54,0x40,0xB9,0xA6,0x8F,0x52 } }; };
template <> struct guid_storage<Windows::Services::Maps::LocalSearch::ILocalLocationFinderStatics>{ static constexpr guid value{ 0xD2EF7344,0xA0DE,0x48CA,{ 0x81,0xA8,0x07,0xC7,0xDC,0xFD,0x37,0xAB } }; };
template <> struct guid_storage<Windows::Services::Maps::LocalSearch::ILocalLocationHoursOfOperationItem>{ static constexpr guid value{ 0x23548C72,0xA1C7,0x43F1,{ 0xA4,0xF0,0x10,0x91,0xC3,0x9E,0xC6,0x40 } }; };
template <> struct guid_storage<Windows::Services::Maps::LocalSearch::ILocalLocationRatingInfo>{ static constexpr guid value{ 0xCB1DAB56,0x3354,0x4311,{ 0x8B,0xC0,0xA2,0xD4,0xD5,0xEB,0x80,0x6E } }; };
template <> struct guid_storage<Windows::Services::Maps::LocalSearch::IPlaceInfoHelperStatics>{ static constexpr guid value{ 0xDD1CA9A7,0xA9C6,0x491B,{ 0xBC,0x09,0xE8,0x0F,0xCE,0xA4,0x8E,0xE6 } }; };
template <> struct default_interface<Windows::Services::Maps::LocalSearch::LocalLocation>{ using type = Windows::Services::Maps::LocalSearch::ILocalLocation; };
template <> struct default_interface<Windows::Services::Maps::LocalSearch::LocalLocationFinderResult>{ using type = Windows::Services::Maps::LocalSearch::ILocalLocationFinderResult; };
template <> struct default_interface<Windows::Services::Maps::LocalSearch::LocalLocationHoursOfOperationItem>{ using type = Windows::Services::Maps::LocalSearch::ILocalLocationHoursOfOperationItem; };
template <> struct default_interface<Windows::Services::Maps::LocalSearch::LocalLocationRatingInfo>{ using type = Windows::Services::Maps::LocalSearch::ILocalLocationRatingInfo; };

template <> struct abi<Windows::Services::Maps::LocalSearch::ILocalCategoriesStatics>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL get_BankAndCreditUnions(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_EatDrink(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_Hospitals(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_HotelsAndMotels(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_All(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_Parking(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_SeeDo(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_Shop(void** value) noexcept = 0;
};};

template <> struct abi<Windows::Services::Maps::LocalSearch::ILocalLocation>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL get_Address(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_Identifier(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_Description(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_DisplayName(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_Point(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_PhoneNumber(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_DataAttribution(void** value) noexcept = 0;
};};

template <> struct abi<Windows::Services::Maps::LocalSearch::ILocalLocation2>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL get_Category(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_RatingInfo(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_HoursOfOperation(void** value) noexcept = 0;
};};

template <> struct abi<Windows::Services::Maps::LocalSearch::ILocalLocationFinderResult>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL get_LocalLocations(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_Status(Windows::Services::Maps::LocalSearch::LocalLocationFinderStatus* value) noexcept = 0;
};};

template <> struct abi<Windows::Services::Maps::LocalSearch::ILocalLocationFinderStatics>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL FindLocalLocationsAsync(void* searchTerm, void* searchArea, void* localCategory, uint32_t maxResults, void** result) noexcept = 0;
};};

template <> struct abi<Windows::Services::Maps::LocalSearch::ILocalLocationHoursOfOperationItem>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL get_Day(Windows::Globalization::DayOfWeek* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_Start(Windows::Foundation::TimeSpan* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_Span(Windows::Foundation::TimeSpan* value) noexcept = 0;
};};

template <> struct abi<Windows::Services::Maps::LocalSearch::ILocalLocationRatingInfo>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL get_AggregateRating(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_RatingCount(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_ProviderIdentifier(void** value) noexcept = 0;
};};

template <> struct abi<Windows::Services::Maps::LocalSearch::IPlaceInfoHelperStatics>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL CreateFromLocalLocation(void* location, void** resultValue) noexcept = 0;
};};

template <typename D>
struct consume_Windows_Services_Maps_LocalSearch_ILocalCategoriesStatics
{
    hstring BankAndCreditUnions() const;
    hstring EatDrink() const;
    hstring Hospitals() const;
    hstring HotelsAndMotels() const;
    hstring All() const;
    hstring Parking() const;
    hstring SeeDo() const;
    hstring Shop() const;
};
template <> struct consume<Windows::Services::Maps::LocalSearch::ILocalCategoriesStatics> { template <typename D> using type = consume_Windows_Services_Maps_LocalSearch_ILocalCategoriesStatics<D>; };

template <typename D>
struct consume_Windows_Services_Maps_LocalSearch_ILocalLocation
{
    Windows::Services::Maps::MapAddress Address() const;
    hstring Identifier() const;
    hstring Description() const;
    hstring DisplayName() const;
    Windows::Devices::Geolocation::Geopoint Point() const;
    hstring PhoneNumber() const;
    hstring DataAttribution() const;
};
template <> struct consume<Windows::Services::Maps::LocalSearch::ILocalLocation> { template <typename D> using type = consume_Windows_Services_Maps_LocalSearch_ILocalLocation<D>; };

template <typename D>
struct consume_Windows_Services_Maps_LocalSearch_ILocalLocation2
{
    hstring Category() const;
    Windows::Services::Maps::LocalSearch::LocalLocationRatingInfo RatingInfo() const;
    Windows::Foundation::Collections::IVectorView<Windows::Services::Maps::LocalSearch::LocalLocationHoursOfOperationItem> HoursOfOperation() const;
};
template <> struct consume<Windows::Services::Maps::LocalSearch::ILocalLocation2> { template <typename D> using type = consume_Windows_Services_Maps_LocalSearch_ILocalLocation2<D>; };

template <typename D>
struct consume_Windows_Services_Maps_LocalSearch_ILocalLocationFinderResult
{
    Windows::Foundation::Collections::IVectorView<Windows::Services::Maps::LocalSearch::LocalLocation> LocalLocations() const;
    Windows::Services::Maps::LocalSearch::LocalLocationFinderStatus Status() const;
};
template <> struct consume<Windows::Services::Maps::LocalSearch::ILocalLocationFinderResult> { template <typename D> using type = consume_Windows_Services_Maps_LocalSearch_ILocalLocationFinderResult<D>; };

template <typename D>
struct consume_Windows_Services_Maps_LocalSearch_ILocalLocationFinderStatics
{
    Windows::Foundation::IAsyncOperation<Windows::Services::Maps::LocalSearch::LocalLocationFinderResult> FindLocalLocationsAsync(param::hstring const& searchTerm, Windows::Devices::Geolocation::Geocircle const& searchArea, param::hstring const& localCategory, uint32_t maxResults) const;
};
template <> struct consume<Windows::Services::Maps::LocalSearch::ILocalLocationFinderStatics> { template <typename D> using type = consume_Windows_Services_Maps_LocalSearch_ILocalLocationFinderStatics<D>; };

template <typename D>
struct consume_Windows_Services_Maps_LocalSearch_ILocalLocationHoursOfOperationItem
{
    Windows::Globalization::DayOfWeek Day() const;
    Windows::Foundation::TimeSpan Start() const;
    Windows::Foundation::TimeSpan Span() const;
};
template <> struct consume<Windows::Services::Maps::LocalSearch::ILocalLocationHoursOfOperationItem> { template <typename D> using type = consume_Windows_Services_Maps_LocalSearch_ILocalLocationHoursOfOperationItem<D>; };

template <typename D>
struct consume_Windows_Services_Maps_LocalSearch_ILocalLocationRatingInfo
{
    Windows::Foundation::IReference<double> AggregateRating() const;
    Windows::Foundation::IReference<int32_t> RatingCount() const;
    hstring ProviderIdentifier() const;
};
template <> struct consume<Windows::Services::Maps::LocalSearch::ILocalLocationRatingInfo> { template <typename D> using type = consume_Windows_Services_Maps_LocalSearch_ILocalLocationRatingInfo<D>; };

template <typename D>
struct consume_Windows_Services_Maps_LocalSearch_IPlaceInfoHelperStatics
{
    Windows::Services::Maps::PlaceInfo CreateFromLocalLocation(Windows::Services::Maps::LocalSearch::LocalLocation const& location) const;
};
template <> struct consume<Windows::Services::Maps::LocalSearch::IPlaceInfoHelperStatics> { template <typename D> using type = consume_Windows_Services_Maps_LocalSearch_IPlaceInfoHelperStatics<D>; };

}
