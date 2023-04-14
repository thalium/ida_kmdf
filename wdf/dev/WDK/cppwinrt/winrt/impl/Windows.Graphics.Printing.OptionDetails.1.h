// C++/WinRT v1.0.190111.3

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#pragma once
#include "winrt/impl/Windows.Graphics.Printing.0.h"
#include "winrt/impl/Windows.Storage.Streams.0.h"
#include "winrt/impl/Windows.Graphics.Printing.OptionDetails.0.h"

WINRT_EXPORT namespace winrt::Windows::Graphics::Printing::OptionDetails {

struct WINRT_EBO IPrintBindingOptionDetails :
    Windows::Foundation::IInspectable,
    impl::consume_t<IPrintBindingOptionDetails>
{
    IPrintBindingOptionDetails(std::nullptr_t = nullptr) noexcept {}
};

struct WINRT_EBO IPrintBorderingOptionDetails :
    Windows::Foundation::IInspectable,
    impl::consume_t<IPrintBorderingOptionDetails>
{
    IPrintBorderingOptionDetails(std::nullptr_t = nullptr) noexcept {}
};

struct WINRT_EBO IPrintCollationOptionDetails :
    Windows::Foundation::IInspectable,
    impl::consume_t<IPrintCollationOptionDetails>
{
    IPrintCollationOptionDetails(std::nullptr_t = nullptr) noexcept {}
};

struct WINRT_EBO IPrintColorModeOptionDetails :
    Windows::Foundation::IInspectable,
    impl::consume_t<IPrintColorModeOptionDetails>
{
    IPrintColorModeOptionDetails(std::nullptr_t = nullptr) noexcept {}
};

struct WINRT_EBO IPrintCopiesOptionDetails :
    Windows::Foundation::IInspectable,
    impl::consume_t<IPrintCopiesOptionDetails>
{
    IPrintCopiesOptionDetails(std::nullptr_t = nullptr) noexcept {}
};

struct WINRT_EBO IPrintCustomItemDetails :
    Windows::Foundation::IInspectable,
    impl::consume_t<IPrintCustomItemDetails>
{
    IPrintCustomItemDetails(std::nullptr_t = nullptr) noexcept {}
};

struct WINRT_EBO IPrintCustomItemListOptionDetails :
    Windows::Foundation::IInspectable,
    impl::consume_t<IPrintCustomItemListOptionDetails>,
    impl::require<IPrintCustomItemListOptionDetails, Windows::Graphics::Printing::OptionDetails::IPrintCustomOptionDetails, Windows::Graphics::Printing::OptionDetails::IPrintItemListOptionDetails, Windows::Graphics::Printing::OptionDetails::IPrintOptionDetails>
{
    IPrintCustomItemListOptionDetails(std::nullptr_t = nullptr) noexcept {}
};

struct WINRT_EBO IPrintCustomItemListOptionDetails2 :
    Windows::Foundation::IInspectable,
    impl::consume_t<IPrintCustomItemListOptionDetails2>
{
    IPrintCustomItemListOptionDetails2(std::nullptr_t = nullptr) noexcept {}
};

struct WINRT_EBO IPrintCustomItemListOptionDetails3 :
    Windows::Foundation::IInspectable,
    impl::consume_t<IPrintCustomItemListOptionDetails3>
{
    IPrintCustomItemListOptionDetails3(std::nullptr_t = nullptr) noexcept {}
};

struct WINRT_EBO IPrintCustomOptionDetails :
    Windows::Foundation::IInspectable,
    impl::consume_t<IPrintCustomOptionDetails>,
    impl::require<IPrintCustomOptionDetails, Windows::Graphics::Printing::OptionDetails::IPrintOptionDetails>
{
    IPrintCustomOptionDetails(std::nullptr_t = nullptr) noexcept {}
};

struct WINRT_EBO IPrintCustomTextOptionDetails :
    Windows::Foundation::IInspectable,
    impl::consume_t<IPrintCustomTextOptionDetails>,
    impl::require<IPrintCustomTextOptionDetails, Windows::Graphics::Printing::OptionDetails::IPrintCustomOptionDetails, Windows::Graphics::Printing::OptionDetails::IPrintOptionDetails>
{
    IPrintCustomTextOptionDetails(std::nullptr_t = nullptr) noexcept {}
};

struct WINRT_EBO IPrintCustomTextOptionDetails2 :
    Windows::Foundation::IInspectable,
    impl::consume_t<IPrintCustomTextOptionDetails2>
{
    IPrintCustomTextOptionDetails2(std::nullptr_t = nullptr) noexcept {}
};

struct WINRT_EBO IPrintCustomToggleOptionDetails :
    Windows::Foundation::IInspectable,
    impl::consume_t<IPrintCustomToggleOptionDetails>
{
    IPrintCustomToggleOptionDetails(std::nullptr_t = nullptr) noexcept {}
};

struct WINRT_EBO IPrintDuplexOptionDetails :
    Windows::Foundation::IInspectable,
    impl::consume_t<IPrintDuplexOptionDetails>
{
    IPrintDuplexOptionDetails(std::nullptr_t = nullptr) noexcept {}
};

struct WINRT_EBO IPrintHolePunchOptionDetails :
    Windows::Foundation::IInspectable,
    impl::consume_t<IPrintHolePunchOptionDetails>
{
    IPrintHolePunchOptionDetails(std::nullptr_t = nullptr) noexcept {}
};

struct WINRT_EBO IPrintItemListOptionDetails :
    Windows::Foundation::IInspectable,
    impl::consume_t<IPrintItemListOptionDetails>,
    impl::require<IPrintItemListOptionDetails, Windows::Graphics::Printing::OptionDetails::IPrintOptionDetails>
{
    IPrintItemListOptionDetails(std::nullptr_t = nullptr) noexcept {}
};

struct WINRT_EBO IPrintMediaSizeOptionDetails :
    Windows::Foundation::IInspectable,
    impl::consume_t<IPrintMediaSizeOptionDetails>
{
    IPrintMediaSizeOptionDetails(std::nullptr_t = nullptr) noexcept {}
};

struct WINRT_EBO IPrintMediaTypeOptionDetails :
    Windows::Foundation::IInspectable,
    impl::consume_t<IPrintMediaTypeOptionDetails>
{
    IPrintMediaTypeOptionDetails(std::nullptr_t = nullptr) noexcept {}
};

struct WINRT_EBO IPrintNumberOptionDetails :
    Windows::Foundation::IInspectable,
    impl::consume_t<IPrintNumberOptionDetails>,
    impl::require<IPrintNumberOptionDetails, Windows::Graphics::Printing::OptionDetails::IPrintOptionDetails>
{
    IPrintNumberOptionDetails(std::nullptr_t = nullptr) noexcept {}
};

struct WINRT_EBO IPrintOptionDetails :
    Windows::Foundation::IInspectable,
    impl::consume_t<IPrintOptionDetails>
{
    IPrintOptionDetails(std::nullptr_t = nullptr) noexcept {}
};

struct WINRT_EBO IPrintOrientationOptionDetails :
    Windows::Foundation::IInspectable,
    impl::consume_t<IPrintOrientationOptionDetails>
{
    IPrintOrientationOptionDetails(std::nullptr_t = nullptr) noexcept {}
};

struct WINRT_EBO IPrintPageRangeOptionDetails :
    Windows::Foundation::IInspectable,
    impl::consume_t<IPrintPageRangeOptionDetails>
{
    IPrintPageRangeOptionDetails(std::nullptr_t = nullptr) noexcept {}
};

struct WINRT_EBO IPrintQualityOptionDetails :
    Windows::Foundation::IInspectable,
    impl::consume_t<IPrintQualityOptionDetails>
{
    IPrintQualityOptionDetails(std::nullptr_t = nullptr) noexcept {}
};

struct WINRT_EBO IPrintStapleOptionDetails :
    Windows::Foundation::IInspectable,
    impl::consume_t<IPrintStapleOptionDetails>
{
    IPrintStapleOptionDetails(std::nullptr_t = nullptr) noexcept {}
};

struct WINRT_EBO IPrintTaskOptionChangedEventArgs :
    Windows::Foundation::IInspectable,
    impl::consume_t<IPrintTaskOptionChangedEventArgs>
{
    IPrintTaskOptionChangedEventArgs(std::nullptr_t = nullptr) noexcept {}
};

struct WINRT_EBO IPrintTaskOptionDetails :
    Windows::Foundation::IInspectable,
    impl::consume_t<IPrintTaskOptionDetails>
{
    IPrintTaskOptionDetails(std::nullptr_t = nullptr) noexcept {}
};

struct WINRT_EBO IPrintTaskOptionDetails2 :
    Windows::Foundation::IInspectable,
    impl::consume_t<IPrintTaskOptionDetails2>
{
    IPrintTaskOptionDetails2(std::nullptr_t = nullptr) noexcept {}
};

struct WINRT_EBO IPrintTaskOptionDetailsStatic :
    Windows::Foundation::IInspectable,
    impl::consume_t<IPrintTaskOptionDetailsStatic>
{
    IPrintTaskOptionDetailsStatic(std::nullptr_t = nullptr) noexcept {}
};

struct WINRT_EBO IPrintTextOptionDetails :
    Windows::Foundation::IInspectable,
    impl::consume_t<IPrintTextOptionDetails>,
    impl::require<IPrintTextOptionDetails, Windows::Graphics::Printing::OptionDetails::IPrintOptionDetails>
{
    IPrintTextOptionDetails(std::nullptr_t = nullptr) noexcept {}
};

}
