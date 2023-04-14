// C++/WinRT v1.0.190111.3

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#pragma once
#include "winrt/impl/Windows.Graphics.Printing.1.h"
#include "winrt/impl/Windows.Storage.Streams.1.h"
#include "winrt/impl/Windows.Graphics.Printing.OptionDetails.1.h"

WINRT_EXPORT namespace winrt::Windows::Graphics::Printing::OptionDetails {

}

namespace winrt::impl {

}

WINRT_EXPORT namespace winrt::Windows::Graphics::Printing::OptionDetails {

struct WINRT_EBO PrintBindingOptionDetails :
    Windows::Graphics::Printing::OptionDetails::IPrintOptionDetails,
    impl::require<PrintBindingOptionDetails, Windows::Graphics::Printing::OptionDetails::IPrintBindingOptionDetails, Windows::Graphics::Printing::OptionDetails::IPrintItemListOptionDetails>
{
    PrintBindingOptionDetails(std::nullptr_t) noexcept {}
};

struct WINRT_EBO PrintBorderingOptionDetails :
    Windows::Graphics::Printing::OptionDetails::IPrintOptionDetails,
    impl::require<PrintBorderingOptionDetails, Windows::Graphics::Printing::OptionDetails::IPrintBorderingOptionDetails, Windows::Graphics::Printing::OptionDetails::IPrintItemListOptionDetails>
{
    PrintBorderingOptionDetails(std::nullptr_t) noexcept {}
};

struct WINRT_EBO PrintCollationOptionDetails :
    Windows::Graphics::Printing::OptionDetails::IPrintOptionDetails,
    impl::require<PrintCollationOptionDetails, Windows::Graphics::Printing::OptionDetails::IPrintCollationOptionDetails, Windows::Graphics::Printing::OptionDetails::IPrintItemListOptionDetails>
{
    PrintCollationOptionDetails(std::nullptr_t) noexcept {}
};

struct WINRT_EBO PrintColorModeOptionDetails :
    Windows::Graphics::Printing::OptionDetails::IPrintOptionDetails,
    impl::require<PrintColorModeOptionDetails, Windows::Graphics::Printing::OptionDetails::IPrintColorModeOptionDetails, Windows::Graphics::Printing::OptionDetails::IPrintItemListOptionDetails>
{
    PrintColorModeOptionDetails(std::nullptr_t) noexcept {}
};

struct WINRT_EBO PrintCopiesOptionDetails :
    Windows::Graphics::Printing::OptionDetails::IPrintOptionDetails,
    impl::require<PrintCopiesOptionDetails, Windows::Graphics::Printing::OptionDetails::IPrintCopiesOptionDetails, Windows::Graphics::Printing::OptionDetails::IPrintNumberOptionDetails>
{
    PrintCopiesOptionDetails(std::nullptr_t) noexcept {}
};

struct WINRT_EBO PrintCustomItemDetails :
    Windows::Graphics::Printing::OptionDetails::IPrintCustomItemDetails
{
    PrintCustomItemDetails(std::nullptr_t) noexcept {}
};

struct WINRT_EBO PrintCustomItemListOptionDetails :
    Windows::Graphics::Printing::OptionDetails::IPrintOptionDetails,
    impl::require<PrintCustomItemListOptionDetails, Windows::Graphics::Printing::OptionDetails::IPrintCustomItemListOptionDetails, Windows::Graphics::Printing::OptionDetails::IPrintCustomItemListOptionDetails2, Windows::Graphics::Printing::OptionDetails::IPrintCustomItemListOptionDetails3, Windows::Graphics::Printing::OptionDetails::IPrintCustomOptionDetails, Windows::Graphics::Printing::OptionDetails::IPrintItemListOptionDetails>
{
    PrintCustomItemListOptionDetails(std::nullptr_t) noexcept {}
    using impl::consume_t<PrintCustomItemListOptionDetails, Windows::Graphics::Printing::OptionDetails::IPrintCustomItemListOptionDetails>::AddItem;
    using impl::consume_t<PrintCustomItemListOptionDetails, Windows::Graphics::Printing::OptionDetails::IPrintCustomItemListOptionDetails2>::AddItem;
};

struct WINRT_EBO PrintCustomTextOptionDetails :
    Windows::Graphics::Printing::OptionDetails::IPrintOptionDetails,
    impl::require<PrintCustomTextOptionDetails, Windows::Graphics::Printing::OptionDetails::IPrintCustomOptionDetails, Windows::Graphics::Printing::OptionDetails::IPrintCustomTextOptionDetails, Windows::Graphics::Printing::OptionDetails::IPrintCustomTextOptionDetails2>
{
    PrintCustomTextOptionDetails(std::nullptr_t) noexcept {}
};

struct WINRT_EBO PrintCustomToggleOptionDetails :
    Windows::Graphics::Printing::OptionDetails::IPrintOptionDetails,
    impl::require<PrintCustomToggleOptionDetails, Windows::Graphics::Printing::OptionDetails::IPrintCustomOptionDetails, Windows::Graphics::Printing::OptionDetails::IPrintCustomToggleOptionDetails>
{
    PrintCustomToggleOptionDetails(std::nullptr_t) noexcept {}
};

struct WINRT_EBO PrintDuplexOptionDetails :
    Windows::Graphics::Printing::OptionDetails::IPrintOptionDetails,
    impl::require<PrintDuplexOptionDetails, Windows::Graphics::Printing::OptionDetails::IPrintDuplexOptionDetails, Windows::Graphics::Printing::OptionDetails::IPrintItemListOptionDetails>
{
    PrintDuplexOptionDetails(std::nullptr_t) noexcept {}
};

struct WINRT_EBO PrintHolePunchOptionDetails :
    Windows::Graphics::Printing::OptionDetails::IPrintOptionDetails,
    impl::require<PrintHolePunchOptionDetails, Windows::Graphics::Printing::OptionDetails::IPrintHolePunchOptionDetails, Windows::Graphics::Printing::OptionDetails::IPrintItemListOptionDetails>
{
    PrintHolePunchOptionDetails(std::nullptr_t) noexcept {}
};

struct WINRT_EBO PrintMediaSizeOptionDetails :
    Windows::Graphics::Printing::OptionDetails::IPrintOptionDetails,
    impl::require<PrintMediaSizeOptionDetails, Windows::Graphics::Printing::OptionDetails::IPrintItemListOptionDetails, Windows::Graphics::Printing::OptionDetails::IPrintMediaSizeOptionDetails>
{
    PrintMediaSizeOptionDetails(std::nullptr_t) noexcept {}
};

struct WINRT_EBO PrintMediaTypeOptionDetails :
    Windows::Graphics::Printing::OptionDetails::IPrintOptionDetails,
    impl::require<PrintMediaTypeOptionDetails, Windows::Graphics::Printing::OptionDetails::IPrintItemListOptionDetails, Windows::Graphics::Printing::OptionDetails::IPrintMediaTypeOptionDetails>
{
    PrintMediaTypeOptionDetails(std::nullptr_t) noexcept {}
};

struct WINRT_EBO PrintOrientationOptionDetails :
    Windows::Graphics::Printing::OptionDetails::IPrintOptionDetails,
    impl::require<PrintOrientationOptionDetails, Windows::Graphics::Printing::OptionDetails::IPrintItemListOptionDetails, Windows::Graphics::Printing::OptionDetails::IPrintOrientationOptionDetails>
{
    PrintOrientationOptionDetails(std::nullptr_t) noexcept {}
};

struct WINRT_EBO PrintPageRangeOptionDetails :
    Windows::Graphics::Printing::OptionDetails::IPrintOptionDetails,
    impl::require<PrintPageRangeOptionDetails, Windows::Graphics::Printing::OptionDetails::IPrintPageRangeOptionDetails>
{
    PrintPageRangeOptionDetails(std::nullptr_t) noexcept {}
};

struct WINRT_EBO PrintQualityOptionDetails :
    Windows::Graphics::Printing::OptionDetails::IPrintOptionDetails,
    impl::require<PrintQualityOptionDetails, Windows::Graphics::Printing::OptionDetails::IPrintItemListOptionDetails, Windows::Graphics::Printing::OptionDetails::IPrintQualityOptionDetails>
{
    PrintQualityOptionDetails(std::nullptr_t) noexcept {}
};

struct WINRT_EBO PrintStapleOptionDetails :
    Windows::Graphics::Printing::OptionDetails::IPrintOptionDetails,
    impl::require<PrintStapleOptionDetails, Windows::Graphics::Printing::OptionDetails::IPrintItemListOptionDetails, Windows::Graphics::Printing::OptionDetails::IPrintStapleOptionDetails>
{
    PrintStapleOptionDetails(std::nullptr_t) noexcept {}
};

struct WINRT_EBO PrintTaskOptionChangedEventArgs :
    Windows::Graphics::Printing::OptionDetails::IPrintTaskOptionChangedEventArgs
{
    PrintTaskOptionChangedEventArgs(std::nullptr_t) noexcept {}
};

struct WINRT_EBO PrintTaskOptionDetails :
    Windows::Graphics::Printing::OptionDetails::IPrintTaskOptionDetails,
    impl::require<PrintTaskOptionDetails, Windows::Graphics::Printing::IPrintTaskOptionsCore, Windows::Graphics::Printing::IPrintTaskOptionsCoreUIConfiguration, Windows::Graphics::Printing::OptionDetails::IPrintTaskOptionDetails2>
{
    PrintTaskOptionDetails(std::nullptr_t) noexcept {}
    static Windows::Graphics::Printing::OptionDetails::PrintTaskOptionDetails GetFromPrintTaskOptions(Windows::Graphics::Printing::PrintTaskOptions const& printTaskOptions);
};

}
