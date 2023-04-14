// C++/WinRT v1.0.190111.3

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#pragma once

WINRT_EXPORT namespace winrt::Windows::Data::Html {

struct IHtmlUtilities;
struct HtmlUtilities;

}

namespace winrt::impl {

template <> struct category<Windows::Data::Html::IHtmlUtilities>{ using type = interface_category; };
template <> struct category<Windows::Data::Html::HtmlUtilities>{ using type = class_category; };
template <> struct name<Windows::Data::Html::IHtmlUtilities>{ static constexpr auto & value{ L"Windows.Data.Html.IHtmlUtilities" }; };
template <> struct name<Windows::Data::Html::HtmlUtilities>{ static constexpr auto & value{ L"Windows.Data.Html.HtmlUtilities" }; };
template <> struct guid_storage<Windows::Data::Html::IHtmlUtilities>{ static constexpr guid value{ 0xFEC00ADD,0x2399,0x4FAC,{ 0xB5,0xA7,0x05,0xE9,0xAC,0xD7,0x18,0x1D } }; };

template <> struct abi<Windows::Data::Html::IHtmlUtilities>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL ConvertToText(void* html, void** text) noexcept = 0;
};};

template <typename D>
struct consume_Windows_Data_Html_IHtmlUtilities
{
    hstring ConvertToText(param::hstring const& html) const;
};
template <> struct consume<Windows::Data::Html::IHtmlUtilities> { template <typename D> using type = consume_Windows_Data_Html_IHtmlUtilities<D>; };

}
