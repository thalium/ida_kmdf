// C++/WinRT v1.0.190111.3

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#pragma once

#include "winrt/base.h"

#include "winrt/Windows.Foundation.h"
#include "winrt/Windows.Foundation.Collections.h"
#include "winrt/impl/Windows.Graphics.Printing.2.h"
#include "winrt/impl/Windows.Storage.Streams.2.h"
#include "winrt/impl/Windows.Graphics.Printing.OptionDetails.2.h"
#include "winrt/Windows.Graphics.Printing.h"

namespace winrt::impl {

template <typename D> void consume_Windows_Graphics_Printing_OptionDetails_IPrintBindingOptionDetails<D>::WarningText(param::hstring const& value) const
{
    check_hresult(WINRT_SHIM(Windows::Graphics::Printing::OptionDetails::IPrintBindingOptionDetails)->put_WarningText(get_abi(value)));
}

template <typename D> hstring consume_Windows_Graphics_Printing_OptionDetails_IPrintBindingOptionDetails<D>::WarningText() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Graphics::Printing::OptionDetails::IPrintBindingOptionDetails)->get_WarningText(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_Graphics_Printing_OptionDetails_IPrintBindingOptionDetails<D>::Description(param::hstring const& value) const
{
    check_hresult(WINRT_SHIM(Windows::Graphics::Printing::OptionDetails::IPrintBindingOptionDetails)->put_Description(get_abi(value)));
}

template <typename D> hstring consume_Windows_Graphics_Printing_OptionDetails_IPrintBindingOptionDetails<D>::Description() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Graphics::Printing::OptionDetails::IPrintBindingOptionDetails)->get_Description(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_Graphics_Printing_OptionDetails_IPrintBorderingOptionDetails<D>::WarningText(param::hstring const& value) const
{
    check_hresult(WINRT_SHIM(Windows::Graphics::Printing::OptionDetails::IPrintBorderingOptionDetails)->put_WarningText(get_abi(value)));
}

template <typename D> hstring consume_Windows_Graphics_Printing_OptionDetails_IPrintBorderingOptionDetails<D>::WarningText() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Graphics::Printing::OptionDetails::IPrintBorderingOptionDetails)->get_WarningText(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_Graphics_Printing_OptionDetails_IPrintBorderingOptionDetails<D>::Description(param::hstring const& value) const
{
    check_hresult(WINRT_SHIM(Windows::Graphics::Printing::OptionDetails::IPrintBorderingOptionDetails)->put_Description(get_abi(value)));
}

template <typename D> hstring consume_Windows_Graphics_Printing_OptionDetails_IPrintBorderingOptionDetails<D>::Description() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Graphics::Printing::OptionDetails::IPrintBorderingOptionDetails)->get_Description(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_Graphics_Printing_OptionDetails_IPrintCollationOptionDetails<D>::WarningText(param::hstring const& value) const
{
    check_hresult(WINRT_SHIM(Windows::Graphics::Printing::OptionDetails::IPrintCollationOptionDetails)->put_WarningText(get_abi(value)));
}

template <typename D> hstring consume_Windows_Graphics_Printing_OptionDetails_IPrintCollationOptionDetails<D>::WarningText() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Graphics::Printing::OptionDetails::IPrintCollationOptionDetails)->get_WarningText(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_Graphics_Printing_OptionDetails_IPrintCollationOptionDetails<D>::Description(param::hstring const& value) const
{
    check_hresult(WINRT_SHIM(Windows::Graphics::Printing::OptionDetails::IPrintCollationOptionDetails)->put_Description(get_abi(value)));
}

template <typename D> hstring consume_Windows_Graphics_Printing_OptionDetails_IPrintCollationOptionDetails<D>::Description() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Graphics::Printing::OptionDetails::IPrintCollationOptionDetails)->get_Description(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_Graphics_Printing_OptionDetails_IPrintColorModeOptionDetails<D>::WarningText(param::hstring const& value) const
{
    check_hresult(WINRT_SHIM(Windows::Graphics::Printing::OptionDetails::IPrintColorModeOptionDetails)->put_WarningText(get_abi(value)));
}

template <typename D> hstring consume_Windows_Graphics_Printing_OptionDetails_IPrintColorModeOptionDetails<D>::WarningText() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Graphics::Printing::OptionDetails::IPrintColorModeOptionDetails)->get_WarningText(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_Graphics_Printing_OptionDetails_IPrintColorModeOptionDetails<D>::Description(param::hstring const& value) const
{
    check_hresult(WINRT_SHIM(Windows::Graphics::Printing::OptionDetails::IPrintColorModeOptionDetails)->put_Description(get_abi(value)));
}

template <typename D> hstring consume_Windows_Graphics_Printing_OptionDetails_IPrintColorModeOptionDetails<D>::Description() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Graphics::Printing::OptionDetails::IPrintColorModeOptionDetails)->get_Description(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_Graphics_Printing_OptionDetails_IPrintCopiesOptionDetails<D>::WarningText(param::hstring const& value) const
{
    check_hresult(WINRT_SHIM(Windows::Graphics::Printing::OptionDetails::IPrintCopiesOptionDetails)->put_WarningText(get_abi(value)));
}

template <typename D> hstring consume_Windows_Graphics_Printing_OptionDetails_IPrintCopiesOptionDetails<D>::WarningText() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Graphics::Printing::OptionDetails::IPrintCopiesOptionDetails)->get_WarningText(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_Graphics_Printing_OptionDetails_IPrintCopiesOptionDetails<D>::Description(param::hstring const& value) const
{
    check_hresult(WINRT_SHIM(Windows::Graphics::Printing::OptionDetails::IPrintCopiesOptionDetails)->put_Description(get_abi(value)));
}

template <typename D> hstring consume_Windows_Graphics_Printing_OptionDetails_IPrintCopiesOptionDetails<D>::Description() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Graphics::Printing::OptionDetails::IPrintCopiesOptionDetails)->get_Description(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_Graphics_Printing_OptionDetails_IPrintCustomItemDetails<D>::ItemId() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Graphics::Printing::OptionDetails::IPrintCustomItemDetails)->get_ItemId(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_Graphics_Printing_OptionDetails_IPrintCustomItemDetails<D>::ItemDisplayName(param::hstring const& value) const
{
    check_hresult(WINRT_SHIM(Windows::Graphics::Printing::OptionDetails::IPrintCustomItemDetails)->put_ItemDisplayName(get_abi(value)));
}

template <typename D> hstring consume_Windows_Graphics_Printing_OptionDetails_IPrintCustomItemDetails<D>::ItemDisplayName() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Graphics::Printing::OptionDetails::IPrintCustomItemDetails)->get_ItemDisplayName(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_Graphics_Printing_OptionDetails_IPrintCustomItemListOptionDetails<D>::AddItem(param::hstring const& itemId, param::hstring const& displayName) const
{
    check_hresult(WINRT_SHIM(Windows::Graphics::Printing::OptionDetails::IPrintCustomItemListOptionDetails)->AddItem(get_abi(itemId), get_abi(displayName)));
}

template <typename D> void consume_Windows_Graphics_Printing_OptionDetails_IPrintCustomItemListOptionDetails2<D>::AddItem(param::hstring const& itemId, param::hstring const& displayName, param::hstring const& description, Windows::Storage::Streams::IRandomAccessStreamWithContentType const& icon) const
{
    check_hresult(WINRT_SHIM(Windows::Graphics::Printing::OptionDetails::IPrintCustomItemListOptionDetails2)->AddItem(get_abi(itemId), get_abi(displayName), get_abi(description), get_abi(icon)));
}

template <typename D> void consume_Windows_Graphics_Printing_OptionDetails_IPrintCustomItemListOptionDetails3<D>::WarningText(param::hstring const& value) const
{
    check_hresult(WINRT_SHIM(Windows::Graphics::Printing::OptionDetails::IPrintCustomItemListOptionDetails3)->put_WarningText(get_abi(value)));
}

template <typename D> hstring consume_Windows_Graphics_Printing_OptionDetails_IPrintCustomItemListOptionDetails3<D>::WarningText() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Graphics::Printing::OptionDetails::IPrintCustomItemListOptionDetails3)->get_WarningText(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_Graphics_Printing_OptionDetails_IPrintCustomItemListOptionDetails3<D>::Description(param::hstring const& value) const
{
    check_hresult(WINRT_SHIM(Windows::Graphics::Printing::OptionDetails::IPrintCustomItemListOptionDetails3)->put_Description(get_abi(value)));
}

template <typename D> hstring consume_Windows_Graphics_Printing_OptionDetails_IPrintCustomItemListOptionDetails3<D>::Description() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Graphics::Printing::OptionDetails::IPrintCustomItemListOptionDetails3)->get_Description(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_Graphics_Printing_OptionDetails_IPrintCustomOptionDetails<D>::DisplayName(param::hstring const& value) const
{
    check_hresult(WINRT_SHIM(Windows::Graphics::Printing::OptionDetails::IPrintCustomOptionDetails)->put_DisplayName(get_abi(value)));
}

template <typename D> hstring consume_Windows_Graphics_Printing_OptionDetails_IPrintCustomOptionDetails<D>::DisplayName() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Graphics::Printing::OptionDetails::IPrintCustomOptionDetails)->get_DisplayName(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_Graphics_Printing_OptionDetails_IPrintCustomTextOptionDetails<D>::MaxCharacters(uint32_t value) const
{
    check_hresult(WINRT_SHIM(Windows::Graphics::Printing::OptionDetails::IPrintCustomTextOptionDetails)->put_MaxCharacters(value));
}

template <typename D> uint32_t consume_Windows_Graphics_Printing_OptionDetails_IPrintCustomTextOptionDetails<D>::MaxCharacters() const
{
    uint32_t value{};
    check_hresult(WINRT_SHIM(Windows::Graphics::Printing::OptionDetails::IPrintCustomTextOptionDetails)->get_MaxCharacters(&value));
    return value;
}

template <typename D> void consume_Windows_Graphics_Printing_OptionDetails_IPrintCustomTextOptionDetails2<D>::WarningText(param::hstring const& value) const
{
    check_hresult(WINRT_SHIM(Windows::Graphics::Printing::OptionDetails::IPrintCustomTextOptionDetails2)->put_WarningText(get_abi(value)));
}

template <typename D> hstring consume_Windows_Graphics_Printing_OptionDetails_IPrintCustomTextOptionDetails2<D>::WarningText() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Graphics::Printing::OptionDetails::IPrintCustomTextOptionDetails2)->get_WarningText(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_Graphics_Printing_OptionDetails_IPrintCustomTextOptionDetails2<D>::Description(param::hstring const& value) const
{
    check_hresult(WINRT_SHIM(Windows::Graphics::Printing::OptionDetails::IPrintCustomTextOptionDetails2)->put_Description(get_abi(value)));
}

template <typename D> hstring consume_Windows_Graphics_Printing_OptionDetails_IPrintCustomTextOptionDetails2<D>::Description() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Graphics::Printing::OptionDetails::IPrintCustomTextOptionDetails2)->get_Description(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_Graphics_Printing_OptionDetails_IPrintCustomToggleOptionDetails<D>::WarningText(param::hstring const& value) const
{
    check_hresult(WINRT_SHIM(Windows::Graphics::Printing::OptionDetails::IPrintCustomToggleOptionDetails)->put_WarningText(get_abi(value)));
}

template <typename D> hstring consume_Windows_Graphics_Printing_OptionDetails_IPrintCustomToggleOptionDetails<D>::WarningText() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Graphics::Printing::OptionDetails::IPrintCustomToggleOptionDetails)->get_WarningText(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_Graphics_Printing_OptionDetails_IPrintCustomToggleOptionDetails<D>::Description(param::hstring const& value) const
{
    check_hresult(WINRT_SHIM(Windows::Graphics::Printing::OptionDetails::IPrintCustomToggleOptionDetails)->put_Description(get_abi(value)));
}

template <typename D> hstring consume_Windows_Graphics_Printing_OptionDetails_IPrintCustomToggleOptionDetails<D>::Description() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Graphics::Printing::OptionDetails::IPrintCustomToggleOptionDetails)->get_Description(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_Graphics_Printing_OptionDetails_IPrintDuplexOptionDetails<D>::WarningText(param::hstring const& value) const
{
    check_hresult(WINRT_SHIM(Windows::Graphics::Printing::OptionDetails::IPrintDuplexOptionDetails)->put_WarningText(get_abi(value)));
}

template <typename D> hstring consume_Windows_Graphics_Printing_OptionDetails_IPrintDuplexOptionDetails<D>::WarningText() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Graphics::Printing::OptionDetails::IPrintDuplexOptionDetails)->get_WarningText(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_Graphics_Printing_OptionDetails_IPrintDuplexOptionDetails<D>::Description(param::hstring const& value) const
{
    check_hresult(WINRT_SHIM(Windows::Graphics::Printing::OptionDetails::IPrintDuplexOptionDetails)->put_Description(get_abi(value)));
}

template <typename D> hstring consume_Windows_Graphics_Printing_OptionDetails_IPrintDuplexOptionDetails<D>::Description() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Graphics::Printing::OptionDetails::IPrintDuplexOptionDetails)->get_Description(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_Graphics_Printing_OptionDetails_IPrintHolePunchOptionDetails<D>::WarningText(param::hstring const& value) const
{
    check_hresult(WINRT_SHIM(Windows::Graphics::Printing::OptionDetails::IPrintHolePunchOptionDetails)->put_WarningText(get_abi(value)));
}

template <typename D> hstring consume_Windows_Graphics_Printing_OptionDetails_IPrintHolePunchOptionDetails<D>::WarningText() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Graphics::Printing::OptionDetails::IPrintHolePunchOptionDetails)->get_WarningText(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_Graphics_Printing_OptionDetails_IPrintHolePunchOptionDetails<D>::Description(param::hstring const& value) const
{
    check_hresult(WINRT_SHIM(Windows::Graphics::Printing::OptionDetails::IPrintHolePunchOptionDetails)->put_Description(get_abi(value)));
}

template <typename D> hstring consume_Windows_Graphics_Printing_OptionDetails_IPrintHolePunchOptionDetails<D>::Description() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Graphics::Printing::OptionDetails::IPrintHolePunchOptionDetails)->get_Description(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::Collections::IVectorView<Windows::Foundation::IInspectable> consume_Windows_Graphics_Printing_OptionDetails_IPrintItemListOptionDetails<D>::Items() const
{
    Windows::Foundation::Collections::IVectorView<Windows::Foundation::IInspectable> value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Graphics::Printing::OptionDetails::IPrintItemListOptionDetails)->get_Items(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_Graphics_Printing_OptionDetails_IPrintMediaSizeOptionDetails<D>::WarningText(param::hstring const& value) const
{
    check_hresult(WINRT_SHIM(Windows::Graphics::Printing::OptionDetails::IPrintMediaSizeOptionDetails)->put_WarningText(get_abi(value)));
}

template <typename D> hstring consume_Windows_Graphics_Printing_OptionDetails_IPrintMediaSizeOptionDetails<D>::WarningText() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Graphics::Printing::OptionDetails::IPrintMediaSizeOptionDetails)->get_WarningText(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_Graphics_Printing_OptionDetails_IPrintMediaSizeOptionDetails<D>::Description(param::hstring const& value) const
{
    check_hresult(WINRT_SHIM(Windows::Graphics::Printing::OptionDetails::IPrintMediaSizeOptionDetails)->put_Description(get_abi(value)));
}

template <typename D> hstring consume_Windows_Graphics_Printing_OptionDetails_IPrintMediaSizeOptionDetails<D>::Description() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Graphics::Printing::OptionDetails::IPrintMediaSizeOptionDetails)->get_Description(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_Graphics_Printing_OptionDetails_IPrintMediaTypeOptionDetails<D>::WarningText(param::hstring const& value) const
{
    check_hresult(WINRT_SHIM(Windows::Graphics::Printing::OptionDetails::IPrintMediaTypeOptionDetails)->put_WarningText(get_abi(value)));
}

template <typename D> hstring consume_Windows_Graphics_Printing_OptionDetails_IPrintMediaTypeOptionDetails<D>::WarningText() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Graphics::Printing::OptionDetails::IPrintMediaTypeOptionDetails)->get_WarningText(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_Graphics_Printing_OptionDetails_IPrintMediaTypeOptionDetails<D>::Description(param::hstring const& value) const
{
    check_hresult(WINRT_SHIM(Windows::Graphics::Printing::OptionDetails::IPrintMediaTypeOptionDetails)->put_Description(get_abi(value)));
}

template <typename D> hstring consume_Windows_Graphics_Printing_OptionDetails_IPrintMediaTypeOptionDetails<D>::Description() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Graphics::Printing::OptionDetails::IPrintMediaTypeOptionDetails)->get_Description(put_abi(value)));
    return value;
}

template <typename D> uint32_t consume_Windows_Graphics_Printing_OptionDetails_IPrintNumberOptionDetails<D>::MinValue() const
{
    uint32_t value{};
    check_hresult(WINRT_SHIM(Windows::Graphics::Printing::OptionDetails::IPrintNumberOptionDetails)->get_MinValue(&value));
    return value;
}

template <typename D> uint32_t consume_Windows_Graphics_Printing_OptionDetails_IPrintNumberOptionDetails<D>::MaxValue() const
{
    uint32_t value{};
    check_hresult(WINRT_SHIM(Windows::Graphics::Printing::OptionDetails::IPrintNumberOptionDetails)->get_MaxValue(&value));
    return value;
}

template <typename D> hstring consume_Windows_Graphics_Printing_OptionDetails_IPrintOptionDetails<D>::OptionId() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Graphics::Printing::OptionDetails::IPrintOptionDetails)->get_OptionId(put_abi(value)));
    return value;
}

template <typename D> Windows::Graphics::Printing::OptionDetails::PrintOptionType consume_Windows_Graphics_Printing_OptionDetails_IPrintOptionDetails<D>::OptionType() const
{
    Windows::Graphics::Printing::OptionDetails::PrintOptionType value{};
    check_hresult(WINRT_SHIM(Windows::Graphics::Printing::OptionDetails::IPrintOptionDetails)->get_OptionType(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_Graphics_Printing_OptionDetails_IPrintOptionDetails<D>::ErrorText(param::hstring const& value) const
{
    check_hresult(WINRT_SHIM(Windows::Graphics::Printing::OptionDetails::IPrintOptionDetails)->put_ErrorText(get_abi(value)));
}

template <typename D> hstring consume_Windows_Graphics_Printing_OptionDetails_IPrintOptionDetails<D>::ErrorText() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Graphics::Printing::OptionDetails::IPrintOptionDetails)->get_ErrorText(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_Graphics_Printing_OptionDetails_IPrintOptionDetails<D>::State(Windows::Graphics::Printing::OptionDetails::PrintOptionStates const& value) const
{
    check_hresult(WINRT_SHIM(Windows::Graphics::Printing::OptionDetails::IPrintOptionDetails)->put_State(get_abi(value)));
}

template <typename D> Windows::Graphics::Printing::OptionDetails::PrintOptionStates consume_Windows_Graphics_Printing_OptionDetails_IPrintOptionDetails<D>::State() const
{
    Windows::Graphics::Printing::OptionDetails::PrintOptionStates value{};
    check_hresult(WINRT_SHIM(Windows::Graphics::Printing::OptionDetails::IPrintOptionDetails)->get_State(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::IInspectable consume_Windows_Graphics_Printing_OptionDetails_IPrintOptionDetails<D>::Value() const
{
    Windows::Foundation::IInspectable value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Graphics::Printing::OptionDetails::IPrintOptionDetails)->get_Value(put_abi(value)));
    return value;
}

template <typename D> bool consume_Windows_Graphics_Printing_OptionDetails_IPrintOptionDetails<D>::TrySetValue(Windows::Foundation::IInspectable const& value) const
{
    bool succeeded{};
    check_hresult(WINRT_SHIM(Windows::Graphics::Printing::OptionDetails::IPrintOptionDetails)->TrySetValue(get_abi(value), &succeeded));
    return succeeded;
}

template <typename D> void consume_Windows_Graphics_Printing_OptionDetails_IPrintOrientationOptionDetails<D>::WarningText(param::hstring const& value) const
{
    check_hresult(WINRT_SHIM(Windows::Graphics::Printing::OptionDetails::IPrintOrientationOptionDetails)->put_WarningText(get_abi(value)));
}

template <typename D> hstring consume_Windows_Graphics_Printing_OptionDetails_IPrintOrientationOptionDetails<D>::WarningText() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Graphics::Printing::OptionDetails::IPrintOrientationOptionDetails)->get_WarningText(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_Graphics_Printing_OptionDetails_IPrintOrientationOptionDetails<D>::Description(param::hstring const& value) const
{
    check_hresult(WINRT_SHIM(Windows::Graphics::Printing::OptionDetails::IPrintOrientationOptionDetails)->put_Description(get_abi(value)));
}

template <typename D> hstring consume_Windows_Graphics_Printing_OptionDetails_IPrintOrientationOptionDetails<D>::Description() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Graphics::Printing::OptionDetails::IPrintOrientationOptionDetails)->get_Description(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_Graphics_Printing_OptionDetails_IPrintPageRangeOptionDetails<D>::WarningText(param::hstring const& value) const
{
    check_hresult(WINRT_SHIM(Windows::Graphics::Printing::OptionDetails::IPrintPageRangeOptionDetails)->put_WarningText(get_abi(value)));
}

template <typename D> hstring consume_Windows_Graphics_Printing_OptionDetails_IPrintPageRangeOptionDetails<D>::WarningText() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Graphics::Printing::OptionDetails::IPrintPageRangeOptionDetails)->get_WarningText(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_Graphics_Printing_OptionDetails_IPrintPageRangeOptionDetails<D>::Description(param::hstring const& value) const
{
    check_hresult(WINRT_SHIM(Windows::Graphics::Printing::OptionDetails::IPrintPageRangeOptionDetails)->put_Description(get_abi(value)));
}

template <typename D> hstring consume_Windows_Graphics_Printing_OptionDetails_IPrintPageRangeOptionDetails<D>::Description() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Graphics::Printing::OptionDetails::IPrintPageRangeOptionDetails)->get_Description(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_Graphics_Printing_OptionDetails_IPrintQualityOptionDetails<D>::WarningText(param::hstring const& value) const
{
    check_hresult(WINRT_SHIM(Windows::Graphics::Printing::OptionDetails::IPrintQualityOptionDetails)->put_WarningText(get_abi(value)));
}

template <typename D> hstring consume_Windows_Graphics_Printing_OptionDetails_IPrintQualityOptionDetails<D>::WarningText() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Graphics::Printing::OptionDetails::IPrintQualityOptionDetails)->get_WarningText(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_Graphics_Printing_OptionDetails_IPrintQualityOptionDetails<D>::Description(param::hstring const& value) const
{
    check_hresult(WINRT_SHIM(Windows::Graphics::Printing::OptionDetails::IPrintQualityOptionDetails)->put_Description(get_abi(value)));
}

template <typename D> hstring consume_Windows_Graphics_Printing_OptionDetails_IPrintQualityOptionDetails<D>::Description() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Graphics::Printing::OptionDetails::IPrintQualityOptionDetails)->get_Description(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_Graphics_Printing_OptionDetails_IPrintStapleOptionDetails<D>::WarningText(param::hstring const& value) const
{
    check_hresult(WINRT_SHIM(Windows::Graphics::Printing::OptionDetails::IPrintStapleOptionDetails)->put_WarningText(get_abi(value)));
}

template <typename D> hstring consume_Windows_Graphics_Printing_OptionDetails_IPrintStapleOptionDetails<D>::WarningText() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Graphics::Printing::OptionDetails::IPrintStapleOptionDetails)->get_WarningText(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_Graphics_Printing_OptionDetails_IPrintStapleOptionDetails<D>::Description(param::hstring const& value) const
{
    check_hresult(WINRT_SHIM(Windows::Graphics::Printing::OptionDetails::IPrintStapleOptionDetails)->put_Description(get_abi(value)));
}

template <typename D> hstring consume_Windows_Graphics_Printing_OptionDetails_IPrintStapleOptionDetails<D>::Description() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Graphics::Printing::OptionDetails::IPrintStapleOptionDetails)->get_Description(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::IInspectable consume_Windows_Graphics_Printing_OptionDetails_IPrintTaskOptionChangedEventArgs<D>::OptionId() const
{
    Windows::Foundation::IInspectable value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Graphics::Printing::OptionDetails::IPrintTaskOptionChangedEventArgs)->get_OptionId(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::Collections::IMapView<hstring, Windows::Graphics::Printing::OptionDetails::IPrintOptionDetails> consume_Windows_Graphics_Printing_OptionDetails_IPrintTaskOptionDetails<D>::Options() const
{
    Windows::Foundation::Collections::IMapView<hstring, Windows::Graphics::Printing::OptionDetails::IPrintOptionDetails> value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Graphics::Printing::OptionDetails::IPrintTaskOptionDetails)->get_Options(put_abi(value)));
    return value;
}

template <typename D> Windows::Graphics::Printing::OptionDetails::PrintCustomItemListOptionDetails consume_Windows_Graphics_Printing_OptionDetails_IPrintTaskOptionDetails<D>::CreateItemListOption(param::hstring const& optionId, param::hstring const& displayName) const
{
    Windows::Graphics::Printing::OptionDetails::PrintCustomItemListOptionDetails itemListOption{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Graphics::Printing::OptionDetails::IPrintTaskOptionDetails)->CreateItemListOption(get_abi(optionId), get_abi(displayName), put_abi(itemListOption)));
    return itemListOption;
}

template <typename D> Windows::Graphics::Printing::OptionDetails::PrintCustomTextOptionDetails consume_Windows_Graphics_Printing_OptionDetails_IPrintTaskOptionDetails<D>::CreateTextOption(param::hstring const& optionId, param::hstring const& displayName) const
{
    Windows::Graphics::Printing::OptionDetails::PrintCustomTextOptionDetails textOption{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Graphics::Printing::OptionDetails::IPrintTaskOptionDetails)->CreateTextOption(get_abi(optionId), get_abi(displayName), put_abi(textOption)));
    return textOption;
}

template <typename D> winrt::event_token consume_Windows_Graphics_Printing_OptionDetails_IPrintTaskOptionDetails<D>::OptionChanged(Windows::Foundation::TypedEventHandler<Windows::Graphics::Printing::OptionDetails::PrintTaskOptionDetails, Windows::Graphics::Printing::OptionDetails::PrintTaskOptionChangedEventArgs> const& eventHandler) const
{
    winrt::event_token eventCookie{};
    check_hresult(WINRT_SHIM(Windows::Graphics::Printing::OptionDetails::IPrintTaskOptionDetails)->add_OptionChanged(get_abi(eventHandler), put_abi(eventCookie)));
    return eventCookie;
}

template <typename D> typename consume_Windows_Graphics_Printing_OptionDetails_IPrintTaskOptionDetails<D>::OptionChanged_revoker consume_Windows_Graphics_Printing_OptionDetails_IPrintTaskOptionDetails<D>::OptionChanged(auto_revoke_t, Windows::Foundation::TypedEventHandler<Windows::Graphics::Printing::OptionDetails::PrintTaskOptionDetails, Windows::Graphics::Printing::OptionDetails::PrintTaskOptionChangedEventArgs> const& eventHandler) const
{
    return impl::make_event_revoker<D, OptionChanged_revoker>(this, OptionChanged(eventHandler));
}

template <typename D> void consume_Windows_Graphics_Printing_OptionDetails_IPrintTaskOptionDetails<D>::OptionChanged(winrt::event_token const& eventCookie) const noexcept
{
    WINRT_VERIFY_(0, WINRT_SHIM(Windows::Graphics::Printing::OptionDetails::IPrintTaskOptionDetails)->remove_OptionChanged(get_abi(eventCookie)));
}

template <typename D> winrt::event_token consume_Windows_Graphics_Printing_OptionDetails_IPrintTaskOptionDetails<D>::BeginValidation(Windows::Foundation::TypedEventHandler<Windows::Graphics::Printing::OptionDetails::PrintTaskOptionDetails, Windows::Foundation::IInspectable> const& eventHandler) const
{
    winrt::event_token eventCookie{};
    check_hresult(WINRT_SHIM(Windows::Graphics::Printing::OptionDetails::IPrintTaskOptionDetails)->add_BeginValidation(get_abi(eventHandler), put_abi(eventCookie)));
    return eventCookie;
}

template <typename D> typename consume_Windows_Graphics_Printing_OptionDetails_IPrintTaskOptionDetails<D>::BeginValidation_revoker consume_Windows_Graphics_Printing_OptionDetails_IPrintTaskOptionDetails<D>::BeginValidation(auto_revoke_t, Windows::Foundation::TypedEventHandler<Windows::Graphics::Printing::OptionDetails::PrintTaskOptionDetails, Windows::Foundation::IInspectable> const& eventHandler) const
{
    return impl::make_event_revoker<D, BeginValidation_revoker>(this, BeginValidation(eventHandler));
}

template <typename D> void consume_Windows_Graphics_Printing_OptionDetails_IPrintTaskOptionDetails<D>::BeginValidation(winrt::event_token const& eventCookie) const noexcept
{
    WINRT_VERIFY_(0, WINRT_SHIM(Windows::Graphics::Printing::OptionDetails::IPrintTaskOptionDetails)->remove_BeginValidation(get_abi(eventCookie)));
}

template <typename D> Windows::Graphics::Printing::OptionDetails::PrintCustomToggleOptionDetails consume_Windows_Graphics_Printing_OptionDetails_IPrintTaskOptionDetails2<D>::CreateToggleOption(param::hstring const& optionId, param::hstring const& displayName) const
{
    Windows::Graphics::Printing::OptionDetails::PrintCustomToggleOptionDetails toggleOption{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Graphics::Printing::OptionDetails::IPrintTaskOptionDetails2)->CreateToggleOption(get_abi(optionId), get_abi(displayName), put_abi(toggleOption)));
    return toggleOption;
}

template <typename D> Windows::Graphics::Printing::OptionDetails::PrintTaskOptionDetails consume_Windows_Graphics_Printing_OptionDetails_IPrintTaskOptionDetailsStatic<D>::GetFromPrintTaskOptions(Windows::Graphics::Printing::PrintTaskOptions const& printTaskOptions) const
{
    Windows::Graphics::Printing::OptionDetails::PrintTaskOptionDetails printTaskOptionDetails{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Graphics::Printing::OptionDetails::IPrintTaskOptionDetailsStatic)->GetFromPrintTaskOptions(get_abi(printTaskOptions), put_abi(printTaskOptionDetails)));
    return printTaskOptionDetails;
}

template <typename D> uint32_t consume_Windows_Graphics_Printing_OptionDetails_IPrintTextOptionDetails<D>::MaxCharacters() const
{
    uint32_t value{};
    check_hresult(WINRT_SHIM(Windows::Graphics::Printing::OptionDetails::IPrintTextOptionDetails)->get_MaxCharacters(&value));
    return value;
}

template <typename D>
struct produce<D, Windows::Graphics::Printing::OptionDetails::IPrintBindingOptionDetails> : produce_base<D, Windows::Graphics::Printing::OptionDetails::IPrintBindingOptionDetails>
{
    int32_t WINRT_CALL put_WarningText(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(WarningText, WINRT_WRAP(void), hstring const&);
            this->shim().WarningText(*reinterpret_cast<hstring const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_WarningText(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(WarningText, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().WarningText());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_Description(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Description, WINRT_WRAP(void), hstring const&);
            this->shim().Description(*reinterpret_cast<hstring const*>(&value));
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
};

template <typename D>
struct produce<D, Windows::Graphics::Printing::OptionDetails::IPrintBorderingOptionDetails> : produce_base<D, Windows::Graphics::Printing::OptionDetails::IPrintBorderingOptionDetails>
{
    int32_t WINRT_CALL put_WarningText(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(WarningText, WINRT_WRAP(void), hstring const&);
            this->shim().WarningText(*reinterpret_cast<hstring const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_WarningText(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(WarningText, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().WarningText());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_Description(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Description, WINRT_WRAP(void), hstring const&);
            this->shim().Description(*reinterpret_cast<hstring const*>(&value));
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
};

template <typename D>
struct produce<D, Windows::Graphics::Printing::OptionDetails::IPrintCollationOptionDetails> : produce_base<D, Windows::Graphics::Printing::OptionDetails::IPrintCollationOptionDetails>
{
    int32_t WINRT_CALL put_WarningText(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(WarningText, WINRT_WRAP(void), hstring const&);
            this->shim().WarningText(*reinterpret_cast<hstring const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_WarningText(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(WarningText, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().WarningText());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_Description(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Description, WINRT_WRAP(void), hstring const&);
            this->shim().Description(*reinterpret_cast<hstring const*>(&value));
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
};

template <typename D>
struct produce<D, Windows::Graphics::Printing::OptionDetails::IPrintColorModeOptionDetails> : produce_base<D, Windows::Graphics::Printing::OptionDetails::IPrintColorModeOptionDetails>
{
    int32_t WINRT_CALL put_WarningText(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(WarningText, WINRT_WRAP(void), hstring const&);
            this->shim().WarningText(*reinterpret_cast<hstring const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_WarningText(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(WarningText, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().WarningText());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_Description(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Description, WINRT_WRAP(void), hstring const&);
            this->shim().Description(*reinterpret_cast<hstring const*>(&value));
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
};

template <typename D>
struct produce<D, Windows::Graphics::Printing::OptionDetails::IPrintCopiesOptionDetails> : produce_base<D, Windows::Graphics::Printing::OptionDetails::IPrintCopiesOptionDetails>
{
    int32_t WINRT_CALL put_WarningText(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(WarningText, WINRT_WRAP(void), hstring const&);
            this->shim().WarningText(*reinterpret_cast<hstring const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_WarningText(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(WarningText, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().WarningText());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_Description(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Description, WINRT_WRAP(void), hstring const&);
            this->shim().Description(*reinterpret_cast<hstring const*>(&value));
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
};

template <typename D>
struct produce<D, Windows::Graphics::Printing::OptionDetails::IPrintCustomItemDetails> : produce_base<D, Windows::Graphics::Printing::OptionDetails::IPrintCustomItemDetails>
{
    int32_t WINRT_CALL get_ItemId(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ItemId, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().ItemId());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_ItemDisplayName(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ItemDisplayName, WINRT_WRAP(void), hstring const&);
            this->shim().ItemDisplayName(*reinterpret_cast<hstring const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_ItemDisplayName(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ItemDisplayName, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().ItemDisplayName());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Graphics::Printing::OptionDetails::IPrintCustomItemListOptionDetails> : produce_base<D, Windows::Graphics::Printing::OptionDetails::IPrintCustomItemListOptionDetails>
{
    int32_t WINRT_CALL AddItem(void* itemId, void* displayName) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(AddItem, WINRT_WRAP(void), hstring const&, hstring const&);
            this->shim().AddItem(*reinterpret_cast<hstring const*>(&itemId), *reinterpret_cast<hstring const*>(&displayName));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Graphics::Printing::OptionDetails::IPrintCustomItemListOptionDetails2> : produce_base<D, Windows::Graphics::Printing::OptionDetails::IPrintCustomItemListOptionDetails2>
{
    int32_t WINRT_CALL AddItem(void* itemId, void* displayName, void* description, void* icon) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(AddItem, WINRT_WRAP(void), hstring const&, hstring const&, hstring const&, Windows::Storage::Streams::IRandomAccessStreamWithContentType const&);
            this->shim().AddItem(*reinterpret_cast<hstring const*>(&itemId), *reinterpret_cast<hstring const*>(&displayName), *reinterpret_cast<hstring const*>(&description), *reinterpret_cast<Windows::Storage::Streams::IRandomAccessStreamWithContentType const*>(&icon));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Graphics::Printing::OptionDetails::IPrintCustomItemListOptionDetails3> : produce_base<D, Windows::Graphics::Printing::OptionDetails::IPrintCustomItemListOptionDetails3>
{
    int32_t WINRT_CALL put_WarningText(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(WarningText, WINRT_WRAP(void), hstring const&);
            this->shim().WarningText(*reinterpret_cast<hstring const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_WarningText(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(WarningText, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().WarningText());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_Description(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Description, WINRT_WRAP(void), hstring const&);
            this->shim().Description(*reinterpret_cast<hstring const*>(&value));
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
};

template <typename D>
struct produce<D, Windows::Graphics::Printing::OptionDetails::IPrintCustomOptionDetails> : produce_base<D, Windows::Graphics::Printing::OptionDetails::IPrintCustomOptionDetails>
{
    int32_t WINRT_CALL put_DisplayName(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(DisplayName, WINRT_WRAP(void), hstring const&);
            this->shim().DisplayName(*reinterpret_cast<hstring const*>(&value));
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
};

template <typename D>
struct produce<D, Windows::Graphics::Printing::OptionDetails::IPrintCustomTextOptionDetails> : produce_base<D, Windows::Graphics::Printing::OptionDetails::IPrintCustomTextOptionDetails>
{
    int32_t WINRT_CALL put_MaxCharacters(uint32_t value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(MaxCharacters, WINRT_WRAP(void), uint32_t);
            this->shim().MaxCharacters(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_MaxCharacters(uint32_t* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(MaxCharacters, WINRT_WRAP(uint32_t));
            *value = detach_from<uint32_t>(this->shim().MaxCharacters());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Graphics::Printing::OptionDetails::IPrintCustomTextOptionDetails2> : produce_base<D, Windows::Graphics::Printing::OptionDetails::IPrintCustomTextOptionDetails2>
{
    int32_t WINRT_CALL put_WarningText(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(WarningText, WINRT_WRAP(void), hstring const&);
            this->shim().WarningText(*reinterpret_cast<hstring const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_WarningText(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(WarningText, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().WarningText());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_Description(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Description, WINRT_WRAP(void), hstring const&);
            this->shim().Description(*reinterpret_cast<hstring const*>(&value));
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
};

template <typename D>
struct produce<D, Windows::Graphics::Printing::OptionDetails::IPrintCustomToggleOptionDetails> : produce_base<D, Windows::Graphics::Printing::OptionDetails::IPrintCustomToggleOptionDetails>
{
    int32_t WINRT_CALL put_WarningText(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(WarningText, WINRT_WRAP(void), hstring const&);
            this->shim().WarningText(*reinterpret_cast<hstring const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_WarningText(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(WarningText, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().WarningText());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_Description(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Description, WINRT_WRAP(void), hstring const&);
            this->shim().Description(*reinterpret_cast<hstring const*>(&value));
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
};

template <typename D>
struct produce<D, Windows::Graphics::Printing::OptionDetails::IPrintDuplexOptionDetails> : produce_base<D, Windows::Graphics::Printing::OptionDetails::IPrintDuplexOptionDetails>
{
    int32_t WINRT_CALL put_WarningText(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(WarningText, WINRT_WRAP(void), hstring const&);
            this->shim().WarningText(*reinterpret_cast<hstring const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_WarningText(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(WarningText, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().WarningText());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_Description(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Description, WINRT_WRAP(void), hstring const&);
            this->shim().Description(*reinterpret_cast<hstring const*>(&value));
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
};

template <typename D>
struct produce<D, Windows::Graphics::Printing::OptionDetails::IPrintHolePunchOptionDetails> : produce_base<D, Windows::Graphics::Printing::OptionDetails::IPrintHolePunchOptionDetails>
{
    int32_t WINRT_CALL put_WarningText(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(WarningText, WINRT_WRAP(void), hstring const&);
            this->shim().WarningText(*reinterpret_cast<hstring const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_WarningText(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(WarningText, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().WarningText());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_Description(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Description, WINRT_WRAP(void), hstring const&);
            this->shim().Description(*reinterpret_cast<hstring const*>(&value));
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
};

template <typename D>
struct produce<D, Windows::Graphics::Printing::OptionDetails::IPrintItemListOptionDetails> : produce_base<D, Windows::Graphics::Printing::OptionDetails::IPrintItemListOptionDetails>
{
    int32_t WINRT_CALL get_Items(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Items, WINRT_WRAP(Windows::Foundation::Collections::IVectorView<Windows::Foundation::IInspectable>));
            *value = detach_from<Windows::Foundation::Collections::IVectorView<Windows::Foundation::IInspectable>>(this->shim().Items());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Graphics::Printing::OptionDetails::IPrintMediaSizeOptionDetails> : produce_base<D, Windows::Graphics::Printing::OptionDetails::IPrintMediaSizeOptionDetails>
{
    int32_t WINRT_CALL put_WarningText(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(WarningText, WINRT_WRAP(void), hstring const&);
            this->shim().WarningText(*reinterpret_cast<hstring const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_WarningText(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(WarningText, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().WarningText());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_Description(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Description, WINRT_WRAP(void), hstring const&);
            this->shim().Description(*reinterpret_cast<hstring const*>(&value));
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
};

template <typename D>
struct produce<D, Windows::Graphics::Printing::OptionDetails::IPrintMediaTypeOptionDetails> : produce_base<D, Windows::Graphics::Printing::OptionDetails::IPrintMediaTypeOptionDetails>
{
    int32_t WINRT_CALL put_WarningText(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(WarningText, WINRT_WRAP(void), hstring const&);
            this->shim().WarningText(*reinterpret_cast<hstring const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_WarningText(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(WarningText, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().WarningText());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_Description(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Description, WINRT_WRAP(void), hstring const&);
            this->shim().Description(*reinterpret_cast<hstring const*>(&value));
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
};

template <typename D>
struct produce<D, Windows::Graphics::Printing::OptionDetails::IPrintNumberOptionDetails> : produce_base<D, Windows::Graphics::Printing::OptionDetails::IPrintNumberOptionDetails>
{
    int32_t WINRT_CALL get_MinValue(uint32_t* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(MinValue, WINRT_WRAP(uint32_t));
            *value = detach_from<uint32_t>(this->shim().MinValue());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_MaxValue(uint32_t* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(MaxValue, WINRT_WRAP(uint32_t));
            *value = detach_from<uint32_t>(this->shim().MaxValue());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Graphics::Printing::OptionDetails::IPrintOptionDetails> : produce_base<D, Windows::Graphics::Printing::OptionDetails::IPrintOptionDetails>
{
    int32_t WINRT_CALL get_OptionId(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(OptionId, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().OptionId());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_OptionType(Windows::Graphics::Printing::OptionDetails::PrintOptionType* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(OptionType, WINRT_WRAP(Windows::Graphics::Printing::OptionDetails::PrintOptionType));
            *value = detach_from<Windows::Graphics::Printing::OptionDetails::PrintOptionType>(this->shim().OptionType());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_ErrorText(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ErrorText, WINRT_WRAP(void), hstring const&);
            this->shim().ErrorText(*reinterpret_cast<hstring const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_ErrorText(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ErrorText, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().ErrorText());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_State(Windows::Graphics::Printing::OptionDetails::PrintOptionStates value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(State, WINRT_WRAP(void), Windows::Graphics::Printing::OptionDetails::PrintOptionStates const&);
            this->shim().State(*reinterpret_cast<Windows::Graphics::Printing::OptionDetails::PrintOptionStates const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_State(Windows::Graphics::Printing::OptionDetails::PrintOptionStates* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(State, WINRT_WRAP(Windows::Graphics::Printing::OptionDetails::PrintOptionStates));
            *value = detach_from<Windows::Graphics::Printing::OptionDetails::PrintOptionStates>(this->shim().State());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Value(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Value, WINRT_WRAP(Windows::Foundation::IInspectable));
            *value = detach_from<Windows::Foundation::IInspectable>(this->shim().Value());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL TrySetValue(void* value, bool* succeeded) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(TrySetValue, WINRT_WRAP(bool), Windows::Foundation::IInspectable const&);
            *succeeded = detach_from<bool>(this->shim().TrySetValue(*reinterpret_cast<Windows::Foundation::IInspectable const*>(&value)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Graphics::Printing::OptionDetails::IPrintOrientationOptionDetails> : produce_base<D, Windows::Graphics::Printing::OptionDetails::IPrintOrientationOptionDetails>
{
    int32_t WINRT_CALL put_WarningText(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(WarningText, WINRT_WRAP(void), hstring const&);
            this->shim().WarningText(*reinterpret_cast<hstring const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_WarningText(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(WarningText, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().WarningText());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_Description(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Description, WINRT_WRAP(void), hstring const&);
            this->shim().Description(*reinterpret_cast<hstring const*>(&value));
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
};

template <typename D>
struct produce<D, Windows::Graphics::Printing::OptionDetails::IPrintPageRangeOptionDetails> : produce_base<D, Windows::Graphics::Printing::OptionDetails::IPrintPageRangeOptionDetails>
{
    int32_t WINRT_CALL put_WarningText(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(WarningText, WINRT_WRAP(void), hstring const&);
            this->shim().WarningText(*reinterpret_cast<hstring const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_WarningText(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(WarningText, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().WarningText());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_Description(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Description, WINRT_WRAP(void), hstring const&);
            this->shim().Description(*reinterpret_cast<hstring const*>(&value));
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
};

template <typename D>
struct produce<D, Windows::Graphics::Printing::OptionDetails::IPrintQualityOptionDetails> : produce_base<D, Windows::Graphics::Printing::OptionDetails::IPrintQualityOptionDetails>
{
    int32_t WINRT_CALL put_WarningText(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(WarningText, WINRT_WRAP(void), hstring const&);
            this->shim().WarningText(*reinterpret_cast<hstring const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_WarningText(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(WarningText, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().WarningText());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_Description(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Description, WINRT_WRAP(void), hstring const&);
            this->shim().Description(*reinterpret_cast<hstring const*>(&value));
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
};

template <typename D>
struct produce<D, Windows::Graphics::Printing::OptionDetails::IPrintStapleOptionDetails> : produce_base<D, Windows::Graphics::Printing::OptionDetails::IPrintStapleOptionDetails>
{
    int32_t WINRT_CALL put_WarningText(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(WarningText, WINRT_WRAP(void), hstring const&);
            this->shim().WarningText(*reinterpret_cast<hstring const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_WarningText(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(WarningText, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().WarningText());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_Description(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Description, WINRT_WRAP(void), hstring const&);
            this->shim().Description(*reinterpret_cast<hstring const*>(&value));
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
};

template <typename D>
struct produce<D, Windows::Graphics::Printing::OptionDetails::IPrintTaskOptionChangedEventArgs> : produce_base<D, Windows::Graphics::Printing::OptionDetails::IPrintTaskOptionChangedEventArgs>
{
    int32_t WINRT_CALL get_OptionId(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(OptionId, WINRT_WRAP(Windows::Foundation::IInspectable));
            *value = detach_from<Windows::Foundation::IInspectable>(this->shim().OptionId());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Graphics::Printing::OptionDetails::IPrintTaskOptionDetails> : produce_base<D, Windows::Graphics::Printing::OptionDetails::IPrintTaskOptionDetails>
{
    int32_t WINRT_CALL get_Options(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Options, WINRT_WRAP(Windows::Foundation::Collections::IMapView<hstring, Windows::Graphics::Printing::OptionDetails::IPrintOptionDetails>));
            *value = detach_from<Windows::Foundation::Collections::IMapView<hstring, Windows::Graphics::Printing::OptionDetails::IPrintOptionDetails>>(this->shim().Options());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL CreateItemListOption(void* optionId, void* displayName, void** itemListOption) noexcept final
    {
        try
        {
            *itemListOption = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CreateItemListOption, WINRT_WRAP(Windows::Graphics::Printing::OptionDetails::PrintCustomItemListOptionDetails), hstring const&, hstring const&);
            *itemListOption = detach_from<Windows::Graphics::Printing::OptionDetails::PrintCustomItemListOptionDetails>(this->shim().CreateItemListOption(*reinterpret_cast<hstring const*>(&optionId), *reinterpret_cast<hstring const*>(&displayName)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL CreateTextOption(void* optionId, void* displayName, void** textOption) noexcept final
    {
        try
        {
            *textOption = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CreateTextOption, WINRT_WRAP(Windows::Graphics::Printing::OptionDetails::PrintCustomTextOptionDetails), hstring const&, hstring const&);
            *textOption = detach_from<Windows::Graphics::Printing::OptionDetails::PrintCustomTextOptionDetails>(this->shim().CreateTextOption(*reinterpret_cast<hstring const*>(&optionId), *reinterpret_cast<hstring const*>(&displayName)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL add_OptionChanged(void* eventHandler, winrt::event_token* eventCookie) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(OptionChanged, WINRT_WRAP(winrt::event_token), Windows::Foundation::TypedEventHandler<Windows::Graphics::Printing::OptionDetails::PrintTaskOptionDetails, Windows::Graphics::Printing::OptionDetails::PrintTaskOptionChangedEventArgs> const&);
            *eventCookie = detach_from<winrt::event_token>(this->shim().OptionChanged(*reinterpret_cast<Windows::Foundation::TypedEventHandler<Windows::Graphics::Printing::OptionDetails::PrintTaskOptionDetails, Windows::Graphics::Printing::OptionDetails::PrintTaskOptionChangedEventArgs> const*>(&eventHandler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL remove_OptionChanged(winrt::event_token eventCookie) noexcept final
    {
        typename D::abi_guard guard(this->shim());
        WINRT_ASSERT_DECLARATION(OptionChanged, WINRT_WRAP(void), winrt::event_token const&);
        this->shim().OptionChanged(*reinterpret_cast<winrt::event_token const*>(&eventCookie));
        return 0;
    }

    int32_t WINRT_CALL add_BeginValidation(void* eventHandler, winrt::event_token* eventCookie) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(BeginValidation, WINRT_WRAP(winrt::event_token), Windows::Foundation::TypedEventHandler<Windows::Graphics::Printing::OptionDetails::PrintTaskOptionDetails, Windows::Foundation::IInspectable> const&);
            *eventCookie = detach_from<winrt::event_token>(this->shim().BeginValidation(*reinterpret_cast<Windows::Foundation::TypedEventHandler<Windows::Graphics::Printing::OptionDetails::PrintTaskOptionDetails, Windows::Foundation::IInspectable> const*>(&eventHandler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL remove_BeginValidation(winrt::event_token eventCookie) noexcept final
    {
        typename D::abi_guard guard(this->shim());
        WINRT_ASSERT_DECLARATION(BeginValidation, WINRT_WRAP(void), winrt::event_token const&);
        this->shim().BeginValidation(*reinterpret_cast<winrt::event_token const*>(&eventCookie));
        return 0;
    }
};

template <typename D>
struct produce<D, Windows::Graphics::Printing::OptionDetails::IPrintTaskOptionDetails2> : produce_base<D, Windows::Graphics::Printing::OptionDetails::IPrintTaskOptionDetails2>
{
    int32_t WINRT_CALL CreateToggleOption(void* optionId, void* displayName, void** toggleOption) noexcept final
    {
        try
        {
            *toggleOption = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CreateToggleOption, WINRT_WRAP(Windows::Graphics::Printing::OptionDetails::PrintCustomToggleOptionDetails), hstring const&, hstring const&);
            *toggleOption = detach_from<Windows::Graphics::Printing::OptionDetails::PrintCustomToggleOptionDetails>(this->shim().CreateToggleOption(*reinterpret_cast<hstring const*>(&optionId), *reinterpret_cast<hstring const*>(&displayName)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Graphics::Printing::OptionDetails::IPrintTaskOptionDetailsStatic> : produce_base<D, Windows::Graphics::Printing::OptionDetails::IPrintTaskOptionDetailsStatic>
{
    int32_t WINRT_CALL GetFromPrintTaskOptions(void* printTaskOptions, void** printTaskOptionDetails) noexcept final
    {
        try
        {
            *printTaskOptionDetails = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetFromPrintTaskOptions, WINRT_WRAP(Windows::Graphics::Printing::OptionDetails::PrintTaskOptionDetails), Windows::Graphics::Printing::PrintTaskOptions const&);
            *printTaskOptionDetails = detach_from<Windows::Graphics::Printing::OptionDetails::PrintTaskOptionDetails>(this->shim().GetFromPrintTaskOptions(*reinterpret_cast<Windows::Graphics::Printing::PrintTaskOptions const*>(&printTaskOptions)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Graphics::Printing::OptionDetails::IPrintTextOptionDetails> : produce_base<D, Windows::Graphics::Printing::OptionDetails::IPrintTextOptionDetails>
{
    int32_t WINRT_CALL get_MaxCharacters(uint32_t* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(MaxCharacters, WINRT_WRAP(uint32_t));
            *value = detach_from<uint32_t>(this->shim().MaxCharacters());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

}

WINRT_EXPORT namespace winrt::Windows::Graphics::Printing::OptionDetails {

inline Windows::Graphics::Printing::OptionDetails::PrintTaskOptionDetails PrintTaskOptionDetails::GetFromPrintTaskOptions(Windows::Graphics::Printing::PrintTaskOptions const& printTaskOptions)
{
    return impl::call_factory<PrintTaskOptionDetails, Windows::Graphics::Printing::OptionDetails::IPrintTaskOptionDetailsStatic>([&](auto&& f) { return f.GetFromPrintTaskOptions(printTaskOptions); });
}

}

WINRT_EXPORT namespace std {

template<> struct hash<winrt::Windows::Graphics::Printing::OptionDetails::IPrintBindingOptionDetails> : winrt::impl::hash_base<winrt::Windows::Graphics::Printing::OptionDetails::IPrintBindingOptionDetails> {};
template<> struct hash<winrt::Windows::Graphics::Printing::OptionDetails::IPrintBorderingOptionDetails> : winrt::impl::hash_base<winrt::Windows::Graphics::Printing::OptionDetails::IPrintBorderingOptionDetails> {};
template<> struct hash<winrt::Windows::Graphics::Printing::OptionDetails::IPrintCollationOptionDetails> : winrt::impl::hash_base<winrt::Windows::Graphics::Printing::OptionDetails::IPrintCollationOptionDetails> {};
template<> struct hash<winrt::Windows::Graphics::Printing::OptionDetails::IPrintColorModeOptionDetails> : winrt::impl::hash_base<winrt::Windows::Graphics::Printing::OptionDetails::IPrintColorModeOptionDetails> {};
template<> struct hash<winrt::Windows::Graphics::Printing::OptionDetails::IPrintCopiesOptionDetails> : winrt::impl::hash_base<winrt::Windows::Graphics::Printing::OptionDetails::IPrintCopiesOptionDetails> {};
template<> struct hash<winrt::Windows::Graphics::Printing::OptionDetails::IPrintCustomItemDetails> : winrt::impl::hash_base<winrt::Windows::Graphics::Printing::OptionDetails::IPrintCustomItemDetails> {};
template<> struct hash<winrt::Windows::Graphics::Printing::OptionDetails::IPrintCustomItemListOptionDetails> : winrt::impl::hash_base<winrt::Windows::Graphics::Printing::OptionDetails::IPrintCustomItemListOptionDetails> {};
template<> struct hash<winrt::Windows::Graphics::Printing::OptionDetails::IPrintCustomItemListOptionDetails2> : winrt::impl::hash_base<winrt::Windows::Graphics::Printing::OptionDetails::IPrintCustomItemListOptionDetails2> {};
template<> struct hash<winrt::Windows::Graphics::Printing::OptionDetails::IPrintCustomItemListOptionDetails3> : winrt::impl::hash_base<winrt::Windows::Graphics::Printing::OptionDetails::IPrintCustomItemListOptionDetails3> {};
template<> struct hash<winrt::Windows::Graphics::Printing::OptionDetails::IPrintCustomOptionDetails> : winrt::impl::hash_base<winrt::Windows::Graphics::Printing::OptionDetails::IPrintCustomOptionDetails> {};
template<> struct hash<winrt::Windows::Graphics::Printing::OptionDetails::IPrintCustomTextOptionDetails> : winrt::impl::hash_base<winrt::Windows::Graphics::Printing::OptionDetails::IPrintCustomTextOptionDetails> {};
template<> struct hash<winrt::Windows::Graphics::Printing::OptionDetails::IPrintCustomTextOptionDetails2> : winrt::impl::hash_base<winrt::Windows::Graphics::Printing::OptionDetails::IPrintCustomTextOptionDetails2> {};
template<> struct hash<winrt::Windows::Graphics::Printing::OptionDetails::IPrintCustomToggleOptionDetails> : winrt::impl::hash_base<winrt::Windows::Graphics::Printing::OptionDetails::IPrintCustomToggleOptionDetails> {};
template<> struct hash<winrt::Windows::Graphics::Printing::OptionDetails::IPrintDuplexOptionDetails> : winrt::impl::hash_base<winrt::Windows::Graphics::Printing::OptionDetails::IPrintDuplexOptionDetails> {};
template<> struct hash<winrt::Windows::Graphics::Printing::OptionDetails::IPrintHolePunchOptionDetails> : winrt::impl::hash_base<winrt::Windows::Graphics::Printing::OptionDetails::IPrintHolePunchOptionDetails> {};
template<> struct hash<winrt::Windows::Graphics::Printing::OptionDetails::IPrintItemListOptionDetails> : winrt::impl::hash_base<winrt::Windows::Graphics::Printing::OptionDetails::IPrintItemListOptionDetails> {};
template<> struct hash<winrt::Windows::Graphics::Printing::OptionDetails::IPrintMediaSizeOptionDetails> : winrt::impl::hash_base<winrt::Windows::Graphics::Printing::OptionDetails::IPrintMediaSizeOptionDetails> {};
template<> struct hash<winrt::Windows::Graphics::Printing::OptionDetails::IPrintMediaTypeOptionDetails> : winrt::impl::hash_base<winrt::Windows::Graphics::Printing::OptionDetails::IPrintMediaTypeOptionDetails> {};
template<> struct hash<winrt::Windows::Graphics::Printing::OptionDetails::IPrintNumberOptionDetails> : winrt::impl::hash_base<winrt::Windows::Graphics::Printing::OptionDetails::IPrintNumberOptionDetails> {};
template<> struct hash<winrt::Windows::Graphics::Printing::OptionDetails::IPrintOptionDetails> : winrt::impl::hash_base<winrt::Windows::Graphics::Printing::OptionDetails::IPrintOptionDetails> {};
template<> struct hash<winrt::Windows::Graphics::Printing::OptionDetails::IPrintOrientationOptionDetails> : winrt::impl::hash_base<winrt::Windows::Graphics::Printing::OptionDetails::IPrintOrientationOptionDetails> {};
template<> struct hash<winrt::Windows::Graphics::Printing::OptionDetails::IPrintPageRangeOptionDetails> : winrt::impl::hash_base<winrt::Windows::Graphics::Printing::OptionDetails::IPrintPageRangeOptionDetails> {};
template<> struct hash<winrt::Windows::Graphics::Printing::OptionDetails::IPrintQualityOptionDetails> : winrt::impl::hash_base<winrt::Windows::Graphics::Printing::OptionDetails::IPrintQualityOptionDetails> {};
template<> struct hash<winrt::Windows::Graphics::Printing::OptionDetails::IPrintStapleOptionDetails> : winrt::impl::hash_base<winrt::Windows::Graphics::Printing::OptionDetails::IPrintStapleOptionDetails> {};
template<> struct hash<winrt::Windows::Graphics::Printing::OptionDetails::IPrintTaskOptionChangedEventArgs> : winrt::impl::hash_base<winrt::Windows::Graphics::Printing::OptionDetails::IPrintTaskOptionChangedEventArgs> {};
template<> struct hash<winrt::Windows::Graphics::Printing::OptionDetails::IPrintTaskOptionDetails> : winrt::impl::hash_base<winrt::Windows::Graphics::Printing::OptionDetails::IPrintTaskOptionDetails> {};
template<> struct hash<winrt::Windows::Graphics::Printing::OptionDetails::IPrintTaskOptionDetails2> : winrt::impl::hash_base<winrt::Windows::Graphics::Printing::OptionDetails::IPrintTaskOptionDetails2> {};
template<> struct hash<winrt::Windows::Graphics::Printing::OptionDetails::IPrintTaskOptionDetailsStatic> : winrt::impl::hash_base<winrt::Windows::Graphics::Printing::OptionDetails::IPrintTaskOptionDetailsStatic> {};
template<> struct hash<winrt::Windows::Graphics::Printing::OptionDetails::IPrintTextOptionDetails> : winrt::impl::hash_base<winrt::Windows::Graphics::Printing::OptionDetails::IPrintTextOptionDetails> {};
template<> struct hash<winrt::Windows::Graphics::Printing::OptionDetails::PrintBindingOptionDetails> : winrt::impl::hash_base<winrt::Windows::Graphics::Printing::OptionDetails::PrintBindingOptionDetails> {};
template<> struct hash<winrt::Windows::Graphics::Printing::OptionDetails::PrintBorderingOptionDetails> : winrt::impl::hash_base<winrt::Windows::Graphics::Printing::OptionDetails::PrintBorderingOptionDetails> {};
template<> struct hash<winrt::Windows::Graphics::Printing::OptionDetails::PrintCollationOptionDetails> : winrt::impl::hash_base<winrt::Windows::Graphics::Printing::OptionDetails::PrintCollationOptionDetails> {};
template<> struct hash<winrt::Windows::Graphics::Printing::OptionDetails::PrintColorModeOptionDetails> : winrt::impl::hash_base<winrt::Windows::Graphics::Printing::OptionDetails::PrintColorModeOptionDetails> {};
template<> struct hash<winrt::Windows::Graphics::Printing::OptionDetails::PrintCopiesOptionDetails> : winrt::impl::hash_base<winrt::Windows::Graphics::Printing::OptionDetails::PrintCopiesOptionDetails> {};
template<> struct hash<winrt::Windows::Graphics::Printing::OptionDetails::PrintCustomItemDetails> : winrt::impl::hash_base<winrt::Windows::Graphics::Printing::OptionDetails::PrintCustomItemDetails> {};
template<> struct hash<winrt::Windows::Graphics::Printing::OptionDetails::PrintCustomItemListOptionDetails> : winrt::impl::hash_base<winrt::Windows::Graphics::Printing::OptionDetails::PrintCustomItemListOptionDetails> {};
template<> struct hash<winrt::Windows::Graphics::Printing::OptionDetails::PrintCustomTextOptionDetails> : winrt::impl::hash_base<winrt::Windows::Graphics::Printing::OptionDetails::PrintCustomTextOptionDetails> {};
template<> struct hash<winrt::Windows::Graphics::Printing::OptionDetails::PrintCustomToggleOptionDetails> : winrt::impl::hash_base<winrt::Windows::Graphics::Printing::OptionDetails::PrintCustomToggleOptionDetails> {};
template<> struct hash<winrt::Windows::Graphics::Printing::OptionDetails::PrintDuplexOptionDetails> : winrt::impl::hash_base<winrt::Windows::Graphics::Printing::OptionDetails::PrintDuplexOptionDetails> {};
template<> struct hash<winrt::Windows::Graphics::Printing::OptionDetails::PrintHolePunchOptionDetails> : winrt::impl::hash_base<winrt::Windows::Graphics::Printing::OptionDetails::PrintHolePunchOptionDetails> {};
template<> struct hash<winrt::Windows::Graphics::Printing::OptionDetails::PrintMediaSizeOptionDetails> : winrt::impl::hash_base<winrt::Windows::Graphics::Printing::OptionDetails::PrintMediaSizeOptionDetails> {};
template<> struct hash<winrt::Windows::Graphics::Printing::OptionDetails::PrintMediaTypeOptionDetails> : winrt::impl::hash_base<winrt::Windows::Graphics::Printing::OptionDetails::PrintMediaTypeOptionDetails> {};
template<> struct hash<winrt::Windows::Graphics::Printing::OptionDetails::PrintOrientationOptionDetails> : winrt::impl::hash_base<winrt::Windows::Graphics::Printing::OptionDetails::PrintOrientationOptionDetails> {};
template<> struct hash<winrt::Windows::Graphics::Printing::OptionDetails::PrintPageRangeOptionDetails> : winrt::impl::hash_base<winrt::Windows::Graphics::Printing::OptionDetails::PrintPageRangeOptionDetails> {};
template<> struct hash<winrt::Windows::Graphics::Printing::OptionDetails::PrintQualityOptionDetails> : winrt::impl::hash_base<winrt::Windows::Graphics::Printing::OptionDetails::PrintQualityOptionDetails> {};
template<> struct hash<winrt::Windows::Graphics::Printing::OptionDetails::PrintStapleOptionDetails> : winrt::impl::hash_base<winrt::Windows::Graphics::Printing::OptionDetails::PrintStapleOptionDetails> {};
template<> struct hash<winrt::Windows::Graphics::Printing::OptionDetails::PrintTaskOptionChangedEventArgs> : winrt::impl::hash_base<winrt::Windows::Graphics::Printing::OptionDetails::PrintTaskOptionChangedEventArgs> {};
template<> struct hash<winrt::Windows::Graphics::Printing::OptionDetails::PrintTaskOptionDetails> : winrt::impl::hash_base<winrt::Windows::Graphics::Printing::OptionDetails::PrintTaskOptionDetails> {};

}
