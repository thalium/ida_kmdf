// C++/WinRT v1.0.190111.3

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#pragma once

#include "winrt/base.h"

#include "winrt/impl/Windows.Foundation.Collections.2.h"
#include "winrt/impl/Windows.Foundation.2.h"

namespace winrt::impl {

template <typename D> void consume_Windows_Foundation_IClosable<D>::Close() const
{
    check_hresult(WINRT_SHIM(Windows::Foundation::IClosable)->Close());
}

template <typename D> void consume_Windows_Foundation_IDeferral<D>::Complete() const
{
    check_hresult(WINRT_SHIM(Windows::Foundation::IDeferral)->Complete());
}

template <typename D> Windows::Foundation::Deferral consume_Windows_Foundation_IDeferralFactory<D>::Create(Windows::Foundation::DeferralCompletedHandler const& handler) const
{
    Windows::Foundation::Deferral result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Foundation::IDeferralFactory)->Create(get_abi(handler), put_abi(result)));
    return result;
}

template <typename D> Windows::Foundation::IInspectable consume_Windows_Foundation_IGetActivationFactory<D>::GetActivationFactory(param::hstring const& activatableClassId) const
{
    Windows::Foundation::IInspectable factory{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Foundation::IGetActivationFactory)->GetActivationFactory(get_abi(activatableClassId), put_abi(factory)));
    return factory;
}

template <typename D> winrt::guid consume_Windows_Foundation_IGuidHelperStatics<D>::CreateNewGuid() const
{
    winrt::guid result{};
    check_hresult(WINRT_SHIM(Windows::Foundation::IGuidHelperStatics)->CreateNewGuid(put_abi(result)));
    return result;
}

template <typename D> winrt::guid consume_Windows_Foundation_IGuidHelperStatics<D>::Empty() const
{
    winrt::guid value{};
    check_hresult(WINRT_SHIM(Windows::Foundation::IGuidHelperStatics)->get_Empty(put_abi(value)));
    return value;
}

template <typename D> bool consume_Windows_Foundation_IGuidHelperStatics<D>::Equals(winrt::guid const& target, winrt::guid const& value) const
{
    bool result{};
    check_hresult(WINRT_SHIM(Windows::Foundation::IGuidHelperStatics)->Equals(get_abi(target), get_abi(value), &result));
    return result;
}

template <typename D> Windows::Foundation::IMemoryBufferReference consume_Windows_Foundation_IMemoryBuffer<D>::CreateReference() const
{
    Windows::Foundation::IMemoryBufferReference reference{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Foundation::IMemoryBuffer)->CreateReference(put_abi(reference)));
    return reference;
}

template <typename D> Windows::Foundation::MemoryBuffer consume_Windows_Foundation_IMemoryBufferFactory<D>::Create(uint32_t capacity) const
{
    Windows::Foundation::MemoryBuffer value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Foundation::IMemoryBufferFactory)->Create(capacity, put_abi(value)));
    return value;
}

template <typename D> uint32_t consume_Windows_Foundation_IMemoryBufferReference<D>::Capacity() const
{
    uint32_t value{};
    check_hresult(WINRT_SHIM(Windows::Foundation::IMemoryBufferReference)->get_Capacity(&value));
    return value;
}

template <typename D> winrt::event_token consume_Windows_Foundation_IMemoryBufferReference<D>::Closed(Windows::Foundation::TypedEventHandler<Windows::Foundation::IMemoryBufferReference, Windows::Foundation::IInspectable> const& handler) const
{
    winrt::event_token cookie{};
    check_hresult(WINRT_SHIM(Windows::Foundation::IMemoryBufferReference)->add_Closed(get_abi(handler), put_abi(cookie)));
    return cookie;
}

template <typename D> typename consume_Windows_Foundation_IMemoryBufferReference<D>::Closed_revoker consume_Windows_Foundation_IMemoryBufferReference<D>::Closed(auto_revoke_t, Windows::Foundation::TypedEventHandler<Windows::Foundation::IMemoryBufferReference, Windows::Foundation::IInspectable> const& handler) const
{
    return impl::make_event_revoker<D, Closed_revoker>(this, Closed(handler));
}

template <typename D> void consume_Windows_Foundation_IMemoryBufferReference<D>::Closed(winrt::event_token const& cookie) const noexcept
{
    WINRT_VERIFY_(0, WINRT_SHIM(Windows::Foundation::IMemoryBufferReference)->remove_Closed(get_abi(cookie)));
}

template <typename D> Windows::Foundation::PropertyType consume_Windows_Foundation_IPropertyValue<D>::Type() const
{
    Windows::Foundation::PropertyType value{};
    check_hresult(WINRT_SHIM(Windows::Foundation::IPropertyValue)->get_Type(put_abi(value)));
    return value;
}

template <typename D> bool consume_Windows_Foundation_IPropertyValue<D>::IsNumericScalar() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::Foundation::IPropertyValue)->get_IsNumericScalar(&value));
    return value;
}

template <typename D> uint8_t consume_Windows_Foundation_IPropertyValue<D>::GetUInt8() const
{
    uint8_t value{};
    check_hresult(WINRT_SHIM(Windows::Foundation::IPropertyValue)->GetUInt8(&value));
    return value;
}

template <typename D> int16_t consume_Windows_Foundation_IPropertyValue<D>::GetInt16() const
{
    int16_t value{};
    check_hresult(WINRT_SHIM(Windows::Foundation::IPropertyValue)->GetInt16(&value));
    return value;
}

template <typename D> uint16_t consume_Windows_Foundation_IPropertyValue<D>::GetUInt16() const
{
    uint16_t value{};
    check_hresult(WINRT_SHIM(Windows::Foundation::IPropertyValue)->GetUInt16(&value));
    return value;
}

template <typename D> int32_t consume_Windows_Foundation_IPropertyValue<D>::GetInt32() const
{
    int32_t value{};
    check_hresult(WINRT_SHIM(Windows::Foundation::IPropertyValue)->GetInt32(&value));
    return value;
}

template <typename D> uint32_t consume_Windows_Foundation_IPropertyValue<D>::GetUInt32() const
{
    uint32_t value{};
    check_hresult(WINRT_SHIM(Windows::Foundation::IPropertyValue)->GetUInt32(&value));
    return value;
}

template <typename D> int64_t consume_Windows_Foundation_IPropertyValue<D>::GetInt64() const
{
    int64_t value{};
    check_hresult(WINRT_SHIM(Windows::Foundation::IPropertyValue)->GetInt64(&value));
    return value;
}

template <typename D> uint64_t consume_Windows_Foundation_IPropertyValue<D>::GetUInt64() const
{
    uint64_t value{};
    check_hresult(WINRT_SHIM(Windows::Foundation::IPropertyValue)->GetUInt64(&value));
    return value;
}

template <typename D> float consume_Windows_Foundation_IPropertyValue<D>::GetSingle() const
{
    float value{};
    check_hresult(WINRT_SHIM(Windows::Foundation::IPropertyValue)->GetSingle(&value));
    return value;
}

template <typename D> double consume_Windows_Foundation_IPropertyValue<D>::GetDouble() const
{
    double value{};
    check_hresult(WINRT_SHIM(Windows::Foundation::IPropertyValue)->GetDouble(&value));
    return value;
}

template <typename D> char16_t consume_Windows_Foundation_IPropertyValue<D>::GetChar16() const
{
    char16_t value{};
    check_hresult(WINRT_SHIM(Windows::Foundation::IPropertyValue)->GetChar16(&value));
    return value;
}

template <typename D> bool consume_Windows_Foundation_IPropertyValue<D>::GetBoolean() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::Foundation::IPropertyValue)->GetBoolean(&value));
    return value;
}

template <typename D> hstring consume_Windows_Foundation_IPropertyValue<D>::GetString() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Foundation::IPropertyValue)->GetString(put_abi(value)));
    return value;
}

template <typename D> winrt::guid consume_Windows_Foundation_IPropertyValue<D>::GetGuid() const
{
    winrt::guid value{};
    check_hresult(WINRT_SHIM(Windows::Foundation::IPropertyValue)->GetGuid(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::DateTime consume_Windows_Foundation_IPropertyValue<D>::GetDateTime() const
{
    Windows::Foundation::DateTime value{};
    check_hresult(WINRT_SHIM(Windows::Foundation::IPropertyValue)->GetDateTime(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::TimeSpan consume_Windows_Foundation_IPropertyValue<D>::GetTimeSpan() const
{
    Windows::Foundation::TimeSpan value{};
    check_hresult(WINRT_SHIM(Windows::Foundation::IPropertyValue)->GetTimeSpan(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::Point consume_Windows_Foundation_IPropertyValue<D>::GetPoint() const
{
    Windows::Foundation::Point value{};
    check_hresult(WINRT_SHIM(Windows::Foundation::IPropertyValue)->GetPoint(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::Size consume_Windows_Foundation_IPropertyValue<D>::GetSize() const
{
    Windows::Foundation::Size value{};
    check_hresult(WINRT_SHIM(Windows::Foundation::IPropertyValue)->GetSize(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::Rect consume_Windows_Foundation_IPropertyValue<D>::GetRect() const
{
    Windows::Foundation::Rect value{};
    check_hresult(WINRT_SHIM(Windows::Foundation::IPropertyValue)->GetRect(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_Foundation_IPropertyValue<D>::GetUInt8Array(com_array<uint8_t>& value) const
{
    check_hresult(WINRT_SHIM(Windows::Foundation::IPropertyValue)->GetUInt8Array(impl::put_size_abi(value), put_abi(value)));
}

template <typename D> void consume_Windows_Foundation_IPropertyValue<D>::GetInt16Array(com_array<int16_t>& value) const
{
    check_hresult(WINRT_SHIM(Windows::Foundation::IPropertyValue)->GetInt16Array(impl::put_size_abi(value), put_abi(value)));
}

template <typename D> void consume_Windows_Foundation_IPropertyValue<D>::GetUInt16Array(com_array<uint16_t>& value) const
{
    check_hresult(WINRT_SHIM(Windows::Foundation::IPropertyValue)->GetUInt16Array(impl::put_size_abi(value), put_abi(value)));
}

template <typename D> void consume_Windows_Foundation_IPropertyValue<D>::GetInt32Array(com_array<int32_t>& value) const
{
    check_hresult(WINRT_SHIM(Windows::Foundation::IPropertyValue)->GetInt32Array(impl::put_size_abi(value), put_abi(value)));
}

template <typename D> void consume_Windows_Foundation_IPropertyValue<D>::GetUInt32Array(com_array<uint32_t>& value) const
{
    check_hresult(WINRT_SHIM(Windows::Foundation::IPropertyValue)->GetUInt32Array(impl::put_size_abi(value), put_abi(value)));
}

template <typename D> void consume_Windows_Foundation_IPropertyValue<D>::GetInt64Array(com_array<int64_t>& value) const
{
    check_hresult(WINRT_SHIM(Windows::Foundation::IPropertyValue)->GetInt64Array(impl::put_size_abi(value), put_abi(value)));
}

template <typename D> void consume_Windows_Foundation_IPropertyValue<D>::GetUInt64Array(com_array<uint64_t>& value) const
{
    check_hresult(WINRT_SHIM(Windows::Foundation::IPropertyValue)->GetUInt64Array(impl::put_size_abi(value), put_abi(value)));
}

template <typename D> void consume_Windows_Foundation_IPropertyValue<D>::GetSingleArray(com_array<float>& value) const
{
    check_hresult(WINRT_SHIM(Windows::Foundation::IPropertyValue)->GetSingleArray(impl::put_size_abi(value), put_abi(value)));
}

template <typename D> void consume_Windows_Foundation_IPropertyValue<D>::GetDoubleArray(com_array<double>& value) const
{
    check_hresult(WINRT_SHIM(Windows::Foundation::IPropertyValue)->GetDoubleArray(impl::put_size_abi(value), put_abi(value)));
}

template <typename D> void consume_Windows_Foundation_IPropertyValue<D>::GetChar16Array(com_array<char16_t>& value) const
{
    check_hresult(WINRT_SHIM(Windows::Foundation::IPropertyValue)->GetChar16Array(impl::put_size_abi(value), put_abi(value)));
}

template <typename D> void consume_Windows_Foundation_IPropertyValue<D>::GetBooleanArray(com_array<bool>& value) const
{
    check_hresult(WINRT_SHIM(Windows::Foundation::IPropertyValue)->GetBooleanArray(impl::put_size_abi(value), put_abi(value)));
}

template <typename D> void consume_Windows_Foundation_IPropertyValue<D>::GetStringArray(com_array<hstring>& value) const
{
    check_hresult(WINRT_SHIM(Windows::Foundation::IPropertyValue)->GetStringArray(impl::put_size_abi(value), put_abi(value)));
}

template <typename D> void consume_Windows_Foundation_IPropertyValue<D>::GetInspectableArray(com_array<Windows::Foundation::IInspectable>& value) const
{
    check_hresult(WINRT_SHIM(Windows::Foundation::IPropertyValue)->GetInspectableArray(impl::put_size_abi(value), put_abi(value)));
}

template <typename D> void consume_Windows_Foundation_IPropertyValue<D>::GetGuidArray(com_array<winrt::guid>& value) const
{
    check_hresult(WINRT_SHIM(Windows::Foundation::IPropertyValue)->GetGuidArray(impl::put_size_abi(value), put_abi(value)));
}

template <typename D> void consume_Windows_Foundation_IPropertyValue<D>::GetDateTimeArray(com_array<Windows::Foundation::DateTime>& value) const
{
    check_hresult(WINRT_SHIM(Windows::Foundation::IPropertyValue)->GetDateTimeArray(impl::put_size_abi(value), put_abi(value)));
}

template <typename D> void consume_Windows_Foundation_IPropertyValue<D>::GetTimeSpanArray(com_array<Windows::Foundation::TimeSpan>& value) const
{
    check_hresult(WINRT_SHIM(Windows::Foundation::IPropertyValue)->GetTimeSpanArray(impl::put_size_abi(value), put_abi(value)));
}

template <typename D> void consume_Windows_Foundation_IPropertyValue<D>::GetPointArray(com_array<Windows::Foundation::Point>& value) const
{
    check_hresult(WINRT_SHIM(Windows::Foundation::IPropertyValue)->GetPointArray(impl::put_size_abi(value), put_abi(value)));
}

template <typename D> void consume_Windows_Foundation_IPropertyValue<D>::GetSizeArray(com_array<Windows::Foundation::Size>& value) const
{
    check_hresult(WINRT_SHIM(Windows::Foundation::IPropertyValue)->GetSizeArray(impl::put_size_abi(value), put_abi(value)));
}

template <typename D> void consume_Windows_Foundation_IPropertyValue<D>::GetRectArray(com_array<Windows::Foundation::Rect>& value) const
{
    check_hresult(WINRT_SHIM(Windows::Foundation::IPropertyValue)->GetRectArray(impl::put_size_abi(value), put_abi(value)));
}

template <typename D> Windows::Foundation::IInspectable consume_Windows_Foundation_IPropertyValueStatics<D>::CreateEmpty() const
{
    Windows::Foundation::IInspectable propertyValue{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Foundation::IPropertyValueStatics)->CreateEmpty(put_abi(propertyValue)));
    return propertyValue;
}

template <typename D> Windows::Foundation::IInspectable consume_Windows_Foundation_IPropertyValueStatics<D>::CreateUInt8(uint8_t value) const
{
    Windows::Foundation::IInspectable propertyValue{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Foundation::IPropertyValueStatics)->CreateUInt8(value, put_abi(propertyValue)));
    return propertyValue;
}

template <typename D> Windows::Foundation::IInspectable consume_Windows_Foundation_IPropertyValueStatics<D>::CreateInt16(int16_t value) const
{
    Windows::Foundation::IInspectable propertyValue{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Foundation::IPropertyValueStatics)->CreateInt16(value, put_abi(propertyValue)));
    return propertyValue;
}

template <typename D> Windows::Foundation::IInspectable consume_Windows_Foundation_IPropertyValueStatics<D>::CreateUInt16(uint16_t value) const
{
    Windows::Foundation::IInspectable propertyValue{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Foundation::IPropertyValueStatics)->CreateUInt16(value, put_abi(propertyValue)));
    return propertyValue;
}

template <typename D> Windows::Foundation::IInspectable consume_Windows_Foundation_IPropertyValueStatics<D>::CreateInt32(int32_t value) const
{
    Windows::Foundation::IInspectable propertyValue{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Foundation::IPropertyValueStatics)->CreateInt32(value, put_abi(propertyValue)));
    return propertyValue;
}

template <typename D> Windows::Foundation::IInspectable consume_Windows_Foundation_IPropertyValueStatics<D>::CreateUInt32(uint32_t value) const
{
    Windows::Foundation::IInspectable propertyValue{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Foundation::IPropertyValueStatics)->CreateUInt32(value, put_abi(propertyValue)));
    return propertyValue;
}

template <typename D> Windows::Foundation::IInspectable consume_Windows_Foundation_IPropertyValueStatics<D>::CreateInt64(int64_t value) const
{
    Windows::Foundation::IInspectable propertyValue{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Foundation::IPropertyValueStatics)->CreateInt64(value, put_abi(propertyValue)));
    return propertyValue;
}

template <typename D> Windows::Foundation::IInspectable consume_Windows_Foundation_IPropertyValueStatics<D>::CreateUInt64(uint64_t value) const
{
    Windows::Foundation::IInspectable propertyValue{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Foundation::IPropertyValueStatics)->CreateUInt64(value, put_abi(propertyValue)));
    return propertyValue;
}

template <typename D> Windows::Foundation::IInspectable consume_Windows_Foundation_IPropertyValueStatics<D>::CreateSingle(float value) const
{
    Windows::Foundation::IInspectable propertyValue{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Foundation::IPropertyValueStatics)->CreateSingle(value, put_abi(propertyValue)));
    return propertyValue;
}

template <typename D> Windows::Foundation::IInspectable consume_Windows_Foundation_IPropertyValueStatics<D>::CreateDouble(double value) const
{
    Windows::Foundation::IInspectable propertyValue{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Foundation::IPropertyValueStatics)->CreateDouble(value, put_abi(propertyValue)));
    return propertyValue;
}

template <typename D> Windows::Foundation::IInspectable consume_Windows_Foundation_IPropertyValueStatics<D>::CreateChar16(char16_t value) const
{
    Windows::Foundation::IInspectable propertyValue{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Foundation::IPropertyValueStatics)->CreateChar16(value, put_abi(propertyValue)));
    return propertyValue;
}

template <typename D> Windows::Foundation::IInspectable consume_Windows_Foundation_IPropertyValueStatics<D>::CreateBoolean(bool value) const
{
    Windows::Foundation::IInspectable propertyValue{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Foundation::IPropertyValueStatics)->CreateBoolean(value, put_abi(propertyValue)));
    return propertyValue;
}

template <typename D> Windows::Foundation::IInspectable consume_Windows_Foundation_IPropertyValueStatics<D>::CreateString(param::hstring const& value) const
{
    Windows::Foundation::IInspectable propertyValue{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Foundation::IPropertyValueStatics)->CreateString(get_abi(value), put_abi(propertyValue)));
    return propertyValue;
}

template <typename D> Windows::Foundation::IInspectable consume_Windows_Foundation_IPropertyValueStatics<D>::CreateInspectable(Windows::Foundation::IInspectable const& value) const
{
    Windows::Foundation::IInspectable propertyValue{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Foundation::IPropertyValueStatics)->CreateInspectable(get_abi(value), put_abi(propertyValue)));
    return propertyValue;
}

template <typename D> Windows::Foundation::IInspectable consume_Windows_Foundation_IPropertyValueStatics<D>::CreateGuid(winrt::guid const& value) const
{
    Windows::Foundation::IInspectable propertyValue{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Foundation::IPropertyValueStatics)->CreateGuid(get_abi(value), put_abi(propertyValue)));
    return propertyValue;
}

template <typename D> Windows::Foundation::IInspectable consume_Windows_Foundation_IPropertyValueStatics<D>::CreateDateTime(Windows::Foundation::DateTime const& value) const
{
    Windows::Foundation::IInspectable propertyValue{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Foundation::IPropertyValueStatics)->CreateDateTime(get_abi(value), put_abi(propertyValue)));
    return propertyValue;
}

template <typename D> Windows::Foundation::IInspectable consume_Windows_Foundation_IPropertyValueStatics<D>::CreateTimeSpan(Windows::Foundation::TimeSpan const& value) const
{
    Windows::Foundation::IInspectable propertyValue{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Foundation::IPropertyValueStatics)->CreateTimeSpan(get_abi(value), put_abi(propertyValue)));
    return propertyValue;
}

template <typename D> Windows::Foundation::IInspectable consume_Windows_Foundation_IPropertyValueStatics<D>::CreatePoint(Windows::Foundation::Point const& value) const
{
    Windows::Foundation::IInspectable propertyValue{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Foundation::IPropertyValueStatics)->CreatePoint(get_abi(value), put_abi(propertyValue)));
    return propertyValue;
}

template <typename D> Windows::Foundation::IInspectable consume_Windows_Foundation_IPropertyValueStatics<D>::CreateSize(Windows::Foundation::Size const& value) const
{
    Windows::Foundation::IInspectable propertyValue{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Foundation::IPropertyValueStatics)->CreateSize(get_abi(value), put_abi(propertyValue)));
    return propertyValue;
}

template <typename D> Windows::Foundation::IInspectable consume_Windows_Foundation_IPropertyValueStatics<D>::CreateRect(Windows::Foundation::Rect const& value) const
{
    Windows::Foundation::IInspectable propertyValue{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Foundation::IPropertyValueStatics)->CreateRect(get_abi(value), put_abi(propertyValue)));
    return propertyValue;
}

template <typename D> Windows::Foundation::IInspectable consume_Windows_Foundation_IPropertyValueStatics<D>::CreateUInt8Array(array_view<uint8_t const> value) const
{
    Windows::Foundation::IInspectable propertyValue{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Foundation::IPropertyValueStatics)->CreateUInt8Array(value.size(), get_abi(value), put_abi(propertyValue)));
    return propertyValue;
}

template <typename D> Windows::Foundation::IInspectable consume_Windows_Foundation_IPropertyValueStatics<D>::CreateInt16Array(array_view<int16_t const> value) const
{
    Windows::Foundation::IInspectable propertyValue{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Foundation::IPropertyValueStatics)->CreateInt16Array(value.size(), get_abi(value), put_abi(propertyValue)));
    return propertyValue;
}

template <typename D> Windows::Foundation::IInspectable consume_Windows_Foundation_IPropertyValueStatics<D>::CreateUInt16Array(array_view<uint16_t const> value) const
{
    Windows::Foundation::IInspectable propertyValue{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Foundation::IPropertyValueStatics)->CreateUInt16Array(value.size(), get_abi(value), put_abi(propertyValue)));
    return propertyValue;
}

template <typename D> Windows::Foundation::IInspectable consume_Windows_Foundation_IPropertyValueStatics<D>::CreateInt32Array(array_view<int32_t const> value) const
{
    Windows::Foundation::IInspectable propertyValue{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Foundation::IPropertyValueStatics)->CreateInt32Array(value.size(), get_abi(value), put_abi(propertyValue)));
    return propertyValue;
}

template <typename D> Windows::Foundation::IInspectable consume_Windows_Foundation_IPropertyValueStatics<D>::CreateUInt32Array(array_view<uint32_t const> value) const
{
    Windows::Foundation::IInspectable propertyValue{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Foundation::IPropertyValueStatics)->CreateUInt32Array(value.size(), get_abi(value), put_abi(propertyValue)));
    return propertyValue;
}

template <typename D> Windows::Foundation::IInspectable consume_Windows_Foundation_IPropertyValueStatics<D>::CreateInt64Array(array_view<int64_t const> value) const
{
    Windows::Foundation::IInspectable propertyValue{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Foundation::IPropertyValueStatics)->CreateInt64Array(value.size(), get_abi(value), put_abi(propertyValue)));
    return propertyValue;
}

template <typename D> Windows::Foundation::IInspectable consume_Windows_Foundation_IPropertyValueStatics<D>::CreateUInt64Array(array_view<uint64_t const> value) const
{
    Windows::Foundation::IInspectable propertyValue{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Foundation::IPropertyValueStatics)->CreateUInt64Array(value.size(), get_abi(value), put_abi(propertyValue)));
    return propertyValue;
}

template <typename D> Windows::Foundation::IInspectable consume_Windows_Foundation_IPropertyValueStatics<D>::CreateSingleArray(array_view<float const> value) const
{
    Windows::Foundation::IInspectable propertyValue{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Foundation::IPropertyValueStatics)->CreateSingleArray(value.size(), get_abi(value), put_abi(propertyValue)));
    return propertyValue;
}

template <typename D> Windows::Foundation::IInspectable consume_Windows_Foundation_IPropertyValueStatics<D>::CreateDoubleArray(array_view<double const> value) const
{
    Windows::Foundation::IInspectable propertyValue{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Foundation::IPropertyValueStatics)->CreateDoubleArray(value.size(), get_abi(value), put_abi(propertyValue)));
    return propertyValue;
}

template <typename D> Windows::Foundation::IInspectable consume_Windows_Foundation_IPropertyValueStatics<D>::CreateChar16Array(array_view<char16_t const> value) const
{
    Windows::Foundation::IInspectable propertyValue{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Foundation::IPropertyValueStatics)->CreateChar16Array(value.size(), get_abi(value), put_abi(propertyValue)));
    return propertyValue;
}

template <typename D> Windows::Foundation::IInspectable consume_Windows_Foundation_IPropertyValueStatics<D>::CreateBooleanArray(array_view<bool const> value) const
{
    Windows::Foundation::IInspectable propertyValue{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Foundation::IPropertyValueStatics)->CreateBooleanArray(value.size(), get_abi(value), put_abi(propertyValue)));
    return propertyValue;
}

template <typename D> Windows::Foundation::IInspectable consume_Windows_Foundation_IPropertyValueStatics<D>::CreateStringArray(array_view<hstring const> value) const
{
    Windows::Foundation::IInspectable propertyValue{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Foundation::IPropertyValueStatics)->CreateStringArray(value.size(), get_abi(value), put_abi(propertyValue)));
    return propertyValue;
}

template <typename D> Windows::Foundation::IInspectable consume_Windows_Foundation_IPropertyValueStatics<D>::CreateInspectableArray(array_view<Windows::Foundation::IInspectable const> value) const
{
    Windows::Foundation::IInspectable propertyValue{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Foundation::IPropertyValueStatics)->CreateInspectableArray(value.size(), get_abi(value), put_abi(propertyValue)));
    return propertyValue;
}

template <typename D> Windows::Foundation::IInspectable consume_Windows_Foundation_IPropertyValueStatics<D>::CreateGuidArray(array_view<winrt::guid const> value) const
{
    Windows::Foundation::IInspectable propertyValue{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Foundation::IPropertyValueStatics)->CreateGuidArray(value.size(), get_abi(value), put_abi(propertyValue)));
    return propertyValue;
}

template <typename D> Windows::Foundation::IInspectable consume_Windows_Foundation_IPropertyValueStatics<D>::CreateDateTimeArray(array_view<Windows::Foundation::DateTime const> value) const
{
    Windows::Foundation::IInspectable propertyValue{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Foundation::IPropertyValueStatics)->CreateDateTimeArray(value.size(), get_abi(value), put_abi(propertyValue)));
    return propertyValue;
}

template <typename D> Windows::Foundation::IInspectable consume_Windows_Foundation_IPropertyValueStatics<D>::CreateTimeSpanArray(array_view<Windows::Foundation::TimeSpan const> value) const
{
    Windows::Foundation::IInspectable propertyValue{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Foundation::IPropertyValueStatics)->CreateTimeSpanArray(value.size(), get_abi(value), put_abi(propertyValue)));
    return propertyValue;
}

template <typename D> Windows::Foundation::IInspectable consume_Windows_Foundation_IPropertyValueStatics<D>::CreatePointArray(array_view<Windows::Foundation::Point const> value) const
{
    Windows::Foundation::IInspectable propertyValue{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Foundation::IPropertyValueStatics)->CreatePointArray(value.size(), get_abi(value), put_abi(propertyValue)));
    return propertyValue;
}

template <typename D> Windows::Foundation::IInspectable consume_Windows_Foundation_IPropertyValueStatics<D>::CreateSizeArray(array_view<Windows::Foundation::Size const> value) const
{
    Windows::Foundation::IInspectable propertyValue{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Foundation::IPropertyValueStatics)->CreateSizeArray(value.size(), get_abi(value), put_abi(propertyValue)));
    return propertyValue;
}

template <typename D> Windows::Foundation::IInspectable consume_Windows_Foundation_IPropertyValueStatics<D>::CreateRectArray(array_view<Windows::Foundation::Rect const> value) const
{
    Windows::Foundation::IInspectable propertyValue{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Foundation::IPropertyValueStatics)->CreateRectArray(value.size(), get_abi(value), put_abi(propertyValue)));
    return propertyValue;
}

template <typename D> hstring consume_Windows_Foundation_IStringable<D>::ToString() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Foundation::IStringable)->ToString(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_Foundation_IUriEscapeStatics<D>::UnescapeComponent(param::hstring const& toUnescape) const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Foundation::IUriEscapeStatics)->UnescapeComponent(get_abi(toUnescape), put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_Foundation_IUriEscapeStatics<D>::EscapeComponent(param::hstring const& toEscape) const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Foundation::IUriEscapeStatics)->EscapeComponent(get_abi(toEscape), put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_Foundation_IUriRuntimeClass<D>::AbsoluteUri() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Foundation::IUriRuntimeClass)->get_AbsoluteUri(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_Foundation_IUriRuntimeClass<D>::DisplayUri() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Foundation::IUriRuntimeClass)->get_DisplayUri(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_Foundation_IUriRuntimeClass<D>::Domain() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Foundation::IUriRuntimeClass)->get_Domain(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_Foundation_IUriRuntimeClass<D>::Extension() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Foundation::IUriRuntimeClass)->get_Extension(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_Foundation_IUriRuntimeClass<D>::Fragment() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Foundation::IUriRuntimeClass)->get_Fragment(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_Foundation_IUriRuntimeClass<D>::Host() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Foundation::IUriRuntimeClass)->get_Host(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_Foundation_IUriRuntimeClass<D>::Password() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Foundation::IUriRuntimeClass)->get_Password(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_Foundation_IUriRuntimeClass<D>::Path() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Foundation::IUriRuntimeClass)->get_Path(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_Foundation_IUriRuntimeClass<D>::Query() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Foundation::IUriRuntimeClass)->get_Query(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::WwwFormUrlDecoder consume_Windows_Foundation_IUriRuntimeClass<D>::QueryParsed() const
{
    Windows::Foundation::WwwFormUrlDecoder ppWwwFormUrlDecoder{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Foundation::IUriRuntimeClass)->get_QueryParsed(put_abi(ppWwwFormUrlDecoder)));
    return ppWwwFormUrlDecoder;
}

template <typename D> hstring consume_Windows_Foundation_IUriRuntimeClass<D>::RawUri() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Foundation::IUriRuntimeClass)->get_RawUri(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_Foundation_IUriRuntimeClass<D>::SchemeName() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Foundation::IUriRuntimeClass)->get_SchemeName(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_Foundation_IUriRuntimeClass<D>::UserName() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Foundation::IUriRuntimeClass)->get_UserName(put_abi(value)));
    return value;
}

template <typename D> int32_t consume_Windows_Foundation_IUriRuntimeClass<D>::Port() const
{
    int32_t value{};
    check_hresult(WINRT_SHIM(Windows::Foundation::IUriRuntimeClass)->get_Port(&value));
    return value;
}

template <typename D> bool consume_Windows_Foundation_IUriRuntimeClass<D>::Suspicious() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::Foundation::IUriRuntimeClass)->get_Suspicious(&value));
    return value;
}

template <typename D> bool consume_Windows_Foundation_IUriRuntimeClass<D>::Equals(Windows::Foundation::Uri const& pUri) const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::Foundation::IUriRuntimeClass)->Equals(get_abi(pUri), &value));
    return value;
}

template <typename D> Windows::Foundation::Uri consume_Windows_Foundation_IUriRuntimeClass<D>::CombineUri(param::hstring const& relativeUri) const
{
    Windows::Foundation::Uri instance{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Foundation::IUriRuntimeClass)->CombineUri(get_abi(relativeUri), put_abi(instance)));
    return instance;
}

template <typename D> Windows::Foundation::Uri consume_Windows_Foundation_IUriRuntimeClassFactory<D>::CreateUri(param::hstring const& uri) const
{
    Windows::Foundation::Uri instance{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Foundation::IUriRuntimeClassFactory)->CreateUri(get_abi(uri), put_abi(instance)));
    return instance;
}

template <typename D> Windows::Foundation::Uri consume_Windows_Foundation_IUriRuntimeClassFactory<D>::CreateWithRelativeUri(param::hstring const& baseUri, param::hstring const& relativeUri) const
{
    Windows::Foundation::Uri instance{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Foundation::IUriRuntimeClassFactory)->CreateWithRelativeUri(get_abi(baseUri), get_abi(relativeUri), put_abi(instance)));
    return instance;
}

template <typename D> hstring consume_Windows_Foundation_IUriRuntimeClassWithAbsoluteCanonicalUri<D>::AbsoluteCanonicalUri() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Foundation::IUriRuntimeClassWithAbsoluteCanonicalUri)->get_AbsoluteCanonicalUri(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_Foundation_IUriRuntimeClassWithAbsoluteCanonicalUri<D>::DisplayIri() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Foundation::IUriRuntimeClassWithAbsoluteCanonicalUri)->get_DisplayIri(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_Foundation_IWwwFormUrlDecoderEntry<D>::Name() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Foundation::IWwwFormUrlDecoderEntry)->get_Name(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_Foundation_IWwwFormUrlDecoderEntry<D>::Value() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Foundation::IWwwFormUrlDecoderEntry)->get_Value(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_Foundation_IWwwFormUrlDecoderRuntimeClass<D>::GetFirstValueByName(param::hstring const& name) const
{
    hstring phstrValue{};
    check_hresult(WINRT_SHIM(Windows::Foundation::IWwwFormUrlDecoderRuntimeClass)->GetFirstValueByName(get_abi(name), put_abi(phstrValue)));
    return phstrValue;
}

template <typename D> Windows::Foundation::WwwFormUrlDecoder consume_Windows_Foundation_IWwwFormUrlDecoderRuntimeClassFactory<D>::CreateWwwFormUrlDecoder(param::hstring const& query) const
{
    Windows::Foundation::WwwFormUrlDecoder instance{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Foundation::IWwwFormUrlDecoderRuntimeClassFactory)->CreateWwwFormUrlDecoder(get_abi(query), put_abi(instance)));
    return instance;
}

template <> struct delegate<Windows::Foundation::DeferralCompletedHandler>
{
    template <typename H>
    struct type : implements_delegate<Windows::Foundation::DeferralCompletedHandler, H>
    {
        type(H&& handler) : implements_delegate<Windows::Foundation::DeferralCompletedHandler, H>(std::forward<H>(handler)) {}

        int32_t WINRT_CALL Invoke() noexcept final
        {
            try
            {
                (*this)();
                return 0;
            }
            catch (...)
            {
                return to_hresult();
            }
        }
    };
};

template <typename D>
struct produce<D, Windows::Foundation::IClosable> : produce_base<D, Windows::Foundation::IClosable>
{
    int32_t WINRT_CALL Close() noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Close, WINRT_WRAP(void));
            this->shim().Close();
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Foundation::IDeferral> : produce_base<D, Windows::Foundation::IDeferral>
{
    int32_t WINRT_CALL Complete() noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Complete, WINRT_WRAP(void));
            this->shim().Complete();
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Foundation::IDeferralFactory> : produce_base<D, Windows::Foundation::IDeferralFactory>
{
    int32_t WINRT_CALL Create(void* handler, void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Create, WINRT_WRAP(Windows::Foundation::Deferral), Windows::Foundation::DeferralCompletedHandler const&);
            *result = detach_from<Windows::Foundation::Deferral>(this->shim().Create(*reinterpret_cast<Windows::Foundation::DeferralCompletedHandler const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Foundation::IGetActivationFactory> : produce_base<D, Windows::Foundation::IGetActivationFactory>
{
    int32_t WINRT_CALL GetActivationFactory(void* activatableClassId, void** factory) noexcept final
    {
        try
        {
            *factory = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetActivationFactory, WINRT_WRAP(Windows::Foundation::IInspectable), hstring const&);
            *factory = detach_from<Windows::Foundation::IInspectable>(this->shim().GetActivationFactory(*reinterpret_cast<hstring const*>(&activatableClassId)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Foundation::IGuidHelperStatics> : produce_base<D, Windows::Foundation::IGuidHelperStatics>
{
    int32_t WINRT_CALL CreateNewGuid(winrt::guid* result) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CreateNewGuid, WINRT_WRAP(winrt::guid));
            *result = detach_from<winrt::guid>(this->shim().CreateNewGuid());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Empty(winrt::guid* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Empty, WINRT_WRAP(winrt::guid));
            *value = detach_from<winrt::guid>(this->shim().Empty());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL Equals(winrt::guid const& target, winrt::guid const& value, bool* result) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Equals, WINRT_WRAP(bool), winrt::guid const&, winrt::guid const&);
            *result = detach_from<bool>(this->shim().Equals(*reinterpret_cast<winrt::guid const*>(&target), *reinterpret_cast<winrt::guid const*>(&value)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Foundation::IMemoryBuffer> : produce_base<D, Windows::Foundation::IMemoryBuffer>
{
    int32_t WINRT_CALL CreateReference(void** reference) noexcept final
    {
        try
        {
            *reference = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CreateReference, WINRT_WRAP(Windows::Foundation::IMemoryBufferReference));
            *reference = detach_from<Windows::Foundation::IMemoryBufferReference>(this->shim().CreateReference());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Foundation::IMemoryBufferFactory> : produce_base<D, Windows::Foundation::IMemoryBufferFactory>
{
    int32_t WINRT_CALL Create(uint32_t capacity, void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Create, WINRT_WRAP(Windows::Foundation::MemoryBuffer), uint32_t);
            *value = detach_from<Windows::Foundation::MemoryBuffer>(this->shim().Create(capacity));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Foundation::IMemoryBufferReference> : produce_base<D, Windows::Foundation::IMemoryBufferReference>
{
    int32_t WINRT_CALL get_Capacity(uint32_t* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Capacity, WINRT_WRAP(uint32_t));
            *value = detach_from<uint32_t>(this->shim().Capacity());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL add_Closed(void* handler, winrt::event_token* cookie) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Closed, WINRT_WRAP(winrt::event_token), Windows::Foundation::TypedEventHandler<Windows::Foundation::IMemoryBufferReference, Windows::Foundation::IInspectable> const&);
            *cookie = detach_from<winrt::event_token>(this->shim().Closed(*reinterpret_cast<Windows::Foundation::TypedEventHandler<Windows::Foundation::IMemoryBufferReference, Windows::Foundation::IInspectable> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL remove_Closed(winrt::event_token cookie) noexcept final
    {
        typename D::abi_guard guard(this->shim());
        WINRT_ASSERT_DECLARATION(Closed, WINRT_WRAP(void), winrt::event_token const&);
        this->shim().Closed(*reinterpret_cast<winrt::event_token const*>(&cookie));
        return 0;
    }
};

template <typename D>
struct produce<D, Windows::Foundation::IPropertyValue> : produce_base<D, Windows::Foundation::IPropertyValue>
{
    int32_t WINRT_CALL get_Type(Windows::Foundation::PropertyType* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Type, WINRT_WRAP(Windows::Foundation::PropertyType));
            *value = detach_from<Windows::Foundation::PropertyType>(this->shim().Type());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_IsNumericScalar(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IsNumericScalar, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().IsNumericScalar());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL GetUInt8(uint8_t* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetUInt8, WINRT_WRAP(uint8_t));
            *value = detach_from<uint8_t>(this->shim().GetUInt8());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL GetInt16(int16_t* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetInt16, WINRT_WRAP(int16_t));
            *value = detach_from<int16_t>(this->shim().GetInt16());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL GetUInt16(uint16_t* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetUInt16, WINRT_WRAP(uint16_t));
            *value = detach_from<uint16_t>(this->shim().GetUInt16());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL GetInt32(int32_t* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetInt32, WINRT_WRAP(int32_t));
            *value = detach_from<int32_t>(this->shim().GetInt32());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL GetUInt32(uint32_t* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetUInt32, WINRT_WRAP(uint32_t));
            *value = detach_from<uint32_t>(this->shim().GetUInt32());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL GetInt64(int64_t* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetInt64, WINRT_WRAP(int64_t));
            *value = detach_from<int64_t>(this->shim().GetInt64());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL GetUInt64(uint64_t* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetUInt64, WINRT_WRAP(uint64_t));
            *value = detach_from<uint64_t>(this->shim().GetUInt64());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL GetSingle(float* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetSingle, WINRT_WRAP(float));
            *value = detach_from<float>(this->shim().GetSingle());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL GetDouble(double* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetDouble, WINRT_WRAP(double));
            *value = detach_from<double>(this->shim().GetDouble());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL GetChar16(char16_t* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetChar16, WINRT_WRAP(char16_t));
            *value = detach_from<char16_t>(this->shim().GetChar16());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL GetBoolean(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetBoolean, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().GetBoolean());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL GetString(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetString, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().GetString());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL GetGuid(winrt::guid* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetGuid, WINRT_WRAP(winrt::guid));
            *value = detach_from<winrt::guid>(this->shim().GetGuid());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL GetDateTime(Windows::Foundation::DateTime* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetDateTime, WINRT_WRAP(Windows::Foundation::DateTime));
            *value = detach_from<Windows::Foundation::DateTime>(this->shim().GetDateTime());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL GetTimeSpan(Windows::Foundation::TimeSpan* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetTimeSpan, WINRT_WRAP(Windows::Foundation::TimeSpan));
            *value = detach_from<Windows::Foundation::TimeSpan>(this->shim().GetTimeSpan());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL GetPoint(Windows::Foundation::Point* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetPoint, WINRT_WRAP(Windows::Foundation::Point));
            *value = detach_from<Windows::Foundation::Point>(this->shim().GetPoint());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL GetSize(Windows::Foundation::Size* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetSize, WINRT_WRAP(Windows::Foundation::Size));
            *value = detach_from<Windows::Foundation::Size>(this->shim().GetSize());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL GetRect(Windows::Foundation::Rect* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetRect, WINRT_WRAP(Windows::Foundation::Rect));
            *value = detach_from<Windows::Foundation::Rect>(this->shim().GetRect());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL GetUInt8Array(uint32_t* __valueSize, uint8_t** value) noexcept final
    {
        try
        {
            *__valueSize = 0;
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetUInt8Array, WINRT_WRAP(void), com_array<uint8_t>&);
            this->shim().GetUInt8Array(detach_abi<uint8_t>(__valueSize, value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL GetInt16Array(uint32_t* __valueSize, int16_t** value) noexcept final
    {
        try
        {
            *__valueSize = 0;
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetInt16Array, WINRT_WRAP(void), com_array<int16_t>&);
            this->shim().GetInt16Array(detach_abi<int16_t>(__valueSize, value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL GetUInt16Array(uint32_t* __valueSize, uint16_t** value) noexcept final
    {
        try
        {
            *__valueSize = 0;
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetUInt16Array, WINRT_WRAP(void), com_array<uint16_t>&);
            this->shim().GetUInt16Array(detach_abi<uint16_t>(__valueSize, value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL GetInt32Array(uint32_t* __valueSize, int32_t** value) noexcept final
    {
        try
        {
            *__valueSize = 0;
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetInt32Array, WINRT_WRAP(void), com_array<int32_t>&);
            this->shim().GetInt32Array(detach_abi<int32_t>(__valueSize, value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL GetUInt32Array(uint32_t* __valueSize, uint32_t** value) noexcept final
    {
        try
        {
            *__valueSize = 0;
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetUInt32Array, WINRT_WRAP(void), com_array<uint32_t>&);
            this->shim().GetUInt32Array(detach_abi<uint32_t>(__valueSize, value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL GetInt64Array(uint32_t* __valueSize, int64_t** value) noexcept final
    {
        try
        {
            *__valueSize = 0;
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetInt64Array, WINRT_WRAP(void), com_array<int64_t>&);
            this->shim().GetInt64Array(detach_abi<int64_t>(__valueSize, value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL GetUInt64Array(uint32_t* __valueSize, uint64_t** value) noexcept final
    {
        try
        {
            *__valueSize = 0;
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetUInt64Array, WINRT_WRAP(void), com_array<uint64_t>&);
            this->shim().GetUInt64Array(detach_abi<uint64_t>(__valueSize, value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL GetSingleArray(uint32_t* __valueSize, float** value) noexcept final
    {
        try
        {
            *__valueSize = 0;
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetSingleArray, WINRT_WRAP(void), com_array<float>&);
            this->shim().GetSingleArray(detach_abi<float>(__valueSize, value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL GetDoubleArray(uint32_t* __valueSize, double** value) noexcept final
    {
        try
        {
            *__valueSize = 0;
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetDoubleArray, WINRT_WRAP(void), com_array<double>&);
            this->shim().GetDoubleArray(detach_abi<double>(__valueSize, value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL GetChar16Array(uint32_t* __valueSize, char16_t** value) noexcept final
    {
        try
        {
            *__valueSize = 0;
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetChar16Array, WINRT_WRAP(void), com_array<char16_t>&);
            this->shim().GetChar16Array(detach_abi<char16_t>(__valueSize, value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL GetBooleanArray(uint32_t* __valueSize, bool** value) noexcept final
    {
        try
        {
            *__valueSize = 0;
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetBooleanArray, WINRT_WRAP(void), com_array<bool>&);
            this->shim().GetBooleanArray(detach_abi<bool>(__valueSize, value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL GetStringArray(uint32_t* __valueSize, void*** value) noexcept final
    {
        try
        {
            *__valueSize = 0;
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetStringArray, WINRT_WRAP(void), com_array<hstring>&);
            this->shim().GetStringArray(detach_abi<hstring>(__valueSize, value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL GetInspectableArray(uint32_t* __valueSize, void*** value) noexcept final
    {
        try
        {
            *__valueSize = 0;
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetInspectableArray, WINRT_WRAP(void), com_array<Windows::Foundation::IInspectable>&);
            this->shim().GetInspectableArray(detach_abi<Windows::Foundation::IInspectable>(__valueSize, value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL GetGuidArray(uint32_t* __valueSize, winrt::guid** value) noexcept final
    {
        try
        {
            *__valueSize = 0;
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetGuidArray, WINRT_WRAP(void), com_array<winrt::guid>&);
            this->shim().GetGuidArray(detach_abi<winrt::guid>(__valueSize, value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL GetDateTimeArray(uint32_t* __valueSize, Windows::Foundation::DateTime** value) noexcept final
    {
        try
        {
            *__valueSize = 0;
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetDateTimeArray, WINRT_WRAP(void), com_array<Windows::Foundation::DateTime>&);
            this->shim().GetDateTimeArray(detach_abi<Windows::Foundation::DateTime>(__valueSize, value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL GetTimeSpanArray(uint32_t* __valueSize, Windows::Foundation::TimeSpan** value) noexcept final
    {
        try
        {
            *__valueSize = 0;
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetTimeSpanArray, WINRT_WRAP(void), com_array<Windows::Foundation::TimeSpan>&);
            this->shim().GetTimeSpanArray(detach_abi<Windows::Foundation::TimeSpan>(__valueSize, value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL GetPointArray(uint32_t* __valueSize, Windows::Foundation::Point** value) noexcept final
    {
        try
        {
            *__valueSize = 0;
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetPointArray, WINRT_WRAP(void), com_array<Windows::Foundation::Point>&);
            this->shim().GetPointArray(detach_abi<Windows::Foundation::Point>(__valueSize, value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL GetSizeArray(uint32_t* __valueSize, Windows::Foundation::Size** value) noexcept final
    {
        try
        {
            *__valueSize = 0;
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetSizeArray, WINRT_WRAP(void), com_array<Windows::Foundation::Size>&);
            this->shim().GetSizeArray(detach_abi<Windows::Foundation::Size>(__valueSize, value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL GetRectArray(uint32_t* __valueSize, Windows::Foundation::Rect** value) noexcept final
    {
        try
        {
            *__valueSize = 0;
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetRectArray, WINRT_WRAP(void), com_array<Windows::Foundation::Rect>&);
            this->shim().GetRectArray(detach_abi<Windows::Foundation::Rect>(__valueSize, value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Foundation::IPropertyValueStatics> : produce_base<D, Windows::Foundation::IPropertyValueStatics>
{
    int32_t WINRT_CALL CreateEmpty(void** propertyValue) noexcept final
    {
        try
        {
            *propertyValue = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CreateEmpty, WINRT_WRAP(Windows::Foundation::IInspectable));
            *propertyValue = detach_from<Windows::Foundation::IInspectable>(this->shim().CreateEmpty());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL CreateUInt8(uint8_t value, void** propertyValue) noexcept final
    {
        try
        {
            *propertyValue = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CreateUInt8, WINRT_WRAP(Windows::Foundation::IInspectable), uint8_t);
            *propertyValue = detach_from<Windows::Foundation::IInspectable>(this->shim().CreateUInt8(value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL CreateInt16(int16_t value, void** propertyValue) noexcept final
    {
        try
        {
            *propertyValue = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CreateInt16, WINRT_WRAP(Windows::Foundation::IInspectable), int16_t);
            *propertyValue = detach_from<Windows::Foundation::IInspectable>(this->shim().CreateInt16(value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL CreateUInt16(uint16_t value, void** propertyValue) noexcept final
    {
        try
        {
            *propertyValue = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CreateUInt16, WINRT_WRAP(Windows::Foundation::IInspectable), uint16_t);
            *propertyValue = detach_from<Windows::Foundation::IInspectable>(this->shim().CreateUInt16(value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL CreateInt32(int32_t value, void** propertyValue) noexcept final
    {
        try
        {
            *propertyValue = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CreateInt32, WINRT_WRAP(Windows::Foundation::IInspectable), int32_t);
            *propertyValue = detach_from<Windows::Foundation::IInspectable>(this->shim().CreateInt32(value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL CreateUInt32(uint32_t value, void** propertyValue) noexcept final
    {
        try
        {
            *propertyValue = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CreateUInt32, WINRT_WRAP(Windows::Foundation::IInspectable), uint32_t);
            *propertyValue = detach_from<Windows::Foundation::IInspectable>(this->shim().CreateUInt32(value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL CreateInt64(int64_t value, void** propertyValue) noexcept final
    {
        try
        {
            *propertyValue = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CreateInt64, WINRT_WRAP(Windows::Foundation::IInspectable), int64_t);
            *propertyValue = detach_from<Windows::Foundation::IInspectable>(this->shim().CreateInt64(value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL CreateUInt64(uint64_t value, void** propertyValue) noexcept final
    {
        try
        {
            *propertyValue = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CreateUInt64, WINRT_WRAP(Windows::Foundation::IInspectable), uint64_t);
            *propertyValue = detach_from<Windows::Foundation::IInspectable>(this->shim().CreateUInt64(value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL CreateSingle(float value, void** propertyValue) noexcept final
    {
        try
        {
            *propertyValue = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CreateSingle, WINRT_WRAP(Windows::Foundation::IInspectable), float);
            *propertyValue = detach_from<Windows::Foundation::IInspectable>(this->shim().CreateSingle(value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL CreateDouble(double value, void** propertyValue) noexcept final
    {
        try
        {
            *propertyValue = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CreateDouble, WINRT_WRAP(Windows::Foundation::IInspectable), double);
            *propertyValue = detach_from<Windows::Foundation::IInspectable>(this->shim().CreateDouble(value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL CreateChar16(char16_t value, void** propertyValue) noexcept final
    {
        try
        {
            *propertyValue = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CreateChar16, WINRT_WRAP(Windows::Foundation::IInspectable), char16_t);
            *propertyValue = detach_from<Windows::Foundation::IInspectable>(this->shim().CreateChar16(value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL CreateBoolean(bool value, void** propertyValue) noexcept final
    {
        try
        {
            *propertyValue = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CreateBoolean, WINRT_WRAP(Windows::Foundation::IInspectable), bool);
            *propertyValue = detach_from<Windows::Foundation::IInspectable>(this->shim().CreateBoolean(value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL CreateString(void* value, void** propertyValue) noexcept final
    {
        try
        {
            *propertyValue = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CreateString, WINRT_WRAP(Windows::Foundation::IInspectable), hstring const&);
            *propertyValue = detach_from<Windows::Foundation::IInspectable>(this->shim().CreateString(*reinterpret_cast<hstring const*>(&value)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL CreateInspectable(void* value, void** propertyValue) noexcept final
    {
        try
        {
            *propertyValue = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CreateInspectable, WINRT_WRAP(Windows::Foundation::IInspectable), Windows::Foundation::IInspectable const&);
            *propertyValue = detach_from<Windows::Foundation::IInspectable>(this->shim().CreateInspectable(*reinterpret_cast<Windows::Foundation::IInspectable const*>(&value)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL CreateGuid(winrt::guid value, void** propertyValue) noexcept final
    {
        try
        {
            *propertyValue = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CreateGuid, WINRT_WRAP(Windows::Foundation::IInspectable), winrt::guid const&);
            *propertyValue = detach_from<Windows::Foundation::IInspectable>(this->shim().CreateGuid(*reinterpret_cast<winrt::guid const*>(&value)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL CreateDateTime(Windows::Foundation::DateTime value, void** propertyValue) noexcept final
    {
        try
        {
            *propertyValue = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CreateDateTime, WINRT_WRAP(Windows::Foundation::IInspectable), Windows::Foundation::DateTime const&);
            *propertyValue = detach_from<Windows::Foundation::IInspectable>(this->shim().CreateDateTime(*reinterpret_cast<Windows::Foundation::DateTime const*>(&value)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL CreateTimeSpan(Windows::Foundation::TimeSpan value, void** propertyValue) noexcept final
    {
        try
        {
            *propertyValue = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CreateTimeSpan, WINRT_WRAP(Windows::Foundation::IInspectable), Windows::Foundation::TimeSpan const&);
            *propertyValue = detach_from<Windows::Foundation::IInspectable>(this->shim().CreateTimeSpan(*reinterpret_cast<Windows::Foundation::TimeSpan const*>(&value)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL CreatePoint(Windows::Foundation::Point value, void** propertyValue) noexcept final
    {
        try
        {
            *propertyValue = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CreatePoint, WINRT_WRAP(Windows::Foundation::IInspectable), Windows::Foundation::Point const&);
            *propertyValue = detach_from<Windows::Foundation::IInspectable>(this->shim().CreatePoint(*reinterpret_cast<Windows::Foundation::Point const*>(&value)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL CreateSize(Windows::Foundation::Size value, void** propertyValue) noexcept final
    {
        try
        {
            *propertyValue = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CreateSize, WINRT_WRAP(Windows::Foundation::IInspectable), Windows::Foundation::Size const&);
            *propertyValue = detach_from<Windows::Foundation::IInspectable>(this->shim().CreateSize(*reinterpret_cast<Windows::Foundation::Size const*>(&value)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL CreateRect(Windows::Foundation::Rect value, void** propertyValue) noexcept final
    {
        try
        {
            *propertyValue = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CreateRect, WINRT_WRAP(Windows::Foundation::IInspectable), Windows::Foundation::Rect const&);
            *propertyValue = detach_from<Windows::Foundation::IInspectable>(this->shim().CreateRect(*reinterpret_cast<Windows::Foundation::Rect const*>(&value)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL CreateUInt8Array(uint32_t __valueSize, uint8_t* value, void** propertyValue) noexcept final
    {
        try
        {
            *propertyValue = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CreateUInt8Array, WINRT_WRAP(Windows::Foundation::IInspectable), array_view<uint8_t const>);
            *propertyValue = detach_from<Windows::Foundation::IInspectable>(this->shim().CreateUInt8Array(array_view<uint8_t const>(reinterpret_cast<uint8_t const *>(value), reinterpret_cast<uint8_t const *>(value) + __valueSize)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL CreateInt16Array(uint32_t __valueSize, int16_t* value, void** propertyValue) noexcept final
    {
        try
        {
            *propertyValue = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CreateInt16Array, WINRT_WRAP(Windows::Foundation::IInspectable), array_view<int16_t const>);
            *propertyValue = detach_from<Windows::Foundation::IInspectable>(this->shim().CreateInt16Array(array_view<int16_t const>(reinterpret_cast<int16_t const *>(value), reinterpret_cast<int16_t const *>(value) + __valueSize)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL CreateUInt16Array(uint32_t __valueSize, uint16_t* value, void** propertyValue) noexcept final
    {
        try
        {
            *propertyValue = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CreateUInt16Array, WINRT_WRAP(Windows::Foundation::IInspectable), array_view<uint16_t const>);
            *propertyValue = detach_from<Windows::Foundation::IInspectable>(this->shim().CreateUInt16Array(array_view<uint16_t const>(reinterpret_cast<uint16_t const *>(value), reinterpret_cast<uint16_t const *>(value) + __valueSize)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL CreateInt32Array(uint32_t __valueSize, int32_t* value, void** propertyValue) noexcept final
    {
        try
        {
            *propertyValue = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CreateInt32Array, WINRT_WRAP(Windows::Foundation::IInspectable), array_view<int32_t const>);
            *propertyValue = detach_from<Windows::Foundation::IInspectable>(this->shim().CreateInt32Array(array_view<int32_t const>(reinterpret_cast<int32_t const *>(value), reinterpret_cast<int32_t const *>(value) + __valueSize)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL CreateUInt32Array(uint32_t __valueSize, uint32_t* value, void** propertyValue) noexcept final
    {
        try
        {
            *propertyValue = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CreateUInt32Array, WINRT_WRAP(Windows::Foundation::IInspectable), array_view<uint32_t const>);
            *propertyValue = detach_from<Windows::Foundation::IInspectable>(this->shim().CreateUInt32Array(array_view<uint32_t const>(reinterpret_cast<uint32_t const *>(value), reinterpret_cast<uint32_t const *>(value) + __valueSize)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL CreateInt64Array(uint32_t __valueSize, int64_t* value, void** propertyValue) noexcept final
    {
        try
        {
            *propertyValue = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CreateInt64Array, WINRT_WRAP(Windows::Foundation::IInspectable), array_view<int64_t const>);
            *propertyValue = detach_from<Windows::Foundation::IInspectable>(this->shim().CreateInt64Array(array_view<int64_t const>(reinterpret_cast<int64_t const *>(value), reinterpret_cast<int64_t const *>(value) + __valueSize)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL CreateUInt64Array(uint32_t __valueSize, uint64_t* value, void** propertyValue) noexcept final
    {
        try
        {
            *propertyValue = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CreateUInt64Array, WINRT_WRAP(Windows::Foundation::IInspectable), array_view<uint64_t const>);
            *propertyValue = detach_from<Windows::Foundation::IInspectable>(this->shim().CreateUInt64Array(array_view<uint64_t const>(reinterpret_cast<uint64_t const *>(value), reinterpret_cast<uint64_t const *>(value) + __valueSize)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL CreateSingleArray(uint32_t __valueSize, float* value, void** propertyValue) noexcept final
    {
        try
        {
            *propertyValue = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CreateSingleArray, WINRT_WRAP(Windows::Foundation::IInspectable), array_view<float const>);
            *propertyValue = detach_from<Windows::Foundation::IInspectable>(this->shim().CreateSingleArray(array_view<float const>(reinterpret_cast<float const *>(value), reinterpret_cast<float const *>(value) + __valueSize)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL CreateDoubleArray(uint32_t __valueSize, double* value, void** propertyValue) noexcept final
    {
        try
        {
            *propertyValue = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CreateDoubleArray, WINRT_WRAP(Windows::Foundation::IInspectable), array_view<double const>);
            *propertyValue = detach_from<Windows::Foundation::IInspectable>(this->shim().CreateDoubleArray(array_view<double const>(reinterpret_cast<double const *>(value), reinterpret_cast<double const *>(value) + __valueSize)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL CreateChar16Array(uint32_t __valueSize, char16_t* value, void** propertyValue) noexcept final
    {
        try
        {
            *propertyValue = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CreateChar16Array, WINRT_WRAP(Windows::Foundation::IInspectable), array_view<char16_t const>);
            *propertyValue = detach_from<Windows::Foundation::IInspectable>(this->shim().CreateChar16Array(array_view<char16_t const>(reinterpret_cast<char16_t const *>(value), reinterpret_cast<char16_t const *>(value) + __valueSize)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL CreateBooleanArray(uint32_t __valueSize, bool* value, void** propertyValue) noexcept final
    {
        try
        {
            *propertyValue = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CreateBooleanArray, WINRT_WRAP(Windows::Foundation::IInspectable), array_view<bool const>);
            *propertyValue = detach_from<Windows::Foundation::IInspectable>(this->shim().CreateBooleanArray(array_view<bool const>(reinterpret_cast<bool const *>(value), reinterpret_cast<bool const *>(value) + __valueSize)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL CreateStringArray(uint32_t __valueSize, void** value, void** propertyValue) noexcept final
    {
        try
        {
            *propertyValue = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CreateStringArray, WINRT_WRAP(Windows::Foundation::IInspectable), array_view<hstring const>);
            *propertyValue = detach_from<Windows::Foundation::IInspectable>(this->shim().CreateStringArray(array_view<hstring const>(reinterpret_cast<hstring const *>(value), reinterpret_cast<hstring const *>(value) + __valueSize)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL CreateInspectableArray(uint32_t __valueSize, void** value, void** propertyValue) noexcept final
    {
        try
        {
            *propertyValue = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CreateInspectableArray, WINRT_WRAP(Windows::Foundation::IInspectable), array_view<Windows::Foundation::IInspectable const>);
            *propertyValue = detach_from<Windows::Foundation::IInspectable>(this->shim().CreateInspectableArray(array_view<Windows::Foundation::IInspectable const>(reinterpret_cast<Windows::Foundation::IInspectable const *>(value), reinterpret_cast<Windows::Foundation::IInspectable const *>(value) + __valueSize)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL CreateGuidArray(uint32_t __valueSize, winrt::guid* value, void** propertyValue) noexcept final
    {
        try
        {
            *propertyValue = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CreateGuidArray, WINRT_WRAP(Windows::Foundation::IInspectable), array_view<winrt::guid const>);
            *propertyValue = detach_from<Windows::Foundation::IInspectable>(this->shim().CreateGuidArray(array_view<winrt::guid const>(reinterpret_cast<winrt::guid const *>(value), reinterpret_cast<winrt::guid const *>(value) + __valueSize)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL CreateDateTimeArray(uint32_t __valueSize, Windows::Foundation::DateTime* value, void** propertyValue) noexcept final
    {
        try
        {
            *propertyValue = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CreateDateTimeArray, WINRT_WRAP(Windows::Foundation::IInspectable), array_view<Windows::Foundation::DateTime const>);
            *propertyValue = detach_from<Windows::Foundation::IInspectable>(this->shim().CreateDateTimeArray(array_view<Windows::Foundation::DateTime const>(reinterpret_cast<Windows::Foundation::DateTime const *>(value), reinterpret_cast<Windows::Foundation::DateTime const *>(value) + __valueSize)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL CreateTimeSpanArray(uint32_t __valueSize, Windows::Foundation::TimeSpan* value, void** propertyValue) noexcept final
    {
        try
        {
            *propertyValue = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CreateTimeSpanArray, WINRT_WRAP(Windows::Foundation::IInspectable), array_view<Windows::Foundation::TimeSpan const>);
            *propertyValue = detach_from<Windows::Foundation::IInspectable>(this->shim().CreateTimeSpanArray(array_view<Windows::Foundation::TimeSpan const>(reinterpret_cast<Windows::Foundation::TimeSpan const *>(value), reinterpret_cast<Windows::Foundation::TimeSpan const *>(value) + __valueSize)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL CreatePointArray(uint32_t __valueSize, Windows::Foundation::Point* value, void** propertyValue) noexcept final
    {
        try
        {
            *propertyValue = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CreatePointArray, WINRT_WRAP(Windows::Foundation::IInspectable), array_view<Windows::Foundation::Point const>);
            *propertyValue = detach_from<Windows::Foundation::IInspectable>(this->shim().CreatePointArray(array_view<Windows::Foundation::Point const>(reinterpret_cast<Windows::Foundation::Point const *>(value), reinterpret_cast<Windows::Foundation::Point const *>(value) + __valueSize)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL CreateSizeArray(uint32_t __valueSize, Windows::Foundation::Size* value, void** propertyValue) noexcept final
    {
        try
        {
            *propertyValue = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CreateSizeArray, WINRT_WRAP(Windows::Foundation::IInspectable), array_view<Windows::Foundation::Size const>);
            *propertyValue = detach_from<Windows::Foundation::IInspectable>(this->shim().CreateSizeArray(array_view<Windows::Foundation::Size const>(reinterpret_cast<Windows::Foundation::Size const *>(value), reinterpret_cast<Windows::Foundation::Size const *>(value) + __valueSize)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL CreateRectArray(uint32_t __valueSize, Windows::Foundation::Rect* value, void** propertyValue) noexcept final
    {
        try
        {
            *propertyValue = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CreateRectArray, WINRT_WRAP(Windows::Foundation::IInspectable), array_view<Windows::Foundation::Rect const>);
            *propertyValue = detach_from<Windows::Foundation::IInspectable>(this->shim().CreateRectArray(array_view<Windows::Foundation::Rect const>(reinterpret_cast<Windows::Foundation::Rect const *>(value), reinterpret_cast<Windows::Foundation::Rect const *>(value) + __valueSize)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Foundation::IStringable> : produce_base<D, Windows::Foundation::IStringable>
{
    int32_t WINRT_CALL ToString(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ToString, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().ToString());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Foundation::IUriEscapeStatics> : produce_base<D, Windows::Foundation::IUriEscapeStatics>
{
    int32_t WINRT_CALL UnescapeComponent(void* toUnescape, void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(UnescapeComponent, WINRT_WRAP(hstring), hstring const&);
            *value = detach_from<hstring>(this->shim().UnescapeComponent(*reinterpret_cast<hstring const*>(&toUnescape)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL EscapeComponent(void* toEscape, void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(EscapeComponent, WINRT_WRAP(hstring), hstring const&);
            *value = detach_from<hstring>(this->shim().EscapeComponent(*reinterpret_cast<hstring const*>(&toEscape)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Foundation::IUriRuntimeClass> : produce_base<D, Windows::Foundation::IUriRuntimeClass>
{
    int32_t WINRT_CALL get_AbsoluteUri(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(AbsoluteUri, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().AbsoluteUri());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_DisplayUri(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(DisplayUri, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().DisplayUri());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Domain(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Domain, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().Domain());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Extension(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Extension, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().Extension());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Fragment(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Fragment, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().Fragment());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Host(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Host, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().Host());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Password(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Password, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().Password());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Path(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Path, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().Path());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Query(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Query, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().Query());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_QueryParsed(void** ppWwwFormUrlDecoder) noexcept final
    {
        try
        {
            *ppWwwFormUrlDecoder = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(QueryParsed, WINRT_WRAP(Windows::Foundation::WwwFormUrlDecoder));
            *ppWwwFormUrlDecoder = detach_from<Windows::Foundation::WwwFormUrlDecoder>(this->shim().QueryParsed());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_RawUri(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(RawUri, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().RawUri());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_SchemeName(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SchemeName, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().SchemeName());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_UserName(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(UserName, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().UserName());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Port(int32_t* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Port, WINRT_WRAP(int32_t));
            *value = detach_from<int32_t>(this->shim().Port());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Suspicious(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Suspicious, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().Suspicious());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL Equals(void* pUri, bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Equals, WINRT_WRAP(bool), Windows::Foundation::Uri const&);
            *value = detach_from<bool>(this->shim().Equals(*reinterpret_cast<Windows::Foundation::Uri const*>(&pUri)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL CombineUri(void* relativeUri, void** instance) noexcept final
    {
        try
        {
            *instance = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CombineUri, WINRT_WRAP(Windows::Foundation::Uri), hstring const&);
            *instance = detach_from<Windows::Foundation::Uri>(this->shim().CombineUri(*reinterpret_cast<hstring const*>(&relativeUri)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Foundation::IUriRuntimeClassFactory> : produce_base<D, Windows::Foundation::IUriRuntimeClassFactory>
{
    int32_t WINRT_CALL CreateUri(void* uri, void** instance) noexcept final
    {
        try
        {
            *instance = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CreateUri, WINRT_WRAP(Windows::Foundation::Uri), hstring const&);
            *instance = detach_from<Windows::Foundation::Uri>(this->shim().CreateUri(*reinterpret_cast<hstring const*>(&uri)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL CreateWithRelativeUri(void* baseUri, void* relativeUri, void** instance) noexcept final
    {
        try
        {
            *instance = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CreateWithRelativeUri, WINRT_WRAP(Windows::Foundation::Uri), hstring const&, hstring const&);
            *instance = detach_from<Windows::Foundation::Uri>(this->shim().CreateWithRelativeUri(*reinterpret_cast<hstring const*>(&baseUri), *reinterpret_cast<hstring const*>(&relativeUri)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Foundation::IUriRuntimeClassWithAbsoluteCanonicalUri> : produce_base<D, Windows::Foundation::IUriRuntimeClassWithAbsoluteCanonicalUri>
{
    int32_t WINRT_CALL get_AbsoluteCanonicalUri(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(AbsoluteCanonicalUri, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().AbsoluteCanonicalUri());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_DisplayIri(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(DisplayIri, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().DisplayIri());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Foundation::IWwwFormUrlDecoderEntry> : produce_base<D, Windows::Foundation::IWwwFormUrlDecoderEntry>
{
    int32_t WINRT_CALL get_Name(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Name, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().Name());
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
            WINRT_ASSERT_DECLARATION(Value, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().Value());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Foundation::IWwwFormUrlDecoderRuntimeClass> : produce_base<D, Windows::Foundation::IWwwFormUrlDecoderRuntimeClass>
{
    int32_t WINRT_CALL GetFirstValueByName(void* name, void** phstrValue) noexcept final
    {
        try
        {
            *phstrValue = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetFirstValueByName, WINRT_WRAP(hstring), hstring const&);
            *phstrValue = detach_from<hstring>(this->shim().GetFirstValueByName(*reinterpret_cast<hstring const*>(&name)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Foundation::IWwwFormUrlDecoderRuntimeClassFactory> : produce_base<D, Windows::Foundation::IWwwFormUrlDecoderRuntimeClassFactory>
{
    int32_t WINRT_CALL CreateWwwFormUrlDecoder(void* query, void** instance) noexcept final
    {
        try
        {
            *instance = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CreateWwwFormUrlDecoder, WINRT_WRAP(Windows::Foundation::WwwFormUrlDecoder), hstring const&);
            *instance = detach_from<Windows::Foundation::WwwFormUrlDecoder>(this->shim().CreateWwwFormUrlDecoder(*reinterpret_cast<hstring const*>(&query)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

}

WINRT_EXPORT namespace winrt::Windows::Foundation {

inline Deferral::Deferral(Windows::Foundation::DeferralCompletedHandler const& handler) :
    Deferral(impl::call_factory<Deferral, Windows::Foundation::IDeferralFactory>([&](auto&& f) { return f.Create(handler); }))
{}

inline winrt::guid GuidHelper::CreateNewGuid()
{
    return impl::call_factory<GuidHelper, Windows::Foundation::IGuidHelperStatics>([&](auto&& f) { return f.CreateNewGuid(); });
}

inline winrt::guid GuidHelper::Empty()
{
    return impl::call_factory<GuidHelper, Windows::Foundation::IGuidHelperStatics>([&](auto&& f) { return f.Empty(); });
}

inline bool GuidHelper::Equals(winrt::guid const& target, winrt::guid const& value)
{
    return impl::call_factory<GuidHelper, Windows::Foundation::IGuidHelperStatics>([&](auto&& f) { return f.Equals(target, value); });
}

inline MemoryBuffer::MemoryBuffer(uint32_t capacity) :
    MemoryBuffer(impl::call_factory<MemoryBuffer, Windows::Foundation::IMemoryBufferFactory>([&](auto&& f) { return f.Create(capacity); }))
{}

inline Windows::Foundation::IInspectable PropertyValue::CreateEmpty()
{
    return impl::call_factory<PropertyValue, Windows::Foundation::IPropertyValueStatics>([&](auto&& f) { return f.CreateEmpty(); });
}

inline Windows::Foundation::IInspectable PropertyValue::CreateUInt8(uint8_t value)
{
    return impl::call_factory<PropertyValue, Windows::Foundation::IPropertyValueStatics>([&](auto&& f) { return f.CreateUInt8(value); });
}

inline Windows::Foundation::IInspectable PropertyValue::CreateInt16(int16_t value)
{
    return impl::call_factory<PropertyValue, Windows::Foundation::IPropertyValueStatics>([&](auto&& f) { return f.CreateInt16(value); });
}

inline Windows::Foundation::IInspectable PropertyValue::CreateUInt16(uint16_t value)
{
    return impl::call_factory<PropertyValue, Windows::Foundation::IPropertyValueStatics>([&](auto&& f) { return f.CreateUInt16(value); });
}

inline Windows::Foundation::IInspectable PropertyValue::CreateInt32(int32_t value)
{
    return impl::call_factory<PropertyValue, Windows::Foundation::IPropertyValueStatics>([&](auto&& f) { return f.CreateInt32(value); });
}

inline Windows::Foundation::IInspectable PropertyValue::CreateUInt32(uint32_t value)
{
    return impl::call_factory<PropertyValue, Windows::Foundation::IPropertyValueStatics>([&](auto&& f) { return f.CreateUInt32(value); });
}

inline Windows::Foundation::IInspectable PropertyValue::CreateInt64(int64_t value)
{
    return impl::call_factory<PropertyValue, Windows::Foundation::IPropertyValueStatics>([&](auto&& f) { return f.CreateInt64(value); });
}

inline Windows::Foundation::IInspectable PropertyValue::CreateUInt64(uint64_t value)
{
    return impl::call_factory<PropertyValue, Windows::Foundation::IPropertyValueStatics>([&](auto&& f) { return f.CreateUInt64(value); });
}

inline Windows::Foundation::IInspectable PropertyValue::CreateSingle(float value)
{
    return impl::call_factory<PropertyValue, Windows::Foundation::IPropertyValueStatics>([&](auto&& f) { return f.CreateSingle(value); });
}

inline Windows::Foundation::IInspectable PropertyValue::CreateDouble(double value)
{
    return impl::call_factory<PropertyValue, Windows::Foundation::IPropertyValueStatics>([&](auto&& f) { return f.CreateDouble(value); });
}

inline Windows::Foundation::IInspectable PropertyValue::CreateChar16(char16_t value)
{
    return impl::call_factory<PropertyValue, Windows::Foundation::IPropertyValueStatics>([&](auto&& f) { return f.CreateChar16(value); });
}

inline Windows::Foundation::IInspectable PropertyValue::CreateBoolean(bool value)
{
    return impl::call_factory<PropertyValue, Windows::Foundation::IPropertyValueStatics>([&](auto&& f) { return f.CreateBoolean(value); });
}

inline Windows::Foundation::IInspectable PropertyValue::CreateString(param::hstring const& value)
{
    return impl::call_factory<PropertyValue, Windows::Foundation::IPropertyValueStatics>([&](auto&& f) { return f.CreateString(value); });
}

inline Windows::Foundation::IInspectable PropertyValue::CreateInspectable(Windows::Foundation::IInspectable const& value)
{
    return impl::call_factory<PropertyValue, Windows::Foundation::IPropertyValueStatics>([&](auto&& f) { return f.CreateInspectable(value); });
}

inline Windows::Foundation::IInspectable PropertyValue::CreateGuid(winrt::guid const& value)
{
    return impl::call_factory<PropertyValue, Windows::Foundation::IPropertyValueStatics>([&](auto&& f) { return f.CreateGuid(value); });
}

inline Windows::Foundation::IInspectable PropertyValue::CreateDateTime(Windows::Foundation::DateTime const& value)
{
    return impl::call_factory<PropertyValue, Windows::Foundation::IPropertyValueStatics>([&](auto&& f) { return f.CreateDateTime(value); });
}

inline Windows::Foundation::IInspectable PropertyValue::CreateTimeSpan(Windows::Foundation::TimeSpan const& value)
{
    return impl::call_factory<PropertyValue, Windows::Foundation::IPropertyValueStatics>([&](auto&& f) { return f.CreateTimeSpan(value); });
}

inline Windows::Foundation::IInspectable PropertyValue::CreatePoint(Windows::Foundation::Point const& value)
{
    return impl::call_factory<PropertyValue, Windows::Foundation::IPropertyValueStatics>([&](auto&& f) { return f.CreatePoint(value); });
}

inline Windows::Foundation::IInspectable PropertyValue::CreateSize(Windows::Foundation::Size const& value)
{
    return impl::call_factory<PropertyValue, Windows::Foundation::IPropertyValueStatics>([&](auto&& f) { return f.CreateSize(value); });
}

inline Windows::Foundation::IInspectable PropertyValue::CreateRect(Windows::Foundation::Rect const& value)
{
    return impl::call_factory<PropertyValue, Windows::Foundation::IPropertyValueStatics>([&](auto&& f) { return f.CreateRect(value); });
}

inline Windows::Foundation::IInspectable PropertyValue::CreateUInt8Array(array_view<uint8_t const> value)
{
    return impl::call_factory<PropertyValue, Windows::Foundation::IPropertyValueStatics>([&](auto&& f) { return f.CreateUInt8Array(value); });
}

inline Windows::Foundation::IInspectable PropertyValue::CreateInt16Array(array_view<int16_t const> value)
{
    return impl::call_factory<PropertyValue, Windows::Foundation::IPropertyValueStatics>([&](auto&& f) { return f.CreateInt16Array(value); });
}

inline Windows::Foundation::IInspectable PropertyValue::CreateUInt16Array(array_view<uint16_t const> value)
{
    return impl::call_factory<PropertyValue, Windows::Foundation::IPropertyValueStatics>([&](auto&& f) { return f.CreateUInt16Array(value); });
}

inline Windows::Foundation::IInspectable PropertyValue::CreateInt32Array(array_view<int32_t const> value)
{
    return impl::call_factory<PropertyValue, Windows::Foundation::IPropertyValueStatics>([&](auto&& f) { return f.CreateInt32Array(value); });
}

inline Windows::Foundation::IInspectable PropertyValue::CreateUInt32Array(array_view<uint32_t const> value)
{
    return impl::call_factory<PropertyValue, Windows::Foundation::IPropertyValueStatics>([&](auto&& f) { return f.CreateUInt32Array(value); });
}

inline Windows::Foundation::IInspectable PropertyValue::CreateInt64Array(array_view<int64_t const> value)
{
    return impl::call_factory<PropertyValue, Windows::Foundation::IPropertyValueStatics>([&](auto&& f) { return f.CreateInt64Array(value); });
}

inline Windows::Foundation::IInspectable PropertyValue::CreateUInt64Array(array_view<uint64_t const> value)
{
    return impl::call_factory<PropertyValue, Windows::Foundation::IPropertyValueStatics>([&](auto&& f) { return f.CreateUInt64Array(value); });
}

inline Windows::Foundation::IInspectable PropertyValue::CreateSingleArray(array_view<float const> value)
{
    return impl::call_factory<PropertyValue, Windows::Foundation::IPropertyValueStatics>([&](auto&& f) { return f.CreateSingleArray(value); });
}

inline Windows::Foundation::IInspectable PropertyValue::CreateDoubleArray(array_view<double const> value)
{
    return impl::call_factory<PropertyValue, Windows::Foundation::IPropertyValueStatics>([&](auto&& f) { return f.CreateDoubleArray(value); });
}

inline Windows::Foundation::IInspectable PropertyValue::CreateChar16Array(array_view<char16_t const> value)
{
    return impl::call_factory<PropertyValue, Windows::Foundation::IPropertyValueStatics>([&](auto&& f) { return f.CreateChar16Array(value); });
}

inline Windows::Foundation::IInspectable PropertyValue::CreateBooleanArray(array_view<bool const> value)
{
    return impl::call_factory<PropertyValue, Windows::Foundation::IPropertyValueStatics>([&](auto&& f) { return f.CreateBooleanArray(value); });
}

inline Windows::Foundation::IInspectable PropertyValue::CreateStringArray(array_view<hstring const> value)
{
    return impl::call_factory<PropertyValue, Windows::Foundation::IPropertyValueStatics>([&](auto&& f) { return f.CreateStringArray(value); });
}

inline Windows::Foundation::IInspectable PropertyValue::CreateInspectableArray(array_view<Windows::Foundation::IInspectable const> value)
{
    return impl::call_factory<PropertyValue, Windows::Foundation::IPropertyValueStatics>([&](auto&& f) { return f.CreateInspectableArray(value); });
}

inline Windows::Foundation::IInspectable PropertyValue::CreateGuidArray(array_view<winrt::guid const> value)
{
    return impl::call_factory<PropertyValue, Windows::Foundation::IPropertyValueStatics>([&](auto&& f) { return f.CreateGuidArray(value); });
}

inline Windows::Foundation::IInspectable PropertyValue::CreateDateTimeArray(array_view<Windows::Foundation::DateTime const> value)
{
    return impl::call_factory<PropertyValue, Windows::Foundation::IPropertyValueStatics>([&](auto&& f) { return f.CreateDateTimeArray(value); });
}

inline Windows::Foundation::IInspectable PropertyValue::CreateTimeSpanArray(array_view<Windows::Foundation::TimeSpan const> value)
{
    return impl::call_factory<PropertyValue, Windows::Foundation::IPropertyValueStatics>([&](auto&& f) { return f.CreateTimeSpanArray(value); });
}

inline Windows::Foundation::IInspectable PropertyValue::CreatePointArray(array_view<Windows::Foundation::Point const> value)
{
    return impl::call_factory<PropertyValue, Windows::Foundation::IPropertyValueStatics>([&](auto&& f) { return f.CreatePointArray(value); });
}

inline Windows::Foundation::IInspectable PropertyValue::CreateSizeArray(array_view<Windows::Foundation::Size const> value)
{
    return impl::call_factory<PropertyValue, Windows::Foundation::IPropertyValueStatics>([&](auto&& f) { return f.CreateSizeArray(value); });
}

inline Windows::Foundation::IInspectable PropertyValue::CreateRectArray(array_view<Windows::Foundation::Rect const> value)
{
    return impl::call_factory<PropertyValue, Windows::Foundation::IPropertyValueStatics>([&](auto&& f) { return f.CreateRectArray(value); });
}

inline Uri::Uri(param::hstring const& uri) :
    Uri(impl::call_factory<Uri, Windows::Foundation::IUriRuntimeClassFactory>([&](auto&& f) { return f.CreateUri(uri); }))
{}

inline Uri::Uri(param::hstring const& baseUri, param::hstring const& relativeUri) :
    Uri(impl::call_factory<Uri, Windows::Foundation::IUriRuntimeClassFactory>([&](auto&& f) { return f.CreateWithRelativeUri(baseUri, relativeUri); }))
{}

inline hstring Uri::UnescapeComponent(param::hstring const& toUnescape)
{
    return impl::call_factory<Uri, Windows::Foundation::IUriEscapeStatics>([&](auto&& f) { return f.UnescapeComponent(toUnescape); });
}

inline hstring Uri::EscapeComponent(param::hstring const& toEscape)
{
    return impl::call_factory<Uri, Windows::Foundation::IUriEscapeStatics>([&](auto&& f) { return f.EscapeComponent(toEscape); });
}

inline WwwFormUrlDecoder::WwwFormUrlDecoder(param::hstring const& query) :
    WwwFormUrlDecoder(impl::call_factory<WwwFormUrlDecoder, Windows::Foundation::IWwwFormUrlDecoderRuntimeClassFactory>([&](auto&& f) { return f.CreateWwwFormUrlDecoder(query); }))
{}

template <typename L> DeferralCompletedHandler::DeferralCompletedHandler(L handler) :
    DeferralCompletedHandler(impl::make_delegate<DeferralCompletedHandler>(std::forward<L>(handler)))
{}

template <typename F> DeferralCompletedHandler::DeferralCompletedHandler(F* handler) :
    DeferralCompletedHandler([=](auto&&... args) { return handler(args...); })
{}

template <typename O, typename M> DeferralCompletedHandler::DeferralCompletedHandler(O* object, M method) :
    DeferralCompletedHandler([=](auto&&... args) { return ((*object).*(method))(args...); })
{}

template <typename O, typename M> DeferralCompletedHandler::DeferralCompletedHandler(com_ptr<O>&& object, M method) :
    DeferralCompletedHandler([o = std::move(object), method](auto&&... args) { return ((*o).*(method))(args...); })
{}

template <typename O, typename M> DeferralCompletedHandler::DeferralCompletedHandler(weak_ref<O>&& object, M method) :
    DeferralCompletedHandler([o = std::move(object), method](auto&&... args) { if (auto s = o.get()) { ((*s).*(method))(args...); } })
{}

inline void DeferralCompletedHandler::operator()() const
{
    check_hresult((*(impl::abi_t<DeferralCompletedHandler>**)this)->Invoke());
}

}

namespace winrt::impl
{
    template <typename D, typename T>
    struct produce<D, Windows::Foundation::IReference<T>> : produce_base<D, Windows::Foundation::IReference<T>>
    {
        int32_t WINRT_CALL get_Value(arg_out<T> value) noexcept final
        {
            try
            {
                typename D::abi_guard guard(this->shim());
                *value = detach_from<T>(this->shim().Value());
                return error_ok;
            }
            catch (...) { return to_hresult(); }
        }
    };

    template <typename D, typename T>
    struct produce<D, Windows::Foundation::IReferenceArray<T>> : produce_base<D, Windows::Foundation::IReferenceArray<T>>
    {
        int32_t WINRT_CALL get_Value(uint32_t* __valueSize, arg_out<T>* value) noexcept final
        {
            try
            {
                *__valueSize = 0;
                *value = nullptr;
                typename D::abi_guard guard(this->shim());
                std::tie(*__valueSize, *value) = detach_abi(this->shim().Value());
                return error_ok;
            }
            catch (...) { return to_hresult(); }
        }
    };

    template <typename T>
    struct reference final : implements<reference<T>, Windows::Foundation::IReference<T>, Windows::Foundation::IPropertyValue>
    {
        reference(T const& value) : m_value(value)
        {
        }

        T Value() const
        {
            return m_value;
        }

        Windows::Foundation::PropertyType Type() const noexcept
        {
            return Windows::Foundation::PropertyType::OtherType;
        }

        static constexpr bool IsNumericScalar() noexcept
        {
            return std::is_arithmetic_v<T> || std::is_enum_v<T>;
        }

        uint8_t GetUInt8() const
        {
            return to_scalar<uint8_t>();
        }

        int16_t GetInt16() const
        {
            return to_scalar<int16_t>();
        }

        uint16_t GetUInt16() const
        {
            return to_scalar<uint16_t>();
        }

        int32_t GetInt32() const
        {
            return to_scalar<int32_t>();
        }

        uint32_t GetUInt32() const
        {
            return to_scalar<uint32_t>();
        }

        int64_t GetInt64() const
        {
            return to_scalar<int64_t>();
        }

        uint64_t GetUInt64() const
        {
            return to_scalar<uint64_t>();
        }

        float GetSingle() { throw hresult_not_implemented(); }
        double GetDouble() { throw hresult_not_implemented(); }
        char16_t GetChar16() { throw hresult_not_implemented(); }
        bool GetBoolean() { throw hresult_not_implemented(); }
        hstring GetString() { throw hresult_not_implemented(); }
        guid GetGuid() { throw hresult_not_implemented(); }
        Windows::Foundation::DateTime GetDateTime() { throw hresult_not_implemented(); }
        Windows::Foundation::TimeSpan GetTimeSpan() { throw hresult_not_implemented(); }
        Windows::Foundation::Point GetPoint() { throw hresult_not_implemented(); }
        Windows::Foundation::Size GetSize() { throw hresult_not_implemented(); }
        Windows::Foundation::Rect GetRect() { throw hresult_not_implemented(); }
        void GetUInt8Array(com_array<uint8_t> &) { throw hresult_not_implemented(); }
        void GetInt16Array(com_array<int16_t> &) { throw hresult_not_implemented(); }
        void GetUInt16Array(com_array<uint16_t> &) { throw hresult_not_implemented(); }
        void GetInt32Array(com_array<int32_t> &) { throw hresult_not_implemented(); }
        void GetUInt32Array(com_array<uint32_t> &) { throw hresult_not_implemented(); }
        void GetInt64Array(com_array<int64_t> &) { throw hresult_not_implemented(); }
        void GetUInt64Array(com_array<uint64_t> &) { throw hresult_not_implemented(); }
        void GetSingleArray(com_array<float> &) { throw hresult_not_implemented(); }
        void GetDoubleArray(com_array<double> &) { throw hresult_not_implemented(); }
        void GetChar16Array(com_array<char16_t> &) { throw hresult_not_implemented(); }
        void GetBooleanArray(com_array<bool> &) { throw hresult_not_implemented(); }
        void GetStringArray(com_array<hstring> &) { throw hresult_not_implemented(); }
        void GetInspectableArray(com_array<Windows::Foundation::IInspectable> &) { throw hresult_not_implemented(); }
        void GetGuidArray(com_array<guid> &) { throw hresult_not_implemented(); }
        void GetDateTimeArray(com_array<Windows::Foundation::DateTime> &) { throw hresult_not_implemented(); }
        void GetTimeSpanArray(com_array<Windows::Foundation::TimeSpan> &) { throw hresult_not_implemented(); }
        void GetPointArray(com_array<Windows::Foundation::Point> &) { throw hresult_not_implemented(); }
        void GetSizeArray(com_array<Windows::Foundation::Size> &) { throw hresult_not_implemented(); }
        void GetRectArray(com_array<Windows::Foundation::Rect> &) { throw hresult_not_implemented(); }

    private:

        template <typename To>
        To to_scalar() const
        {
            if constexpr (IsNumericScalar())
            {
                return static_cast<To>(m_value);
            }
            else
            {
                throw hresult_not_implemented();
            }
        }

        T m_value;
    };

    template <typename T>
    struct reference_traits
    {
        static auto make(T const& value) { return winrt::make<impl::reference<T>>(value); }
    };

    template <>
    struct reference_traits<uint8_t>
    {
        static auto make(uint8_t value) { return Windows::Foundation::PropertyValue::CreateUInt8(value); }
    };

    template <>
    struct reference_traits<uint16_t>
    {
        static auto make(uint16_t value) { return Windows::Foundation::PropertyValue::CreateUInt16(value); }
    };

    template <>
    struct reference_traits<int16_t>
    {
        static auto make(int16_t value) { return Windows::Foundation::PropertyValue::CreateInt16(value); }
    };

    template <>
    struct reference_traits<uint32_t>
    {
        static auto make(uint32_t value) { return Windows::Foundation::PropertyValue::CreateUInt32(value); }
    };

    template <>
    struct reference_traits<int32_t>
    {
        static auto make(int32_t value) { return Windows::Foundation::PropertyValue::CreateInt32(value); }
    };

    template <>
    struct reference_traits<uint64_t>
    {
        static auto make(uint64_t value) { return Windows::Foundation::PropertyValue::CreateUInt64(value); }
    };

    template <>
    struct reference_traits<int64_t>
    {
        static auto make(int64_t value) { return Windows::Foundation::PropertyValue::CreateInt64(value); }
    };

    template <>
    struct reference_traits<float>
    {
        static auto make(float value) { return Windows::Foundation::PropertyValue::CreateSingle(value); }
    };

    template <>
    struct reference_traits<double>
    {
        static auto make(double value) { return Windows::Foundation::PropertyValue::CreateDouble(value); }
    };

    template <>
    struct reference_traits<char16_t>
    {
        static auto make(char16_t value) { return Windows::Foundation::PropertyValue::CreateChar16(value); }
    };

    template <>
    struct reference_traits<bool>
    {
        static auto make(bool value) { return Windows::Foundation::PropertyValue::CreateBoolean(value); }
    };

    template <>
    struct reference_traits<hstring>
    {
        static auto make(hstring const& value) { return Windows::Foundation::PropertyValue::CreateString(value); }
    };

    template <>
    struct reference_traits<Windows::Foundation::IInspectable>
    {
        static auto make(Windows::Foundation::IInspectable const& value) { return Windows::Foundation::PropertyValue::CreateInspectable(value); }
    };

    template <>
    struct reference_traits<guid>
    {
        static auto make(guid const& value) { return Windows::Foundation::PropertyValue::CreateGuid(value); }
    };

    template <>
    struct reference_traits<Windows::Foundation::DateTime>
    {
        static auto make(Windows::Foundation::DateTime value) { return Windows::Foundation::PropertyValue::CreateDateTime(value); }
    };

    template <>
    struct reference_traits<Windows::Foundation::TimeSpan>
    {
        static auto make(Windows::Foundation::TimeSpan value) { return Windows::Foundation::PropertyValue::CreateTimeSpan(value); }
    };

    template <>
    struct reference_traits<Windows::Foundation::Point>
    {
        static auto make(Windows::Foundation::Point const& value) { return Windows::Foundation::PropertyValue::CreatePoint(value); }
    };

    template <>
    struct reference_traits<Windows::Foundation::Size>
    {
        static auto make(Windows::Foundation::Size const& value) { return Windows::Foundation::PropertyValue::CreateSize(value); }
    };

    template <>
    struct reference_traits<Windows::Foundation::Rect>
    {
        static auto make(Windows::Foundation::Rect const& value) { return Windows::Foundation::PropertyValue::CreateRect(value); }
    };
}

WINRT_EXPORT namespace winrt::Windows::Foundation
{
    template <typename T>
    struct IReference :
        IInspectable,
        impl::consume_t<IReference<T>>,
        impl::require<IReference<T>, IPropertyValue>
    {
        static_assert(impl::has_category_v<T>, "T must be WinRT type.");
        IReference<T>(std::nullptr_t = nullptr) noexcept {}

        IReference<T>(T const& value) : IReference<T>(impl::reference_traits<T>::make(value))
        {
        }

    private:

        IReference<T>(IInspectable const& value) : IReference<T>(value.as<IReference<T>>())
        {
        }
    };

    template <typename T>
    bool operator==(IReference<T> const& left, IReference<T> const& right)
    {
        if (get_abi(left) == get_abi(right))
        {
            return true;
        }

        if (!left || !right)
        {
            return false;
        }

        return left.Value() == right.Value();
    }

    template <typename T>
    bool operator!=(IReference<T> const& left, IReference<T> const& right)
    {
        return !(left == right);
    }

    template <typename T>
    struct WINRT_EBO IReferenceArray :
        IInspectable,
        impl::consume_t<IReferenceArray<T>>,
        impl::require<IReferenceArray<T>, IPropertyValue>
    {
        static_assert(impl::has_category_v<T>, "T must be WinRT type.");
        IReferenceArray<T>(std::nullptr_t = nullptr) noexcept {}
    };
}

WINRT_EXPORT namespace winrt
{
    inline Windows::Foundation::IInspectable box_value(param::hstring const& value)
    {
        return Windows::Foundation::IReference<hstring>(*(hstring*)(&value));
    }

    template <typename T, typename = std::enable_if_t<!std::is_convertible_v<T, param::hstring>>>
    Windows::Foundation::IInspectable box_value(T const& value)
    {
        if constexpr (std::is_base_of_v<Windows::Foundation::IInspectable, T>)
        {
            return value;
        }
        else
        {
            return Windows::Foundation::IReference<T>(value);
        }
    }

    template <typename T>
    T unbox_value(Windows::Foundation::IInspectable const& value)
    {
        if constexpr (std::is_base_of_v<Windows::Foundation::IInspectable, T>)
        {
            return value.as<T>();
        }
        else if constexpr (std::is_enum_v<T>)
        {
            if (auto temp = value.try_as<Windows::Foundation::IReference<T>>())
            {
                return temp.Value();
            }
            else
            {
                return static_cast<T>(value.as<Windows::Foundation::IReference<std::underlying_type_t<T>>>().Value());
            }
        }
        else
        {
            return value.as<Windows::Foundation::IReference<T>>().Value();
        }
    }

    template <typename T>
    hstring unbox_value_or(Windows::Foundation::IInspectable const& value, param::hstring const& default_value)
    {
        if (value)
        {
            if (auto temp = value.try_as<Windows::Foundation::IReference<hstring>>())
            {
                return temp.Value();
            }
        }

        return *(hstring*)(&default_value);
    }

    template <typename T, typename = std::enable_if_t<!std::is_same_v<T, hstring>>>
    T unbox_value_or(Windows::Foundation::IInspectable const& value, T const& default_value)
    {
        if (value)
        {
            if constexpr (std::is_base_of_v<Windows::Foundation::IInspectable, T>)
            {
                if (auto temp = value.try_as<T>())
                {
                    return temp;
                }
            }
            else if constexpr (std::is_enum_v<T>)
            {
                if (auto temp = value.try_as<Windows::Foundation::IReference<T>>())
                {
                    return temp.Value();
                }

                if (auto temp = value.try_as<Windows::Foundation::IReference<std::underlying_type_t<T>>>())
                {
                    return static_cast<T>(temp.Value());
                }
            }
            else
            {
                if (auto temp = value.try_as<Windows::Foundation::IReference<T>>())
                {
                    return temp.Value();
                }
            }
        }

        return default_value;
    }
}
WINRT_EXPORT namespace std {
template<> struct hash<winrt::Windows::Foundation::IUnknown> : winrt::impl::hash_base<winrt::Windows::Foundation::IUnknown> {};
template<> struct hash<winrt::Windows::Foundation::IInspectable> : winrt::impl::hash_base<winrt::Windows::Foundation::IInspectable> {};
template<> struct hash<winrt::Windows::Foundation::IActivationFactory> : winrt::impl::hash_base<winrt::Windows::Foundation::IActivationFactory> {};
template<> struct hash<winrt::Windows::Foundation::IAsyncInfo> : winrt::impl::hash_base<winrt::Windows::Foundation::IAsyncInfo> {};
template<> struct hash<winrt::Windows::Foundation::IAsyncAction> : winrt::impl::hash_base<winrt::Windows::Foundation::IAsyncAction> {};
template<typename TProgress> struct hash<winrt::Windows::Foundation::IAsyncActionWithProgress<TProgress>> : winrt::impl::hash_base<winrt::Windows::Foundation::IAsyncActionWithProgress<TProgress>> {};
template<typename TResult> struct hash<winrt::Windows::Foundation::IAsyncOperation<TResult>> : winrt::impl::hash_base<winrt::Windows::Foundation::IAsyncOperation<TResult>> {};
template<typename TResult, typename TProgress> struct hash<winrt::Windows::Foundation::IAsyncOperationWithProgress<TResult, TProgress>> : winrt::impl::hash_base<winrt::Windows::Foundation::IAsyncOperationWithProgress<TResult, TProgress>> {};
template<> struct hash<winrt::Windows::Foundation::AsyncActionCompletedHandler> : winrt::impl::hash_base<winrt::Windows::Foundation::AsyncActionCompletedHandler> {};
template<typename TProgress> struct hash<winrt::Windows::Foundation::AsyncActionProgressHandler<TProgress>> : winrt::impl::hash_base<winrt::Windows::Foundation::AsyncActionProgressHandler<TProgress>> {};
template<typename TProgress> struct hash<winrt::Windows::Foundation::AsyncActionWithProgressCompletedHandler<TProgress>> : winrt::impl::hash_base<winrt::Windows::Foundation::AsyncActionWithProgressCompletedHandler<TProgress>> {};
template<typename TResult> struct hash<winrt::Windows::Foundation::AsyncOperationCompletedHandler<TResult>> : winrt::impl::hash_base<winrt::Windows::Foundation::AsyncOperationCompletedHandler<TResult>> {};
template<typename TResult, typename TProgress> struct hash<winrt::Windows::Foundation::AsyncOperationProgressHandler<TResult, TProgress>> : winrt::impl::hash_base<winrt::Windows::Foundation::AsyncOperationProgressHandler<TResult, TProgress>> {};
template<typename TResult, typename TProgress> struct hash<winrt::Windows::Foundation::AsyncOperationWithProgressCompletedHandler<TResult, TProgress>> : winrt::impl::hash_base<winrt::Windows::Foundation::AsyncOperationWithProgressCompletedHandler<TResult, TProgress>> {};
template<typename T> struct hash<winrt::Windows::Foundation::IReference<T>> : winrt::impl::hash_base<winrt::Windows::Foundation::IReference<T>> {};
template<typename T> struct hash<winrt::Windows::Foundation::EventHandler<T>> : winrt::impl::hash_base<winrt::Windows::Foundation::EventHandler<T>> {};
template<typename TSender, typename TArgs> struct hash<winrt::Windows::Foundation::TypedEventHandler<TSender, TArgs>> : winrt::impl::hash_base<winrt::Windows::Foundation::TypedEventHandler<TSender, TArgs>> {};

}

WINRT_EXPORT namespace std {

template<> struct hash<winrt::Windows::Foundation::IClosable> : winrt::impl::hash_base<winrt::Windows::Foundation::IClosable> {};
template<> struct hash<winrt::Windows::Foundation::IDeferral> : winrt::impl::hash_base<winrt::Windows::Foundation::IDeferral> {};
template<> struct hash<winrt::Windows::Foundation::IDeferralFactory> : winrt::impl::hash_base<winrt::Windows::Foundation::IDeferralFactory> {};
template<> struct hash<winrt::Windows::Foundation::IGetActivationFactory> : winrt::impl::hash_base<winrt::Windows::Foundation::IGetActivationFactory> {};
template<> struct hash<winrt::Windows::Foundation::IGuidHelperStatics> : winrt::impl::hash_base<winrt::Windows::Foundation::IGuidHelperStatics> {};
template<> struct hash<winrt::Windows::Foundation::IMemoryBuffer> : winrt::impl::hash_base<winrt::Windows::Foundation::IMemoryBuffer> {};
template<> struct hash<winrt::Windows::Foundation::IMemoryBufferFactory> : winrt::impl::hash_base<winrt::Windows::Foundation::IMemoryBufferFactory> {};
template<> struct hash<winrt::Windows::Foundation::IMemoryBufferReference> : winrt::impl::hash_base<winrt::Windows::Foundation::IMemoryBufferReference> {};
template<> struct hash<winrt::Windows::Foundation::IPropertyValue> : winrt::impl::hash_base<winrt::Windows::Foundation::IPropertyValue> {};
template<> struct hash<winrt::Windows::Foundation::IPropertyValueStatics> : winrt::impl::hash_base<winrt::Windows::Foundation::IPropertyValueStatics> {};
template<> struct hash<winrt::Windows::Foundation::IStringable> : winrt::impl::hash_base<winrt::Windows::Foundation::IStringable> {};
template<> struct hash<winrt::Windows::Foundation::IUriEscapeStatics> : winrt::impl::hash_base<winrt::Windows::Foundation::IUriEscapeStatics> {};
template<> struct hash<winrt::Windows::Foundation::IUriRuntimeClass> : winrt::impl::hash_base<winrt::Windows::Foundation::IUriRuntimeClass> {};
template<> struct hash<winrt::Windows::Foundation::IUriRuntimeClassFactory> : winrt::impl::hash_base<winrt::Windows::Foundation::IUriRuntimeClassFactory> {};
template<> struct hash<winrt::Windows::Foundation::IUriRuntimeClassWithAbsoluteCanonicalUri> : winrt::impl::hash_base<winrt::Windows::Foundation::IUriRuntimeClassWithAbsoluteCanonicalUri> {};
template<> struct hash<winrt::Windows::Foundation::IWwwFormUrlDecoderEntry> : winrt::impl::hash_base<winrt::Windows::Foundation::IWwwFormUrlDecoderEntry> {};
template<> struct hash<winrt::Windows::Foundation::IWwwFormUrlDecoderRuntimeClass> : winrt::impl::hash_base<winrt::Windows::Foundation::IWwwFormUrlDecoderRuntimeClass> {};
template<> struct hash<winrt::Windows::Foundation::IWwwFormUrlDecoderRuntimeClassFactory> : winrt::impl::hash_base<winrt::Windows::Foundation::IWwwFormUrlDecoderRuntimeClassFactory> {};
template<> struct hash<winrt::Windows::Foundation::Deferral> : winrt::impl::hash_base<winrt::Windows::Foundation::Deferral> {};
template<> struct hash<winrt::Windows::Foundation::GuidHelper> : winrt::impl::hash_base<winrt::Windows::Foundation::GuidHelper> {};
template<> struct hash<winrt::Windows::Foundation::MemoryBuffer> : winrt::impl::hash_base<winrt::Windows::Foundation::MemoryBuffer> {};
template<> struct hash<winrt::Windows::Foundation::PropertyValue> : winrt::impl::hash_base<winrt::Windows::Foundation::PropertyValue> {};
template<> struct hash<winrt::Windows::Foundation::Uri> : winrt::impl::hash_base<winrt::Windows::Foundation::Uri> {};
template<> struct hash<winrt::Windows::Foundation::WwwFormUrlDecoder> : winrt::impl::hash_base<winrt::Windows::Foundation::WwwFormUrlDecoder> {};
template<> struct hash<winrt::Windows::Foundation::WwwFormUrlDecoderEntry> : winrt::impl::hash_base<winrt::Windows::Foundation::WwwFormUrlDecoderEntry> {};

}
