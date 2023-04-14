// C++/WinRT v1.0.190111.3

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#pragma once

#include "winrt/base.h"

#include "winrt/Windows.Foundation.h"
#include "winrt/Windows.Foundation.Collections.h"
#include "winrt/impl/Windows.Foundation.2.h"
#include "winrt/impl/Windows.Foundation.Collections.2.h"
#include "winrt/impl/Windows.Data.Json.2.h"

namespace winrt::impl {

template <typename D> Windows::Data::Json::JsonObject consume_Windows_Data_Json_IJsonArray<D>::GetObjectAt(uint32_t index) const
{
    Windows::Data::Json::JsonObject returnValue{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Data::Json::IJsonArray)->GetObjectAt(index, put_abi(returnValue)));
    return returnValue;
}

template <typename D> Windows::Data::Json::JsonArray consume_Windows_Data_Json_IJsonArray<D>::GetArrayAt(uint32_t index) const
{
    Windows::Data::Json::JsonArray returnValue{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Data::Json::IJsonArray)->GetArrayAt(index, put_abi(returnValue)));
    return returnValue;
}

template <typename D> hstring consume_Windows_Data_Json_IJsonArray<D>::GetStringAt(uint32_t index) const
{
    hstring returnValue{};
    check_hresult(WINRT_SHIM(Windows::Data::Json::IJsonArray)->GetStringAt(index, put_abi(returnValue)));
    return returnValue;
}

template <typename D> double consume_Windows_Data_Json_IJsonArray<D>::GetNumberAt(uint32_t index) const
{
    double returnValue{};
    check_hresult(WINRT_SHIM(Windows::Data::Json::IJsonArray)->GetNumberAt(index, &returnValue));
    return returnValue;
}

template <typename D> bool consume_Windows_Data_Json_IJsonArray<D>::GetBooleanAt(uint32_t index) const
{
    bool returnValue{};
    check_hresult(WINRT_SHIM(Windows::Data::Json::IJsonArray)->GetBooleanAt(index, &returnValue));
    return returnValue;
}

template <typename D> Windows::Data::Json::JsonArray consume_Windows_Data_Json_IJsonArrayStatics<D>::Parse(param::hstring const& input) const
{
    Windows::Data::Json::JsonArray jsonArray{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Data::Json::IJsonArrayStatics)->Parse(get_abi(input), put_abi(jsonArray)));
    return jsonArray;
}

template <typename D> bool consume_Windows_Data_Json_IJsonArrayStatics<D>::TryParse(param::hstring const& input, Windows::Data::Json::JsonArray& result) const
{
    bool succeeded{};
    check_hresult(WINRT_SHIM(Windows::Data::Json::IJsonArrayStatics)->TryParse(get_abi(input), put_abi(result), &succeeded));
    return succeeded;
}

template <typename D> Windows::Data::Json::JsonErrorStatus consume_Windows_Data_Json_IJsonErrorStatics2<D>::GetJsonStatus(int32_t hresult) const
{
    Windows::Data::Json::JsonErrorStatus status{};
    check_hresult(WINRT_SHIM(Windows::Data::Json::IJsonErrorStatics2)->GetJsonStatus(hresult, put_abi(status)));
    return status;
}

template <typename D> Windows::Data::Json::JsonValue consume_Windows_Data_Json_IJsonObject<D>::GetNamedValue(param::hstring const& name) const
{
    Windows::Data::Json::JsonValue returnValue{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Data::Json::IJsonObject)->GetNamedValue(get_abi(name), put_abi(returnValue)));
    return returnValue;
}

template <typename D> void consume_Windows_Data_Json_IJsonObject<D>::SetNamedValue(param::hstring const& name, Windows::Data::Json::IJsonValue const& value) const
{
    check_hresult(WINRT_SHIM(Windows::Data::Json::IJsonObject)->SetNamedValue(get_abi(name), get_abi(value)));
}

template <typename D> Windows::Data::Json::JsonObject consume_Windows_Data_Json_IJsonObject<D>::GetNamedObject(param::hstring const& name) const
{
    Windows::Data::Json::JsonObject returnValue{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Data::Json::IJsonObject)->GetNamedObject(get_abi(name), put_abi(returnValue)));
    return returnValue;
}

template <typename D> Windows::Data::Json::JsonArray consume_Windows_Data_Json_IJsonObject<D>::GetNamedArray(param::hstring const& name) const
{
    Windows::Data::Json::JsonArray returnValue{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Data::Json::IJsonObject)->GetNamedArray(get_abi(name), put_abi(returnValue)));
    return returnValue;
}

template <typename D> hstring consume_Windows_Data_Json_IJsonObject<D>::GetNamedString(param::hstring const& name) const
{
    hstring returnValue{};
    check_hresult(WINRT_SHIM(Windows::Data::Json::IJsonObject)->GetNamedString(get_abi(name), put_abi(returnValue)));
    return returnValue;
}

template <typename D> double consume_Windows_Data_Json_IJsonObject<D>::GetNamedNumber(param::hstring const& name) const
{
    double returnValue{};
    check_hresult(WINRT_SHIM(Windows::Data::Json::IJsonObject)->GetNamedNumber(get_abi(name), &returnValue));
    return returnValue;
}

template <typename D> bool consume_Windows_Data_Json_IJsonObject<D>::GetNamedBoolean(param::hstring const& name) const
{
    bool returnValue{};
    check_hresult(WINRT_SHIM(Windows::Data::Json::IJsonObject)->GetNamedBoolean(get_abi(name), &returnValue));
    return returnValue;
}

template <typename D> Windows::Data::Json::JsonObject consume_Windows_Data_Json_IJsonObjectStatics<D>::Parse(param::hstring const& input) const
{
    Windows::Data::Json::JsonObject jsonObject{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Data::Json::IJsonObjectStatics)->Parse(get_abi(input), put_abi(jsonObject)));
    return jsonObject;
}

template <typename D> bool consume_Windows_Data_Json_IJsonObjectStatics<D>::TryParse(param::hstring const& input, Windows::Data::Json::JsonObject& result) const
{
    bool succeeded{};
    check_hresult(WINRT_SHIM(Windows::Data::Json::IJsonObjectStatics)->TryParse(get_abi(input), put_abi(result), &succeeded));
    return succeeded;
}

template <typename D> Windows::Data::Json::JsonValue consume_Windows_Data_Json_IJsonObjectWithDefaultValues<D>::GetNamedValue(param::hstring const& name, Windows::Data::Json::JsonValue const& defaultValue) const
{
    Windows::Data::Json::JsonValue returnValue{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Data::Json::IJsonObjectWithDefaultValues)->GetNamedValueOrDefault(get_abi(name), get_abi(defaultValue), put_abi(returnValue)));
    return returnValue;
}

template <typename D> Windows::Data::Json::JsonObject consume_Windows_Data_Json_IJsonObjectWithDefaultValues<D>::GetNamedObject(param::hstring const& name, Windows::Data::Json::JsonObject const& defaultValue) const
{
    Windows::Data::Json::JsonObject returnValue{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Data::Json::IJsonObjectWithDefaultValues)->GetNamedObjectOrDefault(get_abi(name), get_abi(defaultValue), put_abi(returnValue)));
    return returnValue;
}

template <typename D> hstring consume_Windows_Data_Json_IJsonObjectWithDefaultValues<D>::GetNamedString(param::hstring const& name, param::hstring const& defaultValue) const
{
    hstring returnValue{};
    check_hresult(WINRT_SHIM(Windows::Data::Json::IJsonObjectWithDefaultValues)->GetNamedStringOrDefault(get_abi(name), get_abi(defaultValue), put_abi(returnValue)));
    return returnValue;
}

template <typename D> Windows::Data::Json::JsonArray consume_Windows_Data_Json_IJsonObjectWithDefaultValues<D>::GetNamedArray(param::hstring const& name, Windows::Data::Json::JsonArray const& defaultValue) const
{
    Windows::Data::Json::JsonArray returnValue{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Data::Json::IJsonObjectWithDefaultValues)->GetNamedArrayOrDefault(get_abi(name), get_abi(defaultValue), put_abi(returnValue)));
    return returnValue;
}

template <typename D> double consume_Windows_Data_Json_IJsonObjectWithDefaultValues<D>::GetNamedNumber(param::hstring const& name, double defaultValue) const
{
    double returnValue{};
    check_hresult(WINRT_SHIM(Windows::Data::Json::IJsonObjectWithDefaultValues)->GetNamedNumberOrDefault(get_abi(name), defaultValue, &returnValue));
    return returnValue;
}

template <typename D> bool consume_Windows_Data_Json_IJsonObjectWithDefaultValues<D>::GetNamedBoolean(param::hstring const& name, bool defaultValue) const
{
    bool returnValue{};
    check_hresult(WINRT_SHIM(Windows::Data::Json::IJsonObjectWithDefaultValues)->GetNamedBooleanOrDefault(get_abi(name), defaultValue, &returnValue));
    return returnValue;
}

template <typename D> Windows::Data::Json::JsonValueType consume_Windows_Data_Json_IJsonValue<D>::ValueType() const
{
    Windows::Data::Json::JsonValueType value{};
    check_hresult(WINRT_SHIM(Windows::Data::Json::IJsonValue)->get_ValueType(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_Data_Json_IJsonValue<D>::Stringify() const
{
    hstring returnValue{};
    check_hresult(WINRT_SHIM(Windows::Data::Json::IJsonValue)->Stringify(put_abi(returnValue)));
    return returnValue;
}

template <typename D> hstring consume_Windows_Data_Json_IJsonValue<D>::GetString() const
{
    hstring returnValue{};
    check_hresult(WINRT_SHIM(Windows::Data::Json::IJsonValue)->GetString(put_abi(returnValue)));
    return returnValue;
}

template <typename D> double consume_Windows_Data_Json_IJsonValue<D>::GetNumber() const
{
    double returnValue{};
    check_hresult(WINRT_SHIM(Windows::Data::Json::IJsonValue)->GetNumber(&returnValue));
    return returnValue;
}

template <typename D> bool consume_Windows_Data_Json_IJsonValue<D>::GetBoolean() const
{
    bool returnValue{};
    check_hresult(WINRT_SHIM(Windows::Data::Json::IJsonValue)->GetBoolean(&returnValue));
    return returnValue;
}

template <typename D> Windows::Data::Json::JsonArray consume_Windows_Data_Json_IJsonValue<D>::GetArray() const
{
    Windows::Data::Json::JsonArray returnValue{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Data::Json::IJsonValue)->GetArray(put_abi(returnValue)));
    return returnValue;
}

template <typename D> Windows::Data::Json::JsonObject consume_Windows_Data_Json_IJsonValue<D>::GetObject() const
{
    Windows::Data::Json::JsonObject returnValue{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Data::Json::IJsonValue)->GetObject(put_abi(returnValue)));
    return returnValue;
}

template <typename D> Windows::Data::Json::JsonValue consume_Windows_Data_Json_IJsonValueStatics<D>::Parse(param::hstring const& input) const
{
    Windows::Data::Json::JsonValue jsonValue{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Data::Json::IJsonValueStatics)->Parse(get_abi(input), put_abi(jsonValue)));
    return jsonValue;
}

template <typename D> bool consume_Windows_Data_Json_IJsonValueStatics<D>::TryParse(param::hstring const& input, Windows::Data::Json::JsonValue& result) const
{
    bool succeeded{};
    check_hresult(WINRT_SHIM(Windows::Data::Json::IJsonValueStatics)->TryParse(get_abi(input), put_abi(result), &succeeded));
    return succeeded;
}

template <typename D> Windows::Data::Json::JsonValue consume_Windows_Data_Json_IJsonValueStatics<D>::CreateBooleanValue(bool input) const
{
    Windows::Data::Json::JsonValue jsonValue{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Data::Json::IJsonValueStatics)->CreateBooleanValue(input, put_abi(jsonValue)));
    return jsonValue;
}

template <typename D> Windows::Data::Json::JsonValue consume_Windows_Data_Json_IJsonValueStatics<D>::CreateNumberValue(double input) const
{
    Windows::Data::Json::JsonValue jsonValue{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Data::Json::IJsonValueStatics)->CreateNumberValue(input, put_abi(jsonValue)));
    return jsonValue;
}

template <typename D> Windows::Data::Json::JsonValue consume_Windows_Data_Json_IJsonValueStatics<D>::CreateStringValue(param::hstring const& input) const
{
    Windows::Data::Json::JsonValue jsonValue{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Data::Json::IJsonValueStatics)->CreateStringValue(get_abi(input), put_abi(jsonValue)));
    return jsonValue;
}

template <typename D> Windows::Data::Json::JsonValue consume_Windows_Data_Json_IJsonValueStatics2<D>::CreateNullValue() const
{
    Windows::Data::Json::JsonValue jsonValue{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Data::Json::IJsonValueStatics2)->CreateNullValue(put_abi(jsonValue)));
    return jsonValue;
}

template <typename D>
struct produce<D, Windows::Data::Json::IJsonArray> : produce_base<D, Windows::Data::Json::IJsonArray>
{
    int32_t WINRT_CALL GetObjectAt(uint32_t index, void** returnValue) noexcept final
    {
        try
        {
            *returnValue = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetObjectAt, WINRT_WRAP(Windows::Data::Json::JsonObject), uint32_t);
            *returnValue = detach_from<Windows::Data::Json::JsonObject>(this->shim().GetObjectAt(index));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL GetArrayAt(uint32_t index, void** returnValue) noexcept final
    {
        try
        {
            *returnValue = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetArrayAt, WINRT_WRAP(Windows::Data::Json::JsonArray), uint32_t);
            *returnValue = detach_from<Windows::Data::Json::JsonArray>(this->shim().GetArrayAt(index));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL GetStringAt(uint32_t index, void** returnValue) noexcept final
    {
        try
        {
            *returnValue = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetStringAt, WINRT_WRAP(hstring), uint32_t);
            *returnValue = detach_from<hstring>(this->shim().GetStringAt(index));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL GetNumberAt(uint32_t index, double* returnValue) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetNumberAt, WINRT_WRAP(double), uint32_t);
            *returnValue = detach_from<double>(this->shim().GetNumberAt(index));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL GetBooleanAt(uint32_t index, bool* returnValue) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetBooleanAt, WINRT_WRAP(bool), uint32_t);
            *returnValue = detach_from<bool>(this->shim().GetBooleanAt(index));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Data::Json::IJsonArrayStatics> : produce_base<D, Windows::Data::Json::IJsonArrayStatics>
{
    int32_t WINRT_CALL Parse(void* input, void** jsonArray) noexcept final
    {
        try
        {
            *jsonArray = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Parse, WINRT_WRAP(Windows::Data::Json::JsonArray), hstring const&);
            *jsonArray = detach_from<Windows::Data::Json::JsonArray>(this->shim().Parse(*reinterpret_cast<hstring const*>(&input)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL TryParse(void* input, void** result, bool* succeeded) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(TryParse, WINRT_WRAP(bool), hstring const&, Windows::Data::Json::JsonArray&);
            *succeeded = detach_from<bool>(this->shim().TryParse(*reinterpret_cast<hstring const*>(&input), *reinterpret_cast<Windows::Data::Json::JsonArray*>(result)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Data::Json::IJsonErrorStatics2> : produce_base<D, Windows::Data::Json::IJsonErrorStatics2>
{
    int32_t WINRT_CALL GetJsonStatus(int32_t hresult, Windows::Data::Json::JsonErrorStatus* status) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetJsonStatus, WINRT_WRAP(Windows::Data::Json::JsonErrorStatus), int32_t);
            *status = detach_from<Windows::Data::Json::JsonErrorStatus>(this->shim().GetJsonStatus(hresult));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Data::Json::IJsonObject> : produce_base<D, Windows::Data::Json::IJsonObject>
{
    int32_t WINRT_CALL GetNamedValue(void* name, void** returnValue) noexcept final
    {
        try
        {
            *returnValue = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetNamedValue, WINRT_WRAP(Windows::Data::Json::JsonValue), hstring const&);
            *returnValue = detach_from<Windows::Data::Json::JsonValue>(this->shim().GetNamedValue(*reinterpret_cast<hstring const*>(&name)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL SetNamedValue(void* name, void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SetNamedValue, WINRT_WRAP(void), hstring const&, Windows::Data::Json::IJsonValue const&);
            this->shim().SetNamedValue(*reinterpret_cast<hstring const*>(&name), *reinterpret_cast<Windows::Data::Json::IJsonValue const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL GetNamedObject(void* name, void** returnValue) noexcept final
    {
        try
        {
            *returnValue = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetNamedObject, WINRT_WRAP(Windows::Data::Json::JsonObject), hstring const&);
            *returnValue = detach_from<Windows::Data::Json::JsonObject>(this->shim().GetNamedObject(*reinterpret_cast<hstring const*>(&name)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL GetNamedArray(void* name, void** returnValue) noexcept final
    {
        try
        {
            *returnValue = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetNamedArray, WINRT_WRAP(Windows::Data::Json::JsonArray), hstring const&);
            *returnValue = detach_from<Windows::Data::Json::JsonArray>(this->shim().GetNamedArray(*reinterpret_cast<hstring const*>(&name)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL GetNamedString(void* name, void** returnValue) noexcept final
    {
        try
        {
            *returnValue = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetNamedString, WINRT_WRAP(hstring), hstring const&);
            *returnValue = detach_from<hstring>(this->shim().GetNamedString(*reinterpret_cast<hstring const*>(&name)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL GetNamedNumber(void* name, double* returnValue) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetNamedNumber, WINRT_WRAP(double), hstring const&);
            *returnValue = detach_from<double>(this->shim().GetNamedNumber(*reinterpret_cast<hstring const*>(&name)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL GetNamedBoolean(void* name, bool* returnValue) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetNamedBoolean, WINRT_WRAP(bool), hstring const&);
            *returnValue = detach_from<bool>(this->shim().GetNamedBoolean(*reinterpret_cast<hstring const*>(&name)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Data::Json::IJsonObjectStatics> : produce_base<D, Windows::Data::Json::IJsonObjectStatics>
{
    int32_t WINRT_CALL Parse(void* input, void** jsonObject) noexcept final
    {
        try
        {
            *jsonObject = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Parse, WINRT_WRAP(Windows::Data::Json::JsonObject), hstring const&);
            *jsonObject = detach_from<Windows::Data::Json::JsonObject>(this->shim().Parse(*reinterpret_cast<hstring const*>(&input)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL TryParse(void* input, void** result, bool* succeeded) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(TryParse, WINRT_WRAP(bool), hstring const&, Windows::Data::Json::JsonObject&);
            *succeeded = detach_from<bool>(this->shim().TryParse(*reinterpret_cast<hstring const*>(&input), *reinterpret_cast<Windows::Data::Json::JsonObject*>(result)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Data::Json::IJsonObjectWithDefaultValues> : produce_base<D, Windows::Data::Json::IJsonObjectWithDefaultValues>
{
    int32_t WINRT_CALL GetNamedValueOrDefault(void* name, void* defaultValue, void** returnValue) noexcept final
    {
        try
        {
            *returnValue = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetNamedValue, WINRT_WRAP(Windows::Data::Json::JsonValue), hstring const&, Windows::Data::Json::JsonValue const&);
            *returnValue = detach_from<Windows::Data::Json::JsonValue>(this->shim().GetNamedValue(*reinterpret_cast<hstring const*>(&name), *reinterpret_cast<Windows::Data::Json::JsonValue const*>(&defaultValue)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL GetNamedObjectOrDefault(void* name, void* defaultValue, void** returnValue) noexcept final
    {
        try
        {
            *returnValue = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetNamedObject, WINRT_WRAP(Windows::Data::Json::JsonObject), hstring const&, Windows::Data::Json::JsonObject const&);
            *returnValue = detach_from<Windows::Data::Json::JsonObject>(this->shim().GetNamedObject(*reinterpret_cast<hstring const*>(&name), *reinterpret_cast<Windows::Data::Json::JsonObject const*>(&defaultValue)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL GetNamedStringOrDefault(void* name, void* defaultValue, void** returnValue) noexcept final
    {
        try
        {
            *returnValue = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetNamedString, WINRT_WRAP(hstring), hstring const&, hstring const&);
            *returnValue = detach_from<hstring>(this->shim().GetNamedString(*reinterpret_cast<hstring const*>(&name), *reinterpret_cast<hstring const*>(&defaultValue)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL GetNamedArrayOrDefault(void* name, void* defaultValue, void** returnValue) noexcept final
    {
        try
        {
            *returnValue = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetNamedArray, WINRT_WRAP(Windows::Data::Json::JsonArray), hstring const&, Windows::Data::Json::JsonArray const&);
            *returnValue = detach_from<Windows::Data::Json::JsonArray>(this->shim().GetNamedArray(*reinterpret_cast<hstring const*>(&name), *reinterpret_cast<Windows::Data::Json::JsonArray const*>(&defaultValue)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL GetNamedNumberOrDefault(void* name, double defaultValue, double* returnValue) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetNamedNumber, WINRT_WRAP(double), hstring const&, double);
            *returnValue = detach_from<double>(this->shim().GetNamedNumber(*reinterpret_cast<hstring const*>(&name), defaultValue));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL GetNamedBooleanOrDefault(void* name, bool defaultValue, bool* returnValue) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetNamedBoolean, WINRT_WRAP(bool), hstring const&, bool);
            *returnValue = detach_from<bool>(this->shim().GetNamedBoolean(*reinterpret_cast<hstring const*>(&name), defaultValue));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Data::Json::IJsonValue> : produce_base<D, Windows::Data::Json::IJsonValue>
{
    int32_t WINRT_CALL get_ValueType(Windows::Data::Json::JsonValueType* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ValueType, WINRT_WRAP(Windows::Data::Json::JsonValueType));
            *value = detach_from<Windows::Data::Json::JsonValueType>(this->shim().ValueType());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL Stringify(void** returnValue) noexcept final
    {
        try
        {
            *returnValue = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Stringify, WINRT_WRAP(hstring));
            *returnValue = detach_from<hstring>(this->shim().Stringify());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL GetString(void** returnValue) noexcept final
    {
        try
        {
            *returnValue = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetString, WINRT_WRAP(hstring));
            *returnValue = detach_from<hstring>(this->shim().GetString());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL GetNumber(double* returnValue) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetNumber, WINRT_WRAP(double));
            *returnValue = detach_from<double>(this->shim().GetNumber());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL GetBoolean(bool* returnValue) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetBoolean, WINRT_WRAP(bool));
            *returnValue = detach_from<bool>(this->shim().GetBoolean());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL GetArray(void** returnValue) noexcept final
    {
        try
        {
            *returnValue = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetArray, WINRT_WRAP(Windows::Data::Json::JsonArray));
            *returnValue = detach_from<Windows::Data::Json::JsonArray>(this->shim().GetArray());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL GetObject(void** returnValue) noexcept final
    {
        try
        {
            *returnValue = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetObject, WINRT_WRAP(Windows::Data::Json::JsonObject));
            *returnValue = detach_from<Windows::Data::Json::JsonObject>(this->shim().GetObject());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Data::Json::IJsonValueStatics> : produce_base<D, Windows::Data::Json::IJsonValueStatics>
{
    int32_t WINRT_CALL Parse(void* input, void** jsonValue) noexcept final
    {
        try
        {
            *jsonValue = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Parse, WINRT_WRAP(Windows::Data::Json::JsonValue), hstring const&);
            *jsonValue = detach_from<Windows::Data::Json::JsonValue>(this->shim().Parse(*reinterpret_cast<hstring const*>(&input)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL TryParse(void* input, void** result, bool* succeeded) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(TryParse, WINRT_WRAP(bool), hstring const&, Windows::Data::Json::JsonValue&);
            *succeeded = detach_from<bool>(this->shim().TryParse(*reinterpret_cast<hstring const*>(&input), *reinterpret_cast<Windows::Data::Json::JsonValue*>(result)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL CreateBooleanValue(bool input, void** jsonValue) noexcept final
    {
        try
        {
            *jsonValue = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CreateBooleanValue, WINRT_WRAP(Windows::Data::Json::JsonValue), bool);
            *jsonValue = detach_from<Windows::Data::Json::JsonValue>(this->shim().CreateBooleanValue(input));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL CreateNumberValue(double input, void** jsonValue) noexcept final
    {
        try
        {
            *jsonValue = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CreateNumberValue, WINRT_WRAP(Windows::Data::Json::JsonValue), double);
            *jsonValue = detach_from<Windows::Data::Json::JsonValue>(this->shim().CreateNumberValue(input));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL CreateStringValue(void* input, void** jsonValue) noexcept final
    {
        try
        {
            *jsonValue = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CreateStringValue, WINRT_WRAP(Windows::Data::Json::JsonValue), hstring const&);
            *jsonValue = detach_from<Windows::Data::Json::JsonValue>(this->shim().CreateStringValue(*reinterpret_cast<hstring const*>(&input)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Data::Json::IJsonValueStatics2> : produce_base<D, Windows::Data::Json::IJsonValueStatics2>
{
    int32_t WINRT_CALL CreateNullValue(void** jsonValue) noexcept final
    {
        try
        {
            *jsonValue = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CreateNullValue, WINRT_WRAP(Windows::Data::Json::JsonValue));
            *jsonValue = detach_from<Windows::Data::Json::JsonValue>(this->shim().CreateNullValue());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

}

WINRT_EXPORT namespace winrt::Windows::Data::Json {

inline JsonArray::JsonArray() :
    JsonArray(impl::call_factory<JsonArray>([](auto&& f) { return f.template ActivateInstance<JsonArray>(); }))
{}

inline Windows::Data::Json::JsonArray JsonArray::Parse(param::hstring const& input)
{
    return impl::call_factory<JsonArray, Windows::Data::Json::IJsonArrayStatics>([&](auto&& f) { return f.Parse(input); });
}

inline bool JsonArray::TryParse(param::hstring const& input, Windows::Data::Json::JsonArray& result)
{
    return impl::call_factory<JsonArray, Windows::Data::Json::IJsonArrayStatics>([&](auto&& f) { return f.TryParse(input, result); });
}

inline Windows::Data::Json::JsonErrorStatus JsonError::GetJsonStatus(int32_t hresult)
{
    return impl::call_factory<JsonError, Windows::Data::Json::IJsonErrorStatics2>([&](auto&& f) { return f.GetJsonStatus(hresult); });
}

inline JsonObject::JsonObject() :
    JsonObject(impl::call_factory<JsonObject>([](auto&& f) { return f.template ActivateInstance<JsonObject>(); }))
{}

inline Windows::Data::Json::JsonObject JsonObject::Parse(param::hstring const& input)
{
    return impl::call_factory<JsonObject, Windows::Data::Json::IJsonObjectStatics>([&](auto&& f) { return f.Parse(input); });
}

inline bool JsonObject::TryParse(param::hstring const& input, Windows::Data::Json::JsonObject& result)
{
    return impl::call_factory<JsonObject, Windows::Data::Json::IJsonObjectStatics>([&](auto&& f) { return f.TryParse(input, result); });
}

inline Windows::Data::Json::JsonValue JsonValue::Parse(param::hstring const& input)
{
    return impl::call_factory<JsonValue, Windows::Data::Json::IJsonValueStatics>([&](auto&& f) { return f.Parse(input); });
}

inline bool JsonValue::TryParse(param::hstring const& input, Windows::Data::Json::JsonValue& result)
{
    return impl::call_factory<JsonValue, Windows::Data::Json::IJsonValueStatics>([&](auto&& f) { return f.TryParse(input, result); });
}

inline Windows::Data::Json::JsonValue JsonValue::CreateBooleanValue(bool input)
{
    return impl::call_factory<JsonValue, Windows::Data::Json::IJsonValueStatics>([&](auto&& f) { return f.CreateBooleanValue(input); });
}

inline Windows::Data::Json::JsonValue JsonValue::CreateNumberValue(double input)
{
    return impl::call_factory<JsonValue, Windows::Data::Json::IJsonValueStatics>([&](auto&& f) { return f.CreateNumberValue(input); });
}

inline Windows::Data::Json::JsonValue JsonValue::CreateStringValue(param::hstring const& input)
{
    return impl::call_factory<JsonValue, Windows::Data::Json::IJsonValueStatics>([&](auto&& f) { return f.CreateStringValue(input); });
}

inline Windows::Data::Json::JsonValue JsonValue::CreateNullValue()
{
    return impl::call_factory<JsonValue, Windows::Data::Json::IJsonValueStatics2>([&](auto&& f) { return f.CreateNullValue(); });
}

}

WINRT_EXPORT namespace std {

template<> struct hash<winrt::Windows::Data::Json::IJsonArray> : winrt::impl::hash_base<winrt::Windows::Data::Json::IJsonArray> {};
template<> struct hash<winrt::Windows::Data::Json::IJsonArrayStatics> : winrt::impl::hash_base<winrt::Windows::Data::Json::IJsonArrayStatics> {};
template<> struct hash<winrt::Windows::Data::Json::IJsonErrorStatics2> : winrt::impl::hash_base<winrt::Windows::Data::Json::IJsonErrorStatics2> {};
template<> struct hash<winrt::Windows::Data::Json::IJsonObject> : winrt::impl::hash_base<winrt::Windows::Data::Json::IJsonObject> {};
template<> struct hash<winrt::Windows::Data::Json::IJsonObjectStatics> : winrt::impl::hash_base<winrt::Windows::Data::Json::IJsonObjectStatics> {};
template<> struct hash<winrt::Windows::Data::Json::IJsonObjectWithDefaultValues> : winrt::impl::hash_base<winrt::Windows::Data::Json::IJsonObjectWithDefaultValues> {};
template<> struct hash<winrt::Windows::Data::Json::IJsonValue> : winrt::impl::hash_base<winrt::Windows::Data::Json::IJsonValue> {};
template<> struct hash<winrt::Windows::Data::Json::IJsonValueStatics> : winrt::impl::hash_base<winrt::Windows::Data::Json::IJsonValueStatics> {};
template<> struct hash<winrt::Windows::Data::Json::IJsonValueStatics2> : winrt::impl::hash_base<winrt::Windows::Data::Json::IJsonValueStatics2> {};
template<> struct hash<winrt::Windows::Data::Json::JsonArray> : winrt::impl::hash_base<winrt::Windows::Data::Json::JsonArray> {};
template<> struct hash<winrt::Windows::Data::Json::JsonError> : winrt::impl::hash_base<winrt::Windows::Data::Json::JsonError> {};
template<> struct hash<winrt::Windows::Data::Json::JsonObject> : winrt::impl::hash_base<winrt::Windows::Data::Json::JsonObject> {};
template<> struct hash<winrt::Windows::Data::Json::JsonValue> : winrt::impl::hash_base<winrt::Windows::Data::Json::JsonValue> {};

}
