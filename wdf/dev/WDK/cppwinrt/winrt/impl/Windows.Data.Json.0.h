// C++/WinRT v1.0.190111.3

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#pragma once

WINRT_EXPORT namespace winrt::Windows::Data::Json {

enum class JsonErrorStatus : int32_t
{
    Unknown = 0,
    InvalidJsonString = 1,
    InvalidJsonNumber = 2,
    JsonValueNotFound = 3,
    ImplementationLimit = 4,
};

enum class JsonValueType : int32_t
{
    Null = 0,
    Boolean = 1,
    Number = 2,
    String = 3,
    Array = 4,
    Object = 5,
};

struct IJsonArray;
struct IJsonArrayStatics;
struct IJsonErrorStatics2;
struct IJsonObject;
struct IJsonObjectStatics;
struct IJsonObjectWithDefaultValues;
struct IJsonValue;
struct IJsonValueStatics;
struct IJsonValueStatics2;
struct JsonArray;
struct JsonError;
struct JsonObject;
struct JsonValue;

}

namespace winrt::impl {

template <> struct category<Windows::Data::Json::IJsonArray>{ using type = interface_category; };
template <> struct category<Windows::Data::Json::IJsonArrayStatics>{ using type = interface_category; };
template <> struct category<Windows::Data::Json::IJsonErrorStatics2>{ using type = interface_category; };
template <> struct category<Windows::Data::Json::IJsonObject>{ using type = interface_category; };
template <> struct category<Windows::Data::Json::IJsonObjectStatics>{ using type = interface_category; };
template <> struct category<Windows::Data::Json::IJsonObjectWithDefaultValues>{ using type = interface_category; };
template <> struct category<Windows::Data::Json::IJsonValue>{ using type = interface_category; };
template <> struct category<Windows::Data::Json::IJsonValueStatics>{ using type = interface_category; };
template <> struct category<Windows::Data::Json::IJsonValueStatics2>{ using type = interface_category; };
template <> struct category<Windows::Data::Json::JsonArray>{ using type = class_category; };
template <> struct category<Windows::Data::Json::JsonError>{ using type = class_category; };
template <> struct category<Windows::Data::Json::JsonObject>{ using type = class_category; };
template <> struct category<Windows::Data::Json::JsonValue>{ using type = class_category; };
template <> struct category<Windows::Data::Json::JsonErrorStatus>{ using type = enum_category; };
template <> struct category<Windows::Data::Json::JsonValueType>{ using type = enum_category; };
template <> struct name<Windows::Data::Json::IJsonArray>{ static constexpr auto & value{ L"Windows.Data.Json.IJsonArray" }; };
template <> struct name<Windows::Data::Json::IJsonArrayStatics>{ static constexpr auto & value{ L"Windows.Data.Json.IJsonArrayStatics" }; };
template <> struct name<Windows::Data::Json::IJsonErrorStatics2>{ static constexpr auto & value{ L"Windows.Data.Json.IJsonErrorStatics2" }; };
template <> struct name<Windows::Data::Json::IJsonObject>{ static constexpr auto & value{ L"Windows.Data.Json.IJsonObject" }; };
template <> struct name<Windows::Data::Json::IJsonObjectStatics>{ static constexpr auto & value{ L"Windows.Data.Json.IJsonObjectStatics" }; };
template <> struct name<Windows::Data::Json::IJsonObjectWithDefaultValues>{ static constexpr auto & value{ L"Windows.Data.Json.IJsonObjectWithDefaultValues" }; };
template <> struct name<Windows::Data::Json::IJsonValue>{ static constexpr auto & value{ L"Windows.Data.Json.IJsonValue" }; };
template <> struct name<Windows::Data::Json::IJsonValueStatics>{ static constexpr auto & value{ L"Windows.Data.Json.IJsonValueStatics" }; };
template <> struct name<Windows::Data::Json::IJsonValueStatics2>{ static constexpr auto & value{ L"Windows.Data.Json.IJsonValueStatics2" }; };
template <> struct name<Windows::Data::Json::JsonArray>{ static constexpr auto & value{ L"Windows.Data.Json.JsonArray" }; };
template <> struct name<Windows::Data::Json::JsonError>{ static constexpr auto & value{ L"Windows.Data.Json.JsonError" }; };
template <> struct name<Windows::Data::Json::JsonObject>{ static constexpr auto & value{ L"Windows.Data.Json.JsonObject" }; };
template <> struct name<Windows::Data::Json::JsonValue>{ static constexpr auto & value{ L"Windows.Data.Json.JsonValue" }; };
template <> struct name<Windows::Data::Json::JsonErrorStatus>{ static constexpr auto & value{ L"Windows.Data.Json.JsonErrorStatus" }; };
template <> struct name<Windows::Data::Json::JsonValueType>{ static constexpr auto & value{ L"Windows.Data.Json.JsonValueType" }; };
template <> struct guid_storage<Windows::Data::Json::IJsonArray>{ static constexpr guid value{ 0x08C1DDB6,0x0CBD,0x4A9A,{ 0xB5,0xD3,0x2F,0x85,0x2D,0xC3,0x7E,0x81 } }; };
template <> struct guid_storage<Windows::Data::Json::IJsonArrayStatics>{ static constexpr guid value{ 0xDB1434A9,0xE164,0x499F,{ 0x93,0xE2,0x8A,0x8F,0x49,0xBB,0x90,0xBA } }; };
template <> struct guid_storage<Windows::Data::Json::IJsonErrorStatics2>{ static constexpr guid value{ 0x404030DA,0x87D0,0x436C,{ 0x83,0xAB,0xFC,0x7B,0x12,0xC0,0xCC,0x26 } }; };
template <> struct guid_storage<Windows::Data::Json::IJsonObject>{ static constexpr guid value{ 0x064E24DD,0x29C2,0x4F83,{ 0x9A,0xC1,0x9E,0xE1,0x15,0x78,0xBE,0xB3 } }; };
template <> struct guid_storage<Windows::Data::Json::IJsonObjectStatics>{ static constexpr guid value{ 0x2289F159,0x54DE,0x45D8,{ 0xAB,0xCC,0x22,0x60,0x3F,0xA0,0x66,0xA0 } }; };
template <> struct guid_storage<Windows::Data::Json::IJsonObjectWithDefaultValues>{ static constexpr guid value{ 0xD960D2A2,0xB7F0,0x4F00,{ 0x8E,0x44,0xD8,0x2C,0xF4,0x15,0xEA,0x13 } }; };
template <> struct guid_storage<Windows::Data::Json::IJsonValue>{ static constexpr guid value{ 0xA3219ECB,0xF0B3,0x4DCD,{ 0xBE,0xEE,0x19,0xD4,0x8C,0xD3,0xED,0x1E } }; };
template <> struct guid_storage<Windows::Data::Json::IJsonValueStatics>{ static constexpr guid value{ 0x5F6B544A,0x2F53,0x48E1,{ 0x91,0xA3,0xF7,0x8B,0x50,0xA6,0x34,0x5C } }; };
template <> struct guid_storage<Windows::Data::Json::IJsonValueStatics2>{ static constexpr guid value{ 0x1D9ECBE4,0x3FE8,0x4335,{ 0x83,0x92,0x93,0xD8,0xE3,0x68,0x65,0xF0 } }; };
template <> struct default_interface<Windows::Data::Json::JsonArray>{ using type = Windows::Data::Json::IJsonArray; };
template <> struct default_interface<Windows::Data::Json::JsonObject>{ using type = Windows::Data::Json::IJsonObject; };
template <> struct default_interface<Windows::Data::Json::JsonValue>{ using type = Windows::Data::Json::IJsonValue; };

template <> struct abi<Windows::Data::Json::IJsonArray>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL GetObjectAt(uint32_t index, void** returnValue) noexcept = 0;
    virtual int32_t WINRT_CALL GetArrayAt(uint32_t index, void** returnValue) noexcept = 0;
    virtual int32_t WINRT_CALL GetStringAt(uint32_t index, void** returnValue) noexcept = 0;
    virtual int32_t WINRT_CALL GetNumberAt(uint32_t index, double* returnValue) noexcept = 0;
    virtual int32_t WINRT_CALL GetBooleanAt(uint32_t index, bool* returnValue) noexcept = 0;
};};

template <> struct abi<Windows::Data::Json::IJsonArrayStatics>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL Parse(void* input, void** jsonArray) noexcept = 0;
    virtual int32_t WINRT_CALL TryParse(void* input, void** result, bool* succeeded) noexcept = 0;
};};

template <> struct abi<Windows::Data::Json::IJsonErrorStatics2>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL GetJsonStatus(int32_t hresult, Windows::Data::Json::JsonErrorStatus* status) noexcept = 0;
};};

template <> struct abi<Windows::Data::Json::IJsonObject>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL GetNamedValue(void* name, void** returnValue) noexcept = 0;
    virtual int32_t WINRT_CALL SetNamedValue(void* name, void* value) noexcept = 0;
    virtual int32_t WINRT_CALL GetNamedObject(void* name, void** returnValue) noexcept = 0;
    virtual int32_t WINRT_CALL GetNamedArray(void* name, void** returnValue) noexcept = 0;
    virtual int32_t WINRT_CALL GetNamedString(void* name, void** returnValue) noexcept = 0;
    virtual int32_t WINRT_CALL GetNamedNumber(void* name, double* returnValue) noexcept = 0;
    virtual int32_t WINRT_CALL GetNamedBoolean(void* name, bool* returnValue) noexcept = 0;
};};

template <> struct abi<Windows::Data::Json::IJsonObjectStatics>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL Parse(void* input, void** jsonObject) noexcept = 0;
    virtual int32_t WINRT_CALL TryParse(void* input, void** result, bool* succeeded) noexcept = 0;
};};

template <> struct abi<Windows::Data::Json::IJsonObjectWithDefaultValues>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL GetNamedValueOrDefault(void* name, void* defaultValue, void** returnValue) noexcept = 0;
    virtual int32_t WINRT_CALL GetNamedObjectOrDefault(void* name, void* defaultValue, void** returnValue) noexcept = 0;
    virtual int32_t WINRT_CALL GetNamedStringOrDefault(void* name, void* defaultValue, void** returnValue) noexcept = 0;
    virtual int32_t WINRT_CALL GetNamedArrayOrDefault(void* name, void* defaultValue, void** returnValue) noexcept = 0;
    virtual int32_t WINRT_CALL GetNamedNumberOrDefault(void* name, double defaultValue, double* returnValue) noexcept = 0;
    virtual int32_t WINRT_CALL GetNamedBooleanOrDefault(void* name, bool defaultValue, bool* returnValue) noexcept = 0;
};};

template <> struct abi<Windows::Data::Json::IJsonValue>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL get_ValueType(Windows::Data::Json::JsonValueType* value) noexcept = 0;
    virtual int32_t WINRT_CALL Stringify(void** returnValue) noexcept = 0;
    virtual int32_t WINRT_CALL GetString(void** returnValue) noexcept = 0;
    virtual int32_t WINRT_CALL GetNumber(double* returnValue) noexcept = 0;
    virtual int32_t WINRT_CALL GetBoolean(bool* returnValue) noexcept = 0;
    virtual int32_t WINRT_CALL GetArray(void** returnValue) noexcept = 0;
    virtual int32_t WINRT_CALL GetObject(void** returnValue) noexcept = 0;
};};

template <> struct abi<Windows::Data::Json::IJsonValueStatics>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL Parse(void* input, void** jsonValue) noexcept = 0;
    virtual int32_t WINRT_CALL TryParse(void* input, void** result, bool* succeeded) noexcept = 0;
    virtual int32_t WINRT_CALL CreateBooleanValue(bool input, void** jsonValue) noexcept = 0;
    virtual int32_t WINRT_CALL CreateNumberValue(double input, void** jsonValue) noexcept = 0;
    virtual int32_t WINRT_CALL CreateStringValue(void* input, void** jsonValue) noexcept = 0;
};};

template <> struct abi<Windows::Data::Json::IJsonValueStatics2>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL CreateNullValue(void** jsonValue) noexcept = 0;
};};

template <typename D>
struct consume_Windows_Data_Json_IJsonArray
{
    Windows::Data::Json::JsonObject GetObjectAt(uint32_t index) const;
    Windows::Data::Json::JsonArray GetArrayAt(uint32_t index) const;
    hstring GetStringAt(uint32_t index) const;
    double GetNumberAt(uint32_t index) const;
    bool GetBooleanAt(uint32_t index) const;
};
template <> struct consume<Windows::Data::Json::IJsonArray> { template <typename D> using type = consume_Windows_Data_Json_IJsonArray<D>; };

template <typename D>
struct consume_Windows_Data_Json_IJsonArrayStatics
{
    Windows::Data::Json::JsonArray Parse(param::hstring const& input) const;
    bool TryParse(param::hstring const& input, Windows::Data::Json::JsonArray& result) const;
};
template <> struct consume<Windows::Data::Json::IJsonArrayStatics> { template <typename D> using type = consume_Windows_Data_Json_IJsonArrayStatics<D>; };

template <typename D>
struct consume_Windows_Data_Json_IJsonErrorStatics2
{
    Windows::Data::Json::JsonErrorStatus GetJsonStatus(int32_t hresult) const;
};
template <> struct consume<Windows::Data::Json::IJsonErrorStatics2> { template <typename D> using type = consume_Windows_Data_Json_IJsonErrorStatics2<D>; };

template <typename D>
struct consume_Windows_Data_Json_IJsonObject
{
    Windows::Data::Json::JsonValue GetNamedValue(param::hstring const& name) const;
    void SetNamedValue(param::hstring const& name, Windows::Data::Json::IJsonValue const& value) const;
    Windows::Data::Json::JsonObject GetNamedObject(param::hstring const& name) const;
    Windows::Data::Json::JsonArray GetNamedArray(param::hstring const& name) const;
    hstring GetNamedString(param::hstring const& name) const;
    double GetNamedNumber(param::hstring const& name) const;
    bool GetNamedBoolean(param::hstring const& name) const;
};
template <> struct consume<Windows::Data::Json::IJsonObject> { template <typename D> using type = consume_Windows_Data_Json_IJsonObject<D>; };

template <typename D>
struct consume_Windows_Data_Json_IJsonObjectStatics
{
    Windows::Data::Json::JsonObject Parse(param::hstring const& input) const;
    bool TryParse(param::hstring const& input, Windows::Data::Json::JsonObject& result) const;
};
template <> struct consume<Windows::Data::Json::IJsonObjectStatics> { template <typename D> using type = consume_Windows_Data_Json_IJsonObjectStatics<D>; };

template <typename D>
struct consume_Windows_Data_Json_IJsonObjectWithDefaultValues
{
    Windows::Data::Json::JsonValue GetNamedValue(param::hstring const& name, Windows::Data::Json::JsonValue const& defaultValue) const;
    Windows::Data::Json::JsonObject GetNamedObject(param::hstring const& name, Windows::Data::Json::JsonObject const& defaultValue) const;
    hstring GetNamedString(param::hstring const& name, param::hstring const& defaultValue) const;
    Windows::Data::Json::JsonArray GetNamedArray(param::hstring const& name, Windows::Data::Json::JsonArray const& defaultValue) const;
    double GetNamedNumber(param::hstring const& name, double defaultValue) const;
    bool GetNamedBoolean(param::hstring const& name, bool defaultValue) const;
};
template <> struct consume<Windows::Data::Json::IJsonObjectWithDefaultValues> { template <typename D> using type = consume_Windows_Data_Json_IJsonObjectWithDefaultValues<D>; };

template <typename D>
struct consume_Windows_Data_Json_IJsonValue
{
    Windows::Data::Json::JsonValueType ValueType() const;
    hstring Stringify() const;
    hstring GetString() const;
    double GetNumber() const;
    bool GetBoolean() const;
    Windows::Data::Json::JsonArray GetArray() const;
    Windows::Data::Json::JsonObject GetObject() const;
};
template <> struct consume<Windows::Data::Json::IJsonValue> { template <typename D> using type = consume_Windows_Data_Json_IJsonValue<D>; };

template <typename D>
struct consume_Windows_Data_Json_IJsonValueStatics
{
    Windows::Data::Json::JsonValue Parse(param::hstring const& input) const;
    bool TryParse(param::hstring const& input, Windows::Data::Json::JsonValue& result) const;
    Windows::Data::Json::JsonValue CreateBooleanValue(bool input) const;
    Windows::Data::Json::JsonValue CreateNumberValue(double input) const;
    Windows::Data::Json::JsonValue CreateStringValue(param::hstring const& input) const;
};
template <> struct consume<Windows::Data::Json::IJsonValueStatics> { template <typename D> using type = consume_Windows_Data_Json_IJsonValueStatics<D>; };

template <typename D>
struct consume_Windows_Data_Json_IJsonValueStatics2
{
    Windows::Data::Json::JsonValue CreateNullValue() const;
};
template <> struct consume<Windows::Data::Json::IJsonValueStatics2> { template <typename D> using type = consume_Windows_Data_Json_IJsonValueStatics2<D>; };

}
