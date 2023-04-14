// C++/WinRT v1.0.190111.3

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#pragma once

#include "winrt/base.h"

#include "winrt/Windows.Foundation.h"
#include "winrt/Windows.Foundation.Collections.h"
#include "winrt/impl/Windows.Foundation.Collections.2.h"
#include "winrt/impl/Windows.Globalization.Collation.2.h"
#include "winrt/Windows.Globalization.h"

namespace winrt::impl {

template <typename D> hstring consume_Windows_Globalization_Collation_ICharacterGrouping<D>::First() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Globalization::Collation::ICharacterGrouping)->get_First(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_Globalization_Collation_ICharacterGrouping<D>::Label() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Globalization::Collation::ICharacterGrouping)->get_Label(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_Globalization_Collation_ICharacterGroupings<D>::Lookup(param::hstring const& text) const
{
    hstring result{};
    check_hresult(WINRT_SHIM(Windows::Globalization::Collation::ICharacterGroupings)->Lookup(get_abi(text), put_abi(result)));
    return result;
}

template <typename D> Windows::Globalization::Collation::CharacterGroupings consume_Windows_Globalization_Collation_ICharacterGroupingsFactory<D>::Create(param::hstring const& language) const
{
    Windows::Globalization::Collation::CharacterGroupings result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Globalization::Collation::ICharacterGroupingsFactory)->Create(get_abi(language), put_abi(result)));
    return result;
}

template <typename D>
struct produce<D, Windows::Globalization::Collation::ICharacterGrouping> : produce_base<D, Windows::Globalization::Collation::ICharacterGrouping>
{
    int32_t WINRT_CALL get_First(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(First, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().First());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Label(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Label, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().Label());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Globalization::Collation::ICharacterGroupings> : produce_base<D, Windows::Globalization::Collation::ICharacterGroupings>
{
    int32_t WINRT_CALL Lookup(void* text, void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Lookup, WINRT_WRAP(hstring), hstring const&);
            *result = detach_from<hstring>(this->shim().Lookup(*reinterpret_cast<hstring const*>(&text)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Globalization::Collation::ICharacterGroupingsFactory> : produce_base<D, Windows::Globalization::Collation::ICharacterGroupingsFactory>
{
    int32_t WINRT_CALL Create(void* language, void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Create, WINRT_WRAP(Windows::Globalization::Collation::CharacterGroupings), hstring const&);
            *result = detach_from<Windows::Globalization::Collation::CharacterGroupings>(this->shim().Create(*reinterpret_cast<hstring const*>(&language)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

}

WINRT_EXPORT namespace winrt::Windows::Globalization::Collation {

inline CharacterGroupings::CharacterGroupings() :
    CharacterGroupings(impl::call_factory<CharacterGroupings>([](auto&& f) { return f.template ActivateInstance<CharacterGroupings>(); }))
{}

inline CharacterGroupings::CharacterGroupings(param::hstring const& language) :
    CharacterGroupings(impl::call_factory<CharacterGroupings, Windows::Globalization::Collation::ICharacterGroupingsFactory>([&](auto&& f) { return f.Create(language); }))
{}

}

WINRT_EXPORT namespace std {

template<> struct hash<winrt::Windows::Globalization::Collation::ICharacterGrouping> : winrt::impl::hash_base<winrt::Windows::Globalization::Collation::ICharacterGrouping> {};
template<> struct hash<winrt::Windows::Globalization::Collation::ICharacterGroupings> : winrt::impl::hash_base<winrt::Windows::Globalization::Collation::ICharacterGroupings> {};
template<> struct hash<winrt::Windows::Globalization::Collation::ICharacterGroupingsFactory> : winrt::impl::hash_base<winrt::Windows::Globalization::Collation::ICharacterGroupingsFactory> {};
template<> struct hash<winrt::Windows::Globalization::Collation::CharacterGrouping> : winrt::impl::hash_base<winrt::Windows::Globalization::Collation::CharacterGrouping> {};
template<> struct hash<winrt::Windows::Globalization::Collation::CharacterGroupings> : winrt::impl::hash_base<winrt::Windows::Globalization::Collation::CharacterGroupings> {};

}
