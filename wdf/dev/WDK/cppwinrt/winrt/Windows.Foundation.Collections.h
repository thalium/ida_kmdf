// C++/WinRT v1.0.190111.3

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#pragma once

#include "winrt/base.h"

#include "winrt/impl/Windows.Foundation.Collections.2.h"
#include "winrt/impl/Windows.Foundation.Collections.2.h"
#include "winrt/Windows.Foundation.h"

namespace winrt::impl {

template <typename D>
struct produce<D, Windows::Foundation::Collections::IPropertySet> : produce_base<D, Windows::Foundation::Collections::IPropertySet>
{};

}

WINRT_EXPORT namespace winrt::Windows::Foundation::Collections {

inline PropertySet::PropertySet() :
    PropertySet(impl::call_factory<PropertySet>([](auto&& f) { return f.template ActivateInstance<PropertySet>(); }))
{}

inline StringMap::StringMap() :
    StringMap(impl::call_factory<StringMap>([](auto&& f) { return f.template ActivateInstance<StringMap>(); }))
{}

inline ValueSet::ValueSet() :
    ValueSet(impl::call_factory<ValueSet>([](auto&& f) { return f.template ActivateInstance<ValueSet>(); }))
{}

}

WINRT_EXPORT namespace std {
template<typename T> struct hash<winrt::Windows::Foundation::Collections::IIterator<T>> : winrt::impl::hash_base<winrt::Windows::Foundation::Collections::IIterator<T>> {};
template<typename T> struct hash<winrt::Windows::Foundation::Collections::IIterable<T>> : winrt::impl::hash_base<winrt::Windows::Foundation::Collections::IIterable<T>> {};
template<typename T> struct hash<winrt::Windows::Foundation::Collections::IVectorView<T>> : winrt::impl::hash_base<winrt::Windows::Foundation::Collections::IVectorView<T>> {};
template<typename T> struct hash<winrt::Windows::Foundation::Collections::IVector<T>> : winrt::impl::hash_base<winrt::Windows::Foundation::Collections::IVector<T>> {};
template<typename T> struct hash<winrt::Windows::Foundation::Collections::IObservableVector<T>> : winrt::impl::hash_base<winrt::Windows::Foundation::Collections::IObservableVector<T>> {};
template<typename T> struct hash<winrt::Windows::Foundation::Collections::VectorChangedEventHandler<T>> : winrt::impl::hash_base<winrt::Windows::Foundation::Collections::VectorChangedEventHandler<T>> {};
template<> struct hash<winrt::Windows::Foundation::Collections::IVectorChangedEventArgs> : winrt::impl::hash_base<winrt::Windows::Foundation::Collections::IVectorChangedEventArgs> {};
template<typename K, typename V> struct hash<winrt::Windows::Foundation::Collections::IKeyValuePair<K, V>> : winrt::impl::hash_base<winrt::Windows::Foundation::Collections::IKeyValuePair<K, V>> {};
template<typename K, typename V> struct hash<winrt::Windows::Foundation::Collections::IMapView<K, V>> : winrt::impl::hash_base<winrt::Windows::Foundation::Collections::IMapView<K, V>> {};
template<typename K, typename V> struct hash<winrt::Windows::Foundation::Collections::IMap<K, V>> : winrt::impl::hash_base<winrt::Windows::Foundation::Collections::IMap<K, V>> {};
template<typename K, typename V> struct hash<winrt::Windows::Foundation::Collections::IObservableMap<K, V>> : winrt::impl::hash_base<winrt::Windows::Foundation::Collections::IObservableMap<K, V>> {};
template<typename K, typename V> struct hash<winrt::Windows::Foundation::Collections::MapChangedEventHandler<K, V>> : winrt::impl::hash_base<winrt::Windows::Foundation::Collections::MapChangedEventHandler<K, V>> {};
template<typename K> struct hash<winrt::Windows::Foundation::Collections::IMapChangedEventArgs<K>> : winrt::impl::hash_base<winrt::Windows::Foundation::Collections::IMapChangedEventArgs<K>> {};

}

WINRT_EXPORT namespace std {

template<> struct hash<winrt::Windows::Foundation::Collections::IPropertySet> : winrt::impl::hash_base<winrt::Windows::Foundation::Collections::IPropertySet> {};
template<> struct hash<winrt::Windows::Foundation::Collections::PropertySet> : winrt::impl::hash_base<winrt::Windows::Foundation::Collections::PropertySet> {};
template<> struct hash<winrt::Windows::Foundation::Collections::StringMap> : winrt::impl::hash_base<winrt::Windows::Foundation::Collections::StringMap> {};
template<> struct hash<winrt::Windows::Foundation::Collections::ValueSet> : winrt::impl::hash_base<winrt::Windows::Foundation::Collections::ValueSet> {};

}
