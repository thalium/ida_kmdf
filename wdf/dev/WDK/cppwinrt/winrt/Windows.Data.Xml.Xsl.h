// C++/WinRT v1.0.190111.3

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#pragma once

#include "winrt/base.h"

#include "winrt/Windows.Foundation.h"
#include "winrt/Windows.Foundation.Collections.h"
#include "winrt/impl/Windows.Data.Xml.Dom.2.h"
#include "winrt/impl/Windows.Data.Xml.Xsl.2.h"

namespace winrt::impl {

template <typename D> hstring consume_Windows_Data_Xml_Xsl_IXsltProcessor<D>::TransformToString(Windows::Data::Xml::Dom::IXmlNode const& inputNode) const
{
    hstring output{};
    check_hresult(WINRT_SHIM(Windows::Data::Xml::Xsl::IXsltProcessor)->TransformToString(get_abi(inputNode), put_abi(output)));
    return output;
}

template <typename D> Windows::Data::Xml::Dom::XmlDocument consume_Windows_Data_Xml_Xsl_IXsltProcessor2<D>::TransformToDocument(Windows::Data::Xml::Dom::IXmlNode const& inputNode) const
{
    Windows::Data::Xml::Dom::XmlDocument output{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Data::Xml::Xsl::IXsltProcessor2)->TransformToDocument(get_abi(inputNode), put_abi(output)));
    return output;
}

template <typename D> Windows::Data::Xml::Xsl::XsltProcessor consume_Windows_Data_Xml_Xsl_IXsltProcessorFactory<D>::CreateInstance(Windows::Data::Xml::Dom::XmlDocument const& document) const
{
    Windows::Data::Xml::Xsl::XsltProcessor xsltProcessor{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Data::Xml::Xsl::IXsltProcessorFactory)->CreateInstance(get_abi(document), put_abi(xsltProcessor)));
    return xsltProcessor;
}

template <typename D>
struct produce<D, Windows::Data::Xml::Xsl::IXsltProcessor> : produce_base<D, Windows::Data::Xml::Xsl::IXsltProcessor>
{
    int32_t WINRT_CALL TransformToString(void* inputNode, void** output) noexcept final
    {
        try
        {
            *output = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(TransformToString, WINRT_WRAP(hstring), Windows::Data::Xml::Dom::IXmlNode const&);
            *output = detach_from<hstring>(this->shim().TransformToString(*reinterpret_cast<Windows::Data::Xml::Dom::IXmlNode const*>(&inputNode)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Data::Xml::Xsl::IXsltProcessor2> : produce_base<D, Windows::Data::Xml::Xsl::IXsltProcessor2>
{
    int32_t WINRT_CALL TransformToDocument(void* inputNode, void** output) noexcept final
    {
        try
        {
            *output = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(TransformToDocument, WINRT_WRAP(Windows::Data::Xml::Dom::XmlDocument), Windows::Data::Xml::Dom::IXmlNode const&);
            *output = detach_from<Windows::Data::Xml::Dom::XmlDocument>(this->shim().TransformToDocument(*reinterpret_cast<Windows::Data::Xml::Dom::IXmlNode const*>(&inputNode)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Data::Xml::Xsl::IXsltProcessorFactory> : produce_base<D, Windows::Data::Xml::Xsl::IXsltProcessorFactory>
{
    int32_t WINRT_CALL CreateInstance(void* document, void** xsltProcessor) noexcept final
    {
        try
        {
            *xsltProcessor = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CreateInstance, WINRT_WRAP(Windows::Data::Xml::Xsl::XsltProcessor), Windows::Data::Xml::Dom::XmlDocument const&);
            *xsltProcessor = detach_from<Windows::Data::Xml::Xsl::XsltProcessor>(this->shim().CreateInstance(*reinterpret_cast<Windows::Data::Xml::Dom::XmlDocument const*>(&document)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

}

WINRT_EXPORT namespace winrt::Windows::Data::Xml::Xsl {

inline XsltProcessor::XsltProcessor(Windows::Data::Xml::Dom::XmlDocument const& document) :
    XsltProcessor(impl::call_factory<XsltProcessor, Windows::Data::Xml::Xsl::IXsltProcessorFactory>([&](auto&& f) { return f.CreateInstance(document); }))
{}

}

WINRT_EXPORT namespace std {

template<> struct hash<winrt::Windows::Data::Xml::Xsl::IXsltProcessor> : winrt::impl::hash_base<winrt::Windows::Data::Xml::Xsl::IXsltProcessor> {};
template<> struct hash<winrt::Windows::Data::Xml::Xsl::IXsltProcessor2> : winrt::impl::hash_base<winrt::Windows::Data::Xml::Xsl::IXsltProcessor2> {};
template<> struct hash<winrt::Windows::Data::Xml::Xsl::IXsltProcessorFactory> : winrt::impl::hash_base<winrt::Windows::Data::Xml::Xsl::IXsltProcessorFactory> {};
template<> struct hash<winrt::Windows::Data::Xml::Xsl::XsltProcessor> : winrt::impl::hash_base<winrt::Windows::Data::Xml::Xsl::XsltProcessor> {};

}
