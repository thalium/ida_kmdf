// C++/WinRT v1.0.190111.3

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#pragma once
#include "winrt/impl/Windows.Data.Xml.Dom.1.h"
#include "winrt/impl/Windows.Data.Xml.Xsl.1.h"

WINRT_EXPORT namespace winrt::Windows::Data::Xml::Xsl {

}

namespace winrt::impl {

}

WINRT_EXPORT namespace winrt::Windows::Data::Xml::Xsl {

struct WINRT_EBO XsltProcessor :
    Windows::Data::Xml::Xsl::IXsltProcessor,
    impl::require<XsltProcessor, Windows::Data::Xml::Xsl::IXsltProcessor2>
{
    XsltProcessor(std::nullptr_t) noexcept {}
    XsltProcessor(Windows::Data::Xml::Dom::XmlDocument const& document);
};

}
