// C++/WinRT v1.0.190111.3

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#pragma once

#include "winrt/base.h"

#include "winrt/Windows.Foundation.h"
#include "winrt/Windows.Foundation.Collections.h"
#include "winrt/impl/Windows.Graphics.Printing.2.h"
#include "winrt/impl/Windows.UI.Xaml.2.h"
#include "winrt/impl/Windows.UI.Xaml.Printing.2.h"
#include "winrt/Windows.UI.Xaml.h"

namespace winrt::impl {

template <typename D> Windows::Graphics::Printing::PrintTaskOptions consume_Windows_UI_Xaml_Printing_IAddPagesEventArgs<D>::PrintTaskOptions() const
{
    Windows::Graphics::Printing::PrintTaskOptions value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Printing::IAddPagesEventArgs)->get_PrintTaskOptions(put_abi(value)));
    return value;
}

template <typename D> int32_t consume_Windows_UI_Xaml_Printing_IGetPreviewPageEventArgs<D>::PageNumber() const
{
    int32_t value{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Printing::IGetPreviewPageEventArgs)->get_PageNumber(&value));
    return value;
}

template <typename D> Windows::Graphics::Printing::PrintTaskOptions consume_Windows_UI_Xaml_Printing_IPaginateEventArgs<D>::PrintTaskOptions() const
{
    Windows::Graphics::Printing::PrintTaskOptions value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Printing::IPaginateEventArgs)->get_PrintTaskOptions(put_abi(value)));
    return value;
}

template <typename D> int32_t consume_Windows_UI_Xaml_Printing_IPaginateEventArgs<D>::CurrentPreviewPageNumber() const
{
    int32_t value{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Printing::IPaginateEventArgs)->get_CurrentPreviewPageNumber(&value));
    return value;
}

template <typename D> Windows::Graphics::Printing::IPrintDocumentSource consume_Windows_UI_Xaml_Printing_IPrintDocument<D>::DocumentSource() const
{
    Windows::Graphics::Printing::IPrintDocumentSource value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Printing::IPrintDocument)->get_DocumentSource(put_abi(value)));
    return value;
}

template <typename D> winrt::event_token consume_Windows_UI_Xaml_Printing_IPrintDocument<D>::Paginate(Windows::UI::Xaml::Printing::PaginateEventHandler const& handler) const
{
    winrt::event_token token{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Printing::IPrintDocument)->add_Paginate(get_abi(handler), put_abi(token)));
    return token;
}

template <typename D> typename consume_Windows_UI_Xaml_Printing_IPrintDocument<D>::Paginate_revoker consume_Windows_UI_Xaml_Printing_IPrintDocument<D>::Paginate(auto_revoke_t, Windows::UI::Xaml::Printing::PaginateEventHandler const& handler) const
{
    return impl::make_event_revoker<D, Paginate_revoker>(this, Paginate(handler));
}

template <typename D> void consume_Windows_UI_Xaml_Printing_IPrintDocument<D>::Paginate(winrt::event_token const& token) const noexcept
{
    WINRT_VERIFY_(0, WINRT_SHIM(Windows::UI::Xaml::Printing::IPrintDocument)->remove_Paginate(get_abi(token)));
}

template <typename D> winrt::event_token consume_Windows_UI_Xaml_Printing_IPrintDocument<D>::GetPreviewPage(Windows::UI::Xaml::Printing::GetPreviewPageEventHandler const& handler) const
{
    winrt::event_token token{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Printing::IPrintDocument)->add_GetPreviewPage(get_abi(handler), put_abi(token)));
    return token;
}

template <typename D> typename consume_Windows_UI_Xaml_Printing_IPrintDocument<D>::GetPreviewPage_revoker consume_Windows_UI_Xaml_Printing_IPrintDocument<D>::GetPreviewPage(auto_revoke_t, Windows::UI::Xaml::Printing::GetPreviewPageEventHandler const& handler) const
{
    return impl::make_event_revoker<D, GetPreviewPage_revoker>(this, GetPreviewPage(handler));
}

template <typename D> void consume_Windows_UI_Xaml_Printing_IPrintDocument<D>::GetPreviewPage(winrt::event_token const& token) const noexcept
{
    WINRT_VERIFY_(0, WINRT_SHIM(Windows::UI::Xaml::Printing::IPrintDocument)->remove_GetPreviewPage(get_abi(token)));
}

template <typename D> winrt::event_token consume_Windows_UI_Xaml_Printing_IPrintDocument<D>::AddPages(Windows::UI::Xaml::Printing::AddPagesEventHandler const& handler) const
{
    winrt::event_token token{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Printing::IPrintDocument)->add_AddPages(get_abi(handler), put_abi(token)));
    return token;
}

template <typename D> typename consume_Windows_UI_Xaml_Printing_IPrintDocument<D>::AddPages_revoker consume_Windows_UI_Xaml_Printing_IPrintDocument<D>::AddPages(auto_revoke_t, Windows::UI::Xaml::Printing::AddPagesEventHandler const& handler) const
{
    return impl::make_event_revoker<D, AddPages_revoker>(this, AddPages(handler));
}

template <typename D> void consume_Windows_UI_Xaml_Printing_IPrintDocument<D>::AddPages(winrt::event_token const& token) const noexcept
{
    WINRT_VERIFY_(0, WINRT_SHIM(Windows::UI::Xaml::Printing::IPrintDocument)->remove_AddPages(get_abi(token)));
}

template <typename D> void consume_Windows_UI_Xaml_Printing_IPrintDocument<D>::AddPage(Windows::UI::Xaml::UIElement const& pageVisual) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Printing::IPrintDocument)->AddPage(get_abi(pageVisual)));
}

template <typename D> void consume_Windows_UI_Xaml_Printing_IPrintDocument<D>::AddPagesComplete() const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Printing::IPrintDocument)->AddPagesComplete());
}

template <typename D> void consume_Windows_UI_Xaml_Printing_IPrintDocument<D>::SetPreviewPageCount(int32_t count, Windows::UI::Xaml::Printing::PreviewPageCountType const& type) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Printing::IPrintDocument)->SetPreviewPageCount(count, get_abi(type)));
}

template <typename D> void consume_Windows_UI_Xaml_Printing_IPrintDocument<D>::SetPreviewPage(int32_t pageNumber, Windows::UI::Xaml::UIElement const& pageVisual) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Printing::IPrintDocument)->SetPreviewPage(pageNumber, get_abi(pageVisual)));
}

template <typename D> void consume_Windows_UI_Xaml_Printing_IPrintDocument<D>::InvalidatePreview() const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Printing::IPrintDocument)->InvalidatePreview());
}

template <typename D> Windows::UI::Xaml::Printing::PrintDocument consume_Windows_UI_Xaml_Printing_IPrintDocumentFactory<D>::CreateInstance(Windows::Foundation::IInspectable const& baseInterface, Windows::Foundation::IInspectable& innerInterface) const
{
    Windows::UI::Xaml::Printing::PrintDocument value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Printing::IPrintDocumentFactory)->CreateInstance(get_abi(baseInterface), put_abi(innerInterface), put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Xaml::DependencyProperty consume_Windows_UI_Xaml_Printing_IPrintDocumentStatics<D>::DocumentSourceProperty() const
{
    Windows::UI::Xaml::DependencyProperty value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Printing::IPrintDocumentStatics)->get_DocumentSourceProperty(put_abi(value)));
    return value;
}

template <> struct delegate<Windows::UI::Xaml::Printing::AddPagesEventHandler>
{
    template <typename H>
    struct type : implements_delegate<Windows::UI::Xaml::Printing::AddPagesEventHandler, H>
    {
        type(H&& handler) : implements_delegate<Windows::UI::Xaml::Printing::AddPagesEventHandler, H>(std::forward<H>(handler)) {}

        int32_t WINRT_CALL Invoke(void* sender, void* e) noexcept final
        {
            try
            {
                (*this)(*reinterpret_cast<Windows::Foundation::IInspectable const*>(&sender), *reinterpret_cast<Windows::UI::Xaml::Printing::AddPagesEventArgs const*>(&e));
                return 0;
            }
            catch (...)
            {
                return to_hresult();
            }
        }
    };
};

template <> struct delegate<Windows::UI::Xaml::Printing::GetPreviewPageEventHandler>
{
    template <typename H>
    struct type : implements_delegate<Windows::UI::Xaml::Printing::GetPreviewPageEventHandler, H>
    {
        type(H&& handler) : implements_delegate<Windows::UI::Xaml::Printing::GetPreviewPageEventHandler, H>(std::forward<H>(handler)) {}

        int32_t WINRT_CALL Invoke(void* sender, void* e) noexcept final
        {
            try
            {
                (*this)(*reinterpret_cast<Windows::Foundation::IInspectable const*>(&sender), *reinterpret_cast<Windows::UI::Xaml::Printing::GetPreviewPageEventArgs const*>(&e));
                return 0;
            }
            catch (...)
            {
                return to_hresult();
            }
        }
    };
};

template <> struct delegate<Windows::UI::Xaml::Printing::PaginateEventHandler>
{
    template <typename H>
    struct type : implements_delegate<Windows::UI::Xaml::Printing::PaginateEventHandler, H>
    {
        type(H&& handler) : implements_delegate<Windows::UI::Xaml::Printing::PaginateEventHandler, H>(std::forward<H>(handler)) {}

        int32_t WINRT_CALL Invoke(void* sender, void* e) noexcept final
        {
            try
            {
                (*this)(*reinterpret_cast<Windows::Foundation::IInspectable const*>(&sender), *reinterpret_cast<Windows::UI::Xaml::Printing::PaginateEventArgs const*>(&e));
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
struct produce<D, Windows::UI::Xaml::Printing::IAddPagesEventArgs> : produce_base<D, Windows::UI::Xaml::Printing::IAddPagesEventArgs>
{
    int32_t WINRT_CALL get_PrintTaskOptions(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(PrintTaskOptions, WINRT_WRAP(Windows::Graphics::Printing::PrintTaskOptions));
            *value = detach_from<Windows::Graphics::Printing::PrintTaskOptions>(this->shim().PrintTaskOptions());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Xaml::Printing::IGetPreviewPageEventArgs> : produce_base<D, Windows::UI::Xaml::Printing::IGetPreviewPageEventArgs>
{
    int32_t WINRT_CALL get_PageNumber(int32_t* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(PageNumber, WINRT_WRAP(int32_t));
            *value = detach_from<int32_t>(this->shim().PageNumber());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Xaml::Printing::IPaginateEventArgs> : produce_base<D, Windows::UI::Xaml::Printing::IPaginateEventArgs>
{
    int32_t WINRT_CALL get_PrintTaskOptions(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(PrintTaskOptions, WINRT_WRAP(Windows::Graphics::Printing::PrintTaskOptions));
            *value = detach_from<Windows::Graphics::Printing::PrintTaskOptions>(this->shim().PrintTaskOptions());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_CurrentPreviewPageNumber(int32_t* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CurrentPreviewPageNumber, WINRT_WRAP(int32_t));
            *value = detach_from<int32_t>(this->shim().CurrentPreviewPageNumber());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Xaml::Printing::IPrintDocument> : produce_base<D, Windows::UI::Xaml::Printing::IPrintDocument>
{
    int32_t WINRT_CALL get_DocumentSource(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(DocumentSource, WINRT_WRAP(Windows::Graphics::Printing::IPrintDocumentSource));
            *value = detach_from<Windows::Graphics::Printing::IPrintDocumentSource>(this->shim().DocumentSource());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL add_Paginate(void* handler, winrt::event_token* token) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Paginate, WINRT_WRAP(winrt::event_token), Windows::UI::Xaml::Printing::PaginateEventHandler const&);
            *token = detach_from<winrt::event_token>(this->shim().Paginate(*reinterpret_cast<Windows::UI::Xaml::Printing::PaginateEventHandler const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL remove_Paginate(winrt::event_token token) noexcept final
    {
        typename D::abi_guard guard(this->shim());
        WINRT_ASSERT_DECLARATION(Paginate, WINRT_WRAP(void), winrt::event_token const&);
        this->shim().Paginate(*reinterpret_cast<winrt::event_token const*>(&token));
        return 0;
    }

    int32_t WINRT_CALL add_GetPreviewPage(void* handler, winrt::event_token* token) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetPreviewPage, WINRT_WRAP(winrt::event_token), Windows::UI::Xaml::Printing::GetPreviewPageEventHandler const&);
            *token = detach_from<winrt::event_token>(this->shim().GetPreviewPage(*reinterpret_cast<Windows::UI::Xaml::Printing::GetPreviewPageEventHandler const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL remove_GetPreviewPage(winrt::event_token token) noexcept final
    {
        typename D::abi_guard guard(this->shim());
        WINRT_ASSERT_DECLARATION(GetPreviewPage, WINRT_WRAP(void), winrt::event_token const&);
        this->shim().GetPreviewPage(*reinterpret_cast<winrt::event_token const*>(&token));
        return 0;
    }

    int32_t WINRT_CALL add_AddPages(void* handler, winrt::event_token* token) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(AddPages, WINRT_WRAP(winrt::event_token), Windows::UI::Xaml::Printing::AddPagesEventHandler const&);
            *token = detach_from<winrt::event_token>(this->shim().AddPages(*reinterpret_cast<Windows::UI::Xaml::Printing::AddPagesEventHandler const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL remove_AddPages(winrt::event_token token) noexcept final
    {
        typename D::abi_guard guard(this->shim());
        WINRT_ASSERT_DECLARATION(AddPages, WINRT_WRAP(void), winrt::event_token const&);
        this->shim().AddPages(*reinterpret_cast<winrt::event_token const*>(&token));
        return 0;
    }

    int32_t WINRT_CALL AddPage(void* pageVisual) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(AddPage, WINRT_WRAP(void), Windows::UI::Xaml::UIElement const&);
            this->shim().AddPage(*reinterpret_cast<Windows::UI::Xaml::UIElement const*>(&pageVisual));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL AddPagesComplete() noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(AddPagesComplete, WINRT_WRAP(void));
            this->shim().AddPagesComplete();
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL SetPreviewPageCount(int32_t count, Windows::UI::Xaml::Printing::PreviewPageCountType type) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SetPreviewPageCount, WINRT_WRAP(void), int32_t, Windows::UI::Xaml::Printing::PreviewPageCountType const&);
            this->shim().SetPreviewPageCount(count, *reinterpret_cast<Windows::UI::Xaml::Printing::PreviewPageCountType const*>(&type));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL SetPreviewPage(int32_t pageNumber, void* pageVisual) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SetPreviewPage, WINRT_WRAP(void), int32_t, Windows::UI::Xaml::UIElement const&);
            this->shim().SetPreviewPage(pageNumber, *reinterpret_cast<Windows::UI::Xaml::UIElement const*>(&pageVisual));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL InvalidatePreview() noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(InvalidatePreview, WINRT_WRAP(void));
            this->shim().InvalidatePreview();
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Xaml::Printing::IPrintDocumentFactory> : produce_base<D, Windows::UI::Xaml::Printing::IPrintDocumentFactory>
{
    int32_t WINRT_CALL CreateInstance(void* baseInterface, void** innerInterface, void** value) noexcept final
    {
        try
        {
            if (innerInterface) *innerInterface = nullptr;
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            Windows::Foundation::IInspectable __local_innerInterface;
            WINRT_ASSERT_DECLARATION(CreateInstance, WINRT_WRAP(Windows::UI::Xaml::Printing::PrintDocument), Windows::Foundation::IInspectable const&, Windows::Foundation::IInspectable&);
            *value = detach_from<Windows::UI::Xaml::Printing::PrintDocument>(this->shim().CreateInstance(*reinterpret_cast<Windows::Foundation::IInspectable const*>(&baseInterface), __local_innerInterface));
            if (innerInterface) *innerInterface = detach_abi(__local_innerInterface);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Xaml::Printing::IPrintDocumentStatics> : produce_base<D, Windows::UI::Xaml::Printing::IPrintDocumentStatics>
{
    int32_t WINRT_CALL get_DocumentSourceProperty(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(DocumentSourceProperty, WINRT_WRAP(Windows::UI::Xaml::DependencyProperty));
            *value = detach_from<Windows::UI::Xaml::DependencyProperty>(this->shim().DocumentSourceProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

}

WINRT_EXPORT namespace winrt::Windows::UI::Xaml::Printing {

inline AddPagesEventArgs::AddPagesEventArgs() :
    AddPagesEventArgs(impl::call_factory<AddPagesEventArgs>([](auto&& f) { return f.template ActivateInstance<AddPagesEventArgs>(); }))
{}

inline GetPreviewPageEventArgs::GetPreviewPageEventArgs() :
    GetPreviewPageEventArgs(impl::call_factory<GetPreviewPageEventArgs>([](auto&& f) { return f.template ActivateInstance<GetPreviewPageEventArgs>(); }))
{}

inline PaginateEventArgs::PaginateEventArgs() :
    PaginateEventArgs(impl::call_factory<PaginateEventArgs>([](auto&& f) { return f.template ActivateInstance<PaginateEventArgs>(); }))
{}

inline PrintDocument::PrintDocument()
{
    Windows::Foundation::IInspectable baseInterface, innerInterface;
    *this = impl::call_factory<PrintDocument, Windows::UI::Xaml::Printing::IPrintDocumentFactory>([&](auto&& f) { return f.CreateInstance(baseInterface, innerInterface); });
}

inline Windows::UI::Xaml::DependencyProperty PrintDocument::DocumentSourceProperty()
{
    return impl::call_factory<PrintDocument, Windows::UI::Xaml::Printing::IPrintDocumentStatics>([&](auto&& f) { return f.DocumentSourceProperty(); });
}

template <typename L> AddPagesEventHandler::AddPagesEventHandler(L handler) :
    AddPagesEventHandler(impl::make_delegate<AddPagesEventHandler>(std::forward<L>(handler)))
{}

template <typename F> AddPagesEventHandler::AddPagesEventHandler(F* handler) :
    AddPagesEventHandler([=](auto&&... args) { return handler(args...); })
{}

template <typename O, typename M> AddPagesEventHandler::AddPagesEventHandler(O* object, M method) :
    AddPagesEventHandler([=](auto&&... args) { return ((*object).*(method))(args...); })
{}

template <typename O, typename M> AddPagesEventHandler::AddPagesEventHandler(com_ptr<O>&& object, M method) :
    AddPagesEventHandler([o = std::move(object), method](auto&&... args) { return ((*o).*(method))(args...); })
{}

template <typename O, typename M> AddPagesEventHandler::AddPagesEventHandler(weak_ref<O>&& object, M method) :
    AddPagesEventHandler([o = std::move(object), method](auto&&... args) { if (auto s = o.get()) { ((*s).*(method))(args...); } })
{}

inline void AddPagesEventHandler::operator()(Windows::Foundation::IInspectable const& sender, Windows::UI::Xaml::Printing::AddPagesEventArgs const& e) const
{
    check_hresult((*(impl::abi_t<AddPagesEventHandler>**)this)->Invoke(get_abi(sender), get_abi(e)));
}

template <typename L> GetPreviewPageEventHandler::GetPreviewPageEventHandler(L handler) :
    GetPreviewPageEventHandler(impl::make_delegate<GetPreviewPageEventHandler>(std::forward<L>(handler)))
{}

template <typename F> GetPreviewPageEventHandler::GetPreviewPageEventHandler(F* handler) :
    GetPreviewPageEventHandler([=](auto&&... args) { return handler(args...); })
{}

template <typename O, typename M> GetPreviewPageEventHandler::GetPreviewPageEventHandler(O* object, M method) :
    GetPreviewPageEventHandler([=](auto&&... args) { return ((*object).*(method))(args...); })
{}

template <typename O, typename M> GetPreviewPageEventHandler::GetPreviewPageEventHandler(com_ptr<O>&& object, M method) :
    GetPreviewPageEventHandler([o = std::move(object), method](auto&&... args) { return ((*o).*(method))(args...); })
{}

template <typename O, typename M> GetPreviewPageEventHandler::GetPreviewPageEventHandler(weak_ref<O>&& object, M method) :
    GetPreviewPageEventHandler([o = std::move(object), method](auto&&... args) { if (auto s = o.get()) { ((*s).*(method))(args...); } })
{}

inline void GetPreviewPageEventHandler::operator()(Windows::Foundation::IInspectable const& sender, Windows::UI::Xaml::Printing::GetPreviewPageEventArgs const& e) const
{
    check_hresult((*(impl::abi_t<GetPreviewPageEventHandler>**)this)->Invoke(get_abi(sender), get_abi(e)));
}

template <typename L> PaginateEventHandler::PaginateEventHandler(L handler) :
    PaginateEventHandler(impl::make_delegate<PaginateEventHandler>(std::forward<L>(handler)))
{}

template <typename F> PaginateEventHandler::PaginateEventHandler(F* handler) :
    PaginateEventHandler([=](auto&&... args) { return handler(args...); })
{}

template <typename O, typename M> PaginateEventHandler::PaginateEventHandler(O* object, M method) :
    PaginateEventHandler([=](auto&&... args) { return ((*object).*(method))(args...); })
{}

template <typename O, typename M> PaginateEventHandler::PaginateEventHandler(com_ptr<O>&& object, M method) :
    PaginateEventHandler([o = std::move(object), method](auto&&... args) { return ((*o).*(method))(args...); })
{}

template <typename O, typename M> PaginateEventHandler::PaginateEventHandler(weak_ref<O>&& object, M method) :
    PaginateEventHandler([o = std::move(object), method](auto&&... args) { if (auto s = o.get()) { ((*s).*(method))(args...); } })
{}

inline void PaginateEventHandler::operator()(Windows::Foundation::IInspectable const& sender, Windows::UI::Xaml::Printing::PaginateEventArgs const& e) const
{
    check_hresult((*(impl::abi_t<PaginateEventHandler>**)this)->Invoke(get_abi(sender), get_abi(e)));
}

template <typename D, typename... Interfaces>
struct PrintDocumentT :
    implements<D, Windows::Foundation::IInspectable, composing, Interfaces...>,
    impl::require<D, Windows::UI::Xaml::Printing::IPrintDocument, Windows::UI::Xaml::IDependencyObject, Windows::UI::Xaml::IDependencyObject2>,
    impl::base<D, Windows::UI::Xaml::Printing::PrintDocument, Windows::UI::Xaml::DependencyObject>
{
    using composable = PrintDocument;

protected:
    PrintDocumentT()
    {
        impl::call_factory<Windows::UI::Xaml::Printing::PrintDocument, Windows::UI::Xaml::Printing::IPrintDocumentFactory>([&](auto&& f) { f.CreateInstance(*this, this->m_inner); });
    }
};

}

WINRT_EXPORT namespace std {

template<> struct hash<winrt::Windows::UI::Xaml::Printing::IAddPagesEventArgs> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Printing::IAddPagesEventArgs> {};
template<> struct hash<winrt::Windows::UI::Xaml::Printing::IGetPreviewPageEventArgs> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Printing::IGetPreviewPageEventArgs> {};
template<> struct hash<winrt::Windows::UI::Xaml::Printing::IPaginateEventArgs> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Printing::IPaginateEventArgs> {};
template<> struct hash<winrt::Windows::UI::Xaml::Printing::IPrintDocument> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Printing::IPrintDocument> {};
template<> struct hash<winrt::Windows::UI::Xaml::Printing::IPrintDocumentFactory> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Printing::IPrintDocumentFactory> {};
template<> struct hash<winrt::Windows::UI::Xaml::Printing::IPrintDocumentStatics> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Printing::IPrintDocumentStatics> {};
template<> struct hash<winrt::Windows::UI::Xaml::Printing::AddPagesEventArgs> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Printing::AddPagesEventArgs> {};
template<> struct hash<winrt::Windows::UI::Xaml::Printing::GetPreviewPageEventArgs> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Printing::GetPreviewPageEventArgs> {};
template<> struct hash<winrt::Windows::UI::Xaml::Printing::PaginateEventArgs> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Printing::PaginateEventArgs> {};
template<> struct hash<winrt::Windows::UI::Xaml::Printing::PrintDocument> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Printing::PrintDocument> {};

}
