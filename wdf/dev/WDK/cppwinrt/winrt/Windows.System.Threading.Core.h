// C++/WinRT v1.0.190111.3

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#pragma once

#include "winrt/base.h"

#include "winrt/Windows.Foundation.h"
#include "winrt/Windows.Foundation.Collections.h"
#include "winrt/impl/Windows.System.Threading.2.h"
#include "winrt/impl/Windows.System.Threading.Core.2.h"
#include "winrt/Windows.System.Threading.h"

namespace winrt::impl {

template <typename D> Windows::Foundation::IAsyncAction consume_Windows_System_Threading_Core_IPreallocatedWorkItem<D>::RunAsync() const
{
    Windows::Foundation::IAsyncAction operation{ nullptr };
    check_hresult(WINRT_SHIM(Windows::System::Threading::Core::IPreallocatedWorkItem)->RunAsync(put_abi(operation)));
    return operation;
}

template <typename D> Windows::System::Threading::Core::PreallocatedWorkItem consume_Windows_System_Threading_Core_IPreallocatedWorkItemFactory<D>::CreateWorkItem(Windows::System::Threading::WorkItemHandler const& handler) const
{
    Windows::System::Threading::Core::PreallocatedWorkItem workItem{ nullptr };
    check_hresult(WINRT_SHIM(Windows::System::Threading::Core::IPreallocatedWorkItemFactory)->CreateWorkItem(get_abi(handler), put_abi(workItem)));
    return workItem;
}

template <typename D> Windows::System::Threading::Core::PreallocatedWorkItem consume_Windows_System_Threading_Core_IPreallocatedWorkItemFactory<D>::CreateWorkItemWithPriority(Windows::System::Threading::WorkItemHandler const& handler, Windows::System::Threading::WorkItemPriority const& priority) const
{
    Windows::System::Threading::Core::PreallocatedWorkItem WorkItem{ nullptr };
    check_hresult(WINRT_SHIM(Windows::System::Threading::Core::IPreallocatedWorkItemFactory)->CreateWorkItemWithPriority(get_abi(handler), get_abi(priority), put_abi(WorkItem)));
    return WorkItem;
}

template <typename D> Windows::System::Threading::Core::PreallocatedWorkItem consume_Windows_System_Threading_Core_IPreallocatedWorkItemFactory<D>::CreateWorkItemWithPriorityAndOptions(Windows::System::Threading::WorkItemHandler const& handler, Windows::System::Threading::WorkItemPriority const& priority, Windows::System::Threading::WorkItemOptions const& options) const
{
    Windows::System::Threading::Core::PreallocatedWorkItem WorkItem{ nullptr };
    check_hresult(WINRT_SHIM(Windows::System::Threading::Core::IPreallocatedWorkItemFactory)->CreateWorkItemWithPriorityAndOptions(get_abi(handler), get_abi(priority), get_abi(options), put_abi(WorkItem)));
    return WorkItem;
}

template <typename D> void consume_Windows_System_Threading_Core_ISignalNotifier<D>::Enable() const
{
    check_hresult(WINRT_SHIM(Windows::System::Threading::Core::ISignalNotifier)->Enable());
}

template <typename D> void consume_Windows_System_Threading_Core_ISignalNotifier<D>::Terminate() const
{
    check_hresult(WINRT_SHIM(Windows::System::Threading::Core::ISignalNotifier)->Terminate());
}

template <typename D> Windows::System::Threading::Core::SignalNotifier consume_Windows_System_Threading_Core_ISignalNotifierStatics<D>::AttachToEvent(param::hstring const& name, Windows::System::Threading::Core::SignalHandler const& handler) const
{
    Windows::System::Threading::Core::SignalNotifier signalNotifier{ nullptr };
    check_hresult(WINRT_SHIM(Windows::System::Threading::Core::ISignalNotifierStatics)->AttachToEvent(get_abi(name), get_abi(handler), put_abi(signalNotifier)));
    return signalNotifier;
}

template <typename D> Windows::System::Threading::Core::SignalNotifier consume_Windows_System_Threading_Core_ISignalNotifierStatics<D>::AttachToEvent(param::hstring const& name, Windows::System::Threading::Core::SignalHandler const& handler, Windows::Foundation::TimeSpan const& timeout) const
{
    Windows::System::Threading::Core::SignalNotifier signalNotifier{ nullptr };
    check_hresult(WINRT_SHIM(Windows::System::Threading::Core::ISignalNotifierStatics)->AttachToEventWithTimeout(get_abi(name), get_abi(handler), get_abi(timeout), put_abi(signalNotifier)));
    return signalNotifier;
}

template <typename D> Windows::System::Threading::Core::SignalNotifier consume_Windows_System_Threading_Core_ISignalNotifierStatics<D>::AttachToSemaphore(param::hstring const& name, Windows::System::Threading::Core::SignalHandler const& handler) const
{
    Windows::System::Threading::Core::SignalNotifier signalNotifier{ nullptr };
    check_hresult(WINRT_SHIM(Windows::System::Threading::Core::ISignalNotifierStatics)->AttachToSemaphore(get_abi(name), get_abi(handler), put_abi(signalNotifier)));
    return signalNotifier;
}

template <typename D> Windows::System::Threading::Core::SignalNotifier consume_Windows_System_Threading_Core_ISignalNotifierStatics<D>::AttachToSemaphore(param::hstring const& name, Windows::System::Threading::Core::SignalHandler const& handler, Windows::Foundation::TimeSpan const& timeout) const
{
    Windows::System::Threading::Core::SignalNotifier signalNotifier{ nullptr };
    check_hresult(WINRT_SHIM(Windows::System::Threading::Core::ISignalNotifierStatics)->AttachToSemaphoreWithTimeout(get_abi(name), get_abi(handler), get_abi(timeout), put_abi(signalNotifier)));
    return signalNotifier;
}

template <> struct delegate<Windows::System::Threading::Core::SignalHandler>
{
    template <typename H>
    struct type : implements_delegate<Windows::System::Threading::Core::SignalHandler, H>
    {
        type(H&& handler) : implements_delegate<Windows::System::Threading::Core::SignalHandler, H>(std::forward<H>(handler)) {}

        int32_t WINRT_CALL Invoke(void* signalNotifier, bool timedOut) noexcept final
        {
            try
            {
                (*this)(*reinterpret_cast<Windows::System::Threading::Core::SignalNotifier const*>(&signalNotifier), timedOut);
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
struct produce<D, Windows::System::Threading::Core::IPreallocatedWorkItem> : produce_base<D, Windows::System::Threading::Core::IPreallocatedWorkItem>
{
    int32_t WINRT_CALL RunAsync(void** operation) noexcept final
    {
        try
        {
            *operation = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(RunAsync, WINRT_WRAP(Windows::Foundation::IAsyncAction));
            *operation = detach_from<Windows::Foundation::IAsyncAction>(this->shim().RunAsync());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::System::Threading::Core::IPreallocatedWorkItemFactory> : produce_base<D, Windows::System::Threading::Core::IPreallocatedWorkItemFactory>
{
    int32_t WINRT_CALL CreateWorkItem(void* handler, void** workItem) noexcept final
    {
        try
        {
            *workItem = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CreateWorkItem, WINRT_WRAP(Windows::System::Threading::Core::PreallocatedWorkItem), Windows::System::Threading::WorkItemHandler const&);
            *workItem = detach_from<Windows::System::Threading::Core::PreallocatedWorkItem>(this->shim().CreateWorkItem(*reinterpret_cast<Windows::System::Threading::WorkItemHandler const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL CreateWorkItemWithPriority(void* handler, Windows::System::Threading::WorkItemPriority priority, void** WorkItem) noexcept final
    {
        try
        {
            *WorkItem = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CreateWorkItemWithPriority, WINRT_WRAP(Windows::System::Threading::Core::PreallocatedWorkItem), Windows::System::Threading::WorkItemHandler const&, Windows::System::Threading::WorkItemPriority const&);
            *WorkItem = detach_from<Windows::System::Threading::Core::PreallocatedWorkItem>(this->shim().CreateWorkItemWithPriority(*reinterpret_cast<Windows::System::Threading::WorkItemHandler const*>(&handler), *reinterpret_cast<Windows::System::Threading::WorkItemPriority const*>(&priority)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL CreateWorkItemWithPriorityAndOptions(void* handler, Windows::System::Threading::WorkItemPriority priority, Windows::System::Threading::WorkItemOptions options, void** WorkItem) noexcept final
    {
        try
        {
            *WorkItem = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CreateWorkItemWithPriorityAndOptions, WINRT_WRAP(Windows::System::Threading::Core::PreallocatedWorkItem), Windows::System::Threading::WorkItemHandler const&, Windows::System::Threading::WorkItemPriority const&, Windows::System::Threading::WorkItemOptions const&);
            *WorkItem = detach_from<Windows::System::Threading::Core::PreallocatedWorkItem>(this->shim().CreateWorkItemWithPriorityAndOptions(*reinterpret_cast<Windows::System::Threading::WorkItemHandler const*>(&handler), *reinterpret_cast<Windows::System::Threading::WorkItemPriority const*>(&priority), *reinterpret_cast<Windows::System::Threading::WorkItemOptions const*>(&options)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::System::Threading::Core::ISignalNotifier> : produce_base<D, Windows::System::Threading::Core::ISignalNotifier>
{
    int32_t WINRT_CALL Enable() noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Enable, WINRT_WRAP(void));
            this->shim().Enable();
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL Terminate() noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Terminate, WINRT_WRAP(void));
            this->shim().Terminate();
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::System::Threading::Core::ISignalNotifierStatics> : produce_base<D, Windows::System::Threading::Core::ISignalNotifierStatics>
{
    int32_t WINRT_CALL AttachToEvent(void* name, void* handler, void** signalNotifier) noexcept final
    {
        try
        {
            *signalNotifier = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(AttachToEvent, WINRT_WRAP(Windows::System::Threading::Core::SignalNotifier), hstring const&, Windows::System::Threading::Core::SignalHandler const&);
            *signalNotifier = detach_from<Windows::System::Threading::Core::SignalNotifier>(this->shim().AttachToEvent(*reinterpret_cast<hstring const*>(&name), *reinterpret_cast<Windows::System::Threading::Core::SignalHandler const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL AttachToEventWithTimeout(void* name, void* handler, Windows::Foundation::TimeSpan timeout, void** signalNotifier) noexcept final
    {
        try
        {
            *signalNotifier = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(AttachToEvent, WINRT_WRAP(Windows::System::Threading::Core::SignalNotifier), hstring const&, Windows::System::Threading::Core::SignalHandler const&, Windows::Foundation::TimeSpan const&);
            *signalNotifier = detach_from<Windows::System::Threading::Core::SignalNotifier>(this->shim().AttachToEvent(*reinterpret_cast<hstring const*>(&name), *reinterpret_cast<Windows::System::Threading::Core::SignalHandler const*>(&handler), *reinterpret_cast<Windows::Foundation::TimeSpan const*>(&timeout)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL AttachToSemaphore(void* name, void* handler, void** signalNotifier) noexcept final
    {
        try
        {
            *signalNotifier = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(AttachToSemaphore, WINRT_WRAP(Windows::System::Threading::Core::SignalNotifier), hstring const&, Windows::System::Threading::Core::SignalHandler const&);
            *signalNotifier = detach_from<Windows::System::Threading::Core::SignalNotifier>(this->shim().AttachToSemaphore(*reinterpret_cast<hstring const*>(&name), *reinterpret_cast<Windows::System::Threading::Core::SignalHandler const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL AttachToSemaphoreWithTimeout(void* name, void* handler, Windows::Foundation::TimeSpan timeout, void** signalNotifier) noexcept final
    {
        try
        {
            *signalNotifier = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(AttachToSemaphore, WINRT_WRAP(Windows::System::Threading::Core::SignalNotifier), hstring const&, Windows::System::Threading::Core::SignalHandler const&, Windows::Foundation::TimeSpan const&);
            *signalNotifier = detach_from<Windows::System::Threading::Core::SignalNotifier>(this->shim().AttachToSemaphore(*reinterpret_cast<hstring const*>(&name), *reinterpret_cast<Windows::System::Threading::Core::SignalHandler const*>(&handler), *reinterpret_cast<Windows::Foundation::TimeSpan const*>(&timeout)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

}

WINRT_EXPORT namespace winrt::Windows::System::Threading::Core {

inline PreallocatedWorkItem::PreallocatedWorkItem(Windows::System::Threading::WorkItemHandler const& handler) :
    PreallocatedWorkItem(impl::call_factory<PreallocatedWorkItem, Windows::System::Threading::Core::IPreallocatedWorkItemFactory>([&](auto&& f) { return f.CreateWorkItem(handler); }))
{}

inline PreallocatedWorkItem::PreallocatedWorkItem(Windows::System::Threading::WorkItemHandler const& handler, Windows::System::Threading::WorkItemPriority const& priority) :
    PreallocatedWorkItem(impl::call_factory<PreallocatedWorkItem, Windows::System::Threading::Core::IPreallocatedWorkItemFactory>([&](auto&& f) { return f.CreateWorkItemWithPriority(handler, priority); }))
{}

inline PreallocatedWorkItem::PreallocatedWorkItem(Windows::System::Threading::WorkItemHandler const& handler, Windows::System::Threading::WorkItemPriority const& priority, Windows::System::Threading::WorkItemOptions const& options) :
    PreallocatedWorkItem(impl::call_factory<PreallocatedWorkItem, Windows::System::Threading::Core::IPreallocatedWorkItemFactory>([&](auto&& f) { return f.CreateWorkItemWithPriorityAndOptions(handler, priority, options); }))
{}

inline Windows::System::Threading::Core::SignalNotifier SignalNotifier::AttachToEvent(param::hstring const& name, Windows::System::Threading::Core::SignalHandler const& handler)
{
    return impl::call_factory<SignalNotifier, Windows::System::Threading::Core::ISignalNotifierStatics>([&](auto&& f) { return f.AttachToEvent(name, handler); });
}

inline Windows::System::Threading::Core::SignalNotifier SignalNotifier::AttachToEvent(param::hstring const& name, Windows::System::Threading::Core::SignalHandler const& handler, Windows::Foundation::TimeSpan const& timeout)
{
    return impl::call_factory<SignalNotifier, Windows::System::Threading::Core::ISignalNotifierStatics>([&](auto&& f) { return f.AttachToEvent(name, handler, timeout); });
}

inline Windows::System::Threading::Core::SignalNotifier SignalNotifier::AttachToSemaphore(param::hstring const& name, Windows::System::Threading::Core::SignalHandler const& handler)
{
    return impl::call_factory<SignalNotifier, Windows::System::Threading::Core::ISignalNotifierStatics>([&](auto&& f) { return f.AttachToSemaphore(name, handler); });
}

inline Windows::System::Threading::Core::SignalNotifier SignalNotifier::AttachToSemaphore(param::hstring const& name, Windows::System::Threading::Core::SignalHandler const& handler, Windows::Foundation::TimeSpan const& timeout)
{
    return impl::call_factory<SignalNotifier, Windows::System::Threading::Core::ISignalNotifierStatics>([&](auto&& f) { return f.AttachToSemaphore(name, handler, timeout); });
}

template <typename L> SignalHandler::SignalHandler(L handler) :
    SignalHandler(impl::make_delegate<SignalHandler>(std::forward<L>(handler)))
{}

template <typename F> SignalHandler::SignalHandler(F* handler) :
    SignalHandler([=](auto&&... args) { return handler(args...); })
{}

template <typename O, typename M> SignalHandler::SignalHandler(O* object, M method) :
    SignalHandler([=](auto&&... args) { return ((*object).*(method))(args...); })
{}

template <typename O, typename M> SignalHandler::SignalHandler(com_ptr<O>&& object, M method) :
    SignalHandler([o = std::move(object), method](auto&&... args) { return ((*o).*(method))(args...); })
{}

template <typename O, typename M> SignalHandler::SignalHandler(weak_ref<O>&& object, M method) :
    SignalHandler([o = std::move(object), method](auto&&... args) { if (auto s = o.get()) { ((*s).*(method))(args...); } })
{}

inline void SignalHandler::operator()(Windows::System::Threading::Core::SignalNotifier const& signalNotifier, bool timedOut) const
{
    check_hresult((*(impl::abi_t<SignalHandler>**)this)->Invoke(get_abi(signalNotifier), timedOut));
}

}

WINRT_EXPORT namespace std {

template<> struct hash<winrt::Windows::System::Threading::Core::IPreallocatedWorkItem> : winrt::impl::hash_base<winrt::Windows::System::Threading::Core::IPreallocatedWorkItem> {};
template<> struct hash<winrt::Windows::System::Threading::Core::IPreallocatedWorkItemFactory> : winrt::impl::hash_base<winrt::Windows::System::Threading::Core::IPreallocatedWorkItemFactory> {};
template<> struct hash<winrt::Windows::System::Threading::Core::ISignalNotifier> : winrt::impl::hash_base<winrt::Windows::System::Threading::Core::ISignalNotifier> {};
template<> struct hash<winrt::Windows::System::Threading::Core::ISignalNotifierStatics> : winrt::impl::hash_base<winrt::Windows::System::Threading::Core::ISignalNotifierStatics> {};
template<> struct hash<winrt::Windows::System::Threading::Core::PreallocatedWorkItem> : winrt::impl::hash_base<winrt::Windows::System::Threading::Core::PreallocatedWorkItem> {};
template<> struct hash<winrt::Windows::System::Threading::Core::SignalNotifier> : winrt::impl::hash_base<winrt::Windows::System::Threading::Core::SignalNotifier> {};

}
