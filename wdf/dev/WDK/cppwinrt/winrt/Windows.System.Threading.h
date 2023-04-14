// C++/WinRT v1.0.190111.3

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#pragma once

#include "winrt/base.h"

#include "winrt/Windows.Foundation.h"
#include "winrt/Windows.Foundation.Collections.h"
#include "winrt/impl/Windows.System.Threading.2.h"
#include "winrt/Windows.System.h"

namespace winrt::impl {

template <typename D> Windows::Foundation::IAsyncAction consume_Windows_System_Threading_IThreadPoolStatics<D>::RunAsync(Windows::System::Threading::WorkItemHandler const& handler) const
{
    Windows::Foundation::IAsyncAction operation{ nullptr };
    check_hresult(WINRT_SHIM(Windows::System::Threading::IThreadPoolStatics)->RunAsync(get_abi(handler), put_abi(operation)));
    return operation;
}

template <typename D> Windows::Foundation::IAsyncAction consume_Windows_System_Threading_IThreadPoolStatics<D>::RunAsync(Windows::System::Threading::WorkItemHandler const& handler, Windows::System::Threading::WorkItemPriority const& priority) const
{
    Windows::Foundation::IAsyncAction operation{ nullptr };
    check_hresult(WINRT_SHIM(Windows::System::Threading::IThreadPoolStatics)->RunWithPriorityAsync(get_abi(handler), get_abi(priority), put_abi(operation)));
    return operation;
}

template <typename D> Windows::Foundation::IAsyncAction consume_Windows_System_Threading_IThreadPoolStatics<D>::RunAsync(Windows::System::Threading::WorkItemHandler const& handler, Windows::System::Threading::WorkItemPriority const& priority, Windows::System::Threading::WorkItemOptions const& options) const
{
    Windows::Foundation::IAsyncAction operation{ nullptr };
    check_hresult(WINRT_SHIM(Windows::System::Threading::IThreadPoolStatics)->RunWithPriorityAndOptionsAsync(get_abi(handler), get_abi(priority), get_abi(options), put_abi(operation)));
    return operation;
}

template <typename D> Windows::Foundation::TimeSpan consume_Windows_System_Threading_IThreadPoolTimer<D>::Period() const
{
    Windows::Foundation::TimeSpan value{};
    check_hresult(WINRT_SHIM(Windows::System::Threading::IThreadPoolTimer)->get_Period(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::TimeSpan consume_Windows_System_Threading_IThreadPoolTimer<D>::Delay() const
{
    Windows::Foundation::TimeSpan value{};
    check_hresult(WINRT_SHIM(Windows::System::Threading::IThreadPoolTimer)->get_Delay(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_System_Threading_IThreadPoolTimer<D>::Cancel() const
{
    check_hresult(WINRT_SHIM(Windows::System::Threading::IThreadPoolTimer)->Cancel());
}

template <typename D> Windows::System::Threading::ThreadPoolTimer consume_Windows_System_Threading_IThreadPoolTimerStatics<D>::CreatePeriodicTimer(Windows::System::Threading::TimerElapsedHandler const& handler, Windows::Foundation::TimeSpan const& period) const
{
    Windows::System::Threading::ThreadPoolTimer timer{ nullptr };
    check_hresult(WINRT_SHIM(Windows::System::Threading::IThreadPoolTimerStatics)->CreatePeriodicTimer(get_abi(handler), get_abi(period), put_abi(timer)));
    return timer;
}

template <typename D> Windows::System::Threading::ThreadPoolTimer consume_Windows_System_Threading_IThreadPoolTimerStatics<D>::CreateTimer(Windows::System::Threading::TimerElapsedHandler const& handler, Windows::Foundation::TimeSpan const& delay) const
{
    Windows::System::Threading::ThreadPoolTimer timer{ nullptr };
    check_hresult(WINRT_SHIM(Windows::System::Threading::IThreadPoolTimerStatics)->CreateTimer(get_abi(handler), get_abi(delay), put_abi(timer)));
    return timer;
}

template <typename D> Windows::System::Threading::ThreadPoolTimer consume_Windows_System_Threading_IThreadPoolTimerStatics<D>::CreatePeriodicTimer(Windows::System::Threading::TimerElapsedHandler const& handler, Windows::Foundation::TimeSpan const& period, Windows::System::Threading::TimerDestroyedHandler const& destroyed) const
{
    Windows::System::Threading::ThreadPoolTimer timer{ nullptr };
    check_hresult(WINRT_SHIM(Windows::System::Threading::IThreadPoolTimerStatics)->CreatePeriodicTimerWithCompletion(get_abi(handler), get_abi(period), get_abi(destroyed), put_abi(timer)));
    return timer;
}

template <typename D> Windows::System::Threading::ThreadPoolTimer consume_Windows_System_Threading_IThreadPoolTimerStatics<D>::CreateTimer(Windows::System::Threading::TimerElapsedHandler const& handler, Windows::Foundation::TimeSpan const& delay, Windows::System::Threading::TimerDestroyedHandler const& destroyed) const
{
    Windows::System::Threading::ThreadPoolTimer timer{ nullptr };
    check_hresult(WINRT_SHIM(Windows::System::Threading::IThreadPoolTimerStatics)->CreateTimerWithCompletion(get_abi(handler), get_abi(delay), get_abi(destroyed), put_abi(timer)));
    return timer;
}

template <> struct delegate<Windows::System::Threading::TimerDestroyedHandler>
{
    template <typename H>
    struct type : implements_delegate<Windows::System::Threading::TimerDestroyedHandler, H>
    {
        type(H&& handler) : implements_delegate<Windows::System::Threading::TimerDestroyedHandler, H>(std::forward<H>(handler)) {}

        int32_t WINRT_CALL Invoke(void* timer) noexcept final
        {
            try
            {
                (*this)(*reinterpret_cast<Windows::System::Threading::ThreadPoolTimer const*>(&timer));
                return 0;
            }
            catch (...)
            {
                return to_hresult();
            }
        }
    };
};

template <> struct delegate<Windows::System::Threading::TimerElapsedHandler>
{
    template <typename H>
    struct type : implements_delegate<Windows::System::Threading::TimerElapsedHandler, H>
    {
        type(H&& handler) : implements_delegate<Windows::System::Threading::TimerElapsedHandler, H>(std::forward<H>(handler)) {}

        int32_t WINRT_CALL Invoke(void* timer) noexcept final
        {
            try
            {
                (*this)(*reinterpret_cast<Windows::System::Threading::ThreadPoolTimer const*>(&timer));
                return 0;
            }
            catch (...)
            {
                return to_hresult();
            }
        }
    };
};

template <> struct delegate<Windows::System::Threading::WorkItemHandler>
{
    template <typename H>
    struct type : implements_delegate<Windows::System::Threading::WorkItemHandler, H>
    {
        type(H&& handler) : implements_delegate<Windows::System::Threading::WorkItemHandler, H>(std::forward<H>(handler)) {}

        int32_t WINRT_CALL Invoke(void* operation) noexcept final
        {
            try
            {
                (*this)(*reinterpret_cast<Windows::Foundation::IAsyncAction const*>(&operation));
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
struct produce<D, Windows::System::Threading::IThreadPoolStatics> : produce_base<D, Windows::System::Threading::IThreadPoolStatics>
{
    int32_t WINRT_CALL RunAsync(void* handler, void** operation) noexcept final
    {
        try
        {
            *operation = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(RunAsync, WINRT_WRAP(Windows::Foundation::IAsyncAction), Windows::System::Threading::WorkItemHandler const);
            *operation = detach_from<Windows::Foundation::IAsyncAction>(this->shim().RunAsync(*reinterpret_cast<Windows::System::Threading::WorkItemHandler const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL RunWithPriorityAsync(void* handler, Windows::System::Threading::WorkItemPriority priority, void** operation) noexcept final
    {
        try
        {
            *operation = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(RunAsync, WINRT_WRAP(Windows::Foundation::IAsyncAction), Windows::System::Threading::WorkItemHandler const, Windows::System::Threading::WorkItemPriority const);
            *operation = detach_from<Windows::Foundation::IAsyncAction>(this->shim().RunAsync(*reinterpret_cast<Windows::System::Threading::WorkItemHandler const*>(&handler), *reinterpret_cast<Windows::System::Threading::WorkItemPriority const*>(&priority)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL RunWithPriorityAndOptionsAsync(void* handler, Windows::System::Threading::WorkItemPriority priority, Windows::System::Threading::WorkItemOptions options, void** operation) noexcept final
    {
        try
        {
            *operation = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(RunAsync, WINRT_WRAP(Windows::Foundation::IAsyncAction), Windows::System::Threading::WorkItemHandler const, Windows::System::Threading::WorkItemPriority const, Windows::System::Threading::WorkItemOptions const);
            *operation = detach_from<Windows::Foundation::IAsyncAction>(this->shim().RunAsync(*reinterpret_cast<Windows::System::Threading::WorkItemHandler const*>(&handler), *reinterpret_cast<Windows::System::Threading::WorkItemPriority const*>(&priority), *reinterpret_cast<Windows::System::Threading::WorkItemOptions const*>(&options)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::System::Threading::IThreadPoolTimer> : produce_base<D, Windows::System::Threading::IThreadPoolTimer>
{
    int32_t WINRT_CALL get_Period(Windows::Foundation::TimeSpan* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Period, WINRT_WRAP(Windows::Foundation::TimeSpan));
            *value = detach_from<Windows::Foundation::TimeSpan>(this->shim().Period());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Delay(Windows::Foundation::TimeSpan* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Delay, WINRT_WRAP(Windows::Foundation::TimeSpan));
            *value = detach_from<Windows::Foundation::TimeSpan>(this->shim().Delay());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL Cancel() noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Cancel, WINRT_WRAP(void));
            this->shim().Cancel();
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::System::Threading::IThreadPoolTimerStatics> : produce_base<D, Windows::System::Threading::IThreadPoolTimerStatics>
{
    int32_t WINRT_CALL CreatePeriodicTimer(void* handler, Windows::Foundation::TimeSpan period, void** timer) noexcept final
    {
        try
        {
            *timer = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CreatePeriodicTimer, WINRT_WRAP(Windows::System::Threading::ThreadPoolTimer), Windows::System::Threading::TimerElapsedHandler const&, Windows::Foundation::TimeSpan const&);
            *timer = detach_from<Windows::System::Threading::ThreadPoolTimer>(this->shim().CreatePeriodicTimer(*reinterpret_cast<Windows::System::Threading::TimerElapsedHandler const*>(&handler), *reinterpret_cast<Windows::Foundation::TimeSpan const*>(&period)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL CreateTimer(void* handler, Windows::Foundation::TimeSpan delay, void** timer) noexcept final
    {
        try
        {
            *timer = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CreateTimer, WINRT_WRAP(Windows::System::Threading::ThreadPoolTimer), Windows::System::Threading::TimerElapsedHandler const&, Windows::Foundation::TimeSpan const&);
            *timer = detach_from<Windows::System::Threading::ThreadPoolTimer>(this->shim().CreateTimer(*reinterpret_cast<Windows::System::Threading::TimerElapsedHandler const*>(&handler), *reinterpret_cast<Windows::Foundation::TimeSpan const*>(&delay)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL CreatePeriodicTimerWithCompletion(void* handler, Windows::Foundation::TimeSpan period, void* destroyed, void** timer) noexcept final
    {
        try
        {
            *timer = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CreatePeriodicTimer, WINRT_WRAP(Windows::System::Threading::ThreadPoolTimer), Windows::System::Threading::TimerElapsedHandler const&, Windows::Foundation::TimeSpan const&, Windows::System::Threading::TimerDestroyedHandler const&);
            *timer = detach_from<Windows::System::Threading::ThreadPoolTimer>(this->shim().CreatePeriodicTimer(*reinterpret_cast<Windows::System::Threading::TimerElapsedHandler const*>(&handler), *reinterpret_cast<Windows::Foundation::TimeSpan const*>(&period), *reinterpret_cast<Windows::System::Threading::TimerDestroyedHandler const*>(&destroyed)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL CreateTimerWithCompletion(void* handler, Windows::Foundation::TimeSpan delay, void* destroyed, void** timer) noexcept final
    {
        try
        {
            *timer = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CreateTimer, WINRT_WRAP(Windows::System::Threading::ThreadPoolTimer), Windows::System::Threading::TimerElapsedHandler const&, Windows::Foundation::TimeSpan const&, Windows::System::Threading::TimerDestroyedHandler const&);
            *timer = detach_from<Windows::System::Threading::ThreadPoolTimer>(this->shim().CreateTimer(*reinterpret_cast<Windows::System::Threading::TimerElapsedHandler const*>(&handler), *reinterpret_cast<Windows::Foundation::TimeSpan const*>(&delay), *reinterpret_cast<Windows::System::Threading::TimerDestroyedHandler const*>(&destroyed)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

}

WINRT_EXPORT namespace winrt::Windows::System::Threading {

inline Windows::Foundation::IAsyncAction ThreadPool::RunAsync(Windows::System::Threading::WorkItemHandler const& handler)
{
    return impl::call_factory<ThreadPool, Windows::System::Threading::IThreadPoolStatics>([&](auto&& f) { return f.RunAsync(handler); });
}

inline Windows::Foundation::IAsyncAction ThreadPool::RunAsync(Windows::System::Threading::WorkItemHandler const& handler, Windows::System::Threading::WorkItemPriority const& priority)
{
    return impl::call_factory<ThreadPool, Windows::System::Threading::IThreadPoolStatics>([&](auto&& f) { return f.RunAsync(handler, priority); });
}

inline Windows::Foundation::IAsyncAction ThreadPool::RunAsync(Windows::System::Threading::WorkItemHandler const& handler, Windows::System::Threading::WorkItemPriority const& priority, Windows::System::Threading::WorkItemOptions const& options)
{
    return impl::call_factory<ThreadPool, Windows::System::Threading::IThreadPoolStatics>([&](auto&& f) { return f.RunAsync(handler, priority, options); });
}

inline Windows::System::Threading::ThreadPoolTimer ThreadPoolTimer::CreatePeriodicTimer(Windows::System::Threading::TimerElapsedHandler const& handler, Windows::Foundation::TimeSpan const& period)
{
    return impl::call_factory<ThreadPoolTimer, Windows::System::Threading::IThreadPoolTimerStatics>([&](auto&& f) { return f.CreatePeriodicTimer(handler, period); });
}

inline Windows::System::Threading::ThreadPoolTimer ThreadPoolTimer::CreateTimer(Windows::System::Threading::TimerElapsedHandler const& handler, Windows::Foundation::TimeSpan const& delay)
{
    return impl::call_factory<ThreadPoolTimer, Windows::System::Threading::IThreadPoolTimerStatics>([&](auto&& f) { return f.CreateTimer(handler, delay); });
}

inline Windows::System::Threading::ThreadPoolTimer ThreadPoolTimer::CreatePeriodicTimer(Windows::System::Threading::TimerElapsedHandler const& handler, Windows::Foundation::TimeSpan const& period, Windows::System::Threading::TimerDestroyedHandler const& destroyed)
{
    return impl::call_factory<ThreadPoolTimer, Windows::System::Threading::IThreadPoolTimerStatics>([&](auto&& f) { return f.CreatePeriodicTimer(handler, period, destroyed); });
}

inline Windows::System::Threading::ThreadPoolTimer ThreadPoolTimer::CreateTimer(Windows::System::Threading::TimerElapsedHandler const& handler, Windows::Foundation::TimeSpan const& delay, Windows::System::Threading::TimerDestroyedHandler const& destroyed)
{
    return impl::call_factory<ThreadPoolTimer, Windows::System::Threading::IThreadPoolTimerStatics>([&](auto&& f) { return f.CreateTimer(handler, delay, destroyed); });
}

template <typename L> TimerDestroyedHandler::TimerDestroyedHandler(L handler) :
    TimerDestroyedHandler(impl::make_delegate<TimerDestroyedHandler>(std::forward<L>(handler)))
{}

template <typename F> TimerDestroyedHandler::TimerDestroyedHandler(F* handler) :
    TimerDestroyedHandler([=](auto&&... args) { return handler(args...); })
{}

template <typename O, typename M> TimerDestroyedHandler::TimerDestroyedHandler(O* object, M method) :
    TimerDestroyedHandler([=](auto&&... args) { return ((*object).*(method))(args...); })
{}

template <typename O, typename M> TimerDestroyedHandler::TimerDestroyedHandler(com_ptr<O>&& object, M method) :
    TimerDestroyedHandler([o = std::move(object), method](auto&&... args) { return ((*o).*(method))(args...); })
{}

template <typename O, typename M> TimerDestroyedHandler::TimerDestroyedHandler(weak_ref<O>&& object, M method) :
    TimerDestroyedHandler([o = std::move(object), method](auto&&... args) { if (auto s = o.get()) { ((*s).*(method))(args...); } })
{}

inline void TimerDestroyedHandler::operator()(Windows::System::Threading::ThreadPoolTimer const& timer) const
{
    check_hresult((*(impl::abi_t<TimerDestroyedHandler>**)this)->Invoke(get_abi(timer)));
}

template <typename L> TimerElapsedHandler::TimerElapsedHandler(L handler) :
    TimerElapsedHandler(impl::make_delegate<TimerElapsedHandler>(std::forward<L>(handler)))
{}

template <typename F> TimerElapsedHandler::TimerElapsedHandler(F* handler) :
    TimerElapsedHandler([=](auto&&... args) { return handler(args...); })
{}

template <typename O, typename M> TimerElapsedHandler::TimerElapsedHandler(O* object, M method) :
    TimerElapsedHandler([=](auto&&... args) { return ((*object).*(method))(args...); })
{}

template <typename O, typename M> TimerElapsedHandler::TimerElapsedHandler(com_ptr<O>&& object, M method) :
    TimerElapsedHandler([o = std::move(object), method](auto&&... args) { return ((*o).*(method))(args...); })
{}

template <typename O, typename M> TimerElapsedHandler::TimerElapsedHandler(weak_ref<O>&& object, M method) :
    TimerElapsedHandler([o = std::move(object), method](auto&&... args) { if (auto s = o.get()) { ((*s).*(method))(args...); } })
{}

inline void TimerElapsedHandler::operator()(Windows::System::Threading::ThreadPoolTimer const& timer) const
{
    check_hresult((*(impl::abi_t<TimerElapsedHandler>**)this)->Invoke(get_abi(timer)));
}

template <typename L> WorkItemHandler::WorkItemHandler(L handler) :
    WorkItemHandler(impl::make_delegate<WorkItemHandler>(std::forward<L>(handler)))
{}

template <typename F> WorkItemHandler::WorkItemHandler(F* handler) :
    WorkItemHandler([=](auto&&... args) { return handler(args...); })
{}

template <typename O, typename M> WorkItemHandler::WorkItemHandler(O* object, M method) :
    WorkItemHandler([=](auto&&... args) { return ((*object).*(method))(args...); })
{}

template <typename O, typename M> WorkItemHandler::WorkItemHandler(com_ptr<O>&& object, M method) :
    WorkItemHandler([o = std::move(object), method](auto&&... args) { return ((*o).*(method))(args...); })
{}

template <typename O, typename M> WorkItemHandler::WorkItemHandler(weak_ref<O>&& object, M method) :
    WorkItemHandler([o = std::move(object), method](auto&&... args) { if (auto s = o.get()) { ((*s).*(method))(args...); } })
{}

inline void WorkItemHandler::operator()(Windows::Foundation::IAsyncAction const& operation) const
{
    check_hresult((*(impl::abi_t<WorkItemHandler>**)this)->Invoke(get_abi(operation)));
}

}

WINRT_EXPORT namespace std {

template<> struct hash<winrt::Windows::System::Threading::IThreadPoolStatics> : winrt::impl::hash_base<winrt::Windows::System::Threading::IThreadPoolStatics> {};
template<> struct hash<winrt::Windows::System::Threading::IThreadPoolTimer> : winrt::impl::hash_base<winrt::Windows::System::Threading::IThreadPoolTimer> {};
template<> struct hash<winrt::Windows::System::Threading::IThreadPoolTimerStatics> : winrt::impl::hash_base<winrt::Windows::System::Threading::IThreadPoolTimerStatics> {};
template<> struct hash<winrt::Windows::System::Threading::ThreadPool> : winrt::impl::hash_base<winrt::Windows::System::Threading::ThreadPool> {};
template<> struct hash<winrt::Windows::System::Threading::ThreadPoolTimer> : winrt::impl::hash_base<winrt::Windows::System::Threading::ThreadPoolTimer> {};

}
