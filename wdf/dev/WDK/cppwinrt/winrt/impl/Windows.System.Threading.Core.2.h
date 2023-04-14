// C++/WinRT v1.0.190111.3

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#pragma once
#include "winrt/impl/Windows.System.Threading.1.h"
#include "winrt/impl/Windows.System.Threading.Core.1.h"

WINRT_EXPORT namespace winrt::Windows::System::Threading::Core {

struct SignalHandler : Windows::Foundation::IUnknown
{
    SignalHandler(std::nullptr_t = nullptr) noexcept {}
    template <typename L> SignalHandler(L lambda);
    template <typename F> SignalHandler(F* function);
    template <typename O, typename M> SignalHandler(O* object, M method);
    template <typename O, typename M> SignalHandler(com_ptr<O>&& object, M method);
    template <typename O, typename M> SignalHandler(weak_ref<O>&& object, M method);
    void operator()(Windows::System::Threading::Core::SignalNotifier const& signalNotifier, bool timedOut) const;
};

}

namespace winrt::impl {

}

WINRT_EXPORT namespace winrt::Windows::System::Threading::Core {

struct WINRT_EBO PreallocatedWorkItem :
    Windows::System::Threading::Core::IPreallocatedWorkItem
{
    PreallocatedWorkItem(std::nullptr_t) noexcept {}
    PreallocatedWorkItem(Windows::System::Threading::WorkItemHandler const& handler);
    PreallocatedWorkItem(Windows::System::Threading::WorkItemHandler const& handler, Windows::System::Threading::WorkItemPriority const& priority);
    PreallocatedWorkItem(Windows::System::Threading::WorkItemHandler const& handler, Windows::System::Threading::WorkItemPriority const& priority, Windows::System::Threading::WorkItemOptions const& options);
};

struct WINRT_EBO SignalNotifier :
    Windows::System::Threading::Core::ISignalNotifier
{
    SignalNotifier(std::nullptr_t) noexcept {}
    static Windows::System::Threading::Core::SignalNotifier AttachToEvent(param::hstring const& name, Windows::System::Threading::Core::SignalHandler const& handler);
    static Windows::System::Threading::Core::SignalNotifier AttachToEvent(param::hstring const& name, Windows::System::Threading::Core::SignalHandler const& handler, Windows::Foundation::TimeSpan const& timeout);
    static Windows::System::Threading::Core::SignalNotifier AttachToSemaphore(param::hstring const& name, Windows::System::Threading::Core::SignalHandler const& handler);
    static Windows::System::Threading::Core::SignalNotifier AttachToSemaphore(param::hstring const& name, Windows::System::Threading::Core::SignalHandler const& handler, Windows::Foundation::TimeSpan const& timeout);
};

}
