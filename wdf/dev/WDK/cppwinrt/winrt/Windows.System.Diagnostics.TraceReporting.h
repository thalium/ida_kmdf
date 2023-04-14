// C++/WinRT v1.0.190111.3

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#pragma once

#include "winrt/base.h"

#include "winrt/Windows.Foundation.h"
#include "winrt/Windows.Foundation.Collections.h"
#include "winrt/impl/Windows.System.Diagnostics.TraceReporting.2.h"
#include "winrt/Windows.System.Diagnostics.h"

namespace winrt::impl {

template <typename D> bool consume_Windows_System_Diagnostics_TraceReporting_IPlatformDiagnosticActionsStatics<D>::IsScenarioEnabled(winrt::guid const& scenarioId) const
{
    bool isActive{};
    check_hresult(WINRT_SHIM(Windows::System::Diagnostics::TraceReporting::IPlatformDiagnosticActionsStatics)->IsScenarioEnabled(get_abi(scenarioId), &isActive));
    return isActive;
}

template <typename D> bool consume_Windows_System_Diagnostics_TraceReporting_IPlatformDiagnosticActionsStatics<D>::TryEscalateScenario(winrt::guid const& scenarioId, Windows::System::Diagnostics::TraceReporting::PlatformDiagnosticEscalationType const& escalationType, param::hstring const& outputDirectory, bool timestampOutputDirectory, bool forceEscalationUpload, param::map_view<hstring, hstring> const& triggers) const
{
    bool result{};
    check_hresult(WINRT_SHIM(Windows::System::Diagnostics::TraceReporting::IPlatformDiagnosticActionsStatics)->TryEscalateScenario(get_abi(scenarioId), get_abi(escalationType), get_abi(outputDirectory), timestampOutputDirectory, forceEscalationUpload, get_abi(triggers), &result));
    return result;
}

template <typename D> Windows::System::Diagnostics::TraceReporting::PlatformDiagnosticActionState consume_Windows_System_Diagnostics_TraceReporting_IPlatformDiagnosticActionsStatics<D>::DownloadLatestSettingsForNamespace(param::hstring const& partner, param::hstring const& feature, bool isScenarioNamespace, bool downloadOverCostedNetwork, bool downloadOverBattery) const
{
    Windows::System::Diagnostics::TraceReporting::PlatformDiagnosticActionState result{};
    check_hresult(WINRT_SHIM(Windows::System::Diagnostics::TraceReporting::IPlatformDiagnosticActionsStatics)->DownloadLatestSettingsForNamespace(get_abi(partner), get_abi(feature), isScenarioNamespace, downloadOverCostedNetwork, downloadOverBattery, put_abi(result)));
    return result;
}

template <typename D> Windows::Foundation::Collections::IVectorView<winrt::guid> consume_Windows_System_Diagnostics_TraceReporting_IPlatformDiagnosticActionsStatics<D>::GetActiveScenarioList() const
{
    Windows::Foundation::Collections::IVectorView<winrt::guid> scenarioIds{ nullptr };
    check_hresult(WINRT_SHIM(Windows::System::Diagnostics::TraceReporting::IPlatformDiagnosticActionsStatics)->GetActiveScenarioList(put_abi(scenarioIds)));
    return scenarioIds;
}

template <typename D> Windows::System::Diagnostics::TraceReporting::PlatformDiagnosticActionState consume_Windows_System_Diagnostics_TraceReporting_IPlatformDiagnosticActionsStatics<D>::ForceUpload(Windows::System::Diagnostics::TraceReporting::PlatformDiagnosticEventBufferLatencies const& latency, bool uploadOverCostedNetwork, bool uploadOverBattery) const
{
    Windows::System::Diagnostics::TraceReporting::PlatformDiagnosticActionState result{};
    check_hresult(WINRT_SHIM(Windows::System::Diagnostics::TraceReporting::IPlatformDiagnosticActionsStatics)->ForceUpload(get_abi(latency), uploadOverCostedNetwork, uploadOverBattery, put_abi(result)));
    return result;
}

template <typename D> Windows::System::Diagnostics::TraceReporting::PlatformDiagnosticTraceSlotState consume_Windows_System_Diagnostics_TraceReporting_IPlatformDiagnosticActionsStatics<D>::IsTraceRunning(Windows::System::Diagnostics::TraceReporting::PlatformDiagnosticTraceSlotType const& slotType, winrt::guid const& scenarioId, uint64_t traceProfileHash) const
{
    Windows::System::Diagnostics::TraceReporting::PlatformDiagnosticTraceSlotState slotState{};
    check_hresult(WINRT_SHIM(Windows::System::Diagnostics::TraceReporting::IPlatformDiagnosticActionsStatics)->IsTraceRunning(get_abi(slotType), get_abi(scenarioId), traceProfileHash, put_abi(slotState)));
    return slotState;
}

template <typename D> Windows::System::Diagnostics::TraceReporting::PlatformDiagnosticTraceRuntimeInfo consume_Windows_System_Diagnostics_TraceReporting_IPlatformDiagnosticActionsStatics<D>::GetActiveTraceRuntime(Windows::System::Diagnostics::TraceReporting::PlatformDiagnosticTraceSlotType const& slotType) const
{
    Windows::System::Diagnostics::TraceReporting::PlatformDiagnosticTraceRuntimeInfo traceRuntimeInfo{ nullptr };
    check_hresult(WINRT_SHIM(Windows::System::Diagnostics::TraceReporting::IPlatformDiagnosticActionsStatics)->GetActiveTraceRuntime(get_abi(slotType), put_abi(traceRuntimeInfo)));
    return traceRuntimeInfo;
}

template <typename D> Windows::Foundation::Collections::IVectorView<Windows::System::Diagnostics::TraceReporting::PlatformDiagnosticTraceInfo> consume_Windows_System_Diagnostics_TraceReporting_IPlatformDiagnosticActionsStatics<D>::GetKnownTraceList(Windows::System::Diagnostics::TraceReporting::PlatformDiagnosticTraceSlotType const& slotType) const
{
    Windows::Foundation::Collections::IVectorView<Windows::System::Diagnostics::TraceReporting::PlatformDiagnosticTraceInfo> traceInfo{ nullptr };
    check_hresult(WINRT_SHIM(Windows::System::Diagnostics::TraceReporting::IPlatformDiagnosticActionsStatics)->GetKnownTraceList(get_abi(slotType), put_abi(traceInfo)));
    return traceInfo;
}

template <typename D> winrt::guid consume_Windows_System_Diagnostics_TraceReporting_IPlatformDiagnosticTraceInfo<D>::ScenarioId() const
{
    winrt::guid value{};
    check_hresult(WINRT_SHIM(Windows::System::Diagnostics::TraceReporting::IPlatformDiagnosticTraceInfo)->get_ScenarioId(put_abi(value)));
    return value;
}

template <typename D> uint64_t consume_Windows_System_Diagnostics_TraceReporting_IPlatformDiagnosticTraceInfo<D>::ProfileHash() const
{
    uint64_t value{};
    check_hresult(WINRT_SHIM(Windows::System::Diagnostics::TraceReporting::IPlatformDiagnosticTraceInfo)->get_ProfileHash(&value));
    return value;
}

template <typename D> bool consume_Windows_System_Diagnostics_TraceReporting_IPlatformDiagnosticTraceInfo<D>::IsExclusive() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::System::Diagnostics::TraceReporting::IPlatformDiagnosticTraceInfo)->get_IsExclusive(&value));
    return value;
}

template <typename D> bool consume_Windows_System_Diagnostics_TraceReporting_IPlatformDiagnosticTraceInfo<D>::IsAutoLogger() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::System::Diagnostics::TraceReporting::IPlatformDiagnosticTraceInfo)->get_IsAutoLogger(&value));
    return value;
}

template <typename D> int64_t consume_Windows_System_Diagnostics_TraceReporting_IPlatformDiagnosticTraceInfo<D>::MaxTraceDurationFileTime() const
{
    int64_t value{};
    check_hresult(WINRT_SHIM(Windows::System::Diagnostics::TraceReporting::IPlatformDiagnosticTraceInfo)->get_MaxTraceDurationFileTime(&value));
    return value;
}

template <typename D> Windows::System::Diagnostics::TraceReporting::PlatformDiagnosticTracePriority consume_Windows_System_Diagnostics_TraceReporting_IPlatformDiagnosticTraceInfo<D>::Priority() const
{
    Windows::System::Diagnostics::TraceReporting::PlatformDiagnosticTracePriority value{};
    check_hresult(WINRT_SHIM(Windows::System::Diagnostics::TraceReporting::IPlatformDiagnosticTraceInfo)->get_Priority(put_abi(value)));
    return value;
}

template <typename D> int64_t consume_Windows_System_Diagnostics_TraceReporting_IPlatformDiagnosticTraceRuntimeInfo<D>::RuntimeFileTime() const
{
    int64_t value{};
    check_hresult(WINRT_SHIM(Windows::System::Diagnostics::TraceReporting::IPlatformDiagnosticTraceRuntimeInfo)->get_RuntimeFileTime(&value));
    return value;
}

template <typename D> int64_t consume_Windows_System_Diagnostics_TraceReporting_IPlatformDiagnosticTraceRuntimeInfo<D>::EtwRuntimeFileTime() const
{
    int64_t value{};
    check_hresult(WINRT_SHIM(Windows::System::Diagnostics::TraceReporting::IPlatformDiagnosticTraceRuntimeInfo)->get_EtwRuntimeFileTime(&value));
    return value;
}

template <typename D>
struct produce<D, Windows::System::Diagnostics::TraceReporting::IPlatformDiagnosticActionsStatics> : produce_base<D, Windows::System::Diagnostics::TraceReporting::IPlatformDiagnosticActionsStatics>
{
    int32_t WINRT_CALL IsScenarioEnabled(winrt::guid scenarioId, bool* isActive) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IsScenarioEnabled, WINRT_WRAP(bool), winrt::guid const&);
            *isActive = detach_from<bool>(this->shim().IsScenarioEnabled(*reinterpret_cast<winrt::guid const*>(&scenarioId)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL TryEscalateScenario(winrt::guid scenarioId, Windows::System::Diagnostics::TraceReporting::PlatformDiagnosticEscalationType escalationType, void* outputDirectory, bool timestampOutputDirectory, bool forceEscalationUpload, void* triggers, bool* result) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(TryEscalateScenario, WINRT_WRAP(bool), winrt::guid const&, Windows::System::Diagnostics::TraceReporting::PlatformDiagnosticEscalationType const&, hstring const&, bool, bool, Windows::Foundation::Collections::IMapView<hstring, hstring> const&);
            *result = detach_from<bool>(this->shim().TryEscalateScenario(*reinterpret_cast<winrt::guid const*>(&scenarioId), *reinterpret_cast<Windows::System::Diagnostics::TraceReporting::PlatformDiagnosticEscalationType const*>(&escalationType), *reinterpret_cast<hstring const*>(&outputDirectory), timestampOutputDirectory, forceEscalationUpload, *reinterpret_cast<Windows::Foundation::Collections::IMapView<hstring, hstring> const*>(&triggers)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL DownloadLatestSettingsForNamespace(void* partner, void* feature, bool isScenarioNamespace, bool downloadOverCostedNetwork, bool downloadOverBattery, Windows::System::Diagnostics::TraceReporting::PlatformDiagnosticActionState* result) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(DownloadLatestSettingsForNamespace, WINRT_WRAP(Windows::System::Diagnostics::TraceReporting::PlatformDiagnosticActionState), hstring const&, hstring const&, bool, bool, bool);
            *result = detach_from<Windows::System::Diagnostics::TraceReporting::PlatformDiagnosticActionState>(this->shim().DownloadLatestSettingsForNamespace(*reinterpret_cast<hstring const*>(&partner), *reinterpret_cast<hstring const*>(&feature), isScenarioNamespace, downloadOverCostedNetwork, downloadOverBattery));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL GetActiveScenarioList(void** scenarioIds) noexcept final
    {
        try
        {
            *scenarioIds = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetActiveScenarioList, WINRT_WRAP(Windows::Foundation::Collections::IVectorView<winrt::guid>));
            *scenarioIds = detach_from<Windows::Foundation::Collections::IVectorView<winrt::guid>>(this->shim().GetActiveScenarioList());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL ForceUpload(Windows::System::Diagnostics::TraceReporting::PlatformDiagnosticEventBufferLatencies latency, bool uploadOverCostedNetwork, bool uploadOverBattery, Windows::System::Diagnostics::TraceReporting::PlatformDiagnosticActionState* result) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ForceUpload, WINRT_WRAP(Windows::System::Diagnostics::TraceReporting::PlatformDiagnosticActionState), Windows::System::Diagnostics::TraceReporting::PlatformDiagnosticEventBufferLatencies const&, bool, bool);
            *result = detach_from<Windows::System::Diagnostics::TraceReporting::PlatformDiagnosticActionState>(this->shim().ForceUpload(*reinterpret_cast<Windows::System::Diagnostics::TraceReporting::PlatformDiagnosticEventBufferLatencies const*>(&latency), uploadOverCostedNetwork, uploadOverBattery));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL IsTraceRunning(Windows::System::Diagnostics::TraceReporting::PlatformDiagnosticTraceSlotType slotType, winrt::guid scenarioId, uint64_t traceProfileHash, Windows::System::Diagnostics::TraceReporting::PlatformDiagnosticTraceSlotState* slotState) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IsTraceRunning, WINRT_WRAP(Windows::System::Diagnostics::TraceReporting::PlatformDiagnosticTraceSlotState), Windows::System::Diagnostics::TraceReporting::PlatformDiagnosticTraceSlotType const&, winrt::guid const&, uint64_t);
            *slotState = detach_from<Windows::System::Diagnostics::TraceReporting::PlatformDiagnosticTraceSlotState>(this->shim().IsTraceRunning(*reinterpret_cast<Windows::System::Diagnostics::TraceReporting::PlatformDiagnosticTraceSlotType const*>(&slotType), *reinterpret_cast<winrt::guid const*>(&scenarioId), traceProfileHash));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL GetActiveTraceRuntime(Windows::System::Diagnostics::TraceReporting::PlatformDiagnosticTraceSlotType slotType, void** traceRuntimeInfo) noexcept final
    {
        try
        {
            *traceRuntimeInfo = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetActiveTraceRuntime, WINRT_WRAP(Windows::System::Diagnostics::TraceReporting::PlatformDiagnosticTraceRuntimeInfo), Windows::System::Diagnostics::TraceReporting::PlatformDiagnosticTraceSlotType const&);
            *traceRuntimeInfo = detach_from<Windows::System::Diagnostics::TraceReporting::PlatformDiagnosticTraceRuntimeInfo>(this->shim().GetActiveTraceRuntime(*reinterpret_cast<Windows::System::Diagnostics::TraceReporting::PlatformDiagnosticTraceSlotType const*>(&slotType)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL GetKnownTraceList(Windows::System::Diagnostics::TraceReporting::PlatformDiagnosticTraceSlotType slotType, void** traceInfo) noexcept final
    {
        try
        {
            *traceInfo = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetKnownTraceList, WINRT_WRAP(Windows::Foundation::Collections::IVectorView<Windows::System::Diagnostics::TraceReporting::PlatformDiagnosticTraceInfo>), Windows::System::Diagnostics::TraceReporting::PlatformDiagnosticTraceSlotType const&);
            *traceInfo = detach_from<Windows::Foundation::Collections::IVectorView<Windows::System::Diagnostics::TraceReporting::PlatformDiagnosticTraceInfo>>(this->shim().GetKnownTraceList(*reinterpret_cast<Windows::System::Diagnostics::TraceReporting::PlatformDiagnosticTraceSlotType const*>(&slotType)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::System::Diagnostics::TraceReporting::IPlatformDiagnosticTraceInfo> : produce_base<D, Windows::System::Diagnostics::TraceReporting::IPlatformDiagnosticTraceInfo>
{
    int32_t WINRT_CALL get_ScenarioId(winrt::guid* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ScenarioId, WINRT_WRAP(winrt::guid));
            *value = detach_from<winrt::guid>(this->shim().ScenarioId());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_ProfileHash(uint64_t* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ProfileHash, WINRT_WRAP(uint64_t));
            *value = detach_from<uint64_t>(this->shim().ProfileHash());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_IsExclusive(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IsExclusive, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().IsExclusive());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_IsAutoLogger(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IsAutoLogger, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().IsAutoLogger());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_MaxTraceDurationFileTime(int64_t* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(MaxTraceDurationFileTime, WINRT_WRAP(int64_t));
            *value = detach_from<int64_t>(this->shim().MaxTraceDurationFileTime());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Priority(Windows::System::Diagnostics::TraceReporting::PlatformDiagnosticTracePriority* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Priority, WINRT_WRAP(Windows::System::Diagnostics::TraceReporting::PlatformDiagnosticTracePriority));
            *value = detach_from<Windows::System::Diagnostics::TraceReporting::PlatformDiagnosticTracePriority>(this->shim().Priority());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::System::Diagnostics::TraceReporting::IPlatformDiagnosticTraceRuntimeInfo> : produce_base<D, Windows::System::Diagnostics::TraceReporting::IPlatformDiagnosticTraceRuntimeInfo>
{
    int32_t WINRT_CALL get_RuntimeFileTime(int64_t* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(RuntimeFileTime, WINRT_WRAP(int64_t));
            *value = detach_from<int64_t>(this->shim().RuntimeFileTime());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_EtwRuntimeFileTime(int64_t* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(EtwRuntimeFileTime, WINRT_WRAP(int64_t));
            *value = detach_from<int64_t>(this->shim().EtwRuntimeFileTime());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

}

WINRT_EXPORT namespace winrt::Windows::System::Diagnostics::TraceReporting {

inline bool PlatformDiagnosticActions::IsScenarioEnabled(winrt::guid const& scenarioId)
{
    return impl::call_factory<PlatformDiagnosticActions, Windows::System::Diagnostics::TraceReporting::IPlatformDiagnosticActionsStatics>([&](auto&& f) { return f.IsScenarioEnabled(scenarioId); });
}

inline bool PlatformDiagnosticActions::TryEscalateScenario(winrt::guid const& scenarioId, Windows::System::Diagnostics::TraceReporting::PlatformDiagnosticEscalationType const& escalationType, param::hstring const& outputDirectory, bool timestampOutputDirectory, bool forceEscalationUpload, param::map_view<hstring, hstring> const& triggers)
{
    return impl::call_factory<PlatformDiagnosticActions, Windows::System::Diagnostics::TraceReporting::IPlatformDiagnosticActionsStatics>([&](auto&& f) { return f.TryEscalateScenario(scenarioId, escalationType, outputDirectory, timestampOutputDirectory, forceEscalationUpload, triggers); });
}

inline Windows::System::Diagnostics::TraceReporting::PlatformDiagnosticActionState PlatformDiagnosticActions::DownloadLatestSettingsForNamespace(param::hstring const& partner, param::hstring const& feature, bool isScenarioNamespace, bool downloadOverCostedNetwork, bool downloadOverBattery)
{
    return impl::call_factory<PlatformDiagnosticActions, Windows::System::Diagnostics::TraceReporting::IPlatformDiagnosticActionsStatics>([&](auto&& f) { return f.DownloadLatestSettingsForNamespace(partner, feature, isScenarioNamespace, downloadOverCostedNetwork, downloadOverBattery); });
}

inline Windows::Foundation::Collections::IVectorView<winrt::guid> PlatformDiagnosticActions::GetActiveScenarioList()
{
    return impl::call_factory<PlatformDiagnosticActions, Windows::System::Diagnostics::TraceReporting::IPlatformDiagnosticActionsStatics>([&](auto&& f) { return f.GetActiveScenarioList(); });
}

inline Windows::System::Diagnostics::TraceReporting::PlatformDiagnosticActionState PlatformDiagnosticActions::ForceUpload(Windows::System::Diagnostics::TraceReporting::PlatformDiagnosticEventBufferLatencies const& latency, bool uploadOverCostedNetwork, bool uploadOverBattery)
{
    return impl::call_factory<PlatformDiagnosticActions, Windows::System::Diagnostics::TraceReporting::IPlatformDiagnosticActionsStatics>([&](auto&& f) { return f.ForceUpload(latency, uploadOverCostedNetwork, uploadOverBattery); });
}

inline Windows::System::Diagnostics::TraceReporting::PlatformDiagnosticTraceSlotState PlatformDiagnosticActions::IsTraceRunning(Windows::System::Diagnostics::TraceReporting::PlatformDiagnosticTraceSlotType const& slotType, winrt::guid const& scenarioId, uint64_t traceProfileHash)
{
    return impl::call_factory<PlatformDiagnosticActions, Windows::System::Diagnostics::TraceReporting::IPlatformDiagnosticActionsStatics>([&](auto&& f) { return f.IsTraceRunning(slotType, scenarioId, traceProfileHash); });
}

inline Windows::System::Diagnostics::TraceReporting::PlatformDiagnosticTraceRuntimeInfo PlatformDiagnosticActions::GetActiveTraceRuntime(Windows::System::Diagnostics::TraceReporting::PlatformDiagnosticTraceSlotType const& slotType)
{
    return impl::call_factory<PlatformDiagnosticActions, Windows::System::Diagnostics::TraceReporting::IPlatformDiagnosticActionsStatics>([&](auto&& f) { return f.GetActiveTraceRuntime(slotType); });
}

inline Windows::Foundation::Collections::IVectorView<Windows::System::Diagnostics::TraceReporting::PlatformDiagnosticTraceInfo> PlatformDiagnosticActions::GetKnownTraceList(Windows::System::Diagnostics::TraceReporting::PlatformDiagnosticTraceSlotType const& slotType)
{
    return impl::call_factory<PlatformDiagnosticActions, Windows::System::Diagnostics::TraceReporting::IPlatformDiagnosticActionsStatics>([&](auto&& f) { return f.GetKnownTraceList(slotType); });
}

}

WINRT_EXPORT namespace std {

template<> struct hash<winrt::Windows::System::Diagnostics::TraceReporting::IPlatformDiagnosticActionsStatics> : winrt::impl::hash_base<winrt::Windows::System::Diagnostics::TraceReporting::IPlatformDiagnosticActionsStatics> {};
template<> struct hash<winrt::Windows::System::Diagnostics::TraceReporting::IPlatformDiagnosticTraceInfo> : winrt::impl::hash_base<winrt::Windows::System::Diagnostics::TraceReporting::IPlatformDiagnosticTraceInfo> {};
template<> struct hash<winrt::Windows::System::Diagnostics::TraceReporting::IPlatformDiagnosticTraceRuntimeInfo> : winrt::impl::hash_base<winrt::Windows::System::Diagnostics::TraceReporting::IPlatformDiagnosticTraceRuntimeInfo> {};
template<> struct hash<winrt::Windows::System::Diagnostics::TraceReporting::PlatformDiagnosticActions> : winrt::impl::hash_base<winrt::Windows::System::Diagnostics::TraceReporting::PlatformDiagnosticActions> {};
template<> struct hash<winrt::Windows::System::Diagnostics::TraceReporting::PlatformDiagnosticTraceInfo> : winrt::impl::hash_base<winrt::Windows::System::Diagnostics::TraceReporting::PlatformDiagnosticTraceInfo> {};
template<> struct hash<winrt::Windows::System::Diagnostics::TraceReporting::PlatformDiagnosticTraceRuntimeInfo> : winrt::impl::hash_base<winrt::Windows::System::Diagnostics::TraceReporting::PlatformDiagnosticTraceRuntimeInfo> {};

}
