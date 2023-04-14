// C++/WinRT v1.0.190111.3

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#pragma once

#include "winrt/base.h"

#include "winrt/Windows.Foundation.h"
#include "winrt/Windows.Foundation.Collections.h"
#include "winrt/impl/Windows.ApplicationModel.Payments.2.h"
#include "winrt/impl/Windows.ApplicationModel.Payments.Provider.2.h"
#include "winrt/Windows.ApplicationModel.Payments.h"

namespace winrt::impl {

template <typename D> Windows::ApplicationModel::Payments::PaymentRequest consume_Windows_ApplicationModel_Payments_Provider_IPaymentAppCanMakePaymentTriggerDetails<D>::Request() const
{
    Windows::ApplicationModel::Payments::PaymentRequest result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Payments::Provider::IPaymentAppCanMakePaymentTriggerDetails)->get_Request(put_abi(result)));
    return result;
}

template <typename D> void consume_Windows_ApplicationModel_Payments_Provider_IPaymentAppCanMakePaymentTriggerDetails<D>::ReportCanMakePaymentResult(Windows::ApplicationModel::Payments::PaymentCanMakePaymentResult const& value) const
{
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Payments::Provider::IPaymentAppCanMakePaymentTriggerDetails)->ReportCanMakePaymentResult(get_abi(value)));
}

template <typename D> Windows::Foundation::IAsyncAction consume_Windows_ApplicationModel_Payments_Provider_IPaymentAppManager<D>::RegisterAsync(param::async_iterable<hstring> const& supportedPaymentMethodIds) const
{
    Windows::Foundation::IAsyncAction result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Payments::Provider::IPaymentAppManager)->RegisterAsync(get_abi(supportedPaymentMethodIds), put_abi(result)));
    return result;
}

template <typename D> Windows::Foundation::IAsyncAction consume_Windows_ApplicationModel_Payments_Provider_IPaymentAppManager<D>::UnregisterAsync() const
{
    Windows::Foundation::IAsyncAction result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Payments::Provider::IPaymentAppManager)->UnregisterAsync(put_abi(result)));
    return result;
}

template <typename D> Windows::ApplicationModel::Payments::Provider::PaymentAppManager consume_Windows_ApplicationModel_Payments_Provider_IPaymentAppManagerStatics<D>::Current() const
{
    Windows::ApplicationModel::Payments::Provider::PaymentAppManager value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Payments::Provider::IPaymentAppManagerStatics)->get_Current(put_abi(value)));
    return value;
}

template <typename D> Windows::ApplicationModel::Payments::PaymentRequest consume_Windows_ApplicationModel_Payments_Provider_IPaymentTransaction<D>::PaymentRequest() const
{
    Windows::ApplicationModel::Payments::PaymentRequest value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Payments::Provider::IPaymentTransaction)->get_PaymentRequest(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_ApplicationModel_Payments_Provider_IPaymentTransaction<D>::PayerEmail() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Payments::Provider::IPaymentTransaction)->get_PayerEmail(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_ApplicationModel_Payments_Provider_IPaymentTransaction<D>::PayerEmail(param::hstring const& value) const
{
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Payments::Provider::IPaymentTransaction)->put_PayerEmail(get_abi(value)));
}

template <typename D> hstring consume_Windows_ApplicationModel_Payments_Provider_IPaymentTransaction<D>::PayerName() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Payments::Provider::IPaymentTransaction)->get_PayerName(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_ApplicationModel_Payments_Provider_IPaymentTransaction<D>::PayerName(param::hstring const& value) const
{
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Payments::Provider::IPaymentTransaction)->put_PayerName(get_abi(value)));
}

template <typename D> hstring consume_Windows_ApplicationModel_Payments_Provider_IPaymentTransaction<D>::PayerPhoneNumber() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Payments::Provider::IPaymentTransaction)->get_PayerPhoneNumber(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_ApplicationModel_Payments_Provider_IPaymentTransaction<D>::PayerPhoneNumber(param::hstring const& value) const
{
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Payments::Provider::IPaymentTransaction)->put_PayerPhoneNumber(get_abi(value)));
}

template <typename D> Windows::Foundation::IAsyncOperation<Windows::ApplicationModel::Payments::PaymentRequestChangedResult> consume_Windows_ApplicationModel_Payments_Provider_IPaymentTransaction<D>::UpdateShippingAddressAsync(Windows::ApplicationModel::Payments::PaymentAddress const& shippingAddress) const
{
    Windows::Foundation::IAsyncOperation<Windows::ApplicationModel::Payments::PaymentRequestChangedResult> result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Payments::Provider::IPaymentTransaction)->UpdateShippingAddressAsync(get_abi(shippingAddress), put_abi(result)));
    return result;
}

template <typename D> Windows::Foundation::IAsyncOperation<Windows::ApplicationModel::Payments::PaymentRequestChangedResult> consume_Windows_ApplicationModel_Payments_Provider_IPaymentTransaction<D>::UpdateSelectedShippingOptionAsync(Windows::ApplicationModel::Payments::PaymentShippingOption const& selectedShippingOption) const
{
    Windows::Foundation::IAsyncOperation<Windows::ApplicationModel::Payments::PaymentRequestChangedResult> result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Payments::Provider::IPaymentTransaction)->UpdateSelectedShippingOptionAsync(get_abi(selectedShippingOption), put_abi(result)));
    return result;
}

template <typename D> Windows::Foundation::IAsyncOperation<Windows::ApplicationModel::Payments::Provider::PaymentTransactionAcceptResult> consume_Windows_ApplicationModel_Payments_Provider_IPaymentTransaction<D>::AcceptAsync(Windows::ApplicationModel::Payments::PaymentToken const& paymentToken) const
{
    Windows::Foundation::IAsyncOperation<Windows::ApplicationModel::Payments::Provider::PaymentTransactionAcceptResult> result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Payments::Provider::IPaymentTransaction)->AcceptAsync(get_abi(paymentToken), put_abi(result)));
    return result;
}

template <typename D> void consume_Windows_ApplicationModel_Payments_Provider_IPaymentTransaction<D>::Reject() const
{
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Payments::Provider::IPaymentTransaction)->Reject());
}

template <typename D> Windows::ApplicationModel::Payments::PaymentRequestCompletionStatus consume_Windows_ApplicationModel_Payments_Provider_IPaymentTransactionAcceptResult<D>::Status() const
{
    Windows::ApplicationModel::Payments::PaymentRequestCompletionStatus value{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Payments::Provider::IPaymentTransactionAcceptResult)->get_Status(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::IAsyncOperation<Windows::ApplicationModel::Payments::Provider::PaymentTransaction> consume_Windows_ApplicationModel_Payments_Provider_IPaymentTransactionStatics<D>::FromIdAsync(param::hstring const& id) const
{
    Windows::Foundation::IAsyncOperation<Windows::ApplicationModel::Payments::Provider::PaymentTransaction> result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Payments::Provider::IPaymentTransactionStatics)->FromIdAsync(get_abi(id), put_abi(result)));
    return result;
}

template <typename D>
struct produce<D, Windows::ApplicationModel::Payments::Provider::IPaymentAppCanMakePaymentTriggerDetails> : produce_base<D, Windows::ApplicationModel::Payments::Provider::IPaymentAppCanMakePaymentTriggerDetails>
{
    int32_t WINRT_CALL get_Request(void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Request, WINRT_WRAP(Windows::ApplicationModel::Payments::PaymentRequest));
            *result = detach_from<Windows::ApplicationModel::Payments::PaymentRequest>(this->shim().Request());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL ReportCanMakePaymentResult(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ReportCanMakePaymentResult, WINRT_WRAP(void), Windows::ApplicationModel::Payments::PaymentCanMakePaymentResult const&);
            this->shim().ReportCanMakePaymentResult(*reinterpret_cast<Windows::ApplicationModel::Payments::PaymentCanMakePaymentResult const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::ApplicationModel::Payments::Provider::IPaymentAppManager> : produce_base<D, Windows::ApplicationModel::Payments::Provider::IPaymentAppManager>
{
    int32_t WINRT_CALL RegisterAsync(void* supportedPaymentMethodIds, void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(RegisterAsync, WINRT_WRAP(Windows::Foundation::IAsyncAction), Windows::Foundation::Collections::IIterable<hstring> const);
            *result = detach_from<Windows::Foundation::IAsyncAction>(this->shim().RegisterAsync(*reinterpret_cast<Windows::Foundation::Collections::IIterable<hstring> const*>(&supportedPaymentMethodIds)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL UnregisterAsync(void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(UnregisterAsync, WINRT_WRAP(Windows::Foundation::IAsyncAction));
            *result = detach_from<Windows::Foundation::IAsyncAction>(this->shim().UnregisterAsync());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::ApplicationModel::Payments::Provider::IPaymentAppManagerStatics> : produce_base<D, Windows::ApplicationModel::Payments::Provider::IPaymentAppManagerStatics>
{
    int32_t WINRT_CALL get_Current(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Current, WINRT_WRAP(Windows::ApplicationModel::Payments::Provider::PaymentAppManager));
            *value = detach_from<Windows::ApplicationModel::Payments::Provider::PaymentAppManager>(this->shim().Current());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::ApplicationModel::Payments::Provider::IPaymentTransaction> : produce_base<D, Windows::ApplicationModel::Payments::Provider::IPaymentTransaction>
{
    int32_t WINRT_CALL get_PaymentRequest(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(PaymentRequest, WINRT_WRAP(Windows::ApplicationModel::Payments::PaymentRequest));
            *value = detach_from<Windows::ApplicationModel::Payments::PaymentRequest>(this->shim().PaymentRequest());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_PayerEmail(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(PayerEmail, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().PayerEmail());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_PayerEmail(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(PayerEmail, WINRT_WRAP(void), hstring const&);
            this->shim().PayerEmail(*reinterpret_cast<hstring const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_PayerName(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(PayerName, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().PayerName());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_PayerName(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(PayerName, WINRT_WRAP(void), hstring const&);
            this->shim().PayerName(*reinterpret_cast<hstring const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_PayerPhoneNumber(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(PayerPhoneNumber, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().PayerPhoneNumber());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_PayerPhoneNumber(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(PayerPhoneNumber, WINRT_WRAP(void), hstring const&);
            this->shim().PayerPhoneNumber(*reinterpret_cast<hstring const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL UpdateShippingAddressAsync(void* shippingAddress, void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(UpdateShippingAddressAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<Windows::ApplicationModel::Payments::PaymentRequestChangedResult>), Windows::ApplicationModel::Payments::PaymentAddress const);
            *result = detach_from<Windows::Foundation::IAsyncOperation<Windows::ApplicationModel::Payments::PaymentRequestChangedResult>>(this->shim().UpdateShippingAddressAsync(*reinterpret_cast<Windows::ApplicationModel::Payments::PaymentAddress const*>(&shippingAddress)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL UpdateSelectedShippingOptionAsync(void* selectedShippingOption, void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(UpdateSelectedShippingOptionAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<Windows::ApplicationModel::Payments::PaymentRequestChangedResult>), Windows::ApplicationModel::Payments::PaymentShippingOption const);
            *result = detach_from<Windows::Foundation::IAsyncOperation<Windows::ApplicationModel::Payments::PaymentRequestChangedResult>>(this->shim().UpdateSelectedShippingOptionAsync(*reinterpret_cast<Windows::ApplicationModel::Payments::PaymentShippingOption const*>(&selectedShippingOption)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL AcceptAsync(void* paymentToken, void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(AcceptAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<Windows::ApplicationModel::Payments::Provider::PaymentTransactionAcceptResult>), Windows::ApplicationModel::Payments::PaymentToken const);
            *result = detach_from<Windows::Foundation::IAsyncOperation<Windows::ApplicationModel::Payments::Provider::PaymentTransactionAcceptResult>>(this->shim().AcceptAsync(*reinterpret_cast<Windows::ApplicationModel::Payments::PaymentToken const*>(&paymentToken)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL Reject() noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Reject, WINRT_WRAP(void));
            this->shim().Reject();
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::ApplicationModel::Payments::Provider::IPaymentTransactionAcceptResult> : produce_base<D, Windows::ApplicationModel::Payments::Provider::IPaymentTransactionAcceptResult>
{
    int32_t WINRT_CALL get_Status(Windows::ApplicationModel::Payments::PaymentRequestCompletionStatus* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Status, WINRT_WRAP(Windows::ApplicationModel::Payments::PaymentRequestCompletionStatus));
            *value = detach_from<Windows::ApplicationModel::Payments::PaymentRequestCompletionStatus>(this->shim().Status());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::ApplicationModel::Payments::Provider::IPaymentTransactionStatics> : produce_base<D, Windows::ApplicationModel::Payments::Provider::IPaymentTransactionStatics>
{
    int32_t WINRT_CALL FromIdAsync(void* id, void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(FromIdAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<Windows::ApplicationModel::Payments::Provider::PaymentTransaction>), hstring const);
            *result = detach_from<Windows::Foundation::IAsyncOperation<Windows::ApplicationModel::Payments::Provider::PaymentTransaction>>(this->shim().FromIdAsync(*reinterpret_cast<hstring const*>(&id)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

}

WINRT_EXPORT namespace winrt::Windows::ApplicationModel::Payments::Provider {

inline Windows::ApplicationModel::Payments::Provider::PaymentAppManager PaymentAppManager::Current()
{
    return impl::call_factory<PaymentAppManager, Windows::ApplicationModel::Payments::Provider::IPaymentAppManagerStatics>([&](auto&& f) { return f.Current(); });
}

inline Windows::Foundation::IAsyncOperation<Windows::ApplicationModel::Payments::Provider::PaymentTransaction> PaymentTransaction::FromIdAsync(param::hstring const& id)
{
    return impl::call_factory<PaymentTransaction, Windows::ApplicationModel::Payments::Provider::IPaymentTransactionStatics>([&](auto&& f) { return f.FromIdAsync(id); });
}

}

WINRT_EXPORT namespace std {

template<> struct hash<winrt::Windows::ApplicationModel::Payments::Provider::IPaymentAppCanMakePaymentTriggerDetails> : winrt::impl::hash_base<winrt::Windows::ApplicationModel::Payments::Provider::IPaymentAppCanMakePaymentTriggerDetails> {};
template<> struct hash<winrt::Windows::ApplicationModel::Payments::Provider::IPaymentAppManager> : winrt::impl::hash_base<winrt::Windows::ApplicationModel::Payments::Provider::IPaymentAppManager> {};
template<> struct hash<winrt::Windows::ApplicationModel::Payments::Provider::IPaymentAppManagerStatics> : winrt::impl::hash_base<winrt::Windows::ApplicationModel::Payments::Provider::IPaymentAppManagerStatics> {};
template<> struct hash<winrt::Windows::ApplicationModel::Payments::Provider::IPaymentTransaction> : winrt::impl::hash_base<winrt::Windows::ApplicationModel::Payments::Provider::IPaymentTransaction> {};
template<> struct hash<winrt::Windows::ApplicationModel::Payments::Provider::IPaymentTransactionAcceptResult> : winrt::impl::hash_base<winrt::Windows::ApplicationModel::Payments::Provider::IPaymentTransactionAcceptResult> {};
template<> struct hash<winrt::Windows::ApplicationModel::Payments::Provider::IPaymentTransactionStatics> : winrt::impl::hash_base<winrt::Windows::ApplicationModel::Payments::Provider::IPaymentTransactionStatics> {};
template<> struct hash<winrt::Windows::ApplicationModel::Payments::Provider::PaymentAppCanMakePaymentTriggerDetails> : winrt::impl::hash_base<winrt::Windows::ApplicationModel::Payments::Provider::PaymentAppCanMakePaymentTriggerDetails> {};
template<> struct hash<winrt::Windows::ApplicationModel::Payments::Provider::PaymentAppManager> : winrt::impl::hash_base<winrt::Windows::ApplicationModel::Payments::Provider::PaymentAppManager> {};
template<> struct hash<winrt::Windows::ApplicationModel::Payments::Provider::PaymentTransaction> : winrt::impl::hash_base<winrt::Windows::ApplicationModel::Payments::Provider::PaymentTransaction> {};
template<> struct hash<winrt::Windows::ApplicationModel::Payments::Provider::PaymentTransactionAcceptResult> : winrt::impl::hash_base<winrt::Windows::ApplicationModel::Payments::Provider::PaymentTransactionAcceptResult> {};

}
