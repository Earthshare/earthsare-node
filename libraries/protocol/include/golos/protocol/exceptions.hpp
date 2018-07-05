#pragma once

#include <fc/exception/exception.hpp>
#include <golos/protocol/protocol.hpp>

#define GOLOS_ASSERT_MESSAGE(FORMAT, ...) \
    FC_LOG_MESSAGE(error, FORMAT, __VA_ARGS__)

#define GOLOS_CTOR_ASSERT(expr, exception_type, exception_ctor) \
    if (!(expr)) { \
        exception_type _E; \
        exception_ctor(_E); \
        throw _E; \
    }

#define GOLOS_ASSERT(expr, exception_type, FORMAT, ...) \
    FC_MULTILINE_MACRO_BEGIN \
        if (!(expr)) { \
            throw exception_type(GOLOS_ASSERT_MESSAGE(FORMAT, __VA_ARGS__)); \
        } \
    FC_MULTILINE_MACRO_END

#define GOLOS_DECLARE_DERIVED_EXCEPTION_BODY(TYPE, BASE, CODE, WHAT) \
    public: \
        enum code_enum { \
            code_value = CODE, \
        }; \
        TYPE(fc::log_message&& m) \
            : BASE(fc::move(m), CODE, BOOST_PP_STRINGIZE(TYPE), WHAT) {} \
        TYPE() \
            : BASE(CODE, BOOST_PP_STRINGIZE(TYPE), WHAT) {} \
        virtual std::shared_ptr<fc::exception> dynamic_copy_exception() const { \
            return std::make_shared<TYPE>(*this); \
        } \
        virtual NO_RETURN void dynamic_rethrow_exception() const { \
            if (code() == CODE) { \
                throw *this; \
            } else { \
                fc::exception::dynamic_rethrow_exception(); \
            } \
        } \
    protected: \
        TYPE(const BASE& c) \
            : BASE(c) {} \
        explicit TYPE(int64_t code, const std::string& name_value, const std::string& what_value) \
            : BASE(code, name_value, what_value) {} \
        explicit TYPE(fc::log_message&& m, int64_t code, const std::string& name_value, const std::string& what_value) \
            : BASE(std::move(m), code, name_value, what_value) {}

#define GOLOS_DECLARE_DERIVED_EXCEPTION(TYPE, BASE, CODE, WHAT) \
    class TYPE: public BASE { \
        GOLOS_DECLARE_DERIVED_EXCEPTION_BODY(TYPE, BASE, CODE, WHAT) \
    };

#define GOLOS_CHECK_PARAM(PARAM, VALIDATOR) \
    FC_MULTILINE_MACRO_BEGIN \
        try { \
            VALIDATOR; \
        } catch (const fc::exception& e) { \
            FC_THROW_EXCEPTION(golos::invalid_parameter, "Invalid value \"${value}\" for parameter \"${param}\": ${errmsg}", \
                    ("param", FC_STRINGIZE(PARAM)) \
                    ("value", PARAM) \
                    ("errmsg", e.to_string()) \
                    ("error", e)); \
        } \
    FC_MULTILINE_MACRO_END

#define GOLOS_CHECK_VALUE(COND, MSG, ...) \
    GOLOS_ASSERT((COND), golos::invalid_value, MSG, __VA_ARGS__)

namespace golos {
    GOLOS_DECLARE_DERIVED_EXCEPTION(
        golos_exception, fc::exception,
        300000, "golos base exception")


    GOLOS_DECLARE_DERIVED_EXCEPTION(
        insufficient_funds, golos_exception,
        300001, "Account does not have sufficient funds")

    GOLOS_DECLARE_DERIVED_EXCEPTION(
        missing_object, golos_exception,
        300002, "Missing object");

    GOLOS_DECLARE_DERIVED_EXCEPTION(
        invalid_parameter, golos_exception,
        300004, "Invalid parameter value");

    GOLOS_DECLARE_DERIVED_EXCEPTION(
        limit_too_large, invalid_parameter,
        300003, "Exceeded limit value");

    class bandwidth_exception : public golos_exception {
        GOLOS_DECLARE_DERIVED_EXCEPTION_BODY(
            bandwidth_exception, golos_exception,
            400001, "bandwidth exceeded error");
    public:
        enum bandwidth_types {
            post_bandwidth,
            comment_bandwidth,
        };
    };

    class logic_exception : public golos_exception {
        GOLOS_DECLARE_DERIVED_EXCEPTION_BODY(
            logic_exception, golos_exception,
            400000, "business logic error");
    public:
        enum error_types {
            reached_limit_for_pending_withdraw_requests    = 1,
            parent_of_comment_cannot_change,
            parent_perlink_of_comment_cannot_change,
        };

        error_types err_id;
    };
    
    GOLOS_DECLARE_DERIVED_EXCEPTION(
        internal_error, golos_exception,
        300005, "internal error");

    GOLOS_DECLARE_DERIVED_EXCEPTION(
        invalid_value, internal_error,
        300006, "invalid value exception");

} // golos


namespace golos { namespace protocol {
    GOLOS_DECLARE_DERIVED_EXCEPTION(
        transaction_exception, fc::exception,
        3000000, "transaction exception")

    GOLOS_DECLARE_DERIVED_EXCEPTION(
        tx_invalid_operation, transaction_exception,
        3000001, "invalid operation in transaction");

    GOLOS_DECLARE_DERIVED_EXCEPTION(
        tx_missing_authority, transaction_exception,
        3010099, "missing authority");

    class tx_missing_active_auth: public tx_missing_authority {
        GOLOS_DECLARE_DERIVED_EXCEPTION_BODY(
            tx_missing_active_auth, tx_missing_authority,
            3010000, "missing required active authority");
    public:
        std::vector<account_name_type> missing_accounts;
        std::vector<public_key_type> used_signatures;
    };

    class tx_missing_owner_auth: public tx_missing_authority {
        GOLOS_DECLARE_DERIVED_EXCEPTION_BODY(
            tx_missing_owner_auth, tx_missing_authority,
            3020000, "missing required owner authority");
    public:
        std::vector<account_name_type> missing_accounts;
        std::vector<public_key_type> used_signatures;
    };

    class tx_missing_posting_auth: public tx_missing_authority {
        GOLOS_DECLARE_DERIVED_EXCEPTION_BODY(
            tx_missing_posting_auth, tx_missing_authority,
            3030000, "missing required posting authority");
    public:
        std::vector<account_name_type> missing_accounts;
        std::vector<public_key_type> used_signatures;
    };

    class tx_missing_other_auth: public tx_missing_authority {
        GOLOS_DECLARE_DERIVED_EXCEPTION_BODY(
            tx_missing_other_auth, tx_missing_authority,
            3040000, "missing required other authority");
    public:
        std::vector<authority> missing_auths;
    };

    class tx_irrelevant_sig: public transaction_exception {
        GOLOS_DECLARE_DERIVED_EXCEPTION_BODY(
            tx_irrelevant_sig, transaction_exception,
            3050000, "irrelevant signature included");
    public:
        std::vector<public_key_type> unused_signatures;
    };

    class tx_duplicate_sig: public transaction_exception {
        GOLOS_DECLARE_DERIVED_EXCEPTION_BODY(
            tx_duplicate_sig, transaction_exception,
            3060000, "duplicate signature included");
    };

    class tx_irrelevant_approval: public transaction_exception {
        GOLOS_DECLARE_DERIVED_EXCEPTION_BODY(
            tx_irrelevant_approval, transaction_exception,
            3070000, "irrelevant approval included");
    public:
        std::vector<account_name_type> unused_approvals;
    };

} } // golos::protocol

FC_REFLECT_ENUM(golos::logic_exception::error_types, 
        (reached_limit_for_pending_withdraw_requests)
        (parent_of_comment_cannot_change)
        (parent_perlink_of_comment_cannot_change)
);

FC_REFLECT_ENUM(golos::bandwidth_exception::bandwidth_types,
        (post_bandwidth)
        (comment_bandwidth)
);
