#pragma once

#include <fc/fixed_string.hpp>

#include <steemit/protocol/authority.hpp>
#include <steemit/protocol/operations/steem_operations.hpp>

#include <steemit/chain/steem_object_types.hpp>
#include <steemit/chain/witness_objects.hpp>
#include <steemit/chain/shared_authority.hpp>

#include <numeric>

namespace steemit {
    namespace chain {

        using steemit::protocol::authority;

        /**
         * @class account_statistics_object
         * @ingroup object
         * @ingroup implementation
         *
         * This object contains regularly updated statistical data about an account. It is provided for the purpose of
         * separating the account data that changes frequently from the account data that is mostly static, which will
         * minimize the amount of data that must be backed up as part of the undo history everytime a transfer is made.
         */
        class account_statistics_object
                : public object<account_statistics_object_type, account_statistics_object> {
        public:
            account_statistics_object() = delete;

            template<typename Constructor, typename Allocator>
            account_statistics_object(Constructor &&c, allocator<Allocator> a) {
                c(*this);
            };

            id_type id;

            account_name_type owner;

            /**
             * Keep the most recent operation as a root pointer to a linked list of the transaction history.
             */
            account_transaction_history_id_type most_recent_op;
            /** Total operations related to this account. */
            uint32_t total_ops = 0;
            /** Total operations related to this account that has been removed from the database. */
            uint32_t removed_ops = 0;

            /**
             * When calculating votes it is necessary to know how much is stored in orders (and thus unavailable for
             * transfers). Rather than maintaining an index of [asset,owner,order_id] we will simply maintain the running
             * total here and update it every time an order is created or modified.
             */
            share_type total_core_in_orders;

            /**
             * Tracks the total fees paid by this account for the purpose of calculating bulk discounts.
             */
            share_type lifetime_fees_paid;

            /**
             * Tracks the fees paid by this account which have not been disseminated to the various parties that receive
             * them yet (registrar, referrer, lifetime referrer, network, etc). This is used as an optimization to avoid
             * doing massive amounts of uint128 arithmetic on each and every operation.
             *
             * These fees will be paid out as vesting cash-back, and this counter will reset during the maintenance
             * interval.
             */
            share_type pending_fees;
            /**
             * Same as @ref pending_fees, except these fees will be paid out as pre-vested cash-back (immediately
             * available for withdrawal) rather than requiring the normal vesting period.
             */
            share_type pending_vested_fees;

            /// @brief Split up and pay out @ref pending_fees and @ref pending_vested_fees
            void process_fees(const account_object &a, database &d) const;

            /**
             * Core fees are paid into the account_statistics_object by this method
             */
            void pay_fee(share_type core_fee, share_type cashback_vesting_threshold);
        };

        /**
         * @brief Tracks the balance of a single account/asset pair
         * @ingroup object
         *
         * This object is indexed on owner and asset_type so that black swan
         * events in asset_type can be processed quickly.
         */
        class account_balance_object
                : public object<account_balance_object_type, account_balance_object> {
        public:
            account_balance_object() = delete;

            template<typename Constructor, typename Allocator>
            account_balance_object(Constructor &&c, allocator<Allocator> a) {
                c(*this);
            };

            id_type id;

            account_name_type owner;
            asset_symbol_type asset_type;
            share_type balance;

            asset get_balance() const {
                return asset(balance, asset_type);
            }

            void adjust_balance(const asset &delta);
        };

        class account_object
                : public object<account_object_type, account_object> {
        public:
            account_object() = delete;

            template<typename Constructor, typename Allocator>
            account_object(Constructor &&c, allocator<Allocator> a)
                    :json_metadata(a) {
                c(*this);
            };

            id_type id;

            account_name_type name;
            public_key_type memo_key;
            shared_string json_metadata;
            account_name_type proxy;

            time_point_sec last_account_update;

            time_point_sec created;
            bool mined = true;
            bool owner_challenged = false;
            bool active_challenged = false;
            time_point_sec last_owner_proved = time_point_sec::min();
            time_point_sec last_active_proved = time_point_sec::min();
            account_name_type recovery_account;
            account_name_type reset_account = STEEMIT_NULL_ACCOUNT;
            time_point_sec last_account_recovery;
            uint32_t comment_count = 0;
            uint32_t lifetime_vote_count = 0;
            uint32_t post_count = 0;

            bool can_vote = true;
            uint16_t voting_power = STEEMIT_100_PERCENT;   ///< current voting power of this account, it falls after every vote
            time_point_sec last_vote_time; ///< used to increase the voting power of this account the longer it goes without voting.

            asset balance = asset(0, STEEM_SYMBOL);  ///< total liquid shares held by this account
            asset savings_balance = asset(0, STEEM_SYMBOL);  ///< total liquid shares held by this account

            /**
             *  SBD Deposits pay interest based upon the interest rate set by witnesses. The purpose of these
             *  fields is to track the total (time * sbd_balance) that it is held. Then at the appointed time
             *  interest can be paid using the following equation:
             *
             *  interest = interest_rate * sbd_seconds / seconds_per_year
             *
             *  Every time the sbd_balance is updated the sbd_seconds is also updated. If at least
             *  STEEMIT_MIN_COMPOUNDING_INTERVAL_SECONDS has past since sbd_last_interest_payment then
             *  interest is added to sbd_balance.
             *
             *  @defgroup sbd_data SBD Balance Data
             */
            ///@{
            asset sbd_balance = asset(0, SBD_SYMBOL); /// total sbd balance
            uint128_t sbd_seconds; ///< total sbd * how long it has been hel
            time_point_sec sbd_seconds_last_update; ///< the last time the sbd_seconds was updated
            time_point_sec sbd_last_interest_payment; ///< used to pay interest at most once per month


            asset savings_sbd_balance = asset(0, SBD_SYMBOL); /// total sbd balance
            uint128_t savings_sbd_seconds; ///< total sbd * how long it has been hel
            time_point_sec savings_sbd_seconds_last_update; ///< the last time the sbd_seconds was updated
            time_point_sec savings_sbd_last_interest_payment; ///< used to pay interest at most once per month

            uint8_t savings_withdraw_requests = 0;
            ///@}

            share_type curation_rewards = 0;
            share_type posting_rewards = 0;

            asset vesting_shares = asset(0, VESTS_SYMBOL); ///< total vesting shares held by this account, controls its voting power
            asset delegated_vesting_shares = asset(0, VESTS_SYMBOL);
            asset received_vesting_shares = asset(0, VESTS_SYMBOL);

            asset vesting_withdraw_rate = asset(0, VESTS_SYMBOL); ///< at the time this is updated it can be at most vesting_shares/104
            time_point_sec next_vesting_withdrawal = fc::time_point_sec::maximum(); ///< after every withdrawal this is incremented by 1 week
            share_type withdrawn = 0; /// Track how many shares have been withdrawn
            share_type to_withdraw = 0; /// Might be able to look this up with operation history.
            uint16_t withdraw_routes = 0;

            fc::array<share_type, STEEMIT_MAX_PROXY_RECURSION_DEPTH> proxied_vsf_votes;// = std::vector<share_type>( STEEMIT_MAX_PROXY_RECURSION_DEPTH, 0 ); ///< the total VFS votes proxied to this account

            uint16_t witnesses_voted_for = 0;

            time_point_sec last_post;

            /**
             * This is a set of assets which the account is allowed to have.
             * This is utilized to restrict buyback accounts to the assets that trade in their markets.
             * In the future we may expand this to allow accounts to e.g. voluntarily restrict incoming transfers.
             */
            optional<flat_set<asset_symbol_type>> allowed_assets;

            /// This function should be used only when the account votes for a witness directly
            share_type witness_vote_weight() const {
                return std::accumulate(proxied_vsf_votes.begin(),
                        proxied_vsf_votes.end(),
                        vesting_shares.amount);
            }

            share_type proxied_vsf_votes_total() const {
                return std::accumulate(proxied_vsf_votes.begin(),
                        proxied_vsf_votes.end(),
                        share_type());
            }

            asset effective_vesting_shares() const {
                return vesting_shares - delegated_vesting_shares +
                       received_vesting_shares;
            }
        };

        class account_authority_object
                : public object<account_authority_object_type, account_authority_object> {
        public:
            account_authority_object() = delete;

            template<typename Constructor, typename Allocator>
            account_authority_object(Constructor &&c, allocator<Allocator> a)
                    : owner(a), active(a), posting(a) {
                c(*this);
            }

            id_type id;

            account_name_type account;

            shared_authority owner;   ///< used for backup control, can set owner or active
            shared_authority active;  ///< used for all monetary operations, can set active or posting
            shared_authority posting; ///< used for voting and posting

            time_point_sec last_owner_update;
        };

        class account_bandwidth_object
                : public object<account_bandwidth_object_type, account_bandwidth_object> {
        public:
            template<typename Constructor, typename Allocator>
            account_bandwidth_object(Constructor &&c, allocator<Allocator> a) {
                c(*this);
            }

            account_bandwidth_object() {
            }

            id_type id;

            account_name_type account;
            bandwidth_type type;
            share_type average_bandwidth;
            share_type lifetime_bandwidth;
            time_point_sec last_bandwidth_update;
        };

        class vesting_delegation_object
                : public object<vesting_delegation_object_type, vesting_delegation_object> {
        public:
            template<typename Constructor, typename Allocator>
            vesting_delegation_object(Constructor &&c, allocator<Allocator> a) {
                c(*this);
            }

            vesting_delegation_object() {
            }

            id_type id;
            account_name_type delegator;
            account_name_type delegatee;
            asset vesting_shares;
            time_point_sec min_delegation_time;
        };

        class vesting_delegation_expiration_object
                : public object<vesting_delegation_expiration_object_type, vesting_delegation_expiration_object> {
        public:
            template<typename Constructor, typename Allocator>
            vesting_delegation_expiration_object(Constructor &&c, allocator<Allocator> a) {
                c(*this);
            }

            vesting_delegation_expiration_object() {
            }

            id_type id;
            account_name_type delegator;
            asset vesting_shares;
            time_point_sec expiration;
        };

        class owner_authority_history_object
                : public object<owner_authority_history_object_type, owner_authority_history_object> {
        public:
            owner_authority_history_object() = delete;

            template<typename Constructor, typename Allocator>
            owner_authority_history_object(Constructor &&c, allocator<Allocator> a)
                    :previous_owner_authority(shared_authority::allocator_type(a.get_segment_manager())) {
                c(*this);
            }

            id_type id;

            account_name_type account;
            shared_authority previous_owner_authority;
            time_point_sec last_valid_time;
        };

        class account_recovery_request_object
                : public object<account_recovery_request_object_type, account_recovery_request_object> {
        public:
            account_recovery_request_object() = delete;

            template<typename Constructor, typename Allocator>
            account_recovery_request_object(Constructor &&c, allocator<Allocator> a)
                    :new_owner_authority(shared_authority::allocator_type(a.get_segment_manager())) {
                c(*this);
            }

            id_type id;

            account_name_type account_to_recover;
            shared_authority new_owner_authority;
            time_point_sec expires;
        };

        class change_recovery_account_request_object
                : public object<change_recovery_account_request_object_type, change_recovery_account_request_object> {
        public:
            template<typename Constructor, typename Allocator>
            change_recovery_account_request_object(Constructor &&c, allocator<Allocator> a) {
                c(*this);
            }

            id_type id;

            account_name_type account_to_recover;
            account_name_type recovery_account;
            time_point_sec effective_on;
        };

        /**
    *  @brief This secondary index will allow a reverse lookup of all accounts that a particular key or account
    *  is an potential signing authority.
    */
        class account_member_index : public chainbase::secondary_index {
        public:
            virtual void object_inserted(const object &obj) override;

            virtual void object_removed(const object &obj) override;

            virtual void about_to_modify(const object &before) override;

            virtual void object_modified(const object &after) override;


            /** given an account or key, map it to the set of accounts that reference it in an active or owner authority */
            map<account_name_type, set<account_name_type>> account_to_account_memberships;
            map<public_key_type, set<account_name_type>> account_to_key_memberships;
            /** some accounts use address authorities in the genesis block */
            map<address, set<account_name_type>> account_to_address_memberships;


        protected:
            set<account_name_type> get_account_members(const account_object &a) const;

            set<public_key_type> get_key_members(const account_object &a) const;

            set<address> get_address_members(const account_object &a) const;

            set<account_name_type> before_account_members;
            set<public_key_type> before_key_members;
            set<address> before_address_members;
        };


        /**
         *  @brief This secondary index will allow a reverse lookup of all accounts that have been referred by
         *  a particular account.
         */
        class account_referrer_index : public chainbase::secondary_index {
        public:
            virtual void object_inserted(const object &obj) override;

            virtual void object_removed(const object &obj) override;

            virtual void about_to_modify(const object &before) override;

            virtual void object_modified(const object &after) override;

            /** maps the referrer to the set of accounts that they have referred */
            map<account_name_type, set<account_name_type>> referred_by;
        };

        struct by_account_asset;
        struct by_asset_balance;
        /**
         * @ingroup object_index
         */
        typedef multi_index_container<
                account_balance_object,
                indexed_by<
                        ordered_unique<tag<by_id>, member<account_balance_object, account_balance_object::id_type, &account_balance_object::id>>,
                        ordered_unique<tag<by_account_asset>,
                                composite_key<
                                        account_balance_object,
                                        member<account_balance_object, account_name_type, &account_balance_object::owner>,
                                        member<account_balance_object, asset_symbol_type, &account_balance_object::asset_type>
                                >
                        >,
                        ordered_unique<tag<by_asset_balance>,
                                composite_key<
                                        account_balance_object,
                                        member<account_balance_object, asset_symbol_type, &account_balance_object::asset_type>,
                                        member<account_balance_object, share_type, &account_balance_object::balance>,
                                        member<account_balance_object, account_name_type, &account_balance_object::owner>
                                >,
                                composite_key_compare<
                                        std::less<asset_symbol_type>,
                                        std::greater<share_type>,
                                        std::less<account_name_type>
                                >
                        >
                >
        > account_balance_object_multi_index_type;

        struct by_name;
        struct by_proxy;
        struct by_last_post;
        struct by_next_vesting_withdrawal;
        struct by_steem_balance;
        struct by_smp_balance;
        struct by_smd_balance;
        struct by_post_count;
        struct by_vote_count;

        /**
         * @ingroup object_index
         */
        typedef multi_index_container<
                account_object,
                indexed_by<
                        ordered_unique<tag<by_id>,
                                member<account_object, account_name_type, &account_object::id>>,
                        ordered_unique<tag<by_name>,
                                member<account_object, account_name_type, &account_object::name>,
                                protocol::string_less>,
                        ordered_unique<tag<by_proxy>,
                                composite_key<account_object,
                                        member<account_object, account_name_type, &account_object::proxy>,
                                        member<account_object, account_name_type, &account_object::id>
                                > /// composite key by proxy
                        >,
                        ordered_unique<tag<by_next_vesting_withdrawal>,
                                composite_key<account_object,
                                        member<account_object, time_point_sec, &account_object::next_vesting_withdrawal>,
                                        member<account_object, account_name_type, &account_object::id>
                                > /// composite key by_next_vesting_withdrawal
                        >,
                        ordered_unique<tag<by_last_post>,
                                composite_key<account_object,
                                        member<account_object, time_point_sec, &account_object::last_post>,
                                        member<account_object, account_name_type, &account_object::id>
                                >,
                                composite_key_compare<std::greater<time_point_sec>, std::less<account_name_type>>
                        >,
                        ordered_unique<tag<by_steem_balance>,
                                composite_key<account_object,
                                        member<account_object, asset, &account_object::balance>,
                                        member<account_object, account_name_type, &account_object::id>
                                >,
                                composite_key_compare<std::greater<asset>, std::less<account_name_type>>
                        >,
                        ordered_unique<tag<by_smp_balance>,
                                composite_key<account_object,
                                        member<account_object, asset, &account_object::vesting_shares>,
                                        member<account_object, account_name_type, &account_object::id>
                                >,
                                composite_key_compare<std::greater<asset>, std::less<account_name_type>>
                        >,
                        ordered_unique<tag<by_smd_balance>,
                                composite_key<account_object,
                                        member<account_object, asset, &account_object::sbd_balance>,
                                        member<account_object, account_name_type, &account_object::id>
                                >,
                                composite_key_compare<std::greater<asset>, std::less<account_name_type>>
                        >,
                        ordered_unique<tag<by_post_count>,
                                composite_key<account_object,
                                        member<account_object, uint32_t, &account_object::post_count>,
                                        member<account_object, account_name_type, &account_object::id>
                                >,
                                composite_key_compare<std::greater<uint32_t>, std::less<account_name_type>>
                        >,
                        ordered_unique<tag<by_vote_count>,
                                composite_key<account_object,
                                        member<account_object, uint32_t, &account_object::lifetime_vote_count>,
                                        member<account_object, account_name_type, &account_object::id>
                                >,
                                composite_key_compare<std::greater<uint32_t>, std::less<account_name_type>>
                        >
                >,
                allocator<account_object>
        > account_index;

        struct by_account;
        struct by_last_valid;

        typedef multi_index_container<
                owner_authority_history_object,
                indexed_by<
                        ordered_unique<tag<by_id>,
                                member<owner_authority_history_object, owner_authority_history_id_type, &owner_authority_history_object::id>>,
                        ordered_unique<tag<by_account>,
                                composite_key<owner_authority_history_object,
                                        member<owner_authority_history_object, account_name_type, &owner_authority_history_object::account>,
                                        member<owner_authority_history_object, time_point_sec, &owner_authority_history_object::last_valid_time>,
                                        member<owner_authority_history_object, owner_authority_history_id_type, &owner_authority_history_object::id>
                                >,
                                composite_key_compare<
                                        std::less<account_name_type>, std::less<time_point_sec>, std::less<owner_authority_history_id_type>>
                        >
                >,
                allocator<owner_authority_history_object>
        > owner_authority_history_index;

        struct by_last_owner_update;

        typedef multi_index_container<
                account_authority_object,
                indexed_by<
                        ordered_unique<tag<by_id>,
                                member<account_authority_object, account_authority_id_type, &account_authority_object::id>>,
                        ordered_unique<tag<by_account>,
                                composite_key<account_authority_object,
                                        member<account_authority_object, account_name_type, &account_authority_object::account>,
                                        member<account_authority_object, account_authority_id_type, &account_authority_object::id>
                                >,
                                composite_key_compare<
                                        std::less<account_name_type>, std::less<account_authority_id_type>>
                        >,
                        ordered_unique<tag<by_last_owner_update>,
                                composite_key<account_authority_object,
                                        member<account_authority_object, time_point_sec, &account_authority_object::last_owner_update>,
                                        member<account_authority_object, account_authority_id_type, &account_authority_object::id>
                                >,
                                composite_key_compare<std::greater<time_point_sec>, std::less<account_authority_id_type>>
                        >
                >,
                allocator<account_authority_object>
        > account_authority_index;


        struct by_account_bandwidth_type;

        typedef multi_index_container<
                account_bandwidth_object,
                indexed_by<
                        ordered_unique<tag<by_id>,
                                member<account_bandwidth_object, account_bandwidth_id_type, &account_bandwidth_object::id>>,
                        ordered_unique<tag<by_account_bandwidth_type>,
                                composite_key<account_bandwidth_object,
                                        member<account_bandwidth_object, account_name_type, &account_bandwidth_object::account>,
                                        member<account_bandwidth_object, bandwidth_type, &account_bandwidth_object::type>
                                >
                        >
                >,
                allocator<account_bandwidth_object>
        > account_bandwidth_index;

        struct by_delegation;

        typedef multi_index_container<
                vesting_delegation_object,
                indexed_by<
                        ordered_unique<tag<by_id>,
                                member<vesting_delegation_object, vesting_delegation_id_type, &vesting_delegation_object::id>>,
                        ordered_unique<tag<by_delegation>,
                                composite_key<vesting_delegation_object,
                                        member<vesting_delegation_object, account_name_type, &vesting_delegation_object::delegator>,
                                        member<vesting_delegation_object, account_name_type, &vesting_delegation_object::delegatee>
                                >,
                                composite_key_compare<protocol::string_less, protocol::string_less>
                        >
                >,
                allocator<vesting_delegation_object>
        > vesting_delegation_index;

        struct by_expiration;
        struct by_account_expiration;

        typedef multi_index_container<
                vesting_delegation_expiration_object,
                indexed_by<
                        ordered_unique<tag<by_id>,
                                member<vesting_delegation_expiration_object, vesting_delegation_expiration_id_type, &vesting_delegation_expiration_object::id>>,
                        ordered_unique<tag<by_expiration>,
                                composite_key<vesting_delegation_expiration_object,
                                        member<vesting_delegation_expiration_object, time_point_sec, &vesting_delegation_expiration_object::expiration>,
                                        member<vesting_delegation_expiration_object, vesting_delegation_expiration_id_type, &vesting_delegation_expiration_object::id>
                                >,
                                composite_key_compare<std::less<time_point_sec>, std::less<vesting_delegation_expiration_id_type>>
                        >,
                        ordered_unique<tag<by_account_expiration>,
                                composite_key<vesting_delegation_expiration_object,
                                        member<vesting_delegation_expiration_object, account_name_type, &vesting_delegation_expiration_object::delegator>,
                                        member<vesting_delegation_expiration_object, time_point_sec, &vesting_delegation_expiration_object::expiration>,
                                        member<vesting_delegation_expiration_object, vesting_delegation_expiration_id_type, &vesting_delegation_expiration_object::id>
                                >,
                                composite_key_compare<std::less<account_name_type>, std::less<time_point_sec>, std::less<vesting_delegation_expiration_id_type>>

                        >
                >,
                allocator<vesting_delegation_expiration_object>
        > vesting_delegation_expiration_index;

        struct by_expiration;

        typedef multi_index_container<
                account_recovery_request_object,
                indexed_by<
                        ordered_unique<tag<by_id>,
                                member<account_recovery_request_object, account_recovery_request_id_type, &account_recovery_request_object::id>>,
                        ordered_unique<tag<by_account>,
                                composite_key<account_recovery_request_object,
                                        member<account_recovery_request_object, account_name_type, &account_recovery_request_object::account_to_recover>,
                                        member<account_recovery_request_object, account_recovery_request_id_type, &account_recovery_request_object::id>
                                >,
                                composite_key_compare<
                                        std::less<account_name_type>, std::less<account_recovery_request_id_type>>
                        >,
                        ordered_unique<tag<by_expiration>,
                                composite_key<account_recovery_request_object,
                                        member<account_recovery_request_object, time_point_sec, &account_recovery_request_object::expires>,
                                        member<account_recovery_request_object, account_recovery_request_id_type, &account_recovery_request_object::id>
                                >,
                                composite_key_compare<std::less<time_point_sec>, std::less<account_recovery_request_id_type>>
                        >
                >,
                allocator<account_recovery_request_object>
        > account_recovery_request_index;

        struct by_effective_date;

        typedef multi_index_container<
                change_recovery_account_request_object,
                indexed_by<
                        ordered_unique<tag<by_id>,
                                member<change_recovery_account_request_object, change_recovery_account_request_id_type, &change_recovery_account_request_object::id>>,
                        ordered_unique<tag<by_account>,
                                composite_key<
                                        change_recovery_account_request_object,
                                        member<change_recovery_account_request_object, account_name_type, &change_recovery_account_request_object::account_to_recover>,
                                        member<change_recovery_account_request_object, change_recovery_account_request_id_type, &change_recovery_account_request_object::id>
                                >,
                                composite_key_compare<
                                        std::less<account_name_type>, std::less<change_recovery_account_request_id_type>>
                        >,
                        ordered_unique<tag<by_effective_date>,
                                composite_key<change_recovery_account_request_object,
                                        member<change_recovery_account_request_object, time_point_sec, &change_recovery_account_request_object::effective_on>,
                                        member<change_recovery_account_request_object, change_recovery_account_request_id_type, &change_recovery_account_request_object::id>
                                >,
                                composite_key_compare<std::less<time_point_sec>, std::less<change_recovery_account_request_id_type>>
                        >
                >,
                allocator<change_recovery_account_request_object>
        > change_recovery_account_request_index;
    }
}

FC_REFLECT(steemit::chain::account_object,
        (id)(name)(memo_key)(json_metadata)(proxy)(last_account_update)
                (created)(mined)
                (owner_challenged)(active_challenged)(last_owner_proved)(last_active_proved)(recovery_account)(last_account_recovery)(reset_account)
                (comment_count)(lifetime_vote_count)(post_count)(can_vote)(voting_power)(last_vote_time)
                (balance)
                (savings_balance)
                (sbd_balance)(sbd_seconds)(sbd_seconds_last_update)(sbd_last_interest_payment)
                (savings_sbd_balance)(savings_sbd_seconds)(savings_sbd_seconds_last_update)(savings_sbd_last_interest_payment)(savings_withdraw_requests)
                (vesting_shares)(delegated_vesting_shares)(received_vesting_shares)
                (vesting_withdraw_rate)(next_vesting_withdrawal)(withdrawn)(to_withdraw)(withdraw_routes)
                (curation_rewards)
                (posting_rewards)
                (proxied_vsf_votes)(witnesses_voted_for)
                (last_post)
)
CHAINBASE_SET_INDEX_TYPE(steemit::chain::account_object, steemit::chain::account_index)

FC_REFLECT(steemit::chain::account_authority_object,
        (id)(account)(owner)(active)(posting)(last_owner_update)
)
CHAINBASE_SET_INDEX_TYPE(steemit::chain::account_authority_object, steemit::chain::account_authority_index)

FC_REFLECT(steemit::chain::account_bandwidth_object,
        (id)(account)(type)(average_bandwidth)(lifetime_bandwidth)(last_bandwidth_update))
CHAINBASE_SET_INDEX_TYPE(steemit::chain::account_bandwidth_object, steemit::chain::account_bandwidth_index)

FC_REFLECT(steemit::chain::vesting_delegation_object,
        (id)(delegator)(delegatee)(vesting_shares)(min_delegation_time))
CHAINBASE_SET_INDEX_TYPE(steemit::chain::vesting_delegation_object, steemit::chain::vesting_delegation_index)

FC_REFLECT(steemit::chain::vesting_delegation_expiration_object,
        (id)(delegator)(vesting_shares)(expiration))

CHAINBASE_SET_INDEX_TYPE(steemit::chain::vesting_delegation_expiration_object, steemit::chain::vesting_delegation_expiration_index)

FC_REFLECT(steemit::chain::owner_authority_history_object,
        (id)(account)(previous_owner_authority)(last_valid_time)
)
CHAINBASE_SET_INDEX_TYPE(steemit::chain::owner_authority_history_object, steemit::chain::owner_authority_history_index)

FC_REFLECT(steemit::chain::account_recovery_request_object,
        (id)(account_to_recover)(new_owner_authority)(expires)
)
CHAINBASE_SET_INDEX_TYPE(steemit::chain::account_recovery_request_object, steemit::chain::account_recovery_request_index)

FC_REFLECT(steemit::chain::change_recovery_account_request_object,
        (id)(account_to_recover)(recovery_account)(effective_on)
)
CHAINBASE_SET_INDEX_TYPE(steemit::chain::change_recovery_account_request_object, steemit::chain::change_recovery_account_request_index)
