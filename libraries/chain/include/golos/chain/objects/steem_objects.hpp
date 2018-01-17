#pragma once

#include <golos/protocol/authority.hpp>
#include <golos/protocol/operations/steem_operations.hpp>

#include <golos/chain/objects/account_object.hpp>
#include <golos/chain/steem_object_types.hpp>

#include <boost/multi_index/composite_key.hpp>
#include <boost/multiprecision/cpp_int.hpp>


namespace golos {
    namespace chain {

        using golos::protocol::price;
        using golos::protocol::asset_symbol_type;

        typedef fc::fixed_string<> reward_fund_name_type;

        /**
         *  @brief This object is used to track pending requests to convert sbd to steem
         *  @ingroup objects
         */
        class convert_request_object : public object<convert_request_object_type, convert_request_object> {
        public:
            template<typename Constructor, typename Allocator>
            convert_request_object(Constructor &&c, allocator <Allocator> a) {
                c(*this);
            }

            convert_request_object() {
            }

            id_type id;

            account_name_type owner; ///< Account requested a conversion
            uint32_t request_id = 0; ///< Id set by owner, the owner,request_id pair must be unique
            protocol::asset<0, 17, 0> amount; ///< Amount requested for conversion
            time_point_sec conversion_date; ///< At this time the feed_history_median_price * amount
        };


        /**
         * @brief Tracks an escrow
         * @ingroup objects
         */
        class escrow_object : public object<escrow_object_type, escrow_object> {
        public:
            template<typename Constructor, typename Allocator>
            escrow_object(Constructor &&c, allocator <Allocator> a) {
                c(*this);
            }

            escrow_object() {
            }

            id_type id;

            uint32_t escrow_id = 20; ///< Unique escrow identifier
            account_name_type from; ///< Account initiated an escrow transfer
            account_name_type to; ///< Account an escrow transfer was intended for
            account_name_type agent; ///< Escrow transfer agent account
            time_point_sec ratification_deadline;
            time_point_sec escrow_expiration;
            protocol::asset<0, 17, 0> sbd_balance;
            protocol::asset<0, 17, 0> steem_balance;
            protocol::asset<0, 17, 0> pending_fee;
            bool to_approved = false;
            bool agent_approved = false;
            bool disputed = false;

            bool is_approved() const {
                return to_approved && agent_approved;
            }
        };


        /**
         * @brief Tracks savings withdrawal requests
         * @ingroup objects
         */
        class savings_withdraw_object : public object<savings_withdraw_object_type, savings_withdraw_object> {
            savings_withdraw_object() = delete;

        public:
            template<typename Constructor, typename Allocator>
            savings_withdraw_object(Constructor &&c, allocator <Allocator> a)
                    :memo(a) {
                c(*this);
            }

            id_type id;

            account_name_type from; ///< Account requested savings withdrawal from
            account_name_type to; ///< Account requested savings withdrawal to
            shared_string memo; ///< Savings withdrawal memo
            uint32_t request_id = 0; ///< Unique savings withdrawal identifier
            protocol::asset<0, 17, 0> amount; ///< Savings withdrawal asset amount
            time_point_sec complete; ///< Savings withdrawal completion timestamp
        };


        /**
         *  @brief Tracks liquidity rewards
         *  If last_update is greater than 1 week, then volume gets reset to 0
         *
         *  When a user is a maker, their volume increases
         *  When a user is a taker, their volume decreases
         *
         *  Every 1000 blocks, the account that has the highest volume_weight() is paid the maximum of
         *  1000 STEEM or 1000 * virtual_supply / (100*blocks_per_year) aka 10 * virtual_supply / blocks_per_year
         *
         *  After being paid volume gets reset to 0
         *
         *  @note Disabled before hardfork 14
         *
         *  @ingroup objects
         */
        class liquidity_reward_balance_object : public object<liquidity_reward_balance_object_type,
                liquidity_reward_balance_object> {
        public:
            template<typename Constructor, typename Allocator>
            liquidity_reward_balance_object(Constructor &&c, allocator <Allocator> a) {
                c(*this);
            }

            liquidity_reward_balance_object() {
            }

            id_type id;

            account_object::id_type owner;
            int64_t steem_volume = 0;
            int64_t sbd_volume = 0;
            uint128_t weight = 0;

            time_point_sec last_update = fc::time_point_sec::min(); /// Used to decay negative liquidity balances. block num

            /// this is the sort index
            uint128_t volume_weight() const {
                return steem_volume * sbd_volume * is_positive();
            }

            uint128_t min_volume_weight() const {
                return std::min(steem_volume, sbd_volume) * is_positive();
            }

            void update_weight(bool hf9) {
                weight = hf9 ? min_volume_weight() : volume_weight();
            }

            inline int is_positive() const {
                return (steem_volume > 0 && sbd_volume > 0) ? 1 : 0;
            }
        };


        /**
         *  @brief Tracks witnesses feed updates
         *  @ingroup objects
         *  @note This object gets updated once per hour, on the hour
         */
        class feed_history_object : public object<feed_history_object_type, feed_history_object> {
            feed_history_object() = delete;

        public:
            template<typename Constructor, typename Allocator>
            feed_history_object(Constructor &&c, allocator <Allocator> a)
                    :price_history(a.get_segment_manager()) {
                c(*this);
            }

            id_type id;

            price<0, 17, 0> current_median_history; ///< The current median of the price history, used as the base for convert operations
            boost::interprocess::deque<price<0, 17, 0>, allocator<price<0, 17, 0>>> price_history; ///< Tracks this last week of median_feed one per hour
        };

        /**
         * @brief Tracks a route to send withdrawn vesting shares.
         * @ingroup objects
         */
        class withdraw_vesting_route_object : public object<withdraw_vesting_route_object_type,
                withdraw_vesting_route_object> {
        public:
            template<typename Constructor, typename Allocator>
            withdraw_vesting_route_object(Constructor &&c, allocator <Allocator> a) {
                c(*this);
            }

            withdraw_vesting_route_object() {
            }

            id_type id;

            account_object::id_type from_account; ///< Account id to withdraw from
            account_object::id_type to_account; ///< Account if to withdraw to
            uint16_t percent = 0; ///< Vesting withdrawal percent
            bool auto_vest = false;
        };


        /*
         * @brief Tracks declined voting rights
         * @ingroup objects
         */
        class decline_voting_rights_request_object : public object<decline_voting_rights_request_object_type,
                decline_voting_rights_request_object> {
        public:
            template<typename Constructor, typename Allocator>
            decline_voting_rights_request_object(Constructor &&c, allocator <Allocator> a) {
                c(*this);
            }

            decline_voting_rights_request_object() {
            }

            id_type id;

            account_object::id_type account; ///< Account identifier vote declines requested for
            time_point_sec effective_date; ///< Timestamp date vote declines is enabled
        };

        /*
         * @brief Tracks reward funds
         * @ingroup objects
         */
        class reward_fund_object : public object<reward_fund_object_type, reward_fund_object> {
        public:
            template<typename Constructor, typename Allocator>
            reward_fund_object(Constructor &&c, allocator <Allocator> a) {
                c(*this);
            }

            reward_fund_object() {
            }

            reward_fund_object::id_type id; ///< Reward fund identifier
            reward_fund_name_type name; ///< Reward fund name
            protocol::asset<0, 17, 0> reward_balance = protocol::asset<0, 17, 0>(0, STEEM_SYMBOL_NAME); ///< Current reward fund balance in @ref asset<0, 17, 0>
            uint128_t recent_claims = 0; ///< Recent rewards claimed from the particular fund
            time_point_sec last_update; ///< Last time particular fund was modified
            uint128_t content_constant = 0; ///< Particular reward fund content constant (e.g. 2000000000000)
            uint16_t percent_curation_rewards = 0; ///< Curation reward percent this fund provides
            uint16_t percent_content_rewards = 0; ///< Content reward percent this fund provides
        };

        struct by_owner;
        struct by_conversion_date;
        typedef multi_index_container <convert_request_object, indexed_by<ordered_unique < tag < by_id>, member<
                convert_request_object, convert_request_object::id_type, &convert_request_object::id>>,
        ordered_unique <tag<by_conversion_date>, composite_key<convert_request_object, member < convert_request_object,
                time_point_sec, &convert_request_object::conversion_date>, member<convert_request_object,
                convert_request_object::id_type, &convert_request_object::id>>
        >,
        ordered_unique <tag<by_owner>, composite_key<convert_request_object, member < convert_request_object,
                account_name_type, &convert_request_object::owner>, member<convert_request_object, uint32_t,
                &convert_request_object::request_id>>
        >
        >,
        allocator <convert_request_object>
        >
        convert_request_index;

        struct by_owner;
        struct by_volume_weight;

        typedef multi_index_container <liquidity_reward_balance_object, indexed_by<
                ordered_unique < tag < by_id>, member<liquidity_reward_balance_object,
                liquidity_reward_balance_object::id_type, &liquidity_reward_balance_object::id>>,
        ordered_unique <tag<by_owner>, member<liquidity_reward_balance_object, account_object::id_type,
                &liquidity_reward_balance_object::owner>>,
        ordered_unique <tag<by_volume_weight>, composite_key<liquidity_reward_balance_object,
                member < liquidity_reward_balance_object, fc::uint128_t,
                &liquidity_reward_balance_object::weight>, member<liquidity_reward_balance_object,
                account_object::id_type, &liquidity_reward_balance_object::owner>>,
        composite_key_compare <std::greater<fc::uint128_t>, std::less<account_object::id_type>>
        >
        >,
        allocator <liquidity_reward_balance_object>
        >
        liquidity_reward_balance_index;

        typedef multi_index_container <feed_history_object, indexed_by<ordered_unique < tag < by_id>, member<
                feed_history_object, feed_history_object::id_type, &feed_history_object::id>>
        >,
        allocator <feed_history_object>
        >
        feed_history_index;

        struct by_withdraw_route;
        struct by_destination;
        typedef multi_index_container <withdraw_vesting_route_object, indexed_by<ordered_unique < tag < by_id>, member<
                withdraw_vesting_route_object, withdraw_vesting_route_object::id_type,
                &withdraw_vesting_route_object::id>>,
        ordered_unique <tag<by_withdraw_route>, composite_key<withdraw_vesting_route_object,
                member < withdraw_vesting_route_object, account_object::id_type,
                &withdraw_vesting_route_object::from_account>, member<withdraw_vesting_route_object,
                account_object::id_type, &withdraw_vesting_route_object::to_account>>,
        composite_key_compare <std::less<account_object::id_type>, std::less<account_object::id_type>>
        >,
        ordered_unique <tag<by_destination>, composite_key<withdraw_vesting_route_object,
                member < withdraw_vesting_route_object, account_object::id_type,
                &withdraw_vesting_route_object::to_account>, member<withdraw_vesting_route_object,
                withdraw_vesting_route_object::id_type, &withdraw_vesting_route_object::id>>
        >
        >,
        allocator <withdraw_vesting_route_object>
        >
        withdraw_vesting_route_index;

        struct by_from_id;
        struct by_to;
        struct by_agent;
        struct by_ratification_deadline;
        struct by_sbd_balance;
        typedef multi_index_container <escrow_object, indexed_by<ordered_unique < tag < by_id>, member<escrow_object,
                escrow_object::id_type, &escrow_object::id>>,
        ordered_unique <tag<by_from_id>, composite_key<escrow_object, member < escrow_object, account_name_type,
                &escrow_object::from>, member<escrow_object, uint32_t, &escrow_object::escrow_id>>
        >,
        ordered_unique <tag<by_to>, composite_key<escrow_object, member < escrow_object, account_name_type,
                &escrow_object::to>, member<escrow_object, escrow_object::id_type, &escrow_object::id>>
        >,
        ordered_unique <tag<by_agent>, composite_key<escrow_object, member < escrow_object, account_name_type,
                &escrow_object::agent>, member<escrow_object, escrow_object::id_type, &escrow_object::id>>
        >,
        ordered_unique <tag<by_ratification_deadline>, composite_key<escrow_object, const_mem_fun < escrow_object, bool,
                &escrow_object::is_approved>, member<escrow_object, time_point_sec,
                &escrow_object::ratification_deadline>, member<escrow_object, escrow_object::id_type,
                &escrow_object::id>>,
        composite_key_compare <std::less<bool>, std::less<time_point_sec>, std::less<escrow_object::id_type>>
        >,
        ordered_unique<tag<by_sbd_balance>, composite_key<escrow_object, member < escrow_object, protocol::asset < 0,
                17, 0>, &escrow_object::sbd_balance>, member<escrow_object, escrow_object::id_type,
                &escrow_object::id>>,
        composite_key_compare <std::greater<protocol::asset < 0, 17, 0>>, std::less<escrow_object::id_type>>
        >
        >,
        allocator <escrow_object>
        >
        escrow_index;

        struct by_from_rid;
        struct by_to_complete;
        struct by_complete_from_rid;
        typedef multi_index_container <savings_withdraw_object, indexed_by<ordered_unique < tag < by_id>, member<
                savings_withdraw_object, savings_withdraw_object::id_type, &savings_withdraw_object::id>>,
        ordered_unique <tag<by_from_rid>, composite_key<savings_withdraw_object, member < savings_withdraw_object,
                account_name_type, &savings_withdraw_object::from>, member<savings_withdraw_object, uint32_t,
                &savings_withdraw_object::request_id>>
        >,
        ordered_unique <tag<by_to_complete>, composite_key<savings_withdraw_object, member < savings_withdraw_object,
                account_name_type, &savings_withdraw_object::to>, member<savings_withdraw_object, time_point_sec,
                &savings_withdraw_object::complete>, member<savings_withdraw_object, savings_withdraw_object::id_type,
                &savings_withdraw_object::id>>
        >,
        ordered_unique <tag<by_complete_from_rid>, composite_key<savings_withdraw_object,
                member < savings_withdraw_object, time_point_sec, &savings_withdraw_object::complete>, member<
                savings_withdraw_object, account_name_type, &savings_withdraw_object::from>, member<
                savings_withdraw_object, uint32_t, &savings_withdraw_object::request_id>>
        >
        >,
        allocator <savings_withdraw_object>
        >
        savings_withdraw_index;

        struct by_account;
        struct by_effective_date;
        typedef multi_index_container <decline_voting_rights_request_object, indexed_by<
                ordered_unique < tag < by_id>, member<decline_voting_rights_request_object,
                decline_voting_rights_request_object::id_type, &decline_voting_rights_request_object::id>>,
        ordered_unique <tag<by_account>, member<decline_voting_rights_request_object, account_object::id_type,
                &decline_voting_rights_request_object::account>>,
        ordered_unique <tag<by_effective_date>, composite_key<decline_voting_rights_request_object,
                member < decline_voting_rights_request_object, time_point_sec,
                &decline_voting_rights_request_object::effective_date>, member<decline_voting_rights_request_object,
                account_object::id_type, &decline_voting_rights_request_object::account>>,
        composite_key_compare <std::less<time_point_sec>, std::less<account_object::id_type>>
        >
        >,
        allocator <decline_voting_rights_request_object>
        >
        decline_voting_rights_request_index;

        struct by_name;
        typedef multi_index_container <reward_fund_object, indexed_by<ordered_unique < tag < by_id>, member<
                reward_fund_object, reward_fund_object::id_type, &reward_fund_object::id>>,
        ordered_unique <tag<by_name>, member<reward_fund_object, reward_fund_name_type, &reward_fund_object::name>>
        >,
        allocator <reward_fund_object>
        >
        reward_fund_index;
    }
} // golos::chain

#include <golos/chain/objects/comment_object.hpp>
#include <golos/chain/objects/account_object.hpp>


FC_REFLECT((golos::chain::feed_history_object), (id)(current_median_history)(price_history))
CHAINBASE_SET_INDEX_TYPE(golos::chain::feed_history_object, golos::chain::feed_history_index)

FC_REFLECT((golos::chain::convert_request_object), (id)(owner)(request_id)(amount)(conversion_date))
CHAINBASE_SET_INDEX_TYPE(golos::chain::convert_request_object, golos::chain::convert_request_index)

FC_REFLECT((golos::chain::liquidity_reward_balance_object), (id)(owner)(steem_volume)(sbd_volume)(weight)(last_update))
CHAINBASE_SET_INDEX_TYPE(golos::chain::liquidity_reward_balance_object, golos::chain::liquidity_reward_balance_index)

FC_REFLECT((golos::chain::withdraw_vesting_route_object), (id)(from_account)(to_account)(percent)(auto_vest))
CHAINBASE_SET_INDEX_TYPE(golos::chain::withdraw_vesting_route_object, golos::chain::withdraw_vesting_route_index)

FC_REFLECT((golos::chain::savings_withdraw_object), (id)(from)(to)(memo)(request_id)(amount)(complete))
CHAINBASE_SET_INDEX_TYPE(golos::chain::savings_withdraw_object, golos::chain::savings_withdraw_index)

FC_REFLECT((golos::chain::escrow_object),
           (id)(escrow_id)(from)(to)(agent)(ratification_deadline)(escrow_expiration)(sbd_balance)(steem_balance)(
                   pending_fee)(to_approved)(agent_approved)(disputed))
CHAINBASE_SET_INDEX_TYPE(golos::chain::escrow_object, golos::chain::escrow_index)

FC_REFLECT((golos::chain::decline_voting_rights_request_object), (id)(account)(effective_date))
CHAINBASE_SET_INDEX_TYPE(golos::chain::decline_voting_rights_request_object,
                         golos::chain::decline_voting_rights_request_index)

FC_REFLECT((golos::chain::reward_fund_object),
           (id)(name)(reward_balance)(recent_claims)(last_update)(content_constant)(percent_curation_rewards)(
                   percent_content_rewards))
CHAINBASE_SET_INDEX_TYPE(golos::chain::reward_fund_object, golos::chain::reward_fund_index)
