#pragma once

#include <golos/plugins/database_api/applied_operation.hpp>
#include <golos/chain/objects/global_property_object.hpp>
#include <golos/chain/objects/account_object.hpp>
#include <golos/chain/objects/steem_objects.hpp>
#include <golos/plugins/database_api/api_objects/comment_api_object.hpp>
#include <golos/plugins/database_api/api_objects/account_api_object.hpp>
#include <golos/plugins/database_api/api_objects/tag_api_object.hpp>
#include <golos/plugins/database_api/api_objects/category_api_object.hpp>
#include <golos/plugins/database_api/api_objects/witness_api_object.hpp>
#include "forward.hpp"

namespace golos {
    namespace plugins {
        namespace database_api {
            using std::string;
            using std::vector;
            using namespace protocol;
            using namespace chain;
            typedef golos::chain::limit_order_object limit_order_api_obj;

            struct extended_limit_order : public limit_order_api_obj {
                extended_limit_order() {
                }

                extended_limit_order(const limit_order_object &o) : limit_order_api_obj(o) {
                }

                double real_price = 0;
                bool rewarded = false;
            };

            struct discussion_index {
                string category;    /// category by which everything is filtered
                vector<string> trending;    /// trending posts over the last 24 hours
                vector<string> payout;      /// pending posts by payout
                vector<string> payout_comments; /// pending comments by payout
                vector<string> trending30;  /// pending lifetime payout
                vector<string> created;     /// creation date
                vector<string> responses;   /// creation date
                vector<string> updated;     /// creation date
                vector<string> active;      /// last update or reply
                vector<string> votes;       /// last update or reply
                vector<string> cashout;     /// last update or reply
                vector<string> maturing;    /// about to be paid out
                vector<string> best;        /// total lifetime payout
                vector<string> hot;         /// total lifetime payout
                vector<string> promoted;    /// pending lifetime payout
            };

            struct category_index {
                vector<string> active;   /// recent activity
                vector<string> recent;   /// recently created
                vector<string> best;     /// total lifetime payout
            };

            struct tag_index {
                vector<string> trending; /// pending payouts
            };

            struct vote_state {
                string voter;
                uint64_t weight = 0;
                int64_t rshares = 0;
                int16_t percent = 0;
                share_type reputation = 0;
                time_point_sec time;
            };

            struct account_vote {
                string authorperm;
                uint64_t weight = 0;
                int64_t rshares = 0;
                int16_t percent = 0;
                time_point_sec time;
            };

            struct discussion : public comment_api_object {
                discussion(const golos::chain::comment_object &o) : comment_api_object(o) {
                }

                discussion() {
                }

                string url; /// /category/@rootauthor/root_permlink#author/permlink
                string root_title;
                asset<0, 17, 0> pending_payout_value = asset<0, 17, 0>(0, SBD_SYMBOL_NAME); ///< sbd
                asset<0, 17, 0> total_pending_payout_value = asset<0, 17, 0>(0,
                                                                             SBD_SYMBOL_NAME); ///< sbd including replies
                vector<vote_state> active_votes;
                vector<string> replies; ///< author/slug mapping
                share_type author_reputation = 0;
                asset<0, 17, 0> promoted = asset<0, 17, 0>(0, SBD_SYMBOL_NAME);
                uint32_t body_length = 0;
                vector<account_name_type> reblogged_by;
                optional<account_name_type> first_reblogged_by;
                optional<time_point_sec> first_reblogged_on;
            };

            /**
             *  Convert's vesting shares
             */
            struct extended_account : public account_api_object {
                extended_account() {
                }

                extended_account(const account_object &a, const golos::chain::database &db) : account_api_object(a, db) {
                }

                asset<0, 17, 0> vesting_balance; /// convert vesting_shares to vesting steem
                share_type reputation = 0;
                std::map<uint64_t, applied_operation> transfer_history; /// transfer to/from vesting
                std::map<uint64_t, applied_operation> market_history; /// limit order / cancel / fill
                std::map<uint64_t, applied_operation> post_history;
                std::map<uint64_t, applied_operation> vote_history;
                std::map<uint64_t, applied_operation> other_history;
                std::set<string> witness_votes;
                std::vector<std::pair<std::string, uint32_t>> tags_usage;
                std::vector<std::pair<account_name_type, uint32_t>> guest_bloggers;

                optional<std::map<uint32_t, extended_limit_order>> open_orders;
                optional<std::vector<account_balance_object>> balances;
                optional<std::vector<call_order_object>> call_orders;
                optional<std::vector<force_settlement_object>> settle_orders;
                optional<std::vector<asset_symbol_type>> assets;
                optional<std::vector<std::string>> comments; /// permlinks for this user
                optional<std::vector<std::string>> blog; /// blog posts for this user
                optional<std::vector<std::string>> feed; /// feed posts for this user
                optional<std::vector<std::string>> recent_replies; /// blog posts for this user
                std::map<std::string, std::vector<std::string>> blog_category; /// blog posts for this user
                optional<std::vector<std::string>> recommended; /// posts recommened for this user
            };


            struct candle_stick {
                time_point_sec open_time;
                uint32_t period = 0;
                double high = 0;
                double low = 0;
                double open = 0;
                double close = 0;
                double steem_volume = 0;
                double dollar_volume = 0;
            };

            struct order_history_item {
                time_point_sec time;
                string type; // buy or sell
                asset<0, 17, 0> sbd_quantity;
                asset<0, 17, 0> steem_quantity;
                double real_price = 0;
            };

            struct market {
                vector<extended_limit_order> bids;
                vector<extended_limit_order> asks;
                vector<order_history_item> history;
                vector<int> available_candlesticks;
                vector<int> available_zoom;
                int current_candlestick = 0;
                int current_zoom = 0;
                vector<candle_stick> price_history;
            };

        }
    }
}

FC_REFLECT_DERIVED((golos::plugins::database_api::extended_account),
                   ((golos::plugins::database_api::account_api_object)),
                   (vesting_balance)(reputation)(transfer_history)(market_history)(post_history)(vote_history)(
                           other_history)(witness_votes)(tags_usage)(guest_bloggers)(open_orders)(comments)(feed)(blog)(
                           recent_replies)(blog_category)(recommended)(balances))


FC_REFLECT((golos::plugins::database_api::vote_state), (voter)(weight)(rshares)(percent)(reputation)(time));
FC_REFLECT((golos::plugins::database_api::account_vote), (authorperm)(weight)(rshares)(percent)(time));

FC_REFLECT((golos::plugins::database_api::discussion_index),
           (category)(trending)(payout)(payout_comments)(trending30)(updated)(created)(responses)(active)(votes)(
                   maturing)(best)(hot)(promoted)(cashout))
FC_REFLECT((golos::plugins::database_api::category_index), (active)(recent)(best))
FC_REFLECT((golos::plugins::database_api::tag_index), (trending))
FC_REFLECT_DERIVED((golos::plugins::database_api::discussion), ((golos::plugins::database_api::comment_api_object)),
                   (url)(root_title)(pending_payout_value)(total_pending_payout_value)(active_votes)(replies)(
                           author_reputation)(promoted)(body_length)(reblogged_by)(first_reblogged_by)(
                           first_reblogged_on))

FC_REFLECT_DERIVED((golos::plugins::database_api::extended_limit_order),
                   ((golos::plugins::database_api::limit_order_api_obj)), (real_price)(rewarded))
FC_REFLECT((golos::plugins::database_api::order_history_item),
           (time)(type)(sbd_quantity)(steem_quantity)(real_price));
FC_REFLECT((golos::plugins::database_api::market),
           (bids)(asks)(history)(price_history)(available_candlesticks)(available_zoom)(current_candlestick)(
                   current_zoom))
FC_REFLECT((golos::plugins::database_api::candle_stick),
           (open_time)(period)(high)(low)(open)(close)(steem_volume)(dollar_volume));
