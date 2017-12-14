#include <golos/plugins/market_history_api/api_plugin.hpp>


#include <golos/plugins/market_history/order_history_object.hpp>
#include <golos/plugins/market_history/bucket_object.hpp>
#include <golos/plugins/market_history/plugin.hpp>

#include <fc/bloom_filter.hpp>

class by_expiration;
namespace golos {
    namespace plugins {
        namespace market_history {
            using std::string;
            using std::vector;
            using golos::plugins::market_history::order_history_index;
            using golos::protocol::signed_block_header;
            using golos::protocol::fill_call_order_operation;
            using golos::protocol::fill_order_operation;
            using golos::protocol::fill_settlement_order_operation;
            using golos::chain::signed_block;
            using golos::chain::asset_object;
            using golos::chain::asset;
            using golos::protocol::asset_name_type;
            using golos::chain::by_asset_name;
            using golos::chain::asset_index;
            using golos::protocol::account_name_type;
            using golos::chain::collateral_bid_object;
            using golos::protocol::share_type;
            using golos::chain::limit_order_index;
            using golos::protocol::price;
            using golos::chain::call_order_index;
            using golos::chain::by_price;
            using golos::chain::force_settlement_index;
            using golos::chain::liquidity_reward_balance_index;
            using golos::chain::by_account;
            using golos::chain::by_owner;
            using golos::chain::by_volume_weight;
            using golos::chain::collateral_bid_index;
            using golos::chain::by_expiration;



            struct collateral_bids {
                string   asset;
                uint32_t limit;
                uint32_t start;
                uint32_t skip;
            };

            template<class C, typename... Args>
            boost::signals2::scoped_connection connect_signal(boost::signals2::signal<void(Args...)> &sig, C &c, void(C::* f)(Args...)) {
                std::weak_ptr<C> weak_c = c.shared_from_this();
                return sig.connect([weak_c, f](Args... args) {
                    std::shared_ptr<C> shared_c = weak_c.lock();
                    if (!shared_c) {
                        return;
                    }
                    ((*shared_c).*f)(args...);
                });
            }

            class api::impl final : public std::enable_shared_from_this<impl> {
            public:
                impl() :
                        _chain(appbase::app().get_plugin<chain::plugin>()),
                        database_(appbase::app().get_plugin<chain::plugin>().db()) {}

                ~impl() = default;

                market_ticker get_ticker(const string &base, const string &quote) const;

                market_volume get_volume(const string &base, const string &quote) const;

                order_book get_order_book(const string &base, const string &quote, unsigned limit) const;

                vector<market_trade> get_trade_history(
                        const string &base,
                        const string &quote,
                        fc::time_point_sec start,
                        fc::time_point_sec stop,
                        unsigned limit = 100
                ) const;

                vector<order_history_object> get_fill_order_history(const string &a, const string &b,
                                                                    uint32_t limit) const;

                vector<bucket_object> get_market_history(const string &a, const string &b, uint32_t bucket_seconds,
                                                         fc::time_point_sec start, fc::time_point_sec end) const;

                flat_set<uint32_t> get_market_history_buckets() const;

                vector<limit_order_object> get_limit_orders(const string &a, const string &b, uint32_t limit) const;

                std::vector<extended_limit_order> get_limit_orders_by_owner(const string &owner) const;

                std::vector<call_order_object> get_call_orders_by_owner(const string &owner) const;

                std::vector<force_settlement_object> get_settle_orders_by_owner(const string &owner) const;

                vector<call_order_object> get_call_orders(const string &a, uint32_t limit) const;

                vector<force_settlement_object> get_settle_orders(const string &a, uint32_t limit) const;

                vector<call_order_object> get_margin_positions(const account_name_type &name) const;

                vector<collateral_bid_object> get_collateral_bids(const string &asset, uint32_t limit,
                                                                  uint32_t start, uint32_t skip) const;

                void subscribe_to_market(std::function<void(const variant &)> callback, string a, string b);

                void unsubscribe_from_market(string a, string b);

                std::vector<liquidity_balance> get_liquidity_queue(const string &start_account, uint32_t limit) const;

                vector<optional<asset_object>> lookup_asset_symbols(const vector<asset_name_type> &asset_symbols) const;

                // Subscriptions
                void set_subscribe_callback(std::function<void(const variant &)> cb, bool clear_filter);

                void set_pending_transaction_callback(std::function<void(const variant &)> cb);

                void set_block_applied_callback(std::function<void(const variant &block_id)> cb);

                void cancel_all_subscriptions();

                // signal handlers
                void on_applied_block(const signed_block &b);

                mutable fc::bloom_filter _subscribe_filter;
                std::function<void(const fc::variant &)> _subscribe_callback;
                std::function<void(const fc::variant &)> _pending_trx_callback;
                std::function<void(const fc::variant &)> _block_applied_callback;

                boost::signals2::scoped_connection _block_applied_connection;

                std::map<std::pair<asset_name_type, asset_name_type>, std::function<void(const variant &)>> _market_subscriptions;

                golos::chain::database& database() {
                    return database_;
                }

                golos::chain::database& database() const {
                    return database_;
                }
                chain::plugin &_chain;

            private:
                golos::chain::database& database_;

            };


            struct operation_process_fill_order_visitor {
                vector<optional<asset_object>> &assets;

                operation_process_fill_order_visitor(vector<optional<asset_object>> &input_assets) : assets(
                        input_assets) {}

                typedef market_trade result_type;

                double price_to_real(const share_type a, int p) const {
                    return double(a.value) / std::pow(10, p);
                };

                template<typename T>
                market_trade operator()(const T &o) const { return {}; }


                market_trade operator()(const fill_order_operation<0, 16, 0> &o) const {
                    market_trade trade;

                    if (assets[0]->asset_name == o.receives.symbol_name()) {
                        trade.amount = price_to_real(o.pays.amount, assets[1]->precision);
                        trade.value = price_to_real(o.receives.amount, assets[0]->precision);
                    } else {
                        trade.amount = price_to_real(o.receives.amount, assets[1]->precision);
                        trade.value = price_to_real(o.pays.amount, assets[0]->precision);
                    }

                    return trade;
                };

                market_trade operator()(const fill_order_operation<0, 17, 0> &o) const {
                    market_trade trade;

                    if (assets[0]->asset_name == o.receives.symbol_name()) {
                        trade.amount = price_to_real(o.pays.amount, assets[1]->precision);
                        trade.value = price_to_real(o.receives.amount, assets[0]->precision);
                    } else {
                        trade.amount = price_to_real(o.receives.amount, assets[1]->precision);
                        trade.value = price_to_real(o.pays.amount, assets[0]->precision);
                    }

                    return trade;
                };


                market_trade operator()(const fill_call_order_operation<0, 16, 0> &o) const {
                    market_trade trade;

                    if (assets[0]->asset_name == o.receives.symbol_name()) {
                        trade.amount = price_to_real(o.pays.amount, assets[1]->precision);
                        trade.value = price_to_real(o.receives.amount, assets[0]->precision);
                    } else {
                        trade.amount = price_to_real(o.receives.amount, assets[1]->precision);
                        trade.value = price_to_real(o.pays.amount, assets[0]->precision);
                    }

                    return trade;
                }

                market_trade operator()(const fill_call_order_operation<0, 17, 0> &o) const {
                    market_trade trade;

                    if (assets[0]->asset_name == o.receives.symbol_name()) {
                        trade.amount = price_to_real(o.pays.amount, assets[1]->precision);
                        trade.value = price_to_real(o.receives.amount, assets[0]->precision);
                    } else {
                        trade.amount = price_to_real(o.receives.amount, assets[1]->precision);
                        trade.value = price_to_real(o.pays.amount, assets[0]->precision);
                    }

                    return trade;
                }

                market_trade operator()(const fill_settlement_order_operation<0, 16, 0> &o) const {
                    market_trade trade;

                    if (assets[0]->asset_name == o.receives.symbol_name()) {
                        trade.amount = price_to_real(o.pays.amount, assets[1]->precision);
                        trade.value = price_to_real(o.receives.amount, assets[0]->precision);
                    } else {
                        trade.amount = price_to_real(o.receives.amount, assets[1]->precision);
                        trade.value = price_to_real(o.pays.amount, assets[0]->precision);
                    }

                    return trade;
                }

                market_trade operator()(const fill_settlement_order_operation<0, 17, 0> &o) const {
                    market_trade trade;

                    if (assets[0]->asset_name == o.receives.symbol_name()) {
                        trade.amount = price_to_real(o.pays.amount, assets[1]->precision);
                        trade.value = price_to_real(o.receives.amount, assets[0]->precision);
                    } else {
                        trade.amount = price_to_real(o.receives.amount, assets[1]->precision);
                        trade.value = price_to_real(o.pays.amount, assets[0]->precision);
                    }

                    return trade;
                }
            };
//////////////////////////////////////////////////////////////////////
//                                                                  //
// Subscriptions                                                    //
//                                                                  //
//////////////////////////////////////////////////////////////////////

            void api::set_subscribe_callback(std::function<void(const variant &)> cb, bool clear_filter) {
                pimpl->database().with_read_lock([&]() {
                    pimpl->set_subscribe_callback(cb, clear_filter);
                });
            }

            void api::impl::set_subscribe_callback(std::function<void(const variant &)> cb, bool clear_filter) {
                _subscribe_callback = cb;
                if (clear_filter || !cb) {
                    static fc::bloom_parameters param;
                    param.projected_element_count = 10000;
                    param.false_positive_probability = 1.0 / 10000;
                    param.maximum_size = 1024 * 8 * 8 * 2;
                    param.compute_optimal_parameters();

                    _subscribe_filter = fc::bloom_filter(param);
                }
            }

            void api::set_pending_transaction_callback(std::function<void(const variant &)> cb) {
                pimpl->database().with_read_lock(
                        [&]() {
                            pimpl->set_pending_transaction_callback(cb);
                        }
                );
            }

            void api::impl::set_pending_transaction_callback(std::function<void(const variant &)> cb) {
                _pending_trx_callback = cb;
            }

            void api::set_block_applied_callback(std::function<void(const variant &block_id)> cb) {
                pimpl->database().with_read_lock([&]() {
                    pimpl->set_block_applied_callback(cb);
                });
            }

            void api::impl::on_applied_block(const golos::chain::signed_block &b) {
                try {
                    _block_applied_callback(fc::variant(signed_block_header(b)));
                } catch (...) {
                    _block_applied_connection.release();
                }
            }

            void api::impl::set_block_applied_callback(std::function<void(const variant &block_header)> cb) {
                _block_applied_callback = cb;
                _block_applied_connection = connect_signal(database().applied_block, *this, &api::impl::on_applied_block);
            }

            void api::cancel_all_subscriptions() {
                pimpl->database().with_read_lock([&]() {
                    pimpl->cancel_all_subscriptions();
                });
            }

            void api::impl::cancel_all_subscriptions() {
                set_subscribe_callback(std::function<void(const fc::variant &)>(), true);
            }

            void api::unsubscribe_from_market(const string &a, const string &b) {
                pimpl->unsubscribe_from_market(a, b);
            }

            void api::impl::unsubscribe_from_market(string a, string b) {
                if (a > b) {
                    std::swap(a, b);
                }
                FC_ASSERT(a != b);
                _market_subscriptions.erase(std::make_pair(a, b));
            }

            vector<optional<asset_object>>
            api::impl::lookup_asset_symbols(const vector<asset_name_type> &asset_symbols) const {
                const auto &assets_by_symbol = database().get_index<asset_index>().indices().get<by_asset_name>();
                vector<optional<asset_object>> result;
                std::transform(asset_symbols.begin(), asset_symbols.end(), std::back_inserter(result),
                               [this, &assets_by_symbol](
                                       const vector<asset_name_type>::value_type &symbol) -> optional<asset_object> {
                                   auto itr = assets_by_symbol.find(symbol);
                                   return itr == assets_by_symbol.end() ? optional<asset_object>() : *itr;
                               });
                return result;
            }

            market_ticker api::impl::get_ticker(const string &base, const string &quote) const {
                const auto assets = lookup_asset_symbols({base, quote});
                FC_ASSERT(assets[0], "Invalid base asset symbol: ${s}", ("s", base));
                FC_ASSERT(assets[1], "Invalid quote asset symbol: ${s}", ("s", quote));

                market_ticker result;
                result.base = base;
                result.quote = quote;
                result.latest = 0;
                result.lowest_ask = 0;
                result.highest_bid = 0;
                result.percent_change = 0;
                result.base_volume = 0;
                result.quote_volume = 0;

                try {
                    const fc::time_point_sec now = fc::time_point::now();
                    const fc::time_point_sec yesterday = database().fetch_block_by_number(1)->timestamp < fc::time_point_sec(now.sec_since_epoch() - 86400) ? fc::time_point_sec(now.sec_since_epoch() - 86400) : database().fetch_block_by_number(1)->timestamp;
                    const auto batch_size = 100;

                    vector<market_trade> trades = get_trade_history(base, quote, now, yesterday, batch_size);
                    if (!trades.empty()) {
                        result.latest = trades[0].price;

                        while (!trades.empty()) {
                            for (const market_trade &t: trades) {
                                result.base_volume += t.value;
                                result.quote_volume += t.amount;
                            }

                            trades = get_trade_history(base, quote, trades.back().date, yesterday, batch_size);
                        }

                        const auto last_trade_yesterday = get_trade_history(base, quote, yesterday,
                                                                            fc::time_point_sec(), 1);
                        if (!last_trade_yesterday.empty()) {
                            const auto price_yesterday = last_trade_yesterday[0].price;
                            result.percent_change = ((result.latest / price_yesterday) - 1) * 100;
                        }
                    } else {
                        const auto last_trade = get_trade_history(base, quote, now, fc::time_point_sec(), 1);
                        if (!last_trade.empty()) {
                            result.latest = last_trade[0].price;
                        }
                    }

                    const auto orders = get_order_book(base, quote, 1);
                    if (!orders.asks.empty()) {
                        result.lowest_ask = orders.asks[0].price;
                    }
                    if (!orders.bids.empty()) {
                        result.highest_bid = orders.bids[0].price;
                    }
                } FC_CAPTURE_AND_RETHROW((base)(quote))

                return result;
            }

            market_volume api::impl::get_volume(const string &base, const string &quote) const {
                const auto ticker = get_ticker(base, quote);

                market_volume result;
                result.base = ticker.base;
                result.quote = ticker.quote;
                result.base_volume = ticker.base_volume;
                result.quote_volume = ticker.quote_volume;

                return result;
            }

            order_book api::impl::get_order_book(const string &base, const string &quote, unsigned limit) const {
                FC_ASSERT(limit <= 50);

                order_book result;
                result.base = base;
                result.quote = quote;

                auto assets = lookup_asset_symbols({base, quote});
                FC_ASSERT(assets[0], "Invalid base asset symbol: ${s}", ("s", base));
                FC_ASSERT(assets[1], "Invalid quote asset symbol: ${s}", ("s", quote));

                std::vector<limit_order_object> orders = get_limit_orders(assets[0]->asset_name, assets[1]->asset_name, limit);

                asset_name_type base_id = assets[0]->asset_name;
                asset_name_type quote_id = assets[1]->asset_name;

                for (const limit_order_object &o : orders) {
                    if (o.sell_price.base.symbol == base_id) {
                        order ord;
                        ord.price = o.sell_price.to_real();
                        ord.quote = (o.for_sale * (o.sell_price.quote / o.sell_price.base)).to_real();
                        ord.base = o.for_sale.to_real();
                        result.bids.push_back(ord);
                    } else {
                        order ord;
                        ord.price = o.sell_price.to_real();
                        ord.quote = o.for_sale.to_real();
                        ord.base = (o.for_sale * (o.sell_price.quote / o.sell_price.base)).to_real();
                        result.asks.push_back(ord);
                    }
                }

                return result;
            }

            std::vector<market_trade> api::impl::get_trade_history(const string &base, const string &quote,
                                                                   fc::time_point_sec start, fc::time_point_sec stop,
                                                                   unsigned limit) const {
                FC_ASSERT(limit <= 100);

                auto assets = lookup_asset_symbols({base, quote});
                FC_ASSERT(assets[0], "Invalid base asset symbol: ${s}", ("s", base));
                FC_ASSERT(assets[1], "Invalid quote asset symbol: ${s}", ("s", quote));

                auto base_id = assets[0]->asset_name;
                auto quote_id = assets[1]->asset_name;

                if (base_id > quote_id) {
                    std::swap(base_id, quote_id);
                }

                const auto &history_idx = database().get_index<order_history_index>().indices().get<by_key>();
                history_key hkey;
                hkey.base = base_id;
                hkey.quote = quote_id;
                hkey.sequence = std::numeric_limits<int64_t>::min();

                if (start.sec_since_epoch() == 0) {
                    start = fc::time_point_sec(fc::time_point::now());
                }

                uint32_t count = 0;
                auto itr = history_idx.lower_bound(hkey);
                vector<market_trade> result;

                while (itr != history_idx.end() && count < limit &&
                       !(itr->key.base != base_id || itr->key.quote != quote_id || itr->time < stop)) {
                    if (itr->time < start) {
                        market_trade trade = itr->op.visit(operation_process_fill_order_visitor(assets));

                        trade.date = itr->time;
                        trade.price = trade.value / trade.amount;

                        result.push_back(trade);
                        ++count;
                    }

                    // Trades are tracked in each direction.
                    ++itr;
                    ++itr;
                }

                return result;
            }

            vector<order_history_object> api::impl::get_fill_order_history(const string &a, const string &b, uint32_t limit) const {
                const auto &db = database();
                asset_name_type a_name = a, b_name = b;
                if (a_name > b_name) {
                    std::swap(a_name, b_name);
                }
                const auto &history_idx = db.get_index<order_history_index>().indices().get<by_key>();
                history_key hkey;
                hkey.base = a_name;
                hkey.quote = b_name;
                hkey.sequence = std::numeric_limits<int64_t>::min();

                uint32_t count = 0;
                auto itr = history_idx.lower_bound(hkey);
                vector<order_history_object> result;
                while (itr != history_idx.end() && count < limit) {
                    if (itr->key.base != a_name || itr->key.quote != b_name) {
                        break;
                    }
                    result.emplace_back(*itr);
                    ++itr;
                    ++count;
                }

                return result;
            }

            vector<bucket_object> api::impl::get_market_history(const std::string &a, const std::string &b,
                                                                uint32_t bucket_seconds, fc::time_point_sec start,
                                                                fc::time_point_sec end) const {
                try {
                    const auto &db = database();
                    vector<bucket_object> result;
                    result.reserve(200);

                    asset_name_type a_name = a, b_name = b;
                    if (a_name > b_name) {
                        std::swap(a_name, b_name);
                    }

                    const auto &by_key_idx = db.get_index<bucket_index>().indices().get<by_key>();

                    auto itr = by_key_idx.lower_bound(bucket_key(a_name, b_name, bucket_seconds, start));
                    while (itr != by_key_idx.end() && itr->key.open <= end && result.size() < 200) {
                        if (!(itr->key.base == a_name && itr->key.quote == b_name &&
                              itr->key.seconds == bucket_seconds)) {
                            return result;
                        }
                        result.emplace_back(*itr);
                        ++itr;
                    }
                    return result;
                } FC_CAPTURE_AND_RETHROW((a)(b)(bucket_seconds)(start)(end))
            }

            flat_set<uint32_t> api::impl::get_market_history_buckets() const {
                auto buckets = appbase::app().get_plugin<market_history::plugin>().get_tracked_buckets();
                return buckets;
            }

/**
 *  @return the limit orders for both sides of the book for the two assets specified up to limit number on each side.
 */
            vector<limit_order_object>
            api::impl::get_limit_orders(const string &a, const string &b, uint32_t limit) const {
                const auto &limit_order_idx = database().get_index<limit_order_index>();
                const auto &limit_price_idx = limit_order_idx.indices().get<by_price>();

                vector<limit_order_object> result;

                asset_name_type a_symbol = a;
                asset_name_type b_symbol = b;

                uint32_t count = 0;
                auto limit_itr = limit_price_idx.lower_bound(price<0, 17, 0>::max(a_symbol, b_symbol));
                auto limit_end = limit_price_idx.upper_bound(price<0, 17, 0>::min(a_symbol, b_symbol));
                while (limit_itr != limit_end && count < limit) {
                    result.push_back(*limit_itr);
                    ++limit_itr;
                    ++count;
                }
                count = 0;
                limit_itr = limit_price_idx.lower_bound(price<0, 17, 0>::max(b_symbol, a_symbol));
                limit_end = limit_price_idx.upper_bound(price<0, 17, 0>::min(b_symbol, a_symbol));
                while (limit_itr != limit_end && count < limit) {
                    result.push_back(*limit_itr);
                    ++limit_itr;
                    ++count;
                }

                return result;
            }

            vector<call_order_object> api::impl::get_call_orders(const string &a, uint32_t limit) const {
                const auto &call_index = database().get_index<call_order_index>().indices().get<by_price>();
                const asset_object &mia = database().get_asset(a);
                price<0, 17, 0> index_price = price<0, 17, 0>::min(
                        database().get_asset_bitasset_data(mia.asset_name).options.short_backing_asset,
                        mia.asset_name);

                return vector<call_order_object>(call_index.lower_bound(index_price.min()),
                                                 call_index.lower_bound(index_price.max()));
            }

            vector<force_settlement_object> api::impl::get_settle_orders(const string &a, uint32_t limit) const {
                const auto &settle_index = database().get_index<force_settlement_index>().indices().get<by_expiration>();
                const asset_object &mia = database().get_asset(a);
                return vector<force_settlement_object>(settle_index.lower_bound(mia.asset_name),
                                                       settle_index.upper_bound(mia.asset_name));
            }

            vector<call_order_object> api::impl::get_margin_positions(const account_name_type &name) const {
                try {
                    const auto &idx = database().get_index<call_order_index>();
                    const auto &aidx = idx.indices().get<by_account>();
                    auto start = aidx.lower_bound(boost::make_tuple(name, STEEM_SYMBOL_NAME));
                    auto end = ++aidx.lower_bound(boost::make_tuple(name, STEEM_SYMBOL_NAME));
                    vector<call_order_object> result;
                    while (start != end) {
                        result.push_back(*start);
                        ++start;
                    }
                    return result;
                } FC_CAPTURE_AND_RETHROW((name))
            }

            vector<collateral_bid_object> api::impl::get_collateral_bids(
                    const string &asset, uint32_t limit, uint32_t start, uint32_t skip) const {
                try {
                    FC_ASSERT(limit <= 100);
                    const asset_object &swan = database().get_asset(asset);
                    FC_ASSERT(swan.is_market_issued());
                    const auto &bad = database().get_asset_bitasset_data(asset);
                    const asset_object &back = database().get_asset(bad.options.short_backing_asset);
                    const auto &idx = database().get_index<collateral_bid_index>();
                    const auto &aidx = idx.indices().get<by_price>();
                    auto start = aidx.lower_bound(boost::make_tuple(asset, price<0, 17, 0>::max(back.asset_name, asset), collateral_bid_object::id_type()));
                    auto end = aidx.lower_bound(boost::make_tuple(asset, price<0, 17, 0>::min(back.asset_name, asset), collateral_bid_object::id_type(STEEMIT_MAX_INSTANCE_ID)));
                    vector<collateral_bid_object> result;
                    while (skip-- > 0 && start != end) {
                        ++start;
                    }
                    while (start != end && limit-- > 0) {
                        result.emplace_back(*start);
                        ++start;
                    }
                    return result;
                } FC_CAPTURE_AND_RETHROW((asset)(limit)(skip))
            }

            std::vector<liquidity_balance>
            api::impl::get_liquidity_queue(const string &start_account, uint32_t limit) const {
                FC_ASSERT(limit <= 1000);

                const auto &liq_idx = database().get_index<liquidity_reward_balance_index>().indices().get<by_volume_weight>();
                auto itr = liq_idx.begin();
                std::vector<liquidity_balance> result;

                result.reserve(limit);

                if (start_account.length()) {
                    const auto &liq_by_acc = database().get_index<liquidity_reward_balance_index>().indices().get<by_owner>();
                    auto acc = liq_by_acc.find(database().get_account(start_account).id);

                    if (acc != liq_by_acc.end()) {
                        itr = liq_idx.find(boost::make_tuple(acc->weight, acc->owner));
                    } else {
                        itr = liq_idx.end();
                    }
                }

                while (itr != liq_idx.end() && result.size() < limit) {
                    liquidity_balance bal;
                    bal.account = database().get(itr->owner).name;
                    bal.weight = itr->weight;
                    result.push_back(bal);

                    ++itr;
                }

                return result;
            }

            std::vector<extended_limit_order>
            api::impl::get_limit_orders_by_owner(const string &owner) const {
                std::vector<extended_limit_order> result;
                const auto &idx = database().get_index<limit_order_index>().indices().get<by_account>();
                auto itr = idx.lower_bound(owner);
                while (itr != idx.end() && itr->seller == owner) {
                    result.emplace_back(*itr);

                    auto assets = lookup_asset_symbols({itr->sell_price.base.symbol, itr->sell_price.quote.symbol});
                    FC_ASSERT(assets[0], "Invalid base asset symbol: ${s}", ("s", itr->sell_price.base));
                    FC_ASSERT(assets[1], "Invalid quote asset symbol: ${s}", ("s", itr->sell_price.quote));

                    std::function<double(const share_type, int)> price_to_real = [&](const share_type a, int p) -> double {
                        return double(a.value) / std::pow(10, p);
                    };

                    if (itr->sell_price.base.symbol == STEEM_SYMBOL_NAME) {
                        result.back().real_price =
                                price_to_real((~result.back().sell_price).base.amount, assets[0]->precision) /
                                price_to_real((~result.back().sell_price).quote.amount, assets[1]->precision);
                    } else {
                        result.back().real_price =
                                price_to_real(result.back().sell_price.base.amount, assets[0]->precision) /
                                price_to_real(result.back().sell_price.quote.amount, assets[1]->precision);
                    }

                    ++itr;
                }
                return result;
            }

            std::vector<call_order_object> api::impl::get_call_orders_by_owner(const string &owner) const {
                std::vector<call_order_object> result;
                const auto &idx = database().get_index<call_order_index>().indices().get<by_account>();
                auto itr = idx.lower_bound(owner);
                while (itr != idx.end() && itr->borrower == owner) {
                    result.emplace_back(*itr);
                    ++itr;
                }
                return result;
            }

            std::vector<force_settlement_object> api::impl::get_settle_orders_by_owner(const string &owner) const {
                std::vector<force_settlement_object> result;
                const auto &idx = database().get_index<force_settlement_index>().indices().get<by_account>();
                auto itr = idx.lower_bound(owner);
                while (itr != idx.end() && itr->owner == owner) {
                    result.emplace_back(*itr);
                    ++itr;
                }
                return result;
            }

            api::api() : pimpl(new impl) {
                JSON_RPC_REGISTER_API(STEEMIT_MARKET_HISTORY_API_PLUGIN_NAME);
            }

            api::~api() {}

            DEFINE_API(api, get_ticker) {
                return pimpl->database().with_read_lock([&]() {
                    return pimpl->get_ticker(args.args->at(0).as<std::string>(), args.args->at(1).as<std::string>());
                });
            }

            DEFINE_API(api, get_volume) {
                return pimpl->database().with_read_lock([&]() {
                    return pimpl->get_volume(args.args->at(0).as<std::string>(), args.args->at(1).as<std::string>());
                });
            }

            DEFINE_API(api, get_order_book) {
                return pimpl->database().with_read_lock([&]() {
                    return pimpl->get_order_book(args.args->at(0).as<std::string>(), args.args->at(1).as<std::string>(),
                                                 args.args->at(2).as<uint32_t>());
                });
            }

            DEFINE_API(api, get_trade_history) {
                return pimpl->database().with_read_lock([&]() {
                    return pimpl->get_trade_history(args.args->at(0).as<std::string>(),
                                                    args.args->at(1).as<std::string>(),
                                                    args.args->at(2).as<fc::time_point_sec>(),
                                                    args.args->at(3).as<fc::time_point_sec>(),
                                                    args.args->at(4).as<uint32_t>());
                });
            }

            DEFINE_API(api, get_fill_order_history) {
                return pimpl->database().with_read_lock([&]() {
                    return pimpl->get_fill_order_history(args.args->at(0).as<std::string>(),
                                                         args.args->at(1).as<std::string>(),
                                                         args.args->at(2).as<uint32_t>());
                });
            }

            DEFINE_API(api, get_market_history) {
                return pimpl->database().with_read_lock([&]() {
                    return pimpl->get_market_history(args.args->at(0).as<std::string>(),
                                                     args.args->at(1).as<std::string>(),
                                                     args.args->at(2).as<uint32_t>(),
                                                     args.args->at(3).as<fc::time_point_sec>(),
                                                     args.args->at(4).as<fc::time_point_sec>());
                });
            }

            DEFINE_API(api, get_market_history_buckets) {
                return pimpl->database().with_read_lock([&]() {
                    return pimpl->get_market_history_buckets();
                });
            }

            DEFINE_API(api, get_limit_orders) {
                return pimpl->database().with_read_lock([&]() {
                    return pimpl->get_limit_orders(args.args->at(0).as<std::string>(),
                                                   args.args->at(1).as<std::string>(),
                                                   args.args->at(2).as<uint32_t>());
                });
            }

            DEFINE_API(api, get_call_orders) {
                return pimpl->database().with_read_lock([&]() {
                    return pimpl->get_call_orders(args.args->at(0).as<std::string>(), args.args->at(1).as<uint32_t>());
                });
            }

            DEFINE_API(api, get_settle_orders) {
                return pimpl->database().with_read_lock([&]() {
                    return pimpl->get_settle_orders(args.args->at(0).as<std::string>(),
                                                    args.args->at(1).as<uint32_t>());
                });
            }

            DEFINE_API(api, get_collateral_bids) {
                return pimpl->database().with_read_lock(
                        [&]() {
                            auto tmp = args.args->at(0).as<collateral_bids>();
                            return pimpl->get_collateral_bids(tmp.asset,tmp.limit,tmp.start,tmp.skip);

                        }

                );
            }

            DEFINE_API(api, get_margin_positions) {
                return pimpl->database().with_read_lock([&]() {
                    return pimpl->get_margin_positions(args.args->at(0).as<std::string>());
                });
            }

            DEFINE_API(api, get_liquidity_queue) {
                return pimpl->database().with_read_lock([&]() {
                    return pimpl->get_liquidity_queue(args.args->at(0).as<std::string>(),
                                                      args.args->at(0).as<uint32_t>());
                });
            }




            DEFINE_API(api,get_call_orders_by_owner){
                return pimpl->database().with_read_lock([&]() {
                    //TODO big proble
                    return pimpl->get_call_orders_by_owner(std::string(""));
                });
            }




            DEFINE_API(api,get_limit_orders_by_owner){
                return pimpl->database().with_read_lock([&]() {
                    //TODO big proble
                    return pimpl->get_limit_orders_by_owner(std::string(""));
                });
            }

            DEFINE_API(api,get_settle_orders_by_owner){
                return pimpl->database().with_read_lock([&]() {
                    //TODO big proble
                    return pimpl->get_settle_orders_by_owner(std::string(""));
                });
            }



        }
    }
} //golos::plugins::chain


FC_REFLECT((golos::plugins::market_history::collateral_bids), (asset)(limit)(start)(skip));
