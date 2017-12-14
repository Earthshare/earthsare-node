#include <golos/chain/objects/account_object.hpp>
#include <golos/chain/objects/comment_object.hpp>
#include <golos/chain/objects/history_object.hpp>
#include <golos/chain/operation_notification.hpp>
#include <golos/plugins/blockchain_statistics/plugin.hpp>
#include <golos/protocol/block.hpp>
#include <golos/version/hardfork.hpp>
#include <golos/chain/database.hpp>
#include <fc/io/json.hpp>

namespace golos {
    namespace plugins {
        namespace blockchain_statistics {
            //using golos::chain::database;
            using namespace golos::protocol;


            struct plugin::plugin_impl final {
            public:
                plugin_impl() : database_(appbase::app().get_plugin<chain::plugin>().db()) {
                }

                ~plugin_impl() = default;

                void on_block(const protocol::signed_block &b);

                void pre_operation(const operation_notification &o);

                void post_operation(const operation_notification &o);

                auto database() -> golos::chain::database & {
                    return database_;
                }

                golos::chain::database &database_;
                flat_set<uint32_t> _tracked_buckets = {60, 3600, 21600, 86400, 604800, 2592000};
                flat_set<bucket_id_type> _current_buckets;
                uint32_t _maximum_history_per_bucket_size = 100;
            };


            void plugin::plugin_impl::pre_operation(const operation_notification &o) {
                auto &db = database();

                if (db.has_hardfork(STEEMIT_HARDFORK_0_17)) {
                    for (auto bucket_id : _current_buckets) {
                        if (o.op.which() == operation::tag<delete_comment_operation<0, 17, 0>>::value) {
                            delete_comment_operation<0, 17, 0> op = o.op.get<delete_comment_operation<0, 17, 0>>();
                            auto comment = db.get_comment(op.author, op.permlink);
                            const auto &bucket = db.get(bucket_id);

                            db.modify(bucket, [&](bucket_object &b) {
                                if (comment.parent_author.length()) {
                                    b.replies_deleted++;
                                } else {
                                    b.root_comments_deleted++;
                                }
                            });
                        } else if (o.op.which() == operation::tag<withdraw_vesting_operation<0, 17, 0>>::value) {
                            withdraw_vesting_operation<0, 17, 0> op = o.op.get<withdraw_vesting_operation<0, 17, 0>>();
                            auto &account = db.get_account(op.account);
                            const auto &bucket = db.get(bucket_id);

                            auto new_vesting_withdrawal_rate =
                                    op.vesting_shares.amount / STEEMIT_VESTING_WITHDRAW_INTERVALS;
                            if (op.vesting_shares.amount > 0 && new_vesting_withdrawal_rate == 0) {
                                new_vesting_withdrawal_rate = 1;
                            }

                            if (!db.has_hardfork(STEEMIT_HARDFORK_0_1)) {
                                new_vesting_withdrawal_rate *= 10000;
                            }

                            db.modify(bucket, [&](bucket_object &b) {
                                if (account.vesting_withdraw_rate.amount > 0) {
                                    b.modified_vesting_withdrawal_requests++;
                                } else {
                                    b.new_vesting_withdrawal_requests++;
                                }

                                // TODO: Figure out how to change delta when a vesting withdraw finishes. Have until March 24th 2018 to figure that out...
                                b.vesting_withdraw_rate_delta +=
                                        new_vesting_withdrawal_rate - account.vesting_withdraw_rate.amount;
                            });
                        }
                    }
                } else {
                    for (auto bucket_id : _current_buckets) {
                        if (o.op.which() == operation::tag<delete_comment_operation<0, 16, 0>>::value) {
                            delete_comment_operation<0, 16, 0> op = o.op.get<delete_comment_operation<0, 16, 0>>();
                            auto comment = db.get_comment(op.author, op.permlink);
                            const auto &bucket = db.get(bucket_id);

                            db.modify(bucket, [&](bucket_object &b) {
                                if (comment.parent_author.length()) {
                                    b.replies_deleted++;
                                } else {
                                    b.root_comments_deleted++;
                                }
                            });
                        } else if (o.op.which() == operation::tag<withdraw_vesting_operation<0, 16, 0>>::value) {
                            withdraw_vesting_operation<0, 16, 0> op = o.op.get<withdraw_vesting_operation<0, 16, 0>>();
                            auto &account = db.get_account(op.account);
                            const auto &bucket = db.get(bucket_id);

                            auto new_vesting_withdrawal_rate =
                                    op.vesting_shares.amount / STEEMIT_VESTING_WITHDRAW_INTERVALS;
                            if (op.vesting_shares.amount > 0 && new_vesting_withdrawal_rate == 0) {
                                new_vesting_withdrawal_rate = 1;
                            }

                            if (!db.has_hardfork(STEEMIT_HARDFORK_0_1)) {
                                new_vesting_withdrawal_rate *= 10000;
                            }

                            db.modify(bucket, [&](bucket_object &b) {
                                if (account.vesting_withdraw_rate.amount > 0) {
                                    b.modified_vesting_withdrawal_requests++;
                                } else {
                                    b.new_vesting_withdrawal_requests++;
                                }

                                // TODO: Figure out how to change delta when a vesting withdraw finishes. Have until March 24th 2018 to figure that out...
                                b.vesting_withdraw_rate_delta +=
                                        new_vesting_withdrawal_rate - account.vesting_withdraw_rate.amount;
                            });
                        }
                    }
                }
            }

            struct operation_process {
                const bucket_object &_bucket;
                database &_db;

                operation_process(database &bsp, const bucket_object &b) : _bucket(b), _db(bsp) {
                }

                typedef void result_type;

                template<typename T>
                void operator()(const T &) const {
                }

                template<uint8_t Major, uint8_t Hardfork, uint16_t Release>
                void operator()(const transfer_operation<Major, Hardfork, Release> &op) const {
                    _db.modify(_bucket, [&](bucket_object &b) {
                        b.transfers++;

                        if (op.amount.symbol_name() == STEEM_SYMBOL_NAME) {
                            b.steem_transferred += op.amount.amount;
                        } else {
                            b.sbd_transferred += op.amount.amount;
                        }
                    });
                }

                template<uint8_t Major, uint8_t Hardfork, uint16_t Release>
                void operator()(const interest_operation<Major, Hardfork, Release> &op) const {
                    _db.modify(_bucket, [&](bucket_object &b) {
                        b.sbd_paid_as_interest += op.interest.amount;
                    });
                }

                template<uint8_t Major, uint8_t Hardfork, uint16_t Release>
                void operator()(const account_create_operation<Major, Hardfork, Release> &op) const {
                    _db.modify(_bucket, [&](bucket_object &b) {
                        b.paid_accounts_created++;
                    });
                }

                template<uint8_t Major, uint8_t Hardfork, uint16_t Release>
                void operator()(const pow_operation<Major, Hardfork, Release> &op) const {
                    _db.modify(_bucket, [&](bucket_object &b) {
                        auto &worker = _db.get_account(op.worker_account);

                        if (worker.created == _db.head_block_time()) {
                            b.mined_accounts_created++;
                        }

                        b.total_pow++;

                        uint64_t bits = (_db.get_dynamic_global_properties().num_pow_witnesses / 4) + 4;
                        uint128_t estimated_hashes = (1 << bits);
                        uint32_t delta_t;

                        if (b.seconds == 0) {
                            delta_t = _db.head_block_time().sec_since_epoch() - b.open.sec_since_epoch();
                        } else {
                            delta_t = b.seconds;
                        }

                        b.estimated_hashpower = (b.estimated_hashpower * delta_t + estimated_hashes) / delta_t;
                    });
                }

                template<uint8_t Major, uint8_t Hardfork, uint16_t Release>
                void operator()(const comment_operation<Major, Hardfork, Release> &op) const {
                    _db.modify(_bucket, [&](bucket_object &b) {
                        auto &comment = _db.get_comment(op.author, op.permlink);

                        if (comment.created == _db.head_block_time()) {
                            if (comment.parent_author.length()) {
                                b.replies++;
                            } else {
                                b.root_comments++;
                            }
                        } else {
                            if (comment.parent_author.length()) {
                                b.reply_edits++;
                            } else {
                                b.root_comment_edits++;
                            }
                        }
                    });
                }

                template<uint8_t Major, uint8_t Hardfork, uint16_t Release>
                void operator()(const vote_operation<Major, Hardfork, Release> &op) const {
                    _db.modify(_bucket, [&](bucket_object &b) {
                        const auto &cv_idx = _db.get_index<comment_vote_index>().indices().get<by_comment_voter>();
                        auto &comment = _db.get_comment(op.author, op.permlink);
                        auto &voter = _db.get_account(op.voter);
                        auto itr = cv_idx.find(boost::make_tuple(comment.id, voter.id));

                        if (itr->num_changes) {
                            if (comment.parent_author.size()) {
                                b.new_reply_votes++;
                            } else {
                                b.new_root_votes++;
                            }
                        } else {
                            if (comment.parent_author.size()) {
                                b.changed_reply_votes++;
                            } else {
                                b.changed_root_votes++;
                            }
                        }
                    });
                }

                template<uint8_t Major, uint8_t Hardfork, uint16_t Release>
                void operator()(const author_reward_operation<Major, Hardfork, Release> &op) const {
                    _db.modify(_bucket, [&](bucket_object &b) {
                        b.payouts++;
                        b.sbd_paid_to_authors += op.sbd_payout.amount;
                        b.vests_paid_to_authors += op.vesting_payout.amount;
                    });
                }

                template<uint8_t Major, uint8_t Hardfork, uint16_t Release>
                void operator()(const curation_reward_operation<Major, Hardfork, Release> &op) const {
                    _db.modify(_bucket, [&](bucket_object &b) {
                        b.vests_paid_to_curators += op.reward.amount;
                    });
                }

                template<uint8_t Major, uint8_t Hardfork, uint16_t Release>
                void operator()(const liquidity_reward_operation<Major, Hardfork, Release> &op) const {
                    _db.modify(_bucket, [&](bucket_object &b) {
                        b.liquidity_rewards_paid += op.payout.amount;
                    });
                }

                template<uint8_t Major, uint8_t Hardfork, uint16_t Release>
                void operator()(const transfer_to_vesting_operation<Major, Hardfork, Release> &op) const {
                    _db.modify(_bucket, [&](bucket_object &b) {
                        b.transfers_to_vesting++;
                        b.steem_vested += op.amount.amount;
                    });
                }

                template<uint8_t Major, uint8_t Hardfork, uint16_t Release>
                void operator()(const fill_vesting_withdraw_operation<Major, Hardfork, Release> &op) const {
                    auto &account = _db.get_account(op.from_account);

                    _db.modify(_bucket, [&](bucket_object &b) {
                        b.vesting_withdrawals_processed++;
                        if (op.deposited.symbol_name() == STEEM_SYMBOL_NAME) {
                            b.vests_withdrawn += op.withdrawn.amount;
                        } else if (op.deposited.symbol_name() == SBD_SYMBOL_NAME) {
                            b.vests_transferred += op.withdrawn.amount;
                        }

                        if (account.vesting_withdraw_rate.amount == 0) {
                            b.finished_vesting_withdrawals++;
                        }
                    });
                }

                template<uint8_t Major, uint8_t Hardfork, uint16_t Release>
                void operator()(const limit_order_create_operation<Major, Hardfork, Release> &op) const {
                    _db.modify(_bucket, [&](bucket_object &b) {
                        b.limit_orders_created++;
                    });
                }

                template<uint8_t Major, uint8_t Hardfork, uint16_t Release>
                void operator()(const fill_order_operation<Major, Hardfork, Release> &op) const {
                    _db.modify(_bucket, [&](bucket_object &b) {
                        b.limit_orders_filled += 2;
                    });
                }

                template<uint8_t Major, uint8_t Hardfork, uint16_t Release>
                void operator()(const limit_order_cancel_operation<Major, Hardfork, Release> &op) const {
                    _db.modify(_bucket, [&](bucket_object &b) {
                        b.limit_orders_cancelled++;
                    });
                }

                template<uint8_t Major, uint8_t Hardfork, uint16_t Release>
                void operator()(const convert_operation<Major, Hardfork, Release> &op) const {
                    _db.modify(_bucket, [&](bucket_object &b) {
                        b.sbd_conversion_requests_created++;
                        b.sbd_to_be_converted += op.amount.amount;
                    });
                }

                template<uint8_t Major, uint8_t Hardfork, uint16_t Release>
                void operator()(const fill_convert_request_operation<Major, Hardfork, Release> &op) const {
                    _db.modify(_bucket, [&](bucket_object &b) {
                        b.sbd_conversion_requests_filled++;
                        b.steem_converted += op.amount_out.amount;
                    });
                }
            };

            void plugin::plugin_impl::on_block(const signed_block &b) {
                auto &db = database();

                if (b.block_num() == 1) {
                    db.create<bucket_object>([&](bucket_object &bo) {
                        bo.open = b.timestamp;
                        bo.seconds = 0;
                        bo.blocks = 1;
                    });
                } else {
                    db.modify(db.get(bucket_id_type()), [&](bucket_object &bo) {
                        bo.blocks++;
                    });
                }

                _current_buckets.clear();
                _current_buckets.insert(bucket_id_type());

                const auto &bucket_idx = db.get_index<bucket_index>().indices().get<by_bucket>();

                uint32_t trx_size = 0;
                uint32_t num_trx = b.transactions.size();

                for (auto trx : b.transactions) {
                    trx_size += fc::raw::pack_size(trx);
                }


                for (auto bucket : _tracked_buckets) {
                    auto open = fc::time_point_sec((db.head_block_time().sec_since_epoch() / bucket) * bucket);
                    auto itr = bucket_idx.find(boost::make_tuple(bucket, open));

                    if (itr == bucket_idx.end()) {
                        _current_buckets.insert(db.create<bucket_object>([&](bucket_object &bo) {
                            bo.open = open;
                            bo.seconds = bucket;
                            bo.blocks = 1;
                        }).id);

                        if (_maximum_history_per_bucket_size > 0) {
                            try {
                                auto cutoff = fc::time_point_sec(
                                        (safe<uint32_t>(db.head_block_time().sec_since_epoch()) -
                                         safe<uint32_t>(bucket) *
                                         safe<uint32_t>(_maximum_history_per_bucket_size)).value);

                                itr = bucket_idx.lower_bound(boost::make_tuple(bucket, fc::time_point_sec()));

                                while (itr->seconds == bucket && itr->open < cutoff) {
                                    auto old_itr = itr;
                                    ++itr;
                                    db.remove(*old_itr);
                                }
                            } catch (fc::overflow_exception &e) {
                            } catch (fc::underflow_exception &e) {
                            }
                        }
                    } else {
                        db.modify(*itr, [&](bucket_object &bo) {
                            bo.blocks++;
                        });

                        _current_buckets.insert(itr->id);
                    }

                    db.modify(*itr, [&](bucket_object &bo) {
                        bo.transactions += num_trx;
                        bo.bandwidth += trx_size;
                    });
                }
            }

            void plugin::plugin_impl::post_operation(const operation_notification &o) {
                try {
                    auto &db = database();

                    for (auto bucket_id : _current_buckets) {
                        const auto &bucket = db.get(bucket_id);

                        if (!is_virtual_operation(o.op)) {
                            db.modify(bucket, [&](bucket_object &b) {
                                b.operations++;
                            });
                        }
                        o.op.visit(operation_process(database(), bucket));
                    }
                } FC_CAPTURE_AND_RETHROW()
            }


            plugin::plugin() {
            }

            plugin::~plugin() {
            }

            void plugin::set_program_options(boost::program_options::options_description &cli,
                                             boost::program_options::options_description &cfg) {
                cli.add_options()("chain-stats-bucket-size", boost::program_options::value<std::string>()->default_value(
                        "[60,3600,21600,86400,604800,2592000]"),
                                  "Track blockchain statistics by grouping orders into buckets of equal size measured in seconds specified as a JSON array of numbers")(
                        "chain-stats-history-per-bucket", boost::program_options::value<uint32_t>()->default_value(100),
                        "How far back in time to track history for each bucket size, measured in the number of buckets (default: 100)");
                cfg.add(cli);
            }

            void plugin::plugin_initialize(const boost::program_options::variables_map &options) {
                try {
                    ilog("chain_stats_plugin: plugin_initialize() begin");
                    _my.reset(new plugin_impl());
                    auto &db = _my->database();

                    db.applied_block.connect([&](const protocol::signed_block &b) {
                        _my->on_block(b);
                    });
                    db.pre_apply_operation.connect([&](const operation_notification &o) {
                        _my->pre_operation(o);
                    });
                    db.post_apply_operation.connect([&](const operation_notification &o) {
                        _my->post_operation(o);
                    });

                    db.add_plugin_index<bucket_index>();

                    if (options.count("chain-stats-bucket-size")) {
                        const std::string &buckets = options["chain-stats-bucket-size"].as<std::string>();
                        _my->_tracked_buckets = fc::json::from_string(buckets).as<flat_set<uint32_t>>();
                    }
                    if (options.count("chain-stats-history-per-bucket")) {
                        _my->_maximum_history_per_bucket_size = options["chain-stats-history-per-bucket"].as<
                                uint32_t>();
                    }

                    wlog("chain-stats-bucket-size: ${b}", ("b", _my->_tracked_buckets));
                    wlog("chain-stats-history-per-bucket: ${h}", ("h", _my->_maximum_history_per_bucket_size));

                    ilog("chain_stats_plugin: plugin_initialize() end");
                } FC_CAPTURE_AND_RETHROW()
            }

            void plugin::plugin_startup() {
                ilog("chain_stats plugin: plugin_startup() begin");

                ilog("chain_stats plugin: plugin_startup() end");
            }

            const flat_set<uint32_t> &plugin::get_tracked_buckets() const {
                return _my->_tracked_buckets;
            }

            uint32_t plugin::get_max_history_per_bucket() const {
                return _my->_maximum_history_per_bucket_size;
            }

        }
    } // golos::blockchain_statistics
}