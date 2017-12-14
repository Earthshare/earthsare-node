#include <golos/plugins/snapshot/snapshot_plugin.hpp>
#include <golos/plugins/snapshot/snapshot_state.hpp>

#include <golos/chain/objects/account_object.hpp>
#include <golos/chain/operation_notification.hpp>
#include <golos/plugins/account_by_key/plugin.hpp>
#include <boost/iostreams/device/mapped_file.hpp>
#include <fc/io/json.hpp>

namespace golos {
    namespace plugins {
        namespace snapshot {
            using golos::chain::operation_notification;
            using golos::chain::account_object;
            using golos::chain::account_authority_object;
            using golos::chain::by_account_asset;
            using golos::chain::account_balance_index;
            using golos::chain::account_balance_object;
            using golos::chain::account_statistics_index;
            using golos::chain::account_statistics_object;
            using golos::chain::by_name;

            struct snapshot_plugin::snapshot_plugin_impl {
            public:
                snapshot_plugin_impl(snapshot_plugin &plugin) : self(plugin),
                        database_(appbase::app().get_plugin<chain::plugin>().db()) {
                }

                golos::chain::database &database() {
                    return database_;
                }

                void pre_operation(const operation_notification &op_obj);

                void post_operation(const operation_notification &op_obj);

                void update_key_lookup(const golos::chain::account_authority_object &a);

                snapshot_plugin &self;

                boost::bimap<std::string, std::string> loaded_snapshots;

                boost::program_options::variables_map options;

                const boost::bimap<std::string, std::string> &get_loaded_snapshots() const {
                    return loaded_snapshots;
                }

                golos::chain::database &database_;

                void load_snapshots(const std::vector<std::string> &snapshots);

            };

            struct pre_operation_visitor {
                snapshot_plugin &_plugin;

                pre_operation_visitor(snapshot_plugin &plugin) : _plugin(plugin) {
                }

                typedef void result_type;

                template<typename T>
                void operator()(const T &) const {
                }
            };

            struct post_operation_visitor {
                snapshot_plugin &_plugin;
                golos::chain::database &database_;

                post_operation_visitor(snapshot_plugin &plugin, golos::chain::database &database) : _plugin(plugin),
                        database_(database) {
                }

                typedef void result_type;

                template<typename T>
                void operator()(const T &) const {
                }

                template<uint8_t Major, uint8_t Hardfork, uint16_t Release>
                void operator()(const hardfork_operation<Major, Hardfork, Release> &op) const {
                    if (op.hardfork_id == STEEMIT_HARDFORK_0_17) {


                        if (_plugin.get_loaded_snapshots().right.find(
                                "1f0617dfc2e7aa49b0d6c394b36087ead02bc7f781e7550dae13e8cb12f13436") !=
                            _plugin.get_loaded_snapshots().right.end()) {
                            snapshot_state snapshot = fc::json::from_file(fc::path(
                                    _plugin.get_loaded_snapshots().right.at(
                                            "1f0617dfc2e7aa49b0d6c394b36087ead02bc7f781e7550dae13e8cb12f13436"))).as<
                                    snapshot_state>();
                            for (account_summary &account : snapshot.accounts) {
                                database_.modify(*database_.find_account(account.name), [&](account_object &a) {
                                    std::size_t position = a.json_metadata.find("created_at: 'GENESIS'");
                                    if (position != std::string::npos) {
                                        a.json_metadata.erase(a.json_metadata.find("created_at: 'GENESIS'"),
                                                              a.json_metadata.find("created_at: 'GENESIS'") +
                                                              std::string("created_at: 'GENESIS'").length());
                                        a.json_metadata.insert(a.json_metadata.find_first_of('{') + 1,
                                                               "\"created_at\": \"GENESIS\",");
                                    }
                                });
                            }
                        }
                    }
                }
            };

            void snapshot_plugin::snapshot_plugin_impl::pre_operation(const operation_notification &note) {
                note.op.visit(pre_operation_visitor(self));
            }

            void snapshot_plugin::snapshot_plugin_impl::post_operation(const operation_notification &note) {
                note.op.visit(post_operation_visitor(self, database()));
            }

            void snapshot_plugin::snapshot_plugin_impl::update_key_lookup(const account_authority_object &a) {
                try {
                    appbase::app().get_plugin<account_by_key::plugin>().update_key_lookup(a);
                } catch (fc::assert_exception) {
                    ilog("Account by key plugin not loaded");
                }
            }

            void snapshot_plugin::snapshot_plugin_impl::load_snapshots(const std::vector<std::string> &snapshots) {
                golos::chain::database &db = database();

                for (const std::vector<std::string>::value_type &iterator : snapshots) {
                    FC_ASSERT(fc::exists(iterator), "Snapshot file '${file}' was not found.", ("file", iterator));

                    ilog("Loading snapshot from ${s}", ("s", iterator));

                    std::string snapshot_hash(
                            fc::sha256::hash(boost::iostreams::mapped_file_source(fc::path(iterator).string()).data()));

                    snapshot_state snapshot = fc::json::from_file(fc::path(iterator)).as<snapshot_state>();
                    for (account_summary &account : snapshot.accounts) {
                        if (db.find_account(account.name) == nullptr) {
                            const auto &new_account = db.create<account_object>(
                                    [&](account_object &a) {
                                        a.name = account.name;
                                        a.memo_key = account.keys.memo_key;

                                        if (snapshot_hash ==
                                            "1f0617dfc2e7aa49b0d6c394b36087ead02bc7f781e7550dae13e8cb12f13436") {
                                            a.json_metadata = "{created_at: 'GENESIS'}";
                                            a.recovery_account = STEEMIT_INIT_MINER_NAME;
                                        } else {
                                            a.json_metadata = account.json_metadata.data();
                                            a.recovery_account = account.recovery_account;
                                        }
                                    });

                            auto &index = db.get_index<account_balance_index>().indices().get<by_account_asset>();
                            auto itr = index.find(boost::make_tuple(new_account.name, STEEM_SYMBOL_NAME));
                            if (itr == index.end()) {
                                db.create<account_balance_object>(
                                        [new_account](account_balance_object &b) {
                                            b.owner = new_account.name;
                                            b.asset_name = STEEM_SYMBOL_NAME;
                                            b.balance = 0;
                                        });
                            }

                            itr = index.find(boost::make_tuple(new_account.name, SBD_SYMBOL_NAME));
                            if (itr == index.end()) {
                                db.create<account_balance_object>(
                                        [new_account](account_balance_object &b) {
                                            b.owner = new_account.name;
                                            b.asset_name = SBD_SYMBOL_NAME;
                                            b.balance = 0;
                                        });
                            }

                            auto &stats_index = db.get_index<account_statistics_index>().indices().get<by_name>();
                            auto stats_itr = stats_index.find(new_account.name);
                            if (stats_itr == stats_index.end()) {
                                db.create<account_statistics_object>([&](account_statistics_object &s) {
                                    s.owner = new_account.name;
                                });
                            }

                            update_key_lookup(db.create<account_authority_object>(
                                    [&](account_authority_object &auth) {
                                        auth.account = account.name;
                                        auth.owner.weight_threshold = 1;
                                        auth.owner = account.keys.owner_key;
                                        auth.active = account.keys.active_key;
                                        auth.posting = account.keys.posting_key;
                                    }));
                        }
                    }

                    loaded_snapshots.insert({iterator, snapshot_hash});
                }
            }


            snapshot_plugin::snapshot_plugin() : impl(new snapshot_plugin_impl(*this)) {
            }

            snapshot_plugin::~snapshot_plugin() {
            }


            void snapshot_plugin::plugin_initialize(const boost::program_options::variables_map &options) {
                ilog("Initializing snapshot plugin");

                impl->options = options;
            }

            void snapshot_plugin::set_program_options(boost::program_options::options_description &command_line_options,
                                                      boost::program_options::options_description &config_file_options) {
                command_line_options.add_options()("snapshot-file",
                                                   boost::program_options::value<std::string>()->composing()->multitoken(),
                                                   "Snapshot files to load");
                config_file_options.add(command_line_options);
            }

            void snapshot_plugin::plugin_startup() {
                if (impl->options.count("snapshot-file")) {
                    impl->load_snapshots(impl->options["snapshot-file"].as<std::vector<std::string>>());
                } else {
#ifndef STEEMIT_BUILD_TESTNET
                    impl->load_snapshots({"snapshot5392323.json"});
#endif
                }
            }

            const boost::bimap<std::string, std::string> &snapshot_plugin::get_loaded_snapshots() const {
                return impl->get_loaded_snapshots();
            }


        }
    }
}
