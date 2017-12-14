#pragma once

#include <appbase/application.hpp>
#include <golos/plugins/chain/plugin.hpp>

namespace golos {
    namespace plugins {
        namespace account_history {
            using namespace chain;


            //
            // Plugins should #define their SPACE_ID's so plugins with
            // conflicting SPACE_ID assignments can be compiled into the
            // same binary (by simply re-assigning some of the conflicting #defined
            // SPACE_ID's in a build script).
            //
            // Assignment of SPACE_ID's cannot be done at run-time because
            // various template automagic depends on them being known at compile
            // time.
            //
#ifndef ACCOUNT_HISTORY_SPACE_ID
#define ACCOUNT_HISTORY_SPACE_ID 5
#endif

            enum account_history_object_type {
                key_account_object_type = 0, bucket_object_type = 1 ///< used in market_history_plugin
            };


            /**
             *  This plugin is designed to track a range of operations by account so that one node
             *  doesn't need to hold the full operation history in memory.
             */
            class plugin final : public appbase::plugin<plugin> {
            public:
                constexpr static const char *plugin_name = "account_history";

                APPBASE_PLUGIN_REQUIRES((chain::plugin))

                static const std::string &name() {
                    static std::string name = plugin_name;
                    return name;
                }

                plugin();

                ~plugin();

                void set_program_options(boost::program_options::options_description &cli,
                                         boost::program_options::options_description &cfg) override;

                void plugin_initialize(const boost::program_options::variables_map &options) override;

                void plugin_startup() override;

                void plugin_shutdown() override {
                }

                flat_map<std::string, std::string> tracked_accounts() const; /// map start_range to end_range
            private:
                struct plugin_impl;

                std::unique_ptr<plugin_impl> my;
            };

        }
    }
} //golos::account_history

