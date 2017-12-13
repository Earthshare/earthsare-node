#include <golos/chain/objects/account_object.hpp>

#include <golos/follow/follow_api.hpp>

namespace golos {
    namespace follow {

        namespace detail {

            inline void set_what(std::vector<follow_type> &what, uint16_t bitmask) {
                if (bitmask & 1 << blog) {
                    what.push_back(blog);
                }
                if (bitmask & 1 << ignore) {
                    what.push_back(ignore);
                }
            }

            class follow_api_impl {
            public:
                follow_api_impl(golos::application::application &_app)
                        : app(_app) {
                }

                std::vector<follow_api_object> get_followers(std::string following, std::string start_follower, follow_type type, uint16_t limit) const;

                std::vector<follow_api_object> get_following(std::string follower, std::string start_following, follow_type type, uint16_t limit) const;

                follow_count_api_object get_follow_count(std::string &account) const;

                std::vector<feed_entry> get_feed_entries(std::string account, uint32_t entry_id, uint16_t limit) const;

                std::vector<comment_feed_entry> get_feed(std::string account, uint32_t entry_id, uint16_t limit) const;

                std::vector<blog_entry> get_blog_entries(std::string account, uint32_t entry_id, uint16_t limit) const;

                std::vector<comment_blog_entry> get_blog(std::string account, uint32_t entry_id, uint16_t limit) const;

                std::vector<account_reputation> get_account_reputations(std::string lower_bound_name, uint32_t limit) const;

                golos::application::application &app;
            };

            std::vector<follow_api_object> follow_api_impl::get_followers(std::string following, std::string start_follower, follow_type type, uint16_t limit) const {
                FC_ASSERT(limit <= 1000);
                std::vector<follow_api_object> result;
                result.reserve(limit);

                const auto &idx = app.chain_database()->get_index<follow_index>().indices().get<by_following_follower>();
                auto itr = idx.lower_bound(std::make_tuple(following, start_follower));
                while (itr != idx.end() && limit &&
                       itr->following == following) {
                    if (type == undefined || itr->what & (1 << type)) {
                        follow_api_object entry;
                        entry.follower = itr->follower;
                        entry.following = itr->following;
                        set_what(entry.what, itr->what);
                        result.push_back(entry);
                        --limit;
                    }

                    ++itr;
                }

                return result;
            }

            std::vector<follow_api_object> follow_api_impl::get_following(std::string follower, std::string start_following, follow_type type, uint16_t limit) const {
                FC_ASSERT(limit <= 100);
                std::vector<follow_api_object> result;
                const auto &idx = app.chain_database()->get_index<follow_index>().indices().get<by_follower_following>();
                auto itr = idx.lower_bound(std::make_tuple(follower, start_following));
                while (itr != idx.end() && limit && itr->follower == follower) {
                    if (type == undefined || itr->what & (1 << type)) {
                        follow_api_object entry;
                        entry.follower = itr->follower;
                        entry.following = itr->following;
                        set_what(entry.what, itr->what);
                        result.push_back(entry);
                        --limit;
                    }

                    ++itr;
                }

                return result;
            }

            follow_count_api_object follow_api_impl::get_follow_count(std::string &account) const {
                follow_count_api_object result;
                auto itr = app.chain_database()->find<follow_count_object, by_account>(account);

                if (itr != nullptr) {
                    result = *itr;
                } else {
                    result.account = account;
                }

                return result;
            }

            std::vector<feed_entry> follow_api_impl::get_feed_entries(std::string account, uint32_t entry_id, uint16_t limit) const {
                FC_ASSERT(limit <=
                          500, "Cannot retrieve more than 500 feed entries at a time.");

                if (entry_id == 0) {
                    entry_id = ~0;
                }

                std::vector<feed_entry> results;
                results.reserve(limit);

                const auto &db = *app.chain_database();
                const auto &feed_idx = db.get_index<feed_index>().indices().get<by_feed>();
                auto itr = feed_idx.lower_bound(boost::make_tuple(account, entry_id));

                while (itr != feed_idx.end() && itr->account == account &&
                       results.size() < limit) {
                    const auto &comment = db.get(itr->comment);
                    feed_entry entry;
                    entry.author = comment.author;
                    entry.permlink = to_string(comment.permlink);
                    entry.entry_id = itr->account_feed_id;
                    if (itr->first_reblogged_by != account_name_type()) {
                        entry.reblog_by.reserve(itr->reblogged_by.size());
                        for (const auto &a : itr->reblogged_by) {
                            entry.reblog_by.push_back(a);
                        }
                        //entry.reblog_by = itr->first_reblogged_by;
                        entry.reblog_on = itr->first_reblogged_on;
                    }
                    results.push_back(entry);

                    ++itr;
                }

                return results;
            }

            std::vector<comment_feed_entry> follow_api_impl::get_feed(std::string account, uint32_t entry_id, uint16_t limit) const {
                FC_ASSERT(limit <=
                          500, "Cannot retrieve more than 500 feed entries at a time.");

                if (entry_id == 0) {
                    entry_id = ~0;
                }

                std::vector<comment_feed_entry> results;
                results.reserve(limit);

                const auto &db = *app.chain_database();
                const auto &feed_idx = db.get_index<feed_index>().indices().get<by_feed>();
                auto itr = feed_idx.lower_bound(boost::make_tuple(account, entry_id));

                while (itr != feed_idx.end() && itr->account == account &&
                       results.size() < limit) {
                    const auto &comment = db.get(itr->comment);
                    comment_feed_entry entry;
                    entry.comment = comment;
                    entry.entry_id = itr->account_feed_id;
                    if (itr->first_reblogged_by != account_name_type()) {
                        //entry.reblog_by = itr->first_reblogged_by;
                        entry.reblog_by.reserve(itr->reblogged_by.size());
                        for (const auto &a : itr->reblogged_by) {
                            entry.reblog_by.push_back(a);
                        }
                        entry.reblog_on = itr->first_reblogged_on;
                    }
                    results.push_back(entry);

                    ++itr;
                }

                return results;
            }

            std::vector<blog_entry> follow_api_impl::get_blog_entries(std::string account, uint32_t entry_id, uint16_t limit) const {
                FC_ASSERT(limit <=
                          500, "Cannot retrieve more than 500 blog entries at a time.");

                if (entry_id == 0) {
                    entry_id = ~0;
                }

                std::vector<blog_entry> results;
                results.reserve(limit);

                const auto &db = *app.chain_database();
                const auto &blog_idx = db.get_index<blog_index>().indices().get<by_blog>();
                auto itr = blog_idx.lower_bound(boost::make_tuple(account, entry_id));

                while (itr != blog_idx.end() && itr->account == account &&
                       results.size() < limit) {
                    const auto &comment = db.get(itr->comment);
                    blog_entry entry;
                    entry.author = comment.author;
                    entry.permlink = to_string(comment.permlink);
                    entry.blog = account;
                    entry.reblog_on = itr->reblogged_on;
                    entry.entry_id = itr->blog_feed_id;

                    results.push_back(entry);

                    ++itr;
                }

                return results;
            }

            std::vector<comment_blog_entry> follow_api_impl::get_blog(std::string account, uint32_t entry_id, uint16_t limit) const {
                FC_ASSERT(limit <=
                          500, "Cannot retrieve more than 500 blog entries at a time.");

                if (entry_id == 0) {
                    entry_id = ~0;
                }

                std::vector<comment_blog_entry> results;
                results.reserve(limit);

                const auto &db = *app.chain_database();
                const auto &blog_idx = db.get_index<blog_index>().indices().get<by_blog>();
                auto itr = blog_idx.lower_bound(boost::make_tuple(account, entry_id));

                while (itr != blog_idx.end() && itr->account == account &&
                       results.size() < limit) {
                    const auto &comment = db.get(itr->comment);
                    comment_blog_entry entry;
                    entry.comment = comment;
                    entry.blog = account;
                    entry.reblog_on = itr->reblogged_on;
                    entry.entry_id = itr->blog_feed_id;

                    results.push_back(entry);

                    ++itr;
                }

                return results;
            }

            std::vector<account_reputation> follow_api_impl::get_account_reputations(std::string lower_bound_name, uint32_t limit) const {
                FC_ASSERT(limit <=
                          1000, "Cannot retrieve more than 1000 account reputations at a time.");

                const auto &acc_idx = app.chain_database()->get_index<account_index>().indices().get<by_name>();
                const auto &rep_idx = app.chain_database()->get_index<reputation_index>().indices().get<by_account>();

                auto acc_itr = acc_idx.lower_bound(lower_bound_name);

                std::vector<account_reputation> results;
                results.reserve(limit);

                while (acc_itr != acc_idx.end() && results.size() < limit) {
                    auto itr = rep_idx.find(acc_itr->name);
                    account_reputation rep;

                    rep.account = acc_itr->name;
                    rep.reputation = itr != rep_idx.end() ? itr->reputation : 0;

                    results.push_back(rep);

                    ++acc_itr;
                }

                return results;
            }

        } // detail

        follow_api::follow_api(const golos::application::api_context &ctx) {
            my = std::make_shared<detail::follow_api_impl>(ctx.app);
        }

        void follow_api::on_api_startup() {
        }

        std::vector<follow_api_object> follow_api::get_followers(std::string following, std::string start_follower, follow_type type, uint16_t limit) const {
            return my->app.chain_database()->with_read_lock([&]() {
                return my->get_followers(following, start_follower, type, limit);
            });
        }

        std::vector<follow_api_object> follow_api::get_following(std::string follower, std::string start_following, follow_type type, uint16_t limit) const {
            return my->app.chain_database()->with_read_lock([&]() {
                return my->get_following(follower, start_following, type, limit);
            });
        }

        follow_count_api_object follow_api::get_follow_count(std::string account) const {
            return my->app.chain_database()->with_read_lock([&]() {
                return my->get_follow_count(account);
            });
        }

        std::vector<feed_entry> follow_api::get_feed_entries(std::string account, uint32_t entry_id, uint16_t limit) const {
            return my->app.chain_database()->with_read_lock([&]() {
                return my->get_feed_entries(account, entry_id, limit);
            });
        }

        std::vector<comment_feed_entry> follow_api::get_feed(std::string account, uint32_t entry_id, uint16_t limit) const {
            return my->app.chain_database()->with_read_lock([&]() {
                return my->get_feed(account, entry_id, limit);
            });
        }

        std::vector<blog_entry> follow_api::get_blog_entries(std::string account, uint32_t entry_id, uint16_t limit) const {
            return my->app.chain_database()->with_read_lock([&]() {
                return my->get_blog_entries(account, entry_id, limit);
            });
        }

        std::vector<comment_blog_entry> follow_api::get_blog(std::string account, uint32_t entry_id, uint16_t limit) const {
            return my->app.chain_database()->with_read_lock([&]() {
                return my->get_blog(account, entry_id, limit);
            });
        }

        std::vector<account_reputation> follow_api::get_account_reputations(std::string lower_bound_name, uint32_t limit) const {
            return my->app.chain_database()->with_read_lock([&]() {
                return my->get_account_reputations(lower_bound_name, limit);
            });
        }

        std::vector<account_name_type> follow_api::get_reblogged_by(const std::string &author, const std::string &permlink) const {
            auto &db = *my->app.chain_database();
            return db.with_read_lock([&]() {
                std::vector<account_name_type> result;
                const auto &post = db.get_comment(author, permlink);
                const auto &blog_idx = db.get_index<blog_index, by_comment>();
                auto itr = blog_idx.lower_bound(post.id);
                while (itr != blog_idx.end() && itr->comment == post.id &&
                       result.size() < 2000) {
                    result.push_back(itr->account);
                    ++itr;
                }
                return result;
            });
        }

        std::vector<std::pair<account_name_type, uint32_t>> follow_api::get_blog_authors(const account_name_type &blog) const {
            auto &db = *my->app.chain_database();
            return db.with_read_lock([&]() {
                std::vector <std::pair<account_name_type, uint32_t>> result;
                const auto &stats_idx = db.get_index<blog_author_stats_index, by_blogger_guest_count>();
                auto itr = stats_idx.lower_bound(boost::make_tuple(blog));
                while (itr != stats_idx.end() && itr->blogger == blog &&
                       result.size() < 2000) {
                    result.push_back(std::make_pair(itr->guest, itr->count));
                    ++itr;
                }
                return result;
            });
        }

    }
} // golos::follow
