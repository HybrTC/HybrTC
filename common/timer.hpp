#pragma once

#include <sys/syscall.h>
#include <unistd.h>
#include <chrono>
#include <mutex>
#include <string>
#include <utility>
#include <vector>

#include <nlohmann/json.hpp>

// #include "utils/spdlog.hpp"

class Timer
{
    struct time_record
    {
        std::chrono::time_point<std::chrono::steady_clock, std::chrono::duration<int64_t, std::nano>> timestamp;
        int64_t thread_id;
        std::string name;

        explicit time_record(std::string name)
            : timestamp(std::chrono::steady_clock::now()), thread_id(syscall(__NR_gettid)), name(std::move(name))
        {
            // SPDLOG_DEBUG("time_record {} {} {}", this->name, thread_id, timestamp.time_since_epoch().count());
        }

        auto to_json() -> nlohmann::json
        {
            return nlohmann::json::object(
                {{"clock", timestamp.time_since_epoch().count()}, {"thread", thread_id}, {"name", name}});
        }
    };

    std::vector<time_record> store;
    std::mutex lock;

  public:
    void operator()(const std::string& str)
    {
        lock.lock();
        store.emplace_back(str);
        lock.unlock();
    }

    auto to_json() -> nlohmann::json
    {
        nlohmann::json records = nlohmann::json::array();

        for (auto r : store)
        {
            records.push_back(r.to_json());
        }

        return records;
    }
};
