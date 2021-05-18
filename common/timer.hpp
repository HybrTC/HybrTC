#pragma once

#include <sys/syscall.h>
#include <unistd.h>
#include <ctime>
#include <string>
#include <utility>
#include <vector>

#include <nlohmann/json.hpp>

class Timer
{
    struct time_record
    {
        clock_t timestamp;
        int64_t thread_id;
        std::string name;

        explicit time_record(std::string name)
            : timestamp(clock()), thread_id(syscall(__NR_gettid)), name(std::move(name))
        {
        }

        auto to_json() -> nlohmann::json
        {
            return nlohmann::json::object({{"clock", timestamp}, {"thread", thread_id}, {"name", name}});
        }
    };

    std::vector<time_record> store;

  public:
    void operator()(std::string str)
    {
        store.emplace_back(std::move(str));
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
