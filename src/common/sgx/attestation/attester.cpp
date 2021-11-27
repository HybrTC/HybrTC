#include <memory>
#include <mutex>

#include <openenclave/attestation/attester.h>
#include <openenclave/attestation/sgx/evidence.h>

#include "common/types.hpp"

#include "attester.hpp"

class AttesterInit
{
  public:
    AttesterInit()
    {
        oe_attester_initialize();
    }

    ~AttesterInit()
    {
        oe_attester_shutdown();
    }
};

static std::shared_ptr<AttesterInit> init = nullptr;
static std::mutex init_lock;

Attester::Attester(const oe_uuid_t* format_id) : format_ptr(format_id)
{
    init_lock.lock();
    if (init == nullptr)
    {
        init = std::make_shared<AttesterInit>();
    }
    init_lock.unlock();
}
