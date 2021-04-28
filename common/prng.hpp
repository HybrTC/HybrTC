#pragma once
#include <limits>
#include <random>

template <class IntType>
class PRNG
{
  private:
    std::random_device rd;
    std::mt19937_64 gen;
    std::uniform_int_distribution<IntType> distrib;

  public:
    PRNG() : gen(rd()), distrib(1, std::numeric_limits<IntType>::max())
    {
    }

    IntType operator()()
    {
        return distrib(gen);
    }
};
