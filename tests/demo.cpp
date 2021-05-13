#include <signal.h>
#include <sys/wait.h>
#include <unistd.h>
#include <array>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <set>
#include <string>
#include <thread>

/*
 * path generator
 */

constexpr const char* FMT_SERVER_BIN = "%s/server/host/server";
constexpr const char* FMT_ENCLAVE_SIGNED = "%s/server/enclave/enclave.signed";
constexpr const char* FMT_CLIENT_BIN = "%s/client/client";

#define PATH_GENERATOR(prefix, format_string, buf) \
    snprintf(&(buf)[0], (buf).size(), format_string, prefix)

std::array<char, BUFSIZ> server_bin = {0};
std::array<char, BUFSIZ> enclave_signed = {0};
std::array<char, BUFSIZ> client_bin = {0};

/*
 * endpoint generator
 */

constexpr const char* FMT_ENDPOINT = "tcp://%s:%s";

#define ENDPOINT_GENERATOR(host, port, buf) \
    snprintf(&(buf)[0], (buf).size(), FMT_ENDPOINT, host, port)

constexpr const char* SERVER0_HOST = "localhost";
constexpr const char* SERVER0_PORT_P = "5000";
constexpr const char* SERVER0_PORT_C = "5001";

constexpr const char* SERVER1_HOST = "localhost";
constexpr const char* SERVER1_PORT_P = "6000";
constexpr const char* SERVER1_PORT_C = "6001";

std::array<char, BUFSIZ> s0_2p_endpoint = {0};
std::array<char, BUFSIZ> s0_2c_endpoint = {0};
std::array<char, BUFSIZ> s1_2p_endpoint = {0};
std::array<char, BUFSIZ> s1_2c_endpoint = {0};

auto main(int argc, const char* argv[]) -> int
{
    if (argc < 2)
    {
        exit(EXIT_FAILURE);
    }

    const char* build_directory = argv[1];
    PATH_GENERATOR(build_directory, FMT_SERVER_BIN, server_bin);
    PATH_GENERATOR(build_directory, FMT_ENCLAVE_SIGNED, enclave_signed);
    PATH_GENERATOR(build_directory, FMT_CLIENT_BIN, client_bin);

    ENDPOINT_GENERATOR(SERVER0_HOST, SERVER0_PORT_P, s0_2p_endpoint);
    ENDPOINT_GENERATOR(SERVER0_HOST, SERVER0_PORT_C, s0_2c_endpoint);
    ENDPOINT_GENERATOR(SERVER1_HOST, SERVER1_PORT_P, s1_2p_endpoint);
    ENDPOINT_GENERATOR(SERVER1_HOST, SERVER1_PORT_C, s1_2c_endpoint);

    pid_t server0_pid = 0;
    pid_t server1_pid = 0;
    pid_t client_pid = 0;

    if ((server0_pid = fork()) == 0)
    {
        /*
         * server 0 ${SERVER0_PORT_C} ${SERVER0_PORT_P}
         * tcp://localhost:${SERVER1_PORT_P}
         * ${CMAKE_BINARY_DIR}/server/enclave/enclave.signed
         */

        execl(
            server_bin.data(),
            server_bin.data(),
            "0",
            SERVER0_PORT_C,
            SERVER0_PORT_P,
            s1_2p_endpoint.data(),
            enclave_signed.data(),
            nullptr);
    }
    else
    {
        fprintf(stderr, "server 0 running on pid=%d\n", server0_pid);
    }

    if ((server1_pid = fork()) == 0)
    {
        /*
         * server 1 ${SERVER1_PORT_C} ${SERVER1_PORT_P}
         * tcp://localhost:${SERVER0_PORT_P}
         * ${CMAKE_BINARY_DIR}/server/enclave/enclave.signed
         */

        execl(
            server_bin.data(),
            server_bin.data(),
            "1",
            SERVER1_PORT_C,
            SERVER1_PORT_P,
            s0_2p_endpoint.data(),
            enclave_signed.data(),
            nullptr);
    }
    else
    {
        fprintf(stderr, "server 1 running on pid=%d\n", server1_pid);
    }

    if ((client_pid = fork()) == 0)
    {
        /*
         * client tcp://localhost:${SERVER0_PORT_C}
         * tcp://localhost:${SERVER1_PORT_C}
         */

        std::this_thread::sleep_for(std::chrono::seconds(2));

        execl(
            client_bin.data(),
            client_bin.data(),
            s0_2c_endpoint.data(),
            s1_2c_endpoint.data(),
            nullptr);
    }
    else
    {
        fprintf(stderr, "client running on pid=%d\n", client_pid);
    }

    // wait for children processes
    std::set<pid_t> children = {client_pid, server0_pid, server1_pid};

    while (!children.empty())
    {
        int status;
        pid_t pid = wait(&status);
        children.erase(pid);

        if (!WIFEXITED(status) || WEXITSTATUS(status) != 0)
        {
            if (WIFCONTINUED(status))
            {
                fprintf(stderr, "WIFCONTINUED=%d\n", WIFCONTINUED(status));
            }
            if (WIFEXITED(status))
            {
                fprintf(stderr, "WIFEXITED=%d\n", WIFEXITED(status));
            }
            if (WIFSIGNALED(status))
            {
                fprintf(stderr, "WIFSIGNALED=%d\n", WIFSIGNALED(status));
            }
            if (WIFSTOPPED(status))
            {
                fprintf(stderr, "WIFSTOPPED=%d\n", WIFSTOPPED(status));
            }

            fprintf(
                stderr, "process %d exit with %d\n", pid, WEXITSTATUS(status));
            kill(0, SIGKILL);
            exit(-1);
        }
    }

    return 0;
}
