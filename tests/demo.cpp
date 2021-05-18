#include <sys/wait.h>
#include <unistd.h>
#include <array>
#include <cstddef>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <set>
#include <string>
#include <thread>

#include <CLI/CLI.hpp>

#ifndef BINARY_DIR
#error BINARY_DIR is not defined
#endif

/*
 * path generator
 */

#define xstr(s) str(s)
#define str(s)  #s

#define SERVER_BIN     xstr(BINARY_DIR) "/server/host/server"
#define ENCLAVE_SIGNED xstr(BINARY_DIR) "/server/enclave/enclave.signed"
#define CLIENT_BIN     xstr(BINARY_DIR) "/client/client"

/*
 * endpoint generator
 */

constexpr const char* FMT_ENDPOINT = "tcp://%s:%s";

#define ENDPOINT_GENERATOR(host, port, buf) snprintf(&(buf)[0], (buf).size(), FMT_ENDPOINT, host, port)

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
    /* pasrse command line argument */

    CLI::App app;

    size_t log_data_size;
    app.add_option("-l,--data-size", log_data_size, "logarithm of data set size")->required();

    CLI11_PARSE(app, argc, argv);

    /* generate parameters */

    ENDPOINT_GENERATOR(SERVER0_HOST, SERVER0_PORT_P, s0_2p_endpoint);
    ENDPOINT_GENERATOR(SERVER0_HOST, SERVER0_PORT_C, s0_2c_endpoint);
    ENDPOINT_GENERATOR(SERVER1_HOST, SERVER1_PORT_P, s1_2p_endpoint);
    ENDPOINT_GENERATOR(SERVER1_HOST, SERVER1_PORT_C, s1_2c_endpoint);

    pid_t server0_pid = 0;
    pid_t server1_pid = 0;
    pid_t client_pid = 0;

    auto data_size = std::to_string(log_data_size);

    if ((server0_pid = fork()) == 0)
    {
        execl(
            SERVER_BIN,
            SERVER_BIN,
            "--server-id",
            "0",
            "--data-size",
            data_size.c_str(),
            "--client-port",
            SERVER0_PORT_C,
            "--peer-port",
            SERVER0_PORT_P,
            "--peer-endpoint",
            s1_2p_endpoint.data(),
            "--enclave-path",
            ENCLAVE_SIGNED,
            nullptr);
    }
    else
    {
        fprintf(stderr, "server 0 running on pid=%d\n", server0_pid);
    }

    if ((server1_pid = fork()) == 0)
    {
        execl(
            SERVER_BIN,
            SERVER_BIN,
            "--server-id",
            "1",
            "--data-size",
            data_size.c_str(),
            "--client-port",
            SERVER1_PORT_C,
            "--peer-port",
            SERVER1_PORT_P,
            "--peer-endpoint",
            s0_2p_endpoint.data(),
            "--enclave-path",
            ENCLAVE_SIGNED,
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

        execl(CLIENT_BIN, CLIENT_BIN, s0_2c_endpoint.data(), s1_2c_endpoint.data(), nullptr);
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
                fprintf(stderr, "Process %d: WIFCONTINUED=%d\n", pid, WIFCONTINUED(status));
            }

            if (WCOREDUMP(status))
            {
                fprintf(stderr, "Process %d: WCOREDUMP=%d\n", pid, WCOREDUMP(status));
            }

            if (WIFSIGNALED(status))
            {
                fprintf(stderr, "Process %d: WIFSIGNALED=%d WTERMSIG=%d\n", pid, WIFSIGNALED(status), WTERMSIG(status));
            }

            if (WIFSTOPPED(status))
            {
                fprintf(stderr, "Process %d: WIFSTOPPED=%d WSTOPSIG=%d\n", pid, WIFSTOPPED(status), WSTOPSIG(status));
            }

            if (WIFEXITED(status))
            {
                fprintf(
                    stderr, "Process %d: WIFEXITED=%d WEXITSTATUS=%d\n", pid, WIFEXITED(status), WEXITSTATUS(status));
            }

            kill(0, SIGKILL);
            exit(-1);
        }
    }

    return 0;
}
