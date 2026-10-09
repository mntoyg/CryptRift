#include "cli_runner.hpp"

#include <cstdlib>
#include <fstream>
#include <sstream>
#include <utility>

#ifndef _WIN32
#include <sys/wait.h>
#endif

namespace {

std::string& binary_path() {
    static std::string path;
    return path;
}

std::string slurp(const char* path) {
    std::ifstream file(path, std::ios::binary);
    std::ostringstream buffer;
    buffer << file.rdbuf();
    return buffer.str();
}

void spill(const char* path, const std::string& data) {
    std::ofstream file(path, std::ios::binary);
    file.write(data.data(), static_cast<std::streamsize>(data.size()));
}

}  // namespace

void set_cli_binary(std::string path) { binary_path() = std::move(path); }

Run run_cli(const std::string& args, const std::string& stdin_data) {
    if (binary_path().empty()) {
        // Better a loud failure than a suite that silently tests nothing.
        return Run{-1, "", "run_cli: the cryptrift binary path was never set\n"};
    }

    const char* stdin_path = "ct_cli_stdin.tmp";
    const char* stdout_path = "ct_cli_stdout.tmp";
    const char* stderr_path = "ct_cli_stderr.tmp";

    spill(stdin_path, stdin_data);

    const std::string command = std::string("\"") + binary_path() + "\" " + args + " > " +
                                stdout_path + " 2> " + stderr_path + " < " + stdin_path;
    const int status = std::system(command.c_str());

    Run result;
#ifdef _WIN32
    // cmd.exe hands back the exit code directly.
    result.exit_code = status;
#else
    result.exit_code = WIFEXITED(status) ? WEXITSTATUS(status) : -1;
#endif
    result.out = slurp(stdout_path);
    result.err = slurp(stderr_path);
    return result;
}
