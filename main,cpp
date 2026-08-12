#include "mfa.hpp"

#include <chrono>
#include <iostream>
#include <thread>

static constexpr auto PollInterval = std::chrono::milliseconds(100);

static void on_mfa_message(mfa::MessageType, const std::string& message) {
    std::cout << message << std::endl;
}

int main() {
    mfa::set_message_listener(on_mfa_message);

    try {
        mfa::start_session();
    } catch (const mfa::Error& error) {
        std::cerr << error.what() << std::endl;
        return 1;
    }

    while (mfa::is_running())
        std::this_thread::sleep_for(PollInterval);

    return 0;
}
