#include <iostream>

#include "../../sdk/cpp/keygate_client.hpp"

int main() {
  try {
    keygate::Client client("127.0.0.1", 8080, "kg_master_local", "demo-cpp");
    std::cout << "health: " << client.health() << "\n";
    std::cout << "resolve: " << client.resolve("telegram", "send", 60) << "\n";
    std::cout << "providers: " << client.providers() << "\n";
  } catch (const std::exception& e) {
    std::cerr << "error: " << e.what() << "\n";
    return 1;
  }
  return 0;
}
