#pragma once

#include <arpa/inet.h>
#include <netdb.h>
#include <sys/socket.h>
#include <unistd.h>

#include <cstdint>
#include <stdexcept>
#include <string>

namespace keygate {

// Минимальный HTTP-клиент без внешних зависимостей.
class Client {
 public:
  Client(std::string host = "127.0.0.1", int port = 8080,
         std::string master_key = "kg_master_local", std::string client_id = "cpp-sdk")
      : host_(std::move(host)), port_(port), master_key_(std::move(master_key)),
        client_id_(std::move(client_id)) {}

  std::string health() { return request("GET", "/healthz", ""); }
  std::string resolve(const std::string& provider, const std::string& scope = "read", int ttl = 60) {
    std::string body = "{\"provider\":\"" + provider + "\",\"scope\":\"" + scope +
                       "\",\"ttl\":" + std::to_string(ttl) + "}";
    return request("POST", "/v1/keys/resolve", body);
  }
  std::string rotate(const std::string& provider) {
    return request("POST", "/v1/keys/rotate", "{\"provider\":\"" + provider + "\"}");
  }
  std::string audit() { return request("GET", "/v1/audit", ""); }
  std::string providers() { return request("GET", "/v1/providers", ""); }

 private:
  std::string request(const std::string& method, const std::string& path, const std::string& body) {
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) throw std::runtime_error("socket failed");

    hostent* host = gethostbyname(host_.c_str());
    if (!host) {
      close(fd);
      throw std::runtime_error("host not found: " + host_);
    }

    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_port = htons(static_cast<uint16_t>(port_));
    addr.sin_addr = *reinterpret_cast<in_addr*>(host->h_addr_list[0]);

    if (connect(fd, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) < 0) {
      close(fd);
      throw std::runtime_error("connect failed");
    }

    std::string req = method + " " + path + " HTTP/1.1\r\n"
                      "Host: " + host_ + ":" + std::to_string(port_) + "\r\n"
                      "X-KeyGate-Key: " + master_key_ + "\r\n"
                      "X-Client-ID: " + client_id_ + "\r\n"
                      "Content-Type: application/json\r\n"
                      "Connection: close\r\n"
                      "Content-Length: " + std::to_string(body.size()) + "\r\n\r\n" + body;
    if (send(fd, req.data(), req.size(), 0) < 0) {
      close(fd);
      throw std::runtime_error("send failed");
    }

    std::string raw;
    char buf[4096];
    ssize_t got;
    while ((got = recv(fd, buf, sizeof(buf), 0)) > 0) {
      raw.append(buf, static_cast<size_t>(got));
    }
    close(fd);

    size_t split = raw.find("\r\n\r\n");
    if (split == std::string::npos) throw std::runtime_error("bad HTTP response");
    std::string headers = raw.substr(0, split);
    std::string payload = raw.substr(split + 4);

    if (headers.find("chunked") != std::string::npos) {
      std::string decoded;
      size_t at = 0;
      while (at < payload.size()) {
        size_t newline = payload.find("\r\n", at);
        if (newline == std::string::npos) break;
        size_t size = std::stoul(payload.substr(at, newline - at), nullptr, 16);
        at = newline + 2;
        if (size == 0) break;
        decoded.append(payload, at, size);
        at += size + 2;
      }
      return decoded;
    }
    return payload;
  }

  std::string host_;
  int port_;
  std::string master_key_;
  std::string client_id_;
};

}  // namespace keygate
