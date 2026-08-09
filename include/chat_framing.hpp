#pragma once

#include <boost/asio.hpp>

#include <arpa/inet.h>

#include <cstdint>
#include <cstring>
#include <stdexcept>
#include <string>

namespace chat {

inline constexpr std::size_t kMaxMessageSize = 12 * 1024 * 1024;

inline std::uint32_t decode_frame_size(const char *header) {
  std::uint32_t network_size = 0;
  std::memcpy(&network_size, header, sizeof(network_size));
  return ntohl(network_size);
}

inline std::string make_frame(const std::string &payload) {
  const auto size = static_cast<std::uint32_t>(payload.size());
  const std::uint32_t network_size = htonl(size);
  std::string frame(sizeof(network_size) + payload.size(), '\0');
  std::memcpy(frame.data(), &network_size, sizeof(network_size));
  std::memcpy(frame.data() + sizeof(network_size), payload.data(), payload.size());
  return frame;
}

inline boost::asio::awaitable<std::string> read_frame(boost::asio::ip::tcp::socket &socket) {
  std::uint32_t network_size = 0;
  co_await boost::asio::async_read(
      socket, boost::asio::buffer(&network_size, sizeof(network_size)),
      boost::asio::use_awaitable);
  const std::uint32_t size = ntohl(network_size);
  if (size > kMaxMessageSize) {
    throw std::runtime_error("message too large");
  }

  std::string payload(size, '\0');
  if (size > 0) {
    co_await boost::asio::async_read(socket, boost::asio::buffer(payload),
                                    boost::asio::use_awaitable);
  }
  co_return payload;
}

} // namespace chat
