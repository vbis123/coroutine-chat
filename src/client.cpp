#include <boost/asio.hpp>

#include <arpa/inet.h>

#include <deque>
#include <cstring>
#include <iostream>
#include <memory>
#include <string>
#include <thread>

using boost::asio::awaitable;
using boost::asio::co_spawn;
using boost::asio::detached;
using boost::asio::ip::tcp;
using boost::asio::use_awaitable;

namespace {
constexpr std::size_t kMaxMessageSize = 1024 * 1024; // 1 MB

std::string make_frame(const std::string &payload) {
  uint32_t len = static_cast<uint32_t>(payload.size());
  uint32_t net_len = htonl(len);
  std::string frame;
  frame.resize(sizeof(uint32_t) + payload.size());
  std::memcpy(frame.data(), &net_len, sizeof(uint32_t));
  std::memcpy(frame.data() + sizeof(uint32_t), payload.data(), payload.size());
  return frame;
}

awaitable<std::string> read_frame(tcp::socket &socket) {
  uint32_t net_len = 0;
  co_await boost::asio::async_read(socket, boost::asio::buffer(&net_len, sizeof(net_len)),
                                  use_awaitable);
  uint32_t len = ntohl(net_len);
  if (len > kMaxMessageSize) {
    throw std::runtime_error("message too large");
  }
  std::string payload;
  payload.resize(len);
  if (len > 0) {
    co_await boost::asio::async_read(socket, boost::asio::buffer(payload), use_awaitable);
  }
  co_return payload;
}
} // namespace

class Client : public std::enable_shared_from_this<Client> {
public:
  Client(boost::asio::io_context &io, std::string name)
      : socket_(io), strand_(socket_.get_executor()), name_(std::move(name)) {}

  awaitable<void> connect(const std::string &host, const std::string &port) {
    tcp::resolver resolver(co_await boost::asio::this_coro::executor);
    auto endpoints = co_await resolver.async_resolve(host, port, use_awaitable);
    co_await boost::asio::async_connect(socket_, endpoints, use_awaitable);
    send(name_);
    co_spawn(strand_, [self = shared_from_this()]() -> awaitable<void> {
      co_return co_await self->reader();
    }, detached);
    co_return;
  }

  void send(const std::string &payload) {
    boost::asio::post(strand_, [self = shared_from_this(), payload]() {
      self->enqueue_frame(make_frame(payload));
    });
  }

private:
  awaitable<void> reader() {
    try {
      for (;;) {
        std::string payload = co_await read_frame(socket_);
        std::cout << payload << "\n";
      }
    } catch (const std::exception &ex) {
      std::cerr << "read error: " << ex.what() << "\n";
    }
    close();
    co_return;
  }

  awaitable<void> writer() {
    try {
      while (!outgoing_.empty()) {
        std::string frame = std::move(outgoing_.front());
        outgoing_.pop_front();
        co_await boost::asio::async_write(socket_, boost::asio::buffer(frame), use_awaitable);
      }
    } catch (const std::exception &ex) {
      std::cerr << "write error: " << ex.what() << "\n";
    }
    writing_ = false;
    co_return;
  }

  void enqueue_frame(std::string frame) {
    outgoing_.push_back(std::move(frame));
    if (writing_) {
      return;
    }
    writing_ = true;
    co_spawn(strand_, [self = shared_from_this()]() -> awaitable<void> {
      co_return co_await self->writer();
    }, detached);
  }

  void close() {
    boost::system::error_code ec;
    socket_.close(ec);
  }

  tcp::socket socket_;
  boost::asio::strand<boost::asio::any_io_executor> strand_;
  std::deque<std::string> outgoing_;
  bool writing_ = false;
  std::string name_;
};

int main(int argc, char **argv) {
  try {
    std::string host = "127.0.0.1";
    std::string port = "5555";
    std::string name = "anon";
    if (argc > 1) {
      host = argv[1];
    }
    if (argc > 2) {
      port = argv[2];
    }
    if (argc > 3) {
      name = argv[3];
    }

    boost::asio::io_context io;
    auto client = std::make_shared<Client>(io, name);

    co_spawn(io, [client, host, port]() -> awaitable<void> {
      co_await client->connect(host, port);
      co_return;
    }, detached);

    std::thread input_thread([client]() {
      std::string line;
      while (std::getline(std::cin, line)) {
        client->send(line);
      }
    });

    io.run();
    input_thread.join();
  } catch (const std::exception &ex) {
    std::cerr << "fatal: " << ex.what() << "\n";
    return 1;
  }
  return 0;
}
