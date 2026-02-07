#include <boost/asio.hpp>
#include <boost/system/error_code.hpp>

#include <arpa/inet.h>

#include <deque>
#include <cstring>
#include <iostream>
#include <memory>
#include <mutex>
#include <string>
#include <unordered_map>
#include <unordered_set>

using boost::asio::awaitable;
using boost::asio::co_spawn;
using boost::asio::detached;
using boost::asio::ip::tcp;
using boost::asio::use_awaitable;

namespace {
constexpr std::size_t kMaxMessageSize = 8 * 1024 * 1024; // 8 MB
constexpr std::size_t kMaxNameSize = 64;

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

class Server;

struct ServerOptions {
  bool system_messages = true;
  std::string join_format = "* {name} joined *";
  std::string leave_format = "* {name} left *";
};

std::string format_system_message(const std::string &fmt, const std::string &name) {
  std::string out;
  out.reserve(fmt.size() + name.size());
  std::size_t pos = 0;
  while (true) {
    std::size_t found = fmt.find("{name}", pos);
    if (found == std::string::npos) {
      out.append(fmt.substr(pos));
      break;
    }
    out.append(fmt.substr(pos, found - pos));
    out.append(name);
    pos = found + 6;
  }
  return out;
}

class Session : public std::enable_shared_from_this<Session> {
public:
  Session(tcp::socket socket, Server &server)
      : socket_(std::move(socket)), server_(server), strand_(socket_.get_executor()) {
    boost::system::error_code ec;
    auto ep = socket_.remote_endpoint(ec);
    if (!ec) {
      remote_ = ep.address().to_string() + ":" + std::to_string(ep.port());
    }
  }

  void start();
  void deliver(const std::string &payload);
  std::string remote_address() const;
  std::string name() const { return name_; }

private:
  awaitable<void> reader();
  awaitable<void> writer();
  void enqueue_frame(std::string frame);
  void close();

  tcp::socket socket_;
  Server &server_;
  boost::asio::strand<boost::asio::any_io_executor> strand_;
  std::deque<std::string> outgoing_;
  bool writing_ = false;
  std::string name_;
  std::string remote_ = "unknown";
};

class Server {
public:
  Server(boost::asio::io_context &io, uint16_t port, ServerOptions options)
      : io_(io), acceptor_(io, tcp::endpoint(tcp::v4(), port)), options_(std::move(options)) {}

  void run() {
    co_spawn(io_, [this]() -> awaitable<void> { co_return co_await accept_loop(); }, detached);
  }

  void join(const std::shared_ptr<Session> &session) {
    std::lock_guard<std::mutex> lock(mutex_);
    clients_.insert(session);
  }

  void leave(const std::shared_ptr<Session> &session) {
    std::lock_guard<std::mutex> lock(mutex_);
    if (!session->name().empty()) {
      name_map_.erase(session->name());
    }
    clients_.erase(session);
  }

  bool register_name(const std::shared_ptr<Session> &session, const std::string &name) {
    std::lock_guard<std::mutex> lock(mutex_);
    if (name_map_.count(name) > 0) {
      return false;
    }
    name_map_[name] = session;
    return true;
  }

  void broadcast(const std::shared_ptr<Session> &from, const std::string &payload) {
    std::string framed = "[" + from->name() + "] " + payload;
    std::lock_guard<std::mutex> lock(mutex_);
    for (const auto &client : clients_) {
      if (client != from) {
        client->deliver(framed);
      }
    }
  }

  void broadcast_all(const std::string &payload) {
    std::lock_guard<std::mutex> lock(mutex_);
    for (const auto &client : clients_) {
      client->deliver(payload);
    }
  }

  bool send_direct(const std::shared_ptr<Session> &from, const std::string &target,
                   const std::string &payload) {
    std::shared_ptr<Session> to;
    {
      std::lock_guard<std::mutex> lock(mutex_);
      auto it = name_map_.find(target);
      if (it == name_map_.end()) {
        return false;
      }
      to = it->second;
    }
    to->deliver("[from " + from->name() + "] " + payload);
    return true;
  }

  void broadcast_system_join(const std::string &name) {
    if (!options_.system_messages) {
      return;
    }
    broadcast_all(format_system_message(options_.join_format, name));
  }

  void broadcast_system_leave(const std::string &name) {
    if (!options_.system_messages) {
      return;
    }
    broadcast_all(format_system_message(options_.leave_format, name));
  }

private:
  awaitable<void> accept_loop() {
    for (;;) {
      tcp::socket socket = co_await acceptor_.async_accept(use_awaitable);
      auto session = std::make_shared<Session>(std::move(socket), *this);
      join(session);
      session->start();
    }
  }

  boost::asio::io_context &io_;
  tcp::acceptor acceptor_;
  std::unordered_set<std::shared_ptr<Session>> clients_;
  std::unordered_map<std::string, std::shared_ptr<Session>> name_map_;
  std::mutex mutex_;
  ServerOptions options_;
};

void Session::start() {
  co_spawn(strand_, [self = shared_from_this()]() -> awaitable<void> {
    co_return co_await self->reader();
  }, detached);
}

void Session::deliver(const std::string &payload) {
  boost::asio::dispatch(strand_, [self = shared_from_this(), payload]() {
    self->enqueue_frame(make_frame(payload));
  });
}

std::string Session::remote_address() const {
  return remote_;
}

awaitable<void> Session::reader() {
  try {
    std::string name = co_await read_frame(socket_);
    if (name.empty() || name.size() > kMaxNameSize) {
      throw std::runtime_error("invalid name");
    }
    if (!server_.register_name(shared_from_this(), name)) {
      throw std::runtime_error("name already in use");
    }
    name_ = name;
    std::cerr << "client connected: " << name_ << " (" << remote_address() << ")\n";
    server_.broadcast_system_join(name_);
    for (;;) {
      std::string payload = co_await read_frame(socket_);
      if (!payload.empty() && payload[0] == '@') {
        auto space = payload.find(' ');
        if (space != std::string::npos && space > 1) {
          std::string target = payload.substr(1, space - 1);
          std::string message = payload.substr(space + 1);
          if (!server_.send_direct(shared_from_this(), target, message)) {
            deliver("system: user not found: " + target);
          }
        } else {
          deliver("system: invalid direct message format, use @name message");
        }
      } else {
        server_.broadcast(shared_from_this(), payload);
      }
    }
  } catch (const std::exception &ex) {
    std::cerr << "client error: " << remote_address() << ": " << ex.what() << "\n";
  }
  close();
  co_return;
}

awaitable<void> Session::writer() {
  try {
    while (!outgoing_.empty()) {
      std::string frame = std::move(outgoing_.front());
      outgoing_.pop_front();
      co_await boost::asio::async_write(socket_, boost::asio::buffer(frame), use_awaitable);
    }
  } catch (const std::exception &ex) {
    std::cerr << "write error: " << remote_address() << ": " << ex.what() << "\n";
  }
  writing_ = false;
  co_return;
}

void Session::enqueue_frame(std::string frame) {
  outgoing_.push_back(std::move(frame));
  if (writing_) {
    return;
  }
  writing_ = true;
  co_spawn(strand_, [self = shared_from_this()]() -> awaitable<void> {
    co_return co_await self->writer();
  }, detached);
}

void Session::close() {
  boost::system::error_code ec;
  socket_.close(ec);
  server_.leave(shared_from_this());
  if (!name_.empty()) {
    std::cerr << "client disconnected: " << name_ << " (" << remote_address() << ")\n";
    server_.broadcast_system_leave(name_);
  } else {
    std::cerr << "client disconnected: " << remote_address() << "\n";
  }
}

bool parse_port(const std::string &arg, uint16_t &port) {
  try {
    int value = std::stoi(arg);
    if (value < 1 || value > 65535) {
      return false;
    }
    port = static_cast<uint16_t>(value);
    return true;
  } catch (...) {
    return false;
  }
}

void print_usage(const char *program) {
  std::cerr << "Использование: " << program << " [port] [options]\n"
            << "Опции:\n"
            << "  --help, -h             Показать эту справку и выйти\n"
            << "  --port, -p <port>       Порт прослушивания (1-65535)\n"
            << "  --no-system, -n         Отключить системные сообщения join/leave\n"
            << "  --join-format, -j <fmt> Формат join (используйте {name})\n"
            << "  --leave-format, -l <fmt> Формат leave (используйте {name})\n";
}

int main(int argc, char **argv) {
  try {
    uint16_t port = 5555;
    ServerOptions options;
    bool port_set = false;

    for (int i = 1; i < argc; ++i) {
      std::string arg = argv[i];
      if (arg == "--help" || arg == "-h") {
        print_usage(argv[0]);
        return 0;
      } else if (arg == "--no-system" || arg == "-n") {
        options.system_messages = false;
      } else if ((arg == "--port" || arg == "-p") && i + 1 < argc) {
        if (!parse_port(argv[++i], port)) {
          throw std::runtime_error("invalid port");
        }
        port_set = true;
      } else if ((arg == "--join-format" || arg == "-j") && i + 1 < argc) {
        options.join_format = argv[++i];
      } else if ((arg == "--leave-format" || arg == "-l") && i + 1 < argc) {
        options.leave_format = argv[++i];
      } else if (!arg.empty() && arg[0] != '-' && !port_set) {
        if (!parse_port(arg, port)) {
          throw std::runtime_error("invalid port");
        }
        port_set = true;
      } else {
        throw std::runtime_error("unknown argument: " + arg);
      }
    }

    boost::asio::io_context io;
    Server server(io, port, options);
    server.run();

    std::cerr << "listening on port " << port << "\n";
    io.run();
  } catch (const std::exception &ex) {
    std::cerr << "fatal: " << ex.what() << "\n";
    return 1;
  }
  return 0;
}
