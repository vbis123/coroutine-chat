#include "chat_framing.hpp"

#include <cassert>
#include <string>

int main() {
  const std::string payload = "hello";
  const std::string frame = chat::make_frame(payload);

  assert(frame.size() == sizeof(std::uint32_t) + payload.size());
  assert(chat::decode_frame_size(frame.data()) == payload.size());
  assert(frame.substr(sizeof(std::uint32_t)) == payload);

  const std::string empty_frame = chat::make_frame("");
  assert(empty_frame.size() == sizeof(std::uint32_t));
  assert(chat::decode_frame_size(empty_frame.data()) == 0);
}
