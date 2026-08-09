cmake_minimum_required(VERSION 3.16)
project(coroutine_chat LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

find_package(Boost REQUIRED COMPONENTS system)

add_executable(chat_server src/server.cpp)
target_include_directories(chat_server PRIVATE include)
target_link_libraries(chat_server PRIVATE Boost::system)

target_compile_options(chat_server PRIVATE -Wall -Wextra -Wpedantic)

add_executable(chat_client src/client.cpp)
target_include_directories(chat_client PRIVATE include)
target_link_libraries(chat_client PRIVATE Boost::system)

target_compile_options(chat_client PRIVATE -Wall -Wextra -Wpedantic)

include(CTest)
if(BUILD_TESTING)
  add_executable(framing_test tests/framing_test.cpp)
  target_include_directories(framing_test PRIVATE include)
  target_link_libraries(framing_test PRIVATE Boost::system)
  target_compile_options(framing_test PRIVATE -Wall -Wextra -Wpedantic)
  add_test(NAME framing COMMAND framing_test)
endif()
