cmake_minimum_required(VERSION 3.28)
set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED True)
project(HotPatchLab VERSION 1.0.0)

set(CROW_INSTALL OFF)
set(CROW_USE_BOOST ON)

include(FetchContent)
FetchContent_Declare(
  Boost
  GIT_REPOSITORY https://github.com/boostorg/boost.git
  GIT_PROGRESS TRUE
  GIT_TAG boost-1.82.0
)
FetchContent_Declare(
  Crow
  GIT_REPOSITORY https://github.com/CrowCpp/Crow.git
  GIT_PROGRESS TRUE
  GIT_TAG v1.2.1
)
FetchContent_MakeAvailable(Boost Crow)

set(CMAKE_EXPORT_COMPILE_COMMANDS ON)
file(GLOB_RECURSE sources src/*.cpp)
add_executable(${PROJECT_NAME} ${sources})

set_property(TARGET ${PROJECT_NAME} PROPERTY INTERPROCEDURAL_OPTIMIZATION)

target_link_libraries(${PROJECT_NAME}
  PRIVATE
  Crow::Crow
  # Boost::asio
)

include_directories(include)

# target_compile_options(HotPatchLab PRIVATE -Wall -Wextra -Werror -Wshadow -O3)
