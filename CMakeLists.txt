cmake_minimum_required(VERSION 3.24)

project(crypto-module VERSION 0.1.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

if(NOT CMAKE_SYSTEM_NAME STREQUAL "Windows")
  message(FATAL_ERROR "KMC targets Windows (named pipes + VS2022).")
endif()

add_subdirectory(kmc)
