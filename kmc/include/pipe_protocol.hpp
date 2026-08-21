#pragma once

#include <windows.h>

#include <cstdint>
#include <string>

bool read_frame(HANDLE pipe, std::string& payload);
bool write_frame(HANDLE pipe, const std::string& payload);
