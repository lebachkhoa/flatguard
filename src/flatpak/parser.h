/*
 * Copyright (C) 2026 lebachkhoa
 * Flatguard is free software: you can redistribute it and/or modify it under
 * the terms of the GNU General Public License as published by the Free Software Foundation,
 * either version 3 of the License, or (at your option) any later version.
 */

#pragma once
#include <filesystem>
#include <string>
#include <vector>
#include <set>

struct AppPermissions
{
    std::string appId;
    std::vector<std::string> shared;
    std::vector<std::string> sockets;
    std::vector<std::string> devices;
    std::vector<std::string> filesystems;
};

namespace FlatpakParser
{
    inline constexpr const char* SECTION_APPLICATION   = "Application";
    inline constexpr const char* KEY_NAME              = "name";

    inline constexpr const char* SECTION_CONTEXT       = "Context";
    inline constexpr const char* KEY_SHARED            = "shared";
    inline constexpr const char* KEY_SOCKETS           = "sockets";
    inline constexpr const char* KEY_DEVICES           = "devices";
    inline constexpr const char* KEY_FILESYSTEMS       = "filesystems";

    AppPermissions parseMetadata(const std::filesystem::path& path);
    std::vector<AppPermissions> scanSystem();
};
