/*
 * Copyright (C) 2026 lebachkhoa
 * Flatguard is free software: you can redistribute it and/or modify it under
 * the terms of the GNU General Public License as published by the Free Software Foundation,
 * either version 3 of the License, or (at your option) any later version.
 */

#include "fs_permissions.h"
#include <filesystem>

// Flatpak filesystem entries have the form:
// <path>[:<access>]
// <path>   : logical name (home, host, xdg-*, /absolute, ~/relative, ...)
// <access> : ro | create

std::vector<FsPermission> FlatpakParser::parseFilesystemPermissions(const std::vector<std::string>& fsEntries)
{
    std::vector<FsPermission> permissions;

    for (const auto& entry : fsEntries) {
        if (entry.empty()) continue;

        // Skip deny entries (prefixed with '!')
        if (entry.front() == '!') continue;

        // Split on the first ':' to separate path from access modifier
        const auto colonPos = entry.find(':');
        std::string path   = (colonPos != std::string::npos) ? entry.substr(0, colonPos) : entry;
        std::string access = (colonPos != std::string::npos) ? entry.substr(colonPos + 1) : "";

        FsAccess fsAccess;
        if (access == "ro") {
            fsAccess = FsAccess::ReadOnly;
        } else if (access == "create") {
            fsAccess = FsAccess::Create;
        } else {
            fsAccess = FsAccess::ReadWrite;
        }

        permissions.push_back({ path, fsAccess });
    }

    return permissions;
}