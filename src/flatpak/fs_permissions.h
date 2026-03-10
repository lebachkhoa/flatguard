/*
 * Copyright (C) 2026 lebachkhoa
 * Flatguard is free software: you can redistribute it and/or modify it under
 * the terms of the GNU General Public License as published by the Free Software Foundation,
 * either version 3 of the License, or (at your option) any later version.
 */

#pragma once
#include <string>
#include <vector>

enum class FsAccess
{
    ReadWrite,      // Read-write access (no suffix)
    ReadOnly,       // Read-only access (:ro)
    Create          // Create read-write access (:create)
};

struct FsPermission
{
    std::string path; 
    FsAccess fsaccess;
};

namespace FlatpakParser
{
    std::vector<FsPermission> parseFilesystemPermissions(const std::vector<std::string>& fsEntries);
};
