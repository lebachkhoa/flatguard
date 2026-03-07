/*
 * Copyright (C) 2026 lebachkhoa
 * Flatguard is free software: you can redistribute it and/or modify it under
 * the terms of the GNU General Public License as published by the Free Software Foundation,
 * either version 3 of the License, or (at your option) any later version.
 */

#pragma once
#include <filesystem>
#include "parser.h"

namespace FlatpakParser
{
    void applyOverrides(AppPermissions& permissions, const std::filesystem::path& appPath);
};
