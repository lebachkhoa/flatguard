/*
 * Copyright (C) 2026 lebachkhoa
 * Flatguard is free software: you can redistribute it and/or modify it under
 * the terms of the GNU General Public License as published by the Free Software Foundation,
 * either version 3 of the License, or (at your option) any later version.
 */

#include <algorithm>
#include <cstdlib>
#include <filesystem>
#include <iostream>
#include "parser.h"
#include "override.h"
#include "../utils/ini_utils.h"

static void applyOverrideFile(AppPermissions& permissions, const std::filesystem::path& overridePath)
{
    if (!std::filesystem::exists(overridePath))
        return;

    CSimpleIniA ini;
    SI_Error rc = ini.LoadFile(overridePath.string().c_str());
    if (rc < 0) {
        std::cerr << "Failed to load override file: " << overridePath << "\n";
        return;
    }

    AppPermissions overridePerms;
    FlatpakParser::parsePermissionsFromIni(ini, overridePerms);

    auto applyList = [](std::vector<std::string>& base, const std::vector<std::string>& overrides) {
        for (const auto& token : overrides) {
            if (!token.empty() && token[0] == '!') {
                const std::string denied = token.substr(1);
                base.erase(std::remove(base.begin(), base.end(), denied), base.end());
            } else {
                if (std::find(base.begin(), base.end(), token) == base.end())
                    base.push_back(token);
            }
        }
    };

    applyList(permissions.shared, overridePerms.shared);
    applyList(permissions.sockets, overridePerms.sockets);
    applyList(permissions.devices, overridePerms.devices);
    applyList(permissions.filesystems, overridePerms.filesystems);
    applyList(permissions.persistent, overridePerms.persistent);
}

void FlatpakParser::applyOverrides(AppPermissions& permissions, const std::filesystem::path& appPath)
{
    std::filesystem::path installOverride =
        appPath.parent_path().parent_path() / "overrides" / permissions.appId;

    // Per-user override ($XDG_DATA_HOME or ~/.local/share)
    std::filesystem::path userBase;
    const char* xdgData = std::getenv("XDG_DATA_HOME");
    if (xdgData != nullptr && std::string(xdgData) != "") {
        userBase = std::filesystem::path(xdgData) / "flatpak" / "overrides";
    }  
    else if (const char* home = std::getenv("HOME")) {
        userBase = std::filesystem::path(home) / ".local" / "share" / "flatpak" / "overrides";
    }
        
    std::filesystem::path userOverride = userBase / permissions.appId;

    applyOverrideFile(permissions, installOverride);
    if (userOverride != installOverride) {
        applyOverrideFile(permissions, userOverride);
    }
}