/*
 * Copyright (C) 2026 lebachkhoa
 * Flatguard is free software: you can redistribute it and/or modify it under
 * the terms of the GNU General Public License as published by the Free Software Foundation,
 * either version 3 of the License, or (at your option) any later version.
 */

#include <iostream>
#include <cstdlib>
#include <filesystem>
#include "parser.h"
#include "../../third_party/SimpleIni.h"
#include "../utils/ini_utils.h"
#include "override.h"

AppPermissions FlatpakParser::parseMetadata(const std::filesystem::path& path)
{
    AppPermissions permissions;

    CSimpleIniA ini;
    SI_Error rc = ini.LoadFile(path.c_str());
    if (rc < 0) {
        std::cerr << "Failed to load metadata file: " << path << "\n";
        permissions.appId = "unknown";
        return permissions;
    }

    permissions.appId = ini.GetValue(SECTION_APPLICATION, KEY_NAME, "unknown");

    parsePermissionsFromIni(ini, permissions);

    return permissions;
}

std::vector<AppPermissions> FlatpakParser::scanSystem()
{
    std::filesystem::path userPath;

    const char* xdgData = std::getenv("XDG_DATA_HOME");
    if (xdgData != nullptr && std::string(xdgData) != "") {
        userPath = std::filesystem::path(xdgData) / "flatpak" / "app";
    } else {
        const char* homeDir = std::getenv("HOME");
        if (homeDir != nullptr) {
            userPath = std::filesystem::path(homeDir) / ".local" / "share" / "flatpak" / "app";
        } else {
            std::cerr << "Error: Could not find HOME directory.\n";
        }
    }

    std::filesystem::path systemPath = "/var/lib/flatpak/app";
    std::vector<AppPermissions> allApps;

    for (const auto& basePath : std::initializer_list<std::filesystem::path>{ systemPath, userPath }) {
        if (!std::filesystem::exists(basePath)) continue;

        try {
            for (const auto& appDir : std::filesystem::directory_iterator(basePath))
            {
                std::filesystem::path metadataPath = appDir.path() / "current/active/metadata";

                if (std::filesystem::exists(metadataPath)){
                    AppPermissions appPerms = parseMetadata(metadataPath);
                    applyOverrides(appPerms, appDir.path());
                    allApps.push_back(appPerms);
                }
            }
        }
        catch (const std::exception& e) {
            std::cerr << "Error parsing metadata: " << basePath << " - " << e.what() << '\n';
        }
    }

    return allApps;
}
