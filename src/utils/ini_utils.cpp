/*
 * Copyright (C) 2026 lebachkhoa
 * Flatguard is free software: you can redistribute it and/or modify it under
 * the terms of the GNU General Public License as published by the Free Software Foundation,
 * either version 3 of the License, or (at your option) any later version.
 */

#include "ini_utils.h"
#include <sstream>
#include <string>
#include <vector>

namespace {
    // Flatpak metadata stores list values as semicolon-separated tokens.
    std::string trim(const std::string& s)
    {
        const std::string whitespace = " \t\n\r\f\v";
        const auto start = s.find_first_not_of(whitespace);
        if (start == std::string::npos) return "";

        const auto end = s.find_last_not_of(whitespace);
        const auto range = end - start + 1;
        return s.substr(start, range);
    }

    // Split a string by semicolons and trim whitespace from each token.
    std::vector<std::string> splitBySemicolon(const std::string& str)
    {
        std::vector<std::string> result;
        std::istringstream stream(str);
        std::string token;
        while (std::getline(stream, token, ';')) {
            std::string t = trim(token);
            if (!t.empty())
                result.push_back(t);
        }
        return result;
    }
}

// Read permissions from the INI file and populate the AppPermissions struct.
void FlatpakParser::parsePermissionsFromIni(CSimpleIniA& ini, AppPermissions& perm)
{
    auto readList = [&](const char* section, const char* key,
                        std::vector<std::string>& out) -> bool {
        const char* value = ini.GetValue(section, key, nullptr);
        if (!value)
            return false;
        out = splitBySemicolon(value);
        return true;
    };

    readList(SECTION_CONTEXT, KEY_SHARED, perm.shared);
    readList(SECTION_CONTEXT, KEY_SOCKETS, perm.sockets);
    readList(SECTION_CONTEXT, KEY_DEVICES, perm.devices);
    readList(SECTION_CONTEXT, KEY_FILESYSTEMS, perm.filesystems);
    readList(SECTION_CONTEXT, KEY_PERSISTENT, perm.persistent);
}