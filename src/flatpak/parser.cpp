/*
 * Copyright (C) 2026 lebachkhoa
 * Flatguard is free software: you can redistribute it and/or modify it under
 * the terms of the GNU General Public License as published by the Free Software Foundation,
 * either version 3 of the License, or (at your option) any later version.
 */

#include <iostream>
#include <sstream>
#include <cstdlib>
#include <filesystem>
#include "parser.h"
#include "SimpleIni.h"

// Flatpak metadata stores list values as semicolon-separated tokens.
static std::string trim(const std::string& s)
{
    const std::string whitespace = " \t\n\r\f\v";
    const auto start = s.find_first_not_of(whitespace);
    if(start == std::string::npos) return "";

    const auto end = s.find_last_not_of(whitespace);
    const auto range = end - start + 1;
    return s.substr(start, range);
}

static std::vector<std::string> splitBySemicolon(const std::string& str)
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

AppPermissions FlatpakParser::parseMetadata(const std::string& path)
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

    auto readList = [&](const char* section, const char* key,
                        std::vector<std::string>& out) -> bool {
        const char* value = ini.GetValue(section, key, nullptr);
        if (!value)
            return false;
        out = splitBySemicolon(value);
        return true;
    };

    readList(SECTION_CONTEXT, KEY_SHARED, permissions.shared);
    readList(SECTION_CONTEXT, KEY_SOCKETS, permissions.sockets);
    readList(SECTION_CONTEXT, KEY_DEVICES, permissions.devices);
    readList(SECTION_CONTEXT, KEY_FILESYSTEMS, permissions.filesystems);

    return permissions;
}

std::vector<AppPermissions> FlatpakParser::scanSystem() 
{
   std::string userPath;

   const char* xdgData = std::getenv("XDG_DATA_HOME");
   if(xdgData != nullptr && std::string(xdgData) != "") {
      userPath = std::string(xdgData) + "/flatpak/app/";
      std::cout << "Detected custom XDG path.\n";
   } else {
      const char* homeDir = std::getenv("HOME");   
      if(homeDir != nullptr) {
         userPath = std::string(homeDir) + "/.local/share/flatpak/app/";
      } else {
         std::cerr << "Error: Could not find HOME directory.\n";
      }
   }
   
   std::string systemPath = "/var/lib/flatpak/app/";
   std::vector<AppPermissions> allApps;

   for (const auto& basePath : std::initializer_list<std::string>{ systemPath, userPath }) 
   {
      if (!std::filesystem::exists(basePath)) continue;

      try
      {
         for (const auto& appDir : std::filesystem::directory_iterator(basePath)) 
         {
            std::filesystem::path metadataPath = appDir.path() / "current/active/metadata";

            if (std::filesystem::exists(metadataPath)) 
            {
               AppPermissions appPerms = parseMetadata(metadataPath.string());
               allApps.push_back(appPerms);
            }
         }
      }
      catch(const std::exception& e)
      {
         std::cerr << "Error parsing metadata: " << basePath << " - " << e.what() << '\n';
      }
   }

   return allApps;
}