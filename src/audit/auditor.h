/*
 * Copyright (C) 2026 lebachkhoa
 * Flatguard is free software: you can redistribute it and/or modify it under
 * the terms of the GNU General Public License as published by the Free Software Foundation,
 * either version 3 of the License, or (at your option) any later version.
 */

#pragma once
#include <string>
#include <vector>
#include "flatpak/parser.h"

enum class Severity
{
    INFO,
    WARNING,
    CRITICAL
};

struct SecurityRule
{
    std::string id;
    std::string name;
    std::string target_field;
    std::string pattern;
    Severity severity;
    std::string description;
};

struct AuditIssue
{
    std::string appId;
    std::string ruleId;
    Severity severity;
    std::string description;
};

namespace Auditor
{
    inline const std::vector<SecurityRule> securityRules = {
        {
            "DEV_01", "Full Device Access", "devices", "all", 
            Severity::CRITICAL, "App has full access to all hardware devices (webcam, etc.)"
        },
        {
            "FS_01", "Home Access", "filesystems", "home", 
            Severity::WARNING, "App has read/write access to your entire home directory."
        },
        {
            "FS_02", "Host Filesystem Access", "filesystems", "host", 
            Severity::CRITICAL, "App has full read/write access to the entire host OS filesystem."
        },
        {
            "SOC_01", "X11 Risk", "sockets", "x11", 
            Severity::INFO, "X11 protocol is insecure and allows keylogging."
        },
        {
            "NET_01", "Network Access", "shared", "network", 
            Severity::INFO, "App has full network access."
        },
        {
            "DBUS_01", "D-Bus Session Access", "sockets", "session-bus", 
            Severity::WARNING, "App has full access to D-Bus session, potential sandbox escape."
        },
        {
            "PERSIST_01", "Full Home Persistence", "persistent", ".",
            Severity::CRITICAL, "App has full persistence of entire home directory outside sandbox."
        },
        {
            "PERSIST_02", "Config Directory Persistence", "persistent", ".config",
            Severity::WARNING, "App has full persistence of all configuration files outside sandbox."
        },
        {
            "PERSIST_03", "SSH Keys Persistence",  "persistent", ".ssh", 
            Severity::CRITICAL, "App has full persistence of SSH keys."
        },
        {
            "PERSIST_04", "GPG Keys Persistence",  "persistent", ".gnupg", 
            Severity::CRITICAL, "App has full persistence of GPG keys."
        },
    };

    std::vector<AuditIssue> auditApp(const AppPermissions& app);
    std::vector<AuditIssue> auditAll(const std::vector<AppPermissions>& apps);
};