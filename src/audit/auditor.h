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
            Severity::CRITICAL, "App can access all hardware devices (webcam, etc.)"
        },
        {
            "FS_01", "Home Access", "filesystems", "home", 
            Severity::INFO, "App can read/write your entire personal home directory."
        },
        {
            "FS_02", "Host Filesystem Access", "filesystems", "host", 
            Severity::CRITICAL, "App has access to the entire host OS filesystem."
        },
        {
            "SOC_01", "X11 Risk", "sockets", "x11", 
            Severity::INFO, "X11 protocol is insecure and allows keylogging."
        },
        {
            "NET_01", "Network Access", "shared", "network", 
            Severity::INFO, "App can communicate over the internet."
        },
        {
            "DBUS_01", "D-Bus Session Access", "sockets", "session-bus", 
            Severity::WARNING, "App can talk to other apps, potential sandbox escape."
        }
    };

    std::vector<AuditIssue> auditApp(const AppPermissions& app);
    std::vector<AuditIssue> auditAll(const std::vector<AppPermissions>& apps);
};