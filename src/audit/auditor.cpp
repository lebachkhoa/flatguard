/*
 * Copyright (C) 2026 lebachkhoa
 * Flatguard is free software: you can redistribute it and/or modify it under
 * the terms of the GNU General Public License as published by the Free Software Foundation,
 * either version 3 of the License, or (at your option) any later version.
 */

#include "auditor.h"
#include <iostream>
#include <algorithm>

std::vector<AuditIssue> Auditor::auditApp(const AppPermissions& app)
{
    std::vector<AuditIssue> issues;

    // Helper: check if a permission list contains a given value
    auto contains = [](const std::vector<std::string>& v, const std::string& val) {
        return std::find(v.begin(), v.end(), val) != v.end();
    };

    // ── Single-permission rules ──────────────────────────────────────────────
    for (const auto& rule : securityRules) 
    {
        const auto& field   = rule.target_field;
        const auto& pattern = rule.pattern;

        const std::vector<std::string>* list = nullptr;
        if      (field == "devices")     list = &app.devices;
        else if (field == "filesystems") list = &app.filesystems;
        else if (field == "sockets")     list = &app.sockets;
        else if (field == "shared")      list = &app.shared;

        if (!list) continue;
        if (!contains(*list, pattern)) continue;

        issues.push_back({app.appId, rule.id, rule.severity, rule.description});
    }

    // ── Combo rules: dangerous permission combinations ───────────────────────
    bool hasNetwork = contains(app.shared,      "network");
    bool hasHome    = contains(app.filesystems, "home");
    bool hasHost    = contains(app.filesystems, "host");
    bool hasX11     = contains(app.sockets,     "x11");
    bool hasDevices = contains(app.devices,     "all");

    if (hasNetwork && hasHome)
        issues.push_back({app.appId, "COMBO_01", Severity::CRITICAL,
            "App can exfiltrate personal files over the internet."});

    if (hasNetwork && hasHost)
        issues.push_back({app.appId, "COMBO_02", Severity::CRITICAL,
            "App can exfiltrate the entire host filesystem over the internet."});

    if (hasNetwork && hasX11)
        issues.push_back({app.appId, "COMBO_03", Severity::CRITICAL,
            "App can capture keystrokes and transmit them remotely."});

    if (hasNetwork && hasDevices)
        issues.push_back({app.appId, "COMBO_04", Severity::CRITICAL,
            "App can stream webcam/microphone over the internet."});

    return issues;
}

std::vector<AuditIssue> Auditor::auditAll(const std::vector<AppPermissions>& apps)
{
    std::vector<AuditIssue> issues;

    for (const auto& app : apps) 
    {
        auto appIssues = auditApp(app);
        issues.insert(issues.end(), appIssues.begin(), appIssues.end());
    }

    return issues;
}