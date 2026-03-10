/*
 * Copyright (C) 2026 lebachkhoa
 * Flatguard is free software: you can redistribute it and/or modify it under
 * the terms of the GNU General Public License as published by the Free Software Foundation,
 * either version 3 of the License, or (at your option) any later version.
 */

#include "auditor.h"
#include "flatpak/fs_permissions.h"
#include <algorithm>

std::vector<AuditIssue> Auditor::auditApp(const AppPermissions& app)
{
    std::vector<AuditIssue> issues;

    // Helper: check if a plain permission list contains a given value
    auto contains = [](const std::vector<std::string>& v, const std::string& val) {
        return std::find(v.begin(), v.end(), val) != v.end();
    };

    // Parse filesystem entries into structured FsPermission objects so that
    // entries like "home:ro" are correctly matched by path regardless of suffix.
    const std::vector<FsPermission> fsParsed =
        FlatpakParser::parseFilesystemPermissions(app.filesystems);

    // Helper: check if any parsed filesystem entry has a given path (no suffix, read-write).
    auto containsFsPath = [&](const std::string& path) {
        return std::any_of(fsParsed.begin(), fsParsed.end(),
            [&](const FsPermission& p) {
                return p.path == path && p.fsaccess == FsAccess::ReadWrite;
            });
    };

    // Helper: check if any parsed filesystem entry has a given path with :create access.
    auto containsFsPathCreatable = [&](const std::string& path) {
        return std::any_of(fsParsed.begin(), fsParsed.end(),
            [&](const FsPermission& p) {
                return p.path == path && p.fsaccess == FsAccess::Create;
            });
    };

    // Helper: check if any parsed filesystem entry has a given path with :ro access.
    auto containsFsPathReadOnly = [&](const std::string& path) {
        return std::any_of(fsParsed.begin(), fsParsed.end(),
            [&](const FsPermission& p) {
                return p.path == path && p.fsaccess == FsAccess::ReadOnly;
            });
    };

    // ── Single-permission rules ──────────────────────────────────────────────
    for (const auto& rule : securityRules) 
    {
        const auto& field   = rule.target_field;
        const auto& pattern = rule.pattern;

        bool matched = false;
        if (field == "devices") {
            matched = contains(app.devices, pattern);
        } else if (field == "sockets") {
            matched = contains(app.sockets, pattern);
        } else if (field == "shared") {
            matched = contains(app.shared, pattern);
        } else if (field == "filesystems") {
            matched = containsFsPath(pattern) || containsFsPathCreatable(pattern) || containsFsPathReadOnly(pattern);
        } else if (field == "persistent") {
            matched = contains(app.persistent, pattern);
        }

        if (!matched) continue;

        // Adjust severity and description when filesystem access is read-only:
        // downgrade one level (CRITICAL→WARNING, WARNING→INFO).
        // Only applies when there is no rw/create entry for the same path.
        Severity sev = rule.severity;
        std::string desc = rule.description;
        if (field == "filesystems" && rule.severity > Severity::INFO
                && containsFsPathReadOnly(pattern)
                && !containsFsPath(pattern) && !containsFsPathCreatable(pattern)) {
            sev = (rule.severity == Severity::CRITICAL) ? Severity::WARNING : Severity::INFO;
            // Replace "read/write" wording with "read-only" in the description.
            const std::string rw = "read/write";
            auto pos = desc.find(rw);
            if (pos != std::string::npos)
                desc.replace(pos, rw.size(), "read-only");
        }

        issues.push_back({app.appId, rule.id, sev, desc});
    }

    // ── Combo rules: dangerous permission combinations ───────────────────────
    bool hasNetwork  = contains(app.shared,  "network");
    bool hasHome     = containsFsPath("home") || containsFsPathCreatable("home") || containsFsPathReadOnly("home");
    bool hasHost     = containsFsPath("host") || containsFsPathCreatable("host") || containsFsPathReadOnly("host");
    bool hasX11      = contains(app.sockets, "x11");
    bool hasDevices  = contains(app.devices, "all");

    // Combo is CRITICAL only when home/host has write access (ro is still bad but less so).
    if (hasNetwork && hasHome) {
        bool writable = containsFsPath("home") || containsFsPathCreatable("home");
        Severity sev = writable ? Severity::CRITICAL : Severity::WARNING;
        issues.push_back({app.appId, "COMBO_01", sev,
            "App can exfiltrate personal files over the internet."});
    }

    if (hasNetwork && hasHost) {
        bool writable = containsFsPath("host") || containsFsPathCreatable("host");
        Severity sev = writable ? Severity::CRITICAL : Severity::WARNING;
        issues.push_back({app.appId, "COMBO_02", sev,
            "App can exfiltrate the entire host filesystem over the internet."});
    }

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