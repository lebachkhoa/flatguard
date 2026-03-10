/*
 * Copyright (C) 2026 lebachkhoa
 * Flatguard is free software: you can redistribute it and/or modify it under
 * the terms of the GNU General Public License as published by the Free Software Foundation,
 * either version 3 of the License, or (at your option) any later version.
 */

#include "flatpak/parser.h"
#include "audit/auditor.h"
#include "color.h"
#include "cxxopts.hpp"
#include <iostream>
#include <vector>
#include <string>
#include <algorithm>
#include <sstream>

static const std::string SEP(50, '-');

// Severity label padded to fixed width for alignment: [CRITICAL] / [WARNING]  / [INFO]    
static std::string sevLabel(Severity s)
{
    if (s == Severity::CRITICAL) return "[CRITICAL]";
    if (s == Severity::WARNING)  return "[WARNING] ";
    return                              "[INFO]    ";
}

static const char* sevColor(Severity s)
{
    if (s == Severity::CRITICAL) return RED;
    if (s == Severity::WARNING)  return YELLOW;
    return CYAN;
}

// Join a string vector with a separator; return "None" if empty
static std::string joinOrNone(const std::vector<std::string>& v, const std::string& sep = ", ")
{
    if (v.empty()) return "None";
    std::string out;
    for (size_t i = 0; i < v.size(); ++i) {
        if (i) out += sep;
        out += v[i];
    }
    return out;
}

// Escape special characters for JSON strings
static std::string jsonEscape(const std::string& s)
{
    std::string out;
    out.reserve(s.size());
    for (char c : s) {
        switch (c) {
            case '"':  out += "\\\""; break;
            case '\\': out += "\\\\"; break;
            case '\n': out += "\\n";  break;
            case '\r': out += "\\r";  break;
            case '\t': out += "\\t";  break;
            default:   out += c;      break;
        }
    }
    return out;
}

void printAuditIssuesJson(const std::vector<AppPermissions>& apps,
                          const std::vector<AuditIssue>&    allIssues)
{
    std::cout << "[\n";
    for (size_t ai = 0; ai < apps.size(); ++ai) {
        const auto& app = apps[ai];

        // Collect issues for this app
        std::vector<const AuditIssue*> appIssues;
        for (const auto& issue : allIssues)
            if (issue.appId == app.appId) {
                appIssues.push_back(&issue);
            }

        bool hasAllDev = std::find(app.devices.begin(), app.devices.end(), "all") != app.devices.end();

        std::cout << "  {\n";
        std::cout << "    \"appId\": \""       << jsonEscape(app.appId) << "\",\n";

        // permissions object
        std::cout << "    \"permissions\": {\n";

        std::cout << "      \"shared\": [";
        for (size_t si = 0; si < app.shared.size(); ++si) {
            if (si) {
                std::cout << ", ";
            }
            std::cout << "\"" << jsonEscape(app.shared[si]) << "\"";
        }
        std::cout << "],\n";

        std::cout << "      \"sockets\": [";
        for (size_t si = 0; si < app.sockets.size(); ++si) {
            if (si) {
                std::cout << ", ";
            }
            std::cout << "\"" << jsonEscape(app.sockets[si]) << "\"";
        }
        std::cout << "],\n";

        if (hasAllDev) {
            std::cout << "      \"devices\": \"all\",\n";
        } else {
            std::cout << "      \"devices\": [";
            for (size_t di = 0; di < app.devices.size(); ++di) {
                if (di) {
                    std::cout << ", ";
                }
                std::cout << "\"" << jsonEscape(app.devices[di]) << "\"";
            }
            std::cout << "],\n";
        }

        std::cout << "      \"files\": [";
        for (size_t fi = 0; fi < app.filesystems.size(); ++fi) {
            if (fi) {
                std::cout << ", ";
            }
            std::cout << "\"" << jsonEscape(app.filesystems[fi]) << "\"";
        }
        std::cout << "],\n";

        std::cout << "      \"persistent\": [";
        for (size_t pi = 0; pi < app.persistent.size(); ++pi) {
            if (pi) {
                std::cout << ", ";
            }
            std::cout << "\"" << jsonEscape(app.persistent[pi]) << "\"";
        }
        std::cout << "]\n";
        std::cout << "    },\n";

        // issues array
        std::cout << "    \"issues\": [\n";
        bool firstIssue = true;
        for (const auto* issue : appIssues) {
            if (!firstIssue) std::cout << ",\n";
            firstIssue = false;

            std::string sev;
            if (issue->severity == Severity::CRITICAL) {
                sev = "CRITICAL";
            } else if (issue->severity == Severity::WARNING) {
                sev = "WARNING";
            } else {
                sev = "INFO";
            }
            std::cout << "      {\n";
            std::cout << "        \"ruleId\": \""      << jsonEscape(issue->ruleId)      << "\",\n";
            std::cout << "        \"severity\": \""    << sev                             << "\",\n";
            std::cout << "        \"description\": \"" << jsonEscape(issue->description) << "\"\n";
            std::cout << "      }";
        }
        if (!firstIssue) {
            std::cout << "\n";
        }
        std::cout << "    ]\n";
        std::cout << "  }";
        if (ai + 1 < apps.size()) {
            std::cout << ",";
        }
        std::cout << "\n";
    }
    std::cout << "]\n";
}

void printAuditIssues(const std::vector<AppPermissions>& apps,
                      const std::vector<AuditIssue>&    allIssues)
{
    for (const auto& app : apps) {
        // Collect issues for this app
        std::vector<const AuditIssue*> appIssues;
        for (const auto& issue : allIssues) {
            if (issue.appId == app.appId) {
                appIssues.push_back(&issue);
            }
        }
        bool hasAllDev = std::find(app.devices.begin(), app.devices.end(), "all") != app.devices.end();
        std::string devStr   = hasAllDev ? "all" : joinOrNone(app.devices);
        std::string filesStr = joinOrNone(app.filesystems);

        // ── Header ─────────────────────────────────────────────────────────
        std::cout << "\n";
        std::cout << BOLD << "Application: " << app.appId << RESET << "\n";
        std::cout << SEP << "\n";

        // ── Permissions Summary ────────────────────────────────────────────
        std::cout << "[+] Permissions Summary:\n";
        std::cout << "    - Shared:      " << joinOrNone(app.shared)      << "\n";
        std::cout << "    - Sockets:     " << joinOrNone(app.sockets)     << "\n";
        std::cout << "    - Devices:     " << devStr                      << "\n";
        std::cout << "    - Files:       " << filesStr                    << "\n";
        std::cout << "    - Persistent:  " << joinOrNone(app.persistent)  << "\n";

        // ── Security Findings ─────────────────────────────────────────────
        std::cout << "\n[!] Security Findings:\n";
        if (appIssues.empty()) {
            std::cout << "  " << GREEN << "[\u2713] No security issues found." << RESET << "\n";
        } else {
            for (const auto* issue : appIssues) {
                std::cout << "  " << sevColor(issue->severity) << sevLabel(issue->severity) << RESET
                          << " " << issue->ruleId << ": " << issue->description << "\n";
            }
        }
        std::cout << SEP << "\n";
    }
}

void printAppList(const std::vector<AppPermissions>& apps)
{
    if (apps.empty()) {
        std::cout << YELLOW << "No Flatpak applications found on this system." << RESET << std::endl;
        return;
    }
    std::cout << BOLD << "Installed Flatpak applications (" << apps.size() << "):" << RESET << std::endl;
    for (const auto& app : apps) {
        std::cout << "  " << GREEN << app.appId << RESET << std::endl;
    }
}

int main(int argc, char* argv[])
{
    cxxopts::Options options("flatguard", "Security auditing tool for Flatpak applications");

    options.add_options()
        ("h,help",  "Show this help message")
        ("a,audit", "Audit a specific app by ID, or use 'all' to audit every app",
            cxxopts::value<std::string>()->default_value("all"))
        ("l,list",  "List all installed Flatpak applications")
        ("j,json",  "Output audit results in JSON format")
        ("version", "Show version information");

    options.custom_help("[--audit <app-id|all>] [--list] [--json]");

    cxxopts::ParseResult result;
    try {
        result = options.parse(argc, argv);
    } catch (const cxxopts::exceptions::exception& e) {
        std::cerr << RED << "Error: " << e.what() << RESET << std::endl;
        std::cout << options.help() << std::endl;
        return 1;
    }

    const auto& unmatched = result.unmatched();
    if (!unmatched.empty()) {
        std::cerr << RED << "Error: unrecognized argument(s):";
        for (const auto& u : unmatched) {
            std::cerr << " '" << u << "'";
        }
        std::cerr << RESET << std::endl;
        std::cerr << "Did you mean: " << BOLD << "--audit " << unmatched.back() << RESET << " ?" << std::endl;
        std::cout << options.help() << std::endl;
        return 1;
    }

    if (result.count("help")) {
        std::cout << options.help() << std::endl;
        return 0;
    }

    if (result.count("version")) {
        std::cout << "flatguard v0.2.0" << std::endl;
        return 0;
    }

    std::vector<AppPermissions> apps = FlatpakParser::scanSystem();

    if (result.count("list")) {
        printAppList(apps);
        return 0;
    }

    std::string auditTarget = result["audit"].as<std::string>();
    bool jsonOutput = result.count("json") > 0;

    if (auditTarget == "all") {
        auto issues = Auditor::auditAll(apps);
        if (jsonOutput)
            printAuditIssuesJson(apps, issues);
        else
            printAuditIssues(apps, issues);
    } else {
        auto it = std::find_if(apps.begin(), apps.end(),
            [&](const AppPermissions& a) -> bool { return a.appId == auditTarget; });

        if (it == apps.end()) {
            std::cerr << RED << "Error: App '" << auditTarget << "' not found." << RESET << std::endl;
            std::cerr << "Use --list to see all installed apps." << std::endl;
            return 1;
        }

        auto issues = Auditor::auditApp(*it);
        if (jsonOutput)
            printAuditIssuesJson({*it}, issues);
        else
            printAuditIssues({*it}, issues);
    }

    return 0;
}