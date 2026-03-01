#include "gtest/gtest.h"
#include "audit/auditor.h"
#include <string>
#include <vector>

// Test case: Ensure no issues are reported when an app has no permissions
TEST(AuditorTests, NoIssuesWhenNoPermissions) {
    AppPermissions app;
    app.appId = "com.example.clean";

    auto issues = Auditor::auditApp(app);
    EXPECT_TRUE(issues.empty());
}

// Test case: Detect full device access (devices=all) -> triggers DEV_01 CRITICAL
TEST(AuditorTests, DetectsFullDeviceAccess) {
    AppPermissions app;
    app.appId = "com.example.dangerous";
    app.devices = {"all"};

    auto issues = Auditor::auditApp(app);
    ASSERT_FALSE(issues.empty());

    bool foundDev01 = false;
    for (const auto& issue : issues) {
        if (issue.ruleId == "DEV_01") {
            foundDev01 = true;
            EXPECT_EQ(issue.severity, Severity::CRITICAL);
            EXPECT_EQ(issue.appId, "com.example.dangerous");
        }
    }
    EXPECT_TRUE(foundDev01);
}

// Test case: Detect home directory access (filesystems=home) -> triggers FS_01 INFO
TEST(AuditorTests, DetectsHomeAccess) {
    AppPermissions app;
    app.appId = "com.example.homeaccess";
    app.filesystems = {"home"};

    auto issues = Auditor::auditApp(app);
    bool foundFs01 = false;
    for (const auto& issue : issues) {
        if (issue.ruleId == "FS_01") {
            foundFs01 = true;
            EXPECT_EQ(issue.severity, Severity::INFO);
        }
    }
    EXPECT_TRUE(foundFs01);
}

// Test case: Detect network access (shared=network) -> triggers NET_01 INFO
TEST(AuditorTests, DetectsNetworkAccess) {
    AppPermissions app;
    app.appId = "com.example.browser";
    app.shared = {"network"};

    auto issues = Auditor::auditApp(app);
    bool foundNet01 = false;
    for (const auto& issue : issues) {
        if (issue.ruleId == "NET_01") {
            foundNet01 = true;
            EXPECT_EQ(issue.severity, Severity::INFO);
        }
    }
    EXPECT_TRUE(foundNet01);
}

// COMBO_01: Network + Home access -> potential data exfiltration of user files
TEST(AuditorTests, ComboNetworkPlusHome) {
    AppPermissions app;
    app.appId = "com.example.combo01";
    app.shared      = {"network"};
    app.filesystems = {"home"};

    auto issues = Auditor::auditApp(app);
    bool foundCombo01 = false;
    for (const auto& issue : issues) {
        if (issue.ruleId == "COMBO_01") {
            foundCombo01 = true;
            EXPECT_EQ(issue.severity, Severity::CRITICAL);
        }
    }
    EXPECT_TRUE(foundCombo01);
}

// COMBO_02: Network + Host filesystem access -> potential full system compromise
TEST(AuditorTests, ComboNetworkPlusHost) {
    AppPermissions app;
    app.appId = "com.example.combo02";
    app.shared      = {"network"};
    app.filesystems = {"host"};

    auto issues = Auditor::auditApp(app);
    bool foundCombo02 = false;
    for (const auto& issue : issues) {
        if (issue.ruleId == "COMBO_02") {
            foundCombo02 = true;
            EXPECT_EQ(issue.severity, Severity::CRITICAL);
        }
    }
    EXPECT_TRUE(foundCombo02);
}

// COMBO_03: Network + X11 socket -> risk of keylogging and remote data transmission
TEST(AuditorTests, ComboNetworkPlusX11) {
    AppPermissions app;
    app.appId = "com.example.combo03";
    app.shared   = {"network"};
    app.sockets  = {"x11"};

    auto issues = Auditor::auditApp(app);
    bool foundCombo03 = false;
    for (const auto& issue : issues) {
        if (issue.ruleId == "COMBO_03") {
            foundCombo03 = true;
            EXPECT_EQ(issue.severity, Severity::CRITICAL);
        }
    }
    EXPECT_TRUE(foundCombo03);
}

// COMBO_04: Network + All devices -> risk of webcam/microphone streaming
TEST(AuditorTests, ComboNetworkPlusDevices) {
    AppPermissions app;
    app.appId = "com.example.combo04";
    app.shared   = {"network"};
    app.devices  = {"all"};

    auto issues = Auditor::auditApp(app);
    bool foundCombo04 = false;
    for (const auto& issue : issues) {
        if (issue.ruleId == "COMBO_04") {
            foundCombo04 = true;
            EXPECT_EQ(issue.severity, Severity::CRITICAL);
        }
    }
    EXPECT_TRUE(foundCombo04);
}

// Ensure standalone network permission does not trigger any combo rules
TEST(AuditorTests, NetworkAloneNoCombos) {
    AppPermissions app;
    app.appId = "com.example.netonly";
    app.shared = {"network"};

    auto issues = Auditor::auditApp(app);
    for (const auto& issue : issues) {
        std::string id = issue.ruleId;
        EXPECT_EQ(id.substr(0, 5), "NET_0")
            << "Unexpected rule triggered: " << id;
    }
}

// Test auditAll: Aggregate issues from multiple applications
TEST(AuditorTests, AuditAllMultipleApps) {
    AppPermissions app1;
    app1.appId = "com.example.one";
    app1.shared = {"network"};

    AppPermissions app2;
    app2.appId = "com.example.two";
    app2.devices = {"all"};

    auto issues = Auditor::auditAll({app1, app2});
    EXPECT_GE(issues.size(), 2u);
}

int main(int argc, char **argv) {
    ::testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}
