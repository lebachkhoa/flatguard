#include "gtest/gtest.h"
#include "audit/auditor.h"
#include <string>
#include <vector>

// App không có permission nào -> không có issue
TEST(AuditorTests, NoIssuesWhenNoPermissions) {
    AppPermissions app;
    app.appId = "com.example.clean";

    auto issues = Auditor::auditApp(app);
    EXPECT_TRUE(issues.empty());
}

// App có "all" trong devices -> phát hiện DEV_01 CRITICAL
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

// App có "home" trong filesystems -> phát hiện FS_01 INFO (nguy hiểm nhưng chưa đủ nguy hiểm một mình)
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

// App có "network" trong shared -> NET_01 luôn là INFO
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

// COMBO_01: network + home -> có thể exfiltrate file cá nhân
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

// COMBO_02: network + host -> có thể exfiltrate toàn bộ hệ thống
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

// COMBO_03: network + x11 -> keylog và gửi về server
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

// COMBO_04: network + devices=all -> stream webcam/microphone ra ngoài
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

// Network một mình không kích hoạt combo rule nào
TEST(AuditorTests, NetworkAloneNoCombos) {
    AppPermissions app;
    app.appId = "com.example.netonly";
    app.shared = {"network"};

    auto issues = Auditor::auditApp(app);
    for (const auto& issue : issues) {
        std::string id = issue.ruleId;
        EXPECT_EQ(id.substr(0, 5), "NET_0")  // chỉ được phép có NET_01
            << "Unexpected rule triggered: " << id;
    }
}

// auditAll trả về tổng hợp issues của nhiều app
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
