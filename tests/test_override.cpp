#include "gtest/gtest.h"
#include "flatpak/parser.h"
#include "flatpak/override.h"
#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <string>
#include <vector>

static const std::filesystem::path kTestBase =
    std::filesystem::temp_directory_path() / "fg_override_test";

// Write override file and return the appPath to pass to applyOverrides().
static std::filesystem::path setupOverrideFile(const std::string& appId, const std::string& content)
{
    std::filesystem::path overrideDir = kTestBase / "flatpak" / "overrides";
    std::filesystem::create_directories(overrideDir);

    std::ofstream f(overrideDir / appId);
    f << content;
    f.close();

    setenv("XDG_DATA_HOME", kTestBase.string().c_str(), /*overwrite=*/1);

    std::filesystem::path appPath = kTestBase / "flatpak" / "app" / appId;
    std::filesystem::create_directories(appPath);
    return appPath;
}

static void cleanupOverrideTest()
{
    unsetenv("XDG_DATA_HOME");
    std::filesystem::remove_all(kTestBase);
}

// ---------------------------------------------------------

// No override file → permissions stay unchanged
TEST(OverrideTests, NoOverrideFile)
{
    cleanupOverrideTest(); // ensure no stray files
    setenv("XDG_DATA_HOME", kTestBase.string().c_str(), 1);

    AppPermissions perms;
    perms.appId = "com.example.nooverride";
    perms.shared = {"network", "ipc"};

    std::filesystem::path appPath = kTestBase / "flatpak" / "app" / perms.appId;
    std::filesystem::create_directories(appPath);

    FlatpakParser::applyOverrides(perms, appPath);

    ASSERT_EQ(perms.shared.size(), 2u);
    EXPECT_EQ(perms.shared[0], "network");
    EXPECT_EQ(perms.shared[1], "ipc");

    cleanupOverrideTest();
}

// Override with !token → removes that token from base
TEST(OverrideTests, RemoveSinglePermission)
{
    AppPermissions perms;
    perms.appId = "org.mozilla.firefox";
    perms.shared = {"network", "ipc"};

    auto appPath = setupOverrideFile("org.mozilla.firefox", "[Context]\nshared=!network\n");

    FlatpakParser::applyOverrides(perms, appPath);

    ASSERT_EQ(perms.shared.size(), 1u);
    EXPECT_EQ(perms.shared[0], "ipc");

    cleanupOverrideTest();
}

// Override removes multiple tokens in one field
TEST(OverrideTests, RemoveMultiplePermissions)
{
    AppPermissions perms;
    perms.appId   = "com.example.app";
    perms.shared  = {"network", "ipc"};
    perms.sockets = {"x11", "wayland", "pulseaudio"};

    auto appPath = setupOverrideFile("com.example.app",
        "[Context]\nshared=!network;!ipc\nsockets=!x11;!pulseaudio\n");

    FlatpakParser::applyOverrides(perms, appPath);

    EXPECT_TRUE(perms.shared.empty());
    ASSERT_EQ(perms.sockets.size(), 1u);
    EXPECT_EQ(perms.sockets[0], "wayland");

    cleanupOverrideTest();
}

// Override adds a new permission not in base
TEST(OverrideTests, AddNewPermission)
{
    AppPermissions perms;
    perms.appId   = "com.example.app";
    perms.devices = {"dri"};

    auto appPath = setupOverrideFile("com.example.app", "[Context]\ndevices=kvm\n");

    FlatpakParser::applyOverrides(perms, appPath);

    ASSERT_EQ(perms.devices.size(), 2u);
    EXPECT_EQ(perms.devices[0], "dri");
    EXPECT_EQ(perms.devices[1], "kvm");

    cleanupOverrideTest();
}

// Override tries to remove a token that doesn't exist → no crash, list unchanged
TEST(OverrideTests, RemoveNonExistentPermission)
{
    AppPermissions perms;
    perms.appId  = "com.example.app";
    perms.shared = {"ipc"};

    auto appPath = setupOverrideFile("com.example.app", "[Context]\nshared=!network\n");

    EXPECT_NO_THROW(FlatpakParser::applyOverrides(perms, appPath));

    ASSERT_EQ(perms.shared.size(), 1u);
    EXPECT_EQ(perms.shared[0], "ipc");

    cleanupOverrideTest();
}

// Override does not duplicate an already-present permission
TEST(OverrideTests, NoDuplicateWhenAddingExisting)
{
    AppPermissions perms;
    perms.appId  = "com.example.app";
    perms.shared = {"network"};

    auto appPath = setupOverrideFile("com.example.app", "[Context]\nshared=network\n");

    FlatpakParser::applyOverrides(perms, appPath);

    ASSERT_EQ(perms.shared.size(), 1u);

    cleanupOverrideTest();
}

// Override applies across all four fields at once
TEST(OverrideTests, AllFieldsApplied)
{
    AppPermissions perms;
    perms.appId       = "com.example.app";
    perms.shared      = {"network", "ipc"};
    perms.sockets     = {"x11", "wayland"};
    perms.devices     = {"dri"};
    perms.filesystems = {"xdg-download", "xdg-music"};

    auto appPath = setupOverrideFile("com.example.app",
        "[Context]\n"
        "shared=!ipc\n"
        "sockets=!wayland\n"
        "devices=kvm\n"
        "filesystems=!xdg-music\n");

    FlatpakParser::applyOverrides(perms, appPath);

    ASSERT_EQ(perms.shared.size(),      1u); EXPECT_EQ(perms.shared[0],      "network");
    ASSERT_EQ(perms.sockets.size(),     1u); EXPECT_EQ(perms.sockets[0],     "x11");
    ASSERT_EQ(perms.devices.size(),     2u); EXPECT_EQ(perms.devices[1],     "kvm");
    ASSERT_EQ(perms.filesystems.size(), 1u); EXPECT_EQ(perms.filesystems[0], "xdg-download");

    cleanupOverrideTest();
}

int main(int argc, char** argv)
{
    ::testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}
