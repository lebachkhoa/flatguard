#include "gtest/gtest.h"
#include "flatpak/fs_permissions.h"
#include <vector>
#include <string>

// ── Basic access modifiers ────────────────────────────────────────────────────

TEST(FsPermissionsTests, NoSuffixIsReadWrite)
{
    auto result = FlatpakParser::parseFilesystemPermissions({"home"});
    ASSERT_EQ(result.size(), 1u);
    EXPECT_EQ(result[0].path,     "home");
    EXPECT_EQ(result[0].fsaccess, FsAccess::ReadWrite);
}

TEST(FsPermissionsTests, RoSuffixIsReadOnly)
{
    auto result = FlatpakParser::parseFilesystemPermissions({"home:ro"});
    ASSERT_EQ(result.size(), 1u);
    EXPECT_EQ(result[0].path,     "home");
    EXPECT_EQ(result[0].fsaccess, FsAccess::ReadOnly);
}

TEST(FsPermissionsTests, CreateSuffixIsCreate)
{
    auto result = FlatpakParser::parseFilesystemPermissions({"home:create"});
    ASSERT_EQ(result.size(), 1u);
    EXPECT_EQ(result[0].path,     "home");
    EXPECT_EQ(result[0].fsaccess, FsAccess::Create);
}

// ── Path varieties ────────────────────────────────────────────────────────────

TEST(FsPermissionsTests, HostPath)
{
    auto result = FlatpakParser::parseFilesystemPermissions({"host"});
    ASSERT_EQ(result.size(), 1u);
    EXPECT_EQ(result[0].path,     "host");
    EXPECT_EQ(result[0].fsaccess, FsAccess::ReadWrite);
}

TEST(FsPermissionsTests, AbsolutePath)
{
    auto result = FlatpakParser::parseFilesystemPermissions({"/usr/share/myapp:ro"});
    ASSERT_EQ(result.size(), 1u);
    EXPECT_EQ(result[0].path,     "/usr/share/myapp");
    EXPECT_EQ(result[0].fsaccess, FsAccess::ReadOnly);
}

TEST(FsPermissionsTests, XdgPrefixPath)
{
    auto result = FlatpakParser::parseFilesystemPermissions({"xdg-documents:ro"});
    ASSERT_EQ(result.size(), 1u);
    EXPECT_EQ(result[0].path,     "xdg-documents");
    EXPECT_EQ(result[0].fsaccess, FsAccess::ReadOnly);
}

TEST(FsPermissionsTests, HomeTildePath)
{
    auto result = FlatpakParser::parseFilesystemPermissions({"~/Downloads"});
    ASSERT_EQ(result.size(), 1u);
    EXPECT_EQ(result[0].path,     "~/Downloads");
    EXPECT_EQ(result[0].fsaccess, FsAccess::ReadWrite);
}

// ── Multiple entries ──────────────────────────────────────────────────────────

TEST(FsPermissionsTests, MultipleEntries)
{
    std::vector<std::string> entries = {"home:ro", "host", "/tmp:create"};
    auto result = FlatpakParser::parseFilesystemPermissions(entries);

    ASSERT_EQ(result.size(), 3u);

    EXPECT_EQ(result[0].path,     "home");
    EXPECT_EQ(result[0].fsaccess, FsAccess::ReadOnly);

    EXPECT_EQ(result[1].path,     "host");
    EXPECT_EQ(result[1].fsaccess, FsAccess::ReadWrite);

    EXPECT_EQ(result[2].path,     "/tmp");
    EXPECT_EQ(result[2].fsaccess, FsAccess::Create);
}

// ── Edge cases ────────────────────────────────────────────────────────────────

TEST(FsPermissionsTests, EmptyInputReturnsEmpty)
{
    auto result = FlatpakParser::parseFilesystemPermissions({});
    EXPECT_TRUE(result.empty());
}

TEST(FsPermissionsTests, EmptyStringEntryIsSkipped)
{
    auto result = FlatpakParser::parseFilesystemPermissions({""});
    EXPECT_TRUE(result.empty());
}

TEST(FsPermissionsTests, MixedWithEmptyEntries)
{
    auto result = FlatpakParser::parseFilesystemPermissions({"", "home:ro", ""});
    ASSERT_EQ(result.size(), 1u);
    EXPECT_EQ(result[0].path, "home");
}

// ── Deny prefix '!' ───────────────────────────────────────────────────────────

TEST(FsPermissionsTests, DenyEntryIsSkipped)
{
    auto result = FlatpakParser::parseFilesystemPermissions({"!home"});
    EXPECT_TRUE(result.empty());
}

TEST(FsPermissionsTests, DenyEntriesMixedWithNormal)
{
    auto result = FlatpakParser::parseFilesystemPermissions({"!home", "host:ro", "!host"});
    ASSERT_EQ(result.size(), 1u);
    EXPECT_EQ(result[0].path,     "host");
    EXPECT_EQ(result[0].fsaccess, FsAccess::ReadOnly);
}

int main(int argc, char** argv)
{
    ::testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}
