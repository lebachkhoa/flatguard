#include "gtest/gtest.h"
#include "flatpak/parser.h"
#include <string>
#include <vector>
#include <fstream>
#include <cstdio>

// Test parseMetadata reads appId correctly
TEST(ParserTests, ParseMetadataAppId) {
    std::string testFile = "/tmp/test_metadata.ini";

    std::ofstream outFile(testFile);
    outFile << "[Application]\nname=com.example.app\n";
    outFile.close();

    AppPermissions permissions = FlatpakParser::parseMetadata(testFile);
    EXPECT_EQ(permissions.appId, "com.example.app");

    std::remove(testFile.c_str());
}

// Test parseMetadata reads shared permissions correctly
TEST(ParserTests, ParseMetadataShared) {
    std::string testFile = "/tmp/test_metadata_shared.ini";

    std::ofstream outFile(testFile);
    outFile << "[Application]\nname=com.example.app\n"
            << "[Context]\nshared=network;ipc;\n";
    outFile.close();

    AppPermissions permissions = FlatpakParser::parseMetadata(testFile);
    ASSERT_EQ(permissions.shared.size(), 2u);
    EXPECT_EQ(permissions.shared[0], "network");
    EXPECT_EQ(permissions.shared[1], "ipc");

    std::remove(testFile.c_str());
}

// Test parseMetadata returns "unknow" when keys are missing
TEST(ParserTests, ParseMetadataMissingKeys) {
    std::string testFile = "/tmp/test_metadata_empty.ini";

    std::ofstream outFile(testFile);
    outFile << "[Application]\nname=com.empty.app\n";
    outFile.close();

    AppPermissions permissions = FlatpakParser::parseMetadata(testFile);
    EXPECT_TRUE(permissions.shared.empty());
    EXPECT_TRUE(permissions.sockets.empty());
    EXPECT_TRUE(permissions.devices.empty());
    EXPECT_TRUE(permissions.filesystems.empty());

    std::remove(testFile.c_str());
}

// Test parseMetadata returns unknown when file not found
TEST(ParserTests, ParseMetadataFileNotFound) {
    AppPermissions permissions = FlatpakParser::parseMetadata("/tmp/nonexistent.ini");
    EXPECT_EQ(permissions.appId, "unknown");
}

int main(int argc, char **argv) {
    ::testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}
