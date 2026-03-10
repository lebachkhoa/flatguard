cmake_minimum_required(VERSION 3.10)
project(Flatguard VERSION 0.2.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED True)

set(SOURCES
    src/flatpak/parser.cpp
    src/flatpak/override.cpp
    src/flatpak/fs_permissions.cpp
    src/utils/ini_utils.cpp
    src/audit/auditor.cpp
)

add_executable(flatguard src/main.cpp ${SOURCES})
target_include_directories(flatguard PRIVATE src third_party)

add_executable(test_parser tests/test_parser.cpp ${SOURCES})
target_include_directories(test_parser PRIVATE src third_party)

add_executable(test_auditor tests/test_auditor.cpp ${SOURCES})
target_include_directories(test_auditor PRIVATE src third_party)

add_executable(test_override tests/test_override.cpp ${SOURCES})
target_include_directories(test_override PRIVATE src third_party)

add_executable(test_fs_permissions tests/test_fs_permissions.cpp ${SOURCES})
target_include_directories(test_fs_permissions PRIVATE src third_party)

enable_testing()

# Google Test
include(FetchContent)
FetchContent_Declare(
    googletest
    URL https://github.com/google/googletest/archive/refs/tags/v1.14.0.zip
    DOWNLOAD_EXTRACT_TIMESTAMP true
)
set(gtest_force_shared_crt ON CACHE BOOL "" FORCE)
FetchContent_MakeAvailable(googletest)

target_link_libraries(test_parser GTest::gtest_main)
add_test(NAME TestParser COMMAND test_parser)

target_link_libraries(test_auditor GTest::gtest_main)
add_test(NAME TestAuditor COMMAND test_auditor)

target_link_libraries(test_override GTest::gtest_main)
add_test(NAME TestOverride COMMAND test_override)

target_link_libraries(test_fs_permissions GTest::gtest_main)
add_test(NAME TestFsPermissions COMMAND test_fs_permissions)

install(TARGETS flatguard DESTINATION bin)
