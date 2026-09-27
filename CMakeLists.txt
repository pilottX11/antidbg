cmake_minimum_required(VERSION 3.15)

project(antidbg
    VERSION 1.0.0
    DESCRIPTION "Cross-platform anti-debugging library for software protection"
    LANGUAGES C)

# ---- options -------------------------------------------------------------
option(ANTIDBG_BUILD_EXAMPLES "Build the example programs" ON)
option(ANTIDBG_BUILD_TESTS    "Build the self-tests"       ON)
option(ANTIDBG_SHARED         "Build antidbg as a shared library" OFF)

# ---- the library ---------------------------------------------------------
set(ANTIDBG_SOURCES
    src/antidbg.c
    src/antidbg_tools.c
    src/antidbg_windows.c
    src/antidbg_linux.c
    src/antidbg_macos.c)

if(ANTIDBG_SHARED)
    add_library(antidbg SHARED ${ANTIDBG_SOURCES})
    set_target_properties(antidbg PROPERTIES C_VISIBILITY_PRESET hidden)
else()
    add_library(antidbg STATIC ${ANTIDBG_SOURCES})
endif()

add_library(antidbg::antidbg ALIAS antidbg)

target_include_directories(antidbg PUBLIC
    $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
    $<INSTALL_INTERFACE:include>)

set_target_properties(antidbg PROPERTIES
    C_STANDARD 99
    C_STANDARD_REQUIRED ON
    POSITION_INDEPENDENT_CODE ON
    VERSION ${PROJECT_VERSION}
    SOVERSION ${PROJECT_VERSION_MAJOR})

# Threads (pthreads on non-Windows).
if(NOT WIN32)
    find_package(Threads REQUIRED)
    target_link_libraries(antidbg PUBLIC Threads::Threads)
endif()

# Windows: user32 provides EnumWindows/GetWindowText used by the tool scanner.
if(WIN32)
    target_link_libraries(antidbg PUBLIC user32)
endif()

# ---- examples ------------------------------------------------------------
if(ANTIDBG_BUILD_EXAMPLES)
    add_executable(antidbg_basic   examples/basic.c)
    add_executable(antidbg_protect examples/protect.c)
    target_link_libraries(antidbg_basic   PRIVATE antidbg)
    target_link_libraries(antidbg_protect PRIVATE antidbg)
endif()

# ---- tests ---------------------------------------------------------------
if(ANTIDBG_BUILD_TESTS)
    enable_testing()
    add_executable(antidbg_tests tests/test_antidbg.c)
    target_link_libraries(antidbg_tests PRIVATE antidbg)
    add_test(NAME antidbg_tests COMMAND antidbg_tests)
endif()

# ---- install -------------------------------------------------------------
include(GNUInstallDirs)
install(TARGETS antidbg
    ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR}
    LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
    RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR})
install(DIRECTORY include/ DESTINATION ${CMAKE_INSTALL_INCLUDEDIR})
