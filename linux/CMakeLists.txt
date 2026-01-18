cmake_minimum_required(VERSION 3.16)
project(crossring-linux VERSION 1.0.0 LANGUAGES C CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Options
option(BUILD_GUI "Build the GTK4 GUI" ON)
option(USE_EBPF "Use eBPF for process monitoring" ON)

# Find packages
find_package(PkgConfig REQUIRED)
pkg_check_modules(SQLITE3 REQUIRED sqlite3)

if(BUILD_GUI)
    pkg_check_modules(GTK4 REQUIRED gtk4)
endif()

# eBPF support
if(USE_EBPF)
    find_library(LIBBPF_LIB bpf REQUIRED)
    find_path(LIBBPF_INCLUDE bpf/bpf.h REQUIRED)
endif()

# Daemon executable
add_executable(crossring-daemon
    src/main.cpp
    src/daemon.cpp
    src/process_monitor.cpp
    src/apparmor_policy.cpp
    src/database.cpp
    src/ipc_server.cpp
    src/persistence_monitor.cpp
    src/network_monitor.cpp
    src/zero_trust.cpp
)

target_include_directories(crossring-daemon PRIVATE
    ${CMAKE_SOURCE_DIR}/include
    ${SQLITE3_INCLUDE_DIRS}
)

target_link_libraries(crossring-daemon PRIVATE
    ${SQLITE3_LIBRARIES}
    pthread
)

if(USE_EBPF)
    target_compile_definitions(crossring-daemon PRIVATE USE_EBPF)
    target_include_directories(crossring-daemon PRIVATE ${LIBBPF_INCLUDE})
    target_link_libraries(crossring-daemon PRIVATE ${LIBBPF_LIB})
endif()

# GUI executable
if(BUILD_GUI)
    add_executable(crossring-gui
        gui/main.cpp
        gui/window.cpp
        gui/dashboard.cpp
        gui/auth_dialog.cpp
    )
    
    target_include_directories(crossring-gui PRIVATE
        ${CMAKE_SOURCE_DIR}/include
        ${GTK4_INCLUDE_DIRS}
    )
    
    target_link_libraries(crossring-gui PRIVATE
        ${GTK4_LIBRARIES}
    )
endif()

# Install
install(TARGETS crossring-daemon DESTINATION bin)
install(FILES systemd/crossring.service DESTINATION /lib/systemd/system)
install(FILES apparmor/crossring-daemon DESTINATION /etc/apparmor.d)

if(BUILD_GUI)
    install(TARGETS crossring-gui DESTINATION bin)
    install(FILES desktop/crossring.desktop DESTINATION share/applications)
endif()

# Packaging
set(CPACK_PACKAGE_NAME "crossring")
set(CPACK_PACKAGE_VERSION ${PROJECT_VERSION})
set(CPACK_PACKAGE_DESCRIPTION "Owner-Gated Offline Endpoint Security")
set(CPACK_PACKAGE_MAINTAINER "CROSSRING Security")

# DEB package
set(CPACK_DEBIAN_PACKAGE_DEPENDS "libc6, libsqlite3-0, libgtk-4-1")
set(CPACK_DEBIAN_PACKAGE_SECTION "security")

# RPM package
set(CPACK_RPM_PACKAGE_REQUIRES "glibc, sqlite, gtk4")
set(CPACK_RPM_PACKAGE_GROUP "System Environment/Security")

include(CPack)
