cmake_minimum_required(VERSION 3.16)

set(EXTRA_COMPONENT_DIRS "")

# Allow override of WiFi blob's ieee80211_raw_frame_sanity_check
set(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} -Wl,--allow-multiple-definition")

include($ENV{IDF_PATH}/tools/cmake/project.cmake)
project(deauth_tool)
