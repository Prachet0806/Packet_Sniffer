# Copy Npcap runtime DLLs next to the test executables.
#
# The Npcap *SDK* (headers + .lib import libs) ships no DLLs, so the SDK lib
# dir will usually contain only .lib files. The actual runtime DLLs live
# where the Npcap *installer* puts them:
#   C:/Windows/System32/Npcap/wpcap.dll + Packet.dll
# (and historically C:/Windows/System32/wpcap.dll).
#
# Usage (from a POST_BUILD custom command):
#   cmake -DNPCAP_SRC_DIR=<sdk lib dir> -DNPCAP_DST_DIR=<exe dir>
#         -P CopyNpcapDLLs.cmake
#
# Copies the first existing candidate for each DLL; warns (does not fail)
# when nothing is found so local builds without Npcap still configure.

if(NOT DEFINED NPCAP_DST_DIR OR "${NPCAP_DST_DIR}" STREQUAL "")
    message(WARNING "CopyNpcapDLLs.cmake: NPCAP_DST_DIR not given, skipping")
    return()
endif()

set(_candidates "")
if(DEFINED NPCAP_SRC_DIR AND NOT "${NPCAP_SRC_DIR}" STREQUAL "")
    list(APPEND _candidates "${NPCAP_SRC_DIR}")
endif()
# Installed Npcap runtime locations (x64 runner + local dev machine).
list(APPEND _candidates
    "C:/Windows/System32/Npcap"
    "C:/Windows/System32"
    "C:/Windows/SysWOW64/Npcap"
    "C:/Windows/SysWOW64"
)

foreach(_dll wpcap.dll Packet.dll)
    set(_found "")
    foreach(_dir IN LISTS _candidates)
        if(EXISTS "${_dir}/${_dll}")
            set(_found "${_dir}/${_dll}")
            break()
        endif()
    endforeach()
    if(_found)
        file(COPY "${_found}" DESTINATION "${NPCAP_DST_DIR}")
        message(STATUS "Copied ${_dll} from ${_found} to ${NPCAP_DST_DIR}")
    else()
        message(WARNING "${_dll} not found in: ${_candidates}")
    endif()
endforeach()
