# Copy Npcap DLLs to target directory if they exist
cmake_parse_arguments(ARG "" "SRC_DIR;DST_DIR" "" ${ARGN})

if(ARG_SRC_DIR AND ARG_DST_DIR)
    set(WPCAP_DLL "${ARG_SRC_DIR}/wpcap.dll")
    set(PACKET_DLL "${ARG_SRC_DIR}/Packet.dll")
    
    if(EXISTS "${WPCAP_DLL}")
        file(COPY "${WPCAP_DLL}" DESTINATION "${ARG_DST_DIR}")
        message(STATUS "Copied wpcap.dll to ${ARG_DST_DIR}")
    else()
        message(WARNING "wpcap.dll not found at ${WPCAP_DLL}")
    endif()
    
    if(EXISTS "${PACKET_DLL}")
        file(COPY "${PACKET_DLL}" DESTINATION "${ARG_DST_DIR}")
        message(STATUS "Copied Packet.dll to ${ARG_DST_DIR}")
    else()
        message(WARNING "Packet.dll not found at ${PACKET_DLL}")
    endif()
endif()