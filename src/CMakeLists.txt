target_sources(kptnhook PRIVATE
    ${CMAKE_CURRENT_LIST_DIR}/main.cpp
    ${CMAKE_CURRENT_LIST_DIR}/handler.cpp
    ${CMAKE_CURRENT_LIST_DIR}/path.cpp
    ${CMAKE_CURRENT_LIST_DIR}/known_dlls.cpp
    ${CMAKE_CURRENT_LIST_DIR}/hook.cpp
    ${CMAKE_CURRENT_LIST_DIR}/arch.cpp
    )