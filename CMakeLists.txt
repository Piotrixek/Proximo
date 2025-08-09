cmake_minimum_required(VERSION 3.15)
project(Proximo LANGUAGES CXX C)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED True)

set(IMGUI_DIR "C:/libs/imgui-docking" CACHE PATH "Path to ImGui source directory")
set(ULTRALIGHT_SDK_DIR "C:/libs/Ultralight" CACHE PATH "Path to Ultralight SDK")
set(LIEF_DIR "C:/libs/LIEF-0.16.6-win64" CACHE PATH "Path to LIEF SDK")

list(APPEND CMAKE_PREFIX_PATH ${LIEF_DIR})
find_package(LIEF REQUIRED)

file(GLOB APP_SOURCES
    "${CMAKE_CURRENT_SOURCE_DIR}/*.cpp"
)

file(GLOB IMGUI_SOURCES
    "${IMGUI_DIR}/imgui.cpp"
    "${IMGUI_DIR}/imgui_draw.cpp"
    "${IMGUI_DIR}/imgui_tables.cpp"
    "${IMGUI_DIR}/imgui_widgets.cpp"
    "${IMGUI_DIR}/backends/imgui_impl_win32.cpp"
    "${IMGUI_DIR}/backends/imgui_impl_dx11.cpp"
)

add_executable(${PROJECT_NAME} WIN32
    ${APP_SOURCES}
    ${IMGUI_SOURCES}
)

if(MSVC)
    set_property(TARGET ${PROJECT_NAME} PROPERTY MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>")
endif()

target_include_directories(${PROJECT_NAME} PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}
    ${IMGUI_DIR}
    ${IMGUI_DIR}/backends
    ${ULTRALIGHT_SDK_DIR}/include
)

target_link_libraries(${PROJECT_NAME} PRIVATE
    d3d11
    d3dcompiler
    dxgi
    gdiplus
    ${ULTRALIGHT_SDK_DIR}/lib/Ultralight.lib
    ${ULTRALIGHT_SDK_DIR}/lib/UltralightCore.lib
    ${ULTRALIGHT_SDK_DIR}/lib/AppCore.lib
    ${ULTRALIGHT_SDK_DIR}/lib/WebCore.lib
    LIEF::LIEF
)

target_compile_definitions(${PROJECT_NAME} PRIVATE NOMINMAX)

add_custom_command(TARGET ${PROJECT_NAME} POST_BUILD
    COMMAND ${CMAKE_COMMAND} -E copy_directory
        "${ULTRALIGHT_SDK_DIR}/bin"
        "$<TARGET_FILE_DIR:${PROJECT_NAME}>"
    COMMAND ${CMAKE_COMMAND} -E copy_directory
        "${ULTRALIGHT_SDK_DIR}/resources"
        "$<TARGET_FILE_DIR:${PROJECT_NAME}>/resources"
    COMMAND ${CMAKE_COMMAND} -E copy
        "$<TARGET_FILE:LIEF::LIEF>"
        "$<TARGET_FILE_DIR:${PROJECT_NAME}>"
    COMMENT "Copying Ultralight & LIEF DLLs and resources"
)

if(MSVC)
    set_target_properties(${PROJECT_NAME} PROPERTIES LINK_FLAGS "/SUBSYSTEM:WINDOWS /ENTRY:mainCRTStartup")
elseif(CMAKE_CXX_COMPILER_ID MATCHES "GNU|Clang")
    set_target_properties(${PROJECT_NAME} PROPERTIES LINK_FLAGS "-mwindows")
endif()