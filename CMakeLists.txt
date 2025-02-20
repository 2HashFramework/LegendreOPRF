cmake_minimum_required(VERSION 3.15)

project(LegendreOPRF VERSION 1.0)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
# I don't know why I need that. But there seems to be something odd in the block implementation of libOTe
add_compile_options(-fpermissive -fcoroutines)

add_executable(LegendreOPRF main.cpp)
add_library(LegendreOPRFlib main.cpp)
add_subdirectory(field25519)
include_directories(libOTe/thirdparty)

if(CMAKE_PROJECT_NAME STREQUAL PROJECT_NAME)
    enable_testing()
    set(BUILD_TESTING ON)
endif()
if(CMAKE_PROJECT_NAME STREQUAL PROJECT_NAME AND BUILD_TESTING)
    add_subdirectory(tests) # only add tests in our project.
endif()
find_package(libOTe REQUIRED)
target_link_libraries(LegendreOPRF oc::libOTe)
target_link_libraries(LegendreOPRFlib oc::libOTe)
set(ENABLE_SIMPLESTOT ON)

# Find GMP library
find_path(GMP_INCLUDE_DIR NAMES gmp.h)
find_library(GMP_LIBRARY NAMES gmp)
find_library(GMPXX_LIBRARY NAMES gmpxx)

if(GMP_INCLUDE_DIR AND GMP_LIBRARY)
    include_directories(${GMP_INCLUDE_DIR})
    target_link_libraries(LegendreOPRF ${GMP_LIBRARY} ${GMPXX_LIBRARY})
    target_link_libraries(LegendreOPRFlib ${GMP_LIBRARY} ${GMPXX_LIBRARY})
else()
    message(FATAL_ERROR "Could not find GMP")
endif()

# Include GMP headers
target_include_directories(LegendreOPRF PRIVATE ${GMP_INCLUDE_DIRS})
target_include_directories(LegendreOPRFlib PRIVATE ${GMP_INCLUDE_DIRS})

# Link GMP library
target_link_libraries(LegendreOPRF PRIVATE ${GMP_LIBRARIES})
target_link_libraries(LegendreOPRFlib PRIVATE ${GMP_LIBRARIES})