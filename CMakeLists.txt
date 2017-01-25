cmake_minimum_required(VERSION 2.8)
project(pathdump-decode C CXX)

if(COMPILER_SUPPORTS_CXX11)
  set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -std=c++11")
else()
  message(FATAL_ERROR "The compiler ${CMAKE_CXX_COMPILER} has no C++11 support. Please use a different C++ compiler.")
endif()
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -std=gnu++11 -O3 -g")

set(CMAKE_MODULE_PATH ${PROJECT_SOURCE_DIR}/cmake-modules)

set(Boost_USE_STATIC_LIBS OFF) 
set(Boost_USE_MULTITHREADED ON)  
set(Boost_USE_STATIC_RUNTIME OFF) 
find_package(Boost REQUIRED COMPONENTS thread system regex) 

find_package(PCAP REQUIRED)

set(EXECUTABLE_OUTPUT_PATH ${PROJECT_BINARY_DIR}/bin)

file(MAKE_DIRECTORY ${EXECUTABLE_OUTPUT_PATH})

set(INCLUDE include)
include_directories(${INCLUDE} ${Boost_INCLUDE_DIRS} ${PCAP_INCLUDE_DIR})

add_executable(decode src/decode_pcap.cc
                      src/decode.cc
                      src/sp.cc)

target_link_libraries(decode ${Boost_LIBRARIES} ${PCAP_LIBRARY})
