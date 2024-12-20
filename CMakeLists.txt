cmake_minimum_required(VERSION 3.19)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED True)

project(passenger)

add_executable(passenger
	src/Atszio.cpp
	src/Main.cpp
)

set_target_properties(passenger PROPERTIES
	MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>")

target_include_directories(passenger PRIVATE src)
