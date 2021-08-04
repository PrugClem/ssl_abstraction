cmake_minimum_required(VERSION 3.8)

# C++ 17 with extensions
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS ON)

project(ssl_client) 
project(ssl_server)
project(ssl_generator)

# ssl_client sources
add_executable(ssl_client "ssl_client.cpp")

# ssl_server sources
add_executable(ssl_server "ssl_server.cpp")

# ssl generator sources
add_executable(ssl_generator "ssl_generator.cpp" "ssl_key_pair.hpp")

# copy certificates post-build
add_custom_command(TARGET ssl_server POST_BUILD
	COMMAND "rsync" "-a" "-delete" "-vh"
	"\"${CMAKE_SOURCE_DIR}/crt/\""
	"\"${CMAKE_BINARY_DIR}/crt/\""
)

# pthread
set(THREADS_PREFER_PTHREAD_FLAG ON)
find_package(Threads REQUIRED)
target_link_libraries(ssl_client PRIVATE Threads::Threads)
target_link_libraries(ssl_server PRIVATE Threads::Threads)

# libcrypto and ssl
target_link_libraries(ssl_client PRIVATE crypto ssl)
target_link_libraries(ssl_server PRIVATE crypto ssl)
target_link_libraries(ssl_generator PRIVATE crypto ssl)
