cmake_minimum_required(VERSION 3.24)
project(bayan1)

set(CMAKE_CXX_STANDARD 17)

find_package(Boost COMPONENTS  program_options  REQUIRED)
include_directories(${Boost_INCLUDE_DIR})


add_executable(${PROJECT_NAME} bayan.cpp)
target_include_directories(${PROJECT_NAME} PRIVATE
                                            include
                                            ${Boost_INCLUDE_DIR}
                           )
target_link_libraries(${PROJECT_NAME} ${Boost_LIBRARIES} )


set(CPACK_GENERATOR DEB)
set(CPACK_PACKAGE_CONTACT https://github.com/friendpostum/Otus_hw8)
include(CPack)
