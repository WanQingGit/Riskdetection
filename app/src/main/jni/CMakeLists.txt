

cmake_minimum_required(VERSION 3.4.1)



add_library( # Sets the name of the library.
             encrypt
             # Sets the library as a shared library.
             SHARED
             encrypt.c )
target_link_libraries(encrypt log dl)
