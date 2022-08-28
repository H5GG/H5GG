#!/bin/bash
./configure CC='clang -mmacosx-version-min=10.4 -arch i386 -arch x86_64' CXX='clang++ -mmacosx-version-min=10.4 -arch i386 -arch x86_64' CPP='clang -E' CXXCPP='clang++ -E' libxml2_LIBS=-lxml2 libxml2_CFLAGS=-I/usr/include/libxml2 --enable-static --disable-shared
