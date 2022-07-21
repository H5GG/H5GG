ARCHS = arm64
TARGET = iphone:13.7:11.4

THEOS_DEVICE_IP = iphoneX.local

THEOS_PLATFORM_DEB_COMPRESSION_TYPE = gzip

ifeq ($(THEOS), )
	export THEOS=/var/mobile/theos
endif

include $(THEOS)/makefiles/common.mk

TWEAK_NAME = h5frida

h5frida_FILES = h5frida.m
h5frida_CFLAGS = -fobjc-arc -fvisibility=hidden 
h5frida_CCFLAGS = -fobjc-arc -fvisibility=hidden -std=c++11
h5frida_LDFLAGS += libfrida-core-15.1.24.a -lresolv
h5frida_LOGOS_DEFAULT_GENERATOR = internal

include $(THEOS_MAKE_PATH)/tweak.mk

clean::
	rm -rf ./packages/*

after-package::
	rm -rf ./packages/*
	cp ./.theos/obj/debug/h5frida.dylib ./h5frida-15.1.24.dylib
	
