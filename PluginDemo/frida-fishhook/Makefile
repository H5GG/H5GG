ARCHS = arm64
TARGET = iphone:13.7:11.4

THEOS_DEVICE_IP = iphoneX.local

THEOS_PLATFORM_DEB_COMPRESSION_TYPE = gzip

ifeq ($(THEOS), )
	export THEOS=/var/mobile/theos
endif

include $(THEOS)/makefiles/common.mk

TWEAK_NAME = fishhook

fishhook_FILES = fishhook.m
h5frida_CFLAGS = -fobjc-arc -fvisibility=hidden 
h5frida_CCFLAGS = -fobjc-arc -fvisibility=hidden -std=c++11
fishhook_LOGOS_DEFAULT_GENERATOR = internal

include $(THEOS_MAKE_PATH)/tweak.mk
