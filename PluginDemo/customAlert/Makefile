ARCHS = arm64
TARGET = iphone:13.7:11.4

THEOS_DEVICE_IP = iphoneX.local

THEOS_PLATFORM_DEB_COMPRESSION_TYPE = gzip

ifeq ($(THEOS), )
	export THEOS=/var/mobile/theos
endif

include $(THEOS)/makefiles/common.mk

TWEAK_NAME = customAlert

customAlert_FILES = Tweak.mm
customAlert_CFLAGS = -fobjc-arc -fvisibility=hidden 
customAlert_CCFLAGS = -fobjc-arc -fvisibility=hidden -std=c++11
customAlert_LOGOS_DEFAULT_GENERATOR = internal

include $(THEOS_MAKE_PATH)/tweak.mk

clean::
	rm -rf ./packages/*

after-package::
	rm -rf ./packages/*
	cp ./.theos/obj/debug/customAlert.dylib ./
	
