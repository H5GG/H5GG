ARCHS = arm64

TARGET = iphone:13.7:11.4

THEOS_DEVICE_IP = 192.168.2.147

THEOS_PLATFORM_DEB_COMPRESSION_TYPE = gzip

DEBUG=0
STRIP=1
FINALPACKAGE=1

include $(THEOS)/makefiles/common.mk


TWEAK_NAME = H5GG

H5GG_FILES = Tweak.mm ldid/ldid.cpp ldid/lookup2.c
H5GG_CFLAGS = -fobjc-arc -fvisibility=hidden 
H5GG_CCFLAGS = -fobjc-arc -fvisibility=hidden -std=c++11
H5GG_LOGOS_DEFAULT_GENERATOR = internal

include $(THEOS_MAKE_PATH)/tweak.mk

clean::
	rm -rf ./packages/*
	rm -rf ./layout

