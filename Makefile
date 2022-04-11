ARCHS = arm64

TARGET = iphone:13.7:11.4

ifeq ($(THEOS), )
	export THEOS=/var/mobile/theos
endif

INSTALL_TARGET_PROCESSES = SpringBoard

THEOS_PLATFORM_DEB_COMPRESSION_TYPE = gzip

STRIP=1

include $(THEOS)/makefiles/common.mk

TWEAK_NAME = H5GG

H5GG_FILES = $(wildcard *.mm *.m *.x *.xm *.c *.cpp *.cc)
H5GG_CFLAGS = -fobjc-arc -fvisibility=hidden 

H5GG_CCFLAGS = -fobjc-arc -fvisibility=hidden -std=c++11

H5GG_LOGOS_DEFAULT_GENERATOR = internal

include $(THEOS_MAKE_PATH)/tweak.mk
