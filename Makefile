ARCHS = arm64

TARGET = iphone:13.7:11.4

export THEOS=/var/mobile/theos
INSTALL_TARGET_PROCESSES = SpringBoard

include $(THEOS)/makefiles/common.mk

TWEAK_NAME = H5GG

H5GG_FILES = $(wildcard *.mm *.m *.x *.xm *.c *.cpp *.cc)
H5GG_CFLAGS = -fobjc-arc -fvisibility=hidden 

H5GG_CCFLAGS = -fobjc-arc -fvisibility=hidden -std=c++11

H5GG_LOGOS_DEFAULT_GENERATOR = internal

include $(THEOS_MAKE_PATH)/tweak.mk
