ARCHS = arm64
TARGET = iphone:13.7:11.4

THEOS_DEVICE_IP = iphoneX.local

THEOS_PLATFORM_DEB_COMPRESSION_TYPE = gzip

ifeq ($(THEOS), )
	export THEOS=/var/mobile/theos
endif

include $(THEOS)/makefiles/common.mk

TWEAK_NAME = StaticInlineHook

StaticInlineHook_FILES = StaticInlineHook.mm
StaticInlineHook_CFLAGS = -fobjc-arc -fvisibility=hidden 
StaticInlineHook_CCFLAGS = -fobjc-arc -fvisibility=hidden -std=c++11
StaticInlineHook_LOGOS_DEFAULT_GENERATOR = internal

StaticInlineHook_LDFLAGS += -L./ #指定静态库目录
StaticInlineHook_LDFLAGS += -ldobby_fixed


include $(THEOS_MAKE_PATH)/tweak.mk
