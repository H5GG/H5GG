
ARCHS = arm64 arm64e

TARGET = iphone:13.7:11.4

#for arm64e-ios13 we need xcode11.7  https://theos.dev/docs/arm64e-deployment
THEOS_PLATFORM_SDK_ROOT = /Applications/Xcode-11.7.app/Contents/Developer
export TARGET_CXX = $(THEOS_PLATFORM_SDK_ROOT)/Toolchains/XcodeDefault.xctoolchain/usr/bin/clang++
export TARGET_LD = $(THEOS_PLATFORM_SDK_ROOT)/Toolchains/XcodeDefault.xctoolchain/usr/bin/clang++
export TARGET_STRIP = $(THEOS_PLATFORM_SDK_ROOT)/Toolchains/XcodeDefault.xctoolchain/usr/bin/strip

DEBUG=0
STRIP=1
FINALPACKAGE=1
THEOS_DEVICE_IP = iphoneX.local
THEOS_PLATFORM_DEB_COMPRESSION_TYPE = gzip

include $(THEOS)/makefiles/common.mk

TWEAK_NAME = libH5GGApp
libH5GGApp_FILES = globalview.mm ContextHostManager.mm
libH5GGApp_CFLAGS = -fobjc-arc -fvisibility=hidden 
libH5GGApp_CCFLAGS = -fobjc-arc -fvisibility=hidden -std=c++11

#libH5GGApp_LDFLAGS += -weak_library libAPAppView.dylib

#libH5GGApp_LOGOS_DEFAULT_GENERATOR = internal

include $(THEOS_MAKE_PATH)/tweak.mk

clean::
	rm -rf ./packages/*
	rm -rf ./layout

before-package::
	find . -name '*.DS_Store' -type f -delete
	cp -R ./H5GGApp_layout/ ./.theos/_/
	cd .. && make 
	cp ./.theos/obj/H5GG.dylib ./.theos/_/Applications/h5ggapp.app/
	
