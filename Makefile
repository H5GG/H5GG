#need theos branch kabiroberai/arch-schemas

ARCHS = arm64 arm64e:v1 arm64e:v2

TARGET = iphone:13.7:11.4
#to support arch:subtype we need a patched lipo
TARGET_LIPO = $(THEOS)/bin/lipo.patched
#for arm64e-ios13 we need xcode11.7
V1.THEOS_PLATFORM_SDK_ROOT = /Applications/Xcode-11.7.app/Contents/Developer
#this branch removed export TARGET_CC TARGET_CXX TARGET_LD TARGET_STRIP TARGET_CODESIGN_ALLOCATE TARGET_CODESIGN TARGET_CODESIGN_FLAGS
export TARGET_CXX = $(THEOS_PLATFORM_SDK_ROOT)/Toolchains/XcodeDefault.xctoolchain/usr/bin/clang++
export TARGET_LD = $(THEOS_PLATFORM_SDK_ROOT)/Toolchains/XcodeDefault.xctoolchain/usr/bin/clang++
export TARGET_STRIP = $(THEOS_PLATFORM_SDK_ROOT)/Toolchains/XcodeDefault.xctoolchain/usr/bin/strip

ifeq ($(THEOS), )
	export THEOS=/var/mobile/theos
endif

THEOS_DEVICE_IP = 192.168.101.8

THEOS_PLATFORM_DEB_COMPRESSION_TYPE = gzip

DEBUG=0
STRIP=1
FINALPACKAGE=1

include $(THEOS)/makefiles/common.mk


H5GGApp=1

ifeq ($(H5GGApp), 0)
TWEAK_NAME = H5GG
H5GG_FILES = Tweak.mm
H5GG_CFLAGS = -fobjc-arc -fvisibility=hidden 
H5GG_CCFLAGS = -fobjc-arc -fvisibility=hidden -std=c++11
H5GG_LOGOS_DEFAULT_GENERATOR = internal
endif

ifeq ($(H5GGApp), 1)
TWEAK_NAME = H5GGApp
H5GGApp_FILES = Tweak.mm globalview.mm
H5GGApp_CFLAGS = -fobjc-arc -fvisibility=hidden 
H5GGApp_CCFLAGS = -fobjc-arc -fvisibility=hidden -std=c++11
H5GGApp_LOGOS_DEFAULT_GENERATOR = internal
H5GGApp_LDFLAGS += -weak_library libAPAppView.dylib -weak_library BackgrounderActionCore.dylib
before-package::
	cp -R ./H5GGApp_layout/ ./.theos/_/
endif

include $(THEOS_MAKE_PATH)/tweak.mk

clean::
	rm -rf ./packages/*
	rm -rf ./layout

