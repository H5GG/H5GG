
DEBUG=0
STRIP=1
FINALPACKAGE=1
THEOS_DEVICE_IP = iphoneX.local
THEOS_PLATFORM_DEB_COMPRESSION_TYPE = gzip

include $(THEOS)/makefiles/common.mk

TWEAK_NAME = h5ggapp

h5ggapp_LOGOS_DEFAULT_GENERATOR = internal

include $(THEOS_MAKE_PATH)/tweak.mk

clean::
	rm -rf ./packages/*
	rm -rf ./layout

before-package::
	find . -name '*.DS_Store' -type f -delete
	cp -R ./H5GGApp_layout/ ./.theos/_/
	ldid -S../app.entitlements ./.theos/_/Applications/h5ggapp.app/h5ggapp
	rm -rf ./.theos/_/Library
	cd .. && make
	cp ./.theos/obj/H5GG.dylib ./.theos/_/Applications/h5ggapp.app/
	mkdir ./packages/Payload
	cp -R ./.theos/_/Applications/h5ggapp.app ./packages/Payload
	cd ./packages && zip -mr ./TrollStore_H5GG.tipa ./Payload
