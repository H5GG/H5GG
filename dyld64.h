#ifndef CLIENT_MAC_HANDLER_DYNAMIC_IMAGES_H__
#define CLIENT_MAC_HANDLER_DYNAMIC_IMAGES_H__

#include <sys/cdefs.h>
#include <sys/_types.h>

struct dyld_uuid_info64 {
	mach_vm_address_t			imageLoadAddress;	/* base address image is mapped into */
	uuid_t						imageUUID;			/* UUID of image */
};

struct dyld_image_info64 {
	mach_vm_address_t			imageLoadAddress;	/* base address image is mapped into */
	mach_vm_address_t			imageFilePath;		/* path dyld used to load the image */
	mach_vm_size_t				imageFileModDate;	/* time_t of image file */
													/* if stat().st_mtime of imageFilePath does not match imageFileModDate, */
													/* then file has been modified since dyld loaded it */
};

struct dyld_all_image_infos64 {
	uint32_t					version;
	uint32_t					infoArrayCount;
	mach_vm_address_t			infoArray;					// struct dyld_image_info64*
	dyld_image_notifier			notification;		
	bool						processDetachedFromSharedRegion;
	bool						libSystemInitialized;
	mach_vm_address_t			dyldImageLoadAddress;
	mach_vm_address_t			jitInfo;
	mach_vm_address_t			dyldVersion;				// char*
	mach_vm_address_t			errorMessage;				// char*
	uint64_t					terminationFlags;
	mach_vm_address_t			coreSymbolicationShmPage;
	uint64_t					systemOrderFlag;
	uint64_t					uuidArrayCount;
	mach_vm_address_t			uuidArray;					// struct dyld_uuid_info*
	mach_vm_address_t			dyldAllImageInfosAddress;	// struct dyld_all_image_infos64*
	uint64_t					initialImageCount;
	uint64_t					errorKind;
	mach_vm_address_t			errorClientOfDylibPath;		// char*
	mach_vm_address_t			errorTargetDylibPath;		// char*
	mach_vm_address_t			errorSymbol;				// char*
	uint64_t					sharedCacheSlide;
};

#endif	/* !CLIENT_MAC_HANDLER_DYNAMIC_IMAGES_H__ */
