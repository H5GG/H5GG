////
////  name_for_tag.h
////  h5gg
////
////  Created by admin on 15/4/2022.
////
//
//#ifndef name_for_tag_h
//#define name_for_tag_h
//
//
//static const char *name_for_tag(int tag)
//{
//    switch (tag) {
////    case VM_MEMORY_MALLOC: return "malloc";
////    case VM_MEMORY_MALLOC_TINY: return "malloc tiny";
////    case VM_MEMORY_MALLOC_SMALL: return "malloc small";
////    case VM_MEMORY_MALLOC_LARGE: return "malloc large";
////    case VM_MEMORY_MALLOC_HUGE: return "malloc huge";
////    case VM_MEMORY_REALLOC: return "malloc realloc";
////    case VM_MEMORY_SBRK: return "sbrk";
////    case VM_MEMORY_ANALYSIS_TOOL: return "Performance tool data";
////    case VM_MEMORY_MACH_MSG: return "Mach message";
////    case VM_MEMORY_IOKIT: return "IOKit";
////    case VM_MEMORY_STACK: return "Stack";
////    case VM_MEMORY_GUARD: return "Guard";
////    case VM_MEMORY_APPKIT: return "AppKit";
////    case VM_MEMORY_FOUNDATION: return "Foundation";
////    case VM_MEMORY_COREGRAPHICS: return "CoreGraphics";
////    case VM_MEMORY_CARBON: return "Carbon";
////    case VM_MEMORY_JAVA: return "Java";
////    case VM_MEMORY_ATS: return "ATS (font support)";
//            
//            
//case VM_MEMORY_MALLOC: return "MALLOC";
//case VM_MEMORY_MALLOC_SMALL: return "MALLOC_SMALL";
//case VM_MEMORY_MALLOC_LARGE: return "MALLOC_LARGE";
//case VM_MEMORY_MALLOC_HUGE: return "MALLOC_HUGE";
//case VM_MEMORY_SBRK: return "SBRK";// uninteresting -- no one should call
//case VM_MEMORY_REALLOC: return "REALLOC";
//case VM_MEMORY_MALLOC_TINY: return "MALLOC_TINY";
//case VM_MEMORY_MALLOC_LARGE_REUSABLE: return "MALLOC_LARGE_REUSABLE";
//case VM_MEMORY_MALLOC_LARGE_REUSED: return "MALLOC_LARGE_REUSED";
//
//case VM_MEMORY_ANALYSIS_TOOL: return "ANALYSIS_TOOL";
//
//case VM_MEMORY_MALLOC_NANO: return "MALLOC_NANO";
//case VM_MEMORY_MALLOC_MEDIUM: return "MALLOC_MEDIUM";
//case VM_MEMORY_MALLOC_PGUARD: return "MALLOC_PGUARD";  // Will be removed
////case VM_MEMORY_MALLOC_PROB_GUARD: return "MALLOC_PROB_GUARD";
//
//case VM_MEMORY_MACH_MSG: return "MACH_MSG";
//case VM_MEMORY_IOKIT: return "IOKIT";
//case VM_MEMORY_STACK: return "STACK";
//case VM_MEMORY_GUARD: return "GUARD";
//case VM_MEMORY_SHARED_PMAP: return "SHARED_PMAP";
///* memory containing a dylib */
//case VM_MEMORY_DYLIB: return "DYLIB";
//case VM_MEMORY_OBJC_DISPATCHERS: return "OBJC_DISPATCHERS";
//
///* Was a nested pmap (VM_MEMORY_SHARED_PMAP) which has now been unnested */
//case VM_MEMORY_UNSHARED_PMAP: return "UNSHARED_PMAP";
//
//
//// Placeholders for now -- as we analyze the libraries and find how they
//// use memory, we can make these labels more specific.
//case VM_MEMORY_APPKIT: return "APPKIT";
//case VM_MEMORY_FOUNDATION: return "FOUNDATION";
//case VM_MEMORY_COREGRAPHICS: return "COREGRAPHICS";
//case VM_MEMORY_CORESERVICES: return "CORESERVICES";
//#define VM_MEMORY_CARBON VM_MEMORY_CORESERVICES
//case VM_MEMORY_JAVA: return "JAVA";
//case VM_MEMORY_COREDATA: return "COREDATA";
//case VM_MEMORY_COREDATA_OBJECTIDS: return "COREDATA_OBJECTIDS";
//case VM_MEMORY_ATS: return "ATS";
//case VM_MEMORY_LAYERKIT: return "LAYERKIT";
//case VM_MEMORY_CGIMAGE: return "CGIMAGE";
//case VM_MEMORY_TCMALLOC: return "TCMALLOC";
//
///* private raster data (i.e. layers, some images, QGL allocator) */
//case VM_MEMORY_COREGRAPHICS_DATA: return "COREGRAPHICS_DATA";
//
///* shared image and font caches */
//case VM_MEMORY_COREGRAPHICS_SHARED: return "COREGRAPHICS_SHARED";
//
///* Memory used for virtual framebuffers, shadowing buffers, etc... */
//case VM_MEMORY_COREGRAPHICS_FRAMEBUFFERS: return "COREGRAPHICS_FRAMEBUFFERS";
//
///* Window backing stores, custom shadow data, and compressed backing stores */
//case VM_MEMORY_COREGRAPHICS_BACKINGSTORES: return "COREGRAPHICS_BACKINGSTORES";
//
///* x-alloc'd memory */
//case VM_MEMORY_COREGRAPHICS_XALLOC: return "COREGRAPHICS_XALLOC";
//
///* catch-all for other uses, such as the read-only shared data page */
//#define VM_MEMORY_COREGRAPHICS_MISC VM_MEMORY_COREGRAPHICS
//
///* memory allocated by the dynamic loader for itself */
//case VM_MEMORY_DYLD: return "DYLD";
///* malloc'd memory created by dyld */
//case VM_MEMORY_DYLD_MALLOC: return "DYLD_MALLOC";
//
///* Used for sqlite page cache */
//case VM_MEMORY_SQLITE: return "SQLITE";
//
///* JavaScriptCore heaps */
//case VM_MEMORY_JAVASCRIPT_CORE: return "JAVASCRIPT_CORE";
//#define VM_MEMORY_WEBASSEMBLY VM_MEMORY_JAVASCRIPT_CORE
///* memory allocated for the JIT */
//case VM_MEMORY_JAVASCRIPT_JIT_EXECUTABLE_ALLOCATOR: return "JAVASCRIPT_JIT_EXECUTABLE_ALLOCATOR";
//case VM_MEMORY_JAVASCRIPT_JIT_REGISTER_FILE: return "JAVASCRIPT_JIT_REGISTER_FILE";
//
///* memory allocated for GLSL */
//case VM_MEMORY_GLSL: return "GLSL";
//
///* memory allocated for OpenCL.framework */
//case VM_MEMORY_OPENCL: return "OPENCL";
//
///* memory allocated for QuartzCore.framework */
//case VM_MEMORY_COREIMAGE: return "COREIMAGE";
//
///* memory allocated for WebCore Purgeable Buffers */
//case VM_MEMORY_WEBCORE_PURGEABLE_BUFFERS: return "WEBCORE_PURGEABLE_BUFFERS";
//
///* ImageIO memory */
//case VM_MEMORY_IMAGEIO: return "IMAGEIO";
//
///* CoreProfile memory */
//case VM_MEMORY_COREPROFILE: return "COREPROFILE";
//
///* assetsd / MobileSlideShow memory */
//case VM_MEMORY_ASSETSD: return "ASSETSD";
//
///* libsystem_kernel os_once_alloc */
//case VM_MEMORY_OS_ALLOC_ONCE: return "OS_ALLOC_ONCE";
//
///* libdispatch internal allocator */
//case VM_MEMORY_LIBDISPATCH: return "LIBDISPATCH";
//
///* Accelerate.framework image backing stores */
//case VM_MEMORY_ACCELERATE: return "ACCELERATE";
//
///* CoreUI image block data */
//case VM_MEMORY_COREUI: return "COREUI";
//
///* CoreUI image file */
//case VM_MEMORY_COREUIFILE: return "COREUIFILE";
//
///* Genealogy buffers */
//case VM_MEMORY_GENEALOGY: return "GENEALOGY";
//
///* RawCamera VM allocated memory */
//case VM_MEMORY_RAWCAMERA: return "RAWCAMERA";
//
///* corpse info for dead process */
//case VM_MEMORY_CORPSEINFO: return "CORPSEINFO";
//
///* Apple System Logger (ASL) messages */
//case VM_MEMORY_ASL: return "ASL";
//
///* Swift runtime */
//case VM_MEMORY_SWIFT_RUNTIME: return "SWIFT_RUNTIME";
//
///* Swift metadata */
//case VM_MEMORY_SWIFT_METADATA: return "SWIFT_METADATA";
//
///* DHMM data */
//case VM_MEMORY_DHMM: return "DHMM";
//
//
///* memory allocated by SceneKit.framework */
//case VM_MEMORY_SCENEKIT: return "SCENEKIT";
//
///* memory allocated by skywalk networking */
//case VM_MEMORY_SKYWALK: return "SKYWALK";
//
//case VM_MEMORY_IOSURFACE: return "IOSURFACE";
//
//case VM_MEMORY_LIBNETWORK: return "LIBNETWORK";
//
//case VM_MEMORY_AUDIO: return "AUDIO";
//
//case VM_MEMORY_VIDEOBITSTREAM: return "VIDEOBITSTREAM";
//
///* memory allocated by CoreMedia */
//case VM_MEMORY_CM_XPC: return "CM_XPC";
//
//case VM_MEMORY_CM_RPC: return "CM_RPC";
//
//case VM_MEMORY_CM_MEMORYPOOL: return "CM_MEMORYPOOL";
//
//case VM_MEMORY_CM_READCACHE: return "CM_READCACHE";
//
//case VM_MEMORY_CM_CRABS: return "CM_CRABS";
//
///* memory allocated for QuickLookThumbnailing */
//case VM_MEMORY_QUICKLOOK_THUMBNAILS: return "QUICKLOOK_THUMBNAILS";
//
///* memory allocated by Accounts framework */
//case VM_MEMORY_ACCOUNTS: return "ACCOUNTS";
//
///* memory allocated by Sanitizer runtime libraries */
//case VM_MEMORY_SANITIZER: return "SANITIZER";
//
///* Differentiate memory needed by GPU drivers and frameworks from generic IOKit allocations */
//case VM_MEMORY_IOACCELERATOR: return "IOACCELERATOR";
//
///* memory allocated by CoreMedia for global image registration of frames */
//case VM_MEMORY_CM_REGWARP: return "CM_REGWARP";
//
///* memory allocated by EmbeddedAcousticRecognition for speech decoder */
//case VM_MEMORY_EAR_DECODER: return "EAR_DECODER";
//
///* CoreUI cached image data */
//case VM_MEMORY_COREUI_CACHED_IMAGE_DATA: return "COREUI_CACHED_IMAGE_DATA";
//
///* ColorSync is using mmap for read-only copies of ICC profile data */
//case VM_MEMORY_COLORSYNC: return "COLORSYNC";
//
///* Reserve 230-239 for Rosetta */
//case VM_MEMORY_ROSETTA: return "ROSETTA";
//case VM_MEMORY_ROSETTA_THREAD_CONTEXT: return "ROSETTA_THREAD_CONTEXT";
//case VM_MEMORY_ROSETTA_INDIRECT_BRANCH_MAP: return "ROSETTA_INDIRECT_BRANCH_MAP";
//case VM_MEMORY_ROSETTA_RETURN_STACK: return "ROSETTA_RETURN_STACK";
//case VM_MEMORY_ROSETTA_EXECUTABLE_HEAP: return "ROSETTA_EXECUTABLE_HEAP";
//case VM_MEMORY_ROSETTA_USER_LDT: return "ROSETTA_USER_LDT";
//case VM_MEMORY_ROSETTA_ARENA: return "ROSETTA_ARENA";
//case VM_MEMORY_ROSETTA_10: return "ROSETTA_10";
//
///* Reserve 240-255 for application */
//case VM_MEMORY_APPLICATION_SPECIFIC_1: return "APPLICATION_SPECIFIC_1";
//case VM_MEMORY_APPLICATION_SPECIFIC_16: return "APPLICATION_SPECIFIC_16";
//            
//        case 0: return "";
//            
//        default: {
//            char* s = (char*)malloc(10);
//            sprintf(s, "<Unknown:%d>", tag);
//            return s;
//        }
//    }
//}
//
//
//
//#endif /* name_for_tag_h */
