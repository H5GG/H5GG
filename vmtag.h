//
//  name_for_tag.h
//  h5gg
//
//  Created by admin on 15/4/2022.
//

#ifndef name_for_tag_h
#define name_for_tag_h


#define VM_MEMORY_MALLOC 1
#define VM_MEMORY_MALLOC_SMALL 2
#define VM_MEMORY_MALLOC_LARGE 3
#define VM_MEMORY_MALLOC_HUGE 4
#define VM_MEMORY_SBRK 5// uninteresting -- no one should call
#define VM_MEMORY_REALLOC 6
#define VM_MEMORY_MALLOC_TINY 7
#define VM_MEMORY_MALLOC_LARGE_REUSABLE 8
#define VM_MEMORY_MALLOC_LARGE_REUSED 9

#define VM_MEMORY_ANALYSIS_TOOL 10

#define VM_MEMORY_MALLOC_NANO 11
#define VM_MEMORY_MALLOC_MEDIUM 12
#define VM_MEMORY_MALLOC_PGUARD 13  // Will be removed
#define VM_MEMORY_MALLOC_PROB_GUARD 13

#define VM_MEMORY_MACH_MSG 20
#define VM_MEMORY_IOKIT 21
#define VM_MEMORY_STACK  30
#define VM_MEMORY_GUARD  31
#define VM_MEMORY_SHARED_PMAP 32
/* memory containing a dylib */
#define VM_MEMORY_DYLIB 33
#define VM_MEMORY_OBJC_DISPATCHERS 34

/* Was a nested pmap (VM_MEMORY_SHARED_PMAP) which has now been unnested */
#define VM_MEMORY_UNSHARED_PMAP 35


// Placeholders for now -- as we analyze the libraries and find how they
// use memory, we can make these labels more specific.
#define VM_MEMORY_APPKIT 40
#define VM_MEMORY_FOUNDATION 41
#define VM_MEMORY_COREGRAPHICS 42
#define VM_MEMORY_CORESERVICES 43
#define VM_MEMORY_CARBON VM_MEMORY_CORESERVICES
#define VM_MEMORY_JAVA 44
#define VM_MEMORY_COREDATA 45
#define VM_MEMORY_COREDATA_OBJECTIDS 46
#define VM_MEMORY_ATS 50
#define VM_MEMORY_LAYERKIT 51
#define VM_MEMORY_CGIMAGE 52
#define VM_MEMORY_TCMALLOC 53

/* private raster data (i.e. layers, some images, QGL allocator) */
#define VM_MEMORY_COREGRAPHICS_DATA     54

/* shared image and font caches */
#define VM_MEMORY_COREGRAPHICS_SHARED   55

/* Memory used for virtual framebuffers, shadowing buffers, etc... */
#define VM_MEMORY_COREGRAPHICS_FRAMEBUFFERS     56

/* Window backing stores, custom shadow data, and compressed backing stores */
#define VM_MEMORY_COREGRAPHICS_BACKINGSTORES    57

/* x-alloc'd memory */
#define VM_MEMORY_COREGRAPHICS_XALLOC 58

/* catch-all for other uses, such as the read-only shared data page */
#define VM_MEMORY_COREGRAPHICS_MISC VM_MEMORY_COREGRAPHICS

/* memory allocated by the dynamic loader for itself */
#define VM_MEMORY_DYLD 60
/* malloc'd memory created by dyld */
#define VM_MEMORY_DYLD_MALLOC 61

/* Used for sqlite page cache */
#define VM_MEMORY_SQLITE 62

/* JavaScriptCore heaps */
#define VM_MEMORY_JAVASCRIPT_CORE 63
#define VM_MEMORY_WEBASSEMBLY VM_MEMORY_JAVASCRIPT_CORE
/* memory allocated for the JIT */
#define VM_MEMORY_JAVASCRIPT_JIT_EXECUTABLE_ALLOCATOR 64
#define VM_MEMORY_JAVASCRIPT_JIT_REGISTER_FILE 65

/* memory allocated for GLSL */
#define VM_MEMORY_GLSL  66

/* memory allocated for OpenCL.framework */
#define VM_MEMORY_OPENCL    67

/* memory allocated for QuartzCore.framework */
#define VM_MEMORY_COREIMAGE 68

/* memory allocated for WebCore Purgeable Buffers */
#define VM_MEMORY_WEBCORE_PURGEABLE_BUFFERS 69

/* ImageIO memory */
#define VM_MEMORY_IMAGEIO       70

/* CoreProfile memory */
#define VM_MEMORY_COREPROFILE   71

/* assetsd / MobileSlideShow memory */
#define VM_MEMORY_ASSETSD       72

/* libsystem_kernel os_once_alloc */
#define VM_MEMORY_OS_ALLOC_ONCE 73

/* libdispatch internal allocator */
#define VM_MEMORY_LIBDISPATCH 74

/* Accelerate.framework image backing stores */
#define VM_MEMORY_ACCELERATE 75

/* CoreUI image block data */
#define VM_MEMORY_COREUI 76

/* CoreUI image file */
#define VM_MEMORY_COREUIFILE 77

/* Genealogy buffers */
#define VM_MEMORY_GENEALOGY 78

/* RawCamera VM allocated memory */
#define VM_MEMORY_RAWCAMERA 79

/* corpse info for dead process */
#define VM_MEMORY_CORPSEINFO 80

/* Apple System Logger (ASL) messages */
#define VM_MEMORY_ASL 81

/* Swift runtime */
#define VM_MEMORY_SWIFT_RUNTIME 82

/* Swift metadata */
#define VM_MEMORY_SWIFT_METADATA 83

/* DHMM data */
#define VM_MEMORY_DHMM 84


/* memory allocated by SceneKit.framework */
#define VM_MEMORY_SCENEKIT 86

/* memory allocated by skywalk networking */
#define VM_MEMORY_SKYWALK 87

#define VM_MEMORY_IOSURFACE 88

#define VM_MEMORY_LIBNETWORK 89

#define VM_MEMORY_AUDIO 90

#define VM_MEMORY_VIDEOBITSTREAM 91

/* memory allocated by CoreMedia */
#define VM_MEMORY_CM_XPC 92

#define VM_MEMORY_CM_RPC 93

#define VM_MEMORY_CM_MEMORYPOOL 94

#define VM_MEMORY_CM_READCACHE 95

#define VM_MEMORY_CM_CRABS 96

/* memory allocated for QuickLookThumbnailing */
#define VM_MEMORY_QUICKLOOK_THUMBNAILS 97

/* memory allocated by Accounts framework */
#define VM_MEMORY_ACCOUNTS 98

/* memory allocated by Sanitizer runtime libraries */
#define VM_MEMORY_SANITIZER 99

/* Differentiate memory needed by GPU drivers and frameworks from generic IOKit allocations */
#define VM_MEMORY_IOACCELERATOR 100

/* memory allocated by CoreMedia for global image registration of frames */
#define VM_MEMORY_CM_REGWARP 101

/* memory allocated by EmbeddedAcousticRecognition for speech decoder */
#define VM_MEMORY_EAR_DECODER 102

/* CoreUI cached image data */
#define VM_MEMORY_COREUI_CACHED_IMAGE_DATA 103

/* ColorSync is using mmap for read-only copies of ICC profile data */
#define VM_MEMORY_COLORSYNC 104

/* Reserve 230-239 for Rosetta */
#define VM_MEMORY_ROSETTA 230
#define VM_MEMORY_ROSETTA_THREAD_CONTEXT 231
#define VM_MEMORY_ROSETTA_INDIRECT_BRANCH_MAP 232
#define VM_MEMORY_ROSETTA_RETURN_STACK 233
#define VM_MEMORY_ROSETTA_EXECUTABLE_HEAP 234
#define VM_MEMORY_ROSETTA_USER_LDT 235
#define VM_MEMORY_ROSETTA_ARENA 236
#define VM_MEMORY_ROSETTA_10 239

/* Reserve 240-255 for application */
#define VM_MEMORY_APPLICATION_SPECIFIC_1 240
#define VM_MEMORY_APPLICATION_SPECIFIC_16 255

#define VM_MAKE_TAG(tag) ((tag) << 24)


static const char *name_for_tag(int tag)
{
    switch (tag) {
//    case VM_MEMORY_MALLOC: return "malloc";
//    case VM_MEMORY_MALLOC_TINY: return "malloc tiny";
//    case VM_MEMORY_MALLOC_SMALL: return "malloc small";
//    case VM_MEMORY_MALLOC_LARGE: return "malloc large";
//    case VM_MEMORY_MALLOC_HUGE: return "malloc huge";
//    case VM_MEMORY_REALLOC: return "malloc realloc";
//    case VM_MEMORY_SBRK: return "sbrk";
//    case VM_MEMORY_ANALYSIS_TOOL: return "Performance tool data";
//    case VM_MEMORY_MACH_MSG: return "Mach message";
//    case VM_MEMORY_IOKIT: return "IOKit";
//    case VM_MEMORY_STACK: return "Stack";
//    case VM_MEMORY_GUARD: return "Guard";
//    case VM_MEMORY_APPKIT: return "AppKit";
//    case VM_MEMORY_FOUNDATION: return "Foundation";
//    case VM_MEMORY_COREGRAPHICS: return "CoreGraphics";
//    case VM_MEMORY_CARBON: return "Carbon";
//    case VM_MEMORY_JAVA: return "Java";
//    case VM_MEMORY_ATS: return "ATS (font support)";
            
            
case VM_MEMORY_MALLOC: return "MALLOC";
case VM_MEMORY_MALLOC_SMALL: return "MALLOC_SMALL";
case VM_MEMORY_MALLOC_LARGE: return "MALLOC_LARGE";
case VM_MEMORY_MALLOC_HUGE: return "MALLOC_HUGE";
case VM_MEMORY_SBRK: return "SBRK";// uninteresting -- no one should call
case VM_MEMORY_REALLOC: return "REALLOC";
case VM_MEMORY_MALLOC_TINY: return "MALLOC_TINY";
case VM_MEMORY_MALLOC_LARGE_REUSABLE: return "MALLOC_LARGE_REUSABLE";
case VM_MEMORY_MALLOC_LARGE_REUSED: return "MALLOC_LARGE_REUSED";

case VM_MEMORY_ANALYSIS_TOOL: return "ANALYSIS_TOOL";

case VM_MEMORY_MALLOC_NANO: return "MALLOC_NANO";
case VM_MEMORY_MALLOC_MEDIUM: return "MALLOC_MEDIUM";
case VM_MEMORY_MALLOC_PGUARD: return "MALLOC_PGUARD";  // Will be removed
//case VM_MEMORY_MALLOC_PROB_GUARD: return "MALLOC_PROB_GUARD";

case VM_MEMORY_MACH_MSG: return "MACH_MSG";
case VM_MEMORY_IOKIT: return "IOKIT";
case VM_MEMORY_STACK: return "STACK";
case VM_MEMORY_GUARD: return "GUARD";
case VM_MEMORY_SHARED_PMAP: return "SHARED_PMAP";
/* memory containing a dylib */
case VM_MEMORY_DYLIB: return "DYLIB";
case VM_MEMORY_OBJC_DISPATCHERS: return "OBJC_DISPATCHERS";

/* Was a nested pmap (VM_MEMORY_SHARED_PMAP) which has now been unnested */
case VM_MEMORY_UNSHARED_PMAP: return "UNSHARED_PMAP";


// Placeholders for now -- as we analyze the libraries and find how they
// use memory, we can make these labels more specific.
case VM_MEMORY_APPKIT: return "APPKIT";
case VM_MEMORY_FOUNDATION: return "FOUNDATION";
case VM_MEMORY_COREGRAPHICS: return "COREGRAPHICS";
case VM_MEMORY_CORESERVICES: return "CORESERVICES";
#define VM_MEMORY_CARBON VM_MEMORY_CORESERVICES
case VM_MEMORY_JAVA: return "JAVA";
case VM_MEMORY_COREDATA: return "COREDATA";
case VM_MEMORY_COREDATA_OBJECTIDS: return "COREDATA_OBJECTIDS";
case VM_MEMORY_ATS: return "ATS";
case VM_MEMORY_LAYERKIT: return "LAYERKIT";
case VM_MEMORY_CGIMAGE: return "CGIMAGE";
case VM_MEMORY_TCMALLOC: return "TCMALLOC";

/* private raster data (i.e. layers, some images, QGL allocator) */
case VM_MEMORY_COREGRAPHICS_DATA: return "COREGRAPHICS_DATA";

/* shared image and font caches */
case VM_MEMORY_COREGRAPHICS_SHARED: return "COREGRAPHICS_SHARED";

/* Memory used for virtual framebuffers, shadowing buffers, etc... */
case VM_MEMORY_COREGRAPHICS_FRAMEBUFFERS: return "COREGRAPHICS_FRAMEBUFFERS";

/* Window backing stores, custom shadow data, and compressed backing stores */
case VM_MEMORY_COREGRAPHICS_BACKINGSTORES: return "COREGRAPHICS_BACKINGSTORES";

/* x-alloc'd memory */
case VM_MEMORY_COREGRAPHICS_XALLOC: return "COREGRAPHICS_XALLOC";

/* catch-all for other uses, such as the read-only shared data page */
#define VM_MEMORY_COREGRAPHICS_MISC VM_MEMORY_COREGRAPHICS

/* memory allocated by the dynamic loader for itself */
case VM_MEMORY_DYLD: return "DYLD";
/* malloc'd memory created by dyld */
case VM_MEMORY_DYLD_MALLOC: return "DYLD_MALLOC";

/* Used for sqlite page cache */
case VM_MEMORY_SQLITE: return "SQLITE";

/* JavaScriptCore heaps */
case VM_MEMORY_JAVASCRIPT_CORE: return "JAVASCRIPT_CORE";
#define VM_MEMORY_WEBASSEMBLY VM_MEMORY_JAVASCRIPT_CORE
/* memory allocated for the JIT */
case VM_MEMORY_JAVASCRIPT_JIT_EXECUTABLE_ALLOCATOR: return "JAVASCRIPT_JIT_EXECUTABLE_ALLOCATOR";
case VM_MEMORY_JAVASCRIPT_JIT_REGISTER_FILE: return "JAVASCRIPT_JIT_REGISTER_FILE";

/* memory allocated for GLSL */
case VM_MEMORY_GLSL: return "GLSL";

/* memory allocated for OpenCL.framework */
case VM_MEMORY_OPENCL: return "OPENCL";

/* memory allocated for QuartzCore.framework */
case VM_MEMORY_COREIMAGE: return "COREIMAGE";

/* memory allocated for WebCore Purgeable Buffers */
case VM_MEMORY_WEBCORE_PURGEABLE_BUFFERS: return "WEBCORE_PURGEABLE_BUFFERS";

/* ImageIO memory */
case VM_MEMORY_IMAGEIO: return "IMAGEIO";

/* CoreProfile memory */
case VM_MEMORY_COREPROFILE: return "COREPROFILE";

/* assetsd / MobileSlideShow memory */
case VM_MEMORY_ASSETSD: return "ASSETSD";

/* libsystem_kernel os_once_alloc */
case VM_MEMORY_OS_ALLOC_ONCE: return "OS_ALLOC_ONCE";

/* libdispatch internal allocator */
case VM_MEMORY_LIBDISPATCH: return "LIBDISPATCH";

/* Accelerate.framework image backing stores */
case VM_MEMORY_ACCELERATE: return "ACCELERATE";

/* CoreUI image block data */
case VM_MEMORY_COREUI: return "COREUI";

/* CoreUI image file */
case VM_MEMORY_COREUIFILE: return "COREUIFILE";

/* Genealogy buffers */
case VM_MEMORY_GENEALOGY: return "GENEALOGY";

/* RawCamera VM allocated memory */
case VM_MEMORY_RAWCAMERA: return "RAWCAMERA";

/* corpse info for dead process */
case VM_MEMORY_CORPSEINFO: return "CORPSEINFO";

/* Apple System Logger (ASL) messages */
case VM_MEMORY_ASL: return "ASL";

/* Swift runtime */
case VM_MEMORY_SWIFT_RUNTIME: return "SWIFT_RUNTIME";

/* Swift metadata */
case VM_MEMORY_SWIFT_METADATA: return "SWIFT_METADATA";

/* DHMM data */
case VM_MEMORY_DHMM: return "DHMM";


/* memory allocated by SceneKit.framework */
case VM_MEMORY_SCENEKIT: return "SCENEKIT";

/* memory allocated by skywalk networking */
case VM_MEMORY_SKYWALK: return "SKYWALK";

case VM_MEMORY_IOSURFACE: return "IOSURFACE";

case VM_MEMORY_LIBNETWORK: return "LIBNETWORK";

case VM_MEMORY_AUDIO: return "AUDIO";

case VM_MEMORY_VIDEOBITSTREAM: return "VIDEOBITSTREAM";

/* memory allocated by CoreMedia */
case VM_MEMORY_CM_XPC: return "CM_XPC";

case VM_MEMORY_CM_RPC: return "CM_RPC";

case VM_MEMORY_CM_MEMORYPOOL: return "CM_MEMORYPOOL";

case VM_MEMORY_CM_READCACHE: return "CM_READCACHE";

case VM_MEMORY_CM_CRABS: return "CM_CRABS";

/* memory allocated for QuickLookThumbnailing */
case VM_MEMORY_QUICKLOOK_THUMBNAILS: return "QUICKLOOK_THUMBNAILS";

/* memory allocated by Accounts framework */
case VM_MEMORY_ACCOUNTS: return "ACCOUNTS";

/* memory allocated by Sanitizer runtime libraries */
case VM_MEMORY_SANITIZER: return "SANITIZER";

/* Differentiate memory needed by GPU drivers and frameworks from generic IOKit allocations */
case VM_MEMORY_IOACCELERATOR: return "IOACCELERATOR";

/* memory allocated by CoreMedia for global image registration of frames */
case VM_MEMORY_CM_REGWARP: return "CM_REGWARP";

/* memory allocated by EmbeddedAcousticRecognition for speech decoder */
case VM_MEMORY_EAR_DECODER: return "EAR_DECODER";

/* CoreUI cached image data */
case VM_MEMORY_COREUI_CACHED_IMAGE_DATA: return "COREUI_CACHED_IMAGE_DATA";

/* ColorSync is using mmap for read-only copies of ICC profile data */
case VM_MEMORY_COLORSYNC: return "COLORSYNC";

/* Reserve 230-239 for Rosetta */
case VM_MEMORY_ROSETTA: return "ROSETTA";
case VM_MEMORY_ROSETTA_THREAD_CONTEXT: return "ROSETTA_THREAD_CONTEXT";
case VM_MEMORY_ROSETTA_INDIRECT_BRANCH_MAP: return "ROSETTA_INDIRECT_BRANCH_MAP";
case VM_MEMORY_ROSETTA_RETURN_STACK: return "ROSETTA_RETURN_STACK";
case VM_MEMORY_ROSETTA_EXECUTABLE_HEAP: return "ROSETTA_EXECUTABLE_HEAP";
case VM_MEMORY_ROSETTA_USER_LDT: return "ROSETTA_USER_LDT";
case VM_MEMORY_ROSETTA_ARENA: return "ROSETTA_ARENA";
case VM_MEMORY_ROSETTA_10: return "ROSETTA_10";

/* Reserve 240-255 for application */
case VM_MEMORY_APPLICATION_SPECIFIC_1: return "APPLICATION_SPECIFIC_1";
case VM_MEMORY_APPLICATION_SPECIFIC_16: return "APPLICATION_SPECIFIC_16";
            
        case 0: return "";
            
        default: {
            static char s[128];
            sprintf(s, "<Unknown:%d>", tag);
            return s;
        }
    }
}



#endif /* name_for_tag_h */
