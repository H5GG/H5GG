#ifndef JJ_Header_h
#define JJ_Header_h

//JJ内存搜索引擎(专为H5GG定制)

/* 一定要加上-fvisibility=hidden编译参数, 否则容易崩溃 */

#pragma GCC diagnostic ignored "-Wdeprecated-register"

#define JJLog(...) //NSLog(__VA_ARGS__)

#include <mach-o/dyld.h>
#include <mach/mach.h>
#include <sys/mman.h>
#include <stdio.h>

#include <vector>
#include <map>
#include <set>

using namespace std;

extern "C" kern_return_t mach_vm_region
(
     vm_map_t target_task,
     mach_vm_address_t *address,
     mach_vm_size_t *size,
     vm_region_flavor_t flavor,
     vm_region_info_t info,
     mach_msg_type_number_t *infoCnt,
     mach_port_t *object_name
 );

extern "C" kern_return_t mach_vm_protect
(
 vm_map_t target_task,
 mach_vm_address_t address,
 mach_vm_size_t size,
 boolean_t set_maximum,
 vm_prot_t new_protection
 );

enum JJ_Search_Type
{
    JJ_Search_Type_Error,
    
    JJ_Search_Type_Double,
    JJ_Search_Type_ULong,
    JJ_Search_Type_SLong,
    JJ_Search_Type_Float,
    JJ_Search_Type_UInt,
    JJ_Search_Type_SInt,
    JJ_Search_Type_UShort,
    JJ_Search_Type_SShort,
    JJ_Search_Type_UByte,
    JJ_Search_Type_SByte,
    
    JJ_Search_Type_Max,
};

const int JJ_Search_Type_Len[] = {0,8,8,8,4,4,4,2,2,1,1};


typedef struct _result_region{
    uint64_t region_base;
    size_t region_size;
    vector<uint32_t> slides;
    vector<int8_t> types;
    
    _result_region(uint64_t base, size_t size) {
        region_base = base;
        region_size = size;
    }
} result_region;

typedef struct _result{
    vector<result_region*> regions;
    size_t count;
} Result;

typedef struct _addrRange{
    uint64_t start;
    uint64_t end;
} AddrRange;

class JJMemoryEngine
{
    mach_port_t task;
    Result *result;
    map<uint64_t,uint64_t> regions;
    bool firstScanDone;
    float float_tolerance;
    int lastNumberType;
    
    void freeResults()
    {
        if(result->count != 0) {
            for(int i =0;i<result->regions.size();i++){
                
                result->regions[i]->slides.clear();
                result->regions[i]->slides.shrink_to_fit();
                result_region *dealloc_1 = result->regions[i];
                delete dealloc_1;
                
            }
        }
        result->regions.clear();
        result->regions.shrink_to_fit();
        Result *dealloc_2 = result;
        delete dealloc_2;
    }
    
    bool readMemory(void* buf, uint64_t addr, size_t len)
    {
        vm_size_t size = 0;
        kern_return_t kr = vm_read_overwrite(this->task, (vm_address_t)addr, len, (vm_address_t)buf, &size);
        if(kr != KERN_SUCCESS || size!=len)
        {
            NSLog(@"readMemory failed! %p %x : %d", addr, len, kr);
            return false;
        }
        
        return true;
    }
    
    bool writeMemory(void* address,void *target, size_t len)
    {
        kern_return_t error = vm_write(this->task, (vm_address_t)address, (vm_offset_t)target, (mach_msg_type_number_t)len);
        if(error != KERN_SUCCESS)
        {
            NSLog(@"writeMemory failed! %p %x", address, len);
            return false;
        }
        
        return true;
    }
    
    uint64_t ScanData(uint64_t buffer, uint64_t size, void* target, int type)
    {
        int len = JJ_Search_Type_Len[type];
        
        register uint64_t p=buffer;
        uint64_t end = buffer + size - len;
        if(type==JJ_Search_Type_Float) {
            register float value_up =  *((float*)target+1) + this->float_tolerance;
            register float value_down = *(float*)target - this->float_tolerance;
            while(p<=end) {
                register float v = *(float*)p;
                if(v>=value_down && v<=value_up) break;
                p+=len;
            }
        } else if(type==JJ_Search_Type_Double) {
            register double value_up =  *((double*)target+1) + this->float_tolerance;
            register double value_down = *(double*)target - this->float_tolerance;
            while(p<=end) {
                register double v = *(double*)p;
                if(v>=value_down && v<=value_up) break;
                p+=len;
            }
        } else if(len==1) {
            register uint8_t value_up =  *((uint8_t*)target+1);
            register uint8_t value_down = *(uint8_t*)target;
            while(p<=end) {
                register uint8_t v = *(uint8_t*)p;
                if(v>=value_down && v<=value_up) break;
                p+=len;
            }
        } else if(len==2) {
            register uint16_t value_up =  *((uint16_t*)target+1);
            register uint16_t value_down = *(uint16_t*)target;
            while(p<=end) {
                register uint16_t v = *(uint16_t*)p;
                if(v>=value_down && v<=value_up) break;
                p+=len;
            }
        } else if(len==4) {
            register uint32_t value_up =  *((uint32_t*)target+1);
            register uint32_t value_down = *(uint32_t*)target;
            while(p<=end) {
                register uint32_t v = *(uint32_t*)p;
                if(v>=value_down && v<=value_up) break;
                p+=len;
            }
        } else if(len==8) {
            register uint64_t value_up =  *((uint64_t*)target+1);
            register uint64_t value_down = *(uint64_t*)target;
            while(p<=end) {
                register uint64_t v = *(uint64_t*)p;
                if(v>=value_down && v<=value_up) break;
                p+=len;
            }
        }
        return p<=end ? p : 0;
    }
    
    void ScanRegion(AddrRange range, uint64_t base, uint64_t size, void* target, int type)
    {
        int len = JJ_Search_Type_Len[type];
        
        void* buffer = malloc(size);
        if(!buffer) throw bad_alloc();
        
        result_region* newRegion = NULL;
        
        if(readMemory(buffer, base, size))
        {
            uint64_t pcurdata = (uint64_t)buffer;
            uint64_t left_size = size;
            while(left_size >= len)
            {
                uint64_t pfound = ScanData(pcurdata, left_size, target, type);
                if(!pfound) break;
                
                uint32_t slide = pfound - (uint64_t)buffer;
                
                if((base+slide)<range.start || (base+slide)>=range.end) break;
                
                if(!newRegion)
                    newRegion = new result_region(base,size);
                
                newRegion->slides.push_back(slide);
                this->result->count++;
                
                pcurdata = pfound + len;
                left_size = (uint64_t)buffer+size - pcurdata;
            }
            
        } else {
            NSLog(@"read mem failed! %p %x", base, size);
        }
        
        if(newRegion) {
            newRegion->slides.shrink_to_fit();
            this->result->regions.push_back(newRegion);
        }
        
        free(buffer);
    }
    
    
    void FirstScan(AddrRange range, void* target, int type)
    {
        int len = JJ_Search_Type_Len[type];
        
        
        size_t stack_size=pthread_get_stacksize_np(pthread_self());
        size_t stack_addr=(size_t)pthread_get_stackaddr_np(pthread_self());
        size_t stack_end = stack_addr + stack_size;
        NSLog(@"stack=%p %x => %p", stack_addr, stack_size, stack_end);
        
        mach_port_t object_name;
        mach_vm_size_t region_size=0;
        mach_vm_address_t region_base = range.start;
        
        vm_region_basic_info_data_64_t info = {0};
        mach_msg_type_number_t info_cnt = VM_REGION_BASIC_INFO_COUNT_64;
        
        while(region_base < range.end) {
            region_base += region_size;
            kern_return_t kr = mach_vm_region(this->task, &region_base, &region_size,
                                              VM_REGION_BASIC_INFO_64, (vm_region_info_t)&info, &info_cnt, &object_name);
            
            if(kr != KERN_SUCCESS) {
                NSLog(@"mach_vm_region failed! %p", region_base);
                break;
            }
            
            NSLog(@"found region %p %x, %x %d", region_base, region_size, info.protection, info.reserved);
            
            uint64_t region_end = region_base+region_size;
            
            if(this->task==mach_task_self()) {
                if((stack_addr>=region_base && stack_addr<region_end)
                   || (stack_end>region_base && stack_addr<=region_end)) {
                    NSLog(@"skip stack region!");
                    continue;
                }
            }
            
            if(!(info.protection & VM_PROT_WRITE)) {
                NSLog(@"skip readlony region!");
                continue;
            }
                
            this->regions[region_base] = region_size;
        }
        
        for(auto region : this->regions) {
            NSLog(@"handle region %p %x [%d]", region.first, region.second, this->result->count);
            ScanRegion(range, region.first, region.second, target, type);
        }
        
        this->result->regions.shrink_to_fit();
    }
    
    void ScanAgain(AddrRange range, void* target, int type)
    {
        int len = JJ_Search_Type_Len[type];
        
        size_t newCount = 0;
        
        for(int i=0; i<this->result->regions.size(); i++)
        {
            result_region* region = this->result->regions[i];
            
            NSLog(@"handle region [%d] %p,%x : %d", i, region->region_base, region->region_size, region->slides.size());
            
            if((region->region_base+region->region_size)<range.start || region->region_base>range.end)
                continue;
            
            result_region* newRegion = NULL;
            
            void* buffer = malloc(region->region_size);
            if(!buffer) throw bad_alloc();
            
            bool read = readMemory(buffer, region->region_base, region->region_size);
            if(read) for(int j=0; j<region->slides.size(); j++)
            {
                UInt64 address = (UInt64)region->region_base + (UInt64)region->slides[j];
                void* pvalue = (void*)((UInt64)buffer + (UInt64)region->slides[j]);
                
                //NSLog(@"handle slide [%d] %p %x : %llX", j, address, region->slide[j], *(UInt64*)pvalue);
                
                if(address>=range.start && address<range.end &&
                   ScanData((uint64_t)pvalue, len, target, type))
                {
                    if(!newRegion)
                        newRegion = new result_region(region->region_base,region->region_size);
                        
                    //NSLog(@"found %p %x", region->region_base, region->slide[j]);
                    
                    newRegion->slides.push_back(region->slides[j]);
                    newCount++;
                }
            } else {
                NSLog(@"read mem failed! [%d] %p %x", i, region->region_base, region->region_size);
            }
            
            delete this->result->regions[i];
            this->result->regions[i] = newRegion;
            if(newRegion) newRegion->slides.shrink_to_fit();
            
            free(buffer);
        }
        
        
        this->result->regions.erase(
                                    remove(this->result->regions.begin(),this->result->regions.end(), (result_region*)NULL), this->result->regions.end());
        
        this->result->regions.shrink_to_fit();
        
        this->result->count = newCount;
    }
    
public:
    JJMemoryEngine(mach_port_t task){
        this->task = task;
        
        this->result = new Result;
        this->result->count = 0;
        
        this->firstScanDone = false;
        this->float_tolerance = 0.0;
        this->lastNumberType = 0;
    }
    
    ~JJMemoryEngine(){
        freeResults();
    }
    
    void SetFloatTolerance(float d)
    {
        this->float_tolerance = d;
    }
    
    void JJScanMemory(AddrRange range, void* target, int type)
    {
        if(type<=0 || type>=JJ_Search_Type_Max) return;
        
        this->lastNumberType = type;
        
        if(this->firstScanDone) {
            ScanAgain(range, target, type);
        } else {
            FirstScan(range, target, type);
            this->firstScanDone = true;
        }
    }

    void JJNearBySearch(int range, void *target, int type)
    {
        if(type<=0 || type>=JJ_Search_Type_Max) return;
        
        int len = JJ_Search_Type_Len[type];
        
        size_t newCount = 0;
        
        range -= range%len;
        range += len;
        
        for(int i=0; i<this->result->regions.size(); i++)
        {
            result_region* region = this->result->regions[i];
            
            bool hasType = region->types.size()>0;
            bool needType = hasType || type!=this->lastNumberType;
            
            NSLog(@"handle region [%d] %p,%x : %d", i, region->region_base, region->region_size, region->slides.size());
            
            result_region* newRegion = NULL;
            
            void* buffer = malloc(region->region_size);
            if(!buffer) throw bad_alloc();
            
            int lastold = 0;
            
            long lastpos = 0;
            
            bool read = readMemory(buffer, region->region_base, region->region_size);
            if(read) for(int j=0; j<region->slides.size(); j++)
            {
                map<uint32_t,int8_t> matched;
                
                uint32_t curslide = region->slides[j];
                long range_start = curslide - range;
                long range_end = curslide + range;
                
                if(range_start < 0) range_start = 0;
                if(range_end > region->region_size) range_end=region->region_size;
                
                if(lastpos > range_start)
                    range_start = lastpos;
                
                lastpos = range_end;
                
                uint64_t data = (uint64_t)buffer + range_start;
                size_t size = range_end - range_start;
                
                JJLog(@"%x[%d]%x [%x %x]", range, j, curslide, range_start, range_end);
                //assert(size>=0 && size<=range*2);
                
                int foundcount = 0;
                uint32_t foundfirst = 0;
                uint32_t foundlast = 0;
                
                uint64_t pcurdata = data;
                uint64_t left_size = size;
                while(left_size >= len)
                {
                    uint64_t pfound = ScanData(pcurdata, left_size, target, type);
                    if(!pfound) break;
                    
                    
                    uint32_t slide = pfound - (uint64_t)buffer;
                    
                    JJLog(@"found %x", slide);
                    
                    matched[slide] = type;
                    
                    if(foundcount==0) foundfirst = slide;
                    foundlast = slide;
                    foundcount++;
                    
                    pcurdata = pfound + len;
                    left_size = (uint64_t)data+size - pcurdata;
                }
                
                
                if(foundcount) for(int o=lastold; o<region->slides.size(); o++) {
                    
                    uint32_t oldslide = region->slides[o];
                    
                    long first_down = (foundfirst-range);
                    long first_up = (foundfirst+range);
                    long last_down = (foundlast-range);
                    long last_up = (foundlast+range);
                    
                    //assert(last_down<first_up);
                    
                    if((oldslide>first_down && oldslide<first_up) || (oldslide>last_down && oldslide<last_up))
                    {
                        JJLog(@"old %d %d [%d] %x", j, lastold, o, oldslide);
                        
                        matched[oldslide] = hasType ? region->types[o] : this->lastNumberType;
                        
                        lastold = o+1;
                    }
                }
                
                if(matched.size()) {
                    
                    if(!newRegion)
                        newRegion = new result_region(region->region_base, region->region_size);
                    
                    for(map<uint32_t,int8_t>::iterator it = matched.begin(); it != matched.end(); ++it) {
                        newRegion->slides.push_back(it->first);
                        if(needType) newRegion->types.push_back(it->second);
                    }
                    
                    newCount += matched.size();
                    
                    JJLog(@"nearby search region %p count=%d=>%d", region->region_base, matched.size(), newCount);
                }
                
            } else {
                NSLog(@"read mem failed! [%d] %p %x", i, region->region_base, region->region_size);
            }
            
            delete this->result->regions[i];
            this->result->regions[i] = newRegion;
            if(newRegion) {
                newRegion->slides.shrink_to_fit();
                newRegion->types.shrink_to_fit();
            }
            
            free(buffer);
        }
        
        
        this->result->regions.erase(
                                    remove(this->result->regions.begin(),this->result->regions.end(), (result_region*)NULL), this->result->regions.end());
        
        this->result->regions.shrink_to_fit();
        
        this->result->count = newCount;
    }
    
    bool JJReadMemory(void* buf, uint64_t addr, int type)
    {
        //NSLog(@"JJReadMemory %p %d", addr, type);
        
        if(type<=0 || type>=JJ_Search_Type_Max) return false;
        
        int len = JJ_Search_Type_Len[type];
        
        return readMemory(buf, addr, len);
    }
    
    bool JJWriteMemory(void* address,void *target, int type)
    {
        if(type<=0 || type>=JJ_Search_Type_Max) return false;
        
        int len = JJ_Search_Type_Len[type];
        
        mach_port_t object_name;
        mach_vm_size_t region_size=0;
        mach_vm_address_t region_base = (uint64_t)address;
        
        vm_region_basic_info_data_64_t info = {0};
        mach_msg_type_number_t info_cnt = VM_REGION_BASIC_INFO_COUNT_64;
        
        
        kern_return_t kr = mach_vm_region(this->task, &region_base, &region_size,
                                              VM_REGION_BASIC_INFO_64, (vm_region_info_t)&info, &info_cnt, &object_name);
        if(kr != KERN_SUCCESS) {
            NSLog(@"mach_vm_region failed! %p", region_base);
            return false;
        }
        
        vm_address_t base = 0;
        if(!(info.protection & VM_PROT_WRITE)) {
            NSLog(@"unwritable region %p %x : %x", region_base, region_size, info.protection);
            base = (uint64_t)address & ~PAGE_MASK;
            //c1越狱这里可能失败, 不能同时rwx??? c1这里返回成功但是实际上并没有成功!!!!
            kr = mach_vm_protect(this->task, base, PAGE_SIZE, false, info.protection|VM_PROT_WRITE|VM_PROT_COPY);
            if(kr != KERN_SUCCESS) {
                NSLog(@"vm_protect failed! kr=%d [%p %x] : %x", kr, base, PAGE_SIZE, info.protection);
                
                kr = mach_vm_protect(this->task, base, PAGE_SIZE, false, VM_PROT_READ|VM_PROT_WRITE|VM_PROT_COPY);
                if(kr != KERN_SUCCESS) {
                    NSLog(@"vm_protect failed2! kr=%d [%p %x] : %x", kr, base, PAGE_SIZE, info.protection);
                    
                    //NSLog(@"mprotect=%d, %d, %s", mprotect((void*)base, PAGE_SIZE, info.protection|VM_PROT_WRITE), errno, strerror(errno));
                    
                    return false;
                }
            }
        }
        
        bool result = writeMemory(address, target, len);
        
        if(!result && base) {
            
            kr = mach_vm_protect(this->task, base, PAGE_SIZE, false, VM_PROT_READ|VM_PROT_WRITE|VM_PROT_COPY);
            
            if(kr != KERN_SUCCESS) {
                NSLog(@"vm_protect again failed! kr=%d [%p %x] : %x", kr, base, PAGE_SIZE, info.protection);
            } else {
                result = writeMemory(address, target, len);
            }
        }
        
        if(base)
            vm_protect(this->task, base, PAGE_SIZE, false, info.protection);
        
        return result;
    }
    
    int JJWriteAll(void * target, int type)
    {
        if(type<=0 || type>=JJ_Search_Type_Max) return 0;
        
        int len = JJ_Search_Type_Len[type];
        
        int count=0;
        for(int i=0; i<this->result->regions.size(); i++)
        {
            result_region* region = result->regions[i];
            for(int j=0; j<region->slides.size(); j++)
            {
                uint64_t address = region->region_base + region->slides[j];
                if(writeMemory((void*)address, target, len))
                    count++;
            }
        }
        return count;
    }
     
    size_t getResultsCount()
    {
        return this->result->count;
    }
    
    vector<void*> getResults(size_t count, size_t skip=0)
    {
        vector<void*> results;
        int index=0;
        for(int i=0; i<this->result->regions.size(); i++)
        {
            result_region* region = result->regions[i];
            
            if((index + region->slides.size()) <= skip) {
                index += region->slides.size();
                continue;
            }
            
            for(int j=0; j<region->slides.size(); j++)
            {
                if(index>=skip && (index-skip)<count) {
                    uint64_t address = region->region_base + region->slides[j];
                    results.push_back((void*)address);
                }
                index++;
            }
        }
        return results;
    }
    
    map<void*,int8_t> getResultsAndTypes(int count, int skip=0)
    {
        map<void*,int8_t> results;
        int index=0;
        for(int i=0; i<this->result->regions.size(); i++)
        {
            result_region* region = this->result->regions[i];
            int hasTypes = region->types.size();
            
            if((index + region->slides.size()) <= skip) {
                index += region->slides.size();
                continue;
            }
            
            for(int j=0; j<region->slides.size(); j++)
            {
                if(index>=skip && (index-skip)<count) {
                    uint64_t address = region->region_base + region->slides[j];
                    results[(void*)address] = hasTypes ? this->result->regions[i]->types[j] : 0;
                }
                index++;
            }
        }
        return results;
    }
};

#endif /* JJ_Header_h */
