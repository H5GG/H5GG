#ifndef _SYS_LIBPROC_H_
#define	_SYS_LIBPROC_H_

#include <sys/cdefs.h>
#include <sys/_types.h>

extern kern_return_t task_for_pid(task_port_t task, pid_t pid, task_port_t *target);
extern kern_return_t task_info(task_port_t task, unsigned int info_num, task_info_t info, unsigned int *info_count);
extern int proc_pidpath(int pid, void * buffer, uint32_t  buffersize) __OSX_AVAILABLE_STARTING(__MAC_10_5, __IPHONE_2_0);
extern int proc_pid_rusage(int pid, int flavor, struct rusage_info_v2 *rusage);// __OSX_AVAILABLE_STARTING(__MAC_10_9, __IPHONE_7_0);
//extern int proc_listpidspath(uint32_t type, uint32_t typeinfo, const char *path, uint32_t pathflags, void *buffer, int buffersize) __OSX_AVAILABLE_STARTING(__MAC_10_5, __IPHONE_2_0);
//extern int proc_listpids(uint32_t type, uint32_t typeinfo, void *buffer, int buffersize) __OSX_AVAILABLE_STARTING(__MAC_10_5, __IPHONE_2_0);
//extern int proc_listallpids(void * buffer, int buffersize) __OSX_AVAILABLE_STARTING(__MAC_10_7, __IPHONE_4_1);
//extern int proc_listpgrppids(pid_t pgrpid, void * buffer, int buffersize) __OSX_AVAILABLE_STARTING(__MAC_10_7, __IPHONE_4_1);
//extern int proc_listchildpids(pid_t ppid, void * buffer, int buffersize) __OSX_AVAILABLE_STARTING(__MAC_10_7, __IPHONE_4_1);
extern int proc_pidinfo(int pid, int flavor, uint64_t arg,  void *buffer, int buffersize) __OSX_AVAILABLE_STARTING(__MAC_10_5, __IPHONE_2_0);
extern int proc_pidfdinfo(int pid, int fd, int flavor, void * buffer, int buffersize) __OSX_AVAILABLE_STARTING(__MAC_10_5, __IPHONE_2_0);
//extern int proc_pidfileportinfo(int pid, uint32_t fileport, int flavor, void *buffer, int buffersize) __OSX_AVAILABLE_STARTING(__MAC_10_7, __IPHONE_4_3);
//extern int proc_name(int pid, void * buffer, uint32_t buffersize) __OSX_AVAILABLE_STARTING(__MAC_10_5, __IPHONE_2_0);
//extern int proc_regionfilename(int pid, uint64_t address, void * buffer, uint32_t buffersize) __OSX_AVAILABLE_STARTING(__MAC_10_5, __IPHONE_2_0);
//extern int proc_kmsgbuf(void * buffer, uint32_t buffersize) __OSX_AVAILABLE_STARTING(__MAC_10_5, __IPHONE_2_0);
//extern int proc_libversion(int *major, int * minor) __OSX_AVAILABLE_STARTING(__MAC_10_5, __IPHONE_2_0);
extern kern_return_t mach_vm_read(vm_map_t target_task, mach_vm_address_t address, mach_vm_size_t size, vm_offset_t *data, mach_msg_type_number_t *dataCnt);
extern kern_return_t mach_vm_read_overwrite(vm_map_t target_task, mach_vm_address_t address, mach_vm_size_t size, mach_vm_address_t data, mach_vm_size_t *outsize);

#endif	/* !_SYS_LIBPROC_H_ */
