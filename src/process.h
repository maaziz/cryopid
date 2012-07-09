#ifndef _PROCESS_H_
#define _PROCESS_H_

#include <sys/types.h>
#include <linux/kdev_t.h>
#include <linux/types.h>

#include "cryopid.h"
#include "cpimage.h"

int is_a_syscall(unsigned long inst, int canonical);
int is_in_syscall(pid_t pid, struct user *user);
void set_syscall_return(struct user* user, unsigned long val);
int memcpy_from_target(pid_t pid, void* dest, const void* src, size_t n);
int memcpy_into_target(pid_t pid, void* dest, const void* src, size_t n);

extern ssize_t r_read(pid_t pid, int fd, void* buf, size_t count);
extern off_t r_lseek(pid_t pid, int fd, off_t offset, int whence);
extern int r_fcntl(pid_t pid, int fd, int cmd);
extern int r_mprotect(pid_t pid, void *start, size_t len, int flags);
extern int r_rt_sigaction(pid_t pid, int sig, struct k_sigaction *ksa,
	struct k_sigaction *oksa, size_t masksz);
extern int r_ioctl(pid_t pid, int fd, int req, void* val);
extern int r_socketcall(pid_t pid, int call, void* args);
extern int r_getpeername(pid_t pid, int s, struct sockaddr *name, socklen_t *namelen);
extern int r_getsockname(pid_t pid, int s, struct sockaddr *name, socklen_t *namelen);

#endif /* _PROCESS_H_ */

/* vim:set ts=8 sw=4 noet: */
