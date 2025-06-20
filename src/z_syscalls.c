#include <syscall.h>

#include "z_asm.h"
#include "z_syscalls.h"

static int errno;

int *z_perrno(void)
{
	return &errno;
}

static long check_error(long rc)
{
	if (rc < 0 && rc > -4096) {
		errno = -rc;
		rc = -1;
	}
	return rc;
}

#define SYSCALL(name, ...)  check_error(z_syscall(SYS_##name, ##__VA_ARGS__))

#define DEF_SYSCALL0(ret, name) \
ret z_##name(void) \
{ \
	return (ret)SYSCALL(name); \
}

#define DEF_SYSCALL1(ret, name, t1, a1) \
ret z_##name(t1 a1) \
{ \
	return (ret)SYSCALL(name, a1); \
}
#define DEF_SYSCALL2(ret, name, t1, a1, t2, a2) \
ret z_##name(t1 a1, t2 a2) \
{ \
	return (ret)SYSCALL(name, a1, a2); \
}
#define DEF_SYSCALL3(ret, name, t1, a1, t2, a2, t3, a3) \
ret z_##name(t1 a1, t2 a2, t3 a3) \
{ \
	return (ret)SYSCALL(name, a1, a2, a3); \
}
#define DEF_SYSCALL5(return_type, name, param1_type, param1, param2_type, param2, param3_type, param3, param4_type, param4, param5_type, param5) \
return_type z_##name(param1_type param1, param2_type param2, param3_type param3, param4_type param4, param5_type param5) { \
    return (return_type)SYSCALL(name, param1, param2, param3, param4, param5); \
}

DEF_SYSCALL3(int, openat, int, dirfd, const char *, filename, int, flags)
DEF_SYSCALL3(ssize_t, read, int, fd, void *, buf, size_t, count)
DEF_SYSCALL3(ssize_t, write, int, fd, const void *, buf, size_t, count)
/* readlink is implemented using readlinkat below */
DEF_SYSCALL1(int, close, int, fd)
DEF_SYSCALL3(int, lseek, int, fd, off_t, off, int, whence)
DEF_SYSCALL1(int, exit, int, status)
DEF_SYSCALL2(int, munmap, void *, addr, size_t, length)
DEF_SYSCALL3(int, mprotect, void *, addr, size_t, length, int, prot)
DEF_SYSCALL1(int, unshare, int, flags)
DEF_SYSCALL5(int, mount, const char *, source, const char *, target, const char *, filesystemtype, unsigned long, mountflags, const void *, data)
DEF_SYSCALL0(ssize_t, getuid)
DEF_SYSCALL0(ssize_t, getgid)
DEF_SYSCALL0(ssize_t, geteuid)

int z_open(const char * filename, int flags)
{
	return z_openat(AT_FDCWD, filename, flags);
}

ssize_t z_readlink(const char *pathname, char *buf, size_t bufsiz)
{
	return (ssize_t)SYSCALL(readlinkat, AT_FDCWD, pathname, buf, bufsiz);
}

void *
z_mmap(void *addr, size_t length, int prot, int flags, int fd, off_t offset)
{
	/* i386 has map (old_mmap) and mmap2, old_map is a legacy single arg
	 * function, use mmap2 but it needs offset in page units.
	 * In same time mmap2 does not exist on x86-64.
	 */
#ifdef SYS_mmap2
	return (void *)SYSCALL(mmap2, addr, length, prot, flags, fd, offset >> 12);
#else
	return (void *)SYSCALL(mmap, addr, length, prot, flags, fd, offset);
#endif
}

