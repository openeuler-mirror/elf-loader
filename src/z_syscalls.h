#ifndef Z_SYSCALLS_H
#define Z_SYSCALLS_H

#include <sys/types.h>
#include <sys/stat.h>
#include <sys/mman.h>

#include <fcntl.h>
#include <unistd.h>

#define z_errno	(*z_perrno())

int	z_exit(int status);
int	z_open(const char *pathname, int flags);
int	z_openat(int dirfd, const char *pathname, int flags);
int	z_close(int fd);
int	z_lseek(int fd, off_t offset, int whence);
ssize_t	z_read(int fd, void *buf, size_t count);
ssize_t	z_write(int fd, const void *buf, size_t count);
ssize_t	z_readlink(const char *pathname, char *buf, size_t bufsiz);
void	*z_mmap(void *addr, size_t length, int prot,
		int flags, int fd, off_t offset);
int	z_munmap(void *addr, size_t length);
int	z_mprotect(void *addr, size_t length, int prot);
int	*z_perrno(void);
int	z_unshare(int flags);
int	z_mount(const char *source, const char *target,
		const char *filesystemtype, unsigned long mountflags,
		const void *data);
ssize_t	z_getuid(void);
ssize_t	z_getgid(void);
ssize_t z_geteuid(void);

#endif /* Z_SYSCALLS_H */
