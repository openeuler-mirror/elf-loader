#define _GNU_SOURCE
#include <fcntl.h>
#include <unistd.h>
#include <sched.h>
#include <stdlib.h>
#include <string.h>
#include <limits.h>
#include <sys/mount.h>
#include <sys/types.h>
#include "z_utils.h"
#include "z_syscalls.h"

// Format specifier for ssize_t based on architecture
#if defined(__i386__) || defined(__i686__)
#define SSIZE_FMT "%d"
#else
#define SSIZE_FMT "%ld"
#endif

#define OSROOT_BUF_SIZE 1024

static void die(const char *msg)
{
        z_fdprintf(2, "%s\n", msg);
        z_exit(1);
}

void do_mount(char *src, char *dst)
{
	if (z_mount(src, dst, "", MS_BIND, NULL) == -1)
		z_printf("mount %s to %s failed\n", src, dst);
	//else
	//	z_printf("mount %s to %s success\n", src, dst);
}

void mount_opt()
{
	char home_opt[200];
	char *home = z_getenv("HOME");

	// If HOME is not set, we can't mount /opt
	if (!home) {
		// Debug message to help diagnose the issue
		z_printf("Warning: HOME environment variable not set, skipping /opt mount\n");
		return;
	}

	size_t home_len = z_strlen(home);
	z_strncpy(home_opt, home, 100);
	z_memcpy(home_opt + home_len, "/opt", 5);

	do_mount(home_opt, "/opt");
}

void mount_os_dir(char *os_root, char *pend, char *dir)
{
	z_strncpy(pend, dir, 36);
	do_mount(os_root, dir);
}

void get_guid(){
	z_printf("uid:" SSIZE_FMT " gid:" SSIZE_FMT "\n", z_getuid(), z_getgid());
}

void set_fd_id(char* fd_path, ssize_t id){

	int map_fd = z_open(fd_path, O_WRONLY);
	if (map_fd < 0) {
			z_printf("open %s failed: %d\n",fd_path, z_errno);
			die("open failed");
	}
	// z_fdprintf(uid_map_fd, "0 %ul 1", id);
	char *p;
	char buf[20] = {
		'0', ' ', ' ', ' ', ' ', ' ', ' ', ' ', ' ', ' ',
		' ', ' ', ' ', ' ', ' ', ' ', ' ', ' ', '1', '\0'
	};

	p = buf + 16;
	do {
		*p-- = "0123456789abcdef"[id % 10];
	} while (id /= 10);
	z_write(map_fd, buf, 20);
	z_close(map_fd);
}

void set_map(ssize_t uid, ssize_t gid){
	int groups_fd = z_open("/proc/self/setgroups", O_WRONLY | O_TRUNC);
	if (groups_fd < 0) {
		z_printf("open /proc/self/setgroups failed: %d\n", z_errno);
		die("open /proc/self/setgroups failed");
	}
	z_write(groups_fd, "deny", 4);
	z_close(groups_fd);

	set_fd_id("/proc/self/uid_map", uid);
	set_fd_id("/proc/self/gid_map", gid);
}

void mount_os_root(char *os_root)
{
	char *pend = os_root + z_strlen(os_root);

	ssize_t uid = z_getuid();
	ssize_t gid = z_getgid();
	ssize_t euid = z_geteuid();
	int clone_flags = 0;

	if (euid)
		clone_flags = CLONE_NEWUSER;
	z_unshare(clone_flags|CLONE_NEWNS);

	set_map(uid, gid);

	z_mount("none", "/", NULL, MS_REC|MS_PRIVATE, NULL);
	mount_os_dir(os_root, pend, "/etc");
	mount_os_dir(os_root, pend, "/usr");
	mount_os_dir(os_root, pend, "/var");
	mount_opt();
}

// set os_root based on cmd
char* find_osroot(char* buf, const char *cmd)
{
        const char *p;

        if (cmd[0] != '/')
                die("XXX: only support full path CMD for now");

        p = z_strstr(cmd, "/usr/");
        if (!p)
                p = z_strstr(cmd, "/opt/");
        if (!p)
                p = z_strstr(cmd, "/bin/");
        if (!p)
                p = z_strstr(cmd, "/sbin/");
        if (!p)
                die("cannot find usr/bin in command");
        if (p - cmd >= OSROOT_BUF_SIZE - 6)
                die("os_root buffer too small");

        z_strncpy(buf, cmd, p - cmd + 1);
        return buf;
}

void mount_epkg_root(char *os_root, const char *cmd)
{
	char buf[OSROOT_BUF_SIZE];

	if (os_root[0] == '{')
		find_osroot(buf, cmd);
	else
		z_strncpy(buf, os_root, OSROOT_BUF_SIZE);

	mount_os_root(buf);
}
