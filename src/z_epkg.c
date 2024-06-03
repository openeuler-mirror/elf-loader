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
	else
		z_printf("mount %s to %s success\n", src, dst);
}

void mount_opt()
{
	char home_opt[200];
	char *home = z_getenv("HOME");
	if (!home)
		return;

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

void mount_os_root(char *os_root)
{
	char *pend = os_root + z_strlen(os_root);

	z_unshare(CLONE_NEWUSER|CLONE_NEWNS);
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
