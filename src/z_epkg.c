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

void mount_opt(char *os_root)
{
	char os_opt[200];
	char opt_epkg_path[200];
	char opt_real_path[200];

	// Initialize manually to avoid memset link error
	z_strncpy(opt_epkg_path, "/opt/epkg", 10);

	size_t os_root_len = z_strlen(os_root);

	// Create paths
	z_strncpy(os_opt, os_root, 100);
	z_strncpy(os_opt + os_root_len, "/opt", 5);

	z_strncpy(opt_real_path, os_root, 100);
	z_strncpy(opt_real_path + os_root_len, "/opt_real", 10);

	// First check if /opt/epkg exists
	int opt_epkg_fd = z_open(opt_epkg_path, O_RDONLY);
	if (opt_epkg_fd >= 0) {
		z_close(opt_epkg_fd);

		// Special handling for /opt/epkg mount isolation
		// Step 1: Create opt_real directory
		int mkdir_fd = z_open(opt_real_path, O_CREAT | O_RDONLY);
		if (mkdir_fd >= 0) {
			z_close(mkdir_fd);
		}

		// Step 2: Bind mount /opt/epkg to os_root/opt_real
		/* z_printf("Bind mounting %s to %s\n", opt_epkg_path, opt_real_path); */
		do_mount(opt_epkg_path, opt_real_path);
	}

	// Step 3: Mount environment /opt directory
	/* z_printf("Bind mounting %s to %s\n", os_opt, "/opt"); */
	do_mount(os_opt, "/opt");

	// Step 4: If /opt/epkg existed, bind mount opt_real back to /opt/epkg
	if (opt_epkg_fd >= 0) {
		// Check if opt_real_path exists
		int opt_real_fd = z_open(opt_real_path, O_RDONLY);
		if (opt_real_fd >= 0) {
			z_close(opt_real_fd);
			/* z_printf("Bind mounting %s to %s\n", opt_real_path, opt_epkg_path); */
			do_mount(opt_real_path, opt_epkg_path);
		}
	}
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
	char os_root_copy[OSROOT_BUF_SIZE];
	z_strncpy(os_root_copy, os_root, OSROOT_BUF_SIZE);
	char *pend = os_root_copy + z_strlen(os_root_copy);

	ssize_t uid = z_getuid();
	ssize_t gid = z_getgid();
	ssize_t euid = z_geteuid();
	int clone_flags = 0;

	if (euid)
		clone_flags = CLONE_NEWUSER;
	z_unshare(clone_flags|CLONE_NEWNS);

	set_map(uid, gid);

	z_mount("none", "/", NULL, MS_REC|MS_PRIVATE, NULL);
	mount_os_dir(os_root_copy, pend, "/etc");
	mount_os_dir(os_root_copy, pend, "/usr");
	mount_os_dir(os_root_copy, pend, "/var");
	mount_opt(os_root);
}
