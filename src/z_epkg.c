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
}

/*
 * Create directory recursively by parsing path and creating each component
 */
static void create_dir_recursive(char *path)
{
	char *path_ptr = path;
	char *slash_ptr;

	// Skip leading slash if present
	if (*path_ptr == '/') {
		path_ptr++;
	}

	// Create directories recursively
	while ((slash_ptr = (char *)z_strchr(path_ptr, '/')) != NULL) {
		*slash_ptr = '\0';  // Temporarily null-terminate
		z_mkdir(path, 0755);  // Create intermediate directory
		*slash_ptr = '/';   // Restore slash
		path_ptr = slash_ptr + 1;
	}

	// Create the final directory
	z_mkdir(path, 0755);
}

/*
 * Determine the appropriate opt_real path to avoid mount loops
 * For public environments (/opt/epkg/envs/...), use private env path
 * For private environments, use the original os_root/opt_real path
 */
static void get_opt_real_path(char *os_root, char *opt_real_path)
{
	if (z_strncmp(os_root, "/opt/epkg/envs/", 15) == 0) {
		// Public environment: extract username and use private env path
		char *user_start = os_root + 15;  // Skip "/opt/epkg/envs/"
		const char *user_end = z_strchr(user_start, '/');
		if (user_end != NULL) {
			// Construct home directory based on username
			char home_dir[200];
			size_t user_len = user_end - user_start;

			if (user_len == 4 && z_strncmp(user_start, "root", 4) == 0) {
				// Root user: use /root
				z_strncpy(home_dir, "/root", 6);
			} else {
				// Other users: use /home/{username}
				z_strncpy(home_dir, "/home/", 7);
				z_strncpy(home_dir + 6, user_start, user_len);
				home_dir[6 + user_len] = '\0';
			}

			// Construct private env path: {home_dir}/.epkg/envs/{env_name}/opt_real without intermediate NULs
			size_t env_name_len;
			if (user_end != NULL) {
				const char *env_name_start = user_end + 1;
				const char *env_name_end = z_strchr(env_name_start, '/');

				// Handle trailing slash in path
				if (env_name_end != NULL && *(env_name_end + 1) == '\0') {
					// Path ends with slash, so env_name_start is the full env name
					env_name_len = env_name_end - env_name_start;
				} else if (env_name_end != NULL) {
					// There's more path after env name
					env_name_len = env_name_end - env_name_start;
				} else {
					// No more slashes, use the rest as env name
					env_name_len = z_strlen(env_name_start);
				}

				char *p = opt_real_path;
				z_memcpy(p, home_dir, z_strlen(home_dir));
				p += z_strlen(home_dir);
				z_memcpy(p, "/.epkg/envs/", 12); // include trailing '/'
				p += 12;
				z_memcpy(p, env_name_start, env_name_len);
				p += env_name_len;
				z_memcpy(p, "/opt_real", 9); // without trailing NUL
				p += 9;
				*p = '\0';
			} else {
				// Fallback to original behavior
				size_t os_root_len = z_strlen(os_root);
				z_strncpy(opt_real_path, os_root, 100);
				z_strncpy(opt_real_path + os_root_len, "/opt_real", 10);
			}
		} else {
			// Fallback to original behavior
			size_t os_root_len = z_strlen(os_root);
			z_strncpy(opt_real_path, os_root, 100);
			z_strncpy(opt_real_path + os_root_len, "/opt_real", 10);
		}
	} else {
		// Private environment: use original behavior
		size_t os_root_len = z_strlen(os_root);
		z_strncpy(opt_real_path, os_root, 100);
		z_strncpy(opt_real_path + os_root_len, "/opt_real", 10);
	}
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

	// Get the appropriate opt_real path to avoid mount loops
	get_opt_real_path(os_root, opt_real_path);
	debug("os_root: %s, opt_real_path: %s\n", os_root, opt_real_path);

	// First check if /opt/epkg exists
	int opt_epkg_fd = z_open(opt_epkg_path, O_RDONLY);
	if (opt_epkg_fd >= 0) {
		z_close(opt_epkg_fd);

		// Special handling for /opt/epkg mount isolation
		// Step 1: Create opt_real directory recursively
		create_dir_recursive(opt_real_path);

		// Step 2: Bind mount /opt/epkg to os_root/opt_real
		debug("Bind mounting %s to %s\n", opt_epkg_path, opt_real_path);
		do_mount(opt_epkg_path, opt_real_path);
	}

	// Step 3: Mount environment /opt directory
	debug("Bind mounting %s to %s\n", os_opt, "/opt");
	do_mount(os_opt, "/opt");

	// Step 4: If /opt/epkg existed, bind mount opt_real back to /opt/epkg
	if (opt_epkg_fd >= 0) {
		debug("Bind mounting %s to %s\n", opt_real_path, opt_epkg_path);
		do_mount(opt_real_path, opt_epkg_path);
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
