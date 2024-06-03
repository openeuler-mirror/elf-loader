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


char* format_relative_path(char *path)
{
	int max_stack_size = 1024;
	char *stack[max_stack_size];
	int top = -1;
	char * token = strtok(path, "/");

	while (token != NULL)
	{
		if (strcmp(token, "..") == 0)
		{
			if (top >= 0)
			{
				--top;
			}
			else
			{
				return NULL;
			}
		}
		else if (strcmp(token, ".") !=0 )
		{
			if (top < max_stack_size -1)
			{
				stack[++top] = token;
			}
		}

		token = strtok(NULL, "/");
	}

	char * result = (char *)malloc(PATH_MAX * sizeof(char));
	int i;

	for (i = 0; i <= top; i++)
	{
		strcat(result, "/");
		strcat(result, stack[i]);
	}

	return result;
}

char* find_os_root(char* os_root, char *cmd)
{
	char *p;
	p = strstr(cmd, "/usr/");
	if (!p)
		p = strstr(cmd, "/bin/");
	if (!p)
		p = strstr(cmd, "/sbin/");

	if (!p)
		return NULL;

	if (p - cmd >= PATH_MAX - 1)
		return NULL;

	strncpy(os_root, cmd, p - cmd);
	p = os_root + (p - cmd);
	*p = '\0';

	return p;
}

char *merge_string(char *str1, char *str2)
{
	char *new_str = (char*)malloc(strlen(str1) + strlen(str2) + 2);

	strcpy(new_str, str1);
	strcat(new_str, " ");
	strcat(new_str, str2);

	return new_str;
}

int is_mounted(char *mount_point, char *mount_source)
{
	int fd;
	int found = 0;
	int max_line_len = 1024;
	char buffer[max_line_len];
	char *mount_str = merge_string(mount_source, mount_point);

	fd=open("/proc/self/mountinfo", O_RDONLY);
	if (fd == -1)
		return -1;

	ssize_t bytes_read;

	while((bytes_read = read(fd, buffer, max_line_len - 1)) > 0){
		buffer[bytes_read] = '\0';

		char *line = strtok(buffer, "\n");
		while (line !=NULL)
		{
			if (strstr(line, mount_str)){
				found = 1;
				break;
			}
			line = strtok(NULL, "\n");
		}
	}

	close(fd);
	return found;
}

void mount_os_dir(char *os_root, char *p, char *dir)
{
	strncpy(p, dir, 6);
	if (is_mounted(dir, os_root) == 0)
	{
		if (mount(os_root, dir, "", MS_BIND, NULL) == -1)
			z_printf("mount %s to %s failed\n", os_root, dir);
		else
			z_printf("mount %s to %s ssuccess\n", os_root, dir);
	}
}

void mount_os_root(char *os_root, char *p)
{
	char usr_dir[] = "/usr";
	char etc_dir[] = "/etc";
	char var_dir[] = "/var";

	unshare(CLONE_NEWNS);
	mount("none", "/", NULL, MS_REC|MS_PRIVATE, NULL);
	mount_os_dir(os_root, p, usr_dir);
	mount_os_dir(os_root, p, etc_dir);
	mount_os_dir(os_root, p, var_dir);
}

char *get_full_path_by_cwd(char *exec_file)
{
	char cur_dir[PATH_MAX];
	char *full_path = (char *)malloc(PATH_MAX * sizeof(char));
	if (getcwd(cur_dir, PATH_MAX) == NULL)
	{
		return NULL;
	}

	strcat(full_path, cur_dir);
	strcat(full_path, "/");
	strcat(full_path, exec_file);

	return full_path;
}

char *get_full_path_by_env(char *exec_file)
{
	char *env_path = getenv("PATH");
	if (env_path == NULL)
	{
		return NULL;
	}

	char * token = strtok(env_path, ":");

	while (token != NULL)
	{
		char *full_path = (char *)malloc(PATH_MAX * sizeof(char));
		strcat(full_path, token);
		strcat(full_path, "/");
		strcat(full_path, exec_file);
		if (access(full_path, F_OK) == 0)
		{
			return full_path;
		}

		token = strtok(NULL, ":");
	}

	return NULL;
}

void mount_epkg_root(char * file)
{
	char *tp;
	char *epkg_root = NULL;
	char os_root[PATH_MAX];
	char *exec_file = file;
	if (exec_file)
	{
		if(exec_file[0] == '/')
		{
			epkg_root = exec_file;
		}
		else if (exec_file[0] == '.')
		{
			epkg_root = format_relative_path(get_full_path_by_cwd(exec_file));
		}
		else
		{
			epkg_root = get_full_path_by_env(exec_file);
		}
	}

	if (epkg_root != NULL)
	{
		tp = find_os_root(os_root, epkg_root);
		if (tp)
		{
			mount_os_root(os_root, tp);
		}
	}
}
