#include <stdlib.h>

void *z_memset(void *s, int c, size_t n)
{
	unsigned char *p = s, *e = p + n;
	while (p < e)
		*p++ = c;
	return s;
}

void *z_memcpy(void *dest, const void *src, size_t n)
{
	unsigned char *d = dest;
	const unsigned char *p = src, *e = p + n;
	while (p < e)
		*d++ = *p++;
	return dest;
}

char *z_strncpy(char *dest, const char *src, size_t n)
{
	size_t i;

	for (i = 0; ; i++) {
		if (i >= n - 1) {
			dest[i] = '\0';
			break;
		}
		dest[i] = src[i];
		if (src[i] == '\0')
			break;
	}

	return dest;
}

size_t z_strlen(const char *str)
{
	const char *p = str;

	while (*p != '\0')
		p++;

	return p - str;
}

int z_strcmp(const char *x, const char *y)
{
    while (*x)
    {
        if (*x != *y)
            break;

        // move to the next pair of characters
        x++;
        y++;
    }

    // return the ASCII difference after converting `char*` to `unsigned char*`
    return *(const unsigned char*)x - *(const unsigned char*)y;
}

extern char **z_environ;

char *z_getenv(const char *name)
{
	if (z_environ == NULL || name[0] == '\0')
		return NULL;

	size_t len = z_strlen(name);

	for (char **ep = z_environ; *ep != NULL; ++ep)
	{
		if (name[0] == (*ep)[0] &&
		    z_strcmp(name, *ep) == 0 &&
		    (*ep)[len] == '=')
			return *ep + len + 1;
	}

	return NULL;
}

int compare(const char *x, const char *y)
{
    while (*x && *y)
    {
        if (*x != *y) {
            return 0;
        }

        x++;
        y++;
    }

    return (*y == '\0');
}

const char* z_strstr(const char* x, const char* y)
{
    while (*x != '\0')
    {
        if ((*x == *y) && compare(x, y)) {
            return x;
        }
        x++;
    }

    return NULL;
}
