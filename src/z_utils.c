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

int z_memcmp(const void *s1, const void *s2, size_t n)
{
	const unsigned char *p1 = s1, *p2 = s2;
	size_t i;

	for (i = 0; i < n; i++) {
		if (p1[i] != p2[i])
			return p1[i] - p2[i];
	}
	return 0;
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
    // Handle NULL pointers
    if (x == NULL || y == NULL)
        return x == y ? 0 : (x == NULL ? -1 : 1);

    while (*x && *y)
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
		// Check if this environment variable starts with name and has '=' after it
		if (name[0] == (*ep)[0]) {
			// Compare only the name part (up to len characters)
			size_t i;
			for (i = 0; i < len; i++) {
				if (name[i] != (*ep)[i])
					break;
			}

			// If we matched the full name and next char is '=', return the value
			if (i == len && (*ep)[len] == '=')
				return *ep + len + 1;
		}
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
