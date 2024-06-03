#ifndef Z_UTILS_H
#define Z_UTILS_H

#include <stdlib.h>
#include <stdarg.h>
#include <alloca.h>
#include <string.h>

#define z_alloca	__builtin_alloca

void	*z_memset(void *s, int c, size_t n);
void	*z_memcpy(void *dest, const void *src, size_t n);
char	*z_strncpy(char *dest, const char *src, size_t n);
char	*z_getenv(const char *name);
size_t	z_strlen(const char *str);
int	z_strcmp(const char *x, const char *y);
const char* z_strstr(const char* x, const char* y);

void	z_vprintf(const char *fmt, va_list ap);
void	z_vfdprintf(int fd, const char *fmt, va_list ap);
void	z_printf(const char *fmt, ...)
	__attribute__ ((format (printf, 1, 2)));
void	z_fdprintf(int fd, const char *fmt, ...)
	__attribute__ ((format (printf, 2, 3)));
void	z_errx(int eval, const char *fmt, ...)
	__attribute__ ((format (printf, 2, 3)));

#ifdef Z_SMALL
#  define z_errx(eval, fmt, ...) z_exit(eval)
#  define z_printf(fmt, ...) do {} while(0)
#  define z_fdprintf(fd, fmt, ...) do {} while(0)
#endif

#endif /* Z_UTILS_H */

