#ifndef MANDOC_CONFIG_H
#define MANDOC_CONFIG_H

#if defined(__linux__) || defined(__MINT__)
#define _GNU_SOURCE	/* See test-*.c what needs this. */
#endif

#include <sys/types.h>
#include <stdio.h>

#define HAVE_DIRENT_NAMLEN 0
#define HAVE_FGETLN 0
#define HAVE_FTS 0
#define HAVE_GETSUBOPT 1
#define HAVE_MMAP 1
#define HAVE_REALLOCARRAY 0
#define HAVE_STRCASESTR 1
#define HAVE_STRLCAT 1
#define HAVE_STRLCPY 1
#define HAVE_STRPTIME 1
#define HAVE_STRSEP 1
#define HAVE_STRTONUM 0
#define HAVE_WCHAR 1
#define HAVE_SQLITE3 0
#define HAVE_SQLITE3_ERRSTR 1
#define HAVE_OHASH 1
#define HAVE_MANPATH 0

#define BINM_APROPOS "apropos"
#define BINM_MAN "man"
#define BINM_WHATIS "whatis"
#define BINM_MAKEWHATIS "makewhatis"

#if !defined(__BEGIN_DECLS)
#  ifdef __cplusplus
#  define	__BEGIN_DECLS		extern "C" {
#  else
#  define	__BEGIN_DECLS
#  endif
#endif
#if !defined(__END_DECLS)
#  ifdef __cplusplus
#  define	__END_DECLS		}
#  else
#  define	__END_DECLS
#  endif
#endif

extern	char	 *fgetln(FILE *, size_t *);
extern	int	  getsubopt(char **, char * const *, char **);
extern	void	 *reallocarray(void *, size_t, size_t);
extern	char	 *strcasestr(const char *, const char *);
extern	size_t	  strlcat(char *, const char *, size_t);
extern	size_t	  strlcpy(char *, const char *, size_t);
extern	char	 *strsep(char **, const char *);
extern	long long strtonum(const char *, long long, long long, const char **);

#endif /* MANDOC_CONFIG_H */
