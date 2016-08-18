#ifndef MANDOC_CONFIG_H
#define MANDOC_CONFIG_H

#include <sys/types.h>
#include <stdio.h>

#define	HAVE_ERR 1
#define HAVE_MANPATH 1
#define HAVE_MMAP 1
#define HAVE_OHASH 0
#define	HAVE_PLEDGE 0
#define	HAVE_PROGNAME 1
#define HAVE_REALLOCARRAY 0
#define	HAVE_SANDBOX_INIT 0
#define HAVE_SQLITE3 0
#define HAVE_STRPTIME 1
#define HAVE_STRTONUM 0
#define HAVE_WCHAR 1

#define BINM_APROPOS "apropos"
#define BINM_MAN "man"
#define BINM_WHATIS "whatis"
#define BINM_MAKEWHATIS "man -w"

extern	void	 *reallocarray(void *, size_t, size_t);
extern	long long strtonum(const char *, long long, long long, const char **);

#endif /* MANDOC_CONFIG_H */
