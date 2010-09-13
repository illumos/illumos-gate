/*
 * Copyright 2006 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*	Copyright (c) 1983, 1984, 1985, 1986, 1987, 1988, 1989 AT&T	*/
/*	  All Rights Reserved  	*/

/*
 * Copyright (c) 1980 Regents of the University of California.
 * All rights reserved. The Berkeley Software License Agreement
 * specifies the terms and conditions for redistribution.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * This module provides with system/library function substitutes for tchar
 * datatype. This also includes two conversion functions between tchar and
 * char arrays.
 *
 * T. Kurosaka, Palo Alto, California, USA
 * March 1989
 *
 * Implementation Notes:
 *	Many functions defined here use a "char" buffer chbuf[].  In the
 * first attempt, there used to be only one chbuf defined as static
 * (private) variable and shared by these functions.  csh linked with that
 * version of this file misbehaved in interpreting "eval `tset ....`".
 * (in general, builtin function with back-quoted expression).
 *	This bug seemed to be caused by sharing of chbuf
 * by these functions simultanously (thru vfork() mechanism?).  We could not
 * identify which two functions interfere each other so we decided to
 * have each of these function its private instance of chbuf.
 * The size of chbuf[] might be much bigger than necessary for some functions.
 */
#ifdef DBG
#include <stdio.h>	/* For <assert.h> needs stderr defined. */
#else /* !DBG */
#define	NDEBUG		/* Disable assert(). */
#endif /* !DBG */

#include <assert.h>
#include "sh.h"

#ifdef MBCHAR
#include <widec.h>	/* For wcsetno() */
#endif

#include <sys/param.h>	/* MAXPATHLEN */
#include <fcntl.h>
#include <unistd.h>


/*
 * strtots(to, from): convert a char string 'from' into a tchar buffer 'to'.
 *	'to' is assumed to have the enough size to hold the conversion result.
 *	When 'to' is NOSTR(=(tchar *)0), strtots() attempts to allocate a space
 *	automatically using xalloc().  It is caller's responsibility to
 *	free the space allocated in this way, by calling xfree(ptr).
 *	In either case, strtots() returns the pointer to the conversion
 *	result (i.e. 'to', if 'to' wasn't NOSTR, or the allocated space.).
 *	When a conversion or allocateion failed,  NOSTR is returned.
 */

tchar	*
strtots(tchar *to, char *from)
{
	int	i;

	if (to == NOSTR) {	/* Need to xalloc(). */
		int	i;

		i = mbstotcs(NOSTR, from, 0);
		if (i < 0) {
			return (NOSTR);
		}

		/* Allocate space for the resulting tchar array. */
		to = (tchar *)xalloc(i * sizeof (tchar));
	}
	i = mbstotcs(to, from, INT_MAX);
	if (i < 0) {
		return (NOSTR);
	}
	return (to);
}

char	*
tstostr(char *to, tchar *from)
{
	tchar	*ptc;
	wchar_t	wc;
	char	*pmb;
	int	len;

	if (to == (char *)NULL) {	/* Need to xalloc(). */
		int	i;
		int	i1;
		char	junk[MB_LEN_MAX];

		/* Get sum of byte counts for each char in from. */
		i = 0;
		ptc = from;
		while (wc = (wchar_t)((*ptc++)&TRIM)) {
			if ((i1 = wctomb(junk, wc)) <= 0) {
				i1 = 1;
			}
			i += i1;
		}

		/* Allocate that much. */
		to = (char *)xalloc(i + 1);
	}

	ptc = from;
	pmb = to;
	while (wc = (wchar_t)((*ptc++)&TRIM)) {
		if ((len = wctomb(pmb, wc)) <= 0) {
			*pmb = (unsigned char)wc;
			len = 1;
		}
		pmb += len;
	}
	*pmb = (char)0;
	return (to);
}

/*
 * mbstotcs(to, from, tosize) is similar to strtots() except that
 * this returns # of tchars of the resulting tchar string.
 * When NULL is give as the destination, no real conversion is carried out,
 * and the function reports how many tchar characters would be made in
 * the converted result including the terminating 0.
 *	tchar	*to;	- Destination buffer, or NULL.
 *	char	*from;	- Source string.
 *	int	tosize; - Size of to, in terms of # of tchars.
 */
int
mbstotcs(tchar *to, char *from, int tosize)
{
	tchar	*ptc = to;
	char	*pmb = from;
	wchar_t	wc;
	int	chcnt = 0;
	int	j;


	/* Just count how many tchar would be in the result. */
	if (to == (tchar *)NULL) {
		while (*pmb) {
			if ((j = mbtowc(&wc, pmb, MB_CUR_MAX)) <= 0) {
				j = 1;
			}
			pmb += j;
			chcnt++;
		}
		chcnt++;	/* For terminator. */
		return (chcnt);	/* # of chars including terminating zero. */
	} else {	/* Do the real conversion. */
		while (*pmb) {
			if ((j = mbtowc(&wc, pmb, MB_CUR_MAX)) <= 0) {
				wc = (unsigned char)*pmb;
				j = 1;
			}
			pmb += j;
			*(ptc++) = (tchar)wc;
			if (++chcnt >= tosize) {
				break;
			}
		}
		/* Terminate with zero only when space is left. */
		if (chcnt < tosize) {
			*ptc = (tchar)0;
			++chcnt;
		}
		return (chcnt); /* # of chars including terminating zero. */
	}
}


/* tchar version of STRING functions. */

/*
 * Returns the number of
 * non-NULL tchar elements in tchar string argument.
 */
int
strlen_(tchar *s)
{
	int n;

	n = 0;
	while (*s++) {
		n++;
	}
	return (n);
}

/*
 * Concatenate tchar string s2 on the end of s1.  S1's space must be large
 * enough.  Return s1.
 */
tchar *
strcat_(tchar *s1, tchar *s2)
{
	tchar *os1;

	os1 = s1;
	while (*s1++)
		;
	--s1;
	while (*s1++ = *s2++)
		;
	return (os1);
}

/*
 * Compare tchar strings:  s1>s2: >0  s1==s2: 0  s1<s2: <0
 * BUGS: Comparison between two characters are done by subtracting two chars
 *	after converting each to an unsigned long int value.  It might not make
 *	a whole lot of sense to do that if the characters are in represented
 *	as wide characters and the two characters belong to different codesets.
 *	Therefore, this function should be used only to test the equallness.
 */
int
strcmp_(tchar *s1, tchar *s2)
{
	while (*s1 == *s2++) {
		if (*s1++ == (tchar)0) {
			return (0);
		}
	}
	return (((unsigned long)*s1) - ((unsigned long)*(--s2)));
}

/*
 * This is only used in sh.glob.c for sorting purpose.
 */
int
strcoll_(tchar *s1, tchar *s2)
{
	char buf1[BUFSIZ];
	char buf2[BUFSIZ];

	tstostr(buf1, s1);
	tstostr(buf2, s2);
	return (strcoll(buf1, buf2));
}

/*
 * Copy tchar string s2 to s1.  s1 must be large enough.
 * return s1
 */
tchar *
strcpy_(tchar *s1, tchar *s2)
{
	tchar *os1;

	os1 = s1;
	while (*s1++ = *s2++)
		;
	return (os1);
}

/*
 * Return the ptr in sp at which the character c appears;
 * NULL if not found
 */
tchar *
index_(tchar *sp, tchar c)
{

	do {
		if (*sp == c) {
			return (sp);
		}
	} while (*sp++);
	return (NULL);
}

/*
 * Return the ptr in sp at which the character c last
 * appears; NOSTR if not found
 */

tchar *
rindex_(tchar *sp, tchar c)
{
	tchar *r;

	r = NOSTR;
	do {
		if (*sp == c) {
			r = sp;
		}
	} while (*sp++);
	return (r);
}

/* Additional misc functions. */

/* Calculate the display width of a string.  */
int
tswidth(tchar *ts)
{
#ifdef MBCHAR
	wchar_t	tc;
	int	w = 0;
	int	p_col;

	while (tc = *ts++) {
		if ((p_col = wcwidth((wchar_t)tc)) > 0)
			w += p_col;
	}
	return (w);
#else /* !MBCHAR --- one char always occupies one column. */
	return (strlen_(ts));
#endif
}

/*
 * Two getenv() substitute functions.  They differ in the type of arguments.
 * BUGS: Both returns the pointer to an allocated space where the env var's
 *	values is stored.  This space is freed automatically on the successive
 *	call of	either function.  Therefore the caller must copy the contents
 *	if it needs to access two env vars.  There is an arbitary limitation
 *	on the number of chars of a env var name.
 */
#define	LONGEST_ENVVARNAME	256		/* Too big? */
tchar *
getenv_(tchar *name_)
{
	char	name[LONGEST_ENVVARNAME * MB_LEN_MAX];

	assert(strlen_(name_) < LONGEST_ENVVARNAME);
	return (getenvs_(tstostr(name, name_)));
}

tchar *
getenvs_(char *name)
{
	static tchar	*pbuf = (tchar *)NULL;
	char	*val;

	if (pbuf) {
		xfree(pbuf);
		pbuf = NOSTR;
	}
	val = getenv(name);
	if (val == (char *)NULL) {
		return (NOSTR);
	}
	return (pbuf = strtots(NOSTR, val));
}

/* Followings are the system call interface for tchar strings. */

/*
 * creat() and open() replacement.
 * BUGS: An unusually long file name could be dangerous.
 */
int
creat_(tchar *name_, int mode)
{
	int fd;
	char chbuf[MAXPATHLEN * MB_LEN_MAX]; /* General use buffer. */

	tstostr(chbuf, name_);
	fd = creat((char *)chbuf, mode);
	if (fd != -1) {
		setfd(fd);
	}
	return (fd);
}

/*VARARGS2*/
int
open_(path_, flags, mode)
	tchar 	*path_;
	int	flags;
	int	mode; /* May be omitted. */
{
	char chbuf[MAXPATHLEN * MB_LEN_MAX]; /* General use buffer. */
	int fd;

	tstostr(chbuf, path_);
	fd = open((char *)chbuf, flags, mode);
	if (fd != -1) {
		setfd(fd);
	}
	return (fd);
}

/*
 * mkstemp replacement
 */
int
mkstemp_(tchar *name_)
{
	int fd;
	char chbuf[MAXPATHLEN * MB_LEN_MAX]; /* General use buffer. */

	tstostr(chbuf, name_);
	fd = mkstemp((char *)chbuf);
	if (fd != -1) {
		setfd(fd);
		strtots(name_, chbuf);
	}
	return (fd);
}

/*
 * read() and write() reaplacement.
 *	int        d;
 *	tchar      *buf;  - where the result be stored.  Not NULL terminated.
 *	int        nchreq; - # of tchars requrested.
 */
int
read_(int d, tchar *buf, int nchreq)
{
	unsigned char chbuf[BUFSIZ * MB_LEN_MAX]; /* General use buffer. */
#ifdef MBCHAR
	/*
	 * We would have to read more than tchar bytes
	 * when there are multibyte characters in the file.
	 */
	int	i, j, fflags;
	unsigned char	*s;	/* Byte being scanned for a multibyte char. */
	/* Points to the pos where next read() to read the data into. */
	unsigned char	*p;
	tchar	*t;
	wchar_t		wc;
	int		b_len;
	int		nchread = 0; /* Count how many bytes has been read. */
	int		nbytread = 0; /* Total # of bytes read. */
	/* # of bytes needed to complete the last char just read. */
	int		delta;
	unsigned char	*q;	/* q points to the first invalid byte. */
	int		mb_cur_max = MB_CUR_MAX;
#ifdef DBG
	tprintf("Entering read_(d=%d, buf=0x%x, nchreq=%d);\n",
	    d, buf, nchreq);
#endif /* DBG */
	/*
	 *	Step 1: We collect the exact number of bytes that make
	 *	nchreq characters into chbuf.
	 *	We must be careful not to read too many bytes as we
	 *	cannot push back such over-read bytes.
	 *	The idea we use here is that n multibyte characters are stored
	 *	in no less than n but less than n*MB_CUR_MAX bytes.
	 */
	assert(nchreq <= BUFSIZ);
	delta = 0;
	p = s = chbuf;
	t = buf;
	while (nchread < nchreq) {
		int		m;  /* # of bytes to try to read this time. */
		int		k;  /* # of bytes successfully read. */

retry:
		/*
		 * Let's say the (N+1)'th byte bN is actually the first
		 * byte of a three-byte character c.
		 * In that case, p, s, q look like this:
		 *
		 *		/-- already read--\ /-- not yet read --\
		 * chbuf[]:	b0 b1 ..... bN bN+1 bN+2 bN+2 ...
		 *		^		^	^
		 *		|		|	|
		 *		p		s	q
		 *				\----------/
		 *				c hasn't been completed
		 *
		 * Just after the next read(), p and q will be adavanced to:
		 *
		 *	/-- already read-----------------------\ /-- not yet -
		 * chbuf[]: b0 b1 ..... bN bN+1 bN+2 bN+2 ... bX bX+1 bX+2...
		 *			^	^		 ^
		 *			|	|		 |
		 *			s	p		 q
		 *			\----------/
		 *			 c has been completed
		 *			 but hasn't been scanned
		 */
		m = nchreq - nchread;
		assert(p + m < chbuf + sizeof (chbuf));
		k = read(d, p, m);
		/*
		 * when child sets O_NDELAY or O_NONBLOCK on stdin
		 * and exits and we are interactive then turn the modes off
		 * and retry
		 */
		if (k == 0) {
			if ((intty && !onelflg && !cflg) &&
			    ((fflags = fcntl(d, F_GETFL, 0)) & O_NDELAY)) {
				fflags &= ~O_NDELAY;
				fcntl(d, F_SETFL, fflags);
				goto retry;
			}
		} else if (k < 0) {
			if (errno == EAGAIN) {
				fflags = fcntl(d, F_GETFL, 0);
				fflags &= ~O_NONBLOCK;
				fcntl(d, F_SETFL, fflags);
				goto retry;
			}
			return (-1);
		}
		nbytread += k;
		q = p + k;
		delta = 0;

		/* Try scaning characters in s..q-1 */
		while (s < q) {
			/* Convert the collected bytes into tchar array. */
			if (*s == 0) {
				/* NUL is treated as a normal char here. */
				*t++ = 0;
				s++;
				nchread++;
				continue;
			}

			if ((b_len = q - s) > mb_cur_max) {
				b_len = mb_cur_max;
			}
			if ((j = mbtowc(&wc, (char *)s, b_len)) <=  0) {
				if (mb_cur_max > 1 && b_len < mb_cur_max) {
					/*
					 * Needs more byte to complete this char
					 * In order to read() more than delta
					 * bytes.
					 */
					break;
				}
				wc = (unsigned char)*s;
				j = 1;
			}

			*t++ = wc;
			nchread++;
			s += j;
		}

		if (k < m) {
			/* We've read as many bytes as possible. */
			while (s < q) {
				if ((b_len = q - s) > mb_cur_max) {
					b_len = mb_cur_max;
				}
				if ((j = mbtowc(&wc, (char *)s, b_len)) <=  0) {
					wc = (unsigned char)*s;
					j = 1;
				}
				*t++ = wc;
				nchread++;
				s += j;
			}
			return (nchread);
		}

		p = q;
	}

	if (mb_cur_max == 1 || (delta = q - s) == 0) {
		return (nchread);
	}

	/*
	 * We may have (MB_CUR_MAX - 1) unread data in the buffer.
	 * Here, the last converted data was an illegal character which was
	 * treated as one byte character. We don't know at this point
	 * whether or not the remaining data is in legal sequence.
	 * We first attempt to convert the remaining data.
	 */
	do {
		if ((j = mbtowc(&wc, (char *)s, delta)) <= 0)
			break;
		*t++ = wc;
		nchread++;
		s += j;
		delta -= j;
	} while (delta > 0);

	if (delta == 0)
		return (nchread);

	/*
	 * There seem to be ugly sequence in the buffer. Fill up till
	 * mb_cur_max and see if we can get a right sequence.
	 */
	while (delta < mb_cur_max) {
		assert((q + 1) < (chbuf + sizeof (chbuf)));
		if (read(d, q, 1) != 1)
			break;
		delta++;
		q++;
		if (mbtowc(&wc, (char *)s, delta) > 0) {
			*t = wc;
			return (nchread + 1);
		}
	}

	/*
	 * no luck. we have filled MB_CUR_MAX bytes in the buffer.
	 * Ideally we should return with leaving such data off and
	 * put them into a local buffer for next read, but we don't
	 * have such.
	 * So, stop reading further, and treat them as all single
	 * byte characters.
	 */
	while (s < q) {
		b_len = q - s;
		if ((j = mbtowc(&wc, (char *)s, b_len)) <=  0) {
			wc = (unsigned char)*s;
			j = 1;
		}
		*t++ = wc;
		nchread++;
		s += j;
	}
	return (nchread);

#else /* !MBCHAR */
	/* One byte always represents one tchar.  Easy! */
	int		i;
	unsigned char	*s;
	tchar		*t;
	int		nchread;

#ifdef DBG
	tprintf("Entering read_(d=%d, buf=0x%x, nchreq=%d);\n",
	    d, buf, nchreq);
#endif /* DBG */
	assert(nchreq <= BUFSIZ);
retry:
	nchread = read(d, (char *)chbuf, nchreq);
	/*
	 * when child sets O_NDELAY or O_NONBLOCK on stdin
	 * and exits and we are interactive then turn the modes off
	 * and retry
	 */
	if (nchread == 0) {
		if ((intty && !onelflg && !cflg) &&
		    ((fflags = fcntl(d, F_GETFL, 0)) & O_NDELAY)) {
			fflags &= ~O_NDELAY;
			fcntl(d, F_SETFL, fflags);
			goto retry;
		}
	} else if (nchread < 0) {
		if (errno == EAGAIN) {
			fflags = fcntl(d, F_GETFL, 0);
			fflags &= ~O_NONBLOCK;
			fcntl(d, F_SETFL, fflags);
			goto retry;
		}
		len = 0;
	} else {
		for (i = 0, t = buf, s = chbuf; i < nchread; ++i) {
		    *t++ = ((tchar)*s++);
		}
	}
	return (nchread);
#endif
}

/*
 * BUG: write_() returns -1 on failure, or # of BYTEs it has written.
 *	For consistency and symmetry, it should return the number of
 *	characters it has actually written, but that is technically
 *	difficult although not impossible.  Anyway, the return
 *	value of write() has never been used by the original csh,
 *	so this bug should be OK.
 */
int
write_(int d, tchar *buf, int nch)
{
	unsigned char chbuf[BUFSIZ*MB_LEN_MAX]; /* General use buffer. */
#ifdef MBCHAR
	tchar		*pt;
	unsigned char	*pc;
	wchar_t		wc;
	int		i, j;

#ifdef	DBG
	tprintf("Entering write_(d=%d, buf=0x%x, nch=%d);\n",
	    d, buf, nch); /* Hope printf() doesn't call write_() itself! */
#endif /* DBG */
	assert(nch * MB_CUR_MAX < sizeof (chbuf));
	i = nch;
	pt = buf;
	pc = chbuf;
	while (i--) {
		/*
		 * Convert to tchar string.
		 * NUL is treated as normal char here.
		 */
		wc = (wchar_t)((*pt++)&TRIM);
		if (wc == (wchar_t)0) {
			*pc++ = 0;
		} else {
			if ((j = wctomb((char *)pc, wc)) <= 0) {
				*pc = (unsigned char)wc;
				j = 1;
			}
			pc += j;
		}
	}
	return (write(d, chbuf, pc - chbuf));
#else /* !MBCHAR */
	/* One byte always represents one tchar.  Easy! */
	int	i;
	unsigned char	*s;
	tchar	*t;

#ifdef	DBG
	tprintf("Entering write_(d=%d, buf=0x%x, nch=%d);\n",
	    d, buf, nch); /* Hope printf() doesn't call write_() itself! */
#endif /* DBG */
	assert(nch <= sizeof (chbuf));
	for (i = 0, t = buf, s = chbuf; i < nch; ++i) {
	    *s++ = (char)((*t++)&0xff);
	}
	return (write(d, (char *)chbuf, nch));
#endif
}

#undef chbuf

#include <sys/types.h>
#include <sys/stat.h>	/* satruct stat */
#include <dirent.h>	/* DIR */

extern DIR *Dirp;

int
stat_(tchar *path, struct stat *buf)
{
	char chbuf[MAXPATHLEN * MB_LEN_MAX]; /* General use buffer. */

	tstostr(chbuf, path);
	return (stat((char *)chbuf, buf));
}

int
lstat_(tchar *path, struct stat *buf)
{
	char chbuf[MAXPATHLEN * MB_LEN_MAX]; /* General use buffer. */

	tstostr(chbuf, path);
	return (lstat((char *)chbuf, buf));
}

int
chdir_(tchar *path)
{
	char chbuf[MAXPATHLEN * MB_LEN_MAX]; /* General use buffer. */

	tstostr(chbuf, path);
	return (chdir((char *)chbuf));
}

tchar *
getwd_(tchar *path)
{
	char chbuf[MAXPATHLEN * MB_LEN_MAX]; /* General use buffer. */
	int	rc;

	rc = (int)getwd((char *)chbuf);
	if (rc == 0) {
		return (0);
	} else {
		return (strtots(path, chbuf));
	}
}

int
unlink_(tchar *path)
{
	char chbuf[MAXPATHLEN * MB_LEN_MAX]; /* General use buffer. */

	tstostr(chbuf, path);
	return (unlink((char *)chbuf));
}

DIR *
opendir_(tchar *dirname)
{
	char chbuf[MAXPATHLEN * MB_LEN_MAX]; /* General use buffer. */

	extern DIR *opendir();
	DIR	*dir;

	dir = opendir(tstostr(chbuf, dirname));
	if (dir != NULL) {
		setfd(dir->dd_fd);
	}
	return (Dirp = dir);
}

int
closedir_(DIR *dirp)
{
	int ret;
	extern int closedir();

	ret = closedir(dirp);
	Dirp = NULL;
	return (ret);
}

int
gethostname_(tchar *name, int namelen)
{
	char chbuf[BUFSIZ * MB_LEN_MAX]; /* General use buffer. */

	assert(namelen < BUFSIZ);
	if (gethostname((char *)chbuf, sizeof (chbuf)) != 0) {
		return (-1);
	}
	if (mbstotcs(name, chbuf, namelen) < 0) {
		return (-1);
	}
	return (0); /* Succeeded. */
}

int
readlink_(tchar *path, tchar *buf, int bufsiz)
{
	char chbuf[MAXPATHLEN * MB_LEN_MAX]; /* General use buffer. */
	char	chpath[MAXPATHLEN + 1];
	int	i;

	tstostr(chpath, path);
	i = readlink(chpath, (char *)chbuf, sizeof (chbuf));
	if (i < 0) {
		return (-1);
	}
	chbuf[i] = (char)0;	/* readlink() doesn't put NULL. */
	i = mbstotcs(buf, chbuf, bufsiz);
	if (i < 0) {
		return (-1);
	}
	return (i - 1); /* Return # of tchars EXCLUDING the terminating NULL. */
}

/* checks that it's a number */

int
chkalldigit_(tchar *str)
{
	char chbuf[BUFSIZ * MB_LEN_MAX]; /* General use buffer. */
	char *c = chbuf;

	(void) tstostr(chbuf, str);

	while (*c)
		if (!isdigit(*(c++)))
			return (-1);

	return (0);
}

int
atoi_(tchar *str)
{
	char chbuf[BUFSIZ * MB_LEN_MAX]; /* General use buffer. */

	tstostr(chbuf, str);
	return (atoi((char *)chbuf));
}

tchar *
simple(tchar *s)
{
	tchar *sname = s;

	while (1) {
		if (any('/', sname)) {
			while (*sname++ != '/')
				;
		} else {
			return (sname);
		}
	}
}
