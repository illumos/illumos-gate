/*
 * CDDL HEADER START
 *
 * The contents of this file are subject to the terms of the
 * Common Development and Distribution License (the "License").
 * You may not use this file except in compliance with the License.
 *
 * You can obtain a copy of the license at usr/src/OPENSOLARIS.LICENSE
 * or http://www.opensolaris.org/os/licensing.
 * See the License for the specific language governing permissions
 * and limitations under the License.
 *
 * When distributing Covered Code, include this CDDL HEADER in each
 * file and include the License file at usr/src/OPENSOLARIS.LICENSE.
 * If applicable, add the following below this CDDL HEADER, with the
 * fields enclosed by brackets "[]" replaced with your own identifying
 * information: Portions Copyright [yyyy] [name of copyright owner]
 *
 * CDDL HEADER END
 */

/*
 * Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#include "lint.h"
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <stdlib.h>
#include <stdio.h>
#include <dlfcn.h>
#include <fcntl.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <sys/param.h>
#include <alloca.h>
#include "iconv.h"
#include "iconvP.h"
#include "../i18n/_loc_path.h"

static iconv_p	iconv_open_all(const char *, const char *, char *);
static iconv_p	iconv_open_private(const char *, const char *);
static iconv_p	iconv_search_alias(const char *, const char *, char *);
static size_t	passthru_icv_iconv(iconv_t, const char **, size_t *, char **,
	size_t *);
static void	passthru_icv_close(iconv_t);

#define	PASSTHRU_MAGIC_NUMBER	(0x53756e)


/*
 * These functions are mainly implemented by using a shared object and
 * the dlopen() functions. The actual conversion algorithm for a particular
 * conversion is implemented via a shared object as a loadable conversion
 * module which is linked dynamically at run time.
 *
 * The loadable conversion module resides as either:
 *
 *	/usr/lib/iconv/geniconvtbl.so
 *
 * if the conversion is supported through a geniconvtbl code conversion
 * binary table or as a module that directly specifies the conversion at:
 *
 *	/usr/lib/iconv/fromcode%tocode.so
 *
 * where fromcode is the source encoding and tocode is the target encoding.
 * The modules have 3 entries: _icv_open(), _icv_iconv(), and _icv_close().
 *
 * If there is no code conversion supported and if the fromcode and the tocode
 * are specifying the same codeset, then, the byte-by-byte, pass-through code
 * conversion that is embedded in the libc is used instead.
 *
 * The following are the related PSARC cases:
 *
 *	PSARC/1993/153 iconv/iconv_open/iconv_close
 *	PSARC/1999/292 Addition of geniconvtbl(1)
 *	PSARC/2001/072 GNU gettext support
 *	PSARC/2009/561 Pass-through iconv code conversion
 *
 * The PSARC/2001/072 includes the /usr/lib/iconv/alias interface.
 */

iconv_t
iconv_open(const char *tocode, const char *fromcode)
{
	iconv_t	cd;
	char	*ipath;

	if ((cd = malloc(sizeof (struct _iconv_info))) == NULL)
		return ((iconv_t)-1);

	/*
	 * Memory for ipath is allocated/released in this function.
	 */
	ipath = malloc(MAXPATHLEN);
	if (ipath == NULL) {
		free(cd);
		return ((iconv_t)-1);
	}

	cd->_conv = iconv_open_all(tocode, fromcode, ipath);
	if (cd->_conv != (iconv_p)-1) {
		/* found a valid module for this conversion */
		free(ipath);
		return (cd);
	}

	/*
	 * Now, try using the encoding name aliasing table
	 */
	cd->_conv = iconv_search_alias(tocode, fromcode, ipath);
	free(ipath);
	if (cd->_conv == (iconv_p)-1) {
		/*
		 * As the last resort, check if the tocode and the fromcode
		 * are referring to the same codeset name or not. If so,
		 * assign the embedded pass-through code conversion.
		 */
		if (strcasecmp(tocode, fromcode) != 0) {
			/*
			 * No valid conversion available. Do failure retrun
			 * with the errno set by iconv_search_alias().
			 */
			free(cd);
			return ((iconv_t)-1);
		}

		/*
		 * For a pass-through byte-by-byte code conversion, allocate
		 * an internal conversion descriptor and initialize the data
		 * fields appropriately and we are done.
		 */
		cd->_conv = malloc(sizeof (struct _iconv_fields));
		if (cd->_conv == NULL) {
			free(cd);
			return ((iconv_t)-1);
		}

		cd->_conv->_icv_handle = NULL;
		cd->_conv->_icv_iconv = passthru_icv_iconv;
		cd->_conv->_icv_close = passthru_icv_close;
		cd->_conv->_icv_state = (void *)PASSTHRU_MAGIC_NUMBER;
	}

	/* found a valid module for this conversion */
	return (cd);
}

static size_t
search_alias(char **paddr, size_t size, const char *variant)
{
	char	*addr = *paddr;
	char 	*p, *sp, *q;
	size_t	var_len, can_len;

	var_len = strlen(variant);
	p = addr;
	q = addr + size;
	while (q > p) {
		if (*p == '#') {
			/*
			 * Line beginning with '#' is a comment
			 */
			p++;
			while ((q > p) && (*p++ != '\n'))
				;
			continue;
		}
		/* skip leading spaces */
		while ((q > p) &&
		    ((*p == ' ') || (*p == '\t')))
			p++;
		if (q <= p)
			break;
		sp = p;
		while ((q > p) && (*p != ' ') &&
		    (*p != '\t') && (*p != '\n'))
			p++;
		if (q <= p) {
			/* invalid entry */
			break;
		}
		if (*p == '\n') {
			/* invalid entry */
			p++;
			continue;
		}

		if (((p - sp) != var_len) ||
		    ((strncmp(sp, variant, var_len) != 0) &&
		    (strncasecmp(sp, variant, var_len) != 0))) {
			/*
			 * didn't match
			 */

			/* skip remaining chars in this line */
			p++;
			while ((q > p) && (*p++ != '\n'))
				;
			continue;
		}

		/* matching entry found */

		/* skip spaces */
		while ((q > p) &&
		    ((*p == ' ') || (*p == '\t')))
			p++;
		if (q <= p)
			break;
		sp = p;
		while ((q > p) && (*p != ' ') &&
		    (*p != '\t') && (*p != '\n'))
			p++;
		can_len = p - sp;
		if (can_len == 0) {
			while ((q > p) && (*p++ != '\n'))
				;
			continue;
		}
		*paddr = sp;
		return (can_len);
		/* NOTREACHED */
	}
	return (0);
}

static iconv_p
iconv_open_all(const char *to, const char *from, char *ipath)
{
	iconv_p	cv;
	int	len;

	/*
	 * First, try using the geniconvtbl conversion, which is
	 * performed by /usr/lib/iconv/geniconvtbl.so with
	 * the conversion table file:
	 * /usr/lib/iconv/geniconvtbl/binarytables/fromcode%tocode.bt
	 *
	 * If the geniconvtbl conversion cannot be done,
	 * try the conversion by the individual shared object.
	 */

	len = snprintf(ipath, MAXPATHLEN, _GENICONVTBL_PATH, from, to);
	if ((len <= MAXPATHLEN) && (access(ipath, R_OK) == 0)) {
		/*
		 * from%to.bt exists in the table dir
		 */
		cv = iconv_open_private(_GENICONVTBL_INT_PATH, ipath);
		if (cv != (iconv_p)-1) {
			/* found a valid module for this conversion */
			return (cv);
		}
	}

	/* Next, try /usr/lib/iconv/from%to.so */
	len = snprintf(ipath, MAXPATHLEN, _ICONV_PATH, from, to);
	if ((len <= MAXPATHLEN) && (access(ipath, R_OK) == 0)) {
		/*
		 * /usr/lib/iconv/from%to.so exists
		 * errno will be set by iconv_open_private on error
		 */
		return (iconv_open_private(ipath, NULL));
	}
	/* no valid module for this conversion found */
	errno = EINVAL;
	return ((iconv_p)-1);
}

static iconv_p
iconv_search_alias(const char *tocode, const char *fromcode, char *ipath)
{
	char	*p;
	char	*to_canonical, *from_canonical;
	size_t	tolen, fromlen;
	iconv_p	cv;
	int	fd;
	struct stat64	statbuf;
	caddr_t	addr;
	size_t	buflen;

	fd = open(_ENCODING_ALIAS_PATH, O_RDONLY);
	if (fd == -1) {
		/*
		 * if no alias file found,
		 * errno will be set to EINVAL.
		 */
		errno = EINVAL;
		return ((iconv_p)-1);
	}
	if (fstat64(fd, &statbuf) == -1) {
		(void) close(fd);
		/* use errno set by fstat64 */
		return ((iconv_p)-1);
	}
	buflen = (size_t)statbuf.st_size;
	addr = mmap(NULL, buflen, PROT_READ, MAP_SHARED, fd, 0);
	(void) close(fd);
	if (addr == MAP_FAILED) {
		/* use errno set by mmap */
		return ((iconv_p)-1);
	}
	p = (char *)addr;
	tolen = search_alias(&p, buflen, tocode);
	if (tolen) {
		to_canonical = alloca(tolen + 1);
		(void) memcpy(to_canonical, p, tolen);
		to_canonical[tolen] = '\0';
	} else {
		to_canonical = (char *)tocode;
	}
	p = (char *)addr;
	fromlen = search_alias(&p, buflen, fromcode);
	if (fromlen) {
		from_canonical = alloca(fromlen + 1);
		(void) memcpy(from_canonical, p, fromlen);
		from_canonical[fromlen] = '\0';
	} else {
		from_canonical = (char *)fromcode;
	}
	(void) munmap(addr, buflen);
	if (tolen == 0 && fromlen == 0) {
		errno = EINVAL;
		return ((iconv_p)-1);
	}

	cv = iconv_open_all(to_canonical, from_canonical, ipath);

	/* errno set by iconv_open_all on error */
	return (cv);
}

static iconv_p
iconv_open_private(const char *lib, const char *tbl)
{
	iconv_t (*fptr)(const char *);
	iconv_p cdpath;

	if ((cdpath = malloc(sizeof (struct _iconv_fields))) == NULL)
		return ((iconv_p)-1);

	if ((cdpath->_icv_handle = dlopen(lib, RTLD_LAZY)) == 0) {
		free(cdpath);
		/* dlopen does not define error no */
		errno = EINVAL;
		return ((iconv_p)-1);
	}

	/* gets address of _icv_open */
	if ((fptr = (iconv_t(*)(const char *))dlsym(cdpath->_icv_handle,
	    "_icv_open")) == NULL) {
		(void) dlclose(cdpath->_icv_handle);
		free(cdpath);
		/* dlsym does not define errno */
		errno = EINVAL;
		return ((iconv_p)-1);
	}

	/*
	 * gets address of _icv_iconv in the loadable conversion module
	 * and stores it in cdpath->_icv_iconv
	 */

	if ((cdpath->_icv_iconv = (size_t(*)(iconv_t, const char **,
	    size_t *, char **, size_t *))dlsym(cdpath->_icv_handle,
	    "_icv_iconv")) == NULL) {
		(void) dlclose(cdpath->_icv_handle);
		free(cdpath);
		/* dlsym does not define errno */
		errno = EINVAL;
		return ((iconv_p)-1);
	}

	/*
	 * gets address of _icv_close in the loadable conversion module
	 * and stores it in cd->_icv_close
	 */
	if ((cdpath->_icv_close = (void(*)(iconv_t))dlsym(cdpath->_icv_handle,
	    "_icv_close")) == NULL) {
		(void) dlclose(cdpath->_icv_handle);
		free(cdpath);
		/* dlsym does not define errno */
		errno = EINVAL;
		return ((iconv_p)-1);
	}

	/*
	 * initialize the state of the actual _icv_iconv conversion routine
	 * For the normal iconv module, NULL will be passed as an argument
	 * although the iconv_open() of the module won't use that.
	 */
	cdpath->_icv_state = (void *)(*fptr)(tbl);

	if (cdpath->_icv_state == (struct _icv_state *)-1) {
		(void) dlclose(cdpath->_icv_handle);
		free(cdpath);
		/* this module does not satisfy this conversion */
		errno = EINVAL;
		return ((iconv_p)-1);
	}

	return (cdpath);
}

int
iconv_close(iconv_t cd)
{
	if (cd == NULL) {
		errno = EBADF;
		return (-1);
	}
	(*(cd->_conv)->_icv_close)(cd->_conv->_icv_state);
	if (cd->_conv->_icv_handle != NULL)
		(void) dlclose(cd->_conv->_icv_handle);
	free(cd->_conv);
	free(cd);
	return (0);
}

/*
 * To have minimal performance impact to the existing run-time behavior,
 * we supply a dummy passthru_icv_close() that will just return.
 */
static void
/*LINTED E_FUNC_ARG_UNUSED*/
passthru_icv_close(iconv_t cd)
{
}

size_t
iconv(iconv_t cd, const char **inbuf, size_t *inbytesleft,
	char **outbuf, size_t *outbytesleft)
{
	/* check if cd is valid */
	if (cd == NULL || cd == (iconv_t)-1) {
		errno = EBADF;
		return ((size_t)-1);
	}

	/* direct conversion */
	return ((*(cd->_conv)->_icv_iconv)(cd->_conv->_icv_state,
	    inbuf, inbytesleft, outbuf, outbytesleft));
}

static size_t
passthru_icv_iconv(iconv_t cd, const char **inbuf, size_t *inbufleft,
	char **outbuf, size_t *outbufleft)
{
	size_t ibl;
	size_t obl;
	size_t len;
	size_t ret_val;

	/* Check if the conversion descriptor is a valid one. */
	if (cd != (iconv_t)PASSTHRU_MAGIC_NUMBER) {
		errno = EBADF;
		return ((size_t)-1);
	}

	/* For any state reset request, return success. */
	if (inbuf == NULL || *inbuf == NULL)
		return (0);

	/*
	 * Initialize internally used variables for a better performance
	 * and prepare for a couple of the return values before the actual
	 * copying of the bytes.
	 */
	ibl = *inbufleft;
	obl = *outbufleft;

	if (ibl > obl) {
		len = obl;
		errno = E2BIG;
		ret_val = (size_t)-1;
	} else {
		len = ibl;
		ret_val = 0;
	}

	/*
	 * Do the copy using memmove(). There are no EILSEQ or EINVAL
	 * checkings since this is a simple copying.
	 */
	(void) memmove((void *)*outbuf, (const void *)*inbuf, len);

	/* Update the return values related to the buffers then do return. */
	*inbuf = *inbuf + len;
	*outbuf = *outbuf + len;
	*inbufleft = ibl - len;
	*outbufleft = obl - len;

	return (ret_val);
}
