/*
 * CDDL HEADER START
 *
 * The contents of this file are subject to the terms of the
 * Common Development and Distribution License, Version 1.0 only
 * (the "License").  You may not use this file except in compliance
 * with the License.
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
 * Copyright 2001-2002 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <errno.h>
#include <strings.h>
#include <string.h>
#include <fcntl.h>
#include <assert.h>
#include <libipp.h>
#include <libnvpair.h>
#include <ipp/ippctl.h>

/*
 * Debug macros
 */

#if	defined(DEBUG) && !defined(lint)
uint32_t	ipp_debug_flags =
/*
 * DBG_IO |
 */
DBG_ERR |
0;

#define	DBG0(flags, fmt)						\
	do {								\
		if (flags & ipp_debug_flags)				\
			fprintf(stderr, "libipp: " __FN__ ": " fmt);	\
	} while (0)

#define	DBG1(flags, fmt, a)						\
	do {								\
		if (flags & ipp_debug_flags)				\
			fprintf(stderr, "libipp: " __FN__ ": " fmt, a);	\
	} while (0)

#define	DBG2(flags, fmt, a, b)						\
	do {								\
		if (flags & ipp_debug_flags)				\
			fprintf(stderr, "libipp: " __FN__ ": " fmt, a,	\
			    b);						\
	} while (0)

#define	DBG3(flags, fmt, a, b, c)					\
	do {								\
		if (flags & ipp_debug_flags)				\
			fprintf(stderr, "libipp: " __FN__ ": " fmt, a,	\
			    b, c);					\
	} while (0)

#else	/* defined(DEBUG) && !defined(lint) */
#define	DBG0(flags, fmt)
#define	DBG1(flags, fmt, a)
#define	DBG2(flags, fmt, a, b)
#define	DBG3(flags, fmt, a, b, c)
#endif	/* defined(DEBUG) && !defined(lint) */

/*
 * Control device node
 */

#define	IPPCTL_DEVICE	"/devices/pseudo/ippctl@0:ctl"

/*
 * Structures.
 */

typedef	struct array_desc_t {
	char	*name;
	char	**array;
	int	nelt;
} array_desc_t;

/*
 * Prototypes
 */

static int	nvlist_callback(nvlist_t *, void *);
static int	string_callback(nvlist_t *, void *);
static int	string_array_callback(nvlist_t *, void *);
static int	dispatch(nvlist_t **, int (*)(nvlist_t *, void *), void *);

/*
 * API functions
 */
#define	__FN__	"ipp_action_create"
int
ipp_action_create(
	const char	*modname,
	const char	*aname,
	nvlist_t	**nvlpp,
	ipp_flags_t	flags)
{
	nvlist_t	*nvlp;
	int		rc;

	/*
	 * Sanity check the arguments.
	 */

	if (nvlpp == NULL || modname == NULL || aname == NULL) {
		DBG0(DBG_ERR, "bad argument\n");
		errno = EINVAL;
		return (-1);
	}

	/*
	 * Add our data to the nvlist. (This information will be removed for
	 * use by ippctl).
	 */

	nvlp = *nvlpp;
	if ((rc = nvlist_add_byte(nvlp, IPPCTL_OP,
	    IPPCTL_OP_ACTION_CREATE)) != 0) {
		DBG1(DBG_ERR, "failed to add '%s' to nvlist\n", IPPCTL_OP);
		goto failed;
	}

	if ((rc = nvlist_add_string(nvlp, IPPCTL_MODNAME,
	    (char *)modname)) != 0) {
		DBG1(DBG_ERR, "failed to add '%s' to nvlist\n",
		    IPPCTL_MODNAME);
		goto failed;
	}

	if ((rc = nvlist_add_string(nvlp, IPPCTL_ANAME, (char *)aname)) != 0) {
		DBG1(DBG_ERR, "failed to add '%s' to nvlist\n", IPPCTL_ANAME);
		goto failed;
	}

	if ((rc = nvlist_add_uint32(nvlp, IPPCTL_FLAGS, flags)) != 0) {
		DBG1(DBG_ERR, "failed to add '%s' to nvlist\n", IPPCTL_FLAGS);
		goto failed;
	}

	/*
	 * Talk to the kernel.
	 */

	return (dispatch(nvlpp, nvlist_callback, (void *)nvlpp));
failed:
	errno = rc;
	return (-1);
}
#undef	__FN__

#define	__FN__	"ipp_action_destroy"
int
ipp_action_destroy(
	const char	*aname,
	ipp_flags_t	flags)
{
	nvlist_t	*nvlp;
	int		rc;

	/*
	 * Sanity check the arguments.
	 */

	if (aname == NULL) {
		DBG0(DBG_ERR, "bad argument\n");
		errno = EINVAL;
		return (-1);
	}

	/*
	 * Create an nvlist for our data as none is passed into the function.
	 */

	if ((rc = nvlist_alloc(&nvlp, NV_UNIQUE_NAME, 0)) != 0) {
		DBG0(DBG_ERR, "failed to allocate nvlist\n");
		nvlp = NULL;
		goto failed;
	}

	if ((rc = nvlist_add_byte(nvlp, IPPCTL_OP,
	    IPPCTL_OP_ACTION_DESTROY)) != 0) {
		DBG1(DBG_ERR, "failed to add '%s' to nvlist\n", IPPCTL_OP);
		goto failed;
	}

	if ((rc = nvlist_add_string(nvlp, IPPCTL_ANAME, (char *)aname)) != 0) {
		DBG1(DBG_ERR, "failed to add '%s' to nvlist\n", IPPCTL_ANAME);
		goto failed;
	}

	if ((rc = nvlist_add_uint32(nvlp, IPPCTL_FLAGS, flags)) != 0) {
		DBG1(DBG_ERR, "failed to add '%s' to nvlist\n", IPPCTL_FLAGS);
		goto failed;
	}

	/*
	 * Talk to the kernel.
	 */

	return (dispatch(&nvlp, NULL, NULL));
failed:
	nvlist_free(nvlp);
	errno = rc;
	return (-1);
}
#undef	__FN__

#define	__FN__	"ipp_action_modify"
int
ipp_action_modify(
	const char	*aname,
	nvlist_t	**nvlpp,
	ipp_flags_t	flags)
{
	nvlist_t	*nvlp;
	int		rc;

	/*
	 * Sanity check the arguments.
	 */

	if (nvlpp == NULL || aname == NULL) {
		DBG0(DBG_ERR, "bad argument\n");
		errno = EINVAL;
		return (-1);
	}

	/*
	 * Add our data to the nvlist.
	 */

	nvlp = *nvlpp;
	if ((rc = nvlist_add_byte(nvlp, IPPCTL_OP,
	    IPPCTL_OP_ACTION_MODIFY)) != 0) {
		DBG1(DBG_ERR, "failed to add '%s' to nvlist\n", IPPCTL_OP);
		goto failed;
	}

	if ((rc = nvlist_add_string(nvlp, IPPCTL_ANAME, (char *)aname)) != 0) {
		DBG1(DBG_ERR, "failed to add '%s' to nvlist\n", IPPCTL_ANAME);
		goto failed;
	}

	if ((rc = nvlist_add_uint32(nvlp, IPPCTL_FLAGS, flags)) != 0) {
		DBG1(DBG_ERR, "failed to add '%s' to nvlist\n", IPPCTL_FLAGS);
		goto failed;
	}

	/*
	 * Talk to the kernel.
	 */

	return (dispatch(nvlpp, nvlist_callback, (void *)nvlpp));
failed:
	errno = rc;
	return (-1);
}
#undef	__FN__

#define	__FN__	"ipp_action_info"
int
ipp_action_info(
	const char	*aname,
	int		(*fn)(nvlist_t *, void *),
	void		*arg,
	ipp_flags_t	flags)
{
	nvlist_t	*nvlp;
	int		rc;

	/*
	 * Sanity check the arguments.
	 */

	if (aname == NULL || fn == NULL) {
		DBG0(DBG_ERR, "bad argument\n");
		errno = EINVAL;
		return (-1);
	}

	/*
	 * Create an nvlist for our data.
	 */

	if ((rc = nvlist_alloc(&nvlp, NV_UNIQUE_NAME, 0)) != 0) {
		DBG0(DBG_ERR, "failed to allocate nvlist\n");
		nvlp = NULL;
	}

	if ((rc = nvlist_add_byte(nvlp, IPPCTL_OP,
	    IPPCTL_OP_ACTION_INFO)) != 0) {
		DBG1(DBG_ERR, "failed to add '%s' to nvlist\n", IPPCTL_OP);
		goto failed;
	}

	if ((rc = nvlist_add_string(nvlp, IPPCTL_ANAME, (char *)aname)) != 0) {
		DBG1(DBG_ERR, "failed to add '%s' to nvlist\n", IPPCTL_ANAME);
		goto failed;
	}

	if ((rc = nvlist_add_uint32(nvlp, IPPCTL_FLAGS, flags)) != 0) {
		DBG1(DBG_ERR, "failed to add '%s' to nvlist\n", IPPCTL_FLAGS);
		goto failed;
	}

	/*
	 * Talk to the kernel.
	 */

	return (dispatch(&nvlp, fn, arg));
failed:
	nvlist_free(nvlp);
	errno = rc;
	return (-1);
}
#undef	__FN__

#define	__FN__	"ipp_action_mod"
int
ipp_action_mod(
	const char	*aname,
	char		**modnamep)
{
	nvlist_t	*nvlp;
	int		rc;

	/*
	 * Sanity check the arguments.
	 */

	if (aname == NULL || modnamep == NULL) {
		DBG0(DBG_ERR, "bad argument\n");
		errno = EINVAL;
		return (-1);
	}

	/*
	 * Create an nvlist for our data.
	 */

	if ((rc = nvlist_alloc(&nvlp, NV_UNIQUE_NAME, 0)) != 0) {
		DBG0(DBG_ERR, "failed to allocate nvlist\n");
		nvlp = NULL;
		goto failed;
	}

	if ((rc = nvlist_add_byte(nvlp, IPPCTL_OP,
	    IPPCTL_OP_ACTION_MOD)) != 0) {
		DBG1(DBG_ERR, "failed to add '%s' to nvlist\n", IPPCTL_OP);
		goto failed;
	}

	if ((rc = nvlist_add_string(nvlp, IPPCTL_ANAME, (char *)aname)) != 0) {
		DBG1(DBG_ERR, "failed to add '%s' to nvlist\n", IPPCTL_ANAME);
		goto failed;
	}

	/*
	 * Talk to the kernel.
	 */

	return (dispatch(&nvlp, string_callback, (void *)modnamep));
failed:
	nvlist_free(nvlp);
	errno = rc;
	return (-1);
}
#undef	__FN__

#define	__FN__	"ipp_list_mods"
int
ipp_list_mods(
	char		***modname_arrayp,
	int		*neltp)
{
	nvlist_t	*nvlp;
	array_desc_t	ad;
	int		rc;

	/*
	 * Sanity check the arguments.
	 */

	if (modname_arrayp == NULL || neltp == NULL) {
		DBG0(DBG_ERR, "bad argument");
		errno = EINVAL;
		return (-1);
	}

	/*
	 * Create an nvlist for our data.
	 */

	if ((rc = nvlist_alloc(&nvlp, NV_UNIQUE_NAME, 0)) != 0) {
		DBG0(DBG_ERR, "failed to allocate nvlist\n");
		nvlp = NULL;
	}

	if ((rc = nvlist_add_byte(nvlp, IPPCTL_OP,
	    IPPCTL_OP_LIST_MODS)) != 0) {
		DBG1(DBG_ERR, "failed to add '%s' to nvlist\n", IPPCTL_OP);
		goto failed;
	}

	/*
	 * Talk to the kernel.
	 */

	ad.name = IPPCTL_MODNAME_ARRAY;
	ad.array = NULL;
	ad.nelt = 0;

	if ((rc = dispatch(&nvlp, string_array_callback, (void *)&ad)) == 0) {
		*modname_arrayp = ad.array;
		*neltp = ad.nelt;
	}

	return (rc);
failed:
	nvlist_free(nvlp);
	errno = rc;
	return (-1);
}
#undef	__FN__

#define	__FN__	"ipp_mod_list_actions"
int
ipp_mod_list_actions(
	const char	*modname,
	char		***aname_arrayp,
	int		*neltp)
{
	nvlist_t	*nvlp;
	array_desc_t	ad;
	int		rc;

	/*
	 * Sanity check the arguments.
	 */

	if (modname == NULL || aname_arrayp == NULL || neltp == NULL) {
		DBG0(DBG_ERR, "bad argument");
		errno = EINVAL;
		return (-1);
	}

	/*
	 * Create an nvlist for our data.
	 */

	if ((rc = nvlist_alloc(&nvlp, NV_UNIQUE_NAME, 0)) != 0) {
		DBG0(DBG_ERR, "failed to allocate nvlist\n");
		nvlp = NULL;
	}

	if ((rc = nvlist_add_byte(nvlp, IPPCTL_OP,
	    IPPCTL_OP_MOD_LIST_ACTIONS)) != 0) {
		DBG1(DBG_ERR, "failed to add '%s' to nvlist\n", IPPCTL_OP);
		goto failed;
	}

	if ((rc = nvlist_add_string(nvlp, IPPCTL_MODNAME,
	    (char *)modname)) != 0) {
		DBG1(DBG_ERR, "failed to add '%s' to nvlist\n", IPPCTL_MODNAME);
		goto failed;
	}

	/*
	 * Talk to the kernel.
	 */

	ad.name = IPPCTL_ANAME_ARRAY;
	ad.array = NULL;
	ad.nelt = 0;

	if ((rc = dispatch(&nvlp, string_array_callback, (void *)&ad)) == 0) {
		*aname_arrayp = ad.array;
		*neltp = ad.nelt;
	}

	return (rc);
failed:
	nvlist_free(nvlp);
	errno = rc;
	return (-1);
}
#undef	__FN__

#define	__FN__	"ipp_free"
void
ipp_free(
	char	*buf)
{
	free(buf);
}
#undef	__FN__

#define	__FN__	"ipp_free_array"
void
ipp_free_array(
	char	**array,
	int	nelt)
{
	int	i;

	assert(array[nelt] == NULL);

	for (i = 0; i < nelt; i++)
		free(array[i]);

	free(array);
}
#undef	__FN__

#define	__FN__	"nvlist_callback"
static int
nvlist_callback(
	nvlist_t	*nvlp,
	void		*arg)
{
	nvlist_t	**nvlpp = (nvlist_t **)arg;
	int		rc;

	/*
	 * Callback function used by ipp_action_create() and
	 * ipp_action_modify()
	 */

	DBG0(DBG_IO, "called\n");

	assert(nvlpp != NULL);
	assert(*nvlpp == NULL);

	/*
	 * Duplicate the nvlist and set the given pointer to point at the new
	 * copy.
	 */

	if ((rc = nvlist_dup(nvlp, nvlpp, 0)) != 0) {
		DBG0(DBG_ERR, "failed to dup nvlist\n");
		errno = rc;
		return (-1);
	}

	return (0);
}
#undef	__FN__

#define	__FN__	"string_callback"
static int
string_callback(
	nvlist_t	*nvlp,
	void		*arg)
{
	char		**namep = (char **)arg;
	char		*name;
	char		*ptr;
	int		rc;

	/*
	 * Callback function used by ipp_action_mod()
	 */

	DBG0(DBG_IO, "called\n");

	assert(namep != NULL);

	/*
	 * Look up the module name from the nvlist.
	 */

	if ((rc = nvlist_lookup_string(nvlp, IPPCTL_MODNAME, &ptr)) != 0) {
		DBG0(DBG_ERR, "failed to find string\n");
		errno = rc;
		return (-1);
	}

	/*
	 * Allocate a duplicate string.
	 */

	if ((name = strdup(ptr)) == NULL) {
		DBG0(DBG_ERR, "failed to duplicate string\n");
		return (-1);
	}

	/*
	 * Set the given pointer to point at the string.
	 */

	*namep = name;
	return (0);
}
#undef	__FN__

#define	__FN__	"string_array_callback"
static int
string_array_callback(
	nvlist_t	*nvlp,
	void		*arg)
{
	array_desc_t	*adp = (array_desc_t *)arg;
	char		**dst;
	char		**src;
	uint_t		nelt;
	int		i;
	int		rc;

	/*
	 * Callback function used by ipp_list_mods()
	 */

	DBG0(DBG_IO, "called\n");

	assert(adp != NULL);

	/*
	 * Look up the module name from the nvlist.
	 */

	if ((rc = nvlist_lookup_string_array(nvlp, adp->name, &src,
	    &nelt)) != 0) {
		DBG0(DBG_ERR, "failed to find array\n");
		errno = rc;
		return (-1);
	}

	/*
	 * Allocate an array.
	 */

	if ((dst = malloc((nelt + 1) * sizeof (char *))) == NULL) {
		DBG0(DBG_ERR, "failed to allocate new array\n");
		return (-1);
	}

	/*
	 * For each string in the array, allocate a new buffer and copy
	 * the string into it.
	 */

	for (i = 0; i < nelt; i++) {
		if ((dst[i] = strdup(src[i])) == NULL) {
			while (--i >= 0) {
				free(dst[i]);
			}
			free(dst);
			DBG0(DBG_ERR, "failed to duplicate array\n");
			return (-1);
		}
	}
	dst[nelt] = NULL;

	/*
	 * Set the information to be passed back.
	 */

	adp->array = dst;
	adp->nelt = nelt;

	return (0);
}
#undef	__FN__

#define	__FN__	"dispatch"
static int
dispatch(
	nvlist_t	**nvlpp,
	int		(*fn)(nvlist_t *, void *),
	void		*arg)
{
	char		*cbuf = NULL;
	char		*dbuf = NULL;
	size_t		cbuflen = 0;
	size_t		dbuflen = 0;
	size_t		thisbuflen = 0;
	size_t		nextbuflen = 0;
	int		rc;
	ippctl_ioctl_t	iioc;
	int		fd;
	nvlist_t	*cnvlp;
	nvlist_t	*dnvlp = NULL;
	int		count;
	int		rval;

	/*
	 * Sanity check the 'command' nvlist.
	 */

	cnvlp = *nvlpp;
	if (cnvlp == NULL) {
		rc = EINVAL;
		return (-1);
	}

	/*
	 * Pack the nvlist and then free the original.
	 */

	if ((rc = nvlist_pack(cnvlp, &cbuf, &cbuflen, NV_ENCODE_NATIVE,
	    0)) != 0) {
		DBG0(DBG_ERR, "failed to pack nvlist\n");
		nvlist_free(cnvlp);
		errno = rc;
		return (-1);
	}
	nvlist_free(cnvlp);
	*nvlpp = NULL;

	/*
	 * Open the control device node.
	 */

	DBG1(DBG_IO, "opening %s\n", IPPCTL_DEVICE);
	if ((fd = open(IPPCTL_DEVICE, O_RDWR | O_NOCTTY)) == -1) {
		DBG1(DBG_ERR, "failed to open %s\n", IPPCTL_DEVICE);
		goto command_failed;
	}

	/*
	 * Set up an ioctl structure to point at the packed nvlist.
	 */

	iioc.ii_buf = cbuf;
	iioc.ii_buflen = cbuflen;

	/*
	 * Issue a command ioctl, passing the ioctl structure.
	 */

	DBG0(DBG_IO, "command\n");
	if ((rc = ioctl(fd, IPPCTL_CMD, &iioc)) < 0) {
		DBG0(DBG_ERR, "command ioctl failed\n");
		goto command_failed;
	}

	/*
	 * Get back the length of the first data buffer.
	 */

	if ((nextbuflen = (size_t)rc) == 0) {
		DBG0(DBG_ERR, "no data buffer\n");
		errno = EPROTO;
		goto command_failed;
	}

	/*
	 * Try to re-use the command buffer as the first data buffer.
	 */

	dbuf = cbuf;
	thisbuflen = cbuflen;

	count = 0;
	while (nextbuflen != 0) {
		dbuflen = nextbuflen;

		/*
		 * Check whether the buffer we have is long enough for the
		 * next lot of data. If it isn't, allocate a new one of
		 * the appropriate length.
		 */

		if (nextbuflen > thisbuflen) {
			if ((dbuf = realloc(dbuf, nextbuflen)) == NULL) {
				DBG0(DBG_ERR,
				    "failed to allocate data buffer\n");
				goto data_failed;
			}
			thisbuflen = nextbuflen;
		}

		/*
		 * Set up an ioctl structure to point at the data buffer.
		 */

		iioc.ii_buf = dbuf;
		iioc.ii_buflen = dbuflen;

		/*
		 * Issue a data ioctl, passing the ioctl structure.
		 */

		DBG2(DBG_IO, "data[%d]: length = %d\n", count, dbuflen);
		if ((rc = ioctl(fd, IPPCTL_DATA, &iioc)) < 0) {
			DBG0(DBG_ERR, "data ioctl failed\n");
			goto data_failed;
		}

		/*
		 * Get the length of the *next* data buffer, if there is
		 * one.
		 */

		nextbuflen = (size_t)rc;
		DBG1(DBG_IO, "nextbuflen = %d\n", nextbuflen);

		/*
		 * Unpack the nvlist that the current data buffer should
		 * now contain.
		 */

		if ((rc = nvlist_unpack(dbuf, dbuflen, &dnvlp, 0)) != 0) {
			DBG0(DBG_ERR, "failed to unpack nvlist\n");
			errno = rc;
			goto data_failed;
		}

		/*
		 * The first data buffer should contain the kernel function's
		 * return code. Subsequent buffers contain nvlists which
		 * should be passed to the given callback function.
		 */

		if (count == 0) {
			if ((rc = nvlist_lookup_int32(dnvlp, IPPCTL_RC,
			    &rval)) != 0) {
				DBG0(DBG_ERR, "failed to find return code\n");
				nvlist_free(dnvlp);
				errno = rc;
				goto data_failed;
			}
		} else {
			if (fn != NULL)
				if (fn(dnvlp, arg) != 0) {

					/*
					 * The callback function returned
					 * a non-zero value. Abort any further
					 * data collection.
					 */

					nvlist_free(dnvlp);
					free(dbuf);
				}
		}

		/*
		 * Free the nvlist now that we have extracted the return
		 * code or called the callback function.
		 */

		nvlist_free(dnvlp);
		dnvlp = NULL;

		count++;
	}

	/*
	 * Free the data buffer as data collection is now complete.
	 */

	free(dbuf);

	/*
	 * Close the control device.
	 */

	(void) close(fd);

	/*
	 * If the kernel returned an error, we should return an error.
	 * and set errno.
	 */

	if (rval != 0) {
		DBG1(DBG_IO, "kernel return code = %d\n", rval);
		errno = rval;
		return (-1);
	}

	return (0);

command_failed:
	free(cbuf);
	if (fd != -1)
		(void) close(fd);
	return (-1);

data_failed:
	if (dbuf != NULL)
		free(dbuf);
	(void) close(fd);
	return (-1);
}
#undef	__FN__
