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
 * Copyright 2006 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * Internal utility routines for the ZFS library.
 */

#include <errno.h>
#include <fcntl.h>
#include <libintl.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <strings.h>
#include <unistd.h>
#include <sys/mnttab.h>

#include <libzfs.h>

#include "libzfs_impl.h"

int
libzfs_errno(libzfs_handle_t *hdl)
{
	return (hdl->libzfs_error);
}

const char *
libzfs_error_action(libzfs_handle_t *hdl)
{
	return (hdl->libzfs_action);
}

const char *
libzfs_error_description(libzfs_handle_t *hdl)
{
	if (hdl->libzfs_desc[0] != '\0')
		return (hdl->libzfs_desc);

	switch (hdl->libzfs_error) {
	case EZFS_NOMEM:
		return (dgettext(TEXT_DOMAIN, "out of memory"));
	case EZFS_BADPROP:
		return (dgettext(TEXT_DOMAIN, "invalid property value"));
	case EZFS_PROPREADONLY:
		return (dgettext(TEXT_DOMAIN, "read only property"));
	case EZFS_PROPTYPE:
		return (dgettext(TEXT_DOMAIN, "property doesn't apply to "
		    "datasets of this type"));
	case EZFS_PROPNONINHERIT:
		return (dgettext(TEXT_DOMAIN, "property cannot be inherited"));
	case EZFS_PROPSPACE:
		return (dgettext(TEXT_DOMAIN, "invalid quota or reservation"));
	case EZFS_BADTYPE:
		return (dgettext(TEXT_DOMAIN, "operation not applicable to "
		    "datasets of this type"));
	case EZFS_BUSY:
		return (dgettext(TEXT_DOMAIN, "pool or dataset is busy"));
	case EZFS_EXISTS:
		return (dgettext(TEXT_DOMAIN, "pool or dataset exists"));
	case EZFS_NOENT:
		return (dgettext(TEXT_DOMAIN, "no such pool or dataset"));
	case EZFS_BADSTREAM:
		return (dgettext(TEXT_DOMAIN, "invalid backup stream"));
	case EZFS_DSREADONLY:
		return (dgettext(TEXT_DOMAIN, "dataset is read only"));
	case EZFS_VOLTOOBIG:
		return (dgettext(TEXT_DOMAIN, "volume size exceeds limit for "
		    "this system"));
	case EZFS_VOLHASDATA:
		return (dgettext(TEXT_DOMAIN, "volume has data"));
	case EZFS_INVALIDNAME:
		return (dgettext(TEXT_DOMAIN, "invalid name"));
	case EZFS_BADRESTORE:
		return (dgettext(TEXT_DOMAIN, "unable to restore to "
		    "destination"));
	case EZFS_BADBACKUP:
		return (dgettext(TEXT_DOMAIN, "backup failed"));
	case EZFS_BADTARGET:
		return (dgettext(TEXT_DOMAIN, "invalid target vdev"));
	case EZFS_NODEVICE:
		return (dgettext(TEXT_DOMAIN, "no such device in pool"));
	case EZFS_BADDEV:
		return (dgettext(TEXT_DOMAIN, "invalid device"));
	case EZFS_NOREPLICAS:
		return (dgettext(TEXT_DOMAIN, "no valid replicas"));
	case EZFS_RESILVERING:
		return (dgettext(TEXT_DOMAIN, "currently resilvering"));
	case EZFS_BADVERSION:
		return (dgettext(TEXT_DOMAIN, "unsupported version"));
	case EZFS_POOLUNAVAIL:
		return (dgettext(TEXT_DOMAIN, "pool is unavailable"));
	case EZFS_DEVOVERFLOW:
		return (dgettext(TEXT_DOMAIN, "too many devices in one vdev"));
	case EZFS_BADPATH:
		return (dgettext(TEXT_DOMAIN, "must be an absolute path"));
	case EZFS_CROSSTARGET:
		return (dgettext(TEXT_DOMAIN, "operation crosses datasets or "
		    "pools"));
	case EZFS_ZONED:
		return (dgettext(TEXT_DOMAIN, "dataset in use by local zone"));
	case EZFS_MOUNTFAILED:
		return (dgettext(TEXT_DOMAIN, "mount failed"));
	case EZFS_UMOUNTFAILED:
		return (dgettext(TEXT_DOMAIN, "umount failed"));
	case EZFS_UNSHAREFAILED:
		return (dgettext(TEXT_DOMAIN, "unshare(1M) failed"));
	case EZFS_SHAREFAILED:
		return (dgettext(TEXT_DOMAIN, "share(1M) failed"));
	case EZFS_DEVLINKS:
		return (dgettext(TEXT_DOMAIN, "failed to create /dev links"));
	case EZFS_PERM:
		return (dgettext(TEXT_DOMAIN, "permission denied"));
	case EZFS_NOSPC:
		return (dgettext(TEXT_DOMAIN, "out of space"));
	case EZFS_IO:
		return (dgettext(TEXT_DOMAIN, "I/O error"));
	case EZFS_INTR:
		return (dgettext(TEXT_DOMAIN, "signal received"));
	case EZFS_ISSPARE:
		return (dgettext(TEXT_DOMAIN, "device is reserved as a hot "
		    "spare"));
	case EZFS_INVALCONFIG:
		return (dgettext(TEXT_DOMAIN, "invalid vdev configuration"));
	case EZFS_RECURSIVE:
		return (dgettext(TEXT_DOMAIN, "recursive dataset dependency"));
	case EZFS_UNKNOWN:
		return (dgettext(TEXT_DOMAIN, "unknown error"));
	default:
		assert(hdl->libzfs_error == 0);
		return (dgettext(TEXT_DOMAIN, "no error"));
	}
}

/*PRINTFLIKE2*/
void
zfs_error_aux(libzfs_handle_t *hdl, const char *fmt, ...)
{
	va_list ap;

	va_start(ap, fmt);

	(void) vsnprintf(hdl->libzfs_desc, sizeof (hdl->libzfs_desc),
	    fmt, ap);
	hdl->libzfs_desc_active = 1;

	va_end(ap);
}

static void
zfs_verror(libzfs_handle_t *hdl, int error, const char *fmt, va_list ap)
{
	(void) vsnprintf(hdl->libzfs_action, sizeof (hdl->libzfs_action),
	    fmt, ap);
	hdl->libzfs_error = error;

	if (hdl->libzfs_desc_active)
		hdl->libzfs_desc_active = 0;
	else
		hdl->libzfs_desc[0] = '\0';

	if (hdl->libzfs_printerr) {
		if (error == EZFS_UNKNOWN) {
			(void) fprintf(stderr, dgettext(TEXT_DOMAIN, "internal "
			    "error: %s\n"), libzfs_error_description(hdl));
			abort();
		}

		(void) fprintf(stderr, "%s: %s\n", hdl->libzfs_action,
		    libzfs_error_description(hdl));
		if (error == EZFS_NOMEM)
			exit(1);
	}
}

/*PRINTFLIKE3*/
int
zfs_error(libzfs_handle_t *hdl, int error, const char *fmt, ...)
{
	va_list ap;

	va_start(ap, fmt);

	zfs_verror(hdl, error, fmt, ap);

	va_end(ap);

	return (-1);
}

static int
zfs_common_error(libzfs_handle_t *hdl, int error, const char *fmt,
    va_list ap)
{
	switch (error) {
	case EPERM:
	case EACCES:
		zfs_verror(hdl, EZFS_PERM, fmt, ap);
		return (-1);

	case EIO:
		zfs_verror(hdl, EZFS_IO, fmt, ap);
		return (-1);

	case EINTR:
		zfs_verror(hdl, EZFS_INTR, fmt, ap);
		return (-1);
	}

	return (0);
}

/*PRINTFLIKE3*/
int
zfs_standard_error(libzfs_handle_t *hdl, int error, const char *fmt, ...)
{
	va_list ap;

	va_start(ap, fmt);

	if (zfs_common_error(hdl, error, fmt, ap) != 0) {
		va_end(ap);
		return (-1);
	}


	switch (error) {
	case ENXIO:
		zfs_verror(hdl, EZFS_IO, fmt, ap);
		break;

	case ENOENT:
		zfs_error_aux(hdl, dgettext(TEXT_DOMAIN,
		    "dataset does not exist"));
		zfs_verror(hdl, EZFS_NOENT, fmt, ap);
		break;

	case ENOSPC:
	case EDQUOT:
		zfs_verror(hdl, EZFS_NOSPC, fmt, ap);
		return (-1);

	case EEXIST:
		zfs_error_aux(hdl, dgettext(TEXT_DOMAIN,
		    "dataset already exists"));
		zfs_verror(hdl, EZFS_EXISTS, fmt, ap);
		break;

	case EBUSY:
		zfs_error_aux(hdl, dgettext(TEXT_DOMAIN,
		    "dataset is busy"));
		zfs_verror(hdl, EZFS_BUSY, fmt, ap);
		break;

	default:
		zfs_error_aux(hdl, strerror(errno));
		zfs_verror(hdl, EZFS_UNKNOWN, fmt, ap);
		break;
	}

	va_end(ap);
	return (-1);
}

/*PRINTFLIKE3*/
int
zpool_standard_error(libzfs_handle_t *hdl, int error, const char *fmt, ...)
{
	va_list ap;

	va_start(ap, fmt);

	if (zfs_common_error(hdl, error, fmt, ap) != 0) {
		va_end(ap);
		return (-1);
	}

	switch (error) {
	case ENODEV:
		zfs_verror(hdl, EZFS_NODEVICE, fmt, ap);
		break;

	case ENOENT:
		zfs_error_aux(hdl, dgettext(TEXT_DOMAIN, "no such pool"));
		zfs_verror(hdl, EZFS_NOENT, fmt, ap);
		break;

	case EEXIST:
		zfs_error_aux(hdl, dgettext(TEXT_DOMAIN,
		    "pool already exists"));
		zfs_verror(hdl, EZFS_EXISTS, fmt, ap);
		break;

	case EBUSY:
		zfs_error_aux(hdl, dgettext(TEXT_DOMAIN, "pool is busy"));
		zfs_verror(hdl, EZFS_EXISTS, fmt, ap);
		break;

	case ENXIO:
		zfs_error_aux(hdl, dgettext(TEXT_DOMAIN,
		    "one or more devices is currently unavailable"));
		zfs_verror(hdl, EZFS_BADDEV, fmt, ap);
		break;

	case ENAMETOOLONG:
		zfs_verror(hdl, EZFS_DEVOVERFLOW, fmt, ap);
		break;

	default:
		zfs_error_aux(hdl, strerror(error));
		zfs_verror(hdl, EZFS_UNKNOWN, fmt, ap);
	}

	va_end(ap);
	return (-1);
}

/*
 * Display an out of memory error message and abort the current program.
 */
int
no_memory(libzfs_handle_t *hdl)
{
	return (zfs_error(hdl, EZFS_NOMEM, "internal error"));
}

/*
 * A safe form of malloc() which will die if the allocation fails.
 */
void *
zfs_alloc(libzfs_handle_t *hdl, size_t size)
{
	void *data;

	if ((data = calloc(1, size)) == NULL)
		(void) no_memory(hdl);

	return (data);
}

/*
 * A safe form of realloc(), which also zeroes newly allocated space.
 */
void *
zfs_realloc(libzfs_handle_t *hdl, void *ptr, size_t oldsize, size_t newsize)
{
	void *ret;

	if ((ret = realloc(ptr, newsize)) == NULL) {
		(void) no_memory(hdl);
		free(ptr);
		return (NULL);
	}

	bzero((char *)ret + oldsize, (newsize - oldsize));
	return (ret);
}

/*
 * A safe form of strdup() which will die if the allocation fails.
 */
char *
zfs_strdup(libzfs_handle_t *hdl, const char *str)
{
	char *ret;

	if ((ret = strdup(str)) == NULL)
		(void) no_memory(hdl);

	return (ret);
}

/*
 * Convert a number to an appropriately human-readable output.
 */
void
zfs_nicenum(uint64_t num, char *buf, size_t buflen)
{
	uint64_t n = num;
	int index = 0;
	char u;

	while (n >= 1024) {
		n /= 1024;
		index++;
	}

	u = " KMGTPE"[index];

	if (index == 0) {
		(void) snprintf(buf, buflen, "%llu", n);
	} else if ((num & ((1ULL << 10 * index) - 1)) == 0) {
		/*
		 * If this is an even multiple of the base, always display
		 * without any decimal precision.
		 */
		(void) snprintf(buf, buflen, "%llu%c", n, u);
	} else {
		/*
		 * We want to choose a precision that reflects the best choice
		 * for fitting in 5 characters.  This can get rather tricky when
		 * we have numbers that are very close to an order of magnitude.
		 * For example, when displaying 10239 (which is really 9.999K),
		 * we want only a single place of precision for 10.0K.  We could
		 * develop some complex heuristics for this, but it's much
		 * easier just to try each combination in turn.
		 */
		int i;
		for (i = 2; i >= 0; i--) {
			(void) snprintf(buf, buflen, "%.*f%c", i,
			    (double)num / (1ULL << 10 * index), u);
			if (strlen(buf) <= 5)
				break;
		}
	}
}

void
libzfs_print_on_error(libzfs_handle_t *hdl, boolean_t printerr)
{
	hdl->libzfs_printerr = printerr;
}

libzfs_handle_t *
libzfs_init(void)
{
	libzfs_handle_t *hdl;

	if ((hdl = calloc(sizeof (libzfs_handle_t), 1)) == NULL) {
		return (NULL);
	}

	if ((hdl->libzfs_fd = open(ZFS_DEV, O_RDWR)) < 0) {
		free(hdl);
		return (NULL);
	}

	if ((hdl->libzfs_mnttab = fopen(MNTTAB, "r")) == NULL) {
		(void) close(hdl->libzfs_fd);
		free(hdl);
		return (NULL);
	}

	hdl->libzfs_sharetab = fopen("/etc/dfs/sharetab", "r");

	return (hdl);
}

void
libzfs_fini(libzfs_handle_t *hdl)
{
	(void) close(hdl->libzfs_fd);
	if (hdl->libzfs_mnttab)
		(void) fclose(hdl->libzfs_mnttab);
	if (hdl->libzfs_sharetab)
		(void) fclose(hdl->libzfs_sharetab);
	namespace_clear(hdl);
	free(hdl);
}

libzfs_handle_t *
zpool_get_handle(zpool_handle_t *zhp)
{
	return (zhp->zpool_hdl);
}

libzfs_handle_t *
zfs_get_handle(zfs_handle_t *zhp)
{
	return (zhp->zfs_hdl);
}

/*
 * Initialize the zc_nvlist_dst member to prepare for receiving an nvlist from
 * an ioctl().
 */
int
zcmd_alloc_dst_nvlist(libzfs_handle_t *hdl, zfs_cmd_t *zc, size_t len)
{
	if (len == 0)
		len = 1024;
	zc->zc_nvlist_dst_size = len;
	if ((zc->zc_nvlist_dst = (uint64_t)(uintptr_t)
	    zfs_alloc(hdl, zc->zc_nvlist_dst_size)) == NULL)
		return (-1);

	return (0);
}

/*
 * Called when an ioctl() which returns an nvlist fails with ENOMEM.  This will
 * expand the nvlist to the size specified in 'zc_nvlist_dst_size', which was
 * filled in by the kernel to indicate the actual required size.
 */
int
zcmd_expand_dst_nvlist(libzfs_handle_t *hdl, zfs_cmd_t *zc)
{
	free((void *)(uintptr_t)zc->zc_nvlist_dst);
	if ((zc->zc_nvlist_dst = (uint64_t)(uintptr_t)
	    zfs_alloc(hdl, zc->zc_nvlist_dst_size))
	    == NULL)
		return (-1);

	return (0);
}

/*
 * Called to free the destination nvlist stored in the command structure.  This
 * is only needed if the caller must abort abnormally.  The various other
 * zcmd_*() routines will free it on failure (or on success, for
 * zcmd_read_nvlist).
 */
void
zcmd_free_nvlists(zfs_cmd_t *zc)
{
	free((void *)(uintptr_t)zc->zc_nvlist_src);
	free((void *)(uintptr_t)zc->zc_nvlist_dst);
}

int
zcmd_write_src_nvlist(libzfs_handle_t *hdl, zfs_cmd_t *zc, nvlist_t *nvl,
    size_t *size)
{
	char *packed;
	size_t len;

	verify(nvlist_size(nvl, &len, NV_ENCODE_NATIVE) == 0);

	if ((packed = zfs_alloc(hdl, len)) == NULL)
		return (-1);

	verify(nvlist_pack(nvl, &packed, &len, NV_ENCODE_NATIVE, 0) == 0);

	zc->zc_nvlist_src = (uint64_t)(uintptr_t)packed;
	zc->zc_nvlist_src_size = len;

	if (size)
		*size = len;
	return (0);
}

/*
 * Unpacks an nvlist from the ZFS ioctl command structure.
 */
int
zcmd_read_dst_nvlist(libzfs_handle_t *hdl, zfs_cmd_t *zc, nvlist_t **nvlp)
{
	if (nvlist_unpack((void *)(uintptr_t)zc->zc_nvlist_dst,
	    zc->zc_nvlist_dst_size, nvlp, 0) != 0)
		return (no_memory(hdl));

	return (0);
}
