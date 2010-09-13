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
 * Copyright 2006 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <sys/types.h>
#include <sys/smbios_impl.h>
#include <sys/sysmacros.h>
#include <sys/stat.h>
#include <sys/mman.h>

#include <alloca.h>
#include <limits.h>
#include <unistd.h>
#include <strings.h>
#include <stdlib.h>
#include <errno.h>
#include <fcntl.h>

#pragma init(smb_init)
static void
smb_init(void)
{
	_smb_debug = getenv("SMB_DEBUG") != NULL;
}

static smbios_hdl_t *
smb_fileopen(int fd, int version, int flags, int *errp)
{
	smbios_entry_t *ep = alloca(SMB_ENTRY_MAXLEN);
	smbios_hdl_t *shp = NULL;
	ssize_t n, elen;
	void *stbuf;

	if ((n = pread64(fd, ep, sizeof (*ep), 0)) != sizeof (*ep))
		return (smb_open_error(shp, errp, n < 0 ? errno : ESMB_NOHDR));

	if (strncmp(ep->smbe_eanchor, SMB_ENTRY_EANCHOR, SMB_ENTRY_EANCHORLEN))
		return (smb_open_error(shp, errp, ESMB_HEADER));

	elen = MIN(ep->smbe_elen, SMB_ENTRY_MAXLEN);

	if ((n = pread64(fd, ep, elen, 0)) != elen)
		return (smb_open_error(shp, errp, n < 0 ? errno : ESMB_NOHDR));

	if ((stbuf = smb_alloc(ep->smbe_stlen)) == NULL)
		return (smb_open_error(shp, errp, ESMB_NOMEM));

	if ((n = pread64(fd, stbuf, ep->smbe_stlen,
	    (off64_t)ep->smbe_staddr)) != ep->smbe_stlen) {
		smb_free(stbuf, ep->smbe_stlen);
		return (smb_open_error(shp, errp, n < 0 ? errno : ESMB_NOSTAB));
	}

	shp = smbios_bufopen(ep, stbuf, ep->smbe_stlen, version, flags, errp);

	if (shp != NULL)
		shp->sh_flags |= SMB_FL_BUFALLOC;
	else
		smb_free(stbuf, ep->smbe_stlen);

	return (shp);
}

static smbios_hdl_t *
smb_biosopen(int fd, int version, int flags, int *errp)
{
	smbios_entry_t *ep = alloca(SMB_ENTRY_MAXLEN);
	smbios_hdl_t *shp = NULL;
	size_t pgsize, pgmask, pgoff;
	void *stbuf, *bios, *p, *q;

	bios = mmap(NULL, SMB_RANGE_LIMIT - SMB_RANGE_START + 1,
	    PROT_READ, MAP_SHARED, fd, (uint32_t)SMB_RANGE_START);

	if (bios == MAP_FAILED)
		return (smb_open_error(shp, errp, ESMB_MAPDEV));

	q = (void *)((uintptr_t)bios + SMB_RANGE_LIMIT - SMB_RANGE_START + 1);

	for (p = bios; p < q; p = (void *)((uintptr_t)p + 16)) {
		if (strncmp(p, SMB_ENTRY_EANCHOR, SMB_ENTRY_EANCHORLEN) == 0)
			break;
	}

	if (p >= q) {
		(void) munmap(bios, SMB_RANGE_LIMIT - SMB_RANGE_START + 1);
		return (smb_open_error(NULL, errp, ESMB_NOTFOUND));
	}

	bcopy(p, ep, sizeof (smbios_entry_t));
	ep->smbe_elen = MIN(ep->smbe_elen, SMB_ENTRY_MAXLEN);
	bcopy(p, ep, ep->smbe_elen);
	(void) munmap(bios, SMB_RANGE_LIMIT - SMB_RANGE_START + 1);

	pgsize = getpagesize();
	pgmask = ~(pgsize - 1);
	pgoff = ep->smbe_staddr & ~pgmask;

	bios = mmap(NULL, ep->smbe_stlen + pgoff,
	    PROT_READ, MAP_SHARED, fd, ep->smbe_staddr & pgmask);

	if (bios == MAP_FAILED)
		return (smb_open_error(shp, errp, ESMB_MAPDEV));

	if ((stbuf = smb_alloc(ep->smbe_stlen)) == NULL) {
		(void) munmap(bios, ep->smbe_stlen + pgoff);
		return (smb_open_error(shp, errp, ESMB_NOMEM));
	}

	bcopy((char *)bios + pgoff, stbuf, ep->smbe_stlen);
	(void) munmap(bios, ep->smbe_stlen + pgoff);
	shp = smbios_bufopen(ep, stbuf, ep->smbe_stlen, version, flags, errp);

	if (shp != NULL)
		shp->sh_flags |= SMB_FL_BUFALLOC;
	else
		smb_free(stbuf, ep->smbe_stlen);

	return (shp);
}

smbios_hdl_t *
smbios_fdopen(int fd, int version, int flags, int *errp)
{
	struct stat64 st1, st2;

	if (stat64(SMB_BIOS_DEVICE, &st1) == 0 && fstat64(fd, &st2) == 0 &&
	    S_ISCHR(st2.st_mode) && st1.st_rdev == st2.st_rdev)
		return (smb_biosopen(fd, version, flags, errp));
	else
		return (smb_fileopen(fd, version, flags, errp));
}

smbios_hdl_t *
smbios_open(const char *file, int version, int flags, int *errp)
{
	smbios_hdl_t *shp;
	int fd;

	if ((fd = open64(file ? file : SMB_SMBIOS_DEVICE, O_RDONLY)) == -1) {
		if ((errno == ENOENT || errno == ENXIO) &&
		    (file == NULL || strcmp(file, SMB_SMBIOS_DEVICE) == 0))
			errno = ESMB_NOTFOUND;
		return (smb_open_error(NULL, errp, errno));
	}

	shp = smbios_fdopen(fd, version, flags, errp);
	(void) close(fd);
	return (shp);
}

static int
smbios_xwrite(smbios_hdl_t *shp, int fd, const void *buf, size_t buflen)
{
	ssize_t resid = buflen;
	ssize_t len;

	while (resid != 0) {
		if ((len = write(fd, buf, resid)) <= 0)
			return (smb_set_errno(shp, errno));
		resid -= len;
		buf = (uchar_t *)buf + len;
	}

	return (0);
}

int
smbios_write(smbios_hdl_t *shp, int fd)
{
	smbios_entry_t ep;
	off64_t off = lseek64(fd, 0, SEEK_CUR) + P2ROUNDUP(sizeof (ep), 16);

	if (off > UINT32_MAX)
		return (smb_set_errno(shp, EOVERFLOW));

	bcopy(&shp->sh_ent, &ep, sizeof (ep));
	ep.smbe_staddr = (uint32_t)off;
	smbios_checksum(shp, &ep);

	if (smbios_xwrite(shp, fd, &ep, sizeof (ep)) == -1 ||
	    lseek64(fd, off, SEEK_SET) != off ||
	    smbios_xwrite(shp, fd, shp->sh_buf, shp->sh_buflen) == -1)
		return (-1);

	return (0);
}
