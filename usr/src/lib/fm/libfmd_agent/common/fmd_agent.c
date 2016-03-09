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

/*
 * libfmd_agent contains the low-level operations that needed by the fmd
 * agents, such as page operations (status/retire/unretire), cpu operations
 * (status/online/offline), etc.
 *
 * Some operations are implemented by /dev/fm ioctls.  Those ioctls are
 * heavily versioned to allow userland patching without requiring a reboot
 * to get a matched /dev/fm.   All the ioctls use packed nvlist to interact
 * between userland and kernel.  (see fmd_agent_nvl_ioctl()).
 */

#include <fcntl.h>
#include <errno.h>
#include <unistd.h>
#include <strings.h>
#include <libnvpair.h>
#include <string.h>
#include <sys/types.h>
#include <sys/devfm.h>
#include <fmd_agent_impl.h>

int
fmd_agent_errno(fmd_agent_hdl_t *hdl)
{
	return (hdl->agent_errno);
}

int
fmd_agent_seterrno(fmd_agent_hdl_t *hdl, int err)
{
	hdl->agent_errno = err;
	return (-1);
}

const char *
fmd_agent_strerr(int err)
{
	return (strerror(err));
}

const char *
fmd_agent_errmsg(fmd_agent_hdl_t *hdl)
{
	return (fmd_agent_strerr(hdl->agent_errno));
}

static int
cleanup_set_errno(fmd_agent_hdl_t *hdl, nvlist_t *innvl, nvlist_t *outnvl,
    int err)
{
	nvlist_free(innvl);
	nvlist_free(outnvl);
	return (fmd_agent_seterrno(hdl, err));
}

/*
 * Perform /dev/fm ioctl.  The input and output data are represented by
 * name-value lists (nvlists).
 */
int
fmd_agent_nvl_ioctl(fmd_agent_hdl_t *hdl, int cmd, uint32_t ver,
    nvlist_t *innvl, nvlist_t **outnvlp)
{
	fm_ioc_data_t fid;
	int err = 0;
	char *inbuf = NULL, *outbuf = NULL;
	size_t insz = 0, outsz = 0;

	if (innvl != NULL) {
		if ((err = nvlist_size(innvl, &insz, NV_ENCODE_NATIVE)) != 0)
			return (err);
		if (insz > FM_IOC_MAXBUFSZ)
			return (ENAMETOOLONG);
		if ((inbuf = umem_alloc(insz, UMEM_DEFAULT)) == NULL)
			return (errno);

		if ((err = nvlist_pack(innvl, &inbuf, &insz,
		    NV_ENCODE_NATIVE, 0)) != 0) {
			umem_free(inbuf, insz);
			return (err);
		}
	}

	if (outnvlp != NULL) {
		outsz = FM_IOC_OUT_BUFSZ;
	}
	for (;;) {
		if (outnvlp != NULL) {
			outbuf = umem_alloc(outsz, UMEM_DEFAULT);
			if (outbuf == NULL) {
				err = errno;
				break;
			}
		}

		fid.fid_version = ver;
		fid.fid_insz = insz;
		fid.fid_inbuf = inbuf;
		fid.fid_outsz = outsz;
		fid.fid_outbuf = outbuf;

		if (ioctl(hdl->agent_devfd, cmd, &fid) < 0) {
			if (errno == ENAMETOOLONG && outsz != 0 &&
			    outsz < (FM_IOC_OUT_MAXBUFSZ / 2)) {
				umem_free(outbuf, outsz);
				outsz *= 2;
				outbuf = umem_alloc(outsz, UMEM_DEFAULT);
				if (outbuf == NULL) {
					err = errno;
					break;
				}
			} else {
				err = errno;
				break;
			}
		} else if (outnvlp != NULL) {
			err = nvlist_unpack(fid.fid_outbuf, fid.fid_outsz,
			    outnvlp, 0);
			break;
		} else {
			break;
		}
	}

	if (inbuf != NULL)
		umem_free(inbuf, insz);
	if (outbuf != NULL)
		umem_free(outbuf, outsz);

	return (err);
}

/*
 * Open /dev/fm and return a handle.  ver is the overall interface version.
 */
static fmd_agent_hdl_t *
fmd_agent_open_dev(int ver, int mode)
{
	fmd_agent_hdl_t *hdl;
	int fd, err;
	nvlist_t *nvl;

	if ((fd = open("/dev/fm", mode)) < 0)
		return (NULL); /* errno is set for us */

	if ((hdl = umem_alloc(sizeof (fmd_agent_hdl_t),
	    UMEM_DEFAULT)) == NULL) {
		err = errno;
		(void) close(fd);
		errno = err;
		return (NULL);
	}

	hdl->agent_devfd = fd;
	hdl->agent_version = ver;

	/*
	 * Get the individual interface versions.
	 */
	if ((err = fmd_agent_nvl_ioctl(hdl, FM_IOC_VERSIONS, ver, NULL, &nvl))
	    < 0) {
		(void) close(fd);
		umem_free(hdl, sizeof (fmd_agent_hdl_t));
		errno = err;
		return (NULL);
	}

	hdl->agent_ioc_versions = nvl;
	return (hdl);
}

fmd_agent_hdl_t *
fmd_agent_open(int ver)
{
	if (ver > FMD_AGENT_VERSION) {
		errno = ENOTSUP;
		return (NULL);
	}
	return (fmd_agent_open_dev(ver, O_RDONLY));
}

void
fmd_agent_close(fmd_agent_hdl_t *hdl)
{
	(void) close(hdl->agent_devfd);
	nvlist_free(hdl->agent_ioc_versions);
	umem_free(hdl, sizeof (fmd_agent_hdl_t));
}

/*
 * Given a interface name, return the kernel interface version.
 */
int
fmd_agent_version(fmd_agent_hdl_t *hdl, const char *op, uint32_t *verp)
{
	int err;

	err = nvlist_lookup_uint32(hdl->agent_ioc_versions,
	    op, verp);

	if (err != 0) {
		errno = err;
		return (-1);
	}
	return (0);
}

static int
fmd_agent_pageop_v1(fmd_agent_hdl_t *hdl, int cmd, nvlist_t *fmri)
{
	int err;
	nvlist_t *nvl = NULL;

	if ((err = nvlist_alloc(&nvl, NV_UNIQUE_NAME_TYPE, 0)) != 0 ||
	    (err = nvlist_add_nvlist(nvl, FM_PAGE_RETIRE_FMRI, fmri)) != 0 ||
	    (err = fmd_agent_nvl_ioctl(hdl, cmd, 1, nvl, NULL)) != 0)
		return (cleanup_set_errno(hdl, nvl, NULL, err));

	nvlist_free(nvl);
	return (0);
}

static int
fmd_agent_pageop(fmd_agent_hdl_t *hdl, int cmd, nvlist_t *fmri)
{
	uint32_t ver;

	if (fmd_agent_version(hdl, FM_PAGE_OP_VERSION, &ver) == -1)
		return (fmd_agent_seterrno(hdl, errno));

	switch (ver) {
	case 1:
		return (fmd_agent_pageop_v1(hdl, cmd, fmri));

	default:
		return (fmd_agent_seterrno(hdl, ENOTSUP));
	}
}

int
fmd_agent_page_retire(fmd_agent_hdl_t *hdl, nvlist_t *fmri)
{
	int rc = fmd_agent_pageop(hdl, FM_IOC_PAGE_RETIRE, fmri);
	int err = fmd_agent_errno(hdl);

	/*
	 * FM_IOC_PAGE_RETIRE ioctl returns:
	 *   0 - success in retiring page
	 *   -1, errno = EIO - page is already retired
	 *   -1, errno = EAGAIN - page is scheduled for retirement
	 *   -1, errno = EINVAL - page fmri is invalid
	 *   -1, errno = any else - error
	 */
	if (rc == 0 || err == EIO || err == EINVAL) {
		if (rc == 0)
			(void) fmd_agent_seterrno(hdl, 0);
		return (FMD_AGENT_RETIRE_DONE);
	}
	if (err == EAGAIN)
		return (FMD_AGENT_RETIRE_ASYNC);

	return (FMD_AGENT_RETIRE_FAIL);
}

int
fmd_agent_page_unretire(fmd_agent_hdl_t *hdl, nvlist_t *fmri)
{
	int rc = fmd_agent_pageop(hdl, FM_IOC_PAGE_UNRETIRE, fmri);
	int err = fmd_agent_errno(hdl);

	/*
	 * FM_IOC_PAGE_UNRETIRE ioctl returns:
	 *   0 - success in unretiring page
	 *   -1, errno = EIO - page is already unretired
	 *   -1, errno = EAGAIN - page couldn't be locked, still retired
	 *   -1, errno = EINVAL - page fmri is invalid
	 *   -1, errno = any else - error
	 */
	if (rc == 0 || err == EIO || err == EINVAL) {
		if (rc == 0)
			(void) fmd_agent_seterrno(hdl, 0);
		return (FMD_AGENT_RETIRE_DONE);
	}

	return (FMD_AGENT_RETIRE_FAIL);
}

int
fmd_agent_page_isretired(fmd_agent_hdl_t *hdl, nvlist_t *fmri)
{
	int rc = fmd_agent_pageop(hdl, FM_IOC_PAGE_STATUS, fmri);
	int err = fmd_agent_errno(hdl);

	/*
	 * FM_IOC_PAGE_STATUS returns:
	 *   0 - page is retired
	 *   -1, errno = EAGAIN - page is scheduled for retirement
	 *   -1, errno = EIO - page not scheduled for retirement
	 *   -1, errno = EINVAL - page fmri is invalid
	 *   -1, errno = any else - error
	 */
	if (rc == 0 || err == EINVAL) {
		if (rc == 0)
			(void) fmd_agent_seterrno(hdl, 0);
		return (FMD_AGENT_RETIRE_DONE);
	}
	if (err == EAGAIN)
		return (FMD_AGENT_RETIRE_ASYNC);

	return (FMD_AGENT_RETIRE_FAIL);
}
