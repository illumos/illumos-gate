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
 * Copyright 2007 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 * Copyright 2012 Milan Jurik. All rights reserved.
 */

#include <sys/param.h>
#include <string.h>
#include <door.h>
#include <sys/mman.h>
#include "nscd_door.h"
#include "nscd_log.h"
#include <getxby_door.h>
#include <sys/types.h>
#include <errno.h>
#include <fcntl.h>

static void
initdoor(void *buf, int *doorfd)
{
	nss_pheader_t	*phdr = (nss_pheader_t *)buf;
	door_info_t 	doori;
	char		*me = "initdoor";

	*doorfd = open64(NAME_SERVICE_DOOR, O_RDONLY, 0);

	_NSCD_LOG(NSCD_LOG_FRONT_END, NSCD_LOG_LEVEL_DEBUG)
		(me, "door is %s (fd is %d)\n", NAME_SERVICE_DOOR,
		    *doorfd);

	if (*doorfd == -1) {
		NSCD_SET_STATUS(phdr, NSS_ERROR, errno);
		return;
	}

	if (door_info(*doorfd, &doori) < 0 ||
	    (doori.di_attributes & DOOR_REVOKED) ||
	    doori.di_data != (uintptr_t)NAME_SERVICE_DOOR_COOKIE) {

		/*
		 * we should close doorfd because we just opened it
		 */
		(void) close(*doorfd);

		_NSCD_LOG(NSCD_LOG_FRONT_END, NSCD_LOG_LEVEL_DEBUG)
		(me, "door %d not valid\n", *doorfd);

		NSCD_SET_STATUS(phdr, NSS_ERROR, ECONNREFUSED);
		return;
	}

	NSCD_SET_STATUS_SUCCESS(phdr);
}

/* general door call functions used by nscd */

static nss_status_t
copy_output(void *outdata, int outdlen,
	nss_pheader_t *phdr, nss_pheader_t *outphdr)
{
	void		*dp;
	nss_status_t	ret = NSS_SUCCESS;
	char		*me = "copy_output";

	if (outdata != NULL && phdr->data_off > 0 && phdr->data_len > 0) {
		if (phdr->data_len <= outdlen) {
			dp = (char *)phdr + phdr->data_off;
			(void) memmove(outdata, dp, phdr->data_len);
		} else {

			_NSCD_LOG(NSCD_LOG_FRONT_END, NSCD_LOG_LEVEL_DEBUG)
			(me, "output buffer not large enough "
			    " should be > %d but is %d\n",
			    phdr->data_len, outdlen);

			if (outphdr != NULL) {
				NSCD_SET_N2N_STATUS(phdr, NSS_NSCD_PRIV,
				    0, NSCD_INVALID_ARGUMENT);
				NSCD_COPY_STATUS(outphdr, phdr);
			}
			ret = NSS_NSCD_PRIV;
		}
	}

	return (ret);
}

nss_status_t
_nscd_doorcall(int callnum)
{
	size_t		buflen;
	nss_pheader_t	*phdr;
	void		*dptr;
	size_t		ndata;
	size_t		adata;
	int		ret;
	char		*me = "_nscd_doorcall";

	_NSCD_LOG(NSCD_LOG_FRONT_END, NSCD_LOG_LEVEL_DEBUG)
	(me, "processing door call %d ...\n", callnum);

	/* allocate door buffer from the stack */
	NSCD_ALLOC_DOORBUF(callnum, 0, dptr, buflen);
	ndata = buflen;
	adata = buflen;

	ret = _nsc_trydoorcall(&dptr, &ndata, &adata);

	if (ret != NSS_SUCCESS) {
		phdr = (nss_pheader_t *)dptr;
		_NSCD_LOG(NSCD_LOG_FRONT_END, NSCD_LOG_LEVEL_DEBUG)
		(me, "door call (%d) failed (status = %d, error = %s)\n",
		    callnum, ret, strerror(NSCD_GET_ERRNO(phdr)));
	}

	return (ret);
}


nss_status_t
_nscd_doorcall_data(int callnum, void *indata, int indlen,
	void *outdata, int outdlen, nss_pheader_t *phdr)
{
	void		*uptr;
	size_t		buflen;
	void		*dptr;
	void		*datap;
	size_t		ndata;
	size_t		adata;
	nss_pheader_t	*phdr_d;
	int		ret;
	char		*me = "_nscd_doorcall_data";

	_NSCD_LOG(NSCD_LOG_FRONT_END, NSCD_LOG_LEVEL_DEBUG)
	(me, "processing door call %d ...\n", callnum);

	/* allocate door buffer from the stack */
	NSCD_ALLOC_DOORBUF(callnum, indlen, uptr, buflen);
	dptr = uptr;
	ndata = buflen;
	adata = buflen;
	datap = NSCD_N2N_DOOR_DATA(void, dptr);
	if (indata != NULL)
		(void) memmove(datap, indata, indlen);

	ret = _nsc_trydoorcall(&dptr, &ndata, &adata);

	phdr_d = (nss_pheader_t *)dptr;
	if (ret != NSS_SUCCESS) {
		_NSCD_LOG(NSCD_LOG_FRONT_END, NSCD_LOG_LEVEL_DEBUG)
		(me, "door call (%d) failed (status = %d, error = %s)\n",
		    callnum, ret, strerror(NSCD_GET_ERRNO(phdr_d)));
	} else {
		if (phdr != NULL) {
			NSCD_COPY_STATUS(phdr, phdr_d);
		}
		ret = copy_output(outdata, outdlen, phdr_d, phdr);
	}

	/* if new buffer allocated for this door call, free it */
	if (dptr != uptr)
		(void) munmap(dptr, ndata);

	return (ret);
}

nss_status_t
_nscd_doorcall_fd(int fd, int callnum, void *indata, int indlen,
	void *outdata, int outdlen, nss_pheader_t *phdr)
{
	void		*uptr;
	void		*dptr;
	void		*datap;
	size_t		ndata;
	size_t		adata;
	size_t		buflen;
	door_arg_t	param;
	int		ret, errnum;
	nss_pheader_t	*phdr_d;
	char		*me = "_nscd_doorcall_fd";

	_NSCD_LOG(NSCD_LOG_FRONT_END, NSCD_LOG_LEVEL_DEBUG)
	(me, "processing door call %d (fd = %d)...\n", callnum, fd);

	/* allocate door buffer from the stack */
	NSCD_ALLOC_DOORBUF(callnum, indlen, uptr, buflen);
	dptr = uptr;
	ndata = buflen;
	adata = buflen;
	datap = NSCD_N2N_DOOR_DATA(void, dptr);
	if (indata != NULL)
		(void) memmove(datap, indata, indlen);

	param.rbuf = (char *)dptr;
	param.rsize = ndata;
	param.data_ptr = (char *)dptr;
	param.data_size = adata;
	param.desc_ptr = NULL;
	param.desc_num = 0;
	ret = door_call(fd, &param);
	if (ret < 0) {
		errnum = errno;
		/*
		 * door call did not get through, return errno
		 * if requested
		 */
		if (phdr != NULL) {
			NSCD_SET_STATUS(phdr, NSS_ERROR, errnum);
		}

		_NSCD_LOG(NSCD_LOG_FRONT_END, NSCD_LOG_LEVEL_DEBUG)
		(me, "door call (%d to %d) did not get through (%s)\n",
		    callnum, fd, strerror(errnum));

		return (NSS_ERROR);
	}
	ndata = param.rsize;
	dptr = (void *)param.data_ptr;

	/*
	 * door call got through, check if operation failed.
	 * if so, return error info if requested
	 */
	phdr_d = (nss_pheader_t *)dptr;
	ret = NSCD_GET_STATUS(phdr_d);
	if (ret != NSS_SUCCESS) {
		if (phdr != NULL) {
			NSCD_COPY_STATUS(phdr, phdr_d);
		}

		_NSCD_LOG(NSCD_LOG_FRONT_END, NSCD_LOG_LEVEL_DEBUG)
		(me, "door call (%d to %d) failed: p_status = %d, "
		    "p_errno = %s, nscd status = %d\n", callnum, fd,
		    ret, strerror(NSCD_GET_ERRNO(phdr_d)),
		    NSCD_GET_NSCD_STATUS(phdr_d));
	} else
		ret = copy_output(outdata, outdlen, phdr_d, phdr);

	/* if new buffer allocated for this door call, free it */
	if (dptr != uptr)
		(void) munmap(dptr, param.rsize);


	return (ret);
}

static void
send_doorfd(void **dptr, size_t *ndata, size_t *adata,
	door_desc_t *pdesc)
{
	nss_pheader_t	*phdr = (nss_pheader_t *)*dptr;
	door_arg_t	param;
	int		ret;
	int		doorfd;
	int		errnum;
	char		*me = "send_doorfd";

	initdoor(*dptr, &doorfd);
	if (NSCD_STATUS_IS_NOT_OK(phdr))
		return;

	param.rbuf = (char *)*dptr;
	param.rsize = *ndata;
	param.data_ptr = (char *)*dptr;
	param.data_size = *adata;
	param.desc_ptr = pdesc;
	param.desc_num = 1;
	ret = door_call(doorfd, &param);
	if (ret < 0) {
		errnum = errno;

		_NSCD_LOG(NSCD_LOG_FRONT_END, NSCD_LOG_LEVEL_DEBUG)
		(me, "door call (to fd %d) failed (%s)\n",
		    doorfd, strerror(errnum));
		(void) close(doorfd);
		NSCD_SET_STATUS(phdr, NSS_ERROR, errnum);
		return;
	}
	*adata = param.data_size;
	*ndata = param.rsize;
	*dptr = (void *)param.data_ptr;

	if (*adata == 0 || *dptr == NULL) {
		_NSCD_LOG(NSCD_LOG_FRONT_END, NSCD_LOG_LEVEL_DEBUG)
		(me, "no data\n");

		NSCD_SET_STATUS(phdr, NSS_ERROR, ENOTCONN);
	}

	(void) close(doorfd);
}

nss_status_t
_nscd_doorcall_sendfd(int fd, int callnum, void *indata, int indlen,
	nss_pheader_t *phdr)
{
	void		*uptr;
	void		*dptr;
	void		*datap;
	size_t		ndata;
	size_t		adata;
	size_t		buflen;
	nss_pheader_t	*phdr_d;
	door_desc_t	desc;
	char		*me = "_nscd_doorcall_sendfd";

	_NSCD_LOG(NSCD_LOG_FRONT_END, NSCD_LOG_LEVEL_DEBUG)
	(me, "processing door call %d (fd = %d)...\n", callnum, fd);

	/* allocate door buffer from the stack */
	NSCD_ALLOC_DOORBUF(callnum, indlen, uptr, buflen);
	dptr = uptr;
	ndata = buflen;
	adata = buflen;
	datap = NSCD_N2N_DOOR_DATA(void, dptr);
	if (indata != NULL)
		(void) memmove(datap, indata, indlen);
	desc.d_attributes = DOOR_DESCRIPTOR;
	desc.d_data.d_desc.d_descriptor = fd;

	send_doorfd(&dptr, &ndata, &adata, &desc);

	phdr_d = (nss_pheader_t *)dptr;
	if (NSCD_STATUS_IS_NOT_OK(phdr_d)) {
		if (phdr != NULL)
			*phdr = *phdr_d;

		_NSCD_LOG(NSCD_LOG_FRONT_END, NSCD_LOG_LEVEL_DEBUG)
		(me, "door call (%d) failed (status = %d, error = %s)\n",
		    callnum, NSCD_GET_STATUS(phdr_d),
		    strerror(NSCD_GET_ERRNO(phdr_d)));
	}

	return (NSCD_GET_STATUS(phdr_d));
}
