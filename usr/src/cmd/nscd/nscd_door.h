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

#ifndef	_NSCD_DOOR_H
#define	_NSCD_DOOR_H

/*
 * Definitions for nscd to nscd door interfaces
 */

#ifdef	__cplusplus
extern "C" {
#endif

#include <alloca.h>
#include <nss_dbdefs.h>

/* door for Trusted Extensions */
#define	TSOL_NAME_SERVICE_DOOR	"/var/tsol/doors/name_service_door"
/* TX per label nscd indication file */
#define	TSOL_NSCD_PER_LABEL_FILE "/var/tsol/doors/nscd_per_label"

/* nscd v2 nscd -> nscd call numbers */
#define	NSCD_PING	(NSCD_CALLCAT_N2N|0x01)
#define	NSCD_GETADMIN	(NSCD_CALLCAT_N2N|0x02)
#define	NSCD_SETADMIN	(NSCD_CALLCAT_N2N|0x03)
#define	NSCD_GETPUADMIN	(NSCD_CALLCAT_N2N|0x04)
#define	NSCD_SETPUADMIN	(NSCD_CALLCAT_N2N|0x05)
#define	NSCD_KILLSERVER	(NSCD_CALLCAT_N2N|0x06)

#define	NSCD_IMHERE	(NSCD_CALLCAT_N2N|0x10)	/* IMHERE+WHOAMI */
#define	NSCD_FORK	(NSCD_CALLCAT_N2N|0x20)
#define	NSCD_SETUID	(NSCD_CALLCAT_N2N|0x30)
#define	NSCD_KILL	(NSCD_CALLCAT_N2N|0x40)
#define	NSCD_PULSE	(NSCD_CALLCAT_N2N|0x50)
#define	NSCD_REFRESH	(NSCD_CALLCAT_N2N|0x60)

/* nscd v2 nscd identities */

#define	NSCD_MAIN	0x00000001
#define	NSCD_FORKER	0x00000002
#define	NSCD_CHILD	0x00000004
#define	NSCD_WHOAMI	0x0000000F

#define	NSCD_ALLOC_DOORBUF(cn, dsz, uptr, usz) \
	usz = (sizeof (nss_pheader_t) + (dsz)); \
	uptr = alloca(usz); \
	(void) memset(uptr, 0, usz); \
	((nss_pheader_t *)uptr)->nsc_callnumber = (cn); \
	((nss_pheader_t *)uptr)->p_version = NSCD_HEADER_REV; \
	((nss_pheader_t *)uptr)->pbufsiz = usz; \
	((nss_pheader_t *)uptr)->data_off = sizeof (nss_pheader_t); \
	((nss_pheader_t *)uptr)->key_off = sizeof (nss_pheader_t); \
	((nss_pheader_t *)uptr)->dbd_off = sizeof (nss_pheader_t); \
	((nss_pheader_t *)uptr)->data_len = dsz;

#define	NSCD_N2N_DOOR_DATA(type, buf) \
	(type *)((void *)(((char *)(buf)) + sizeof (nss_pheader_t)))

#define	NSCD_N2N_DOOR_BUF_SIZE(struct) \
	sizeof (nss_pheader_t) + sizeof (struct)

#define	NSCD_SET_STATUS(ph, st, errno) \
	{ \
		int	e = errno; \
		(ph)->p_status = st; \
		if (e != -1) \
			(ph)->p_errno = e; \
	}

#define	NSCD_SET_HERRNO(ph, herrno) \
	(ph)->p_herrno = herrno;


#define	NSCD_SET_STATUS_SUCCESS(ph) \
	(ph)->p_status = NSS_SUCCESS; \
	(ph)->p_errno = 0;

#define	NSCD_SET_N2N_STATUS(ph, st, errno, n2nst) \
	{ \
		int	e = errno; \
		(ph)->p_status = st; \
		if (e != -1) \
			(ph)->p_errno = e; \
		(ph)->nscdpriv = n2nst; \
	}

#define	NSCD_STATUS_IS_OK(ph) \
	(((ph)->p_status) == NSS_SUCCESS)

#define	NSCD_STATUS_IS_NOT_OK(ph) \
	(((ph)->p_status) != NSS_SUCCESS)

#define	NSCD_GET_STATUS(ph) \
	(((nss_pheader_t *)(ph))->p_status)

#define	NSCD_GET_ERRNO(ph) \
	(((nss_pheader_t *)(ph))->p_errno)

#define	NSCD_GET_HERRNO(ph) \
	(((nss_pheader_t *)(ph))->p_herrno)

#define	NSCD_GET_NSCD_STATUS(ph) \
	(((nss_pheader_t *)(ph))->nscdpriv)

#define	NSCD_CLEAR_STATUS(ph) \
	(ph)->p_status = 0; \
	(ph)->p_errno = 0; \
	(ph)->nscdpriv = 0;

#define	NSCD_COPY_STATUS(ph, ph1) \
	(ph)->p_status = (ph1)->p_status; \
	(ph)->p_errno = (ph1)->p_errno; \
	(ph)->nscdpriv = (ph1)->nscdpriv;

nss_status_t	_nscd_doorcall(int callnum);
nss_status_t 	_nscd_doorcall_data(int callnum, void *indata,
			int indlen, void *outdata, int outdlen,
			nss_pheader_t *phdr);

nss_status_t	 _nscd_doorcall_fd(int fd, int callnum, void *indata,
			int indlen, void *outdata, int outdlen,
			nss_pheader_t *phdr);

nss_status_t	_nscd_doorcall_sendfd(int fd, int callnum,
			void *indata, int indlen, nss_pheader_t *phdr);

#ifdef	__cplusplus
}
#endif

#endif	/* _NSCD_DOOR_H */
