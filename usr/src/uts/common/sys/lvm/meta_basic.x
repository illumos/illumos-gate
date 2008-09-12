%/*
% * CDDL HEADER START
% *
% * The contents of this file are subject to the terms of the
% * Common Development and Distribution License (the "License").
% * You may not use this file except in compliance with the License.
% *
% * You can obtain a copy of the license at usr/src/OPENSOLARIS.LICENSE
% * or http://www.opensolaris.org/os/licensing.
% * See the License for the specific language governing permissions
% * and limitations under the License.
% *
% * When distributing Covered Code, include this CDDL HEADER in each
% * file and include the License file at usr/src/OPENSOLARIS.LICENSE.
% * If applicable, add the following below this CDDL HEADER, with the
% * fields enclosed by brackets "[]" replaced with your own identifying
% * information: Portions Copyright [yyyy] [name of copyright owner]
% *
% * CDDL HEADER END
% */
%
%/*
% * Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
% * Use is subject to license terms.
% */
%

%/* get timeval32 definition */
%#include <sys/types32.h>

#ifndef _KERNEL
%#ifdef _KERNEL
%#error "Compiling kernel file rpcgened without _KERNEL define."
%#endif /* _KERNEL */
#endif /* _KERNEL */
%#include <sys/dditypes.h>

#ifdef RPC_XDR
#ifndef _KERNEL
%bool_t
%xdr_uint_t(XDR *xdrs, uint_t *objp)
%{
%	if (!xdr_u_int(xdrs, (u_int *)objp))
%		return (FALSE);
%	return (TRUE);
%}
%bool_t
%xdr_ushort_t(XDR *xdrs, ushort_t *objp)
%{
%	if (!xdr_u_short(xdrs, (u_short *)objp))
%		return (FALSE);
%	return (TRUE);
%}
%bool_t
%xdr_dev_t(XDR *xdrs, dev_t *objp)
%{
%	if (!xdr_u_int(xdrs, (u_int *)objp))
%		return (FALSE);
%	return (TRUE);
%}
%bool_t
%xdr_dev32_t(XDR *xdrs, dev32_t *objp)
%{
%	if (!xdr_u_int(xdrs, (u_int *)objp))
%		return (FALSE);
%	return (TRUE);
%}
%bool_t
%xdr_md_dev64_t(XDR *xdrs, md_dev64_t *objp)
%{
%	if (!xdr_u_longlong_t(xdrs, objp))
%		return (FALSE);
%	return (TRUE);
%}
%bool_t
%xdr_size_t(XDR *xdrs, size_t *objp)
%{
%	if (!xdr_u_int(xdrs, (u_int *) objp))
%		return (FALSE);
%	return (TRUE);
%}
%bool_t
%xdr_daddr_t(XDR *xdrs, daddr_t *objp)
%{
%	if (!xdr_int(xdrs, (int *) objp))
%		return (FALSE);
%	return (TRUE);
%}
%bool_t
%xdr_daddr32_t(XDR *xdrs, daddr32_t *objp)
%{
%	if (!xdr_int(xdrs, (int *) objp))
%		return (FALSE);
%	return (TRUE);
%}
%bool_t
%xdr_diskaddr_t(XDR *xdrs, diskaddr_t *objp)
%{
%	if (!xdr_u_longlong_t(xdrs, objp))
%		return (FALSE);
%	return (TRUE);
%}
%bool_t
%xdr_ddi_devid_t(XDR *xdrs, ddi_devid_t *objp)
%{
%	/* device ids not supported for non-local sets */
%	return (TRUE);
%}
%bool_t
%xdr_off_t(XDR *xdrs, off_t *objp)
%{
%	if (!xdr_int(xdrs, (int *) objp))
%		return (FALSE);
%	return (TRUE);
%}
%bool_t
%xdr_timeval(XDR *xdrs, struct timeval *objp)
%{
%	if (!xdr_int(xdrs, (int *)&objp->tv_sec))
%		return (FALSE);
%	if (!xdr_int(xdrs, (int *)&objp->tv_usec))
%		return (FALSE);
%	return (TRUE);
%}
%
%bool_t
%xdr_md_timeval32_t(XDR *xdrs, md_timeval32_t *objp)
%{
%	if (!xdr_int(xdrs, &objp->tv_sec))
%		return (FALSE);
%	if (!xdr_int(xdrs, &objp->tv_usec))
%		return (FALSE);
%	return (TRUE);
%}
%
#else /* _KERNEL */
%#ifdef _LP64
%bool_t
%xdr_timeval(XDR *xdrs, struct timeval *objp)
%{
%	struct timeval32 tv32;
%	if (xdrs->x_op == XDR_ENCODE)
%		TIMEVAL_TO_TIMEVAL32(&tv32, objp);
%	if (!xdr_int(xdrs, &tv32.tv_sec))
%		return (FALSE);
%	if (!xdr_int(xdrs, &tv32.tv_usec))
%		return (FALSE);
%	if (xdrs->x_op == XDR_DECODE)
%		TIMEVAL32_TO_TIMEVAL(objp, &tv32);
%	return (TRUE);
%}
%#else /* !_LP64 */
%bool_t
%xdr_timeval(XDR *xdrs, struct timeval *objp)
%{
%	if (!xdr_int(xdrs, (int *)&objp->tv_sec))
%		return (FALSE);
%	if (!xdr_int(xdrs, (int *)&objp->tv_usec))
%		return (FALSE);
%	return (TRUE);
%}
%#endif /* _LP64 */
#endif /* !_KERNEL */
%
%bool_t
%xdr_minor_t(XDR *xdrs, minor_t *objp)
%{
%	if (!xdr_u_int(xdrs, (u_int *)objp))
%		return (FALSE);
%	return (TRUE);
%}
%
%bool_t
%xdr_clnt_stat(XDR *xdrs, enum clnt_stat *objp)
%{
%	if (!xdr_enum(xdrs, (enum_t *)objp))
%		return (FALSE);
%	return (TRUE);
%}
%
#ifdef	_KERNEL
%
%#define	LASTUNSIGNED	((u_int)0-1)
%
%/*
% * xdr_vector():
% *
% * XDR a fixed length array. Unlike variable-length arrays,
% * the storage of fixed length arrays is static and unfreeable.
% * > basep: base of the array
% * > size: size of the array
% * > elemsize: size of each element
% * > xdr_elem: routine to XDR each element
% */
%bool_t
%xdr_vector(xdrs, basep, nelem, elemsize, xdr_elem)
%	XDR *xdrs;
%	char *basep;
%	u_int nelem;
%	u_int elemsize;
%	xdrproc_t xdr_elem;
%{
%	u_int i;
%	char *elptr;
%
%	elptr = basep;
%	for (i = 0; i < nelem; i++) {
%		if (! (*xdr_elem)(xdrs, elptr, LASTUNSIGNED)) {
%			return (FALSE);
%		}
%		elptr += elemsize;
%	}
%	return (TRUE);
%}
#endif /* _KERNEL */
#endif	/* RPC_XDR */

#ifdef RPC_HDR
%
%/*
% * Some constants
% */
const	MD_MAX_SETNAME = 50;
const	MD_MAX_NODENAME = 63;
const	MAX_HOST_ADDRS	= 3;
const	MD_MAX_MNNODENAME = 256;

const	MED_MAX_HOSTS	= 3;
const	MED_DEF_HOSTS	= 3;

const	MD_MAXSIDES = 8;
const	MD_LOCAL_SET = 0;

const	MD_MNMAXSIDES = 128;
const	MDDB_SN_LEN = 12;
const	MDDB_MINOR_NAME_MAX = 32;
const	MD_MAXDRVNM = 16;

const	MD_MAX_BLKS_FOR_SMALL_DEVS = 2147483647;
%#define	MD_MAX_BLKS_FOR_EXTVTOC	4294967295ULL
%
%/* Minimum number of metadevice database replicas needed */
const	MD_MINREPLICAS = 1;

%#define	MD_MAX_SETNAME_PLUS_1	(MD_MAX_SETNAME + 1)
%#define	MD_MAX_NODENAME_PLUS_1	(MD_MAX_NODENAME + 1)
%#define	MD_MAX_MNNODENAME_PLUS_1	(MD_MAX_MNNODENAME + 1)
%
%#define	MD_SET_BAD	((set_t)~0UL)
%
%#define	MD_LOCAL_NAME	""
%
%#define	MD_SIDEWILD	((side_t)~0UL)
%
%#define	MD_KEYWILD	((mdkey_t)0)
%#define	MD_KEYBAD	((mdkey_t)~0UL)
%#define	MD_UNITBAD	((unit_t)~0UL)
%#define	MD_HSPID_WILD	((hsp_t)~0UL)

%/* Maximum length of a metadevice name */
%#define	MD_MAX_SIDENAME_LEN	(MD_MAXDRVNM + MD_MAX_SETNAME + 2)
%
%/*
% * dev_t is 64 bit now across userland and kernel. Whereever 32 bit value
% * is specifically needed, dev32_t will be used. Internally dev_t is used.
% * timeval is always 32 bit across userland and kernel.
% */
%typedef u_longlong_t		md_dev64_t;
%typedef struct timeval32	md_timeval32_t;
%
%/*
% * The following definitions are not available, when operating in
% * a 32 bit environment. As we are always dealing with
% * 64 bit devices, md_dev64_t, we need those definitions also in
% * a 32 bit environment
% */
%#ifndef	NBITSMAJOR64
%#define	NBITSMAJOR64	32	/* # of major device bits in 64-bit Solaris */
%#endif	/* NBITSMAJOR64 */
%
%#ifndef	NBITSMINOR64
%#define	NBITSMINOR64	32	/* # of minor device bits in 64-bit Solaris */
%#endif	/* NBITSMINOR64 */
%
%#ifndef	MAXMAJ64
%#define	MAXMAJ64	0xfffffffful	/* max major value */
%#endif	/* MAXMAJ64 */
%
%#ifndef	MAXMIN64
%#define	MAXMIN64	0xfffffffful	/* max minor value */
%#endif	/* MAXMIN64 */
%
%#ifndef	NODEV64
%#define	NODEV64		0xffffffffffffffffuLL
%#endif	/* NODEV64 */
%
%#ifndef	NODEV32
%#define	NODEV32		0xffffffffuL
%#endif	/* NODEV32 */
%
%#ifndef	MD_DISKADDR_ERROR
%#define	MD_DISKADDR_ERROR	0xffffffffffffffffuLL
%#endif /* MD_DISKADDR_ERROR */

#endif	/* RPC_HDR */

#if defined(RPC_HDR) || defined(RPC_XDR)
%
%/* namespace key */
typedef	int	mdkey_t;

%
%/* set ID */
typedef	u_int	set_t;	

%
%/* record ID type */
typedef int		mddb_recid_t;

%
%/* side ID */
typedef	u_int		side_t;	

%
%/* Multi-node node ID */
typedef uint32_t	md_mn_nodeid_t;

%
%/* Shared definitions */
#include	"meta_arr.x"

#endif	/* defined(RPC_HDR) || defined(RPC_XDR) */

#ifdef RPC_HDR
%
%#if defined(__STDC__) || defined(__cplusplus)
#ifndef _KERNEL
%extern	bool_t	xdr_uint_t(XDR *xdrs, uint_t *objp);
%extern	bool_t	xdr_ushort_t(XDR *xdrs, ushort_t *objp);
%extern	bool_t	xdr_dev_t(XDR *xdrs, dev_t *objp);
%extern	bool_t	xdr_dev32_t(XDR *xdrs, dev32_t *objp);
%extern	bool_t	xdr_md_dev64_t(XDR *xdrs, md_dev64_t *objp);
%extern	bool_t	xdr_size_t(XDR *xdrs, size_t *objp);
%extern	bool_t	xdr_daddr_t(XDR *xdrs, daddr_t *objp);
%extern	bool_t	xdr_daddr32_t(XDR *xdrs, daddr32_t *objp);
%extern	bool_t	xdr_diskaddr_t(XDR *xdrs, diskaddr_t *objp);
%extern	bool_t	xdr_ddi_devid_t(XDR *xdrs, ddi_devid_t *objp);
%extern	bool_t	xdr_off_t(XDR *xdrs, off_t *objp);
%extern bool_t  xdr_md_timeval32_t(XDR *xdrs, md_timeval32_t *objp);
#endif /* !_KERNEL */
%extern	bool_t	xdr_minor_t(XDR *xdrs, minor_t *objp);
%extern	bool_t	xdr_timeval(XDR *xdrs, struct timeval *objp);
%extern	bool_t	xdr_clnt_stat(XDR *xdrs, enum clnt_stat *objp);
#ifdef _KERNEL
%extern bool_t	xdr_vector(XDR *xdrs, char *basep,
%			u_int nelem, u_int elemsize,
%			xdrproc_t xdr_elem);
#endif	/* _KERNEL */
%#else /* K&R C */
#ifndef _KERNEL
%extern	bool_t	xdr_uint_t();
%extern	bool_t	xdr_ushort_t();
%extern	bool_t	xdr_dev_t();
%extern	bool_t	xdr_dev32_t();
%extern	bool_t	xdr_md_dev64_t();
%extern	bool_t	xdr_size_t();
%extern	bool_t	xdr_daddr_t();
%extern	bool_t	xdr_daddr32_t();
%extern	bool_t	xdr_diskaddr_t();
%extern	bool_t	xdr_ddi_devid_t();
%extern	bool_t	xdr_off_t();
%extern bool_t  xdr_md_timeval32_t();
#endif /* !_KERNEL */
%extern	bool_t	xdr_minor_t();
%extern	bool_t	xdr_timeval();
%extern	bool_t	xdr_clnt_stat();
%
#ifdef _KERNEL
%extern bool_t	xdr_vector();
#endif	/* _KERNEL */
%#endif /* K&R C */
#endif	/* RPC_HDR */
