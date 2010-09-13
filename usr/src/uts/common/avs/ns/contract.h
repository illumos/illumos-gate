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
 * Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*
 * The sole purpose of this file is to document our violations of the DDI
 * in Solaris and to get ddict to run on the data services stack.
 * Definitions and declarations contained in this file are never compiled
 * into the code.  It is only included if we are running ddict on our src.
 *
 * IMPORTANT NOTE:
 * Many of the declarations are not correct. It does not matter.
 * Structure declarations only define the fields we require.
 * Structures which we use in an opaque manner are defined as void *
 */

#ifndef	_SYS_CONTRACT_H
#define	_SYS_CONTRACT_H

#ifdef	__cplusplus
extern "C" {
#endif

/*
 * Define our interfaces for nsctl because ddict is stupid
 * about intermodule dependencies
 */
#include <sys/nsctl/nsctl_inter.h>

/*
 * Define our ncall interfaces
 */
#include <sys/nsctl/ncall_inter.h>

/*
 * The STRUCT_DECL definitions in the ddict headers are fouled up
 * we include our own model.h here to redefine it to avoid errors.
 */
#if !defined(_SunOS_5_6)
#include <sys/nsctl/model.h>
#endif

/*
 * General violations
 * Everybody violates these
 * Why are they called ddi if it is not part of it?
 */

#define	DDI_PROP_NOTPROM 0

int ddi_rele_driver(void) { }
int ddi_hold_installed_driver(void) { }

/*
 * SV module violations
 */
void *curthread;
int devcnt;

/*
 * The following from vnode.h
 */
typedef struct  vode {
	int v_lock;	/* SDBC uses this too */
	int v_type;	/* nskern too */
	int v_rdev;	/* nskern too */
} vnode_t;

#define	FOLLOW 0
#define	NULLVPP NULL
#define	AT_RDEV 0
#define	VOP_GETATTR(vp, vap, f, cr) ((void)0)
#define	VN_RELE(vp) ((void)0)

/*
 *  The fields we use from vattr_t
 */
typedef struct vattr {
	uint_t	va_mask;
	dev_t	va_rdev;
	int	va_size;	/* nskern */
} vattr_t;

int lookupname(void, void, void, void, void) { }

/*
 * End of SV module violations
 */

/*
 * DSW/II module violations
 */

/*
 * This is really bogus that ddict does not understand sys/inttypes.h
 */
#define	INT32_MIN	0
#define	INT32_MAX	0
#define	INT64_MAX	0

/*
 * End of DSW/II module violations
 */

/*
 * UNISTAT module violations
 */

void mod_miscops;
typedef enum { B_FALSE, B_TRUE } boolean_t;

/*
 * End of UNISTAT module violations
 */

/*
 * NSCTL module violations
 */
#define	ERESTART 0
#define	EUSERS 0
#define	ENAMETOOLONG 0
#define	ENOSYS	0
#define	FOPEN	0
int ddi_name_to_major() { }
/*
 * End of NSCTL module violations
 */

/*
 * NSKERN module violations
 */
#define	UL_GETFSIZE	0
#define	USHRT_MAX	0

typedef	u_longlong_t	rlim64_t;
int ulimit() { }
int maxphys;

#define	AT_SIZE	0
#define	VBLK	0
#define	VCHR	0
#define	VREG	0
#define	VLNK	0

#define	VOP_CLOSE(vp, f, c, o, cr)	((void)0)
#define	VOP_RWLOCK(vp, w)	((void)0)
#define	VOP_RWUNLOCK(vp, w)	((void)0)
#define	VOP_READ(vp, uiop, iof, cr)	((void)0)
#define	VOP_WRITE(vp, uiop, iof, cr)	((void)0)

int vn_open(char *pnamep, void seg, int filemode, int createmode,
		struct vnode **vpp, void crwhy, mode_t umask) { }

/*
 * End of NSKERN module violations
 */

/*
 * NVRAM module violations
 */
#define	MMU_PAGESIZE	0

#ifndef MAXNAMELEN
#define	MAXNAMELEN	1
#endif

#define	DEVMAP_DEFAULTS 0
#define	PFN_INVALID	-1

char hw_serial[1];
int mmu_ptob(void arg) { }
int roundup(void arg) { }

/*
 * End of NVRAM module violations
 */

/*
 * RDCSVR (SNDR) module
 * Contract PSARC 2001/699
 */
#define	DUP_DONE	0
#define	DUP_ERROR	0
#define	DUP_INPROGRESS	0
#define	DUP_NEW		0
#define	DUP_DROP	0

#define	RPC_MAXDATASIZE	0


typedef void * file_t;		/* opaque */
typedef	void SVCXPRT;		/* opaque */
typedef	void SVCMASTERXPRT;	/* opaque */
typedef void xdrproc_t;		/* opaque */
typedef int enum_t;

typedef struct svc_req {	/* required fields */
	int rq_vers;
	int rq_proc;
} svc_req_t;

void SVC_FREEARGS(void xprt, void a, void *b) { }
void SVC_DUP(void xprt, void req, void i, void j, void *dr) { }
void svcerr_systemerr(void xprt) { }
void svcerr_noproc(void xprt) { }
void SVC_DUPDONE(void xprt, void dr, void a, void b, void c) { }

SVCXPRT *svc_tli_kcreate(void *f, void *n, void *b, void **x, void *t,
	uint_t c, uint_t d) { }

/*
 * non-ddi not under contracts
 */
struct netbuf {
	int	maxlen;
	int	len;
	char	*buf;
}

/*
 * End of RDCSRV module Contracts
 */

/*
 * RDC (SNDR) module
 * Contract PSARC 2001/699
 */

typedef	u_longlong_t	rpcproc_t;
typedef	u_longlong_t	xdrproc_t;
typedef	u_longlong_t	rpcvers_t;
#define	__dontcare__    -1
#define	RPC_INTR 0
#define	RPC_SUCCESS	0
#define	RPC_TLIERROR	0
#define	RPC_XPRTFAILED	0
#define	RPC_VERSMISMATCH	0
#define	RPC_PROGVERSMISMATCH 0
#define	RPC_INPROGRESS	0

#define	ENOEXEC	0
#define	EBADF	0

/*
 * XDR routines
 * from rpc/xdr.h
 */
typedef	void * XDR;	/* opaque */
int xdr_void() { }
int xdr_int() { }
int xdr_union() { }
int xdr_enum() { }
int xdr_u_int() { }
int xdr_u_longlong_t() { }
int xdr_opaque() { }
int xdr_bytes() { }
int xdr_array() { }
#define	NULL_xdrproc_t ((xdrproc_t)0)

/*
 * The following imported rpc/clnt.h
 */

/* Client is mostly opaque exccept for the following */

typedef struct __client {	/* required fields */
	void *cl_auth;
	bool_t cl_nosignal;
} CLIENT;

#define	CLSET_PROGRESS	0
#define	KNC_STRSIZE	128
struct knetconfig {
	unsigned int	knc_semantics;
	caddr_t		knc_protofmly;
	caddr_t		knc_proto;
	dev_t		knc_rdev;
};

void *clnt_sperrno() { }
void IS_UNRECOVERABLE_RPC(a) { }
void CLNT_CONTROL(cl, request, info) { }
void AUTH_DESTROY(void *a) { }
void CLNT_DESTROY(void *a) { }

int clnt_tli_kcreate(void *a, void *b, void c, void d, void e, void f,
	void *g, void **h) { }

int clnt_tli_kinit(void *h, void *config, void *addr, uint_t a, int b,
	void *c) { }

void	 CLNT_CALL(void, void, void, void, void, void, void) { }

/*
 * The following imported from rpc/svc.h
 */
void svc_sendreply() { }
void svcerr_decode() { }
void SVC_GETARGS() { }

/*
 * The following imported from sys/file.h
 */

void getf(void) { }
void releasef(void) { }

/*
 * Not under contract
 */
void sigintr(void) { }
void sigunintr(void) { }
dev_t expldev() { }

/*
 * End of RDC module
 */

/*
 * SDBC module violations
 */

/*
 *  devid uses internal structure
 *  from sys/ddi_impldefs.h
 */
typedef struct impl_devid {
	uchar_t did_type_hi;
	uchar_t did_type_lo;
} impl_devid_t;

#define	DEVID_GETTYPE(devid)  0
#define	DEVID_SCSI_SERIAL 0

#define	ENOLINK	0	/* NCALL too */
#define	E2BIG	0
#define	ENOENT 0
#define	EIDRM 0

#define	B_KERNBUF 0
#define	KSTAT_TYPE_RAW 0
#define	MAXPATHLEN 0

#define	VN_HOLD(bp) ((void)0)

/* Page list IO stuff */
typedef struct page {
	int v_count;	/* sdbc */
} page_t;
page_t kvp;		/* We use the kernel segment */
int page_add(void) { }
int page_find(void) { }
int page_list_concat(void) { }
int pageio_setup(void) { }
int pageio_done(void) { }

void kobj_getsymvalue(void) { }
int ddi_dev_pathname(void) { }

/*
 * HACK ALERT
 * struct buf hack for ddict.
 * SDBC currently violates in struct buf
 * 	b_pages
 *	b_proc
 * which we will define as the pad fields for ddict since
 * we can not overload the definition of struct buf with our own stuff.
 */

#define	b_pages	b_pad7	/* b_pages in struct buf */
#define	b_proc	b_pad8	/* b_proc in struct buf */
#define	b_forw	b_pad1	/* b_forw in struct buf */
#define	b_back	b_pad2	/* b_back in struct buf */

/*
 * End of SDBC moduel violations
 */

/*
 * SCMTEST module violations
 */

#define	ESRCH	0	/* NCALL too */

/*
 * End of SCMTEST module violations
 */
/*
 * SFTM module violations
 * Note: XXX This list is currently incomplete
 */

typedef void * cqe_t;			/* opaque */
typedef void * fcal_packet_t;		/* opaque */
typedef void * soc_response_t;		/* opaque */
typedef void * la_els_logi_t;		/* opaque */
typedef void * la_els_adisc_t;		/* opaque */
typedef void * fcp_rsp_t;		/* opaque */
typedef void * soc_request_t;		/* opaque */
typedef void * els_payload_t;		/* opaque */
typedef void * la_els_logo_t;		/* opaque */
typedef void * fc_frame_header_t;	/* opaque */

typedef struct la_els_prli_s {
	uchar_t		ls_code;
	uchar_t		page_length;
	ushort_t	payload_length;
	uchar_t		service_params[1];
} la_els_prli_t;

typedef	la_els_prli_t la_els_prli_reply_t;
typedef la_els_prli_t la_els_prlo_t;
typedef	la_els_prli_t la_els_prlo_reply_t;

/*
 * The following from /usr/include/sys/fc4/fcp.h
 */
typedef struct fcp_cntl {
	uchar_t	cntl_reserved_1	: 5,
		cntl_qtype	: 3;
	uchar_t	cntl_kill_tsk	: 1,
		cntl_clr_aca	: 1,
		cntl_reset	: 1,
		cntl_reserved_2	: 2,
		cntl_clr_tsk	: 1,
		cntl_abort_tsk	: 1,
		cntl_reserved_3	: 1;
	uchar_t	cntl_reserved_4	: 6,
		cntl_read_data	: 1,
		cntl_write_data	: 1;
} fcp_cntl_t;

typedef struct fcp_ent_addr {
	ushort_t ent_addr_0;
	ushort_t ent_addr_1;
	ushort_t ent_addr_2;
	ushort_t ent_addr_3;
} fcp_ent_addr_t;

typedef struct fcp_cmd_s {
	fcp_ent_addr_t	fcp_ent_addr;
	fcp_cntl_t	fcp_cntl;
	uchar_t		fcp_cdb[1];
	int		fcp_data_len;
} fcp_cmd_t;

typedef struct fcal_transport {
	uchar_t dummy1;
	uchar_t dummy2;
} fcal_transport_t;

/*
 * End of SFTM module violations
 */

/*
 * STE module violations
 */

typedef void  la_wwn_t;		/* opaque */
/* WWN formats from sys/fcal/fcal_linkapp.h */
typedef union la_wwn {
	uchar_t		raw_wwn[8];
	struct {
		uint_t	naa_id : 4;
		uint_t	nport_id : 12;
		uint_t	wwn_hi : 16;
		uint_t	wwn_lo;
	} w;
} la_wwn_t;

insque(void) { }
remque(void) { }
snprintf(void) { }

/*
 * STE uses inq_serial and inq_ackqreqq from struct scsi_inquiry
 */
#define	inq_serial	inq_pid
#define	inq_ackqreqq	inq_pid
/*
 * End of STE module violations
 */

/*
 * NCALL module violations
 */
#define	ENONET	0

/* NCALLSRV */
typedef int bool_t;

/* NCALLIP */
#ifndef TRUE
#define	TRUE	1
#endif

#ifndef FALSE
#define	FALSE	0
#endif

#define	ERANGE	0
#define	ENODATA	0

#define	RPC_TIMEDOUT 0

/*
 * End of NCALL violations
 */
#ifdef	__cplusplus
}
#endif

#endif /* _SYS_CONTRACT_H */
