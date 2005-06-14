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
 * Copyright (c) 2001 by Sun Microsystems, Inc.
 * All rights reserved.
 */

#ifndef _DHCP_SVC_PUBLIC_H
#define	_DHCP_SVC_PUBLIC_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * Contains published interfaces to the DHCP data service.
 */

#ifdef	__cplusplus
extern "C" {
#endif

#include <sys/types.h>
#include <netinet/in.h>			/* struct in_addr */
#include <netinet/dhcp.h>

#define	DSVC_PUBLIC_VERSION	1	/* version of public layer interface */

/*
 * Errors which can be returned from the defined API
 * Note: must be kept in sync with errmsgs[] in private/errmsgs.c.
 */
#define	DSVC_SUCCESS		0	/* success */
#define	DSVC_EXISTS		1	/* object already exists */
#define	DSVC_ACCESS		2	/* access denied */
#define	DSVC_NO_CRED		3	/* no underlying credential */
#define	DSVC_NOENT		4	/* object doesn't exist */
#define	DSVC_BUSY		5	/* object temporarily busy (again) */
#define	DSVC_INVAL		6	/* invalid argument(s) */
#define	DSVC_INTERNAL		7	/* internal data store error */
#define	DSVC_UNAVAILABLE	8	/* underlying service required by */
					/* public module unavailable */
#define	DSVC_COLLISION		9	/* update collision */
#define	DSVC_UNSUPPORTED	10	/* operation not supported */
#define	DSVC_NO_MEMORY		11	/* operation ran out of memory */
#define	DSVC_NO_RESOURCES	12	/* non-memory resources unavailable */
#define	DSVC_BAD_RESOURCE	13	/* malformed/missing RESOURCE setting */
#define	DSVC_BAD_PATH		14	/* malformed/missing PATH setting */
#define	DSVC_MODULE_VERSION	15	/* public layer version mismatch */
#define	DSVC_MODULE_ERR		16	/* internal public module error */
#define	DSVC_MODULE_LOAD_ERR	17	/* error loading public module */
#define	DSVC_MODULE_UNLOAD_ERR	18	/* error unloading public module */
#define	DSVC_MODULE_CFG_ERR	19	/* Module configuration failure */
#define	DSVC_SYNCH_ERR		20	/* error in synchronization protocol */
#define	DSVC_NO_LOCKMGR		21	/* cannot contact lock manager */
#define	DSVC_NO_LOCATION	22	/* location nonexistent */
#define	DSVC_BAD_CONVER		23	/* malformed/missing CONVER setting */
#define	DSVC_NO_TABLE		24	/* container does not exist */
#define	DSVC_TABLE_EXISTS	25	/* container already exists */

#define	DSVC_NERR		(DSVC_TABLE_EXISTS + 1)

/*
 * Flags that can be passed to open_*
 */
#define	DSVC_CREATE		0x01	/* create container; must not exist */
#define	DSVC_READ		0x02	/* open container for reading */
#define	DSVC_WRITE		0x04	/* open container for writing */
#define	DSVC_NONBLOCK		0x08	/* open container in nonblocking mode */

/*
 * Query macros - used for initializing query flags to lookup_*
 */
#define	DSVC_QINIT(q)		((q) = 0)
#define	DSVC_QEQ(q, v)		((q) = ((q) | (v) | ((v) << 16)))
#define	DSVC_QNEQ(q, v)		((q) = ((~((v) << 16)) & (q)) | (v))
#define	DSVC_QISEQ(q, v)	(((q) & (v)) && ((q) & ((v) << 16)))
#define	DSVC_QISNEQ(q, v)	(((q) & (v)) && (!((q) & ((v) << 16))))

#define	DSVC_MAX_MACSYM_LEN	128	/* max length of a macro or symbol */

/*
 * DHCP Configuration Container (dhcptab(4))
 */
#define	DT_DHCPTAB		"dhcptab"	/* Default name of container */
#define	DT_SYMBOL		's'
#define	DT_MACRO		'm'

/* Query flags for lookup_dt */
#define	DT_QKEY			0x01
#define	DT_QTYPE		0x02
#define	DT_QALL			(DT_QKEY|DT_QTYPE)

/*
 * Consumer's dhcptab record form. Dynamically allocated by underlying data
 * store.  dt_sig is set by underlying data store -- it's opaque to the
 * DHCP service, and is used by the data store to detect update collisions.
 * All fields must be fixed-width types and in host byte order.  Note that
 * SUNWbinfiles writes these records directly to disk, thus changing its
 * definition may introduce binary compatibility problems.  Note also that
 * fields have been carefully ordered to avoid internal padding and the
 * structure's size is 64-bit aligned to avoid capricious trailing padding.
 */
typedef struct {
	uint64_t	dt_sig;			/* Opaque atomic cookie */
	char		*dt_value;		/* Value of type dt_type */
	char		dt_key[DSVC_MAX_MACSYM_LEN + 1]; /* Macro/symbol name */
	char		dt_type;		/* Type of data */
	char		dt_pad[2];		/* Pad to 64-bit boundary */
} dt_rec_t;

typedef struct dt_rec_list {
	dt_rec_t		*dtl_rec;
	struct dt_rec_list	*dtl_next;	/* Next record in the list */
} dt_rec_list_t;

/*
 * DHCP Network Container (dhcp_network(4))
 */
#define	DN_MAX_CID_LEN		(DSVC_MAX_MACSYM_LEN / 2)
#define	DN_MAX_COMMENT_LEN	48

/* Query flags for lookup_dn */
#define	DN_QCID			0x0001
#define	DN_QCIP			0x0002
#define	DN_QSIP			0x0004
#define	DN_QLEASE		0x0008
#define	DN_QMACRO		0x0010
#define	DN_QFDYNAMIC		0x0020
#define	DN_QFAUTOMATIC		0x0040
#define	DN_QFMANUAL		0x0080
#define	DN_QFUNUSABLE		0x0100
#define	DN_QFBOOTP_ONLY		0x0200
#define	DN_QALL			(DN_QCID | DN_QCIP | DN_QSIP | DN_QLEASE |\
				    DN_QMACRO | DN_QFDYNAMIC | DN_QFAUTOMATIC |\
				    DN_QFMANUAL | DN_QFUNUSABLE |\
				    DN_QFBOOTP_ONLY)

/* dn_flags values */
#define	DN_FDYNAMIC		0x00	/* Non-permanent */
#define	DN_FAUTOMATIC		0x01	/* Lease is permanent */
#define	DN_FMANUAL		0x02	/* Manually allocated (sacred) */
#define	DN_FUNUSABLE		0x04	/* Address is unusable */
#define	DN_FBOOTP_ONLY		0x08	/* Address is reserved for BOOTP */
#define	DN_FALL			(DN_FDYNAMIC | DN_FAUTOMATIC | DN_FMANUAL |\
				    DN_FUNUSABLE | DN_FBOOTP_ONLY)

/*
 * Consumer's DHCP network container record form. Dynamically allocated by
 * underlying data store.  dn_sig is set by underlying data store -- it's
 * opaque to the DHCP service, and is used by the data store to detect
 * update collisions.  All fields must be fixed-width types and in host
 * byte order. Note that SUNWbinfiles writes these records directly to
 * disk, thus changing its definition may introduce binary compatibility
 * problems.  Note also that fields have been carefully ordered to avoid
 * internal padding and the structure's size is 64-bit aligned to avoid
 * capricious trailing padding.
 */
typedef struct {
	uint64_t	dn_sig;			/* Opaque atomic cookie */
	struct in_addr	dn_cip;			/* Client IP address */
	struct in_addr	dn_sip;			/* Server IP address */
	lease_t		dn_lease;		/* Abs lease expiration */
	char		dn_macro[DSVC_MAX_MACSYM_LEN + 1];
	char		dn_comment[DN_MAX_COMMENT_LEN + 1];
	uchar_t		dn_cid[DN_MAX_CID_LEN];	/* Opaque client id */
	uchar_t		dn_cid_len;		/* Length of client id */
	uchar_t		dn_flags;		/* Flags */
} dn_rec_t;

typedef struct dn_rec_list {
	dn_rec_t		*dnl_rec;	/* The record itself */
	struct dn_rec_list	*dnl_next;	/* Next entry in the list */
} dn_rec_list_t;

/*
 * Synchronization Service Type and values.
 */
typedef uint32_t dsvc_synchtype_t;

#define	DSVC_SYNCH_NONE		0		/* no synch type */
#define	DSVC_SYNCH_DSVCD	1		/* dsvclockd(1M) synch type */

/*
 * Generic API provided by SMI
 */
extern dt_rec_t	*alloc_dtrec(const char *, char, const char *);
extern dn_rec_t *alloc_dnrec(const uchar_t *, uchar_t, uchar_t, struct in_addr,
		    struct in_addr, lease_t, const char *, const char *);
extern dt_rec_list_t *add_dtrec_to_list(dt_rec_t *, dt_rec_list_t *);
extern dn_rec_list_t *add_dnrec_to_list(dn_rec_t *, dn_rec_list_t *);
extern void	free_dtrec(dt_rec_t *);
extern void	free_dnrec(dn_rec_t *);
extern void	free_dtrec_list(dt_rec_list_t *);
extern void	free_dnrec_list(dn_rec_list_t *);
extern const char *dhcpsvc_errmsg(uint_t);

/*
 * The remaining functions are not directly callable by the libdhcpsvc
 * implementation; don't expose them to it.
 */
#ifndef	_DHCPSVC_IMPL

/*
 * Generic Service Provider Layer API provided by data store implementor
 */
extern int	status(const char *);
extern int	version(int *);
extern int	configure(const char *);
extern int	mklocation(const char *);

/*
 * dhcptab Service Provider Layer API
 */
extern int	list_dt(const char *, char ***, uint_t *);
extern int	open_dt(void **, const char *, uint_t);
extern int	close_dt(void **);
extern int	add_dt(void *, dt_rec_t *);
extern int	remove_dt(const char *);
extern int	modify_dt(void *, const dt_rec_t *, dt_rec_t *);
extern int	delete_dt(void *, const dt_rec_t *);
extern int	lookup_dt(void *, boolean_t, uint_t, int,
		    const dt_rec_t *, dt_rec_list_t **, uint_t *);
/*
 * DHCP Network Service Provider Layer API
 * IP address arguments are host order.
 */
extern int	list_dn(const char *, char ***, uint_t *);
extern int	open_dn(void **, const char *, uint_t, const struct in_addr *,
		    const struct in_addr *);
extern int	close_dn(void **);
extern int	add_dn(void *, dn_rec_t *);
extern int	remove_dn(const char *, const struct in_addr *);
extern int	modify_dn(void *, const dn_rec_t *, dn_rec_t *);
extern int	delete_dn(void *, const dn_rec_t *);
extern int	lookup_dn(void *, boolean_t, uint_t, int,
		    const dn_rec_t *, dn_rec_list_t **, uint_t *);
#endif

#ifdef	__cplusplus
}
#endif

#endif	/* !_DHCP_SVC_PUBLIC_H */
