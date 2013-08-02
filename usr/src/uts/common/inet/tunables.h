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
 * Copyright (c) 1991, 2010, Oracle and/or its affiliates. All rights reserved.
 * Copyright (c) 1990 Mentat Inc.
 * Copyright (c) 2013 by Delphix. All rights reserved.
 */

#ifndef _INET_TUNABLES_H
#define	_INET_TUNABLES_H

#include <sys/types.h>
#include <net/if.h>
#ifdef _KERNEL
#include <sys/netstack.h>
#endif

#ifdef	__cplusplus
extern "C" {
#endif

#define	MAXPROPNAMELEN	64

/*
 * The `mod_ioc_prop_s' datastructure is used as an IOCTL argument for
 * SIOCSETPROP and SIOCGETPROP ioctls. This datastructure identifies the
 * protocol (`mpr_proto') property (`mpr_name'), which needs to be modified
 * or retrieved (`mpr_valsize' and `mpr_val'). If the property applies to an
 * interface then `mpr_ifname' contains the name of the interface.
 */
typedef struct mod_ioc_prop_s {
	uint_t		mpr_version;
	uint_t		mpr_flags;			/* see below */
	/* name of the interface (ill) for which property will be applied */
	char		mpr_ifname[LIFNAMSIZ];
	uint_t		mpr_proto;			/* see below */
	char		mpr_name[MAXPROPNAMELEN];	/* property name */
	uint_t		mpr_valsize;			/* size of mpr_val */
	char		mpr_val[1];
} mod_ioc_prop_t;

#define	MOD_PROP_VERSION	1

/* permission flags for properties */
#define	MOD_PROP_PERM_READ	0x1
#define	MOD_PROP_PERM_WRITE	0x2
#define	MOD_PROP_PERM_RW	(MOD_PROP_PERM_READ|MOD_PROP_PERM_WRITE)

/* mpr_flags values */
#define	MOD_PROP_ACTIVE		0x01	/* current value of the property */
#define	MOD_PROP_DEFAULT	0x02	/* default value of the property */
#define	MOD_PROP_POSSIBLE	0x04	/* possible values for the property */
#define	MOD_PROP_PERM		0x08	/* read/write permission for property */
#define	MOD_PROP_APPEND		0x10	/* append to multi-valued property */
#define	MOD_PROP_REMOVE		0x20	/* remove from multi-valued property */

/* mpr_proto values */
#define	MOD_PROTO_NONE		0x00
#define	MOD_PROTO_IPV4		0x01	/* property is applicable to IPV4 */
#define	MOD_PROTO_IPV6		0x02	/* property is applicable to IPV6 */
#define	MOD_PROTO_RAWIP		0x04	/* property is applicable to ICMP */
#define	MOD_PROTO_TCP		0x08	/* property is applicable to TCP */
#define	MOD_PROTO_UDP		0x10	/* property is applicable to UDP */
#define	MOD_PROTO_SCTP		0x20	/* property is applicable to SCTP */

/* property is applicable to both IPV[4|6] */
#define	MOD_PROTO_IP		(MOD_PROTO_IPV4|MOD_PROTO_IPV6)

#ifdef	_KERNEL

typedef struct mod_prop_info_s mod_prop_info_t;

/* set/get property callback functions */
typedef int	mod_prop_setf_t(netstack_t *, cred_t *, mod_prop_info_t *,
		    const char *, const void *, uint_t);
typedef int	mod_prop_getf_t(netstack_t *, mod_prop_info_t *, const char *,
		    void *, uint_t, uint_t);

typedef struct mod_propval_uint32_s {
	uint32_t	mod_propval_umin;
	uint32_t	mod_propval_umax;
	uint32_t	mod_propval_ucur;
} mod_propval_uint32_t;

/*
 * protocol property information
 */
struct mod_prop_info_s {
	char			*mpi_name;	/* property name */
	uint_t			mpi_proto;	/* property protocol */
	mod_prop_setf_t		*mpi_setf;	/* sets the property value */
	mod_prop_getf_t		*mpi_getf;	/* gets the property value */
	/*
	 * Holds the current value of the property. Whenever applicable
	 * holds the min/max value too.
	 */
	union {
		mod_propval_uint32_t	mpi_uval;
		boolean_t		mpi_bval;
		uint64_t		_pad[2];
	} u;
	/*
	 * Holds the default value of the property, that is value of
	 * the property at boot time.
	 */
	union {
		uint32_t	mpi_def_uval;
		boolean_t	mpi_def_bval;
	} u_def;
};

/* shortcuts to access current/default values */
#define	prop_min_uval	u.mpi_uval.mod_propval_umin
#define	prop_max_uval	u.mpi_uval.mod_propval_umax
#define	prop_cur_uval	u.mpi_uval.mod_propval_ucur
#define	prop_cur_bval	u.mpi_bval
#define	prop_def_uval	u_def.mpi_def_uval
#define	prop_def_bval	u_def.mpi_def_bval

#define	MS		1L
#define	SECONDS		(1000 * MS)
#define	MINUTES		(60 * SECONDS)
#define	HOURS		(60 * MINUTES)
#define	DAYS		(24 * HOURS)

#define	MB		(1024 * 1024)

/* Largest TCP/UDP/SCTP port number */
#define	ULP_MAX_PORT	(64 * 1024 - 1)

/* extra privilege ports for upper layer protocols, tcp, sctp and udp */
#define	ULP_DEF_EPRIV_PORT1	2049
#define	ULP_DEF_EPRIV_PORT2	4045

#define	ULP_MAX_BUF	(1<<30) /* Largest possible send/receive buffer */

/* generic function to set/get global module properties */
extern mod_prop_setf_t	mod_set_boolean, mod_set_uint32,
			mod_set_aligned, mod_set_extra_privports;

extern mod_prop_getf_t	mod_get_boolean, mod_get_uint32,
			mod_get_allprop, mod_get_extra_privports;

extern int		mod_uint32_value(const void *, mod_prop_info_t *,
    uint_t, unsigned long *);
extern mod_prop_info_t	*mod_prop_lookup(mod_prop_info_t[], const char *,
    uint_t);
extern int		mod_set_buf_prop(mod_prop_info_t[], netstack_t *,
    cred_t *cr, mod_prop_info_t *, const char *, const void *, uint_t);
extern int		mod_get_buf_prop(mod_prop_info_t[], netstack_t *,
    mod_prop_info_t *, const char *, void *, uint_t, uint_t);

#endif	/* _KERNEL */

/*
 * End-system model definitions that include the weak/strong end-system
 * definitions in RFC 1122, Section 3.3.4.5. IP_WEAK_ES and IP_STRONG_ES
 * conform to the corresponding  RFC 1122 definitions. The IP_SRC_PRI_ES
 * hostmodel is similar to IP_WEAK_ES with one additional enhancement: for
 * a packet with source S2, destination D2, the route selection algorithm
 * will first attempt to find a route for the destination that goes out
 * through an interface where S2 is configured and marked UP.  If such
 * a route cannot be found, then the best-matching route for D2 will be
 * selected, ignoring any mismatches between S2 and the interface addresses
 * on the outgoing interface implied by the route.
 */
typedef enum {
	IP_WEAK_ES = 0,
	IP_SRC_PRI_ES,
	IP_STRONG_ES,
	IP_MAXVAL_ES
} ip_hostmodel_t;

#ifdef	__cplusplus
}
#endif

#endif	/* _INET_TUNABLES_H */
