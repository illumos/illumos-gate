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

#ifndef _DHCP_SVC_PRIVATE_H
#define	_DHCP_SVC_PRIVATE_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * Contains SMI-private interfaces to DHCP data service.  DO NOT SHIP!
 */

#ifdef	__cplusplus
extern "C" {
#endif

#include <sys/types.h>
#include <stddef.h>
#include <dhcp_svc_confopt.h>
#include <dhcp_svc_public.h>

#define	DSVC_PRIVATE_VERSION	1	/* Version of private layer API */
#define	DSVC_MODULE_DIR		"/usr/lib/inet/dhcp/svc"
#define	DSVC_PUBLIC_PREFIX	"ds"

/*
 * Public (service provider) layer definitions at boundary with private layer.
 */
typedef	int (*dsvc_splfuncp_t)();

typedef struct {
	dsvc_splfuncp_t	status;
	dsvc_splfuncp_t	version;
	dsvc_splfuncp_t	mklocation;
	dsvc_splfuncp_t	list_dt;
	dsvc_splfuncp_t	open_dt;
	dsvc_splfuncp_t	close_dt;
	dsvc_splfuncp_t	remove_dt;
	dsvc_splfuncp_t	lookup_dt;
	dsvc_splfuncp_t	add_dt;
	dsvc_splfuncp_t	modify_dt;
	dsvc_splfuncp_t	delete_dt;
	dsvc_splfuncp_t	list_dn;
	dsvc_splfuncp_t	open_dn;
	dsvc_splfuncp_t	close_dn;
	dsvc_splfuncp_t	remove_dn;
	dsvc_splfuncp_t	lookup_dn;
	dsvc_splfuncp_t	add_dn;
	dsvc_splfuncp_t	modify_dn;
	dsvc_splfuncp_t	delete_dn;
} dsvc_splapi_t;

#define	DSVC_NSPLFUNCS	(sizeof (dsvc_splapi_t) / sizeof (dsvc_splfuncp_t))
#define	DSVC_CUR_CONVER	(-1)	/* magic "get the current version" token */

typedef struct {
	char		*d_resource;	/* datastore name; e.g. "SUNWfiles" */
	char		*d_location;	/* location of datastore containers */
	char		*d_config;	/* datastore-specific config data */
	int		d_conver;	/* container version */
} dsvc_datastore_t;

/*
 * Container types.
 */
typedef enum {
	DSVC_DHCPTAB,
	DSVC_DHCPNETWORK
} dsvc_contype_t;

/*
 * Container ID: so far just the network and netmask for DSVC_DHCPNETWORK
 * containers, but may include more information in the future.
 */
typedef struct {
	struct in_addr		c_net; 		/* network number */
	struct in_addr		c_mask;		/* netmask */
} dsvc_conid_t;

struct dsvc_synch_ops;				/* forward declaration */

/*
 * Per-handle synchronization information, used when modules require
 * private-layer synchronization.
 */
typedef struct {
	dsvc_datastore_t	*s_datastore;	/* datastore backpointer */
	char			s_loctoken[MAXPATHLEN];
	char			*s_conname;	/* container name */
	boolean_t		s_nonblock;	/* container opened NONBLOCK */
	struct dsvc_synch_ops	*s_ops;		/* pointer to ops vector */
	void			*s_data;	/* synch-layer private data */
} dsvc_synch_t;

/*
 * Synchronization operations; each synchronization strategy must implement
 * these operations.  Right now, we only have one synchronization strategy,
 * but this may change someday.
 */
typedef struct dsvc_synch_ops {
	int		(*synch_init)(dsvc_synch_t *, unsigned int);
	void		(*synch_fini)(dsvc_synch_t *);
	int		(*synch_rdlock)(dsvc_synch_t *, void **);
	int		(*synch_wrlock)(dsvc_synch_t *, void **);
	int		(*synch_unlock)(dsvc_synch_t *, void *);
} dsvc_synch_ops_t;

#define	DSVC_SYNCH_INIT(sp, flags)	((sp)->s_ops->synch_init((sp), (flags)))
#define	DSVC_SYNCH_FINI(sp)		((sp)->s_ops->synch_fini((sp)))
#define	DSVC_SYNCH_RDLOCK(sp, cp)	((sp)->s_ops->synch_rdlock((sp), (cp)))
#define	DSVC_SYNCH_WRLOCK(sp, cp)	((sp)->s_ops->synch_wrlock((sp), (cp)))
#define	DSVC_SYNCH_UNLOCK(sp, c)	((sp)->s_ops->synch_unlock((sp), (c)))

/*
 * We divide the dsvc_synchtype_t up into two parts: a strategy part and a
 * flags part.  Right now, the only flag tells private layer to request
 * cross-host synchronization.  This is here instead of <dhcp_svc_public.h>
 * since it's not a public interface and there's nowhere better to put it.
 */
#define	DSVC_SYNCH_FLAGMASK		0xffff0000
#define	DSVC_SYNCH_STRATMASK		0x0000ffff
#define	DSVC_SYNCH_CROSSHOST		0x00010000

/*
 * Private layer handle, one per open instance of a container.
 * Allocated by open_dd(), destroyed by close_dd().
 */
typedef struct dsvc_handle {
	dsvc_datastore_t	d_desc;		/* datastore descriptor */
	void			*d_instance;	/* dlopen() instance  */
	dsvc_contype_t		d_type;		/* container type */
	dsvc_conid_t		d_conid;	/* container id */
	void			*d_hand;	/* public module handle */
	dsvc_synch_t		*d_synch;	/* synchronization state */
	dsvc_splapi_t		d_api;		/* service provider layer API */
} *dsvc_handle_t;

/*
 * Quick-n-dirty check for an invalid dsvc_handle_t.
 */
#define	DSVC_HANDLE_INVAL(h)	((h) == NULL || (h)->d_instance == NULL || \
				(h)->d_hand == NULL)

extern int enumerate_dd(char ***, int *);
extern int list_dd(dsvc_datastore_t *, dsvc_contype_t, char ***, uint_t *);
extern int status_dd(dsvc_datastore_t *);
extern int mklocation_dd(dsvc_datastore_t *);
extern int add_dd_entry(dsvc_handle_t, void *);
extern int modify_dd_entry(dsvc_handle_t, const void *, void *);
extern int delete_dd_entry(dsvc_handle_t, void *);
extern int close_dd(dsvc_handle_t *);
extern int remove_dd(dsvc_datastore_t *, dsvc_contype_t, const char *);
extern int open_dd(dsvc_handle_t *, dsvc_datastore_t *, dsvc_contype_t,
	    const char *, uint_t);
extern int lookup_dd(dsvc_handle_t, boolean_t, uint_t, int, const void *,
	    void **, uint_t *);
extern void free_dd(dsvc_handle_t, void *);
extern void free_dd_list(dsvc_handle_t, void *);
extern int confopt_to_datastore(dhcp_confopt_t *, dsvc_datastore_t *);
extern int module_synchtype(dsvc_datastore_t *, dsvc_synchtype_t *);

/*
 * Under DEBUG, the DHCP_CONFOPT_ROOT environment variable can be set to
 * the path of a directory for the DHCP server to use an alternate root
 * for its configuration information and datastores.
 */
#ifdef DEBUG
#define	DHCP_CONFOPT_ROOT ((getenv("DHCP_CONFOPT_ROOT") != NULL) ? \
			    getenv("DHCP_CONFOPT_ROOT") : "")
#else
#define	DHCP_CONFOPT_ROOT ""
#endif

#ifdef	__cplusplus
}
#endif

#endif	/* !_DHCP_SVC_PRIVATE_H */
