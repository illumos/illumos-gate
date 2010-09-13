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
 * Copyright (c) 2009, 2010, Oracle and/or its affiliates. All rights reserved.
 */

#ifndef	_SYS_DAMAP_H
#define	_SYS_DAMAP_H

#ifdef	__cplusplus
extern "C" {
#endif

/*
 * Delta (device) Address Map Interfaces
 *
 * These interfaces provide time-stablized sets of 'addresses',
 * where addresses are string representations of device
 * or bus-specific address.  The mechanisms include interfaces to
 * report and remove address from a map, time stabilization, callouts
 * to higher-level configuration and unconfiguration actions, and
 * address lookup functions.
 *
 * Per Address Reports
 * With per-address reporting, the caller reports the addition and removal
 * each address visible to it. Each report is independently time stabilized;
 * Once a report has stabilized, the reported address is either
 * activated & configured, or unconfigured & released.
 *
 * Full Set Reports
 * When using fullset reporting, the report provider enumerates the entire
 * set of addresses visible to the provider at a given point in time.
 * The entire set is then stabilized.
 * Upon stabilizing, any newly reported addresses are activated & configured
 * and any previously active addresses which are no longer visible are
 * automatically unconfigured and released, freeing the provider from
 * the need to explicitly unconfigure addresses no longer present.
 *
 * Stabilization
 * Once an address has been reported (or reported as removed), the report
 * is time stabilized before the framework initiates a configuration
 * or unconfiguration action.  If the address is re-reported while undergoing
 * stabilization, the timer is reset for either the address or the full
 * set of addresses reported to the map.
 *
 * Activation/Release
 * Once a reported address has passed its stabilization, the address is
 * 'activated' by the framework.  Once activated, the address is passed
 * to a configuration callout to perform whatever actions are necessary.
 * If a reported address is deleted or fails to stabilize, the address
 * is released by the map.
 * A report provider may register callback functions to be invoked
 * as part of the address activation & release process.  In addition to
 * the callbacks, a provider can also supply a handle to provider-private
 * data at the time an address is reported.  This handle is returned to
 * provider as an argument to the activation & release callbacks.
 *
 * Lookup/Access
 * The set of stable addresses contained in a map can be obtained by
 * calling interfaces to lookup either a single address or the full
 * list of stable addresses.
 */

/*
 * damap_t:		Handle to a delta address map
 * damap_id_t:  	Handle to an entry of damap_t
 */
typedef struct __damap_dm *damap_t;
typedef id_t damap_id_t;

/*
 * damap_id_list_t:	List of damap_id_handles
 * NB. Not Used
 */
typedef struct __damap_id_list *damap_id_list_t;

#define	NODAM (damap_id_t)0

/*
 * activate_cb:		Provider callback when reported address is activated
 * deactivate_cb:	Provider callback when address has been released
 *
 * configure_cb:	Class callout to configure newly activated addresses
 * unconfig_cb:		Class callout to unconfigure deactivated addresses
 */
typedef enum {
	DAMAP_DEACT_RSN_GONE = 0,
	DAMAP_DEACT_RSN_CFG_FAIL,
	DAMAP_DEACT_RSN_UNSTBL
} damap_deact_rsn_t;

typedef void (*damap_activate_cb_t)(void *, char *, int, void **);
typedef void (*damap_deactivate_cb_t)(void *, char *, int, void *,
    damap_deact_rsn_t);

typedef int (*damap_configure_cb_t)(void *, damap_t *, damap_id_t);
typedef int (*damap_unconfig_cb_t)(void *, damap_t *, damap_id_t);

/*
 * Map reporting mode
 */
typedef enum {DAMAP_REPORT_PERADDR, DAMAP_REPORT_FULLSET} damap_rptmode_t;

/*
 * Map create options flags
 * DAMAP_SERIALCONFIG - serialize activate/deactivate operations
 * DAMAP_MTCONFIG - multithread config/unconfg operations
 */
#define	DAMAP_SERIALCONFIG	0
#define	DAMAP_MTCONFIG		1

int	damap_create(char *, damap_rptmode_t, int, int,
	    void *, damap_activate_cb_t, damap_deactivate_cb_t,
	    void *, damap_configure_cb_t, damap_unconfig_cb_t,
	    damap_t **);
void	damap_destroy(damap_t *);

char	*damap_name(damap_t *);
int	damap_size(damap_t *);
int	damap_is_empty(damap_t *);
int	damap_sync(damap_t *, int);

int	damap_addr_add(damap_t *, char *, damap_id_t *, nvlist_t *, void *);
int	damap_addr_del(damap_t *, char *);
int	damap_addrid_del(damap_t *, int);

/*
 * modifiers to damap_addrset_end()
 */
#define	DAMAP_END_RESET	1
#define	DAMAP_END_ABORT	2

int		damap_addrset_begin(damap_t *);
int		damap_addrset_add(damap_t *, char *, damap_id_t *,
		    nvlist_t *, void *);
int		damap_addrset_end(damap_t *, int);
int		damap_addrset_flush(damap_t *);
int		damap_addrset_reset(damap_t *, int);
damap_id_t	damap_id_next(damap_t *, damap_id_list_t, damap_id_t);
char		*damap_id2addr(damap_t *, damap_id_t);
nvlist_t	*damap_id2nvlist(damap_t *, damap_id_t);
int		damap_id_hold(damap_t *, damap_id_t);
void		damap_id_rele(damap_t *, damap_id_t);
int		damap_id_ref(damap_t *, damap_id_t);
void		damap_id_list_rele(damap_t *, damap_id_list_t);
void		*damap_id_priv_get(damap_t *, damap_id_t);
void		damap_id_priv_set(damap_t *, damap_id_t, void *);
damap_id_t	damap_lookup(damap_t *, char *);
int		damap_lookup_all(damap_t *, damap_id_list_t *);

#define	DAM_SUCCESS	0
#define	DAM_EEXIST	1
#define	DAM_MAPFULL	2
#define	DAM_EINVAL	3
#define	DAM_FAILURE	4
#define	DAM_SHAME	5

#ifdef	__cplusplus
}
#endif

#endif	/* _SYS_DAMAP_H */
