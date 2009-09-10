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

#ifndef _BRIDGED_GLOBAL_H
#define	_BRIDGED_GLOBAL_H

/*
 * Globally visible symbols within the "bridged" bridging daemon
 */

#include <sys/types.h>
#include <sys/ethernet.h>
#include <net/bridge.h>
#include <libdlpi.h>
#include <libdladm.h>
#include <libdlbridge.h>

#ifdef __cplusplus
extern "C" {
#endif

struct portdata {
	int vlan_id;
	int port_index;
	unsigned int speed;
	boolean_t phys_status;		/* physical layer status */
	boolean_t admin_status;		/* administrative status */
	boolean_t kern_added;		/* set when added to kernel bridge */
	boolean_t stp_added;		/* set when added to STP machine */
	boolean_t referenced;		/* used for refresh */
	boolean_t sdu_failed;		/* set for non-matching max SDU */
	boolean_t admin_non_stp;	/* copy of STP library config */
	boolean_t bpdu_protect;		/* BPDU seen when non-STP */
	bridge_state_t state;
	dlpi_handle_t dlpi;
	dlpi_notifyid_t notifyid;
	datalink_id_t linkid;
	const char *name;
	uchar_t mac_addr[ETHERADDRL];
};

/* Number of reserved (internal) fdarray entries */
#define	FDOFFSET	2

/* main.c */
extern int lock_engine(void);
extern void unlock_engine(void);
extern ssize_t strioctl(int, int, void *, size_t);
extern struct portdata *find_by_linkid(datalink_id_t);
extern void get_dladm_speed(struct portdata *);
extern void enable_forwarding(struct portdata *);
extern boolean_t debugging;
extern uint32_t tablemax;
extern const char *instance_name;
extern dladm_handle_t dlhandle;
extern boolean_t shutting_down;
extern struct pollfd *fdarray;

/* door.c */
extern void init_door(void);

/* dlpi.c */
extern boolean_t port_dlpi_open(const char *, struct portdata *,
    datalink_class_t);

/* rstp.c */
extern void rstp_init(void);
extern void rstp_refresh(void);
extern void rstp_change_mac(struct portdata *, const unsigned char *);
extern boolean_t rstp_add_port(struct portdata *);

/* events.c */
extern void open_bridge_control(void);
extern void event_loop(void);
extern int refresh_count;
extern dladm_bridge_prot_t protect;
extern uint_t nextport;
extern struct portdata **allports;
extern int control_fd;

#ifdef __cplusplus
}
#endif

#endif /* _BRIDGED_GLOBAL_H */
