/************************************************************************
 * RSTP library - Rapid Spanning Tree (802.1t, 802.1w)
 * Copyright (C) 2001-2003 Optical Access
 * Author: Alex Rozin
 *
 * This file is part of RSTP library.
 *
 * RSTP library is free software; you can redistribute it and/or modify it
 * under the terms of the GNU Lesser General Public License as published by the
 * Free Software Foundation; version 2.1
 *
 * RSTP library is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU Lesser
 * General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with RSTP library; see the file COPYING.  If not, write to the Free
 * Software Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA
 * 02111-1307, USA.
 **********************************************************************/

 /* This file contains prototypes for API from an operation
    system to the RSTP */

#ifndef _STP_API_H__
#define _STP_API_H__

#include <sys/types.h>

#define STP_DBG 1

/************************
 * Common base constants
 ************************/

#ifndef INOUT
#  define IN      /* consider as comments near 'input' parameters */
#  define OUT     /* consider as comments near 'output' parameters */
#  define INOUT   /* consider as comments near 'input/output' parameters */
#endif

#ifndef Zero
#  define Zero        0
#  define One         1
#endif

#ifndef Bool
#  define Bool        int
#  define False       0
#  define True        1
#endif

/********************************************
 * constants: default values and linitations
 *********************************************/

/* bridge configuration */

#define DEF_BR_PRIO 32768
#define MIN_BR_PRIO 0
#define MAX_BR_PRIO 61440

#define DEF_BR_HELLOT   2
#define MIN_BR_HELLOT   1
#define MAX_BR_HELLOT   10

#define DEF_BR_MAXAGE   20
#define MIN_BR_MAXAGE   6
#define MAX_BR_MAXAGE   40

#define DEF_BR_FWDELAY  15
#define MIN_BR_FWDELAY  4
#define MAX_BR_FWDELAY  30

#define	IEEE_TIMER_SCALE	256

/* Note that this works with unscaled values */
#define	CHECK_BRIDGE_CONFIG(cfg) \
	(2 * (cfg.forward_delay - 1) >= cfg.max_age && \
	cfg.max_age >= 2 * (cfg.hello_time + 1))

/*
 * These macros provide limits and tests for displaying comprehensible errors.
 */
#define	NO_MAXAGE(cfg) ((cfg.forward_delay - 1) < (cfg.hello_time + 1))
#define	MIN_FWDELAY_NOM(cfg)	\
	(cfg.hello_time < MIN_BR_FWDELAY - 2 ? MIN_BR_FWDELAY : \
	cfg.hello_time + 2)
#define	MAX_HELLOTIME_NOM(cfg)	\
	(cfg.forward_delay > MAX_BR_HELLOT + 2 ? MAX_BR_HELLOT : \
	cfg.forward_delay - 2)

#define	SMALL_MAXAGE(cfg)	(cfg.max_age < 2 * (cfg.hello_time + 1))
#define	MIN_MAXAGE(cfg)	\
	(cfg.hello_time < (MIN_BR_MAXAGE / 2 - 1) ? MIN_BR_MAXAGE : \
	(2 * (cfg.hello_time + 1)))
#define	MAX_HELLOTIME(cfg)	\
	(cfg.max_age > 2 * (MAX_BR_HELLOT + 1) ? MAX_BR_HELLOT : \
	(cfg.max_age / 2 - 1))

#define	MIN_FWDELAY(cfg)	(cfg.max_age / 2 + 1)
#define	MAX_MAXAGE(cfg)	\
	(cfg.forward_delay > (MAX_BR_MAXAGE / 2 + 1) ? MAX_BR_MAXAGE : \
	(2 * (cfg.forward_delay - 1)))

#define	CAPPED_MAXAGE(cfg)	(cfg.forward_delay < (MAX_BR_MAXAGE / 2 + 1))
#define	FLOORED_MAXAGE(cfg)	(cfg.hello_time > (MIN_BR_MAXAGE / 2 - 1))

#define DEF_FORCE_VERS  2 /* NORMAL_RSTP */

/* port configuration */

#define DEF_PORT_PRIO   128
#define MIN_PORT_PRIO   0
#define MAX_PORT_PRIO   240 /* in steps of 16 */

#define DEF_ADMIN_NON_STP   False
#define DEF_ADMIN_EDGE      True
#define DEF_LINK_DELAY      3 /* see edge.c */
#define DEF_P2P         P2P_AUTO

#include <uid_stp.h>
#include <stp_bpdu.h>

#ifndef __STPM_T__
#define __STPM_T__
struct stpm_t;
typedef struct stpm_t STPM_T;
#endif
#ifndef __STP_VECTORS_T__
#define __STP_VECTORS_T__
struct stp_vectors;
typedef struct stp_vectors STP_VECTORS_T;
#endif

/* Section 1: Create/Delete/Start/Stop the RSTP instance */

void /* init the engine */
STP_IN_init (STP_VECTORS_T *vectors);

int
STP_IN_stpm_create (int vlan_id, char* name);

int
STP_IN_stpm_delete (int vlan_id);

int
STP_IN_port_add (int vlan_id, int port_index);

int
STP_IN_port_remove (int vlan_id, int port_index);

int
STP_IN_stop_all (void);

int
STP_IN_delete_all (void);

/* Section 2. "Get" management */

Bool
STP_IN_get_is_stpm_enabled (int vlan_id);

int
STP_IN_stpm_get_vlan_id_by_name (char* name, int* vlan_id);

int
STP_IN_stpm_get_name_by_vlan_id (int vlan_id, char* name, size_t buffsize);

const char*
STP_IN_get_error_explanation (int rstp_err_no);

int
STP_IN_stpm_get_cfg (int vlan_id, UID_STP_CFG_T* uid_cfg);

int
STP_IN_stpm_get_state (int vlan_id, UID_STP_STATE_T* entry);

int
STP_IN_port_get_cfg (int vlan_id, int port_index, UID_STP_PORT_CFG_T* uid_cfg);

int
STP_IN_port_get_state (int vlan_id, UID_STP_PORT_STATE_T* entry);

const char *
STP_IN_state2str(RSTP_PORT_STATE);

/* Section 3. "Set" management */

int
STP_IN_stpm_set_cfg (int vlan_id,
                     UID_STP_CFG_T* uid_cfg);

int
STP_IN_port_set_cfg (int vlan_id, int port_index,
                     UID_STP_PORT_CFG_T* uid_cfg);

#ifdef STP_DBG
int STP_IN_dbg_set_port_trace (char *mach_name, int enadis,
    int vlan_id, int port_index);
#endif

/* Section 4. RSTP functionality events */

int
STP_IN_one_second (void);

int /* for Link UP/DOWN */
STP_IN_enable_port (int port_index, Bool enable);

int /* call it, when port speed has been changed, speed in Kb/s  */
STP_IN_changed_port_speed (int port_index, long speed);

int /* call it, when current port duplex mode has been changed  */
STP_IN_changed_port_duplex (int port_index);

int
STP_IN_check_bpdu_header (BPDU_T* bpdu, size_t len);

int
STP_IN_rx_bpdu (int vlan_id, int port_index, BPDU_T* bpdu, size_t len);

void
STP_IN_get_bridge_id(int vlan_id, unsigned short *priority, unsigned char *mac);

#endif /* _STP_API_H__ */
