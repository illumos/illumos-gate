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

/* This file contains prototypes for system dependent API
   from the RSTP to an operation system */

#ifndef _STP_OUT_H__
#define _STP_OUT_H__

#include "stp_vectors.h"
#define	STP_OUT_flush_lt		(*stp_vectors->flush_lt)
#define	STP_OUT_get_port_mac		(*stp_vectors->get_port_mac)
#define	STP_OUT_get_port_oper_speed	(*stp_vectors->get_port_oper_speed)
#define	STP_OUT_get_port_link_status	(*stp_vectors->get_port_link_status)
#define	STP_OUT_get_duplex		(*stp_vectors->get_duplex)
#ifdef STRONGLY_SPEC_802_1W
#define	STP_OUT_set_learning		(*stp_vectors->set_learning)
#define	STP_OUT_set_forwarding		(*stp_vectors->set_forwarding)
#else
#define	STP_OUT_set_port_state		(*stp_vectors->set_port_state)
#endif
#define	STP_OUT_set_hardware_mode	(*stp_vectors->set_hardware_mode)
#define	STP_OUT_tx_bpdu			(*stp_vectors->tx_bpdu)
#define	STP_OUT_get_port_name		(*stp_vectors->get_port_name)
#define	STP_OUT_get_init_stpm_cfg	(*stp_vectors->get_init_stpm_cfg)
#define	STP_OUT_get_init_port_cfg	(*stp_vectors->get_init_port_cfg)

#endif /* _STP_OUT_H__ */

