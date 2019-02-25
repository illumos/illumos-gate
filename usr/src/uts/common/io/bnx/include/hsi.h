/*
 * Copyright 2014-2017 Cavium, Inc.
 * The contents of this file are subject to the terms of the Common Development
 * and Distribution License, v.1,  (the "License").
 *
 * You may not use this file except in compliance with the License.
 *
 * You can obtain a copy of the License at available
 * at http://opensource.org/licenses/CDDL-1.0
 *
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#ifndef PRIVATE_HSI_H
#define PRIVATE_HSI_H

#define tcp_syn_dos_defense		(0x10 + 0x020)
#define rxp_unicast_bytes_rcvd		(0x10 + 0x0d0)
#define rxp_multicast_bytes_rcvd	(0x10 + 0x0d8)
#define rxp_broadcast_bytes_rcvd	(0x10 + 0x0e0)
#define RXP_HSI_OFFSETOFF(x)		(x)

#define com_no_buffer			(0x10 + 0x074)
#define COM_HSI_OFFSETOFF(x)		(x)

#define unicast_bytes_xmit		(0x410 + 0x030)
#define multicast_bytes_xmit		(0x410 + 0x038)
#define broadcast_bytes_xmit		(0x410 + 0x040)
#define TPAT_HSI_OFFSETOFF(x)		(x)

#endif
