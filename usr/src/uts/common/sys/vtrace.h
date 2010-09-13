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
 * Copyright 2004 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*	Copyright (c) 1983, 1984, 1985, 1986, 1987, 1988, 1989 AT&T	*/
/*	  All Rights Reserved  	*/

/*
 * Portions of this source code were derived from Berkeley 4.3 BSD
 * under license from the Regents of the University of California.
 */

#ifndef _SYS_VTRACE_H
#define	_SYS_VTRACE_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifndef	_ASM
#include <sys/types.h>
#include <sys/time.h>
#ifdef	_KERNEL
#include <sys/cpuvar.h>
#endif	/* _KERNEL */
#endif	/* _ASM */

#ifdef	__cplusplus
extern "C" {
#endif

/*
 * vtrace is a legacy tracing framework that has been subsumed by the DTrace
 * framework.  To allow tracing of legacy vtrace points, the points themselves
 * have been retained, and are provided to DTrace via the "vtrace" DTrace
 * provider (which is itself implemented in terms of the statically defined
 * tracing provider).  Provided in this header file are the facility
 * definitions currently in use, along with the specific tracing codes still
 * in use.  They are here purely for understanding extant vtrace points; the
 * constants should not be changed, and should not be added to.  (And any all
 * new tracing points should be implemented in terms of DTRACE_PROBE() and
 * friends.)
 */
#define	TR_FAC_TRAP		2	/* traps */
#define	TR_FAC_INTR		3	/* interrupts */
#define	TR_FAC_DISP		5	/* dispatcher */
#define	TR_FAC_VM		6	/* VM system */
#define	TR_FAC_PROC		7	/* process subsystem */
#define	TR_FAC_STREAMS_FR	11	/* STREAMS framework */
#define	TR_FAC_TCP		14	/* tcp protocol module */
#define	TR_FAC_UDP		15	/* udp protocol module */
#define	TR_FAC_IP		16	/* ip protocol module */
#define	TR_FAC_ARP		17	/* arp protocol module */
#define	TR_FAC_LE		18	/* lance ethernet driver */
#define	TR_FAC_SCSI		21	/* SCSI */
#define	TR_FAC_CALLOUT		24	/* callout table */
#define	TR_FAC_SPECFS		29	/* specfs fileystem */
#define	TR_FAC_SWAPFS		30	/* swapfs fileystem */
#define	TR_FAC_TMPFS		31	/* tmpfs fileystem */
#define	TR_FAC_UFS		32	/* UFS */
#define	TR_FAC_NFS		33	/* NFS */
#define	TR_FAC_KRPC		36	/* Kernel RPC */
#define	TR_FAC_SCHED		37	/* swapper */
#define	TR_FAC_SCSI_RES		38	/* SCSI_RESOURCE */
#define	TR_FAC_SCSI_ISP		39	/* ISP HBA Driver SCSI */
#define	TR_FAC_IA		40	/* IA scheduling class */
#define	TR_FAC_BE		43	/* Fast Ethernet driver */
#define	TR_FAC_FIFO		44	/* Fifos */
#define	TR_FAC_RLOGINP		45	/* rlmod protocol module */
#define	TR_FAC_PHYSIO		47	/* physio */
#define	TR_FAC_META		48	/* meta disk */
#define	TR_FAC_SCSI_FAS		49	/* fas scsi HBA driver */
#define	TR_FAC_SOCKFS		50	/* socket fileystem */
#define	TR_FAC_DEVMAP		51	/* devmap */
#define	TR_FAC_DADA		52	/* target driver for ide */

/*
 * TR_FAC_TRAP tags
 */

#define	TR_TRAP_END			1
#define	TR_C_TRAP_HANDLER_ENTER		6
#define	TR_C_TRAP_HANDLER_EXIT		7

/*
 * TR_FAC_INTR tags
 */

#define	TR_INTR_PASSIVATE	3

/*
 * TR_FAC_DISP tags
 */

#define	TR_DISP_START		0
#define	TR_DISP_END		1
#define	TR_SWTCH_START		2
#define	TR_SWTCH_END		3
#define	TR_PREEMPT_START	4
#define	TR_PREEMPT_END		5
#define	TR_RESUME_START		6
#define	TR_FRONTQ		8
#define	TR_BACKQ		9
#define	TR_CPU_RESCHED		10
#define	TR_SLEEP		11
#define	TR_TRAPRET		12
#define	TR_TICK			13
#define	TR_UPDATE		14
#define	TR_CPU_SURRENDER	16
#define	TR_PREEMPT		17


/*
 * TR_FAC_VM tags
 */

#define	TR_PAGE_INIT		0
#define	TR_PAGE_WS_IN		1
#define	TR_PAGE_WS_OUT		2
#define	TR_PAGE_WS_FREE		3
#define	TR_PAGEOUT_START	5
#define	TR_PAGEOUT_END		6
#define	TR_PAGEOUT_HAND_WRAP	7
#define	TR_PAGEOUT_ISREF	9
#define	TR_PAGEOUT_FREE		10
#define	TR_PAGEOUT_CV_SIGNAL	11
#define	TR_SEGMAP_FAULT		20
#define	TR_SEGMAP_GETMAP	21
#define	TR_SEGMAP_RELMAP	22
#define	TR_SEGMAP_PAGECREATE	23
#define	TR_SEGMAP_GETPAGE	24
#define	TR_SEGVN_FAULT		25
#define	TR_SEGVN_GETPAGE	26
#define	TR_ANON_GETPAGE		27
#define	TR_ANON_PRIVATE		28
#define	TR_SWAP_ALLOC		30
#define	TR_PVN_READ_KLUSTER	31
#define	TR_PVN_GETDIRTY		32
#define	TR_PAGE_CREATE_START	33
#define	TR_PAGE_CREATE_TOOBIG	34
#define	TR_PAGE_CREATE_NOMEM	35
#define	TR_PAGE_CREATE_SUCCESS	36
#define	TR_PAGE_CREATE_SLEEP_START	37
#define	TR_PAGE_CREATE_SLEEP_END	38
#define	TR_PAGE_FREE_FREE	40
#define	TR_PAGE_FREE_CACHE_HEAD	41
#define	TR_PAGE_FREE_CACHE_TAIL	42
#define	TR_PAGE_UNFREE_FREE	43
#define	TR_PAGE_UNFREE_CACHE	44
#define	TR_PAGE_DESTROY		45
#define	TR_PAGE_HASHIN		46
#define	TR_PAGE_HASHOUT		47
#define	TR_ANON_PROC		48
#define	TR_ANON_SHM		49
#define	TR_ANON_TMPFS		50
#define	TR_ANON_SEGKP		53
#define	TR_SAMPLE_WS_START	56
#define	TR_SAMPLE_WS_END	57
#define	TR_AS_INFO		59
#define	TR_SEG_INFO		60
#define	TR_PAGE_RENAME		61

/*
 * TR_FAC_PROC tags
 */

#define	TR_PROC_EXEC		0
#define	TR_PROC_EXIT		1
#define	TR_PROC_FORK		2
#define	TR_EXECMAP_PREREAD	3
#define	TR_EXECMAP_NO_PREREAD	4

/*
 * TR_FAC_SCHED tags
 */

#define	TR_SWAPIN		0
#define	TR_SWAPOUT		1
#define	TR_RUNIN		2
#define	TR_RUNOUT		3
#define	TR_CHOOSE_SWAPOUT	4
#define	TR_CHOOSE_SWAPIN	5
#define	TR_SOFTSWAP		6
#define	TR_DESPERATE		8
#define	TR_HIGH_DEFICIT		9
#define	TR_SWAPIN_VALUES	10
#define	TR_UNLOAD		11
#define	TR_SWAPOUT_LWP		12
#define	TR_SWAPQ_LWP		13
#define	TR_SWAPQ_PROC		14

/*
 * TR_FAC_STREAMS_FR tags
 */

#define	TR_STRREAD_AWAKE	6
#define	TR_STRRPUT_PROTERR	8
#define	TR_I_PUSH		14
#define	TR_I_POP		15
#define	TR_STRSENDSIG		24
#define	TR_QATTACH_FLAGS	25
#define	TR_STRWAITQ_TIME	31
#define	TR_STRWAITQ_WAIT2	32
#define	TR_STRWAITQ_INTR2	33
#define	TR_STRWAITQ_WAKE2	34
#define	TR_QRUNSERVICE_START	39
#define	TR_SENDSIG		42
#define	TR_INSERTQ		43
#define	TR_REMOVEQ		44
#define	TR_CANPUT_IN    	47
#define	TR_CANPUT_OUT   	48
#define	TR_BCANPUT_IN   	49
#define	TR_BCANPUT_OUT  	50
#define	TR_STRWRITE_IN		51
#define	TR_STRWRITE_OUT		52
#define	TR_STRWRITE_WAIT	53
#define	TR_STRWRITE_WAKE	54
#define	TR_STRWRITE_RESID	56
#define	TR_STRPUTMSG_IN		57
#define	TR_STRPUTMSG_WAIT	58
#define	TR_STRPUTMSG_WAKE	59
#define	TR_STRPUTMSG_OUT	60
#define	TR_QRUNSERVICE_END	65
#define	TR_PUT_START		68
#define	TR_PUTNEXT_START	70
#define	TR_PUTNEXT_END		71
#define	TR_DRAIN_SYNCQ_START	72
#define	TR_DRAIN_SYNCQ_END	73
#define	TR_STRGETMSG_ENTER	74
#define	TR_STRGETMSG_WAIT	75
#define	TR_STRGETMSG_DONE	76
#define	TR_STRGETMSG_AWAKE	77
#define	TR_KSTRGETMSG_ENTER	78
#define	TR_KSTRGETMSG_WAIT	79
#define	TR_KSTRGETMSG_DONE	80
#define	TR_KSTRGETMSG_AWAKE	81
#define	TR_KSTRPUTMSG_IN	82
#define	TR_KSTRPUTMSG_WAIT	83
#define	TR_KSTRPUTMSG_WAKE	84
#define	TR_KSTRPUTMSG_OUT	85
#define	TR_CANPUTNEXT_IN	86
#define	TR_CANPUTNEXT_OUT	87

/*
 * TR_FAC_TCP tags
 */

#define	TR_TCP_RPUT_IN		2
#define	TR_TCP_RPUT_OUT		3
#define	TR_TCP_WPUT_IN		4
#define	TR_TCP_WPUT_OUT		5
#define	TR_TCP_RSRV_IN		6
#define	TR_TCP_RSRV_OUT		7
#define	TR_TCP_WSRV_IN		8

/*
 * TR_FAC_UDP tags
 */

#define	TR_UDP_OPEN		0
#define	TR_UDP_CLOSE		1
#define	TR_UDP_RPUT_START	2
#define	TR_UDP_RPUT_END		3
#define	TR_UDP_WPUT_START	4
#define	TR_UDP_WPUT_END		5
#define	TR_UDP_WPUT_OTHER_START	6
#define	TR_UDP_WPUT_OTHER_END	7

/*
 * TR_FAC_IP tags
 */

#define	TR_IP_OPEN		0
#define	TR_IP_CLOSE		1
#define	TR_IP_RPUT_START	2
#define	TR_IP_RPUT_END		3
#define	TR_IP_WPUT_START	4
#define	TR_IP_WPUT_END		5
#define	TR_IP_RPUT_LOCL_START	12
#define	TR_IP_RPUT_LOCL_END	13
#define	TR_IP_RPUT_LOCL_ERR	14
#define	TR_IP_RSRV_START	15
#define	TR_IP_RSRV_END		16
#define	TR_IP_CKSUM_START	17
#define	TR_IP_CKSUM_END		18
#define	TR_IP_WPUT_IRE_START	21
#define	TR_IP_WPUT_IRE_END	22
#define	TR_IP_WPUT_FRAG_START	23
#define	TR_IP_WPUT_FRAG_END	24
#define	TR_IP_WPUT_LOCAL_START	25
#define	TR_IP_WPUT_LOCAL_END	26

/*
 * TR_FAC_ARP tags
 */

#define	TR_ARP_OPEN		0
#define	TR_ARP_CLOSE		1
#define	TR_ARP_RPUT_START	2
#define	TR_ARP_RPUT_END		3
#define	TR_ARP_WPUT_START	4
#define	TR_ARP_WPUT_END		5
#define	TR_ARP_WSRV_START	6
#define	TR_ARP_WSRV_END		7

/*
 * TR_FAC_LE tags
 */

#define	TR_LE_OPEN		0
#define	TR_LE_CLOSE		1
#define	TR_LE_WPUT_START	2
#define	TR_LE_WPUT_END		3
#define	TR_LE_WSRV_START	4
#define	TR_LE_WSRV_END		5
#define	TR_LE_START_START	6
#define	TR_LE_START_END		7
#define	TR_LE_INTR_START	8
#define	TR_LE_INTR_END		9
#define	TR_LE_READ_START	10
#define	TR_LE_READ_END		11
#define	TR_LE_SENDUP_START	12
#define	TR_LE_SENDUP_END	13
#define	TR_LE_ADDUDIND_START	14
#define	TR_LE_ADDUDIND_END	15
#define	TR_LE_GETBUF_START	16
#define	TR_LE_GETBUF_END	17
#define	TR_LE_FREEBUF_START	18
#define	TR_LE_FREEBUF_END	19
#define	TR_LE_PROTO_START	20
#define	TR_LE_PROTO_END		21
#define	TR_LE_INIT_START	22
#define	TR_LE_INIT_END		23

/*
 * TR_FAC_BE tags
 */

#define	TR_BE_OPEN		0
#define	TR_BE_CLOSE		1
#define	TR_BE_WPUT_START	2
#define	TR_BE_WPUT_END		3
#define	TR_BE_WSRV_START	4
#define	TR_BE_WSRV_END		5
#define	TR_BE_START_START	6
#define	TR_BE_START_END		7
#define	TR_BE_INTR_START	8
#define	TR_BE_INTR_END		9
#define	TR_BE_READ_START	10
#define	TR_BE_READ_END		11
#define	TR_BE_SENDUP_START	12
#define	TR_BE_SENDUP_END	13
#define	TR_BE_ADDUDIND_START	14
#define	TR_BE_ADDUDIND_END	15
#define	TR_BE_PROTO_START	20
#define	TR_BE_PROTO_END		21
#define	TR_BE_INIT_START	22

/*
 * TR_FAC_PHYSIO
 */
#define	TR_PHYSIO_START			0
#define	TR_PHYSIO_LOCK_START		1
#define	TR_PHYSIO_LOCK_END		2
#define	TR_PHYSIO_UNLOCK_START		3
#define	TR_PHYSIO_UNLOCK_END		4
#define	TR_PHYSIO_GETBUF_START		5
#define	TR_PHYSIO_GETBUF_END		6
#define	TR_PHYSIO_END			7
#define	TR_PHYSIO_AS_LOCK_START		8
#define	TR_PHYSIO_SEG_LOCK_START	9
#define	TR_PHYSIO_SEG_LOCK_END		10
#define	TR_PHYSIO_AS_FAULT_START	11
#define	TR_PHYSIO_AS_LOCK_END		12
#define	TR_PHYSIO_AS_UNLOCK_START	13
#define	TR_PHYSIO_SEG_UNLOCK_START	14
#define	TR_PHYSIO_AS_UNLOCK_END		15
#define	TR_PHYSIO_SEGVN_START		16
#define	TR_PHYSIO_SEGVN_UNLOCK_END	17
#define	TR_PHYSIO_SEGVN_HIT_END		18
#define	TR_PHYSIO_SEGVN_FILL_END	19
#define	TR_PHYSIO_SEGVN_MISS_END	20

/*
 * TR_FAC_IA tags
 */

#define	TR_PID_ON		0
#define	TR_PID_OFF		1
#define	TR_GROUP_ON		2
#define	TR_GROUP_OFF		3
#define	TR_ACTIVE_CHAIN		5

/*
 * TR_FAC_SCSI tags
 */

#define	TR_ESPSVC_ACTION_CALL			0
#define	TR_ESPSVC_START				1
#define	TR_ESPSVC_END				2
#define	TR_ESP_CALLBACK_START			3
#define	TR_ESP_CALLBACK_END			4
#define	TR_ESP_DOPOLL_START			5
#define	TR_ESP_DOPOLL_END			6
#define	TR_ESP_FINISH_START			7
#define	TR_ESP_FINISH_END			8
#define	TR_ESP_FINISH_SELECT_START		9
#define	TR_ESP_FINISH_SELECT_RESET1_END		10
#define	TR_ESP_FINISH_SELECT_FINISH_END		13
#define	TR_ESP_FINISH_SELECT_ACTION1_END	14
#define	TR_ESP_FINISH_SELECT_ACTION2_END	15
#define	TR_ESP_FINISH_SELECT_RESET2_END		16
#define	TR_ESP_FINISH_SELECT_RESET3_END		17
#define	TR_ESP_FINISH_SELECT_ACTION3_END	18
#define	TR_ESP_HANDLE_CLEARING_START		19
#define	TR_ESP_HANDLE_CLEARING_END		20
#define	TR_ESP_HANDLE_CLEARING_RETURN1_END	22
#define	TR_ESP_HANDLE_CLEARING_ABORT_END	23
#define	TR_ESP_HANDLE_CLEARING_RETURN3_END	26
#define	TR_ESP_HANDLE_CMD_START_START		27
#define	TR_ESP_HANDLE_CMD_START_END		28
#define	TR_ESP_HANDLE_CMD_DONE_START		30
#define	TR_ESP_HANDLE_CMD_DONE_END		31
#define	TR_ESP_HANDLE_CMD_DONE_ABORT1_END	32
#define	TR_ESP_HANDLE_CMD_DONE_ABORT2_END	33
#define	TR_ESP_HANDLE_C_CMPLT_START		34
#define	TR_ESP_HANDLE_C_CMPLT_RETURN1_END	36
#define	TR_ESP_HANDLE_C_CMPLT_ACTION1_END	37
#define	TR_ESP_HANDLE_C_CMPLT_ACTION2_END	38
#define	TR_ESP_HANDLE_C_CMPLT_ACTION3_END	39
#define	TR_ESP_HANDLE_C_CMPLT_ACTION4_END	40
#define	TR_ESP_HANDLE_C_CMPLT_RETURN2_END	41
#define	TR_ESP_HANDLE_C_CMPLT_ACTION5_END	42
#define	TR_ESP_HANDLE_C_CMPLT_PHASEMANAGE_END	43
#define	TR_ESP_HANDLE_DATA_START		44
#define	TR_ESP_HANDLE_DATA_END			45
#define	TR_ESP_HANDLE_DATA_ABORT1_END		46
#define	TR_ESP_HANDLE_DATA_ABORT2_END		47
#define	TR_ESP_HANDLE_DATA_ABORT3_END		48
#define	TR_ESP_HANDLE_DATA_DONE_START		49
#define	TR_ESP_HANDLE_DATA_DONE_END		50
#define	TR_ESP_HANDLE_DATA_DONE_RESET_END	51
#define	TR_ESP_HANDLE_DATA_DONE_PHASEMANAGE_END	52
#define	TR_ESP_HANDLE_MORE_MSGIN_START		55
#define	TR_ESP_HANDLE_MORE_MSGIN_RETURN2_END	57
#define	TR_ESP_HANDLE_MSG_IN_START		58
#define	TR_ESP_HANDLE_MSG_IN_END		59
#define	TR_ESP_HANDLE_MSG_IN_DONE_START		60
#define	TR_ESP_HANDLE_MSG_IN_DONE_SNDMSG_END	64
#define	TR_ESP_HANDLE_MSG_IN_DONE_ACTION_END	65
#define	TR_ESP_HANDLE_MSG_IN_DONE_RETURN2_END	66
#define	TR_ESP_HANDLE_MSG_OUT_START		67
#define	TR_ESP_HANDLE_MSG_OUT_END		68
#define	TR_ESP_HANDLE_MSG_OUT_PHASEMANAGE_END	69
#define	TR_ESP_HANDLE_MSG_OUT_DONE_START	70
#define	TR_ESP_HANDLE_MSG_OUT_DONE_END		71
#define	TR_ESP_HANDLE_MSG_OUT_DONE_PHASEMANAGE_END	73
#define	TR_ESP_HANDLE_UNKNOWN_START		76
#define	TR_ESP_HANDLE_UNKNOWN_INT_DISCON_END	78
#define	TR_ESP_HANDLE_UNKNOWN_RESET_END		84
#define	TR_ESP_ISTART_START			89
#define	TR_ESP_ISTART_END			90
#define	TR_ESP_PHASEMANAGE_CALL			91
#define	TR_ESP_PHASEMANAGE_START		92
#define	TR_ESP_PHASEMANAGE_END			93
#define	TR_ESP_RECONNECT_START			96
#define	TR_ESP_RECONNECT_F2_END			99
#define	TR_ESP_RECONNECT_RETURN2_END		107
#define	TR_ESP_RECONNECT_RESET5_END		108
#define	TR_ESP_RUNPOLL_START			109
#define	TR_ESP_RUNPOLL_END			110
#define	TR_ESP_SCSI_IMPL_PKTALLOC_START		111
#define	TR_ESP_SCSI_IMPL_PKTALLOC_END		112
#define	TR_ESP_SCSI_IMPL_PKTFREE_START		113
#define	TR_ESP_SCSI_IMPL_PKTFREE_END		114
#define	TR_ESP_STARTCMD_START			115
#define	TR_ESP_STARTCMD_END			116
#define	TR_ESP_STARTCMD_RE_SELECTION_END	117
#define	TR_ESP_STARTCMD_ALLOC_TAG2_END		119
#define	TR_ESP_STARTCMD_PREEMPT_CALL		120
#define	TR_ESP_START_START			121
#define	TR_ESP_START_END			122
#define	TR_ESP_START_PREPARE_PKT_END		123
#define	TR_ESP_WATCH_START			124
#define	TR_ESP_WATCH_END			125
#define	TR_MAKE_SD_CMD_START			126
#define	TR_MAKE_SD_CMD_END			127
#define	TR_MAKE_SD_CMD_INIT_PKT_START		136
#define	TR_MAKE_SD_CMD_INIT_PKT_END		137
#define	TR_MAKE_SD_CMD_INIT_PKT_SBUF_START	138
#define	TR_MAKE_SD_CMD_INIT_PKT_SBUF_END	139
#define	TR_SDDONE_BIODONE_CALL			142
#define	TR_SDDONE_START				143
#define	TR_SDDONE_END				144
#define	TR_SDINTR_START				145
#define	TR_SDINTR_END				146
#define	TR_SDINTR_COMMAND_DONE_END		147
#define	TR_SDRUNOUT_START			150
#define	TR_SDRUNOUT_END				151
#define	TR_SDSTART_START			152
#define	TR_SDSTART_END				153
#define	TR_SDSTART_NO_WORK_END			154
#define	TR_SDSTART_NO_RESOURCES_END		155
#define	TR_SDSTRATEGY_START			156
#define	TR_SDSTRATEGY_END			157
#define	TR_SDSTRATEGY_DISKSORT_START		158
#define	TR_SDSTRATEGY_DISKSORT_END		159
#define	TR_SD_CHECK_ERROR_START			162
#define	TR_SD_CHECK_ERROR_END			164
#define	TR__ESP_START_START			165
#define	TR__ESP_START_END			166
#define	TR_ESP_EMPTY_STARTQ_START		169
#define	TR_ESP_EMPTY_STARTQ_END			170
#define	TR_SDSTRATEGY_SMALL_WINDOW_START	171
#define	TR_SDSTRATEGY_SMALL_WINDOW_END		172
#define	TR_SDSTART_SMALL_WINDOW_START		173
#define	TR_SDSTART_SMALL_WINDOW_END		174
#define	TR_ESP_USTART_START			175
#define	TR_ESP_USTART_END			176
#define	TR_ESP_USTART_NOT_FOUND_END		177
#define	TR_ESP_USTART_DEFAULT_END		178
#define	TR_ESP_PREPARE_PKT_TRAN_BADPKT_END	180
#define	TR_ESP_PREPARE_PKT_TRAN_ACCEPT_END	181
#define	TR_ESP_ALLOC_TAG_START			182
#define	TR_ESP_ALLOC_TAG_END			183
#define	TR_ESP_CALL_PKT_COMP_START		184
#define	TR_ESP_CALL_PKT_COMP_END		185
#define	TR_ESP_SCSI_IMPL_DMAFREE_START		192
#define	TR_ESP_SCSI_IMPL_DMAFREE_END		193

/*
 * TR_FAC_SCSI_ISP tags
 */

#define	TR_ISP_SCSI_GETCAP_START	1
#define	TR_ISP_SCSI_GETCAP_END		2
#define	TR_ISP_SCSI_SETCAP_START	3
#define	TR_ISP_SCSI_SETCAP_END		4
#define	TR_ISP_SCSI_START_START		7
#define	TR_ISP_SCSI_START_DMA_START	8
#define	TR_ISP_SCSI_START_DMA_END	9
#define	TR_ISP_SCSI_START_END		10
#define	TR_ISP_I_START_CMD_START	11
#define	TR_ISP_I_START_CMD_Q_FULL_END	12
#define	TR_ISP_I_START_CMD_END		15
#define	TR_ISP_I_RUN_POLLED_CMD_START	16
#define	TR_ISP_I_RUN_POLLED_CMD_END	17
#define	TR_ISP_INTR_START		18
#define	TR_ISP_INTR_Q_END		25
#define	TR_ISP_INTR_END			26
#define	TR_ISP_I_ASYNCH_EVENT_START	33
#define	TR_ISP_I_ASYNCH_EVENT_END	34
#define	TR_ISP_I_WATCH_START		43
#define	TR_ISP_I_WATCH_END		44
#define	TR_ISP_I_TIMEOUT_START		45
#define	TR_ISP_I_TIMEOUT_END		46
#define	TR_ISP_I_QFLUSH_START		47
#define	TR_ISP_I_QFLUSH_END		48
#define	TR_ISP_I_SET_MARKER_START	49
#define	TR_ISP_I_SET_MARKER_END		50
#define	TR_ISP_SCSI_ABORT_START		51
#define	TR_ISP_SCSI_ABORT_END		53
#define	TR_ISP_SCSI_RESET_START		54
#define	TR_ISP_SCSI_RESET_END		56
#define	TR_ISP_I_RESET_INTERFACE_START	57
#define	TR_ISP_I_RESET_INTERFACE_END	58
#define	TR_ISP_I_CALL_PKT_COMP_START	59
#define	TR_ISP_I_CALL_PKT_COMP_END	60
#define	TR_ISP_I_EMPTY_WAITQ_START	61
#define	TR_ISP_I_EMPTY_WAITQ_END	62
#define	TR_ISP_I_START_CMD_AFTER_SYNC	66
#define	TR_ISP_INTR_ASYNC_END		69
#define	TR_ISP_INTR_MBOX_END		70
#define	TR_ISP_I_MBOX_CMD_COMPLETE_START	74
#define	TR_ISP_I_MBOX_CMD_COMPLETE_END		75
#define	TR_ISP_I_MBOX_CMD_START_START		76
#define	TR_ISP_I_MBOX_CMD_START_END		77
#define	TR_ISP_SCSI_PKTALLOC_START	78
#define	TR_ISP_SCSI_PKTALLOC_END	79
#define	TR_ISP_SCSI_PKTFREE_START	80
#define	TR_ISP_SCSI_PKTFREE_DONE	81
#define	TR_ISP_SCSI_PKTFREE_END		82
#define	TR_ISP_SCSI_DMAGET_START	83
#define	TR_ISP_SCSI_DMAGET_ERROR_END	84
#define	TR_ISP_SCSI_DMAGET_END		85
#define	TR_ISP_SCSI_DMAFREE_START	86
#define	TR_ISP_SCSI_DMAFREE_END		87
#define	TR_ISP_I_RESET_INIT_CHIP_START	88
#define	TR_ISP_I_RESET_INIT_CHIP_END	89

/*
 * TR_FAC_SCSI_FAS tags
 */

#define	TR_FASSVC_ACTION_CALL			1
#define	TR_FASSVC_END				2
#define	TR_FASSVC_START				3
#define	TR_FAS_ALLOC_TAG_END			4
#define	TR_FAS_ALLOC_TAG_START			5
#define	TR_FAS_DOPOLL_END			6
#define	TR_FAS_DOPOLL_START			7
#define	TR_FAS_EMPTY_WAITQ_END			8
#define	TR_FAS_EMPTY_WAITQ_START		9
#define	TR_FAS_FINISH_END			10
#define	TR_FAS_FINISH_SELECT_ACTION3_END	11
#define	TR_FAS_FINISH_SELECT_FINISH_END		12
#define	TR_FAS_FINISH_SELECT_RESET1_END		13
#define	TR_FAS_FINISH_SELECT_RESET2_END		14
#define	TR_FAS_FINISH_SELECT_START		16
#define	TR_FAS_FINISH_START			17
#define	TR_FAS_HANDLE_CLEARING_ABORT_END	18
#define	TR_FAS_HANDLE_CLEARING_END		19
#define	TR_FAS_HANDLE_CLEARING_START		22
#define	TR_FAS_HANDLE_CMD_DONE_END		24
#define	TR_FAS_HANDLE_CMD_DONE_START		25
#define	TR_FAS_HANDLE_CMD_START_END		26
#define	TR_FAS_HANDLE_CMD_START_START		27
#define	TR_FAS_HANDLE_C_CMPLT_ACTION1_END	28
#define	TR_FAS_HANDLE_C_CMPLT_ACTION2_END	29
#define	TR_FAS_HANDLE_C_CMPLT_START		34
#define	TR_FAS_HANDLE_DATA_ABORT1_END		35
#define	TR_FAS_HANDLE_DATA_ABORT2_END		36
#define	TR_FAS_HANDLE_DATA_DONE_ACTION2_END	37
#define	TR_FAS_HANDLE_DATA_DONE_RESET_END	39
#define	TR_FAS_HANDLE_DATA_DONE_START		40
#define	TR_FAS_HANDLE_DATA_END			41
#define	TR_FAS_HANDLE_DATA_START		42
#define	TR_FAS_HANDLE_MORE_MSGIN_RETURN2_END	43
#define	TR_FAS_HANDLE_MORE_MSGIN_START		44
#define	TR_FAS_HANDLE_MSG_IN_DONE_ACTION_END	45
#define	TR_FAS_HANDLE_MSG_IN_DONE_RETURN2_END	46
#define	TR_FAS_HANDLE_MSG_IN_DONE_SNDMSG_END	47
#define	TR_FAS_HANDLE_MSG_IN_DONE_START		48
#define	TR_FAS_HANDLE_MSG_IN_END		49
#define	TR_FAS_HANDLE_MSG_IN_START		50
#define	TR_FAS_HANDLE_MSG_OUT_DONE_END		51
#define	TR_FAS_HANDLE_MSG_OUT_DONE_START	53
#define	TR_FAS_HANDLE_MSG_OUT_END		54
#define	TR_FAS_HANDLE_MSG_OUT_PHASEMANAGE_END	55
#define	TR_FAS_HANDLE_MSG_OUT_START		56
#define	TR_FAS_HANDLE_UNKNOWN_INT_DISCON_END	57
#define	TR_FAS_HANDLE_UNKNOWN_RESET_END		58
#define	TR_FAS_HANDLE_UNKNOWN_START		59
#define	TR_FAS_ISTART_END			60
#define	TR_FAS_ISTART_START			61
#define	TR_FAS_PHASEMANAGE_CALL			62
#define	TR_FAS_PHASEMANAGE_END			63
#define	TR_FAS_PHASEMANAGE_START		64
#define	TR_FAS_POLL_END				65
#define	TR_FAS_POLL_START			66
#define	TR_FAS_PREPARE_PKT_TRAN_ACCEPT_END	67
#define	TR_FAS_PREPARE_PKT_TRAN_BADPKT_END	68
#define	TR_FAS_RECONNECT_RESET5_END		70
#define	TR_FAS_RECONNECT_RETURN2_END		71
#define	TR_FAS_RECONNECT_START			72
#define	TR_FAS_RUNPOLL_END			73
#define	TR_FAS_RUNPOLL_START			74
#define	TR_FAS_SCSI_IMPL_DMAFREE_END		75
#define	TR_FAS_SCSI_IMPL_DMAFREE_START		76
#define	TR_FAS_SCSI_IMPL_PKTALLOC_END		77
#define	TR_FAS_SCSI_IMPL_PKTALLOC_START		78
#define	TR_FAS_SCSI_IMPL_PKTFREE_END		79
#define	TR_FAS_SCSI_IMPL_PKTFREE_START		80
#define	TR_FAS_STARTCMD_END			81
#define	TR_FAS_STARTCMD_START			82
#define	TR_FAS_START_END			83
#define	TR_FAS_START_PREPARE_PKT_END		84
#define	TR_FAS_START_START			85
#define	TR_FAS_USTART_END			86
#define	TR_FAS_USTART_NOT_FOUND_END		87
#define	TR_FAS_USTART_START			88
#define	TR_FAS_WATCH_END			89
#define	TR_FAS_SCSI_IMPL_DMAGET_END		90
#define	TR_FAS_SCSI_IMPL_DMAGET_START		91
#define	TR__FAS_START_END			92
#define	TR__FAS_START_START			93
#define	TR_FAS_EMPTY_CALLBACKQ_START		111
#define	TR_FAS_EMPTY_CALLBACKQ_END		112
#define	TR_FAS_CALL_PKT_COMP_START		113
#define	TR_FAS_CALL_PKT_COMP_END		114

/*
 * TR_FAC_CALLOUT tags
 */

#define	TR_TIMEOUT			0
#define	TR_UNTIMEOUT			1
#define	TR_UNTIMEOUT_BOGUS_ID		2
#define	TR_UNTIMEOUT_EXECUTING		3
#define	TR_UNTIMEOUT_SELF		4
#define	TR_CALLOUT_START		5
#define	TR_CALLOUT_END			6

/*
 * TR_FAC_SPECFS tags
 */

#define	TR_SPECFS_GETPAGE	0
#define	TR_SPECFS_GETAPAGE	1
#define	TR_SPECFS_PUTPAGE	2
#define	TR_SPECFS_PUTAPAGE	3
#define	TR_SPECFS_SEGMAP	4
#define	TR_SPECFS_OPEN		5

/*
 * TR_FAC_TMPFS tags
 */

#define	TR_TMPFS_LOOKUP		0
#define	TR_TMPFS_CREATE		1
#define	TR_TMPFS_REMOVE		2
#define	TR_TMPFS_RENAME		3
#define	TR_TMPFS_RWTMP_START	4
#define	TR_TMPFS_RWTMP_END	5

/*
 * TR_FAC_SWAPFS tags
 */

#define	TR_SWAPFS_GETPAGE	2
#define	TR_SWAPFS_GETAPAGE	3
#define	TR_SWAPFS_PUTPAGE	4
#define	TR_SWAPFS_PUTAPAGE	5

/*
 * TR_FAC_UFS tags
 */

#define	TR_UFS_SYNCIP_START	0
#define	TR_UFS_SYNCIP_END	1
#define	TR_UFS_OPEN		2
#define	TR_UFS_CLOSE		4
#define	TR_UFS_READ_START	6
#define	TR_UFS_READ_END		7
#define	TR_UFS_WRITE_START	8
#define	TR_UFS_WRITE_END	9
#define	TR_UFS_RWIP_START	10
#define	TR_UFS_RWIP_END		11
#define	TR_UFS_GETATTR_START	12
#define	TR_UFS_GETATTR_END	13
#define	TR_UFS_SETATTR_START	14
#define	TR_UFS_SETATTR_END	15
#define	TR_UFS_ACCESS_START	16
#define	TR_UFS_ACCESS_END	17
#define	TR_UFS_READLINK_START	18
#define	TR_UFS_READLINK_END	19
#define	TR_UFS_FSYNC_START	20
#define	TR_UFS_FSYNC_END	21
#define	TR_UFS_LOOKUP_START	22
#define	TR_UFS_LOOKUP_END	23
#define	TR_UFS_CREATE_START	24
#define	TR_UFS_CREATE_END	25
#define	TR_UFS_REMOVE_START	26
#define	TR_UFS_REMOVE_END	27
#define	TR_UFS_LINK_START	28
#define	TR_UFS_LINK_END		29
#define	TR_UFS_RENAME_START	30
#define	TR_UFS_RENAME_END	31
#define	TR_UFS_MKDIR_START	32
#define	TR_UFS_MKDIR_END	33
#define	TR_UFS_RMDIR_START	34
#define	TR_UFS_RMDIR_END	35
#define	TR_UFS_READDIR_START	36
#define	TR_UFS_READDIR_END	37
#define	TR_UFS_SYMLINK_START	38
#define	TR_UFS_SYMLINK_END	39
#define	TR_UFS_GETPAGE_START	40
#define	TR_UFS_GETPAGE_END	41
#define	TR_UFS_PUTPAGE_START	44
#define	TR_UFS_PUTPAGE_END	45
#define	TR_UFS_PUTAPAGE_START	46
#define	TR_UFS_PUTAPAGE_END	47
#define	TR_UFS_MAP_START	48
#define	TR_UFS_MAP_END		49
#define	TR_UFS_GETSECATTR_START	50
#define	TR_UFS_GETSECATTR_END	51
#define	TR_UFS_SETSECATTR_START	52
#define	TR_UFS_SETSECATTR_END	53

/*
 * TR_FAC_NFS tags
 *
 *	Simple convention: client tags range from 0-99, server
 *	tags range from 100 up.
 */

#define	TR_RFSCALL_START	0
#define	TR_RFSCALL_END		1
#define	TR_FHTOVP_START		2
#define	TR_FHTOVP_END		3

#define	TR_VOP_GETATTR_START	100
#define	TR_VOP_GETATTR_END	101
#define	TR_VOP_SETATTR_START	102
#define	TR_VOP_SETATTR_END	103
#define	TR_VOP_LOOKUP_START	104
#define	TR_VOP_LOOKUP_END	105
#define	TR_VOP_READLINK_START	106
#define	TR_VOP_READLINK_END	107
#define	TR_VOP_RWLOCK_START	108
#define	TR_VOP_RWLOCK_END	109
#define	TR_VOP_ACCESS_START	110
#define	TR_VOP_ACCESS_END	111
#define	TR_VOP_READ_START	114
#define	TR_VOP_READ_END		115
#define	TR_VOP_RWUNLOCK_START	118
#define	TR_VOP_RWUNLOCK_END	119
#define	TR_VOP_WRITE_START	120
#define	TR_VOP_WRITE_END	121
#define	TR_VOP_CREATE_START	122
#define	TR_VOP_CREATE_END	123
#define	TR_VOP_REMOVE_START	124
#define	TR_VOP_REMOVE_END	125
#define	TR_VOP_RENAME_START	126
#define	TR_VOP_RENAME_END	127
#define	TR_VOP_LINK_START	128
#define	TR_VOP_LINK_END		129
#define	TR_VOP_SYMLINK_START	130
#define	TR_VOP_SYMLINK_END	131
#define	TR_VOP_MKDIR_START	132
#define	TR_VOP_MKDIR_END	133
#define	TR_VOP_RMDIR_START	134
#define	TR_VOP_RMDIR_END	135
#define	TR_VOP_READDIR_START	136
#define	TR_VOP_READDIR_END	137
#define	TR_RFS_GETATTR_START	142
#define	TR_RFS_GETATTR_END	143
#define	TR_RFS_SETATTR_START	144
#define	TR_RFS_SETATTR_END	145
#define	TR_RFS_LOOKUP_START	146
#define	TR_RFS_LOOKUP_END	147
#define	TR_RFS_READLINK_START	148
#define	TR_RFS_READLINK_END	149
#define	TR_RFS_READ_START	150
#define	TR_RFS_READ_END		151
#define	TR_RFS_WRITE_START	152
#define	TR_RFS_WRITE_END	153
#define	TR_RFS_CREATE_START	154
#define	TR_RFS_CREATE_END	155
#define	TR_RFS_REMOVE_START	156
#define	TR_RFS_REMOVE_END	157
#define	TR_RFS_RENAME_START	158
#define	TR_RFS_RENAME_END	159
#define	TR_RFS_LINK_START	160
#define	TR_RFS_LINK_END		161
#define	TR_RFS_SYMLINK_START	162
#define	TR_RFS_SYMLINK_END	163
#define	TR_RFS_MKDIR_START	164
#define	TR_RFS_MKDIR_END	165
#define	TR_RFS_RMDIR_START	166
#define	TR_RFS_RMDIR_END	167
#define	TR_RFS_READDIR_START	168
#define	TR_RFS_READDIR_END	169
#define	TR_RFS_STATFS_START	170
#define	TR_RFS_STATFS_END	171
#define	TR_SVC_SENDREPLY_START	178
#define	TR_SVC_SENDREPLY_END	179

/* More VOP calls */
#define	TR_VOP_FSYNC_START	180
#define	TR_VOP_FSYNC_END	181
#define	TR_VOP_PUTPAGE_START	182
#define	TR_VOP_PUTPAGE_END	183
#define	TR_SVC_GETARGS_START	186
#define	TR_SVC_GETARGS_END	187
#define	TR_CHECKEXPORT_START	188
#define	TR_CHECKEXPORT_END	189
#define	TR_SVC_FREEARGS_START	192
#define	TR_SVC_FREEARGS_END	193

/* NFS fast path server trace points */
#define	TR_NFSFP_QUE_REQ_ENQ	212
#define	TR_NFSFP_QUE_REQ_DEQ	213
#define	TR_SVC_FREERES_START	222
#define	TR_SVC_FREERES_END	223

/* Name cache tracing */
#define	TR_DNLC_ENTER_START	218
#define	TR_DNLC_ENTER_END	219
#define	TR_DNLC_LOOKUP_START	220
#define	TR_DNLC_LOOKUP_END	221

/* Common dispatch tracing */
#define	TR_CMN_DISPATCH_START	224
#define	TR_CMN_PROC_START	225
#define	TR_CMN_PROC_END		226
#define	TR_CMN_DISPATCH_END	227

/* More VOP calls */
#define	TR_VOP_SPACE_START	228
#define	TR_VOP_SPACE_END	229

/*
 * TR_FAC_KRPC tags
 */

#define	TR_SVC_GETREQ_START		0
#define	TR_SVC_RUN			4
#define	TR_SVC_CLTS_KRECV_START		5
#define	TR_SVC_CLTS_KRECV_END		6
#define	TR_XDR_CALLMSG_START		7
#define	TR_XDR_CALLMSG_END		8
#define	TR_SVC_CLTS_KSEND_START		9
#define	TR_SVC_CLTS_KSEND_END		10
#define	TR_XDR_REPLYMSG_START		11
#define	TR_XDR_REPLYMSG_END		12
#define	TR_RPCMODOPEN_START		13
#define	TR_RPCMODOPEN_END		14
#define	TR_RPCMODRPUT_START		15
#define	TR_RPCMODRPUT_END		16
#define	TR_SVC_QUEUEREQ_START		23
#define	TR_SVC_QUEUEREQ_END		24
#define	TR_SVC_GETREQ_AUTH_START	25
#define	TR_SVC_GETREQ_AUTH_END		26
#define	TR_SVC_COTS_KRECV_START		32
#define	TR_SVC_COTS_KRECV_END		33
#define	TR_SVC_COTS_KDUP_DONE		34
#define	TR_SVC_COTS_KSEND_START		36
#define	TR_SVC_COTS_KSEND_END		37

/*
 * TR_FAC_SCSI_RES
 */

#define	TR_SCSI_INIT_PKT_START				0
#define	TR_SCSI_INIT_PKT_END				3
#define	TR_SCSI_ALLOC_CONSISTENT_BUF_START		10
#define	TR_SCSI_ALLOC_CONSISTENT_BUF_END		14
#define	TR_SCSI_FREE_CONSISTENT_BUF_START		15
#define	TR_SCSI_FREE_CONSISTENT_BUF_END			16
#define	TR_SCSI_IMPL_DMAGET_START			24
#define	TR_SCSI_IMPL_DMAGET_END				25
#define	TR_SCSI_DESTROY_PKT_START			28
#define	TR_SCSI_DESTROY_PKT_END				29

#define	TR_FIFOREAD_WAIT	3
#define	TR_FIFOREAD_WAKE	4
#define	TR_FIFOWRITE_OUT	7
#define	TR_FIFOWRITE_WAIT	9
#define	TR_FIFOWRITE_WAKE	10

#define	TR_RLOGINP_RPUT_IN	0
#define	TR_RLOGINP_RPUT_OUT	1
#define	TR_RLOGINP_RSRV_IN	2
#define	TR_RLOGINP_RSRV_OUT	3
#define	TR_RLOGINP_WSRV_IN	4
#define	TR_RLOGINP_WSRV_OUT	5
#define	TR_RLOGINP_WPUT_IN	6
#define	TR_RLOGINP_WPUT_OUT	7
#define	TR_RLOGINP_WINCTL_IN	8
#define	TR_RLOGINP_WINCTL_OUT	9

/*
 * TR_FAC_SOCKFS tags
 */
#define	TR_SOCKFS_OPEN		0

/*
 * TR_FAC_DEVMAP tags
 */

#define	TR_DEVMAP_DUP			0
#define	TR_DEVMAP_UNMAP			1
#define	TR_DEVMAP_FREE			2
#define	TR_DEVMAP_FAULT			3
#define	TR_DEVMAP_FAULTA		4
#define	TR_DEVMAP_SETPROT		5
#define	TR_DEVMAP_CHECKPROT		6
#define	TR_DEVMAP_SEGDEV_BADOP		7
#define	TR_DEVMAP_SYNC			8
#define	TR_DEVMAP_INCORE		9
#define	TR_DEVMAP_LOCKOP		10
#define	TR_DEVMAP_GETPROT		11
#define	TR_DEVMAP_GETOFFSET		12
#define	TR_DEVMAP_GETTYPE		13
#define	TR_DEVMAP_GETVP			14
#define	TR_DEVMAP_ADVISE		15
#define	TR_DEVMAP_PAGELOCK		17
#define	TR_DEVMAP_GETMEMID		18
#define	TR_DEVMAP_SOFTUNLOCK		19
#define	TR_DEVMAP_FAULTPAGE		20
#define	TR_DEVMAP_FAULTPAGES		21
#define	TR_DEVMAP_SEGMAP_SETUP		22
#define	TR_DEVMAP_DEVICE		23
#define	TR_DEVMAP_DO_CTXMGT		24
#define	TR_DEVMAP_ROUNDUP		25
#define	TR_DEVMAP_FIND_HANDLE		26
#define	TR_DEVMAP_UNLOAD		27
#define	TR_DEVMAP_GET_LARGE_PGSIZE	28
#define	TR_DEVMAP_SOFTLOCK_INIT		29
#define	TR_DEVMAP_SOFTLOCK_RELE		30
#define	TR_DEVMAP_CTX_RELE		31
#define	TR_DEVMAP_LOAD			32
#define	TR_DEVMAP_SETUP			33
#define	TR_DEVMAP_SEGMAP		34
#define	TR_DEVMAP_DEVMEM_SETUP		35
#define	TR_DEVMAP_DEVMEM_REMAP		36
#define	TR_DEVMAP_UMEM_SETUP		37
#define	TR_DEVMAP_UMEM_REMAP		38
#define	TR_DEVMAP_SET_CTX_TIMEOUT	39
#define	TR_DEVMAP_DEFAULT_ACCESS	40
#define	TR_DEVMAP_UMEM_ALLOC		41
#define	TR_DEVMAP_UMEM_FREE		42
#define	TR_DEVMAP_CTXTO			43
#define	TR_DEVMAP_DUP_CK1		44
#define	TR_DEVMAP_UNMAP_CK1		45
#define	TR_DEVMAP_UNMAP_CK2		46
#define	TR_DEVMAP_UNMAP_CK3		47
#define	TR_DEVMAP_FAULT_CK1		48
#define	TR_DEVMAP_SETPROT_CK1		49
#define	TR_DEVMAP_FAULTPAGE_CK1		50
#define	TR_DEVMAP_DO_CTXMGT_CK1		51
#define	TR_DEVMAP_DO_CTXMGT_CK2		52
#define	TR_DEVMAP_DO_CTXMGT_CK3		53
#define	TR_DEVMAP_DO_CTXMGT_CK4		54
#define	TR_DEVMAP_ROUNDUP_CK1		55
#define	TR_DEVMAP_ROUNDUP_CK2		56
#define	TR_DEVMAP_CTX_RELE_CK1		57

/*
 * TR_FAC_DAD tags
 */

#define	TR_DCDSTRATEGY_START				1
#define	TR_DCDSTRATEGY_DISKSORT_START			2
#define	TR_DCDSTRATEGY_DISKSORT_END			3
#define	TR_DCDSTRATEGY_SMALL_WINDOW_START		4
#define	TR_DCDSTRATEGY_SMALL_WINDOW_END			5
#define	TR_DCDSTRATEGY_END				6
#define	TR_DCDSTART_START				7
#define	TR_DCDSTART_NO_WORK_END				8
#define	TR_DCDSTART_NO_RESOURCES_END			9
#define	TR_DCASTART_SMALL_WINDOW_START			10
#define	TR_DCDSTART_SMALL_WINDOW_END			11
#define	TR_DCDSTART_END					12
#define	TR_MAKE_DCD_CMD_START				13
#define	TR_MAKE_DCD_CMD_INIT_PKT_START			14
#define	TR_MAKE_DCD_CMD_INIT_PKT_END			15
#define	TR_MAKE_DCD_CMD_END				17
#define	TR_DCDINTR_START				18
#define	TR_DCDINTR_COMMAND_DONE_END			19
#define	TR_DCDINTR_END					20
#define	TR_DCDONE_START					21
#define	TR_DCDDONE_BIODONE_CALL				22
#define	TR_DCDDONE_END					23
#define	TR_DCD_CHECK_ERROR_START			24
#define	TR_DCD_CHECK_ERROR_END				25
#define	TR_DCDRUNOUT_START				26
#define	TR_DCDRUNOUT_END				27

#if defined(DEBUG) || defined(lint) || defined(__lint)

#define	TRACE_0(fac, tag, name) {				\
	extern void __dtrace_probe___vtrace_##tag(void);	\
	__dtrace_probe___vtrace_##tag();			\
}

#define	TRACE_1(fac, tag, name, d1) {				\
	extern void __dtrace_probe___vtrace_##tag(ulong_t);	\
	__dtrace_probe___vtrace_##tag((ulong_t)(d1));		\
}

#define	TRACE_2(fac, tag, name, d1, d2) {			\
	extern void __dtrace_probe___vtrace_##tag(ulong_t, ulong_t);	\
	__dtrace_probe___vtrace_##tag((ulong_t)(d1), (ulong_t)(d2));	\
}

#define	TRACE_3(fac, tag, name, d1, d2, d3) {				\
	extern void __dtrace_probe___vtrace_##tag(ulong_t, ulong_t, ulong_t); \
	__dtrace_probe___vtrace_##tag((ulong_t)(d1), (ulong_t)(d2), \
	    (ulong_t)(d3));	\
}

#define	TRACE_4(fac, tag, name, d1, d2, d3, d4) {			\
	extern void __dtrace_probe___vtrace_##tag(ulong_t, ulong_t, ulong_t, \
	    ulong_t); \
	__dtrace_probe___vtrace_##tag((ulong_t)(d1), (ulong_t)(d2), \
	    (ulong_t)(d3), (ulong_t)(d4));	\
}

#define	TRACE_5(fac, tag, name, d1, d2, d3, d4, d5) {			\
	extern void __dtrace_probe___vtrace_##tag(ulong_t, ulong_t, ulong_t, \
	    ulong_t, ulong_t); \
	__dtrace_probe___vtrace_##tag((ulong_t)(d1), (ulong_t)(d2), \
	    (ulong_t)(d3), (ulong_t)(d4), (ulong_t)(d5));	\
}

#else

#define	TRACE_0(fac, tag, name)
#define	TRACE_1(fac, tag, name, d1)
#define	TRACE_2(fac, tag, name, d1, d2)
#define	TRACE_3(fac, tag, name, d1, d2, d3)
#define	TRACE_4(fac, tag, name, d1, d2, d3, d4)
#define	TRACE_5(fac, tag, name, d1, d2, d3, d4, d5)

#endif

#ifdef	__cplusplus
}
#endif

#endif	/* _SYS_VTRACE_H */
