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

#ifndef	_SYS_EXACCT_CATALOG_H
#define	_SYS_EXACCT_CATALOG_H

#ifdef	__cplusplus
extern "C" {
#endif

/*
 * exacct_catalog.h contains the default catalog for SunOS resource values
 * reported via the extended accounting facility.  Each recorded value written
 * to an exacct file is identified via its catalog tag, which is the first four
 * bytes of each object.  The exacct catalog tag is a 32-bit integer partitioned
 * into three fields, as illustrated by the following diagram.
 *
 * 31	   27	   23						  0
 * +-------+-------+----------------------------------------------+
 * |type   |catalog|id						  |
 * +-------+-------+----------------------------------------------+
 *
 * Each of the fields is described in more detail below.
 */

/*
 * Data type field.  These should correspond to the values of an ea_item_type_t,
 * shifted left 28 bits, plus the special value for a record group.  All
 * unspecified values of this field are reserved for future use.
 */
#define	EXT_TYPE_MASK		((uint_t)0xf << 28)

#define	EXT_NONE		((uint_t)0x0 << 28)
#define	EXT_UINT8		((uint_t)0x1 << 28)
#define	EXT_UINT16		((uint_t)0x2 << 28)
#define	EXT_UINT32		((uint_t)0x3 << 28)
#define	EXT_UINT64		((uint_t)0x4 << 28)
#define	EXT_DOUBLE		((uint_t)0x5 << 28)
#define	EXT_STRING		((uint_t)0x6 << 28)
#define	EXT_EXACCT_OBJECT	((uint_t)0x7 << 28)
#define	EXT_RAW			((uint_t)0x8 << 28)
#define	EXT_GROUP		((uint_t)0xf << 28)

/*
 * The catalog type field is the second four bits of the catalog tag.  All
 * unspecified values of this field are reserved for future use.
 */
#define	EXC_CATALOG_MASK	((uint_t)0xf << 24)

#define	EXC_NONE		(0x0 << 24)
#define	EXC_LOCAL		(0x1 << 24)
#define	EXC_DEFAULT		EXC_NONE

/*
 * The data id field comprises the final 24 bits of an ea_catalog_t.  The
 * current Solaris data ids defined in this version of the exacct format follow.
 * All values of this field are reserved if the catalog type is EXC_DEFAULT.  If
 * the catalog type is EXC_LOCAL, this field is application defined.
 */
#define	EXD_DATA_MASK		0xffffff

#define	EXD_NONE		0x000000

#define	EXD_VERSION		0x000001
#define	EXD_FILETYPE		0x000002
#define	EXD_CREATOR		0x000003
#define	EXD_HOSTNAME		0x000004

#define	EXD_GROUP_HEADER	0x0000ff
#define	EXD_GROUP_PROC		0x000100
#define	EXD_GROUP_TASK		0x000101
#define	EXD_GROUP_LWP		0x000102
#define	EXD_GROUP_PROC_TAG	0x000103
#define	EXD_GROUP_TASK_TAG	0x000104
#define	EXD_GROUP_LWP_TAG	0x000105
#define	EXD_GROUP_PROC_PARTIAL	0x000106
#define	EXD_GROUP_TASK_PARTIAL	0x000107
#define	EXD_GROUP_TASK_INTERVAL	0x000108
#define	EXD_GROUP_FLOW		0x000109
#define	EXD_GROUP_RFMA		0x00010a
#define	EXD_GROUP_FMA		0x00010b
#define	EXD_GROUP_NET_LINK_DESC	0X00010c
#define	EXD_GROUP_NET_FLOW_DESC	0X00010d
#define	EXD_GROUP_NET_LINK_STATS	0X00010e
#define	EXD_GROUP_NET_FLOW_STATS	0X00010f

#define	EXD_PROC_PID		0x001000
#define	EXD_PROC_UID		0x001001
#define	EXD_PROC_GID		0x001002
#define	EXD_PROC_TASKID		0x001003
#define	EXD_PROC_PROJID		0x001004
#define	EXD_PROC_HOSTNAME	0x001005
#define	EXD_PROC_COMMAND	0x001006
#define	EXD_PROC_START_SEC	0x001007
#define	EXD_PROC_START_NSEC	0x001008
#define	EXD_PROC_FINISH_SEC	0x001009
#define	EXD_PROC_FINISH_NSEC	0x00100a
#define	EXD_PROC_CPU_USER_SEC	0x00100b
#define	EXD_PROC_CPU_USER_NSEC	0x00100c
#define	EXD_PROC_CPU_SYS_SEC	0x00100d
#define	EXD_PROC_CPU_SYS_NSEC	0x00100e
#define	EXD_PROC_TTY_MAJOR	0x00100f
#define	EXD_PROC_TTY_MINOR	0x001010
#define	EXD_PROC_FAULTS_MAJOR	0x001011
#define	EXD_PROC_FAULTS_MINOR	0x001012
#define	EXD_PROC_MESSAGES_RCV	0x001013
#define	EXD_PROC_MESSAGES_SND	0x001014
#define	EXD_PROC_BLOCKS_IN	0x001015
#define	EXD_PROC_BLOCKS_OUT	0x001016
#define	EXD_PROC_CHARS_RDWR	0x001017
#define	EXD_PROC_CONTEXT_VOL	0x001018
#define	EXD_PROC_CONTEXT_INV	0x001019
#define	EXD_PROC_SIGNALS	0x00101a
#define	EXD_PROC_SWAPS		0x00101b
#define	EXD_PROC_SYSCALLS	0x00101c
#define	EXD_PROC_ACCT_FLAGS	0x00101d
#define	EXD_PROC_TAG		0x00101e
#define	EXD_PROC_ANCPID		0x00101f
#define	EXD_PROC_WAIT_STATUS	0x001020
#define	EXD_PROC_ZONENAME	0x001021
/*
 * Physical memory usage estimates, in kilobytes.  Counts usage due to
 * both memory used exclusively by the process, and memory shared with
 * other processes.
 */
#define	EXD_PROC_MEM_RSS_AVG_K	0x001022
#define	EXD_PROC_MEM_RSS_MAX_K	0x001023

#define	EXD_TASK_TASKID		0x002000
#define	EXD_TASK_PROJID		0x002001
#define	EXD_TASK_HOSTNAME	0x002002
#define	EXD_TASK_START_SEC	0x002003
#define	EXD_TASK_START_NSEC	0x002004
#define	EXD_TASK_FINISH_SEC	0x002005
#define	EXD_TASK_FINISH_NSEC	0x002006
#define	EXD_TASK_CPU_USER_SEC	0x002007
#define	EXD_TASK_CPU_USER_NSEC	0x002008
#define	EXD_TASK_CPU_SYS_SEC	0x002009
#define	EXD_TASK_CPU_SYS_NSEC	0x00200a
#define	EXD_TASK_FAULTS_MAJOR	0x00200b
#define	EXD_TASK_FAULTS_MINOR	0x00200c
#define	EXD_TASK_MESSAGES_RCV	0x00200d
#define	EXD_TASK_MESSAGES_SND	0x00200e
#define	EXD_TASK_BLOCKS_IN	0x00200f
#define	EXD_TASK_BLOCKS_OUT	0x002010
#define	EXD_TASK_CHARS_RDWR	0x002011
#define	EXD_TASK_CONTEXT_VOL	0x002012
#define	EXD_TASK_CONTEXT_INV	0x002013
#define	EXD_TASK_SIGNALS	0x002014
#define	EXD_TASK_SWAPS		0x002015
#define	EXD_TASK_SYSCALLS	0x002016
#define	EXD_TASK_TAG		0x002017
#define	EXD_TASK_ANCTASKID	0x002018
#define	EXD_TASK_ZONENAME	0x002019

#define	EXD_FLOW_V4SADDR	0x003000
#define	EXD_FLOW_V4DADDR	0x003001
#define	EXD_FLOW_V6SADDR	0x003002
#define	EXD_FLOW_V6DADDR	0x003003
#define	EXD_FLOW_SPORT		0x003004
#define	EXD_FLOW_DPORT		0x003005
#define	EXD_FLOW_PROTOCOL	0x003006
#define	EXD_FLOW_DSFIELD	0x003007
#define	EXD_FLOW_NBYTES		0x003008
#define	EXD_FLOW_NPKTS		0x003009
#define	EXD_FLOW_CTIME		0x00300a
#define	EXD_FLOW_LSEEN		0x00300b
#define	EXD_FLOW_PROJID		0x00300c
#define	EXD_FLOW_UID		0x00300d
#define	EXD_FLOW_ANAME		0x00300e

#define	EXD_FMA_LABEL		0x004000
#define	EXD_FMA_VERSION		0x004001
#define	EXD_FMA_OSREL		0x004002
#define	EXD_FMA_OSVER		0x004003
#define	EXD_FMA_PLAT		0x004004
#define	EXD_FMA_TODSEC		0x004005
#define	EXD_FMA_TODNSEC		0x004006
#define	EXD_FMA_NVLIST		0x004007
#define	EXD_FMA_MAJOR		0x004008
#define	EXD_FMA_MINOR		0x004009
#define	EXD_FMA_INODE		0x00400A
#define	EXD_FMA_OFFSET		0x00400B
#define	EXD_FMA_UUID		0x00400C

/* For EXD_GROUP_FLDESC  and EXD_GROUP_LNDESC */
#define	EXD_NET_DESC_NAME	0x005001
#define	EXD_NET_DESC_EHOST	0x005002
#define	EXD_NET_DESC_EDEST	0x005003
#define	EXD_NET_DESC_VLAN_TPID	0x005004
#define	EXD_NET_DESC_VLAN_TCI	0x005005
#define	EXD_NET_DESC_SAP	0x005006
#define	EXD_NET_DESC_PRIORITY	0x005007
#define	EXD_NET_DESC_BWLIMIT	0x005008
/* For EXD_GROUP_FLDESC  only */
#define	EXD_NET_DESC_DEVNAME	0x005009
#define	EXD_NET_DESC_V4SADDR	0x00500a
#define	EXD_NET_DESC_V4DADDR	0x00500b
#define	EXD_NET_DESC_V6SADDR	0x00500c
#define	EXD_NET_DESC_V6DADDR	0x00500d
#define	EXD_NET_DESC_SPORT	0x00500e
#define	EXD_NET_DESC_DPORT	0x00500f
#define	EXD_NET_DESC_PROTOCOL	0x005010
#define	EXD_NET_DESC_DSFIELD	0x005011

/* For EXD_NET_STATS */
#define	EXD_NET_STATS_NAME	0x006000
#define	EXD_NET_STATS_CURTIME	0x006001
#define	EXD_NET_STATS_IBYTES	0x006002
#define	EXD_NET_STATS_OBYTES	0x006003
#define	EXD_NET_STATS_IPKTS	0x006004
#define	EXD_NET_STATS_OPKTS	0x006005
#define	EXD_NET_STATS_IERRPKTS	0x006006
#define	EXD_NET_STATS_OERRPKTS	0x006007

#ifdef	__cplusplus
}
#endif

#endif	/* _SYS_EXACCT_CATALOG_H */
