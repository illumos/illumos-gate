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
 * Copyright 2012 Nexenta Systems, Inc. All rights reserved.
 * Copyright (c) 2013, Joyent, Inc. All rights reserved.
 */

/*
 * Copyright (c) 2000 to 2010, LSI Corporation.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms of all code within
 * this file that is exclusively owned by LSI, with or without
 * modification, is permitted provided that, in addition to the CDDL 1.0
 * License requirements, the following conditions are met:
 *
 *    Neither the name of the author nor the names of its contributors may be
 *    used to endorse or promote products derived from this software without
 *    specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
 * FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
 * COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING,
 * BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS
 * OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED
 * AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
 * OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT
 * OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH
 * DAMAGE.
 */

#ifndef _SYS_SCSI_ADAPTERS_MPTVAR_H
#define	_SYS_SCSI_ADAPTERS_MPTVAR_H

#include <sys/byteorder.h>
#include <sys/isa_defs.h>
#include <sys/sunmdi.h>
#include <sys/mdi_impldefs.h>
#include <sys/scsi/adapters/mpt_sas/mptsas_ioctl.h>
#include <sys/scsi/adapters/mpt_sas/mpi/mpi2_tool.h>
#include <sys/scsi/adapters/mpt_sas/mpi/mpi2_cnfg.h>

#ifdef	__cplusplus
extern "C" {
#endif

/*
 * Compile options
 */
#ifdef DEBUG
#define	MPTSAS_DEBUG		/* turn on debugging code */
#endif	/* DEBUG */

#define	MPTSAS_INITIAL_SOFT_SPACE	4

#define	MAX_MPI_PORTS		16

/*
 * Note below macro definition and data type definition
 * are used for phy mask handling, it should be changed
 * simultaneously.
 */
#define	MPTSAS_MAX_PHYS		16
typedef uint16_t		mptsas_phymask_t;

#define	MPTSAS_INVALID_DEVHDL	0xffff
#define	MPTSAS_SATA_GUID	"sata-guid"

/*
 * MPT HW defines
 */
#define	MPTSAS_MAX_DISKS_IN_CONFIG	14
#define	MPTSAS_MAX_DISKS_IN_VOL		10
#define	MPTSAS_MAX_HOTSPARES		2
#define	MPTSAS_MAX_RAIDVOLS		2
#define	MPTSAS_MAX_RAIDCONFIGS		5

/*
 * 64-bit SAS WWN is displayed as 16 characters as HEX characters,
 * plus two means the prefix 'w' and end of the string '\0'.
 */
#define	MPTSAS_WWN_STRLEN	(16 + 2)
#define	MPTSAS_MAX_GUID_LEN	64

/*
 * DMA routine flags
 */
#define	MPTSAS_DMA_HANDLE_ALLOCD	0x2
#define	MPTSAS_DMA_MEMORY_ALLOCD	0x4
#define	MPTSAS_DMA_HANDLE_BOUND	0x8

/*
 * If the HBA supports DMA or bus-mastering, you may have your own
 * scatter-gather list for physically non-contiguous memory in one
 * I/O operation; if so, there's probably a size for that list.
 * It must be placed in the ddi_dma_lim_t structure, so that the system
 * DMA-support routines can use it to break up the I/O request, so we
 * define it here.
 */
#if defined(__sparc)
#define	MPTSAS_MAX_DMA_SEGS	1
#define	MPTSAS_MAX_CMD_SEGS	1
#else
#define	MPTSAS_MAX_DMA_SEGS	256
#define	MPTSAS_MAX_CMD_SEGS	257
#endif
#define	MPTSAS_MAX_FRAME_SGES(mpt) \
	(((mpt->m_req_frame_size - (sizeof (MPI2_SCSI_IO_REQUEST))) / 8) + 1)

/*
 * Caculating how many 64-bit DMA simple elements can be stored in the first
 * frame. Note that msg_scsi_io_request contains 2 double-words (8 bytes) for
 * element storage.  And 64-bit dma element is 3 double-words (12 bytes) in
 * size.
 */
#define	MPTSAS_MAX_FRAME_SGES64(mpt) \
	((mpt->m_req_frame_size - \
	(sizeof (MPI2_SCSI_IO_REQUEST)) + sizeof (MPI2_SGE_IO_UNION)) / 12)

/*
 * Scatter-gather list structure defined by HBA hardware
 */
typedef	struct NcrTableIndirect {	/* Table Indirect entries */
	uint32_t count;		/* 24 bit count */
	union {
		uint32_t address32;	/* 32 bit address */
		struct {
			uint32_t Low;
			uint32_t High;
		} address64;		/* 64 bit address */
	} addr;
} mptti_t;

/*
 * preferred pkt_private length in 64-bit quantities
 */
#ifdef	_LP64
#define	PKT_PRIV_SIZE	2
#define	PKT_PRIV_LEN	16	/* in bytes */
#else /* _ILP32 */
#define	PKT_PRIV_SIZE	1
#define	PKT_PRIV_LEN	8	/* in bytes */
#endif

#define	PKT2CMD(pkt)	((struct mptsas_cmd *)((pkt)->pkt_ha_private))
#define	CMD2PKT(cmdp)	((struct scsi_pkt *)((cmdp)->cmd_pkt))
#define	EXTCMDS_STATUS_SIZE (sizeof (struct scsi_arq_status))

/*
 * get offset of item in structure
 */
#define	MPTSAS_GET_ITEM_OFF(type, member) ((size_t)(&((type *)0)->member))

/*
 * WWID provided by LSI firmware is generated by firmware but the WWID is not
 * IEEE NAA standard format, OBP has no chance to distinguish format of unit
 * address. According LSI's confirmation, the top nibble of RAID WWID is
 * meanless, so the consensus between Solaris and OBP is to replace top nibble
 * of WWID provided by LSI to "3" always to hint OBP that this is a RAID WWID
 * format unit address.
 */
#define	MPTSAS_RAID_WWID(wwid) \
	((wwid & 0x0FFFFFFFFFFFFFFF) | 0x3000000000000000)

typedef	struct mptsas_target {
		uint64_t		m_sas_wwn;	/* hash key1 */
		mptsas_phymask_t	m_phymask;	/* hash key2 */
		/*
		 * m_dr_flag is a flag for DR, make sure the member
		 * take the place of dr_flag of mptsas_hash_data.
		 */
		uint8_t			m_dr_flag;	/* dr_flag */
		uint16_t		m_devhdl;
		uint32_t		m_deviceinfo;
		uint8_t			m_phynum;
		uint32_t		m_dups;
		int32_t			m_timeout;
		int32_t			m_timebase;
		int32_t			m_t_throttle;
		int32_t			m_t_ncmds;
		int32_t			m_reset_delay;
		int32_t			m_t_nwait;

		uint16_t		m_qfull_retry_interval;
		uint8_t			m_qfull_retries;
		uint16_t		m_enclosure;
		uint16_t		m_slot_num;
		uint32_t		m_tgt_unconfigured;
		uint8_t			m_led_status;

} mptsas_target_t;

typedef struct mptsas_smp {
	uint64_t	m_sasaddr;	/* hash key1 */
	mptsas_phymask_t m_phymask;	/* hash key2 */
	uint8_t		reserved1;
	uint16_t	m_devhdl;
	uint32_t	m_deviceinfo;
	uint16_t	m_pdevhdl;
	uint32_t	m_pdevinfo;
} mptsas_smp_t;

typedef struct mptsas_hash_data {
	uint64_t	key1;
	mptsas_phymask_t key2;
	uint8_t		dr_flag;
	uint16_t	devhdl;
	uint32_t	device_info;
} mptsas_hash_data_t;

typedef struct mptsas_cache_frames {
	ddi_dma_handle_t m_dma_hdl;
	ddi_acc_handle_t m_acc_hdl;
	caddr_t m_frames_addr;
	uint32_t m_phys_addr;
} mptsas_cache_frames_t;

typedef struct	mptsas_cmd {
	uint_t			cmd_flags;	/* flags from scsi_init_pkt */
	ddi_dma_handle_t	cmd_dmahandle;	/* dma handle */
	ddi_dma_cookie_t	cmd_cookie;
	uint_t			cmd_cookiec;
	uint_t			cmd_winindex;
	uint_t			cmd_nwin;
	uint_t			cmd_cur_cookie;
	off_t			cmd_dma_offset;
	size_t			cmd_dma_len;
	uint32_t		cmd_totaldmacount;

	ddi_dma_handle_t	cmd_arqhandle;	/* dma arq handle */
	ddi_dma_cookie_t	cmd_arqcookie;
	struct buf		*cmd_arq_buf;
	ddi_dma_handle_t	cmd_ext_arqhandle; /* dma extern arq handle */
	ddi_dma_cookie_t	cmd_ext_arqcookie;
	struct buf		*cmd_ext_arq_buf;

	int			cmd_pkt_flags;

	/* timer for command in active slot */
	int			cmd_active_timeout;

	struct scsi_pkt		*cmd_pkt;
	struct scsi_arq_status	cmd_scb;
	uchar_t			cmd_cdblen;	/* length of cdb */
	uchar_t			cmd_rqslen;	/* len of requested rqsense */
	uchar_t			cmd_privlen;
	uint_t			cmd_scblen;
	uint32_t		cmd_dmacount;
	uint64_t		cmd_dma_addr;
	uchar_t			cmd_age;
	ushort_t		cmd_qfull_retries;
	uchar_t			cmd_queued;	/* true if queued */
	struct mptsas_cmd	*cmd_linkp;
	mptti_t			*cmd_sg; /* Scatter/Gather structure */
	uchar_t			cmd_cdb[SCSI_CDB_SIZE];
	uint64_t		cmd_pkt_private[PKT_PRIV_LEN];
	uint32_t		cmd_slot;
	uint32_t		ioc_cmd_slot;

	mptsas_cache_frames_t	*cmd_extra_frames;

	uint32_t		cmd_rfm;
	mptsas_target_t		*cmd_tgt_addr;
} mptsas_cmd_t;

/*
 * These are the defined cmd_flags for this structure.
 */
#define	CFLAG_CMDDISC		0x000001 /* cmd currently disconnected */
#define	CFLAG_WATCH		0x000002 /* watchdog time for this command */
#define	CFLAG_FINISHED		0x000004 /* command completed */
#define	CFLAG_CHKSEG		0x000008 /* check cmd_data within seg */
#define	CFLAG_COMPLETED		0x000010 /* completion routine called */
#define	CFLAG_PREPARED		0x000020 /* pkt has been init'ed */
#define	CFLAG_IN_TRANSPORT	0x000040 /* in use by host adapter driver */
#define	CFLAG_RESTORE_PTRS	0x000080 /* implicit restore ptr on reconnect */
#define	CFLAG_ARQ_IN_PROGRESS	0x000100 /* auto request sense in progress */
#define	CFLAG_TRANFLAG		0x0001ff /* covers transport part of flags */
#define	CFLAG_TM_CMD		0x000200 /* cmd is a task management command */
#define	CFLAG_CMDARQ		0x000400 /* cmd is a 'rqsense' command */
#define	CFLAG_DMAVALID		0x000800 /* dma mapping valid */
#define	CFLAG_DMASEND		0x001000 /* data is going 'out' */
#define	CFLAG_CMDIOPB		0x002000 /* this is an 'iopb' packet */
#define	CFLAG_CDBEXTERN		0x004000 /* cdb kmem_alloc'd */
#define	CFLAG_SCBEXTERN		0x008000 /* scb kmem_alloc'd */
#define	CFLAG_FREE		0x010000 /* packet is on free list */
#define	CFLAG_PRIVEXTERN	0x020000 /* target private kmem_alloc'd */
#define	CFLAG_DMA_PARTIAL	0x040000 /* partial xfer OK */
#define	CFLAG_QFULL_STATUS	0x080000 /* pkt got qfull status */
#define	CFLAG_TIMEOUT		0x100000 /* passthru/config command timeout */
#define	CFLAG_PMM_RECEIVED	0x200000 /* use cmd_pmm* for saving pointers */
#define	CFLAG_RETRY		0x400000 /* cmd has been retried */
#define	CFLAG_CMDIOC		0x800000 /* cmd is just for for ioc, no io */
#define	CFLAG_EXTARQBUFVALID	0x1000000 /* extern arq buf handle is valid */
#define	CFLAG_PASSTHRU		0x2000000 /* cmd is a passthrough command */
#define	CFLAG_XARQ		0x4000000 /* cmd requests for extra sense */
#define	CFLAG_CMDACK		0x8000000 /* cmd for event ack */
#define	CFLAG_TXQ		0x10000000 /* cmd queued in the tx_waitq */
#define	CFLAG_FW_CMD		0x20000000 /* cmd is a fw up/down command */
#define	CFLAG_CONFIG		0x40000000 /* cmd is for config header/page */
#define	CFLAG_FW_DIAG		0x80000000 /* cmd is for FW diag buffers */

#define	MPTSAS_SCSI_REPORTLUNS_ADDRESS_SIZE			8
#define	MPTSAS_SCSI_REPORTLUNS_ADDRESS_MASK			0xC0
#define	MPTSAS_SCSI_REPORTLUNS_ADDRESS_PERIPHERAL			0x00
#define	MPTSAS_SCSI_REPORTLUNS_ADDRESS_FLAT_SPACE			0x40
#define	MPTSAS_SCSI_REPORTLUNS_ADDRESS_LOGICAL_UNIT		0x80
#define	MPTSAS_SCSI_REPORTLUNS_ADDRESS_EXTENDED_UNIT		0xC0
#define	MPTSAS_SCSI_REPORTLUNS_ADDRESS_LOGICAL_UNIT_2B		0x00
#define	MPTSAS_SCSI_REPORTLUNS_ADDRESS_LOGICAL_UNIT_4B		0x01
#define	MPTSAS_SCSI_REPORTLUNS_ADDRESS_LOGICAL_UNIT_6B		0x10
#define	MPTSAS_SCSI_REPORTLUNS_ADDRESS_LOGICAL_UNIT_8B		0x20
#define	MPTSAS_SCSI_REPORTLUNS_ADDRESS_LOGICAL_UNIT_SIZE		0x30

#define	MPTSAS_HASH_ARRAY_SIZE	16
/*
 * hash table definition
 */

#define	MPTSAS_HASH_FIRST	0xffff
#define	MPTSAS_HASH_NEXT	0x0000

typedef struct mptsas_dma_alloc_state
{
	ddi_dma_handle_t	handle;
	caddr_t			memp;
	size_t			size;
	ddi_acc_handle_t	accessp;
	ddi_dma_cookie_t	cookie;
} mptsas_dma_alloc_state_t;

/*
 * passthrough request structure
 */
typedef struct mptsas_pt_request {
	uint8_t *request;
	uint32_t request_size;
	uint32_t data_size;
	uint32_t dataout_size;
	uint32_t direction;
	ddi_dma_cookie_t data_cookie;
	ddi_dma_cookie_t dataout_cookie;
} mptsas_pt_request_t;

/*
 * config page request structure
 */
typedef struct mptsas_config_request {
	uint32_t	page_address;
	uint8_t		action;
	uint8_t		page_type;
	uint8_t		page_number;
	uint8_t		page_length;
	uint8_t		page_version;
	uint8_t		ext_page_type;
	uint16_t	ext_page_length;
} mptsas_config_request_t;

typedef struct mptsas_fw_diagnostic_buffer {
	mptsas_dma_alloc_state_t	buffer_data;
	uint8_t				extended_type;
	uint8_t				buffer_type;
	uint8_t				force_release;
	uint32_t			product_specific[23];
	uint8_t				immediate;
	uint8_t				enabled;
	uint8_t				valid_data;
	uint8_t				owned_by_firmware;
	uint32_t			unique_id;
} mptsas_fw_diagnostic_buffer_t;

/*
 * FW diag request structure
 */
typedef struct mptsas_diag_request {
	mptsas_fw_diagnostic_buffer_t	*pBuffer;
	uint8_t				function;
} mptsas_diag_request_t;

typedef struct mptsas_hash_node {
	void *data;
	struct mptsas_hash_node *next;
} mptsas_hash_node_t;

typedef struct mptsas_hash_table {
	struct mptsas_hash_node *head[MPTSAS_HASH_ARRAY_SIZE];
	/*
	 * last position in traverse
	 */
	struct mptsas_hash_node *cur;
	uint16_t line;

} mptsas_hash_table_t;

/*
 * RAID volume information
 */
typedef struct mptsas_raidvol {
	ushort_t	m_israid;
	uint16_t	m_raidhandle;
	uint64_t	m_raidwwid;
	uint8_t		m_state;
	uint32_t	m_statusflags;
	uint32_t	m_settings;
	uint16_t	m_devhdl[MPTSAS_MAX_DISKS_IN_VOL];
	uint8_t		m_disknum[MPTSAS_MAX_DISKS_IN_VOL];
	ushort_t	m_diskstatus[MPTSAS_MAX_DISKS_IN_VOL];
	uint64_t	m_raidsize;
	int		m_raidlevel;
	int		m_ndisks;
	mptsas_target_t	*m_raidtgt;
} mptsas_raidvol_t;

/*
 * RAID configurations
 */
typedef struct mptsas_raidconfig {
		mptsas_raidvol_t	m_raidvol[MPTSAS_MAX_RAIDVOLS];
		uint16_t		m_physdisk_devhdl[
					    MPTSAS_MAX_DISKS_IN_CONFIG];
		uint8_t			m_native;
} m_raidconfig_t;

/*
 * Structure to hold active outstanding cmds.  Also, keep
 * timeout on a per target basis.
 */
typedef struct mptsas_slots {
	mptsas_hash_table_t	m_tgttbl;
	mptsas_hash_table_t	m_smptbl;
	m_raidconfig_t		m_raidconfig[MPTSAS_MAX_RAIDCONFIGS];
	uint8_t			m_num_raid_configs;
	uint16_t		m_tags;
	size_t			m_size;
	uint16_t		m_n_slots;
	mptsas_cmd_t		*m_slot[1];
} mptsas_slots_t;

/*
 * Structure to hold command and packets for event ack
 * and task management commands.
 */
typedef struct  m_event_struct {
	struct mptsas_cmd		m_event_cmd;
	struct m_event_struct	*m_event_linkp;
	/*
	 * event member record the failure event and eventcntx
	 * event member would be used in send ack pending process
	 */
	uint32_t		m_event;
	uint32_t		m_eventcntx;
	uint_t			in_use;
	struct scsi_pkt		m_event_pkt;	/* must be last */
						/* ... scsi_pkt_size() */
} m_event_struct_t;
#define	M_EVENT_STRUCT_SIZE	(sizeof (m_event_struct_t) - \
				sizeof (struct scsi_pkt) + scsi_pkt_size())

#define	MAX_IOC_COMMANDS	8

/*
 * A pool of MAX_IOC_COMMANDS is maintained for event ack commands.
 * A new event ack command requests mptsas_cmd and scsi_pkt structures
 * from this pool, and returns it back when done.
 */

typedef struct m_replyh_arg {
	void *mpt;
	uint32_t rfm;
} m_replyh_arg_t;
_NOTE(DATA_READABLE_WITHOUT_LOCK(m_replyh_arg_t::mpt))
_NOTE(DATA_READABLE_WITHOUT_LOCK(m_replyh_arg_t::rfm))

/*
 * Flags for DR handler topology change
 */
#define	MPTSAS_TOPO_FLAG_DIRECT_ATTACHED_DEVICE		0x0
#define	MPTSAS_TOPO_FLAG_EXPANDER_ASSOCIATED		0x1
#define	MPTSAS_TOPO_FLAG_LUN_ASSOCIATED			0x2
#define	MPTSAS_TOPO_FLAG_RAID_ASSOCIATED		0x4
#define	MPTSAS_TOPO_FLAG_RAID_PHYSDRV_ASSOCIATED	0x8
#define	MPTSAS_TOPO_FLAG_EXPANDER_ATTACHED_DEVICE	0x10

typedef struct mptsas_topo_change_list {
	void *mpt;
	uint_t  event;
	union {
		uint8_t physport;
		mptsas_phymask_t phymask;
	} un;
	uint16_t devhdl;
	void *object;
	uint8_t flags;
	struct mptsas_topo_change_list *next;
} mptsas_topo_change_list_t;


_NOTE(DATA_READABLE_WITHOUT_LOCK(mptsas_topo_change_list_t::mpt))
_NOTE(DATA_READABLE_WITHOUT_LOCK(mptsas_topo_change_list_t::event))
_NOTE(DATA_READABLE_WITHOUT_LOCK(mptsas_topo_change_list_t::physport))
_NOTE(DATA_READABLE_WITHOUT_LOCK(mptsas_topo_change_list_t::devhdl))
_NOTE(DATA_READABLE_WITHOUT_LOCK(mptsas_topo_change_list_t::object))
_NOTE(DATA_READABLE_WITHOUT_LOCK(mptsas_topo_change_list_t::flags))

/*
 * Status types when calling mptsas_get_target_device_info
 */
#define	DEV_INFO_SUCCESS		0x0
#define	DEV_INFO_FAIL_PAGE0		0x1
#define	DEV_INFO_WRONG_DEVICE_TYPE	0x2
#define	DEV_INFO_PHYS_DISK		0x3
#define	DEV_INFO_FAIL_ALLOC		0x4

/*
 * mpt hotplug event defines
 */
#define	MPTSAS_DR_EVENT_RECONFIG_TARGET	0x01
#define	MPTSAS_DR_EVENT_OFFLINE_TARGET	0x02
#define	MPTSAS_TOPO_FLAG_REMOVE_HANDLE	0x04

/*
 * SMP target hotplug events
 */
#define	MPTSAS_DR_EVENT_RECONFIG_SMP	0x10
#define	MPTSAS_DR_EVENT_OFFLINE_SMP	0x20
#define	MPTSAS_DR_EVENT_MASK		0x3F

/*
 * mpt hotplug status definition for m_dr_flag
 */

/*
 * MPTSAS_DR_INACTIVE
 *
 * The target is in a normal operating state.
 * No dynamic reconfiguration operation is in progress.
 */
#define	MPTSAS_DR_INACTIVE				0x0
/*
 * MPTSAS_DR_INTRANSITION
 *
 * The target is in a transition mode since
 * hotplug event happens and offline procedure has not
 * been finished
 */
#define	MPTSAS_DR_INTRANSITION			0x1

typedef struct mptsas_tgt_private {
	int t_lun;
	struct mptsas_target *t_private;
} mptsas_tgt_private_t;

/*
 * The following defines are used in mptsas_set_init_mode to track the current
 * state as we progress through reprogramming the HBA from target mode into
 * initiator mode.
 */

#define	IOUC_READ_PAGE0		0x00000100
#define	IOUC_READ_PAGE1		0x00000200
#define	IOUC_WRITE_PAGE1	0x00000400
#define	IOUC_DONE		0x00000800
#define	DISCOVERY_IN_PROGRESS	MPI2_SASIOUNIT0_PORTFLAGS_DISCOVERY_IN_PROGRESS
#define	AUTO_PORT_CONFIGURATION	MPI2_SASIOUNIT0_PORTFLAGS_AUTO_PORT_CONFIG

/*
 * Last allocated slot is used for TM requests.  Since only m_max_requests
 * frames are allocated, the last SMID will be m_max_requests - 1.
 */
#define	MPTSAS_SLOTS_SIZE(mpt) \
	(sizeof (struct mptsas_slots) + (sizeof (struct mptsas_cmd *) * \
		mpt->m_max_requests))
#define	MPTSAS_TM_SLOT(mpt)	(mpt->m_max_requests - 1)

/*
 * Macro for phy_flags
 */

typedef struct smhba_info {
	kmutex_t	phy_mutex;
	uint8_t		phy_id;
	uint64_t	sas_addr;
	char		path[8];
	uint16_t	owner_devhdl;
	uint16_t	attached_devhdl;
	uint8_t		attached_phy_identify;
	uint32_t	attached_phy_info;
	uint8_t		programmed_link_rate;
	uint8_t		hw_link_rate;
	uint8_t		change_count;
	uint32_t	phy_info;
	uint8_t		negotiated_link_rate;
	uint8_t		port_num;
	kstat_t		*phy_stats;
	uint32_t	invalid_dword_count;
	uint32_t	running_disparity_error_count;
	uint32_t	loss_of_dword_sync_count;
	uint32_t	phy_reset_problem_count;
	void		*mpt;
} smhba_info_t;

typedef struct mptsas_phy_info {
	uint8_t			port_num;
	uint8_t			port_flags;
	uint16_t		ctrl_devhdl;
	uint32_t		phy_device_type;
	uint16_t		attached_devhdl;
	mptsas_phymask_t	phy_mask;
	smhba_info_t		smhba_info;
} mptsas_phy_info_t;


typedef struct mptsas_doneq_thread_arg {
	void		*mpt;
	uint64_t	t;
} mptsas_doneq_thread_arg_t;

#define	MPTSAS_DONEQ_THREAD_ACTIVE	0x1
typedef struct mptsas_doneq_thread_list {
	mptsas_cmd_t		*doneq;
	mptsas_cmd_t		**donetail;
	kthread_t		*threadp;
	kcondvar_t		cv;
	ushort_t		reserv1;
	uint32_t		reserv2;
	kmutex_t		mutex;
	uint32_t		flag;
	uint32_t		len;
	mptsas_doneq_thread_arg_t	arg;
} mptsas_doneq_thread_list_t;

typedef struct mptsas {
	int		m_instance;

	struct mptsas *m_next;

	scsi_hba_tran_t		*m_tran;
	smp_hba_tran_t		*m_smptran;
	kmutex_t		m_mutex;
	kmutex_t		m_passthru_mutex;
	kcondvar_t		m_cv;
	kcondvar_t		m_passthru_cv;
	kcondvar_t		m_fw_cv;
	kcondvar_t		m_config_cv;
	kcondvar_t		m_fw_diag_cv;
	dev_info_t		*m_dip;

	/*
	 * soft state flags
	 */
	uint_t		m_softstate;

	struct mptsas_slots *m_active;	/* outstanding cmds */

	mptsas_cmd_t	*m_waitq;	/* cmd queue for active request */
	mptsas_cmd_t	**m_waitqtail;	/* wait queue tail ptr */

	kmutex_t	m_tx_waitq_mutex;
	mptsas_cmd_t	*m_tx_waitq;	/* TX cmd queue for active request */
	mptsas_cmd_t	**m_tx_waitqtail;	/* tx_wait queue tail ptr */
	int		m_tx_draining;	/* TX queue draining flag */

	mptsas_cmd_t	*m_doneq;	/* queue of completed commands */
	mptsas_cmd_t	**m_donetail;	/* queue tail ptr */

	/*
	 * variables for helper threads (fan-out interrupts)
	 */
	mptsas_doneq_thread_list_t	*m_doneq_thread_id;
	uint32_t		m_doneq_thread_n;
	uint32_t		m_doneq_thread_threshold;
	uint32_t		m_doneq_length_threshold;
	uint32_t		m_doneq_len;
	kcondvar_t		m_doneq_thread_cv;
	kmutex_t		m_doneq_mutex;

	int		m_ncmds;	/* number of outstanding commands */
	m_event_struct_t *m_ioc_event_cmdq;	/* cmd queue for ioc event */
	m_event_struct_t **m_ioc_event_cmdtail;	/* ioc cmd queue tail */

	ddi_acc_handle_t m_datap;	/* operating regs data access handle */

	struct _MPI2_SYSTEM_INTERFACE_REGS	*m_reg;

	ushort_t	m_devid;	/* device id of chip. */
	uchar_t		m_revid;	/* revision of chip. */
	uint16_t	m_svid;		/* subsystem Vendor ID of chip */
	uint16_t	m_ssid;		/* subsystem Device ID of chip */

	uchar_t		m_sync_offset;	/* default offset for this chip. */

	timeout_id_t	m_quiesce_timeid;

	ddi_dma_handle_t m_dma_req_frame_hdl;
	ddi_acc_handle_t m_acc_req_frame_hdl;
	ddi_dma_handle_t m_dma_reply_frame_hdl;
	ddi_acc_handle_t m_acc_reply_frame_hdl;
	ddi_dma_handle_t m_dma_free_queue_hdl;
	ddi_acc_handle_t m_acc_free_queue_hdl;
	ddi_dma_handle_t m_dma_post_queue_hdl;
	ddi_acc_handle_t m_acc_post_queue_hdl;

	/*
	 * list of reset notification requests
	 */
	struct scsi_reset_notify_entry	*m_reset_notify_listf;

	/*
	 * qfull handling
	 */
	timeout_id_t	m_restart_cmd_timeid;

	/*
	 * scsi	reset delay per	bus
	 */
	uint_t		m_scsi_reset_delay;

	int		m_pm_idle_delay;

	uchar_t		m_polled_intr;	/* intr was polled. */
	uchar_t		m_suspended;	/* true	if driver is suspended */

	struct kmem_cache *m_kmem_cache;
	struct kmem_cache *m_cache_frames;

	/*
	 * hba options.
	 */
	uint_t		m_options;

	int		m_in_callback;

	int		m_power_level;	/* current power level */

	int		m_busy;		/* power management busy state */

	off_t		m_pmcsr_offset; /* PMCSR offset */

	ddi_acc_handle_t m_config_handle;

	ddi_dma_attr_t		m_io_dma_attr;	/* Used for data I/O */
	ddi_dma_attr_t		m_msg_dma_attr; /* Used for message frames */
	ddi_device_acc_attr_t	m_dev_acc_attr;
	ddi_device_acc_attr_t	m_reg_acc_attr;

	/*
	 * request/reply variables
	 */
	caddr_t		m_req_frame;
	uint64_t	m_req_frame_dma_addr;
	caddr_t		m_reply_frame;
	uint64_t	m_reply_frame_dma_addr;
	caddr_t		m_free_queue;
	uint64_t	m_free_queue_dma_addr;
	caddr_t		m_post_queue;
	uint64_t	m_post_queue_dma_addr;

	m_replyh_arg_t *m_replyh_args;

	uint16_t	m_max_requests;
	uint16_t	m_req_frame_size;

	/*
	 * Max frames per request reprted in IOC Facts
	 */
	uint8_t		m_max_chain_depth;
	/*
	 * Max frames per request which is used in reality. It's adjusted
	 * according DMA SG length attribute, and shall not exceed the
	 * m_max_chain_depth.
	 */
	uint8_t		m_max_request_frames;

	uint16_t	m_free_queue_depth;
	uint16_t	m_post_queue_depth;
	uint16_t	m_max_replies;
	uint32_t	m_free_index;
	uint32_t	m_post_index;
	uint8_t		m_reply_frame_size;
	uint32_t	m_ioc_capabilities;

	/*
	 * indicates if the firmware was upload by the driver
	 * at boot time
	 */
	ushort_t	m_fwupload;

	uint16_t	m_productid;

	/*
	 * per instance data structures for dma memory resources for
	 * MPI handshake protocol. only one handshake cmd can run at a time.
	 */
	ddi_dma_handle_t	m_hshk_dma_hdl;
	ddi_acc_handle_t	m_hshk_acc_hdl;
	caddr_t			m_hshk_memp;
	size_t			m_hshk_dma_size;

	/* Firmware version on the card at boot time */
	uint32_t		m_fwversion;

	/* MSI specific fields */
	ddi_intr_handle_t	*m_htable;	/* For array of interrupts */
	int			m_intr_type;	/* What type of interrupt */
	int			m_intr_cnt;	/* # of intrs count returned */
	size_t			m_intr_size;    /* Size of intr array */
	uint_t			m_intr_pri;	/* Interrupt priority   */
	int			m_intr_cap;	/* Interrupt capabilities */
	ddi_taskq_t		*m_event_taskq;

	/* SAS specific information */

	union {
		uint64_t	m_base_wwid;	/* Base WWID */
		struct {
#ifdef _BIG_ENDIAN
			uint32_t	m_base_wwid_hi;
			uint32_t	m_base_wwid_lo;
#else
			uint32_t	m_base_wwid_lo;
			uint32_t	m_base_wwid_hi;
#endif
		} sasaddr;
	} un;

	uint8_t			m_num_phys;		/* # of PHYs */
	mptsas_phy_info_t	m_phy_info[MPTSAS_MAX_PHYS];
	uint8_t			m_port_chng;	/* initiator port changes */
	MPI2_CONFIG_PAGE_MAN_0   m_MANU_page0;   /* Manufactor page 0 info */
	MPI2_CONFIG_PAGE_MAN_1   m_MANU_page1;   /* Manufactor page 1 info */

	/* FMA Capabilities */
	int			m_fm_capabilities;
	ddi_taskq_t		*m_dr_taskq;
	int			m_mpxio_enable;
	uint8_t			m_done_traverse_dev;
	uint8_t			m_done_traverse_smp;
	int			m_diag_action_in_progress;
	uint16_t		m_dev_handle;
	uint16_t		m_smp_devhdl;

	/*
	 * Event recording
	 */
	uint8_t			m_event_index;
	uint32_t		m_event_number;
	uint32_t		m_event_mask[4];
	mptsas_event_entry_t	m_events[MPTSAS_EVENT_QUEUE_SIZE];

	/*
	 * FW diag Buffer List
	 */
	mptsas_fw_diagnostic_buffer_t
		m_fw_diag_buffer_list[MPI2_DIAG_BUF_TYPE_COUNT];

	/*
	 * Event Replay flag (MUR support)
	 */
	uint8_t			m_event_replay;

	/*
	 * IR Capable flag
	 */
	uint8_t			m_ir_capable;

	/*
	 * Is HBA processing a diag reset?
	 */
	uint8_t			m_in_reset;

	/*
	 * per instance cmd data structures for task management cmds
	 */
	m_event_struct_t	m_event_task_mgmt;	/* must be last */
							/* ... scsi_pkt_size */
} mptsas_t;
#define	MPTSAS_SIZE	(sizeof (struct mptsas) - \
			sizeof (struct scsi_pkt) + scsi_pkt_size())
/*
 * Only one of below two conditions is satisfied, we
 * think the target is associated to the iport and
 * allow call into mptsas_probe_lun().
 * 1. physicalsport == physport
 * 2. (phymask & (1 << physport)) == 0
 * The condition #2 is because LSI uses lowest PHY
 * number as the value of physical port when auto port
 * configuration.
 */
#define	IS_SAME_PORT(physicalport, physport, phymask, dynamicport) \
	((physicalport == physport) || (dynamicport && (phymask & \
	(1 << physport))))

_NOTE(MUTEX_PROTECTS_DATA(mptsas::m_mutex, mptsas))
_NOTE(SCHEME_PROTECTS_DATA("safe sharing", mptsas::m_next))
_NOTE(SCHEME_PROTECTS_DATA("stable data", mptsas::m_dip mptsas::m_tran))
_NOTE(SCHEME_PROTECTS_DATA("stable data", mptsas::m_kmem_cache))
_NOTE(DATA_READABLE_WITHOUT_LOCK(mptsas::m_io_dma_attr.dma_attr_sgllen))
_NOTE(DATA_READABLE_WITHOUT_LOCK(mptsas::m_devid))
_NOTE(DATA_READABLE_WITHOUT_LOCK(mptsas::m_productid))
_NOTE(DATA_READABLE_WITHOUT_LOCK(mptsas::m_port_type))
_NOTE(DATA_READABLE_WITHOUT_LOCK(mptsas::m_mpxio_enable))
_NOTE(DATA_READABLE_WITHOUT_LOCK(mptsas::m_ntargets))
_NOTE(DATA_READABLE_WITHOUT_LOCK(mptsas::m_instance))

/*
 * These should eventually migrate into the mpt header files
 * that may become the /kernel/misc/mpt module...
 */
#define	mptsas_init_std_hdr(hdl, mp, DevHandle, Lun, ChainOffset, Function) \
	mptsas_put_msg_DevHandle(hdl, mp, DevHandle); \
	mptsas_put_msg_ChainOffset(hdl, mp, ChainOffset); \
	mptsas_put_msg_Function(hdl, mp, Function); \
	mptsas_put_msg_Lun(hdl, mp, Lun)

#define	mptsas_put_msg_DevHandle(hdl, mp, val) \
	ddi_put16(hdl, &(mp)->DevHandle, (val))
#define	mptsas_put_msg_ChainOffset(hdl, mp, val) \
	ddi_put8(hdl, &(mp)->ChainOffset, (val))
#define	mptsas_put_msg_Function(hdl, mp, val) \
	ddi_put8(hdl, &(mp)->Function, (val))
#define	mptsas_put_msg_Lun(hdl, mp, val) \
	ddi_put8(hdl, &(mp)->LUN[1], (val))

#define	mptsas_get_msg_Function(hdl, mp) \
	ddi_get8(hdl, &(mp)->Function)

#define	mptsas_get_msg_MsgFlags(hdl, mp) \
	ddi_get8(hdl, &(mp)->MsgFlags)

#define	MPTSAS_ENABLE_DRWE(hdl) \
	ddi_put32(hdl->m_datap, &hdl->m_reg->WriteSequence, \
		MPI2_WRSEQ_FLUSH_KEY_VALUE); \
	ddi_put32(hdl->m_datap, &hdl->m_reg->WriteSequence, \
		MPI2_WRSEQ_1ST_KEY_VALUE); \
	ddi_put32(hdl->m_datap, &hdl->m_reg->WriteSequence, \
		MPI2_WRSEQ_2ND_KEY_VALUE); \
	ddi_put32(hdl->m_datap, &hdl->m_reg->WriteSequence, \
		MPI2_WRSEQ_3RD_KEY_VALUE); \
	ddi_put32(hdl->m_datap, &hdl->m_reg->WriteSequence, \
		MPI2_WRSEQ_4TH_KEY_VALUE); \
	ddi_put32(hdl->m_datap, &hdl->m_reg->WriteSequence, \
		MPI2_WRSEQ_5TH_KEY_VALUE); \
	ddi_put32(hdl->m_datap, &hdl->m_reg->WriteSequence, \
		MPI2_WRSEQ_6TH_KEY_VALUE);

/*
 * m_options flags
 */
#define	MPTSAS_OPT_PM		0x01	/* Power Management */

/*
 * m_softstate flags
 */
#define	MPTSAS_SS_DRAINING		0x02
#define	MPTSAS_SS_QUIESCED		0x04
#define	MPTSAS_SS_MSG_UNIT_RESET	0x08
#define	MPTSAS_DID_MSG_UNIT_RESET	0x10

/*
 * regspec defines.
 */
#define	CONFIG_SPACE	0	/* regset[0] - configuration space */
#define	IO_SPACE	1	/* regset[1] - used for i/o mapped device */
#define	MEM_SPACE	2	/* regset[2] - used for memory mapped device */
#define	BASE_REG2	3	/* regset[3] - used for 875 scripts ram */

/*
 * Handy constants
 */
#define	FALSE		0
#define	TRUE		1
#define	UNDEFINED	-1
#define	FAILED		-2

/*
 * power management.
 */
#define	MPTSAS_POWER_ON(mpt) { \
	pci_config_put16(mpt->m_config_handle, mpt->m_pmcsr_offset, \
	    PCI_PMCSR_D0); \
	delay(drv_usectohz(10000)); \
	(void) pci_restore_config_regs(mpt->m_dip); \
	mptsas_setup_cmd_reg(mpt); \
}

#define	MPTSAS_POWER_OFF(mpt) { \
	(void) pci_save_config_regs(mpt->m_dip); \
	pci_config_put16(mpt->m_config_handle, mpt->m_pmcsr_offset, \
	    PCI_PMCSR_D3HOT); \
	mpt->m_power_level = PM_LEVEL_D3; \
}

/*
 * inq_dtype:
 * Bits 5 through 7 are the Peripheral Device Qualifier
 * 001b: device not connected to the LUN
 * Bits 0 through 4 are the Peripheral Device Type
 * 1fh: Unknown or no device type
 *
 * Although the inquiry may return success, the following value
 * means no valid LUN connected.
 */
#define	MPTSAS_VALID_LUN(sd_inq) \
	(((sd_inq->inq_dtype & 0xe0) != 0x20) && \
	((sd_inq->inq_dtype & 0x1f) != 0x1f))

/*
 * Default is to have 10 retries on receiving QFULL status and
 * each retry to be after 100 ms.
 */
#define	QFULL_RETRIES		10
#define	QFULL_RETRY_INTERVAL	100

/*
 * Handy macros
 */
#define	Tgt(sp)	((sp)->cmd_pkt->pkt_address.a_target)
#define	Lun(sp)	((sp)->cmd_pkt->pkt_address.a_lun)

#define	IS_HEX_DIGIT(n)	(((n) >= '0' && (n) <= '9') || \
	((n) >= 'a' && (n) <= 'f') || ((n) >= 'A' && (n) <= 'F'))

/*
 * poll time for mptsas_pollret() and mptsas_wait_intr()
 */
#define	MPTSAS_POLL_TIME	30000	/* 30 seconds */

/*
 * default time for mptsas_do_passthru
 */
#define	MPTSAS_PASS_THRU_TIME_DEFAULT	60	/* 60 seconds */

/*
 * macro to return the effective address of a given per-target field
 */
#define	EFF_ADDR(start, offset)		((start) + (offset))

#define	SDEV2ADDR(devp)		(&((devp)->sd_address))
#define	SDEV2TRAN(devp)		((devp)->sd_address.a_hba_tran)
#define	PKT2TRAN(pkt)		((pkt)->pkt_address.a_hba_tran)
#define	ADDR2TRAN(ap)		((ap)->a_hba_tran)
#define	DIP2TRAN(dip)		(ddi_get_driver_private(dip))


#define	TRAN2MPT(hba)		((mptsas_t *)(hba)->tran_hba_private)
#define	DIP2MPT(dip)		(TRAN2MPT((scsi_hba_tran_t *)DIP2TRAN(dip)))
#define	SDEV2MPT(sd)		(TRAN2MPT(SDEV2TRAN(sd)))
#define	PKT2MPT(pkt)		(TRAN2MPT(PKT2TRAN(pkt)))

#define	ADDR2MPT(ap)		(TRAN2MPT(ADDR2TRAN(ap)))

#define	POLL_TIMEOUT		(2 * SCSI_POLL_TIMEOUT * 1000000)
#define	SHORT_POLL_TIMEOUT	(1000000)	/* in usec, about 1 secs */
#define	MPTSAS_QUIESCE_TIMEOUT	1		/* 1 sec */
#define	MPTSAS_PM_IDLE_TIMEOUT	60		/* 60 seconds */

#define	MPTSAS_GET_ISTAT(mpt)  (ddi_get32((mpt)->m_datap, \
			&(mpt)->m_reg->HostInterruptStatus))

#define	MPTSAS_SET_SIGP(P) \
		ClrSetBits(mpt->m_devaddr + NREG_ISTAT, 0, NB_ISTAT_SIGP)

#define	MPTSAS_RESET_SIGP(P) (void) ddi_get8(mpt->m_datap, \
			(uint8_t *)(mpt->m_devaddr + NREG_CTEST2))

#define	MPTSAS_GET_INTCODE(P) (ddi_get32(mpt->m_datap, \
			(uint32_t *)(mpt->m_devaddr + NREG_DSPS)))


#define	MPTSAS_START_CMD(mpt, req_desc_lo, req_desc_hi) \
	ddi_put32(mpt->m_datap, &mpt->m_reg->RequestDescriptorPostLow,\
	    req_desc_lo);\
	ddi_put32(mpt->m_datap, &mpt->m_reg->RequestDescriptorPostHigh,\
	    req_desc_hi);

#define	INTPENDING(mpt) \
	(MPTSAS_GET_ISTAT(mpt) & MPI2_HIS_REPLY_DESCRIPTOR_INTERRUPT)

/*
 * Mask all interrupts to disable
 */
#define	MPTSAS_DISABLE_INTR(mpt)	\
	ddi_put32((mpt)->m_datap, &(mpt)->m_reg->HostInterruptMask, \
	    (MPI2_HIM_RIM | MPI2_HIM_DIM | MPI2_HIM_RESET_IRQ_MASK))

/*
 * Mask Doorbell and Reset interrupts to enable reply desc int.
 */
#define	MPTSAS_ENABLE_INTR(mpt)	\
	ddi_put32(mpt->m_datap, &mpt->m_reg->HostInterruptMask, \
	(MPI2_HIM_DIM | MPI2_HIM_RESET_IRQ_MASK))

#define	MPTSAS_GET_NEXT_REPLY(mpt, index)  \
	&((uint64_t *)(void *)mpt->m_post_queue)[index]

#define	MPTSAS_GET_NEXT_FRAME(mpt, SMID) \
	(mpt->m_req_frame + (mpt->m_req_frame_size * SMID))

#define	ClrSetBits32(hdl, reg, clr, set) \
	ddi_put32(hdl, (reg), \
	    ((ddi_get32(mpt->m_datap, (reg)) & ~(clr)) | (set)))

#define	ClrSetBits(reg, clr, set) \
	ddi_put8(mpt->m_datap, (uint8_t *)(reg), \
		((ddi_get8(mpt->m_datap, (uint8_t *)(reg)) & ~(clr)) | (set)))

#define	MPTSAS_WAITQ_RM(mpt, cmdp)	\
	if ((cmdp = mpt->m_waitq) != NULL) { \
		/* If the queue is now empty fix the tail pointer */	\
		if ((mpt->m_waitq = cmdp->cmd_linkp) == NULL) \
			mpt->m_waitqtail = &mpt->m_waitq; \
		cmdp->cmd_linkp = NULL; \
		cmdp->cmd_queued = FALSE; \
	}

#define	MPTSAS_TX_WAITQ_RM(mpt, cmdp)	\
	if ((cmdp = mpt->m_tx_waitq) != NULL) { \
		/* If the queue is now empty fix the tail pointer */	\
		if ((mpt->m_tx_waitq = cmdp->cmd_linkp) == NULL) \
			mpt->m_tx_waitqtail = &mpt->m_tx_waitq; \
		cmdp->cmd_linkp = NULL; \
		cmdp->cmd_queued = FALSE; \
	}

/*
 * defaults for	the global properties
 */
#define	DEFAULT_SCSI_OPTIONS	SCSI_OPTIONS_DR
#define	DEFAULT_TAG_AGE_LIMIT	2
#define	DEFAULT_WD_TICK		10

/*
 * invalid hostid.
 */
#define	MPTSAS_INVALID_HOSTID  -1

/*
 * Get/Set hostid from SCSI port configuration page
 */
#define	MPTSAS_GET_HOST_ID(configuration) (configuration & 0xFF)
#define	MPTSAS_SET_HOST_ID(hostid) (hostid | ((1 << hostid) << 16))

/*
 * Config space.
 */
#define	MPTSAS_LATENCY_TIMER	0x40

/*
 * Offset to firmware version
 */
#define	MPTSAS_FW_VERSION_OFFSET	9

/*
 * Offset and masks to get at the ProductId field
 */
#define	MPTSAS_FW_PRODUCTID_OFFSET	8
#define	MPTSAS_FW_PRODUCTID_MASK	0xFFFF0000
#define	MPTSAS_FW_PRODUCTID_SHIFT	16

/*
 * Subsystem ID for HBAs.
 */
#define	MPTSAS_HBA_SUBSYSTEM_ID    0x10C0
#define	MPTSAS_RHEA_SUBSYSTEM_ID	0x10B0

/*
 * reset delay tick
 */
#define	MPTSAS_WATCH_RESET_DELAY_TICK 50	/* specified in milli seconds */

/*
 * Ioc reset return values
 */
#define	MPTSAS_RESET_FAIL	-1
#define	MPTSAS_NO_RESET		0
#define	MPTSAS_SUCCESS_HARDRESET	1
#define	MPTSAS_SUCCESS_MUR	2

/*
 * throttle support.
 */
#define	MAX_THROTTLE	32
#define	HOLD_THROTTLE	0
#define	DRAIN_THROTTLE	-1
#define	QFULL_THROTTLE	-2

/*
 * Passthrough/config request flags
 */
#define	MPTSAS_DATA_ALLOCATED		0x0001
#define	MPTSAS_DATAOUT_ALLOCATED	0x0002
#define	MPTSAS_REQUEST_POOL_CMD		0x0004
#define	MPTSAS_ADDRESS_REPLY		0x0008
#define	MPTSAS_CMD_TIMEOUT		0x0010

/*
 * response code tlr flag
 */
#define	MPTSAS_SCSI_RESPONSE_CODE_TLR_OFF	0x02

/*
 * System Events
 */
#ifndef	DDI_VENDOR_LSI
#define	DDI_VENDOR_LSI	"LSI"
#endif	/* DDI_VENDOR_LSI */

/*
 * Shared functions
 */
int mptsas_save_cmd(struct mptsas *mpt, struct mptsas_cmd *cmd);
void mptsas_remove_cmd(mptsas_t *mpt, mptsas_cmd_t *cmd);
void mptsas_waitq_add(mptsas_t *mpt, mptsas_cmd_t *cmd);
void mptsas_log(struct mptsas *mpt, int level, char *fmt, ...);
int mptsas_poll(mptsas_t *mpt, mptsas_cmd_t *poll_cmd, int polltime);
int mptsas_do_dma(mptsas_t *mpt, uint32_t size, int var, int (*callback)());
int mptsas_send_config_request_msg(mptsas_t *mpt, uint8_t action,
	uint8_t pagetype, uint32_t pageaddress, uint8_t pagenumber,
	uint8_t pageversion, uint8_t pagelength, uint32_t
	SGEflagslength, uint32_t SGEaddress32);
int mptsas_send_extended_config_request_msg(mptsas_t *mpt, uint8_t action,
	uint8_t extpagetype, uint32_t pageaddress, uint8_t pagenumber,
	uint8_t pageversion, uint16_t extpagelength,
	uint32_t SGEflagslength, uint32_t SGEaddress32);
int mptsas_update_flash(mptsas_t *mpt, caddr_t ptrbuffer, uint32_t size,
	uint8_t type, int mode);
int mptsas_check_flash(mptsas_t *mpt, caddr_t origfile, uint32_t size,
	uint8_t type, int mode);
int mptsas_download_firmware();
int mptsas_can_download_firmware();
int mptsas_dma_alloc(mptsas_t *mpt, mptsas_dma_alloc_state_t *dma_statep);
void mptsas_dma_free(mptsas_dma_alloc_state_t *dma_statep);
mptsas_phymask_t mptsas_physport_to_phymask(mptsas_t *mpt, uint8_t physport);
void mptsas_fma_check(mptsas_t *mpt, mptsas_cmd_t *cmd);
int mptsas_check_acc_handle(ddi_acc_handle_t handle);
int mptsas_check_dma_handle(ddi_dma_handle_t handle);
void mptsas_fm_ereport(mptsas_t *mpt, char *detail);
int mptsas_dma_addr_create(mptsas_t *mpt, ddi_dma_attr_t dma_attr,
    ddi_dma_handle_t *dma_hdp, ddi_acc_handle_t *acc_hdp, caddr_t *dma_memp,
    uint32_t alloc_size, ddi_dma_cookie_t *cookiep);
void mptsas_dma_addr_destroy(ddi_dma_handle_t *, ddi_acc_handle_t *);

/*
 * impl functions
 */
int mptsas_ioc_wait_for_response(mptsas_t *mpt);
int mptsas_ioc_wait_for_doorbell(mptsas_t *mpt);
int mptsas_ioc_reset(mptsas_t *mpt, int);
int mptsas_send_handshake_msg(mptsas_t *mpt, caddr_t memp, int numbytes,
    ddi_acc_handle_t accessp);
int mptsas_get_handshake_msg(mptsas_t *mpt, caddr_t memp, int numbytes,
    ddi_acc_handle_t accessp);
int mptsas_send_config_request_msg(mptsas_t *mpt, uint8_t action,
    uint8_t pagetype, uint32_t pageaddress, uint8_t pagenumber,
    uint8_t pageversion, uint8_t pagelength, uint32_t SGEflagslength,
    uint32_t SGEaddress32);
int mptsas_send_extended_config_request_msg(mptsas_t *mpt, uint8_t action,
    uint8_t extpagetype, uint32_t pageaddress, uint8_t pagenumber,
    uint8_t pageversion, uint16_t extpagelength,
    uint32_t SGEflagslength, uint32_t SGEaddress32);

int mptsas_request_from_pool(mptsas_t *mpt, mptsas_cmd_t **cmd,
    struct scsi_pkt **pkt);
void mptsas_return_to_pool(mptsas_t *mpt, mptsas_cmd_t *cmd);
void mptsas_destroy_ioc_event_cmd(mptsas_t *mpt);
void mptsas_start_config_page_access(mptsas_t *mpt, mptsas_cmd_t *cmd);
int mptsas_access_config_page(mptsas_t *mpt, uint8_t action, uint8_t page_type,
    uint8_t page_number, uint32_t page_address, int (*callback) (mptsas_t *,
    caddr_t, ddi_acc_handle_t, uint16_t, uint32_t, va_list), ...);

int mptsas_ioc_task_management(mptsas_t *mpt, int task_type,
    uint16_t dev_handle, int lun, uint8_t *reply, uint32_t reply_size,
    int mode);
int mptsas_send_event_ack(mptsas_t *mpt, uint32_t event, uint32_t eventcntx);
void mptsas_send_pending_event_ack(mptsas_t *mpt);
void mptsas_set_throttle(struct mptsas *mpt, mptsas_target_t *ptgt, int what);
int mptsas_restart_ioc(mptsas_t *mpt);
void mptsas_update_driver_data(struct mptsas *mpt);
uint64_t mptsas_get_sata_guid(mptsas_t *mpt, mptsas_target_t *ptgt, int lun);

/*
 * init functions
 */
int mptsas_ioc_get_facts(mptsas_t *mpt);
int mptsas_ioc_get_port_facts(mptsas_t *mpt, int port);
int mptsas_ioc_enable_port(mptsas_t *mpt);
int mptsas_ioc_enable_event_notification(mptsas_t *mpt);
int mptsas_ioc_init(mptsas_t *mpt);

/*
 * configuration pages operation
 */
int mptsas_get_sas_device_page0(mptsas_t *mpt, uint32_t page_address,
    uint16_t *dev_handle, uint64_t *sas_wwn, uint32_t *dev_info,
    uint8_t *physport, uint8_t *phynum, uint16_t *pdevhandle,
    uint16_t *slot_num, uint16_t *enclosure);
int mptsas_get_sas_io_unit_page(mptsas_t *mpt);
int mptsas_get_sas_io_unit_page_hndshk(mptsas_t *mpt);
int mptsas_get_sas_expander_page0(mptsas_t *mpt, uint32_t page_address,
    mptsas_smp_t *info);
int mptsas_set_ioc_params(mptsas_t *mpt);
int mptsas_get_manufacture_page5(mptsas_t *mpt);
int mptsas_get_sas_port_page0(mptsas_t *mpt, uint32_t page_address,
    uint64_t *sas_wwn, uint8_t *portwidth);
int mptsas_get_bios_page3(mptsas_t *mpt,  uint32_t *bios_version);
int
mptsas_get_sas_phy_page0(mptsas_t *mpt, uint32_t page_address,
    smhba_info_t *info);
int
mptsas_get_sas_phy_page1(mptsas_t *mpt, uint32_t page_address,
    smhba_info_t *info);
int
mptsas_get_manufacture_page0(mptsas_t *mpt);
void
mptsas_create_phy_stats(mptsas_t *mpt, char *iport, dev_info_t *dip);
void mptsas_destroy_phy_stats(mptsas_t *mpt);
int mptsas_smhba_phy_init(mptsas_t *mpt);
/*
 * RAID functions
 */
int mptsas_get_raid_settings(mptsas_t *mpt, mptsas_raidvol_t *raidvol);
int mptsas_get_raid_info(mptsas_t *mpt);
int mptsas_get_physdisk_settings(mptsas_t *mpt, mptsas_raidvol_t *raidvol,
    uint8_t physdisknum);
int mptsas_delete_volume(mptsas_t *mpt, uint16_t volid);
void mptsas_raid_action_system_shutdown(mptsas_t *mpt);

#define	MPTSAS_IOCSTATUS(status) (status & MPI2_IOCSTATUS_MASK)
/*
 * debugging.
 */
#if defined(MPTSAS_DEBUG)

void mptsas_printf(char *fmt, ...);

#define	MPTSAS_DBGPR(m, args)	\
	if (mptsas_debug_flags & (m)) \
		mptsas_printf args
#else	/* ! defined(MPTSAS_DEBUG) */
#define	MPTSAS_DBGPR(m, args)
#endif	/* defined(MPTSAS_DEBUG) */

#define	NDBG0(args)	MPTSAS_DBGPR(0x01, args)	/* init	*/
#define	NDBG1(args)	MPTSAS_DBGPR(0x02, args)	/* normal running */
#define	NDBG2(args)	MPTSAS_DBGPR(0x04, args)	/* property handling */
#define	NDBG3(args)	MPTSAS_DBGPR(0x08, args)	/* pkt handling */

#define	NDBG4(args)	MPTSAS_DBGPR(0x10, args)	/* kmem alloc/free */
#define	NDBG5(args)	MPTSAS_DBGPR(0x20, args)	/* polled cmds */
#define	NDBG6(args)	MPTSAS_DBGPR(0x40, args)	/* interrupts */
#define	NDBG7(args)	MPTSAS_DBGPR(0x80, args)	/* queue handling */

#define	NDBG8(args)	MPTSAS_DBGPR(0x0100, args)	/* arq */
#define	NDBG9(args)	MPTSAS_DBGPR(0x0200, args)	/* Tagged Q'ing */
#define	NDBG10(args)	MPTSAS_DBGPR(0x0400, args)	/* halting chip */
#define	NDBG11(args)	MPTSAS_DBGPR(0x0800, args)	/* power management */

#define	NDBG12(args)	MPTSAS_DBGPR(0x1000, args)	/* enumeration */
#define	NDBG13(args)	MPTSAS_DBGPR(0x2000, args)	/* configuration page */
#define	NDBG14(args)	MPTSAS_DBGPR(0x4000, args)	/* LED control */
#define	NDBG15(args)	MPTSAS_DBGPR(0x8000, args)

#define	NDBG16(args)	MPTSAS_DBGPR(0x010000, args)
#define	NDBG17(args)	MPTSAS_DBGPR(0x020000, args)	/* scatter/gather */
#define	NDBG18(args)	MPTSAS_DBGPR(0x040000, args)
#define	NDBG19(args)	MPTSAS_DBGPR(0x080000, args)	/* handshaking */

#define	NDBG20(args)	MPTSAS_DBGPR(0x100000, args)	/* events */
#define	NDBG21(args)	MPTSAS_DBGPR(0x200000, args)	/* dma */
#define	NDBG22(args)	MPTSAS_DBGPR(0x400000, args)	/* reset */
#define	NDBG23(args)	MPTSAS_DBGPR(0x800000, args)	/* abort */

#define	NDBG24(args)	MPTSAS_DBGPR(0x1000000, args)	/* capabilities */
#define	NDBG25(args)	MPTSAS_DBGPR(0x2000000, args)	/* flushing */
#define	NDBG26(args)	MPTSAS_DBGPR(0x4000000, args)
#define	NDBG27(args)	MPTSAS_DBGPR(0x8000000, args)

#define	NDBG28(args)	MPTSAS_DBGPR(0x10000000, args)	/* hotplug */
#define	NDBG29(args)	MPTSAS_DBGPR(0x20000000, args)	/* timeouts */
#define	NDBG30(args)	MPTSAS_DBGPR(0x40000000, args)	/* mptsas_watch */
#define	NDBG31(args)	MPTSAS_DBGPR(0x80000000, args)	/* negotations */

/*
 * auto request sense
 */
#define	RQ_MAKECOM_COMMON(pkt, flag, cmd) \
	(pkt)->pkt_flags = (flag), \
	((union scsi_cdb *)(pkt)->pkt_cdbp)->scc_cmd = (cmd), \
	((union scsi_cdb *)(pkt)->pkt_cdbp)->scc_lun = \
	    (pkt)->pkt_address.a_lun

#define	RQ_MAKECOM_G0(pkt, flag, cmd, addr, cnt) \
	RQ_MAKECOM_COMMON((pkt), (flag), (cmd)), \
	FORMG0ADDR(((union scsi_cdb *)(pkt)->pkt_cdbp), (addr)), \
	FORMG0COUNT(((union scsi_cdb *)(pkt)->pkt_cdbp), (cnt))


#ifdef	__cplusplus
}
#endif

#endif	/* _SYS_SCSI_ADAPTERS_MPTVAR_H */
