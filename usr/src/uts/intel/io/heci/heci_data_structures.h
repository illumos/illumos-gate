/*
 * Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*
 * Part of Intel(R) Manageability Engine Interface Linux driver
 *
 * Copyright (c) 2003 - 2008 Intel Corp.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions, and the following disclaimer,
 *    without modification.
 * 2. Redistributions in binary form must reproduce at minimum a disclaimer
 *    substantially similar to the "NO WARRANTY" disclaimer below
 *    ("Disclaimer") and any redistribution must be conditioned upon
 *    including a substantially similar Disclaimer requirement for further
 *    binary redistribution.
 * 3. Neither the names of the above-listed copyright holders nor the names
 *    of any contributors may be used to endorse or promote products derived
 *    from this software without specific prior written permission.
 *
 * Alternatively, this software may be distributed under the terms of the
 * GNU General Public License ("GPL") version 2 as published by the Free
 * Software Foundation.
 *
 * NO WARRANTY
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTIBILITY AND FITNESS FOR
 * A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 * HOLDERS OR CONTRIBUTORS BE LIABLE FOR SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
 * STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING
 * IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGES.
 *
 */

#ifndef _HECI_DATA_STRUCTURES_H_
#define	_HECI_DATA_STRUCTURES_H_

#include <sys/varargs.h>
#include <sys/types.h>

#ifndef SUNOS
#define	SUNOS
#endif

/*
 * error code definition
 */
#define	ESLOTS_OVERFLOW	1
#define	ECORRUPTED_MESSAGE_HEADER	1000
#define	ECOMPLETE_MESSAGE	1001

#define	HECI_FC_MESSAGE_RESERVED_LENGTH	5

/*
 * Number of queue lists used by this driver
 */
#define	HECI_IO_LISTS_NUMBER	7

/*
 * Maximum transmission unit (MTU) of heci messages
 */
#define	IAMTHIF_MTU	4160
#pragma pack(1)


/*
 * HECI HW Section
 */

/* HECI registers */
/* H_CB_WW - Host Circular Buffer (CB) Write Window register */
#define	H_CB_WW	0
/* H_CSR - Host Control Status register */
#define	H_CSR	4
/* ME_CB_RW - ME Circular Buffer Read Window register (read only) */
#define	ME_CB_RW	8
/* ME_CSR_HA - ME Control Status Host Access register (read only) */
#define	ME_CSR_HA	0xC


/* register bits of H_CSR (Host Control Status register) */
/* Host Circular Buffer Depth - maximum number of 32-bit entries in CB */
#define	H_CBD	0xFF000000
/* Host Circular Buffer Write Pointer */
#define	H_CBWP	0x00FF0000
/* Host Circular Buffer Read Pointer */
#define	H_CBRP	0x0000FF00
/* Host Reset */
#define	H_RST	0x00000010
/* Host Ready */
#define	H_RDY	0x00000008
/* Host Interrupt Generate */
#define	H_IG	0x00000004
/* Host Interrupt Status */
#define	H_IS	0x00000002
/* Host Interrupt Enable */
#define	H_IE	0x00000001


/*
 * register bits of ME_CSR_HA (ME Control Status Host Access register)
 * ME CB (Circular Buffer) Depth HRA (Host Read Access)
 *  - host read only access to ME_CBD
 */
#define	ME_CBD_HRA	0xFF000000
/* ME CB Write Pointer HRA - host read only access to ME_CBWP */
#define	ME_CBWP_HRA	0x00FF0000
/* ME CB Read Pointer HRA - host read only access to ME_CBRP */
#define	ME_CBRP_HRA	0x0000FF00
/* ME Reset HRA - host read only access to ME_RST */
#define	ME_RST_HRA	0x00000010
/* ME Ready HRA - host read only access to ME_RDY */
#define	ME_RDY_HRA	0x00000008
/* ME Interrupt Generate HRA - host read only access to ME_IG */
#define	ME_IG_HRA	0x00000004
/* ME Interrupt Status HRA - host read only access to ME_IS */
#define	ME_IS_HRA	0x00000002
/* ME Interrupt Enable HRA - host read only access to ME_IE */
#define	ME_IE_HRA	0x00000001

#define	HECI_MINOR_NUMBER	1
/* #define  HECI_PTHI_MINOR_NUMBER	0 */
#define	MAKE_MINOR_NUM(minor, instance)	(((uint_t)(minor) << 8) \
				    | ((instance) & 0xFF))
#define	HECI_MINOR_TO_INSTANCE(x)	((x) & 0xFF)
#define	HECI_MINOR_TO_IFNUM(x)		(((x) >> 8) & 0xFF)

#define	HECI_MAX_OPEN_HANDLE_COUNT	253

/*
 * debug kernel print macro define
 */
#define	PRN(...)	_PRN("%s():  "__VA_ARGS__, "")
#define	_PRN(format, ...)					\
	cmn_err(CE_CONT, format"%s", __func__, __VA_ARGS__)

#ifdef DEBUG
extern int heci_debug;
#define	DBG(...) { if (heci_debug) PRN(__VA_ARGS__); }
#else
#define	DBG
#endif

#define	assert(expr) \
	if (!(expr)) {                                   \
		cmn_err(CE_WARN, "Assertion failed! %s,%s,line=%d", #expr, \
		__FILE__, __LINE__);          \
	}

#define	list_next(p)	((p)->list_next)

#define	walk_list(p, n, h) \
	for (p = list_next(h), n = list_next(p);	\
		p != (h); \
		p = n, n = list_next(p))


#define	list_init(ptr) { \
	(ptr)->list_next = (ptr); (ptr)->list_prev = (ptr); \
}

#define	LIST_INIT_HEAD	list_init
#define	list_del_init(n)	{ \
	    list_del(n); \
	    list_init(n); \
	}

#define	list_empty(l)	((l)->list_next == (l))
#define	list_del(p)	{ (p)->list_next->list_prev = (p)->list_prev; \
	(p)->list_prev->list_next = (p)->list_next; }
#define	list_add_tail(newnode, head) { \
		(head)->list_prev->list_next = (newnode); \
		(newnode)->list_prev = (head)->list_prev; \
		(head)->list_prev = (newnode); \
		(newnode)->list_next = (head); \
	}
#define	list_relink_node(newnode, head)	{ \
		list_del(newnode); \
		list_add_tail(newnode, head); \
	}

#ifdef __GNUC__

#define	find_struct(ptr, type, member) ( \
	{ \
	const __typeof(((type *)0)->member) *__tmpp = (ptr);  \
	(type *)(void *)((char *)__tmpp - ((size_t)&((type *)0)->member)); \
	})
#else
/* type unsafe version */
#define	find_struct(ptr, type, member) \
		((type *)(void *)((char *)(ptr) \
		- ((size_t)&((type *)0)->member)))

#endif

#define	list_for_each_entry_safe(pos, n, head, member, type)                  \
	for (pos = find_struct((head)->list_next, type, member),      \
		n = find_struct(pos->member.list_next, type, member); \
		&pos->member != (head);                                    \
		pos = n, n = find_struct(n->member.list_next, type, member))

#define	HZ		drv_usectohz(1000000)
/*
 * time to wait HECI become ready after init
 */
#define	HECI_INTEROP_TIMEOUT    (HZ * 7)

/*
 * watch dog definition
 */
#define	HECI_WATCHDOG_DATA_SIZE	16
#define	HECI_START_WD_DATA_SIZE	20
#define	HECI_WD_PARAMS_SIZE	4
#define	HECI_WD_STATE_INDEPENDENCE_MSG_SENT	(1 << 0)

#define	HECI_WD_HOST_CLIENT_ID	1
#define	HECI_IAMTHIF_HOST_CLIENT_ID	2

struct guid {
	uint32_t data1;
	uint16_t data2;
	uint16_t data3;
	uint8_t data4[8];
};

/* File state */
enum file_state {
	HECI_FILE_INITIALIZING = 0,
	HECI_FILE_CONNECTING,
	HECI_FILE_CONNECTED,
	HECI_FILE_DISCONNECTING,
	HECI_FILE_DISCONNECTED
};

/* HECI device states */
enum heci_states {
	HECI_INITIALIZING = 0,
	HECI_ENABLED,
	HECI_RESETING,
	HECI_DISABLED,
	HECI_RECOVERING_FROM_RESET,
	HECI_POWER_DOWN,
	HECI_POWER_UP
};

enum iamthif_states {
	HECI_IAMTHIF_IDLE,
	HECI_IAMTHIF_WRITING,
	HECI_IAMTHIF_FLOW_CONTROL,
	HECI_IAMTHIF_READING,
	HECI_IAMTHIF_READ_COMPLETE
};

enum heci_file_transaction_states {
	HECI_IDLE,
	HECI_WRITING,
	HECI_WRITE_COMPLETE,
	HECI_FLOW_CONTROL,
	HECI_READING,
	HECI_READ_COMPLETE
};

/* HECI CB */
enum heci_cb_major_types {
	HECI_READ = 0,
	HECI_WRITE,
	HECI_IOCTL,
	HECI_OPEN,
	HECI_CLOSE
};

/* HECI user data struct */
struct heci_message_data {
	uint32_t size;
	char *data;
#ifndef  _LP64
	char *pad;
#endif
};

#define	HECI_CONNECT_TIMEOUT	3	/* at least 2 seconds */

#define	IAMTHIF_STALL_TIMER	12	/* seconds */
#define	IAMTHIF_READ_TIMER	15	/* seconds */
struct heci_file {
	void * private_data;
};

struct heci_cb_private {
	struct list_node cb_list;
	enum heci_cb_major_types major_file_operations;
	void *file_private;
	struct heci_message_data request_buffer;
	struct heci_message_data response_buffer;
	unsigned long information;
	unsigned long read_time;
	struct heci_file *file_object;
};


struct io_heci_list {
	struct heci_cb_private heci_cb;
	int status;
	struct iamt_heci_device *device_extension;
};

struct heci_driver_version {
	uint8_t major;
	uint8_t minor;
	uint8_t hotfix;
	uint16_t build;
};

struct heci_client {
	uint32_t max_message_length;
	uint8_t protocol_version;
};

/*
 *  HECI BUS Interface Section
 */
struct heci_msg_hdr {
	uint32_t me_addr:8;
	uint32_t host_addr:8;
	uint32_t length:9;
	uint32_t reserved:6;
	uint32_t msg_complete:1;
};


struct hbm_cmd {
	uint8_t cmd:7;
	uint8_t is_response:1;
};


struct heci_bus_message {
	struct hbm_cmd cmd;
	uint8_t command_specific_data[];
};

struct hbm_version {
	uint8_t minor_version;
	uint8_t major_version;
};

struct hbm_host_version_request {
	struct hbm_cmd cmd;
	uint8_t reserved;
	struct hbm_version host_version;
};

struct hbm_host_version_response {
	struct hbm_cmd cmd;
	int host_version_supported;
	struct hbm_version me_max_version;
};

struct hbm_host_stop_request {
	struct hbm_cmd cmd;
	uint8_t reason;
	uint8_t reserved[2];
};

struct hbm_host_stop_response {
	struct hbm_cmd cmd;
	uint8_t reserved[3];
};

struct hbm_me_stop_request {
	struct hbm_cmd cmd;
	uint8_t reason;
	uint8_t reserved[2];
};

struct hbm_host_enum_request {
	struct hbm_cmd cmd;
	uint8_t reserved[3];
};

struct hbm_host_enum_response {
	struct hbm_cmd cmd;
	uint8_t reserved[3];
	uint8_t valid_addresses[32];
};

struct heci_client_properties {
	struct guid protocol_name;
	uint8_t protocol_version;
	uint8_t max_number_of_connections;
	uint8_t fixed_address;
	uint8_t single_recv_buf;
	uint32_t max_msg_length;
};

struct hbm_props_request {
	struct hbm_cmd cmd;
	uint8_t address;
	uint8_t reserved[2];
};


struct hbm_props_response {
	struct hbm_cmd cmd;
	uint8_t address;
	uint8_t status;
	uint8_t reserved[1];
	struct heci_client_properties client_properties;
};

struct hbm_client_connect_request {
	struct hbm_cmd cmd;
	uint8_t me_addr;
	uint8_t host_addr;
	uint8_t reserved;
};

struct hbm_client_connect_response {
	struct hbm_cmd cmd;
	uint8_t me_addr;
	uint8_t host_addr;
	uint8_t status;
};

struct hbm_client_disconnect_request {
	struct hbm_cmd cmd;
	uint8_t me_addr;
	uint8_t host_addr;
	uint8_t reserved[1];
};

struct hbm_flow_control {
	struct hbm_cmd cmd;
	uint8_t me_addr;
	uint8_t host_addr;
	uint8_t reserved[HECI_FC_MESSAGE_RESERVED_LENGTH];
};

struct heci_me_client {
	struct heci_client_properties props;
	uint8_t client_id;
	uint8_t flow_ctrl_creds;
};

#pragma pack()
/* Private file struct */
struct heci_file_private {
	struct list_node link;
	struct heci_file *file;
	enum file_state state;
	struct pollhead tx_pollwait;
	kcondvar_t	rx_wait;
	struct pollhead pollwait;
	kmutex_t file_lock;
	kmutex_t read_io_lock;
	kmutex_t write_io_lock;
	int read_pending;
	int status;
	/* ID of client connected */
	uint8_t host_client_id;
	uint8_t me_client_id;
	uint8_t flow_ctrl_creds;
	uint8_t timer_count;
	enum heci_file_transaction_states reading_state;
	enum heci_file_transaction_states writing_state;
	int sm_state;
	struct heci_cb_private *read_cb;
};

/* private device struct */
struct iamt_heci_device {
	dev_info_t	*dip;
	ddi_acc_handle_t io_handle;
	ddi_iblock_cookie_t sc_iblk;

	/*
	 * lists of queues
	 */

	/* array of pointers to  aio lists */
	struct io_heci_list *io_list_array[HECI_IO_LISTS_NUMBER];
	struct io_heci_list read_list;	/* driver read queue */
	struct io_heci_list write_list;	/* driver write queue */
	struct io_heci_list write_waiting_list;	/* write waiting queue */
	struct io_heci_list ctrl_wr_list;	/* managed write IOCTL list */
	struct io_heci_list ctrl_rd_list;	/* managed read IOCTL list */
	struct io_heci_list pthi_cmd_list;	/* PTHI list for cmd waiting */

	/* driver managed PTHI list for reading completed pthi cmd data */
	struct io_heci_list pthi_read_complete_list;
	/*
	 * list of files
	 */
	struct list_node file_list;
	/*
	 * memory of device
	 */
	char *mem_addr;
	/*
	 * lock for the device
	 */
	kmutex_t device_lock;
	ddi_taskq_t	*work;
	int recvd_msg;

	ddi_taskq_t *reinit_tsk;
	timeout_id_t wd_timer;
	/*
	 * hw states of host and fw(ME)
	 */
	uint32_t host_hw_state;
	uint32_t me_hw_state;
	/*
	 * waiting queue for receive message from FW
	 */
	kcondvar_t wait_recvd_msg;
	kcondvar_t wait_stop_wd;
	/*
	 * heci device  states
	 */
	enum heci_states heci_state;
	int stop;

	uint32_t extra_write_index;
	uint32_t rd_msg_buf[128];	/* used for control messages */
	uint32_t wr_msg_buf[128];	/* used for control messages */
	uint32_t ext_msg_buf[8];	/* for control responses    */
	uint32_t rd_msg_hdr;

	struct hbm_version version;

	int host_buffer_is_empty;
	struct heci_file_private wd_file_ext;
	struct heci_me_client *me_clients; /* Note: need to be allocated */
	uint8_t heci_me_clients[32];	/* list of existing clients */
	uint8_t num_heci_me_clients;
	uint8_t heci_host_clients[32];	/* list of existing clients */
	uint8_t current_host_client_id;

	int wd_pending;
	int wd_stoped;
	uint16_t wd_timeout;	/* seconds ((wd_data[1] << 8) + wd_data[0]) */
	unsigned char wd_data[HECI_START_WD_DATA_SIZE];


	uint16_t wd_due_counter;
	int asf_mode;
	int wd_bypass;	/* if 1, don't refresh watchdog ME client */

	struct heci_file *iamthif_file_object;
	struct heci_file_private iamthif_file_ext;
	int iamthif_ioctl;
	int iamthif_canceled;
	uint32_t iamthif_timer;
	uint32_t iamthif_stall_timer;
	struct heci_file files[256]; /* a file handle for each client */
	unsigned char iamthif_msg_buf[IAMTHIF_MTU];
	uint32_t iamthif_msg_buf_size;
	uint32_t iamthif_msg_buf_index;
	int iamthif_flow_control_pending;
	enum iamthif_states iamthif_state;

	struct heci_cb_private *iamthif_current_cb;
	uint8_t write_hang;
	int need_reset;
	long open_handle_count;

};

/*
 * read_heci_register - Read a byte from the heci device
 *
 * @device: the device structure
 * @offset: offset from which to read the data
 *
 * @return the byte read.
 */
uint32_t read_heci_register(struct iamt_heci_device *device,
			    unsigned long offset);

/*
 * write_heci_register - Write  4 bytes to the heci device
 *
 * @device: the device structure
 * @offset: offset from which to write the data
 * @value: the byte to write
 */
void write_heci_register(struct iamt_heci_device *device, unsigned long offset,
		uint32_t value);

#define	UIO_OFFSET(p)	(((struct uio *)p)->uio_offset)
#define	UIO_LENGTH(p)	(((struct uio *)p)->uio_resid)
#define	UIO_BUFF(p)	((char *)((struct uio *)p)->uio_iov->iov_base)

#endif /* _HECI_DATA_STRUCTURES_H_ */
