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

#ifndef _T10_H
#define	_T10_H

/*
 * This header file describes the service level between the transport
 * layer and the emulation portion. These procedure calls can be thought
 * of as part of the T10 SAM-3 specification.
 */

#ifdef __cplusplus
extern "C" {
#endif

/*
 * Here are the header files which are required to define references found
 * in this file. No other header files are to be included.
 */
#include <pthread.h>
#include <sys/avl.h>
#include <signal.h>
#include <sys/scsi/generic/sense.h>

#include "queue.h"

#ifdef lint
/*
 * lints sees aio_return64, but can't find it in the aio structure. To keep
 * lint happy this define is used.
 */
#define	aio_return64 aio_return
#endif

typedef void *transport_t;
typedef void *t10_targ_handle_t;

typedef void *t10_lun_handle_t;

typedef void *emul_handle_t;
typedef void *emul_cmd_t;

typedef	enum {
	ClearSet,
	ResetTarget,
	ResetLun,
	InventoryChange,
	CapacityChange,
	DeviceOnline,
	DeviceOffline
} TaskOp_t;

/*
 * For an explanation of the t10_cmd_state_t and t10_cmd_event_t
 * see t10_sam.c:t10_cmd_state_machine()
 */
typedef enum {
	T10_Cmd_S1_Free		= 1,
	T10_Cmd_S2_In,
	T10_Cmd_S3_Trans,
	T10_Cmd_S4_AIO,
	T10_Cmd_S5_Wait,
	T10_Cmd_S6_Freeing_In,
	T10_Cmd_S7_Freeing_AIO
} t10_cmd_state_t;

typedef enum {
	T10_Cmd_T1		= 1,
	T10_Cmd_T2,
	T10_Cmd_T3,
	T10_Cmd_T4,
	T10_Cmd_T5,
	T10_Cmd_T6,		/* cancel */
	T10_Cmd_T7,
	T10_Cmd_T8		/* shutdown */
} t10_cmd_event_t;

typedef enum {
	lu_online,
	lu_offline,
	lu_errored
} t10_lu_state_t;

/*
 * The t10_cmd_t structure bridges the gap between the transport and
 * emulation services. At certain times either the transport or emulation
 * service needs to access the data stored within this structure.
 * For now we'll just use macros which hide the reference, but in the
 * future when the transport and emulation services are loadable modules
 * these macros will become functions so that the structure can change
 * inside of the T10 space and not cause compatibility issues.
 */
#define	T10_MAX_OUT(cmd)	(cmd->c_lu->l_targ->s_maxout)
#define	T10_MMAP_AREA(cmd)	(cmd->c_lu->l_common->l_mmap)
#define	T10_PARAMS_AREA(cmd)	trans_params_area(cmd)
#define	T10_TRANS_ID(cmd)	(cmd->c_trans_id)
#define	T10_DATA(cmd)		(cmd->c_data)
#define	T10_DATA_LEN(cmd)	(cmd->c_data_len)
#define	T10_DATA_OFFSET(cmd)	(cmd->c_offset)
#define	T10_CMD_LAST(cmd)	(cmd->c_last)
#define	T10_CMD_STATUS(cmd)	(cmd->c_cmd_status)
#define	T10_CMD_RESID(cmd)	(cmd->c_resid)
#define	T10_SENSE_LEN(cmd)	(cmd->c_cmd_sense_len)
#define	T10_SENSE_DATA(cmd)	(cmd->c_cmd_sense)
#define	T10_PGR_TNAME(cmd)	(cmd->c_lu->l_targ->s_targ_base)
#define	T10_PGR_INAME(cmd)	(cmd->c_lu->l_targ->s_i_name)

#define	T10_DEFAULT_TPG	1

/*
 * []------------------------------------------------------------------[]
 * | SAM-3 revision 14, section 4.9 -- Logical Unit Numbers		|
 * | The specification allows for 64-bit LUNs, but at this point	|
 * | most OSes don't support that many. Section 4.9.7, table 9 gives	|
 * | the Flat Space Addressing Method which allows for 16,383 LUNs.	|
 * | This will be the imposed maximum even though the code can support	|
 * | more. Raise this number if needed.					|
 * []------------------------------------------------------------------[]
 */
#define	T10_MAX_LUNS	16383

/*
 * SPC-3 Revision 21c, Section 6.4.2 Table 85
 * Version Descriptor Values
 */
#define	T10_TRANS_ISCSI		0x960 /* iSCSI (no version claimed) */
#define	T10_TRANS_FC		0x8c0 /* FCP (no version claimed) */

typedef struct t10_aio {
	/*
	 * This must be the first member of the structure. aioread/aiowrite
	 * take as one of the arguments an pointer to a aio_result_t
	 * structure. When the operation is complete the aio_return and
	 * aio_errno of that structure are updated. When aiowait() is
	 * called the address of that aio_result_t is returned. By having
	 * this structure at the beginning we can pass in the data_ptr
	 * structure address. The ste_aio_process thread will get everything
	 * it needs from the aiowait to send a message to the correct
	 * STE thread. Clear as mud?
	 */
	aio_result_t	a_aio;

	void		(*a_aio_cmplt)(emul_cmd_t id);
	emul_cmd_t	a_id;
	struct t10_cmd	*a_cmd;
} t10_aio_t;

/*
 * Bidirectional structure used to track requests from the transport
 * and send reponse data from the emulation.
 *
 * The glue logic for t10_send_cmd will allocate this structure, fill in
 * in with the provided data and put it on the LUN queue. The LUN thread
 * will dequeue this request and call the appropriate LUN command interpreter.
 */
typedef struct t10_cmd {
	/*
	 * Transport specific tracking value. If this value is non-zero it
	 * means this command was part of a previous command that wasn't
	 * completed. Currently this is only used for DATA_OUT (SCSI write op)
	 * commands.
	 */
	transport_t		c_trans_id;

	t10_cmd_state_t		c_state;

	/*
	 * Emulation specific tracking value.
	 */
	emul_cmd_t		c_emul_id;

	/*
	 * Per I_T_L structure used to determine which command
	 * interpreter to call and which transport queue to send the response.
	 */
	struct t10_lu_impl	*c_lu;

	/*
	 * Pointer to command buffer. No interpretation of data is
	 * done by the glue logic. Interpretation is done by the LUN
	 * emulation code.
	 */
	uint8_t			*c_cdb;
	size_t			c_cdb_len;

	/*
	 * Optional offset into the command. If more than one response
	 * is required this value indicates where the data belongs.
	 */
	off_t			c_offset;

	/*
	 * Data for transfer.
	 */
	char			*c_data;
	size_t			c_data_len;
	size_t			c_resid;

	/*
	 * Indicates if this response is the last to be sent
	 * and will be followed closely by a complete message. Enables
	 * transports to phase collapse the final READ data PDU with
	 * completion PDU if possible.
	 */
	Boolean_t		c_last;

	/*
	 * When the transport is finished sending the data it will
	 * call t10_cmd_destroy() which will cause the SAM-3 layer to
	 * call the emulation function stored here with this command
	 * pointer. The emulation code is responsible for freeing any
	 * memory it allocated.
	 */
	void			(*c_emul_complete)(emul_handle_t id);

	/*
	 * During transitions from T10 layer to transport one of three
	 * messages are sent. The state machine needs access to these
	 * values to pass things along so we keep it here.
	 */
	msg_type_t		c_msg;

	/*
	 * SCSI sense information.
	 */
	int			c_cmd_status;
	char			*c_cmd_sense;
	size_t			c_cmd_sense_len;

	/*
	 * List of active commands at the ITL level.
	 */
	avl_tree_t		c_cmd_avl;

	struct t10_cmd		*c_cmd_next;
} t10_cmd_t;

/*
 * Each LU has a structure which contains common data for all I_T's who
 * access this LU.
 */
typedef struct t10_lu_common {
	/*
	 * Logic Unit Number
	 */
	int			l_num;

	/*
	 * state of device
	 */
	t10_lu_state_t		l_state;

	/*
	 * Internal ID which will be unique for all LUs. This will be
	 * used for log messages to help tracking details.
	 */
	int			l_internal_num;

	/*
	 * Thread ID which is running this logical unit. This is currently
	 * used for only one purpose which is to locate this structure
	 * in case of a SIGBUS. It's possible for the underlying file system
	 * to run out of space for an mmap'd LU. The only means of notification
	 * the OS has is to send a SIGBUS. The thread only receives the memory
	 * address, so we look for our thread ID amongst all of the LU
	 * available.
	 */
	pthread_t		l_thr_id;

	/*
	 * If we receive a SIGBUS the initiator needs to be notified that
	 * something bad has occurred. This means we need to know which
	 * command was being emulated so that we can find the appropriate
	 * transport.
	 * Special handling needs to be done if the thread is initializing
	 * the LU so we need a flag to indicate that fact.
	 */
	t10_cmd_t		*l_curr;
	Boolean_t		l_curr_provo;

	/*
	 * The implementation uses a 16 byte EUI value for the GUID.
	 * Not only is this value used for SCSI INQUIRY data, but it
	 * is used to distinquish this common LUN from other LUNs in
	 * the AVL tree.
	 */
	uint8_t			*l_guid;
	size_t			l_guid_len;

	/*
	 * Other common information which is needed for ever device
	 * type.
	 */
	int			l_dtype;
	char			*l_pid,
				*l_vid;

	/*
	 * Each dtype has different parameters that it uses. This
	 * is a place holder for storing a pointer to some structure which
	 * contains that information.
	 */
	void			*l_dtype_params;

	/*
	 * Parameter information in XML format.
	 */
	tgt_node_t		*l_root;
	Boolean_t		l_root_okay_to_free;

	/*
	 * File descriptor for the open file which is the backing store
	 * for this device. This can be a regular file or a character
	 * special device if we're acting as a bridge between transports.
	 */
	int			l_fd;

	void			*l_mmap;
	off64_t			l_size;

	Boolean_t		l_fast_write_ack;

	/*
	 * AVL tree containing all I_T_L nexus' which are actively using
	 * this LUN.
	 */
	avl_tree_t		l_all_open;

	/*
	 * Each I_T will place requests for command emulation on this
	 * queue. Common requests are msg_ste_cmd and msg_ste_shutdown
	 */
	target_queue_t		*l_from_transports;

	/*
	 * Mutex used to lock access to the AVL tree.
	 */
	pthread_mutex_t		l_common_mutex;

	/*
	 * When a target is looking to see if an existing LUN is opened
	 * a search of all LUNs needs to be done and will use this
	 * AVL node. This field is modified only by the AVL code.
	 */
	avl_node_t		l_all_luns;
} t10_lu_common_t;

/*
 * Each I_T_L has a LU structure associated with it.
 */
typedef struct t10_lu_impl {
	/*
	 * pointer to common area of LUN.
	 */
	t10_lu_common_t		*l_common;
	pthread_mutex_t		l_mutex;

	/*
	 * Mutex to protect access to active commands
	 */
	pthread_mutex_t		l_cmd_mutex;
	pthread_cond_t		l_cmd_cond;
	Boolean_t		l_wait_for_drain;

	avl_tree_t		l_cmds;

	/*
	 * Queue for sending command results and R2T results back
	 * to the transport.
	 */
	target_queue_t		*l_to_transport;

	/*
	 * Back pointer to target structure who created this LUN reference.
	 */
	struct t10_targ_impl	*l_targ;

	struct scsi_cmd_table	*l_cmd_table;

	/*
	 * Per LU methods for issuing commands and data to the
	 * DTYPE emulator.
	 */
	void			(*l_cmd)(t10_cmd_t *cmd, uint8_t *cdb,
	    size_t cdb_len);
	void			(*l_data)(t10_cmd_t *cmd, emul_handle_t e,
	    size_t offset, char *data, size_t data_len);

	/*
	 * AVL node information for all other I_T nexus' who are referencing
	 * this LUN. This is used by the AVL code and *not* modified by
	 * this daemon directly.
	 */
	avl_node_t		l_open_lu_node;

	/*
	 * AVL node information for all LUN's being access by this I_T nexus.
	 * This is used by the AVL code and *not* modified by this daemon
	 * directly.
	 */
	avl_node_t		l_open_targ_node;

	/*
	 * Logical Unit Number. This value is used as the comparision value
	 * for the AVL search at the per target level.
	 */
	int			l_targ_lun;

	Boolean_t		l_dsense_enabled;
	Boolean_t		l_pgr_read;

	/*
	 * Statistics on a per ITL basis
	 */
	uint64_t		l_cmds_read,
				l_cmds_write,
				l_sects_read,
				l_sects_write;

	/*
	 * Each time a command is run the value of l_status is checked.
	 * If non-zero the command isn't executed and instead a transport
	 * complete message is sent with these values. This is commonly
	 * used to send UNIT ATTENTION for things like power on.
	 * -- Do we need some sort of stack to push and pop these values?
	 */
	int			l_status,
				l_asc,
				l_ascq;
} t10_lu_impl_t;

typedef struct t10_targ_impl {
	char			*s_i_name;
	char			*s_targ_base;
	int			s_targ_num; /* used in log messages */
	avl_tree_t		s_open_lu;
	pthread_mutex_t		s_mutex;

	/*
	 * The transport layer will set the maximum output size
	 * it's able to deal with during a call to set_create_handle()
	 */
	size_t			s_maxout;

	/*
	 * Target Port Set
	 */
	int			s_tpgt;

	/*
	 * transport version number to use in standard inquiry data
	 */
	int			s_trans_vers;

	/*
	 * Transport response queue. This queue will be stored in each
	 * lun that gets created.
	 */
	target_queue_t		*s_to_transport;

	/*
	 * During a SCSI WRITE the emulation will call trans_rqst_datain.
	 * If the transport indicated data was available by using non-zero
	 * values for the optional data and length when t10_send_cmd was
	 * called this callback is used when the emulation requests data.
	 */
	void		(*s_dataout_cb)(t10_cmd_t *, char *data,
	    size_t *data_len);

} t10_targ_impl_t;

typedef struct t10_shutdown {
	t10_lu_impl_t	*t_lu;
	target_queue_t	*t_q;
} t10_shutdown_t;

typedef struct scsi_cmd_table {
	void	(*cmd_start)(struct t10_cmd *, uint8_t *, size_t);
	void	(*cmd_data)(struct t10_cmd *, emul_handle_t e,
			    size_t offset, char *data, size_t data_len);
	void	(*cmd_end)(emul_handle_t e);
	char	*cmd_name;
} scsi_cmd_table_t;

typedef struct sam_device_table {
	Boolean_t	(*t_common_init)(t10_lu_common_t *);
	void		(*t_common_fini)(t10_lu_common_t *);
	void		(*t_per_init)(t10_lu_impl_t *);
	void		(*t_per_fini)(t10_lu_impl_t *);
	void		(*t_task_mgmt)(t10_lu_common_t *, TaskOp_t);
	char		*t_type_name;
} sam_device_table_t;

typedef struct t10_conn_shutdown {
	target_queue_t *t10_to_conn_q;
	target_queue_t *conn_to_t10_q;
} t10_conn_shutdown_t;

/*
 * []----
 * | Interfaces
 * []----
 */

extern target_queue_t *mgmtq;
void t10_init(target_queue_t *q);
void lu_buserr_handler(int sig, siginfo_t *sip, void *v);

/*
 * []------------------------------------------------------------------[]
 * | Methods called by the transports					|
 * []------------------------------------------------------------------[]
 */
/*
 * t10_handle_create -- create target handle to be used by transports
 */
t10_targ_handle_t
t10_handle_create(char *targ, char *init, int trans_vers, int tpg, int max_out,
    target_queue_t *tq, void (*datain_cb)(t10_cmd_t *, char *, size_t *));

/*
 * t10_handle_disable -- drains commands from emulation queues
 */
void
t10_handle_disable(t10_targ_handle_t t);

/*
 * t10_handle_destroy -- free resources used by handle
 */
int
t10_handle_destroy(t10_targ_handle_t t, Boolean_t wait);

Boolean_t
t10_cmd_create(t10_targ_handle_t t, int lun_number, uint8_t *cdb,
    size_t cdb_len, transport_t trans_id, t10_cmd_t **);

/*
 * t10_send_cmd -- send a command block to an target/LUN for emulation
 */
Boolean_t
t10_cmd_send(t10_targ_handle_t t, t10_cmd_t *cmd,
    char *opt_data, size_t opt_data_len);

Boolean_t
t10_cmd_data(t10_targ_handle_t t, t10_cmd_t *cmd, size_t offset,
    char *data, size_t data_len);

void
t10_cmd_done(t10_cmd_t *cmd);

Boolean_t
t10_task_mgmt(t10_targ_handle_t t, TaskOp_t op, int opt_lun, void *tag);

/*
 * t10_cmd_shoot_event -- perform transition to the  state of a T10 command
 */
void t10_cmd_shoot_event(t10_cmd_t *c, t10_cmd_event_t e);

void t10_targ_stat(t10_targ_handle_t t, char **buf);

/*
 * t10_thick_provision -- management function used when creating a new lun
 */
Boolean_t t10_thick_provision(char *target, int lun, target_queue_t *q);

/*
 * []------------------------------------------------------------------[]
 * | Methods called by the emulation routines				|
 * []------------------------------------------------------------------[]
 */

t10_cmd_t *trans_cmd_dup(t10_cmd_t *cmd);

/*
 * trans_send_datain -- Emulation layer sending data to initiator
 */
Boolean_t trans_send_datain(t10_cmd_t *cmd, char *data, size_t data_len,
    size_t offset, void (*callback)(emul_handle_t t), Boolean_t last,
    emul_handle_t id);

/*
 * trans_rqst_dataout -- Emulation needs more data to complete request
 */
Boolean_t trans_rqst_dataout(t10_cmd_t *cmd, char *data, size_t data_len,
    size_t offset, emul_cmd_t emul_id, void (*callback)(emul_handle_t e));

/*
 * trans_send_complete -- Emulation has completed request w/ opt. sense data
 */
void trans_send_complete(t10_cmd_t *cmd, int t10_status);

/*
 * trans_aiowrite -- asynchronous write and kicks the aio wait thread
 */
void trans_aiowrite(t10_cmd_t *cmd, char *data, size_t data_len, off_t offset,
    t10_aio_t *taio);

/*
 * trans_aioread -- asynchronous read and kicks the aio wait thread
 */
void trans_aioread(t10_cmd_t *cmd, char *data, size_t data_len, off_t offset,
    t10_aio_t *taio);

/*
 * trans_params_area -- given a t10_cmd return the dtype params
 */
void *trans_params_area(t10_cmd_t *cmd);

/*
 * []------------------------------------------------------------------[]
 * | Declaration of emulation entry points				|
 * []------------------------------------------------------------------[]
 */
Boolean_t sbc_common_init(t10_lu_common_t *lu);
void sbc_common_fini(t10_lu_common_t *lu);
void sbc_task_mgmt(t10_lu_common_t *lu, TaskOp_t op);
void sbc_per_init(t10_lu_impl_t *itl);
void sbc_per_fini(t10_lu_impl_t *itl);
Boolean_t ssc_common_init(t10_lu_common_t *lu);
void ssc_common_fini(t10_lu_common_t *lu);
void ssc_task_mgmt(t10_lu_common_t *lu, TaskOp_t op);
void ssc_per_init(t10_lu_impl_t *itl);
void ssc_per_fini(t10_lu_impl_t *itl);
Boolean_t raw_common_init(t10_lu_common_t *lu);
void raw_common_fini(t10_lu_common_t *lu);
void raw_per_init(t10_lu_impl_t *itl);
void raw_per_fini(t10_lu_impl_t *itl);
void raw_task_mgmt(t10_lu_common_t *lu, TaskOp_t op);
Boolean_t osd_common_init(t10_lu_common_t *lu);
void osd_common_fini(t10_lu_common_t *lu);
void osd_per_init(t10_lu_impl_t *itl);
void osd_per_fini(t10_lu_impl_t *itl);
void osd_task_mgmt(t10_lu_common_t *lu, TaskOp_t op);

#ifdef __cplusplus
}
#endif

#endif /* _T10_H */
