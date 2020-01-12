/*
 * This file and its contents are supplied under the terms of the
 * Common Development and Distribution License ("CDDL"), version 1.0.
 * You may only use this file in accordance with the terms of version
 * 1.0 of the CDDL.
 *
 * A full copy of the text of the CDDL should have accompanied this
 * source.  A copy of the CDDL is also available via the Internet at
 * http://www.illumos.org/license/CDDL.
 */

/*
 * Copyright 2019, Joyent, Inc.
 */

/*
 * USB CCID class driver
 *
 * Slot Detection
 * --------------
 *
 * A CCID reader has one or more slots, each of which may or may not have a ICC
 * (integrated circuit card) present. Some readers actually have a card that's
 * permanently plugged in while other readers allow for cards to be inserted and
 * removed. We model all CCID readers that don't have removable cards as ones
 * that are removable, but never fire any events. Readers with removable cards
 * are required to have an Interrupt-IN pipe.
 *
 * Each slot starts in an unknown state. After attaching we always kick off a
 * discovery. When a change event comes in, that causes us to kick off a
 * discovery again, though we focus it only on those endpoints that have noted a
 * change. At attach time we logically mark that every endpoint has changed,
 * allowing us to figure out what its actual state is. We don't rely on any
 * initial Interrupt-IN polling to allow for the case where either the hardware
 * doesn't report it or to better handle the devices without an Interrupt-IN
 * entry. Just because we open up the Interrupt-IN pipe, hardware is not
 * obligated to tell us, as the detaching and reattaching of a driver will not
 * cause a power cycle.
 *
 * The Interrupt-IN exception callback may need to restart polling. In addition,
 * we may fail to start or restart polling due to a transient issue. In cases
 * where the attempt to start polling has failed, we try again in one second
 * with a timeout.
 *
 * Discovery is run through a taskq. The various slots are checked serially. If
 * a discovery is running when another change event comes in, we flag ourselves
 * for a follow up run. This means that it's possible that we end up processing
 * items early and that the follow up run is ignored.
 *
 * Two state flags are used to keep track of this dance: CCID_F_WORKER_REQUESTED
 * and CCID_F_WORKER_RUNNING. The first is used to indicate that discovery is
 * desired. The second is to indicate that it is actively running. When
 * discovery is requested, the caller first checks the current flags. If neither
 * flag is set, then it knows that it can kick off discovery. Regardless if it
 * can kick off the taskq, it always sets requested. Once the taskq entry
 * starts, it removes any DISCOVER_REQUESTED flags and sets DISCOVER_RUNNING. If
 * at the end of discovery, we find that another request has been made, the
 * discovery function will kick off another entry in the taskq.
 *
 * The one possible problem with this model is that it means that we aren't
 * throttling the set of incoming requests with respect to taskq dispatches.
 * However, because these are only driven by an Interrupt-IN pipe, it is hoped
 * that the frequency will be rather reduced. If it turns out that that's not
 * the case, we may need to use a timeout or another trick to ensure that only
 * one discovery per tick or so is initialized. The main reason we don't just do
 * that off the bat and add a delay is because of contactless cards which may
 * need to be acted upon in a soft real-time fashion.
 *
 * Command Handling
 * ----------------
 *
 * Commands are issued to a CCID reader on a Bulk-OUT pipe. Responses are
 * generated as a series of one or more messages on a Bulk-IN pipe. To correlate
 * these commands a sequence number is used. This sequence number is one byte
 * and can be in the range [ CCID_SEQ_MIN, CCID_SEQ_MAX ]. To keep track of the
 * allocated IDs we leverage an ID space.
 *
 * A CCID reader contains a number of slots. Each slot can be addressed
 * separately as each slot represents a separate place that a card may be
 * inserted or not. A given slot may only have a single outstanding command. A
 * given CCID reader may only have a number of commands outstanding to the CCID
 * device as a whole based on a value in the class descriptor (see the
 * ccd_bMacCCIDBusySlots member of the ccid_class_descr_t).
 *
 * To simplify the driver, we only support issuing a single command to a CCID
 * reader at any given time. All commands that are outstanding are queued in a
 * per-device list ccid_command_queue. The head of the queue is the current
 * command that we believe is outstanding to the reader or will be shortly. The
 * command is issued by sending a Bulk-OUT request with a CCID header. Once we
 * have the Bulk-OUT request acknowledged, we begin sending Bulk-IN messages to
 * the controller. Once the Bulk-IN message is acknowledged, then we complete
 * the command and proceed to the next command. This is summarized in the
 * following state machine:
 *
 *              +-----------------------------------------------------+
 *              |                                                     |
 *              |                        ccid_command_queue           |
 *              |                    +---+---+---------+---+---+      |
 *              v                    | h |   |         |   | t |      |
 *  +-------------------------+      | e |   |         |   | a |      |
 *  | ccid_command_dispatch() |<-----| a |   |   ...   |   | i |      |
 *  +-----------+-------------+      | d |   |         |   | l |      |
 *              |                    +---+---+---------+---+---+      |
 *              v                                                     |
 *  +-------------------------+      +-------------------------+      |
 *  | usb_pipe_bulk_xfer()    |----->| ccid_dispatch_bulk_cb() |      |
 *  | ccid_bulkout_pipe       |      +------------+------------+      |
 *  +-------------------------+                   |                   |
 *                                                |                   |
 *              |                                 v                   |
 *              |                    +-------------------------+      |
 *              |                    | ccid_bulkin_schedule()  |      |
 *              v                    +------------+------------+      |
 *                                                |                   |
 *     /--------------------\                     |                   |
 *    /                      \                    v                   |
 *    |  ###    CCID HW      |       +-------------------------+      |
 *    |  ###                 |       | usb_pipe_bulk_xfer()    |      |
 *    |                      | ----> | ccid_bulkin_pipe        |      |
 *    |                      |       +------------+------------+      |
 *    \                      /                    |                   |
 *     \--------------------/                     |                   |
 *                                                v                   |
 *                                   +-------------------------+      |
 *                                   | ccid_reply_bulk_cb()    |      |
 *                                   +------------+------------+      |
 *                                                |                   |
 *                                                |                   |
 *                                                v                   |
 *                                   +-------------------------+      |
 *                                   | ccid_command_complete() +------+
 *                                   +-------------------------+
 *
 *
 * APDU and TPDU Processing and Parameter Selection
 * ------------------------------------------------
 *
 * Readers provide four different modes for us to be able to transmit data to
 * and from the card. These are:
 *
 * 1. Character Mode 2. TPDU Mode 3. Short APDU Mode 4. Extended APDU Mode
 *
 * Readers either support mode 1, mode 2, mode 3, or mode 3 and 4. All readers
 * that support extended APDUs support short APDUs. At this time, we do not
 * support character mode or TPDU mode, and we use only short APDUs even for
 * readers that support extended APDUs.
 *
 * The ICC and the reader need to be in agreement in order for them to be able
 * to exchange information. The ICC indicates what it supports by replying to a
 * power on command with an ATR (answer to reset). This data can be parsed to
 * indicate which of two protocols the ICC supports. These protocols are
 * referred to as:
 *
 *  o T=0
 *  o T=1
 *
 * These protocols are defined in the ISO/IEC 7816-3:2006 specification. When a
 * reader supports an APDU mode, then the driver does not have to worry about
 * the underlying protocol and can just send an application data unit (APDU).
 * Otherwise, the driver must take the application data (APDU) and transform it
 * into the form required by the corresponding protocol.
 *
 * There are several parameters that need to be negotiated to ensure that the
 * protocols work correctly. To negotiate these parameters and to select a
 * protocol, the driver must construct a PPS (protocol and parameters structure)
 * request and exchange that with the ICC. A reader may optionally take care of
 * performing this and indicates its support for this in dwFeatures member of
 * the USB class descriptor.
 *
 * In addition, the reader itself must often be told of these configuration
 * changes through the means of a CCID_REQUEST_SET_PARAMS command. Once both of
 * these have been performed, the reader and ICC can communicate to their hearts
 * desire.
 *
 * Both the negotiation and the setting of the parameters can be performed
 * automatically by the CCID reader. When the reader supports APDU exchanges,
 * then it must support some aspects of this negotiation. Because of that, we
 * never consider performing this and only support readers that offer this kind
 * of automation.
 *
 * User I/O Basics
 * ---------------
 *
 * A user performs I/O by writing APDUs (Application Protocol Data Units). A
 * user issues a system call that ends up in write(9E) (write(2), writev(2),
 * pwrite(2), pwritev(2), etc.). The user data is consumed by the CCID driver
 * and a series of commands will then be issued to the device, depending on the
 * protocol mode. The write(9E) call does not block for this to finish. Once
 * write(9E) has returned, the user may block in a read(2) related system call
 * or poll for POLLIN.
 *
 * A thread may not call read(9E) without having called write(9E). This model is
 * due to the limited capability of hardware. Only a single command can be going
 * on a given slot and due to the fact that many commands change the hardware
 * state, we do not try to multiplex multiple calls to write() or read().
 *
 *
 * User I/O, Transaction Ends, ICC removals, and Reader Removals
 * -------------------------------------------------------------
 *
 * While the I/O model given to user land is somewhat simple, there are a lot of
 * tricky pieces to get right because we are in a multi-threaded pre-emptible
 * system. In general, there are four different levels of state that we need to
 * keep track of:
 *
 *   1. User threads in I/O
 *   2. Kernel protocol level support (T=1, apdu, etc.).
 *   3. Slot/ICC state
 *   4. CCID Reader state
 *
 * Of course, each level cares about the state above it. The kernel protocol
 * level state (2) cares about the User threads in I/O (1). The same is true
 * with the other levels caring about the levels above it. With this in mind
 * there are three non-data path things that can go wrong:
 *
 *   A. The user can end a transaction (whether through an ioctl or close(9E)).
 *   B. The ICC can be removed
 *   C. The CCID device can be removed or reset at a USB level.
 *
 * Each of these has implications on the outstanding I/O and other states of
 * the world. When events of type A occur, we need to clean up states 1 and 2.
 * Then events of type B occur we need to clean up states 1-3. When events of
 * type C occur we need to clean up states 1-4. The following discusses how we
 * should clean up these different states:
 *
 * Cleaning up State 1:
 *
 *   To clean up the User threads in I/O there are three different cases to
 *   consider. The first is cleaning up a thread that is in the middle of
 *   write(9E). The second is cleaning up thread that is blocked in read(9E).
 *   The third is dealing with threads that are stuck in chpoll(9E).
 *
 *   To handle the write case, we have a series of flags that is on the CCID
 *   slot's I/O structure (ccid_io_t, cs_io on the ccid_slot_t). When a thread
 *   begins its I/O it will set the CCID_IO_F_PREPARING flag. This flag is used
 *   to indicate that there is a thread that is performing a write(9E), but it
 *   is not holding the ccid_mutex because of the operations that it is taking.
 *   Once it has finished, the thread will remove that flag and instead
 *   CCID_IO_F_IN_PROGRESS will be set. If we find that the CCID_IO_F_PREPARING
 *   flag is set, then we will need to wait for it to be removed before
 *   continuing. The fact that there is an outstanding physical I/O will be
 *   dealt with when we clean up state 2.
 *
 *   To handle the read case, we have a flag on the ccid_minor_t which indicates
 *   that a thread is blocked on a condition variable (cm_read_cv), waiting for
 *   the I/O to complete. The way this gets cleaned up varies a bit on each of
 *   the different cases as each one will trigger a different error to the
 *   thread. In all cases, the condition variable will be signaled. Then,
 *   whenever the thread comes out of the condition variable it will always
 *   check the state to see if it has been woken up because the transaction is
 *   being closed, the ICC has been removed, or the reader is being
 *   disconnected. In all such cases, the thread in read will end up receiving
 *   an error (ECANCELED, ENXIO, and ENODEV respectively).
 *
 *   If we have hit the case that this needs to be cleaned up, then the
 *   CCID_MINOR_F_READ_WAITING flag will be set on the ccid_minor_t's flags
 *   member (cm_flags). In this case, the broader system must change the
 *   corresponding system state flag for the appropriate condition, signal the
 *   read cv, and then wait on an additional cv in the minor, the
 *   ccid_iowait_cv).
 *
 *   Cleaning up the poll state is somewhat simpler. If any of the conditions
 *   (A-C) occur, then we must flag POLLERR. In addition if B and C occur, then
 *   we will flag POLLHUP at the same time. This will guarantee that any threads
 *   in poll(9E) are woken up.
 *
 * Cleaning up State 2.
 *
 *   While the user I/O thread is a somewhat straightforward, the kernel
 *   protocol level is a bit more complicated. The core problem is that when a
 *   user issues a logical I/O through an APDU, that may result in a series of
 *   one or more protocol level physical commands. The core crux of the issue
 *   with cleaning up this state is twofold:
 *
 *     1. We don't want to block a user thread while I/O is outstanding
 *     2. We need to take one of several steps to clean up the aforementioned
 *        I/O
 *
 *   To try and deal with that, there are a number of different things that we
 *   do. The first thing we do is that we clean up the user state based on the
 *   notes in cleaning up in State 1. Importantly we need to _block_ on this
 *   activity.
 *
 *   Once that is done, we need to proceed to step 2. Since we're doing only
 *   APDU processing, this is as simple as waiting for that command to complete
 *   and/or potentially issue an abort or reset.
 *
 *   While this is ongoing an additional flag (CCID_SLOT_F_NEED_IO_TEARDOWN)
 *   will be set on the slot to make sure that we know that we can't issue new
 *   I/O or that we can't proceed to the next transaction until this phase is
 *   finished.
 *
 * Cleaning up State 3
 *
 *   When the ICC is removed, this is not dissimilar to the previous states. To
 *   handle this we need to first make sure that state 1 and state 2 are
 *   finished being cleaned up. We will have to _block_ on this from the worker
 *   thread. The problem is that we have certain values such as the operations
 *   vector, the ATR data, etc. that we need to make sure are still valid while
 *   we're in the process of cleaning up state. Once all that is done and the
 *   worker thread proceeds we will consider processing a new ICC insertion.
 *   The one good side is that if the ICC was removed, then it should be simpler
 *   to handle all of the outstanding I/O.
 *
 * Cleaning up State 4
 *
 *   When the reader is removed, then we need to clean up all the prior states.
 *   However, this is somewhat simpler than the other cases, as once this
 *   happens our detach endpoint will be called to clean up all of our
 *   resources. Therefore, before we call detach, we need to explicitly clean up
 *   state 1; however, we then at this time leave all the remaining state to be
 *   cleaned up during detach(9E) as part of normal tear down.
 */

#include <sys/modctl.h>
#include <sys/errno.h>
#include <sys/conf.h>
#include <sys/ddi.h>
#include <sys/sunddi.h>
#include <sys/cmn_err.h>
#include <sys/sysmacros.h>
#include <sys/stream.h>
#include <sys/strsun.h>
#include <sys/strsubr.h>
#include <sys/filio.h>

#define	USBDRV_MAJOR_VER	2
#define	USBDRV_MINOR_VER	0
#include <sys/usb/usba.h>
#include <sys/usb/usba/usbai_private.h>
#include <sys/usb/clients/ccid/ccid.h>
#include <sys/usb/clients/ccid/uccid.h>

#include <atr.h>

/*
 * Set the amount of parallelism we'll want to have from kernel threads which
 * are processing CCID requests. This is used to size the number of asynchronous
 * requests in the pipe policy. A single command can only ever be outstanding to
 * a single slot. However, multiple slots may potentially be able to be
 * scheduled in parallel. However, we don't actually support this at all and
 * we'll only ever issue a single command. This basically covers the ability to
 * have some other asynchronous operation outstanding if needed.
 */
#define	CCID_NUM_ASYNC_REQS	2

/*
 * This is the number of Bulk-IN requests that we will have cached per CCID
 * device. While many commands will generate a single response, the commands
 * also have the ability to generate time extensions, which means that we'll
 * want to be able to schedule another Bulk-IN request immediately. If we run
 * out, we will attempt to refill said cache and will not fail commands
 * needlessly.
 */
#define	CCID_BULK_NALLOCED		16

/*
 * This is a time in seconds for the bulk-out command to run and be submitted.
 */
#define	CCID_BULK_OUT_TIMEOUT	5
#define	CCID_BULK_IN_TIMEOUT	5

/*
 * There are two different Interrupt-IN packets that we might receive. The
 * first, RDR_to_PC_HardwareError, is a fixed four byte packet. However, the
 * other one, RDR_to_PC_NotifySlotChange, varies in size as it has two bits per
 * potential slot plus one byte that's always used. The maximum number of slots
 * in a device is 256. This means there can be up to 64 bytes worth of data plus
 * the extra byte, so 65 bytes.
 */
#define	CCID_INTR_RESPONSE_SIZE	65

/*
 * Minimum and maximum minor ids. We treat the maximum valid 32-bit minor as
 * what we can use due to issues in some file systems and the minors that they
 * can use. We reserved zero as an invalid minor number to make it easier to
 * tell if things have been initialized or not.
 */
#define	CCID_MINOR_MIN		1
#define	CCID_MINOR_MAX		MAXMIN32
#define	CCID_MINOR_INVALID	0

/*
 * This value represents the minimum size value that we require in the CCID
 * class descriptor's dwMaxCCIDMessageLength member. We got to 64 bytes based on
 * the required size of a bulk transfer packet size. Especially as many CCID
 * devices are these class of speeds. The specification does require that the
 * minimum size of the dwMaxCCIDMessageLength member is at least the size of its
 * bulk endpoint packet size.
 */
#define	CCID_MIN_MESSAGE_LENGTH	64

/*
 * Required forward declarations.
 */
struct ccid;
struct ccid_slot;
struct ccid_minor;
struct ccid_command;

/*
 * This structure is used to map between the global set of minor numbers and the
 * things represented by them.
 *
 * We have two different kinds of  minor nodes. The first are CCID slots. The
 * second are cloned opens of those slots. Each of these items has a
 * ccid_minor_idx_t embedded in them that is used to index them in an AVL tree.
 * Given that the number of entries that should be present here is unlikely to
 * be terribly large at any given time, it is hoped that an AVL tree will
 * suffice for now.
 */
typedef struct ccid_minor_idx {
	id_t cmi_minor;
	avl_node_t cmi_avl;
	boolean_t cmi_isslot;
	union {
		struct ccid_slot *cmi_slot;
		struct ccid_minor *cmi_user;
	} cmi_data;
} ccid_minor_idx_t;

typedef enum ccid_minor_flags {
	CCID_MINOR_F_WAITING		= 1 << 0,
	CCID_MINOR_F_HAS_EXCL		= 1 << 1,
	CCID_MINOR_F_TXN_RESET		= 1 << 2,
	CCID_MINOR_F_READ_WAITING	= 1 << 3,
	CCID_MINOR_F_WRITABLE		= 1 << 4,
} ccid_minor_flags_t;

typedef struct ccid_minor {
	ccid_minor_idx_t	cm_idx;		/* write-once */
	cred_t			*cm_opener;	/* write-once */
	struct ccid_slot	*cm_slot;	/* write-once */
	list_node_t		cm_minor_list;
	list_node_t		cm_excl_list;
	kcondvar_t		cm_read_cv;
	kcondvar_t		cm_iowait_cv;
	kcondvar_t		cm_excl_cv;
	ccid_minor_flags_t	cm_flags;
	struct pollhead		cm_pollhead;
} ccid_minor_t;

typedef enum ccid_slot_flags {
	CCID_SLOT_F_CHANGED		= 1 << 0,
	CCID_SLOT_F_INTR_GONE		= 1 << 1,
	CCID_SLOT_F_INTR_ADD		= 1 << 2,
	CCID_SLOT_F_PRESENT		= 1 << 3,
	CCID_SLOT_F_ACTIVE		= 1 << 4,
	CCID_SLOT_F_NEED_TXN_RESET	= 1 << 5,
	CCID_SLOT_F_NEED_IO_TEARDOWN	= 1 << 6,
	CCID_SLOT_F_INTR_OVERCURRENT	= 1 << 7,
} ccid_slot_flags_t;

#define	CCID_SLOT_F_INTR_MASK	(CCID_SLOT_F_CHANGED | CCID_SLOT_F_INTR_GONE | \
    CCID_SLOT_F_INTR_ADD)
#define	CCID_SLOT_F_WORK_MASK	(CCID_SLOT_F_INTR_MASK | \
    CCID_SLOT_F_NEED_TXN_RESET | CCID_SLOT_F_INTR_OVERCURRENT)
#define	CCID_SLOT_F_NOEXCL_MASK	(CCID_SLOT_F_NEED_TXN_RESET | \
    CCID_SLOT_F_NEED_IO_TEARDOWN)

typedef void (*icc_init_func_t)(struct ccid *, struct ccid_slot *);
typedef int (*icc_transmit_func_t)(struct ccid *, struct ccid_slot *);
typedef void (*icc_complete_func_t)(struct ccid *, struct ccid_slot *,
    struct ccid_command *);
typedef void (*icc_teardown_func_t)(struct ccid *, struct ccid_slot *, int);
typedef void (*icc_fini_func_t)(struct ccid *, struct ccid_slot *);

typedef struct ccid_icc {
	atr_data_t		*icc_atr_data;
	atr_protocol_t		icc_protocols;
	atr_protocol_t		icc_cur_protocol;
	ccid_params_t		icc_params;
	icc_init_func_t		icc_init;
	icc_transmit_func_t	icc_tx;
	icc_complete_func_t	icc_complete;
	icc_teardown_func_t	icc_teardown;
	icc_fini_func_t		icc_fini;
} ccid_icc_t;

/*
 * Structure used to take care of and map I/O requests and things. This may not
 * make sense as we develop the T=0 and T=1 code.
 */
typedef enum ccid_io_flags {
	/*
	 * This flag is used during the period that a thread has started calling
	 * into ccid_write(9E), but before it has finished queuing up the write.
	 * This blocks pollout or another thread in write.
	 */
	CCID_IO_F_PREPARING	= 1 << 0,
	/*
	 * This flag is used once a ccid_write() ICC tx function has
	 * successfully completed. While this is set, the device is not
	 * writable; however, it is legal to call ccid_read() and block. This
	 * flag will remain set until the actual write is done. This indicates
	 * that the transmission protocol has finished.
	 */
	CCID_IO_F_IN_PROGRESS	= 1 << 1,
	/*
	 * This flag is used to indicate that the logical I/O has completed in
	 * one way or the other and that a reader can consume data. When this
	 * flag is set, then POLLIN | POLLRDNORM should be signaled. Until the
	 * I/O is consumed via ccid_read(), calls to ccid_write() will fail with
	 * EBUSY. When this flag is set, the kernel protocol level should be
	 * idle and it should be safe to tear down.
	 */
	CCID_IO_F_DONE		= 1 << 2,
} ccid_io_flags_t;

/*
 * If any of the flags in the POLLOUT group are set, then the device is not
 * writeable. The same distinction isn't true for POLLIN. We are only readable
 * if CCID_IO_F_DONE is set. However, you are allowed to call read as soon as
 * CCID_IO_F_IN_PROGRESS is set.
 */
#define	CCID_IO_F_POLLOUT_FLAGS	(CCID_IO_F_PREPARING | CCID_IO_F_IN_PROGRESS | \
    CCID_IO_F_DONE)
#define	CCID_IO_F_ALL_FLAGS	(CCID_IO_F_PREPARING | CCID_IO_F_IN_PROGRESS | \
    CCID_IO_F_DONE | CCID_IO_F_ABANDONED)

typedef struct ccid_io {
	ccid_io_flags_t	ci_flags;
	size_t		ci_ilen;
	uint8_t		ci_ibuf[CCID_APDU_LEN_MAX];
	mblk_t		*ci_omp;
	kcondvar_t	ci_cv;
	struct ccid_command *ci_command;
	int		ci_errno;
	mblk_t		*ci_data;
} ccid_io_t;

typedef struct ccid_slot {
	ccid_minor_idx_t	cs_idx;		/* WO */
	uint_t			cs_slotno;	/* WO */
	struct ccid		*cs_ccid;	/* WO */
	ccid_slot_flags_t	cs_flags;
	ccid_class_voltage_t	cs_voltage;
	mblk_t			*cs_atr;
	struct ccid_command	*cs_command;
	ccid_minor_t		*cs_excl_minor;
	list_t			cs_excl_waiters;
	list_t			cs_minors;
	ccid_icc_t		cs_icc;
	ccid_io_t		cs_io;
} ccid_slot_t;

typedef enum ccid_attach_state {
	CCID_ATTACH_USB_CLIENT	= 1 << 0,
	CCID_ATTACH_MUTEX_INIT	= 1 << 1,
	CCID_ATTACH_TASKQ	= 1 << 2,
	CCID_ATTACH_CMD_LIST	= 1 << 3,
	CCID_ATTACH_OPEN_PIPES	= 1 << 4,
	CCID_ATTACH_SEQ_IDS	= 1 << 5,
	CCID_ATTACH_SLOTS	= 1 << 6,
	CCID_ATTACH_HOTPLUG_CB	= 1 << 7,
	CCID_ATTACH_INTR_ACTIVE	= 1 << 8,
	CCID_ATTACH_MINORS	= 1 << 9,
} ccid_attach_state_t;

typedef enum ccid_flags {
	CCID_F_HAS_INTR		= 1 << 0,
	CCID_F_NEEDS_PPS	= 1 << 1,
	CCID_F_NEEDS_PARAMS	= 1 << 2,
	CCID_F_NEEDS_DATAFREQ	= 1 << 3,
	CCID_F_DETACHING	= 1 << 5,
	CCID_F_WORKER_REQUESTED	= 1 << 6,
	CCID_F_WORKER_RUNNING	= 1 << 7,
	CCID_F_DISCONNECTED	= 1 << 8
} ccid_flags_t;

#define	CCID_F_DEV_GONE_MASK	(CCID_F_DETACHING | CCID_F_DISCONNECTED)
#define	CCID_F_WORKER_MASK	(CCID_F_WORKER_REQUESTED | \
    CCID_F_WORKER_RUNNING)

typedef struct ccid_stats {
	uint64_t	cst_intr_errs;
	uint64_t	cst_intr_restart;
	uint64_t	cst_intr_unknown;
	uint64_t	cst_intr_slot_change;
	uint64_t	cst_intr_hwerr;
	uint64_t	cst_intr_inval;
	uint64_t	cst_ndiscover;
	hrtime_t	cst_lastdiscover;
} ccid_stats_t;

typedef struct ccid {
	dev_info_t		*ccid_dip;
	kmutex_t		ccid_mutex;
	ccid_attach_state_t	ccid_attach;
	ccid_flags_t		ccid_flags;
	id_space_t		*ccid_seqs;
	ddi_taskq_t		*ccid_taskq;
	usb_client_dev_data_t	*ccid_dev_data;
	ccid_class_descr_t	ccid_class;		/* WO */
	usb_ep_xdescr_t		ccid_bulkin_xdesc;	/* WO */
	usb_pipe_handle_t	ccid_bulkin_pipe;	/* WO */
	usb_ep_xdescr_t		ccid_bulkout_xdesc;	/* WO */
	usb_pipe_handle_t	ccid_bulkout_pipe;	/* WO */
	usb_ep_xdescr_t		ccid_intrin_xdesc;	/* WO */
	usb_pipe_handle_t	ccid_intrin_pipe;	/* WO */
	usb_pipe_handle_t	ccid_control_pipe;	/* WO */
	uint_t			ccid_nslots;		/* WO */
	size_t			ccid_bufsize;		/* WO */
	ccid_slot_t		*ccid_slots;
	timeout_id_t		ccid_poll_timeout;
	ccid_stats_t		ccid_stats;
	list_t			ccid_command_queue;
	list_t			ccid_complete_queue;
	usb_bulk_req_t		*ccid_bulkin_cache[CCID_BULK_NALLOCED];
	uint_t			ccid_bulkin_alloced;
	usb_bulk_req_t		*ccid_bulkin_dispatched;
} ccid_t;

/*
 * Command structure for an individual CCID command that we issue to a
 * controller. Note that the command caches a copy of some of the data that's
 * normally inside the CCID header in host-endian fashion.
 */
typedef enum ccid_command_state {
	CCID_COMMAND_ALLOCATED	= 0x0,
	CCID_COMMAND_QUEUED,
	CCID_COMMAND_DISPATCHED,
	CCID_COMMAND_REPLYING,
	CCID_COMMAND_COMPLETE,
	CCID_COMMAND_TRANSPORT_ERROR,
	CCID_COMMAND_CCID_ABORTED
} ccid_command_state_t;

typedef enum ccid_command_flags {
	CCID_COMMAND_F_USER	= 1 << 0,
} ccid_command_flags_t;

typedef struct ccid_command {
	list_node_t		cc_list_node;
	kcondvar_t		cc_cv;
	uint8_t			cc_mtype;
	ccid_response_code_t	cc_rtype;
	uint8_t			cc_slot;
	ccid_command_state_t	cc_state;
	ccid_command_flags_t	cc_flags;
	int			cc_usb;
	usb_cr_t		cc_usbcr;
	size_t			cc_reqlen;
	id_t			cc_seq;
	usb_bulk_req_t		*cc_ubrp;
	ccid_t			*cc_ccid;
	hrtime_t		cc_queue_time;
	hrtime_t		cc_dispatch_time;
	hrtime_t		cc_dispatch_cb_time;
	hrtime_t		cc_response_time;
	hrtime_t		cc_completion_time;
	mblk_t			*cc_response;
} ccid_command_t;

/*
 * ddi_soft_state(9F) pointer. This is used for instances of a CCID controller.
 */
static void *ccid_softstate;

/*
 * This is used to keep track of our minor nodes.
 */
static kmutex_t ccid_idxlock;
static avl_tree_t ccid_idx;
static id_space_t *ccid_minors;

/*
 * Required Forwards
 */
static void ccid_intr_poll_init(ccid_t *);
static void ccid_worker_request(ccid_t *);
static void ccid_command_dispatch(ccid_t *);
static void ccid_command_free(ccid_command_t *);
static int ccid_bulkin_schedule(ccid_t *);
static void ccid_command_bcopy(ccid_command_t *, const void *, size_t);

static int ccid_write_apdu(ccid_t *, ccid_slot_t *);
static void ccid_complete_apdu(ccid_t *, ccid_slot_t *, ccid_command_t *);
static void ccid_teardown_apdu(ccid_t *, ccid_slot_t *, int);


static int
ccid_idx_comparator(const void *l, const void *r)
{
	const ccid_minor_idx_t *lc = l, *rc = r;

	if (lc->cmi_minor > rc->cmi_minor)
		return (1);
	if (lc->cmi_minor < rc->cmi_minor)
		return (-1);
	return (0);
}

static void
ccid_error(ccid_t *ccid, const char *fmt, ...)
{
	va_list ap;

	va_start(ap, fmt);
	if (ccid != NULL) {
		vdev_err(ccid->ccid_dip, CE_WARN, fmt, ap);
	} else {
		vcmn_err(CE_WARN, fmt, ap);
	}
	va_end(ap);
}

static void
ccid_minor_idx_free(ccid_minor_idx_t *idx)
{
	ccid_minor_idx_t *ip;

	VERIFY3S(idx->cmi_minor, !=, CCID_MINOR_INVALID);
	mutex_enter(&ccid_idxlock);
	ip = avl_find(&ccid_idx, idx, NULL);
	VERIFY3P(idx, ==, ip);
	avl_remove(&ccid_idx, idx);
	id_free(ccid_minors, idx->cmi_minor);
	idx->cmi_minor = CCID_MINOR_INVALID;
	mutex_exit(&ccid_idxlock);
}

static boolean_t
ccid_minor_idx_alloc(ccid_minor_idx_t *idx, boolean_t sleep)
{
	id_t id;

	mutex_enter(&ccid_idxlock);
	if (sleep) {
		id = id_alloc(ccid_minors);
	} else {
		id = id_alloc_nosleep(ccid_minors);
	}
	if (id == -1) {
		mutex_exit(&ccid_idxlock);
		return (B_FALSE);
	}
	idx->cmi_minor = id;
	avl_add(&ccid_idx, idx);
	mutex_exit(&ccid_idxlock);

	return (B_TRUE);
}

static ccid_minor_idx_t *
ccid_minor_find(minor_t m)
{
	ccid_minor_idx_t i = { 0 };
	ccid_minor_idx_t *ret;

	i.cmi_minor = m;
	mutex_enter(&ccid_idxlock);
	ret = avl_find(&ccid_idx, &i, NULL);
	mutex_exit(&ccid_idxlock);

	return (ret);
}

static ccid_minor_idx_t *
ccid_minor_find_user(minor_t m)
{
	ccid_minor_idx_t *idx;

	idx = ccid_minor_find(m);
	if (idx == NULL) {
		return (NULL);
	}
	VERIFY0(idx->cmi_isslot);
	return (idx);
}

static void
ccid_clear_io(ccid_io_t *io)
{
	freemsg(io->ci_data);
	io->ci_data = NULL;
	io->ci_errno = 0;
	io->ci_flags &= ~CCID_IO_F_DONE;
	io->ci_ilen = 0;
	bzero(io->ci_ibuf, sizeof (io->ci_ibuf));
}

/*
 * Check if the conditions are met to signal the next exclusive holder. For this
 * to be true, there should be no one holding it. In addition, there must be
 * someone in the queue waiting. Finally, we want to make sure that the ICC, if
 * present, is in a state where it could handle these kinds of issues. That
 * means that we shouldn't have an outstanding I/O question or warm reset
 * ongoing. However, we must not block this on the condition of an ICC being
 * present. But, if the reader has been disconnected, don't signal anyone.
 */
static void
ccid_slot_excl_maybe_signal(ccid_slot_t *slot)
{
	ccid_minor_t *cmp;

	VERIFY(MUTEX_HELD(&slot->cs_ccid->ccid_mutex));

	if ((slot->cs_ccid->ccid_flags & CCID_F_DISCONNECTED) != 0)
		return;
	if (slot->cs_excl_minor != NULL)
		return;
	if ((slot->cs_flags & CCID_SLOT_F_NOEXCL_MASK) != 0)
		return;
	cmp = list_head(&slot->cs_excl_waiters);
	if (cmp == NULL)
		return;
	cv_signal(&cmp->cm_excl_cv);
}

static void
ccid_slot_excl_rele(ccid_slot_t *slot)
{
	ccid_minor_t *cmp;
	ccid_t *ccid = slot->cs_ccid;

	VERIFY(MUTEX_HELD(&ccid->ccid_mutex));
	VERIFY3P(slot->cs_excl_minor, !=, NULL);

	cmp = slot->cs_excl_minor;

	/*
	 * If we have an outstanding command left by the user when they've
	 * closed the slot, we need to clean up this command. We need to call
	 * the protocol specific handler here to determine what to do. If the
	 * command has completed, but the user has never called read, then it
	 * will simply clean it up. Otherwise it will indicate that there is
	 * some amount of external state still ongoing to take care of and clean
	 * up later.
	 */
	if (slot->cs_icc.icc_teardown != NULL) {
		slot->cs_icc.icc_teardown(ccid, slot, ECANCELED);
	}

	/*
	 * There may either be a thread blocked in read or in the process of
	 * preparing a write. In either case, we need to make sure that they're
	 * woken up or finish, before we finish tear down.
	 */
	while ((cmp->cm_flags & CCID_MINOR_F_READ_WAITING) != 0 ||
	    (slot->cs_io.ci_flags & CCID_IO_F_PREPARING) != 0) {
		cv_wait(&cmp->cm_iowait_cv, &ccid->ccid_mutex);
	}

	/*
	 * At this point, we hold the lock and there should be no other threads
	 * that are past the basic sanity checks. So at this point, note that
	 * this minor no longer has exclusive access (causing other read/write
	 * calls to fail) and start the process of cleaning up the outstanding
	 * I/O on the slot. It is OK that at this point the thread may try to
	 * obtain exclusive access again. It will end up blocking on everything
	 * else.
	 */
	cmp->cm_flags &= ~CCID_MINOR_F_HAS_EXCL;
	slot->cs_excl_minor = NULL;

	/*
	 * If at this point, we have an I/O that's noted as being done, but no
	 * one blocked in read, then we need to clean that up. The ICC teardown
	 * function is only designed to take care of in-flight I/Os.
	 */
	if ((slot->cs_io.ci_flags & CCID_IO_F_DONE) != 0)
		ccid_clear_io(&slot->cs_io);

	/*
	 * Regardless of when we're polling, we need to go through and error
	 * out.
	 */
	pollwakeup(&cmp->cm_pollhead, POLLERR);

	/*
	 * If we've been asked to reset the card before handing it off, schedule
	 * that. Otherwise, allow the next entry in the queue to get woken up
	 * and given access to the card.
	 */
	if ((cmp->cm_flags & CCID_MINOR_F_TXN_RESET) != 0) {
		slot->cs_flags |= CCID_SLOT_F_NEED_TXN_RESET;
		ccid_worker_request(ccid);
		cmp->cm_flags &= ~CCID_MINOR_F_TXN_RESET;
	} else {
		ccid_slot_excl_maybe_signal(slot);
	}
}

static int
ccid_slot_excl_req(ccid_slot_t *slot, ccid_minor_t *cmp, boolean_t nosleep)
{
	VERIFY(MUTEX_HELD(&slot->cs_ccid->ccid_mutex));

	if (slot->cs_excl_minor == cmp) {
		VERIFY((cmp->cm_flags & CCID_MINOR_F_HAS_EXCL) != 0);
		return (EEXIST);
	}

	if ((cmp->cm_flags & CCID_MINOR_F_WAITING) != 0) {
		return (EINPROGRESS);
	}

	/*
	 * If we were asked to try and fail quickly, do that before the main
	 * loop.
	 */
	if (nosleep && slot->cs_excl_minor != NULL &&
	    (slot->cs_flags & CCID_SLOT_F_NOEXCL_MASK) == 0) {
		return (EBUSY);
	}

	/*
	 * Mark that we're waiting in case we race with another thread trying to
	 * claim exclusive access for this. Insert ourselves on the wait list.
	 * If for some reason we get a signal, then we can't know for certain if
	 * we had a signal / cv race. In such a case, we always wake up the
	 * next person in the queue (potentially spuriously).
	 */
	cmp->cm_flags |= CCID_MINOR_F_WAITING;
	list_insert_tail(&slot->cs_excl_waiters, cmp);
	while (slot->cs_excl_minor != NULL ||
	    (slot->cs_flags & CCID_SLOT_F_NOEXCL_MASK) != 0) {
		if (cv_wait_sig(&cmp->cm_excl_cv, &slot->cs_ccid->ccid_mutex)
		    == 0) {
			/*
			 * Remove ourselves from the list and try to signal the
			 * next thread.
			 */
			list_remove(&slot->cs_excl_waiters, cmp);
			cmp->cm_flags &= ~CCID_MINOR_F_WAITING;
			ccid_slot_excl_maybe_signal(slot);
			return (EINTR);
		}

		/*
		 * Check if the reader is going away. If so, then we're done
		 * here.
		 */
		if ((slot->cs_ccid->ccid_flags & CCID_F_DISCONNECTED) != 0) {
			list_remove(&slot->cs_excl_waiters, cmp);
			cmp->cm_flags &= ~CCID_MINOR_F_WAITING;
			return (ENODEV);
		}
	}

	VERIFY0(slot->cs_flags & CCID_SLOT_F_NOEXCL_MASK);
	list_remove(&slot->cs_excl_waiters, cmp);

	cmp->cm_flags &= ~CCID_MINOR_F_WAITING;
	cmp->cm_flags |= CCID_MINOR_F_HAS_EXCL;
	slot->cs_excl_minor = cmp;
	return (0);
}

/*
 * Check whether or not we're in a state that we can signal a POLLIN. To be able
 * to signal a POLLIN (meaning that we can read) the following must be true:
 *
 *   o There is a client that has an exclusive hold open
 *   o There is a data which is readable by the client (an I/O is done).
 *
 * Unlike with pollout, we don't care about the state of the ICC.
 */
static void
ccid_slot_pollin_signal(ccid_slot_t *slot)
{
	ccid_t *ccid = slot->cs_ccid;
	ccid_minor_t *cmp = slot->cs_excl_minor;

	if (cmp == NULL)
		return;

	VERIFY(MUTEX_HELD(&ccid->ccid_mutex));

	if ((slot->cs_io.ci_flags & CCID_IO_F_DONE) == 0)
		return;

	pollwakeup(&cmp->cm_pollhead, POLLIN | POLLRDNORM);
}

/*
 * Check whether or not we're in a state that we can signal a POLLOUT. To be
 * able to signal a POLLOUT (meaning that we can write) the following must be
 * true:
 *
 *   o There is a minor which has an exclusive hold on the device
 *   o There is no outstanding I/O activity going on, meaning that there is no
 *     operation in progress and any write data has been consumed.
 *   o There is an ICC present
 *   o There is no outstanding I/O cleanup being done, whether a T=1 abort, a
 *     warm reset, or something else.
 */
static void
ccid_slot_pollout_signal(ccid_slot_t *slot)
{
	ccid_t *ccid = slot->cs_ccid;
	ccid_minor_t *cmp = slot->cs_excl_minor;

	if (cmp == NULL)
		return;

	VERIFY(MUTEX_HELD(&ccid->ccid_mutex));

	if ((slot->cs_io.ci_flags & CCID_IO_F_POLLOUT_FLAGS) != 0 ||
	    (slot->cs_flags & CCID_SLOT_F_ACTIVE) == 0 ||
	    (ccid->ccid_flags & CCID_F_DEV_GONE_MASK) != 0 ||
	    (slot->cs_flags & CCID_SLOT_F_NEED_IO_TEARDOWN) != 0)
		return;

	pollwakeup(&cmp->cm_pollhead, POLLOUT);
}

static void
ccid_slot_io_teardown_done(ccid_slot_t *slot)
{
	ccid_t *ccid = slot->cs_ccid;

	VERIFY(MUTEX_HELD(&ccid->ccid_mutex));
	slot->cs_flags &= ~CCID_SLOT_F_NEED_IO_TEARDOWN;
	cv_broadcast(&slot->cs_io.ci_cv);

	ccid_slot_pollout_signal(slot);
}

/*
 * This will probably need to change when we start doing TPDU processing.
 */
static size_t
ccid_command_resp_length(ccid_command_t *cc)
{
	uint32_t len;
	const ccid_header_t *cch;

	VERIFY3P(cc, !=, NULL);
	VERIFY3P(cc->cc_response, !=, NULL);

	/*
	 * Fetch out an arbitrarily aligned LE uint32_t value from the header.
	 */
	cch = (ccid_header_t *)cc->cc_response->b_rptr;
	bcopy(&cch->ch_length, &len, sizeof (len));
	len = LE_32(len);
	return (len);
}

static uint8_t
ccid_command_resp_param2(ccid_command_t *cc)
{
	const ccid_header_t *cch;

	VERIFY3P(cc, !=, NULL);
	VERIFY3P(cc->cc_response, !=, NULL);

	cch = (ccid_header_t *)cc->cc_response->b_rptr;

	return (cch->ch_param2);
}

/*
 * Complete a single command. The way that a command completes depends on the
 * kind of command that occurs. If this command is flagged as a user command,
 * that implies that it must be handled in a different way from administrative
 * commands. User commands are placed into the minor to consume via a read(9E).
 * Non-user commands are placed into a completion queue and must be picked up
 * via the ccid_command_poll() interface.
 */
static void
ccid_command_complete(ccid_command_t *cc)
{
	ccid_t *ccid = cc->cc_ccid;

	VERIFY(MUTEX_HELD(&ccid->ccid_mutex));
	cc->cc_completion_time = gethrtime();
	list_remove(&ccid->ccid_command_queue, cc);

	if (cc->cc_flags & CCID_COMMAND_F_USER) {
		ccid_slot_t *slot;

		slot = &ccid->ccid_slots[cc->cc_slot];
		ASSERT(slot->cs_icc.icc_complete != NULL);
		slot->cs_icc.icc_complete(ccid, slot, cc);
	} else {
		list_insert_tail(&ccid->ccid_complete_queue, cc);
		cv_broadcast(&cc->cc_cv);
	}

	/*
	 * Finally, we also need to kick off the next command.
	 */
	ccid_command_dispatch(ccid);
}

static void
ccid_command_state_transition(ccid_command_t *cc, ccid_command_state_t state)
{
	VERIFY(MUTEX_HELD(&cc->cc_ccid->ccid_mutex));

	cc->cc_state = state;
	cv_broadcast(&cc->cc_cv);
}

static void
ccid_command_transport_error(ccid_command_t *cc, int usb_status, usb_cr_t cr)
{
	VERIFY(MUTEX_HELD(&cc->cc_ccid->ccid_mutex));

	ccid_command_state_transition(cc, CCID_COMMAND_TRANSPORT_ERROR);
	cc->cc_usb = usb_status;
	cc->cc_usbcr = cr;
	cc->cc_response = NULL;

	ccid_command_complete(cc);
}

static void
ccid_command_status_decode(ccid_command_t *cc,
    ccid_reply_command_status_t *comp, ccid_reply_icc_status_t *iccp,
    ccid_command_err_t *errp)
{
	ccid_header_t cch;
	size_t mblen;

	VERIFY3S(cc->cc_state, ==, CCID_COMMAND_COMPLETE);
	VERIFY3P(cc->cc_response, !=, NULL);
	mblen = msgsize(cc->cc_response);
	VERIFY3U(mblen, >=, sizeof (cch));

	bcopy(cc->cc_response->b_rptr, &cch, sizeof (cch));
	if (comp != NULL) {
		*comp = CCID_REPLY_STATUS(cch.ch_param0);
	}

	if (iccp != NULL) {
		*iccp = CCID_REPLY_ICC(cch.ch_param0);
	}

	if (errp != NULL) {
		*errp = cch.ch_param1;
	}
}

static void
ccid_reply_bulk_cb(usb_pipe_handle_t ph, usb_bulk_req_t *ubrp)
{
	size_t mlen;
	ccid_t *ccid;
	ccid_slot_t *slot;
	ccid_header_t cch;
	ccid_command_t *cc;

	boolean_t header_valid = B_FALSE;

	VERIFY(ubrp->bulk_data != NULL);
	mlen = msgsize(ubrp->bulk_data);
	ccid = (ccid_t *)ubrp->bulk_client_private;
	mutex_enter(&ccid->ccid_mutex);

	/*
	 * Before we do anything else, we should mark that this Bulk-IN request
	 * is no longer being dispatched.
	 */
	VERIFY3P(ubrp, ==, ccid->ccid_bulkin_dispatched);
	ccid->ccid_bulkin_dispatched = NULL;

	if ((cc = list_head(&ccid->ccid_command_queue)) == NULL) {
		/*
		 * This is certainly an odd case. This means that we got some
		 * response but there are no entries in the queue. Go ahead and
		 * free this. We're done here.
		 */
		mutex_exit(&ccid->ccid_mutex);
		usb_free_bulk_req(ubrp);
		return;
	}

	slot = &ccid->ccid_slots[cc->cc_slot];

	if (mlen >= sizeof (ccid_header_t)) {
		bcopy(ubrp->bulk_data->b_rptr, &cch, sizeof (cch));
		header_valid = B_TRUE;
	}

	/*
	 * If the current command isn't in the replying state, then something is
	 * clearly wrong and this probably isn't intended for the current
	 * command. That said, if we have enough bytes, let's check the sequence
	 * number as that might be indicative of a bug otherwise.
	 */
	if (cc->cc_state != CCID_COMMAND_REPLYING) {
		if (header_valid) {
			VERIFY3S(cch.ch_seq, !=, cc->cc_seq);
		}
		mutex_exit(&ccid->ccid_mutex);
		usb_free_bulk_req(ubrp);
		return;
	}

	/*
	 * CCID section 6.2.7 says that if we get a short or zero length packet,
	 * then we need to treat that as though the running command was aborted
	 * for some reason. However, section 3.1.3 talks about sending zero
	 * length packets on general principle.  To further complicate things,
	 * we don't have the sequence number.
	 *
	 * If we have an outstanding command still, then we opt to treat the
	 * zero length packet as an abort.
	 */
	if (!header_valid) {
		ccid_command_state_transition(cc, CCID_COMMAND_CCID_ABORTED);
		ccid_command_complete(cc);
		mutex_exit(&ccid->ccid_mutex);
		usb_free_bulk_req(ubrp);
		return;
	}

	/*
	 * If the sequence or slot number don't match the head of the list or
	 * the response type is unexpected for this command then we should be
	 * very suspect of the hardware at this point. At a minimum we should
	 * fail this command and issue a reset.
	 */
	if (cch.ch_seq != cc->cc_seq ||
	    cch.ch_slot != cc->cc_slot ||
	    cch.ch_mtype != cc->cc_rtype) {
		ccid_command_state_transition(cc, CCID_COMMAND_CCID_ABORTED);
		ccid_command_complete(cc);
		slot->cs_flags |= CCID_SLOT_F_NEED_TXN_RESET;
		ccid_worker_request(ccid);
		mutex_exit(&ccid->ccid_mutex);
		usb_free_bulk_req(ubrp);
		return;
	}

	/*
	 * Check that we have all the bytes that we were told we'd have. If we
	 * don't, simulate this as an aborted command and issue a reset.
	 */
	if (LE_32(cch.ch_length) + sizeof (ccid_header_t) > mlen) {
		ccid_command_state_transition(cc, CCID_COMMAND_CCID_ABORTED);
		ccid_command_complete(cc);
		slot->cs_flags |= CCID_SLOT_F_NEED_TXN_RESET;
		ccid_worker_request(ccid);
		mutex_exit(&ccid->ccid_mutex);
		usb_free_bulk_req(ubrp);
		return;
	}

	/*
	 * This response is for us. Before we complete the command check to see
	 * what the state of the command is. If the command indicates that more
	 * time has been requested, then we need to schedule a new Bulk-IN
	 * request.
	 */
	if (CCID_REPLY_STATUS(cch.ch_param0) == CCID_REPLY_STATUS_MORE_TIME) {
		int ret;

		ret = ccid_bulkin_schedule(ccid);
		if (ret != USB_SUCCESS) {
			ccid_command_transport_error(cc, ret, USB_CR_OK);
			slot->cs_flags |= CCID_SLOT_F_NEED_TXN_RESET;
			ccid_worker_request(ccid);
		}
		mutex_exit(&ccid->ccid_mutex);
		usb_free_bulk_req(ubrp);
		return;
	}

	/*
	 * Take the message block from the Bulk-IN request and store it on the
	 * command. We want this regardless if it succeeded, failed, or we have
	 * some unexpected status value.
	 */
	cc->cc_response = ubrp->bulk_data;
	ubrp->bulk_data = NULL;
	ccid_command_state_transition(cc, CCID_COMMAND_COMPLETE);
	ccid_command_complete(cc);
	mutex_exit(&ccid->ccid_mutex);
	usb_free_bulk_req(ubrp);
}

static void
ccid_reply_bulk_exc_cb(usb_pipe_handle_t ph, usb_bulk_req_t *ubrp)
{
	ccid_t *ccid;
	ccid_command_t *cc;

	ccid = (ccid_t *)ubrp->bulk_client_private;
	mutex_enter(&ccid->ccid_mutex);

	/*
	 * Before we do anything else, we should mark that this Bulk-IN request
	 * is no longer being dispatched.
	 */
	VERIFY3P(ubrp, ==, ccid->ccid_bulkin_dispatched);
	ccid->ccid_bulkin_dispatched = NULL;

	/*
	 * While there are many different reasons that the Bulk-IN request could
	 * have failed, each of these are treated as a transport error. If we
	 * have a dispatched command, then we treat this as corresponding to
	 * that command. Otherwise, we drop this.
	 */
	if ((cc = list_head(&ccid->ccid_command_queue)) != NULL) {
		if (cc->cc_state == CCID_COMMAND_REPLYING) {
			ccid_command_transport_error(cc, USB_SUCCESS,
			    ubrp->bulk_completion_reason);
		}
	}
	mutex_exit(&ccid->ccid_mutex);
	usb_free_bulk_req(ubrp);
}

/*
 * Fill the Bulk-IN cache. If we do not entirely fill this, that's fine. If
 * there are no scheduled resources then we'll deal with that when we actually
 * get there.
 */
static void
ccid_bulkin_cache_refresh(ccid_t *ccid)
{
	VERIFY(MUTEX_HELD(&ccid->ccid_mutex));
	while (ccid->ccid_bulkin_alloced < CCID_BULK_NALLOCED) {
		usb_bulk_req_t *ubrp;

		if ((ubrp = usb_alloc_bulk_req(ccid->ccid_dip,
		    ccid->ccid_bufsize, 0)) == NULL)
			return;

		ubrp->bulk_len = ccid->ccid_bufsize;
		ubrp->bulk_timeout = CCID_BULK_IN_TIMEOUT;
		ubrp->bulk_client_private = (usb_opaque_t)ccid;
		ubrp->bulk_attributes = USB_ATTRS_SHORT_XFER_OK |
		    USB_ATTRS_AUTOCLEARING;
		ubrp->bulk_cb = ccid_reply_bulk_cb;
		ubrp->bulk_exc_cb = ccid_reply_bulk_exc_cb;

		ccid->ccid_bulkin_cache[ccid->ccid_bulkin_alloced] = ubrp;
		ccid->ccid_bulkin_alloced++;
	}

}

static usb_bulk_req_t *
ccid_bulkin_cache_get(ccid_t *ccid)
{
	usb_bulk_req_t *ubrp;

	VERIFY(MUTEX_HELD(&ccid->ccid_mutex));

	if (ccid->ccid_bulkin_alloced == 0) {
		ccid_bulkin_cache_refresh(ccid);
		if (ccid->ccid_bulkin_alloced == 0)
			return (NULL);
	}

	ccid->ccid_bulkin_alloced--;
	ubrp = ccid->ccid_bulkin_cache[ccid->ccid_bulkin_alloced];
	VERIFY3P(ubrp, !=, NULL);
	ccid->ccid_bulkin_cache[ccid->ccid_bulkin_alloced] = NULL;

	return (ubrp);
}

/*
 * Attempt to schedule a Bulk-In request. Note that only one should ever be
 * scheduled at any time.
 */
static int
ccid_bulkin_schedule(ccid_t *ccid)
{
	VERIFY(MUTEX_HELD(&ccid->ccid_mutex));
	if (ccid->ccid_bulkin_dispatched == NULL) {
		usb_bulk_req_t *ubrp;
		int ret;

		ubrp = ccid_bulkin_cache_get(ccid);
		if (ubrp == NULL) {
			return (USB_NO_RESOURCES);
		}

		if ((ret = usb_pipe_bulk_xfer(ccid->ccid_bulkin_pipe, ubrp,
		    0)) != USB_SUCCESS) {
			ccid_error(ccid,
			    "!failed to schedule Bulk-In response: %d", ret);
			usb_free_bulk_req(ubrp);
			return (ret);
		}

		ccid->ccid_bulkin_dispatched = ubrp;
	}

	return (USB_SUCCESS);
}

/*
 * Make sure that the head of the queue has been dispatched. If a dispatch to
 * the device fails, fail the command and try the next one.
 */
static void
ccid_command_dispatch(ccid_t *ccid)
{
	ccid_command_t *cc;

	VERIFY(MUTEX_HELD(&ccid->ccid_mutex));
	while ((cc = list_head(&ccid->ccid_command_queue)) != NULL) {
		int ret;

		if ((ccid->ccid_flags & CCID_F_DEV_GONE_MASK) != 0)
			return;

		/*
		 * Head of the queue is already being processed. We're done
		 * here.
		 */
		if (cc->cc_state > CCID_COMMAND_QUEUED) {
			return;
		}

		/*
		 * Mark the command as being dispatched to the device. This
		 * prevents anyone else from getting in and confusing things.
		 */
		ccid_command_state_transition(cc, CCID_COMMAND_DISPATCHED);
		cc->cc_dispatch_time = gethrtime();

		/*
		 * Drop the global lock while we schedule the USB I/O.
		 */
		mutex_exit(&ccid->ccid_mutex);

		ret = usb_pipe_bulk_xfer(ccid->ccid_bulkout_pipe, cc->cc_ubrp,
		    0);
		mutex_enter(&ccid->ccid_mutex);
		if (ret != USB_SUCCESS) {
			/*
			 * We don't need to free the usb_bulk_req_t here as it
			 * will be taken care of when the command itself is
			 * freed.
			 */
			ccid_error(ccid, "!Bulk pipe dispatch failed: %d\n",
			    ret);
			ccid_command_transport_error(cc, ret, USB_CR_OK);
		}
	}
}

static int
ccid_command_queue(ccid_t *ccid, ccid_command_t *cc)
{
	id_t seq;
	ccid_header_t *cchead;

	seq = id_alloc_nosleep(ccid->ccid_seqs);
	if (seq == -1)
		return (ENOMEM);
	cc->cc_seq = seq;
	VERIFY3U(seq, <=, UINT8_MAX);
	cchead = (void *)cc->cc_ubrp->bulk_data->b_rptr;
	cchead->ch_seq = (uint8_t)seq;

	mutex_enter(&ccid->ccid_mutex);
	/*
	 * Take a shot at filling up our reply cache while we're submitting this
	 * command.
	 */
	ccid_bulkin_cache_refresh(ccid);
	list_insert_tail(&ccid->ccid_command_queue, cc);
	ccid_command_state_transition(cc, CCID_COMMAND_QUEUED);
	cc->cc_queue_time = gethrtime();
	ccid_command_dispatch(ccid);
	mutex_exit(&ccid->ccid_mutex);

	return (0);
}

/*
 * Normal callback for Bulk-Out requests which represents commands issued to the
 * device.
 */
static void
ccid_dispatch_bulk_cb(usb_pipe_handle_t ph, usb_bulk_req_t *ubrp)
{
	int ret;
	ccid_command_t *cc = (void *)ubrp->bulk_client_private;
	ccid_t *ccid = cc->cc_ccid;

	mutex_enter(&ccid->ccid_mutex);
	VERIFY3S(cc->cc_state, ==, CCID_COMMAND_DISPATCHED);
	ccid_command_state_transition(cc, CCID_COMMAND_REPLYING);
	cc->cc_dispatch_cb_time = gethrtime();

	/*
	 * Since we have successfully sent the command, give it a Bulk-In
	 * response to reply to us with. If that fails, we'll note a transport
	 * error which will kick off the next command if needed.
	 */
	ret = ccid_bulkin_schedule(ccid);
	if (ret != USB_SUCCESS) {
		ccid_command_transport_error(cc, ret, USB_CR_OK);
	}
	mutex_exit(&ccid->ccid_mutex);
}

/*
 * Exception callback for the Bulk-Out requests which represent commands issued
 * to the device.
 */
static void
ccid_dispatch_bulk_exc_cb(usb_pipe_handle_t ph, usb_bulk_req_t *ubrp)
{
	ccid_command_t *cc = (void *)ubrp->bulk_client_private;
	ccid_t *ccid = cc->cc_ccid;

	mutex_enter(&ccid->ccid_mutex);
	ccid_command_transport_error(cc, USB_SUCCESS,
	    ubrp->bulk_completion_reason);
	mutex_exit(&ccid->ccid_mutex);
}

static void
ccid_command_free(ccid_command_t *cc)
{
	VERIFY0(list_link_active(&cc->cc_list_node));
	VERIFY(cc->cc_state == CCID_COMMAND_ALLOCATED ||
	    cc->cc_state >= CCID_COMMAND_COMPLETE);

	if (cc->cc_response != NULL) {
		freemsgchain(cc->cc_response);
		cc->cc_response = NULL;
	}

	if (cc->cc_ubrp != NULL) {
		usb_free_bulk_req(cc->cc_ubrp);
		cc->cc_ubrp = NULL;
	}

	if (cc->cc_seq != 0) {
		id_free(cc->cc_ccid->ccid_seqs, cc->cc_seq);
		cc->cc_seq = 0;
	}

	cv_destroy(&cc->cc_cv);
	kmem_free(cc, sizeof (ccid_command_t));
}

/*
 * Copy len bytes of data from buf into the allocated message block.
 */
static void
ccid_command_bcopy(ccid_command_t *cc, const void *buf, size_t len)
{
	size_t mlen;

	mlen = msgsize(cc->cc_ubrp->bulk_data);
	VERIFY3U(mlen + len, >=, len);
	VERIFY3U(mlen + len, >=, mlen);
	mlen += len;
	VERIFY3U(mlen, <=, cc->cc_ubrp->bulk_len);

	bcopy(buf, cc->cc_ubrp->bulk_data->b_wptr, len);
	cc->cc_ubrp->bulk_data->b_wptr += len;
}

/*
 * Allocate a command of a specific size and parameters. This will allocate a
 * USB bulk transfer that the caller will copy data to.
 */
static int
ccid_command_alloc(ccid_t *ccid, ccid_slot_t *slot, boolean_t block,
    mblk_t *datamp, size_t datasz, uint8_t mtype, uint8_t param0,
    uint8_t param1, uint8_t param2, ccid_command_t **ccp)
{
	size_t allocsz;
	int kmflag, usbflag;
	ccid_command_t *cc;
	ccid_header_t *cchead;
	ccid_response_code_t rtype;

	switch (mtype) {
	case CCID_REQUEST_POWER_ON:
	case CCID_REQUEST_POWER_OFF:
	case CCID_REQUEST_SLOT_STATUS:
	case CCID_REQUEST_GET_PARAMS:
	case CCID_REQUEST_RESET_PARAMS:
	case CCID_REQUEST_ICC_CLOCK:
	case CCID_REQUEST_T0APDU:
	case CCID_REQUEST_MECHANICAL:
	case CCID_REQEUST_ABORT:
		if (datasz != 0)
			return (EINVAL);
		break;
	case CCID_REQUEST_TRANSFER_BLOCK:
	case CCID_REQUEST_ESCAPE:
	case CCID_REQUEST_SECURE:
	case CCID_REQUEST_SET_PARAMS:
	case CCID_REQUEST_DATA_CLOCK:
		break;
	default:
		return (EINVAL);
	}

	switch (mtype) {
	case CCID_REQUEST_POWER_ON:
	case CCID_REQUEST_SECURE:
	case CCID_REQUEST_TRANSFER_BLOCK:
		rtype = CCID_RESPONSE_DATA_BLOCK;
		break;

	case CCID_REQUEST_POWER_OFF:
	case CCID_REQUEST_SLOT_STATUS:
	case CCID_REQUEST_ICC_CLOCK:
	case CCID_REQUEST_T0APDU:
	case CCID_REQUEST_MECHANICAL:
	case CCID_REQEUST_ABORT:
		rtype = CCID_RESPONSE_SLOT_STATUS;
		break;

	case CCID_REQUEST_GET_PARAMS:
	case CCID_REQUEST_RESET_PARAMS:
	case CCID_REQUEST_SET_PARAMS:
		rtype = CCID_RESPONSE_PARAMETERS;
		break;

	case CCID_REQUEST_ESCAPE:
		rtype = CCID_RESPONSE_ESCAPE;
		break;

	case CCID_REQUEST_DATA_CLOCK:
		rtype = CCID_RESPONSE_DATA_CLOCK;
		break;
	default:
		return (EINVAL);
	}

	if (block) {
		kmflag = KM_SLEEP;
		usbflag = USB_FLAGS_SLEEP;
	} else {
		kmflag = KM_NOSLEEP | KM_NORMALPRI;
		usbflag = 0;
	}

	if (datasz + sizeof (ccid_header_t) < datasz)
		return (EINVAL);
	if (datasz + sizeof (ccid_header_t) > ccid->ccid_bufsize)
		return (EINVAL);

	cc = kmem_zalloc(sizeof (ccid_command_t), kmflag);
	if (cc == NULL)
		return (ENOMEM);

	allocsz = datasz + sizeof (ccid_header_t);
	if (datamp == NULL) {
		cc->cc_ubrp = usb_alloc_bulk_req(ccid->ccid_dip, allocsz,
		    usbflag);
	} else {
		cc->cc_ubrp = usb_alloc_bulk_req(ccid->ccid_dip, 0, usbflag);
	}
	if (cc->cc_ubrp == NULL) {
		kmem_free(cc, sizeof (ccid_command_t));
		return (ENOMEM);
	}

	list_link_init(&cc->cc_list_node);
	cv_init(&cc->cc_cv, NULL, CV_DRIVER, NULL);
	cc->cc_mtype = mtype;
	cc->cc_rtype = rtype;
	cc->cc_slot = slot->cs_slotno;
	cc->cc_reqlen = datasz;
	cc->cc_ccid = ccid;
	cc->cc_state = CCID_COMMAND_ALLOCATED;

	/*
	 * Fill in bulk request attributes. Note that short transfers out
	 * are not OK.
	 */
	if (datamp != NULL) {
		cc->cc_ubrp->bulk_data = datamp;
	}
	cc->cc_ubrp->bulk_len = allocsz;
	cc->cc_ubrp->bulk_timeout = CCID_BULK_OUT_TIMEOUT;
	cc->cc_ubrp->bulk_client_private = (usb_opaque_t)cc;
	cc->cc_ubrp->bulk_attributes = USB_ATTRS_AUTOCLEARING;
	cc->cc_ubrp->bulk_cb = ccid_dispatch_bulk_cb;
	cc->cc_ubrp->bulk_exc_cb = ccid_dispatch_bulk_exc_cb;

	/*
	 * Fill in the command header. We fill in everything except the sequence
	 * number, which is done by the actual dispatch code.
	 */
	cchead = (void *)cc->cc_ubrp->bulk_data->b_rptr;
	cchead->ch_mtype = mtype;
	cchead->ch_length = LE_32(datasz);
	cchead->ch_slot = slot->cs_slotno;
	cchead->ch_seq = 0;
	cchead->ch_param0 = param0;
	cchead->ch_param1 = param1;
	cchead->ch_param2 = param2;
	cc->cc_ubrp->bulk_data->b_wptr += sizeof (ccid_header_t);
	*ccp = cc;

	return (0);
}

/*
 * The rest of the stack is in charge of timing out commands and potentially
 * aborting them. At this point in time, there's no specific timeout aspect
 * here.
 */
static void
ccid_command_poll(ccid_t *ccid, ccid_command_t *cc)
{
	VERIFY0(cc->cc_flags & CCID_COMMAND_F_USER);

	mutex_enter(&ccid->ccid_mutex);
	while ((cc->cc_state < CCID_COMMAND_COMPLETE) &&
	    (ccid->ccid_flags & CCID_F_DEV_GONE_MASK) == 0) {
		cv_wait(&cc->cc_cv, &ccid->ccid_mutex);
	}

	/*
	 * Treat this as a consumption and remove it from the completion list.
	 */
#ifdef DEBUG
	ccid_command_t *check;
	for (check = list_head(&ccid->ccid_complete_queue); check != NULL;
	    check = list_next(&ccid->ccid_complete_queue, check)) {
		if (cc == check)
			break;
	}
	ASSERT3P(check, !=, NULL);
#endif
	VERIFY(list_link_active(&cc->cc_list_node));
	list_remove(&ccid->ccid_complete_queue, cc);
	mutex_exit(&ccid->ccid_mutex);
}

static int
ccid_command_power_off(ccid_t *ccid, ccid_slot_t *cs)
{
	int ret;
	ccid_command_t *cc;
	ccid_reply_icc_status_t cis;
	ccid_reply_command_status_t crs;

	if ((ret = ccid_command_alloc(ccid, cs, B_TRUE, NULL, 0,
	    CCID_REQUEST_POWER_OFF, 0, 0, 0, &cc)) != 0) {
		return (ret);
	}

	if ((ret = ccid_command_queue(ccid, cc)) != 0) {
		ccid_command_free(cc);
		return (ret);
	}

	ccid_command_poll(ccid, cc);

	if (cc->cc_state != CCID_COMMAND_COMPLETE) {
		ret = EIO;
		goto done;
	}

	ccid_command_status_decode(cc, &crs, &cis, NULL);
	if (crs == CCID_REPLY_STATUS_FAILED) {
		if (cis == CCID_REPLY_ICC_MISSING) {
			ret = ENXIO;
		} else {
			ret = EIO;
		}
	} else {
		ret = 0;
	}
done:
	ccid_command_free(cc);
	return (ret);
}

static int
ccid_command_power_on(ccid_t *ccid, ccid_slot_t *cs, ccid_class_voltage_t volt,
    mblk_t **atrp)
{
	int ret;
	ccid_command_t *cc;
	ccid_reply_command_status_t crs;
	ccid_reply_icc_status_t cis;
	ccid_command_err_t cce;

	if (atrp == NULL)
		return (EINVAL);

	*atrp = NULL;

	switch (volt) {
	case CCID_CLASS_VOLT_AUTO:
	case CCID_CLASS_VOLT_5_0:
	case CCID_CLASS_VOLT_3_0:
	case CCID_CLASS_VOLT_1_8:
		break;
	default:
		return (EINVAL);
	}

	if ((ret = ccid_command_alloc(ccid, cs, B_TRUE, NULL, 0,
	    CCID_REQUEST_POWER_ON, volt, 0, 0, &cc)) != 0) {
		return (ret);
	}

	if ((ret = ccid_command_queue(ccid, cc)) != 0) {
		ccid_command_free(cc);
		return (ret);
	}

	ccid_command_poll(ccid, cc);

	if (cc->cc_state != CCID_COMMAND_COMPLETE) {
		ret = EIO;
		goto done;
	}

	/*
	 * Look for a few specific errors here:
	 *
	 * - ICC_MUTE via a few potential ways
	 * - Bad voltage
	 */
	ccid_command_status_decode(cc, &crs, &cis, &cce);
	if (crs == CCID_REPLY_STATUS_FAILED) {
		if (cis == CCID_REPLY_ICC_MISSING) {
			ret = ENXIO;
		} else if (cis == CCID_REPLY_ICC_INACTIVE &&
		    cce == 7) {
			/*
			 * This means that byte 7 was invalid. In other words,
			 * that the voltage wasn't correct. See Table 6.1-2
			 * 'Errors' in the CCID r1.1.0 spec.
			 */
			ret = ENOTSUP;
		} else {
			ret = EIO;
		}
	} else {
		size_t len;

		len = ccid_command_resp_length(cc);
		if (len == 0) {
			ret = EINVAL;
			goto done;
		}

#ifdef	DEBUG
		/*
		 * This should have already been checked by the response
		 * framework, but sanity check this again.
		 */
		size_t mlen = msgsize(cc->cc_response);
		VERIFY3U(mlen, >=, len + sizeof (ccid_header_t));
#endif

		/*
		 * Munge the message block to have the ATR. We want to make sure
		 * that the write pointer is set to the maximum length that we
		 * got back from the driver (the message block could strictly
		 * speaking be larger, because we got a larger transfer for some
		 * reason).
		 */
		cc->cc_response->b_rptr += sizeof (ccid_header_t);
		cc->cc_response->b_wptr = cc->cc_response->b_rptr + len;
		*atrp = cc->cc_response;
		cc->cc_response = NULL;
		ret = 0;
	}

done:
	ccid_command_free(cc);
	return (ret);
}

static int
ccid_command_get_parameters(ccid_t *ccid, ccid_slot_t *slot,
    atr_protocol_t *protp, ccid_params_t *paramsp)
{
	int ret;
	uint8_t prot;
	size_t mlen;
	ccid_command_t *cc;
	ccid_reply_command_status_t crs;
	ccid_reply_icc_status_t cis;
	const void *cpbuf;

	if ((ret = ccid_command_alloc(ccid, slot, B_TRUE, NULL, 0,
	    CCID_REQUEST_GET_PARAMS, 0, 0, 0, &cc)) != 0) {
		return (ret);
	}

	if ((ret = ccid_command_queue(ccid, cc)) != 0)
		goto done;

	ccid_command_poll(ccid, cc);

	if (cc->cc_state != CCID_COMMAND_COMPLETE) {
		ret = EIO;
		goto done;
	}

	ccid_command_status_decode(cc, &crs, &cis, NULL);
	if (crs != CCID_REPLY_STATUS_COMPLETE) {
		if (cis == CCID_REPLY_ICC_MISSING) {
			ret = ENXIO;
		} else {
			ret = EIO;
		}
		goto done;
	}

	/*
	 * The protocol is in ch_param2 of the header.
	 */
	prot = ccid_command_resp_param2(cc);
	mlen = ccid_command_resp_length(cc);
	cpbuf = cc->cc_response->b_rptr + sizeof (ccid_header_t);

	ret = 0;
	switch (prot) {
	case 0:
		if (mlen < sizeof (ccid_params_t0_t)) {
			ret = EOVERFLOW;
			goto done;
		}
		*protp = ATR_P_T0;
		bcopy(cpbuf, &paramsp->ccp_t0, sizeof (ccid_params_t0_t));
		break;
	case 1:
		if (mlen < sizeof (ccid_params_t1_t)) {
			ret = EOVERFLOW;
			goto done;
		}
		*protp = ATR_P_T1;
		bcopy(cpbuf, &paramsp->ccp_t1, sizeof (ccid_params_t1_t));
		break;
	default:
		ret = ECHRNG;
		break;
	}

done:
	ccid_command_free(cc);
	return (ret);
}

static void
ccid_hw_error(ccid_t *ccid, ccid_intr_hwerr_t *hwerr)
{
	ccid_slot_t *slot;

	/* Make sure the slot number is within range. */
	if (hwerr->cih_slot >= ccid->ccid_nslots)
		return;

	slot = &ccid->ccid_slots[hwerr->cih_slot];

	/* The only error condition defined by the spec is overcurrent. */
	if (hwerr->cih_code != CCID_INTR_HWERR_OVERCURRENT)
		return;

	/*
	 * The worker thread will take care of this situation.
	 */
	slot->cs_flags |= CCID_SLOT_F_INTR_OVERCURRENT;
	ccid_worker_request(ccid);
}

static void
ccid_intr_pipe_cb(usb_pipe_handle_t ph, usb_intr_req_t *uirp)
{
	mblk_t *mp;
	size_t msglen, explen;
	uint_t i;
	boolean_t change;
	ccid_intr_hwerr_t ccid_hwerr;
	ccid_t *ccid = (ccid_t *)uirp->intr_client_private;

	mp = uirp->intr_data;
	if (mp == NULL)
		goto done;

	msglen = msgsize(mp);
	if (msglen == 0)
		goto done;

	switch (mp->b_rptr[0]) {
	case CCID_INTR_CODE_SLOT_CHANGE:
		mutex_enter(&ccid->ccid_mutex);
		ccid->ccid_stats.cst_intr_slot_change++;

		explen = 1 + ((2 * ccid->ccid_nslots + (NBBY-1)) / NBBY);
		if (msglen < explen) {
			ccid->ccid_stats.cst_intr_inval++;
			mutex_exit(&ccid->ccid_mutex);
			goto done;
		}

		change = B_FALSE;
		for (i = 0; i < ccid->ccid_nslots; i++) {
			uint_t byte = (i * 2 / NBBY) + 1;
			uint_t shift = i * 2 % NBBY;
			uint_t present = 1 << shift;
			uint_t delta = 2 << shift;

			if (mp->b_rptr[byte] & delta) {
				ccid_slot_t *slot = &ccid->ccid_slots[i];

				slot->cs_flags &= ~CCID_SLOT_F_INTR_MASK;
				slot->cs_flags |= CCID_SLOT_F_CHANGED;
				if (mp->b_rptr[byte] & present) {
					slot->cs_flags |= CCID_SLOT_F_INTR_ADD;
				} else {
					slot->cs_flags |= CCID_SLOT_F_INTR_GONE;
				}
				change = B_TRUE;
			}
		}

		if (change) {
			ccid_worker_request(ccid);
		}
		mutex_exit(&ccid->ccid_mutex);
		break;
	case CCID_INTR_CODE_HW_ERROR:
		mutex_enter(&ccid->ccid_mutex);
		ccid->ccid_stats.cst_intr_hwerr++;

		if (msglen < sizeof (ccid_intr_hwerr_t)) {
			ccid->ccid_stats.cst_intr_inval++;
			mutex_exit(&ccid->ccid_mutex);
			goto done;
		}

		bcopy(mp->b_rptr, &ccid_hwerr, sizeof (ccid_intr_hwerr_t));
		ccid_hw_error(ccid, &ccid_hwerr);

		mutex_exit(&ccid->ccid_mutex);
		break;
	default:
		mutex_enter(&ccid->ccid_mutex);
		ccid->ccid_stats.cst_intr_unknown++;
		mutex_exit(&ccid->ccid_mutex);
		break;
	}

done:
	usb_free_intr_req(uirp);
}

static void
ccid_intr_pipe_except_cb(usb_pipe_handle_t ph, usb_intr_req_t *uirp)
{
	ccid_t *ccid = (ccid_t *)uirp->intr_client_private;

	ccid->ccid_stats.cst_intr_errs++;
	switch (uirp->intr_completion_reason) {
	case USB_CR_PIPE_RESET:
	case USB_CR_NO_RESOURCES:
		ccid->ccid_stats.cst_intr_restart++;
		ccid_intr_poll_init(ccid);
		break;
	default:
		break;
	}
	usb_free_intr_req(uirp);
}

/*
 * Clean up all the state associated with this slot and its ICC.
 */
static void
ccid_slot_teardown(ccid_t *ccid, ccid_slot_t *slot, boolean_t signal)
{
	VERIFY(MUTEX_HELD(&ccid->ccid_mutex));

	if (slot->cs_icc.icc_fini != NULL) {
		slot->cs_icc.icc_fini(ccid, slot);
	}

	atr_data_reset(slot->cs_icc.icc_atr_data);
	slot->cs_icc.icc_protocols = ATR_P_NONE;
	slot->cs_icc.icc_cur_protocol = ATR_P_NONE;
	slot->cs_icc.icc_init = NULL;
	slot->cs_icc.icc_tx = NULL;
	slot->cs_icc.icc_complete = NULL;
	slot->cs_icc.icc_teardown = NULL;
	slot->cs_icc.icc_fini = NULL;

	slot->cs_voltage = 0;
	freemsgchain(slot->cs_atr);
	slot->cs_atr = NULL;

	if (signal && slot->cs_excl_minor != NULL) {
		pollwakeup(&slot->cs_excl_minor->cm_pollhead, POLLHUP);
	}
}

/*
 * Wait for teardown of outstanding user I/O.
 */
static void
ccid_slot_io_teardown(ccid_t *ccid, ccid_slot_t *slot)
{
	/*
	 * If there is outstanding user I/O, then we need to go ahead and take
	 * care of that. Once this function returns, the user I/O will have been
	 * dealt with; however, before we can tear down things, we need to make
	 * sure that the logical I/O has been completed.
	 */
	if (slot->cs_icc.icc_teardown != NULL) {
		slot->cs_icc.icc_teardown(ccid, slot, ENXIO);
	}

	while ((slot->cs_flags & CCID_SLOT_F_NEED_IO_TEARDOWN) != 0) {
		cv_wait(&slot->cs_io.ci_cv, &ccid->ccid_mutex);
	}
}

/*
 * The given CCID slot has been inactivated. Clean up.
 */
static void
ccid_slot_inactive(ccid_t *ccid, ccid_slot_t *slot)
{
	VERIFY(MUTEX_HELD(&ccid->ccid_mutex));

	slot->cs_flags &= ~CCID_SLOT_F_ACTIVE;

	ccid_slot_io_teardown(ccid, slot);

	/*
	 * Now that we've finished completely waiting for the logical I/O to be
	 * torn down, it's safe for us to proceed with the rest of the needed
	 * tear down.
	 */
	ccid_slot_teardown(ccid, slot, B_TRUE);
}

/*
 * The given CCID slot has been removed. Clean up.
 */
static void
ccid_slot_removed(ccid_t *ccid, ccid_slot_t *slot, boolean_t notify)
{
	VERIFY(MUTEX_HELD(&ccid->ccid_mutex));
	if ((slot->cs_flags & CCID_SLOT_F_PRESENT) == 0) {
		VERIFY0(slot->cs_flags & CCID_SLOT_F_ACTIVE);
		return;
	}

	/*
	 * This slot is gone, mark the flags accordingly.
	 */
	slot->cs_flags &= ~CCID_SLOT_F_PRESENT;

	ccid_slot_inactive(ccid, slot);
}

static void
ccid_slot_setup_functions(ccid_t *ccid, ccid_slot_t *slot)
{
	uint_t bits = CCID_CLASS_F_SHORT_APDU_XCHG | CCID_CLASS_F_EXT_APDU_XCHG;

	slot->cs_icc.icc_init = NULL;
	slot->cs_icc.icc_tx = NULL;
	slot->cs_icc.icc_complete = NULL;
	slot->cs_icc.icc_teardown = NULL;
	slot->cs_icc.icc_fini = NULL;

	switch (ccid->ccid_class.ccd_dwFeatures & bits) {
	case CCID_CLASS_F_SHORT_APDU_XCHG:
	case CCID_CLASS_F_EXT_APDU_XCHG:
		/*
		 * Readers with extended APDU support always also support
		 * short APDUs. We only ever use short APDUs.
		 */
		slot->cs_icc.icc_tx = ccid_write_apdu;
		slot->cs_icc.icc_complete = ccid_complete_apdu;
		slot->cs_icc.icc_teardown = ccid_teardown_apdu;
		break;
	default:
		break;
	}

	/*
	 * When we don't have a supported tx function, we don't want to end
	 * up blocking attach. It's important we attach so that users can try
	 * and determine information about the ICC and reader.
	 */
	if (slot->cs_icc.icc_tx == NULL) {
		ccid_error(ccid, "!CCID does not support I/O transfers to ICC");
	}
}

/*
 * We have an ICC present in a slot. We require that the reader does all
 * protocol and parameter related initializations for us. Just parse the ATR
 * for our own use and use GET_PARAMS to query the parameters the reader set
 * up for us.
 */
static boolean_t
ccid_slot_params_init(ccid_t *ccid, ccid_slot_t *slot, mblk_t *atr)
{
	int ret;
	atr_parsecode_t p;
	atr_protocol_t prot;
	atr_data_t *data;

	/*
	 * Use the slot's atr data structure. This is only used when we're in
	 * the worker context, so it should be safe to access in a lockless
	 * fashion.
	 */
	data = slot->cs_icc.icc_atr_data;
	atr_data_reset(data);
	if ((p = atr_parse(atr->b_rptr, msgsize(atr), data)) != ATR_CODE_OK) {
		ccid_error(ccid, "!failed to parse ATR data from slot %d: %s",
		    slot->cs_slotno, atr_strerror(p));
		return (B_FALSE);
	}

	if ((ret = ccid_command_get_parameters(ccid, slot, &prot,
	    &slot->cs_icc.icc_params)) != 0) {
		ccid_error(ccid, "!failed to get parameters for slot %u: %d",
		    slot->cs_slotno, ret);
		return (B_FALSE);
	}

	slot->cs_icc.icc_protocols = atr_supported_protocols(data);
	slot->cs_icc.icc_cur_protocol = prot;

	if ((ccid->ccid_flags & (CCID_F_NEEDS_PPS | CCID_F_NEEDS_PARAMS |
	    CCID_F_NEEDS_DATAFREQ)) != 0) {
		ccid_error(ccid, "!CCID reader does not support required "
		    "protocol/parameter setup automation");
		return (B_FALSE);
	}

	return (B_TRUE);
}

/*
 * Set up the ICC function parameters and initialize the ICC engine.
 */
static boolean_t
ccid_slot_prot_init(ccid_t *ccid, ccid_slot_t *slot)
{
	ccid_slot_setup_functions(ccid, slot);

	if (slot->cs_icc.icc_init != NULL) {
		slot->cs_icc.icc_init(ccid, slot);
	}

	return (B_TRUE);
}

static int
ccid_slot_power_on(ccid_t *ccid, ccid_slot_t *slot, ccid_class_voltage_t volts,
    mblk_t **atr)
{
	int ret;

	VERIFY(MUTEX_HELD(&ccid->ccid_mutex));

	mutex_exit(&ccid->ccid_mutex);
	if ((ret = ccid_command_power_on(ccid, slot, volts, atr))
	    != 0) {
		freemsg(*atr);

		/*
		 * If we got ENXIO, then we know that there is no ICC
		 * present. This could happen for a number of reasons.
		 * For example, we could have just started up and no
		 * card was plugged in (we default to assuming that one
		 * is). Also, some readers won't really tell us that
		 * nothing is there until after the power on fails,
		 * hence why we don't bother with doing a status check
		 * and just try to power on.
		 */
		if (ret == ENXIO) {
			mutex_enter(&ccid->ccid_mutex);
			slot->cs_flags &= ~CCID_SLOT_F_PRESENT;
			return (ret);
		}

		/*
		 * If we fail to power off the card, check to make sure
		 * it hasn't been removed.
		 */
		if (ccid_command_power_off(ccid, slot) == ENXIO) {
			mutex_enter(&ccid->ccid_mutex);
			slot->cs_flags &= ~CCID_SLOT_F_PRESENT;
			return (ENXIO);
		}

		mutex_enter(&ccid->ccid_mutex);
		return (ret);
	}

	if (!ccid_slot_params_init(ccid, slot, *atr)) {
		ccid_error(ccid, "!failed to set slot paramters for ICC");
		mutex_enter(&ccid->ccid_mutex);
		return (ENOTSUP);
	}

	if (!ccid_slot_prot_init(ccid, slot)) {
		ccid_error(ccid, "!failed to setup protocol for ICC");
		mutex_enter(&ccid->ccid_mutex);
		return (ENOTSUP);
	}

	mutex_enter(&ccid->ccid_mutex);
	return (0);
}

static int
ccid_slot_power_off(ccid_t *ccid, ccid_slot_t *slot)
{
	int ret;

	VERIFY(MUTEX_HELD(&ccid->ccid_mutex));

	ccid_slot_io_teardown(ccid, slot);

	/*
	 * Now that we've finished completely waiting for the logical I/O to be
	 * torn down, try and power off the ICC.
	 */
	mutex_exit(&ccid->ccid_mutex);
	ret = ccid_command_power_off(ccid, slot);
	mutex_enter(&ccid->ccid_mutex);

	if (ret != 0)
		return (ret);

	ccid_slot_inactive(ccid, slot);

	return (ret);
}

static int
ccid_slot_inserted(ccid_t *ccid, ccid_slot_t *slot)
{
	uint_t nvolts = 4;
	uint_t cvolt = 0;
	mblk_t *atr = NULL;
	ccid_class_voltage_t volts[4] = { CCID_CLASS_VOLT_AUTO,
	    CCID_CLASS_VOLT_5_0, CCID_CLASS_VOLT_3_0, CCID_CLASS_VOLT_1_8 };

	VERIFY(MUTEX_HELD(&ccid->ccid_mutex));
	if ((ccid->ccid_flags & CCID_F_DEV_GONE_MASK) != 0) {
		return (0);
	}

	if ((slot->cs_flags & CCID_SLOT_F_ACTIVE) != 0) {
		return (0);
	}

	slot->cs_flags |= CCID_SLOT_F_PRESENT;

	/*
	 * Now, we need to activate this ccid device before we can do anything
	 * with it. First, power on the device. There are two hardware features
	 * which may be at play. There may be automatic voltage detection and
	 * automatic activation on insertion. In theory, when either of those
	 * are present, we should always try to use the auto voltage.
	 *
	 * What's less clear in the specification is if the Auto-Voltage
	 * property is present is if we should try manual voltages or not. For
	 * the moment we do.
	 */
	if ((ccid->ccid_class.ccd_dwFeatures &
	    (CCID_CLASS_F_AUTO_ICC_ACTIVATE | CCID_CLASS_F_AUTO_ICC_VOLTAGE))
	    == 0) {
		/* Skip auto-voltage */
		cvolt++;
	}

	for (; cvolt < nvolts; cvolt++) {
		int ret;

		if (volts[cvolt] != CCID_CLASS_VOLT_AUTO &&
		    (ccid->ccid_class.ccd_bVoltageSupport & volts[cvolt])
		    == 0) {
			continue;
		}

		if ((ret = ccid_slot_power_on(ccid, slot, volts[cvolt], &atr))
		    != 0) {
			continue;
		}

		break;
	}

	if (cvolt >= nvolts) {
		ccid_error(ccid, "!failed to activate and power on ICC, no "
		    "supported voltages found");
		goto notsup;
	}

	slot->cs_voltage = volts[cvolt];
	slot->cs_atr = atr;
	slot->cs_flags |= CCID_SLOT_F_ACTIVE;

	ccid_slot_pollout_signal(slot);

	return (0);

notsup:
	freemsg(atr);
	ccid_slot_teardown(ccid, slot, B_FALSE);
	return (ENOTSUP);
}

static int
ccid_slot_warm_reset(ccid_t *ccid, ccid_slot_t *slot)
{
	int ret;
	mblk_t *atr;
	ccid_class_voltage_t voltage;

	VERIFY(MUTEX_HELD(&ccid->ccid_mutex));

	ccid_slot_io_teardown(ccid, slot);

	voltage = slot->cs_voltage;

	ccid_slot_teardown(ccid, slot, B_FALSE);

	ret = ccid_slot_power_on(ccid, slot, voltage, &atr);
	if (ret != 0) {
		freemsg(atr);
		return (ret);
	}

	slot->cs_voltage = voltage;
	slot->cs_atr = atr;

	return (ret);
}

static boolean_t
ccid_slot_reset(ccid_t *ccid, ccid_slot_t *slot)
{
	int ret;

	VERIFY(MUTEX_HELD(&ccid->ccid_mutex));
	VERIFY(slot->cs_flags & CCID_SLOT_F_NEED_TXN_RESET);
	VERIFY(ccid->ccid_flags & CCID_F_WORKER_RUNNING);

	if (ccid->ccid_flags & CCID_F_DEV_GONE_MASK)
		return (B_TRUE);

	/*
	 * Power off the ICC. This will wait for logical I/O if needed.
	 */
	ret = ccid_slot_power_off(ccid, slot);

	/*
	 * If we failed to power off the ICC because the ICC is removed, then
	 * just return that we failed, so that we can let the next lap clean
	 * things up by noting that the ICC has been removed.
	 */
	if (ret != 0 && ret == ENXIO) {
		return (B_FALSE);
	}

	if (ret != 0) {
		ccid_error(ccid, "!failed to reset slot %d for next txn: %d; "
		    "taking another lap", slot->cs_slotno, ret);
		return (B_FALSE);
	}

	/*
	 * Mimic a slot insertion to power this back on. Don't worry about
	 * success or failure, because as far as we care for resetting it, we've
	 * done our duty once we've powered it off successfully.
	 */
	(void) ccid_slot_inserted(ccid, slot);

	return (B_TRUE);
}

/*
 * We've been asked to perform some amount of work on the various slots that we
 * have. This may be because the slot needs to be reset due to the completion of
 * a transaction or it may be because an ICC inside of the slot has been
 * removed.
 */
static void
ccid_worker(void *arg)
{
	uint_t i;
	ccid_t *ccid = arg;

	mutex_enter(&ccid->ccid_mutex);
	ccid->ccid_stats.cst_ndiscover++;
	ccid->ccid_stats.cst_lastdiscover = gethrtime();
	ccid->ccid_flags |= CCID_F_WORKER_RUNNING;
	ccid->ccid_flags &= ~CCID_F_WORKER_REQUESTED;

	for (i = 0; i < ccid->ccid_nslots; i++) {
		ccid_slot_t *slot = &ccid->ccid_slots[i];
		uint_t flags;

		VERIFY(MUTEX_HELD(&ccid->ccid_mutex));

		if ((ccid->ccid_flags & CCID_F_DEV_GONE_MASK) != 0) {
			ccid->ccid_flags &= ~CCID_F_WORKER_MASK;
			mutex_exit(&ccid->ccid_mutex);
			return;
		}

		/*
		 * Snapshot the flags before we start processing the worker. At
		 * this time we clear out all of the change flags as we'll be
		 * operating on the device. We do not clear the
		 * CCID_SLOT_F_NEED_TXN_RESET flag, as we want to make sure that
		 * this is maintained until we're done here.
		 */
		flags = slot->cs_flags & CCID_SLOT_F_WORK_MASK;
		slot->cs_flags &= ~CCID_SLOT_F_INTR_MASK;

		if ((flags & CCID_SLOT_F_INTR_OVERCURRENT) != 0) {
			ccid_slot_inactive(ccid, slot);
		}

		if ((flags & CCID_SLOT_F_CHANGED) != 0) {
			if (flags & CCID_SLOT_F_INTR_GONE) {
				ccid_slot_removed(ccid, slot, B_TRUE);
			} else {
				(void) ccid_slot_inserted(ccid, slot);
				if ((slot->cs_flags & CCID_SLOT_F_ACTIVE)
				    != 0) {
					ccid_slot_excl_maybe_signal(slot);
				}
			}
			VERIFY(MUTEX_HELD(&ccid->ccid_mutex));
		}

		if ((flags & CCID_SLOT_F_NEED_TXN_RESET) != 0) {
			/*
			 * If the CCID_SLOT_F_PRESENT flag is set, then we
			 * should attempt to power off and power on the ICC in
			 * an attempt to reset it. If this fails, trigger
			 * another worker that needs to operate.
			 */
			if ((slot->cs_flags & CCID_SLOT_F_PRESENT) != 0) {
				if (!ccid_slot_reset(ccid, slot)) {
					ccid_worker_request(ccid);
					continue;
				}
			}

			VERIFY(MUTEX_HELD(&ccid->ccid_mutex));
			slot->cs_flags &= ~CCID_SLOT_F_NEED_TXN_RESET;
			/*
			 * Try to signal the next thread waiting for exclusive
			 * access.
			 */
			ccid_slot_excl_maybe_signal(slot);
		}
	}

	/*
	 * If we have a request to operate again, delay before we consider this,
	 * to make sure we don't do too much work ourselves.
	 */
	if ((ccid->ccid_flags & CCID_F_WORKER_REQUESTED) != 0) {
		mutex_exit(&ccid->ccid_mutex);
		delay(drv_usectohz(1000) * 10);
		mutex_enter(&ccid->ccid_mutex);
	}

	ccid->ccid_flags &= ~CCID_F_WORKER_RUNNING;
	if ((ccid->ccid_flags & CCID_F_DEV_GONE_MASK) != 0) {
		ccid->ccid_flags &= ~CCID_F_WORKER_REQUESTED;
		mutex_exit(&ccid->ccid_mutex);
		return;
	}

	if ((ccid->ccid_flags & CCID_F_WORKER_REQUESTED) != 0) {
		(void) ddi_taskq_dispatch(ccid->ccid_taskq, ccid_worker, ccid,
		    DDI_SLEEP);
	}
	mutex_exit(&ccid->ccid_mutex);
}

static void
ccid_worker_request(ccid_t *ccid)
{
	boolean_t run;

	VERIFY(MUTEX_HELD(&ccid->ccid_mutex));
	if ((ccid->ccid_flags & CCID_F_DEV_GONE_MASK) != 0) {
		return;
	}

	run = (ccid->ccid_flags & CCID_F_WORKER_MASK) == 0;
	ccid->ccid_flags |= CCID_F_WORKER_REQUESTED;
	if (run) {
		mutex_exit(&ccid->ccid_mutex);
		(void) ddi_taskq_dispatch(ccid->ccid_taskq, ccid_worker, ccid,
		    DDI_SLEEP);
		mutex_enter(&ccid->ccid_mutex);
	}
}

static void
ccid_intr_restart_timeout(void *arg)
{
	ccid_t *ccid = arg;

	mutex_enter(&ccid->ccid_mutex);
	if ((ccid->ccid_flags & CCID_F_DEV_GONE_MASK) != 0) {
		ccid->ccid_poll_timeout = NULL;
		mutex_exit(&ccid->ccid_mutex);
	}
	mutex_exit(&ccid->ccid_mutex);

	ccid_intr_poll_init(ccid);
}

/*
 * Search for the current class descriptor from the configuration cloud and
 * parse it for our use. We do this by first finding the current interface
 * descriptor and expecting it to be one of the next descriptors.
 */
static boolean_t
ccid_parse_class_desc(ccid_t *ccid)
{
	uint_t i;
	size_t len, tlen;
	usb_client_dev_data_t *dp;
	usb_alt_if_data_t *alt;

	/*
	 * Establish the target length we're looking for from usb_parse_data().
	 * Note that we cannot use the sizeof (ccid_class_descr_t) for this
	 * because that function does not know how to account for the padding at
	 * the end of the target structure (which is reasonble). So we manually
	 * figure out the number of bytes it should in theory write.
	 */
	tlen = offsetof(ccid_class_descr_t, ccd_bMaxCCIDBusySlots) +
	    sizeof (ccid->ccid_class.ccd_bMaxCCIDBusySlots);
	dp = ccid->ccid_dev_data;
	alt = &dp->dev_curr_cfg->cfg_if[dp->dev_curr_if].if_alt[0];
	for (i = 0; i < alt->altif_n_cvs; i++) {
		usb_cvs_data_t *cvs = &alt->altif_cvs[i];
		if (cvs->cvs_buf == NULL)
			continue;
		if (cvs->cvs_buf_len != CCID_DESCR_LENGTH)
			continue;
		if (cvs->cvs_buf[1] != CCID_DESCR_TYPE)
			continue;
		if ((len = usb_parse_data("ccscc3lcllc5lccscc", cvs->cvs_buf,
		    cvs->cvs_buf_len, &ccid->ccid_class,
		    sizeof (ccid->ccid_class))) >= tlen) {
			return (B_TRUE);
		}
		ccid_error(ccid, "!failed to parse CCID class descriptor from "
		    "cvs %u, expected %lu bytes, received %lu", i, tlen, len);
	}

	ccid_error(ccid, "!failed to find matching CCID class descriptor");
	return (B_FALSE);
}

/*
 * Verify whether or not we can support this CCID reader.
 */
static boolean_t
ccid_supported(ccid_t *ccid)
{
	usb_client_dev_data_t *dp;
	usb_alt_if_data_t *alt;
	ccid_class_features_t feat;
	uint_t bits;
	uint16_t ver = ccid->ccid_class.ccd_bcdCCID;

	if (CCID_VERSION_MAJOR(ver) != CCID_VERSION_ONE) {
		ccid_error(ccid, "!refusing to attach to CCID with unsupported "
		    "version %x.%2x", CCID_VERSION_MAJOR(ver),
		    CCID_VERSION_MINOR(ver));
		return (B_FALSE);
	}

	/*
	 * Check the number of endpoints. This should have either two or three.
	 * If three, that means we should expect an interrupt-IN endpoint.
	 * Otherwise, we shouldn't. Any other value indicates something weird
	 * that we should ignore.
	 */
	dp = ccid->ccid_dev_data;
	alt = &dp->dev_curr_cfg->cfg_if[dp->dev_curr_if].if_alt[0];
	switch (alt->altif_descr.bNumEndpoints) {
	case 2:
		ccid->ccid_flags &= ~CCID_F_HAS_INTR;
		break;
	case 3:
		ccid->ccid_flags |= CCID_F_HAS_INTR;
		break;
	default:
		ccid_error(ccid, "!refusing to attach to CCID with unsupported "
		    "number of endpoints: %d", alt->altif_descr.bNumEndpoints);
		return (B_FALSE);
	}

	/*
	 * Try and determine the appropriate buffer size. This can be a little
	 * tricky. The class descriptor tells us the maximum size that the
	 * reader accepts. While it may be tempting to try and use a larger
	 * value such as the maximum size, the readers really don't like
	 * receiving bulk transfers that large. However, there are also reports
	 * of readers that will overwrite to a fixed minimum size. Until we see
	 * such a thing in the wild there's probably no point in trying to deal
	 * with it here.
	 */
	ccid->ccid_bufsize = ccid->ccid_class.ccd_dwMaxCCIDMessageLength;
	if (ccid->ccid_bufsize < CCID_MIN_MESSAGE_LENGTH) {
		ccid_error(ccid, "!CCID reader maximum CCID message length (%u)"
		    " is less than minimum packet length (%u)",
		    ccid->ccid_bufsize, CCID_MIN_MESSAGE_LENGTH);
		return (B_FALSE);
	}

	/*
	 * At this time, we do not require that the system have automatic ICC
	 * activation or automatic ICC voltage. These are handled automatically
	 * by the system.
	 */
	feat = ccid->ccid_class.ccd_dwFeatures;

	/*
	 * Check the number of data rates that are supported by the reader. If
	 * the reader has a non-zero value and we don't support automatic
	 * negotiation then warn about that.
	 */
	if (ccid->ccid_class.ccd_bNumDataRatesSupported != 0 &&
	    (feat & CCID_CLASS_F_AUTO_BAUD) == 0) {
		ccid_error(ccid, "!CCID reader only supports fixed clock rates,"
		    " data will be limited to default values");
	}

	/*
	 * Check which automatic features the reader provides and which features
	 * it does not. Missing features will require additional work before a
	 * card can be activated. Note, this also applies to APDU based readers
	 * which may need to have various aspects of the device negotiated.
	 */

	/*
	 * The footnote for these two bits in CCID r1.1.0 indicates that
	 * when neither are missing we have to do the PPS negotiation
	 * ourselves.
	 */
	bits = CCID_CLASS_F_AUTO_PARAM_NEG | CCID_CLASS_F_AUTO_PPS;
	if ((feat & bits) == 0) {
		ccid->ccid_flags |= CCID_F_NEEDS_PPS;
	}

	if ((feat & CCID_CLASS_F_AUTO_PARAM_NEG) == 0) {
		ccid->ccid_flags |= CCID_F_NEEDS_PARAMS;
	}

	bits = CCID_CLASS_F_AUTO_BAUD | CCID_CLASS_F_AUTO_ICC_CLOCK;
	if ((feat & bits) != bits) {
		ccid->ccid_flags |= CCID_F_NEEDS_DATAFREQ;
	}

	return (B_TRUE);
}

static boolean_t
ccid_open_pipes(ccid_t *ccid)
{
	int ret;
	usb_ep_data_t *ep;
	usb_client_dev_data_t *data;
	usb_pipe_policy_t policy;

	data = ccid->ccid_dev_data;

	/*
	 * First fill all the descriptors.
	 */
	ep = usb_lookup_ep_data(ccid->ccid_dip, data, data->dev_curr_if, 0, 0,
	    USB_EP_ATTR_BULK, USB_EP_DIR_IN);
	if (ep == NULL) {
		ccid_error(ccid, "!failed to find CCID Bulk-IN endpoint");
		return (B_FALSE);
	}

	if ((ret = usb_ep_xdescr_fill(USB_EP_XDESCR_CURRENT_VERSION,
	    ccid->ccid_dip, ep, &ccid->ccid_bulkin_xdesc)) != USB_SUCCESS) {
		ccid_error(ccid, "!failed to fill Bulk-IN xdescr: %d", ret);
		return (B_FALSE);
	}

	ep = usb_lookup_ep_data(ccid->ccid_dip, data, data->dev_curr_if, 0, 0,
	    USB_EP_ATTR_BULK, USB_EP_DIR_OUT);
	if (ep == NULL) {
		ccid_error(ccid, "!failed to find CCID Bulk-OUT endpoint");
		return (B_FALSE);
	}

	if ((ret = usb_ep_xdescr_fill(USB_EP_XDESCR_CURRENT_VERSION,
	    ccid->ccid_dip, ep, &ccid->ccid_bulkout_xdesc)) != USB_SUCCESS) {
		ccid_error(ccid, "!failed to fill Bulk-OUT xdescr: %d", ret);
		return (B_FALSE);
	}

	if (ccid->ccid_flags & CCID_F_HAS_INTR) {
		ep = usb_lookup_ep_data(ccid->ccid_dip, data, data->dev_curr_if,
		    0, 0, USB_EP_ATTR_INTR, USB_EP_DIR_IN);
		if (ep == NULL) {
			ccid_error(ccid, "!failed to find CCID Intr-IN "
			    "endpoint");
			return (B_FALSE);
		}

		if ((ret = usb_ep_xdescr_fill(USB_EP_XDESCR_CURRENT_VERSION,
		    ccid->ccid_dip, ep, &ccid->ccid_intrin_xdesc)) !=
		    USB_SUCCESS) {
			ccid_error(ccid, "!failed to fill Intr-OUT xdescr: %d",
			    ret);
			return (B_FALSE);
		}
	}

	/*
	 * Now open up the pipes.
	 */
	bzero(&policy, sizeof (policy));
	policy.pp_max_async_reqs = CCID_NUM_ASYNC_REQS;

	if ((ret = usb_pipe_xopen(ccid->ccid_dip, &ccid->ccid_bulkin_xdesc,
	    &policy, USB_FLAGS_SLEEP, &ccid->ccid_bulkin_pipe)) !=
	    USB_SUCCESS) {
		ccid_error(ccid, "!failed to open Bulk-IN pipe: %d\n", ret);
		return (B_FALSE);
	}

	if ((ret = usb_pipe_xopen(ccid->ccid_dip, &ccid->ccid_bulkout_xdesc,
	    &policy, USB_FLAGS_SLEEP, &ccid->ccid_bulkout_pipe)) !=
	    USB_SUCCESS) {
		ccid_error(ccid, "!failed to open Bulk-OUT pipe: %d\n", ret);
		usb_pipe_close(ccid->ccid_dip, ccid->ccid_bulkin_pipe,
		    USB_FLAGS_SLEEP, NULL, NULL);
		ccid->ccid_bulkin_pipe = NULL;
		return (B_FALSE);
	}

	if (ccid->ccid_flags & CCID_F_HAS_INTR) {
		if ((ret = usb_pipe_xopen(ccid->ccid_dip,
		    &ccid->ccid_intrin_xdesc, &policy, USB_FLAGS_SLEEP,
		    &ccid->ccid_intrin_pipe)) != USB_SUCCESS) {
			ccid_error(ccid, "!failed to open Intr-IN pipe: %d\n",
			    ret);
			usb_pipe_close(ccid->ccid_dip, ccid->ccid_bulkin_pipe,
			    USB_FLAGS_SLEEP, NULL, NULL);
			ccid->ccid_bulkin_pipe = NULL;
			usb_pipe_close(ccid->ccid_dip, ccid->ccid_bulkout_pipe,
			    USB_FLAGS_SLEEP, NULL, NULL);
			ccid->ccid_bulkout_pipe = NULL;
			return (B_FALSE);
		}
	}

	ccid->ccid_control_pipe = data->dev_default_ph;
	return (B_TRUE);
}

static void
ccid_slots_fini(ccid_t *ccid)
{
	uint_t i;

	for (i = 0; i < ccid->ccid_nslots; i++) {
		VERIFY3U(ccid->ccid_slots[i].cs_slotno, ==, i);

		if (ccid->ccid_slots[i].cs_command != NULL) {
			ccid_command_free(ccid->ccid_slots[i].cs_command);
			ccid->ccid_slots[i].cs_command = NULL;
		}

		cv_destroy(&ccid->ccid_slots[i].cs_io.ci_cv);
		freemsgchain(ccid->ccid_slots[i].cs_atr);
		atr_data_free(ccid->ccid_slots[i].cs_icc.icc_atr_data);
		list_destroy(&ccid->ccid_slots[i].cs_minors);
		list_destroy(&ccid->ccid_slots[i].cs_excl_waiters);
	}

	ddi_remove_minor_node(ccid->ccid_dip, NULL);
	kmem_free(ccid->ccid_slots, sizeof (ccid_slot_t) * ccid->ccid_nslots);
	ccid->ccid_nslots = 0;
	ccid->ccid_slots = NULL;
}

static boolean_t
ccid_slots_init(ccid_t *ccid)
{
	uint_t i;

	/*
	 * The class descriptor has the maximum index that one can index into.
	 * We therefore have to add one to determine the actual number of slots
	 * that exist.
	 */
	ccid->ccid_nslots = ccid->ccid_class.ccd_bMaxSlotIndex + 1;
	ccid->ccid_slots = kmem_zalloc(sizeof (ccid_slot_t) * ccid->ccid_nslots,
	    KM_SLEEP);
	for (i = 0; i < ccid->ccid_nslots; i++) {
		ccid_slot_t *slot = &ccid->ccid_slots[i];

		/*
		 * We initialize every possible slot as having changed to make
		 * sure that we have a chance to discover it. See the slot
		 * detection section in the big theory statement for more info.
		 */
		slot->cs_flags |= CCID_SLOT_F_CHANGED;
		slot->cs_slotno = i;
		slot->cs_ccid = ccid;
		slot->cs_icc.icc_atr_data = atr_data_alloc();
		slot->cs_idx.cmi_minor = CCID_MINOR_INVALID;
		slot->cs_idx.cmi_isslot = B_TRUE;
		slot->cs_idx.cmi_data.cmi_slot = slot;
		cv_init(&slot->cs_io.ci_cv, NULL, CV_DRIVER, NULL);
		list_create(&slot->cs_minors, sizeof (ccid_minor_t),
		    offsetof(ccid_minor_t, cm_minor_list));
		list_create(&slot->cs_excl_waiters, sizeof (ccid_minor_t),
		    offsetof(ccid_minor_t, cm_excl_list));
	}

	return (B_TRUE);
}

static void
ccid_minors_fini(ccid_t *ccid)
{
	uint_t i;

	ddi_remove_minor_node(ccid->ccid_dip, NULL);
	for (i = 0; i < ccid->ccid_nslots; i++) {
		if (ccid->ccid_slots[i].cs_idx.cmi_minor == CCID_MINOR_INVALID)
			continue;
		ccid_minor_idx_free(&ccid->ccid_slots[i].cs_idx);
	}
}

static boolean_t
ccid_minors_init(ccid_t *ccid)
{
	uint_t i;

	for (i = 0; i < ccid->ccid_nslots; i++) {
		char buf[32];

		(void) ccid_minor_idx_alloc(&ccid->ccid_slots[i].cs_idx,
		    B_TRUE);

		(void) snprintf(buf, sizeof (buf), "slot%u", i);
		if (ddi_create_minor_node(ccid->ccid_dip, buf, S_IFCHR,
		    ccid->ccid_slots[i].cs_idx.cmi_minor,
		    DDI_NT_CCID_ATTACHMENT_POINT, 0) != DDI_SUCCESS) {
			ccid_minors_fini(ccid);
			return (B_FALSE);
		}
	}

	return (B_TRUE);
}

static void
ccid_intr_poll_fini(ccid_t *ccid)
{
	if (ccid->ccid_flags & CCID_F_HAS_INTR) {
		timeout_id_t tid;

		mutex_enter(&ccid->ccid_mutex);
		tid = ccid->ccid_poll_timeout;
		ccid->ccid_poll_timeout = NULL;
		mutex_exit(&ccid->ccid_mutex);
		(void) untimeout(tid);
		usb_pipe_stop_intr_polling(ccid->ccid_intrin_pipe,
		    USB_FLAGS_SLEEP);
	} else {
		VERIFY3P(ccid->ccid_intrin_pipe, ==, NULL);
	}
}

static void
ccid_intr_poll_init(ccid_t *ccid)
{
	int ret;
	usb_intr_req_t *uirp;

	uirp = usb_alloc_intr_req(ccid->ccid_dip, 0, USB_FLAGS_SLEEP);
	uirp->intr_client_private = (usb_opaque_t)ccid;
	uirp->intr_attributes = USB_ATTRS_SHORT_XFER_OK |
	    USB_ATTRS_AUTOCLEARING;
	uirp->intr_len = CCID_INTR_RESPONSE_SIZE;
	uirp->intr_cb = ccid_intr_pipe_cb;
	uirp->intr_exc_cb = ccid_intr_pipe_except_cb;

	mutex_enter(&ccid->ccid_mutex);
	if (ccid->ccid_flags & CCID_F_DEV_GONE_MASK) {
		mutex_exit(&ccid->ccid_mutex);
		usb_free_intr_req(uirp);
		return;
	}

	if ((ret = usb_pipe_intr_xfer(ccid->ccid_intrin_pipe, uirp,
	    USB_FLAGS_SLEEP)) != USB_SUCCESS) {
		ccid_error(ccid, "!failed to start polling on CCID Intr-IN "
		    "pipe: %d", ret);
		ccid->ccid_poll_timeout = timeout(ccid_intr_restart_timeout,
		    ccid, drv_usectohz(1000000));
		usb_free_intr_req(uirp);
	}
	mutex_exit(&ccid->ccid_mutex);
}

static void
ccid_cleanup_bulkin(ccid_t *ccid)
{
	uint_t i;

	VERIFY3P(ccid->ccid_bulkin_dispatched, ==, NULL);
	for (i = 0; i < ccid->ccid_bulkin_alloced; i++) {
		VERIFY3P(ccid->ccid_bulkin_cache[i], !=, NULL);
		usb_free_bulk_req(ccid->ccid_bulkin_cache[i]);
		ccid->ccid_bulkin_cache[i] = NULL;
	}

#ifdef	DEBUG
	for (i = 0; i < CCID_BULK_NALLOCED; i++) {
		VERIFY3P(ccid->ccid_bulkin_cache[i], ==, NULL);
	}
#endif
	ccid->ccid_bulkin_alloced = 0;
}

static int
ccid_disconnect_cb(dev_info_t *dip)
{
	int inst;
	ccid_t *ccid;
	uint_t i;

	if (dip == NULL)
		goto done;

	inst = ddi_get_instance(dip);
	ccid = ddi_get_soft_state(ccid_softstate, inst);
	if (ccid == NULL)
		goto done;
	VERIFY3P(dip, ==, ccid->ccid_dip);

	mutex_enter(&ccid->ccid_mutex);
	/*
	 * First, set the disconnected flag. This will make sure that anyone
	 * that tries to make additional operations will be kicked out. This
	 * flag is checked by detach and by users.
	 */
	ccid->ccid_flags |= CCID_F_DISCONNECTED;

	/*
	 * Now, go through any threads that are blocked on a minor for exclusive
	 * access. They should be woken up and they'll fail due to the fact that
	 * we've set the disconnected flag above.
	 */
	for (i = 0; i < ccid->ccid_nslots; i++) {
		ccid_minor_t *cmp;
		ccid_slot_t *slot = &ccid->ccid_slots[i];

		for (cmp = list_head(&slot->cs_excl_waiters); cmp != NULL;
		    cmp = list_next(&slot->cs_excl_waiters, cmp)) {
			cv_signal(&cmp->cm_excl_cv);
		}
	}

	/*
	 * Finally, we need to basically wake up anyone blocked in read and make
	 * sure that they don't wait there forever and make sure that anyone
	 * polling gets a POLLHUP. We can't really distinguish between this and
	 * an ICC being removed. It will be discovered when someone tries to do
	 * an operation and they receive an ENODEV. We only need to do this on
	 * minors that have exclusive access. Don't worry about them finishing
	 * up, this'll be done as part of detach.
	 */
	for (i = 0; i < ccid->ccid_nslots; i++) {
		ccid_slot_t *slot = &ccid->ccid_slots[i];
		if (slot->cs_excl_minor == NULL)
			continue;

		pollwakeup(&slot->cs_excl_minor->cm_pollhead,
		    POLLHUP | POLLERR);
		cv_signal(&slot->cs_excl_minor->cm_read_cv);
	}

	/*
	 * If there are outstanding commands, they will ultimately be cleaned
	 * up as the USB commands themselves time out. We will get notified
	 * through the various bulk xfer exception callbacks, which will induce
	 * the cleanup through ccid_command_transport_error(). This will also
	 * take care of commands waiting for I/O teardown.
	 */
	mutex_exit(&ccid->ccid_mutex);

done:
	return (USB_SUCCESS);
}

static usb_event_t ccid_usb_events = {
	ccid_disconnect_cb,
	NULL,
	NULL,
	NULL
};

static void
ccid_cleanup(dev_info_t *dip)
{
	int inst;
	ccid_t *ccid;

	if (dip == NULL)
		return;

	inst = ddi_get_instance(dip);
	ccid = ddi_get_soft_state(ccid_softstate, inst);
	if (ccid == NULL)
		return;
	VERIFY3P(dip, ==, ccid->ccid_dip);

	/*
	 * Make sure we set the detaching flag so anything running in the
	 * background knows to stop.
	 */
	mutex_enter(&ccid->ccid_mutex);
	ccid->ccid_flags |= CCID_F_DETACHING;
	mutex_exit(&ccid->ccid_mutex);

	if ((ccid->ccid_attach & CCID_ATTACH_MINORS) != 0) {
		ccid_minors_fini(ccid);
		ccid->ccid_attach &= ~CCID_ATTACH_MINORS;
	}

	if ((ccid->ccid_attach & CCID_ATTACH_INTR_ACTIVE) != 0) {
		ccid_intr_poll_fini(ccid);
		ccid->ccid_attach &= ~CCID_ATTACH_INTR_ACTIVE;
	}

	/*
	 * At this point, we have shut down the interrupt pipe, the last place
	 * aside from a user that could have kicked off I/O. So finally wait for
	 * any worker threads.
	 */
	if (ccid->ccid_taskq != NULL) {
		ddi_taskq_wait(ccid->ccid_taskq);
		mutex_enter(&ccid->ccid_mutex);
		VERIFY0(ccid->ccid_flags & CCID_F_WORKER_MASK);
		mutex_exit(&ccid->ccid_mutex);
	}

	if ((ccid->ccid_attach & CCID_ATTACH_HOTPLUG_CB) != 0) {
		usb_unregister_event_cbs(dip, &ccid_usb_events);
		ccid->ccid_attach &= ~CCID_ATTACH_HOTPLUG_CB;
	}

	if ((ccid->ccid_attach & CCID_ATTACH_SLOTS) != 0) {
		ccid_slots_fini(ccid);
		ccid->ccid_attach &= ~CCID_ATTACH_SLOTS;
	}

	if ((ccid->ccid_attach & CCID_ATTACH_SEQ_IDS) != 0) {
		id_space_destroy(ccid->ccid_seqs);
		ccid->ccid_seqs = NULL;
		ccid->ccid_attach &= ~CCID_ATTACH_SEQ_IDS;
	}

	if ((ccid->ccid_attach & CCID_ATTACH_OPEN_PIPES) != 0) {
		usb_pipe_close(dip, ccid->ccid_bulkin_pipe, USB_FLAGS_SLEEP,
		    NULL, NULL);
		ccid->ccid_bulkin_pipe = NULL;
		usb_pipe_close(dip, ccid->ccid_bulkout_pipe, USB_FLAGS_SLEEP,
		    NULL, NULL);
		ccid->ccid_bulkout_pipe = NULL;
		if ((ccid->ccid_flags & CCID_F_HAS_INTR) != 0) {
			usb_pipe_close(dip, ccid->ccid_intrin_pipe,
			    USB_FLAGS_SLEEP, NULL, NULL);
			ccid->ccid_intrin_pipe = NULL;
		} else {
			VERIFY3P(ccid->ccid_intrin_pipe, ==, NULL);
		}
		ccid->ccid_control_pipe = NULL;
		ccid->ccid_attach &= ~CCID_ATTACH_OPEN_PIPES;
	}

	/*
	 * Now that all of the pipes are closed. If we happened to have any
	 * cached bulk requests, we should free them.
	 */
	ccid_cleanup_bulkin(ccid);

	if (ccid->ccid_attach & CCID_ATTACH_CMD_LIST) {
		ccid_command_t *cc;

		while ((cc = list_remove_head(&ccid->ccid_command_queue)) !=
		    NULL) {
			ccid_command_free(cc);
		}
		list_destroy(&ccid->ccid_command_queue);

		while ((cc = list_remove_head(&ccid->ccid_complete_queue)) !=
		    NULL) {
			ccid_command_free(cc);
		}
		list_destroy(&ccid->ccid_complete_queue);
	}

	if ((ccid->ccid_attach & CCID_ATTACH_TASKQ) != 0) {
		ddi_taskq_destroy(ccid->ccid_taskq);
		ccid->ccid_taskq = NULL;
		ccid->ccid_attach &= ~CCID_ATTACH_TASKQ;
	}

	if ((ccid->ccid_attach & CCID_ATTACH_MUTEX_INIT) != 0) {
		mutex_destroy(&ccid->ccid_mutex);
		ccid->ccid_attach &= ~CCID_ATTACH_MUTEX_INIT;
	}

	if ((ccid->ccid_attach & CCID_ATTACH_USB_CLIENT) != 0) {
		usb_client_detach(dip, ccid->ccid_dev_data);
		ccid->ccid_dev_data = NULL;
		ccid->ccid_attach &= ~CCID_ATTACH_USB_CLIENT;
	}

	ASSERT0(ccid->ccid_attach);
	ddi_soft_state_free(ccid_softstate, inst);
}

static int
ccid_attach(dev_info_t *dip, ddi_attach_cmd_t cmd)
{
	ccid_t *ccid;
	int inst, ret;
	char buf[64];

	if (cmd != DDI_ATTACH)
		return (DDI_FAILURE);

	inst = ddi_get_instance(dip);
	if (ddi_soft_state_zalloc(ccid_softstate, inst) != DDI_SUCCESS) {
		ccid_error(NULL, "!failed to allocate soft state for ccid "
		    "instance %d", inst);
		return (DDI_FAILURE);
	}

	ccid = ddi_get_soft_state(ccid_softstate, inst);
	ccid->ccid_dip = dip;

	if ((ret = usb_client_attach(dip, USBDRV_VERSION, 0)) != USB_SUCCESS) {
		ccid_error(ccid, "!failed to attach to usb client: %d", ret);
		goto cleanup;
	}
	ccid->ccid_attach |= CCID_ATTACH_USB_CLIENT;

	if ((ret = usb_get_dev_data(dip, &ccid->ccid_dev_data, USB_PARSE_LVL_IF,
	    0)) != USB_SUCCESS) {
		ccid_error(ccid, "!failed to get usb device data: %d", ret);
		goto cleanup;
	}

	mutex_init(&ccid->ccid_mutex, NULL, MUTEX_DRIVER,
	    ccid->ccid_dev_data->dev_iblock_cookie);
	ccid->ccid_attach |= CCID_ATTACH_MUTEX_INIT;

	(void) snprintf(buf, sizeof (buf), "ccid%d_taskq", inst);
	ccid->ccid_taskq = ddi_taskq_create(dip, buf, 1, TASKQ_DEFAULTPRI, 0);
	if (ccid->ccid_taskq == NULL) {
		ccid_error(ccid, "!failed to create CCID taskq");
		goto cleanup;
	}
	ccid->ccid_attach |= CCID_ATTACH_TASKQ;

	list_create(&ccid->ccid_command_queue, sizeof (ccid_command_t),
	    offsetof(ccid_command_t, cc_list_node));
	list_create(&ccid->ccid_complete_queue, sizeof (ccid_command_t),
	    offsetof(ccid_command_t, cc_list_node));

	if (!ccid_parse_class_desc(ccid)) {
		ccid_error(ccid, "!failed to parse CCID class descriptor");
		goto cleanup;
	}

	if (!ccid_supported(ccid)) {
		ccid_error(ccid,
		    "!CCID reader is not supported, not attaching");
		goto cleanup;
	}

	if (!ccid_open_pipes(ccid)) {
		ccid_error(ccid, "!failed to open CCID pipes, not attaching");
		goto cleanup;
	}
	ccid->ccid_attach |= CCID_ATTACH_OPEN_PIPES;

	(void) snprintf(buf, sizeof (buf), "ccid%d_seqs", inst);
	if ((ccid->ccid_seqs = id_space_create(buf, CCID_SEQ_MIN,
	    CCID_SEQ_MAX + 1)) == NULL) {
		ccid_error(ccid, "!failed to create CCID sequence id space");
		goto cleanup;
	}
	ccid->ccid_attach |= CCID_ATTACH_SEQ_IDS;

	if (!ccid_slots_init(ccid)) {
		ccid_error(ccid, "!failed to initialize CCID slot structures");
		goto cleanup;
	}
	ccid->ccid_attach |= CCID_ATTACH_SLOTS;

	if (usb_register_event_cbs(dip, &ccid_usb_events, 0) != USB_SUCCESS) {
		ccid_error(ccid, "!failed to register USB hotplug callbacks");
		goto cleanup;
	}
	ccid->ccid_attach |= CCID_ATTACH_HOTPLUG_CB;

	/*
	 * Before we enable the interrupt pipe, take a shot at priming our
	 * bulkin_cache.
	 */
	mutex_enter(&ccid->ccid_mutex);
	ccid_bulkin_cache_refresh(ccid);
	mutex_exit(&ccid->ccid_mutex);

	if (ccid->ccid_flags & CCID_F_HAS_INTR) {
		ccid_intr_poll_init(ccid);
	}
	ccid->ccid_attach |= CCID_ATTACH_INTR_ACTIVE;

	/*
	 * Create minor nodes for each slot.
	 */
	if (!ccid_minors_init(ccid)) {
		ccid_error(ccid, "!failed to create minor nodes");
		goto cleanup;
	}
	ccid->ccid_attach |= CCID_ATTACH_MINORS;

	mutex_enter(&ccid->ccid_mutex);
	ccid_worker_request(ccid);
	mutex_exit(&ccid->ccid_mutex);

	return (DDI_SUCCESS);

cleanup:
	ccid_cleanup(dip);
	return (DDI_FAILURE);
}

static int
ccid_getinfo(dev_info_t *dip, ddi_info_cmd_t cmd, void *arg, void **outp)
{
	return (DDI_FAILURE);
}

static int
ccid_detach(dev_info_t *dip, ddi_detach_cmd_t cmd)
{
	int inst;
	ccid_t *ccid;

	if (cmd != DDI_DETACH)
		return (DDI_FAILURE);

	inst = ddi_get_instance(dip);
	ccid = ddi_get_soft_state(ccid_softstate, inst);
	VERIFY3P(ccid, !=, NULL);
	VERIFY3P(dip, ==, ccid->ccid_dip);

	mutex_enter(&ccid->ccid_mutex);

	/*
	 * If the device hasn't been disconnected from a USB sense, refuse to
	 * detach. Otherwise, there's no way to guarantee that the ccid
	 * driver will be attached when a user hotplugs an ICC.
	 */
	if ((ccid->ccid_flags & CCID_F_DISCONNECTED) == 0) {
		mutex_exit(&ccid->ccid_mutex);
		return (DDI_FAILURE);
	}

	if (!list_is_empty(&ccid->ccid_command_queue) ||
	    !list_is_empty(&ccid->ccid_complete_queue)) {
		mutex_exit(&ccid->ccid_mutex);
		return (DDI_FAILURE);
	}
	mutex_exit(&ccid->ccid_mutex);

	ccid_cleanup(dip);
	return (DDI_SUCCESS);
}

static void
ccid_minor_free(ccid_minor_t *cmp)
{
	VERIFY3U(cmp->cm_idx.cmi_minor, ==, CCID_MINOR_INVALID);
	crfree(cmp->cm_opener);
	cv_destroy(&cmp->cm_iowait_cv);
	cv_destroy(&cmp->cm_read_cv);
	cv_destroy(&cmp->cm_excl_cv);
	kmem_free(cmp, sizeof (ccid_minor_t));

}

static int
ccid_open(dev_t *devp, int flag, int otyp, cred_t *credp)
{
	ccid_minor_idx_t *idx;
	ccid_minor_t *cmp;
	ccid_slot_t *slot;

	/*
	 * Always check the zone first, to make sure we lie about it existing.
	 */
	if (crgetzoneid(credp) != GLOBAL_ZONEID)
		return (ENOENT);

	if ((otyp & (FNDELAY | FEXCL)) != 0)
		return (EINVAL);

	if (drv_priv(credp) != 0)
		return (EPERM);

	if (otyp != OTYP_CHR)
		return (ENOTSUP);

	if ((flag & FREAD) != FREAD)
		return (EINVAL);

	idx = ccid_minor_find(getminor(*devp));
	if (idx == NULL) {
		return (ENOENT);
	}

	/*
	 * We don't expect anyone to be able to get a non-slot related minor. If
	 * that somehow happens, guard against it and error out.
	 */
	if (!idx->cmi_isslot) {
		return (ENOENT);
	}

	slot = idx->cmi_data.cmi_slot;

	mutex_enter(&slot->cs_ccid->ccid_mutex);
	if ((slot->cs_ccid->ccid_flags & CCID_F_DISCONNECTED) != 0) {
		mutex_exit(&slot->cs_ccid->ccid_mutex);
		return (ENODEV);
	}
	mutex_exit(&slot->cs_ccid->ccid_mutex);

	cmp = kmem_zalloc(sizeof (ccid_minor_t), KM_SLEEP);

	cmp->cm_idx.cmi_minor = CCID_MINOR_INVALID;
	cmp->cm_idx.cmi_isslot = B_FALSE;
	cmp->cm_idx.cmi_data.cmi_user = cmp;
	if (!ccid_minor_idx_alloc(&cmp->cm_idx, B_FALSE)) {
		kmem_free(cmp, sizeof (ccid_minor_t));
		return (ENOSPC);
	}
	cv_init(&cmp->cm_excl_cv, NULL, CV_DRIVER, NULL);
	cv_init(&cmp->cm_read_cv, NULL, CV_DRIVER, NULL);
	cv_init(&cmp->cm_iowait_cv, NULL, CV_DRIVER, NULL);
	cmp->cm_opener = crdup(credp);
	cmp->cm_slot = slot;
	*devp = makedevice(getmajor(*devp), cmp->cm_idx.cmi_minor);

	if ((flag & FWRITE) == FWRITE) {
		cmp->cm_flags |= CCID_MINOR_F_WRITABLE;
	}

	mutex_enter(&slot->cs_ccid->ccid_mutex);
	list_insert_tail(&slot->cs_minors, cmp);
	mutex_exit(&slot->cs_ccid->ccid_mutex);

	return (0);
}

/*
 * Copy a command which may have a message block chain out to the user.
 */
static int
ccid_read_copyout(struct uio *uiop, const mblk_t *mp)
{
	offset_t off;

	off = uiop->uio_loffset;
	VERIFY3P(mp->b_next, ==, NULL);

	for (; mp != NULL; mp = mp->b_cont) {
		int ret;

		if (MBLKL(mp) == 0)
			continue;

		ret = uiomove(mp->b_rptr, MBLKL(mp), UIO_READ, uiop);
		if (ret != 0) {
			return (EFAULT);
		}
	}

	uiop->uio_loffset = off;
	return (0);
}

/*
 * Called to indicate that we are ready for a user to consume the I/O.
 */
static void
ccid_user_io_done(ccid_t *ccid, ccid_slot_t *slot)
{
	ccid_minor_t *cmp;

	VERIFY(MUTEX_HELD(&ccid->ccid_mutex));

	slot->cs_io.ci_flags &= ~CCID_IO_F_IN_PROGRESS;
	slot->cs_io.ci_flags |= CCID_IO_F_DONE;
	cmp = slot->cs_excl_minor;
	if (cmp != NULL) {
		ccid_slot_pollin_signal(slot);
		cv_signal(&cmp->cm_read_cv);
	}
}

/*
 * This is called in a few different sitautions. It's called when an exclusive
 * hold is being released by a user on the slot. It's also called when the ICC
 * is removed, the reader has been unplugged, or the ICC is being reset. In all
 * these cases we need to make sure that I/O is taken care of and we won't be
 * leaving behind vestigial garbage.
 */
static void
ccid_teardown_apdu(ccid_t *ccid, ccid_slot_t *slot, int error)
{

	VERIFY(MUTEX_HELD(&ccid->ccid_mutex));

	/*
	 * If no I/O is in progress, then there's nothing to do at our end.
	 */
	if ((slot->cs_io.ci_flags & CCID_IO_F_IN_PROGRESS) == 0) {
		return;
	}

	slot->cs_io.ci_errno = error;
	ccid_user_io_done(ccid, slot);

	/*
	 * There is still I/O going on. We need to mark this on the slot such
	 * that no one can gain ownership of it or issue commands. This will
	 * block hand off of a slot.
	 */
	slot->cs_flags |= CCID_SLOT_F_NEED_IO_TEARDOWN;
}

/*
 * This function is called in response to a CCID command completing.
 */
static void
ccid_complete_apdu(ccid_t *ccid, ccid_slot_t *slot, ccid_command_t *cc)
{
	ccid_reply_command_status_t crs;
	ccid_reply_icc_status_t cis;
	ccid_command_err_t cce;

	VERIFY(MUTEX_HELD(&ccid->ccid_mutex));
	VERIFY3P(slot->cs_io.ci_command, ==, cc);

	/*
	 * This completion could be called due to the fact that a user is no
	 * longer present, but we still have outstanding work to do in the
	 * stack. As such, we need to go through and check if the flag was set
	 * on the slot during teardown and if so, clean it up now.
	 */
	if ((slot->cs_flags & CCID_SLOT_F_NEED_IO_TEARDOWN) != 0) {
		ccid_command_free(cc);
		slot->cs_io.ci_command = NULL;
		ccid_slot_io_teardown_done(slot);
		return;
	}

	/*
	 * Process this command and figure out what we should logically be
	 * returning to the user.
	 */
	if (cc->cc_state != CCID_COMMAND_COMPLETE) {
		slot->cs_io.ci_errno = EIO;
		slot->cs_flags |= CCID_SLOT_F_NEED_TXN_RESET;
		ccid_worker_request(ccid);
		goto consume;
	}

	ccid_command_status_decode(cc, &crs, &cis, &cce);
	if (crs == CCID_REPLY_STATUS_COMPLETE) {
		mblk_t *mp;

		mp = cc->cc_response;
		cc->cc_response = NULL;
		mp->b_rptr += sizeof (ccid_header_t);
		slot->cs_io.ci_errno = 0;
		slot->cs_io.ci_data = mp;
	} else if (cis == CCID_REPLY_ICC_MISSING) {
		slot->cs_io.ci_errno = ENXIO;
	} else {
		/*
		 * There are a few more semantic things we can do
		 * with the errors here that we're throwing out and
		 * lumping as EIO. Oh well.
		 */
		slot->cs_io.ci_errno = EIO;
	}

	/*
	 * Now, we can go ahead and wake up a reader to process this command.
	 */
consume:
	slot->cs_io.ci_command = NULL;
	ccid_command_free(cc);
	ccid_user_io_done(ccid, slot);
}

/*
 * We have the user buffer in the CCID slot. Given that, transform it into
 * something that we can send to the device. For APDU's this is simply creating
 * a transfer command and copying it into that buffer.
 */
static int
ccid_write_apdu(ccid_t *ccid, ccid_slot_t *slot)
{
	int ret;
	ccid_command_t *cc;

	VERIFY(MUTEX_HELD(&ccid->ccid_mutex));

	if ((ret = ccid_command_alloc(ccid, slot, B_FALSE, NULL,
	    slot->cs_io.ci_ilen, CCID_REQUEST_TRANSFER_BLOCK, 0, 0, 0,
	    &cc)) != 0) {
		return (ret);
	}

	cc->cc_flags |= CCID_COMMAND_F_USER;
	ccid_command_bcopy(cc, slot->cs_io.ci_ibuf, slot->cs_io.ci_ilen);

	slot->cs_io.ci_command = cc;
	mutex_exit(&ccid->ccid_mutex);

	if ((ret = ccid_command_queue(ccid, cc)) != 0) {
		mutex_enter(&ccid->ccid_mutex);
		slot->cs_io.ci_command = NULL;
		ccid_command_free(cc);
		return (ret);
	}

	mutex_enter(&ccid->ccid_mutex);

	return (0);
}

static int
ccid_read(dev_t dev, struct uio *uiop, cred_t *credp)
{
	int ret;
	ccid_minor_idx_t *idx;
	ccid_minor_t *cmp;
	ccid_slot_t *slot;
	ccid_t *ccid;
	boolean_t done;

	if (uiop->uio_resid <= 0) {
		return (EINVAL);
	}

	if ((idx = ccid_minor_find_user(getminor(dev))) == NULL) {
		return (ENOENT);
	}

	cmp = idx->cmi_data.cmi_user;
	slot = cmp->cm_slot;
	ccid = slot->cs_ccid;

	mutex_enter(&ccid->ccid_mutex);
	if ((ccid->ccid_flags & CCID_F_DISCONNECTED) != 0) {
		mutex_exit(&ccid->ccid_mutex);
		return (ENODEV);
	}

	/*
	 * First, check if we have exclusive access. If not, we're done.
	 */
	if ((cmp->cm_flags & CCID_MINOR_F_HAS_EXCL) == 0) {
		mutex_exit(&ccid->ccid_mutex);
		return (EACCES);
	}

	/*
	 * While it's tempting to mirror ccid_write() here and check if we have
	 * a tx or rx function, that actually has no relevance on read. The only
	 * thing that matters is whether or not we actually have an I/O.
	 */

	/*
	 * If there's been no write I/O issued, then this read is not allowed.
	 * While this may seem like a silly constraint, it certainly simplifies
	 * a lot of the surrounding logic and fits with the current consumer
	 * model.
	 */
	if ((slot->cs_io.ci_flags & (CCID_IO_F_IN_PROGRESS | CCID_IO_F_DONE))
	    == 0) {
		mutex_exit(&ccid->ccid_mutex);
		return (ENODATA);
	}

	/*
	 * If another thread is already blocked in read, then don't allow us
	 * in. We only want to allow one thread to attempt to consume a read,
	 * just as we only allow one thread to initiate a write.
	 */
	if ((cmp->cm_flags & CCID_MINOR_F_READ_WAITING) != 0) {
		mutex_exit(&ccid->ccid_mutex);
		return (EBUSY);
	}

	/*
	 * Check if an I/O has completed. Once it has, call the protocol
	 * specific code. Note that the lock may be dropped after polling. In
	 * such a case we will have to logically recheck several conditions.
	 *
	 * Note, we don't really care if the slot is active or not as I/O could
	 * have been in flight while the slot was inactive.
	 */
	while ((slot->cs_io.ci_flags & CCID_IO_F_DONE) == 0) {
		if (uiop->uio_fmode & FNONBLOCK) {
			mutex_exit(&ccid->ccid_mutex);
			return (EWOULDBLOCK);
		}

		/*
		 * While we perform a cv_wait_sig() we'll end up dropping the
		 * CCID mutex. This means that we need to notify the rest of the
		 * driver that a thread is blocked in read. This is used not
		 * only for excluding multiple threads trying to read from the
		 * device, but more importantly so that we know that if the ICC
		 * or reader are removed, that we need to wake up this thread.
		 */
		cmp->cm_flags |= CCID_MINOR_F_READ_WAITING;
		ret = cv_wait_sig(&cmp->cm_read_cv, &ccid->ccid_mutex);
		cmp->cm_flags &= ~CCID_MINOR_F_READ_WAITING;
		cv_signal(&cmp->cm_iowait_cv);

		if (ret == 0) {
			mutex_exit(&ccid->ccid_mutex);
			return (EINTR);
		}

		/*
		 * Check if the reader has been removed. We do not need to check
		 * for other conditions, as we'll end up being told that the I/O
		 * is done and that the error has been set.
		 */
		if ((ccid->ccid_flags & CCID_F_DISCONNECTED) != 0) {
			mutex_exit(&ccid->ccid_mutex);
			return (ENODEV);
		}
	}

	/*
	 * We'll either have an error or data available for the user at this
	 * point that we can copy out. We need to make sure that it's not too
	 * large. The data should have already been adjusted such that we only
	 * have data payloads.
	 */
	done = B_FALSE;
	if (slot->cs_io.ci_errno == 0) {
		size_t mlen;

		mlen = msgsize(slot->cs_io.ci_data);
		if (mlen > uiop->uio_resid) {
			ret = EOVERFLOW;
		} else {
			if ((ret = ccid_read_copyout(uiop, slot->cs_io.ci_data))
			    == 0) {
				done = B_TRUE;
			}
		}
	} else {
		ret = slot->cs_io.ci_errno;
		done = B_TRUE;
	}

	if (done) {
		ccid_clear_io(&slot->cs_io);
		ccid_slot_pollout_signal(slot);
	}

	mutex_exit(&ccid->ccid_mutex);

	return (ret);
}

static int
ccid_write(dev_t dev, struct uio *uiop, cred_t *credp)
{
	int ret;
	ccid_minor_idx_t *idx;
	ccid_minor_t *cmp;
	ccid_slot_t *slot;
	ccid_t *ccid;
	size_t len, cbytes;

	if (uiop->uio_resid > CCID_APDU_LEN_MAX) {
		return (E2BIG);
	}

	if (uiop->uio_resid <= 0) {
		return (EINVAL);
	}

	len = uiop->uio_resid;
	idx = ccid_minor_find_user(getminor(dev));
	if (idx == NULL) {
		return (ENOENT);
	}

	cmp = idx->cmi_data.cmi_user;
	slot = cmp->cm_slot;
	ccid = slot->cs_ccid;

	/*
	 * Now that we have the slot, verify whether or not we can perform this
	 * I/O.
	 */
	mutex_enter(&ccid->ccid_mutex);
	if ((ccid->ccid_flags & CCID_F_DISCONNECTED) != 0) {
		mutex_exit(&ccid->ccid_mutex);
		return (ENODEV);
	}

	/*
	 * Check that we are open for writing, have exclusive access, and
	 * there's a card present. If not, error out.
	 */
	if ((cmp->cm_flags & (CCID_MINOR_F_WRITABLE | CCID_MINOR_F_HAS_EXCL)) !=
	    (CCID_MINOR_F_WRITABLE | CCID_MINOR_F_HAS_EXCL)) {
		mutex_exit(&ccid->ccid_mutex);
		return (EACCES);
	}

	if ((slot->cs_flags & CCID_SLOT_F_ACTIVE) == 0) {
		mutex_exit(&ccid->ccid_mutex);
		return (ENXIO);
	}

	/*
	 * Make sure that we have a supported transmit function.
	 */
	if (slot->cs_icc.icc_tx == NULL) {
		mutex_exit(&ccid->ccid_mutex);
		return (ENOTSUP);
	}

	/*
	 * See if another command is in progress. If so, try to claim it.
	 * Otherwise, fail with EBUSY. Note, we only fail for commands that are
	 * user initiated. There may be other commands that are ongoing in the
	 * system.
	 */
	if ((slot->cs_io.ci_flags & CCID_IO_F_POLLOUT_FLAGS) != 0) {
		mutex_exit(&ccid->ccid_mutex);
		return (EBUSY);
	}

	/*
	 * Use uiocopy and not uiomove. This way if we fail for whatever reason,
	 * we don't have to worry about restoring the original buffer.
	 */
	if (uiocopy(slot->cs_io.ci_ibuf, len, UIO_WRITE, uiop, &cbytes) != 0) {
		mutex_exit(&ccid->ccid_mutex);
		return (EFAULT);
	}

	slot->cs_io.ci_ilen = len;
	slot->cs_io.ci_flags |= CCID_IO_F_PREPARING;
	slot->cs_io.ci_omp = NULL;

	/*
	 * Now that we're here, go ahead and call the actual tx function.
	 */
	if ((ret = slot->cs_icc.icc_tx(ccid, slot)) != 0) {
		/*
		 * The command wasn't actually transmitted. In this case we need
		 * to reset the copied in data and signal anyone who is polling
		 * that this is writeable again. We don't have to worry about
		 * readers at this point, as they won't get in unless
		 * CCID_IO_F_IN_PROGRESS has been set.
		 */
		slot->cs_io.ci_ilen = 0;
		bzero(slot->cs_io.ci_ibuf, sizeof (slot->cs_io.ci_ibuf));
		slot->cs_io.ci_flags &= ~CCID_IO_F_PREPARING;

		ccid_slot_pollout_signal(slot);
	} else {
		slot->cs_io.ci_flags &= ~CCID_IO_F_PREPARING;
		slot->cs_io.ci_flags |= CCID_IO_F_IN_PROGRESS;
		uiop->uio_resid -= cbytes;
	}
	/*
	 * Notify a waiter that we've moved on.
	 */
	cv_signal(&slot->cs_excl_minor->cm_iowait_cv);
	mutex_exit(&ccid->ccid_mutex);

	return (ret);
}

static int
ccid_ioctl_status(ccid_slot_t *slot, intptr_t arg, int mode)
{
	uccid_cmd_status_t ucs;
	ccid_t *ccid = slot->cs_ccid;

	if (ddi_copyin((void *)arg, &ucs, sizeof (ucs), mode & FKIOCTL) != 0)
		return (EFAULT);

	if (ucs.ucs_version != UCCID_CURRENT_VERSION)
		return (EINVAL);

	ucs.ucs_status = 0;
	ucs.ucs_instance = ddi_get_instance(slot->cs_ccid->ccid_dip);
	ucs.ucs_slot = slot->cs_slotno;

	mutex_enter(&slot->cs_ccid->ccid_mutex);
	if ((slot->cs_flags & CCID_SLOT_F_PRESENT) != 0)
		ucs.ucs_status |= UCCID_STATUS_F_CARD_PRESENT;
	if ((slot->cs_flags & CCID_SLOT_F_ACTIVE) != 0)
		ucs.ucs_status |= UCCID_STATUS_F_CARD_ACTIVE;

	if (slot->cs_atr != NULL) {
		ucs.ucs_atrlen = MIN(UCCID_ATR_MAX, MBLKL(slot->cs_atr));
		bcopy(slot->cs_atr->b_rptr, ucs.ucs_atr, ucs.ucs_atrlen);
	} else {
		bzero(ucs.ucs_atr, sizeof (ucs.ucs_atr));
		ucs.ucs_atrlen = 0;
	}

	bcopy(&ccid->ccid_class, &ucs.ucs_class, sizeof (ucs.ucs_class));

	if (ccid->ccid_dev_data->dev_product != NULL) {
		(void) strlcpy(ucs.ucs_product,
		    ccid->ccid_dev_data->dev_product, sizeof (ucs.ucs_product));
		ucs.ucs_status |= UCCID_STATUS_F_PRODUCT_VALID;
	} else {
		ucs.ucs_product[0] = '\0';
	}

	if (ccid->ccid_dev_data->dev_serial != NULL) {
		(void) strlcpy(ucs.ucs_serial, ccid->ccid_dev_data->dev_serial,
		    sizeof (ucs.ucs_serial));
		ucs.ucs_status |= UCCID_STATUS_F_SERIAL_VALID;
	} else {
		ucs.ucs_serial[0] = '\0';
	}
	mutex_exit(&slot->cs_ccid->ccid_mutex);

	if ((slot->cs_flags & CCID_SLOT_F_ACTIVE) != 0) {
		ucs.ucs_status |= UCCID_STATUS_F_PARAMS_VALID;
		ucs.ucs_prot = slot->cs_icc.icc_cur_protocol;
		ucs.ucs_params = slot->cs_icc.icc_params;
	}

	if (ddi_copyout(&ucs, (void *)arg, sizeof (ucs), mode & FKIOCTL) != 0)
		return (EFAULT);

	return (0);
}

static int
ccid_ioctl_txn_begin(ccid_slot_t *slot, ccid_minor_t *cmp, intptr_t arg,
    int mode)
{
	int ret;
	uccid_cmd_txn_begin_t uct;
	boolean_t nowait;

	if (ddi_copyin((void *)arg, &uct, sizeof (uct), mode & FKIOCTL) != 0)
		return (EFAULT);

	if (uct.uct_version != UCCID_CURRENT_VERSION)
		return (EINVAL);

	if ((uct.uct_flags & ~UCCID_TXN_DONT_BLOCK) != 0)
		return (EINVAL);
	nowait = (uct.uct_flags & UCCID_TXN_DONT_BLOCK) != 0;

	mutex_enter(&slot->cs_ccid->ccid_mutex);
	if ((cmp->cm_flags & CCID_MINOR_F_WRITABLE) == 0) {
		mutex_exit(&slot->cs_ccid->ccid_mutex);
		return (EACCES);
	}

	ret = ccid_slot_excl_req(slot, cmp, nowait);
	mutex_exit(&slot->cs_ccid->ccid_mutex);

	return (ret);
}

static int
ccid_ioctl_txn_end(ccid_slot_t *slot, ccid_minor_t *cmp, intptr_t arg, int mode)
{
	uccid_cmd_txn_end_t uct;

	if (ddi_copyin((void *)arg, &uct, sizeof (uct), mode & FKIOCTL) != 0) {
		return (EFAULT);
	}

	if (uct.uct_version != UCCID_CURRENT_VERSION) {
		return (EINVAL);
	}

	mutex_enter(&slot->cs_ccid->ccid_mutex);
	if (slot->cs_excl_minor != cmp) {
		mutex_exit(&slot->cs_ccid->ccid_mutex);
		return (EINVAL);
	}
	VERIFY3S(cmp->cm_flags & CCID_MINOR_F_HAS_EXCL, !=, 0);

	/*
	 * Require exactly one of the flags to be set.
	 */
	switch (uct.uct_flags) {
	case UCCID_TXN_END_RESET:
		cmp->cm_flags |= CCID_MINOR_F_TXN_RESET;

	case UCCID_TXN_END_RELEASE:
		break;

	default:
		mutex_exit(&slot->cs_ccid->ccid_mutex);
		return (EINVAL);
	}

	ccid_slot_excl_rele(slot);
	mutex_exit(&slot->cs_ccid->ccid_mutex);

	return (0);
}

static int
ccid_ioctl_fionread(ccid_slot_t *slot, ccid_minor_t *cmp, intptr_t arg,
    int mode)
{
	int data;

	mutex_enter(&slot->cs_ccid->ccid_mutex);
	if ((cmp->cm_flags & (CCID_MINOR_F_WRITABLE | CCID_MINOR_F_HAS_EXCL)) ==
	    (CCID_MINOR_F_WRITABLE | CCID_MINOR_F_HAS_EXCL)) {
		mutex_exit(&slot->cs_ccid->ccid_mutex);
		return (EACCES);
	}

	if ((slot->cs_io.ci_flags & CCID_IO_F_DONE) != 0) {
		mutex_exit(&slot->cs_ccid->ccid_mutex);
		return (ENODATA);
	}

	/*
	 * If there's an error, claim that there's at least one byte to read
	 * even if it means we'll get the error and consume it. FIONREAD only
	 * allows up to an int of data. Realistically because we don't allow
	 * extended APDUs, the amount of data here should be always less than
	 * INT_MAX.
	 */
	if (slot->cs_io.ci_errno != 0) {
		data = 1;
	} else {
		size_t s = msgsize(slot->cs_io.ci_data);
		data = MIN(s, INT_MAX);
	}

	if (ddi_copyout(&data, (void *)arg, sizeof (data), mode & FKIOCTL)
	    != 0) {
		mutex_exit(&slot->cs_ccid->ccid_mutex);
		return (EFAULT);
	}

	mutex_exit(&slot->cs_ccid->ccid_mutex);
	return (0);
}

static int
ccid_ioctl_icc_modify(ccid_slot_t *slot, ccid_minor_t *cmp, intptr_t arg,
    int mode)
{
	int ret = 0;
	uccid_cmd_icc_modify_t uci;
	ccid_t *ccid;

	if (ddi_copyin((void *)arg, &uci, sizeof (uci), mode & FKIOCTL) != 0) {
		return (EFAULT);
	}

	if (uci.uci_version != UCCID_CURRENT_VERSION) {
		return (EINVAL);
	}

	switch (uci.uci_action) {
	case UCCID_ICC_POWER_ON:
	case UCCID_ICC_POWER_OFF:
	case UCCID_ICC_WARM_RESET:
		break;
	default:
		return (EINVAL);
	}

	ccid = slot->cs_ccid;
	mutex_enter(&ccid->ccid_mutex);
	if ((cmp->cm_flags & (CCID_MINOR_F_WRITABLE | CCID_MINOR_F_HAS_EXCL)) !=
	    (CCID_MINOR_F_WRITABLE | CCID_MINOR_F_HAS_EXCL)) {
		mutex_exit(&ccid->ccid_mutex);
		return (EACCES);
	}

	switch (uci.uci_action) {
	case UCCID_ICC_WARM_RESET:
		ret = ccid_slot_warm_reset(ccid, slot);
		break;

	case UCCID_ICC_POWER_OFF:
		ret = ccid_slot_power_off(ccid, slot);
		break;

	case UCCID_ICC_POWER_ON:
		ret = ccid_slot_inserted(ccid, slot);
		break;
	}

	mutex_exit(&ccid->ccid_mutex);

	return (ret);
}

static int
ccid_ioctl(dev_t dev, int cmd, intptr_t arg, int mode, cred_t *credp,
    int *rvalp)
{
	ccid_minor_idx_t *idx;
	ccid_slot_t *slot;
	ccid_minor_t *cmp;

	idx = ccid_minor_find_user(getminor(dev));
	if (idx == NULL) {
		return (ENOENT);
	}

	cmp = idx->cmi_data.cmi_user;
	slot = cmp->cm_slot;

	mutex_enter(&slot->cs_ccid->ccid_mutex);
	if ((slot->cs_ccid->ccid_flags & CCID_F_DISCONNECTED) != 0) {
		mutex_exit(&slot->cs_ccid->ccid_mutex);
		return (ENODEV);
	}
	mutex_exit(&slot->cs_ccid->ccid_mutex);

	switch (cmd) {
	case UCCID_CMD_TXN_BEGIN:
		return (ccid_ioctl_txn_begin(slot, cmp, arg, mode));
	case UCCID_CMD_TXN_END:
		return (ccid_ioctl_txn_end(slot, cmp, arg, mode));
	case UCCID_CMD_STATUS:
		return (ccid_ioctl_status(slot, arg, mode));
	case FIONREAD:
		return (ccid_ioctl_fionread(slot, cmp, arg, mode));
	case UCCID_CMD_ICC_MODIFY:
		return (ccid_ioctl_icc_modify(slot, cmp, arg, mode));
	default:
		break;
	}

	return (ENOTTY);
}

static int
ccid_chpoll(dev_t dev, short events, int anyyet, short *reventsp,
    struct pollhead **phpp)
{
	short ready = 0;
	ccid_minor_idx_t *idx;
	ccid_minor_t *cmp;
	ccid_slot_t *slot;
	ccid_t *ccid;

	idx = ccid_minor_find_user(getminor(dev));
	if (idx == NULL) {
		return (ENOENT);
	}

	cmp = idx->cmi_data.cmi_user;
	slot = cmp->cm_slot;
	ccid = slot->cs_ccid;

	mutex_enter(&ccid->ccid_mutex);
	if ((ccid->ccid_flags & CCID_F_DISCONNECTED) != 0) {
		mutex_exit(&ccid->ccid_mutex);
		return (ENODEV);
	}

	if ((cmp->cm_flags & CCID_MINOR_F_HAS_EXCL) != 0) {
		/*
		 * If the CCID_IO_F_DONE flag is set, then we're always
		 * readable. However, flags are insufficient to be writeable.
		 */
		if ((slot->cs_io.ci_flags & CCID_IO_F_DONE) != 0) {
			ready |= POLLIN | POLLRDNORM;
		} else if ((slot->cs_flags & CCID_SLOT_F_ACTIVE) != 0 &&
		    (slot->cs_io.ci_flags & CCID_IO_F_POLLOUT_FLAGS) == 0 &&
		    slot->cs_icc.icc_tx != NULL) {
			ready |= POLLOUT;
		}

		if ((slot->cs_flags & CCID_SLOT_F_PRESENT) == 0) {
			ready |= POLLHUP;
		}
	}

	*reventsp = ready & events;
	if ((*reventsp == 0 && !anyyet) || (events & POLLET)) {
		*phpp = &cmp->cm_pollhead;
	}

	mutex_exit(&ccid->ccid_mutex);

	return (0);
}

static int
ccid_close(dev_t dev, int flag, int otyp, cred_t *credp)
{
	ccid_minor_idx_t *idx;
	ccid_minor_t *cmp;
	ccid_slot_t *slot;

	idx = ccid_minor_find_user(getminor(dev));
	if (idx == NULL) {
		return (ENOENT);
	}

	/*
	 * First tear down the global index entry.
	 */
	cmp = idx->cmi_data.cmi_user;
	slot = cmp->cm_slot;
	ccid_minor_idx_free(idx);

	/*
	 * If the minor node was closed without an explicit transaction end,
	 * then we need to assume that the reader's ICC is in an arbitrary
	 * state. For example, the ICC could have a specific PIV applet
	 * selected. In such a case, the only safe thing to do is to force a
	 * reset.
	 */
	mutex_enter(&slot->cs_ccid->ccid_mutex);
	if ((cmp->cm_flags & CCID_MINOR_F_HAS_EXCL) != 0) {
		cmp->cm_flags |= CCID_MINOR_F_TXN_RESET;
		ccid_slot_excl_rele(slot);
	}

	list_remove(&slot->cs_minors, cmp);
	mutex_exit(&slot->cs_ccid->ccid_mutex);

	pollhead_clean(&cmp->cm_pollhead);
	ccid_minor_free(cmp);

	return (0);
}

static struct cb_ops ccid_cb_ops = {
	ccid_open,		/* cb_open */
	ccid_close,		/* cb_close */
	nodev,			/* cb_strategy */
	nodev,			/* cb_print */
	nodev,			/* cb_dump */
	ccid_read,		/* cb_read */
	ccid_write,		/* cb_write */
	ccid_ioctl,		/* cb_ioctl */
	nodev,			/* cb_devmap */
	nodev,			/* cb_mmap */
	nodev,			/* cb_segmap */
	ccid_chpoll,		/* cb_chpoll */
	ddi_prop_op,		/* cb_prop_op */
	NULL,			/* cb_stream */
	D_MP,			/* cb_flag */
	CB_REV,			/* cb_rev */
	nodev,			/* cb_aread */
	nodev			/* cb_awrite */
};

static struct dev_ops ccid_dev_ops = {
	DEVO_REV,		/* devo_rev */
	0,			/* devo_refcnt */
	ccid_getinfo,		/* devo_getinfo */
	nulldev,		/* devo_identify */
	nulldev,		/* devo_probe */
	ccid_attach,		/* devo_attach */
	ccid_detach,		/* devo_detach */
	nodev,			/* devo_reset */
	&ccid_cb_ops,		/* devo_cb_ops */
	NULL,			/* devo_bus_ops */
	NULL,			/* devo_power */
	ddi_quiesce_not_supported /* devo_quiesce */
};

static struct modldrv ccid_modldrv = {
	&mod_driverops,
	"USB CCID",
	&ccid_dev_ops
};

static struct modlinkage ccid_modlinkage = {
	MODREV_1,
	{ &ccid_modldrv, NULL }
};

int
_init(void)
{
	int ret;

	if ((ret = ddi_soft_state_init(&ccid_softstate, sizeof (ccid_t),
	    0)) != 0) {
		return (ret);
	}

	if ((ccid_minors = id_space_create("ccid_minors", CCID_MINOR_MIN,
	    INT_MAX)) == NULL) {
		ddi_soft_state_fini(&ccid_softstate);
		return (ret);
	}

	if ((ret = mod_install(&ccid_modlinkage)) != 0) {
		id_space_destroy(ccid_minors);
		ccid_minors = NULL;
		ddi_soft_state_fini(&ccid_softstate);
		return (ret);
	}

	mutex_init(&ccid_idxlock, NULL, MUTEX_DRIVER, NULL);
	avl_create(&ccid_idx, ccid_idx_comparator, sizeof (ccid_minor_idx_t),
	    offsetof(ccid_minor_idx_t, cmi_avl));

	return (ret);
}

int
_info(struct modinfo *modinfop)
{
	return (mod_info(&ccid_modlinkage, modinfop));
}

int
_fini(void)
{
	int ret;

	if ((ret = mod_remove(&ccid_modlinkage)) != 0) {
		return (ret);
	}

	avl_destroy(&ccid_idx);
	mutex_destroy(&ccid_idxlock);
	id_space_destroy(ccid_minors);
	ccid_minors = NULL;
	ddi_soft_state_fini(&ccid_softstate);

	return (ret);
}
