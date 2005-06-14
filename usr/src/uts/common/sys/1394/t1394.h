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
 * Copyright 1999-2002 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef	_SYS_1394_T1394_H
#define	_SYS_1394_T1394_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * t1394.h
 *    Contains all of the prototypes, defines, and structures necessary
 *    for building drivers using the Solaris 1394 Software Framework.
 */

#include <sys/types.h>
#include <sys/dditypes.h>
#include <sys/ddi.h>
#include <sys/sunddi.h>

#include <sys/1394/s1394_impl.h>
#include <sys/1394/cmd1394.h>
#include <sys/1394/id1394.h>
#include <sys/1394/ixl1394.h>
#include <sys/1394/ieee1394.h>
#include <sys/1394/ieee1212.h>

#ifdef	__cplusplus
extern "C" {
#endif

/*
 * Macro to convert a byte stream into a big endian quadlet or octlet or
 * back the other way.  All data is treated as byte streams over the 1394
 * bus.  These macros will convert the data to a big endian "integer" on
 * x86 platforms, and it will do nothing if it is not on x86.
 */
#ifdef _LITTLE_ENDIAN
#define	T1394_DATA32(DATA)	ddi_swap32(DATA)
#define	T1394_DATA64(DATA)	ddi_swap64(DATA)
#else
#define	T1394_DATA32(DATA)	(DATA)
#define	T1394_DATA64(DATA)	(DATA)
#endif

/* The various "handles" returned by the 1394 Framework */

/* Target handle type */
typedef struct target_handle	*t1394_handle_t;
/* Address handle type */
typedef struct address_handle	*t1394_addr_handle_t;
/* Isoch single handle type */
typedef struct isoch_handle	*t1394_isoch_single_handle_t;
/* Isoch CEC handle type */
typedef struct isoch_handle	*t1394_isoch_cec_handle_t;
/* Config ROM handle type */
typedef struct cfgrom_handle	*t1394_cfgrom_handle_t;


/*
 * t1394_localinfo_t
 *    is filled in and returned by the 1394 Framework at attach time
 *    (in the t1394_attachinfo_t structure returned from t1394_attach())
 *    to provide the local host nodeID and the current bus generation.
 */
typedef struct t1394_localinfo_s {
	uint_t			bus_generation;
	uint_t			local_nodeID;
} t1394_localinfo_t;

/*
 * t1394_attachinfo_t
 *    is filled in and returned by the 1394 Framework at attach time
 *    (returned from the call to t1394_attach()).  This structure contains
 *    the t1394_localinfo_t structure described above, as well as the
 *    iblock cookie and the attributes necessary for DMA allocations, etc.
 */
typedef struct t1394_attachinfo_s {
	ddi_iblock_cookie_t 	iblock_cookie;
	ddi_device_acc_attr_t	acc_attr;
	ddi_dma_attr_t		dma_attr;
	t1394_localinfo_t	localinfo;
} t1394_attachinfo_t;


/*
 * t1394_addr_enable_t
 *    is used in the t1394_alloc_addr_t structure, passed to
 *    t1394_alloc_addr(), to indicate what types of (incoming)
 *    asynchronous requests will be allowed in a given address block.
 *    If, for example, an address block is intended to be read-only,
 *    then only the T1394_ADDR_RDENBL bit should be enabled at allocation
 *    time.  Then, when incoming requests of an inappropriate type (write
 *    or lock requests, in this case) arrive, the 1394 Framework can
 *    automatically respond to them with TYPE_ERROR in the response
 *    without having to notify the target driver.
 */
typedef enum {
	T1394_ADDR_RDENBL =	(1 << 0),
	T1394_ADDR_WRENBL =	(1 << 1),
	T1394_ADDR_LKENBL =	(1 << 2)
} t1394_addr_enable_t;

/*
 * t1394_addr_type_t
 *    is used in the t1394_alloc_addr_t structure, passed to
 *    t1394_alloc_addr(), to indicate what type of address block the
 *    target driver would like to allocate.
 *    T1394_ADDR_POSTED_WRITE indicates posted write memory, where
 *    incoming write requests are automatically acknowledged as complete.
 *    T1394_ADDR_NORMAL indicates memory, unlike the posted write area,
 *    where all requests regardless of type are ack_pended upon receipt
 *    and are subsequently responded to.
 *    T1394_ADDR_CSR memory range is generally used by target drivers
 *    that are implementing a well-defined protocol.
 *    And T1394_ADDR_FIXED is used to indicate to t1394_alloc_addr()
 *    that a specific set of addresses are needed.  Unlike the other three
 *    types, this type of request is used to choose a specific address or
 *    range of addresses in 1394 address space.
 */
typedef enum {
	T1394_ADDR_POSTED_WRITE	= 0,
	T1394_ADDR_NORMAL	= 1,
	T1394_ADDR_CSR		= 2,
	T1394_ADDR_FIXED	= 3
} t1394_addr_type_t;

/*
 * t1394_addr_evts_t
 *    is used in the t1394_alloc_addr_t structure, passed to
 *    t1394_alloc_addr(), to specify callback routines for the
 *    allocated address block.  When a request of the appropriate type
 *    (read/write/lock) is received to a target driver's address
 *    block, the appropriate callback routine is consulted and if it is
 *    non-NULL it is called and passed a cmd1394_cmd_t structure used to
 *    describe the incoming asynch request.
 */
typedef struct t1394_addr_evts {
	void	(*recv_read_request)(cmd1394_cmd_t *req);
	void	(*recv_write_request)(cmd1394_cmd_t *req);
	void	(*recv_lock_request)(cmd1394_cmd_t *req);
} t1394_addr_evts_t;

/*
 * t1394_alloc_addr_t
 *    is passed to t1394_alloc_addr(), when 1394 address space is being
 *    allocated, to describe the type of address space.  The target driver
 *    is responsible for specifying the aa_enable, aa_type, and aa_evts
 *    fields described above as well as the size of the allocated block.
 *    Additionally, the target driver may specify backing store
 *    (aa_kmem_bufp), a specific address (in aa_address if aa_type is
 *    T1394_ADDR_FIXED), and a callback argument (in aa_arg) to be
 *    passed to the target in any of its callback routines.
 *    When it returns, t1394_alloc_addr() will return in aa_address the
 *    starting address of the requested block of 1394 address space and
 *    and address block handle (aa_hdl) used to free the address block
 *    in a call to t1394_free_addr().
 */
typedef struct t1394_alloc_addr {
	t1394_addr_type_t	aa_type;	/* IN: address region */
	size_t			aa_length;	/* IN: # bytes requested */
	t1394_addr_enable_t	aa_enable;	/* IN: request enables */
	t1394_addr_evts_t	aa_evts;	/* IN: event callbacks */
	opaque_t		aa_arg;		/* IN: evt callback arg */
	caddr_t			aa_kmem_bufp;	/* IN: backing-store buf */
	uint64_t		aa_address;	/* IN/OUT: alloced address */
	t1394_addr_handle_t	aa_hdl;		/* OUT: returned to target */
} t1394_alloc_addr_t;

/*
 * t1394_fcp_evts_t
 *    is used in t1394_fcp_register_controller(). FCP only allows writes.
 */
typedef struct t1394_fcp_evts {
	int		(*fcp_write_request)(cmd1394_cmd_t *req);
	opaque_t	fcp_arg;
} t1394_fcp_evts_t;

/* values returned by the FCP callback */
enum {
	T1394_REQ_CLAIMED,	/* request is recognized by the target */
	T1394_REQ_UNCLAIMED	/* request is not recognized by the target */
};

/*
 * t1394_cmp_reg_t
 *    CMP register types
 */
typedef enum {
	T1394_CMP_OMPR,		/* oMPR */
	T1394_CMP_IMPR		/* iMPR */
} t1394_cmp_reg_t;

/*
 * t1394_cmp_evts_t
 *    is used in t1394_cmp_register().
 */
typedef struct t1394_cmp_evts {
	void		(*cmp_reg_change)(opaque_t, t1394_cmp_reg_t);
	opaque_t	cmp_arg;
} t1394_cmp_evts_t;

/*
 * t1394_isoch_rsrc_error_t
 *    is used in the rsrc_fail_target() callback to indicate the reason
 *    for the resource allocation failure.  T1394_RSRC_BANDWIDTH indicates
 *    that insufficient bandwidth was available for the requested allocation,
 *    and T1394_RSRC_CHANNEL indicates that none of the requested channels
 *    were available.
 */
typedef enum {
	T1394_RSRC_BANDWIDTH	= 1,
	T1394_RSRC_CHANNEL	= 2
} t1394_isoch_rsrc_error_t;

/*
 * t1394_isoch_singleinfo_t
 *    is passed to the t1394_alloc_isoch_single() routine.  A target
 *    driver will use this structure to indicate the channels it supports,
 *    the maximum speed for the isochronous channel, the amount of
 *    bandwidth required, and the callback (and callback arg) to be used
 *    when notifying the target of resource reallocation failures.
 */
typedef struct t1394_isoch_singleinfo_s {
	uint64_t	si_channel_mask;	/* channels supported */
	uint_t		si_speed;		/* 1394 speed for the channel */
	uint_t		si_bandwidth;		/* max bytes per cycle */
	void		(*rsrc_fail_target)(
			    t1394_isoch_single_handle_t	t1394_single_hdl,
			    opaque_t			single_evt_arg,
			    t1394_isoch_rsrc_error_t	fail_args);
	opaque_t	single_evt_arg;
} t1394_isoch_singleinfo_t;

/*
 * t1394_isoch_single_out_t
 *    is filled in and returned to the target by the
 *    t1394_alloc_isoch_single() routine.  It indicates the number of the
 *    channel that was actually allocated for the target driver.  This
 *    channel number will typically be used by a target driver to setup
 *    isochronous DMA or other resources.
 */
typedef struct t1394_isoch_single_out_s {
	uint_t		channel_num;	/* number for the allocated channel */
} t1394_isoch_single_out_t;

/*
 * t1394_setup_target_args_t
 *    is used in the setup_target() callback to indicate the channel number
 *    and channel speed for the isochronous channel coordinated by the
 *    Isoch CEC routines.
 */
typedef struct t1394_setup_target_args_s {
	uint_t		channel_num;	/* number for the allocated channel */
	uint_t		channel_speed;	/* 1394 speed for the channel */
} t1394_setup_target_args_t;

/*
 * t1394_cec_options_t
 *    is used in the t1394_isoch_cec_props_t structure, passed to
 *    t1394_alloc_isoch_cec().  As the cec_options field in that
 *    structure, it can be used to request that the 1394 Framework
 *    NOT automatically reallocate the same isochronous channel and
 *    bandwidth, if a bus reset happens.  The default behavior is to
 *    let the 1394 Framework attempt to reallocate the same channel and
 *    bandwidth the target had after a bus reset, but some target drivers
 *    may not require this functionality and they therefore have the option
 *    to decline this service.
 */
typedef enum {
	T1394_NO_IRM_ALLOC	= (1 << 0)
} t1394_cec_options_t;

/*
 * t1394_isoch_cec_props_t
 *    is used in calls to the t1394_alloc_isoch_cec() routine.  The
 *    minimum and maximum speeds, channels supported, and the amount
 *    of bandwidth necessary for the channel are specified.  These
 *    characteristics of the Isoch CEC are specified at allocation time
 *    and are used to pass or fail targets that try to join the Isoch
 *    CEC later.
 */
typedef struct t1394_isoch_cec_props_s {
	uint_t			cec_min_speed;	  /* min speed supported */
	uint_t			cec_max_speed;	  /* max speed supported */
	uint64_t		cec_channel_mask; /* channels supported  */
	uint_t			cec_bandwidth;	  /* max bytes per cycle */
	t1394_cec_options_t	cec_options;
} t1394_isoch_cec_props_t;

/*
 * t1394_isoch_cec_evts_t
 *    is used in the t1394_join_isochinfo_t structure, passed to
 *    t1394_join_isoch_cec().  This structure is a list of callbacks
 *    for each of the various events the Isoch CEC is responsible for
 *    coordinating.
 *    The setup_target() callback is called after the isochronous
 *    channel and bandwidth for the Isoch CEC have been allocated
 *    (as a result of a call to t1394_setup_isoch_cec()) to inform the
 *    member targets of the channel number and speed.
 *    The start_target() callback is called for all member targets
 *    as a result of a call to t1394_start_isoch_cec().
 *    The stop_target() callback is called for all member targets
 *    as a result of a call to t1394_stop_isoch_cec().
 *    The rsrc_fail_target() callback (as mentioned above) is called
 *    to indicate that the 1394 Framework was unable to reallocate
 *    isochronous resources and the reason for the failure.
 *    And the teardown_target() callback is called as a result of
 *    a call to t1394_teardown_isoch_cec() to indicate that the
 *    isochronous channel and bandwidth are being freed up.
 */
typedef struct t1394_isoch_cec_evts_s {
	int	(*setup_target)(
		    t1394_isoch_cec_handle_t		t1394_isoch_cec_hdl,
		    opaque_t				isoch_cec_evts_arg,
		    t1394_setup_target_args_t		*setup_args);
	int	(*start_target)(
		    t1394_isoch_cec_handle_t		t1394_isoch_cec_hdl,
		    opaque_t				isoch_cec_evts_arg);
	void	(*stop_target)(
		    t1394_isoch_cec_handle_t		t1394_isoch_cec_hdl,
		    opaque_t				isoch_cec_evts_arg);
	void	(*rsrc_fail_target)(
		    t1394_isoch_cec_handle_t		t1394_isoch_cec_hdl,
		    opaque_t				isoch_cec_evts_arg,
		    t1394_isoch_rsrc_error_t		fail_args);
	void	(*teardown_target)(
		    t1394_isoch_cec_handle_t		t1394_isoch_cec_hdl,
		    opaque_t				isoch_cec_evts_arg);
} t1394_isoch_cec_evts_t;

/*
 * t1394_jii_options_t
 *    is used in the t1394_join_isochinfo_t structure, passed to
 *    t1394_join_isoch_cec().  As the jii_options field in that
 *    structure, it is used to indicate to the 1394 Framework
 *    that the member target is the talker on the channel.  There can
 *    be no more than one talker per Isoch CEC, and a member target
 *    may fail in t1394_join_isoch_cec() because there is already a
 *    talker on the Isoch CEC.
 */
typedef enum {
	T1394_TALKER		= (1 << 0)
} t1394_jii_options_t;

/*
 * t1394_join_isochinfo_t
 *    is used in calls to the t1394_join_isoch_cec() routine.  The
 *    req_channel_mask field indicate the channels that a member
 *    target can support.  If these channels are inconsistent with
 *    the characteristics passed in at allocation or with the current
 *    characteristics of the other members of the Isoch CEC, then the
 *    t1394_join_isoch_cec() call will fail.
 *    The req_max_speed field is used similarly.  If the member target's
 *    maximum speed is inconsistent with the other members of the
 *    Isoch CEC, then the t1394_join_isoch_cec() will fail.
 *    In addition to the above fields, a joining member target will pass
 *    the jii_options (indicate talker or listener), the callbacks and
 *    the callback arg (see above).
 */
typedef struct t1394_join_isochinfo_s {
	uint64_t		req_channel_mask; /* target chnls supported */
	uint_t			req_max_speed;	  /* target max_speed */
	t1394_jii_options_t	jii_options;
	opaque_t		isoch_cec_evts_arg;
	t1394_isoch_cec_evts_t	isoch_cec_evts;
} t1394_join_isochinfo_t;


/*
 * t1394_targetinfo_t
 *    is used in calls to the t1394_get_targetinfo() routine.  The
 *    structure returned to the target contains current_max_payload,
 *    the default maximum block size that the host device will use in
 *    asynchronous block reads and writes to the target's device.
 *    It also contains current_max_speed,  the default maximum speed at
 *    which the host device will communicate with the target's device.
 *    The structure also contains the target driver's target nodeID,
 *    the number assigned to the device for the current bus
 *    generation.  It will contain T1394_INVALID_NODEID if the target
 *    device is no longer connected to the 1394 Serial Bus.
 */
typedef struct t1394_targetinfo_s {
	uint_t			current_max_payload;
	uint_t			current_max_speed;
	uint_t			target_nodeID;
} t1394_targetinfo_t;
#define	T1394_INVALID_NODEID	0xFFFF

/*
 * t1394_cfgrom_entryinfo_t
 *    is used in calls to the t1394_add_cfgrom_entry() routine.  The
 *    t1394_cfgrom_entryinfo_t structure contains the information necessary
 *    to add the Config ROM entry.  The ce_buffer and ce_size are used to
 *    describe the data to be added, and the ce_key is used to indicate
 *    what type of entry in the Config ROM buffer the data represents
 *    (see ieee1212.h fro key types).
 */
typedef struct t1394_cfgrom_entryinfo_s {
	uint_t			ce_key;		/* key for Root Dir. entry */
	size_t			ce_size;	/* size of the buffer */
	uint32_t		*ce_buffer;	/* buffer for Config ROM data */
} t1394_cfgrom_entryinfo_t;



/*
 * ATTACH and DETACH:
 *    These are the calls into 1394 Framework used during target driver
 *    attach() and detach().  The t1394_attach() routine takes a dip and
 *    a version (T1394_VERSION_V1) as its input arguments, and it fills
 *    in and returns a t1394_attachinfo_t structure (described above) and
 *    the t1394_handle_t.  This target handle is used in all subsequent
 *    calls into the 1394 Framework.
 *    The t1394_detach() routine is called from a target driver's detach()
 *    routine to unregister itself from the 1394 Framework.
 */
int t1394_attach(dev_info_t *dip, int version, uint_t flags,
    t1394_attachinfo_t *attachinfo, t1394_handle_t *t1394_hdl);
/* Version value */
#define	T1394_VERSION_V1	1

int t1394_detach(t1394_handle_t *t1394_hdl, uint_t flags);


/*
 * OUTGOING ASYNCHRONOUS COMMANDS:
 *    These are the calls into 1394 Framework used for allocating/freeing
 *    and sending (outgoing) asynchronous requests.  The t1394_alloc_cmd()
 *    routine takes a target driver's handle as an input argument and
 *    returns the cmd1394_cmd_t structure necessary for sending asynch
 *    requests.  The flags parameter is used to indicate whether or not the
 *    1394 Framework may sleep while allocating memory for the command.
 *    The t1394_free_cmd() routine is used to free up commands allocated
 *    by t1394_alloc_cmd().  Commands should not be in use at the time
 *    t1394_free_cmd() is called or the call may fail (return DDI_FAILURE).
 *    After an asynch command has been allocated and filled in (see
 *    the cmd1394.h file for more details) to indicate the type of request,
 *    what types of options are necessary, callback functions and/or data
 *    (if necessary), the command is passed to either t1394_read(),
 *    t1394_write(), or t1394_lock().  These routines will return DDI_SUCCESS
 *    or DDI_FAILURE depending on whether the command has been successfully
 *    accepted by the 1394 Framework.  If the command is a "blocking"
 *    command, the function will not return until the command has completed.
 *    If, however, a callback has been specified in the command, that
 *    function will be called when the command completes.
 */
int t1394_alloc_cmd(t1394_handle_t t1394_hdl, uint_t flags,
    cmd1394_cmd_t **cmdp);
/* Flags passed to t1394_alloc_cmd() */
#define	T1394_ALLOC_CMD_NOSLEEP		0x00000001 /* don't sleep in alloc */
#define	T1394_ALLOC_CMD_FCP_COMMAND	0x00010000 /* FCP command */
#define	T1394_ALLOC_CMD_FCP_RESPONSE	0x00020000 /* FCP response */

int t1394_free_cmd(t1394_handle_t t1394_hdl, uint_t flags,
    cmd1394_cmd_t **cmdp);

int t1394_read(t1394_handle_t t1394_hdl, cmd1394_cmd_t *cmd);

int t1394_write(t1394_handle_t t1394_hdl, cmd1394_cmd_t *cmd);

int t1394_lock(t1394_handle_t t1394_hdl, cmd1394_cmd_t *cmd);


/*
 * 1394 ADDRESS SPACE AND INCOMING ASYNCHRONOUS COMMANDS:
 *    These are the calls into the 1394 Framework used for allocating/freeing
 *    1394 address space and handling incoming asynchronous requests.  The
 *    t1394_alloc_addr() routine is used to allocate 1394 address space.  It
 *    is passed the target handle and a t1394_alloc_addr_t structure
 *    (described above).
 *    The t1394_free_addr() routine is used to free any allocated address
 *    space that the target may have.  Typically, this will be done in a
 *    target driver's detach() routine (before calling t1394_detach()).
 *    The t1394_recv_request_done() routine is used after a target has
 *    received and handled an incoming asynch request.  It is used to send
 *    a response to the request.  After the command is sent to
 *    t1394_recv_request_done(), it should not be modified or used because
 *    the 1394 Framework may free it up without notifying the target driver.
 */
int t1394_alloc_addr(t1394_handle_t t1394_hdl, t1394_alloc_addr_t *addr_allocp,
    uint_t flags, int *result);
/* Results codes returned by t1394_alloc_addr() */
#define	T1394_EALLOC_ADDR		(-400)
#define	T1394_EADDR_FIRST		T1394_EALLOC_ADDR
#define	T1394_EADDR_LAST		T1394_EALLOC_ADDR
/*
 * NOTE: Make sure T1394_EADDR_LAST is updated if a new error code is
 * added. t1394_errmsg.c uses *FIRST and *LAST as bounds checks.
 */

int t1394_free_addr(t1394_handle_t t1394_hdl, t1394_addr_handle_t *addr_hdl,
    uint_t flags);

int t1394_recv_request_done(t1394_handle_t t1394_hdl, cmd1394_cmd_t *resp,
    uint_t flags);


/*
 * FCP SERVICES:
 *    Function Control Protocol (FCP) is defined in IEC 61883-1 and supported
 *    by the 1394 Framework. While target drivers could use t1394_alloc_addr()
 *    and standard asynchronous services, only one driver could use FCP at a
 *    time, because the FCP addresses have fixed values. To allow sharing of
 *    FCP address space, the following Framework services should be used.
 *
 *    t1394_fcp_register_controller() registers the target as an FCP controller,
 *    which allows it to write into target's FCP command register and receive
 *    write requests into host's FCP response register. It takes a valid
 *    t1394_handle_t argument, hence it should be called after t1394_attach().
 *    t1394_fcp_unregister_controller() unregisters the target.
 *
 *    t1394_fcp_register_target() and t1394_fcp_unregister_target() are
 *    target counterparts of the above controller functions.
 */

int t1394_fcp_register_controller(t1394_handle_t t1394_hdl,
    t1394_fcp_evts_t *evts, uint_t flags);

int t1394_fcp_unregister_controller(t1394_handle_t t1394_hdl);

int t1394_fcp_register_target(t1394_handle_t t1394_hdl,
    t1394_fcp_evts_t *evts, uint_t flags);

int t1394_fcp_unregister_target(t1394_handle_t t1394_hdl);


/*
 * CMP services:
 *    Connection Management Procedures (CMP) is defined in IEC 61883-1 and
 *    supported by the 1394 Framework by providing the drivers with shared
 *    access to iMPR and oMPR registers, which are created by the Framework
 *    when t1394_cmp_register() is called and destroyed when
 *    t1394_cmp_unregister() is called. These registers can be read using
 *    t1394_cmp_read() function and compare-swapped using t1394_cmp_cas().
 *
 *    oPCR and iPCR registers can be allocated by the drivers using
 *    t1394_alloc_addr() function.
 */
int t1394_cmp_register(t1394_handle_t t1394_hdl, t1394_cmp_evts_t *evts,
    uint_t flags);

int t1394_cmp_unregister(t1394_handle_t t1394_hdl);

int t1394_cmp_read(t1394_handle_t t1394_hdl, t1394_cmp_reg_t reg,
    uint32_t *valp);

int t1394_cmp_cas(t1394_handle_t t1394_hdl, t1394_cmp_reg_t reg,
    uint32_t arg_val, uint32_t new_val, uint32_t *old_valp);


/*
 * ISOCHRONOUS SERVICES:
 *    These are the calls into the 1394 Framework used for isochronous
 *    services. The t1394_alloc_isoch_single() routine takes a target
 *    handle and a t1394_isoch_singleinfo_t structure (see above).  It will
 *    attempt to setup an isochronous channel (which will be automatically
 *    reallocated after bus resets), and it will return the channel number
 *    of the allocated channel in the t1394_isoch_single_out_t structure.
 *    Additionally, it returns a t1394_isoch_single_handle_t structure
 *    which is passed to t1394_free_isoch_single() when the isochronous
 *    channel is no longer required.
 *    The t1394_alloc_isoch_cec() and t1394_free_isoch_cec() are used to
 *    allocate and free an Isoch Channel Event Coordinator (CEC).  Target
 *    drivers pass a t1394_isoch_cec_props_t structure (described above)
 *    to specify the initial characteristics of the Isoch CEC.
 *    Targets will subsequently join the Isoch CEC with t1394_join_isoch_cec()
 *    before setting up the channel with t1394_setup_isoch_cec().
 *    Calls to t1394_join_isoch_cec() are used by targets who wish to join
 *    the Isoch CEC and receive all of the channel event notifications.
 *    When they want to leave target drivers call t1394_leave_isoch_cec().
 *    The t1394_setup_isoch_cec(), as described above, is used to setup the
 *    the isochronous channel and bandwidth and to notify all member targets
 *    of the allocated channel number and speed.  After targets have finished
 *    using the isoch channel, the resources can be torn down with a call to
 *    t1394_teardown_isoch_cec().
 *    Additionally, the t1394_start_isoch_cec() and t1394_stop_isoch_cec()
 *    routines can be used by member targets to coordinate additional events,
 *    such as the starting and stopping of isochronous DMA or other resources.
 */
int t1394_alloc_isoch_single(t1394_handle_t t1394_hdl,
    t1394_isoch_singleinfo_t *sii, uint_t flags,
    t1394_isoch_single_out_t *output_args,
    t1394_isoch_single_handle_t *t1394_single_hdl, int *result);

void t1394_free_isoch_single(t1394_handle_t t1394_hdl,
    t1394_isoch_single_handle_t *t1394_single_hdl, uint_t flags);

int t1394_alloc_isoch_cec(t1394_handle_t t1394_hdl,
    t1394_isoch_cec_props_t *props, uint_t flags,
    t1394_isoch_cec_handle_t *t1394_isoch_cec_hdl);

int t1394_free_isoch_cec(t1394_handle_t t1394_hdl, uint_t flags,
    t1394_isoch_cec_handle_t *t1394_isoch_cec_hdl);

int t1394_join_isoch_cec(t1394_handle_t t1394_hdl,
    t1394_isoch_cec_handle_t t1394_isoch_cec_hdl, uint_t flags,
    t1394_join_isochinfo_t *join_isoch_info);

int t1394_leave_isoch_cec(t1394_handle_t t1394_hdl,
    t1394_isoch_cec_handle_t t1394_isoch_cec_hdl, uint_t flags);

int t1394_setup_isoch_cec(t1394_handle_t t1394_hdl,
    t1394_isoch_cec_handle_t t1394_isoch_cec_hdl, uint_t flags, int *result);

/* Results codes returned by t1394_setup_isoch_cec() */
#define	T1394_ENO_BANDWIDTH	(-500)
#define	T1394_ENO_CHANNEL	(-501)
#define	T1394_ETARGET		(-502)
#define	T1394_CEC_ERR_FIRST	T1394_ENO_BANDWIDTH
#define	T1394_CEC_ERR_LAST	T1394_ETARGET
/*
 * NOTE: Make sure T1394_ERR_LAST is updated if a new error code is
 * added. t1394_errmsg.c uses *FIRST and *LAST as bounds checks.
 */

int t1394_start_isoch_cec(t1394_handle_t t1394_hdl,
    t1394_isoch_cec_handle_t t1394_isoch_cec_hdl, uint_t flags);

int t1394_stop_isoch_cec(t1394_handle_t t1394_hdl,
    t1394_isoch_cec_handle_t t1394_isoch_cec_hdl, uint_t flags);

int t1394_teardown_isoch_cec(t1394_handle_t t1394_hdl,
    t1394_isoch_cec_handle_t t1394_isoch_cec_hdl, uint_t flags);


/*
 * ISOCHRONOUS DMA (LOCAL ISOCH DMA) SERVICES:
 *    These are the calls into the 1394 Framework used for local
 *    isochronous DMA services. The t1394_alloc_isoch_dma() routine
 *    takes a target handle and an id1394_isoch_dmainfo_t structure
 *    (see id1394.h for details) as its input arguments and returns a
 *    t1394_isoch_dma_handle_t that the target driver will use with all
 *    other local host DMA calls.  After allocating a local host DMA
 *    resource, a target driver may start and stop it as often as desired
 *    using the t1394_start_isoch_dma() and t1394_stop_isoch_dma() calls.
 *    The t1394_start_isoch_dma() takes an id1394_isoch_dma_ctrlinfo_t
 *    structure (also discussed in more detail in id1394.h) as an
 *    additional argument to indicate among other things the conditions
 *    under which the host DMA will be started.
 *    The t1394_free_isoch_dma() is used, not surprisingly, to free up
 *    allocate isoch DMA resources.
 *    And the t1394_update_isoch_dma() routine is used to update a running
 *    isochronous stream.  By creating and passing a temporary IXL command
 *    or set of commands and both the kernel virtual addresses of the
 *    temporary and original commands, a target driver can request that the
 *    1394 Framework replace the original field contents with those in the
 *    temporary command and update the corresponding hardware DMA elements.
 */
int t1394_alloc_isoch_dma(t1394_handle_t t1394_hdl,
    id1394_isoch_dmainfo_t *idi, uint_t flags,
    t1394_isoch_dma_handle_t *t1394_idma_hdl, int *result);

/*
 * Results codes returned by t1394_alloc_isoch_dma(). See ixl1394.h for possible
 * IXL1394 compilation errors.
 * NOTE: Make sure T1394_IDMA_ERR_LAST is updated if a new error code is
 * added.
 */
#define	T1394_EIDMA_NO_RESRCS	(-600)
#define	T1394_EIDMA_CONFLICT	(-601)
#define	T1394_IDMA_ERR_FIRST	T1394_EIDMA_NO_RESRCS
#define	T1394_IDMA_ERR_LAST	T1394_EIDMA_CONFLICT

void t1394_free_isoch_dma(t1394_handle_t t1394_hdl, uint_t flags,
    t1394_isoch_dma_handle_t *t1394_idma_hdl);

int t1394_start_isoch_dma(t1394_handle_t t1394_hdl,
    t1394_isoch_dma_handle_t t1394_idma_hdl,
    id1394_isoch_dma_ctrlinfo_t *idma_ctrlinfo, uint_t flags, int *result);

void t1394_stop_isoch_dma(t1394_handle_t t1394_hdl,
    t1394_isoch_dma_handle_t t1394_idma_hdl, uint_t flags);

/* See ixl1394.h for possible IXL1394 t1394_update_isoch_dma() errors. */
int t1394_update_isoch_dma(t1394_handle_t t1394_hdl,
    t1394_isoch_dma_handle_t t1394_idma_hdl,
    id1394_isoch_dma_updateinfo_t *idma_updateinfo, uint_t flags, int *result);


/*
 * MISCELLANEOUS SERVICES:
 *    These are the calls into the 1394 Framework used for miscellaneous
 *    services, including getting target information and topology map,
 *    adding to and removing from local Config ROM, initiating bus resets,
 *    etc.  The t1394_get_targetinfo() routine is used to get information
 *    about the target driver's device and about current bus conditions
 *    that might be useful to a target.  By passing the target handle and
 *    current bus generation, a target driver can expect to receive a filled
 *    in t1394_targetinfo_t structure (see above) that contains the
 *    current_max_payload, current_max_speed, and device's nodeID.
 *    The t1394_initiate_bus_reset() routine can be used by target drivers
 *    to initiate a bus reset.  This call should be used only when it is
 *    absolutely imperative, however, as bus resets affect all devices on
 *    the 1394 Serial Bus and excessive use of bus resets can have an
 *    adverse effect on overall bus performance.
 *    The t1394_get_topology_map() will return the TOPOLOGY_MAP (see
 *    IEEE 1394-1995, Section 8.3.2.4.1) which is a list of SelfID packets
 *    from the current bus generation.
 *    The t1394_CRC16() call is used to calculate cyclic redundancy checks
 *    (CRCs) necessary for use in Config ROM buffers.
 *    The t1394_add_cfgrom_entry() and t1394_rem_cfgrom_entry() calls are
 *    used, respectively, to add and remove entries from the local host
 *    Config ROM buffer.  (See above for a description of the
 *    t1394_cfgrom_entryinfo_t structure.)
 *    And the t1394_errmsg() routine is used to convert result codes which
 *    have been returned by the 1394 Framework into character strings for
 *    use in error messages.
 */
int t1394_get_targetinfo(t1394_handle_t t1394_hdl, uint_t bus_generation,
    uint_t flags, t1394_targetinfo_t *targetinfo);

void t1394_initiate_bus_reset(t1394_handle_t t1394_hdl, uint_t flags);

int t1394_get_topology_map(t1394_handle_t t1394_hdl, uint_t bus_generation,
    size_t tm_length, uint_t flags, uint32_t *tm_buffer);

uint_t t1394_CRC16(uint32_t *d, size_t crc_length, uint_t flags);

int t1394_add_cfgrom_entry(t1394_handle_t t1394_hdl,
    t1394_cfgrom_entryinfo_t *cfgrom_entryinfo, uint_t flags,
    t1394_cfgrom_handle_t *t1394_cfgrom_hdl, int *result);
/* Results codes returned by t1394_add_cfgrom_entry() */
#define	T1394_ECFGROM_FULL		(-700)
#define	T1394_EINVALID_PARAM		(-701)
#define	T1394_EINVALID_CONTEXT		(-702)
#define	T1394_NOERROR			(-703)
#define	T1394_ECFG_FIRST		T1394_ECFGROM_FULL
#define	T1394_ECFG_LAST			T1394_NOERROR
/*
 * NOTE: Make sure T1394_ECFG_LAST is updated if a new error code is
 * added. t1394_errmsg.c uses *FIRST and *LAST as bounds checks.
 */

int t1394_rem_cfgrom_entry(t1394_handle_t t1394_hdl, uint_t flags,
    t1394_cfgrom_handle_t *t1394_cfgrom_hdl, int *result);

const char *t1394_errmsg(int result, uint_t flags);

#ifdef __cplusplus
}
#endif

#endif	/* _SYS_1394_T1394_H */
