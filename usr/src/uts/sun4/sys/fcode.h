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
 * Copyright 2005 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef	_SYS_FCODE_H
#define	_SYS_FCODE_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <sys/sysmacros.h>
#include <sys/ddi.h>
#include <sys/sunddi.h>
#include <sys/fc_plat.h>
#include <sys/pci.h>

#ifdef	__cplusplus
extern "C" {
#endif

/*
 * The FCode driver presents a private interface to the fcode
 * user level interpreter.  This interface is subject to change
 * at any time and is only provided for use by the fcode interpreter.
 *
 * The user program opens the device, causing a new instance of
 * the driver to be cloned.  This instance is specific to a specific
 * instance of a new device managed by the kernel and driver framework.
 *
 * The interpreter does an FC_GET_PARAMETERS ioctl to get the fcode
 * length, which can be mmap-ed (at offset 0) to provide access to a copy
 * of the device's fcode.
 *
 * The interpreter uses the FC_RUN_PRIV ioctl to request privileged
 * operations to be run by the driver.
 *
 * The interpreter sends an FC_VALIDATE ioctl to notify the
 * driver that it's done interpreting FCode to signify a normal
 * ending sequence when the interpreter later closes the device.
 * This way the driver can easily distinguish between the user
 * level interpreter failing and finishing normally, thus validating
 * the interpreters actions and the state it downloads to the driver.
 * The 'arg' value in the FC_VALIDATE ioctl is ignored, there
 * are no arguments to this ioctl.
 */

#define	FCIOC			(0xfc<<8)
#define	FC_GET_PARAMETERS	(FCIOC | 1)
#define	FC_RUN_PRIV		(FCIOC | 2)
#define	FC_VALIDATE		(FCIOC | 3)
#define	FC_GET_MY_ARGS		(FCIOC | 4)
#define	FC_GET_FCODE_DATA	(FCIOC | 5)
#define	FC_SET_FCODE_ERROR	(FCIOC | 6)

#define	FC_GET_MY_ARGS_BUFLEN	256	/* Max my-args length */

/*
 * FC_GET_PARAMETERS: Expected as the first ioctl after a successful
 * open and blocking read (the read returns 0 when there's something
 * to interpret).  The ioctl arg is a pointer to an fc_parameters
 * data structure which is filled in by the driver with the fcode
 * len (if any) and unit address of the new device.
 * Offset 0 .. fcode len may be used as the offset to an mmap call to
 * provide access to a copy of the device fcode. The unit address is
 * returned as a NULL terminated string.
 */

struct fc_parameters {
	int32_t	fcode_size;
	char	unit_address[OBP_MAXPATHLEN];
	int	config_address;
};



/*
 * FC_RUN_PRIV: The ioctl 'arg' is a pointer to an array of fc_cell_t's
 * in the following format:
 *
 * fc_cell_t[0]: Pointer to a NULL terminated string: service name
 * fc_cell_t[1]: Number of input arguments (Call this value 'A')
 * fc_cell_t[2]: Number of output result cells allocated (Call this val 'R')
 * fc_cell_t[3]: Error Cell (See below)
 * fc_cell_t[4]: Priv Violation Cell (non-zero if priv. violation)
 * fc_cell_t[5]: Argument cell[0] (Possibly none)
 * fc_cell_t[5 + 'A']: Result cell[0] (Possibly none)
 *
 * The array is variable sized, and must contain a minimum of 5 fc_cell_t's.
 * The size (in fc_cell_t's) is 5 + 'A' + 'R'.
 *
 * The argument cells are filled in by the caller.  The result cells
 * (if any) and error cell are returned to the caller by the driver.
 * The error cell and priv violation cell are filled in and returned
 * to the caller by the driver.
 *
 * Error Cell Values:
 *
 *	-1:	The call itself failed (the service name was unknown).
 *
 *	0:	No error (though the result cells may indicate results
 *		that signify an error consistent with the service request.)
 *
 * Priv Violation Cell Values:
 *
 *	0:	No priv violation
 *
 *	-1:	Executing the request caused a priv. violation.
 *		For example, an rl@ from an address not mapped in
 *		by the interpreter.
 */

#define	FC_ERR_NONE	fc_int2cell(0)
#define	FC_ERR_SVC_NAME	fc_int2cell(-1)

#define	FC_PRIV_OK	fc_intcell(0)
#define	FC_PRIV_ERROR	fc_int2cell(-1)

/*
 * Client interface template:
 * The actual number of arguments is nargs.
 * The actual number of results is nresults.
 * The variable array 'v' contains 'nargs + nresults' elements
 */
struct fc_client_interface {
	fc_cell_t	svc_name;
	fc_cell_t	nargs;
	fc_cell_t	nresults;
	fc_cell_t	error;
	fc_cell_t	priv_error;
	fc_cell_t	v[1];	/* variable array of args and results */
};

typedef	struct fc_client_interface fc_ci_t;

#define	fc_arg(cp, i)		(cp->v[(i)])
#define	fc_result(cp, i)	(cp->v[fc_cell2int(cp->nargs) + (i)])

#define	FCC_FIXED_CELLS			5

/*
 * FC_GET_FCODE_DATA: This ioctl allows userland portion of the fcode
 * interpreter to get the fcode into a local buffer without having
 * to use mmap() interface (which calls hat_getkpfnum() routine).
 * This allows DR kernel cage memory to be relocated while this
 * fcode buffer is allocated.
 *
 * The ioctl arg is a pointer to an fc_fcode_info structure which
 * has the fcode_size field set with the expected fcode length.
 * The driver uses this field to validate correct size before using
 * copyout() to fill in the fcode_ptr buffer with fcode data.
 */
typedef struct fc_fcode_info {
	int32_t	fcode_size;
	char	*fcode_ptr;
} fc_fcode_info_t;

/*
 * The service name len (max) is limited by the size of a method name
 */
#define	FC_SVC_NAME_LEN		OBP_MAXPROPNAME

/*
 * "Internally" generated service names ...
 */
#define	FC_SVC_VALIDATE		"sunos,validate"
#define	FC_SVC_INVALIDATE	"sunos,invalidate"
#define	FC_SVC_EXIT		"sunos,exit"

#define	FC_OPEN_METHOD		"open"
#define	FC_CLOSE_METHOD		"close"
#define	FC_FIND_FCODE		"$find"

/*
 * Property related group:
 *
 * sunos,get*proplen ( propname-cstr phandle -- proplen )
 * sunos,get*prop ( propname-cstr buf phandle -- proplen )
 *
 * sunos,property ( propname-cstr buf len phandle -- )
 */

#define	FC_GET_MY_PROPLEN	"sunos,get-my-proplen"
#define	FC_GET_MY_PROP		"sunos,get-my-prop"

#define	FC_GET_IN_PROPLEN	"sunos,get-inherited-proplen"
#define	FC_GET_IN_PROP		"sunos,get-inherited-prop"

#define	FC_GET_PKG_PROPLEN	"sunos,get-package-proplen"
#define	FC_GET_PKG_PROP		"sunos,get-package-prop"

#define	FC_CREATE_PROPERTY	"sunos,property"

/*
 * Register access and dma ... same as 1275
 *
 * dma-map-in maps in a suitable aligned user address.
 */
#define	FC_RL_FETCH		"rl@"
#define	FC_RW_FETCH		"rw@"
#define	FC_RB_FETCH		"rb@"

#define	FC_RL_STORE		"rl!"
#define	FC_RW_STORE		"rw!"
#define	FC_RB_STORE		"rb!"

#define	FC_MAP_IN		"map-in"
#define	FC_MAP_OUT		"map-out"
#define	FC_DMA_MAP_IN		"dma-map-in"
#define	FC_DMA_MAP_OUT		"dma-map-out"

/*
 * PCI configuration space access methods ... same as pci binding
 */
#define	FC_PCI_CFG_L_FETCH	"config-l@"
#define	FC_PCI_CFG_W_FETCH	"config-w@"
#define	FC_PCI_CFG_B_FETCH	"config-b@"

#define	FC_PCI_CFG_L_STORE	"config-l!"
#define	FC_PCI_CFG_W_STORE	"config-w!"
#define	FC_PCI_CFG_B_STORE	"config-b!"

/*
 * Device node creation ...
 *
 * Create a new device with the given name, unit-address, parent.phandle
 * with a phandle that must have been previously allocated using
 * sunos,alloc-phandle.  finish-device marks the device creation and
 * the creation of its properties as complete. (It's a signal to the
 * the OS that the node is now reasonably complete.)
 *
 * sunos,new-device ( name-cstr unit-addr-cstr parent.phandle phandle -- )
 * finish-device ( phandle  -- )
 */
#define	FC_NEW_DEVICE		"sunos,new-device"
#define	FC_FINISH_DEVICE	"sunos,finish-device"

/*
 * Navigation and configuration:
 *
 * sunos,probe-address ( -- phys.lo ... )
 * sunos,probe-space ( -- phys.hi )
 *
 * sunos,ap-phandle ( -- ap.phandle )
 *	Return attachment point phandle
 *
 * sunos,parent ( child.phandle -- parent.phandle )
 *
 * child ( parent.phandle -- child.phandle )
 * peer ( phandle -- phandle.sibling )
 *
 * sunos,alloc-phandle ( -- phandle )
 * Allocates a unique phandle, not associated with the device tree
 *
 * sunos,config-child ( -- child.phandle )
 * Return the phandle of the child being configured.
 */

#define	FC_PROBE_ADDRESS	"sunos,probe-address"
#define	FC_PROBE_SPACE		"sunos,probe-space"
#define	FC_AP_PHANDLE		"sunos,ap-phandle"
#define	FC_PARENT		"sunos,parent"
#define	FC_CHILD_FCODE		"child"
#define	FC_PEER_FCODE		"peer"
#define	FC_ALLOC_PHANDLE	"sunos,alloc-phandle"
#define	FC_CONFIG_CHILD		"sunos,config-child"

/*
 * Fcode Drop In Routines:
 * sunos,get_fcode_size ( cstr -- len )
 * Returns the size in bytes of the Fcode for a given drop in.
 * sunos,get_fcode (cstr buf len -- status? )
 * Returns the Fcode image for a given drop in.
 */
#define	FC_GET_FCODE_SIZE	"sunos,get-fcode-size"
#define	FC_GET_FCODE		"sunos,get-fcode"

/*
 * Values for fc_request 'error'. This has been moved from the _KERNEL
 * area to allow the FC_SET_FCODE_ERROR ioctl to use these values to
 * signal the kernel as to the disposition of the userland interpreter.
 * NOTE: Positive values are used to indicate a kernel error,
 * negative values are used to identify userland interpreter errors.
 */
#define	FC_SUCCESS	0		/* FCode interpreted successfully */
#define	FC_TIMEOUT	1		/* Timer expired */
#define	FC_ERROR	-1		/* Interpreter error */
#define	FC_EXEC_FAILED	-2		/* Interpreter failed to exec */
#define	FC_NO_FCODE	-3		/* Interpreter couldn't find fcode */
#define	FC_FCODE_ABORT	-4		/* Interpreter called exit(1) */
#define	FC_ERROR_VALID(s) ((s) >= FC_FCODE_ABORT) && ((s) <= FC_TIMEOUT)

/*
 * kernel internal data structures and interfaces
 * for the fcode interpreter.
 */
#if defined(_KERNEL)

/*
 * PCI bus-specific arguments.
 *
 * We can't get the physical config address of the child from the
 * unit address, so we supply it here, along with the child's dip
 * as the bus specific argument to pci_ops_alloc_handle.
 */

struct pci_ops_bus_args {
	int32_t config_address;		/* phys.hi config addr component */
};

/*
 * Define data structures for resource lists and handle management
 *
 * 'untyped' resources are managed by the provider.
 */
struct fc_dma_resource {
	void *virt;
	size_t len;
	ddi_dma_handle_t h;
	uint32_t devaddr;
	struct buf *bp;
};

struct fc_map_resource {
	void *virt;
	size_t len;
	ddi_acc_handle_t h;
	void *regspec;
};

struct fc_nodeid_resource {
	int nodeid;		/* An allocated nodeid */
};

struct fc_contigious_resource {
	void *virt;
	size_t len;
};
struct fc_untyped_resource {
	int utype;		/* providers private type field */
	void (*free)(void *);	/* function to free the resource */
	void *resource;		/* Pointer to the resource */
};

typedef enum {
	RT_DMA = 0,
	RT_MAP,
	RT_NODEID,
	RT_CONTIGIOUS,
	RT_UNTYPED
} fc_resource_type_t;

struct fc_resource {
	struct fc_resource *next;
	fc_resource_type_t type;
	union {
		struct fc_dma_resource d;
		struct fc_map_resource m;
		struct fc_nodeid_resource n;
		struct fc_contigious_resource c;
		struct fc_untyped_resource r;
	} un;
};

#define	fc_dma_virt	un.d.virt
#define	fc_dma_len	un.d.len
#define	fc_dma_handle	un.d.h
#define	fc_dma_devaddr	un.d.devaddr
#define	fc_dma_bp	un.d.bp

#define	fc_map_virt	un.m.virt
#define	fc_map_len	un.m.len
#define	fc_map_handle	un.m.h
#define	fc_regspec	un.m.regspec

#define	fc_nodeid_r	un.n.nodeid

#define	fc_contig_virt	un.c.virt
#define	fc_contig_len	un.c.len

#define	fc_untyped_type	un.r.utype
#define	fc_untyped_free	un.r.free
#define	fc_untyped_r	un.r.resource

struct fc_phandle_entry {
	struct fc_phandle_entry *next;
	dev_info_t	*dip;
	fc_phandle_t	h;
};

extern void fc_phandle_table_alloc(struct fc_phandle_entry **);
extern void fc_phandle_table_free(struct fc_phandle_entry **);
extern dev_info_t *fc_phandle_to_dip(struct fc_phandle_entry **, fc_phandle_t);
extern fc_phandle_t fc_dip_to_phandle(struct fc_phandle_entry **, dev_info_t *);
extern void fc_add_dip_to_phandle(struct fc_phandle_entry **, dev_info_t *,
    fc_phandle_t);

/*
 * Structures and functions for managing our own subtree rooted
 * at the attachment point. The parent linkage is established
 * at node creation time.  The 'downwards' linkage isn't established
 * until the node is bound.
 */
struct fc_device_tree {
	dev_info_t *dip;
	struct fc_device_tree *child;
	struct fc_device_tree *peer;
};

void fc_add_child(dev_info_t *child, dev_info_t *parent,
    struct fc_device_tree *head);

void fc_remove_child(dev_info_t *child, struct fc_device_tree *head);

dev_info_t *fc_child_node(dev_info_t *parent, struct fc_device_tree *head);
dev_info_t *fc_peer_node(dev_info_t *devi, struct fc_device_tree *head);
struct fc_device_tree *fc_find_node(dev_info_t *, struct fc_device_tree *);

void fc_create_device_tree(dev_info_t *ap, struct fc_device_tree **head);
void fc_remove_device_tree(struct fc_device_tree **head);

/*
 * Our handles represent a list of resources associated with an
 * attachment point.  The handles chain, just as the ops functions
 * do, with the ops caller responsible for remembering the handle
 * of the ops function below it. NB: Externally, this data structure
 * is opaque. (Not all members may be present in each chained cookie.)
 * For example, the dtree head is valid in only a single instance
 * of a set of chained cookies, so use the access function to find it.)
 */
struct fc_resource_list {
	struct fc_resource *head;
	void *next_handle;		/* next handle in chain */
	dev_info_t *ap;			/* Attachment point dip */
	dev_info_t *child;		/* Child being configured, if any */
	dev_info_t *cdip;		/* Current node, if any */
	int cdip_state;			/* node creation state - see below */
	void *fcode;			/* fcode kernel address */
	size_t fcode_size;		/* fcode size or zero */
	char *unit_address;		/* childs unit address */
	char *my_args;			/* initial setting for my-args */
	void *bus_args;			/* bus dependent arguments */
	struct fc_phandle_entry *ptable; /* devinfo/phandle table */
	struct fc_device_tree *dtree;	/* Our subtree (leaf cookie only) */
};

typedef struct fc_resource_list *fco_handle_t;

/*
 * Values for cdip_state:
 */
#define	FC_CDIP_NOSTATE		0x00	/* No state - no nodes created */
#define	FC_CDIP_STARTED		0x01	/* Node started - dip in cdip */
#define	FC_CDIP_DONE		0x02	/* Node finished - last dip in cdip */
#define	FC_CDIP_CONFIG		0x10	/* subtree configured */

/*
 * Functions to allocate handles for the fcode_interpreter.
 *
 * This function allocates a handle, used to store resources
 * associated with this fcode request including the address of
 * the mapped in and copied in fcode and it's size or NULL, 0
 * if there is no fcode (the interpreter may look for a drop-in
 * driver if there is no fcode), the unit address of child and
 * bus specific arguments.  For PCI, the bus specific arguments
 * include the child's prototype dip and the config address of
 * the child, which can't be derived from the unit address.
 *
 * The 'handle' returned also contains resource information
 * about any allocations of kernel resources that the fcode
 * may have created.  Thus, the handle's life is the life
 * of the plug-in card and can't be released until the card
 * is removed.  Upon release, the resources are released.
 */
extern fco_handle_t
fc_ops_alloc_handle(dev_info_t *ap, dev_info_t *config_child,
    void *fcode, size_t fcode_size, char *unit_address, void *bus_args);

extern fco_handle_t
pci_fc_ops_alloc_handle(dev_info_t *ap, dev_info_t *config_child,
    void *fcode, size_t fcode_size, char *unit_address,
    struct pci_ops_bus_args *bus_args);

extern fco_handle_t
gp2_fc_ops_alloc_handle(dev_info_t *ap, dev_info_t *config_child,
    void *fcode, size_t fcode_size, char *unit_address,
    char *my_args);

extern void pci_fc_ops_free_handle(fco_handle_t handle);
extern void gp2_fc_ops_free_handle(fco_handle_t handle);
extern void fc_ops_free_handle(fco_handle_t handle);

extern struct fc_phandle_entry **fc_handle_to_phandle_head(fco_handle_t rp);

struct fc_device_tree **fc_handle_to_dtree_head(fco_handle_t);
struct fc_device_tree *fc_handle_to_dtree(fco_handle_t);

/*
 * fc_ops_t is the main glue back to the framework and attachment point driver
 * for privileged driver operations.  The framework/driver provides a pointer
 * to the fc_ops function to handle the request given in the args.  The dip
 * and handle are passed back to the framework/driver to distinguish
 * requests, if necessary.  The argument array is an array of fc_cell_t's
 * and is defined in fcode.h
 *
 * The ops function should return -1 to indicate that the service name is
 * unknown and return the value 0 to indicate that the service name was known
 * and processed (even if it failed).  ops functions may chain, using the
 * return code to communicate if the current function handled the service
 * request. Using this technique, the driver can provide certain ops functions
 * and allow a framework ops function to handle standardized ops functions,
 * or work hand in hand with a framework function so both can handle an op.
 * If an ops function is not handled, thus returning -1 to the driver, the
 * driver will log an error noting the name of the service and return the
 * error to the caller.
 */
typedef int (fc_ops_t)(dev_info_t *, fco_handle_t, fc_ci_t *);

extern fc_ops_t fc_ops;
extern fc_ops_t pci_fc_ops;
extern fc_ops_t gp2_fc_ops;

/*
 * Internal structure used to enque an fcode request
 * The 'next' and 'busy' fields are protected by a mutex.
 * Thread synchronization is accomplished via use of the 'busy' field.
 */
struct fc_request {
	struct fc_request *next;	/* Next in chain (private) */
	int		busy;		/* Waiters flag (private; see below) */
	int		error;		/* Interpreter return code (private) */
	dev_info_t	*ap_dip;	/* Attachment point. ie: pci nexus */
	fc_ops_t	*ap_ops;	/* driver's fcode ops function */
	fco_handle_t	handle;		/* Caller's private identifier */
	timeout_id_t	timeout;	/* Timeout identifier */
};

/*
 * Values for 'busy'.  The requester initializes the field to FC_R_INIT (0),
 * then waits for it be set to FC_R_DONE.  The framework sets it to
 * FC_R_BUSY while working on the request so it can distinguish between
 * an inactive and an active request.
 */
#define	FC_R_INIT	0		/* initialized, on queue */
#define	FC_R_BUSY	1		/* request is active, busy */
#define	FC_R_DONE	2		/* request is done and may be deq'd */

/*
 * Function to call to invoke the fcode interpreter.
 *
 * This function will wait and return when the interpreter either
 * completes successfully or fails, returning pass/fail status as
 * the return code.  Interim calls to the driver's ops function will
 * be made for both priv. ops and to create device nodes and properties.
 *
 * Calling this function will log a message to userland to request the
 * eventd to start the userland fcode interpreter process. The interpreter
 * opens /dev/fcode, which clones an instance of the driver, and then
 * waits in a 'read' until there's an active request.
 * XXX: For the prototype, we can start it manually or use an init.d script.
 *
 * 'ap' is the attachment point dip: that is, the driving parent's dev_info_t
 * ie: for pci devices, this will be the dip of the pci nexus.
 *
 * The 'handle' is provided for the caller, and can be used to
 * identify the request along with the attachment point dip, both
 * of which will be passed back to the driver's ops function.
 * The handle is allocated first by calling a bus-specific
 * <bus>_ops_handle_alloc function.
 *
 * ops functions may chain; an ops function should return -1 if
 * the call was not recognized, or 0 if the call was recognized.
 */
extern int fcode_interpreter(dev_info_t *, fc_ops_t *, fco_handle_t);

/*
 * The fcode implementation uses this function to wait for and 'de-queue'
 * an fcode request.  It's triggered by a 'read' request from the
 * userland interpreter. It uses a 'sig' form of waiting (cv_wait_sig),
 * so the interpreter can interrupt the read.
 */
extern struct fc_request *fc_get_request(void);

/*
 * When the fcode implementation is finished servicing a request, it calls this
 * function to mark the request as done and to signal the originating thread
 * (now waiting in fcode_interpreter) that the request is done.
 */
extern void fc_finish_request(struct fc_request *);

/*
 * The fcode implementation uses these functions to manage
 * resource items and resource lists ...
 */
extern void fc_add_resource(fco_handle_t, struct fc_resource *);
extern void fc_rem_resource(fco_handle_t, struct fc_resource *);
extern void fc_lock_resource_list(fco_handle_t);
extern void fc_unlock_resource_list(fco_handle_t);

/*
 * ops common and helper functions
 */
extern int fc_fail_op(dev_info_t *, fco_handle_t, fc_ci_t *);
extern int fc_success_op(dev_info_t *, fco_handle_t, fc_ci_t *);

extern int fc_syntax_error(fc_ci_t *, char *);
extern int fc_priv_error(fc_ci_t *, char *);

/*
 * Recharacterized ddi functions we need to define ...
 *
 * The only difference is we call through the attachment point driver,
 * as a proxy for the child that isn't yet attached. The ddi functions
 * optimize these functions by not necessarily calling through the
 * attachment point driver.
 */
int fc_ddi_dma_alloc_handle(dev_info_t *dip, ddi_dma_attr_t *attr,
    int (*waitfp)(caddr_t), caddr_t arg, ddi_dma_handle_t *handlep);
int fc_ddi_dma_buf_bind_handle(ddi_dma_handle_t handle, struct buf *bp,
    uint_t flags, int (*waitfp)(caddr_t), caddr_t arg,
    ddi_dma_cookie_t *cookiep, uint_t *ccountp);
int fc_ddi_dma_unbind_handle(ddi_dma_handle_t handle);
void fc_ddi_dma_free_handle(ddi_dma_handle_t *handlep);
int fc_ddi_dma_sync(ddi_dma_handle_t h, off_t o, size_t l, uint_t whom);

/*
 * The ndi prop functions aren't appropriate for the interpreter.
 * We create byte-array, untyped properties.
 */

int fc_ndi_prop_update(dev_t, dev_info_t *, char *, uchar_t *, uint_t);

/*
 * The setup and teardown parts of physio()
 */
int fc_physio_setup(struct buf **bpp, void *io_base, size_t io_len);
void fc_physio_free(struct buf **bpp, void *io_base, size_t io_len);

/*
 * debugging macros
 */
extern int fcode_debug;
#define	dcmn_err(level, args) if (fcode_debug >= level) cmn_err args

#ifdef DEBUG

void fc_debug(char *, uintptr_t, uintptr_t,
    uintptr_t, uintptr_t, uintptr_t);

#define	FC_DEBUG0(level, flag, s) if (fcode_debug >= level) \
    fc_debug(s, 0, 0, 0, 0, 0)
#define	FC_DEBUG1(level, flag, fmt, a1) if (fcode_debug >= level) \
    fc_debug(fmt, (uintptr_t)(a1), 0, 0, 0, 0);
#define	FC_DEBUG2(level, flag, fmt, a1, a2) if (fcode_debug >= level) \
    fc_debug(fmt, (uintptr_t)(a1), (uintptr_t)(a2), 0, 0, 0);
#define	FC_DEBUG3(level, flag, fmt, a1, a2, a3) \
    if (fcode_debug >= level) \
    fc_debug(fmt, (uintptr_t)(a1), (uintptr_t)(a2), (uintptr_t)(a3), 0, 0);
#else
#define	FC_DEBUG0(level, flag, s)
#define	FC_DEBUG1(level, flag, fmt, a1)
#define	FC_DEBUG2(level, flag, fmt, a1, a2)
#define	FC_DEBUG3(level, flag, fmt, a1, a2, a3)
#endif


#endif	/* defined(_KERNEL) */

#ifdef	__cplusplus
}
#endif

#endif	/* _SYS_FCODE_H */
