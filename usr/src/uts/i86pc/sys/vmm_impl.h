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
 * Copyright 2014 Pluribus Networks Inc.
 * Copyright 2018 Joyent, Inc.
 */

#ifndef _VMM_IMPL_H_
#define	_VMM_IMPL_H_

#include <sys/mutex.h>
#include <sys/queue.h>
#include <sys/varargs.h>
#include <sys/zone.h>

/*
 * /dev names:
 *      /dev/vmmctl         - control device
 *      /dev/vmm/<name>     - vm devices
 */
#define	VMM_DRIVER_NAME		"vmm"
#define	VMM_CTL_MINOR_NODE	"ctl"
#define	VMM_CTL_MINOR		0

#ifdef	_KERNEL

/*
 * Rather than creating whole character devices for devmem mappings, they are
 * available by mmap(2)ing the vmm handle at a specific offset.  These offsets
 * begin just above the maximum allow guest physical address.
 */
#include <vm/vm_param.h>
#define	VM_DEVMEM_START	(VM_MAXUSER_ADDRESS + 1)

struct vmm_devmem_entry {
	list_node_t	vde_node;
	int		vde_segid;
	char		vde_name[SPECNAMELEN + 1];
	size_t		vde_len;
	off_t		vde_off;
};
typedef struct vmm_devmem_entry vmm_devmem_entry_t;

typedef struct vmm_zsd vmm_zsd_t;

enum vmm_softc_state {
	VMM_HELD	= 1,	/* external driver(s) possess hold on VM */
	VMM_CLEANUP	= 2,	/* request that holds are released */
	VMM_PURGED	= 4,	/* all hold have been released */
	VMM_BLOCK_HOOK	= 8	/* mem hook install temporarily blocked */
};

struct vmm_softc {
	list_node_t	vmm_node;
	struct vm	*vmm_vm;
	minor_t		vmm_minor;
	char		vmm_name[VM_MAX_NAMELEN];
	uint_t		vmm_flags;
	boolean_t	vmm_is_open;
	list_t		vmm_devmem_list;
	list_t		vmm_holds;
	kcondvar_t	vmm_cv;

	/* For zone specific data */
	list_node_t	vmm_zsd_linkage;
	zone_t		*vmm_zone;
	vmm_zsd_t	*vmm_zsd;
};
typedef struct vmm_softc vmm_softc_t;

void vmm_zsd_init(void);
void vmm_zsd_fini(void);
int vmm_zsd_add_vm(vmm_softc_t *sc);
void vmm_zsd_rem_vm(vmm_softc_t *sc);
int vmm_do_vm_destroy(vmm_softc_t *, boolean_t);

#endif /* _KERNEL */

/*
 * VMM trace ring buffer constants
 */
#define	VMM_DMSG_RING_SIZE		0x100000	/* 1MB */
#define	VMM_DMSG_BUF_SIZE		256

/*
 * VMM trace ring buffer content
 */
typedef struct vmm_trace_dmsg {
	timespec_t		timestamp;
	char			buf[VMM_DMSG_BUF_SIZE];
	struct vmm_trace_dmsg	*next;
} vmm_trace_dmsg_t;

/*
 * VMM trace ring buffer header
 */
typedef struct vmm_trace_rbuf {
	kmutex_t		lock;		/* lock to avoid clutter */
	int			looped;		/* completed ring */
	int			allocfailed;	/* dmsg mem alloc failed */
	size_t			size;		/* current size */
	size_t			maxsize;	/* max size */
	vmm_trace_dmsg_t	*dmsgh;		/* messages head */
	vmm_trace_dmsg_t	*dmsgp;		/* ptr to last message */
} vmm_trace_rbuf_t;

/*
 * VMM trace ring buffer interfaces
 */
void vmm_trace_log(const char *fmt, ...);

#endif	/* _VMM_IMPL_H_ */
