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
 * Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*
 * The door lightweight RPC I/F.
 */

#ifndef	_SYS_DOOR_H
#define	_SYS_DOOR_H

#ifdef	__cplusplus
extern "C" {
#endif

/*
 * Attributes associated with doors.
 */

/* Attributes originally obtained from door_create operation */
#define	DOOR_UNREF	0x01	/* Deliver an unref notification with door */
#define	DOOR_PRIVATE	0x02	/* Use a private pool of server threads */
#define	DOOR_UNREF_MULTI 0x10	/* Deliver unref notification more than once */
#define	DOOR_REFUSE_DESC 0x40	/* Do not accept descriptors from callers */
#define	DOOR_NO_CANCEL	0x80	/* No server thread cancel on client abort */
#define	DOOR_NO_DEPLETION_CB 0x100 /* No thread create callbacks on depletion */

/* Attributes (additional) returned with door_info and door_desc_t data */
#define	DOOR_LOCAL	0x04	/* Descriptor is local to current process */
#define	DOOR_REVOKED	0x08	/* Door has been revoked */
#define	DOOR_IS_UNREF	0x20	/* Door is currently unreferenced */
#define	DOOR_PRIVCREATE	0x200	/* Door has a private thread creation func */
#define	DOOR_DEPLETION_CB 0x400	/* Set only during depletion callbacks */

#if !defined(_ASM)

#include <sys/types.h>

#if defined(_KERNEL)
#include <sys/mutex.h>
#include <sys/vnode.h>
#include <sys/door_impl.h>
#endif /* defined(_KERNEL) */

/* Basic door type information */
typedef unsigned long long door_ptr_t;	/* Handle 64 bit pointers */
typedef unsigned long long door_id_t;	/* Unique door identifier */
typedef	unsigned int	   door_attr_t;	/* Door attributes */

#ifdef _KERNEL
struct __door_handle;
typedef struct __door_handle *door_handle_t;	/* opaque kernel door handle */
#endif

#define	DOOR_INVAL -1			/* An invalid door descriptor */
#define	DOOR_UNREF_DATA ((void *)1)	/* Unreferenced invocation address */

/* Door descriptor passed to door_info to get current thread's binding */
#define	DOOR_QUERY -2

/* Masks of applicable flags */
#define	DOOR_CREATE_MASK	(DOOR_UNREF | DOOR_PRIVATE | \
	    DOOR_UNREF_MULTI | DOOR_REFUSE_DESC | DOOR_NO_CANCEL | \
	    DOOR_NO_DEPLETION_CB | DOOR_PRIVCREATE)
#define	DOOR_KI_CREATE_MASK	(DOOR_UNREF | DOOR_UNREF_MULTI)

/* Mask of above attributes */
#define	DOOR_ATTR_MASK	(DOOR_CREATE_MASK | \
	    DOOR_LOCAL | DOOR_REVOKED | DOOR_IS_UNREF)

/* Attributes used to describe door_desc_t data */
#define	DOOR_DESCRIPTOR	0x10000	/* A file descriptor is being passed */
#ifdef _KERNEL
#define	DOOR_HANDLE	0x20000 /* A kernel door handle is being passed */
#endif
#define	DOOR_RELEASE	0x40000	/* Passed references are also released */

/* Misc attributes used internally */
#define	DOOR_DELAY	0x80000	/* Delayed unref delivery */
#define	DOOR_UNREF_ACTIVE 0x100000	/* Unreferenced call is active */

/* door parameters */
#define	DOOR_PARAM_DESC_MAX	1	/* max number of request descriptors */
#define	DOOR_PARAM_DATA_MAX	2	/* max bytes of request data */
#define	DOOR_PARAM_DATA_MIN	3	/* min bytes of request data */

/*
 * On AMD64, 32-bit pack door_desc and door_info to avoid needing special
 * copyin/copyout conversions due to differing alignment rules between
 * 32-bit x86 and 64-bit amd64.
 */

#if _LONG_LONG_ALIGNMENT == 8 && _LONG_LONG_ALIGNMENT_32 == 4
#pragma pack(4)
#endif

/*
 * Structure used to pass descriptors/objects in door invocations
 */

typedef struct door_desc {
	door_attr_t	d_attributes;	/* Tag for union */
	union {
		/* File descriptor is passed */
		struct {
			int		d_descriptor;
			door_id_t	d_id;		/* unique id */
		} d_desc;
#ifdef _KERNEL
		/* Kernel passes handles referring to doors */
		door_handle_t d_handle;
#endif
		/* Reserved space */
		int		d_resv[5];
	} d_data;
} door_desc_t;

/*
 * Structure used to return info from door_info
 */
typedef struct door_info {
	pid_t		di_target;	/* Server process */
	door_ptr_t	di_proc;	/* Server procedure */
	door_ptr_t	di_data;	/* Data cookie */
	door_attr_t	di_attributes;	/* Attributes associated with door */
	door_id_t	di_uniquifier;	/* Unique number */
	int		di_resv[4];	/* Future use */
} door_info_t;

#if _LONG_LONG_ALIGNMENT == 8 && _LONG_LONG_ALIGNMENT_32 == 4
#pragma pack()
#endif

/*
 * Structure used to return info from door_cred
 */
typedef struct door_cred {
	uid_t	dc_euid;	/* Effective uid of client */
	gid_t	dc_egid;	/* Effective gid of client */
	uid_t	dc_ruid;	/* Real uid of client */
	gid_t	dc_rgid;	/* Real gid of client */
	pid_t	dc_pid;		/* pid of client */
	int	dc_resv[4];	/* Future use */
} door_cred_t;

/*
 * Structure used to pass/return data from door_call
 *
 * All fields are in/out paramters. Upon return these fields
 * are updated to reflect the true location and size of the results.
 */
typedef struct door_arg {
	char		*data_ptr;	/* Argument/result data */
	size_t		data_size;	/* Argument/result data size */
	door_desc_t	*desc_ptr;	/* Argument/result descriptors */
	uint_t		desc_num;	/* Argument/result num discriptors */
	char		*rbuf;		/* Result area */
	size_t		rsize;		/* Result size */
} door_arg_t;

#if defined(_SYSCALL32)
/*
 * Structure to pass/return data from 32-bit program's door_call.
 */
typedef struct door_arg32 {
	caddr32_t	data_ptr;	/* Argument/result data */
	size32_t	data_size;	/* Argument/result data size */
	caddr32_t	desc_ptr;	/* Argument/result descriptors */
	uint32_t	desc_num;	/* Argument/result num descriptors */
	caddr32_t	rbuf;		/* Result area */
	size32_t	rsize;		/* Result size */
} door_arg32_t;
#endif

/*
 * Structure used to pass door invocation information.
 */
struct door_results {
	void		*cookie;
	char		*data_ptr;
	size_t		data_size;
	door_desc_t	*desc_ptr;
	size_t		desc_num;
	void		(*pc)();
	int		nservers;	/* zero if thread pool is empty */
	door_info_t	*door_info;
};

#if defined(_SYSCALL32)
/*
 * Structure used to pass door invocation information to 32-bit processes.
 */
struct door_results32 {
	caddr32_t	cookie;
	caddr32_t	data_ptr;
	size32_t	data_size;
	caddr32_t	desc_ptr;
	size32_t	desc_num;
	caddr32_t	pc;
	int		nservers;
	caddr32_t	door_info;
};
#endif

/*
 * Structure used to pass a descriptor list to door_return.
 */
typedef struct door_return_desc {
	door_desc_t	*desc_ptr;
	uint_t		desc_num;
} door_return_desc_t;

#if defined(_SYSCALL32)
typedef struct door_return_desc32 {
	caddr32_t	desc_ptr;
	uint_t		desc_num;
} door_return_desc32_t;
#endif

#if defined(_KERNEL)

/*
 * Errors used for doors. Negative numbers to avoid conflicts with errnos
 */
#define	DOOR_WAIT	-1	/* Waiting for response */
#define	DOOR_EXIT	-2	/* Server thread has exited */

#define	VTOD(v)	((struct door_node *)(v->v_data))
#define	DTOV(d) ((d)->door_vnode)

/*
 * Underlying 'filesystem' object definition
 */
typedef struct door_node {
	vnode_t		*door_vnode;
	struct proc 	*door_target;	/* Proc handling this doors invoc's. */
	struct door_node *door_list;	/* List of active doors in proc */
	struct door_node *door_ulist;	/* Unref list */
	void		(*door_pc)();	/* Door server entry point */
	void		*door_data;	/* Cookie passed during invocations */
	door_id_t	door_index;	/* Used as a uniquifier */
	door_attr_t	door_flags;	/* State associated with door */
	uint_t		door_active;	/* Number of active invocations */
	door_pool_t	door_servers;	/* Private pool of server threads */
	size_t		door_data_max;	/* param: max request data size */
	size_t		door_data_min;	/* param: min request data size */
	uint_t		door_desc_max;	/* param: max request descriptors */
	uint_t		door_bound_threads; /* number of bound threads */
} door_node_t;

/* Test if a door has been revoked */
#define	DOOR_INVALID(dp)	((dp)->door_flags & DOOR_REVOKED)

struct file;
int	door_insert(struct file *, door_desc_t *);
int	door_finish_dispatch(caddr_t);
uintptr_t door_final_sp(uintptr_t, size_t, int);
int	door_upcall(vnode_t *, door_arg_t *, struct cred *, size_t, uint_t);
void	door_slam(void);
void	door_exit(void);
void	door_revoke_all(void);
void	door_deliver_unref(door_node_t *);
void	door_list_delete(door_node_t *);
void	door_fork(kthread_t *, kthread_t *);
void	door_bind_thread(door_node_t *);
void	door_unbind_thread(door_node_t *);

extern kmutex_t door_knob;
extern kcondvar_t door_cv;
extern size_t door_max_arg;

/*
 * In-kernel doors interface.  These functions are considered Sun Private
 * and may change incompatibly in a minor release of Solaris.
 */
int	door_ki_upcall(door_handle_t, door_arg_t *);
int	door_ki_upcall_limited(door_handle_t, door_arg_t *, struct cred *,
    size_t, uint_t);
int	door_ki_create(void (*)(void *, door_arg_t *,
    void (**)(void *, void *), void **, int *), void *, door_attr_t,
    door_handle_t *);
void	door_ki_hold(door_handle_t);
void	door_ki_rele(door_handle_t);
int	door_ki_open(char *, door_handle_t *);
int	door_ki_info(door_handle_t, door_info_t *);
int	door_ki_getparam(door_handle_t, int, size_t *);
int	door_ki_setparam(door_handle_t, int, size_t);
door_handle_t door_ki_lookup(int did);

#endif	/* defined(_KERNEL) */
#endif	/* !defined(_ASM) */

/*
 * System call subcodes
 */
#define	DOOR_CREATE	0
#define	DOOR_REVOKE	1
#define	DOOR_INFO	2
#define	DOOR_CALL	3
#define	DOOR_BIND	6
#define	DOOR_UNBIND	7
#define	DOOR_UNREFSYS	8
#define	DOOR_UCRED	9
#define	DOOR_RETURN	10
#define	DOOR_GETPARAM	11
#define	DOOR_SETPARAM	12

#ifdef	__cplusplus
}
#endif

#endif	/* _SYS_DOOR_H */
