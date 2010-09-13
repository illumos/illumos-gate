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

#ifndef	_SYS_EXACCT_H
#define	_SYS_EXACCT_H

#include <sys/types.h>
#include <sys/task.h>
#include <sys/proc.h>
#include <sys/procset.h>

#ifdef _KERNEL
#include <sys/acctctl.h>
#include <sys/kmem.h>
#include <sys/taskq.h>
#include <sys/vnode.h>
#endif

#ifdef	__cplusplus
extern "C" {
#endif

#define	EXACCT_VERSION	1

/*
 * unpack and free allocation options:  the behaviour of the ea_free_object()
 * function is coordinated with whether an unpack used EUP_ALLOC or EUP_NOALLOC,
 * such that unpacked object hierarchies can be later freed successfully.
 */
#define	EUP_ALLOC	0x0	/* allocate new memory for vbl length objects */
#define	EUP_NOALLOC	0x1	/* use existing buffer for vbl length objects */
#define	EUP_ALLOC_MASK	0x1

/*
 * wracct and putacct record type options:  the properties of the partial and
 * interval records differ slightly:  a partial record is a snapshot of the
 * resource usage for the given process or task, while an interval record
 * reports the current usage since the last interval record or creation.
 * Interval records are supported only for tasks.
 */
#define	EW_PARTIAL		(0x01)	/* partial record */
#define	EW_INTERVAL		(0x02)	/* interval record */
#define	EW_FINAL		(0x04)	/* final record: used only in kernel */

/*
 * putacct contents option:  the contents of the buffer passed to putacct may be
 * identified either as raw data or as a packed exacct record.
 */
#define	EP_RAW			0
#define	EP_EXACCT_OBJECT	1

#define	EXACCT_MAX_BUFSIZE	(64 * 1024)

#ifndef _KERNEL
extern size_t getacct(idtype_t, id_t, void *, size_t);
extern int putacct(idtype_t, id_t, void *, size_t, int);
extern int wracct(idtype_t, id_t, int);
#endif /* ! _KERNEL */

/*
 * Error codes.  libexacct reports these errors through the ea_error() function;
 * in the case of EXR_SYSCALL_FAIL, errno will contain the error code
 * encountered by the underlying system call.
 */
#define	EXR_OK			0
#define	EXR_SYSCALL_FAIL	1
#define	EXR_CORRUPT_FILE	2
#define	EXR_EOF			3
#define	EXR_NO_CREATOR		4
#define	EXR_INVALID_BUF		5
#define	EXR_NOTSUPP		6
#define	EXR_UNKN_VERSION	7
#define	EXR_INVALID_OBJ		8

typedef uint64_t ea_size_t;
typedef uint32_t ea_catalog_t;

typedef enum {EO_ERROR = -1, EO_NONE = 0, EO_GROUP, EO_ITEM} ea_object_type_t;

typedef struct ea_item {
	/*
	 * The ei_u union is discriminated via the type field of the enclosing
	 * object's catalog tag.
	 */
	union {
		uint8_t		ei_u_uint8;
		uint16_t	ei_u_uint16;
		uint32_t	ei_u_uint32;
		uint64_t	ei_u_uint64;
		double		ei_u_double;
		char		*ei_u_string;
		void		*ei_u_object;	/* for embedded packed object */
		void		*ei_u_raw;
	}			ei_u;
	ea_size_t		ei_size;
} ea_item_t;
#define	ei_uint8	ei_u.ei_u_uint8
#define	ei_uint16	ei_u.ei_u_uint16
#define	ei_uint32	ei_u.ei_u_uint32
#define	ei_uint64	ei_u.ei_u_uint64
#define	ei_double	ei_u.ei_u_double
#define	ei_string	ei_u.ei_u_string
#define	ei_object	ei_u.ei_u_object
#define	ei_raw		ei_u.ei_u_raw

typedef struct ea_group {
	uint32_t		eg_nobjs;
	struct ea_object	*eg_objs;
} ea_group_t;

typedef struct ea_object {
	ea_object_type_t	eo_type;
	union {
		ea_group_t	eo_u_group;
		ea_item_t	eo_u_item;
	}			eo_u;
	struct ea_object	*eo_next;
	ea_catalog_t		eo_catalog;
} ea_object_t;
#define	eo_group	eo_u.eo_u_group
#define	eo_item		eo_u.eo_u_item

extern int ea_set_item(ea_object_t *, ea_catalog_t, const void *, size_t);
extern int ea_set_group(ea_object_t *, ea_catalog_t);

/*
 * In prior releases, the following three functions had the type void, and so
 * could not return a status code.  In SunOS 5.9, the return type has been
 * changed to int, so that if errors are detected the invoking application
 * can be notified appropriately.
 */
extern int ea_attach_to_object(ea_object_t *, ea_object_t *);
extern int ea_attach_to_group(ea_object_t *, ea_object_t *);
extern int ea_free_item(ea_object_t *, int);

extern void ea_free_object(ea_object_t *, int);
extern size_t ea_pack_object(ea_object_t *, void *, size_t);
extern void *ea_alloc(size_t);
extern void ea_free(void *, size_t);
extern char *ea_strdup(const char *);
extern void ea_strfree(char *);

#ifdef _KERNEL
extern ea_object_t *ea_alloc_item(ea_catalog_t, void *, size_t);
extern ea_object_t *ea_alloc_group(ea_catalog_t);
extern ea_object_t *ea_attach_item(ea_object_t *, void *, size_t, ea_catalog_t);
extern void exacct_commit_task(void *);
extern void exacct_commit_proc(proc_t *, int);
extern void exacct_update_task_mstate(proc_t *);
extern int exacct_tag_task(ac_info_t *, task_t *, void *, size_t, int);
extern int exacct_tag_proc(ac_info_t *, pid_t, taskid_t, void *, size_t, int,
    const char *);
extern void exacct_commit_flow(void *);
extern int exacct_commit_netinfo(void *, int);
extern void exacct_init(void);
extern void *exacct_create_header(size_t *);
extern int exacct_write_header(ac_info_t *, void *, size_t);
extern void exacct_calculate_proc_usage(proc_t *, proc_usage_t *,
    ulong_t *, int, int);
extern int exacct_commit_callback(ac_info_t *, void *, size_t, void *,
    size_t, size_t *);
extern int exacct_assemble_proc_usage(ac_info_t *, proc_usage_t *,
    int (*)(ac_info_t *, void *, size_t, void *, size_t, size_t *),
    void *, size_t, size_t *, int);
extern int exacct_assemble_task_usage(ac_info_t *, task_t *,
    int (*)(ac_info_t *, void *, size_t, void *, size_t, size_t *),
    void *, size_t, size_t *, int);
extern int exacct_assemble_flow_usage(ac_info_t *, flow_usage_t *,
    int (*)(ac_info_t *, void *, size_t, void *, size_t, size_t *),
    void *, size_t, size_t *);
extern void exacct_move_mstate(proc_t *, task_t *, task_t *);
extern int exacct_assemble_net_usage(ac_info_t *, void *,
    int (*)(ac_info_t *, void *, size_t, void *, size_t, size_t *),
    void *, size_t, size_t *, int);
extern taskq_t *exacct_queue;
extern kmem_cache_t *exacct_object_cache;
#endif /* _KERNEL */

#ifdef	__cplusplus
}
#endif

#endif	/* _SYS_EXACCT_H */
