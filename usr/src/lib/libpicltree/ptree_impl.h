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
 * Copyright (c) 1999-2001 by Sun Microsystems, Inc.
 * All rights reserved.
 */

#ifndef	_PTREE_IMPL_H
#define	_PTREE_IMPL_H

#ifdef	__cplusplus
extern "C" {
#endif

#include <synch.h>
#include <pthread.h>

typedef uint64_t picl_hdl_t;

/*
 * Hash table size of Ptree and PICL tables
 */
#define	HASH_TBL_SIZE		128
#define	HASH_INDEX(s, x)	((int)((x) & ((s) - 1)))

/*
 * Invalid PICL handle
 */
#define	PICL_INVALID_PICLHDL	(picl_hdl_t)0

/*
 * Is the object PICLized?
 */
#define	IS_PICLIZED(x)		((x)->picl_hdl != 0)

/*
 * A handle is a 64-bit quantity with the daemon's pid value in top 32 bits
 * and the raw handle value in the lower 32 bits.
 */
#define	HASH_VAL(x)		((x) & 0xFFFFFFFF)
#define	GET_PID(x)		((x) >> 32)
#define	MAKE_HANDLE(x, y)	(((picl_hdl_t)(x) << 32) | (y))

/*
 * Lock type when locking a node
 */
#define	RDLOCK_NODE		1
#define	WRLOCK_NODE		2

/*
 * Property access operation
 */
#define	PROP_READ		1
#define	PROP_WRITE		2

/*
 * PICL object type
 */
typedef	struct picl_obj		picl_obj_t;

/*
 * Hash table structure
 */
struct hash_elem {
	uint32_t		hdl;
	union {
		void		*data;
		uint32_t	ptreeh;
	} u;
	struct hash_elem	*next;
};
typedef	struct hash_elem	hash_elem_t;
#define	hash_obj	u.data
#define	hash_hdl	u.ptreeh

typedef struct {
	int		hash_size;
	hash_elem_t	**tbl;
} hash_t;

/*
 * Property expression list
 */
typedef struct prop_list {
	char			*pname;
	char			*pval;
	struct prop_list	*next;
} prop_list_t;

/*
 * PICL property (scalar or a table entry)
 */
struct picl_prop {
	ptree_propinfo_t	info;
	void			*pvalue;
	picl_obj_t		*nodep;		/* prop's node or table */
	picl_obj_t		*next_in_list;
	picl_obj_t		*next_by_row;
	picl_obj_t		*next_by_col;
};
typedef	struct picl_prop	picl_prop_t;

/*
 * PICL node
 */
struct picl_node {
	rwlock_t	rwlock;		/* protects properties */
	picl_obj_t	*firstprop;
	char		*classname;
	picl_obj_t	*parent;	/* protected by ptree lock */
	picl_obj_t	*child;		/* protected by ptree lock */
	picl_obj_t	*sibling;	/* protected by ptree lock */
};
typedef struct picl_node	picl_node_t;

/*
 * PICL object types
 */
#define	PICL_OBJ_NODE		0x1
#define	PICL_OBJ_PROP		0x2
#define	PICL_OBJ_TABLE		0x4
#define	PICL_OBJ_TABLEENTRY	0x8

/*
 * PICL object
 */
struct picl_obj {
	uint32_t	obj_type;
	picl_hdl_t	ptree_hdl;		/* ptree handle */
	picl_hdl_t	picl_hdl;		/* client handle */
	union {
		picl_node_t	node;
		picl_prop_t	prop;
	} u;
};

#define	pinfo_ver	u.prop.info.version
#define	prop_type	u.prop.info.piclinfo.type
#define	prop_size	u.prop.info.piclinfo.size
#define	prop_mode	u.prop.info.piclinfo.accessmode
#define	prop_name	u.prop.info.piclinfo.name
#define	prop_val	u.prop.pvalue
#define	next_row	u.prop.next_by_row
#define	next_col	u.prop.next_by_col
#define	next_prop	u.prop.next_in_list
#define	table_prop	u.prop.next_in_list
#define	prop_node	u.prop.nodep
#define	prop_table	u.prop.nodep
#define	read_func	u.prop.info.read
#define	write_func	u.prop.info.write

#define	first_prop	u.node.firstprop
#define	node_lock	u.node.rwlock
#define	child_node	u.node.child
#define	sibling_node	u.node.sibling
#define	parent_node	u.node.parent
#define	node_classname	u.node.classname

/*
 * PICL event queue structures
 */
struct eventq {
	const char		*ename;
	const void		*earg;
	size_t		size;
	void		(*completion_handler)(char *ename, void *earg,
			    size_t size);
	struct eventq	*next;
};
typedef struct eventq	eventq_t;

/*
 * Event handler list
 */
struct eh_list {
	char		*ename;
	void		*cookie;
	void		(*evt_handler)(const char *ename, const void *earg,
			    size_t size, void *cookie);
	short		execflg;
	short		wakeupflg;
	pthread_cond_t	cv;
	struct eh_list	*next;
};
typedef struct eh_list	evt_handler_t;

#define	SUPER_USER		0

#define	MIN(x, y)		((x) < (y) ? (x) : (y))

typedef struct picld_plugin_reg_list {
	picld_plugin_reg_t		reg;
	struct picld_plugin_reg_list	*next;
} picld_plugin_reg_list_t;

typedef struct picld_plinfo {
	char			*libname;
	char			*pathname;
	void			*dlh;
	struct picld_plinfo	*next;
} picld_plugin_desc_t;

extern	int	xptree_initialize(int);
extern	void	xptree_destroy(void);
extern	int	xptree_reinitialize(void);
extern	int	xptree_refresh_notify(uint32_t secs);
extern	int	cvt_picl2ptree(picl_hdl_t piclh, picl_hdl_t *ptreeh);
extern	void	cvt_ptree2picl(picl_hdl_t *vbuf);
extern	int	xptree_get_propinfo_by_name(picl_nodehdl_t nodeh,
			const char *pname, ptree_propinfo_t *pinfo);
extern	int	xptree_get_propval_with_cred(picl_prophdl_t proph, void *valbuf,
			size_t size, door_cred_t cred);
extern	int	xptree_get_propval_by_name_with_cred(picl_nodehdl_t nodeh,
			const char *propname, void *valbuf, size_t sz,
			door_cred_t cred);
extern	int	xptree_update_propval_with_cred(picl_prophdl_t proph,
			const void *valbuf, size_t sz, door_cred_t cred);
extern	int	xptree_update_propval_by_name_with_cred(picl_nodehdl_t nodeh,
			const char *propname, const void *valbuf, size_t sz,
			door_cred_t cred);

/*
 * PICL daemon verbose level flag
 */
extern	int	verbose_level;
extern	void	dbg_print(int level, const char *fmt, ...);
extern	void	dbg_exec(int level, void (*fn)(void *), void *arg);

#ifdef	__cplusplus
}
#endif

#endif	/* _PTREE_IMPL_H */
