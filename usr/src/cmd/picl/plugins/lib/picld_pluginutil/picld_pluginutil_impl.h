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

#ifndef	_PICLD_PLUGINUTIL_IMPL_H
#define	_PICLD_PLUGINUTIL_IMPL_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef	__cplusplus
extern "C" {
#endif

#define	PER_ALLOC_COUNT		256
#define	RECORD_SIZE_MAX		1024
#define	STARTING_INDEX		0
#define	SUPPORTED_VERSION_NUM	1.1

/* reserved keyword (case insensitive) */
#define	KEYWORD_INT_TYPE	"int"
#define	KEYWORD_UINT_TYPE	"uint"
#define	KEYWORD_FLOAT_TYPE	"float"
#define	KEYWORD_STRING_TYPE	"string"
#define	KEYWORD_VOID_TYPE	"void"
#define	KEYWORD_READ_MODE	"r"
#define	KEYWORD_WRITE_MODE	"w"
#define	KEYWORD_READWRITE_MODE	"rw"
#define	KEYWORD_WITH_STR	"with"

#define	WHITESPACE		" \t\n"
#define	RECORD_WHITESPACE	": \t\n"
#define	DOUBLE_QUOTE		"\""

typedef	struct {
	char			*path;
} path_cmd_t;

typedef	struct {
	picl_nodehdl_t		nodeh;
	char			*nodename;
	char			*classname;
} node_cmd_t;

typedef	struct {
	picl_prophdl_t		proph;
	size_t			size;
	int			type;
	int			accessmode;
	char			*pname;
	void			*valbuf;
} prop_cmd_t;

typedef	struct {
	picl_prophdl_t		proph;
	char			*pname;
	char			*dstnode;
} refprop_cmd_t;

typedef	struct {
	picl_nodehdl_t		nodeh;
	char			*newnodename;
	char			*newnodeclass;
	char			*dstnode;
} refnode_cmd_t;

typedef	struct {
	picl_prophdl_t		tblh;
	int			newtbl;
	char			*tname;
} table_cmd_t;

typedef	struct {
	int			index;
	int			nproph;
	picl_prophdl_t		*prophs;
} row_cmd_t;

typedef	struct {
	int32_t			level;
} verbose_cmd_t;

typedef struct {
	int			type;
	union {
		path_cmd_t	path;
		node_cmd_t	node;
		prop_cmd_t	prop;
		refprop_cmd_t	refprop;
		refnode_cmd_t	refnode;
		table_cmd_t	table;
		row_cmd_t	row;
		verbose_cmd_t	verbose;
	} u;
} command_t;

typedef struct {
	int		count;
	int		allocated;
	float		version_no;
	int		inside_node_block;
	int		verbose;
	const char	*fname;
	int		inside_table_block;
	int		current_tbl;
	int		inside_row_block;
	int		current_row;
	command_t	*commands;
} cmdbuf_t;

#define	pathcmd_name		u.path.path
#define	nodecmd_nodeh		u.node.nodeh
#define	nodecmd_nodename	u.node.nodename
#define	nodecmd_classname	u.node.classname
#define	nodecmd_classname	u.node.classname
#define	propcmd_proph		u.prop.proph
#define	propcmd_pname		u.prop.pname
#define	propcmd_type		u.prop.type
#define	propcmd_accessmode	u.prop.accessmode
#define	propcmd_size		u.prop.size
#define	propcmd_valbuf		u.prop.valbuf
#define	refpropcmd_proph	u.refprop.proph
#define	refpropcmd_pname	u.refprop.pname
#define	refpropcmd_dstnode	u.refprop.dstnode
#define	refnodecmd_nodeh	u.refnode.nodeh
#define	refnodecmd_name		u.refnode.newnodename
#define	refnodecmd_class	u.refnode.newnodeclass
#define	refnodecmd_dstnode	u.refnode.dstnode
#define	tablecmd_tblh		u.table.tblh
#define	tablecmd_newtbl		u.table.newtbl
#define	tablecmd_tname		u.table.tname
#define	rowcmd_index		u.row.index
#define	rowcmd_nproph		u.row.nproph
#define	rowcmd_prophs		u.row.prophs
#define	verbosecmd_level	u.verbose.level

#ifdef	__cplusplus
}
#endif

#endif	/* _PICLD_PLUGINUTIL_IMPL_H */
