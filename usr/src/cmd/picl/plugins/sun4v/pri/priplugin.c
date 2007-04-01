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
 * Copyright 2007 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include "priplugin.h"

#pragma init(priplugin_register)	/* place in .init section */

picl_nodehdl_t	root_node;
md_t		*mdp;
mde_cookie_t	rootnode;

void priplugin_init(void);
void priplugin_fini(void);

picld_plugin_reg_t priplugin_reg = {
	PICLD_PLUGIN_VERSION_1,
	PICLD_PLUGIN_CRITICAL,
	"pri_plugin",
	priplugin_init,
	priplugin_fini
};

void
set_prop_info(ptree_propinfo_t *propinfo, int size, char *name, int type)
{
	propinfo->version = PICLD_PLUGIN_VERSION_1;
	propinfo->read = NULL;
	propinfo->write = NULL;
	propinfo->piclinfo.type = type;
	propinfo->piclinfo.accessmode = PICL_READ;
	propinfo->piclinfo.size = size;
	(void) strncpy(propinfo->piclinfo.name, name,
	    sizeof (propinfo->piclinfo.name));
}

boolean_t
prop_exists(picl_nodehdl_t node, char *name)
{
	int status;
	picl_prophdl_t proph;

	status = ptree_get_prop_by_name(node, name, &proph);
	if (status == PICL_SUCCESS)
		return (B_TRUE);
	else
		return (B_FALSE);
}

void
add_md_prop(picl_nodehdl_t node, int size, char *name, void* value, int type)
{
	ptree_propinfo_t propinfo;
	picl_prophdl_t proph;

	if (!prop_exists(node, name)) {
		set_prop_info(&propinfo, size, name, type);

		(void) ptree_create_and_add_prop(node, &propinfo,
		    value, &proph);
	}
}

void
priplugin_init(void)
{
	int status;

	pri_debug(LOG_NOTICE, "priplugin: entered\n");
	status = ptree_get_root(&root_node);
	if (status != PICL_SUCCESS) {
		pri_debug(LOG_NOTICE, "priplugin: can't get picl root node\n");
		return;
	}

	mdp = pri_devinit();
	if (mdp == NULL) {
		pri_debug(LOG_NOTICE, "priplugin: cannot init pri: %d\n",
		    errno);
		return;
	}

	rootnode = md_root_node(mdp);

	pri_debug(LOG_NOTICE, "priplugin: have root picl and PRI nodes\n");

	status = ptree_walk_tree_by_class(root_node, "memory",
	    "memory-segments", add_mem_prop);
	if (status != PICL_SUCCESS) {
		pri_debug(LOG_NOTICE, "pri: memory-segments walk failed\n");
	} else
		pri_debug(LOG_NOTICE, "pri: success walking memory node\n");

	io_dev_addlabel();

	pri_devfini(mdp);
}

void
priplugin_fini(void)
{
}

void
priplugin_register(void)
{
	picld_plugin_register(&priplugin_reg);
}

/*VARARGS2*/
void
pri_debug(int level, char *fmt, ...)
{
#if (PRI_DEBUG != 0)
	va_list	ap;

	va_start(ap, fmt);
	vsyslog(level, fmt, ap);
	va_end(ap);
#endif
}
