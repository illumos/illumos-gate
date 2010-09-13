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

#include <unistd.h>
#include <stdio.h>
#include <stdarg.h>
#include "msg.h"
#include "_libld.h"

/*
 * GNU ld --wrap support, also known as -z wrap.
 *
 * We maintain an AVL tree of wrapped symbol names. Every undefined
 * symbol is tested against this tree, and those that match have
 * their names modified to produce the wrapping effect:
 *
 * -	An undefined reference to XXX is converted to __wrap_XXX
 * -	An undefined reference to __real_XXX is converted to XXX
 *
 * This operation has a cost, but that is mitigated by two factors:
 *
 * -	This is a test feature, not used for production code, so somewhat
 *	longer link times are tolerable.
 * -	The cost of this feature is only paid when it is used. Otherwise,
 *	the sole overhead is the cost of testing the NULL AVL tree pointer
 *	during symbol processing.
 */


/*
 * AVL comparison function for WrapSymNode items.
 *
 * entry:
 *	n1, n2 - pointers to nodes to be compared
 *
 * exit:
 *	Returns -1 if (n1 < n2), 0 if they are equal, and 1 if (n1 > n2)
 */
static int
wrap_cmp(const void *n1, const void *n2)
{
	int		rc;

	rc = strcmp(((WrapSymNode *)n1)->wsn_name,
	    ((WrapSymNode *)n2)->wsn_name);

	if (rc > 0)
		return (1);
	if (rc < 0)
		return (-1);
	return (0);
}

/*
 * Enter a -z wrap symbol into the ofl_wrap AVL tree
 *
 * entry:
 *	ofl - Output file descriptor
 *	name - Name of symbol to be entered. Caller must ensure that
 *		memory used to hold name remains available for the life
 *		of the link-edit process.
 *
 * exit:
 *	On success, updates ofl->wrap_cache with a pointer to the
 *	resulting WrapSymNode, and returns that pointer. On failure,
 *	returns NULL.
 */
WrapSymNode *
ld_wrap_enter(Ofl_desc *ofl, const char *name)
{
	WrapSymNode	*wsnp, wsn;
	avl_index_t	where;
	size_t		name_len, wrapname_len;
	char		*tmpname;

	/* If this is the first wrap symbol, create the AVL tree */
	if (ofl->ofl_wrap == NULL) {
		ofl->ofl_wrap = libld_calloc(1, sizeof (*ofl->ofl_wrap));
		if (ofl->ofl_wrap == NULL)
			return (NULL);
		avl_create(ofl->ofl_wrap, wrap_cmp, sizeof (WrapSymNode),
		    SGSOFFSETOF(WrapSymNode, wsn_avlnode));
	}

	/* Have we already entered this one? */
	wsn.wsn_name = name;
	if ((wsnp = avl_find(ofl->ofl_wrap, &wsn, &where)) != NULL)
		return (wsnp);

	/*
	 * Allocate a new node, along with room for the wrapped name.
	 * Since strings have byte alignment, we can allocate it immediately
	 * following the AVL node without the need for alignment padding.
	 */
	name_len = strlen(wsn.wsn_name);
	wrapname_len = MSG_STR_UU_WRAP_U_SIZE + name_len + 1;
	if ((wsnp = libld_calloc(1, sizeof (*wsnp) + wrapname_len)) == NULL)
		return (NULL);
	wsnp->wsn_name = name;

	wsnp->wsn_wrapname = tmpname = (char *)(wsnp + 1);
	(void) snprintf(tmpname, wrapname_len, MSG_ORIG(MSG_FMT_STRCAT),
	    MSG_ORIG(MSG_STR_UU_WRAP_U), name);

	/* Insert the new node */
	avl_insert(ofl->ofl_wrap, wsnp, where);
	return (wsnp);
}
