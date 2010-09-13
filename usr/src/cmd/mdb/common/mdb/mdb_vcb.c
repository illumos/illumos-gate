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
 * Copyright 2004 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * In order to implement walk iteration variables (that is, ::walk walk varname)
 * we need to keep track of the active walk variables as the pipeline is
 * processed.  Each variable is tracked using a VCB (Variable Control Block)
 * that keeps a pointer to the variable in the MDB variable hash table, as
 * well as an addrvec (array of values) and parent pointer.  Each command in
 * the pipeline keeps its own list of VCBs, and these are inherited from left
 * to right in the pipeline.  The diagram shows an example pipeline and the
 * contents of c_addrv and VCBs at each stage:
 *
 *     > ::walk proc p |     ::map .+1    |   ::eval '<p=K'
 *
 *                                 vcb(p)              vcb(p)
 *                             0<- parent <----------- parent
 *                       c_addrv   addrv     c_addrv   addrv
 *                       123       123       124       123
 *                       456       456       457       456
 *                       789       789       790       789
 *
 * Then the first command (::walk) begins life with no VCBs.  It then creates
 * a new VCB for the rest of the pipeline and adds it to the next command's
 * VCB list (::map).  Before ::map is executed, it will first pass along a set
 * of VCBs to its "child" ::eval.  The important operations defined for VCBs
 * are as follows:
 *
 * (1) mdb_vcb_inherit - Prior to processing each command (pipeline stage), the
 * debugger calls the inherit routine to cause the next command to inherit the
 * VCBs from the current command.  The inherit routine allocates a new VCB
 * containing a pointer to the same variable, and sets its parent pointer to
 * point back to the parent VCB.  A VCB created by ::walk has a NULL parent
 * pointer indicating that it inherits its value from dot.
 *
 * (2) mdb_vcb_propagate - Prior to invoking the dcmd associated with a command,
 * the debugger propagates the next value stored in the VCB to its variable.
 * The VCB stores the values the variable should assume (that is, the values
 * of the variable that correspond to the value stored in the command's c_addrv)
 * in an addrvec in the VCB itself.
 *
 * (3) mdb_vcb_update - As each dcmd executes, it produces output for the next
 * stage in the pipeline.  The *next* stage of the pipeline's mdb_cmd_t has
 * already inherited the necessary VCBs in step (1), and so we just need to
 * record the current value of the variable into the VCB's addrv.  In the base
 * case (the first pipeline stage), the variable is not yet set, so we want
 * to store the current value of dot (produced by ::walk's callback) into the
 * addrv.  This value is passed in directly from the parsing code as a parameter
 * before the parser resets dot itself.  For subsequent pipeline stages, we
 * need to store into addrv the value the variable previously held when the
 * dcmd that produced this new value of dot was executed.  This value is
 * stored in the corresponding index of the parent VCB's addrv.
 *
 * (4) mdb_vcb_find - Given an mdb_var_t, determines if there already exists a
 * vcb for this variable, and if so returns it.  This allows us to avoid
 * re-creating a vcb every time through a walk, such as:
 *
 * 	> ::walk proc p | ::walk proc v | ::eval "<p=Kn"
 *
 * In this case, we don't want to create a new vcb for 'v' every time we execute
 * the second walk.
 *
 * Unfortunately, determining the addrv index is complicated by the fact that
 * pipes involve the asynchronous execution of the dcmds and the parser.  This
 * asynchrony means that the parser may not actually consume the output of a
 * given dcmd until long after it has completed, and thus when the parser is
 * ready to reset dot, it does not know what addrv index produced this value.
 * We work around this problem by explicitly flushing the pipeline after each
 * dcmd invocation if VCBs are active.  This does impact performance, so we
 * may need to re-evaluate in the future if pipelines are producing huge
 * amounts of data and a large number of VCBs are active simultaneously.
 */

#include <mdb/mdb_frame.h>
#include <mdb/mdb_debug.h>
#include <mdb/mdb_modapi.h>
#include <mdb/mdb_vcb.h>
#include <mdb/mdb.h>

mdb_vcb_t *
mdb_vcb_create(mdb_var_t *v)
{
	mdb_vcb_t *vcb = mdb_zalloc(sizeof (mdb_vcb_t), UM_SLEEP);
	vcb->vc_var = v;
	return (vcb);
}

void
mdb_vcb_destroy(mdb_vcb_t *vcb)
{
	mdb_dprintf(MDB_DBG_DSTK, "delete vcb %p (%s)\n", (void *)vcb,
	    mdb_nv_get_name(vcb->vc_var));

	mdb_addrvec_destroy(&vcb->vc_addrv);
	mdb_free(vcb, sizeof (mdb_vcb_t));
}

void
mdb_vcb_propagate(mdb_vcb_t *vcb)
{
	while (vcb != NULL) {
		mdb_addrvec_t *adp = &vcb->vc_addrv;
		ASSERT(vcb->vc_adnext < adp->ad_nelems);
		mdb_nv_set_value(vcb->vc_var, adp->ad_data[vcb->vc_adnext++]);
		vcb = vcb->vc_link;
	}
}

void
mdb_vcb_purge(mdb_vcb_t *vcb)
{
	while (vcb != NULL) {
		mdb_vcb_t *n = vcb->vc_link;
		mdb_vcb_destroy(vcb);
		vcb = n;
	}
}

void
mdb_vcb_inherit(mdb_cmd_t *src, mdb_cmd_t *dst)
{
	mdb_vcb_t *vc1, *vc2;

	for (vc1 = src->c_vcbs; vc1 != NULL; vc1 = vc1->vc_link) {
		vc2 = mdb_vcb_create(vc1->vc_var);
		vc2->vc_parent = vc1;
		vc2->vc_link = dst->c_vcbs;
		dst->c_vcbs = vc2;
	}
}

void
mdb_vcb_insert(mdb_vcb_t *vcb, mdb_frame_t *fp)
{
	if (fp->f_pcmd != NULL) {
		mdb_cmd_t *cp = fp->f_pcmd;

		mdb_dprintf(MDB_DBG_DSTK, "insert vcb %p (%s)\n",
		    (void *)vcb, mdb_nv_get_name(vcb->vc_var));

		ASSERT(vcb->vc_link == NULL);
		vcb->vc_link = cp->c_vcbs;
		cp->c_vcbs = vcb;
	}
}

void
mdb_vcb_update(struct mdb_frame *fp, uintptr_t value)
{
	mdb_vcb_t *vcb;

	for (vcb = fp->f_pcmd->c_vcbs; vcb != NULL; vcb = vcb->vc_link) {
		if (vcb->vc_parent != NULL) {
			mdb_addrvec_t *adp = &vcb->vc_parent->vc_addrv;
			adp->ad_ndx = vcb->vc_parent->vc_adnext - 1;
			ASSERT(adp->ad_ndx < adp->ad_nelems);
			value = adp->ad_data[adp->ad_ndx++];
		}
		mdb_addrvec_unshift(&vcb->vc_addrv, value);
	}
}

mdb_vcb_t *
mdb_vcb_find(mdb_var_t *var, mdb_frame_t *fp)
{
	mdb_vcb_t *vcb;

	if (fp->f_pcmd != NULL) {
		vcb = fp->f_pcmd->c_vcbs;
		while (vcb != NULL) {
			if (vcb->vc_var == var)
				return (vcb);
			vcb = vcb->vc_link;
		}
	}

	return (NULL);
}
