#!/usr/sbin/dtrace -s
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
 * Copyright 2017 Nexenta Systems, Inc.  All rights reserved.
 */

/*
 * User-level dtrace for testoplock
 * Usage: dtrace -s tol.d -c ./testoplock
 */

#pragma D option flowindent

self int trace;
self int mask;

/*
 * Trace almost everything
 */
pid$target:testoplock::entry
{
  self->trace++;
}

/*
 * If traced and not masked, print entry/return
 */
pid$target:testoplock::entry
/self->trace > 0 && self->mask == 0/
{
  printf("\t0x%x", arg0);
  printf("\t0x%x", arg1);
  printf("\t0x%x", arg2);
  printf("\t0x%x", arg3);
  printf("\t0x%x", arg4);
  printf("\t0x%x", arg5);
}

/* Skip the bsearch calls. */
pid$target:testoplock:xlate_nt_status:entry
{
  self->mask++;
}

pid$target:testoplock:xlate_nt_status:return
{
  self->mask--;
}

pid$target:testoplock::return
/self->trace > 0 && self->mask == 0/
{
  printf("\t0x%x", arg1);
}

pid$target:testoplock::return
{
  self->trace--;
}

/* ---------------------- */

pid$target::smb_oplock_request:entry
{
	self->sr = arg0;
	self->of = arg1;
	self->statep = arg2;
	this->state = *(uint32_t *)copyin(self->statep, 4);
	printf(" entry state=0x%x\n", this->state);
}

pid$target::smb_oplock_request:return
{
	this->sr = (userland pid`smb_request_t *)self->sr;
	this->state = *(uint32_t *)copyin(self->statep, 4);
	printf(" return state=0x%x\n", this->state);
	printf("\nsr->arg.open = ");
	print(this->sr->arg.open);
}

pid$target::smb_oplock_break_cmn:entry
{
	this->node = (userland pid`smb_node_t *)arg0;
	this->ofile = (userland pid`smb_ofile_t *)arg1;
	printf("\nnode->n_oplock = ");
	print(this->node->n_oplock);
	printf("\nofile->f_oplock = ");
	print(this->ofile->f_oplock);
}

pid$target::smb_oplock_ind_break:entry
{
	this->ofile = (userland pid`smb_ofile_t *)arg0;
	printf("\nofile->f_oplock = ");
	print(this->ofile->f_oplock);
}
