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
 * Example using the "fksmb$pid" dtrace provider.
 * Traces all SMB commands using the probes:
 *	start, done
 * all of which have two args:
 *	args[0]: char * (probe-name)
 *	args[1]: ulong (struct smb_request *)
 *
 * Note: the "userland" type classifier causes dtrace to
 * automatically copyin the struct for us.  (Nice!)
 */

fksmb$target:::smb_start
{
	this->pn = copyinstr(arg0);
	this->sr = (userland pid`smb_request_t *)arg1;

	printf(" %s mid=0x%x uid=0x%x tid=0x%x\n",
	    this->pn,
	    this->sr->smb_mid,
	    this->sr->smb_uid,
	    this->sr->smb_tid);
}

fksmb$target:::smb_done
{
	this->pn = copyinstr(arg0);
	this->sr = (userland pid`smb_request_t *)arg1;

	printf(" %s mid=0x%x status=0x%x\n",
	    this->pn,
	    this->sr->smb_mid,
	    this->sr->smb_error.status);
}

fksmb$target:::smb2_start
{
	this->pn = copyinstr(arg0);
	this->sr = (userland pid`smb_request_t *)arg1;

	printf(" %s mid=0x%x uid=0x%x tid=0x%x\n",
	    this->pn,
	    this->sr->smb2_messageid,
	    this->sr->smb2_ssnid,
	    this->sr->smb_tid);
}

fksmb$target:::smb2_done
{
	this->pn = copyinstr(arg0);
	this->sr = (userland pid`smb_request_t *)arg1;

	printf(" %s mid=0x%x status=0x%x\n",
	    this->pn,
	    this->sr->smb2_messageid,
	    this->sr->smb2_status);
}
