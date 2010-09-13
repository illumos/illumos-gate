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
 * ISO 9660 System Use Sharing Protocol extension filesystem specifications
 * Copyright (c) 1991,2000,2001 by Sun Microsystems, Inc.
 * All rights reserved.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <sys/types.h>
#include <sys/t_lock.h>
#include <sys/param.h>
#include <sys/systm.h>
#include <sys/sysmacros.h>
#include <sys/kmem.h>
#include <sys/signal.h>
#include <sys/user.h>
#include <sys/proc.h>
#include <sys/disp.h>
#include <sys/buf.h>
#include <sys/pathname.h>
#include <sys/vfs.h>
#include <sys/vnode.h>
#include <sys/file.h>
#include <sys/uio.h>
#include <sys/conf.h>

#include <vm/page.h>

#include <sys/fs/hsfs_spec.h>
#include <sys/fs/hsfs_isospec.h>
#include <sys/fs/hsfs_node.h>
#include <sys/fs/hsfs_impl.h>
#include <sys/fs/hsfs_susp.h>
#include <sys/fs/hsfs_rrip.h>

#include <sys/statvfs.h>
#include <sys/mount.h>
#include <sys/swap.h>
#include <sys/errno.h>
#include <sys/debug.h>
#include "fs/fs_subr.h"
#include <sys/cmn_err.h>



/*
 * 	Common Signatures for all SUSP
 */
ext_signature_t  susp_signature_table[ ] = {
	SUSP_SP,	share_protocol,		/* must be first in table */
	SUSP_CE,	share_continue,		/* must be second in table */
	SUSP_PD,	share_padding,
	SUSP_ER,	share_ext_ref,
	SUSP_ST,	share_stop,
	(char *)NULL,	NULL
};

/*
 * These are global pointers referring to the above table, so the
 * positions must not change as marked on the right above.
 */
ext_signature_t	*susp_sp = &susp_signature_table[0];
ext_signature_t	*susp_ce = &susp_signature_table[1];


/*
 * ext name	version 	implemented	signature table
 *
 * the SUSP must be the first entry in the table.
 * the RRIP must be the second entry in the table. We need to be able
 * to check the RRIP bit being set, so we must know it's position.
 * RRIP_BIT is set to 2 in rrip.h
 */
extension_name_t   extension_name_table[]  =  {
	"SUSP_1991A",	SUSP_VERSION,		susp_signature_table, /* #1 */
	RRIP_ER_EXT_ID,	RRIP_EXT_VERSION, 	rrip_signature_table,
	(char *)NULL,	0,			(ext_signature_t *)NULL
};

extension_name_t	*susp_ext_name = extension_name_table;

/*
 * share_protocol()
 *
 * sig_handler() for SUSP signature "SP"
 *
 * This function looks for the "SP" signature field, which means that
 * the SUSP is supported on the current CD-ROM.  It looks for the word
 * 0xBEEF in the signature.  If that exists, the SUSP is implemented.
 * The function will then set the implemented bit in the "SUSP" entry
 * of the extention_name_table[]. If the bytes don't match, then we
 * 	return a big fat NULL and treat this as an ISO 9660 CD-ROM.
 */
uchar_t *
share_protocol(sig_args_t *sig_args_p)
{
	uchar_t *sp_ptr = sig_args_p->SUF_ptr;

	/* Let's check the check bytes */
	if (!CHECK_BYTES_OK(sp_ptr))
		return ((uchar_t *)NULL);

	/*
	 * 	Ah, we have the go ahead, so let's set the implemented bit
	 * of the SUSP in the extension_name_table[]
	 */

	if (SUSP_VERSION < SUF_VER(sp_ptr)) {
		cmn_err(CE_NOTE,
		    "System Use Sharing Protocol ver. %d:not supported\n",
		    (int)SUF_VER(sp_ptr));
		return ((uchar_t *)NULL);
	}

	SET_SUSP_BIT(sig_args_p->fsp);

	sig_args_p->fsp->hsfs_sua_off = SP_SUA_OFFSET(sp_ptr);

	return (sp_ptr + SUF_LEN(sp_ptr));
}

/*
 * share_ext_ref()
 *
 * sig_handler() for SUSP signature "ER"
 *
 * This function looks for the "ER" signature field, which lists an
 * extension that is implemented on the current CD-ROM.  The function
 * will then search through the extention_name_table[], looking for the
 * extension reference in this SUF.
 *
 * If the correct extension reference is found, and the version number
 * in the "ER" SUF is less than or equal to the version specified in
 * the extension_name_table, the implemented bit will be set to 1.
 *
 * If the version number in the "ER" field is greater than that in the
 * extension_name_table or no reference can be matched, the reference
 * will be skipped the function will return the next field.
 */
uchar_t *
share_ext_ref(sig_args_t *sig_args_p)
{
	uchar_t *er_ptr = sig_args_p->SUF_ptr;
	extension_name_t *extnp;
	int index;

	/*
	 * Find appropriate extension and signature table
	 */
	for (extnp = extension_name_table, index = 0;
	    extnp->extension_name != (char *)NULL;
	    extnp++, index++)  {
		if (strncmp(extnp->extension_name,
			    (char *)ER_ext_id(er_ptr),
			    ER_ID_LEN(er_ptr)) == 0) {
			SET_IMPL_BIT(sig_args_p->fsp, index);
		}
	}

	return (er_ptr + SUF_LEN(er_ptr));
}

/*
 * share_continue()
 *
 * sig_handler() for SUSP signature "CE"
 *
 * This function looks for the "CE" signature field. This means that
 * the SUA is continued in another block on the CD-ROM.  Because it is
 * not a requirement that this "CE" field come at the end of the SUA,
 * this function will only set up a structure containing the
 * information  needed to read the next SUA, somewhere on the disk.
 *
 * The end of the SUA is signaled by 2 NULL bytes, where the next
 * signature would have been.
 *
 * This one will be tough to implement.
 */
uchar_t *
share_continue(sig_args_t *sig_args_p)
{
	uchar_t *ce_ptr = sig_args_p->SUF_ptr;

	sig_args_p->cont_info_p->cont_lbn    = CE_BLK_LOC(ce_ptr);
	sig_args_p->cont_info_p->cont_offset = CE_OFFSET(ce_ptr);
	sig_args_p->cont_info_p->cont_len    = CE_CONT_LEN(ce_ptr);

	return (ce_ptr + SUF_LEN(ce_ptr));
}


/*
 * share_padding()
 *
 * sig_handler() for SUSP signature "PD"
 *
 * All this function is needed for is bypassing a certain number of
 * bytes.  So, we just advance past this field and we're set.
 */
uchar_t *
share_padding(sig_args_t *sig_args_p)
{
	uchar_t *pd_ptr = sig_args_p->SUF_ptr;

	return (pd_ptr +  SUF_LEN(pd_ptr));
}



/*
 * share_stop()
 *
 * sig_handler() for SUSP signature "ST"
 *
 * All this is used for is signaling the end of an SUA.
 * It fills the flag variable with the
 */
uchar_t *
share_stop(sig_args_t *sig_args_p)
{
	uchar_t *st_ptr = sig_args_p->SUF_ptr;

	sig_args_p->flags = END_OF_SUA;	/* stop parsing the SUA NOW!!!! */

	return (st_ptr +  SUF_LEN(st_ptr));
}
