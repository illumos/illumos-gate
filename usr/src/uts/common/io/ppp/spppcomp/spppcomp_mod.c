/*
 * spppcomp_mod.c - modload support for PPP compression STREAMS module.
 *
 * Copyright (c) 2011 Bayard G. Bell. All rights reserved.
 *
 * CONTRIBUTOR MAKES NO REPRESENTATION OR WARRANTIES ABOUT THE SUITABILITY
 * OF THE SOFTWARE, EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED
 * TO THE IMPLIED WARRANTIES OF MERCHANTABILITY, FITNESS FOR A
 * PARTICULAR PURPOSE, OR NON-INFRINGEMENT.  CONTRIBUTOR SHALL NOT BE LIABLE
 * FOR ANY DAMAGES SUFFERED BY LICENSEE AS A RESULT OF USING, MODIFYING OR
 * DISTRIBUTING THIS SOFTWARE OR ITS DERIVATIVES
 *
 * Copyright (c) 2000 by Sun Microsystems, Inc.
 * All rights reserved.
 *
 * Permission to use, copy, modify, and distribute this software and its
 * documentation is hereby granted, provided that the above copyright
 * notice appears in all copies.
 *
 * SUN MAKES NO REPRESENTATION OR WARRANTIES ABOUT THE SUITABILITY OF
 * THE SOFTWARE, EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED
 * TO THE IMPLIED WARRANTIES OF MERCHANTABILITY, FITNESS FOR A
 * PARTICULAR PURPOSE, OR NON-INFRINGEMENT.  SUN SHALL NOT BE LIABLE FOR
 * ANY DAMAGES SUFFERED BY LICENSEE AS A RESULT OF USING, MODIFYING OR
 * DISTRIBUTING THIS SOFTWARE OR ITS DERIVATIVES
 *
 * Copyright (c) 1994 The Australian National University.
 * All rights reserved.
 *
 * Permission to use, copy, modify, and distribute this software and its
 * documentation is hereby granted, provided that the above copyright
 * notice appears in all copies.  This software is provided without any
 * warranty, express or implied. The Australian National University
 * makes no representations about the suitability of this software for
 * any purpose.
 *
 * IN NO EVENT SHALL THE AUSTRALIAN NATIONAL UNIVERSITY BE LIABLE TO ANY
 * PARTY FOR DIRECT, INDIRECT, SPECIAL, INCIDENTAL, OR CONSEQUENTIAL DAMAGES
 * ARISING OUT OF THE USE OF THIS SOFTWARE AND ITS DOCUMENTATION, EVEN IF
 * THE AUSTRALIAN NATIONAL UNIVERSITY HAVE BEEN ADVISED OF THE POSSIBILITY
 * OF SUCH DAMAGE.
 *
 * THE AUSTRALIAN NATIONAL UNIVERSITY SPECIFICALLY DISCLAIMS ANY WARRANTIES,
 * INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY
 * AND FITNESS FOR A PARTICULAR PURPOSE.  THE SOFTWARE PROVIDED HEREUNDER IS
 * ON AN "AS IS" BASIS, AND THE AUSTRALIAN NATIONAL UNIVERSITY HAS NO
 * OBLIGATION TO PROVIDE MAINTENANCE, SUPPORT, UPDATES, ENHANCEMENTS,
 * OR MODIFICATIONS.
 *
 * This module is derived from the original SVR4 STREAMS PPP compression
 * module originally written by Paul Mackerras <paul.mackerras@cs.anu.edu.au>.
 *
 * James Carlson <james.d.carlson@sun.com> and Adi Masputra
 * <adi.masputra@sun.com> rewrote and restructured the code for improved
 * performance and scalability.
 */

#include <sys/types.h>
#include <sys/syslog.h>
#include <sys/conf.h>
#include <sys/errno.h>
#include <sys/ddi.h>
#include <sys/conf.h>
#include <sys/modctl.h>
#include <net/pppio.h>

#include "s_common.h"

/*
 * Globals for PPP compression loadable module wrapper
 */
extern struct streamtab spppcomp_tab;
extern const char spppcomp_module_description[];

static struct fmodsw fsw = {
	COMP_MOD_NAME,				/* f_name */
	&spppcomp_tab,				/* f_str */
	D_NEW | D_MP | D_MTPERQ			/* f_flag */
};

static struct modlstrmod modlstrmod = {
	&mod_strmodops,				/* strmod_modops */
	(char *)spppcomp_module_description,	/* strmod_linkinfo */
	&fsw					/* strmod_fmodsw */
};

static struct modlinkage modlinkage = {
	MODREV_1,			/* ml_rev, has to be MODREV_1 */
	(void *) &modlstrmod,		/* ml_linkage, NULL-terminated list */
	NULL				/*  of linkage structures */
};

int
_init(void)
{
	return (mod_install(&modlinkage));
}

int
_fini(void)
{
	return (mod_remove(&modlinkage));
}

int
_info(struct modinfo *modinfop)
{
	return (mod_info(&modlinkage, modinfop));
}
