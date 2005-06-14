/*
 * Copyright (c) 1999 by Sun Microsystems, Inc.
 * All rights reserved.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifndef	_SUNW_IRS_INIT_H
#define	_SUNW_IRS_INIT_H

extern struct irs_acc	*sunw_irs_nis_acc(const char *);
extern struct irs_acc	*sunw_irs_irp_acc(const char *);

#ifndef	__SUNW_IRS_INIT_NODEFINE

#define	__irs_nis_acc	sunw_irs_nis_acc
#define	__irs_irp_acc	sunw_irs_irp_acc

#endif	/* __SUNW_IRS_INIT_NODEFINE */

#endif	/* _SUNW_IRS_INIT_H */
