/* $Id: strmode.h,v 1.3 2001/06/09 02:22:17 mouring Exp $ */

#ifndef	_STRMODE_H
#define	_STRMODE_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef __cplusplus
extern "C" {
#endif


#ifndef HAVE_STRMODE

void strmode(register mode_t mode, register char *p);

#endif

#ifdef __cplusplus
}
#endif

#endif /* _STRMODE_H */
