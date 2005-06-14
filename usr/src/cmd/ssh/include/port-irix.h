/*
 * XXX - Add OpenSSH copyright
 */

#ifndef	_PORT_IRIX_H
#define	_PORT_IRIX_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef __cplusplus
extern "C" {
#endif


#if defined(WITH_IRIX_PROJECT) || defined(WITH_IRIX_JOBS) || defined(WITH_IRIX_ARRAY)

void irix_setusercontext(struct passwd *pw);

#endif /* defined(WITH_IRIX_PROJECT) || defined(WITH_IRIX_JOBS) || defined(WITH_IRIX_ARRAY) */

#ifdef __cplusplus
}
#endif

#endif /* _PORT_IRIX_H */
