/*
 * XXX - Add OpenSSH copyright...
 */

#ifndef	_DIRNAME_H
#define	_DIRNAME_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef __cplusplus
extern "C" {
#endif


#ifndef HAVE_DIRNAME

char *dirname(const char *path);

#endif

#ifdef __cplusplus
}
#endif

#endif /* _DIRNAME_H */
