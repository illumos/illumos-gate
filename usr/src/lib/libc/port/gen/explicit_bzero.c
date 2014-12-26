/*	$OpenBSD: explicit_bzero.c,v 1.3 2014/06/21 02:34:26 matthew Exp $ */
/*
 * Public domain.
 * Written by Matthew Dempsky.
 */

#include <string.h>

#pragma weak __explicit_bzero_hook
/* ARGSUSED */
void
__explicit_bzero_hook(void *buf, size_t len)
{
}

void
explicit_bzero(void *buf, size_t len)
{
	(void) memset(buf, 0, len);
	__explicit_bzero_hook(buf, len);
}
