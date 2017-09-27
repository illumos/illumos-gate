#ifndef	_OSDEP_H
#define _OSDEP_H

#define __unused __attribute__((unused))

#include "io.h"
#include "byteswap.h"
#include "latch.h"

#if defined(__sun)
typedef	unsigned long Address;
#endif

/* ANSI prototyping macro */
#ifdef	__STDC__
#  define	P(x)	x
#else
#  define	P(x)	()
#endif

#endif
