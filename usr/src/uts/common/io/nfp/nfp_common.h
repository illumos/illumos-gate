/*

(C) Copyright nCipher Corporation Ltd 2002-2008 All rights reserved

Copyright (c) 2008-2013 Thales e-Security All rights reserved

Copyright (c) 2014 Thales UK All rights reserved

*/

#ifndef NFP_COMMON_H
#define NFP_COMMON_H

#include <sys/types.h>
#include <sys/conf.h>

typedef uint32_t UINT32;
typedef uint8_t BYTE;

#define DEFINE_NFPCI_PACKED_STRUCTS
#include "nfpci.h"
#include "nfdev-solaris.h"

typedef int oserr_t;

#if CH_BIGENDIAN

/* Big Endian Sparc */

#define SWP32(x) \
( (((unsigned int)(x)>>24)&0xff) | (((unsigned int)(x)>>8)&0xff00) | (((unsigned int)(x)<<8)&0xff0000) | (((unsigned int)(x)<<24)&0xff000000) ) 

#define SWP16(x) ( (((x)>>8)&0xff) | (((x)<<8)&0xff00) )

#define FROM_LE32_IO(x)		SWP32(*x)
#define TO_LE32_IO(x,y)		*x=SWP32(y)

#define FROM_LE32_MEM(x)	SWP32(*x)
#define TO_LE32_MEM(x,y)	*x=SWP32(y)

#define FROM_LE16_IO(x)		SWP16(*x)
#define TO_LE16_IO(x,y)		*x=SWP16(y)

#else

/* Little Endian x86 */

#define FROM_LE32_IO(x) (*x)
#define TO_LE32_IO(x,y) (*x=y)

#define FROM_LE32_MEM(x) (*x)
#define TO_LE32_MEM(x,y) (*x=y)

#define FROM_LE16_IO(x) (*x)
#define TO_LE16_IO(x,y) (*x=y)

#endif /* !CH_BIGENDIAN */

#include <sys/types.h>

#if CH_KERNELVER == 260
#define nfp_get_lbolt( lbolt, err ) err= drv_getparm( LBOLT, lbolt )
#else
#define nfp_get_lbolt( lbolt, err ) { *lbolt= ddi_get_lbolt(); err= 0; }
#endif

#endif

