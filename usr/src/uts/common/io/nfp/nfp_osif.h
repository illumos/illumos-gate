/*

nfp_osif.h: nCipher PCI HSM OS interface declarations

(C) Copyright nCipher Corporation Ltd 2002-2008 All rights reserved

Copyright (c) 2008-2013 Thales e-Security All rights reserved

Copyright (c) 2014 Thales UK All rights reserved

history

10/10/2001 jsh  Original

*/

#ifndef NFP_OSIF_H
#define NFP_OSIF_H

#include "nfp_hostif.h"
#include "nfp_error.h"

/* general typedefs ----------------------------------------------- */

typedef volatile unsigned int reg32;
typedef volatile unsigned short reg16;
typedef volatile unsigned char reg8;

/* sempaphores, mutexs and events --------------------------------- */

#if 0
extern nfp_err nfp_sema_init( nfp_sema *sema, int initial);
extern void nfp_sema_destroy( nfp_sema *sema );
extern void nfp_sema_post( nfp_sema *sema );
extern void nfp_sema_wait( nfp_sema *sema );
extern int nfp_sema_wait_sig( nfp_sema *sema );

extern nfp_err nfp_mutex_init( nfp_mutex *mutex );
extern void nfp_mutex_destroy( nfp_mutex *mutex );
extern void nfp_mutex_enter( nfp_mutex *mutex );
extern void nfp_mutex_exit( nfp_mutex *mutex );

extern nfp_err nfp_event_init( nfp_event *event );
extern void nfp_event_destroy( nfp_event *event );
extern void nfp_event_set( nfp_event *event );
extern void nfp_event_clear( nfp_event *event );
extern void nfp_event_wait( nfp_event *event );
extern void nfp_event_wait_sig( nfp_event *event );

#endif

/* timeouts ------------------------------------------------------ */

extern void nfp_sleep( int ms );

/* memory handling ----------------------------------------------- */

#define KMALLOC_DMA	0
#define KMALLOC_CACHED	1

extern void *nfp_kmalloc( int size, int flags );
extern void *nfp_krealloc( void *ptr, int size, int flags );
extern void nfp_kfree( void * );

/* config space access ------------------------------------------------ */

/* return Little Endian 32 bit config register */
extern nfp_err nfp_config_inl( nfp_cdev *pdev, int offset, unsigned int *res );

/* io space access ------------------------------------------------ */

extern unsigned int nfp_inl( nfp_cdev *pdev, int bar, int offset );
extern unsigned short nfp_inw( nfp_cdev *pdev, int bar, int offset );
extern void nfp_outl( nfp_cdev *pdev, int bar, int offset, unsigned int data );
extern void nfp_outw( nfp_cdev *pdev, int bar, int offset, unsigned short data );

/* user and device memory space access ---------------------------- */

/* NB these 2 functions are not guarenteed to be re-entrant for a given device */
extern nfp_err nfp_copy_from_user_to_dev( nfp_cdev *cdev, int bar, int offset, const char *ubuf, int len);
extern nfp_err nfp_copy_to_user_from_dev( nfp_cdev *cdev, int bar, int offset, char *ubuf, int len);

extern nfp_err nfp_copy_from_user( char *kbuf, const char *ubuf, int len );
extern nfp_err nfp_copy_to_user( char *ubuf, const char *kbuf, int len );

extern nfp_err nfp_copy_from_dev( nfp_cdev *cdev, int bar, int offset, char *kbuf, int len );
extern nfp_err nfp_copy_to_dev( nfp_cdev *cdev, int bar, int offset, const char *kbuf, int len);

/* debug ------------------------------------------------------------ */

#define NFP_DBG1	1
#define NFP_DBGE	NFP_DBG1
#define NFP_DBG2	2
#define NFP_DBG3	3
#define NFP_DBG4	4

#ifdef STRANGE_VARARGS
extern void nfp_log();
#else
extern void nfp_log( int severity, const char *format, ...);
#endif

extern int nfp_debug;

#endif
