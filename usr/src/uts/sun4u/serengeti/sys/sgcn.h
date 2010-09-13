/*
 * CDDL HEADER START
 *
 * The contents of this file are subject to the terms of the
 * Common Development and Distribution License (the "License").
 * You may not use this file except in compliance with the License.
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
 * Copyright 2004 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef	_SGCN_H
#define	_SGCN_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef __cplusplus
extern "C" {
#endif

/*
 * Console driver
 *
 * There is no hardware serial port is provided. A standalone
 * co-processor SC acts as console device. The communication
 * between SC and a domain is via SRAM on the choosen I/O board.
 *
 * This driver manipulates SRAM from domain Solaris side.
 */

/*
 * Logically there are two sets of interfaces defined here.
 * The first part describes IOSRAM structures and will be
 * exposed to all relevant clients, like SC, OBP.
 * The second part defines internal driver data structure
 * used by sgcn dirver.
 */

#include <sys/types.h>
#include <sys/stream.h>
#include <sys/tty.h>
#include <sys/ddi.h>
#include <sys/sunddi.h>

/*
 * IOSRAM structure
 *
 * Solaris and OBP use separate console buffers. But they share
 * the same console buffer structure.
 *
 *              +---------------+ <- console buffer base address (BASE)
 *              |   header      |
 *              +---------------+ <- cnsram_in_begin + BASE
 *              |   input       |
 *              |   buffer      | <- cnsram_in_rdptr + BASE
 *              |               | <- cnsram_in_wrptr + BASE
 *              |               |
 *              +---------------+ <- cnsram_in_end + BASE
 *              |///////////////|
 *              |///////////////| <- reserved for future expansion
 *              |///////////////|
 *              +---------------+ <- cnsram_out_begin + BASE
 *              |   output      |
 *              |   buffer      | <- cnsram_out_rdptr + BASE
 *              |               | <- cnsram_out_wrptr + BASE
 *              +---------------+ <- cnsram_out_end + BASE
 *              |///////////////|
 *              |///////////////| <- reserved for future expansion
 *              |///////////////|
 *              +---------------+ <- cnsram_size + BASE
 */

/*
 * Console IOSRAM header structure
 * The header size is fixed, despite of 32-bit or 64-bit Solaris
 */
typedef struct {
	int32_t cnsram_magic;		/* magic number, CNSRAM_MAGIC	*/
	int32_t cnsram_version;		/* verison number		*/
	int32_t cnsram_size;		/* console buffer size		*/

	/*
	 * the followings are all relative to beginning of console buffer
	 */
	int32_t cnsram_in_begin;
	int32_t cnsram_in_end;
	int32_t cnsram_in_rdptr;
	int32_t cnsram_in_wrptr;

	int32_t cnsram_out_begin;
	int32_t cnsram_out_end;
	int32_t cnsram_out_rdptr;
	int32_t cnsram_out_wrptr;
} cnsram_header;

#define	CNSRAM_MAGIC		0x434F4E00		/* "CON" */
#define	CNSRAM_VERSION_1	1

/*
 * sgcn driver's soft state structure
 */
typedef struct sgcn {
	/* mutexes */
	kmutex_t sgcn_lock;		/* protects sgcn_t (soft state)	*/

	/* these are required by sbbc driver */
	kmutex_t sgcn_sbbc_in_lock;	/* input data lock 		*/
	kmutex_t sgcn_sbbc_outspace_lock; /* output data lock 		*/
	kmutex_t sgcn_sbbc_brk_lock;	/* break sequence lock 		*/
	uint_t sgcn_sbbc_in_state;	/* input data state		*/
	uint_t sgcn_sbbc_outspace_state; /* output data state		*/
	uint_t sgcn_sbbc_brk_state;	/* break sequence state		*/

	/* stream queues */
	queue_t *sgcn_writeq;		/* stream write queue		*/
	queue_t	*sgcn_readq;		/* stream read queue		*/

	/* pre-allocated console input buffer */
	char *sgcn_inbuf;		/* console input buffer		*/
	uint_t sgcn_inbuf_size;		/* buffer size			*/

	/* dev info */
	dev_info_t	*sgcn_dip;	/* dev_info			*/

	/* for handling IOCTL messages */
	bufcall_id_t	sgcn_wbufcid;	/* for console ioctl	*/
	tty_common_t	sgcn_tty;	/* for console ioctl	*/

	/* for console output timeout */
	time_t sgcn_sc_active;		/* last time (sec) SC was active */

} sgcn_t;

/* Constants used by promif routines */
#define	SGCN_CLNT_STR	"CON_CLNT"
#define	SGCN_OBP_STR	"CON_OBP"

/* alternate break sequence */
extern void (*abort_seq_handler)();

extern struct mod_ops mod_driverops;

#ifdef __cplusplus
}
#endif

#endif	/* _SGCN_H */
