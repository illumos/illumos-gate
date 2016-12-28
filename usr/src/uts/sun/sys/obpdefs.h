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
 * Copyright 2007 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef	_SYS_OBPDEFS_H
#define	_SYS_OBPDEFS_H

#ifdef	__cplusplus
extern "C" {
#endif

#define	OBP_PSEUDO_ROMVEC_VERSION	5555

typedef	int		ihandle_t;
typedef	int		phandle_t;
typedef	phandle_t	pnode_t;

/*
 * Device type matching
 */

#define	OBP_NONODE	((pnode_t)0)
#define	OBP_BADNODE	((pnode_t)-1)

/*
 * Property Defines
 */

#define	OBP_NAME		"name"
#define	OBP_REG			"reg"
#define	OBP_INTR		"intr"
#define	OBP_RANGES		"ranges"
#define	OBP_INTERRUPTS		"interrupts"
#define	OBP_COMPATIBLE		"compatible"
#define	OBP_STATUS		"status"
#define	OBP_BOARDNUM		"board#"

#define	OBP_MAC_ADDR		"mac-address"
#define	OBP_STDINPATH		"stdin-path"
#define	OBP_STDOUTPATH		"stdout-path"
#define	OBP_IDPROM		"idprom"

#define	OBP_DEVICETYPE		"device_type"
#define	OBP_DISPLAY		"display"
#define	OBP_DISPLAY_CONSOLE	"console"
#define	OBP_NETWORK		"network"
#define	OBP_BYTE		"byte"
#define	OBP_BLOCK		"block"
#define	OBP_SERIAL		"serial"
#define	OBP_HIERARCHICAL	"hierarchical"
#define	OBP_IPI			"ipi3"
#define	OBP_CPU			"cpu"
#define	OBP_ADDRESS		"address"
#define	OBP_SIZE		"size"
#define	OBP_ALLOCSIZE		"alloc-size"

/*
 * OBP status values defines
 */
#define	OBP_ST_OKAY		"okay"
#define	OBP_ST_DISABLED		"disabled"
#define	OBP_ST_FAIL		"fail"

/*
 * Max size of a path component and a property name (not value)
 * These are standard definitions.
 */
#define	OBP_MAXDRVNAME		32	/* defined in P1275 */
#define	OBP_MAXPROPNAME		32	/* defined in P1275 */

/*
 * NB: Max pathname length is a platform-dependent parameter.
 * Also note that this parameter is used to define the crpconfig
 * structure in cpr.h. The cprconfig structure is currently
 * consumed by other consolidations. Care should be take before
 * changing this parameter value.
 */
#define	OBP_MAXPATHLEN		256	/* Platform dependent */

/*
 *  Every OBP node must have a `/' followed by at least 2 chars,
 *  so we can deduce the maxdepth of any OBP tree to be
 *  OBP_MAXPATHNAME/3.  This is a good first swag.
 */

#define	OBP_STACKDEPTH		(OBP_MAXPATHLEN/3)

#define	ROMVEC_BLKSIZE		512	/* XXX */

/*
 *  OBP Module mailbox messages for MP's
 *
 *	00..7F	: power-on self test
 *
 *	80..8F	: active in boot prom (at the "ok" prompt)
 *
 *	90..EF  : idle in boot prom
 *
 *	F0	: active in application
 *
 *	F1..FA	: reserved for future use
 *
 *	FB	: One processor exited to the PROM via op_exit(),
 *		  call to prom_stopcpu() requested.
 *
 *	FC	: One processor entered the PROM via op_enter(),
 *		  call to prom_idlecpu() requested.
 *
 *	FD	: One processor hit a BREAKPOINT,
 *		  call to prom_idlecpu() requested.
 *
 *	FE	: One processor got a WATCHDOG RESET
 *		  call to prom_stopcpu() requested.
 *
 *	FF	: This processor not available.
 *
 */

#define	OBP_MB_IDLE_LOW		((unsigned char)(0x90))
#define	OBP_MB_IDLE_HIGH	((unsigned char)(0xef))

#define	OBP_MB_IS_IDLE(s)	(((s) >= OBP_MB_IDLE_LOW) && \
				    ((s) <= OBP_MB_IDLE_HIGH))

#define	OBP_MB_ACTIVE		((unsigned char)(0xf0))
#define	OBP_MB_EXIT_STOP	((unsigned char)(0xfb))
#define	OBP_MB_ENTER_IDLE	((unsigned char)(0xfc))
#define	OBP_MB_BRKPT_IDLE	((unsigned char)(0xfd))
#define	OBP_MB_WATCHDOG_STOP	((unsigned char)(0xfe))

/*
 * The possible values for "*romp->v_insource" and "*romp->v_outsink" are
 * listed below.  These may be extended in the future.  Your program should
 * cope with this gracefully (e.g. by continuing to vector through the ROM
 * I/O routines if these are set in a way you don't understand).
 */
#define	INKEYB		0	/* Input from parallel keyboard. */
#define	INUARTA		1	/* Input or output to Uart A.	*/
#define	INUARTB		2	/* Input or output to Uart B.	*/
#define	INUARTC		3	/* Input or output to Uart C.	*/
#define	INUARTD		4	/* Input or output to Uart D.	*/
#define	OUTSCREEN	0	/* Output to frame buffer.	*/
#define	OUTUARTA	1	/* Input or output to Uart A.	*/
#define	OUTUARTB	2	/* Input or output to Uart B.	*/
#define	OUTUARTC	3	/* Input or output to Uart C.	*/
#define	OUTUARTD	4	/* Input or output to Uart D.	*/

/*
 * Structure set up by the boot command to pass arguments to the booted
 * program.
 */
struct bootparam {
	char	*bp_argv[8];	/* String arguments.			*/
	char	bp_strings[100]; /* String table for string arguments.	*/
	char	bp_dev[2];	/* Device name.				*/
	int	bp_ctlr;	/* Controller Number.			*/
	int	bp_unit;	/* Unit Number.				*/
	int	bp_part;	/* Partition/file Number.		*/
	char	*bp_name;	/* File name.  Points into "bp_strings"	*/
	struct boottab *bp_boottab; /* Points to table entry for device	*/
};

#ifdef	__cplusplus
}
#endif

#endif	/* _SYS_OBPDEFS_H */
