/*
 * CDDL HEADER START
 *
 * The contents of this file are subject to the terms of the
 * Common Development and Distribution License, Version 1.0 only
 * (the "License").  You may not use this file except in compliance
 * with the License.
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
 * Copyright 2005 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef _SYS_ROMP_H
#define	_SYS_ROMP_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <sys/types.h>
#include <sys/param.h>

#ifdef __cplusplus
extern "C" {
#endif

/*
 * Autoconfig operations
 */

struct config_ops {
#ifdef	_KERNEL
	pnode_t	(*devr_next)(/* pnode_t nodeid */);
	pnode_t	(*devr_child)(/* pnode_t nodeid */);
#else	/* _KERNEL */
	int	(*devr_next)(/* pnode_t nodeid */);
	int	(*devr_child)(/* pnode_t nodeid */);
#endif	/* _KERNEL */
	int	(*devr_getproplen)(/* pnode_t nodeid, char *name */);
	int	(*devr_getprop)(/* pnode_t nodeid, char *name, caddr_t buf */);
	int	(*devr_setprop)(/* pnode_t nodeid, char *name, caddr_t value,
	    uint_t size */);
	caddr_t	(*devr_nextprop)(/* pnode_t nodeid, char *previous */);
};

struct romvec_obp {
	uint_t	op_magic;		/* magic mushroom */
	uint_t	op_romvec_version;	/* Version number of "romvec" */
	uint_t	op_plugin_version;	/* Plugin Architecture version */
	uint_t	op_mon_id;		/* version # of monitor firmware */

	struct memlist **v_physmemory;	/* total physical memory list */
	struct memlist **v_virtmemory;	/* taken virtual memory list */
	struct memlist **v_availmemory;	/* available physical memory */
	struct config_ops *op_config_ops; /* dev_info configuration access */

	/*
	 * storage device access facilities
	 */
	char	**v_bootcmd;	/* expanded with PROM defaults */
	uint_t	(*v_open)(/* char *name */);
	uint_t	(*v_close)(/* ihandle_t fileid */);

	/*
	 * block-oriented device access
	 */
	uint_t	(*v_read_blocks)();
	uint_t	(*v_write_blocks)();

	/*
	 * network device access
	 */
	uint_t	(*v_xmit_packet)();
	uint_t	(*v_poll_packet)();

	/*
	 * byte-oriented device access
	 */
	uint_t	(*v_read_bytes)();
	uint_t	(*v_write_bytes)();

	/*
	 * 'File' access - i.e.,  Tapes for byte devices.
	 * TFTP for network devices
	 */
	uint_t	(*v_seek)();

	/*
	 * single character I/O
	 */
	uchar_t	*v_insource;	/* Current source of input */
	uchar_t	*v_outsink;	/* Currrent output sink */
	uchar_t	(*v_getchar)();	/* Get a character from input */
	void	(*v_putchar)();	/* Put a character to output sink. */
	int	(*v_mayget)();	/* Maybe get a character, or "-1". */
	int	(*v_mayput)();	/* Maybe put a character, or "-1". */

	/*
	 * Frame buffer
	 */
	void	(*v_fwritestr)();	/* write a string to framebuffer */

	/*
	 * Miscellaneous Goodies
	 */
	void	(*op_boot)(/* char *bootspec */);	/* reboot machine */
	int	(*v_printf)();		/* handles fmt string plus 5 args */
	void	(*op_enter)();		/* Entry for keyboard abort. */
	int	*op_milliseconds;	/* Counts in milliseconds. */
	void	(*op_exit)();		/* Exit from user program. */

	/*
	 * Note:  Different semantics for V0 versus other op_vector_cmd:
	 */
	void	(**op_vector_cmd)();	/* Handler for the vector */
	void	(*op_interpret)(/* char *string, ... */);
					/* interpret forth string */

	/* boot parameters and 'old' style device access */
	struct bootparam	**v_bootparam;

	uint_t	(*v_mac_address)(/* int fd, caddr_t buf */);
			/* Copyout ether address */

	/*
	 * new V2 openprom stuff
	 */

	char	**op2_bootpath;	/* Full path name of boot device */
	char	**op2_bootargs;	/* Boot command line after dev spec */

#ifdef	_KERNEL
	ihandle_t *op2_stdin;	/* Console input device */
	ihandle_t *op2_stdout;	/* Console output device */

	phandle_t (*op2_phandle)(/* ihandle_t */);
					/* Convert ihandle to phandle */
#else	/* _KERNEL */
	int	*op2_stdin;	/* Console input device */
	int	*op2_stdout;	/* Console output device */

	int	(*op2_phandle)(/* ihandle_t */);
					/* Convert ihandle to phandle */
#endif	/* _KERNEL */

	caddr_t (*op2_alloc)(/* caddr_t virthint, uint_t size */);
					/* Allocate physical memory */

	void    (*op2_free)(/* caddr_t virthint, uint_t size */);
					/* Deallocate physical memory */

	caddr_t (*op2_map)(/* caddr_t virthint, uint_t space, uint_t phys,
	    uint_t size */);		/* Create device mapping */

	void    (*op2_unmap)(/* caddr_t virt, uint_t size */);
					/* Destroy device mapping */

#ifdef	_KERNEL
	ihandle_t (*op2_open)(/* char *name */);
#else	/* _KERNEL */
	int	(*op2_open)(/* char *name */);
#endif	/* _KERNEL */
	uint_t	(*op2_close)(/* int ihandle */);

	int (*op2_read)(/* int ihandle, caddr_t buf, uint_t len */);
	int (*op2_write)(/* int ihandle, caddr_t buf, uint_t len */);
	int (*op2_seek)(/* int ihandle, uint_t offsh, uint_t offsl */);

	void    (*op2_chain)(/* caddr_t virt, uint_t size, caddr_t entry,
	    caddr_t argaddr, uint_t arglen */);

	void    (*op2_release)(/* caddr_t virt, uint_t size */);

	/*
	 * End V2 stuff
	 */

	caddr_t	(*op3_alloc)(/* caddr_t virthint, uint_t size, int align */);
					/* Allocate mem and align */

	int	*v_reserved[14];

	/*
	 * Sun4c specific romvec routines (From sys/sun4c/machine/romvec.h)
	 * Common to all PROM versions.
	 */

	void    (*op_setcxsegmap)(/* int ctx, caddr_t v, int pmgno */);
					/* Set segment in any context. */

	/*
	 * V3 MP only functions: It's a fatal error to call these from a UP.
	 */

	int (*op3_startcpu)(/* pnode_t moduleid, dev_reg_t contextable,
	    int whichcontext, caddr_t pc */);

	int (*op3_stopcpu)(/* pnode_t */);

	int (*op3_idlecpu)(/* pnode_t */);
	int (*op3_resumecpu)(/* pnode_t */);
};

union sunromvec {
	struct romvec_obp	obp;
};

extern union sunromvec *romp;

#ifdef __cplusplus
}
#endif

#endif	/* _SYS_ROMP_H */
