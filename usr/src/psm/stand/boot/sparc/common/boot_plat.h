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
 * Copyright 2010 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef _BOOT_PLAT_H
#define	_BOOT_PLAT_H

#ifdef __cplusplus
extern "C" {
#endif


/*
 * boot platform defaults per architecture
 */
typedef struct bootplat_defaults {
	char	*plat_defaults_name;
	char	*plat_defaults_path;
	int	plat_defaults_vac;
} bootplat_defaults_t;

/* boot_plat.c */
extern int	verbosemode;
extern char	filename[];
extern char	*const defname;
extern char	*const defname64;

extern int	bootprog(char *, char *, boolean_t);
extern char	*choose_default_filename(char *, char *);
extern char	*get_default_filename(void);
extern void	post_mountroot(char *, char *);
extern void	redirect_boot_path(char *, char *);
extern void	set_client_bootargs(const char *, const char *);
extern boolean_t is_netdev(char *devpath);


/* bootops.c */
extern struct bootops	bootops;

extern void	setup_bootops(void);
extern void	update_memlist(char *, char *, struct memlist **);


/*
 * bootprop.c.  These variables will be exported to the standalone as boot
 * properties.
 */
extern char	*v2path, *kernname, *systype, *my_own_name;
extern char	v2args_buf[];
#define	V2ARGS_BUF_SZ	OBP_MAXPATHLEN
extern char	*v2args;
extern char	*mfg_name;
extern char	*impl_arch_name;
extern char	*bootp_response;
extern char	*boot_message;
extern int	cache_state;
extern uint64_t	memlistextent;
extern char	*netdev_path;

extern void	set_default_filename(char *filename);


/* get.c */
extern int	cons_gets(char *, int);


/* machdep.c */
extern int  vac;

extern void	fiximp(void);
extern void	retain_nvram_page();
extern int	cpu_is_ultrasparc_1(void);


/* memlist.c */
extern void		init_memlists(void);
extern struct memlist	*fill_memlists(char *name, char *prop,
    struct memlist *old);


/* srt0.c */
extern void	_start(void *romp, ...);
extern void	exitto(int (*entrypoint)());
extern void	exitto64(int (*entrypoint)(), void *bootvec);


/* standalloc.c */
extern caddr_t	memlistpage;
extern caddr_t	scratchmemp;



#ifdef __cplusplus
}
#endif

#endif /* _BOOT_PLAT_H */
