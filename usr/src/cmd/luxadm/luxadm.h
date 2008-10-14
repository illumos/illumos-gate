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
 * Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*
 * luxadm.h
 *
 * External functions and global variables needed for PHOTON
 */

/*
 * I18N message number ranges
 *  This file: 13500 - 13999
 *  Shared common messages: 1 - 1999
 */

#ifndef	_LUXADM_H
#define	_LUXADM_H



#ifdef	__cplusplus
extern "C" {
#endif


/* External functions */
extern int	fc_update(unsigned, unsigned, char *);
extern int	fcal_update(unsigned, char *);
extern int	q_qlgc_update(unsigned, char *);
extern int	emulex_update(char *);
extern int	emulex_fcode_reader(int, char *, char *, uint32_t);
extern int	setboot(unsigned, unsigned, char *);
extern int	sysdump(int);
extern int	h_insertSena_fcdev();
extern int	hotplug(int, char **, int, int);
extern int	hotplug_e(int, char **, int, int);
extern void	print_fabric_dtype_prop(uchar_t *, uchar_t *, uchar_t);
/* SSA and RSM */
extern int	p_download(char *, char *, int, int, uchar_t *);
extern void	ssa_fast_write(char *);
extern void	ssa_perf_statistics(char *);
extern void	ssa_cli_start(char **, int);
extern void	ssa_cli_stop(char **, int);
extern void	ssa_cli_display_config(char **argv, char *, int, int, int);
extern void	cli_display_envsen_data(char **, int);
extern int	p_sync_cache(char *);
extern int	p_purge(char *);
extern void	led(char **, int, int);
extern void	alarm_enable(char **, int, int);
extern void	alarm_set(char **, int);
extern void	power_off(char **, int);
extern char 	*get_physical_name(char *);

/* SSA LIB environment sense */
extern int	scsi_get_envsen_data(int, char *, int);
extern int	scsi_put_envsen_data(int, char *, int);

/* hotplug */
extern void	print_errString(int, char *);
extern int	print_devState(char *, char *, int, int, int);
extern void	print_dev_state(char *, int);
extern void	print_bus_state(char *, int);
extern int	dev_handle_insert(char *, int);
extern int	dev_handle_remove(char *, int);
extern int	dev_handle_replace(char *, int);

/* funct.c */
extern char	ctoi(char);


/* Functions for FC-HBA based operations */
extern int fchba_display_port(int verbose);
extern int fchba_non_encl_probe();
extern int fchba_inquiry(char **argv);
extern int fchba_dump_map(char **argv);
extern int use_fchba();
extern int fchba_display_link_status(char **);
extern int fchba_display_config(char **, int, int);
extern int fchba_hotplug_e(int, char **, int, int);

/* for g_adm.c & hotplug.c */
int print_devState(char *, char *, int, int, int);

#ifdef	__cplusplus
}
#endif

#endif	/* _LUXADM_H */
