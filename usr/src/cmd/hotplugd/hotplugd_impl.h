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
 * Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef	_HOTPLUGD_IMPL_H
#define	_HOTPLUGD_IMPL_H

#ifdef  __cplusplus
extern "C" {
#endif

/*
 * Define macros to test connection states.
 */
#define	HP_IS_ENABLED(s)	(s == DDI_HP_CN_STATE_ENABLED)

#define	HP_IS_ONLINE(s)		((s == DDI_HP_CN_STATE_ONLINE) || \
				(s == DDI_HP_CN_STATE_MAINTENANCE))

#define	HP_IS_OFFLINE(s)	((s == DDI_HP_CN_STATE_PORT_EMPTY) || \
				(s == DDI_HP_CN_STATE_PORT_PRESENT) || \
				(s == DDI_HP_CN_STATE_OFFLINE))

/*
 * Define size of nvlist buffer for set/get commands.
 */
#define	HP_PRIVATE_BUF_SZ	4096

/*
 * Define a string for parsing /devices paths.
 */
#define	S_DEVICES		"/devices"

/*
 * Global functions.
 */
void		log_err(char *fmt, ...);
void		log_info(char *fmt, ...);
void		hp_dprintf(char *fmt, ...);
boolean_t	door_server_init(void);
void		door_server_fini(void);
int		getinfo(const char *path, const char *connection, uint_t flags,
		    hp_node_t *rootp);
int		changestate(const char *path, const char *connection, int state,
		    uint_t flags, int *old_statep, hp_node_t *resultsp);
int		private_options(const char *path, const char *connection,
		    hp_cmd_t cmd, const char *options, char **resultsp);
int		copy_usage(hp_node_t root);
int		rcm_resources(hp_node_t root, char ***rsrcsp);
void		free_rcm_resources(char **rsrcs);
int		rcm_offline(char **rsrcs, uint_t flags, hp_node_t root);
void		rcm_online(char **rsrcs);
void		rcm_remove(char **rsrcs);

#ifdef  __cplusplus
}
#endif

#endif	/* _HOTPLUGD_IMPL_H */
