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

#ifndef	_SYSEVENT_CONF_MOD_H
#define	_SYSEVENT_CONF_MOD_H

#ifdef	__cplusplus
extern "C" {
#endif


/*
 * syseventd_print debug levels for sysevent_conf_mod
 */
#define	DBG_TEST	1	/* info of interest when testing */
#define	DBG_EXEC	2	/* path and args to exec */
#define	DBG_EVENTS	3	/* received events */
#define	DBG_MATCHES	4	/* dump specs for matching events */
#define	DBG_MACRO	5	/* macro expansion */
#define	DBG_CONF_FILE	6	/* sysevent.conf parsing */
#define	DBG_DETAILED	7	/* all the above and more */


/*
 * Directory where sysevent.conf files reside
 */
#define	SYSEVENT_CONFIG_DIR		"/etc/sysevent/config"

/*
 * Lock file name to serialize registry updates
 */
#define	LOCK_FILENAME			"/var/run/syseventconf.lock"

/*
 * sysevent.conf files list
 */
typedef struct conftab {
	char		*cf_conf_file;		/* source conf file */
	struct conftab	*cf_next;
} conftab_t;

/*
 * sysevent.conf table
 */
typedef struct syseventtab {
	char	*se_conf_file;			/* source conf file */
	int	se_lineno;			/* line number */
	char	*se_vendor;			/* vendor */
	char	*se_publisher;			/* publisher */
	char	*se_class;			/* event class */
	char	*se_subclass;			/* event subclass */
	char	*se_user;			/* user */
	char	*se_reserved1;			/* reserved1 */
	char	*se_reserved2;			/* reserved2 */
	char	*se_path;			/* event path */
	char	*se_args;			/* optional args */
	uid_t	se_uid;				/* user id */
	gid_t	se_gid;				/* group id */
	struct	syseventtab *se_next;
} syseventtab_t;

typedef struct sysevent_hdr_info {
	char	*class;
	char	*subclass;
	char	*vendor;
	char	*publisher;
} sysevent_hdr_info_t;


/*
 * Structures for building arbitarily long strings and argument lists
 */
typedef struct str {
	char	*s_str;
	int	s_len;
	int	s_alloc;
	int	s_hint;
} str_t;

/*
 * Queue of commands ready to be transported to syseventconfd
 */
typedef struct cmdqueue {
	sysevent_t	*event;
	struct cmdqueue	*next;
} cmdqueue_t;

/*
 * syseventconfd state
 */
enum {
	CONFD_STATE_OK,
	CONFD_STATE_NOT_RUNNING,
	CONFD_STATE_STARTED,
	CONFD_STATE_ERR,
	CONFD_STATE_DISABLED
};


/*
 * Prototypes
 */
static char *skip_spaces(char **cpp);
static char *next_field(char **cpp);
static void *sc_malloc(size_t n);
static void *sc_realloc(void *p, size_t current, size_t n);
static void sc_free(void *p, size_t n);
static char *sc_strdup(char *cp);
static void sc_strfree(char *s);

static str_t *initstr(int hint);
static void freestr(str_t *str);
static void resetstr(str_t *str);
static int strcopys(str_t *str, char *s);
static int strcats(str_t *str, char *s);
static int strcatc(str_t *str, int c);
static char *fstrgets(str_t *str, FILE *fp);
static void strtrunc(str_t *str, int pos);

static void build_event_table(void);
static void free_event_table(void);
static int enter_lock(char *lock_file);
static void exit_lock(int lock_fd, char *lock_file);
static str_t *snip_identifier(char *id, char **end);
static str_t *snip_delimited_identifier(char *id, char **end);
static char *se_attr_type_to_str(int se_attr_type);
static str_t *find_macro_definition(sysevent_t *ev, nvlist_t *nvlist,
	syseventtab_t *sep, char *token, sysevent_hdr_info_t *hdr);
static int expand_macros(sysevent_t *ev, nvlist_t *nvlist,
	syseventtab_t *sep, str_t *line, sysevent_hdr_info_t *hdr);
static void start_syseventconfd(void);
static int system1(const char *s_path, const char *s);
static void abort_cmd_queue(void);
static int queue_event(sysevent_t *ev, syseventtab_t *sep,
	sysevent_hdr_info_t *hdr);
static int transport_event(sysevent_t *cmd);
static void transport_queued_events(void);
static int sysevent_conf_event(sysevent_t *ev, int flag);


#ifdef	__cplusplus
}
#endif

#endif	/* _SYSEVENT_CONF_MOD_H */
