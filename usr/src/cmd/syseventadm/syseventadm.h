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

#ifndef	_SYSEVENTADM_H
#define	_SYSEVENTADM_H

#ifdef	__cplusplus
extern "C" {
#endif

/*
 * Directory where sysevent.conf files reside
 */
#define	SYSEVENT_CONFIG_DIR		"/etc/sysevent/config"

/*
 * Lock file name to serialize registry updates
 */
#define	LOCK_FILENAME	"/var/run/syseventconf.lock"

/*
 * Required suffix for all sysevent.conf files
 */
#define	SYSEVENT_CONF_SUFFIX		",sysevent.conf"

/*
 * cmd types for list/remove
 */
#define	CMD_LIST	0
#define	CMD_REMOVE	1

/*
 * Exit codes
 */
#define	EXIT_OK			0
#define	EXIT_NO_MATCH		1
#define	EXIT_USAGE		2
#define	EXIT_PERM		3
#define	EXIT_CMD_FAILED		4
#define	EXIT_NO_MEM		5

/*
 * sysevent.conf record
 */
typedef struct serecord {
	char	*se_vendor;			/* vendor */
	char	*se_publisher;			/* publisher */
	char	*se_class;			/* event class */
	char	*se_subclass;			/* event subclass */
	char	*se_user;			/* user */
	char	*se_reserved1;			/* reserved1 */
	char	*se_reserved2;			/* reserved2 */
	char	*se_path;			/* event path */
	char	*se_args;			/* optional args */
} serecord_t;


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
 * Prototypes
 */
int main(int argc, char **argv);
static void enter_lock(char *root_dir);
static void exit_lock(void);
static void set_root_dir(char *dir);
static int usage(void);
static int add_cmd(void);
static int list_remove_cmd(int cmd);
static int list_file(char *fname);
static int remove_file(char *fname);
static int check_for_removes(FILE *fp);
static int restart_cmd(void);

static str_t *read_next_line(FILE *fp);
static serecord_t *parse_line(str_t *line);

static int matches_serecord(serecord_t *sep);
static void print_serecord(FILE *fp, serecord_t *sep);
static void free_serecord(serecord_t *sep);

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
static void strcats(str_t *str, char *s);
static void strcatc(str_t *str, int c);
static char *fstrgets(str_t *str, FILE *fp);
static char **build_strlist(char **, int *, int *, char *);

static void no_mem_err(void);

#ifdef	__cplusplus
}
#endif

#endif	/* _SYSEVENTADM_H */
