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
 *
 * Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef _DEVFSADM_IMPL_H
#define	_DEVFSADM_IMPL_H

#ifdef	__cplusplus
extern "C" {
#endif

#include <dlfcn.h>
#include <stdarg.h>
#include <fcntl.h>
#include <sys/file.h>
#include <locale.h>
#include <libintl.h>
#include <ctype.h>
#include <signal.h>
#include <deflt.h>
#include <ftw.h>
#include <sys/instance.h>
#include <sys/types.h>
#include <dirent.h>
#include <pwd.h>
#include <grp.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/mkdev.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <errno.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/int_types.h>
#include <limits.h>
#include <strings.h>
#include <devfsadm.h>
#include <libdevinfo.h>
#include <sys/devinfo_impl.h>
#include <sys/modctl.h>
#include <libgen.h>
#include <sys/hwconf.h>
#include <sys/sunddi.h>
#include <door.h>
#include <syslog.h>
#include <libsysevent.h>
#include <thread.h>
#include <message.h>
#include <sys/cladm.h>
#include <sys/sysevent/dev.h>
#include <libzonecfg.h>
#include <device_info.h>
#include <sys/fs/sdev_impl.h>
#include <sys/syscall.h>
#include <rpcsvc/ypclnt.h>
#include <sys/sysevent/eventdefs.h>

#define	DEV_LOCK_FILE ".devfsadm_dev.lock"
#define	DAEMON_LOCK_FILE ".devfsadm_daemon.lock"

#define	DEV "/dev"
#define	ETC "/etc"
#define	ETCDEV "/etc/dev"
#define	DEV_LEN 4
#define	DEVICES "/devices"
#define	DEVICES_LEN 8
#define	MODULE_DIRS "/usr/lib/devfsadm/linkmod"
#define	ALIASFILE "/etc/driver_aliases"
#define	NAME_TO_MAJOR "/etc/name_to_major"
#define	RECONFIG_BOOT "_INIT_RECONFIG"
#define	PID_STR_LEN 10
#define	EXTRA_PRIVS	"/etc/security/extra_privs"
#define	DEV_POLICY	"/etc/security/device_policy"
#define	LDEV_FILE	"/etc/logindevperm"

#define	DEVFSADM_DEFAULT_FILE "/etc/default/devfsadm"

#define	MINOR_FINI_TIMEOUT_DEFAULT 2

#define	SYNCH_DOOR_PERMS	(S_IRUSR | S_IWUSR)

#define	DRVCONFIG "drvconfig"
#define	DEVFSADM "devfsadm"
#define	DEVFSADMD "devfsadmd"
#define	DEVLINKS "devlinks"
#define	TAPES "tapes"
#define	AUDLINKS "audlinks"
#define	PORTS "ports"
#define	DISKS "disks"

#define	MAX_IDLE_DELAY 5
#define	MAX_DELAY 30
#define	NAME 0x01
#define	ADDR 0x03
#define	MINOR 0x04
#define	COUNTER 0x05
#define	CONSTANT 0x06
#define	TYPE 0x07
#define	TYPE_S "type"
#define	ADDR_S "addr"
#define	ADDR_S_LEN 4
#define	MINOR_S "minor"
#define	MINOR_S_LEN 5
#define	NAME_S "name"
#define	TAB '\t'
#define	NEWLINE '\n'
#define	MAX_DEVLINK_LINE 4028
#define	INTEGER 0
#define	LETTER 1
#define	MAX_PERM_LINE 256
#define	MAX_LDEV_LINE 256
#define	LDEV_DELIMS " \t\n"
#define	LDEV_DRVLIST_DELIMS "="
#define	LDEV_DRV_DELIMS ", \t\n"
#define	LDEV_DEV_DELIM ":"
#define	LDEV_DRVLIST_NAME "driver"
#define	NFP_HASH_SZ 256

#define	TYPE_LINK 0x00
#define	TYPE_DEVICES 0x01

#define	CREATE_LINK 0x01
#define	READ_LINK 0x02
#define	CREATE_NODE 0x01
#define	READ_NODE 0x02

#define	CACHE_STATE 0x0
#define	SYNC_STATE 0x1

#define	MODULE_ACTIVE 0x01

/* Possible flag values for flag member of numeral_t */
#define	NUMERAL_RESERVED 0x01

#define	MAX_SLEEP 120

#define	DEVLINKTAB_FILE "/etc/devlink.tab"

#define	MODULE_SUFFIX ".so"
#define	MINOR_INIT "minor_init"
#define	MINOR_FINI "minor_fini"
#define	_DEVFSADM_CREATE_REG "_devfsadm_create_reg"
#define	_DEVFSADM_REMOVE_REG "_devfsadm_remove_reg"

#define	NUM_EV_STR		4
#define	EV_TYPE			0
#define	EV_CLASS		1
#define	EV_PATH_NAME		2
#define	EV_MINOR_NAME		3

/* add new debug level and meanings here */
#define	DEVLINK_MID		"devfsadm:devlink"
#define	MODLOAD_MID		"devfsadm:modload"
#define	INITFINI_MID		"devfsadm:initfini"
#define	EVENT_MID		"devfsadm:event"
#define	REMOVE_MID		"devfsadm:remove"
#define	LOCK_MID		"devfsadm:lock"
#define	PATH2INST_MID		"devfsadm:path2inst"
#define	CACHE_MID		"devfsadm:cache"
#define	BUILDCACHE_MID		"devfsadm:buildcache"
#define	RECURSEDEV_MID		"devfsadm:recursedev"
#define	INSTSYNC_MID		"devfsadm:instsync"
#define	FILES_MID		"devfsadm:files"
#define	ENUM_MID		"devfsadm:enum"
#define	RSRV_MID		"devfsadm:rsrv"	/* enum interface reserve  */
#define	RSBY_MID		"devfsadm:rsby"	/* enum reserve bypass */
#define	LINKCACHE_MID		"devfsadm:linkcache"
#define	ADDREMCACHE_MID		"devfsadm:addremcache"
#define	MALLOC_MID		"devfsadm:malloc"
#define	READDIR_MID		"devfsadm:readdir"
#define	READDIR_ALL_MID		"devfsadm:readdir_all"
#define	DEVNAME_MID		"devfsadm:devname"
#define	ALL_MID			"all"

#define	DEVFSADM_DEBUG_ON	(verbose == NULL) ? FALSE : TRUE

typedef struct recurse_dev {
	void (*fcn)(char *, void *);
	void *data;
} recurse_dev_t;

typedef struct link {
	char *devlink; /* without ".../dev/"   prefix */
	char *contents; /* without "../devices" prefix */
	struct link *next;
} link_t;

typedef struct linkhead {
	regex_t dir_re_compiled;
	char *dir_re;
	link_t *link;
	link_t *nextlink;
	struct linkhead *nexthead;
} linkhead_t;

typedef struct link_list  {
	int type;
	char *constant;
	int arg;
	struct link_list *next;
} link_list_t;

typedef struct selector_list {
	int key;
	char *val;
	int arg;
	struct selector_list *next;
} selector_list_t;

typedef struct devlinktab_list {
	int line_number;
	char *selector_pattern;
	char *p_link_pattern;
	char *s_link_pattern;
	selector_list_t *selector;
	link_list_t *p_link;
	link_list_t *s_link;
	struct devlinktab_list *next;
} devlinktab_list_t;

typedef struct module {
	char *name;
	void *dlhandle;
	int (*minor_init)();
	int (*minor_fini)();
	int flags;
	struct module *next;
} module_t;

typedef struct create_list {
	devfsadm_create_t *create;
	module_t *modptr;
	regex_t node_type_comp;
	regex_t drv_name_comp;
	struct create_list *next;
} create_list_t;

struct minor {
	di_node_t node;
	di_minor_t minor;
	struct minor *next;
};

struct mlist {
	struct minor *head;
	struct minor *tail;
};

typedef struct remove_list {
	devfsadm_remove_V1_t *remove;
	module_t *modptr;
	struct remove_list *next;
} remove_list_t;

typedef struct item {
	char *i_key;
	struct item *i_next;
} item_t;

typedef struct cleanup_data {
	int flags;
	char *phypath;
	remove_list_t *rm;
} cleanup_data_t;

typedef struct n2m {
	major_t major;
	char *driver;
	struct n2m *next;
} n2m_t;

/* structures for devfsadm_enumerate() */
typedef struct numeral {
	char *id;
	char *full_path;
	int rule_index;
	char *cmp_str;
	struct numeral *next;
	int flags;
} numeral_t;

typedef struct numeral_set {
	int re_count;
	char **re;
	numeral_t *headnumeral;
	struct numeral_set *next;
} numeral_set_t;

typedef struct temp {
	int integer;
	struct temp *next;
} temp_t;

typedef struct driver_alias {
	char *driver_name;
	char *alias_name;
	struct driver_alias *next;
} driver_alias_t;

struct driver_list {
	char driver_name[MAXNAMELEN];
	struct driver_list *next;
};

struct login_dev {
	char *ldev_console;
	int ldev_perms;
	char *ldev_device;
	regex_t ldev_device_regex;
	struct driver_list *ldev_driver_list;
	struct login_dev *ldev_next;
};

#define	MAX_DEV_NAME_COUNT	100
struct devlink_cb_arg {
	char *dev_names[MAX_DEV_NAME_COUNT];
	char *link_contents[MAX_DEV_NAME_COUNT];
	int count;
	int rv;
};

struct dca_impl {
	char *dci_root;
	char *dci_minor;
	char *dci_driver;
	void *dci_arg;
	int dci_error;
	int dci_flags;
};

/* sysevent queue related */
typedef struct syseventq_s {
	struct syseventq_s *next;
	char *class;
	char *subclass;
	nvlist_t *nvl;
} syseventq_t;

static int devfsadm_enumerate_int_start(char *devfs_path,
	int index, char **buf, devfsadm_enumerate_t rules[],
	int nrules, char *start);
static void set_root_devices_dev_dir(char *dir);
static void pre_and_post_cleanup(int flags);
static void hot_cleanup(char *, char *, char *, char *, int);
static void devfsadm_exit(int status);
static void rm_link_from_cache(char *devlink);
static void rm_all_links_from_cache();
static void add_link_to_cache(char *devlink, char *physpath);
static linkhead_t *get_cached_links(char *dir_re);
static void build_devlink_list(char *check_link, void *data);
static void instance_flush_thread(void);
static int s_rmdir(char *path);
static void rm_parent_dir_if_empty(char *path);
static void free_link_list(link_list_t *head);
static void free_selector_list(selector_list_t *head);
void devfsadm_err_print(char *message, ...);
void defvsadm_print(int level, char *message, ...);
static int call_minor_init(module_t *module);
static void load_module(char *module, char *cdir);
static void invalidate_enumerate_cache(void);
static pid_t enter_dev_lock(void);
static void exit_dev_lock(int exiting);
static pid_t enter_daemon_lock(void);
static void exit_daemon_lock(int exiting);
static int process_devlink_compat(di_minor_t minor, di_node_t node);
static int alias(char *, char *);
static int devfsadm_copy(void);
static void flush_path_to_inst(void);
static void detachfromtty(void);
static void minor_process(di_node_t node, di_minor_t minor,
    struct mlist *dep);
static void read_minor_perm_file(void);
static void read_driver_aliases_file(void);
static void load_modules(void);
static void unload_modules(void);
static void *s_malloc(const size_t size);
static void *s_zalloc(const size_t size);
static void devfs_instance_mod(void);
static void add_minor_pathname(char *, char *, char *);
static int check_minor_type(di_node_t node, di_minor_t minor, void *arg);
static void cache_deferred_minor(struct mlist *dep, di_node_t node,
    di_minor_t minor);
static int compare_field(char *full_name, char *field_item, int field);
static int component_cat(char *link, char *name, int field);
static void recurse_dev_re(char *current_dir, char *path_re, recurse_dev_t *rd);
static void matching_dev(char *devpath, void *data);
static int resolve_link(char *devpath, char **content_p, int *type_p,
    char **devfs_path, int dangle);
static int clean_ok(devfsadm_remove_V1_t *remove);
static int translate_major(dev_t old_dev, dev_t *new_dev);
static int get_major_no(char *driver, major_t *major);
static int load_n2m_table(char *filename);
static int get_stat_info(char *, struct stat *);
static char *new_id(numeral_t *, int, char *);
static int find_enum_id(devfsadm_enumerate_t rules[], int nrules,
    char *devfs_path, int index, char *min, int type, char **buf, int multiple);
static void daemon_update(void);
static void usage(void);
static int getnexttoken(char *next, char **nextp, char **tokenpp, char *tchar);
static int class_ok(char *class);
static int create_link_common(char *devlink, char *contents, int *exists);
static char *dequote(char *src);
static void parse_args(int argc, char *argv[]);
static void process_devinfo_tree(void);
static void *minor_fini_thread(void *arg);
static void *s_realloc(void *ptr, const size_t size);
static void read_devlinktab_file(void);
static selector_list_t *create_selector_list(char *selector);
static int parse_selector(char **selector, char **key, char **val);
int devfsadm_noupdate(void);
const char *devfsadm_root_path(void);
static link_list_t *create_link_list(char *link);
static void s_unlink(const char *file);
static void s_closedir(DIR *dirp);
static void s_mkdirp(const char *path, const mode_t mode);
static int is_minor_node(char *contents, char **mn_root);
static int construct_devlink(char *link, link_list_t *link_build,
				char *contents, di_minor_t minor,
				di_node_t node, char *pattern);
static int split_devlinktab_entry(char *entry, char **selector, char **p_link,
	    char **s_link);
static int devlink_matches(devlinktab_list_t *entry, di_minor_t minor,
			    di_node_t node);
static int build_links(devlinktab_list_t *entry, di_minor_t minor,
			di_node_t node);
static numeral_set_t *get_enum_cache(devfsadm_enumerate_t rules[],
				    int nrules);
static void enumerate_recurse(char *current_dir, char *path_left,
    numeral_set_t *setp, devfsadm_enumerate_t rules[], int index);

static int match_path_component(char *file_re, char *file, char **id,
				int subexp);
static void create_cached_numeral(char *path, numeral_set_t *setp,
    char *numeral_id, devfsadm_enumerate_t rules[], int index);
static int devfsadm_copy_file(const char *file, const struct stat *stat,
			    int flags, struct FTW *ftw);
static void getattr(char *devname, char *aminor, int spectype, dev_t dev,
    mode_t *mode, uid_t *uid, gid_t *gid);
static int minor_matches_rule(di_node_t node, di_minor_t minor,
				create_list_t *create);
static void add_verbose_id(char *mid);
static char *get_component(char *str, const char *comp_num);
static char *alloc_cmp_str(const char *devfs_path, devfsadm_enumerate_t *dep);
static int lookup_enum_cache(numeral_set_t *set, char *cmp_str,
    devfsadm_enumerate_t rules[], int index, numeral_t **matchnpp);
static void sync_handler(void *cookie, char *ap, size_t asize,
    door_desc_t *dp, uint_t ndesc);
static int zone_pathcheck(char *checkpath);
static void process_deferred_links(struct dca_impl *dcip, int flag);
static void event_handler(sysevent_t *ev);
static void dca_impl_init(char *root, char *minor, struct dca_impl *dcip);
static void lock_dev(void);
static void unlock_dev(int flag);
static int devlink_cb(di_devlink_t dl, void *arg);
static void free_dev_names(struct devlink_cb_arg *x);

int load_devpolicy(void);
static void load_dev_acl(void);
static void load_minor_perm_file(void);

static nvlist_t *build_event_attributes(char *, char *, char *,
    di_node_t, char *, int, char *);
static void log_event(char *, char *, nvlist_t *);
static void build_and_enq_event(char *, char *, char *, di_node_t, char *);

static void read_logindevperm_file(void);
static void set_logindev_perms(char *devlink);

static void reset_node_permissions(di_node_t, di_minor_t);

/*
 * devname related
 */
static void devname_lookup_handler(void *, char *, size_t,
    door_desc_t *, uint_t);		/* /dev name lookup server */
static int devname_kcall(int, void *);	/* syscall into the devname fs */

static void nfphash_create(void);
static int nfphash_fcn(char *key);
static item_t *nfphash_lookup(char *key);
static void nfphash_insert(char *key);
static void nfphash_destroy(void);

/* Enumerate reserve related */
static void read_enumerate_file(void);
static int enumerate_parse(char *rsvstr, char *path_left, numeral_set_t *setp,
    devfsadm_enumerate_t rules[], int index);
static void create_reserved_numeral(numeral_set_t *setp, char *numeral_id);

/* convenient short hands */
#define	vprint		devfsadm_print
#define	err_print	devfsadm_errprint
#ifndef TRUE
#define	TRUE	1
#endif
#ifndef FALSE
#define	FALSE	0
#endif

#ifdef	__cplusplus
}
#endif

#endif /* _DEVFSADM_IMPL_H */
