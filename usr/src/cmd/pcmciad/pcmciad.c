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
 * Copyright 2006 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 *  PCMCIA User Daemon
 *	This is a newer daemon than the original version.
 *	It is a restructuring to use multiple threads
 *	and LWP in order to not lose any events and
 *	to better be able to service devices.  It has
 *	hooks for using external processing functions
 *	of various types.
 *
 *	If you add a new built-in handler, please keep its functions
 *	grouped together.
 *
 *	The prototype external shared object code assumes that you
 *	have three entry points defined.  It doesn't load global.
 *	The entry points are:
 *	void handler(char *, char *, int, int, void *)
 *	void init(void)
 *	void fini(void)
 *
 *	If init() doesn't exist it isn't called and fini() currently
 *	isn't ever called.  handler() must exist.  They must use these
 *	these specific names.
 *
 *	init() is called just before the first time the handler is to
 *	be called.  This allows any initial setup that might be
 *	necessary.  It is only called once.
 *
 *	External handlers can reference symbols in the main program
 *	but the symbols will be invisible across handlers.
 */

#include	<stdio.h>
#include	<stdlib.h>
#include	<unistd.h>
#include	<ctype.h>
#include	<fcntl.h>
#include	<sys/types.h>
#include	<sys/fcntl.h>
#define	_KERNEL
#include	<sys/dditypes.h>
#undef _KERNEL
#include	<sys/sunddi.h>
#include	<sys/ddi_impldefs.h>
#include	<sys/pctypes.h>
#include	<sys/stream.h>
#include	<stropts.h>
#include	<sys/modctl.h>
#include	<sys/signal.h>
#include	<sys/sad.h>
#include	<sys/pem.h>
#include	<sys/pcmcia.h>
#include	<sys/sservice.h>
#include	<string.h>
#include	<search.h>
#include	<ftw.h>
#include	<pwd.h>
#include	<grp.h>

/* memory card support headers */
#include	<errno.h>
#include	<dirent.h>
#include	<signal.h>
#include	<limits.h>
#include	<sys/stat.h>
#include	<sys/mnttab.h>
#include	<sys/wait.h>
#include	<sys/dkio.h>

#include	<thread.h>
#include	<synch.h>

#include	<dlfcn.h>

/*
 * pcmciad
 *
 * the basic daemon is a multithreaded entity that listens for
 * PCMCIA events and acts on them.
 * one thread just reads the event driver and constructs work requests
 * on a per-socket work queue.  A wakeup is given to the work thread
 * for that work queue.  When the work thread wakes up, it starts
 * processing its queue one item at a time until the queue is empty.
 * It then goes to sleep and waits to get another work item.
 *
 * One additional thread is used for processing special commands
 * that need to be serialized in order to avoid problems.  The list of
 * commands is currently "drvconfig, disks".
 *
 * note that the work to be done is driver dependent.
 * The daemon makes every attempt to identify what needs to be done
 * and call the driver specific functions.  If nothing is found then
 * a default behavior is used (modload the driver and then call
 * devlinks is the built in behavior)
 */

/*
 * The macros defined here that are used to specify the encoding
 *	of the socket and function number fields must match the
 *	functionality of the similar macros defined in cs_priv.h
 * Since this daemon code is going to be completely replaced in
 *	Solaris 2.7 by the generic DDI hotplug framework, no
 *	effort was made to include cs_priv.h
 * The following is taken from cs_priv.h:
 *      The encoding of the socket number is:
 *
 *              xxxxxxxx | xxxxgfff | xxxxxxxx | xsssssss
 *
 *      g - global CIS bit
 *      f - function number bit
 *      s - socket number bit
 *      x - don't care bits
 */
#define	SOCKET(socket)		((socket) & (PCMCIA_MAX_SOCKETS - 1))
#define	FUNCTION(socket)	(((socket) >> 16) & (PCMCIA_MAX_FUNCTIONS - 1))
#define	XSOCKET(socket, func)	(((socket & (PCMCIA_MAX_SOCKETS - 1))) | \
				(((func) & (PCMCIA_MAX_FUNCTIONS - 1)) << 16))

/*
 * daemon global variables and datatypes
 */
/* prototypes for per driver functions */
static void serial(char *, char *, int, int, void *);
static void serinit(void);

static void defhandler(char *, char *, int, int, void *);

typedef void (* function_t)(char *, char *, int, int, void *);
typedef void (* if_func_t)(void);

static void memory(char *, char *, int, int, void *);
static void meminit(void);

static void disk(char *, char *, int, int, void *);
static void diskinit(void);

#define	MAX_DRIVERS		128

#define	DRV_NOT_INIT		0x0002
#define	DRV_NOT_LOAD		0x0001
#define	DRV_SHARED_OBJ		0x0004
#define	DRV_SHELL_SCRIPT	0x0008

struct driver_specific {
	char	*driver;
	char	*class;
	uint_t   flags;
	function_t handler;
	if_func_t init;
	if_func_t fini;
	void	*handle;
};
static struct driver_specific driver_map[MAX_DRIVERS] = {
	{"pcser", "serial", DRV_NOT_INIT, serial, serinit, NULL},
	{"pcmem", "memory", DRV_NOT_INIT, memory, meminit, NULL},
	{"pcata", "disk", DRV_NOT_INIT, disk, diskinit, NULL}
};

static int num_drivers = 3;

struct work {
	struct work *next, *prev;
	union em_primitives *prim;
};

struct tasklist {
	struct work	work;
	mutex_t		lock;
	cond_t		sleep;
	thread_t	thread;
	function_t	drivers[8];
};
static struct tasklist	**tasklists;

struct driver_aliases {
	struct driver_aliases *next;
	char	*name;
	char	*alias;
};
static struct driver_aliases	*aliases = NULL;

#define	DBG_ALL		0xffff
#define	DBG_SETUP	0x0001
#define	DBG_MODLOAD	0x0002
#define	DBG_TASK	0x0004
#define	DBG_DEVSETUP	0x0008
#define	DBG_SYSCALL	0x0010
#define	DBG_ALIASING	0x0080

static int debug = 0;

static int pem;			/* event manager descriptor */

/*
 * Global mutexes to single-thread certain card handler
 *	routines.
 */
static void init_global_locks();
#ifndef	lint
static mutex_t serinit_lock;
static mutex_t meminit_lock;
#endif

#define	DEFAULT_DIR	"/usr/lib/pcmcia"

static char *default_dir = DEFAULT_DIR;
static char *device = "/dev/pem";
static char *pcmcia_root_dir = "/devices";

#ifndef	lint
static char *pcmcia_driver_class = "root";
#endif

static int num_sockets;		/* current number of sockets */

static int task_state = 0;	/* zero is not running */

/* prototypes used internally */
static char *find_alias(char *);
static void init_aliases(char *);
static void drv_init_table(char *);
static void em_init(int);
static void setup_autopush(char *);
static void *event_read(void *);

static void task_create(int);
static void task_init(int);

static int is_blank(char *);

int
main(int argc, char *argv[])
{
	sigset_t	sigs;
	int		c;


	while ((c = getopt(argc, argv, "Dd:l:")) != EOF) {
		switch (c) {
		case 'D':
			debug = (debug << 1) | 1;
			break;
		case 'd':
			device = optarg;
			break;
		case 'l':
			default_dir = optarg;
			break;
		default:
			(void) fprintf(stderr,
				"usage: pcmciad [-D] [-d device]\n");
			exit(1);
		}
	}

	if (debug)
		(void) printf("debug level 0x%x\n", debug);

	(void) chdir(default_dir);
	(void) init_aliases("/etc/driver_aliases");
	(void) drv_init_table(default_dir);
	(void) init_global_locks();

	pem = open(device, O_RDWR);
	if (pem < 0) {
		if (debug)
			perror(device);
		exit(2);
	}
	if (!debug) {
		(void) close(0);
		(void) close(1);
		(void) close(2);
		if (fork() == 0) {
			(void) setsid();
		} else {
			exit(0);
		}
	} else {
		setbuf(stdout, NULL);
	}

	(void) em_init(pem);

	task_state = 1;		/* mark as running */
	(void) task_init(num_sockets);

#ifndef	lint
	(void) thr_setconcurrency(thr_getconcurrency() + 1);

	if (debug) {
		(void) printf("concurrency == %d\n",
					thr_getconcurrency());
	}
#endif

	/*
	 * the per-socket threads are up and running
	 * so we now start the work finding task
	 */
#ifdef	lint

	(void *) event_read(0);
#else
	if (thr_create(NULL, 0, event_read, (void *) pem,
		THR_BOUND | THR_NEW_LWP | THR_DAEMON, NULL) != 0)
		exit(0x20);
#endif

	(void) sigfillset(&sigs);

#ifndef	lint
	if (thr_sigsetmask(SIG_BLOCK, &sigs, NULL) < 0)
		perror("thr_sigsetmask");
#endif
	(void) sigpause(1);
	return (0x22);
}

/*
 * is_blank() returns 1 (true) if a line specified is composed of
 * whitespace characters only. otherwise, it returns 0 (false).
 *
 * Note. the argument (line) must be null-terminated.
 */
static int
is_blank(char *line)
{
	for (/* nothing */; *line != '\0'; line++)
		if (!isspace(*line))
			return (0);
	return (1);
}

/*
 * alias handling
 * we need to be able to find the mapping between certain
 * device names and the appropriate driver.  This code
 * searches the driver alias list.  It needs to know when
 * to re-read and reconstruct the list in the event of new
 * aliases being added.
 */

/*
 * init_aliases(filename)
 *	read in the aliases file and construct a fast lookup
 *	list.  We don't want to read every time since that could
 *	take too long in multiple event conditions.
 */

static void
init_aliases(char *path)
{
	FILE *file;
	char name[128], alias[128], line[256], *cp;
	int i, len;
	struct driver_aliases *nalias;

	file = fopen(path, "r");
	if (file != NULL) {
		while (fgets(line, sizeof (line), file) != NULL) {
			/* cut off comments starting with '#' */
			if ((cp = strchr(line, '#')) != NULL)
				*cp = '\0';
			/* ignore comment or blank lines */
			if (is_blank(line))
				continue;
			/* sanity-check */
			if (sscanf(line, "%s %[^\n]\n", name, alias) != 2)
				continue;
			if (alias[0] == '"') {
				len = strlen(alias);
				for (i = 1; i < len; i++)
					alias[i-1] = alias[i];
				alias[len-2] = '\0';
			}
			nalias = malloc(sizeof (struct driver_aliases));
			if (nalias == NULL)
				break;
			nalias->name = strdup(name);
			nalias->alias = strdup(alias);
			nalias->next = aliases;
			aliases = nalias;
			if (debug & DBG_ALIASING) {
				(void) printf("add alias: %s <- %s\n",
							name, alias);
			}
		}
		(void) fclose(file);
	}
}

/*
 * find_alias(name)
 *	look up name in the alias list and return either the alias
 *	or NULL (if none found).
 */

char *
find_alias(char *name)
{
	struct driver_aliases *alias;
	for (alias = aliases; alias != NULL; alias = alias->next) {
		if (debug & DBG_ALIASING) {
			(void) printf("alias: %s == %s [name = %s]\n",
					name, alias->alias, alias->name);
		}
		if (strcmp(name, alias->alias) == 0)
			return (alias->name);
	}
	return (NULL);
}

/*
 * driver handler lookup, initialization functions
 */

static void
drv_init_table(char *dir)
{
	DIR *dfd;
	char driver[64], *cp;
	struct dirent *dirx;
	int drvr, found = 0, flags;

	dfd = opendir(dir);
	if (dfd == NULL) {
		return;
	}
	for (; num_drivers < MAX_DRIVERS; ) {
		dirx = readdir(dfd);
		if (dirx == NULL)
			break;
		/* skip dot names */
		if (dirx->d_name[0] == '.')
			continue;
		cp = strchr(dirx->d_name, '.');
		if (cp == NULL) {
			/*
			 * not a .so so skip for now
			 * later could be a shell script or
			 * other scripting function or a
			 * directory for class specific
			 * drivers
			 */
			if (debug & DBG_DEVSETUP) {
				(void) printf("Skipping: %s\n",
							dirx->d_name);
			}
			continue;
		}
		/*
		 * as support is added for different types of objects,
		 * the appropriate check and setup should be done
		 * here. Some possible future additions:
		 * .sh (shell), .pl (perl) and .exe (executable)
		 */
		if (strcmp(cp, ".so.1") == 0) {
			/*
			 * we have an object so claim it
			 */
			(void) memset(driver, '\0', sizeof (driver));
			(void) strncpy(driver, dirx->d_name,
						cp - dirx->d_name);
			found = 1;
			flags = DRV_NOT_INIT |
				DRV_NOT_LOAD | DRV_SHARED_OBJ;
		}
		if (found) {
			/* want to replace if new module found */
			for (drvr = 0; drvr <= num_drivers; drvr++)
				if (strcmp(driver_map[drvr].driver, driver) ==
				    0)
					break;
			driver_map[drvr].driver = strdup(driver);
			driver_map[drvr].class = "*";
			driver_map[drvr].flags = flags;
			if (debug & DBG_DEVSETUP)
				(void) printf("Found %s (%s) "
					"as shared object\n",
					dirx->d_name,
					driver_map[drvr].driver);
			num_drivers++;
		}
	}
}

static int
drv_load(struct driver_specific *driver)
{
	void *handle;
	char path[256];

	if (driver == NULL)
		return (0);
	if (driver->flags & DRV_SHARED_OBJ &&
				driver->flags & DRV_NOT_LOAD) {
		(void) sprintf(path, "%s/%s.so.1", default_dir,
						driver->driver);
		handle = dlopen(path, RTLD_LAZY);
		if (handle == NULL)
			return (0);
		/* now have a handle so get the three functions */
		driver->handle = handle;
		driver->init = (if_func_t)dlsym(handle, "init");
		driver->handler = (function_t)dlsym(handle, "handler");
		driver->fini = (if_func_t)dlsym(handle, "fini");
		if (driver->handler != NULL)
			driver->flags &= ~DRV_NOT_LOAD;
		if (driver->init == NULL)
			driver->flags &= ~DRV_NOT_INIT;
		return (1);
	}
	return (0);
}

static void *
find_handler(char *name)
{
	char *alias;
	int i;
	alias = find_alias(name);
	if (alias != NULL) {
		for (i = 0; i < num_drivers; i ++) {
			if (strcmp(name, driver_map[i].driver) == 0 ||
			    strcmp(alias, driver_map[i].driver) == 0) {
				if (debug)
					(void) printf(
						"found handler for %s "
						"(flags=%x)\n",
						driver_map[i].driver,
						driver_map[i].flags);
				if (driver_map[i].flags & DRV_NOT_LOAD) {
					(void) printf("load driver\n");
					if (drv_load(&driver_map[i])) {
						driver_map[i].init();
						driver_map[i].flags &=
							~DRV_NOT_INIT;
					}
				}
				if (driver_map[i].flags & DRV_NOT_INIT) {
					driver_map[i].init();
					driver_map[i].flags &= ~DRV_NOT_INIT;
				}

				return ((void *)driver_map[i].handler);
			}
		}
	}

	return ((void *) defhandler);
}

/*
 * fix_device_path(root, dev)
 *	for a new device that was created during a MODCONFIG, it
 *	is necessary to either run "drvconfig" which takes too long
 *	or patch the new name which ended up with a ".." prepended
 *	to the name.
 */

static void
fix_device_path(char *root, char *dev)
{
	char *rootdir, *cp, *lastpart, *newname;

	if ((rootdir = (char *)malloc(strlen(root) + strlen(dev) + 4))
							== NULL) {
	    if (debug & DBG_DEVSETUP) {
		perror("pcmciad: fixup_devnames malloc");
	    }
	    return;
	}
	if ((newname = (char *)malloc(strlen(root) + strlen(dev) + 4))
							== NULL) {
	    if (debug) {
		perror("pcmciad: fixup_devnames malloc");
	    }
	    return;
	}

	if (debug & DBG_DEVSETUP) {
		(void) printf("fixup_devnames(%s, %s)\n", root, dev);
	}
	lastpart = strrchr(dev, '/');
	if (lastpart == NULL)
		return;
	lastpart++;
	if (debug & DBG_DEVSETUP)
		(void) printf("\tlastpart = %s\n", lastpart);

	(void) sprintf(rootdir, "%s%s", root, dev);
	(void) sprintf(newname, "%s%s", root, dev);
	/* get last component to replace */
	cp = strrchr(rootdir, '/') + 1;
	(void) sprintf(cp, "..%s", lastpart);
	if (debug & DBG_DEVSETUP) {
	    (void) printf("\tfixup_devnames: starting at [%s]\n",
			rootdir);
	    (void) printf("fixup_devnames: rename(%s, %s)\n",
			rootdir, newname);
	}
	(void) rename(rootdir, newname);
	free(rootdir);
	free(newname);

}

/*
 * initialize the event interface.
 */

static void
em_init(int fd)
{
	uchar_t			*evp;
	em_init_req_t		*init;
	em_adapter_info_req_t	*info;
	em_adapter_info_ack_t	*infoack;
	struct strbuf		strbuf;
	int			flags, i;
	char			buff[1024];


	if (debug & DBG_SETUP) {
		(void) printf("em_init(%d)\n", fd);
	}

	/* LINTED lint won't shut up about this line */
	init = (em_init_req_t *)buff;
	(void) memset(buff, '\0', sizeof (buff));

	init->em_primitive = EM_INIT_REQ;
	init->em_logical_socket = -1; /* all sockets */
	init->em_event_mask_offset = sizeof (em_init_req_t);
	init->em_event_mask_length = sizeof (ulong_t);

	evp = (uchar_t *)buff + sizeof (em_init_req_t);
	/* LINTED lint won't shut up about this line */
	*(ulong_t *)evp = -1;	/* all events */

	strbuf.maxlen = sizeof (em_init_req_t) + sizeof (ulong_t);
	strbuf.len = strbuf.maxlen;
	strbuf.buf = buff;

	if (putmsg(fd, &strbuf, NULL, 0) < 0) {
		perror("putmsg");
		exit(2);
	}

	if (debug & DBG_SETUP) {
		(void) printf("\tsent EM_INIT_REQ\n");
	}

	strbuf.maxlen = sizeof (buff);
	flags = 0;
	if (getmsg(fd, &strbuf, NULL, &flags) < 0) {
		perror("em_init: getmsg");
		exit(3);
	}

	if (debug & DBG_SETUP) {
		(void) printf("\treceived primitive: %d\n",
		    (int)init->em_primitive);
	}

	/* LINTED lint won't shut up about this line */
	info = (em_adapter_info_req_t *)buff;
	info->em_primitive = EM_ADAPTER_INFO_REQ;
	strbuf.maxlen = sizeof (em_adapter_info_req_t);
	strbuf.len = strbuf.maxlen;
	strbuf.buf = buff;
	if (putmsg(fd, &strbuf, NULL, 0) < 0) {
		perror("putmsg");
		exit(2);
	}

	if (debug & DBG_SETUP) {
		(void) printf("\tsent EM_ADAPTER_INFO_REQ\n");
	}

	strbuf.maxlen = sizeof (buff);
	flags = 0;
	if (getmsg(fd, &strbuf, NULL, &flags) < 0) {
		perror("em_init: getmsg");
		exit(3);
	}

	/* LINTED lint won't shut up about this line */
	infoack = (em_adapter_info_ack_t *)buff;
	if (infoack->em_primitive == EM_ADAPTER_INFO_ACK) {
		if (debug & DBG_SETUP) {
			(void) printf("adapter info:\n");
			(void) printf("\tsockets: %d\n",
			    (int)infoack->em_num_sockets);
			(void) printf("\twindows: %d\n",
			    (int)infoack->em_num_windows);
		}

		num_sockets = infoack->em_num_sockets;
		for (i = 0; i < num_sockets; i++) {
			em_ident_socket_req_t *ident;
			int f;
			for (f = 0; f < PCMCIA_MAX_FUNCTIONS; f++) {
				/* LINTED lint won't shut up about this line */
				ident = (em_ident_socket_req_t *)buff;
				ident->em_primitive = EM_IDENT_SOCKET_REQ;
				ident->em_socket = XSOCKET(i, f);
				strbuf.maxlen = sizeof (em_ident_socket_req_t);
				strbuf.len = strbuf.maxlen;
				strbuf.buf = buff;
				if (putmsg(fd, &strbuf, NULL, 0) < 0) {
					perror("putmsg");
				}
			}
		}
	} else {
		if (debug & DBG_TASK) {
			(void) printf("\treceived primitive: %d\n",
				(int)infoack->em_primitive);
		}
	}
}

/*
 * event_read(fd)
 *	read event from the event manager driver.
 *	This is run as a bound thread so that it won't ever
 *	have to wait for a thread to become available.
 *	This is the whole driving force behind the tasks.
 */

static char cbuff[4096];
static char dbuff[4096];

static void *
event_read(void *xx)
{
	union em_primitives *prim;
	struct strbuf ctl, data;
	struct tasklist *task;
	int fd = (int)xx;
	int running;
	sigset_t sigs;

	/*
	 * before doing anything else, make sure other threads
	 * won't kill us with spurious signals
	 */
	(void) sigfillset(&sigs);
#ifndef	lint
	if (thr_sigsetmask(SIG_BLOCK, &sigs, NULL) < 0)
		perror("thr_sigsetmask");
#endif

	for (running = 1; running; ) {
		int flags = 0;
		data.maxlen = sizeof (dbuff);
		data.buf = dbuff;

		ctl.maxlen = sizeof (cbuff);
		ctl.buf = cbuff;

		(void) memset(cbuff, '\0', sizeof (cbuff));

		if (getmsg(fd, &ctl, &data, &flags) < 0) {
			if (errno != EINTR && errno != EBUSY &&
						errno != ENOENT) {
				perror("event_read: getmsg");
				exit(0x10);
			} else
				continue;
		}

		/* LINTED lint won't shut up about this line */
		prim = (union em_primitives *)cbuff;
		if (prim->em_primitive != EM_EVENT_IND) {
			(void) fprintf(stderr,
					"unexpected indicator\n");
		} else {
			struct work *work;
			/*
			 * now have an event indicator
			 * find the socket and dup the message then
			 * queue the message onto the work list
			 */
			prim = (union em_primitives *)malloc(ctl.len);
			if (prim == NULL) {
				continue;
			}
			(void) memcpy((char *)prim, cbuff, ctl.len);
			task = tasklists[
			    SOCKET(prim->event_ind.em_logical_socket)];
			work = (struct work *)malloc(sizeof (struct work));
			if (work == NULL) {
				free(prim);
				continue;
			}
			work->prim = prim;

			if (debug & DBG_TASK) {
			    (void) printf("socket %d: function %d about to "
						"queue work\n",
				(int)
				SOCKET(prim->event_ind.em_logical_socket),
				(int)
				FUNCTION(prim->event_ind.em_logical_socket));
			}
#ifndef	lint
			(void) mutex_lock(&task->lock);
#endif
			insque((struct qelem *)work,
				(struct qelem *)task->work.prev);
			if (debug & DBG_TASK)
				(void) printf("...done\n");
#ifndef	lint
			(void) cond_broadcast(&task->sleep);
			(void) mutex_unlock(&task->lock);
#endif
		}
	}
	/* NOTREACHED */
	return ((void *) NULL);
}

/*
 * event_process(socket, prim)
 *	when a socket thread wakes up and finds work
 *	it calls this function to decode the event
 *	indication.  Currently, only events are processed
 * Only the sockert number is passed in the "socket"
 *	arguemnt - the function number is not encoded
 *	in the "socket" argument.
 */
static void
event_process(int socket, union em_primitives *prim)
{
	struct tasklist *task;
	int function, i;
	char *name = "*";
	char *class = "*";
	struct pcm_make_dev	*md = NULL;
	void *arg = NULL;

	function = FUNCTION(prim->event_ind.em_logical_socket);
	socket = SOCKET(socket);
	task = tasklists[socket];

	if (debug & DBG_TASK) {
		(void) printf("event_process(%d, %d, %x)\n",
				socket, function, (int)prim);
	}

	switch (prim->em_primitive) {
		/* general "event" indication */
	case EM_EVENT_IND:
		/*
		 * some events are handled in here directly
		 * or are done here and in the specific code
		 */
		if (debug & DBG_TASK) {
			(void) printf("event = %d\n",
				(int)prim->event_ind.em_event);
		}
		switch (prim->event_ind.em_event) {
		case PCE_CARD_INSERT:
			/*
			 * card insertion must be preprocessed
			 * in the daemon common code since we
			 * don't know the drivers yet.
			 * it is a time for cleanup. The driver
			 * specific code will get this on ident.
			 */
			for (i = 0; i < PCMCIA_MAX_FUNCTIONS; i++)
				task->drivers[i] = defhandler;
			return;

		case PCE_CARD_REMOVAL:
			/*
			 * driver specific processing is
			 * all we need to do. cleanup on insert.
			 */
			break;

		case PCE_DEV_IDENT:
			/*
			 * do a modload to make things start running.
			 * this only does something the first time
			 * but that time is needed.
			 */
			name = ((char *)prim) +
				prim->event_ind.em_event_info_offset;
			arg = (void *)name;

			/*
			 * now identify the driver and setup
			 * per driver function info
			 */
			task->drivers[function] =
				(function_t)find_handler(name);
			task->drivers[function](name, "*",
						PCE_CARD_INSERT,
						socket, NULL);
			break;

		case PCE_INIT_DEV:
			/* LINTED lint won't shut up about this line */
			md = (struct pcm_make_dev *)(((char *)prim) +
				prim->event_ind.em_event_info_offset);
			if (debug & DBG_DEVSETUP) {
			    (void) printf("prim=%x, offset = %x (%s)\n",
				(int)prim,
				(int)prim->event_ind.em_event_info_offset,
				md->op == SS_CSINITDEV_CREATE_DEVICE ?
				"create" : "remove");
			}
			if (debug & DBG_DEVSETUP)
				(void) printf("\tmd = %x\n", (int)md);
			arg = (void *)md;
			break;

		default:
			arg = (void *) (prim);
			break;
		}
		task->drivers[function](name, class,
					prim->event_ind.em_event,
					socket, arg);
	}
}

/*
 * task_socket(socket)
 *	this is the thread code for per-socket tasks.
 *	it will check for work and sleep on its condition
 *	variable when there is no work.
 */

static void *
task_socket(void *socket_val)
{
	struct tasklist *task;
	int socket = (int)socket_val;
	struct work *work;

	task = tasklists[socket];
	while (task_state) {
		if (debug & DBG_TASK) {
		    (void) printf(
			"task socket(%d) checking for work %x:%x\n",
			socket, (int)task->work.next,
			(int)task->work.prev);
		}
#ifndef	lint
		(void) mutex_lock(&task->lock);
		while (task->work.next == &task->work) {
			/* nothing to do so go to sleep */
			(void) cond_wait(&task->sleep, &task->lock);
		}
#endif
		if (debug & DBG_TASK) {
			(void) printf("task socket(%d) have work\n",
								socket);
		}
		/* we have a work item so get it and remove from list */
		work = task->work.next;
		remque((struct qelem *)task->work.next);
#ifndef	lint
		(void) mutex_unlock(&task->lock);
#endif
		/* we have work item isolated so process it */
		(void) event_process(socket, work->prim);
		free(work->prim);
		free(work);
	}
	return (0);
}

/*
 * task_create(socket)
 *	create a task (structure and thread) for specified socket
 */
static void
task_create(int socket)
{
	int		err = 0;
	struct tasklist *task;


	task = (struct tasklist *)malloc(sizeof (struct tasklist));
	tasklists[socket] = task;
#ifndef	lint
	(void) cond_init(&task->sleep, USYNC_THREAD, 0);
	(void) mutex_init(&task->lock, USYNC_THREAD, 0);
#endif
	task->work.next = &task->work;
	task->work.prev = &task->work;
	/*
	 * create a thread for the socket/tasklist
	 * note that the work list is empty so the thread will
	 * immediately block in a wait on the condition.
	 * nothing will add a work item until all threads are
	 * created so no need to start it suspended
	 */
#ifdef	lint
	(void *) task_socket(0);
	if (err) {
#else
	if ((err = thr_create(NULL, 0, task_socket, (void *) socket,
					0, &task->thread)) != 0) {
#endif
		errno = 0;
		if (debug & DBG_SETUP)
			(void) fprintf(stderr,
					"nothread on %d (err=%d)\n",
					socket, err);
		perror("thr_create");
	}
}


/*
 * task_init(sockets)
 *	given the number of sockets, go through and initialize
 *	a task list and thread for them.
 */
static void
task_init(int sockets)
{
	int i;

	/*
	 * in order to deal with new sockets coming online use
	 * sockets * 2 as the preallocated list.  We may have to
	 * revisit if we can get more than twice the number dynamically.
	 */
	tasklists = (struct tasklist **)malloc(sizeof (struct tasklist *) *
						(num_sockets * 2));
	if (tasklists == NULL)
		exit(4);
	for (i = 0; i < sockets; i++) {
		(void) task_create(i);
	}
}

/*
 * defhandler(driver, class, event, socket, data)
 *	default handler for drivers that don't need much
 */

static void
defhandler(char *driver, char *class, int event, int socket, void *data)
{
	if (debug & DBG_TASK) {
		(void) printf("defhandler(%s, %s, %x, %x, %x)\n",
			driver, class, event, socket, (int)data);
	}

	switch (event) {
	case PCE_INIT_DEV:
		(void) system("/usr/sbin/devlinks");
		break;
	}
}


/* serial handler functions */

#define	SER_MODE_TERM_DEFAULT	0666	/* rw-rw-rw- */
#define	SER_TERM_UID_DEFAULT	0	/* root UID */
#define	SER_TERM_GID_DEFAULT	3	/* sys GID */
#define	SER_TERM_USER_DEFAULT	"root"
#define	SER_TERM_GROUP_DEFAULT	"sys"

#define	SER_MODE_CUA_DEFAULT	0600	/* rw------- */
#define	SER_CUA_UID_DEFAULT	5	/* uucp UID */
#define	SER_CUA_GID_DEFAULT	5	/* uucp GID */
#define	SER_CUA_USER_DEFAULT	"uucp"
#define	SER_CUA_GROUP_DEFAULT	"uucp"

static int ser_mode_term;
static int ser_term_uid;
static int ser_term_gid;

static int ser_mode_cua;
static int ser_cua_uid;
static int ser_cua_gid;

static void
serinit()
{
	struct passwd *pw;
	struct group *gr;

#ifndef	lint
	(void) mutex_lock(&serinit_lock);
#endif

	setpwent();
	setgrent();

	/*
	 * Setup the dial-in devices
	 * /dev/term devices are linked
	 *	to these.
	 */
	ser_mode_term = SER_MODE_TERM_DEFAULT;
	ser_term_uid = SER_TERM_UID_DEFAULT;
	ser_term_gid = SER_TERM_GID_DEFAULT;

	if ((pw = getpwnam(SER_TERM_USER_DEFAULT)) != NULL) {
	    if ((gr = getgrnam(SER_TERM_GROUP_DEFAULT)) != NULL) {
		ser_term_uid = pw->pw_uid;
		ser_term_gid = gr->gr_gid;
	    } /* getgrnam */
	} /* getpwnam */

	/*
	 * Setup the dial-out devices
	 * /dev/cua devices are linked
	 *	to these.
	 */
	ser_mode_cua = SER_MODE_CUA_DEFAULT;
	ser_cua_uid = SER_CUA_UID_DEFAULT;
	ser_cua_gid = SER_CUA_GID_DEFAULT;

	if ((pw = getpwnam(SER_CUA_USER_DEFAULT)) != NULL) {
	    if ((gr = getgrnam(SER_CUA_GROUP_DEFAULT)) != NULL) {
		ser_cua_uid = pw->pw_uid;
		ser_cua_gid = gr->gr_gid;
	    } /* getgrnam */
	} /* getpwnam */

	endgrent();
	endpwent();

#ifndef	lint
	(void) mutex_unlock(&serinit_lock);
#endif
}

/*
 * serial(driver, class, event, socket, data)
 *	default serial device handler
 */
static void
serial(char *driver, char *class, int event, int socket, void *data)
{
	char path[MAXPATHLEN];
	char device[MODMAXNAMELEN];
	int ser_mode, ser_uid, ser_gid;
#ifdef	lint
	driver = driver;
	class = class;
#endif

	socket = SOCKET(socket);

	if (debug & DBG_TASK) {
		(void) printf("serial(0x%x, 0x%x, 0x%x)\n",
					event, socket, (int)data);
	}

	switch (event) {
	case PCE_INIT_DEV:
		{
			struct pcm_make_dev *md = (struct pcm_make_dev *)data;
			char *cp, *dir;

			if (md->op == SS_CSINITDEV_REMOVE_DEVICE)
				break;

			cp = strrchr(md->path, ',');
			setup_autopush(md->driver);
			if (cp && strcmp(cp, ",cu") == 0) {
				dir = "cua";
				ser_mode = ser_mode_cua;
				ser_uid = ser_cua_uid;
				ser_gid = ser_cua_gid;
			} else {
				dir = "term";
				ser_mode = ser_mode_term;
				ser_uid = ser_term_uid;
				ser_gid = ser_term_gid;
			}
			(void) sprintf(device, "/dev/%s/pc%d",
							dir, socket);
			(void) sprintf(path, "../../devices%s",
							md->path);
			if (debug & DBG_TASK) {
				(void) printf("symlink(%s, %s)\n",
						path, device);
			}
			(void) unlink(device);
			if (symlink(path, device) < 0 &&
						debug & DBG_SYSCALL) {
				char error[64];
				(void) sprintf(error, "symlink: %s",
								device);
				perror(device);
			}
			if (chmod(device, ser_mode) < 0)
				perror("chmod");
			if (chown(device, ser_uid, ser_gid) < 0)
				perror("chown");
		}
		break;
	}
}

static void
setup_autopush(char *driver)
{
#ifdef	lint
	driver = driver;
	return;
#else
	major_t			major_num;
	struct strapush		push;
	int			sadfd;


	if ((modctl(MODGETMAJBIND, driver, strlen(driver) + 1,
		    &major_num)) < 0) {
		if (debug & DBG_SYSCALL) {
			perror("modctl(MODGETMAJBIND)");
		}
	    return;
	} else {
	    if (debug & DBG_SYSCALL) {
		(void) printf("\tdriver = [%s], major_num = %d\n",
		    driver, (int)major_num);
	    }

	    push.sap_major = major_num;
	    push.sap_minor = 0;
	    push.sap_lastminor = 255;
	    push.sap_cmd = SAP_ALL;

	    /* XXX need to look at /etc/iu.ap instead */
	    (void) strcpy(push.sap_list[0], "ldterm");
	    (void) strcpy(push.sap_list[1], "ttcompat");
	    push.sap_npush = 2;

	    if ((sadfd = open(ADMINDEV, O_RDWR)) < 0) {
		if (debug & DBG_SYSCALL) {
		    perror("open(ADMINDEV)");
		}
		return;
	    } else {
		if (ioctl(sadfd, SAD_SAP, &push) < 0) {
			if (debug & DBG_SYSCALL) {
				perror("\tioctl(SAD_SAP)");
			}
		}
		(void) close(sadfd);
	    }
	}
#endif
}


/*
 * Common define for the memory() and disk() function handler
 */
#define	VOLDSK_PATH	"/vol/dev/dsk"
#define	VOLRDSK_PATH	"/vol/dev/rdsk"
#define	DEVDSK_PATH	"/dev/dsk"
#define	DEVRDSK_PATH	"/dev/rdsk"
#define	START_CHAR	'c'
#define	PDIR		"/var/run/pcmcia" /* piped directory */


/* code for the memory() function handler */
#define	VOLD_TYPE_PCRAM	"pcram"
#define	PCMEM_PATH	"/pcmem"
#define	PCRAM_FILE	"/var/run/pcmcia/pcram" /* special pipe file */

static void unmount_media(long, char *);
static void signal_vold(long, char *);
int volmgt_running();
char *media_findname(char *);

/*
 * memory(driver, class, event, socket data)
 *	this is the default memory card handler
 */

static void
meminit()
{
	static void makepdir();

#ifndef	lint
	mutex_lock(&meminit_lock);
#endif

	(void) makepdir();

#ifndef	lint
	mutex_unlock(&meminit_lock);
#endif
}

static void
memory(char *driver, char *class, int event, int socket, void *data)
{
	struct pcm_make_dev *md = (struct pcm_make_dev *)data;
#ifdef	lint
	driver = NULL;
	class = NULL;
#endif

	socket = SOCKET(socket);

	if (debug & DBG_TASK) {
		(void) printf("memory(%x, %x, %x)\n",
					event, socket, (int)data);
	}
	switch (event) {
	case PCE_INIT_DEV:
		if ((md->op == SS_CSINITDEV_CREATE_DEVICE) &&
					(md->flags != PCM_EVENT_MORE)) {
			if (debug & DBG_TASK) {
			    (void) printf("Run disks cmd for memory\n");
			}
			(void) system("/usr/sbin/disks");
		}
		signal_vold(socket, md->path);
		break;
	case PCE_DEV_IDENT:
		break;
	case PCE_CARD_REMOVAL:
		unmount_media(socket, VOLD_TYPE_PCRAM);
		break;
	}
}


/* code for the disk() function handler */
			/*
			 * Note that PSARC/1994/238 requires to use
			 *	"/pcdisk" directory name instead of
			 *	"/pcata"
			 */
#define	PCDISK_PATH	"/pcdisk"
#define	PCATA_FILE	"/tmp/.pcmcia/pcata" /* special pipe file */

/*
 * disk(driver, class, event, socket data)
 *	this is the default disk card handler
 */

static void
diskinit()
{
	/*
	 * Later - Create /tmp/.pcmcia/pcata pipe file
	 *	to support pcata/volmgt.
	 */

	/*
	 * XXX Don't forget to consider whether or not you need to
	 *	single-thread this code like serinit and meminit
	 *	does by using a global mutex!
	 */
}

static void
disk(char *driver, char *class, int event, int socket, void *data)
{
	struct pcm_make_dev *md = (struct pcm_make_dev *)data;
#ifdef	lint
	driver = driver;
	class = class;
#endif


	if (debug & DBG_TASK) {
		(void) printf("disk(%x, %x, %x)\n",
					event, socket, (int)data);
	}
	switch (event) {
	case PCE_INIT_DEV:
		if ((md->op == SS_CSINITDEV_CREATE_DEVICE) &&
					(md->flags != PCM_EVENT_MORE)) {
			if (debug & DBG_TASK) {
			    (void) printf("Run disks cmd for disk\n");
			}
			(void) system("/usr/sbin/disks");
		}
		/*
		 * LATER - add support volmgt/pcata
		 *	signal_vold(...);
		 */
		break;
	case PCE_DEV_IDENT:
		break;
	case PCE_CARD_REMOVAL:
		/*
		 * LATER - add support volmgt/pcata
		 *	unmount_media(...);
		 */
		break;
	}
}



/* code for the pcmem/volmgt support */

/*
 * get_devrdsk
 *	Given cn[tn]dnsn or cn[tn] (vold alias) path,
 *	read the link path from /dev/rdsk and compare
 *	to see if it matches with device_type and
 *	the socket information.
 *	And return a complete /dev/rdsk/cn[tn]dnsn
 *
 */
static const char *
get_devrdsk(long socket, char *path, char *device_type)
{
	DIR		*dskdirp;
	struct dirent	*dskentp;
	struct stat	sb;
	const char	*devp = NULL;
	char		namebuf[MAXNAMELEN];
	char		linkbuf[MAXNAMELEN];
	int		linksize;
	int		found;
	int		gotit;
	int		i, searchlen;


	if ((dskdirp = opendir(DEVRDSK_PATH)) == NULL) {
	    if (debug) {
		(void) printf(
			"get_devrdsk: Error opening directory %s\n",
			DEVRDSK_PATH);
	    }
	    return (NULL);
	}

	while (dskentp = readdir(dskdirp)) {

		/*
		 * skip . and .. and
		 *	anything else starting with dot)
		 */
		if (dskentp->d_name[0] == '.') {
			continue;
		}

		/*
		 * Silently Ignore for now any names not
		 * stating with START_CHAR
		 */
		if (dskentp->d_name[0] != START_CHAR) {
			continue;
		}

		/*
		 * Skip if path [cntn] is not a subset of
		 * dskentp->d_name [cntndnsn]
		 */
		if (strncmp(dskentp->d_name, path, strlen(path)) != 0) {
			continue;
		}

		/*
		 * found a name that matches!
		 */
		(void) sprintf(namebuf, "%s/%s", DEVRDSK_PATH,
		    dskentp->d_name);

		if (lstat(namebuf, &sb) < 0) {
		    if (debug) {
			(void) printf("\tget_devrdsk: Cannot stat %s\n",
				namebuf);
		    }
		    continue;
		}

		found = 0;
		if (S_ISLNK(sb.st_mode)) {
			linksize = readlink(namebuf, linkbuf,
							MAXNAMELEN);
			if (linksize <= 0) {
			    if (debug) {
				(void) printf("\tget_devrdsk: "
			    "Could not read symbolic link %s\n",
					namebuf);
			    }
			    continue;
			}
			linkbuf[linksize] = '\0';

			if (debug & DBG_DEVSETUP) {
			    (void) printf(
				"\tget_devrdsk: check path %s\n",
				linkbuf);
			}

			/* Make sure it is a right device_type */
			devp = strstr(linkbuf, device_type);
			if (devp == NULL)
				continue;

			/*
			 * If it is VOLD_TYPE_PCRAM, search backward
			 *	until '@' character, then a number
			 *	after '@' is a socket number
			 *
			 * ../../devices/../\
			 *	MemoryAliasName@SocketN[,FunctN]/\
			 *	pcram:tn,dn:dev,raw
			 */
			searchlen = strlen(linkbuf) - strlen(devp);
			gotit = 0;
			for (i = searchlen; i > 0; i--) {
				if (*devp == '@') {
					gotit++;
					break;
				}
				devp--;
			}
			if (gotit) {
				/* Get socket info. */
				devp++;
				if (debug & DBG_DEVSETUP) {
					(void) printf(
				"\tget_devrdsk: devp=%s\n", devp);
				}
				if (socket == (long)atoi(devp)) {
					found++;
					/* exit readdir() loop */
					break;
				}
			} else {
				if (debug) {
					(void) printf(
				"\tget_devrdsk: Invalid path [%s] "
				"for device_type [%s]\n",
						linkbuf, device_type);
				}
			}

		}  /* if (S_ISLNK) */
	}  /* while (dskentp) */

	(void) closedir(dskdirp);
	return (found ? namebuf : NULL);
}

/*
 * unmount_media - Unmount PCMCIA media file system
 *
 * If the user accidentally removes the card without
 * using eject(1) command, this routine is called for unmounting
 * a mounted file system assuming that the directory is not busy
 */
static void
unmount_media(long socket, char *device_type)
{
	static void	start_unmount(char *, char *);
	static FILE	*fp = NULL;
	struct mnttab	mnt;
	const char	*nvp;
	char		pname[100];
	int		isit_voldp, isit_pcmemp, isit_devp;
	int		dnlen;


	/* mtab is gone... let it go */
	if ((fp = fopen(MNTTAB, "r")) == NULL) {
		perror(MNTTAB);
		goto out;
	}

	while (getmntent(fp, &mnt) == 0) {

		isit_voldp = strncmp(mnt.mnt_special, VOLDSK_PATH,
		    strlen(VOLDSK_PATH));
		isit_pcmemp = strncmp(mnt.mnt_mountp, PCMEM_PATH,
		    strlen(PCMEM_PATH));
		isit_devp = strncmp(mnt.mnt_special, DEVDSK_PATH,
		    strlen(DEVDSK_PATH));

		/*
		 * Skip if mnt_special is not a VOLDSK_PATH
		 * or DEVDSK_PATH
		 */
		if ((isit_voldp == 0) && (isit_pcmemp == 0) ||
		    (isit_devp == 0)) {

			/* Check for cn[tn]dnsn in /dev/dsk */
			nvp = strchr(mnt.mnt_special, START_CHAR);
			(void) strcpy(pname, nvp);

			/*
			 * extract cn[tn]dnsn from
			 * /vol/dev/dsk/cn[tn]dnsn/...
			 */
			if (isit_voldp == 0) {
				dnlen = strcspn(pname, "/");
				pname[dnlen] = NULL;
			}

			if (get_devrdsk(socket, pname, device_type)
							!= NULL) {
			    start_unmount(mnt.mnt_special,
						mnt.mnt_mountp);
			}
		}
	}
out:
	(void) fclose(fp);
}

/*
 * start_unmount - Start to unmount mounting directory
 *
 * Using mnt_special for unmounting vold path, and
 * mnt_mountp for regular umount(1M)
 */
static void
start_unmount(char *mnt_special, char *mnt_mountp)
{
	static int	req_vold_umount(char *);
	static int	do_umount(char *);
	int		err = 0;

	/*
	 * If vold is running we have to request the vold
	 * to unmount the file system (sigh!) in order to
	 * to clean up /vol enviroment (?)
	 */
#ifdef	lint
	/* LINTED */
	if (0) {
#else
	if (volmgt_running()) {
#endif
		if (req_vold_umount(mnt_special) == 0) {
			err++;
		}
	} else {

		/*
		 * Great! we can do a simple umount(1M)
		 * if the vold is not runing by umount <mnt_mountp>
		 * (including /pcmem/<mnt_mountp> after
		 * vold is disabled
		 *
		 * OR when the user removes the memory card WITHOUT
		 * using eject(1) command
		 */
		if (do_umount(mnt_mountp) == 0) {
			err++;
		}
	}

	if (err && debug) {
		(void) fprintf(stderr, ("start_unmount: %s is busy\n"),
		    mnt_mountp);
	}
}

/*
 * req_vold_umount - Request vold to unmount
 *	/vol/dev/rdsk/cntndnsn/..
 *
 * If vold is running, this routine is called when the user
 * removes a PC card WITHOUT using eject(1) command
 */
static int
req_vold_umount(char *path)
{
	int		fd;
	int		rval = 0;
	const char	*rawpath;



	/* Convert to "raw" path (rdsk) for DKIOCEJECT ioctl() */
#ifdef	lint
	rawpath = path;
#else
	rawpath = (char *)media_findname(path);
#endif
	if ((fd = open(rawpath, O_RDONLY|O_NDELAY)) < 0) {
		if (debug) {
			if (errno == EBUSY) {
				(void) printf(
				    "\treq_vold_umount: %s is busy\n",
				    rawpath);
				perror(rawpath);
			}
		}
		goto out;
	}

	if (debug) {
		(void) printf(
		    "\treq_vold_umount: Unmount vold path [%s]\n",
		    rawpath);
	}

	/*
	 * This simulates the volmgt eject(1) command
	 * to request the vold to eject/umount and cleanup
	 * its enviroment after unmount so we can use the same
	 * slot for different PC card
	 */
	if (ioctl(fd, DKIOCEJECT, 0) < 0) {
		/* suppose to see ENOSYS from pcmem driver */
		/* or ENOENT since card is gone */
		if (errno != ENOSYS && errno != ENOENT) {
			/* Could be EBUSY [16] (Mount device busy) */
			if (debug) {
				(void) printf(
			"\treq_vold_umount: DKIOCEJECT errno [%d]\n",
				    errno);
			}
		goto out;
	    }
	}
	rval = 1;
out:
	(void) close(fd);
	return (rval);
}


/*
 * do_umount - Unmount a file system when volmgt is not running
 */
static int
do_umount(char *path)
{
	pid_t	pid;
	int	fd;


	/*
	 * Use fork1 instead since this is a Solaris thread program
	 */
	if ((pid = fork1()) == 0) {
		/* the child */
		/* get rid of those nasty err messages */
		fd = open("/dev/null", O_RDWR);
		(void) dup2(fd, 0);
		(void) dup2(fd, 1);
		(void) dup2(fd, 2);
		(void) execl("/etc/umount", "/etc/umount", path, NULL);
		(void) fprintf(stderr,
		    "pcmciad: exec of  \"/etc/umount %s\" failed; %s\n",
		    path, strerror(errno));
		return (-1);
	}

	/* the parent */
	/* wait for the umount command to exit */
	(void) waitpid(pid, NULL, 0);
	if (debug) {
		(void) printf("\tdo_umount: \"/etc/umount %s\"\n",
								path);
	}

	return (1);
}

/*
 * get_rdsk_path
 *	Given /devices/.. path, return cntndnsn path in
 *	/dev/rdsk that matches it
 */
static const char *
get_rdsk_path(char *dev)
{
	char		*res = NULL;
	char		path_buf[MAXPATHLEN+1];
	struct stat	sb_targ;
	struct stat	sb;
	DIR		*dp = NULL;
	struct dirent	*ent;


	/* get the dev_t for our target */
	(void) sprintf(path_buf, "%s%s", pcmcia_root_dir,
			dev);

	if (stat(path_buf, &sb_targ) < 0) {
		if (debug) {
			(void) printf(
		"\tget_rdsk_path: error: can't stat %s (%s)\n",
				path_buf, strerror(errno));
		}
		goto dun;
	}

	/* Must be a raw device */
	if ((sb_targ.st_mode & S_IFMT) != S_IFCHR) {
		if (debug) {
			(void) printf(
		"\tget_rdsk_path: Not a raw device [%s]\n",
				path_buf);
		}
		goto dun;
	}

	/* scan the disks directory for the "right device" */
	if ((dp = opendir(DEVRDSK_PATH)) == NULL) {
		if (debug) {
			(void) printf(
		"\terror: can't open directory %s (%s)\n",
				DEVRDSK_PATH, strerror(errno));
		}
		goto dun;
	}

	while ((ent = readdir(dp)) != NULL) {
		if (ent->d_name[0] == '.') {
			continue;
		}
		(void) sprintf(path_buf, "%s/%s", DEVRDSK_PATH,
			ent->d_name);
		if (stat(path_buf, &sb) < 0) {
			if (debug) {
				(void) printf(
			"\terror: can't stat \"%s\" (%s)\n",
					path_buf, strerror(errno));
			}
			continue;
		}

		if (sb.st_rdev != sb_targ.st_rdev) {
			continue;
		}

		/* found it! */
		res = strdup(path_buf);
		if (debug) {
			(void) printf(
		"\tget_rdsk_path: found \"%s\"\n",
				res);
		}
		break;
	}

dun:
	if (dp != NULL) {
		(void) closedir(dp);
	}
	return (res);

}

/*
 * signal_vold - tell vold that a new path has been added
 */
static void
signal_vold(long socket, char *device)
{
	static void		wr_to_pipe(char *, char *, int);
	static const char	*get_rdsk_path(char *);
	const char		*rpath;


	if (debug) {
		(void) printf("\tsignal_vold: entering for \"%s\"\n",
			device);
	}

#ifndef	lint
	/* Do not write to the pipe if vold is not running */
	if (volmgt_running() == 0) {
	    if (debug) {
		(void) printf("\tsignal_vold: volmgt NOT running\n");
	    }
	    return;
	}
#endif

	if ((rpath = get_rdsk_path(device)) == NULL) {
		/*
		 * disks(1) command does not work correctly
		 * or the devices can not be found in devfs tree
		 */
		if (debug) {
		    (void) fprintf(stderr,
			("\tsignal_vold: error - get NULL devpath\n"));
		}
		return;
	}

	wr_to_pipe("insert", (char *)rpath, socket);
}

static void
wr_to_pipe(char *event, char *path, int socket)
{
	static int	fd = -1;
	char		buf[BUFSIZ];


	/* open a named pipe without blocking */
	if (fd < 0) {
		if ((fd = open(PCRAM_FILE, O_WRONLY | O_NDELAY)) < 0) {
			/*
			 * May be reader process does NOT open
			 * the other end ofthe pipe yet
			 */
			if (debug) {
				(void) printf(
	"wr_to_pipe: open(\"%s\") failed (errno %d, NO reader?)\n",
					PCRAM_FILE, errno);
			}
			return;
		}
	}

	(void) sprintf(buf, "%s, %s, %d", event, path, socket);
	(void) write(fd, buf, (unsigned int) strlen(buf));
	(void) write(fd, "\n", 1);
	if (debug) {
		(void) printf("\twr_to_pipe: wrote: \"%s\"\n", buf);
	}
}
/*
 * Create PCMCIA pipe directory
 */
static void
makepdir()
{
	extern int	errno;


	/* Make a pipe directory */
	if (debug) {
		(void) printf("\nmakepdir: \tmkdir %s\n", PDIR);
	}

	if (mkdir(PDIR, 0755) < 0) {
	    if (errno != EEXIST) {
		if (debug) {
			(void) fprintf(stderr, (
		"error: can't create pipe directory %s (%s)\n"),
			    PDIR, strerror(errno));
		}
		return;
	    } /* !EEXIST */
	} /* mkdir */

	/* Make a fifo special named pipe file */
	if (debug) {
		(void) printf("\t\tmknod %s\n", PCRAM_FILE);
	}

	if (mknod(PCRAM_FILE, (mode_t)(S_IFIFO|0600), NULL) < 0) {
	    if (errno != EEXIST) {
		if (debug) {
			(void) fprintf(stderr, (
			    "error: can't create named pipe %s (%s)\n"),
			    PCRAM_FILE, strerror(errno));
		}
	    }
	}
}

static void
init_global_locks()
{
#ifndef	lint
	(void) mutex_init(&serinit_lock, USYNC_THREAD, 0);
	(void) mutex_init(&meminit_lock, USYNC_THREAD, 0);
#endif
}
