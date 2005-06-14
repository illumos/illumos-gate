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
 * Copyright 2003 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <unistd.h>
#include <string.h>
#include <strings.h>
#include <stropts.h>
#include <errno.h>
#include <sys/systeminfo.h>
#include <sys/types.h>
#include <sys/stat.h>
#include "wrsmconf.h"
#include "wrsmconf_impl.h"

#define	ADMINDEVNAME 	"/dev/wrsmadmin"	/* Admin */
#define	CTLRDEVNAME	"/dev/wrsm%d"		/* Controller */
#define	WCIDEVNAME	"/dev/wci%x"		/* WCI */

#define	DIRNAMEFMT	"/etc/wrsm/c%d"
#define	FILENAMEFMT	"/etc/wrsm/c%d/config"
#define	HOSTNAMEFMT	"/etc/wrsm/c%d/hostname"

/*
 *	Macros to produce a quoted string containing the value of a
 *	preprocessor macro. For example, if SIZE is defined to be 256,
 *	VAL2STR(SIZE) is "256". This is used to construct format
 *	strings for scanf-family functions below.
 */
#define	QUOTE(x)	#x
#define	VAL2STR(x)	QUOTE(x)

/* Private function in libwrsmconf */
extern void wrsm_print_controller(FILE *fp, wrsm_controller_t *cont);

extern int ErrorCount;

/* Saves cont config in a file to be read at next reboot */
static void
store_config(wrsm_controller_t *cont)
{
	char filename[MAXPATHLEN];
	FILE *fp;

	(void) sprintf(filename, DIRNAMEFMT, cont->controller_id);
	(void) mkdir(filename, 0755);
	(void) sprintf(filename, HOSTNAMEFMT, cont->controller_id);
	if ((fp = fopen(filename, "w")) != NULL) {
		(void) fprintf(fp, "hostname=%s", cont->hostname);
		(void) fclose(fp);
	}
	/* Save to file for rc2 script to read at boot */
	(void) sprintf(filename, FILENAMEFMT, cont->controller_id);
	(void) wrsm_save_config(filename, cont);
}

#define	DPRINTF(x)	if (libwrsmconf_debug) (void) printf x
int
wrsm_check_config(wrsm_controller_t *cont)
{
	int i;
	wrsm_routing_data_t *routing;
	wrsm_wnodeid_t wnode;
	wrsm_gnid_t gnid;
	boolean_t libwrsmconf_debug = B_FALSE;
	wrsm_cnode_bitmask_t cnode_bitmask;

	if (getenv("LIBWRSMCONF_DEBUG") != NULL) {
		libwrsmconf_debug = B_TRUE;
	}

	/* Check for NULL pointers */
	if (cont == NULL) {
		DPRINTF(("ERROR: Controller is null\n"));
		return (EINVAL);
	}
	if (cont->WRSM_ALIGN_PTR(routing) == NULL) {
		DPRINTF(("ERROR: routing is null\n"));
		return (EINVAL);
	}
	if (cont->WRSM_ALIGN_PTR(members) == NULL) {
		DPRINTF(("ERROR: members is null\n"));
		return (EINVAL);
	}
	if (cont->config_protocol_version != CONFIG_PROTOCOL_VERSION) {
		DPRINTF(("ERROR: config protocol version mismatch: got %d "
		    "expecting %d\n", cont->config_protocol_version,
		    CONFIG_PROTOCOL_VERSION));
		return (ENOTSUP);
	}

	/* For each member in the cluster... */
	WRSMSET_ZERO(cnode_bitmask);
	for (i = 0; i < cont->nmembers; i++) {
		int j;
		wrsm_net_member_t *member = cont->WRSM_ALIGN_PTR(members)[i];
		if (member == NULL) {
			DPRINTF(("ERROR: members[%d] is null\n", i));
			return (EINVAL);
		}
		if (member->cnodeid >= WRSM_MAX_CNODES) {
			DPRINTF(("ERROR: cnode id %d exceeds max of %d\n",
			    member->cnodeid, WRSM_MAX_CNODES));
			return (EINVAL);
		}
		if (WRSM_IN_SET(cnode_bitmask, member->cnodeid)) {
			DPRINTF(("ERROR: cnode id %d appears twice\n",
			    member->cnodeid));
			return (EINVAL);
		}
		WRSMSET_ADD(cnode_bitmask, member->cnodeid);
		if (member->exported_ncslices.id[0] == 0) {
			DPRINTF(("ERROR: cnode id %d exports no small-page "
			    "ncslice\n", member->cnodeid));
			return (EINVAL);
		}
		if (member->imported_ncslices.id[0] == 0) {
			DPRINTF(("ERROR: cnode id %d imports no small-page "
			    "ncslice\n", member->cnodeid));
			return (EINVAL);
		}
		for (j = 1; j < WRSM_NODE_NCSLICES; j++) {
			int index = member->exported_ncslices.id[j] & 0x3;
			if (member->exported_ncslices.id[j] && index != j) {
				DPRINTF(("ERROR: cnode id %d exported ncslice "
				    "0x%x in wrong index %d\n",
				    member->cnodeid,
				    member->exported_ncslices.id[j], j));
				return (EINVAL);
			}
			index = member->imported_ncslices.id[j] & 0x3;
			if (member->imported_ncslices.id[j] && index != j) {
				DPRINTF(("ERROR: cnode id %d imported ncslice "
				    "0x%x in wrong index %d\n",
				    member->cnodeid,
				    member->exported_ncslices.id[j], j));
				return (EINVAL);
			}
		}
	}

	/* For each wci in the routing table... */
	routing = cont->WRSM_ALIGN_PTR(routing);
	for (i = 0; i < routing->nwcis; i++) {
		wrsm_wci_data_t *this_wci = routing->WRSM_ALIGN_PTR(wcis)[i];

		/* Verify wcis are listed in increasing order based on port */
		if ((i > 0) && (this_wci->port <=
		    routing->WRSM_ALIGN_PTR(wcis)[i - 1]->port)) {
			DPRINTF(("ERROR: wci %d is not in port order",
			    this_wci->port));
			return (EINVAL);
		}

		/* Verify reachable and gnid_to_wnode tables are consistent */
		for (wnode = 0; wnode < WRSM_MAX_WNODES; wnode++) {
			int count = 0;

			/*
			 * Count the number of times this wnode appears in
			 * gnid_to_wnode table -- Should be one for reachable
			 * nodes, zero of unreachable nodes.
			 */
			for (gnid = 0; gnid < WRSM_MAX_WNODES; gnid++) {
				if (this_wci->gnid_to_wnode[gnid] == wnode) {
					count++;
				}
			}
			if (this_wci->wnode_reachable[wnode] && count != 1) {
				DPRINTF(("ERROR: reachable wnode %d has %d "
				    "gnid_to_wnode entries for wci %d\n",
				    wnode, count, this_wci->port));
				return (EINVAL);
			} else if ((!this_wci->wnode_reachable[wnode]) &&
			    count != 0) {
				DPRINTF(("ERROR: unreachable wnode %d has %d "
				    "gnid_to_wnode entries for wci %d\n",
				    wnode, count, this_wci->port));
				return (EINVAL);
			}
		}

	}

	/* Verify that stripe groups are listed in order based on group_id */
	for (i = 1; i < routing->ngroups; i++) {
		if (routing->WRSM_ALIGN_PTR(stripe_groups)[i]->group_id <
		    routing->WRSM_ALIGN_PTR(stripe_groups)[i - 1]->group_id) {
			DPRINTF(("ERROR: stripe group %d not in group_id "
			    "order\n", routing->
			    WRSM_ALIGN_PTR(stripe_groups)[i]->group_id));
			return (EINVAL);
		}
	}
	return (0);
}

int
wrsm_initial_config(wrsm_controller_t *cont)
{
	int fd;
	int rc;
	int block_size;
	int tmp_errno;
	void *packed;
	wrsm_admin_arg_config_t initial = {0};

	if (!cont) {
		errno = EFAULT;
		return (-1);
	}

	if ((errno = wrsm_check_config(cont)) != 0) {
		return (-1);
	}

	if ((packed = wrsm_cf_pack(cont, &block_size)) == NULL) {
		errno = ENOMEM;
		return (-1);
	}

	initial.ioctl_version = WRSM_CF_IOCTL_VERSION;
	initial.controller_id = cont->controller_id;
	initial.controller_data_size = block_size;
	initial.WRSM_ALIGN_PTR(controller) = (wrsm_controller_t *)packed;

	fd = open(ADMINDEVNAME, O_RDONLY);
	if (fd == -1) {
		wrsm_free_packed_cont(packed);
		errno = EACCES;
		return (-1);
	}

	rc = ioctl(fd, WRSM_INITIALCFG, initial);
	tmp_errno = errno;
	if (rc == 0) {
		store_config(cont);
	}

	(void) close(fd);
	wrsm_free_packed_cont(packed);

	errno = tmp_errno;
	return (rc);
}

/*
 * Start config in /etc/wrsm for this controller.
 */
int
wrsm_start_config(int controller_id)
{
	FILE *fp;
	int fd;
	int rc;
	int block_size;
	int tmp_errno;
	void *packed;
	wrsm_admin_arg_config_t start = {0};
	char filename[MAXPATHLEN];
	char hostname[WRSM_HOSTNAMELEN+1];
	wrsm_controller_t *cont;

	(void) sprintf(filename, HOSTNAMEFMT, controller_id);
	if ((fp = fopen(filename, "r")) == NULL) {
		return (1);
	}
	if (fscanf(fp, "hostname=%" VAL2STR(WRSM_HOSTNAMELEN) "s",
	    hostname) == 0) {
		(void) fclose(fp);
		return (1);
	}
	(void) fclose(fp);

	(void) sprintf(filename, FILENAMEFMT, controller_id);
	rc = wrsm_read_config_for_host(filename, &cont, hostname);
	if (rc != 0) {
		return (rc);
	}

	if (controller_id != cont->controller_id) {
		(void) wrsm_free_config(cont);
		return (rc);
	}

	if ((errno = wrsm_check_config(cont)) != 0) {
		return (-1);
	}

	if ((packed = wrsm_cf_pack(cont, &block_size)) == NULL) {
		(void) wrsm_free_config(cont);
		errno = ENOMEM;
		return (-1);
	}

	start.ioctl_version = WRSM_CF_IOCTL_VERSION;
	start.controller_id = cont->controller_id;
	start.controller_data_size = block_size;
	start.WRSM_ALIGN_PTR(controller) = (wrsm_controller_t *)packed;

	fd = open(ADMINDEVNAME, O_RDONLY);
	if (fd == -1) {
		wrsm_free_packed_cont(packed);
		(void) wrsm_free_config(cont);
		errno = EACCES;
		return (-1);
	}

	rc = ioctl(fd, WRSM_INITIALCFG, start);
	tmp_errno = errno;
	if ((rc == -1) && (errno == EEXIST)) {
		/*
		 * if controller config is already installed,
		 * make sure sessions are enabled.
		 */
		rc = ioctl(fd, WRSM_STARTCFG, cont->controller_id);
		tmp_errno = errno;
	}

	(void) close(fd);
	wrsm_free_packed_cont(packed);
	(void) wrsm_free_config(cont);

	errno = tmp_errno;
	return (rc);
}

int
wrsm_start_all_configs(void)
{
	int rc;
	int retval = 0;
	int fd;
	int i;
	int maxcont;

	fd = open(ADMINDEVNAME, O_RDONLY);
	if (fd == -1) {
		errno = EACCES;
		return (-1);
	}
	(void) close(fd);

	if ((maxcont = wrsm_get_num_controllers()) == -1) {
		return (-1);
	}

	for (i = 0; i < maxcont; i++) {
		rc = wrsm_start_config(i);
		if (rc == -1) {
			retval = rc;
		}
	}

	return (retval);
}

int
wrsm_replace_config(wrsm_controller_t *cont)
{
	int fd;
	int rc;
	int tmp_errno;
	int block_size;
	void *packed;
	wrsm_admin_arg_config_t replace = {0};

	if (!cont) {
		errno = EFAULT;
		return (-1);
	}

	if ((errno = wrsm_check_config(cont)) != 0) {
		return (-1);
	}

	if ((packed = wrsm_cf_pack(cont, &block_size)) == NULL) {
		errno = ENOMEM;
		return (-1);
	}

	replace.ioctl_version = WRSM_CF_IOCTL_VERSION;
	replace.controller_id = cont->controller_id;
	replace.controller_data_size = block_size;
	replace.WRSM_ALIGN_PTR(controller) = (wrsm_controller_t *)packed;

	fd = open(ADMINDEVNAME, O_RDONLY);
	if (fd == -1) {
		wrsm_free_packed_cont(packed);
		errno = EACCES;
		return (-1);
	}

	rc = ioctl(fd, WRSM_REPLACECFG, &replace);
	tmp_errno = errno;
	if (rc == 0) {
		store_config(cont);
	}

	(void) close(fd);
	wrsm_free_packed_cont(packed);

	errno = tmp_errno;
	return (rc);
}

int
wrsm_enable_config(int controller_id, size_t num_wcis,
    wrsm_safari_port_t *wci_ids_in)
{
	int fd;
	int rc;
	int tmp_errno;
	wrsm_admin_arg_wci_t enable = {0};

	if (!wci_ids_in) {
		errno = EFAULT;
		return (-1);
	}

	enable.ioctl_version = WRSM_CF_IOCTL_VERSION;
	enable.controller_id = controller_id;
	enable.nwcis = num_wcis;
	enable.WRSM_ALIGN_PTR(wci_ids) = wci_ids_in;

	fd = open(ADMINDEVNAME, O_RDONLY);
	if (fd == -1) {
		errno = EACCES;
		return (-1);
	}

	rc = ioctl(fd, WRSM_ENABLECFG, &enable);
	tmp_errno = errno;

	(void) close(fd);

	errno = tmp_errno;
	return (rc);
}

int
wrsm_install_config(int controller_id, size_t num_wcis,
    wrsm_safari_port_t *wci_ids_in)
{
	int fd;
	int rc;
	int tmp_errno;
	wrsm_admin_arg_wci_t install = {0};

	if (!wci_ids_in) {
		errno = EFAULT;
		return (-1);
	}

	install.ioctl_version = WRSM_CF_IOCTL_VERSION;
	install.controller_id = controller_id;
	install.nwcis = num_wcis;
	install.WRSM_ALIGN_PTR(wci_ids) = wci_ids_in;

	fd = open(ADMINDEVNAME, O_RDONLY);
	if (fd == -1) {
		errno = EACCES;
		return (-1);
	}

	rc = ioctl(fd, WRSM_INSTALLCFG, &install);
	tmp_errno = errno;

	(void) close(fd);

	errno = tmp_errno;
	return (rc);
}

int
wrsm_remove_config(int controller_id)
{
	int rc;
	int fd;
	int tmp_errno;

	fd = open(ADMINDEVNAME, O_RDONLY);
	if (fd == -1) {
		errno = EACCES;
		return (-1);
	}

	rc = ioctl(fd, WRSM_REMOVECFG, controller_id);
	tmp_errno = errno;
	if (rc == 0) {
		char filename[MAXPATHLEN];
		/* Delete file read by rc2 script at boot */
		(void) sprintf(filename, FILENAMEFMT, controller_id);
		(void) unlink(filename);
		(void) sprintf(filename, HOSTNAMEFMT, controller_id);
		(void) unlink(filename);
		(void) sprintf(filename, DIRNAMEFMT, controller_id);
		(void) rmdir(filename);
	}


	(void) close(fd);

	errno = tmp_errno;
	return (rc);
}

int
wrsm_remove_all_configs(void)
{
	int rc;
	int retval = 0;
	int fd;
	int i;
	int maxcont;

	fd = open(ADMINDEVNAME, O_RDONLY);
	if (fd == -1) {
		errno = EACCES;
		return (-1);
	}
	(void) close(fd);

	if ((maxcont = wrsm_get_num_controllers()) == -1) {
		return (-1);
	}

	for (i = 0; i < maxcont; i++) {
		rc = wrsm_remove_config(i);
		if (rc == -1) {
			retval = rc;
		}
	}

	return (retval);
}


/*
 * Stop config.  don't remove from /etc/wrsm.
 */
int
wrsm_stop_config(int controller_id)
{
	int rc;
	int fd;
	int tmp_errno;

	fd = open(ADMINDEVNAME, O_RDONLY);
	if (fd == -1) {
		errno = EACCES;
		return (-1);
	}

	rc = ioctl(fd, WRSM_REMOVECFG, controller_id);
	tmp_errno = errno;
	if ((rc == -1) && (errno == EBUSY)) {
		/*
		 * controller config can't be removed;
		 * make sure sessions are disabled.
		 */
		rc = ioctl(fd, WRSM_STOPCFG, controller_id);
		tmp_errno = errno;
	}

	(void) close(fd);

	errno = tmp_errno;
	return (rc);
}

int
wrsm_stop_all_configs(void)
{
	int rc;
	int retval = 0;
	int fd;
	int i;
	int maxcont;

	fd = open(ADMINDEVNAME, O_RDONLY);
	if (fd == -1) {
		errno = EACCES;
		return (-1);
	}
	(void) close(fd);

	if ((maxcont = wrsm_get_num_controllers()) == -1) {
		return (-1);
	}

	for (i = 0; i < maxcont; i++) {
		rc = wrsm_stop_config(i);
		if (rc == -1) {
			retval = rc;
		}
	}

	return (retval);
}

int
wrsm_get_config(int controller_id, wrsm_controller_t **cont)
{
	int fd;
	int tmp_errno;
	wrsm_admin_arg_config_t getarg = {0};
	wrsm_controller_t *unpacked;

	if (!cont) {
		errno = EFAULT;
		return (-1);
	}

	fd = open(ADMINDEVNAME, O_RDONLY);
	if (fd == -1) {
		errno = EACCES;
		return (-1);
	}

	getarg.ioctl_version = WRSM_CF_IOCTL_VERSION;
	getarg.controller_id = controller_id;
	getarg.controller_data_size = 0;
	if (ioctl(fd, WRSM_GETCFG, &getarg) != 0) {
		tmp_errno = errno;

		(void) close(fd);
		errno = tmp_errno;
		return (-1);
	}

	getarg.WRSM_ALIGN_PTR(controller) =
	    malloc(getarg.controller_data_size);
	if (!getarg.WRSM_ALIGN_PTR(controller)) {
		(void) close(fd);
		errno = ENOMEM;
		return (-1);
	}

	if (ioctl(fd, WRSM_GETCFG, &getarg) != 0) {
		tmp_errno = errno;
		free(getarg.WRSM_ALIGN_PTR(controller));

		(void) close(fd);

		errno = tmp_errno;
		return (-1);
	}

	unpacked = wrsm_cf_unpack((char *)getarg.WRSM_ALIGN_PTR(controller));
	*cont = unpacked;
	(void) close(fd);
	return (0);
}

int
wrsm_get_num_controllers(void)
{
	int num_conts;
	int fd;
	int tmp_errno;

	fd = open(ADMINDEVNAME, O_RDONLY);
	if (fd == -1) {
		errno = EACCES;
		return (-1);
	}

	num_conts = ioctl(fd, WRSM_CONTROLLERS, 0);
	tmp_errno = errno;

	(void) close(fd);

	errno = tmp_errno;
	return (num_conts);
}

int
wrsm_save_config(char *path, wrsm_controller_t *config)
{
	FILE *fp;

	if (!config) {
		errno = EFAULT;
		return (-1);
	}

	if ((fp = fopen(path, "w")) == NULL) {
		return (-1);
	}

	wrsm_print_controller(fp, config);
	(void) fclose(fp);
	return (0);
}

int
wrsm_read_config(char *path, wrsm_controller_t **config)
{
	return (wrsm_read_config_for_host(path, config, NULL));
}

int
wrsm_read_config_for_host(char *path, wrsm_controller_t **config,
    char *hostname)
{
	char localhost[WRSM_HOSTNAMELEN] = "";
	extern FILE *yyin;
	wrsm_controller_t *cfg;

	if (!path || !config) {
		errno = EFAULT;
		return (-1);
	}

	if ((yyin = fopen(path, "r")) == NULL) {
		errno = EACCES;
		return (-1);
	}

	wrsm_lexx_reset();
	wrsm_yacc_reset();
	yyparse();
	(void) fclose(yyin);

	if (ErrorCount > 0) {
		errno = EINVAL;
		return (-1);
	}

	if (hostname)
		cfg = wrsm_find_controller_by_hostname(hostname);
	else {
		(void) sysinfo(SI_HOSTNAME, localhost, WRSM_HOSTNAMELEN);
		cfg = wrsm_find_controller_by_hostname(localhost);
	}
	if (cfg == NULL) {
		errno = EINVAL;
		return (-1);
	}
	/* Allocate memory for the caller's data structure */
	*config = (wrsm_controller_t *)malloc(sizeof (wrsm_controller_t));
	/* Copy controller from static structure to caller's structure */
	(void) memcpy(*config, cfg, sizeof (wrsm_controller_t));
	/* Zero the static structure, so we don't free any of the pointers */
	(void) memset(cfg, 0, sizeof (wrsm_controller_t));
	/* Free the other unused controllers read from the file */
	wrsm_yacc_reset();
	wrsm_lexx_reset();

	return (0);
}

int
wrsm_free_config(wrsm_controller_t *config)
{
	wrsm_cf_free(config, sizeof (wrsm_controller_t));
	return (0);
}

int
wrsm_link_disable(wrsm_safari_port_t wci_id, int linkno)
{
	int rc;
	int fd;
	int tmp_errno;
	char devname[MAXPATHLEN];

	(void) sprintf(devname, WCIDEVNAME, wci_id);
	fd = open(devname, O_RDONLY);
	if (fd == -1) {
		errno = EACCES;
		return (-1);
	}

	rc = ioctl(fd, WRSM_WCI_LINKDOWN, &linkno);
	tmp_errno = errno;

	(void) close(fd);

	errno = tmp_errno;
	return (rc);
}

int
wrsm_link_enable(wrsm_safari_port_t wci_id, int linkno)
{
	int rc;
	int fd;
	int tmp_errno;
	char devname[MAXPATHLEN];

	(void) sprintf(devname, WCIDEVNAME, wci_id);
	fd = open(devname, O_RDONLY);
	if (fd == -1) {
		errno = EACCES;
		return (-1);
	}

	rc = ioctl(fd, WRSM_WCI_LINKUP, &linkno);
	tmp_errno = errno;

	(void) close(fd);
	errno = tmp_errno;
	return (rc);
}

int
wrsm_memory_test(int controller_id, wrsm_memloopback_arg_t *memoryinfo)
{
	char devname[MAXPATHLEN];
	int fd;
	int rc;
	int tmp_errno;

	(void) sprintf(devname, CTLRDEVNAME, controller_id);
	fd = open(devname, O_RDONLY);
	if (fd == -1) {
		errno = EACCES;
		return (-1);
	}

	rc = ioctl(fd, WRSM_CTLR_MEM_LOOPBACK, memoryinfo);
	tmp_errno = errno;

	(void) close(fd);
	errno = tmp_errno;
	return (rc);
}


int
wrsm_link_test_setup(int wci_instance, int link_number)
{
	int fd;
	int rc;
	int tmp_errno;
	char devname[MAXPATHLEN];

	(void) sprintf(devname, WCIDEVNAME, wci_instance);
	if ((fd = open(devname, O_RDONLY)) == -1) {
		errno = EACCES;
		return (-1);
	}
	rc = ioctl(fd, WRSM_WCI_LOOPBACK_ON, link_number);
	tmp_errno = errno;

	(void) close(fd);
	errno = tmp_errno;
	return (rc);
}

int
wrsm_link_test(int wci_instance, wrsm_linktest_arg_t *linkinfo)
{
	int fd;
	int rc;
	int tmp_errno;
	char devname[MAXPATHLEN];

	(void) sprintf(devname, WCIDEVNAME, wci_instance);
	if ((fd = open(devname, O_RDONLY)) == -1) {
		errno = EACCES;
		return (-1);
	}
	rc = ioctl(fd, WRSM_WCI_LINKTEST, linkinfo);
	tmp_errno = errno;

	(void) close(fd);
	errno = tmp_errno;
	return (rc);
}

int
wrsm_link_test_teardown(int wci_instance, int link_number)
{
	int fd;
	int rc;
	int tmp_errno;
	char devname[MAXPATHLEN];

	(void) sprintf(devname, WCIDEVNAME, wci_instance);
	if ((fd = open(devname, O_RDONLY)) == -1) {
		errno = EACCES;
		return (-1);
	}
	rc = ioctl(fd, WRSM_WCI_LOOPBACK_OFF, link_number);
	tmp_errno = errno;

	(void) close(fd);
	errno = tmp_errno;
	return (rc);
}
