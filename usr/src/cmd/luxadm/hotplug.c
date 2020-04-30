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



/*LINTLIBRARY*/


/*
 * Hotplug program for SENA, RSM and SSA
 * subsystems and individual FC_AL devices.
 */

/* #define		 _POSIX_SOURCE 1 */

/*
 * I18N message number ranges
 *  This file: 5500 - 5999
 *  Shared common messages: 1 - 1999
 */


/*	Includes	*/
#include	<stdlib.h>
#include	<stdio.h>
#include	<sys/file.h>
#include	<sys/errno.h>
#include	<sys/types.h>
#include	<sys/stat.h>
#include	<sys/utsname.h>
#include	<fcntl.h>
#include	<unistd.h>
#include	<errno.h>
#include	<string.h>
#include	<sys/sunddi.h>
#include	<sys/ddi.h>		/* for min */
#include	<sys/scsi/scsi.h>
#include	<nl_types.h>
#include	<dirent.h>
#include	<sys/wait.h>
#include	<l_common.h>
#include	<l_error.h>
#include	<stgcom.h>
#include	<a_state.h>
#include	<a5k.h>
#include	<rom.h>
#include	"hot.h"
#include	"common.h"
#include	"luxadm.h"


/* Internal variables. */
static char *cmdStrg[][4] = {
		{ "disks", "-C", 0, 0 },
		{ "disks", 0, 0, 0 },
		{ "drvconfig", "-i", "ssd", 0 },
		{ "drvconfig", 0, 0, 0 },
		{ "devlinks", 0, 0, 0 },
		{ "tapes", "-C", 0, 0 }
};

/*	External variables	*/
extern	char		*dtype[]; /* From adm.c */
extern	int		Options;
extern	const		int OPTION_CAPF;

/*	Internal functions	*/
/* SENA and Individual FC device Hotplug */
static	int	h_pre_insert_encl_dev(timestruc_t *, timestruc_t *,
		timestruc_t *);
static	int	h_post_insert_dev(timestruc_t, timestruc_t);
static	int	h_pre_remove_dev(Hotplug_Devlist *,
		WWN_list *wwn_list, int, int);
static	int	h_post_remove_dev(Hotplug_Devlist *, int, int);
static	int	h_pre_hotplug(Hotplug_Devlist **,
		WWN_list *, int, int, int);
static	int	h_post_hotplug(Hotplug_Devlist *,
		WWN_list *, int, int, int, int);
static	int	h_post_insert_encl(timestruc_t);
static	int	h_pre_hotplug_sena(Hotplug_Devlist *,
		WWN_list *, int, int, int);
static	int	h_post_hotplug_sena(Hotplug_Devlist *,
		WWN_list *, int, int, int, int);
static	int	h_remove_ses_nodes(struct dlist *);
static	int	h_print_list_warn(Hotplug_Devlist *, int, int);
static	int	h_display_logical_nodes(struct dlist *);
static	void	h_print_logical_nodes(struct dlist *);
static	int	h_remove_nodes(struct dlist *);
static	int	h_print_list(Hotplug_Devlist *, int *, int);
static	int	h_get_fcdev_state(char *, char *, int, int *, int *, int);
static	int	h_chk_dev_busy(Hotplug_Devlist *,
		WWN_list *, int *, int, int);
static	int	h_execCmnd(char **, int);
int		hotplug(int, char **, int, int);
int		h_insertSena_fcdev();
static	int	h_find_new_device_link(char *, timestruc_t);



/*
 * Assists the user in hot inserting FC_AL
 * individual device(s) and SENA enclosure(s).
 *
 * RETURNS:
 *	0	 if OK
 *	non-zero otherwise
 */
int
h_insertSena_fcdev()
{
timestruc_t	ses_time, dsk_time, rmt_time;
int		err;
struct stat	ses_stat;

	if ((err = h_pre_insert_encl_dev(&ses_time, &dsk_time,
							&rmt_time)) != 0) {
		return (err);
	}
	(void) fprintf(stdout, MSGSTR(5500,
			"Please hit <RETURN> when you have finished"
			" adding Fibre Channel Enclosure(s)/Device(s): "));
	(void) getchar();

	if ((err = h_post_insert_dev(dsk_time, rmt_time)) != 0) {
		return (err);
	}

	if (stat(SES_DIR, &ses_stat) < 0) {
		/*
		 * Non existence of /dev/es dir indicates
		 * no ses devices inserted.
		 * No need to call h_post_insert_encl().
		 */
		if (errno == ENOENT) {
			(void) fprintf(stdout, MSGSTR(5662,
				" No new enclosure(s) were added!!\n\n"));
			return (0);
		} else {
			return (L_LSTAT_ES_DIR_ERROR);
		}
	}

	/*
	 * if the latest mod time of /dev/es is not newer than
	 * the original mod time no need to call
	 * h_post_insert_encl().
	 */
	if ((&ses_time != (timestruc_t *)NULL) &&
			!(NEWER(ses_stat.st_ctim, ses_time))) {
		(void) fprintf(stdout, MSGSTR(5662,
			" No new enclosure(s) were added!!\n\n"));
		return (0);
	}
	if ((err = h_post_insert_encl(ses_time)) != 0) {
		return (err);
	}
	return (0);
}



/*
 * gets the devices state - check for disk's reservations.
 *
 * RETURNS:
 *	0	 if OK
 *	non-zero otherwise
 */
static	int
h_get_fcdev_state(char *fc_dev, char *path_phys, int force_flag,
		int *busy_flag, int *reserve_flag, int verbose_flag)
{
int		err;
L_inquiry	inq;
L_disk_state	l_disk_state;


	if ((err = g_get_inquiry(path_phys, &inq)) != 0) {
		(void) fprintf(stderr,
				MSGSTR(5501,
				"Inquiry failed for %s\n"),
				path_phys);
		return (err);
	}
	if (inq.inq_port) {
		if ((err = l_get_disk_port_status(path_phys, &l_disk_state,
					FC_PORT_B, verbose_flag)) != 0) {
			return (err);
		}
	} else {
		if ((err = l_get_disk_port_status(path_phys, &l_disk_state,
					FC_PORT_A, verbose_flag)) != 0) {
			return (err);
		}
	}

	/*
	 * Don't print error msg. if disk is reserved
	 * and tried to be removed from the same port.
	 * If force flag is set, remove the disk without
	 * checking the disk reservations.
	 */
	if (!force_flag) {
		if (((inq.inq_port) &&
		(l_disk_state.g_disk_state.d_state_flags[FC_PORT_B] &
				L_RESERVED)) ||
			((!inq.inq_port) &&
		(l_disk_state.g_disk_state.d_state_flags[FC_PORT_A] &
				L_RESERVED))) {
			*reserve_flag = 1;
		}
	}
	return (0);
}


/*
 * Forks a child process and let the child to
 * execute a given command string by calling the
 * the execvp() function. Then, the parent process
 * waits for the child to exit. Once the parent process
 * is notified by the kernel with the termination of
 * the child, then the  parent checks for the exit
 * status of the child and return to the caller with -1 in case
 * of error and zero otherwise.
 *
 * RETURNS:
 *	0	 if OK
 *	non-zero otherwise
 */
int
h_execCmnd(char *argStr[], int nArg)
{
pid_t	pid;
int	ix, status;

	if ((pid = fork()) < 0) {
		(void) fprintf(stderr,
			MSGSTR(133,
			"Error: Failed to fork a process.\n"));
		return (-1);
	} else if (pid == 0) {
		/* child process */
		if (execvp(argStr[0], argStr) < 0) {
			(void) fprintf(stderr,
				MSGSTR(5502,
				" Error: execvp() failed to run "
				"the command:"));
			for (ix = 0; ix < nArg; ix++) {
				(void) fprintf(stderr,
					" %s", argStr[ix]);
			}
			(void) fprintf(stderr, "\n");
			/* let parent know about the error. */
			exit(ENOEXEC);
		}
	}

	/* parent executes the following. */
	if (waitpid(pid, &status, 0) != pid) {
		(void) fprintf(stderr,
			MSGSTR(5503,
			"Error: waitpid() failed.\n"));
		return (-1);
	}
	if (WIFEXITED(status) &&
			WEXITSTATUS(status) == ENOEXEC) {
		/* child failed to run the command string. */
		return (-1);
	}
	return (0);

}




/*
 * frees the hotplug disk list structure.
 *
 * RETURNS:
 *	N/A
 */
void
h_free_hotplug_dlist(Hotplug_Devlist **hotplug_dlist)
{
Hotplug_Devlist	*list = NULL;

	while (*hotplug_dlist != NULL) {
		list = *hotplug_dlist;
		*hotplug_dlist = (*hotplug_dlist)->next;
		(void) g_free_multipath(list->seslist);
		(void) g_free_multipath(list->dlhead);
		(void) free((void *)list);
	}
}


/*
 * finds whether device (SENA or an FCAL device) is busy or not.
 *
 * OUTPUT:
 *	busy_flag = 1 (if device busy)
 *
 * RETURNS:
 *	0	 if O.K.
 *	non-zero otherwise
 */
static int
h_chk_dev_busy(Hotplug_Devlist *hotplug_dev, WWN_list *wwn_list,
		int *busy_flag, int force_flag, int verbose_flag)
{
int	err;
struct dlist *dlist;

	if (hotplug_dev->dev_type == DTYPE_ESI) {
		if ((err = l_offline_photon(hotplug_dev, wwn_list,
					force_flag, verbose_flag)) != 0) {
			if (err == L_DEV_BUSY) {
				*busy_flag = 1;
			} else {
				return (err);
			}
		}
		for (dlist = hotplug_dev->dlhead;
				dlist != NULL; dlist = dlist->next) {
			(void) g_online_drive(dlist->multipath,
							force_flag);
		}
	} else {
		if ((err = g_offline_drive(hotplug_dev->dlhead,
						force_flag)) != 0) {
			if (err == L_DEV_BUSY) {
				*busy_flag = 1;
			} else {
				return (err);
			}
		}
		(void) g_online_drive(hotplug_dev->dlhead, force_flag);
	}
	return (0);
}



/*
 * prints the given list to stdout,
 * gets the input from user whether
 * to skip the busy devices or quit
 * and passes that input to the calling
 * function.
 *
 * OUTPUT:
 *	int	*action
 *		s = Skip
 *		q = Quit
 *
 * RETURNS:
 *	0	 if OK
 *	non-zero otherwise
 */
static	int
h_print_list(Hotplug_Devlist *bsyRsrv_disk_list, int *action, int enc_type)
{
Hotplug_Devlist *list;
int		i = 1;
char		choice[2];

	(void) fprintf(stdout,
	    MSGSTR(5504, "The list of devices being used"
	    " (either busy or reserved) by the host:\n"));
	for (list = bsyRsrv_disk_list; list != NULL; list = list->next, i++) {
	    if ((list->dev_type == DTYPE_DIRECT) &&
		(list->dev_location == SENA)) {
		if (list->f_flag != 0) {
		    if (enc_type == DAK_ENC_TYPE) {
			(void) fprintf(stdout, MSGSTR(5663,
			    "  %d: Box Name:    \"%s\"  slot %d\n"),
			    i, list->box_name, list->slot);
		    } else {
			(void) fprintf(stdout, MSGSTR(137,
			    "  %d: Box Name:    \"%s\" front slot %d\n"),
			    i, list->box_name, list->slot);
		    }
		} else {
		    if (enc_type == DAK_ENC_TYPE) {
			(void) fprintf(stdout, MSGSTR(5663,
			    "  %d: Box Name:    \"%s\"  slot %d\n"),
			    i, list->box_name, list->slot + (MAX_DRIVES_DAK/2));
		    } else {
			(void) fprintf(stdout, MSGSTR(136,
				"  %d: Box Name:    \"%s\" rear slot %d\n"),
				i, list->box_name, list->slot);
		    }
		}
	    } else if (((list->dev_type == DTYPE_DIRECT) ||
			(list->dev_type == DTYPE_SEQUENTIAL)) &&
			(list->dev_location == NON_SENA)) {
		(void) fprintf(stdout, MSGSTR(5505,
		    "  %d: Device %s\n"),
		    i, list->dev_name);
	    } else if (list->dev_type == DTYPE_ESI) {
		(void) fprintf(stdout, MSGSTR(5506,
		    "  %d: Box: %s\n"),
		    i, list->box_name);
	    }
	}

	/* Get the user input and continue accordingly. */
	(void) fprintf(stdout,
		MSGSTR(5507,
		"\n\nPlease enter 's' or <CR> to Skip the \"busy/reserved\""
		" device(s) or\n'q' to Quit and run the"
		" subcommand with\n-F (force) option. [Default: s]: "));
	for (;;) {
		(void) gets(choice);
		if (choice[0] == 'q' || choice[0] == 'Q' ||
			choice[0] == 's' || choice[0] == 'S' ||
			choice[0] == '\0') {
			break;
		}
		(void) fprintf(stdout, MSGSTR(5508,
			" Enter an appropriate option [s,<CR>,q]: "));
	}
	if (choice[0] == 'q' || choice[0] == 'Q') {
		*action = QUIT;
	} else {
		*action = SKIP;
	}
	(void) fprintf(stdout, "\n\n");
	return (0);
}



/*
 * prints the warning message.
 *
 * RETURNS:
 *	None.
 */
static void
h_prt_warning()
{
	(void) fprintf(stderr,
			MSGSTR(5509,
			"\n WARNING!!! Please ensure that no"
			" filesystems are mounted on these device(s).\n"
			" All data on these devices should have been"
			" backed up.\n\n\n"));
}



/*
 * handle helper-mode hotplug commands
 *
 * RETURNS:
 *	0	 if OK
 *	non-zero otherwise
 */
int
hotplug(int todo, char **argv, int verbose_flag, int force_flag)
{
char		ses_path[MAXPATHLEN], dev_path[MAXPATHLEN];
char		*path_phys = NULL, code, node_wwn_s[WWN_S_LEN];
char		inq_path[MAXNAMELEN], *ptr = NULL;
uchar_t		node_wwn[WWN_SIZE], port_wwn[WWN_SIZE];
int		tid, slot, path_index, dtype, f_r, err = 0;
int		al_pa, i, dev_location, found_nullwwn = 0;
int		busy_flag = 0, reserve_flag = 0, action = 0;
int		pathcnt = 1;
L_state		l_state;
gfc_map_t	map;
Path_struct	*path_struct;
WWN_list	*wwn_list = NULL;
Box_list	*box_list;
Hotplug_Devlist	*disk_list, *disk_list_head, *disk_list_tail;
Hotplug_Devlist	*bsyRsrv_dskLst_head, *bsyRsrv_dskLst_tail;
int		enc_type;
L_inquiry   inq;
char	    *physpath;
Path_struct *p_pathstruct;
char		temp2path[MAXPATHLEN];
mp_pathlist_t	pathlist;
int		p_pw = 0, p_on = 0, p_st = 0;

	/* Initialize structures and pointers here */
	disk_list_head = disk_list_tail = (Hotplug_Devlist *)NULL;
	bsyRsrv_dskLst_head = (Hotplug_Devlist *)NULL;
	bsyRsrv_dskLst_tail = (Hotplug_Devlist *)NULL;
	map.dev_addr = NULL;

#ifdef	DEBUG
	(void) fprintf(stderr,
			"DEBUG: luxadm: hotplug() entering for \"%s\" ...\n",
			argv[0] ? argv[0] : "<null ptr>");
#endif
	if ((err = l_get_box_list(&box_list, 0)) != 0) {
		return (err);
	}

	if (todo == REMOVE_DEVICE) {
		(void) h_prt_warning();
	}

	/*
	 * At this point user want to insert or remove
	 * one or more pathnames they've specified.
	 */
	if ((err = g_get_wwn_list(&wwn_list, verbose_flag)) != 0) {
		(void) l_free_box_list(&box_list);
		return (err);
	}
	for (path_index = 0; argv[path_index] != NULL; path_index++) {
		if ((err = l_convert_name(argv[path_index], &path_phys,
					&path_struct, verbose_flag)) != 0) {
			/* Make sure we have a device path. */
			(void) strcpy(inq_path, argv[path_index]);
			if (((ptr = strstr(inq_path, ",")) != NULL) &&
				((*(ptr + 1) == 'f') || (*(ptr + 1) == 'r') ||
				    (*(ptr +1) == 's')) &&
							todo == REMOVE_DEVICE) {
				if (err != -1) {
					(void) print_errString(err,
							argv[path_index]);
					err = 0;
					continue;
				}
				*ptr = '\0';
				slot = path_struct->slot;
				f_r = path_struct->f_flag;
				if ((err = l_convert_name(inq_path, &path_phys,
					&path_struct, verbose_flag)) != 0) {
					(void) fprintf(stderr, "\n");
					(void) fprintf(stderr,
							MSGSTR(33,
						" Error: converting"
						" %s to physical path.\n"
						" Invalid pathname.\n"),
						argv[path_index]);
					if (err != -1) {
						(void) print_errString(err,
							argv[path_index]);
					}
					err = 0;
					continue;
				}
				if ((err = print_devState(argv[path_index],
						path_struct->p_physical_path,
					f_r, slot, verbose_flag)) != 0) {
						err = 0;
						continue;
				}
			}
			if (path_struct->ib_path_flag) {
				path_phys = path_struct->p_physical_path;
			} else {
				if (err != -1) {
					(void) print_errString(err,
							argv[path_index]);
				} else {
					(void) fprintf(stderr, "\n");
					(void) fprintf(stderr,
						MSGSTR(33,
						" Error: converting"
						" %s to physical path.\n"
						" Invalid pathname.\n"),
						argv[path_index]);
				}
				err = 0;
				continue;
			}
		}
		if (path_struct->slot_valid ||
					strstr(path_phys, DRV_NAME_SSD)) {
			dtype = DTYPE_DIRECT;
		} else if (strstr(path_phys, SLSH_DRV_NAME_ST)) {
			dtype = DTYPE_SEQUENTIAL;
		} else {
			dtype = DTYPE_ESI;
		}

		if (strstr(path_phys, SCSI_VHCI) != NULL) {
			/* obtain phci */
			(void) strcpy(temp2path, path_phys);
			if (err = g_get_pathlist(temp2path, &pathlist)) {
				(void) print_errString(err, NULL);
				exit(-1);
			}
			pathcnt = pathlist.path_count;
			p_pw = p_on = p_st = 0;
			for (i = 0; i < pathcnt; i++) {
				if (pathlist.path_info[i].path_state <
					MAXPATHSTATE) {
					if (strstr(pathlist.path_info[i].
						path_addr,
						path_struct->argv) != NULL) {
						p_pw = i;
						break;
					}
					if (pathlist.path_info[i].path_state ==
						MDI_PATHINFO_STATE_ONLINE) {
						p_on = i;
					}
					if (pathlist.path_info[i].path_state ==
						MDI_PATHINFO_STATE_STANDBY) {
						p_st = i;
					}
				}
			}
			if (strstr(pathlist.path_info[p_pw].path_addr,
				path_struct->argv) != NULL) {
				/* matching input pwwn */
				(void) strcpy(temp2path,
					pathlist.path_info[p_pw].path_hba);
			} else if (pathlist.path_info[p_on].path_state ==
				MDI_PATHINFO_STATE_ONLINE) {
				/* on_line path */
				(void) strcpy(temp2path,
					pathlist.path_info[p_on].path_hba);
			} else {
				/* standby or path0 */
				(void) strcpy(temp2path,
					pathlist.path_info[p_st].path_hba);
			}
			free(pathlist.path_info);
			(void) strcat(temp2path, FC_CTLR);
		} else {
			(void) strcpy(temp2path, path_phys);
		}

		if ((err = g_get_dev_map(temp2path, &map, verbose_flag))
			!= 0) {
			return (err);
		}

		if ((map.hba_addr.port_topology == FC_TOP_PUBLIC_LOOP) ||
			(map.hba_addr.port_topology == FC_TOP_FABRIC)) {
			/* public or fabric loop device */
				free((void *)map.dev_addr);
				(void) fprintf(stderr, MSGSTR(5540,
				"This operation is not "
				"supported in this topology.\n"));
				exit(-1);
		}

		if (todo == REPLACE_DEVICE) {
			(void) fprintf(stderr,
				MSGSTR(5511,
				"Error:"
				" replace_device is not supported"
				" on this subsystem.\n"));
			exit(-1);
		}

		if ((todo == REMOVE_DEVICE) &&
				(dtype == DTYPE_DIRECT ||
				dtype == DTYPE_SEQUENTIAL ||
				dtype == DTYPE_UNKNOWN)) {
			if (l_chk_null_wwn(path_struct, ses_path,
				&l_state, verbose_flag) == 1) {
				found_nullwwn = 1;
				/*
				 * set dev_path to NULL,
				 * if disk has null wwn.
				 */
				*dev_path = '\0';
				dev_location = SENA;
				goto getinfo;
			}
		}

		(void) strcpy(ses_path, path_phys);

		if (strstr(ses_path, "ses") == NULL &&
			l_get_ses_path(path_phys, ses_path, &map,
					verbose_flag) != 0) {

			/* Could be a non-photon disk device */
			if ((todo == REMOVE_DEVICE) &&
					(dtype == DTYPE_DIRECT ||
					dtype == DTYPE_SEQUENTIAL)) {
				dev_location = NON_SENA;

				if ((err = h_get_fcdev_state(argv[path_index],
						path_phys, force_flag,
						&busy_flag, &reserve_flag,
						verbose_flag)) != 0) {
					goto done;
				}
				(void) strcpy(dev_path, path_phys);
				if ((err = g_get_wwn(dev_path, port_wwn,
						node_wwn, &al_pa,
						verbose_flag)) != 0) {
					goto done;
				}
				(void) sprintf(node_wwn_s,
				"%1.2x%1.2x%1.2x%1.2x%1.2x%1.2x%1.2x%1.2x",
				node_wwn[0], node_wwn[1], node_wwn[2],
				node_wwn[3], node_wwn[4], node_wwn[5],
				node_wwn[6], node_wwn[7]);
				tid = g_sf_alpa_to_switch[al_pa];
				goto loop;
			}
			continue;
		}

		if (strstr(ses_path, "ses") != NULL) {
			dev_location = SENA;
		    if ((err = l_convert_name(ses_path, &physpath,
			    &p_pathstruct, 0)) != 0) {
			free(physpath);
			free(p_pathstruct);
			goto done;

		    }
		    if ((err = g_get_inquiry(physpath, &inq)) != 0) {
			free(physpath);
			free(p_pathstruct);
			goto done;
		    }
		    enc_type = l_get_enc_type(inq);

		}
		if ((err = l_get_status(ses_path,
				&l_state, verbose_flag)) != 0) {
			goto done;
		}
		if (dtype == DTYPE_ESI) {
			/* could be removing a photon */
			if (todo == REMOVE_DEVICE) {
				/*
				 * Need the select ID (tid) for the IB.
				 */
				if ((err = g_get_wwn(ses_path, port_wwn,
						node_wwn, &al_pa,
						verbose_flag)) != 0) {
						goto done;
				}
				(void) sprintf(node_wwn_s,
				"%1.2x%1.2x%1.2x%1.2x%1.2x%1.2x%1.2x%1.2x",
				node_wwn[0], node_wwn[1], node_wwn[2],
				node_wwn[3], node_wwn[4], node_wwn[5],
				node_wwn[6], node_wwn[7]);
				tid = g_sf_alpa_to_switch[al_pa];
				*dev_path = '\0';
				/*
				 * Check if any disk in this photon
				 * is reserved by another host
				 */
				if (!force_flag) {
					for (
					i = 0;
					i < l_state.total_num_drv/2;
					i++) {
		if ((l_state.drv_front[i].g_disk_state.d_state_flags[PORT_A] &
							L_RESERVED) ||
		(l_state.drv_front[i].g_disk_state.d_state_flags[PORT_B] &
						L_RESERVED) ||
		(l_state.drv_rear[i].g_disk_state.d_state_flags[PORT_A] &
						L_RESERVED) ||
		(l_state.drv_rear[i].g_disk_state.d_state_flags[PORT_B] &
						L_RESERVED)) {
						reserve_flag = 1;
						}
					}
				}
				goto loop;
			}
			(void) fprintf(stderr,
				MSGSTR(5512,
				"Error: %s already exists!!\n"),
				argv[path_index]);
			goto done;
		}
getinfo:
		if (!path_struct->slot_valid) {
			/* We are passing the disks path */
			if ((err = l_get_slot(path_struct, &l_state,
					verbose_flag)) != 0) {
				goto done;
			}
		}

		slot = path_struct->slot;
		if (path_struct->f_flag) {
			tid = l_state.drv_front[slot].ib_status.sel_id;
			code = l_state.drv_front[slot].ib_status.code;
			(void) strcpy(node_wwn_s,
			l_state.drv_front[slot].g_disk_state.node_wwn_s);
		} else {
			tid = l_state.drv_rear[slot].ib_status.sel_id;
			code = l_state.drv_rear[slot].ib_status.code;
			(void) strcpy(node_wwn_s,
			l_state.drv_rear[slot].g_disk_state.node_wwn_s);
		}

		if (found_nullwwn) {
			goto loop;
		}

		l_make_node(ses_path, tid, dev_path, &map, 0);

		if ((todo == INSERT_DEVICE) &&
			(g_device_in_map(&map, tid) ||
			(code != S_NOT_INSTALLED))) {
			(void) fprintf(stderr,
				MSGSTR(5513, "\nNotice: %s may "
				"already be present.\n"),
				argv[path_index]);
			if (path_struct->f_flag) {
				if ((l_state.drv_front[slot].l_state_flag
						!= L_NO_PATH_FOUND) &&
				(!l_state.drv_front[slot].ib_status.dev_off))
					continue;
			} else {
				if ((l_state.drv_rear[slot].l_state_flag
						!= L_NO_PATH_FOUND) &&
				(!l_state.drv_rear[slot].ib_status.dev_off))
					continue;
			}
		}

		/* Check if disk is reserved */
		if ((todo == REMOVE_DEVICE) && (!force_flag)) {
			if (path_struct->f_flag) {
	if ((l_state.drv_front[slot].g_disk_state.d_state_flags[PORT_A] &
						L_RESERVED) ||
		(l_state.drv_front[slot].g_disk_state.d_state_flags[PORT_B] &
						L_RESERVED)) {
					reserve_flag = 1;
				}
			} else {
		if ((l_state.drv_rear[slot].g_disk_state.d_state_flags[PORT_A] &
					L_RESERVED) ||
		(l_state.drv_rear[slot].g_disk_state.d_state_flags[PORT_B] &
						L_RESERVED)) {
					reserve_flag = 1;
				}
			}
		}

loop:
		if ((disk_list = (Hotplug_Devlist *)
			calloc(1, sizeof (Hotplug_Devlist))) == NULL) {
			(void) print_errString(L_MALLOC_FAILED, NULL);
			goto done;
		}

		/*
		 * dev_path is NULL when removing a whole encloser. We
		 * don't want to call g_get_multipath while removing whole
		 * enclosure. Its being taken care later in the code path
		 */

		if ((todo != INSERT_DEVICE) && (dtype != DTYPE_ESI)) {
			if ((err = g_get_multipath(dev_path,
					&(disk_list->dlhead),
					wwn_list, verbose_flag)) != 0) {
				if (disk_list->dlhead != NULL) {
					(void) g_free_multipath(
							disk_list->dlhead);
				}
				goto done;
			}
		}
		disk_list->dev_type = dtype;
		disk_list->dev_location = dev_location;
		(void) strcpy(disk_list->dev_name,
					argv[path_index]);
		disk_list->tid = tid;
		(void) strcpy(disk_list->node_wwn_s, node_wwn_s);
		if (dev_location == SENA) {
			if ((err = l_get_allses(ses_path, box_list,
				&(disk_list->seslist), 0)) != 0) {
				if (disk_list->seslist != NULL) {
				(void) g_free_multipath(disk_list->seslist);
				}
				goto done;
			}
			(void) strcpy(disk_list->box_name,
				(char *)l_state.ib_tbl.enclosure_name);
			disk_list->slot = slot;
			disk_list->f_flag = path_struct->f_flag;
		}
		if (todo == REMOVE_DEVICE && !force_flag && !reserve_flag) {
			if ((err = h_chk_dev_busy(disk_list, wwn_list,
				&busy_flag, force_flag, verbose_flag)) != 0) {
				goto done;
			}
		}

		if (reserve_flag || busy_flag) {
			if (reserve_flag)
				disk_list->reserve_flag = 1;
			if (busy_flag)
				disk_list->busy_flag = 1;

			if (bsyRsrv_dskLst_head == NULL) {
				bsyRsrv_dskLst_head =
					bsyRsrv_dskLst_tail = disk_list;
			} else {
				disk_list->prev = bsyRsrv_dskLst_tail;
				bsyRsrv_dskLst_tail->next = disk_list;
				bsyRsrv_dskLst_tail = disk_list;
			}
			reserve_flag = 0;
			busy_flag = 0;

		} else if (disk_list_head == NULL) {
			disk_list_head = disk_list_tail = disk_list;
		} else {
			disk_list->prev = disk_list_tail;
			disk_list_tail->next = disk_list;
			disk_list_tail = disk_list;
		}
	}

	if (bsyRsrv_dskLst_head != NULL) {
		if ((err = h_print_list(bsyRsrv_dskLst_head,
						&action, enc_type)) != 0) {
			goto done;
		}
		if (action == SKIP) {
			(void) h_free_hotplug_dlist(&bsyRsrv_dskLst_head);
		} else if (action == QUIT) {
			goto done;
		}
	}
	if (disk_list_head != NULL) {
		if ((h_print_list_warn(disk_list_head, todo, enc_type)) != 0) {
			goto done;
		}
	if ((err = h_pre_hotplug(&disk_list_head, wwn_list, todo, verbose_flag,
			    force_flag)) != 0) {
			goto done;
		}
		if (disk_list_head != NULL) {
			if (todo == REMOVE_DEVICE) {
				(void) fprintf(stdout, MSGSTR(5514,
					"\nHit <Return> after "
					"removing the device(s)."));
			} else {
				(void) fprintf(stdout, MSGSTR(5515,
					"\nHit <Return> after "
					"inserting the device(s)."));
			}
			(void) getchar();
			(void) fprintf(stdout, "\n");
			if ((err = h_post_hotplug(disk_list_head, wwn_list,
					todo, verbose_flag, force_flag,
					enc_type)) != 0) {
				goto done;
			}
		}
	}
done:
	(void) l_free_box_list(&box_list);
	(void) g_free_wwn_list(&wwn_list);
	if (err && err != -1) {
		return (err);
	}
	free((void *)map.dev_addr);
	return (0);
}




/*
 * Internal routine to clean up ../'s in paths.
 * returns 0 if no "../" are left.
 *
 * Wouldn't it be nice if there was a standard system library
 * routine to do this...?
 */
static int
cleanup_dotdot_path(char *path)
{
	char holder[MAXPATHLEN];
	char *dotdot;
	char *previous_slash;

	/* Find the first "/../" in the string */
	dotdot = strstr(path, "/../");
	if (dotdot == NULL) {
		return (0);
	}


	/*
	 * If the [0] character is '/' and "../" immediatly
	 * follows it, then we can strip the ../
	 *
	 *	/../../foo/bar == /foo/bar
	 *
	 */
	if (dotdot == path) {
		strcpy(holder, &path[3]); /* strip "/.." */
		strcpy(path, holder);
		return (1);
	}

	/*
	 * Now look for the LAST "/" before the "/../"
	 * as this is the parent dir we can get rid of.
	 * We do this by temporarily truncating the string
	 * at the '/' just before "../" using the dotdot pointer.
	 */
	*dotdot = '\0';
	previous_slash = strrchr(path, '/');
	if (previous_slash == NULL) {
		/*
		 * hmm, somethings wrong.  path looks something
		 * like "foo/../bar/" so we can't really deal with it.
		 */
		return (0);
	}
	/*
	 * Now truncate the path just after the previous '/'
	 * and slam everything after the "../" back on
	 */
	*(previous_slash+1) = '\0';
	(void) strcat(path, dotdot+4);
	return (1); /* We may have more "../"s */
}


/*
 * Follow symbolic links from the logical device name to
 * the /devfs physical device name.  To be complete, we
 * handle the case of multiple links.  This function
 * either returns NULL (no links, or some other error),
 * or the physical device name, alloc'ed on the heap.
 *
 * For S10 the physical path may be non-existent.
 *
 * NOTE: If the path is relative, it will be forced into
 * an absolute path by pre-pending the pwd to it.
 */
char *
h_get_physical_name_from_link(char *path)
{
	struct stat	stbuf;
	char		source[MAXPATHLEN];
	char		scratch[MAXPATHLEN];
	char		pwd[MAXPATHLEN];
	char		*tmp;
	int			cnt;

	/* return NULL if path is NULL */
	if (path == NULL) {
		return (NULL);
	}

	strcpy(source, path);
	for (;;) {

		/*
		 * First make sure the path is absolute.  If not, make it.
		 * If it's already an absolute path, we have no need
		 * to determine the cwd, so the program should still
		 * function within security-by-obscurity directories.
		 */
		if (source[0] != '/') {
			tmp = getcwd(pwd, MAXPATHLEN);
			if (tmp == NULL) {
				O_DPRINTF("getcwd() failed - %s\n",
					strerror(errno));
				return (NULL);
			}
			/*
			 * Handle special case of "./foo/bar"
			 */
			if (source[0] == '.' && source[1] == '/') {
				strcpy(scratch, source+2);
			} else { /* no "./" so just take everything */
				strcpy(scratch, source);
			}
			strcpy(source, pwd);
			(void) strcat(source, "/");
			(void) strcat(source, scratch);
		}

		/*
		 * Clean up any "../"s that are in the path
		 */
		while (cleanup_dotdot_path(source));

		/*
		 * source is now an absolute path to the link we're
		 * concerned with
		 *
		 * S10: Do NOT ignore dangling links, pointing to devfs nodes.
		 */
		if (strstr(source, "/devices")) {
			return (g_alloc_string(source));
		}

		if (lstat(source, &stbuf) == -1) {
			O_DPRINTF("lstat() failed for - %s\n",
				source, strerror(errno));
			return (NULL);
		}
		/*
		 * If the file is not a link, we're done one
		 * way or the other.  If there were links,
		 * return the full pathname of the resulting
		 * file.
		 *
		 * Note:  All of our temp's are on the stack,
		 * so we have to copy the final result to the heap.
		 */
		if (!S_ISLNK(stbuf.st_mode)) {
			return (g_alloc_string(source));
		}
		cnt = readlink(source, scratch, sizeof (scratch));
		if (cnt < 0) {
			O_DPRINTF("readlink() failed - %s\n",
				strerror(errno));
			return (NULL);
		}
		/*
		 * scratch is on the heap, and for some reason readlink
		 * doesn't always terminate things properly so we have
		 * to make certain we're properly terminated
		 */
		scratch[cnt] = '\0';

		/*
		 * Now check to see if the link is relative.  If so,
		 * then we have to append it to the directory
		 * which the source was in. (This is non trivial)
		 */
		if (scratch[0] != '/') {
			tmp = strrchr(source, '/');
			if (tmp == NULL) { /* Whoa!  Something's hosed! */
				O_DPRINTF("Internal error... corrupt path.\n");
				return (NULL);
			}
			/* Now strip off just the directory path */
			*(tmp+1) = '\0'; /* Keeping the last '/' */
			/* and append the new link */
			(void) strcat(source, scratch);
			/*
			 * Note:  At this point, source should have "../"s
			 * but we'll clean it up in the next pass through
			 * the loop.
			 */
		} else {
			/* It's an absolute link so no worries */
			strcpy(source, scratch);
		}
	}
	/* Never reach here */
}

/*
 * Function for getting physical pathnames
 *
 * For S10 the physical path may not exist at the time devctl calls
 * are made. So we should not return error if stat fails on /devices path.
 *
 * This function can handle 2 different inputs.
 *
 * 1) Inputs of the form /dev/rdsk/cNtNdNsN
 *	These are identified by being a link
 *	The physical path they are linked to is returned.
 *
 * 2) Inputs of the form /devices/...
 *	These are actual physical names.
 *	They are not converted.
 */
char *
h_get_physical_name(char *path)
{
	struct stat	stbuf;
	char		s[MAXPATHLEN];
	char		savedir[MAXPATHLEN];
	char		*result = NULL;
	int		status = 0;

	/* return invalid path if path NULL */
	if (path == NULL) {
		return (NULL);
	}

	(void) strcpy(s, path);

	status = lstat(s, &stbuf);

	/*
	 * S10: If string is devfs node we allow failed lstat.
	 */
	if ((status == -1) || !S_ISLNK(stbuf.st_mode)) {
		/* Make sure a full path as that is required. */
		if (strstr(s, "/devices")) {
			result = g_alloc_string(s);
		} else {
			if (getcwd(savedir,
				sizeof (savedir)) == NULL) {
				return (NULL);
			}
			/*
			 * Check for this format:
			 * ./ssd@0,1:g,raw
			 */
			if (s[0] == '.') {
				(void) strcat(savedir, &s[1]);
			} else {
				(void) strcat(savedir, "/");
				(void) strcat(savedir, s);
			}
			if ((status != -1) || strstr(s, "/devices")) {
				result = g_alloc_string(savedir);
			}
		}
	} else {
		/*
		 * Entry is linked file
		 * so follow link to physical name
		 */
		result = h_get_physical_name_from_link(path);
	}

exit:
	return (result);
}


/*
 * handle expert-mode hotplug commands
 *
 * return 0 iff all is okay
 */
int
hotplug_e(int todo, char **argv, int verbose_flag, int force_flag)
{
char		*path_phys = NULL;
char		bus_path[MAXPATHLEN];
char		*ptr;
int		exit_code;
devctl_hdl_t	dcp;
uint_t		devstate;
int		i = 0, pathcnt = 1;
mp_pathlist_t	pathlist;
int		p_pw = 0, p_on = 0, p_st = 0;


	switch (todo) {
	case DEV_ONLINE:
	case DEV_OFFLINE:
	case DEV_GETSTATE:
	case DEV_RESET:
		/* get physical name */
		if ((path_phys = h_get_physical_name(argv[0])) == NULL) {

		(void) fprintf(stderr,
				MSGSTR(112, "Error: Invalid pathname (%s)"),
				argv[0]);
		(void) fprintf(stderr, "\n");
			return (1);
		}

		if (verbose_flag) {
			(void) fprintf(stdout,
					MSGSTR(5516,
					"phys path = \"%s\"\n"),
					path_phys);
		}

		/* acquire rights to hack on device */
		if ((dcp = devctl_device_acquire(path_phys,
			force_flag ? 0 : DC_EXCL)) == NULL) {

			(void) fprintf(stderr, MSGSTR(5517,
			    "Error: can't acquire \"%s\": %s\n"),
			    path_phys, strerror(errno));
			return (1);
		}

		switch (todo) {
		case DEV_ONLINE:
			exit_code = devctl_device_online(dcp);
			break;
		case DEV_OFFLINE:
			exit_code = devctl_device_offline(dcp);
			break;
		case DEV_GETSTATE:
			if ((exit_code = devctl_device_getstate(dcp,
				&devstate)) == 0) {
				print_dev_state(argv[0], devstate);
			}
			break;
		case DEV_RESET:
			exit_code = devctl_device_reset(dcp);
			break;
		}

		if (exit_code != 0) {
			perror(MSGSTR(5518, "devctl"));
		}

		/* all done now -- release device */
		devctl_release(dcp);
		break;

	/* for hotplugging bus operations */
	case BUS_QUIESCE:
	case BUS_UNQUIESCE:
	case BUS_GETSTATE:
	case BUS_RESET:
	case BUS_RESETALL:
		/* get physical name */
		if ((path_phys = h_get_physical_name(argv[0])) ==
			NULL) {
			(void) fprintf(stderr,
				MSGSTR(112, "Error: Invalid pathname (%s)"),
				argv[0]);
			(void) fprintf(stderr, "\n");
			return (1);
		}
		if (verbose_flag) {
			printf(MSGSTR(5519, "phys path = \"%s\"\n"), path_phys);
		}

		/* acquire rights to hack on device */
		/* delete leaf part from path_phys. */
		if (strstr(path_phys, SCSI_VHCI) != NULL) {
			/* obtain phci */
			(void) strcpy(bus_path, path_phys);
			if (g_get_pathlist(bus_path, &pathlist)) {
				(void) fprintf(stderr,
			MSGSTR(112, "Error: Invalid pathname (%s)"),
				path_phys);
				(void) fprintf(stderr, "\n");
				return (1);
			}
			pathcnt = pathlist.path_count;
			p_pw = p_on = p_st = 0;
			for (i = 0; i < pathcnt; i++) {
				if (pathlist.path_info[i].path_state <
					MAXPATHSTATE) {
					if (strstr(pathlist.path_info[i].
						path_addr,
						argv[0]) != NULL) {
						p_pw = i;
						break;
					}
					if (pathlist.path_info[i].path_state ==
						MDI_PATHINFO_STATE_ONLINE) {
						p_on = i;
					}
					if (pathlist.path_info[i].path_state ==
						MDI_PATHINFO_STATE_STANDBY) {
						p_st = i;
					}
				}
			}
			if (strstr(pathlist.path_info[p_pw].path_addr,
				argv[0]) != NULL) {
				/* matching input pwwn */
				(void) strcpy(bus_path,
					pathlist.path_info[p_pw].path_hba);
			} else if (pathlist.path_info[p_on].path_state ==
				MDI_PATHINFO_STATE_ONLINE) {
				/* on_line path */
				(void) strcpy(bus_path,
					pathlist.path_info[p_on].path_hba);
			} else {
				/* standby or path0 */
				(void) strcpy(bus_path,
					pathlist.path_info[p_st].path_hba);
			}
			free(pathlist.path_info);
		} else {

			(void) strcpy(bus_path, path_phys);
			ptr = strrchr(bus_path, '/');
			if (ptr) {
				*ptr = '\0';
			} else {
				(void) fprintf(stderr,
				MSGSTR(112, "Error: Invalid pathname (%s)"),
					path_phys);
				(void) fprintf(stderr, "\n");
				return (1);
			}
		}

		if ((dcp = devctl_bus_acquire(bus_path,
			force_flag ? 0 : DC_EXCL)) == NULL) {
			(void) fprintf(stderr,
					MSGSTR(5521,
				" Error: can't acquire bus node from"
					" the path \"%s\": %s\n"),
					bus_path, strerror(errno));
			return (1);
		}

		switch (todo) {
		case BUS_QUIESCE:
			exit_code = devctl_bus_quiesce(dcp);
			break;
		case BUS_UNQUIESCE:
			exit_code = devctl_bus_unquiesce(dcp);
			break;
		case BUS_GETSTATE:
			if ((exit_code = devctl_bus_getstate(dcp,
				&devstate)) == 0) {
				print_bus_state(argv[0], devstate);
			}
			break;
		case BUS_RESET:
			exit_code = devctl_bus_reset(dcp);
			break;
		case BUS_RESETALL:
			exit_code = devctl_bus_resetall(dcp);
			break;
		}

		if (exit_code != 0) {
			perror(MSGSTR(5522, "devctl"));
		}

		/* all done now -- release device */
		devctl_release(dcp);
		break;
	}

	return (exit_code);
}



/*
 * Prepares an individual FC_AL device
 * to be removed from the specified
 * slot.
 *
 * RETURNS:
 *	0	 if OK
 *	non-zero otherwise.
 */
static	int
h_pre_remove_dev(Hotplug_Devlist *hotplug_disk, WWN_list *wwn_list,
			int verbose_flag, int force_flag)
{
char		*dev_path, device_name[MAXNAMELEN];
int		err;

	/* Initialize pointers */
	dev_path = NULL;

	if (hotplug_disk->dlhead != NULL) {
		dev_path = hotplug_disk->dlhead->dev_path;
	(void) strcpy(device_name, (hotplug_disk->dlhead)->logical_path);
	}
	(void) fprintf(stdout,
			MSGSTR(157,
			"stopping:  %s...."), device_name);
	if (!(strstr(dev_path, SLSH_DRV_NAME_ST))) {
		if ((err = g_dev_stop(dev_path, wwn_list, verbose_flag)) != 0)
			return (err);
	}
	(void) fprintf(stdout, MSGSTR(156, "Done\n"));

	(void) fprintf(stdout,
			MSGSTR(158, "offlining: %s...."), device_name);
	if ((err = g_offline_drive(hotplug_disk->dlhead,
						force_flag)) != 0) {
		(void) fprintf(stdout,
				MSGSTR(160,
				"\nonlining: %s\n"), device_name);

		(void) g_online_drive(hotplug_disk->dlhead, force_flag);
		(void) fprintf(stdout,
				MSGSTR(159, "starting:  %s...."),
				device_name);
		if ((err = g_dev_start(dev_path, 0)) != 0) {
			return (err);
		}
		(void) fprintf(stdout, MSGSTR(156, "Done\n"));
		return (err);
	}
	(void) fprintf(stdout, MSGSTR(156, "Done\n"));
	return (0);
}



/*
 * Prepares a SENA enclosure or SENA FC_AL device
 * to be inserted/removed from a specified slot.
 *
 * RETURNS:
 *	0	 if OK
 *	non-zero otherwise.
 */
static	int
h_pre_hotplug_sena(Hotplug_Devlist *hotplug_dev,
			WWN_list *wwn_list, int todo,
			int verbose_flag, int force_flag)
{
int			slot, f_r, i, found_null_wwn = 0, err;
char			*ses_path, *dev_path, code;
char			node_wwn_s[WWN_SIZE], device_name[MAXNAMELEN];
struct l_state_struct	l_state;
struct dlist		*dl;


	if (hotplug_dev->dev_type == DTYPE_ESI) {
		/* entire photon is being removed */
		if ((err = l_offline_photon(hotplug_dev, wwn_list,
				force_flag, verbose_flag)) != 0) {
			return (err);
		}
		return (0);
	}

	/* if device is an individual sena disk */
	dl = hotplug_dev->seslist;
	while (dl) {
		ses_path = dl->dev_path;
		if ((err = l_get_status(ses_path, &l_state,
				verbose_flag)) == 0)
			break;
		dl = dl->next;
	}
	if (dl == NULL) {
		return (L_GET_STATUS_FAILED);
	}

	f_r = hotplug_dev->f_flag;
	slot = hotplug_dev->slot;
	(void) l_get_drive_name(device_name, slot, f_r, hotplug_dev->box_name);

	/* check if disk has null wwn */
	if (f_r) {
		(void) strncpy(node_wwn_s,
		l_state.drv_front[slot].g_disk_state.node_wwn_s, WWN_SIZE);
	} else {
		(void) strncpy(node_wwn_s,
		l_state.drv_rear[slot].g_disk_state.node_wwn_s, WWN_SIZE);
	}
	for (i = 0; i < WWN_SIZE; i++) {
		if (node_wwn_s[i] != '0')
			break;
		found_null_wwn = 1;
	}

	switch (todo) {
		case INSERT_DEVICE:
			if (hotplug_dev->f_flag) {
				code =
				l_state.drv_front[slot].ib_status.code;
			} else {
				code =
				l_state.drv_rear[slot].ib_status.code;
			}
			if (code & S_NOT_INSTALLED) {
				/*
				 * At this point we know that the drive is not
				 * there. Turn on the RQST INSERT bit to make
				 * the LED blink
				 */
				if ((err = l_encl_status_page_funcs
					(SET_RQST_INSRT, 0, todo,
					ses_path, &l_state, f_r, slot,
					verbose_flag)) != 0) {
					(void) print_errString(err,
								device_name);
					(void) fprintf(stderr,
						MSGSTR(5530,
						" %s: could not turn "
						"on LED\n"),
						device_name);
				}
			} else {
				/*
				 * Drive is there so start it.
				 */
				if ((err = l_encl_status_page_funcs
					(SET_DRV_ON, 0, todo,
					ses_path, &l_state, f_r, slot,
					verbose_flag)) != 0) {
					(void) print_errString(err,
								device_name);
					(void) fprintf(stderr,
						MSGSTR(5531,
						" could not enable"
						" %s\n"),
						device_name);
				}
			}
			break;

		case REMOVE_DEVICE:
			/*
			 * if disk has null wwn, then
			 * there is no need to check the
			 * disk/loop status.
			 */
			if (found_null_wwn == 1) {
				if (getenv("_LUX_W_DEBUG") != NULL) {
					(void) fprintf(stdout,
						"Device %s has "
						"null WWN.\n",
						device_name);
				}
				goto rmv;
			}
			if (hotplug_dev->f_flag) {
				if (
			l_state.drv_front[slot].ib_status.code
					== S_NOT_INSTALLED) {
				(void) fprintf(stderr,
						MSGSTR(86,
					" Notice: %s may already"
					" be removed.\n"),
					device_name);
				return (0);
				}
			} else if (
			l_state.drv_rear[slot].ib_status.code
					== S_NOT_INSTALLED) {
				(void) fprintf(stderr,
					MSGSTR(86,
					" Notice: %s may already"
					" be removed.\n"),
					device_name);
				return (0);
			}

rmv:
		if (hotplug_dev->dlhead == NULL) {
			dev_path = NULL;
		} else {
			dev_path = hotplug_dev->dlhead->dev_path;
		}

		(void) fprintf(stdout,
				MSGSTR(157,
				"stopping:  %s...."), device_name);
		if ((err = g_dev_stop(dev_path, wwn_list, 0)) != 0) {
			return (err);
		}
		(void) fprintf(stdout, MSGSTR(156, "Done\n"));

		(void) fprintf(stdout,
				MSGSTR(158, "offlining: %s...."),
				device_name);
		if ((err = g_offline_drive(hotplug_dev->dlhead,
						force_flag)) != 0) {
			(void) fprintf(stdout,
					MSGSTR(160,
				"\nonlining: %s\n"), device_name);
			(void) g_online_drive(hotplug_dev->dlhead, force_flag);

			(void) fprintf(stdout,
					MSGSTR(159, "starting:  %s...."),
					device_name);
			(void) g_dev_start(dev_path, 0);
			(void) fprintf(stdout, MSGSTR(156, "Done\n"));
			return (err);
		}
		(void) fprintf(stdout, MSGSTR(156, "Done\n"));

		/*
		 * Take the drive off the loop
		 * and blink the LED.
		 */
		if (hotplug_dev->dev_location == SENA) {
			if ((err = l_encl_status_page_funcs(SET_RQST_RMV, 0,
				todo, ses_path, &l_state, f_r,
				slot, verbose_flag)) != 0) {
				(void) print_errString(err, device_name);
				(void) fprintf(stderr,
					MSGSTR(5539,
					" %s: could not blink"
					" the yellow LED\n"),
					device_name);
			}
		}
		break;
	}
	return (0);
}



/*
 * Performs the post removal operations for
 * a SENA enclosure or a SENA FC_AL disk.
 *
 * RETURNS:
 *	0	 if OK
 *	non-zero otherwise
 */
static	int
h_post_hotplug_sena(Hotplug_Devlist *hotplug_dev,
			WWN_list *wwn_list, int todo,
			int verbose_flag, int force_flag, int enc_type)
{
char			*ses_path, *dev_path = NULL, device_name[MAXNAMELEN];
int			tid, slot, f_r, al_pa, timeout = 0;
uchar_t			port_wwn[WWN_SIZE], node_wwn[WWN_SIZE];
char			code;
int			wait_spinup_flag = 0, wait_map_flag = 0;
int			wait_node_flag = 0, err = 0, nArg;
gfc_map_t		map;
WWN_list		*newWwn_list = NULL;
struct dlist		*dl, *dl1;
struct l_state_struct	l_state;


	dl = hotplug_dev->seslist;
	slot = hotplug_dev->slot;
	f_r = hotplug_dev->f_flag;
	tid = hotplug_dev->tid;

	if (hotplug_dev->dev_type == DTYPE_ESI) {
		/*
		 * See if photon has really been removed. If not,
		 * try onlining the devices if applicable
		 */
		H_DPRINTF("  post_hotplug_sena: Seeing if enclosure "
			"has really been removed:\n"
			"  tid=0x%x, ses_path %s\n",
			tid, dl->dev_path);

		while (dl) {
			ses_path = dl->dev_path;
			if ((err = g_get_dev_map(ses_path, &map, 0)) == 0) {
				if ((map.hba_addr.port_topology ==
					FC_TOP_PUBLIC_LOOP) ||
					(map.hba_addr.port_topology ==
					FC_TOP_FABRIC)) {
					/* public or fabric loop device */
					free((void *)map.dev_addr);
					(void) fprintf(stdout, MSGSTR(5540,
					"This operation is not "
					"supported in this topology.\n"));
					return (0);
				}
				if ((err = g_get_wwn(ses_path, port_wwn,
					node_wwn, &al_pa, verbose_flag)) == 0) {
					tid = g_sf_alpa_to_switch[al_pa];
					if (g_device_in_map(&map, tid)) {
						free((void *)map.dev_addr);
						break;
					}
				}
				FREE_DEV_ADDR(map.dev_addr);
			}

			dl = dl->next;
		}
		FREE_DEV_ADDR(map.dev_addr);
		if (dl) {
			(void) fprintf(stdout, MSGSTR(5640,
				"Photon \"%s\" not removed."
				" Onlining Drives in enclosure.\n"),
				hotplug_dev->box_name);
			for (dl = hotplug_dev->dlhead; dl; ) {
				(void) g_online_drive(dl->multipath,
						force_flag);
				(void) g_free_multipath(dl->multipath);
				dl1 = dl;
				dl = dl->next;
				(void) free(dl1);
			}
			hotplug_dev->dlhead = NULL;
			return (0);
		}
		/*
		 * Remove logical nodes for this
		 * photon, this includes ses and
		 * /dev/dsk entries.
		 * In Solaris7, disks with -C option
		 * removes the /dev/dsk entries.
		 * The -C option is available
		 * only for Solaris7. From Solaris8
		 * or higher releases, the "disks"
		 * program will be replaced by the
		 * devfsadm program.
		 */
		/* pass "disks -C" as cmdStrg. */
		nArg = 2;
		if (h_execCmnd(cmdStrg[0], nArg) != 0) {
			for (dl = hotplug_dev->dlhead;
				dl != NULL; dl = dl->next) {
				if ((err = h_remove_nodes(dl->multipath))
								!= 0) {
					return (err);
				}
			}
		} else {
			(void) fprintf(stdout,
					MSGSTR(5541,
				"  Logical Nodes being removed"
				" under /dev/dsk/ and /dev/rdsk:\n"));
			for (dl = hotplug_dev->dlhead;
					dl != NULL; dl = dl->next) {
				(void) h_print_logical_nodes(dl->multipath);
			}
		}

		for (dl = hotplug_dev->dlhead; dl != NULL; ) {
			(void) g_free_multipath(dl->multipath);
			dl1 = dl;
			dl = dl->next;
			(void) free(dl1);
		}
		hotplug_dev->dlhead = NULL;
		if ((err =  h_remove_ses_nodes(hotplug_dev->seslist)) != 0) {
			return (err);
		}
		return (0);
	}

	/* post hotplug operations for a SENA disk. */
	if (enc_type == DAK_ENC_TYPE) {
		(void) sprintf(device_name, MSGSTR(5664,
		    "  Drive in Box Name \"%s\" slot %d"),
		    hotplug_dev->box_name,
		    f_r ? slot : slot + (MAX_DRIVES_DAK/2));
	} else {
		if (tid & 0x10) {
			(void) sprintf(device_name, MSGSTR(5542,
			    "  Drive in Box Name \"%s\" rear slot %d"),
			    hotplug_dev->box_name, slot);
		} else {
			(void) sprintf(device_name, MSGSTR(5543,
			    "  Drive in Box Name \"%s\" front slot %d"),
			    hotplug_dev->box_name, slot);
		}
	}
	(void) fprintf(stdout, "%s\n", device_name);

	dl = hotplug_dev->seslist;
	while (dl) {
		ses_path = dl->dev_path;
		if ((err = l_get_status(ses_path, &l_state,
					verbose_flag)) == 0)
			break;
		dl = dl->next;
	}
	if (dl == NULL) {
		print_errString(err, ses_path);
		return (L_GET_STATUS_FAILED);
	}

	code = 0;
	while (((err = l_encl_status_page_funcs(OVERALL_STATUS,
			&code, todo, ses_path, &l_state, f_r, slot,
			verbose_flag)) != 0) || (code != 0)) {
		if (err) {
			(void) print_errString(err, ses_path);
		} else if (todo == REMOVE_DEVICE) {
			if (code == S_OK) {
				(void) fprintf(stderr,
						MSGSTR(5544,
					"\n  Warning: Device has not been"
					" removed from the enclosure\n"
					"  and is still on the loop."));
				return (0);
			} else {
				(void) fprintf(stderr,
						MSGSTR(5545,
					"  Notice: Device has not been"
					" removed from the enclosure.\n"
					"  It has been removed from the"
					" loop and is ready to be\n"
					"  removed"
					" from the enclosure, and"
					" the LED is blinking.\n\n"));
			}
			goto loop2;
		} else if ((todo == INSERT_DEVICE) &&
				((code != S_NOT_AVAILABLE) ||
				(timeout >
					PHOTON_SPINUP_TIMEOUT) ||
				err)) {
					(void) fprintf(stderr,
						MSGSTR(5546,
						"\n Warning: Disk status is"
						" Not OK!\n\n"));
				return (0);
		}
		(void) sleep(PHOTON_SPINUP_DELAY);
		if (wait_spinup_flag++ == 0) {
			(void) fprintf(stdout, MSGSTR(5547,
				" Waiting for the disk to spin up:"));
		} else {
			(void) fprintf(stdout, ".");
		}
		timeout++;
	}
	if (wait_spinup_flag) {
		(void) fprintf(stdout, "\n");
	}
loop2:
	switch (todo) {
		case INSERT_DEVICE:
			/* check loop map that drive is present */
			for (;;) {
				dl = hotplug_dev->seslist;
				map.dev_addr = (gfc_port_dev_info_t *)NULL;
				while (dl) {
					ses_path = dl->dev_path;
					if ((err = g_get_dev_map(ses_path,
						&map, verbose_flag)) != 0) {
					(void) fprintf(stderr,
							MSGSTR(5548,
						" Error: Could not get"
						" map for %s.\n"),
							ses_path);
						return (err);
					}
				if (g_device_in_map(&map, tid)) {
						goto loop3;
					}
					FREE_DEV_ADDR(map.dev_addr);
					dl = dl->next;
				}
				if (timeout > PHOTON_SPINUP_TIMEOUT) {
					(void) fprintf(stderr,
						MSGSTR(5549,
						" Warning: Device not in"
						" loop map.\n"));
					FREE_DEV_ADDR(map.dev_addr);
					return (0);
				}
				if (wait_map_flag++ == 0) {
					(void) fprintf(stdout,
						MSGSTR(5550,
					"  Waiting for the device "
					"to appear in the loop map:"));
				} else {
					(void) fprintf(stdout, ".");
				}
				timeout++;
				(void) sleep(PHOTON_SPINUP_DELAY);
			}
loop3:
			if (wait_map_flag) {
				(void) fprintf(stdout, "\n");
			}

			/*
			 * Run drvconfig and disks to create
			 * logical nodes
			 */
			for (;;) {
				/* pass "disks" as cmdStrg */
				nArg = 3;
				if (h_execCmnd(cmdStrg[2], nArg) != 0) {
					(void) fprintf(stderr,
							MSGSTR(5551,
							" Could not "
						"run drvconfig.\n"));
					FREE_DEV_ADDR(map.dev_addr);
					return (L_DRVCONFIG_ERROR);
				}

				if (l_device_present(ses_path, tid, &map,
					verbose_flag, &dev_path) == 1)
					break;
				if (timeout > PHOTON_SPINUP_TIMEOUT) {
					(void) fprintf(stderr,
							MSGSTR(5552,
						" Warning: Could not find "
						"any node for inserted "
						"device\n"));
					FREE_DEV_ADDR(map.dev_addr);
					return (0);
				}
				if (wait_node_flag++ == 0) {
					(void) fprintf(stdout,
						MSGSTR(5553,
					"  Waiting for the logical "
					"node to be created:"));
				} else {
					(void) fprintf(stdout, ".");
				}
				timeout++;
				(void) sleep(PHOTON_SPINUP_DELAY);
			}
			FREE_DEV_ADDR(map.dev_addr);
			if (wait_node_flag) {
				(void) fprintf(stdout, "\n");
			}
			/*
			 * In Solaris7, disks with -C
			 * option creates the new links
			 * and removes any stale links.
			 * In pre-Solaris7 releases, just
			 * disks should do it all.
			 */
			/* pass "disks -C" as cmdStrg */
			nArg = 2;
			if (h_execCmnd(cmdStrg[0], nArg) != 0) {
				return (L_DISKS_ERROR);
			}
			/*
			 * Get a new wwn list here in order to
			 * get the multiple paths to a newly added
			 * device.
			 */
			if ((err = g_get_wwn_list(&newWwn_list,
						verbose_flag)) != 0) {
				return (err);
			}
			if ((err = g_get_multipath(dev_path, &dl,
					newWwn_list, 0)) != 0) {
				return (err);
			}
			if ((err = h_display_logical_nodes(dl)) != 0) {
				return (err);
			}
			break;

		case REMOVE_DEVICE:
/*
 * TBD
 * Need to check all loops.
 */
			/* check whether device is still in loop map */
			if ((err = g_get_dev_map(ses_path, &map,
					verbose_flag)) != 0) {
				return (err);
			}

			if ((map.hba_addr.port_topology ==
				FC_TOP_PUBLIC_LOOP) ||
				(map.hba_addr.port_topology ==
				FC_TOP_FABRIC)) {
				/* public or fabric loop device */
				free((void *)map.dev_addr);
				(void) fprintf(stderr, MSGSTR(5540,
				"This operation is not "
				"supported in this topology.\n"));
				/*
				 * calling routine expects a 0 return code
				 * or a pre-defined luxadm error code.
				 * Here we do not have a pre-defined error
				 * code, a 0 is returned.
				 */
				return (0);
			}

			if (g_device_in_map(&map, tid)) {
				(void) fprintf(stderr, MSGSTR(5554,
				" Warning: Device still in the loop map.\n"));
				FREE_DEV_ADDR(map.dev_addr);
				return (0);
			}
			FREE_DEV_ADDR(map.dev_addr);
			/*
			 * In Solaris7, "disks -C" program
			 * removes the /dev/{r}dsk entries.
			 * The -C option is available only
			 * for Solaris7. From Solaris8 or
			 * higher releases, the "disks" program
			 * will be replaced by devfsadm.
			 */
			/* pass "disks -C" as cmdStrg */
			nArg = 2;
			if (h_execCmnd(cmdStrg[0], nArg) != 0) {
				return (L_DISKS_ERROR);
			}
			(void) fprintf(stdout,
					MSGSTR(5555,
			"  Logical Nodes being removed"
			" under /dev/dsk/ and /dev/rdsk:\n"));
			(void) h_print_logical_nodes(
					hotplug_dev->dlhead);
			break;
	}
	return (0);
}




/*
 * Creates new ses entries under /dev/es
 * directory for the newly added
 * enclosures.
 *
 * RETURNS:
 *	0	 if OK
 *	non-zero otherwise
 */
static	int
h_post_insert_encl(timestruc_t ses_lastmtim)
{
struct stat		ses_stat;
char			lname[MAXPATHLEN];
int			err, found_newlink = 0;
DIR			*dir;
struct dirent		*dirent;
Box_list		*bl1, *box_list = NULL;


	if ((dir = opendir(SES_DIR)) == NULL) {
		return (L_OPEN_ES_DIR_FAILED);
	}
	if ((err = l_get_box_list(&box_list, 0)) != 0) {
		closedir(dir);
		return (err);
	}

	/*
	 * The mod time of /dev/es was newer than the mod time prior to
	 * insert so dir entry is checked at this time.
	 */
	while ((dirent = readdir(dir)) != (struct dirent *)NULL) {
		if (strcmp(dirent->d_name, ".") == 0 ||
			strcmp(dirent->d_name, "..") == 0)
			continue;

		(void) sprintf(lname, SES_DIR"/%s", dirent->d_name);
		if (lstat(lname, &ses_stat) < 0) {
			(void) print_errString(L_LSTAT_ES_DIR_ERROR,
							lname);
			continue;
		}

		for (bl1 = box_list; bl1; bl1 = bl1->box_next) {
			if (strstr(lname, bl1->b_physical_path))
				break;
		}

		if (box_list && bl1)
			continue;

		if (NEWER(ses_stat.st_ctim, ses_lastmtim)) {
			/* New enclosure was detected. */
			found_newlink++;
			if (found_newlink == 1) {
				(void) fprintf(stdout, MSGSTR(5556,
				"  New Logical Nodes under /dev/es:\n"));
			}
			(void) fprintf(stdout, "\t%s\n",
				dirent->d_name);
		}
	}
	if (!found_newlink) {
		(void) fprintf(stdout, MSGSTR(5662,
			" No new enclosure(s) were added!!\n\n"));
	}

	closedir(dir);

	(void) l_free_box_list(&box_list);
	return (0);
}



/*
 * performs the post removal of individual
 * FC_AL disks.
 *
 * RETURNS:
 *	0	 if OK
 *	non-zero otherwise
 */
static	int
h_post_remove_dev(Hotplug_Devlist *hotplug_disk,
    int todo, int verbose_flag)
{
	char		device_name[MAXNAMELEN], *dev_path = NULL;
	int		tid, err;
	gfc_map_t	map;
	int		nArg;


	tid = hotplug_disk->tid;
	(void) sprintf(device_name,
			MSGSTR(5557,
			"\n  Device: %s"),
			(hotplug_disk->dlhead)->logical_path);

	(void) fprintf(stdout, "%s\n", device_name);

	dev_path = (hotplug_disk->dlhead)->dev_path;

	/*
	 * On qlc, after a forcelip on a FC combo box, it sometimes takes 17
	 * seconds for the loop to come back online.  During this 17 seconds,
	 * g_get_dev_map * will return L_NO_DEVICES_FOUND.  This delay
	 * has been added to assure that the L_NO_DEVICES_FOUND returned from
	 * g_get_dev_map is not the result of the 17 second delay on FC combo.
	 * This only affects qlc.
	 */
	if ((err = g_get_dev_map(dev_path, &map, verbose_flag)) != 0) {
		if ((err == L_NO_DEVICES_FOUND) &&
		    (strstr(dev_path, "SUNW,qlc@") != NULL)) {
			sleep(QLC_LIP_DELAY);
			if ((err = g_get_dev_map(dev_path, &map, verbose_flag))
			    != 0) {
				if (err != L_NO_DEVICES_FOUND)
					return (err);
			}
		} else if (err != L_NO_DEVICES_FOUND)
			return (err);
	}

	/*
	 * if g_get_dev_map returns L_NO_DEVICES_FOUND, then there are not
	 * devices attached to the HBA and there is no sense in calling
	 * g_device_in_map().
	 */
	if (err != L_NO_DEVICES_FOUND) {
		if ((map.hba_addr.port_topology == FC_TOP_PUBLIC_LOOP) ||
			(map.hba_addr.port_topology == FC_TOP_FABRIC)) {
			/* public or fabric loop device */
			free((void *)map.dev_addr);
			(void) fprintf(stderr, MSGSTR(5540,
				"This operation is not "
				"supported in this topology.\n"));
			return (0);
		}

		if (g_device_in_map(&map, tid) != 0) {
			(void) fprintf(stderr,
				MSGSTR(5558,
				" Warning: Device has"
				" not been removed from\n"
				"  the slot and is still"
				" in the loop map.\n\n"));
			free((void *)map.dev_addr);
			return (0);
		}
		free((void *)map.dev_addr);
	}
	/*
	 * In Solaris7, "disks -C" program
	 * removes the /dev/{r}dsk entries.
	 * The -C option is available only
	 * for Solaris7. From Solaris8 or
	 * higher releases, the "disks" program
	 * will be replaced by devfsadm.
	 */
	/* pass "disks -C" as cmdStrg. */
	nArg = 2;
	if (h_execCmnd(cmdStrg[0], nArg) != 0) {
		return (L_DISKS_ERROR);
	}
	/* pass "tapes -C as cmdStrg. */
	if (h_execCmnd(cmdStrg[5], nArg) != 0) {
		return (L_TAPES_ERROR);
	}
	(void) h_print_logical_nodes(hotplug_disk->dlhead);

	return (0);
}



/*
 * Gets the last modification time for
 * /dev/es/ and /dev/rdsk directories
 * and passes these values to the caller.
 *
 * RETURNS:
 *	0	 if OK
 *	non-zero in case of error
 */
static	int
h_pre_insert_encl_dev(timestruc_t *ses_time, timestruc_t *dsk_time,
						timestruc_t *rmt_time)
{
struct stat	ses_stat, dsk_stat, rmt_stat;

	if (stat(SES_DIR, &ses_stat) < 0) {
		/*
		 * Even if there exists no /dev/es don't fail it.
		 * The host doesn't have to have any enclosure device
		 * configured.
		 */
		if (errno == ENOENT) {
			ses_time = (timestruc_t *)NULL;
		} else {
			return (L_LSTAT_ES_DIR_ERROR);
		}
	} else {
		*ses_time = ses_stat.st_mtim;
	}

	if (stat(DEV_DSK_DIR, &dsk_stat) < 0) {
		return (L_STAT_DEV_DIR_ERROR);
	} else {
		*dsk_time = dsk_stat.st_mtim;
	}
	if (stat(DEV_TAPE_DIR, &rmt_stat) < 0) {
		/*
		 * Even if there exists no /dev/rmt don't fail it.
		 * The host doesn't have to have any tape device
		 * configured.
		 */
		if (errno == ENOENT) {
			rmt_time = (timestruc_t *)NULL;
		} else {
			return (L_STAT_RMT_DIR_ERROR);
		}
	} else {
		*rmt_time = rmt_stat.st_mtim;
	}

	return (0);
}



/*
 * Waits for loop intialization to complete
 * and runs drvconfig, disks and devlinks to create device nodes
 * for devices that are being added and prints the newly created
 * /dev/rdsk entries.
 *
 * RETURNS:
 *	0	 if OK
 *	non-zero in case of error
 */

static	int
h_post_insert_dev(timestruc_t dsk_lastmtim, timestruc_t rmt_lastmtim)
{
int		found_newlink = 0, nArg;

	(void) fprintf(stdout,
		MSGSTR(5560,
		"\nWaiting for Loop Initialization to complete...\n"));

	/*
	 * We sleep here to let the system create nodes. Not sleeping
	 * could cause the drvconfig below to run too soon.
	 */

	(void) sleep(NODE_CREATION_TIME);

	/*
	 * Run drvconfig and disks to create
	 * logical nodes
	 */
	/* pass "drvconfig" as cmdStrg */
	nArg = 1;
	if (h_execCmnd(cmdStrg[3], nArg) != 0) {
		return (L_DRVCONFIG_ERROR);
	}

	/*
	 * In 2.7, disks with the -C
	 * option should be used to
	 * create new links and remove
	 * any stale links.
	 * In pre-2.7 releases, just
	 * disks should do it all.
	 */

	/* pass "disks -C" as cmdStrg */
	nArg = 2;
	if (h_execCmnd(cmdStrg[0], nArg) != 0) {
		return (L_DISKS_ERROR);
	}
	/* pass "tapes -C as cmdStrg */
	if (h_execCmnd(cmdStrg[5], nArg) != 0) {
		return (L_TAPES_ERROR);
	}

	/* pass "devlinks" as cmdStrg */
	nArg = 1;
	if (h_execCmnd(cmdStrg[4], nArg) != 0) {
		return (L_DEVLINKS_ERROR);
	}

	/* check /dev/dsk  and /dev/rmt for new links */
	found_newlink = h_find_new_device_link(DEV_DSK_DIR, dsk_lastmtim) +
			h_find_new_device_link(DEV_TAPE_DIR, rmt_lastmtim);

	if (!found_newlink) {
		(void) fprintf(stdout, MSGSTR(5562,
			" No new device(s) were added!!\n\n"));
	}

	return (0);
}



/*
 * Performs the pre hotplug operations on SENA enclosure(s),
 * SENA disk(s) and individual fcal disk(s).
 * If the device is failed to remove, then it removes the device from the
 * hotplug list and continues with the next device in the list.
 *
 * RETURNS:
 *	0	 if OK
 *	prints an error message to stderr and returns 0
 */
static int
h_pre_hotplug(Hotplug_Devlist **disk_list_head_ptr,
			WWN_list *wwn_list, int todo,
			int verbose_flag, int force_flag)
{
Hotplug_Devlist	*list, *disk_list;
int		err = 0;

	disk_list = *disk_list_head_ptr;
	while (disk_list != NULL) {
		if ((disk_list->dev_type == DTYPE_ESI) ||
			(disk_list->dev_location == SENA)) {
			if ((err = h_pre_hotplug_sena(disk_list, wwn_list,
				    todo, verbose_flag, force_flag)) != 0) {
				(void) print_errString(err,
						disk_list->dev_name);
				goto delete;
			}
		} else if (disk_list->dev_location == NON_SENA) {
			if ((err = h_pre_remove_dev(disk_list, wwn_list,
					verbose_flag, force_flag)) != 0) {
				(void) print_errString(err,
						disk_list->dev_name);
				goto delete;
			}
		}
		disk_list = disk_list->next;
		continue;
delete:
		list = disk_list->prev;
		if (list != NULL) {
			list->next = disk_list->next;
			if (list->next != NULL)
				list->next->prev = list;
		}
		list = disk_list;
		disk_list = disk_list->next;
		if (list == *disk_list_head_ptr)
			*disk_list_head_ptr = disk_list;
		(void) g_free_multipath(list->seslist);
		(void) g_free_multipath(list->dlhead);
		(void) free(list);
	}
	return (0);
}



/*
 * Performs the post removal of a list of SENA enclosure(s),
 * SENA disk(s) and individual fcal disk(s).
 *
 * RETURNS:
 *	0	 O.K.
 *	non-zero otherwise
 */
static int
h_post_hotplug(Hotplug_Devlist *hotplug_dlist,
			WWN_list *wwn_list, int todo,
			int verbose_flag, int force_flag, int enc_type)
{
Hotplug_Devlist	*list;
int		err;

	/* Do a lip on every loop so that we get the latest loop maps */
	if (todo != INSERT_DEVICE) {
		if ((err = g_forcelip_all(hotplug_dlist)) != 0) {
			return (err);
		}
	}

	while (hotplug_dlist != NULL) {
		if ((hotplug_dlist->dev_location == SENA) ||
			(hotplug_dlist->dev_type == DTYPE_ESI)) {
		if ((err = h_post_hotplug_sena(hotplug_dlist, wwn_list, todo,
				verbose_flag, force_flag, enc_type)) != 0)
			(void) print_errString(err, hotplug_dlist->dev_name);
		} else if (hotplug_dlist->dev_location == NON_SENA) {
			if ((err = h_post_remove_dev(hotplug_dlist,
					todo, verbose_flag)) != 0)
				(void) print_errString(err,
						hotplug_dlist->dev_name);
		}
		list = hotplug_dlist;
		hotplug_dlist = hotplug_dlist->next;
		(void) g_free_multipath(list->seslist);
		(void) g_free_multipath(list->dlhead);
		(void) free(list);
	}
	return (0);
}


/*
 * removes the device's logical paths.
 *
 * RETURNS:
 *	0	 if OK
 *	non-zero otherwise
 */
static	int
h_remove_nodes(struct dlist *dl)
{
char		link[MAXPATHLEN], path[MAXPATHLEN];
char		lname[MAXPATHLEN], *ptr;
DIR		*dir;
struct	dirent	*dirent;
struct	dlist	*dlist;

	if ((dir = opendir(DEV_DSK_DIR)) == NULL) {
		return (L_READ_DEV_DIR_ERROR);
	}
	if (dl == NULL) {
		/* pass "disks" as cmdStrg */
		if (h_execCmnd(cmdStrg[1], 1) != 0) {
			return (L_DISKS_ERROR);
		}
	}

	(void) fprintf(stdout,
			MSGSTR(5563,
			"    Removing Logical Nodes: \n"));

	while ((dirent = readdir(dir)) != (struct dirent *)NULL) {
		if (strcmp(dirent->d_name, ".") == 0 ||
				strcmp(dirent->d_name, "..") == 0) {
			continue;
		}
		(void) sprintf(lname, DEV_DSK_DIR"/%s", dirent->d_name);
		if (readlink((const char *)lname, (char *)link,
					(size_t)MAXPATHLEN) <= 0) {
			(void) fprintf(stderr,
					MSGSTR(5564,
					" Error: Could not read %s\n"),
					lname);
				continue;
		}
		for (dlist = dl; dlist != NULL; dlist = dlist->next) {
			(void) strcpy(path, dlist->dev_path);
			ptr = strrchr(path, ':');
			if (ptr)
				*ptr = '\0';
			if (strstr(link, path)) {
				(void) unlink(lname);
				(void) sprintf(lname, "/dev/rdsk/%s",
							dirent->d_name);
				(void) fprintf(stdout,
						MSGSTR(5565,
						"\tRemoving %s\n"),
						dirent->d_name);
				(void) unlink(lname);
			}
		}
	}
	closedir(dir);
	return (0);
}



/*
 * removes the SENA's ses paths.
 *
 * RETURNS:
 *	0	 if OK
 *	non-zero otherwise
 */
static int
h_remove_ses_nodes(struct dlist *dlist)
{
char		link[MAXPATHLEN], lname[MAXPATHLEN];
DIR		*dir;
struct dirent	*dirent;
struct	dlist	*dl;


	if ((dir = opendir(SES_DIR)) == NULL) {
		return (L_READ_DEV_DIR_ERROR);
	}

	(void) fprintf(stdout, MSGSTR(5566, "  Removing Ses Nodes:\n"));

	/*
	 * Remove the ses entries
	 * of the form ses<#>
	 * from the /dev/es directory.
	 */

	while ((dirent = readdir(dir)) != (struct dirent *)NULL) {
		if (strcmp(dirent->d_name, ".") == 0 ||
			strcmp(dirent->d_name, "..") == 0)
			continue;

		(void) sprintf(lname, SES_DIR"/%s", dirent->d_name);
		if (readlink((const char *)lname, (char *)link,
			(size_t)MAXPATHLEN) <= 0) {
			(void) fprintf(stderr,
					MSGSTR(5564,
					" Error: Could not read %s\n"),
					lname);
			continue;
		}
		for (dl = dlist; dl != NULL; dl = dl->next) {
			if (strstr(link, dl->dev_path)) {
				(void) fprintf(stdout,
						MSGSTR(5568,
						"\tRemoving %s\n"),
						lname);
				(void) unlink(lname);
			}
		}
	}
	closedir(dir);
	(void) g_free_multipath(dlist);
	return (0);
}


/*
 * prints the device's logical
 * paths for disks to stdout.
 *
 * RETURNS:
 *	0	 if OK
 *	non-zero otherwise
 */
static	void
h_print_logical_nodes(struct dlist *disk_list)
{
char		*lpath, *ptr, *buf_ptr, buf[MAXNAMELEN], dev[MAXNAMELEN];
struct dlist	*dlist;
int		i, found_dev = 0;
char		*tape_entries[] = { "", "b", "bn", "c", "cb", "cbn", "cn",
				"h", "hb", "hbn", "hn", "l", "lb",
				"lbn", "ln", "m", "mb", "mbn", "mn",
				"n", "u", "ub", "ubn", "un", NULL};

	for (dlist = disk_list; dlist != NULL; dlist = dlist->next) {
		lpath = dlist->logical_path;
		if ((ptr = strrchr(lpath, 'c')) == NULL)
			continue;
		(void) strcpy(buf, ptr);
		if ((ptr = strrchr(buf, 's')) == NULL)
			continue;
		*(++ptr) = '\0';
		found_dev++;
		if (found_dev == 1)
			(void) fprintf(stdout,
					MSGSTR(5559, "  Logical Nodes being "
					"removed under /dev/dsk/ and "
					"/dev/rdsk:\n"));
		for (i = 0; i <= 7; i++) {
			(void) sprintf(dev, "%s%d", buf, i);
			(void) fprintf(stdout, "\t%s\n", dev);
		}
	}
	found_dev = 0;
	for (dlist = disk_list; dlist != NULL; dlist = dlist->next) {
		lpath = dlist->logical_path;
		if (strstr(lpath, DEV_TAPE_DIR)) {
			if ((ptr = strrchr(lpath, '/')) == NULL)
				continue;
			found_dev++;
			if (found_dev == 1)
				(void) fprintf(stdout, "Logical Nodes being "
						"removed under /dev/rmt:\n");
			ptr++;
			buf_ptr = ptr;
			while (*ptr >= '0' && *ptr <= '9')
				ptr++;
			*ptr = '\0';
			for (i = 0, ptr = tape_entries[0];
					ptr != NULL;
					i++, ptr = tape_entries[i]) {
				(void) sprintf(dev, "%s%s", buf_ptr, ptr);
				(void) fprintf(stdout, "\t%s\n", dev);
			}
		}
	}
}

/*
 * displays logical paths to a
 * device to stdout.
 *
 * RETURNS:
 *	0	 if OK
 *	non-zero otherwise
 */
static int
h_display_logical_nodes(struct dlist *dlist)
{
char		link[MAXPATHLEN], path[MAXPATHLEN];
char		lname[MAXPATHLEN], *d1;
DIR		*dir;
struct	dirent	*dirent;
struct	dlist	*dl;


	if ((dir = opendir(DEV_DSK_DIR)) == NULL) {
		return (L_READ_DEV_DIR_ERROR);
	}
	(void) fprintf(stdout,
			MSGSTR(5569,
			"  Logical Nodes under /dev/dsk and /dev/rdsk :\n"));

	while ((dirent = readdir(dir)) != (struct dirent *)NULL) {
		if (strcmp(dirent->d_name, ".") == 0 ||
			strcmp(dirent->d_name, "..") == 0) {
				continue;
		}
		(void) sprintf(lname, DEV_DSK_DIR"/%s", dirent->d_name);
		if (readlink((const char *)lname, (char *)link,
			(size_t)MAXPATHLEN) <= 0) {
			(void) print_errString(L_SYMLINK_ERROR, lname);
			continue;
		}
		for (dl = dlist; dl; dl = dl->next) {
			(void) strcpy(path, dl->dev_path);
			d1 = strrchr(path, ':');
			if (d1)
				*d1 = '\0';
			if (strstr(link, path)) {
				(void) fprintf(stdout,
						"\t%s\n",
						dirent->d_name);
			}
		}
	}

	closedir(dir);
	return (0);
}



/*
 * prints a list of devices which
 * will be inserted or removed
 * to the stdout and asks for
 * the user's confirmation.
 *
 * RETURNS:
 *	0	 if OK
 *	non-zero otherwise
 */
static int
h_print_list_warn(Hotplug_Devlist *disk_list_head, int todo, int enc_type)
{
int			i;
char			choice[2];
struct dlist		*dl_ses, *dl_multi;
Hotplug_Devlist		*disk_list = disk_list_head;

	(void) fprintf(stdout,
		MSGSTR(5570, "The list of devices which will be "));
	switch (todo) {
		case INSERT_DEVICE:
			(void) fprintf(stdout,
			MSGSTR(5571, "inserted is:\n"));
			break;
		case REMOVE_DEVICE:
			(void) fprintf(stdout,
			MSGSTR(5572, "removed is:\n"));
			break;
	}

	for (i = 1; disk_list; i++, disk_list = disk_list->next) {
		if ((disk_list->dev_type == DTYPE_DIRECT) &&
			(disk_list->dev_location == SENA)) {
		    if (disk_list->f_flag != 0) {
			if (enc_type == DAK_ENC_TYPE) {
			    (void) fprintf(stdout, MSGSTR(5665,
				"  %d: Box Name:    \"%s\" slot %d\n"),
				i, disk_list->box_name, disk_list->slot);
			} else {
			    (void) fprintf(stdout, MSGSTR(137,
				"  %d: Box Name:    \"%s\" front slot %d\n"),
				i, disk_list->box_name, disk_list->slot);
			}
		    } else {
			if (enc_type == DAK_ENC_TYPE) {
			    (void) fprintf(stdout, MSGSTR(5665,
				"  %d: Box Name:    \"%s\" slot %d\n"),
				i, disk_list->box_name,
				disk_list->slot + (MAX_DRIVES_DAK/2));
			} else {
				(void) fprintf(stdout, MSGSTR(136,
				    "  %d: Box Name:    \"%s\" rear slot %d\n"),
				    i, disk_list->box_name, disk_list->slot);
			}
		    }
		} else if (((disk_list->dev_type == DTYPE_DIRECT) ||
				(disk_list->dev_type == DTYPE_SEQUENTIAL)) &&
				(disk_list->dev_location == NON_SENA)) {
			(void) fprintf(stdout, MSGSTR(5573,
					"  %d: Device name: %s\n"),
					i, disk_list->dev_name);
		} else if (disk_list->dev_type == DTYPE_ESI) {
			(void) fprintf(stdout, MSGSTR(5574,
				"  %d: Box name:    %s\n"),
				i, disk_list->box_name);
		}
		if (getenv("_LUX_H_DEBUG") != NULL) {
			if (disk_list->dev_location == SENA) {
				(void) fprintf(stdout,
				"      Select ID:\t0x%x\n",
					disk_list->tid);
				if (disk_list->dev_type != DTYPE_ESI) {
					if (enc_type == DAK_ENC_TYPE) {
						(void) fprintf(stdout,
					    "      Location:   \tSlot %d \n",
					    disk_list->f_flag
					    ? disk_list->slot
					    : disk_list->slot
							+MAX_DRIVES_DAK/2);
					} else {
						(void) fprintf(stdout,
					    "      Location:   \tSlot %d %s \n",
					    disk_list->slot, disk_list->f_flag
					    ? "front" : "rear");
					}
				}
			}
		}
		if (todo == REMOVE_DEVICE) {
			(void) fprintf(stdout, "     ");
			(void) fprintf(stdout, MSGSTR(90, "Node WWN:"));
			(void) fprintf(stdout, "    %s\n",
				disk_list->node_wwn_s);

			(void) fprintf(stdout, "     ");
			(void) fprintf(stdout, MSGSTR(35, "Device Type:"));
			if (disk_list->dev_type == DTYPE_ESI) {
				(void) fprintf(stdout, MSGSTR(5581,
					" SENA (%s)\n"),
					dtype[disk_list->dev_type]);
			} else {
				(void) fprintf(stdout, "%s\n",
					dtype[disk_list->dev_type]);
			}

			if (disk_list->dev_type == DTYPE_ESI) {
				dl_ses = disk_list->seslist;
				(void) fprintf(stdout, MSGSTR(5575,
						"     SES Paths:\n"));
				while (dl_ses) {
					(void) fprintf(stdout, MSGSTR(5576,
					"      %s\n"), dl_ses->dev_path);
					dl_ses = dl_ses->next;
				}
			} else {
				dl_multi = disk_list->dlhead;
				(void) fprintf(stdout, MSGSTR(5577,
						"     Device Paths:\n"));
				while (dl_multi) {
					(void) fprintf(stdout, MSGSTR(5578,
						"      %s\n"),
						dl_multi->logical_path);
					dl_multi = dl_multi->next;
				}
			}
		}
		(void) fprintf(stdout, "\n");
	}
	(void) fprintf(stdout, MSGSTR(5579,
			"\nPlease verify the above list of devices"
			" and\nthen enter 'c' or <CR> to Continue"
			" or 'q' to Quit. [Default: c]: "));

	/* Get the user input and continue accordingly. */
	for (;;) {
		(void) gets(choice);
		if (choice[0] == 'c' || choice[0] == 'C' ||
				choice[0] == 'q' || choice[0] == 'Q' ||
				choice[0] == '\0') {
			break;
		}
		(void) fprintf(stdout, MSGSTR(5580,
			" Enter an appropriate option [c,<CR>,q]: "));
	}

	if (choice[0] == 'q' || choice[0] == 'Q') {
		return (-1);
	}
	return (0);
}


static int
h_find_new_device_link(char *device_dir, timestruc_t lastmtim)
{
struct stat	dsk_stat;
char		lname[MAXPATHLEN], link[MAXPATHLEN];
char		*link_ptr;
DIR		*dir;
struct dirent	*dirent;
int		found_newlink = 0;


	if ((dir = opendir(device_dir)) == NULL) {
		if (errno == ENOENT) {
			return (0);
		} else {
			return (L_READ_DEV_DIR_ERROR);
		}
	}

	while ((dirent = readdir(dir)) != (struct dirent *)NULL) {
		if (strcmp(dirent->d_name, ".") == 0 ||
			strcmp(dirent->d_name, "..") == 0) {
			continue;
		}
		(void) sprintf(lname, "%s/%s", device_dir, dirent->d_name);
		if (lstat(lname, &dsk_stat) < 0) {
			(void) print_errString(L_LSTAT_ES_DIR_ERROR,
									lname);
			continue;
		}
		if (readlink((const char *)lname, (char *)link,
				(size_t)MAXPATHLEN) <= 0) {
			(void) print_errString(L_SYMLINK_ERROR, lname);
			continue;
		}

		/*
		 * "link" can be a relative pathname. But, since
		 * g_get_path_type() only accepts absolute paths, we
		 * will skip to the part where "/devices/" begins and pass a
		 * pointer from there. Since "link" is got from readlink(),
		 * it is unlikely that it will not have /devices string, but
		 * we will check for it anyways.
		 */
		if (!(link_ptr = strstr(link, "/devices/")))
			continue;
		if (!g_get_path_type(link_ptr)) {
			continue;
		}
		if (NEWER(dsk_stat.st_ctim, lastmtim)) {
			found_newlink++;
			if (found_newlink == 1) {
				if (! (strcmp(device_dir, DEV_DSK_DIR))) {
					(void) fprintf(stdout, MSGSTR(5561,
						"  New Logical Nodes under "
						"/dev/dsk and /dev/rdsk :\n"));
				} else {	/* device_dir is /dev/rmt */
					(void) fprintf(stdout, "New Logical "
						"Node under /dev/rmt:\n");
				}
			}
			(void) fprintf(stdout, "\t%s\n", dirent->d_name);
		}
	}
	closedir(dir);
	return (found_newlink);
}


/*
 * prints the device state.
 *
 * RETURNS:
 *	None.
 */
void
print_dev_state(char *devname, int state)
{
	(void) printf("\t%s: ", devname);
	if (state & DEVICE_ONLINE) {
		(void) printf(MSGSTR(3000, "Online"));
		if (state & DEVICE_BUSY) {
			(void) printf(" ");
			(void) printf(MSGSTR(37, "Busy"));
		}
		if (state & DEVICE_DOWN) {
			(void) printf(" ");
			(void) printf(MSGSTR(118, "Down"));
		}
	} else {
		if (state & DEVICE_OFFLINE) {
			(void) printf(MSGSTR(3001, "Offline"));
			if (state & DEVICE_DOWN) {
				(void) printf(" ");
				(void) printf(MSGSTR(118, "Down"));
			}
		}
	}
	(void) printf("\n");
}


/*
 * prints the bus state.
 *
 * RETURNS:
 *	None.
 */
void
print_bus_state(char *devname, int state)
{
	(void) printf("\t%s: ", devname);
	if (state == BUS_QUIESCED) {
		(void) printf(MSGSTR(3002, "Quiesced"));
	} else if (state == BUS_ACTIVE) {
		(void) printf(MSGSTR(39, "Active"));
	} else if (state == BUS_SHUTDOWN) {
		(void) printf(MSGSTR(3003, "Shutdown"));
	}
	(void) printf("\n");
}
