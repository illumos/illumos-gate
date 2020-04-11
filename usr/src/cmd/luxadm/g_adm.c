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



#define	LUX_SF_INST_SHIFT4MINOR 6
#define	LUX_SF_MINOR2INST(x)    (x >> LUX_SF_INST_SHIFT4MINOR)

#include	<stdlib.h>
#include	<stdio.h>
#include	<sys/file.h>
#include	<sys/errno.h>
#include	<sys/types.h>
#include	<sys/stat.h>
#include	<sys/param.h>
#include	<kstat.h>
#include	<sys/mkdev.h>
#include	<locale.h>
#include	<nl_types.h>
#include	<fcntl.h>
#include	<unistd.h>
#include	<strings.h>
#include	<ctype.h>
#include	<dirent.h>
#include	<limits.h>
#include	<stdarg.h>
#include	<termio.h>		/* For password */
#include	<signal.h>
#include	<sys/scsi/scsi.h>
#include	<sys/scsi/generic/commands.h>
#include	<l_common.h>
#include	<l_error.h>
#include	<stgcom.h>
#include	<a_state.h>
#include	<devid.h>
#include	<g_state.h>
#include	"common.h"

extern char		*dtype[];
extern char		*whoami;
extern	int	Options;
extern	const	int OPTION_A;
extern	const	int OPTION_B;
extern	const	int OPTION_C;
extern	const	int OPTION_D;
extern	const	int OPTION_E;
extern	const	int OPTION_F;
extern	const	int OPTION_L;
extern	const	int OPTION_P;
extern	const	int OPTION_R;
extern	const	int OPTION_T;
extern	const	int OPTION_V;
extern	const	int OPTION_Z;
extern	const	int OPTION_Y;
extern	const	int OPTION_CAPF;
extern	const	int PVERBOSE;
extern	const	int SAVE;
extern	const	int EXPERT;

static		struct termios	termios;
static		int termio_fd;
static	void	pho_display_config(char *);
static	void	dpm_display_config(char *);
static	void	n_rem_list_entry(uchar_t,  struct gfc_map *,
		WWN_list **);
static	void	n_rem_list_entry_fabric(int, struct gfc_map *,
		WWN_list **);
static	void	n_rem_wwn_entry(uchar_t *, WWN_list **);
static	void	display_disk_info(L_inquiry, L_disk_state,
		Path_struct *, struct mode_page *, int, char *, int);
static	void	display_lun_info(L_disk_state, Path_struct *,
		struct mode_page *, int, WWN_list *, char *);
static	void	display_fc_disk(struct path_struct *, char *, gfc_map_t *,
		L_inquiry, int);
static	void	adm_display_err(char *, int);
static	void	temperature_messages(struct l_state_struct *, int);
static	void	ctlr_messages(struct l_state_struct *, int, int);
static	void	fan_messages(struct l_state_struct *, int, int);
static	void	ps_messages(struct l_state_struct *, int, int);
static	void	abnormal_condition_display(struct l_state_struct *);
static	void	loop_messages(struct l_state_struct *, int, int);
static	void	revision_msg(struct l_state_struct *, int);
static	void	mb_messages(struct l_state_struct *, int, int);
static	void	back_plane_messages(struct l_state_struct *, int, int);
static	void	dpm_SSC100_messages(struct l_state_struct *, int, int);
static	void	mb_messages(struct l_state_struct *, int, int);
static	void	back_plane_messages(struct l_state_struct *, int, int);
static	void	dpm_SSC100_messages(struct l_state_struct *, int, int);
static	void	trans_decode(Trans_elem_st *trans);
static	void	trans_messages(struct l_state_struct *, int);
static	void	adm_print_pathlist(char *);
static	void	display_path_info(char *, char *, WWN_list *);
static void	copy_wwn_data_to_str(char *, const uchar_t *);
static void	adm_mplist_free(struct mplist_struct *);
static int	lun_display(Path_struct *path_struct, L_inquiry inq_struct,
		int verbose);
static int	non_encl_fc_disk_display(Path_struct *path_struct,
		L_inquiry inq_struct, int verbose);
static int	get_enclStatus(char *phys_path, char *encl_name, int off_flag);
static int	get_host_controller_pwwn(char *hba_path, uchar_t *pwwn);
static int	get_lun_capacity(char *devpath,
		struct scsi_capacity_16 *cap_data);
static int	get_path_status(char *devpath, int *status);
static int	get_FC4_host_controller_pwwn(char *hba_path, uchar_t *pwwn);

/*
 * Gets the device's state from the SENA IB and
 * checks whether device is offlined, bypassed
 * or if the slot is empty and prints it to the
 * stdout.
 *
 * RETURNS:
 *	0	 O.K.
 *	non-zero otherwise
 */
int
print_devState(char *devname, char *ppath, int fr_flag, int slot,
						int verbose_flag)
{
L_state		l_state;
int		err;
int		i, elem_index = 0;
uchar_t		device_off, ib_status_code, bypass_a_en, bypass_b_en;
Bp_elem_st	bpf, bpr;


	if ((err = l_get_status(ppath, &l_state, verbose_flag)) != 0) {
		(void) print_errString(err, ppath);
		return (err);
	}

	for (i = 0; i <  (int)l_state.ib_tbl.config.enc_num_elem; i++) {
		elem_index++;
		if (l_state.ib_tbl.config.type_hdr[i].type == ELM_TYP_BP) {
			break;
		}
		elem_index += l_state.ib_tbl.config.type_hdr[i].num;
	}
	(void) bcopy((const void *)
			&(l_state.ib_tbl.p2_s.element[elem_index]),
			(void *)&bpf, sizeof (bpf));
	(void) bcopy((const void *)
			&(l_state.ib_tbl.p2_s.element[elem_index + 1]),
			(void *)&bpr, sizeof (bpr));

	if (fr_flag) {
		device_off = l_state.drv_front[slot].ib_status.dev_off;
		bypass_a_en = l_state.drv_front[slot].ib_status.bypass_a_en;
		bypass_b_en = l_state.drv_front[slot].ib_status.bypass_b_en;
		ib_status_code = l_state.drv_front[slot].ib_status.code;
	} else {
		device_off = l_state.drv_rear[slot].ib_status.dev_off;
		bypass_a_en = l_state.drv_rear[slot].ib_status.bypass_a_en;
		bypass_b_en = l_state.drv_rear[slot].ib_status.bypass_b_en;
		ib_status_code = l_state.drv_rear[slot].ib_status.code;
	}
	if (device_off) {
		(void) fprintf(stdout,
				MSGSTR(2000,
				"%s is offlined and bypassed.\n"
				" Could not get device specific"
				" information.\n\n"),
				devname);
	} else if (bypass_a_en && bypass_b_en) {
		(void) fprintf(stdout,
				MSGSTR(2001,
				"%s is bypassed (Port:AB).\n"
				" Could not get device specific"
				" information.\n\n"),
				devname);
	} else if (ib_status_code == S_NOT_INSTALLED) {
		(void) fprintf(stdout,
				MSGSTR(2002,
				"Slot %s is empty.\n\n"),
				devname);
	} else if (((bpf.code != S_NOT_INSTALLED) &&
		((bpf.byp_a_enabled || bpf.en_bypass_a) &&
		(bpf.byp_b_enabled || bpf.en_bypass_b))) ||
		((bpr.code != S_NOT_INSTALLED) &&
		((bpr.byp_a_enabled || bpr.en_bypass_a) &&
		(bpr.byp_b_enabled || bpr.en_bypass_b)))) {
		(void) fprintf(stdout,
				MSGSTR(2003,
				"Backplane(Port:AB) is bypassed.\n"
				" Could not get device specific"
				" information for"
				" %s.\n\n"), devname);
	} else {
		(void) fprintf(stderr,
				MSGSTR(33,
				" Error: converting"
				" %s to physical path.\n"
				" Invalid pathname.\n"),
				devname);
	}
	return (-1);
}

/*
 * Given an error number, this functions
 * calls the get_errString() to print a
 * corresponding error message to the stderr.
 * get_errString() always returns an error
 * message, even in case of undefined error number.
 * So, there is no need to check for a NULL pointer
 * while printing the error message to the stdout.
 *
 * RETURNS: N/A
 *
 */
void
print_errString(int errnum, char *devpath)
{

char	*errStr;

	errStr = g_get_errString(errnum);

	if (devpath == NULL) {
		(void) fprintf(stderr,
				"%s \n\n", errStr);
	} else {
		(void) fprintf(stderr,
				"%s - %s.\n\n", errStr, devpath);
	}

	/* free the allocated memory for error string */
	if (errStr != NULL)
		(void) free(errStr);
}

/*
 * adm_inquiry() Display the inquiry information for
 * a SENA enclosure(s) or disk(s).
 *
 * RETURNS:
 *	none.
 */
int
adm_inquiry(char **argv)
{
L_inquiry	inq;
L_inquiry80	inq80;
size_t		serial_len;
int		path_index = 0, retval = 0;
int		slot, f_r, err = 0, argpwwn, argnwwn;
char		inq_path[MAXNAMELEN];
char		*path_phys = NULL, *ptr;
Path_struct	*path_struct;
WWN_list	*wwn_list, *wwn_list_ptr, *list_start;
char		last_logical_path[MAXPATHLEN];

	while (argv[path_index] != NULL) {
	    if ((err = l_convert_name(argv[path_index], &path_phys,
		&path_struct, Options & PVERBOSE)) != 0) {
		(void) strcpy(inq_path, argv[path_index]);
		if (((ptr = strstr(inq_path, ",")) != NULL) &&
			((*(ptr + 1) == 'f') || (*(ptr + 1) == 'r') ||
			    (*(ptr +1) == 's'))) {
			if (err != -1) {
				(void) print_errString(err, argv[path_index]);
				path_index++;
				retval++;
				continue;
			}
			*ptr = '\0';
			slot = path_struct->slot;
			f_r = path_struct->f_flag;
			path_phys = NULL;
			if ((err = l_convert_name(inq_path, &path_phys,
				&path_struct, Options & PVERBOSE)) != 0) {
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
				path_index++;
				retval++;
				continue;
			}
			if ((err = print_devState(argv[path_index],
					path_struct->p_physical_path,
					f_r, slot, Options & PVERBOSE)) != 0) {
				path_index++;
				retval++;
				continue;
			}
		} else {
			if (err != -1) {
				(void) print_errString(err, argv[path_index]);
			} else {
			    (void) fprintf(stderr, "\n ");
			    (void) fprintf(stderr,
				MSGSTR(112, "Error: Invalid pathname (%s)"),
				argv[path_index]);
			    (void) fprintf(stderr, "\n");
			}
		}
		path_index++;
		retval++;
		continue;
	    }

	    if (strstr(argv[path_index], "/") != NULL) {
		if (err = g_get_inquiry(path_phys, &inq)) {
		    (void) fprintf(stderr, "\n");
		    (void) print_errString(err, argv[path_index]);
		    (void) fprintf(stderr, "\n");
		    path_index++;
		    retval++;
		    continue;
		}

		serial_len = sizeof (inq80.inq_serial);
		if (err = g_get_serial_number(path_phys, inq80.inq_serial,
		    &serial_len)) {
		    (void) fprintf(stderr, "\n");
		    (void) print_errString(err, argv[path_index]);
		    (void) fprintf(stderr, "\n");
		    path_index++;
		    retval++;
		    continue;
		}
		print_inq_data(argv[path_index], path_phys, inq,
		    inq80.inq_serial, serial_len);
		path_index++;
		continue;
	    }
	    if ((err = g_get_wwn_list(&wwn_list, 0)) != 0) {
		return (err);
	    }
	    g_sort_wwn_list(&wwn_list);
	    list_start = wwn_list;
	    argpwwn = argnwwn = 0;
	    (void) strcpy(last_logical_path, path_phys);
	    for (wwn_list_ptr = wwn_list; wwn_list_ptr != NULL;
		wwn_list_ptr = wwn_list_ptr->wwn_next) {
		if (strcasecmp(wwn_list_ptr->port_wwn_s, path_struct->argv) ==
			0) {
			list_start = wwn_list_ptr;
			argpwwn = 1;
			break;
		} else if (strcasecmp(wwn_list_ptr->node_wwn_s,
			path_struct->argv) == 0) {
			list_start = wwn_list_ptr;
			argnwwn = 1;
			break;
		}
	    }

	    if (!(argpwwn || argnwwn)) {
		/*
		 * if the wwn list is null or the arg device not found
		 * from the wwn list, still go ahead to issue inquiry.
		 */
		if (err = g_get_inquiry(path_phys, &inq)) {
		    (void) fprintf(stderr, "\n");
		    (void) print_errString(err, argv[path_index]);
		    (void) fprintf(stderr, "\n");
		    path_index++;
		    retval++;
		    continue;
		}

		serial_len = sizeof (inq80.inq_serial);
		if (err = g_get_serial_number(path_phys, inq80.inq_serial,
		    &serial_len)) {
		    (void) fprintf(stderr, "\n");
		    (void) print_errString(err, argv[path_index]);
		    (void) fprintf(stderr, "\n");
		    path_index++;
		    retval++;
		    continue;
		}
		print_inq_data(argv[path_index], path_phys, inq,
		    inq80.inq_serial, serial_len);
		(void) g_free_wwn_list(&wwn_list);
		path_index++;
		continue;
	    }

	    for (wwn_list_ptr = list_start; wwn_list_ptr != NULL;
			wwn_list_ptr = wwn_list_ptr->wwn_next) {
		if (argpwwn) {
			if (strcasecmp(wwn_list_ptr->port_wwn_s,
				path_struct->argv) != 0) {
				continue;
			}
			(void) strcpy(path_phys,
				wwn_list_ptr->physical_path);
		} else if (argnwwn) {
			if (strcasecmp(wwn_list_ptr->node_wwn_s,
				path_struct->argv) != 0) {
				continue;
			}
			if (strstr(wwn_list_ptr->logical_path,
				last_logical_path) != NULL) {
				continue;
			}
			(void) strcpy(path_phys,
				wwn_list_ptr->physical_path);
			(void) strcpy(last_logical_path,
				wwn_list_ptr->logical_path);
		}

		if (err = g_get_inquiry(path_phys, &inq)) {
		    (void) fprintf(stderr, "\n");
		    (void) print_errString(err, argv[path_index]);
		    (void) fprintf(stderr, "\n");
		    retval++;
		    break;
		}

		serial_len = sizeof (inq80.inq_serial);
		if (err = g_get_serial_number(path_phys, inq80.inq_serial,
		    &serial_len)) {
		    (void) fprintf(stderr, "\n");
		    (void) print_errString(err, argv[path_index]);
		    (void) fprintf(stderr, "\n");
		    retval++;
		    break;
		}
		print_inq_data(argv[path_index], path_phys, inq,
		    inq80.inq_serial, serial_len);

	    }

	    (void) g_free_wwn_list(&wwn_list);
	    path_index++;
	}
	return (retval);
}

/*
 *	FORCELIP expert function
 */
int
adm_forcelip(char **argv)
{
int		slot, f_r, path_index = 0, err = 0, retval = 0;
Path_struct	*path_struct = NULL;
char		*path_phys = NULL, *ptr;
char		 err_path[MAXNAMELEN];

	while (argv[path_index] != NULL) {
		if ((err = l_convert_name(argv[path_index], &path_phys,
				&path_struct, Options & PVERBOSE)) != 0) {
			(void) strcpy(err_path, argv[path_index]);
			if (err != -1) {
				(void) print_errString(err, argv[path_index]);
				path_index++;
				retval++;
				continue;
			}
			if (((ptr = strstr(err_path, ", ")) != NULL) &&
				((*(ptr + 1) == 'f') || (*(ptr + 1) == 'r') ||
							(*(ptr +1) == 's'))) {
				*ptr = '\0';
				slot = path_struct->slot;
				f_r = path_struct->f_flag;
				path_phys = NULL;
				if ((err = l_convert_name(err_path,
						&path_phys, &path_struct,
						Options & PVERBOSE)) != 0) {
					(void) fprintf(stderr, MSGSTR(33,
						" Error: converting"
						" %s to physical path.\n"
						" Invalid pathname.\n"),
							argv[path_index]);
					if (err != -1) {
						(void) print_errString(err,
							argv[path_index]);
					}
					path_index++;
					retval++;
					continue;
				}
				if ((err = print_devState(argv[path_index],
					path_struct->p_physical_path,
					f_r, slot, Options & PVERBOSE)) != 0) {
					path_index++;
					retval++;
					continue;
				}
			} else {
				(void) fprintf(stderr, "\n ");
				(void) fprintf(stderr, MSGSTR(112,
					"Error: Invalid pathname (%s)"),
							argv[path_index]);
				(void) fprintf(stderr, "\n");
			}
			path_index++;
			retval++;
			continue;
		}
		if (err = g_force_lip(path_phys, Options & PVERBOSE)) {
			(void) print_errString(err, argv[path_index]);
			path_index++;
			retval++;
			continue;
		}
		path_index++;
		if (path_struct != NULL) {
			(void) free(path_struct);
		}
	}
	return (retval);
}


/*
 *	DISPLAY function
 *
 * RETURNS:
 *	0	O.K.
 */
int
adm_display_config(char **argv)
{
L_inquiry	inq, ses_inq;
int		i, slot, f_r, path_index = 0, err = 0, opnerr = 0;
int		retval = 0;
gfc_map_t	map;
Path_struct	*path_struct;
char		*path_phys = NULL, *ptr;
char		ses_path[MAXPATHLEN], inq_path[MAXNAMELEN];


	while (argv[path_index] != NULL) {
	    VERBPRINT(MSGSTR(2108, "  Displaying information for: %s\n"),
			argv[path_index]);
		map.dev_addr = (gfc_port_dev_info_t *)NULL;
	    if ((err = l_convert_name(argv[path_index], &path_phys,
		&path_struct, Options & PVERBOSE)) != 0) {
		if (strstr(argv[path_index], SCSI_VHCI) == NULL) {

			(void) strcpy(inq_path, argv[path_index]);
			if (((ptr = strstr(inq_path, ",")) != NULL) &&
				((*(ptr + 1) == 'f') || (*(ptr + 1) == 'r') ||
				(*(ptr +1) == 's'))) {

				if (err != -1) {
					(void) print_errString(err,
						argv[path_index]);
					path_index++;
					retval++;
					continue;
				}
				*ptr = '\0';
				slot = path_struct->slot;
				f_r = path_struct->f_flag;
				if ((err = l_convert_name(inq_path, &path_phys,
					&path_struct, Options & PVERBOSE))
					!= 0) {

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
					path_index++;
					retval++;
					continue;
				}

				if ((err = print_devState(argv[path_index],
					path_struct->p_physical_path,
					f_r, slot, Options & PVERBOSE)) != 0) {
						path_index++;
						retval++;
						continue;
				}
			} else {
				if (err != -1) {
					(void) print_errString(err,
						argv[path_index]);
				} else {
					(void) fprintf(stderr, "\n ");
					(void) fprintf(stderr,
						MSGSTR(112,
					"Error: Invalid pathname (%s)"),
						argv[path_index]);
					(void) fprintf(stderr, "\n");
				}
			}

		} else {
			if (err != -1) {
				(void) print_errString(err,
					argv[path_index]);
			} else {
				(void) fprintf(stderr, "\n ");
				(void) fprintf(stderr,
					MSGSTR(112,
				"Error: Invalid pathname (%s)"),
					argv[path_index]);
				(void) fprintf(stderr, "\n");
			}
		}

		path_index++;
		retval++;
		continue;
	    }

	/*
	 * See what kind of device we are talking to.
	 */
	if ((opnerr = g_get_inquiry(path_phys, &inq)) != 0) {
		if (opnerr == L_OPEN_PATH_FAIL) {
			/*
			 * We check only for L_OPEN_PATH_FAIL because
			 * that is the only error code returned by
			 * g_get_inquiry() which is not got from the ioctl
			 * call itself. So, we are dependent, in a way, on the
			 * implementation of g_get_inquiry().
			 *
			 */
			(void) print_errString(errno, argv[path_index]);
			path_index++;
			retval++;
			continue;
		}
	    } else if (!g_enclDiskChk((char *)inq.inq_vid,
			(char *)inq.inq_pid)) {
		    if ((err = lun_display(path_struct,
					inq, Options & PVERBOSE)) != 0) {
			    (void) print_errString(err, path_phys);
			    exit(1);
		    }
	    } else if (strstr((char *)inq.inq_pid, ENCLOSURE_PROD_ID) != NULL) {
		/*
		 * Display SENA enclosure.
		 */
		(void) fprintf(stdout, "\n\t\t\t\t   ");
		print_chars(inq.inq_pid, sizeof (inq.inq_pid), 0);

		(void) fprintf(stdout, "\n");
		if (Options & OPTION_R) {
			adm_display_err(path_phys,
			    (inq.inq_dtype & DTYPE_MASK));
		} else {
			pho_display_config(path_phys);
		}
	    } else if ((((inq.inq_dtype & DTYPE_MASK) == DTYPE_ESI)) &&
			(l_get_enc_type(inq) == DAK_ENC_TYPE)) {
		/*
		 *  Display for the Daktari/DPM
		 */
		(void) fprintf(stdout, "\n\t\t");
		for (i = 0; i < sizeof (inq.inq_pid); i++) {
		    (void) fprintf(stdout, "%c", inq.inq_pid[i]);
		}
		(void) fprintf(stdout, "\n");
		if (Options & OPTION_R) {
		    adm_display_err(path_phys,
			(inq.inq_dtype & DTYPE_MASK));
		} else {
		    dpm_display_config(path_phys);
		}
		/*
		 * if device is in SENA enclosure
		 *
		 * if the slot is valid, then I know this is a SENA enclosure
		 * and can continue
		 * otherwise:
		 *	I first get the ses_path, if this doesn't fail
		 *	I retrieve the inquiry data from the ses node
		 *	    and check teh PID to make sure this is a SENA
		 */
	    } else if (((inq.inq_dtype & DTYPE_MASK) == DTYPE_DIRECT) &&
			((path_struct->slot_valid == 1) ||
			    ((g_get_dev_map(path_phys, &map,
				(Options & PVERBOSE)) == 0) &&
			    (l_get_ses_path(path_phys, ses_path,
				&map, Options & PVERBOSE) == 0) &&
			    (g_get_inquiry(ses_path, &ses_inq) == 0) &&
			    ((strstr((char *)ses_inq.inq_pid, ENCLOSURE_PROD_ID)
				!= NULL))))) {
		if (Options & OPTION_R) {
			adm_display_err(path_phys,
			(inq.inq_dtype & DTYPE_MASK));
		} else {
			display_fc_disk(path_struct, ses_path, &map, inq,
							Options & PVERBOSE);
		}

	    } else if (strstr((char *)inq.inq_pid, "SUN_SEN") != 0) {
			if (strcmp(argv[path_index], path_phys) != 0) {
				(void) fprintf(stdout, "  ");
				(void) fprintf(stdout,
				MSGSTR(5, "Physical Path:"));
				(void) fprintf(stdout, "\n  %s\n", path_phys);
			}
			(void) fprintf(stdout, MSGSTR(2109, "DEVICE is a "));
			print_chars(inq.inq_vid, sizeof (inq.inq_vid), 1);
			(void) fprintf(stdout, " ");
			print_chars(inq.inq_pid, sizeof (inq.inq_pid), 1);
			(void) fprintf(stdout, MSGSTR(2110, " card."));
			if (inq.inq_len > 31) {
				(void) fprintf(stdout, "   ");
				(void) fprintf(stdout, MSGSTR(26, "Revision:"));
				(void) fprintf(stdout, " ");
				print_chars(inq.inq_revision,
					sizeof (inq.inq_revision), 0);
			}
			(void) fprintf(stdout, "\n");
		/* if device is not in SENA or SSA enclosures. */
	    } else if ((inq.inq_dtype & DTYPE_MASK) < 0x10) {
		switch ((inq.inq_dtype & DTYPE_MASK)) {
			case DTYPE_DIRECT:
			case DTYPE_SEQUENTIAL: /* Tape */
				if (Options & OPTION_R) {
					adm_display_err(path_phys,
					(inq.inq_dtype & DTYPE_MASK));
				} else if (non_encl_fc_disk_display(path_struct,
					inq, Options & PVERBOSE) != 0) {
					(void) fprintf(stderr,
						MSGSTR(2111,
						"Error: getting the device"
						" information.\n"));
					retval++;
				}
				break;
			/* case 0x01: same as default */
			default:
				(void) fprintf(stdout, "  ");
				(void) fprintf(stdout, MSGSTR(35,
						"Device Type:"));
				(void) fprintf(stdout, "%s\n",
					dtype[inq.inq_dtype & DTYPE_MASK]);
				break;
		}
	    } else if ((inq.inq_dtype & DTYPE_MASK) < 0x1f) {
			(void) fprintf(stdout,
				MSGSTR(2112, "  Device type: Reserved"));
			(void) fprintf(stdout, "\n");
	    } else {
			(void) fprintf(stdout,
				MSGSTR(2113, "  Device type: Unknown device"));
			(void) fprintf(stdout, "\n");
	    }
	    path_index++;
	    if (map.dev_addr != NULL) {
		free((void *)map.dev_addr);
	    }
	    (void) free(path_struct);
	}
	return (retval);
}


/*
 * Powers off a list of SENA enclosure(s)
 * and disk(s) which is provided by the user.
 *
 * RETURNS:
 *	none.
 */
int
adm_power_off(char **argv, int off_flag)
{
int		path_index = 0, err = 0, retval = 0;
L_inquiry	inq;
char		*path_phys = NULL;
Path_struct	*path_struct;

	while (argv[path_index] != NULL) {
		if ((err = l_convert_name(argv[path_index], &path_phys,
			&path_struct, Options & PVERBOSE)) != 0) {
			/*
			 * In case we did not find the device
			 * in the /devices directory.
			 *
			 * Only valid for pathnames like box,f1
			 */
			if (path_struct->ib_path_flag) {
				path_phys = path_struct->p_physical_path;
			} else {
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
				path_index++;
				retval++;
				continue;
			}
		}
		if (path_struct->ib_path_flag) {
			/*
			 * We are addressing a disk using a path
			 * format type box,f1.
			 */
			if (err = l_dev_pwr_up_down(path_phys,
			    path_struct, off_flag, Options & PVERBOSE,
			    Options & OPTION_CAPF)) {
				/*
				 * Is it Bypassed... try to give more
				 * informtaion.
				 */
				print_devState(argv[path_index],
					path_struct->p_physical_path,
					path_struct->f_flag, path_struct->slot,
					Options & PVERBOSE);
				retval++;
			}
			path_index++;
			continue;
		}

		if (err = g_get_inquiry(path_phys, &inq)) {
			(void) print_errString(err, argv[path_index]);
			path_index++;
			retval++;
			continue;
		}
		if ((strstr((char *)inq.inq_pid, ENCLOSURE_PROD_ID) != 0) ||
			(strncmp((char *)inq.inq_vid, "SUN     ",
			sizeof (inq.inq_vid)) &&
			((inq.inq_dtype & DTYPE_MASK) == DTYPE_ESI))) {

			if (get_enclStatus(path_phys, argv[path_index],
						off_flag) != 0) {
				path_index++;
				retval++;
				continue;
			}
			/* power off SENA enclosure. */
			if (err = l_pho_pwr_up_down(argv[path_index], path_phys,
			    off_flag, Options & PVERBOSE,
			    Options & OPTION_CAPF)) {
				(void) print_errString(err, argv[path_index]);
				retval++;
			}
		} else if ((inq.inq_dtype & DTYPE_MASK) == DTYPE_DIRECT) {
			if (err = l_dev_pwr_up_down(path_phys,
			    path_struct, off_flag, Options & PVERBOSE,
			    Options & OPTION_CAPF)) {
				(void) print_errString(err, argv[path_index]);
				retval++;
			}
		} else {
			/*
			 * SSA section:
			 */
			(void) print_errString(L_INVALID_PATH,
						argv[path_index]);
		}
		path_index++;
	}
	return (retval);
}



void
adm_bypass_enable(char **argv, int bypass_flag)
{
int		path_index = 0, err = 0;
L_inquiry	inq;
char		*path_phys = NULL;
Path_struct	*path_struct;

	if ((err = l_convert_name(argv[path_index], &path_phys,
		&path_struct, Options & PVERBOSE)) != 0) {
		/*
		 * In case we did not find the device
		 * in the /devices directory.
		 *
		 * Only valid for pathnames like box,f1
		 */
		if (path_struct->ib_path_flag) {
			path_phys = path_struct->p_physical_path;
		} else {
			(void) fprintf(stderr,
					MSGSTR(33,
						" Error: converting"
						" %s to physical path.\n"
						" Invalid pathname.\n"),
					argv[path_index]);
			if (err != -1) {
				(void) print_errString(err, argv[path_index]);
			}
			exit(-1);
		}
	}
	if (path_struct->ib_path_flag) {
		if (Options & OPTION_F) {
			E_USEAGE();
			exit(-1);
		}
		/*
		 * We are addressing a disk using a path
		 * format type box,f1 and no disk
		 * path was found.
		 * So set the Force flag so no reserved/busy
		 * check is performed.
		 */
		if (err = l_dev_bypass_enable(path_struct,
			bypass_flag, OPTION_CAPF,
			Options & OPTION_A,
			Options & PVERBOSE)) {
			(void) print_errString(err, argv[path_index]);
			exit(-1);
		}
		return;
	}

	if (err = g_get_inquiry(path_phys, &inq)) {
		(void) print_errString(err, argv[path_index]);
		exit(-1);
	}
	if ((strstr((char *)inq.inq_pid, ENCLOSURE_PROD_ID) != 0) ||
		(strncmp((char *)inq.inq_vid, "SUN     ",
		sizeof (inq.inq_vid)) &&
		((inq.inq_dtype & DTYPE_MASK) == DTYPE_ESI))) {
		if ((!((Options & OPTION_F) ||
			(Options & OPTION_R))) ||
			((Options & OPTION_R) &&
			(Options & OPTION_F))) {
			E_USEAGE();
			exit(-1);
		}
		if (err = l_bp_bypass_enable(path_phys, bypass_flag,
			Options & OPTION_A,
			Options & OPTION_F,
			Options & OPTION_CAPF,
			Options & PVERBOSE)) {
		    (void) print_errString(err, argv[path_index]);
		    exit(-1);
		}
	} else if ((inq.inq_dtype & DTYPE_MASK) == DTYPE_DIRECT) {
		if (Options & OPTION_F) {
			E_USEAGE();
			exit(-1);
		}
		if (err = l_dev_bypass_enable(path_struct,
			bypass_flag, Options & OPTION_CAPF,
			Options & OPTION_A,
			Options & PVERBOSE)) {
			(void) print_errString(err, argv[path_index]);
			exit(-1);
		}
	}
}

/*
 * adm_download() Download subsystem microcode.
 * Path must point to a LUX IB.
 *
 * RETURNS:
 *	None.
 */
void
adm_download(char **argv, char *file_name)
{
int		path_index = 0, err = 0;
char		*path_phys = NULL;
L_inquiry	inq;
Path_struct	*path_struct;

	while (argv[path_index] != NULL) {
		/*
		 * See what kind of device we are talking to.
		 */
		if ((err = l_convert_name(argv[path_index], &path_phys,
			&path_struct, Options & PVERBOSE)) != 0) {
			(void) fprintf(stderr,
					MSGSTR(33,
						" Error: converting"
						" %s to physical path.\n"
						" Invalid pathname.\n"),
					argv[path_index]);
			if (err != -1) {
				(void) print_errString(err, argv[path_index]);
			}
			exit(-1);
		}
		if (err = g_get_inquiry(path_phys, &inq)) {
			(void) print_errString(err, argv[path_index]);
			exit(-1);
		}
		if ((strstr((char *)inq.inq_pid, ENCLOSURE_PROD_ID) != 0) ||
			(strncmp((char *)inq.inq_vid, "SUN     ",
			sizeof (inq.inq_vid)) &&
			((inq.inq_dtype & DTYPE_MASK) == DTYPE_ESI))) {
			if (err = l_download(path_phys,
				file_name, (Options & SAVE),
				(Options & PVERBOSE))) {
				(void) print_errString(err,
					(err == L_OPEN_PATH_FAIL) ?
					argv[path_index]: file_name);
				exit(-1);
			}
		} else {
			(void) fprintf(stderr,
				MSGSTR(112, "Error: Invalid pathname (%s)"),
				argv[path_index]);
		}
		path_index++;
	}
}

/*
 * display_link_status() Reads and displays the link status.
 *
 * RETURNS:
 *	none.
 */
void
display_link_status(char **argv)
{
AL_rls		*rls = NULL, *n;
int		path_index = 0, err = 0;
char		*path_phys = NULL;
Path_struct	*path_struct;


	while (argv[path_index] != NULL) {
		if ((err = l_convert_name(argv[path_index], &path_phys,
			&path_struct, Options & PVERBOSE)) != 0) {
			(void) fprintf(stderr,
					MSGSTR(33,
						" Error: converting"
						" %s to physical path.\n"
						" Invalid pathname.\n"),
					argv[path_index]);
			if (err != -1) {
				(void) print_errString(err, argv[path_index]);
			}
			exit(-1);
		}
		if (err = g_rdls(path_phys, &rls, Options & PVERBOSE)) {
		    (void) print_errString(err, argv[path_index]);
		    exit(-1);
		}
		n = rls;
		if (n != NULL) {
			(void) fprintf(stdout,
			MSGSTR(2007, "\nLink Error Status "
				"information for loop:%s\n"),
				n->driver_path);
			(void) fprintf(stdout, MSGSTR(2008, "al_pa   lnk fail "
			"   sync loss   signal loss   sequence err"
			"   invalid word   CRC\n"));
		}
		while (n) {
			if ((n->payload.rls_linkfail == 0xffffffff) &&
			    (n->payload.rls_syncfail == 0xffffffff) &&
			    (n->payload.rls_sigfail == 0xffffffff) &&
			    (n->payload.rls_primitiverr == 0xffffffff) &&
			    (n->payload.rls_invalidword == 0xffffffff) &&
			    (n->payload.rls_invalidcrc == 0xffffffff)) {
				(void) fprintf(stdout,
					"%x\t%-12d%-12d%-14d%-15d%-15d%-12d\n",
					n->al_ha,
					n->payload.rls_linkfail,
					n->payload.rls_syncfail,
					n->payload.rls_sigfail,
					n->payload.rls_primitiverr,
					n->payload.rls_invalidword,
					n->payload.rls_invalidcrc);
			} else {
				(void) fprintf(stdout,
					"%x\t%-12u%-12u%-14u%-15u%-15u%-12u\n",
					n->al_ha,
					n->payload.rls_linkfail,
					n->payload.rls_syncfail,
					n->payload.rls_sigfail,
					n->payload.rls_primitiverr,
					n->payload.rls_invalidword,
					n->payload.rls_invalidcrc);
			}
			n = n->next;
		}

		path_index++;
	}
	(void) fprintf(stdout,
		MSGSTR(2009, "NOTE: These LESB counts are not"
		" cleared by a reset, only power cycles.\n"
		"These counts must be compared"
		" to previously read counts.\n"));
}


/*
 * ib_present_chk() Check to see if IB 0 or 1 is present in the box.
 *
 * RETURN:
 *	1 if ib present
 *	0 otherwise
 */
int
ib_present_chk(struct l_state_struct *l_state, int which_one)
{
Ctlr_elem_st	ctlr;
int	i;
int	elem_index = 0;
int	result = 1;

	for (i = 0; i < (int)l_state->ib_tbl.config.enc_num_elem; i++) {
	    elem_index++;		/* skip global */
	    if (l_state->ib_tbl.config.type_hdr[i].type == ELM_TYP_IB) {
		(void) bcopy((const void *)
			&l_state->ib_tbl.p2_s.element[elem_index + which_one],
			(void *)&ctlr, sizeof (ctlr));
		if (ctlr.code == S_NOT_INSTALLED) {
			result = 0;
		}
		break;
	    }
	    elem_index += l_state->ib_tbl.config.type_hdr[i].num;
	}
	return (result);
}

/*
 * print_individual_state() Print individual disk status.
 *
 * RETURNS:
 *	none.
 */
void
print_individual_state(int status, int port)
{
	if (status & L_OPEN_FAIL) {
		(void) fprintf(stdout, " (");
		(void) fprintf(stdout,
		MSGSTR(28, "Open Failed"));
		(void) fprintf(stdout, ")  ");
	} else if (status & L_NOT_READY) {
		(void) fprintf(stdout, " (");
		(void) fprintf(stdout,
			MSGSTR(20, "Not Ready"));
		(void) fprintf(stdout, ")    ");
	} else if (status & L_NOT_READABLE) {
		(void) fprintf(stdout, "(");
		(void) fprintf(stdout,
		MSGSTR(88, "Not Readable"));
		(void) fprintf(stdout, ")  ");
	} else if (status & L_SPUN_DWN_D) {
		(void) fprintf(stdout, " (");
		(void) fprintf(stdout,
		MSGSTR(68, "Spun Down"));
		(void) fprintf(stdout, ")    ");
	} else if (status & L_SCSI_ERR) {
		(void) fprintf(stdout, " (");
		(void) fprintf(stdout,
		MSGSTR(70, "SCSI Error"));
		(void) fprintf(stdout, ")   ");
	} else if (status & L_RESERVED) {
		if (port == PORT_A) {
			(void) fprintf(stdout,
			MSGSTR(2010,
				" (Rsrv cnflt:A) "));
		} else if (port == PORT_B) {
			(void) fprintf(stdout,
			MSGSTR(2011,
				" (Rsrv cnflt:B) "));
		} else {
			(void) fprintf(stdout,
			MSGSTR(2012,
				" (Reserve cnflt)"));
		}
	} else if (status & L_NO_LABEL) {
		(void) fprintf(stdout, "(");
		(void) fprintf(stdout,
			MSGSTR(92, "No UNIX Label"));
		(void) fprintf(stdout, ") ");
	}
}


/*
 * display_disk_msg() Displays status for
 * an individual SENA device.
 *
 * RETURNS:
 *	none.
 */
void
display_disk_msg(struct l_disk_state_struct *dsk_ptr,
	struct l_state_struct *l_state, Bp_elem_st *bp, int front_flag)
{
int	loop_flag = 0;
int	a_and_b = 0;
int	state_a = 0, state_b = 0;

	if (dsk_ptr->ib_status.code == S_NOT_INSTALLED) {
		(void) fprintf(stdout,
			MSGSTR(30, "Not Installed"));
			(void) fprintf(stdout, " ");
		if (dsk_ptr->ib_status.fault ||
			dsk_ptr->ib_status.fault_req) {
			(void) fprintf(stdout, "(");
			(void) fprintf(stdout,
				MSGSTR(2013, "Faulted"));
			(void) fprintf(stdout,
						")           ");
		} else if (dsk_ptr->ib_status.ident ||
			dsk_ptr->ib_status.rdy_to_ins ||
			dsk_ptr->ib_status.rmv) {
			(void) fprintf(stdout,
				MSGSTR(2014,
						"(LED Blinking)      "));
		} else {
			(void) fprintf(stdout,
						"                    ");
		}
	} else if (dsk_ptr->ib_status.dev_off) {
		(void) fprintf(stdout, MSGSTR(2015, "Off"));
		if (dsk_ptr->ib_status.fault || dsk_ptr->ib_status.fault_req) {
			(void) fprintf(stdout, "(");
			(void) fprintf(stdout,
				MSGSTR(2016, "Faulted"));
			(void) fprintf(stdout,
					")                      ");
		} else if (dsk_ptr->ib_status.bypass_a_en &&
			dsk_ptr->ib_status.bypass_b_en) {
			(void) fprintf(stdout,
				MSGSTR(2017,
					"(Bypassed:AB)"));
			(void) fprintf(stdout,
					"                  ");
		} else if (dsk_ptr->ib_status.bypass_a_en) {
			(void) fprintf(stdout,
				MSGSTR(2018,
					"(Bypassed: A)"));
			(void) fprintf(stdout,
					"                  ");
		} else if (dsk_ptr->ib_status.bypass_b_en) {
			(void) fprintf(stdout,
				MSGSTR(2019,
					"(Bypassed: B)"));
			(void) fprintf(stdout,
					"                  ");
		} else {
			(void) fprintf(stdout,
					"                              ");
		}
	} else {
		(void) fprintf(stdout, MSGSTR(2020, "On"));

		if (dsk_ptr->ib_status.fault || dsk_ptr->ib_status.fault_req) {
			(void) fprintf(stdout, " (");
			(void) fprintf(stdout,
				MSGSTR(2021, "Faulted"));
			(void) fprintf(stdout, ")      ");
		} else if (dsk_ptr->ib_status.bypass_a_en &&
			dsk_ptr->ib_status.bypass_b_en) {
			(void) fprintf(stdout, " ");
			(void) fprintf(stdout,
				MSGSTR(2022, "(Bypassed:AB)"));
			(void) fprintf(stdout, "  ");
		} else if (ib_present_chk(l_state, 0) &&
			dsk_ptr->ib_status.bypass_a_en) {
			/*
			 * Before printing that the port is bypassed
			 * verify that there is an IB for this port.
			 * If not then don't print.
			 */
			(void) fprintf(stdout, " ");
			(void) fprintf(stdout,
				MSGSTR(2023, "(Bypassed: A)"));
			(void) fprintf(stdout, "  ");
		} else if (ib_present_chk(l_state, 1) &&
			dsk_ptr->ib_status.bypass_b_en) {
			(void) fprintf(stdout, " ");
			(void) fprintf(stdout,
				MSGSTR(2024, "(Bypassed: B)"));
			(void) fprintf(stdout, "  ");
		} else if ((bp->code != S_NOT_INSTALLED) &&
				((bp->byp_a_enabled || bp->en_bypass_a) &&
				!(bp->byp_b_enabled || bp->en_bypass_b))) {
			(void) fprintf(stdout,
				MSGSTR(2025,
					" (Bypassed BP: A)"));
		} else if ((bp->code != S_NOT_INSTALLED) &&
				((bp->byp_b_enabled || bp->en_bypass_b) &&
				!(bp->byp_a_enabled || bp->en_bypass_a))) {
			(void) fprintf(stdout,
				MSGSTR(2026,
					"(Bypassed BP: B)"));
		} else if ((bp->code != S_NOT_INSTALLED) &&
				((bp->byp_a_enabled || bp->en_bypass_a) &&
				(bp->byp_b_enabled || bp->en_bypass_b))) {
			(void) fprintf(stdout,
				MSGSTR(2027,
					"(Bypassed BP:AB)"));
		} else {
			state_a = dsk_ptr->g_disk_state.d_state_flags[PORT_A];
			state_b = dsk_ptr->g_disk_state.d_state_flags[PORT_B];
			a_and_b = state_a & state_b;

			if (dsk_ptr->l_state_flag & L_NO_LOOP) {
				(void) fprintf(stdout,
				MSGSTR(2028,
					" (Loop not accessible)"));
				loop_flag = 1;
			} else if (dsk_ptr->l_state_flag & L_INVALID_WWN) {
				(void) fprintf(stdout,
				MSGSTR(2029,
					" (Invalid WWN)  "));
			} else if (dsk_ptr->l_state_flag & L_INVALID_MAP) {
				(void) fprintf(stdout,
				MSGSTR(2030,
					" (Login failed) "));
			} else if (dsk_ptr->l_state_flag & L_NO_PATH_FOUND) {
				(void) fprintf(stdout,
				MSGSTR(2031,
					" (No path found)"));
			} else if (a_and_b) {
				print_individual_state(a_and_b, PORT_A_B);
			} else if (state_a && (!state_b)) {
				print_individual_state(state_a, PORT_A);
			} else if ((!state_a) && state_b) {
				print_individual_state(state_b, PORT_B);
			} else if (state_a || state_b) {
				/* NOTE: Double state - should do 2 lines. */
				print_individual_state(state_a | state_b,
								PORT_A_B);
			} else {
				(void) fprintf(stdout, " (");
				(void) fprintf(stdout,
					MSGSTR(29, "O.K."));
				(void) fprintf(stdout,
					")         ");
			}
		}
		if (loop_flag) {
			(void) fprintf(stdout, "          ");
		} else if (strlen(dsk_ptr->g_disk_state.node_wwn_s)) {
			(void) fprintf(stdout, "%s",
			dsk_ptr->g_disk_state.node_wwn_s);
		} else {
			(void) fprintf(stdout, "                ");
		}
	}
	if (front_flag) {
		(void) fprintf(stdout, "    ");
	}
}



/*
 * pho_display_config() Displays device status
 * information for a SENA enclosure.
 *
 * RETURNS:
 *	none.
 */
void
pho_display_config(char *path_phys)
{
L_state		l_state;
Bp_elem_st	bpf, bpr;
int		i, j, elem_index = 0, err = 0;


	/* Get global status */
	if (err = l_get_status(path_phys, &l_state,
			(Options & PVERBOSE))) {
	    (void) print_errString(err, path_phys);
	    exit(-1);
	}

	/*
	 * Look for abnormal status.
	 */
	if (l_state.ib_tbl.p2_s.ui.ab_cond) {
		abnormal_condition_display(&l_state);
	}

	(void) fprintf(stdout,
		MSGSTR(2032, "                                 DISK STATUS \n"
		"SLOT   FRONT DISKS       (Node WWN)         "
		" REAR DISKS        (Node WWN)\n"));
	/*
	 * Print the status for each disk
	 */
	for (j = 0; j <  (int)l_state.ib_tbl.config.enc_num_elem; j++) {
		elem_index++;
		if (l_state.ib_tbl.config.type_hdr[j].type == ELM_TYP_BP)
			break;
		elem_index += l_state.ib_tbl.config.type_hdr[j].num;
	}
	(void) bcopy((const void *)
		&(l_state.ib_tbl.p2_s.element[elem_index]),
		(void *)&bpf, sizeof (bpf));
	(void) bcopy((const void *)
		&(l_state.ib_tbl.p2_s.element[elem_index + 1]),
		(void *)&bpr, sizeof (bpr));

	for (i = 0; i < (int)l_state.total_num_drv/2; i++) {
		(void) fprintf(stdout, "%-2d     ", i);
		display_disk_msg(&l_state.drv_front[i], &l_state, &bpf, 1);
		display_disk_msg(&l_state.drv_rear[i], &l_state, &bpr, 0);
		(void) fprintf(stdout, "\n");
	}



	/*
	 * Display the subsystem status.
	 */
	(void) fprintf(stdout,
		MSGSTR(2242,
	"                                SUBSYSTEM STATUS\nFW Revision:"));
	print_chars(l_state.ib_tbl.config.prod_revision,
		sizeof (l_state.ib_tbl.config.prod_revision), 1);
	(void) fprintf(stdout, MSGSTR(2034, "   Box ID:%d"),
		l_state.ib_tbl.box_id);
	(void) fprintf(stdout, "   ");
	(void) fprintf(stdout, MSGSTR(90, "Node WWN:"));
	for (i = 0; i < 8; i++) {
		(void) fprintf(stdout, "%1.2x",
		l_state.ib_tbl.config.enc_node_wwn[i]);
	}
	/* Make sure NULL terminated  although it is supposed to be */
	if (strlen((const char *)l_state.ib_tbl.enclosure_name) <=
		sizeof (l_state.ib_tbl.enclosure_name)) {
		(void) fprintf(stdout, MSGSTR(2035, "   Enclosure Name:%s\n"),
			l_state.ib_tbl.enclosure_name);
	}

	/*
	 *
	 */
	elem_index = 0;
	/* Get and print CONTROLLER messages */
	for (i = 0; i < (int)l_state.ib_tbl.config.enc_num_elem; i++) {
	    elem_index++;		/* skip global */
	    switch (l_state.ib_tbl.config.type_hdr[i].type) {
		case ELM_TYP_PS:
			ps_messages(&l_state, i, elem_index);
			break;
		case ELM_TYP_FT:
			fan_messages(&l_state, i, elem_index);
			break;
		case ELM_TYP_BP:
			back_plane_messages(&l_state, i, elem_index);
			break;
		case ELM_TYP_IB:
			ctlr_messages(&l_state, i, elem_index);
			break;
		case ELM_TYP_LN:
			/*
			 * NOTE: I just use the Photon's message
			 * string here and don't look at the
			 * language code. The string includes
			 * the language name.
			 */
			if (l_state.ib_tbl.config.type_hdr[i].text_len != 0) {
				(void) fprintf(stdout, "%s\t",
				l_state.ib_tbl.config.text[i]);
			}
			break;
		case ELM_TYP_LO:	/* Loop configuration */
			loop_messages(&l_state, i, elem_index);
			break;
		case ELM_TYP_MB:	/* Loop configuration */
			mb_messages(&l_state, i, elem_index);
			break;

	    }
		/*
		 * Calculate the index to each element.
		 */
		elem_index += l_state.ib_tbl.config.type_hdr[i].num;
	}
	(void) fprintf(stdout, "\n");
}




/*
 * dpm_display_config() Displays device status
 * information for a DAKTARI enclosure.
 *
 * RETURNS:
 *	none.
 */
void
dpm_display_config(char *path_phys)
{
L_state		l_state;
Bp_elem_st	bpf, bpr;
int		i, j, elem_index = 0, err = 0, count;


	/* Get global status */
	if (err = l_get_status(path_phys, &l_state,
			(Options & PVERBOSE))) {
	    (void) print_errString(err, path_phys);
	    exit(-1);
	}

	/*
	 * Look for abnormal status.
	 */
	if (l_state.ib_tbl.p2_s.ui.ab_cond) {
		abnormal_condition_display(&l_state);
	}

	(void) fprintf(stdout,
		MSGSTR(2247, "                 DISK STATUS \n"
		"SLOT   DISKS             (Node WWN)         \n"));
	/*
	 * Print the status for each disk
	 */
	for (j = 0; j <  (int)l_state.ib_tbl.config.enc_num_elem; j++) {
		elem_index++;
		if (l_state.ib_tbl.config.type_hdr[j].type == ELM_TYP_BP)
			break;
		elem_index += l_state.ib_tbl.config.type_hdr[j].num;
	}
	(void) bcopy((const void *)
		&(l_state.ib_tbl.p2_s.element[elem_index]),
		(void *)&bpf, sizeof (bpf));
	(void) bcopy((const void *)
		&(l_state.ib_tbl.p2_s.element[elem_index + 1]),
		(void *)&bpr, sizeof (bpr));

	for (i = 0, count = 0;
			i < (int)l_state.total_num_drv/2;
			i++, count++) {
		(void) fprintf(stdout, "%-2d     ", count);
		display_disk_msg(&l_state.drv_front[i], &l_state, &bpf, 1);
		(void) fprintf(stdout, "\n");
	}
	for (i = 0; i < (int)l_state.total_num_drv/2; i++, count++) {
		(void) fprintf(stdout, "%-2d     ", count);
		display_disk_msg(&l_state.drv_rear[i], &l_state, &bpf, 1);
		(void) fprintf(stdout, "\n");
	}


	/*
	 * Display the subsystem status.
	 */
	(void) fprintf(stdout,
		MSGSTR(2033,
	"\t\tSUBSYSTEM STATUS\nFW Revision:"));
	for (i = 0; i < sizeof (l_state.ib_tbl.config.prod_revision); i++) {
		(void) fprintf(stdout, "%c",
			l_state.ib_tbl.config.prod_revision[i]);
	}
	(void) fprintf(stdout, MSGSTR(2034, "   Box ID:%d"),
		l_state.ib_tbl.box_id);
	(void) fprintf(stdout, "\n  ");

	(void) fprintf(stdout, MSGSTR(90, "Node WWN:"));

	for (i = 0; i < 8; i++) {
		(void) fprintf(stdout, "%1.2x",
		l_state.ib_tbl.config.enc_node_wwn[i]);
	}
	/* Make sure NULL terminated  although it is supposed to be */
	if (strlen((const char *)l_state.ib_tbl.enclosure_name) <=
		sizeof (l_state.ib_tbl.enclosure_name)) {
		(void) fprintf(stdout, MSGSTR(2035, "   Enclosure Name:%s\n"),
			l_state.ib_tbl.enclosure_name);
	}

	/*
	 *
	 */
	elem_index = 0;
	/* Get and print CONTROLLER messages */
	for (i = 0; i < (int)l_state.ib_tbl.config.enc_num_elem; i++) {
	    elem_index++;		/* skip global */
	    switch (l_state.ib_tbl.config.type_hdr[i].type) {
		case ELM_TYP_PS:
			ps_messages(&l_state, i, elem_index);
			break;
		case ELM_TYP_FT:
			fan_messages(&l_state, i, elem_index);
			break;
		case ELM_TYP_BP:
			dpm_SSC100_messages(&l_state, i, elem_index);
			break;
		case ELM_TYP_IB:
			ctlr_messages(&l_state, i, elem_index);
			break;
		case ELM_TYP_LN:
			/*
			 * NOTE: I just use the Photon's message
			 * string here and don't look at the
			 * language code. The string includes
			 * the language name.
			 */
			if (l_state.ib_tbl.config.type_hdr[i].text_len != 0) {
				(void) fprintf(stdout, "%s\t",
				l_state.ib_tbl.config.text[i]);
			}
			break;
		case ELM_TYP_LO:	/* Loop configuration */
			loop_messages(&l_state, i, elem_index);
			break;
		case ELM_TYP_MB:	/* Loop configuration */
			mb_messages(&l_state, i, elem_index);
			break;
		case ELM_TYP_FL:
			trans_messages(&l_state, 1);
			break;

	    }
		/*
		 * Calculate the index to each element.
		 */
		elem_index += l_state.ib_tbl.config.type_hdr[i].num;
	}
	(void) fprintf(stdout, "\n");
}






/*
 * Change the FPM (Front Panel Module) password of the
 * subsystem associated with the IB addressed by the
 * enclosure or pathname to name.
 *
 */
void
intfix(void)
{
	if (termio_fd) {
		termios.c_lflag |= ECHO;
		ioctl(termio_fd, TCSETS, &termios);
	}
	exit(SIGINT);
}


/*
 * up_password() Changes the password for SENA enclosure.
 *
 * RETURNS:
 *	none.
 */
void
up_password(char **argv)
{
int		path_index = 0, err = 0;
char		password[1024];
char		input[1024];
int		i, j, matched, equal;
L_inquiry	inq;
void		(*sig)();
char		*path_phys = NULL;
Path_struct	*path_struct;


	if ((termio_fd = open("/dev/tty", O_RDONLY)) == -1) {
		(void) fprintf(stderr,
		MSGSTR(2036, "Error: tty open failed.\n"));
		exit(-1);
	}
	ioctl(termio_fd, TCGETS, &termios);
	sig = sigset(SIGINT, (void (*)())intfix);
	/*
	 * Make sure path valid and is to a PHO
	 * before bothering operator.
	 */
	if ((err = l_convert_name(argv[path_index], &path_phys,
		&path_struct, Options & PVERBOSE)) != 0) {
		(void) fprintf(stderr,
			MSGSTR(33,
				" Error: converting"
				" %s to physical path.\n"
				" Invalid pathname.\n"),
				argv[path_index]);
		if (err != -1) {
			(void) print_errString(err, argv[path_index]);
		}
		exit(-1);
	}
	if (err = g_get_inquiry(path_phys, &inq)) {
		(void) print_errString(err, argv[path_index]);
		exit(-1);
	}
	if ((strstr((char *)inq.inq_pid, ENCLOSURE_PROD_ID) == 0) &&
			(!(strncmp((char *)inq.inq_vid, "SUN     ",
			sizeof (inq.inq_vid)) &&
			((inq.inq_dtype & DTYPE_MASK) == DTYPE_ESI)))) {
		/*
		 * Again this is like the ssaadm code in that the name
		 * is still not defined before this code must be released.
		 */
		(void) fprintf(stderr,
		MSGSTR(2037, "Error: Enclosure is not a %s\n"),
			ENCLOSURE_PROD_ID);
		exit(-1);
	}
	(void) fprintf(stdout,
			MSGSTR(2038,
			"Changing FPM password for subsystem %s\n"),
			argv[path_index]);

	equal = 0;
	while (!equal) {
		memset(input, 0, sizeof (input));
		memset(password, 0, sizeof (password));
		(void) fprintf(stdout,
		MSGSTR(2039, "New password: "));

		termios.c_lflag &= ~ECHO;
		ioctl(termio_fd, TCSETS, &termios);

		(void) gets(input);
		(void) fprintf(stdout,
		MSGSTR(2040, "\nRe-enter new password: "));
		(void) gets(password);
		termios.c_lflag |= ECHO;
		ioctl(termio_fd, TCSETS, &termios);
		for (i = 0; input[i]; i++) {
			if (!isdigit(input[i])) {
				(void) fprintf(stderr,
			MSGSTR(2041, "\nError: Invalid password."
			" The password"
			" must be 4 decimal-digit characters.\n"));
				exit(-1);
			}
		}
		if (i && (i != 4)) {
			(void) fprintf(stderr,
			MSGSTR(2042, "\nError: Invalid password."
			" The password"
			" must be 4 decimal-digit characters.\n"));
			exit(-1);
		}
		for (j = 0; password[j]; j++) {
			if (!isdigit(password[j])) {
				(void) fprintf(stderr,
			MSGSTR(2043, "\nError: Invalid password."
			" The password"
			" must be 4 decimal-digit characters.\n"));
				exit(-1);
			}
		}
		if (i != j) {
			matched = -1;
		} else for (i = matched = 0; password[i]; i++) {
			if (password[i] == input[i]) {
				matched++;
			}
		}
		if ((matched != -1) && (matched == i)) {
			equal = 1;
		} else {
			(void) fprintf(stdout,
			MSGSTR(2044, "\npassword: They don't match;"
			" try again.\n"));
		}
	}
	(void) fprintf(stdout, "\n");
	sscanf(input, "%s", password);
	(void) signal(SIGINT, sig);	/* restore signal handler */

	/*  Send new password to IB */
	if (l_new_password(path_phys, input)) {
		(void) print_errString(err, path_phys);
		exit(-1);
	}
}

/*
 * Call g_failover to process failover command
 */
void
adm_failover(char **argv)
{
int		path_index = 0, err = 0;
char		pathclass[20];
char		*path_phys = NULL;

	(void) memset(pathclass, 0, sizeof (pathclass));
	(void) strcpy(pathclass, argv[path_index++]);
	if ((strcmp(pathclass, "primary") != 0) &&
		(strcmp(pathclass, "secondary") != 0)) {
			(void) fprintf(stderr,
			MSGSTR(2300, "Incorrect pathclass\n"));
			exit(-1);
	}

	while (argv[path_index] != NULL) {
		path_phys = g_get_physical_name(argv[path_index++]);
		if ((path_phys == NULL) ||
			(strstr(path_phys, SCSI_VHCI) == NULL)) {
				(void) fprintf(stderr,
				MSGSTR(2301, "Incorrect pathname\n"));
				exit(-1);
		}

		if (err = g_failover(path_phys, pathclass)) {
			(void) print_errString(err, NULL);
			exit(-1);
		}
	}
}



/*
 * up_encl_name() Update the enclosures logical name.
 *
 * RETURNS:
 *	none.
 */
void
up_encl_name(char **argv, int argc)
{
int		i, rval, al_pa, path_index = 0, err = 0;
L_inquiry	inq;
Box_list	*b_list = NULL;
uchar_t		node_wwn[WWN_SIZE], port_wwn[WWN_SIZE];
char		wwn1[(WWN_SIZE*2)+1], name[1024], *path_phys = NULL;
Path_struct	*path_struct;

	(void) memset(name, 0, sizeof (name));
	(void) memset(&inq, 0, sizeof (inq));
	(void) sscanf(argv[path_index++], "%s", name);
	for (i = 0; name[i]; i++) {
		if ((!isalnum(name[i]) &&
			((name[i] != '#') &&
			(name[i] != '-') &&
			(name[i] != '_') &&
			(name[i] != '.'))) || i >= 16) {
			(void) fprintf(stderr,
			MSGSTR(2045, "Error: Invalid enclosure name.\n"));
			(void) fprintf(stderr, MSGSTR(2046,
			"Usage: %s [-v] subcommand {a name consisting of"
			" 1-16 alphanumeric characters}"
			" {enclosure... | pathname...}\n"), whoami);
			exit(-1);
		}
	}

	if (((Options & PVERBOSE) && (argc != 5)) ||
		(!(Options & PVERBOSE) && (argc != 4))) {
		(void) fprintf(stderr,
		MSGSTR(114, "Error: Incorrect number of arguments.\n"));
		(void) fprintf(stderr,  MSGSTR(2047,
		"Usage: %s [-v] subcommand {a name consisting of"
		" 1-16 alphanumeric characters}"
		" {enclosure... | pathname...}\n"), whoami);
		exit(-1);
	}

	if ((err = l_convert_name(argv[path_index], &path_phys,
		&path_struct, Options & PVERBOSE)) != 0) {
		(void) fprintf(stderr,
				MSGSTR(33,
				" Error: converting"
				" %s to physical path.\n"
				" Invalid pathname.\n"),
				argv[path_index]);
		if (err != -1) {
			(void) print_errString(err, argv[path_index]);
		}
		exit(-1);
	}
	/*
	 * Make sure we are talking to an IB.
	 */
	if (err = g_get_inquiry(path_phys, &inq)) {
		(void) print_errString(err, argv[path_index]);
		exit(-1);
	}
	if ((strstr((char *)inq.inq_pid, ENCLOSURE_PROD_ID) == 0) &&
			(!(strncmp((char *)inq.inq_vid, "SUN     ",
			sizeof (inq.inq_vid)) &&
			((inq.inq_dtype & DTYPE_MASK) == DTYPE_ESI)))) {
		/*
		 * Again this is like the ssaadm code in that the name
		 * is still not defined before this code must be released.
		 */
		(void) fprintf(stderr,
		MSGSTR(2048, "Error: Pathname does not point to a %s"
		" enclosure\n"), ENCLOSURE_PROD_NAME);
		exit(-1);
	}

	if (err = g_get_wwn(path_phys, port_wwn, node_wwn, &al_pa,
		Options & PVERBOSE)) {
		(void) print_errString(err, argv[path_index]);
		exit(-1);
	}

	for (i = 0; i < WWN_SIZE; i++) {
		(void) sprintf(&wwn1[i << 1], "%02x", node_wwn[i]);
	}
	if ((err = l_get_box_list(&b_list, Options & PVERBOSE)) != 0) {
		(void) print_errString(err, argv[path_index]);
		exit(-1);
	}
	if (b_list == NULL) {
		(void) fprintf(stdout,
			MSGSTR(93, "No %s enclosures found "
			"in /dev/es\n"), ENCLOSURE_PROD_NAME);
		exit(-1);
	} else if (l_duplicate_names(b_list, wwn1, name,
		Options & PVERBOSE)) {
		(void) fprintf(stderr,
		MSGSTR(2049, "Warning: The name you selected, %s,"
		" is already being used.\n"
		"Please choose a unique name.\n"
		"You can use the \"probe\" subcommand to"
		" see all of the enclosure names.\n"),
		name);
		(void) l_free_box_list(&b_list);
		exit(-1);
	}
	(void) l_free_box_list(&b_list);

	/*  Send new name to IB */
	if (rval = l_new_name(path_phys, name)) {
		(void) print_errString(rval, path_phys);
		exit(-1);
	}
	if (Options & PVERBOSE) {
		(void) fprintf(stdout,
			MSGSTR(2050, "The enclosure has been renamed to %s\n"),
			name);
	}
}


static int
get_enclStatus(char *phys_path, char *encl_name, int off_flag)
{
int	found_pwrOnDrv = 0, slot;
int	found_pwrOffDrv = 0, err = 0;
L_state	l_state;

	if ((err = l_get_status(phys_path,
				&l_state, Options & PVERBOSE)) != 0) {
		(void) print_errString(err, encl_name);
		return (err);
	}

	if (off_flag) {
		for (slot = 0; slot < l_state.total_num_drv/2;
							slot++) {
			if (((l_state.drv_front[slot].ib_status.code !=
							S_NOT_INSTALLED) &&
			(!l_state.drv_front[slot].ib_status.dev_off)) ||
			((l_state.drv_rear[slot].ib_status.code !=
							S_NOT_INSTALLED) &&
			(!l_state.drv_rear[slot].ib_status.dev_off))) {
				found_pwrOnDrv++;
				break;
			}
		}
		if (!found_pwrOnDrv) {
			(void) fprintf(stdout,
				MSGSTR(2051,
				"Notice: Drives in enclosure"
				" \"%s\" have already been"
				" powered off.\n\n"),
				encl_name);
			return (-1);
		}
	} else {
		for (slot  = 0; slot < l_state.total_num_drv/2;
							slot++) {
			if (((l_state.drv_front[slot].ib_status.code !=
							S_NOT_INSTALLED) &&
			(l_state.drv_front[slot].ib_status.dev_off)) ||
			((l_state.drv_rear[slot].ib_status.code !=
							S_NOT_INSTALLED) &&
			(l_state.drv_rear[slot].ib_status.dev_off))) {
				found_pwrOffDrv++;
				break;
			}
		}
		if (!found_pwrOffDrv) {
			(void) fprintf(stdout,
				MSGSTR(2052,
				"Notice: Drives in enclosure"
				" \"%s\" have already been"
				" powered on.\n\n"),
				encl_name);
			return (-1);
		}
	}
	return (0);
}





/*
 * adm_led() The led_request subcommand requests the subsystem
 * to display the current state or turn off, on, or blink
 * the yellow LED associated with the disk specified by the
 * enclosure or pathname.
 *
 * RETURNS:
 *	none.
 */
void
adm_led(char **argv, int led_action)
{
int		path_index = 0, err = 0;
gfc_map_t	map;
L_inquiry	inq;
Dev_elem_st	status;
char		*path_phys = NULL;
Path_struct	*path_struct;
int		enc_t = 0;		/* enclosure type */
char		ses_path[MAXPATHLEN];
L_inquiry	ses_inq;

	while (argv[path_index] != NULL) {
		if ((err = l_convert_name(argv[path_index], &path_phys,
			&path_struct, Options & PVERBOSE)) != 0) {
			/* Make sure we have a device path. */
			if (path_struct->ib_path_flag) {
				path_phys = path_struct->p_physical_path;
			} else {
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
				exit(-1);
			}
		}
		if (!path_struct->ib_path_flag) {
			if (err = g_get_inquiry(path_phys, &inq)) {
				(void) print_errString(err, argv[path_index]);
				exit(-1);
			}
			if ((inq.inq_dtype & DTYPE_MASK) != DTYPE_DIRECT) {
				(void) fprintf(stderr,
				MSGSTR(2053,
				"Error: pathname must be to a disk device.\n"
				" %s\n"), argv[path_index]);
				exit(-1);
			}
		}
		/*
		 * See if we are in fact talking to a loop or not.
		 */
		if (err = g_get_dev_map(path_phys, &map,
			(Options & PVERBOSE))) {
			(void) print_errString(err, argv[path_index]);

		}
		    if (led_action == L_LED_ON) {
			(void) fprintf(stderr, MSGSTR(2054,
			    "The led_on functionality is not applicable "
			    "to this subsystem.\n"));
			exit(-1);
		    }
		    if (err = l_led(path_struct, led_action, &status,
			    (Options & PVERBOSE))) {
			(void) print_errString(err, argv[path_index]);
			exit(-1);
		    }

		    /* Check to see if we have a daktari */
		    if (l_get_ses_path(path_phys, ses_path, &map,
			    (Options & PVERBOSE)) == 0) {
			if (g_get_inquiry(ses_path, &ses_inq) == 0) {
			    enc_t = l_get_enc_type(ses_inq);
			}
		    }
		    switch (led_action) {
		    case L_LED_STATUS:
			if (status.fault || status.fault_req) {
			    if (!path_struct->slot_valid) {
				(void) fprintf(stdout,
				    MSGSTR(2055, "LED state is ON for "
				    "device:\n  %s\n"), path_phys);
			    } else {
				if (enc_t == DAK_ENC_TYPE) {
				    if (path_struct->f_flag) {
					(void) fprintf(stdout,
					    MSGSTR(2236, "LED state is ON for "
					    "device in location: slot %d\n"),
					    path_struct->slot);
				    } else {
					(void) fprintf(stdout,
					    MSGSTR(2236, "LED state is ON for "
					    "device in location: slot %d\n"),
					    path_struct->slot +
							(MAX_DRIVES_DAK/2));
				    }
				} else {
				    (void) fprintf(stdout,
				    (path_struct->f_flag) ?
				    MSGSTR(2056, "LED state is ON for "
				    "device in location: front,slot %d\n")
				    : MSGSTR(2057, "LED state is ON for "
				    "device in location: rear,slot %d\n"),
				    path_struct->slot);
				    }
			    }
			} else if (status.ident || status.rdy_to_ins ||
				status.rmv) {
			    if (!path_struct->slot_valid) {
				(void) fprintf(stdout, MSGSTR(2058,
				    "LED state is BLINKING for "
				    "device:\n  %s\n"), path_phys);
			    } else {
				if (enc_t == DAK_ENC_TYPE) {
				    if (path_struct->f_flag) {
					(void) fprintf(stdout, MSGSTR(2237,
					"LED state is BLINKING for "
					"device in location: slot %d\n"),
					path_struct->slot);
				    } else {
					(void) fprintf(stdout, MSGSTR(2237,
					"LED state is BLINKING for "
					"device in location: slot %d\n"),
					path_struct->slot + (MAX_DRIVES_DAK/2));
				    }
				} else {
				    (void) fprintf(stdout,
				    (path_struct->f_flag) ?
				    MSGSTR(2059, "LED state is BLINKING for "
				    "device in location: front,slot %d\n")
				    : MSGSTR(2060, "LED state is BLINKING for "
				    "device in location: rear,slot %d\n"),
				    path_struct->slot);
				}
			    }
			} else {
			    if (!path_struct->slot_valid) {
				(void) fprintf(stdout,
				MSGSTR(2061, "LED state is OFF for "
				"device:\n  %s\n"), path_phys);
			    } else {
				if (enc_t == DAK_ENC_TYPE) {
				    if (path_struct->f_flag) {
					(void) fprintf(stdout, MSGSTR(2238,
					"LED state is OFF for "
					"device in location: slot %d\n"),
					path_struct->slot);
				    } else {
					(void) fprintf(stdout, MSGSTR(2238,
					"LED state is OFF for "
					"device in location: slot %d\n"),
					path_struct->slot + MAX_DRIVES_DAK/2);
				    }
				} else {
				    (void) fprintf(stdout,
					(path_struct->f_flag) ?
					MSGSTR(2062, "LED state is OFF for "
					"device in location: front,slot %d\n")
					: MSGSTR(2063, "LED state is OFF for "
					"device in location: rear,slot %d\n"),
					path_struct->slot);
				}
			    }
			}
			break;
		    }
		    free((void *)map.dev_addr);
		    path_index++;
	}
}





/*
 * dump() Dump information
 *
 * RETURNS:
 *	none.
 */
void
dump(char **argv)
{
uchar_t		*buf;
int		path_index = 0, err = 0;
L_inquiry	inq;
char		hdr_buf[MAXNAMELEN];
Rec_diag_hdr	*hdr, *hdr_ptr;
char		*path_phys = NULL;
Path_struct	*path_struct;

	/*
	 * get big buffer
	 */
	if ((hdr = (struct rec_diag_hdr *)calloc(1, MAX_REC_DIAG_LENGTH)) ==
								NULL) {
		(void) print_errString(L_MALLOC_FAILED, NULL);
		exit(-1);
	}
	buf = (uchar_t *)hdr;

	while (argv[path_index] != NULL) {
		if ((err = l_convert_name(argv[path_index], &path_phys,
			&path_struct, Options & PVERBOSE)) != 0) {
			(void) fprintf(stderr,
				MSGSTR(33,
					" Error: converting"
					" %s to physical path.\n"
					" Invalid pathname.\n"),
				argv[path_index]);
			if (err != -1) {
				(void) print_errString(err, argv[path_index]);
			}
			exit(-1);
		}
		if (err = g_get_inquiry(path_phys, &inq)) {
			(void) print_errString(err, argv[path_index]);
		} else {
			(void) g_dump(MSGSTR(2065, "INQUIRY data:   "),
			(uchar_t *)&inq, 5 + inq.inq_len, HEX_ASCII);
		}

		(void) memset(buf, 0, MAX_REC_DIAG_LENGTH);
		if (err = l_get_envsen(path_phys, buf, MAX_REC_DIAG_LENGTH,
			(Options & PVERBOSE))) {
		    (void) print_errString(err, argv[path_index]);
		    exit(-1);
		}
		(void) fprintf(stdout,
			MSGSTR(2066, "\t\tEnvironmental Sense Information\n"));

		/*
		 * Dump all pages.
		 */
		hdr_ptr = hdr;

		while (hdr_ptr->page_len != 0) {
			(void) sprintf(hdr_buf, MSGSTR(2067, "Page %d:   "),
				hdr_ptr->page_code);
			(void) g_dump(hdr_buf, (uchar_t *)hdr_ptr,
				HEADER_LEN + hdr_ptr->page_len, HEX_ASCII);
			hdr_ptr += ((HEADER_LEN + hdr_ptr->page_len) /
				sizeof (struct	rec_diag_hdr));
		}
		path_index++;
	}
	(void) free(buf);
}



/*
 * display_socal_stats() Display socal driver kstat information.
 *
 * RETURNS:
 *	none.
 */
void
display_socal_stats(int port, char *socal_path, struct socal_stats *fc_stats)
{
int		i;
int		header_flag = 0;
char		status_msg_buf[MAXNAMELEN];
int		num_status_entries;

	(void) fprintf(stdout, MSGSTR(2068,
		"\tInformation for FC Loop on port %d of"
		" FC100/S Host Adapter\n\tat path: %s\n"),
		port, socal_path);
	if (fc_stats->version > 1) {
		(void) fprintf(stdout, "\t");
		(void) fprintf(stdout, MSGSTR(32,
			"Information from %s"), fc_stats->drvr_name);
		(void) fprintf(stdout, "\n");
		if ((*fc_stats->node_wwn != '\0') &&
			(*fc_stats->port_wwn[port] != '\0')) {
			(void) fprintf(stdout, MSGSTR(104,
				"  Host Adapter WWN's: Node:%s"
				"  Port:%s\n"),
				fc_stats->node_wwn,
				fc_stats->port_wwn[port]);
		}
		if (*fc_stats->fw_revision != '\0') {
			(void) fprintf(stdout, MSGSTR(105,
				"  Host Adapter Firmware Revision: %s\n"),
				fc_stats->fw_revision);
		}
		if (fc_stats->parity_chk_enabled != 0) {
			(void) fprintf(stdout, MSGSTR(2069,
			"  This Host Adapter checks S-Bus parity.\n"));
		}
	}

	(void) fprintf(stdout, MSGSTR(2070,
		"  Version Resets  Req_Q_Intrpts  Qfulls"
		" Unsol_Resps Lips\n"));

	(void) fprintf(stdout,  "  %4d%8d%11d%13d%10d%7d\n",
			fc_stats->version,
			fc_stats->resets,
			fc_stats->reqq_intrs,
			fc_stats->qfulls,
			fc_stats->pstats[port].unsol_resps,
			fc_stats->pstats[port].lips);

	(void) fprintf(stdout, MSGSTR(2071,
		"  Els_rcvd  Abts"
		"     Abts_ok Offlines Loop_onlines Onlines\n"));

	(void) fprintf(stdout, "  %4d%9d%10d%9d%13d%10d\n",
			fc_stats->pstats[port].els_rcvd,
			fc_stats->pstats[port].abts,
			fc_stats->pstats[port].abts_ok,
			fc_stats->pstats[port].offlines,
			fc_stats->pstats[port].online_loops,
			fc_stats->pstats[port].onlines);

	/* If any status conditions exist then display */
	if (fc_stats->version > 1) {
		num_status_entries = FC_STATUS_ENTRIES;
	} else {
		num_status_entries = 64;
	}

	for (i = 0; i < num_status_entries; i++) {
		if (fc_stats->pstats[port].resp_status[i] != 0) {
			if (header_flag++ == 0) {
				(void) fprintf(stdout, MSGSTR(2072,
				"  Fibre Channel Transport status:\n        "
				"Status                       Value"
				"           Count\n"));
			}
			(void) l_format_fc_status_msg(status_msg_buf,
			fc_stats->pstats[port].resp_status[i], i);
			(void) fprintf(stdout, "        %s\n",
				status_msg_buf);
		}
	}
}



/*
 * display_sf_stats() Display sf driver kstat information.
 *
 * This routine is called by private loop device only
 *
 * RETURNS:
 *	none.
 */
void
display_sf_stats(char *path_phys, int dtype, struct sf_stats *sf_stats)
{
int		i, al_pa, err = 0;
gfc_map_t	map;
uchar_t		node_wwn[WWN_SIZE];
uchar_t		port_wwn[WWN_SIZE];
gfc_port_dev_info_t	*dev_addr_list;

	if (sf_stats->version > 1) {
		(void) fprintf(stdout, "\n\t");
		(void) fprintf(stdout, MSGSTR(32,
			"Information from %s"),
			sf_stats->drvr_name);
		(void) fprintf(stdout, "\n");
	} else {
		(void) fprintf(stdout,
			MSGSTR(2073, "\n\t\tInformation from sf driver:\n"));
	}

	(void) fprintf(stdout, MSGSTR(2074,
		"  Version  Lip_count  Lip_fail"
		" Alloc_fail  #_cmds "
		"Throttle_limit  Pool_size\n"));

	(void) fprintf(stdout, "  %4d%9d%12d%11d%10d%11d%12d\n",
			sf_stats->version,
			sf_stats->lip_count,
			sf_stats->lip_failures,
			sf_stats->cralloc_failures,
			sf_stats->ncmds,
			sf_stats->throttle_limit,
			sf_stats->cr_pool_size);

	(void) fprintf(stdout, MSGSTR(2075,
		"\n\t\tTARGET ERROR INFORMATION:\n"));
	(void) fprintf(stdout, MSGSTR(2076,
		"AL_PA  Els_fail Timouts Abts_fail"
		" Tsk_m_fail "
		" Data_ro_mis Dl_len_mis Logouts\n"));

	if (err = g_get_dev_map(path_phys, &map, (Options & PVERBOSE))) {
		(void) print_errString(err, path_phys);
		exit(-1);
	}

	if (dtype == DTYPE_DIRECT) {
		if (err = g_get_wwn(path_phys, port_wwn, node_wwn, &al_pa,
			Options & PVERBOSE)) {
			(void) print_errString(err, path_phys);
			exit(-1);
		}
		/* for san toleration, only need to modify the code    */
		/* such that the current sf_al_map structure replaced  */
		/* by the new gfc_map structure for private loop device */
		for (i = 0, dev_addr_list = map.dev_addr; i < map.count;
			i++, dev_addr_list++) {
			if (dev_addr_list->gfc_port_dev.priv_port.sf_al_pa
					== al_pa) {
				(void) fprintf(stdout,
				"%3x%10d%8d%10d%11d%13d%11d%9d\n",
				al_pa,
				sf_stats->tstats[i].els_failures,
				sf_stats->tstats[i].timeouts,
				sf_stats->tstats[i].abts_failures,
				sf_stats->tstats[i].task_mgmt_failures,
				sf_stats->tstats[i].data_ro_mismatches,
				sf_stats->tstats[i].dl_len_mismatches,
				sf_stats->tstats[i].logouts_recvd);
				break;
			}
		}
		if (i >= map.count) {
			(void) print_errString(L_INVALID_LOOP_MAP, path_phys);
			exit(-1);
		}
	} else {
		for (i = 0, dev_addr_list = map.dev_addr; i < map.count;
			i++, dev_addr_list++) {
			(void) fprintf(stdout,
			"%3x%10d%8d%10d%11d%13d%11d%9d\n",
			dev_addr_list->gfc_port_dev.priv_port.sf_al_pa,
			sf_stats->tstats[i].els_failures,
			sf_stats->tstats[i].timeouts,
			sf_stats->tstats[i].abts_failures,
			sf_stats->tstats[i].task_mgmt_failures,
			sf_stats->tstats[i].data_ro_mismatches,
			sf_stats->tstats[i].dl_len_mismatches,
			sf_stats->tstats[i].logouts_recvd);
		}
	}
	free((void *)map.dev_addr);
}



/*
 * adm_display_err() Displays enclosure specific
 * error information.
 *
 * RETURNS:
 *	none.
 */
static void
adm_display_err(char *path_phys, int dtype)
{
int		i, drvr_inst, sf_inst, socal_inst, port, al_pa, err = 0;
char		*char_ptr, socal_path[MAXPATHLEN], drvr_path[MAXPATHLEN];
struct		stat sbuf;
kstat_ctl_t	*kc;
kstat_t		*ifp_ks, *sf_ks, *fc_ks;
sf_stats_t	sf_stats;
socal_stats_t	fc_stats;
ifp_stats_t	ifp_stats;
int		header_flag = 0, pathcnt = 1;
char		status_msg_buf[MAXNAMELEN];
gfc_map_t	map;
uchar_t		node_wwn[WWN_SIZE], port_wwn[WWN_SIZE];
uint_t		path_type;
gfc_port_dev_info_t	*dev_addr_list;
mp_pathlist_t	pathlist;
int		p_on = 0, p_st = 0;

	if ((kc = kstat_open()) == (kstat_ctl_t *)NULL) {
		(void) fprintf(stderr,
			MSGSTR(2077, " Error: can't open kstat\n"));
		exit(-1);
	}

	if (strstr(path_phys, SCSI_VHCI)) {
		(void) strcpy(drvr_path, path_phys);
		if (err = g_get_pathlist(drvr_path, &pathlist)) {
			(void) print_errString(err, NULL);
			exit(-1);
		}
		pathcnt = pathlist.path_count;
		p_on = p_st = 0;
		for (i = 0; i < pathcnt; i++) {
			if (pathlist.path_info[i].path_state < MAXPATHSTATE) {
				if (pathlist.path_info[i].path_state ==
					MDI_PATHINFO_STATE_ONLINE) {
					p_on = i;
					break;
				} else if (pathlist.path_info[i].path_state ==
					MDI_PATHINFO_STATE_STANDBY) {
					p_st = i;
				}
			}
		}
		if (pathlist.path_info[p_on].path_state ==
		    MDI_PATHINFO_STATE_ONLINE) {
			/* on_line path */
			(void) strcpy(drvr_path,
				pathlist.path_info[p_on].path_hba);
		} else {
			/* standby or path0 */
			(void) strcpy(drvr_path,
				pathlist.path_info[p_st].path_hba);
		}
		free(pathlist.path_info);
	} else {

		(void) strcpy(drvr_path, path_phys);

		if ((char_ptr = strrchr(drvr_path, '/')) == NULL) {
			(void) print_errString(L_INVLD_PATH_NO_SLASH_FND,
				path_phys);
			exit(-1);
		}
		*char_ptr = '\0';   /* Make into nexus or HBA driver path. */
	}
	/*
	 * Each HBA and driver stack has its own structures
	 * for this, so we have to handle each one individually.
	 */
	path_type = g_get_path_type(drvr_path);

	if (path_type) { /* Quick sanity check for valid path */
		if ((err = g_get_nexus_path(drvr_path, &char_ptr)) != 0) {
			(void) print_errString(err, path_phys);
			exit(-1);
		}
		(void) strcpy(socal_path, char_ptr);

	}

	/* attach :devctl to get node stat instead of dir stat. */
	(void) strcat(drvr_path, FC_CTLR);

	if (stat(drvr_path, &sbuf) < 0) {
		(void) print_errString(L_LSTAT_ERROR, path_phys);
		exit(-1);
	}

	drvr_inst = minor(sbuf.st_rdev);


	/*
	 * first take care of ifp card.
	 */
	if (path_type & FC4_PCI_FCA) {
	    if ((ifp_ks = kstat_lookup(kc, "ifp",
			drvr_inst, "statistics")) != NULL) {

		if (kstat_read(kc, ifp_ks, &ifp_stats) < 0) {
			(void) fprintf(stderr,
				MSGSTR(2082,
				"Error: could not read ifp%d\n"), drvr_inst);
			exit(-1);
		}
		(void) fprintf(stdout, MSGSTR(2083,
			"\tInformation for FC Loop of"
			" FC100/P Host Adapter\n\tat path: %s\n"),
			drvr_path);
		if (ifp_stats.version > 1) {
			(void) fprintf(stdout, "\t");
			(void) fprintf(stdout, MSGSTR(32,
				"Information from %s"),
				ifp_stats.drvr_name);
			(void) fprintf(stdout, "\n");
			if ((*ifp_stats.node_wwn != '\0') &&
				(*ifp_stats.port_wwn != '\0')) {
				(void) fprintf(stdout, MSGSTR(104,
					"  Host Adapter WWN's: Node:%s"
					"  Port:%s\n"),
					ifp_stats.node_wwn,
					ifp_stats.port_wwn);
			}
			if (*ifp_stats.fw_revision != 0) {
				(void) fprintf(stdout, MSGSTR(105,
				"  Host Adapter Firmware Revision: %s\n"),
				ifp_stats.fw_revision);
			}
			if (ifp_stats.parity_chk_enabled != 0) {
				(void) fprintf(stdout, MSGSTR(2084,
				"  This Host Adapter checks "
				"PCI-Bus parity.\n"));
			}
		}

		(void) fprintf(stdout, MSGSTR(2085,
			"        Version Lips\n"));
		(void) fprintf(stdout, "  %10d%7d\n",
				ifp_stats.version,
				ifp_stats.lip_count);
		/* If any status conditions exist then display */
		for (i = 0; i < FC_STATUS_ENTRIES; i++) {
			if (ifp_stats.resp_status[i] != 0) {
				if (header_flag++ == 0) {
					(void) fprintf(stdout, MSGSTR(2086,
					"  Fibre Channel Transport "
					"status:\n        "
					"Status           "
					"            Value"
					"           Count\n"));
				}
				(void) l_format_ifp_status_msg(
					status_msg_buf,
					ifp_stats.resp_status[i], i);
					(void) fprintf(stdout, "        %s\n",
					status_msg_buf);
			}
		}

		(void) fprintf(stdout, MSGSTR(2087,
			"\n\t\tTARGET ERROR INFORMATION:\n"));
		(void) fprintf(stdout, MSGSTR(2088,
			"AL_PA  logouts_recvd  task_mgmt_failures"
			"  data_ro_mismatches  data_len_mismatch\n"));

		if (err = g_get_dev_map(path_phys, &map,
					(Options & PVERBOSE))) {
			(void) print_errString(err, path_phys);
			exit(-1);
		}


		if (dtype == DTYPE_DIRECT) {
			if (err = g_get_wwn(path_phys, port_wwn,
				node_wwn, &al_pa,
				Options & PVERBOSE)) {
				(void) print_errString(err,
				path_phys);
				exit(-1);
			}
			for (i = 0, dev_addr_list = map.dev_addr;
				i < map.count; i++,
				dev_addr_list++) {
				if (dev_addr_list->gfc_port_dev.
					priv_port.sf_al_pa
					== al_pa) {
					(void) fprintf
					(stdout,
					"%3x%14d%18d%20d%20d\n",
					al_pa,
					ifp_stats.tstats[i].
						logouts_recvd,
					ifp_stats.tstats[i].
						task_mgmt_failures,
					ifp_stats.tstats[i].
						data_ro_mismatches,
					ifp_stats.tstats[i].
						dl_len_mismatches);
					break;
				}
			}
			if (i >= map.count) {

				(void) print_errString(
				L_INVALID_LOOP_MAP, path_phys);
				exit(-1);
			}

		} else {
			for (i = 0, dev_addr_list = map.dev_addr;
				i < map.count; i++,
				dev_addr_list++) {
				(void) fprintf(stdout,
				"%3x%14d%18d%20d%20d\n",
				dev_addr_list->gfc_port_dev.
					priv_port.sf_al_pa,
				ifp_stats.tstats[i].logouts_recvd,
				ifp_stats.tstats[i].task_mgmt_failures,
				ifp_stats.tstats[i].data_ro_mismatches,
				ifp_stats.tstats[i].dl_len_mismatches);
			}
		}

		free((void *)map.dev_addr);
	    }
	} else if (path_type & FC4_SF_XPORT) {
	/*
	 * process cards with sf xport nodes.
	 */
	    if (stat(socal_path, &sbuf) < 0) {
		(void) print_errString(L_LSTAT_ERROR, path_phys);
		exit(-1);
	    }
	    socal_inst = minor(sbuf.st_rdev)/2;
	    port = socal_inst%2;

	    sf_inst = LUX_SF_MINOR2INST(minor(sbuf.st_rdev));
	    if (!(sf_ks = kstat_lookup(kc, "sf", sf_inst,
		"statistics"))) {
		(void) fprintf(stderr,
			MSGSTR(2078,
		" Error: could not lookup driver stats for sf%d\n"),
			sf_inst);
		exit(-1);
	    }
	    if (!(fc_ks = kstat_lookup(kc, "socal", socal_inst,
					"statistics"))) {
		(void) fprintf(stderr,
			MSGSTR(2079,
		" Error: could not lookup driver stats for socal%d\n"),
			socal_inst);
		exit(-1);
	    }
	    if (kstat_read(kc, sf_ks, &sf_stats) < 0) {
		(void) fprintf(stderr,
			MSGSTR(2080,
		" Error: could not read driver stats for sf%d\n"),
			sf_inst);
		exit(-1);
	    }
	    if (kstat_read(kc, fc_ks, &fc_stats) < 0) {
		(void) fprintf(stderr,
			MSGSTR(2081,
		" Error: could not read driver stats for socal%d\n"),
			socal_inst);
		exit(-1);
	    }
	    (void) display_socal_stats(port, socal_path, &fc_stats);
	    (void) display_sf_stats(path_phys, dtype, &sf_stats);
	} else if ((path_type & FC_FCA_MASK) == FC_PCI_FCA) {
		fprintf(stderr, MSGSTR(2252,
			"\n WARNING!! display -r on qlc is"
			" currently not supported.\n"));
	} else {
		fprintf(stderr, MSGSTR(2253,
			"\n WARNING!! display -r is not supported on path\n"
			" %s\n"), drvr_path);
	}
	(void) kstat_close(kc);

}



/*ARGSUSED*/
/*
 * adm_display_verbose_disk() Gets the mode page information
 * for a SENA disk and prints that information.
 *
 * RETURNS:
 *	none.
 */
void
adm_display_verbose_disk(char *path, int verbose)
{
uchar_t		*pg_buf;
Mode_header_10	*mode_header_ptr;
Mp_01		*pg1_buf;
Mp_04		*pg4_buf;
struct mode_page *pg_hdr;
int		offset, hdr_printed = 0, err = 0;

	if ((err = l_get_mode_pg(path, &pg_buf, verbose)) == 0) {

		mode_header_ptr = (struct mode_header_10_struct *)(int)pg_buf;
		pg_hdr = ((struct mode_page *)((int)pg_buf +
		    (uchar_t)sizeof (struct mode_header_10_struct) +
		    (uchar_t *)(uintptr_t)(mode_header_ptr->bdesc_length)));
		offset = sizeof (struct mode_header_10_struct) +
		    mode_header_ptr->bdesc_length;
		while (offset < (mode_header_ptr->length +
			sizeof (mode_header_ptr->length))) {
			switch (pg_hdr->code) {
				case 0x01:
				pg1_buf = (struct mode_page_01_struct *)
					(int)pg_hdr;
				P_DPRINTF("  adm_display_verbose_disk:"
					"Mode Sense page 1 found.\n");
				if (hdr_printed++ == 0) {
					(void) fprintf(stdout,
						MSGSTR(2089,
						"  Mode Sense data:\n"));
				}
				(void) fprintf(stdout,
					MSGSTR(2090,
					"    AWRE:\t\t\t%d\n"
					"    ARRE:\t\t\t%d\n"
					"    Read Retry Count:\t\t"
					"%d\n"
					"    Write Retry Count:\t\t"
					"%d\n"),
					pg1_buf->awre,
					pg1_buf->arre,
					pg1_buf->read_retry_count,
					pg1_buf->write_retry_count);
				break;
				case MODEPAGE_GEOMETRY:
				pg4_buf = (struct mode_page_04_struct *)
					(int)pg_hdr;
				P_DPRINTF("  adm_display_verbose_disk:"
					"Mode Sense page 4 found.\n");
				if (hdr_printed++ == 0) {
					(void) fprintf(stdout,
						MSGSTR(2091,
						"  Mode Sense data:\n"));
				}
				if (pg4_buf->rpm) {
					(void) fprintf(stdout,
						MSGSTR(2092,
						"    Medium rotation rate:\t"
						"%d RPM\n"), pg4_buf->rpm);
				}
				break;
			}
			offset += pg_hdr->length + sizeof (struct mode_page);
			pg_hdr = ((struct mode_page *)((int)pg_buf +
				(uchar_t)offset));
		}





	} else if (getenv("_LUX_P_DEBUG") != NULL) {
			(void) print_errString(err, path);
	}
}

/*
 * Print out the port_wwn or node_wwn
 */
void
print_wwn(FILE *fd, uchar_t *pn_wwn)
{

	(void) fprintf(fd,
		" %1.2x%1.2x%1.2x%1.2x%1.2x%1.2x%1.2x%1.2x",
		pn_wwn[0], pn_wwn[1], pn_wwn[2], pn_wwn[3],
		pn_wwn[4], pn_wwn[5], pn_wwn[6], pn_wwn[7]);
}

/*
 * Print out the fabric dev port_id, hard_addr, port_wwn and node_wwn
 */
void
print_fabric_prop(int pos, uchar_t *port_wwn, uchar_t *node_wwn, int port_addr,
	int hard_addr)
{
	(void) fprintf(stdout, "%-4d %-6x  %-6x   ",
		pos, port_addr, hard_addr);
	print_wwn(stdout, port_wwn);
	print_wwn(stdout, node_wwn);
}

/*
 * Print out the private loop dev port_id, hard_addr, port_wwn and node_wwn
 */
void
print_private_loop_prop(int pos, uchar_t *port_wwn, uchar_t *node_wwn,
	int port_addr, int hard_addr)
{
	(void) fprintf(stdout, "%-3d   %-2x  %-2x    %-2x    ",
		pos, port_addr, g_sf_alpa_to_switch[port_addr], hard_addr);
	print_wwn(stdout, port_wwn);
	print_wwn(stdout, node_wwn);
}

/*
 * Get the device map from
 * fc nexus driver and prints the map.
 *
 * RETURNS:
 *	none.
 */
void
dump_map(char **argv)
{
int		i = 0, path_index = 0, pathcnt = 1;
int		limited_map_flag = 0, err = 0;
char		*path_phys = NULL;
Path_struct	*path_struct;
struct lilpmap	limited_map;
uint_t		dev_type;
char		temp2path[MAXPATHLEN];
mp_pathlist_t	pathlist;
int		p_pw = 0, p_on = 0, p_st = 0;
gfc_dev_t	map_root, map_dev;
int		*port_addr, *hard_addr, pos = 0, count;
uchar_t		*hba_port_wwn, *port_wwn, *node_wwn, *dtype_prop;
uint_t		map_topo;

	while (argv[path_index] != NULL) {
		if ((err = l_convert_name(argv[path_index], &path_phys,
			&path_struct, Options & PVERBOSE)) != 0) {
			(void) fprintf(stderr,
				MSGSTR(33,
					" Error: converting"
					" %s to physical path.\n"
					" Invalid pathname.\n"),
				argv[path_index]);
			if (err != -1) {
				(void) print_errString(err, argv[path_index]);
			}
			exit(-1);
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

		if ((dev_type = g_get_path_type(temp2path)) == 0) {
			(void) print_errString(L_INVALID_PATH,
						argv[path_index]);
			exit(-1);
		}

		if ((map_root = g_dev_map_init(temp2path, &err,
			MAP_FORMAT_LILP)) == NULL) {
		    if (dev_type & FC_FCA_MASK) {
			(void) print_errString(err, argv[path_index]);
			exit(-1);
		    } else {
			/*
			 * This did not work so try the FCIO_GETMAP
			 * type ioctl.
			 */
			if (err = g_get_limited_map(path_phys,
				&limited_map, (Options & PVERBOSE))) {
				(void) print_errString(err,
						argv[path_index]);
				exit(-1);
			}
			limited_map_flag++;
		    }

		}

		if (limited_map_flag) {
		    (void) fprintf(stdout,
			MSGSTR(2093,
			"Host Adapter AL_PA: %x\n"),
			limited_map.lilp_myalpa);

		    (void) fprintf(stdout,
			MSGSTR(2094,
			"Pos AL_PA\n"));
		    for (i = 0; i < (uint_t)limited_map.lilp_length; i++) {
			(void) fprintf(stdout, "%-3d   %-2x\n",
				i, limited_map.lilp_list[i]);
		    }
		} else {
		    if ((err = g_dev_prop_lookup_bytes(map_root,
			PORT_WWN_PROP, &count, &hba_port_wwn)) != 0) {
			g_dev_map_fini(map_root);
			(void) print_errString(err, argv[path_index]);
			exit(-1);
		    }
		    if ((err = g_get_map_topology(
				map_root, &map_topo)) != 0) {
			(void) print_errString(err, argv[path_index]);
			exit(-1);
		    }

		    if ((map_dev = g_get_first_dev(map_root, &err)) == NULL) {
			if (err == L_NO_SUCH_DEV_FOUND) {
			    g_dev_map_fini(map_root);
			    (void) fprintf(stderr,
			    MSGSTR(2308, " No devices are found on %s.\n"),
			    argv[path_index]);
			    exit(-1);
			} else {
			    g_dev_map_fini(map_root);
			    (void) print_errString(err, argv[path_index]);
			    exit(-1);
			}
		    }

		    switch (map_topo) {
		    case FC_TOP_FABRIC:
		    case FC_TOP_PUBLIC_LOOP:
		    case FC_TOP_PT_PT:
			(void) fprintf(stdout,
			MSGSTR(2095, "Pos  Port_ID Hard_Addr Port WWN"
			"         Node WWN         Type\n"));
			while (map_dev) {
			    if ((err = g_dev_prop_lookup_ints(
				map_dev, PORT_ADDR_PROP, &port_addr)) != 0) {
				g_dev_map_fini(map_root);
				(void) print_errString(err, argv[path_index]);
				exit(-1);
			    }
			    if ((err = g_dev_prop_lookup_bytes(map_dev,
				PORT_WWN_PROP, &count, &port_wwn)) != 0) {
				g_dev_map_fini(map_root);
				(void) print_errString(err, argv[path_index]);
				exit(-1);
			    }
			    if ((err = g_dev_prop_lookup_bytes(map_dev,
				NODE_WWN_PROP, &count, &node_wwn)) != 0) {
				g_dev_map_fini(map_root);
				(void) print_errString(err, argv[path_index]);
				exit(-1);
			    }
			    if ((err = g_dev_prop_lookup_ints(
				map_dev, HARD_ADDR_PROP, &hard_addr)) != 0) {
				g_dev_map_fini(map_root);
				(void) print_errString(err, argv[path_index]);
				exit(-1);
			    }
			    print_fabric_prop(pos++, port_wwn,
					node_wwn, *port_addr, *hard_addr);
			    if ((err =  g_dev_prop_lookup_bytes(map_dev,
				INQ_DTYPE_PROP, &count, &dtype_prop)) != 0) {
				(void) fprintf(stdout,
				MSGSTR(2307, " Failed to get the type.\n"));
			    } else {
				print_fabric_dtype_prop(hba_port_wwn, port_wwn,
					*dtype_prop);
			    }

			    if (((map_dev = g_get_next_dev(
				map_dev, &err)) == NULL) &&
				(err != L_NO_SUCH_DEV_FOUND)) {
				g_dev_map_fini(map_root);
				(void) print_errString(err, argv[path_index]);
				exit(-1);
			    }
			}
			break;
		    case FC_TOP_PRIVATE_LOOP:
			(void) fprintf(stdout,
			MSGSTR(2295,
			"Pos AL_PA ID Hard_Addr "
			"Port WWN         Node WWN         Type\n"));

			while (map_dev) {
			    if ((err = g_dev_prop_lookup_ints(
				map_dev, PORT_ADDR_PROP, &port_addr)) != 0) {
				g_dev_map_fini(map_root);
				(void) print_errString(err, argv[path_index]);
				exit(-1);
			    }
			    if ((err = g_dev_prop_lookup_bytes(map_dev,
				PORT_WWN_PROP, &count, &port_wwn)) != 0) {
				g_dev_map_fini(map_root);
				(void) print_errString(err, argv[path_index]);
				exit(-1);
			    }
			    if ((err = g_dev_prop_lookup_bytes(map_dev,
				NODE_WWN_PROP, &count, &node_wwn)) != 0) {
				g_dev_map_fini(map_root);
				(void) print_errString(err, argv[path_index]);
				exit(-1);
			    }
			    if ((err = g_dev_prop_lookup_ints(
				map_dev, HARD_ADDR_PROP, &hard_addr)) != 0) {
				g_dev_map_fini(map_root);
				(void) print_errString(err, argv[path_index]);
				exit(-1);
			    }
			    print_private_loop_prop(pos++, port_wwn,
					node_wwn, *port_addr, *hard_addr);
			    if ((err =  g_dev_prop_lookup_bytes(map_dev,
				INQ_DTYPE_PROP, &count, &dtype_prop)) != 0) {
				(void) fprintf(stdout,
				MSGSTR(2307, " Failed to get the type.\n"));
			    } else {
				print_private_loop_dtype_prop(hba_port_wwn,
					port_wwn, *dtype_prop);
			    }

			    if (((map_dev = g_get_next_dev(
				map_dev, &err)) == NULL) &&
				(err != L_NO_SUCH_DEV_FOUND)) {
				g_dev_map_fini(map_root);
				(void) print_errString(err, argv[path_index]);
				exit(-1);
			    }
			}
			break;
		    default:
			(void) print_errString(L_UNEXPECTED_FC_TOPOLOGY,
			argv[path_index]);
			exit(-1);
		    }
		    g_dev_map_fini(map_root);
		}
		limited_map_flag = 0;
		path_index++;
	}
}

/*
 * Gets a list of non-SENA fcal devices
 * found on the system.
 *
 * OUTPUT:
 *	wwn_list pointer
 *			NULL: No non-enclosure devices found.
 *			!NULL: Devices found
 *                      wwn_list points to a linked list of wwn's.
 * RETURNS:
 *	0	O.K.
 */
int
n_get_non_encl_list(WWN_list **wwn_list_ptr, int verbose)
{
int		i, j, k, err, found_ib = 0, pathcnt = 1;
WWN_list	*wwn_list;
Box_list	*b_list = NULL;
gfc_map_t	map;
uchar_t		box_id;
gfc_port_dev_info_t	*dev_addr_list;
char		phci_path[MAXPATHLEN], oldphci_path[MAXPATHLEN];
mp_pathlist_t	pathlist;


	/*
	 * Only interested in devices that are not part of
	 * a Photon enclosure.
	 */
	if ((err = l_get_box_list(&b_list, verbose)) != 0) {
		return (err);	/* Failure */
	}

	if (err = g_get_wwn_list(&wwn_list, verbose)) {
		(void) l_free_box_list(&b_list);
		return (err);
	}

	while (b_list != NULL) {

		pathcnt = 1;
		if (strstr(b_list->b_physical_path, SCSI_VHCI) != NULL) {
			(void) strcpy(phci_path, b_list->b_physical_path);
			if (err = g_get_pathlist(phci_path, &pathlist)) {
				(void) print_errString(err, NULL);
				exit(-1);
			}
			pathcnt = pathlist.path_count;
		}

		for (k = 0; k < pathcnt; k++) {

		if ((k > 0) && (strstr(oldphci_path,
			pathlist.path_info[k].path_hba))) {
				continue;
		}

		if (strstr(b_list->b_physical_path, SCSI_VHCI) == NULL) {
			if ((err = g_get_dev_map(b_list->b_physical_path,
				&map, verbose)) != 0) {
				(void) g_free_wwn_list(&wwn_list);
				(void) l_free_box_list(&b_list);
				return (err);
			}
		} else {
			(void) strcpy(phci_path,
				pathlist.path_info[k].path_hba);
			(void) strcpy(oldphci_path, phci_path);
			(void) strcat(phci_path, FC_CTLR);
			if (g_get_dev_map(phci_path, &map, verbose)) {
				continue;
			}
			if (pathcnt == 1) {
				free(pathlist.path_info);
			}
		}


		switch (map.hba_addr.port_topology) {
		case FC_TOP_FABRIC:
		case FC_TOP_PUBLIC_LOOP:

			for (i = 0, dev_addr_list = map.dev_addr;
				i < map.count; i++, dev_addr_list++) {
				for (found_ib = 1, j = 0; j < WWN_SIZE;
					j++) {
					if (b_list->b_node_wwn[j] !=
						dev_addr_list->gfc_port_dev.
						pub_port.dev_nwwn.raw_wwn[j]) {
						found_ib = 0;
					}
				}
				if (found_ib) {
					(void) n_rem_list_entry_fabric(
					dev_addr_list->gfc_port_dev.
					pub_port.dev_did.port_id, &map,
					&wwn_list);
				}
			}
			break;

		case FC_TOP_PRIVATE_LOOP:

			for (i = 0, dev_addr_list = map.dev_addr;
				i < map.count; i++, dev_addr_list++) {
				for (found_ib = 1, j = 0; j < WWN_SIZE;
					j++) {
					if (b_list->b_node_wwn[j] !=
						dev_addr_list->gfc_port_dev.
						priv_port.sf_node_wwn[j]) {
							found_ib = 0;
					}
				}
				if (found_ib) {
					box_id = g_sf_alpa_to_switch
						[dev_addr_list->gfc_port_dev.
						priv_port.sf_al_pa] &
						BOX_ID_MASK;
					/* This function has been added */
					/* here only to keep from having */
					/* to tab over farther */
					(void) n_rem_list_entry(box_id, &map,
						&wwn_list);
					if (wwn_list == NULL) {
						/* Return the list */
						*wwn_list_ptr = NULL;
						break;
					}
				}
			}
			break;
		case FC_TOP_PT_PT:
			(void) free((void *)map.dev_addr);
			return (L_PT_PT_FC_TOP_NOT_SUPPORTED);
		default:
			(void) free((void *)map.dev_addr);
			return (L_UNEXPECTED_FC_TOPOLOGY);
		}
		free((void *)map.dev_addr);

		}
		if (pathcnt > 1) {
			free(pathlist.path_info);
		}

		b_list = b_list->box_next;
	}
	/* Return the list */
	*wwn_list_ptr = wwn_list;
	(void) l_free_box_list(&b_list);
	return (0);
}



/*
 * n_rem_list_entry() We found an IB so remove disks that
 * are in the Photon from the individual device list.
 *
 * OUTPUT:
 *	wwn_list - removes the fcal disks that are in SENA enclosure
 *
 * RETURNS:
 *	none
 */
void
n_rem_list_entry(uchar_t box_id,  struct gfc_map *map,
	struct	wwn_list_struct **wwn_list)
{
int		k;
gfc_port_dev_info_t	*dev_addr_list;

	N_DPRINTF("  n_rem_list_entry: Removing devices"
		" with box_id=0x%x from device list.\n", box_id);


		for (k = 0, dev_addr_list = map->dev_addr; k < map->count;
			k++, dev_addr_list++) {
			if ((g_sf_alpa_to_switch[dev_addr_list->gfc_port_dev.
				priv_port.sf_hard_address] & BOX_ID_MASK)
				== box_id) {
				n_rem_wwn_entry(dev_addr_list->gfc_port_dev.
					priv_port.sf_node_wwn, wwn_list);
			}
		}

}



/*
 * n_rem_list_entry_fabric() We found an IB so remove disks that
 * are in the Photon from the individual device list.
 *
 * OUTPUT:
 *	wwn_list - removes the fcal disks that are in SENA enclosure
 *
 * RETURNS:
 *	none
 */
void
n_rem_list_entry_fabric(int pa,  struct gfc_map *map,
	struct	wwn_list_struct **wwn_list)
{
int		k;
gfc_port_dev_info_t	*dev_addr_ptr;

	N_DPRINTF("  n_rem_list_entry: Removing devices"
		" with the same domain and area ID as"
		" 0x%x PA from device list.\n", pa);
	for (k = 0, dev_addr_ptr = map->dev_addr; k < map->count;
				k++, dev_addr_ptr++) {

		/* matching the domain and area id with input alpa, */
		/* ignoring last 8 bits. */
		if ((dev_addr_ptr->gfc_port_dev.pub_port.dev_did.port_id |
				0xff) == (pa | 0xff)) {
			n_rem_wwn_entry(dev_addr_ptr->
				gfc_port_dev.pub_port.dev_nwwn.raw_wwn,
				wwn_list);
		}
	}
}


/*
 * n_rem_wwn_entry() removes input wwn from wwn_list.
 *
 * OUTPUT:
 *	wwn_list - removes the input wwn from wwn_list if found.
 *
 * RETURNS:
 *	none
 */
void
n_rem_wwn_entry(uchar_t node_wwn[], struct  wwn_list_struct **wwn_list)
{
int		l, found_dev;
WWN_list	*inner, *l1;

	inner = *wwn_list;
	while (inner != NULL) {
		for (found_dev = 1, l = 0; l < WWN_SIZE; l++) {
			if (inner->w_node_wwn[l] != node_wwn[l]) {
				found_dev = 0;
			}
		}
		if (found_dev) {
			/* Remove this entry from the list */
			if (inner->wwn_prev != NULL) {
				inner->wwn_prev->wwn_next =
					inner->wwn_next;
			} else {
				*wwn_list = inner->wwn_next;
			}
			if (inner->wwn_next != NULL) {
				inner->wwn_next->wwn_prev =
					inner->wwn_prev;
			}
			l1 = inner;
			N_DPRINTF("  n_rem_wwn_entry: "
				"Removing Logical=%s "
				"Current=0x%x, "
				"Prev=0x%x, Next=0x%x\n",
				l1->logical_path,
				l1,
				l1->wwn_prev,
				l1->wwn_next);
			inner = inner->wwn_next;
			if ((l1->wwn_prev == NULL) &&
				(l1->wwn_next) == NULL) {
				(void) free(l1->physical_path);
				(void) free(l1->logical_path);
				(void) free(l1);
				*wwn_list = NULL;
				N_DPRINTF("  n_rem_list_entry: "
				"No non-Photon "
				"devices left"
				" in the list.\n");
				return;
			}
				(void) free(l1->physical_path);
				(void) free(l1->logical_path);
				(void) free(l1);
		} else {
			inner = inner->wwn_next;
		}
	}
}


/*
 * non_encl_probe() Finds and displays a list of
 * non-SENA fcal devices which is found on the
 * system.
 *
 * RETURNS:
 *	none.
 */
void
non_encl_probe()
{
WWN_list	*wwn_list, *wwn_listh, *inner, *l1;
int		err = 0;
char		lun_a[MAXPATHLEN], lun_b[MAXPATHLEN], temppath[MAXPATHLEN];
char		*tempptra, *tempptrb, *tempptr;
mp_pathlist_t	pathlist;
int		compare_result, retr_outer = 0;
ddi_devid_t	devid1 = NULL, devid2 = NULL;
di_node_t	root = DI_NODE_NIL;

	if (err = n_get_non_encl_list(&wwn_list, (Options & PVERBOSE))) {
		(void) print_errString(err, NULL);
		exit(-1);
	}

	g_sort_wwn_list(&wwn_list);

	wwn_listh = wwn_list;

	if (wwn_list != NULL) {
		if (wwn_list->wwn_next != NULL) {
			(void) fprintf(stdout,
			    MSGSTR(2098, "\nFound Fibre Channel device(s):\n"));
		} else {
			(void) fprintf(stdout,
			    MSGSTR(2099, "\nFound Fibre Channel device:\n"));
		}
	} else {
		return;
	}

	while (wwn_list != NULL) {
	    if (strstr(wwn_list->physical_path, SCSI_VHCI) != NULL) {
		(void) strcpy(temppath, wwn_list->physical_path);
		if ((!g_get_pathlist(temppath,
		    &pathlist)) &&
		    ((tempptra = strchr(pathlist.path_info[0].
		    path_addr, ','))) != NULL) {
			tempptra++;
			(void) strcpy(lun_a, tempptra);
			free(pathlist.path_info);
		}
	    } else {
		if ((((tempptr = strstr(wwn_list->physical_path,
		    SLSH_DRV_NAME_ST)) != NULL) ||
		    ((tempptr = strstr(wwn_list->physical_path,
		    SLSH_DRV_NAME_SSD)) != NULL)) &&
		    ((tempptra = strchr(tempptr, ',')) != NULL)) {
			tempptra++;
			(void) strcpy(lun_a, tempptra);
		}
	    }
	    (void) fprintf(stdout, "  ");
	    (void) fprintf(stdout, MSGSTR(90, "Node WWN:"));
	    (void) fprintf(stdout, "%s  ", wwn_list->node_wwn_s);

	    if (wwn_list->device_type < 0x10) {
		(void) fprintf(stdout, MSGSTR(35, "Device Type:"));
		(void) fprintf(stdout, "%s",
		dtype[wwn_list->device_type]);
	    } else if (wwn_list->device_type < 0x1f) {
			(void) fprintf(stdout, MSGSTR(2100,
			"Type:Reserved"));
	    } else {
			(void) fprintf(stdout, MSGSTR(2101,
			"Type:Unknown"));
	    }
	    (void) fprintf(stdout, "\n    ");
	    (void) fprintf(stdout, MSGSTR(31, "Logical Path:%s"),
			wwn_list->logical_path);
	    (void) fprintf(stdout, "\n");

	    if (Options & OPTION_P) {
		(void) fprintf(stdout, "    ");
		(void) fprintf(stdout,
		MSGSTR(5, "Physical Path:"));
		(void) fprintf(stdout, "\n     %s\n", wwn_list->physical_path);
	    }
	    inner = wwn_list->wwn_next;

	    while (inner != NULL) {
		if (strcmp(inner->node_wwn_s, wwn_list->node_wwn_s) == 0) {

		    if (tempptra != NULL) {
			if (strstr(inner->physical_path,
			    SCSI_VHCI) != NULL) {
			    (void) strcpy(temppath,
			    inner->physical_path);

			    if ((!g_get_pathlist(temppath, &pathlist)) &&
				((tempptrb = strchr(
				pathlist.path_info[0].path_addr, ','))) !=
				    NULL) {
				tempptrb++;
				(void) strcpy(lun_b, tempptrb);
				free(pathlist.path_info);
			    }
			} else {
			    if ((((tempptr = strstr(inner->physical_path,
				SLSH_DRV_NAME_ST)) != NULL) ||
				((tempptr = strstr(inner->physical_path,
				SLSH_DRV_NAME_SSD)) != NULL)) &&
				((tempptrb = strchr(tempptr, ',')) != NULL)) {
				tempptrb++;
				(void) strcpy(lun_b, tempptrb);
			    }
			}
		    }

		    if (((tempptra == NULL) || (strcmp(lun_a, lun_b)) == 0)) {

			/*
			 * Have we retrieved a snapshot yet?
			 */
			if (root == DI_NODE_NIL) {
			    if ((root = di_init("/", DINFOCPYALL)) ==
				DI_NODE_NIL) {
				(void) fprintf(stdout,
				    MSGSTR(2319,
				    "\nFailed to get device tree snapshot:\n"));
				exit(1);
			    }
			}

			/* Apply devid to ssd devices only */
			if (!retr_outer && strstr(wwn_list->physical_path,
			    SLSH_DRV_NAME_SSD) != NULL) {
			    if ((err = g_devid_get(wwn_list->physical_path,
				&devid1, root, SSD_DRVR_NAME)) != 0) {
				(void) print_errString(err,
				    wwn_list->physical_path);
			    }
			/*
			 * Try retrieve of devid only once. If it fails
			 * don't try it again but print error,
			 * There should be a devid prop.
			 */
			    retr_outer = 1;
			}
			/*
			 * Apply devid to block devices only.
			 * Get devid of inner path and compare
			 * with outer path's devid.
			 */
			if ((strstr(inner->physical_path,
			    SLSH_DRV_NAME_SSD) != NULL) &&
			    devid1 != NULL) {

			    if ((err = g_devid_get(inner->physical_path,
				&devid2, root, SSD_DRVR_NAME)) != 0) {

				(void) print_errString(err,
				    inner->physical_path);
				compare_result = 0;
			    } else {
				compare_result = devid_compare(devid1, devid2);
			    }
			} else {
			    /* devid isn't applied */
			    compare_result = 0;
			}

			if (compare_result == 0) {

			    if (strcmp(wwn_list->logical_path,
				inner->logical_path)) {
				(void) fprintf(stdout, "    ");
				(void) fprintf(stdout,
				    MSGSTR(31, "Logical Path:%s"),
					inner->logical_path);
				(void) fprintf(stdout, "\n");

				if (Options & OPTION_P) {
				    (void) fprintf(stdout, "    ");
				    (void) fprintf(stdout, MSGSTR(5,
					"Physical Path:"));
				    (void) fprintf(stdout, "\n     %s\n",
					inner->physical_path);
				}
			    }

			    /* Remove this entry from the list */
			    if (inner->wwn_prev != NULL) {
				inner->wwn_prev->wwn_next =
				inner->wwn_next;
			    }

			    if (inner->wwn_next != NULL) {
				inner->wwn_next->wwn_prev =
				inner->wwn_prev;
			    }
			    free(inner->physical_path);
			    free(inner->logical_path);
			    l1 = inner;
			    inner = inner->wwn_next;
			    (void) free(l1);

			} else {
			    inner = inner->wwn_next;
			} /* End if (compare_result == 0) */

		    } else {
			inner = inner->wwn_next;
		    }
		} else {
		    inner = inner->wwn_next;
		}
		devid2 = NULL;
	    }
	    wwn_list = wwn_list->wwn_next;
	    retr_outer = 0;
	    devid1 = NULL;
	} /* End while (wwn_list != NULL) */

	(void) g_free_wwn_list(&wwn_listh);
	(void) di_fini(root);
}

void
pho_probe()
{

Box_list	*b_list, *o_list, *c_list;
int		multi_path_flag, multi_print_flag;
int		duplicate_names_found = 0, err = 0;

	b_list = o_list = c_list = NULL;
	if ((err = l_get_box_list(&b_list, Options & PVERBOSE)) != 0) {
		(void) print_errString(err, NULL);
		exit(-1);
	}
	if (b_list == NULL) {
		(void) fprintf(stdout,
			MSGSTR(93, "No %s enclosures found "
			"in /dev/es\n"), ENCLOSURE_PROD_NAME);
	} else {
		o_list = b_list;
		if (b_list->box_next != NULL) {
			(void) fprintf(stdout, MSGSTR(2102,
				"Found Enclosure(s)"));
		} else {
			(void) fprintf(stdout, MSGSTR(2103, "Found Enclosure"));
		}
		(void) fprintf(stdout, ":\n");
		while (b_list != NULL) {
			/* Don't re-print multiple paths */
			c_list = o_list;
			multi_print_flag = 0;
			while (c_list != b_list) {
				if (strcmp(c_list->b_node_wwn_s,
					b_list->b_node_wwn_s) == 0) {
					multi_print_flag = 1;
					break;
				}
				c_list = c_list->box_next;
			}
			if (multi_print_flag) {
				b_list = b_list->box_next;
				continue;
			}
			(void) fprintf(stdout,
			MSGSTR(2104, "%s   Name:%s   Node WWN:%s   "),
			b_list->prod_id_s, b_list->b_name,
				b_list->b_node_wwn_s);
			/*
			 * Print logical path on same line if not multipathed.
			 */
			multi_path_flag = 0;
			c_list = o_list;
			while (c_list != NULL) {
				if ((c_list != b_list) &&
					(strcmp(c_list->b_node_wwn_s,
					b_list->b_node_wwn_s) == 0)) {
					multi_path_flag = 1;
				}
				c_list = c_list->box_next;
			}
			if (multi_path_flag) {
				(void) fprintf(stdout, "\n  ");
			}
			(void) fprintf(stdout,
			MSGSTR(31, "Logical Path:%s"),
			b_list->logical_path);

			if (Options & OPTION_P) {
				(void) fprintf(stdout, "\n  ");
				(void) fprintf(stdout,
				MSGSTR(5, "Physical Path:"));
				(void) fprintf(stdout, "%s",
				b_list->b_physical_path);
			}
			c_list = o_list;
			while (c_list != NULL) {
				if ((c_list != b_list) &&
				(strcmp(c_list->b_node_wwn_s,
					b_list->b_node_wwn_s) == 0)) {
					(void) fprintf(stdout, "\n  ");
					(void) fprintf(stdout,
					MSGSTR(31, "Logical Path:%s"),
					c_list->logical_path);
					if (Options & OPTION_P) {
						(void) fprintf(stdout, "\n  ");
						(void) fprintf(stdout,
						MSGSTR(5, "Physical Path:"));
						(void) fprintf(stdout, "%s",
						c_list->b_physical_path);
					}
				}
				c_list = c_list->box_next;
			}
			(void) fprintf(stdout, "\n");
			/* Check for duplicate names */
			if (l_duplicate_names(o_list, b_list->b_node_wwn_s,
				(char *)b_list->b_name,
				Options & PVERBOSE)) {
				duplicate_names_found++;
			}
			b_list = b_list->box_next;
		}
	}
	if (duplicate_names_found) {
		(void) fprintf(stdout,
			MSGSTR(2105, "\nWARNING: There are enclosures with "
			"the same names.\n"
			"You can not use the \"enclosure\""
			" name to specify these subsystems.\n"
			"Please use the \"enclosure_name\""
			" subcommand to select unique names.\n\n"));
	}
	(void) l_free_box_list(&b_list);
}

/*
 * display_port_status() Prints the device's
 * port status.
 *
 * RETURNS:
 *	none.
 */
void
display_port_status(int d_state_flag)
{

	if (d_state_flag & L_OPEN_FAIL) {
		(void) fprintf(stdout, MSGSTR(28, "Open Failed"));
	} else if (d_state_flag & L_NOT_READY) {
		(void) fprintf(stdout, MSGSTR(20, "Not Ready"));
	} else if (d_state_flag & L_NOT_READABLE) {
		(void) fprintf(stdout, MSGSTR(88, "Not Readable"));
	} else if (d_state_flag & L_SPUN_DWN_D) {
		(void) fprintf(stdout, MSGSTR(68, "Spun Down"));
	} else if (d_state_flag & L_SCSI_ERR) {
		(void) fprintf(stdout, MSGSTR(70, "SCSI Error"));
	} else if (d_state_flag & L_RESERVED) {
		(void) fprintf(stdout, MSGSTR(73, "Reservation conflict"));
	} else if (d_state_flag & L_NO_LABEL) {
		(void) fprintf(stdout, MSGSTR(92, "No UNIX Label"));
	} else {
		(void) fprintf(stdout, MSGSTR(29, "O.K."));
	}
	(void) fprintf(stdout, "\n");
}

/*
 * Displays individual SENA
 * FC disk information.
 *
 * Caller to this routine should free the storage due to
 * the use of g_get_dev_map
 *
 * RETURNS:
 *	none.
 */
void
display_fc_disk(struct path_struct *path_struct, char *ses_path,
	gfc_map_t *map, L_inquiry inq, int verbose)
{
static WWN_list		*wwn_list = NULL;
static char		path_phys[MAXPATHLEN];
static L_disk_state	l_disk_state;
static L_inquiry	local_inq;
static uchar_t		node_wwn[WWN_SIZE];
char			same_path_phys = B_FALSE; /* To chk for repeat args */
uchar_t			port_wwn[WWN_SIZE], *pg_buf;
char			logical_path[MAXPATHLEN];
int			al_pa, port_a_flag = 0;
int			offset, mode_data_avail = 0;
int			no_path_flag = 0, err = 0;
L_state			l_state;
Mode_header_10		*mode_header_ptr = NULL;
struct mode_page	*pg_hdr;

	/*
	 * Do a quick check to see if its the same path as in last call.
	 * path_phys is a static array and so dont worry about its
	 * initialization.
	 */
	if (strcmp(path_phys, path_struct->p_physical_path) == 0)
		same_path_phys = B_TRUE;

	(void) strcpy(path_phys, path_struct->p_physical_path);
	(void) memset((char *)logical_path, 0, sizeof (logical_path));

	/*
	 * slot_valid is 1 when argument is of the form 'enclosure,[f|r]<n>'.
	 * If slot_valid != 1, g_get_dev_map and l_get_ses_path would
	 * already have been called
	 */
	if (path_struct->slot_valid == 1) {
		/* Get the location information. */
		if (err = g_get_dev_map(path_phys, map, (Options & PVERBOSE))) {
			(void) print_errString(err, path_phys);
			exit(-1);
		}
		if (err = l_get_ses_path(path_phys, ses_path, map,
			(Options & PVERBOSE))) {
			(void) print_errString(err, path_phys);
			exit(-1);
		}
	}

	/*
	 * Get the WWN for our disk if we already haven't or if there was an
	 * error earlier
	 */
	if (same_path_phys == B_FALSE) {
		if (err = g_get_wwn(path_phys, port_wwn, node_wwn,
			&al_pa, (Options & PVERBOSE))) {
			(void) print_errString(err, path_phys);
			exit(-1);
		}

		if (err = g_get_inquiry(ses_path, &local_inq)) {
			(void) print_errString(err, ses_path);
			exit(-1);
		}
	}

	/*
	 * We are interested only a couple of ib_tbl fields and
	 * those get filled using l_get_ib_status.
	 * Note that NOT ALL of ib_tbl fields get filled here
	 */
	if ((err = l_get_ib_status(ses_path, &l_state,
				Options & PVERBOSE)) != 0) {
		(void) print_errString(err, ses_path);
		exit(-1);
	}

	/*
	 * Get path to all the FC disk and tape devices.
	 * if we haven't already done so in a previous pass
	 */
	if ((wwn_list == NULL) && (err = g_get_wwn_list(&wwn_list, verbose))) {
		(void) print_errString(err, ses_path);
		exit(-1);   /* Failure */
	}

	/*
	 * Get the disk status if it is a different path_phys from
	 * last time.
	 */
	if (same_path_phys == B_FALSE) {
		(void) memset(&l_disk_state, 0,
				sizeof (struct l_disk_state_struct));
		if (err = l_get_disk_status(path_phys, &l_disk_state,
				wwn_list, (Options & PVERBOSE))) {
			(void) print_errString(err, path_phys);
			exit(-1);
		}
	}

	if (l_disk_state.l_state_flag & L_NO_PATH_FOUND) {
		(void) fprintf(stderr, MSGSTR(2106,
			"\nWARNING: No path found "
			"in /dev/rdsk directory\n"
			"  Please check the logical links in /dev/rdsk\n"
			"  (It may be necessary to run the \"disks\" "
			"program.)\n\n"));

		/* Just call to get the status directly. */
		if (err = l_get_port(ses_path, &port_a_flag, verbose)) {
			(void) print_errString(err, ses_path);
			exit(-1);
		}
		if (err = l_get_disk_port_status(path_phys,
			&l_disk_state, port_a_flag,
			(Options & PVERBOSE))) {
			(void) print_errString(err, path_phys);
			exit(-1);
		}
		no_path_flag++;
	}

	if (strlen(l_disk_state.g_disk_state.node_wwn_s) == 0) {
		(void) sprintf(l_disk_state.g_disk_state.node_wwn_s,
			"%1.2x%1.2x%1.2x%1.2x%1.2x%1.2x%1.2x%1.2x",
			node_wwn[0], node_wwn[1], node_wwn[2], node_wwn[3],
			node_wwn[4], node_wwn[5], node_wwn[6], node_wwn[7]);
	}

	/* get mode page information for FC device */
	if (l_get_mode_pg(path_phys, &pg_buf, Options & PVERBOSE) == 0) {
		mode_header_ptr = (struct mode_header_10_struct *)(int)pg_buf;
		pg_hdr = ((struct mode_page *)((int)pg_buf +
			(uchar_t)sizeof (struct mode_header_10_struct) +
			(uchar_t *)(uintptr_t)(mode_header_ptr->bdesc_length)));
		offset = sizeof (struct mode_header_10_struct) +
			mode_header_ptr->bdesc_length;
		while (offset < (mode_header_ptr->length +
			sizeof (mode_header_ptr->length)) &&
						!mode_data_avail) {
			if (pg_hdr->code == MODEPAGE_CACHING) {
				mode_data_avail++;
				break;
			}
			offset += pg_hdr->length + sizeof (struct mode_page);
			pg_hdr = ((struct mode_page *)((int)pg_buf +
				(uchar_t)offset));
		}
	}

	switch ((inq.inq_dtype & DTYPE_MASK)) {
	case DTYPE_DIRECT:
	    fprintf(stdout, MSGSTR(121, "DEVICE PROPERTIES for disk: %s\n"),
		path_struct->argv);
	    break;
	case DTYPE_SEQUENTIAL: /* Tape */
	    fprintf(stdout, MSGSTR(2249, "DEVICE PROPERTIES for tape: %s\n"),
		path_struct->argv);
	    break;
	default:
	    fprintf(stdout, MSGSTR(2250, "DEVICE PROPERTIES for: %s\n"),
		path_struct->argv);
	    break;
	}

	if (l_disk_state.g_disk_state.port_a_valid) {
		(void) fprintf(stdout, "  ");
		(void) fprintf(stdout, MSGSTR(141, "Status(Port A):"));
		(void) fprintf(stdout, "\t");
		display_port_status(
			l_disk_state.g_disk_state.d_state_flags[PORT_A]);
	} else {
		if (path_struct->f_flag) {
			if ((ib_present_chk(&l_state, 0) == 1) &&
		(l_state.drv_front[path_struct->slot].ib_status.bypass_a_en)) {
				(void) fprintf(stdout,
					MSGSTR(66,
					"  Status(Port A):\tBYPASSED\n"));
			}
		} else {
			if ((ib_present_chk(&l_state, 0) == 1) &&
		(l_state.drv_rear[path_struct->slot].ib_status.bypass_a_en)) {
				(void) fprintf(stdout,
					MSGSTR(66,
					"  Status(Port A):\tBYPASSED\n"));
			}
		}
	}

	if (l_disk_state.g_disk_state.port_b_valid) {
		(void) fprintf(stdout, "  ");
		(void) fprintf(stdout, MSGSTR(142, "Status(Port B):"));
		(void) fprintf(stdout, "\t");
	display_port_status(l_disk_state.g_disk_state.d_state_flags[PORT_B]);
	} else {
		if (path_struct->f_flag) {
			if ((ib_present_chk(&l_state, 1) == 1) &&
		(l_state.drv_front[path_struct->slot].ib_status.bypass_b_en)) {
				(void) fprintf(stdout,
					MSGSTR(65,
					"  Status(Port B):\tBYPASSED\n"));
			}
		} else {
			if ((ib_present_chk(&l_state, 1) == 1) &&
		(l_state.drv_rear[path_struct->slot].ib_status.bypass_b_en)) {
				(void) fprintf(stdout,
					MSGSTR(65,
					"  Status(Port B):\tBYPASSED\n"));
			}
		}
	}

	if (no_path_flag) {
		(void) fprintf(stdout, "  ");
		if (port_a_flag != 0) {
			(void) fprintf(stdout, MSGSTR(142, "Status(Port B):"));
		} else {
			(void) fprintf(stdout, MSGSTR(141, "Status(Port A):"));
		}
		(void) fprintf(stdout, "\t");
		display_port_status(
		l_disk_state.g_disk_state.d_state_flags[port_a_flag]);
	} else if ((!l_disk_state.g_disk_state.port_a_valid) &&
			(!l_disk_state.g_disk_state.port_b_valid)) {
		(void) fprintf(stdout, MSGSTR(2107, "  Status:\t\t"
		"No state available.\n"));
	}

	(void) display_disk_info(inq, l_disk_state, path_struct, pg_hdr,
		mode_data_avail, (char *)local_inq.inq_box_name, verbose);
}





/*
 * non_encl_fc_disk_display() Prints the device specific
 * information for an individual fcal device.
 *
 * RETURNS:
 *	none.
 */
static int
non_encl_fc_disk_display(Path_struct *path_struct,
				L_inquiry inq_struct, int verbose)
{

char			phys_path[MAXPATHLEN];
uchar_t			node_wwn[WWN_SIZE], port_wwn[WWN_SIZE], *pg_buf = NULL;
L_disk_state		l_disk_state;
struct dlist		*mlist;
int			i = 0, al_pa, offset, mode_data_avail = 0, err = 0;
int			path_a_found = 0, path_b_found = 0, argpwwn = 0,
			argnwwn = 0, pathcnt = 1;
L_inquiry		local_inq;
Mode_header_10		*mode_header_ptr;
struct mode_page	*pg_hdr;
WWN_list		*wwn_list, *wwn_list_ptr, *list_start;
char			temppath[MAXPATHLEN], last_logical_path[MAXPATHLEN];
mp_pathlist_t		pathlist;

	(void) strcpy(phys_path, path_struct->p_physical_path);

	/* Get path to all the FC disk and tape devices. */
	if (err = g_get_wwn_list(&wwn_list, verbose)) {
		return (err);
	}

	g_sort_wwn_list(&wwn_list);

	list_start = wwn_list;
	(void) strcpy(last_logical_path, phys_path);

	for (wwn_list_ptr = wwn_list; wwn_list_ptr != NULL;
		wwn_list_ptr = wwn_list_ptr->wwn_next) {
		if (strcasecmp(wwn_list_ptr->port_wwn_s,
			path_struct->argv) == 0) {
			list_start = wwn_list_ptr;
			argpwwn = 1;
			break;
		} else if (strcasecmp(wwn_list_ptr->node_wwn_s,
			path_struct->argv) == 0) {
			list_start = wwn_list_ptr;
			argnwwn = 1;
			break;
		}
	}

	for (wwn_list_ptr = list_start; wwn_list_ptr != NULL;
		wwn_list_ptr = wwn_list_ptr->wwn_next) {


	if (argpwwn) {
		if (strcasecmp(wwn_list_ptr->port_wwn_s,
			path_struct->argv) != 0) {
			continue;
		}
		(void) strcpy(phys_path, wwn_list_ptr->physical_path);
		path_a_found = 0;
		path_b_found = 0;
		mode_data_avail = 0;
	} else if (argnwwn) {
		if (strstr(wwn_list_ptr->logical_path,
			last_logical_path) != NULL) {
			continue;
		}
		if (strcasecmp(wwn_list_ptr->node_wwn_s,
			path_struct->argv) != 0) {
			continue;
		}
		(void) strcpy(phys_path, wwn_list_ptr->physical_path);
		(void) strcpy(last_logical_path,
			wwn_list_ptr->logical_path);
		path_a_found = 0;
		path_b_found = 0;
		mode_data_avail = 0;
	}

	(void) memset(&l_disk_state, 0, sizeof (struct l_disk_state_struct));

	if ((err = g_get_multipath(phys_path,
		&(l_disk_state.g_disk_state.multipath_list),
		wwn_list, verbose)) != 0) {
		return (err);
	}
	mlist = l_disk_state.g_disk_state.multipath_list;
	if (mlist == NULL) {
		l_disk_state.l_state_flag = L_NO_PATH_FOUND;
		N_DPRINTF(" non_encl_fc_disk_display: Error finding"
			" multiple paths to the disk.\n");
		(void) g_free_wwn_list(&wwn_list);
		return (-1);
	}

	/* get mode page information for FC device */
	if (l_get_mode_pg(phys_path, &pg_buf, verbose) == 0) {
		mode_header_ptr = (struct mode_header_10_struct *)(int)pg_buf;
		pg_hdr = ((struct mode_page *)((int)pg_buf +
			(uchar_t)sizeof (struct mode_header_10_struct) +
			(uchar_t *)(uintptr_t)(mode_header_ptr->bdesc_length)));
		offset = sizeof (struct mode_header_10_struct) +
			mode_header_ptr->bdesc_length;
		while (offset < (mode_header_ptr->length +
			sizeof (mode_header_ptr->length)) &&
						!mode_data_avail) {
			if (pg_hdr->code == MODEPAGE_CACHING) {
				mode_data_avail++;
				break;
			}
			offset += pg_hdr->length + sizeof (struct mode_page);
			pg_hdr = ((struct mode_page *)((int)pg_buf +
				(uchar_t)offset));
		}
	}

	switch ((inq_struct.inq_dtype & DTYPE_MASK)) {
	case DTYPE_DIRECT:
	    fprintf(stdout, MSGSTR(121, "DEVICE PROPERTIES for disk: %s\n"),
		path_struct->argv);
	    break;
	case DTYPE_SEQUENTIAL: /* Tape */
	    fprintf(stdout, MSGSTR(2249, "DEVICE PROPERTIES for tape: %s\n"),
		path_struct->argv);
	    break;
	default:
	    fprintf(stdout, MSGSTR(2250, "DEVICE PROPERTIES for: %s\n"),
		path_struct->argv);
	    break;
	}
	while ((mlist != NULL) && (!(path_a_found && path_b_found))) {
		(void) strcpy(phys_path, mlist->dev_path);
		if (err = g_get_inquiry(phys_path, &local_inq)) {
			(void) fprintf(stderr,
				MSGSTR(2114,
				"non_encl_fc_disk_display: Inquiry failed\n"));
			(void) print_errString(err, phys_path);
			(void) g_free_multipath(
				l_disk_state.g_disk_state.multipath_list);
			(void) g_free_wwn_list(&wwn_list);
			return (-1);
		}
		if ((err = g_get_wwn(mlist->dev_path, port_wwn, node_wwn,
					&al_pa, verbose)) != 0) {
			(void) print_errString(err, mlist->dev_path);
			(void) g_free_multipath(
				l_disk_state.g_disk_state.multipath_list);
			(void) g_free_wwn_list(&wwn_list);
			return (-1);
		}
		if (strlen(l_disk_state.g_disk_state.node_wwn_s) == 0) {
			(void) sprintf(l_disk_state.g_disk_state.node_wwn_s,
			"%1.2x%1.2x%1.2x%1.2x%1.2x%1.2x%1.2x%1.2x",
			node_wwn[0], node_wwn[1], node_wwn[2], node_wwn[3],
			node_wwn[4], node_wwn[5], node_wwn[6], node_wwn[7]);
		}
		if ((err = l_get_disk_port_status(phys_path, &l_disk_state,
				(local_inq.inq_port) ? FC_PORT_B : FC_PORT_A,
				verbose)) != 0) {
			(void) print_errString(err, phys_path);
			(void) g_free_multipath(
				l_disk_state.g_disk_state.multipath_list);
			exit(-1);
		}

		if ((!local_inq.inq_port) && (!path_a_found)) {
			(void) sprintf(l_disk_state.g_disk_state.port_a_wwn_s,
				"%1.2x%1.2x%1.2x%1.2x%1.2x%1.2x%1.2x%1.2x",
			port_wwn[0], port_wwn[1], port_wwn[2], port_wwn[3],
			port_wwn[4], port_wwn[5], port_wwn[6], port_wwn[7]);
		path_a_found = l_disk_state.g_disk_state.port_a_valid = 1;
		}
		if ((local_inq.inq_port) && (!path_b_found)) {
		path_b_found = l_disk_state.g_disk_state.port_b_valid = 1;
			(void) sprintf(l_disk_state.g_disk_state.port_b_wwn_s,
				"%1.2x%1.2x%1.2x%1.2x%1.2x%1.2x%1.2x%1.2x",
			port_wwn[0], port_wwn[1], port_wwn[2], port_wwn[3],
			port_wwn[4], port_wwn[5], port_wwn[6], port_wwn[7]);
		}

		if ((strstr(mlist->dev_path, SCSI_VHCI) != NULL) &&
			(!l_get_disk_port_status(phys_path, &l_disk_state,
			(!local_inq.inq_port) ? FC_PORT_B : FC_PORT_A,
			verbose))) {
			(void) strcpy(temppath, mlist->dev_path);
			if (err = g_get_pathlist(temppath, &pathlist)) {
				(void) print_errString(err, NULL);
				exit(-1);
			}
			pathcnt = pathlist.path_count;
			if (pathcnt > 1) {
				for (i = 0; i < pathcnt; i++) {
					if ((!path_a_found) &&
						(path_b_found) &&
						(strstr(pathlist.path_info[i].
						path_addr,
						l_disk_state.g_disk_state.
						port_b_wwn_s) == NULL)) {

						(void) strncpy(l_disk_state.
						g_disk_state.port_a_wwn_s,
						pathlist.path_info[i].
						path_addr, 16);
						path_a_found = l_disk_state.
						g_disk_state.port_a_valid = 1;
					}
					if ((path_a_found) &&
						(!path_b_found) &&
						(strstr(pathlist.path_info[i].
						path_addr,
						l_disk_state.g_disk_state.
						port_a_wwn_s) == NULL)) {

						(void) strncpy(l_disk_state.
						g_disk_state.port_b_wwn_s,
						pathlist.path_info[i].
						path_addr, 16);
						path_b_found = l_disk_state.
						g_disk_state.port_b_valid = 1;
					}
					if ((path_a_found) && (path_b_found)) {
						break;
					}
				}
			}
			free(pathlist.path_info);
		}

		mlist = mlist->next;
	}

	if (l_disk_state.g_disk_state.port_a_valid) {
		(void) fprintf(stdout, "  ");
		(void) fprintf(stdout, MSGSTR(141, "Status(Port A):"));
		(void) fprintf(stdout, "\t");
	display_port_status(l_disk_state.g_disk_state.d_state_flags[FC_PORT_A]);
	}

	if (l_disk_state.g_disk_state.port_b_valid) {
		(void) fprintf(stdout, "  ");
		(void) fprintf(stdout, MSGSTR(142, "Status(Port B):"));
		(void) fprintf(stdout, "\t");
	display_port_status(l_disk_state.g_disk_state.d_state_flags[FC_PORT_B]);
	}

	(void) display_disk_info(local_inq, l_disk_state, path_struct,
				pg_hdr, mode_data_avail, NULL, verbose);
	(void) g_free_multipath(l_disk_state.g_disk_state.multipath_list);

	if (!(argpwwn || argnwwn)) {
		break;
	}

	}
	(void) g_free_wwn_list(&wwn_list);
	return (0);
}



/*
 * display_disk_info() Prints the device specific information
 * for any FC_AL disk device.
 *
 * RETURNS:
 *	none.
 */
void
display_disk_info(L_inquiry inq, L_disk_state l_disk_state,
		Path_struct *path_struct, struct mode_page *pg_hdr,
		int mode_data_avail, char *name_buf, int options)
{
float		num_blks;
struct dlist	*mlist;
int		port_a, port_b;
struct	my_mode_caching	*pg8_buf;
L_inquiry	enc_inq;
char		*enc_phys_path;
Path_struct	*enc_path_struct;
int		enc_type = 0;
L_inquiry80	inq80;
size_t		serial_len;
int		err;

	serial_len = sizeof (inq80.inq_serial);
	err = g_get_serial_number(path_struct->p_physical_path,
	    inq80.inq_serial, &serial_len);
	if (err) {
		fprintf(stderr, "\n");
		print_errString(err, path_struct->p_physical_path);
		fprintf(stderr, "\n");
		exit(1);
	}
	(void) fprintf(stdout, "  ");
	(void) fprintf(stdout, MSGSTR(3, "Vendor:"));
	(void) fprintf(stdout, "\t\t");
	print_chars(inq.inq_vid, sizeof (inq.inq_vid), 0);

	(void) fprintf(stdout, MSGSTR(2115, "\n  Product ID:\t\t"));
	print_chars(inq.inq_pid, sizeof (inq.inq_pid), 0);

	(void) fprintf(stdout, MSGSTR(2116, "\n  WWN(Node):\t\t%s"),
				l_disk_state.g_disk_state.node_wwn_s);

	if (l_disk_state.g_disk_state.port_a_valid) {
		(void) fprintf(stdout, MSGSTR(2117, "\n  WWN(Port A):\t\t%s"),
				l_disk_state.g_disk_state.port_a_wwn_s);
	}
	if (l_disk_state.g_disk_state.port_b_valid) {
		(void) fprintf(stdout, MSGSTR(2118, "\n  WWN(Port B):\t\t%s"),
				l_disk_state.g_disk_state.port_b_wwn_s);
	}
	(void) fprintf(stdout, "\n  ");
	(void) fprintf(stdout, MSGSTR(2119, "Revision:"));
	(void) fprintf(stdout, "\t\t");
	print_chars(inq.inq_revision, sizeof (inq.inq_revision), 0);

	(void) fprintf(stdout, "\n  ");
	(void) fprintf(stdout, MSGSTR(17, "Serial Num:"));
	(void) fprintf(stdout, "\t\t");
	print_chars(inq80.inq_serial, serial_len, 0);
	num_blks = l_disk_state.g_disk_state.num_blocks;
	if (num_blks) {
		num_blks /= 2048;	/* get Mbytes */
		(void) fprintf(stdout, "\n  ");
		(void) fprintf(stdout,
			MSGSTR(60,
		"Unformatted capacity:\t%6.3f MBytes"), num_blks);
	}
	(void) fprintf(stdout, "\n");

	if (l_disk_state.g_disk_state.persistent_reserv_flag) {
		(void) fprintf(stdout,
			MSGSTR(2120, "  Persistent Reserve:\t"));
		if (l_disk_state.g_disk_state.persistent_active) {
			(void) fprintf(stdout,
				MSGSTR(39, "Active"));
				(void) fprintf(stdout, "\n");
		}
		if (l_disk_state.g_disk_state.persistent_registered) {
			(void) fprintf(stdout,
				MSGSTR(2121, "Found Registered Keys"));
		} else {
			(void) fprintf(stdout,
				MSGSTR(87, "Not being used"));
		}
		(void) fprintf(stdout, "\n");
	}

	if ((mode_data_avail) && (pg_hdr->code == MODEPAGE_CACHING)) {
		pg8_buf = (struct my_mode_caching *)(int)pg_hdr;
		if (pg8_buf->wce) {
			(void) fprintf(stdout,
				MSGSTR(2122,
				"  Write Cache:\t\t"
				"Enabled\n"));
		}
		if (pg8_buf->rcd == 0) {
			(void) fprintf(stdout,
				MSGSTR(2123,
				"  Read Cache:\t\t"
				"Enabled\n"));
			(void) fprintf(stdout,
				MSGSTR(2320,
				"    Minimum prefetch:"
				"\t0x%x\n"
				"    Maximum prefetch:"
				"\t0x%x\n"),
				pg8_buf->min_prefetch,
				pg8_buf->max_prefetch);
		}
	}

	/*
	 * When /dev/rdsk/cxtxdxsx form of input is specified
	 * for display command the initial library version didn't
	 * display Location information.  The change is made
	 * to display the same Location info as the non-library version.
	 */

	if (name_buf != NULL) {
	    fprintf(stdout, MSGSTR(2125, "  Location:\t\t"));
	    if (path_struct->slot_valid) {
		/*
		 * We have to do another inquiry on the enclosure (name_buf)
		 * to determine if this device is within a daktari, or
		 * a two sided device.
		 */
		if (!l_convert_name(name_buf, &enc_phys_path,
			&enc_path_struct, 0)) {
		    if (!g_get_inquiry(enc_phys_path, &enc_inq)) {
			enc_type = l_get_enc_type(enc_inq);
		    }
		}
		/* If either of the above fail, we just assume the default */
		free(enc_phys_path);
		free(enc_path_struct);
		if (enc_type == DAK_ENC_TYPE) {
			if (path_struct->f_flag) {
				(void) fprintf(stdout, MSGSTR(2239,
				    "In slot %d in the enclosure named: %s\n"),
				    path_struct->slot, name_buf);
			} else {
				(void) fprintf(stdout, MSGSTR(2239,
				    "In slot %d in the enclosure named: %s\n"),
				    path_struct->slot + (MAX_DRIVES_DAK/2),
								name_buf);
			}
		} else	{  /* Default enclosure type */
		    (void) fprintf(stdout, path_struct->f_flag ?
				MSGSTR(2126,
			"In slot %d in the Front of the enclosure named: %s\n")
				: MSGSTR(2127,
			"In slot %d in the Rear of the enclosure named: %s\n"),
				path_struct->slot, name_buf);
		}
	    } else {
		(void) fprintf(stdout, MSGSTR(2228,
			"In the enclosure named: %s\n"),
			name_buf);
	    }
	}

	(void) fprintf(stdout, "  %s\t\t%s\n",
			MSGSTR(35, "Device Type:"),
			dtype[inq.inq_dtype & DTYPE_MASK]);

	mlist = l_disk_state.g_disk_state.multipath_list;
	(void) fprintf(stdout, MSGSTR(2128, "  Path(s):\n"));
	if (strstr(mlist->dev_path, SCSI_VHCI) != NULL) {
		(void) fprintf(stdout, "  %s\n  %s\n",
			mlist->logical_path, mlist->dev_path);
		(void) adm_print_pathlist(mlist->dev_path);
	} else {
		while (mlist) {
			(void) fprintf(stdout, "  %s\n  %s\n",
				mlist->logical_path, mlist->dev_path);
			mlist = mlist->next;
		}
	}

	if (Options & OPTION_V) {
		if (path_struct->slot_valid) {
			port_a = PORT_A;
			port_b = PORT_B;
		} else {
			port_a = FC_PORT_A;
			port_b = FC_PORT_B;
		}
		/* Only bother if the state is O.K. */
		if ((l_disk_state.g_disk_state.port_a_valid) &&
			(l_disk_state.g_disk_state.d_state_flags[port_a] == 0))
		adm_display_verbose_disk(path_struct->p_physical_path, options);
		else if ((l_disk_state.g_disk_state.port_b_valid) &&
			(l_disk_state.g_disk_state.d_state_flags[port_b] == 0))
		adm_display_verbose_disk(path_struct->p_physical_path, options);
	}
	(void) fprintf(stdout, "\n");

}



/*
 * temp_decode() Display temperature bytes 1-3 state.
 *
 * RETURNS:
 *	none.
 */
void
temp_decode(Temp_elem_st *temp)
{
	if (temp->ot_fail) {
		(void) fprintf(stdout, MSGSTR(2129,
			": FAILURE - Over Temperature"));
	}
	if (temp->ut_fail) {
		(void) fprintf(stdout, MSGSTR(2130,
			": FAILURE - Under Temperature"));
	}
	if (temp->ot_warn) {
		(void) fprintf(stdout, MSGSTR(2131,
			": WARNING - Over Temperature"));
	}
	if (temp->ut_warn) {
		(void) fprintf(stdout, MSGSTR(2132,
			": WARNING - Under Temperature"));
	}
}



/*
 * disp_degree() Display temperature in Degrees Celsius.
 *
 * RETURNS:
 *	none.
 */
void
disp_degree(Temp_elem_st *temp)
{
int	t;

	t = temp->degrees;
	t -= 20;	/* re-adjust */
	/*
	 * NL_Comment
	 * The %c is the degree symbol.
	 */
	(void) fprintf(stdout, ":%1.2d%cC ", t, 186);
}



/*
 * trans_decode() Display tranceivers state.
 *
 * RETURNS:
 *	none.
 */
void
trans_decode(Trans_elem_st *trans)
{
	if (trans->disabled) {
		(void) fprintf(stdout, ": ");
		(void) fprintf(stdout, MSGSTR(34,
			"Disabled"));
	}
	if (trans->lol) {
		(void) fprintf(stdout, MSGSTR(2133,
			": Not receiving a signal"));
	}
	if (trans->lsr_fail) {
		(void) fprintf(stdout, MSGSTR(2134,
			": Laser failed"));
	}
}



/*
 * trans_messages() Display tranceiver status.
 *
 * NOTE: The decoding of the status assumes that the elements
 * are in order with the first two elements are for the
 * "A" IB. It also assumes the tranceivers are numbered
 * 0 and 1.
 *
 * RETURNS:
 *	none.
 */
void
trans_messages(struct l_state_struct *l_state, int ib_a_flag)
{
Trans_elem_st	trans;
int	i, j, k;
int	count = 0;
int	elem_index = 0;

	/* Get and print messages */
	for (i = 0; i < (int)l_state->ib_tbl.config.enc_num_elem; i++) {
	    elem_index++;
	    if (l_state->ib_tbl.config.type_hdr[i].type == ELM_TYP_FL) {

		if (l_state->ib_tbl.config.type_hdr[i].text_len != 0) {
			(void) fprintf(stdout, "\n\t\t%s\n",
			l_state->ib_tbl.config.text[i]);
		}
		count = k = 0;

		for (j = 0; j <
			(int)l_state->ib_tbl.config.type_hdr[i].num; j++) {
			/*
			 * Only display the status for the selected IB.
			 */
		    if ((count < 2 && ib_a_flag) ||
				(count >= 2 && !ib_a_flag)) {
			(void) bcopy((const void *)
				&l_state->ib_tbl.p2_s.element[elem_index + j],
				(void *)&trans, sizeof (trans));

			if (k == 0) {
				(void) fprintf(stdout, "\t\t%d ", k);
			} else {
				(void) fprintf(stdout, "\n\t\t%d ", k);
			}
			if (trans.code == S_OK) {
				(void) fprintf(stdout,
				MSGSTR(29, "O.K."));
				revision_msg(l_state, elem_index + j);
			} else if ((trans.code == S_CRITICAL) ||
				(trans.code == S_NONCRITICAL)) {
				(void) fprintf(stdout,
				MSGSTR(2135, "Failed"));
				revision_msg(l_state, elem_index + j);
				trans_decode(&trans);
			} else if (trans.code == S_NOT_INSTALLED) {
				(void) fprintf(stdout,
				MSGSTR(30, "Not Installed"));
			} else if (trans.code == S_NOT_AVAILABLE) {
				(void) fprintf(stdout,
				MSGSTR(34, "Disabled"));
				revision_msg(l_state, elem_index + j);
			} else {
				(void) fprintf(stdout,
				MSGSTR(4, "Unknown status"));
			}
			k++;
		    }
		    count++;
		}
	    }
		/*
		 * Calculate the index to each element.
		 */
		elem_index += l_state->ib_tbl.config.type_hdr[i].num;
	}
	(void) fprintf(stdout, "\n");
}



/*
 * temperature_messages() Display temperature status.
 *
 * RETURNS:
 *	none.
 */
void
temperature_messages(struct l_state_struct *l_state, int rear_flag)
{
Temp_elem_st	temp;
int	i, j, last_ok = 0;
int	all_ok = 1;
int	elem_index = 0;

	/* Get and print messages */
	for (i = 0; i < (int)l_state->ib_tbl.config.enc_num_elem; i++) {
	    elem_index++;	/* skip global */
	    if (l_state->ib_tbl.config.type_hdr[i].type == ELM_TYP_TS) {
		if (!rear_flag) {
		rear_flag = 1;		/* only do front or rear backplane */
		if (l_state->ib_tbl.config.type_hdr[i].text_len != 0) {
			(void) fprintf(stdout, "\t  %s",
			l_state->ib_tbl.config.text[i]);
		}

		/*
		 * Check global status and if not all O.K.
		 * then print individually.
		 */
		(void) bcopy((const void *)&l_state->ib_tbl.p2_s.element[i],
			(void *)&temp, sizeof (temp));
		for (j = 0; j <
			(int)l_state->ib_tbl.config.type_hdr[i].num; j++) {
			(void) bcopy((const void *)
			&l_state->ib_tbl.p2_s.element[elem_index + j],
				(void *)&temp, sizeof (temp));

			if ((j == 0) && (temp.code == S_OK) &&
				(!(temp.ot_fail || temp.ot_warn ||
					temp.ut_fail || temp.ut_warn))) {
				(void) fprintf(stdout, "\n\t  %d", j);
			} else if ((j == 6) && (temp.code == S_OK) &&
				all_ok) {
				(void) fprintf(stdout, "\n\t  %d", j);
			} else if (last_ok && (temp.code == S_OK)) {
				(void) fprintf(stdout, "%d", j);
			} else {
				(void) fprintf(stdout, "\n\t\t%d", j);
			}
			if (temp.code == S_OK) {
				disp_degree(&temp);
				if (temp.ot_fail || temp.ot_warn ||
					temp.ut_fail || temp.ut_warn) {
					temp_decode(&temp);
					all_ok = 0;
					last_ok = 0;
				} else {
					last_ok++;
				}
			} else if (temp.code == S_CRITICAL) {
				(void) fprintf(stdout,
				MSGSTR(122, "Critical failure"));
				last_ok = 0;
				all_ok = 0;
			} else if (temp.code == S_NONCRITICAL) {
				(void) fprintf(stdout,
				MSGSTR(89, "Non-Critical Failure"));
				last_ok = 0;
				all_ok = 0;
			} else if (temp.code == S_NOT_INSTALLED) {
				(void) fprintf(stdout,
				MSGSTR(30, "Not Installed"));
				last_ok = 0;
				all_ok = 0;
			} else if (temp.code == S_NOT_AVAILABLE) {
				(void) fprintf(stdout,
				MSGSTR(34, "Disabled"));
				last_ok = 0;
				all_ok = 0;
			} else {
				(void) fprintf(stdout,
				MSGSTR(4, "Unknown status"));
				last_ok = 0;
				all_ok = 0;
			}
		}
		if (all_ok) {
			(void) fprintf(stdout,
			MSGSTR(2136, " (All temperatures are "
			"NORMAL.)"));
		}
		all_ok = 1;
		(void) fprintf(stdout, "\n");
	    } else {
		rear_flag = 0;
	    }
	    }
	    elem_index += l_state->ib_tbl.config.type_hdr[i].num;
	}
}



/*
 * ib_decode() Display IB byte 3 state.
 *
 * RETURNS:
 *	none.
 */
void
ib_decode(Ctlr_elem_st *ctlr)
{
	if (ctlr->overtemp_alart) {
		(void) fprintf(stdout, MSGSTR(2137,
			" - IB Over Temperature Alert "));
	}
	if (ctlr->ib_loop_1_fail) {
		(void) fprintf(stdout, MSGSTR(2138,
			" - IB Loop 1 has failed "));
	}
	if (ctlr->ib_loop_0_fail) {
		(void) fprintf(stdout, MSGSTR(2139,
			" - IB Loop 0 has failed "));
	}
}



/*
 * mb_messages() Display motherboard
 * (interconnect assembly) messages.
 *
 * RETURNS:
 *	none.
 */
void
mb_messages(struct l_state_struct *l_state, int index, int elem_index)
{
int		j;
Interconnect_st	interconnect;

	if (l_state->ib_tbl.config.type_hdr[index].text_len != 0) {
		(void) fprintf(stdout, "%s\n",
		l_state->ib_tbl.config.text[index]);
	}
	for (j = 0; j < (int)l_state->ib_tbl.config.type_hdr[index].num;
			j++) {
		(void) bcopy((const void *)
			&l_state->ib_tbl.p2_s.element[elem_index + j],
			(void *)&interconnect, sizeof (interconnect));
		(void) fprintf(stdout, "\t");

		if (interconnect.code == S_OK) {
			(void) fprintf(stdout,
			MSGSTR(29, "O.K."));
			revision_msg(l_state, elem_index + j);
		} else if (interconnect.code == S_NOT_INSTALLED) {
			(void) fprintf(stdout,
			MSGSTR(30, "Not Installed"));
		} else if (interconnect.code == S_CRITICAL) {
			if (interconnect.eprom_fail != 0) {
				(void) fprintf(stdout, MSGSTR(2140,
					"Critical Failure: EEPROM failure"));
			} else {
				(void) fprintf(stdout, MSGSTR(2141,
					"Critical Failure: Unknown failure"));
			}
			revision_msg(l_state, elem_index + j);
		} else if (interconnect.code == S_NONCRITICAL) {
			if (interconnect.eprom_fail != 0) {
				(void) fprintf(stdout, MSGSTR(2142,
				"Non-Critical Failure: EEPROM failure"));
			} else {
				(void) fprintf(stdout, MSGSTR(2143,
				"Non-Critical Failure: Unknown failure"));
			}
			revision_msg(l_state, elem_index + j);
		} else if (interconnect.code == S_NOT_AVAILABLE) {
			(void) fprintf(stdout,
			MSGSTR(34, "Disabled"));
			revision_msg(l_state, elem_index + j);
		} else {
			(void) fprintf(stdout,
			MSGSTR(4, "Unknown status"));
		}
		(void) fprintf(stdout, "\n");
	}


}



/*
 * back_plane_messages() Display back_plane messages
 * including the temperature's.
 *
 * RETURNS:
 *	none.
 */
void
back_plane_messages(struct l_state_struct *l_state, int index, int elem_index)
{
Bp_elem_st	bp;
int		j;
char		status_string[MAXPATHLEN];

	if (l_state->ib_tbl.config.type_hdr[index].text_len != 0) {
		(void) fprintf(stdout, "%s\n",
		l_state->ib_tbl.config.text[index]);
	}
	for (j = 0; j < (int)l_state->ib_tbl.config.type_hdr[index].num;
			j++) {
		(void) bcopy((const void *)
			&l_state->ib_tbl.p2_s.element[elem_index + j],
			(void *)&bp, sizeof (bp));
		if (j == 0) {
			(void) fprintf(stdout,
				MSGSTR(2144, "\tFront Backplane: "));
		} else {
			(void) fprintf(stdout,
				MSGSTR(2145, "\tRear Backplane:  "));
		}

		(void) l_element_msg_string(bp.code, status_string);
		(void) fprintf(stdout, "%s", status_string);

		if (bp.code != S_NOT_INSTALLED) {
			revision_msg(l_state, elem_index + j);
			if ((bp.byp_a_enabled || bp.en_bypass_a) &&
				!(bp.byp_b_enabled || bp.en_bypass_b)) {
				(void) fprintf(stdout, " (");
				(void) fprintf(stdout,
				MSGSTR(130, "Bypass A enabled"));
				(void) fprintf(stdout, ")");
			} else if ((bp.byp_b_enabled || bp.en_bypass_b) &&
				!(bp.byp_a_enabled || bp.en_bypass_a)) {
				(void) fprintf(stdout, " (");
				(void) fprintf(stdout,
				MSGSTR(129, "Bypass B enabled"));
				(void) fprintf(stdout, ")");
			/* This case covers where a and b are bypassed */
			} else if (bp.byp_b_enabled || bp.en_bypass_b) {
				(void) fprintf(stdout,
				MSGSTR(2146, " (Bypass's A & B enabled)"));
			}
			(void) fprintf(stdout, "\n");
			temperature_messages(l_state, j);
		} else {
			(void) fprintf(stdout, "\n");
		}
	}
}


/*
 * dpm_SSC100_messages() Display SSC100 messages
 * including the temperature's.
 *
 * RETURNS:
 *	none.
 */
void
dpm_SSC100_messages(struct l_state_struct *l_state, int index, int elem_index)
{
Bp_elem_st	bp;
int		j;
char		status_string[MAXPATHLEN];

	if (l_state->ib_tbl.config.type_hdr[index].text_len != 0) {
		(void) fprintf(stdout, "%s\n",
		l_state->ib_tbl.config.text[index]);
	}
	for (j = 0; j < (int)l_state->ib_tbl.config.type_hdr[index].num;
			j++) {
		(void) bcopy((const void *)
			&l_state->ib_tbl.p2_s.element[elem_index + j],
			(void *)&bp, sizeof (bp));
		(void) fprintf(stdout, MSGSTR(2246, "    SSC100 #%d:    "), j);

		(void) l_element_msg_string(bp.code, status_string);
		(void) fprintf(stdout, "%s", status_string);

		if (bp.code != S_NOT_INSTALLED) {
			revision_msg(l_state, elem_index + j);
			if ((bp.byp_a_enabled || bp.en_bypass_a) &&
				!(bp.byp_b_enabled || bp.en_bypass_b)) {
				(void) fprintf(stdout, " (");
				(void) fprintf(stdout,
				MSGSTR(130, "Bypass A enabled"));
				(void) fprintf(stdout, ")");
			} else if ((bp.byp_b_enabled || bp.en_bypass_b) &&
				!(bp.byp_a_enabled || bp.en_bypass_a)) {
				(void) fprintf(stdout, " (");
				(void) fprintf(stdout,
				MSGSTR(129, "Bypass B enabled"));
				(void) fprintf(stdout, ")");
			/* This case covers where a and b are bypassed */
			} else if (bp.byp_b_enabled || bp.en_bypass_b) {
				(void) fprintf(stdout,
				MSGSTR(2146, " (Bypass's A & B enabled)"));
			}
			(void) fprintf(stdout, "\n");
		} else {
			(void) fprintf(stdout, "\n");
		}
	}
	temperature_messages(l_state, 0);
}




/*
 * loop_messages() Display loop messages.
 *
 * RETURNS:
 *	none.
 */
void
loop_messages(struct l_state_struct *l_state, int index, int elem_index)
{
Loop_elem_st	loop;
int		j;

	if (l_state->ib_tbl.config.type_hdr[index].text_len != 0) {
		(void) fprintf(stdout, "%s\n",
		l_state->ib_tbl.config.text[index]);
	}
	for (j = 0; j < (int)l_state->ib_tbl.config.type_hdr[index].num;
			j++) {
		(void) bcopy((const void *)
			&l_state->ib_tbl.p2_s.element[elem_index + j],
			(void *)&loop, sizeof (loop));

		(void) fprintf(stdout, "\t");
		if (j == 0) {
			if (loop.code == S_NOT_INSTALLED) {
				(void) fprintf(stdout,
				MSGSTR(2147, "Loop A is not installed"));
			} else {
				if (loop.split) {
					(void) fprintf(stdout, MSGSTR(2148,
				"Loop A is configured as two separate loops."));
				} else {
					(void) fprintf(stdout, MSGSTR(2149,
				"Loop A is configured as a single loop."));
				}
			}
		} else {
			if (loop.code == S_NOT_INSTALLED) {
				(void) fprintf(stdout,
				MSGSTR(2150, "Loop B is not installed"));
			} else {
				if (loop.split) {
					(void) fprintf(stdout, MSGSTR(2151,
				"Loop B is configured as two separate loops."));
				} else {
					(void) fprintf(stdout, MSGSTR(2152,
				"Loop B is configured as a single loop."));
				}
			}
		}
		(void) fprintf(stdout, "\n");
	}
}



/*
 * ctlr_messages() Display ESI Controller status.
 *
 * RETURNS:
 *	none.
 */
void
ctlr_messages(struct l_state_struct *l_state, int index, int elem_index)
{
Ctlr_elem_st	ctlr;
int		j;
int		ib_a_flag = 1;

	if (l_state->ib_tbl.config.type_hdr[index].text_len != 0) {
		(void) fprintf(stdout, "%s\n",
		l_state->ib_tbl.config.text[index]);
	}
	for (j = 0; j < (int)l_state->ib_tbl.config.type_hdr[index].num;
			j++) {
		(void) bcopy((const void *)
			&l_state->ib_tbl.p2_s.element[elem_index + j],
			(void *)&ctlr, sizeof (ctlr));
		if (j == 0) {
			(void) fprintf(stdout, MSGSTR(2153, "\tA: "));
		} else {
			(void) fprintf(stdout, MSGSTR(2154, "\tB: "));
			ib_a_flag = 0;
		}
		if (ctlr.code == S_OK) {
			(void) fprintf(stdout, MSGSTR(29, "O.K."));
			/* If any byte 3 bits set display */
			ib_decode(&ctlr);
			/* Display Version message */
			revision_msg(l_state, elem_index + j);
			/*
			 * Display the tranciver module state for this
			 * IB.
			 */
			trans_messages(l_state, ib_a_flag);
		} else if (ctlr.code == S_CRITICAL) {
			(void) fprintf(stdout,
			MSGSTR(122, "Critical failure"));
			ib_decode(&ctlr);
			(void) fprintf(stdout, "\n");
		} else if (ctlr.code == S_NONCRITICAL) {
			(void) fprintf(stdout,
			MSGSTR(89, "Non-Critical Failure"));
			ib_decode(&ctlr);
			(void) fprintf(stdout, "\n");
		} else if (ctlr.code == S_NOT_INSTALLED) {
			(void) fprintf(stdout,
			MSGSTR(30, "Not Installed"));
			(void) fprintf(stdout, "\n");
		} else if (ctlr.code == S_NOT_AVAILABLE) {
			(void) fprintf(stdout,
			MSGSTR(34, "Disabled"));
			(void) fprintf(stdout, "\n");
		} else {
			(void) fprintf(stdout,
			MSGSTR(4, "Unknown status"));
			(void) fprintf(stdout, "\n");
		}
	}
}



/*
 * fan_decode() Display Fans bytes 1-3 state.
 *
 * RETURNS:
 *	none.
 */
void
fan_decode(Fan_elem_st *fan)
{
	if (fan->fail) {
		(void) fprintf(stdout, MSGSTR(2155,
			":Yellow LED is on"));
	}
	if (fan->speed == 0) {
		(void) fprintf(stdout, MSGSTR(2156,
			":Fan stopped"));
	} else if (fan->speed < S_HI_SPEED) {
		(void) fprintf(stdout, MSGSTR(2157,
			":Fan speed Low"));
	} else {
		(void) fprintf(stdout, MSGSTR(2158,
			":Fan speed Hi"));
	}
}

/*
 * fan_messages() Display Fan status.
 *
 * RETURNS:
 *	none.
 */
void
fan_messages(struct l_state_struct *l_state, int hdr_index, int elem_index)
{
Fan_elem_st	fan;
int	j;

	/* Get and print messages */
	if (l_state->ib_tbl.config.type_hdr[hdr_index].text_len != 0) {
		(void) fprintf(stdout, "%s\n",
		l_state->ib_tbl.config.text[hdr_index]);
	}
	for (j = 0; j < (int)l_state->ib_tbl.config.type_hdr[hdr_index].num;
			j++) {
		(void) bcopy((const void *)
			&l_state->ib_tbl.p2_s.element[elem_index + j],
			(void *)&fan, sizeof (fan));
		(void) fprintf(stdout, "\t%d ", j);
		if (fan.code == S_OK) {
			(void) fprintf(stdout, MSGSTR(29, "O.K."));
			revision_msg(l_state, elem_index + j);
		} else if (fan.code == S_CRITICAL) {
			(void) fprintf(stdout,
			MSGSTR(122, "Critical failure"));
			fan_decode(&fan);
			revision_msg(l_state, elem_index + j);
		} else if (fan.code == S_NONCRITICAL) {
			(void) fprintf(stdout,
			MSGSTR(89, "Non-Critical Failure"));
			fan_decode(&fan);
			revision_msg(l_state, elem_index + j);
		} else if (fan.code == S_NOT_INSTALLED) {
			(void) fprintf(stdout,
			MSGSTR(30, "Not Installed"));
		} else if (fan.code == S_NOT_AVAILABLE) {
			(void) fprintf(stdout,
			MSGSTR(34, "Disabled"));
			revision_msg(l_state, elem_index + j);
		} else {
			(void) fprintf(stdout,
			MSGSTR(4, "Unknown status"));
		}
	}
	(void) fprintf(stdout, "\n");
}



/*
 * ps_decode() Display Power Supply bytes 1-3 state.
 *
 * RETURNS:
 *	none.
 */
void
ps_decode(Ps_elem_st *ps)
{
	if (ps->dc_over) {
		(void) fprintf(stdout, MSGSTR(2159,
			": DC Voltage too high"));
	}
	if (ps->dc_under) {
		(void) fprintf(stdout, MSGSTR(2160,
			": DC Voltage too low"));
	}
	if (ps->dc_over_i) {
		(void) fprintf(stdout, MSGSTR(2161,
			": DC Current too high"));
	}
	if (ps->ovrtmp_fail || ps->temp_warn) {
		(void) fprintf(stdout, MSGSTR(2162,
			": Temperature too high"));
	}
	if (ps->ac_fail) {
		(void) fprintf(stdout, MSGSTR(2163,
			": AC Failed"));
	}
	if (ps->dc_fail) {
		(void) fprintf(stdout, MSGSTR(2164,
			": DC Failed"));
	}
}



/*
 * revision_msg() Print the revision message from page 7.
 *
 * RETURNS:
 *	none.
 */
void
revision_msg(struct l_state_struct *l_state, int index)
{
	if (strlen((const char *)
		l_state->ib_tbl.p7_s.element_desc[index].desc_string)) {
		(void) fprintf(stdout, "(%s)",
		l_state->ib_tbl.p7_s.element_desc[index].desc_string);
	}
}



/*
 * ps_messages() Display Power Supply status.
 *
 * RETURNS:
 *	none.
 */
void
ps_messages(struct l_state_struct *l_state, int	index, int elem_index)
{
Ps_elem_st	ps;
int	j;

	/* Get and print Power Supply messages */

	if (l_state->ib_tbl.config.type_hdr[index].text_len != 0) {
		(void) fprintf(stdout, "%s\n",
		l_state->ib_tbl.config.text[index]);
	}

	for (j = 0; j < (int)l_state->ib_tbl.config.type_hdr[index].num;
		j++) {
		(void) bcopy((const void *)
			&l_state->ib_tbl.p2_s.element[elem_index + j],
			(void *)&ps, sizeof (ps));
		(void) fprintf(stdout, "\t%d ", j);
		if (ps.code == S_OK) {
			(void) fprintf(stdout, MSGSTR(29, "O.K."));
			revision_msg(l_state, elem_index + j);
		} else if (ps.code == S_CRITICAL) {
			(void) fprintf(stdout,
			MSGSTR(122, "Critical failure"));
			ps_decode(&ps);
			revision_msg(l_state, elem_index + j);
		} else if (ps.code == S_NONCRITICAL) {
			(void) fprintf(stdout,
			MSGSTR(89, "Non-Critical Failure"));
			ps_decode(&ps);
			revision_msg(l_state, elem_index + j);
		} else if (ps.code == S_NOT_INSTALLED) {
			(void) fprintf(stdout,
			MSGSTR(30, "Not Installed"));
		} else if (ps.code == S_NOT_AVAILABLE) {
			(void) fprintf(stdout,
			MSGSTR(34, "Disabled"));
			revision_msg(l_state, elem_index + j);
		} else {
			(void) fprintf(stdout,
			MSGSTR(4, "Unknown status"));
		}

	}
	(void) fprintf(stdout, "\n");
}



/*
 * abnormal_condition() Display any abnormal condition messages.
 *
 * RETURNS:
 *	none.
 */
void
abnormal_condition_display(struct l_state_struct *l_state)
{

	(void) fprintf(stdout, "\n");
	if (l_state->ib_tbl.p2_s.ui.crit) {
		(void) fprintf(stdout,
			MSGSTR(2165, "                         "
			"CRITICAL CONDITION DETECTED\n"));
	}
	if (l_state->ib_tbl.p2_s.ui.non_crit) {
		(void) fprintf(stdout,
			MSGSTR(2166, "                   "
			"WARNING: NON-CRITICAL CONDITION DETECTED\n"));
	}
	if (l_state->ib_tbl.p2_s.ui.invop) {
		(void) fprintf(stdout,
			MSGSTR(2167, "                      "
			"WARNING: Invalid Operation bit set.\n"
			"\tThis means an Enclosure Control page"
			" or an Array Control page with an invalid\n"
			"\tformat has previously been transmitted to the"
			" Enclosure Services card by a\n\tSend Diagnostic"
			" SCSI command.\n"));
	}
	(void) fprintf(stdout, "\n");
}





/*
 * adm_start() Spin up the given list
 * of SENA devices.
 *
 * RETURNS:
 *	none.
 */
int
adm_start(char **argv)
{
char		*path_phys = NULL;
Path_struct	*path_struct;
int		err = 0, retval = 0;

	while (*argv != NULL) {
		if ((err = l_convert_name(*argv, &path_phys,
			&path_struct, Options & PVERBOSE)) != 0) {
			(void) fprintf(stderr, MSGSTR(33,
				" Error: converting"
				" %s to physical path.\n"
				" Invalid pathname.\n"),
				*argv);
		if (err != -1) {
			(void) print_errString(err, *argv);
		}
		(argv)++;
		retval++;
		continue;
	    }
	    VERBPRINT(MSGSTR(101, "Issuing start to:\n %s\n"), *argv);
	    if (err = g_start(path_phys))  {
		(void) print_errString(err, *argv);
		(argv)++;
		retval++;
		continue;
	    }
	    (argv)++;
	}
	return (retval);
}



/*
 * adm_stop() Spin down a
 * given list of SENA devices.
 *
 * RETURNS:
 *	none.
 */
int
adm_stop(char **argv)
{
char		*path_phys = NULL;
Path_struct	*path_struct;
int		err = 0, retval = 0;

	while (*argv != NULL) {
		if ((err = l_convert_name(*argv, &path_phys,
		    &path_struct, Options & PVERBOSE)) != 0) {
			(void) fprintf(stderr,
			    MSGSTR(33,
			    " Error: converting"
			    " %s to physical path.\n"
			    " Invalid pathname.\n"),
			    *argv);
			if (err != -1) {
				(void) print_errString(err, *argv);
			}
			(argv)++;
			retval++;
			continue;
		}

		/*
		 * scsi stop is not supported for tape drives.
		 * The scsi unload op code for tape is the same as a
		 * scsi stop for disk so this command will eject the tape.
		 * If an eject is the desired behavior then remove the
		 * following if block. ('mt offline' will give you
		 * the same eject functionality).
		 */
		if (strstr(path_phys, SLSH_DRV_NAME_ST)) {
			errno = ENOTSUP;
			(void) print_errString(0, path_phys);
			(argv)++;
			continue;
		}

		VERBPRINT(MSGSTR(100, "Issuing stop to:\n %s\n"), *argv);
			if (err = g_stop(path_phys, 1))  {
			(void) print_errString(err, *argv);
			(argv)++;
			retval++;
			continue;
		}
		(argv)++;
	}
	return (retval);
}


/*
 * On a SOC+ chip, the port is either put into (offline) or pulled out
 * of (online) a loopback mode since the laser cannot be turned on or off.
 * As of this writing, this feature is yet to be supported by the ifp
 * driver on a QLogic card.
 *
 * INPUT :
 *	Command line args and flag - LUX_P_ONLINE or LUX_P_OFFLINE
 *	The path that is passed has to be the physical path to the port.
 *	For example :
 *	/devices/sbus@2,0/SUNW,socal@2,0:0
 *	/devices/io-unit@f,e0200000/sbi@0,0/SUNW,socal@2,0:0
 *	/devices/pci@1f,4000/SUNW,ifp@2:devctl
 * RETURNS :
 *	Nothing
 */
int
adm_port_offline_online(char *argv[], int flag)
{
	int		err, retval = 0;
	char		*path_phys = NULL;
	char		*nexus_path_ptr = NULL;
	Path_struct	*path_struct = NULL;

	while (*argv != NULL) {
		if ((err = l_convert_name(*argv, &path_phys,
			&path_struct, Options & PVERBOSE)) != 0) {
			(void) fprintf(stderr,
				MSGSTR(33,
					" Error: converting"
					" %s to physical path.\n"
					" Invalid pathname.\n"),
				*argv);
			if (err != -1) {
				(void) print_errString(err, *argv);
			}
			argv++;
			retval++;
			continue;
		}

		/* Get the nexus path - need this to print messages */
		if ((err = g_get_nexus_path(path_phys, &nexus_path_ptr)) != 0) {
			(void) print_errString(err, *argv);
			retval++;
			goto cleanup_and_go;
		}

		if (flag == LUX_P_OFFLINE) {
			if ((err = g_port_offline(nexus_path_ptr))) {
				(void) print_errString(err, nexus_path_ptr);
				retval++;
				goto cleanup_and_go;
			}
			fprintf(stdout,
				MSGSTR(2223, "Port %s has been disabled\n"),
					nexus_path_ptr);
		} else if (flag == LUX_P_ONLINE) {
			if ((err = g_port_online(nexus_path_ptr))) {
				(void) print_errString(err, nexus_path_ptr);
				retval++;
				goto cleanup_and_go;
			}
			fprintf(stdout,
				MSGSTR(2224, "Port %s has been enabled\n"),
					nexus_path_ptr);
		} else {
			(void) fprintf(stderr,
					MSGSTR(2225,
					"Unknown action requested "
					"on port - %d\nIgnoring."),
					flag);
			retval++;
		}
cleanup_and_go:
		free(path_phys);
		free(path_struct);
		free(nexus_path_ptr);
		argv++;
	}
	return (retval);
}

/*
 * Expert level subcommand 'luxadm -e port'
 * which displays all FC ports on a host and state information for
 * connectivity (CONNECTED or NOT CONNECTED) indicating whether there
 * are devices attached to the port.
 *
 * Sample output for ifp:
 *
 * /devices/pci@1f,4000/SUNW,ifp@2:devctl		CONNECTED
 * /devices/pci@1f,2000/SUNW,ifp@1:devctl		NOT CONNECTED
 *
 * Sample output for socal:
 *
 * /devices/sbus@2,0/SUNW,socal@d,10000:0               CONNECTED
 * /devices/sbus@2,0/SUNW,socal@d,10000:1               NOT CONNECTED
 * /devices/sbus@2,0/SUNW,socal@2,0:0                   NOT CONNECTED
 * /devices/sbus@2,0/SUNW,socal@2,0:1                   CONNECTED
 *
 * Note: for socal the path returned is not a devctl path as there is no
 * devctl path for socal.
 *
 * Sample output for fp:
 *
 * /devices/sbus@2,0/SUNW,qlc@5/fp@0,0:devctl        CONNECTED
 * /devices/sbus@2,0/SUNW,qlc@4/fp@1,0:devctl        CONNECTED
 */
int
adm_display_port(int verbose)
{
	/*
	 * If another port driver needs to be searched, add it here
	 */
	static char *portdrvr_list[] = {"socal",
					"fp",
					"ifp",
					NULL};
	portlist_t portlist;
	int x = 0, err = 0, retval = 0;
	int port_state;

	portlist.hbacnt = 0;

	/*
	 * Look for all HBA ports as listed in portdrvr_list[]
	 */
	while (portdrvr_list[x]) {
		if (err = g_get_port_path(portdrvr_list[x], &portlist)) {
			if (err != L_PORT_DRIVER_NOT_FOUND &&
			    err != L_PHYS_PATH_NOT_FOUND) {
				(void) print_errString(err, portdrvr_list[x]);
				retval++;
			}
		}
		x++;
	}


	/*
	 * For each port path found get the connection state.
	 * If there are devices attached the state is considered connected.
	 */
	for (x = 0; x < portlist.hbacnt; x++) {
		if (err = g_get_port_state(portlist.physpath[x],
			    &port_state, verbose)) {
			(void) print_errString(err, portlist.physpath[x]);
			retval++;
		} else {
			fprintf(stdout, "%-65s  ", portlist.physpath[x]);
			if (port_state == PORT_CONNECTED) {
				(void) fprintf(stdout,
						MSGSTR(2233,
						"CONNECTED\n"));
			} else {
				(void) fprintf(stdout,
						MSGSTR(2234,
						"NOT CONNECTED\n"));
			}
		}
	}
	g_free_portlist(&portlist);
	return (retval);
}

/*
 * Expert level subcommand 'luxadm -e external_loopback <portpath>
 *				      internal_loopback
 *				      no_loopback
 * Does just what you would think. Sets port in designated loopback
 * mode.
 * INPUT:  portpath - path to device on which to set loopback mode
 *	   flag     - loopback mode to set. Values are:
 *			EXT_LOOPBACK
 *			INT_LOOPBACK
 *			NO_LOOPBACK
 *
 * RETURN: 0 on success
 *         non-zero on failure
 */
int
adm_port_loopback(char *portpath, int flag)
{
	int		err;
	char		*path_phys = NULL;
	Path_struct	*path_struct = NULL;
	int		cmd;

	if ((err = l_convert_name(portpath, &path_phys,
		&path_struct, Options & PVERBOSE)) != 0) {
		(void) fprintf(stderr,
			MSGSTR(33,
				" Error: converting"
				" %s to physical path.\n"
				" Invalid pathname.\n"),
			portpath);
		if (err != -1) {
			(void) print_errString(err, portpath);
		}
		return (-1);
	}

	switch (flag) {
		case EXT_LOOPBACK:
			cmd = EXT_LPBACK;
			break;
		case INT_LOOPBACK:
			cmd = INT_LPBACK;
			break;
		case NO_LOOPBACK:
			cmd = NO_LPBACK;
			break;
		default:
			(void) fprintf(stderr,
					MSGSTR(2225,
					"Unknown action requested "
					"on port - %d\nIgnoring."),
					flag);
			free(path_phys);
			free(path_struct);
			return (-1);
	}


	if ((err = g_loopback_mode(path_phys, cmd)) != 0) {
		(void) print_errString(err, portpath);
		free(path_phys);
		free(path_struct);
		return (-1);
	} else {
		switch (flag) {
			case EXT_LOOPBACK:
				(void) fprintf(stdout,
						MSGSTR(2230,
						"External loopback mode set "
						"on:\n%s\n"),
						portpath);
				break;
			case INT_LOOPBACK:
				(void) fprintf(stdout,
						MSGSTR(2231,
						"Internal loopback mode set "
						"on:\n%s\n"),
						portpath);
				break;
			case NO_LOOPBACK:
				(void) fprintf(stdout,
						MSGSTR(2232,
						"Loopback mode unset "
						"on:\n%s\n"),
						portpath);
				break;
			default:
				fprintf(stderr,
					MSGSTR(2248, "Undefined command\n"));
				break;
		}
	}
	free(path_phys);
	free(path_struct);
	return (0);
}



/*
 * To print the pathlist and mpxio path attributes
 */
void
adm_print_pathlist(char *dev_path)
{
	int		i, pathcnt = 1;
	mp_pathlist_t	pathlist;
	int		retval = 0;
	char		temppath[MAXPATHLEN];
	char		wwns[(WWN_SIZE *2) +1];
	uchar_t		wwn_data[WWN_SIZE];
	int		err;
	int		state, ext_state = 0;
	char	*path_state[5];

	path_state[0] = MSGSTR(2400, "INIT");
	path_state[1] = MSGSTR(2401, "ONLINE");
	path_state[2] = MSGSTR(2402, "STANDBY");
	path_state[3] = MSGSTR(2403, "FAULT");
	path_state[4] = MSGSTR(2404, "OFFLINE");

	(void) strcpy(temppath, dev_path);
	retval = g_get_pathlist(temppath, &pathlist);
	if (retval != 0) {
		(void) print_errString(retval, NULL);
		exit(-1);
	}
	pathcnt = pathlist.path_count;
	for (i = 0; i < pathcnt; i++) {
		(void) fprintf(stdout,
		MSGSTR(2303, "   Controller      \t%s\n"),
			pathlist.path_info[i].path_hba);

		(void) fprintf(stdout,
		MSGSTR(2304, "    Device Address\t\t%s\n"),
			pathlist.path_info[i].path_addr);

		if ((err = get_host_controller_pwwn(
				pathlist.path_info[i].path_hba,
				(uchar_t *)&wwn_data)) != 0) {
			if (err != ENOTSUP) {
				(void) print_errString(err,
					pathlist.path_info[i].path_hba);
				exit(1);
			}
		}

		if (!err) {
			copy_wwn_data_to_str(wwns, wwn_data);
			(void) fprintf(stdout,
			    MSGSTR(2326, "    Host controller port WWN\t%s\n"),
				wwns);
		}

		(void) fprintf(stdout,
		MSGSTR(2305, "    Class\t\t\t%s\n"),
			pathlist.path_info[i].path_class);
		if (pathlist.path_info[i].path_state < MAXPATHSTATE) {
			(void) fprintf(stdout,
			MSGSTR(2306, "    State\t\t\t%s\n"),
			path_state[pathlist.path_info[i].path_state]);
		}
		if ((err = g_stms_get_path_state(dev_path,
				pathlist.path_info[i].path_hba, &state,
				&ext_state)) != 0) {
			(void) print_errString(err,
				pathlist.path_info[i].path_hba);
			exit(1);
		} else {
			if ((ext_state & MDI_PATHINFO_STATE_USER_DISABLE)
				== MDI_PATHINFO_STATE_USER_DISABLE) {
				ext_state = 0;
				fprintf(stdout,
				MSGSTR(2327,
				"    I/Os disabled on this %s path\n\n"),
				path_state[pathlist.path_info[i].path_state]);
			}
		}
	}
	/* Free memory for per path info properties */
	free(pathlist.path_info);
}

/*
 * compare_multipath
 * compares path with all paths in pathlist
 * If there is a match, 0 is returned, otherwise 1 is returned
 */
int
compare_multipath(char *path, struct mplist_struct *pathlist)
{

	while (pathlist != NULL) {
		if (strncmp(path, pathlist->devpath, MAXPATHLEN) == 0) {
			return (0);
		}
		pathlist = pathlist->next;
	}
	return (1);
}

/*
 * lun_display() Prints the
 * information for an individual lun.
 *
 * RETURNS:
 *	none.
 */
static int
lun_display(Path_struct *path_struct, L_inquiry inq_struct, int verbose)
{

char			phys_path[MAXPATHLEN], last_logical_path[MAXPATHLEN];
uchar_t			*pg_buf = NULL;
L_disk_state		l_disk_state;
struct dlist		*mlist;
int			offset, mode_data_avail, err = 0;
Mode_header_10		*mode_header_ptr;
struct mode_page	*pg_hdr;
WWN_list		*wwn_list, *list_start, *wwn_list_ptr;
WWN_list		*wwn_list_find;
int			found = 0;
int			argpwwn = 0, argnwwn = 0;
struct mplist_struct	*mplistp, *mpl, *mpln;
struct dlist		*dlist;



	strcpy(phys_path, path_struct->p_physical_path);
	strcpy(last_logical_path, phys_path);

	mplistp = mpl = mpln = (struct mplist_struct *)NULL;
	/*
	 * Get path to all the FC disk and tape devices.
	 * If there is no slash in the argument in this routine, we assume
	 * it is a wwn argument.
	 */
	if (strstr(path_struct->argv, "/") != NULL) {
		if ((err = g_devices_get_all(&wwn_list)) != 0) {
			return (err);
		}
	} else {
		if ((err = g_get_wwn_list(&wwn_list, verbose)) != 0) {
			return (err);
		}
	}

	g_sort_wwn_list(&wwn_list);

	list_start = wwn_list;

	for (wwn_list_ptr = wwn_list; wwn_list_ptr != NULL;
		wwn_list_ptr = wwn_list_ptr->wwn_next) {
		if (strcasecmp(wwn_list_ptr->port_wwn_s,
			path_struct->argv) == 0) {
			list_start = wwn_list_ptr;
			argpwwn = 1;
			break;
		} else if (strcasecmp(wwn_list_ptr->node_wwn_s,
			path_struct->argv) == 0) {
			list_start = wwn_list_ptr;
			argnwwn = 1;
			break;
		}
	}

	for (wwn_list_ptr = list_start; wwn_list_ptr != NULL;
		wwn_list_ptr = wwn_list_ptr->wwn_next) {


	if (argpwwn) {
		if (strcasecmp(wwn_list_ptr->port_wwn_s,
			path_struct->argv) != 0) {
			continue;
		}
		(void) strcpy(phys_path, wwn_list_ptr->physical_path);
	} else if (argnwwn) {
		if (strstr(wwn_list_ptr->logical_path,
			last_logical_path) != NULL) {
			continue;
		}
		if (strcasecmp(wwn_list_ptr->node_wwn_s,
			path_struct->argv) != 0) {
			continue;
		}
		(void) strcpy(phys_path, wwn_list_ptr->physical_path);
		(void) strcpy(last_logical_path,
			wwn_list_ptr->logical_path);
	}

	if (argnwwn || argpwwn) {
		if (compare_multipath(wwn_list_ptr->logical_path,
			mplistp) == 0) {
			continue;
		}
	}

	mode_data_avail = 0;

	(void) memset(&l_disk_state, 0, sizeof (struct l_disk_state_struct));

	/*
	 * Don't call g_get_multipath if this is a SCSI_VHCI device
	 * dlist gets alloc'ed here to retain the free at the end
	 */
	if (strstr(phys_path, SCSI_VHCI) == NULL) {
		if ((err = g_get_multipath(phys_path,
				    &(l_disk_state.g_disk_state.multipath_list),
				    wwn_list, verbose)) != 0) {
			return (err);
		}

		mlist = l_disk_state.g_disk_state.multipath_list;
		if (mlist == NULL) {
			l_disk_state.l_state_flag = L_NO_PATH_FOUND;
			N_DPRINTF(" lun_display: Error finding"
			    " multiple paths to the disk.\n");
			(void) g_free_wwn_list(&wwn_list);
			return (L_NO_VALID_PATH);
		}
	} else {
		/* Search for match on physical path name */
		for (wwn_list_find = list_start; wwn_list_find != NULL;
		    wwn_list_find = wwn_list_find->wwn_next) {
			if (strncmp(wwn_list_find->physical_path, phys_path,
				    strlen(wwn_list_find->physical_path))
				    == 0) {
				found++;
				break;
			}
		}

		if (!found) {
			return (L_NO_VALID_PATH);
		} else {
			found = 0;
		}

		if ((dlist = (struct dlist *)
			    calloc(1, sizeof (struct dlist))) == NULL) {
			    return (L_MALLOC_FAILED);
		}
		if ((dlist->logical_path = (char *)calloc(1,
			    strlen(wwn_list_find->logical_path) + 1)) == NULL) {
			return (L_MALLOC_FAILED);
		}
		if ((dlist->dev_path = (char *)calloc(1,
			    strlen(phys_path) + 1)) == NULL) {
			return (L_MALLOC_FAILED);
		}
		strncpy(dlist->logical_path, wwn_list_find->logical_path,
		    strlen(wwn_list_find->logical_path));
		strncpy(dlist->dev_path, phys_path, strlen(phys_path));
		l_disk_state.g_disk_state.multipath_list = dlist;
	}

	if (argnwwn || argpwwn) {
		for (mlist = l_disk_state.g_disk_state.multipath_list;
		    mlist != NULL; mlist = mlist->next) {
			/* add the path to the list for compare */
			if ((mpl = (struct mplist_struct *)
				    calloc(1, sizeof (struct mplist_struct)))
			    == NULL) {
				adm_mplist_free(mplistp);
				return (L_MALLOC_FAILED);
			}

			mpl->devpath = (char *)calloc(1, MAXPATHLEN+1);
			if (mpl->devpath == NULL) {
				adm_mplist_free(mplistp);
				return (L_MALLOC_FAILED);
			}
			strncpy(mpl->devpath, mlist->logical_path,
			    strlen(mlist->logical_path));
			if (mplistp == NULL) {
				mplistp = mpln = mpl;
			} else {
				mpln->next = mpl;
				mpln = mpl;
			}
		}
	}

	/* get mode page information for FC device */
	if (l_get_mode_pg(phys_path, &pg_buf, verbose) == 0) {
		mode_header_ptr = (struct mode_header_10_struct *)
					(void *)pg_buf;
		offset = sizeof (struct mode_header_10_struct) +
			mode_header_ptr->bdesc_length;
		pg_hdr = (struct mode_page *)&pg_buf[offset];

		while (offset < (mode_header_ptr->length +
			sizeof (mode_header_ptr->length)) &&
						!mode_data_avail) {
			if (pg_hdr->code == MODEPAGE_CACHING) {
				mode_data_avail++;
				break;
			}
			offset += pg_hdr->length + sizeof (struct mode_page);
			pg_hdr = (struct mode_page *)&pg_buf[offset];
		}
	}

	switch ((inq_struct.inq_dtype & DTYPE_MASK)) {
	case DTYPE_DIRECT:
	    fprintf(stdout, MSGSTR(121, "DEVICE PROPERTIES for disk: %s\n"),
		path_struct->argv);
	    break;
	case DTYPE_SEQUENTIAL: /* Tape */
	    fprintf(stdout, MSGSTR(2249, "DEVICE PROPERTIES for tape: %s\n"),
		path_struct->argv);
	    break;
	default:
	    fprintf(stdout, MSGSTR(2250, "DEVICE PROPERTIES for: %s\n"),
		path_struct->argv);
	    break;
	}

	(void) display_lun_info(l_disk_state, path_struct, pg_hdr,
			mode_data_avail, wwn_list, phys_path);

	(void) g_free_multipath(l_disk_state.g_disk_state.multipath_list);

	if (!(argpwwn || argnwwn)) {
		break;
	}

	} /* End for wwn_list_ptr = list_start... */

	(void) g_free_wwn_list(&wwn_list);
	adm_mplist_free(mplistp);
	return (0);
}

/*
 * display_lun_info() Prints the device specific information
 * for a lun.
 *
 * RETURNS:
 *	none.
 */
void
display_lun_info(L_disk_state l_disk_state, Path_struct *path_struct,
		struct mode_page *pg_hdr, int mode_data_avail, WWN_list
		*wwn_list, char *phys_path)
{
float		lunMbytes;
struct scsi_capacity_16 cap_data;
struct dlist	*mlist;
struct	my_mode_caching	*pg8_buf;
int		err;
L_inquiry	inq;
hrtime_t	start_time, end_time;
char		*envdb = NULL;
int		peripheral_qual;
L_inquiry80	inq80;
size_t		serial_len = sizeof (inq80.inq_serial);

	if ((envdb = getenv("_LUX_T_DEBUG")) != NULL) {
		start_time = gethrtime();
	}

	memset(&cap_data, 0, sizeof (cap_data));

	if (err = g_get_inquiry(phys_path, &inq)) {
	    fprintf(stderr, "\n");
	    print_errString(err, phys_path);
	    fprintf(stderr, "\n");
	    exit(1);
	}

	if (err = g_get_serial_number(phys_path, inq80.inq_serial,
	    &serial_len)) {
		fprintf(stderr, "\n");
		print_errString(err, phys_path);
		fprintf(stderr, "\n");
		exit(1);
	}
	/*
	 * check to see if the peripheral qualifier is zero
	 * if it is non-zero, we will return with an error.
	 */
	peripheral_qual = inq.inq_dtype & ~DTYPE_MASK;
	if (peripheral_qual != DPQ_POSSIBLE) {
		fprintf(stderr, MSGSTR(2254, "\n Error: Logical Unit "
			    "(%s) is not available.\n"), phys_path);
		exit(1);
	}

	fprintf(stdout, "  ");
	fprintf(stdout, MSGSTR(3, "Vendor:"));
	fprintf(stdout, "\t\t");
	print_chars(inq.inq_vid, sizeof (inq.inq_vid), 0);
	fprintf(stdout, MSGSTR(2115, "\n  Product ID:\t\t"));
	print_chars(inq.inq_pid, sizeof (inq.inq_pid), 0);

	fprintf(stdout, "\n  ");
	fprintf(stdout, MSGSTR(2119, "Revision:"));
	fprintf(stdout, "\t\t");
	print_chars(inq.inq_revision, sizeof (inq.inq_revision), 0);

	fprintf(stdout, "\n  ");
	fprintf(stdout, MSGSTR(17, "Serial Num:"));
	fprintf(stdout, "\t\t");
	print_chars(inq80.inq_serial, serial_len, 0);

	if ((inq.inq_dtype & DTYPE_MASK) == DTYPE_DIRECT) {
		if ((err = get_lun_capacity(phys_path, &cap_data)) != 0) {
			print_errString(err, phys_path);
			exit(1);
		}

		if (cap_data.sc_capacity > 0 && cap_data.sc_lbasize > 0) {
			lunMbytes = cap_data.sc_capacity + 1;
			lunMbytes *= cap_data.sc_lbasize;
			lunMbytes /= (float)(1024*1024);
			fprintf(stdout, "\n  ");
			fprintf(stdout, MSGSTR(60,
			"Unformatted capacity:\t%6.3f MBytes"), lunMbytes);
		}
	}

	fprintf(stdout, "\n");

	if ((mode_data_avail) && (pg_hdr->code == MODEPAGE_CACHING)) {
		pg8_buf = (struct my_mode_caching *)(void *)pg_hdr;
		if (pg8_buf->wce) {
			fprintf(stdout, MSGSTR(2122, "  Write Cache:\t\t"
				"Enabled\n"));
		}
		if (pg8_buf->rcd == 0) {
			fprintf(stdout, MSGSTR(2123, "  Read Cache:\t\t"
				"Enabled\n"));
			fprintf(stdout, MSGSTR(2124, "    Minimum prefetch:"
				"\t0x%x\n    Maximum prefetch:\t0x%x\n"),
				pg8_buf->min_prefetch,
				pg8_buf->max_prefetch);
		}
	}

	fprintf(stdout, "  %s\t\t%s\n", MSGSTR(35, "Device Type:"),
			dtype[inq.inq_dtype & DTYPE_MASK]);


	fprintf(stdout, MSGSTR(2128, "  Path(s):\n"));
	fprintf(stdout, "\n");

	if ((mlist = l_disk_state.g_disk_state.multipath_list) == NULL) {
		fprintf(stderr, MSGSTR(2323, "Error: No paths found (%s)"),
			path_struct->argv);
		exit(1);
	}


	if (strstr(mlist->dev_path, SCSI_VHCI) != NULL) {
		fprintf(stdout, "  %s\n  %s\n",
			mlist->logical_path, mlist->dev_path);
		adm_print_pathlist(mlist->dev_path);
	} else {
		/*
		 * first display user's requested path
		 * This will avoid duplicate inquiries as well
		 */
		for (mlist = l_disk_state.g_disk_state.multipath_list;
			mlist != NULL; mlist = mlist->next) {
		    if ((strcmp(mlist->dev_path, path_struct->p_physical_path))
				== 0) {
			display_path_info(mlist->dev_path, mlist->logical_path,
				wwn_list);
			break;
		    }
		}

		/*
		 * Now display rest of paths
		 * skipping one already displayed
		 */
		for (mlist = l_disk_state.g_disk_state.multipath_list;
			mlist != NULL; mlist = mlist->next) {
		    if ((strcmp(mlist->dev_path, path_struct->p_physical_path))
				== 0) {
			continue;
		    }
		    if (err = g_get_inquiry(mlist->dev_path, &inq)) {
			fprintf(stderr, "\n");
			print_errString(err, mlist->dev_path);
			fprintf(stderr, "\n");
			exit(1);
		    }
		    display_path_info(mlist->dev_path, mlist->logical_path,
				wwn_list);
		}
	}
	fprintf(stdout, "\n");

	if (envdb != NULL) {
		end_time = gethrtime();
		fprintf(stdout, "      display_lun_info: "
		"\t\tTime = %lld millisec\n",
		(end_time - start_time)/1000000);
	}
}

/*
 * display_path_info() Prints the path specific information
 * for a lun.
 * Note: Only applies to ssd nodes currently
 *
 * RETURNS:
 *	none.
 */
static void
display_path_info(char *devpath, char *logicalpath, WWN_list *wwn_list)
{
WWN_list	*wwn_list_walk;
int		err;
uchar_t		wwn_data[WWN_SIZE];
char		wwns[(WWN_SIZE *2) +1];
char		drvr_path[MAXPATHLEN];
char		*cptr;
int		status;

	fprintf(stdout, "  %s\n", logicalpath);
	fprintf(stdout, "  %s\n", devpath);
	fprintf(stdout, "    %s\t\t", MSGSTR(2321, "LUN path port WWN:"));

	/*
	 * Walk the wwn list passed in and print the
	 * port wwn matching the device path
	 */
	for (wwn_list_walk = wwn_list; wwn_list_walk != NULL;
		wwn_list_walk = wwn_list_walk->wwn_next) {
		if (strcmp(wwn_list_walk->physical_path, devpath) == 0) {
			fprintf(stdout, "%s", wwn_list_walk->port_wwn_s);
			break;
		}
	}
	/*
	 * newline here in case port wwn not found
	 */
	fprintf(stdout, "\n");

	drvr_path[0] = '\0';
	(void) strcat(drvr_path, devpath);
	if (((cptr = strstr(drvr_path, SLSH_DRV_NAME_SSD)) != NULL) ||
		((cptr = strstr(drvr_path, SLSH_DRV_NAME_ST)) != NULL)) {;
		*cptr = '\0';
	} else {
		fprintf(stderr, MSGSTR(2324, "Error: Incorrect path (%s)\n"),
				drvr_path);
		exit(1);
	}
	*cptr = '\0';

	if ((err = get_host_controller_pwwn(drvr_path,
			(uchar_t *)&wwn_data)) != 0) {
		print_errString(err, drvr_path);
		exit(1);
	}

	copy_wwn_data_to_str(wwns, wwn_data);
	fprintf(stdout, "    %s\t%s\n",
		MSGSTR(2322, "Host controller port WWN:"), wwns);

	/*
	 * Determine path status
	 */
	if ((err = get_path_status(devpath, &status)) != 0) {
		print_errString(err, devpath);
		exit(1);
	} else {
		fprintf(stdout, "    %s\t\t", MSGSTR(2329, "Path status:"));
		display_port_status(status);
	}
}

/*
 * Retrieves the lun capacity
 */
static int
get_lun_capacity(char *devpath, struct scsi_capacity_16 *cap_data)
{
int	fd;

	if (devpath == NULL || cap_data == NULL) {
		return (L_INVALID_PATH);
	}

	if ((fd = g_object_open(devpath, O_RDONLY | O_NDELAY)) == -1) {
		return (L_OPEN_PATH_FAIL);
	} else {
		(void) g_scsi_read_capacity_1016_cmd(fd, cap_data,
			sizeof (struct scsi_capacity_16));
		close(fd);
	}
	return (0);
}

/*
 * Retrieves the reservation status
 */
static int
get_path_status(char *devpath, int *status)
{
int	fd, mystatus = 0;


	if (devpath == NULL || status == NULL) {
		return (L_INVALID_PATH);
	}

	*status = 0;
	if ((fd = g_object_open(devpath, O_RDONLY | O_NDELAY)) == -1) {
		return (L_OPEN_PATH_FAIL);
	} else {
		if ((mystatus = g_scsi_tur(fd)) != 0) {
			if ((mystatus & L_SCSI_ERROR) &&
				((mystatus & ~L_SCSI_ERROR) == STATUS_CHECK)) {
				*status = L_NOT_READY;
			} else if ((mystatus & L_SCSI_ERROR) &&
				((mystatus & ~L_SCSI_ERROR) ==
					STATUS_RESERVATION_CONFLICT)) {
				*status = L_RESERVED;
			} else {
				*status = L_SCSI_ERR;
			}
		}
	}
	close(fd);
	return (0);
}

/*
 * Description:
 *	Retrieves the port wwn associated with the hba node
 *
 * hba_path: /devices/pci@8,600000/SUNW,qlc@4/fp@0,0
 * pwwn: ptr to a uchar_t array of size WWN_SIZE
 */
static int
get_host_controller_pwwn(char *hba_path, uchar_t *pwwn)
{
char *cptr, *portptr;
int found = 0, err, devlen;
char my_hba_path[MAXPATHLEN];
di_node_t node;
di_prom_prop_t promprop;
uchar_t *port_wwn_data = NULL;
int di_ret;
di_prom_handle_t ph;
char *promname;
uchar_t *promdata;
uint_t path_type;
fc_port_dev_t hba_port;

	if (hba_path == NULL || pwwn == NULL) {
		return (L_INVALID_PATH);
	}

	if ((path_type = g_get_path_type(hba_path)) == 0) {
		return (L_INVALID_PATH);
	}

	/*
	 * ifp nodes do not have a port-wwn prom property
	 * so handle them via FC4 device map
	 */
	if (path_type & FC4_XPORT_MASK) {
		if ((err = get_FC4_host_controller_pwwn(hba_path, pwwn)) != 0) {
			return (err);
		} else {
			return (0);
		}
	/* For Leadville path get the port wwn through g_get_host param. */
	} else if ((path_type & FC_GEN_XPORT) &&
		((path_type & FC_FCA_MASK) == FC_FCA_MASK)) {
		/*
		 * For Leadville path, get the port wwn through
		 * g_get_host param. This is a general solution
		 * to support 3rd party vendor Leadville FCA.
		 */
		my_hba_path[0] = '\0';
		(void) strlcat(my_hba_path, hba_path, sizeof (my_hba_path));
		(void) snprintf(my_hba_path, sizeof (my_hba_path), "%s%s",
			hba_path, FC_CTLR);
		if ((err = g_get_host_params(
			my_hba_path, &hba_port, 0)) != 0) {
			return (err);
		} else {
			(void) memcpy(pwwn, &hba_port.dev_pwwn.raw_wwn[0],
			    WWN_SIZE);
			return (0);
		}
	} else if ((path_type & FC_FCA_MASK) == FC_PCI_FCA) {
		/*
		 * Get port WWN through prom property
		 */
		my_hba_path[0] = '\0';
		(void) strlcat(my_hba_path, hba_path, sizeof (my_hba_path));
		/*
		 * sanity check for /devices mount point
		 */
		if (strlen(my_hba_path) > (devlen = strlen("/devices"))) {
			cptr = &my_hba_path[devlen];
		} else {
			return (L_INVALID_PATH);
		}

		/*
		 * Now strip off the trailing "/fp@"
		 */
		if ((portptr = strstr(cptr, "/fp@")) != NULL) {
			*portptr = '\0';
		}

		if ((node = di_init(cptr, DINFOCPYALL)) == DI_NODE_NIL) {
			return (L_DEV_SNAPSHOT_FAILED);
		}

		if (di_nodeid(node) == DI_SID_NODEID) {
			di_ret = di_prop_lookup_bytes(DDI_DEV_T_ANY, node,
				"port-wwn", &port_wwn_data);
			if (di_ret == -1 || port_wwn_data == NULL) {
				di_fini(node);
				return (L_NO_WWN_PROP_FOUND);
			} else {
				(void) memcpy(pwwn, port_wwn_data, WWN_SIZE);
				found++;
			}
		} else if (di_nodeid(node) == DI_PROM_NODEID) {
		    if ((ph = di_prom_init()) == DI_PROM_HANDLE_NIL) {
			di_fini(node);
			return (L_PROM_INIT_FAILED);
		    }

		    for (promprop = di_prom_prop_next(ph, node,
			DI_PROM_PROP_NIL);
			promprop != DI_PROM_PROP_NIL;
			promprop = di_prom_prop_next(ph, node, promprop)) {
			if (((promname = di_prom_prop_name(
				promprop)) != NULL) &&
				(strcmp(promname, "port-wwn") == 0) &&
				(di_prom_prop_data(promprop,
					&promdata) == WWN_SIZE)) {
				/* Found port-wwn */
				(void) memcpy(pwwn, promdata, WWN_SIZE);
				found++;
				break;
			}
		    }
		    di_prom_fini(ph);
		}

		di_fini(node);
		if (found) {
			return (0);
		} else {
			return (L_INVALID_PATH);
		}
	} else {
		return (L_INVALID_PATH_TYPE);
	}
}


/*
 * Description:
 *    Retrieve pwwn via SFIOCGMAP
 */
static int
get_FC4_host_controller_pwwn(char *hba_path, uchar_t *pwwn)
{
sf_al_map_t sf_map;
char my_hba_path[MAXPATHLEN];
int fd;

	if (hba_path == NULL || pwwn == NULL) {
		return (L_INVALID_PATH);
	}

	(void) snprintf(my_hba_path, sizeof (my_hba_path), "%s%s",
			hba_path, FC_CTLR);

	if ((fd = g_object_open(my_hba_path, O_NDELAY | O_RDONLY)) == -1) {
		return (errno);
	}

	memset(&sf_map, 0, sizeof (sf_al_map_t));

	if (ioctl(fd, SFIOCGMAP, &sf_map) != 0) {
		close(fd);
		return (L_SFIOCGMAP_IOCTL_FAIL);
	}

	close(fd);

	if (sf_map.sf_count == 0) {
		close(fd);
		return (L_SFIOCGMAP_IOCTL_FAIL);
	}

	(void) memcpy(pwwn, &sf_map.sf_hba_addr.sf_port_wwn[0], WWN_SIZE);

	return (0);
}

/*
 * from_ptr: ptr to uchar_t array of size WWN_SIZE
 * to_ptr: char ptr to string of size WWN_SIZE*2+1
 */
void
copy_wwn_data_to_str(char *to_ptr, const uchar_t *from_ptr)
{
	if ((to_ptr == NULL) || (from_ptr == NULL))
		return;

	sprintf(to_ptr, "%1.2x%1.2x%1.2x%1.2x%1.2x%1.2x%1.2x%1.2x",
	from_ptr[0], from_ptr[1], from_ptr[2], from_ptr[3],
	from_ptr[4], from_ptr[5], from_ptr[6], from_ptr[7]);
}

/*
 * Frees a previously allocated mplist_struct
 */
void
adm_mplist_free(struct mplist_struct *mplistp)
{
struct mplist_struct *mplistn;

	while (mplistp != NULL) {
		mplistn = mplistp->next;
		if (mplistp->devpath != NULL) {
			free(mplistp->devpath);
			mplistp->devpath = NULL;
		}
		free(mplistp);
		mplistp = mplistn;
	}
}

int
adm_reserve(char *path)
{
	char	*path_phys = NULL;
	int	err;
	if ((path_phys =
		    g_get_physical_name(path)) == NULL) {

		(void) fprintf(stderr, "%s: ", whoami);
		(void) fprintf(stderr,
			MSGSTR(112, "Error: Invalid pathname (%s)"),
			path);
		(void) fprintf(stderr, "\n");
		return (1);
	}

	if ((err = g_reserve(path_phys)) != 0) {
	    (void) print_errString(err, path);
	    return (1);
	}
	return (0);
}

int
adm_release(char *path)
{
	char	*path_phys = NULL;
	int	err;
	if ((path_phys =
		    g_get_physical_name(path)) == NULL) {

		(void) fprintf(stderr, "%s: ", whoami);
		(void) fprintf(stderr,
			MSGSTR(112, "Error: Invalid pathname (%s)"),
			path);
		(void) fprintf(stderr, "\n");
		return (1);
	}

	if ((err = g_release(path_phys)) != 0) {
	    (void) print_errString(err, path);
	    return (1);
	}
	return (0);
}

void
i18n_catopen() {
    (void) g_i18n_catopen();
}

int adm_check_file(char **path, int flag) {
	int err;
	if (err = l_check_file(*path, flag)) {
	    (void) print_errString(err, *path);
	    return (-1);
	}

	(void) fprintf(stdout, MSGSTR(2212, "Download file O.K. \n\n"));
	return (0);
}

/*
 * Print out private loop dev dtype
 */
void
print_private_loop_dtype_prop(uchar_t *hba_port_wwn, uchar_t *port_wwn,
	uchar_t dtype_prop)
{
	if ((dtype_prop & DTYPE_MASK) < 0x10) {
		(void) fprintf(stdout, " 0x%-2x (%s",
		(dtype_prop & DTYPE_MASK), dtype[(dtype_prop & DTYPE_MASK)]);
	} else if ((dtype_prop & DTYPE_MASK) < 0x1f) {
		(void) fprintf(stdout,
		MSGSTR(2243, " 0x%-2x (Reserved"),
		(dtype_prop & DTYPE_MASK));
	} else {
		(void) fprintf(stdout, MSGSTR(2245,
		" 0x%-2x (Unknown Type"), (dtype_prop & DTYPE_MASK));
	}
	/* Check to see if this is the HBA */
	if (wwnConversion(hba_port_wwn) == wwnConversion(port_wwn)) {
		/* MATCH */
		(void) fprintf(stdout, MSGSTR(2244,
		",Host Bus Adapter)\n"));
	} else {
		(void) fprintf(stdout, ")\n");
	}
}
