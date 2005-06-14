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

#ifndef _LIBFSMGT_H
#define	_LIBFSMGT_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef __cplusplus
extern "C" {
#endif

#include <stdio.h>
#include <sys/param.h>
#include <nfs/nfs_sec.h>
#include <sys/utsname.h>

#define	DFSTYPES	"/etc/dfs/fstypes"		/* dfs list */
#define	DFSTAB		"/etc/dfs/dfstab"		/* dfs list */
#define	BUFSIZE		65536
#define	LINESZ		2048

typedef void *fs_dfstab_entry_t;

/*
 * Public data type declarations
 */

/*
 * Represents a list of the /etc/vfstab entries
 */
typedef struct mount_default_list {
	struct mount_default_list *next;
	char *resource;
	char *fsckdevice;
	char *mountp;
	char *fstype;
	char *fsckpass;
	char *mountatboot;
	char *mntopts;
} fs_mntdefaults_t;

/*
 * Represents a list of /etc/mnttab entries
 */
typedef struct mount_list {
	struct mount_list *next;
	char *resource;
	char *mountp;
	char *fstype;
	char *mntopts;
	char *time;
	uint_t major;
	uint_t minor;
	boolean_t overlayed;
} fs_mntlist_t;

/*
 * Represents a /etc/dfs/sharetab entry
 */
typedef struct share_list {
	struct share_list *next;
	char *path;
	char *resource;
	char *fstype;
	char *options;
	char *description;
} fs_sharelist_t;

/*
 * Represents a list of /etc/mnttab entries with associated
 * information from kstat.
 */
typedef struct nfs_mntlist {
	struct nfs_mntlist *next;
	char		nml_curpath[MAXPATHLEN];	/* current path on */
							/* server */
	char		nml_curserver[SYS_NMLN];	/* current server */
	char		**nml_failoverlist;	/* The list of servers */
						/* and corresponding */
						/* paths for failover. */
	char		*nml_fstype;		/* filesystem type */
	char		*nml_mntopts;		/* mount options */
	char		*nml_mountp;		/* mount point */
	char		*nml_resource;		/* mnttab.mnt_special */
	char		nml_proto[KNC_STRSIZE];	/* transfer protocol */
	char		*nml_securitymode;	/* security mode name */
	char		*nml_time;		/* time mounted */
	int		nml_failovercount;	/* number of failover servers */
	int		nml_retrans;		/* times to retry request */
	int		nml_timeo;		/* inital timeout in 10th sec */
	ulong_t		nml_fsid;		/* filesystem ID */
	uint_t		nml_acdirmax;	/* max time to hold cached dir attr */
	uint_t		nml_acdirmin;	/* min time to hold cached dir attr */
	uint_t		nml_acregmax;	/* max time to hold cached file attr */
	uint_t		nml_acregmin;	/* min time to hold cached file attr */
	uint32_t	nml_curread;		/* current read size */
	uint32_t	nml_curwrite;		/* current write size */
	uint32_t	nml_vers;		/* nfs version */
	boolean_t	nml_directio;	/* force direct IO */
	boolean_t	nml_grpid;	/* group id inherited from parent */
	boolean_t	nml_hard;	/* hard or soft mount */
	boolean_t	nml_intr;	/* Key board intrupts */
	boolean_t	nml_noac;	/* no ata and attribute caching */
	boolean_t	nml_nocto;	/* no close-to-open  consistency */
	boolean_t	nml_overlayed;	/* Is filesystem overlayed */
	boolean_t	nml_xattr;	/* allow extended attributes */
} nfs_mntlist_t;

/*
 * Command execution interface method declarations
 */

/*
 * Method: cmd_execute_command
 *
 * Description: Executes the command passed into the function as if it was
 * the input to a shell and returns the separated stdout and stderr messages
 * which can be accessed by the client via the returned file descriptors using
 * the cmd_retrieve_string method or one of their own methods.
 *
 * Parameters:
 * char * - The command to execute.  Expected in the format of a shell command.
 * int * - Upon return from the function, this is the file descriptor that can
 * 	be used to access the output from the command to stdout.
 * int * - Upon return from the function, this is the file descriptor that can
 *	be used to access the output from the command to stderr.
 *
 * Return:
 * Returns 0 (zero).
 * Supposed to be the integer representing the exit value of the command
 * executed, but due to the way blocking on file descriptors works, it will
 * only return a 0 (zero) value.  The reason: The producer, in this case the
 * command being executed, will block when a certain amount of data is written
 * to the file descriptor and will not be able to write any more data until the
 * consumer reads from the file descriptor so since we are not reading in the
 * data from the file descriptors in this method and we are allowing the client
 * do what they want with the data we can't wait until the command is finished
 * executing to get the return value.
 */
int	cmd_execute_command(char *cmd, int *output_filedes, int *error_filedes);

/*
 * Method: cmd_execute_command_and_retrieve_string
 *
 * Description: Executes the command passed into the function as if it was the
 * input to a shell and returns the output to stderr and stdout as a string as
 * it would appear in the shell (stdout and stderr are mixed).
 *
 * Parameters:
 * char * - The command to execute.  Expected in the format of a shell command.
 * int * - Upon return from the function, this should be used to determine if an
 * 	error occurred in the execution of the command and the retrieval of
 *	output data from the command.
 * data from the command.
 *
 * Return:
 * The output to stdout and stderr created by the execution of the passed in
 * command.
 */
char	*cmd_execute_command_and_retrieve_string(char *cmd, int *errp);

/*
 * Method: cmd_retrieve_string
 *
 * Description: Retrieves the data from the passed in file descriptor and
 * returns it to the caller in the form of a string.
 *
 * Parameters:
 * int - The file descriptor to be read from.
 * int * - Upon return from the function, this should be the used to determine
 * 	if an error occurred in the retrieval of the data from the file
 *	descriptor.
 *	A non-zero value represents the occurrence of an error.
 *
 * Return:
 * The data from the file descriptor in the form of a string.
 * NOTE: The caller must free the space allocated (with calloc) for the return
 * value using free().
 */
char	*cmd_retrieve_string(int filedes, int *errp);

/*
 * File interface method declarations
 */

/*
 * NOTE: the caller of this function is responsible for freeing any
 * memory allocated by calling fileutil_free_string_array()
 *
 * Method: fileutil_add_string_to_array
 *
 * Description: Adds one line to the file image string array
 *
 * Parameters:
 * char ***string_array - pointer array of strings holding the lines
 *         for the new file
 * char *line - the line to be added to the new file
 * int *count - the number of elements in the string array
 * int *err - error pointer for returning any errors encountered
 *
 * Return:
 * B_TRUE on success, B_FALSE on failure.
 *
 * Note:
 * On success string_array is set to the new array of strings. On failure
 * string_array is unchanged.
 */
boolean_t fileutil_add_string_to_array(char ***, char *, int *, int *);

/*
 * Method: fileutil_free_string_array
 *
 * Description: Frees the space allocated to a string array.
 *
 * Parameters:
 * char ** - is the array to be freed
 * int - the number of elements in the array
 */
void	fileutil_free_string_array(char **, int);

/*
 * Method: fileutil_get_cmd_from_string
 *
 * Description: Returns a string containing a line with all comments and
 * trailing white space removed.
 *
 * Parameters:
 * char *input_stringp - the line to remove all coments and trailing white
 *	space.
 *
 * Note: The memory allocated for the returned string must be freed by the
 * caller of fileutil_get_cmd_from_string().
 */
char	*fileutil_get_cmd_from_string(char *input_stringp);

/*
 * Method: fileutil_get_first_column_data
 *
 * Description: Returns a string array which is filled with the data in the
 * first column of the lines in a table formatted file.
 * Examples of table formatted files include: /etc/netcofig, /etc/nfssec.conf
 *
 * Parameters:
 * FILE* - The file pointer of the table formatted file to get data from.
 * int* - will be filled with the number of elements in the array that is passed
 *	back.
 * int* - error pointer.  If an error occurs this will be non-zero upon return
 * 	the function.
 *
 * Returns:
 * Two-dimensional array of characters (string array).  Each element in the
 * array is the first column data of each row in the table.
 */
char	**fileutil_get_first_column_data(FILE *, int *, int *);

/*
 * Method: fileutil_getfs
 *
 * Description: Convenience function for retrieving the default remote file
 * system type from /etc/dfs/fstypes.
 *
 * Parameters:
 * FILE * - The /etc/dfs/fstypes file pointer.
 *
 * Return:
 * The default remote filesystem type.
 */
char	*fileutil_getfs(FILE *);

/*
 * Method: fileutil_getline
 *
 * Description: Convenience function for retrieving the next line from a file.
 *              Commented lines are not returned and comments at the end of
 *              a line are removed.
 *
 * Parameters:
 * FILE * - The file pointer to a file that has been opened for reading.
 * char * - The line retrived from the file will be placed in this string.
 * int * - error pointer - If an error occurs this will be non-zero upon
 *                         return from the function.
 *
 * Return:
 * If successfull the line retrieved from the file will be returned.
 * Otherwise NULL be be returned.
 */
char	*fileutil_getline(FILE *, char *, int);

/*
 * Mount defaults (/etc/vfstab) interface method declarations
 */
/*
 * Method: fs_add_mount_default
 *
 * Description: Adds an entry to vfstab based on the fs_mntdefaults_t
 *              structure that is passed in.
 *
 * Parameters:
 * fs_mntdefaults_t *newp - The structure containing the mount information
 *                          to be placed in vfstab.
 * int *errp - error pointer - If an error occurs this will be non-zero upon
 *                             return from the function.
 *
 * Return:
 * If successful a pointer to a list containing all the present vfstab
 * entries is returned. On failure NULL is returned.
 */
fs_mntdefaults_t	*fs_add_mount_default(fs_mntdefaults_t *, int *);

/*
 * Method: fs_check_for_duplicate_DFStab_paths
 *
 * Description: Checks dfstab for duplicate paths and returns the number of
 * times the path passed in was encountered. The functon is used to help make
 * sure a path is only listed in dfstab once.
 *
 * Parameters:
 * char *path - the path to check for
 * int *err - error pointer - If an error occurs this will be non-zero upon
 *	return from the function.
 *
 * Return:
 * The number of times the specified path is encountered in dfstab.
 */
int fs_check_for_duplicate_DFStab_paths(char *path, int *err);

/*
 * Method: fs_del_mount_default_ent
 *
 * Description: Deletes the specified vfstab entry from the vfstab file.
 *
 * Parameters:
 * fs_mntdefaults_t *old_vfstab_ent - The mount information that corresponds
 *                                    to the vfstab entry to be deleted.
 * int *errp - error pointer - If an error occurs this will be non-zero upon
 *                             return from the function.
 *
 * Return:
 * If successful a pointer to a list containing all the changed vfstab
 * entries is returned. On failure NULL is returned.
 */
fs_mntdefaults_t	*fs_del_mount_default_ent(fs_mntdefaults_t *, int *);

/*
 * Method: fs_edit_mount_defaults
 *
 * Description: Edits the specified vfstab entry with the new mount
 * information passed in.
 *
 * Parameters:
 * fs_mntdefaults_t *old_vfstab_ent - The old vfstab entry that is to be edited.
 * fs_mntdefaults_t *new_vfstab_ent - The new vfstab entry information.
 * int *errp - error pointer - If an error occurs this will be non-zero upon
 *                             return from the function
 *
 * Return:
 */
fs_mntdefaults_t	*fs_edit_mount_defaults(fs_mntdefaults_t *,
				fs_mntdefaults_t *, int *);

/*
 * Method: fs_free_mntdefaults_list
 *
 * Description: Frees the memory used when a fs_mntdefaults_t structure
 *              is populated.
 *
 * Parameters:
 * fs_mntdefaults_t *headp - The pointer to the first element in the list
 *                           of mntdefault structures.
 */
void	fs_free_mntdefaults_list(fs_mntdefaults_t *headp);


/*
 * Method: fs_get_filtered_mount_defaults
 *
 * Description: Retrieves vfstab entries based in the fields in the
 * fs_mntdefaults_t structure passed in. The fields that are not to
 * be used in the filter will be set to NULL.
 *
 * Parameters:
 * fs_mntdefaults_t *filter - The structure containing the fields to be
 *                            used for the filter.
 * int *errp - error pointer - If an error occurs this will be non-zero upon
 *                             return from the function
 *
 * Return:
 * The list of all vfstab entries meeting the filter criteria are returned.
 * On failure NULL is returned.
 */
fs_mntdefaults_t	*fs_get_filtered_mount_defaults(
				fs_mntdefaults_t *filter, int *errp);

/*
 * Method: fs_get_mount_defaults
 *
 * Description: Retrieves vfstab entries and returns a list of
 *              fs_mntdefaults_t structures.
 *
 * Parameters:
 * int *errp - error pointer - If an error occurs this will be non-zero upon
 *                             return from the function
 *
 * Return:
 * fs_mntdefaults_t * - Returns a list of all vfstab entries.
 */
fs_mntdefaults_t	*fs_get_mount_defaults(int *errp);

/*
 * Mount (/etc/mnttab) interface method declarations
 */
/*
 * Method: fs_free_mount_list
 *
 * Description: Frees the mount list created when retrieving mnttab entries.
 *
 * Parameters:
 * fs_mntlist_t *headp - The mount list to be freed.
 */
void	fs_free_mount_list(fs_mntlist_t *mnt_list);

/*
 * Method: fs_get_availablesize
 *
 * Description: Calculates the total size available on the filesystem.
 *
 * Parameters:
 * char *mntpnt - The mount point to use for gathering the stat information
 * int *errp - error pointer - If an error occurs this will be non-zero upon
 *                             return from the function
 *
 * Return:
 * The total size available on the filesystem.
 */
unsigned long long	fs_get_availablesize(char *mntpnt, int *errp);

/*
 * Method: fs_get_avail_for_nonsuperuser_size
 *
 * Description: Calculates the available space on the filesystem for
 *              nonsuperusers.
 *
 * Parameters:
 * char *mntpnt - The mount point for the filesystem.
 * int *errp - error pointer - If an error occurs this will be non-zero upon
 *                             return from the function
 *
 * Return:
 * The available space for nonsuperusers.
 * On failure NULL is returned.
 */
unsigned long long	fs_get_avail_for_nonsuperuser_size(char *mntpnt,
				int *errp);

/*
 * Method: fs_get_blocksize
 *
 * Description: Retrieves the preferred filesystem block size.
 *
 * Parameters:
 * char *mntpnt - The mount point for the filesystem.
 * int *errp - error pointer - If an error occurs this will be non-zero upon
 *                             return from the function
 *
 * Return:
 * Returns the preferred filesystem block size.
 * On failure NULL is returned.
 */

unsigned long long	fs_get_blocksize(char *mntpnt, int *errp);

/*
 * Method: fs_get_filtered_mount_list
 *
 * Description: Can be used to filter mounts only by the following mount
 * attributes or a mixture of them:
 * 1.) resource
 * 2.) mount point
 * 3.) mount option string
 * 4.) time mounted
 *
 * Parameters:
 * char *resource - The name of the resource to be mounted
 * char *mountp - The pathname of the directory on which the filesystem
 *                is mounted
 * char *mntopts - The mount options
 * char *time - The time at which the filesystem was mounted
 * boolean_t find_overlays - Flag used to turn on overlay checking
 * int *errp - error pointer - If an error occurs this will be non-zero upon
 *                             return from the function
 *
 * Return:
 * The list of all mnttab entries meeting the filter criteria are returned.
 * On failure NULL is returned.
 */
fs_mntlist_t		*fs_get_filtered_mount_list(char *resource,
				char *mountp, char *fstype, char *mntopts,
				char *time, boolean_t find_overlays,
				int *errp);

/*
 * Method: fs_get_fragsize
 *
 * Description: Determines the fundamental filesystem block size.
 *
 * Parameters:
 * char *mntpnt - The mount point for the filesystem.
 * int *errp - error pointer - If an error occurs this will be non-zero upon
 *                             return from the function
 *
 * Return:
 * Returns the fundamental filesystem block size.
 * On failure NULL is returned.
 */
unsigned long		fs_get_fragsize(char *mntpnt, int *errp);

/*
 * Method: fs_get_maxfilenamelen
 *
 * Description: Determines the maximum file name length for the filesystem.
 *
 * Parameters:
 * char *mntpnt - The mount point for the filesystem.
 * int *errp - error pointer - If an error occurs this will be non-zero upon
 *                             return from the function
 *
 * Return:
 * Returns the  maximum file name length for the specified filesystem.
 * On failure NULL is returned.
 */
unsigned long		fs_get_maxfilenamelen(char *mntpnt, int *errp);

/*
 * Method: fs_get_mounts_by_mntopt
 *
 * Description: Returns only mounts with the specified mount option set.
 *
 * Parameters:
 * char *mntopt - The mount option used for filtering mounts
 * boolean_t find_overlays - Flag used to turn on overlay checking
 * int *errp - error pointer - If an error occurs this will be non-zero upon
 *                             return from the function
 *
 * Return:
 * Returns the list of all mnttab entries with the matching mount option.
 * On failure NULL is returned.
 */
fs_mntlist_t		*fs_get_mounts_by_mntopt(char *mntopt,
				boolean_t find_overlays, int *errp);

/*
 * Method: fs_get_mount_list
 *
 * Description: Returns a list of all mounts in mnttab
 *
 * Parameters:
 * char *mntpnt - The mount point for the filesystem
 * boolean_t find_overlays - Flag used to turn on overlay checking
 * int *errp - error pointer - If an error occurs this will be non-zero upon
 *                             return from the function
 *
 * Return:
 * Returns the list of all mounts and associated mount information for mounts
 * listed in mnttab. On failure NULL is returned.
 */
fs_mntlist_t		*fs_get_mount_list(boolean_t find_overlays, int *errp);

/*
 * Method: fs_get_totalsize
 *
 * Description: Determines the total size of the filesystem using the
 * total number of blocks and the block size.
 *
 * Parameters:
 * char *mntpnt - The mount point for the filesystem
 * int *errp - error pointer - If an error occurs this will be non-zero upon
 *                             return from the function
 *
 * Return:
 * Returns the total size of the filesystem.
 * On failure NULL is returned.
 */
unsigned long long	fs_get_totalsize(char *mntpnt, int *errp);

/*
 * Method: fs_get_usedsize
 *
 * Description: Calculates the size of the used portion of the filesystem.
 *
 * Parameters:
 * char *mntpnt - The mount point for the filesystem
 * int *errp - error pointer - If an error occurs this will be non-zero upon
 *                             return from the function
 *
 * Return:
 * Returns the size of the the used portion of the filesystem.
 * On failure NULL is returned.
 */
unsigned long long	fs_get_usedsize(char *mntpnt, int *errp);

/*
 * Method: fs_is_readonly
 *
 * Description: Checks the filesystem flags to see if the filesystem is
 * readonly.
 *
 * Parameters:
 * char *mntpnt - The mount point for the filesystem
 * int *errp - error pointer - If an error occurs this will be non-zero upon
 *                             return from the function
 *
 * Return:
 * Returns B_TRUE if the readonly flag is set and B_FALSE if not.
 * On error the error pointer is set to errno.
 */
boolean_t		fs_is_readonly(char *mntpnt, int *errp);

/*
 * Method: fs_parse_optlist_for_option
 *
 * Description:
 * This method will parse the given comma delimited option list (optlist) for
 * the option passed into the function.  If the option (opt) to search for
 * is one that sets a value such as onerror=, the value to the right of the "="
 * character will be returned from the function.  This function expects the
 * opt parameter to have the "=" character appended when searching for options
 * which set a value.
 *
 * Parameters:
 * char *optlist - The option string to be parsed
 * char *opt - The option to search for
 * int *errp - error pointer - If an error occurs this will be non-zero upon
 *                             return from the function
 *
 * Return:
 * Returns the option as found in the option list.
 * If the option is not found NULL is returned.
 * On error NULL is returned and the error pointer is set to errno.
 */
char			*fs_parse_optlist_for_option(char *optlist, char *opt,
				int *errp);

/*
 * Share (/etc/dfs/sharetab) interface method declarations
 */
/*
 * Method: fs_free_share_list
 *
 * Description: Used to free populated fs_sharelist_t structures
 *
 * Parameters:
 * fs_sharelist_t *headp - the pointer to the first element in the list.
 */
void		fs_free_share_list(fs_sharelist_t *share_list);

/*
 * Method: fs_get_share_list
 *
 * Description: Gets a list of the shares on the system from /etc/dfs/sharetab
 *
 * Parameters:
 * int *errp - error pointer - If an error occurs this will be non-zero upon
 *                             return from the function
 *
 * Return:
 * Returns a list of fs_sharelist_t structures containing all of the shares
 * from sharetab.
 * On error NULL is returned and errp is set to errno.
 */
fs_sharelist_t	*fs_get_share_list(int *errp);

/*
 * Method: fs_parse_opts_for_sec_modes
 *
 * Description: Parses the option string for security modes and returns
 * an array of strings containing all modes.
 *
 * Parameters:
 * 	char * - options string to be parsed.
 * 	int * - count of the number of modes found.
 *	int * - error code.
 *
 * Return:
 * Returns an array of string containing all security opts listed in the
 * passed in option string. On error NULL is returned.
 */
char **fs_parse_opts_for_sec_modes(char *, int *, int *);

/*
 * Method: fs_create_array_from_accesslist
 *
 * Description: Takes the colon seperated access list parses the list
 *              into an array containing all the elements of the list.
 *              The array created is returned and count is set to the
 *              number of elements in the array.
 *
 * Parameters:
 * char *access_list - The string containing the colon sperated access list.
 * int *count - Will contain the number of elements in the array.
 * int *err - any errors encountered.
 */
char **fs_create_array_from_accesslist(char *access_list, int *count, int *err);

/*
 * FS dfstab (/etc/dfs/dfstab) interface method declarations
 */

/*
 * Method: fs_add_DFStab_ent
 *
 * Description: Adds an entry to dfstab and to the list of dfstab
 * entries. Returns a pointer to the head of the dfstab entry list.
 *
 * Parameters:
 * char *cmd - the share command to be added to dfstab
 * int *errp - error pointer - If an error occurs this will be non-zero upon
 *                             return from the function
 *
 * Return:
 * Returns the pointer to the updated dfstab entry list.
 */
fs_dfstab_entry_t fs_add_DFStab_ent(char *, int *);

/*
 * Method: fs_del_DFStab_ent
 *
 * Description: Deletes an entry from dfstab and from the list of
 *              dfstab entries.
 *
 * Parameters:
 * char *del_cmd - The share command to be removed
 * int *errp - error pointer - If an error occurs this will be non-zero upon
 *                             return from the function
 *
 * Return:
 * Returns the pointer to the updated dfstab entry list.
 */
fs_dfstab_entry_t fs_del_DFStab_ent(char *, int *);

/*
 * NOTE: the caller of this function is responsible for freeing any
 * memory allocated by calling fs_free_DFStab_ents()
 *
 * Method: fs_edit_DFStab_ent
 *
 * Description: Changes the specified line in dfstab to match the second
 *              string passed in.
 *
 * Parameters:
 * char *old_cmd - The share command that will be changed.
 * char *new_cmd - The share command that will replace old_cmd.
 * int *errp - error pointer - If an error occurs this will be non-zero upon
 *                             return from the function
 *
 * Return:
 * Returns the pointer to the updated dfstab entry list.
 */
fs_dfstab_entry_t fs_edit_DFStab_ent(char *, char *, int *);

/*
 * Method: fs_free_DFStab_ents
 *
 * Description: Frees the dfstab entry list.
 *
 * Parameters:
 * fs_dfstab_entry_t list - The pointer to the dfstab entry list.
 */
void fs_free_DFStab_ents(fs_dfstab_entry_t);

/*
 * NOTE: the caller of this function is responsible for freeing any
 * memory allocated by calling fs_free_DFStab_ents()
 *
 * Method: fs_get_DFStab_ents
 *
 * Description: Retrieves the dfstab entry list.
 *
 * Parameters:
 * int *errp - error pointer - If an error occurs this will be non-zero upon
 *                             return from the function
 *
 * Return:
 * Returns the pointer to the dfstab entry list.
 * If NULL is returned and errp is 0 then dfstab has no entries. If errp is
 * not 0 there was an error and the value of errp is set to the errno
 * value for that error.
 */
fs_dfstab_entry_t fs_get_DFStab_ents(int *err);

/*
 * NOTE: the caller of this function is responsible for freeing any
 * memory allocated by calling fs_free_DFStab_ents()
 *
 * Method: fs_get_DFStab_ent_Desc
 *
 * Description: Retrieves the description information for the present
 *              dfstab entry.
 *
 * Parameters:
 * fs_dfstab_entry_t entry - the dfstab entry to retrieve the description from.
 *
 * Return:
 * The string containing the description for the dfstab entry.
 * If the description is not set NULL is returned.
 *
 * Note: the description is an optional share option and a return value of
 *       NULL is not an error but indicates that the description was not set.
 */
char *fs_get_DFStab_ent_Desc(fs_dfstab_entry_t);

/*
 * Method: fs_get_DFStab_ent_Fstype
 *
 * Description: Retrieves the filesystem type information from the dfstab
 *              entry passed in.
 *
 * Parameters:
 * fs_dfstab_entry_t entry - the dfstab entry to retrieve the fstype from.
 *
 * Return:
 * The string containing the filesystem type.
 *
 * Note: if fstype is not set in the dfstab entry the default fstype is
 *       returned.
 */
char *fs_get_DFStab_ent_Fstype(fs_dfstab_entry_t);

/*
 * Method: fs_get_DFStab_ent_Next
 *
 * Description: Retrieves the next entry in the dfstab entry list.
 *
 * Parameters:
 * fs_dfstab_entry_t entry - The dfstab entry pointer to get the next
 *                           pointer from.
 *
 * Return:
 * Returns the next dfstab entry.
 * A return value of NULL indicates the end of the dfstab entry list.
 */
fs_dfstab_entry_t fs_get_DFStab_ent_Next(fs_dfstab_entry_t);

/*
 * Method: fs_get_DFStab_ent_Options
 *
 * Description: Retrieves the share options from the dfstab
 *              entry passed in.
 *
 * Parameters:
 * fs_dfstab_entry_t entry - The dfstab entry to retrieve the share
 *                           options from.
 *
 * Return:
 * Returns the string containing the share options.
 * A NULL value indicates that no options were specified in the dfstab entry.
 */
char *fs_get_DFStab_ent_Options(fs_dfstab_entry_t);

/*
 * Method: fs_get_DFStab_ent_Path
 *
 * Description: Retrieves the path information from the dfstab
 *              entry passed in.
 *
 * Parameters:
 * fs_dfstab_entry_t entry - the dfstab entry to retrieve the path from.
 *
 * Return:
 * Returns the string containing the path.
 * A NULL value indecates that no path information is available for the
 * dfstab entry. A NULL value here is an error and indicates an invalid
 * dfstab entry.
 */
char *fs_get_DFStab_ent_Path(fs_dfstab_entry_t);

/*
 * Method: fs_get_DFStab_ent_Res
 *
 * Description: Retrieves the resource information from the dfstab entry
 *              passed in.
 *
 * Parameters:
 * fs_dfstab_entry_t entry - the dfstab entry to retrieve the resource
 *                           information from.
 *
 * Return:
 * Returns the string containing the path.
 * A NULL value indecates that no resource information is available for the
 * dfstab entry.
 */
char *fs_get_DFStab_ent_Res(fs_dfstab_entry_t);

/*
 * Method: fs_get_Dfstab_share_cmd
 *
 * Description: Retrieves the share command that corresponds to the
 *              dfstab entry passed in.
 *
 * Parameters:
 * fs_dfstab_entry_t entry - The dfstab entry that will be used to create
 *                           a share command.
 * int *errp - error pointer - If an error occurs this will be non-zero upon
 *                             return from the function
 *
 * Return:
 * Returns the string containing the share command.
 * A NULL value indicates an error occured and errp will be non zero.
 */
char *fs_get_Dfstab_share_cmd(fs_dfstab_entry_t, int *);

/*
 * NOTE: the caller of this function is responsible for freeing any
 * memory allocated by calling fs_free_DFStab_ents()
 *
 * Method: fs_set_DFStab_ent
 *
 * Description: Used to add entries into dfstab
 *
 * Parameters:
 * char *path - The path for the dfstab entry
 * char *fstype - The filesystem type for the share
 * char *options - The share options to be used for the dfstab entry
 * char *description - The description for the share
 * int *errp - error pointer - If an error occurs this will be non-zero upon
 *                             return from the function
 *
 * Return:
 * Returns a pointer to the begining of the dfstab entry list
 * Failure returns NULL
 */
fs_dfstab_entry_t fs_set_DFStab_ent(char *, char *, char *, char *, int *);

/*
 * NOTE: the caller of this function is responsible for freeing any
 * memory allocated by calling fs_free_DFStab_ents()
 *
 * Method: fs_del_All_DFStab_ents_with_Path
 *
 * Description: Removes all dfstab entries with the specified path.
 *
 * Parameters:
 *            char *path - The path to checked for removal from dfstab.
 *            int *err - error pointer.
 *
 * Return: returns a pointer to the nfs list of dfstab entries.
 */
fs_dfstab_entry_t fs_del_All_DFStab_ents_with_Path(char *, int *);

/*
 * Debuging functions
 */
void fs_print_dfstab_entries(fs_dfstab_entry_t);

/*
 * NFS mount interface method declarations
 */
/*
 * Method: nfs_free_mntinfo_list
 *
 * Description: Used to free the network id list, which is an array of strings.
 *
 * Parameters:
 * nfs_mntlist_t *mountinfo_list - The list of mounts and associated mount
 *                                 information
 *
 */
void nfs_free_mntinfo_list(nfs_mntlist_t *);

/*
 * NOTE: the caller of this function is responsible for freeing any
 * memory allocated by calling nfs_free_mntinfo_list()
 *
 * Method: nfs_get_filtered_mount_list
 *
 * Description: Can be used to filter nfs mounts only by the following mount
 * attributes or a mixture of them:
 * 1.) resource
 * 2.) mount point
 * 3.) mount option string
 * 4.) time mounted
 *
 * NULL must be passed into the options that are not being used in the filter.
 *
 * Parameters:
 * char *resource - The name of the resource to be mounted
 * char *mountp - The pathname of the directory on which the filesystem
 *                is mounted
 * char *mntopts - The mount options
 * char *time - The time at which the filesystem was mounted
 * boolean_t find_overlays - Flag used to turn on overlay checking
 * int *errp - error pointer - If an error occurs this will be non-zero upon
 *                             return from the function
 *
 * Return:
 * nfs_mntlist_t * - Returns a list of nfs mounts based on the
 *                   parameters passed in.
 */
nfs_mntlist_t *nfs_get_filtered_mount_list(char *resource, char *mountp,
	char *mntopts, char *time, boolean_t find_overlays,
	int *errp);

/*
 * NOTE: the caller of this function is responsible for freeing any
 * memory allocated by calling nfs_free_mntinfo_list()
 *
 * Method: nfs_get_mounts_by_mntopt
 *
 * Description: Can be used to filter mounts by the mount options attribute.
 *
 * Parameters:
 * char *mntopts - The mount options
 * boolean_t find_overlays - Flag used to turn on overlay checking
 * int *errp - error pointer - If an error occurs this will be non-zero upon
 *                             return from the function
 *
 * Return:
 * nfs_mntlist_t * - Returns a list of nfs mounts based on the
 *                   parameters passed in.
 */
nfs_mntlist_t *nfs_get_mounts_by_mntopt(char *mntopt, boolean_t find_overlays,
	int *errp);

/*
 * NOTE: the caller of this function is responsible for freeing any
 * memory allocated by calling nfs_free_mntinfo_list()
 *
 * Method: nfs_get_mount_list
 *
 * Description: Used to gather all NFS mounts and there associated
 *              mount information.
 *
 * Parameters:
 * int *errp - error pointer - If an error occurs this will be non-zero upon
 *                             return from the function
 *
 * Return:
 * nfs_mntlist_t * - Returns a list of all nfs mounts.
 */
nfs_mntlist_t *nfs_get_mount_list(int *);

/*
 * Netconfig (/etc/netconfig) interface method declarations
 */
/*
 * Method: netcfg_free_networkid_list
 *
 * Description: Used to free the network id list, which is an array of strings.
 *
 * Parameters:
 * char **netlist - The array of strings containing the network id list
 * int  num_elements - The number of elements in the network id list
 *
 */
void	netcfg_free_networkid_list(char **netlist, int num_elements);

/*
 * NOTE: the caller of this function is responsible for freeing any
 * memory allocated by calling netcfg_free_networkid_list()
 *
 * Method: netcfg_get_networkid_list
 *
 * Description: Used to create the network id list.
 *
 * Parameters:
 * int *num_elements - The number of elements in the network id list.
 * int *errp - error pointer - If an error occurs this will be non-zero upon
 *                             return from the function
 *
 * Return:
 * char    ** - Returns the netowk id list.
 */
char	**netcfg_get_networkid_list(int *num_elements, int *errp);

/*
 * nfssec (/etc/nfssec.conf) interface method declarations
 */
/*
 * Method: nfssec_free_secmode_list
 *
 * Description: Used to free the NFS security mode list.
 *
 * Parameters:
 * char **seclist - The array of strings containing the security mode list
 * int num_elements - The number of elements in the list
 *
 */
void	nfssec_free_secmode_list(char **seclist, int num_elements);

/*
 * Method: nfssec_get_default_secmode
 *
 * Description: Used to retrieve the default security mode
 *
 * Parameters:
 * int *errp - error pointer - If an error occurs this will be non-zero upon
 *                             return from the function
 *
 * Return:
 * char * - Returns the name of the default security mode
 */
char	*nfssec_get_default_secmode(int *errp);

/*
 * NOTE: the caller of this function is responsible for freeing any
 * memory allocated by calling nfssec_free_secmode_list()
 *
 * Method: nfssec_get_nfs_secmode_list
 *
 * Description: Used to create the NFS security mode list.
 *
 * Parameters:
 * int *num_elements - The number of elements in the security mode list
 * int *errp - error pointer - If an error occurs this will be non-zero upon
 *                             return from the function
 *
 * Return:
 * char ** - Returns the NFS security mode list
 *
 */
char	**nfssec_get_nfs_secmode_list(int *num_elements, int *errp);

/*
 * System information interface method declarations
 */
/*
 * Method: sys_get_hostname
 *
 * Description: Used to retrieve the name of the host
 *
 * Parameters:
 * int *errp - error pointer - If an error occurs this will be non-zero upon
 *                             return from the function
 *
 * Return:
 * char * - Returns the name of the host system
 */
char *sys_get_hostname(int *errp);


#ifdef __cplusplus
}
#endif

#endif /* _LIBFSMGT_H */
