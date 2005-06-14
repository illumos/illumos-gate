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
 * Copyright 2004 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * This file implements windows style INI files.  It caches
 * files in memory, so they are not parsed on each read.
 *
 *  WARNING:    This library is completely UN-THREAD-SAFE and NON-REENTRANT.
 */

/* LINTLIBRARY */

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>
#include <strings.h>
#include <string.h>
#include <ctype.h>
#include <sys/stat.h>
#include <net/pfkeyv2.h>   /* ipsec alg, etc., values */
#include <errno.h>

#include "conflib.h"

#define	INI_MAX_CACHED 10	/* Maximum number of files to keep cached */
#define	MAX_LONG_LEN 20		/* The printed size of a 32 bit number    */

/* *********************   Internal Structures	  ******************** */

/* This is the simplest part.  A label.	 This is the atom of the ini file */
typedef struct {
	char Label[MAX_LABEL_LEN];
	char Value[MAX_VALUE_LEN];
} LabelType;

/* A section contains an array list of labels */
typedef struct {
	int NumLabels;
	char SectionName[MAX_FILENAME_LEN];
	LabelType *Labels;
} SectionType;

/* An ini file contains an array list of Sections */
typedef struct {
	int NumSections;
	char Filename[MAX_FILENAME_LEN];
	time_t	   ModificationTime;
	SectionType *Sections;
} IniFileType;

/* An IniFileList Contains a linked list of ini files */
typedef struct s {
	IniFileType IniFile;
	struct s *Next;
} IniFileList;

static IniFileList *IniHead = NULL;

#define	BUF_LEN		MAX_LABEL_LEN + MAX_VALUE_LEN
#define	INI_SECTION	1
#define	INI_LABEL	2
#define	INI_ERROR	0

char ErrorString[ERROR_STRING_LEN];

boolean_t encr_alg_set = FALSE;  /* true if encr_alg set */

/* These are the valid ipsec actions mipagent and friends support. */
char *validIPsecAction[] = {
	"apply",	/* outbound IPsec Policy */
	"permit",	/* inbound IPsec Policy */
	NULL
};

/* Each entry in our various ipsec algorithm tables is one of these */
struct ipsec_alg {
	char *alg;
	uint_t value;
};

/* Some macroed values */
#define	NO_AH_AALG	256
#define	NO_ESP_AALG	256
#define	NO_ESP_EALG	256

/* valid encr_algs to match with user config */
struct ipsec_alg encr_algs[] = {
	{"any", SADB_EALG_NONE},
	{"des", SADB_EALG_DESCBC},
	{"des-cbc", SADB_EALG_DESCBC},
	{"3des", SADB_EALG_3DESCBC},
	{"3des-cbc", SADB_EALG_3DESCBC},
	{"blowfish", SADB_EALG_BLOWFISH},
	{"blowfish-cbc", SADB_EALG_BLOWFISH},
	{"aes", SADB_EALG_AES},
	{"aes-cbc", SADB_EALG_AES},
	{"null", SADB_EALG_NULL},
	{"none", NO_ESP_EALG},
	{NULL, 0}
};

/* one auth_algs to match with user configs */
struct ipsec_alg auth_algs[] = {
	{"any", SADB_AALG_NONE},
	{"md5", SADB_AALG_MD5HMAC},
	{"hmac-md5", SADB_AALG_MD5HMAC},
	{"sha1", SADB_AALG_SHA1HMAC},
	{"hmac-sha1", SADB_AALG_SHA1HMAC},
	{"sha", SADB_AALG_SHA1HMAC},
	{"hmac-sha", SADB_AALG_SHA1HMAC},
	{"none", NO_AH_AALG},
	{NULL, 0}
};

#define	SADB_SA_SHARED	0
#define	SADB_SA_UNIQUE	1

/*
 * One for sa_algs.  OK, these aren't algs, but in order to make the parsing
 * of properties easy, they're laid out "<tag> <alg> <tag> <alg> ...", so it's
 * designed so <tag> maps directly to the function that parses <alg>.  The
 * "... sa (shared | unique)" bit then needs to be done analogously.
 */
struct ipsec_alg sa_algs[] = {
	{"shared", SADB_SA_SHARED},
	{"unique", SADB_SA_UNIQUE},
	{NULL, 0},
};


/*
 * Internal prototypes
 */
static int IniLoadFile(char *Filename);
static void InitializeIniFile(IniFileList *FileList);
static int IniParseFile(IniFileType *File, char *Filename);
static int AddSection(IniFileType *IniFile, char *Section);
static int AddLabel(IniFileType *IniFile, int SectionNdx, char *Label,
    char *Data);
static void ModifyLabel(IniFileType *IniFile, int SectionNdx, int LabelNdx,
    char *Data);
static int IniCheckComment(char *buffer);
static int ParseLine(char *buffer, char *TempLabel, char *TempValue);
static int IniLoaded(char *Filename);
static int IniUpdateLocalCopy(char *Filename, char *Section, char *Label,
    char *Data);
#ifndef lint /* this function is not used for now */
static char *GetSectionList(IniFileType *IniFile, char *argv, int *NumSections,
    int *elementSize);
#endif /* lint */
static IniFileList *UnlinkFile(char *Filename);
static int IniUnloadFile(char *Filename);
static int IniUpdateFile(char *Filename, char *Section, char *Label,
    char *Data);
static int CopyToSection(char *Section, FILE *in, FILE *out, int CopySection);
static void CopyToEOF(FILE *in, FILE *out, char *Label);
static char *dirname(char *FullPath);
static void CheckAndAllocateCacheSpace();
static void IniFreeFile(IniFileList *File);
static int Rename(char *source, char *dest);
static int GetSectionProfileString(IniFileList *IniFile, char *Section,
    char *Label, char *dest, int destLen);
static int GetLabelProfileString(IniFileList *IniFile, int SectionNdx,
    char *Label, char *dest, int destLen);

/* ipsec algorithm parsing routines */
int parsealg(char *, struct ipsec_alg *);
int parse_algs(int, int, ipsec_req_t *);
int parse_esp_auth_alg(char *, ipsec_req_t *);
int parse_esp_encr_alg(char *, ipsec_req_t *);
int parse_ah_alg(char *, ipsec_req_t *);
int parse_sa_alg(char *, ipsec_req_t *);
uint_t isIPsecActionValid(char *);


/* something to switch on */
enum ipsec_alg_type { ESP_ENCR_ALG = 1, ESP_AUTH_ALG, AH_AUTH_ALG, SA_ALG };

/* table for parsing IPSEC related algs */
struct ipsec_cmd {
	char	*c_name;
	int	(*c_func)(char *, ipsec_req_t *);
} ipseccmd[] = {
	{ "encr_auth_algs",	parse_esp_auth_alg },
	{ "encr_algs",		parse_esp_encr_alg },
	{ "auth_algs",		parse_ah_alg },
	{ "sa",			parse_sa_alg },
	{ 0,			0 },
};


/*
 * Function: InitializeIniFile
 *
 * Arguments: IniFileList *
 *
 * Description: This function will Initialize an ini file
 *
 * Returns: void
 *
 */
static void
InitializeIniFile(IniFileList *New)
{
	New->Next = NULL;
	New->IniFile.NumSections = 0;
	(void) memset(New->IniFile.Filename, 0, MAX_FILENAME_LEN);
	New->IniFile.ModificationTime = 0;
	New->IniFile.Sections = NULL;
} /* InitializeIniFile */

/*
 * Function: FileHasChanged
 *
 * Arguments: ModificationTime, Filename
 *
 * Description: This function will return true if the filename's
 *              modification time is different than the one passed in.
 *              It also returns true on error.  If we aren't able to get a
 *              stat() of the file, just assume it has changed.
 *
 * Returns: int (non zero if time has changed)
 *
 */
static int
FileHasChanged(time_t ModificationTime, char *Filename)
{
	struct stat file_stats;

	if (stat(Filename, &file_stats) == (-1)) {
		char *errMsg = strerror(errno);

		if (errno == ENOENT)
			return (TRUE); /* file does not exist */

		/*
		 * Some kind of error.  Just return TRUE.
		 * Note: we come in here twice, once via IniLoaded(), and
		 * (if that fails) again from IniLoadFile().  It would be
		 * mostly innocuous to overwrite ErrorString with this [same]
		 * message, but why bother?
		 */
		if (ErrorString[0] == '\0') {
			snprintf(ErrorString, sizeof (ErrorString), "Warning: "
			    "unable to retrieve stats on <%s>.  %s.", Filename,
			    errMsg != NULL ? errMsg : "Unknown error");
		}

		return (TRUE);
	}

	/*
	 * Now return the change state
	 */
	return (ModificationTime != file_stats.st_mtime);
} /* FileHasChanged */

/*
 * Function: IniLoadFile
 *
 * Arguments: Filename
 *
 * Description: This function loads in a configuration file.
 *              It caches files by moving them to the head of the linked
 *              list.  It also checks for files that have changed on the disk
 *              by using stat().
 *
 * Returns: int (zero on success)
 *
 */
static int
IniLoadFile(char *Filename)
{
	IniFileList *NewIniFileNode, *Probe;
	IniFileList *Last = NULL;

	for (Probe = IniHead; Probe; Probe = Probe->Next) {
		/* Check to see if it is already loaded */
		if (strcmp(Probe->IniFile.Filename, Filename) == 0) {
			/*
			 * Found it, we already have it cached.
			 * check Date/Time stamp
			 */
			if (FileHasChanged(Probe->IniFile.
			    ModificationTime, Filename)) {
				/* Reload the file */
				(void)  IniUnloadFile(Filename);
				break; /* Leave loop */
			} else {
				/*
				 * It is our file, and it hasn't changed,
				 * Cache our entry by moving it to the head
				 * of the list and return success.
				 */
				if (Last) {
					/*
					 * Only move it if this is not the
					 * first entry.
					 */
					Last->Next = Probe->Next;
					Probe->Next = IniHead;
					IniHead = Probe;
				}
				return (0);
			}
		} /* strcmp checking filename */
		Last = Probe;
	} /* For loop searching for file */

	/*
	 * Now, we know that we don't have the file cached or loaded, so
	 * allocate memory and load it.
	 * Note: IniFileList is the bucket that holds a STATIC IniFileType.
	 */
	NewIniFileNode = malloc(sizeof (IniFileList));
	if (!NewIniFileNode) {
		(void)  strcpy(ErrorString,
		    "Unable to allocate memory for new ini file.");
		return (-1);
	}

	/*
	 * Add it to our head.	But first, remove the last entry if we have
	 * Too many items in our cache.
	 */
	CheckAndAllocateCacheSpace();
	NewIniFileNode->Next = IniHead;
	IniHead = NewIniFileNode;

	/*
	 * Now we have a pointer to New.  Clear it, and parse in the
	 * new file
	 */
	InitializeIniFile(NewIniFileNode);
	if (IniParseFile(&NewIniFileNode->IniFile, Filename)) {
		/* Remove ini file from list */
		IniHead = NewIniFileNode->Next;
		free(NewIniFileNode);
		return (-2);
	}

	return (0);
} /* IniLoadFile */

/*
 * Function: CheckAndAllocateCacheSpace
 *
 * Arguments: none
 *
 * Description: This routine will check to see if our INI cache is full, and
 *              if so, will delete the last (least recently used) entry.
 *
 * Returns: void
 *
 */
static void
CheckAndAllocateCacheSpace()
{
	IniFileList *Probe;
	IniFileList *Last;
	int count;

	/* Return if the cache is empty (or nearly empty) */
	if (!IniHead || !IniHead->Next)
		return;

	/*
	 * Send Probe to next to end of list, and last to one before probe,
	 * while counting with count.
	 */
	for (Probe = IniHead, count = 0, Last = IniHead;
	    Probe->Next;
	    Probe = Probe->Next, count++)
		Last = Probe;

	if (count >= INI_MAX_CACHED) {
		/* Our cache is full.  Free the last entry */
		Last->Next = NULL;
		IniFreeFile(Probe);
	}
} /* CheckAndAllocateCacheSpace */

/*
 * Function: IniParseFile
 *
 * Arguments: IniFileType *File, char *Filename
 *
 * Description: This routine will parse the INI file and load the Section
 *              and Label arrays.
 *
 * Returns: int
 */
static int
IniParseFile(IniFileType *File, char *Filename)
{
	int LineNo;
	char CurrentSection[MAX_LABEL_LEN];
	char buffer[BUF_LEN];
	char TempLabel[MAX_LABEL_LEN], TempValue[MAX_VALUE_LEN];
	FILE *handle;
	int rc;
	struct stat file_stat;

	/*
	 * Copy the filename...
	 */
	(void)  strncpy(File->Filename, Filename, MAX_FILENAME_LEN);
	File->Filename[MAX_FILENAME_LEN-1] = 0; /* Just in case we overran */

	(void) memset(CurrentSection, 0, MAX_LABEL_LEN);

	/* Set the modification time */
	if (stat(Filename, &file_stat) == 0) {
		File->ModificationTime = file_stat.st_mtime;
	} else {
		char *errMsg = strerror(errno);

		(void) snprintf(ErrorString, sizeof (ErrorString),
		    "Unable to stat <%s>.  %s.", Filename,
		    errMsg != NULL ? errMsg : "Unknown error");

		return (-1);
	}

	/* Open the file */
	handle = fopen(Filename, "rt");
	if (handle == NULL) {
		char *errMsg = strerror(errno);

		(void) snprintf(ErrorString, sizeof (ErrorString),
		    "Unable to open file <%s>.  %s.", Filename,
		    errMsg != NULL ? errMsg : "Unknown error");

		return (-1);
	}

	LineNo = 0;
	while (fgets(buffer, BUF_LEN, handle)) {
		LineNo++;
		/* If it is a comment or a blank line, don't process it */
		if (IniCheckComment(buffer))
			continue;

		switch (ParseLine(buffer, TempLabel, TempValue)) {
		case INI_SECTION:
				/* Call our add section function */
			rc = AddSection(File, TempLabel);
			/* If an error occurs, AddSection sets ErrorString */
			if (rc < 0) {
				(void)  fclose(handle);
				return (rc);
			}
			break;

		case INI_LABEL:
				/*
				 * check to see if we are before our first
				 * section label
				 */
			if (!File->NumSections) {
				(void) sprintf(ErrorString, "Data outside of "
				    "section on line %d.", LineNo);
				(void) fclose(handle);
				return (-2);
			}
			rc = AddLabel(File, File->NumSections-1, TempLabel,
			    TempValue);
			/* If an error occurs, AddLabel sets ErrorString */
			if (rc < 0) {
				(void) fclose(handle);
				return (rc);
			}
			break;
		case INI_ERROR:
		default:
			(void) snprintf(ErrorString, sizeof (ErrorString),
			    "Error parsing INI file (%s) on line %d.",
			    Filename, LineNo);
			(void) fclose(handle);
			return (-3);
		}
	}

	/* Success! */
	(void) fclose(handle);
	return (0);
} /* IniParseFile */

/*
 * Function: TrimWhiteSpace
 *
 * Arguments: char *buffer
 *
 * Description: This function removes leading and trailing white space
 *              from a string.
 *
 * Returns: static void
 */
static void
TrimWhiteSpace(char *buffer)
{
	int i, j;
	/* First, find first non-whitespace character */
	for (i = 0; buffer[i] && isspace((int)buffer[i]); i++);

	/*
	 * Now, i is pointing to the first non-white space
	 * character in buffer
	 */

	/* Find the last non-whitespace character */
	for (j = strlen(buffer)-1; j > 0 && isspace((int)buffer[j]); j--);

	if ((i > j) || (j < 0)) {
		/* Empty */
		buffer[0] = 0;
	} else {
		/* copy the usable buffer */
		bcopy(&buffer[i], buffer, (j-i)+1);
		/* and Null-terminate it */
		buffer[(j-i)+1] = 0;
	}
} /* TrimWhiteSpace */

/*
 * Function: ParseLine
 *
 * Arguments: char *buffer, char *TempTag, char *TempValue
 *
 * Description:  This routine will return either the section or label
 *               information.  If it finds a section line in the buffer,
 *               it will return the section name in the TempTag Field.
 *               If it finds a Label, it will fill out TempValue and
 *               TempTag.
 *
 * Returns: int
 */
static int
ParseLine(char *staticBuffer, char *TempTag, char *TempValue)
{
	int i = 0, j = 0;
	int EqualFound = FALSE;
	char buffer[BUF_LEN];

	(void) strlcpy(buffer, staticBuffer, BUF_LEN);

	/* Trim the white space of the entire buffer first */
	TrimWhiteSpace(buffer);

	if (buffer[0] == '[') {
		/* Must be a section */
		for (i = 1; buffer[i] && buffer[i] != ']'; i++)
			TempTag[j++] = buffer[i];

		/* Check to make sure we got an end-bracket */
		if (buffer[i] != ']')
			/* Bad Section! */
			return (INI_ERROR);

		TempTag[j] = 0;
		TrimWhiteSpace(TempTag);
		return (INI_SECTION);
	}
	for (i = 0; buffer[i]; i++)	{
		if (buffer[i] == '=') {
			EqualFound = TRUE;
			TempTag[j] = 0;
			j = 0;
		} else {
			if (!EqualFound)
				TempTag[j++] = buffer[i];
			else
				TempValue[j++] = buffer[i];
		}
	}
	if (!EqualFound) {
		/* Bad Label! */
		return (INI_ERROR);
	}
	TempValue[j] = 0;
	/* Handle EOLN */
	if (TempValue[j-1] == '\n')
		TempValue[j-1] = 0;

	/* And finally, trim the white space off of our return strings */
	TrimWhiteSpace(TempTag);
	TrimWhiteSpace(TempValue);
	return (INI_LABEL);
} /* ParseLine */


/*
 * Function: IniUpdateFile
 *
 * Arguments: char *Filename, char *Section, char *Label, char *Data
 *
 * Description: This will update our INI file.  It copies the file from
 *              it's original position to a temp one, then renames to
 *              overwrite the original.
 *
 * Returns: int (zero on success)
 */
static int
IniUpdateFile(char *Filename, char *Section, char *Label, char *Data)
{
	FILE *in, *out;
	char TempFile[MAX_FILENAME_LEN];
	int DeleteSection = 0;
	int DeleteLabel = 0;

	/* Set our deletion flags */
	if (!Label && !Data)
		DeleteSection = 1;

	if (!Data)
		DeleteLabel = 1;

	/*
	 * Don't worry about checking the handle right away.  It's checked
	 * later.  If the input file open fails, we assume that the file just
	 * does not exist.  It will be created when the output file is renamed
	 * into the input file (or it is copied).
	 */
	in = fopen(Filename, "r+");

	/* Create a temporary file name in the same directory as the INI file */
	(void) strlcpy(TempFile, tempnam(dirname(Filename), NULL),
		sizeof (TempFile));

	out = fopen(TempFile, "w");
	if (!out) {
		char *errMsg = strerror(errno);

		(void) snprintf(ErrorString, sizeof (ErrorString),
		    "Unable to copy <%s>, can't open temp file <%s>.  %s.",
		    Filename, TempFile,
		    errMsg != NULL ? errMsg : "Unknown error");

		(void) fclose(in);
		return (-1);
	}

	if (in)	{
		/* Our input file exists */
		if (!CopyToSection(Section, in, out, DeleteSection?0:1)) {
			/*
			 * Section did not exist, make one
			 * If DeleteSection or DeleteLabel is set, it's a nop.
			 */

			if (!DeleteSection && !DeleteLabel) {
				(void)  fprintf(out, "[%s]\n", Section);
				(void)  fprintf(out, "%s=%s\n", Label, Data);
			}
		} else {
			if (DeleteSection) {
				/*
				 * Delete the section.
				 * Copy to EOF with NULL as the label
				 */
				CopyToEOF(in, out, NULL);
			} else {
				/*
				 * Section did exist, just dump label, and
				 * search for next section or same label line,
				 * so we can erase it.
				 */
				if (!DeleteLabel) {
					/*
					 * Dump the new label, only if
					 * we're not deleting it
					 */
					(void) fprintf(out, "%s=%s\n",
					    Label, Data);
				}
				CopyToEOF(in, out, Label);
			}
		}
		(void) fclose(in);
	} else {
		/* no input file, just put output */
		(void) fprintf(out, "[%s]\n", Section);
		(void) fprintf(out, "%s=%s\n", Label, Data);
	}

	(void) fclose(out);
	/*
	 * The rename could file for many reasons, but all of them are very
	 * bad ones.  Assume that Rename has set ErrorString.
	 */
	if (Rename(TempFile, Filename)) {
		return (-1);
	}
	/* Let our internal update set the return code now */
	return (IniUpdateLocalCopy(Filename, Section, Label, Data));
} /* IniUpdateFile */

/*
 * Function: Rename
 *
 * Arguments: char *source, char *dest
 *
 * Description: This function tries a rename.  If it fails, it tries a copy.
 *              It should never fail, since the temp file is in the same
 *              directory as the input file.
 *
 * Returns: int (zero on success)
 */
int
Rename(char *source, char *dest)
{
	int rc;
	if ((rc = rename(source, dest)) != 0) {
		/* Do copy! */
		FILE *in, *out;
		char buffer[BUFSIZ]; /* use the system BUFSIZ for efficiency */
		int nchars;

		in = fopen(source, "r");
		if (!in) {
			char *errMsg = strerror(errno);

			(void) snprintf(ErrorString, sizeof (ErrorString),
			    "Error opening source file <%s> for rename.  %s.",
			    source, errMsg != NULL ? errMsg : "Unknown error");

			return (-1);
		}
		out = fopen(dest, "w");
		if (!out) {
			char *errMsg = strerror(errno);

			(void)  fclose(in);
			(void)  unlink(dest);
			(void) snprintf(ErrorString, sizeof (ErrorString),
			    "Error opening target file <%s> for rename.  %s.",
			    dest, errMsg != NULL ? errMsg : "Unknown error");

			return (-2);
		}

		/* Ok, now do copy */
		do {
			nchars = fread(buffer, 1, BUFSIZ, in);
			if (nchars > 0) {
				rc = fwrite(buffer, 1, nchars, out);
				if (rc != nchars) {
					char *errMsg = strerror(errno);

					(void) snprintf(ErrorString,
					    sizeof (ErrorString),
					    "Error writing target file <%s> "
					    "during rename.  %s.", dest,
					    errMsg != NULL ? errMsg :
					    "Unknown error.");

					(void) fclose(in);
					(void) fclose(out);
					(void) unlink(source);
					return (rc);
				}
			}
		} while (nchars > 0);

		/* if fread() fails... */
		if (nchars < 0) {
			char *errMsg = strerror(errno);

			(void) snprintf(ErrorString, sizeof (ErrorString),
			    "Error reading source file <%s>.  %s.", source,
			    errMsg != NULL ? errMsg : "Unknown error");

			(void) fclose(in);
			(void) fclose(out);
			(void) unlink(source);
			return (nchars);
		}

		(void) fclose(in);
		(void) fclose(out);
		(void) unlink(source);
		rc = nchars;
	}

	return (rc);
} /* Rename */

/*
 * Function: dirname
 *
 * Arguments: char *FullPath
 *
 * Description: This function will return the directory name of the
 *              passed in filename.  This is for out temporary file.
 *              the reason it is not in /tmp or /usr/tmp is that
 *              MV does not work across filesystems.
 *
 * Returns: char *
 */
static char *
dirname(char *FullPath)
{
	int len;
	static char Dirname[MAX_FILENAME_LEN * 8];

	(void) strncpy(Dirname, FullPath, MAX_FILENAME_LEN * 8);
	Dirname[MAX_FILENAME_LEN * 8 - 1] = 0;

	for (len = strlen(Dirname); len; len--) {
		if (Dirname[len] == '/') {
			Dirname[len] = 0;
			return (Dirname);
		}
	}
	/*
	 * If we got here, then we searched the whole string, return NULL
	 */
	return (NULL);
} /* dirname */

/*
 * Function: RemoveSection
 *
 * Arguments: int SectionNdx, IniFileType *File
 *
 * Description: This function will remove a section from the given INI file.
 *              It does all the necessary garbage collection.
 *
 * Returns: int (zero on success)
 */
static int
RemoveSection(int SectionNdx, IniFileType *File)
{
	/* First, remove all the labels */
	if (File->Sections[SectionNdx].Labels)
		free(File->Sections[SectionNdx].Labels);

	/* Finally, remove the Section */
	if (File->NumSections &&
	    (SectionNdx < File->NumSections) &&
	    SectionNdx >= 0) {
		int NumToMove;
		NumToMove = File->NumSections - SectionNdx -1;
		/* Copy the rest down a notch */
		if (NumToMove > 0) {
			(void)  memcpy(&File->Sections[SectionNdx],
			    &File->Sections[SectionNdx+1],
			    sizeof (SectionType) * NumToMove);
		}
		/* Free the last one */
		File->NumSections--;
		return (0);
	} /* Sanity Check */
	(void) snprintf(ErrorString, sizeof (ErrorString),
	    "Unable to remove section <%s> in INI file <%s>",
	    File->Sections->SectionName, File->Filename);
	return (-1);
} /*RemoveSection*/
/*
 * Function: RemoveLabel
 *
 * Arguments: SectionType *Section, int LabelNdx
 *
 * Description: This function will remove a label from the given INI
 *              file.  (No GC is necessary, since the Arrays are Static)
 *
 * Returns: int
 */
static int
RemoveLabel(SectionType *Section, int LabelNdx)
{

	/* Sanity Check */
	if (Section->NumLabels &&
	    (LabelNdx < Section->NumLabels) &&
	    LabelNdx >= 0) {
		int NumToMove;
		NumToMove = Section->NumLabels - LabelNdx -1;
		/* Copy the rest down a notch */
		if (NumToMove > 0) {
			(void) memcpy(&Section->Labels[LabelNdx],
			    &Section->Labels[LabelNdx+1],
			    sizeof (LabelType) * NumToMove);
		}
		/* Free the last one */
		Section->NumLabels--;
		return (0);
	} /* Sanity Check */
	(void) snprintf(ErrorString, sizeof (ErrorString),
	    "Unable to remove label <%s> from INI file ",
	    Section->Labels->Label);
	return (-1);
} /* RemoveLabel */

/*
 * Function: IniUpdateLocalCopy
 *
 * Arguments: char *Filename, char *Section, char *Label, char *Data
 *
 * Description: This function will update the internal copy of the data
 *              we have.  (It is called form IniUpdateFile)
 *
 * Returns: int
 */
static int
IniUpdateLocalCopy(char *Filename, char *Section, char *Label, char *Data)
{
	IniFileList *FileProbe;
	IniFileType *File;
	int SectionNdx, LabelNdx;
	struct stat file_stats;
	int DeleteSection = 0;
	int DeleteLabel = 0;
	int rc;

	/* Set our deletion flags */
	if (!Label && !Data)
		DeleteSection = 1;

	if (!Data)
		DeleteLabel = 1;

	/*
	 * First, search for the file
	 */
	for (FileProbe = IniHead;
	    FileProbe;
	    FileProbe = FileProbe->Next) {
		if (strcmp(FileProbe->IniFile.Filename,
		    Filename) == 0)
			break;
	}

	if (!FileProbe) {
		/*
		 * We did not find the file.  Someone did a write without
		 * a read.  Return an error.  (The file is still written to,
		 * and the next read will parse it in.)
		 */
		(void) sprintf(ErrorString, "Warning: file not loaded.");
		return (0);
	}
	File = &FileProbe->IniFile;

	/*
	 * Now let's update our statistics, so our cache is up to date.
	 */
	if (stat(Filename, &file_stats) == (-1)) {
		char *errMsg = strerror(errno);

		(void) snprintf(ErrorString, sizeof (ErrorString),
		    "Error: Unable to retrieve statistics on <%s>.  %s.",
		    Filename, errMsg != NULL ? errMsg : "Unknown error");

		return (-2);
	} else
		File->ModificationTime = file_stats.st_mtime;

	/*
	 * now, File contains our file pointer.	 Check
	 * to see if our section exists.
	 */
	for (SectionNdx = 0; SectionNdx < File->NumSections; SectionNdx++) {
		if (strcmp(Section,
		    File->Sections[SectionNdx].SectionName) == 0) {
			/* We have the section! */
			break;
		}
	}
	if (SectionNdx >= File->NumSections) {
		if (DeleteSection || DeleteLabel) {
			(void) snprintf(ErrorString, sizeof (ErrorString),
			    "Error IniUpdateLocalCopy: "
			    "Section not found in <%s>",
			    Filename);
			return (-1); /* Error, not found */
		}

		/* Oops New Section/Label! */
		SectionNdx = AddSection(File, Section);
		if (SectionNdx < 0)
			return (SectionNdx);
		(void)  AddLabel(File, SectionNdx, Label, Data);
	} else {
		if (DeleteSection) {
			return (RemoveSection(SectionNdx, File));
		}
		/* We have the section.	 Search for the label */
		for (LabelNdx = 0;
		    LabelNdx < File->Sections[SectionNdx].NumLabels;
		    LabelNdx++) {
			if (strcasecmp(Label,
			    File->Sections[SectionNdx].Labels[LabelNdx].Label)
			    == 0) {
				if (DeleteLabel) {
					return (RemoveLabel(
						&File->Sections[SectionNdx],
						    LabelNdx));
				}

				/* Found the label.  Update the data */
				ModifyLabel(File, SectionNdx, LabelNdx, Data);
				break;
			}
		}
		if (LabelNdx >= File->Sections[SectionNdx].NumLabels) {
			if (DeleteLabel) {
				(void) snprintf(ErrorString,
				    sizeof (ErrorString),
				    "Error IniUpdateLocalCopy: "
				    "Label not found in <%s>",
				    Filename);
				return (-1); /* Error, not found */
			}
			/* Need to add a label! */
			rc = AddLabel(File, SectionNdx, Label, Data);
			if (rc < 0)
				return (rc);
		}
	}
	return (0);
} /* IniUpdateLocalCopy */

/*
 * Function: AddSection
 *
 * Arguments: IniFileType *IniFile, char *Section
 *
 * Description: This function will add a section to the passed in file.
 *
 * Returns: int
 */
static int
AddSection(IniFileType *IniFile, char *Section)
{
	SectionType *SectionPointer;

	/*
	 * Set up new section Array
	 */
	SectionPointer = malloc(sizeof (SectionType) *
	    (IniFile->NumSections + 1));
	if (!SectionPointer) {
		(void) strcpy(ErrorString, "Out of memory allocating section.");
		return (-1);
	}
	/*
	 * Copy old sections over - including pointers
	 */
	if (IniFile->NumSections) {
		(void) memcpy(SectionPointer, IniFile->Sections,
		    IniFile->NumSections * sizeof (SectionType));
		free(IniFile->Sections); /* Free the old sections Array */
	}
	/*
	 * Update new section
	 */
	(void) memset(SectionPointer[IniFile->NumSections].SectionName, '0',
	    MAX_FILENAME_LEN);
	(void) strncpy(SectionPointer[IniFile->NumSections].SectionName,
	    Section,
	    MAX_SECTION_LEN);
	SectionPointer[
		IniFile->NumSections].SectionName[MAX_SECTION_LEN - 1] = 0;
	SectionPointer[IniFile->NumSections].Labels = NULL;
	SectionPointer[IniFile->NumSections].NumLabels = 0;

	IniFile->NumSections++;
	IniFile->Sections = SectionPointer; /* Update array pointer */

	/* Return an index to the newly added one */
	return (IniFile->NumSections-1);
} /* AddSection */

/*
 * Function: AddLabel
 *
 * Arguments: IniFileType *IniFile, int SectionNdx, char *Label, char *Data
 *
 * Description: This function adds a label to a section.
 *
 * Returns: static int
 */
static int
AddLabel(IniFileType *IniFile, int SectionNdx, char *Label, char *Data)
{
	SectionType *SectionPointer;
	LabelType *LabelPointer;

	/*
	 * Set up CurrentSection pointer for ease of typing.
	 */
	SectionPointer = &IniFile->Sections[SectionNdx];

	/*
	 * Allocate enough room for new label
	 */
	LabelPointer = malloc(sizeof (LabelType) *
	    (SectionPointer->NumLabels+1));
	if (!LabelPointer) {
		(void) strcpy(ErrorString, "Out of memory allocating label.");
		return (-3);
	}
	if (SectionPointer->NumLabels) {
		/* Do the copy */
		(void) memcpy(LabelPointer, SectionPointer->Labels,
		    sizeof (LabelType) * SectionPointer->NumLabels);
		free(SectionPointer->Labels);
	}

	(void) memset(LabelPointer[SectionPointer->NumLabels].Label, 0,
	    MAX_LABEL_LEN);
	(void) memset(LabelPointer[SectionPointer->NumLabels].Value, 0,
	    MAX_VALUE_LEN);
	(void) strlcpy(LabelPointer[SectionPointer->NumLabels].Label,
	    Label, MAX_LABEL_LEN);
	(void) strlcpy(LabelPointer[SectionPointer->NumLabels].Value,
	    Data, MAX_VALUE_LEN);

	SectionPointer->NumLabels++;
	SectionPointer->Labels = LabelPointer;

	/* return the index of the new label */
	return (SectionPointer->NumLabels-1);
} /* AddLabel */

/*
 * Function: ModifyLabel
 *
 * Arguments: IniFileType *IniFile, int SectionNdx, int LabelNdx, char *Data
 *
 * Description: This function will just modify the data of a label in memory.
 *
 * Returns: void
 */
static void
ModifyLabel(IniFileType *IniFile, int SectionNdx, int LabelNdx, char *Data)
{
	(void) memset(IniFile->Sections[SectionNdx].Labels[LabelNdx].Value,
	    0, MAX_VALUE_LEN);
	(void) strlcpy(IniFile->Sections[SectionNdx].Labels[LabelNdx].Value,
	    Data, MAX_VALUE_LEN);
} /* ModifyLabel */

/*
 * Function: SectionCmp
 *
 * Arguments: char *line, char *Section
 *
 * Description: This function returns zero if the line is a section line,
 *              and contains our section.
 *
 * Returns: int
 */
static int
SectionCmp(char *line, char *Section)
{
	char TempLabel[MAX_LABEL_LEN], TempValue[MAX_LABEL_LEN];

	switch (ParseLine(line, TempLabel, TempValue)) {
	case INI_SECTION:
		return (strcmp(Section, TempLabel));
	default: /* Not a section */
		return (-1);
	}

} /* SectionCmp */

/*
 * Function: CopyToSection
 *
 * Arguments: char *Section, FILE *in, FILE *out, int CopySection
 *
 * Description: Copies the files from in to out, until it gets to
 *              the namedSection.  If CopySection is non-zero, it
 *              will also copy the section line.  If it is zero
 *              the section line will not be copied (for deletion)
 *
 * Returns: int (non-zero if the section was found)
 */
static int
CopyToSection(char *Section, FILE *in, FILE *out, int CopySection)
{
	char tempbuffer[MAX_VALUE_LEN + MAX_LABEL_LEN];

	while (fgets(tempbuffer, MAX_VALUE_LEN + MAX_LABEL_LEN, in)) {
		if (!(SectionCmp(tempbuffer, Section))) {
			/* We have the section */
			if (CopySection)
				(void)  fputs(tempbuffer, out);

			return (TRUE);
		}
		(void) fputs(tempbuffer, out);
	}

	return (FALSE);
} /* CopyToSection */

/*
 * Function: CopyToEOF
 *
 * Arguments: FILE *in, FILE *out, char *Label
 *
 * Description: Copies from *in to *out, deleting Label in the current
 *              section.  If Lable is NULL, then all labels are deleted until
 *              the next section is reached.
 *
 * Returns: void
 */
static void
CopyToEOF(FILE *in, FILE *out, char *Label)
{
	char tempbuffer[BUF_LEN];
	int SectionFound = FALSE;
	char TempLabel[MAX_LABEL_LEN];
	char TempValue[MAX_VALUE_LEN];


	while (fgets(tempbuffer, BUF_LEN - 1, in)) {
		if (!SectionFound) {
			switch (ParseLine(tempbuffer, TempLabel, TempValue)) {
			case INI_SECTION:
				(void) fputs(tempbuffer, out);
				SectionFound = TRUE;
				break;
			case INI_LABEL:
				if (Label) {
					/*
					 * If label is non-null, then copy
					 * everything EXCEPT the given label.
					 */
					if (strcasecmp(Label, TempLabel)) {
						(void) fputs(tempbuffer, out);
					}
				}
				break;
			default:
				(void) fputs(tempbuffer, out);
				break;
			}
		} else {
			/*
			 * If the next section has been found,
			 * just write everything
			 */
			(void) fputs(tempbuffer, out);
		} /* if SectionFound */
	} /* end While */
} /* CopyToEOF */


/*
 * Function: GetSectionList
 *
 * Arguments: IniFileType *IniFile, char *argv, int *NumSections,
 *            int *elementSize
 *
 * Description: This routine returns a list of sections in a newly
 *              allocated array.
 *
 * Returns: char *, and modifies NumSections and elementSize
 */
static char *
GetSectionList(IniFileType *IniFile, char *argv, int *NumSections,
    int *elementSize)
{
	int i;

	/*
	 * Do garbage collection
	 */
	if (argv) {
		free(argv);
	}
	argv = NULL;

	if (!IniFile->NumSections)
		return (argv);

	argv = calloc(1, IniFile->NumSections*MAX_FILENAME_LEN);
	if (!argv) {
		(void) sprintf(ErrorString,
		    "Out of memory getting section list.");

		return (NULL);
	}
	for (i = 0; i < IniFile->NumSections; i++) {
		(void) strlcpy(&argv[i*MAX_FILENAME_LEN],
		    IniFile->Sections[i].SectionName,
		    MAX_FILENAME_LEN);
	}
	*NumSections = IniFile->NumSections;
	*elementSize = MAX_FILENAME_LEN;
	return (argv);
} /* GetSectionList */

/*
 * Function: IniLoaded
 *
 * Arguments: char *Filename
 *
 * Description: Returns true if the specified file is loaded and has
 *              not changed.
 *
 * Returns: int
 */
static int
IniLoaded(char *Filename)
{
	IniFileList *Probe;

	for (Probe = IniHead; Probe; Probe = Probe->Next) {
		if (strcmp(Filename, Probe->IniFile. Filename) == 0) {
			if (FileHasChanged(Probe->IniFile.ModificationTime,
			    Filename)) {
				return (FALSE);
			} else {
				return (TRUE);
			}
		}
	}
	return (FALSE);
} /* IniLoaded */


/*
 * Function: IniCheckComment
 *
 * Arguments: char *buffer
 *
 * Description: Returns true if the given line is a comment, or if it is
 *              blank.  Also removes any partial-line comments by
 *              replacing the semi-colon with a NULL;
 *
 *              A comment is of the form :
 *                  ; comment
 *               or
 *                  # comment
 *
 * Returns: int
 */
static int
IniCheckComment(char *buffer)
{
	int i;

	for (i = 0; buffer[i] && (buffer[i] != '\n'); i++) {
		if (buffer[i] == ';' || buffer[i] == '#') {
			if (i) {
				/* check for \; or \# */
				if (buffer[i-1] == '\\')
					continue;
			}
			/*
			 * Otherwise, mark it as a null, and check for an
			 * empty string
			 */
			buffer[i] = 0;
			break;
		}
	}

	for (i = 0; buffer[i] && (buffer[i] != '\n'); i++) {
		if (!isspace(buffer[i]))
			return (0);
	}

	return (1); /* This is a blank (or commented) line */
} /* IniCheckComment */

/*
 * Function: IniUnloadFile
 *
 * Arguments: char *Filename
 *
 * Description:  This routine will remove an ini file from our list,
 *               and free up memory.
 *
 * Returns: int (zero on success)
 */
static int
IniUnloadFile(char *Filename)
{
	IniFileList *File;

	File = UnlinkFile(Filename);
	if (!File)
		return (-1);
	IniFreeFile(File);
	return (0);
} /* IniUnloadFile */

/*
 * Function: IniFreeFile
 *
 * Arguments: IniFileList *File
 *
 * Description: Does the garbage collection on a file.  (frees all data)
 *
 * Returns: void
 */
static void
IniFreeFile(IniFileList *File)
{
	int CurrentSection;

	/*
	 * Now, free up all the memory
	 */
	for (CurrentSection = 0; CurrentSection < File->IniFile.NumSections;
	    CurrentSection++) {
		/*
		 * Free up label array
		 */
		if (File->IniFile.Sections[CurrentSection].Labels)
			free(File->IniFile.Sections[CurrentSection].Labels);
	}

	/* Now free up the sections */
	if (File->IniFile.Sections)
		free(File->IniFile.Sections);

	/* and finally... */
	free(File);

} /* IniFreeFile */

/*
 * Function: UnlinkFile
 *
 * Arguments: char *Filename
 *
 * Description:  This routine will remove the file from the linked list, and
 *               return a pointer to it, so it can be freed.
 *
 * Returns: IniFileList *
 */
static IniFileList *
UnlinkFile(char *Filename)
{
	IniFileList *Probe;
	IniFileList *PrevProbe = NULL;

	for (Probe = IniHead; Probe; Probe = Probe->Next) {
		if (strcmp(Filename, Probe->IniFile.Filename) == 0) {
			if (!PrevProbe) {
				IniHead = Probe->Next;
			} else {
				PrevProbe->Next = Probe->Next;
			}
			return (Probe);
		}
		PrevProbe = Probe;
	}
	return (NULL);
} /* UnlinkFile */

/*
 * Function: GetSectionProfileString
 *
 * Arguments: char *Section, char *Label, dest, destLen
 *
 * Description: This function is part of GetPrivateProfileString.  It was
 *              Only Added to improve the C-Style formatting.  (Fors got
 *              nested too deep.)
 *
 * Returns: static int
 */
static int
GetSectionProfileString(IniFileList *IniFile, char *Section, char *Label,
    char *dest, int destLen)
{
	int i;

	/* We have the file */
	for (i = 0; i < IniFile->IniFile.NumSections; i++) {
		if (strcasecmp(Section,
		    IniFile->IniFile.Sections[i].SectionName)
		    == 0) {
			return (GetLabelProfileString(IniFile,
			    i, Label, dest, destLen));
		}
	} /* end section for */

	(void) snprintf(ErrorString, sizeof (ErrorString),
		"Unable to find section <%s>.", Section);

	return (-1);
} /* GetSectionProfileString */

/*
 * Function: GetLabelProfileString
 *
 * Arguments: char *Section, char *Label, char *dest, int destLen
 *
 * Description: This function is part of GetPrivateProfileString.  It was
 *              Only Added to improve the C-Style formatting.  (Fors got
 *              nested too deep.)
 *
 * Returns: static int
 */
static int
GetLabelProfileString(IniFileList *IniFile, int si, char *Label,
    char *dest, int destLen)
{
	int j;

	/* We have the section */
	for (j = 0;
	    j < IniFile->IniFile.Sections[si].NumLabels;
	    j++) {
		if (strcasecmp(Label,
		    IniFile->IniFile.Sections[si].Labels[j].Label) == 0) {
			/* We finally have it! */
			(void) strncpy(dest,
			    IniFile->IniFile.Sections[si].Labels[j].Value,
			    destLen);
			return (0);
		}
	} /* end label for */

	(void) snprintf(ErrorString, sizeof (ErrorString),
		"Unable to find label <%s>.", Label);

	return (-1);
} /* GetLabelProfileString */

/*
 *
 *		     E X T E R N A L   F U N C T I O N S
 *
 *  These functions are called by external programs.  (They are non-static)
 *
 */



/*
 * Function: WritePrivateProfileString
 *
 * Arguments: char *Section, char *Label, char *data
 *
 * Description: Sets the new string into [Section] Label=data
 *
 * Returns: int (zero on success)
 */
int
WritePrivateProfileString(char *Section, char *Label, char *data,
    char *Filename)
{
	/*
	 * Unload the file, if it is loaded.  The next read will load it.
	 */

	return (IniUpdateFile(Filename, Section, Label, data));
} /* WritePrivateProfileString */

/*
 * Function: DeletePrivateProfileSection
 *
 * Arguments: char *Section, char *Filename
 *
 * Description: Deletes an entire section (and all labels)
 *
 * Returns: int (zero on success)
 */
int
DeletePrivateProfileSection(char *Section, char *Filename)
{
	return (IniUpdateFile(Filename, Section, NULL, NULL));
} /* DeletePrivateProfileSection*/

/*
 * Function: DeletePrivateProfileLabel
 *
 * Arguments: char *Section, char *Label, char *Filename
 *
 * Description: Deletes a label from a section.
 *
 * Returns: int (zero on success)
 */
int
DeletePrivateProfileLabel(char *Section, char *Label, char *Filename)
{
	return (IniUpdateFile(Filename, Section, Label, NULL));
} /* DeletePrivateProfileLabel */

/*
 * Function: WritePrivateProfileInt
 *
 * Arguments: char *Section, char *Label, int data, char *Filename
 *
 * Description: Sets the new int into [Section] Label=data
 *
 * Returns: int (zero on success)
 */
int
WritePrivateProfileInt(char *Section, char *Label, int data, char *Filename)
{
	char Tempbuffer[MAX_LONG_LEN]; /* we only need 10 + a negative sign */

	(void) sprintf(Tempbuffer, "%d", data);
	return (IniUpdateFile(Filename, Section, Label, Tempbuffer));
} /* WritePrivateProfileInt */

/*
 * Function: GetPrivateProfileString
 *
 * Arguments: char *Section, char *Label, char *defaultValue
 *
 * Description: retrieves data from a section
 *
 * Returns: int (zero on success)
 */
int
GetPrivateProfileString(char *Section, char *Label, char *defaultValue,
    char *dest, int destLen, char *Filename)
{
	IniFileList *IniFile;
	char errMsg[ERROR_SUBSTRING_LEN];
	int rc;

	/*
	 * First, Lookup the file, then lookup the section,
	 * then lookup the label, then copy the string
	 */

	ErrorString[0] = 0;  /* Clear the error string */

	/* set default value */
	(void) strlcpy(dest, defaultValue, destLen);

	if (!IniLoaded(Filename)) {
		rc = IniLoadFile(Filename);
		if (rc < 0) {
			return (rc);
		}
	}

	for (IniFile = IniHead; IniFile; IniFile = IniFile->Next) {
		if (strcmp(Filename, IniFile->IniFile.Filename) == 0)
			return (GetSectionProfileString(IniFile, Section,
			    Label, dest, destLen));
	} /* end file for */

	/*
	 * IniLoaded() and IniLoadFile() call FileHasChanged() which may have
	 * something to say via ErrorString - don't overwrite it!
	 */
	(void) snprintf(errMsg, ERROR_SUBSTRING_LEN,
	    "Unable to find file <%s>.  ", Filename);

	strlcat(ErrorString, errMsg, sizeof (ErrorString));

	return (-1);
} /* GetPrivateProfileString */

/*
 * Function: GetPrivateProfileInt
 *
 * Arguments: char *Section, char *Label, int defaultValue
 *
 * Description: Returns the int associated with [Section], Label=Int
 *
 * Returns: int
 */
int
GetPrivateProfileInt(char *Section, char *Label, int defaultValue,
    char *Filename)
{
	char String[MAX_LONG_LEN];

	(void)  GetPrivateProfileString(Section, Label, "", String,
	    MAX_LONG_LEN, Filename);

	if (!String[0]) /* Our default return value is "" */
		return (defaultValue);
	else
		return (atoi(String));
} /* GetPrivateProfileInt */

/*
 * Function: IniListSections
 *
 * Arguments: char *Filename, int *NumSections, int *elementSize
 *
 * Description: Returns a list of sections. (allocates an array)
 *
 * Returns: char *
 */
char *
IniListSections(char *Filename, int *NumSections, int *elementSize)
{
	static char *argv = NULL;
	IniFileList *IniFile;
	char errMsg[ERROR_SUBSTRING_LEN];
	int rc;

	if (!IniLoaded(Filename)) {
		rc = IniLoadFile(Filename);
		if (rc < 0) {
			return (NULL);
		}
	}
	for (IniFile = IniHead; IniFile; IniFile = IniFile->Next) {
		if (strcmp(Filename, IniFile->IniFile.Filename) == 0) {
			argv = GetSectionList(&IniFile->IniFile, argv,
			    NumSections, elementSize);
			return (argv);
		}
	}

	/*
	 * IniLoaded() and IniLoadFile() call FileHasChanged() which may have
	 * something to say via ErrorString - don't overwrite it!
	 */
	(void) snprintf(errMsg, sizeof (ErrorString),
	    "Unable to find file <%s>.  ", Filename);

	strlcat(ErrorString, errMsg, sizeof (ErrorString));

	return (NULL);
} /* IniListSections */


/*
 * Function: parsealg
 *
 * Arguments: char *algname, struct ipsec_alg *table
 *
 * Description: finds the ipsec algorithm value associated with the ipsec
 *     algorithm string.
 *
 * Returns: valid alg value on success, -1 on failure.
 */
int
parsealg(char *algname, struct ipsec_alg *table)
{
	struct ipsec_alg *ep;

	if ((algname == NULL) || (table == NULL))
		return (-1);

	for (ep = table; ep->alg != NULL; ep++) {
		if (strcasecmp(ep->alg, algname) == 0)
			return (ep->value);
	}

	/* no match */
	return (-1);
}


/*
 * Function: parse_algs
 *
 * Arguments: int which_alg, int alg, ipsec_req_t *ipsr
 *
 * Description: sets the values in the ipsec_req_t passed in based on
 *	the algorithm, and which protection scheme it belongs to (ah_auth,
 *	esp_auth, or esp_encr.  SA is also passed through here as a sanity
 *	check measure, and because of the way the parsing routines are
 *	designed - the user specifies all this as part of a the properties
 *	of a single IPsec policy.
 *
 * Returns: valid alg value on success, -1 on failure.
 */
int
parse_algs(int which_alg, int alg, ipsec_req_t *ipsr)
{
	if (alg == -1)
		/* alg is bad */
		return (-1);

	if (ipsr == NULL)
		/* user didn't pass a pointer to set, alg is valid, OK */
		return (0);

	switch (which_alg) {
	case ESP_ENCR_ALG:
		if (alg == NO_ESP_AALG) {
			if (ipsr->ipsr_esp_auth_alg == SADB_AALG_NONE)
				ipsr->ipsr_esp_req = 0;
			ipsr->ipsr_esp_alg = SADB_EALG_NONE;
		} else {
			ipsr->ipsr_esp_req =
			    IPSEC_PREF_REQUIRED | IPSEC_PREF_UNIQUE;
			ipsr->ipsr_esp_alg = alg;
		}
		break;

	case ESP_AUTH_ALG:
		if (alg == NO_ESP_AALG) {
			if (ipsr->ipsr_esp_alg == SADB_EALG_NONE ||
			    ipsr->ipsr_esp_alg == SADB_EALG_NULL)
				ipsr->ipsr_esp_req = 0;
			ipsr->ipsr_esp_auth_alg = SADB_AALG_NONE;
		} else {
			ipsr->ipsr_esp_req =
			    IPSEC_PREF_REQUIRED | IPSEC_PREF_UNIQUE;
			ipsr->ipsr_esp_auth_alg = alg;

			/* Let the user specify NULL encryption implicitly. */
			if (ipsr->ipsr_esp_alg == SADB_EALG_NONE &&
			    !encr_alg_set)
				ipsr->ipsr_esp_alg = SADB_EALG_NONE;
		}
		break;

	case AH_AUTH_ALG:
		if (alg == NO_AH_AALG) {
			ipsr->ipsr_ah_req = 0;
			ipsr->ipsr_auth_alg = SADB_AALG_NONE;
		} else {
			ipsr->ipsr_ah_req =
			    IPSEC_PREF_REQUIRED | IPSEC_PREF_UNIQUE;
			ipsr->ipsr_auth_alg = alg;
		}
		break;

	case SA_ALG:
		if ((alg != SADB_SA_SHARED) &&
		    (alg != SADB_SA_UNIQUE))
			return (-1);
		break;

	default:
		/* don't know what to do!  Fail. */
		return (-1);
	}
	return (0);
}

/* ipsec algorithm parsing routines */
int
parse_esp_encr_alg(char *which_alg, ipsec_req_t *ipsr)
{
	return (parse_algs(ESP_ENCR_ALG, parsealg(which_alg, encr_algs), ipsr));
}

int
parse_esp_auth_alg(char *which_alg, ipsec_req_t *ipsr)
{
	return (parse_algs(ESP_AUTH_ALG, parsealg(which_alg, auth_algs), ipsr));
}

int
parse_ah_alg(char *which_alg, ipsec_req_t *ipsr)
{
	return (parse_algs(AH_AUTH_ALG, parsealg(which_alg, auth_algs), ipsr));
}

int
parse_sa_alg(char *which_alg, ipsec_req_t *ipsr)
{
	return (parse_algs(SA_ALG, parsealg(which_alg, sa_algs), ipsr));
}


/*
 * Function: isIPsecActionValid
 *
 * Parameters: action - the string containing the action in question.
 *
 * Description: Verifies the action is a valid ipsec action.  Note that this
 *		function is NOT tollerant to leading whitespace!
 *
 * Returns: 0 on failure.
 *          strlen of the action on success (so the caller can index past it).
 */
uint_t
isIPsecActionValid(char *action)
{
	int i;
	char *cp = action;

	for (i = 0; validIPsecAction[i] != NULL; i++) {
		/* match check */
		if (strncasecmp(cp, validIPsecAction[i],
		    strlen(validIPsecAction[i])) == 0)
			return (strlen(validIPsecAction[i]));

		/* try the next action */
	}

	return (0);
}

/*
 * Function: parseIPsecProps
 *
 * Parameters:	props - the string containing "{<props>}" for validation.
 *		ipsr  - place to put parsed policy, NULL if not required.
 *			In this case parseIPsecProps() just tests to see
 *			if props are valid.
 *
 * Description: Verify properties are valid, and if so, put their values
 *              in the struct ipsec_req_t passed in.  Valid properties are
 *		of the form "<tag> <alg>".  Supported <tags> are in ipseccmd[],
 *		and the corresponding algs are in auth_algs[], and encr_algs[].
 *		Note: this function is tollerant to properties begining with
 *		blank spaces, but an open bracket MUST preceed <tag><alg>.
 *
 * Returns: 0 on failure in which case the values in ipsr are incomplete.
 *	    number of bytes parsed on success in which case the values in ipsr,
 *	    if passed in, are complete.
 */
int
parseIPsecProps(char *props, ipsec_req_t *ipsr)
{
	struct ipsec_cmd *cmd;
	char *p, *freeP, *deltaP = 0, *lasts;
	int bytes_parsed = 0, ioff = 0, ret;
	boolean_t bopen_found = _B_FALSE, bclose_found = _B_FALSE;

	p = strdup(props);

	if (p == NULL)
		return (0);

	freeP = p;  /* strtok_r() is destructive */

	while ((p = strtok_r(p, " ", &lasts)) != NULL) {
		/*
		 * What did strtok_r() return if we have "   { <properties..."?
		 * Skip white-space in general.		^^^
		 */
		if ((*p != '\0') && (isspace(*p))) {
			deltaP = p + strlen(p);
			p = NULL;
			continue;
		}

		if (!bopen_found) {
			/* Every property begins with an open-bracket */
			if (*p != '{') {
				free(freeP);
				return (0);
			}
			bopen_found = _B_TRUE;
			/* move on */
			p++;
		}

		if (*p == '}') {
			/* this means we should be done */
			if ((!bopen_found) || (bclose_found)) {
				free(freeP);
				return (0);
			}

			bclose_found = _B_TRUE;

			deltaP = p + strlen(p);

			p = NULL;
			continue;
		}

		if (bclose_found) {
			/* Stuff after the close! */
			free(freeP);
			return (0);
		}

		/* once for each <tag> the user wants set */
		for (cmd = ipseccmd; cmd->c_func != NULL; cmd++) {
			/* valid <tag>? */
			if ((cmd->c_name) &&
			    (strcasecmp(cmd->c_name, p) == 0)) {
				/* <alg> follows <tag>> */
				p = NULL;
				p = strtok_r(p, " ", &lasts);

				if (p == NULL) {
					/* nothing follows <tag> = error */
					free(freeP);
					return (0);
				}

				/* last <alg> may have a "}" at the end */
				if (strcmp(&p[strlen(p)-1], "}") == 0) {
					if (bclose_found) {
						/* already found one = fail */
						free(freeP);
						return (0);
					}
					bclose_found = _B_TRUE;

					/* char shortcuts are cool */
					p[strlen(p)-1] = NULL;
					ioff = 1;
				}

				/*
				 * Call the parse command for this <alg>, but
				 * only if we're filling in the ipsec_req_t.
				 */
				if (ipsr == NULL)
					/* make sure it's valid in context */
					ret = parsealg(p, encr_algs);
				else
					/* also parse it into ipsr */
					ret = (*cmd->c_func)(p, ipsr);

				if (ret < 0) {
					/* the parse command failed */
					free(freeP);
					return (0);
				} else {
					/* how far have we've come */
					deltaP = p + strlen(p) + ioff;

					/* parsed->next */
					p = NULL;
					break;
				}
			}
		}

		/* cmd->c_func = NULL, next alg */
		p = NULL;
	}

	/* calculate how many bytes we've parsed */
	bytes_parsed = deltaP - freeP;

	/* finished with this */
	free(freeP);

	/* reset the per-policy parsing boolean */
	encr_alg_set = FALSE;

	/* as long as we got to a valid close bracket, we're fine */
	if (!bclose_found)
		return (0);

	return (bytes_parsed);
}

/*
 * Function:isIPsecPolicyValid
 *
 * Arguments:	policy  what the user is trying to set as policy properties.
 *
 * Description: This function validates an IPSec policy.  The policy MUST be
 *		a single valid action, followed by a valid set of properties
 *              as specified by ipsec(7P).  Note that we don't necessarily
 *		support all the actions that ipsec supports, see
 *		validIPsecActions[].
 *
 * Returns: _B_TRUE if the policy is valid, _B_FALSE if the policy is not.
 *
 * Note: this function only exists because ipSec has no API at this time.
 */
boolean_t
isIPsecPolicyValid(char *policy, ipsec_req_t *ipsr)
{
	int c_len = 0;
	char *cp;

	if (policy == NULL)
		return (_B_FALSE);

	/* Parse the policy */
	cp = policy;

	/* actions first */
	if ((c_len = isIPsecActionValid(cp)) == 0)
		return (_B_FALSE);

	cp += c_len;

	while (isspace(*cp))
		cp++;

	/* now "{<properties>}" */
	if ((c_len = parseIPsecProps(cp, ipsr)) == 0)
		return (_B_FALSE);

	cp += c_len;

	/* trailing blanks are OK... */
	while (isspace(*cp))
		cp++;

	/* ...but nothing else! */
	return (*cp == '\0');
}
