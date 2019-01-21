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
 *	Copyright (c) 1988 AT&T
 *	  All Rights Reserved
 *
 * Copyright (c) 1995, 2010, Oracle and/or its affiliates. All rights reserved.
 */

#include <errno.h>
#include "alist.h"
#include "mcs.h"
#include "extern.h"
#include "gelf.h"

/*
 * Type used to pass state information for the current
 * file between routines.
 */
typedef struct {
	int		Sect_exists;
	int		notesegndx;
	int		notesctndx;
	Seg_Table	*b_e_seg_table;
	section_info_table *sec_table;
	int64_t		*off_table;	/* maintains section's offset; set to */
					/*	retain old offset, else 0 */
	int64_t		*nobits_table;	/* maintains NOBITS sections */
	char		*new_sec_string;
} file_state_t;


/*
 * Function prototypes.
 */
static void copy_file(int, char *, Tmp_File *);
static void
copy_non_elf_to_temp_ar(int, Elf *, int, Elf_Arhdr *, char *, Cmd_Info *);
static void copy_elf_file_to_temp_ar_file(int, Elf_Arhdr *, char *);
static int process_file(Elf *, char *, Cmd_Info *);
static void initialize(int shnum, Cmd_Info *, file_state_t *);
static int build_segment_table(Elf*, GElf_Ehdr *, file_state_t *);
static int traverse_file(Elf *, GElf_Ehdr *, char *, Cmd_Info *,
    file_state_t *);
static uint64_t location(int64_t, int, Elf *, file_state_t *);
static uint64_t scn_location(Elf_Scn *, Elf *, file_state_t *);
static int build_file(Elf *, GElf_Ehdr *, Cmd_Info *, file_state_t *);
static void post_process(Cmd_Info *, file_state_t *);



int
each_file(char *cur_file, Cmd_Info *cmd_info)
{
	Elf *elf = 0;
	Elf_Cmd cmd;
	Elf *arf = 0;
	Elf_Arhdr *mem_header;
	char *cur_filenm = NULL;
	int code = 0;
	int error = 0, err = 0;
	int ar_file = 0;
	int fdartmp;
	int fd;
	int oflag;

	if (cmd_info->flags & MIGHT_CHG)
		oflag = O_RDWR;
	else
		oflag = O_RDONLY;

	if ((fd = open(cur_file, oflag)) == -1) {
		error_message(OPEN_ERROR, SYSTEM_ERROR, strerror(errno),
		    prog, cur_file);
		return (FAILURE);
	}

	/*
	 * Note, elf_begin requires ELF_C_READ even if MIGHT_CHK is in effect.
	 * libelf does not allow elf_begin() with ELF_C_RDWR when processing
	 * archive file members.  Because we are limited to ELF_C_READ use, any
	 * ELF data modification must be provided by updating a copy of
	 * the data, rather than updating the original file data.
	 */
	cmd = ELF_C_READ;
	if ((arf = elf_begin(fd, cmd, NULL)) == NULL) {
		error_message(LIBELF_ERROR, LIBelf_ERROR, elf_errmsg(-1), prog);
		(void) elf_end(arf);
		(void) close(fd);   /* done processing this file */
		return (FAILURE);
	}

	if ((elf_kind(arf) == ELF_K_AR)) {
		ar_file = 1;
		if (CHK_OPT(cmd_info, MIGHT_CHG)) {
			artmpfile.tmp_name = tempnam(TMPDIR, "mcs2");
			if ((fdartmp = open(artmpfile.tmp_name,
			    O_WRONLY | O_APPEND | O_CREAT,
			    (mode_t)0666)) == 0) {
				error_message(OPEN_TEMP_ERROR,
				    SYSTEM_ERROR, strerror(errno),
				    prog, artmpfile);
				(void) elf_end(arf);
				(void) close(fd);
				mcs_exit(FAILURE);
			}
			artmpfile.tmp_unlink = 1;
			/* write magic string to artmpfile */
			if ((write(fdartmp, ARMAG, SARMAG)) != SARMAG) {
				error_message(WRITE_ERROR,
				    SYSTEM_ERROR, strerror(errno),
				    prog, artmpfile.tmp_name, cur_file);
				mcs_exit(FAILURE);
			}
		}
	} else {
		ar_file = 0;
		cur_filenm = cur_file;
	}

	/*
	 * Holds temporary file;
	 * if archive, holds the current member file if it has an ehdr,
	 * and there were no errors in
	 * processing the object file.
	 */
	elftmpfile.tmp_name = tempnam(TMPDIR, "mcs1");

	while ((elf = elf_begin(fd, cmd, arf)) != 0) {
		if (ar_file) /* get header info */ {
			size_t	len;

			if ((mem_header = elf_getarhdr(elf)) == NULL) {
				error_message(GETARHDR_ERROR, LIBelf_ERROR,
				    elf_errmsg(-1), prog, cur_file,
				    elf_getbase(elf));
				(void) elf_end(elf);
				(void) elf_end(arf);
				(void) close(fd);
				free_tempfile(&artmpfile);
				return (FAILURE);
			}

			if (cur_filenm != NULL)
				free(cur_filenm);

			len = (strlen(cur_file) + 3 +
			    strlen(mem_header->ar_name));

			if ((cur_filenm = malloc(len)) == NULL) {
				error_message(MALLOC_ERROR,
				    PLAIN_ERROR, NULL, prog);
				mcs_exit(FAILURE);
			}

			(void) snprintf(cur_filenm, len, "%s[%s]",
			    cur_file, mem_header->ar_name);
		}

		if (elf_kind(elf) == ELF_K_ELF) {
			if ((code = process_file(elf, cur_filenm, cmd_info)) ==
			    FAILURE) {
				if (!ar_file) {
					(void) elf_end(arf);
					(void) elf_end(elf);
					(void) close(fd);
					return (FAILURE);
				} else {
					copy_non_elf_to_temp_ar(fd, elf,
					    fdartmp, mem_header,
					    cur_file, cmd_info);
					error++;
				}
			} else if (ar_file && CHK_OPT(cmd_info, MIGHT_CHG)) {
				if (code == DONT_BUILD)
					copy_non_elf_to_temp_ar(fd, elf,
					    fdartmp, mem_header,
					    cur_file, cmd_info);
				else
					copy_elf_file_to_temp_ar_file(
					    fdartmp, mem_header, cur_file);
			}
		} else {
			/*
			 * decide what to do with non-ELF file
			 */
			if (!ar_file) {
				error_message(FILE_TYPE_ERROR, PLAIN_ERROR,
				    NULL, prog, cur_filenm);
				(void) close(fd);
				return (FAILURE);
			} else {
				if (CHK_OPT(cmd_info, MIGHT_CHG))
					copy_non_elf_to_temp_ar(fd, elf,
					    fdartmp, mem_header,
					    cur_file, cmd_info);
			}
		}
		cmd = elf_next(elf);
		(void) elf_end(elf);
	}

	err = elf_errno();
	if (err != 0) {
		error_message(LIBELF_ERROR, LIBelf_ERROR,
		    elf_errmsg(err), prog);
		error_message(NOT_MANIPULATED_ERROR, PLAIN_ERROR, NULL,
		    prog, cur_file);
		return (FAILURE);
	}

	(void) elf_end(arf);

	if (ar_file && CHK_OPT(cmd_info, MIGHT_CHG)) {
		(void) close(fdartmp); /* done writing to ar_temp_file */
		/* copy ar_temp_file to FILE */
		copy_file(fd, cur_file, &artmpfile);
	} else if (code != DONT_BUILD && CHK_OPT(cmd_info, MIGHT_CHG))
		copy_file(fd, cur_file, &elftmpfile);
	(void) close(fd);   /* done processing this file */
	return (error);
}

static int
process_file(Elf *elf, char *cur_file, Cmd_Info *cmd_info)
{
	int		error = SUCCESS;
	int		x;
	GElf_Ehdr	ehdr;
	size_t		shnum;
	file_state_t	state;

	/*
	 * Initialize
	 */
	if (gelf_getehdr(elf, &ehdr) == NULL) {
		error_message(LIBELF_ERROR, LIBelf_ERROR, elf_errmsg(-1), prog);
		return (FAILURE);
	}

	if (elf_getshdrnum(elf, &shnum) == -1) {
		error_message(LIBELF_ERROR, LIBelf_ERROR, elf_errmsg(-1), prog);
		return (FAILURE);
	}

	/* Initialize per-file state */
	state.Sect_exists = 0;
	state.notesegndx = -1;
	state.notesctndx = -1;
	state.b_e_seg_table = NULL;
	state.sec_table = NULL;
	state.off_table = 0;
	state.nobits_table = NULL;
	state.new_sec_string = NULL;

	initialize(shnum, cmd_info, &state);

	if ((ehdr.e_phnum != 0) &&
	    (build_segment_table(elf, &ehdr, &state) == FAILURE)) {
		x = error = FAILURE;
	} else if ((x = traverse_file(elf, &ehdr, cur_file,
	    cmd_info, &state)) == FAILURE) {
		error_message(WRN_MANIPULATED_ERROR, PLAIN_ERROR, NULL,
		    prog, cur_file);
		error = FAILURE;
	} else if (x != DONT_BUILD && x != FAILURE) {
		post_process(cmd_info, &state);
		if (build_file(elf, &ehdr, cmd_info, &state) == FAILURE) {
			error_message(WRN_MANIPULATED_ERROR, PLAIN_ERROR,
			    NULL, prog, cur_file);
			error = FAILURE;
		}
	}

	/* Release any dynamicaly allocated buffers */
	if (state.b_e_seg_table != NULL)
		free(state.b_e_seg_table);
	if (state.sec_table != NULL)
		free(state.sec_table);
	if (state.off_table != NULL)
		free(state.off_table);
	if (state.nobits_table != NULL)
		free(state.nobits_table);
	if (state.new_sec_string != NULL)
		free(state.new_sec_string);

	if (x == DONT_BUILD)
		return (DONT_BUILD);
	else
		return (error);
}

static int
traverse_file(Elf *elf, GElf_Ehdr * ehdr, char *cur_file, Cmd_Info *cmd_info,
    file_state_t *state)
{
	Elf_Scn		*scn;
	Elf_Scn		*temp_scn;
	Elf_Data	*data;
	GElf_Shdr	*shdr;
	char		*temp_name;
	section_info_table *sinfo;
	GElf_Xword	x;
	int		ret = 0, SYM = 0;	/* used by strip command */
	int		phnum = ehdr->e_phnum;
	unsigned	int i, scn_index;
	size_t		shstrndx, shnum;

	state->Sect_exists = 0;

	if (elf_getshdrnum(elf, &shnum) == -1) {
		error_message(LIBELF_ERROR, LIBelf_ERROR, elf_errmsg(-1), prog);
		return (FAILURE);
	}
	if (elf_getshdrstrndx(elf, &shstrndx) == -1) {
		error_message(LIBELF_ERROR, LIBelf_ERROR, elf_errmsg(-1), prog);
		return (FAILURE);
	}

	scn = 0;
	scn_index = 1;
	sinfo = &state->sec_table[scn_index];
	while ((scn = elf_nextscn(elf, scn)) != 0) {
		char *name;

		shdr = &(sinfo->shdr);
		if (gelf_getshdr(scn, shdr) == NULL) {
			error_message(NO_SECT_TABLE_ERROR,
			    LIBelf_ERROR, elf_errmsg(-1), prog, cur_file);
			return (FAILURE);
		}

		/*
		 * Note: If the object has problems, name
		 * may be set to NULL by the following.
		 */
		name = elf_strptr(elf, shstrndx, (size_t)shdr->sh_name);

		sinfo->scn	= scn;
		sinfo->secno	= scn_index;
		sinfo->osecno	= scn_index;
		SET_ACTION(sinfo->flags, ACT_NOP);
		sinfo->name	= name;
		if (ehdr->e_phnum == 0)
			SET_LOC(sinfo->flags, NOSEG);
		else
			SET_LOC(sinfo->flags, scn_location(scn, elf, state));

		if (shdr->sh_type == SHT_GROUP) {
			if (aplist_append(&cmd_info->sh_groups,
			    sinfo, 10) == NULL) {
				error_message(MALLOC_ERROR, PLAIN_ERROR,
				    NULL, prog);
				mcs_exit(FAILURE);
			}
		}

		/*
		 * If the target section is pointed by a section
		 * holding relocation infomation, then the
		 * pointing section would be useless if the
		 * target section is removed.
		 */
		if ((shdr->sh_type == SHT_REL ||
		    shdr->sh_type == SHT_RELA) &&
		    (shdr->sh_info != SHN_UNDEF &&
		    (temp_scn = elf_getscn(elf, shdr->sh_info)) != 0)) {
			GElf_Shdr tmp_shdr;
			if (gelf_getshdr(temp_scn, &tmp_shdr) != NULL) {
				temp_name = elf_strptr(elf, shstrndx,
				    (size_t)tmp_shdr.sh_name);
				sinfo->rel_name = temp_name;
				sinfo->rel_scn_index =
				    shdr->sh_info;
				if (phnum == 0)
					sinfo->rel_loc = NOSEG;
				else
					sinfo->rel_loc =
					    scn_location(temp_scn, elf, state);
			}
		}
		data = 0;
		if ((data = elf_getdata(scn, data)) == NULL) {
			error_message(LIBELF_ERROR,
			    LIBelf_ERROR, elf_errmsg(-1), prog);
			return (FAILURE);
		}
		sinfo->data = data;

		/*
		 * Check if this section is a candidate for
		 * action to be processes.
		 */
		if ((name != NULL) && (sectcmp(name) == 0)) {
			SET_CANDIDATE(sinfo->flags);

			/*
			 * This flag just shows that there was a
			 * candidate.
			 */
			state->Sect_exists++;
		}

		/*
		 * Any of the following section types should
		 * also be removed (if possible) if invoked via
		 * the 'strip' command.
		 */
		if (CHK_OPT(cmd_info, I_AM_STRIP) &&
		    ((shdr->sh_type == SHT_SUNW_DEBUG) ||
		    (shdr->sh_type == SHT_SUNW_DEBUGSTR))) {
			SET_CANDIDATE(sinfo->flags);
			state->Sect_exists++;
		}


		/*
		 * Zap this file ?
		 */
		if ((cmd_info->flags & zFLAG) &&
		    (shdr->sh_type == SHT_PROGBITS)) {
			SET_CANDIDATE(sinfo->flags);
			state->Sect_exists++;
		}
		x = GET_LOC(sinfo->flags);

		/*
		 * Remember the note section index so that we can
		 * reset the NOTE segment offset to point to it. Depending
		 * on the operation being carried out, the note section may
		 * be assigned a new location in the resulting ELF
		 * image, and the program header needs to reflect that.
		 *
		 * There can be multiple contiguous note sections in
		 * an object, referenced by a single NOTE segment. We
		 * want to be sure and remember the one referenced by
		 * the program header, and not one of the others.
		 */
		if ((shdr->sh_type == SHT_NOTE) && (state->notesctndx == -1) &&
		    (state->notesegndx != -1) &&
		    (state->b_e_seg_table[state->notesegndx].p_offset
		    == shdr->sh_offset))
			state->notesctndx = scn_index;

		if (x == IN || x == PRIOR)
			state->off_table[scn_index] = shdr->sh_offset;
		if (shdr->sh_type == SHT_NOBITS)
			state->nobits_table[scn_index] = 1;

		/*
		 * If this section satisfies the condition,
		 * apply the actions specified.
		 */
		if (ISCANDIDATE(sinfo->flags)) {
			ret += apply_action(sinfo, cur_file, cmd_info);
		}

		/*
		 * If I am strip command, determine if symtab can go or not.
		 */
		if (CHK_OPT(cmd_info, I_AM_STRIP) &&
		    (CHK_OPT(cmd_info, xFLAG) == 0) &&
		    (CHK_OPT(cmd_info, lFLAG) == 0)) {
			if (shdr->sh_type == SHT_SYMTAB &&
			    GET_LOC(sinfo->flags) == AFTER) {
				SYM = scn_index;
			}
		}
		scn_index++;
		sinfo++;
	}
	sinfo->scn	= (Elf_Scn *) -1;

	/*
	 * If there were any errors traversing the file,
	 * just return error.
	 */
	if (ret != 0)
		return (FAILURE);

	/*
	 * Remove symbol table if possible
	 */
	if (CHK_OPT(cmd_info, I_AM_STRIP) && SYM != 0) {
		GElf_Shdr tmp_shdr;

		(void) gelf_getshdr(state->sec_table[SYM].scn, &tmp_shdr);
		state->sec_table[SYM].secno = (GElf_Word)DELETED;
		++(cmd_info->no_of_nulled);
		if (state->Sect_exists == 0)
			++state->Sect_exists;
		SET_ACTION(state->sec_table[SYM].flags, ACT_DELETE);
		state->off_table[SYM] = 0;
		/*
		 * Can I remove section header
		 * string table ?
		 */
		if ((tmp_shdr.sh_link < shnum) &&
		    (tmp_shdr.sh_link != SHN_UNDEF) &&
		    (tmp_shdr.sh_link != shstrndx) &&
		    (GET_LOC(state->sec_table[tmp_shdr.sh_link].flags) ==
		    AFTER)) {
			state->sec_table[tmp_shdr.sh_link].secno =
			    (GElf_Word)DELETED;
			++(cmd_info->no_of_nulled);
			if (state->Sect_exists == 0)
				++state->Sect_exists;
			SET_ACTION(state->sec_table[tmp_shdr.sh_link].flags,
			    ACT_DELETE);
			state->off_table[tmp_shdr.sh_link] = 0;
		}
	}

	/*
	 * If I only printed the contents, then
	 * just report so.
	 */
	if (CHK_OPT(cmd_info, pFLAG) && !CHK_OPT(cmd_info, MIGHT_CHG))
		return (DONT_BUILD); /* don't bother creating a new file */
				/* since the file has not changed */

	/*
	 * I might need to add a new section. Check it.
	 */
	if (state->Sect_exists == 0 && CHK_OPT(cmd_info, aFLAG)) {
		int act = 0;
		state->new_sec_string = calloc(1, cmd_info->str_size + 1);
		if (state->new_sec_string == NULL)
			return (FAILURE);
		for (act = 0; act < actmax; act++) {
			if (Action[act].a_action == ACT_APPEND) {
				(void) strcat(state->new_sec_string,
				    Action[act].a_string);
				(void) strcat(state->new_sec_string, "\n");
				cmd_info->no_of_append = 1;
			}
		}
	}

	/*
	 * If I did not append any new sections, and I did not
	 * modify/delete any sections, then just report so.
	 */
	if ((state->Sect_exists == 0 && cmd_info->no_of_append == 0) ||
	    !CHK_OPT(cmd_info, MIGHT_CHG))
		return (DONT_BUILD);

	/*
	 * Found at least one section which was processed.
	 *	Deleted or Appended or Compressed.
	 */
	if (state->Sect_exists) {
		/*
		 * First, handle the deleted sections.
		 */
		if (cmd_info->no_of_delete != 0 ||
		    cmd_info->no_of_nulled != 0) {
			int acc = 0;
			int rel_idx;

			/*
			 * Handle relocation/target
			 * sections.
			 */
			sinfo = &(state->sec_table[0]);
			for (i = 1; i < shnum; i++) {
				sinfo++;
				rel_idx = sinfo->rel_scn_index;
				if (rel_idx == 0)
					continue;

				/*
				 * If I am removed, then remove my
				 * target section.
				 */
				if (((sinfo->secno ==
				    (GElf_Word)DELETED) ||
				    (sinfo->secno ==
				    (GElf_Word)NULLED)) &&
				    sinfo->rel_loc != IN) {
					if (GET_LOC(state->
					    sec_table[rel_idx].flags) == PRIOR)
						state->sec_table[rel_idx].
						    secno = (GElf_Word)NULLED;
					else
						state->sec_table[rel_idx].
						    secno = (GElf_Word)DELETED;
					SET_ACTION(state->sec_table[rel_idx].
					    flags, ACT_DELETE);
				}

				/*
				 * I am not removed. Check if my target is
				 * removed or nulled. If so, let me try to
				 * remove my self.
				 */
				if (((state->sec_table[rel_idx].secno ==
				    (GElf_Word)DELETED) ||
				    (state->sec_table[rel_idx].secno ==
				    (GElf_Word)NULLED)) &&
				    (GET_LOC(sinfo->flags) != IN)) {
					if (GET_LOC(sinfo->flags) ==
					    PRIOR)
						sinfo->secno =
						    (GElf_Word)NULLED;
					else
						sinfo->secno =
						    (GElf_Word)DELETED;
					SET_ACTION(sinfo->flags, ACT_DELETE);
				}
			}

			/*
			 * Now, take care of DELETED sections
			 */
			sinfo = &(state->sec_table[1]);
			for (i = 1; i < shnum; i++) {
				shdr = &(sinfo->shdr);
				if (sinfo->secno == (GElf_Word)DELETED) {
					acc++;
					/*
					 * The SHT_GROUP section which this
					 * section is a member may be able
					 * to be removed. See post_process().
					 */
					if (shdr->sh_flags & SHF_GROUP)
						cmd_info->flags |=
						    SHF_GROUP_DEL;
				} else {
					/*
					 * The data buffer of SHT_GROUP this
					 * section is a member needs to be
					 * updated. See post_process().
					 */
					sinfo->secno -= acc;
					if ((shdr->sh_flags & SHF_GROUP) &&
					    (acc != 0))
						cmd_info->flags |=
						    SHF_GROUP_MOVE;
				}
				sinfo++;
			}
		}
	}

	/*
	 * I know that the file has been modified.
	 * A new file need to be created.
	 */
	return (SUCCESS);
}

static int
build_file(Elf *src_elf, GElf_Ehdr *src_ehdr, Cmd_Info *cmd_info,
    file_state_t *state)
{
	Elf_Scn *src_scn;
	Elf_Scn *dst_scn;
	int	new_sh_name = 0;	/* to hold the offset for the new */
					/* section's name */
	Elf *dst_elf = 0;
	Elf_Data *elf_data;
	Elf_Data *data;
	int64_t scn_no, x;
	size_t no_of_symbols = 0;
	section_info_table *info;
	unsigned int    c = 0;
	int fdtmp;
	GElf_Shdr src_shdr;
	GElf_Shdr dst_shdr;
	GElf_Ehdr dst_ehdr;
	GElf_Off  new_offset = 0, r;
	size_t shnum, shstrndx;


	if (elf_getshdrnum(src_elf, &shnum) == -1) {
		error_message(LIBELF_ERROR, LIBelf_ERROR, elf_errmsg(-1), prog);
		return (FAILURE);
	}
	if (elf_getshdrstrndx(src_elf, &shstrndx) == -1) {
		error_message(LIBELF_ERROR, LIBelf_ERROR, elf_errmsg(-1), prog);
		return (FAILURE);
	}

	if ((fdtmp = open(elftmpfile.tmp_name, O_RDWR | O_TRUNC | O_CREAT,
	    (mode_t)0666)) == -1) {
		error_message(OPEN_TEMP_ERROR, SYSTEM_ERROR, strerror(errno),
		    prog, elftmpfile.tmp_name);
		return (FAILURE);
	}
	elftmpfile.tmp_unlink = 1;

	if ((dst_elf = elf_begin(fdtmp, ELF_C_WRITE, (Elf *) 0)) == NULL) {
		error_message(READ_ERROR, LIBelf_ERROR, elf_errmsg(-1),
		    prog, elftmpfile.tmp_name);
		(void) close(fdtmp);
		return (FAILURE);
	}

	if (gelf_newehdr(dst_elf, gelf_getclass(src_elf)) == 0) {
		error_message(LIBELF_ERROR, LIBelf_ERROR, elf_errmsg(-1), prog);
		return (FAILURE);
	}

	/* initialize dst_ehdr */
	(void) gelf_getehdr(dst_elf, &dst_ehdr);
	dst_ehdr = *src_ehdr;

	/*
	 * If we are removing the header string table section,
	 * remove the reference to it from the ELF header.
	 */
	if ((shstrndx != SHN_UNDEF) &&
	    (state->sec_table[shstrndx].secno == (GElf_Word)DELETED))
		dst_ehdr.e_shstrndx = SHN_UNDEF;

	/*
	 * flush the changes to the ehdr so the ident
	 * array and header string table index are filled in.
	 */
	(void) gelf_update_ehdr(dst_elf, &dst_ehdr);


	if (src_ehdr->e_phnum != 0) {
		(void) elf_flagelf(dst_elf, ELF_C_SET, ELF_F_LAYOUT);

		if (gelf_newphdr(dst_elf, src_ehdr->e_phnum) == 0) {
			error_message(LIBELF_ERROR, LIBelf_ERROR,
			    elf_errmsg(-1), prog);
			return (FAILURE);
		}

		for (x = 0; x < src_ehdr->e_phnum; ++x) {
			GElf_Phdr dst;
			GElf_Phdr src;

			/* LINTED */
			(void) gelf_getphdr(src_elf, (int)x, &src);
			/* LINTED */
			(void) gelf_getphdr(dst_elf, (int)x, &dst);
			(void) memcpy(&dst, &src, sizeof (GElf_Phdr));
			/* LINTED */
			(void) gelf_update_phdr(dst_elf, (int)x, &dst);
		}

		x = location(dst_ehdr.e_phoff, 0, src_elf, state);
		if (x == AFTER)
			new_offset = (GElf_Off)src_ehdr->e_ehsize;
	}

	scn_no = 1;
	while ((src_scn = state->sec_table[scn_no].scn) != (Elf_Scn *) -1) {
		info = &state->sec_table[scn_no];
		/*  If section should be copied to new file NOW */
		if ((info->secno != (GElf_Word)DELETED) &&
		    info->secno <= scn_no) {
			if ((dst_scn = elf_newscn(dst_elf)) == NULL) {
				error_message(LIBELF_ERROR,
				    LIBelf_ERROR, elf_errmsg(-1), prog);
				return (FAILURE);
			}
			(void) gelf_getshdr(dst_scn, &dst_shdr);
			(void) gelf_getshdr(info->scn, &src_shdr);
			(void) memcpy(&dst_shdr, &src_shdr, sizeof (GElf_Shdr));

			/*
			 * Update link and info fields
			 * The sh_link field may have special values so
			 * check them first.
			 */
			if ((src_shdr.sh_link >= shnum) ||
			    (src_shdr.sh_link == 0))
				dst_shdr.sh_link = src_shdr.sh_link;
			else if ((int)state->sec_table[src_shdr.sh_link].secno <
			    0)
				dst_shdr.sh_link = 0;
			else
				dst_shdr.sh_link =
				    state->sec_table[src_shdr.sh_link].secno;

			if ((src_shdr.sh_type == SHT_REL) ||
			    (src_shdr.sh_type == SHT_RELA)) {
				if ((src_shdr.sh_info >= shnum) ||
				    ((int)state->sec_table[src_shdr.
				    sh_info].secno < 0))
					dst_shdr.sh_info = 0;
				else
					dst_shdr.sh_info = state->
					    sec_table[src_shdr.sh_info].secno;
			}

			data = state->sec_table[scn_no].data;
			if ((elf_data = elf_newdata(dst_scn)) == NULL) {
				error_message(LIBELF_ERROR,
				    LIBelf_ERROR, elf_errmsg(-1), prog);
				return (FAILURE);
			}
			*elf_data = *data;

			/*
			 * SHT_{DYNSYM, SYMTAB} might need some change, as
			 * they may contain section symbols that reference
			 * removed sections. SHT_SUNW_LDYNSYM does not
			 * contain section symbols, and therefore does not
			 * have this issue.
			 */
			if (((src_shdr.sh_type == SHT_SYMTAB) ||
			    (src_shdr.sh_type == SHT_DYNSYM)) &&
			    src_shdr.sh_entsize != 0 &&
			    (cmd_info->no_of_delete != 0 ||
			    cmd_info->no_of_nulled != 0)) {
				char	*new_sym;

				no_of_symbols = src_shdr.sh_size /
				    src_shdr.sh_entsize;
				new_sym = malloc(no_of_symbols *
				    src_shdr.sh_entsize);
				if (new_sym == NULL) {
					error_message(MALLOC_ERROR,
					    PLAIN_ERROR, NULL, prog);
					mcs_exit(FAILURE);
				}

				/* CSTYLED */
				elf_data->d_buf = (void *) new_sym;
				for (c = 0; c < no_of_symbols; c++) {
					GElf_Sym csym;

					(void) gelf_getsym(data, c, &csym);

					if ((csym.st_shndx < SHN_LORESERVE) &&
					    (csym.st_shndx != SHN_UNDEF)) {
						section_info_table *i;
						i = &state->
						    sec_table[csym.st_shndx];
						if (((int)i->secno !=
						    DELETED) &&
						    ((int)i->secno != NULLED)) {
							csym.st_shndx =
							    i->secno;
						} else {
							/* BEGIN CSTYLED */
							if (src_shdr.sh_type ==
							    SHT_SYMTAB) {
							/*
							 * The section which
							 * this * symbol relates
							 * to is removed.
							 * There is no way to
							 * specify this fact,
							 * just change the shndx
							 * to 1.
							 */
							    csym.st_shndx = 1;
							} else {
							/*
							 * If this is in a
							 * .dynsym, NULL it out.
							 */
							    csym.st_shndx = 0;
							    csym.st_name = 0;
							    csym.st_value = 0;
							    csym.st_size = 0;
							    csym.st_info = 0;
							    csym.st_other = 0;
							    csym.st_shndx = 0;
							}
							/* END CSTYLED */
						}
					}

					(void) gelf_update_sym(elf_data, c,
					    &csym);
				}
			}

			/* update SHT_SYMTAB_SHNDX */
			if ((src_shdr.sh_type == SHT_SYMTAB_SHNDX) &&
			    (src_shdr.sh_entsize != 0) &&
			    ((cmd_info->no_of_delete != 0) ||
			    (cmd_info->no_of_nulled != 0))) {
				GElf_Word	*oldshndx;
				GElf_Word	*newshndx;
				uint_t		entcnt;

				entcnt = src_shdr.sh_size /
				    src_shdr.sh_entsize;
				oldshndx = data->d_buf;
				newshndx = malloc(entcnt * src_shdr.sh_entsize);
				if (newshndx == NULL) {
					error_message(MALLOC_ERROR,
					    PLAIN_ERROR, NULL, prog);
					mcs_exit(FAILURE);
				}
				elf_data->d_buf = (void *)newshndx;
				for (c = 0; c < entcnt; c++) {
					if (oldshndx[c] != SHN_UNDEF) {
						section_info_table *i;
						i = &state->
						    sec_table[oldshndx[c]];
						if (((int)i->secno !=
						    DELETED) &&
						    ((int)i->secno != NULLED))
							newshndx[c] = i->secno;
						else
							newshndx[c] =
							    oldshndx[c];
					} else
							newshndx[c] =
							    oldshndx[c];
				}
			}

			/*
			 * If the section is to be updated,
			 * do so.
			 */
			if (ISCANDIDATE(info->flags)) {
				if ((GET_LOC(info->flags) == PRIOR) &&
				    (((int)info->secno == NULLED) ||
				    ((int)info->secno == EXPANDED) ||
				    ((int)info->secno == SHRUNK))) {
					/*
					 * The section is updated,
					 * but the position is not too
					 * good. Need to NULL this out.
					 */
					dst_shdr.sh_name = 0;
					dst_shdr.sh_type = SHT_PROGBITS;
					if ((int)info->secno != NULLED) {
						(cmd_info->no_of_moved)++;
						SET_MOVING(info->flags);
					}
				} else {
					/*
					 * The section is positioned AFTER,
					 * or there are no segments.
					 * It is safe to update this section.
					 */
					data = state->sec_table[scn_no].mdata;
					*elf_data = *data;
					dst_shdr.sh_size = elf_data->d_size;
				}
			}
			/* add new section name to shstrtab? */
			else if (!state->Sect_exists &&
			    (state->new_sec_string != NULL) &&
			    (scn_no == shstrndx) &&
			    (dst_shdr.sh_type == SHT_STRTAB) &&
			    ((src_ehdr->e_phnum == 0) ||
			    ((x = scn_location(dst_scn, dst_elf, state))
			    != IN) ||
			    (x != PRIOR))) {
				size_t sect_len;

				sect_len = strlen(SECT_NAME);
				if ((elf_data->d_buf =
				    malloc((dst_shdr.sh_size +
				    sect_len + 1))) == NULL) {
					error_message(MALLOC_ERROR,
					    PLAIN_ERROR, NULL, prog);
					mcs_exit(FAILURE);
				}
				/* put original data plus new data in section */
				(void) memcpy(elf_data->d_buf,
				    data->d_buf, data->d_size);
				(void) memcpy(&((char *)elf_data->d_buf)
				    [data->d_size], SECT_NAME, sect_len + 1);
				/* LINTED */
				new_sh_name = (int)dst_shdr.sh_size;
				dst_shdr.sh_size += sect_len + 1;
				elf_data->d_size += sect_len + 1;
			}

			/*
			 * Compute offsets.
			 */
			if (src_ehdr->e_phnum != 0) {
				/*
				 * Compute section offset.
				 */
				if (state->off_table[scn_no] == 0) {
					if (dst_shdr.sh_addralign != 0) {
						r = new_offset %
						    dst_shdr.sh_addralign;
						if (r)
							new_offset +=
							    dst_shdr.
							    sh_addralign - r;
					}
					dst_shdr.sh_offset = new_offset;
					elf_data->d_off = 0;
				} else {
					if (state->nobits_table[scn_no] == 0)
						new_offset =
						    state->off_table[scn_no];
				}
				if (state->nobits_table[scn_no] == 0)
					new_offset += dst_shdr.sh_size;
			}

			/* flush changes */
			(void) gelf_update_shdr(dst_scn, &dst_shdr);
		}
		scn_no++;
	}

	/*
	 * This is the real new section.
	 */
	if (!state->Sect_exists && state->new_sec_string != NULL) {
		size_t string_size;
		string_size = strlen(state->new_sec_string) + 1;
		if ((dst_scn = elf_newscn(dst_elf)) == NULL) {
			error_message(LIBELF_ERROR,
			    LIBelf_ERROR, elf_errmsg(-1), prog);
			return (FAILURE);
		}
		(void) gelf_getshdr(dst_scn, &dst_shdr);

		dst_shdr.sh_name = new_sh_name;
		dst_shdr.sh_type = SHT_PROGBITS;
		dst_shdr.sh_flags = 0;
		dst_shdr.sh_addr = 0;
		if (src_ehdr->e_phnum != 0)
			dst_shdr.sh_offset = new_offset;
		else
			dst_shdr.sh_offset = 0;
		dst_shdr.sh_size = string_size + 1;
		dst_shdr.sh_link = 0;
		dst_shdr.sh_info = 0;
		dst_shdr.sh_addralign = 1;
		dst_shdr.sh_entsize = 0;
		(void) gelf_update_shdr(dst_scn, &dst_shdr); /* flush changes */

		if ((elf_data = elf_newdata(dst_scn)) == NULL) {
			error_message(LIBELF_ERROR,
			    LIBelf_ERROR, elf_errmsg(-1), prog);
			return (FAILURE);
		}
		elf_data->d_size = string_size + 1;
		if ((elf_data->d_buf = (char *)
		    calloc(1, string_size + 1)) == NULL) {
			error_message(MALLOC_ERROR,
			    PLAIN_ERROR, NULL, prog);
			mcs_exit(FAILURE);
		}
		(void) memcpy(&((char *)elf_data->d_buf)[1],
		    state->new_sec_string, string_size);
		elf_data->d_align = 1;
		new_offset += string_size + 1;
	}

	/*
	 * If there are sections which needed to be moved,
	 * then do it here.
	 */
	if (cmd_info->no_of_moved != 0) {
		int cnt;
		info = &state->sec_table[0];

		for (cnt = 0; cnt < shnum; cnt++, info++) {
			if ((GET_MOVING(info->flags)) == 0)
				continue;

			if ((src_scn = elf_getscn(src_elf, info->osecno)) ==
			    NULL) {
				error_message(LIBELF_ERROR,
				    LIBelf_ERROR, elf_errmsg(-1), prog);
				return (FAILURE);
			}
			if (gelf_getshdr(src_scn, &src_shdr) == NULL) {
				error_message(LIBELF_ERROR,
				    LIBelf_ERROR, elf_errmsg(-1), prog);
				return (FAILURE);
			}
			if ((dst_scn = elf_newscn(dst_elf)) == NULL) {
				error_message(LIBELF_ERROR,
				    LIBelf_ERROR, elf_errmsg(-1), prog);
				return (FAILURE);
			}
			if (gelf_getshdr(dst_scn, &dst_shdr) == NULL) {
				error_message(LIBELF_ERROR,
				    LIBelf_ERROR, elf_errmsg(-1), prog);
				return (FAILURE);
			}
			dst_shdr = src_shdr;

			data = info->mdata;

			dst_shdr.sh_offset = new_offset;  /* UPDATE fields */
			dst_shdr.sh_size = data->d_size;

			if ((shnum >= src_shdr.sh_link) ||
			    (src_shdr.sh_link == 0))
				dst_shdr.sh_link = src_shdr.sh_link;
			else
				dst_shdr.sh_link =
				    state->sec_table[src_shdr.sh_link].osecno;

			if ((shnum >= src_shdr.sh_info) ||
			    (src_shdr.sh_info == 0))
				dst_shdr.sh_info = src_shdr.sh_info;
			else
				dst_shdr.sh_info =
				    state->sec_table[src_shdr.sh_info].osecno;
			(void) gelf_update_shdr(dst_scn, &dst_shdr);
			if ((elf_data = elf_newdata(dst_scn)) == NULL) {
				error_message(LIBELF_ERROR,
				    LIBelf_ERROR, elf_errmsg(-1), prog);
				return (FAILURE);
			}
			(void) memcpy(elf_data, data, sizeof (Elf_Data));

			new_offset += data->d_size;
		}
	}

	/*
	 * In the event that the position of the sting table has changed,
	 * as a result of deleted sections, update the ehdr->e_shstrndx.
	 */
	if ((shstrndx > 0) && (shnum > 0) &&
	    (state->sec_table[shstrndx].secno < shnum)) {
		if (state->sec_table[shstrndx].secno < SHN_LORESERVE) {
			dst_ehdr.e_shstrndx =
			    state->sec_table[dst_ehdr.e_shstrndx].secno;
		} else {
			Elf_Scn		*_scn;
			GElf_Shdr	shdr0;

			/*
			 * If shstrndx requires 'Extended ELF Sections'
			 * then it is stored in shdr[0].sh_link
			 */
			dst_ehdr.e_shstrndx = SHN_XINDEX;
			if ((_scn = elf_getscn(dst_elf, 0)) == NULL) {
				error_message(LIBELF_ERROR,
				    LIBelf_ERROR, elf_errmsg(-1), prog);
				return (FAILURE);
			}
			(void) gelf_getshdr(_scn, &shdr0);
			shdr0.sh_link = state->sec_table[shstrndx].secno;
			(void) gelf_update_shdr(_scn, &shdr0);
		}
	}

	if (src_ehdr->e_phnum != 0) {
		size_t align = gelf_fsize(dst_elf, ELF_T_ADDR, 1, EV_CURRENT);

		/* UPDATE location of program header table */
		if (location(dst_ehdr.e_phoff, 0, dst_elf, state) == AFTER) {
			r = new_offset % align;
			if (r)
				new_offset += align - r;

			dst_ehdr.e_phoff = new_offset;
			new_offset += dst_ehdr.e_phnum * dst_ehdr.e_phentsize;
		}
		/* UPDATE location of section header table */
		if ((location(dst_ehdr.e_shoff, 0, src_elf, state) == AFTER) ||
		    ((location(dst_ehdr.e_shoff, 0, src_elf, state) == PRIOR) &&
		    (!state->Sect_exists && state->new_sec_string != NULL))) {
			r = new_offset % align;
			if (r)
				new_offset += align - r;

			dst_ehdr.e_shoff = new_offset;
		}

		/*
		 * The NOTE segment is the one segment whos
		 * sections might get moved by mcs processing.
		 * Make sure that the NOTE segments offset points
		 * to the .note section.
		 */
		if ((state->notesegndx != -1) && (state->notesctndx != -1) &&
		    (state->sec_table[state->notesctndx].secno)) {
			Elf_Scn *	notescn;
			GElf_Shdr	nshdr;

			notescn = elf_getscn(dst_elf,
			    state->sec_table[state->notesctndx].secno);
			(void) gelf_getshdr(notescn, &nshdr);

			if (gelf_getclass(dst_elf) == ELFCLASS32) {
				Elf32_Phdr * ph	= elf32_getphdr(dst_elf) +
				    state->notesegndx;
				/* LINTED */
				ph->p_offset	= (Elf32_Off)nshdr.sh_offset;
			} else {
				Elf64_Phdr * ph	= elf64_getphdr(dst_elf) +
				    state->notesegndx;
				ph->p_offset	= (Elf64_Off)nshdr.sh_offset;
			}
		}
	}

	/* copy ehdr changes back into real ehdr */
	(void) gelf_update_ehdr(dst_elf, &dst_ehdr);
	if (elf_update(dst_elf, ELF_C_WRITE) < 0) {
		error_message(LIBELF_ERROR, LIBelf_ERROR, elf_errmsg(-1), prog);
		return (FAILURE);
	}

	(void) elf_end(dst_elf);
	(void) close(fdtmp);
	return (SUCCESS);
}

/*
 * Search through PHT saving the beginning and ending segment offsets
 */
static int
build_segment_table(Elf * elf, GElf_Ehdr * ehdr, file_state_t *state)
{
	unsigned int i;

	state->b_e_seg_table = (Seg_Table *)
	    calloc(ehdr->e_phnum, sizeof (Seg_Table));
	if (state->b_e_seg_table == NULL) {
		error_message(MALLOC_ERROR, PLAIN_ERROR, NULL, prog);
		mcs_exit(FAILURE);
	}

	for (i = 0; i < ehdr->e_phnum; i++) {
		GElf_Phdr ph;

		(void) gelf_getphdr(elf, i, &ph);

		/*
		 * remember the note SEGMENTS index so that we can
		 * re-set it's p_offset later if needed.
		 */
		if (ph.p_type == PT_NOTE)
			state->notesegndx = i;

		state->b_e_seg_table[i].p_offset = ph.p_offset;
		state->b_e_seg_table[i].p_memsz  = ph.p_offset + ph.p_memsz;
		state->b_e_seg_table[i].p_filesz = ph.p_offset + ph.p_filesz;
	}
	return (SUCCESS);
}


static void
copy_elf_file_to_temp_ar_file(
	int fdartmp,
	Elf_Arhdr *mem_header,
	char *cur_file)
{
	char *buf;
	char mem_header_buf[sizeof (struct ar_hdr) + 1];
	int fdtmp3;
	struct stat stbuf;

	if ((fdtmp3 = open(elftmpfile.tmp_name, O_RDONLY)) == -1) {
		error_message(OPEN_TEMP_ERROR, SYSTEM_ERROR, strerror(errno),
		    prog, elftmpfile.tmp_name);
		mcs_exit(FAILURE);
	}

	(void) stat(elftmpfile.tmp_name, &stbuf); /* for size of file */

	if ((buf =
	    malloc(ROUNDUP(stbuf.st_size))) == NULL) {
		error_message(MALLOC_ERROR, PLAIN_ERROR, NULL, prog);
		mcs_exit(FAILURE);
	}

	if (read(fdtmp3, buf, stbuf.st_size) != stbuf.st_size) {
		error_message(READ_MANI_ERROR, SYSTEM_ERROR, strerror(errno),
		    prog, elftmpfile.tmp_name, cur_file);
		mcs_exit(FAILURE);
	}

	(void) sprintf(mem_header_buf, FORMAT, mem_header->ar_rawname,
	    mem_header->ar_date, (unsigned)mem_header->ar_uid,
	    (unsigned)mem_header->ar_gid, (unsigned)mem_header->ar_mode,
	    stbuf.st_size, ARFMAG);

	if (write(fdartmp, mem_header_buf,
	    (unsigned)sizeof (struct ar_hdr)) !=
	    (unsigned)sizeof (struct ar_hdr)) {
		error_message(WRITE_MANI_ERROR, SYSTEM_ERROR, strerror(errno),
		    prog, elftmpfile.tmp_name, cur_file);
		mcs_exit(FAILURE);
	}

	if (stbuf.st_size & 0x1) {
		buf[stbuf.st_size] = '\n';
		if (write(fdartmp, buf, (size_t)ROUNDUP(stbuf.st_size)) !=
		    (size_t)ROUNDUP(stbuf.st_size)) {
			error_message(WRITE_MANI_ERROR,	SYSTEM_ERROR,
			    strerror(errno), prog, elftmpfile.tmp_name,
			    cur_file);
			mcs_exit(FAILURE);
		}
	} else if (write(fdartmp, buf, stbuf.st_size) != stbuf.st_size) {
			error_message(WRITE_MANI_ERROR, SYSTEM_ERROR,
			    strerror(errno), prog, elftmpfile.tmp_name,
			    cur_file);
			mcs_exit(FAILURE);
	}
	free(buf);
	(void) close(fdtmp3);
}

static void
copy_non_elf_to_temp_ar(
	int fd,
	Elf *elf,
	int fdartmp,
	Elf_Arhdr *mem_header,
	char *cur_file,
	Cmd_Info *cmd_info)
{
	char    mem_header_buf[sizeof (struct ar_hdr) + 1];
	char *file_buf;

	if ((strcmp(mem_header->ar_name, "/") != 0) &&
	    (strcmp(mem_header->ar_name, "/SYM64/") != 0)) {
		(void) sprintf(mem_header_buf, FORMAT, mem_header->ar_rawname,
		    mem_header->ar_date, (unsigned)mem_header->ar_uid,
		    (unsigned)mem_header->ar_gid, (unsigned)mem_header->ar_mode,
		    mem_header->ar_size, ARFMAG);

		if (write(fdartmp, mem_header_buf, sizeof (struct ar_hdr)) !=
		    sizeof (struct ar_hdr)) {
			error_message(WRITE_MANI_ERROR, SYSTEM_ERROR,
			    strerror(errno), prog, cur_file);
			mcs_exit(FAILURE);
		}
		if ((file_buf =
		    malloc(ROUNDUP(mem_header->ar_size))) == NULL) {
			error_message(MALLOC_ERROR, PLAIN_ERROR, NULL,
			    prog);
			mcs_exit(FAILURE);
		}

		if (lseek(fd, elf_getbase(elf), 0) != elf_getbase(elf)) {
			error_message(WRITE_MANI_ERROR, prog, cur_file);
			mcs_exit(FAILURE);
		}

		if (read(fd, file_buf,
		    (size_t)ROUNDUP(mem_header->ar_size)) !=
		    (size_t)ROUNDUP(mem_header->ar_size)) {
			error_message(READ_MANI_ERROR, SYSTEM_ERROR,
			    strerror(errno), prog, cur_file);
			mcs_exit(FAILURE);
		}
		if (write(fdartmp,
		    file_buf,
		    (size_t)ROUNDUP(mem_header->ar_size)) !=
		    (size_t)ROUNDUP(mem_header->ar_size)) {
			error_message(WRITE_MANI_ERROR, SYSTEM_ERROR,
			    strerror(errno), prog, cur_file);
			mcs_exit(FAILURE);
		}
		free(file_buf);
	} else if (CHK_OPT(cmd_info, MIGHT_CHG)) {
		error_message(SYM_TAB_AR_ERROR, PLAIN_ERROR, NULL,
		    prog, cur_file);
		error_message(EXEC_AR_ERROR, PLAIN_ERROR, NULL, cur_file);
	}
}

/*
 * Replace contents of file
 *
 * entry:
 *	ofd - Open file descriptor for file fname
 *	fname - Name of file being processed
 *	temp_file_name - Address of pointer to temporary
 *		file containing new contents for fname.
 *
 * exit:
 *	The contents of the file given by temp_file->tmp_name are
 *	copied to the file fname. The temporary file is
 *	unlinked, and temp_file reset.
 */
static void
copy_file(int ofd, char *fname, Tmp_File *temp_file)
{
	enum { MMAP_USED, MMAP_UNUSED } mmap_status;
	int		i;
	int		fdtmp2;
	struct stat	stbuf;
	char		*buf;

	for (i = 0; signum[i]; i++) /* started writing, cannot interrupt */
		(void) signal(signum[i], SIG_IGN);

	if ((fdtmp2 = open(temp_file->tmp_name, O_RDONLY)) == -1) {
		error_message(OPEN_TEMP_ERROR, SYSTEM_ERROR, strerror(errno),
		    prog, temp_file->tmp_name);
		mcs_exit(FAILURE);
	}

	(void) stat(temp_file->tmp_name, &stbuf); /* for size of file */

	/*
	 * Get the contents of the updated file.
	 * First try mmap()'ing. If mmap() fails,
	 * then use the malloc() and read().
	 */
	mmap_status = MMAP_USED;
	buf = (char *)mmap(0, stbuf.st_size, PROT_READ, MAP_SHARED, fdtmp2, 0);
	if (buf == (caddr_t)-1) {
		if ((buf =
		    malloc(stbuf.st_size * sizeof (char))) == NULL) {
			error_message(MALLOC_ERROR, PLAIN_ERROR, NULL,
			    prog);
			mcs_exit(FAILURE);
		}

		if (read(fdtmp2, buf, stbuf.st_size) != stbuf.st_size) {
			error_message(READ_SYS_ERROR, SYSTEM_ERROR,
			    strerror(errno), prog, temp_file->tmp_name);
			mcs_exit(FAILURE);
		}
		mmap_status = MMAP_UNUSED;
	}

	if (ftruncate(ofd, 0) == -1) {
		error_message(WRITE_MANI_ERROR2, SYSTEM_ERROR, strerror(errno),
		    prog, fname);
		mcs_exit(FAILURE);
	}
	if (lseek(ofd, 0, SEEK_SET) == -1) {
		error_message(WRITE_MANI_ERROR2, SYSTEM_ERROR, strerror(errno),
		    prog, fname);
		mcs_exit(FAILURE);
	}
	if ((write(ofd, buf, stbuf.st_size)) != stbuf.st_size) {
		error_message(WRITE_MANI_ERROR2, SYSTEM_ERROR, strerror(errno),
		    prog, fname);
		mcs_exit(FAILURE);
	}

	/*
	 * clean
	 */
	if (mmap_status == MMAP_USED)
		(void) munmap(buf, stbuf.st_size);
	else
		free(buf);
	(void) close(fdtmp2);
	free_tempfile(temp_file);
}

static uint64_t
location(int64_t offset, int mem_search, Elf * elf, file_state_t *state)
{
	int i;
	uint64_t upper;
	GElf_Ehdr ehdr;

	(void) gelf_getehdr(elf, &ehdr);

	for (i = 0; i < ehdr.e_phnum; i++) {
		if (mem_search)
			upper = state->b_e_seg_table[i].p_memsz;
		else
			upper = state->b_e_seg_table[i].p_filesz;
		if ((offset >= state->b_e_seg_table[i].p_offset) &&
		    (offset <= upper))
			return (IN);
		else if (offset < state->b_e_seg_table[i].p_offset)
			return (PRIOR);
	}
	return (AFTER);
}

static uint64_t
scn_location(Elf_Scn * scn, Elf * elf, file_state_t *state)
{
	GElf_Shdr shdr;

	(void) gelf_getshdr(scn, &shdr);

	/*
	 * If the section is not a NOTE section and it has no
	 * virtual address then it is not part of a mapped segment.
	 */
	if (shdr.sh_addr == 0)
		return (location(shdr.sh_offset + shdr.sh_size, 0, elf, state));

	return (location(shdr.sh_offset + shdr.sh_size, 1, elf, state));
}

static void
initialize(int shnum, Cmd_Info *cmd_info, file_state_t *state)
{
	/*
	 * Initialize command info
	 */
	cmd_info->no_of_append = cmd_info->no_of_delete =
	    cmd_info->no_of_nulled = cmd_info->no_of_compressed =
	    cmd_info->no_of_moved = 0;
	cmd_info->sh_groups = NULL;

	state->sec_table = (section_info_table *)
	    calloc(shnum + 1, sizeof (section_info_table));
	if (state->sec_table == NULL) {
		error_message(MALLOC_ERROR, PLAIN_ERROR, NULL, prog);
		mcs_exit(FAILURE);
	}

	state->off_table = (int64_t *)calloc(shnum, sizeof (int64_t));
	if (state->off_table == NULL) {
		error_message(MALLOC_ERROR, PLAIN_ERROR, NULL, prog);
		mcs_exit(FAILURE);
	}

	state->nobits_table = (int64_t *)calloc(shnum, sizeof (int64_t));
	if (state->nobits_table == NULL) {
		error_message(MALLOC_ERROR, PLAIN_ERROR, NULL, prog);
		mcs_exit(FAILURE);
	}
}

/*
 * Update the contents of SHT_GROUP if needed
 */
static void
post_process(Cmd_Info *cmd_info, file_state_t *state)
{
	Aliste			idx;
	section_info_table	*sinfo;
	Word			*grpdata, *ngrpdata;
	int64_t			sno, sno2;
	Word			i, j, num;

	/*
	 * If no change is required, then return.
	 */
	if ((cmd_info->flags & (SHF_GROUP_MOVE|SHF_GROUP_DEL)) == 0)
		return;

	/*
	 * If SHF_GROUP sections were removed, we might need to
	 * remove SHT_GROUP sections.
	 */
	if (cmd_info->flags & SHF_GROUP_DEL) {
		Word	grpcnt;
		int	deleted = 0;

		for (APLIST_TRAVERSE(cmd_info->sh_groups, idx, sinfo)) {
			if (sinfo->secno == (GElf_Word)DELETED)
				continue;
			num = (sinfo->shdr).sh_size/sizeof (Word);
			grpcnt = 0;
			grpdata = (Word *)(sinfo->data->d_buf);
			for (i = 1; i < num; i++) {
				if (state->sec_table[grpdata[i]].secno !=
				    (GElf_Word)DELETED)
					grpcnt++;
			}

			/*
			 * All members in this SHT_GROUP were removed.
			 * We can remove this SHT_GROUP.
			 */
			if (grpcnt == 0) {
				sinfo->secno = (GElf_Word)DELETED;
				(cmd_info->no_of_delete)++;
				deleted = 1;
			}
		}

		/*
		 * If we deleted a SHT_GROUP section,
		 * we need to reasign section numbers.
		 */
		if (deleted) {
			section_info_table *sinfo;

			sno = 1;
			sno2 = 1;
			while (state->sec_table[sno].scn != (Elf_Scn *)-1) {
				sinfo = &state->sec_table[sno];
				if (sinfo->secno != (GElf_Word) DELETED)
					sinfo->secno = sno2++;
				sno++;
			}
		}
	}

	/*
	 * Now we can update data buffers of the SHT_GROUP sections.
	 */
	for (APLIST_TRAVERSE(cmd_info->sh_groups, idx, sinfo)) {
		if (sinfo->secno == (GElf_Word)DELETED)
			continue;
		num = (sinfo->shdr).sh_size/sizeof (Word);

		/*
		 * Need to generate the updated data buffer
		 */
		if ((sinfo->mdata = malloc(sizeof (Elf_Data))) == NULL) {
			error_message(MALLOC_ERROR, PLAIN_ERROR, NULL,
			    prog);
			mcs_exit(FAILURE);
		}
		*(sinfo->mdata) = *(sinfo->data);
		if ((ngrpdata = sinfo->mdata->d_buf =
		    malloc(sinfo->data->d_size)) == NULL) {
			error_message(MALLOC_ERROR, PLAIN_ERROR, NULL,
			    prog);
			mcs_exit(FAILURE);
		}

		grpdata = (Word *)(sinfo->data->d_buf);
		ngrpdata[0] = grpdata[0];
		j = 1;
		for (i = 1; i < num; i++) {
			if (state->sec_table[grpdata[i]].secno !=
			    (GElf_Word)DELETED) {
				ngrpdata[j++] =
				    state->sec_table[grpdata[i]].secno;
			}
		}
		sinfo->mdata->d_size = j * sizeof (Word);
		sinfo->data = sinfo->mdata;
	}
	free(cmd_info->sh_groups);
	cmd_info->sh_groups = NULL;
}
