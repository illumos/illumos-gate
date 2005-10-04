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
/*	Copyright (c) 1989 AT&T	*/
/*	  All Rights Reserved  	*/


#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * Copyright 2005 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#include <stdio.h>

/* Get definitions for the relocation types supported. */
#define	ELF_TARGET_ALL
#include <elf.h>

static const char *Fmtrel = "%-20s";
static const char *Fmtreld = "%-20d";



/*
 * MACHINE DEPENDENT
 *
 * Print the ASCII representation of the ELF relocation type `type' to
 * stdout.  This function should work for any machine type supported by
 * ELF.  Since the set of machine-specific relocation types is machine-
 * specific (hah!), if a machine type or relocation type is not recognized,
 * the decimal value of the relocation type is printed.
 *
 * This function needs to be updated any time the set of machine types
 * supported by ELF is enlarged (tho' it won't malfunction, dump won't
 * be maximally helpful if print_reloc_type() isn't updated).
 */
void
print_reloc_type(int machine, int type)
{
	switch (machine) {
	case EM_M32:
		switch (type) {
		case (R_M32_NONE):
			(void) printf(Fmtrel,
				"R_M32_NONE");
			break;
		case (R_M32_32):
			(void) printf(Fmtrel,
				"R_M32_32");
			break;
		case (R_M32_32_S):
			(void) printf(Fmtrel,
				"R_M32_32_S");
			break;
		case (R_M32_PC32_S):
			(void) printf(Fmtrel,
				"R_M32_PC32_S");
			break;
		case (R_M32_GOT32_S):
			(void) printf(Fmtrel,
				"R_M32_GOT32_S");
			break;
		case (R_M32_PLT32_S):
			(void) printf(Fmtrel,
				"R_M32_PLT32_S");
			break;
		case (R_M32_COPY):
			(void) printf(Fmtrel,
				"R_M32_COPY");
			break;
		case (R_M32_GLOB_DAT):
			(void) printf(Fmtrel,
				"R_M32_GLOB_DAT");
			break;
		case (R_M32_JMP_SLOT):
			(void) printf(Fmtrel,
				"R_M32_JMP_SLOT");
			break;
		case (R_M32_RELATIVE):
			(void) printf(Fmtrel,
				"R_M32_RELATIVE");
			break;
		case (R_M32_RELATIVE_S):
			(void) printf(Fmtrel,
				"R_M32_RELATIVE_S");
			break;
		default:
			(void) printf(Fmtreld, type);
			break;
		}
		break;
	case EM_386:
		switch (type) {
		case (R_386_NONE):
			(void) printf(Fmtrel,
				"R_386_NONE");
			break;
		case (R_386_32):
			(void) printf(Fmtrel,
				"R_386_32");
			break;
		case (R_386_GOT32):
			(void) printf(Fmtrel,
				"R_386_GOT32");
			break;
		case (R_386_PLT32):
			(void) printf(Fmtrel,
				"R_386_PLT32");
			break;
		case (R_386_COPY):
			(void) printf(Fmtrel,
				"R_386_COPY");
			break;
		case (R_386_GLOB_DAT):
			(void) printf(Fmtrel,
				"R_386_GLOB_DAT");
			break;
		case (R_386_JMP_SLOT):
			(void) printf(Fmtrel,
				"R_386_JMP_SLOT");
			break;
		case (R_386_RELATIVE):
			(void) printf(Fmtrel,
				"R_386_RELATIVE");
			break;
		case (R_386_GOTOFF):
			(void) printf(Fmtrel,
				"R_386_GOTOFF");
			break;
		case (R_386_GOTPC):
			(void) printf(Fmtrel,
				"R_386_GOTPC");
			break;
		case (R_386_32PLT):
			(void) printf(Fmtrel,
				"R_386_32PLT");
			break;
		case (R_386_TLS_GD_PLT):
			(void) printf(Fmtrel,
				"R_386_TLS_GD_PLT");
			break;
		case (R_386_TLS_LDM_PLT):
			(void) printf(Fmtrel,
				"R_386_TLS_LDM_PLT");
			break;
		case (R_386_TLS_TPOFF):
			(void) printf(Fmtrel,
				"R_386_TLS_TPOFF");
			break;
		case (R_386_TLS_IE):
			(void) printf(Fmtrel,
				"R_386_TLS_IE");
			break;
		case (R_386_TLS_GOTIE):
			(void) printf(Fmtrel,
				"R_386_TLS_GOTIE");
			break;
		case (R_386_TLS_LE):
			(void) printf(Fmtrel,
				"R_386_TLS_LE");
			break;
		case (R_386_TLS_GD):
			(void) printf(Fmtrel,
				"R_386_TLS_GD");
			break;
		case (R_386_TLS_LDM):
			(void) printf(Fmtrel,
				"R_386_TLS_LDM");
			break;
		case (R_386_16):
			(void) printf(Fmtrel,
				"R_386_16");
			break;
		case (R_386_8):
			(void) printf(Fmtrel,
				"R_386_8");
			break;
		case (R_386_PC8):
			(void) printf(Fmtrel,
				"R_386_PC8");
			break;
		case (R_386_TLS_LDO_32):
			(void) printf(Fmtrel,
				"R_386_TLS_LDO_32");
			break;
		case (R_386_TLS_DTPMOD32):
			(void) printf(Fmtrel,
				"R_386_TLS_DTPMOD32");
			break;
		case (R_386_TLS_DTPOFF32):
			(void) printf(Fmtrel,
				"R_386_TLS_DTPOFF32");
			break;
		default:
			(void) printf(Fmtreld, type);
			break;
		}
		break;
	case EM_SPARC:		/* SPARC */
	case EM_SPARC32PLUS:	/* SPARC32PLUS */
	case EM_SPARCV9:	/* SPARC V9 */
		switch (type) {
		case (R_SPARC_NONE):
			(void) printf(Fmtrel,
				"R_SPARC_NONE");
			break;
		case (R_SPARC_8):
			(void) printf(Fmtrel,
				"R_SPARC_8");
			break;
		case (R_SPARC_16):
			(void) printf(Fmtrel,
				"R_SPARC_16");
			break;
		case (R_SPARC_32):
			(void) printf(Fmtrel,
				"R_SPARC_32");
			break;
		case (R_SPARC_DISP8):
			(void) printf(Fmtrel,
				"R_SPARC_DISP8");
			break;
		case (R_SPARC_DISP16):
			(void) printf(Fmtrel,
				"R_SPARC_DISP16");
			break;
		case (R_SPARC_DISP32):
			(void) printf(Fmtrel,
				"R_SPARC_DISP32");
			break;
		case (R_SPARC_WDISP30):
			(void) printf(Fmtrel,
				"R_SPARC_WDISP30");
			break;
		case (R_SPARC_WDISP22):
			(void) printf(Fmtrel,
				"R_SPARC_WDISP22");
			break;
		case (R_SPARC_HI22):
			(void) printf(Fmtrel,
				"R_SPARC_HI22");
			break;
		case (R_SPARC_22):
			(void) printf(Fmtrel,
				"R_SPARC_22");
			break;
		case (R_SPARC_13):
			(void) printf(Fmtrel,
				"R_SPARC_13");
			break;
		case (R_SPARC_LO10):
			(void) printf(Fmtrel,
				"R_SPARC_LO10");
			break;
		case (R_SPARC_GOT10):
			(void) printf(Fmtrel,
				"R_SPARC_GOT10");
			break;
		case (R_SPARC_GOT13):
			(void) printf(Fmtrel,
				"R_SPARC_GOT13");
			break;
		case (R_SPARC_GOT22):
			(void) printf(Fmtrel,
				"R_SPARC_GOT22");
			break;
		case (R_SPARC_PC10):
			(void) printf(Fmtrel,
				"R_SPARC_PC10");
			break;
		case (R_SPARC_PC22):
			(void) printf(Fmtrel,
				"R_SPARC_PC22");
			break;
		case (R_SPARC_WPLT30):
			(void) printf(Fmtrel,
				"R_SPARC_WPLT30");
			break;
		case (R_SPARC_COPY):
			(void) printf(Fmtrel,
				"R_SPARC_COPY");
			break;
		case (R_SPARC_GLOB_DAT):
			(void) printf(Fmtrel,
				"R_SPARC_GLOB_DAT");
			break;
		case (R_SPARC_JMP_SLOT):
			(void) printf(Fmtrel,
				"R_SPARC_JMP_SLOT");
			break;
		case (R_SPARC_RELATIVE):
			(void) printf(Fmtrel,
				"R_SPARC_RELATIVE");
			break;
		case (R_SPARC_UA32):
			(void) printf(Fmtrel,
				"R_SPARC_UA32");
			break;
		case (R_SPARC_PLT32):
			(void) printf(Fmtrel,
				"R_SPARC_PLT32");
			break;
		case (R_SPARC_HIPLT22):
			(void) printf(Fmtrel,
				"R_SPARC_HIPLT22");
			break;
		case (R_SPARC_LOPLT10):
			(void) printf(Fmtrel,
				"R_SPARC_LOPLT10");
			break;
		case (R_SPARC_PCPLT32):
			(void) printf(Fmtrel,
				"R_SPARC_PCPLT32");
			break;
		case (R_SPARC_PCPLT22):
			(void) printf(Fmtrel,
				"R_SPARC_PCPLT22");
			break;
		case (R_SPARC_PCPLT10):
			(void) printf(Fmtrel,
				"R_SPARC_PCPLT10");
			break;
		case (R_SPARC_10):
			(void) printf(Fmtrel,
				"R_SPARC_10");
			break;
		case (R_SPARC_11):
			(void) printf(Fmtrel,
				"R_SPARC_11");
			break;
		case (R_SPARC_64):
			(void) printf(Fmtrel,
				"R_SPARC_64");
			break;
		case (R_SPARC_OLO10):
			(void) printf(Fmtrel,
				"R_SPARC_OLO10");
			break;
		case (R_SPARC_HH22):
			(void) printf(Fmtrel,
				"R_SPARC_HH22");
			break;
		case (R_SPARC_HM10):
			(void) printf(Fmtrel,
				"R_SPARC_HM10");
			break;
		case (R_SPARC_LM22):
			(void) printf(Fmtrel,
				"R_SPARC_LM22");
			break;
		case (R_SPARC_PC_HH22):
			(void) printf(Fmtrel,
				"R_SPARC_PC_HH22");
			break;
		case (R_SPARC_PC_HM10):
			(void) printf(Fmtrel,
				"R_SPARC_PC_HM10");
			break;
		case (R_SPARC_PC_LM22):
			(void) printf(Fmtrel,
				"R_SPARC_PC_LM22");
			break;
		case (R_SPARC_WDISP16):
			(void) printf(Fmtrel,
				"R_SPARC_WDISP16");
			break;
		case (R_SPARC_WDISP19):
			(void) printf(Fmtrel,
				"R_SPARC_WDISP19");
			break;
		case (R_SPARC_GLOB_JMP):
			(void) printf(Fmtrel,
				"R_SPARC_GLOB_JMP");
			break;
		case (R_SPARC_7):
			(void) printf(Fmtrel,
				"R_SPARC_7");
			break;
		case (R_SPARC_5):
			(void) printf(Fmtrel,
				"R_SPARC_5");
			break;
		case (R_SPARC_6):
			(void) printf(Fmtrel,
				"R_SPARC_6");
			break;
		case (R_SPARC_DISP64):
			(void) printf(Fmtrel,
				"R_SPARC_DISP64");
			break;
		case (R_SPARC_PLT64):
			(void) printf(Fmtrel,
				"R_SPARC_PLT64");
			break;
		case (R_SPARC_HIX22):
			(void) printf(Fmtrel,
				"R_SPARC_HIX22");
			break;
		case (R_SPARC_LOX10):
			(void) printf(Fmtrel,
				"R_SPARC_LOX10");
			break;
		case (R_SPARC_H44):
			(void) printf(Fmtrel,
				"R_SPARC_H44");
			break;
		case (R_SPARC_M44):
			(void) printf(Fmtrel,
				"R_SPARC_M44");
			break;
		case (R_SPARC_L44):
			(void) printf(Fmtrel,
				"R_SPARC_L44");
			break;
		case (R_SPARC_REGISTER):
			(void) printf(Fmtrel,
				"R_SPARC_REGISTER");
			break;
		case (R_SPARC_UA64):
			(void) printf(Fmtrel,
				"R_SPARC_UA64");
			break;
		case (R_SPARC_UA16):
			(void) printf(Fmtrel,
				"R_SPARC_UA16");
			break;
		case (R_SPARC_TLS_GD_HI22):
			(void) printf(Fmtrel,
				"R_SPARC_TLS_GD_HI22");
			break;
		case (R_SPARC_TLS_GD_LO10):
			(void) printf(Fmtrel,
				"R_SPARC_TLS_GD_LO10");
			break;
		case (R_SPARC_TLS_GD_ADD):
			(void) printf(Fmtrel,
				"R_SPARC_TLS_GD_ADD");
			break;
		case (R_SPARC_TLS_GD_CALL):
			(void) printf(Fmtrel,
				"R_SPARC_TLS_GD_CALL");
			break;
		case (R_SPARC_TLS_LDM_HI22):
			(void) printf(Fmtrel,
				"R_SPARC_TLS_LDM_HI22");
			break;
		case (R_SPARC_TLS_LDM_LO10):
			(void) printf(Fmtrel,
				"R_SPARC_TLS_LDM_LO10");
			break;
		case (R_SPARC_TLS_LDM_ADD):
			(void) printf(Fmtrel,
				"R_SPARC_TLS_LDM_ADD");
			break;
		case (R_SPARC_TLS_LDM_CALL):
			(void) printf(Fmtrel,
				"R_SPARC_TLS_LDM_CALL");
			break;
		case (R_SPARC_TLS_LDO_HIX22):
			(void) printf(Fmtrel,
				"R_SPARC_TLS_LDO_HIX22");
			break;
		case (R_SPARC_TLS_LDO_LOX10):
			(void) printf(Fmtrel,
				"R_SPARC_TLS_LDO_LOX10");
			break;
		case (R_SPARC_TLS_LDO_ADD):
			(void) printf(Fmtrel,
				"R_SPARC_TLS_LDO_ADD");
			break;
		case (R_SPARC_TLS_IE_HI22):
			(void) printf(Fmtrel,
				"R_SPARC_TLS_IE_HI22");
			break;
		case (R_SPARC_TLS_IE_LO10):
			(void) printf(Fmtrel,
				"R_SPARC_TLS_IE_LO10");
			break;
		case (R_SPARC_TLS_IE_LD):
			(void) printf(Fmtrel,
				"R_SPARC_TLS_IE_LD");
			break;
		case (R_SPARC_TLS_IE_LDX):
			(void) printf(Fmtrel,
				"R_SPARC_TLS_IE_LDX");
			break;
		case (R_SPARC_TLS_IE_ADD):
			(void) printf(Fmtrel,
				"R_SPARC_TLS_IE_ADD");
			break;
		case (R_SPARC_TLS_LE_HIX22):
			(void) printf(Fmtrel,
				"R_SPARC_TLS_LE_HIX22");
			break;
		case (R_SPARC_TLS_LE_LOX10):
			(void) printf(Fmtrel,
				"R_SPARC_TLS_LE_LOX10");
			break;
		case (R_SPARC_TLS_DTPMOD32):
			(void) printf(Fmtrel,
				"R_SPARC_TLS_DTPMOD32");
			break;
		case (R_SPARC_TLS_DTPMOD64):
			(void) printf(Fmtrel,
				"R_SPARC_TLS_DTPMOD64");
			break;
		case (R_SPARC_TLS_DTPOFF32):
			(void) printf(Fmtrel,
				"R_SPARC_TLS_DTPOFF32");
			break;
		case (R_SPARC_TLS_DTPOFF64):
			(void) printf(Fmtrel,
				"R_SPARC_TLS_DTPOFF64");
			break;
		case (R_SPARC_TLS_TPOFF32):
			(void) printf(Fmtrel,
				"R_SPARC_TLS_TPOFF32");
			break;
		case (R_SPARC_TLS_TPOFF64):
			(void) printf(Fmtrel,
				"R_SPARC_TLS_TPOFF64");
			break;
		default:
			(void) printf(Fmtreld, type);
			break;
		}
		break;
	default:
		(void) printf(Fmtreld, type);
		break;
	}
}
