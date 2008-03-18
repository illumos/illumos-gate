#
# CDDL HEADER START
#
# The contents of this file are subject to the terms of the
# Common Development and Distribution License (the "License").
# You may not use this file except in compliance with the License.
#
# You can obtain a copy of the license at usr/src/OPENSOLARIS.LICENSE
# or http://www.opensolaris.org/os/licensing.
# See the License for the specific language governing permissions
# and limitations under the License.
#
# When distributing Covered Code, include this CDDL HEADER in each
# file and include the License file at usr/src/OPENSOLARIS.LICENSE.
# If applicable, add the following below this CDDL HEADER, with the
# fields enclosed by brackets "[]" replaced with your own identifying
# information: Portions Copyright [yyyy] [name of copyright owner]
#
# CDDL HEADER END
#

#
# Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
# Use is subject to license terms.
#
# ident	"%Z%%M%	%I%	%E% SMI"

@ _START_

# Message file for cmd/sgs/libld - sparc specific.

@ MSG_REL_UNIMPL	"relocation error: file %s:  symbol %s: \
			 unimplemented relocation type: %d"
@ MSG_REL_UNNOBITS	"relocation error: %s: file %s: symbol %s: \
			 unsupported number of bits: %d"
@ MSG_REL_LOSEBITS	"relocation error: %s: file %s: symbol %s: \
			 value 0x%llx loses %d bits at offset 0x%llx"
@ MSG_REL_UNRELREL	"relocation error: %s: file %s: symbol %s: \
			 non-relative PLT relocation can not be used in \
			 building a shared object"
@ MSG_REL_SHOBJABS44	"relocation error: %s: file %s: symbol %s: \
			 relocations based on the ABS44 \
			 coding model can not \
			 be used in building a shared object"
@ MSG_REL_BADGOTFIX	"relocation error: %s: file %s: symbol %s: \
			 internal gotop_fixups error"
@ MSG_REL_ASSIGNGOT	"internal error: assign_got() invalid got index \
			 0x%llx for symbol `%s'"
@ MSG_REL_SMALLGOT	"too many symbols require `small' PIC references:\n\
			 \thave %d, maximum %d -- recompile some \
			 modules -K PIC."
@ MSG_REL_MIXEDGOT	"too many symbols require mixed mode \
			 (both `small' and `large') PIC references:\n\
			 \thave %d, maximum %d -- recompile some \
			 modules -K PIC."

@ MSG_SYM_INCOMPREG1	"register %s symbol used incompatibly:\n\
			 \t(file %s symbol `%s', file %s symbol `%s');"
@ MSG_SYM_INCOMPREG2	"register symbol `%s' used incompatibly:\n\
			 \t(file %s value=%s, file %s value=%s);"
@ MSG_SYM_INCOMPREG3	"register %s local symbol visibility incompatible:\n\
			 \t(file %s symbol `%s', file %s symbol `%s');"
@ MSG_SYM_MULTINIREG	"register %s symbol `%s' multiply-initialized:\n\
			 \t(file %s shndx=ABS, file %s shndx=ABS);"

@ MSG_SYM_BADSCRATCH	"file %s: section %s: symbol[%d]: %s: malformed \
			 scratch register\n\
			 \t(should be: unnamed, global and undefined)"
@ MSG_SYM_BADREG	"file %s: section %s: symbol[%d]: invalid register \
			 symbol value: 0x%llx"

@ _END_

@ MSG_STO_REGISTERG1	"<SCRATCH REGISTER 1>"
@ MSG_STO_REGISTERG2	"<SCRATCH REGISTER 2>"
@ MSG_STO_REGISTERG3	"<SCRATCH REGISTER 3>"
@ MSG_STO_REGISTERG4	"<SCRATCH REGISTER 4>"
@ MSG_STO_REGISTERG5	"<SCRATCH REGISTER 5>"
@ MSG_STO_REGISTERG6	"<SCRATCH REGISTER 6>"
@ MSG_STO_REGISTERG7	"<SCRATCH REGISTER 7>"

@ MSG_PTH_RTLD_SPARCV9	"/usr/lib/sparcv9/ld.so.1"
