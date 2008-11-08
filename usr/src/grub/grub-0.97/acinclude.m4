dnl grub_ASM_USCORE checks if C symbols get an underscore after
dnl compiling to assembler.
dnl Written by Pavel Roskin. Based on grub_ASM_EXT_C written by
dnl Erich Boleyn and modified by OKUJI Yoshinori
AC_DEFUN([grub_ASM_USCORE],
[AC_REQUIRE([AC_PROG_CC])
AC_MSG_CHECKING([if C symbols get an underscore after compilation])
AC_CACHE_VAL(grub_cv_asm_uscore,
[cat > conftest.c <<\EOF
int
func (int *list)
{
  *list = 0;
  return *list;
}
EOF

if AC_TRY_COMMAND([${CC-cc} ${CFLAGS} -S conftest.c]) && test -s conftest.s; then
  true
else
  AC_MSG_ERROR([${CC-cc} failed to produce assembly code])
fi

if grep _func conftest.s >/dev/null 2>&1; then
  grub_cv_asm_uscore=yes
else
  grub_cv_asm_uscore=no
fi

rm -f conftest*])

if test "x$grub_cv_asm_uscore" = xyes; then
  AC_DEFINE_UNQUOTED([HAVE_ASM_USCORE], $grub_cv_asm_uscore,
    [Define if C symbols get an underscore after compilation])
fi

AC_MSG_RESULT([$grub_cv_asm_uscore])
])


dnl Some versions of `objcopy -O binary' vary their output depending
dnl on the link address.
AC_DEFUN([grub_PROG_OBJCOPY_ABSOLUTE],
[AC_MSG_CHECKING([whether ${OBJCOPY} works for absolute addresses])
AC_CACHE_VAL(grub_cv_prog_objcopy_absolute,
[cat > conftest.c <<\EOF
void
cmain (void)
{
   *((int *) 0x1000) = 2;
}
EOF

if AC_TRY_EVAL(ac_compile) && test -s conftest.o; then :
else
  AC_MSG_ERROR([${CC-cc} cannot compile C source code])
fi
grub_cv_prog_objcopy_absolute=yes
for link_addr in 2000 8000 7C00; do
  if AC_TRY_COMMAND([${CC-cc} ${CFLAGS} -nostdlib -Wl,-N -Wl,-Ttext -Wl,$link_addr conftest.o -o conftest.exec]); then :
  else
    AC_MSG_ERROR([${CC-cc} cannot link at address $link_addr])
  fi
  if AC_TRY_COMMAND([${OBJCOPY-objcopy} -O binary conftest.exec conftest]); then :
  else
    AC_MSG_ERROR([${OBJCOPY-objcopy} cannot create binary files])
  fi
  if test ! -f conftest.old || AC_TRY_COMMAND([cmp -s conftest.old conftest]); then
    mv -f conftest conftest.old
  else
    grub_cv_prog_objcopy_absolute=no
    break
  fi
done
rm -f conftest*])
AC_MSG_RESULT([$grub_cv_prog_objcopy_absolute])])

dnl Mass confusion!
dnl Older versions of GAS interpret `.code16' to mean ``generate 32-bit
dnl instructions, but implicitly insert addr32 and data32 bytes so
dnl that the code works in real mode''.
dnl
dnl Newer versions of GAS interpret `.code16' to mean ``generate 16-bit
dnl instructions,'' which seems right.  This requires the programmer
dnl to explicitly insert addr32 and data32 instructions when they want
dnl them.
dnl
dnl We only support the newer versions, because the old versions cause
dnl major pain, by requiring manual assembly to get 16-bit instructions into
dnl stage1/stage1.S.
AC_DEFUN([grub_ASM_ADDR32],
[AC_REQUIRE([AC_PROG_CC])
AC_REQUIRE([grub_ASM_PREFIX_REQUIREMENT])
AC_MSG_CHECKING([for .code16 addr32 assembler support])
AC_CACHE_VAL(grub_cv_asm_addr32,
[cat > conftest.s.in <<\EOF
	.code16
l1:	@ADDR32@	movb	%al, l1
EOF

if test "x$grub_cv_asm_prefix_requirement" = xyes; then
  sed -e s/@ADDR32@/addr32/ < conftest.s.in > conftest.s
else
  sed -e s/@ADDR32@/addr32\;/ < conftest.s.in > conftest.s
fi

if AC_TRY_COMMAND([${CC-cc} ${CFLAGS} -c conftest.s]) && test -s conftest.o; then
  grub_cv_asm_addr32=yes
else
  grub_cv_asm_addr32=no
fi

rm -f conftest*])

AC_MSG_RESULT([$grub_cv_asm_addr32])])

dnl
dnl Later versions of GAS requires that addr32 and data32 prefixes
dnl appear in the same lines as the instructions they modify, while
dnl earlier versions requires that they appear in separate lines.
AC_DEFUN([grub_ASM_PREFIX_REQUIREMENT],
[AC_REQUIRE([AC_PROG_CC])
AC_MSG_CHECKING(dnl
[whether addr32 must be in the same line as the instruction])
AC_CACHE_VAL(grub_cv_asm_prefix_requirement,
[cat > conftest.s <<\EOF
	.code16
l1:	addr32	movb	%al, l1
EOF

if AC_TRY_COMMAND([${CC-cc} ${CFLAGS} -c conftest.s]) && test -s conftest.o; then
  grub_cv_asm_prefix_requirement=yes
else
  grub_cv_asm_prefix_requirement=no
fi

rm -f conftest*])

if test "x$grub_cv_asm_prefix_requirement" = xyes; then
  grub_tmp_addr32="addr32"
  grub_tmp_data32="data32"
else
  grub_tmp_addr32="addr32;"
  grub_tmp_data32="data32;"
fi

AC_DEFINE_UNQUOTED([ADDR32], $grub_tmp_addr32,
  [Define it to \"addr32\" or \"addr32;\" to make GAS happy])
AC_DEFINE_UNQUOTED([DATA32], $grub_tmp_data32,
  [Define it to \"data32\" or \"data32;\" to make GAS happy])

AC_MSG_RESULT([$grub_cv_asm_prefix_requirement])])

dnl
dnl Older versions of GAS require that absolute indirect calls/jumps are
dnl not prefixed with `*', while later versions warn if not prefixed.
AC_DEFUN([grub_ASM_ABSOLUTE_WITHOUT_ASTERISK],
[AC_REQUIRE([AC_PROG_CC])
AC_MSG_CHECKING(dnl
[whether an absolute indirect call/jump must not be prefixed with an asterisk])
AC_CACHE_VAL(grub_cv_asm_absolute_without_asterisk,
[cat > conftest.s <<\EOF
	lcall	*(offset)	
offset:
	.long	0
	.word	0
EOF

if AC_TRY_COMMAND([${CC-cc} ${CFLAGS} -c conftest.s]) && test -s conftest.o; then
  grub_cv_asm_absolute_without_asterisk=no
else
  grub_cv_asm_absolute_without_asterisk=yes
fi

rm -f conftest*])

if test "x$grub_cv_asm_absolute_without_asterisk" = xyes; then
  AC_DEFINE(ABSOLUTE_WITHOUT_ASTERISK, 1, [Define if an absolute indirect call/jump must NOT be prefixed with `*'])
fi

AC_MSG_RESULT([$grub_cv_asm_absolute_without_asterisk])])

dnl
dnl grub_CHECK_START_SYMBOL checks if start is automatically defined by
dnl the compiler.
dnl Written by OKUJI Yoshinori
AC_DEFUN([grub_CHECK_START_SYMBOL],
[AC_REQUIRE([AC_PROG_CC])
AC_MSG_CHECKING([if start is defined by the compiler])
AC_CACHE_VAL(grub_cv_check_start_symbol,
[AC_TRY_LINK([], [asm ("incl start")],
   grub_cv_check_start_symbol=yes,
   grub_cv_check_start_symbol=no)])

if test "x$grub_cv_check_start_symbol" = xyes; then
  AC_DEFINE(HAVE_START_SYMBOL, 1, [Define if start is defined])
fi

AC_MSG_RESULT([$grub_cv_check_start_symbol])
])

dnl
dnl grub_CHECK_USCORE_START_SYMBOL checks if _start is automatically
dnl defined by the compiler.
dnl Written by OKUJI Yoshinori
AC_DEFUN([grub_CHECK_USCORE_START_SYMBOL],
[AC_REQUIRE([AC_PROG_CC])
AC_MSG_CHECKING([if _start is defined by the compiler])
AC_CACHE_VAL(grub_cv_check_uscore_start_symbol,
[AC_TRY_LINK([], [asm ("incl _start")],
   grub_cv_check_uscore_start_symbol=yes,
   grub_cv_check_uscore_start_symbol=no)])

if test "x$grub_cv_check_uscore_start_symbol" = xyes; then
  AC_DEFINE(HAVE_USCORE_START_SYMBOL, 1, [Define if _start is defined])
fi

AC_MSG_RESULT([$grub_cv_check_uscore_start_symbol])
])

dnl
dnl grub_CHECK_USCORE_USCORE_BSS_START_SYMBOL checks if __bss_start is
dnl automatically defined by the compiler.
dnl Written by Michael Hohmoth.
AC_DEFUN([grub_CHECK_USCORE_USCORE_BSS_START_SYMBOL],
[AC_REQUIRE([AC_PROG_CC])
AC_MSG_CHECKING([if __bss_start is defined by the compiler])
AC_CACHE_VAL(grub_cv_check_uscore_uscore_bss_start_symbol,
[AC_TRY_LINK([], [asm ("incl __bss_start")],
   grub_cv_check_uscore_uscore_bss_start_symbol=yes,
   grub_cv_check_uscore_uscore_bss_start_symbol=no)])

if test "x$grub_cv_check_uscore_uscore_bss_start_symbol" = xyes; then
  AC_DEFINE(HAVE_USCORE_USCORE_BSS_START_SYMBOL, 1, [Define if __bss_start is defined])
fi

AC_MSG_RESULT([$grub_cv_check_uscore_uscore_bss_start_symbol])
])

dnl
dnl grub_CHECK_EDATA_SYMBOL checks if edata is automatically defined by the
dnl compiler.
dnl Written by Michael Hohmuth.
AC_DEFUN([grub_CHECK_EDATA_SYMBOL],
[AC_REQUIRE([AC_PROG_CC])
AC_MSG_CHECKING([if edata is defined by the compiler])
AC_CACHE_VAL(grub_cv_check_edata_symbol,
[AC_TRY_LINK([], [asm ("incl edata")],
   grub_cv_check_edata_symbol=yes,
   grub_cv_check_edata_symbol=no)])

if test "x$grub_cv_check_edata_symbol" = xyes; then
  AC_DEFINE(HAVE_EDATA_SYMBOL, 1, [Define if edata is defined])
fi

AC_MSG_RESULT([$grub_cv_check_edata_symbol])
])

dnl
dnl grub_CHECK_USCORE_EDATA_SYMBOL checks if _edata is automatically
dnl defined by the compiler.
dnl Written by Michael Hohmuth.
AC_DEFUN([grub_CHECK_USCORE_EDATA_SYMBOL],
[AC_REQUIRE([AC_PROG_CC])
AC_MSG_CHECKING([if _edata is defined by the compiler])
AC_CACHE_VAL(grub_cv_check_uscore_edata_symbol,
[AC_TRY_LINK([], [asm ("incl _edata")],
   grub_cv_check_uscore_edata_symbol=yes,
   grub_cv_check_uscore_edata_symbol=no)])

if test "x$grub_cv_check_uscore_edata_symbol" = xyes; then
  AC_DEFINE(HAVE_USCORE_EDATA_SYMBOL, 1, [Define if _edata is defined])
fi

AC_MSG_RESULT([$grub_cv_check_uscore_edata_symbol])
])

dnl
dnl grub_CHECK_END_SYMBOL checks if end is automatically defined by the
dnl compiler.
dnl Written by OKUJI Yoshinori
AC_DEFUN([grub_CHECK_END_SYMBOL],
[AC_REQUIRE([AC_PROG_CC])
AC_MSG_CHECKING([if end is defined by the compiler])
AC_CACHE_VAL(grub_cv_check_end_symbol,
[AC_TRY_LINK([], [asm ("incl end")],
   grub_cv_check_end_symbol=yes,
   grub_cv_check_end_symbol=no)])

if test "x$grub_cv_check_end_symbol" = xyes; then
  AC_DEFINE(HAVE_END_SYMBOL, 1, [Define if end is defined])
fi

AC_MSG_RESULT([$grub_cv_check_end_symbol])
])

dnl
dnl grub_CHECK_USCORE_END_SYMBOL checks if _end is automatically defined
dnl by the compiler.
dnl Written by OKUJI Yoshinori
AC_DEFUN([grub_CHECK_USCORE_END_SYMBOL],
[AC_REQUIRE([AC_PROG_CC])
AC_MSG_CHECKING([if _end is defined by the compiler])
AC_CACHE_VAL(grub_cv_check_uscore_end_symbol,
[AC_TRY_LINK([], [asm ("incl _end")],
   grub_cv_check_uscore_end_symbol=yes,
   grub_cv_check_uscore_end_symbol=no)])

if test "x$grub_cv_check_uscore_end_symbol" = xyes; then
  AC_DEFINE(HAVE_USCORE_END_SYMBOL, 1, [Define if end is defined])
fi

AC_MSG_RESULT([$grub_cv_check_uscore_end_symbol])
])

dnl grub_DEFINE_FILE(MACRO_NAME, FILE_NAME, DESCRIPTION)
dnl grub_DEFINE_FILE defines a macro as the contents of a file safely.
dnl Replace some escape sequences, because autoconf doesn't handle them
dnl gracefully.
dnl Written by OKUJI Yoshinori.
AC_DEFUN([grub_DEFINE_FILE],
[AC_REQUIRE([AC_PROG_CC])
# Because early versions of GNU sed 3.x are too buggy, use a C program
# instead of shell commands. *sigh*
cat >conftest.c <<\EOF
#include <stdio.h>

int
main (void)
{
  int c;

  while ((c = getchar ()) != EOF)
    {
      switch (c)
        {
	case '\n':
	  fputs ("\\n", stdout);
	  break;
	case '\r':
	  fputs ("\\r", stdout);
	  break;
	case '\\':
	  fputs ("\\\\", stdout);
	  break;
	case '"':
	  fputs ("\\\"", stdout);
	  break;
	default:
	  putchar (c);
	}
    }

  return 0;
}
EOF

if AC_TRY_COMMAND([${CC-cc} ${CFLAGS} conftest.c -o conftest]) && test -s conftest; then
  grub_tmp_value=`./conftest < "[$2]"`
else
  AC_MSG_ERROR([${CC-cc} failed to produce an executable file])
fi

AC_DEFINE_UNQUOTED([$1], "$grub_tmp_value", [$3])
rm -f conftest*
])
