dnl Configure script for GRUB.
dnl Copyright 1999,2000,2001,2002,2003,2004,2005 Free Software Foundation, Inc.

dnl Permission to use, copy, modify and distribute this software and its
dnl documentation is hereby granted, provided that both the copyright
dnl notice and this permission notice appear in all copies of the
dnl software, derivative works or modified versions, and any portions
dnl thereof, and that both notices appear in supporting documentation.
dnl
dnl THE FREE SOFTWARE FOUNDATION ALLOWS FREE USE OF THIS SOFTWARE IN ITS
dnl "AS IS" CONDITION.  THE FREE SOFTWARE FOUNDATION DISCLAIMS ANY
dnl LIABILITY OF ANY KIND FOR ANY DAMAGES WHATSOEVER RESULTING FROM THE
dnl USE OF THIS SOFTWARE.

AC_PREREQ(2.57)
AC_INIT([GRUB], [0.97], [bug-grub@gnu.org])
AC_CONFIG_SRCDIR([stage2/stage2.c])
AC_CONFIG_HEADER([config.h])
AM_INIT_AUTOMAKE

AC_CANONICAL_HOST

case "$host_cpu" in
i[[3456]]86) host_cpu=i386 ;;
x86_64) host_cpu=x86_64 ;;
*) AC_MSG_ERROR([unsupported CPU type]) ;;
esac

AC_SUBST(host_cpu)
AC_SUBST(host_vendor)

#
# Options
#

AM_MAINTAINER_MODE
if test "x$enable_maintainer_mode" = xyes; then
  AC_PATH_PROG(PERL,perl)
  if test -z "$PERL"; then
    AC_MSG_ERROR([perl not found])
  fi
fi

# This should be checked before AC_PROG_CC
if test "x$CFLAGS" = x; then
  default_CFLAGS=yes
fi

if test "x$host_cpu" = xx86_64; then
  CFLAGS="-m32 $CFLAGS"
fi

#
# Programs
#

AC_CHECK_TOOL(CC, gcc)
AC_PROG_CC
# We need this for older versions of Autoconf.
_AM_DEPENDENCIES(CC)

dnl Because recent automake complains about AS, set it here.
CCAS="$CC"
AC_SUBST(CCAS)

AC_ARG_WITH(binutils,
  [  --with-binutils=DIR     search the directory DIR to find binutils])

if test "x$with_binutils" != x; then
dnl AC_PATH_TOOL is not seen in autoconf 2.13, so use AC_PATH_PROG
dnl instead for now. It is preferable when you cross-compile GRUB.
dnl  AC_PATH_TOOL(RANLIB, ranlib, :, "$with_binutils:$PATH")
  AC_PATH_PROG(RANLIB, ranlib, :, "$with_binutils:$PATH")
else
  AC_PROG_RANLIB
fi

# optimization flags
if test "x$ac_cv_prog_gcc" = xyes; then
  if test "x$default_CFLAGS" = xyes; then
    # Autoconf may set CFLAGS to -O2 and/or -g. So eliminate them.
    CFLAGS="`echo $CFLAGS | sed -e 's/-g//g' -e 's/-O[[0-9]]//g'` -g"
    # If the user specify the directory for binutils, add the option `-B'.
    if test "x$with_binutils" != x; then
      CFLAGS="-B$with_binutils/ $CFLAGS"
    fi
    STAGE1_CFLAGS="-O2"
    GRUB_CFLAGS="-O2"
    AC_CACHE_CHECK([whether optimization for size works], size_flag, [
      saved_CFLAGS=$CFLAGS
      CFLAGS="-Os -g"
      AC_TRY_COMPILE(, , size_flag=yes, size_flag=no)
      CFLAGS=$saved_CFLAGS
    ])
    if test "x$size_flag" = xyes; then
      STAGE2_CFLAGS="-Os"
    else
      STAGE2_CFLAGS="-O2 -fno-strength-reduce -fno-unroll-loops"
    fi
    # OpenBSD has a GCC extension for protecting applications from
    # stack smashing attacks, but GRUB doesn't want this feature.
    AC_CACHE_CHECK([whether gcc has -fno-stack-protector],
		   no_stack_protector_flag, [
      saved_CFLAGS=$CFLAGS
      CFLAGS="-fno-stack-protector"
      AC_TRY_COMPILE(,
		     ,
		     no_stack_protector_flag=yes,
		     no_stack_protector_flag=no)
      CFLAGS=$saved_CFLAGS
    ])
    if test "x$no_stack_protector_flag" = xyes; then
      STAGE2_CFLAGS="$STAGE2_CFLAGS -fno-stack-protector"
    fi
  fi
fi

AC_SUBST(STAGE1_CFLAGS)
AC_SUBST(STAGE2_CFLAGS)
AC_SUBST(GRUB_CFLAGS)

# Enforce coding standards.
CPPFLAGS="$CPPFLAGS -Wall -Wmissing-prototypes -Wunused -Wshadow"
CPPFLAGS="$CPPFLAGS -Wpointer-arith"

AC_CACHE_CHECK([whether -Wundef works], undef_flag, [
  saved_CPPFLAGS="$CPPFLAGS"
  CPPFLAGS="-Wundef"
  AC_TRY_COMPILE(, , undef_flag=yes, undef_flag=no)
  CPPFLAGS="$saved_CPPFLAGS"
])

# The options `-falign-*' are supported by gcc 3.0 or later.
# Probably it is sufficient to only check for -falign-loops.
AC_CACHE_CHECK([whether -falign-loops works], [falign_loop_flag], [
  saved_CPPFLAGS="$CPPFLAGS"
  CPPFLAGS="-falign-loops=1"
  AC_TRY_COMPILE(, , [falign_loop_flag=yes], [falign_loop_flag=no])
  CPPFLAGS="$saved_CPPFLAGS"
])

# Force no alignment to save space.
if test "x$falign_loop_flag" = xyes; then
  CPPFLAGS="$CPPFLAGS -falign-jumps=1 -falign-loops=1 -falign-functions=1"
else
  CPPFLAGS="$CPPFLAGS -malign-jumps=1 -malign-loops=1 -malign-functions=1"
fi

if test "x$undef_flag" = xyes; then
  CPPFLAGS="$CPPFLAGS -Wundef"
fi

if test "x$with_binutils" != x; then
dnl  AC_PATH_TOOL(OBJCOPY, objcopy, , "$with_binutils:$PATH")
  AC_PATH_PROG(OBJCOPY, objcopy, , "$with_binutils:$PATH")
else
  AC_CHECK_TOOL(OBJCOPY, objcopy)
fi

# Defined in acinclude.m4.
grub_ASM_USCORE
grub_PROG_OBJCOPY_ABSOLUTE
if test "x$grub_cv_prog_objcopy_absolute" != xyes; then
  AC_MSG_ERROR([GRUB requires a working absolute objcopy; upgrade your binutils])
fi

grub_ASM_PREFIX_REQUIREMENT

grub_ASM_ADDR32
if test "x$grub_cv_asm_addr32" != xyes; then
  AC_MSG_ERROR([GRUB requires GAS .code16 addr32 support; upgrade your binutils])
fi

grub_ASM_ABSOLUTE_WITHOUT_ASTERISK

grub_CHECK_START_SYMBOL
grub_CHECK_USCORE_START_SYMBOL
if test "x$grub_cv_check_start_symbol" != "xyes" \
	-a "x$grub_cv_check_uscore_start_symbol" != "xyes"; then
  AC_MSG_ERROR([Neither start nor _start is defined])
fi

grub_CHECK_USCORE_USCORE_BSS_START_SYMBOL
grub_CHECK_USCORE_EDATA_SYMBOL
grub_CHECK_EDATA_SYMBOL
if test "x$grub_cv_check_uscore_uscore_bss_start_symbol" != "xyes" \
	-a "x$grub_cv_check_uscore_edata_symbol" != "xyes" \
	-a "x$grub_cv_check_edata_symbol" != "xyes"; then
  AC_MSG_ERROR([None of __bss_start, _edata, edata defined])
fi

grub_CHECK_END_SYMBOL
grub_CHECK_USCORE_END_SYMBOL
if test "x$grub_cv_check_end_symbol" != "xyes" \
	-a "x$grub_cv_check_uscore_end_symbol" != "xyes"; then
  AC_MSG_ERROR([Neither end nor _end is defined])
fi

# Check for curses libraries.
AC_ARG_WITH(curses,
  [  --without-curses        do not use curses])

# Get the filename or the whole disk and open it.
# Known to work on NetBSD.
AC_CHECK_LIB(util, opendisk, [GRUB_LIBS="$GRUB_LIBS -lutil"
  AC_DEFINE(HAVE_OPENDISK, 1, [Define if opendisk() in -lutil can be used])])

# Unless the user specify --without-curses, check for curses.
if test "x$with_curses" != "xno"; then
  AC_CHECK_LIB(ncurses, wgetch, [GRUB_LIBS="$GRUB_LIBS -lncurses"
  AC_DEFINE(HAVE_LIBCURSES, 1, [Define if you have a curses library])],
    [AC_CHECK_LIB(curses, wgetch, [GRUB_LIBS="$GRUB_LIBS -lcurses"
       AC_DEFINE(HAVE_LIBCURSES, 1, [Define if you have a curses library])])])
fi

AC_SUBST(GRUB_LIBS)

# Check for headers.
AC_CHECK_HEADERS(string.h strings.h ncurses/curses.h ncurses.h curses.h)

# Check for user options.

# filesystems support.
AC_ARG_ENABLE(ext2fs,
  [  --disable-ext2fs        disable ext2fs support in Stage 2])

if test x"$enable_ext2fs" != xno; then
  FSYS_CFLAGS="$FSYS_CFLAGS -DFSYS_EXT2FS=1"
fi

AC_ARG_ENABLE(fat,
  [  --disable-fat           disable FAT support in Stage 2])

if test x"$enable_fat" != xno; then
  FSYS_CFLAGS="$FSYS_CFLAGS -DFSYS_FAT=1"
fi

AC_ARG_ENABLE(ffs,
  [  --disable-ffs           disable FFS support in Stage 2])

if test x"$enable_ffs" != xno; then
  FSYS_CFLAGS="$FSYS_CFLAGS -DFSYS_FFS=1"
fi

AC_ARG_ENABLE(ufs,
  [  --disable-ufs           disable UFS support in Stage 2])

if test x"$enable_ufs" != xno; then
  FSYS_CFLAGS="$FSYS_CFLAGS -DFSYS_UFS=1"
fi

AC_ARG_ENABLE(ufs2,
  [  --disable-ufs2          disable UFS2 support in Stage 2])

if test x"$enable_ufs2" != xno; then
  FSYS_CFLAGS="$FSYS_CFLAGS -DFSYS_UFS2=1"
fi

AC_ARG_ENABLE(minix,
  [  --disable-minix         disable Minix fs support in Stage 2])

if test x"$enable_minix" != xno; then
  FSYS_CFLAGS="$FSYS_CFLAGS -DFSYS_MINIX=1"
fi

AC_ARG_ENABLE(reiserfs,
  [  --disable-reiserfs      disable ReiserFS support in Stage 2])

if test x"$enable_reiserfs" != xno; then
  FSYS_CFLAGS="$FSYS_CFLAGS -DFSYS_REISERFS=1"
fi

AC_ARG_ENABLE(vstafs,
  [  --disable-vstafs        disable VSTa FS support in Stage 2])

if test x"$enable_vstafs" != xno; then
  FSYS_CFLAGS="$FSYS_CFLAGS -DFSYS_VSTAFS=1"
fi

AC_ARG_ENABLE(jfs,
  [  --disable-jfs           disable IBM JFS support in Stage 2])

if test x"$enable_jfs" != xno; then
  FSYS_CFLAGS="$FSYS_CFLAGS -DFSYS_JFS=1"
fi

AC_ARG_ENABLE(xfs,
  [  --disable-xfs           disable SGI XFS support in Stage 2])

if test x"$enable_xfs" != xno; then
  FSYS_CFLAGS="$FSYS_CFLAGS -DFSYS_XFS=1"
fi

AC_ARG_ENABLE(zfs,
  [  --disable-zfs           disable ZFS support in Stage 2])

if test x"$enable_zfs" != xno; then
  FSYS_CFLAGS="$FSYS_CFLAGS -DFSYS_ZFS=1"
fi

AC_ARG_ENABLE(iso9660,
  [  --disable-iso9660       disable ISO9660 support in Stage 2])

if test x"$enable_iso9660" != xno; then
  FSYS_CFLAGS="$FSYS_CFLAGS -DFSYS_ISO9660=1"
fi

dnl AC_ARG_ENABLE(tftp,
dnl [  --enable-tftp           enable TFTP support in Stage 2])
dnl 
dnl #if test x"$enable_tftp" = xyes; then
dnl FSYS_CFLAGS="$FSYS_CFLAGS -DFSYS_TFTP=1"
dnl fi

AC_ARG_ENABLE(gunzip,
  [  --disable-gunzip        disable decompression in Stage 2])

if test x"$enable_gunzip" = xno; then
  FSYS_CFLAGS="$FSYS_CFLAGS -DNO_DECOMPRESSION=1"
fi

AC_ARG_ENABLE(md5-password,
  [  --disable-md5-password  disable MD5 password support in Stage 2])
if test "x$enable_md5_password" != xno; then
  FSYS_CFLAGS="$FSYS_CFLAGS -DUSE_MD5_PASSWORDS=1"
fi

dnl The netboot support.
dnl General options.
AC_ARG_ENABLE(packet-retransmission,
  [  --disable-packet-retransmission
                          turn off packet retransmission])
if test "x$enable_packet_retransmission" != xno; then
  NET_EXTRAFLAGS="$NET_EXTRAFLAGS -DCONGESTED=1 -DCONFIG_PCI"
fi

AC_ARG_ENABLE(pci-direct,
  [  --enable-pci-direct     access PCI directly instead of using BIOS])
if test "x$enable_pci_direct" = xyes; then
  NET_EXTRAFLAGS="$NET_EXTRAFLAGS -DCONFIG_PCI_DIRECT=1"
fi

dnl Device drivers.
AC_ARG_ENABLE(3c595,
  [  --enable-3c595          enable 3Com595 driver])
if test "x$enable_3c595" = xyes; then
  NET_CFLAGS="$NET_CFLAGS -DINCLUDE_3C595=1"
  NETBOOT_DRIVERS="$NETBOOT_DRIVERS 3c595.o"
fi

AC_ARG_ENABLE(3c90x,
  [  --enable-3c90x          enable 3Com90x driver])
if test "x$enable_3c90x" = xyes; then
  NET_CFLAGS="$NET_CFLAGS -DINCLUDE_3C90X=1"
  NETBOOT_DRIVERS="$NETBOOT_DRIVERS 3c90x.o"
fi

AC_ARG_ENABLE(davicom,
  [  --enable-davicom        enable Davicom driver])
if test "x$enable_davicom" = xyes; then
  NET_CFLAGS="$NET_CFLAGS -DINCLUDE_DAVICOM=1"
  NETBOOT_DRIVERS="$NETBOOT_DRIVERS davicom.o"
fi

AC_ARG_ENABLE(e1000,
  [  --enable-e1000          enable Etherexpress Pro/1000 driver])
if test "x$enable_e1000" = xyes; then
  NET_CFLAGS="$NET_CFLAGS -DINCLUDE_E1000=1"
  NETBOOT_DRIVERS="$NETBOOT_DRIVERS e1000.o"
fi

AC_ARG_ENABLE(eepro100,
  [  --enable-eepro100       enable Etherexpress Pro/100 driver])
if test "x$enable_eepro100" = xyes; then
  NET_CFLAGS="$NET_CFLAGS -DINCLUDE_EEPRO100=1"
  NETBOOT_DRIVERS="$NETBOOT_DRIVERS eepro100.o"
fi

AC_ARG_ENABLE(epic100,
  [  --enable-epic100        enable SMC 83c170 EPIC/100 driver])
if test "x$enable_epic100" = xyes; then
  NET_CFLAGS="$NET_CFLAGS -DINCLUDE_EPIC100=1"
  NETBOOT_DRIVERS="$NETBOOT_DRIVERS epic100.o"
fi

AC_ARG_ENABLE(forcedeth,
  [  --enable-forcedeth      enable Nvidia Geforce driver])
if test "x$enable_forcedeth" = xyes; then
  NET_CFLAGS="$NET_CFLAGS -DINCLUDE_FORCEDETH=1"
  NETBOOT_DRIVERS="$NETBOOT_DRIVERS forcedeth.o"
fi

AC_ARG_ENABLE(natsemi,
  [  --enable-natsemi        enable NatSemi DP8381x driver])
if test "x$enable_natsemi" = xyes; then
  NET_CFLAGS="$NET_CFLAGS -DINCLUDE_NATSEMI=1"
  NETBOOT_DRIVERS="$NETBOOT_DRIVERS natsemi.o"
fi

AC_ARG_ENABLE(ns83820,
  [  --enable-ns83820        enable NS83820 driver])
if test "x$enable_ns83820" = xyes; then
  NET_CFLAGS="$NET_CFLAGS -DINCLUDE_NS83820=1"
  NETBOOT_DRIVERS="$NETBOOT_DRIVERS ns83820.o"
fi

AC_ARG_ENABLE(ns8390,
  [  --enable-ns8390         enable NE2000 PCI driver])
if test "x$enable_ns8390" = xyes; then
  NET_CFLAGS="$NET_CFLAGS -DINCLUDE_NS8390=1"
  NETBOOT_DRIVERS="$NETBOOT_DRIVERS ns8390.o"
fi

AC_ARG_ENABLE(pcnet32,
  [  --enable-pcnet32        enable AMD Lance/PCI PCNet/32 driver])
if test "x$enable_pcnet32" = xyes; then
  NET_CFLAGS="$NET_CFLAGS -DINCLUDE_PCNET32=1"
  NETBOOT_DRIVERS="$NETBOOT_DRIVERS pcnet32.o"
fi

AC_ARG_ENABLE(pnic,
  [  --enable-pnic           enable Bochs Pseudo Nic driver])
if test "x$enable_pnic" = xyes; then
  NET_CFLAGS="$NET_CFLAGS -DINCLUDE_PNIC=1"
  NETBOOT_DRIVERS="$NETBOOT_DRIVERS pnic.o"
fi

AC_ARG_ENABLE(rtl8139,
  [  --enable-rtl8139        enable Realtek 8139 driver])
if test "x$enable_rtl8139" = xyes; then
  NET_CFLAGS="$NET_CFLAGS -DINCLUDE_RTL8139=1"
  NETBOOT_DRIVERS="$NETBOOT_DRIVERS rtl8139.o"
fi

AC_ARG_ENABLE(r8169,
  [  --enable-r8169          enable Realtek 8169 driver])
if test "x$enable_r8169" = xyes; then
  NET_CFLAGS="$NET_CFLAGS -DINCLUDE_R8169=1"
  NETBOOT_DRIVERS="$NETBOOT_DRIVERS r8169.o"
fi

AC_ARG_ENABLE(sis900,
  [  --enable-sis900         enable SIS 900 and SIS 7016 driver])
if test "x$enable_sis900" = xyes; then
  NET_CFLAGS="$NET_CFLAGS -DINCLUDE_SIS900=1"
  NETBOOT_DRIVERS="$NETBOOT_DRIVERS sis900.o"
fi

AC_ARG_ENABLE(sundance,
  [  --enable-sundance       enable Sundance ST201 driver])
if test "x$enable_sundance" = xyes; then
  NET_CFLAGS="$NET_CFLAGS -DINCLUDE_SUNDANCE=1"
  NETBOOT_DRIVERS="$NETBOOT_DRIVERS sundance.o"
fi

AC_ARG_ENABLE(tg3,
  [  --enable-tg3            enable Broadcom Tigon3 driver])
if test "x$enable_tg3" = xyes; then
  NET_CFLAGS="$NET_CFLAGS -DINCLUDE_TG3=1"
  NETBOOT_DRIVERS="$NETBOOT_DRIVERS tg3.o"
fi

AC_ARG_ENABLE(tulip,
  [  --enable-tulip          enable Tulip driver])
if test "x$enable_tulip" = xyes; then
  NET_CFLAGS="$NET_CFLAGS -DINCLUDE_TULIP=1"
  NETBOOT_DRIVERS="$NETBOOT_DRIVERS tulip.o"
fi

AC_ARG_ENABLE(tlan,
  [  --enable-tlan           enable TI ThunderLAN driver])
if test "x$enable_tlan" = xyes; then
  NET_CFLAGS="$NET_CFLAGS -DINCLUDE_TLAN=1"
  NETBOOT_DRIVERS="$NETBOOT_DRIVERS tlan.o"
fi

AC_ARG_ENABLE(undi,
  [  --enable-undi           enable PXE UNDI driver])
if test "x$enable_undi" = xyes; then
  NET_CFLAGS="$NET_CFLAGS -DINCLUDE_UNDI=1"
  NETBOOT_DRIVERS="$NETBOOT_DRIVERS undi.o"
fi

AC_ARG_ENABLE(via-rhine,
  [  --enable-via-rhine      enable Rhine-I/II driver])
if test "x$enable_via_rhine" = xyes; then
  NET_CFLAGS="$NET_CFLAGS -DINCLUDE_VIA_RHINE=1"
  NETBOOT_DRIVERS="$NETBOOT_DRIVERS via_rhine.o"
fi

AC_ARG_ENABLE(w89c840,
  [  --enable-w89c840        enable Winbond W89c840 driver])
if test "x$enable_w89c840" = xyes; then
  NET_CFLAGS="$NET_CFLAGS -DINCLUDE_W89C840=1"
  NETBOOT_DRIVERS="$NETBOOT_DRIVERS w89c840.o"
fi

dnl Check if the netboot support is turned on.
AM_CONDITIONAL(NETBOOT_SUPPORT, test "x$NET_CFLAGS" != x)
if test "x$NET_CFLAGS" != x; then
  FSYS_CFLAGS="$FSYS_CFLAGS -DFSYS_TFTP=1"
fi

dnl extra flag for ns8390.c
AC_ARG_ENABLE(compex-rl2000-fix,
  [  --enable-compex-rl2000-fix
                          specify this if you have a Compex RL2000 PCI])
if test "x$enable_compex_rl2000_fix" = xyes; then
  NET_EXTRAFLAGS="$NET_EXTRAFLAGS -DCOMPEX_RL2000_FIX=1"
fi

AC_ARG_ENABLE(ne-scan,
  [  --enable-ne-scan=LIST   probe for NE base address using LIST],
  [NET_EXTRAFLAGS="$NET_EXTRAFLAGS -DNE_SCAN=$enable_ne_scan"],
  [NET_EXTRAFLAGS="$NET_EXTRAFLAGS -DNE_SCAN=0x280,0x300,0x320,0x340"])

AC_ARG_ENABLE(wd-default-mem,
  [  --enable-wd-default-mem=MEM
                          set the default memory location for WD/SMC],
  [NET_EXTRAFLAGS="$NET_EXTRAFLAGS -DWD_DEFAULT_MEM=$enable_wd_default_mem"],
  [NET_EXTRAFLAGS="$NET_EXTRAFLAGS -DWD_DEFAULT_MEM=0xCC000"])

dnl Diskless
AC_ARG_ENABLE(diskless,
  [  --enable-diskless       enable diskless support])
AM_CONDITIONAL(DISKLESS_SUPPORT, test "x$enable_diskless" = xyes)

dnl Graphical splashscreen support
AC_ARG_ENABLE(graphics,
  [  --disable-graphics      disable graphics terminal support])
AM_CONDITIONAL(GRAPHICS_SUPPORT, test "x$enable_graphics" != xno)

dnl Hercules terminal
AC_ARG_ENABLE(hercules,
  [  --disable-hercules      disable hercules terminal support])
AM_CONDITIONAL(HERCULES_SUPPORT, test "x$enable_hercules" != xno)

dnl Serial terminal
AC_ARG_ENABLE(serial,
  [  --disable-serial        disable serial terminal support])
AM_CONDITIONAL(SERIAL_SUPPORT, test "x$enable_serial" != xno)

dnl Simulation of the slowness of a serial device.
AC_ARG_ENABLE(serial-speed-simulation,
  [  --enable-serial-speed-simulation
                          simulate the slowness of a serial device])
AM_CONDITIONAL(SERIAL_SPEED_SIMULATION,
  test "x$enable_serial_speed_simulation" = xyes)

# Sanity check.
if test "x$enable_diskless" = xyes; then
  if test "x$NET_CFLAGS" = x; then
    AC_MSG_ERROR([You must enable at least one network driver])
  fi
fi

dnl Embed a menu string in GRUB itself.
AC_ARG_ENABLE(preset-menu,
  [  --enable-preset-menu=FILE
                          preset a menu file FILE in Stage 2])
if test "x$enable_preset_menu" = x; then
  :
else
  if test -r $enable_preset_menu; then
    grub_DEFINE_FILE(PRESET_MENU_STRING, [$enable_preset_menu],
    		     [Define if there is user specified preset menu string])
  else
    AC_MSG_ERROR([Cannot read the preset menu file $enable_preset_menu])
  fi
fi

dnl Build the example Multiboot kernel.
AC_ARG_ENABLE(example-kernel,
  [  --enable-example-kernel
                          build the example Multiboot kernel])
AM_CONDITIONAL(BUILD_EXAMPLE_KERNEL, test "x$enable_example_kernel" = xyes)

dnl Automatic Linux mem= option.
AC_ARG_ENABLE(auto-linux-mem-opt,
  [  --disable-auto-linux-mem-opt
                          don't pass Linux mem= option automatically])
if test "x$enable_auto_linux_mem_opt" = xno; then
  :
else
  AC_DEFINE(AUTO_LINUX_MEM_OPT, 1, [Define if you don't want to pass the mem= option to Linux])
fi

dnl Now substitute the variables.
AC_SUBST(FSYS_CFLAGS)
AC_SUBST(NET_CFLAGS)
AC_SUBST(NET_EXTRAFLAGS)
AC_SUBST(NETBOOT_DRIVERS)

dnl Because recent automake complains about CCASFLAGS, set it here.
CCASFLAGS='$(DEFS) $(DEFAULT_INCLUDES) $(INCLUDES) $(CPPFLAGS) $(CFLAGS)'
AC_SUBST(CCASFLAGS)


dnl Output.
AC_CONFIG_FILES([Makefile stage1/Makefile stage2/Makefile \
		 docs/Makefile lib/Makefile util/Makefile \
		 grub/Makefile netboot/Makefile util/grub-image \
		 util/grub-install util/grub-md5-crypt \
		 util/grub-terminfo util/grub-set-default])
AC_OUTPUT
