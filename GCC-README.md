
# Illumos GCC 4

## Intro

This is a work in progress that may or may not work (or work well) at any
given time.  If you encounter problems you think are likely my fault, send me
email describing them in detail.

This has booted to login and done fairly basic work on 32bit and 64bit x86 in
qemu, VirtualBox (32bit), and a random whitebox Athlon 64.  And on a Sun-Fire
V250 on sun4u.  It has been tried nowhere else.

## What you need

### Patched GCC 4.4.4

This is the GCC available at http://github.com/richlowe/gcc on the il-4_4_4
branch.  It is patched in numerous ways, a stock GCC will most certainly not
work.

I've made binary tarballs available, they assume a `--prefix` of
`/opt/gcc/4.4.4` (unpack them from `/opt`)

i386:  http://richlowe.openindiana.org/~richlowe/il-gcc-444-i386.tar.bz2
sparc: http://richlowe.openindiana.org/~richlowe/il-gcc-444-sparc.tar.bz2

### Further patch GCC

Unfortunately, we need to bake appropriate runpaths for libstdc++ and libgcc_s
into the GCC spec, at least at present, so you need to further patch GCC to
reflect the location in which you're going to install it.

Choose a prefix in which to install GCC (the one you'll give to `configure
--prefix`), I'm using /opt/gcc/4.4.4.

Now, look at revision a1583073 (`git show a1583073`).  In every place that
changeset added a /usr/sfw/lib path, adding a matching path based on your
prefix _before_ the SFW path (you need your libcc_s to be found first).

I'm hoping to find a way to avoid doing this, but at present haven't come up
with one that works in every case.

### Build GCC

I've been using a script to make this easier on myself

```bash
#!/bin/ksh -e
VER=$1

if [[ -z $VER ]]; then
    print -u2 "Usage: build.sh <Version>"
    exit 2
fi

export PATH="/opt/dejagnu/bin:/opt/SUNWspro/bin:"
PATH="$PATH:/usr/gnu/bin:/usr/sfw/bin"
PATH="$PATH:/usr/bin:/usr/ccs/bin" 

export CC=/usr/sfw/bin/gcc
export CFLAGS="-g -O2" 

AS_OPTIONS=""
if [[ $(mach) == "sparc" ]]; then
       CFLAGS="$CFLAGS -fkeep-inline-functions"
       AS_OPTIONS="--without-gnu-as --with-as=/usr/ccs/bin/as"
else
     AS_OPTIONS="--with-gnu-as --with-as=/usr/sfw/bin/as"
fi

export STAGE1_CFLAGS=$CFLAGS
export CFLAGS_FOR_TARGET=$CFLAGS

GMSGFMT=/usr/gnu/bin/msgfmt \
../../configure --prefix=/opt/gcc/$VER $AS_OPTIONS \
    --with-ld=/usr/bin/ld \
    --without-gnu-ld \
    --enable-languages="c,c++,objc" \
    --enable-shared  \
    --with-mpfr-include=/usr/include/mpfr \
    --with-gmp-include=/usr/include/gmp

gmake -j8 CFLAGS="$CFLAGS" STAGE1_CFLAGS="$CFLAGS" \
    CFLAGS_FOR_TARGET="$CFLAGS" bootstrap 
```

Then:

```bash
mkdir -p builds/il-444 && cd builds/il-444
../../build.sh 4.4.4
```

If you wish to run the tests, you'll need to install expect, then build and
install dejagnu and run 'gmake check-gcc'.  It's most useful to compare the
test results of an unpatched build and a patch build at the same GCC revision
(the gcc-4.4.4 tag, v. the il-4_4_4 branch for instance).

## Build Illumos

As part of this, I've (at least temporarily) adjusted the build infrastruture
to support building with either version of GCC as either shadow or primary
compiler.  This adds a little complication to building with GCC4

In addition to your normal settings in your env file you should add

```bash
source ./illumos.sh			# Source your normal environment file
export GCC_ROOT=/opt/gcc/4.4.4;		# Where to find GCC4.x
export CW_GCC_DIR=${GCC_ROOT}/bin;	# A temporary hack to allow bootstrap of cw(1)
export __GNUC="";			# Use GCC as the primary compiler
export __GNUC4="";			# Use GCC4 specific flags
```

This should be sufficient to have GCC 4 used as the primary throughout the
build (check nightly.log, and/or run `mcs -p foo.o` to check individual
objects.

## Illumos Live is really helpful

A good and convenient way to test stuff is to use Joyent's illumos-live
(http://github.com/joyent/illumos-live).  My fork contains some additional
changes to make it mildly more convenient if you don't have netbooting
infrastructure.

Just make sure that the projects/illumos tree is a clone of this branch, edit
the generated illumos.sh env file as in "Build Illumos" above, and build it
following their directions.
