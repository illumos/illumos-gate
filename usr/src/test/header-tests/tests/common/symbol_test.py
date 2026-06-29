#!@PYTHON@
#
# This file and its contents are supplied under the terms of the
# Common Development and Distribution License ("CDDL"), version 1.0.
# You may only use this file in accordance with the terms of version
# 1.0 of the CDDL.
#
# A full copy of the text of the CDDL should have accompanied this
# source.  A copy of the CDDL is also available via the Internet at
# http://www.illumos.org/license/CDDL.
#

#
# Copyright 2026 Gordon W. Ross
#

"""
symbol_test.py - C and C++ symbol visibility test driver.

Reads an environment config file and one or more symbols config files,
generates probe programs for each (symbol, environment) pair, compiles
them, and reports pass/fail.  Supports parallel compilation jobs.

This program is run separately for 64-bit compiles and (where supported)
32-bit compiles by the test driver scripts.  See the setup.ksh scripts in
the ../c-symbols/ and ../cxx-symbols/ directories for examples.

See also tests/common/README.md.
"""

import argparse
import io
import os
import signal
import subprocess
import sys
import tempfile
import threading
from concurrent.futures import ThreadPoolExecutor


# ---------------------------------------------------------------------------
# parse_cfg - shared cfg file parser
# ---------------------------------------------------------------------------

def parse_cfg(fileobj, filename, handlers):
    """
    Parse a cfg file-like object, dispatching each directive line to handlers.

    Handles continuation lines (trailing backslash), blank lines, and comments
    (lines starting with '#').  Each non-blank, non-comment line is split on
    '|' with each field stripped, then dispatched as:

        handlers[keyword](fields, filename, lineno)

    Unknown keywords cause an error via sys.exit().
    """
    lineno = 0
    accum = ''
    for raw in fileobj:
        lineno += 1
        text = raw.rstrip('\n').rstrip('\r')
        if text.endswith('\\'):
            accum += text[:-1]
            continue
        accum += text
        line = accum.strip()
        accum = ''
        if not line or line.startswith('#'):
            continue
        parts = [p.strip() for p in line.split('|')]
        keyword, fields = parts[0], parts[1:]
        if keyword not in handlers:
            sys.exit(
                f'error: {filename}:{lineno}: unknown keyword {keyword!r}')
        handlers[keyword](fields, filename, lineno)


# ---------------------------------------------------------------------------
# CompileEnv - one compilation environment (name, lang standard, defines)
# ---------------------------------------------------------------------------

class CompileEnv:
    """One compilation environment as defined by an 'env' line in the cfg."""

    def __init__(self, name, lang, defs):
        self.name = name
        self.lang = lang    # e.g. 'c++98', 'c99'
        self.defs = defs    # preprocessor defines string, may be empty


# ---------------------------------------------------------------------------
# EnvConfig - loads and represents the env cfg file
# See test_parse_env.py for examples of method calls and results.
# ---------------------------------------------------------------------------

class EnvConfig:
    """
    Loads a compilation environment config file (c-symbols-env.cfg or
    cxx-symbols-env.cfg) and provides environment and group lookup.

    Public attributes:
      envs:   dict  name -> CompileEnv
      groups: dict  name -> frozenset of env names
    """

    def __init__(self, lang):
        self.lang = lang
        self.envs = {}
        self.groups = {}

    def load(self, path):
        """Load env cfg from a file path."""
        # Locations searched for the file:
        #   1. path as given
        #   2. $STF_SUITE/cfg/<path>
        #   3. cfg/<path>
        candidates = [path]
        if not os.path.isabs(path):
            stf = os.environ.get('STF_SUITE', '../..')
            candidates.append(os.path.join(stf, 'cfg', path))
            candidates.append(os.path.join('cfg', path))

        for candidate in candidates:
            if os.path.exists(candidate):
                with open(candidate) as f:
                    self._parse(f, filename=candidate)
                return

        sys.exit(f'error: env cfg file not found: {path}')

    def _parse(self, fileobj, filename='<input>'):
        """
        Parse a file-like object as an environment config file.

        self.lang must be 'c' or 'c++'.  Each env line's lang field is
        validated against this value; a mismatch is an error.
        """
        handlers = {
            'env':       lambda f, fn, ln: self._do_env(f, fn, ln),
            'env_group': self._do_env_group,
        }
        parse_cfg(fileobj, filename, handlers)

    def _do_env(self, fields, filename, lineno):
        if len(fields) != 3:
            sys.exit(
                f'error: {filename}:{lineno}: env: expected 3 fields, '
                f'got {len(fields)}')

        name, env_lang, defs = fields

        # Validate lang consistency
        is_cxx = env_lang.startswith('c++')
        if self.lang == 'c++' and not is_cxx:
            sys.exit(
                f'error: --lang=c++ but {filename} line {lineno} '
                f'has lang {env_lang!r}')
        if self.lang == 'c' and is_cxx:
            sys.exit(
                f'error: --lang=c but {filename} line {lineno} '
                f'has lang {env_lang!r}')

        self.envs[name] = CompileEnv(name=name, lang=env_lang, defs=defs)

    def _do_env_group(self, fields, filename, lineno):
        if len(fields) != 2:
            sys.exit(
                f'error: {filename}:{lineno}: env_group: expected 2 fields, '
                f'got {len(fields)}')

        name, members_str = fields
        members = set()
        for member in members_str.split():
            if member in self.envs:
                members.add(member)
            elif member in self.groups:
                members |= self.groups[member]
            else:
                sys.exit(
                    f'error: {filename}:{lineno}: '
                    f'reference to undefined env {member!r}')

        self.groups[name] = frozenset(members)

    def resolve(self, spec):
        """
        Parse an env spec string like 'CXX98+ -CXX11 +CXX98'.

        Returns (test_set, need_set) where both are sets of env names:
          test_set  - all envs to compile
          need_set  - envs where compilation must succeed (pass)

        Bare name or +name -> added to both test_set and need_set.
        -name -> added to test_set only (must fail).
        """
        test_set = set()
        need_set = set()

        for token in spec.split():
            if token.startswith('+'):
                act = True
                token = token[1:]
            elif token.startswith('-'):
                act = False
                token = token[1:]
            else:
                act = True

            # Expand token - may be a single env or a group
            expanded = self._expand(token)
            test_set |= expanded
            if act:
                need_set |= expanded
            else:
                need_set -= expanded

        return (test_set, need_set)

    def _expand(self, name):
        """Return frozenset of env names for a single env name or group name."""
        if name in self.envs:
            return frozenset({name})
        if name in self.groups:
            return self.groups[name]
        sys.exit(f'error: reference to undefined env or group {name!r}')


# ---------------------------------------------------------------------------
# SymEntry - one symbol entry from a symbols config file
# ---------------------------------------------------------------------------

class SymEntry:
    """One test entry as parsed from a symbols config file."""

    def __init__(self, directive, symbol, env_spec, headers,
                 rtype=None, atypes=None, defval=None):
        self.directive = directive  # 'func' | 'type' | 'value' | 'define'
        self.symbol    = symbol     # name to test
        self.env_spec  = env_spec   # raw env spec string e.g. 'CXX98+ -CXX11'
        self.headers   = headers    # list of header filenames
        self.rtype     = rtype      # return/declaration type (not for define)
        self.atypes    = atypes if atypes is not None else []
        self.defval    = defval     # expected value for 'define', else None


# ---------------------------------------------------------------------------
# SymConfig - loads symbols config files
# See test_parse_sym.py for examples of method calls and results.
# ---------------------------------------------------------------------------

class SymConfig:
    """
    Loads one or more symbols config files.

    Public attributes:
      entries: list of SymEntry, in file order
    """

    def __init__(self):
        self.entries = []

    def load(self, path):
        """Load symbols config from a file path, with STF_SUITE search."""
        candidates = [path]
        if not os.path.isabs(path):
            stf = os.environ.get('STF_SUITE', '../..')
            candidates.append(os.path.join(stf, 'cfg', path))
            candidates.append(os.path.join('cfg', path))

        for candidate in candidates:
            if os.path.exists(candidate):
                with open(candidate) as f:
                    self._parse(f, filename=candidate)
                return

        sys.exit(f'error: symbols config file not found: {path}')

    def _parse(self, fileobj, filename='<input>'):
        """Parse a file-like object as a symbols config file."""
        handlers = {
            'type':   self._do_type,
            'value':  self._do_value,
            'define': self._do_define,
            'func':   self._do_func,
        }
        parse_cfg(fileobj, filename, handlers)

    @staticmethod
    def _split_list(s):
        """Split a semicolon-separated field, stripping each item."""
        return [item.strip() for item in s.split(';') if item.strip()]

    def _do_type(self, fields, filename, lineno):
        # type | decl | headers | envs
        if len(fields) != 3:
            sys.exit(
                f'error: {filename}:{lineno}: type: expected 3 fields, '
                f'got {len(fields)}')
        decl, hdrs, envs = fields
        self.entries.append(SymEntry(
            directive='type',
            symbol=decl,
            rtype=decl,
            headers=self._split_list(hdrs),
            env_spec=envs,
        ))

    def _do_value(self, fields, filename, lineno):
        # value | name | type | headers | envs
        if len(fields) != 4:
            sys.exit(
                f'error: {filename}:{lineno}: value: expected 4 fields, '
                f'got {len(fields)}')
        name, rtype, hdrs, envs = fields
        self.entries.append(SymEntry(
            directive='value',
            symbol=name,
            rtype=rtype,
            headers=self._split_list(hdrs),
            env_spec=envs,
        ))

    def _do_define(self, fields, filename, lineno):
        # define | name | value | headers | envs  (value may be empty)
        if len(fields) != 4:
            sys.exit(
                f'error: {filename}:{lineno}: define: expected 4 fields, '
                f'got {len(fields)}')
        name, defval, hdrs, envs = fields
        self.entries.append(SymEntry(
            directive='define',
            symbol=name,
            defval=defval if defval else None,
            headers=self._split_list(hdrs),
            env_spec=envs,
        ))

    def _do_func(self, fields, filename, lineno):
        # func | name | rtype | atypes | headers | envs
        if len(fields) != 5:
            sys.exit(
                f'error: {filename}:{lineno}: func: expected 5 fields, '
                f'got {len(fields)}')
        name, rtype, atypes, hdrs, envs = fields
        self.entries.append(SymEntry(
            directive='func',
            symbol=name,
            rtype=rtype,
            atypes=self._split_list(atypes),
            headers=self._split_list(hdrs),
            env_spec=envs,
        ))


# ---------------------------------------------------------------------------
# ProbeGen - generates probe program source for a (SymEntry, lang) pair
# See test_gen_probe.py for examples of method calls and results.
# ---------------------------------------------------------------------------

class ProbeGen:

    RESULT_MACRO = (
        '#if __cplusplus >= 201103L\n'
        '#define RESULT(v) result{v}\n'
        '#else\n'
        '#define RESULT(v) result = (v)\n'
        '#endif\n'
    )

    @staticmethod
    def gen_probe(entry, lang):
        """
        Generate probe program source text for a SymEntry and language.

        """
        out = []

        for h in entry.headers:
            out.append(f'#include <{h}>\n')

        rtype = entry.rtype or ''
        prefix, suffix = ProbeGen._split_rtype(rtype)
        is_fnptr = suffix != ''

        # Emit the RESULT() macro for C++ func probes with a non-void,
        # non-fnptr return value (brace-init catches narrowing errors in
        # C++11+; plain assignment used for C++98).
        has_rtype = (entry.directive == 'func' and
                     rtype != '' and rtype != 'void')
        use_result = has_rtype and not is_fnptr and lang == 'c++'

        if use_result:
            out.append(ProbeGen.RESULT_MACRO)

        # Emit return type prefix + trailing space (matches C programs'
        # unconditional addprogch(' ') after the rtype loop).
        if rtype:
            out.append(prefix + ' ')

        if entry.directive == 'type':
            out.append('test_type;\n')

        elif entry.directive == 'value':
            out.append(f'test_value{suffix};\n')
            out.append('void\ntest_func(void)\n{\n')
            out.append(f'\ttest_value = {entry.symbol};\n}}\n')

        elif entry.directive == 'define':
            out.append(f'#if !defined({entry.symbol})')
            if entry.defval:
                out.append(f' || {entry.symbol} != {entry.defval}')
            out.append(f'\n#error {entry.symbol} is not defined or has the wrong value')
            out.append('\n#endif\n')
            out.append('\n')

        elif entry.directive == 'func':
            arglist = ProbeGen._build_arglist(entry.atypes)
            out.append(f'\ntest_func({arglist}){suffix}\n{{\n\t')

            call = f'{entry.symbol}({ProbeGen._build_callargs(entry.atypes)})'

            if use_result:
                out.append(f'{rtype} RESULT({call});\n\treturn result;\n}}')
            elif has_rtype or is_fnptr:
                out.append(f'return {call};\n}}')
            else:
                out.append(f'{call};\n}}')
            out.append('\n')

        return ''.join(out)

    @staticmethod
    def _split_rtype(rtype):
        """
        Split rtype for function pointer support.

        For 'void (*)(int)': returns ('void (*', ')(int)')
        For 'double':        returns ('double', '')
        """
        idx = rtype.find('(*')
        if idx >= 0:
            return rtype[:idx + 2], rtype[idx + 2:]
        return rtype, ''

    @staticmethod
    def _build_arglist(atypes):
        """Build the formal parameter list string, matching C arg-name insertion."""
        if not atypes:
            return 'void'
        parts = []
        for i, atype in enumerate(atypes):
            if atype == '':
                parts.append('void')
            elif atype == 'void':
                parts.append('void')
            elif '(*' in atype:
                idx = atype.index('(*')
                parts.append(f'{atype[:idx + 2]}a{i}{atype[idx + 2:]}')
            elif '[' in atype:
                idx = atype.index('[')
                parts.append(f'{atype[:idx]}a{i}{atype[idx:]}')
            else:
                parts.append(f'{atype} a{i}')
        return ', '.join(parts)

    @staticmethod
    def _build_callargs(atypes):
        """Build actual argument names for the function call, skipping void/empty."""
        return ', '.join(
            f'a{i}' for i, atype in enumerate(atypes)
            if atype not in ('', 'void')
        )


# ---------------------------------------------------------------------------
# Job - inputs to a single (symbol, env) compilation
# ---------------------------------------------------------------------------

class Job:
    """All inputs needed to run one compilation job in a worker thread."""

    __slots__ = ('index', 'entry', 'env', 'expect_pass', 'lang',
                 'compiler', 'mflag', 'arch', 'std_flag', 'base_flags',
                 'tmpdir', 'debug', 'extra_debug', 'force')

    def __init__(self, index, entry, env, expect_pass, lang,
                 compiler, mflag, arch, std_flag, base_flags,
                 tmpdir, debug, extra_debug, force):
        self.index       = index
        self.entry       = entry
        self.env         = env
        self.expect_pass = expect_pass
        self.lang        = lang
        self.compiler    = compiler
        self.mflag       = mflag
        self.arch        = arch          # '64-bit' or '32-bit'
        self.std_flag    = std_flag      # e.g. '-std=c99'
        self.base_flags  = base_flags    # list of flags common to all jobs
        self.tmpdir      = tmpdir
        self.debug       = debug         # -d: show probe + compiler output on failure
        self.extra_debug = extra_debug   # -D: also show compiler command on pass
        self.force       = force         # -f: continue after failures


# ---------------------------------------------------------------------------
# TestDriver - builds job list, drives thread pool, reports results
# ---------------------------------------------------------------------------

class TestDriver:
    """
    Expands symbol entries × environments into jobs, runs them in a thread
    pool, and reports results.
    """

    def run(self, entries, env_config, compiler, mflag, arch,
                base_flags, tmpdir, opts):
        """
        Run all (symbol, env) compilations.

        Returns True if all tests passed (and not interrupted), else False.
        """
        lock = threading.Lock()
        stop = threading.Event()
        counters = {'pass': 0, 'fail': 0}

        orig_sigint  = signal.getsignal(signal.SIGINT)
        orig_sigterm = signal.getsignal(signal.SIGTERM)

        def handle_signal(signum, frame):
            stop.set()

        signal.signal(signal.SIGINT,  handle_signal)
        signal.signal(signal.SIGTERM, handle_signal)

        # run_job() is the worker function called by each thread in the pool.
        # It captures all output for one job in a local buffer, then acquires
        # the lock to write (flush) it contiguously to the output stream.
        def run_job(job):
            if stop.is_set():
                return

            # Generate probe source and write to temp file.
            src  = ProbeGen.gen_probe(job.entry, job.lang)
            ext  = 'cc' if job.lang == 'c++' else 'c'
            base = os.path.join(job.tmpdir, f'job-{job.index}')
            srcfile = f'{base}.{ext}'
            objfile = f'{base}.o'
            logfile = f'{base}.log'

            with open(srcfile, 'w') as f:
                f.write(src)

            # Build compiler command.
            env_defs = job.env.defs.split() if job.env.defs else []
            cmd = ([job.compiler, job.mflag, job.std_flag] +
                   job.base_flags + env_defs +
                   ['-c', srcfile, '-o', objfile])

            with open(logfile, 'w') as lf:
                proc = subprocess.run(cmd, stdout=lf, stderr=lf)

            compile_ok = (proc.returncode == 0)
            passed     = (compile_ok == job.expect_pass)

            # Output buffer (flushed at end of job)
            sign  = '+' if job.expect_pass else '-'
            label = f'{job.entry.symbol} : {sign}{job.env.name} ({job.arch})'
            out   = [f'TEST STARTING {label}:']

            if job.extra_debug:
                out.append(f'TEST DEBUG {label}: command: {" ".join(cmd)}')

            if job.debug and not passed:
                out.append(f'TEST DEBUG {label}: probe program:')
                for line in src.splitlines():
                    out.append(f'TEST DEBUG {label}:   {line}')
                with open(logfile) as lf:
                    cc_out = lf.read().strip()
                if cc_out:
                    out.append(f'TEST DEBUG {label}: compiler output:')
                    for line in cc_out.splitlines():
                        out.append(f'TEST DEBUG {label}:   {line}')

            if passed:
                out.append(f'TEST PASS: {label}')
            else:
                verb   = 'FAILING' if job.force else 'FAILED'
                reason = (f'error compiling in {job.env.name}'
                          if job.expect_pass
                          else f'symbol visible in {job.env.name}')
                out.append(f'TEST {verb} {label}: {reason}')

            with lock:
                print('\n'.join(out), flush=True)
                if passed:
                    counters['pass'] += 1
                else:
                    counters['fail'] += 1
                    if not job.force:
                        stop.set()

        # Build the list of jobs to run.
        jobs = []
        for entry in entries:
            if opts.sym and entry.symbol != opts.sym:
                continue
            test_set, need_set = env_config.resolve(entry.env_spec)
            if opts.env:
                narrow, _ = env_config.resolve(opts.env)
                test_set  &= narrow
                need_set  &= narrow
            for env_name in sorted(test_set):
                env = env_config.envs[env_name]
                jobs.append(Job(
                    index=len(jobs),
                    entry=entry,
                    env=env,
                    expect_pass=(env_name in need_set),
                    lang=opts.lang,
                    compiler=compiler,
                    mflag=mflag,
                    arch=arch,
                    std_flag=f'-std={env.lang}',
                    base_flags=base_flags,
                    tmpdir=tmpdir,
                    debug=opts.debug,
                    extra_debug=opts.extra_debug,
                    force=opts.force,
                ))

        # The ThreadPoolExecutor runs up to opts.j worker threads concurrently.
        # executor.submit() queues each job; the pool calls run_job(job) in a
        # worker thread.  Exiting the "with" block waits for all submitted jobs
        # to finish before proceeding.
        with ThreadPoolExecutor(max_workers=opts.j) as executor:
            for job in jobs:
                executor.submit(run_job, job)

        signal.signal(signal.SIGINT,  orig_sigint)
        signal.signal(signal.SIGTERM, orig_sigterm)

        passes = counters['pass']
        total  = passes + counters['fail']
        if passes == total:
            print(f'TEST SUMMARY: {passes} / {total} (ok)')
        else:
            print(f'TEST SUMMARY: {passes} / {total} ({total - passes} failing)')

        return counters['fail'] == 0 and not stop.is_set()


# ---------------------------------------------------------------------------
# Compiler detection
# ---------------------------------------------------------------------------

# Exit codes emitted by the compiler-detection probe.
_COMP_STUDIO  = 51
_COMP_CLANG   = 52
_COMP_GCC     = 53
_COMP_UNKNOWN = 99

# clang defines both __GNUC__ and __clang__, therefore test for
# __clang__ ahead of __GNUC__.

_C_PROBE_SRC = """\
#include <stdlib.h>
int main(int argc, char **argv) {
#if defined(__SUNPRO_C)
exit(51);
#elif defined(__clang__)
exit(52);
#elif defined(__GNUC__)
exit(53);
#else
exit(99);
#endif
}
"""

_CXX_PROBE_SRC = """\
#include <cstdlib>
int main(int argc, char **argv) {
#if defined(__SUNPRO_CC)
exit(51);
#elif defined(__clang__)
exit(52);
#elif defined(__GNUC__)
exit(53);
#else
exit(99);
#endif
}
"""

# Base flags used for all C compilations.
# We turn off -Wformat-security because the auto-generated tests don't pass
# string literals to printf family functions, which will trigger warnings in
# some compilers (e.g. clang-16).
_C_BASE_FLAGS = [
    '-Wall', '-Werror', '-nostdinc',
    '-isystem', '/usr/include',
    '-Wno-format-security',
]


def _run_compiler_probe(compiler, src, ext, mflag, tmpdir):
    """
    Write src to detect.ext, compile with compiler+mflag, run the result.
    Returns the probe exit code, or None on compile/exec failure.
    """
    srcfile   = os.path.join(tmpdir, f'detect.{ext}')
    exec_name = os.path.join(tmpdir, 'detect')
    with open(srcfile, 'w') as f:
        f.write(src)
    try:
        r = subprocess.run(
            [compiler, mflag, srcfile, '-o', exec_name],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        if r.returncode != 0:
            return None
        r = subprocess.run(
            [exec_name],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        return r.returncode
    except OSError:
        return None


def _validate_c_compiler(cc, mflag, tmpdir):
    """Return True if cc is a usable C compiler (gcc or clang); else False."""
    code = _run_compiler_probe(cc, _C_PROBE_SRC, 'c', mflag, tmpdir)
    return code in (_COMP_GCC, _COMP_CLANG)


def _validate_cxx_compiler(cc, mflag, tmpdir):
    """Return True if cc is a usable C++ compiler (g++ or clang++); else False."""
    code = _run_compiler_probe(cc, _CXX_PROBE_SRC, 'cc', mflag, tmpdir)
    return code in (_COMP_GCC, _COMP_CLANG)


def _compiler_kind(compiler):
    """
    Return 'clang' or 'gcc' by inspecting the compiler's --version output.
    Used when an explicit compiler path is given and the kind cannot be
    inferred from the name.
    """
    result = subprocess.run(
        [compiler, '--version'],
        capture_output=True, text=True)
    if 'clang' in result.stdout.lower():
        return 'clang'
    return 'gcc'


def find_c_compiler(mflag, tmpdir, explicit=None):
    """
    Find a usable C compiler.  Returns the compiler path.
    Raises SystemExit if none is found.
    """
    candidates = [explicit] if explicit else ['gcc', 'clang']
    for cc in candidates:
        if _validate_c_compiler(cc, mflag, tmpdir):
            return cc
    if explicit:
        sys.exit(f'error: C compiler {explicit!r} is not usable')
    sys.exit('error: no usable C compiler found (tried gcc, clang)')


def find_cxx_compiler(mflag, tmpdir, explicit=None):
    """
    Find a usable C++ compiler.  Returns (compiler, kind) where kind is
    'gcc' or 'clang'.  Raises SystemExit if none is found.
    """
    if explicit:
        if not _validate_cxx_compiler(explicit, mflag, tmpdir):
            sys.exit(f'error: C++ compiler {explicit!r} is not usable')
        return explicit, _compiler_kind(explicit)
    for cc, kind in [('g++', 'gcc'), ('clang++', 'clang')]:
        if _validate_cxx_compiler(cc, mflag, tmpdir):
            return cc, kind
    sys.exit('error: no usable C++ compiler found (tried g++, clang++)')


def find_gcc_cxx_includes(compiler):
    """
    Query a GCC C++ compiler for its internal include directory and return a
    base_flags list with all necessary -isystem paths.

    The compiler reports its internal include directory as, e.g.:
      /opt/gcc-14/lib/gcc/x86_64-pc-solaris2.11/14.2.0/include

    We parse out prefix, target triple, and version, then build:
      -isystem prefix/include/c++/version
      -isystem prefix/include/c++/version/target
      -isystem prefix/lib/gcc/target/version/include
      -isystem /usr/include
    """
    result = subprocess.run(
        [compiler, '-print-file-name=include'],
        capture_output=True, text=True)
    buf = result.stdout.strip()

    sep = '/lib/gcc/'
    idx = buf.find(sep)
    if idx < 0:
        sys.exit(f'error: unexpected -print-file-name=include output: {buf!r}')

    prefix = buf[:idx]
    rest   = buf[idx + len(sep):]   # "target/version/include"
    parts  = rest.split('/')
    if len(parts) < 3:
        sys.exit(f'error: cannot parse target/version from: {buf!r}')
    target  = parts[0]
    version = parts[1]

    return [
        '-Wall', '-Werror', '-nostdinc',
        '-isystem', f'{prefix}/include/c++/{version}',
        '-isystem', f'{prefix}/include/c++/{version}/{target}',
        '-isystem', f'{prefix}/lib/gcc/{target}/{version}/include',
        '-isystem', '/usr/include',
        '-Wno-format-security',
    ]


def find_clang_cxx_includes(compiler):
    """
    Query a clang++ compiler for its C++ include search paths by running
    it in preprocessing mode with -v, then parse the include list from
    stderr.  Returns a base_flags list with -isystem for each path found,
    plus -isystem /usr/include.
    """
    result = subprocess.run(
        [compiler, '-xc++', '-E', '-v', '-'],
        input='', capture_output=True, text=True)

    paths = []
    in_list = False
    for line in result.stderr.splitlines():
        if line == '#include <...> search starts here:':
            in_list = True
        elif line == 'End of search list.':
            break
        elif in_list:
            paths.append(line.strip())

    if not paths:
        sys.exit(f'error: could not determine C++ include paths from {compiler}')

    flags = ['-Wall', '-Werror', '-nostdinc']
    for p in paths:
        flags += ['-isystem', p]
    if '/usr/include' not in paths:
        flags += ['-isystem', '/usr/include']
    flags.append('-Wno-format-security')
    return flags


# ---------------------------------------------------------------------------
# Argument parsing and main
# ---------------------------------------------------------------------------

def _parse_args():
    p = argparse.ArgumentParser(
        description='Test C/C++ symbol visibility in system headers.')

    p.add_argument('--lang', required=True, choices=('c', 'c++'),
                   help='Language to test')

    bits = p.add_mutually_exclusive_group(required=True)
    bits.add_argument('-m64', dest='mflag', action='store_const', const='-m64',
                      help='Compile for 64-bit')
    bits.add_argument('-m32', dest='mflag', action='store_const', const='-m32',
                      help='Compile for 32-bit')

    p.add_argument('-c', dest='compiler', metavar='COMPILER', default=None,
                   help='Explicit compiler path')
    p.add_argument('-d', dest='debug', action='store_true',
                   help='Show probe and compiler output on failure')
    p.add_argument('-D', dest='extra_debug', action='store_true',
                   help='Also show compiler command (implies -d)')
    p.add_argument('-e', dest='env', metavar='ENV', default=None,
                   help='Narrow to one environment name')
    p.add_argument('-f', dest='force', action='store_true',
                   help='Continue after failures')
    p.add_argument('-j', dest='j', metavar='N', type=int, default=None,
                   help='Number of parallel jobs (default: SYMBOL_TEST_JOBS or 4)')
    p.add_argument('-s', dest='sym', metavar='SYM', default=None,
                   help='Narrow to one symbol name')

    p.add_argument('-C', dest='compiler_check', action='store_true',
                   help='Check compiler only, do not run tests')

    p.add_argument('env_cfg', nargs='?', help='Environment config file')
    p.add_argument('sym_cfgs', nargs='*', metavar='sym_cfg',
                   help='One or more symbols config files')

    args = p.parse_args()
    if args.extra_debug:
        args.debug = True
    jobs = 4
    env_jobs = os.environ.get('SYMBOL_TEST_JOBS')
    if env_jobs is not None:
        jobs = int(env_jobs)
    if args.j is not None:
        jobs = args.j
    args.j = jobs
    if not args.compiler_check and not args.env_cfg:
        p.error('env_cfg is required unless -C is specified')
    if not args.compiler_check and not args.sym_cfgs:
        p.error('at least one sym_cfg is required unless -C is specified')
    return args


def main():
    args = _parse_args()
    mflag = args.mflag
    arch  = '64-bit' if mflag == '-m64' else '32-bit'

    with tempfile.TemporaryDirectory() as tmpdir:
        if args.lang == 'c':
            compiler   = find_c_compiler(mflag, tmpdir, args.compiler)
            base_flags = _C_BASE_FLAGS
        else:
            # kind is 'gcc' or 'clang', used to select the right
            # include path discovery method.
            compiler, kind = find_cxx_compiler(mflag, tmpdir, args.compiler)
            if kind == 'gcc':
                base_flags = find_gcc_cxx_includes(compiler)
            else:
                base_flags = find_clang_cxx_includes(compiler)

        if args.compiler_check:
            sys.exit(0)

        env_cfg = EnvConfig(args.lang)
        env_cfg.load(args.env_cfg)

        sym_cfg = SymConfig()
        for path in args.sym_cfgs:
            sym_cfg.load(path)

        ok = TestDriver().run(
            sym_cfg.entries, env_cfg, compiler,
            mflag, arch, base_flags, tmpdir, args)

    sys.exit(0 if ok else 1)


if __name__ == '__main__':
    main()
