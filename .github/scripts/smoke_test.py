"""
Smoke test a built keystone library with this repository's Python bindings.

usage: smoke_test.py <path to keystone.dll | libkeystone.so | libkeystone.dylib>
"""
import os
import sys
import shutil
import tempfile
import subprocess

lib = os.path.abspath(sys.argv[1])
root = os.path.abspath(os.path.join(os.path.dirname(__file__), '..', '..'))

# stage the bindings next to the library, the way the patching plugin ships them
stage = tempfile.mkdtemp()
shutil.copytree(os.path.join(root, 'bindings', 'python', 'keystone'), os.path.join(stage, 'keystone'))

# use the file name the bindings (and the patching plugin) load on this platform
name = os.path.basename(lib)
if name.endswith('.dll'):
    name = 'keystone.dll'
elif name.endswith('.dylib'):
    name = 'libkeystone.dylib'
elif '.so' in name:
    name = 'libkeystone.so'
shutil.copy(lib, os.path.join(stage, 'keystone', name))

CHECKS = r"""
import sys, os
sys.path.insert(0, %r)
import keystone as k
loaded = os.path.basename(k.keystone._ks._name)
assert loaded == %r, 'loaded %%s instead' %% loaded

def asm(arch, mode, text, ea=0):
    enc, _ = k.Ks(arch, mode).asm(text, ea, True)
    return enc.hex()

X, A = k.KS_ARCH_X86, k.KS_ARCH_ARM
cases = [
    (asm(X, k.KS_MODE_64, 'xor eax, eax'), '31c0'),
    (asm(X, k.KS_MODE_64, 'mov rax, qword ptr [0x140002000]', 0x140001000), '488b05f90f0000'),  # gaasedelen: rip-relative
    (asm(X, k.KS_MODE_64, 'mov rax, qword ptr [0x7fff00000000]', 0x140001000), '48a100000000ff7f0000'),
    (asm(X, k.KS_MODE_32, 'push 0x402000', 0x401000), '6800204000'),
    (asm(A, k.KS_MODE_ARM, 'strbeq r0, [r1]'), '0000c105'),
    (asm(A, k.KS_MODE_THUMB, 'movw r0, #1'), '40f20100'),
    (asm(k.KS_ARCH_ARM64, k.KS_MODE_LITTLE_ENDIAN, 'bl 0x2000', 0x1000), '00040094'),
    (asm(k.KS_ARCH_PPC, k.KS_MODE_PPC32 | k.KS_MODE_BIG_ENDIAN, 'stw 5, 0x18(1)'), '90a10018'),
    (asm(k.KS_ARCH_MIPS, k.KS_MODE_MIPS32 | k.KS_MODE_BIG_ENDIAN, '.set noreorder; b 0x1100', 0x1000), '1000003f'),
    (asm(k.KS_ARCH_SPARC, k.KS_MODE_SPARC32 | k.KS_MODE_BIG_ENDIAN, 'ba 0x1100', 0x1000), '10800040'),
    (asm(k.KS_ARCH_SYSTEMZ, k.KS_MODE_BIG_ENDIAN, 'bcr 0, %%r0'), '0700'),
    (asm(k.KS_ARCH_HEXAGON, k.KS_MODE_LITTLE_ENDIAN, 'nop'), '00c0007f'),
    (asm(k.KS_ARCH_EVM, 0, 'JUMPDEST'), '5b'),
]
bad = [(got, want) for got, want in cases if got != want]
assert not bad, 'mismatches: %%r' %% bad

ks = k.Ks(X, k.KS_MODE_32); ks.syntax = k.KS_OPT_SYNTAX_NASM
assert ks.asm('mov eax, 10', 0, True)[0].hex() == 'b80a000000', 'radix'  # gaasedelen: decimal after setting syntax
print('%%s: %%d cases ok' %% (loaded, len(cases) + 1))
""" % (stage, name)

subprocess.run([sys.executable, '-c', CHECKS], check=True, timeout=120)

# gaasedelen 9ddb5e8: upstream keystone loops forever on an unterminated string
HANG = r"""
import sys; sys.path.insert(0, %r); import keystone as k
try:
    k.Ks(k.KS_ARCH_X86, k.KS_MODE_64).asm(".string '", 0, True)
except k.KsError:
    pass
""" % stage
try:
    subprocess.run([sys.executable, '-c', HANG], check=True, timeout=30)
except subprocess.TimeoutExpired:
    sys.exit("hang test failed: assembling \".string '\" did not return")
print('hang test ok')
