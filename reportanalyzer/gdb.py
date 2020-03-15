import re
# copied from https://github.com/Exiv2/exiv2/issues/712
text = """Program received signal SIGINT, Interrupt.
0x00007ffff62276a9 in std::__cxx11::basic_string<char, std::char_traits<char>, std::allocator<char> >::_M_append(char const*, unsigned long) () from /usr/lib/x86_64-linux-gnu/libstdc++.so.6
[ Legend: Modified register | Code | Heap | Stack | String ]
───────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────── registers ────
$rax   : 0x0000620001c10a74  →  0xbebebebebe002020
$rbx   : 0x00007fffffccfd80  →  0x0000620001c10080  →  0x2020202020202020 ("        "?)
$rcx   : 0x0               
$rdx   : 0x2               
$rsp   : 0x00007fffffccfa80  →  0x00007fffffccfad0  →  0x00007fffffccfeb0  →  0x00007fffffcd0290  →  0x00007fffffcd0670  →  0x00007fffffcd0a50  →  0x00007fffffcd0e30  →  0x00007fffffcd1210
$rbp   : 0x9f6             
$rsi   : 0x00007ffff69f2020  →  0x0000000000000000
$rdi   : 0x0000620001c10080  →  0x2020202020202020 ("        "?)
$rip   : 0x00007ffff62276a9  →  <std::__cxx11::basic_string<char,+0> add rsp, 0x8
$r8    : 0x00007fffffccfd90  →  0x0000000000000f00
$r9    : 0x9f4             
$r10   : 0x00007fffffccf1e0  →  0x00007ffff6f036b3  →  <operator+0> mov r15, rax
$r11   : 0x00007fffffccf1e0  →  0x00007ffff6f036b3  →  <operator+0> mov r15, rax
$r12   : 0x00000ffffff99f84  →  0x0000000000000000
$r13   : 0x00007fffffccfc20  →  0x0000000041b58ab3
$r14   : 0x00007ffff69600a0  →  0x006e776f6e6b6e75 ("unknown"?)
$r15   : 0x00007fffffffdb20  →  0x0000000041b58ab3
$eflags: [carry PARITY adjust ZERO sign trap INTERRUPT direction overflow resume virtualx86 identification]
$cs: 0x0033 $ss: 0x002b $ds: 0x0000 $es: 0x0000 $fs: 0x0000 $gs: 0x0000 
───────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────── stack ────
0x00007fffffccfa80│+0x0000: 0x00007fffffccfad0  →  0x00007fffffccfeb0  →  0x00007fffffcd0290  →  0x00007fffffcd0670  →  0x00007fffffcd0a50  →  0x00007fffffcd0e30  →  0x00007fffffcd1210     ← $rsp
0x00007fffffccfa88│+0x0008: 0x00007fffffccfe80  →  0x00007ffff69600a0  →  0x006e776f6e6b6e75 ("unknown"?)
0x00007fffffccfa90│+0x0010: 0x00007fffffccfad0  →  0x00007fffffccfeb0  →  0x00007fffffcd0290  →  0x00007fffffcd0670  →  0x00007fffffcd0a50  →  0x00007fffffcd0e30  →  0x00007fffffcd1210
0x00007fffffccfa98│+0x0018: 0x00007ffff681f34b  →  <Exiv2::Internal::indent[abi:cxx11](int)+86> jmp 0x7ffff681f326 <Exiv2::Internal::indent[abi:cxx11](int)+49>
0x00007fffffccfaa0│+0x0020: 0x00000825fff99f84  →  0x0000000000000000
0x00007fffffccfaa8│+0x0028: 0x00007fffffccfd80  →  0x0000620001c10080  →  0x2020202020202020
0x00007fffffccfab0│+0x0030: 0x00007ffff69600a0  →  0x006e776f6e6b6e75 ("unknown"?)
0x00007fffffccfab8│+0x0038: 0x7ebffb45ba0eea00
─────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────── code:x86:64 ────
   0x7ffff622769e <std::__cxx11::basic_string<char,+0> mov    rdi, QWORD PTR [rbx]
   0x7ffff62276a1 <std::__cxx11::basic_string<char,+0> mov    QWORD PTR [rbx+0x8], rbp
   0x7ffff62276a5 <std::__cxx11::basic_string<char,+0> mov    BYTE PTR [rdi+rbp*1], 0x0
 → 0x7ffff62276a9 <std::__cxx11::basic_string<char,+0> add    rsp, 0x8
   0x7ffff62276ad <std::__cxx11::basic_string<char,+0> mov    rax, rbx
   0x7ffff62276b0 <std::__cxx11::basic_string<char,+0> pop    rbx
   0x7ffff62276b1 <std::__cxx11::basic_string<char,+0> pop    rbp
   0x7ffff62276b2 <std::__cxx11::basic_string<char,+0> ret    
   0x7ffff62276b3 <std::__cxx11::basic_string<char,+0> nop    DWORD PTR [rax+rax*1+0x0]
─────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────── threads ────
[#0] Id 1, Name: "exiv2", stopped, reason: SIGINT
───────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────── trace ────
[#0] 0x7ffff62276a9 → std::__cxx11::basic_string<char, std::char_traits<char>, std::allocator<char> >::_M_append(char const*, unsigned long)()
[#1] 0x7ffff681f34b → Exiv2::Internal::indent[abi:cxx11](int)(d=0x825)
[#2] 0x7ffff66eb692 → Exiv2::(anonymous namespace)::BigTiffImage::printIFD(this=0x61300000de80, out=@0x672ac0, option=Exiv2::kpsRecursive, dir_offset=0x80, depth=0xd20)
[#3] 0x7ffff66ebe88 → Exiv2::(anonymous namespace)::BigTiffImage::printIFD(this=0x61300000de80, out=@0x672ac0, option=Exiv2::kpsRecursive, dir_offset=0x80, depth=0xd1f)
[#4] 0x7ffff66ebe88 → Exiv2::(anonymous namespace)::BigTiffImage::printIFD(this=0x61300000de80, out=@0x672ac0, option=Exiv2::kpsRecursive, dir_offset=0x80, depth=0xd1e)
[#5] 0x7ffff66ebe88 → Exiv2::(anonymous namespace)::BigTiffImage::printIFD(this=0x61300000de80, out=@0x672ac0, option=Exiv2::kpsRecursive, dir_offset=0x80, depth=0xd1d)
[#6] 0x7ffff66ebe88 → Exiv2::(anonymous namespace)::BigTiffImage::printIFD(this=0x61300000de80, out=@0x672ac0, option=Exiv2::kpsRecursive, dir_offset=0x80, depth=0xd1c)
[#7] 0x7ffff66ebe88 → Exiv2::(anonymous namespace)::BigTiffImage::printIFD(this=0x61300000de80, out=@0x672ac0, option=Exiv2::kpsRecursive, dir_offset=0x80, depth=0xd1b)
[#8] 0x7ffff66ebe88 → Exiv2::(anonymous namespace)::BigTiffImage::printIFD(this=0x61300000de80, out=@0x672ac0, option=Exiv2::kpsRecursive, dir_offset=0x80, depth=0xd1a)
[#9] 0x7ffff66ebe88 → Exiv2::(anonymous namespace)::BigTiffImage::printIFD(this=0x61300000de80, out=@0x672ac0, option=Exiv2::kpsRecursive, dir_offset=0x80, depth=0xd19)
"""

stacks = []
stack=[]
lastnumber = -1
for line in text.split("\n"):
    number = re.findall(r"#(\d+)", line)
    if not len(number)==1:
        continue
    number = int(number[0])
    if number == 0:
        if stack:
            stacks.append(stack)
        stack = [line]
    elif number == lastnumber+1:
        stack.append(line)
    else:
        stacks.append(stack)
        stack = []
    lastnumber = number
stacks.append(stack)
print(stacks)

def extract_funcnames(line):
    res = []
    for word in line.replace("(anonymous namespace)::","").split():
        if "(" in word:
            res.append(word.split("(")[0])
    return res

for stack in stacks:
    for line in stack:
        print(extract_funcnames(line))
    print("--------------")