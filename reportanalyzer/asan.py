#encoding: utf-8
import re

def extract_funcnames(line):
    if " in " in line:
        return line.split(" in ")[1].split()[0].split("(")[0]
    return line

def parse_asan(text, func_extract_funcnames=extract_funcnames):
    stacks = []
    tmp=[]
    lastnumber = -1
    for line in text.split("\n"):
        number = re.findall(r"#(\d+)", line)
        if not len(number)==1:
            continue
        number = int(number[0])
        if number == 0:
            if tmp:
                stacks.append(tmp)
            tmp = [extract_funcnames(line)]
        elif number == lastnumber+1:
            tmp.append(extract_funcnames(line))
        else:
            stacks.append(tmp)
            tmp = []
        lastnumber = number
    stacks.append(tmp)
    #print(stacks)
    return stacks

if __name__ == "__main__":
    # copied from https://github.com/Exiv2/exiv2/issues/712
    text = """=================================================================
==16699==ERROR: AddressSanitizer: unknown-crash on address 0x7f9a857b7143 at pc 0x7f9a84dcc1db bp 0x7ffcb8c7b650 sp 0x7ffcb8c7b648
READ of size 1 at 0x7f9a857b7143 thread T0
    #0 0x7f9a84dcc1da in Exiv2::getULong(unsigned char const*, Exiv2::ByteOrder) /home/fuzzer/victim/exiv2/src/types.cpp:289:28
    #1 0x7f9a84ebd4c4 in Exiv2::Internal::CiffDirectory::readDirectory(unsigned char const*, unsigned int, Exiv2::ByteOrder) /home/fuzzer/victim/exiv2/src/crwimage_int.cpp:285:22
    #2 0x7f9a84ebd84e in Exiv2::Internal::CiffComponent::read(unsigned char const*, unsigned int, unsigned int, Exiv2::ByteOrder) /home/fuzzer/victim/exiv2/src/crwimage_int.cpp:231:9
    #3 0x7f9a84ebd84e in Exiv2::Internal::CiffDirectory::readDirectory(unsigned char const*, unsigned int, Exiv2::ByteOrder) /home/fuzzer/victim/exiv2/src/crwimage_int.cpp:305
    #4 0x7f9a84c5c29d in Exiv2::CrwParser::decode(Exiv2::CrwImage*, unsigned char const*, unsigned int) /home/fuzzer/victim/exiv2/src/crwimage.cpp:150:9
    #5 0x7f9a84c5afa0 in Exiv2::CrwImage::readMetadata() /home/fuzzer/victim/exiv2/src/crwimage.cpp:107:9
    #6 0x589421 in Action::Print::printList() /home/fuzzer/victim/exiv2/src/actions.cpp:483:9
    #7 0x57c1df in Action::Print::run(std::__cxx11::basic_string<char, std::char_traits<char>, std::allocator<char> > const&) /home/fuzzer/victim/exiv2/src/actions.cpp:218:26
    #8 0x4f4c5f in main /home/fuzzer/victim/exiv2/src/exiv2.cpp:77:23
    #9 0x7f9a836be82f in __libc_start_main /build/glibc-LK5gWL/glibc-2.23/csu/../csu/libc-start.c:291
    #10 0x41ff38 in _start (/home/fuzzer/victim/exiv2/build/bin/exiv2+0x41ff38)

AddressSanitizer can not describe address in more detail (wild memory access suspected).
SUMMARY: AddressSanitizer: unknown-crash /home/fuzzer/victim/exiv2/src/types.cpp:289:28 in Exiv2::getULong(unsigned char const*, Exiv2::ByteOrder)
Shadow bytes around the buggy address:
  0x0ff3d0aeedd0: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
  0x0ff3d0aeede0: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
  0x0ff3d0aeedf0: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
  0x0ff3d0aeee00: fe fe fe fe fe fe fe fe fe fe fe fe fe fe fe fe
  0x0ff3d0aeee10: fe fe fe fe fe fe fe fe fe fe fe fe fe fe fe fe
=>0x0ff3d0aeee20: fe fe fe fe fe fe fe fe[fe]fe fe fe fe fe fe fe
  0x0ff3d0aeee30: fe fe fe fe fe fe fe fe fe fe fe fe fe fe fe fe
  0x0ff3d0aeee40: fe fe fe fe fe fe fe fe fe fe fe fe fe fe fe fe
  0x0ff3d0aeee50: fe fe fe fe fe fe fe fe fe fe fe fe fe fe fe fe
  0x0ff3d0aeee60: fe fe fe fe fe fe fe fe fe fe fe fe fe fe fe fe
  0x0ff3d0aeee70: fe fe fe fe fe fe fe fe fe fe fe fe fe fe fe fe
Shadow byte legend (one shadow byte represents 8 application bytes):
  Addressable:           00
  Partially addressable: 01 02 03 04 05 06 07
  Heap left redzone:       fa
  Heap right redzone:      fb
  Freed heap region:       fd
  Stack left redzone:      f1
  Stack mid redzone:       f2
  Stack right redzone:     f3
  Stack partial redzone:   f4
  Stack after return:      f5
  Stack use after scope:   f8
  Global redzone:          f9
  Global init order:       f6
  Poisoned by user:        f7
  Container overflow:      fc
  Array cookie:            ac
  Intra object redzone:    bb
  ASan internal:           fe
  Left alloca redzone:     ca
  Right alloca redzone:    cb
==16699==ABORTING"""
    for stack in parse_asan(text):
        for func in stack:
            print(func)
        print("--------------")
