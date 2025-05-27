## elf-loader启动gcc上报can't load ELF 错误

### 现象

```bash
epkg env create t1
epkg env activate t1
epkg install gcc
gcc --version
# 报错
error: can't load ELF /home/duan/.epkg/envs/t1/usr/bin/gcc  

```

### 分析

增加错误打印

```c
static unsigned long loadelf_anon(int fd, Elf_Ehdr *ehdr, Elf_Phdr *phdr)
{
    unsigned long minva, maxva;
    Elf_Phdr *iter;
    ssize_t sz;
    int flags, dyn = ehdr->e_type == ET_DYN;
    unsigned char *p, *base, *hint;

    minva = (unsigned long)-1;
    maxva = 0;

    // 添加调试信息,打印ELF文件类型和入口点
    z_printf("正在加载ELF文件: 类型=%d, 入口点=0x%lx\n", ehdr->e_type, ehdr->e_entry);

    // 遍历所有程序头,找出可加载段的范围
    for (iter = phdr; iter < &phdr[ehdr->e_phnum]; iter++) {
        if (iter->p_type != PT_LOAD)
            continue;
        if (iter->p_vaddr < minva)
            minva = iter->p_vaddr;
        if (iter->p_vaddr + iter->p_memsz > maxva)
            maxva = iter->p_vaddr + iter->p_memsz;
        
        // 打印每个可加载段的信息
        z_printf("可加载段: 虚拟地址=0x%lx, 内存大小=0x%lx, 标志=0x%x\n",
                iter->p_vaddr, iter->p_memsz, iter->p_flags);
    }

    // 按页对齐地址范围
    minva = TRUNC_PG(minva);
    maxva = ROUND_PG(maxva);

    z_printf("内存范围: 起始=0x%lx, 结束=0x%lx, 大小=0x%lx\n",
            minva, maxva, maxva - minva);

    // 对于动态ELF,让内核选择地址
    hint = dyn ? NULL : (void *)minva;
    // 修改映射标志:动态ELF不使用MAP_FIXED_NOREPLACE
    flags = dyn ? (MAP_PRIVATE | MAP_ANONYMOUS) : (MAP_FIXED_NOREPLACE | MAP_PRIVATE | MAP_ANONYMOUS);

    // 首先尝试映射整个内存范围
    base = z_mmap(hint, maxva - minva, PROT_NONE, flags, -1, 0);
    if (base == (void *)-1) {
        z_printf("初始内存映射失败: errno=%d\n", z_errno);
        return -1;
    }
    z_munmap(base, maxva - minva);

    // 分别映射每个段
    flags = MAP_FIXED_NOREPLACE | MAP_ANONYMOUS | MAP_PRIVATE;
    for (iter = phdr; iter < &phdr[ehdr->e_phnum]; iter++) {
        unsigned long off, start;
        if (iter->p_type != PT_LOAD)
            continue;
        off = iter->p_vaddr & ALIGN;
        start = dyn ? (unsigned long)base : 0;
        start += TRUNC_PG(iter->p_vaddr);
        sz = ROUND_PG(iter->p_memsz + off);

        // 映射段内存
        p = z_mmap((void *)start, sz, PROT_WRITE, flags, -1, 0);
        if (p == (void *)-1) {
            z_printf("段映射失败: 地址=0x%lx, 大小=0x%lx, errno=%d\n", 
                    start, sz, z_errno);
            goto err;
        }

        // 读取段内容
        if (z_lseek(fd, iter->p_offset, SEEK_SET) < 0) {
            z_printf("定位文件偏移失败: offset=0x%lx\n", iter->p_offset);
            goto err;
        }
        if (z_read(fd, p + off, iter->p_filesz) != (ssize_t)iter->p_filesz) {
            z_printf("读取段内容失败: 大小=0x%lx\n", iter->p_filesz);
            goto err;
        }

        // 设置段权限
        z_mprotect(p, sz, PFLAGS(iter->p_flags));
    }

    return (unsigned long)base;
err:
    z_munmap(base, maxva - minva);
    return LOAD_ERR;
}
```



返回结果为

```bash
[duan@8241ac1b6145 src]$ dist/elf-loader-aarch64 /home/duan/.epkg/envs/t1/usr/bin/gcc
正在加载ELF文件: 类型=2, 入口点=0x404940
可加载段: 虚拟地址=0x400000, 内存大小=0xe42a0, 标志=0x5
可加载段: 虚拟地址=0x4fab58, 内存大小=0x3b068, 标志=0x6
内存范围: 起始=0x400000, 结束=0x536000, 大小=0x136000
初始内存映射失败: errno=17
error: can't load ELF /home/duan/.epkg/envs/t1/usr/bin/gcc
```



验证其他程序，可正常工作

```bash
[duan@8241ac1b6145 src]$ dist/elf-loader-aarch64 /home/duan/.epkg/envs/t1/usr/bin/ls
正在加载ELF文件: 类型=3, 入口点=0x5d00
可加载段: 虚拟地址=0x0, 内存大小=0x21ba0, 标志=0x5
可加载段: 虚拟地址=0x3ee90, 内存大小=0x2700, 标志=0x6
内存范围: 起始=0x0, 结束=0x42000, 大小=0x42000
正在加载ELF文件: 类型=3, 入口点=0x194c0
可加载段: 虚拟地址=0x0, 内存大小=0x22de0, 标志=0x5
可加载段: 虚拟地址=0x3eb70, 内存大小=0x27e0, 标志=0x6
内存范围: 起始=0x0, 结束=0x42000, 大小=0x42000
Makefile  c.sh	i686	loader.c  loongarch64  test.sh	z_asm.h  z_epkg.c  z_epkg.o  z_err.o	 z_printf.o    z_syscalls.h  z_utils.c	z_utils.o
aarch64   dist	loader	loader.o  riscv64      x86_64	z_elf.h  z_epkg.h  z_err.c   z_printf.c  z_syscalls.c  z_syscalls.o  z_utils.h
```



```shell
# c.sh
#!/bin/bash

DIR="/home/duan/.epkg/envs/t1/usr/bin"

echo -e "ELF Type\tFile Path"
echo "--------\t---------"

for file in "$DIR"/*; do
    if [[ -f "$file" && -x "$file" ]]; then
        type=$(readelf -h "$file" 2>/dev/null | grep 'Type:' | awk '{print $2}')
        if [[ "$type" == "EXEC" || "$type" == "DYN" ]]; then
            printf "%-8s\t%s\n" "$type" "$file"
        fi
    fi
done


[duan@8241ac1b6145 src]$ bash c.sh
ELF Type	File Path
--------\t---------
DYN     	/home/duan/.epkg/envs/t1/usr/bin/[
EXEC    	/home/duan/.epkg/envs/t1/usr/bin/aarch64-openEuler-linux-gcc
EXEC    	/home/duan/.epkg/envs/t1/usr/bin/aarch64-openEuler-linux-gcc-12
DYN     	/home/duan/.epkg/envs/t1/usr/bin/addr2line
DYN     	/home/duan/.epkg/envs/t1/usr/bin/ar
DYN     	/home/duan/.epkg/envs/t1/usr/bin/arch
DYN     	/home/duan/.epkg/envs/t1/usr/bin/as
...
EXEC    	/home/duan/.epkg/envs/t1/usr/bin/gcc
EXEC    	/home/duan/.epkg/envs/t1/usr/bin/gcc-ar
DYN     	/home/duan/.epkg/envs/t1/usr/bin/ls
DYN     	/home/duan/.epkg/envs/t1/usr/bin/lsattr
EXEC    	/home/duan/.epkg/envs/t1/usr/bin/lto-dump
...
```

验证可知DYN类型的程序可以正常工作，EXEC加载冲突



elf-loader占用了0x400000的入口

```bash
[duan@8241ac1b6145 src]$ dist/elf-loader-aarch64 /home/duan/.epkg/envs/t1/usr/bin/gcc
error: can't load ELF /home/duan/.epkg/envs/t1/usr/bin/gcc
[duan@8241ac1b6145 src]$ readelf -h dist/elf-loader-aarch64
ELF Header:
  Magic:   7f 45 4c 46 02 01 01 00 00 00 00 00 00 00 00 00
  Class:                             ELF64
  Data:                              2's complement, little endian
  Version:                           1 (current)
  OS/ABI:                            UNIX - System V
  ABI Version:                       0
  Type:                              EXEC (Executable file)
  Machine:                           AArch64
  Version:                           0x1
  Entry point address:               0x401680
  Start of program headers:          64 (bytes into file)
  Start of section headers:          72608 (bytes into file)
  Flags:                             0x0
  Size of this header:               64 (bytes)
  Size of program headers:           56 (bytes)
  Number of program headers:         2
  Size of section headers:           64 (bytes)
  Number of section headers:         8
  Section header string table index: 7


```



### 修改方案及验证

```bash

# 定制连接器，修改起始地址
[duan@8241ac1b6145 src]$ cat link.ld
/* file: link.ld */
ENTRY(z_start)

SECTIONS
{
  . = 0x300000; # 修改起始地址

  .text : {
    *(.text .text.*)
  }

  .rodata : {
    *(.rodata .rodata.*)
  }

  .data : {
    *(.data .data.*)
  }

  .bss : {
    *(.bss .bss.*)
    *(COMMON)
  }

  /DISCARD/ : {
    *(.eh_frame)
    *(.note*)
  }
}

[duan@8241ac1b6145 src]$ git diff
diff --git a/src/Makefile b/src/Makefile
index bd22f5d..8978a23 100644
--- a/src/Makefile
+++ b/src/Makefile
@@ -98,6 +98,8 @@ ifeq "$(STATIC)" "1"
   CFLAGS += -static
 endif

+LDFLAGS += -T link.ld
+

[duan@8241ac1b6145 src]$ readelf -h dist/elf-loader-aarch64
ELF Header:
  Magic:   7f 45 4c 46 02 01 01 00 00 00 00 00 00 00 00 00
  Class:                             ELF64
  Data:                              2's complement, little endian
  Version:                           1 (current)
  OS/ABI:                            UNIX - System V
  ABI Version:                       0
  Type:                              EXEC (Executable file)
  Machine:                           AArch64
  Version:                           0x1
  Entry point address:               0x301680
  Start of program headers:          64 (bytes into file)
  Start of section headers:          72608 (bytes into file)
  Flags:                             0x0
  Size of this header:               64 (bytes)
  Size of program headers:           56 (bytes)
  Number of program headers:         2
  Size of section headers:           64 (bytes)
  Number of section headers:         8
  Section header string table index: 7

[duan@8241ac1b6145 src]$ dist/elf-loader-aarch64 /home/duan/.epkg/envs/t1/usr/bin/gcc
gcc: fatal error: no input files
compilation terminated.

[duan@8241ac1b6145 src]$ dist/elf-loader-aarch64 /home/duan/.epkg/envs/t1/usr/bin/gcc --version
gcc (GCC) 12.3.1 (openEuler 12.3.1-30.oe2403)
Copyright (C) 2022 Free Software Foundation, Inc.
This is free software; see the source for copying conditions.  There is NO
warranty; not even for MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
```



### 验证其他架构

使用当前的elf-loader进行构建，提示错误，因为offset不为0

```bash
duan@2b4857a3c566:~/elf-loader/src$ gcc
assertion failed [segment_file_offset == 0]: first load segment not at file offset 0
(ElfMapper.cpp:399 map_elf)
 Trace/breakpoint trap
 

查看elf-loader，offset不为0
duan@2b4857a3c566:~/elf-loader/src$ readelf -l elf-loader

Elf file type is EXEC (Executable file)
Entry point 0x301380
There are 2 program headers, starting at offset 64

Program Headers:
  Type           Offset             VirtAddr           PhysAddr
                 FileSiz            MemSiz              Flags  Align
  LOAD           0x0000000000001000 0x0000000000300000 0x0000000000300000
                 0x00000000000016a4 0x00000000000016a4         0x1000
  LOAD           0x00000000000026c0 0x00000000003016c0 0x00000000003016c0
                 0x00000000000001ac 0x0000000000000284         0x1000

 Section to Segment mapping:
  Segment Sections...
   00     .text
   01     .data .bss
```



### 重新修改

修改Makefile，增加  -Ttext=0x300000，去掉 -T link.ld；

```makefile
# 修改Makefile
@@ -52,7 +52,7 @@ PKG_loongarch64 := gcc-loongarch64-linux-gnu libc6-dev-loong64-cross
 COMMON_FLAGS := -pipe -Wall -Wextra -fno-ident -fno-stack-protector -U_FORTIFY_SOURCE
 CFLAGS += $(COMMON_FLAGS) -fPIC
 LDFLAGS += -nostartfiles -nodefaultlibs -nostdlib
-LDFLAGS += -e z_start -pie -Wl,-Bsymbolic,--no-undefined,--build-id=none
+LDFLAGS += -e z_start -pie -Wl,-Bsymbolic,--no-undefined,--build-id=none,-Ttext=0x300000
 ASFLAGS += $(COMMON_FLAGS) -Wa,--noexecstack
```

