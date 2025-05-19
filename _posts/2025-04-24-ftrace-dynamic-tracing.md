---
layout: post
title: "ftrace 매커니즘 검증하기"
---

ftrace 기반의 동적 추적은 CPU가 무시하는 NOP 명령어를 커널 함수의 시작부분에 삽입하고 런타임에 핸들러 함수를 호출하는 명령어 패치로 실행된다. 동적 추적 설정을 활성화한 후 컴파일하면 커널 함수의 시작 5바이트에 NOP 명령어가 추가된다. 
그래서 추적할 커널 함수의 시작 5바이트를 볼 수 있다면 함수 호출 명령어로 패치되는지 확인할 수 있다.

get_inst.c
```
#include <linux/init.h>
#include <linux/module.h>
#include <linux/kallsyms.h>
#include <linux/kprobes.h>
static struct kprobe kp = {
    .symbol_name = "kallsyms_lookup_name"
};

static int __init hello_init(void)
{
    typedef unsigned long (*kallsyms_lookup_name_t)(const char *name);
    kallsyms_lookup_name_t kallsyms_lookup_name;
    int i = 0;
    register_kprobe(&kp);
    kallsyms_lookup_name = (kallsyms_lookup_name_t) kp.addr;
    unregister_kprobe(&kp);

    // do_unlinkat() 커널 함수 추적
    char *func_addr = (char *)kallsyms_lookup_name("do_unlinkat");

    for (i = 0; i < 5; i++)
    {
        pr_info("0x%02x ", (u8)func_addr[i]);
    }

    pr_info("fun addr 0x%lx\n", func_addr);
    return 0;
}
module_init(hello_init);


static void __exit hello_exit(void)
{
    printk("Hello World Module Exit\n");
}
module_exit(hello_exit);


MODULE_LICENSE("GPL");
MODULE_AUTHOR("dwh0403");
MODULE_DESCRIPTION("hello world module");
MODULE_ALIAS("hello_module");
```

Makefile
```
obj-m := get_inst.o

KERNELBUILD :=/lib/modules/$(shell uname -r)/build

default:
        make -C $(KERNELBUILD) M=$(shell pwd) modules
clean:
        rm -rf *.o *.ko *.mod.c .*.cmd *.markers *.order *.symvers .tmp_versions
```

실행 (환경: ubuntu x86 64bit)
```
$ make
$ sudo insmod get_inst.ko
$ sudo dmesg
[2308853.381185] 0x0f
[2308853.381190] 0x1f
[2308853.381191] 0x44
[2308853.381192] 0x00
[2308853.381193] 0x00
[2308853.381194] fun addr 0xffffffffbbaf5e40
$ sudo rmmod get_inst
```

실제 x86 64bit 에서 정의한 5바이트 NOP 명령어와 동일하다. 

arch/x86/include/asm/nops.h
```
#define BYTES_NOP1	0x90
#define BYTES_NOP2	0x66,BYTES_NOP1
#define BYTES_NOP3	0x0f,0x1f,0x00
#define BYTES_NOP4	0x0f,0x1f,0x40,0x00
#define BYTES_NOP5	0x0f,0x1f,0x44,0x00,0x00
```

fentry를 사용하는 eBPF 프로그램을 로드하고 실행한다. (실행은 [eunomia.dev](https://eunomia.dev/tutorials/3-fentry-unlink/) 또는 libbpf-bootstrap 참고)
```
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

char LICENSE[] SEC("license") = "Dual BSD/GPL";

SEC("fentry/do_unlinkat")
int BPF_PROG(do_unlinkat, int dfd, struct filename *name)
{
    pid_t pid;

    pid = bpf_get_current_pid_tgid() >> 32;
    bpf_printk("fentry: pid = %d, filename = %s\n", pid, name->name);
    return 0;
}

SEC("fexit/do_unlinkat")
int BPF_PROG(do_unlinkat_exit, int dfd, struct filename *name, long ret)
{
    pid_t pid;

    pid = bpf_get_current_pid_tgid() >> 32;
    bpf_printk("fexit: pid = %d, filename = %s, ret = %ld\n", pid, name->name, ret);
    return 0;
}
```
```
$ sudo insmod get_inst.ko
$ sudo dmesg
[2309217.760782] 0xe8
[2309217.760787] 0x7b
[2309217.760788] 0x54
[2309217.760789] 0x87
[2309217.760790] 0x04
[2309217.760791] fun addr 0xffffffffbbaf5e40
```

아래 코드로 호출되는 함수의 주소를 구할 수 있다. 

calc.c

```
#include <stdio.h>
#include <stdint.h>

uint64_t calculate_call_target(uint64_t call_instruction_address, uint32_t rel32) {
    int32_t signed_offset = (int32_t)rel32;
    return call_instruction_address + 5 + signed_offset;
}

int main() {
    uint64_t call_addr = 0xffffffffbbaf5e40;
    // 7b 54 87 04 -> 04 87 54 7b
    uint32_t rel32 = 0x0487547b;

    uint64_t target = calculate_call_target(call_addr, rel32);

    printf("CALL 명령어 주소:        0x%lx\n", call_addr);
    printf("오프셋 (rel32):         0x%x\n", rel32);
    printf("CALL이 점프할 주소:     0x%lx\n", target);

    return 0;
}
```

```
$ clang -o clac clac.c
$ ./clac
CALL 명령어 주소:        0xffffffffbbaf5e40
오프셋 (rel32):         0x487547b
CALL이 점프할 주소:     0xffffffffc036b2c0
```

심볼주소 확인

```
$ sudo cat /proc/kallsyms | grep c036b2c0
ffffffffc036b2c0 t bpf_trampoline_6442575765	[bpf]
```

eBPF 대신 커널 트레이싱 활성화로도 확인이 가능하다. 

```
$ cd /sys/kernel/debug/tracing
$ sudo echo 'p:do_unlinkat do_unlinkat' >> kprobe_events
$ sudo echo 1 > events/kprobes/do_unlinkat/enable
```
```
$ sudo dmesg
[2354550.346010] 0xe8
[2354550.346013] 0xbb
[2354550.346015] 0x51
[2354550.346016] 0xcb
[2354550.346017] 0x04
[2354550.346018] fun addr 0xffffffffbbaf5e40
$ ./calc
CALL 명령어 주소:        0xffffffffbbaf5e40
오프셋 (rel32):         0x4cb51bb
CALL이 점프할 주소:     0xffffffffc07ab000
$ sudo cat /proc/kallsyms | grep c07ab000
ffffffffc07ab000 t ftrace_trampoline	[__builtin__ftrace]
```
<br>
참조
- [Dynamic Tracking Triggered by a Pondering Question: A 'Case Study'](https://www.ebpf.top/en/post/ftrace_kernel_dynamic/)
- [Monitoring unlink System Calls with fentry](https://eunomia.dev/tutorials/3-fentry-unlink/)
