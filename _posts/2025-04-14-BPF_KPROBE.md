---
layout: post
title: "BPF_KPROBE"
---

BPF_KPROBE는 bpf_tracing.h에 정의되어있는 매크로 함수다.

```
#define BPF_KPROBE(name, args...)					    \
name(struct pt_regs *ctx);						    \
static __always_inline typeof(name(0))					    \
____##name(struct pt_regs *ctx, ##args);				    \
typeof(name(0)) name(struct pt_regs *ctx)				    \
{									    \
	_Pragma("GCC diagnostic push")					    \
	_Pragma("GCC diagnostic ignored \"-Wint-conversion\"")		    \
	return ____##name(___bpf_kprobe_args(args));			    \
	_Pragma("GCC diagnostic pop")					    \
}									    \
static __always_inline typeof(name(0))					    \
____##name(struct pt_regs *ctx, ##args)
```

조금 복잡해보이는데, eBPF 프로그램을 전처리만 해서 어떻게 변경되는지 확인할 수 있다.

example.bpf.c

```
int BPF_KPROBE(do_unlinkat, int dfd, struct filename *name)
{
    pid_t pid;
    const char *filename;

    pid = bpf_get_current_pid_tgid() >> 32;
    filename = BPF_CORE_READ(name, name);
    bpf_printk("KPROBE ENTRY pid = %d, filename = %s\n", pid, filename);
    return 0;
}
```

전처리 실행

```
clang -E example.bpf.c > example.proc.c
```

결과는 다음과 같다. 

```
int do_unlinkat(struct pt_regs *ctx); 
static inline __attribute__((always_inline)) typeof(do_unlinkat(0)) 
____do_unlinkat(struct pt_regs *ctx, int dfd, struct filename *name); 

typeof(do_unlinkat(0)) do_unlinkat(struct pt_regs *ctx) 
{
    #pragma GCC diagnostic push
    #pragma GCC diagnostic ignored "-Wint-conversion"
    return ____do_unlinkat(ctx, (void *)(((const struct user_pt_regs *)(ctx))->regs[0]), (void *)(((const struct user_pt_regs *)(ctx))->regs[1]));
#pragma GCC diagnostic pop
} 
static inline __attribute__((always_inline)) typeof(do_unlinkat(0)) 
____do_unlinkat(struct pt_regs *ctx, int dfd, struct filename *name)
{
    pid_t pid;
    const char *filename;

    pid = bpf_get_current_pid_tgid() >> 32;
    filename = ({ typeof((name)->name) __r; ({ bpf_probe_read_kernel((void *)(&__r), sizeof(*(&__r)), (const void *)__builtin_preserve_access_index(&((typeof(((name))))(((name))))->name)); }); __r; });
    ({ static const char ____fmt[] = "KPROBE ENTRY pid = %d, filename = %s\n"; bpf_trace_printk(____fmt, sizeof(____fmt), pid, filename); });
    return 0;
}
```

함수 선언과 정의 부분이 분리되어있고, 내부 함수가 추가로 생성되어 내부에서 해당 함수를 호출한다.
왜 이렇게 되어있을까?

kprobe를 사용하면 커널에서 실행되는 데이터를 동적으로 확인할 수 있다. 원하는 위치(커널 함수)와 호출될 핸들러 함수를 kprobe에 등록하면,
원하는 위치의 명령어의 첫 번째 바이트를 중단점 명령어로 바꾼다.
CPU가 중단점에 도달하면 트랩이 발생하고, kprobes는 핸들러 함수를 실행시킨다.

이때 핸들러 함수의 인자로 kprobe 구조체 주소와 저장된 CPU 레지스터 상태를 전달한다.

```
handler_pre(struct kprobe *p, struct pt_regs *regs)
```

핸들러 함수는 위 두개의 인자로 고정된다. CPU 레지스터 상태가 담긴 pt_regs에서 원하는 정보(함수 인자)를 꺼내서 사용한다. 
예를 들어 x86 프로세서일때의 pt_regs는 아래와 같다.

arch/x86/include/uapi/asm/ptrace.h

```
struct pt_regs {
	unsigned long r15;
	unsigned long r14;
	unsigned long r13;
	unsigned long r12;
	unsigned long rbp;
	unsigned long rbx;
	unsigned long r11;
	unsigned long r10;
	unsigned long r9;
	unsigned long r8;
	unsigned long rax;
	unsigned long rcx;
	unsigned long rdx;
	unsigned long rsi;
	unsigned long rdi;

	unsigned long orig_rax;
	unsigned long rip;
	unsigned long cs;
	unsigned long eflags;
	unsigned long rsp;
	unsigned long ss;
};
```

BPF_PROBE 매크로 함수는 사용자가 원하는 데이터만 매개변수로 지정하면 자동으로 pt_regs에서 꺼내서 매핑한다. 

즉 추가로 생성된 내부 함수는 사용자가 지정한 매개변수를 받는 함수이고, 내부 함수를 호출하는 함수는 kprobe에 등록될 핸들러 함수인 것이다.
사용자가 원하는 인자만 지정하면 가져올 수 있게 감싼것으로 보면 될 것 같다. 
```
return ____##name(___bpf_kprobe_args(args));
```
```
#define ___bpf_kprobe_args0()           ctx
#define ___bpf_kprobe_args1(x)          ___bpf_kprobe_args0(), (unsigned long long)PT_REGS_PARM1(ctx)
#define ___bpf_kprobe_args2(x, args...) ___bpf_kprobe_args1(args), (unsigned long long)PT_REGS_PARM2(ctx)
#define ___bpf_kprobe_args3(x, args...) ___bpf_kprobe_args2(args), (unsigned long long)PT_REGS_PARM3(ctx)
#define ___bpf_kprobe_args4(x, args...) ___bpf_kprobe_args3(args), (unsigned long long)PT_REGS_PARM4(ctx)
#define ___bpf_kprobe_args5(x, args...) ___bpf_kprobe_args4(args), (unsigned long long)PT_REGS_PARM5(ctx)
#define ___bpf_kprobe_args6(x, args...) ___bpf_kprobe_args5(args), (unsigned long long)PT_REGS_PARM6(ctx)
#define ___bpf_kprobe_args7(x, args...) ___bpf_kprobe_args6(args), (unsigned long long)PT_REGS_PARM7(ctx)
#define ___bpf_kprobe_args8(x, args...) ___bpf_kprobe_args7(args), (unsigned long long)PT_REGS_PARM8(ctx)
#define ___bpf_kprobe_args(args...)     ___bpf_apply(___bpf_kprobe_args, ___bpf_narg(args))(args)
```

___bpf_kprobe_args는 인자의 개수를 구하고 개수에 따라 위 매크로 함수 중 하나를 호출한다. (실제로는 전부 매크로라서 호출이 아니라 사용된 위치에 대체된다.)

___bpf_narg 매크로 함수는 인자의 개수를 계산한다. 

```
#ifndef ___bpf_nth
#define ___bpf_nth(_, _1, _2, _3, _4, _5, _6, _7, _8, _9, _a, _b, _c, N, ...) N
#endif
#ifndef ___bpf_narg
#define ___bpf_narg(...) \
	___bpf_nth(_, ##__VA_ARGS__, 12, 11, 10, 9, 8, 7, 6, 5, 4, 3, 2, 1, 0)
#endif
```

반환된 인자 개수와 ___bpf_kprobe_args를 ___bpf_apply 매크로 함수로 넘기는데, ___bpf_apply는 단순히 ___bpf_kprobe_args 뒤에 인자 개수를 합친 함수를 호출한다.

```
#ifndef ___bpf_concat
#define ___bpf_concat(a, b) a ## b
#endif
#ifndef ___bpf_apply
#define ___bpf_apply(fn, n) ___bpf_concat(fn, n)
#endif
```

만약 인자의 개수가 2개라면 아래 매크로 함수가 호출된다. 

```
#define ___bpf_kprobe_args2(x, args...) ___bpf_kprobe_args1(args), (unsigned long long)PT_REGS_PARM2(ctx)
```

결국 마지막엔 pt_regs를 user_pt_regs로 캐스팅하고, 해당 구조체의 regs 배열의 인덱스 순서대로 꺼낸값을 반환하는 것을 볼 수 있다. 
실제로 첫 번째 매개변수는 rdi, 두 번째 매개변수는 rsi에 저장되어있다. 

```
#define __PT_REGS_CAST(x) ((const struct user_pt_regs *)(x))
#define __PT_PARM1_REG regs[0]
#define __PT_PARM2_REG regs[1]

#define PT_REGS_PARM1(x) (__PT_REGS_CAST(x)->__PT_PARM1_REG)
#define PT_REGS_PARM2(x) (__PT_REGS_CAST(x)->__PT_PARM2_REG)
```

이러한 과정을 거쳐 실제로 아래와 같이 호출한다. 

```
return ____do_unlinkat(ctx, (void *)(((const struct user_pt_regs *)(ctx))->regs[0]), (void *)(((const struct user_pt_regs *)(ctx))->regs[1]));
```
