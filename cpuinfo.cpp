#include "cpuinfo.h"

#if defined(__GNUC__) && defined(i386)
#define __cpuid__(v, a, b, c, d)                       
__asm__ __volatile__(
	"pushl %%ebx\n\t"
	"cpuid\n\t"
	"movl %%ebx, %%esi\n\t"
	"popl %%ebx\n\t"
	:"=a"(a), "=S"(b), "=c"(c), "=d"(d)
	: "a"(v))
#elif defined(__GNUC__) && defined(__x86_64__)
#define __cpuid__(v, a, b, c, d)                       
__asm__ __volatile__(
	"pushq %%rbx\n\t"
	"cpuid\n\t"
	"movl %%ebx, %%esi\n\t"
	"popq %%rbx\n\t"
	:"=a"(a), "=S"(b), "=c"(c), "=d"(d)
	: "a"(v))
#elif defined(_MSC_VER) && defined(_M_IX86)    
#define __cpuid__(v, a, b, c, d)                       
__asm __volatile{
	__asm mov eax, v
	__asm cpuid
	__asm mov a, eax
	__asm mov b, ebx
	__asm mov c, ecx
	__asm mov d, edx
}
#elif defined(_MSC_VER) && defined(_M_X64)
#define __cpuid__(v, a, b, c, d)                       
{
	unsigned int t[4];
	__cpuid(t, v);
	a = t[0]; b = t[1]; c = t[2]; d = t[3];
}
#else
#define __cpuid__(v, a, b, c, d)                       
(a) = (b) = (c) = (d) = 0
#endif

static int has_cpuid(void)
{
	int has = 0;

#if defined(__GNUC__) && defined(i386)
	__asm__(
		"pushfl\n\t"
		"popl %%eax\n\t"
		"movl %%eax, %%edx\n\t"
		"xorl $0x200000, %%eax\n\t"
		"pushl %%eax\n\t"
		"popfl\n\t"
		"pushfl\n\t"
		"popl %%eax\n\t"
		"xorl %%eax, %%edx\n\t"
		"jz done\n\t"
		"movl $1, %0\n\t"
		"done:\n\t"
		:"=m"(has)
		:
		: "%eax", "%edx"
		);
#elif defined(__GNUC__) && defined(__x86_64__)
	__asm__(
		"pushfq\n\t"
		"popq %%rax\n\t"
		"movq %%rax, %%rdx\n\t"
		"xorq $0x200000, %%eax\n\t"
		"pushq %%rax\n\t"
		"popfq\n\t"
		"pushfq\n\t"
		"popq %%rax\n\t"
		"xorl %%eax, %%edx\n\t"
		"jz done\n\t"
		"movl $1, %0\n\t"
		"done:\n\t"
		:"=m"(has)
		:
		: "%rax", "%rdx"
		);
#elif defined(_MSC_VER) && defined(_M_IX86)
	__asm {
		pushfd
			pop eax
			mov edx, eax
			xor eax, 0x200000
			push eax
			popfd
			pushfd
			pop eax
			xor edx, eax
			jz done
			mov has, 1
		done:
	}
#elif defined(_MSC_VER) && defined(_M_X64)
	has = 1;
#endif

	return has;
}

int cpuinfo(unsigned int eax, cpu_info_t *cpu)
{
	if (!(has_cpuid() && cpu))
		return 0;

	__cpuid__(eax, cpu->eax, cpu->ebx, cpu->ecx, cpu->edx);

	return 1;
}