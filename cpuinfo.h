//
//#ifndef CPUINFO_H
//#define CPUINFO_H
//
//#ifdef __cplusplus
//extern "C" {
//#endif
//
//#define CPU_HAS_RDRAND           0x40000000
//#define CPU_HAS_F16C             0x20000000
//#define CPU_HAS_AVX              0x10000000
//#define CPU_HAS_OSXSAVE          0x08000000
//#define CPU_HAS_XSAVE            0x04000000
//#define CPU_HAS_AES              0x02000000
//#define CPU_HAS_TSC_DEADLINE     0x01000000
//#define CPU_HAS_POPCNT           0x00800000
//#define CPU_HAS_MOVBE            0x00400000
//#define CPU_HAS_x2APIC           0x00200000
//#define CPU_HAS_SSE4_2           0x00100000
//#define CPU_HAS_SSE4_1           0x00080000
//#define CPU_HAS_DCA              0x00040000
//#define CPU_HAS_PCID             0x00020000
//#define CPU_HAS_PDCM             0x00008000
//#define CPU_HAS_xTPR             0x00004000
//#define CPU_HAS_CMPXCHG          0x00002000
//#define CPU_HAS_FMA              0x00001000
//#define CPU_HAS_SDBG             0x00000800
//#define CPU_HAS_CNXT_ID          0x00000400
//#define CPU_HAS_SSSE3            0x00000200
//#define CPU_HAS_TM2              0x00000100
//#define CPU_HAS_EIST             0x00000080
//#define CPU_HAS_SMX              0x00000040
//#define CPU_HAS_VMX              0x00000020
//#define CPU_HAS_DS_CPL           0x00000010
//#define CPU_HAS_MONITOR          0x00000008
//#define CPU_HAS_DTES64           0x00000004
//#define CPU_HAS_PCLMULQDQ        0x00000002
//#define CPU_HAS_SSE3             0x00000001
//
//#define CPU_HAS_PBE              0x80000000
//#define CPU_HAS_TM               0x20000000
//#define CPU_HAS_HTT              0x10000000
//#define CPU_HAS_SS               0x08000000
//#define CPU_HAS_SSE2             0x04000000
//#define CPU_HAS_SSE              0x02000000
//#define CPU_HAS_FXSR             0x01000000
//#define CPU_HAS_MMX              0x00800000
//#define CPU_HAS_ACPI             0x00400000
//#define CPU_HAS_DS               0x00200000
//#define CPU_HAS_CLFSH            0x00080000
//#define CPU_HAS_PSN              0x00040000
//#define CPU_HAS_PSE36            0x00020000
//#define CPU_HAS_PAT              0x00010000
//#define CPU_HAS_CMOV             0x00008000
//#define CPU_HAS_MCA              0x00004000
//#define CPU_HAS_PGE              0x00002000
//#define CPU_HAS_MTRR             0x00001000
//#define CPU_HAS_SEP              0x00000800
//#define CPU_HAS_APIC             0x00000200
//#define CPU_HAS_CX8              0x00000100
//#define CPU_HAS_MCE              0x00000080
//#define CPU_HAS_PAE              0x00000040
//#define CPU_HAS_MSR              0x00000020
//#define CPU_HAS_TSC              0x00000010
//#define CPU_HAS_PSE              0x00000008
//#define CPU_HAS_DE               0x00000004
//#define CPU_HAS_VME              0x00000002
//#define CPU_HAS_FPU              0x00000001
//
//	typedef struct {
//		unsigned int eax;
//		unsigned int ebx;
//		unsigned int ecx;
//		unsigned int edx;
//	} cpu_info_t;
//
//	extern int cpuinfo(unsigned int eax, cpu_info_t *cpu);
//
//#ifdef __cplusplus
//}
//#endif
//
//#endif /* CPUINFO_H */
