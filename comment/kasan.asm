void kmalloc_oob_right(void)
{
	char *ptr;
	size_t size = 123;

	pr_info("out-of-bounds to right\n");
	ptr = kmalloc(size, GFP_KERNEL);
	if (!ptr) {
		pr_err("Allocation failed\n");
		return;
	}

	ptr[size] = 'x';
	ptr[size+1] = 'a';
	ptr[size+2] = 'b';
	ptr[size+3] = 'c';
	kfree(ptr);
}


(gdb) disassemble kmalloc_oob_right
Dump of assembler code for function kmalloc_oob_right:
   0xffffffff815d76a0 <+0>:	push   %rbx
   0xffffffff815d76a1 <+1>:	mov    $0xffffffff82739d80,%rdi
   0xffffffff815d76a8 <+8>:	callq  0xffffffff81121014 <printk>
   0xffffffff815d76ad <+13>:	mov    $0xffffffff82b4b058,%rdi ====
   0xffffffff815d76b4 <+20>:	callq  0xffffffff812cca30 <__asan_load8> ====
   0xffffffff815d76b9 <+25>:	mov    0x1573998(%rip),%rdi        # 0xffffffff82b4b058 <kmalloc_caches+56>
   0xffffffff815d76c0 <+32>:	mov    $0x7b,%edx
   0xffffffff815d76c5 <+37>:	mov    $0xcc0,%esi
   0xffffffff815d76ca <+42>:	callq  0xffffffff812c73c0 <kmem_cache_alloc_trace>
   0xffffffff815d76cf <+47>:	test   %rax,%rax
   0xffffffff815d76d2 <+50>:	je     0xffffffff815d7714 <kmalloc_oob_right+116>
   0xffffffff815d76d4 <+52>:	lea    0x7b(%rax),%rdi ====
   0xffffffff815d76d8 <+56>:	mov    %rax,%rbx
   0xffffffff815d76db <+59>:	callq  0xffffffff812cc7f0 <__asan_store1> ====
   0xffffffff815d76e0 <+64>:	lea    0x7c(%rbx),%rdi ====
   0xffffffff815d76e4 <+68>:	movb   $0x78,0x7b(%rbx)
   0xffffffff815d76e8 <+72>:	callq  0xffffffff812cc7f0 <__asan_store1> ====
   0xffffffff815d76ed <+77>:	lea    0x7d(%rbx),%rdi ====
   0xffffffff815d76f1 <+81>:	movb   $0x61,0x7c(%rbx)
   0xffffffff815d76f5 <+85>:	callq  0xffffffff812cc7f0 <__asan_store1> ====
   0xffffffff815d76fa <+90>:	lea    0x7e(%rbx),%rdi ====
   0xffffffff815d76fe <+94>:	movb   $0x62,0x7d(%rbx)
   0xffffffff815d7702 <+98>:	callq  0xffffffff812cc7f0 <__asan_store1> ====
   0xffffffff815d7707 <+103>:	movb   $0x63,0x7e(%rbx)
   0xffffffff815d770b <+107>:	mov    %rbx,%rdi
   0xffffffff815d770e <+110>:	pop    %rbx
   0xffffffff815d770f <+111>:	jmpq   0xffffffff812c8500 <kfree>
   0xffffffff815d7714 <+116>:	pop    %rbx
   0xffffffff815d7715 <+117>:	mov    $0xffffffff82739dc0,%rdi
   0xffffffff815d771c <+124>:	jmpq   0xffffffff81121014 <printk>


(gdb) disassemble kmalloc_oob_right
Dump of assembler code for function kmalloc_oob_right:
   0xffffffff813846b0 <+0>:	mov    $0xffffffff8220157f,%rdi
   0xffffffff813846b7 <+7>:	callq  0xffffffff810b4dc9 <printk>
   0xffffffff813846bc <+12>:	mov    0xf16995(%rip),%rdi        # 0xffffffff8229b058 <kmalloc_caches+56>
   0xffffffff813846c3 <+19>:	mov    $0x7b,%edx
   0xffffffff813846c8 <+24>:	mov    $0xcc0,%esi
   0xffffffff813846cd <+29>:	callq  0xffffffff811b8a30 <kmem_cache_alloc_trace>
   0xffffffff813846d2 <+34>:	test   %rax,%rax
   0xffffffff813846d5 <+37>:	je     0xffffffff813846ef <kmalloc_oob_right+63>
   0xffffffff813846d7 <+39>:	movb   $0x78,0x7b(%rax)
   0xffffffff813846db <+43>:	movb   $0x61,0x7c(%rax)
   0xffffffff813846df <+47>:	mov    %rax,%rdi
   0xffffffff813846e2 <+50>:	movb   $0x62,0x7d(%rax)
   0xffffffff813846e6 <+54>:	movb   $0x63,0x7e(%rax)
   0xffffffff813846ea <+58>:	jmpq   0xffffffff811b9b10 <kfree>
   0xffffffff813846ef <+63>:	mov    $0xffffffff82201599,%rdi
   0xffffffff813846f6 <+70>:	jmpq   0xffffffff810b4dc9 <printk>
