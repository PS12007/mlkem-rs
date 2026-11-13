
mlkem::hazmat::compress_d11:
	movzx eax, cx
	movabs rcx, 676419291136
	imul rcx, rax
	movabs rax, 549590673408
	add rax, rcx
	shr rax, 40
	and eax, 2047
	ret
