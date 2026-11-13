
mlkem::hazmat::compress_d4:
	movzx eax, cx
	movabs rcx, 5284525712
	imul rcx, rax
	movabs rax, 549590674048
	add rax, rcx
	shr rax, 40
	and eax, 15
	ret
