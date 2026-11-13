
mlkem::hazmat::compress_d10:
	movzx eax, cx
	movabs rcx, 338209645568
	imul rcx, rax
	movabs rax, 549590673408
	add rax, rcx
	shr rax, 40
	and eax, 1023
	ret
