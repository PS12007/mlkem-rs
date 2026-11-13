
mlkem::hazmat::compress_d1:
	movzx eax, cx
	imul rcx, rax, 660565714
	movabs rax, 549590674048
	add rax, rcx
	shr rax, 40
	and eax, 1
	ret
