
mlkem::hazmat::compress_d5:
	movzx eax, cx
	movabs rcx, 10569051424
	imul rcx, rax
	movabs rax, 549590674048
	add rax, rcx
	shr rax, 40
	and eax, 31
	ret
