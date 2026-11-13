
mlkem::hazmat::decompress_d1:
	movzx eax, cx
	imul eax, eax, 3329
	inc eax
	shr eax
	ret
