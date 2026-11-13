
mlkem::hazmat::barrett_reduce:
	movsx eax, cx
	imul eax, eax, 20159
	add eax, 33554432
	sar eax, 26
	imul eax, eax, -3329
	add eax, ecx
	ret
