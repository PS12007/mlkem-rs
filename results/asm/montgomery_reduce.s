
mlkem::hazmat::montgomery_reduce:
	imul eax, ecx, -218038272
	sar eax, 16
	imul eax, eax, -3329
	add eax, ecx
	shr eax, 16
	ret
