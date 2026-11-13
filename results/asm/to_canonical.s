
mlkem::hazmat::to_canonical:
	movsx eax, cx
	shr eax, 15
	and eax, 3329
	add eax, ecx
	ret
