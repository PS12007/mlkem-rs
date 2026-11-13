
mlkem::hazmat::is_zero_mask:
	push rax
	xor eax, eax
	test ecx, ecx
	setne al
	mov dword ptr [rsp + 4], eax
	lea rax, [rsp + 4]
	#APP
	#NO_APP
	mov eax, dword ptr [rsp + 4]
	dec eax
	pop rcx
	ret
