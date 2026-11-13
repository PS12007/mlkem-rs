
mlkem::hazmat::cbd_eta2:
	push rsi
	push rdi
	push rbx
	sub rsp, 544
	mov rdi, rdx
	mov rsi, rcx
	xor ebx, ebx
	lea rcx, [rsp + 32]
	mov r8d, 512
	xor edx, edx
	call memset
	xor eax, eax
.LBB56_1:
	mov rcx, rax
	shr rcx
	mov edx, ebx
	and dl, 4
	movzx edx, dl
	movzx ecx, byte ptr [rdi + rcx]
	bt ecx, edx
	setb r8b
	lea r9d, [rdx + 2]
	movzx r9d, r9b
	bt ecx, r9d
	setb r9b
	lea r10d, [rdx + 1]
	movzx r10d, r10b
	bt ecx, r10d
	adc r8b, 0
	or dl, 3
	movzx edx, dl
	bt ecx, edx
	adc r9b, 0
	movzx ecx, r8b
	movzx edx, r9b
	sub ecx, edx
	mov word ptr [rsp + 2*rax + 32], cx
	inc rax
	add bl, 4
	cmp rax, 256
	jne .LBB56_1
	lea rdx, [rsp + 32]
	mov r8d, 512
	mov rcx, rsi
	call memcpy
	mov rax, rsi
	add rsp, 544
	pop rbx
	pop rdi
	pop rsi
	ret
