
mlkem::hazmat::cbd_eta3:
	push r15
	push r14
	push rsi
	push rdi
	push rbx
	sub rsp, 544
	mov rdi, rdx
	mov rsi, rcx
	xor r14d, r14d
	lea rbx, [rsp + 32]
	mov r8d, 512
	mov rcx, rbx
	xor edx, edx
	call memset
.LBB57_1:
	lea rax, [r14 + 3]
	mov rcx, r14
	shr rcx, 3
	mov rdx, rax
	shr rdx, 3
	mov r8d, r14d
	and r8b, 6
	movzx r9d, byte ptr [rdi + rcx]
	mov ecx, r14d
	and ecx, 6
	bt r9d, ecx
	setb cl
	movzx edx, byte ptr [rdi + rdx]
	and eax, 7
	bt edx, eax
	setb al
	lea rdx, [r14 + 4]
	mov r10, rdx
	shr r10, 3
	inc r8b
	movzx r8d, r8b
	bt r9d, r8d
	setb r8b
	movzx r9d, byte ptr [rdi + r10]
	and edx, 6
	bt r9d, edx
	setb dl
	lea r9, [r14 + 2]
	mov r10, r9
	shr r10, 3
	lea r11, [r14 + 5]
	mov r15, r11
	shr r15, 3
	movzx r10d, byte ptr [rdi + r10]
	and r9d, 6
	bt r10d, r9d
	adc r8b, cl
	movzx ecx, r8b
	movzx r8d, byte ptr [rdi + r15]
	and r11d, 7
	bt r8d, r11d
	adc dl, al
	movzx eax, dl
	sub ecx, eax
	mov word ptr [rbx], cx
	add rbx, 2
	add r14, 6
	cmp r14, 1536
	jne .LBB57_1
	lea rdx, [rsp + 32]
	mov r8d, 512
	mov rcx, rsi
	call memcpy
	mov rax, rsi
	add rsp, 544
	pop rbx
	pop rdi
	pop rsi
	pop r14
	pop r15
	ret
