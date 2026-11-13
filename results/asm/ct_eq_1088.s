
mlkem::hazmat::ct_eq_1088:
	sub rsp, 40
	movdqa xmmword ptr [rsp + 16], xmm6
	pxor xmm0, xmm0
	mov eax, 48
	pxor xmm1, xmm1
.LBB36_1:
	movdqu xmm2, xmmword ptr [rcx + rax - 48]
	movdqu xmm3, xmmword ptr [rcx + rax - 32]
	movdqu xmm4, xmmword ptr [rcx + rax - 16]
	movdqu xmm5, xmmword ptr [rcx + rax]
	movdqu xmm6, xmmword ptr [rdx + rax - 48]
	pxor xmm6, xmm2
	movdqa xmm2, xmm0
	por xmm2, xmm6
	movdqu xmm0, xmmword ptr [rdx + rax - 32]
	pxor xmm0, xmm3
	movdqa xmm3, xmm1
	por xmm3, xmm0
	movdqu xmm0, xmmword ptr [rdx + rax - 16]
	pxor xmm0, xmm4
	por xmm0, xmm2
	movdqu xmm1, xmmword ptr [rdx + rax]
	pxor xmm1, xmm5
	por xmm1, xmm3
	add rax, 64
	cmp rax, 1136
	jne .LBB36_1
	por xmm1, xmm0
	pxor xmm0, xmm0
	pcmpeqb xmm0, xmm1
	pmovmskb eax, xmm0
	xor ecx, ecx
	xor eax, 65535
	setne cl
	mov dword ptr [rsp + 12], ecx
	lea rax, [rsp + 12]
	#APP
	#NO_APP
	movzx eax, byte ptr [rsp + 12]
	dec al
	movaps xmm6, xmmword ptr [rsp + 16]
	add rsp, 40
	ret
