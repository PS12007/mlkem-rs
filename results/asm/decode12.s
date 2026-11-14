
mlkem::hazmat::decode12:
	push rsi
	push rdi
	push rbx
	sub rsp, 608
	movdqa xmmword ptr [rsp + 592], xmm9
	movdqa xmmword ptr [rsp + 576], xmm8
	movaps xmmword ptr [rsp + 560], xmm7
	movaps xmmword ptr [rsp + 544], xmm6
	mov rdi, rdx
	mov rsi, rcx
	xor ebx, ebx
	lea rcx, [rsp + 32]
	mov r8d, 512
	xor edx, edx
	call memset
	xor eax, eax
	xor edx, edx
	xor r8d, r8d
	jmp .LBB61_1
.LBB61_6:
	mov rdx, r9
	mov eax, ecx
.LBB61_2:
	mov ecx, ebx
	and ecx, 4095
	mov word ptr [rsp + r8 + 32], cx
	add r8, 2
	shr ebx, 12
	add eax, -12
	cmp r8, 512
	je .LBB61_3
.LBB61_1:
	cmp eax, 12
	jae .LBB61_2
	cmp rdx, 383
	ja .LBB61_9
	movzx r9d, byte ptr [rdi + rdx]
	mov ecx, eax
	shl r9d, cl
	or ebx, r9d
	lea r9, [rdx + 1]
	lea ecx, [rax + 8]
	cmp eax, 3
	ja .LBB61_6
	cmp r9, 384
	je .LBB61_9
	movzx r9d, byte ptr [rdi + rdx + 1]
	shl r9d, cl
	or ebx, r9d
	add rdx, 2
	or eax, 16
	jmp .LBB61_2
.LBB61_3:
	movdqa xmm0, xmmword ptr [rip + __xmm@f2fff2fff2fff2fff2fff2fff2fff2ff]
	movdqa xmm4, xmmword ptr [rsp + 32]
	movdqa xmm5, xmmword ptr [rsp + 48]
	movdqa xmm3, xmmword ptr [rsp + 64]
	movdqa xmm2, xmmword ptr [rsp + 80]
	movdqa xmm6, xmm4
	paddw xmm6, xmm0
	movdqa xmm7, xmm5
	paddw xmm7, xmm0
	pxor xmm1, xmm1
	pxor xmm8, xmm8
	pcmpgtw xmm8, xmm6
	pxor xmm9, xmm9
	pcmpgtw xmm9, xmm7
	pand xmm4, xmm8
	pandn xmm8, xmm6
	por xmm8, xmm4
	pand xmm5, xmm9
	pandn xmm9, xmm7
	por xmm9, xmm5
	movdqa xmmword ptr [rsp + 32], xmm8
	movdqa xmmword ptr [rsp + 48], xmm9
	movdqa xmm4, xmm3
	paddw xmm4, xmm0
	movdqa xmm5, xmm2
	paddw xmm5, xmm0
	pxor xmm6, xmm6
	pcmpgtw xmm6, xmm4
	pxor xmm7, xmm7
	pcmpgtw xmm7, xmm5
	pand xmm3, xmm6
	pandn xmm6, xmm4
	por xmm6, xmm3
	pand xmm2, xmm7
	pandn xmm7, xmm5
	por xmm7, xmm2
	movdqa xmmword ptr [rsp + 64], xmm6
	movdqa xmmword ptr [rsp + 80], xmm7
	movdqa xmm2, xmmword ptr [rsp + 96]
	movdqa xmm3, xmmword ptr [rsp + 112]
	movdqa xmm4, xmm2
	paddw xmm4, xmm0
	movdqa xmm5, xmm3
	paddw xmm5, xmm0
	pxor xmm6, xmm6
	pcmpgtw xmm6, xmm4
	pxor xmm7, xmm7
	pcmpgtw xmm7, xmm5
	pand xmm2, xmm6
	pandn xmm6, xmm4
	por xmm6, xmm2
	pand xmm3, xmm7
	pandn xmm7, xmm5
	por xmm7, xmm3
	movdqa xmmword ptr [rsp + 96], xmm6
	movdqa xmmword ptr [rsp + 112], xmm7
	movdqa xmm2, xmmword ptr [rsp + 128]
	movdqa xmm3, xmmword ptr [rsp + 144]
	movdqa xmm4, xmm2
	paddw xmm4, xmm0
	movdqa xmm5, xmm3
	paddw xmm5, xmm0
	pxor xmm6, xmm6
	pcmpgtw xmm6, xmm4
	pxor xmm7, xmm7
	pcmpgtw xmm7, xmm5
	pand xmm2, xmm6
	pandn xmm6, xmm4
	por xmm6, xmm2
	pand xmm3, xmm7
	pandn xmm7, xmm5
	por xmm7, xmm3
	movdqa xmmword ptr [rsp + 128], xmm6
	movdqa xmmword ptr [rsp + 144], xmm7
	movdqa xmm2, xmmword ptr [rsp + 160]
	movdqa xmm3, xmmword ptr [rsp + 176]
	movdqa xmm4, xmm2
	paddw xmm4, xmm0
	movdqa xmm5, xmm3
	paddw xmm5, xmm0
	pxor xmm6, xmm6
	pcmpgtw xmm6, xmm4
	pxor xmm7, xmm7
	pcmpgtw xmm7, xmm5
	pand xmm2, xmm6
	pandn xmm6, xmm4
	por xmm6, xmm2
	pand xmm3, xmm7
	pandn xmm7, xmm5
	por xmm7, xmm3
	movdqa xmmword ptr [rsp + 160], xmm6
	movdqa xmmword ptr [rsp + 176], xmm7
	movdqa xmm2, xmmword ptr [rsp + 192]
	movdqa xmm3, xmmword ptr [rsp + 208]
	movdqa xmm4, xmm2
	paddw xmm4, xmm0
	movdqa xmm5, xmm3
	paddw xmm5, xmm0
	pxor xmm6, xmm6
	pcmpgtw xmm6, xmm4
	pxor xmm7, xmm7
	pcmpgtw xmm7, xmm5
	pand xmm2, xmm6
	pandn xmm6, xmm4
	por xmm6, xmm2
	pand xmm3, xmm7
	pandn xmm7, xmm5
	por xmm7, xmm3
	movdqa xmmword ptr [rsp + 192], xmm6
	movdqa xmmword ptr [rsp + 208], xmm7
	movdqa xmm2, xmmword ptr [rsp + 224]
	movdqa xmm3, xmmword ptr [rsp + 240]
	movdqa xmm4, xmm2
	paddw xmm4, xmm0
	movdqa xmm5, xmm3
	paddw xmm5, xmm0
	pxor xmm6, xmm6
	pcmpgtw xmm6, xmm4
	pxor xmm7, xmm7
	pcmpgtw xmm7, xmm5
	pand xmm2, xmm6
	pandn xmm6, xmm4
	por xmm6, xmm2
	pand xmm3, xmm7
	pandn xmm7, xmm5
	por xmm7, xmm3
	movdqa xmmword ptr [rsp + 224], xmm6
	movdqa xmmword ptr [rsp + 240], xmm7
	movdqa xmm2, xmmword ptr [rsp + 256]
	movdqa xmm3, xmmword ptr [rsp + 272]
	movdqa xmm4, xmm2
	paddw xmm4, xmm0
	movdqa xmm5, xmm3
	paddw xmm5, xmm0
	pxor xmm6, xmm6
	pcmpgtw xmm6, xmm4
	pxor xmm7, xmm7
	pcmpgtw xmm7, xmm5
	pand xmm2, xmm6
	pandn xmm6, xmm4
	por xmm6, xmm2
	pand xmm3, xmm7
	pandn xmm7, xmm5
	por xmm7, xmm3
	movdqa xmmword ptr [rsp + 256], xmm6
	movdqa xmmword ptr [rsp + 272], xmm7
	movdqa xmm2, xmmword ptr [rsp + 288]
	movdqa xmm3, xmmword ptr [rsp + 304]
	movdqa xmm4, xmm2
	paddw xmm4, xmm0
	movdqa xmm5, xmm3
	paddw xmm5, xmm0
	pxor xmm6, xmm6
	pcmpgtw xmm6, xmm4
	pxor xmm7, xmm7
	pcmpgtw xmm7, xmm5
	pand xmm2, xmm6
	pandn xmm6, xmm4
	por xmm6, xmm2
	pand xmm3, xmm7
	pandn xmm7, xmm5
	por xmm7, xmm3
	movdqa xmmword ptr [rsp + 288], xmm6
	movdqa xmmword ptr [rsp + 304], xmm7
	movdqa xmm2, xmmword ptr [rsp + 320]
	movdqa xmm3, xmmword ptr [rsp + 336]
	movdqa xmm4, xmm2
	paddw xmm4, xmm0
	movdqa xmm5, xmm3
	paddw xmm5, xmm0
	pxor xmm6, xmm6
	pcmpgtw xmm6, xmm4
	pxor xmm7, xmm7
	pcmpgtw xmm7, xmm5
	pand xmm2, xmm6
	pandn xmm6, xmm4
	por xmm6, xmm2
	pand xmm3, xmm7
	pandn xmm7, xmm5
	por xmm7, xmm3
	movdqa xmmword ptr [rsp + 320], xmm6
	movdqa xmmword ptr [rsp + 336], xmm7
	movdqa xmm2, xmmword ptr [rsp + 352]
	movdqa xmm3, xmmword ptr [rsp + 368]
	movdqa xmm4, xmm2
	paddw xmm4, xmm0
	movdqa xmm5, xmm3
	paddw xmm5, xmm0
	pxor xmm6, xmm6
	pcmpgtw xmm6, xmm4
	pxor xmm7, xmm7
	pcmpgtw xmm7, xmm5
	pand xmm2, xmm6
	pandn xmm6, xmm4
	por xmm6, xmm2
	pand xmm3, xmm7
	pandn xmm7, xmm5
	por xmm7, xmm3
	movdqa xmmword ptr [rsp + 352], xmm6
	movdqa xmmword ptr [rsp + 368], xmm7
	movdqa xmm2, xmmword ptr [rsp + 384]
	movdqa xmm3, xmmword ptr [rsp + 400]
	movdqa xmm4, xmm2
	paddw xmm4, xmm0
	movdqa xmm5, xmm3
	paddw xmm5, xmm0
	pxor xmm6, xmm6
	pcmpgtw xmm6, xmm4
	pxor xmm7, xmm7
	pcmpgtw xmm7, xmm5
	pand xmm2, xmm6
	pandn xmm6, xmm4
	por xmm6, xmm2
	pand xmm3, xmm7
	pandn xmm7, xmm5
	por xmm7, xmm3
	movdqa xmmword ptr [rsp + 384], xmm6
	movdqa xmmword ptr [rsp + 400], xmm7
	movdqa xmm2, xmmword ptr [rsp + 416]
	movdqa xmm3, xmmword ptr [rsp + 432]
	movdqa xmm4, xmm2
	paddw xmm4, xmm0
	movdqa xmm5, xmm3
	paddw xmm5, xmm0
	pxor xmm6, xmm6
	pcmpgtw xmm6, xmm4
	pxor xmm7, xmm7
	pcmpgtw xmm7, xmm5
	pand xmm2, xmm6
	pandn xmm6, xmm4
	por xmm6, xmm2
	pand xmm3, xmm7
	pandn xmm7, xmm5
	por xmm7, xmm3
	movdqa xmmword ptr [rsp + 416], xmm6
	movdqa xmmword ptr [rsp + 432], xmm7
	movdqa xmm2, xmmword ptr [rsp + 448]
	movdqa xmm3, xmmword ptr [rsp + 464]
	movdqa xmm4, xmm2
	paddw xmm4, xmm0
	movdqa xmm5, xmm3
	paddw xmm5, xmm0
	pxor xmm6, xmm6
	pcmpgtw xmm6, xmm4
	pxor xmm7, xmm7
	pcmpgtw xmm7, xmm5
	pand xmm2, xmm6
	pandn xmm6, xmm4
	por xmm6, xmm2
	pand xmm3, xmm7
	pandn xmm7, xmm5
	por xmm7, xmm3
	movdqa xmmword ptr [rsp + 448], xmm6
	movdqa xmmword ptr [rsp + 464], xmm7
	movdqa xmm2, xmmword ptr [rsp + 480]
	movdqa xmm3, xmmword ptr [rsp + 496]
	movdqa xmm4, xmm2
	paddw xmm4, xmm0
	movdqa xmm5, xmm3
	paddw xmm5, xmm0
	pxor xmm6, xmm6
	pcmpgtw xmm6, xmm4
	pxor xmm7, xmm7
	pcmpgtw xmm7, xmm5
	pand xmm2, xmm6
	pandn xmm6, xmm4
	por xmm6, xmm2
	pand xmm3, xmm7
	pandn xmm7, xmm5
	por xmm7, xmm3
	movdqa xmmword ptr [rsp + 480], xmm6
	movdqa xmmword ptr [rsp + 496], xmm7
	movdqa xmm2, xmmword ptr [rsp + 512]
	movdqa xmm3, xmmword ptr [rsp + 528]
	movdqa xmm4, xmm2
	paddw xmm4, xmm0
	paddw xmm0, xmm3
	pxor xmm5, xmm5
	pcmpgtw xmm5, xmm4
	pcmpgtw xmm1, xmm0
	pand xmm2, xmm5
	pandn xmm5, xmm4
	por xmm5, xmm2
	pand xmm3, xmm1
	pandn xmm1, xmm0
	por xmm1, xmm3
	movdqa xmmword ptr [rsp + 512], xmm5
	movdqa xmmword ptr [rsp + 528], xmm1
	lea rdx, [rsp + 32]
	mov r8d, 512
	mov rcx, rsi
	call memcpy
	mov rax, rsi
	movaps xmm6, xmmword ptr [rsp + 544]
	movaps xmm7, xmmword ptr [rsp + 560]
	movaps xmm8, xmmword ptr [rsp + 576]
	movaps xmm9, xmmword ptr [rsp + 592]
	add rsp, 608
	pop rbx
	pop rdi
	pop rsi
	ret
.LBB61_9:
	cmp rdx, 385
	mov ecx, 384
	cmovae rcx, rdx
	lea r8, [rip + anon.bcdc364150e6b6d4e7eb0dd3f005f22e.52]
	mov edx, 384
	call core::panicking::panic_bounds_check
	ud2
