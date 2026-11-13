
mlkem::hazmat::message_encode:
	push rsi
	sub rsp, 64
	mov rsi, rcx
	xorps xmm0, xmm0
	movaps xmmword ptr [rsp + 48], xmm0
	movaps xmmword ptr [rsp + 32], xmm0
	lea r8, [rsp + 32]
	mov r9d, 32
	mov rcx, rdx
	mov edx, 1
	call mlkem::encode::poly_compress_encode
	movaps xmm0, xmmword ptr [rsp + 32]
	movaps xmm1, xmmword ptr [rsp + 48]
	movups xmmword ptr [rsi + 16], xmm1
	movups xmmword ptr [rsi], xmm0
	mov rax, rsi
	add rsp, 64
	pop rsi
	ret

======================= Additional context =========================

mlkem::encode::poly_compress_encode:
	push rsi
	push rdi
	push rbp
	push rbx
	sub rsp, 1160
	movaps xmmword ptr [rsp + 1136], xmm11
	movdqa xmmword ptr [rsp + 1120], xmm10
	movdqa xmmword ptr [rsp + 1104], xmm9
	movaps xmmword ptr [rsp + 1088], xmm8
	movdqa xmmword ptr [rsp + 1072], xmm7
	movdqa xmmword ptr [rsp + 1056], xmm6
	movdqu xmm1, xmmword ptr [rcx]
	movdqu xmm2, xmmword ptr [rcx + 16]
	movdqa xmm3, xmm1
	psraw xmm3, 15
	movdqa xmm0, xmmword ptr [rip + __xmm@0d010d010d010d010d010d010d010d01]
	pand xmm3, xmm0
	movdqa xmm4, xmm2
	psraw xmm4, 15
	pand xmm4, xmm0
	paddw xmm3, xmm1
	paddw xmm4, xmm2
	movdqa xmmword ptr [rsp + 32], xmm3
	movdqa xmmword ptr [rsp + 48], xmm4
	movdqu xmm1, xmmword ptr [rcx + 32]
	movdqu xmm2, xmmword ptr [rcx + 48]
	movdqa xmm3, xmm1
	psraw xmm3, 15
	pand xmm3, xmm0
	movdqa xmm4, xmm2
	psraw xmm4, 15
	pand xmm4, xmm0
	paddw xmm3, xmm1
	paddw xmm4, xmm2
	movdqa xmmword ptr [rsp + 64], xmm3
	movdqa xmmword ptr [rsp + 80], xmm4
	movdqu xmm1, xmmword ptr [rcx + 64]
	movdqu xmm2, xmmword ptr [rcx + 80]
	movdqa xmm3, xmm1
	psraw xmm3, 15
	pand xmm3, xmm0
	movdqa xmm4, xmm2
	psraw xmm4, 15
	pand xmm4, xmm0
	paddw xmm3, xmm1
	paddw xmm4, xmm2
	movdqa xmmword ptr [rsp + 96], xmm3
	movdqa xmmword ptr [rsp + 112], xmm4
	movdqu xmm1, xmmword ptr [rcx + 96]
	movdqu xmm2, xmmword ptr [rcx + 112]
	movdqa xmm3, xmm1
	psraw xmm3, 15
	pand xmm3, xmm0
	movdqa xmm4, xmm2
	psraw xmm4, 15
	pand xmm4, xmm0
	paddw xmm3, xmm1
	paddw xmm4, xmm2
	movdqa xmmword ptr [rsp + 128], xmm3
	movdqa xmmword ptr [rsp + 144], xmm4
	movdqu xmm1, xmmword ptr [rcx + 128]
	movdqu xmm2, xmmword ptr [rcx + 144]
	movdqa xmm3, xmm1
	psraw xmm3, 15
	pand xmm3, xmm0
	movdqa xmm4, xmm2
	psraw xmm4, 15
	pand xmm4, xmm0
	paddw xmm3, xmm1
	paddw xmm4, xmm2
	movdqa xmmword ptr [rsp + 160], xmm3
	movdqa xmmword ptr [rsp + 176], xmm4
	movdqu xmm1, xmmword ptr [rcx + 160]
	movdqu xmm2, xmmword ptr [rcx + 176]
	movdqa xmm3, xmm1
	psraw xmm3, 15
	pand xmm3, xmm0
	movdqa xmm4, xmm2
	psraw xmm4, 15
	pand xmm4, xmm0
	paddw xmm3, xmm1
	paddw xmm4, xmm2
	movdqa xmmword ptr [rsp + 192], xmm3
	movdqa xmmword ptr [rsp + 208], xmm4
	movdqu xmm1, xmmword ptr [rcx + 192]
	movdqu xmm2, xmmword ptr [rcx + 208]
	movdqa xmm3, xmm1
	psraw xmm3, 15
	pand xmm3, xmm0
	movdqa xmm4, xmm2
	psraw xmm4, 15
	pand xmm4, xmm0
	paddw xmm3, xmm1
	paddw xmm4, xmm2
	movdqa xmmword ptr [rsp + 224], xmm3
	movdqa xmmword ptr [rsp + 240], xmm4
	movdqu xmm1, xmmword ptr [rcx + 224]
	movdqu xmm2, xmmword ptr [rcx + 240]
	movdqa xmm3, xmm1
	psraw xmm3, 15
	pand xmm3, xmm0
	movdqa xmm4, xmm2
	psraw xmm4, 15
	pand xmm4, xmm0
	paddw xmm3, xmm1
	paddw xmm4, xmm2
	movdqa xmmword ptr [rsp + 256], xmm3
	movdqa xmmword ptr [rsp + 272], xmm4
	movdqu xmm1, xmmword ptr [rcx + 256]
	movdqu xmm2, xmmword ptr [rcx + 272]
	movdqa xmm3, xmm1
	psraw xmm3, 15
	pand xmm3, xmm0
	movdqa xmm4, xmm2
	psraw xmm4, 15
	pand xmm4, xmm0
	paddw xmm3, xmm1
	paddw xmm4, xmm2
	movdqa xmmword ptr [rsp + 288], xmm3
	movdqa xmmword ptr [rsp + 304], xmm4
	movdqu xmm1, xmmword ptr [rcx + 288]
	movdqu xmm2, xmmword ptr [rcx + 304]
	movdqa xmm3, xmm1
	psraw xmm3, 15
	pand xmm3, xmm0
	movdqa xmm4, xmm2
	psraw xmm4, 15
	pand xmm4, xmm0
	paddw xmm3, xmm1
	paddw xmm4, xmm2
	movdqa xmmword ptr [rsp + 320], xmm3
	movdqa xmmword ptr [rsp + 336], xmm4
	movdqu xmm1, xmmword ptr [rcx + 320]
	movdqu xmm2, xmmword ptr [rcx + 336]
	movdqa xmm3, xmm1
	psraw xmm3, 15
	pand xmm3, xmm0
	movdqa xmm4, xmm2
	psraw xmm4, 15
	pand xmm4, xmm0
	paddw xmm3, xmm1
	paddw xmm4, xmm2
	movdqa xmmword ptr [rsp + 352], xmm3
	movdqa xmmword ptr [rsp + 368], xmm4
	movdqu xmm1, xmmword ptr [rcx + 352]
	movdqu xmm2, xmmword ptr [rcx + 368]
	movdqa xmm3, xmm1
	psraw xmm3, 15
	pand xmm3, xmm0
	movdqa xmm4, xmm2
	psraw xmm4, 15
	pand xmm4, xmm0
	paddw xmm3, xmm1
	paddw xmm4, xmm2
	movdqa xmmword ptr [rsp + 384], xmm3
	movdqa xmmword ptr [rsp + 400], xmm4
	movdqu xmm1, xmmword ptr [rcx + 384]
	movdqu xmm2, xmmword ptr [rcx + 400]
	movdqa xmm3, xmm1
	psraw xmm3, 15
	pand xmm3, xmm0
	movdqa xmm4, xmm2
	psraw xmm4, 15
	pand xmm4, xmm0
	paddw xmm3, xmm1
	paddw xmm4, xmm2
	movdqa xmmword ptr [rsp + 416], xmm3
	movdqa xmmword ptr [rsp + 432], xmm4
	movdqu xmm1, xmmword ptr [rcx + 416]
	movdqu xmm2, xmmword ptr [rcx + 432]
	movdqa xmm3, xmm1
	psraw xmm3, 15
	pand xmm3, xmm0
	movdqa xmm4, xmm2
	psraw xmm4, 15
	pand xmm4, xmm0
	paddw xmm3, xmm1
	paddw xmm4, xmm2
	movdqa xmmword ptr [rsp + 448], xmm3
	movdqa xmmword ptr [rsp + 464], xmm4
	movdqu xmm1, xmmword ptr [rcx + 448]
	movdqu xmm2, xmmword ptr [rcx + 464]
	movdqa xmm3, xmm1
	psraw xmm3, 15
	pand xmm3, xmm0
	movdqa xmm4, xmm2
	psraw xmm4, 15
	pand xmm4, xmm0
	paddw xmm3, xmm1
	paddw xmm4, xmm2
	movdqa xmmword ptr [rsp + 480], xmm3
	movdqa xmmword ptr [rsp + 496], xmm4
	movdqu xmm1, xmmword ptr [rcx + 480]
	movdqu xmm2, xmmword ptr [rcx + 496]
	movdqa xmm3, xmm1
	psraw xmm3, 15
	pand xmm3, xmm0
	movdqa xmm4, xmm2
	psraw xmm4, 15
	pand xmm4, xmm0
	paddw xmm3, xmm1
	paddw xmm4, xmm2
	movdqa xmmword ptr [rsp + 512], xmm3
	mov ecx, edx
	and cl, 15
	mov eax, -1
	shl eax, cl
	movdqa xmmword ptr [rsp + 528], xmm4
	mov ecx, edx
	and ecx, 63
	movd xmm0, ecx
	xor ecx, ecx
	pxor xmm1, xmm1
	movdqa xmm2, xmmword ptr [rip + __xmm@0000000013afb7690000000013afb769]
	movdqa xmm3, xmmword ptr [rip + __xmm@0000007ff6282a800000007ff6282a80]
.LBB34_1:
	movdqa xmm7, xmmword ptr [rsp + 2*rcx + 32]
	movdqa xmm6, xmm7
	punpcklwd xmm6, xmm1
	movdqa xmm5, xmm6
	punpckhdq xmm5, xmm1
	punpckldq xmm6, xmm1
	punpckhwd xmm7, xmm1
	movdqa xmm9, xmm7
	punpckhdq xmm9, xmm1
	punpckldq xmm7, xmm1
	psllq xmm7, xmm0
	psllq xmm9, xmm0
	psllq xmm6, xmm0
	psllq xmm5, xmm0
	movdqa xmm8, xmm5
	pmuludq xmm8, xmm2
	psrlq xmm5, 32
	pmuludq xmm5, xmm2
	psllq xmm5, 32
	movdqa xmm4, xmm6
	pmuludq xmm4, xmm2
	psrlq xmm6, 32
	pmuludq xmm6, xmm2
	psllq xmm6, 32
	movdqa xmm11, xmm9
	pmuludq xmm11, xmm2
	psrlq xmm9, 32
	pmuludq xmm9, xmm2
	psllq xmm9, 32
	movdqa xmm10, xmm7
	pmuludq xmm10, xmm2
	psrlq xmm7, 32
	pmuludq xmm7, xmm2
	psllq xmm7, 32
	paddq xmm10, xmm3
	paddq xmm10, xmm7
	paddq xmm11, xmm3
	paddq xmm11, xmm9
	paddq xmm4, xmm3
	paddq xmm4, xmm6
	paddq xmm8, xmm3
	paddq xmm8, xmm5
	psrlq xmm8, 40
	psrlq xmm4, 40
	shufps xmm4, xmm8, 136
	psrlq xmm11, 40
	psrlq xmm10, 40
	shufps xmm10, xmm11, 136
	pslld xmm10, 16
	psrad xmm10, 16
	pslld xmm4, 16
	psrad xmm4, 16
	packssdw xmm4, xmm10
	movd xmm5, eax
	pshuflw xmm5, xmm5, 0
	pshufd xmm5, xmm5, 68
	pandn xmm5, xmm4
	movdqu xmmword ptr [rsp + 2*rcx + 544], xmm5
	add rcx, 8
	cmp rcx, 256
	jne .LBB34_1
	lea ecx, [rdx - 1]
	mov eax, edx
	shl rax, 5
	cmp r9, rax
	sete al
	cmp ecx, 12
	jae .LBB34_3
	test al, al
	je .LBB34_13
.LBB34_5:
	mov r10d, -1
	mov ecx, edx
	shl r10d, cl
	not r10d
	lea r11d, [rdx - 8]
	xor esi, esi
	xor ecx, ecx
	xor edi, edi
	xor ebx, ebx
	jmp .LBB34_7
.LBB34_6:
	add rbx, 2
	mov ecx, ebp
	cmp rbx, 512
	je .LBB34_12
.LBB34_7:
	mov eax, esi
	movzx esi, word ptr [rsp + rbx + 544]
	and esi, r10d
	shl esi, cl
	or esi, eax
	lea ebp, [rcx + rdx]
	cmp ebp, 8
	jb .LBB34_6
	cmp rdi, r9
	mov rax, r9
	cmova rax, rdi
	add ecx, r11d
	shr ecx, 3
	inc ecx
.LBB34_9:
	cmp rax, rdi
	je .LBB34_11
	mov byte ptr [r8 + rdi], sil
	inc rdi
	shr esi, 8
	add ebp, -8
	dec ecx
	jne .LBB34_9
	jmp .LBB34_6
.LBB34_12:
	movaps xmm6, xmmword ptr [rsp + 1056]
	movaps xmm7, xmmword ptr [rsp + 1072]
	movaps xmm8, xmmword ptr [rsp + 1088]
	movaps xmm9, xmmword ptr [rsp + 1104]
	movaps xmm10, xmmword ptr [rsp + 1120]
	movaps xmm11, xmmword ptr [rsp + 1136]
	add rsp, 1160
	pop rbx
	pop rbp
	pop rdi
	pop rsi
	ret
.LBB34_3:
	xor eax, eax
	test al, al
	jne .LBB34_5
.LBB34_13:
	lea rcx, [rip + anon.cc8941bcbf02e25ec4f0f024fc8c8e42.51]
	lea r8, [rip + anon.cc8941bcbf02e25ec4f0f024fc8c8e42.52]
	mov edx, 71
	call core::panicking::panic
	ud2
.LBB34_11:
	lea r8, [rip + anon.cc8941bcbf02e25ec4f0f024fc8c8e42.53]
	mov rcx, rax
	mov rdx, r9
	call core::panicking::panic_bounds_check
	ud2
