
mlkem::hazmat::ct_select_32:
	jmp mlkem::ct::ct_select_bytes

======================= Additional context =========================

mlkem::ct::ct_select_bytes:
	push rax
	mov byte ptr [rsp + 7], r9b
	lea rax, [rsp + 7]
	#APP
	#NO_APP
	movdqu xmm0, xmmword ptr [rdx]
	movdqu xmm1, xmmword ptr [r8]
	movzx eax, byte ptr [rsp + 7]
	movd xmm2, eax
	punpcklbw xmm2, xmm2
	pshuflw xmm2, xmm2, 0
	pshufd xmm2, xmm2, 68
	movdqa xmm3, xmm2
	pandn xmm3, xmm1
	pand xmm0, xmm2
	por xmm0, xmm3
	movdqu xmmword ptr [rcx], xmm0
	movdqu xmm0, xmmword ptr [rdx + 16]
	movdqu xmm1, xmmword ptr [r8 + 16]
	pand xmm0, xmm2
	pandn xmm2, xmm1
	por xmm2, xmm0
	movdqu xmmword ptr [rcx + 16], xmm2
	pop rax
	ret
