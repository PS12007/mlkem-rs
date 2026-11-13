
mlkem::hazmat::ct_eq_32:
	push rax
	movdqu xmm0, xmmword ptr [rcx]
	movdqu xmm1, xmmword ptr [rcx + 16]
	movdqu xmm2, xmmword ptr [rdx]
	pcmpeqb xmm2, xmm0
	movdqu xmm0, xmmword ptr [rdx + 16]
	pcmpeqb xmm0, xmm1
	pand xmm0, xmm2
	pmovmskb eax, xmm0
	xor ecx, ecx
	xor eax, 65535
	setne cl
	mov dword ptr [rsp + 4], ecx
	lea rax, [rsp + 4]
	#APP
	#NO_APP
	movzx eax, byte ptr [rsp + 4]
	dec al
	pop rcx
	ret
