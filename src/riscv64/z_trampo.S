	.text
	.align	4
	.globl	z_trampo
	.type	z_trampo,@function
z_trampo:
	mv	sp, a1		# Set new stack pointer
	jr	a0		# Jump to target
	ebreak		# Should not reach
	.size	z_trampo, .-z_trampo
