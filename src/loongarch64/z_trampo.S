	.text
	.align	4
	.globl	z_trampo
	.type	z_trampo,@function
z_trampo:
	move	$sp, $a1	# Set new stack pointer
	jr	$a0		# Jump to target
	break	0		# Should not reach
	.size	z_trampo, .-z_trampo
