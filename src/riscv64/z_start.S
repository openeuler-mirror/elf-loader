	.text
	.align	4
	.globl	z_start
	.hidden	z_start
	.type	z_start,@function
z_start:
	mv	a0, sp		# First argument: stack pointer
	mv	a1, a2		# Second argument: auxv pointer
	call	z_entry
	ebreak		# Should not reach
	.size	z_start, .-z_start
