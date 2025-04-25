	.text
	.align	4
	.globl	z_start
	.hidden	z_start
	.type	z_start,@function
z_start:
	move	$a0, $sp	# First argument: stack pointer
	move	$a1, $a2	# Second argument: auxv pointer
	bl	z_entry
	break	0		# Should not reach
	.size	z_start, .-z_start
