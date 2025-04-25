# LoongArch syscall ABI:
# a7: syscall number
# a0-a5: arguments
# a0: return value
	.text
	.align	4
	.globl	z_syscall
	.type	z_syscall,@function
z_syscall:
	move	$a7, $a0	# syscall number
	move	$a0, $a1	# arg1
	move	$a1, $a2	# arg2
	move	$a2, $a3	# arg3
	move	$a3, $a4	# arg4
	move	$a4, $a5	# arg5
	move	$a5, $a6	# arg6
	syscall	0
	jr	$ra
	.size	z_syscall, .-z_syscall
