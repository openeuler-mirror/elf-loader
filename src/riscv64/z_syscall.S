# RISC-V syscall ABI:
# a7: syscall number
# a0-a5: arguments
# a0: return value
	.text
	.align	4
	.globl	z_syscall
	.type	z_syscall,@function
z_syscall:
	mv	a7, a0		# syscall number
	mv	a0, a1		# arg1
	mv	a1, a2		# arg2
	mv	a2, a3		# arg3
	mv	a3, a4		# arg4
	mv	a4, a5		# arg5
	mv	a5, a6		# arg6
	ecall
	ret
	.size	z_syscall, .-z_syscall
