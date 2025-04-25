# RISC-V specific implementation of memcpy
# This is needed because the C version might not be properly handled with -nostdlib

	.text
	.align	4
	.globl	memcpy
	.type	memcpy,@function
memcpy:
	mv	t0, a0		# Save dest pointer
1:
	beqz	a2, 2f		# If n == 0, return
	lb	t1, 0(a1)	# Load byte from src
	sb	t1, 0(a0)	# Store byte to dest
	addi	a0, a0, 1	# Increment dest pointer
	addi	a1, a1, 1	# Increment src pointer
	addi	a2, a2, -1	# Decrement counter
	j	1b		# Loop
2:
	mv	a0, t0		# Return original dest pointer
	ret
	.size	memcpy, .-memcpy
