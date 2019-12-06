	.text

/* Switch from current_thread to next thread_thread, and make
 * next_thread the current_thread.  Use t0 as a temporary register,
 * which should be caller saved. */

	.globl uthread_switch
uthread_switch:
    ld ra, 0(sp)
    ld a0, 8(sp)
    ret
