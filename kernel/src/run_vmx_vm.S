// extern fn run_vm_vmx() -> u64;
.global run_vm_vmx
run_vm_vmx:
    pushfq  // to preserve the current rflags register
    push rbp
    push rcx
    push rdx
    push rsi
    push rdi
    push rax
    // use r14 and r15 as scratch register
    push r14
    push r15

    // Assume this is the first VM launch
    // Set the host RSP/RIP -- Why??
    mov r14, 0x6C14;  // VMCS_HOST_RSP
    vmwrite r14, rsp
    lea r15, [rip + .VMExit]  // set the address to go when vm-exit occurs
    mov r14, 0x6C16;  // VMCS_HOST_RIP
    vmwrite r14, r15

    // vm launch
    vmlaunch    // comment out for test --> this instruction immediately causes a kernel crash, maybe it has to do with nested virt??
                // look at nested-vm-launch codes to get to know how to write vmlaunch asm codes for nested vm..

.VMFailure:
    // VMLAUNCH failed. If it were successful, VM-exit should have led to VMExit
    jmp .Exit

.VMExit:
    // vm-exit occured.

.Exit:
    // Adjust the stack pointer --> why is it needed?
    //pop rax  // comment out for test  --> Is this necessary??

    // Restore host registers
    pop r15
    pop r14
    pop rax
    pop rdi
    pop rsi
    pop rdx
    pop rcx
    pop rbp

    pushfq  // save the rflags value of the vmexit
    pop rax // return the rflags value of the vmexit

    popfq  // restore the original rflags value
    ret