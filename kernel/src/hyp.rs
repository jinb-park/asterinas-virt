use x86::msr::{self, rdmsr, wrmsr};
use x86;
use crate::vmcs;
use core::arch::asm;
use x86::controlregs::{Cr0, Cr4};
use x86::dtables::DescriptorTablePointer;
use x86::segmentation::SegmentSelector;
use x86::current::rflags::RFlags;
use core::arch::global_asm;

unsafe extern {
    /// Runs the guest until VM-exit occurs.
    unsafe fn run_vm_vmx() -> u64;
}
global_asm!(include_str!("run_vmx_vm.S"));

// for VMCS control field
/// The types of the control field.
#[derive(Clone, Copy)]
enum VmxControl {
    PinBased,
    ProcessorBased,
    ProcessorBased2,
    VmExit,
    VmEntry,
}

// global variables for loading and running a VM through VMX
#[repr(C, align(4096))]
struct VmxonRegion {
    revision_id: u32,
    _data: [u8; 4096 - 4],
}
#[repr(C, align(4096))]
struct VmcsRegion {
    revision_id: u32,
    abort_indicator: u32,
    _data: [u8; 4088],
}
static mut VMXON_REGION: VmxonRegion = VmxonRegion {
    revision_id: 0,
    _data: [0; 4096 - 4],
};
static mut VMCS_REGION: VmcsRegion = VmcsRegion {
    revision_id: 0,
    abort_indicator: 0,
    _data: [0; 4088],
};

// Guest code and stack
static mut GUEST_STACK: [u8; 4096] = [0; 4096];
fn guest_code() {
    unsafe {
        asm!("cpuid");
    }
}

fn get_cpl() -> u16 {
    unsafe {
        let cs: u16;
        asm!("mov {0:x}, cs", out(reg) cs);
        cs & 0x3 // Extract the lowest 2 bits
    }
}

/// Updates the CR0 to satisfy the requirement for entering VMX
/// operation.
fn adjust_cr0() {
    // In order to enter VMX operation, some bits in CR0 (and CR4) have to be
    // set or cleared as indicated by the FIXED0 and FIXED1 MSRs. The rule is
    // summarized as below (taking CR0 as an example):
    //
    //        IA32_VMX_CR0_FIXED0 IA32_VMX_CR0_FIXED1 Meaning
    // Bit X  1                   (Always 1)          The bit X of CR0 is fixed to 1
    // Bit X  0                   1                   The bit X of CR0 is flexible
    // Bit X  (Always 0)          0                   The bit X of CR0 is fixed to 0
    //
    // Some UEFI implementations do not fullfil those requirements for CR0 and
    // need adjustments. The requirements for CR4 are always satisfied as far
    // as the author has experimented (although not guaranteed).
    //
    // See: A.7 VMX-FIXED BITS IN CR0
    // See: A.8 VMX-FIXED BITS IN CR4
    unsafe {
        let fixed0cr0 = rdmsr(msr::IA32_VMX_CR0_FIXED0);
        let fixed1cr0 = rdmsr(msr::IA32_VMX_CR0_FIXED1);
        let mut new_cr0 = x86::controlregs::cr0().bits() as u64;
        new_cr0 &= fixed1cr0;
        new_cr0 |= fixed0cr0;
        let new_cr0 = x86::controlregs::Cr0::from_bits_truncate(new_cr0 as usize);
        x86::controlregs::cr0_write(new_cr0);
    }
}

/// Updates the `IA32_FEATURE_CONTROL` MSR to satisfy the requirement for
/// entering VMX operation.
fn adjust_feature_control_msr() {
    const IA32_FEATURE_CONTROL_LOCK_BIT_FLAG: u64 = 1 << 0;
    const IA32_FEATURE_CONTROL_ENABLE_VMX_OUTSIDE_SMX_FLAG: u64 = 1 << 2;

    // If the lock bit is cleared, set it along with the VMXON-outside-SMX
    // operation bit. Without those two bits, the VMXON instruction fails. They
    // are normally set but not always, for example, Bochs with OVFM does not.
    // See: 23.7 ENABLING AND ENTERING VMX OPERATION
    unsafe {
        let feature_control = rdmsr(msr::IA32_FEATURE_CONTROL);
        if (feature_control & IA32_FEATURE_CONTROL_LOCK_BIT_FLAG) == 0 {
            wrmsr(
                msr::IA32_FEATURE_CONTROL,
                feature_control
                    | IA32_FEATURE_CONTROL_ENABLE_VMX_OUTSIDE_SMX_FLAG
                    | IA32_FEATURE_CONTROL_LOCK_BIT_FLAG,
            );
        }
    }
}

fn cr4_vmx_enable() {
    unsafe {
        let mut cr4 = x86_64::registers::control::Cr4::read();
        cr4.set(x86_64::registers::control::Cr4Flags::VIRTUAL_MACHINE_EXTENSIONS, true);
        x86_64::registers::control::Cr4::write(cr4);
    }
}

fn invoke_vmxon() {
    // reference: conditions to be met for it to succeed
    // https://www.felixcloutier.com/x86/vmxon
    //
    // VmFailInvalid
    // -- (1) addr is not 4KB-aligned or addr sets any bit beyond phy-addr width
    //    -- If IA32_VMX_BASIC[48] is read as 1, VMfailInvalid occurs if addr sets any bits in the range 63:32; see Appendix A.1.
    // -- (2) rev[30:0] ≠ VMCS revision identifier supported by processor OR rev[31] = 1
    //    -- maybe, this is the reason.. have to figure out why it happens..
    //
    // How to debug?
    // -- vmxon is emulated by L0 hypervisor (host)
    // -- "static int handle_vmxon(struct kvm_vcpu *vcpu" --> it seems that this function handles vmxon of L1 hyp.
    // -- ftrace or kprobe this function~! --> vmxon handle is invoked!! 
    // -- can't see return value in ftrace.. use kretprobe instead~!
    // -- [JB] handle_vmxon returned 1 --> debug here~!
    // -- ...
    unsafe {
        let revision_id = rdmsr(msr::IA32_VMX_BASIC) as u64;
        let mut vmxon_phys: usize = &VMXON_REGION as *const _ as usize - 0xffff_ffff_8000_0000; // kernel code base addr;
        VMXON_REGION.revision_id = revision_id as u32;

        ostd::early_println!("VMXON_REGION addr: {:X}, revid: {:#X}", vmxon_phys, VMXON_REGION.revision_id);
        x86::bits64::vmx::vmxon(vmxon_phys as u64).unwrap();
    }
}

/// The wrapper of the VMREAD instruction. Returns zero on error.
fn vmread(field: u32) -> u64 {
    // Safety: this project runs at CPL0.
    unsafe { x86::bits64::vmx::vmread(field) }.unwrap_or(0)
}

fn vmwrite<T: Into<u64>>(field: u32, val: T)
where
    u64: From<T>,
{
    // Safety: this project runs at CPL0.
    unsafe { x86::bits64::vmx::vmwrite(field, u64::from(val)) }.unwrap();
}

/// Returns an adjust value for the control field according to the capability
/// MSR.
fn adjust_vmx_control(control: VmxControl, requested_value: u64) -> u64 {
    const IA32_VMX_BASIC_VMX_CONTROLS_FLAG: u64 = 1 << 55;

    // This determines the right VMX capability MSR based on the value of
    // IA32_VMX_BASIC. This is required to fullfil the following requirements:
    //
    // "It is necessary for software to consult only one of the capability MSRs
    //  to determine the allowed settings of the pin based VM-execution controls:"
    // See: A.3.1 Pin-Based VM-Execution Controls
    let vmx_basic = unsafe { rdmsr(x86::msr::IA32_VMX_BASIC) };
    let true_cap_msr_supported = (vmx_basic & IA32_VMX_BASIC_VMX_CONTROLS_FLAG) != 0;

    let cap_msr = match (control, true_cap_msr_supported) {
        (VmxControl::PinBased, true) => x86::msr::IA32_VMX_TRUE_PINBASED_CTLS,
        (VmxControl::PinBased, false) => x86::msr::IA32_VMX_PINBASED_CTLS,
        (VmxControl::ProcessorBased, true) => x86::msr::IA32_VMX_TRUE_PROCBASED_CTLS,
        (VmxControl::ProcessorBased, false) => x86::msr::IA32_VMX_PROCBASED_CTLS,
        (VmxControl::VmExit, true) => x86::msr::IA32_VMX_TRUE_EXIT_CTLS,
        (VmxControl::VmExit, false) => x86::msr::IA32_VMX_EXIT_CTLS,
        (VmxControl::VmEntry, true) => x86::msr::IA32_VMX_TRUE_ENTRY_CTLS,
        (VmxControl::VmEntry, false) => x86::msr::IA32_VMX_ENTRY_CTLS,
        // There is no TRUE MSR for IA32_VMX_PROCBASED_CTLS2. Just use
        // IA32_VMX_PROCBASED_CTLS2 unconditionally.
        (VmxControl::ProcessorBased2, _) => x86::msr::IA32_VMX_PROCBASED_CTLS2,
    };

    // Each bit of the following VMCS values might have to be set or cleared
    // according to the value indicated by the VMX capability MSRs.
    //  - pin-based VM-execution controls,
    //  - primary processor-based VM-execution controls,
    //  - secondary processor-based VM-execution controls.
    //
    // The VMX capability MSR is composed of two 32bit values, the lower 32bits
    // indicate bits can be 0, and the higher 32bits indicates bits can be 1.
    // In other words, if those bits are "cleared", corresponding bits MUST BE 1
    // and MUST BE 0 respectively. The below summarizes the interpretation:
    //
    //        Lower bits (allowed 0) Higher bits (allowed 1) Meaning
    // Bit X  1                      1                       The bit X is flexible
    // Bit X  1                      0                       The bit X is fixed to 0
    // Bit X  0                      1                       The bit X is fixed to 1
    //
    // The following code enforces this logic by setting bits that must be 1,
    // and clearing bits that must be 0.
    //
    // See: A.3.1 Pin-Based VM-Execution Controls
    // See: A.3.2 Primary Processor-Based VM-Execution Controls
    // See: A.3.3 Secondary Processor-Based VM-Execution Controls
    let capabilities = unsafe { rdmsr(cap_msr) };
    let allowed0 = capabilities as u32;
    let allowed1 = (capabilities >> 32) as u32;
    let mut effective_value = u32::try_from(requested_value).unwrap();
    effective_value |= allowed0;
    effective_value &= allowed1;
    u64::from(effective_value)
}

fn enable_vmx() {
    ostd::early_println!("Enabling VMX operation");

    // Check if the CPU supports VMX operation
    let cpuid = x86::cpuid::CpuId::new();
    if let Some(feature_info) = cpuid.get_feature_info() {
        if feature_info.has_vmx() {
            ostd::early_println!("VMX operation is supported");
        } else {
            ostd::early_println!("VMX operation is not supported");
            return;
        }
    } else {
        ostd::early_println!("Failed to get feature info");
        return;
    }

    // Enable VMX operation
    // "Before system software can enter VMX operation, it enables VMX by
    //  setting CR4.VMXE[bit 13] = 1."
    // See: 24.7 ENABLING AND ENTERING VMX OPERATION
    cr4_vmx_enable();

    // Prepare for entering VMX operation by executing the VMXON instruction.
    // To enter VMX operation, several requirements must be met or the
    // instruction fails. We assume all those conditions are already satisfied
    // except ones with the IA32_FEATURE_CONTROL MSR and CR0. Let us fix them
    // up. For details of the requirements,
    // See: VMXON-Enter VMX Operation
    //
    // "VMXON is also controlled by the IA32_FEATURE_CONTROL MSR (...)."
    // See: 24.7 ENABLING AND ENTERING VMX OPERATION
    // "In VMX operation, processors may fix certain bits in CR0 and CR4 to
    //  specific values and not support other values. VMXON fails if any of
    //  these bits contains an unsupported value"
    // See: 24.8 RESTRICTIONS ON VMX OPERATION
    adjust_feature_control_msr();
    adjust_cr0();

    // Execute the VMXON instruction. This instruction requires 4KB of a
    // region called "VMXON region" and that part of the region is initialized
    // with the VMCS revision identifier, which can be read from the
    // IA32_VMX_BASIC MSR.
    //
    // Successful execution of it puts the processor into the operation mode
    // called "VMX root operation" (ie, host-mode) allowing the use of the
    // other VMX instructions.
    //
    // "Before executing VMXON, software should write the VMCS revision
    //  identifier (see Section 25.2) to the VMXON region."
    // See: 25.11.5 VMXON Region
    //
    // "Software can discover the VMCS revision identifier that a processor
    //  uses by reading the VMX capability MSR IA32_VMX_BASIC (see Appendix A.1)."
    // See: 25.2 FORMAT OF THE VMCS REGION
    invoke_vmxon();

    ostd::early_println!("VMX operation enabled");
    ostd::early_println!("CPL: {}", get_cpl());
}

fn enable_vmcs() {
    unsafe {
        let revision_id = rdmsr(msr::IA32_VMX_BASIC) as u64;
        let mut vmcs_phys: usize = &VMCS_REGION as *const _ as usize - 0xffff_ffff_8000_0000; // kernel code base addr;
        VMCS_REGION.revision_id = revision_id as u32;

        x86::bits64::vmx::vmclear(vmcs_phys as u64).unwrap();
        ostd::early_println!("VMCS_REGION addr: {:X}, revid: {:#X}", vmcs_phys, VMXON_REGION.revision_id);
        x86::bits64::vmx::vmptrld(vmcs_phys as u64).unwrap();
    }
}

/// Reads the CR0 register.
pub(crate) fn cr0() -> Cr0 {
    // Safety: this project runs at CPL0.
    unsafe { x86::controlregs::cr0() }
}

/// Reads the CR3 register.
pub(crate) fn cr3() -> u64 {
    // Safety: this project runs at CPL0.
    unsafe { x86::controlregs::cr3() }
}

/// Reads the CR4 register.
pub(crate) fn cr4() -> Cr4 {
    // Safety: this project runs at CPL0.
    unsafe { x86::controlregs::cr4() }
}

/// Selector functions
fn get_es() -> u16 {
    let segment: u16;
    unsafe { asm!("mov %es, {0:x}", out(reg) segment, options(att_syntax)) };
    segment
}
fn get_cs() -> u16 {
    let segment: u16;
    unsafe { asm!("mov %cs, {0:x}", out(reg) segment, options(att_syntax)) };
    segment
}
fn get_ss() -> u16 {
    let segment: u16;
    unsafe { asm!("mov %ss, {0:x}", out(reg) segment, options(att_syntax)) };
    segment
}
fn get_ds() -> u16 {
    let segment: u16;
    unsafe { asm!("mov %ds, {0:x}", out(reg) segment, options(att_syntax)) };
    segment
}
fn get_fs() -> u16 {
    let segment: u16;
    unsafe { asm!("mov %fs, {0:x}", out(reg) segment, options(att_syntax)) };
    segment
}
fn get_gs() -> u16 {
    let segment: u16;
    unsafe { asm!("mov %gs, {0:x}", out(reg) segment, options(att_syntax)) };
    segment
}
fn get_tr() -> u16 {
    let tr: u16;
    unsafe { asm!("str {0:x}", out(reg) tr, options(nomem, nostack)); }
    tr
}
fn get_gdt_base() -> u64 {
    let mut gdtr: DescriptorTablePointer<u64> = Default::default();
    unsafe {
        x86::dtables::sgdt(&mut gdtr);
    }
    gdtr.base as u64
}
fn get_idt_base() -> u64 {
    let mut idtr: DescriptorTablePointer<u64> = Default::default();
    unsafe {
        x86::dtables::sidt(&mut idtr);
    }
    idtr.base as u64
}
fn get_tr_base() -> u64 {
    // First, get the tr selector.
    let tr_selector = unsafe {
        let tr: u16;
        asm!("str {0:x}", out(reg) tr, options(nomem, nostack));
        SegmentSelector::from_raw(tr)
    };

    // We read the tr selector, and now we have to get base from GDT.
    // In x86-64, tr base is stored in GDT.
    // First, we need to know gdt base address.
    let mut gdtr: DescriptorTablePointer<u64> = Default::default();
    unsafe {
        x86::dtables::sgdt(&mut gdtr);
    }
    let gdt_base = gdtr.base as u64;

    // Now we have to parse GDT to find TR base.
    // First, we have to get the index.
    let index = tr_selector.index();
    // Because each entry in GDT is 8bytes, we have to multiply by 8.
    let tr_descriptor_addr = gdt_base + (index as u64) * 8;
    // GDT entry's format is defined in `Descriptor` struct in `x86::segmentation`.
    // So, we can use struct `Descriptor` to parse it.
    let tr_descriptor: x86::segmentation::Descriptor;
    unsafe {
        tr_descriptor = core::ptr::read(tr_descriptor_addr as *const _);
    }

    ostd::early_println!("tr_descriptor1: {:X}", tr_descriptor.as_u64());
    tr_descriptor.as_u64() // As we know, in tr_descriptor's format, base address are stored in as_u64().
}

#[repr(packed)]
struct Descriptor64 {
    limit: u16,
    base0: u16,
    base1: u8,
    pad1: u8,
    pad2: u8,
    base2: u8,
    base3: u32,
    zero1: u32,
}
fn get_tr_base2() -> u64 {
    let gdt_base = get_gdt_base();
    let tr = get_tr();
    let trd_addr = gdt_base + tr as u64;
    let trd64: Descriptor64;
    unsafe {
        trd64 = core::ptr::read(trd_addr as *const _);
    }
    let tr_base = ((trd64.base3 as u64) << 32) | ((trd64.base0 as u64) | ((trd64.base1 as u64) << 16)) | ((trd64.base2 as u64) << 24);
    ostd::early_println!("tr_descriptor2: {:X}", tr_base);
    tr_base
}

const IA32_VMX_EXIT_CTLS_HOST_ADDRESS_SPACE_SIZE_FLAG: u64 = 1 << 9;
const IA32_VMX_ENTRY_CTLS_IA32E_MODE_GUEST_FLAG: u64 = 1 << 9;

unsafe fn init_vmcs_control() {
    // reference: https://github.com/shubham0d/ProtoVirt
    // Set control fields
    vmwrite(
        vmcs::control::PINBASED_EXEC_CONTROLS,
        adjust_vmx_control(VmxControl::PinBased, 0),
    );
    vmwrite(
        vmcs::control::PRIMARY_PROCBASED_EXEC_CONTROLS,
        adjust_vmx_control(VmxControl::ProcessorBased, 0),
    );
    vmwrite(
        vmcs::control::SECONDARY_PROCBASED_EXEC_CONTROLS,
        adjust_vmx_control(VmxControl::ProcessorBased2, 0),
    );
    vmwrite(
        vmcs::control::VMEXIT_CONTROLS,
        adjust_vmx_control(VmxControl::VmExit, IA32_VMX_EXIT_CTLS_HOST_ADDRESS_SPACE_SIZE_FLAG),
    );
    vmwrite(
        vmcs::control::VMENTRY_CONTROLS,
        adjust_vmx_control(VmxControl::VmEntry, IA32_VMX_ENTRY_CTLS_IA32E_MODE_GUEST_FLAG),
    );

    // Igore exception bitmap
    // -- exception bitmap: 32-bit field in which one bit is for each exception
    // -- setting 0 means ignoring vmexit for any guest exception.
    vmwrite(
        vmcs::control::EXCEPTION_BITMAP,
        0 as u64,
    );

    // VPID == 0 (single cpu, don't care it for now)
    vmwrite(
        vmcs::control::VPID,
        0 as u64,
    );

    // Checks on Host Control Registers and MSRs
    // CR0/CR3/CR4
    vmwrite(vmcs::host::CR0, cr0().bits() as u64);
    vmwrite(vmcs::host::CR3, cr3());
    vmwrite(vmcs::host::CR4, cr4().bits() as u64);

    // Setting host selectors
    vmwrite(vmcs::host::ES_SELECTOR, get_es());
    vmwrite(vmcs::host::CS_SELECTOR, get_cs());
    vmwrite(vmcs::host::SS_SELECTOR, get_ss());
    vmwrite(vmcs::host::DS_SELECTOR, get_ds());
    vmwrite(vmcs::host::FS_SELECTOR, get_fs());
    vmwrite(vmcs::host::GS_SELECTOR, get_gs());
    vmwrite(vmcs::host::TR_SELECTOR, get_tr());

    vmwrite(vmcs::host::FS_BASE, rdmsr(msr::IA32_FS_BASE));
    vmwrite(vmcs::host::GS_BASE, rdmsr(msr::IA32_GS_BASE));
    vmwrite(vmcs::host::TR_BASE, get_tr_base2());
    vmwrite(vmcs::host::GDTR_BASE, get_gdt_base());
    vmwrite(vmcs::host::IDTR_BASE, get_idt_base());
    
    vmwrite(vmcs::host::IA32_SYSENTER_ESP, rdmsr(msr::SYSENTER_ESP_MSR));
    vmwrite(vmcs::host::IA32_SYSENTER_EIP, rdmsr(msr::SYSENTER_EIP_MSR));
    vmwrite(vmcs::host::IA32_SYSENTER_CS, rdmsr(msr::SYSENTER_CS_MSR));

    // Setting the guest control area
    vmwrite(vmcs::guest::ES_SELECTOR, vmread(vmcs::host::ES_SELECTOR));
    vmwrite(vmcs::guest::CS_SELECTOR, vmread(vmcs::host::CS_SELECTOR));
    vmwrite(vmcs::guest::SS_SELECTOR, vmread(vmcs::host::SS_SELECTOR));
    vmwrite(vmcs::guest::DS_SELECTOR, vmread(vmcs::host::DS_SELECTOR));
    vmwrite(vmcs::guest::FS_SELECTOR, vmread(vmcs::host::FS_SELECTOR));
    vmwrite(vmcs::guest::GS_SELECTOR, vmread(vmcs::host::GS_SELECTOR));
    vmwrite(vmcs::guest::TR_SELECTOR, vmread(vmcs::host::TR_SELECTOR));
    vmwrite(vmcs::guest::LDTR_SELECTOR, 0 as u64);
    vmwrite(vmcs::guest::INTERRUPT_STATUS, 0 as u64);
    vmwrite(vmcs::guest::PML_INDEX, 0 as u64);

    vmwrite(vmcs::guest::LINK_PTR_FULL, u64::MAX);
    vmwrite(vmcs::guest::IA32_DEBUGCTL_FULL, 0 as u64);
    vmwrite(vmcs::guest::IA32_PAT_FULL, vmread(vmcs::host::IA32_PAT_FULL));
    vmwrite(vmcs::guest::IA32_EFER_FULL, vmread(vmcs::host::IA32_EFER_FULL));
    vmwrite(vmcs::guest::IA32_PERF_GLOBAL_CTRL_FULL, vmread(vmcs::host::IA32_PERF_GLOBAL_CTRL_FULL));

    vmwrite(vmcs::guest::ES_LIMIT, u64::MAX);
    vmwrite(vmcs::guest::CS_LIMIT, u64::MAX);
    vmwrite(vmcs::guest::SS_LIMIT, u64::MAX);
    vmwrite(vmcs::guest::DS_LIMIT, u64::MAX);
    vmwrite(vmcs::guest::FS_LIMIT, u64::MAX);
    vmwrite(vmcs::guest::GS_LIMIT, u64::MAX);
    vmwrite(vmcs::guest::LDTR_LIMIT, u64::MAX);
    vmwrite(vmcs::guest::TR_LIMIT, 0x67 as u64);
    vmwrite(vmcs::guest::GDTR_LIMIT, 0xffff as u64);
    vmwrite(vmcs::guest::IDTR_LIMIT, 0xffff as u64);

    let es_access_rights = if vmread(vmcs::guest::ES_SELECTOR) == 0 {
        0x10000 as u64
    } else {
        0xc093 as u64
    };
    vmwrite(vmcs::guest::ES_ACCESS_RIGHTS, es_access_rights);
    vmwrite(vmcs::guest::CS_ACCESS_RIGHTS, 0xa09b as u64);
    vmwrite(vmcs::guest::SS_ACCESS_RIGHTS, 0xc093 as u64);

    let ds_access_rights = if vmread(vmcs::guest::DS_SELECTOR) == 0 {
        0x10000 as u64
    } else {
        0xc093 as u64
    };
    vmwrite(vmcs::guest::DS_ACCESS_RIGHTS, ds_access_rights);

    let fs_access_rights = if vmread(vmcs::guest::FS_SELECTOR) == 0 {
        0x10000 as u64
    } else {
        0xc093 as u64
    };
    vmwrite(vmcs::guest::FS_ACCESS_RIGHTS, fs_access_rights);

    let gs_access_rights = if vmread(vmcs::guest::GS_SELECTOR) == 0 {
        0x10000 as u64
    } else {
        0xc093 as u64
    };
    vmwrite(vmcs::guest::GS_ACCESS_RIGHTS, gs_access_rights);
    vmwrite(vmcs::guest::LDTR_ACCESS_RIGHTS, 0x10000 as u64);
    vmwrite(vmcs::guest::TR_ACCESS_RIGHTS, 0x8b as u64);
    vmwrite(vmcs::guest::INTERRUPTIBILITY_STATE, 0 as u64);
    vmwrite(vmcs::guest::ACTIVITY_STATE, 0 as u64);
    vmwrite(vmcs::guest::VMX_PREEMPTION_TIMER_VALUE, 0 as u64);

    vmwrite(vmcs::guest::IA32_SYSENTER_CS, vmread(vmcs::host::IA32_SYSENTER_CS));
    vmwrite(vmcs::guest::IA32_SYSENTER_ESP, vmread(vmcs::host::IA32_SYSENTER_ESP));
    vmwrite(vmcs::guest::IA32_SYSENTER_EIP, vmread(vmcs::host::IA32_SYSENTER_EIP));

    vmwrite(vmcs::guest::CR0, vmread(vmcs::host::CR0));
    vmwrite(vmcs::guest::CR3, vmread(vmcs::host::CR3));
    vmwrite(vmcs::guest::CR4, vmread(vmcs::host::CR4));

    vmwrite(vmcs::guest::ES_BASE, 0 as u64);
    vmwrite(vmcs::guest::CS_BASE, 0 as u64);
    vmwrite(vmcs::guest::SS_BASE, 0 as u64);
    vmwrite(vmcs::guest::DS_BASE, 0 as u64);
    vmwrite(vmcs::guest::FS_BASE, vmread(vmcs::host::FS_BASE));
    vmwrite(vmcs::guest::GS_BASE, vmread(vmcs::host::GS_BASE));
    vmwrite(vmcs::guest::LDTR_BASE, 0 as u64);
    vmwrite(vmcs::guest::TR_BASE, vmread(vmcs::host::TR_BASE));
    vmwrite(vmcs::guest::GDTR_BASE, vmread(vmcs::host::GDTR_BASE));
    vmwrite(vmcs::guest::IDTR_BASE, vmread(vmcs::host::IDTR_BASE));
    vmwrite(vmcs::guest::RFLAGS, 2 as u64);

    // Guest code selection
    let guest_stack_addr = &GUEST_STACK as *const _ as u64;
    let guest_code_addr = guest_code as u64;
    let run_vm_vmx_addr = run_vm_vmx as u64;
    vmwrite(vmcs::guest::RSP, guest_stack_addr);
    vmwrite(vmcs::guest::RIP, guest_code_addr);

    ostd::early_println!("run_vm_vmx_addr: {:X}", run_vm_vmx_addr);
    ostd::early_println!("init_vmcs_control end");
}

fn vm_exit_reason() -> u32 {
    let mut reason = vmread(vmcs::ro::EXIT_REASON) as u32;
    reason &= 0xffff;
    reason
}

fn vm_succeed(flags: RFlags) -> bool {
    if flags.contains(RFlags::FLAGS_ZF) {
        // See: 31.4 VM INSTRUCTION ERROR NUMBERS
        ostd::early_println!("VmFailValid with {}", vmread(vmcs::ro::VM_INSTRUCTION_ERROR));
        false
    } else if flags.contains(RFlags::FLAGS_CF) {
        ostd::early_println!("VmFailInvalid");
        false
    } else {
        ostd::early_println!("vmlaunch success: {:#x}", vm_exit_reason());
        true
    }
}

fn launch_vm() -> bool {
    ostd::early_println!("launch_vm start");
    let flags = unsafe { run_vm_vmx() };
    vm_succeed(RFlags::from_raw(flags))
}

fn vmxoff() {
    unsafe { asm!("vmxoff") };
}

pub fn start_hypervisor() {
    ostd::early_println!("Starting the hypervisor");
    enable_vmx();
    enable_vmcs();
    unsafe { init_vmcs_control(); }
    let _ = launch_vm();  // [TODO] it causes a kernel panic, figure out why and fix it!
    vmxoff();
    ostd::early_println!("vmx_enable end");
}