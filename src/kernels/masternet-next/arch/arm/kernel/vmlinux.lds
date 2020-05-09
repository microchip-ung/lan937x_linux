OUTPUT_ARCH(arm)
ENTRY(stext)
jiffies = jiffies_64;
SECTIONS
{
 /DISCARD/ : {
  *(.ARM.exidx.exit.text) *(.ARM.extab.exit.text) *(.ARM.exidx.text.exit) *(.ARM.extab.text.exit) *(.ARM.exidx.cpuexit.text) *(.ARM.extab.cpuexit.text) *(.exitcall.exit) *(.discard) *(.discard.*)
  *(.alt.smp.init)
 }
 . = ((0xC0000000)) + 0x00008000;
 .head.text : {
  _text = .;
  KEEP(*(.head.text))
 }
 . = ALIGN(1<<20);
 .text : {
  _stext = .;
  . = ALIGN(8); __idmap_text_start = .; *(.idmap.text) __idmap_text_end = .; __entry_text_start = .; *(.entry.text) __entry_text_end = .; . = ALIGN(8); __irqentry_text_start = .; *(.irqentry.text) __irqentry_text_end = .; . = ALIGN(8); __softirqentry_text_start = .; *(.softirqentry.text) __softirqentry_text_end = .; . = ALIGN(8); *(.text.hot .text .text.fixup .text.unlikely) *(.text..refcount) *(.ref.text) . = ALIGN(8); __sched_text_start = .; *(.sched.text) __sched_text_end = .; . = ALIGN(8); __cpuidle_text_start = .; *(.cpuidle.text) __cpuidle_text_end = .; . = ALIGN(8); __lock_text_start = .; *(.spinlock.text) __lock_text_end = .; . = ALIGN(8); __kprobes_text_start = .; *(.kprobes.text) __kprobes_text_end = .; *(.gnu.warning) *(.glue_7) *(.glue_7t) . = ALIGN(4); *(.got)
 }
 . = ALIGN(1<<20);
 _etext = .;
 . = ALIGN(((1 << 12))); .rodata : AT(ADDR(.rodata) - 0) { __start_rodata = .; *(.rodata) *(.rodata.*) __start_ro_after_init = .; *(.data..ro_after_init) . = ALIGN(8); __start___jump_table = .; KEEP(*(__jump_table)) __stop___jump_table = .; __end_ro_after_init = .; . = ALIGN(8); __start___tracepoints_ptrs = .; KEEP(*(__tracepoints_ptrs)) __stop___tracepoints_ptrs = .; *(__tracepoints_strings) } .rodata1 : AT(ADDR(.rodata1) - 0) { *(.rodata1) } .pci_fixup : AT(ADDR(.pci_fixup) - 0) { __start_pci_fixups_early = .; KEEP(*(.pci_fixup_early)) __end_pci_fixups_early = .; __start_pci_fixups_header = .; KEEP(*(.pci_fixup_header)) __end_pci_fixups_header = .; __start_pci_fixups_final = .; KEEP(*(.pci_fixup_final)) __end_pci_fixups_final = .; __start_pci_fixups_enable = .; KEEP(*(.pci_fixup_enable)) __end_pci_fixups_enable = .; __start_pci_fixups_resume = .; KEEP(*(.pci_fixup_resume)) __end_pci_fixups_resume = .; __start_pci_fixups_resume_early = .; KEEP(*(.pci_fixup_resume_early)) __end_pci_fixups_resume_early = .; __start_pci_fixups_suspend = .; KEEP(*(.pci_fixup_suspend)) __end_pci_fixups_suspend = .; __start_pci_fixups_suspend_late = .; KEEP(*(.pci_fixup_suspend_late)) __end_pci_fixups_suspend_late = .; } .builtin_fw : AT(ADDR(.builtin_fw) - 0) { __start_builtin_fw = .; KEEP(*(.builtin_fw)) __end_builtin_fw = .; } __ksymtab : AT(ADDR(__ksymtab) - 0) { __start___ksymtab = .; KEEP(*(SORT(___ksymtab+*))) __stop___ksymtab = .; } __ksymtab_gpl : AT(ADDR(__ksymtab_gpl) - 0) { __start___ksymtab_gpl = .; KEEP(*(SORT(___ksymtab_gpl+*))) __stop___ksymtab_gpl = .; } __ksymtab_unused : AT(ADDR(__ksymtab_unused) - 0) { __start___ksymtab_unused = .; KEEP(*(SORT(___ksymtab_unused+*))) __stop___ksymtab_unused = .; } __ksymtab_unused_gpl : AT(ADDR(__ksymtab_unused_gpl) - 0) { __start___ksymtab_unused_gpl = .; KEEP(*(SORT(___ksymtab_unused_gpl+*))) __stop___ksymtab_unused_gpl = .; } __ksymtab_gpl_future : AT(ADDR(__ksymtab_gpl_future) - 0) { __start___ksymtab_gpl_future = .; KEEP(*(SORT(___ksymtab_gpl_future+*))) __stop___ksymtab_gpl_future = .; } __kcrctab : AT(ADDR(__kcrctab) - 0) { __start___kcrctab = .; KEEP(*(SORT(___kcrctab+*))) __stop___kcrctab = .; } __kcrctab_gpl : AT(ADDR(__kcrctab_gpl) - 0) { __start___kcrctab_gpl = .; KEEP(*(SORT(___kcrctab_gpl+*))) __stop___kcrctab_gpl = .; } __kcrctab_unused : AT(ADDR(__kcrctab_unused) - 0) { __start___kcrctab_unused = .; KEEP(*(SORT(___kcrctab_unused+*))) __stop___kcrctab_unused = .; } __kcrctab_unused_gpl : AT(ADDR(__kcrctab_unused_gpl) - 0) { __start___kcrctab_unused_gpl = .; KEEP(*(SORT(___kcrctab_unused_gpl+*))) __stop___kcrctab_unused_gpl = .; } __kcrctab_gpl_future : AT(ADDR(__kcrctab_gpl_future) - 0) { __start___kcrctab_gpl_future = .; KEEP(*(SORT(___kcrctab_gpl_future+*))) __stop___kcrctab_gpl_future = .; } __ksymtab_strings : AT(ADDR(__ksymtab_strings) - 0) { *(__ksymtab_strings) } __init_rodata : AT(ADDR(__init_rodata) - 0) { *(.ref.rodata) } __param : AT(ADDR(__param) - 0) { __start___param = .; KEEP(*(__param)) __stop___param = .; } __modver : AT(ADDR(__modver) - 0) { __start___modver = .; KEEP(*(__modver)) __stop___modver = .; } .notes : AT(ADDR(.notes) - 0) { __start_notes = .; KEEP(*(.note.*)) __stop_notes = .; } . = ALIGN(((1 << 12))); __end_rodata = .;
 . = ALIGN(4);
 __ex_table : AT(ADDR(__ex_table) - 0) {
  __start___ex_table = .;
  *(__ex_table)
  __stop___ex_table = .;
 }
 . = ALIGN(8); .ARM.unwind_idx : { __start_unwind_idx = .; *(.ARM.exidx*) __stop_unwind_idx = .; } .ARM.unwind_tab : { __start_unwind_tab = .; *(.ARM.extab*) __stop_unwind_tab = .; }
 . = ALIGN(1<<20);
 __init_begin = .;
 __vectors_start = .; .vectors 0xffff0000 : AT(__vectors_start) { *(.vectors) } . = __vectors_start + SIZEOF(.vectors); __vectors_end = .; __stubs_start = .; .stubs ADDR(.vectors) + 0x1000 : AT(__stubs_start) { *(.stubs) } . = __stubs_start + SIZEOF(.stubs); __stubs_end = .; PROVIDE(vector_fiq_offset = vector_fiq - ADDR(.vectors));
 . = ALIGN(8); .init.text : AT(ADDR(.init.text) - 0) { _sinittext = .; *(.init.text .init.text.*) *(.text.startup) *(.meminit.text*) _einittext = .; }
 .exit.text : {
  *(.exit.text) *(.text.exit) *(.memexit.text)
 }
 .init.proc.info : {
  . = ALIGN(4); __proc_info_begin = .; *(.proc.info.init) __proc_info_end = .;
 }
 .init.arch.info : {
  __arch_info_begin = .;
  *(.arch.info.init)
  __arch_info_end = .;
 }
 .init.tagtable : {
  __tagtable_begin = .;
  *(.taglist.init)
  __tagtable_end = .;
 }
 .init.pv_table : {
  __pv_table_begin = .;
  *(.pv_table)
  __pv_table_end = .;
 }
 .init.data : AT(ADDR(.init.data) - 0) { KEEP(*(SORT(___kentry+*))) *(.init.data init.data.*) *(.meminit.data*) *(.init.rodata .init.rodata.*) *(.meminit.rodata) . = ALIGN(8); __clk_of_table = .; KEEP(*(__clk_of_table)) KEEP(*(__clk_of_table_end)) . = ALIGN(8); __reservedmem_of_table = .; KEEP(*(__reservedmem_of_table)) KEEP(*(__reservedmem_of_table_end)) . = ALIGN(8); __timer_of_table = .; KEEP(*(__timer_of_table)) KEEP(*(__timer_of_table_end)) . = ALIGN(32); __dtb_start = .; KEEP(*(.dtb.init.rodata)) __dtb_end = .; . = ALIGN(8); __irqchip_of_table = .; KEEP(*(__irqchip_of_table)) KEEP(*(__irqchip_of_table_end)) . = ALIGN(16); __setup_start = .; KEEP(*(.init.setup)) __setup_end = .; __initcall_start = .; KEEP(*(.initcallearly.init)) __initcall0_start = .; KEEP(*(.initcall0.init)) KEEP(*(.initcall0s.init)) __initcall1_start = .; KEEP(*(.initcall1.init)) KEEP(*(.initcall1s.init)) __initcall2_start = .; KEEP(*(.initcall2.init)) KEEP(*(.initcall2s.init)) __initcall3_start = .; KEEP(*(.initcall3.init)) KEEP(*(.initcall3s.init)) __initcall4_start = .; KEEP(*(.initcall4.init)) KEEP(*(.initcall4s.init)) __initcall5_start = .; KEEP(*(.initcall5.init)) KEEP(*(.initcall5s.init)) __initcallrootfs_start = .; KEEP(*(.initcallrootfs.init)) KEEP(*(.initcallrootfss.init)) __initcall6_start = .; KEEP(*(.initcall6.init)) KEEP(*(.initcall6s.init)) __initcall7_start = .; KEEP(*(.initcall7.init)) KEEP(*(.initcall7s.init)) __initcall_end = .; __con_initcall_start = .; KEEP(*(.con_initcall.init)) __con_initcall_end = .; . = ALIGN(4); __initramfs_start = .; KEEP(*(.init.ramfs)) . = ALIGN(8); KEEP(*(.init.ramfs.info)) }
 .exit.data : {
  *(.exit.data .exit.data.*) *(.fini_array .fini_array.*) *(.dtors .dtors.*) *(.memexit.data*) *(.memexit.rodata*)
 }
 . = ALIGN(1<<20);
 __init_end = .;
 _sdata = .;
 . = ALIGN((1 << 12)); .data : AT(ADDR(.data) - 0) { . = ALIGN(((1 << 12) << 1)); __start_init_task = .; init_thread_union = .; init_stack = .; KEEP(*(.data..init_task)) KEEP(*(.data..init_thread_info)) . = __start_init_task + ((1 << 12) << 1); __end_init_task = .; . = ALIGN((1 << 12)); __nosave_begin = .; *(.data..nosave) . = ALIGN((1 << 12)); __nosave_end = .; . = ALIGN((1 << 12)); *(.data..page_aligned) . = ALIGN((1 << 6)); *(.data..cacheline_aligned) . = ALIGN((1 << 6)); *(.data..read_mostly) . = ALIGN((1 << 6)); *(.xiptext) *(.data) *(.ref.data) *(.data..shared_aligned) *(.data.unlikely) __start_once = .; *(.data.once) __end_once = .; . = ALIGN(32); *(__tracepoints) . = ALIGN(8); __start___verbose = .; KEEP(*(__verbose)) __stop___verbose = .; CONSTRUCTORS } . = ALIGN(8); __bug_table : AT(ADDR(__bug_table) - 0) { __start___bug_table = .; KEEP(*(__bug_table)) __stop___bug_table = .; }
 _edata = .;
 . = ALIGN(0); __bss_start = .; . = ALIGN(0); .sbss : AT(ADDR(.sbss) - 0) { *(.dynsbss) *(.sbss) *(.scommon) } . = ALIGN(0); .bss : AT(ADDR(.bss) - 0) { *(.bss..page_aligned) *(.dynbss) *(.bss) *(COMMON) } . = ALIGN(0); __bss_stop = .;
 _end = .;
 .stab 0 : { *(.stab) } .stabstr 0 : { *(.stabstr) } .stab.excl 0 : { *(.stab.excl) } .stab.exclstr 0 : { *(.stab.exclstr) } .stab.index 0 : { *(.stab.index) } .stab.indexstr 0 : { *(.stab.indexstr) } .comment 0 : { *(.comment) }
}
__start_rodata_section_aligned = ALIGN(__start_rodata, 1 << 20);
ASSERT((__proc_info_end - __proc_info_begin), "missing CPU support")
ASSERT((__arch_info_end - __arch_info_begin), "no machine record defined")
