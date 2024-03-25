

kvm_x86_init()
-> kvm_mmu_x86_module_init()
   -> tdp_mmu_allowed = tdp_mmu_enabled
   -> kvm_mmu_spte_module_init()
      -> allow_mmio_caching = enable_mmio_caching;


vmx_init() or svm_init()
-> kvm_x86_vendor_init()
   -> __kvm_x86_vendor_init()
      -> kvm_mmu_vendor_module_init()
         -> kvm_mmu_reset_all_pte_masks()
            -> shadow_accessed_mask = PT_ACCESSED_MASK; (1 << 5)
   -> ops->hardware_setup = hardware_setup()
      -> kvm_mmu_set_ept_masks()
         -> shadow_accessed_mask = has_ad_bits ? VMX_EPT_ACCESS_BIT : 0ull; (1 << 8)

kvm_create_vm()
-> hardware_enable_all()
   -> on_each_cpu(hardware_enable_nolock, &failed, 1);
      -> __hardware_enable_nolock()
         -> kvm_arch_hardware_enable()
            -> static_call(kvm_x86_hardware_enable)() = hardware_enable()

