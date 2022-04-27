#include <iostream>
#include <vector>
#include <string.h>

#include <sai.h>


extern sai_status_t sai_create_direction_lookup_entry(
        _In_ const sai_direction_lookup_entry_t *direction_lookup_entry,
        _In_ uint32_t attr_count,
        _In_ const sai_attribute_t *attr_list);

extern sai_status_t sai_create_outbound_eni_lookup_from_vm_entry(
        _In_ const sai_outbound_eni_lookup_from_vm_entry_t *outbound_eni_lookup_from_vm_entry,
        _In_ uint32_t attr_count,
        _In_ const sai_attribute_t *attr_list);

extern sai_status_t sai_create_outbound_eni_to_vni_entry(
        _In_ const sai_outbound_eni_to_vni_entry_t *outbound_eni_to_vni_entry,
        _In_ uint32_t attr_count,
        _In_ const sai_attribute_t *attr_list);

extern sai_dash_api_t sai_dash_api_impl;

int main(int argc, char **argv)
{
    sai_object_id_t switch_id = SAI_NULL_OBJECT_ID;
    sai_attribute_t attr;
    std::vector<sai_attribute_t> attrs;

    sai_direction_lookup_entry_t dle = {};
    dle.switch_id = switch_id;
    dle.vni = 60;

    attr.id = SAI_DIRECTION_LOOKUP_ENTRY_ATTR_DIRECTION;
    attr.value.u32 = 1;
    attrs.push_back(attr);
    
    /* sai_status_t status = sai_dash_api_impl.create_direction_lookup_entry(&dle, attrs.size(), attrs.data()); */
    sai_status_t status = sai_create_direction_lookup_entry(&dle, attrs.size(), attrs.data());
    if (status != SAI_STATUS_SUCCESS)
    {
        std::cout << "Failed to create Direction Lookup Entry" << std::endl;
        return 1;
    }

    attrs.clear();

    sai_outbound_eni_lookup_from_vm_entry_t elfv;
    elfv.switch_id = switch_id;
    elfv.smac[0] = 0xcc;
    elfv.smac[1] = 0xcc;
    elfv.smac[2] = 0xcc;
    elfv.smac[3] = 0xcc;
    elfv.smac[4] = 0xcc;
    elfv.smac[5] = 0xcc;

    attr.id = SAI_OUTBOUND_ENI_LOOKUP_FROM_VM_ENTRY_ATTR_ENI;
    attr.value.u16 = 7;
    attrs.push_back(attr);

    /* status = sai_dash_api_impl.create_outbound_eni_lookup_from_vm_entry(&elfv, attrs.size(), attrs.data()); */
    status = sai_create_outbound_eni_lookup_from_vm_entry(&elfv, attrs.size(), attrs.data());
    if (status != SAI_STATUS_SUCCESS)
    {
        std::cout << "Failed to create ENI Lookup From VM" << std::endl;
        return 1;
    }

    attrs.clear();

    sai_outbound_eni_to_vni_entry_t e2v = {};
    e2v.switch_id = switch_id;
    e2v.eni = 7;

    attr.id = SAI_OUTBOUND_ENI_TO_VNI_ENTRY_ATTR_VNI;
    attr.value.u32 = 9;
    attrs.push_back(attr);

    /* status = sai_dash_api_impl.create_outbound_eni_to_vni_entry(&e2v, attrs.size(), attrs.data()); */
    status = sai_create_outbound_eni_to_vni_entry(&e2v, attrs.size(), attrs.data());
    if (status != SAI_STATUS_SUCCESS)
    {
        std::cout << "Failed to create ENI To VNI" << std::endl;
        return 1;
    }

    attrs.clear();


    std::cout << "Done." << std::endl;

    return 0;
}
