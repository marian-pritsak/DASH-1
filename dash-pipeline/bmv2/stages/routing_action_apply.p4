#ifndef _DASH_STAGE_ACTION_APPLY_P4_
#define _DASH_STAGE_ACTION_APPLY_P4_

#include "../routing_actions/routing_actions.p4"
#include "tunnel_stage.p4"

control routing_action_apply(
    inout headers_t hdr,
    inout metadata_t meta)
{
    apply {
        do_action_nat46.apply(hdr, meta);
        do_action_nat64.apply(hdr, meta);

        // Encaps needs to be added after all other transforms, from inner ones to outer ones,
        // because it requires the transforms on the inner packet to be finished in order to
        // get the correct inner packet size and other informations.
        do_action_static_encap.apply(hdr, meta);

        tunnel_stage.apply(hdr, meta);
    }
}

#endif /* _DASH_STAGE_ACTION_APPLY_P4_ */
