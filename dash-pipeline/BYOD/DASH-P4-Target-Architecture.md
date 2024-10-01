# DASH P4 Target Architecture

A P4 target architecture is the abstract hardware model that a P4 program is designed to run on, defining the specific processing elements and behavior of packet processing pipelines.
It helps bridge the gap between a P4 program's logic and the actual implementation on various types of network devices, ensuring compatibility and optimization across different platforms.
DASH P4 target architecture is defined with purpose to serve as a development baseline for BYOD applications.

The DASH P4 model encompasses a set of control stages. Each top-level object within this model is designed to receive a specific set of parameters.

**Parser**: The parser is responsible for processing the input packet and a header stack.
It operates without access to any metadata during the parsing stage, focusing solely on the packet's content and structure.

**Control**: The control stage is designed to handle three distinct types of metadata, each serving a different purpose within the target architecture:
* Standard Metadata: This is a read-only type of metadata that provides essential information about the packet obtained from prior stages, such as the parser and other fixed hardware units.
* User Metadata: This metadata category is read/write and contains application-specific variables. It allows for the customization and storage of data relevant to the application's logic.

## Parser

```p4
parser DashParser<HEADERS>(
             packet_in packet,
             out HEADERS headers);
```

### Default parser

The DPU's parser supports a hybrid architecture that incorporates both predefined (fixed) headers and standard transitions between headers as defined by the Internet Engineering Task Force (IETF).
These transitions are determined based on the "next header type" field present within each protocol.

The user need only include dash_parser.p4 and reference dash_fixed_parser in the P4 package declaration to use the built-in hardware parser.
The program should then use the native headers structure, dash_headers_t.

Complete list of native headers to be provided within the P4 TA document.

## Main control

```p4
control DASHMainControl<HEADERS, USER_META, PKT_OUT_META>(
        inout HEADERS headers,
        in standard_metadata_t std_meta,
        inout USER_META user_meta,
        inout PKT_OUT_META pkt_out_meta);
```

## Extern objects

`dash_drop`

Terminal extern function that stops packet processing and drops the packet.

Signature:

```p4
extern void dash_drop();
```

`dash_send_to_port`

Terminal extern function that stops packet processing and sends the packet to the specified port.

Signature:

```p4
extern void dash_send_to_port(in sai_object_id_t port);
```

Paramaters:
* `port[in]`: This parameter specifies the logical SAI port to which the packet will be sent to.

`dash_send_to_controller`

Terminal extern function that forwards packet metadata to a controller

Signature:

```p4
extern void dash_send_to_controller<PACKET_META>(in PACKET_META pkt_in_meta);
```

Paramaters:
* `pkt_in_meta[in]`: The metadata of the packet being sent to the controller for processing

## Examples

```p4 
#include <dash_model.p4>
#include <dash_headers.p4>
#include <dash_externs.p4>
#include <dash_parser.p4>

#define TCP_SYN_FLAG 0x02
#define TCP_FIN_FLAG 0x01
#define TCP_RST_FLAG 0x04


@dash_controller_metadata("packet_in")

struct ctrl_meta_t {
    bit<8> ip_protocol;
    bit<6> tcp_flags;
}


control plnsg(
    inout dash_headers_t headers,
    in dash_standard_metadata_t std_meta,
    inout dash_empty_metadata_t user_meta,
) {

    ctrl_meta_t data;

    action deny() {
        dash_drop();
    }

    action allow(sai_object_id_t port) {
        dash_send_to_port(port);
    }

    /* flow matching for TCP/UDP flows */
    DashDirectCounter(NvCounterType.PACKETS_AND_BYTES) acl_counter;

    table acl {
        key = {
            headers.inner_ipv6.src_addr : exact;
            headers.inner_ipv6.dst_addr : exact;
            headers.inner_ipv6.next_header : exact;
            headers.inner_tcp.src_port : exact;    // TODO: std_meta.l4_src_port
            headers.inner_tcp.dst_port : exact;    // TODO: std_meta.l4_dst_port
        }

        actions = {
            deny;
            allow;
            NoAction;
        }

        direct_counter = acl_counter;
        default_action = NoAction;
        size = 32768;

    }

    apply {

        data._reserved = 0;
        data.ip_protocol = 0;
        data.tcp_flags = 0;

 
        if (headers.inner_ipv6.isValid()) {
            if (headers.inner_tcp.isValid()) {
                if (headers.inner_tcp.flags != TCP_FIN_FLAG && headers.inner_tcp.flags != TCP_RST_FLAG) {
					acl.apply(); // On hit the entry will send_to_port or drop and execution ends here
				}
				// On miss the packet goes to the controller to insert the offload rule
				data.ip_protocol = NV_TCP_PROTOCOL;
				data.tcp_flags = headers.inner_tcp.flags;
			}
			else if (headers.inner_udp.isValid()) {
				acl.apply(); // On hit the entry will send_to_port or drop and execution ends here
				data.ip_protocol = NV_UDP_PROTOCOL;
			}
		}

        // On miss the packet goes to the controller to insert the offload rule
        dash_send_to_controller(data);
    }
}

 

// Instantiate the top-level Dpu Rx package

DashPipeline(
    dash_fixed_parser(),
    plnsg()
) main;
```
