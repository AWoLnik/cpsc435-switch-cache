/* -*- P4_16 -*- */
#include <core.p4>
#include <v1model.p4>

const bit<16> TYPE_IPV4 = 0x800;
const bit<8>  IP_PROT_UDP  = 0x11;

const bit<32> CLIENT_ADDR = 0x0A000002; /*10.0.0.2*/
const bit<32> SERVER_ADDR = 0x0A000001; /*10.0.0.2*/
const bit<16> UDP_PORT    = 1234;

/*************************************************************************
*********************** H E A D E R S  ***********************************
*************************************************************************/

typedef bit<9>  egressSpec_t;
typedef bit<48> macAddr_t;
typedef bit<32> ip4Addr_t;

header ethernet_t {
    macAddr_t dstAddr;
    macAddr_t srcAddr;
    bit<16>   etherType;
}

header ipv4_t {
    bit<4>    version;
    bit<4>    ihl;
    bit<8>    diffserv;
    bit<16>   totalLen;
    bit<16>   identification;
    bit<3>    flags;
    bit<13>   fragOffset;
    bit<8>    ttl;
    bit<8>    protocol;
    bit<16>   hdrChecksum;
    ip4Addr_t srcAddr;
    ip4Addr_t dstAddr;
}

header udp_t {
    bit<16> srcPort;
    bit<16> dstPort;
    bit<16> length_;
    bit<16> checksum;
}

header request_t {
    bit<8>  key;
}

header response_t {
    bit<8>  key;
    bit<8>  is_valid;
    bit<32> val;
}

struct metadata {
    /* empty */
}

struct headers {
    ethernet_t        ethernet;
    ipv4_t            ipv4;
    udp_t             udp;
    request_t         request;
    response_t        response;
}

/*************************************************************************
*********************** P A R S E R  ***********************************
*************************************************************************/

parser MyParser(packet_in packet,
                out headers hdr,
                inout metadata meta,
                inout standard_metadata_t standard_metadata) {

    state start {
        transition parse_ethernet;
    }

    state parse_ethernet {
        packet.extract(hdr.ethernet);
        transition select(hdr.ethernet.etherType) {
            TYPE_IPV4: parse_ipv4;
            default: accept;
        }
    }

    state parse_ipv4 {
        packet.extract(hdr.ipv4);
        transition select(hdr.ipv4.protocol) {
            IP_PROT_UDP: parse_udp;
            default: accept;
        }
    }

    state parse_udp {
        packet.extract(hdr.udp);
        transition select(hdr.ipv4.srcAddr) {
            CLIENT_ADDR: parse_request;
            SERVER_ADDR: parse_response;
            default: accept;
        }
    }

    state parse_request {
        packet.extract(hdr.request);
        transition accept;
    }

    state parse_response {
        packet.extract(hdr.response);
        transition accept;
    }

}

/*************************************************************************
************   C H E C K S U M    V E R I F I C A T I O N   *************
*************************************************************************/

control MyVerifyChecksum(inout headers hdr, inout metadata meta) {
    apply {  }
}


/*************************************************************************
**************  I N G R E S S   P R O C E S S I N G   *******************
*************************************************************************/

control MyIngress(inout headers hdr,
                  inout metadata meta,
                  inout standard_metadata_t standard_metadata) {

    register<bit<33>>(256) regCache;
    bit<1> regHit = 0;
    bit<32> regVal = 0;

    action drop() {
        mark_to_drop();
    }

    action ipv4_forward(macAddr_t dstAddr, egressSpec_t port) {
        standard_metadata.egress_spec = port;
        hdr.ethernet.srcAddr = hdr.ethernet.dstAddr;
        hdr.ethernet.dstAddr = dstAddr;
        hdr.ipv4.ttl = hdr.ipv4.ttl - 1;
    }

    table ipv4_lpm {
        key = {
            hdr.ipv4.dstAddr: lpm;
        }
        actions = {
            ipv4_forward;
            drop;
            NoAction;
        }
        size = 1024;
        default_action = drop();
    }

    action reply(bit<32> val) {
        hdr.ipv4.dstAddr = CLIENT_ADDR;
        hdr.ipv4.srcAddr = SERVER_ADDR;
        hdr.ipv4.totalLen = hdr.ipv4.totalLen + 5;

        hdr.udp.dstPort = hdr.udp.srcPort;
        hdr.udp.srcPort = UDP_PORT;
        hdr.udp.checksum = 0;
        hdr.udp.length_ = hdr.udp.length_ + 5;

        hdr.request.setInvalid();
        hdr.response.setValid();

        hdr.response.key = hdr.request.key;
        hdr.response.is_valid = 1;
        hdr.response.val = val;
    }

    action write_register_cache(bit<8> key, bit<32> val) {
        bit<33> reg = 0;
        reg[32:32] = 1;
        reg[31:0] = val;
        regCache.write((bit<32>)key, reg);
    }

    action check_register_cache() {
        bit<33> reg = 0;

        regCache.read(reg, (bit<32>)hdr.request.key);

        if(reg[32:32] == 1) {
            regHit = 1;
            regVal = reg[31:0];
        }
    }

    table cache_exact {
        key = {
            hdr.request.key: exact;
        }
        actions = {
            reply;
            check_register_cache;
        }
        size = 256;
        default_action = check_register_cache();
    }

    apply {
        if (hdr.request.isValid()) {
            cache_exact.apply();
            if(regHit == 1) {
                reply(regVal);
            }
        } else if (hdr.response.isValid() && hdr.response.is_valid == 1) {
            write_register_cache(hdr.response.key, hdr.response.val);
        }

        if (hdr.ipv4.isValid()) {
            ipv4_lpm.apply();
        } else {
            drop();
        }
    }
}

/*************************************************************************
****************  E G R E S S   P R O C E S S I N G   *******************
*************************************************************************/

control MyEgress(inout headers hdr,
                 inout metadata meta,
                 inout standard_metadata_t standard_metadata) {
    apply {  }
}

/*************************************************************************
*************   C H E C K S U M    C O M P U T A T I O N   **************
*************************************************************************/

control MyComputeChecksum(inout headers  hdr, inout metadata meta) {
    apply {
    update_checksum(
        hdr.ipv4.isValid(),
          { hdr.ipv4.version,
            hdr.ipv4.ihl,
            hdr.ipv4.diffserv,
            hdr.ipv4.totalLen,
            hdr.ipv4.identification,
            hdr.ipv4.flags,
            hdr.ipv4.fragOffset,
            hdr.ipv4.ttl,
            hdr.ipv4.protocol,
            hdr.ipv4.srcAddr,
            hdr.ipv4.dstAddr },
        hdr.ipv4.hdrChecksum,
        HashAlgorithm.csum16);
    }
}

/*************************************************************************
***********************  D E P A R S E R  *******************************
*************************************************************************/

control MyDeparser(packet_out packet, in headers hdr) {
    apply {
        packet.emit(hdr.ethernet);
        packet.emit(hdr.ipv4);
        packet.emit(hdr.udp);
        packet.emit(hdr.request);
        packet.emit(hdr.response);
    }
}

/*************************************************************************
***********************  S W I T C H  *******************************
*************************************************************************/

V1Switch(
MyParser(),
MyVerifyChecksum(),
MyIngress(),
MyEgress(),
MyComputeChecksum(),
MyDeparser()
) main;