/* -*- P4_16 -*- */
#include <core.p4>
#include <v1model.p4>

const bit<16> TYPE_IPV4 = 0x800;
const bit<8> PROTO_PROTECTION = 253;

/*************************************************************************
*********************** H E A D E R S  ***********************************
*************************************************************************/

typedef bit<9>  egressSpec_t;
typedef bit<48> macAddr_t;
typedef bit<32> ip4Addr_t;

header protection_t {
    bit<16> nextType;
    bit<32> seqNo;
}

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

struct metadata {
    bit<1>  do_clone;
    bit<32> clone_session;

    bit<1>  do_decap;
    bit<32> expected;
    bit<32> seqIdx;
    macAddr_t decap_dstAddr;
    egressSpec_t decap_port;
}

struct headers {
    ethernet_t    ethernet;
    ipv4_t        ipv4;        
    protection_t  protection;
    ipv4_t        inner_ipv4;  
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
            PROTO_PROTECTION: parse_protection;
            default: accept;
        }
    }

    state parse_protection {
        packet.extract(hdr.protection);
        transition select(hdr.protection.nextType) {
            TYPE_IPV4: parse_inner_ipv4;
            default: accept;
        }
    }

    state parse_inner_ipv4 {
        packet.extract(hdr.inner_ipv4);
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
    
    register<bit<32>>(2) next_seq;
    register<bit<32>>(2) expected_seq;

    action drop() {
        mark_to_drop(standard_metadata);
    }
    action protect_tunnel(macAddr_t dstAddr,
                      egressSpec_t port,
                      ip4Addr_t tunnelSrc,
                      ip4Addr_t tunnelDst,
                      bit<32> cloneSession,
                      bit<32> seqIdx) {
        bit<32> seq;

        next_seq.read(seq, seqIdx);
        next_seq.write(seqIdx, seq + 1);

        hdr.inner_ipv4 = hdr.ipv4;
        hdr.inner_ipv4.setValid();

        hdr.protection.setValid();
        hdr.protection.nextType = TYPE_IPV4;
        hdr.protection.seqNo = seq;

        hdr.ipv4.version = 4;
        hdr.ipv4.ihl = 5;
        hdr.ipv4.diffserv = 0;
        hdr.ipv4.totalLen = hdr.inner_ipv4.totalLen + (bit<16>)26;
        hdr.ipv4.identification = 0;
        hdr.ipv4.flags = 0;
        hdr.ipv4.fragOffset = 0;
        hdr.ipv4.ttl = 64;
        hdr.ipv4.protocol = PROTO_PROTECTION;
        hdr.ipv4.hdrChecksum = 0;
        hdr.ipv4.srcAddr = tunnelSrc;
        hdr.ipv4.dstAddr = tunnelDst;

        standard_metadata.egress_spec = port;
        hdr.ethernet.srcAddr = hdr.ethernet.dstAddr;
        hdr.ethernet.dstAddr = dstAddr;

        meta.do_clone = 1;
        meta.clone_session = cloneSession;
    }

    action protected_decap_forward(macAddr_t dstAddr,
                               egressSpec_t port,
                               bit<32> seqIdx) {
        expected_seq.read(meta.expected, seqIdx);

        meta.do_decap = 1;
        meta.seqIdx = seqIdx;
        meta.decap_dstAddr = dstAddr;
        meta.decap_port = port;
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
            protect_tunnel;
            protected_decap_forward;
            drop;
            NoAction;
        }
        size = 1024;
        default_action = drop();
    }

    apply {
        meta.do_clone = 0;
        meta.clone_session = 0;
        meta.do_decap = 0;

        if (hdr.ipv4.isValid()) {
            ipv4_lpm.apply();
        }

        if (meta.do_decap == 1) {
            if (hdr.protection.seqNo == meta.expected) {
                expected_seq.write(meta.seqIdx, meta.expected + 1);

                hdr.ipv4 = hdr.inner_ipv4;
                hdr.protection.setInvalid();
                hdr.inner_ipv4.setInvalid();

                standard_metadata.egress_spec = meta.decap_port;
                hdr.ethernet.srcAddr = hdr.ethernet.dstAddr;
                hdr.ethernet.dstAddr = meta.decap_dstAddr;
                hdr.ipv4.ttl = hdr.ipv4.ttl - 1;
            } else {
                mark_to_drop(standard_metadata);
            }
        }
    }
}

/*************************************************************************
****************  E G R E S S   P R O C E S S I N G   *******************
*************************************************************************/

control MyEgress(inout headers hdr,
                 inout metadata meta,
                 inout standard_metadata_t standard_metadata) {
    apply {
        if (meta.do_clone == 1 && standard_metadata.instance_type == 0) {
            clone(CloneType.E2E, meta.clone_session);
        }
    }
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
        packet.emit(hdr.protection);
        packet.emit(hdr.inner_ipv4);
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
