#include <core.p4>
#include <v1model.p4>

bit<3> max(in bit<3> val, in bit<3> bound) {
    return val < bound ? val : bound;
}
header ethernet_t {
    bit<48> dst_addr;
    bit<48> src_addr;
    bit<16> eth_type;
}

header ipv4_t {
    bit<4>  version;
    bit<4>  ihl;
    bit<8>  diffserv;
    bit<16> totalLen;
    bit<16> identification;
    bit<3>  flags;
    bit<13> fragOffset;
    bit<8>  ttl;
    bit<8>  protocol;
    bit<16> hdrChecksum;
    bit<32> srcAddr;
    bit<32> dstAddr;
}

header tcp_t {
    bit<16> srcPort;
    bit<16> dstPort;
    bit<32> seqNo;
    bit<32> ackNo;
    bit<4>  dataOffset;
    bit<4>  res;
    bit<8>  flags;
    bit<16> window;
    bit<16> checksum;
    bit<16> urgentPtr;
}

struct Headers {
    ethernet_t eth_hdr;
    ipv4_t     ipv4_hdr;
    tcp_t      tcp_hdr;
}

struct Meta {
}

parser p(packet_in pkt, out Headers hdr, inout Meta m, inout standard_metadata_t sm) {
    state start {
        transition parse_ethernet;
    }
    state parse_ethernet {
        pkt.extract(hdr.eth_hdr);
        transition parse_ipv4;
    }
    state parse_ipv4 {
        pkt.extract(hdr.ipv4_hdr);
        transition parse_tcp;
    }
    state parse_tcp {
        pkt.extract(hdr.tcp_hdr);
        transition parse_ingress;
    }
    state parse_ingress {
        transition accept;
    }
}

control ingress(inout Headers h, inout Meta m, inout standard_metadata_t sm) {
    action drop() {
        mark_to_drop(sm);
        exit;
    }
    action Bqhfm(bit<8> XHnC) {
        sm.egress_spec = 8517;
        h.tcp_hdr.ackNo = sm.packet_length;
        h.ipv4_hdr.version = h.ipv4_hdr.ihl;
    }
    action SdYHr(bit<64> OmLw) {
        h.ipv4_hdr.version = h.ipv4_hdr.ihl;
        sm.priority = sm.priority - (sm.priority - h.ipv4_hdr.flags + 6146);
    }
    action QHmoE(bit<16> HlKv) {
        h.tcp_hdr.dataOffset = h.tcp_hdr.res;
        sm.priority = h.ipv4_hdr.flags;
        h.tcp_hdr.dataOffset = h.ipv4_hdr.ihl - h.tcp_hdr.res;
        sm.enq_qdepth = sm.enq_qdepth;
        h.ipv4_hdr.flags = sm.priority;
        sm.priority = h.ipv4_hdr.flags;
    }
    action aNdne(bit<64> HxLX) {
        h.ipv4_hdr.flags = h.ipv4_hdr.flags - h.ipv4_hdr.flags + 9841;
        h.ipv4_hdr.fragOffset = h.ipv4_hdr.fragOffset;
        h.ipv4_hdr.diffserv = h.tcp_hdr.flags;
        h.eth_hdr.src_addr = 4365;
    }
    action MurzO(bit<16> hWIn, bit<32> Yine) {
        h.ipv4_hdr.protocol = h.ipv4_hdr.ttl;
        h.ipv4_hdr.flags = 3w5 + sm.priority + 3w7 - h.ipv4_hdr.flags + sm.priority;
        h.ipv4_hdr.protocol = h.ipv4_hdr.protocol;
        h.ipv4_hdr.ttl = h.ipv4_hdr.protocol;
        sm.egress_rid = 9613;
    }
    action pYftf(bit<64> gykK, bit<4> uuXP, bit<8> SYhS) {
        h.eth_hdr.src_addr = h.eth_hdr.dst_addr;
        sm.priority = sm.priority;
        h.tcp_hdr.dstPort = h.tcp_hdr.dstPort;
        sm.egress_global_timestamp = h.eth_hdr.src_addr;
    }
    action qylHB(bit<32> atXk, bit<16> hVoI, bit<8> pUkJ) {
        h.ipv4_hdr.srcAddr = 5492;
        h.ipv4_hdr.ttl = h.ipv4_hdr.diffserv;
        h.eth_hdr.src_addr = sm.ingress_global_timestamp + sm.egress_global_timestamp;
        sm.enq_qdepth = sm.deq_qdepth + sm.enq_qdepth - 8267;
        h.ipv4_hdr.ihl = h.tcp_hdr.res + h.ipv4_hdr.version + h.ipv4_hdr.ihl;
        sm.packet_length = h.tcp_hdr.ackNo - (atXk - h.tcp_hdr.ackNo);
    }
    action ALQcc(bit<128> rWBl, bit<64> JWfD) {
        h.eth_hdr.src_addr = h.eth_hdr.dst_addr;
        h.eth_hdr.dst_addr = sm.ingress_global_timestamp;
    }
    action MPfvS(bit<128> FiPp, bit<8> dTBA) {
        h.ipv4_hdr.fragOffset = h.ipv4_hdr.fragOffset + (h.ipv4_hdr.fragOffset + h.ipv4_hdr.fragOffset);
        sm.deq_qdepth = sm.enq_qdepth;
        h.tcp_hdr.dstPort = h.tcp_hdr.checksum + h.tcp_hdr.window;
        h.tcp_hdr.res = 9403;
    }
    action dLdqu() {
        sm.enq_qdepth = 6245;
        h.ipv4_hdr.flags = sm.priority - (h.ipv4_hdr.flags - (sm.priority + h.ipv4_hdr.flags + h.ipv4_hdr.flags));
        sm.ingress_port = sm.egress_port;
        sm.enq_timestamp = sm.enq_timestamp;
        sm.enq_qdepth = sm.enq_qdepth;
        sm.egress_spec = sm.egress_spec;
    }
    action mWvgY(bit<128> URXc, bit<8> gyCQ, bit<8> UdqD) {
        h.ipv4_hdr.fragOffset = h.ipv4_hdr.fragOffset;
        h.ipv4_hdr.fragOffset = h.ipv4_hdr.fragOffset - (13w7768 + h.ipv4_hdr.fragOffset - 9115) + h.ipv4_hdr.fragOffset;
        h.tcp_hdr.flags = h.tcp_hdr.flags;
    }
    action jJeAx(bit<32> qagg, bit<32> MaJX, bit<128> luWg) {
        h.tcp_hdr.ackNo = qagg;
        sm.egress_spec = sm.egress_spec - (sm.egress_spec + (9w496 + sm.egress_port)) - sm.ingress_port;
    }
    action hPwLn(bit<8> BWCd) {
        h.ipv4_hdr.ttl = h.ipv4_hdr.protocol;
        sm.priority = h.ipv4_hdr.flags;
    }
    action UnpLf() {
        h.eth_hdr.src_addr = sm.ingress_global_timestamp + 48w8092 - h.eth_hdr.dst_addr + sm.ingress_global_timestamp - 48w6705;
        sm.egress_global_timestamp = h.eth_hdr.src_addr + (sm.egress_global_timestamp - 4853);
        sm.egress_global_timestamp = h.eth_hdr.src_addr;
        sm.ingress_global_timestamp = h.eth_hdr.src_addr + sm.ingress_global_timestamp - (7064 + (sm.egress_global_timestamp - 8951));
        sm.egress_global_timestamp = h.eth_hdr.dst_addr;
        h.eth_hdr.eth_type = h.eth_hdr.eth_type;
    }
    action exLhe(bit<128> yrTz, bit<128> MGxl, bit<64> VnLe) {
        h.tcp_hdr.flags = h.tcp_hdr.flags;
        h.ipv4_hdr.flags = sm.priority - sm.priority + 3089;
        h.ipv4_hdr.ihl = h.ipv4_hdr.version;
    }
    action ZOkHw() {
        h.ipv4_hdr.totalLen = h.tcp_hdr.dstPort;
        sm.egress_port = sm.ingress_port + 5767;
        h.ipv4_hdr.fragOffset = 6016;
        h.eth_hdr.src_addr = sm.ingress_global_timestamp;
        h.tcp_hdr.dataOffset = h.ipv4_hdr.version - (h.tcp_hdr.res - (h.ipv4_hdr.ihl + h.ipv4_hdr.ihl)) - h.ipv4_hdr.version;
        h.tcp_hdr.flags = h.ipv4_hdr.ttl + h.ipv4_hdr.diffserv - 8w51 + h.ipv4_hdr.diffserv - h.tcp_hdr.flags;
    }
    action cPUmo(bit<128> ILPP) {
        h.ipv4_hdr.diffserv = h.ipv4_hdr.protocol;
        sm.ingress_global_timestamp = h.eth_hdr.src_addr;
        h.ipv4_hdr.fragOffset = 7111 - h.ipv4_hdr.fragOffset;
        h.ipv4_hdr.fragOffset = h.ipv4_hdr.fragOffset;
    }
    action bsFty(bit<64> rzKe, bit<128> bgjy, bit<128> HZbK) {
        h.ipv4_hdr.ttl = h.ipv4_hdr.diffserv;
        h.ipv4_hdr.fragOffset = h.ipv4_hdr.fragOffset;
        sm.packet_length = h.tcp_hdr.seqNo + h.ipv4_hdr.dstAddr;
        h.ipv4_hdr.fragOffset = h.ipv4_hdr.fragOffset - h.ipv4_hdr.fragOffset - h.ipv4_hdr.fragOffset;
        sm.deq_qdepth = sm.deq_qdepth + (3605 + (19w6551 - 19w8123 - sm.enq_qdepth));
        sm.enq_qdepth = sm.enq_qdepth + sm.deq_qdepth;
    }
    action kzoXF(bit<16> SYYe) {
        sm.enq_qdepth = sm.deq_qdepth;
        h.tcp_hdr.ackNo = 8506;
    }
    action WfMUt() {
        h.tcp_hdr.seqNo = 4059 - sm.enq_timestamp;
        h.tcp_hdr.dataOffset = h.tcp_hdr.res;
        h.ipv4_hdr.version = 1455 + (4w10 + 4w6 + 4w5) - 4w6;
        h.ipv4_hdr.fragOffset = h.ipv4_hdr.fragOffset;
    }
    action nPqyV() {
        h.ipv4_hdr.ihl = h.tcp_hdr.res;
        h.ipv4_hdr.ihl = h.tcp_hdr.res;
        sm.priority = sm.priority + (h.ipv4_hdr.flags - (sm.priority + 3w1 + h.ipv4_hdr.flags));
        h.ipv4_hdr.diffserv = h.ipv4_hdr.diffserv + (h.ipv4_hdr.diffserv + 8w214) - h.ipv4_hdr.ttl - h.ipv4_hdr.ttl;
        h.tcp_hdr.checksum = h.tcp_hdr.srcPort;
    }
    action TDyLg(bit<16> ieiv) {
        h.ipv4_hdr.dstAddr = h.ipv4_hdr.dstAddr;
        sm.ingress_port = sm.egress_port + (460 + (6688 + 9w486)) + 9w91;
        h.tcp_hdr.flags = 8w122 - 8w64 - 8w30 + 8w179 - h.ipv4_hdr.diffserv;
        h.ipv4_hdr.flags = 4766;
        sm.priority = sm.priority + (h.ipv4_hdr.flags - (3w3 + 3w6 + 3w2));
        sm.egress_global_timestamp = sm.ingress_global_timestamp + h.eth_hdr.dst_addr + 3701;
    }
    action jhEJx(bit<4> XnHf, bit<32> FovU, bit<16> cHay) {
        h.tcp_hdr.urgentPtr = 8923 - (h.tcp_hdr.checksum + (h.ipv4_hdr.identification - (h.tcp_hdr.urgentPtr - h.tcp_hdr.srcPort)));
        h.tcp_hdr.res = XnHf + h.ipv4_hdr.ihl;
        sm.enq_timestamp = sm.packet_length + (32w2264 + h.tcp_hdr.seqNo + 32w5221 + FovU);
    }
    table TExyZI {
        key = {
            h.ipv4_hdr.fragOffset: ternary @name("ozwuvm") ;
            sm.enq_qdepth        : lpm @name("WXMTty") ;
            sm.priority          : range @name("iKOYpn") ;
        }
        actions = {
            drop();
            dLdqu();
            nPqyV();
            hPwLn();
        }
    }
    table UijWYj {
        key = {
            sm.enq_qdepth        : exact @name("kvEnwc") ;
            h.ipv4_hdr.fragOffset: ternary @name("rEdcYr") ;
            sm.enq_qdepth        : lpm @name("aXICAG") ;
            sm.enq_timestamp     : range @name("ohfFfr") ;
        }
        actions = {
            MurzO();
            drop();
            WfMUt();
        }
    }
    table TOEefg {
        key = {
            h.ipv4_hdr.fragOffset: exact @name("zdgbdF") ;
            h.ipv4_hdr.version   : exact @name("USvKau") ;
            h.eth_hdr.src_addr   : lpm @name("EexcJD") ;
        }
        actions = {
            ZOkHw();
            kzoXF();
        }
    }
    table WEWvAq {
        key = {
            h.tcp_hdr.dataOffset: exact @name("ZgkoxG") ;
            sm.priority         : range @name("DPIuTI") ;
        }
        actions = {
            drop();
            kzoXF();
            qylHB();
        }
    }
    table PLLAKs {
        key = {
            sm.egress_global_timestamp: exact @name("qvohEn") ;
            h.eth_hdr.src_addr        : ternary @name("FXOVKp") ;
        }
        actions = {
            drop();
        }
    }
    table DplzWp {
        key = {
            sm.egress_spec: exact @name("QYZnOO") ;
            h.ipv4_hdr.ttl: exact @name("PTCMYc") ;
            sm.priority   : ternary @name("tppKRp") ;
        }
        actions = {
        }
    }
    table ZkiQmC {
        key = {
            sm.deq_qdepth        : exact @name("ouskBg") ;
            h.ipv4_hdr.fragOffset: lpm @name("XzXJxz") ;
        }
        actions = {
            dLdqu();
            UnpLf();
            QHmoE();
            TDyLg();
        }
    }
    table RZYgri {
        key = {
            sm.ingress_global_timestamp: exact @name("ajQqgO") ;
            h.ipv4_hdr.fragOffset      : lpm @name("wfHaVQ") ;
        }
        actions = {
            drop();
            ZOkHw();
            hPwLn();
        }
    }
    table dlkSGa {
        key = {
            h.ipv4_hdr.diffserv       : exact @name("gOcudu") ;
            h.tcp_hdr.dataOffset      : exact @name("VrvKie") ;
            h.eth_hdr.dst_addr        : exact @name("RKGsVp") ;
            sm.instance_type          : lpm @name("VVsGtl") ;
            sm.egress_global_timestamp: range @name("hzbvdb") ;
        }
        actions = {
            hPwLn();
        }
    }
    table kKhSmY {
        key = {
            sm.deq_qdepth        : exact @name("kGOUgm") ;
            h.ipv4_hdr.fragOffset: exact @name("CRkHjr") ;
            sm.priority          : ternary @name("VRCieC") ;
            h.ipv4_hdr.fragOffset: lpm @name("WoYsJE") ;
        }
        actions = {
            dLdqu();
            kzoXF();
            drop();
        }
    }
    table TLLgQs {
        key = {
            h.ipv4_hdr.fragOffset: exact @name("BdUdJB") ;
            h.eth_hdr.eth_type   : exact @name("eHnBZp") ;
            h.tcp_hdr.seqNo      : exact @name("rhOHSY") ;
            h.ipv4_hdr.fragOffset: lpm @name("ffRfKF") ;
            h.ipv4_hdr.fragOffset: range @name("jrfsxQ") ;
        }
        actions = {
        }
    }
    table NLWjTJ {
        key = {
            h.tcp_hdr.flags   : exact @name("vjAUBK") ;
            h.ipv4_hdr.srcAddr: exact @name("fMADLX") ;
            sm.egress_spec    : range @name("KzhETv") ;
        }
        actions = {
            Bqhfm();
            UnpLf();
            hPwLn();
        }
    }
    table iiRdsU {
        key = {
            sm.deq_qdepth        : exact @name("QaAudw") ;
            sm.egress_port       : exact @name("xlspzI") ;
            h.ipv4_hdr.fragOffset: lpm @name("amXVWV") ;
        }
        actions = {
            drop();
            dLdqu();
            Bqhfm();
        }
    }
    table AxQQaq {
        key = {
            h.ipv4_hdr.fragOffset: lpm @name("jXNoOS") ;
        }
        actions = {
            drop();
            jhEJx();
            WfMUt();
        }
    }
    table ckKyEc {
        key = {
            sm.enq_timestamp : exact @name("yUlmQE") ;
            sm.egress_port   : exact @name("IJauzd") ;
            h.tcp_hdr.dstPort: exact @name("GTRpnZ") ;
            sm.ingress_port  : range @name("UHHdRE") ;
        }
        actions = {
            drop();
            QHmoE();
            qylHB();
        }
    }
    table jLhfaZ {
        key = {
            h.ipv4_hdr.totalLen: lpm @name("ZujsYW") ;
        }
        actions = {
            drop();
            dLdqu();
            UnpLf();
            hPwLn();
            ZOkHw();
            jhEJx();
        }
    }
    table KZvNzk {
        key = {
            h.ipv4_hdr.fragOffset: exact @name("YDXKng") ;
            h.ipv4_hdr.fragOffset: exact @name("wHkogI") ;
            sm.enq_qdepth        : exact @name("gfVJiB") ;
            h.ipv4_hdr.flags     : range @name("dnKatr") ;
        }
        actions = {
            drop();
            TDyLg();
        }
    }
    table roQIEJ {
        key = {
            h.tcp_hdr.dstPort : exact @name("EIavjN") ;
            h.eth_hdr.dst_addr: ternary @name("adbrpS") ;
            sm.deq_qdepth     : lpm @name("JTWked") ;
        }
        actions = {
            jhEJx();
            UnpLf();
        }
    }
    table tcrFTv {
        key = {
            h.ipv4_hdr.srcAddr        : exact @name("JACpxo") ;
            h.ipv4_hdr.fragOffset     : exact @name("ZohmSs") ;
            sm.egress_port            : exact @name("tWwbmi") ;
            sm.egress_global_timestamp: ternary @name("aVaUZp") ;
            h.ipv4_hdr.ttl            : lpm @name("pljBTn") ;
            sm.egress_global_timestamp: range @name("StITCo") ;
        }
        actions = {
            Bqhfm();
        }
    }
    table OnLnRM {
        key = {
        }
        actions = {
            hPwLn();
            qylHB();
            nPqyV();
        }
    }
    table eLVnLq {
        key = {
            h.tcp_hdr.flags      : exact @name("OlDYqM") ;
            sm.egress_spec       : exact @name("JBcMTx") ;
            h.ipv4_hdr.fragOffset: exact @name("Fwiguk") ;
            h.eth_hdr.src_addr   : range @name("dzxGNg") ;
        }
        actions = {
            drop();
            MurzO();
        }
    }
    table iGJVZe {
        key = {
            sm.deq_qdepth       : exact @name("FfcCAA") ;
            h.eth_hdr.src_addr  : exact @name("leFQzt") ;
            h.tcp_hdr.seqNo     : exact @name("oeEWiy") ;
            h.tcp_hdr.dataOffset: range @name("pHpovv") ;
        }
        actions = {
            drop();
            QHmoE();
            jhEJx();
            Bqhfm();
        }
    }
    table lAJhKF {
        key = {
            h.ipv4_hdr.flags    : exact @name("AExSdk") ;
            h.tcp_hdr.dataOffset: exact @name("EDpWjr") ;
            h.tcp_hdr.res       : exact @name("koiHPP") ;
            sm.deq_qdepth       : ternary @name("bJDsyC") ;
            sm.priority         : range @name("pYyGLy") ;
        }
        actions = {
            UnpLf();
            WfMUt();
            TDyLg();
            Bqhfm();
            MurzO();
        }
    }
    table QCkLkc {
        key = {
            h.tcp_hdr.flags    : exact @name("JRRNok") ;
            sm.priority        : exact @name("vkAVQv") ;
            h.ipv4_hdr.protocol: exact @name("WCWLIg") ;
            h.tcp_hdr.dstPort  : ternary @name("mhyixK") ;
        }
        actions = {
            drop();
            kzoXF();
            MurzO();
        }
    }
    table VGviyJ {
        key = {
            sm.ingress_port    : ternary @name("AGEJgo") ;
            h.tcp_hdr.flags    : lpm @name("lkMCJy") ;
            h.ipv4_hdr.diffserv: range @name("vzPyrt") ;
        }
        actions = {
            drop();
            MurzO();
            ZOkHw();
            kzoXF();
            UnpLf();
        }
    }
    table gXqjky {
        key = {
            h.ipv4_hdr.totalLen: exact @name("Vqeoen") ;
            sm.priority        : exact @name("DOfSSw") ;
            h.ipv4_hdr.version : exact @name("ZNinUN") ;
            h.ipv4_hdr.flags   : lpm @name("PpCBKO") ;
        }
        actions = {
            kzoXF();
            WfMUt();
            hPwLn();
        }
    }
    table ehNFOI {
        key = {
            h.ipv4_hdr.totalLen: lpm @name("lZXowr") ;
        }
        actions = {
            drop();
            qylHB();
            jhEJx();
            kzoXF();
            QHmoE();
            dLdqu();
            UnpLf();
        }
    }
    table wmSiQH {
        key = {
            h.ipv4_hdr.fragOffset: exact @name("fXmEWH") ;
            sm.egress_port       : exact @name("JJVqvv") ;
            h.tcp_hdr.res        : exact @name("BXLyyO") ;
            sm.priority          : lpm @name("zlWmjF") ;
        }
        actions = {
            drop();
        }
    }
    table tBoMfz {
        key = {
            h.eth_hdr.dst_addr: exact @name("MEBINt") ;
            h.ipv4_hdr.ttl    : exact @name("RXkCpO") ;
            h.ipv4_hdr.version: exact @name("KbiKQT") ;
            sm.instance_type  : range @name("UIkziD") ;
        }
        actions = {
            drop();
            Bqhfm();
            dLdqu();
            QHmoE();
            nPqyV();
        }
    }
    table SZjYJl {
        key = {
            h.ipv4_hdr.flags: exact @name("BShSkU") ;
            h.ipv4_hdr.ttl  : exact @name("tnVaNP") ;
            h.tcp_hdr.flags : ternary @name("FJsloz") ;
        }
        actions = {
            QHmoE();
            TDyLg();
            WfMUt();
            Bqhfm();
        }
    }
    table RhTFSA {
        key = {
            h.ipv4_hdr.srcAddr       : exact @name("GadZrL") ;
            h.ipv4_hdr.identification: ternary @name("YJSdIg") ;
            h.ipv4_hdr.totalLen      : range @name("blPJqm") ;
        }
        actions = {
            nPqyV();
            UnpLf();
            drop();
        }
    }
    apply {
        ZkiQmC.apply();
        lAJhKF.apply();
        RZYgri.apply();
        SZjYJl.apply();
        TExyZI.apply();
        if (h.tcp_hdr.isValid()) {
            QCkLkc.apply();
            TOEefg.apply();
            tcrFTv.apply();
            gXqjky.apply();
            AxQQaq.apply();
            OnLnRM.apply();
        } else {
            wmSiQH.apply();
            DplzWp.apply();
            ehNFOI.apply();
            ckKyEc.apply();
            if (h.ipv4_hdr.fragOffset + 8391 != 6345) {
                roQIEJ.apply();
                RhTFSA.apply();
                NLWjTJ.apply();
            } else {
                KZvNzk.apply();
                jLhfaZ.apply();
                iGJVZe.apply();
                UijWYj.apply();
                tBoMfz.apply();
            }
            VGviyJ.apply();
        }
        dlkSGa.apply();
        TLLgQs.apply();
        PLLAKs.apply();
        eLVnLq.apply();
        WEWvAq.apply();
        kKhSmY.apply();
        iiRdsU.apply();
    }
}

control vrfy(inout Headers h, inout Meta m) {
    apply {
    }
}

control update(inout Headers h, inout Meta m) {
    apply {
    }
}

control egress(inout Headers h, inout Meta m, inout standard_metadata_t sm) {
    apply {
    }
}

control deparser(packet_out pkt, in Headers h) {
    apply {
        pkt.emit(h);
    }
}

V1Switch(p(), vrfy(), ingress(), egress(), update(), deparser()) main;
