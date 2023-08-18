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
    action GlNdK(bit<8> YxND, bit<16> OpMZ) {
        sm.egress_spec = sm.egress_port;
        h.ipv4_hdr.hdrChecksum = 4943;
        sm.egress_spec = 2684 + sm.egress_port + (9w28 - 9w127 + 9w83);
        sm.egress_global_timestamp = h.eth_hdr.src_addr;
    }
    action sjECE(bit<128> VytR, bit<4> YuCe) {
        sm.deq_qdepth = sm.deq_qdepth + (sm.deq_qdepth + (sm.deq_qdepth - sm.deq_qdepth));
        h.ipv4_hdr.flags = h.ipv4_hdr.flags;
        h.ipv4_hdr.fragOffset = h.ipv4_hdr.fragOffset + (h.ipv4_hdr.fragOffset + 13w1235) - 13w5825 - h.ipv4_hdr.fragOffset;
        h.tcp_hdr.ackNo = h.tcp_hdr.seqNo;
        h.tcp_hdr.urgentPtr = h.tcp_hdr.dstPort;
        h.ipv4_hdr.fragOffset = h.ipv4_hdr.fragOffset + (13w1346 - h.ipv4_hdr.fragOffset) + h.ipv4_hdr.fragOffset - 13w4245;
    }
    action vRNfx(bit<64> tETF, bit<128> rfiU, bit<8> gRAa) {
        h.eth_hdr.dst_addr = sm.egress_global_timestamp + (sm.egress_global_timestamp + (48w461 - 48w5928)) + 48w5541;
        h.tcp_hdr.res = h.tcp_hdr.res;
        sm.egress_spec = sm.egress_port;
        sm.egress_spec = sm.egress_port + sm.ingress_port + sm.ingress_port;
        h.ipv4_hdr.srcAddr = h.ipv4_hdr.srcAddr;
        h.ipv4_hdr.flags = sm.priority + (8693 + sm.priority);
    }
    action vQjzJ(bit<128> zAys) {
        h.tcp_hdr.dataOffset = 7425 - 9365 - (h.tcp_hdr.res - (6594 + 4w11));
        h.ipv4_hdr.protocol = h.tcp_hdr.flags - (8w90 + h.ipv4_hdr.diffserv + h.ipv4_hdr.protocol + 3110);
        h.tcp_hdr.dataOffset = h.ipv4_hdr.version;
        h.tcp_hdr.urgentPtr = h.tcp_hdr.dstPort + h.tcp_hdr.urgentPtr - 6808;
        h.ipv4_hdr.flags = sm.priority;
        h.tcp_hdr.dstPort = h.tcp_hdr.checksum;
    }
    action vzGPF(bit<4> wmGS) {
        sm.deq_qdepth = sm.enq_qdepth - (sm.deq_qdepth + sm.deq_qdepth);
        h.ipv4_hdr.fragOffset = h.ipv4_hdr.fragOffset;
        h.eth_hdr.eth_type = 9584 + sm.egress_rid - (h.ipv4_hdr.hdrChecksum - h.ipv4_hdr.hdrChecksum);
        sm.deq_qdepth = sm.enq_qdepth;
    }
    action EYUzI(bit<8> pCim) {
        h.eth_hdr.src_addr = sm.egress_global_timestamp - h.eth_hdr.dst_addr - 48w7997 - 2635 - 1944;
        h.tcp_hdr.res = h.tcp_hdr.dataOffset - (h.tcp_hdr.dataOffset + (4w12 - 4w11) - 4w9);
        sm.deq_qdepth = sm.enq_qdepth;
        h.tcp_hdr.res = h.ipv4_hdr.version + h.ipv4_hdr.version + 49;
        sm.egress_port = sm.ingress_port - (sm.egress_spec - sm.ingress_port);
    }
    action GNvBN() {
        sm.deq_qdepth = sm.deq_qdepth;
        h.ipv4_hdr.fragOffset = h.ipv4_hdr.fragOffset;
        h.tcp_hdr.res = h.tcp_hdr.res + (h.ipv4_hdr.version - (h.tcp_hdr.dataOffset - h.tcp_hdr.dataOffset));
        h.ipv4_hdr.srcAddr = sm.packet_length;
        sm.egress_port = 9w39 + 9w153 + sm.egress_spec - 9w208 - sm.egress_spec;
    }
    action wPAxY() {
        h.ipv4_hdr.flags = h.ipv4_hdr.flags;
        h.tcp_hdr.seqNo = 8550;
        h.tcp_hdr.dstPort = sm.egress_rid;
    }
    action EoHOB(bit<8> sKZg, bit<64> bwKL) {
        sm.deq_qdepth = sm.enq_qdepth + sm.enq_qdepth + sm.enq_qdepth;
        h.ipv4_hdr.flags = 4764 - sm.priority;
    }
    action fbaCz(bit<128> pUuZ, bit<4> Vvmh) {
        sm.ingress_port = sm.egress_port + 7056;
        sm.deq_qdepth = sm.enq_qdepth;
        h.tcp_hdr.dstPort = h.tcp_hdr.checksum + (h.eth_hdr.eth_type + (16w9198 + 16w739) + 16w2892);
        sm.priority = h.ipv4_hdr.flags;
    }
    action IHFRe(bit<4> TIMf) {
        sm.egress_spec = sm.ingress_port;
        h.ipv4_hdr.version = h.ipv4_hdr.version + (997 - TIMf - 4w15) - h.tcp_hdr.res;
        h.ipv4_hdr.fragOffset = 7459;
        h.tcp_hdr.res = h.tcp_hdr.dataOffset + (TIMf + (4w11 - h.ipv4_hdr.ihl + 4w11));
        sm.deq_qdepth = sm.deq_qdepth;
        sm.instance_type = h.ipv4_hdr.srcAddr;
    }
    action kVpMs(bit<8> ZKEN, bit<128> pgRP) {
        sm.ingress_port = sm.egress_port;
        sm.priority = 4406 + h.ipv4_hdr.flags + (1255 - sm.priority) - 3w6;
        sm.enq_qdepth = sm.deq_qdepth;
        sm.enq_qdepth = sm.deq_qdepth;
        h.ipv4_hdr.diffserv = h.ipv4_hdr.protocol + h.ipv4_hdr.protocol + 286;
        sm.ingress_port = sm.ingress_port;
    }
    action VXJlJ(bit<16> wFRO, bit<16> mvRD) {
        sm.priority = sm.priority;
        h.ipv4_hdr.fragOffset = h.ipv4_hdr.fragOffset;
        sm.priority = sm.priority + h.ipv4_hdr.flags - h.ipv4_hdr.flags;
        h.ipv4_hdr.fragOffset = h.ipv4_hdr.fragOffset - 13w3397 + h.ipv4_hdr.fragOffset - h.ipv4_hdr.fragOffset + h.ipv4_hdr.fragOffset;
    }
    action tPmwQ() {
        h.eth_hdr.src_addr = h.eth_hdr.dst_addr;
        sm.enq_timestamp = sm.enq_timestamp;
        h.tcp_hdr.res = 8790 - h.ipv4_hdr.ihl + h.ipv4_hdr.version;
        h.tcp_hdr.seqNo = 3605 + h.ipv4_hdr.srcAddr;
        h.ipv4_hdr.flags = sm.priority;
    }
    action Rzheg() {
        sm.ingress_port = sm.egress_port - (sm.egress_spec - (sm.ingress_port - sm.ingress_port - sm.ingress_port));
        h.ipv4_hdr.protocol = h.ipv4_hdr.protocol;
        sm.enq_qdepth = sm.enq_qdepth;
        h.ipv4_hdr.version = h.ipv4_hdr.ihl;
    }
    action wXPxr(bit<16> TrGH, bit<16> nRYj) {
        sm.deq_qdepth = sm.deq_qdepth;
        h.tcp_hdr.flags = h.tcp_hdr.flags - (h.tcp_hdr.flags - h.ipv4_hdr.diffserv) - h.ipv4_hdr.protocol;
        h.tcp_hdr.urgentPtr = h.ipv4_hdr.hdrChecksum;
        h.ipv4_hdr.ihl = h.tcp_hdr.res;
    }
    action DkiNI(bit<32> CBpP) {
        h.ipv4_hdr.diffserv = h.tcp_hdr.flags;
        sm.egress_spec = 6696;
        sm.ingress_port = sm.ingress_port;
        h.tcp_hdr.res = h.tcp_hdr.dataOffset;
    }
    action siavW(bit<128> cKjt, bit<8> vCev, bit<16> UxnX) {
        h.ipv4_hdr.diffserv = h.ipv4_hdr.ttl;
        sm.enq_qdepth = sm.deq_qdepth;
        h.ipv4_hdr.totalLen = h.tcp_hdr.srcPort;
        h.tcp_hdr.flags = h.ipv4_hdr.protocol - h.tcp_hdr.flags;
        h.ipv4_hdr.flags = sm.priority;
    }
    action FNfyw(bit<8> bCGh, bit<16> KFfb) {
        sm.deq_qdepth = sm.deq_qdepth - (19w6742 + 5891) - 19w3020 - 9075;
        h.tcp_hdr.res = h.ipv4_hdr.ihl + h.tcp_hdr.dataOffset;
        sm.deq_qdepth = 9807;
        h.ipv4_hdr.ttl = h.ipv4_hdr.protocol - 3501;
        sm.deq_qdepth = 25;
    }
    action OhEmF(bit<64> gRko, bit<64> cJAv) {
        h.tcp_hdr.res = h.tcp_hdr.dataOffset - (6827 - h.tcp_hdr.dataOffset);
        h.ipv4_hdr.fragOffset = 5988;
    }
    action lalki(bit<128> vBdG) {
        h.ipv4_hdr.fragOffset = h.ipv4_hdr.fragOffset - h.ipv4_hdr.fragOffset;
        sm.ingress_port = sm.ingress_port;
    }
    action Gdkyx(bit<8> uXRj) {
        sm.enq_qdepth = sm.deq_qdepth;
        sm.ingress_port = sm.egress_spec;
        h.tcp_hdr.seqNo = h.ipv4_hdr.srcAddr - sm.instance_type;
    }
    action zAMNF() {
        sm.ingress_global_timestamp = 9514 - (48w964 + 48w4341 - 48w5242) + sm.ingress_global_timestamp;
        h.ipv4_hdr.flags = sm.priority - h.ipv4_hdr.flags;
        h.ipv4_hdr.hdrChecksum = h.ipv4_hdr.identification - (h.tcp_hdr.srcPort - h.ipv4_hdr.identification);
        h.ipv4_hdr.flags = h.ipv4_hdr.flags;
    }
    action nxuOT(bit<128> kzxo, bit<16> ipWH) {
        sm.priority = sm.priority - sm.priority + (h.ipv4_hdr.flags - (8894 + 3w6));
        sm.deq_qdepth = sm.deq_qdepth + sm.enq_qdepth + sm.enq_qdepth;
        sm.egress_port = 6848;
    }
    action IKerV(bit<128> grNs, bit<32> wReo) {
        h.ipv4_hdr.identification = h.tcp_hdr.dstPort;
        h.eth_hdr.src_addr = h.eth_hdr.dst_addr + sm.ingress_global_timestamp - (3211 - 9084 - 48w3887);
        h.ipv4_hdr.dstAddr = 5458;
    }
    action Srdgv() {
        sm.ingress_global_timestamp = 1071;
        sm.priority = 6732;
        h.eth_hdr.src_addr = sm.egress_global_timestamp + (h.eth_hdr.src_addr - (8110 - h.eth_hdr.dst_addr));
        h.tcp_hdr.flags = h.ipv4_hdr.diffserv;
    }
    action iboJZ(bit<32> ATrX) {
        h.ipv4_hdr.ihl = h.tcp_hdr.dataOffset - h.tcp_hdr.dataOffset;
        h.ipv4_hdr.ihl = h.ipv4_hdr.ihl - (h.tcp_hdr.dataOffset - h.tcp_hdr.dataOffset);
    }
    action Ijngi(bit<4> oONr, bit<8> OZtF) {
        sm.egress_port = sm.ingress_port - sm.ingress_port;
        sm.packet_length = sm.instance_type;
        sm.ingress_port = sm.ingress_port - 9143 - (sm.egress_spec + 2596 + 9w91);
        sm.priority = sm.priority;
    }
    action mCNJR() {
        h.tcp_hdr.res = h.ipv4_hdr.version;
        sm.priority = sm.priority + sm.priority + sm.priority + 3190 - h.ipv4_hdr.flags;
        h.ipv4_hdr.fragOffset = h.ipv4_hdr.fragOffset;
    }
    table VkjcDg {
        key = {
            h.ipv4_hdr.fragOffset: exact @name("ONZJLj") ;
            h.ipv4_hdr.flags     : ternary @name("tyulJo") ;
            sm.deq_qdepth        : lpm @name("KwCnbu") ;
            h.tcp_hdr.dstPort    : range @name("DVOVOV") ;
        }
        actions = {
            drop();
            EYUzI();
            iboJZ();
            vzGPF();
            zAMNF();
        }
    }
    table mkASVJ {
        key = {
            sm.egress_spec      : ternary @name("RnahxR") ;
            h.tcp_hdr.dataOffset: lpm @name("pzVCOb") ;
        }
        actions = {
        }
    }
    table eXhDKe {
        key = {
            h.tcp_hdr.urgentPtr: range @name("nsjdmx") ;
        }
        actions = {
            drop();
            vzGPF();
            FNfyw();
        }
    }
    table XlZozk {
        key = {
            h.ipv4_hdr.fragOffset: exact @name("IZRBNj") ;
            h.ipv4_hdr.fragOffset: exact @name("tZWbZZ") ;
            sm.deq_qdepth        : exact @name("DBxqIv") ;
        }
        actions = {
            GlNdK();
            mCNJR();
            VXJlJ();
        }
    }
    table cckyhi {
        key = {
            sm.packet_length: exact @name("xzOjaa") ;
            sm.enq_timestamp: exact @name("OKMAnW") ;
            h.tcp_hdr.res   : exact @name("LNjAjB") ;
            sm.enq_qdepth   : ternary @name("PVuxJe") ;
        }
        actions = {
            Ijngi();
            wXPxr();
            FNfyw();
            drop();
            GNvBN();
        }
    }
    table tggGPl {
        key = {
            sm.egress_rid      : exact @name("xNwosk") ;
            h.tcp_hdr.checksum : exact @name("tlPnxy") ;
            h.tcp_hdr.ackNo    : exact @name("LUejwc") ;
            sm.instance_type   : ternary @name("oLfzvY") ;
            h.ipv4_hdr.protocol: lpm @name("JCeyUB") ;
        }
        actions = {
            Rzheg();
            VXJlJ();
        }
    }
    table VjOQsY {
        key = {
            sm.deq_qdepth: range @name("jnqoFq") ;
        }
        actions = {
            drop();
            Srdgv();
            Rzheg();
            EYUzI();
        }
    }
    table WcStbu {
        key = {
            h.ipv4_hdr.protocol: ternary @name("LQUuFt") ;
            sm.deq_qdepth      : lpm @name("aUoogj") ;
        }
        actions = {
            drop();
            zAMNF();
            wXPxr();
            iboJZ();
            DkiNI();
            Ijngi();
        }
    }
    table NDvTfe {
        key = {
            sm.priority: exact @name("JlExju") ;
        }
        actions = {
            wXPxr();
            FNfyw();
        }
    }
    table xcsuAl {
        key = {
            h.ipv4_hdr.version : exact @name("MxQBgd") ;
            sm.enq_qdepth      : exact @name("iSnwgL") ;
            h.ipv4_hdr.totalLen: lpm @name("aiUXyK") ;
            h.tcp_hdr.checksum : range @name("YFopfD") ;
        }
        actions = {
            drop();
            iboJZ();
            EYUzI();
        }
    }
    table KrvjIo {
        key = {
            h.ipv4_hdr.flags: lpm @name("yKQTtm") ;
        }
        actions = {
            drop();
            IHFRe();
        }
    }
    table yPSqrO {
        key = {
            h.tcp_hdr.dataOffset: lpm @name("VOwRni") ;
        }
        actions = {
            drop();
            wXPxr();
            IHFRe();
        }
    }
    table qaoCgL {
        key = {
            sm.enq_qdepth  : exact @name("wpgkTy") ;
            sm.enq_qdepth  : exact @name("FFtZft") ;
            h.tcp_hdr.flags: ternary @name("uHBnDZ") ;
            h.tcp_hdr.res  : range @name("pZlvXS") ;
        }
        actions = {
            EYUzI();
            drop();
        }
    }
    table kUnJuv {
        key = {
            sm.ingress_port    : exact @name("LjlPsh") ;
            h.ipv4_hdr.protocol: exact @name("SiiwIy") ;
            h.ipv4_hdr.diffserv: exact @name("BKmQLF") ;
            h.ipv4_hdr.flags   : ternary @name("wcmFwv") ;
            sm.egress_spec     : lpm @name("cXGXGZ") ;
        }
        actions = {
            Ijngi();
            iboJZ();
            mCNJR();
            Srdgv();
            IHFRe();
        }
    }
    table gvtEft {
        key = {
            h.ipv4_hdr.fragOffset: lpm @name("kAetEJ") ;
        }
        actions = {
            drop();
            wXPxr();
            FNfyw();
            Rzheg();
        }
    }
    table mEQWWE {
        key = {
            h.ipv4_hdr.fragOffset: exact @name("fNEMLs") ;
            sm.egress_port       : exact @name("vMXkKb") ;
            sm.enq_qdepth        : exact @name("hLowqE") ;
        }
        actions = {
            drop();
            wXPxr();
            GlNdK();
            tPmwQ();
        }
    }
    table dmrwJF {
        key = {
            h.ipv4_hdr.flags  : ternary @name("BXLlpU") ;
            h.ipv4_hdr.dstAddr: range @name("wqduRt") ;
        }
        actions = {
            vzGPF();
            zAMNF();
            wXPxr();
        }
    }
    table SaCBvA {
        key = {
            sm.ingress_global_timestamp: exact @name("tVCNKk") ;
            h.ipv4_hdr.fragOffset      : exact @name("rXptDf") ;
            h.ipv4_hdr.fragOffset      : lpm @name("PRJWYd") ;
            h.ipv4_hdr.totalLen        : range @name("BEMTAb") ;
        }
        actions = {
            IHFRe();
        }
    }
    table lDUaYO {
        key = {
            h.tcp_hdr.ackNo: lpm @name("ABQQBM") ;
        }
        actions = {
            IHFRe();
            GNvBN();
            tPmwQ();
        }
    }
    table wUDXUm {
        key = {
            h.tcp_hdr.ackNo    : exact @name("CcyzDp") ;
            h.ipv4_hdr.protocol: exact @name("SvYWYr") ;
            sm.enq_qdepth      : ternary @name("CbmzNg") ;
            sm.ingress_port    : lpm @name("WdFczR") ;
            sm.enq_qdepth      : range @name("ggnEYa") ;
        }
        actions = {
            drop();
            GNvBN();
            Srdgv();
            VXJlJ();
            iboJZ();
        }
    }
    table TsMOPw {
        key = {
            sm.priority: lpm @name("jeWOvn") ;
        }
        actions = {
            drop();
            zAMNF();
            DkiNI();
            tPmwQ();
            GlNdK();
            mCNJR();
        }
    }
    table hZDuZP {
        key = {
            h.eth_hdr.dst_addr: exact @name("KteFXY") ;
            h.eth_hdr.src_addr: exact @name("BNzkjZ") ;
            sm.egress_rid     : exact @name("grEVJY") ;
        }
        actions = {
            drop();
            FNfyw();
            EYUzI();
        }
    }
    table htNExt {
        key = {
            h.ipv4_hdr.ihl       : ternary @name("MBCOSn") ;
            sm.enq_timestamp     : lpm @name("MGBdwv") ;
            h.ipv4_hdr.fragOffset: range @name("VxYBoY") ;
        }
        actions = {
            EYUzI();
            zAMNF();
            tPmwQ();
            Ijngi();
        }
    }
    apply {
        hZDuZP.apply();
        gvtEft.apply();
        wUDXUm.apply();
        mEQWWE.apply();
        eXhDKe.apply();
        yPSqrO.apply();
        NDvTfe.apply();
        VjOQsY.apply();
        WcStbu.apply();
        if (h.ipv4_hdr.isValid()) {
            XlZozk.apply();
            htNExt.apply();
        } else {
            dmrwJF.apply();
            tggGPl.apply();
            if (sm.priority + h.ipv4_hdr.flags - (1346 + h.ipv4_hdr.flags) != 3w1 + 3w0) {
                lDUaYO.apply();
                KrvjIo.apply();
                mkASVJ.apply();
                if (sm.ingress_global_timestamp == h.eth_hdr.src_addr) {
                    VkjcDg.apply();
                    cckyhi.apply();
                    xcsuAl.apply();
                    SaCBvA.apply();
                } else {
                    qaoCgL.apply();
                    kUnJuv.apply();
                }
                TsMOPw.apply();
            } else {
            }
        }
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
