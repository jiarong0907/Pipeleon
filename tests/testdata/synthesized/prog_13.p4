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
    action kPcve() {
        sm.priority = 8436;
        h.ipv4_hdr.fragOffset = h.ipv4_hdr.fragOffset;
    }
    action YuyuL() {
        sm.priority = 1940;
        sm.enq_timestamp = sm.enq_timestamp - (2500 + 32w4474) - 32w2720 + 1808;
    }
    action klCfx(bit<16> XETC, bit<16> QzAO, bit<8> EFmh) {
        sm.ingress_global_timestamp = sm.egress_global_timestamp + (48w6088 + 48w8807) + 48w4935 - sm.egress_global_timestamp;
        h.ipv4_hdr.ihl = h.ipv4_hdr.ihl;
        h.tcp_hdr.dataOffset = h.tcp_hdr.res;
    }
    action uohxC() {
        h.tcp_hdr.res = 2443;
        h.ipv4_hdr.version = 1630;
        h.tcp_hdr.ackNo = 421;
        sm.instance_type = h.tcp_hdr.ackNo;
    }
    action IkBGN(bit<4> fdoQ, bit<16> XeuW) {
        h.tcp_hdr.flags = h.ipv4_hdr.diffserv - (8w64 + 4004 + 8w212) - h.tcp_hdr.flags;
        h.ipv4_hdr.hdrChecksum = 2227;
        sm.egress_global_timestamp = sm.egress_global_timestamp;
        sm.enq_qdepth = sm.deq_qdepth;
        h.tcp_hdr.checksum = h.tcp_hdr.checksum - (h.tcp_hdr.srcPort - h.tcp_hdr.window) + h.ipv4_hdr.identification;
        h.ipv4_hdr.ttl = h.ipv4_hdr.protocol;
    }
    action wnuSJ(bit<8> fuON) {
        sm.egress_port = 270;
        sm.deq_qdepth = 258;
        h.ipv4_hdr.fragOffset = h.ipv4_hdr.fragOffset;
        sm.priority = 1267 - (3w2 - sm.priority + 3w6) + 3w2;
    }
    action bOBYF(bit<4> cDow, bit<16> NcKp, bit<128> vLaQ) {
        sm.egress_spec = sm.egress_port + sm.ingress_port;
        h.eth_hdr.src_addr = 6292;
        sm.egress_port = sm.ingress_port;
    }
    action qdqld() {
        sm.ingress_port = sm.egress_spec;
        h.ipv4_hdr.dstAddr = 3592;
        h.ipv4_hdr.flags = h.ipv4_hdr.flags + sm.priority + 1880 + (3w3 + 3w0);
        h.eth_hdr.dst_addr = sm.egress_global_timestamp;
    }
    action RNLGB(bit<64> JLJC, bit<32> xJGy) {
        h.ipv4_hdr.ihl = h.tcp_hdr.dataOffset;
        h.tcp_hdr.flags = h.ipv4_hdr.ttl;
        h.ipv4_hdr.ihl = h.ipv4_hdr.version + h.ipv4_hdr.ihl;
        sm.priority = h.ipv4_hdr.flags;
        sm.instance_type = h.tcp_hdr.ackNo + (xJGy + xJGy - 32w1248) + sm.enq_timestamp;
    }
    action rDPGm() {
        h.ipv4_hdr.ttl = 9576;
        sm.enq_qdepth = sm.deq_qdepth;
        sm.ingress_global_timestamp = h.eth_hdr.src_addr;
        h.ipv4_hdr.fragOffset = 7769 + (h.ipv4_hdr.fragOffset + 1032 + 13w6240) - h.ipv4_hdr.fragOffset;
        sm.packet_length = h.tcp_hdr.ackNo - h.ipv4_hdr.dstAddr;
        h.ipv4_hdr.fragOffset = h.ipv4_hdr.fragOffset - h.ipv4_hdr.fragOffset + (h.ipv4_hdr.fragOffset - 8333 - 13w2804);
    }
    action piASE(bit<8> HajK, bit<4> ekiv, bit<128> Mboh) {
        h.ipv4_hdr.diffserv = h.tcp_hdr.flags - HajK + HajK - 8w251 + 8w5;
        sm.enq_qdepth = sm.deq_qdepth;
    }
    action Yuhsr(bit<128> RMWc, bit<64> rJFj) {
        h.ipv4_hdr.ttl = h.ipv4_hdr.ttl - h.tcp_hdr.flags;
        sm.instance_type = sm.packet_length - h.ipv4_hdr.srcAddr;
        h.ipv4_hdr.fragOffset = h.ipv4_hdr.fragOffset;
    }
    action QlEJI(bit<16> EDPv, bit<4> Hkqx, bit<128> VGTE) {
        h.tcp_hdr.dataOffset = Hkqx;
        h.ipv4_hdr.totalLen = h.tcp_hdr.srcPort + (EDPv - (h.ipv4_hdr.hdrChecksum + h.tcp_hdr.urgentPtr));
    }
    action kpWAO(bit<8> GeLN, bit<128> LfwI) {
        h.ipv4_hdr.flags = sm.priority;
        sm.priority = sm.priority - (3w2 + 3w0 + 3w2 - 3w4);
        sm.enq_qdepth = sm.enq_qdepth;
    }
    action WXWri() {
        sm.instance_type = 3055 + h.ipv4_hdr.dstAddr;
        sm.egress_spec = sm.ingress_port + 1926;
        h.eth_hdr.dst_addr = sm.egress_global_timestamp;
    }
    action ShpTi(bit<128> Ttcg, bit<64> pGWu) {
        h.tcp_hdr.seqNo = h.ipv4_hdr.dstAddr;
        sm.ingress_global_timestamp = sm.ingress_global_timestamp;
        sm.priority = sm.priority;
    }
    action zzMls(bit<4> mFdv, bit<128> fine, bit<4> Zbju) {
        sm.deq_qdepth = sm.enq_qdepth;
        h.tcp_hdr.dataOffset = mFdv;
        sm.packet_length = h.ipv4_hdr.srcAddr + (7390 - h.ipv4_hdr.srcAddr - 3543) - sm.instance_type;
        h.tcp_hdr.dataOffset = h.tcp_hdr.dataOffset;
        h.ipv4_hdr.fragOffset = h.ipv4_hdr.fragOffset;
    }
    action qPMAD(bit<8> zSKZ, bit<32> VTnZ) {
        sm.deq_qdepth = sm.deq_qdepth + sm.deq_qdepth;
        sm.egress_spec = sm.ingress_port + (9w354 - 9w284) + 9w435 - 9450;
        h.ipv4_hdr.dstAddr = VTnZ - VTnZ + h.ipv4_hdr.dstAddr - h.tcp_hdr.ackNo;
    }
    action WLyQs(bit<8> ZkDe) {
        h.ipv4_hdr.diffserv = h.tcp_hdr.flags;
        h.ipv4_hdr.flags = 8380;
        h.ipv4_hdr.diffserv = ZkDe;
        h.ipv4_hdr.ihl = h.ipv4_hdr.version + (h.ipv4_hdr.version - (1959 - h.tcp_hdr.res));
        h.tcp_hdr.window = 524 - (h.tcp_hdr.urgentPtr + (h.tcp_hdr.urgentPtr + (16w7070 - h.eth_hdr.eth_type)));
        h.ipv4_hdr.diffserv = 5767 - ZkDe;
    }
    action YGRsD(bit<32> suzZ) {
        h.ipv4_hdr.srcAddr = h.tcp_hdr.seqNo - (32w8181 + 32w1832 - sm.instance_type + suzZ);
        h.tcp_hdr.ackNo = sm.instance_type;
        h.tcp_hdr.dataOffset = h.ipv4_hdr.version;
        sm.deq_qdepth = sm.enq_qdepth + sm.deq_qdepth;
        h.ipv4_hdr.hdrChecksum = h.ipv4_hdr.identification + (h.ipv4_hdr.hdrChecksum - h.tcp_hdr.urgentPtr + h.eth_hdr.eth_type);
    }
    action lOYIP(bit<128> wwCc) {
        sm.priority = h.ipv4_hdr.flags;
        sm.enq_qdepth = 2078 - 6806;
        h.eth_hdr.src_addr = sm.egress_global_timestamp;
    }
    action CtYds(bit<32> vEaN, bit<8> CTFP) {
        h.ipv4_hdr.flags = h.ipv4_hdr.flags - (3w1 - h.ipv4_hdr.flags - 3w4 - sm.priority);
        h.ipv4_hdr.ihl = h.tcp_hdr.dataOffset + h.tcp_hdr.res;
    }
    action DzizT(bit<64> YyRX, bit<128> nstE, bit<128> eZbs) {
        h.tcp_hdr.res = h.ipv4_hdr.version;
        h.ipv4_hdr.flags = sm.priority;
        h.ipv4_hdr.fragOffset = 3329 + (h.ipv4_hdr.fragOffset - h.ipv4_hdr.fragOffset + 1467 + 13w7234);
        h.ipv4_hdr.identification = h.ipv4_hdr.totalLen;
    }
    action SPpMT(bit<4> ULRV, bit<8> LyDj, bit<16> notI) {
        h.ipv4_hdr.dstAddr = 5846 - (h.tcp_hdr.ackNo - (sm.packet_length + 9321));
        h.tcp_hdr.dataOffset = h.ipv4_hdr.version + (h.tcp_hdr.dataOffset - (h.tcp_hdr.dataOffset + (4w10 - 4w4)));
        h.ipv4_hdr.diffserv = LyDj;
        h.tcp_hdr.res = h.ipv4_hdr.version + (ULRV + h.tcp_hdr.dataOffset - 7497) - h.tcp_hdr.res;
        sm.deq_qdepth = sm.deq_qdepth - (sm.enq_qdepth - sm.enq_qdepth + (19w3752 + 19w6418));
        sm.deq_qdepth = sm.enq_qdepth + sm.enq_qdepth;
    }
    action bLoaX(bit<64> Dbuk, bit<8> UpXf, bit<16> Oybv) {
        sm.enq_qdepth = sm.deq_qdepth + sm.enq_qdepth;
        sm.deq_qdepth = 4569 + sm.enq_qdepth - (sm.deq_qdepth + sm.enq_qdepth) + sm.deq_qdepth;
        sm.priority = sm.priority;
        sm.ingress_port = sm.ingress_port - (7658 - sm.ingress_port) + (sm.egress_port + 9w116);
        h.tcp_hdr.flags = h.ipv4_hdr.protocol;
    }
    action MwDUk() {
        h.ipv4_hdr.flags = sm.priority;
        h.tcp_hdr.checksum = h.tcp_hdr.checksum;
    }
    action RzxlX(bit<16> jyKc, bit<32> kkcN) {
        sm.egress_rid = sm.egress_rid + 1455;
        h.ipv4_hdr.diffserv = h.ipv4_hdr.ttl;
    }
    action KMgiz(bit<128> xYwe, bit<8> xZCd) {
        sm.deq_qdepth = sm.deq_qdepth + (5962 - (sm.enq_qdepth + 19w3736)) - sm.deq_qdepth;
        sm.enq_qdepth = 332 - (sm.enq_qdepth - (sm.deq_qdepth + sm.enq_qdepth));
    }
    action ezKyQ(bit<8> dwCJ, bit<32> qXBz) {
        sm.egress_port = sm.egress_port - 8249 + (sm.egress_port - 9w497 + 6854);
        h.tcp_hdr.urgentPtr = h.tcp_hdr.urgentPtr;
        h.tcp_hdr.flags = h.tcp_hdr.flags;
    }
    action NVyxM(bit<8> Brtz, bit<16> gXDO, bit<16> CAkQ) {
        h.ipv4_hdr.diffserv = h.tcp_hdr.flags;
        sm.instance_type = h.tcp_hdr.ackNo - h.tcp_hdr.ackNo;
        h.eth_hdr.dst_addr = sm.ingress_global_timestamp + (sm.egress_global_timestamp + 3838);
        h.ipv4_hdr.version = h.ipv4_hdr.ihl + h.ipv4_hdr.ihl;
        sm.deq_qdepth = 6815 + (19w1362 + sm.deq_qdepth + sm.deq_qdepth + sm.deq_qdepth);
    }
    action yREPT() {
        sm.egress_spec = sm.egress_port;
        h.ipv4_hdr.protocol = h.ipv4_hdr.ttl;
        sm.deq_qdepth = sm.enq_qdepth + (19w6819 + sm.deq_qdepth) + sm.enq_qdepth - 19w5294;
    }
    action uUUcp(bit<16> tIOc, bit<32> RDip, bit<32> AGpc) {
        h.tcp_hdr.dstPort = 1233 + h.tcp_hdr.dstPort - tIOc - sm.egress_rid;
        h.tcp_hdr.seqNo = h.tcp_hdr.seqNo - AGpc;
        h.eth_hdr.dst_addr = 3827;
        h.tcp_hdr.res = h.tcp_hdr.res;
        h.tcp_hdr.res = h.tcp_hdr.res - h.tcp_hdr.res;
        h.ipv4_hdr.fragOffset = h.ipv4_hdr.fragOffset - (13w54 - 13w7567 + 13w2405 + 13w3782);
    }
    action GCtda() {
        h.ipv4_hdr.fragOffset = h.ipv4_hdr.fragOffset;
        h.tcp_hdr.dataOffset = 9838 + h.ipv4_hdr.ihl;
        sm.packet_length = 8252;
    }
    action vYsqt(bit<128> qRtx, bit<64> rLNu) {
        h.tcp_hdr.dataOffset = h.tcp_hdr.dataOffset + h.tcp_hdr.dataOffset + (h.tcp_hdr.res + (h.tcp_hdr.dataOffset - h.ipv4_hdr.version));
        h.tcp_hdr.dataOffset = h.ipv4_hdr.version;
    }
    action tqKat(bit<32> Serp) {
        h.tcp_hdr.res = h.tcp_hdr.res;
        sm.enq_timestamp = 360 - h.ipv4_hdr.dstAddr + h.ipv4_hdr.srcAddr + sm.enq_timestamp;
    }
    table VWqlMq {
        key = {
            h.tcp_hdr.window     : exact @name("sclArS") ;
            h.ipv4_hdr.fragOffset: lpm @name("nRsGkB") ;
        }
        actions = {
            drop();
            MwDUk();
        }
    }
    table ARIMMQ {
        key = {
            h.tcp_hdr.urgentPtr: exact @name("diHDqG") ;
        }
        actions = {
            YGRsD();
        }
    }
    table fXrKRB {
        key = {
            sm.egress_spec: ternary @name("ppaMzQ") ;
            sm.egress_port: lpm @name("PwgPru") ;
        }
        actions = {
            drop();
            SPpMT();
            MwDUk();
            rDPGm();
            WLyQs();
        }
    }
    table jciwkY {
        key = {
            h.ipv4_hdr.identification: exact @name("NlGqiu") ;
            h.tcp_hdr.res            : exact @name("ebzjlW") ;
            sm.egress_rid            : range @name("uGpoJx") ;
        }
        actions = {
            WXWri();
            RzxlX();
            WLyQs();
            qPMAD();
        }
    }
    table CXHXwJ {
        key = {
        }
        actions = {
            drop();
            CtYds();
            yREPT();
            wnuSJ();
        }
    }
    table HrtMdh {
        key = {
            h.tcp_hdr.dataOffset: exact @name("fzQCVY") ;
            h.tcp_hdr.res       : exact @name("UMhrvi") ;
            h.ipv4_hdr.flags    : exact @name("xnuQFk") ;
            sm.priority         : ternary @name("SnLqdm") ;
        }
        actions = {
            drop();
            YGRsD();
            uUUcp();
            uohxC();
        }
    }
    table TZAKeC {
        key = {
            h.ipv4_hdr.ttl : ternary @name("lRQThB") ;
            h.tcp_hdr.flags: range @name("CcNlac") ;
        }
        actions = {
            drop();
            WXWri();
            WLyQs();
        }
    }
    table cEbigA {
        key = {
            sm.enq_qdepth              : exact @name("KUrOOd") ;
            h.ipv4_hdr.hdrChecksum     : exact @name("xVEgub") ;
            sm.ingress_global_timestamp: range @name("uJWtym") ;
        }
        actions = {
            drop();
            rDPGm();
            CtYds();
        }
    }
    table qsVowo {
        key = {
            sm.egress_global_timestamp: exact @name("QNaxzw") ;
            sm.egress_spec            : exact @name("omZYXU") ;
            h.ipv4_hdr.hdrChecksum    : exact @name("fkWXnE") ;
            h.ipv4_hdr.flags          : ternary @name("yOvqYT") ;
        }
        actions = {
            uohxC();
        }
    }
    table WzwXEG {
        key = {
            h.tcp_hdr.dstPort   : exact @name("WxArQO") ;
            sm.egress_port      : exact @name("EwgPcZ") ;
            h.tcp_hdr.dataOffset: exact @name("XMZuKH") ;
            sm.egress_spec      : ternary @name("IpoOek") ;
        }
        actions = {
            drop();
        }
    }
    table ADjkgP {
        key = {
            sm.egress_spec    : exact @name("FRslPt") ;
            h.eth_hdr.dst_addr: lpm @name("sLYwLy") ;
            h.ipv4_hdr.ihl    : range @name("wFcgDa") ;
        }
        actions = {
            drop();
            SPpMT();
            IkBGN();
            kPcve();
            WLyQs();
            YuyuL();
            NVyxM();
        }
    }
    table xNPOZi {
        key = {
            sm.priority          : exact @name("pDoPsk") ;
            sm.priority          : exact @name("zFALob") ;
            h.ipv4_hdr.fragOffset: lpm @name("LWKQWg") ;
            sm.ingress_port      : range @name("IAknsP") ;
        }
        actions = {
            WXWri();
            ezKyQ();
            RzxlX();
        }
    }
    table qCXrPH {
        key = {
            sm.priority: ternary @name("vRnoHo") ;
        }
        actions = {
            drop();
            RzxlX();
            qPMAD();
            yREPT();
            ezKyQ();
            uohxC();
        }
    }
    table IrTVaE {
        key = {
            h.tcp_hdr.res : exact @name("kpgvgo") ;
            h.ipv4_hdr.ihl: exact @name("mxMCQh") ;
        }
        actions = {
            WLyQs();
            wnuSJ();
            CtYds();
        }
    }
    table GPyjvu {
        key = {
            sm.ingress_port            : exact @name("oYWAZC") ;
            sm.ingress_global_timestamp: exact @name("QVgXmY") ;
        }
        actions = {
            NVyxM();
            wnuSJ();
        }
    }
    table uoNpZj {
        key = {
            sm.egress_spec       : exact @name("uGOVDD") ;
            h.tcp_hdr.dataOffset : exact @name("VYVtPe") ;
            h.ipv4_hdr.protocol  : exact @name("QIKXok") ;
            h.ipv4_hdr.fragOffset: range @name("mnnMSm") ;
        }
        actions = {
            drop();
            kPcve();
        }
    }
    table uKJqBA {
        key = {
            h.ipv4_hdr.flags: exact @name("yfLgTp") ;
            sm.egress_port  : exact @name("wtreWT") ;
            h.tcp_hdr.res   : exact @name("nCctgD") ;
            h.ipv4_hdr.ihl  : ternary @name("IxOwNQ") ;
        }
        actions = {
            drop();
            YGRsD();
            YuyuL();
            RzxlX();
            SPpMT();
        }
    }
    table ystVzY {
        key = {
            h.ipv4_hdr.fragOffset: exact @name("XbWDPf") ;
            h.tcp_hdr.ackNo      : lpm @name("gBMCHw") ;
            sm.enq_qdepth        : range @name("tzTXpS") ;
        }
        actions = {
            drop();
            klCfx();
            CtYds();
        }
    }
    table uCFELY {
        key = {
            h.ipv4_hdr.flags   : exact @name("KEYFPm") ;
            h.ipv4_hdr.diffserv: exact @name("wtNBUP") ;
            h.tcp_hdr.res      : ternary @name("uXbZKV") ;
        }
        actions = {
            drop();
            kPcve();
            uohxC();
            YuyuL();
            IkBGN();
            NVyxM();
            qdqld();
        }
    }
    table BbtUkq {
        key = {
            h.tcp_hdr.dataOffset: lpm @name("nzHABE") ;
            h.tcp_hdr.seqNo     : range @name("YySUcj") ;
        }
        actions = {
            rDPGm();
            YuyuL();
        }
    }
    table gLGzxu {
        key = {
        }
        actions = {
            uohxC();
            ezKyQ();
            WXWri();
            CtYds();
            SPpMT();
        }
    }
    table ZcANmV {
        key = {
            h.ipv4_hdr.flags: exact @name("QmkibJ") ;
            h.tcp_hdr.res   : exact @name("XzfLuu") ;
            sm.enq_qdepth   : exact @name("wLkDVw") ;
            h.tcp_hdr.flags : range @name("mpgzRs") ;
        }
        actions = {
            GCtda();
            yREPT();
            RzxlX();
            rDPGm();
        }
    }
    table VihytG {
        key = {
            sm.egress_port       : exact @name("raQyjc") ;
            h.tcp_hdr.flags      : ternary @name("vzjVVc") ;
            h.ipv4_hdr.fragOffset: lpm @name("SmpEsM") ;
        }
        actions = {
            drop();
            CtYds();
            NVyxM();
            GCtda();
        }
    }
    table tnyJPg {
        key = {
            sm.priority      : exact @name("hbzJQw") ;
            h.tcp_hdr.dstPort: ternary @name("iCCcDO") ;
        }
        actions = {
            WLyQs();
            YuyuL();
            RzxlX();
            GCtda();
            tqKat();
        }
    }
    apply {
        BbtUkq.apply();
        VWqlMq.apply();
        qCXrPH.apply();
        TZAKeC.apply();
        HrtMdh.apply();
        if (h.ipv4_hdr.isValid()) {
            jciwkY.apply();
            fXrKRB.apply();
        } else {
            WzwXEG.apply();
            cEbigA.apply();
        }
        tnyJPg.apply();
        uKJqBA.apply();
        GPyjvu.apply();
        if (h.eth_hdr.isValid()) {
            gLGzxu.apply();
            IrTVaE.apply();
            VihytG.apply();
            ARIMMQ.apply();
            uCFELY.apply();
            xNPOZi.apply();
        } else {
            uoNpZj.apply();
            ZcANmV.apply();
            CXHXwJ.apply();
            ystVzY.apply();
            qsVowo.apply();
        }
        ADjkgP.apply();
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
