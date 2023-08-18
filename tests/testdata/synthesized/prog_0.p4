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
    action qjXaK(bit<64> Puqe) {
        sm.egress_rid = 2835 - (h.ipv4_hdr.hdrChecksum + (h.ipv4_hdr.hdrChecksum + 16w8102 + 16w1569));
        sm.egress_spec = sm.ingress_port + (sm.ingress_port - 9w53) + 9w454 - 774;
        sm.ingress_global_timestamp = 8751 - (48w8139 - sm.egress_global_timestamp) - h.eth_hdr.src_addr + 48w2826;
        h.tcp_hdr.srcPort = h.eth_hdr.eth_type;
        h.tcp_hdr.flags = 7944;
    }
    action aKFys(bit<64> OdXb) {
        h.tcp_hdr.dataOffset = h.tcp_hdr.dataOffset;
        h.ipv4_hdr.fragOffset = h.ipv4_hdr.fragOffset;
    }
    action ImStJ() {
        h.ipv4_hdr.hdrChecksum = h.tcp_hdr.checksum - h.ipv4_hdr.totalLen;
        sm.egress_spec = sm.egress_port;
        h.ipv4_hdr.flags = sm.priority - h.ipv4_hdr.flags;
    }
    action jWeyf(bit<4> rAWI) {
        h.ipv4_hdr.fragOffset = h.ipv4_hdr.fragOffset;
        h.ipv4_hdr.fragOffset = h.ipv4_hdr.fragOffset - (h.ipv4_hdr.fragOffset - h.ipv4_hdr.fragOffset + (h.ipv4_hdr.fragOffset - 13w1305));
    }
    action sJimE(bit<4> nSqb, bit<128> LAyP) {
        h.ipv4_hdr.flags = 9034 + h.ipv4_hdr.flags;
        sm.deq_qdepth = sm.deq_qdepth;
        h.ipv4_hdr.srcAddr = h.ipv4_hdr.dstAddr - h.tcp_hdr.ackNo;
        sm.priority = sm.priority;
        h.tcp_hdr.checksum = 3823 - h.tcp_hdr.checksum + (16w7783 + 16w6906) - 16w7614;
        h.ipv4_hdr.fragOffset = 3346;
    }
    action PmphQ(bit<128> NdZo) {
        h.ipv4_hdr.ttl = h.tcp_hdr.flags;
        sm.egress_global_timestamp = h.eth_hdr.dst_addr - 4675;
    }
    action BCrUN(bit<32> qJRj, bit<8> wBDJ) {
        h.tcp_hdr.flags = h.ipv4_hdr.diffserv - h.ipv4_hdr.protocol + (h.ipv4_hdr.protocol + h.ipv4_hdr.ttl) - h.ipv4_hdr.diffserv;
        h.ipv4_hdr.srcAddr = h.ipv4_hdr.dstAddr + qJRj;
        sm.deq_qdepth = 651;
        h.ipv4_hdr.diffserv = h.tcp_hdr.flags + 6358;
        sm.instance_type = h.ipv4_hdr.dstAddr;
        h.tcp_hdr.res = 3412;
    }
    action ZXlQg(bit<64> Vzfa) {
        sm.priority = 5582 - h.ipv4_hdr.flags;
        h.ipv4_hdr.dstAddr = sm.instance_type;
    }
    action cWrzY(bit<32> rXJY) {
        h.ipv4_hdr.protocol = h.tcp_hdr.flags;
        h.eth_hdr.src_addr = sm.ingress_global_timestamp + 8951;
    }
    action Rpjkh(bit<16> hnQy) {
        h.tcp_hdr.ackNo = h.tcp_hdr.ackNo - (8165 + sm.enq_timestamp + 32w2584 - 32w9647);
        h.tcp_hdr.dstPort = h.tcp_hdr.window;
        sm.ingress_global_timestamp = sm.egress_global_timestamp + sm.egress_global_timestamp;
        sm.enq_qdepth = sm.deq_qdepth;
        sm.egress_port = sm.ingress_port;
    }
    action puESf(bit<4> Pmwb, bit<4> wGkS) {
        h.ipv4_hdr.fragOffset = 2418 - h.ipv4_hdr.fragOffset + h.ipv4_hdr.fragOffset + 13w8021 - 13w3097;
        sm.enq_timestamp = h.ipv4_hdr.dstAddr + 4588;
        sm.deq_qdepth = sm.enq_qdepth;
    }
    action ymafC(bit<16> luvv) {
        h.ipv4_hdr.fragOffset = 13w7562 - 13w6258 - 13w6735 + 4876 + h.ipv4_hdr.fragOffset;
        h.ipv4_hdr.ttl = h.ipv4_hdr.diffserv;
        h.ipv4_hdr.ttl = h.ipv4_hdr.diffserv - (4114 - h.tcp_hdr.flags);
    }
    action jXBPb(bit<64> wuPW, bit<8> UUnD) {
        sm.egress_spec = sm.ingress_port - sm.egress_port;
        sm.packet_length = 718 - (8062 - (sm.enq_timestamp + (sm.packet_length - 32w7829)));
    }
    action EcNYR(bit<64> IzTj, bit<16> AQCX) {
        sm.enq_qdepth = sm.enq_qdepth;
        h.tcp_hdr.dataOffset = 6146;
    }
    action JKTrO(bit<64> EHWd) {
        h.tcp_hdr.flags = h.ipv4_hdr.ttl - h.ipv4_hdr.protocol;
        h.tcp_hdr.srcPort = 7423 - (h.tcp_hdr.window + 436);
        h.ipv4_hdr.fragOffset = h.ipv4_hdr.fragOffset - h.ipv4_hdr.fragOffset - (6299 - 227);
        h.tcp_hdr.res = h.ipv4_hdr.version + 4w12 - h.ipv4_hdr.version + h.tcp_hdr.dataOffset - h.tcp_hdr.res;
        h.tcp_hdr.dataOffset = h.tcp_hdr.dataOffset;
        sm.deq_qdepth = sm.enq_qdepth;
    }
    action zYadR() {
        sm.deq_qdepth = sm.deq_qdepth + sm.deq_qdepth;
        sm.egress_spec = sm.egress_spec;
        sm.priority = sm.priority;
    }
    action VxJjy() {
        h.ipv4_hdr.fragOffset = 8419;
        h.tcp_hdr.res = h.ipv4_hdr.ihl;
        h.eth_hdr.dst_addr = h.eth_hdr.dst_addr;
        h.ipv4_hdr.diffserv = h.ipv4_hdr.protocol;
    }
    action EzpQH() {
        sm.enq_qdepth = sm.enq_qdepth;
        h.ipv4_hdr.hdrChecksum = h.tcp_hdr.checksum;
        h.tcp_hdr.srcPort = 16w6937 - h.ipv4_hdr.identification + 16w5307 + h.ipv4_hdr.totalLen - h.tcp_hdr.dstPort;
        h.ipv4_hdr.ttl = h.ipv4_hdr.protocol;
        h.ipv4_hdr.fragOffset = h.ipv4_hdr.fragOffset;
        h.ipv4_hdr.fragOffset = h.ipv4_hdr.fragOffset;
    }
    action KBxtZ(bit<8> glli, bit<64> nGic, bit<8> ysAq) {
        sm.egress_spec = sm.egress_port + sm.ingress_port - sm.ingress_port;
        sm.ingress_port = sm.egress_spec + sm.egress_port;
    }
    action RjKIi() {
        h.ipv4_hdr.diffserv = h.ipv4_hdr.protocol - (h.ipv4_hdr.ttl - 9341);
        h.ipv4_hdr.flags = 6997 + h.ipv4_hdr.flags;
        sm.egress_global_timestamp = sm.ingress_global_timestamp;
        h.tcp_hdr.ackNo = sm.enq_timestamp - h.tcp_hdr.seqNo;
        h.ipv4_hdr.protocol = h.ipv4_hdr.diffserv;
    }
    action leEYn(bit<32> JoHd) {
        sm.egress_global_timestamp = h.eth_hdr.src_addr;
        sm.instance_type = h.tcp_hdr.seqNo;
    }
    action vgEdC(bit<8> IdrI, bit<128> WbXV, bit<8> JJZS) {
        h.ipv4_hdr.flags = sm.priority;
        h.ipv4_hdr.fragOffset = h.ipv4_hdr.fragOffset;
        h.ipv4_hdr.fragOffset = 7047 - h.ipv4_hdr.fragOffset;
        h.tcp_hdr.flags = h.ipv4_hdr.ttl + (h.ipv4_hdr.ttl - h.ipv4_hdr.diffserv);
        h.ipv4_hdr.identification = h.eth_hdr.eth_type + h.tcp_hdr.dstPort;
        sm.deq_qdepth = sm.deq_qdepth + (sm.deq_qdepth + 7635 - sm.enq_qdepth + sm.enq_qdepth);
    }
    action RCjIj(bit<8> UaAn) {
        h.ipv4_hdr.hdrChecksum = h.tcp_hdr.checksum + (h.ipv4_hdr.totalLen + sm.egress_rid) + 2299;
        h.ipv4_hdr.fragOffset = h.ipv4_hdr.fragOffset;
        sm.enq_qdepth = sm.enq_qdepth + sm.enq_qdepth + 7139;
        sm.egress_global_timestamp = 9466 + 6970;
        h.tcp_hdr.ackNo = h.ipv4_hdr.srcAddr;
    }
    action bUJMO(bit<64> wNaL) {
        h.ipv4_hdr.diffserv = h.ipv4_hdr.ttl + h.ipv4_hdr.diffserv;
        h.ipv4_hdr.diffserv = h.ipv4_hdr.diffserv;
        sm.priority = 8121 + sm.priority;
        h.tcp_hdr.dataOffset = h.ipv4_hdr.version;
    }
    action pbufJ() {
        h.ipv4_hdr.ihl = h.tcp_hdr.res - (h.tcp_hdr.dataOffset + (h.tcp_hdr.dataOffset - h.ipv4_hdr.ihl) - 4w7);
        h.tcp_hdr.flags = h.ipv4_hdr.protocol;
        sm.instance_type = h.tcp_hdr.ackNo;
        sm.instance_type = h.ipv4_hdr.dstAddr - (32w3668 + 7046 - 32w736) - 32w6447;
        sm.deq_qdepth = sm.deq_qdepth;
    }
    action sHqIK(bit<128> PLXW, bit<4> MCVf) {
        sm.egress_port = sm.egress_spec + 2364;
        sm.egress_port = 9w392 + sm.egress_port - 9w251 + sm.ingress_port + sm.egress_port;
    }
    action SUeGj(bit<64> RxCq, bit<16> zEqX, bit<4> JXla) {
        sm.ingress_port = sm.egress_spec;
        sm.egress_spec = sm.egress_port;
        sm.ingress_port = 5975;
        sm.enq_qdepth = sm.deq_qdepth + (sm.enq_qdepth - sm.enq_qdepth) - sm.enq_qdepth;
        h.eth_hdr.dst_addr = 8313;
    }
    action sshDd(bit<8> WfPX) {
        h.ipv4_hdr.identification = h.ipv4_hdr.totalLen - (h.tcp_hdr.checksum - 16w3137 - 2451) - h.tcp_hdr.dstPort;
        sm.packet_length = h.ipv4_hdr.srcAddr;
    }
    action ycHSk(bit<8> qxkN, bit<16> cuqx, bit<16> uWii) {
        h.ipv4_hdr.fragOffset = h.ipv4_hdr.fragOffset;
        h.tcp_hdr.dataOffset = h.ipv4_hdr.ihl + h.ipv4_hdr.ihl - h.ipv4_hdr.version;
        sm.enq_qdepth = sm.enq_qdepth;
        sm.ingress_port = sm.ingress_port - sm.egress_port;
    }
    action Bmpvw(bit<64> Aoar, bit<32> thnL, bit<64> Sape) {
        sm.priority = 5480 - (sm.priority - sm.priority);
        h.ipv4_hdr.version = h.ipv4_hdr.version - h.ipv4_hdr.version + (4w7 + h.ipv4_hdr.version) - h.tcp_hdr.res;
    }
    action srvjd(bit<8> NLKf) {
        sm.egress_global_timestamp = h.eth_hdr.dst_addr;
        sm.egress_global_timestamp = 8442;
        h.tcp_hdr.window = h.tcp_hdr.window + (8915 + (16w640 + 16w8557)) - h.ipv4_hdr.totalLen;
    }
    action PiVtD() {
        h.tcp_hdr.ackNo = 9509 - h.tcp_hdr.ackNo;
        h.ipv4_hdr.version = h.ipv4_hdr.ihl;
        h.ipv4_hdr.fragOffset = h.ipv4_hdr.fragOffset - h.ipv4_hdr.fragOffset - (h.ipv4_hdr.fragOffset + 13w7637 - h.ipv4_hdr.fragOffset);
        h.tcp_hdr.dstPort = h.tcp_hdr.dstPort - h.tcp_hdr.srcPort;
    }
    action lqcMQ(bit<32> suKo) {
        sm.ingress_global_timestamp = h.eth_hdr.dst_addr + sm.ingress_global_timestamp;
        h.ipv4_hdr.fragOffset = h.ipv4_hdr.fragOffset;
        sm.ingress_port = sm.ingress_port;
        h.ipv4_hdr.flags = h.ipv4_hdr.flags - 3w1 - 3w0 + 9683 - h.ipv4_hdr.flags;
    }
    action xaCTa(bit<8> UuZe, bit<128> aSSs, bit<64> kWBR) {
        h.ipv4_hdr.ttl = h.tcp_hdr.flags;
        sm.ingress_port = sm.egress_port;
        h.ipv4_hdr.srcAddr = h.ipv4_hdr.dstAddr;
    }
    action mAvuJ(bit<64> UiOC, bit<8> QBgo) {
        h.ipv4_hdr.fragOffset = h.ipv4_hdr.fragOffset + h.ipv4_hdr.fragOffset + (h.ipv4_hdr.fragOffset - (h.ipv4_hdr.fragOffset + 13w4945));
        sm.priority = h.ipv4_hdr.flags;
        h.tcp_hdr.checksum = h.tcp_hdr.dstPort + (16w5148 + 16w9796) + 1697 + h.tcp_hdr.srcPort;
        h.ipv4_hdr.ihl = h.tcp_hdr.res + h.ipv4_hdr.version;
    }
    table pvVTbg {
        key = {
            sm.enq_qdepth        : exact @name("aOkfGT") ;
            sm.egress_port       : exact @name("ztnWKU") ;
            h.ipv4_hdr.ihl       : exact @name("cuavPb") ;
            h.ipv4_hdr.fragOffset: range @name("zPgAIW") ;
        }
        actions = {
            drop();
        }
    }
    table ksqYWK {
        key = {
            h.tcp_hdr.urgentPtr: exact @name("Ymkmqt") ;
            sm.packet_length   : exact @name("gilBtl") ;
            h.ipv4_hdr.protocol: lpm @name("NCXuKe") ;
        }
        actions = {
            EzpQH();
            BCrUN();
            ymafC();
        }
    }
    table dzKHzw {
        key = {
            sm.egress_global_timestamp : exact @name("kRfrgF") ;
            sm.ingress_global_timestamp: exact @name("dNPOeP") ;
            h.tcp_hdr.dataOffset       : lpm @name("JWgWfp") ;
            h.ipv4_hdr.diffserv        : range @name("PkRLtu") ;
        }
        actions = {
            ImStJ();
            RCjIj();
            Rpjkh();
            RjKIi();
            ymafC();
            sshDd();
        }
    }
    table oTGNaL {
        key = {
            sm.egress_spec     : exact @name("ocZqhy") ;
            h.ipv4_hdr.diffserv: range @name("rqjhJZ") ;
        }
        actions = {
            drop();
        }
    }
    table WFNOlY {
        key = {
            sm.enq_qdepth: exact @name("AASuUQ") ;
            h.tcp_hdr.res: ternary @name("SQrYno") ;
        }
        actions = {
            drop();
            sshDd();
            EzpQH();
            cWrzY();
            BCrUN();
            jWeyf();
            RjKIi();
            ImStJ();
        }
    }
    table OBDGVw {
        key = {
            sm.egress_spec    : exact @name("bxedxY") ;
            h.tcp_hdr.window  : exact @name("gRUFbH") ;
            sm.ingress_port   : exact @name("WPSgdu") ;
            h.eth_hdr.src_addr: lpm @name("KQOlhp") ;
            h.tcp_hdr.res     : range @name("HQHKTM") ;
        }
        actions = {
            lqcMQ();
            pbufJ();
            cWrzY();
        }
    }
    table uxOhSK {
        key = {
            h.ipv4_hdr.ihl      : exact @name("aeHKgS") ;
            h.tcp_hdr.dataOffset: exact @name("uBLcWE") ;
            h.ipv4_hdr.dstAddr  : exact @name("KKHDrk") ;
            sm.priority         : range @name("rDqeNo") ;
        }
        actions = {
            drop();
            BCrUN();
            srvjd();
            cWrzY();
            Rpjkh();
            RjKIi();
        }
    }
    table RXmByu {
        key = {
            sm.egress_port            : exact @name("MaqACk") ;
            sm.egress_global_timestamp: ternary @name("arOeGS") ;
        }
        actions = {
            drop();
            ImStJ();
            PiVtD();
            sshDd();
        }
    }
    table RxqdpT {
        key = {
            h.tcp_hdr.res        : exact @name("GXOVCe") ;
            h.ipv4_hdr.flags     : exact @name("DEhLdc") ;
            h.ipv4_hdr.fragOffset: range @name("rTBOHR") ;
        }
        actions = {
            leEYn();
        }
    }
    table JLbFug {
        key = {
            sm.deq_qdepth        : exact @name("GinQbs") ;
            h.ipv4_hdr.fragOffset: ternary @name("cljQBL") ;
            sm.deq_qdepth        : lpm @name("osrmtL") ;
            sm.priority          : range @name("RcaVyZ") ;
        }
        actions = {
            VxJjy();
            zYadR();
            cWrzY();
            Rpjkh();
            PiVtD();
        }
    }
    table KHFaPa {
        key = {
            h.eth_hdr.src_addr   : exact @name("wdspbU") ;
            sm.priority          : exact @name("qbVrcw") ;
            h.ipv4_hdr.fragOffset: ternary @name("YqqntP") ;
        }
        actions = {
            drop();
            RjKIi();
            sshDd();
        }
    }
    table DyhVnD {
        key = {
            sm.instance_type  : exact @name("bTHvWQ") ;
            h.ipv4_hdr.flags  : exact @name("nHlawH") ;
            sm.egress_rid     : ternary @name("wzKqtz") ;
            h.eth_hdr.dst_addr: range @name("SFIczR") ;
        }
        actions = {
            drop();
            ymafC();
            pbufJ();
            sshDd();
            RCjIj();
        }
    }
    table SIigrC {
        key = {
            sm.enq_qdepth             : exact @name("ipORLR") ;
            sm.egress_global_timestamp: exact @name("PTkWQG") ;
            sm.egress_global_timestamp: ternary @name("zcNlAs") ;
            h.tcp_hdr.seqNo           : lpm @name("WZCjcF") ;
            h.eth_hdr.src_addr        : range @name("SVGCkZ") ;
        }
        actions = {
            EzpQH();
            pbufJ();
        }
    }
    table tCxnrk {
        key = {
            sm.egress_rid        : exact @name("jUYYGt") ;
            h.ipv4_hdr.fragOffset: exact @name("Namgzl") ;
            sm.deq_qdepth        : exact @name("IUtlvA") ;
        }
        actions = {
            VxJjy();
            zYadR();
            ImStJ();
        }
    }
    table omNTnO {
        key = {
            h.eth_hdr.dst_addr: exact @name("EzfSyt") ;
            h.tcp_hdr.res     : ternary @name("EixfNJ") ;
            sm.deq_qdepth     : lpm @name("fihpKS") ;
            h.ipv4_hdr.ttl    : range @name("OzwRgJ") ;
        }
        actions = {
            drop();
            leEYn();
            jWeyf();
            zYadR();
        }
    }
    table SOBVjw {
        key = {
            h.ipv4_hdr.fragOffset: exact @name("QlqWQX") ;
            h.ipv4_hdr.fragOffset: exact @name("jTHTCy") ;
            h.ipv4_hdr.fragOffset: lpm @name("ufZIwi") ;
            sm.enq_timestamp     : range @name("WCKkHy") ;
        }
        actions = {
            PiVtD();
        }
    }
    table wCnNjY {
        key = {
            h.tcp_hdr.res     : exact @name("zJQCfj") ;
            sm.ingress_port   : exact @name("RDLVON") ;
            h.ipv4_hdr.version: lpm @name("bZcEVN") ;
        }
        actions = {
            ymafC();
            lqcMQ();
            ycHSk();
        }
    }
    table wTcWFN {
        key = {
            h.tcp_hdr.dataOffset: ternary @name("KZzVCE") ;
            sm.deq_qdepth       : lpm @name("sWagvz") ;
        }
        actions = {
            drop();
            RCjIj();
            VxJjy();
            lqcMQ();
            ImStJ();
        }
    }
    table XsFnYg {
        key = {
            h.ipv4_hdr.totalLen: ternary @name("wogJnj") ;
            sm.ingress_port    : range @name("PITJhh") ;
        }
        actions = {
            drop();
            puESf();
        }
    }
    table eHmYdC {
        key = {
            h.tcp_hdr.ackNo            : exact @name("cbyKFk") ;
            sm.ingress_global_timestamp: ternary @name("gzKZpE") ;
        }
        actions = {
        }
    }
    table SpSXsh {
        key = {
            h.tcp_hdr.dataOffset      : exact @name("EEGULw") ;
            sm.egress_global_timestamp: exact @name("gIaLmW") ;
            sm.enq_timestamp          : exact @name("CluIrq") ;
            h.eth_hdr.dst_addr        : lpm @name("acbWNZ") ;
            sm.packet_length          : range @name("fGojXm") ;
        }
        actions = {
            ycHSk();
            VxJjy();
            srvjd();
            leEYn();
        }
    }
    table hSqFEA {
        key = {
            h.tcp_hdr.srcPort: lpm @name("DAuoAK") ;
        }
        actions = {
            srvjd();
            jWeyf();
        }
    }
    apply {
        DyhVnD.apply();
        if (h.tcp_hdr.isValid()) {
            SpSXsh.apply();
            wTcWFN.apply();
        } else {
            omNTnO.apply();
            oTGNaL.apply();
        }
        dzKHzw.apply();
        if (h.tcp_hdr.isValid()) {
            OBDGVw.apply();
            ksqYWK.apply();
            eHmYdC.apply();
        } else {
            JLbFug.apply();
            uxOhSK.apply();
            RxqdpT.apply();
            tCxnrk.apply();
            SIigrC.apply();
        }
        RXmByu.apply();
        pvVTbg.apply();
        if (!!h.ipv4_hdr.isValid()) {
            SOBVjw.apply();
            WFNOlY.apply();
            KHFaPa.apply();
            if (!!h.eth_hdr.isValid()) {
                XsFnYg.apply();
                wCnNjY.apply();
            } else {
                hSqFEA.apply();
            }
        } else {
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
