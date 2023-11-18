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
    bit<3>  BsZZdG;
    bit<3>  KuryeD;
    bit<3>  mEOLiZ;
    bit<3>  CfVCQv;
    bit<3>  IplYjc;
    bit<3>  dffbJU;
    bit<3>  PvElpT;
    bit<3>  zwGOet;
    bit<3>  lFnMZL;
    bit<3>  vyREwV;
    bit<3>  IjHrAT;
    bit<3>  OLkxAt;
    bit<3>  phAknF;
    bit<3>  DmzkLz;
    bit<3>  qPxyjR;
    bit<3>  GpkAUO;
    bit<3>  rtCPFT;
    bit<3>  OPTsWY;
    bit<3>  KIfJZv;
    bit<3>  eiefPs;
    bit<3>  RBerTa;
    bit<3>  mmBiCb;
    bit<4>  jeeQNk;
    bit<4>  ukYLUD;
    bit<4>  VSvGUO;
    bit<4>  EPBDAV;
    bit<4>  XOpdfV;
    bit<4>  tdkOAI;
    bit<4>  ebEalU;
    bit<4>  hXnvmy;
    bit<4>  UxMcfa;
    bit<4>  rnxdVX;
    bit<4>  RXoMFC;
    bit<4>  pgHkeB;
    bit<4>  KEbjCx;
    bit<4>  YaZZvt;
    bit<4>  mTOOwf;
    bit<4>  PCSkJu;
    bit<4>  HgOptt;
    bit<4>  yFPhNC;
    bit<4>  Cocdsn;
    bit<4>  lbWyBM;
    bit<4>  bepiif;
    bit<4>  trdSWk;
    bit<8>  mLALxe;
    bit<8>  NQnfkO;
    bit<8>  mwxYYL;
    bit<8>  MXSYxR;
    bit<8>  hGGsRl;
    bit<8>  gXUrRx;
    bit<8>  vPHSwE;
    bit<8>  xwwZeA;
    bit<8>  zLUgNE;
    bit<8>  eYQQzF;
    bit<8>  tjMKCj;
    bit<8>  zsueiK;
    bit<8>  yBGShQ;
    bit<8>  EbmByZ;
    bit<8>  Bxnbbt;
    bit<8>  ZDzQyy;
    bit<8>  IyjvHz;
    bit<8>  hUltCJ;
    bit<8>  pjJtAS;
    bit<8>  XzhHJx;
    bit<8>  nrUHbX;
    bit<8>  TItDCZ;
    bit<9>  Vquqcz;
    bit<9>  geuEZM;
    bit<9>  bBWYye;
    bit<9>  nzkIUJ;
    bit<9>  gEpTYY;
    bit<9>  BvnPie;
    bit<9>  BckpYg;
    bit<9>  gVDnEQ;
    bit<9>  wKDxEH;
    bit<9>  lOZOop;
    bit<9>  GGGqbd;
    bit<9>  TwqtSG;
    bit<9>  suqLDU;
    bit<9>  nLfExC;
    bit<9>  bmViAq;
    bit<9>  dkZuUc;
    bit<9>  ZKRNvI;
    bit<9>  xGNwfb;
    bit<9>  doCRHz;
    bit<9>  JHKXFx;
    bit<9>  BKTgck;
    bit<9>  oMNZNk;
    bit<13> Yzfrde;
    bit<13> rgebQB;
    bit<13> CglrNM;
    bit<13> hTLQfc;
    bit<13> upQCYx;
    bit<13> aMubdO;
    bit<13> HoFOUW;
    bit<13> JCsZqU;
    bit<13> YaEemy;
    bit<13> XGYSrw;
    bit<13> nWIelt;
    bit<13> kVtYuN;
    bit<13> ekNxVV;
    bit<13> yvlxGD;
    bit<13> qejCXq;
    bit<13> HwiMJv;
    bit<13> eRobBy;
    bit<13> kxlBWM;
    bit<13> COkbRT;
    bit<13> QWrfXb;
    bit<13> ZUKwDZ;
    bit<13> QPVnOr;
    bit<16> bngAaQ;
    bit<16> VPWJjR;
    bit<16> FOVbDf;
    bit<16> CyEWng;
    bit<16> vEhLih;
    bit<16> tiZHJq;
    bit<16> dcKuIu;
    bit<16> CDHPbg;
    bit<16> DQeKnb;
    bit<16> oOEvqo;
    bit<16> bDmKHf;
    bit<16> FJaGAA;
    bit<16> zABEOq;
    bit<16> HtBufj;
    bit<16> jyGmum;
    bit<16> Aafeae;
    bit<16> mWZeQe;
    bit<16> PsHQnL;
    bit<16> GLSkUh;
    bit<16> AizfGB;
    bit<16> PedNkL;
    bit<16> IneAus;
    bit<19> SLPpHN;
    bit<19> buAOKt;
    bit<19> fyfftH;
    bit<19> pzSEkO;
    bit<19> BUxHag;
    bit<19> lfnXkv;
    bit<19> ajIlKR;
    bit<19> OjaGuX;
    bit<19> eCufBB;
    bit<19> SSBVUQ;
    bit<19> fRlatm;
    bit<19> ACcMmc;
    bit<19> NnqOCf;
    bit<19> daeDUw;
    bit<19> mvshNU;
    bit<19> GAClqd;
    bit<19> olyugp;
    bit<19> KXSdaq;
    bit<19> cRFOsO;
    bit<19> HLJhUf;
    bit<19> FkvVEo;
    bit<19> lGVwWe;
    bit<32> xKuYZV;
    bit<32> CpqgZC;
    bit<32> pNylwh;
    bit<32> qZwGsp;
    bit<32> ODBMXM;
    bit<32> reqFaF;
    bit<32> uUOoYt;
    bit<32> RckAZD;
    bit<32> fCSphg;
    bit<32> WScqKH;
    bit<32> LLYpou;
    bit<32> oNMtBh;
    bit<32> XFCcmo;
    bit<32> UMuqJS;
    bit<32> hhqsne;
    bit<32> ZayOsg;
    bit<32> KhqMOv;
    bit<32> veSHgB;
    bit<32> AljLOs;
    bit<32> eRqDVx;
    bit<32> reHNUr;
    bit<32> LXGEuK;
    bit<48> VixUKg;
    bit<48> FenUfS;
    bit<48> EbyqYn;
    bit<48> lITXqv;
    bit<48> YSUJSf;
    bit<48> igmsiR;
    bit<48> BvuIgS;
    bit<48> IDmbpH;
    bit<48> flxnCA;
    bit<48> QRnxQd;
    bit<48> CgYnRw;
    bit<48> jZbssI;
    bit<48> VsCEkF;
    bit<48> WhbpjR;
    bit<48> JBCqwV;
    bit<48> TjzaMM;
    bit<48> hsIhsm;
    bit<48> RGISep;
    bit<48> KZqisq;
    bit<48> DNerSr;
    bit<48> ECVyWL;
    bit<48> gNiNAb;
    bit<64> NEeKCX;
    bit<64> mPjgSl;
    bit<64> KBAlpa;
    bit<64> QlJhjF;
    bit<64> yZszKw;
    bit<64> QbWGQQ;
    bit<64> rmwiXF;
    bit<64> KAoYQo;
    bit<64> bJeQio;
    bit<64> QwOQDZ;
    bit<64> aKcwfD;
    bit<64> rzKGeT;
    bit<64> HXHgJb;
    bit<64> uMHUeP;
    bit<64> rCrWZT;
    bit<64> allyjK;
    bit<64> dpXDea;
    bit<64> iFahMc;
    bit<64> xaqsoj;
    bit<64> wIVVOZ;
    bit<64> ngIzGE;
    bit<64> xQrGMi;
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
    action ggIyu(bit<64> RcIs) {
        m.KXSdaq = m.cRFOsO - (m.daeDUw + sm.enq_qdepth);
    }
    action bcgyj() {
        m.GAClqd = 7060 - sm.deq_qdepth;
    }
    action wGcyw(bit<8> cKNa, bit<4> eoNm) {
        m.KXSdaq = sm.deq_qdepth;
    }
    action binBg(bit<64> pZOa, bit<8> AdXg) {
        m.JBCqwV = m.QRnxQd - m.flxnCA;
    }
    action tOEMc(bit<8> gNnN, bit<128> NSnX) {
        h.ipv4_hdr.fragOffset = m.QPVnOr + m.COkbRT;
    }
    action lFGbx(bit<16> SQSH) {
        h.eth_hdr.dst_addr = 7022;
    }
    action mZkRl(bit<8> COeX, bit<4> KTdm) {
        m.CyEWng = m.bDmKHf;
    }
    action zoGLg(bit<32> FTpx) {
        h.eth_hdr.dst_addr = m.ECVyWL;
    }
    action fKskQ(bit<4> SYIM) {
        m.fyfftH = 6087;
    }
    action avCHE(bit<64> GsFl, bit<128> EQiA) {
        m.VSvGUO = m.jeeQNk;
    }
    action pKaiA() {
        m.HtBufj = h.tcp_hdr.window;
    }
    action wyIzf() {
        m.wKDxEH = m.wKDxEH - (m.lOZOop + 9w60 + m.GGGqbd);
    }
    action ujHPI(bit<16> nRza, bit<128> pFVS) {
        m.TwqtSG = m.BvnPie;
    }
    action hViHK(bit<8> DAdR, bit<8> klqu) {
        m.fRlatm = 19w1803 + m.daeDUw + 19w7105 - 4655;
    }
    action zPHIl(bit<32> haoC) {
        h.ipv4_hdr.dstAddr = h.ipv4_hdr.dstAddr;
    }
    action FYGkz(bit<4> beSQ) {
        m.FOVbDf = m.tiZHJq;
    }
    action PPxyz() {
        m.KXSdaq = sm.deq_qdepth;
    }
    action ZIiOo(bit<128> SDoa) {
        h.ipv4_hdr.fragOffset = 3717 - (13w2317 - 13w6755 - m.ZUKwDZ);
    }
    action qDpMi(bit<64> ujgl, bit<64> Wycd) {
        m.ECVyWL = 48w4326 + 48w3392 - 9264 - 48w1857;
    }
    action LnzCR() {
        h.ipv4_hdr.flags = m.RBerTa + (3805 + (m.eiefPs + 3w0));
    }
    action bhXiX() {
        m.dffbJU = m.eiefPs;
    }
    action rmNjp(bit<4> qftH) {
        h.eth_hdr.dst_addr = sm.ingress_global_timestamp;
    }
    action PQQfa(bit<4> joAN) {
        m.reHNUr = m.uUOoYt;
    }
    action kfryr(bit<128> WBQf) {
        m.GpkAUO = m.qPxyjR + (m.qPxyjR + m.IplYjc) + m.mmBiCb;
    }
    action PQRri() {
        h.ipv4_hdr.diffserv = m.Bxnbbt;
    }
    action kNVAj(bit<16> VIbg, bit<4> MUfE) {
        m.xGNwfb = 5824 - m.Vquqcz;
    }
    action XphvF() {
        h.ipv4_hdr.ihl = m.ebEalU;
    }
    action JQMbZ(bit<64> tLwT, bit<64> wmXq) {
        m.SSBVUQ = 6057 + sm.enq_qdepth;
    }
    action xEgOi() {
        m.BckpYg = m.gVDnEQ;
    }
    action TAISK(bit<16> hhzn, bit<4> zdqU) {
        h.eth_hdr.dst_addr = 7537;
    }
    action bqjRP(bit<64> IJLm) {
        h.ipv4_hdr.srcAddr = m.oNMtBh;
    }
    action JVFxO(bit<128> uNmI, bit<128> XFzH) {
        m.UMuqJS = sm.instance_type + m.KhqMOv;
    }
    action ReToP() {
        m.dffbJU = m.dffbJU;
    }
    action xxDWh(bit<128> EoXt) {
        m.XGYSrw = m.kVtYuN - 13w7574 - 13w3671 + 9566;
    }
    action Jdgcb(bit<64> TcbI, bit<4> nxVK) {
        h.ipv4_hdr.ihl = 8139;
    }
    action amphv(bit<16> oCrZ) {
        h.ipv4_hdr.flags = 3w7 + 3w5 - 3w4 + 3w6;
    }
    action jWsji(bit<64> Psqo) {
        m.YaEemy = m.JCsZqU - (13w1777 + m.COkbRT - m.Yzfrde);
    }
    action KcJqQ() {
        h.tcp_hdr.ackNo = m.ZayOsg + (m.fCSphg - 32w9502) - 32w317;
    }
    action kXViD(bit<16> QCDI) {
        m.CDHPbg = m.VPWJjR + h.ipv4_hdr.hdrChecksum;
    }
    action WajTG(bit<4> DaaO) {
        h.tcp_hdr.srcPort = m.IneAus;
    }
    action JshYA(bit<128> PIBw) {
        m.XFCcmo = m.qZwGsp + (32w2275 - 32w2499) - m.UMuqJS;
    }
    action DziAK(bit<128> spsd, bit<4> wHOO) {
        m.TItDCZ = m.TItDCZ;
    }
    action ATscb(bit<32> GhkN, bit<4> UDch) {
        h.tcp_hdr.seqNo = m.KhqMOv - (32w2380 + 32w392 - 32w9655);
    }
    action CqJFV(bit<128> FBMR) {
        m.HLJhUf = 1292;
    }
    action OIpeh(bit<4> Ejqj, bit<16> oRMn) {
        m.XFCcmo = m.eRqDVx + m.UMuqJS;
    }
    action dsyQq(bit<8> bbYl, bit<64> rjPF) {
        h.ipv4_hdr.flags = m.OPTsWY;
    }
    action AtsgT(bit<8> Fial) {
        m.lOZOop = m.lOZOop;
    }
    action zpCIV(bit<64> uiAy, bit<64> wWqD) {
        m.qZwGsp = m.XFCcmo;
    }
    action ALBxs(bit<64> jSXB, bit<64> oalA) {
        h.ipv4_hdr.protocol = 7747;
    }
    action ejioR(bit<64> Hzoo) {
        m.BckpYg = m.ZKRNvI + sm.egress_spec;
    }
    action OqbXV(bit<128> PBuG) {
        m.CDHPbg = m.zABEOq;
    }
    action WPEsz(bit<32> oxKO, bit<16> pvLK) {
        h.eth_hdr.src_addr = m.FenUfS;
    }
    action PadBX() {
        m.xQrGMi = 1469 + 64w7006 - 64w7621 + 64w1930;
    }
    action DldUK(bit<8> OCnK) {
        m.nrUHbX = m.nrUHbX;
    }
    action JUkDZ() {
        h.ipv4_hdr.protocol = 8393;
    }
    action GrRBG() {
        m.XFCcmo = m.reqFaF;
    }
    action vVMdW(bit<8> qRgx) {
        h.eth_hdr.src_addr = m.VsCEkF;
    }
    action wIuno(bit<4> SNyf) {
        m.HLJhUf = 2723 + m.daeDUw;
    }
    action MvrDx(bit<8> JXWB) {
        h.ipv4_hdr.flags = m.RBerTa;
    }
    action sXFhv(bit<64> yyVB) {
        m.RGISep = m.ECVyWL;
    }
    action kXIVp(bit<4> wbKH) {
        m.eRobBy = 5646 + 2851 + m.QWrfXb + m.YaEemy;
    }
    table CTNBlN {
        key = {
            m.ZUKwDZ: exact @name("ZESduC") ;
            m.LLYpou: exact @name("nnCPtd") ;
        }
        actions = {
            PQQfa();
        }
    }
    table rMCgLR {
        key = {
            h.ipv4_hdr.srcAddr: exact @name("jadGoF") ;
        }
        actions = {
            drop();
            ATscb();
        }
    }
    table jpAHco {
        key = {
            m.HwiMJv: exact @name("fLrqUR") ;
        }
        actions = {
            WPEsz();
            JUkDZ();
        }
    }
    table XPhGYt {
        key = {
            m.eYQQzF: lpm @name("UAMNEa") ;
            m.olyugp: exact @name("OOonnb") ;
        }
        actions = {
            WajTG();
            DldUK();
        }
    }
    table YHjCNS {
        key = {
            m.IDmbpH: exact @name("JeDEVw") ;
        }
        actions = {
            ATscb();
            PQQfa();
        }
    }
    table HiQyje {
        key = {
            m.ngIzGE: lpm @name("SSjOHR") ;
            m.eiefPs: exact @name("pcZYNA") ;
        }
        actions = {
            drop();
            bqjRP();
        }
    }
    table qtSoXN {
        key = {
            m.TwqtSG: lpm @name("Hzwhec") ;
            m.VsCEkF: exact @name("OXRsoN") ;
        }
        actions = {
            GrRBG();
            ggIyu();
        }
    }
    table zhimbd {
        key = {
            h.ipv4_hdr.totalLen: lpm @name("rdDJwx") ;
            m.lbWyBM           : exact @name("flVnlj") ;
        }
        actions = {
            amphv();
        }
    }
    table ZDPizi {
        key = {
            m.YaEemy: exact @name("FHNODu") ;
        }
        actions = {
            jWsji();
            drop();
        }
    }
    table dESCWV {
        key = {
            m.KAoYQo: ternary @name("qdhNqc") ;
        }
        actions = {
            AtsgT();
        }
    }
    table RTReDd {
        key = {
            m.ngIzGE: lpm @name("CUqMdA") ;
        }
        actions = {
            kNVAj();
        }
    }
    table PIGZyQ {
        key = {
            sm.egress_global_timestamp: exact @name("YnUniM") ;
        }
        actions = {
        }
    }
    table IUCAju {
        key = {
            m.vyREwV: ternary @name("fbwDwn") ;
            m.upQCYx: ternary @name("TyHsXS") ;
            m.mEOLiZ: ternary @name("YSMtrT") ;
        }
        actions = {
            drop();
        }
    }
    table akkrLk {
        key = {
            m.eRqDVx: lpm @name("wxfoup") ;
            m.VsCEkF: exact @name("oOXwFB") ;
            m.aKcwfD: exact @name("AiWoAB") ;
        }
        actions = {
            sXFhv();
            PQQfa();
        }
    }
    table vsQQiM {
        key = {
            m.bDmKHf: exact @name("qBiIhs") ;
        }
        actions = {
            ALBxs();
        }
    }
    table gmmPnt {
        key = {
            h.ipv4_hdr.ttl: lpm @name("wvkwJM") ;
            m.EPBDAV      : exact @name("vRMjTR") ;
            m.UMuqJS      : exact @name("DjMwFp") ;
        }
        actions = {
            drop();
            wIuno();
        }
    }
    table wMuqDb {
        key = {
            m.nWIelt: lpm @name("teXIsL") ;
        }
        actions = {
        }
    }
    table tNCulc {
        key = {
            m.rgebQB: lpm @name("thwJEW") ;
            m.hTLQfc: exact @name("KmMwVY") ;
        }
        actions = {
            zpCIV();
        }
    }
    table thQnku {
        key = {
            m.bDmKHf: lpm @name("MXeCtR") ;
        }
        actions = {
            AtsgT();
        }
    }
    table yiOtwc {
        key = {
            m.KIfJZv: ternary @name("SFSUJh") ;
            m.mwxYYL: ternary @name("vREfLg") ;
        }
        actions = {
        }
    }
    table DYeqqo {
        key = {
            m.hTLQfc: ternary @name("mOomnD") ;
            m.pNylwh: exact @name("FQruwZ") ;
        }
        actions = {
            zPHIl();
        }
    }
    apply {
        rMCgLR.apply();
        if (m.ngIzGE != m.xQrGMi - m.NEeKCX) {
            IUCAju.apply();
            tNCulc.apply();
        } else {
            RTReDd.apply();
            XPhGYt.apply();
            wMuqDb.apply();
        }
        HiQyje.apply();
        jpAHco.apply();
        gmmPnt.apply();
        if (h.ipv4_hdr.isValid()) {
            akkrLk.apply();
            zhimbd.apply();
            thQnku.apply();
        } else {
            ZDPizi.apply();
        }
        PIGZyQ.apply();
        if (h.eth_hdr.isValid()) {
            YHjCNS.apply();
        } else {
            dESCWV.apply();
        }
        vsQQiM.apply();
        yiOtwc.apply();
        DYeqqo.apply();
        CTNBlN.apply();
        if (h.eth_hdr.isValid()) {
            qtSoXN.apply();
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
