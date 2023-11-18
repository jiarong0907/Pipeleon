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
    bit<3>  EHnRZW;
    bit<3>  glJNcU;
    bit<3>  KbldIm;
    bit<3>  UlWwKG;
    bit<3>  ZkAGaD;
    bit<3>  XBGkFz;
    bit<3>  WDMJvE;
    bit<3>  RReYUK;
    bit<3>  DmqMGp;
    bit<3>  aihCRO;
    bit<3>  pPKGie;
    bit<3>  XtfoQC;
    bit<3>  SCGRxQ;
    bit<3>  DWviFn;
    bit<3>  gHxlcC;
    bit<3>  gqjuKu;
    bit<3>  dPwcwk;
    bit<3>  CpYfmw;
    bit<3>  eQOxlg;
    bit<3>  bCfLTv;
    bit<3>  gECdhh;
    bit<3>  tMpUUO;
    bit<4>  sHngkW;
    bit<4>  hYVDpC;
    bit<4>  jDdPMr;
    bit<4>  xGIuWf;
    bit<4>  TGnYNx;
    bit<4>  KpGLEj;
    bit<4>  INlNZi;
    bit<4>  gBhTvq;
    bit<4>  ISNyDD;
    bit<4>  RJSPxz;
    bit<4>  OrHgzH;
    bit<4>  TCQAag;
    bit<4>  NRTfIU;
    bit<4>  UiRlEu;
    bit<4>  eATQGG;
    bit<4>  xWDjad;
    bit<4>  BarCGT;
    bit<4>  lxUgHZ;
    bit<4>  gYNwfe;
    bit<4>  ixpndG;
    bit<4>  bKtABz;
    bit<4>  GgJYHP;
    bit<8>  zUroqo;
    bit<8>  NEWRiK;
    bit<8>  gtxyEe;
    bit<8>  UcyWFY;
    bit<8>  RVGYFp;
    bit<8>  GkzuDW;
    bit<8>  zgBlFL;
    bit<8>  pImBbT;
    bit<8>  uQSXIO;
    bit<8>  qukDpt;
    bit<8>  fhKsCF;
    bit<8>  afucjt;
    bit<8>  hFmIDa;
    bit<8>  JeucHp;
    bit<8>  CLRQKW;
    bit<8>  NfXqvv;
    bit<8>  wMnAlX;
    bit<8>  FPlYRH;
    bit<8>  RnHsbT;
    bit<8>  RokLIY;
    bit<8>  GVWZgP;
    bit<8>  BmrUKN;
    bit<9>  CAxRUR;
    bit<9>  EpIlEV;
    bit<9>  YhKOOF;
    bit<9>  POQGRg;
    bit<9>  HhznSX;
    bit<9>  BGZrCI;
    bit<9>  MwWSvK;
    bit<9>  iDfqMs;
    bit<9>  KbUdGH;
    bit<9>  mCPOgQ;
    bit<9>  fuzcvJ;
    bit<9>  vuPzPu;
    bit<9>  RVTUXk;
    bit<9>  dkgEcE;
    bit<9>  BnAIPP;
    bit<9>  xEusWS;
    bit<9>  GYfnzJ;
    bit<9>  frABNt;
    bit<9>  QYnWLf;
    bit<9>  xKQxlo;
    bit<9>  EFPenb;
    bit<9>  PMCBLv;
    bit<13> qtzrxM;
    bit<13> TzAEAk;
    bit<13> WvthkH;
    bit<13> mboSAJ;
    bit<13> CZYNQC;
    bit<13> gNJuyu;
    bit<13> OCWVQQ;
    bit<13> fAeYfK;
    bit<13> vUXybM;
    bit<13> REnNkX;
    bit<13> gIUSgY;
    bit<13> hcQMpq;
    bit<13> AvwVuw;
    bit<13> lTRyWD;
    bit<13> TTidCb;
    bit<13> FhnItU;
    bit<13> bewCkV;
    bit<13> XkWlBi;
    bit<13> svGUuq;
    bit<13> HJrQhb;
    bit<13> CedXMn;
    bit<13> ceGVvB;
    bit<16> fLywNM;
    bit<16> LnrxKi;
    bit<16> iIdFMt;
    bit<16> bBltjv;
    bit<16> nHObnD;
    bit<16> wUjaLG;
    bit<16> qIXqiE;
    bit<16> NEfRmS;
    bit<16> YDkLFd;
    bit<16> PkGsPl;
    bit<16> NzkqBt;
    bit<16> ytgHmn;
    bit<16> TCuRlb;
    bit<16> yAxFWc;
    bit<16> atGHLl;
    bit<16> vuprEp;
    bit<16> PJwlMB;
    bit<16> BBcgyl;
    bit<16> FZiEfC;
    bit<16> GFfwOi;
    bit<16> gBAQQS;
    bit<16> sQHHNc;
    bit<19> HpcFYs;
    bit<19> nSYftj;
    bit<19> cdzUQG;
    bit<19> qxUYFD;
    bit<19> kOzgzB;
    bit<19> gfIVEx;
    bit<19> igWFuD;
    bit<19> WVVdvG;
    bit<19> BiVOTS;
    bit<19> SZuFOl;
    bit<19> lzFtlh;
    bit<19> UmJobv;
    bit<19> MqgFTq;
    bit<19> fwjwmQ;
    bit<19> JHnwqv;
    bit<19> gGMfaO;
    bit<19> lMtuyx;
    bit<19> OfGZDn;
    bit<19> oarHBN;
    bit<19> aWTDRn;
    bit<19> iOJdBv;
    bit<19> uFPfnX;
    bit<32> FvnUJT;
    bit<32> HawoeN;
    bit<32> hWrvxO;
    bit<32> feHRCg;
    bit<32> VBHHTo;
    bit<32> XzKcpD;
    bit<32> EUmdZU;
    bit<32> HgHlNp;
    bit<32> SyglmC;
    bit<32> qrrrjF;
    bit<32> dqDLdN;
    bit<32> xyqSRn;
    bit<32> MdoBsW;
    bit<32> pkYBlm;
    bit<32> CGdRjp;
    bit<32> JZZrQx;
    bit<32> vgOmEx;
    bit<32> JIwZeh;
    bit<32> ybDZaO;
    bit<32> UPkDAs;
    bit<32> JVvLxz;
    bit<32> yWQkjj;
    bit<48> veQqYw;
    bit<48> bKjZps;
    bit<48> aXEfvc;
    bit<48> SxwQJg;
    bit<48> HoOYHI;
    bit<48> roIMyV;
    bit<48> NFzRuX;
    bit<48> kykbKM;
    bit<48> UokoUx;
    bit<48> tRqTGL;
    bit<48> BzfDjA;
    bit<48> NVQvES;
    bit<48> oCTsDv;
    bit<48> hNieTz;
    bit<48> dIwLJa;
    bit<48> SWwuZW;
    bit<48> vZeBZb;
    bit<48> bhPxeE;
    bit<48> xQmuLy;
    bit<48> UdKjti;
    bit<48> hKgskl;
    bit<48> TccoMh;
    bit<64> oJDoyJ;
    bit<64> VGpJEN;
    bit<64> dVYlGu;
    bit<64> daqorJ;
    bit<64> EzFpTo;
    bit<64> ZbWSFL;
    bit<64> AWXACj;
    bit<64> xeXGav;
    bit<64> WlUEwp;
    bit<64> LyHhaK;
    bit<64> NkpjEM;
    bit<64> MvQFnV;
    bit<64> XWXjql;
    bit<64> PBWjBx;
    bit<64> tSBXJZ;
    bit<64> zHmwIY;
    bit<64> eJPNhm;
    bit<64> FvosJg;
    bit<64> ExPFeJ;
    bit<64> gOUrQr;
    bit<64> YMicaA;
    bit<64> ibuAms;
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
    action gmhhW() {
        m.zHmwIY = m.NkpjEM;
    }
    action HCytX(bit<64> Neea) {
        h.tcp_hdr.res = m.jDdPMr;
    }
    action klREU() {
        m.wMnAlX = m.zUroqo;
    }
    action VxKXy(bit<32> erGh, bit<64> qtct) {
        m.RJSPxz = 4w13 - m.RJSPxz - m.INlNZi + m.bKtABz;
    }
    action ZMLPO() {
        m.ExPFeJ = 323;
    }
    action cWffL(bit<16> afML, bit<4> SHYc) {
        m.ZkAGaD = m.RReYUK;
    }
    action kpAmb() {
        m.eJPNhm = m.EzFpTo;
    }
    action VTErL(bit<4> MGsB, bit<8> aqij) {
        m.RVTUXk = sm.egress_port;
    }
    action yIBjE(bit<8> Cagp, bit<64> qMBi) {
        m.igWFuD = m.nSYftj;
    }
    action TqPGV(bit<128> yHkU) {
        m.iDfqMs = m.POQGRg;
    }
    action fHRNU(bit<4> EJEj) {
        h.eth_hdr.dst_addr = 48w3582 + 48w1756 - sm.ingress_global_timestamp - 48w5575;
    }
    action SWkhf() {
        h.ipv4_hdr.totalLen = 16w9525 + m.bBltjv - m.iIdFMt + 16w9027;
    }
    action zZhne(bit<8> hetu) {
        m.bCfLTv = 4561 - (m.glJNcU - (m.aihCRO - m.XtfoQC));
    }
    action mgRDh() {
        m.gfIVEx = m.gGMfaO - m.iOJdBv;
    }
    action bPHYq() {
        m.tSBXJZ = m.XWXjql;
    }
    action XhyHW() {
        m.gBhTvq = 2871 + (9008 + 272);
    }
    action rJrvk() {
        h.tcp_hdr.flags = m.UcyWFY - (8w249 + 8w51) - m.hFmIDa;
    }
    action OMvyi(bit<128> ZGfP, bit<4> QjsJ) {
        h.ipv4_hdr.hdrChecksum = m.NEfRmS;
    }
    action GXLwI() {
        m.CpYfmw = sm.priority + 6536 + m.gECdhh;
    }
    action VPgrL(bit<4> EEpg) {
        h.tcp_hdr.checksum = m.YDkLFd - m.FZiEfC;
    }
    action VFPGg(bit<4> rwsE, bit<128> BTZL) {
        h.ipv4_hdr.fragOffset = m.qtzrxM;
    }
    action oetUv(bit<32> vOFf, bit<32> aBlq) {
        m.gOUrQr = 6972 + 64w1668 + m.ZbWSFL + m.AWXACj;
    }
    action FykCa(bit<32> qUUS) {
        h.eth_hdr.src_addr = m.TccoMh + (m.bKjZps - m.bKjZps + 48w4004);
    }
    action IRmrD(bit<32> ZPFZ) {
        m.yWQkjj = m.SyglmC - (7132 - 32w6708) - 32w1432;
    }
    action UKJQa(bit<16> qmtX) {
        m.SZuFOl = m.gfIVEx + m.aWTDRn;
    }
    action UxPuV() {
        h.ipv4_hdr.fragOffset = m.CZYNQC;
    }
    action dPAkw(bit<8> nUir, bit<4> wReL) {
        m.AWXACj = 361 + m.ZbWSFL;
    }
    action buJxl() {
        m.MqgFTq = m.OfGZDn;
    }
    action BekkA() {
        h.ipv4_hdr.diffserv = m.NfXqvv;
    }
    action MpGjb(bit<4> zZgR, bit<32> aMXG) {
        m.tSBXJZ = 5781 + m.FvosJg;
    }
    action lKShi(bit<4> igxa, bit<32> kaNi) {
        m.SyglmC = m.FvnUJT;
    }
    action ZCZXx(bit<16> NbBz) {
        m.TCuRlb = m.vuprEp;
    }
    action imtHp(bit<8> lPss) {
        m.fhKsCF = m.GVWZgP;
    }
    action dkHfE(bit<4> hdxh) {
        m.mCPOgQ = m.BGZrCI + (m.mCPOgQ - 9w461) - 3931;
    }
    action yQGca(bit<128> LrSS, bit<128> ZVYP) {
        h.eth_hdr.src_addr = m.UdKjti;
    }
    action DnEck(bit<4> OZvd) {
        h.ipv4_hdr.totalLen = m.sQHHNc;
    }
    action WRajL(bit<8> mDtx) {
        m.SxwQJg = m.UokoUx;
    }
    action qdSpB(bit<8> cSkS, bit<128> YiLy) {
        m.AWXACj = m.zHmwIY;
    }
    action jquCw() {
        m.svGUuq = m.ceGVvB + m.HJrQhb;
    }
    action Kyomm() {
        m.BnAIPP = m.POQGRg - m.iDfqMs - m.RVTUXk;
    }
    action eDQKr() {
        h.ipv4_hdr.ihl = m.bKtABz;
    }
    action tAiiE() {
        h.ipv4_hdr.dstAddr = m.qrrrjF;
    }
    action WKlcg() {
        m.NzkqBt = 6658 - (16w2454 + 16w7988) - h.tcp_hdr.srcPort;
    }
    action zSKZz(bit<8> Idnj, bit<16> LWnW) {
        h.tcp_hdr.srcPort = m.qIXqiE;
    }
    action WQJaf() {
        m.ibuAms = m.daqorJ + m.YMicaA - (64w7751 - m.tSBXJZ);
    }
    action rokPJ(bit<8> aBLu) {
        m.cdzUQG = m.SZuFOl;
    }
    action VcvfH(bit<8> Abfg) {
        m.pImBbT = m.NEWRiK;
    }
    action iAwES(bit<8> jrUe) {
        h.tcp_hdr.dataOffset = h.tcp_hdr.dataOffset - h.ipv4_hdr.ihl;
    }
    action RVGju(bit<8> eAdX) {
        m.ceGVvB = m.TzAEAk;
    }
    action DbMVa(bit<64> bsYh) {
        h.ipv4_hdr.fragOffset = h.ipv4_hdr.fragOffset;
    }
    action OiExf() {
        h.ipv4_hdr.srcAddr = 6791;
    }
    action rhQtY() {
        h.ipv4_hdr.protocol = m.pImBbT;
    }
    action GdjzT(bit<4> DpDl, bit<8> SeCK) {
        h.tcp_hdr.urgentPtr = 3738 + m.YDkLFd;
    }
    action QEfzw(bit<8> xMOW, bit<8> AgjL) {
        m.MdoBsW = m.yWQkjj;
    }
    action MqdSM() {
        m.JHnwqv = 7403 + (m.qxUYFD - m.JHnwqv) - 19w6536;
    }
    action BMSin(bit<128> brMi, bit<8> GFOB) {
        m.BzfDjA = m.xQmuLy;
    }
    action DwIul(bit<128> WVDx, bit<8> awsF) {
        h.ipv4_hdr.fragOffset = m.REnNkX;
    }
    action IEKcB(bit<64> gETL) {
        h.tcp_hdr.ackNo = 1059;
    }
    action gDKAp(bit<32> DoEs, bit<16> Yara) {
        m.OfGZDn = m.SZuFOl + 709;
    }
    action FpdGQ(bit<16> XEBZ, bit<16> XwtA) {
        h.ipv4_hdr.fragOffset = m.TzAEAk;
    }
    action VsYSC(bit<32> DjcX) {
        h.ipv4_hdr.fragOffset = 9338;
    }
    action QgQoF(bit<64> wbea) {
        h.ipv4_hdr.flags = m.UlWwKG;
    }
    action rErQU(bit<4> TsLw) {
        m.SCGRxQ = 3969;
    }
    action rLTsc(bit<128> mTxT, bit<128> cwwP) {
        m.gfIVEx = m.qxUYFD - m.UmJobv;
    }
    action sjkKO(bit<32> cBrd, bit<4> mEZR) {
        m.YMicaA = 8322;
    }
    action KTisl() {
        h.ipv4_hdr.flags = 7365 - m.KbldIm + m.ZkAGaD;
    }
    action HHExR(bit<32> TmBC, bit<128> bnlQ) {
        m.UlWwKG = sm.priority;
    }
    action MeLqB() {
        m.ybDZaO = 9089;
    }
    action UKzos(bit<16> MlmA) {
        h.tcp_hdr.seqNo = m.feHRCg + (h.tcp_hdr.seqNo - m.xyqSRn);
    }
    action JECbP(bit<32> kNEz, bit<4> ylsg) {
        h.ipv4_hdr.flags = m.ZkAGaD + m.aihCRO - (3w4 + 3w3);
    }
    action USWeR(bit<128> BfVM, bit<16> nelD) {
        h.ipv4_hdr.hdrChecksum = 5025;
    }
    action JqSvW(bit<128> jDDR, bit<4> TYCv) {
        m.lTRyWD = h.ipv4_hdr.fragOffset;
    }
    action uYfSw(bit<16> udqk) {
        h.eth_hdr.src_addr = m.HoOYHI + sm.egress_global_timestamp - (5400 + m.SxwQJg);
    }
    action hUBiQ(bit<64> jbhJ) {
        m.lxUgHZ = m.hYVDpC - m.ISNyDD;
    }
    action voFqx(bit<128> qLEC, bit<32> UEkJ) {
        h.ipv4_hdr.flags = m.XBGkFz - m.tMpUUO - m.eQOxlg - 3w3;
    }
    action jweXg(bit<32> Plre, bit<128> XhDy) {
        m.dVYlGu = m.oJDoyJ;
    }
    action jQhtg(bit<4> gqpu, bit<128> kSwS) {
        m.GgJYHP = m.INlNZi;
    }
    action wlRnG(bit<8> yObu) {
        m.dqDLdN = m.UPkDAs;
    }
    action UKhcX(bit<4> JJUQ) {
        m.LyHhaK = m.ibuAms + (m.YMicaA + m.ExPFeJ);
    }
    table PgrzhH {
        key = {
            m.NkpjEM: exact @name("eJNonD") ;
        }
        actions = {
            lKShi();
            UxPuV();
        }
    }
    table aPpkXt {
        key = {
            m.aihCRO: exact @name("thSrsn") ;
            m.HpcFYs: exact @name("kgJNvA") ;
        }
        actions = {
            MeLqB();
            GXLwI();
        }
    }
    table SiPVQE {
        key = {
            m.GVWZgP: lpm @name("OaoLRK") ;
        }
        actions = {
            OiExf();
            MeLqB();
        }
    }
    table dAtaJw {
        key = {
            m.nSYftj: lpm @name("RrZzlO") ;
        }
        actions = {
        }
    }
    table STDjjL {
        key = {
            m.qukDpt: ternary @name("lyQHBM") ;
            m.eQOxlg: ternary @name("GNrLFr") ;
            m.zUroqo: exact @name("dRPmXu") ;
        }
        actions = {
            eDQKr();
            SWkhf();
        }
    }
    table PhRDbY {
        key = {
            sm.egress_spec: exact @name("YPwpeP") ;
        }
        actions = {
        }
    }
    table MBFKsO {
        key = {
            m.tMpUUO: exact @name("bDkeal") ;
        }
        actions = {
            drop();
            ZCZXx();
        }
    }
    table zNhKOc {
        key = {
            m.GkzuDW: lpm @name("OOKzAG") ;
        }
        actions = {
            SWkhf();
        }
    }
    table bVdZmn {
        key = {
            m.WvthkH: lpm @name("hrXtEM") ;
            m.LyHhaK: exact @name("ECWOsI") ;
        }
        actions = {
            hUBiQ();
            GXLwI();
        }
    }
    table eZWisl {
        key = {
            m.DWviFn                  : ternary @name("WFUQrE") ;
            sm.egress_global_timestamp: ternary @name("kmnvyj") ;
            m.nHObnD                  : ternary @name("CnqORe") ;
        }
        actions = {
            kpAmb();
        }
    }
    table DlhDbi {
        key = {
            sm.enq_qdepth: lpm @name("DmCQwi") ;
            m.aihCRO     : exact @name("DPyCuL") ;
            m.xQmuLy     : exact @name("tiVZJB") ;
        }
        actions = {
            VPgrL();
        }
    }
    table FrVrKY {
        key = {
            h.ipv4_hdr.ihl: exact @name("RzwQdp") ;
        }
        actions = {
            VsYSC();
        }
    }
    table npRIyq {
        key = {
            m.OrHgzH: lpm @name("HZEEjB") ;
            m.qIXqiE: exact @name("lWThjC") ;
            m.xyqSRn: exact @name("ZHWXjA") ;
        }
        actions = {
            drop();
            wlRnG();
        }
    }
    table BXmCrS {
        key = {
            m.bBltjv: exact @name("VUIDlB") ;
        }
        actions = {
            VxKXy();
            zSKZz();
        }
    }
    table pZNHro {
        key = {
            m.UokoUx          : exact @name("nYgzPF") ;
            m.DWviFn          : exact @name("IezQBw") ;
            h.ipv4_hdr.dstAddr: exact @name("yAlHfI") ;
        }
        actions = {
            GdjzT();
        }
    }
    table uyXpjZ {
        key = {
            m.KbldIm: lpm @name("mfOPoE") ;
            m.XkWlBi: exact @name("XOMmjb") ;
            m.SWwuZW: exact @name("UjhWfk") ;
        }
        actions = {
            VPgrL();
        }
    }
    table gUeBhe {
        key = {
            m.bewCkV: lpm @name("nJveFV") ;
        }
        actions = {
            ZCZXx();
            IRmrD();
        }
    }
    table fsytus {
        key = {
            m.PMCBLv: exact @name("HnTgaa") ;
        }
        actions = {
            tAiiE();
            MqdSM();
        }
    }
    table CZkZiL {
        key = {
            m.uFPfnX: ternary @name("FvcjyZ") ;
        }
        actions = {
            GdjzT();
            ZMLPO();
        }
    }
    table LmTxKD {
        key = {
            m.tSBXJZ: lpm @name("thBrED") ;
        }
        actions = {
            JECbP();
        }
    }
    table UOYFPH {
        key = {
            m.WlUEwp: ternary @name("XDoWyv") ;
            m.RJSPxz: ternary @name("xoBkZl") ;
        }
        actions = {
            IEKcB();
        }
    }
    apply {
        bVdZmn.apply();
        BXmCrS.apply();
        uyXpjZ.apply();
        npRIyq.apply();
        if (h.ipv4_hdr.isValid()) {
            SiPVQE.apply();
            LmTxKD.apply();
            CZkZiL.apply();
            if (h.eth_hdr.isValid()) {
                gUeBhe.apply();
                if (h.tcp_hdr.isValid()) {
                    FrVrKY.apply();
                    aPpkXt.apply();
                    if (m.yWQkjj + h.ipv4_hdr.srcAddr + m.MdoBsW - 32w5889 != 32w5483) {
                        dAtaJw.apply();
                        STDjjL.apply();
                    } else {
                        fsytus.apply();
                        MBFKsO.apply();
                    }
                } else {
                    pZNHro.apply();
                    UOYFPH.apply();
                    if (h.eth_hdr.isValid()) {
                        DlhDbi.apply();
                        PgrzhH.apply();
                    } else {
                        eZWisl.apply();
                        zNhKOc.apply();
                        PhRDbY.apply();
                    }
                }
            } else {
            }
        } else {
        }
        bit<16> MqzVQb = h.tcp_hdr.window;
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
