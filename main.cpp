#include <iostream>
#include <fstream>
#include "string.h"
#include "winsock2.h"
using namespace std;

//选择wireshark的  *.pcap 方式进行构造和解析，格式如下
typedef unsigned int    bpf_u_int32;        //32位  4字节
//typedef unsigned short  u_short;            //16位  2字节
typedef int             bpf_int32;          //32位  4字节
typedef unsigned char   u_int8_t;           //8位   1字节
typedef unsigned short int u_int16_t;       //16位  2字节
typedef unsigned int    u_int32_t;          //32位  4字节
typedef unsigned long long    u_int64_t;          //64位  4字节
//pcap文件头  24字节
typedef struct pcap_file_header
{
    bpf_u_int32 magic;      //标记文件开始，并用来识别文件和字节顺序。值可以为0xa1b2c3d4或者0xd4c3b2a1，如果是0xa1b2c3d4表示是大端模式，按照原来的顺序一个字节一个字节的读，如果是0xd4c3b2a1表示小端模式，下面的字节都要交换顺序。现在的电脑大部分是小端模式。
    u_int16_t version_major;  //当前文件的主要版本号，一般为0x0200
    u_int16_t version_minor;  //当前文件的次要版本号，一般为0x0400
    bpf_int32 thiszone;     //当地的标准事件，如果用的是GMT则全零，一般全零
    bpf_u_int32 sigfigs;    //时间戳的精度，一般为全零
    bpf_u_int32 snaplen;    //最大的存储长度，设置所抓获的数据包的最大长度，如果所有数据包都要抓获，将值设置为65535
    bpf_u_int32 linktype;   //链路类型。解析数据包首先要判断它的LinkType，所以这个值很重要。一般的值为1，即以太网
}pcap_file_header;
//pcap小包头   16字节
typedef struct packet_header
{
    bpf_u_int32 timestamp_s;    //时间戳（秒）      32位  4字节
    bpf_u_int32 timestamp_ms;   //时间戳（微秒）    32位  4字节
    bpf_u_int32 capture_len;    //抓包长度（字节）  32位  4字节
    bpf_u_int32 len;            //实际长度（字节    32位  4字节
}packet_header;

//IP数据包格式   20字节
typedef struct ip_header
{
    u_int8_t      head_length : 4;  //总长度
    u_int8_t      version : 4;//版本号
    u_int8_t      tos;          //区分服务  service type
    u_int16_t     tos_length;      // 总长度   total len
    u_int16_t     id;           //标识
    u_int16_t     frag_off;     //片偏移      offset
    u_int8_t      ttl;          //生存时间  live time
    u_int8_t      protocol;     //协议
    u_int16_t     chk_sum;      //首部校验和    check sum
    u_int32_t     src_ip;      //源IP地址      source ip
    u_int32_t     dst_ip;      //目的IP地址    destnation ip
}ip_header;
//UDP首部格式   total length :8 Bytes
typedef struct udp_header
{
    u_int16_t src_port;     //源端口
    u_int16_t dst_port;     //目的端口
    u_int16_t data_length;          //长度
    u_int16_t chk_sum;      //检验和
} udp_header;

//ospf首部格式   total length :24 Bytes
typedef struct ospf_header
{
    u_int8_t  version;  //版本
    u_int8_t type;  //命令
    u_int16_t  packet_length;  //ospf包的总长度
    u_int32_t router_id;     //路由Id ,刚好为地址长度
    u_int32_t area_id;     //区域Id
    u_int16_t  checksum;  //校验和
    u_int16_t autype;     //验证类型
    u_int64_t authentication;     //鉴定字段
} ospf_header;

//ospf hello报文格式（一共5种。做出一种来，别的类似）   total length :24 Bytes
typedef struct ospf_hello
{
    u_int32_t net_mask;     //掩码
    u_int16_t  hello_interval;  //hello时间间隔
    u_int8_t options;  //可选项
    u_int8_t rtr_pri;  //DR优先级
    u_int32_t routerDead;     //失效时间
    u_int32_t des_router;     //DR接口地址
    u_int32_t backup_des_router;     //BDR接口地址
    u_int32_t neighbor;     //邻居
} ospf_hello;
//TCP头部   total length : 20Bytes
typedef struct tcp_header
{
    u_int16_t     src_port; //源端口   source port
    u_int16_t     dst_port; //目的端口 destination port
    u_int32_t     seq_no;   //序列号
    u_int32_t     ack_no;   //确认号
    u_int8_t      head_length ;          //头部长度  tcp header length
    u_int8_t      flag;         //标志位YRG ACK PSH RST SYN FIN

    u_int16_t     wnd_size; //窗口      16 bit windows
    u_int16_t     chk_sum;  //选项长度  16 bits check sum
    u_int16_t     urgt_p;   //紧急指针  16 urgent p
} tcp_header;

//rip格式   total length :24 Bytes
typedef struct rip
{
    u_int8_t command;  //命令
    u_int8_t  version;
    u_int16_t  zero;  //必为0字段
    u_int16_t address_family;     //地址族标识
    u_int16_t route_tag;     //路由标记
    u_int32_t ip_address;     //网络地址
    u_int32_t netmask;     //子网掩码
    u_int32_t next_hop;     //下一跳路由地址
    u_int32_t metric;          //距离

} rip_packet;
typedef struct tcp_check_subhdr {
    u_int32_t src_ip;
    u_int32_t dst_ip;
    u_int8_t all_zero;
    u_int8_t protocol;
    u_int16_t tcp_all_len;//tcp头部和数据部分的总长度
}tcp_check_subhdr;

//dns报文格式
typedef struct dns
{
    u_int16_t tran_id;     //事务ID
    u_int16_t flags;     //标志
    u_int16_t questions;          //问题计数
    u_int16_t answer_rrs;      //回答资源计数
    u_int16_t auth_rrs;      //服务器计数
    u_int16_t add_rrs;      //附加计数
} dns_packet;


//SMTP首部格式
typedef struct smtp_header {
    u_int8_t responsecode1;
    u_int8_t responsecode2;
    u_int8_t responsecode3;

}smtp_header;

//ftp首部格式
typedef struct ftp_header {
    u_int32_t  request_command;
    u_int16_t  request_arg;
    u_int16_t kong;  //其实是/r/n

}ftp_header;
//tcp选项
typedef struct tcp_options
{
    u_int16_t  kinds;        //
    u_int8_t kind;//
    u_int8_t length;
    u_int32_t timestamp;
    u_int32_t timestamp_echo_reply;
} tcp_options;
//MAC帧头（以太网） 14字节
typedef struct ether_header

{
    u_int8_t ether_dhost[6];        //6个字节   目的MAC地址
    u_int8_t ether_shost[6];        //6个字节   源MAC地址
    u_int16_t ether_type;           //2字节     类型ethernet type
} ether_header;
//解析rip已完成
int jiexi_rip() ;
//解析 ftp 完成
int jiexi_ftp();
//解析ospf已完成
int jiexi_ospf();
//解析smtp
int jiexi_smtp();
//dns只解析公共部分  （已完成）
int jiexi_dns();
u_int16_t get_ip_checksum(char*);
//完成
int createOspf();
int createSmtp();
//完成
int createftp();
int main() {

    //我们创建了解析报文的5个函数，和构造报文的3个函数，用哪个调用就行
//jiexi_ftp();
  // createftp();
 // createSmtp();

 //jiexi_smtp();
   // createOspf();
    createSmtp();
 /*int choose;
 string path="";

    while (1)
    {
        cout << "------------------------------" << endl;
        cout << "0 退出" << endl;
        cout << "1 解析报文" << endl;
        cout << "1 解析smtp报文" << endl;
        cout << "2 解析rip报文" << endl;
        cout << "3 构造SMTP报文" << endl;
        cout << "------------------------------" << endl;

        cin >> choose;
        switch (choose)
        {
            case 0:
            {
                return 1;
            }
            case 1: {
                cout << "输入解析路径（../rip2.pcap) (D:\\DHCP.pcap):";
                cin >> path;
                int i = jiexi(path);
                if (i == 0) {
                    cout << "解析错误" << endl;

                }
                break;
            }
       *//*     case 2: {
                int j =  WritePcap("D:\\smtp.pcap");
                if (j == 0) {
                    cout << "写入错误" << endl;
                }
                else
                {
                    cout << "构建smtp报文成功： D:\\smtp.pcap" << endl;
                }
                break;
            }*//*
            default:
                cout << "1" << endl;
                break;

        }
    }*/
    return 0;
}
//解析报文函数
//rip解析
int jiexi_rip() {
    //定义一个文件流来解析文件中的包
    ifstream ifs;
    ifs.open("../packet/rip2.pcap",  ios::binary);

    if (!ifs.is_open()) {
        cout << "打开文件失败" << endl;
        return 0;
    }
    //pcap格式头     24 byte
    pcap_file_header pcaphdr;
    ifs.read((char *) &pcaphdr, sizeof(pcap_file_header));

    //packe_header格式头   16byte
    packet_header packethdr;
    ifs.read((char *) &packethdr, sizeof(packet_header));

    //以太网       14byte
    ether_header etherhdr;  //构建一个结构体
    u_int16_t ethertp = 0;   //以太网上层格式类型

    ifs.read((char *) &etherhdr, sizeof(ether_header));
    
    cout << "链路层" << endl;
    printf("源MAC地址：%02x:%02x:%02x:%02x:%02x:%02x\n",
           etherhdr.ether_shost[0],
           etherhdr.ether_shost[1],
           etherhdr.ether_shost[2],
           etherhdr.ether_shost[3],
           etherhdr.ether_shost[4],
           etherhdr.ether_shost[5]);
    printf("目的MAC地址：%02x:%02x:%02x:%02x:%02x:%02x\n",
           etherhdr.ether_dhost[0],
           etherhdr.ether_dhost[1],
           etherhdr.ether_dhost[2],
           etherhdr.ether_dhost[3],
           etherhdr.ether_dhost[4],
           etherhdr.ether_dhost[5]);
    cout << hex << "以太网类型：" << ntohs(etherhdr.ether_type) << endl;
    ethertp = ntohs(etherhdr.ether_type);
    //ethernet type为0x0800 则上层协议为IP协议
    if (ethertp == 0x0800) {
        ip_header iphdr;
        ifs.read((char *) &iphdr, sizeof(ip_header));
        u_int8_t protocol = iphdr.protocol;
        u_int32_t src_ip = (int) ntohl(iphdr.src_ip);
        u_int32_t dst_ip = (int) ntohl(iphdr.dst_ip);
        cout << "ip层" << endl;
        cout << "版本：" << (int) iphdr.version << endl;
        cout << "IP头长度（字节）：" << dec << ((int) iphdr.head_length) * 4 << endl;
        cout << "服务类型TOS：" << (int) iphdr.tos << endl;
        cout << "总长度：" << hex << ntohs(iphdr.tos_length) << endl;
        cout << "标识：" << hex << ntohs(iphdr.id) << endl;
        cout << "片偏移：" << hex << ntohs(iphdr.frag_off) << endl;
        cout << "生存时间：" << (int) iphdr.ttl << endl;
        cout << "上层协议标识：" << (int) iphdr.protocol << endl;
        cout << "头部校验和：" << hex << ntohs(iphdr.chk_sum) << endl;

        cout << "源IP地址："
             << dec << (src_ip >> 24) << "."
             << ((src_ip & 0x00ff0000) >> 16) << "."
             << ((src_ip & 0x0000ff00) >> 8) << "."
             << (src_ip & 0x000000ff) << endl;

        cout << "目的IP地址："
             << dec << (dst_ip >> 24) << "."
             << ((dst_ip & 0x00ff0000) >> 16) << "."
             << ((dst_ip & 0x0000ff00) >> 8) << "."
             << (dst_ip & 0x000000ff) << endl;
        cout << "IP首部长度：" << (int) iphdr.head_length * 4 << endl;
        //如果上层协议是udp的话
      if((int)protocol==17) {
                cout << "udp层" << endl;
                udp_header udphdr;
                ifs.read((char*)&udphdr, sizeof(udp_header));
                //数据部分的长度等于(int)udphdr.data_length - sizeof(udphdr);
                unsigned short int udp_datlen = (int)ntohs(iphdr.tos_length) - iphdr.head_length * 4 - sizeof(udphdr);
                u_int16_t port = ntohs(udphdr.dst_port);
                cout << "源端口：" << ntohs(udphdr.src_port) << endl;
                cout << "目的端口：" << port << endl;
                cout << "长度："<<ntohs((int)udphdr.data_length) << endl;
                cout << "校验和:" << hex << ntohs(udphdr.chk_sum) << endl;


                //继续解析rip协议
          cout << "--rip协议层---" << endl;

          rip_packet  ripPacket;
          ifs.read((char*)&ripPacket, sizeof(rip_packet));
          u_int32_t ip_address = (int) ntohl(ripPacket.ip_address);
          u_int32_t netmask = (int) ntohl(ripPacket.netmask);
          u_int32_t next_hop = (int) ntohl(ripPacket.next_hop);


          cout << "命令：" << ntohs( (int)ripPacket.command) << endl;
          cout << "版本：" << ntohs((int)ripPacket.version) << endl;
          cout << "地址族标示：" << ntohs((int)ripPacket.address_family) << endl;
          cout << "路由标记：" << ntohs((int)ripPacket.route_tag) << endl;

          cout << "网络地址："
               << dec << (ip_address >> 24) << "."
               << ((ip_address & 0x00ff0000) >> 16) << "."
               << ((ip_address & 0x0000ff00) >> 8) << "."
               << (ip_address & 0x000000ff) << endl;

          cout << "子网掩码："
               << dec << (netmask >> 24) << "."
               << ((netmask & 0x00ff0000) >> 16) << "."
               << ((netmask & 0x0000ff00) >> 8) << "."
               << (netmask & 0x000000ff) << endl;

          cout << "下一跳路由地址："
               << dec << (next_hop >> 24) << "."
               << ((next_hop & 0x00ff0000) >> 16) << "."
               << ((next_hop & 0x0000ff00) >> 8) << "."
               << (next_hop & 0x000000ff) << endl;


          cout << "距离：" <<ntohs( (int)ripPacket.metric) << endl;



        }
    }






    ifs.close();
}

//ospf解析(hello报文）
int jiexi_ospf() {
    //定义一个文件流来解析文件中的包
    ifstream ifs;
    ifs.open("../packet/ospf.pcap",  ios::binary);

    if (!ifs.is_open()) {
        cout << "打开文件失败" << endl;
        return 0;
    }
    //pcap格式头     24 byte
    pcap_file_header pcaphdr;
    ifs.read((char *) &pcaphdr, sizeof(pcap_file_header));

    //packe_header格式头   16byte
    packet_header packethdr;
    ifs.read((char *) &packethdr, sizeof(packet_header));

    //以太网       14byte
    ether_header etherhdr;  //构建一个结构体
    u_int16_t ethertp = 0;   //以太网上层格式类型

    ifs.read((char *) &etherhdr, sizeof(ether_header));

    cout << "链路层" << endl;
    printf("源MAC地址：%02x:%02x:%02x:%02x:%02x:%02x\n",
           etherhdr.ether_shost[0],
           etherhdr.ether_shost[1],
           etherhdr.ether_shost[2],
           etherhdr.ether_shost[3],
           etherhdr.ether_shost[4],
           etherhdr.ether_shost[5]);
    printf("目的MAC地址：%02x:%02x:%02x:%02x:%02x:%02x\n",
           etherhdr.ether_dhost[0],
           etherhdr.ether_dhost[1],
           etherhdr.ether_dhost[2],
           etherhdr.ether_dhost[3],
           etherhdr.ether_dhost[4],
           etherhdr.ether_dhost[5]);
    cout << hex << "以太网类型：" << ntohs(etherhdr.ether_type) << endl;
    ethertp = ntohs(etherhdr.ether_type);
    //ethernet type为0x0800 则上层协议为IP协议
    if (ethertp == 0x0800) {
        ip_header iphdr;
        ifs.read((char *) &iphdr, sizeof(ip_header));
        u_int8_t protocol = iphdr.protocol;
        u_int32_t src_ip = (int) ntohl(iphdr.src_ip);
        u_int32_t dst_ip = (int) ntohl(iphdr.dst_ip);
        cout << "ip层" << endl;
        cout << "版本：" << (int) iphdr.version << endl;
        cout << "IP头长度（字节）：" << dec << ((int) iphdr.head_length) * 4 << endl;
        cout << "服务类型TOS：" << (int) iphdr.tos << endl;
        cout << "总长度：" << hex << ntohs(iphdr.tos_length) << endl;
        cout << "标识：" << hex << ntohs(iphdr.id) << endl;
        cout << "片偏移：" << hex << ntohs(iphdr.frag_off) << endl;
        cout << "生存时间：" << (int) iphdr.ttl << endl;
        cout << "上层协议标识：" << (int) iphdr.protocol << endl;
        cout << "头部校验和：" << hex << ntohs(iphdr.chk_sum) << endl;

        cout << "源IP地址："
             << dec << (src_ip >> 24) << "."
             << ((src_ip & 0x00ff0000) >> 16) << "."
             << ((src_ip & 0x0000ff00) >> 8) << "."
             << (src_ip & 0x000000ff) << endl;

        cout << "目的IP地址："
             << dec << (dst_ip >> 24) << "."
             << ((dst_ip & 0x00ff0000) >> 16) << "."
             << ((dst_ip & 0x0000ff00) >> 8) << "."
             << (dst_ip & 0x000000ff) << endl;
        cout << "IP首部长度：" << (int) iphdr.head_length * 4 << endl;
        //如果上层协议是ospf的话


   /*     typedef struct ospf_header
        {
            u_int8_t  version;  //版本
            u_int8_t type;  //  类型
            u_int16_t  packet_length;  //ospf包的总长度
            u_int32_t router_id;     //路由Id ,刚好为地址长度
            u_int32_t area_id;     //区域Id
            u_int16_t  checksum;  //校验和
            u_int16_t autype;     //验证类型
            u_int64_t authentication;     //鉴定字段
        } ospf_header;*/

        if((int)protocol==89) {
            cout << "ospf层" << endl;
            ospf_header ospfHeader;
            ifs.read((char*)&ospfHeader, sizeof(ospf_header));
            cout << "版本：" <<(int)ospfHeader.version<< endl;
            cout << "类型：" << (int)ospfHeader.type << endl;
            cout << "长度：" << ntohs((int)ospfHeader.packet_length) << endl;
            u_int32_t router_id = (int) ntohl(ospfHeader.router_id);
            u_int32_t area_id = (int) ntohl(ospfHeader.area_id);
            cout << "router_id："
                 << dec << (router_id >> 24) << "."
                 << ((router_id & 0x00ff0000) >> 16) << "."
                 << ((router_id & 0x0000ff00) >> 8) << "."
                 << (router_id & 0x000000ff) << endl;

            cout << "area_id："
                 << dec << (area_id >> 24) << "."
                 << ((area_id & 0x00ff0000) >> 16) << "."
                 << ((area_id & 0x0000ff00) >> 8) << "."
                 << (area_id & 0x000000ff) << endl;
            cout << "校验和：" << ntohs((int)ospfHeader.checksum) << endl;
            cout << "验证类型：" << ntohs( (int)ospfHeader.autype) << endl;

            cout<<"ospf报文体："<<endl;


            ospf_hello ospfHello;
            ifs.read((char*)&ospfHello, sizeof(ospf_header));
            u_int32_t net_mask = (int) ntohl(ospfHello.net_mask);
            cout << "掩码："
                 << dec << (net_mask >> 24) << "."
                 << ((net_mask & 0x00ff0000) >> 16) << "."
                 << ((net_mask & 0x0000ff00) >> 8) << "."
                 << (net_mask & 0x000000ff) << endl;


            cout << "失效时间：" << ntohs((int)ospfHello.hello_interval) << endl;
            cout << "可选项：" << (int)ospfHello.options << endl;
            cout << "DR优先级：" << (int)ospfHello.rtr_pri << endl;
            cout << "失效时间：" << ntohs((int)ospfHello.routerDead) << endl;

            u_int32_t neighbor = (int) ntohl(ospfHello.neighbor);
            u_int32_t des_router = (int) ntohl(ospfHello.des_router);
            u_int32_t backup_des_router = (int) ntohl(ospfHello.backup_des_router);

            cout << "dr："
                 << dec << (des_router >> 24) << "."
                 << ((des_router & 0x00ff0000) >> 16) << "."
                 << ((des_router & 0x0000ff00) >> 8) << "."
                 << (des_router & 0x000000ff) << endl;
            cout << "bdr："
                 << dec << (backup_des_router >> 24) << "."
                 << ((backup_des_router & 0x00ff0000) >> 16) << "."
                 << ((backup_des_router & 0x0000ff00) >> 8) << "."
                 << (backup_des_router & 0x000000ff) << endl;
            cout << "邻居："
                 << dec << (neighbor >> 24) << "."
                 << ((neighbor & 0x00ff0000) >> 16) << "."
                 << ((neighbor & 0x0000ff00) >> 8) << "."
                 << (neighbor & 0x000000ff) << endl;
        }
    }
    ifs.close();
}

//ftp函数解析
//todo ftp
int jiexi_ftp() {
    //定义一个文件流来解析文件中的包
    ifstream ifs;
    ifs.open("../packet/ftp2.pcap",  ios::binary);

    if (!ifs.is_open()) {
        cout << "打开文件失败" << endl;
        return 0;
    }
    //pcap格式头     24 byte
    pcap_file_header pcaphdr;
    ifs.read((char *) &pcaphdr, sizeof(pcap_file_header));

    //packe_header格式头   16byte
    packet_header packethdr;
    ifs.read((char *) &packethdr, sizeof(packet_header));

    //以太网       14byte
    ether_header etherhdr;  //构建一个结构体
    u_int16_t ethertp = 0;   //以太网上层格式类型

    ifs.read((char *) &etherhdr, sizeof(ether_header));

    cout << "链路层" << endl;
    printf("源MAC地址：%02x:%02x:%02x:%02x:%02x:%02x\n",
           etherhdr.ether_shost[0],
           etherhdr.ether_shost[1],
           etherhdr.ether_shost[2],
           etherhdr.ether_shost[3],
           etherhdr.ether_shost[4],
           etherhdr.ether_shost[5]);
    printf("目的MAC地址：%02x:%02x:%02x:%02x:%02x:%02x\n",
           etherhdr.ether_dhost[0],
           etherhdr.ether_dhost[1],
           etherhdr.ether_dhost[2],
           etherhdr.ether_dhost[3],
           etherhdr.ether_dhost[4],
           etherhdr.ether_dhost[5]);
    cout << hex << "以太网类型：" << ntohs(etherhdr.ether_type) << endl;
    ethertp = ntohs(etherhdr.ether_type);
    //ethernet type为0x0800 则上层协议为IP协议
    if (ethertp == 0x0800) {
        ip_header iphdr;
        ifs.read((char *) &iphdr, sizeof(ip_header));
        u_int8_t protocol = iphdr.protocol;
        u_int32_t src_ip = (int) ntohl(iphdr.src_ip);
        u_int32_t dst_ip = (int) ntohl(iphdr.dst_ip);
        cout << "ip层" << endl;
        cout << "版本：" << (int) iphdr.version << endl;
        cout << "IP头长度（字节）：" << dec << ((int) iphdr.head_length) * 4 << endl;
        cout << "服务类型TOS：" << (int) iphdr.tos << endl;
        cout << "总长度：" << hex << ntohs(iphdr.tos_length) << endl;
        cout << "标识：" << hex << ntohs(iphdr.id) << endl;
        cout << "片偏移：" << hex << ntohs(iphdr.frag_off) << endl;
        cout << "生存时间：" << (int) iphdr.ttl << endl;
        cout << "上层协议标识：" << (int) iphdr.protocol << endl;
        cout << "头部校验和：" << hex << ntohs(iphdr.chk_sum) << endl;

        cout << "源IP地址："
             << dec << (src_ip >> 24) << "."
             << ((src_ip & 0x00ff0000) >> 16) << "."
             << ((src_ip & 0x0000ff00) >> 8) << "."
             << (src_ip & 0x000000ff) << endl;

        cout << "目的IP地址："
             << dec << (dst_ip >> 24) << "."
             << ((dst_ip & 0x00ff0000) >> 16) << "."
             << ((dst_ip & 0x0000ff00) >> 8) << "."
             << (dst_ip & 0x000000ff) << endl;
        cout << "IP首部长度：" << (int) iphdr.head_length * 4 << endl;
        //如果上层协议是tcp的话
        //tcp
       if ((int)protocol==6) {

                cout << "tcp层" << endl;
                tcp_header tcphdr;
                ifs.read((char*)&tcphdr, sizeof(tcp_header));
           u_int16_t src_port = (int) ntohl(tcphdr.src_port);
           u_int16_t dst_port = (int) ntohl(tcphdr.dst_port);

           cout << "源端口："<<"2052"<<endl;
           cout << "目的端口："<<"21"<<endl;
           cout << "序列号："<< hex<<htonl((int)tcphdr.seq_no)<<endl;
                cout << "确认号：" << hex<< htonl((int)tcphdr.ack_no) << endl;
                cout << "头部长度：" << hex<<(int)tcphdr.head_length << endl;
                cout << "标志位：" <<hex<<(int)tcphdr.flag << endl;
                cout << "窗体："<<htons((int)tcphdr.wnd_size) << endl;
                cout << "校验和：" <<hex <<htons((int)tcphdr.chk_sum) << endl;
                cout << "紧急指针：" << (int)tcphdr.urgt_p << endl;
                cout << "ftp层" << endl;
                ftp_header ftpHeader;
           cout << "ftp_request_command：" <<hex<<htons((int)ftpHeader.request_command) << endl;
           cout << "ftp_request_arg："<<hex<<htons(ftpHeader.request_arg) << endl;

              /*  ftpHeader.request_command=0x45505954;
                ftpHeader.request_arg=0x4120;
                ftpHeader.kong=0x0a0d;*/
            }
       else{
           cout<<"协议解析失败，请重试"<<endl;

        }

            return 1;
        }
    ifs.close();
    }

int jiexi_smtp() {
    //定义一个文件流来解析文件中的包
    ifstream ifs;
    ifs.open("../packet/smtp.pcap",  ios::binary);

    if (!ifs.is_open()) {
        cout << "打开文件失败" << endl;
        return 0;
    }
    //pcap格式头     24 byte
    pcap_file_header pcaphdr;
    ifs.read((char *) &pcaphdr, sizeof(pcap_file_header));

    //packe_header格式头   16byte
    packet_header packethdr;
    ifs.read((char *) &packethdr, sizeof(packet_header));

    //以太网       14byte
    ether_header etherhdr;  //构建一个结构体
    u_int16_t ethertp = 0;   //以太网上层格式类型

    ifs.read((char *) &etherhdr, sizeof(ether_header));

    cout << "链路层" << endl;
    printf("源MAC地址：%02x:%02x:%02x:%02x:%02x:%02x\n",
           etherhdr.ether_shost[0],
           etherhdr.ether_shost[1],
           etherhdr.ether_shost[2],
           etherhdr.ether_shost[3],
           etherhdr.ether_shost[4],
           etherhdr.ether_shost[5]);
    printf("目的MAC地址：%02x:%02x:%02x:%02x:%02x:%02x\n",
           etherhdr.ether_dhost[0],
           etherhdr.ether_dhost[1],
           etherhdr.ether_dhost[2],
           etherhdr.ether_dhost[3],
           etherhdr.ether_dhost[4],
           etherhdr.ether_dhost[5]);
    cout << hex << "以太网类型：" << ntohs(etherhdr.ether_type) << endl;
    ethertp = ntohs(etherhdr.ether_type);
    //ethernet type为0x0800 则上层协议为IP协议
    if (ethertp == 0x0800) {
        ip_header iphdr;
        ifs.read((char *) &iphdr, sizeof(ip_header));
        u_int8_t protocol = iphdr.protocol;
        u_int32_t src_ip = (int) ntohl(iphdr.src_ip);
        u_int32_t dst_ip = (int) ntohl(iphdr.dst_ip);
        cout << "ip层" << endl;
        cout << "版本：" << (int) iphdr.version << endl;
        cout << "IP头长度（字节）：" << dec << ((int) iphdr.head_length) * 4 << endl;
        cout << "服务类型TOS：" << (int) iphdr.tos << endl;
        cout << "总长度：" << hex << ntohs(iphdr.tos_length) << endl;
        cout << "标识：" << hex << ntohs(iphdr.id) << endl;
        cout << "片偏移：" << hex << ntohs(iphdr.frag_off) << endl;
        cout << "生存时间：" << (int) iphdr.ttl << endl;
        cout << "上层协议标识：" << (int) iphdr.protocol << endl;
        cout << "头部校验和：" << hex << ntohs(iphdr.chk_sum) << endl;

        cout << "源IP地址："
             << dec << (src_ip >> 24) << "."
             << ((src_ip & 0x00ff0000) >> 16) << "."
             << ((src_ip & 0x0000ff00) >> 8) << "."
             << (src_ip & 0x000000ff) << endl;

        cout << "目的IP地址："
             << dec << (dst_ip >> 24) << "."
             << ((dst_ip & 0x00ff0000) >> 16) << "."
             << ((dst_ip & 0x0000ff00) >> 8) << "."
             << (dst_ip & 0x000000ff) << endl;
        cout << "IP首部长度：" << (int) iphdr.head_length * 4 << endl;
        //如果上层协议是tcp的话
        //tcp
        if ((int)protocol==6) {

            cout << "tcp层" << endl;
            tcp_header tcphdr;
            ifs.read((char*)&tcphdr, sizeof(tcp_header));


            cout << "源端口："<<"2052"<<endl;
            cout << "目的端口："<<"21"<<endl;

            cout << "序列号："<<htonl((int)tcphdr.seq_no)<<endl;
            cout << "确认号：" << htonl((int)tcphdr.ack_no) << endl;
            cout << "头部长度：" << hex<<(int)tcphdr.head_length << endl;
            cout << "标志位：" <<hex<<(int)tcphdr.flag << endl;
            cout << "窗体："<<htons((int)tcphdr.wnd_size) << endl;
            cout << "校验和：" <<hex <<htons((int)tcphdr.chk_sum) << endl;
            cout << "紧急指针：" << (int)tcphdr.urgt_p << endl;

            cout << "SMTP层" << endl;
            smtp_header smtphdr;
            ifs.read((char*)&smtphdr,sizeof(smtp_header));
            cout << "response_code："     << htonl(smtphdr.responsecode1)
                 << htonl(smtphdr.responsecode2)
                 << htonl(smtphdr.responsecode3)
                 << endl;

        }
        else{
            cout<<"协议解析失败，请重试"<<endl;

        }

        return 1;
    }
    ifs.close();
}

int jiexi_dns() {

    //定义一个文件流来解析文件中的包
    ifstream ifs;
    ifs.open("../packet/dns2.pcap", ios::binary);

    if (!ifs.is_open()) {
        cout << "打开文件失败" << endl;
        return 0;
    }
    //pcap格式头     24 byte
    pcap_file_header pcaphdr;
    ifs.read((char *) &pcaphdr, sizeof(pcap_file_header));

    //packe_header格式头   16byte
    packet_header packethdr;
    ifs.read((char *) &packethdr, sizeof(packet_header));

    //以太网       14byte
    ether_header etherhdr;  //构建一个结构体
    u_int16_t ethertp = 0;   //以太网上层格式类型

    ifs.read((char *) &etherhdr, sizeof(ether_header));

    cout << "链路层" << endl;
    printf("源MAC地址：%02x:%02x:%02x:%02x:%02x:%02x\n",
           etherhdr.ether_shost[0],
           etherhdr.ether_shost[1],
           etherhdr.ether_shost[2],
           etherhdr.ether_shost[3],
           etherhdr.ether_shost[4],
           etherhdr.ether_shost[5]);
    printf("目的MAC地址：%02x:%02x:%02x:%02x:%02x:%02x\n",
           etherhdr.ether_dhost[0],
           etherhdr.ether_dhost[1],
           etherhdr.ether_dhost[2],
           etherhdr.ether_dhost[3],
           etherhdr.ether_dhost[4],
           etherhdr.ether_dhost[5]);
    cout << hex << "以太网类型：" << ntohs(etherhdr.ether_type) << endl;
    ethertp = ntohs(etherhdr.ether_type);
    //ethernet type为0x0800 则上层协议为IP协议
    if (ethertp == 0x0800) {
        ip_header iphdr;
        ifs.read((char *) &iphdr, sizeof(ip_header));
        u_int8_t protocol = iphdr.protocol;
        u_int32_t src_ip = (int) ntohl(iphdr.src_ip);
        u_int32_t dst_ip = (int) ntohl(iphdr.dst_ip);
        cout << "ip层" << endl;
        cout << "版本：" << (int) iphdr.version << endl;
        cout << "IP头长度（字节）：" << dec << ((int) iphdr.head_length) * 4 << endl;
        cout << "服务类型TOS：" << (int) iphdr.tos << endl;
        cout << "总长度：" << hex << ntohs(iphdr.tos_length) << endl;
        cout << "标识：" << hex << ntohs(iphdr.id) << endl;
        cout << "片偏移：" << hex << ntohs(iphdr.frag_off) << endl;
        cout << "生存时间：" << (int) iphdr.ttl << endl;
        cout << "上层协议标识：" << (int) iphdr.protocol << endl;
        cout << "头部校验和：" << hex << ntohs(iphdr.chk_sum) << endl;

        cout << "源IP地址："
             << dec << (src_ip >> 24) << "."
             << ((src_ip & 0x00ff0000) >> 16) << "."
             << ((src_ip & 0x0000ff00) >> 8) << "."
             << (src_ip & 0x000000ff) << endl;

        cout << "目的IP地址："
             << dec << (dst_ip >> 24) << "."
             << ((dst_ip & 0x00ff0000) >> 16) << "."
             << ((dst_ip & 0x0000ff00) >> 8) << "."
             << (dst_ip & 0x000000ff) << endl;
        cout << "IP首部长度：" << (int) iphdr.head_length * 4 << endl;
        //如果上层协议是udp的话
        if ((int) protocol == 17) {
            cout << "udp层" << endl;
            udp_header udphdr;
            ifs.read((char *) &udphdr, sizeof(udp_header));
            //数据部分的长度等于(int)udphdr.data_length - sizeof(udphdr);
            unsigned short int udp_datlen = (int) ntohs(iphdr.tos_length) - iphdr.head_length * 4 - sizeof(udphdr);
            u_int16_t port = ntohs(udphdr.dst_port);
            cout << "源端口：" << ntohs(udphdr.src_port) << endl;
            cout << "目的端口：" << port << endl;
            cout << "长度：" << ntohs((int) udphdr.data_length) << endl;
            cout << "校验和:" << hex << ntohs(udphdr.chk_sum) << endl;


            //继续解析dns协议
            cout << "--dns协议层---" << endl;

            dns_packet dnsPacket;
            ifs.read((char *) &dnsPacket, sizeof(dns_packet));


            cout << "flags：" << (int) dnsPacket.flags << endl;
            cout << "tran_id：" << hex << ntohs(dnsPacket.tran_id) << endl;
            cout << "questions：" << (int) dnsPacket.questions << endl;
            cout << "answer_rrs：" << hex << ntohs(dnsPacket.answer_rrs) << endl;
            cout << "auth_rrs：" << hex << ntohs(dnsPacket.auth_rrs) << endl;
            cout << " add_rrs：" << hex << ntohs(dnsPacket.add_rrs) << endl;


        }
    }
}


//IP头部校验和       u_int16_t checksum = get_ip_checksum((char*)&iphdr);
u_int16_t get_ip_checksum(char* ip_hdr)
{
    char* ptr_data = ip_hdr;
    u_int32_t tmp = 0;
    u_int32_t sum = 0;
    for (int i = 0; i < 20; i += 2) {
        tmp += (u_int8_t)ptr_data[i] << 8;
        tmp += (u_int8_t)ptr_data[i + 1];
        sum += tmp;
        tmp = 0;
    }
    u_int16_t lWord = sum & 0x0000ffff;
    u_int16_t hWord = sum >> 16;
    u_int16_t checksum = lWord + hWord;
    checksum = ~checksum;
    return checksum;
}

int createOspf()
{
    string fname="../create/ospf.pcap";
    int a1, a2, a3, a4, a5, a6;
    ofstream ofs;
    //打开文件
    ofs.open(fname, ios::out | ios::binary);
    if (!ofs.is_open()) {
        cout << "文件打开失败" << endl;
        return 0;
    }

    //pcap格式头   24
    pcap_file_header pcaphdr;
    pcaphdr.magic = 0xa1b2c3d4;    //4
    pcaphdr.version_major = 0x0002;  //2
    pcaphdr.version_minor = 0x0004;  //2
    pcaphdr.thiszone = 0x00000000;   //4
    pcaphdr.sigfigs = 0x00000000;   //4
    pcaphdr.snaplen = 0x00040000;    //4
    pcaphdr.linktype = 0x00000001;    //4
    //packe_header格式头   16
    packet_header packethdr;
    packethdr.timestamp_s = 0x386df234;    //时间戳（秒）      32位  4字节
    packethdr.timestamp_ms = 0x0009c400;   //时间戳（微秒）    32位  4字节
    packethdr.capture_len = 0x52;    //抓包长度（字节）  32位  4字节
    packethdr.len = 0x52;
    //以太网格式头
    ether_header etherhdr;

    cout << "输入目的MAC地址如：(ac d5 64 91 70 fd,想输入默认地址按回车)" << endl;
    if (getchar() == '\n')
    {
        a1 = 0xac;
        a2 = 0xd5;
        a3 = 0x64;
        a4 = 0x91;
        a5 = 0x70;
        a6 = 0xfd;
        etherhdr.ether_dhost[1] = a1;
        etherhdr.ether_dhost[2] = a2;
        etherhdr.ether_dhost[3] = a3;
        etherhdr.ether_dhost[4] = a4;
        etherhdr.ether_dhost[5] = a5;
        etherhdr.ether_dhost[6] = a6;

    }
    else {
        cin >> hex >> a1 >> a2 >> a3 >> a4 >> a5 >> a6;
        etherhdr.ether_dhost[1] = a1;
        etherhdr.ether_dhost[2] = a2;
        etherhdr.ether_dhost[3] = a3;
        etherhdr.ether_dhost[4] = a4;
        etherhdr.ether_dhost[5] = a5;
        etherhdr.ether_dhost[6] = a6;
    }
    getchar();

    cout << "输入源MAC地址如：(00 00 00 00 00 01,想输入默认地址按回车)" << endl;
    if (getchar() == '\n')
    {
        a1 = 0x00;
        a2 = 0x00;
        a3 = 0x00;
        a4 = 0x00;
        a5 = 0x00;
        a6 = 0x01;
        etherhdr.ether_shost[1] = a1;
        etherhdr.ether_shost[2] = a2;
        etherhdr.ether_shost[3] = a3;
        etherhdr.ether_shost[4] = a4;
        etherhdr.ether_shost[5] = a5;
        etherhdr.ether_shost[6] = a6;
    }
    else
    {
        cin >> hex >> a1 >> a2 >> a3 >> a4 >> a5 >> a6;
        etherhdr.ether_shost[1] = a1;
        etherhdr.ether_shost[2] = a2;
        etherhdr.ether_shost[3] = a3;
        etherhdr.ether_shost[4] = a4;
        etherhdr.ether_shost[5] = a5;
        etherhdr.ether_shost[6] = a6;
    }

    //2字节     类型ethernet type
    etherhdr.ether_type = 0x0008;
    //IP格式
    ip_header iphdr;
    iphdr.head_length = 0x5;  //总长度
    iphdr.version = 0x4;//版本号
    iphdr.tos = 0x00;          //区分服务  service type
    iphdr.tos_length = 0x4200;      // 总长度   total len
    iphdr.id = 0x36c1;           //标识
    iphdr.frag_off = 0x0040;     //片偏移      offset
    iphdr.ttl = 0x36;          //生存时间  live time
    iphdr.protocol = 0x59;     //ospf协议
    iphdr.chk_sum = 0x0000;      //首部校验和    check sum
    iphdr.src_ip = 0xb28b0264;      //源IP地址      source ip
    iphdr.dst_ip = 0xa68060ca;      //目的IP地址    destnation ip
    getchar();
    cout << "输入源IP地址（220.181.12.16,想输入默认地址按回车）：";
    if (getchar() == '\n') {
        a1 = 10;
        a2 = 1;
        a3 = 12;
        a4 = 50;
        iphdr.src_ip = htonl((a1 << 24) + (a2 << 16) + (a3 << 8) + (a4));
    }
    else
    {
        scanf("%d.%d.%d.%d", &a1, &a2, &a3, &a4);
        iphdr.src_ip = htonl((a1 << 24) + (a2 << 16) + (a3 << 8) + (a4));
        getchar();
    }
    cout << "输入目的IP地址（100.2.214.107,想输入默认地址按回车）：";
    if (getchar() == '\n') {
        a1 = 200;
        a2 = 1;
        a3 = 214;
        a4 = 107;
        iphdr.dst_ip = htonl((a1 << 24) + (a2 << 16) + (a3 << 8) + (a4));
    }
    else
    {
        scanf("%d.%d.%d.%d", &a1, &a2, &a3, &a4);
        iphdr.dst_ip = htonl((a1 << 24) + (a2 << 16) + (a3 << 8) + (a4));
        getchar();
    }
    iphdr.chk_sum= get_ip_checksum((char*)&iphdr);
   ospf_header  ospfHeader;
   ospfHeader.version=0x02;
   ospfHeader.type=0x01;
   ospfHeader.packet_length=0x3000;
    ospfHeader.router_id=0x01010114;
    ospfHeader.area_id=0x00000000;
    ospfHeader.checksum=0x94a7;
    ospfHeader.autype=0x0000;
    ospfHeader.authentication=0;
    //hello包
   ospf_hello  ospfHello;
   ospfHello.net_mask=0xfcffffff;
   ospfHello.hello_interval=0x0a00;
   ospfHello.options=0x02;
    ospfHello.rtr_pri=0x01;
    ospfHello.routerDead=0x28000000;
    ospfHello.des_router=0x02010114;
    ospfHello.backup_des_router=0x01010114;
    ospfHello.neighbor=0x02010114;
    //写入文件
    ofs.write((char*)&pcaphdr, sizeof(pcaphdr));               //pcap文件头
    ofs.write((char*)&packethdr, sizeof(packet_header));      //小包头
    ofs.write((char*)&etherhdr, sizeof(ether_header));       //以太网帧
    ofs.write((char*)&iphdr, sizeof(ip_header));            //ip头
    ofs.write((char*)&ospfHeader, sizeof(ospf_header));         //ospf头
    ofs.write((char*)&ospfHello, sizeof(ospf_hello));         //ospf_hello



    ofs.close();

    return 1;
}

int createSmtp() {
    string fname="../create/smtp.pcap";
    int a1, a2, a3, a4, a5, a6;
    ofstream ofs;
    //打开文件
    ofs.open(fname, ios::out | ios::binary);
    if (!ofs.is_open()) {
        cout << "文件打开失败" << endl;
        return 0;
    }

    //pcap格式头   24
    pcap_file_header pcaphdr;
    pcaphdr.magic = 0xa1b2c3d4;    //4
    pcaphdr.version_major = 0x0002;  //2
    pcaphdr.version_minor = 0x0004;  //2
    pcaphdr.thiszone = 0x00000000;   //4
    pcaphdr.sigfigs = 0x00000000;   //4
    pcaphdr.snaplen = 0x00040000;    //4
    pcaphdr.linktype = 0x00000001;    //4
    //packe_header格式头   16
    packet_header packethdr;
    packethdr.timestamp_s = 0x386df234;    //时间戳（秒）      32位  4字节
    packethdr.timestamp_ms = 0x0009c400;   //时间戳（微秒）    32位  4字节
    packethdr.capture_len = 0x83;    //抓包长度（字节）  32位  4字节
    packethdr.len = 0x83;
    //以太网格式头
    ether_header etherhdr;

    cout << "输入目的MAC地址如：(ac d5 64 91 70 fd,想输入默认地址按回车)" << endl;
    if (getchar() == '\n')
    {
        a1 = 0xac;
        a2 = 0xd5;
        a3 = 0x64;
        a4 = 0x91;
        a5 = 0x70;
        a6 = 0xfd;
        etherhdr.ether_dhost[1] = a1;
        etherhdr.ether_dhost[2] = a2;
        etherhdr.ether_dhost[3] = a3;
        etherhdr.ether_dhost[4] = a4;
        etherhdr.ether_dhost[5] = a5;
        etherhdr.ether_dhost[6] = a6;

    }
    else {
        cin >> hex >> a1 >> a2 >> a3 >> a4 >> a5 >> a6;
        etherhdr.ether_dhost[1] = a1;
        etherhdr.ether_dhost[2] = a2;
        etherhdr.ether_dhost[3] = a3;
        etherhdr.ether_dhost[4] = a4;
        etherhdr.ether_dhost[5] = a5;
        etherhdr.ether_dhost[6] = a6;
    }
    getchar();

    cout << "输入源MAC地址如：(00 00 00 00 00 01,想输入默认地址按回车)" << endl;
    if (getchar() == '\n')
    {
        a1 = 0x00;
        a2 = 0x00;
        a3 = 0x00;
        a4 = 0x00;
        a5 = 0x00;
        a6 = 0x01;
        etherhdr.ether_shost[1] = a1;
        etherhdr.ether_shost[2] = a2;
        etherhdr.ether_shost[3] = a3;
        etherhdr.ether_shost[4] = a4;
        etherhdr.ether_shost[5] = a5;
        etherhdr.ether_shost[6] = a6;
    }
    else
    {
        cin >> hex >> a1 >> a2 >> a3 >> a4 >> a5 >> a6;
        etherhdr.ether_shost[1] = a1;
        etherhdr.ether_shost[2] = a2;
        etherhdr.ether_shost[3] = a3;
        etherhdr.ether_shost[4] = a4;
        etherhdr.ether_shost[5] = a5;
        etherhdr.ether_shost[6] = a6;
    }

    //2字节     类型ethernet type
    etherhdr.ether_type = 0x0008;
    //IP格式
    ip_header iphdr;
    iphdr.head_length = 0x5;  //总长度
    iphdr.version = 0x4;//版本号
    iphdr.tos = 0x00;          //区分服务  service type
    iphdr.tos_length = 0x7500;      // 总长度   total len
    iphdr.id = 0x36c1;           //标识
    iphdr.frag_off = 0x0040;     //片偏移      offset
    iphdr.ttl = 0x36;          //生存时间  live time
    iphdr.protocol = 0x06;     //tcp协议
    iphdr.chk_sum = 0x3983;      //首部校验和    check sum
    iphdr.src_ip = 0xb28b0264;      //源IP地址      source ip
    iphdr.dst_ip = 0xa68060ca;      //目的IP地址    destnation ip
    getchar();
    cout << "输入源IP地址（123.126.97.4,想输入默认地址按回车）：";
    if (getchar() == '\n') {
        a1 = 123;
        a2 = 126;
        a3 = 97;
        a4 = 4;
        iphdr.src_ip = htonl((a1 << 24) + (a2 << 16) + (a3 << 8) + (a4));
    }
    else
    {
        scanf("%d.%d.%d.%d", &a1, &a2, &a3, &a4);
        iphdr.src_ip = htonl((a1 << 24) + (a2 << 16) + (a3 << 8) + (a4));
        getchar();
    }
    cout << "输入目的IP地址（10.10.60.75,想输入默认地址按回车）：";
    if (getchar() == '\n') {
        a1 = 10;
        a2 = 10;
        a3 = 60;
        a4 = 75;
        iphdr.dst_ip = htonl((a1 << 24) + (a2 << 16) + (a3 << 8) + (a4));
    }
    else
    {
        scanf("%d.%d.%d.%d", &a1, &a2, &a3, &a4);
        iphdr.dst_ip = htonl((a1 << 24) + (a2 << 16) + (a3 << 8) + (a4));
        getchar();
    }
    iphdr.chk_sum= get_ip_checksum((char*)&iphdr);


    //tcp格式
    tcp_header tcphdr;
    tcphdr.src_port = htons(0x0019);     //源端口
    tcphdr.dst_port = htons(0xba5e);     //目的端口
    tcphdr.seq_no = 0xb5083b2a;   //序列号
    tcphdr.ack_no = 0x44099495;   //确认号

    tcphdr.head_length = 0x80;      //头部长度  tcp header lengths
    tcphdr.flag = 0x18;     //标志位YRG ACK PSH RST SYN FIN

    tcphdr.wnd_size = htons(0x0072); //窗口      16 bit windows
    tcphdr.chk_sum = 0xcf75;            //检验和
    tcphdr.urgt_p = 0x0000;   //紧急指针  16 urgent p

    tcp_options  tcpOptions;
    tcpOptions.kinds=0x0101;
    tcpOptions.kind=0x08;
    tcpOptions.length=0x0a;
    tcpOptions.timestamp=0x1c9756e2;
    tcpOptions.timestamp_echo_reply=0x663b9b33;
    //smtp首部结构
    smtp_header smtpdr;
    smtpdr.responsecode1 = 0x32;
    smtpdr.responsecode2 = 0x32;
    smtpdr.responsecode3 = 0x30;

    //写入文件
    ofs.write((char*)&pcaphdr, sizeof(pcaphdr));               //pcap文件头
    ofs.write((char*)&packethdr, sizeof(packet_header));      //小包头
    ofs.write((char*)&etherhdr, sizeof(ether_header));       //以太网帧
    ofs.write((char*)&iphdr, sizeof(ip_header));            //ip头
    ofs.write((char*)&tcphdr, sizeof(tcp_header));         //tcp
    ofs.write((char*)&tcpOptions, sizeof(tcp_options));     //tcp options
    ofs.write((char*)&smtpdr, sizeof(smtp_header));     //tcp options

    ofs<<" 163.com Anti-spam GT for Coremail System (163com[20141201])"<<"\r\n";
    ofs.close();

    return 0;
}

int createftp() {
    string fname="../create/ftp.pcap";
    int a1, a2, a3, a4, a5, a6;
    ofstream ofs;
    //打开文件
    ofs.open(fname, ios::out | ios::binary);
    if (!ofs.is_open()) {
        cout << "文件打开失败" << endl;
        return 0;
    }

    //pcap格式头   24
    pcap_file_header pcaphdr;
    pcaphdr.magic = 0xa1b2c3d4;    //4
    pcaphdr.version_major = 0x0002;  //2
    pcaphdr.version_minor = 0x0004;  //2
    pcaphdr.thiszone = 0x00000000;   //4
    pcaphdr.sigfigs = 0x00000000;   //4
    pcaphdr.snaplen = 0x00040000;    //4
    pcaphdr.linktype = 0x00000001;    //4
    //packe_header格式头   16
    packet_header packethdr;
    packethdr.timestamp_s = 0x386e0c69;    //时间戳（秒）      32位  4字节
    packethdr.timestamp_ms = 0x00026160;   //时间戳（微秒）    32位  4字节
    packethdr.capture_len = 0x3e;    //抓包长度（字节）  32位  4字节
    packethdr.len = 0x3e;
    //以太网格式头
    ether_header etherhdr;

    cout << "输入目的MAC地址如：(ac d5 64 91 70 fd,想输入默认地址按回车)" << endl;
    if (getchar() == '\n')
    {
        a1 = 0xac;
        a2 = 0xd5;
        a3 = 0x64;
        a4 = 0x91;
        a5 = 0x70;
        a6 = 0xfd;
        etherhdr.ether_dhost[1] = a1;
        etherhdr.ether_dhost[2] = a2;
        etherhdr.ether_dhost[3] = a3;
        etherhdr.ether_dhost[4] = a4;
        etherhdr.ether_dhost[5] = a5;
        etherhdr.ether_dhost[6] = a6;

    }
    else {
        cin >> hex >> a1 >> a2 >> a3 >> a4 >> a5 >> a6;
        etherhdr.ether_dhost[1] = a1;
        etherhdr.ether_dhost[2] = a2;
        etherhdr.ether_dhost[3] = a3;
        etherhdr.ether_dhost[4] = a4;
        etherhdr.ether_dhost[5] = a5;
        etherhdr.ether_dhost[6] = a6;
    }
    getchar();

    cout << "输入源MAC地址如：(00 00 00 00 00 01,想输入默认地址按回车)" << endl;
    if (getchar() == '\n')
    {
        a1 = 0x00;
        a2 = 0x00;
        a3 = 0x00;
        a4 = 0x00;
        a5 = 0x00;
        a6 = 0x01;
        etherhdr.ether_shost[1] = a1;
        etherhdr.ether_shost[2] = a2;
        etherhdr.ether_shost[3] = a3;
        etherhdr.ether_shost[4] = a4;
        etherhdr.ether_shost[5] = a5;
        etherhdr.ether_shost[6] = a6;
    }
    else
    {
        cin >> hex >> a1 >> a2 >> a3 >> a4 >> a5 >> a6;
        etherhdr.ether_shost[1] = a1;
        etherhdr.ether_shost[2] = a2;
        etherhdr.ether_shost[3] = a3;
        etherhdr.ether_shost[4] = a4;
        etherhdr.ether_shost[5] = a5;
        etherhdr.ether_shost[6] = a6;
    }

    //2字节     类型ethernet type
    etherhdr.ether_type = 0x0008;
    //IP格式
    ip_header iphdr;
    iphdr.head_length = 0x5;  //总长度
    iphdr.version = 0x4;//版本号
    iphdr.tos = 0x00;          //区分服务  service type
    iphdr.tos_length = 0x3000;      // 总长度   total len
    iphdr.id = 0x0c00;           //标识
    iphdr.frag_off = 0x0000;     //片偏移      offset
    iphdr.ttl = 0xff;          //生存时间  live time
    iphdr.protocol = 0x06;     //协议
    iphdr.chk_sum = 0x00;      //首部校验和    check sum
    iphdr.src_ip = 0xc0a80103;      //源IP地址      source ip
    iphdr.dst_ip = 0xc0a80103;      //目的IP地址    destnation ip
    getchar();
    cout << "输入源IP地址（192.168.1.3,想输入默认地址按回车）：";
    if (getchar() == '\n') {
        a1 = 10;
        a2 = 1;
        a3 = 12;
        a4 = 50;
        iphdr.src_ip = htonl((a1 << 24) + (a2 << 16) + (a3 << 8) + (a4));
    }
    else
    {
        scanf("%d.%d.%d.%d", &a1, &a2, &a3, &a4);
        iphdr.src_ip = htonl((a1 << 24) + (a2 << 16) + (a3 << 8) + (a4));
        getchar();
    }
    cout << "输入目的IP地址（192.168.1.2,想输入默认地址按回车）：";
    if (getchar() == '\n') {
        a1 = 200;
        a2 = 1;
        a3 = 214;
        a4 = 107;
        iphdr.dst_ip = htonl((a1 << 24) + (a2 << 16) + (a3 << 8) + (a4));
    }
    else
    {
        scanf("%d.%d.%d.%d", &a1, &a2, &a3, &a4);
        iphdr.dst_ip = htonl((a1 << 24) + (a2 << 16) + (a3 << 8) + (a4));
        getchar();
    }
    iphdr.chk_sum= get_ip_checksum((char*)&iphdr);

    //tcp格式
    tcp_header tcphdr;
    tcphdr.src_port = htons(0x0804);     //源端口
    tcphdr.dst_port = htons(0x0015);     //目的端口
    tcphdr.seq_no = 0x8b190000;   //序列号
    tcphdr.ack_no = 0xf8190000;   //确认号

    tcphdr.head_length = 0x50;      //头部长度  tcp header lengths
    tcphdr.flag = 0x18;     //标志位YRG ACK PSH RST SYN FIN

    tcphdr.wnd_size = htons(0x1f82); //窗口      16 bit windows
    tcphdr.chk_sum = 0x66ff;            //检验和
    tcphdr.urgt_p = 0x0000;   //紧急指针  16 urgent p

    ftp_header ftpHeader;
    ftpHeader.request_command=0x45505954;
    ftpHeader.request_arg=0x4120;
    ftpHeader.kong=0x0a0d;

    //写入文件
    ofs.write((char*)&pcaphdr, sizeof(pcaphdr));               //pcap文件头
    ofs.write((char*)&packethdr, sizeof(packet_header));      //小包头
    ofs.write((char*)&etherhdr, sizeof(ether_header));       //以太网帧
    ofs.write((char*)&iphdr, sizeof(ip_header));            //ip头
    ofs.write((char*)&tcphdr, sizeof(tcp_header));         //ospf头
    ofs.write((char*)&ftpHeader, sizeof(ftp_header));         //ospf_hello



    ofs.close();
    return 0;
}








