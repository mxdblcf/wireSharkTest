#include <iostream>
#include <fstream>
#include "string.h"
#include "winsock2.h"
using namespace std;

//ѡ��wireshark��  *.pcap ��ʽ���й���ͽ�������ʽ����
typedef unsigned int    bpf_u_int32;        //32λ  4�ֽ�
//typedef unsigned short  u_short;            //16λ  2�ֽ�
typedef int             bpf_int32;          //32λ  4�ֽ�
typedef unsigned char   u_int8_t;           //8λ   1�ֽ�
typedef unsigned short int u_int16_t;       //16λ  2�ֽ�
typedef unsigned int    u_int32_t;          //32λ  4�ֽ�
typedef unsigned long long    u_int64_t;          //64λ  4�ֽ�
//pcap�ļ�ͷ  24�ֽ�
typedef struct pcap_file_header
{
    bpf_u_int32 magic;      //����ļ���ʼ��������ʶ���ļ����ֽ�˳��ֵ����Ϊ0xa1b2c3d4����0xd4c3b2a1�������0xa1b2c3d4��ʾ�Ǵ��ģʽ������ԭ����˳��һ���ֽ�һ���ֽڵĶ��������0xd4c3b2a1��ʾС��ģʽ��������ֽڶ�Ҫ����˳�����ڵĵ��Դ󲿷���С��ģʽ��
    u_int16_t version_major;  //��ǰ�ļ�����Ҫ�汾�ţ�һ��Ϊ0x0200
    u_int16_t version_minor;  //��ǰ�ļ��Ĵ�Ҫ�汾�ţ�һ��Ϊ0x0400
    bpf_int32 thiszone;     //���صı�׼�¼�������õ���GMT��ȫ�㣬һ��ȫ��
    bpf_u_int32 sigfigs;    //ʱ����ľ��ȣ�һ��Ϊȫ��
    bpf_u_int32 snaplen;    //���Ĵ洢���ȣ�������ץ������ݰ�����󳤶ȣ�����������ݰ���Ҫץ�񣬽�ֵ����Ϊ65535
    bpf_u_int32 linktype;   //��·���͡��������ݰ�����Ҫ�ж�����LinkType���������ֵ����Ҫ��һ���ֵΪ1������̫��
}pcap_file_header;
//pcapС��ͷ   16�ֽ�
typedef struct packet_header
{
    bpf_u_int32 timestamp_s;    //ʱ������룩      32λ  4�ֽ�
    bpf_u_int32 timestamp_ms;   //ʱ�����΢�룩    32λ  4�ֽ�
    bpf_u_int32 capture_len;    //ץ�����ȣ��ֽڣ�  32λ  4�ֽ�
    bpf_u_int32 len;            //ʵ�ʳ��ȣ��ֽ�    32λ  4�ֽ�
}packet_header;

//IP���ݰ���ʽ   20�ֽ�
typedef struct ip_header
{
    u_int8_t      head_length : 4;  //�ܳ���
    u_int8_t      version : 4;//�汾��
    u_int8_t      tos;          //���ַ���  service type
    u_int16_t     tos_length;      // �ܳ���   total len
    u_int16_t     id;           //��ʶ
    u_int16_t     frag_off;     //Ƭƫ��      offset
    u_int8_t      ttl;          //����ʱ��  live time
    u_int8_t      protocol;     //Э��
    u_int16_t     chk_sum;      //�ײ�У���    check sum
    u_int32_t     src_ip;      //ԴIP��ַ      source ip
    u_int32_t     dst_ip;      //Ŀ��IP��ַ    destnation ip
}ip_header;
//UDP�ײ���ʽ   total length :8 Bytes
typedef struct udp_header
{
    u_int16_t src_port;     //Դ�˿�
    u_int16_t dst_port;     //Ŀ�Ķ˿�
    u_int16_t data_length;          //����
    u_int16_t chk_sum;      //�����
} udp_header;

//ospf�ײ���ʽ   total length :24 Bytes
typedef struct ospf_header
{
    u_int8_t  version;  //�汾
    u_int8_t type;  //����
    u_int16_t  packet_length;  //ospf�����ܳ���
    u_int32_t router_id;     //·��Id ,�պ�Ϊ��ַ����
    u_int32_t area_id;     //����Id
    u_int16_t  checksum;  //У���
    u_int16_t autype;     //��֤����
    u_int64_t authentication;     //�����ֶ�
} ospf_header;

//ospf hello���ĸ�ʽ��һ��5�֡�����һ������������ƣ�   total length :24 Bytes
typedef struct ospf_hello
{
    u_int32_t net_mask;     //����
    u_int16_t  hello_interval;  //helloʱ����
    u_int8_t options;  //��ѡ��
    u_int8_t rtr_pri;  //DR���ȼ�
    u_int32_t routerDead;     //ʧЧʱ��
    u_int32_t des_router;     //DR�ӿڵ�ַ
    u_int32_t backup_des_router;     //BDR�ӿڵ�ַ
    u_int32_t neighbor;     //�ھ�
} ospf_hello;
//TCPͷ��   total length : 20Bytes
typedef struct tcp_header
{
    u_int16_t     src_port; //Դ�˿�   source port
    u_int16_t     dst_port; //Ŀ�Ķ˿� destination port
    u_int32_t     seq_no;   //���к�
    u_int32_t     ack_no;   //ȷ�Ϻ�
    u_int8_t      head_length ;          //ͷ������  tcp header length
    u_int8_t      flag;         //��־λYRG ACK PSH RST SYN FIN

    u_int16_t     wnd_size; //����      16 bit windows
    u_int16_t     chk_sum;  //ѡ���  16 bits check sum
    u_int16_t     urgt_p;   //����ָ��  16 urgent p
} tcp_header;

//rip��ʽ   total length :24 Bytes
typedef struct rip
{
    u_int8_t command;  //����
    u_int8_t  version;
    u_int16_t  zero;  //��Ϊ0�ֶ�
    u_int16_t address_family;     //��ַ���ʶ
    u_int16_t route_tag;     //·�ɱ��
    u_int32_t ip_address;     //�����ַ
    u_int32_t netmask;     //��������
    u_int32_t next_hop;     //��һ��·�ɵ�ַ
    u_int32_t metric;          //����

} rip_packet;
typedef struct tcp_check_subhdr {
    u_int32_t src_ip;
    u_int32_t dst_ip;
    u_int8_t all_zero;
    u_int8_t protocol;
    u_int16_t tcp_all_len;//tcpͷ�������ݲ��ֵ��ܳ���
}tcp_check_subhdr;

//dns���ĸ�ʽ
typedef struct dns
{
    u_int16_t tran_id;     //����ID
    u_int16_t flags;     //��־
    u_int16_t questions;          //�������
    u_int16_t answer_rrs;      //�ش���Դ����
    u_int16_t auth_rrs;      //����������
    u_int16_t add_rrs;      //���Ӽ���
} dns_packet;


//SMTP�ײ���ʽ
typedef struct smtp_header {
    u_int8_t responsecode1;
    u_int8_t responsecode2;
    u_int8_t responsecode3;

}smtp_header;

//ftp�ײ���ʽ
typedef struct ftp_header {
    u_int32_t  request_command;
    u_int16_t  request_arg;
    u_int16_t kong;  //��ʵ��/r/n

}ftp_header;
//tcpѡ��
typedef struct tcp_options
{
    u_int16_t  kinds;        //
    u_int8_t kind;//
    u_int8_t length;
    u_int32_t timestamp;
    u_int32_t timestamp_echo_reply;
} tcp_options;
//MAC֡ͷ����̫���� 14�ֽ�
typedef struct ether_header

{
    u_int8_t ether_dhost[6];        //6���ֽ�   Ŀ��MAC��ַ
    u_int8_t ether_shost[6];        //6���ֽ�   ԴMAC��ַ
    u_int16_t ether_type;           //2�ֽ�     ����ethernet type
} ether_header;
//����rip�����
int jiexi_rip() ;
//���� ftp ���
int jiexi_ftp();
//����ospf�����
int jiexi_ospf();
//����smtp
int jiexi_smtp();
//dnsֻ������������  ������ɣ�
int jiexi_dns();
u_int16_t get_ip_checksum(char*);
//���
int createOspf();
int createSmtp();
//���
int createftp();
int main() {

    //���Ǵ����˽������ĵ�5���������͹��챨�ĵ�3�����������ĸ����þ���
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
        cout << "0 �˳�" << endl;
        cout << "1 ��������" << endl;
        cout << "1 ����smtp����" << endl;
        cout << "2 ����rip����" << endl;
        cout << "3 ����SMTP����" << endl;
        cout << "------------------------------" << endl;

        cin >> choose;
        switch (choose)
        {
            case 0:
            {
                return 1;
            }
            case 1: {
                cout << "�������·����../rip2.pcap) (D:\\DHCP.pcap):";
                cin >> path;
                int i = jiexi(path);
                if (i == 0) {
                    cout << "��������" << endl;

                }
                break;
            }
       *//*     case 2: {
                int j =  WritePcap("D:\\smtp.pcap");
                if (j == 0) {
                    cout << "д�����" << endl;
                }
                else
                {
                    cout << "����smtp���ĳɹ��� D:\\smtp.pcap" << endl;
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
//�������ĺ���
//rip����
int jiexi_rip() {
    //����һ���ļ����������ļ��еİ�
    ifstream ifs;
    ifs.open("../packet/rip2.pcap",  ios::binary);

    if (!ifs.is_open()) {
        cout << "���ļ�ʧ��" << endl;
        return 0;
    }
    //pcap��ʽͷ     24 byte
    pcap_file_header pcaphdr;
    ifs.read((char *) &pcaphdr, sizeof(pcap_file_header));

    //packe_header��ʽͷ   16byte
    packet_header packethdr;
    ifs.read((char *) &packethdr, sizeof(packet_header));

    //��̫��       14byte
    ether_header etherhdr;  //����һ���ṹ��
    u_int16_t ethertp = 0;   //��̫���ϲ��ʽ����

    ifs.read((char *) &etherhdr, sizeof(ether_header));
    
    cout << "��·��" << endl;
    printf("ԴMAC��ַ��%02x:%02x:%02x:%02x:%02x:%02x\n",
           etherhdr.ether_shost[0],
           etherhdr.ether_shost[1],
           etherhdr.ether_shost[2],
           etherhdr.ether_shost[3],
           etherhdr.ether_shost[4],
           etherhdr.ether_shost[5]);
    printf("Ŀ��MAC��ַ��%02x:%02x:%02x:%02x:%02x:%02x\n",
           etherhdr.ether_dhost[0],
           etherhdr.ether_dhost[1],
           etherhdr.ether_dhost[2],
           etherhdr.ether_dhost[3],
           etherhdr.ether_dhost[4],
           etherhdr.ether_dhost[5]);
    cout << hex << "��̫�����ͣ�" << ntohs(etherhdr.ether_type) << endl;
    ethertp = ntohs(etherhdr.ether_type);
    //ethernet typeΪ0x0800 ���ϲ�Э��ΪIPЭ��
    if (ethertp == 0x0800) {
        ip_header iphdr;
        ifs.read((char *) &iphdr, sizeof(ip_header));
        u_int8_t protocol = iphdr.protocol;
        u_int32_t src_ip = (int) ntohl(iphdr.src_ip);
        u_int32_t dst_ip = (int) ntohl(iphdr.dst_ip);
        cout << "ip��" << endl;
        cout << "�汾��" << (int) iphdr.version << endl;
        cout << "IPͷ���ȣ��ֽڣ���" << dec << ((int) iphdr.head_length) * 4 << endl;
        cout << "��������TOS��" << (int) iphdr.tos << endl;
        cout << "�ܳ��ȣ�" << hex << ntohs(iphdr.tos_length) << endl;
        cout << "��ʶ��" << hex << ntohs(iphdr.id) << endl;
        cout << "Ƭƫ�ƣ�" << hex << ntohs(iphdr.frag_off) << endl;
        cout << "����ʱ�䣺" << (int) iphdr.ttl << endl;
        cout << "�ϲ�Э���ʶ��" << (int) iphdr.protocol << endl;
        cout << "ͷ��У��ͣ�" << hex << ntohs(iphdr.chk_sum) << endl;

        cout << "ԴIP��ַ��"
             << dec << (src_ip >> 24) << "."
             << ((src_ip & 0x00ff0000) >> 16) << "."
             << ((src_ip & 0x0000ff00) >> 8) << "."
             << (src_ip & 0x000000ff) << endl;

        cout << "Ŀ��IP��ַ��"
             << dec << (dst_ip >> 24) << "."
             << ((dst_ip & 0x00ff0000) >> 16) << "."
             << ((dst_ip & 0x0000ff00) >> 8) << "."
             << (dst_ip & 0x000000ff) << endl;
        cout << "IP�ײ����ȣ�" << (int) iphdr.head_length * 4 << endl;
        //����ϲ�Э����udp�Ļ�
      if((int)protocol==17) {
                cout << "udp��" << endl;
                udp_header udphdr;
                ifs.read((char*)&udphdr, sizeof(udp_header));
                //���ݲ��ֵĳ��ȵ���(int)udphdr.data_length - sizeof(udphdr);
                unsigned short int udp_datlen = (int)ntohs(iphdr.tos_length) - iphdr.head_length * 4 - sizeof(udphdr);
                u_int16_t port = ntohs(udphdr.dst_port);
                cout << "Դ�˿ڣ�" << ntohs(udphdr.src_port) << endl;
                cout << "Ŀ�Ķ˿ڣ�" << port << endl;
                cout << "���ȣ�"<<ntohs((int)udphdr.data_length) << endl;
                cout << "У���:" << hex << ntohs(udphdr.chk_sum) << endl;


                //��������ripЭ��
          cout << "--ripЭ���---" << endl;

          rip_packet  ripPacket;
          ifs.read((char*)&ripPacket, sizeof(rip_packet));
          u_int32_t ip_address = (int) ntohl(ripPacket.ip_address);
          u_int32_t netmask = (int) ntohl(ripPacket.netmask);
          u_int32_t next_hop = (int) ntohl(ripPacket.next_hop);


          cout << "���" << ntohs( (int)ripPacket.command) << endl;
          cout << "�汾��" << ntohs((int)ripPacket.version) << endl;
          cout << "��ַ���ʾ��" << ntohs((int)ripPacket.address_family) << endl;
          cout << "·�ɱ�ǣ�" << ntohs((int)ripPacket.route_tag) << endl;

          cout << "�����ַ��"
               << dec << (ip_address >> 24) << "."
               << ((ip_address & 0x00ff0000) >> 16) << "."
               << ((ip_address & 0x0000ff00) >> 8) << "."
               << (ip_address & 0x000000ff) << endl;

          cout << "�������룺"
               << dec << (netmask >> 24) << "."
               << ((netmask & 0x00ff0000) >> 16) << "."
               << ((netmask & 0x0000ff00) >> 8) << "."
               << (netmask & 0x000000ff) << endl;

          cout << "��һ��·�ɵ�ַ��"
               << dec << (next_hop >> 24) << "."
               << ((next_hop & 0x00ff0000) >> 16) << "."
               << ((next_hop & 0x0000ff00) >> 8) << "."
               << (next_hop & 0x000000ff) << endl;


          cout << "���룺" <<ntohs( (int)ripPacket.metric) << endl;



        }
    }






    ifs.close();
}

//ospf����(hello���ģ�
int jiexi_ospf() {
    //����һ���ļ����������ļ��еİ�
    ifstream ifs;
    ifs.open("../packet/ospf.pcap",  ios::binary);

    if (!ifs.is_open()) {
        cout << "���ļ�ʧ��" << endl;
        return 0;
    }
    //pcap��ʽͷ     24 byte
    pcap_file_header pcaphdr;
    ifs.read((char *) &pcaphdr, sizeof(pcap_file_header));

    //packe_header��ʽͷ   16byte
    packet_header packethdr;
    ifs.read((char *) &packethdr, sizeof(packet_header));

    //��̫��       14byte
    ether_header etherhdr;  //����һ���ṹ��
    u_int16_t ethertp = 0;   //��̫���ϲ��ʽ����

    ifs.read((char *) &etherhdr, sizeof(ether_header));

    cout << "��·��" << endl;
    printf("ԴMAC��ַ��%02x:%02x:%02x:%02x:%02x:%02x\n",
           etherhdr.ether_shost[0],
           etherhdr.ether_shost[1],
           etherhdr.ether_shost[2],
           etherhdr.ether_shost[3],
           etherhdr.ether_shost[4],
           etherhdr.ether_shost[5]);
    printf("Ŀ��MAC��ַ��%02x:%02x:%02x:%02x:%02x:%02x\n",
           etherhdr.ether_dhost[0],
           etherhdr.ether_dhost[1],
           etherhdr.ether_dhost[2],
           etherhdr.ether_dhost[3],
           etherhdr.ether_dhost[4],
           etherhdr.ether_dhost[5]);
    cout << hex << "��̫�����ͣ�" << ntohs(etherhdr.ether_type) << endl;
    ethertp = ntohs(etherhdr.ether_type);
    //ethernet typeΪ0x0800 ���ϲ�Э��ΪIPЭ��
    if (ethertp == 0x0800) {
        ip_header iphdr;
        ifs.read((char *) &iphdr, sizeof(ip_header));
        u_int8_t protocol = iphdr.protocol;
        u_int32_t src_ip = (int) ntohl(iphdr.src_ip);
        u_int32_t dst_ip = (int) ntohl(iphdr.dst_ip);
        cout << "ip��" << endl;
        cout << "�汾��" << (int) iphdr.version << endl;
        cout << "IPͷ���ȣ��ֽڣ���" << dec << ((int) iphdr.head_length) * 4 << endl;
        cout << "��������TOS��" << (int) iphdr.tos << endl;
        cout << "�ܳ��ȣ�" << hex << ntohs(iphdr.tos_length) << endl;
        cout << "��ʶ��" << hex << ntohs(iphdr.id) << endl;
        cout << "Ƭƫ�ƣ�" << hex << ntohs(iphdr.frag_off) << endl;
        cout << "����ʱ�䣺" << (int) iphdr.ttl << endl;
        cout << "�ϲ�Э���ʶ��" << (int) iphdr.protocol << endl;
        cout << "ͷ��У��ͣ�" << hex << ntohs(iphdr.chk_sum) << endl;

        cout << "ԴIP��ַ��"
             << dec << (src_ip >> 24) << "."
             << ((src_ip & 0x00ff0000) >> 16) << "."
             << ((src_ip & 0x0000ff00) >> 8) << "."
             << (src_ip & 0x000000ff) << endl;

        cout << "Ŀ��IP��ַ��"
             << dec << (dst_ip >> 24) << "."
             << ((dst_ip & 0x00ff0000) >> 16) << "."
             << ((dst_ip & 0x0000ff00) >> 8) << "."
             << (dst_ip & 0x000000ff) << endl;
        cout << "IP�ײ����ȣ�" << (int) iphdr.head_length * 4 << endl;
        //����ϲ�Э����ospf�Ļ�


   /*     typedef struct ospf_header
        {
            u_int8_t  version;  //�汾
            u_int8_t type;  //  ����
            u_int16_t  packet_length;  //ospf�����ܳ���
            u_int32_t router_id;     //·��Id ,�պ�Ϊ��ַ����
            u_int32_t area_id;     //����Id
            u_int16_t  checksum;  //У���
            u_int16_t autype;     //��֤����
            u_int64_t authentication;     //�����ֶ�
        } ospf_header;*/

        if((int)protocol==89) {
            cout << "ospf��" << endl;
            ospf_header ospfHeader;
            ifs.read((char*)&ospfHeader, sizeof(ospf_header));
            cout << "�汾��" <<(int)ospfHeader.version<< endl;
            cout << "���ͣ�" << (int)ospfHeader.type << endl;
            cout << "���ȣ�" << ntohs((int)ospfHeader.packet_length) << endl;
            u_int32_t router_id = (int) ntohl(ospfHeader.router_id);
            u_int32_t area_id = (int) ntohl(ospfHeader.area_id);
            cout << "router_id��"
                 << dec << (router_id >> 24) << "."
                 << ((router_id & 0x00ff0000) >> 16) << "."
                 << ((router_id & 0x0000ff00) >> 8) << "."
                 << (router_id & 0x000000ff) << endl;

            cout << "area_id��"
                 << dec << (area_id >> 24) << "."
                 << ((area_id & 0x00ff0000) >> 16) << "."
                 << ((area_id & 0x0000ff00) >> 8) << "."
                 << (area_id & 0x000000ff) << endl;
            cout << "У��ͣ�" << ntohs((int)ospfHeader.checksum) << endl;
            cout << "��֤���ͣ�" << ntohs( (int)ospfHeader.autype) << endl;

            cout<<"ospf�����壺"<<endl;


            ospf_hello ospfHello;
            ifs.read((char*)&ospfHello, sizeof(ospf_header));
            u_int32_t net_mask = (int) ntohl(ospfHello.net_mask);
            cout << "���룺"
                 << dec << (net_mask >> 24) << "."
                 << ((net_mask & 0x00ff0000) >> 16) << "."
                 << ((net_mask & 0x0000ff00) >> 8) << "."
                 << (net_mask & 0x000000ff) << endl;


            cout << "ʧЧʱ�䣺" << ntohs((int)ospfHello.hello_interval) << endl;
            cout << "��ѡ�" << (int)ospfHello.options << endl;
            cout << "DR���ȼ���" << (int)ospfHello.rtr_pri << endl;
            cout << "ʧЧʱ�䣺" << ntohs((int)ospfHello.routerDead) << endl;

            u_int32_t neighbor = (int) ntohl(ospfHello.neighbor);
            u_int32_t des_router = (int) ntohl(ospfHello.des_router);
            u_int32_t backup_des_router = (int) ntohl(ospfHello.backup_des_router);

            cout << "dr��"
                 << dec << (des_router >> 24) << "."
                 << ((des_router & 0x00ff0000) >> 16) << "."
                 << ((des_router & 0x0000ff00) >> 8) << "."
                 << (des_router & 0x000000ff) << endl;
            cout << "bdr��"
                 << dec << (backup_des_router >> 24) << "."
                 << ((backup_des_router & 0x00ff0000) >> 16) << "."
                 << ((backup_des_router & 0x0000ff00) >> 8) << "."
                 << (backup_des_router & 0x000000ff) << endl;
            cout << "�ھӣ�"
                 << dec << (neighbor >> 24) << "."
                 << ((neighbor & 0x00ff0000) >> 16) << "."
                 << ((neighbor & 0x0000ff00) >> 8) << "."
                 << (neighbor & 0x000000ff) << endl;
        }
    }
    ifs.close();
}

//ftp��������
//todo ftp
int jiexi_ftp() {
    //����һ���ļ����������ļ��еİ�
    ifstream ifs;
    ifs.open("../packet/ftp2.pcap",  ios::binary);

    if (!ifs.is_open()) {
        cout << "���ļ�ʧ��" << endl;
        return 0;
    }
    //pcap��ʽͷ     24 byte
    pcap_file_header pcaphdr;
    ifs.read((char *) &pcaphdr, sizeof(pcap_file_header));

    //packe_header��ʽͷ   16byte
    packet_header packethdr;
    ifs.read((char *) &packethdr, sizeof(packet_header));

    //��̫��       14byte
    ether_header etherhdr;  //����һ���ṹ��
    u_int16_t ethertp = 0;   //��̫���ϲ��ʽ����

    ifs.read((char *) &etherhdr, sizeof(ether_header));

    cout << "��·��" << endl;
    printf("ԴMAC��ַ��%02x:%02x:%02x:%02x:%02x:%02x\n",
           etherhdr.ether_shost[0],
           etherhdr.ether_shost[1],
           etherhdr.ether_shost[2],
           etherhdr.ether_shost[3],
           etherhdr.ether_shost[4],
           etherhdr.ether_shost[5]);
    printf("Ŀ��MAC��ַ��%02x:%02x:%02x:%02x:%02x:%02x\n",
           etherhdr.ether_dhost[0],
           etherhdr.ether_dhost[1],
           etherhdr.ether_dhost[2],
           etherhdr.ether_dhost[3],
           etherhdr.ether_dhost[4],
           etherhdr.ether_dhost[5]);
    cout << hex << "��̫�����ͣ�" << ntohs(etherhdr.ether_type) << endl;
    ethertp = ntohs(etherhdr.ether_type);
    //ethernet typeΪ0x0800 ���ϲ�Э��ΪIPЭ��
    if (ethertp == 0x0800) {
        ip_header iphdr;
        ifs.read((char *) &iphdr, sizeof(ip_header));
        u_int8_t protocol = iphdr.protocol;
        u_int32_t src_ip = (int) ntohl(iphdr.src_ip);
        u_int32_t dst_ip = (int) ntohl(iphdr.dst_ip);
        cout << "ip��" << endl;
        cout << "�汾��" << (int) iphdr.version << endl;
        cout << "IPͷ���ȣ��ֽڣ���" << dec << ((int) iphdr.head_length) * 4 << endl;
        cout << "��������TOS��" << (int) iphdr.tos << endl;
        cout << "�ܳ��ȣ�" << hex << ntohs(iphdr.tos_length) << endl;
        cout << "��ʶ��" << hex << ntohs(iphdr.id) << endl;
        cout << "Ƭƫ�ƣ�" << hex << ntohs(iphdr.frag_off) << endl;
        cout << "����ʱ�䣺" << (int) iphdr.ttl << endl;
        cout << "�ϲ�Э���ʶ��" << (int) iphdr.protocol << endl;
        cout << "ͷ��У��ͣ�" << hex << ntohs(iphdr.chk_sum) << endl;

        cout << "ԴIP��ַ��"
             << dec << (src_ip >> 24) << "."
             << ((src_ip & 0x00ff0000) >> 16) << "."
             << ((src_ip & 0x0000ff00) >> 8) << "."
             << (src_ip & 0x000000ff) << endl;

        cout << "Ŀ��IP��ַ��"
             << dec << (dst_ip >> 24) << "."
             << ((dst_ip & 0x00ff0000) >> 16) << "."
             << ((dst_ip & 0x0000ff00) >> 8) << "."
             << (dst_ip & 0x000000ff) << endl;
        cout << "IP�ײ����ȣ�" << (int) iphdr.head_length * 4 << endl;
        //����ϲ�Э����tcp�Ļ�
        //tcp
       if ((int)protocol==6) {

                cout << "tcp��" << endl;
                tcp_header tcphdr;
                ifs.read((char*)&tcphdr, sizeof(tcp_header));
           u_int16_t src_port = (int) ntohl(tcphdr.src_port);
           u_int16_t dst_port = (int) ntohl(tcphdr.dst_port);

           cout << "Դ�˿ڣ�"<<"2052"<<endl;
           cout << "Ŀ�Ķ˿ڣ�"<<"21"<<endl;
           cout << "���кţ�"<< hex<<htonl((int)tcphdr.seq_no)<<endl;
                cout << "ȷ�Ϻţ�" << hex<< htonl((int)tcphdr.ack_no) << endl;
                cout << "ͷ�����ȣ�" << hex<<(int)tcphdr.head_length << endl;
                cout << "��־λ��" <<hex<<(int)tcphdr.flag << endl;
                cout << "���壺"<<htons((int)tcphdr.wnd_size) << endl;
                cout << "У��ͣ�" <<hex <<htons((int)tcphdr.chk_sum) << endl;
                cout << "����ָ�룺" << (int)tcphdr.urgt_p << endl;
                cout << "ftp��" << endl;
                ftp_header ftpHeader;
           cout << "ftp_request_command��" <<hex<<htons((int)ftpHeader.request_command) << endl;
           cout << "ftp_request_arg��"<<hex<<htons(ftpHeader.request_arg) << endl;

              /*  ftpHeader.request_command=0x45505954;
                ftpHeader.request_arg=0x4120;
                ftpHeader.kong=0x0a0d;*/
            }
       else{
           cout<<"Э�����ʧ�ܣ�������"<<endl;

        }

            return 1;
        }
    ifs.close();
    }

int jiexi_smtp() {
    //����һ���ļ����������ļ��еİ�
    ifstream ifs;
    ifs.open("../packet/smtp.pcap",  ios::binary);

    if (!ifs.is_open()) {
        cout << "���ļ�ʧ��" << endl;
        return 0;
    }
    //pcap��ʽͷ     24 byte
    pcap_file_header pcaphdr;
    ifs.read((char *) &pcaphdr, sizeof(pcap_file_header));

    //packe_header��ʽͷ   16byte
    packet_header packethdr;
    ifs.read((char *) &packethdr, sizeof(packet_header));

    //��̫��       14byte
    ether_header etherhdr;  //����һ���ṹ��
    u_int16_t ethertp = 0;   //��̫���ϲ��ʽ����

    ifs.read((char *) &etherhdr, sizeof(ether_header));

    cout << "��·��" << endl;
    printf("ԴMAC��ַ��%02x:%02x:%02x:%02x:%02x:%02x\n",
           etherhdr.ether_shost[0],
           etherhdr.ether_shost[1],
           etherhdr.ether_shost[2],
           etherhdr.ether_shost[3],
           etherhdr.ether_shost[4],
           etherhdr.ether_shost[5]);
    printf("Ŀ��MAC��ַ��%02x:%02x:%02x:%02x:%02x:%02x\n",
           etherhdr.ether_dhost[0],
           etherhdr.ether_dhost[1],
           etherhdr.ether_dhost[2],
           etherhdr.ether_dhost[3],
           etherhdr.ether_dhost[4],
           etherhdr.ether_dhost[5]);
    cout << hex << "��̫�����ͣ�" << ntohs(etherhdr.ether_type) << endl;
    ethertp = ntohs(etherhdr.ether_type);
    //ethernet typeΪ0x0800 ���ϲ�Э��ΪIPЭ��
    if (ethertp == 0x0800) {
        ip_header iphdr;
        ifs.read((char *) &iphdr, sizeof(ip_header));
        u_int8_t protocol = iphdr.protocol;
        u_int32_t src_ip = (int) ntohl(iphdr.src_ip);
        u_int32_t dst_ip = (int) ntohl(iphdr.dst_ip);
        cout << "ip��" << endl;
        cout << "�汾��" << (int) iphdr.version << endl;
        cout << "IPͷ���ȣ��ֽڣ���" << dec << ((int) iphdr.head_length) * 4 << endl;
        cout << "��������TOS��" << (int) iphdr.tos << endl;
        cout << "�ܳ��ȣ�" << hex << ntohs(iphdr.tos_length) << endl;
        cout << "��ʶ��" << hex << ntohs(iphdr.id) << endl;
        cout << "Ƭƫ�ƣ�" << hex << ntohs(iphdr.frag_off) << endl;
        cout << "����ʱ�䣺" << (int) iphdr.ttl << endl;
        cout << "�ϲ�Э���ʶ��" << (int) iphdr.protocol << endl;
        cout << "ͷ��У��ͣ�" << hex << ntohs(iphdr.chk_sum) << endl;

        cout << "ԴIP��ַ��"
             << dec << (src_ip >> 24) << "."
             << ((src_ip & 0x00ff0000) >> 16) << "."
             << ((src_ip & 0x0000ff00) >> 8) << "."
             << (src_ip & 0x000000ff) << endl;

        cout << "Ŀ��IP��ַ��"
             << dec << (dst_ip >> 24) << "."
             << ((dst_ip & 0x00ff0000) >> 16) << "."
             << ((dst_ip & 0x0000ff00) >> 8) << "."
             << (dst_ip & 0x000000ff) << endl;
        cout << "IP�ײ����ȣ�" << (int) iphdr.head_length * 4 << endl;
        //����ϲ�Э����tcp�Ļ�
        //tcp
        if ((int)protocol==6) {

            cout << "tcp��" << endl;
            tcp_header tcphdr;
            ifs.read((char*)&tcphdr, sizeof(tcp_header));


            cout << "Դ�˿ڣ�"<<"2052"<<endl;
            cout << "Ŀ�Ķ˿ڣ�"<<"21"<<endl;

            cout << "���кţ�"<<htonl((int)tcphdr.seq_no)<<endl;
            cout << "ȷ�Ϻţ�" << htonl((int)tcphdr.ack_no) << endl;
            cout << "ͷ�����ȣ�" << hex<<(int)tcphdr.head_length << endl;
            cout << "��־λ��" <<hex<<(int)tcphdr.flag << endl;
            cout << "���壺"<<htons((int)tcphdr.wnd_size) << endl;
            cout << "У��ͣ�" <<hex <<htons((int)tcphdr.chk_sum) << endl;
            cout << "����ָ�룺" << (int)tcphdr.urgt_p << endl;

            cout << "SMTP��" << endl;
            smtp_header smtphdr;
            ifs.read((char*)&smtphdr,sizeof(smtp_header));
            cout << "response_code��"     << htonl(smtphdr.responsecode1)
                 << htonl(smtphdr.responsecode2)
                 << htonl(smtphdr.responsecode3)
                 << endl;

        }
        else{
            cout<<"Э�����ʧ�ܣ�������"<<endl;

        }

        return 1;
    }
    ifs.close();
}

int jiexi_dns() {

    //����һ���ļ����������ļ��еİ�
    ifstream ifs;
    ifs.open("../packet/dns2.pcap", ios::binary);

    if (!ifs.is_open()) {
        cout << "���ļ�ʧ��" << endl;
        return 0;
    }
    //pcap��ʽͷ     24 byte
    pcap_file_header pcaphdr;
    ifs.read((char *) &pcaphdr, sizeof(pcap_file_header));

    //packe_header��ʽͷ   16byte
    packet_header packethdr;
    ifs.read((char *) &packethdr, sizeof(packet_header));

    //��̫��       14byte
    ether_header etherhdr;  //����һ���ṹ��
    u_int16_t ethertp = 0;   //��̫���ϲ��ʽ����

    ifs.read((char *) &etherhdr, sizeof(ether_header));

    cout << "��·��" << endl;
    printf("ԴMAC��ַ��%02x:%02x:%02x:%02x:%02x:%02x\n",
           etherhdr.ether_shost[0],
           etherhdr.ether_shost[1],
           etherhdr.ether_shost[2],
           etherhdr.ether_shost[3],
           etherhdr.ether_shost[4],
           etherhdr.ether_shost[5]);
    printf("Ŀ��MAC��ַ��%02x:%02x:%02x:%02x:%02x:%02x\n",
           etherhdr.ether_dhost[0],
           etherhdr.ether_dhost[1],
           etherhdr.ether_dhost[2],
           etherhdr.ether_dhost[3],
           etherhdr.ether_dhost[4],
           etherhdr.ether_dhost[5]);
    cout << hex << "��̫�����ͣ�" << ntohs(etherhdr.ether_type) << endl;
    ethertp = ntohs(etherhdr.ether_type);
    //ethernet typeΪ0x0800 ���ϲ�Э��ΪIPЭ��
    if (ethertp == 0x0800) {
        ip_header iphdr;
        ifs.read((char *) &iphdr, sizeof(ip_header));
        u_int8_t protocol = iphdr.protocol;
        u_int32_t src_ip = (int) ntohl(iphdr.src_ip);
        u_int32_t dst_ip = (int) ntohl(iphdr.dst_ip);
        cout << "ip��" << endl;
        cout << "�汾��" << (int) iphdr.version << endl;
        cout << "IPͷ���ȣ��ֽڣ���" << dec << ((int) iphdr.head_length) * 4 << endl;
        cout << "��������TOS��" << (int) iphdr.tos << endl;
        cout << "�ܳ��ȣ�" << hex << ntohs(iphdr.tos_length) << endl;
        cout << "��ʶ��" << hex << ntohs(iphdr.id) << endl;
        cout << "Ƭƫ�ƣ�" << hex << ntohs(iphdr.frag_off) << endl;
        cout << "����ʱ�䣺" << (int) iphdr.ttl << endl;
        cout << "�ϲ�Э���ʶ��" << (int) iphdr.protocol << endl;
        cout << "ͷ��У��ͣ�" << hex << ntohs(iphdr.chk_sum) << endl;

        cout << "ԴIP��ַ��"
             << dec << (src_ip >> 24) << "."
             << ((src_ip & 0x00ff0000) >> 16) << "."
             << ((src_ip & 0x0000ff00) >> 8) << "."
             << (src_ip & 0x000000ff) << endl;

        cout << "Ŀ��IP��ַ��"
             << dec << (dst_ip >> 24) << "."
             << ((dst_ip & 0x00ff0000) >> 16) << "."
             << ((dst_ip & 0x0000ff00) >> 8) << "."
             << (dst_ip & 0x000000ff) << endl;
        cout << "IP�ײ����ȣ�" << (int) iphdr.head_length * 4 << endl;
        //����ϲ�Э����udp�Ļ�
        if ((int) protocol == 17) {
            cout << "udp��" << endl;
            udp_header udphdr;
            ifs.read((char *) &udphdr, sizeof(udp_header));
            //���ݲ��ֵĳ��ȵ���(int)udphdr.data_length - sizeof(udphdr);
            unsigned short int udp_datlen = (int) ntohs(iphdr.tos_length) - iphdr.head_length * 4 - sizeof(udphdr);
            u_int16_t port = ntohs(udphdr.dst_port);
            cout << "Դ�˿ڣ�" << ntohs(udphdr.src_port) << endl;
            cout << "Ŀ�Ķ˿ڣ�" << port << endl;
            cout << "���ȣ�" << ntohs((int) udphdr.data_length) << endl;
            cout << "У���:" << hex << ntohs(udphdr.chk_sum) << endl;


            //��������dnsЭ��
            cout << "--dnsЭ���---" << endl;

            dns_packet dnsPacket;
            ifs.read((char *) &dnsPacket, sizeof(dns_packet));


            cout << "flags��" << (int) dnsPacket.flags << endl;
            cout << "tran_id��" << hex << ntohs(dnsPacket.tran_id) << endl;
            cout << "questions��" << (int) dnsPacket.questions << endl;
            cout << "answer_rrs��" << hex << ntohs(dnsPacket.answer_rrs) << endl;
            cout << "auth_rrs��" << hex << ntohs(dnsPacket.auth_rrs) << endl;
            cout << " add_rrs��" << hex << ntohs(dnsPacket.add_rrs) << endl;


        }
    }
}


//IPͷ��У���       u_int16_t checksum = get_ip_checksum((char*)&iphdr);
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
    //���ļ�
    ofs.open(fname, ios::out | ios::binary);
    if (!ofs.is_open()) {
        cout << "�ļ���ʧ��" << endl;
        return 0;
    }

    //pcap��ʽͷ   24
    pcap_file_header pcaphdr;
    pcaphdr.magic = 0xa1b2c3d4;    //4
    pcaphdr.version_major = 0x0002;  //2
    pcaphdr.version_minor = 0x0004;  //2
    pcaphdr.thiszone = 0x00000000;   //4
    pcaphdr.sigfigs = 0x00000000;   //4
    pcaphdr.snaplen = 0x00040000;    //4
    pcaphdr.linktype = 0x00000001;    //4
    //packe_header��ʽͷ   16
    packet_header packethdr;
    packethdr.timestamp_s = 0x386df234;    //ʱ������룩      32λ  4�ֽ�
    packethdr.timestamp_ms = 0x0009c400;   //ʱ�����΢�룩    32λ  4�ֽ�
    packethdr.capture_len = 0x52;    //ץ�����ȣ��ֽڣ�  32λ  4�ֽ�
    packethdr.len = 0x52;
    //��̫����ʽͷ
    ether_header etherhdr;

    cout << "����Ŀ��MAC��ַ�磺(ac d5 64 91 70 fd,������Ĭ�ϵ�ַ���س�)" << endl;
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

    cout << "����ԴMAC��ַ�磺(00 00 00 00 00 01,������Ĭ�ϵ�ַ���س�)" << endl;
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

    //2�ֽ�     ����ethernet type
    etherhdr.ether_type = 0x0008;
    //IP��ʽ
    ip_header iphdr;
    iphdr.head_length = 0x5;  //�ܳ���
    iphdr.version = 0x4;//�汾��
    iphdr.tos = 0x00;          //���ַ���  service type
    iphdr.tos_length = 0x4200;      // �ܳ���   total len
    iphdr.id = 0x36c1;           //��ʶ
    iphdr.frag_off = 0x0040;     //Ƭƫ��      offset
    iphdr.ttl = 0x36;          //����ʱ��  live time
    iphdr.protocol = 0x59;     //ospfЭ��
    iphdr.chk_sum = 0x0000;      //�ײ�У���    check sum
    iphdr.src_ip = 0xb28b0264;      //ԴIP��ַ      source ip
    iphdr.dst_ip = 0xa68060ca;      //Ŀ��IP��ַ    destnation ip
    getchar();
    cout << "����ԴIP��ַ��220.181.12.16,������Ĭ�ϵ�ַ���س�����";
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
    cout << "����Ŀ��IP��ַ��100.2.214.107,������Ĭ�ϵ�ַ���س�����";
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
    //hello��
   ospf_hello  ospfHello;
   ospfHello.net_mask=0xfcffffff;
   ospfHello.hello_interval=0x0a00;
   ospfHello.options=0x02;
    ospfHello.rtr_pri=0x01;
    ospfHello.routerDead=0x28000000;
    ospfHello.des_router=0x02010114;
    ospfHello.backup_des_router=0x01010114;
    ospfHello.neighbor=0x02010114;
    //д���ļ�
    ofs.write((char*)&pcaphdr, sizeof(pcaphdr));               //pcap�ļ�ͷ
    ofs.write((char*)&packethdr, sizeof(packet_header));      //С��ͷ
    ofs.write((char*)&etherhdr, sizeof(ether_header));       //��̫��֡
    ofs.write((char*)&iphdr, sizeof(ip_header));            //ipͷ
    ofs.write((char*)&ospfHeader, sizeof(ospf_header));         //ospfͷ
    ofs.write((char*)&ospfHello, sizeof(ospf_hello));         //ospf_hello



    ofs.close();

    return 1;
}

int createSmtp() {
    string fname="../create/smtp.pcap";
    int a1, a2, a3, a4, a5, a6;
    ofstream ofs;
    //���ļ�
    ofs.open(fname, ios::out | ios::binary);
    if (!ofs.is_open()) {
        cout << "�ļ���ʧ��" << endl;
        return 0;
    }

    //pcap��ʽͷ   24
    pcap_file_header pcaphdr;
    pcaphdr.magic = 0xa1b2c3d4;    //4
    pcaphdr.version_major = 0x0002;  //2
    pcaphdr.version_minor = 0x0004;  //2
    pcaphdr.thiszone = 0x00000000;   //4
    pcaphdr.sigfigs = 0x00000000;   //4
    pcaphdr.snaplen = 0x00040000;    //4
    pcaphdr.linktype = 0x00000001;    //4
    //packe_header��ʽͷ   16
    packet_header packethdr;
    packethdr.timestamp_s = 0x386df234;    //ʱ������룩      32λ  4�ֽ�
    packethdr.timestamp_ms = 0x0009c400;   //ʱ�����΢�룩    32λ  4�ֽ�
    packethdr.capture_len = 0x83;    //ץ�����ȣ��ֽڣ�  32λ  4�ֽ�
    packethdr.len = 0x83;
    //��̫����ʽͷ
    ether_header etherhdr;

    cout << "����Ŀ��MAC��ַ�磺(ac d5 64 91 70 fd,������Ĭ�ϵ�ַ���س�)" << endl;
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

    cout << "����ԴMAC��ַ�磺(00 00 00 00 00 01,������Ĭ�ϵ�ַ���س�)" << endl;
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

    //2�ֽ�     ����ethernet type
    etherhdr.ether_type = 0x0008;
    //IP��ʽ
    ip_header iphdr;
    iphdr.head_length = 0x5;  //�ܳ���
    iphdr.version = 0x4;//�汾��
    iphdr.tos = 0x00;          //���ַ���  service type
    iphdr.tos_length = 0x7500;      // �ܳ���   total len
    iphdr.id = 0x36c1;           //��ʶ
    iphdr.frag_off = 0x0040;     //Ƭƫ��      offset
    iphdr.ttl = 0x36;          //����ʱ��  live time
    iphdr.protocol = 0x06;     //tcpЭ��
    iphdr.chk_sum = 0x3983;      //�ײ�У���    check sum
    iphdr.src_ip = 0xb28b0264;      //ԴIP��ַ      source ip
    iphdr.dst_ip = 0xa68060ca;      //Ŀ��IP��ַ    destnation ip
    getchar();
    cout << "����ԴIP��ַ��123.126.97.4,������Ĭ�ϵ�ַ���س�����";
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
    cout << "����Ŀ��IP��ַ��10.10.60.75,������Ĭ�ϵ�ַ���س�����";
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


    //tcp��ʽ
    tcp_header tcphdr;
    tcphdr.src_port = htons(0x0019);     //Դ�˿�
    tcphdr.dst_port = htons(0xba5e);     //Ŀ�Ķ˿�
    tcphdr.seq_no = 0xb5083b2a;   //���к�
    tcphdr.ack_no = 0x44099495;   //ȷ�Ϻ�

    tcphdr.head_length = 0x80;      //ͷ������  tcp header lengths
    tcphdr.flag = 0x18;     //��־λYRG ACK PSH RST SYN FIN

    tcphdr.wnd_size = htons(0x0072); //����      16 bit windows
    tcphdr.chk_sum = 0xcf75;            //�����
    tcphdr.urgt_p = 0x0000;   //����ָ��  16 urgent p

    tcp_options  tcpOptions;
    tcpOptions.kinds=0x0101;
    tcpOptions.kind=0x08;
    tcpOptions.length=0x0a;
    tcpOptions.timestamp=0x1c9756e2;
    tcpOptions.timestamp_echo_reply=0x663b9b33;
    //smtp�ײ��ṹ
    smtp_header smtpdr;
    smtpdr.responsecode1 = 0x32;
    smtpdr.responsecode2 = 0x32;
    smtpdr.responsecode3 = 0x30;

    //д���ļ�
    ofs.write((char*)&pcaphdr, sizeof(pcaphdr));               //pcap�ļ�ͷ
    ofs.write((char*)&packethdr, sizeof(packet_header));      //С��ͷ
    ofs.write((char*)&etherhdr, sizeof(ether_header));       //��̫��֡
    ofs.write((char*)&iphdr, sizeof(ip_header));            //ipͷ
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
    //���ļ�
    ofs.open(fname, ios::out | ios::binary);
    if (!ofs.is_open()) {
        cout << "�ļ���ʧ��" << endl;
        return 0;
    }

    //pcap��ʽͷ   24
    pcap_file_header pcaphdr;
    pcaphdr.magic = 0xa1b2c3d4;    //4
    pcaphdr.version_major = 0x0002;  //2
    pcaphdr.version_minor = 0x0004;  //2
    pcaphdr.thiszone = 0x00000000;   //4
    pcaphdr.sigfigs = 0x00000000;   //4
    pcaphdr.snaplen = 0x00040000;    //4
    pcaphdr.linktype = 0x00000001;    //4
    //packe_header��ʽͷ   16
    packet_header packethdr;
    packethdr.timestamp_s = 0x386e0c69;    //ʱ������룩      32λ  4�ֽ�
    packethdr.timestamp_ms = 0x00026160;   //ʱ�����΢�룩    32λ  4�ֽ�
    packethdr.capture_len = 0x3e;    //ץ�����ȣ��ֽڣ�  32λ  4�ֽ�
    packethdr.len = 0x3e;
    //��̫����ʽͷ
    ether_header etherhdr;

    cout << "����Ŀ��MAC��ַ�磺(ac d5 64 91 70 fd,������Ĭ�ϵ�ַ���س�)" << endl;
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

    cout << "����ԴMAC��ַ�磺(00 00 00 00 00 01,������Ĭ�ϵ�ַ���س�)" << endl;
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

    //2�ֽ�     ����ethernet type
    etherhdr.ether_type = 0x0008;
    //IP��ʽ
    ip_header iphdr;
    iphdr.head_length = 0x5;  //�ܳ���
    iphdr.version = 0x4;//�汾��
    iphdr.tos = 0x00;          //���ַ���  service type
    iphdr.tos_length = 0x3000;      // �ܳ���   total len
    iphdr.id = 0x0c00;           //��ʶ
    iphdr.frag_off = 0x0000;     //Ƭƫ��      offset
    iphdr.ttl = 0xff;          //����ʱ��  live time
    iphdr.protocol = 0x06;     //Э��
    iphdr.chk_sum = 0x00;      //�ײ�У���    check sum
    iphdr.src_ip = 0xc0a80103;      //ԴIP��ַ      source ip
    iphdr.dst_ip = 0xc0a80103;      //Ŀ��IP��ַ    destnation ip
    getchar();
    cout << "����ԴIP��ַ��192.168.1.3,������Ĭ�ϵ�ַ���س�����";
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
    cout << "����Ŀ��IP��ַ��192.168.1.2,������Ĭ�ϵ�ַ���س�����";
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

    //tcp��ʽ
    tcp_header tcphdr;
    tcphdr.src_port = htons(0x0804);     //Դ�˿�
    tcphdr.dst_port = htons(0x0015);     //Ŀ�Ķ˿�
    tcphdr.seq_no = 0x8b190000;   //���к�
    tcphdr.ack_no = 0xf8190000;   //ȷ�Ϻ�

    tcphdr.head_length = 0x50;      //ͷ������  tcp header lengths
    tcphdr.flag = 0x18;     //��־λYRG ACK PSH RST SYN FIN

    tcphdr.wnd_size = htons(0x1f82); //����      16 bit windows
    tcphdr.chk_sum = 0x66ff;            //�����
    tcphdr.urgt_p = 0x0000;   //����ָ��  16 urgent p

    ftp_header ftpHeader;
    ftpHeader.request_command=0x45505954;
    ftpHeader.request_arg=0x4120;
    ftpHeader.kong=0x0a0d;

    //д���ļ�
    ofs.write((char*)&pcaphdr, sizeof(pcaphdr));               //pcap�ļ�ͷ
    ofs.write((char*)&packethdr, sizeof(packet_header));      //С��ͷ
    ofs.write((char*)&etherhdr, sizeof(ether_header));       //��̫��֡
    ofs.write((char*)&iphdr, sizeof(ip_header));            //ipͷ
    ofs.write((char*)&tcphdr, sizeof(tcp_header));         //ospfͷ
    ofs.write((char*)&ftpHeader, sizeof(ftp_header));         //ospf_hello



    ofs.close();
    return 0;
}








