/**
 * @file ipconfiguration.cpp
 * @author Rainer Thomas (rainer.thomas.ube@t-online.de)
 * @brief
 * @version 0.1
 * @date 2024-06-20
 *
 * @copyright Copyright (c) 2024
 *
 */
#include <string>
#include <json.hpp>
#include <ioctl_netif.h>
#include <iostream>
#include <fstream>
#include <ostream>
#include <arpa/inet.h>
#include "logger.h"

/******
unsigned int src_net1;	// ip Adresse des UAS oder UAC der ruft
unsigned int src_net2;	// ip Adresse des UAS oder UAC der ruft
unsigned int sip_ip1;	// ip Adresse des sip proxys
unsigned int sip_ip2;	// ip Adresse des sip proxys
unsigned int netmask_ip1;	// ip Adresse des sip proxys
unsigned int netmask_ip2;	// ip Adresse des sip proxys
 */

// {"ip":[{"id":0,"mac":"22:33:44:55:66:77","ipAddress":"192.168.1.200","netMask":24,"gateway":"192.168.1.254"},{"id":1,"mac":"22:33:44:55:66:78","ipAddress":"192.168.2.200","netMask":24,"gateway":"192.168.2.254"}],"route":[]}

using namespace nlohmann;

using namespace std;

namespace ns_ip
{

    void from_json(const json &j, dnat_sip_proxy_h &dsp)
    {

        try
        {
            json tmp1 = j.at("ip")[0];

            string ip1Str = tmp1.at("ipAddress");
            string strMask1 = tmp1.at("netMask");

            json tmp2 = j.at("ip")[1];
            string ip2Str = tmp2.at("ipAddress");
            string strMask2 = tmp2.at("netMask");

            int mask1 = stoi(strMask1);
            int mask2 = stoi(strMask2);

            iprint(LOG_INFO, "IP CONFIG: ip1=%s/%d ip2=%s/%d", ip1Str.c_str(), mask1, ip2Str.c_str(), mask2);
            
            inet_aton(ip1Str.c_str(), (in_addr *)&dsp.sip_ip1);
            inet_aton(ip2Str.c_str(), (in_addr *)&dsp.sip_ip2);

            dsp.sip_ip1 = htonl(dsp.sip_ip1);
            dsp.sip_ip2 = htonl(dsp.sip_ip2);

            dsp.netmask_ip1 = -(1 << 32 - mask1);
            dsp.netmask_ip2 = -(1 << 32 - mask2);

            dsp.src_net1 = dsp.sip_ip1 & dsp.netmask_ip1;
            dsp.src_net2 = dsp.sip_ip2 & dsp.netmask_ip2;

            dsp.sip_ip1 = htonl(dsp.sip_ip1);
            dsp.sip_ip2 = htonl(dsp.sip_ip2);
            dsp.netmask_ip1 = htonl(dsp.netmask_ip1);
            dsp.netmask_ip2 = htonl(dsp.netmask_ip2);
            dsp.src_net1 = htonl(dsp.src_net1);
            dsp.src_net2 = htonl(dsp.src_net2);

            // iprint(LOG_INFO, "IP CONFIG: ip1=%X ip2=%X mask1=%X mask2=%X net1=%X net2=%X\n", dsp.sip_ip1, dsp.sip_ip2, dsp.netmask_ip1, dsp.netmask_ip2, dsp.src_net1, dsp.src_net2);
        }
        catch (std::exception &e)
        {
            iprint(LOG_INFO,"excetion convert ipConfiguration to  \"dnat_sip_proxy_h\"   %s\n",e.what()); 
        }
        catch (...)
        {
            iprint(LOG_INFO,"excetion convert ipConfiguration to  \"dnat_sip_proxy_h\"   \n"); 
            
        }
    }
}
