#include <ioctl_netif.h>


unsigned int src_net1;	// ip Adresse des UAS oder UAC der ruft
unsigned int src_net2;	// ip Adresse des UAS oder UAC der ruft
unsigned int sip_ip1;	// ip Adresse des sip proxys
unsigned int sip_ip2;	// ip Adresse des sip proxys
unsigned int netmask_ip1;	// ip Adresse des sip proxys
unsigned int netmask_ip2;	// ip Adresse des sip proxys


// unsigned int mask = -(1 << 32 - prefix);


dnat_sip_proxy_h ip2kernel;


