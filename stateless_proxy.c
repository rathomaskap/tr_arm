
/* $Id: stateless_proxy.c 3553 2011-05-05 06:14:19Z nanang $ */
/* 
 * Copyright (C) 2008-2011 Teluu Inc. (http://www.teluu.com)
 * Copyright (C) 2003-2008 Benny Prijono <benny@prijono.org>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA 
 */
#define THIS_FILE   "stateless_proxy.c"

/* Common proxy functions */
#define STATEFUL    0

// #include <string.h>

#include <err.h>
#include <stdarg.h>
#include <setjmp.h>

#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <stdio.h>
#include <arpa/inet.h>
#include <ioctl_netif.h>
#include <signal.h>

#include "proxy_iocl.h"
#include "/home/rainer/work/buildroot-2018.08.2/output/host/arm-buildroot-linux-gnueabihf/sysroot/usr/include/string.h"


extern struct t_config  *sp;
extern struct trace_config_t tc;



unsigned int snullNet = 192<<0|255<<8;

// unsigned int snullNet = 192<<0|168<<8|255<<16;
// unsigned int LOCALNet = 127<<0|0<<8|0<<16|1<<24;
// unsigned int LOCALNet = 192<<0|168<<8|70<<16|76<<24;

void sigusr1(int);


#include "proxy.h"
#include "myconfig.h"
#include <pjmedia/sdp.h>
#include <pj/list.h>
#include <stdlib.h>


char devnet[] = "/dev/devNet";


char strout[1000];

struct dnat_sip_proxy_h  dnat_sip_proxy;

// call_state wird nicht benoetigt
// enum ed137_call_state_t {ed137_call_idle=1,ed137_call_invite=2,ed137_call_ok=3, ed137_call_ack=4};


/*
 * Ein Verbindungsaufbau beginnt mit der Invite Meldung. In dieser Meldung steht im SDP unter Media Port die Portnummer des rufenden.
 * Die TRY Meldung wird nicht ausgewertet.
 * In der OK Response (200) steht die Port Nummer des gerufenen
 * Die Acknowledge Meldung schliesst den Dialog ab.
 *
 *
 *  r
 */

// unsigned int callindex;

enum call_state_t  {CS_IDLE=1,CS_INVITE,CS_TRYING,CS_OK};


#define MAX_STR_CALL 200
struct ed137_call_t
{
	PJ_DECL_LIST_MEMBER(struct ed137_call_t); // pjlib/include/pj/list.h
	unsigned int index;				// wird bei jedem call incrementiert
	char call_id[MAX_STR_CALL];				//
	unsigned short src_port;
	unsigned short des_port;
	pj_in_addr src_ip;
	pj_in_addr des_ip;
	enum call_state_t state;			// invite,
	char 	user[MAX_STR_CALL];				// User des Calls

};

struct ed137_call_t call_list; // verkettete Liste aller aktiven calls


int	cmp_call_user(struct ed137_call_t *call, struct t_config *sp);
int	send_call_data(struct ed137_call_t *call, struct t_config *sp,int index, int ioctl_id);
void print_ip(unsigned int ip);
void ip2string(char *buffer,unsigned int ip);
int	delete_call_data(struct ed137_call_t *call, struct t_config *sp,int index);
int get_lowest_callid(struct ed137_call_t *call);




// int cmp_call_list(void *value, const struct ed137_call_t *node)

int cmp_call_list(void *value, const pj_list_type *base_node)
{
	const struct ed137_call_t *node;

	node = (struct ed137_call_t *) base_node;

	char *call_id = (char *) value;
	int len1 = strlen(call_id);
	int len2 = strlen(node->call_id);
	if(len1 != len2) return 1; // nicht gleich, da Laenge unterschiedlich
	return strcmp(call_id,node->call_id);

}

/* Callback to be called to handle incoming requests. */
static pj_bool_t on_rx_request( pjsip_rx_data *rdata );

/* Callback to be called to handle incoming response. */
static pj_bool_t on_rx_response( pjsip_rx_data *rdata );

void print_call_info(struct ed137_call_t *call);
void print_call_list(struct ed137_call_t *call);



static pj_status_t init_stateless_proxy(void)
{
    static pjsip_module mod_stateless_proxy =
    {
	NULL, NULL,			    /* prev, next.	*/
	{ "mod-stateless-proxy", 19 },	    /* Name.		*/
	-1,				    /* Id		*/
	PJSIP_MOD_PRIORITY_UA_PROXY_LAYER,  /* Priority		*/
	NULL,				    /* load()		*/
	NULL,				    /* start()		*/
	NULL,				    /* stop()		*/
	NULL,				    /* unload()		*/
	&on_rx_request,			    /* on_rx_request()	*/
	&on_rx_response,		    /* on_rx_response()	*/
	NULL,				    /* on_tx_request.	*/
	NULL,				    /* on_tx_response()	*/
	NULL,				    /* on_tsx_state()	*/
    };

    pj_status_t status;

    /* Register our module to receive incoming requests. */
    status = pjsip_endpt_register_module( global.endpt, &mod_stateless_proxy);
    PJ_ASSERT_RETURN(status == PJ_SUCCESS, 1);

    return PJ_SUCCESS;
}


/* Callback to be called to handle incoming requests. */
static pj_bool_t on_rx_request( pjsip_rx_data *rdata )
{
    pjsip_tx_data *tdata;
    pj_status_t status;
    pjmedia_sdp_session *sdp;
    pjsip_uri *uri;
    pjsip_sip_uri *sip_uri;
    pjsip_contact_hdr *contact_hdr;
//    pj_pool_t *mypool;
    struct ed137_call_t *new_call;
    char call_id[MAX_STR_CALL];
    int len;
    struct ed137_call_t *call;

//    pjsip_rr_hdr *first_rr_hdr;
//    pjsip_rr_hdr *rr;

/*
    pjsip_routing_hdr *routing;
    pjsip_sip_uri *url;
    pjsip_sip_uri *myuri;
*/


   // unsigned short port;
    char *s;


    /* Verify incoming request */
    status = proxy_verify_request(rdata);
    if (status != PJ_SUCCESS) {
	app_perror("RX invalid request", status);
	return PJ_TRUE;
    }
/*
 * 	das sind die Werte fuer "data->msg_info.msg->line.req.method.id"
 *
    PJSIP_INVITE_METHOD,
    PJSIP_CANCEL_METHOD,
    PJSIP_ACK_METHOD,
    PJSIP_BYE_METHOD,
    PJSIP_REGISTER_METHOD,
    PJSIP_OPTIONS_METHOD,
*/

    printf("Type ID=%d\n",rdata->msg_info.msg->type);
    printf("ID=%d\n %s\n",rdata->msg_info.msg->line.req.method.id,rdata->msg_info.msg->line.req.method.name.ptr);

    /*
    PJ_DECL(pj_status_t) pjmedia_sdp_parse( pj_pool_t *pool,
    				        char *buf, pj_size_t len,
    					pjmedia_sdp_session **p_sdp );
	*/


	// mypool = pj_pool_create(&global.cp.factory, "request pool",4000, 4000, NULL);

	/*
	 * es wird angenommen, dass die URI des Gerufenen im request header und die des Rufenden im contact header steht
	 * TODO ueberpruefen, ob die obige Annahme stimmt.
	 */

    if(rdata->msg_info.msg->line.req.method.id == PJSIP_INVITE_METHOD) {

		s = rdata->msg_info.msg->body->data;


//		first_rr_hdr = pjsip_rr_hdr_create(global.pool);
//		myuri = pjsip_sip_uri_create( global.pool, PJ_FALSE);
//		pj_strdup2(global.pool, &myuri->host, "localhost");
//		first_rr_hdr->name_addr.uri = (pjsip_uri*) myuri;
//		rr = pjsip_rr_hdr_create(global.pool);
//        if (first_rr_hdr && rr){
//        	pj_list_insert_after(first_rr_hdr, rr);
//        }





        status = pjmedia_sdp_parse(global.pool,s,rdata->msg_info.msg->body->len,&sdp);


		if(status == PJ_SUCCESS){

			if(sdp->media_count == 1) {

			    uri = pjsip_uri_get_uri(rdata->msg_info.msg->line.req.uri);

			    /* nur SIP/SIPS schemes */
			    if (PJSIP_URI_SCHEME_IS_SIP(uri) || PJSIP_URI_SCHEME_IS_SIPS(uri)) {

			    	sip_uri = (pjsip_sip_uri*) uri;
			    	// ermittle den user des gerufenen

			    	snprintf(strout,sip_uri->user.slen+1,"%s",sip_uri->user.ptr);
			    	printf(" user:%s ",strout);
			    	// ist die invite Meldung eine Wiederholung?

		    		len = (rdata->msg_info.cid->id.slen+1)<MAX_STR_CALL?rdata->msg_info.cid->id.slen:MAX_STR_CALL;
					strncpy(call_id,rdata->msg_info.cid->id.ptr,len);
					call_id[len]='\0';
					new_call = pj_list_search(&call_list, call_id,cmp_call_list);
					if(new_call) {
						printf("den call gibt es schon\n");
						print_call_list(&call_list);

					} else
						{


						//if(user == inconfigfile)
							{
							new_call = 	malloc(sizeof(struct ed137_call_t));
							if(!new_call) {

								return PJ_FALSE;
							}
// 							new_call->index = callindex++;
							printf("======= get lowest callid\n");
							new_call->index = get_lowest_callid(&call_list);
							new_call->state = CS_INVITE;
							pj_list_push_back(&call_list,new_call);


							len = (sip_uri->user.slen+1)<MAX_STR_CALL?sip_uri->user.slen:MAX_STR_CALL;
							strncpy(new_call->user,sip_uri->user.ptr,len);
							new_call->user[len]='\0';


							new_call->src_port = sdp->media[0]->desc.port;
							new_call->des_ip = pj_inet_addr(&sip_uri->host);


		//			    	snprintf(strout,sip_uri->host.slen+1,"%s",sip_uri->host.ptr);
		//			    	printf("und die Audio muss nach Adresse %s ",strout);

							// suche contact header
							contact_hdr = pjsip_msg_find_hdr(rdata->msg_info.msg, PJSIP_H_CONTACT, NULL);
							if(contact_hdr) {

								uri = pjsip_uri_get_uri(contact_hdr->uri);
								if (PJSIP_URI_SCHEME_IS_SIP(uri) || PJSIP_URI_SCHEME_IS_SIPS(uri)) {

									sip_uri = (pjsip_sip_uri*) uri;

									new_call->src_ip = pj_inet_addr(&sip_uri->host);

									// Die Port Nummer des Gerufenen steht in der response Meldung

									// ermittle die
									len = (rdata->msg_info.cid->id.slen+1)<MAX_STR_CALL?rdata->msg_info.cid->id.slen:MAX_STR_CALL;
									strncpy(new_call->call_id,rdata->msg_info.cid->id.ptr,len);
									new_call->call_id[len]='\0';

									printf("neuer call\n");
									print_call_list(&call_list);


		//					    	snprintf(strout,sip_uri->host.slen+1,"%s",sip_uri->host.ptr);
		//					    	printf("und kommt von %s:%hd\n",strout,port);
								}
							}
						}
					}
			    }
			}
		}
    }
    else if(rdata->msg_info.msg->line.req.method.id == PJSIP_BYE_METHOD)
    {


		// das ist der Bye Request

		len = (rdata->msg_info.cid->id.slen+1)<MAX_STR_CALL?rdata->msg_info.cid->id.slen:MAX_STR_CALL;
		strncpy(call_id,rdata->msg_info.cid->id.ptr,len);
		call_id[len]='\0';
		call = pj_list_search(&call_list, call_id,cmp_call_list);
		if(call) {

			printf("call aus Liste entfernt!\n");
			print_call_info(call);
			// TODO hier muss der Call entfernt werden
			pj_list_erase(call);
			printf("active call List\n");
			print_call_list(&call_list);
			call->state = CS_IDLE;
			delete_call_data(call, sp,call->index);
			free(call);

		}
		else  {
			printf("call nicht in Liste gefunden\n");
			print_call_list(&call_list);

		}



    }


    /*
     * Request looks sane, next clone the request to create transmit data.
     */
    status = pjsip_endpt_create_request_fwd(global.endpt, rdata, NULL, NULL, 0, &tdata);
    if (status != PJ_SUCCESS) {
		pjsip_endpt_respond_stateless(global.endpt, rdata, PJSIP_SC_INTERNAL_SERVER_ERROR, NULL,NULL, NULL);
		return PJ_TRUE;
    }



//     pjsip_msg_add_hdr(tdata->msg, (pjsip_hdr*)rr);

/*

    routing = pjsip_rr_hdr_create(global.pool);
    pjsip_msg_add_hdr(tdata->msg, (pjsip_hdr*)routing);
    url = pjsip_sip_uri_create(global.pool, 0);
    routing->name_addr.uri = (pjsip_uri*)url;
    pj_strdup2(global.pool, &url->host, "192.168.70.76");
    url->lr_param = 0;
*/

    /* Process routing */
    status = proxy_process_routing(tdata);
    if (status != PJ_SUCCESS) {
	app_perror("Error processing route", status);
	return PJ_TRUE;
    }

    /* Calculate target */
    status = proxy_calculate_target(rdata, tdata);
    if (status != PJ_SUCCESS) {
	app_perror("Error calculating target", status);
	return PJ_TRUE;
    }

    /* Target is set, forward the request */
    status = pjsip_endpt_send_request_stateless(global.endpt, tdata,NULL, NULL);
    if (status != PJ_SUCCESS) {
	app_perror("Error forwarding request", status);
	return PJ_TRUE;
    }

//    pj_pool_safe_release(&mypool);

    return PJ_TRUE;
}


/* Callback to be called to handle incoming response. */
static pj_bool_t on_rx_response( pjsip_rx_data *rdata )
{
    pjsip_tx_data *tdata;
    pjsip_response_addr res_addr;
    pjsip_via_hdr *hvia;
    pj_status_t status;
    int index;

    pjmedia_sdp_session *sdp;
//    pj_str_t *uri;
    pj_pool_t *mypool;


    unsigned short port;
    char *s;
    int len;
    char call_id[MAX_STR_CALL];
    struct ed137_call_t *call;


    /* Create response to be forwarded upstream (Via will be stripped here) */
    status = pjsip_endpt_create_response_fwd(global.endpt, rdata, 0, &tdata);
    if (status != PJ_SUCCESS) {
	app_perror("Error creating response", status);
	return PJ_TRUE;
    }

    /* Get topmost Via header */
    hvia = (pjsip_via_hdr*) pjsip_msg_find_hdr(tdata->msg, PJSIP_H_VIA, NULL);
    if (hvia == NULL) {
	/* Invalid response! Just drop it */
	pjsip_tx_data_dec_ref(tdata);
	return PJ_TRUE;
    }

    /* Calculate the address to forward the response */
    pj_bzero(&res_addr, sizeof(res_addr));
    res_addr.dst_host.type = PJSIP_TRANSPORT_UDP;
    res_addr.dst_host.flag = pjsip_transport_get_flag_from_type(PJSIP_TRANSPORT_UDP);

    /* Destination address is Via's received param */
    res_addr.dst_host.addr.host = hvia->recvd_param;
    if (res_addr.dst_host.addr.host.slen == 0) {
	/* Someone has messed up our Via header! */
	res_addr.dst_host.addr.host = hvia->sent_by.host;
    }

    /* Destination port is the rpot */
    if (hvia->rport_param != 0 && hvia->rport_param != -1)
	res_addr.dst_host.addr.port = hvia->rport_param;

    if (res_addr.dst_host.addr.port == 0) {
	/* Ugh, original sender didn't put rport!
	 * At best, can only send the response to the port in Via.
	 */
	res_addr.dst_host.addr.port = hvia->sent_by.port;
    }

	mypool = pj_pool_create(&global.cp.factory, "request pool",4000, 4000, NULL);


    // printf("Type ID=%d\n",rdata->msg_info.msg->type); // auf den Typ muss man nicht testen, da nur eine Response in Frage kommt

	printf("method.id =%d\n",rdata->msg_info.msg->line.req.method.id);

    if(rdata->msg_info.msg->line.req.method.id == 200) {
    	// hier interessiert nur die OK Meldungen, da dort der Messagebody mit gesendet wird
    	// bestimme Port Nr des gerufenen und call_id
    	if(rdata->msg_info.cseq->method.id == PJSIP_INVITE_METHOD) {

			if(rdata->msg_info.msg->body) {

				s = rdata->msg_info.msg->body->data;
				status = pjmedia_sdp_parse(mypool,s,rdata->msg_info.msg->body->len,&sdp);
				if(status == PJ_SUCCESS){
					if(sdp->media_count == 1) {

						port = sdp->media[0]->desc.port;
						printf("die Portnummer des gerufenen ist %hd\n",port);

						len = (rdata->msg_info.cid->id.slen+1)<MAX_STR_CALL?rdata->msg_info.cid->id.slen:MAX_STR_CALL;
						strncpy(call_id,rdata->msg_info.cid->id.ptr,len);
						call_id[len]='\0';
						call = pj_list_search(&call_list, call_id,cmp_call_list);
						if(call) {
							// die Call ID ist in der Liste vorhanden
							call->des_port = port;
							// TODO  hier muss der Aufruf IOCTL erfolgen
							if(call->state == CS_INVITE) {

								// es kann mehrfach ok gesendet werden, z.B. wenn der codec nicht passt
								index = cmp_call_user(call,sp);
								if(index>=0) {
									printf("call in Liste gefunden und user ok,!\n");
									call->state = CS_OK;
									print_call_list(&call_list);
									send_call_data(call,sp,index,NETIF_SET_TRACE_SESSIONS);
								} else
								{
									printf("user des calls nicht im config File gefunden\n");
									pj_list_erase(call);

								}

							}
						}
					}
				}
			}
    	}
    	else if(rdata->msg_info.cseq->method.id == PJSIP_BYE_METHOD || rdata->msg_info.cseq->method.id == PJSIP_CANCEL_METHOD) {
    		// das ist die Statusmeldung auf Bye

    		/*
    		len = (rdata->msg_info.cid->id.slen+1)<MAX_STR_CALL?rdata->msg_info.cid->id.slen:MAX_STR_CALL;
			strncpy(call_id,rdata->msg_info.cid->id.ptr,len);
			call_id[len]='\0';
			call = pj_list_search(&call_list, call_id,cmp_call_list);
			if(call) {

				printf("call aus Liste entfernt!\n");
				print_call_info(call);
				// TODO hier muss der Call entfernt werden
				pj_list_erase(call);
				printf("active call List\n");
				print_call_list(&call_list);
				call->state = CS_IDLE;
				delete_call_data(call, sp,call->index);
				free(call);

			}
			else  {
				printf("call nicht in Liste gefunden\n");
				print_call_list(&call_list);

			}

		*/

    	}
    }

    pj_pool_safe_release(&mypool);


    printf("Response ID=%d\n",rdata->msg_info.msg->line.req.method.id);

    snprintf(strout,rdata->msg_info.msg->line.req.method.name.slen+1,"%s",rdata->msg_info.msg->line.req.method.name.ptr);
    printf("Response Name = %s\n",strout);


    /* Forward response */
    status = pjsip_endpt_send_response(global.endpt, &res_addr, tdata, NULL, NULL);
    if (status != PJ_SUCCESS) {
	app_perror("Error forwarding response", status);
	return PJ_TRUE;
    }

    return PJ_TRUE;
}


/*
 * main()
 */

int dz_net;
struct sigaction sa;

int main(int argc, char *argv[])
{
    pj_status_t status;
    int ret;
    char buffer[32];
	struct ed137_call_t *p;
	int index;


    global.send_config = PJ_FALSE;
    printf("tr_arm2 Version 1.0\n");
	dz_net = open(devnet,O_RDWR);
	memset(&dnat_sip_proxy,0,sizeof(dnat_sip_proxy));

	sa.sa_flags = 0;
	sigemptyset(&sa.sa_mask);
	sigaddset(&sa.sa_mask, SIGUSR1);
	sa.sa_handler = sigusr1;
	sigaction(SIGUSR1, &sa, NULL);



	if(argc >1 && argv[argc-1][0] != '-') {

    	ret = readConfig(argv[argc-1]);
    	if (ret == EXIT_FAILURE) return -1;

    	/*
    	 * config mit ioctl senden
    	 */

    	dz_net = open(devnet,O_RDWR);
    	ret = ioctl_reset_all_sessions(dz_net);
    	if(ret==-1) {
    		printf("error: reset all sessions\n");
    	}

    ret = ioctl_set_trace_config(dz_net,&tc);

    	if (ret) {
    		printf("error: set_trace_config\n");
    	}




    }
//	printf("loesche alle Firewall NAT regeln\n");
//	system("iptables -t nat -F"); // alle Firewall Regeln loeschen

    global.port = 5060;
    pj_log_set_level(4);

    status = init_options(argc, argv);
    if (status != PJ_SUCCESS)
	return 1;



/*
   print_ip(htonl(dnat_sip_proxy.src_net1));
//   printf("srcip=%X\n",dnat_sip_proxy.src_net1);
   if(dnat_sip_proxy.src_net1&0xff000000){
	   dnat_sip_proxy.src_net1 &=0x00ffffff;
	   ip2string(buffer,htonl(dnat_sip_proxy.src_net1));
	   printf("Adresse src_net1 auf %s geaendert\n",buffer);
   }

   printf("src_net2=");
   print_ip(htonl(dnat_sip_proxy.src_net2));

   if(dnat_sip_proxy.src_net2&0xff000000){
	   dnat_sip_proxy.src_net2 &=0x00ffffff;
	   ip2string(buffer,htonl(dnat_sip_proxy.src_net2));
	   printf("Adresse src_net2 auf %s geaendert\n",buffer);
   }
*/

   printf("src_net1= %X ",dnat_sip_proxy.src_net1);
   print_ip(htonl(dnat_sip_proxy.src_net1));
   printf(" srcip1=%X\n",dnat_sip_proxy.sip_ip1);

   printf("netmask ip1=");
   print_ip(htonl(dnat_sip_proxy.netmask_ip1));
   printf("  %X\n",dnat_sip_proxy.netmask_ip2);

   printf("src_net2= %X ",dnat_sip_proxy.src_net2);
   print_ip(htonl(dnat_sip_proxy.src_net2));
   printf(" srcip2=%X\n",dnat_sip_proxy.sip_ip2);

   printf("netmask ip2=");
   print_ip(htonl(dnat_sip_proxy.netmask_ip2));
   printf("  %X\n",dnat_sip_proxy.netmask_ip2);




//    if(dnat_sip_proxy.src_net1&0xff000000){
// 	   dnat_sip_proxy.src_net1 &=0x00ffffff; 
// 	   ip2string(buffer,htonl(dnat_sip_proxy.src_net1));
// 	   printf("Adresse src_net1 auf %s geaendert\n",buffer);
//    }

   if(htonl(dnat_sip_proxy.src_net1) & ~htonl(dnat_sip_proxy.netmask_ip1)) {

	   printf("netaddr1 %X netmask1 %X \n", htonl(dnat_sip_proxy.src_net1), ~htonl(dnat_sip_proxy.netmask_ip1));

	   unsigned tmp = htonl(dnat_sip_proxy.src_net1) & htonl(dnat_sip_proxy.netmask_ip1);
	   dnat_sip_proxy.src_net1 = htonl(tmp);
	   ip2string(buffer,htonl(dnat_sip_proxy.src_net1));
	   printf("Adresse src_net1 auf %s geaendert\n",buffer);
   }
   


   printf("src_net2=");
   print_ip(htonl(dnat_sip_proxy.src_net2));

//    if(dnat_sip_proxy.src_net2&0xff000000){
// 	   dnat_sip_proxy.src_net2 &=0x00ffffff;
// 	   ip2string(buffer,htonl(dnat_sip_proxy.src_net2));
// 	   printf("Adresse src_net2 auf %s geaendert\n",buffer);
//    }


   if(htonl(dnat_sip_proxy.src_net2) & ~htonl(dnat_sip_proxy.netmask_ip2)) {

	   printf("netaddr2 %X netmask2 %X \n", htonl(dnat_sip_proxy.src_net2), ~htonl(dnat_sip_proxy.netmask_ip2));

	   unsigned tmp = htonl(dnat_sip_proxy.src_net2) & htonl(dnat_sip_proxy.netmask_ip2);
	   dnat_sip_proxy.src_net2 = htonl(tmp);
	   ip2string(buffer,htonl(dnat_sip_proxy.src_net2));
	   printf("Adresse src_net2 auf %s geaendert\n",buffer);
   }

//	getchar();

   printf("sip_ip1=");
   print_ip(htonl(dnat_sip_proxy.sip_ip1));

   printf("sip_ip2=");
   print_ip(htonl(dnat_sip_proxy.sip_ip2)); 

   ret =  ioctl_set_sip_proxy_addr(dz_net,&dnat_sip_proxy);
   if(ret) {
	   printf("error: ioctl_set_sip_proxy_addr\n");
	   return -1;
   }



    status = init_stack();
    if (status != PJ_SUCCESS) {
	app_perror("Error initializing stack", status);
	return 1;
    }

    status = init_proxy();
    if (status != PJ_SUCCESS) {
	app_perror("Error initializing proxy", status);
	return 1;
    }

    status = init_stateless_proxy();
    if (status != PJ_SUCCESS) {
	app_perror("Error initializing stateless proxy", status);
	return 1;
    }

    pj_list_init(&call_list);


#if PJ_HAS_THREADS
    status = pj_thread_create(global.pool, "sproxy", &worker_thread, 
			      NULL, 0, 0, &global.thread);
    if (status != PJ_SUCCESS) {
	app_perror("Error creating thread", status);
	return 1;
    }

    while (!global.quit_flag) {
	char line[10];

	puts("\n"
	     "Menu:\n"
	     "  q    quit\n"
	     "  d    dump status\n"
	     "  dd   dump detailed status\n"
		 "  c    call list\n"
	     "");

	while (fgets(line, sizeof(line), stdin) == NULL) {

	    // puts("EOF while reading stdin, will quit now..");
	    // global.quit_flag = PJ_TRUE;
	    // break;
		global.send_config = PJ_FALSE;
		if(sp) {
			free(sp->sessionParam);
		}
		free(sp);
		sp=NULL;
		ret = readConfig(argv[argc-1]);
    	if (ret == EXIT_FAILURE)
    		{
    		global.quit_flag = PJ_TRUE;
    		printf("error: reading config file or wrong syntax in config file\n");
       		}

   		global.send_config = PJ_FALSE;

   		p = &call_list;
    	while ((p=p->next) != &call_list) {
			index = cmp_call_user(p,sp);
			if(index>=0) {
				printf("call in Liste gefunden und user ok,!\n");
				print_call_list(p);
				send_call_data(p,sp,index,NETIF_UPDATE_TRACE_SESSIONS);
			} else
			{
				printf("user des calls nicht aktueller call_list gefunden\n");
			}
    	}












	}

	if (line[0] == 'q') {
	    global.quit_flag = PJ_TRUE;
	} else if (line[0] == 'd') {
	    pj_bool_t detail = (line[1] == 'd');
	    pjsip_endpt_dump(global.endpt, detail);
#if STATEFUL
	    pjsip_tsx_layer_dump(detail);
#endif
	} else if('c') {
		print_call_list(&call_list);
		}
    }

    pj_thread_join(global.thread);

#else
    puts("\nPress Ctrl-C to quit\n");
    for (;;) {
	pj_time_val delay = {0, 0};
	pjsip_endpt_handle_events(global.endpt, &delay);
    }
#endif

    destroy_stack();

    return 0;
}


void print_call_info(struct ed137_call_t *call)
{
char addr_ptr[20];

printf("user:%s\n",call->user);
printf("call_id: %s\n",call->call_id);
printf("call_index:%d\n",call->index);
printf("call_state:%d\n",call->state);

pj_inet_ntop(PJ_AF_INET, &call->src_ip,	addr_ptr, 20);
printf("ip_src: %s:%hd\n",addr_ptr,call->src_port);
pj_inet_ntop(PJ_AF_INET, &call->des_ip,	addr_ptr, 20);
printf("ip_des: %s:%hd\n",addr_ptr, call->des_port);

}

void print_call_list(struct ed137_call_t *call)
{
	struct ed137_call_t *p;
	p = call;
	while ((p=p->next) != call) {
		print_call_info(p);
	}

}

/*
 * sucht die kleinste id in der verketteten Liste.
 * int get_lowest_callid(struct ed137_call_t *call)
 */

int get_lowest_callid(struct ed137_call_t *call)
{
struct ed137_call_t *p;
int found;
int call_id = 0;

if(call->next == call)
	{
	printf("list of calls is empty\n");
	return 0; // Liste ist leer
	}

do {
	found = 0;
	p = call;
//	printf("+found=%d p=%X call=%X\n",found,p,call);
	p=p->next;
	while (p!= call)
		{
//		printf("-found=%d p=%X call=%X %d \n",found,p,call,call_id);
		if(p->index == call_id)
			{
			found = -1;
			call_id++;
			break;
			}
		p=p->next;
		}
//	printf("!found=%d p=%X call=%X %d \n",found,p,call,call_id);


	}
while (found);
printf("==================new call ID is %d\n",call_id);
return call_id;
}


/*
 * return index von sessionParameter, -1 Fehler
 */


int	cmp_call_user(struct ed137_call_t *call, struct t_config *sp)
{
int retval = -1;
for (int i=0;i<sp->count;i++) {
	retval = strncmp(call->user,sp->sessionParam[i].userpart,strlen(sp->sessionParam[i].userpart));
	if (!retval && strlen(sp->sessionParam[i].userpart)) {
		retval = i;
		break;
	}

}
return retval;
}

int	delete_call_data(struct ed137_call_t *call, struct t_config *sp,int index)
{
	int id;
	int ret;

	id = call->index;
	ret =  ioctl_del_trace_session(dz_net,id);
	if(ret == -1) {
		printf("error: ioctl %s\n",__FUNCTION__);
	}
	return ret;
}


int	send_call_data(struct ed137_call_t *call, struct t_config *sp,int index,int ioctl_id)
{
	struct trace_session_t ts;

	int ret;
	int i;

	ts.id = call->index;
	ts.on_delay.autorepeat = 	!strncmp(sp->sessionParam[index].on.autorepeat,"on",2)?-1:0;
	ts.on_delay.r2s_delay =  	!strncmp(sp->sessionParam[index].on.r2sdelay,"on",2)?-1:0;
	ts.on_delay.lenght = 		sp->sessionParam[index].on.index;
	for(i=0;i<ts.on_delay.lenght;i++) {
		ts.on_delay.delay[i] = sp->sessionParam[index].on.array[i];
	}

	ts.off_delay.autorepeat = 	!strncmp(sp->sessionParam[index].off.autorepeat,"on",2)?-1:0;
	ts.off_delay.r2s_delay =  	!strncmp(sp->sessionParam[index].off.r2sdelay,"on",2)?-1:0;
	ts.off_delay.lenght = 		sp->sessionParam[index].off.index;
	for(i=0;i<ts.off_delay.lenght;i++) {
		ts.off_delay.delay[i] = sp->sessionParam[index].off.array[i];
	}





	if(!strncmp("from_uas",sp->sessionParam[index].direction,sizeof("from_uas"))) {
		printf("direction is from_uas\n");
		ts.desip = call->src_ip.s_addr;
		ts.desport = call->src_port;
		ts.srcip = call->des_ip.s_addr;
		ts.srcport = call->des_port;
		ts.to_uas = 0;

	} else {
		printf("direction is to_uas\n");
		ts.desip = call->des_ip.s_addr;
		ts.desport = call->des_port;
		ts.srcip = call->src_ip.s_addr;
		ts.srcport = call->src_port;
		ts.to_uas = -1;
	}


	ts.desport = htons(ts.desport);
	ts.srcport = htons(ts.srcport);




	printf("FUNCTION:%s\n", __FUNCTION__);
	printf("id:             %d\n",ts.id);
	printf("desip:         ");
	// ts.destip = htonl(ts.destip);
	print_ip(htonl(ts.desip));

	printf("srcip:         ");
	// ts.destip = htonl(ts.destip);
	print_ip(htonl(ts.srcip));

	ts.dummydesip = snullNet;
	ts.dummydesip&=0x0000ffff;
	ts.dummydesip|= ts.desip&0xffff0000;

	ts.dummysrcip = snullNet;
	ts.dummysrcip&=0x0000ffff;
	ts.dummysrcip|= ts.srcip&0xffff0000;



	printf("***************************\n");
	printf("dummydesip:        ");
	print_ip(htonl(ts.dummydesip));
	printf("dummysrcip:        ");
	print_ip(htonl(ts.dummysrcip));

	printf("dst_port:       %hd\n",htons(ts.desport));
	printf("src_port:       %hd\n",htons(ts.srcport));

	printf("on  lenght:         %d\n",ts.on_delay.lenght);
	printf("on  r2s_delay:      %d\n",ts.on_delay.r2s_delay);
	printf("on  autorepeat:     %d\n",ts.on_delay.autorepeat);

	ip2string(sp->sessionParam[index].desip,ts.desip);
	ip2string(sp->sessionParam[index].srcip,ts.srcip);
	for(int i=0;i<ts.on_delay.lenght;i++)  {
		printf("on  delay data[%d] = %X\n",i,ts.on_delay.delay[i]);
	}
	printf("off lenght:         %d\n",ts.off_delay.lenght);
	printf("off r2s_delay:      %d\n",ts.off_delay.r2s_delay);
	printf("off autorepeat:     %d\n",ts.off_delay.autorepeat);
	for(int i=0;i<ts.off_delay.lenght;i++)  {
		printf("off delay data[%d] = %X\n",i,ts.off_delay.delay[i]);
	}

	printf("***************************\n");


//	ip2string(sp->sessionParam[index].dummyip,ts.dummyip);
//	sprintf(sp->sessionParam[index].iptables,"/usr/sbin/iptables -t nat -p udp %s PREROUTING -d %s  --dport %hd --sport %hd -i eth0 -j DNAT --to %s:%hd\n","-A",sp->sessionParam[index].destip,ts.dst_port,ts.src_port,sp->sessionParam[index].dummyip,ts.dst_port);
//	sprintf(sp->sessionParam[index].iptables,"/usr/sbin/iptables -t nat %s PREROUTING -d %s  -i eth0 -j DNAT --to %s\n","-A",sp->sessionParam[index].destip,sp->sessionParam[index].dummyip);
//	printf("%s\n",sp->sessionParam[index].iptables);
//	system(sp->sessionParam[index].iptables);
//	system("route del -net 192.168.255.0 netmask 255.255.255.0 sn0");
//	system("route add -net 192.168.255.0 netmask 255.255.255.0 sn0");

	switch (ioctl_id) {
		case NETIF_SET_TRACE_SESSIONS:
			ret = ioctl_set_trace_session(dz_net,&ts);
			if(ret == -1) {
				printf("error: ioctl NETIF_SET_TRACE_SESSIONS %s\n",__FUNCTION__);
			}
			break;
		case NETIF_UPDATE_TRACE_SESSIONS:
			ret = ioctl_update_trace_session(dz_net,&ts);
			if(ret == -1) {
				printf("error: ioctl NETIF_UPDATE_TRACE_SESSIONS %s\n",__FUNCTION__);
			}
			break;
	}

return 0;
}

void ip2string(char *buffer,unsigned int ip)
{
	unsigned char bytes[4];
	bytes[0] = ip & 0xFF;
	bytes[1] = (ip >> 8) & 0xFF;
	bytes[2] = (ip >> 16) & 0xFF;
	bytes[3] = (ip >> 24) & 0xFF;
	sprintf(buffer,"%d.%d.%d.%d", bytes[3], bytes[2], bytes[1], bytes[0]);
}

void print_ip(unsigned int ip)
{
    unsigned char bytes[4];
    bytes[0] = ip & 0xFF;
    bytes[1] = (ip >> 8) & 0xFF;
    bytes[2] = (ip >> 16) & 0xFF;
    bytes[3] = (ip >> 24) & 0xFF;
    printf("%d.%d.%d.%d\n", bytes[3], bytes[2], bytes[1], bytes[0]);
}


void sigusr1(int a)
{
printf("sigusr1 detected, send config file parameter\n");
global.send_config = PJ_TRUE;
}
