/**
 * @file pvmain.cpp
 * @author Rainer Thomas (rainer.thomas.ube@t-online.de)
 * @brief  Steuerung des SIP Proxy im Paketverzoegerer
 * @version 0.1
 * @date 2024-06-13
 * 
 * @copyright Copyright (c) 2024
 * 
 */


#define THIS_FILE   "pvmain.cpp"

#include <iostream>
#include <fstream>
#include <ostream>
#include <string>
#include <iomanip>
#include <exception>
#include <string_view>
#include <functional>
#include <thread>
#include <mutex>
#include <condition_variable>

#include <stdio.h>
#include <errno.h>
#include <ctype.h>

#include <unistd.h>
#include <string.h>
#include <stdlib.h>
#include <fcntl.h>
#include <termios.h>
#include <signal.h>
#include <sys/ioctl.h>
#include <regex.h>
#include <sys/ipc.h> 
#include <sys/shm.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <sys/poll.h>
#include <ifaddrs.h>
#include <json.hpp>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <syslog.h>
#include <sstream>
#include <thread>
#include <string>
#include <map>
#include <limits.h>
#include <pjlib.h>
#include <math.h> 

#include "proxy.h"
#include "myconfig.h"
#include <pjmedia/sdp.h>
#include <pj/list.h>
#include <stdlib.h>

#define iprint(level,...) syslog(level & 0xFFFF,__VA_ARGS__)


char devnet[] = "/dev/devNet";
char strout[1000];
struct dnat_sip_proxy_h  dnat_sip_proxy;            // Umleitung der SIP Pakete auf den Proxy


#define MAX_STR_CALL 200                                    // maximale Laenge des SIP Strings    
enum call_state_t  {CS_IDLE=1,CS_INVITE,CS_TRYING,CS_OK};   // Zustände der State Machine

struct ed137_call_t
{
	PJ_DECL_LIST_MEMBER(struct ed137_call_t); 		// pjlib/include/pj/list.h
	unsigned int index;								// wird bei jedem call incrementiert
	char call_id[MAX_STR_CALL];						//
	unsigned short src_port;
	unsigned short des_port;
	pj_in_addr src_ip;
	pj_in_addr des_ip;
	enum call_state_t state;						// invite,
	char 	user[MAX_STR_CALL];						// User des Calls

};
struct ed137_call_t call_list; // verkettete Liste aller aktiven Calls
/*********************************************************************
 * Prototypen 
 ********************************************************************/
int	cmp_call_user(struct ed137_call_t *call, struct t_config *sp);
int	send_call_data(struct ed137_call_t *call, struct t_config *sp,int index, int ioctl_id);
void print_ip(unsigned int ip);
void ip2string(char *buffer,unsigned int ip);
int	delete_call_data(struct ed137_call_t *call, struct t_config *sp,int index);
int get_lowest_callid(struct ed137_call_t *call);

static pj_bool_t on_rx_request( pjsip_rx_data *rdata );     // Callback to be called to handle incoming requests. 
static pj_bool_t on_rx_response( pjsip_rx_data *rdata );    // Callback to be called to handle incoming response.


void print_call_info(struct ed137_call_t *call);
void print_call_list(struct ed137_call_t *call);


/*********************************************************************
 * Main Funktion
 ********************************************************************/


int main(int argc, char *argv[])
{
openlog("vcsCore",LOG_NDELAY,LOG_LOCAL6);
 
}


/**
 * @brief Vergleicht Value
 * 
 * @param value 		String 1
 * @param base_node 	Struktur, die ein Listenelement sein kann
 * @return int 			0 gleich , !0 ungleich	
 */


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

/**
 * @brief Wird aufgerufen, wenn ein SIP Meldung empfangen wurde
 * 
 * @param rdata             Daten der Meldung
 * @return pj_bool_t 
 */

static pj_bool_t on_rx_request( pjsip_rx_data *rdata )
{
    pjsip_tx_data *tdata;
    pj_status_t status;
    pjmedia_sdp_session *sdp;
    pjsip_uri *uri;
    pjsip_sip_uri *sip_uri;
    pjsip_contact_hdr *contact_hdr;
    struct ed137_call_t *new_call;
    char call_id[MAX_STR_CALL];
    int len;
    struct ed137_call_t *call;


    char *s; //@TODO


    
    status = proxy_verify_request(rdata);       // Verify incoming request
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
