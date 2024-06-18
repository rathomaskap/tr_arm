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

#define THIS_FILE "pvmain.cpp"

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
#include <ioctl_netif.h>
#include <sio_client.h>
#include <json.hpp>
#include "logger.h"
#include "delayline.h"

using namespace std;
using namespace sio;
using namespace nlohmann;

/*
Loglevel fuer SYSLOG

LOG_EMERG               system is unusable
LOG_ALERT               action must be taken immediately
LOG_CRIT                critical conditions
LOG_ERR                 error conditions
LOG_WARNING             warning conditions
LOG_NOTICE              normal, but significant, condition
LOG_INFO
*/



char devnet[] = "/dev/devNet";
char strout[1000];

// FIXME:
//  extern struct t_config *sp;

struct t_config *sp;

struct dnat_sip_proxy_h dnat_sip_proxy; // Umleitung der SIP Pakete auf den Proxy

#define MAX_STR_CALL 200 // maximale Laenge des SIP Strings
enum call_state_t
{
    CS_IDLE = 1,
    CS_INVITE,
    CS_TRYING,
    CS_OK
}; // Zustände der State Machine

struct ed137_call_t
{
    PJ_DECL_LIST_MEMBER(struct ed137_call_t); // pjlib/include/pj/list.h
    unsigned int index;                       // wird bei jedem call incrementiert
    char call_id[MAX_STR_CALL];               //
    unsigned short src_port;
    unsigned short des_port;
    pj_in_addr src_ip;
    pj_in_addr des_ip;
    enum call_state_t state; // invite,
    char user[MAX_STR_CALL]; // User des Calls
};
struct ed137_call_t call_list; // verkettete Liste aller aktiven Calls
/*********************************************************************
 * Prototypen
 ********************************************************************/
int cmp_call_user(struct ed137_call_t *call, struct t_config *sp);
int send_call_data(struct ed137_call_t *call, struct t_config *sp, int index, int ioctl_id);
void print_ip(unsigned int ip);
void ip2string(char *buffer, unsigned int ip);
int delete_call_data(struct ed137_call_t *call, struct t_config *sp, int index);
int get_lowest_callid(struct ed137_call_t *call);

static pj_bool_t on_rx_request(pjsip_rx_data *rdata);  // Callback to be called to handle incoming requests.
static pj_bool_t on_rx_response(pjsip_rx_data *rdata); // Callback to be called to handle incoming response.

void print_call_info(struct ed137_call_t *call);
void print_call_list(struct ed137_call_t *call);
static pj_status_t init_stateless_proxy(void);
void ev_activate_config(event &event);
void ev_delayLine(event &event);

/*********************************************************************
 * Globale Variable
 ********************************************************************/

int dz_net;
std::map<int, std::string> pipeNames;
std::string pipeNameStr;
std::mutex _lock;
std::condition_variable_any _cond;
bool connect_finish = false;
socket::ptr current_socket;

vector<ns_dl::delayLineParam> dlp;


int limitCidLen(int len)
{
    (len + 1) < MAX_STR_CALL ? len + 1 : MAX_STR_CALL;
}

class connection_listener
{

    sio::client &handler;

public:
    connection_listener(sio::client &h) : handler(h)
    {
    }

    void on_connected()
    {
        _lock.lock();
        _cond.notify_all();
        connect_finish = true;
        cout << "connect_finish\n";
        _lock.unlock();
    }
    void on_close(client::close_reason const &reason)
    {
        std::cout << "sio closed " << reason << std::endl;
        exit(0);
    }

    void on_fail()
    {
        std::cout << "sio failed " << std::endl;
        exit(0);
    }
};

/*********************************************************************
 * Main Funktion
 ********************************************************************/

int main(int argc, char *argv[])
{
    int ret;
    pj_status_t status; 

    openlog("pv", LOG_NDELAY, LOG_LOCAL6);

    iprint(LOG_ERR, "tr_arm3 Version 1.0 GUI\n");

    dz_net = open(devnet, O_RDWR);
    if (dz_net < 0)
    {
        iprint(LOG_ERR, "error: open device devnet\n");
    }

    status = init_stack();
    if (status != PJ_SUCCESS) {
	iprint(LOG_ERR,"Error initializing stack %d", status);
	return 1;
    }



    status = init_proxy();
    if (status != PJ_SUCCESS)
    {
        iprint(LOG_ERR, "Error initializing proxy %d", status);
        return 1;
    }

    status = init_stateless_proxy();
    if (status != PJ_SUCCESS)
    {
        iprint(LOG_ERR, "Error initializing stateless proxy %d", status);
        return 1;
    }

    pj_list_init(&call_list);

#if PJ_HAS_THREADS
    status = pj_thread_create(global.pool, "sproxy", &worker_thread,
                              NULL, 0, 0, &global.thread);
    if (status != PJ_SUCCESS)
    {
        iprint(LOG_ERR, "Error creating thread %d", status);
        return 1;
    }

#else
    puts("\nPress Ctrl-C to quit\n");
    for (;;)
    {
        pj_time_val delay = {0, 0};
        pjsip_endpt_handle_events(global.endpt, &delay);
    }
#endif

    sio::client h;
    connection_listener l(h);

    h.set_open_listener(std::bind(&connection_listener::on_connected, &l));
    h.set_close_listener(std::bind(&connection_listener::on_close, &l, std::placeholders::_1));
    h.set_fail_listener(std::bind(&connection_listener::on_fail, &l));
    //		h.connect("http://127.0.0.1:4000");
    h.connect("http://192.168.1.98:4000");

    _lock.lock();
    if (!connect_finish)
    {
        _cond.wait(_lock);
    }
    _lock.unlock();
    current_socket = h.socket();

    current_socket->on("sessions", ev_activate_config);
    current_socket->on("reset", ev_activate_config);
    current_socket->on("delayline", ev_delayLine);
    current_socket->on("ipConfiguration", ev_activate_config);

    pj_thread_join(global.thread);
    destroy_stack();
    return 0;
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

    node = (struct ed137_call_t *)base_node;

    char *call_id = (char *)value;
    int len1 = strlen(call_id);
    int len2 = strlen(node->call_id);
    if (len1 != len2)
        return 1; // nicht gleich, da Laenge unterschiedlich
    return strcmp(call_id, node->call_id);
}

static pj_status_t init_stateless_proxy(void)
{
    static pjsip_module mod_stateless_proxy =
        {
            NULL, NULL,                        /* prev, next.	*/
            {"mod-stateless-proxy", 19},       /* Name.		*/
            -1,                                /* Id		*/
            PJSIP_MOD_PRIORITY_UA_PROXY_LAYER, /* Priority		*/
            NULL,                              /* load()		*/
            NULL,                              /* start()		*/
            NULL,                              /* stop()		*/
            NULL,                              /* unload()		*/
            &on_rx_request,                    /* on_rx_request()	*/
            &on_rx_response,                   /* on_rx_response()	*/
            NULL,                              /* on_tx_request.	*/
            NULL,                              /* on_tx_response()	*/
            NULL,                              /* on_tsx_state()	*/
        };

    pj_status_t status;

    /* Register our module to receive incoming requests. */
    status = pjsip_endpt_register_module(global.endpt, &mod_stateless_proxy);
    PJ_ASSERT_RETURN(status == PJ_SUCCESS, 1);

    return PJ_SUCCESS;
}

/**
 * @brief Wird aufgerufen, wenn ein SIP Meldung empfangen wurde
 *
 * @param rdata             Daten der Meldung
 * @return pj_bool_t
 */

static pj_bool_t on_rx_request(pjsip_rx_data *rdata)
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

    char *sdpData; // SDP Buffer fuer pjmedia_sdp_parse

    status = proxy_verify_request(rdata); // Verify incoming request
    if (status != PJ_SUCCESS)
    {
        app_perror("RX invalid request", status);
        return PJ_TRUE;
    }
    /*
     * 	Das sind die Werte fuer "data->msg_info.msg->line.req.method.id"
     *
        PJSIP_INVITE_METHOD,
        PJSIP_CANCEL_METHOD,
        PJSIP_ACK_METHOD,
        PJSIP_BYE_METHOD,
        PJSIP_REGISTER_METHOD,
        PJSIP_OPTIONS_METHOD,
    */

    iprint(LOG_INFO, "Type ID=%d\n", rdata->msg_info.msg->type); // Ausgabe des Meldungstyps
    iprint(LOG_INFO, "ID=%d\n %s\n", rdata->msg_info.msg->line.req.method.id, rdata->msg_info.msg->line.req.method.name.ptr);

    /*
     * Es wird angenommen, dass die URI des Gerufenen im request header und die des Rufenden im contact header steht
     * TODO: ueberpruefen, ob die obige Annahme stimmt.
     */

    if (rdata->msg_info.msg->line.req.method.id == PJSIP_INVITE_METHOD)
    {

        sdpData = (char *)rdata->msg_info.msg->body->data;

        status = pjmedia_sdp_parse(global.pool, sdpData, rdata->msg_info.msg->body->len, &sdp);

        if (status == PJ_SUCCESS)
        {

            if (sdp->media_count == 1)
            {

                uri = (pjsip_uri *)pjsip_uri_get_uri(rdata->msg_info.msg->line.req.uri);

                /* nur SIP/SIPS schemes */
                if (PJSIP_URI_SCHEME_IS_SIP(uri) || PJSIP_URI_SCHEME_IS_SIPS(uri))
                {

                    sip_uri = (pjsip_sip_uri *)uri;
                    // Ermittle den User des Gerufenen

                    snprintf(strout, sip_uri->user.slen + 1, "%s", sip_uri->user.ptr);
                    iprint(LOG_INFO, "Destination User: %s ", strout);
                    // Ist die invite Meldung ein neuer call oder ein reinvite?

                    // Kompiere die Call id des Calls nach call_id

                    len = limitCidLen(rdata->msg_info.cid->id.slen);

                    strncpy(call_id, rdata->msg_info.cid->id.ptr, len);
                    call_id[len] = '\0';

                    // gibt es die Call ID schon
                    new_call = (ed137_call_t *)pj_list_search(&call_list, call_id, cmp_call_list);
                    if (new_call)
                    {
                        iprint(LOG_INFO, "Den call gibt es schon\n");
                        print_call_list(&call_list);
                    }
                    else
                    {
                        // Der Call ist ein neuer Call

                        try
                        {
                            new_call = new ed137_call_t;
                        }
                        catch (...)
                        {
                            iprint(LOG_ERR, "out of memory");
                            return PJ_FALSE;
                        }

                        // interne Call ID (nicht SIP Call ID) in Struktur schreiben

                        iprint(LOG_INFO, "Get lowest call id in list\n");
                        new_call->index = get_lowest_callid(&call_list);
                        new_call->state = CS_INVITE;
                        pj_list_push_back(&call_list, new_call);

                        // TODO: welcher = User in Struktur schreiben
                        len = (sip_uri->user.slen + 1) < MAX_STR_CALL - 1 ? sip_uri->user.slen : MAX_STR_CALL - 1;
                        strncpy(new_call->user, sip_uri->user.ptr, len);
                        new_call->user[len] = '\0';

                        new_call->src_port = sdp->media[0]->desc.port;
                        new_call->des_ip = pj_inet_addr(&sip_uri->host);

                        // Suche contact header
                        contact_hdr = (pjsip_contact_hdr *)pjsip_msg_find_hdr(rdata->msg_info.msg, PJSIP_H_CONTACT, NULL);
                        if (contact_hdr)
                        {
                            uri = (pjsip_uri *)pjsip_uri_get_uri(contact_hdr->uri);
                            if (PJSIP_URI_SCHEME_IS_SIP(uri) || PJSIP_URI_SCHEME_IS_SIPS(uri))
                            {

                                sip_uri = (pjsip_sip_uri *)uri;
                                new_call->src_ip = pj_inet_addr(&sip_uri->host);

                                // Die Port Nummer des Gerufenen steht in der response Meldung und wird spaeter ergaenzt

                                strncpy(new_call->call_id, call_id, MAX_STR_CALL - 1);

                                iprint(LOG_INFO, "new call with call_id %s registered\n", call_id);
                                print_call_list(&call_list);
                            }
                        }
                        else
                        {
                            return PJ_FALSE;
                        }
                    }
                }
            }
        }
    }
    else if (rdata->msg_info.msg->line.req.method.id == PJSIP_BYE_METHOD)
    {

        // Das ist der BYE Request

        // Bestimme die Call ID

        len = limitCidLen(rdata->msg_info.cid->id.slen);

        strncpy(call_id, rdata->msg_info.cid->id.ptr, len);
        call_id[len] = '\0';

        // Suche den Call in der Liste

        call = (ed137_call_t *)pj_list_search(&call_list, call_id, cmp_call_list);
        if (call)
        {

            iprint(LOG_INFO, "call removed from List call id=%s!\n", call_id);
            print_call_info(call);
            // TODO: hier muss der Call entfernt werden
            pj_list_erase(call);

            iprint(LOG_INFO, "active call list after remove\n");
            print_call_list(&call_list);

            call->state = CS_IDLE;

            // TODO: sp ueberarbeiten
            delete_call_data(call, sp, call->index);
            delete (call);
        }
        else
        {
            iprint(LOG_ERR, "Call not found in list\n");
            print_call_list(&call_list);
        }
    }

    /*
     * Request looks sane, next clone the request to create transmit data.
     */
    status = pjsip_endpt_create_request_fwd(global.endpt, rdata, NULL, NULL, 0, &tdata);
    if (status != PJ_SUCCESS)
    {
        pjsip_endpt_respond_stateless(global.endpt, rdata, PJSIP_SC_INTERNAL_SERVER_ERROR, NULL, NULL, NULL);
        return PJ_TRUE;
    }

    status = proxy_process_routing(tdata); // Process routing
    if (status != PJ_SUCCESS)
    {
        iprint(LOG_ERR, "Error processing route, %d", status);
        return PJ_TRUE;
    }

    status = proxy_calculate_target(rdata, tdata); // Calculate target
    if (status != PJ_SUCCESS)
    {
        iprint(LOG_ERR, "Error calculating target %d", status);
        return PJ_TRUE;
    }

    status = pjsip_endpt_send_request_stateless(global.endpt, tdata, NULL, NULL); // Target is set, forward the request
    if (status != PJ_SUCCESS)
    {
        iprint(LOG_ERR, "Error forwarding request %d", status);
        return PJ_TRUE;
    }

    return PJ_TRUE;
}

/**
 * @brief Callback to be called to handle incoming response.
 *
 * @param rdata             received data
 * @return pj_bool_t        PJ_TRUE message is processed
 */

// FIXME:
static pj_bool_t on_rx_response(pjsip_rx_data *rdata)
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

    status = pjsip_endpt_create_response_fwd(global.endpt, rdata, 0, &tdata); // Create response to be forwarded upstream (Via will be stripped here)
    if (status != PJ_SUCCESS)
    {
        app_perror("Error creating response", status);
        return PJ_TRUE;
    }

    hvia = (pjsip_via_hdr *)pjsip_msg_find_hdr(tdata->msg, PJSIP_H_VIA, NULL); // Get topmost Via header
    if (hvia == NULL)
    {
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
    if (res_addr.dst_host.addr.host.slen == 0)
    {
        /* Someone has messed up our Via header! */
        res_addr.dst_host.addr.host = hvia->sent_by.host;
    }

    /* Destination port is the rpot */
    if (hvia->rport_param != 0 && hvia->rport_param != -1)
        res_addr.dst_host.addr.port = hvia->rport_param;

    if (res_addr.dst_host.addr.port == 0)
    {
        /* Ugh, original sender didn't put rport!
         * At best, can only send the response to the port in Via.
         */
        res_addr.dst_host.addr.port = hvia->sent_by.port;
    }

    mypool = pj_pool_create(&global.cp.factory, "request pool", 4000, 4000, NULL);

    // printf("Type ID=%d\n",rdata->msg_info.msg->type); // auf den Typ muss man nicht testen, da nur eine Response in Frage kommt

    printf("method.id =%d\n", rdata->msg_info.msg->line.req.method.id);

    if (rdata->msg_info.msg->line.req.method.id == 200)
    {
        // hier interessiert nur die OK Meldungen, da dort der Messagebody mit gesendet wird
        // bestimme Port Nr des gerufenen und call_id
        if (rdata->msg_info.cseq->method.id == PJSIP_INVITE_METHOD)
        {

            if (rdata->msg_info.msg->body)
            {

                s = (char *)rdata->msg_info.msg->body->data;
                status = pjmedia_sdp_parse(mypool, s, rdata->msg_info.msg->body->len, &sdp);
                if (status == PJ_SUCCESS)
                {
                    if (sdp->media_count == 1)
                    {

                        port = sdp->media[0]->desc.port;
                        printf("die Portnummer des gerufenen ist %hd\n", port);

                        len = limitCidLen(rdata->msg_info.cid->id.slen);

                        strncpy(call_id, rdata->msg_info.cid->id.ptr, len);
                        call_id[len] = '\0';
                        call = (ed137_call_t *)pj_list_search(&call_list, call_id, cmp_call_list);
                        if (call)
                        {
                            // die Call ID ist in der Liste vorhanden
                            call->des_port = port;
                            // TODO:  hier muss der Aufruf IOCTL erfolgen
                            if (call->state == CS_INVITE)
                            {

                                // es kann mehrfach ok gesendet werden, z.B. wenn der codec nicht passt
                                index = cmp_call_user(call, sp);
                                if (index >= 0)
                                {
                                    printf("call in Liste gefunden und user ok,!\n");
                                    call->state = CS_OK;
                                    print_call_list(&call_list);
                                    send_call_data(call, sp, index, NETIF_SET_TRACE_SESSIONS);
                                }
                                else
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
        else if (rdata->msg_info.cseq->method.id == PJSIP_BYE_METHOD || rdata->msg_info.cseq->method.id == PJSIP_CANCEL_METHOD)
        {
            // das ist die Statusmeldung auf Bye

            len = limitCidLen(rdata->msg_info.cid->id.slen);
            strncpy(call_id, rdata->msg_info.cid->id.ptr, len);
            call_id[len] = '\0';
            call = (ed137_call_t *)pj_list_search(&call_list, call_id, cmp_call_list);
            if (call)
            {

                printf("call aus Liste entfernt!\n");
                print_call_info(call);
                // TODO: hier muss der Call entfernt werden
                pj_list_erase(call);
                printf("active call List\n");
                print_call_list(&call_list);
                call->state = CS_IDLE;
                delete_call_data(call, sp, call->index);
                free(call);
            }
            else
            {
                printf("call nicht in Liste gefunden\n");
                print_call_list(&call_list);
            }
        }
    }

    pj_pool_safe_release(&mypool);

    iprint(LOG_INFO, "Response ID=%d\n", rdata->msg_info.msg->line.req.method.id);

    snprintf(strout, rdata->msg_info.msg->line.req.method.name.slen + 1, "%s", rdata->msg_info.msg->line.req.method.name.ptr);
    iprint(LOG_INFO, "Response Name = %s\n", strout);

    /* Forward response */
    status = pjsip_endpt_send_response(global.endpt, &res_addr, tdata, NULL, NULL);
    if (status != PJ_SUCCESS)
    {
        iprint(LOG_ERR, "Error forwarding response %d", status);
        return PJ_TRUE;
    }
    return PJ_TRUE;
}

/**
 * @brief gibt eine Liste aller Calls aus
 *
 * @param call  Verkettete Liste aller calls
 */
void print_call_list(struct ed137_call_t *call)
{
    struct ed137_call_t *p;
    p = call;
    while ((p = p->next) != call)
    {
        print_call_info(p);
    }
}

/**
 * @brief gibt die Parameter eines calls aus
 *
 * @param call
 */

void print_call_info(struct ed137_call_t *call)
{
    char addr_ptr[20];

    iprint(LOG_INFO, "user:%s\n", call->user);
    iprint(LOG_INFO, "call_id: %s\n", call->call_id);
    iprint(LOG_INFO, "call_index:%d\n", call->index);
    iprint(LOG_INFO, "call_state:%d\n", call->state);

    pj_inet_ntop(PJ_AF_INET, &call->src_ip, addr_ptr, 20);
    iprint(LOG_INFO, "ip_src: %s:%hd\n", addr_ptr, call->src_port);
    pj_inet_ntop(PJ_AF_INET, &call->des_ip, addr_ptr, 20);
    iprint(LOG_INFO, "ip_des: %s:%hd\n", addr_ptr, call->des_port);
}

/**
 * @brief  sucht die kleinste id in der verketteten Liste.
 *
 * @param call
 * @return int 0 Liste ist leer
 *
 */
int get_lowest_callid(struct ed137_call_t *call)
{
    struct ed137_call_t *p;
    int found;
    int call_id = 0;

    if (call->next == call)
    {
        iprint(LOG_INFO, "list of calls is empty\n");
        return 0; // Liste ist leer
    }

    do
    {
        found = 0;
        p = call;
        p = p->next;
        while (p != call)
        {
            if (p->index == call_id)
            {
                found = -1;
                call_id++;
                break;
            }
            p = p->next;
        }
    } while (found);
    iprint(LOG_INFO, "lowest call ID is %d\n", call_id);
    return call_id;
}

/**
 * @brief loescht die Struktur im kernel fuer einen call
 *
 * @param call
 * @param sp
 * @param index
 * @return int
 */

int delete_call_data(struct ed137_call_t *call, struct t_config *sp, int index)
{
    int id;
    int ret;

    id = call->index;
    ret = ioctl_del_trace_session(dz_net, id);
    if (ret == -1)
    {
        printf("error: ioctl %s\n", __FUNCTION__);
    }
    return ret;
}

/**
 * @brief
 *
 * @param call
 * @param sp
 * @param index
 * @param ioctl_id
 * @return int
 */
int send_call_data(struct ed137_call_t *call, struct t_config *sp, int index, int ioctl_id)
{
    struct trace_session_t ts;

    int ret;
    int i;

    ts.id = call->index;
    ts.on_delay.autorepeat = !strncmp(sp->sessionParam[index].on.autorepeat, "on", 2) ? -1 : 0;
    ts.on_delay.r2s_delay = !strncmp(sp->sessionParam[index].on.r2sdelay, "on", 2) ? -1 : 0;
    ts.on_delay.lenght = sp->sessionParam[index].on.index;
    for (i = 0; i < ts.on_delay.lenght; i++)
    {
        ts.on_delay.delay[i] = sp->sessionParam[index].on.array[i];
    }

    ts.off_delay.autorepeat = !strncmp(sp->sessionParam[index].off.autorepeat, "on", 2) ? -1 : 0;
    ts.off_delay.r2s_delay = !strncmp(sp->sessionParam[index].off.r2sdelay, "on", 2) ? -1 : 0;
    ts.off_delay.lenght = sp->sessionParam[index].off.index;
    for (i = 0; i < ts.off_delay.lenght; i++)
    {
        ts.off_delay.delay[i] = sp->sessionParam[index].off.array[i];
    }
}
/**
 * @brief  sucht den user part eines calls in der Struktur sp
 *
 * @param call
 * @param sp
 * @return int -1 call nicht gefunden
 *              >=0 call index des calls
 */
int cmp_call_user(struct ed137_call_t *call, struct t_config *sp)
{
    int retval = -1;
    for (int i = 0; i < sp->count; i++)
    {
        retval = strncmp(call->user, sp->sessionParam[i].userpart, strlen(sp->sessionParam[i].userpart));
        if (!retval && strlen(sp->sessionParam[i].userpart))
        {
            retval = i;
            break;
        }
    }
    return retval;
}


namespace ns {
    // a simple struct to model a person
    struct person {
        std::string name;
        std::string address;
        int age;
    };
}


void ev_activate_config(event &event)
{

    string s;
    json j;
    

        try
        {
            j = json::parse(event.get_message().get()->get_string());
            cout << endl << endl;
            cout << j.dump();

            //	j = json::parse(event.get_message().get()->get_string());
        }
        catch (std::exception &e)
        {
            std::stringstream log;
        }
}


void ev_delayLine(event &event)
{

    string s;
    json j;
    

        try
        {
            j = json::parse(event.get_message().get()->get_string());
            cout << endl << endl;
            cout << j.dump();
            dlp = j;

            ns_dl::printDelayLine(dlp);

            //	j = json::parse(event.get_message().get()->get_string());
        }
        catch (std::exception &e)
        {
            std::stringstream log;
        }
}