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
#define STATEFUL 1

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
#include "ipconfiguration.h"
#include <vector>
#include <map>
#include "pvmain.h"
#include "sessionParam.h"

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

// copiert einen pj_str in einen c++ string

string pj_str2string(pj_str_t &p)
{
    string s = string(p.ptr, 0, p.slen);
    // iprint(LOG_INFO,"pj_str2string: %s\n",s.c_str());

    return s;
}

char devnet[] = "/dev/devNet";

map<string, ed137_call_t> allCalls;
dummy_device_t dd;

/*********************************************************************
 * Prototypen
 ********************************************************************/
int cmp_call_user(ed137_call_t &call);
int send_call_data(ed137_call_t &call, int ioctl_id);
void print_ip(unsigned int ip);
void ip2string(char *buffer, unsigned int ip);
int delete_call_data(ed137_call_t &call);
int get_lowest_callid();
bool userInDlp(struct ed137_call_t &call);

static pj_bool_t on_rx_request(pjsip_rx_data *rdata);  // Callback to be called to handle incoming requests.
static pj_bool_t on_rx_response(pjsip_rx_data *rdata); // Callback to be called to handle incoming response.

void print_call_info(ed137_call_t &call);
void print_call_list();
static pj_status_t init_stateless_proxy(void);


void ev_activate_config(event &event);
void ev_ipConfiguration(event &event);
void ev_delayLine(event &event);

void sendCallData();

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

vector<ns_dl::delayLineParam> dlp;      // aktuelle Daten, mit denen der Kernel arbeitet
// vector<ns_dl::delayLineParam> newdlp;   // Werte von der Mangement Oberflaeche, um die Differenz zu dlp zu bilden

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
        iprint(LOG_INFO, "connect_finish\n");
        _lock.unlock();
    }
    void on_close(client::close_reason const &reason)
    {
        // std::cout << "sio closed " << reason << std::endl;
        iprint(LOG_INFO, "sio closed\n");
        exit(0);
    }

    void on_fail()
    {
        iprint(LOG_ERR, "sio failed\n");
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

    global.port = 5060;
    global.record_route = true;
    pj_log_set_level(4);

    status = init_stack();
    if (status != PJ_SUCCESS)
    {
        iprint(LOG_ERR, "Error initializing stack %d", status);
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

#if PJ_HAS_THREADS
    status = pj_thread_create(global.pool, "sproxy", &worker_thread,
                              NULL, 0, 0, &global.thread);
    if (status != PJ_SUCCESS)
    {
        iprint(LOG_ERR, "Error creating thread %d", status);
        return 1;
    }

#else
    puts("\nPress Ctrl-C to quit\n");^
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

    current_socket->on("reset", ev_activate_config);
    current_socket->on("delayline", ev_delayLine);
    current_socket->on("ipConfiguration", ev_ipConfiguration);

    json st = {{"alive", "ok"}};
    for (;;)
    {
        sleep(5);
        current_socket->emit("alive", st.dump());
    }

    pj_thread_join(global.thread);
    destroy_stack();
    return 0;
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

    iprint(LOG_INFO, "request Type ID: %d  METHODE: %s\n", rdata->msg_info.msg->line.req.method.id, pj_str2string(rdata->msg_info.msg->line.req.method.name).c_str());

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

                    // Ist die invite Meldung ein neuer call oder ein reinvite?

                    string call_id = pj_str2string(rdata->msg_info.cid->id);

                    // gibt es die Call ID schon
                    auto new_call = allCalls.find(call_id);

                    if (new_call != allCalls.end())
                    {
                        iprint(LOG_INFO, "Den call gibt es schon\n");
                        print_call_list();
                    }
                    else
                    {
                        // Der Call ist ein neuer Call

                        ed137_call_t newCall;

                        // interne Call ID (nicht SIP Call ID) in Struktur schreiben

                        newCall.id = get_lowest_callid();
                        newCall.state = CS_INVITE;
                        newCall.dstUserPart = pj_str2string(sip_uri->user);
                        newCall.dstUri = pj_str2string(sip_uri->user) + "@" + pj_str2string(sip_uri->host);

                        iprint(LOG_INFO, "dstUri: %s", newCall.dstUri.c_str());

                        // TODO: welcher = User in Struktur schreiben

                        newCall.src_port = sdp->media[0]->desc.port;
                        newCall.des_ip = pj_inet_addr(&sip_uri->host);
                       
                        newCall.delayLineFound = false;

                        // Suche contact header
                        contact_hdr = (pjsip_contact_hdr *)pjsip_msg_find_hdr(rdata->msg_info.msg, PJSIP_H_CONTACT, NULL);
                        if (contact_hdr)
                        {
                            uri = (pjsip_uri *)pjsip_uri_get_uri(contact_hdr->uri);
                            if (PJSIP_URI_SCHEME_IS_SIP(uri) || PJSIP_URI_SCHEME_IS_SIPS(uri))
                            {

                                sip_uri = (pjsip_sip_uri *)uri;
                                newCall.src_ip = pj_inet_addr(&sip_uri->host);

                                newCall.srcUri = pj_str2string(sip_uri->user) + "@" + pj_str2string(sip_uri->host);
                                iprint(LOG_INFO, "srcUri: %s", newCall.srcUri.c_str());

                                 newCall.srcUserPart = pj_str2string(sip_uri->user);

                                // Die Port Nummer des Gerufenen steht in der response Meldung und wird spaeter ergaenzt
                                newCall.call_id = call_id;

                                iprint(LOG_INFO, "new call with call_id %s registered\n", call_id.c_str());
                                print_call_list();
                            }
                        }
                        else
                        {
                            return PJ_FALSE;
                        }
                        allCalls.insert(pair<string, ed137_call_t>(call_id, newCall));
                    }
                }
            }
        }
    }
    else if (rdata->msg_info.msg->line.req.method.id == PJSIP_BYE_METHOD)
    {

        string call_id = pj_str2string(rdata->msg_info.cid->id);

        // Suche den Call in der Liste

        auto call = allCalls.find(call_id);
        if (call != allCalls.end())
        {

            iprint(LOG_INFO, "call removed from List call id=%s!\n", call_id.c_str());
            print_call_info(call->second);
            // TODO: hier muss der Call entfernt werden

            iprint(LOG_INFO, "active call list after remove\n");
            // TODO: sp ueberarbeiten
            delete_call_data(call->second);
            allCalls.erase(call_id);
            print_call_list();

            json erg;
            ns_sess::to_json(erg, allCalls);
            current_socket->emit("session2Node", erg.dump());
            iprint(LOG_INFO, "session: %s", erg.dump().c_str());
        }
        else
        {
            iprint(LOG_ERR, "Call not found in list ID=%s\n", call_id.c_str());
            print_call_list();
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

    pjmedia_sdp_session *sdp;
    pj_pool_t *mypool;

    unsigned short port;
    char *s;
    int len;

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

    iprint(LOG_INFO, "response Type ID: %d  METHODE: %s\n", rdata->msg_info.msg->line.req.method.id, pj_str2string(rdata->msg_info.msg->line.req.method.name).c_str());

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
                        iprint(LOG_INFO, "Die Portnummer des gerufenen ist %hd\n", port);
                        string call_id = pj_str2string(rdata->msg_info.cid->id);

                        // FIXME:
                        auto call = allCalls.find(call_id);
                        if (call != allCalls.end())
                        {
                            // die Call ID ist in der Liste vorhanden

                            if (call->second.state == CS_INVITE)
                            {
                                // es kann mehrfach ok gesendet werden, z.B. wenn der codec nicht passt
                                call->second.des_port = port;
                                iprint(LOG_INFO, "call ok verarbeitet call_id=%d\n", call_id.c_str());
                                call->second.state = CS_OK;
                                print_call_list();
                            }
                            if (userInDlp(call->second))
                            {
                                call->second.delayLineFound = true;
                                // send_call_data(call->second, NETIF_SET_TRACE_SESSIONS);
                                sendCallData();
                            }
                            else
                            {
                                iprint(LOG_INFO, "user des calls nicht gefunden\n");
                            }
                            json erg;
                            ns_sess::to_json(erg, allCalls);
                            current_socket->emit("session2Node", erg.dump());
                            iprint(LOG_INFO, "session: %s", erg.dump().c_str());
                        }
                    }
                }
            }
        }
    }
    else if (rdata->msg_info.cseq->method.id == PJSIP_BYE_METHOD || rdata->msg_info.cseq->method.id == PJSIP_CANCEL_METHOD)
    {
        cout << "BYE hier sollte ich nicht hinkommen\n";
        /*
        string call_id = pj_str2string(rdata->msg_info.cid->id);
        auto call = allCalls.find(call_id);
        if (call != allCalls.end())
        {

            iprint(LOG_INFO, "Call aus Liste entfernt! id=%s\n", call_id);

            print_call_info(call->second);

            // TODO: hier muss der Call entfernt werden
            allCalls.erase(call->first);
            print_call_list();
            delete_call_data(call->second);

            json erg;
            ns_sess::to_json(erg, allCalls);
            current_socket->emit("session2Node", erg.dump());
            iprint(LOG_INFO, "session: %s", erg.dump().c_str());
        }
        else
        {
            iprint(LOG_INFO,"call nicht in Liste gefunden\n");
            print_call_list();
        }
        */
    }

    pj_pool_safe_release(&mypool);

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
void print_call_list()
{
    for (auto it : allCalls)
    {
        print_call_info(it.second);
    }
}

/**
 * @brief gibt die Parameter eines calls aus
 *
 * @param call
 */

void print_call_info(ed137_call_t &call)
{
    char addr_ptr[20];

    iprint(LOG_INFO, "dstUserPart:%s\n", call.dstUserPart.c_str());
    iprint(LOG_INFO, "srcUserPart:%s\n", call.srcUserPart.c_str());

    iprint(LOG_INFO, "call_id: %s\n", call.call_id.c_str());
    iprint(LOG_INFO, "call_index:%d\n", call.id);
    iprint(LOG_INFO, "call_state:%d\n", call.state);

    pj_inet_ntop(PJ_AF_INET, &call.src_ip, addr_ptr, 20);
    iprint(LOG_INFO, "ip_src: %s:%hd\n", addr_ptr, call.src_port);
    pj_inet_ntop(PJ_AF_INET, &call.des_ip, addr_ptr, 20);
    iprint(LOG_INFO, "ip_des: %s:%hd\n", addr_ptr, call.des_port);
}

/**
 * @brief  sucht die kleinste id in der verketteten Liste.
 *
 * @param call
 * @return int 0 Liste ist leer
 *
 */
int get_lowest_callid()
{
    int id = 0;

    if (allCalls.size() == 0)
    {
        id = 0;
    }
    else
    {

        bool found = false;

        do
        {
            found = false;
            for (auto it = allCalls.begin(); it != allCalls.end(); it++)
            {
                if (it->second.id == id)
                {
                    found = true;
                    id++;
                    break;
                }
            }
        } while (found == true);
    }

    iprint(LOG_INFO, "lowest call ID is %d\n", id);
    return id;
}

/**
 * @brief loescht die Struktur im kernel fuer einen call
 *
 * @param call
 * @param index
 * @return int
 */

int delete_call_data(ed137_call_t &call)
{
    int id;
    int ret;

    ret = ioctl_del_trace_session(dz_net, call.id);
    if (ret == -1)
    {
        iprint(LOG_ERR, "error: ioctl %s\n", __FUNCTION__);
    }
    return ret;
}

/**
 * @brief
 *
 * @param call
 * @param index
 * @param ioctl_id
 * @return int
 */
int send_call_data(ed137_call_t &call, int ioctl_id)
{
    struct trace_session_t ts;

    int ret;
    int i;
    ns_dl::delayLineParam erg;

    bool found = false;
    for (auto it : dlp)
    {
        if (it.dstUserPart == call.dstUserPart)
        {
            found = true;
            erg = it;
            break;
        }
    }

    if (found)
    {
        iprint(LOG_INFO, "User Part was found\n");
        ts.id = call.id;

        ts.on_delay.autorepeat = erg.autoRepeatOn;
        ts.on_delay.r2s_delay = erg.r2sDelay;

        ts.on_delay.lenght = 0;
        ts.on_delay.delay[0] = 0; // FIXME:

        ts.off_delay.autorepeat = erg.autoRepeatOff;
        ts.off_delay.r2s_delay = erg.r2sDelay;
        ts.off_delay.lenght = 0;
        ts.off_delay.delay[0] = 0; // FIXME:
    }
}

/**
 * @brief Sucht in den delay line parametern den userpart des calls
 *
 * @param call
 * @return bool true gefunden, false nicht gefunden
 */

bool userInDlp(struct ed137_call_t &call)
{
    bool retval = false;

    for (auto it : dlp)
    {
        if (call.dstUserPart == it.dstUserPart)
        {
            retval = true;
            break;
        }
    }
    return retval;
}

namespace ns
{
    // a simple struct to model a person
    struct person
    {
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
        iprint(LOG_INFO, "%s", j.dump().c_str());

        //	j = json::parse(event.get_message().get()->get_string());
    }
    catch (std::exception &e)
    {
        iprint(LOG_ERR, "error parse config: %s", e.what());
    }
}

void ev_delayLine(event &event)
{

    string s;
    json j;

    try
    {
        j = json::parse(event.get_message().get()->get_string());
        iprint(LOG_INFO, "%s", j.dump().c_str());
        dlp = j;

        ns_dl::printDelayLine(dlp);

        // wandle dlp in die Struktur
        sendCallData();

        // hier kann sich die Farbe des Sessioneintrags aendern
        json erg;
        ns_sess::to_json(erg, allCalls);
        current_socket->emit("session2Node", erg.dump());
        iprint(LOG_INFO, "session: %s", erg.dump().c_str());

        //	j = json::parse(event.get_message().get()->get_string());
    }
    catch (std::exception &e)
    {
        iprint(LOG_ERR, "error: ev_delayLine convert to json\n");
    }
}

void ev_ipConfiguration(event &event)
{

    string s;
    json j;
    dnat_sip_proxy_h dsp;
    int ret;

    try
    {
        j = json::parse(event.get_message().get()->get_string());
        iprint(LOG_INFO, "%s", j.dump().c_str());

        ns_ip::from_json(j, dsp);
        ns_ip::from_json2dummy(j,dd);

        ret = ioctl_set_sip_proxy_addr(dz_net, &dsp);
    }
    catch (std::exception &e)
    {
        std::stringstream log;
    }
}
/**
 * @brief
 *
 */
void sendCallData()
{

    trace_session_t ts;
    pj_in_addr addr;

    // deactivate delay line
    // deleate all data
    // insert new data

ioctl_reset_all_sessions(dz_net);

    for (auto i = allCalls.begin(); i != allCalls.end(); i++)
    {
        i->second.delayLineFound = false;
        for (auto l : dlp)
        {
            if (i->second.dstUserPart == l.dstUserPart && i->second.srcUserPart == l.srcUserPart)
            {
                i->second.delayLineFound = true;

                ts.desip = i->second.des_ip.s_addr;
                ts.desport = htons(i->second.des_port);
                ts.srcip = i->second.src_ip.s_addr;
                ts.srcport = htons(i->second.src_port);
                ts.id = i->second.id;
                ts.to_uas = l.direction;
                ts.on_delay.autorepeat = l.autoRepeatOn;
                ts.on_delay.r2s_delay = l.r2sDelay;


                ts.dummydesip = dd.ip;
	            ts.dummydesip&= dd.netmask;
	            ts.dummydesip|= htonl(ts.desip) & ~dd.netmask;
                ts.dummydesip = htonl(ts.dummydesip);

                iprint(LOG_INFO,"dd.ip=%X dd.netmask=%X ts.desip=%X ts.dummydesip=%X\n",dd.ip,dd.netmask,htonl(ts.desip),ts.dummydesip);

	            ts.dummysrcip = dd.ip;
	            ts.dummysrcip&= dd.netmask;
	            ts.dummysrcip|= htonl(ts.srcip) & ~dd.netmask;
                ts.dummysrcip = htonl(ts.dummysrcip);

                iprint(LOG_INFO,"dd.ip=%X dd.netmask=%X ts.srcip=%X ts.dummysrcip=%X\n",dd.ip,dd.netmask,htonl(ts.srcip),ts.dummysrcip);




                int lineOnSize = l.lineOn.size();
                ts.on_delay.lenght = (lineOnSize < MAX_DELAY) ? lineOnSize : MAX_DELAY;
                for (int i = 0; i < ts.on_delay.lenght; i++)
                {
                    ts.on_delay.delay[i] = l.lineOn[i];
                }

                ts.off_delay.autorepeat = l.autoRepeatOff;
                ts.off_delay.r2s_delay = l.r2sDelay;
                ts.off_delay.lenght = (l.lineOff.size() < MAX_DELAY) ? l.lineOff.size() : MAX_DELAY;
                for (int i = 0; i < ts.off_delay.lenght; i++)
                {
                    ts.off_delay.delay[i] = l.lineOff[i];
                }

                ioctl_set_trace_session(dz_net, &ts);
            }
        }
    }
    for (auto i : allCalls)
    {
        iprint(LOG_INFO, "delayLineFound=%d\n", i.second.delayLineFound);
    }
}

