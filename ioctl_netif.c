/*
 * ioctl_netif.c
 *
 *  Created on: 14.06.2019
 *      Author: rainer
 */

#include <err.h>
#include <stdarg.h>
#include <setjmp.h>
#include <stdio.h>

#include <unistd.h>
#include <sys/ioctl.h>


#include <ioctl_netif.h>

/*
 * ioctl Interface zum snull device
 *
 * nachfolgende Daten muessen uebertragen werden:
 *
 * - Anzahl der sessions
 * - delaychain
 * - pro session
 *		+ ipaddr und port
 * 		+ r2s delay on/off
 * 		+ autorepeat on/off
 * 		+ delayline
 */


// delete all sessions
int ioctl_reset_all_sessions(int dz)
{

int retval;
unsigned long dummy = 0;
retval = ioctl(dz,_IOW('N',NETIF_RESET_ALL_SESSIONS, dummy),dummy);
return retval;
}


// set trace_config_t





int ioctl_set_trace_config(int dz,struct trace_config_t *tc)
{

int retval;

printf("address of tc=%X\n",(unsigned int) tc);
for(int i=0;i<MAX_FIFO;i++) {
	printf("i=%d   ->  %X %d\n",i,(unsigned int) &tc->delaychain[i],(unsigned int) tc->delaychain[i]);
}

retval = ioctl(dz,_IOW('N',NETIF_SET_TRACE_CONFIG,*tc), tc);
return retval;

}


// set trace_session_t

int ioctl_set_trace_session(int dz,struct trace_session_t *ts)
{

int retval;
retval = ioctl(dz,_IOW('N',NETIF_SET_TRACE_SESSIONS, *ts),ts);
return retval;
}

int ioctl_del_trace_session(int dz,int id)
{
int retval;
retval = ioctl(dz,_IOW('N',NETIF_DEL_TRACE_SESSIONS, id),id);
return retval;

}

int ioctl_update_trace_session(int dz,struct trace_session_t *ts)
{

int retval;
retval = ioctl(dz,_IOW('N',NETIF_UPDATE_TRACE_SESSIONS, *ts),ts);
return retval;
}


int ioctl_set_sip_proxy_addr(int dz,struct dnat_sip_proxy_h *p)
{
int retval;
retval = ioctl(dz,_IOW('N',NETIF_COPY_SIP_ADDR, sizeof(struct dnat_sip_proxy_h)),p);
return retval;

}
