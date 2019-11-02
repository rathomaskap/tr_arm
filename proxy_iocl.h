/*
 * proxy_iocl.h
 *
 *  Created on: 23.05.2019
 *      Author: rainer
 */

#ifndef PROXY_IOCL_H_
#define PROXY_IOCL_H_

//#include <linux/types.h>
#include <sys/types.h>


struct proxy_ioctl_t	{
	unsigned int ip;
	unsigned short port;
	int r2sdelay;				// true = R2S Pakete werden verzögert
	int autorepeat;
	int *delayline;
};



#endif /* PROXY_IOCL_H_ */
