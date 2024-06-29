/*
 * config.h
 *
 *  Created on: 21.05.2019
 *      Author: rainer
 */

#ifndef MYCONFIG_H_
#define MYCONFIG_H_


#define ARRAY_SIZE_DELAY_CHAIN 1024


/*


#define MAX_STRING_CONFIG	40
#define MAX_STRING_DELAYLINE 400
int readConfig(char *argv);
struct arrayData_t {
	int array[ARRAY_SIZE_DELAY_CHAIN];
	int index;
	int error;	// true = error, false ! error
	char r2sdelay[MAX_STRING_CONFIG];
	char autorepeat[MAX_STRING_CONFIG];
	char delayline[MAX_STRING_DELAYLINE];
};


struct session_desc_t {
	char userpart[MAX_STRING_CONFIG];
	char direction[MAX_STRING_CONFIG];
	struct arrayData_t on;
	struct arrayData_t off;

	char iptables[200];
	char desip[30];
	char srcip[30];
	char dummydesip[30];
	char dummysrcip[30];

};




struct t_config {
int count;
int delaychain[64];
int change_delay;  // 0 = false
struct session_desc_t *sessionParam;
};

*/

#endif /* MYCONFIG_H_ */
