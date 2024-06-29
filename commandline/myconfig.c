/*
 * myconfig.c
 *
 *  Created on: 20.05.2019
 *      Author: rainer
 */

#include <err.h>
//#include <stdarg.h>
//#include <setjmp.h>

#include <libconfig.h>
#include <stdlib.h>
#include "myconfig.h"
#include <ctype.h>
#include <stdio.h>
// #include <linux/types.h>
#include "ioctl_netif.h"

// bei <string.h> wird das include file von pjsip eingebunden
// #include "/home/rainer/work/buildroot-2018.08.2/output/host/arm-buildroot-linux-gnueabihf/sysroot/usr/include/string.h"
#include <string.h>


char *error[] =
	{
			"vor Komma keine Zahl\n",   // -1
			"keine gueltige Zahl gefunden\n",  //-2
			"Klammer ist schon offen, Schachtelung nicht erlaubt\n",  // -3
			"Klammer zu ohne Klammer offen\n",	// -4
			"nach Klammer zu oder Zahl kein Komma\n",   // -5
			"Zahl hat unerlaubten Wertebereich, nur 0..63, 0x40 und 0x80\n", //-6
			"Klammer zu fehlt\n", // -7
			"nach Komma keine Zahl oder Klammer\n", // -8
			"vor Klammer kein Wiederholungszaehler\n", // -9
			"leere Klammer\n", // -10
			"zu viele Arrayeintraege\n", // -11#
			"Wiederholungszaehler muss > 0 sein\n", // -12#
	};


/*
 * return 0 = ok else error
 */


int scanDelayLine(struct arrayData_t *sp);

char *setdelaychain;

char *str_tmp;

struct t_config  *sp;
struct trace_config_t tc;


int readConfig(char *argv) {
	config_t cfg;
	config_setting_t *root, *setting, *element, *feld;
	int ret;


	sp = malloc(sizeof(struct t_config));
	if(!sp)  {
		printf("error: malloc sp %s\n",__FUNCTION__);
	}


	sp->change_delay = 0;

	config_init(&cfg);

	/* Read the file. If there is an error, report it and exit. */
	if (!config_read_file(&cfg, argv)) {
		fprintf(stderr, "%s:%d - %s\n", config_error_file(&cfg),
				config_error_line(&cfg), config_error_text(&cfg));
		config_destroy(&cfg);
		return (EXIT_FAILURE);
	}

	root = config_root_setting(&cfg);

	ret = config_setting_lookup_string(root, "setdelaychain", (const char **) &setdelaychain);
	if (!ret) {

		printf("error: reading setdelaychain\n");
		return (EXIT_FAILURE);
	} else {

		if (!strncmp("on", setdelaychain, 2)) {
			// Parameter einlesen und setzen
			feld = config_setting_get_member(root, "delaychain");
			sp->count = config_setting_length(feld);
			if (sp->count == 64) {

				for (int t = 0; t < 64; t++) {
					element = config_setting_get_elem(feld, t);
					ret = config_setting_get_int(element);
					// printf("t=%d delay=%d\n",t,ret);
					if(ret >10000) {
						printf("error: delaychain Wert nicht erlaubt maximal 10.000\n");
					}
					tc.delaychain[t] = ret;
//					if(!ret) {
//						printf("error:delaychain wert nicht erlaubt\n");
//						return (EXIT_FAILURE);
//					}

				}

			} else {
				printf("error: delaychain muss 64 Eintraege habe\n");
			}
		} else if (!strncmp("off", setdelaychain, 3)) {
			// keine Aenderung vornehmen
			sp->change_delay = 1;
		} else if (!strncmp("default", setdelaychain, 7)) {
			for (int t = 0; t < 64; t++) {
				tc.delaychain[t]=16*t+16;
			}

		}

	}

	setting = config_setting_get_member(root, "sessions");
	if (setting != NULL) {
		sp->count = config_setting_length(setting);
		if (sp->count > 0) {
			sp->sessionParam = malloc(sp->count * sizeof(struct session_desc_t));
			if (sp->sessionParam) {
				// sp->count = config_setting_length(setting); // nach oben verschieben, ansonsten wird die falsche Anzahl allokiert

				for (int p = 0; p < sp->count; p++) {

					element = config_setting_get_elem(setting, p);
					ret = config_setting_lookup_string(element, "userpart", (const char **) &str_tmp);
					if (!ret) {
						printf("error: record reading userpart\n");
						return (EXIT_FAILURE);
					} else
					{
						strncpy(sp->sessionParam[p].userpart,str_tmp,MAX_STRING_CONFIG);

					}
					ret = config_setting_lookup_string(element, "direction",(const char **) &str_tmp);

					if (!ret) {
						printf("error: record reading direction\n");
						return (EXIT_FAILURE);
					} else
					{
						strncpy(sp->sessionParam[p].direction,str_tmp,MAX_STRING_CONFIG);
					}
					ret = config_setting_lookup_string(element, "on_r2sdelay",(const char **) &str_tmp);

					if (!ret) {
						printf("error: record reading on_r2sdelay\n");
						return (EXIT_FAILURE);
					} else
					{
						strncpy(sp->sessionParam[p].on.r2sdelay,str_tmp,MAX_STRING_CONFIG);
					}
					ret = config_setting_lookup_string(element, "on_autorepeat",(const char **) &str_tmp);

					if (!ret) {
						printf("error: record reading on_autorepeat\n");
						return (EXIT_FAILURE);
					} else
					{
						strncpy(sp->sessionParam[p].on.autorepeat,str_tmp,MAX_STRING_CONFIG);
					}

					ret = config_setting_lookup_string(element, "on_delayline",(const char **) &str_tmp);

					if (!ret) {
						printf("error: record reading on_delayline\n");
						return (EXIT_FAILURE);
					} else {

						strncpy(sp->sessionParam[p].on.delayline,str_tmp,MAX_STRING_DELAYLINE);
						printf("on_delayline: %s\n\n", sp->sessionParam[p].on.delayline);
						ret = scanDelayLine(&sp->sessionParam[p].on);
						if (ret < 0) {
							printf("error: nr=%d %s", ret * -1 - 1,
									error[(ret * -1) - 1]);
							return (EXIT_FAILURE);
						}
						for (int v = 0; v < sp->sessionParam[p].on.index; v++) {
							printf("%2.2d ", sp->sessionParam[p].on.array[v]);
						}
						printf("\n\n");

					}


					ret = config_setting_lookup_string(element, "off_r2sdelay",(const char **) &str_tmp);

					if (!ret) {
						printf("error: record reading off_r2sdelay\n");
						return (EXIT_FAILURE);
					} else
					{
						strncpy(sp->sessionParam[p].off.r2sdelay,str_tmp,MAX_STRING_CONFIG);
					}
					ret = config_setting_lookup_string(element, "off_autorepeat",(const char **) &str_tmp);

					if (!ret) {
						printf("error: record reading off_autorepeat\n");
						return (EXIT_FAILURE);
					} else
					{
						strncpy(sp->sessionParam[p].off.autorepeat,str_tmp,MAX_STRING_CONFIG);
					}

					ret = config_setting_lookup_string(element, "off_delayline",(const char **) &str_tmp);

					if (!ret) {
						printf("error: record reading off_delayline\n");
						return (EXIT_FAILURE);
					} else {

						strncpy(sp->sessionParam[p].off.delayline,str_tmp,MAX_STRING_DELAYLINE);
						printf("off_delayline: %s\n\n", sp->sessionParam[p].off.delayline);
						ret = scanDelayLine(&sp->sessionParam[p].off);
						if (ret < 0) {
							printf("error: nr=%d %s", ret * -1 - 1,
									error[(ret * -1) - 1]);
							return (EXIT_FAILURE);
						}
						for (int v = 0; v < sp->sessionParam[p].off.index; v++) {
							printf("%2.2d ", sp->sessionParam[p].off.array[v]);
						}
						printf("\n\n");

					}
				}
			} else
				return (EXIT_FAILURE);
		} else
			return (EXIT_FAILURE);
	} else
		return (EXIT_FAILURE);

	/* Get the store name. */

	config_destroy(&cfg);
/*
 * falls keine Fehler aufgetreten ist kann alles an den Treiber gesendet werden
 */
	return (EXIT_SUCCESS);
}

#define false 0
#define true -1

int scanDelayLine(struct arrayData_t *sp)
{
char *p = sp->delayline;
char *endp;
int index = 0;
int t;
int schleifenIndexStart;
int schleifenIndexStop;
int schleifencounter;
int repeatCounter;
int bracketOpen = false;
long int l;

sp->error = true;

enum scanState_t {normal=1, digit=3,findKommaOrBracketOpen=4,findKommaOrBracketClose=5};
enum last_char_t {charNone=1,charDigit=2, charBracketOpen=3, charBracketClose=4,charKomma=5};


enum scanState_t state = normal;
enum last_char_t lastChar = charNone;

while (*p!='\0') {

	if(index > ARRAY_SIZE_DELAY_CHAIN) return -11;

	switch (state) {
	case normal:
		if (isspace(*p)) p++;
		if (*p==',') return -1;   // Semikolon ohne Zahl
		if (isxdigit(*p)) state=digit;
		else if (*p=='{') return -9;
		else if (*p=='}') return -10;
		break;
	case digit:
		l = strtol(p,&endp,0);
		if(p==endp) return -2;	// keine gueltige zahl gefunden
		p=endp;
		lastChar = charDigit;

		if(!bracketOpen) {

			state = findKommaOrBracketOpen;
		}
		else {

			state = findKommaOrBracketClose;
		}
		break;
	case findKommaOrBracketOpen:
		if (isspace(*p)) p++;
		else if (*p=='{') {   // Semikolon ohne Zahl

			if(bracketOpen) {

				return -3;     // Klammer ist schon offen, Schachtelung nicht erlaubt
			}
			else {
				printf("wiederholungszaehler = %d\n",(int)l);

				if(lastChar!=charDigit) return -9;
				schleifenIndexStart = index;
				repeatCounter = l;
				if(repeatCounter <1) return -12;
				lastChar=charBracketOpen;
				bracketOpen=true;
				p++;
				state = normal;
			}
		}
		else if(*p==',') {
			p++;

			if(l<0 || (l>63 && l!=0x40 && l!=0x80 )) return -6;

			printf("zahl = %d\n",(int)l);
			lastChar = charKomma;

			sp->array[index++]=l;

			state = normal;
		}
		else if (isxdigit(*p)) state=digit;
		else if(*p=='}') return -10;

	break;
	case findKommaOrBracketClose:
		if (isspace(*p)) p++;
		else if (*p=='}') {

			if(bracketOpen== false) {

				return -4;     // Klammer zu obwohl nich offen
			}
			else {

				if(lastChar == charBracketOpen) return -10;
				bracketOpen=false;
				p++;
				lastChar=charBracketClose;
				schleifenIndexStop=index;
				printf("schleife = %d\n",(int) l);
				sp->array[index++]=l;

				schleifencounter=schleifenIndexStop-schleifenIndexStart;
				if(schleifencounter>=0) {

					for(int j=0;j<repeatCounter-1;j++) {

						t=schleifenIndexStart;
						for(int i=0;i<=schleifencounter;i++) {

							sp->array[index++]= sp->array[t++];
							if(index > ARRAY_SIZE_DELAY_CHAIN) return -11;
						}
					}
				}
			}
		}
		else if(*p==',') {
			p++;
			state = normal;
			if(lastChar == charDigit) {
				sp->array[index++]=l;
			}

			lastChar=charKomma;

			printf("schleife = %d\n",(int)l);

		}
		else return -5; // nach Klammer zu oder Zahl kein Semikolon

		break;
	}
}

if(bracketOpen) return -5; // Klammer zu fehlt
if(lastChar==charKomma) return -7;
if(lastChar==charDigit) sp->array[index++]=l ;
sp->index = index;
sp->error = false;
return 0;
}
