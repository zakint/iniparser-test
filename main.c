#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "iniparser.h"

void create_example_ini_file(void);
int  parse_ini_file(char * ini_name);

int main(int argc, char * argv[])
{
        parse_ini_file("modfilter.ini");
}

int parse_ini_file(char * filterfile_path)
{
     dictionary *   ini ;
    ini = iniparser_load(filterfile_path);
    if (ini==NULL) {
        fprintf(stderr, "cannot parse file: %s\n", filterfile_path);
        return;
    }
    //iniparser_dump(ini, stderr);
	
	int secnum = iniparser_getnsec(ini);
	
	printf("secnum: %d\n",secnum);
	for(int i = 0; i< secnum; i++)
	{
		char id[1024] = {0};
        char bpf_tmp[4096] = {0};
        char fcode[1024] = {0};
		
		strcpy(id, iniparser_getsecname(ini,i));
		printf("id:%s\n",id);
		
		char key_bpf[1024] = {0};
		sprintf(key_bpf,"%s:bpf",id);
		//strcpy(bpf_tmp,iniparser_getstring(ini,key_bpf,NULL));
		printf("%s\n",iniparser_getstring(ini,key_bpf,NULL));
		
		char key_mcode[1024] = {0};
		sprintf(key_mcode,"%s:mcode",id);		
		const char* result = iniparser_getstring(ini,key_mcode,NULL);
		if(result == NULL) 
		{
			printf("INI Format Wrong");
			exit(1);
		}			
		else{
			strcpy(fcode,result);
			printf("%s\n",fcode);
		}
		
        if (id == NULL || bpf_tmp == NULL || fcode == NULL )
        {
            fprintf(stderr, "Wrong format in ini file");
            exit(1);
        }

		/*
        // TODO: here is dump!!
        char *bpf = (char*)malloc(4096);
        strncpy(bpf, bpf_tmp, 4096);
        strnrepl("$MAC", mac_addr, bpf, 4096);

        fprintf(stderr, "id: \"%s\"; bpf: \"%s\"; fcode = %02d\n", id, bpf, atoi(fcode));

        filters_add(ctx, id, bpf,fcode);
        // the bpf is not needed anymore
        free(bpf);
		*/
    }
}