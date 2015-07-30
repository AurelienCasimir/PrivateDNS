#include <stdio.h>
#include <stdlib.h>
#include <inttypes.h>
#include  <stdint.h>
#include <string.h>
#include <fcntl.h> // for open
#include <unistd.h> // for close

uint16_t jenkins_one_at_a_time_hash(char *key, size_t len)
{
    uint16_t hash, i;
    for(hash = i = 0; i < len; ++i)
    {
        hash += key[i];
        hash += (hash << 10);
        hash ^= (hash >> 6);
    }
    hash += (hash << 3);
    hash ^= (hash >> 11);
    hash += (hash << 15);
    return hash;
}

int main(int argc, char **argv)
{
	int length = 0;
	int already_exist = 0;
	FILE *fp;
	char filepath[100], url[100], ip[16];
	
	if (argc < 3)
	{
		printf("Usage: %s <URL> <IP>\n", argv[0]);
		exit(1);
	}

	length += sprintf(filepath, "./db/");
	length += sprintf(filepath + length, "%" PRIu16 "", jenkins_one_at_a_time_hash(argv[1], strlen(argv[1])));
	
	fp = fopen(filepath, "a+");
	if (fp == NULL) 
	{
		fprintf(stderr, "error opening/creating file\n");
		exit(1);
	}

	while(!already_exist && (fscanf(fp, "%s %s", url, ip)==2)) //Stop reading if success or fail reading 2 arguments
		{
			if(!strcmp(argv[1], url) && !strcmp(argv[2], ip))
			{
				already_exist = 1;
			}
		}
	if (!already_exist) 
		fprintf(fp, "%s %s\n", argv[1], argv[2]);
	else
		printf("This entry is already in the database\n");

	fclose(fp);
	return 0;
}
