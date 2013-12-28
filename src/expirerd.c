/*
* /expirer/expirerd.c - At specific time period, automagically the files will expire.
*
* Copyright (C) 2013 Lakshmipathi.G <lakshmipathi.g@giis.co.in>
* Visit www.giis.co.in for manuals or docs.
*/

#include <db.h>
#include <sys/time.h>
#include <string.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <signal.h>
#define DB_PATH "/etc/expirer/info.db"


struct expirer_data {
	unsigned long int inode_number,expiry_time;
	int owner;
	char *file_path;
	char *sha256sum;
};

void restart_process(char **args){
	int childpid;

	childpid = fork ();
	if (childpid < 0) {
		perror ("fork failed");
	} else if (childpid  == 0) {
		printf ("new process %d", getpid());
		int rv = execve (args[0], args, NULL);
		if (rv == -1) {
			perror ("execve");
			exit (EXIT_FAILURE);
		}

	} else {
		sleep (5);
		printf ("killing %d\n", getpid());
		kill (getpid (), SIGTERM);
	}
}

char md5sum[34];
volatile sig_atomic_t signal_received = 0;
void sighandler (int signum) {
	signal_received = 1;
}


void compute_md5sum(char *filelocation){
	FILE *pf;
	char md5_cmd[512];
	extern char md5sum[34];
	//Recompute md5  of recovered file
	memset(md5_cmd,'\0',512);
	memset(md5sum,'\0',34);
	sprintf(md5_cmd,"md5sum %s",filelocation);
	pf=popen(md5_cmd,"r");
	if(!pf){
		fprintf(stderr,"Could not open pipe");
		return ;
	}

	//get data
	fgets(md5sum, 34 , pf);

	if (pclose(pf) != 0)
		fprintf(stderr," Error: close Failed.");
}

time_t expirer_current_time();
validate_entries(struct expirer_data user){
	struct stat filestat;
	extern char md5sum[34];

	if (stat(user.file_path, &filestat) == -1){
		printf("file %s not found : disk-file already renamed/unlinked.\n",user.file_path);
		return 1;
	}
	else{
		if (user.inode_number != filestat.st_ino || user.owner != filestat.st_uid){
			printf("Either file inode is re-used %lu or\
					Owner has been changed %d.\
					So Skipping this file%d\n",user.inode_number,user.owner,user.file_path);
			return 1;
		}
		compute_md5sum(user.file_path);
		if((strcmp (user.sha256sum,md5sum)))
			return 1; //checksum mismatch

	}

	return 0;
}
// get current time in seconds.
time_t expirer_current_time(){
	struct timeval tv;
	struct timezone tz;

	gettimeofday(&tv, &tz);
	return tv.tv_sec;
}

int main(int argc,char* argv[]){

	unsigned long int etime;
	DBT key, data;
	DB *my_database;
	struct expirer_data user;
	char *buffer,*key_buf;
	int ret;
	u_int32_t flags;
	struct stat filestat;
	unsigned long int cur_time=0;
	FILE *fd;
	char buf[32];
	DBC *cursorp;

	if (signal (SIGUSR1, sighandler) == SIG_ERR) {
		perror ("signal failed");
	}
forever_loop:
	if (signal_received) {
		goto close_db;
	}
	// get pid and log it
	fd = fopen("/var/run/expirerd.pid","w");
	sprintf(buf,"%d",getpid());
	fwrite(buf,sizeof(int),1,fd);
	fclose(fd);

	if (stat(DB_PATH, &filestat) == -1){
		printf("file not found");
		return 1;
	}
	if (filestat.st_uid !=0 || filestat.st_mode != 33184 ){
		printf("Wrong DB permissions uid=%d mode=%d",filestat.st_uid,filestat.st_mode);
		return 1;
	}

	ret = db_create(&my_database, NULL, 0);
	if (ret != 0) {
		printf("\n db_create failed.");
		return 1;
	}
	flags = DB_CREATE;   

	ret = my_database->open(my_database,NULL,DB_PATH,NULL,DB_BTREE,flags,0);
	if (ret != 0) {
		printf("\n db_open failed.");
		return 1;
	}


	/* Zero out the DBTs before using them. */
	memset(&key, 0, sizeof(DBT));
	memset(&data, 0, sizeof(DBT));

	/* Get a cursor */
	my_database->cursor(my_database,NULL,&cursorp,0);

	ret = cursorp->get(cursorp,&key,&data,DB_NEXT);

	if (ret < 0) {
		printf("\n Empty Db");
		sleep(120);//ideally sleep until USR1 received!
	}else{
		key_buf = key.data;
		buffer = data.data;
		etime = *((unsigned long *)key.data);

		user.owner = *((int *)data.data);
		user.inode_number = *((unsigned long *)(buffer+sizeof(int)));
		user.expiry_time = *((unsigned long*)(buffer + sizeof(int) +sizeof(unsigned long int)));
		user.file_path = buffer + (sizeof(unsigned long int) * 2) + sizeof(int); 
		user.sha256sum = buffer + (sizeof(unsigned long int) * 2) + sizeof(int) + strlen(user.file_path) +1; 


		cur_time = expirer_current_time();
		while (user.expiry_time > cur_time){
			sleep(10);
			cur_time = expirer_current_time();
			if (signal_received) 
				goto close_db;
		}

		//validate current disk file entries match db stat
		if (validate_entries(user) == 0){
			unlink(user.file_path);
			cursorp->del(cursorp, 0);
		}else //Ignore- perm changed or file renamed/deleted - checksum mismatch.
		{
			cursorp->del(cursorp, 0);
		}

	}
	/* Cursors must be closed */
close_db:
	if (cursorp != NULL)
		cursorp->close(cursorp); 

	if (my_database != NULL)
		my_database->close(my_database, 0);
	if(signal_received){
		signal_received = 0;
		restart_process (argv);
	}

	goto forever_loop;
}
