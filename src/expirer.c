/*
* /expirer/expirer.c - At specific time period, automagically the files will expire.
*
* Copyright (C) 2013 Lakshmipathi.G <lakshmipathi.g@giis.co.in>
* Visit www.giis.co.in for manuals or docs.
*/

#define _GNU_SOURCE
#include <dirent.h>     /* Defines DT_* constants */
#include <fcntl.h>
#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <sys/syscall.h>
#include <sys/time.h>
#include <sys/time.h>
#include <ext2fs/ext2fs.h>
#include <ext2fs/ext2_io.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <pwd.h>
#include <errno.h>
#include <assert.h>    /* assert */
#include <libgen.h>
/* argp */
#include <argp.h>
// bdb routines
#include <db.h>
#include <string.h>
#include <stdlib.h>
#include <signal.h>


#define handle_error(msg) \
do { perror(msg); exit(EXIT_FAILURE); } while (0)
#define BUF_SIZE 1024
#define TRUE 1
#define FALSE 0
#define MAXPATHLEN 4096
#define DB_PATH "/etc/expirer/info.db"



struct arguments
{
	char *device_name,*filepath,*mounteddir;
	char *deltime;		    /* 1-device 2-filepath 3-time 4-scan*/
	int flag;
};
struct ext2_struct_inode_scan {
	errcode_t		magic;
	ext2_filsys		fs;
	ext2_ino_t		current_inode;
	blk64_t			current_block;
	dgrp_t			current_group;
	ext2_ino_t		inodes_left;
	blk_t			blocks_left;
	dgrp_t			groups_left;
	blk_t			inode_buffer_blocks;
	char *			inode_buffer;
	int			inode_size;
	char *			ptr;
	int			bytes_left;
	char			*temp_buffer;
	errcode_t		(*done_group)(ext2_filsys fs,
					      ext2_inode_scan scan,
					      dgrp_t group,
					      void * priv_data);
	void *			done_group_data;
	int			bad_block_ptr;
	int			scan_flags;
	int			reserved[6];
};

struct node {
	unsigned long file_inode,parent_inode,expiry_time;
	char *pathname;
	struct node* next;
	};
struct node *head=NULL;

static struct argp_option options[] =
{  
	{"device",   'd', "Device name", 0,"Partition where the file resides."},
	{"file",   'f', "Absoulte path", 0,"Absoulte path of expiry file."},
	{"scan", 's', 0, 0, "Re-create the database."},
	{"mounteddir",   'm', "Mount point", 0,"Directory where partition mounted."},
	{"time", 't', "Minutes", 0, "Remaining minutes before the file expires."},
	{"list", 'l', 0, 0, "List file  details."},
	{"cancel", 'c', 0, 0, "Cancel an entry."},
	{0}
};
int EXT2_BLOCK_SIZE;
char device[75];
const char *argp_program_version = "expirer 0.1 (27-12-2012) ";
const char *argp_program_bug_address = "<lakshmipathi.g@giis.co.in>";


/* Functions involved. */
static error_t parse_opt (int, char *, struct argp_state *); 
time_t expirer_current_time();
void expirer_read_inode(ext2_filsys,struct stat * ,struct ext2_inode *);
void expirer_write_inode(ext2_filsys,struct stat * ,struct ext2_inode *);
void expirer_set_dtime(struct ext2_inode *, int);
void expirer_computer_md5sum(char *);
int expirer_list_files(int,char *);
void expirer_file_inode_list_push(struct node**,unsigned long,unsigned long ,unsigned long );
char* expirer_get_abs_path(char *);
void expirer_add_list_to_bdb(struct node*);
void expirer_compute_md5sum(char *);

static char args_doc[] = "";
static char doc[] = "\n\nUsage: expirer [-s scan -d devicename -m mounteddir] [-l list] [-c -f filepath] [-d devicename -f filepath -t minutes]\n\nexpirer - File expiry tool for ext{2,3,4} file system.(http://www.giis.co.in)\n\n";
static struct argp argp = {options, parse_opt, args_doc, doc};


static error_t parse_opt (int key, char *arg, struct argp_state *state)
{
	struct arguments *arguments = state->input;

	switch (key)
	{
		case 'd':
			arguments->device_name=arg;
			break;
		case 'f':
			arguments->filepath=arg;
			break;
		case 'c':
			arguments->flag=3;
			break;
		case 'l':
			arguments->flag=2;
			break;
		case 's':
			arguments->flag=1;
			break;
		case 'm':
			arguments->mounteddir=arg;
			break;
		case 't':
			arguments->deltime=arg;
			break;
		default:
			return ARGP_ERR_UNKNOWN;
	}
	return 0;
}

struct stat* getfilestat(char *path);


typedef struct expirer_data {
	int owner;
	unsigned long int inode_number,expiry_time;
	char *file_path;
	char *sha256sum;
} EXPIRER_DATA;
char md5sum[34];
char mounteddir[75];

int main(int argc,char *argv[]){
	ext2_filsys	current_fs = NULL;
	extern char device[75];
	char *filename;
	extern char mounteddir[75];
	int  open_flags = EXT2_FLAG_SOFTSUPP_FEATURES | EXT2_FLAG_RW;
	blk_t superblock=0;
	blk_t blocksize=0;
	int retval=0;
	int i=0,childpid,running;
	int ans=0,mins=60;
	struct arguments arguments;
	struct stat filestat;
	struct ext2_inode inode,*in={'\0'};
	struct ext2_inode_large *large_inode;
	extern char md5sum[34];
	EXPIRER_DATA user;

	/* Set defaults */
	arguments.device_name="";
	arguments.filepath="";
	arguments.flag=0;
	arguments.deltime="";
	arguments.mounteddir="";

	argp_parse (&argp, argc, argv, 0, 0, &arguments);

	/* Collect inputs */
	filename=arguments.filepath;
	if (arguments.deltime != "")
		mins=atoi(arguments.deltime);
	strcpy(device,arguments.device_name);

	if(arguments.flag == 2){
		expirer_list_files(0,filename);
		return 0;
	}
	if(arguments.flag == 3){
		if (filename == ""){
			printf("\n Usage : expirer -c -f absolutepath\n\n");
			return 1;
		}
		expirer_list_files(1,filename);
		return 0;
	}
	if(arguments.flag == 1){
		if (arguments.device_name == ""){
			printf("\n Usage : expirer -s -d devicename\n\n");
			return 1;
		}
		strcpy(mounteddir,arguments.mounteddir);
	}

	if (arguments.flag !=1 && stat(filename, &filestat) == -1)
		handle_error("file not found");
	// basic checks
	if (arguments.flag !=1 && getuid() != 0 && getuid() != filestat.st_uid ){
		printf("%d - %d",getuid(),filestat.st_uid);
		handle_error("Only owner can set expiry time\n");
	}

	if ( arguments.flag!=1 && (!S_ISREG(filestat.st_mode)))
		handle_error("Only regular file type supported.\n");


	retval = ext2fs_open(device, open_flags, superblock, blocksize,unix_io_manager, &current_fs);
	if (retval) {
		current_fs = NULL;
		handle_error("Error while opening filesystem.\n");
	}

	EXT2_BLOCK_SIZE=current_fs->blocksize;
	if (arguments.flag == 1){
		printf("\n Re-scanning drive %s for mountpoint%s\n",device,mounteddir);
		expirer_search_inodetype(current_fs,1); //regular files
		expirer_search_inodetype(current_fs,2); //directory inode

		//re-fill the data
		expirer_add_list_to_bdb(head);
		return 0;
	}
	expirer_read_inode(current_fs,&filestat,&inode);
	expirer_set_dtime(&inode,mins);
	expirer_write_inode(current_fs,&filestat,&inode);
	ext2fs_close(current_fs);
	//fill-in the values
	user.owner = filestat.st_uid;
	user.inode_number = filestat.st_ino ;
	user.expiry_time = inode.i_dtime;
	user.file_path = filename;
	expirer_compute_md5sum(filename);
	user.sha256sum = md5sum;

	expirer_bdb_insert(&user);
	
	running=system("pgrep expirerd &> /dev/null");
	if (running == 0){
	// If already running restart it via USR1 signal
	system("touch /var/run/expirerd.pid && kill -USR1 `cat /var/run/expirerd.pid` &> /dev/null");
	}else{
		system("/usr/sbin/expirerd &>/dev/null &");
	}

	fprintf(stdout,"\n File %s will expire in %d minutes : %s\n",user.file_path,mins,ctime(&user.expiry_time));
	return 0;
}
void expirer_add_list_to_bdb(struct node* current){
	EXPIRER_DATA user;
	struct stat filestat={'\0'};
	char *pathname=NULL;

	while(current!=NULL){

		user.inode_number = current->file_inode;
		user.expiry_time = current->expiry_time;
		user.file_path = expirer_get_abs_path(current->pathname);
		stat(user.file_path, &filestat);
		user.owner = filestat.st_uid;
		expirer_compute_md5sum(user.file_path);
		user.sha256sum = md5sum;

		expirer_bdb_insert(&user);
		current=current->next;
	}
}

int update_file_inode_list(struct node* current,unsigned long fileinode,unsigned long parent_inode,char *pathname){

	while(current!=NULL){
		if(fileinode == current->file_inode){
			current->parent_inode=parent_inode;
			current->pathname=pathname;
		}
		current=current->next;
	}
	return 1;
}
int search_file_inode_list(unsigned long fileinode){
	struct node* current=head;

	while(current!=NULL){
		if(fileinode == current->file_inode)
			return 0;
		current=current->next;
	}
	return 1;
}

struct private_data{
	unsigned long parent_inode;
	ext2_filsys current_fs;
};

char abs_path[75];
char* expirer_get_abs_path(char *path){
	extern char mounteddir[75],abs_path[75];
	memset(abs_path,0,75);
	strcpy(abs_path,mounteddir);
	return strcat(abs_path,path);
}
int expirer_check_entries(struct ext2_dir_entry *dirent,
			int offset EXT2FS_ATTR((unused)),
			int blocksize EXT2FS_ATTR((unused)),
			char *buf EXT2FS_ATTR((unused)), void *private)
{
	char *pathname=NULL;
	struct private_data *pnode = (struct private_data *)private;
	unsigned long file_inode= (unsigned long) dirent->inode;

	if(!search_file_inode_list(file_inode)){
		ext2fs_get_pathname (pnode->current_fs, pnode->parent_inode, dirent->inode, &pathname);
		update_file_inode_list(head,file_inode,pnode->parent_inode,pathname);
	}
}

/*
 * If inodetype = 1 , search only regular inodes and  create list of file inodes.
 * If inodetype = 2 , search only dir inodes and then lookup for file_inode# 
 */

int expirer_search_inodetype(ext2_filsys current_fs,int inodetype){
	ext2_inode_scan scan = 0;
	ext2_ino_t  ino;
	unsigned long count=0;
	struct ext2_inode inode,*in={'\0'};
	int retval=0,grp_desc=0;
	struct private_data *pino={'\0'};
	pino = calloc (1,sizeof(struct private_data));

	retval = ext2fs_open_inode_scan(current_fs, 0, &scan);
	if (retval) {
		handle_error("while opening inode scan");
	}


	do {
		retval = ext2fs_get_next_inode(scan, &ino, &inode);
	} while (retval == EXT2_ET_BAD_BLOCK_IN_INODE_TABLE);
	if (retval) {
		handle_error("error while starting inode scan");
	}

	while (ino){
		if (inodetype == 1){

			if (!LINUX_S_ISREG(inode.i_mode))
				goto next;

			if(inode.i_dtime && inode.i_links_count)
				expirer_file_inode_list_push(&head,ino,0,inode.i_dtime);

		}else{ 
			if (!LINUX_S_ISDIR(inode.i_mode))
				goto next;

			if (inode.i_dtime)
				goto next;
			pino->parent_inode=ino;
			pino->current_fs=current_fs;
			retval = ext2fs_dir_iterate(current_fs, ino, 0, 0,
					expirer_check_entries, pino);
		}

next:
		do {
			retval = ext2fs_get_next_inode(scan, &ino, &inode);
		} while (retval == EXT2_ET_BAD_BLOCK_IN_INODE_TABLE);
	}
	free(pino);
	if (scan)
		ext2fs_close_inode_scan(scan); 
}



//print the list
void expirer_printlist(struct node* current){
	while(current!=NULL){
		printf("\n file :%u",current->file_inode);
		printf("\n parent:%u",current->parent_inode);
		printf("\n dtime:%d",current->expiry_time);
		printf("\n pathname:%s",current->pathname);
		current=current->next;
	}
}

//push data into the list
void expirer_file_inode_list_push(struct node** headref,unsigned long file_inode,unsigned long parent_inode,unsigned long dtime){

	struct node* newnode=NULL;
	newnode=malloc(sizeof(struct node));

	newnode->file_inode=file_inode;
	newnode->parent_inode=parent_inode;
	newnode->expiry_time=dtime;

	newnode->next=*headref;

	*headref=newnode;
#if 0
	expirer_printlist(*headref);
#endif

}

void expirer_read_inode(ext2_filsys current_fs,struct stat* filestat,struct ext2_inode *in){
	ext2fs_read_inode(current_fs,filestat->st_ino,in);
}

void expirer_write_inode(ext2_filsys current_fs,struct stat* filestat,struct ext2_inode *in){
	int retval=0;
	retval=ext2fs_write_inode(current_fs,filestat->st_ino,in);
	if (retval) {
		current_fs = NULL;
		handle_error("Error while writing inode.");
	}
}

void expirer_set_dtime(struct ext2_inode *in,int minutes){
	if (minutes)
		in->i_dtime=(minutes*60)+expirer_current_time();
	else
		in->i_dtime=0;

}
/*
 * *expirer_list_files 
 * flag 0 - Just parse through the db using cursor.
 * flag 1 - Find given path and remove it from db.
 */
int expirer_list_files(int flag,char *filename){
	DBT key, data;
	DB *my_database;
	EXPIRER_DATA user;
	char *buffer,*key_buf;
	int ret;
	u_int32_t flags;
	DBC *cursorp;

	ret = db_create(&my_database, NULL, 0);
	if (ret != 0) {
		handle_error("db create fails.");
	}
	flags = DB_CREATE;   

	ret = my_database->open(my_database,NULL,DB_PATH,NULL,DB_BTREE,flags,0);
	if (ret != 0) {
		handle_error("db open fails.");
	}


	/* Zero out the DBTs before using them. */
	memset(&key, 0, sizeof(DBT));
	memset(&data, 0, sizeof(DBT));

	/* Get a cursor */
	my_database->cursor(my_database,NULL,&cursorp,0);

	if (!flag){
	printf("\n\tFilename\t      Expires on\n");
	printf("\n\t--------\t      ----------\n");
	}
	while ((ret = cursorp->get(cursorp,&key,&data,DB_NEXT)) == 0){
		key_buf = key.data;
		buffer = data.data;

		user.owner = *((int *)data.data);
		user.inode_number = *((unsigned long *)(buffer+sizeof(int)));
		user.expiry_time = *((unsigned long*)(buffer + sizeof(int) +sizeof(unsigned long int)));
		user.file_path = buffer + (sizeof(unsigned long int) * 2) + sizeof(int); 
		user.sha256sum = buffer + (sizeof(unsigned long int) * 2) + sizeof(int) + strlen(user.file_path) +1; 
		if (!flag){
			printf("\n\t%s\t",user.file_path);
			printf("%s",ctime(&user.expiry_time));
		}else{
			if (!strcmp(user.file_path,filename))
			{
			cursorp->del(cursorp, 0);
			if (cursorp != NULL)
			    cursorp->close(cursorp); 

			if (my_database != NULL)
			    my_database->close(my_database, 0);
			return 0;
			}
		}

	}
	if (cursorp != NULL)
	    cursorp->close(cursorp); 

	if (my_database != NULL)
	    my_database->close(my_database, 0);

	return 0;

}

void expirer_compute_md5sum(char *filelocation){
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


// get current time in seconds.
time_t expirer_current_time(){
	struct timeval tv;
	struct timezone tz;

	gettimeofday(&tv, &tz);
	return tv.tv_sec;
}


int btreecompare(DB *db,const DBT *d1,const DBT *d2){
	unsigned long int d1_key = *(unsigned long int *)d1->data;
	unsigned long int d2_key = *(unsigned long int *)d2->data;

	if (d1_key < d2_key)
		return -1;
	else if (d1_key > d2_key)
		return 1;
	else	
		return 0;
}

int expirer_bdb_insert(EXPIRER_DATA *user){
	DBT key, data;
	DB *my_database;
	int buffsize, bufflen;
	char *databuff;
	u_int32_t flags;
	int ret;


	ret = db_create(&my_database, NULL, 0);
	if (ret != 0) {
		handle_error("db create failed");
	}

	/* Enable support for duplicate records */
	ret = my_database->set_flags(my_database,DB_DUPSORT);
	if (ret !=0 ){
		handle_error("Attempt to set duplication flag failed");
	}

	my_database->set_bt_compare(my_database,btreecompare);

	flags = DB_CREATE;   


	ret = my_database->open(my_database,NULL,DB_PATH,NULL,DB_BTREE,flags,0);
	if (ret != 0) {
		if (my_database != NULL)
			my_database->close(my_database, 0);
		handle_error("Open db failed");
	}


	/* Get the buffer */
	buffsize = sizeof(int) + sizeof(unsigned long)+ sizeof(unsigned long)+
		(strlen(user->file_path) + strlen(user->sha256sum) + 2);
	databuff = malloc(buffsize);
	memset(databuff, 0, buffsize);

	/* copy everything to the buffer */
	memcpy(databuff, &(user->owner), sizeof(int));
	bufflen = sizeof(int);

	memcpy(databuff + bufflen, &(user->inode_number),sizeof(unsigned long));
	bufflen += sizeof(unsigned long);

	memcpy(databuff + bufflen, &(user->expiry_time),sizeof(unsigned long));
	bufflen += sizeof(unsigned long);

	memcpy(databuff + bufflen, user->file_path, 
			strlen(user->file_path) + 1);
	bufflen += strlen(user->file_path) + 1;

	memcpy(databuff + bufflen, user->sha256sum, 
			strlen(user->sha256sum) + 1);
	bufflen += strlen(user->sha256sum) + 1;

	/* Zero out the DBTs before using them. */
	memset(&key, 0, sizeof(DBT));
	memset(&data, 0, sizeof(DBT));

	key.data = &(user->expiry_time);
	key.size = sizeof(unsigned long);

	data.data = databuff;
	data.size = bufflen;

	ret = my_database->put(my_database, NULL, &key, &data, 0);
	if (ret != 0 ){
		if (my_database != NULL)
			my_database->close(my_database, 0);
		handle_error("insert record failed");
	}

	/* When we're done with the database, close it. */
	if (my_database != NULL)
		my_database->close(my_database, 0);
	free(databuff);

}
