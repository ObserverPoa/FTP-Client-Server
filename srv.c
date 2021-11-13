#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <sys/wait.h>
#include <signal.h>
#include <dirent.h>
#include <sys/stat.h>
#include <pwd.h>
#include <grp.h>
#include <time.h>
#include <errno.h>
#include <fcntl.h>

#define MAX_BUFF 4096
#define ASCII_MODE (S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH)
#define BIN_MODE (S_IXUSR | S_IXGRP | S_IXOTH)

/*****************  child process information linked list    *****************/
struct child_info_node
{
	struct child_info_node* next; // next node pointer
	pid_t chld_pid; // child process pid
	unsigned int service_tm; // service time of child process
};
static struct child_info_node* child_info_head = NULL;
static struct child_info_node* child_info_tail = NULL;
static int child_info_size = 0;

void insert_child_info(struct child_info_node* node) // insert new node at tail
{
	if (child_info_size == 0)
	{
		child_info_head = node;
		child_info_tail = node;
	}
	else
	{
		child_info_tail->next = node;
		child_info_tail = node;
	}
	++child_info_size;
}

void update_child_info(unsigned int time) // updates service_tm.
{
	struct child_info_node* cur = child_info_head;
	while (cur != NULL)
	{
		cur->service_tm += time;
		cur = cur->next;
	}
}

void delete_child_info(pid_t pid) // delete node that match with child prid
{
	struct child_info_node* prev = NULL;
	struct child_info_node* cur = child_info_head;
	while (cur != NULL && cur->chld_pid != pid)
	{
		prev = cur;
		cur = cur->next;
	}

	if (cur != NULL)
	{
		if (cur == child_info_head) // delete head node
		{
			child_info_head = cur->next;
		}
		else // delete other node
		{
			prev->next = cur->next;
		}

		if (cur->next == NULL) // if deleted tail node
		{
			child_info_tail = prev;
		}
		free(cur);
		--child_info_size;
	}
}

unsigned int get_child_time(pid_t pid) // return specific child service time.
{
	struct child_info_node* prev = NULL;
	struct child_info_node* cur = child_info_head;
	while (cur != NULL && cur->chld_pid != pid)
	{
		prev = cur;
		cur = cur->next;
	}

	if (cur != NULL)
	{
		return cur->service_tm;
	}
	else
	{
		return 0;
	}
}

void clear_child_info() // clear linked list
{
	struct child_info_node* cur = child_info_head;
	while (cur != NULL)
	{
		struct child_info_node* tmp = cur;
		cur = cur->next;
		free(tmp);
	}
	child_info_head = NULL;
	child_info_tail = NULL;
	child_info_size = 0;
}
/*************************************************************************************/

void sh_chld(int); // SIGCHLD handler
void sh_alrm(int); // SIGALRM handler

int send_append(char* buff, char* src, int sockfd, int* total); // append to result buffer. send buffer if full
int print_ls_detail(char** paths, int size, int opt_a, char** upper, int upper_nulpos, char* buff, int sockfd, int* total); // ls with -l option
int print_ls_dir(char* tmp, char* buff, int opt_a, int opt_l, int sockfd, int* total); // if arg of ls is directory

char* convert_str_to_addr(char* str, unsigned int* port); // return dotted decimal ip string, store port num in port parsed from str.
int cmd_process(char* rcv_buff, char* snd_buff, int sockfd); // process FTP command

int user_match(char* user, char* passwd); // check received user id and passwd matches with specific info in passwd file.
int log_auth(int connfd, char* buff); // client authenticator

ssize_t print_str(char* str) // print string to stdout
{
	ssize_t res = 0;
	if (str)
	{
		res = write(STDOUT_FILENO, str, strlen(str));
	}
	return res;
}

int main(int argc, char **argv)
{
	if(argc < 2) // if port number is not entered
	{
		print_str("port number is required!!\n");
		return 1;
	}

	char rcv_buff[MAX_BUFF], snd_buff[MAX_BUFF], username[MAX_BUFF]; // receiving FTP command buffer, result buffer to send to client
	struct sockaddr_in serv_addr, cli_addr, cli_data_addr; // socket address
	int srv_sock, cli_sock, cli_data_sock; // socket descriptor
	int n;

	if((srv_sock = socket(PF_INET, SOCK_STREAM, 0)) < 0) // open new socket(server)
	{
		print_str("failed to create socket!!\n");
		return 1;
	}

	// setup server socket address
	memset(&serv_addr, 0, sizeof(serv_addr));
	serv_addr.sin_family = AF_INET;
	serv_addr.sin_addr.s_addr = htonl(INADDR_ANY);
	serv_addr.sin_port = htons(atoi(argv[1]));

	if (bind(srv_sock, (struct sockaddr*)&serv_addr, sizeof(serv_addr)) < 0) // bind server socket with address
	{
		print_str("failed to bind local address!!\n");
		close(srv_sock);
		return 1;
	}

	listen(srv_sock, 5); // listen (max queue: 5)

	signal(SIGCHLD, sh_chld); // install signal handler of SIGCHLD
	signal(SIGALRM, sh_alrm); // install signal handler of SIGALRM

	while (1) // infinite loop
	{
		pid_t pid;
		int len = sizeof(cli_addr);
		cli_sock = accept(srv_sock, (struct sockaddr*)&cli_addr, &len); // accept client connection

		// crate new child process
		if ((pid = fork()) > 0) // parent server process code
		{
			struct child_info_node* node = (struct child_info_node*)malloc(sizeof(struct child_info_node));
			node->next = NULL;
			node->chld_pid = pid;
			node->service_tm = 1;
			unsigned int tm = alarm(10); // renew alarm 10 sec
			if (tm > 0)
			{
				update_child_info(10 - tm); // add time passed
			}
			insert_child_info(node); // insert to list
		}
		else if (pid == 0) // child server process code (interact with client)
		{
			signal(SIGCHLD, SIG_DFL); // remove SIGCHLD handler.
			signal(SIGALRM, SIG_IGN); // ignore SIGALRM in child.
			close(srv_sock); // close server socket

			int motd_fail = 0;
			FILE* fp_checkIP = fopen("access.txt", "r");
			FILE* fp_motd = fopen("motd", "r");
			if (!fp_checkIP)
			{
				print_str("failed to open access.txt!!\n");
				return 1;
			}
			else if (!fp_motd)
			{
				motd_fail = 1;
			}

			char cli_ip[4][4]; // to store splited dotted-decimal string by dot.
			char* tok = strtok(inet_ntoa(cli_addr.sin_addr), ".");
			for (int i = 0; i < 4; ++i) // split dotted-decimal string of client ip address
			{
				if (tok == NULL || strlen(tok) > 3) {
					print_str("IP addr format error\n"); return 1;
				}
				strcpy(&cli_ip[i][0], tok);
				tok = strtok(NULL, ".");
			}

			char* line = NULL; // one line of access.txt
			size_t line_size;
			ssize_t res;
			int acceptable = 0;
			rewind(fp_checkIP);
			// find the ip address that matches the client ip address in access.txt.
			while ((res = getline(&line, &line_size, fp_checkIP)) != -1)
			{
				if (res > 0 && line[res - 1] == '\n')
				{
					line[res - 1] = '\0'; // remove trailing delimeter in line.
				}
				tok = strtok(line, ".");
				acceptable = 1;
				for (int i = 0; i < 4; ++i)
				{
					if (tok == NULL || (strcmp(tok, "*") && strcmp(&cli_ip[i][0], tok)))
					{
						acceptable = 0;
						break;
					}
					tok = strtok(NULL, ".");
				}
				if (acceptable) { break; }
			}
			free(line);
			if (!acceptable) // if no ip in access.txt matches client's ip
			{
				strcpy(snd_buff, "431 This client can’t access. Close the session.");
				write(cli_sock, snd_buff, strlen(snd_buff));
				print_str(snd_buff); print_str("\n");
				return 1;
			}

			time_t t;
			struct tm *lt;
			char tmp_buff[100];
			time(&t);
			lt = localtime(&t);
			strftime(tmp_buff, 100, "%a %b %d %X %Z %Y", lt);

			strcpy(snd_buff, "220 ");
			line = NULL;
			if (getline(&line, &line_size, fp_motd) > 0)
			{
				char* ptr;
				if (ptr = strstr(line, "%s"))
				{
					*ptr = '\0';
					strcat(snd_buff, line);
					strcat(snd_buff, tmp_buff);
					strcat(snd_buff, ptr + 2);
				}
				else
				{
					motd_fail = 1;
				}

			}
			else
			{
				motd_fail = 1;
			}
			free(line);

			if (motd_fail)
			{
				strcat(snd_buff, "sswlab.kw.ac.kr FTP server (version myftp [1.0] ");
				strcat(snd_buff, tmp_buff);
				strcat(snd_buff, ") ready.");
			}

			write(cli_sock, snd_buff, strlen(snd_buff));
			print_str(snd_buff); print_str("\n");

			if (log_auth(cli_sock, username) < 0) // if failed to authenicate client
			{
				return 1;
			}

			while (1) // loop until receive "QUIT" from client. or read/write error (client disconnected)
			{
				memset(rcv_buff, 0, MAX_BUFF);
				memset(snd_buff, 0, MAX_BUFF);

				if ((n = read(cli_sock, rcv_buff, MAX_BUFF - 1)) <= 0) // receive whether client can connect to server
				{
					print_str("read() error\n"); return 1;
				}
				rcv_buff[n] = '\0';
				print_str(rcv_buff); print_str("\n");

				if (cmd_process(rcv_buff, snd_buff, cli_sock))
				{
					return 1;
				}
			}

			return 0; // child will be terminated.
		}
		else
		{
			print_str("fork() failed!\n");
		}

		// parent process code section
		//close(client_fd); // disconnect client.
	}

	return 0;
}

void sh_chld(int signum) // called in parent process
{
	unsigned int tm = alarm(10); // renew alarm 10 sec
	if (tm > 0)
	{
		update_child_info(10 - tm); // add time passed
	}

	pid_t pid = wait(NULL);
	if (pid != -1)
	{
		char service_tm[25] = {'\0'};
		unsigned int tm = get_child_time(pid);
		snprintf(service_tm, 25, "%u", tm);
		print_str("total service time : "); print_str(service_tm); print_str(" sec\n");
		delete_child_info(pid); // delete terminated child info from list
	}
}
void sh_alrm(int signum) // called in parent process
{
	update_child_info(10); // add passed time to service tines (10 sec)
	alarm(10); // set 10 second alarm
}

int send_append(char* buff, char* src, int sockfd, int* total) // append to result buffer.
{
	if (MAX_BUFF - strlen(buff) <= strlen(src)) // if cannot append to result buffer(overflow), flush. then, clear and append
	{
		int len = strlen(buff);
		*total += len;
		if (write(sockfd, buff, len) <= 0)
		{
			return -1;
		}
		memset(buff, 0, MAX_BUFF);
		strcat(buff, src);
		return len;
	}
	else
	{
		strcat(buff, src);
		return 0;
	}
}

int print_ls_detail(char** paths, int size, int opt_a, char** upper, int upper_nulpos, char* buff, int sockfd, int* total) // ls with -l option
{
	int max_field_len[5] = {0}; // max string length of each field. (link count, user name, gruop name, file size, last mod date)

	char** fields = (char**)calloc(size * 7, sizeof(char*)); // 2d array of each fields.
	if (fields == NULL)
	{
		return -1;
	}

	//////////////////////////////// fill in "fields" array ///////////////////////////////
	int p_size = 0; // actual printed count.(important if option -a is not used.)
	for (int i = 0; i < size; ++i)
	{
		if (opt_a || (!opt_a && paths[i][0] != '.'))
		{
			struct stat stat_buf;
			if (upper != NULL) // if parent path exist, make the relative path an absolute path and get the stat.
			{
				char* tmp_ptr = (char*)realloc(*upper, upper_nulpos + strlen(paths[i]) + 1);
				if(tmp_ptr == NULL)
				{
					for (int i = 0; i < size * 7; free(fields[i++]));
					free(fields); return -1;
				}
				else
				{
					*upper = tmp_ptr;
				}

				if (lstat(strcat(*upper, paths[i]), &stat_buf) == -1)
				{
					for (int i = 0; i < size * 7; free(fields[i++]));
					free(fields); return -1;
				}
				(*upper)[upper_nulpos] = '\0';
			}
			else
			{
				if (lstat(paths[i], &stat_buf) == -1)
				{
					for (int i = 0; i < size * 7; free(fields[i++]));
					free(fields); return -1;
				}
			}

			// get link count and update max_field_len.
			char nlink_buf[50] = {'\0'};
			snprintf(nlink_buf, 50, "%lu", stat_buf.st_nlink);
			if (strlen(nlink_buf) > max_field_len[0])
			{
				max_field_len[0] = strlen(nlink_buf);
			}

			// get user name and update max_field_len.
			struct passwd* pw;
			if ((pw = getpwuid(stat_buf.st_uid)) == NULL)
			{
				for (int i = 0; i < size * 7; free(fields[i++]));
				free(fields); return -1;
			}
			if (strlen(pw->pw_name) > max_field_len[1])
			{
				max_field_len[1] = strlen(pw->pw_name);
			}

			// get group name and update max_field_len.
			struct group* gr;
			if ((gr = getgrgid(stat_buf.st_gid)) == NULL)
			{
				for (int i = 0; i < size * 7; free(fields[i++]));
				free(fields); return -1;
			}
			if (strlen(gr->gr_name) > max_field_len[2])
			{
				max_field_len[2] = strlen(gr->gr_name);
			}

			// get file size and update max_field_len.
			char size_buf[50] = {'\0'};
			snprintf(size_buf, 50, "%lu", stat_buf.st_size);
			if (strlen(size_buf) > max_field_len[3])
			{
				max_field_len[3] = strlen(size_buf);
			}

			// get last modification time and update max_field_len.
			char mtime[256] = {'\0'};
			struct tm* ltm = localtime(&stat_buf.st_mtime);
			if (ltm == NULL)
			{
				for (int i = 0; i < size * 7; free(fields[i++]));
				free(fields); return -1;
			}
			strftime(mtime, 256, "%b %e %H:%M", ltm);
			if (strlen(mtime) > max_field_len[4])
			{
				max_field_len[4] = strlen(mtime);
			}

			// allocate memory for each fields.
			fields[p_size * 7] = (char*)calloc(11, sizeof(char));
			fields[p_size * 7 + 1] = (char*)calloc(strlen(nlink_buf) + 1, sizeof(char));
			fields[p_size * 7 + 2] = (char*)calloc(strlen(pw->pw_name) + 1, sizeof(char));
			fields[p_size * 7 + 3] = (char*)calloc(strlen(gr->gr_name) + 1, sizeof(char));
			fields[p_size * 7 + 4] = (char*)calloc(strlen(size_buf) + 1, sizeof(char));
			fields[p_size * 7 + 5] = (char*)calloc(strlen(mtime) + 1, sizeof(char));
			fields[p_size * 7 + 6] = (char*)calloc(strlen(paths[i]) + 2, sizeof(char));
			if (!fields[p_size * 7] || !fields[p_size * 7 + 1] || !fields[p_size * 7 + 2] || !fields[p_size * 7 + 3] ||
				!fields[p_size * 7 + 4] || !fields[p_size * 7 + 5] || !fields[p_size * 7 + 6])
			{
				for (int i = 0; i < size * 7; free(fields[i++]));
				free(fields); return -1;
			}

			// get permissions and make formatted string.
			if (S_ISREG(stat_buf.st_mode)) fields[p_size * 7][0] = '-';
			else if (S_ISDIR(stat_buf.st_mode)) fields[p_size * 7][0] = 'd';
			else if (S_ISCHR(stat_buf.st_mode)) fields[p_size * 7][0] = 'c';
			else if (S_ISBLK(stat_buf.st_mode)) fields[p_size * 7][0] = 'b';
			else if (S_ISFIFO(stat_buf.st_mode)) fields[p_size * 7][0] = 'p';
			else if (S_ISLNK(stat_buf.st_mode)) fields[p_size * 7][0] = 'l';
			else if (S_ISSOCK(stat_buf.st_mode)) fields[p_size * 7][0] = 's';
			else
			{
				for (int i = 0; i < size * 7; free(fields[i++]));
				free(fields); return -1;
			}

			fields[p_size * 7][1] = (stat_buf.st_mode & S_IRUSR) ? 'r' : '-';
			fields[p_size * 7][2] = (stat_buf.st_mode & S_IWUSR) ? 'w' : '-';
			fields[p_size * 7][3] = (stat_buf.st_mode & S_ISUID) ? 's' : ((stat_buf.st_mode & S_IXUSR) ? 'x' : '-');
			fields[p_size * 7][4] = (stat_buf.st_mode & S_IRGRP) ? 'r' : '-';
			fields[p_size * 7][5] = (stat_buf.st_mode & S_IWGRP) ? 'w' : '-';
			fields[p_size * 7][6] = (stat_buf.st_mode & S_ISGID) ? 's' : ((stat_buf.st_mode & S_IXGRP) ? 'x' : '-');
			fields[p_size * 7][7] = (stat_buf.st_mode & S_IROTH) ? 'r' : '-';
			fields[p_size * 7][8] = (stat_buf.st_mode & S_IWOTH) ? 'w' : '-';
			fields[p_size * 7][9] = (stat_buf.st_mode & S_ISVTX) ? 't' : ((stat_buf.st_mode & S_IXOTH) ? 'x' : '-');
			fields[p_size * 7][10] = '\0';

			// copy other fields into fields array.
			strcpy(fields[p_size * 7 + 1], nlink_buf);
			strcpy(fields[p_size * 7 + 2], pw->pw_name);
			strcpy(fields[p_size * 7 + 3], gr->gr_name);
			strcpy(fields[p_size * 7 + 4], size_buf);
			strcpy(fields[p_size * 7 + 5], mtime);
			strcpy(fields[p_size * 7 + 6], paths[i]);
			if (S_ISDIR(stat_buf.st_mode)) { strcat(fields[p_size * 7 + 6], "/"); } // if current file is directory, append "/" to file name.
			++p_size;
		}
	}
	////////////////////////////// End of fill in "fields" array /////////////////////////////


	/////////////////////////////// print fields ////////////////////////////
	for (int i = 0; i < p_size; ++i)
	{
		if (send_append(buff, fields[i * 7], sockfd, total) < 0) { return -2; }
		if (send_append(buff, " ", sockfd, total) < 0) { return -2; }

		for (int j = 1; j <= 5; ++j)
		{
			if (j == 2 || j == 3)
			{
				if (send_append(buff, fields[i * 7 + j], sockfd, total) < 0) { return -2; }
				if (send_append(buff, " ", sockfd, total) < 0) { return -2; }
				for (int k = 0; k < max_field_len[j - 1] - strlen(fields[i * 7 + j]); ++k)
				{
					if (send_append(buff, " ", sockfd, total) < 0) { return -2; }
				}
			}
			else
			{
				for (int k = 0; k < max_field_len[j - 1] - strlen(fields[i * 7 + j]); ++k)
				{
					if (send_append(buff, " ", sockfd, total) < 0) { return -2; }
				}
				if (send_append(buff, fields[i * 7 + j], sockfd, total) < 0) { return -2; }
				if (send_append(buff, " ", sockfd, total) < 0) { return -2; }
			}
		}

		if (send_append(buff, fields[i * 7 + 6], sockfd, total) < 0) { return -2; }
		if (send_append(buff, "\n", sockfd, total) < 0) { return -2; }
	}
	////////////////////////// End of print fields /////////////////////////

	for (int i = 0; i < size * 7; free(fields[i++]));
	free(fields);
	return 0;
}

int print_ls_dir(char* tmp, char* buff, int opt_a, int opt_l, int sockfd, int* total) // if arg of ls is directory
{
	DIR* dir = opendir(tmp); // open "tmp" directory
	struct dirent* dp = NULL; // directory entry pointer

	if (dir == NULL) // if failed to open "tmp" directory, return.
	{
		return -1;
	}

	///////////////// make a copy of the tmp string ///////////////
	char* pathname = (char*)malloc(strlen(tmp) + 2);
	if (pathname == NULL)
	{
		return -1;
	}
	strcpy(pathname, tmp);
	int orig_nulpos = strlen(pathname);
	if (pathname[orig_nulpos - 1] != '/')
	{
		strcat(pathname, "/");
		++orig_nulpos;
	}
	///////////// End of make a copy of the tmp string /////////////

	/////////// get directory entry names of current opened directory //////////////
	// inserts names ascii sorted in ascending order.
	char** names = NULL; // directory entry names (dynamic array).
	int count = 0;
	while((dp = readdir(dir)) != NULL) // the pointer of the directory entry of the pathname is stored in dp, one at a time.
	{
		// find insert position.
		int pos = 0;
		for (; pos < count; ++pos)
		{
			if (strcmp(names[pos], dp->d_name) > 0)
			{
				break;
			}
		}

		char** tmp_ptr = (char**)realloc(names, (count + 1) * sizeof(char*));
		if (tmp_ptr == NULL) // increase "names" array size by 1.
		{
			closedir(dir); // close opened directory.
			for (int i = 0; i < count; free(names[i++]));
			free(names); free(pathname);
			return -1;
		}
		else
		{
			names = tmp_ptr;
		}
		for (int i = count - 1; i >= pos; --i)
		{
			names[i + 1] = names[i];
		}
		if ((names[pos] = (char*)malloc(strlen(dp->d_name) + 1)) == NULL)
		{
			closedir(dir); // close opened directory.
			for (int i = 0; i < count; free(names[i++]));
			free(names); free(pathname);
			return -1;
		}
		strcpy(names[pos], dp->d_name); // store direcotry/file name of current dirent.
		++count;
	}
	///////////// End of get directory entries of current opened directory //////////////

	//////////////////// print sorted directory/file names. ///////////////////////////
	if (opt_l)
	{
		if (print_ls_detail(names, count, opt_a, &pathname, orig_nulpos, buff, sockfd, total) == -2)
		{
			closedir(dir); // close opened directory.
			free(pathname);
			for (int i = 0; i < count; free(names[i++]));
			free(names);
			return -2;
		}
	}
	else
	{
		for (int i = 0; i < count; ++i)
		{
			if (opt_a || (!opt_a && names[i][0] != '.')) // if option -a is not used, only non-hidden files / folders are printed.
			{
				char* tmp_ptr = (char*)realloc(pathname, orig_nulpos + strlen(names[i]) + 1);
				if(tmp_ptr == NULL)
				{
					closedir(dir); // close opened directory.
					for (int i = 0; i < count; free(names[i++]));
					free(names); free(pathname);
					return -1;
				}
				else
				{
					pathname = tmp_ptr;
				}

				struct stat stat_buf;
				if (lstat(strcat(pathname, names[i]), &stat_buf) == -1)
				{
					closedir(dir); // close opened directory.
					for (int i = 0; i < count; free(names[i++]));
					free(names); free(pathname);
					return -1;
				}
				pathname[orig_nulpos] = '\0';

				if (send_append(buff, names[i], sockfd, total) < 0) { return -2; } // print directory/file name
				if (S_ISDIR(stat_buf.st_mode))
				{
					if (send_append(buff, "/", sockfd, total) < 0) { return -2; } // if it is a directory, append "/"
				}
				if (send_append(buff, "\n", sockfd, total) < 0) { return -2; }
			}
		}
	}
	//////////////////// End of print sorted directory/file names. ////////////////////////

	closedir(dir); // close opened directory.
	free(pathname);
	for (int i = 0; i < count; free(names[i++]));
	free(names);
	return 0;
}

// return dotted decimal ip string, store port num in port parsed from str.
char* convert_str_to_addr(char* str, unsigned int* port)
{
	char* addr = (char*)malloc(25);
	*port = 0; // initialize

	char *tok = strtok(str, ",");
	if (tok != NULL)
	{
		// concatenate ip address fields in addr
		strcpy(addr, tok);
		for (int i = 0; i < 3; ++i)
		{
			if ((tok = strtok(NULL, ",")) != NULL)
			{
				strcat(addr, ".");
				strcat(addr, tok);
			}
		}
		if ((tok = strtok(NULL, ",")) != NULL)
		{
			*port |= (atoi(tok) << 8); // upper 8bit of port num
			if ((tok = strtok(NULL, "")) != NULL)
			{
				*port |= atoi(tok); //lower 8bit of port num
			}
		}
	}
	return addr;
}

int cmd_process(char* rcv_buff, char* snd_buff, int sockfd) // process FTP command
{
	static int mode_ba = 0;
	struct sockaddr_in cli_data_addr; // socket address
	int cli_data_sock; // socket descriptor
	int n;

	char* cmd = strtok(rcv_buff, " ");
	if (!cmd)
	{
		print_str("cmd_process() error."); return -1;
	}

	if (!strcmp(cmd, "PORT"))
	{
		char* tok = strtok(NULL, " ");
		char temp[MAX_BUFF];
		char* host_ip;
		unsigned int port_num;
		strcpy(temp, tok);
		host_ip = convert_str_to_addr(temp, (unsigned int*)&port_num);

		if ((cli_data_sock = socket(PF_INET, SOCK_STREAM, 0)) < 0) // open new socket (data connection)
		{
			strcpy(snd_buff, "550 Failed to access.");
			write(sockfd, snd_buff, strlen(snd_buff));
			print_str(snd_buff); print_str("\n");
			return 0;
		}
		// setup client socket address (data connection)
		memset(&cli_data_addr, 0, sizeof(cli_data_addr));
		cli_data_addr.sin_family = AF_INET;
		cli_data_addr.sin_addr.s_addr = inet_addr(host_ip);
		cli_data_addr.sin_port = htons(port_num);
		free(host_ip);

		if (connect(cli_data_sock, (struct sockaddr*)&cli_data_addr, sizeof(cli_data_addr)) < 0) // connect to client(data connection)
		{
			strcpy(snd_buff, "550 Failed to access.");
			write(sockfd, snd_buff, strlen(snd_buff));
			print_str(snd_buff); print_str("\n");
			return 0;
		}

		strcpy(snd_buff, "220 PORT command performed successfully.");
		write(sockfd, snd_buff, strlen(snd_buff));
		print_str(snd_buff); print_str("\n");

		if ((n = read(sockfd, rcv_buff, MAX_BUFF - 1)) <= 0) // receive whether client can connect to server
		{
			print_str("read() error\n"); return -1;
		}
		rcv_buff[n] = '\0';
		print_str(rcv_buff); print_str("\n");

		cmd = strtok(rcv_buff, " ");
		if (!cmd)
		{
			print_str("cmd_process() error."); return -1;
		}

		if (!strcmp(cmd, "NLST") || !strcmp(cmd, "LIST")) // if command is NLST or LIST
		{
			strcpy(snd_buff, "150 Opening data connection for directory list.");
			write(sockfd, snd_buff, strlen(snd_buff));
			print_str(snd_buff); print_str("\n");

			char* opt = strtok(NULL, "");
			int total = 0;
			memset(snd_buff, 0, MAX_BUFF);

			if (opt == NULL)
			{
				if (!strcmp(cmd, "NLST"))
				{
					if (print_ls_dir("./", snd_buff, 0, 0, cli_data_sock, &total) == -2)
					{
						close(cli_data_sock);
						strcpy(snd_buff, "550 Failed transmission.");
						write(sockfd, snd_buff, strlen(snd_buff));
						print_str(snd_buff); print_str("\n");
						return 0;
					}
				}
				else
				{
					if (print_ls_dir("./", snd_buff, 1, 1, cli_data_sock, &total) == -2)
					{
						close(cli_data_sock);
						strcpy(snd_buff, "550 Failed transmission.");
						write(sockfd, snd_buff, strlen(snd_buff));
						print_str(snd_buff); print_str("\n");
						return 0;
					}
				}
			}
			else if (!strcmp(opt, "-a"))
			{
				if (print_ls_dir("./", snd_buff, 1, 0, cli_data_sock, &total) == -2)
				{
					close(cli_data_sock);
					strcpy(snd_buff, "550 Failed transmission.");
					write(sockfd, snd_buff, strlen(snd_buff));
					print_str(snd_buff); print_str("\n");
					return 0;
				}
			}
			else if (!strcmp(opt, "-l"))
			{
				if (print_ls_dir("./", snd_buff, 0, 1, cli_data_sock, &total) == -2)
				{
					close(cli_data_sock);
					strcpy(snd_buff, "550 Failed transmission.");
					write(sockfd, snd_buff, strlen(snd_buff));
					print_str(snd_buff); print_str("\n");
					return 0;
				}
			}
			else if (!strcmp(opt, "-al"))
			{
				if (print_ls_dir("./", snd_buff, 1, 1, cli_data_sock, &total) == -2)
				{
					close(cli_data_sock);
					strcpy(snd_buff, "550 Failed transmission.");
					write(sockfd, snd_buff, strlen(snd_buff));
					print_str(snd_buff); print_str("\n");
					return 0;
				}
			}
			else
			{
				print_str("cmd_process() error."); return -1;
			}

			if (strlen(snd_buff) > 0)
			{
				total += strlen(snd_buff);
				if (write(cli_data_sock, snd_buff, strlen(snd_buff)) <= 0)
				{
					close(cli_data_sock);
					strcpy(snd_buff, "550 Failed transmission.");
					write(sockfd, snd_buff, strlen(snd_buff));
					print_str(snd_buff); print_str("\n");
					return 0;
				}
			}
			close(cli_data_sock);
			strcpy(snd_buff, "226 Complete transmission");
			write(sockfd, snd_buff, strlen(snd_buff));
			print_str(snd_buff);

			char total_s[25] = {'\0'};
			snprintf(total_s, 25, "%d", total);
			print_str(" | "); print_str(total_s); print_str(" bytes\n");

		}
		else if (!strcmp(cmd, "RETR"))
		{
			char* path = strtok(NULL, " ");
			strcpy(snd_buff, "150 Opening "); strcat(snd_buff, mode_ba ? "ascii" : "binary"); strcat(snd_buff, " mode data connection for "); strcat(snd_buff, path);
			write(sockfd, snd_buff, strlen(snd_buff));
			print_str(snd_buff); print_str("\n");

			int snd_fd = open(path, O_RDONLY);
			if (snd_fd < 0)
			{
				strcpy(snd_buff, "550 Failed transmission.");
				write(sockfd, snd_buff, strlen(snd_buff));
				print_str(snd_buff); print_str("\n");
				close(cli_data_sock);
				return 0;
			}

			int total = 0;
			int finish = 0;
			int cnt = 0;
			char ch;
			while (1)
			{
				int handover = 0; // boolean. used only when ascii mode
				int processed = 0; // boolean. used only when ascii mode
				while (cnt < MAX_BUFF)
				{
					if ((n = read(snd_fd, &ch, 1)) < 0) // read file byte by byte
					{
						strcpy(snd_buff, "550 Failed transmission.");
						write(sockfd, snd_buff, strlen(snd_buff));
						print_str(snd_buff); print_str("\n");
						close(cli_data_sock);
						return 0;
					}
					else if (n == 0)
					{
						finish = 1;
						break;
					}

					if (!cnt)
					{
						snd_buff[0] = ch;
						++cnt;
					}
					else
					{
						if (mode_ba)
						{
							if (!processed && ((snd_buff[cnt - 1] == '\r' && ch == '\n') || (snd_buff[cnt - 1] == '\n' && ch == '\r')))
							{
								snd_buff[cnt - 1] = '\n';
								processed = 1;
							}
							else if (processed && (cnt + 1 >= MAX_BUFF) && (ch == '\n' || ch == '\r'))
							{
								handover = 1;
								break;
							}
							else
							{
								snd_buff[cnt] = ch;
								++cnt;
								processed = 0;
							}
						}
						else
						{
							snd_buff[cnt] = ch;
							++cnt;
						}
					}
				}
				if (finish && !cnt)
				{
					break;
				}

				if (write(cli_data_sock, snd_buff, cnt) <= 0)
				{
					strcpy(snd_buff, "550 Failed transmission.");
					write(sockfd, snd_buff, strlen(snd_buff));
					print_str(snd_buff); print_str("\n");
					close(cli_data_sock);
					return 0;
				}
				total += cnt;

				if (finish)
				{
					break;
				}

				if (mode_ba && handover)
				{
					cnt = 1;
					snd_buff[0] = ch;
				}
				else
				{
					cnt = 0;
				}
			}
			close(snd_fd);
			close(cli_data_sock);
			strcpy(snd_buff, "226 Complete transmission");
			write(sockfd, snd_buff, strlen(snd_buff));
			print_str(snd_buff);

			char total_s[25] = {'\0'};
			snprintf(total_s, 25, "%d", total);
			print_str(" | "); print_str(total_s); print_str(" bytes\n");
		}
		else if (!strcmp(cmd, "STOR"))
		{
			char* path = strtok(NULL, " ");
			strcpy(snd_buff, "150 Opening "); strcat(snd_buff, mode_ba ? "ascii" : "binary"); strcat(snd_buff, " mode data connection for "); strcat(snd_buff, path);
			write(sockfd, snd_buff, strlen(snd_buff));
			print_str(snd_buff); print_str("\n");

			int rcv_fd = open(path, O_RDWR | O_CREAT | O_TRUNC, mode_ba ? ASCII_MODE : BIN_MODE);
			if (rcv_fd < 0)
			{
				strcpy(snd_buff, "550 Failed transmission.");
				write(sockfd, snd_buff, strlen(snd_buff));
				print_str(snd_buff); print_str("\n");
				close(cli_data_sock);
				return 0;
			}

			int total = 0;
			while (1)
			{
				if ((n = read(cli_data_sock, rcv_buff, MAX_BUFF)) < 0) // receive data from data connection
				{
					strcpy(snd_buff, "550 Failed transmission.");
					write(sockfd, snd_buff, strlen(snd_buff));
					print_str(snd_buff); print_str("\n");
					close(cli_data_sock);
					return 0;
				}
				else if (n == 0)
				{
					break;
				}
				total += n;
				write(rcv_fd, rcv_buff, n);
			}
			close(rcv_fd);
			strcpy(snd_buff, "226 Complete transmission");
			write(sockfd, snd_buff, strlen(snd_buff));
			print_str(snd_buff);
			close(cli_data_sock);

			char total_s[25] = {'\0'};
			snprintf(total_s, 25, "%d", total);
			print_str(" | "); print_str(total_s); print_str(" bytes\n");
		}
		else
		{
			print_str("cmd_process() error\n"); return -1;
		}
	}
	else if (!strcmp(cmd, "PWD")) // if command is PWD
	{
		char cwd[4000];
		getcwd(cwd, 4000);
		strcpy(snd_buff, "257 \""); strcat(snd_buff, cwd); strcat(snd_buff, "\" is current directory.");
		write(sockfd, snd_buff, strlen(snd_buff));
		print_str(snd_buff); print_str("\n");
	}
	else if (!strcmp(cmd, "CWD")) // if command is CWD
	{
		char* path = strtok(NULL, " ");
		if (access(path, F_OK) == -1) // check path exists.
		{
			strcpy(snd_buff, "550 "); strcat(snd_buff, path); strcat(snd_buff, ": Can’t find such file or directory.");
		}
		else if (chdir(path) == -1) // if path exist, change working directory to "path".
		{
			strcpy(snd_buff, "550 "); strcat(snd_buff, path); strcat(snd_buff, ": Can’t find such file or directory.");
		}
		else
		{
			strcpy(snd_buff, "250 CWD command succeeds.");
		}
		write(sockfd, snd_buff, strlen(snd_buff));
		print_str(snd_buff); print_str("\n");
	}
	else if (!strcmp(cmd, "CDUP")) // if command is CDUP
	{
		if (access("..", F_OK) == -1) // check path exists.
		{
			strcpy(snd_buff, "550 ..: Can’t find such file or directory.");
		}
		else if (chdir("..") == -1) // if path exist, change working directory to "path".
		{
			strcpy(snd_buff, "550 ..: Can’t find such file or directory.");
		}
		else
		{
			strcpy(snd_buff, "250 CWD command succeeds.");
		}
		write(sockfd, snd_buff, strlen(snd_buff));
		print_str(snd_buff); print_str("\n");
	}
	else if (!strcmp(cmd, "MKD")) // if command is MKD
	{
		int failed = 0;
		char* path = NULL;
		while (path = strtok(NULL, " ")) // make multiple directories.
		{
			if (mkdir(path, 0775) == -1)
			{
				failed = 1;
				break;
			}
		}
		if (failed)
		{
			strcpy(snd_buff, "550 "); strcat(snd_buff, path); strcat(snd_buff, ": Can’t create directory");
		}
		else
		{
			strcpy(snd_buff, "250 MKD command performed successfully.");
		}
		write(sockfd, snd_buff, strlen(snd_buff));
		print_str(snd_buff); print_str("\n");
	}
	else if (!strcmp(cmd, "DELE")) // if command is DELE
	{
		int failed = 0;
		char* path = NULL;
		while (path = strtok(NULL, " ")) // remove multiplie files.
		{
			if (unlink(path) == -1)
			{
				failed = 1;
				break;
			}
		}
		if (failed)
		{
			strcpy(snd_buff, "550 "); strcat(snd_buff, path); strcat(snd_buff, ": Can’t find such file or directory.");
		}
		else
		{
			strcpy(snd_buff, "250 DELE command performed successfully.");
		}
		write(sockfd, snd_buff, strlen(snd_buff));
		print_str(snd_buff); print_str("\n");
	}
	else if (!strcmp(cmd, "RMD")) // if command is RMD
	{
		int failed = 0;
		char* path = NULL;
		while (path = strtok(NULL, " ")) // remove multiple empty directories.
		{
			if (rmdir(path) == -1)
			{
				failed = 1;
				break;
			}
		}
		if (failed)
		{
			strcpy(snd_buff, "550 "); strcat(snd_buff, path); strcat(snd_buff, ": Can’t remove directory.");
		}
		else
		{
			strcpy(snd_buff, "250 RMD command performed successfully.");
		}
		write(sockfd, snd_buff, strlen(snd_buff));
		print_str(snd_buff); print_str("\n");
	}
	else if (!strcmp(cmd, "RNFR")) // if command is RNFR
	{
		char* from = strtok(NULL, " ");

		if (access(from, F_OK) == -1) // check path exists.
		{
			strcpy(snd_buff, "550 "); strcat(snd_buff, from); strcat(snd_buff, ": Can’t find such file or directory.");
			write(sockfd, snd_buff, strlen(snd_buff));
			print_str(snd_buff); print_str("\n");
			return 0;
		}
		strcpy(snd_buff, "350 File exists, ready to rename.");
		write(sockfd, snd_buff, strlen(snd_buff));
		print_str(snd_buff); print_str("\n");

		char rcv_buff2[MAX_BUFF];
		if ((n = read(sockfd, rcv_buff2, MAX_BUFF - 1)) <= 0) // receive whether client can connect to server
		{
			print_str("read() error\n"); return 1;
		}
		rcv_buff2[n] = '\0';
		print_str(rcv_buff2); print_str("\n");

		cmd = strtok(rcv_buff2, " ");

		if (!strcmp(cmd, "RNTO")) // if second command is RNTO
		{
			char* to = strtok(NULL, " ");
			if (rename(from, to) == -1) // rename file/directory "from" to "to".
			{
				strcpy(snd_buff, "550 "); strcat(snd_buff, from); strcat(snd_buff, ": Can’t be renamed.");
			}
			else
			{
				strcpy(snd_buff, "250 RNTO command succeeds.");
			}
			write(sockfd, snd_buff, strlen(snd_buff));
			print_str(snd_buff); print_str("\n");
		}
		else
		{
			print_str("cmd_process() error"); return -1;
		}
	}
	else if (!strcmp(cmd, "QUIT"))
	{
		strcpy(snd_buff, "221 Goodbye.");
		write(sockfd, snd_buff, strlen(snd_buff));
		print_str(snd_buff); print_str("\n");
		return 1;
	}
	else if (!strcmp(cmd, "TYPE"))
	{
		char* arg = strtok(NULL, " ");

		if (!strcmp(arg, "I"))
		{
			mode_ba = 0;
			if (mode_ba == 0) { strcpy(snd_buff, "201 Type set to I."); }
			else { strcpy(snd_buff, "502 Type doesn’t set."); }
		}
		else if (!strcmp(arg, "A"))
		{
			mode_ba = 1;
			if (mode_ba == 1) { strcpy(snd_buff, "201 Type set to A."); }
			else { strcpy(snd_buff, "502 Type doesn’t set."); }
		}
		else
		{
			strcpy(snd_buff, "502 Type doesn’t set.");
		}
		write(sockfd, snd_buff, strlen(snd_buff));
		print_str(snd_buff); print_str("\n");
	}
	else
	{
		print_str("cmd_process() error\n"); return -1;
	}

	return 0;
}


int user_match(char* user, char* passwd) // check received user id and passwd matches with specific info in passwd file.
{
	FILE *fp = NULL;
	struct passwd *pw;

	fp = fopen("passwd", "r"); // open passwd file in read mode
	if (fp == NULL)
	{
		print_str("failed to open passwd!!\n");
		return -1;
	}

	while ((pw = fgetpwent(fp)) != NULL) // get passwd structs from passwd file.
	{
		if ((!passwd && !strcmp(pw->pw_name, user)) ||
			(passwd && !strcmp(pw->pw_name, user) && !strcmp(pw->pw_passwd, passwd)))// successful authentication
		{
			return 0;
		}
	}

	fclose(fp);
	return -1;
}

int log_auth(int sockfd, char* buff) // client authenticator
{
	char user[MAX_BUFF], passwd[MAX_BUFF], snd_buff[MAX_BUFF];
	int n, count = 1;

	while (1)
	{
		// receive user id from client
		if ((n = read(sockfd, user, MAX_BUFF - 1)) <= 0) // receive whether client can connect to server
		{
			print_str("read() error\n"); return -1;
		}
		user[n] = '\0';
		print_str(user); print_str("\n");

		char* tok = strtok(user, " ");
		char* tok2 = strtok(NULL, "");
		if (strcmp(tok, "USER") || !tok2) { return -1; }

		if(user_match(tok2, NULL) >= 0) // successful authentication
		{
			strcpy(snd_buff, "331 Password is required for "); strcat(snd_buff, tok2); strcat(snd_buff, " .");
			write(sockfd, snd_buff, strlen(snd_buff));
			print_str(snd_buff); print_str("\n");
		}
		else
		{
			if (count >= 3)
			{
				strcpy(snd_buff, "530 Failed to log-in.");
				write(sockfd, snd_buff, strlen(snd_buff));
				print_str(snd_buff); print_str("\n");
				return -1;
			}
			else
			{
				strcpy(snd_buff, "430 Invalid username or password.");
				write(sockfd, snd_buff, strlen(snd_buff));
				print_str(snd_buff); print_str("\n");
				count++;
				continue;
			}
		}

		// receive user pw from client
		if ((n = read(sockfd, passwd, MAX_BUFF - 1)) <= 0) // receive whether client can connect to server
		{
			print_str("read() error\n"); return -1;
		}
		passwd[n] = '\0';
		print_str(passwd); print_str("\n");

		tok = strtok(passwd, " ");
		char* tok3 = strtok(NULL, "");
		if (strcmp(tok, "PASS") || !tok3) { return -1; }

		if(user_match(tok2, tok3) >= 0) // successful authentication
		{
			strcpy(snd_buff, "230 User "); strcat(snd_buff, tok2); strcat(snd_buff, " logged in.");
			write(sockfd, snd_buff, strlen(snd_buff));
			print_str(snd_buff); print_str("\n");
			strcpy(tok2, buff);
			break;
		}
		else
		{
			if (count >= 3)
			{
				strcpy(snd_buff, "530 Failed to log-in.");
				write(sockfd, snd_buff, strlen(snd_buff));
				print_str(snd_buff); print_str("\n");
				return -1;
			}
			else
			{
				strcpy(snd_buff, "430 Invalid username or password.");
				write(sockfd, snd_buff, strlen(snd_buff));
				print_str(snd_buff); print_str("\n");
				count++;
				continue;
			}
		}
	}

	return 0;
}
