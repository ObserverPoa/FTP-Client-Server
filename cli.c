#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <sys/wait.h>
#include <signal.h>
#include <string.h>
#include <time.h>
#include <fcntl.h>

#define MAX_BUFF 4096
#define ASCII_MODE (S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH)
#define BIN_MODE (S_IXUSR | S_IXGRP | S_IXOTH)

ssize_t print_str(char* str);
ssize_t read_line(char* buff);
int conv_cmd(char* buff, char* cmd_buff);
int log_in(int sockfd);

int main(int argc, char **argv)
{
	if(argc < 3) // if both ip and port number not entered
	{
		print_str("server ip and port number are required!!\n");
		return 1;
	}

	char stdin_buff[MAX_BUFF], snd_buff1[MAX_BUFF], snd_buff2[MAX_BUFF], rcv_buff[MAX_BUFF]; // buffers
	char* hostport;
	struct sockaddr_in serv_addr, tmp_addr, data_addr; // socket address
	int serv_sock, tmp_sock, data_sock; // socket descriptor
	int snd_fd, rcv_fd;
	int mode_ba = 0; // 0: binary, 1: ascii
	int n;

	srand(time(NULL));

	if ((serv_sock = socket(AF_INET, SOCK_STREAM, 0)) < 0) // open new socket(server)
	{
		print_str("failed to create socket!!\n");
		return 1;
	}

	// setup server socket address
	memset(&serv_addr, 0, sizeof(serv_addr));
	serv_addr.sin_family = AF_INET;
	serv_addr.sin_addr.s_addr = inet_addr(argv[1]);
	serv_addr.sin_port = htons(atoi(argv[2]));

	if (connect(serv_sock, (struct sockaddr*)&serv_addr, sizeof(serv_addr)) < 0) // connect to server
	{
		print_str("failed to connect server!!\n");
		return 1;
	}
	print_str("Connected to sswlab.kw.ac.kr.\n");

	if (log_in(serv_sock)) { return 1; }

	while (1)
	{
		memset(stdin_buff, 0, MAX_BUFF);
		memset(snd_buff1, 0, MAX_BUFF);
		memset(snd_buff2, 0, MAX_BUFF);
		memset(rcv_buff, 0, MAX_BUFF);

		print_str("ftp> ");
		if (read_line(stdin_buff) < 0) // read user command
		{
			print_str("read() error!!\n");
			break;
		}

		int ret = conv_cmd(stdin_buff, snd_buff1);
		if ((ret < 0) // convert user command
			|| ((ret == 1) && ((rcv_fd = open(snd_buff1 + 5, O_RDWR | O_CREAT | O_TRUNC, mode_ba ? ASCII_MODE : BIN_MODE)) < 0))
			|| ((ret == 2) && ((snd_fd = open(snd_buff1 + 5, O_RDONLY)) < 0)))
		{
			continue;
		}

		if (ret >= 1 && ret <= 3)
		{
			if((tmp_sock = socket(AF_INET, SOCK_STREAM, 0)) < 0) // open new socket(data connection)
			{
				print_str("failed to create socket!!\n"); return 1;
			}
			// setup data connection socket address
			memset(&tmp_addr, 0, sizeof(tmp_addr));
			tmp_addr.sin_family = AF_INET;
			tmp_addr.sin_addr.s_addr = inet_addr("127.0.0.1");

			int bind_success = 0;
			for (short i = 10001; i <= 60000; ++i)
			{
				tmp_addr.sin_port = htons(i);
				if (bind(tmp_sock, (struct sockaddr*)&tmp_addr, sizeof(tmp_addr)) >= 0) // bind data connection socket with address
				{
					bind_success = 1;
					break;
				}
			}
			if (!bind_success)
			{
				print_str("failed to bind local address!!\n"); return 1;
			}
			listen(tmp_sock, 5);

			unsigned char* ip = (unsigned char*)&tmp_addr.sin_addr.s_addr;
			unsigned char* pt = (unsigned char*)&tmp_addr.sin_port;
			snprintf(snd_buff2, MAX_BUFF, "PORT %d,%d,%d,%d,%d,%d", ip[0], ip[1], ip[2], ip[3], pt[0], pt[1]);
			write(serv_sock, snd_buff2, strlen(snd_buff2)); // send data connection ip, port to control connection

			int len = sizeof(data_addr);
			data_sock = accept(tmp_sock, (struct sockaddr*)&data_addr, &len); // accpt data connection from server

			if ((n = read(serv_sock, rcv_buff, MAX_BUFF - 1)) <= 0) // receive ack of PORT from control connection
			{
				print_str("read() error\n"); return 1;
			}
			rcv_buff[n] = '\0';
			print_str(rcv_buff); print_str("\n");
		}
		else if (ret == 5)
		{
			snd_buff1[strchr(snd_buff1, '\n') - snd_buff1] = '\0';
		}

		write(serv_sock, snd_buff1, strlen(snd_buff1)); // send FTP command to server
		if ((n = read(serv_sock, rcv_buff, MAX_BUFF - 1)) <= 0) // receive common response from control connection
		{
			print_str("read() error\n"); return 1;
		}
		rcv_buff[n] = '\0';
		print_str(rcv_buff); print_str("\n");

		if (ret == 1 || ret == 3) // get, ls , dir
		{
			int total = 0;
			while (1)
			{
				if ((n = read(data_sock, rcv_buff, MAX_BUFF)) < 0) // receive data from data connection
				{
					print_str("read() error\n"); return 1;
				}
				else if (n == 0)
				{
					break;
				}
				total += n;
				write((ret == 1) ? rcv_fd : STDOUT_FILENO, rcv_buff, n);
			}
			if (ret == 1) { close(rcv_fd); }

			if ((n = read(serv_sock, rcv_buff, MAX_BUFF - 1)) <= 0) // receive message from control connection
			{
				print_str("read() error\n"); return 1;
			}
			rcv_buff[n] = '\0';
			print_str(rcv_buff); print_str("\n");
			close(data_sock);
			close(tmp_sock);

			char total_s[25] = {'\0'};
			snprintf(total_s, 25, "%d", total);
			print_str("OK. "); print_str(total_s); print_str(" bytes is received.\n");
		}
		else if (ret == 2) // put
		{
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
						print_str("read() error\n"); return 1;
					}
					else if (n == 0)
					{
						finish = 1;
						break;
					}

					if (!cnt)
					{
						snd_buff1[0] = ch;
						++cnt;
					}
					else
					{
						if (mode_ba)
						{
							if (!processed && ((snd_buff1[cnt - 1] == '\r' && ch == '\n') || (snd_buff1[cnt - 1] == '\n' && ch == '\r')))
							{
								snd_buff1[cnt - 1] = '\n';
								processed = 1;
							}
							else if (processed && (cnt + 1 >= MAX_BUFF) && (ch == '\n' || ch == '\r'))
							{
								handover = 1;
								break;
							}
							else
							{
								snd_buff1[cnt] = ch;
								++cnt;
								processed = 0;
							}
						}
						else
						{
							snd_buff1[cnt] = ch;
							++cnt;
						}
					}
				}
				if (finish && !cnt)
				{
					break;
				}

				write(data_sock, snd_buff1, cnt);
				total += cnt;

				if (finish)
				{
					break;
				}

				if (mode_ba && handover)
				{
					cnt = 1;
					snd_buff1[0] = ch;
				}
				else
				{
					cnt = 0;
				}
			}
			close(snd_fd);
			close(data_sock);
			if ((n = read(serv_sock, rcv_buff, MAX_BUFF - 1)) <= 0) // receive message from control connection
			{
				print_str("read() error\n"); return 1;
			}
			rcv_buff[n] = '\0';
			print_str(rcv_buff); print_str("\n");
			close(tmp_sock);

			char total_s[25] = {'\0'};
			snprintf(total_s, 25, "%d", total);
			print_str("OK. "); print_str(total_s); print_str(" bytes is sent.\n");
		}
		else if (ret == 4) // type, bin, ascii
		{
			char* tok = strtok(rcv_buff, " ");
			if (!tok) { print_str("unexpected srv reply\n"); return 1; }
			if (!strcmp(tok, "201"))
			{
				mode_ba = (snd_buff1[5] == 'I') ? 0 : 1;
			}
		}
		else if (ret == 5) // rename
		{
			char* second = snd_buff1 + strlen(snd_buff1) + 1;
			write(serv_sock, second, strlen(second)); // send FTP command to server
			if ((n = read(serv_sock, rcv_buff, MAX_BUFF - 1)) <= 0) // receive common response from control connection
			{
				print_str("read() error\n"); return 1;
			}
			rcv_buff[n] = '\0';
			print_str(rcv_buff); print_str("\n");
		}
		else if (ret == 6) // quit
		{
			break;
		}
	}

	return 0;
}

ssize_t print_str(char* str) // print string to stdout
{
	ssize_t res = 0;
	if (str)
	{
		res = write(STDOUT_FILENO, str, strlen(str));
	}
	return res;
}

ssize_t read_line(char* buff) // read line from stdin
{
	ssize_t res = read(STDIN_FILENO, buff, MAX_BUFF);
	if (res >= 0)
	{
		if (buff[res - 1] == '\n' || res == MAX_BUFF)
		{
			buff[res - 1] = '\0';
		}
		else
		{
			buff[res] = '\0';
		}
	}
	return res;
}

int conv_cmd(char* buff, char* cmd_buff) // convert user command to FTP command
{
	char* cmd = strtok(buff, " ");
	if (!cmd)
	{
		return -1;
	}

	if (!strcmp(cmd, "ls"))
	{
		char* opt = strtok(NULL, "");
		if (!opt || !strcmp(opt, "-a") || !strcmp(opt, "-l") || !strcmp(opt, "-al"))
		{
			strcat(cmd_buff, "NLST "); // converted command name.
			if (opt)
			{
				strcat(cmd_buff, opt);
			}
		}
		else
		{
			print_str("ls: wrong option.\n"); return -1;
		}
		return 3;
	}
	else if (!strcmp(cmd, "dir"))
	{
		char* tok = strtok(NULL, "");
		if (!tok)
		{
			strcat(cmd_buff, "LIST");
		}
		else
		{
			print_str("dir: never accept argument.\n"); return -1;
		}
		return 3;
	}
	else if (!strcmp(cmd, "pwd"))
	{
		strcat(cmd_buff, "PWD");
	}
	else if (!strcmp(cmd, "cd"))
	{
		char* arg1 = strtok(NULL, " ");
		char* arg2 = strtok(NULL, "");
		if (!arg1 || arg2)
		{
			print_str("cd: 1 argument is required.\n"); return -1;
		}

		if (!strcmp(arg1, ".."))
		{
			strcat(cmd_buff, "CDUP");
		}
		else
		{
			strcat(cmd_buff, "CWD ");
			if (strlen(arg1) <= MAX_BUFF - 5)
			{
				strcat(cmd_buff, arg1);
			}
			else
			{
				print_str("cd: argument is too long.\n"); return -1;
			}
		}
	}
	else if (!strcmp(cmd, "mkdir") || !strcmp(cmd, "delete") || !strcmp(cmd, "rmdir"))
	{
		char* arg = strtok(NULL, " ");
		if (!arg)
		{
			print_str(cmd); print_str(": at least 1 argument is required.\n");
			return -1;
		}

		if (!strcmp(cmd, "mkdir")) { strcat(cmd_buff, "MKD"); }
		else if (!strcmp(cmd, "delete")) { strcat(cmd_buff, "DELE"); }
		else { strcat(cmd_buff, "RMD"); }

		do
		{
			if (strlen(arg) + 1 <= MAX_BUFF - strlen(cmd_buff) - 1)
			{
				strcat(cmd_buff, " ");
				strcat(cmd_buff, arg);
			}
			else
			{
				print_str(cmd); print_str(": argument is too long.\n");
				return -1;
			}
		} while (arg = strtok(NULL, " "));
	}
	else if (!strcmp(cmd, "rename"))
	{
		char* arg1 = strtok(NULL, " ");
		char* arg2 = strtok(NULL, " ");
		char* arg3 = strtok(NULL, "");
		if (!arg1 || !arg2 || arg3)
		{
			print_str("rename: only 2 argument is required.\n"); return -1;
		}

		if (strlen(arg1) + strlen(arg2) + 12 <= MAX_BUFF)
		{
			strcat(cmd_buff, "RNFR "); // converted command name.
			strcat(cmd_buff, arg1); // arg1
			strcat(cmd_buff, "\nRNTO "); // converted command name.
			strcat(cmd_buff, arg2); // arg2
		}
		else
		{
			print_str("rename: argument is too long.\n"); return -1;
		}
		return 5;
	}
	else if (!strcmp(cmd, "quit"))
	{
		strcat(cmd_buff, "QUIT");
		return 6;
	}
	else if (!strcmp(cmd, "get") || !strcmp(cmd, "put"))
	{
		int ret;
		char* arg1 = strtok(NULL, " ");
		char* arg2 = strtok(NULL, "");
		if (!arg1 || arg2)
		{
			print_str(cmd); print_str(": 1 argument is required.\n");
			return -1;
		}

		if (!strcmp(cmd, "get"))
		{
			ret = 1;
			strcat(cmd_buff, "RETR ");
		}
		else
		{
			ret = 2;
			strcat(cmd_buff, "STOR ");
		}

		if (strlen(arg1) <= MAX_BUFF - 6)
		{
			strcat(cmd_buff, arg1);
		}
		else
		{
			print_str(cmd); print_str(": argument is too long.\n");
			return -1;
		}

		return ret; // inform that cmd is RETR or STOR.
	}
	else if (!strcmp(cmd, "type"))
	{
		char* arg = strtok(NULL, "");
		if (!strcmp(arg, "binary"))
		{
			strcat(cmd_buff, "TYPE I");
		}
		else if (!strcmp(arg, "ascii"))
		{
			strcat(cmd_buff, "TYPE A");
		}
		else
		{
			print_str("type: wrong argument.\n"); return -1;
		}
		return 4;
	}
	else if (!strcmp(cmd, "bin"))
	{
		strcat(cmd_buff, "TYPE I");
		return 4;
	}
	else if (!strcmp(cmd, "ascii"))
	{
		strcat(cmd_buff, "TYPE A");
		return 4;
	}
	else // unknown command
	{
		print_str("Unknown command!.\n"); return -1;
	}

	return 0;
}

int log_in(int sockfd) // login to server
{
	int n;
	char user[MAX_BUFF], buf[MAX_BUFF], *passwd;
	char zero = 0;

	if ((n = read(sockfd, buf, MAX_BUFF - 1)) <= 0) // receive whether client can connect to server
	{
		print_str("read() error\n"); return -1;
	}
	buf[n] = '\0';
	print_str(buf); print_str("\n");

	char* tok = strtok(buf, " ");
	if (!strcmp(tok, "431")) // rejected by server
	{
		return 1;
	}

	for(;;) // try login to server up to 3 times
	{
		memset(user, 0, MAX_BUFF);
		memset(buf, 0, MAX_BUFF);
		// read id from stdin
		print_str("Name : ");
		read_line(user);
		if (strlen(user) > MAX_BUFF - 6)
		{
			print_str("user name is too long.\n"); return -1;
		}

		// send id to server
		strcat(buf, "USER ");
		strcat(buf, user);
		write(sockfd, buf, strlen(buf));

		if ((n = read(sockfd, buf, MAX_BUFF - 1)) <= 0) // receive whether client can connect to server
		{
			print_str("read() error\n"); return -1;
		}
		buf[n] = '\0';
		print_str(buf); print_str("\n");

		char* tok = strtok(buf, " ");
		if (!strcmp(tok, "430")) // rejected by server
		{
			continue;
		}
		else if (!strcmp(tok, "530"))
		{
			return 1;
		}

		// read pw from stdin
		passwd = getpass("Password : ");
		if (strlen(passwd) > MAX_BUFF - 6)
		{
			print_str("password is too long.\n"); return -1;
		}

		// send pw to server
		memset(buf, 0, MAX_BUFF);
		strcat(buf, "PASS ");
		strcat(buf, passwd);
		write(sockfd, buf, strlen(buf));

		if ((n = read(sockfd, buf, MAX_BUFF - 1)) <= 0) // receive whether client can connect to server
		{
			print_str("read() error\n"); return -1;
		}
		buf[n] = '\0';
		print_str(buf); print_str("\n");

		tok = strtok(buf, " ");
		if (!strcmp(tok, "230")) // accepted by server
		{
			break;
		}
		else if (!strcmp(tok, "530"))
		{
			return 1;
		}
	}

	return 0;
}
