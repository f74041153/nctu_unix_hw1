#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <iostream>
#include <string>
#include <vector>
#include <getopt.h>
#include <fstream>
#include <sstream>
#include <dirent.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <map>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <regex>

using namespace std;

enum Protocol{ NO, TCP, UDP };

struct Input{
	bool has_proto;
	int proto;
	bool has_fstr;
	string fstr;
};

struct NetContent{
	string proto;
	string local_addr;
	string foreign_addr;
	string pid_prog_and_arg;
};

map< string, vector<string> > inode2pid;

void parse_arg(int argc, char* argv[],struct Input& input){
	const char* optstring = "tu";
	int c,cnt = 0;
	struct option opts[] = {
		{"tcp",0,NULL,'t'},
		{"udp",0,NULL,'u'}
	};

	while((c = getopt_long(argc,argv,optstring,opts,NULL)) != -1){
		cnt ++;
		switch(c){
			case 't':
				input.has_proto = true;
				input.proto = TCP;
				break;
			case 'u':
				input.has_proto = true;
				input.proto = UDP;
				break;
			default:
				exit(EXIT_FAILURE);
		}
	}

	if(argc-1 > cnt){
		input.has_fstr = true;
		input.fstr = argv[argc-1];
	}
}

void traverse_fd(){
	struct dirent *entry = NULL;
	DIR *proc_dp = NULL;	
	string proc_dir = "/proc";
	proc_dp = opendir(&proc_dir[0]);
	if (proc_dp != NULL) {
		while ((entry = readdir(proc_dp))!=NULL){
			if(isdigit(entry->d_name[0])){
				string fd_dir = proc_dir + "/" + entry->d_name + "/fd";
				string pid = entry->d_name;
				DIR * fd_dp = opendir(&fd_dir[0]);
				if(fd_dp != NULL){
					while((entry = readdir(fd_dp))!=NULL){
						if(isdigit(entry->d_name[0])){
							char buf[256];
					    	string path = fd_dir + "/"  + entry->d_name;	
							int size = readlink(&path[0],buf,sizeof(buf));
							buf[size] = '\0';
							stringstream ss(buf);
							string str,inode;
							getline(ss,str,':');
							if(!strcmp(&str[0],"socket")){
								ss >> str;
								inode = str.substr(1,str.size()-2);
								inode2pid[inode].push_back(pid);
							}else if(!strcmp(&str[0],"[0000]")){
								ss >> inode;
								inode2pid[inode].push_back(pid);
							}
						}
					}
					closedir(fd_dp);
				}
			}
		}
		closedir(proc_dp);
	}
}

void fetch_cmd(string inode, struct NetContent& netcontent){
	
	if(inode2pid[inode].empty()){
		netcontent.pid_prog_and_arg = "-";
		return;
	}	
	string pid = inode2pid[inode][0];
	string path = "/proc/" + pid +"/cmdline";
	string cmd, arg;
	ifstream ifs(&path[0]);
	if(!ifs){
		perror(&path[0]);
	}else{
		getline(ifs,cmd);
		stringstream ss1(cmd);
		getline(ss1,cmd,'\0');
		stringstream ss2(cmd);
		while(getline(ss2,cmd,'/'));
		netcontent.pid_prog_and_arg = pid + "/" + cmd;
		while(getline(ss1,arg,'\0')){
			netcontent.pid_prog_and_arg += " " + arg;
		}
		ifs.close();
	}
}

void show_result(struct NetContent netcontent, struct Input input){
	char output[1024];
	sprintf(output,"%-10s%-25s%-25s%s", netcontent.proto.c_str(), netcontent.local_addr.c_str(), \
					netcontent.foreign_addr.c_str(), netcontent.pid_prog_and_arg.c_str());
	if(!input.has_fstr || (input.has_fstr && regex_search(output,regex(input.fstr)))){
		cout << output << endl;		
	}
}

void list_connection(string proto_u, string proto_l, struct Input input){
	cout << "List of " + proto_u + " connections:" << endl;
	printf("%-10s%-25s%-25s%s\n","Proto","Local Address","Foreign Address","PID/Program name and arguments");
	for(int v=0; v<2; v++){
		string proto = proto_l + ((v==1)?"6":"");
		string netpath = "/proc/net/"+ proto;
		ifstream ifs(&netpath[0]);
		if(!ifs){
				perror(&netpath[0]);
		}else{
			string netline;
			getline(ifs,netline);
			while(getline(ifs,netline)){
				struct NetContent netcontent;
				netcontent.proto = proto;
				stringstream ss1(netline);
				string str1;
				ss1 >> str1;
				
				for(int local=1; local>=0; local--){
					ss1 >> str1;
					// ip
					stringstream ss2(str1);
					getline(ss2,str1,':');
					if(!v){
						struct in_addr in;
						in.s_addr = strtoul(&str1[0],NULL,16);
						char _ip[64];
						inet_ntop(AF_INET, (void*)&in, _ip, INET_ADDRSTRLEN);
						if(local){
							netcontent.local_addr = _ip;
						}else{
							netcontent.foreign_addr = _ip;
						}
					}else{
						struct in6_addr in6;
						sscanf(&str1[0], "%08X%08X%08X%08X",&in6.s6_addr32[0], &in6.s6_addr32[1], &in6.s6_addr32[2], &in6.s6_addr32[3]);
						char _ip6[256];
						inet_ntop(AF_INET6, &in6, _ip6, INET6_ADDRSTRLEN);
						if(local){
							netcontent.local_addr = _ip6;
						}else{
							netcontent.foreign_addr = _ip6;	
						}			
					}	
					// port
					getline(ss2,str1,':');
					uint16_t port = (unsigned short)strtoul(&str1[0],NULL,16);
					if(local){
						netcontent.local_addr += ":";
						netcontent.local_addr += port?to_string(port):"*";
					}else{
						netcontent.foreign_addr += ":";
						netcontent.foreign_addr += port?to_string(port):"*";
					}
				}
				string inode;
				for(int i=0;i<7;i++) ss1 >> inode;
				fetch_cmd(inode,netcontent);
				show_result(netcontent,input);
			}
			ifs.close();
		}
	}	
}

int main(int argc, char* argv[]){
	
	struct Input input;
	input.has_proto = false;
	input.has_fstr = false;
	
	parse_arg(argc,argv,input);

	traverse_fd();

	if(!input.has_proto || input.proto == TCP){
		list_connection("TCP","tcp",input);
	}

	if(!input.has_proto) printf("\n");

	if(!input.has_proto || input.proto == UDP){
		list_connection("UDP","udp",input);
	}

	return 0;
}

