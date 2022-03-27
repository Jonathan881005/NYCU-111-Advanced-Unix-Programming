#include <iostream>
#include <cstring>
#include <dirent.h>
#include <sys/stat.h>
#include <pwd.h>
#include <fcntl.h>
#include <unistd.h>
#include <fstream>
#include <sstream>
#include <regex>
using namespace std;

#define FORMAT "%s\t\t%s\t\t%s\t\t%s\t\t%s\t\t%s\t\t%s\n"

string cmd_reg = "no", type_reg = "no", fname_reg = "no";
bool is_filter_c = false, is_filter_t = false, is_filter_f = false;

struct pid_info
{
    string pid; // 1
    string cmd; // 1
    string user;// 1

	string fd;		// 2
	string type;	// 2
	string node;	// 2
	string name;	// 2

    string path;// 1
};

// Check if it is a digit
bool is_a_digit(char* str){
	string s(str);
	return s.find_first_not_of("0123456789") == string::npos;
}

// Extract a valid filetype
string get_filetype(struct stat s){
	if(S_ISREG(s.st_mode)) return "REG";
	if(S_ISDIR(s.st_mode)) return "DIR";
	if(S_ISCHR(s.st_mode)) return "CHR";
	if(S_ISFIFO(s.st_mode)) return "FIFO";
	if(S_ISSOCK(s.st_mode)) return "SOCK";
	return "unknown";
}

// Get a valid fd
string get_special_fd(string str){
	if(str == "cwd")
		return "cwd";
	if(str == "root")
		return "rtd";
	if(str == "exe")
		return "txt";
	else
		return str;
}

// Apply filter on output
void check_and_print(struct pid_info info){
	regex cmd_re(".*(" + cmd_reg + ").*");
	regex fname_re(".*(" + fname_reg + ").*");

	if(is_filter_c && !regex_search(info.cmd, cmd_re)){ // cmd filter & not found
		return;
	}
	if(is_filter_t && (info.type != type_reg)){ // type filter & not matched
		return;
	}
	if(is_filter_f && !regex_search(info.name, fname_re)){ // filename filter & not matched
		return;
	}

	printf(FORMAT, info.cmd.c_str(), info.pid.c_str(), info.user.c_str(), 
					info.fd.c_str(), info.type.c_str(), info.node.c_str(), info.name.c_str());

	return;
}

// Read cwd, exe, root  / also fds
void read_link(string type, struct pid_info info){

	string linkpath = info.path + type;
	// printf("%s\n", linkpath.c_str());
	char buf[1024];
	int n = readlink(linkpath.c_str(), buf, sizeof(buf)-1);

	if(n < 0){ // read link error
		info.fd = get_special_fd(type);
		info.type = "unknown";
		info.node = "";
		info.name = linkpath + " (" + strerror(errno) + ")";
	}
	else{ // read link succuess
		info.fd = get_special_fd(type);
		buf[n] = '\0';
		struct stat s;
		stat(linkpath.c_str(), &s);
		info.type = get_filetype(s);
		info.node = to_string(s.st_ino);
        info.name = buf;
		
		// from read_fd
		if(strcmp(info.path.substr(info.path.length()-4, info.path.length()).c_str(), "/fd/") == 0){ 
			// Handle fd, type(deleted), name
			lstat(linkpath.c_str(), &s);
			if((s.st_mode & S_IREAD) && (s.st_mode & S_IWRITE))
				info.fd = type + "u";
			else if(s.st_mode & S_IRUSR)
				info.fd = type + "r";
			else if(s.st_mode & S_IWUSR)
				info.fd = type + "w";

			string tmp;
			tmp.assign(buf);
			if(strstr(buf, "deleted") != NULL){ // remove " (deleted)"
				info.name = tmp.substr(0, tmp.length()-10);
			}
			else{
				info.name = buf;
			}
			
		}
	}

    check_and_print(info);
}

// Read all unique mapped file
void parse_map(struct pid_info info){
	string map_path = info.path + "/maps";
	ifstream mapfile(map_path);
    stringstream ss;
    string offset;
	info.fd = "mem";
	info.type = "REG";
    string str, dev;
	bool afterheap = false; // set if pass through heap
    while (getline(mapfile, str))
    {
        ss << str;
        ss >> str >> str >> offset >> dev >> info.node >> info.name;
        ss.str("");
        ss.clear();

		if(!afterheap){ 
			if(!strstr(info.name.c_str(), "[heap]")){ // if haven't reach heap (exe), continue
				continue;
			}
			else{
				afterheap = true; // heap -> start dump message
				continue;
			}
		}

		// inode = 0, non-first memory block -> skip
        if (stoi(info.node.c_str()) == 0 || offset != "00000000"){
            continue;
		}
		if (dev == "00:00"){
			continue;
		}


        if(strstr(info.node.c_str(), "deleted") != NULL) // deleted! -> change fd, type
        {
            info.fd = "del";
            info.type = "unknown";
        }
	
		check_and_print(info);

    }
    mapfile.close();

}

// Read all fds
void read_fd(struct pid_info info)
{
    string initial_path = info.path;
	info.path += "fd/";
    DIR *dp = opendir(info.path.c_str());
    if(!dp){ // open error (permission denied)
		info.fd = "NOFD";
		info.type = "";
		info.node = "";
        info.name = initial_path + "/fd (" + strerror(errno) + ")";
		check_and_print(info);
    }
	else{
    	struct dirent* dirp;
		while((dirp = readdir(dp))){
			if(!strcmp(dirp->d_name, ".") || !strcmp(dirp->d_name, ".."))
				continue;
			read_link(dirp->d_name, info);
		}
		closedir(dp);
	}
}

void open_dirp(char* pid){
	// Read pid_infos, error -> skip
	struct pid_info info;

	// Get pid & path
	info.pid.assign(pid);
	info.path = "/proc/" + info.pid + "/";

    // Get command line
	string path_cmd = info.path + "comm";
	int fd = open(path_cmd.c_str(), O_RDONLY);
	if (fd < 0){
		return;
	}
	char buf[1024];
	int n = read(fd, buf, sizeof(buf));
	close(fd);
	if(n < 0){
		return;
	}
	buf[n-1] = '\0';
	info.cmd = buf;

	// Get username
	struct stat pid_stat;
    struct passwd *pwd;
    if(!stat(info.path.c_str(), &pid_stat)){
        pwd = getpwuid(pid_stat.st_uid);
		if(pwd != NULL){ 
			info.user = pwd->pw_name;
		}
		else{
			return;
		}
    }

	read_link("cwd", info);
	read_link("root", info);
	read_link("exe", info);
	parse_map(info);
	read_fd(info);

	// printf("%s %s %s\n", info.cmd.c_str(), info.pid.c_str(), info.user.c_str());
}

int main(int argc, char *argv[]){
	
	// Handle option filter
	for(int i = 1; i < argc; i+=2){
		if(strcmp(argv[i], "-c") == 0){
			is_filter_c = true;
			cmd_reg = argv[i+1];
			continue;
		}
		if(strcmp(argv[i], "-t") == 0){
			// Invalid types -> error and terminate
			if(strcmp(argv[i+1], "REG") && strcmp(argv[i+1], "CHR") && strcmp(argv[i+1], "DIR") && strcmp(argv[i+1], "FIFO") && strcmp(argv[i+1], "SOCK") && strcmp(argv[i+1], "unknown")){
					printf("Invalid TYPE option.\n");
					return 0;
			}
			is_filter_t = true;
			type_reg = argv[i+1];
			continue;
		}
		if(strcmp(argv[i], "-f") == 0){
			is_filter_f = true;
			fname_reg = argv[i+1];
			continue;
		}
		printf("Invalid option filter.\n");
		return 0; // None of the option filter matched -> Invalid
	}

	// Print first line
	printf(FORMAT, "COMMAND", "PID", "USER", "FD", "TYPE", "NODE", "NAME");

	// Traverse directory
  	DIR *dp = opendir("/proc");
    struct dirent* dirp;
    while((dirp = readdir(dp))){
        if(!strcmp(dirp->d_name, ".") || !strcmp(dirp->d_name, "..") || !is_a_digit(dirp->d_name))
            continue;

        open_dirp(dirp->d_name);   
    }
    closedir(dp);
}
