#include <algorithm>
#include <iostream>
#include <chrono>
#include <sys/mman.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <cstring>
#include <re2/re2.h>
#include <set>
#include <experimental/filesystem>

#define DELIM "DILDO"

namespace fs = std::experimental::filesystem;

std::set<re2::StringPiece> res_set;
void handleError(const char* error);
void do_search(const char* fileName, const char* regex);
char* mapFile(const char* fileName, size_t& length);
std::string delim(DELIM);

int main(int argc, const char *argv[])
{
    if(argc != 3)
    {
        printf("Usage: %s [service directory] \"regex\"\n", argv[0]);
        printf("Example: %s /mnt/pcap/service1/ \"fl.g\"\n", argv[0]);
        exit(1);
    }

    for(auto& p: fs::directory_iterator(argv[1]))
    {
        const char *file = p.path().c_str();
        do_search(file, argv[2]);
    }
    for(auto &s : res_set )
    {
        std::cout << s << delim;
    }
}

void handleError(const char* error) {
    perror(error);
    exit(255);
}

void do_search(const char* fileName, const char* regex)
{
	size_t length;
	char* address = mapFile(fileName, length);

    std::string re_str = "(" + std::string(regex) + ")";
    RE2 re(re_str);
    re2::StringPiece word;
    re2::StringPiece input(address, length);
        
    while(RE2::FindAndConsume(&input, re, &word))
    {
        res_set.insert(word);
    }
}

char* mapFile(const char* fileName, size_t& length)
{
    int fd = open(fileName, O_RDONLY);
    if (fd == -1){
        handleError("Failed to open file");
    }

    struct stat fileStat;

    if (fstat(fd, &fileStat) == -1){
        handleError("Failed to call fstat");
    }

    length = fileStat.st_size;

    char* address = (char*)mmap(NULL, length, PROT_READ, MAP_PRIVATE, fd, 0u);

    if (address == MAP_FAILED){
        handleError("Map failed");
    }

    madvise(address, fileStat.st_size, MADV_SEQUENTIAL|MADV_WILLNEED);

    return address;
}

