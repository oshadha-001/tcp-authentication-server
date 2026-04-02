
#include <stdio.h>
#include <stdlib.h>
#include <ctype.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <signal.h>
#include <time.h>
#include <openssl/sha.h>
#include <sys/stat.h>

#define PORT 50920
#define MAX 4096
#define SID "1039"

typedef struct {
    char token[64];
    time_t last_active;
    int logged_in;
    char username[50];
} session_t;

void handle_sigchld(int sig){
    while(waitpid(-1,NULL,WNOHANG)>0);
}

void log_event(char *ip, int port, char *user, char *cmd){
    FILE *f = fopen("server_IT24103920.log","a");
    time_t now = time(NULL);
    fprintf(f,"%ld | %s:%d | %s | %s\n",now,ip,port,user,cmd);
    fclose(f);
}

void hash_password(char *pass, char *out){
    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256((unsigned char*)pass, strlen(pass), hash);
    for(int i=0;i<SHA256_DIGEST_LENGTH;i++)
        sprintf(out+(i*2),"%02x",hash[i]);
}

void generate_token(char *token){
    sprintf(token,"%ld%d",time(NULL),rand());
}

int validate_username(char *u){
    for(int i=0;u[i];i++){
        if(!isalnum(u[i])) return 0;
    }
    return 1;
}

void handle_client(int sock, struct sockaddr_in addr){
    char buffer[MAX];
    char response[MAX];
    int len;

    session_t session={0};
    int fail_count=0;

    char ip[INET_ADDRSTRLEN];
    inet_ntop(AF_INET,&addr.sin_addr,ip,sizeof(ip));
    int port = ntohs(addr.sin_port);

    while(1){
        memset(buffer,0,MAX);
        int r=recv(sock,buffer,MAX,0);
        if(r<=0) break;

        if(sscanf(buffer,"LEN:%d",&len)!=1 || len>4096){
            sprintf(response,"ERR 400 SID:%s Invalid length\n",SID);
            send(sock,response,strlen(response),0);
            continue;
        }

        char *payload=strchr(buffer,'\n');
        if(!payload) continue;
        payload++;

        if(session.logged_in && difftime(time(NULL),session.last_active)>300){
            session.logged_in=0;
        }

        if(strncmp(payload,"REGISTER",8)==0){
            char user[50],pass[50],hash[100];
            sscanf(payload,"REGISTER %s %s",user,pass);

            if(!validate_username(user)){
                sprintf(response,"ERR 400 SID:%s Invalid username\n",SID);
            } else {
                hash_password(pass,hash);
                mkdir("users",0777);
                char path[200];
                sprintf(path,"users/%s.txt",user);
                FILE *f=fopen(path,"w");
                fprintf(f,"%s",hash);
                fclose(f);
                sprintf(response,"OK 200 SID:%s Registered\n",SID);
            }
        }

        else if(strncmp(payload,"LOGIN",5)==0){
            if(fail_count>=3){
                sprintf(response,"ERR 403 SID:%s Locked\n",SID);
            } else {
                char user[50],pass[50],hash[100],stored[100];
                sscanf(payload,"LOGIN %s %s",user,pass);
                hash_password(pass,hash);

                char path[200];
                sprintf(path,"users/%s.txt",user);
                FILE *f=fopen(path,"r");

                if(!f){
                    sprintf(response,"ERR 401 SID:%s No user\n",SID);
                } else {
                    fscanf(f,"%s",stored);
                    fclose(f);
                    if(strcmp(hash,stored)==0){
                        session.logged_in=1;
                        strcpy(session.username,user);
                        generate_token(session.token);
                        session.last_active=time(NULL);
                        fail_count=0;
                        sprintf(response,"OK 200 SID:%s TOKEN:%s\n",SID,session.token);
                    } else {
                        fail_count++;
                        sprintf(response,"ERR 403 SID:%s Wrong\n",SID);
                    }
                }
            }
        }

        else if(strncmp(payload,"LOGOUT",6)==0){
            session.logged_in=0;
            sprintf(response,"OK 200 SID:%s Logout\n",SID);
        }

        else{
            sprintf(response,"ERR 404 SID:%s Unknown\n",SID);
        }

        send(sock,response,strlen(response),0);
        log_event(ip,port,session.username,payload);
    }

    close(sock);
    exit(0);
}

int main(){
    int server_fd,client_sock;
    struct sockaddr_in server,client;
    socklen_t c=sizeof(client);

    signal(SIGCHLD,handle_sigchld);

    server_fd=socket(AF_INET,SOCK_STREAM,0);

    server.sin_family=AF_INET;
    server.sin_addr.s_addr=INADDR_ANY;
    server.sin_port=htons(PORT);

    bind(server_fd,(struct sockaddr*)&server,sizeof(server));
    listen(server_fd,10);

    while(1){
        client_sock=accept(server_fd,(struct sockaddr*)&client,&c);
        if(fork()==0){
            close(server_fd);
            handle_client(client_sock,client);
        }
        close(client_sock);
    }
}
