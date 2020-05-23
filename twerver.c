#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <string.h>
#include <signal.h>
#include "socket.h"

#ifndef PORT
    #define PORT 50732
#endif

#define LISTEN_SIZE 5
#define WELCOME_MSG "Welcome to CSC209 Twitter! Enter your username: "
#define SEND_MSG "send"
#define SHOW_MSG "show"
#define FOLLOW_MSG "follow"
#define UNFOLLOW_MSG "unfollow"
#define QUIT_MSG "quit"
#define BUF_SIZE 256
#define MSG_LIMIT 8
#define FOLLOW_LIMIT 5

struct client {
    int fd;
    struct in_addr ipaddr;
    char username[BUF_SIZE];
    char message[MSG_LIMIT][BUF_SIZE];
    struct client *following[FOLLOW_LIMIT]; // Clients this user is following
    struct client *followers[FOLLOW_LIMIT]; // Clients who follow this user
    char inbuf[BUF_SIZE]; // Used to hold input from the client
    char *in_ptr; // A pointer into inbuf to help with partial reads
    struct client *next;
};


// Provided functions. 
void add_client(struct client **clients, int fd, struct in_addr addr);
void remove_client(struct client **clients, int fd);

// These are some of the function prototypes that we used in our solution 
// You are not required to write functions that match these prototypes, but
// you may find them helpful when thinking about operations in your program.

// Send the message in s to all clients in active_clients. 
void announce(struct client *active_clients, char *s);

// Move client c from new_clients list to active_clients list. 
void activate_client(struct client *c, 
    struct client **active_clients_ptr, struct client **new_clients_ptr);

int find_network_newline(const char *buf, int n);

//invalid command check
void invalid_check(struct client *active_clients, struct client *p);

//show message
void show_msg(struct client *active_clients, struct client * p);

//inactive client message
void inactive_client_msg(struct client *active_clients, struct client *p);

//limit violation message
void lt_violation(struct client * active_clients, struct client *p, char * type);

//quit message
void quit_msg(struct client * active_clients, struct client *p);

//goodbye message
void good_bye(struct client *active_clients, char *client);

// The set of socket descriptors for select to monitor.
// This is a global variable because we need to remove socket descriptors
// from allset when a write to a socket fails. 
fd_set allset;

/* 
 * Create a new client, initialize it, and add it to the head of the linked
 * list.
 */
void add_client(struct client **clients, int fd, struct in_addr addr) {
    struct client *p = malloc(sizeof(struct client));
    if (!p) {
        perror("malloc");
        exit(1);
    }

    printf("Adding client %s\n", inet_ntoa(addr));
    p->fd = fd;
    p->ipaddr = addr;
    p->username[0] = '\0';
    p->in_ptr = p->inbuf;
    p->inbuf[0] = '\0';
    p->next = *clients;

    // initialize followers to empty
    for (int i = 0; i < FOLLOW_LIMIT; i++){
        (p->followers)[i] = NULL;
    }

    // initialize followings to empty
    for (int j = 0; j < FOLLOW_LIMIT; j++){
        (p->following)[j] = NULL;
    }

    // initialize messages to empty strings
    for (int k = 0; k < MSG_LIMIT; k++) {
        p->message[k][0] = '\0';
    }

    *clients = p;
}

/* 
 * Remove client from the linked list and close its socket.
 * Also, remove socket descriptor from allset.
 */
void remove_client(struct client **clients, int fd) {
    struct client **p;

    for (p = clients; *p && (*p)->fd != fd; p = &(*p)->next)
        ;

    // Now, p points to (1) top, or (2) a pointer to another client
    // This avoids a special case for removing the head of the list
    if (*p) {
        //Removing the client from other clients' following/followers lists

        struct client * q;
        // Removing client's followers
        for (int i = 0; i < FOLLOW_LIMIT; i++){
            q = ((*p)->followers)[i];
            if (q){
                for (int j = 0; j < FOLLOW_LIMIT; j++){
                    if ((q->following)[j]){
                        if (strcmp(((q->following)[j])->username, (*p)->username) == 0){
                            printf("%s is no longer following %s because they disconnected\n", q->username, (*p)->username);
                            (q->following)[j] = NULL;
                            break;
                        }
                    }
                }
            } 
        }

        struct client * r;
        // Removing client's followings
        for (int i = 0; i < FOLLOW_LIMIT; i++){
            r = ((*p)->following)[i];
            if (r){
                for (int j = 0; j < FOLLOW_LIMIT; j++){
                    if ((r->followers)[j]){    
                        if (strcmp(((r->followers)[j])->username, (*p)->username) == 0){
                            printf("%s no longer has %s as a follower because they disconnected\n", r->username, (*p)->username);
                            (r->followers)[j] = NULL;
                            break;
                        }
                    }
                }
            } 
        }

        // Remove the client
        struct client *t = (*p)->next;
        printf("Removing client %d %s\n", fd, inet_ntoa((*p)->ipaddr));
        FD_CLR((*p)->fd, &allset);
        close((*p)->fd);
        free(*p);
        *p = t;
    } else {
        fprintf(stderr, 
            "Trying to remove fd %d, but I don't know about it\n", fd);
    }
}


int main (int argc, char **argv) {
    int clientfd, maxfd, nready;
    struct client *p;
    struct sockaddr_in q;
    fd_set rset;

    // If the server writes to a socket that has been closed, the SIGPIPE
    // signal is sent and the process is terminated. To prevent the server
    // from terminating, ignore the SIGPIPE signal. 
    struct sigaction sa;
    sa.sa_handler = SIG_IGN;
    sa.sa_flags = 0;
    sigemptyset(&sa.sa_mask);
    if (sigaction(SIGPIPE, &sa, NULL) == -1) {
        perror("sigaction");
        exit(1);
    }

    // A list of active clients (who have already entered their names). 
    struct client *active_clients = NULL;

    // A list of clients who have not yet entered their names. This list is
    // kept separate from the list of active clients, because until a client
    // has entered their name, they should not issue commands or 
    // or receive announcements. 
    struct client *new_clients = NULL;

    struct sockaddr_in *server = init_server_addr(PORT);
    int listenfd = set_up_server_socket(server, LISTEN_SIZE);
    free(server);

    // Initialize allset and add listenfd to the set of file descriptors
    // passed into select 
    FD_ZERO(&allset);
    FD_SET(listenfd, &allset);

    // maxfd identifies how far into the set to search
    maxfd = listenfd;

    while (1) {
        // make a copy of the set before we pass it into select
        rset = allset;

        nready = select(maxfd + 1, &rset, NULL, NULL, NULL);
        if (nready == -1) {
            perror("select");
            exit(1);
        } else if (nready == 0) {
            continue;
        }

        // check if a new client is connecting
        if (FD_ISSET(listenfd, &rset)) {
            printf("A new client is connecting\n");
            clientfd = accept_connection(listenfd, &q);

            FD_SET(clientfd, &allset);
            if (clientfd > maxfd) {
                maxfd = clientfd;
            }
            printf("Connection from %s\n", inet_ntoa(q.sin_addr));
            add_client(&new_clients, clientfd, q.sin_addr);
            char *greeting = WELCOME_MSG;
            if (write(clientfd, greeting, strlen(greeting)) == -1) {
                fprintf(stderr, 
                    "Write to client %s failed\n", inet_ntoa(q.sin_addr));
                printf("Disconnect from %s\n", inet_ntoa(q.sin_addr));
                remove_client(&new_clients, clientfd);
            }
        }

        // Check which other socket descriptors have something ready to read.
        // The reason we iterate over the rset descriptors at the top level and
        // search through the two lists of clients each time is that it is
        // possible that a client will be removed in the middle of one of the
        // operations. This is also why we call break after handling the input.
        // If a client has been removed, the loop variables may no longer be 
        // valid.

        int cur_fd, handled;
        for (cur_fd = 0; cur_fd <= maxfd; cur_fd++) {
            if (FD_ISSET(cur_fd, &rset)) {
                handled = 0;

                // Check if any new clients are entering their names
                for (p = new_clients; p != NULL; p = p->next) {
                    if (cur_fd == p->fd) {
                        // handle input from a new client who has not yet
                        // entered an acceptable name
                        char name[BUF_SIZE] = "";

                        int n_read = read(cur_fd, name, BUF_SIZE - strlen(p->inbuf) - 1);
                        printf("[%d] Read %d bytes\n", cur_fd, n_read);

                        //check for disconnection
                        if (n_read == 0){
                            printf("Disconnect from %s\n", inet_ntoa(p->ipaddr));
                            remove_client(&new_clients,cur_fd);
                            break;
                        }
                        else if(n_read == -1){
                            perror("read");
                            exit(1);
                        }
                        name[n_read] = '\0';

                        strcat(p->inbuf, name);

                        int where;
                        //partial reads check
                        if ((where = find_network_newline(p->inbuf, strlen(p->inbuf))) > 0){
                            p->inbuf[where - 2] = '\0';
                        }
                        else{
                            break;
                        }

                        printf("[%d] Found newline %s\n", cur_fd, p->inbuf);

                        //checking validity
                        int in_valid = 0;
                        if (strlen(p->inbuf) != 0){
                            for (struct client * q = active_clients; q != NULL; q = q->next){

                                //duplicate name check
                                if (strcmp(q->username, p->inbuf) == 0){
                                    in_valid = 1;
                                    break;
                                }
                            }
                        }
                        else{               //empty string check
                            in_valid = 1;
                        }

                        //Ask the client to re-enter if invalid name
                        if (in_valid) {
                            strcpy(p->inbuf, "\0");
                            char re_enter[35] = "Please re-entry a new username: ";
                            printf("%s\n", re_enter);
                            strcat(re_enter, "\r\n");
                            re_enter[34] = '\0';

                            int n_write = 0;
                            n_write = write(cur_fd, re_enter, strlen(re_enter));
                            if (n_write == -1){
                                perror("write");
                                exit(1);
                            }
                            else if (n_write == 0){
                                printf("Disconnect from %s\n", inet_ntoa(p->ipaddr));
                                remove_client(&new_clients, cur_fd);
                            }
                            
                            break;
                        }

                        //set valid username
                        strcpy(p->username, p->inbuf);
                        (p->username)[strlen(p->inbuf)] = '\0';

                        //make client active member
                        activate_client(p, &active_clients, &new_clients);

                        char join_msg[strlen(p->inbuf) +  21];
                        strcpy(join_msg, p->inbuf);
                        strncat(join_msg, " has just joined.", 18);
                        printf("%s\n", join_msg);
                        strcat(join_msg, "\r\n");
                        join_msg[strlen(p->inbuf) +  20] = '\0';
                        announce(active_clients, join_msg);

                        strcpy(p->inbuf, "\0");

                        handled = 1;
                        break;
                    }
                }

                if (!handled) {
                    // Check if this socket descriptor is an active client
                    for (p = active_clients; p != NULL; p = p->next) {
                        if (cur_fd == p->fd) {

                            // handle input from an active client
                            char text[BUF_SIZE] = "";
                            int n_read = read(cur_fd, text, BUF_SIZE - strlen(p->inbuf) - 1);
                            printf("[%d] Read %d bytes\n", cur_fd, n_read);

                            //check for disconnection
                            if (n_read == 0){
                                good_bye(active_clients, p->username);
                                printf("Disconnect from %s\n", inet_ntoa(p->ipaddr));
                                remove_client(&active_clients,cur_fd);
                                break;
                            }
                            else if (n_read == -1){
                                perror("read");
                                exit(1);
                            }

                            //getting client written text 
                            text[n_read] = '\0';

                            strcat(p->inbuf, text);

                           int where;
                            //partial reads check
                            if ((where = find_network_newline(p->inbuf, strlen(p->inbuf))) > 0){
                                p->inbuf[where - 2] = '\0';
                            }
                            else{
                                break;
                            }

                            printf("[%d] Found newline %s\n", cur_fd, p->inbuf);

                            printf("%s: %s\n", p->username, p->inbuf);

                            char *ptr = strchr(p->inbuf, ' ');

                            char command[9] = "\0";
                            char msg[141] = "\0";

                            //populating command and msg
                            if (ptr){                           // Found space in text
                                
                                int command_len = strlen(p->inbuf) - strlen(ptr);

                                if (command_len > 8){
                                    invalid_check(active_clients, p);
                                    break;
                                }
                                else{
                                    //command
                                    strncpy(command, p->inbuf, command_len);
                                    command[command_len] = '\0';

                                    //message or name
                                    int msg_size;
                                    if (strlen(ptr + 1) < 141){
                                        msg_size = strlen(ptr + 1);
                                    }
                                    else{
                                        msg_size = 140;
                                    }
                                    strncpy(msg, ptr + 1, msg_size);
                                    msg[msg_size] = '\0';
                                }
                            }
                            else{

                                if(strlen(p->inbuf) > 8){
                                    invalid_check(active_clients, p);
                                    break;
                                }
                                else{
                                    //command
                                    strncpy(command, p->inbuf, 8);
                                    command[8] = '\0';
                                }
                            }

                            strcpy(p->inbuf,"\0");

                            if (strcmp(command, FOLLOW_MSG) == 0 && strlen(msg) != 0){      //follow
                                struct client * to_follow = NULL;

                                for (struct client * q = active_clients; q != NULL; q = q -> next){
                                    if (strcmp(q->username, msg) == 0){
                                        to_follow = q;
                                        break;
                                    }
                                }

                                //to check whether the client to be followed is an active member
                                if (!to_follow){
                                    inactive_client_msg(active_clients, p);
                                    break;
                                }

                                //check available following space
                                int following_space_available = -1;
                                for (int i = 0; i < FOLLOW_LIMIT; i++){
                                    if(!(p->following[i])){
                                        following_space_available = i;
                                    }
                                }

                                //check available follower space
                                int follower_space_available = -1;
                                for (int j = 0; j < FOLLOW_LIMIT; j++){
                                    if(!(to_follow->followers[j])){
                                        follower_space_available = j;
                                    }
                                }

                                //setting client to be followed by checking for available space
                                if (following_space_available != -1 && follower_space_available != -1){
                                    (p->following)[following_space_available] = to_follow;
                                    printf("%s is following %s\n", p->username, to_follow->username);

                                    (to_follow->followers)[follower_space_available] = p;
                                    printf("%s has %s as a follower\n", to_follow->username, p->username);
                                    
                                }
                                else{

                                    //Violation of follow limit
                                    lt_violation(active_clients, p, "FOLLOW\0");
                                }

                            }
                            else if (strcmp(command, UNFOLLOW_MSG) == 0 && strlen(msg) != 0){       //unfollow   
                                struct client * to_unfollow = NULL;

                                for (struct client * q = active_clients; q != NULL; q = q -> next){
                                    if (strcmp(q->username, msg) == 0){
                                        to_unfollow = q;
                                    }
                                }


                                //to check whether the client to be unfollowed is an active member
                                if (!to_unfollow){
                                    inactive_client_msg(active_clients, p);
                                    break;
                                }


                                //remove from to_unfollow's followers list
                                for (int j = 0; j < FOLLOW_LIMIT; j++){
                                    if ((to_unfollow->followers)[j]){
                                        if(strcmp(((to_unfollow->followers)[j])->username, p->username) == 0){
                                            printf("%s no longer has %s as a follower\n", to_unfollow->username, p->username);
                                            to_unfollow->followers[j] = NULL;
                                            break;
                                        }
                                    }
                                }


                                //remove from client's following list
                                for (int i = 0; i < FOLLOW_LIMIT; i++){
                                    if ((p->following)[i]){
                                        if(strcmp(((p->following)[i])->username, to_unfollow->username) == 0){
                                            printf("%s unfollows %s\n", p->username, to_unfollow->username);
                                            p->following[i] = NULL;
                                            break;
                                        }
                                    }
                                }


                            }
                            else if (strcmp(command, SHOW_MSG) == 0 && strlen(msg) == 0){       //show

                                show_msg(active_clients, p);
                            }
                            else if (strcmp(command, SEND_MSG) == 0){

                                //finding the number of messages sent
                                int cur_messages = 0;
                                for (int i = 0; i < MSG_LIMIT; i++){
                                    if(strlen(p->message[i])){
                                        cur_messages++;
                                    }
                                    else{
                                        break;
                                    }
                                }

                                //msg limit violation check
                                if (cur_messages == MSG_LIMIT){
                                    lt_violation(active_clients, p, "MSG\0");
                                    break;
                                }
                                else{
                                    strcpy((p->message)[cur_messages], msg);
                                }

                                int msg_to_send_size = strlen((p->message)[cur_messages]) + strlen(p->username) + 5;
                                char send_to_followers[msg_to_send_size];
                                strcpy(send_to_followers, p->username);
                                strcat(send_to_followers, ": ");
                                strcat(send_to_followers, (p->message)[cur_messages]);
                                strcat(send_to_followers, "\r\n");
                                send_to_followers[msg_to_send_size - 1] = '\0';

                                //writing msg to all the client's followers
                                for (int j = 0; j < FOLLOW_LIMIT; j++){
                                    int n_write = 0;
                                    if((p->followers)[j]){
                                        n_write = write(((p->followers)[j])->fd, send_to_followers, strlen(send_to_followers));
                                        if (n_write == -1){
                                            perror("write");
                                            exit(1);
                                        }
                                        else if(n_write == 0){
                                            quit_msg(active_clients, p);
                                        }
                                    }
                                }
                            }
                            else if (strcmp(command, QUIT_MSG) == 0){

                                quit_msg(active_clients, p);
                            }
                            else{

                                invalid_check(active_clients, p);
                            }

                            break;

                        }
                    }
                }
            }
        }
    }
    return 0;
}

/*
 * Search the first n characters of buf for a network newline (\r\n).
 * Return one plus the index of the '\n' of the first network newline,
 * or -1 if no network newline is found.
 * Definitely do not use strchr or other string functions to search here. (Why not?)
 */
int find_network_newline(const char *buf, int n) {
  int i;
  for (i = 0; i < (n-1); i++) {

    if ((buf[i] == '\r') && (buf[i+1] == '\n'))   {
      return i + 2;
    }
  }
  return -1;
}

void activate_client(struct client *c, struct client **active_clients_ptr, struct client **new_clients_ptr){
    struct client ** p;
    for (p = new_clients_ptr; *p && (*p) != c; p = &(*p)->next)
        ;
    struct client *remain_new_client = (*p)->next;
    *p = remain_new_client;

    c->next = *active_clients_ptr;
    *active_clients_ptr = c;
}

void announce(struct client *active_clients, char *s){
    struct client *p;
    for (p = active_clients; p != NULL; p = p->next){
        int n_write = 0;
        n_write = write(p->fd, s, strlen(s));
        if (n_write == -1){
            perror("write");
            exit(1);
        }
        else if(n_write == 0){
            printf("Disconnect from %s\n", inet_ntoa(p->ipaddr));
            remove_client(&active_clients,p->fd);
            break;
        }
    }
}

void invalid_check(struct client *active_clients, struct client *p){
    char invalid_msg[18] = "Invalid Command";
    printf("%s\n", invalid_msg);
    strcat(invalid_msg, "\r\n");
    invalid_msg[17] = '\0';

    int n_write = 0;
    n_write = write(p->fd, invalid_msg, strlen(invalid_msg));
    if (n_write == -1){
        perror("write");
        exit(1);
    }
    else if(n_write == 0){
        quit_msg(active_clients, p);
    } 
}

void lt_violation(struct client * active_clients, struct client *p, char * type){
    int msg_size = strlen(type) + 19;
    char msg_limit_issue[msg_size];
    strcpy(msg_limit_issue, type);
    strcat(msg_limit_issue,  " Limit Violation");
    printf("%s\n", msg_limit_issue);
    strcat(msg_limit_issue, "\r\n");
    msg_limit_issue[msg_size - 1] = '\0';

    int n_write = 0;
    n_write = write(p->fd, msg_limit_issue, msg_size);
    if (n_write == -1){
        perror("write");
        exit(1);
    }
    else if(n_write == 0){
        quit_msg(active_clients, p);
    }
}

void show_msg(struct client * active_clients, struct client * p){
    for (int i = 0; i < FOLLOW_LIMIT; i++){
        if ((p->following)[i]){
            for (int j = 0; j < MSG_LIMIT; j++){
                if (strlen(((p->following[i])->message)[j])){
                    int show_msg_size = strlen(((p->following)[i])->username) + strlen((((p->following)[i])->message)[j]) + 11;
                    char show_msg[show_msg_size];
                    strcpy(show_msg, ((p->following)[i])->username);
                    strcat(show_msg, " wrote: ");
                    strcat(show_msg, (((p->following)[i])->message)[j]);
                    strcat(show_msg, "\r\n");
                    show_msg[show_msg_size - 1] = '\0';

                    int n_write = 0;
                    n_write = write(p->fd, show_msg, strlen(show_msg));
                    if (n_write == -1){
                        perror("write");
                        exit(1);
                    }
                    else if(n_write == 0){
                        quit_msg(active_clients, p);
                        break;
                    }
                }  
            }
        }
    }
}

void inactive_client_msg(struct client * active_clients, struct client * p){
    char non_active_client_msg[42] = "Not an active member - unable to follow";
    printf("%s\n", non_active_client_msg);
    strcat(non_active_client_msg, "\r\n");
    non_active_client_msg[41] = '\0';
    
    int n_write = 0;
    n_write = write(p->fd, non_active_client_msg, strlen(non_active_client_msg));
    if (n_write == -1){
        perror("write");
        exit(1);
    }
    else if(n_write == 0){
        quit_msg(active_clients, p);
    }
}

void quit_msg(struct client * active_clients, struct client *p){
    good_bye(active_clients, p->username);
    printf("Disconnect from %s\n", inet_ntoa(p->ipaddr));
    remove_client(&active_clients,p->fd);
}

void good_bye(struct client * active_clients, char * client){
    int msg_size = strlen(client) + 10;
    char msg[msg_size];
    strcpy(msg, "Goodbye ");
    strcat(msg, client);
    strcat(msg, "\n");
    msg[msg_size - 1] = '\0';
    announce(active_clients, msg);
}