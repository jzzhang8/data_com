#include "myftp.h"


int main(int argc, char ** argv){
    int port = atoi(argv[1]);
    int i;
    for(i = 0;i < MAXJOIN;i++){
        threadClient[i].available = 1;
    }
    int sd = socket(AF_INET, SOCK_STREAM, 0);
    if(sd < 0){
        printf("create socket error: %s (ERRNO:%d)\n",strerror(errno), errno);
        exit(0);
    }
    int client_sd;
    struct sockaddr_in server_addr;
    // set server_addr
    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_addr.s_addr = htonl(INADDR_ANY);
    server_addr.sin_port = htons(port);
    socklen_t addrlen = sizeof(server_addr);
    long on = 1;
    if(setsockopt(sd, SOL_SOCKET, SO_REUSEADDR, &(on), sizeof(long)) < 0){
        perror("set sock opt");
    }
    if(bind(sd,(struct sockaddr *)&server_addr, sizeof(server_addr))<0){
        printf("bind error: %s (ERRNO:%d)\n",strerror(errno), errno);
        exit(0);
    }
    if(listen(sd, 1024) < 0){
        printf("listen error: %s (ERRNO:%d)\n",strerror(errno), errno);
        exit(0);
    }
    struct sockaddr_in client_addr;
    int addr_len = sizeof(client_addr);


    /* SSL command */
    /*----------------------------------------------------------------*/
    /* Register all algorithms */
    SSL_METHOD      *meth;


    OpenSSL_add_all_algorithms();

    /* Load encryption & hashing algorithms for the SSL program */
    SSL_library_init();

    /* Load the error strings for SSL & CRYPTO APIs */
    SSL_load_error_strings();

    /* Create a SSL_METHOD structure (choose a SSL/TLS protocol version) */
    meth = (SSL_METHOD*)TLSv1_method();

    /* Create a SSL_CTX structure */
    ctx = SSL_CTX_new(meth);

    if (!ctx) {
        ERR_print_errors_fp(stderr);
        exit(1);
    }

    /* Load the server certificate into the SSL_CTX structure */
    if (SSL_CTX_use_certificate_file(ctx, RSA_SERVER_CERT, SSL_FILETYPE_PEM)
            <= 0) {
        ERR_print_errors_fp(stderr);
        exit(1);
    }

    /* set password for the private key file. Use this statement carefully */
    SSL_CTX_set_default_passwd_cb_userdata(ctx, (char*)"4430");


    /* Load the private-key corresponding to the server certificate */
    if (SSL_CTX_use_PrivateKey_file(ctx, RSA_SERVER_KEY, SSL_FILETYPE_PEM) <=
            0) {
        ERR_print_errors_fp(stderr);
        exit(1);
    }

    /* Check if the server certificate and private-key matches */
    if (!SSL_CTX_check_private_key(ctx)) {
        fprintf(stderr,
                "Private key does not match the certificate public key\n");
        exit(1);
    }


    while(1){
        if((client_sd = accept(sd, (struct sockaddr *)&client_addr, &addr_len))<0){
            printf("accpet error: %s (ERRNO:%d)\n",strerror(errno), errno);
            exit(0);
        }
        // find an available threadClient
        for(i = 0 ;i < MAXJOIN;i++){ 
            if(threadClient[i].available){
                threadClient[i].available = 0;
                struct _threadParam threadParam; 
                threadParam.client_sd = client_sd;
                threadParam.threadClientIdx = i;
                memcpy(&(threadClient[i].threadParam), &(threadParam), sizeof(threadParam));
                //printf("start idx:%d\n", i);
                //start thread
                pthread_create(&(threadClient[i].thread), NULL, threadFun, &(threadClient[i].threadParam));
                pthread_detach(threadClient[i].thread);
                break;
            }
        }

    }

    SSL_CTX_free(ctx);
    
    close(sd);
    return 0;
}
