#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <arpa/inet.h>
#include <sys/stat.h>
#include <stdlib.h>
#include <time.h>

#include <openssl/rsa.h>
#include <openssl/pem.h>

#define SA struct sockaddr
#define BACKLOG_SIZE 64
#define SRV_ADDR "127.0.0.1"    
   
   /* This function receives the file sent by the client
   @ input sk = socket through which the file is received
   @ returns 0 in case of success, 1 otherwise */

    void printbyte(char b) 
	{
  		char c;

  		c = b;
  		c = c >> 4;
  		c = c & 15;
  		printf("%X", c);
  		c = b;
  		c = c & 15;
  		printf("%X:", c);
	}


//********** Function to generate a hash(digest) value ***********//

int hash_gen(char* buffer,unsigned char* md_value2)
{
	EVP_MD_CTX mdctx;

	const EVP_MD *md;

	int md_len,i;

	OpenSSL_add_all_digests();

	md = EVP_get_digestbyname("sha1");

	if(!md) {
	printf("Unknown message digest %s\n", "sha1");
	exit(1);
	}

	EVP_MD_CTX_init(&mdctx);

	EVP_DigestInit_ex(&mdctx, md, NULL);

	EVP_DigestUpdate(&mdctx, buffer, strlen(buffer));
	
	EVP_DigestFinal_ex(&mdctx, md_value2, &md_len);

	EVP_MD_CTX_cleanup(&mdctx);

	//printf("\n Calculated Digest is: ");
        //for(i = 0; i < md_len; i++) printbyte( md_value2[i]);
        //printf("\n");

	return md_len;
}



int symmetric_decrypt(char* ciphertext, char* plaintext,char* key,int enctextsize)
{

 	int nc; /* amount of bytes [de]crypted at each step */
  	int nctot; /* total amount of encrypted bytes */
  	int pt_len; /* plain text size */
  	int ct_len; /* encrypted text size */
  	int ct_ptr; /* first available entry in the buffer */
  	int msg_len; /* message length */
	int k_size;

 	/* Context allocation */
  	EVP_CIPHER_CTX *ctx = (EVP_CIPHER_CTX *)malloc(sizeof(EVP_CIPHER_CTX));

  	/* Context initialization */
  	EVP_CIPHER_CTX_init(ctx);

 	/* Context setup for encryption */
  	EVP_DecryptInit(ctx, EVP_des_ecb(), NULL, NULL);

	/* Decryption key setup */
  	EVP_DecryptInit(ctx, NULL, key, NULL);

 	/* Encryption */
  	nc = 0;
  	nctot = 0;
  	ct_ptr = 0;
   
	EVP_DecryptUpdate(ctx, &plaintext[ct_ptr], &nc, ciphertext, enctextsize);
    
  	ct_ptr += nc;
  	nctot += nc;
  	
	EVP_DecryptFinal(ctx, &plaintext[ct_ptr], &nc);

  	nctot += nc;
	
	return nctot;

}




int receive_file(int sk) {

	int ret;
    	int name_size;		// length of the name of the received file
    	char* filename;		// name of the received file
    	int size,i;			// size of the buffer for the plaintext
    	char* buffer;		// plaintext buffer

    	FILE* file;			// pointer to the file where the received message will be saved

	time_t t;

	t = time(NULL);

 	srand ( time(NULL));

	int local_random = rand();

	send(sk, &local_random, sizeof(int), 0);

	printf("\n generated random value is %d",local_random);


    	/* Reception of the length of the file name */
    	ret = recv(sk, &name_size, sizeof(name_size), MSG_WAITALL);
	
    	if (ret != sizeof(name_size)) {
	  printf("%d \n Error receiving the length of the file name\n",ret);
	  return 1;
   	 }

   	 /* Memory allocation */
   	 filename = malloc(sizeof(char) * (name_size + 1));
   	 if(filename == NULL) {
      		printf("\n Error allocating memory\n");
      		return 1;
    	}

    	/* Reception of the file name */
    	ret = recv(sk, filename, name_size, MSG_WAITALL);
    
   	 if(ret != name_size){
     		 printf(" \n Error receiving the file name\n");
     		 return 1;
    	}
    
    filename[name_size] ='\0'; /* End of string */
 
    	/* Reception of the file size */
    	ret = recv(sk, &size, sizeof(size), MSG_WAITALL);
    	if(ret != sizeof(size)) {
      	printf("\n Error receiving the file size\n");
      	return 1;
    	}
 
   	 /* Memory allocation */
   	 buffer = malloc(size * sizeof(char));
    	if(buffer == NULL){
      		printf("\n Error allocating memory\n");
      		return 1;
    	}

    	/* Reception of the file */
    	ret = recv(sk, buffer, size, MSG_WAITALL);
    	if(ret != size) {
      		printf("\n Error receiving the file\n");
      		return 1;
    		}





//***** SEPARATE THE RECIEVED TEXT BEGIN *****//

	int remote_random;
	int md_len = 20;
	int rem_rand_size = sizeof(remote_random);
	char* recieved_hash;
	char* ciphertext;
	char* enc_key;
	int enckeysize =128; 
	int enctextsize;

	recieved_hash = malloc(md_len);

	RSA* rsa = RSA_new();
	
	enctextsize = size - enckeysize - rem_rand_size;
	
	ciphertext = malloc(enctextsize);

	enc_key = malloc(enckeysize);

 	memcpy(ciphertext,buffer,enctextsize);

	memcpy(enc_key,&buffer[enctextsize],enckeysize);

	memcpy(&remote_random,&buffer[enctextsize+enckeysize],rem_rand_size);
	

//****** Generate hash for freshness and origin(password) check *****//

	char* password;
	int password_size;
	int loc_rand_size;
	int fresh_size;
	char* fresh_txt;

	file = fopen("passofAhash.txt","r");

	fseek(file,0,SEEK_END);

	password_size = ftell(file);

	password = malloc(password_size * sizeof (char));

	fseek(file, 0, SEEK_SET);
	/* File reading */
	ret = fread(&password[0], 1, password_size, file);

	fclose(file);


	loc_rand_size=sizeof(local_random);

	fresh_size=password_size+loc_rand_size+sizeof(remote_random);
	
	fresh_txt = malloc(fresh_size);
	
	memcpy(fresh_txt,&password[0],password_size);

	memcpy(&fresh_txt[password_size],&local_random,loc_rand_size);

	memcpy(&fresh_txt[password_size+loc_rand_size],&remote_random,rem_rand_size);

	const EVP_MD *md;

	md = EVP_get_digestbyname("sha1");

	unsigned char md_value[EVP_MD_size(md)];

	md_len=hash_gen(fresh_txt,&md_value[0]);

	printf("\n \n Freshness hash calculated in server is:\n ");
        for(i = 0; i < md_len; i++) printbyte(md_value[i]);
        printf("\n");


//***** DECRYPT THE KEY PART BEGIN *****//

	char* key;
	int flen;
	FILE* fp;

	fp = fopen("priv.pem","r"); 
	
	OpenSSL_add_all_algorithms();

	rsa = PEM_read_RSAPrivateKey(fp,&rsa,NULL,"password");

	if(rsa == NULL) printf("\n ERROR reading rsa private key \n");

	flen = RSA_size(rsa);

	key = malloc(flen);

	ret = RSA_private_decrypt(flen,enc_key,key,rsa,RSA_PKCS1_PADDING);
	
	printf("\n Recieved symmetric key is : \n");
	for (i = 0; i < 8; i++)
    		printbyte(key[i]);
  	printf("\n");

	free(enc_key);
	fclose(fp);
	RSA_free(rsa);

///*** DECRYPT the key part END ***///

	

///*** DECRYPT THE MESSAGE PART BEGIN ***///

	int nctot;
	char* decryptedtext;
	char* plaintext;
	int msg_len;

	decryptedtext = (char *)malloc(enctextsize+128);

	//call decryption function
	nctot = symmetric_decrypt(ciphertext,decryptedtext,key, enctextsize);

	msg_len = nctot - md_len; //size of plaintext message

	plaintext = malloc(msg_len);

	//separate the plain text from the freshness and password hash
	memcpy(plaintext,decryptedtext,msg_len);

	memcpy(recieved_hash,&decryptedtext[msg_len],md_len);

	printf("\n \n Freshness hash recieved from client is: \n");
        for(i = 0; i < md_len; i++) printbyte(recieved_hash[i]);
        printf("\n");

	//compare recieved digest with locally calculated digest to 	check freshness and password
	ret = strcmp(recieved_hash,&md_value[0]);

	if(ret==0)printf("\n MESSAGE FRESHNESS AND ORIGIN IS VERIFIED"); 

	else printf("message not fresh with ret value %d",ret);


//***** DECRYPT the message part END *****//

	
    /* Open the file to save the received message */
    file = fopen(filename,"w");
      if(file == NULL) {
	printf("\n File not found\n");
	return 1;
    }
    
    /* Write the received message in the local file */
    ret = fwrite(plaintext, 1, msg_len, file);
    if(ret < msg_len) {
	printf("\n Error writing the file \n");
	return 1;
    }    
    
    printf("\n Received file %s with size %d bytes\n", filename, size);
    
    fclose(file);
    free(filename);
    free(buffer);
	free(ciphertext);
	free(plaintext);
	
    return 0;
   
}
   
int main(int argc, char*argv[]) {
    
    socklen_t len;					/* Length of the client address */
    int sk;						/* Passive socket */
    int optval;						/* Socket options */
    struct sockaddr_in my_addr, cl_addr;		/* Server and client addressed */
    char cl_paddr[INET_ADDRSTRLEN];			/* Client IP addresses */
    uint16_t cl_port;					/* Client port */
    int ret;
    int cl_sk;						/* Client socket */
    int srv_port;					/* Server port number */
    struct sockaddr_in srv_addr;			/* Server address */
	
    printf("simple server, v. 0.1\n");   
	
    // Command line arguments check
    if (argc!=2) {
	printf ("Error inserting parameters. Usage: \n\t %s (port) \n\n", argv[0]);
	return 1;
    }

    // Port number validity check
    if (atoi(argv[1]) <= 0 || atoi(argv[1]) > 65535) {
	printf ("Port number is not valid\n");
	return 1;
    }
	
    srv_port = atoi(argv[1]);
    printf ("server: Port: %d \n",srv_port);
	
    memset(&srv_addr, 0, sizeof(srv_addr)); 
    srv_addr.sin_family = AF_INET; 
    srv_addr.sin_port = htons(srv_port); 
    ret = inet_pton(AF_INET, SRV_ADDR, &srv_addr.sin_addr);
    
    if(ret <= 0) {
        printf("\n Wrong server address\n");
        return 1;
    }
 
    /* New socket creation */
    sk = socket(AF_INET, SOCK_STREAM, 0);
    if(sk == -1){
        printf("\nError creating the socket\n");
        return 1;
    }
    
    optval = 1;
    ret = setsockopt(sk, SOL_SOCKET, SO_REUSEADDR, &optval, sizeof(optval));
    if(ret == -1) {
        printf("\nError setting SO_REUSEADDR\n");
        return 1;
    }
    
    /* The socket is binded with the IP address and the port number */
    memset(&my_addr, 0, sizeof(my_addr)); 
    my_addr.sin_family = AF_INET;
    my_addr.sin_addr.s_addr = htonl(INADDR_ANY); 
    my_addr.sin_port = htons(srv_port);
    
    ret = bind(sk, (SA *) &my_addr, sizeof(my_addr));
    if(ret == -1) {
        printf("\nError binding the socket\n");
        return 1;
    }
    
    /* Creation of backlog queue */
    ret = listen(sk, BACKLOG_SIZE);
    if(ret == -1) {
        printf("\nError creating the backlog queue, size %d\n", BACKLOG_SIZE);
        return 1;
    }
    	
    printf("Waiting for connections ...\n");
    
    while(1) {
        
	/* Accept a request arrived at sk, which is served by cl_sk */
        len = sizeof(cl_addr);
        cl_sk = accept(sk, (SA *) &cl_addr, &len);
        
	if(cl_sk == -1) {
            printf("\nError during connession\n");
            return 1;
        }
        
        inet_ntop(AF_INET, &cl_addr.sin_addr, cl_paddr, sizeof(cl_paddr));
        cl_port = ntohs(cl_addr.sin_port);
        printf("\nConnession with client %s established on port %d\n", SRV_ADDR, srv_port);

	if(receive_file(cl_sk)) {
	  printf("Error receiving the file\n");
	  return 1;
	}
		
	printf ("\nConnection terminated\n");
	close(cl_sk);
	return 0;
    }
	
   close(sk);
   return 0;
   
}
