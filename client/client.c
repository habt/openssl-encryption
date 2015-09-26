#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <arpa/inet.h>
#include <sys/stat.h>
#include <stdlib.h>

#include <openssl/rsa.h>
#include <openssl/pem.h>

#define SA struct sockaddr

   /* This function sends a file to the server
   @ input file_name = name of the file to be sent
   @ input sk = socket used to send the file
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
	int md_len,i;

	EVP_MD_CTX mdctx;

	const EVP_MD *md;

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
       // for(i = 0; i < md_len; i++) printbyte( md_value2[i]);
        //printf("\n");

	return md_len;
}


//********** Function to perform symmetric encryption ***********//

int symmetric_encrypt(char* buffer, char* ciphertext,int size)
{

 	int nc; /* amount of bytes [de]crypted at each step */
  	int nctot; /* total amount of encrypted bytes */
  	int pt_len; /* plain text size */
  	int ct_len; /* encrypted text size */
  	int ct_ptr; /* first available entry in the buffer */
  	int msg_len; /* message length */
	int k_size,i;
	char* key;
	FILE* fp;

	k_size=EVP_CIPHER_key_length(EVP_des_ecb());

 	key=malloc(k_size*sizeof(char)); /* encryption key */

 	/* Context allocation */
  	EVP_CIPHER_CTX *ctx = (EVP_CIPHER_CTX *)malloc(sizeof(EVP_CIPHER_CTX));

  	/* Context initialization */
  	EVP_CIPHER_CTX_init(ctx);

 	/* Context setup for encryption */
  	EVP_EncryptInit(ctx, EVP_des_ecb(), NULL, NULL);

 	/* key generation */ 
	fp=fopen("key", "r");

	fread(key, 1,k_size, fp);

	fclose(fp);

	printf("\n symmetric key used is : \n");

	for (i = 0; i < k_size; i++)
    		printbyte(key[i]);
  	//printf("\n");

	/* Encryption key setup */
  	EVP_EncryptInit(ctx, NULL, key, NULL);

 	/* Encryption */
  	nc = 0;
  	nctot = 0;
  	ct_ptr = 0;

  	EVP_EncryptUpdate(ctx, ciphertext, &nc, buffer, size);
  
  	ct_ptr += nc;
  	nctot += nc;
  	
  	EVP_EncryptFinal(ctx, &ciphertext[ct_ptr], &nc);

  	nctot += nc; // total length of message

  	EVP_CIPHER_CTX_cleanup(ctx);

  	free(ctx);
	free(key);

  	//for (i = 0; i < nctot; i++) printbyte(ciphertext[i]);

  	printf("\n\n");
	return nctot;
	
}



int RSA_encrypt(char* keybuffer,char* enckey,int size,RSA* rsa)
{
	int ret,i;
	int enckeysize =RSA_size(rsa);

	ret = RSA_public_encrypt(size,keybuffer,enckey,rsa,RSA_PKCS1_PADDING);

	//for(i=0;i<strlen(enckey);i++) printbyte(enckey[i]);

	return enckeysize;
}




   int send_file(char* file_name, int sk) {
	  
	FILE* file;

	FILE* fp;

	int name_size;			// size of the name of the file to be sent
	int size,k_size; 			// size of the file to be sent
	int ret, i; 			
	unsigned char* buffer;		// pointer to the buffer containing the file
	char* sym_key;

	int enckeysize;

	int remote_random,local_random;

char* password;

	//***** recieve the random value from server *****//

	ret = recv(sk, &remote_random, sizeof(int), MSG_WAITALL);


	file = fopen("key","r");

	/* Retrieve the size of the key to be sent */
	fseek(file,0,SEEK_END);
	k_size = ftell(file);

	/* Memory allocation for the key to be sent */
	sym_key = malloc(k_size * sizeof (char));
	fseek(file, 0, SEEK_SET);

	/* Read key from file */
	ret = fread(sym_key, 1, k_size, file);

	
//***** RSA ENCRYPTION PART BEGIN *****//

	char* enckey;

	RSA* rsa = RSA_new();

	fp = fopen("pub.pem","r");

	PEM_read_RSAPublicKey(fp,&rsa,NULL,NULL);

	enckeysize =RSA_size(rsa); 

	enckey=malloc(enckeysize * sizeof(char));

	RSA_encrypt(sym_key,enckey,k_size,rsa);

	fclose(fp);

//*** RSA ENCRYPTION PART end ***//
	
	/* Computation of the length of the filename */
	name_size = strlen(file_name);

	/* Open the file to be sent */
	file = fopen(file_name,"r");
	if(file == NULL) {
	  printf("\nError opening the file file\n");
	  return 1;
	}
    	
    	/* Retrieve the size of the file to be sent */
	fseek(file,0,SEEK_END);
	size = ftell(file);
	
	/* Memory allocation for the file to be sent */
	buffer = malloc(size * sizeof (char));
	fseek(file, 0, SEEK_SET);

	/* File reading */
	ret = fread(buffer, 1, size, file);
	  if(ret < size) {
	  printf("\n Error reading the file \n");
	  return 1;
	}
	
	fclose(file);
	
	/* The length of the file name is sent */
	ret = send(sk, &name_size, sizeof(name_size), 0);
 
	if(ret != sizeof(name_size)){
	  printf("\n Error trasmitting the length of the file name\n ");
	  return 1;
	}
    
	/* The file name is sent */
	ret = send(sk, file_name, name_size, 0); 
	if(ret < name_size){
	  printf("\n Error transmitting the file name\n ");
	  return 1;
	}
		


//****** Generate hash for freshness and origin(password) check *****//

	time_t t;
	int password_size;
	int fresh_size;
	char* fresh_txt;

	t = time(NULL);

 	srand ( time(NULL));

	local_random = rand();

	file = fopen("passofA.txt","r");

	fseek(file,0,SEEK_END);

	password_size = ftell(file);

	password = malloc(password_size * sizeof (char));

	fseek(file, 0, SEEK_SET);

	ret = fread(password, 1, password_size, file);
	
	fclose(file);

	int pass_hash_len;

	const EVP_MD *md1;

	md1 = EVP_get_digestbyname("sha1");

	unsigned char pass_md_value[EVP_MD_size(md1)];

	pass_hash_len=hash_gen(password,&pass_md_value[0]);

	fresh_size=sizeof(password)+sizeof(local_random)+sizeof(remote_random);
	
	fresh_txt = malloc(fresh_size);

	int loc_rand_size=sizeof(local_random);

	int rem_rand_size = sizeof(remote_random);

	memcpy(fresh_txt,&pass_md_value[0],pass_hash_len);

	memcpy(&fresh_txt[pass_hash_len],&local_random,loc_rand_size);

	memcpy(&fresh_txt[pass_hash_len+loc_rand_size],&remote_random,rem_rand_size);

	const EVP_MD *md;

	md = EVP_get_digestbyname("sha1");

	unsigned char md_value[EVP_MD_size(md)];
	
	int md_len;

	md_len=hash_gen(fresh_txt,&md_value[0]);

	printf("\n Freshness Digest is: \n");
        for(i = 0; i < md_len; i++) printbyte(md_value[i]);
        printf("\n");



///*** SYMMETRIC KEY ENCRYPTION PART BEGIN ***///

	char* totbuffer;
	int  nctot;
	char *plaintext, *ciphertext;
	int totbufsize = size+md_len;

	totbuffer = malloc(totbufsize);

	// message + digest for freshness and password 
	memcpy(totbuffer,buffer,size);  

	memcpy(&totbuffer[size],md_value,md_len);

	ciphertext = malloc(totbufsize+128);

	nctot = symmetric_encrypt(totbuffer,ciphertext,totbufsize); //  encrypted size


//***** SYMMETRIC KEY encryption part END *****///



//***** concatenate enckey and ciphertext *****//

	char* textnkeynhash;
	int totsize;

	totsize=nctot+enckeysize+loc_rand_size;
	
	textnkeynhash=malloc(totsize);
	
	memcpy(textnkeynhash,ciphertext,nctot);

	memcpy(&textnkeynhash[nctot],enckey,enckeysize);

	memcpy(&textnkeynhash[nctot+enckeysize],&local_random,loc_rand_size);


	/* The file size is sent */
	ret = send(sk, &totsize, sizeof(totsize), 0);
	  if(ret != sizeof(size)){
	  printf("\n Error transmitting the file size\n ");
	  return 1;
	}

	/* The file is sent */
	ret = send(sk, textnkeynhash, totsize, 0);
	if(ret < size){
	  printf("\n Error transmitting the file\n");
	  return 1;
	}
	
	printf("\n File %s with size %d bytes has been sent\n", file_name, totsize);
	free(buffer);
	free(ciphertext);
    
	return 0;
	
}

int main(int argc, char*argv[]) {   
  
    int ret;				/* function returns */
    int sk;				/* server communication socket */
    int cl_port; 			/* port number */

    struct sockaddr_in srv_addr;	/* server address */

    // Command line arguments check
    if (argc!=4) {
	printf ("Error inserting parameters. Usage: \n\t %s (IP) (port) (file_name)\n\n", argv[0]);
	return 1;
    }
    
    // Port number validity check
    if ( atoi(argv[2]) <= 0 ||  atoi(argv[2]) > 65535 ) {
	printf ("Port number is not valid\n");
	return 1;
    }

    cl_port = atoi(argv[2]);
    printf ("client: Port: %d \n",cl_port);
	
    memset(&srv_addr, 0, sizeof(srv_addr)); 
    srv_addr.sin_family = AF_INET; 
    srv_addr.sin_port = htons(cl_port); 
    ret = inet_pton(AF_INET, argv[1], &srv_addr.sin_addr);
    
    if(ret <= 0) {
        printf("\n Wrong server address\n");
        return 1;
    }
	  
    /* New socket creation */
    sk = socket(AF_INET, SOCK_STREAM, 0);
    
    if(sk == -1) {
        printf("\nError creating the socket\n");
        return 1;
    }
    
    /* TCP connection setup */
    ret = connect(sk, (SA *) &srv_addr, sizeof(srv_addr));
    
    if(ret == -1) {
        printf("\n Error establishing a connection with the server\n");
        return 1;
    }
   
    printf("\n Connection with server %s established on port %d.\n", argv[1], cl_port);

    /* The file is sent to the server */
    if(send_file(argv[3], sk))
	printf("Error sending the file to the server.\n");
   
    return 0;
    
}
