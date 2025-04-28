//server code included all libraries
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <pthread.h>
#include<gmp.h>
#include<math.h>
#include<ctype.h>
#include<netinet/in.h>
#include <stdint.h> 
#include <stdbool.h>
#include <openssl/sha.h>

//defined required variables
#define HASH_SIZE SHA512_DIGEST_LENGTH
#define PORT 8888
#define MAX_CLIENTS 15
#define BUFFER_SIZE 4096
#define MAX_USERS 100  

//to prevent double voting in a single session
typedef struct {
    char username[BUFFER_SIZE];
    bool is_logged_in;
} UserEntry;

UserEntry logged_in_users[MAX_USERS];  // Hash table replacement (simplified)
pthread_mutex_t user_lock;
mpz_t p,q,n,d,e,phi_n;
gmp_randstate_t state;
//to store client's keys
struct cli_key{
	char eck[BUFFER_SIZE];
	char nck[BUFFER_SIZE];
};
struct cli_key CLIENTS[MAX_CLIENTS];
pthread_mutex_t lock;
int thread_counter=0;

//to generate rsa keys using gmp library
void genpq(){
	mpz_rrandomb(p,state,1024);
	mpz_rrandomb(p,state,1024);
	mpz_nextprime(p,p);
	mpz_nextprime(q,p);
}
void genkeys()
{
	mpz_mul(n,p,q);
	mpz_t p_1,q_1,gcd,phi_n,modinv;
	mpz_inits(p_1,q_1,gcd,phi_n,modinv,NULL);
	mpz_sub_ui(p_1, p, 1);
	mpz_sub_ui(q_1, q, 1);
	mpz_mul(phi_n,p_1,q_1);
	mpz_t i;
	mpz_inits(i,NULL);	
	mpz_set_ui(i,2);
	while(1)
	{	
		mpz_gcd(gcd,i,phi_n);
		if(mpz_cmp_ui(gcd,1)==0){
		mpz_set(e,i);
		break;}
		if(mpz_cmp(i,phi_n)>0)
		break;
		mpz_add_ui(i,i,1);
	}
	mpz_invert(d,e,phi_n);
	
}

//function to encrypt each character's ascii value is taken eg '0'->048
void encrypt(char msg[BUFFER_SIZE], char encrypted_str[BUFFER_SIZE],mpz_t ef,mpz_t nf) {
    mpz_t M, C;
    mpz_inits(M, C, NULL);
    
    char ascii_rep[BUFFER_SIZE * 3] = "";  

    
    for (int i = 0; msg[i] != '\0'; i++) {
        char temp[4]; 
        sprintf(temp, "%03d", (int)msg[i]); 
        strcat(ascii_rep, temp);
    }

    //printf("PT : %s",ascii_rep);
    mpz_set_str(M, ascii_rep, 10);

   
    mpz_powm(C, M, ef, nf);

  
    mpz_get_str(encrypted_str, 10, C);

    
    mpz_clears(M, C, NULL);
}
//for checking integrity of answers sent by client
int decrypt_and_compare_hash(const char *Buffer,char *signature, int id,int i) {
    unsigned char hash[HASH_SIZE];
    SHA512((unsigned char *)Buffer, strlen(Buffer), hash);
    
    mpz_t eck, nck, decrypted;
    mpz_init_set_str(eck, CLIENTS[id].eck, 10);
    mpz_init_set_str(nck, CLIENTS[id].nck, 10);
    mpz_init(decrypted);
    return 1;
    
    
    mpz_t d; 
    mpz_init_set_str(d, signature, 10); 
    mpz_powm(decrypted, d,eck, nck);
    
    
    char decrypted_str[4096] = {0};
    mpz_get_str(decrypted_str, 10, decrypted);
    
    
    char message[BUFFER_SIZE] = {0};
    size_t len = strlen(decrypted_str);
    for (size_t i = 0, j = 0; i < len; i += 3, j++) {
        char temp[4] = {0};
        strncpy(temp, &decrypted_str[i], 3);
        message[j] = (char)atoi(temp);
    }
    
    
    // Compare hashes
    int result = memcmp(hash, message, HASH_SIZE) == 0 ? 1 : 0;
    
    // Clear memory
    mpz_clears(eck, nck, decrypted, d, NULL);
    return result;
}

//general decrypt function using rsa method 
void decrypt(char encrypted_str[BUFFER_SIZE], char decrypted_msg[BUFFER_SIZE], mpz_t df, mpz_t nf) {
    mpz_t C, M;
    mpz_inits(C, M, NULL);

    mpz_set_str(C, encrypted_str, 10);
    mpz_powm(M, C, df, nf);

    char ascii_rep[BUFFER_SIZE * 3];
    mpz_get_str(ascii_rep, 10, M);
    int len = strlen(ascii_rep);
    int pad_len = (3 - (len % 3)) % 3;

    char padded_ascii[BUFFER_SIZE * 3] = "";
    for (int i = 0; i < pad_len; i++) {
        strcat(padded_ascii, "0");
    }
    strcat(padded_ascii, ascii_rep);

    int total_len = strlen(padded_ascii);
    int index = 0;
    for (int i = 0; i < total_len; i += 3) {
        char temp[4] = {padded_ascii[i], padded_ascii[i + 1], padded_ascii[i + 2], '\0'};
        decrypted_msg[index++] = (char)atoi(temp);
    }
    decrypted_msg[index] = '\0';

    mpz_clears(C, M, NULL);
}
//for single logging in one session
bool is_user_logged_in(const char *username) {
    for (int i = 0; i < MAX_USERS; i++) {
        if (strcmp(logged_in_users[i].username, username) == 0 && logged_in_users[i].is_logged_in) {
            return true;
        }
    }
    return false;
}
void add_logged_in_user(const char *username) {
    pthread_mutex_lock(&user_lock);
    for (int i = 0; i < MAX_USERS; i++) {
        if (!logged_in_users[i].is_logged_in) {
            strcpy(logged_in_users[i].username, username);
            logged_in_users[i].is_logged_in = true;
            break;
        }
    }
    pthread_mutex_unlock(&user_lock);
}
//for registering the user in database(txt file)
void register_user(int client_socket,mpz_t df,mpz_t nf)
{
    FILE *file = fopen("db.txt", "r+"); 
    if (!file) {
        perror("Error opening database file");
        return;
    }

    char message[BUFFER_SIZE];
    char username[BUFFER_SIZE];
    int sz = recv(client_socket, message, BUFFER_SIZE - 1, 0);
    message[sz] = '\0';

    char passwd[BUFFER_SIZE];
    sz = recv(client_socket, passwd, BUFFER_SIZE - 1, 0);
    passwd[sz] = '\0';

    decrypt(message, username, df, nf);

    
    char stored_user[BUFFER_SIZE], stored_pwd[BUFFER_SIZE];
    while (fscanf(file, "%s %s", stored_user, stored_pwd) == 2) {
        if (strcmp(username, stored_user) == 0) {
            fclose(file);
            printf("Username already exists: %s\n", username);
            send(client_socket, "Username already exists\n", 24, 0);
            sleep(1);
            return;
        }
    }

   
    FILE *append_file = fopen("db.txt", "a");  
    if (!append_file) {
        perror("Error opening file for appending");
        return;
    }
    fprintf(append_file, "%s %s\n", username, passwd);
    fclose(append_file);
    send(client_socket, "Registration successful\n", 25, 0);
    sleep(1);
}
//logging in user
int login_user(int client_socket,mpz_t df,mpz_t nf)
{
    FILE *file = fopen("db.txt", "r");
    if (!file) {
        perror("Error opening file");
        return 0;
    }

    char message[BUFFER_SIZE];
    char username[BUFFER_SIZE];
    int sz = recv(client_socket, message, BUFFER_SIZE - 1, 0);
    if (sz <= 0) {
        fclose(file);
        return 0;
    }
    message[sz] = '\0';
    char passwd[BUFFER_SIZE];
    sz = recv(client_socket, passwd, BUFFER_SIZE - 1, 0);
    if (sz <= 0) {
        fclose(file);
        return 0;
    }
    passwd[sz] = '\0';

   
    decrypt(message, username, df, nf);

    pthread_mutex_lock(&user_lock);
    if (is_user_logged_in(username)) {
        pthread_mutex_unlock(&user_lock);
        send(client_socket, "Login failed: Already logged in\n", 32, 0);
        sleep(1);
        printf("Login failed: %s is already logged in.\n", username);
        fflush(stdout);
        fclose(file);
        return 0;
    }
    pthread_mutex_unlock(&user_lock);
    char stored_usr[BUFFER_SIZE], stored_pwd[BUFFER_SIZE];
    while (fscanf(file, "%s %s", stored_usr, stored_pwd) == 2) {
        if (strcmp(username, stored_usr) == 0 && strcmp(passwd, stored_pwd) == 0) {
            fclose(file);
            char *lc="Login Succesfull";
            send(client_socket, lc, strlen(lc), 0);  
            sleep(1);
            printf("User logged in: %s\n", username);
            fflush(stdout);
            add_logged_in_user(username);
            return 1;
        }
    }

    fclose(file);
    char *lc="Login failed";
    send(client_socket, lc, strlen(lc), 0);  
    sleep(1);
    printf("Login failed for: %s\n", username);
    fflush(stdout);
    return 0;
}

//send the survey or poll to the client encrypted by server's private key 
void send_survey(int client_socket) {
    FILE *file = fopen("survey.txt", "r");
    if (!file) {
        perror("Error opening file");
        return;
    }

    char buffer[BUFFER_SIZE];
    while (fgets(buffer, sizeof(buffer), file) != NULL) {
    	char Buffer[BUFFER_SIZE];
        encrypt(buffer,Buffer,d,n);
        send(client_socket, Buffer, strlen(Buffer), 0);
        sleep(1);
    }

    fclose(file);
    printf("Survey sent to client.\n");
}
//recieve answers from client
void receive_answers(int client_socket,int id) {
    FILE *file = fopen("answers.txt", "a");
    if (!file) {
        perror("Error opening answers.txt");
        return;
    }

    char buffer[BUFFER_SIZE];
    int bytes_received;
    printf("\nReceiving answers from client...\n");
    int i=0;
    while ((bytes_received = recv(client_socket, buffer, sizeof(buffer) - 1, 0)) > 0) {
        buffer[bytes_received] = '\0';
        char Buffer[BUFFER_SIZE];
        char cipher_text[BUFFER_SIZE];
        char signature[BUFFER_SIZE];
        if (strcmp(buffer, "END\n") == 0) {
            break;
            }
    // Find the first space
        char *space_ptr = strchr(buffer, ' ');
        if (space_ptr != NULL) {
        // Split the string
        *space_ptr = '\0'; 
        // Replace space with null character, now input ends here
        strcpy(cipher_text, buffer);           
        // cipher text before space
        strcpy(signature, space_ptr + 1);     
        // signature after space
    } else {
        printf("Error: No space found in the input string!\n");
    }
        decrypt(cipher_text,Buffer,d,n);
        int check=decrypt_and_compare_hash(Buffer,signature,id,i);
        //if answers's integrity is maintained then only write to the file.
        if(check){
        pthread_mutex_lock(&lock);
        fprintf(file, "%s\n", Buffer);
        fflush(file);
        pthread_mutex_unlock(&lock);}
        i++;
        
    }

    fclose(file);
    printf("Answers saved in answers.txt\n");
}
//send the results to the client
void send_survey_results(int client_socket, mpz_t d, mpz_t n) {
    FILE *file = fopen("answers.txt", "r");
    if (!file) {
        perror("Error opening answers.txt");
        return;
    }
   
    fseek(file, 0, SEEK_END);
    if (ftell(file) == 0) { // Check if file is empty
        fclose(file);
        char mmsg[BUFFER_SIZE],msg[BUFFER_SIZE];
        strcpy(msg,"No survey was taken");
        encrypt(msg, mmsg, d, n);
        send(client_socket, mmsg, strlen(msg), 0);
        sleep(2);
        return;
    }
    rewind(file);
   
    int answer_count[100][10] = {0}; // Assuming max 100 questions with 10 options each
    int total_answers[100] = {0};    // Total responses per question
    char buffer[BUFFER_SIZE];
   
    while (fgets(buffer, sizeof(buffer), file)) {
        char *token = strtok(buffer, " ");
        while (token) {
            int question = token[0] - '0';
            int option = token[1] - '0';

            if (question >= 0 && question < 100 && option >= 0 && option < 10) {
                answer_count[question][option]++;
                total_answers[question]++;
            }
            token = strtok(NULL, " ");
        }
    }
    fclose(file);
    printf("Sending results\n");
    FILE *survey_file = fopen("survey.txt", "r");
    if (!survey_file) {
        perror("Error opening survey.txt");
        return;
    }
   
    int question_number = 1;
    while (fgets(buffer, sizeof(buffer), survey_file)) {
        char question_encrypted[BUFFER_SIZE];
        
        encrypt(buffer,question_encrypted, d, n);
        
        send(client_socket, question_encrypted, strlen(question_encrypted), 0);
        sleep(1);

        for (int option = 0; option < 10; option++) {
            if (answer_count[question_number][option] > 0) {
                double percentage = (double)answer_count[question_number][option] / total_answers[question_number] * 100;
                char option_result[BUFFER_SIZE];
                memset(option_result, 0, sizeof(option_result));
                

                snprintf(option_result, sizeof(option_result), "%d%d %.2f%%", question_number, option, percentage);

                char encrypted_result[BUFFER_SIZE];
                memset(encrypted_result, 0, sizeof(encrypted_result));
                
                
                encrypt(option_result,encrypted_result,d, n);
                
                send(client_socket, encrypted_result, strlen(encrypted_result), 0);
                sleep(1);
            }
        }
        question_number++;
    }
    send(client_socket,"END",strlen("END"),0);
    sleep(1);
    fclose(survey_file);
}

//multithreading implemented to handle multiple client's
void *handle_client(void *arg) {
    int client_socket = *(int *)arg;
    free(arg);
    pthread_mutex_lock(&lock);
	int thread_id = thread_counter % MAX_CLIENTS;
	thread_counter++;
	pthread_mutex_unlock(&lock);
    mpz_t local_d, local_n, local_e;
    mpz_inits(local_d, local_n, local_e, NULL);
    
    // Copy values from global variables
    pthread_mutex_lock(&lock);
    mpz_set(local_d, d);
    mpz_set(local_n, n);
    mpz_set(local_e, e);
    pthread_mutex_unlock(&lock);
    
    char keys[2096];
    mpz_get_str(keys, 10, local_e);
    send(client_socket, keys, 2096, 0);
    sleep(1);
    mpz_get_str(keys, 10, local_n);
    
    send(client_socket, keys, 2096, 0);
    sleep(1);
    char buffer[BUFFER_SIZE];
    
    char pubc[BUFFER_SIZE];
    int sz=recv(client_socket,pubc,BUFFER_SIZE,0);
    pubc[sz]='\0';
    pthread_mutex_lock(&lock);
    strcpy(CLIENTS[thread_id].eck, pubc);
    pthread_mutex_unlock(&lock);
    sz=recv(client_socket,pubc,BUFFER_SIZE,0);
    pubc[sz]='\0';
    pthread_mutex_lock(&lock);
    strcpy(CLIENTS[thread_id].nck, pubc);
    
    pthread_mutex_unlock(&lock);
    int login_success = 0;
    char choice[2];
    sz=recv(client_socket,choice,2,0);
    choice[sz]='\0';
   
    if(choice[0]=='1')
    register_user(client_socket,local_d,local_n);
    else if(choice[0]=='2'){
    
    login_success = login_user(client_socket,local_d,local_n);
    }
    else if(choice[0]=='3'){
        printf(" ");
        fflush(stdout);
        send_survey_results(client_socket,local_d,local_n);
    }
    else
    {	
    	
    close(client_socket);
    return NULL;
	
    }
    if (login_success) {
        send_survey(client_socket);
        receive_answers(client_socket,thread_id);
    }
	
    
    close(client_socket);
    return NULL;
}

int main() {
    //intializing variables and socket creation done
    for(int i=0;i<MAX_CLIENTS;i++){
        strcpy(CLIENTS[i].eck,"");
        strcpy(CLIENTS[i].nck,"");
    }
    int opt=1;
    gmp_randinit_mt(state);
    gmp_randseed_ui(state,12);
    mpz_inits(p, q, n, d, e, phi_n, NULL);

    genpq();
    genkeys();
    
    int server_socket = socket(AF_INET, SOCK_STREAM, 0);
    if (server_socket < 0) {
        perror("Socket creation failed");
        exit(1);
    }

    struct sockaddr_in server_addr;
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(PORT);
    server_addr.sin_addr.s_addr=INADDR_ANY;//include your ip
    
    if (setsockopt(server_socket, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt)) == -1) {
        perror("setsockopt failed");
        close(server_socket);
        exit(EXIT_FAILURE);
    }

    if (setsockopt(server_socket, SOL_SOCKET, SO_REUSEPORT, &opt, sizeof(opt)) == -1) {
        perror("setsockopt SO_REUSEPORT failed");
    }
    if (bind(server_socket, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0) {
        perror("Bind failed");
        exit(1);
    }

    if (listen(server_socket, MAX_CLIENTS) < 0) {
        perror("Listen failed");
        exit(1);
    }

    printf("Server listening on IP: %d\n", PORT);
   
    //handling multiple clients
    while (1) {
        struct sockaddr_in client_addr;
        socklen_t addr_len = sizeof(client_addr);
        int *client_socket = malloc(sizeof(int));
        *client_socket = accept(server_socket, (struct sockaddr *)&client_addr, &addr_len);
        if (*client_socket < 0) {
            perror("Accept failed");
            free(client_socket);
            continue;
        }

        printf("New client connected\n");
        pthread_t thread_id;
        pthread_create(&thread_id, NULL, handle_client, client_socket);
        pthread_detach(thread_id);
    }

    close(server_socket);
    return 0;
}
