//client side code included all libraries
#include <bits/stdc++.h>
#include <unistd.h>
#include <sys/socket.h>
#include <arpa/inet.h>  
#include<gmp.h>
#include <openssl/evp.h>
#include <iomanip>
#include <sstream>
using namespace std;
//defined required variables.
#define PORT 8888
#define SIZE 100
#define BUFFER_SIZE 4096
mpz_t ea,na;
typedef long long unsigned int number;

// hashing implemented using openssl library

string hashed_password_to_string(const unsigned char* hashed_password, size_t length) {
    stringstream ss;
    for (size_t i = 0; i < length; ++i) {
        ss << std::setw(2) << std::setfill('0') << std::hex << (int)hashed_password[i];
    }
    return ss.str();
}


void sha512_hash(const char *password, unsigned char *output) {
    EVP_MD_CTX *mdctx = EVP_MD_CTX_new();
    if (mdctx == NULL) {
        printf("Error creating EVP_MD_CTX\n");
        exit(1);
    }

    if (EVP_DigestInit_ex(mdctx, EVP_sha512(), NULL) != 1) {
        printf("Error initializing SHA-512\n");
        EVP_MD_CTX_free(mdctx);
        exit(1);
    }

    if (EVP_DigestUpdate(mdctx, password, strlen(password)) != 1) {
        printf("Error updating SHA-512\n");
        EVP_MD_CTX_free(mdctx);
        exit(1);
    }

    unsigned int len;
    if (EVP_DigestFinal_ex(mdctx, output, &len) != 1) {
        printf("Error finalizing SHA-512\n");
        EVP_MD_CTX_free(mdctx);
        exit(1);
    }

    EVP_MD_CTX_free(mdctx);
}


// RSA key generation using gmp library
void genpq(mpz_t p,mpz_t q,gmp_randstate_t state){
    mpz_rrandomb(p,state,1024);
    mpz_rrandomb(q,state,1024);
    mpz_nextprime(p,p);
    mpz_nextprime(q,q);
}

void genkeys(mpz_t n,mpz_t e,mpz_t d,mpz_t p,mpz_t q){
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
        break;
        }
        if(mpz_cmp(i,phi_n)>0)
        break;
        mpz_add_ui(i,i,1);
    }
    mpz_invert(d,e,phi_n);

    mpz_clear(p_1);
    mpz_clear(q_1);
    mpz_clear(gcd);
    mpz_clear(phi_n);
    mpz_clear(modinv);
    mpz_clear(i);
    }

//encrypting message using same logic as in server side
void encrypt_message(const char *msg, char *encrypted_str, mpz_t e, mpz_t n) {
    mpz_t M, C;
    mpz_inits(M, C, NULL);
   
    char ascii_rep[BUFFER_SIZE * 3] = "";  
    for (int i = 0; msg[i] != '\0'; i++) {
        char temp[4];
        sprintf(temp, "%03d", (int)msg[i]);
        strcat(ascii_rep, temp);
    }
    mpz_set_str(M, ascii_rep, 10);
    mpz_powm(C, M, e, n);  
    mpz_get_str(encrypted_str, 10, C);  
    mpz_clears(M, C, NULL);
}
//decoding cipher text
string decodeCT(const char ctmsg[], int size, mpz_t ea, mpz_t na) {
    mpz_t C, M;
    mpz_inits(C, M, NULL);

   
    string ct_clean(ctmsg, size); 
    mpz_set_str(C, ct_clean.c_str(), 10);

    
    mpz_powm(M, C, ea, na);

    
    char* ascii_rep = mpz_get_str(NULL, 10, M);
    int len = strlen(ascii_rep);

    int pad_len = (3 - (len % 3)) % 3;
    string padded_ascii = string(pad_len, '0') + ascii_rep;

    
    string actual_msg;
    for (size_t i = 0; i < padded_ascii.length(); i += 3) {
        string block = padded_ascii.substr(i, 3);
        try {
            int ascii_code = stoi(block);
            actual_msg += static_cast<char>(ascii_code);
        } catch (const exception& e) {
            cerr << "Decode error with block '" << block << "': " << e.what() << endl;
        }
    }

    free(ascii_rep);
    mpz_clears(C, M, NULL);

    return actual_msg;
}

//reading survey from local file and then answering survey with suitable mechanism to maintain integrity of answers and confidentiality of answers also
void read_and_answer_survey(int client_socket, mpz_t ef, mpz_t nf) {
    ifstream file("local.txt", ios::in);
    if (!file.is_open()) {
        perror("Error opening local.txt");
        return;
    }

    char question[BUFFER_SIZE];
    char answer[10];
    int question_count = 0;

    while (file.getline(question, sizeof(question))) {
        cout << question << endl;

        cout << "Enter your answer: ";
        cin >> answer;
        char encrypted_hash[4096],enc_ans[4096];
        // Compute SHA-512 hash of the answer
        unsigned char hash[EVP_MAX_MD_SIZE];
        sha512_hash(answer, hash);
        
        
        string hashed_str = hashed_password_to_string(hash, 64);
        
        
        char messsage[BUFFER_SIZE];
        //encrypt the hash using clients private key(signature).
        encrypt_message(hashed_str.c_str(), encrypted_hash, ef, nf);
        //encrypt answer using server's public key for confidentiality.
        encrypt_message(answer,enc_ans,ea,na);
        string message = string(enc_ans) + " " + string(encrypted_hash);
        // Send the message to the server
        send(client_socket, message.c_str(), strlen(message.c_str()), 0);
        sleep(1);

        question_count++;
    }

    file.close();
    cout << "All questions answered." << endl;

    // Notify the server that all answers are sent
    send(client_socket, "END\n", 4, 0);
    sleep(1);
}

// Register
void register_user(mpz_t e, mpz_t n, int sfd) {
    string username;
    string password;
    unsigned char hashed_password[EVP_MAX_MD_SIZE];

    cout << "Enter username: ";
    cin >> username;

    cout << "Enter password: ";
    cin >> password;

   
    char encrypted_username[4096];  
    encrypt_message(username.c_str(), encrypted_username, e, n);


    sha512_hash(password.c_str(), hashed_password);
    string hashed_password_str = hashed_password_to_string(hashed_password, 64);

    cout << endl;
    

   send(sfd, encrypted_username, strlen(encrypted_username), 0);  
   sleep(1);
   send(sfd, hashed_password_str.c_str(), hashed_password_str.size(), 0);
   sleep(1);
}
//recieve survey and write it to local file.
void receiveAndWriteToFile(int sfd) {
    char buffer[BUFFER_SIZE]; 
    int size;
    
    ofstream outFile("local.txt", ios::out | ios::binary);
    if (!outFile) {
        cerr << "Error opening file!" << endl;
        return;
    }

    while ((size = recv(sfd, buffer, sizeof(buffer) - 1, 0)) > 0) {
        buffer[size] = '\0';  
        string Buffer=decodeCT(buffer,size,ea,na);
        if (Buffer == "end") { 
            break;
        }

        outFile.write(Buffer.c_str(), Buffer.length());
    }

    outFile.close();
    
}
//viewing the results
void view_result(int sfd) {
    char buffer[BUFFER_SIZE];
    
    cout << "Survey Results:\n";
    
    while (true) {
        ssize_t size = recv(sfd, buffer, sizeof(buffer) - 1, 0);

        if (size <= 0) {
            break; 
        }
        
        buffer[size] = '\0'; 
        
        
        if (strcmp(buffer, "END") == 0) {
            break; 
        }
        string Buffer=decodeCT(buffer,size,ea,na);
        cout << Buffer << endl; 
        fflush(stdout);
    }
    
    cout << "End of Results.\n";
}
int main() {
    //initalize variables and keys and connect to the server
    gmp_randstate_t state;
    gmp_randinit_mt(state);
    gmp_randseed_ui(state, 10);
   
    int sfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sfd == -1) {
        cout << "Error while creating socket!" << endl;
       
    }

    struct sockaddr_in addr;
    addr.sin_family = AF_INET;
    addr.sin_port = htons(PORT);
    addr.sin_addr.s_addr = INADDR_ANY; //your IP
    int c = connect(sfd, (struct sockaddr*)&addr, sizeof(addr));
    if (c == -1) {
        cout << "Error while connecting!" << endl;
    }


    mpz_t p, q, n, e, d;
    mpz_inits(p, q, n, e, d, NULL);
    genpq(p, q, state);
    genkeys(n, e, d, p, q);
    //exchanging of keys

    char pua[BUFFER_SIZE];
    int sz=recv(sfd,pua,BUFFER_SIZE,0);
    pua[sz]='\0';
    
    mpz_inits(ea,NULL);
    mpz_set_str(ea,pua,10);
    sz=recv(sfd,pua,BUFFER_SIZE,0);
    pua[sz]='\0';
    mpz_inits(na,NULL);
    mpz_set_str(na,pua,10);
    
    

//  send

    char pub_key[4096];
    mpz_get_str(pub_key, 10, e);
    send(sfd, pub_key, strlen(pub_key), 0);
    sleep(1);
    mpz_get_str(pub_key, 10, n);
    send(sfd, pub_key, strlen(pub_key), 0);
    sleep(1);
   

// login and register
   int ch;
   cout<<"1. Register\n2. Login\n3. View Results\n4. Exit\nEnter your choice: ";
   cin>>ch;
   string choice_str = to_string(ch);
   send(sfd, choice_str.c_str(), choice_str.size(), 0);
   sleep(1);
   int login_succes=0;
   switch (ch) {
            case 1:
                register_user(ea, na,sfd);
                break;
            case 2:
               register_user(ea,na,sfd);
                break;
            case 3:
                view_result(sfd);
                return 0;
            case 4:
                printf("Exiting program.\n");
                close(sfd);
                return 0;
            default:
                printf("Invalid choice. Please try again.\n");
                close(sfd);
                return 0;
        }
   

    char buffer[BUFFER_SIZE];
    ssize_t size;
    if((size = recv(sfd, buffer, sizeof(buffer) - 1, 0)) > 0) {

    cout<<buffer<<endl;
    if(strcmp(buffer,"Login Succesfull")==0)
    login_succes=1;
    buffer[size] = '\0';
    }
    if(login_succes==1){
    receiveAndWriteToFile(sfd);
        read_and_answer_survey(sfd,d,n);
    }
    close(sfd);
    return 0;
}