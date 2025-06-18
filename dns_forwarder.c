#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <sys/socket.h>
#include <getopt.h>
#include <netinet/in.h>
#include <curl/curl.h>
#include <openssl/bio.h>
#include <openssl/evp.h>

#define DOMAIN_NAME_LIMIT 256
#define MAX_RESPONSE_SIZE 1024

typedef struct {
    char* data;
    size_t size;
} MemoryStruct;

char *base64_encode(const unsigned char *input, int length) {
    BIO *bio, *b64;
    char *encoded;
    long encoded_size;

    // Create a BIO chain for base64 encoding
    b64 = BIO_new(BIO_f_base64());
    if (!b64) {
        perror("BIO_new BIO_f_base64 failed");
        return NULL;
    }

    bio = BIO_new(BIO_s_mem());
    if (!bio) {
        perror("BIO_new BIO_s_mem failed");
        BIO_free_all(b64);
        return NULL;
    }

    bio = BIO_push(b64, bio); 

    // Write the input data into the BIO chain for encoding
    BIO_write(bio, input, length);
    BIO_flush(bio);

    // Get the length of the base64-encoded data
    encoded_size = BIO_get_mem_data(bio, &encoded);
    if (encoded_size < 0) {
        perror("BIO_get_mem_data failed");
        BIO_free_all(bio);
        return NULL;
    }

    // Create a copy of the encoded data
    char *result = strndup(encoded, encoded_size);
    
    // Clean up the BIO chain and free resources
    BIO_free_all(bio);

    return result;
}

// Callback to handle the response data
size_t write_data_callback(void *contents, size_t size, size_t nmemb, void *user_data_ptr) {
    size_t actual_size = size * nmemb;
    MemoryStruct *mem = (MemoryStruct *)user_data_ptr;
    char *ptr = realloc(mem->data, mem->size + actual_size + 1);
    if (ptr == NULL) {
        printf("Memory is not enough - realloc returned NULL\n");
        return 0;
    }
    mem->data = ptr;
    memcpy(&(mem->data[mem->size]), contents, actual_size);
    mem->size += actual_size;
    mem->data[mem->size] = 0;
    return actual_size;
}

// Function to URL encode the base64 DNS query
char *url_encode(const char *str) {
    CURL *curl = curl_easy_init();
    char *encoded = NULL;

    if (curl) {
        encoded = curl_easy_escape(curl, str, 0);
        curl_easy_cleanup(curl);
    }

    return encoded;
}

// Function to perform DNS-over-HTTPS request
void perform_doh_request(const char *dns_msg, size_t dns_msg_len, const char *server, char **dns_response, size_t *dns_response_len) {
    CURL *curl;
    CURLcode res;
    char url[1024]; 
    MemoryStruct chunk;
    chunk.data = malloc(1); 
    chunk.size = 0;

    curl = curl_easy_init();
    if (curl) {
        // Step 1: Base64 encode the DNS query
        char *encoded_dns = base64_encode((const unsigned char *)dns_msg, dns_msg_len);
        if (encoded_dns == NULL) {
            fprintf(stderr, "Base64 encoding failed\n");
            return;
        }

        // Step 2: URL encode the base64-encoded DNS query (URL-safe base64)
        char *url_encoded_dns = url_encode(encoded_dns);
        free(encoded_dns); 

        if (url_encoded_dns == NULL) {
            fprintf(stderr, "URL encoding failed\n");
            return;
        }

        // Step 3: Create the DoH URL with the DNS query as a parameter
        snprintf(url, sizeof(url), "https://%s/dns-query?dns=%s", server, url_encoded_dns);
        curl_free(url_encoded_dns); 

        // Step 4: Set up curl options
        curl_easy_setopt(curl, CURLOPT_URL, url);
        curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_data_callback);
        curl_easy_setopt(curl, CURLOPT_WRITEDATA, (void *)&chunk);

        // Step 5: Perform the HTTP request
        res = curl_easy_perform(curl);
        if (res != CURLE_OK) {
            fprintf(stderr, "curl_easy_perform() failed: %s\n", curl_easy_strerror(res));
        } else {
            *dns_response = chunk.data;
            *dns_response_len = chunk.size;
        }

        // Clean up
        curl_easy_cleanup(curl);
    }
}

void dispatch_nxdomain_response(int sockfd, const char* dns_msg, size_t dns_msg_len, const struct sockaddr_in* client_address, socklen_t client_address_length) {
    char response[MAX_RESPONSE_SIZE];
    size_t response_len = dns_msg_len;  
    
    memcpy(response, dns_msg, dns_msg_len);  
    
    // Set the response flag (mark as response) and NXDOMAIN response code
    response[2] |= 0x80;  
    response[3] &= 0xF0;  
    response[3] |= 0x03;  
    
    // Set the answer section length to 0 (No answers in NXDOMAIN)
    response[6] = 0;  
    response[7] = 0;
    
    // Adjust response length to account for the lack of answer section
    response_len = 12; 

    // Send the response back to the client
    ssize_t sent_bytes = sendto(sockfd, response, response_len, 0, (const struct sockaddr*)client_address, client_address_length);
    if (sent_bytes < 0) {
        perror("sendto failed");
    } else {
        printf("Sent NXDOMAIN response to client\n");
    }
}


void load_deny_list(const char* denylist_filename, char** deny_list, int* deny_list_size) {
    FILE* file = fopen(denylist_filename, "r");
    if (file == NULL) {
        perror("Error while opening the file");
        exit(1);
    }
    char line[DOMAIN_NAME_LIMIT];
    while (fgets(line, sizeof(line), file)) {
        line[strcspn(line, "\n")] = '\0';  
        deny_list[*deny_list_size] = strdup(line);
        (*deny_list_size)++;
    }
    fclose(file);
}

char* extract_domain(const char* dns_msg, size_t dns_msg_len) {
    if (dns_msg_len < 12) {
        return NULL;  
    }

    const unsigned char* p = (const unsigned char*)dns_msg + 12;  
    int len = *p;
    if (len == 0) {
        return NULL; 
    }

    char* domain = malloc(DOMAIN_NAME_LIMIT);
    int domain_len = 0;
    while (len != 0) {
        p++;
        memcpy(domain + domain_len, p, len);
        domain_len += len;
        p += len;
        len = *p;  
        if (len != 0) {
            domain[domain_len] = '.'; 
            domain_len++;
        }
    }
    domain[domain_len] = '\0'; 
    return domain;
}


int main(int argc, char* argv[]) {
    char* dst_ip = NULL;
    char* deny_list_file = NULL;
    char* log_filename = NULL;
    int use_doh = 0;
    char* doh_server_address = NULL;

    int opt;
    struct option long_options[] = {
        {"dst_ip", required_argument, NULL, 'd'},
        {"deny_list_file", required_argument, NULL, 'f'},
        {"log_filename", required_argument, NULL, 'l'},
        {"doh", no_argument, &use_doh, 1},
        {"doh_server_address", required_argument, NULL, 0},
        {NULL, 0, NULL, 0}
    };

    while ((opt = getopt_long(argc, argv, "d:f:l:", long_options, NULL)) != -1) {
        switch (opt) {
            case 'd':
                dst_ip = optarg;
                break;
            case 'f':
                deny_list_file = optarg;
                break;
            case 'l':
                log_filename = optarg;
                break;
            case 0:
                if (strcmp(long_options[optind - 1].name, "doh_server_address") == 0) {
                    doh_server_address = optarg;
                }
                break;
            case '?':
                fprintf(stderr, "Usage: %s [-d DST_IP] -f DENY_LIST_FILE [-l log_filename] [--doh] [--doh_server_address doh_server_address]\n", argv[0]);
                exit(1);
        }
    }

    if (deny_list_file == NULL) {
        fprintf(stderr, "Deny list file (deny_list_file.txt) is required.\n");
        exit(1);
    }

    for (int i = optind; i < argc; i++) {
        if (strcmp(argv[i], "--doh") == 0) {
            use_doh = 1;
        } else if (strcmp(argv[i], "--doh_server_address") == 0) {
            if (i + 1 < argc) {
                doh_server_address = argv[++i];
            } else {
                fprintf(stderr, "--doh_server_address option requires an argument.\n");
                exit(1);
            }
        }
    }

    char* deny_list[256];
    int deny_list_size = 0;
    load_deny_list(deny_list_file, deny_list, &deny_list_size);

    FILE* log_file_pointer = NULL;
    if (log_filename != NULL) {
        log_file_pointer = fopen(log_filename, "a");
        if (log_file_pointer == NULL) {
            perror("Error while opening the log file");
            exit(1);
        }
    }

    int sockfd = socket(AF_INET, SOCK_DGRAM, 0);
    if (sockfd < 0) {
        perror("Error while creating the socket");
        exit(1);
    }

    struct sockaddr_in server_address;
    memset(&server_address, 0, sizeof(server_address));
    server_address.sin_family = AF_INET;
    server_address.sin_addr.s_addr = inet_addr("127.0.0.1");
    server_address.sin_port = htons(5354);
    printf("IP Address: %s\n", inet_ntoa(server_address.sin_addr));
    printf("Port: %d\n", ntohs(server_address.sin_port));

    if (bind(sockfd, (const struct sockaddr*)&server_address, sizeof(server_address)) < 0) {
        perror("Error while binding the socket");
        exit(1);
    }

    printf("DNS forwarder started!!\n");

    while (1) {
        char buffer[MAX_RESPONSE_SIZE];
        struct sockaddr_in client_address;
        socklen_t len = sizeof(client_address);

        ssize_t n = recvfrom(sockfd, buffer, sizeof(buffer), 0, (struct sockaddr*)&client_address, &len);
        if (n < 0) {
            perror("Error while receiving the data");
            continue;
        }
        else {
            printf("Received %zd bytes from client\n", n);
            printf("Received DNS Query:\n");
            for (int i = 0; i < n; i++) {
                printf("%02x ", (unsigned char)buffer[i]);
            }
            printf("\n");
        }

        char* domain = extract_domain(buffer, n);
        if (domain == NULL) {
            fprintf(stderr, "Error while extracting domain from DNS message\n");
            continue;
        }
        printf("Domain: %s\n", domain);

        int denied = 0;
        for (int i = 0; i < deny_list_size; i++) {
            if (strcmp(domain, deny_list[i]) == 0) {
                denied = 1;
                break;
            }
        }

        if (denied) {
            dispatch_nxdomain_response(sockfd, buffer, n, &client_address, len);
            if (log_file_pointer != NULL) {
                fprintf(log_file_pointer, "%s DENY\n", domain);
                fflush(log_file_pointer);
            }
        } else {
            if (use_doh || doh_server_address != NULL) {
                char* dns_response = NULL;
                size_t dns_response_len = 0;
                perform_doh_request(buffer, n, doh_server_address ? doh_server_address : "8.8.8.8", &dns_response, &dns_response_len);
                sendto(sockfd, dns_response, dns_response_len, 0, (const struct sockaddr*)&client_address, len);
                printf("Sent %zd bytes to client\n", n);
                free(dns_response);
            } else {
                struct sockaddr_in resolver_addr;
                memset(&resolver_addr, 0, sizeof(resolver_addr));
                resolver_addr.sin_family = AF_INET;
                resolver_addr.sin_port = htons(5354);
                if (dst_ip == NULL || strlen(dst_ip) == 0) {
                    fprintf(stderr, "Error: dst_ip is NULL or empty\n");
                    continue;
                }
                if (inet_pton(AF_INET, dst_ip, &resolver_addr.sin_addr) <= 0) {
                    perror("Invalid destination IP address");
                    continue;
                }

                sendto(sockfd, buffer, n, 0, (const struct sockaddr*)&resolver_addr, sizeof(resolver_addr));

                char response[MAX_RESPONSE_SIZE];
                ssize_t dns_response_len = recvfrom(sockfd, response, sizeof(response), 0, NULL, NULL);
                if (dns_response_len < 0) {
                    perror("Error while receiving response from resolver");
                    continue;
                }

                sendto(sockfd, response, dns_response_len, 0, (const struct sockaddr*)&client_address, len);
            }

            if (log_file_pointer != NULL) {
                fprintf(log_file_pointer, "%s ALLOW\n", domain);
                fflush(log_file_pointer);
            }
        }

        free(domain);
    }

    close(sockfd);

    if (log_file_pointer != NULL) {
        fclose(log_file_pointer);
    }

    for (int i = 0; i < deny_list_size; i++) {
        free(deny_list[i]);
    }

    return 0;
}