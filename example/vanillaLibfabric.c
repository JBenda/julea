#include <glib.h>

#include <rdma/fabric.h>
#include <rdma/fi_endpoint.h>
#include <rdma/fi_rma.h>
#include <rdma/fi_cm.h>


// build connection
#include <sys/socket.h>

// parse address string
#include <stdio.h>
#include <stdlib.h>
#include <netdb.h>
#include <netinet/in.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <inttypes.h>

const char provider_name[] = "verbs";
const char server_address[] = "10.0.10.1";
const enum fi_ep_type endpoint_type = FI_EP_MSG; // FI_EP_MSG // FI_EP_RDM // FI_EP_DGRAM
const char message[] = "Hello :)"; 
const uint32_t server_port = 47592;

#define PP_CLOSE_FID(fd) \
	do { \
		int ret; \
		if((fd)) {  \
			ret = fi_close(&(fd)->fid); \
			if(ret) { \
				g_error("failed to close fid!"); \
				fd = NULL; \
			} \
		} \
	} while(0) \

struct {
	struct fi_info* hints;
	struct {
		char* dst_addr;
		uint32_t dst_port;
	} opts;
	int ctrl_connfd;
	void* ctrl_buf;
	char is_server;
	struct fid_cq* txcq;
	struct fid_cq* rxcq;
	void* ctx;
	struct fid_ep* ep;
	struct fid_pep* pep;
	struct fi_info* fi;
	struct fi_info* fi_pep;
	struct fid_fabric* fabric;
	struct fid_eq* eq;
	struct fi_eq_attr eq_attr;
	struct fid_domain* domain;
	struct fid_av* av;
	struct fid_mr* mr;
	fi_addr_t local_fi_addr, remote_fi_addr;
} ct;

void free_ct(void);
void run_msg(void);
void init_client(void);
void init_server(void);
void msg_client(void);
void msg_server(void);
int parse_address(char* address, uint16_t port,  struct addrinfo** result);
void server_connect(void);
char verify_cq(uint64_t msg_len);
struct fi_info* get_info(void);
void open_ep(void);
void client_connect(void);

void free_ct(void) {
	if(ct.hints) {
		fi_freeinfo(ct.hints);
		ct.hints = NULL;
	}
}

int parse_address(char* address, uint16_t port, struct addrinfo** result) {
	int ret;
	const char* err_msg;
	char port_s[6];

	// interface for address resolving
	struct addrinfo hints = {
		.ai_family = AF_INET,
		.ai_socktype = SOCK_STREAM,
		.ai_protocol = IPPROTO_TCP,
		.ai_flags = AI_NUMERICSERV
	};
	snprintf(port_s, 6, "%" PRIu16, port);
	ret = getaddrinfo(address, port_s, &hints, result);
	if(ret != 0) {
		err_msg = gai_strerror(ret);
		g_error("getarrdinfo error: %s", err_msg);
		ret = -EXIT_FAILURE;
	} else if (*result == NULL) {
		g_error("parse address gives no results!");
		ret = -EXIT_FAILURE;
	} else {
		ret = EXIT_SUCCESS;
	}
	return ret;
}

void init_client(void) {
	int ret;
	struct addrinfo* itr;

	struct addrinfo* address = malloc(sizeof(struct addrinfo));
	ret = parse_address(ct.opts.dst_addr, ct.opts.dst_port, &address);
	if(ret) return;

	for(itr = address; itr;itr = itr->ai_next) {
		ct.ctrl_connfd = socket(itr->ai_family, itr->ai_socktype, itr->ai_protocol);
		if(ct.ctrl_connfd == -1) {
			continue;
		}
		ret = connect(ct.ctrl_connfd, itr->ai_addr, itr->ai_addrlen);
		if(ret != -1) { break; }
		// close(ct.ctrl_connfd); TODO
	}
	if(!itr || ret == -1) {
		g_error("failed to connect!");
	}
	freeaddrinfo(address);
}
char verify_cq(uint64_t msg_len) {
	int ret;
	struct fi_cq_err_entry comp;
	uint64_t msg_cnt = 0;

	while(msg_cnt < msg_len) {
		ret = fi_cq_read(ct.txcq, &comp, 1);
		if(ret < 0 && ret != -FI_EAGAIN) {
			g_error("failed to verify len!");
			return 0; 
		}
		msg_cnt += ret;
	}
	return 1;
}

struct fi_info* get_info(void) {
	struct fi_info* info;
	fi_getinfo(FI_VERSION(FI_MAJOR_VERSION, FI_MINOR_VERSION), NULL, NULL, 0, ct.hints, &info);
	// maybe setup ct.rx_ctx_ptr
	return info;
}

void open_ep(void) {
	// open endpoint!
	int ret;
	struct fi_cq_attr attrs;
	struct fi_av_attr a_attrs;
	attrs.wait_obj = FI_WAIT_NONE;
	attrs.size = ct.fi->tx_attr->size;
	ret = fi_cq_open(ct.domain, &attrs, &ct.txcq, &ct.txcq);
	if(ret) { g_error("failed to open tx c queue"); return; }
	attrs.size = ct.fi->rx_attr->size;
	ret = fi_cq_open(ct.domain, &attrs, &ct.rxcq, &ct.rxcq);
	if(ret) { g_error("failed to open rx c queue"); return; }
	// endpoint type check!
	if(ct.fi->ep_attr->type != endpoint_type) {
		g_error("wong ep type!"); return; }
	if(endpoint_type == FI_EP_RDM || endpoint_type == FI_EP_DGRAM) {
		if(ct.fi->domain_attr->av_type != FI_AV_UNSPEC) {
			a_attrs.type = ct.fi->domain_attr->av_type;
		}
		ret = fi_av_open(ct.domain, &a_attrs, &ct.av, NULL);
		if(ret) { g_error("failed to open av!"); return; }
	}
	if (ct.fi->tx_attr->mode & FI_MSG_PREFIX)
	{g_error("hanlde prefixes!"); return; }
	if (ct.fi->rx_attr->mode & FI_MSG_PREFIX)
	{g_error("hanlde prefixes!"); return; }
	ret = fi_endpoint(ct.domain, ct.fi, &ct.ep, NULL);
	if(ret) { g_error("failed to open endpoint!"); return; }
}

void client_connect(void) {
	struct fi_eq_cm_entry entry;
	uint32_t event;
	int ret;
	const char* name; // rem_name

	// read name len
	uint32_t len;
	recv(ct.ctrl_connfd, (char*)&len, sizeof(len), 0);
	len = ntohl(len);

	// read addr format and addr
	recv(ct.ctrl_connfd, (char*)&ct.hints->addr_format, sizeof(ct.hints->addr_format), 0);
	ct.hints->dest_addr = malloc(len);
	ct.hints->dest_addrlen = len;


	ct.fi = get_info();
	ret = fi_fabric(ct.fi->fabric_attr, &(ct.fabric), NULL);
	if(ret) { g_error("failed to open fabric!"); return; }
	ret = fi_eq_open(ct.fabric, &(ct.eq_attr), &(ct.eq), NULL);
	if(ret) { g_error("failed to open event queue!"); return; }
	ret = fi_domain(ct.fabric, ct.fi, &(ct.domain), NULL);
	if(ret) { g_error("failed to open domain!"); return; }

	open_ep();


	if(endpoint_type == FI_EP_MSG) {
		ret = fi_ep_bind(ct.ep, &ct.eq->fid, 0);
		if(ret) { g_error("failed to bind eq!"); return; }
	} else {
		ret = fi_ep_bind(ct.ep, &ct.av->fid, 0);
		if(ret) { g_error("failed to bind av!"); return; }
	}
	ret = fi_ep_bind(ct.ep, &ct.txcq->fid, FI_TRANSMIT);
	if(ret) { g_error("failed to bind tx!"); return; }
	ret = fi_ep_bind(ct.ep, &ct.rxcq->fid, FI_RECV);
	if(ret) { g_error("failed to bind rx!"); return; }
	ret = fi_enable(ct.ep);
	if(ret) { g_error("failed to enable ep!"); return; }

	ret = fi_connect(ct.ep, name, NULL, 0);
	if(ret) { g_error("failed to connect!"); return; }
	ret = fi_eq_sread(ct.eq, &event, &entry, sizeof(entry), -1, 0);
	if(ret != sizeof(entry)) {
		g_error("failed read connetcion result!"); return; }
	if(event != FI_CONNECTED || entry.fid != &ct.ep->fid) {
		g_error("connection denied!"); return;
	}
}

void server_connect(void) {
	struct fi_eq_cm_entry entry;
	uint32_t event;
	size_t addrlen = 0;
	uint32_t len = 0;
	int ret;
	struct fi_info* p_info;

	p_info = get_info();
	ret = fi_fabric(p_info->fabric_attr, &ct.fabric, NULL);
	if(ret) { g_error("failed to create fabric"); return; }
	ret = fi_eq_open(ct.fabric, &ct.eq_attr, &ct.eq, NULL);
	if(ret) { g_error("failed to create eq"); return; }
	ret = fi_passive_ep(ct.fabric, p_info, &ct.pep, NULL);
	if(ret) { g_error("failed to create pep"); return; }
	ret = fi_pep_bind(ct.pep, &ct.eq->fid, 0);
	if(ret) { g_error("failed to bind pep"); return; }
	ret = fi_listen(ct.pep);
	if(ret) { g_error("failet do start listen!"); return; }


	// send name
	void* name = NULL;
	ret = fi_getname(&ct.pep->fid, name, &addrlen);
	if((ret != -FI_ETOOSMALL) || (addrlen <= 0)) {
		g_error("failed to fetch name len!");
		return;
	}
	name = malloc(addrlen);
	ret = fi_getname(&ct.pep->fid, name, &addrlen);
	if(ret) { g_error("failed to fetch name!"); return; }

	len = htonl(addrlen);
	send(ct.ctrl_connfd, (char*)&len, sizeof(len), 0);
	send(ct.ctrl_connfd, &ct.fi_pep->addr_format, sizeof(ct.fi_pep->addr_format), 0);
	send(ct.ctrl_connfd,name, addrlen, 0);
	
	// wait for client
	ret = fi_eq_sread(ct.eq, &event, &entry, sizeof(entry), -1, 0);
	if(ret != sizeof(entry)) {
		g_error("failing listen for client on pep!"); return;
	}
	if(event != FI_CONNREQ) {
		g_error("reciving otherthings then CM!"); return;
	}
	ct.fi = entry.info;
	ret = fi_domain(ct.fabric, ct.fi, &ct.domain, NULL);
	if(ret) { g_error("failed to start domain!"); return; }

	open_ep();

	ret = fi_accept(ct.ep, NULL, 0);
	if(ret) { g_error("failed to accept!"); return; }

	ret = fi_eq_sread(ct.eq, &event, &entry, sizeof(entry), -1, 0);
	if(ret != sizeof(entry)) { g_error("failed to read accept!"); return; }
	if(event != FI_CONNECTED | entry.fid != &ct.ep->fid) {
		g_error("no accept message?"); return;
	}


}


void msg_client(void){
	int ret;

	init_client();
	client_connect();
	
	// maybe sync?
	
	// sending a message
	char* tx_buf = malloc(sizeof(message));
	memcpy(tx_buf, message, sizeof(message));
	const uint64_t msg_len = sizeof(message);
	while(1) { 
		ret = fi_send(
				ct.ep,
				tx_buf,
				msg_len,
				fi_mr_desc(ct.mr),
				ct.remote_fi_addr,
				ct.ctx);
		if(!ret) break;
		if(ret != -FI_EAGAIN) { g_error("send failed!"); return; }
	}
	verify_cq(msg_len);
}

void msg_server(){
	int ret;

	init_server();
	server_connect();

	// reciving a message
	char* rx_buf = malloc(sizeof(message));
	const uint64_t msg_len = sizeof(message);
	// verify_cq(??rx_seq??);
	while(1) {
		ret = fi_recv(
			ct.ep,
			rx_buf,
			msg_len,
			fi_mr_desc(ct.mr),
			0,
			ct.ctx);
		if(!ret) break;
		if(ret != -FI_EAGAIN) { g_error("recive failed!"); return; }
	}
	if(!verify_cq(msg_len)) { g_error("verification failed!"); return; }
	g_message("recived message: %s", rx_buf);

}

void run_msg(void) {
	if(ct.is_server) {msg_server();}
	else {msg_client();}
}



int main(int argc, char** argv) {
	if (argc != 2) { g_error("expect 1 argument [client|server]"); return EXIT_FAILURE; }
	if(strcmp(argv[1], "client") == 0) { ct.is_server = 0; }
	else if (strcmp(argv[1], "server") == 0) { ct.is_server = 1; }
	else { g_error("expect client or server, not '%s'.", argv[1]); return EXIT_FAILURE; }

	char* p_name = malloc(sizeof(provider_name));
	memcpy(p_name, provider_name, sizeof(provider_name));
	char* s_address = malloc(sizeof(server_address));
	memcpy(s_address, server_address, sizeof(server_address));

	int ret = EXIT_SUCCESS;

	ct.hints = fi_allocinfo();
	if(!ct.hints) return EXIT_FAILURE;
	ct.hints->caps = FI_MSG;
	ct.hints->mode = FI_CONTEXT | FI_CONTEXT2 | FI_MSG_PREFIX;
	ct.hints->domain_attr->mr_mode = FI_MR_LOCAL; // | OFI_MR_BASIC_MAP;
	ct.hints->fabric_attr->prov_name = p_name;
	ct.hints->ep_attr->type = endpoint_type; 
	ct.opts.dst_addr = s_address;
	ct.opts.dst_port = server_port;
	ct.eq_attr.wait_obj = FI_WAIT_UNSPEC;

	switch (endpoint_type) {
	case FI_EP_MSG: run_msg(); break;
	default: g_error("Endpoint not supported!"); ret = EXIT_FAILURE;
	}
	fi_shutdown(ct.ep,0);

	free_ct();
	return -ret;
}
