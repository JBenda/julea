#include <glib.h>

#include <rdma/fabric.h>
#include <rdma/fi_endpoint.h>
#include <rdma/fi_rma.h>
#include <rdma/fi_cm.h>


// build connection
#include <sys/socket.h>
#include <stdlib.h>
#include <stdio.h>
#include <sys/uio.h>

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
	struct fid_fabric* fabric;
	struct fid_eq* eq;
	struct fi_eq_attr eq_attr;
	struct fid_domain* domain;
	struct fid_av* av;
	struct fid_mr* mr;
	struct fid_mr no_mr;
	fi_addr_t local_fi_addr, remote_fi_addr;
	char* buf;
	int buf_size;
} ct;

void free_ct(void);
void run_msg(void);
void init_client(void);
void msg_client(void);
void msg_server(void);
int parse_address(char* address, uint16_t port,  struct addrinfo** result);
void server_connect(void);
char verify_cq(struct fid_cq* cq, uint64_t count);
struct fi_info* get_info(void);
void open_ep(void);
void client_connect(void);
void init_server(void);
void init_ep(void);
void init_mr(void);
int remaining_bytes_cq(void);

void free_ct(void) {
	if(ct.hints) {
		fi_freeinfo(ct.hints);
		ct.hints = NULL;
	}
	if(ct.fi) {
		fi_freeinfo(ct.fi);
		ct.fi = NULL;
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
		g_error("socket: failed to connect!");
	}
	freeaddrinfo(address);
}
char verify_cq(struct fid_cq* cq, uint64_t count) {
	int ret;
	struct fi_cq_err_entry comp;
	uint64_t msg_cnt = 0;

	while(msg_cnt < count) {
		ret = fi_cq_read(cq, &comp, 1);
		if(ret > 0) {
			msg_cnt += ret;
		}
		if(ret < 0 && ret != -FI_EAGAIN) {
			g_error("failed to verify len!");
			return 0; 
		}
	}
	return 1;
}

struct fi_info* get_info(void) {
	struct fi_info* info;
	int ret;
	ret = fi_getinfo(FI_VERSION(1, 11), NULL, NULL, 0, ct.hints, &info);
	if(ret) { g_error("nothing found!\n\t%s", fi_strerror(-ret)); exit(EXIT_FAILURE);}
	// maybe setup ct.rx_ctx_ptr
	return info;
}

void open_ep(void) {
	// open endpoint!
	int ret;
	struct fi_cq_attr attrs = {0};
	struct fi_av_attr a_attrs = {0};
	attrs.wait_obj = FI_WAIT_NONE;
	attrs.size = ct.fi->tx_attr->size;
	ret = fi_cq_open(ct.domain, &attrs, &ct.txcq, &ct.txcq);
	if(ret) { g_error("[s:%i]failed to open tx c queue"
			"\n\t%s",ct.is_server,fi_strerror(-ret)); return; }
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

void init_mr(void) {
	int ret;

	if(ct.fi->tx_attr->mode & FI_MSG_PREFIX) {
		g_message("[s:%i] tx prefix size: %lu", ct.is_server,
				ct.fi->ep_attr->msg_prefix_size);
	}
	if(ct.fi->rx_attr->mode & FI_MSG_PREFIX) {
		g_message("[s:%i] rx prefix size: %lu", ct.is_server,
				ct.fi->ep_attr->msg_prefix_size);
	}

	if(ct.fi->domain_attr->mr_mode & FI_MR_LOCAL) {
		g_message("[s:%i]setup mr", ct.is_server);
		ct.buf_size = sizeof(message) * 2;
		ct.buf = malloc(ct.buf_size);
		g_message("ct.buf: %p", (void*)ct.buf);
		memset(ct.buf, 0, ct.buf_size);
		ret = fi_mr_reg(ct.domain,
				ct.buf,
				ct.buf_size,
				FI_SEND | FI_RECV, 0, 0xC0DE, 0, &(ct.mr), NULL);
		if(ret) {
			g_error("failed to setup mr");
			exit(EXIT_FAILURE);
		}
	} else {
		ct.mr = &(ct.no_mr);
	}
}

void init_ep(void) {
	int ret;

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
}

void client_connect(void) {
	struct fi_eq_cm_entry entry;
	uint32_t event;
	int ret;

	// read name len
	uint32_t len;
	ret = recv(ct.ctrl_connfd, (char*)&len, sizeof(len), 0);
	if(ret == -1 || ret != sizeof(len)) {
		g_error("failed to recive addr len!");
		return;
	}
	len = ntohl(len);

	// read addr format and addr
	ret = recv(ct.ctrl_connfd, (char*)&ct.hints->addr_format, sizeof(ct.hints->addr_format), 0);
	if(ret == -1 || ret != sizeof(ct.hints->addr_format)) {
		g_error("failed to recive addr_format");
		return;
	}
	ct.hints->dest_addr = malloc(len);
	ct.hints->dest_addrlen = len;
	g_message("fetch address: %u", len);
	ret = recv(ct.ctrl_connfd, (char*)ct.hints->dest_addr, len, 0);
	if(ret == -1 || (uint32_t)ret != len) {
		g_error("failed to recive addr! (%d)", ret);
		return;
	}


	ct.fi = get_info();
	ret = fi_fabric(ct.fi->fabric_attr, &(ct.fabric), NULL);
	if(ret) { g_error("failed to open fabric!"); return; }
	ret = fi_eq_open(ct.fabric, &(ct.eq_attr), &(ct.eq), NULL);
	if(ret) { g_error("failed to open event queue!"); return; }
	ret = fi_domain(ct.fabric, ct.fi, &(ct.domain), NULL);
	if(ret) { g_error("failed to open domain!"); return; }

	init_mr();
	open_ep();
	init_ep();

	ret = fi_connect(ct.ep, ct.hints->dest_addr, NULL, 0);
	if(ret) { g_error("verbs: failed to connect!"); return; }
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
	void* name = NULL;

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
	ret = fi_getname(&ct.pep->fid, NULL, &addrlen);
	if((ret != -FI_ETOOSMALL) || (addrlen <= 0)) {
		g_error("failed to fetch name len!");
		return;
	}
	name = malloc(addrlen);
	ret = fi_getname(&ct.pep->fid, name, &addrlen);
	if(ret) { g_error("failed to fetch name!"); return; }

	len = htonl(addrlen);
	g_message("send len: %lu", addrlen);
	ret = send(ct.ctrl_connfd, (char*)&len, sizeof(len), 0);
	if(ret == -1 || ret != sizeof(len)) { g_error("failed to send len!"); return; }
	ret = send(ct.ctrl_connfd, &p_info->addr_format, sizeof(p_info->addr_format), 0);
	if(ret == -1 || ret != sizeof(p_info->addr_format)) {
		g_error("failed to send format!"); return; }
	ret = send(ct.ctrl_connfd,name, addrlen, 0);
	if(ret == -1 || ret != 16) {
		g_error("failed to send addr!(%d)", ret); return;
	}
	
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

	init_mr();
	open_ep();
	init_ep();

	ret = fi_accept(ct.ep, NULL, 0);
	if(ret) { g_error("failed to accept!"); return; }

	ret = fi_eq_sread(ct.eq, &event, &entry, sizeof(entry), -1, 0);
	if(ret != sizeof(entry)) { g_error("failed to read accept!"); return; }
	if(event != FI_CONNECTED || entry.fid != &ct.ep->fid) {
		g_error("no accept message?"); return;
	}


}


void msg_client(void){
	int ret;
	char* tx_buf;
	const uint64_t msg_len = sizeof(message);


	init_client();
	client_connect();

	if(ct.mr == &ct.no_mr) {
		tx_buf = malloc(msg_len);
	} else {
		tx_buf = ct.buf;
	}
	g_message("tx_buf: %p", (void*)tx_buf);
	
	// maybe sync?
	
	// sending a message
	memcpy(tx_buf, message, msg_len);
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
	if(!verify_cq(ct.txcq, 1)) {
		g_error("failed to verifycq!");
		return;
	}
	g_message("client msg finished!");
}

void init_server(void) {
	struct sockaddr_in ctrl_addr = {0};
	int optval = 1;
	int ret;
	int listendfd;

	listendfd = socket(AF_INET, SOCK_STREAM, 0);
	if(listendfd == -1) {
		g_error("failed to tsart sockket!");
		exit(EXIT_FAILURE);
	}
	ret = setsockopt(listendfd, SOL_SOCKET, SO_REUSEADDR, (const char*)&optval, sizeof(optval));
	if(ret == -1) {
		g_error("failed to set option!");
		exit(EXIT_FAILURE);
	}

	ctrl_addr.sin_family = AF_INET;
	ctrl_addr.sin_port = htons(server_port);
	ctrl_addr.sin_addr.s_addr = htonl(INADDR_ANY);

	ret = bind(listendfd, (struct sockaddr*)&ctrl_addr,
			sizeof(ctrl_addr));
	if(ret == -1) {
		g_error("failet to bind socket!");
		exit(EXIT_FAILURE);
	}

	ret = listen(listendfd, 10);
	if(ret == -1) {
		g_error("failed to listen to socket!");
		exit(EXIT_FAILURE);
	}

	ct.ctrl_connfd = accept(listendfd, NULL, NULL);
	if(ct.ctrl_connfd == -1) {
		g_error("failet do accept socket!");
		exit(EXIT_FAILURE);
	}
	// close(listendfd);
}

void msg_server(void){
	int ret;
	char* rx_buf;
	const uint64_t msg_len = sizeof(message);


	init_server();
	server_connect();

	if(ct.mr == &ct.no_mr) {
		rx_buf = malloc(sizeof(message));
	} else {
		rx_buf = ct.buf + ct.buf_size / 2;
	}
	memset(rx_buf, 0, msg_len);

	// reciving a message
	// verify_cq(??rx_seq??);
	g_message("start recv");
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
	g_message("start verification");
	if(!verify_cq(ct.rxcq, 1)) { g_error("verification failed!"); return; }
	g_message("recived message: %s", rx_buf);
	g_print("rec: ");
	for(int i = 0; i < (int)msg_len; ++i) {
		g_print("%i ", rx_buf[i]);
	}
	g_print("\n");
	// g_message("bytes remaining: %i", remaining_bytes_cq());
}

int remaining_bytes_cq(void) {
	int ret;
	struct fi_cq_err_entry comp;
	uint64_t msg_cnt = 0;

	while(1) {
		ret = fi_cq_read(ct.txcq, &comp, 1);
		if(ret > 0)  {
			msg_cnt += ret;
			g_message("remain(tmp): %lu", msg_cnt);
		} else if(ret < 0 && ret != -FI_EAGAIN) {
			g_error("failed to verify len!");
			return msg_cnt; 
		}
	}
	return msg_cnt;
}

void run_msg(void) {
	if(ct.is_server) {msg_server();}
	else {msg_client();}
}



int main(int argc, char** argv) {
	char* p_name = malloc(sizeof(provider_name));
	char* s_address = malloc(sizeof(server_address));
	int ret = EXIT_SUCCESS;

	if (argc != 2) { g_error("expect 1 argument [client|server]"); return EXIT_FAILURE; }
	if(strcmp(argv[1], "client") == 0) { ct.is_server = 0; }
	else if (strcmp(argv[1], "server") == 0) { ct.is_server = 1; }
	else { g_error("expect client or server, not '%s'.", argv[1]); return EXIT_FAILURE; }

	memcpy(p_name, provider_name, sizeof(provider_name));
	memcpy(s_address, server_address, sizeof(server_address));

	ct.hints = fi_allocinfo();
	if(!ct.hints) return EXIT_FAILURE;
	ct.hints->caps = FI_MSG;
	ct.hints->mode = FI_CONTEXT | FI_CONTEXT2 | FI_MSG_PREFIX;
	ct.hints->domain_attr->mr_mode = FI_MR_LOCAL | FI_MR_ALLOCATED | FI_MR_PROV_KEY | FI_MR_VIRT_ADDR;
	ct.hints->ep_attr->type = endpoint_type; 
	ct.hints->fabric_attr->prov_name = p_name;
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
