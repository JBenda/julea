#include <glib.h>
#include <rdma/fabric.h>
#include <rdma/fi_endpoint.h>
#include <rdma/fi_rma.h>
#include <rdma/fi_cm.h>

#define EVENT_SIZE 512
struct my_event {
	uint32_t type;
	void* data;
};

struct passive_connection {
	struct fi_info* info;
	struct fid_fabric* provider;
	struct fid_pep* passive_endpoint;
	struct fid_eq* event_queue;
};

struct active_connection {
	struct fid_ep* endpoint;
	struct fid_cq* content_queue;
};

int main(int argc, char** argv);
void printFabrics(struct fi_info*);
void printAddressTypes(void);
struct fi_info* findInfo(void);
struct fid_fabric* createProvider(struct fi_info*);
struct fid_pep* createPassiveEndpoint(struct fi_info*, struct fid_fabric*);
struct fid_eq* newEventQueue(struct fid_fabric*);
int setupPassiveConnection(struct passive_connection*);
int closePassiveConnection(struct passive_connection*);
int etablishConnection(struct active_connection*,  struct fid_fabric*,  struct fi_eq_cm_entry*);
void runServer(void);
void runClient(void);

void printAddressTypes() {
	g_print(
			"Address Types:\n"
			"\tFI_FORMAT_UNSPEC: %i,\n"
			"\tFI_SOCKADDR: %i,\n"
			"\tFI_SOCKADDR_IN: %i,\n"
			"\tFI_SOCKADDR_IN6: %i,\n"
			"\tFI_SOCKADDR_IB: %i,\n"
			"\tFI_ADDR_PSMX: %i,\n"
			"\tFI_ADDR_GNI: %i,\n"
			"\tFI_ADDR_STR: %i\n",
			FI_FORMAT_UNSPEC,
			FI_SOCKADDR,
			FI_SOCKADDR_IN,
			FI_SOCKADDR_IN6,
			FI_SOCKADDR_IB,
			FI_ADDR_PSMX,
			FI_ADDR_GNI,
			FI_ADDR_STR);
}

void printFabrics (struct fi_info* infos){
	struct fi_info* itr;

	g_print("Fabrics:\n");
	for(itr = infos; itr->next; itr = itr->next)
	{
		g_print("\tname: %s, provider: %s, addr(set?%itype?=str?%i):",
				itr->fabric_attr->name,
				itr->fabric_attr->prov_name,
				!!itr->src_addr,
				itr->addr_format);
		if (itr->src_addr && itr->addr_format == FI_ADDR_STR) {
			g_print(" %s", (char*)itr->src_addr);
		}
		g_print("\n");
	}
}

struct fi_info* findInfo() {
	struct fi_info* result = NULL;
	struct fi_info* hints;
	struct fi_info* fabric_infos;
	struct fi_domain_attr* domain_buffer;
	int error;

	hints = fi_allocinfo();
	hints->caps = FI_MSG | FI_RMA;
	hints->ep_attr->type = FI_EP_MSG;
	domain_buffer = hints->domain_attr;
	hints->domain_attr = NULL;

	error = fi_getinfo(
			FI_VERSION(1, 6),
			NULL,
			NULL,
			FI_SOURCE,
			hints,
			&fabric_infos);
	if (error != 0) {
		g_critical("Error while initiating fi_info with:\n\t%s",
				fi_strerror(abs(error)));
		goto end;
	}
	printAddressTypes();
	printFabrics(fabric_infos);
	g_print("Select the first fabric");
	result = fi_dupinfo(fabric_infos);
end:
	hints->domain_attr = domain_buffer;
	fi_freeinfo(hints);
	fi_freeinfo(fabric_infos);
	return result;
}

struct fid_fabric* createProvider(struct fi_info* info) {
	struct fid_fabric* result = NULL;
	int error;
	error =  fi_fabric(info->fabric_attr, &result, NULL);
	if (error != FI_SUCCESS) {
		g_critical("Failed to setup fabric, with:\n\t%s",
				fi_strerror(abs(error)));
		result = NULL;
	}
	return result;
}

struct fid_pep* createPassiveEndpoint(
		struct fi_info* info,
		struct fid_fabric* provider) {
	struct fid_pep* result = NULL;
	int error;
	error = fi_passive_ep(provider, info, &result, NULL);
	if(!!error) {
		g_critical("Failed to create passive endpoint, with:\n\t%s",
				fi_strerror(abs(error)));
	}
	return result;
}

struct fid_eq* newEventQueue(struct fid_fabric* provider) {
	struct fid_eq* result;
	struct fi_eq_attr attr = {
		.size = 0,
		.flags = 0,
		.wait_obj = FI_WAIT_UNSPEC,
		.signaling_vector = 0,
		.wait_set = NULL
	};
	int error;

	error = fi_eq_open(provider, &attr, &result, NULL);
	if (!!error) {
		g_critical("Failed to create event queue, with\n\t%s",
				fi_strerror(abs(error)));
		result = NULL;
	}

	return result;
}

struct fid_cq* newContentQueue(struct fid_domain* domain) {
	int error;
	struct fi_cq_attr attr;
	struct fid_cq* result;

	error = fi_cq_open(domain, &attr, &result, &result);
	if (error < 0) {
		g_critical("Failed to create Content Queue, with:\n\t%s",
				fi_strerror(abs(error)));
		return NULL;
	}
	return result;
}

int setupPassiveConnection(struct passive_connection* connection) {
	struct fi_info* info;
	struct fid_fabric* provider;
	struct fid_pep* passive_endpoint;
	struct fid_eq* event_queue;
	int error;

	if(!(info = findInfo())) { goto fail; }
	if(!(provider = createProvider(info))) { goto fail; }
	if(!(passive_endpoint = createPassiveEndpoint(info, provider))) { goto fail; }
	if(!(event_queue = newEventQueue(provider))) { goto fail; }

	// ep must be socket type to support connection managment events
	// https://ofiwg.github.io/libfabric/master/man/fi_endpoint.3.html
	error = fi_pep_bind(passive_endpoint,  &event_queue->fid, 0);
	if(error != 0) {
		g_critical("Failing to bind endpoint, with:\n\t%s",
				fi_strerror(abs(error)));
		goto fail;
	}
	error = fi_listen(passive_endpoint);
	if (error != 0) {
		g_critical("Failed to setting passive endpoint to listen, with:\n\t%s",
				fi_strerror(abs(error)));
		goto fail;
	}
	g_message("Setup Passive Endpoint, can recive connections now :)");

	connection->event_queue = event_queue;
	connection->info = info;
	connection->passive_endpoint = passive_endpoint;
	connection->provider = provider;

	return 0;
fail:
	return 1;
}

int closePassiveConnection(struct passive_connection* connection) {
	int error;
	if((error = fi_close(&connection->passive_endpoint->fid)) != 0) {
		g_critical("Failed to close passive endpoint, with:\n\t%s",
				fi_strerror(abs(error)));
		return 1;
	}
	if((error = fi_close(&connection->provider->fid)) != 0) {
		g_critical("Failed to close provider, with:\n\t%s",
				fi_strerror(abs(error)));
		return 1;
	}
	return 0;
}


int readEvent(struct passive_connection* connection, struct my_event* event) {
	int error;
	struct fi_eq_err_entry event_queue_err;

	error = fi_eq_sread(connection->event_queue, &event->type, event->data, EVENT_SIZE, 1000, 0);
	if (error < 0) {
		if (error == -FI_EAVAIL) {
			error = fi_eq_readerr(connection->event_queue, &event_queue_err, 0);
			if (error < 0) {
				g_critical("Error while reading error from event queue:\n\t%s",
						fi_strerror(abs(error)));
			} else {
				g_critical("Error message on event queue:\n\t%s",
						fi_eq_strerror(
							connection->event_queue,
							event_queue_err.prov_errno,
							event_queue_err.err_data,
							NULL,
							0));
			}
		}
		return -1;
	} else {
		return error;
	}
}

int etablishConnection(struct active_connection* connection, struct fid_fabric* provider, struct fi_eq_cm_entry* request) {
	int error;
	struct fid_domain* domain;

	fi_domain(provider, request->info, &domain, NULL);
	g_message("Got connection request!");
	error = fi_endpoint(
				NULL,
				request->info,
				&connection->endpoint,
				NULL);
	fi_freeinfo(request->info);
	if (error < 0) {
		g_critical("Failed to create endpoint for connection, with\n\t%s",
				fi_strerror(abs(error)));
		return -1;
	}

	if(!(connection->content_queue = newContentQueue(domain))) {
		fi_close(&connection->endpoint->fid);
		return -1;
	}
	error = fi_ep_bind(connection->endpoint, &connection->content_queue->fid, 0); 
	if (error < 0) {
		g_critical("Failed to bind active endpoint, with\n\t%s",
				fi_strerror(abs(error)));
		return -1;
	}

	fi_accept(connection->endpoint, NULL, 0);
	return 0;
}

void runServer() {
	int read;
	struct passive_connection connection;
	struct my_event event;

	event.data = malloc(EVENT_SIZE);

	if(setupPassiveConnection(&connection) != 0) {
		g_critical("Failed to setup passive connection!");
		goto fail;
	}

	do {
		if((read = readEvent(&connection, &event)) >= 0) {
			if (event.type == FI_CONNREQ) {
				struct active_connection new_connection;
				etablishConnection(
						&new_connection,
						connection.provider,
						(struct fi_eq_cm_entry*)event.data);
			}
		}
	} while(1);



	if(closePassiveConnection(&connection)) { goto fail; }
fail:
	return;
}

void runClient() {
}

int main(int argc, char** argv) {
	if (argc != 2) {
		g_critical("usage: cmd [server|client]");
		return 1;
	}
	if (strcmp(argv[1], "server") == 0) {
		runServer();
	} else if (strcmp(argv[1], "client")) {
		runClient();
	} else {
		g_critical("expected server or client, got '%s'", argv[1]);
		return 1;
	}
	return 0;

