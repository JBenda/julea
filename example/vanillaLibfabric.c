#include <glib.h>
#include <rdma/fabric.h>
#include <rdma/fi_endpoint.h>
#include <rdma/fi_rma.h>
#include <rdma/fi_cm.h>

int main(void);
void printFabrics(struct fi_info*);
void printAddressTypes(void);
struct fi_info* findInfo(void);
struct fid_fabric* createProvider(struct fi_info*);
struct fid_pep* createPassiveEndpoint(struct fi_info*, struct fid_fabric*);
struct fid_eq* openEventQueue(struct fid_fabric*);

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

struct fid_eq* openEventQueue(struct fid_fabric* provider) {
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

int main() {
	struct fi_info* info;
	struct fid_fabric* provider;
	struct fid_pep* passive_endpoint;
	struct fid_eq* event_queue;
	int error;

	if(!(info = findInfo())) { goto end; }
	if(!(provider = createProvider(info))) { goto end; }
	if(!(passive_endpoint = createPassiveEndpoint(info, provider))) { goto end; }
	if(!(event_queue = openEventQueue(provider))) { goto end; }

	// ep must be socket type to support connection managment events
	// https://ofiwg.github.io/libfabric/master/man/fi_endpoint.3.html
	error = fi_pep_bind(passive_endpoint,  &provider->fid, 0);
	if(error != 0) {
		g_critical("Failing to bind endpoint, with:\n\t%s",
				fi_strerror(abs(error)));
		goto end;
	}
	error = fi_listen(passive_endpoint);
	if (error != 0) {
		g_critical("Failed to setting passive endpoint to listen, with:\n\t%s",
				fi_strerror(abs(error)));
		goto end;
	}
	g_print("Setup Passive Endpoint, can recive connections now :)");

end:
	fi_freeinfo(info);
}
