/* Example program using libflowmanager to produce active flow counts every 5
 * minutes. 
 * Demonstrates how foreachFlow should be used.
 *
 * Author: Shane Alcock
 */

#define __STDC_FORMAT_MACROS

#include <stdio.h>
#include <assert.h>
#include <getopt.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <stdlib.h>

#include <libtrace.h>
#include <libflowmanager.h>

/* This data structure is used to demonstrate how to use the 'extension' 
 * pointer to store custom data for a flow */
typedef struct counter {
	uint64_t packets;
	uint8_t init_dir;
} CounterFlow;

typedef struct flowcounts {
	uint64_t in;
	uint64_t out;
} FlowCounters;

#define REPORT_FREQ (300)
double last_report = 0;

FlowManager *fm = NULL;

/* Initialises the custom data for the given flow. Allocates memory for a
 * CounterFlow structure and ensures that the extension pointer points at
 * it.
 */
void init_counter_flow(Flow *f, uint8_t dir) {
	CounterFlow *cflow = NULL;

	cflow = (CounterFlow *)malloc(sizeof(CounterFlow));
	cflow->init_dir = dir;
	cflow->packets = 0;
	f->extension = cflow;
}

/* Expires all flows that libflowmanager believes have been idle for too
 * long. The exp_flag variable tells libflowmanager whether it should force
 * expiry of all flows (e.g. if you have reached the end of the program and
 * want the stats for all the still-active flows). Otherwise, only flows
 * that have been idle for longer than their expiry timeout will be expired.
 */
void expire_counter_flows(double ts, bool exp_flag) {
        Flow *expired;

        /* Loop until libflowmanager has no more expired flows available */
	while ((expired = fm->expireNextFlow(ts, exp_flag)) != NULL) {

                CounterFlow *cflow = (CounterFlow *)expired->extension;
		
		/* We could do something with the packet count here, e.g.
		 * print it to stdout, but that would just produce lots of
		 * noisy output for no real benefit */


		/* Don't forget to free our custom data structure */
                free(cflow);

		/* VERY IMPORTANT: release the Flow structure itself so
		 * that libflowmanager can now safely delete the flow */
                fm->releaseFlow(expired);
        }
}

/* The function I want to run against each active flow. The return type
 * must be an int and the parameters must be a Flow * and a void *.
 */
int count_active_flows(Flow *f, void *data) {

	/* As always, we need to cast the extension pointer as well */
	CounterFlow *cflow = (CounterFlow *)f->extension;

	/* The void * contains a pointer to our FlowCounters structure, but
	 * we have to cast it to the right type before we can use it */
	FlowCounters *current; 
	current = (FlowCounters *)data;

	/* Increment the appropriate counter */
	if (cflow->init_dir == 0)
		current->out ++;
	else
		current->in ++;

	/* Return 1 to indicate success and to carry on to the next flow */

	/* XXX If we wanted to stop after a certain number of flows, we would
	 * need to return zero when that number of flows is met */
	return 1;

}

void per_packet(libtrace_packet_t *packet) {

        Flow *f;
        CounterFlow *cflow = NULL;
        uint8_t dir;
        bool is_new = false;

        libtrace_tcp_t *tcp = NULL;
        libtrace_ip_t *ip = NULL;
        double ts;

        uint16_t l3_type;

        /* Libflowmanager only deals with IP traffic, so ignore anything
	 * that does not have an IP header */
        ip = (libtrace_ip_t *)trace_get_layer3(packet, &l3_type, NULL);
        if (l3_type != 0x0800) return;
        if (ip == NULL) return;

        ts = trace_get_seconds(packet);
	
	/* Expire all suitably idle flows */
        expire_counter_flows(ts, false);

	/* Initialise our last report time */
	if (last_report == 0)
		last_report = ts;

	/* Check if we need to do a report */
	while (last_report + REPORT_FREQ < ts) {
		FlowCounters fc;
		/* Initialise the counter */
		fc.in = 0;
		fc.out = 0;

		/* Use foreachFlow to run the count function against
		 * each active flow. Pass in a pointer to fc as user data so
		 * that we can have access to the final counts when the
		 * counting is done.
		 */
		if (fm->foreachFlow(count_active_flows, &fc) == -1) {
			fprintf(stderr, "Error counting flows\n");
			exit(1);
		}

		/* Print some results! */
		printf("%.2f %" PRIu64 " %" PRIu64 "\n",ts, fc.out, fc.in);

		last_report += REPORT_FREQ;
	}

	/* Many trace formats do not support direction tagging (e.g. PCAP), so
	 * using trace_get_direction() is not an ideal approach. The one we
	 * use here is not the nicest, but it is pretty consistent and 
	 * reliable. Feel free to replace this with something more suitable
	 * for your own needs!.
	 */
        if (ip->ip_src.s_addr < ip->ip_dst.s_addr)
                dir = 0;
        else
                dir = 1;

        /* Ignore packets where the IP addresses are the same - something is
         * probably screwy and it's REALLY hard to determine direction */
        if (ip->ip_src.s_addr == ip->ip_dst.s_addr)
                return;


        /* Match the packet to a Flow - this will create a new flow if
	 * there is no matching flow already in the Flow map and set the
	 * is_new flag to true. */
        f = fm->matchPacketToFlow(packet, dir, &is_new);

	/* Libflowmanager did not like something about that packet - best to
	 * just ignore it and carry on */
        if (f == NULL)
                return;

	/* If the returned flow is new, you will probably want to allocate and
	 * initialise any custom data that you intend to track for the flow */
        if (is_new)
                init_counter_flow(f, dir);
	
	/* Cast the extension pointer to match the custom data type */	
        cflow = (CounterFlow *)f->extension;

	/* Increment our packet counter */
	cflow->packets ++;

        /* Tell libflowmanager to update the expiry time for this flow */
        fm->updateFlowExpiry(f, packet, dir, ts);


}


int main(int argc, char *argv[]) {

        libtrace_t *trace;
        libtrace_packet_t *packet;

        bool opt_true = true;
        bool opt_false = false;

        double ts;
        int i;

        fm = new FlowManager();

        packet = trace_create_packet();
        if (packet == NULL) {
                perror("Creating libtrace packet");
                return -1;
        }

	/* This tells libflowmanager to ignore any flows where an RFC1918
	 * private IP address is involved */
        if (fm->setConfigOption(LFM_CONFIG_IGNORE_RFC1918, &opt_true) == 0)
                return -1;

	/* This tells libflowmanager not to replicate the TCP timewait
	 * behaviour where closed TCP connections are retained in the Flow
	 * map for an extra 2 minutes */
        if (fm->setConfigOption(LFM_CONFIG_TCP_TIMEWAIT, &opt_false) == 0)
                return -1;

	/* This tells libflowmanager not to utilise the fast expiry rules for
	 * short-lived UDP connections - these rules are experimental 
	 * behaviour not in line with recommended "best" practice */
	if (fm->setConfigOption(LFM_CONFIG_SHORT_UDP, &opt_false) == 0)
		return -1;

        optind = 1;

        for (i = optind; i < argc; i++) {

                printf("%s\n", argv[i]);
                
		/* Bog-standard libtrace stuff for reading trace files */
		trace = trace_create(argv[i]);

                if (!trace) {
                        perror("Creating libtrace trace");
                        return -1;
                }

                if (trace_is_err(trace)) {
                        trace_perror(trace, "Opening trace file");
                        trace_destroy(trace);
                        continue;
                }

                if (trace_start(trace) == -1) {
                        trace_perror(trace, "Starting trace");
                        trace_destroy(trace);
                        continue;
                }
                while (trace_read_packet(trace, packet) > 0) {
                        ts = trace_get_seconds(packet);
			per_packet(packet);

                }

                if (trace_is_err(trace)) {
                        trace_perror(trace, "Reading packets");
                        trace_destroy(trace);
                        continue;
                }

                trace_destroy(trace);

        }

        trace_destroy_packet(packet);
	expire_counter_flows(ts, true);
        delete(fm);

        return 0;

}

