#include "pktgen.h"

/* Global PKTGEN configuration */
pktgen_t pktgen;

/* Per-core information */
__thread core_info_t core_info;

/**
 *
 * pktgen_usage - Display the help for the command line.
 *
 * DESCRIPTION
 * Display the help message for the command line.
 *
 * RETURNS: N/A
 *
 * SEE ALSO:
 */

static void pktgen_usage(const char *prgname) {
	printf(
		"Usage: %s [EAL options] -- [-h] [-c num_cores] [-f num_flows] [-s payload_size] [-r rate] [-t duration]\n"
		"  -c num_cores	Number of cores\n"
		"  -f num_flows	Number of flows\n"
		"  -s payload_size	Size of payload\n"
		"  -r rate	Request transmission rate\n"
		"  -t duration	Traffic duration\n"
		"  -h		Display the help information\n",
		prgname);
}

/**
 * pktgen_parse_args - Main parsing routine for the command line.
 *
 * @param argc
 * @param argv
 * @return: N/A
 */
static int pktgen_parse_args(int argc, char **argv) {
	int opt;
	char *prgname = argv[0];

	while ((opt = getopt(argc, argv, "c:f:s:r:t:h:")) != -1) {
		switch (opt) {
		case 'c':	/* Number of cores we are using */
			pktgen.nb_cores = atoi(optarg);
			break;

		case 'f':	/* Number of flows per core */
			pktgen.nb_flows = atoi(optarg);
			break;

		case 's':	/* Size of payload */
			pktgen.payload_size = atoi(optarg);
			break;

		case 'r':	/* Transmit rate */
			pktgen.tx_rate = atof(optarg);
			break;

		case 't':	/* Traffic generation duration */
			pktgen.duration = atoi(optarg);
			break;

		case 'h':	/* print out the help message */
			pktgen_usage(prgname);
			return -1;

		default:
			return -1;
		}
	}

	if (!pktgen.nb_cores) {
		perror("Need to specify the number of cores!");
	}

	for (int i = 0; i < pktgen.nb_cores; i++) {
		pktgen.latsamp_stats[i].data = (uint64_t *)calloc(MAX_LATENCY_ENTRIES, sizeof(uint64_t));
		pktgen.latsamp_stats[i].num_samples = 0;
	}

    return 0;
}

int main(int argc, char ** argv) {
	int32_t ret;

    /* initialize EAL */
	ret = rte_eal_init(argc, argv);
	if (ret < 0) {
		return -1;
    }

    argc -= ret;
	argv += ret;

	/* parse application arguments (after the EAL ones) */
	ret = pktgen_parse_args(argc, argv);
	if (ret < 0) {
		return -1;
	}

    pktgen_config_ports();

    ret = 0;
	/* launch per-lcore init on every lcore */
	rte_eal_mp_remote_launch(pktgen_launch_one_lcore, NULL, CALL_MAIN);
    rte_eal_mp_wait_lcore();

    /* clean up the EAL */
	rte_eal_cleanup();
	printf("Bye...\n");

	return 0;
}