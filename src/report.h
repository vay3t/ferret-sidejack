#ifndef REPORT_H
#define REPORT_H
#ifdef __cplusplus
extern "C" {
#endif

void report_stats1(struct Ferret *ferret);
void report_stats2(struct Ferret *ferret);

void record_host_transmit(struct Ferret *ferret, unsigned ipv4, unsigned frame_size);
void record_host_receive(struct Ferret *ferret, unsigned ipv4, unsigned frame_size);
void record_host2host(struct Ferret *ferret, unsigned ipsrc, unsigned ipdst, unsigned frame_size);

void report_hosts_topn(struct Ferret *ferret, unsigned report_count);
void report_fanout_topn(struct Ferret *ferret, unsigned report_count);
void report_fanin_topn(struct Ferret *ferret, unsigned report_count);

void report_hosts_set_parameter(struct Ferret *ferret, const char *name, const char *value);
void report_fanout_set_parameter(struct Ferret *ferret, const char *name, const char *value);

#ifdef __cplusplus
}
#endif
#endif
