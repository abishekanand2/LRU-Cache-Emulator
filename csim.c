/*

This program simulates cache memory loads and stores. I have created structures
representing the cache, sets, and lines. First, I built a command-line tool that
takes in s, E, and b along with some other options. Then, I built a trace file
parser to figure out the operation, address, and size. Based on these
parameters, helper functions cache_load and cache_store are used to simulate the
cache access and hits, misses, evictions, dirty_bytes, and dirty_bytes evicted
are all kept track of and updated.

*/
#include "cachelab.h"
#include <errno.h>
#include <getopt.h>
#include <math.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

// cache line
typedef struct line {
    int valid_bit;
    unsigned long long tag;
    struct line *next_line;
    int dirty_bit;
} line;

// cache set
typedef struct set {
    struct line *first_line;
    int amt_lines;
    struct set *next_set;
} set;

// cache
typedef struct cache {
    struct set *first_set;
    int S;
    int s;
    int b;
    int E;
    unsigned long B;
} cache;

// initializing cache set
set *initialize_set(void) {
    set *s = malloc(sizeof(set));
    if (s == NULL) {
        printf("Error initializing set \n");
        return s;
    }
    s->amt_lines = 0;
    s->first_line = NULL;
    s->next_set = NULL;
    return s;
}

// initializing cache line
line *initialize_line(void) {
    line *l = malloc(sizeof(line));
    if (l == NULL) {
        printf("Error initializing line \n");
        return l;
    }
    l->valid_bit = 0;
    l->tag = 0;
    l->next_line = NULL;
    l->dirty_bit = 0;
    return l;
}

// extract tag and set index using bit manipulation
void parse_address(unsigned long long address, unsigned long long *set_index,
                   unsigned long long *tag, cache *c) {
    int tag_bits = 64 - c->s - c->b;

    *tag = address >> (64 - tag_bits);

    unsigned long long no_block_bits = address >> c->b;
    unsigned long long clear_tag = (1 << c->s) - 1;
    *set_index = no_block_bits & clear_tag;
}

// simulate a store operation
void cache_store(csim_stats_t *statistics, cache *c,
                 unsigned long long address) {
    unsigned long long set_index = 0;
    unsigned long long tag = 0;
    parse_address(address, &set_index, &tag, c);
    set *cur_set = c->first_set;
    for (unsigned long long i = 0; i < set_index; i++) {
        cur_set = cur_set->next_set;
    }
    line *l = cur_set->first_line;
    line *previous = NULL;
    bool found = false;
    // if set initially empty
    if (!l) {
        statistics->dirty_bytes += c->B;
        line *new_line = initialize_line();
        new_line->valid_bit = 1;
        new_line->tag = tag;
        new_line->dirty_bit = 1;
        cur_set->first_line = new_line;
        cur_set->amt_lines++;
        statistics->misses++;
        return;
    }
    while (l->next_line && !found) {
        if (l->valid_bit && l->tag == tag) {
            found = true;
        } else {
            previous = l;
            l = l->next_line;
        }
    }
    if (l->valid_bit && !found && l->tag == tag) {
        found = true;
    }
    if (found) {
        statistics->hits++;
        statistics->dirty_bytes += c->B;
        if (l->dirty_bit) {
            statistics->dirty_bytes -= c->B;
        }
        l->dirty_bit = 1;
        if (previous) {
            previous->next_line = l->next_line;
            l->next_line = cur_set->first_line;
            cur_set->first_line = l;
        }
    } else {
        statistics->misses++;
        statistics->dirty_bytes += c->B;
        if (cur_set->amt_lines < c->E) {
            line *new_line = initialize_line();
            new_line->valid_bit = 1;
            new_line->tag = tag;
            new_line->dirty_bit = 1;
            new_line->next_line = cur_set->first_line;
            cur_set->first_line = new_line;
            cur_set->amt_lines++;
        } else {
            statistics->evictions++;
            l = cur_set->first_line;
            previous = NULL;
            while (l->next_line != NULL) {
                previous = l;
                l = l->next_line;
            }
            if (previous) {
                line *new_line = initialize_line();
                new_line->valid_bit = 1;
                new_line->tag = tag;
                new_line->next_line = cur_set->first_line;
                new_line->dirty_bit = 1;
                cur_set->first_line = new_line;
                if (l->dirty_bit) {
                    statistics->dirty_bytes -= c->B;
                    statistics->dirty_evictions += c->B;
                }
                free(l);
                previous->next_line = NULL;
            } else {
                if (l->dirty_bit) {
                    statistics->dirty_evictions += c->B;
                    statistics->dirty_bytes -= c->B;
                }
                l->tag = tag;
                l->dirty_bit = 1;
                l->valid_bit = 1;
            }
        }
    }
}

// simulate cache load
void cache_load(csim_stats_t *statistics, cache *c,
                unsigned long long address) {
    unsigned long long set_index;
    unsigned long long tag = 0;
    parse_address(address, &set_index, &tag, c);
    set *cur_set = c->first_set;
    for (unsigned long long i = 0; i < set_index; i++) {
        cur_set = cur_set->next_set;
    }
    line *previous = NULL;
    line *l = cur_set->first_line;
    bool found = false;
    if (!l) {
        statistics->misses++;
        line *new_line = initialize_line();
        new_line->valid_bit = 1;
        new_line->tag = tag;
        cur_set->first_line = new_line;
        cur_set->amt_lines++;
        return;
    }
    while (!found && l->next_line) {
        if (l->tag == tag && l->valid_bit) {
            found = true;
        } else {
            previous = l;
            l = l->next_line;
        }
    }
    if (!found && l->tag == tag && l->valid_bit) {
        found = true;
    }
    if (found) {
        if (previous != NULL) {
            previous->next_line = l->next_line;
            l->next_line = cur_set->first_line;
            cur_set->first_line = l;
        }
        statistics->hits++;
    } else {
        statistics->misses++;
        if (cur_set->amt_lines < c->E) {
            line *new_line = initialize_line();
            new_line->tag = tag;
            new_line->next_line = cur_set->first_line;
            cur_set->first_line = new_line;
            new_line->valid_bit = 1;
            cur_set->amt_lines++;
        } else {
            statistics->evictions++;
            line *new_line = initialize_line();
            new_line->tag = tag;
            new_line->next_line = cur_set->first_line;
            new_line->valid_bit = 1;
            cur_set->first_line = new_line;
            l = cur_set->first_line;
            previous = NULL;
            while (l->next_line) {
                previous = l;
                l = l->next_line;
            }
            if (previous) {
                if (l->dirty_bit) {
                    statistics->dirty_evictions += c->B;
                    statistics->dirty_bytes -= c->B;
                }
                free(l);
                previous->next_line = NULL;
            }
        }
    }
}

// Reads in the operation, address, and size
// Calls either cache_store or cache_load based on the parsed operation
int process_trace_file(csim_stats_t *stats, cache *c, const char *trace) {
    FILE *tfp = fopen(trace, "rt");
    if (!tfp) {
        fprintf(stderr, "Error opening");
        return 1;
    }

    int parse_error = 0;
    char operation;
    unsigned long long address;
    int size;
    while (fscanf(tfp, "%c %llx %d", &operation, &address, &size) > 0) {
        switch (operation) {

        case 'S':
            cache_store(stats, c, address);
            break;

        case 'L':
            cache_load(stats, c, address);
            break;

        case '?':
            break;
        }
    }
    return parse_error;
}

// Command line tool
// reads in all the inputs, initializes a cache and the starting statistics and
// calls process trace file
int main(int argc, char **argv) {
    int opt;
    char *t;
    int s = -1;
    int b = -1;
    int E = 0;
    bool s_check = false;
    bool b_check = false;
    bool E_check = false;
    bool t_check = false;

    while ((opt = getopt(argc, argv, "hvs:b:E:t:")) != -1) {
        switch (opt) {
        case 'h':
            printf("called with only -h \n");
            return 0;
        case 'v':
            printf("v \n");
            break;
        case 's':
            s_check = true;
            s = atoi(optarg);
            if (s < 0) {
                printf("s Value not positive \n");
            } else {
                printf("s with value: %d \n", s);
            }
            break;
        case 'b':
            b_check = true;
            b = atoi(optarg);
            if (b < 0) {
                printf("b Value not positive \n");
            } else {
                printf("b with value: %d \n", b);
            }
            break;
        case 'E':
            E_check = true;
            E = atoi(optarg);
            if (E < 0) {
                printf("E Value not positive \n");
            } else {
                printf("E with value: %d \n", E);
            }
            break;
        case 't':
            t_check = true;
            t = optarg;
            if (t == NULL) {
                printf("t is NULL \n");
            } else {
                printf("t with value: %s \n", t);
            }
            break;
        default:
            printf("Error parsing commands");
            return 1;
        }
    }

    if (!s_check || !b_check || !E_check || !t_check) {
        printf("not enough arguments supplied \n");
        return 1;
    }

    // initialize the cache
    cache *c = malloc(sizeof(cache));
    if (c == NULL) {
        printf("Error initializing cache \n");
    }
    int total_sets = (int)pow(2, s);
    c->S = total_sets;
    c->s = s;
    c->b = b;
    c->E = E;
    c->B = (unsigned long)pow(2, b);
    c->first_set = initialize_set();
    set *cur = c->first_set;
    for (int i = 0; i < total_sets - 1; i++) {
        cur->next_set = initialize_set();
        cur = cur->next_set;
    }

    csim_stats_t *statistics = malloc(sizeof(csim_stats_t));
    if (statistics == NULL) {
        printf("Error initializing statistics \n");
    }
    statistics->hits = 0;
    statistics->misses = 0;
    statistics->evictions = 0;
    statistics->dirty_bytes = 0;
    statistics->dirty_evictions = 0;

    int result = process_trace_file(statistics, c, t);
    printSummary(statistics);
    free(statistics);
    set *cur_set = c->first_set;
    while (cur_set != NULL) {
        line *l = cur_set->first_line;
        set *free_set_helper = cur_set;
        while (l != NULL) {
            line *free_line_helper = l;
            l = l->next_line;
            free(free_line_helper);
        }
        cur_set = cur_set->next_set;
        free(free_set_helper);
    }
    free(c);
    return result;
}
