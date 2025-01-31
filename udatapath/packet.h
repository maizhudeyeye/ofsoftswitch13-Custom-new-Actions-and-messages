/* Copyright (c) 2011, TrafficLab, Ericsson Research, Hungary
 
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 *   * Redistributions of source code must retain the above copyright notice,
 *     this list of conditions and the following disclaimer.
 *   * Redistributions in binary form must reproduce the above copyright
 *     notice, this list of conditions and the following disclaimer in the
 *     documentation and/or other materials provided with the distribution.
 *   * Neither the name of the Ericsson Research nor the names of its
 *     contributors may be used to endorse or promote products derived from
 *     this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 *
 *
 * Author: Zoltán Lajos Kis <zoltan.lajos.kis@ericsson.com>
 */

#ifndef UDP_PACKET_H
#define UDP_PACKET_H 1

#include <stdbool.h>
#include "action_set.h"
#include "datapath.h"
#include "packet_handle_std.h"
#include "ofpbuf.h"
#include "oflib/ofl-structs.h"
#include "packets.h"

#define TOP_K 10
#define MOD 10
#define LAMDA 8

/****************************************************************************
 * Represents a packet received on the datapath, and its associated processing
 * state.
 ****************************************************************************/


struct packet {
    struct datapath    *dp;
    struct ofpbuf      *buffer;    /* buffer containing the packet */
    uint32_t            in_port;
    struct action_set  *action_set; /* action set associated with the packet */
    bool                packet_out; /* true if the packet arrived in a packet out msg */

    uint32_t            out_group; /* OFPG_ANY = no out group */
    uint32_t            out_port;  /* OFPP_ANY = no out port */
    uint16_t            out_port_max_len;  /* max length to send, if out_port is OFPP_CONTROLLER */
    uint32_t            out_queue;
    uint8_t             table_id; /* table in which is processed */
    uint32_t            buffer_id; /* if packet is stored in buffer, buffer_id;
                                      otherwise 0xffffffff */
    uint64_t            tunnel_id; /* tunnel id set by logical input port */

    struct packet_handle_std  *handle_std; /* handler for standard match structure */

#ifdef NS3_OFSWITCH13
    // When compiling the ns3 library, including a ns3 packet uid (associated 
    // with ns3 internal packet), a change counter and a clone flag.
    uint64_t ns3_uid;
    uint8_t changes;
    bool clone;
#endif
};

struct four_tuple{
    uint32_t ip_src;
    uint32_t ip_dst;
    uint16_t tcp_src;
    uint16_t tcp_dst;
};

struct elephant_node{
    bool exist_flow_flag;
    uint32_t vote_yes;
    uint32_t vote_no;
    struct four_tuple ft;
};

extern struct elephant_node top_k_array[TOP_K];

/* Creates a packet. */
struct packet *
packet_create(struct datapath *dp, uint32_t in_port, struct ofpbuf *buf, uint64_t tunnel_id, bool packet_out);

/* Converts the packet to a string representation. */
char *
packet_to_string(struct packet *pkt);

/* Destroys a packet along with all its associated structures */
void
packet_destroy(struct packet *pkt);

/* Clones a packet deeply, i.e. all associated structures are also cloned. */
struct packet *
packet_clone(struct packet *pkt);

/* Compute the hash of a data packet and record it in a sketch. */
void 
record_sketch(const struct four_tuple *ft);

uint8_t 
sketch_hash(const struct four_tuple *ft);

void 
initialize_elephant_array(struct elephant_node *array, uint8_t length);

void 
clear_elephant_node(struct elephant_node *node);

/* Compare four tuple. */
int 
four_tuple_compare(const struct four_tuple *a, const struct four_tuple *b);

#endif /* UDP_PACKET_H */
