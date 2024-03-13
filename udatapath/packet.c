/* Copyright (c) 2011, TrafficLab, Ericsson Research, Hungary
 * Copyright (c) 2012, CPqD, Brazil  
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
 */

#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <sys/types.h>
#include "datapath.h"
#include "dp_buffers.h"
#include "packet.h"
#include "packets.h"
#include "action_set.h"
#include "ofpbuf.h"
#include "oflib/ofl-structs.h"
#include "oflib/ofl-print.h"
#include "util.h"


struct packet *
packet_create(struct datapath *dp, uint32_t in_port,
    struct ofpbuf *buf, uint64_t tunnel_id, bool packet_out) {
    struct packet *pkt;

    pkt = xmalloc(sizeof(struct packet));

    pkt->dp         = dp;
    pkt->buffer     = buf;
    pkt->in_port    = in_port;
    pkt->action_set = action_set_create(dp->exp);

    pkt->packet_out       = packet_out;
    pkt->out_group        = OFPG_ANY;
    pkt->out_port         = OFPP_ANY;
    pkt->out_port_max_len = 0;
    pkt->out_queue        = 0;
    pkt->buffer_id        = NO_BUFFER;
    pkt->table_id         = 0;
    pkt->tunnel_id        = tunnel_id;

#ifdef NS3_OFSWITCH13
    pkt->ns3_uid          = 0;
    pkt->changes          = 0;
    pkt->clone            = false;
#endif

    pkt->handle_std = packet_handle_std_create(pkt);
    return pkt;
}

struct packet *
packet_clone(struct packet *pkt) {
    struct packet *clone;

    clone = xmalloc(sizeof(struct packet));
    clone->dp         = pkt->dp;
    clone->buffer     = ofpbuf_clone(pkt->buffer);
    clone->in_port    = pkt->in_port;
    /* There is no case we need to keep the action-set, but if it's needed
     * we could add a parameter to the function... Jean II
     * clone->action_set = action_set_clone(pkt->action_set);
     */
    clone->action_set = action_set_create(pkt->dp->exp);


    clone->packet_out       = pkt->packet_out;
    clone->out_group        = OFPG_ANY;
    clone->out_port         = OFPP_ANY;
    clone->out_port_max_len = 0;
    clone->out_queue        = 0;
    clone->buffer_id        = NO_BUFFER; // the original is saved in buffer,
                                         // but this buffer is a copy of that,
                                         // and might be altered later
    clone->table_id         = pkt->table_id;

    clone->handle_std = packet_handle_std_clone(clone, pkt->handle_std);

#ifdef NS3_OFSWITCH13
    clone->ns3_uid          = pkt->ns3_uid;
    clone->changes          = pkt->changes;
    clone->clone            = true;
    if (pkt->dp->pkt_clone_cb != 0) {
        pkt->dp->pkt_clone_cb (pkt, clone);
    }
#endif
    return clone;
}

struct elephant_node top_k_array[TOP_K];
void
packet_destroy(struct packet *pkt) {
    /* If packet is saved in a buffer, do not destroy it,
     * if buffer is still valid */
     
    if (pkt->buffer_id != NO_BUFFER) {
        if (dp_buffers_is_alive(pkt->dp->buffers, pkt->buffer_id)) {
            return;
        } else {
            dp_buffers_discard(pkt->dp->buffers, pkt->buffer_id, false);
        }
    }

#ifdef NS3_OFSWITCH13
    if (pkt->dp->pkt_destroy_cb != 0) {
        pkt->dp->pkt_destroy_cb (pkt);
    }
#endif
    action_set_destroy(pkt->action_set);
    ofpbuf_delete(pkt->buffer);
    packet_handle_std_destroy(pkt->handle_std);
    free(pkt);
}

char *
packet_to_string(struct packet *pkt) {
    char *str;
    size_t str_size;
    FILE *stream = open_memstream(&str, &str_size);

    fprintf(stream, "pkt{in=\"");
    ofl_port_print(stream, pkt->in_port);
    fprintf(stream, "\", actset=");
    action_set_print(stream, pkt->action_set);
    fprintf(stream, ", pktout=\"%u\", ogrp=\"", pkt->packet_out);
    ofl_group_print(stream, pkt->out_group);
    fprintf(stream, "\", oprt=\"");
    ofl_port_print(stream, pkt->out_port);
    fprintf(stream, "\", buffer=\"");
    ofl_buffer_print(stream, pkt->buffer_id);
#ifdef NS3_OFSWITCH13
    fprintf(stream, "\", ns3pktid=\"%" PRIu64, pkt->ns3_uid);
    fprintf(stream, "\", changes=\"%u", pkt->changes);
    fprintf(stream, "\", clone=\"%u", pkt->clone);
#endif    
    fprintf(stream, "\", std=");
    packet_handle_std_print(stream, pkt->handle_std);
    fprintf(stream, "}");

    fclose(stream);
    return str;
}

/**
 * @brief 计算hash值
 * 
 * @param ft 数据包四元组
 * @return uint8_t 返回hash值
 */
uint8_t sketch_hash(const struct four_tuple *ft){
    // 对每个成员进行取模操作
    uint32_t ip_src_mod = (ft->ip_src) % MOD;
    uint32_t ip_dst_mod = (ft->ip_dst) % MOD;
    uint32_t tcp_src_mod = (ft->tcp_src) % MOD;
    uint32_t tcp_dst_mod = (ft->tcp_dst) % MOD;

    // 求和
    uint32_t sum = ip_src_mod + ip_dst_mod + tcp_src_mod + tcp_dst_mod;

    // 对和再取模
    uint8_t hash_value = sum % MOD;
    return hash_value;
}

/* Compute the hash of a data packet and record it in a sketch. */
/**
 * @brief 计算数据包四元组的hash值并把它记录到sketch中
 * 
 * @param ft 数据包四元组
 */
void record_sketch(const struct four_tuple *ft){
    uint8_t hash_value = sketch_hash(ft);
    if(top_k_array[hash_value].exist_flow_flag == 0){
        top_k_array[hash_value].ft.ip_src = ft->ip_src;
        top_k_array[hash_value].ft.ip_dst = ft->ip_dst;
        top_k_array[hash_value].ft.tcp_src = ft->tcp_src;
        top_k_array[hash_value].ft.tcp_dst = ft->tcp_dst;
        top_k_array[hash_value].vote_yes++;
        top_k_array[hash_value].exist_flow_flag = 1;
    }else{
        if(four_tuple_compare(ft, &top_k_array[hash_value].ft) == 0){
            top_k_array[hash_value].vote_yes++;
        }else{
            top_k_array[hash_value].vote_no++;
        }
        if(top_k_array[hash_value].vote_no >= LAMDA * top_k_array[hash_value].vote_yes){
            clear_elephant_node(&top_k_array[hash_value]);
        }
    }
}
/**
 * @brief 初始化sketch数据结构
 * 
 * @param array 大象流数组
 * @param length 数组长度
 */
void initialize_elephant_array(struct elephant_node *array, uint8_t length){
    for(uint8_t i = 0; i < length; i++){
        clear_elephant_node(&array[i]);
    }
}

/**
 * @brief 清除数组中某一项
 * 
 * @param node 
 */
void clear_elephant_node(struct elephant_node *node){
    node->ft.ip_src = 0;
    node->ft.ip_dst = 0;
    node->ft.tcp_src = 0;
    node->ft.tcp_dst = 0;
    node->vote_no = 0;
    node->vote_yes = 0;
    node->exist_flow_flag = 0;
}

/**
 * @brief 比较两个四元组是否相同
 * 
 * @param a 第一个四元组
 * @param b 第二个四元组
 * @return int 0相同，-1不同
 */
int four_tuple_compare(const struct four_tuple *a, const struct four_tuple *b) {
    if (a->ip_src != b->ip_src) return -1;
    if (a->ip_dst != b->ip_dst) return -1;
    if (a->tcp_src != b->tcp_src) return -1;
    if (a->tcp_dst != b->tcp_dst) return -1;
    return 0; // equal
}
