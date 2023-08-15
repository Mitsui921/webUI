/*
 * Copyright 2019-present Open Networking Foundation
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

// Any P4 program usually starts by including the P4 core library and the
// architecture definition, v1model in this case.
// https://github.com/p4lang/p4c/blob/master/p4include/core.p4
// https://github.com/p4lang/p4c/blob/master/p4include/v1model.p4
#include <core.p4>
#include <v1model.p4>
#include "NDNCore.p4"
#include "defs.p4"

/**
 * Send the packet to the CPU port.
 */
action Send_to_cpu()
{ clone( CloneType.I2E, CPU_MIRROR_SESSION_ID ); }


//------------------------------------------------------------------------------
// 3. INGRESS PIPELINE IMPLEMENTATION
//
// All packets will be processed by this pipeline right after the parser block.
// It provides the logic for forwarding behaviors such as:
// - L2 bridging
// - L3 routing
//
// The first part of the block defines the match-action tables needed for the
// different behaviors, while the implementation is concluded with the *apply*
// statement, where we specify the order of tables in the pipeline.
//
// This block operates on the parsed headers (hdr), the user-defined metadata
// (local_metadata), and the architecture-specific instrinsic metadata
// (standard_metadata).
//------------------------------------------------------------------------------
control IngressPipeImpl (inout parsed_headers_t    hdr,
                         inout local_metadata_t    local_metadata,
                         inout standard_metadata_t standard_metadata) {

    register<bit<NUMBER_OF_PORTS>>(REGISTER_ARRAY_SIZE) PIT;
    register<bit<NDN_CACHE_LEN>>(REGISTER_ARRAY_SIZE) CS;
    register<bit<256>>(REGISTER_ARRAY_SIZE) PIT_IPV6;
    
    // drop action definition, shared by many tables. Hence we define it on top.
    action drop() {
        mark_to_drop(standard_metadata);
    }

    action nop() {
        NoAction();
    }
    
   /**
   * Sets the packet's output port based on the Interest or Data's Name.
   * @param port: Port associated with this name. Provided by the table.
   */
    
    action set_egress_port(port_num_t port_num) {
        standard_metadata.egress_spec = port_num;
    }
    
    action set_mcast_grp(bit<16> mcast_grp) {
        standard_metadata.mcast_grp = mcast_grp;        // 通过查表，设置发出的组播组号
    }
    
    action set_egress_port_ip(port_num_t port_num, bit<32> dst_ip) {
        standard_metadata.egress_spec = port_num;
        if(hdr.ipv4.isValid())
        {
            hdr.ipv4.dst_addr = dst_ip;
        }
    }
    
    action computeStoreTablesIndex() {
        hash(local_metadata.hashtray, HashAlgorithm.crc16, (bit<16>)0, { hdr.components[0].value, hdr.components[1].value, hdr.components[2].value}, (bit<32>)65536);
        hash(local_metadata.hashtray_prefix1, HashAlgorithm.crc16, (bit<16>)0, { hdr.components[0].value}, (bit<32>)65536);
        hash(local_metadata.hashtray_prefix2, HashAlgorithm.crc16, (bit<16>)0, { hdr.components[0].value, hdr.components[1].value }, (bit<32>)65536);
        hash(local_metadata.hashtray_prefix3, HashAlgorithm.crc16, (bit<16>)0, { hdr.components[0].value, hdr.components[1].value, hdr.components[2].value }, (bit<32>)65536);
    }
    
    
    table fib_lpm4 {
        key = { local_metadata.hashtray : exact; }
        
        actions = {
          set_egress_port_ip;
        }
    }
    
    table fib_lpm1 {
        key = { local_metadata.hashtray_prefix1 : exact; }
        
        actions = {
          set_egress_port_ip;
        }
    }
    
    table fib_lpm2 {
        key = { local_metadata.hashtray_prefix2 : exact; }
        
        actions = {
          set_egress_port_ip;
        }
    }
    
    table fib_lpm3 {
        key = { local_metadata.hashtray_prefix3 : exact; }
        
        actions = {
          set_egress_port_ip;
        }
    }
    
    table hashName_table {
        
        actions = {
          computeStoreTablesIndex;
        }
          
        default_action = computeStoreTablesIndex;
    }
    
    action ShiftToRightmostRaisedBit(bit<NUMBER_OF_PORTS_LOG> dist) {
      standard_metadata.egress_spec = (bit<9>) dist;
      local_metadata.mcastports = local_metadata.mcastports >> dist;
    }
    
    table getNextFlaggedPort {
      
        key = { local_metadata.mcastports : ternary; }
          
        actions = {
          ShiftToRightmostRaisedBit;
          drop;
        }
          
        const default_action = drop();
          
        const entries = {
        // (pattern &&& mask)
          1     &&& 0b1    : ShiftToRightmostRaisedBit(0);
          2     &&& 0b11   : ShiftToRightmostRaisedBit(1);
          4     &&& 0b111  : ShiftToRightmostRaisedBit(2);
          8     &&& 0b1111 : ShiftToRightmostRaisedBit(3);
          16    &&& 0x1F   : ShiftToRightmostRaisedBit(4);
          32    &&& 0x3F   : ShiftToRightmostRaisedBit(5);
          64    &&& 0x7F   : ShiftToRightmostRaisedBit(6);
          128   &&& 0xFF   : ShiftToRightmostRaisedBit(7);
          256   &&& 0x1FF  : ShiftToRightmostRaisedBit(8);
          512   &&& 0x3FF  : ShiftToRightmostRaisedBit(9);
          1024  &&& 0x7FF  : ShiftToRightmostRaisedBit(10);
          2048  &&& 0xFFF  : ShiftToRightmostRaisedBit(11);
          4096  &&& 0x1FFF : ShiftToRightmostRaisedBit(12);
          8192  &&& 0x3FFF : ShiftToRightmostRaisedBit(13);
          16384 &&& 0x7FFF : ShiftToRightmostRaisedBit(14);
          32768 &&& 0xFFFF : ShiftToRightmostRaisedBit(15);
        }   
    }
    
    // --- l2_exact_table (for unicast entries) --------------------------------
    
    table l2_exact_table {
        key = {
            hdr.ethernet.dst_addr: exact;
        }
        actions = {
            set_egress_port;
            @defaultonly drop;
        }
        const default_action = drop;
        // The @name annotation is used here to provide a name to this table
        // counter, as it will be needed by the compiler to generate the
        // corresponding P4Info entity.
        @name("l2_exact_table_counter")
        counters = direct_counter(CounterType.packets_and_bytes);
    }
    
    action send_to_cpu() {
        standard_metadata.egress_spec = CPU_PORT;
    }

    action ndp_ns_to_na(bit<48> target_mac) {
        hdr.ethernet.src_addr = target_mac;
        hdr.ethernet.dst_addr = IPV6_MCAST_01;
        ipv6_addr_t host_ipv6_tmp = hdr.ipv6.src_addr;
        hdr.ipv6.src_addr = hdr.ndp.target_ipv6_addr;
        hdr.ipv6.dst_addr = host_ipv6_tmp;
        hdr.ipv6.next_hdr = IP_PROTO_ICMPV6;
        hdr.icmpv6.type = ICMP6_TYPE_NA;
        hdr.ndp.flags = NDP_FLAG_ROUTER | NDP_FLAG_OVERRIDE;
        hdr.ndp.type = NDP_OPT_TARGET_LL_ADDR;
        hdr.ndp.length = 1;
        hdr.ndp.target_mac_addr = target_mac;
        standard_metadata.egress_spec = standard_metadata.ingress_port;
    }

    table ndp_reply_table {
        key = {
            hdr.ndp.target_ipv6_addr: ternary;
        }
        actions = {
            ndp_ns_to_na;
            drop;
        }
        
        const default_action = drop();
        
       const entries = {
          0x20010001000100000000000000000000     &&& 0xffffffffffff00000000000000000000    : ndp_ns_to_na(0x1b);
	  }
        //@name("ndp_reply_table_counter")
        //counters = direct_counter(CounterType.packets_and_bytes);
    }
    
    action get_teid()
    {
        local_metadata.teid = hdr.srh.segment_lists[31:0];
    }
    
    table srh {
        key = {
            hdr.srh.segment_lists: ternary;
        }
        actions = {
            get_teid;
            drop;
        }
        const default_action = drop();

       const entries = {
          0x20010001000100000000000100000000 &&& 0xffffffffffff00000000000100000000    : get_teid();
	  }
    }

    action set_pdr_id(pdr_id_t id){
        local_metadata.upf.pdr_id = id;
    }

    action set_far_id(far_id_t id){
        local_metadata.upf.far_id = id;
    }
    
    action Set_dmac( bit<48> dmac)
   { hdr.ethernet.dst_addr = dmac; }

    table upf_pdr_getfar_table{
        key = {
             local_metadata.upf.pdr_id: exact;
        }
        actions = {
            set_far_id;
            drop;
        }
        const default_action = drop;
    }

    table upf_far_action_table{
        key = {
            local_metadata.upf.far_id: exact;
        }
        actions = {
            nop;
            drop;
        }
        const default_action = drop;
    }

    table upf_ue_filter_table{
        key = {
            local_metadata.ue_addr:exact;
        }
        actions ={
            nop;
            set_pdr_id;
        }
        const default_action = nop;
    }
    
    table l2_forward_bypass_table{
        key = {
            hdr.ethernet.src_addr: exact;
            hdr.ethernet.dst_addr: exact;
        }
        actions ={
            nop;
            set_egress_port;
        }
        const default_action = nop;
    }
    
    table broadcast {

        key = {
            hdr.ethernet.src_addr : exact;     // 根据 ingress_port 选择映射的组播号
            //standard_metadata.ingress_port : exact;     // 根据 ingress_port 选择映射的组播号
        }
        actions = {
            set_mcast_grp;
            NoAction;
        }
        size = 32;
        default_action =  NoAction;

    }
    
    table upf_arp_table {
      
      key = {
         hdr.ipv4.dst_addr: exact;
      }
           
      actions = {
         nop;
         Set_dmac;
      }

      const default_action = nop;
   }
   
    apply {
        
        bit<NUMBER_OF_PORTS> in_port;
        bit<256> ipv6_addr;
        
        if ((local_metadata.parsed == 0) && (hdr.ethernet.ether_type == ETHERTYPE_NDN)){
          mark_to_drop(standard_metadata);
          return;
        }
        
        if (hdr.icmpv6.isValid() && hdr.icmpv6.type == ICMP6_TYPE_NS) {
            ndp_reply_table.apply(); 
            return;
        }

        if(upf_ue_filter_table.apply().hit){
            upf_pdr_getfar_table.apply();
            upf_far_action_table.apply();
            //return;
        }

        if ((local_metadata.NDNpkttype == NDNTYPE_DATA) || (local_metadata.NDNpkttype == NDNTYPE_INTEREST))
        {
            hashName_table.apply();
        }
        if (local_metadata.NDNpkttype == NDNTYPE_NAK) {

          Send_to_cpu();

        }
        else if (local_metadata.NDNpkttype == NDNTYPE_DATA) {
         
          
          PIT.read(local_metadata.mcastports, (bit<32>)local_metadata.hashtray);

          if (local_metadata.mcastports == 0) {

            drop();

          } else {

            //--- a) add to the content store
#ifdef CONTENT_STORE
            CS.write((bit<32>)local_metadata.hashtray, local_metadata.cs_data);
#endif
            
            //--- b) clean the pit entry
            PIT.write((bit<32>)local_metadata.hashtray, 0);

            //--- c) mirror the Data packet to all requesting faces
            getNextFlaggedPort.apply();
          }
        }//NDNTYPE_DATA
        
        else if (local_metadata.NDNpkttype == NDNTYPE_INTEREST) //Parser rejected other packet types; only Interest is possible here
        {
    #ifdef CONTENT_STORE
         
           bit<NDN_CACHE_LEN> ndnCache;
           CS.read(ndnCache, (bit<32>)local_metadata.hashtray);

          if (ndnCache != 0) {
            standard_metadata.egress_spec = standard_metadata.ingress_port;
            hdr.cs_data.setValid();
            hdr.cs_data.type = ndnCache[(NDN_CACHE_LEN-1):(NDN_CACHE_LEN-8)];
            hdr.cs_data.lencode = ndnCache[(NDN_CACHE_LEN-9):(NDN_CACHE_LEN-16)];
            hdr.cs_data.value = ndnCache[(NDN_CACHE_LEN-17):0];
            
            hdr.tl0.setInvalid();
            hdr.name.setInvalid();
            hdr.components[0].setInvalid();
            hdr.components[1].setInvalid();
            hdr.components[2].setInvalid();
            hdr.components[3].setInvalid();
            hdr.components[4].setInvalid();
            hdr.userid.setInvalid();
            hdr.qos.setInvalid();
            hdr.selectors.setInvalid();
            hdr.fresh.setInvalid();
            hdr.nonce.setInvalid();
            hdr.lifetime.setInvalid();
            hdr.link.setInvalid();
            hdr.delegation.setInvalid();
            
            bit<48> temp = hdr.ethernet.src_addr;
            hdr.ethernet.src_addr = hdr.ethernet.dst_addr;
            hdr.ethernet.dst_addr = temp;
            
            if(hdr.ipv4.isValid())
            {
                bit<32> temp2 = hdr.ipv4.src_addr;
                hdr.ipv4.src_addr = hdr.ipv4.dst_addr;
                hdr.ipv4.dst_addr = temp2;
                hdr.ipv4.total_len = hdr.ipv4.total_len - local_metadata.NDNpktsize[15:0] + (NDN_CACHE_VALUE_LEN / 8);
            }
            if(hdr.udp.isValid())
            {
                hdr.udp.len = hdr.udp.len - local_metadata.NDNpktsize[15:0] + (NDN_CACHE_VALUE_LEN / 8);
                hdr.udp.checksum = 0;
            }
            return;
          }  else {
    #endif // CONTENT_STORE       
            // Extract association in PIT index 'regindex'.
            PIT.read(in_port, (bit<32>)local_metadata.hashtray);
            
            // CASE A: 
            if (in_port == 0) {
              // A.1 -- Consult the FIB
              
              if(!fib_lpm4.apply().hit)
              {
                  if(!fib_lpm3.apply().hit)
                  {
                      if(!fib_lpm2.apply().hit)
                      {
                          if(!fib_lpm1.apply().hit)
                          {
                              drop();
                          }
                      }
                  }
              }
              
              // A.2 -- Store data in PIT
              PIT.write((bit<32>)local_metadata.hashtray, 
                  (bit<NUMBER_OF_PORTS>) 1 << ((bit<8>) standard_metadata.ingress_port));
              return;
            // CASE B: 
            // Cell is already occupied with the same name as this Interest
            } else{
              
              // B.1 -- Retrieve the bit array already there
              PIT.read(local_metadata.mcastports, (bit<32>)local_metadata.hashtray);
              
              // B.2 -- BIT-OR the current array with the bit of this ingress_port
              // to memorize that it is also requesting the same name
              local_metadata.mcastports = local_metadata.mcastports | 
                ((bit<NUMBER_OF_PORTS>) 1 << ((bit<8>) standard_metadata.ingress_port));

              // B.3 -- Store the result back in the PIT
              PIT.write((bit<32>)local_metadata.hashtray, local_metadata.mcastports);
              return;
            } 
    #ifdef CONTENT_STORE
          }
    #endif
        }
        upf_arp_table.apply();
        l2_exact_table.apply();
        l2_forward_bypass_table.apply();
        //broadcast.apply();
    }
}