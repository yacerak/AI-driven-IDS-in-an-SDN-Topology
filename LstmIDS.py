#!/usr/bin/env python3
import os
# Suppress TensorFlow/ONNX warnings
os.environ['TF_CPP_MIN_LOG_LEVEL'] = '3'
os.environ['ORT_DISABLE_GPU'] = '1'
import warnings; warnings.filterwarnings("ignore", category=UserWarning)

from ryu.lib.packet import arp
from collections import defaultdict  # Added for mac_to_port

import pandas as pd
import joblib
import numpy as np
import requests
import time 
from ryu.lib import hub  
import threading  
from decoder2 import NSLKDDDecoder
from tensorflow.keras.models import load_model

from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet, ethernet, ether_types, ipv4, packet_base
import onnxruntime as ort

import logging

import os
os.environ['CUDA_VISIBLE_DEVICES'] = '-1'
os.environ['TF_ENABLE_ONEDNN_OPTS']   = '0'

# --- NSL-KDD feature definitions ---
feature_columns = [
    "duration", "protocol_type", "service", "flag", "src_bytes", "dst_bytes",
    "land", "wrong_fragment", "urgent", "hot", "num_failed_logins", "logged_in",
    "num_compromised", "root_shell", "su_attempted", "num_root", "num_file_creations",
    "num_shells", "num_access_files", "num_outbound_cmds", "is_host_login",
    "is_guest_login", "count", "srv_count", "serror_rate", "srv_serror_rate",
    "rerror_rate", "srv_rerror_rate", "same_srv_rate", "diff_srv_rate",
    "srv_diff_host_rate", "dst_host_count", "dst_host_srv_count",
    "dst_host_same_srv_rate", "dst_host_diff_srv_rate", "dst_host_same_src_port_rate",
    "dst_host_srv_diff_host_rate", "dst_host_serror_rate", "dst_host_srv_serror_rate",
    "dst_host_rerror_rate", "dst_host_srv_rerror_rate"
]
categorical_cols = ["protocol_type", "service", "flag"]

class IDSController(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        super().__init__(*args, **kwargs)
        self.log_buffer = []
        self.buffer_lock = threading.Lock()
        self.flow_lock   = threading.Lock()
        self.ip_to_mac   = {}
        self.dps         = {}
        self.mac_to_port = defaultdict(lambda: defaultdict(int))

        hub.spawn(self._async_log_writer)

        self.numeric_cols = [c for c in feature_columns if c not in categorical_cols]
        self.logger.setLevel(logging.INFO)
        self.CLASS_MAP = {0: "normal", 1: "abnormal"}

        self.encoder = joblib.load("modeles/onehot_encoder.pkl")
        self.model   = ort.InferenceSession("modeles/lstm_quant.onnx",
                                            providers=["CPUExecutionProvider"])

        # one‐hot names = col_category for every category in each categorical column
        ohe_names = [
            f"{col}_{cat}"
            for col, cats in zip(categorical_cols, self.encoder.categories_)
            for cat in cats
        ]
        self.feature_names = self.numeric_cols + ohe_names

        self.decoder = NSLKDDDecoder(feature_callback=self.on_features)

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        """Fixed method with correct variable order"""
        print("switch_features_handler")   
        datapath = ev.msg.datapath
        self.dps[datapath.id] = datapath
        parser = datapath.ofproto_parser
        # table-miss
        self.add_flow(datapath, 0, parser.OFPMatch(),
                      [parser.OFPActionOutput(datapath.ofproto.OFPP_CONTROLLER)])
        # ARP
        arp_match = parser.OFPMatch(eth_type=ether_types.ETH_TYPE_ARP)
        self.add_flow(datapath, 1, arp_match,
                      [parser.OFPActionOutput(datapath.ofproto.OFPP_CONTROLLER)])
    
    def _async_log_writer(self):
        """Background thread for writing logs"""
        while True:
            with self.buffer_lock:
                if self.log_buffer:
                    with open("predictions_ltsm.csv", "a") as f:
                        f.writelines(self.log_buffer)
                    self.log_buffer.clear() 
            hub.sleep(1)  # Non-blocking sleep
    
    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):
        try:
            msg      = ev.msg
            datapath = msg.datapath
            parser   = datapath.ofproto_parser
            in_port  = msg.match['in_port']

            pkt = packet.Packet(msg.data)
            eth = pkt.get_protocol(ethernet.ethernet)
            if eth.ethertype == ether_types.ETH_TYPE_LLDP:
                return

            # LEARN MAC first:
            src = eth.src                          # <<< FIX: define src here
            dpid = format(datapath.id, 'd').zfill(16)
            self.mac_to_port[dpid][src] = in_port

            # ARP?
            if eth.ethertype == ether_types.ETH_TYPE_ARP:
                self.handle_arp(datapath, msg, pkt)
                return

            # IP → IDS
            ip_pkt = pkt.get_protocol(ipv4.ipv4)
            if ip_pkt:
                pkt_info = {
                    'ip': {'src': ip_pkt.src, 'dst': ip_pkt.dst},
                    'raw': msg.data,
                    'timestamp': time.time()
                }
                # pass src_ip through features
                pkt_info['src_ip'] = ip_pkt.src     # <<< FIX: include this so on_features sees src_ip
                hub.spawn(self._async_ids_processing, pkt_info, datapath)

            # FORWARDING (learning-switch)...
            dst = eth.dst
            out_port = (self.mac_to_port[dpid].get(dst, datapath.ofproto.OFPP_FLOOD))
            if out_port == datapath.ofproto.OFPP_FLOOD:
                self.add_flow(datapath, 1,
                              parser.OFPMatch(eth_dst=dst),
                              [parser.OFPActionOutput(out_port)])
            actions = [parser.OFPActionOutput(out_port)]
            if out_port != datapath.ofproto.OFPP_FLOOD:
                match = parser.OFPMatch(in_port=in_port, eth_dst=dst, eth_src=src)
                self.add_flow(datapath, 1, match, actions, msg.buffer_id)
            data = msg.data if msg.buffer_id == datapath.ofproto.OFP_NO_BUFFER else None
            out = parser.OFPPacketOut(datapath=datapath, buffer_id=msg.buffer_id,
                                     in_port=in_port, actions=actions, data=data)
            datapath.send_msg(out)

        except Exception as e:
            self.logger.error(f"Packet handling failed: {e}", exc_info=True)

        
    
    def _async_ids_processing(self, pkt_info, datapath):
        """Asynchronous IDS feature processing and blocking"""
        try:
            self.decoder.process_packet(pkt_info)
        except Exception as e:
            self.logger.error(f"IDS processing failed: {str(e)}")
    
    def _async_inference(self, features, datapath):
        try:
            resp = requests.post("http://127.0.0.1:5000/predict", json=features, timeout=0.1)
            result = resp.json()
            if result["label"] == 1:  # attack
                self.block_ip(...)
        except Exception as e:
            self.logger.error(f"Inference error: {e}")
    
    def on_features(self, features, datapath=None):
        """Callback for processed features"""
        if not features:
            return
        try:
            df = self.preprocess_features(features)
            X  = np.expand_dims(df.values, axis=0).astype(np.float32)
            inp_name  = self.model.get_inputs()[0].name
            out_name  = self.model.get_outputs()[0].name
            probs     = self.model.run([out_name], {inp_name: X})[0][0]
            label     = self.CLASS_MAP[np.argmax(probs)]

            # log
            with self.buffer_lock:
                self.log_buffer.clear()           # <<< FIX
                row_id = features.get('row_id','')
                src_ip = features.get('src_ip','unknown')
                self.log_buffer.append(f"{row_id},{src_ip},{label},{probs.max()}\n")

            # block if attack
            if label != "normal" and datapath:
                self.logger.warning(f"Blocking {src_ip}")
                self._block_ip(datapath, src_ip)  # <<< FIX: correct method

        except Exception as e:
            self.logger.error(f"Feature processing failed: {e}", exc_info=True)
            
    def preprocess_features(self, features):
        """One-hot encode + align to MLP feature order, filling missing fields."""
        print("preprocess_features")       
        for i, col in enumerate(categorical_cols):
            if col not in features:
                features[col] = self.encoder.categories_[i][0]
            else:
                if features[col] not in self.encoder.categories_[i]:
                    features[col] = self.encoder.categories_[i][0]

        # Create DataFrame
        df = pd.DataFrame([features])

        # Convert numeric columns
        df[self.numeric_cols] = df[self.numeric_cols].apply(pd.to_numeric, errors="coerce").fillna(0)

        # One-hot encode categoricals
        arr = self.encoder.transform(df[categorical_cols])
        names = [f"{col}_{cat}" for col, cats in zip(categorical_cols, self.encoder.categories_) for cat in cats]
        encoded_df = pd.DataFrame(arr, columns=names, dtype=float)

        # Combine and align to model
        full_df = pd.concat([df[self.numeric_cols], encoded_df], axis=1)
        full_df = full_df.reindex(columns=self.feature_names, fill_value=0.0)
        return full_df.astype(np.float64)

    def _block_ip(self, datapath, ip_address):
        """Thread-safe flow blocking"""
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        
        # Add drop flow for malicious IP
        match = parser.OFPMatch(eth_type=ether_types.ETH_TYPE_IP, ipv4_src=ip_address)
        self.add_flow(
            datapath=datapath,
            priority=100,
            match=match,
            actions=[],
            hard_timeout=300,  # Now properly accepted
            idle_timeout=0
        )

    def add_flow(self, datapath, priority, match, actions, buffer_id=None, idle_timeout=0, hard_timeout=0):
        """Add flow entry with timeout support"""
        print("add_flow")
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
    
        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)]
    
        mod = parser.OFPFlowMod(
            datapath=datapath,
            priority=priority,
            match=match,
            instructions=inst,
            idle_timeout=idle_timeout,
            hard_timeout=hard_timeout
        )
    
        if buffer_id:
            mod.buffer_id = buffer_id
        
        datapath.send_msg(mod)
    
    def handle_arp(self, datapath, msg, pkt):
        arp_pkt = pkt.get_protocol(arp.arp)
        if arp_pkt:
            # Always learn source IP/MAC regardless of opcode
            self.ip_to_mac[arp_pkt.src_ip] = arp_pkt.src_mac
            self.logger.info(f"Learned {arp_pkt.src_ip} -> {arp_pkt.src_mac}")

            if arp_pkt.opcode == arp.ARP_REQUEST:
                self.logger.debug(f"ARP Request: {arp_pkt.src_ip} -> {arp_pkt.dst_ip}")
                # Forward request to all ports except incoming
                self.flood_arp(datapath, msg, arp_pkt)
                # Send reply if we know the target
                self.send_arp_reply(datapath, arp_pkt, msg)
            elif arp_pkt.opcode == arp.ARP_REPLY:
                self.logger.debug(f"ARP Reply: {arp_pkt.src_ip} is at {arp_pkt.src_mac}")
            
    def send_arp_reply(self, datapath, arp_pkt, msg):
        """Send ARP reply for known IP addresses"""
        # Check if we know the target IP's MAC
        in_port = msg.match['in_port']  # Fixed line
    
        actions = [datapath.ofproto_parser.OFPActionOutput(in_port)]
        target_ip = arp_pkt.dst_ip
        if target_ip not in self.ip_to_mac:    
            self.logger.warning(f"No MAC found for IP {target_ip}, cannot reply")
            return

        # Build ARP reply
        arp_reply = arp.arp(
            opcode=arp.ARP_REPLY,
            src_mac=self.ip_to_mac[target_ip],
            src_ip=target_ip,
            dst_mac=arp_pkt.src_mac,
            dst_ip=arp_pkt.src_ip
        )

        # Build Ethernet frame
        eth_reply = ethernet.ethernet(
            ethertype=ether_types.ETH_TYPE_ARP,
            dst=arp_pkt.src_mac,
            src=self.ip_to_mac[target_ip]
        )

        # Construct full packet
        pkt = packet.Packet()
        pkt.add_protocol(eth_reply)
        pkt.add_protocol(arp_reply)
        pkt.serialize()

        # Send reply back through incoming port
        actions = [datapath.ofproto_parser.OFPActionOutput(msg.in_port)]
        out = datapath.ofproto_parser.OFPPacketOut(
            datapath=datapath,
            buffer_id=datapath.ofproto.OFP_NO_BUFFER,
            in_port=datapath.ofproto.OFPP_CONTROLLER,
            actions=actions,
            data=pkt.data
        )
        datapath.send_msg(out)
        self.logger.info(f"Sent ARP reply for {target_ip} to {arp_pkt.src_ip}")
    
    def _cleanup_tables(self):
        """Periodic cleanup of MAC tables"""
        with self.flow_lock:
            for dpid in list(self.mac_to_port.keys()):
                if dpid not in self.dps:  # Switch disconnected
                    del self.mac_to_port[dpid]
    
    def flood_arp(self, datapath, msg, arp_pkt):
        """Flood ARP requests to all ports except incoming"""
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
    
        # Create match for ARP
        match = parser.OFPMatch(
            eth_type=ether_types.ETH_TYPE_ARP,
            arp_tpa=arp_pkt.dst_ip
        )

        # Flood to all ports except incoming
        actions = [parser.OFPActionOutput(ofproto.OFPP_FLOOD)]
        
        # Install temporary flow
        self.add_flow(
            datapath=datapath,
            priority=2,
            match=match,
            actions=actions,
            idle_timeout=5,  # Now properly accepted
            hard_timeout=0
        )

        # Send original packet out
        data = msg.data if msg.buffer_id == ofproto.OFP_NO_BUFFER else None
        out = parser.OFPPacketOut(
            datapath=datapath,
            buffer_id=msg.buffer_id,
            in_port=msg.match['in_port'],
            actions=actions,
            data=data
        )
        datapath.send_msg(out)
        

