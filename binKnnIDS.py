#!/usr/bin/env python3
import warnings
warnings.filterwarnings("ignore", category=UserWarning)

import pandas as pd
import joblib
import numpy as np
from decoder2 import NSLKDDDecoder

from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet, ethernet, ether_types, ipv4, packet_base

import logging

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
        # enable debug logging
        self.numeric_cols = [c for c in feature_columns if c not in categorical_cols]
        self.logger.setLevel(logging.INFO) 

        # track datapaths and MAC learning
        self.dps = {}
        self.mac_to_port = {}

        # load your pre-trained models
        self.encoder = joblib.load("modeles/onehot_encoder.pkl")
        self.model    = joblib.load("modeles/binaryKNN.pkl")

        # set up the NSL-KDD decoder with a callback
        self.decoder = NSLKDDDecoder(feature_callback=self.on_features)
        self.CLASS_MAP = {0: "normal", 1: "abnormal"}

        # one‐hot names = col_category for every category in each categorical column
        ohe_names = [
            f"{col}_{cat}"
            for col, cats in zip(categorical_cols, self.encoder.categories_)
            for cat in cats
        ]
        if hasattr(self.model, 'feature_names_in_'):
           self.feature_names = self.model.feature_names_in_

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        datapath = ev.msg.datapath
        # store datapath for future use in block_ip
        self.dps[datapath.id] = datapath

        # install table-miss flow entry
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER,
                                          ofproto.OFPCML_NO_BUFFER)]
        self.add_flow(datapath, 0, match, actions)

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        datapath = ev.msg.datapath
        self.dps[datapath.id] = datapath

        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER,
                                          ofproto.OFPCML_NO_BUFFER)]
        self.add_flow(datapath, 0, match, actions)

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):
        msg = ev.msg
        datapath = msg.datapath
        parser = datapath.ofproto_parser
        in_port = msg.match['in_port']

        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocol(ethernet.ethernet)

        # Ignore LLDP
        if eth.ethertype == ether_types.ETH_TYPE_LLDP:
            return

        # IDS PART
        ip_pkt = pkt.get_protocol(ipv4.ipv4)
        payload = msg.data  # Use raw packet data for IDS
        if ip_pkt:
            pkt_info = {
                'ip':  {'src': ip_pkt.src, 'dst': ip_pkt.dst},
                'raw': payload
            }
            features = self.decoder.process_packet(pkt_info)

            if features:
                self.logger.info(f"[IDS] on_features() firing for {features['src_ip']}")
                self.on_features(features)

        # Learning-switch part
        src = eth.src
        dst = eth.dst
        dpid = format(datapath.id, 'd').zfill(16)
        self.mac_to_port.setdefault(dpid, {})[src] = in_port

        if dst in self.mac_to_port[dpid]:
            out_port = self.mac_to_port[dpid][dst]
        else:
            out_port = datapath.ofproto.OFPP_FLOOD

        actions = [parser.OFPActionOutput(out_port)]
        if out_port != datapath.ofproto.OFPP_FLOOD:
            match = parser.OFPMatch(in_port=in_port, eth_dst=dst, eth_src=src)
            if msg.buffer_id != datapath.ofproto.OFP_NO_BUFFER:
                self.add_flow(datapath, 1, match, actions, msg.buffer_id)
                return
            else:
                self.add_flow(datapath, 1, match, actions)

        data = None
        if msg.buffer_id == datapath.ofproto.OFP_NO_BUFFER:
            data = msg.data

        out = parser.OFPPacketOut(datapath=datapath,
                                  buffer_id=msg.buffer_id,
                                  in_port=in_port,
                                  actions=actions,
                                  data=data)
        datapath.send_msg(out)

    def on_features(self, features):
        df = self.preprocess_features(features)
        numeric_label = self.model.predict(df)[0]
        label = self.CLASS_MAP[numeric_label]

        if label.lower() != "normal":
            self.logger.error(f"🚨 {label.upper()} detected from {features['src_ip']} — blocking")
            self.block_ip(features['src_ip'])
        else:
            self.logger.info(f"✅ Normal traffic from {features['src_ip']}")

    def on_features(self, features):
        df = self.preprocess_features(features)
        numeric_label = self.model.predict(df)[0]  # Returns 0 or 1
        label = self.CLASS_MAP[numeric_label]      # Convert to string
    
        if label.lower() != "normal":
            self.logger.error(f"🚨 {label.upper()} detected from {features['src_ip']} — blocking")
            self.block_ip(features['src_ip'])
        else:
            self.logger.info(f"✅ Normal traffic from {features['src_ip']}")


    def preprocess_features(self, features):
        """One-hot encode + align to MLP feature order, filling missing fields."""
        
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
        full_df = full_df.reindex(columns=self.model.feature_names_in_, fill_value=0.0)
        return full_df.astype(np.float64)

    def block_ip(self, ip):
        """Install a longer-lasting block rule."""
        for dp in self.dps.values():
            parser = dp.ofproto_parser
            match = parser.OFPMatch(eth_type=0x0800, ipv4_src=ip)
            mod = parser.OFPFlowMod(
                datapath=dp,
                priority=100,
                match=match,
                instructions=[],
                hard_timeout=3600  # 1 hour timeout
            )
            dp.send_msg(mod)

    def add_flow(self, datapath, priority, match, actions, buffer_id=None):
        ofproto = datapath.ofproto
        parser  = datapath.ofproto_parser
        inst    = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)]
        if buffer_id:
            mod = parser.OFPFlowMod(datapath=datapath, buffer_id=buffer_id,
                                    priority=priority, match=match,
                                    instructions=inst)
        else:
            mod = parser.OFPFlowMod(datapath=datapath,
                                    priority=priority,
                                    match=match,
                                    instructions=inst)
        datapath.send_msg(mod)

