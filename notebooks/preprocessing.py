# %%
"""
## Preprocessing of EBSNN

1. Temporarily implemented a fast version, just to make training possible
    1. features, labels (for train, valid, and test set)
    2. pickle for file (no need of h5py with enough memory)
    3. segmentation is not done here
2. Then implement detailed preprocessing
    1. handle errors
    2. removing features like IP addresses as described in the paper
3. I want the preprocessing to handle details and nothing special to do in dataset.
"""

# %%
import os
import sys
import pickle
import json
import dpkt
import h5py
import numpy as np
import traceback
import glob
import math
from sklearn.model_selection import train_test_split
from bitstring import BitArray
from enum import Enum
# def calculate_alpha(counter, mode='normal'):
#     if mode == 'normal':
#         alpha = torch.tensor(counter, dtype=torch.float32)
#         alpha = alpha / alpha.sum(0).expand_as(alpha)
#     elif mode == 'invert':
#         alpha = torch.tensor(counter, dtype=torch.float32)
#         alpha_sum = alpha.sum(0)
#         alpha_sum_expand = alpha_sum.expand_as(alpha)
#         alpha = (alpha_sum - alpha) / alpha_sum_expand
#     # fill all zeros to ones
#     alpha[alpha==0.] = 1.
#     return alpha
#Labels=Enum('Labels', ['reddit','facebook','NeteaseMusic','twitter','qqmail','instagram','weibo','iqiyi','imdb','TED','douban','amazon','youtube','JD','youku','baidu','google','tieba','taobao','bing'], start=0) ##d2
Labels=Enum('Labels', ['MS-Exchange','facebook','kugou','sinauc','thunder','weibo','aimchat','gmail','mssql','skype','tudou','yahoomail', 'amazon', 'google', 'netflix','sohu','twitter','youku', 'baidu','itunes', 'pplive','spotify','vimeo','youtube','cloudmusic','jd','qq','taobao','voipbuster'], start=0)

def eprint(*args, **kargs):
    print(*args, file=sys.stderr, **kargs)

def process_buffer(buf, max_length=1500):
    eth = dpkt.ethernet.Ethernet(buf)
    if not isinstance(eth.data, dpkt.ip.IP):
        return None
    ip = eth.data
    if not isinstance(ip.data, dpkt.tcp.TCP):
        return None
    tcp = ip.data
    payload = tcp.data
    res=[]
    ## read the packet in binary format and transform it into a sequence of 8-bit integers in the range of [0~255]
    int_list=list(buf)
    ##The 8-bit integer sequence of the packet is then split into the Ethernet header, IPv4 header, the TCP/UDP header,and the payload subsequences.
    W=0
    try:
        c = BitArray(buf)
        W=len(c.bin)
        eth_header=c[:112]
        U=c[116:120].uint
        IPV4_header=c[112:112+32*U]
        V=c[208+32*U:212+32*U].uint #for TCP
        TCP_header=c[112+32*U:112+32*(U+V)]
        payload=c[112+32*(U+V):]
        eth_header=int_list[:14]
        IPV4_header=int_list[14:14+4*U]
        TCP_header=int_list[14+4*U:14+4*(U+V)]
        payload=int_list[14+4*(U+V):]
        ## the segment generator preprocesses and breaks these subsequences into byte segments with fixed-length N,
        N=4 #4 bytes form a segment
        #payload_seg_num=math.ceil(len(payload)/N)
        #pad_num=payload_seg_num*N-len(payload)
        #payload=payload+[0]*pad_num
        ## masked
        ip_id=IPV4_header[4]
        ip_id=BitArray(bin(ip_id)).bin.zfill(8)
        ip_id='0'*6+ip_id[6:]
        IPV4_header[4]=int(ip_id, 2)
        IPV4_header[10:20]=[0]*10
        TCP_header[0]=0
        TCP_header[1]=0
        res=IPV4_header+TCP_header+payload
    except:
        print(W)
        traceback.print_exc()
    return res


def identify_flow(pfile):
    f=open(pfile, 'rb')
    start_tcp=False
    end_tcp=False
    flows=[]
    flow=[]
    pcap=dpkt.pcap.Reader(f)
    for ts, buf in pcap:
        try:
            eth=dpkt.ethernet.Ethernet(buf)
            ip=eth.data
            if not isinstance(ip, dpkt.ip.IP):
                continue
            tcp=ip.data
            if not isinstance(tcp, dpkt.tcp.TCP):
                continue
            if tcp.flags==0x02: #SYN
                if len(flow):
                    flows.append(flow)
                flow=[]
                continue
            if len(flow)>20:
                continue
            if len(tcp.data)==0:
                continue
            flow.append(buf)
        except:
            eprint('ERROR identifying flows',)# eth, tcp)
            traceback.print_exc()

    f.close()
    return flows


def collect_flows(data_dir):
    all_flows={}
    if 'd2' in data_dir:
        files=glob.glob(os.path.join(data_dir,'*.pcap'))
        for f in files:
            label=f.strip().split('/')[-1].split('_')[0]
            if label not in all_flows.keys():
                all_flows[label]=[]
            try:
                flow_f=identify_flow(f)
                all_flows[label].extend(flow_f)
            except:
                eprint('cannot identify flows from file', f)
                traceback.print_exc()
    if 'd1' in data_dir:
        files=glob.glob(os.path.join(data_dir,'**/*.pcap'))
        for f in files:
            label=f.strip().split('/')[-2]
            if label not in all_flows.keys():
                all_flows[label]=[]
            try:
                flow_f=identify_flow(f)
                all_flows[label].extend(flow_f)
            except:
                eprint('cannot identify flows from file', f)
                traceback.print_exc()

    print(len(all_flows), [len(fl) for fl in all_flows.values()])
    return all_flows

def extract_flow_feature(flows):
    #flows in the form: list of flow list
    #including flows extracted from all pcap files in a APP/web class
    feature=[]
    for flow in flows:
        #a piece of flow containing eth list, with length at most 20
        length=[]
        packets=[]
        for bi, buf in enumerate(flow):
            packet_feature=process_buffer(buf)
            if not packet_feature:
                continue
            packets.append(packet_feature)
            eth = dpkt.ethernet.Ethernet(buf)
            length.append(eth.data.len)
        feature.append((length, packets))
    return feature



def read_class(class_name, data_dir):
    "read a class of packets"
    features = []
    count = 0
    for file in os.listdir(os.path.join(data_dir, class_name)):
        with open(f'../data/d1/{class_name}/{file}', 'rb') as f:
            try:
                pcap = dpkt.pcap.Reader(f)
            except Exception as e:
                traceback.print_exc()
                continue

            for timestamp, buffer in pcap:
                processed_data = process_buffer(buffer)
                if processed_data is not None:  # TODO: better handling
                    features.append(processed_data)
                    count += 1
        break   # FIXME: data size not consistent with paper (weibo 80k vs. 50k), break just for debugging

    print(f"class {class_name} total {count} packets")   # NOTE by zian: does flow needs extra processing ?
    return features


def read_dataset(data_dir, is_flow=True):
    "dataset `d1` or `d2`"

    features = []
    labels = []
    label2id = {}
    id2label = {}
    if is_flow:
        all_flows=collect_flows(data_dir)
        for i, (label, flows) in enumerate(all_flows.items()):
            if len(flows)==0:
                continue
            label2id[label] = Labels[label].value
            id2label[i] = Labels(i).name
            lid=Labels[label].value
            flow_feature=extract_flow_feature(flows)
            features.extend(flow_feature)
            labels.extend([lid]*len(flow_feature))

        return features, labels, label2id, id2label

    for i, class_name in enumerate(os.listdir(data_dir)):
        label2id[class_name] = Labels[class_name].value
        id2label[i] = Labels(i).name
        class_features = read_class(class_name, data_dir)
        lid=Labels[class_name].value
        class_labels = [lid for j in range(len(class_features))]
        features += class_features
        labels += class_labels

    return features, labels, label2id, id2label


def main(is_flow='flow'):

    X, y, label2id, id2label = read_dataset('../data/d1', is_flow=='flow')
    print(y[:5])

    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=1)

    X_train, X_val, y_train, y_val = train_test_split(X_train, y_train, test_size=0.25, random_state=1) # 0.25 x 0.8 = 0.2

    with open(f'../data/d1_train_dump_{is_flow}.pkl', 'wb') as f:
        pickle.dump(X_train, f)
        pickle.dump(y_train, f)
        pickle.dump(label2id, f)
        pickle.dump(id2label, f)

    with open(f'../data/d1_val_dump_{is_flow}.pkl', 'wb') as f:
        pickle.dump(X_val, f)
        pickle.dump(y_val, f)
        pickle.dump(label2id, f)
        pickle.dump(id2label, f)

    with open(f'../data/d1_test_dump_{is_flow}.pkl', 'wb') as f:
        pickle.dump(X_test, f)
        pickle.dump(y_test, f)
        pickle.dump(label2id, f)
        pickle.dump(id2label, f)


if __name__ == '__main__':
    main('flow')
    main('packet')



# %%
