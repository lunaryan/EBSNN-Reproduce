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
from sklearn.model_selection import train_test_split

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
def eprint(*args, **kargs):
    print(*args, file=sys.stderr, **kargs)

def process_buffer(buffer, max_length=1500):
    """
    TODO: detailed processing of packet data (read the paper)

    DPKT docs: https://kbandla.github.io/dpkt/
    """
    try:
        eth = dpkt.ethernet.Ethernet(buffer)
        if not isinstance(eth.data, dpkt.ip.IP):
            return None
        ip = eth.data
        if not isinstance(ip.data, dpkt.tcp.TCP):
            return None
        tcp = ip.data
        payload = tcp.data
    except Exception as e:
        print("[error] {}".format(e))

    # redundant if do padding here
    return bytes(ip)   # debug


def identify_flow(pfile):
    #Each flow is identified with a 4-tuple: (src_ip, dst_ip, src_port, dst_port) and within a SYN-FIN session
    f=open(pfile, 'rb')
    start_tcp=False
    end_tcp=False
    flows=[]
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
                start_tcp=True
                src=ip.src
                dst=ip.dst
                sport=tcp.sport
                dport=tcp.dport
                id=(src,dst,sport,dport)
                flow=dict()
                flow[id]=[]
            if tcp.flags==0x01: #FIN
                start_tcp=False
                flows.append(flow) #in case the same id tuple
            if start_tcp and ip.src==src and ip.dst==dst and tcp.sport==sport and tcp.dport==dport:
                flow[id].append(eth)
        except:
            eprint('ERROR identifying flows',)# eth, tcp)
            traceback.print_exc()

    f.close()
    len_stat=[]
    if len(flows)==0:
        return flows
    for flow in flows:
        flow=list(flow.values())[0]
        len_stat.append(len(flow))
    print('max length of flow in this file:', max(len_stat))
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

    print(len(all_flows), [fl for fl in all_flows.items()])





def read_class(class_name, data_dir):
    "read a class of packets"
    features = []
    count = 0
    failed_files = []
    for file in os.listdir(os.path.join(data_dir, class_name)):
        with open(f'../data/d1/{class_name}/{file}', 'rb') as f:
            try:
                pcap = dpkt.pcap.Reader(f)
            except Exception as e:
                failed_files.append(file)
                traceback.print_exc()
                continue

            for timestamp, buffer in pcap:
                #TODO: add length feature
                processed_data = process_buffer(buffer)
                if processed_data is not None:  # TODO: better handling
                    features.append(processed_data)
                    count += 1
        break   # FIXME: data size not consistent with paper (weibo 80k vs. 50k), break just for debugging

    print(f"class {class_name} total {count} packets")   # NOTE by zian: does flow needs extra processing ?
    print("failed files:", failed_files)
    return features




def read_dataset(data_dir):
    "dataset `d1` or `d2`"

    features = []
    labels = []
    label2id = {}
    id2label = {}
    #TODO: suitable for d2
    for i, class_name in enumerate(os.listdir(data_dir)):
        label2id[class_name] = i
        id2label[i] = class_name
        class_features = read_class(class_name, data_dir)
        class_labels = [i for j in range(len(class_features))]
        features += class_features
        labels += class_labels

    return features, labels, label2id, id2label


def main():

    X, y, label2id, id2label = read_dataset('../data/d1')
    print(y[:5])

    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=1)

    X_train, X_val, y_train, y_val = train_test_split(X_train, y_train, test_size=0.25, random_state=1) # 0.25 x 0.8 = 0.2

    with open('../data/d1_train_dump.pkl', 'wb') as f:
        pickle.dump(X_train, f)
        pickle.dump(y_train, f)
        pickle.dump(label2id, f)
        pickle.dump(id2label, f)

    with open('../data/d1_val_dump.pkl', 'wb') as f:
        pickle.dump(X_val, f)
        pickle.dump(y_val, f)
        pickle.dump(label2id, f)
        pickle.dump(id2label, f)

    with open('../data/d1_test_dump.pkl', 'wb') as f:
        pickle.dump(X_test, f)
        pickle.dump(y_test, f)
        pickle.dump(label2id, f)
        pickle.dump(id2label, f)


if __name__ == '__main__':
    main()



# %%
