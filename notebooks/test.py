from preprocessing import *

def test_identify_flow():
    #file='../data/d1/baidu/baidu__overall.pcap'
    file='../data/edited/extra_AIMchat1.pcap'
    flows=identify_flow(file)
    print(len(flows))
    for flow in flows:
        print(len(flow), end=' ')


def test_collect_flows():
    #collect_flows('../data/d1')
    collect_flows('../data/d2')

if __name__=='__main__':
    test_identify_flow()
    #test_collect_flows()
