from preprocessing import *

def test_identify_flow():
    #file='../data/d1/baidu/baidu__overall.pcap'
    file='../data/test.pcap'
    flows=identify_flow(file)
    print(len(flows))
    for flow in flows:
        flow=list(flow.values())[0]
        print(len(flow))


def test_collect_flows():
    collect_flows('../data/d1')
    collect_flows('../data/d2')

if __name__=='__main__':
    test_identify_flow()
    #test_collect_flows()
