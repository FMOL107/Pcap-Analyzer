# coding:UTF-8
__author__ = 'dj'

import collections
import tempfile
import sys


def get_all_pcap(PCAPS, PD):
    '''
    File processing for pcap files, returning dictionary format
    '''
    pcaps = collections.OrderedDict()
    for count, i in enumerate(PCAPS, 1):
        pcaps[count] = PD.ether_decode(i)
    return pcaps


def get_filter_pcap(PCAPS, PD, key, value):
    '''
    Return specific protocols for filtering
    '''
    pcaps = collections.OrderedDict()
    count = 1
    for p in PCAPS:
        pcap = PD.ether_decode(p)
        if key == 'Procotol':
            if value == pcap.get('Procotol').upper():
                pcaps[count] = pcap
                count += 1
            else:
                pass
        elif key == 'Source':
            if value == pcap.get('Source').upper():
                pcaps[count] = pcap
                count += 1
        elif key == 'Destination':
            if value == pcap.get('Destination').upper():
                pcaps[count] = pcap
                count += 1
        else:
            pass
    # Return pcap filtered records in order
    return pcaps


def proto_filter(filter_type, value, PCAPS, PD):
    '''
    Protocol filtering to select the correct protocol to display based on the selection
    Filter by "Start address: port", "Destination address: port", "Protocol"
    '''
    if filter_type == u'all':
        pcaps = get_all_pcap(PCAPS, PD)
    elif filter_type == u'proto':
        key = 'Procotol'
        value = str(value).strip().upper()
        pcaps = get_filter_pcap(PCAPS, PD, key, value)
    elif filter_type == u'ipsrc':
        key = 'Source'
        value = str(value).strip().upper()
        pcaps = get_filter_pcap(PCAPS, PD, key, value)
    elif filter_type == u'ipdst':
        key = 'Destination'
        value = str(value).strip().upper()
        pcaps = get_filter_pcap(PCAPS, PD, key, value)
    else:
        pcaps = get_all_pcap(PCAPS, PD)
    return pcaps


def showdata_from_id(PCAPS, dataid):
    pcap = PCAPS[dataid]
    # Exporting redirected data
    show_temp_name = tempfile.NamedTemporaryFile(prefix='show_', dir='/tmp')
    old = sys.stdout
    show_file = open(show_temp_name.name, 'w')
    sys.stdout = show_file
    pcap.show()
    sys.stdout = old
    show_file.close()
    # Read data
    with open(show_temp_name.name, 'r') as showf:
        data = showf.read()
    result = data.strip().split('###')[1:]
    html = '''
            <div class="accordion-group">
                <div class="accordion-heading">
                    <b><a class="accordion-toggle" data-toggle="collapse" data-parent="#accordion" href="#collapse{id}">
                        {proto}
                    </a></b><br>
                    </div>
                    <div id="collapse{id}" class="accordion-body collapse" style="height: 0px; ">
                    <div class="accordion-inner">
                        {values}
                    </div>
                </div>
            </div>
'''
    all_html = ''
    id = 0
    for proto, value in zip(result[::2], result[1::2]):
        id += 1
        html_proto = proto.strip()[1:-1].strip()
        html_values = ''
        values = value.strip().split('\n')
        for v in values:
            val = v.split('  =')
            if len(val) == 2:
                html_values += '<b>{0} = {1}</b><br>'.format(
                    val[0].strip(), val[1].strip())
            elif len(val) == 1:
                html_values += '<b>{0} = {1}</b><br>'.format('options', 'None')
        all_html += html.format(proto=html_proto,
                                values=html_values, id=str(id))
    return all_html
