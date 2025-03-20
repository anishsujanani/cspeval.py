'''
Author: Anish Sujanani
Date: March, 2025
'''

import requests
import sys

directives_values_colours_map = {
    'default-src': { 
        'red'  : ['*', 'data', 'blob', 'filesystem'], 
        'green': ['none', 'self'] 
    },
    'base-uri': { 
        'green': ['none', 'self'], 
        'red'  : ['*'] 
    },
    'style-src': {
        'red': ['unsafe-inline']
    }
}

colstrings = {
    'green'    : '\033[92m',
    'red'      : '\033[91m',
    'underline': '\033[4m',
    'end'      : '\033[0m'
}    

def get_csp_header_for_domain(url):
    r = requests.get(url)
    return dict(r.headers).get('Content-Security-Policy')

def colour_value_string(directive, value):
    if directive not in directives_values_colours_map:
        return f'{value}\n'
    
    _val = value.strip().replace('"', '').replace("'", '') 
    end = colstrings['end']
    itrbl = iter([colstrings[colour] for colour, values in directives_values_colours_map[directive].items() if _val in values])
    colapply = next(itrbl, '')
    return f'{colapply}{value}{end}\n'
 
def nice_csp_print(header_val):
    op = ''
    
    statements = header_val.split(';')[:-1]
    for s in statements: 
        directive, *values = s.strip().split(' ')

        op += f'\n{colstrings["underline"]}{directive}{colstrings["end"]}\n'

        for v in values:
            op += colour_value_string(directive, v)

    return op    

if __name__ == '__main__':
    if len(sys.argv) != 2:
        print('Usage: python3 nicecsp.py <url>')
        sys.exit(1)

    header_val = get_csp_header_for_domain(sys.argv[1])
    print(nice_csp_print(header_val))
