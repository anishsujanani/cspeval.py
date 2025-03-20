'''
Author: Anish Sujanani
Date: March, 2025
'''

import requests
import sys

directives_values_colours_map = {
    'base-uri': { # no explicit red, * is invalid 
        'green': ['none', 'self']
    },
    'child-src': {
        'green': ['none', 'self'],
        'red'  : ['unsafe-inline', 'unsafe-eval', 'data', 'blob']
    },
    'connect-src': {
        'green': ['none', 'self'],
        'red'  : ['unsafe-inline', 'unsafe-eval', 'data', 'blob']
    },
    'default-src': {
        'green': ['none', 'self'],
        'red'  : ['unsafe-inline', 'unsafe-eval', 'data', 'blob']
    },
    'font-src': {
        'green': ['none', 'self'],
        'red'  : ['unsafe-inline', 'unsafe-eval', 'data', 'blob']
    },
    'form-action': { # no explicit red, * is invalid
        'green': ['self', 'none']
    },
    'frame-ancestors': { # no explicit red, * is invalid
        'green': ['self', 'none'] 
    },
    'frame-src': {
        'green': ['none', 'self'],
        'red'  : ['unsafe-inline', 'unsafe-eval', 'data', 'blob']
    },
    'img-src': {
        'green': ['none', 'self'],
        'red'  : ['unsafe-inline', 'unsafe-eval', 'data', 'blob', 'filesystems']
    },
     'manifest-src': {
        'green': ['none', 'self'],
        'red'  : ['unsafe-inline', 'unsafe-eval', 'data', 'blob']
    },
    'media-src': {
        'green': ['none', 'self'],
        'red'  : ['unsafe-inline', 'unsafe-eval', 'data', 'blob']
    },
    'navigate-to': {
        'green': ['none', 'self'],
        'red'  : ['unsafe-inline', 'unsafe-eval', 'data', 'blob']
    },
    'object-src': {
        'green': ['none', 'self'],
        'red'  : ['unsafe-inline', 'unsafe-eval', 'data', 'blob']
    },
    'prefetch-src': {
        'green': ['none', 'self'],
        'red'  : ['unsafe-inline', 'unsafe-eval', 'data', 'blob']
    },
    'sandbox': {}, # max restriction without explicit values
    'script-src': {
        'green': ['none', 'self', 'report-sample'],
        'red'  : ['unsafe-inline', 'unsafe-eval', 'data', 'blob', 'strict-dynamic']
    },
    'script-src-attr': {
        'green': ['none', 'self', 'report-sample'],
        'red'  : ['unsafe-inline', 'unsafe-eval', 'data', 'blob', 'strict-dynamic']
    },
    'script-src-elem': {
        'green': ['none', 'self', 'report-sample'],
        'red'  : ['unsafe-inline', 'unsafe-eval', 'data', 'blob', 'strict-dynamic']
    },
    'style-src': {
        'green': ['none', 'self'],
        'red'  : ['unsafe-inline', 'unsafe-eval', 'data', 'blob', 'unsafe-hashes']
    },
    'style-src-attr': {
        'green': ['none', 'self'],
        'red'  : ['unsafe-inline', 'unsafe-eval', 'data', 'blob', 'unsafe-hashes']
    },
    'style-src-elem': {
        'green': ['none', 'self'],
        'red'  : ['unsafe-inline', 'unsafe-eval', 'data', 'blob', 'unsafe-hashes']
    },
    'trusted-types': {
        'green': ['default', 'none'],
        'red': ['*'] 
    },
    'worker-src': {
        'green': ['none', 'self'],
        'red'  : ['unsafe-inline', 'unsafe-eval', 'data', 'blob']
    }
}

colstrings = {
    'green'    : '\033[92m',
    'red'      : '\033[91m',
    'white'    : '\033[37m',
    'cyan'     : '\033[36m',
    'underline': '\033[4m',
    'end'      : '\033[0m'
}    

def get_csp_header_for_domain(url):
    r = requests.get(url)
    return dict(r.headers).get('content-security-policy-report-only')

def colour_value_string(directive, value):
    if directive not in directives_values_colours_map:
        return f'{value}\n'
    
    _val = value.strip().replace('"', '').replace("'", '') 
    end = colstrings['end']
    itrbl = iter([colstrings[colour] for colour, values in directives_values_colours_map[directive].items() if _val in values])
    colapply = next(itrbl, 'no_match')

    # if we didn't match this value against any known colouring rule, can apply custom colour here 
    if colapply == 'no_match':

        # custom rule to red-highlight custom policies in trusted_types directives
        if directive == 'trusted_types':
            colapply = colstrings['red']

        # custom rule to green-highlight subdomains and cyan for external 
        # domains (or values that aren't explicitly red-highlighted)
        else:    
            _domain = sys.argv[1].split('://')[1].split('.')[-2] 
            if _domain in _val:
                colapply = colstrings['green']
            else:
                colapply = colstrings['cyan']


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
