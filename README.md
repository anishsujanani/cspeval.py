# cspeval.py

A tool to parse CSP headers out of GET requests, pretty-print directives and colour-code values based on security impact. The colour map is a `dict` in the code if you want custom highlights. 

Flow:
1. If you are not sure what header to use, enter a dummy value, ex.: `abc`. The script will give you an error and a list of headers that were returned. 
2. Check if the domain sets a `Content-Security-Policy`, `content-security-policy-report-only`, etc. (case-sensitive)
3. Run the script with the right header name.
4. The directives and values are colour-coded based on the map in the code.
5. Custom rules include:
	- cyan-coding URLs that do not belong to the same domain.
	- red-coding all custom policies set in the `trusted_types` directive.

Output:
![DemoGIF][1]

Usage:
```
python3 cspeval.py <domain> <header_name>
```

[1]: https://github.com/anishsujanani/cspeval.py/blob/master/cspeval_op.gif 
