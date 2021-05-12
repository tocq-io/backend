Currently only a simple python script that shows the basic sharing and sending of objects between 2 parties.

Tests can be executed like this:
- export wrangler account-id env variable CF_ACCOUNT_ID
- run 'wrangler dev' in [Cloudflare folder](../cloudflare)
- run 'python3 test_basic_local.py'

Test can also be changed to run only in memory, without wrangler by changing 'with_http' to 'False' in test_basic_local.py.

(Yeah, this is a bit short but it will change over time. Promised.)
