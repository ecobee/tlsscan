# tlsscan

tlsscan scans the tls configuration of any TLS enabled protocol (https, smtps, imaps, etc).  Tools like ssllabs are more feature rich, however they are run by external third parties and so we cannot scan internal systems, there may be rating limiting, etc.

## Building

It's all go, with no exotic extras, so it should just be `go build` in the directory.

There's no configaration files to worry about right now, it's all either compiled in or commandline switches

## Running

You can run tlsscan, and specify options on the commandline:

`./tlsscan --host api.ecobee.com:443`

Output is in JSON format to make it easily parsable by other tools, you can use `jq` to beautify it a little:

```
$ ./tlsscan --host api.ecobee.com:443 | jq '.'
{
  "ciphersuites": [
    "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
    "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
    "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384",
    "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256",
    "TLS_RSA_WITH_AES_256_GCM_SHA384",
    "TLS_RSA_WITH_AES_256_CBC_SHA256"
  ],
  "tlsversion": [
    "TLSv1_2"
  ]
}
```

## Bugs 🐜

Go currently filters out ciphersuites which it does not support, and so it does not check the full list. 
